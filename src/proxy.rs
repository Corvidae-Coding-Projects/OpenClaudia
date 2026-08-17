//! HTTP Proxy Server - The core of `OpenClaudia`.
//!
//! Accepts OpenAI-compatible requests and forwards them to the configured provider
//! after running hooks and injecting context.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
    Json, Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc,
};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::compaction::{CompactionOverrides, ContextCompactor};
use crate::config::{AppConfig, ProviderConfig};
use crate::context::{
    hook_result_reference_items, ContextBudget, ContextFreshness, ContextItem, ContextProjector,
    HostInstructionSource, ReferenceSource, UserInstructionSource,
};
use crate::file_types::extensions_from_tool_input;
use crate::hooks::{
    load_claude_code_hooks, merge_hooks_config, HookEngine, HookError, HookEvent, HookInput,
    HookResult,
};
use crate::mcp::McpManager;
use crate::oauth::OAuthStore;
use crate::plugins::PluginManager;
use crate::providers::{self, get_adapter, ApiKey, ProviderAdapter};
use crate::services::policy::{
    request_output_token_budget, ProviderRequestPolicy, ProviderRequestPolicyInput,
};
use crate::session::{get_session_context, SessionManager, TokenUsage};
use crate::vdd::{VddEngine, VddResult};

/// Normalize base URL by stripping trailing slash and /v1 suffix.
/// This prevents double /v1/v1 when endpoint paths include /v1 prefix.
#[must_use]
pub fn normalize_base_url(base_url: &str) -> String {
    base_url
        .trim_end_matches('/')
        .trim_end_matches("/v1")
        .trim_end_matches('/')
        .to_string()
}

/// Shared state for the proxy
#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<AppConfig>,
    pub client: Client,
    pub hook_engine: HookEngine,
    /// Operator-supplied overrides for compaction behavior.
    ///
    /// Stored as overrides — *not* a fully realized [`ContextCompactor`] —
    /// because the actual compactor is model-specific and must be built
    /// per request from `request.model`. Storing the overrides separately
    /// lets `compact_request_context` build the per-request compactor in
    /// one call (`ContextCompactor::for_model_with_overrides`) with zero
    /// clones (crosslink #489).
    pub compactor_overrides: CompactionOverrides,
    pub session_manager: Arc<RwLock<SessionManager>>,
    pub plugin_manager: Arc<PluginManager>,
    pub mcp_manager: Arc<RwLock<McpManager>>,
    /// OAuth session store for Claude Max authentication
    pub oauth_store: Arc<OAuthStore>,
    /// VDD engine for adversarial review (if enabled)
    pub vdd_engine: Option<Arc<tokio::sync::Mutex<VddEngine>>>,
    /// Optional controller used by `openclaudia loop` to count completed
    /// proxy turns, fire Stop hooks, and shut the server down at the
    /// documented iteration limit.
    pub loop_control: Option<Arc<LoopControl>>,
}

pub struct LoopControl {
    max_iterations: u32,
    completed_iterations: AtomicU32,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl LoopControl {
    const fn new(max_iterations: u32, shutdown_tx: tokio::sync::watch::Sender<bool>) -> Self {
        Self {
            max_iterations,
            completed_iterations: AtomicU32::new(0),
            shutdown_tx,
        }
    }

    fn completed_iterations(&self) -> u32 {
        self.completed_iterations.load(Ordering::SeqCst)
    }

    fn mark_completed_iteration(&self) -> u32 {
        self.completed_iterations.fetch_add(1, Ordering::SeqCst) + 1
    }

    const fn reached_limit(&self, iteration: u32) -> bool {
        self.max_iterations > 0 && iteration >= self.max_iterations
    }

    fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Errors that can occur in the proxy
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Provider not configured: {0}")]
    ProviderNotConfigured(String),

    #[error("No API key configured for provider: {0}")]
    NoApiKey(String),

    #[error("Request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Invalid request body: {0}")]
    InvalidBody(String),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Hook blocked request: {0}")]
    HookBlocked(String),

    #[error("Policy denied request: {0}")]
    PolicyDenied(String),
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NoApiKey(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::RequestError(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            Self::HookBlocked(_) | Self::PolicyDenied(_) => {
                (StatusCode::FORBIDDEN, self.to_string())
            }
            Self::ProviderNotConfigured(_) | Self::InvalidBody(_) | Self::JsonError(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
        };

        let body = serde_json::json!({
            "error": {
                "message": message,
                "type": "proxy_error"
            }
        });

        (status, Json(body)).into_response()
    }
}

/// OpenAI-compatible chat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: MessageContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(
        default,
        flatten,
        skip_serializing_if = "std::collections::HashMap::is_empty"
    )]
    pub extra: std::collections::HashMap<String, Value>,
}

/// Message content can be string or array of content parts
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

/// Content part for multimodal messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPart {
    #[serde(rename = "type")]
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<Value>,
}

/// OpenAI-compatible chat completion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, Value>,
}

/// Create the proxy router
pub fn create_router(state: ProxyState) -> Router {
    Router::new()
        // Health check
        .route("/health", get(health_check))
        // Auth routes (device flow for Claude Max OAuth)
        .route("/auth/device", get(auth_device_page))
        .route("/auth/device/start", axum::routing::post(auth_device_start))
        .route(
            "/auth/device/submit",
            axum::routing::post(auth_device_submit),
        )
        .route("/auth/status", get(auth_status))
        // Stats endpoint for token usage
        .route("/stats", get(session_stats))
        // OpenAI-compatible endpoints
        .route("/v1/chat/completions", any(proxy_chat_completions))
        .route("/v1/completions", any(proxy_completions))
        .route("/v1/models", get(list_models))
        // Anthropic-compatible endpoints (for direct Anthropic clients)
        .route("/v1/messages", any(proxy_anthropic_messages))
        // Catch-all for other API routes
        .route("/v1/{*path}", any(proxy_passthrough))
        .with_state(state)
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "openclaudia",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Session stats endpoint - returns token usage and turn metrics.
///
/// Uses [`SessionManager::current_view`] (crosslink #458) — a zero-copy
/// [`SessionView`](crate::session::SessionView) over the active session,
/// so building the JSON payload never deep-copies `turn_metrics` or
/// `cumulative_usage`.
async fn session_stats(State(state): State<ProxyState>) -> impl IntoResponse {
    let sm = state.session_manager.read().await;
    Json(sm.current_view().map_or_else(
        || serde_json::json!({ "error": "No active session" }),
        |session| {
            let last_turn = session.turn_metrics().last();
            let cumulative = session.cumulative_usage();
            serde_json::json!({
                "session_id": session.id(),
                "mode": session.mode(),
                "request_count": session.request_count(),
                "turns": session.turn_metrics().len(),
                "cumulative_usage": {
                    "input_tokens": cumulative.input_tokens,
                    "output_tokens": cumulative.output_tokens,
                    "cache_read_tokens": cumulative.cache_read_tokens,
                    "cache_write_tokens": cumulative.cache_write_tokens,
                    "total_tokens": cumulative.total(),
                },
                "last_turn": last_turn.map(|t| serde_json::json!({
                    "turn_number": t.turn_number,
                    "estimated_input_tokens": t.estimated_input_tokens,
                    "injected_context_tokens": t.injected_context_tokens,
                    "system_prompt_tokens": t.system_prompt_tokens,
                    "tool_def_tokens": t.tool_def_tokens,
                    "actual_usage": t.actual_usage.as_ref().map(|u| serde_json::json!({
                        "input_tokens": u.input_tokens,
                        "output_tokens": u.output_tokens,
                        "cache_read_tokens": u.cache_read_tokens,
                        "cache_write_tokens": u.cache_write_tokens,
                    })),
                })),
            })
        },
    ))
}

/// Device flow page - HTML UI for OAuth authentication
async fn auth_device_page() -> impl IntoResponse {
    axum::response::Html(include_str!("../assets/device_flow.html"))
}

/// Start device authorization flow
async fn auth_device_start(
    State(state): State<ProxyState>,
) -> Result<impl IntoResponse, ProxyError> {
    use crate::oauth::PkceParams;

    let pkce = PkceParams::generate();
    let oauth_state = pkce.state.clone();

    // Store PKCE for later verification
    state.oauth_store.store_challenge(pkce.clone());

    // Build authorization URL via the canonical builder so OAUTH_SCOPES and
    // OAUTH_AUTHORIZE_URL remain the single source of truth.
    // Previously used a hand-rolled format! with stale scope list
    // ("org:create_api_key user:profile user:inference") missing
    // "user:sessions:claude_code". See crosslink #272.
    let auth_url = pkce.build_auth_url();

    info!("Device flow auth URL generated");

    Ok(Json(serde_json::json!({
        "auth_url": auth_url,
        "state": oauth_state
    })))
}

fn required_non_empty_payload_string<'a>(
    payload: &'a Value,
    field: &str,
) -> Result<&'a str, ProxyError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ProxyError::InvalidBody(format!("Missing non-empty string field '{field}'")))
}

fn extract_device_submit_fields(payload: &Value) -> Result<(String, String), ProxyError> {
    let raw_code = required_non_empty_payload_string(payload, "code")?;
    let (code, parsed_state) = crate::oauth::parse_auth_code(raw_code);
    if code.trim().is_empty() {
        return Err(ProxyError::InvalidBody(
            "Missing non-empty string field 'code'".to_string(),
        ));
    }

    let oauth_state = match parsed_state {
        Some(state) if !state.trim().is_empty() => state,
        Some(_) => {
            return Err(ProxyError::InvalidBody(
                "Missing non-empty string field 'state'".to_string(),
            ));
        }
        None => required_non_empty_payload_string(payload, "state")?.to_string(),
    };

    Ok((code, oauth_state))
}

/// Submit authorization code from device flow
async fn auth_device_submit(
    State(state): State<ProxyState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<impl IntoResponse, ProxyError> {
    use crate::oauth::{OAuthClient, OAuthSession};

    let (code, oauth_state) = extract_device_submit_fields(&payload)?;

    // Get PKCE challenge
    let pkce = state
        .oauth_store
        .take_challenge(&oauth_state)
        .ok_or_else(|| ProxyError::InvalidBody("Invalid state parameter".to_string()))?;

    // Exchange code for tokens
    let client = OAuthClient::new()
        .map_err(|e| ProxyError::InvalidBody(format!("OAuth client init failed: {e}")))?;
    let token_response = client
        .exchange_code(&code, &pkce)
        .await
        .map_err(|e| ProxyError::InvalidBody(format!("Token exchange failed: {e}")))?;

    // Create session
    let mut session = OAuthSession::from_token_response(token_response);

    // Try to create API key if we have the scope
    if session.can_create_api_key() {
        if let Ok(api_key) = client
            .create_api_key(&session.credentials.access_token)
            .await
        {
            session.api_key = Some(api_key);
        }
    }

    let session_id = session.id.clone();
    state.oauth_store.store_session(session);

    info!(
        "Device flow authentication successful, session: {}",
        session_id
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Authentication successful",
        "session_id": session_id
    })))
}

/// Check authentication status
async fn auth_status(State(state): State<ProxyState>, headers: HeaderMap) -> impl IntoResponse {
    // Crosslink #908: cookie-parsing chain was duplicated between this
    // route and `proxy_anthropic_messages`. Both now share
    // `lookup_oauth_session_from_cookie` so any future cookie-parsing
    // change (e.g. moving to the `cookie` crate for proper RFC-6265
    // handling) only needs to land in one place.
    let session = lookup_oauth_session_from_cookie(&headers, &state.oauth_store);

    // No "any valid session" fallback — an absent cookie returns
    // `authenticated: false`. The previous fallback let any unauth
    // caller learn another user's session id. See crosslink #375.

    match session {
        Some(s) => Json(serde_json::json!({
            "authenticated": true,
            "session_id": s.id
        })),
        None => Json(serde_json::json!({
            "authenticated": false,
            "session_id": null
        })),
    }
}

fn model_list_json(data: Vec<Value>) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("object".to_string(), Value::String("list".to_string()));
    body.insert("data".to_string(), Value::Array(data));
    Value::Object(body)
}

fn static_model_list_json_for_provider(provider: &str) -> Value {
    let catalog_provider = providers::canonical_static_catalog_provider(provider);
    let data: Vec<Value> = providers::static_models_for_provider(catalog_provider)
        .iter()
        .map(|id| {
            serde_json::json!({
                "id": *id,
                "object": "model",
                "owned_by": catalog_provider,
            })
        })
        .collect();

    model_list_json(data)
}

#[cfg(test)]
fn static_model_list_json() -> Value {
    let data: Vec<Value> = providers::STATIC_MODEL_CATALOG_PROVIDERS
        .iter()
        .flat_map(|provider| {
            providers::static_models_for_provider(provider)
                .iter()
                .map(move |id| {
                    serde_json::json!({
                        "id": *id,
                        "object": "model",
                        "owned_by": *provider,
                    })
                })
        })
        .collect();

    model_list_json(data)
}

fn upstream_model_list_json(fallback_owner: &str, models: Vec<providers::ModelInfo>) -> Value {
    let data: Vec<Value> = models
        .into_iter()
        .map(|model| {
            let mut value = serde_json::json!({
                "id": model.id,
                "object": "model",
                "owned_by": model.owned_by.as_deref().unwrap_or(fallback_owner),
            });
            if let Some(created) = model.created {
                value["created"] = serde_json::json!(created);
            }
            value
        })
        .collect();

    model_list_json(data)
}

async fn model_list_json_for_state(state: &ProxyState) -> Value {
    let target = state.config.proxy.target.as_str();
    let adapter = match get_adapter(target) {
        Ok(adapter) => adapter,
        Err(err) => {
            warn!(target, error = %err, "Unknown provider for /v1/models; using static fallback");
            return static_model_list_json_for_provider(target);
        }
    };
    let fallback_provider = if providers::STATIC_MODEL_CATALOG_PROVIDERS.contains(&adapter.name()) {
        adapter.name()
    } else {
        providers::canonical_static_catalog_provider(target)
    };

    if adapter.supports_model_listing() {
        if let Some(provider_config) = state.config.active_provider() {
            let extra_headers: Vec<(String, String)> = provider_config
                .headers
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            match providers::fetch_models_with_headers(
                &provider_config.base_url,
                provider_config.api_key.as_ref(),
                &extra_headers,
                adapter,
            )
            .await
            {
                Ok(models) if !models.is_empty() => {
                    return upstream_model_list_json(adapter.name(), models);
                }
                Ok(_) => {
                    debug!(
                        target,
                        "Provider /v1/models returned no models; using static fallback"
                    );
                }
                Err(err) => {
                    warn!(target, error = %err, "Provider /v1/models failed; using static fallback");
                }
            }
        } else {
            warn!(
                target,
                "No active provider config for /v1/models; using static fallback"
            );
        }
    }

    static_model_list_json_for_provider(fallback_provider)
}

/// List available models for the active provider.
async fn list_models(State(state): State<ProxyState>) -> impl IntoResponse {
    Json(model_list_json_for_state(&state).await)
}

/// Run `PreToolUse` hooks for tool calls in the response
async fn run_pre_tool_use_hooks(
    hook_engine: &HookEngine,
    session_id: Option<&str>,
    tool_name: &str,
    tool_input: &serde_json::Value,
) -> HookResult {
    // Security enforcement handled by the permissions system (src/permissions.rs)

    // Extract file extensions from tool input for context
    let extensions = extensions_from_tool_input(tool_name, tool_input);

    let mut hook_input =
        HookInput::new(HookEvent::PreToolUse).with_tool(tool_name, tool_input.clone());

    if let Some(sid) = session_id {
        hook_input = hook_input.with_session_id(sid);
    }

    // Add extensions as extra context
    if !extensions.is_empty() {
        hook_input = hook_input.with_extra("extensions", serde_json::json!(extensions));
    }

    let result = hook_engine.run(HookEvent::PreToolUse, &hook_input).await;

    if !result.allowed {
        debug!(
            tool = %tool_name,
            "PreToolUse hook blocked tool execution"
        );
    }

    result
}

/// Prepare a chat completion request: run hooks, inject context, MCP tools,
/// plugins, and VDD.
///
/// The `#[allow(clippy::too_many_lines)]` below is deliberately retained
/// — this function is a long linear sequence of independent injection
/// phases (hook, prompt-mod, context inject, MCP tools, plugin
/// tools, VDD context). Breaking it further without an enclosing
/// orchestrator would just move line count around. A follow-up PR can
/// formalize a `RequestContextPipeline` if it becomes worth the weight.
#[allow(clippy::too_many_lines)]
async fn prepare_request_context(
    request: &mut ChatCompletionRequest,
    state: &ProxyState,
) -> Result<(), ProxyError> {
    // Convert client-authored and compaction-compatibility system records at
    // the boundary. Client instructions retain explicit user authority;
    // compaction summaries and grounding records remain reference data.
    let mut context_items = take_system_context_items(request);

    // Run UserPromptSubmit hooks
    let last_user_message = request
        .messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| match &m.content {
            MessageContent::Text(t) => t.clone(),
            MessageContent::Parts(parts) => parts
                .iter()
                .filter_map(|p| p.text.clone())
                .collect::<Vec<_>>()
                .join("\n"),
        });

    let hook_input = HookInput::new(HookEvent::UserPromptSubmit)
        .with_prompt(last_user_message.unwrap_or_default());

    let hook_result = state
        .hook_engine
        .run(HookEvent::UserPromptSubmit, &hook_input)
        .await;

    if !hook_result.allowed {
        let reason = hook_result
            .outputs
            .first()
            .and_then(|o| o.reason.clone())
            .unwrap_or_else(|| "Request blocked by hook".to_string());
        return Err(ProxyError::HookBlocked(reason));
    }

    context_items.extend(hook_result_reference_items(
        &hook_result,
        "user_prompt_submit",
        500,
    ));

    // Add MCP tools
    let mcp_tools = state
        .mcp_manager
        .read()
        .await
        .tools_as_openai_functions()
        .await;
    if !mcp_tools.is_empty() {
        let mut tools = request.tools.take().unwrap_or_default();
        tools.extend(mcp_tools);
        request.tools = Some(tools);
    }

    // Add plugin commands as context
    let plugin_commands: Vec<String> = state
        .plugin_manager
        .all_commands()
        .iter()
        .map(|(plugin, cmd)| format!("/{}:{} (from {})", plugin.name(), cmd.name, plugin.name()))
        .collect();
    if !plugin_commands.is_empty() {
        let commands_context = format!("Available plugin commands: {}", plugin_commands.join(", "));
        context_items.push(ContextItem::reference(
            "proxy.plugin_commands",
            ReferenceSource::Plugin,
            "plugin-manager:commands",
            commands_context,
            ContextFreshness::Session,
            600,
        ));
    }

    // Inject session context
    let session_context = {
        let sm = state.session_manager.read().await;
        sm.get_session().map(get_session_context)
    };
    if let Some(context) = session_context {
        context_items.push(ContextItem::host_instruction(
            "proxy.session_policy",
            HostInstructionSource::SessionPolicy,
            "host:session-manager",
            context,
            ContextFreshness::Session,
            100,
        ));
    }

    // Inject VDD advisory from previous turn
    {
        let mut sm = state.session_manager.write().await;
        if let Some(vdd_observation) = sm.take_vdd_observation() {
            context_items.push(vdd_observation);
            debug!("Attached VDD advisory as reference context from previous turn");
        }
    }

    let projection = ContextProjector::project(context_items, ContextBudget::default());
    tracing::debug!(
        entries = projection.trace.entries.len(),
        system_bytes = projection.trace.stable_system_bytes
            + projection.trace.dynamic_system_bytes
            + projection.trace.system_join_bytes,
        reference_bytes = projection.trace.reference_bytes,
        estimated_tokens = projection.trace.total_estimated_tokens,
        "projected typed proxy context"
    );
    projection.augment_chat_request(request);

    // Run PreToolUse hooks for tool calls in previous messages
    for msg in &request.messages {
        if let Some(tool_calls) = &msg.tool_calls {
            for tool_call in tool_calls {
                if let (Some(name), Some(args)) = (
                    tool_call
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(|n| n.as_str()),
                    tool_call.get("function").and_then(|f| f.get("arguments")),
                ) {
                    let session_id = {
                        let sm = state.session_manager.read().await;
                        sm.get_session().map(|s| s.id.clone())
                    };
                    let hook_result = run_pre_tool_use_hooks(
                        &state.hook_engine,
                        session_id.as_deref(),
                        name,
                        args,
                    )
                    .await;

                    for output in &hook_result.outputs {
                        if let Some(extra_data) = output.extra.get("metadata") {
                            debug!(metadata = %extra_data, "Hook provided extra metadata");
                        }
                    }

                    if let Err(hook_err) = HookEngine::check_blocked(&hook_result) {
                        let reason = match hook_err {
                            HookError::Blocked(r) => r,
                            _ => "PreToolUse hook blocked".to_string(),
                        };
                        return Err(ProxyError::HookBlocked(format!(
                            "Tool '{name}' blocked: {reason}"
                        )));
                    }
                }
            }
        }
    }

    Ok(())
}

fn take_system_context_items(request: &mut ChatCompletionRequest) -> Vec<ContextItem> {
    let mut retained = Vec::with_capacity(request.messages.len());
    let mut items = Vec::new();
    let mut next_system_is_compaction_summary = false;
    for (index, message) in request.messages.drain(..).enumerate() {
        if message.role != "system" {
            retained.push(message);
            continue;
        }
        let is_compaction_boundary = crate::compaction::is_compact_boundary_message(&message);
        let is_compaction_summary = next_system_is_compaction_summary;
        next_system_is_compaction_summary = is_compaction_boundary;
        let declared_source = message
            .extra
            .get("metadata")
            .and_then(|metadata| metadata.get("openclaudia_context_source"))
            .and_then(Value::as_str);
        let content = match message.content {
            MessageContent::Text(text) => text,
            MessageContent::Parts(parts) => parts
                .into_iter()
                .filter_map(|part| part.text)
                .collect::<Vec<_>>()
                .join("\n"),
        };
        let id = format!("proxy.system.{index}");
        let origin = format!("proxy-request:messages[{index}]");
        let priority = 70u16.saturating_add(u16::try_from(index).unwrap_or(u16::MAX));
        let item = if is_compaction_boundary || is_compaction_summary {
            ContextItem::reference(
                id,
                ReferenceSource::Session,
                origin,
                content,
                ContextFreshness::Turn,
                priority,
            )
        } else if declared_source == Some("reality") {
            ContextItem::reference(
                id,
                ReferenceSource::Reality,
                origin,
                content,
                ContextFreshness::Turn,
                priority,
            )
        } else {
            ContextItem::user_instruction(
                id,
                UserInstructionSource::DirectInstruction,
                origin,
                content,
                ContextFreshness::Turn,
                priority,
            )
        };
        items.push(item);
    }
    request.messages = retained;
    items
}

/// Estimate turn tokens (input / system / tool-definition), record them on
/// the active session, log the per-turn usage, and fire the
/// `token_warning` notification when estimated input exceeds the
/// configured warn threshold. Extracted from `proxy_chat_completions`
/// per crosslink #247 (SRP decomposition).
async fn record_turn_estimate(
    state: &ProxyState,
    request: &ChatCompletionRequest,
    estimated_input: usize,
) {
    // Break down token components
    let system_prompt_tokens: usize = request
        .messages
        .iter()
        .filter(|m| m.role == "system")
        .map(crate::compaction::estimate_message_tokens)
        .sum();

    let tool_def_tokens: usize = request.tools.as_ref().map_or(0, |tools| {
        tools
            .iter()
            .map(|t| crate::compaction::estimate_tokens(&t.to_string()))
            .sum()
    });

    let injected_context_tokens = system_prompt_tokens + tool_def_tokens;

    let mut sm = state.session_manager.write().await;
    let Some(session) = sm.get_session_mut() else {
        return;
    };

    let turn = session.record_turn_estimate(
        estimated_input,
        injected_context_tokens,
        system_prompt_tokens,
        tool_def_tokens,
    );
    let context_window = crate::compaction::get_context_window(&request.model);
    // Integer-safe utilization computation.
    let utilization_pct_x10 = estimated_input
        .saturating_mul(1000)
        .checked_div(context_window)
        .unwrap_or(0);
    #[allow(clippy::cast_possible_truncation)]
    let usage_pct_f64 = f64::from(utilization_pct_x10 as u32) / 10.0;

    if state.config.session.token_tracking.log_usage {
        info!(
            turn = turn,
            estimated_input = estimated_input,
            system_prompt = system_prompt_tokens,
            tool_defs = tool_def_tokens,
            context_window = context_window,
            utilization_pct = format!("{usage_pct_f64:.1}%"),
            "Turn token estimate"
        );
    }

    let warn_threshold = state.config.session.token_tracking.warn_threshold;
    // Integer threshold avoids usize→f32 precision loss.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let threshold_tokens = (f64::from(context_window as u32) * f64::from(warn_threshold)) as usize;
    if estimated_input > threshold_tokens {
        warn!(
            estimated = estimated_input,
            threshold = format!("{:.0}%", warn_threshold * 100.0),
            context_window = context_window,
            "Token usage approaching context window limit"
        );
        // Fire token warning notification
        drop(sm); // release the write lock before the hook fires notifications
        state
            .hook_engine
            .fire_notification(
                "token_warning",
                serde_json::json!({ "usage_pct": usage_pct_f64 }),
            )
            .await;
    }
}

/// Run the VDD adversarial-review pipeline against a freshly-converted
/// builder response and return the (possibly-revised) response.
///
/// Consolidates the four `Response::from_parts` reassembly sites
/// previously inlined in `proxy_chat_completions` (one per VDD result
/// variant plus the JSON-parse-failure fallthrough) into a single
/// pattern-matched helper. See crosslink #247 point 5.
///
/// Bounded read closes crosslink #352: `max_response_bytes` (default
/// 50 MiB) caps the buffered body; over-limit and other read errors
/// log at `warn!` and return an empty passthrough rather than feeding
/// an empty buffer to the VDD engine.
async fn apply_vdd_review(
    response_value: Response,
    state: &ProxyState,
    request: &ChatCompletionRequest,
    provider_name: &str,
    api_key: Option<&ApiKey>,
) -> Result<Response, ProxyError> {
    let Some(vdd_engine) = &state.vdd_engine else {
        return Ok(response_value);
    };

    let (parts, body) = response_value.into_parts();
    let max_bytes = state.config.proxy.max_response_bytes;
    let response_bytes = match axum::body::to_bytes(body, max_bytes).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                error = %e,
                max_bytes = max_bytes,
                "Failed to read upstream response body for VDD review; \
                 returning empty passthrough to the client (crosslink #352)."
            );
            return Ok(Response::from_parts(parts, Body::empty()));
        }
    };

    // Parse the body as JSON. Non-JSON bodies are passed through verbatim.
    let Ok(response_json) = serde_json::from_slice::<Value>(&response_bytes) else {
        return Ok(Response::from_parts(parts, Body::from(response_bytes)));
    };

    fire_vdd_hook_event(
        &state.hook_engine,
        HookEvent::PreAdversaryReview,
        provider_name,
        &request.model,
        serde_json::json!({
            "mode": state.config.vdd.mode.to_string(),
            "response_bytes": response_bytes.len(),
        }),
    )
    .await;

    let vdd_result = {
        let engine = vdd_engine.lock().await;
        let builder = crate::vdd::BuilderProvider::new(provider_name, api_key);
        engine
            .process_response(&response_json, request, builder)
            .await
    };

    match &vdd_result {
        Ok(result) => {
            fire_vdd_result_hooks(&state.hook_engine, provider_name, &request.model, result).await;
        }
        Err(error) => {
            fire_vdd_hook_event(
                &state.hook_engine,
                HookEvent::PostAdversaryReview,
                provider_name,
                &request.model,
                serde_json::json!({
                    "ok": false,
                    "error": error.to_string(),
                }),
            )
            .await;
        }
    }

    // Decide which bytes to ship back. Only `Blocking` produces new bytes;
    // every other path reuses the original response body.
    let body_bytes: Vec<u8> = match vdd_result {
        Ok(VddResult::Advisory(advisory)) => {
            let genuine = advisory
                .findings
                .iter()
                .filter(|f| f.status == crate::vdd::FindingStatus::Genuine)
                .count();
            if let Some(observation) = advisory.context_observation {
                let mut sm = state.session_manager.write().await;
                sm.store_vdd_observation(observation);
            }
            info!(
                total = advisory.findings.len(),
                genuine = genuine,
                "VDD advisory review complete"
            );
            response_bytes.to_vec()
        }
        Ok(VddResult::Blocking(blocking)) => {
            info!(
                iterations = blocking.session.iterations.len(),
                genuine = blocking.session.total_genuine,
                converged = blocking.session.converged,
                crosslink_issues = blocking.crosslink_issues.len(),
                "VDD blocking loop complete"
            );
            serde_json::to_vec(&blocking.final_response).unwrap_or_else(|_| response_bytes.to_vec())
        }
        Ok(VddResult::Skipped(reason)) => {
            debug!(reason = %reason, "VDD skipped");
            response_bytes.to_vec()
        }
        Err(e) => {
            warn!(error = %e, "VDD error (non-blocking, returning original response)");
            response_bytes.to_vec()
        }
    };

    Ok(Response::from_parts(parts, Body::from(body_bytes)))
}

async fn fire_vdd_result_hooks(
    hook_engine: &HookEngine,
    provider_name: &str,
    model: &str,
    result: &VddResult,
) {
    for (event, payload) in vdd_result_hook_plan(result) {
        fire_vdd_hook_event(hook_engine, event, provider_name, model, payload).await;
    }
}

fn vdd_result_hook_plan(result: &VddResult) -> Vec<(HookEvent, Value)> {
    match result {
        VddResult::Advisory(advisory) => {
            let genuine = advisory
                .findings
                .iter()
                .filter(|finding| finding.status == crate::vdd::FindingStatus::Genuine)
                .count();
            let mut events = vec![(
                HookEvent::PostAdversaryReview,
                serde_json::json!({
                    "ok": true,
                    "result": "advisory",
                    "total_findings": advisory.findings.len(),
                    "genuine_findings": genuine,
                    "static_analysis_results": advisory.static_analysis.len(),
                    "context_observation_bytes": advisory
                        .context_observation
                        .as_ref()
                        .map_or(0, crate::context::ContextItem::content_bytes),
                }),
            )];
            if genuine > 0 {
                events.push((
                    HookEvent::VddConflict,
                    serde_json::json!({
                        "result": "advisory",
                        "genuine_findings": genuine,
                    }),
                ));
            }
            events
        }
        VddResult::Blocking(blocking) => {
            let mut events = vec![(
                HookEvent::PostAdversaryReview,
                serde_json::json!({
                    "ok": true,
                    "result": "blocking",
                    "iterations": blocking.session.iterations.len(),
                    "total_findings": blocking.session.total_findings,
                    "genuine_findings": blocking.session.total_genuine,
                    "false_positives": blocking.session.total_false_positives,
                    "converged": blocking.session.converged,
                    "crosslink_issues": blocking.crosslink_issues.len(),
                }),
            )];
            if blocking.session.total_genuine > 0 {
                events.push((
                    HookEvent::VddConflict,
                    serde_json::json!({
                        "result": "blocking",
                        "genuine_findings": blocking.session.total_genuine,
                    }),
                ));
            }
            if blocking.session.converged {
                events.push((
                    HookEvent::VddConverged,
                    serde_json::json!({
                        "result": "blocking",
                        "iterations": blocking.session.iterations.len(),
                        "termination_reason": blocking.session.termination_reason,
                    }),
                ));
            }
            events
        }
        VddResult::Skipped(reason) => vec![(
            HookEvent::PostAdversaryReview,
            serde_json::json!({
                "ok": true,
                "result": "skipped",
                "reason": reason,
            }),
        )],
    }
}

async fn fire_vdd_hook_event(
    hook_engine: &HookEngine,
    event: HookEvent,
    provider_name: &str,
    model: &str,
    payload: Value,
) {
    let input = HookInput::new(event)
        .with_extra("provider", serde_json::json!(provider_name))
        .with_extra("model", serde_json::json!(model))
        .with_extra("payload", payload);
    let result = hook_engine.run(event, &input).await;
    if !result.allowed {
        warn!(
            event = ?event,
            provider = %provider_name,
            model = %model,
            "VDD hook returned a deny decision; VDD lifecycle hooks are observational"
        );
    }
    for (hook_error_index, hook_error) in result.errors.iter().enumerate() {
        warn!(
            event = ?event,
            provider = %provider_name,
            model = %model,
            hook_error_index,
            error = %hook_error,
            "VDD hook execution failed"
        );
    }
}

/// Build a model-specific compactor, apply session hints, and compact the
/// request context if needed. Logs results and fires hooks. Non-fatal: errors
/// are logged at warn and do not abort the request.
async fn compact_request_context(request: &mut ChatCompletionRequest, state: &ProxyState) {
    // Single-pass construction — no temporary clones of CompactionConfig.
    // Adding a new override field is enforced at compile time via the
    // destructuring in `CompactionConfig::apply_overrides` (crosslink #489).
    let compactor =
        ContextCompactor::for_model_with_overrides(&request.model, &state.compactor_overrides);

    let actual_token_hint: Option<usize> = {
        let sm = state.session_manager.read().await;
        sm.get_session().and_then(|session| {
            session
                .turn_metrics
                .last()
                .and_then(|tm| tm.actual_usage.as_ref())
                .map(|u| usize::try_from(u.input_tokens).unwrap_or(usize::MAX))
        })
    };

    match compactor
        .compact_with_hint(
            request,
            Some(&state.hook_engine),
            None,
            actual_token_hint,
            None,
        )
        .await
    {
        Ok(result) if result.compacted => {
            let summary_len = result.summary.as_ref().map_or(0, std::string::String::len);
            info!(
                original = result.original_tokens,
                new = result.new_tokens,
                summarized = result.messages_summarized,
                summary_len = summary_len,
                "Context compacted"
            );
            debug!(summary_len, "Compaction summary generated");
            state
                .hook_engine
                .fire_notification(
                    "compaction",
                    serde_json::json!({ "summary_length": summary_len }),
                )
                .await;
        }
        Ok(_) => {}
        Err(crate::compaction::CompactionError::HookBlocked(reason)) => {
            warn!(reason = %reason, "Compaction blocked by hook");
        }
        Err(crate::compaction::CompactionError::Failed(reason)) => {
            warn!(reason = %reason, "Compaction failed");
        }
    }
}

async fn complete_loop_iteration(state: &ProxyState) {
    let Some(control) = state.loop_control.as_ref() else {
        return;
    };

    let iteration = control.mark_completed_iteration();
    let session_id = {
        let sm = state.session_manager.read().await;
        sm.get_session().map(|session| session.id.clone())
    };
    let mut stop_input =
        HookInput::new(HookEvent::Stop).with_extra("iteration", serde_json::json!(iteration));
    if let Some(session_id) = session_id {
        stop_input = stop_input.with_session_id(session_id);
    }

    let stop_result = state.hook_engine.run(HookEvent::Stop, &stop_input).await;
    if !stop_result.allowed {
        info!(
            iteration,
            reason = ?stop_result
                .outputs
                .first()
                .and_then(|output| output.reason.as_deref()),
            "Loop mode Stop hook requested shutdown"
        );
        control.request_shutdown();
        return;
    }

    if control.reached_limit(iteration) {
        info!(
            iteration,
            max_iterations = control.max_iterations,
            "Loop mode reached maximum completed iterations"
        );
        control.request_shutdown();
    }
}

/// Resolve the target provider, its configuration, and the API key for a
/// chat-completion request.
///
/// Returns `(provider_name, provider_config, api_key)`. The provider config is
/// borrowed from `state.config`; callers must hold `state` across the
/// returned reference's lifetime.
///
/// # Errors
///
/// - [`ProxyError::ProviderNotConfigured`] if the resolved provider name has
///   no entry in `state.config.providers`.
/// - [`ProxyError::NoApiKey`] if neither the request headers nor the provider
///   config supply an API key for a non-local provider.
fn resolve_provider<'a>(
    state: &'a ProxyState,
    headers: &HeaderMap,
    model: &str,
) -> Result<(String, &'a ProviderConfig, Option<ApiKey>), ProxyError> {
    let provider_name = determine_provider(model, &state.config);
    let provider = state
        .config
        .get_provider(&provider_name)
        .ok_or_else(|| ProxyError::ProviderNotConfigured(provider_name.clone()))?;
    let api_key = extract_api_key(headers)?.or_else(|| provider.api_key.clone());
    if api_key.is_none() && !crate::config::is_local_provider_name(&provider_name) {
        return Err(ProxyError::NoApiKey(provider_name));
    }
    Ok((provider_name, provider, api_key))
}

fn adapter_headers(
    adapter: &dyn ProviderAdapter,
    api_key: Option<&ApiKey>,
) -> Vec<(String, String)> {
    api_key.map_or_else(
        || vec![("content-type".to_string(), "application/json".to_string())],
        |key| adapter.get_headers(key),
    )
}

/// Increment the active session's request counter, if one exists.
///
/// Holds the session-manager write lock for the smallest possible scope.
async fn bump_session_request_count(state: &ProxyState) {
    let mut sm = state.session_manager.write().await;
    if let Some(session) = sm.get_session_mut() {
        session.increment_requests();
    }
}

/// For OpenAI-compatible streaming requests, inject `stream_options` so the
/// upstream includes a final usage event we can attribute to the session.
///
/// No-op for Anthropic-style providers (their streaming protocol carries
/// usage in `message_delta`/`message_start` events instead) and for any
/// payload that already specifies `stream_options`.
fn inject_stream_options_if_needed(
    transformed_request: &mut Value,
    is_stream: bool,
    provider_name: &str,
) {
    if !is_stream || provider_name.contains("anthropic") {
        return;
    }
    if let Some(obj) = transformed_request.as_object_mut() {
        if !obj.contains_key("stream_options") {
            obj.insert(
                "stream_options".to_string(),
                serde_json::json!({"include_usage": true}),
            );
        }
    }
}

/// Apply the provider adapter's request transform (with thinking config),
/// inject OpenAI-style `stream_options` when applicable, and forward the
/// request upstream.
///
/// # Errors
///
/// - [`ProxyError::InvalidBody`] if the adapter's transform fails.
/// - Any [`ProxyError`] surfaced by [`forward_to_provider_raw_reqwest`].
async fn transform_and_forward(
    state: &ProxyState,
    provider: &ProviderConfig,
    provider_name: &str,
    api_key: Option<&ApiKey>,
    request: &ChatCompletionRequest,
    is_stream: bool,
) -> Result<reqwest::Response, ProxyError> {
    // Crosslink #433: get_adapter now returns Result<&'static dyn …>; an
    // unknown provider name surfaces as a 400 instead of a silent OpenAI
    // fallback. The error string already lists the supported set so the
    // client sees a useful diagnostic.
    let adapter = get_adapter(provider_name).map_err(|e| ProxyError::InvalidBody(e.to_string()))?;
    debug!(provider = adapter.name(), "Using provider adapter");

    let mut transformed_request = adapter
        .transform_request_with_thinking(request, &provider.thinking)
        .map_err(|e| ProxyError::InvalidBody(e.to_string()))?;

    inject_stream_options_if_needed(&mut transformed_request, is_stream, provider_name);

    forward_to_provider_raw_reqwest(
        &state.client,
        provider,
        &adapter.chat_endpoint(&request.model),
        &transformed_request,
        is_stream,
        adapter_headers(adapter, api_key),
    )
    .await
}

/// Record an upstream-reported token usage tally against the active session
/// and optionally log it at `info`.
///
/// The session write lock is held only for the mutation itself; logging
/// happens after the lock is released to minimize contention. Logging is
/// gated on both the `log_usage` config flag and the existence of a session
/// (matching the original inline behavior).
async fn record_actual_usage_for_session(state: &ProxyState, usage: TokenUsage) {
    // Snapshot of values needed for logging, captured before releasing the
    // lock so we can drop the guard before doing any I/O.
    let input_tokens = usage.input_tokens;
    let output_tokens = usage.output_tokens;
    let cache_read_tokens = usage.cache_read_tokens;
    let cache_write_tokens = usage.cache_write_tokens;

    let recorded = {
        let mut sm = state.session_manager.write().await;
        sm.get_session_mut().is_some_and(|session| {
            session.record_actual_usage(usage);
            true
        })
    };

    if recorded && state.config.session.token_tracking.log_usage {
        info!(
            input = input_tokens,
            output = output_tokens,
            cache_read = cache_read_tokens,
            cache_write = cache_write_tokens,
            "Actual token usage from provider"
        );
    }
}

fn proxy_policy_error(error: &crate::services::policy::PolicyError) -> ProxyError {
    ProxyError::PolicyDenied(error.to_string())
}

fn enforce_model_policy(
    state: &ProxyState,
    request: &ChatCompletionRequest,
) -> Result<(), ProxyError> {
    ProviderRequestPolicy::new(&state.config.policy)
        .check(ProviderRequestPolicyInput {
            model: &request.model,
            estimated_input_tokens: 0,
            output_token_budget: 0,
            cumulative_session_tokens: 0,
        })
        .map_err(|error| proxy_policy_error(&error))
}

async fn enforce_token_policy(
    state: &ProxyState,
    request: &ChatCompletionRequest,
    estimated_input: usize,
) -> Result<(), ProxyError> {
    let cumulative_total = {
        let sm = state.session_manager.read().await;
        sm.current_view()
            .map_or(0, |session| session.cumulative_usage().total())
    };
    ProviderRequestPolicy::new(&state.config.policy)
        .check(ProviderRequestPolicyInput {
            model: &request.model,
            estimated_input_tokens: estimated_input,
            output_token_budget: request_output_token_budget(request.max_tokens),
            cumulative_session_tokens: cumulative_total,
        })
        .map_err(|error| proxy_policy_error(&error))
}

async fn proxy_chat_completions(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, ProxyError> {
    let mut request: ChatCompletionRequest =
        serde_json::from_str(&body).map_err(|e| ProxyError::InvalidBody(e.to_string()))?;

    info!(
        model = %request.model,
        messages = request.messages.len(),
        "Proxying chat completion request"
    );

    enforce_model_policy(&state, &request)?;

    let (provider_name, provider, api_key) = resolve_provider(&state, &headers, &request.model)?;

    bump_session_request_count(&state).await;

    // Compact first: compaction emits legacy system-role boundary/summary
    // records for transcript compatibility. The typed preparation step must
    // run afterwards so model-authored summary text is demoted to bounded
    // session reference data before provider dispatch.
    compact_request_context(&mut request, &state).await;
    // Prepare request: run hooks, project typed context, MCP tools, plugins,
    // VDD, and every system-role value left by the client or compactor.
    prepare_request_context(&mut request, &state).await?;
    let estimated_input = crate::compaction::estimate_request_tokens(&request);
    enforce_token_policy(&state, &request, estimated_input).await?;

    // Pre-request token estimation and tracking
    let token_tracking_enabled = state.config.session.token_tracking.enabled;
    if token_tracking_enabled {
        record_turn_estimate(&state, &request, estimated_input).await;
    }

    let is_stream = request.stream.unwrap_or(false);
    let raw_response = transform_and_forward(
        &state,
        provider,
        &provider_name,
        api_key.as_ref(),
        &request,
        is_stream,
    )
    .await?;

    // Post-response: non-streaming chat completions must be normalized back
    // into OpenAI shape after the provider-native request/response roundtrip.
    let max_bytes = state.config.proxy.max_response_bytes;
    if is_stream {
        let response = convert_response(raw_response, max_bytes).await?;
        complete_loop_iteration(&state).await;
        Ok(response)
    } else {
        let (response_value, usage) =
            convert_response_with_usage(raw_response, max_bytes, &provider_name).await?;
        if let Some(usage) = usage {
            if token_tracking_enabled {
                record_actual_usage_for_session(&state, usage).await;
            }
        }
        if token_tracking_enabled {
            let response = apply_vdd_review(
                response_value,
                &state,
                &request,
                &provider_name,
                api_key.as_ref(),
            )
            .await?;
            complete_loop_iteration(&state).await;
            Ok(response)
        } else {
            complete_loop_iteration(&state).await;
            Ok(response_value)
        }
    }
}

/// Handle MCP tool calls from the model response.
///
/// # Errors
///
/// Returns `ProxyError::InvalidBody` if the MCP server is not connected or
/// the tool call fails.
pub async fn handle_mcp_tool_call(
    mcp_manager: &Arc<RwLock<McpManager>>,
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, ProxyError> {
    let mcp = mcp_manager.read().await;

    // Check if the MCP server is connected (format: mcp__servername__toolname)
    let parts: Vec<&str> = tool_name.splitn(3, "__").collect();
    if parts.len() == 3 && parts[0] == "mcp" {
        let server_name = parts[1];
        if !mcp.is_connected(server_name).await {
            return Err(ProxyError::InvalidBody(format!(
                "MCP server '{server_name}' is not connected"
            )));
        }
    }

    // Call the tool
    match mcp.call_tool(tool_name, arguments).await {
        Ok(result) => Ok(result),
        Err(e) => Err(ProxyError::InvalidBody(format!(
            "MCP tool call failed: {e}"
        ))),
    }
}

/// Fire a `tool_error` notification when a tool execution fails.
/// This should be called by any code path that executes tools and gets an error.
pub async fn fire_tool_error_notification(
    hook_engine: &HookEngine,
    tool_name: &str,
    error_msg: &str,
) {
    hook_engine
        .fire_notification(
            "tool_error",
            serde_json::json!({
                "tool": tool_name,
                "error": error_msg,
            }),
        )
        .await;
}

/// Disconnect all MCP servers gracefully
pub async fn shutdown_mcp(mcp_manager: &Arc<RwLock<McpManager>>) {
    let mcp = mcp_manager.write().await;
    if let Err(e) = mcp.disconnect_all().await {
        warn!(error = %e, "Error disconnecting MCP servers");
    }
}

/// Proxy completions (legacy `OpenAI` format)
async fn proxy_completions(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, ProxyError> {
    let request: Value =
        serde_json::from_str(&body).map_err(|e| ProxyError::InvalidBody(e.to_string()))?;

    let model = request["model"]
        .as_str()
        .unwrap_or("gpt-3.5-turbo-instruct");
    let provider_name = determine_provider(model, &state.config);
    let provider = state
        .config
        .get_provider(&provider_name)
        .ok_or_else(|| ProxyError::ProviderNotConfigured(provider_name.clone()))?;

    let api_key = extract_api_key(&headers)?.or_else(|| provider.api_key.clone());
    if api_key.is_none() && !crate::config::is_local_provider_name(&provider_name) {
        return Err(ProxyError::NoApiKey(provider_name));
    }

    let is_stream = request["stream"].as_bool().unwrap_or(false);
    let max_bytes = state.config.proxy.max_response_bytes;
    let raw = forward_to_provider(
        &state.client,
        provider,
        &provider_name,
        api_key.as_ref(),
        "/v1/completions",
        &request,
        is_stream,
    )
    .await?;

    let response = convert_response(raw, max_bytes).await?;
    complete_loop_iteration(&state).await;
    Ok(response)
}

/// Resolved authentication for a `/v1/messages` request.
///
/// Modeled as an enum (rather than a pair of `Option`s) to make the
/// "exactly one is present" invariant unrepresentable-as-broken at the
/// type level — see crosslink #386.
enum AnthropicAuth {
    /// An OAuth Bearer session was matched from the request's
    /// `anthropic_session=…` cookie.
    Oauth(crate::oauth::OAuthSession),
    /// No OAuth session matched; an API key was supplied either by the
    /// caller (`Authorization` / `x-api-key`) or by provider config.
    ApiKey(ApiKey),
}

/// Look up an OAuth session from the request's `anthropic_session`
/// cookie, if any.
///
/// Returns `None` when the cookie header is absent, malformed, or
/// names a session that is not in the store. Does NOT fall back to
/// "any valid session" — see crosslink #375 (critical) for the
/// reasoning. Extracted from the inline parse chain in
/// `proxy_anthropic_messages` for crosslink #386.
fn lookup_oauth_session_from_cookie(
    headers: &HeaderMap,
    oauth_store: &OAuthStore,
) -> Option<crate::oauth::OAuthSession> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                let cookie = cookie.trim();
                cookie
                    .strip_prefix("anthropic_session=")
                    .map(std::string::ToString::to_string)
            })
        })
        .and_then(|session_id| {
            debug!(
                "[/v1/messages] Looking up session from cookie: {}",
                session_id
            );
            oauth_store.get_session(&session_id)
        })
}

/// Resolve the authentication mode for an Anthropic `/v1/messages`
/// request.
///
/// OAuth is preferred when a valid session cookie is present; otherwise
/// an API key from `Authorization` / `x-api-key` / provider config is
/// used. Returns `Err(ProxyError::NoApiKey)` only when neither path is
/// available. Extracted for crosslink #386.
fn resolve_anthropic_auth(
    headers: &HeaderMap,
    oauth_store: &OAuthStore,
    provider: &ProviderConfig,
) -> Result<AnthropicAuth, ProxyError> {
    if let Some(session) = lookup_oauth_session_from_cookie(headers, oauth_store) {
        return Ok(AnthropicAuth::Oauth(session));
    }
    let api_key = extract_api_key(headers)?
        .or_else(|| provider.api_key.clone())
        .ok_or_else(|| ProxyError::NoApiKey("anthropic".to_string()))?;
    Ok(AnthropicAuth::ApiKey(api_key))
}

/// Send an Anthropic `/v1/messages` request authenticated by an OAuth
/// Bearer session.
///
/// Mutates the request body in place to (1) inject the Claude Code
/// prefix block required for the API to accept the OAuth token and
/// (2) strip `cache_control.ttl` (the OAuth path rejects TTL). Both
/// transformations live in `claude_credentials` so the proxy and the
/// CLI client share one source of truth.
///
/// Header construction is delegated to
/// [`AnthropicAdapter::oauth_headers`] — there are no inline magic
/// strings in this function. See crosslink #386 (and #272, #338).
async fn send_oauth_anthropic_messages(
    client: &Client,
    provider: &ProviderConfig,
    session: &crate::oauth::OAuthSession,
    request: &mut Value,
    max_bytes: usize,
) -> Result<Response, ProxyError> {
    info!("[/v1/messages] Using OAuth session: {}", session.id);

    // CRITICAL co-requisites of every OAuth-authenticated request.
    crate::claude_credentials::inject_oauth_prefix_only(request);
    crate::claude_credentials::strip_cache_control_ttl(request);

    let url = format!("{}/v1/messages", normalize_base_url(&provider.base_url));
    let mut builder = client.post(&url).json(request);
    for (name, value) in
        crate::providers::AnthropicAdapter::oauth_headers(&session.credentials.access_token)
    {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let response = builder.send().await?;
    convert_response(response, max_bytes).await
}

/// Send an Anthropic `/v1/messages` request authenticated by an API
/// key.
///
/// Thin wrapper around [`forward_to_provider`] kept symmetric with
/// [`send_oauth_anthropic_messages`] so the dispatch site reads
/// uniformly. Crosslink #386.
async fn send_api_key_anthropic_messages(
    client: &Client,
    provider: &ProviderConfig,
    api_key: &ApiKey,
    request: &Value,
    max_bytes: usize,
) -> Result<Response, ProxyError> {
    let is_stream = request["stream"].as_bool().unwrap_or(false);
    let raw = forward_to_provider(
        client,
        provider,
        "anthropic",
        Some(api_key),
        "/v1/messages",
        request,
        is_stream,
    )
    .await?;
    convert_response(raw, max_bytes).await
}

/// Proxy Anthropic messages endpoint.
///
/// Handles OAuth Bearer token auth (with Claude Code system-prompt
/// injection) and falls back to API-key auth. The handler itself is
/// kept slim — parse, resolve auth, dispatch — with the OAuth-specific
/// transformations factored into [`crate::claude_credentials`] and the
/// per-mode send paths into [`send_oauth_anthropic_messages`] /
/// [`send_api_key_anthropic_messages`]. See crosslink #386.
async fn proxy_anthropic_messages(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, ProxyError> {
    let mut request: Value =
        serde_json::from_str(&body).map_err(|e| ProxyError::InvalidBody(e.to_string()))?;

    let provider = state
        .config
        .get_provider("anthropic")
        .ok_or_else(|| ProxyError::ProviderNotConfigured("anthropic".to_string()))?;

    let max_bytes = state.config.proxy.max_response_bytes;
    let response = match resolve_anthropic_auth(&headers, &state.oauth_store, provider)? {
        AnthropicAuth::Oauth(session) => {
            send_oauth_anthropic_messages(
                &state.client,
                provider,
                &session,
                &mut request,
                max_bytes,
            )
            .await
        }
        AnthropicAuth::ApiKey(api_key) => {
            send_api_key_anthropic_messages(&state.client, provider, &api_key, &request, max_bytes)
                .await
        }
    }?;
    complete_loop_iteration(&state).await;
    Ok(response)
}

/// Passthrough for unhandled routes
async fn proxy_passthrough(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response, ProxyError> {
    // Whitelist safe headers to forward — prevents credential leaks from
    // custom X-* headers or Authorization headers meant for other services.
    const SAFE_PASSTHROUGH_HEADERS: &[&str] = &[
        "accept",
        "accept-encoding",
        "accept-language",
        "user-agent",
        "content-type",
    ];
    let path = request.uri().path();
    let provider = state
        .config
        .active_provider()
        .ok_or_else(|| ProxyError::ProviderNotConfigured(state.config.proxy.target.clone()))?;

    let api_key = extract_api_key(&headers)?.or_else(|| provider.api_key.clone());
    if api_key.is_none() && !crate::config::is_local_provider_name(&state.config.proxy.target) {
        return Err(ProxyError::NoApiKey(state.config.proxy.target.clone()));
    }

    let url = format!("{}{}", normalize_base_url(&provider.base_url), path);
    debug!(url = %url, "Passthrough request");

    let mut req_builder = state.client.request(request.method().clone(), &url);

    for (key, value) in &headers {
        let key_lower = key.as_str().to_lowercase();
        if SAFE_PASSTHROUGH_HEADERS.contains(&key_lower.as_str()) {
            if let Ok(v) = value.to_str() {
                req_builder = req_builder.header(key.as_str(), v);
            }
        }
    }

    // Set auth header based on provider
    // Provider-owned auth headers via the adapter's get_headers method.
    // Previously this called a local `set_auth_header` helper that branched
    // on provider-name equality — the adapter trait is the correct
    // abstraction (crosslink #338).
    //
    // Crosslink #433: get_adapter now propagates an explicit error if
    // `state.config.proxy.target` is a typo'd name. This used to silently
    // fall back to OpenAIAdapter; the failure was invisible.
    let adapter = crate::providers::get_adapter(&state.config.proxy.target)
        .map_err(|e| ProxyError::InvalidBody(e.to_string()))?;
    for (k, v) in adapter_headers(adapter, api_key.as_ref()) {
        req_builder = req_builder.header(k.as_str(), v.as_str());
    }

    let response = req_builder.send().await?;
    convert_response(response, state.config.proxy.max_response_bytes).await
}

/// Determine which provider to use based on model name.
///
/// Delegates classification to the typed [`crate::providers::ProviderKind`]
/// enum (crosslink #332). When the model name does not match any known
/// prefix, falls back to `config.proxy.target` — preserving the contract
/// that callers can rely on a configured default when the model is opaque.
#[must_use]
pub fn determine_provider(model: &str, config: &AppConfig) -> String {
    if providers::is_openai_compatible_passthrough_target(&config.proxy.target) {
        return config.proxy.target.clone();
    }
    let kind = crate::providers::ProviderKind::from_model(model);
    if kind == crate::providers::ProviderKind::Unknown {
        return config.proxy.target.clone();
    }
    kind.name().to_string()
}

/// Extract API key from `Authorization` or `x-api-key` header.
///
/// Returns `Some(ApiKey)` if the header value parses AND passes
/// [`ApiKey::try_from_string`] validation (non-empty, ASCII, no control
/// chars). A header that fails validation is silently dropped to `None`
/// rather than returning an error — the header may be someone else's
/// garbage (malformed client, stale cookie) and the caller's fallback to
/// `provider.api_key` is the correct recovery. See crosslink #256.
fn extract_api_key(headers: &HeaderMap) -> Result<Option<ApiKey>, ProxyError> {
    // Authorization header — must use `Bearer <key>` form.
    //
    // Crosslink #831: a client that sends a bare API key in
    // `Authorization` (no `Bearer ` prefix) plus a second key in
    // `x-api-key` would previously succeed using the second one, with
    // the first silently dropped. Combined with the proxy-level
    // fallback to `provider.api_key`, an operator could be billing an
    // unintended key with no audit trail. We now fail-closed: ANY
    // presence of `Authorization` that does not parse as
    // `Bearer <key>` is a 400 InvalidBody, not a silent fall-through
    // to alternate auth schemes.
    let authz = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let from_authz: Option<String> = if let Some(v) = authz {
        if let Some(key) = v.strip_prefix("Bearer ") {
            Some(key.to_string())
        } else {
            warn!(
                "Authorization header present but lacks 'Bearer ' prefix; \
                 rejecting request rather than falling through to x-api-key (crosslink #831)"
            );
            return Err(ProxyError::InvalidBody(
                "Authorization header must use 'Bearer <key>' format".to_string(),
            ));
        }
    } else {
        None
    };

    let raw = if let Some(k) = from_authz {
        k
    } else if let Some(s) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        s.to_string()
    } else {
        return Ok(None);
    };

    match ApiKey::try_from_string(raw) {
        Ok(key) => Ok(Some(key)),
        Err(e) => {
            // Structured log — never the raw value.
            warn!(
                error = %e,
                "Rejected malformed api_key supplied via request header"
            );
            Ok(None)
        }
    }
}

/// Read a [`reqwest::Response`] body up to `max_bytes`, returning the
/// accumulated data as a `Vec<u8>`.
///
/// Returns [`ProxyError::InvalidBody`] if the stream exceeds the limit or
/// any chunk yields an I/O error, preventing memory-exhaustion `DoS` from
/// hostile or buggy upstreams.
async fn read_body_capped(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, ProxyError> {
    use futures::StreamExt as _;

    let mut stream = response.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| ProxyError::InvalidBody(format!("upstream body read error: {e}")))?;
        if buf.len() + chunk.len() > max_bytes {
            return Err(ProxyError::InvalidBody(format!(
                "upstream response exceeded {max_bytes}-byte limit"
            )));
        }
        buf.extend_from_slice(&chunk);
    }

    Ok(buf)
}

/// Convert a non-streaming chat-completion response to `OpenAI` shape, also
/// extracting token usage if present.
///
/// `max_bytes` caps the body read; callers pass
/// `state.config.proxy.max_response_bytes` (default 50 MiB). A response body
/// that exceeds the limit returns [`ProxyError::InvalidBody`].
async fn convert_response_with_usage(
    response: reqwest::Response,
    max_bytes: usize,
    provider_name: &str,
) -> Result<(Response, Option<TokenUsage>), ProxyError> {
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = Response::builder().status(status);

    for (key, value) in response.headers() {
        if key != header::TRANSFER_ENCODING
            && key != header::CONTENT_LENGTH
            && (key != header::CONTENT_TYPE || !status.is_success())
        {
            if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(key.as_str(), v);
            }
        }
    }

    // Bounded read: prevents memory-DoS from a hostile or buggy upstream.
    let body = read_body_capped(response, max_bytes).await?;

    if !status.is_success() {
        let response = builder
            .body(Body::from(body))
            .map_err(|e| ProxyError::InvalidBody(format!("Failed to build response body: {e}")))?;
        return Ok((response, None));
    }

    let raw_json = serde_json::from_slice::<Value>(&body).map_err(|e| {
        ProxyError::InvalidBody(format!("Failed to parse provider response JSON: {e}"))
    })?;
    let adapter = get_adapter(provider_name).map_err(|e| ProxyError::InvalidBody(e.to_string()))?;
    let raw_usage = adapter.extract_token_usage(&raw_json);
    let transformed_json = adapter
        .transform_response(raw_json, false)
        .map_err(|e| ProxyError::InvalidBody(format!("Provider response transform failed: {e}")))?;

    let usage = raw_usage.or_else(|| {
        let usage = extract_usage_from_response(&transformed_json);
        (usage.total() > 0).then_some(usage)
    });

    let body = serde_json::to_vec(&transformed_json).map_err(|e| {
        ProxyError::InvalidBody(format!("Failed to serialize transformed response: {e}"))
    })?;

    let response = builder
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .map_err(|e| ProxyError::InvalidBody(format!("Failed to build response body: {e}")))?;
    Ok((response, usage))
}

/// Extract token usage from a provider's JSON response
/// Handles `OpenAI` format (`usage.prompt_tokens/completion_tokens`)
/// and Anthropic format (`usage.input_tokens/output_tokens`)
fn extract_usage_from_response(response: &Value) -> TokenUsage {
    let Some(usage) = response.get("usage") else {
        return TokenUsage::default();
    };

    // OpenAI format
    let input_tokens = usage
        .get("prompt_tokens")
        .and_then(serde_json::Value::as_u64)
        // Anthropic format
        .or_else(|| {
            usage
                .get("input_tokens")
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(0);

    let output_tokens = usage
        .get("completion_tokens")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            usage
                .get("output_tokens")
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(0);

    let cache_read_tokens = usage
        .get("cache_read_input_tokens")
        .and_then(serde_json::Value::as_u64)
        // OpenAI format uses prompt_tokens_details.cached_tokens
        .or_else(|| {
            usage
                .get("prompt_tokens_details")
                .and_then(|d| d.get("cached_tokens"))
                .and_then(serde_json::Value::as_u64)
        })
        .unwrap_or(0);

    let cache_write_tokens = usage
        .get("cache_creation_input_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    TokenUsage {
        input_tokens,
        output_tokens,
        cache_read_tokens,
        cache_write_tokens,
    }
}

/// Extract token usage from an SSE data line (JSON).
///
/// For Anthropic: look for `message_delta` with `usage` in the top-level.
/// For `OpenAI`: look for the final chunk with a `usage` field (when
/// `stream_options.include_usage` is set).
///
/// Returns `Some(TokenUsage)` if usage was found, `None` otherwise.
#[must_use]
pub fn extract_usage_from_sse_event(json: &Value) -> Option<TokenUsage> {
    // Anthropic: message_delta event carries cumulative usage at the top level
    if json.get("type").and_then(|t| t.as_str()) == Some("message_delta") {
        if let Some(usage) = json.get("usage") {
            let output_tokens = usage
                .get("output_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            // message_delta usually only has output_tokens; input is on message_start
            if output_tokens > 0 {
                return Some(TokenUsage {
                    input_tokens: 0,
                    output_tokens,
                    cache_read_tokens: 0,
                    cache_write_tokens: 0,
                });
            }
        }
    }

    // Anthropic: message_start carries input usage
    if json.get("type").and_then(|t| t.as_str()) == Some("message_start") {
        if let Some(usage) = json.get("message").and_then(|m| m.get("usage")) {
            let input_tokens = usage
                .get("input_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let cache_read = usage
                .get("cache_read_input_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let cache_write = usage
                .get("cache_creation_input_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if input_tokens > 0 || cache_read > 0 || cache_write > 0 {
                return Some(TokenUsage {
                    input_tokens,
                    output_tokens: 0,
                    cache_read_tokens: cache_read,
                    cache_write_tokens: cache_write,
                });
            }
        }
    }

    // OpenAI: final chunk with usage field (when stream_options.include_usage is true)
    if let Some(usage) = json.get("usage") {
        if usage.is_object() {
            let u = extract_usage_from_response(json);
            if u.total() > 0 {
                return Some(u);
            }
        }
    }

    None
}

/// SSE stream timeout duration: if no data arrives within this window,
/// the stream is considered stalled.
///
/// Tool-heavy agent turns can legitimately spend minutes with no provider
/// bytes while the model reasons about the next action. Keep this long enough
/// that normal agentic turns do not abort between tool batches.
pub const SSE_STREAM_TIMEOUT_SECS: u64 = 300;

/// Maximum bytes the SSE per-line accumulator may hold without a `\n`.
///
/// Caps memory against a hostile or broken upstream that streams payloads
/// without newlines. When exceeded, the accumulator is dropped and a
/// warning is logged. See crosslink #695.
pub const MAX_SSE_LINE_BYTES: usize = 1024 * 1024;

/// Forward request to upstream provider.
///
/// `api_key` is an [`ApiKey`] newtype — the raw secret only leaves it at
/// the adapter's `.get_headers(api_key)` call, which is the single audited
/// boundary where headers are constructed. See crosslink #256 and #338.
///
/// Auth headers are produced by the provider's
/// [`ProviderAdapter::get_headers`] implementation, not by a local
/// substring test on `base_url`. Previously three separate locations
/// (`forward_to_provider`, `set_auth_header`, and
/// `proxy_anthropic_messages`) each branched on a different discriminator
/// (URL substring vs. provider-name equality vs. hardcoded literal); now
/// only the adapter matters. Adding a new provider with unusual auth is
/// a one-file change instead of four.
async fn forward_to_provider<T: Serialize + Sync>(
    client: &Client,
    provider: &ProviderConfig,
    provider_name: &str,
    api_key: Option<&ApiKey>,
    path: &str,
    body: &T,
    is_stream: bool,
) -> Result<reqwest::Response, ProxyError> {
    let url = format!("{}{}", normalize_base_url(&provider.base_url), path);
    debug!(url = %url, stream = is_stream, "Forwarding to provider");

    let mut req = client.post(&url).json(body);

    // Provider-owned auth and protocol headers.
    //
    // Crosslink #433: unknown provider names now surface as
    // `InvalidBody(UnknownProvider…)` rather than a silent OpenAIAdapter
    // fallback. This is the auth-header construction site, so the failure
    // mode here was particularly silent (the request would have shipped
    // with Bearer auth pointed at the wrong endpoint).
    let adapter = crate::providers::get_adapter(provider_name)
        .map_err(|e| ProxyError::InvalidBody(e.to_string()))?;
    for (key, value) in adapter_headers(adapter, api_key) {
        req = req.header(key.as_str(), value.as_str());
    }

    // Operator-supplied passthrough headers from config (these override
    // the adapter's defaults — reqwest uses last-write-wins semantics).
    for (key, value) in &provider.headers {
        req = req.header(key.as_str(), value.as_str());
    }

    Ok(req.send().await?)
}

/// Forward request to upstream provider with raw Value body and custom headers.
/// Returns the raw `reqwest::Response` for inspection before conversion.
async fn forward_to_provider_raw_reqwest(
    client: &Client,
    provider: &ProviderConfig,
    path: &str,
    body: &Value,
    is_stream: bool,
    custom_headers: Vec<(String, String)>,
) -> Result<reqwest::Response, ProxyError> {
    let url = format!("{}{}", normalize_base_url(&provider.base_url), path);
    debug!(url = %url, stream = is_stream, "Forwarding to provider (raw/reqwest)");

    let mut req = client.post(&url).json(body);

    for (key, value) in custom_headers {
        req = req.header(key.as_str(), value.as_str());
    }

    for (key, value) in &provider.headers {
        req = req.header(key.as_str(), value.as_str());
    }

    Ok(req.send().await?)
}

/// Convert reqwest response to axum response.
///
/// `max_bytes` caps the body read; callers pass
/// `state.config.proxy.max_response_bytes` (default 50 MiB). A response body
/// that exceeds the limit returns [`ProxyError::InvalidBody`].
async fn convert_response(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Response, ProxyError> {
    let status = StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = Response::builder().status(status);

    // Copy response headers
    for (key, value) in response.headers() {
        if key != header::TRANSFER_ENCODING && key != header::CONTENT_LENGTH {
            if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
                builder = builder.header(key.as_str(), v);
            }
        }
    }

    // Bounded read — prevents memory-DoS from unbounded upstream bodies.
    let body = read_body_capped(response, max_bytes).await?;

    // If the response is HTML (error page from CDN/proxy), convert to a
    // clean JSON error instead of dumping raw HTML to the terminal.
    if !status.is_success() {
        let body_str = String::from_utf8_lossy(&body);
        if body_str.trim_start().starts_with('<') || body_str.contains("<!DOCTYPE") {
            let clean_error = serde_json::json!({
                "error": {
                    "type": "upstream_error",
                    "message": format!("Provider returned HTTP {status} with HTML error page"),
                    "status": status.as_u16()
                }
            });
            let json_body = serde_json::to_string(&clean_error).unwrap_or_default();
            return builder
                .header("content-type", "application/json")
                .body(Body::from(json_body))
                .map_err(|e| ProxyError::InvalidBody(format!("Failed to build error body: {e}")));
        }
    }

    builder
        .body(Body::from(body))
        .map_err(|e| ProxyError::InvalidBody(format!("Failed to build response body: {e}")))
}

/// Build a `ProxyState` from the given config, initializing all subsystems.
async fn build_proxy_state(config: AppConfig) -> anyhow::Result<ProxyState> {
    build_proxy_state_with_loop_control(config, None).await
}

async fn build_proxy_state_with_loop_control(
    config: AppConfig,
    loop_control: Option<Arc<LoopControl>>,
) -> anyhow::Result<ProxyState> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_mins(5))
        .build()?;

    // Load hooks from both OpenClaudia config and Claude Code settings.json
    let claude_hooks = load_claude_code_hooks();
    let merged_hooks = merge_hooks_config(config.hooks.clone(), claude_hooks);
    let hook_engine = HookEngine::new(merged_hooks);

    // Compaction overrides default to "no overrides" — the per-request
    // model-specific compactor is built in `compact_request_context` using
    // these as a delta on top of the model defaults (crosslink #489).
    let compactor_overrides = CompactionOverrides::default();

    // Initialize session manager
    let session_manager = Arc::new(RwLock::new(SessionManager::new(
        &config.session.persist_path,
    )));

    // Initialize plugin manager and discover plugins.
    // crosslink #893: try_new surfaces missing-$HOME as a warning rather
    // than degrading silently to a project-only manager.
    let mut plugin_manager = match PluginManager::try_new() {
        Ok(pm) => pm,
        Err(e) => {
            warn!(error = %e, "PluginManager: falling back to project-only search");
            PluginManager::new()
        }
    };
    let plugin_errors = plugin_manager.discover();
    for err in plugin_errors {
        warn!(error = %err, "Plugin discovery error");
    }
    let plugin_manager = Arc::new(plugin_manager);

    // Initialize MCP manager and connect to configured servers
    let mcp_manager = Arc::new(RwLock::new(McpManager::new()));
    connect_mcp_servers(&mcp_manager, &plugin_manager).await;

    // Initialize OAuth store for Claude Max authentication
    let oauth_store = Arc::new(OAuthStore::new());

    // Initialize VDD engine if enabled
    let vdd_engine = if config.vdd.enabled {
        if let Err(e) = config.vdd.validate(&config.proxy.target) {
            anyhow::bail!("VDD configuration error: {e}");
        }
        info!(
            mode = %config.vdd.mode,
            adversary = %config.vdd.adversary.provider,
            "VDD engine enabled"
        );
        Some(Arc::new(tokio::sync::Mutex::new(VddEngine::new(
            &config.vdd,
            &config,
            client.clone(),
        ))))
    } else {
        debug!(
            "VDD is disabled. To enable adversarial review, add vdd.enabled=true to config.yaml"
        );
        None
    };

    Ok(ProxyState {
        config: Arc::new(config),
        client,
        hook_engine,
        compactor_overrides,
        session_manager,
        plugin_manager,
        mcp_manager,
        oauth_store,
        vdd_engine,
        loop_control,
    })
}

/// Connect to all MCP servers discovered through plugins.
///
/// `pub` so the full-screen TUI can call it at startup (the proxy is
/// not the only consumer of MCP — wiring it on `cmd_tui` lets the
/// `list_mcp_resources` / `read_mcp_resource` tools dispatch into a
/// real manager instead of returning the "not wired" stub).
pub async fn connect_mcp_servers(
    mcp_manager: &Arc<RwLock<McpManager>>,
    plugin_manager: &Arc<PluginManager>,
) {
    let trusted = match mcp_trust_grants_from_startup() {
        Ok(trusted) => trusted,
        Err(error) => {
            warn!(
                env = "OPENCLAUDIA_TRUST_MCP_SERVERS",
                %error,
                "MCP startup is blocked because the host trust grant is invalid"
            );
            return;
        }
    };
    connect_mcp_servers_with_trust(mcp_manager, plugin_manager, &trusted).await;
}

/// Connect only MCP servers covered by an explicit host trust grant.
///
/// Entries use `plugin-id/server-name`. This function is public for trusted
/// host frontends and integration tests; it is not part of agent tool
/// dispatch.
#[allow(clippy::too_many_lines)]
pub async fn connect_mcp_servers_with_trust<S: std::hash::BuildHasher + Sync>(
    mcp_manager: &Arc<RwLock<McpManager>>,
    plugin_manager: &Arc<PluginManager>,
    trusted: &std::collections::HashSet<String, S>,
) {
    let mcp = mcp_manager.write().await;
    for (plugin, server) in plugin_manager.all_mcp_servers() {
        let trust_id = format!("{}/{}", plugin.id, server.name);
        if !trusted.contains(&trust_id) {
            if let Err(error) = mcp.disconnect(&server.name).await {
                warn!(
                    server = %server.name,
                    %error,
                    "Failed to terminate MCP server while revoking trust"
                );
            }
            warn!(
                plugin = %plugin.id,
                server = %server.name,
                trust_id,
                env = "OPENCLAUDIA_TRUST_MCP_SERVERS",
                "MCP server remains disconnected pending an explicit host trust grant"
            );
            continue;
        }
        info!(
            plugin = %plugin.id,
            server = %server.name,
            trust_id,
            transport = %server.transport,
            env_grants = server.env.len(),
            header_grants = server.headers.len(),
            "Applying explicit MCP server trust grant"
        );
        let tool_timeout = server.timeout.map(std::time::Duration::from_millis);
        match server.transport.as_str() {
            "stdio" => {
                if server.always_load.is_some() {
                    warn!(
                        server = %server.name,
                        plugin = %plugin.name(),
                        "MCP alwaysLoad is a tool-search hint; OpenClaudia currently eager-loads MCP tools"
                    );
                }
                if !server.headers.is_empty() || server.headers_helper.is_some() {
                    warn!(
                        server = %server.name,
                        plugin = %plugin.name(),
                        "MCP stdio server declares HTTP headers; ignoring headers for stdio transport"
                    );
                }
                if let Some(command) = &server.command {
                    let args: Vec<&str> = server
                        .args
                        .iter()
                        .map(std::string::String::as_str)
                        .collect();
                    match mcp
                        .connect_stdio_with_env_and_timeout(
                            &server.name,
                            command,
                            &args,
                            &server.env,
                            tool_timeout,
                        )
                        .await
                    {
                        Ok(()) => {
                            info!(server = %server.name, plugin = %plugin.name(), "Connected MCP (stdio)");
                        }
                        Err(e) => {
                            warn!(server = %server.name, error = %e, "MCP connect failed");
                        }
                    }
                }
            }
            "http" => {
                if let Some(url) = &server.url {
                    if server.always_load.is_some() {
                        warn!(
                            server = %server.name,
                            plugin = %plugin.name(),
                            "MCP alwaysLoad is a tool-search hint; OpenClaudia currently eager-loads MCP tools"
                        );
                    }
                    match mcp
                        .connect_http_with_headers_helper_and_timeout(
                            &server.name,
                            url,
                            &server.headers,
                            server.headers_helper.as_deref(),
                            tool_timeout,
                        )
                        .await
                    {
                        Ok(()) => {
                            info!(server = %server.name, plugin = %plugin.name(), "Connected MCP (http)");
                        }
                        Err(e) => {
                            warn!(server = %server.name, error = %e, "MCP connect failed");
                        }
                    }
                }
            }
            _ => {
                warn!(server = %server.name, transport = %server.transport, "Unknown MCP transport");
            }
        }
    }
    let count = mcp.server_count().await;
    drop(mcp);
    if count > 0 {
        info!(connected = count, "MCP servers initialized");
    }
}

fn mcp_trust_grants_from_startup() -> Result<std::collections::HashSet<String>, String> {
    let Some(value) = std::env::var_os("OPENCLAUDIA_TRUST_MCP_SERVERS") else {
        return Ok(std::collections::HashSet::new());
    };
    let value = value
        .to_str()
        .ok_or_else(|| "OPENCLAUDIA_TRUST_MCP_SERVERS contains non-Unicode data".to_string())?;
    let mut trusted = std::collections::HashSet::new();
    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let valid = entry
            .split_once('/')
            .is_some_and(|(plugin, server)| !plugin.is_empty() && !server.is_empty());
        if !valid || entry.contains('*') {
            return Err(format!(
                "invalid MCP trust id '{entry}'; expected exact plugin-id/server-name"
            ));
        }
        trusted.insert(entry.to_string());
    }
    Ok(trusted)
}

/// Fire the `SessionStart` hook and return the session ID.
async fn fire_session_start(state: &ProxyState) -> String {
    let session_id = {
        let mut sm = state.session_manager.write().await;
        let id = sm.get_or_create_session().id.clone();
        drop(sm);
        id
    };

    let start_input = HookInput::new(HookEvent::SessionStart).with_session_id(&session_id);
    let start_result = state
        .hook_engine
        .run(HookEvent::SessionStart, &start_input)
        .await;

    info!(
        session_id = %session_id,
        hooks_allowed = start_result.allowed,
        "Session started"
    );

    session_id
}

/// Start the proxy server.
///
/// # Errors
///
/// Returns an error if binding the TCP listener or serving fails.
pub async fn start_server(config: AppConfig) -> anyhow::Result<()> {
    let addr = format!("{}:{}", config.proxy.host, config.proxy.port);
    let state = build_proxy_state(config).await?;
    fire_session_start(&state).await;

    let app = create_router(state);

    info!(address = %addr, "Starting OpenClaudia proxy server");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Start the proxy server with graceful shutdown support.
///
/// # Errors
///
/// Returns an error if binding the TCP listener, serving, or VDD
/// configuration validation fails.
pub async fn start_server_with_shutdown(
    config: AppConfig,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let addr = format!("{}:{}", config.proxy.host, config.proxy.port);

    // Build the proxy state + fire SessionStart hook via the SAME
    // helpers that `start_server` uses. The previous implementation of
    // this function duplicated ~150 lines of initialization (Client,
    // hook merging, compactor, session manager, plugin
    // discovery, MCP connect loop, OAuth store, VDD engine setup,
    // SessionStart hook). Any change to provisioning had to land in
    // two places — classic stovepipe. See crosslink #246.
    let state = build_proxy_state(config).await?;
    fire_session_start(&state).await;

    let app = create_router(state);

    info!(address = %addr, "Starting OpenClaudia proxy server (with shutdown support)");

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    // Use axum's graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            // Wait for shutdown signal
            loop {
                if shutdown_rx.changed().await.is_err() || *shutdown_rx.borrow() {
                    info!("Shutdown signal received, stopping server...");
                    break;
                }
            }
        })
        .await?;

    Ok(())
}

/// Start the proxy server in loop mode.
///
/// A loop iteration is one completed proxied chat/completion response. After
/// each iteration this fires the `Stop` hook with the iteration number; the
/// server shuts down when a Stop hook blocks or when `max_iterations` is
/// reached (`0` means unlimited until Ctrl+C).
///
/// # Errors
///
/// Returns an error if binding the TCP listener, serving, or VDD
/// configuration validation fails.
pub async fn start_loop_server(config: AppConfig, max_iterations: u32) -> anyhow::Result<()> {
    let addr = format!("{}:{}", config.proxy.host, config.proxy.port);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let control = Arc::new(LoopControl::new(max_iterations, shutdown_tx.clone()));
    let state = build_proxy_state_with_loop_control(config, Some(control.clone())).await?;
    let session_id = fire_session_start(&state).await;
    let session_manager = Arc::clone(&state.session_manager);

    let app = create_router(state);

    info!(
        address = %addr,
        max_iterations = if max_iterations == 0 {
            "unlimited".to_string()
        } else {
            max_iterations.to_string()
        },
        "Starting OpenClaudia loop proxy server"
    );

    let ctrl_c_shutdown = shutdown_tx.clone();
    tokio::spawn(async move {
        if matches!(tokio::signal::ctrl_c().await, Ok(())) {
            info!("Received Ctrl+C, initiating loop shutdown...");
            let _ = ctrl_c_shutdown.send(true);
        }
    });

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            loop {
                if shutdown_rx.changed().await.is_err() || *shutdown_rx.borrow() {
                    info!("Loop shutdown signal received, stopping server...");
                    break;
                }
            }
        })
        .await?;

    let completed = control.completed_iterations();
    let handoff = format!(
        "Loop mode completed after {completed} iteration(s).\nSession ended after {completed} iteration(s)."
    );
    let mut sm = session_manager.write().await;
    let active_session_matches = sm
        .get_session()
        .is_some_and(|session| session.id == session_id);
    if active_session_matches {
        if let Err(e) = sm.end_session(Some(&handoff)) {
            warn!(error = %e, "Failed to persist session at end of loop mode");
        }
    }

    info!(completed, "Loop mode ended");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal `AppConfig` suitable for unit tests.
    /// `AppConfig` does not implement `Default`; we deserialise from a
    /// minimal JSON value that satisfies every required field.
    fn minimal_config(target: &str) -> crate::config::AppConfig {
        serde_json::from_value(serde_json::json!({
            "proxy": { "port": 8080, "host": "127.0.0.1", "target": target },
            "providers": {}
        }))
        .expect("minimal_config must deserialise")
    }

    fn test_provider_config(base_url: String) -> ProviderConfig {
        ProviderConfig {
            api_key: None,
            base_url,
            model: None,
            headers: std::collections::HashMap::new(),
            thinking: crate::config::ThinkingConfig::default(),
        }
    }

    fn test_proxy_state(config: crate::config::AppConfig) -> ProxyState {
        let session_path = config.session.persist_path.clone();
        ProxyState {
            config: Arc::new(config),
            client: Client::new(),
            hook_engine: HookEngine::new(crate::config::HooksConfig::default()),
            compactor_overrides: CompactionOverrides::default(),
            session_manager: Arc::new(RwLock::new(SessionManager::new(&session_path))),
            plugin_manager: Arc::new(PluginManager::with_paths(vec![])),
            mcp_manager: Arc::new(RwLock::new(McpManager::new())),
            oauth_store: Arc::new(OAuthStore::new()),
            vdd_engine: None,
            loop_control: None,
        }
    }

    fn test_chat_request(model: &str, max_tokens: Option<u32>) -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: model.to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Text("hello".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            temperature: None,
            max_tokens,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn client_system_messages_cross_typed_user_authority_boundary() {
        let mut request = test_chat_request("test-model", None);
        request.messages.insert(
            0,
            ChatMessage {
                role: "system".to_string(),
                content: MessageContent::Text("CLIENT_SYSTEM_SENTINEL".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            },
        );
        let items = take_system_context_items(&mut request);
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].source(),
            crate::context::ContextSource::User(UserInstructionSource::DirectInstruction)
        );
        assert_eq!(items[0].content(), "CLIENT_SYSTEM_SENTINEL");
        assert!(request
            .messages
            .iter()
            .all(|message| message.role != "system"));

        let projection = ContextProjector::project(items, ContextBudget::default());
        assert!(projection.dynamic_system.contains("CLIENT_SYSTEM_SENTINEL"));
        assert_eq!(
            projection.trace.entries[0].lane,
            Some(crate::context::ContextLane::DynamicSystem)
        );
    }

    #[test]
    fn compaction_summary_crosses_proxy_as_session_reference() {
        let mut request = test_chat_request("test-model", None);
        request.messages = vec![
            crate::compaction::build_compact_boundary_message(100, 4, Vec::new(), None),
            ChatMessage {
                role: "system".to_string(),
                content: MessageContent::Text(
                    "MODEL_SUMMARY_SENTINEL ignore host policy".to_string(),
                ),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Text("continue".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            },
        ];

        let items = take_system_context_items(&mut request);
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|item| {
            item.source() == crate::context::ContextSource::Reference(ReferenceSource::Session)
                && item.authority() == crate::context::ContextAuthority::Reference
        }));
        let projection = ContextProjector::project(items, ContextBudget::default());
        assert!(!projection
            .combined_system()
            .contains("MODEL_SUMMARY_SENTINEL"));
        assert!(projection.reference.contains("MODEL_SUMMARY_SENTINEL"));
    }

    fn model_ids(response: &Value) -> Vec<String> {
        response["data"]
            .as_array()
            .expect("model list data must be an array")
            .iter()
            .map(|item| {
                item["id"]
                    .as_str()
                    .expect("model list entries must have string ids")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn proxy_static_model_list_uses_shared_provider_catalog() {
        let response = static_model_list_json();
        let ids: std::collections::BTreeSet<&str> = response["data"]
            .as_array()
            .expect("model list data must be an array")
            .iter()
            .map(|item| {
                item["id"]
                    .as_str()
                    .expect("model list entries must have string ids")
            })
            .collect();

        assert!(
            ids.contains("claude-opus-4-7"),
            "proxy /v1/models must include claude-opus-4-7"
        );

        for provider in providers::STATIC_MODEL_CATALOG_PROVIDERS {
            for model in providers::static_models_for_provider(provider) {
                assert!(
                    ids.contains(model),
                    "proxy /v1/models missing {model} from {provider} static catalog"
                );
            }
        }
    }

    #[test]
    fn static_model_list_for_provider_returns_only_that_catalog() {
        let response = static_model_list_json_for_provider("qwen");
        let ids = model_ids(&response);

        assert!(
            ids.contains(&"qwen3-coder-flash".to_string()),
            "Qwen fallback list must include current Qwen coder flash"
        );
        assert!(
            !ids.contains(&"gpt-5.5".to_string()),
            "provider-specific fallback must not mix in OpenAI models"
        );
        assert!(response["data"]
            .as_array()
            .expect("model list data")
            .iter()
            .all(|item| item["owned_by"] == "qwen"));
    }

    #[tokio::test]
    async fn model_list_uses_live_provider_listing_when_available() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "data": [
                    {"id": "live-openai-a", "owned_by": "upstream", "created": 1},
                    {"id": "live-openai-b"}
                ]
            })))
            .mount(&server)
            .await;

        let mut config = minimal_config("openai");
        config
            .providers
            .insert("openai".to_string(), test_provider_config(server.uri()));
        let state = test_proxy_state(config);

        let response = model_list_json_for_state(&state).await;
        let ids = model_ids(&response);

        assert_eq!(ids, vec!["live-openai-a", "live-openai-b"]);
        assert_eq!(response["data"][0]["owned_by"], "upstream");
        assert_eq!(response["data"][0]["created"], 1);
        assert_eq!(response["data"][1]["owned_by"], "openai");
    }

    #[tokio::test]
    async fn model_list_falls_back_to_active_static_catalog_when_listing_unsupported() {
        let mut config = minimal_config("anthropic");
        config.providers.insert(
            "anthropic".to_string(),
            test_provider_config("http://127.0.0.1:9".to_string()),
        );
        let state = test_proxy_state(config);

        let response = model_list_json_for_state(&state).await;
        let ids = model_ids(&response);

        assert!(
            ids.contains(&"claude-opus-4-7".to_string()),
            "Anthropic fallback list must include Claude Opus 4.7"
        );
        assert!(
            !ids.contains(&"gpt-5.5".to_string()),
            "active-provider fallback must not return a cross-provider list"
        );
        assert!(response["data"]
            .as_array()
            .expect("model list data")
            .iter()
            .all(|item| item["owned_by"] == "anthropic"));
    }

    async fn upstream_response(
        status: StatusCode,
        content_type: &str,
        body: String,
    ) -> reqwest::Response {
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let content_type = content_type.to_string();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let reason = status.canonical_reason().unwrap_or("OK");
                let header = format!(
                    "HTTP/1.1 {} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
                    status.as_u16(),
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
            }
        });

        reqwest::get(format!("http://{addr}")).await.expect("GET")
    }

    async fn response_json(response: Response) -> Value {
        let body = response.into_body();
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("response body must be JSON")
    }

    #[tokio::test]
    async fn convert_response_with_usage_transforms_anthropic_chat_completion() {
        let raw = serde_json::json!({
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-6",
            "stop_reason": "end_turn",
            "content": [
                {"type": "text", "text": "hello from claude"}
            ],
            "usage": {
                "input_tokens": 12,
                "output_tokens": 5,
                "cache_read_input_tokens": 3,
                "cache_creation_input_tokens": 2
            }
        });
        let upstream = upstream_response(StatusCode::OK, "application/json", raw.to_string()).await;

        let (response, usage) = convert_response_with_usage(upstream, 1024 * 1024, "anthropic")
            .await
            .expect("valid Anthropic response should transform");

        assert_eq!(response.status(), StatusCode::OK);
        let usage = usage.expect("raw Anthropic usage should be preserved");
        assert_eq!(usage.input_tokens, 12);
        assert_eq!(usage.output_tokens, 5);
        assert_eq!(usage.cache_read_tokens, 3);
        assert_eq!(usage.cache_write_tokens, 2);

        let body = response_json(response).await;
        assert_eq!(body["object"], "chat.completion");
        assert_eq!(
            body["choices"][0]["message"]["content"],
            "hello from claude"
        );
        assert_eq!(body["usage"]["prompt_tokens"], 12);
        assert_eq!(body["usage"]["completion_tokens"], 5);
    }

    #[tokio::test]
    async fn convert_response_with_usage_rejects_malformed_openai_response() {
        let upstream = upstream_response(
            StatusCode::OK,
            "application/json",
            serde_json::json!({"id": "bad", "choices": []}).to_string(),
        )
        .await;

        let err = convert_response_with_usage(upstream, 1024 * 1024, "openai")
            .await
            .expect_err("empty choices must fail at provider boundary");

        match err {
            ProxyError::InvalidBody(msg) => {
                assert!(msg.contains("Provider response transform failed"), "{msg}");
                assert!(msg.contains("empty 'choices' array"), "{msg}");
            }
            other => panic!("expected InvalidBody, got {other:?}"),
        }
    }

    #[test]
    fn extract_device_submit_fields_accepts_separate_code_and_state() {
        let payload = serde_json::json!({
            "code": "auth_code_123",
            "state": "state_abc"
        });

        let (code, state) =
            extract_device_submit_fields(&payload).expect("valid payload should parse");

        assert_eq!(code, "auth_code_123");
        assert_eq!(state, "state_abc");
    }

    #[test]
    fn extract_device_submit_fields_accepts_combined_code_and_state() {
        let payload = serde_json::json!({
            "code": "auth_code_123#state_abc"
        });

        let (code, state) =
            extract_device_submit_fields(&payload).expect("combined payload should parse");

        assert_eq!(code, "auth_code_123");
        assert_eq!(state, "state_abc");
    }

    #[test]
    fn extract_device_submit_fields_prefers_combined_state_over_payload_state() {
        let payload = serde_json::json!({
            "code": "auth_code_123#state_from_code",
            "state": "state_from_payload"
        });

        let (code, state) =
            extract_device_submit_fields(&payload).expect("combined payload should parse");

        assert_eq!(code, "auth_code_123");
        assert_eq!(state, "state_from_code");
    }

    #[test]
    fn extract_device_submit_fields_rejects_missing_or_malformed_code() {
        for payload in [
            serde_json::json!({ "state": "state_abc" }),
            serde_json::json!({ "code": "", "state": "state_abc" }),
            serde_json::json!({ "code": "   ", "state": "state_abc" }),
            serde_json::json!({ "code": 123, "state": "state_abc" }),
            serde_json::json!({ "code": "#state_abc" }),
        ] {
            let err = extract_device_submit_fields(&payload)
                .expect_err("missing or malformed code must fail");
            match err {
                ProxyError::InvalidBody(msg) => assert!(msg.contains("'code'"), "{msg}"),
                other => panic!("expected InvalidBody, got {other:?}"),
            }
        }
    }

    #[test]
    fn extract_device_submit_fields_rejects_missing_or_malformed_state() {
        for payload in [
            serde_json::json!({ "code": "auth_code_123" }),
            serde_json::json!({ "code": "auth_code_123", "state": "" }),
            serde_json::json!({ "code": "auth_code_123", "state": "   " }),
            serde_json::json!({ "code": "auth_code_123", "state": 123 }),
            serde_json::json!({ "code": "auth_code_123#" }),
        ] {
            let err = extract_device_submit_fields(&payload)
                .expect_err("missing or malformed state must fail");
            match err {
                ProxyError::InvalidBody(msg) => assert!(msg.contains("'state'"), "{msg}"),
                other => panic!("expected InvalidBody, got {other:?}"),
            }
        }
    }

    #[test]
    fn device_flow_page_surfaces_structured_proxy_errors_as_text() {
        let html = include_str!("../assets/device_flow.html");

        assert!(html.contains("function errorMessage(data)"), "{html}");
        assert!(html.contains("data.error.message"), "{html}");
        assert!(html.contains("status.textContent = message"), "{html}");
        assert!(
            html.contains(
                "showTextStatus('Authentication failed: ' + errorMessage(data), 'error')"
            ),
            "{html}"
        );
    }

    // ── Phase 2 spec-pinning tests (#552 / spec #537 B-proxy) ────────────────

    /// Spec — `normalize_base_url` strips trailing slashes and `/v1` suffix.
    /// Prevents double `/v1/v1` when endpoint paths include the prefix.
    #[test]
    fn normalize_base_url_strips_v1_and_slash() {
        assert_eq!(
            normalize_base_url("https://api.anthropic.com/v1/"),
            "https://api.anthropic.com"
        );
        assert_eq!(
            normalize_base_url("https://api.anthropic.com/v1"),
            "https://api.anthropic.com"
        );
        assert_eq!(
            normalize_base_url("https://api.openai.com/"),
            "https://api.openai.com"
        );
        assert_eq!(
            normalize_base_url("https://api.openai.com"),
            "https://api.openai.com"
        );
        // URL with no /v1 and no trailing slash is unchanged
        assert_eq!(
            normalize_base_url("http://localhost:8080"),
            "http://localhost:8080"
        );
    }

    /// Spec — `determine_provider` maps model prefixes to the right provider name.
    #[test]
    fn determine_provider_model_prefix_routing() {
        let config = minimal_config("anthropic");

        assert_eq!(determine_provider("claude-opus-4", &config), "anthropic");
        assert_eq!(
            determine_provider("claude-sonnet-4-6", &config),
            "anthropic"
        );
        assert_eq!(
            determine_provider("anthropic/claude-3", &config),
            "anthropic"
        );

        assert_eq!(determine_provider("gpt-4", &config), "openai");
        assert_eq!(determine_provider("gpt-4o", &config), "openai");
        assert_eq!(determine_provider("o1-preview", &config), "openai");
        assert_eq!(determine_provider("o3-mini", &config), "openai");
        assert_eq!(determine_provider("o4-pro", &config), "openai");

        assert_eq!(determine_provider("gemini-2.5-pro", &config), "google");
        assert_eq!(determine_provider("gemini-flash", &config), "google");

        assert_eq!(determine_provider("deepseek-r1", &config), "deepseek");

        assert_eq!(determine_provider("qwen-long", &config), "qwen");
        assert_eq!(determine_provider("qwq-32b", &config), "qwen");
        assert_eq!(determine_provider("qvq-72b", &config), "qwen");

        assert_eq!(determine_provider("glm-4", &config), "zai");

        assert_eq!(determine_provider("M2-her", &config), "minimax");
    }

    /// Spec — unknown model prefix falls back to `config.proxy.target`.
    #[test]
    fn determine_provider_unknown_model_uses_target() {
        let config = minimal_config("deepseek");
        assert_eq!(
            determine_provider("some-unknown-model-xyz", &config),
            "deepseek"
        );
    }

    #[test]
    fn determine_provider_preserves_openai_compatible_aggregator_targets() {
        let config = minimal_config("openrouter");
        assert_eq!(
            determine_provider("anthropic/claude-sonnet-4-6", &config),
            "openrouter"
        );
        assert_eq!(determine_provider("openai/gpt-5.2", &config), "openrouter");

        let config = minimal_config("opencode");
        assert_eq!(determine_provider("qwen3.7-plus", &config), "opencode");
        assert_eq!(determine_provider("kimi-k2.7-code", &config), "opencode");
    }

    // ── Usage extraction (B1-adjacent: token tracking in proxy) ──────────────

    /// Spec — `extract_usage_from_sse_event` handles Anthropic `message_start`.
    #[test]
    fn extract_usage_message_start_anthropic() {
        let event = serde_json::json!({
            "type": "message_start",
            "message": {
                "usage": {
                    "input_tokens": 42,
                    "cache_read_input_tokens": 10,
                    "cache_creation_input_tokens": 5
                }
            }
        });
        let usage = extract_usage_from_sse_event(&event).expect("must extract usage");
        assert_eq!(usage.input_tokens, 42);
        assert_eq!(usage.cache_read_tokens, 10);
        assert_eq!(usage.cache_write_tokens, 5);
        assert_eq!(usage.output_tokens, 0);
    }

    /// Spec — `extract_usage_from_sse_event` handles Anthropic `message_delta`.
    #[test]
    fn extract_usage_message_delta_anthropic() {
        let event = serde_json::json!({
            "type": "message_delta",
            "usage": { "output_tokens": 75 }
        });
        let usage = extract_usage_from_sse_event(&event).expect("must extract output usage");
        assert_eq!(usage.output_tokens, 75);
        assert_eq!(usage.input_tokens, 0);
    }

    /// Spec — `extract_usage_from_sse_event` handles `OpenAI` final chunk with `usage`.
    #[test]
    fn extract_usage_openai_final_chunk() {
        let event = serde_json::json!({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50
            },
            "choices": []
        });
        let usage = extract_usage_from_sse_event(&event).expect("must extract OpenAI usage");
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
    }

    /// Spec — `extract_usage_from_sse_event` returns `None` for non-usage events.
    #[test]
    fn extract_usage_returns_none_for_non_usage_events() {
        let event = serde_json::json!({
            "type": "content_block_start",
            "content_block": { "type": "text" }
        });
        assert!(
            extract_usage_from_sse_event(&event).is_none(),
            "non-usage events must return None"
        );
    }

    /// Spec — `extract_usage_from_sse_event` returns `None` when all counts are zero.
    #[test]
    fn extract_usage_returns_none_for_all_zero_counts() {
        let event = serde_json::json!({
            "usage": { "prompt_tokens": 0, "completion_tokens": 0 }
        });
        // OpenAI zero-usage chunk must not produce Some(zero)
        assert!(
            extract_usage_from_sse_event(&event).is_none(),
            "all-zero usage must return None"
        );
    }

    /// Spec - `SSE_STREAM_TIMEOUT_SECS` constant is 5 minutes.
    #[test]
    fn sse_stream_timeout_constant_pinned_at_5_minutes() {
        assert_eq!(
            SSE_STREAM_TIMEOUT_SECS, 300,
            "SSE_STREAM_TIMEOUT_SECS must stay at 5 minutes unless timeout UX is revalidated"
        );
    }

    /// Spec — `ProxyError::HookBlocked` maps to 403 Forbidden.
    #[test]
    fn proxy_error_hook_blocked_is_403() {
        let err = ProxyError::HookBlocked("dangerous tool".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Spec — enterprise policy denial maps to 403 Forbidden.
    #[test]
    fn proxy_error_policy_denied_is_403() {
        let err = ProxyError::PolicyDenied("model denied".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn enforce_model_policy_rejects_unlisted_model() {
        let mut config = minimal_config("anthropic");
        config
            .policy
            .model_allowlist
            .insert("claude-opus-4-7".to_string());
        let state = test_proxy_state(config);
        let request = test_chat_request("not-allowed", Some(64));

        let err = enforce_model_policy(&state, &request).expect_err("model must be denied");

        assert!(matches!(err, ProxyError::PolicyDenied(_)));
        assert!(
            err.to_string().contains("not-allowed"),
            "denial should name the rejected model"
        );
    }

    #[tokio::test]
    async fn enforce_token_policy_rejects_request_cap() {
        let mut config = minimal_config("anthropic");
        config.policy.max_request_tokens = Some(10);
        let state = test_proxy_state(config);
        let request = test_chat_request("claude-opus-4-7", Some(64));

        let err = enforce_token_policy(&state, &request, 11)
            .await
            .expect_err("request estimate over cap must be denied");

        assert!(matches!(err, ProxyError::PolicyDenied(_)));
        assert!(
            err.to_string().contains("per-request"),
            "denial should identify the request cap"
        );
    }

    #[tokio::test]
    async fn enforce_token_policy_rejects_projected_session_cap() {
        let mut config = minimal_config("anthropic");
        config.policy.max_session_tokens = Some(100);
        let state = test_proxy_state(config);
        {
            let mut sm = state.session_manager.write().await;
            sm.get_or_create_session();
            let session = sm
                .get_session_mut()
                .expect("get_or_create_session must create a mutable session");
            session.record_actual_usage(TokenUsage {
                input_tokens: 40,
                output_tokens: 10,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            });
            drop(sm);
        }
        let request = test_chat_request("claude-opus-4-7", Some(25));

        let err = enforce_token_policy(&state, &request, 26)
            .await
            .expect_err("projected session total over cap must be denied");

        assert!(matches!(err, ProxyError::PolicyDenied(_)));
        assert!(
            err.to_string().contains("per-session"),
            "denial should identify the session cap"
        );
    }

    #[tokio::test]
    async fn enforce_token_policy_allows_projected_session_exactly_at_cap() {
        let mut config = minimal_config("anthropic");
        config.policy.max_session_tokens = Some(100);
        let state = test_proxy_state(config);
        {
            let mut sm = state.session_manager.write().await;
            sm.get_or_create_session();
            let session = sm
                .get_session_mut()
                .expect("get_or_create_session must create a mutable session");
            session.record_actual_usage(TokenUsage {
                input_tokens: 40,
                output_tokens: 10,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            });
            drop(sm);
        }
        let request = test_chat_request("claude-opus-4-7", Some(25));

        enforce_token_policy(&state, &request, 25)
            .await
            .expect("exact session cap boundary must be allowed");
    }

    fn test_vdd_finding(status: crate::vdd::FindingStatus) -> crate::vdd::Finding {
        crate::vdd::Finding {
            id: "finding-1".to_string(),
            severity: crate::vdd::Severity::High,
            cwe: Some("CWE-79".to_string()),
            description: "test finding".to_string(),
            file_path: Some("src/lib.rs".to_string()),
            line_range: Some((1, 1)),
            status,
            adversary_reasoning: "reason".to_string(),
            iteration: 1,
        }
    }

    #[test]
    fn vdd_advisory_hook_plan_reports_conflict_for_genuine_findings() {
        let result = VddResult::Advisory(crate::vdd::VddAdvisoryResult {
            findings: vec![
                test_vdd_finding(crate::vdd::FindingStatus::Genuine),
                test_vdd_finding(crate::vdd::FindingStatus::FalsePositive),
            ],
            context_observation: Some(crate::context::ContextItem::reference(
                "vdd.test",
                crate::context::ReferenceSource::Vdd,
                "vdd:test",
                "review context",
                crate::context::ContextFreshness::Turn,
                700,
            )),
            static_analysis: vec![],
            tokens_used: crate::session::TokenUsage::default(),
        });

        let plan = vdd_result_hook_plan(&result);
        let events: Vec<HookEvent> = plan.iter().map(|(event, _)| *event).collect();

        assert_eq!(events[0], HookEvent::PostAdversaryReview);
        assert!(events.contains(&HookEvent::VddConflict));
        assert!(!events.contains(&HookEvent::VddConverged));
        assert_eq!(plan[0].1["genuine_findings"], 1);
    }

    #[test]
    fn vdd_blocking_hook_plan_reports_conflict_and_convergence() {
        let mut session = crate::vdd::review::VddSession::new(crate::config::VddMode::Blocking);
        session.total_findings = 3;
        session.total_genuine = 1;
        session.total_false_positives = 2;
        session.finalize(true, "clean pass");

        let result = VddResult::Blocking(crate::vdd::VddBlockingResult {
            final_response: serde_json::json!({"ok": true}),
            session,
            crosslink_issues: vec!["issue-1".to_string()],
        });

        let plan = vdd_result_hook_plan(&result);
        let events: Vec<HookEvent> = plan.iter().map(|(event, _)| *event).collect();

        assert_eq!(events[0], HookEvent::PostAdversaryReview);
        assert!(events.contains(&HookEvent::VddConflict));
        assert!(events.contains(&HookEvent::VddConverged));
    }

    #[test]
    fn vdd_skipped_hook_plan_reports_post_review_only() {
        let result = VddResult::Skipped("Response too short".to_string());
        let plan = vdd_result_hook_plan(&result);

        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].0, HookEvent::PostAdversaryReview);
        assert_eq!(plan[0].1["result"], "skipped");
        assert_eq!(plan[0].1["reason"], "Response too short");
    }

    /// Spec — `ProxyError::NoApiKey` maps to 401 Unauthorized.
    #[test]
    fn proxy_error_no_api_key_is_401() {
        let err = ProxyError::NoApiKey("anthropic".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // `strip_cache_control_ttl` lives in `claude_credentials` since
    // crosslink #386 — its tests are colocated there. The proxy is
    // covered indirectly by the dispatch-level tests below.

    // ── #304: bounded body read + swallowed-error fixes ──────────────────────

    /// Spec — `read_body_capped` rejects a body that exceeds `max_bytes`.
    ///
    /// A hostile upstream streaming more than the configured limit must receive
    /// a `ProxyError::InvalidBody` rather than silently exhausting allocator
    /// memory (memory-DoS vector closed by #304 / crosslink #352).
    #[tokio::test]
    async fn read_body_capped_rejects_oversize_body() {
        use tokio::io::AsyncWriteExt as _;

        // Spin up a minimal HTTP/1.1 server that returns a 6-byte body,
        // then cap the read at 4 bytes. The helper must return InvalidBody.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello!")
                    .await;
            }
        });

        let response = reqwest::get(format!("http://{addr}")).await.expect("GET");
        let err = read_body_capped(response, 4).await.unwrap_err();

        match err {
            ProxyError::InvalidBody(msg) => {
                assert!(
                    msg.contains("exceeded") || msg.contains("limit"),
                    "error message must describe the size limit, got: {msg}"
                );
            }
            other => panic!("expected InvalidBody, got: {other:?}"),
        }
    }

    /// Spec — `read_body_capped` surfaces async I/O errors as `InvalidBody`.
    ///
    /// When an upstream closes the connection mid-stream, the error must reach
    /// the caller rather than being swallowed into an empty buffer that feeds
    /// opaque downstream failures (fixed in #304).
    #[tokio::test]
    async fn read_body_capped_surfaces_stream_error() {
        // Use a listener that accepts the connection then immediately drops it
        // without sending an HTTP response, forcing a read error.
        use tokio::io::AsyncWriteExt as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        // Spawn a task that sends a valid HTTP header but closes the body mid-
        // stream so reqwest sees a truncated response.
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Send an HTTP/1.1 response with content-length but no body.
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                    .await;
                // Drop stream → connection reset → reqwest body read error.
            }
        });

        let response = reqwest::get(format!("http://{addr}"))
            .await
            .expect("initial response");

        let result = read_body_capped(response, 1024 * 1024).await;
        assert!(
            result.is_err(),
            "a truncated upstream body must surface as an error, not empty Ok"
        );
        assert!(
            matches!(result.unwrap_err(), ProxyError::InvalidBody(_)),
            "truncated body error must be InvalidBody variant"
        );
    }

    /// Spec — utilization ppm computation is correct and requires no float casts.
    ///
    /// Regression for #304 finding 1 & 2: the `#[allow(clippy::cast_*)]`
    /// suppressions are gone; the integer ppm formula must produce the same
    /// percentage as the float formula it replaced, with no truncation at
    /// typical usize values.
    #[test]
    fn utilization_ppm_matches_expected_percentage() {
        // Simulate a 128 k-token context window with 64 k tokens used (50 %).
        let context_window: usize = 128_000;
        let estimated_input: usize = 64_000;

        let utilization_ppm = estimated_input
            .saturating_mul(1_000_000)
            .checked_div(context_window)
            .unwrap_or(0);

        // 50.0 % → 500_000 ppm
        assert_eq!(utilization_ppm, 500_000, "50 % must be 500_000 ppm");

        // Rendered string must be "50.0%"
        let rendered = format!(
            "{}.{}%",
            utilization_ppm / 10_000,
            (utilization_ppm % 10_000) / 1_000
        );
        assert_eq!(rendered, "50.0%");

        // No truncation: a large context window (>= 2^32) must still work on
        // 64-bit targets without wrapping.
        let large_window: usize = 1_000_000_000; // 1 billion tokens
        let large_input: usize = 750_000_000; // 75 %
        let ppm_large = large_input
            .saturating_mul(1_000_000)
            .checked_div(large_window)
            .unwrap_or(0);
        assert_eq!(
            ppm_large, 750_000,
            "75 % of 1B-token window must be 750_000 ppm"
        );
    }
}

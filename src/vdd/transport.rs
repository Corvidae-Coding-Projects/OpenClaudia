//! HTTP transport for the VDD loop: adversary + builder request plumbing.

use reqwest::Client;
use serde_json::Value;
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::config::{AppConfig, ProviderConfig, VddConfig};
use crate::providers::{get_adapter, ApiKey, ProviderAdapter};
use crate::proxy::ChatCompletionRequest;
use crate::session::TokenUsage;

use crate::vdd::error::VddError;
use crate::vdd::helpers::truncate_output;

/// Runtime authentication material for a provider used by VDD.
///
/// This is deliberately separate from [`VddConfig`]: startup can select
/// account-backed auth for the current session without persisting bearer tokens
/// into `.openclaudia/config.yaml`.
#[derive(Clone, PartialEq, Eq)]
pub enum VddProviderAuth {
    ApiKey(ApiKey),
    ClaudeAgentSdk(crate::claude_agent_sdk::ClaudeAgentSdk),
    ClaudeCodeToken(crate::secrets::OAuthToken),
    CodexResponses(crate::codex_credentials::CodexResponsesAuth),
    None,
}

impl std::fmt::Debug for VddProviderAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.write_str("VddProviderAuth::ApiKey(<redacted>)"),
            Self::ClaudeAgentSdk(_) => f.write_str("VddProviderAuth::ClaudeAgentSdk"),
            Self::ClaudeCodeToken(_) => f.write_str("VddProviderAuth::ClaudeCodeToken(<redacted>)"),
            Self::CodexResponses(auth) => f
                .debug_tuple("VddProviderAuth::CodexResponses")
                .field(auth)
                .finish(),
            Self::None => f.write_str("VddProviderAuth::None"),
        }
    }
}

impl VddProviderAuth {
    #[must_use]
    pub const fn api_key(api_key: ApiKey) -> Self {
        Self::ApiKey(api_key)
    }

    #[must_use]
    pub const fn claude_code_token(token: crate::secrets::OAuthToken) -> Self {
        Self::ClaudeCodeToken(token)
    }

    #[must_use]
    pub const fn claude_agent_sdk(sdk: crate::claude_agent_sdk::ClaudeAgentSdk) -> Self {
        Self::ClaudeAgentSdk(sdk)
    }

    #[must_use]
    pub const fn codex_responses(auth: crate::codex_credentials::CodexResponsesAuth) -> Self {
        Self::CodexResponses(auth)
    }
}

async fn complete_vdd_via_claude_agent_sdk(
    sdk: &crate::claude_agent_sdk::ClaudeAgentSdk,
    provider_name: &str,
    request: &Value,
    timeout: std::time::Duration,
) -> Result<crate::claude_agent_sdk::ClaudeAgentSdkTurn, String> {
    if !provider_name.eq_ignore_ascii_case("anthropic") {
        return Err(format!(
            "Claude Agent SDK auth can only be used with Anthropic, got '{provider_name}'"
        ));
    }
    let turn = tokio::time::timeout(timeout, sdk.complete_turn(request, "high"))
        .await
        .map_err(|_| {
            format!(
                "Claude Agent SDK VDD request timed out after {} seconds",
                timeout.as_secs()
            )
        })?
        .map_err(|error| error.to_string())?;
    if !turn.tool_calls.is_empty() {
        return Err(format!(
            "Claude Agent SDK returned {} tool call(s) to a no-tools VDD request",
            turn.tool_calls.len()
        ));
    }
    if turn.content.trim().is_empty() {
        return Err("Claude Agent SDK completed VDD request without assistant content".to_string());
    }
    Ok(turn)
}

fn claude_agent_sdk_response_json(turn: &crate::claude_agent_sdk::ClaudeAgentSdkTurn) -> Value {
    serde_json::json!({
        "content": [{"type": "text", "text": turn.content}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": turn.usage.input_tokens,
            "output_tokens": turn.usage.output_tokens,
            "cache_read_input_tokens": turn.usage.cache_read_tokens,
            "cache_creation_input_tokens": turn.usage.cache_write_tokens,
        }
    })
}

/// Forward a request to a provider and return the raw reqwest response.
///
/// URL composition is entirely delegated to the adapter via `endpoint`
/// (the return value of `ProviderAdapter::chat_endpoint`), so provider-specific
/// path conventions (e.g. Google's `/v1beta/models/{model}:generateContent`)
/// are handled in the adapter, not here.
pub async fn forward_request(
    client: &Client,
    provider_name: &str,
    provider: &ProviderConfig,
    endpoint: &str,
    body: &Value,
    mut headers: crate::secrets::SensitiveHeaders,
) -> Result<reqwest::Response, String> {
    let base_url = provider
        .base_url
        .trim_end_matches('/')
        .trim_end_matches("/v1")
        .trim_end_matches('/');

    // endpoint already encodes the full provider-specific path, including
    // any model name or version segment (e.g. Google's v1beta path). OAuth
    // and Codex-backed flows may provide a fully-qualified endpoint.
    let url = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        format!("{base_url}{endpoint}")
    };

    crate::provider_transport::validate_endpoint(provider_name, &url)
        .map_err(|error| error.to_string())?;

    debug!("VDD: Sending verifier request");

    headers.extend(&provider.headers);
    let req = headers
        .apply(client.post(&url).json(body))
        .map_err(|error| format!("invalid provider headers: {error}"))?;

    let response = crate::provider_transport::send(req)
        .await
        .map_err(|error| error.to_string())?;
    if response.status().is_success() {
        return Ok(response);
    }

    let status = response.status();
    let body = read_bounded_failure_body(response).await?;
    Err(format!(
        "provider returned HTTP {status}: {}",
        headers.sanitize_diagnostic(&body)
    ))
}

async fn read_bounded_failure_body(
    response: reqwest::Response,
) -> Result<Zeroizing<String>, String> {
    use futures::StreamExt as _;

    let mut stream = response.bytes_stream();
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|error| format!("failed to read provider error body: {error}"))?;
        let remaining = crate::secrets::MAX_DIAGNOSTIC_INPUT_BYTES.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining || remaining == 0 {
            break;
        }
    }
    Ok(Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned()))
}

fn chat_messages_as_values(request: &ChatCompletionRequest) -> Result<Vec<Value>, VddError> {
    request
        .messages
        .iter()
        .map(|message| {
            serde_json::to_value(message)
                .map_err(|e| VddError::AdversaryRequestFailed(format!("message encode: {e}")))
        })
        .collect()
}

fn responses_text_from_json(json: &Value) -> Option<String> {
    if let Some(text) = json.get("output_text").and_then(Value::as_str) {
        return Some(text.to_string());
    }

    let mut out = String::new();
    for item in json.get("output").and_then(Value::as_array)? {
        for part in item
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(text) = part
                .get("text")
                .and_then(Value::as_str)
                .or_else(|| part.get("content").and_then(Value::as_str))
            {
                out.push_str(text);
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

fn responses_usage_from_json(json: &Value) -> TokenUsage {
    let Some(usage) = json.get("usage") else {
        return TokenUsage::default();
    };
    let raw_input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_read_tokens = usage
        .get("input_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_write_tokens = usage
        .get("input_tokens_details")
        .and_then(|details| details.get("cache_write_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    TokenUsage {
        input_tokens: raw_input_tokens
            .saturating_sub(cache_read_tokens)
            .saturating_sub(cache_write_tokens),
        output_tokens: usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_read_tokens,
        cache_write_tokens,
    }
}

fn responses_text_from_sse(raw: &str) -> Result<(String, TokenUsage), VddError> {
    let mut text = String::new();
    let mut usage = TokenUsage::default();
    let mut completed = false;
    for line in raw.lines() {
        let Some(data) = line.trim_start().strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let json = serde_json::from_str::<Value>(data).map_err(|e| {
            VddError::AdversaryRequestFailed(format!("responses SSE frame decode: {e}"))
        })?;
        match json.get("type").and_then(Value::as_str).unwrap_or_default() {
            "response.output_text.delta" => {
                if let Some(delta) = json.get("delta").and_then(Value::as_str) {
                    text.push_str(delta);
                }
            }
            "response.completed" => {
                if let Some(response) = json.get("response") {
                    crate::pipeline::validate_openai_responses_terminal_json(response).map_err(
                        |error| {
                            VddError::AdversaryRequestFailed(format!(
                                "responses terminal validation: {error}"
                            ))
                        },
                    )?;
                    completed = true;
                    usage.accumulate(&responses_usage_from_json(response));
                    if text.is_empty() {
                        if let Some(final_text) = responses_text_from_json(response) {
                            text = final_text;
                        }
                    }
                }
            }
            "response.failed" | "response.incomplete" => {
                let message = json
                    .get("response")
                    .and_then(|response| response.get("error"))
                    .or_else(|| json.get("error"))
                    .and_then(|error| {
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .or_else(|| error.as_str())
                    })
                    .unwrap_or("Responses API request failed");
                return Err(VddError::AdversaryRequestFailed(message.to_string()));
            }
            _ => {}
        }
    }
    if !completed {
        return Err(VddError::AdversaryRequestFailed(
            "Responses stream ended before response.completed".to_string(),
        ));
    }
    if text.trim().is_empty() {
        return Err(VddError::AdversaryRequestFailed(
            "Responses verifier completed without assistant content".to_string(),
        ));
    }
    Ok((text, usage))
}

fn validate_vdd_chat_terminal(
    adapter: &dyn ProviderAdapter,
    response: &Value,
) -> Result<(), String> {
    let normalized = adapter
        .transform_response(response.clone(), false)
        .map_err(|error| format!("provider response transform failed: {error}"))?;
    let terminal = crate::pipeline::validate_chat_completion_terminal(&normalized)?;
    if terminal != crate::pipeline::ProviderTerminalOutcome::Completed {
        return Err("VDD provider requested tools in a no-tools verification turn".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep the bounded VDD request and its budget settlement in one transaction.
async fn send_to_codex_responses(
    run: &crate::tools::ToolRunContext,
    client: &Client,
    auth: &crate::codex_credentials::CodexResponsesAuth,
    request: &ChatCompletionRequest,
    timeout: std::time::Duration,
    timeout_secs: u64,
) -> Result<(String, TokenUsage), VddError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let messages = chat_messages_as_values(request)?;
    let mut body =
        crate::pipeline::build_openai_responses_request(&request.model, &messages, "medium")
            .map_err(|e| VddError::AdversaryRequestFailed(format!("responses transform: {e}")))?;
    body["stream"] = Value::Bool(false);
    if let Some(obj) = body.as_object_mut() {
        obj.remove("tools");
        obj.remove("tool_choice");
        obj.remove("parallel_tool_calls");
        obj.remove("include");
    }
    let provider_budget = crate::provider_budget::reserve_provider_call(
        run,
        "openai",
        &request.model,
        &mut body,
        u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
    )
    .map_err(|error| {
        VddError::AdversaryRequestFailed(format!("Run budget denied provider call: {error}"))
    })?;
    crate::codex_credentials::finalize_chatgpt_responses_request(&mut body);

    let endpoint = format!(
        "{}/responses",
        crate::proxy::normalize_base_url(crate::codex_credentials::CODEX_CHATGPT_BASE_URL)
    );
    crate::provider_transport::validate_endpoint("openai", &endpoint)
        .map_err(|error| VddError::AdversaryRequestFailed(error.to_string()))?;
    let headers = auth
        .headers()
        .map_err(|error| VddError::AdversaryRequestFailed(error.to_string()))?;
    let req = headers
        .apply(client.post(endpoint).json(&body))
        .map_err(|error| VddError::AdversaryRequestFailed(error.to_string()))?;

    let response = tokio::time::timeout_at(
        deadline,
        crate::provider_transport::send_until(req, deadline),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: "openai".to_string(),
        elapsed_secs: timeout_secs,
    })?
    .map_err(|e| VddError::AdversaryRequestFailed(format!("responses request: {e}")))?;
    let status = response.status();

    if !status.is_success() {
        let raw = tokio::time::timeout_at(deadline, read_bounded_failure_body(response))
            .await
            .map_err(|_| VddError::Timeout {
                provider: "openai".to_string(),
                elapsed_secs: timeout_secs,
            })?
            .map_err(|e| VddError::AdversaryRequestFailed(format!("responses body: {e}")))?;
        let diagnostic = headers.sanitize_diagnostic(&raw);
        return Err(VddError::AdversaryRequestFailed(format!(
            "responses request failed with HTTP {status}: {}",
            truncate_output(diagnostic.as_str(), 1000)
        )));
    }

    let raw = zeroize::Zeroizing::new(
        tokio::time::timeout_at(
            deadline,
            crate::provider_transport::read_body_capped(
                response,
                crate::provider_transport::MAX_JSON_RESPONSE_BYTES,
            ),
        )
        .await
        .map_err(|_| VddError::Timeout {
            provider: "openai".to_string(),
            elapsed_secs: timeout_secs,
        })?
        .map_err(|e| VddError::AdversaryRequestFailed(format!("responses body: {e}")))?,
    );
    let raw_text = String::from_utf8_lossy(&raw);

    let result = if raw_text
        .lines()
        .any(|line| line.trim_start().starts_with("data:"))
    {
        responses_text_from_sse(&raw_text)
    } else {
        let json = serde_json::from_slice::<Value>(&raw)
            .map_err(|e| VddError::AdversaryRequestFailed(format!("responses JSON decode: {e}")))?;
        crate::pipeline::validate_openai_responses_terminal_json(&json).map_err(|error| {
            VddError::AdversaryRequestFailed(format!("responses terminal validation: {error}"))
        })?;
        let text = responses_text_from_json(&json).unwrap_or_default();
        if text.trim().is_empty() {
            return Err(VddError::AdversaryRequestFailed(
                "Responses verifier completed without assistant content".to_string(),
            ));
        }
        Ok((text, responses_usage_from_json(&json)))
    };
    if let Ok((_, usage)) = &result {
        provider_budget.reconcile(usage).map_err(|error| {
            VddError::AdversaryRequestFailed(format!(
                "Provider budget reconciliation failed: {error}"
            ))
        })?;
    }
    result
}

fn adversary_headers_and_endpoint(
    config: &VddConfig,
    provider_config: &ProviderConfig,
    adapter: &dyn ProviderAdapter,
    request: &ChatCompletionRequest,
    transformed: &mut Value,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(crate::secrets::SensitiveHeaders, String), VddError> {
    match runtime_auth {
        Some(VddProviderAuth::ApiKey(api_key)) => Ok((
            adapter.get_headers(api_key),
            adapter.chat_endpoint(&request.model),
        )),
        Some(VddProviderAuth::ClaudeCodeToken(token)) => {
            if !config.adversary.provider.eq_ignore_ascii_case("anthropic") {
                return Err(VddError::ConfigError(format!(
                    "Claude Code auth can only be used with Anthropic VDD adversary, got '{}'",
                    config.adversary.provider
                )));
            }
            crate::claude_credentials::inject_oauth_prefix_only(transformed)
                .map_err(|error| VddError::ConfigError(error.to_string()))?;
            Ok((
                crate::claude_credentials::get_oauth_headers(token)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
                crate::claude_credentials::get_oauth_endpoint(&request.model)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
            ))
        }
        Some(VddProviderAuth::None) => Ok((
            crate::secrets::SensitiveHeaders::new(),
            adapter.chat_endpoint(&request.model),
        )),
        None => {
            let api_key = config
                .adversary
                .api_key
                .as_ref()
                .or(provider_config.api_key.as_ref())
                .ok_or_else(|| {
                    VddError::ConfigError(format!(
                        "No API key for adversary provider '{}'",
                        config.adversary.provider
                    ))
                })?;
            Ok((
                adapter.get_headers(api_key),
                adapter.chat_endpoint(&request.model),
            ))
        }
        Some(VddProviderAuth::CodexResponses(_) | VddProviderAuth::ClaudeAgentSdk(_)) => {
            unreachable!("handled above")
        }
    }
}

/// Send a request to the adversary provider. Returns (`response_text`, `token_usage`).
///
/// Per-request timeout — crosslink #496 — wraps both the HTTP send and the
/// body read in `tokio::time::timeout` so a hung adversary cannot block the
/// VDD loop indefinitely. The timeout is configurable via
/// `vdd.adversary.request_timeout_seconds` (default 120 s).
#[allow(clippy::too_many_lines)] // Keep the bounded VDD request and its budget settlement in one transaction.
pub async fn send_to_adversary(
    run: &crate::tools::ToolRunContext,
    client: &Client,
    config: &VddConfig,
    app_config: &AppConfig,
    request: &ChatCompletionRequest,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(String, TokenUsage), VddError> {
    let provider_config = app_config
        .providers
        .get(&config.adversary.provider)
        .ok_or_else(|| {
            VddError::ConfigError(format!(
                "Adversary provider '{}' not configured in providers section",
                config.adversary.provider
            ))
        })?;

    let timeout_secs = config.adversary.request_timeout_seconds;
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let deadline = tokio::time::Instant::now() + timeout;

    if let Some(VddProviderAuth::CodexResponses(auth)) = runtime_auth {
        if !config.adversary.provider.eq_ignore_ascii_case("openai") {
            return Err(VddError::ConfigError(format!(
                "Codex Responses auth can only be used with OpenAI VDD adversary, got '{}'",
                config.adversary.provider
            )));
        }
        return send_to_codex_responses(run, client, auth, request, timeout, timeout_secs).await;
    }

    // Crosslink #433: a typo in `config.adversary.provider` now surfaces
    // as `ConfigError` instead of being silently mapped to OpenAIAdapter.
    let adapter = get_adapter(&config.adversary.provider)
        .map_err(|e| VddError::ConfigError(e.to_string()))?;
    let mut transformed = adapter
        .transform_request(request)
        .map_err(|e| VddError::AdversaryRequestFailed(e.to_string()))?;

    if let Some(VddProviderAuth::ClaudeAgentSdk(sdk)) = runtime_auth {
        let provider_budget = crate::provider_budget::reserve_provider_call(
            run,
            &config.adversary.provider,
            &request.model,
            &mut transformed,
            u64::from(config.adversary.max_tokens),
        )
        .map_err(|error| {
            VddError::AdversaryRequestFailed(format!("Run budget denied provider call: {error}"))
        })?;
        let turn = complete_vdd_via_claude_agent_sdk(
            sdk,
            &config.adversary.provider,
            &transformed,
            timeout,
        )
        .await
        .map_err(VddError::AdversaryRequestFailed)?;
        provider_budget.reconcile(&turn.usage).map_err(|error| {
            VddError::AdversaryRequestFailed(format!(
                "Provider budget reconciliation failed: {error}"
            ))
        })?;
        info!(
            response_length = turn.content.len(),
            "VDD: Received Agent SDK adversary response"
        );
        return Ok((turn.content, turn.usage));
    }

    let (headers, endpoint) = adversary_headers_and_endpoint(
        config,
        provider_config,
        adapter,
        request,
        &mut transformed,
        runtime_auth,
    )?;

    let provider_name = config.adversary.provider.clone();
    let provider_budget = crate::provider_budget::reserve_provider_call(
        run,
        &provider_name,
        &request.model,
        &mut transformed,
        u64::from(config.adversary.max_tokens),
    )
    .map_err(|error| {
        VddError::AdversaryRequestFailed(format!("Run budget denied provider call: {error}"))
    })?;

    let response = tokio::time::timeout_at(
        deadline,
        forward_request(
            client,
            &config.adversary.provider,
            provider_config,
            &endpoint,
            &transformed,
            headers,
        ),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: provider_name.clone(),
        elapsed_secs: timeout_secs,
    })?
    .map_err(VddError::AdversaryRequestFailed)?;

    // The body consumes the remainder of the same deadline rather than
    // receiving a fresh timeout window after response headers arrive.
    let response_json: Value = tokio::time::timeout_at(
        deadline,
        crate::provider_transport::read_json_capped(
            response,
            crate::provider_transport::MAX_JSON_RESPONSE_BYTES,
        ),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: provider_name.clone(),
        elapsed_secs: timeout_secs,
    })?
    .map_err(|e| VddError::AdversaryRequestFailed(e.to_string()))?;
    validate_vdd_chat_terminal(adapter, &response_json)
        .map_err(VddError::AdversaryRequestFailed)?;

    // Crosslink #479: route extraction through the ProviderAdapter trait
    // so provider-specific response shapes (Gemini, Ollama, Anthropic) are
    // handled the same way they are on the main proxy path. The previous
    // free functions silently returned an empty string / zero tokens for
    // any provider whose response shape they did not hardcode.
    let text = adapter
        .extract_response_text(&response_json)
        .unwrap_or_default();
    if text.trim().is_empty() {
        return Err(VddError::AdversaryRequestFailed(
            "Adversary completed without assistant content".to_string(),
        ));
    }
    let tokens = adapter
        .extract_token_usage(&response_json)
        .unwrap_or_default();
    provider_budget.reconcile(&tokens).map_err(|error| {
        VddError::AdversaryRequestFailed(format!("Provider budget reconciliation failed: {error}"))
    })?;

    // Always log at INFO level for debugging, truncated
    info!(
        response_length = text.len(),
        "VDD: Received adversary response ({} chars)",
        text.len()
    );

    if config.tracking.log_adversary_responses {
        // Log first 1000 chars to see what we're getting
        info!(
            "VDD: Adversary response preview: {}",
            truncate_output(&text, 1000)
        );
    }

    Ok((text, tokens))
}

/// Send a revision request back to the builder provider.
///
/// Symmetric per-request timeout for the builder (crosslink #496). The
/// builder revision call sits inside the same blocking-loop iteration as
/// the adversary call, so a hung builder would block the loop just as
/// badly. The timeout reuses the adversary's configured value for
/// simplicity — they're the same upper bound on how long any single
/// HTTP round-trip in the loop is allowed to take.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Existing transport boundary plus the shared run authority.
pub async fn send_to_builder(
    run: &crate::tools::ToolRunContext,
    client: &Client,
    config: &VddConfig,
    app_config: &AppConfig,
    request: &ChatCompletionRequest,
    provider_name: &str,
    api_key: Option<&ApiKey>,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(String, Value, TokenUsage), VddError> {
    let provider_config = app_config.providers.get(provider_name).ok_or_else(|| {
        VddError::BuilderRevisionFailed(format!(
            "Builder provider '{provider_name}' not configured"
        ))
    })?;

    // Crosslink #433: explicit error for an unknown builder provider
    // name, no silent OpenAIAdapter fallback.
    let adapter = get_adapter(provider_name).map_err(|e| VddError::ConfigError(e.to_string()))?;
    let timeout_secs = config.adversary.request_timeout_seconds;
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let deadline = tokio::time::Instant::now() + timeout;

    if let Some(VddProviderAuth::CodexResponses(auth)) = runtime_auth {
        if !provider_name.eq_ignore_ascii_case("openai") {
            return Err(VddError::ConfigError(format!(
                "Codex Responses auth can only be used with OpenAI builder, got '{provider_name}'"
            )));
        }
        let (text, tokens) =
            send_to_codex_responses(run, client, auth, request, timeout, timeout_secs).await?;
        return Ok((
            text.clone(),
            serde_json::json!({ "output_text": text }),
            tokens,
        ));
    }

    let mut transformed = adapter
        .transform_request(request)
        .map_err(|e| VddError::BuilderRevisionFailed(e.to_string()))?;

    if let Some(VddProviderAuth::ClaudeAgentSdk(sdk)) = runtime_auth {
        let provider_budget = crate::provider_budget::reserve_provider_call(
            run,
            provider_name,
            &request.model,
            &mut transformed,
            u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
        )
        .map_err(|error| {
            VddError::BuilderRevisionFailed(format!("Run budget denied provider call: {error}"))
        })?;
        let turn = complete_vdd_via_claude_agent_sdk(sdk, provider_name, &transformed, timeout)
            .await
            .map_err(VddError::BuilderRevisionFailed)?;
        provider_budget.reconcile(&turn.usage).map_err(|error| {
            VddError::BuilderRevisionFailed(format!(
                "Provider budget reconciliation failed: {error}"
            ))
        })?;
        let response = claude_agent_sdk_response_json(&turn);
        return Ok((turn.content, response, turn.usage));
    }

    let (headers, endpoint) = match runtime_auth {
        Some(VddProviderAuth::ApiKey(api_key)) => (
            adapter.get_headers(api_key),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::ClaudeCodeToken(token)) => {
            if !provider_name.eq_ignore_ascii_case("anthropic") {
                return Err(VddError::ConfigError(format!(
                    "Claude Code auth can only be used with Anthropic builder, got '{provider_name}'"
                )));
            }
            crate::claude_credentials::inject_oauth_prefix_only(&mut transformed)
                .map_err(|error| VddError::ConfigError(error.to_string()))?;
            (
                crate::claude_credentials::get_oauth_headers(token)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
                crate::claude_credentials::get_oauth_endpoint(&request.model)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
            )
        }
        Some(VddProviderAuth::None) => (
            crate::secrets::SensitiveHeaders::new(),
            adapter.chat_endpoint(&request.model),
        ),
        None => (
            api_key.map(|k| adapter.get_headers(k)).unwrap_or_default(),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::CodexResponses(_) | VddProviderAuth::ClaudeAgentSdk(_)) => {
            unreachable!("handled above")
        }
    };

    let pname = provider_name.to_string();
    let provider_budget = crate::provider_budget::reserve_provider_call(
        run,
        provider_name,
        &request.model,
        &mut transformed,
        u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
    )
    .map_err(|error| {
        VddError::BuilderRevisionFailed(format!("Run budget denied provider call: {error}"))
    })?;

    let response = tokio::time::timeout_at(
        deadline,
        forward_request(
            client,
            provider_name,
            provider_config,
            &endpoint,
            &transformed,
            headers,
        ),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: pname.clone(),
        elapsed_secs: timeout_secs,
    })?
    .map_err(VddError::BuilderRevisionFailed)?;

    let response_json: Value = tokio::time::timeout_at(
        deadline,
        crate::provider_transport::read_json_capped(
            response,
            crate::provider_transport::MAX_JSON_RESPONSE_BYTES,
        ),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: pname,
        elapsed_secs: timeout_secs,
    })?
    .map_err(|e| VddError::BuilderRevisionFailed(e.to_string()))?;
    validate_vdd_chat_terminal(adapter, &response_json).map_err(VddError::BuilderRevisionFailed)?;

    // Crosslink #479: trait dispatch instead of hardcoded shape matching.
    let text = adapter
        .extract_response_text(&response_json)
        .unwrap_or_default();
    if text.trim().is_empty() {
        return Err(VddError::BuilderRevisionFailed(
            "Builder completed without assistant content".to_string(),
        ));
    }
    let tokens = adapter
        .extract_token_usage(&response_json)
        .unwrap_or_default();
    provider_budget.reconcile(&tokens).map_err(|error| {
        VddError::BuilderRevisionFailed(format!("Provider budget reconciliation failed: {error}"))
    })?;

    Ok((text, response_json, tokens))
}

/// Send a verification request through the builder's provider.
/// Reuses the same HTTP plumbing as `send_to_builder` but with a
/// simpler interface (no revision response needed).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Existing transport boundary plus the shared run authority.
pub async fn send_to_builder_for_verification(
    run: &crate::tools::ToolRunContext,
    client: &Client,
    config: &VddConfig,
    app_config: &AppConfig,
    request: &ChatCompletionRequest,
    provider_name: &str,
    api_key: Option<&ApiKey>,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(String, TokenUsage), VddError> {
    let provider_config = app_config.providers.get(provider_name).ok_or_else(|| {
        VddError::ConfigError(format!(
            "Builder provider '{provider_name}' not configured — \
             cannot run verification agent"
        ))
    })?;

    // Crosslink #433: explicit error for an unknown verifier provider name.
    let timeout_secs = config.adversary.request_timeout_seconds;
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let deadline = tokio::time::Instant::now() + timeout;

    if let Some(VddProviderAuth::CodexResponses(auth)) = runtime_auth {
        if !provider_name.eq_ignore_ascii_case("openai") {
            return Err(VddError::ConfigError(format!(
                "Codex Responses auth can only be used with OpenAI verifier, got '{provider_name}'"
            )));
        }
        return send_to_codex_responses(run, client, auth, request, timeout, timeout_secs).await;
    }

    let adapter = get_adapter(provider_name).map_err(|e| VddError::ConfigError(e.to_string()))?;
    let mut transformed = adapter
        .transform_request(request)
        .map_err(|e| VddError::AdversaryRequestFailed(format!("verifier transform: {e}")))?;

    if let Some(VddProviderAuth::ClaudeAgentSdk(sdk)) = runtime_auth {
        let provider_budget = crate::provider_budget::reserve_provider_call(
            run,
            provider_name,
            &request.model,
            &mut transformed,
            u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
        )
        .map_err(|error| {
            VddError::AdversaryRequestFailed(format!(
                "Run budget denied verifier provider call: {error}"
            ))
        })?;
        let turn = complete_vdd_via_claude_agent_sdk(sdk, provider_name, &transformed, timeout)
            .await
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!("verifier request: {error}"))
            })?;
        provider_budget.reconcile(&turn.usage).map_err(|error| {
            VddError::AdversaryRequestFailed(format!(
                "Verifier budget reconciliation failed: {error}"
            ))
        })?;
        return Ok((turn.content, turn.usage));
    }

    let (headers, endpoint) = match runtime_auth {
        Some(VddProviderAuth::ApiKey(api_key)) => (
            adapter.get_headers(api_key),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::ClaudeCodeToken(token)) => {
            if !provider_name.eq_ignore_ascii_case("anthropic") {
                return Err(VddError::ConfigError(format!(
                    "Claude Code auth can only be used with Anthropic verifier, got '{provider_name}'"
                )));
            }
            crate::claude_credentials::inject_oauth_prefix_only(&mut transformed)
                .map_err(|error| VddError::ConfigError(error.to_string()))?;
            (
                crate::claude_credentials::get_oauth_headers(token)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
                crate::claude_credentials::get_oauth_endpoint(&request.model)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
            )
        }
        Some(VddProviderAuth::None) => (
            crate::secrets::SensitiveHeaders::new(),
            adapter.chat_endpoint(&request.model),
        ),
        None => (
            api_key.map(|k| adapter.get_headers(k)).unwrap_or_default(),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::CodexResponses(_) | VddProviderAuth::ClaudeAgentSdk(_)) => {
            unreachable!("handled above")
        }
    };

    let pname = provider_name.to_string();
    let provider_budget = crate::provider_budget::reserve_provider_call(
        run,
        provider_name,
        &request.model,
        &mut transformed,
        u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
    )
    .map_err(|error| {
        VddError::AdversaryRequestFailed(format!(
            "Run budget denied verifier provider call: {error}"
        ))
    })?;

    let response = tokio::time::timeout_at(
        deadline,
        forward_request(
            client,
            provider_name,
            provider_config,
            &endpoint,
            &transformed,
            headers,
        ),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: pname.clone(),
        elapsed_secs: timeout_secs,
    })?
    .map_err(|e| VddError::AdversaryRequestFailed(format!("verifier request: {e}")))?;

    let response_json: Value = tokio::time::timeout_at(
        deadline,
        crate::provider_transport::read_json_capped(
            response,
            crate::provider_transport::MAX_JSON_RESPONSE_BYTES,
        ),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: pname,
        elapsed_secs: timeout_secs,
    })?
    .map_err(|e| VddError::AdversaryRequestFailed(format!("verifier response: {e}")))?;
    validate_vdd_chat_terminal(adapter, &response_json).map_err(|error| {
        VddError::AdversaryRequestFailed(format!("verifier terminal validation: {error}"))
    })?;

    // Crosslink #479: trait dispatch instead of hardcoded shape matching.
    let text = adapter
        .extract_response_text(&response_json)
        .unwrap_or_default();
    if text.trim().is_empty() {
        return Err(VddError::AdversaryRequestFailed(
            "Verifier completed without assistant content".to_string(),
        ));
    }
    let tokens = adapter
        .extract_token_usage(&response_json)
        .unwrap_or_default();
    provider_budget.reconcile(&tokens).map_err(|error| {
        VddError::AdversaryRequestFailed(format!("Verifier budget reconciliation failed: {error}"))
    })?;

    Ok((text, tokens))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        GuardrailsConfig, HooksConfig, KeybindingsConfig, PermissionsConfig, ProviderConfig,
        ProxyConfig, SessionConfig, ThinkingConfig, VddAdversaryConfig, VddConfig,
    };
    use std::collections::HashMap;
    use std::time::Duration;

    fn cfg_with_timeout(secs: u64) -> VddConfig {
        VddConfig {
            enabled: true,
            adversary: VddAdversaryConfig {
                provider: "openai".to_string(),
                model: None,
                api_key: None,
                temperature: 0.3,
                max_tokens: 256,
                request_timeout_seconds: secs,
            },
            ..Default::default()
        }
    }

    #[test]
    fn responses_verifier_requires_completed_terminal_event() {
        let raw = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n",
            "data: [DONE]\n"
        );
        let error = responses_text_from_sse(raw).expect_err("missing completion must fail");
        assert!(
            error.to_string().contains("before response.completed"),
            "{error}"
        );
    }

    #[test]
    fn responses_verifier_rejects_refusal_as_success() {
        let raw = concat!(
            "data: {\"type\":\"response.completed\",\"response\":{",
            "\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[{",
            "\"type\":\"message\",\"content\":[{",
            "\"type\":\"refusal\",\"refusal\":\"cannot comply\"}]}]}}\n",
            "data: [DONE]\n"
        );
        let error = responses_text_from_sse(raw).expect_err("refusal must fail");
        assert!(error.to_string().contains("refused"), "{error}");
    }

    #[test]
    fn responses_usage_keeps_cache_buckets_disjoint() {
        let usage = responses_usage_from_json(&serde_json::json!({
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "input_tokens_details": {
                    "cached_tokens": 30,
                    "cache_write_tokens": 20
                }
            }
        }));
        assert_eq!(usage.input_tokens, 50);
        assert_eq!(usage.output_tokens, 10);
        assert_eq!(usage.cache_read_tokens, 30);
        assert_eq!(usage.cache_write_tokens, 20);
    }

    fn app_cfg_with_provider(provider: &str, base_url: &str) -> AppConfig {
        let mut providers = HashMap::new();
        providers.insert(
            provider.to_string(),
            ProviderConfig {
                base_url: base_url.to_string(),
                api_key: Some(
                    crate::providers::ApiKey::try_from_string("test-key".to_string()).unwrap(),
                ),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );
        AppConfig {
            proxy: ProxyConfig::default(),
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: crate::config::MemoryConfig::default(),
            web_fetch: crate::config::WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        }
    }

    fn dummy_request() -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "gpt-4".to_string(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn shared_vdd_transport_redacts_and_bounds_provider_failures() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const SECRET: &str = "s025-vdd-header-secret-b921a4";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "message": format!("echo {SECRET}"),
                    "padding": "x".repeat(crate::secrets::MAX_DIAGNOSTIC_BYTES * 2)
                }
            })))
            .mount(&server)
            .await;
        let provider = ProviderConfig {
            base_url: server.uri(),
            api_key: None,
            model: None,
            headers: crate::secrets::SensitiveHeaders::new(),
            thinking: ThinkingConfig::default(),
        };
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_header_bearer(
            reqwest::header::AUTHORIZATION,
            crate::secrets::SecretString::try_from_string(SECRET.to_string()).expect("secret"),
        );

        let error = forward_request(
            &Client::new(),
            "local",
            &provider,
            "/v1/chat/completions",
            &serde_json::json!({}),
            headers,
        )
        .await
        .expect_err("non-success provider response must fail");

        assert!(
            !error.contains(SECRET),
            "VDD leaked provider credential: {error}"
        );
        assert!(error.contains(crate::secrets::REDACTED_SECRET), "{error}");
        assert!(error.len() <= crate::secrets::MAX_DIAGNOSTIC_BYTES + 64);
    }

    // ── Crosslink #496: VDD HTTP timeout ──────────────────────────────────
    //
    // A slow / hung adversary upstream cannot block the VDD loop
    // indefinitely. `send_to_adversary` gives the HTTP send and body read one
    // shared monotonic deadline; on expiry it returns
    // `VddError::Timeout { provider, elapsed_secs }`.

    /// The configured timeout value is propagated from
    /// `VddConfig.adversary.request_timeout_seconds` into the actual
    /// timeout the transport applies. We can't observe the duration
    /// directly, but we can pin that the typed config field is honoured
    /// by checking the timeout's serde default + override semantics.
    #[test]
    fn vdd_timeout_default_is_120_seconds() {
        let cfg = VddConfig::default();
        assert_eq!(cfg.adversary.request_timeout_seconds, 120);
    }

    #[test]
    fn vdd_timeout_override_is_respected_via_config() {
        let cfg = cfg_with_timeout(7);
        assert_eq!(cfg.adversary.request_timeout_seconds, 7);
    }

    /// Hit a reserved-IP "blackhole" address (`192.0.2.1` is TEST-NET-1
    /// per RFC 5737; routed-but-unreachable on every machine that
    /// honours the registry). The connect will hang past the 1 s
    /// timeout. Asserts that we get `VddError::Timeout` (the new
    /// variant) — not `AdversaryRequestFailed`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn send_to_adversary_surfaces_timeout_variant_on_hang() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mut cfg = cfg_with_timeout(1);
        cfg.adversary.provider = "local".to_string();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let app_cfg = app_cfg_with_provider("local", &server.uri());
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let req = dummy_request();

        // Run the call and advance virtual time past the 1s budget.
        let handle = tokio::spawn(async move {
            send_to_adversary(
                crate::tools::security::test_run_context(),
                &client,
                &cfg,
                &app_cfg,
                &req,
                None,
            )
            .await
        });
        // Drive paused-time forward past the configured timeout.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = handle.await.expect("join task");

        match result {
            Err(VddError::Timeout {
                provider,
                elapsed_secs,
            }) => {
                assert_eq!(provider, "local");
                assert_eq!(elapsed_secs, 1);
            }
            Err(other) => panic!("expected VddError::Timeout, got {other:?}"),
            Ok(_) => panic!("expected timeout, got successful response"),
        }
    }

    /// The `VddError::Timeout` Display includes both the provider name
    /// and the elapsed seconds so the operator can see *which* upstream
    /// is hung and *how long* it has been waiting — required for
    /// triage. The previous code returned a stringly-typed
    /// `AdversaryRequestFailed("...timed out after {n}s")` which forces
    /// callers to substring-match to detect timeouts.
    #[test]
    fn vdd_timeout_error_display_has_provider_and_seconds() {
        let err = VddError::Timeout {
            provider: "google".to_string(),
            elapsed_secs: 42,
        };
        let display = err.to_string();
        assert!(display.contains("google"), "got: {display}");
        assert!(display.contains("42"), "got: {display}");
    }
}

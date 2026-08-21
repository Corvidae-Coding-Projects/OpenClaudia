//! API pipeline — builds requests, streams responses, and executes tools.
//!
//! Extracted from the `cmd_chat` function in `main.rs` to enable reuse
//! from both the rustyline REPL and the ratatui TUI.

use crate::config::{AppConfig, ThinkingConfig};
use crate::memory::MemoryDb;
use crate::permissions::{
    ApprovalProvenance, AuthorizationResult, ExecutionPermit, PermissionManager, PermissionRule,
};
use crate::providers::{
    anthropic_rejects_manual_thinking, apply_anthropic_adaptive_thinking,
    convert_messages_to_anthropic_checked, convert_tool_definitions_to_anthropic_checked,
    convert_tools_to_gemini_functions, extract_gemini_text_content, get_adapter,
};
use crate::proxy::{self, normalize_base_url};
use crate::services::policy::{PolicyEnforcer, PolicyError};
use crate::session::TokenUsage;
use crate::tools::{self, AnthropicToolAccumulator, ToolCall, ToolCallAccumulator};
use crate::tui::events::{ApiRetryKind, AppEvent, PermissionResponse};
use eventsource_stream::Eventsource;
use futures::StreamExt;
use serde_json::Value;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

/// Send an event to the TUI, logging and returning early if the channel is closed.
macro_rules! send_event {
    ($tx:expr, $event:expr) => {
        if $tx.send($event).is_err() {
            tracing::warn!("TUI channel closed, stopping pipeline");
            return Err("TUI channel closed".to_string());
        }
    };
}

/// Send an event to the TUI from a non-Result context (tool execution loop).
/// Returns from the enclosing function with current results if channel is dead.
macro_rules! send_event_or_break {
    ($tx:expr, $event:expr) => {
        if $tx.send($event).is_err() {
            tracing::warn!("TUI channel closed during tool execution");
            break;
        }
    };
}

/// Outcome of a single conversation turn (one API round-trip + tool execution).
#[derive(Debug)]
pub struct TurnResult {
    /// Full response text accumulated during streaming.
    pub content: String,
    /// Provider reasoning content accumulated during streaming, when the
    /// upstream exposes it separately from visible text.
    pub reasoning_content: Option<String>,
    /// Structured tool calls returned by the model.
    pub tool_calls: Vec<ToolCall>,
    /// Tool result messages to append to the conversation history.
    pub tool_results: Vec<Value>,
    /// Token usage observed from streaming events.
    pub usage: TokenUsage,
    /// Whether the model returned tool calls that need a follow-up API call.
    pub needs_followup: bool,
    /// Normalized finish reason surfaced to the caller, when the provider
    /// reports one. `None` for normal stop on streams that do not propagate
    /// a distinct termination cause through this layer.
    ///
    /// Values currently emitted by [`handle_google_response`] (crosslink #788):
    /// - `Some("safety_blocked")` — Gemini set `finishReason` to `SAFETY`,
    ///   `RECITATION`, or `BLOCKLIST`. Text may be empty; callers should
    ///   surface a user-visible error rather than treating this as a normal
    ///   empty completion.
    /// - `Some("length")` — `MAX_TOKENS` truncation.
    /// - `Some("stop")` — explicit `STOP` from the provider.
    /// - `Some(other)` — verbatim pass-through for unrecognized reasons.
    pub finish_reason: Option<String>,
}

// ─── Request building ───────────────────────────────────────────────────────

/// Wire protocol used for the outbound provider request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WireApi {
    /// `OpenAI`-compatible Chat Completions (`messages`, `choices[].delta`).
    #[default]
    ChatCompletions,
    /// `OpenAI` Responses (`input`, `response.output_text.delta`, response items).
    OpenAiResponses,
}

impl WireApi {
    #[must_use]
    pub const fn is_responses(self) -> bool {
        matches!(self, Self::OpenAiResponses)
    }
}

/// Build an Anthropic-format request body.
///
/// If `prompt_blocks` is provided, the system prompt is emitted as a
/// multi-block array for cache efficiency (stable prefix with
/// `cache_control`, dynamic suffix without).  Otherwise the system
/// prompt is extracted from `messages` as a single cached block.
///
/// # Errors
///
/// Returns an error when historical assistant `tool_calls` contain malformed
/// Anthropic tool-call arguments that cannot be represented safely.
pub fn build_anthropic_request(
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
) -> Result<Value, String> {
    let anthropic_messages =
        convert_messages_to_anthropic_checked(messages).map_err(|e| e.to_string())?;
    let openai_tools = tools::get_all_tool_definitions(true);
    let anthropic_tools =
        convert_tool_definitions_to_anthropic_checked(&openai_tools).map_err(|e| e.to_string())?;

    let mut req = serde_json::json!({
        "model": model,
        "messages": anthropic_messages,
        "max_tokens": crate::DEFAULT_MAX_TOKENS,
        "stream": true,
        "tools": anthropic_tools
    });

    if let Some(blocks) = prompt_blocks {
        // Multi-block system prompt: stable prefix (cached) + dynamic suffix (not cached)
        req["system"] = crate::providers::build_system_blocks(blocks);
    } else {
        // Legacy single-block path: extract from messages
        let system_msg = messages
            .iter()
            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("system"))
            .and_then(|m| m.get("content").and_then(|c| c.as_str()))
            .map(String::from);
        if let Some(sys) = system_msg {
            req["system"] = crate::providers::build_system_blocks_from_string(&sys);
        }
    }

    if claude_code_token.is_some() {
        crate::claude_credentials::inject_oauth_prefix_only(&mut req);
    }

    // Apply effort level. `high` / `max` switch Anthropic into thinking mode.
    // Newer models (Fable/Mythos, Opus 4.8/4.7) reject manual thinking
    // budgets, so they use the adaptive-thinking + output_config.effort
    // shape. Older/manual-capable models keep the Claude Code budget path.
    // MAX_THINKING_TOKENS env var overrides manual budgets outright. See
    // `crate::thinking` for the precedence chain and keyword-trigger logic
    // (ultrathink / think ultra hard).
    match effort_level {
        "high" | "max" | "xhigh" => {
            if anthropic_rejects_manual_thinking(model) {
                apply_anthropic_adaptive_thinking(&mut req, model, Some(effort_level));
                req["max_tokens"] = serde_json::json!(40_000);
            } else if let Some(budget) =
                crate::thinking::anthropic_thinking_budget(Some(effort_level))
            {
                req["thinking"] = serde_json::json!({
                    "type": "enabled",
                    "budget_tokens": budget,
                });
                // Headroom for the thinking block plus the answer. Claude
                // Code uses max_tokens > budget_tokens; 40k covers 32k
                // thinking + ~8k answer comfortably.
                req["max_tokens"] = serde_json::json!(40_000);
            }
        }
        "low" => {
            req["max_tokens"] = serde_json::json!(2048);
        }
        _ => {} // medium = default
    }

    Ok(req)
}

/// Build an `OpenAI`-compatible request body (used by `OpenAI`, `DeepSeek`, `Qwen`, `Z.AI`).
///
/// `effort_level` propagates as `reasoning_effort` for supported `OpenAI`
/// reasoning levels. `max` is kept as a user-facing alias for `OpenAI`'s
/// `xhigh` tier.
#[must_use]
pub fn build_openai_request(model: &str, messages: &[Value], effort_level: &str) -> Value {
    let mut req = serde_json::json!({
        "model": model,
        "messages": messages,
        "max_tokens": crate::DEFAULT_MAX_TOKENS,
        "stream": true,
        "tools": tools::get_all_tool_definitions(true)
    });
    match effort_level {
        "none" | "minimal" | "low" | "medium" | "high" | "xhigh" => {
            req["reasoning_effort"] = serde_json::json!(effort_level);
        }
        "max" => {
            req["reasoning_effort"] = serde_json::json!("xhigh");
        }
        _ => {}
    }
    req
}

fn text_from_message_content(content: &Value) -> Result<String, String> {
    if let Some(text) = content.as_str() {
        return Ok(text.to_string());
    }
    let Some(parts) = content.as_array() else {
        return Err(format!(
            "Responses message content must be string or array, got {}",
            json_value_type_name(content)
        ));
    };
    let mut text = String::new();
    for part in parts {
        if let Some(part_text) = part.get("text").and_then(Value::as_str) {
            text.push_str(part_text);
        }
    }
    Ok(text)
}

fn response_input_message(role: &str, text: &str) -> Value {
    let item_type = if role == "assistant" {
        "output_text"
    } else {
        "input_text"
    };
    serde_json::json!({
        "type": "message",
        "role": role,
        "content": [{"type": item_type, "text": text}]
    })
}

fn responses_input_items(messages: &[Value]) -> Result<(String, Vec<Value>), String> {
    let mut instructions = Vec::new();
    let mut input = Vec::new();

    for (index, msg) in messages.iter().enumerate() {
        let role = msg
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("message at index {index} missing string 'role': {msg}"))?;
        let content = text_from_message_content(msg.get("content").unwrap_or(&Value::Null))?;
        match role {
            "system" => {
                if !content.is_empty() {
                    instructions.push(content);
                }
            }
            "user" => input.push(response_input_message("user", &content)),
            "assistant" => {
                if !content.is_empty() {
                    input.push(response_input_message("assistant", &content));
                }
                if let Some(tool_calls) = msg.get("tool_calls").and_then(Value::as_array) {
                    for call in tool_calls {
                        let func = call.get("function").ok_or_else(|| {
                            format!("assistant tool call missing 'function': {call}")
                        })?;
                        let name = func
                            .get("name")
                            .and_then(Value::as_str)
                            .filter(|name| !name.is_empty())
                            .ok_or_else(|| {
                                format!("assistant tool call missing function.name: {call}")
                            })?;
                        let arguments =
                            func.get("arguments")
                                .and_then(Value::as_str)
                                .ok_or_else(|| {
                                    format!(
                                        "assistant tool call missing function.arguments: {call}"
                                    )
                                })?;
                        let arguments = history_safe_tool_arguments(name, arguments);
                        let call_id = call
                            .get("id")
                            .and_then(Value::as_str)
                            .filter(|id| !id.is_empty())
                            .ok_or_else(|| format!("assistant tool call missing id: {call}"))?;
                        input.push(serde_json::json!({
                            "type": "function_call",
                            "name": name,
                            "arguments": arguments,
                            "call_id": call_id
                        }));
                    }
                }
            }
            "tool" => {
                let call_id = msg
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| format!("tool message missing tool_call_id: {msg}"))?;
                input.push(serde_json::json!({
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": content
                }));
            }
            other => {
                return Err(format!(
                    "Responses backend does not support message role '{other}' at index {index}"
                ));
            }
        }
    }

    Ok((instructions.join("\n\n"), input))
}

fn responses_tools_from_openai_tools(openai_tools: &Value) -> Result<Vec<Value>, String> {
    let tools = openai_tools
        .as_array()
        .ok_or_else(|| "built-in tool definitions must be a JSON array".to_string())?;
    tools
        .iter()
        .enumerate()
        .map(|(index, tool)| {
            let func = tool
                .get("function")
                .ok_or_else(|| format!("Tool at index {index} missing 'function': {tool}"))?;
            let name = func
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format!("Tool at index {index} missing function.name: {tool}"))?;
            let mut out = serde_json::Map::new();
            out.insert("type".to_string(), Value::String("function".to_string()));
            out.insert("name".to_string(), Value::String(name.to_string()));
            if let Some(description) = func.get("description").and_then(Value::as_str) {
                out.insert(
                    "description".to_string(),
                    Value::String(description.to_string()),
                );
            }
            out.insert(
                "parameters".to_string(),
                func.get("parameters")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
            );
            Ok(Value::Object(out))
        })
        .collect()
}

fn responses_reasoning(effort_level: &str) -> Option<Value> {
    match effort_level {
        "none" | "minimal" | "low" | "medium" | "high" | "xhigh" => {
            Some(serde_json::json!({ "effort": effort_level }))
        }
        "max" => Some(serde_json::json!({ "effort": "xhigh" })),
        _ => None,
    }
}

/// Build an `OpenAI` Responses API request body.
///
/// # Errors
///
/// Returns an error when the chat-style session history cannot be represented
/// as Responses input items.
pub fn build_openai_responses_request(
    model: &str,
    messages: &[Value],
    effort_level: &str,
) -> Result<Value, String> {
    let (instructions, input) = responses_input_items(messages)?;
    let tools = responses_tools_from_openai_tools(&tools::get_all_tool_definitions(true))?;
    let mut req = serde_json::json!({
        "model": model,
        "input": input,
        "stream": true,
        "store": false,
        "tools": tools,
        "tool_choice": "auto",
        "parallel_tool_calls": true,
        "include": ["reasoning.encrypted_content"]
    });
    if !instructions.is_empty() {
        req["instructions"] = Value::String(instructions);
    }
    if let Some(reasoning) = responses_reasoning(effort_level) {
        req["reasoning"] = reasoning;
    }
    Ok(req)
}

/// Build the canonical chat-completions request used for policy accounting
/// before provider-specific adapter transformation.
///
/// # Errors
///
/// Returns an error if a session message cannot be converted into a typed chat
/// message or if the built-in tool definitions are not represented as an array.
pub fn build_chat_completion_request(
    model: &str,
    messages: &[Value],
) -> Result<proxy::ChatCompletionRequest, String> {
    let messages = messages
        .iter()
        .enumerate()
        .map(|(index, msg)| {
            serde_json::from_value::<proxy::ChatMessage>(msg.clone()).map_err(|e| {
                format!("message at index {index} is not a valid chat message: {e}: {msg}")
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tools = tools::get_all_tool_definitions(true)
        .as_array()
        .ok_or_else(|| "built-in tool definitions must be a JSON array".to_string())?
        .clone();

    Ok(proxy::ChatCompletionRequest {
        model: model.to_string(),
        messages,
        temperature: None,
        max_tokens: Some(crate::DEFAULT_MAX_TOKENS),
        stream: Some(true),
        tools: Some(tools),
        tool_choice: None,
        extra: std::collections::HashMap::new(),
    })
}

fn thinking_config_for_pipeline_effort(
    provider: &str,
    effort_level: &str,
) -> Option<ThinkingConfig> {
    let provider_lower = provider.to_ascii_lowercase();
    let is_openai = provider_lower == "openai";
    let is_glm_reasoning = matches!(provider_lower.as_str(), "zai" | "glm" | "zhipu");

    let effort = match effort_level {
        "high" | "max" | "xhigh" => Some(effort_level),
        "none" | "minimal" if is_openai || is_glm_reasoning => Some(effort_level),
        "low" | "medium" if is_openai => Some(effort_level),
        _ => None,
    }?;

    Some(ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: Some(effort.to_string()),
        adaptive: true,
    })
}

fn build_adapter_request(
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
) -> Result<Value, String> {
    let request = build_chat_completion_request(model, messages)?;
    let adapter = get_adapter(provider).map_err(|e| e.to_string())?;
    let body = thinking_config_for_pipeline_effort(provider, effort_level).map_or_else(
        || adapter.transform_request(&request),
        |thinking| adapter.transform_request_with_thinking(&request, &thinking),
    );
    body.map_err(|e| e.to_string())
}

/// Build a Google Gemini-format request body.
///
/// # Errors
///
/// Returns an error if the built-in tool definitions cannot be represented as
/// Gemini function declarations.
pub fn build_google_request(messages: &[Value], effort_level: &str) -> Result<Value, String> {
    let openai_tools = tools::get_all_tool_definitions(true);
    let tools_vec = openai_tools
        .as_array()
        .ok_or_else(|| "built-in tool definitions must be a JSON array".to_string())?;
    let functions = convert_tools_to_gemini_functions(tools_vec).map_err(|e| e.to_string())?;

    let mut contents = Vec::new();
    let mut system_parts: Vec<String> = Vec::new();
    for (msg_index, msg) in messages.iter().enumerate() {
        let role = msg.get("role").and_then(Value::as_str).ok_or_else(|| {
            format!("Google message at index {msg_index} missing string 'role': {msg}")
        })?;
        let text = msg.get("content").and_then(Value::as_str).ok_or_else(|| {
            format!("Google message at index {msg_index} missing string 'content': {msg}")
        })?;
        if role == "system" {
            if !text.is_empty() {
                system_parts.push(text.to_string());
            }
            continue;
        }
        let gemini_role = match role {
            "assistant" => "model",
            "user" | "tool" => "user",
            _ => {
                return Err(format!(
                    "Google message at index {msg_index} has unsupported role '{role}': {msg}"
                ));
            }
        };
        contents.push(serde_json::json!({
            "role": gemini_role,
            "parts": [{"text": text}]
        }));
    }

    // Gemini takes `thinkingConfig.thinkingBudget` inside
    // generationConfig. When effort is high/max we hand it the Claude
    // Code ULTRATHINK constant, clamped to Gemini's documented ceiling.
    let mut generation_config = serde_json::json!({"maxOutputTokens": 4096});
    if matches!(effort_level, "high" | "max") {
        const GEMINI_THINKING_CAP: u32 = 32_768;
        let budget = crate::thinking::anthropic_thinking_budget(Some(effort_level))
            .unwrap_or(crate::thinking::ULTRATHINK_BUDGET_TOKENS)
            .min(GEMINI_THINKING_CAP);
        generation_config["thinkingConfig"] = serde_json::json!({"thinkingBudget": budget});
    }
    let mut req = serde_json::json!({
        "contents": contents,
        "generationConfig": generation_config,
        "tools": [{"functionDeclarations": functions}]
    });
    let system_text = (!system_parts.is_empty()).then(|| system_parts.join("\n\n"));
    if let Some(sys) = system_text {
        req["systemInstruction"] = serde_json::json!({"parts": [{"text": sys}]});
    }
    Ok(req)
}

/// Build the appropriate request body for the given provider.
///
/// `prompt_blocks` is used only for the Anthropic path to enable multi-block
/// cache-efficient system prompts.  Pass `None` for the legacy single-block path.
///
/// # Errors
///
/// Returns an error when the selected provider's request conversion rejects
/// malformed message history.
pub fn build_request(
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
) -> Result<Value, String> {
    build_request_for_wire(
        WireApi::ChatCompletions,
        provider,
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
    )
}

/// Build the appropriate request body for the given provider and wire API.
///
/// # Errors
///
/// Returns an error when the selected request conversion rejects malformed
/// message history.
pub fn build_request_for_wire(
    wire_api: WireApi,
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
) -> Result<Value, String> {
    // Resolve ultrathink keyword / env override against the base effort
    // so every provider path sees the same effective level (Claude Code
    // does the same in `resolveAppliedEffort`). If env says `unset` /
    // `auto`, `medium` flows through as the request builders' no-op
    // effort level, omitting provider effort hints.
    let resolved = crate::thinking::resolve_effort(effort_level, messages);
    let effective = resolved.as_deref().unwrap_or("medium");
    let prepared_messages = prompt_blocks.map(|context| context.prepare_json_messages(messages));
    let effective_messages = prepared_messages.as_deref().unwrap_or(messages);
    if wire_api == WireApi::OpenAiResponses {
        return build_openai_responses_request(model, effective_messages, effective);
    }
    match provider.to_ascii_lowercase().as_str() {
        "anthropic" => build_anthropic_request(
            model,
            effective_messages,
            effective,
            claude_code_token,
            prompt_blocks,
        ),
        "google" | "gemini" => build_google_request(effective_messages, effective),
        _ => build_adapter_request(provider, model, effective_messages, effective),
    }
}

/// Resolve the API endpoint for the given provider configuration.
///
/// # Errors
///
/// Returns [`crate::providers::ProviderError::UnknownProvider`] when
/// `provider` is not a registered adapter name AND the caller is not
/// using a Claude Code OAuth token (OAuth bypasses adapter dispatch
/// because the endpoint is fixed by `get_oauth_endpoint`). Previously
/// (crosslink #433) this function silently fell back to
/// `/v1/chat/completions` against `OpenAIAdapter`, hiding typos in
/// `proxy.target` from the user.
pub fn resolve_endpoint(
    provider: &str,
    model: &str,
    base_url: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
) -> Result<String, crate::providers::ProviderError> {
    resolve_endpoint_for_wire(
        WireApi::ChatCompletions,
        provider,
        model,
        base_url,
        claude_code_token,
    )
}

/// Resolve the API endpoint for the given provider and wire API.
///
/// # Errors
///
/// Returns [`crate::providers::ProviderError::UnknownProvider`] for unknown
/// Chat Completions providers.
pub fn resolve_endpoint_for_wire(
    wire_api: WireApi,
    provider: &str,
    model: &str,
    base_url: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
) -> Result<String, crate::providers::ProviderError> {
    if wire_api == WireApi::OpenAiResponses {
        return Ok(format!("{}/responses", normalize_base_url(base_url)));
    }
    if claude_code_token.is_some() {
        Ok(crate::claude_credentials::get_oauth_endpoint(model))
    } else {
        let adapter = get_adapter(provider)?;
        Ok(format!(
            "{}{}",
            normalize_base_url(base_url),
            adapter.chat_endpoint(model)
        ))
    }
}

/// Build the headers needed for the API request.
///
/// `api_key` is `Option<&ApiKey>`. If both `api_key` and
/// `claude_code_token` are `None`, the function returns an empty auth set.
/// Callers validate whether that is acceptable for the selected provider
/// (for example, Anthropic OAuth bootstrap and local providers can proceed
/// without static API keys). See crosslink #256.
///
/// # Errors
///
/// Returns [`crate::providers::ProviderError::UnknownProvider`] when
/// `provider` is unknown AND an API key is being used (the OAuth path
/// uses `get_oauth_headers` which doesn't go through adapter dispatch).
/// See crosslink #433.
pub fn resolve_headers(
    provider: &str,
    api_key: Option<&crate::providers::ApiKey>,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    extra_headers: &crate::secrets::SensitiveHeaders,
) -> Result<crate::secrets::SensitiveHeaders, crate::providers::ProviderError> {
    let mut headers = if let Some(token) = claude_code_token {
        crate::claude_credentials::get_oauth_headers(token)
    } else if let Some(key) = api_key {
        let adapter = get_adapter(provider)?;
        adapter.get_headers(key)
    } else {
        crate::secrets::SensitiveHeaders::new()
    };
    headers.extend(extra_headers);
    Ok(headers)
}

// ─── Streaming + tool execution ─────────────────────────────────────────────

/// Parameters for [`run_turn`]. Bundled to keep the call-site argument count
/// within clippy's `too_many_arguments` limit.
pub struct RunTurnParams<'a> {
    pub run_context: Arc<tools::ToolRunContext>,
    pub client: &'a reqwest::Client,
    pub endpoint: &'a str,
    pub headers: &'a crate::secrets::SensitiveHeaders,
    pub request_body: &'a Value,
    pub provider: &'a str,
    pub model_identity: &'a str,
    pub memory_db: Option<Arc<MemoryDb>>,
    pub app_config: Option<Arc<AppConfig>>,
    pub permission_mgr: Option<Arc<PermissionManager>>,
    pub transient_allowed_tool_rules: &'a [PermissionRule],
    pub hook_engine: Option<Arc<crate::hooks::HookEngine>>,
    pub policy_enforcer: Option<Arc<PolicyEnforcer>>,
    /// Session-scoped `TaskManager` used by `task_create` / `task_update`
    /// / `task_list` / `task_get`. The TUI keeps a single
    /// `Arc<Mutex<TaskManager>>` and clones the `Arc` into every turn so
    /// the task tools have a place to read/write — without this they
    /// returned "Task management not available (no session)".
    pub task_mgr: Arc<Mutex<crate::session::TaskManager>>,
    pub session_id: Option<String>,
    pub tx: mpsc::Sender<AppEvent>,
}

// ---------------------------------------------------------------------------
// Retry classifier + backoff helpers (crosslink #592, #595, #596, #597)
// ---------------------------------------------------------------------------

/// Maximum retry attempts for transient API errors.
///
/// Matches CC's `withRetry.ts::DEFAULT_MAX_RETRIES` (10). Per crosslink
/// #592 — was previously 3, which gave up too quickly on rate-limit
/// surges that 10 attempts of jittered exponential backoff would have
/// ridden out.
pub const MAX_API_RETRIES: u32 = 10;

/// HTTP status codes that warrant a retry. Matches CC's
/// `withRetry.ts` transient-status set:
///   * 408 — Request Timeout
///   * 409 — Conflict (transient concurrent-mutation case)
///   * 429 — Rate Limited
///   * 500 / 502 / 503 / 504 — server-side transient
///   * 529 — Anthropic-specific "service overloaded"
#[must_use]
pub const fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 409 | 429 | 500 | 502 | 503 | 504 | 529)
}

/// Transport-layer errors that warrant a retry.
///
/// `ConnectionReset` and `BrokenPipe` are the canonical "TCP/TLS
/// dropped under us" signals every long-lived streaming client sees;
/// both are transient. Per crosslink #597.
#[must_use]
pub fn is_transient_transport_error(err: &reqwest::Error) -> bool {
    use std::io;
    // Walk the source chain looking for an io::Error whose kind is
    // ConnectionReset or BrokenPipe. reqwest doesn't surface these
    // structurally so source-chain inspection is the supported path.
    let mut cur: &dyn std::error::Error = err;
    loop {
        if let Some(ioerr) = cur.downcast_ref::<io::Error>() {
            if matches!(
                ioerr.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) {
                return true;
            }
        }
        match cur.source() {
            Some(next) => cur = next,
            None => return false,
        }
    }
}

/// Exponential backoff (base = `2^(attempt+1)` seconds) with ±25% jitter,
/// per crosslink #596 — when many clients hit the same 429 they must not
/// all retry in lockstep and re-collide. Returns a wait in seconds.
///
/// The jitter is deterministic on a thread-local RNG path (we use
/// `std::time::Instant::now()` nanos as the jitter source so unit tests
/// observe non-equal sleeps without needing a `rand` dependency).
fn backoff_with_jitter(attempt: u32) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let base = 2u64.saturating_pow(attempt + 1);
    // Jitter range is ±25% of base, minimum ±1 so attempt=0 still
    // produces some spread between concurrent retriers.
    let max_jitter = std::cmp::max(base / 4, 1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    let jitter = nanos % (max_jitter * 2 + 1); // 0..=2*max_jitter
                                               // Apply jitter as an unsigned offset around the base. Adding
                                               // `jitter` then subtracting `max_jitter` keeps everything unsigned
                                               // and saturates at 1 (we never want a 0-second sleep on a stuck
                                               // transient).
    let raw = base.saturating_add(jitter).saturating_sub(max_jitter);
    raw.max(1)
}

fn retry_jitter_seed() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()))
}

const fn retry_after_with_jitter_from(
    retry_after_secs: u64,
    jitter_seed: u64,
) -> std::time::Duration {
    let base_ms = retry_after_secs.saturating_mul(1_000);
    if base_ms == 0 {
        return std::time::Duration::ZERO;
    }
    let max_jitter_ms = base_ms / 4;
    let jitter_ms = jitter_seed % (max_jitter_ms + 1);
    std::time::Duration::from_millis(base_ms.saturating_add(jitter_ms))
}

fn retry_after_with_jitter(retry_after_secs: u64) -> std::time::Duration {
    retry_after_with_jitter_from(retry_after_secs, retry_jitter_seed())
}

/// Map a model name to a lighter sibling that's suitable as a fallback when
/// the requested model is sustainedly overloaded (HTTP 529).
///
/// The mapping is intentionally conservative — it only fires for model
/// families where the lighter sibling is a known good degraded-mode target.
/// Returns an empty string when no sensible fallback is known, in which
/// case [`AppEvent::OverloadFallback`] is still emitted (so log consumers
/// see the exhaustion signal) but the UI surface should not auto-switch.
///
/// See crosslink #598 — CC has an analogous mapping in
/// `getFallbackModelForOverload` that downgrades opus→sonnet→haiku.
#[must_use]
pub fn overload_fallback_for(model: &str) -> &'static str {
    let m = model.to_ascii_lowercase();
    // Claude family — opus → sonnet → haiku
    if m.contains("opus") {
        return "claude-sonnet-4-6";
    }
    if m.contains("sonnet") {
        return "claude-haiku-4-5";
    }
    if m.contains("haiku") {
        // Already the lightest tier — no further fallback.
        return "";
    }
    // GPT family — latest frontier/standard models → current mini/nano tiers.
    if m.starts_with("gpt-5.5") || m.starts_with("gpt-5.4") {
        return "gpt-5.4-mini";
    }
    if m.starts_with("gpt-5") {
        return "gpt-5-mini";
    }
    // Older GPT/o-series families keep the legacy lightweight fallback.
    if m.starts_with("gpt-4") || m.starts_with("o1") || m.starts_with("o3") || m.starts_with("o4") {
        return "gpt-4o-mini";
    }
    // Gemini family — pro → flash
    if m.contains("gemini") && m.contains("pro") {
        return "gemini-3.5-flash";
    }
    ""
}

/// Drive the API request through up to `MAX_API_RETRIES` attempts,
/// classifying transient transport errors and retryable HTTP statuses
/// per crosslink #595/#596/#597. Each retry emits a structured
/// `tracing::warn!` (`target="openclaudia::retry"`, `event="api_retry"`)
/// so log consumers can bucket retry pressure programmatically. The
/// user-facing retry state is emitted through [`AppEvent::ApiRetry`] so host
/// status cannot be confused with model-authored stream content.
///
/// When the loop exhausts [`MAX_API_RETRIES`] on a 529 ("service
/// overloaded") status, the function additionally emits
/// [`AppEvent::OverloadFallback`] with an advisory model hint so the
/// orchestrator can suggest or automatically switch to a lighter
/// sibling. See crosslink #598.
async fn send_with_retry(
    client: &reqwest::Client,
    endpoint: &str,
    headers: &crate::secrets::SensitiveHeaders,
    request_body: &Value,
    tx: &mpsc::Sender<AppEvent>,
) -> Result<reqwest::Response, String> {
    let mut response = None;
    for attempt in 0..=MAX_API_RETRIES {
        let req = headers
            .apply(client.post(endpoint).json(request_body))
            .map_err(|error| error.to_string())?;

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) if attempt < MAX_API_RETRIES && is_transient_transport_error(&e) => {
                let wait_secs = backoff_with_jitter(attempt);
                tracing::warn!(
                    target: "openclaudia::retry",
                    event = "api_retry",
                    kind = "transport",
                    attempt = attempt + 1,
                    max_attempts = MAX_API_RETRIES + 1,
                    wait_secs,
                    error = %e,
                    "transient transport error, retrying"
                );
                let _ = tx.send(AppEvent::ApiRetry {
                    kind: ApiRetryKind::Transport,
                    attempt: attempt + 1,
                    max_attempts: MAX_API_RETRIES + 1,
                    delay_ms: wait_secs.saturating_mul(1_000),
                    status: None,
                });
                tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;
                continue;
            }
            Err(e) => return Err(format!("Request failed: {e}")),
        };
        let status = resp.status().as_u16();

        if is_retryable_status(status) && attempt < MAX_API_RETRIES {
            let wait = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map_or_else(
                    || std::time::Duration::from_secs(backoff_with_jitter(attempt)),
                    retry_after_with_jitter,
                );
            tracing::warn!(
                target: "openclaudia::retry",
                event = "api_retry",
                kind = "status",
                attempt = attempt + 1,
                max_attempts = MAX_API_RETRIES + 1,
                status,
                wait_ms = wait.as_millis(),
                "transient API status, retrying"
            );
            let delay_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
            let _ = tx.send(AppEvent::ApiRetry {
                kind: ApiRetryKind::Status,
                attempt: attempt + 1,
                max_attempts: MAX_API_RETRIES + 1,
                delay_ms,
                status: Some(status),
            });
            tokio::time::sleep(wait).await;
            continue;
        }

        if !resp.status().is_success() {
            // Crosslink #598: the retry loop has reached its budget on a
            // retryable status. If that status is 529 (Anthropic "service
            // overloaded"), emit an OverloadFallback advisory so the UI
            // can suggest / auto-switch to a lighter model. We compute
            // the hint from the request body's `model` field — the
            // request was built upstream by the proxy and always carries
            // it.
            if status == 529 {
                let model = request_body
                    .get("model")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let hint = overload_fallback_for(model);
                tracing::warn!(
                    target: "openclaudia::retry",
                    event = "overload_fallback",
                    model,
                    model_hint = hint,
                    "529 overload persisted past retry budget; emitting OverloadFallback"
                );
                let _ = tx.send(AppEvent::OverloadFallback {
                    model_hint: hint.to_string(),
                });
            }
            let body = crate::secrets::read_bounded_diagnostic_body(resp)
                .await
                .unwrap_or_else(|_| zeroize::Zeroizing::new(String::new()));
            let diagnostic = headers.sanitize_diagnostic(&body);
            return Err(format!("API error {status}: {diagnostic}"));
        }

        response = Some(resp);
        break;
    }
    response.ok_or_else(|| "Max retries exceeded".to_string())
}

/// Run one turn of the conversation: send request, stream response, execute tools.
///
/// Sends `AppEvent` variants through `tx` as they occur so the TUI can update
/// in real time. Returns a `TurnResult` describing what happened.
///
/// # Errors
///
/// Returns `Err` if the HTTP request itself fails (network error, etc.).
pub async fn run_turn(p: RunTurnParams<'_>) -> Result<TurnResult, String> {
    let RunTurnParams {
        run_context,
        client,
        endpoint,
        headers,
        request_body,
        provider,
        model_identity,
        memory_db,
        app_config,
        permission_mgr,
        transient_allowed_tool_rules,
        hook_engine,
        policy_enforcer,
        task_mgr,
        session_id,
        tx,
    } = p;
    tracing::info!(
        endpoint,
        model = request_body
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("?"),
        system_blocks = request_body
            .get("system")
            .and_then(|v| v.as_array())
            .map_or(0, std::vec::Vec::len),
        messages = request_body
            .get("messages")
            .and_then(|v| v.as_array())
            .map_or(0, std::vec::Vec::len),
        has_tools = request_body
            .get("tools")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty()),
        "Sending API request"
    );

    // Send request with retry on transient errors. See `send_with_retry`
    // for the per-attempt classification logic (crosslink #592 #595 #596 #597).
    let response = send_with_retry(client, endpoint, headers, request_body, &tx).await?;

    // For Google, handle non-streaming JSON response
    if provider == "google" {
        return handle_google_response(
            run_context,
            response,
            memory_db,
            app_config,
            permission_mgr,
            transient_allowed_tool_rules,
            hook_engine.clone(),
            policy_enforcer.clone(),
            task_mgr.clone(),
            session_id.clone(),
            model_identity,
            headers,
            &tx,
        )
        .await;
    }

    if request_body.get("input").is_some() && request_body.get("messages").is_none() {
        return stream_responses_sse_response(SseStreamParams {
            run_context,
            response,
            headers,
            provider,
            model_identity,
            memory_db,
            app_config,
            permission_mgr,
            transient_allowed_tool_rules,
            hook_engine,
            policy_enforcer,
            task_mgr,
            session_id,
            tx: &tx,
        })
        .await;
    }

    // Stream SSE response (Anthropic / OpenAI format)
    stream_sse_response(SseStreamParams {
        run_context,
        response,
        headers,
        provider,
        model_identity,
        memory_db,
        app_config,
        permission_mgr,
        transient_allowed_tool_rules,
        hook_engine,
        policy_enforcer,
        task_mgr,
        session_id,
        tx: &tx,
    })
    .await
}

/// Outcome of classifying the top-level `finishReason` from a Gemini
/// non-streaming response.
///
/// Pure data carrier produced by [`classify_google_finish_reason`] so the
/// mapping logic stays unit-testable in isolation from the channels and
/// HTTP plumbing in [`handle_google_response`]. See crosslink #788 for
/// the gap this addresses: the prior implementation silently dropped
/// `SAFETY` / `RECITATION` / `BLOCKLIST` and returned an empty
/// completion to the TUI with no signal whatsoever.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GoogleFinishClassification {
    /// Normalized finish reason to surface on `TurnResult.finish_reason`.
    pub finish_reason: Option<String>,
    /// When `Some`, a user-visible error message the caller must push
    /// onto the TUI via `AppEvent::ApiError`. Set for filtered output
    /// (`SAFETY` / `RECITATION` / `BLOCKLIST`); `None` otherwise.
    pub user_error: Option<String>,
}

/// Classify `candidates[0].finishReason` from a Gemini JSON response.
///
/// Maps Gemini's enum vocabulary to OC's normalized vocabulary:
/// - `SAFETY` / `RECITATION` / `BLOCKLIST` → `Some("safety_blocked")`
///   plus a user-facing error and a `tracing::warn!` log.
/// - `MAX_TOKENS` → `Some("length")` plus a `tracing::warn!` log.
/// - `STOP` → `Some("stop")`.
/// - Any other non-empty string → `Some(other)` (verbatim pass-through;
///   never classified as a safety block).
/// - Missing / non-string → `None`.
///
/// `text_len_bytes` is the length of the text body already extracted by
/// the caller; it is included in the warn log so operators can correlate
/// "blocked + had partial text" vs "blocked + empty completion".
#[must_use]
pub fn classify_google_finish_reason(
    gemini_json: &Value,
    text_len_bytes: usize,
) -> GoogleFinishClassification {
    let raw = gemini_json
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("finishReason"))
        .and_then(|r| r.as_str());

    match raw {
        Some(reason @ ("SAFETY" | "RECITATION" | "BLOCKLIST")) => {
            tracing::warn!(
                finish_reason = reason,
                text_len = text_len_bytes,
                "Gemini suppressed candidate output (filtered response)"
            );
            GoogleFinishClassification {
                finish_reason: Some("safety_blocked".to_string()),
                user_error: Some(format!(
                    "Gemini blocked the response (finishReason={reason}). \
                     The model returned no usable content."
                )),
            }
        }
        Some("MAX_TOKENS") => {
            tracing::warn!(
                finish_reason = "MAX_TOKENS",
                text_len = text_len_bytes,
                "Gemini truncated response at max_tokens"
            );
            GoogleFinishClassification {
                finish_reason: Some("length".to_string()),
                user_error: None,
            }
        }
        Some("STOP") => GoogleFinishClassification {
            finish_reason: Some("stop".to_string()),
            user_error: None,
        },
        Some(other) => GoogleFinishClassification {
            // Unknown / future finish reasons: pass through verbatim so
            // the caller can decide. Do NOT classify these as safety
            // blocks — that would over-trigger user-visible errors on
            // benign new Gemini enum values.
            finish_reason: Some(other.to_string()),
            user_error: None,
        },
        None => GoogleFinishClassification::default(),
    }
}

fn google_response_parts(gemini_json: &Value) -> Result<&[Value], String> {
    let candidate = gemini_json
        .get("candidates")
        .and_then(|c| c.get(0))
        .ok_or_else(|| format!("Gemini response missing candidates[0]: {gemini_json}"))?;

    candidate
        .get("content")
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .map(Vec::as_slice)
        .ok_or_else(|| format!("Gemini candidate missing content.parts array: {candidate}"))
}

fn extract_google_text(parts: &[Value]) -> Result<String, String> {
    extract_gemini_text_content(parts).map_err(|e| e.to_string())
}

/// Extract structured tool calls from Gemini `content.parts`.
fn extract_google_tool_calls_from_parts(parts: &[Value]) -> Result<Vec<ToolCall>, String> {
    let mut calls = Vec::new();

    for part in parts {
        let Some(fc) = part.get("functionCall") else {
            continue;
        };

        if !fc.is_object() {
            return Err(format!("Gemini functionCall must be an object: {fc}"));
        }

        let name = fc
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("Gemini functionCall missing non-empty string 'name': {fc}"))?
            .to_string();

        let args = fc
            .get("args")
            .ok_or_else(|| format!("Gemini functionCall missing object 'args': {fc}"))?;

        if !args.is_object() {
            return Err(format!(
                "Gemini functionCall has non-object 'args': expected JSON object, got {}",
                json_value_type_name(args)
            ));
        }

        let args = serde_json::to_string(args).map_err(|e| {
            format!("Gemini functionCall has unserializable 'args': {e}; functionCall: {fc}")
        })?;

        calls.push(ToolCall {
            id: format!("call_{}", uuid::Uuid::new_v4()),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name,
                arguments: args,
            },
        });
    }

    Ok(calls)
}

/// Extract structured tool calls from a Gemini non-streaming response.
#[cfg(test)]
fn extract_google_tool_calls(gemini_json: &Value) -> Result<Vec<ToolCall>, String> {
    extract_google_tool_calls_from_parts(google_response_parts(gemini_json)?)
}

const fn json_value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Extract `(prompt_tokens, candidates_tokens)` from a Gemini response.
fn extract_google_usage(gemini_json: &Value) -> (u64, u64) {
    let usage = gemini_json.get("usageMetadata");
    let input = usage
        .and_then(|u| u.get("promptTokenCount"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output = usage
        .and_then(|u| u.get("candidatesTokenCount"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    (input, output)
}

/// Handle a non-streaming Google Gemini response.
#[allow(clippy::too_many_arguments)]
async fn handle_google_response(
    run_context: Arc<tools::ToolRunContext>,
    response: reqwest::Response,
    memory_db: Option<Arc<MemoryDb>>,
    app_config: Option<Arc<AppConfig>>,
    permission_mgr: Option<Arc<PermissionManager>>,
    transient_allowed_tool_rules: &[PermissionRule],
    hook_engine: Option<Arc<crate::hooks::HookEngine>>,
    policy_enforcer: Option<Arc<PolicyEnforcer>>,
    task_mgr: Arc<Mutex<crate::session::TaskManager>>,
    session_id: Option<String>,
    model_identity: &str,
    headers: &crate::secrets::SensitiveHeaders,
    tx: &mpsc::Sender<AppEvent>,
) -> Result<TurnResult, String> {
    let body = zeroize::Zeroizing::new(response.text().await.unwrap_or_default());
    let gemini_json: Value =
        serde_json::from_str(&body).map_err(|e| format!("Failed to parse Gemini response: {e}"))?;

    // Check for Gemini error responses
    if let Some(error) = gemini_json.get("error") {
        let msg = error
            .get("message")
            .and_then(Value::as_str)
            .filter(|message| !message.is_empty())
            .ok_or_else(|| {
                headers
                    .sanitize_diagnostic(&format!(
                        "Gemini API error missing non-empty string 'message': {error}"
                    ))
                    .to_string()
            })?;
        let code = error
            .get("code")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        return Err(format!(
            "Gemini API error ({code}): {}",
            headers.sanitize_diagnostic(msg)
        ));
    }

    let parts = google_response_parts(&gemini_json)
        .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;
    let text = extract_google_text(parts)
        .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;

    // #788: surface Gemini SAFETY / RECITATION / BLOCKLIST blocks via the pure helper.
    let GoogleFinishClassification {
        finish_reason,
        user_error,
    } = classify_google_finish_reason(&gemini_json, text.len());
    if let Some(msg) = user_error {
        send_event!(tx, AppEvent::ApiError(headers.sanitize_diagnostic(&msg)));
    }

    if !text.is_empty() {
        send_event!(tx, AppEvent::StreamText(text.clone()));
    }

    let tool_calls = extract_google_tool_calls_from_parts(parts)
        .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;
    let (input_tokens, output_tokens) = extract_google_usage(&gemini_json);

    // Execute tool calls if any
    let (tool_results, needs_followup) = execute_tool_calls_for_tui(
        run_context,
        &tool_calls,
        memory_db,
        app_config,
        permission_mgr,
        transient_allowed_tool_rules,
        hook_engine,
        policy_enforcer,
        task_mgr,
        session_id.as_deref(),
        model_identity,
        tx,
    )
    .await;

    if !needs_followup {
        send_event!(tx, AppEvent::ResponseDone);
    }

    Ok(TurnResult {
        content: text,
        reasoning_content: None,
        tool_calls,
        tool_results,
        usage: TokenUsage {
            input_tokens,
            output_tokens,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        },
        needs_followup,
        finish_reason,
    })
}

/// Outcome of enforcing the per-line SSE buffer cap.
///
/// SSE frames are line-delimited. A hostile or broken upstream that
/// streams bytes without ever emitting `\n` would otherwise grow the
/// accumulator without bound until the process OOMs (crosslink #695).
/// This enum records the action taken by [`enforce_sse_line_cap`].
#[derive(Debug, PartialEq, Eq)]
pub enum SseLineCapOutcome {
    /// Buffer is within the cap; nothing was discarded.
    WithinCap,
    /// Buffer exceeded [`proxy::MAX_SSE_LINE_BYTES`] without a newline.
    /// The accumulator was reset; the caller should log a warning.
    /// Carries the number of bytes discarded for forensic reporting.
    Exceeded {
        /// Number of bytes dropped from the accumulator.
        discarded_bytes: usize,
    },
}

/// Enforce the per-line SSE buffer cap.
///
/// If `buffer` already contains a newline, the in-flight line is bounded
/// by the next `find('\n')` and we leave the accumulator untouched —
/// existing drain logic will consume it. Otherwise, if the unterminated
/// remainder has grown past [`proxy::MAX_SSE_LINE_BYTES`] we clear the
/// buffer and report the discard so the caller can warn.
///
/// Pure function — no I/O, no allocation when within cap, fully testable.
pub fn enforce_sse_line_cap(buffer: &mut String) -> SseLineCapOutcome {
    if buffer.contains('\n') {
        return SseLineCapOutcome::WithinCap;
    }
    if buffer.len() < proxy::MAX_SSE_LINE_BYTES {
        return SseLineCapOutcome::WithinCap;
    }
    let discarded_bytes = buffer.len();
    buffer.clear();
    SseLineCapOutcome::Exceeded { discarded_bytes }
}

/// Emit a structured timeout event for a stalled SSE stream.
///
/// The timeout is runtime metadata, not provider-authored assistant text, so
/// it must not be appended to `full_content`.
fn handle_sse_timeout(
    elapsed_secs: u64,
    full_content_bytes: usize,
    tx: &mpsc::Sender<AppEvent>,
) -> Result<(), String> {
    tracing::error!(
        target: "openclaudia::stream",
        event = "sse_stream_timeout",
        kind = "result",
        is_error = true,
        elapsed_secs,
        timeout_secs = proxy::SSE_STREAM_TIMEOUT_SECS,
        content_so_far_bytes = full_content_bytes,
        "SSE stream timed out without further data"
    );
    send_event!(
        tx,
        AppEvent::StreamTimeout {
            elapsed_secs,
            timeout_secs: proxy::SSE_STREAM_TIMEOUT_SECS,
        }
    );
    Ok(())
}

/// Borrowed inputs threaded through the SSE-streaming code path.
///
/// Bundled because the inner function previously took 8 positional
/// arguments, which trips `clippy::too_many_arguments` (threshold 7).
/// All fields are owned / `Arc`-shared resources the inner pipeline
/// stages need; the param struct mirrors the established
/// [`RunTurnParams`] pattern.
struct SseStreamParams<'a> {
    run_context: Arc<tools::ToolRunContext>,
    response: reqwest::Response,
    headers: &'a crate::secrets::SensitiveHeaders,
    provider: &'a str,
    model_identity: &'a str,
    memory_db: Option<Arc<MemoryDb>>,
    app_config: Option<Arc<AppConfig>>,
    permission_mgr: Option<Arc<PermissionManager>>,
    transient_allowed_tool_rules: &'a [PermissionRule],
    hook_engine: Option<Arc<crate::hooks::HookEngine>>,
    policy_enforcer: Option<Arc<PolicyEnforcer>>,
    task_mgr: Arc<Mutex<crate::session::TaskManager>>,
    session_id: Option<String>,
    tx: &'a mpsc::Sender<AppEvent>,
}

async fn stream_sse_response(p: SseStreamParams<'_>) -> Result<TurnResult, String> {
    let SseStreamParams {
        run_context,
        response,
        headers: _,
        provider,
        model_identity,
        memory_db,
        app_config,
        permission_mgr,
        transient_allowed_tool_rules,
        hook_engine,
        policy_enforcer,
        task_mgr,
        session_id,
        tx,
    } = p;
    let mut stream = response.bytes_stream().eventsource();
    let mut full_content = String::new();
    let mut reasoning_content = String::new();
    let mut tool_accumulator = ToolCallAccumulator::new();
    let mut anthropic_accumulator = AnthropicToolAccumulator::new();
    let mut stream_usage = TokenUsage::default();
    let mut in_thinking_block = false;
    let mut last_data_time = std::time::Instant::now();
    let stream_timeout = std::time::Duration::from_secs(proxy::SSE_STREAM_TIMEOUT_SECS);

    loop {
        let sse = match tokio::time::timeout(stream_timeout, stream.next()).await {
            Ok(Some(Ok(sse))) => sse,
            Ok(Some(Err(e))) => {
                send_event!(tx, AppEvent::ApiError(format!("Stream error: {e}").into()));
                break;
            }
            Ok(None) => break,
            Err(_) => {
                handle_sse_timeout(last_data_time.elapsed().as_secs(), full_content.len(), tx)?;
                break;
            }
        };

        last_data_time = std::time::Instant::now();
        if sse.data == "[DONE]" {
            break;
        }

        if let Ok(json) = serde_json::from_str::<Value>(&sse.data) {
            // Extract usage BEFORE the accumulator (both can process the same event)
            if let Some(usage) = proxy::extract_usage_from_sse_event(&json) {
                stream_usage.accumulate(&usage);
            }

            let action = process_sse_event(
                &json,
                in_thinking_block,
                &mut anthropic_accumulator,
                &mut tool_accumulator,
            );
            dispatch_sse_action(
                action,
                SseActionDispatch {
                    full_content: &mut full_content,
                    reasoning_content: &mut reasoning_content,
                    in_thinking_block: &mut in_thinking_block,
                    tx,
                },
            )?;
        }
    }

    finalize_sse_stream(SseFinalize {
        run_context,
        provider,
        model_identity,
        full_content,
        reasoning_content,
        tool_accumulator,
        anthropic_accumulator,
        stream_usage,
        memory_db,
        app_config,
        permission_mgr,
        transient_allowed_tool_rules,
        hook_engine,
        policy_enforcer,
        task_mgr,
        session_id,
        tx,
    })
    .await
}

struct SseActionDispatch<'a> {
    full_content: &'a mut String,
    reasoning_content: &'a mut String,
    in_thinking_block: &'a mut bool,
    tx: &'a mpsc::Sender<AppEvent>,
}

fn dispatch_sse_action(action: SseAction, ctx: SseActionDispatch<'_>) -> Result<(), String> {
    let SseActionDispatch {
        full_content,
        reasoning_content,
        in_thinking_block,
        tx,
    } = ctx;
    match action {
        SseAction::Text(text) => {
            send_event!(tx, AppEvent::StreamText(text.clone()));
            full_content.push_str(&text);
        }
        SseAction::Thinking(text) => {
            send_event!(tx, AppEvent::StreamThinking(text));
        }
        SseAction::Reasoning(text) => {
            let display_text = merge_reasoning_delta(reasoning_content, &text);
            if !display_text.is_empty() {
                send_event!(tx, AppEvent::StreamThinking(display_text));
            }
        }
        SseAction::ThinkingStart => {
            *in_thinking_block = true;
            send_event!(tx, AppEvent::StreamThinking(String::new(),));
        }
        SseAction::ThinkingEnd => {
            *in_thinking_block = false;
        }
        SseAction::None => {}
    }
    Ok(())
}

/// Owned + borrowed state handed to [`finalize_sse_stream`].
///
/// Extracted from `stream_sse_response` (which otherwise tipped over
/// the `clippy::too_many_lines` threshold once `task_mgr` was threaded
/// through). The struct lets the finalize helper take ownership of the
/// accumulators and the per-turn channels in a single move.
struct SseFinalize<'a> {
    run_context: Arc<tools::ToolRunContext>,
    provider: &'a str,
    model_identity: &'a str,
    full_content: String,
    reasoning_content: String,
    tool_accumulator: ToolCallAccumulator,
    anthropic_accumulator: AnthropicToolAccumulator,
    stream_usage: TokenUsage,
    memory_db: Option<Arc<MemoryDb>>,
    app_config: Option<Arc<AppConfig>>,
    permission_mgr: Option<Arc<PermissionManager>>,
    transient_allowed_tool_rules: &'a [PermissionRule],
    hook_engine: Option<Arc<crate::hooks::HookEngine>>,
    policy_enforcer: Option<Arc<PolicyEnforcer>>,
    task_mgr: Arc<Mutex<crate::session::TaskManager>>,
    session_id: Option<String>,
    tx: &'a mpsc::Sender<AppEvent>,
}

/// Drain the streaming accumulators into a `TurnResult`, dispatching
/// any captured tool calls. Sends `ResponseDone` when no follow-up
/// turn is needed — the agentic loop handles the follow-up case.
async fn finalize_sse_stream(f: SseFinalize<'_>) -> Result<TurnResult, String> {
    // Determine tool calls from the appropriate accumulator
    let tool_calls = if f.provider == "anthropic" && f.anthropic_accumulator.has_tool_use() {
        f.anthropic_accumulator.finalize_tool_calls()
    } else if f.tool_accumulator.has_tool_calls() {
        f.tool_accumulator.finalize()
    } else {
        vec![]
    };

    // Execute tool calls if any
    let (tool_results, has_tools) = execute_tool_calls_for_tui(
        f.run_context,
        &tool_calls,
        f.memory_db,
        f.app_config,
        f.permission_mgr,
        f.transient_allowed_tool_rules,
        f.hook_engine,
        f.policy_enforcer,
        f.task_mgr,
        f.session_id.as_deref(),
        f.model_identity,
        f.tx,
    )
    .await;

    // Only send ResponseDone if there are NO tool calls needing followup.
    // When there are tool calls, the caller (app.rs agentic loop) handles
    // the followup requests and sends ResponseDone when truly finished.
    if !has_tools {
        send_event!(f.tx, AppEvent::ResponseDone);
    }

    Ok(TurnResult {
        content: f.full_content,
        reasoning_content: (!f.reasoning_content.is_empty()).then_some(f.reasoning_content),
        tool_calls,
        tool_results,
        usage: f.stream_usage,
        needs_followup: has_tools,
        // The SSE accumulators expose stop_reason internally but this
        // layer does not currently surface it. Anthropic / OpenAI
        // streams report `None`; only the Google JSON path populates
        // this field today (crosslink #788).
        finish_reason: None,
    })
}

/// Result of processing a single SSE event — testable without channels.
#[derive(Debug)]
pub enum SseAction {
    /// Emit text to the streaming output
    Text(String),
    /// Emit thinking text
    Thinking(String),
    /// Emit OpenAI-compatible reasoning text.
    Reasoning(String),
    /// Start a thinking block
    ThinkingStart,
    /// End a thinking block
    ThinkingEnd,
    /// No action needed (event consumed internally by accumulators)
    None,
}

/// Process a single SSE JSON event and return the action to take.
/// Pure function — no channels, no I/O, fully testable.
#[must_use]
pub fn process_sse_event(
    json: &Value,
    in_thinking_block: bool,
    anthropic_accumulator: &mut AnthropicToolAccumulator,
    tool_accumulator: &mut ToolCallAccumulator,
) -> SseAction {
    // Note: usage extraction is handled by the caller after the accumulator
    // processes the event. We used to return SseAction::Usage here, but that
    // caused the accumulator to miss events like message_start and message_delta
    // which contain both usage AND tool call state (stop_reason: "tool_use").

    // Thinking block detection (Anthropic)
    if let Some(event_type) = json.get("type").and_then(|t| t.as_str()) {
        if event_type == "content_block_start"
            && json
                .get("content_block")
                .and_then(|b| b.get("type"))
                .and_then(|t| t.as_str())
                == Some("thinking")
        {
            return SseAction::ThinkingStart;
        }
        if event_type == "content_block_stop" && in_thinking_block {
            return SseAction::ThinkingEnd;
        }
        if event_type == "content_block_delta" && in_thinking_block {
            if let Some(text) = json
                .get("delta")
                .and_then(|d| d.get("thinking"))
                .and_then(|t| t.as_str())
            {
                return SseAction::Thinking(text.to_string());
            }
            if let Some(text) = json
                .get("delta")
                .and_then(|d| d.get("text"))
                .and_then(|t| t.as_str())
            {
                return SseAction::Thinking(text.to_string());
            }
        }
    }

    // Anthropic format: process through accumulator
    if let Some(text) = anthropic_accumulator.process_event(json) {
        return SseAction::Text(text);
    }

    // OpenAI format: choices[0].delta.content
    if let Some(delta) = json
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"))
    {
        if let Some(reasoning) = openai_reasoning_delta_text(delta) {
            return SseAction::Reasoning(reasoning);
        }
        if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
            return SseAction::Text(content.to_string());
        }
        tool_accumulator.process_delta(delta);
    }

    SseAction::None
}

#[derive(Debug)]
enum ResponsesSseAction {
    Text(String),
    Reasoning(String),
    ToolCall(ToolCall),
    Usage(TokenUsage),
    Error(String),
    Done,
    None,
}

fn parse_responses_usage(response: &Value) -> Option<TokenUsage> {
    let usage = response.get("usage")?;
    let input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = usage
        .get("output_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_read_tokens = usage
        .get("input_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if input_tokens == 0 && output_tokens == 0 && cache_read_tokens == 0 {
        return None;
    }
    Some(TokenUsage {
        input_tokens,
        output_tokens,
        cache_read_tokens,
        cache_write_tokens: 0,
    })
}

fn responses_error_message(json: &Value, fallback: &str) -> String {
    json.get("response")
        .and_then(|response| response.get("error"))
        .or_else(|| json.get("error"))
        .and_then(|error| {
            error
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| error.as_str())
        })
        .filter(|message| !message.is_empty())
        .map_or_else(|| fallback.to_string(), str::to_string)
}

fn parse_responses_function_call(item: &Value) -> Result<Option<ToolCall>, String> {
    if item.get("type").and_then(Value::as_str) != Some("function_call") {
        return Ok(None);
    }
    let call_id = item
        .get("call_id")
        .and_then(Value::as_str)
        .or_else(|| item.get("id").and_then(Value::as_str))
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "Responses function_call missing call_id".to_string())?;
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| "Responses function_call missing name".to_string())?;
    let arguments = item
        .get("arguments")
        .and_then(Value::as_str)
        .unwrap_or("{}");
    Ok(Some(ToolCall {
        id: call_id.to_string(),
        call_type: "function".to_string(),
        function: tools::FunctionCall {
            name: name.to_string(),
            arguments: arguments.to_string(),
        },
    }))
}

fn process_responses_sse_event(json: &Value) -> Result<ResponsesSseAction, String> {
    match json.get("type").and_then(Value::as_str).unwrap_or_default() {
        "response.output_text.delta" => Ok(json
            .get("delta")
            .and_then(Value::as_str)
            .filter(|delta| !delta.is_empty())
            .map_or(ResponsesSseAction::None, |delta| {
                ResponsesSseAction::Text(delta.to_string())
            })),
        "response.reasoning_text.delta" | "response.reasoning_summary_text.delta" => Ok(json
            .get("delta")
            .and_then(Value::as_str)
            .filter(|delta| !delta.is_empty())
            .map_or(ResponsesSseAction::None, |delta| {
                ResponsesSseAction::Reasoning(delta.to_string())
            })),
        "response.output_item.done" => {
            let Some(item) = json.get("item") else {
                return Ok(ResponsesSseAction::None);
            };
            parse_responses_function_call(item)
                .map(|call| call.map_or(ResponsesSseAction::None, ResponsesSseAction::ToolCall))
        }
        "response.completed" => {
            if let Some(response) = json.get("response") {
                if let Some(usage) = parse_responses_usage(response) {
                    return Ok(ResponsesSseAction::Usage(usage));
                }
            }
            Ok(ResponsesSseAction::Done)
        }
        "response.failed" => Ok(ResponsesSseAction::Error(responses_error_message(
            json,
            "Responses API request failed",
        ))),
        "response.incomplete" => Ok(ResponsesSseAction::Error(responses_error_message(
            json,
            "Responses API request returned incomplete",
        ))),
        _ => Ok(ResponsesSseAction::None),
    }
}

fn dispatch_responses_action(
    action: ResponsesSseAction,
    full_content: &mut String,
    reasoning_content: &mut String,
    tool_calls: &mut Vec<ToolCall>,
    usage: &mut TokenUsage,
    tx: &mpsc::Sender<AppEvent>,
) -> Result<bool, String> {
    match action {
        ResponsesSseAction::Text(text) => {
            send_event!(tx, AppEvent::StreamText(text.clone()));
            full_content.push_str(&text);
        }
        ResponsesSseAction::Reasoning(text) => {
            let display_text = merge_reasoning_delta(reasoning_content, &text);
            if !display_text.is_empty() {
                send_event!(tx, AppEvent::StreamThinking(display_text));
            }
        }
        ResponsesSseAction::ToolCall(call) => tool_calls.push(call),
        ResponsesSseAction::Usage(observed) => {
            usage.accumulate(&observed);
            return Ok(true);
        }
        ResponsesSseAction::Error(message) => return Err(message),
        ResponsesSseAction::Done => return Ok(true),
        ResponsesSseAction::None => {}
    }
    Ok(false)
}

async fn stream_responses_sse_response(p: SseStreamParams<'_>) -> Result<TurnResult, String> {
    let SseStreamParams {
        run_context,
        response,
        headers,
        model_identity,
        memory_db,
        app_config,
        permission_mgr,
        transient_allowed_tool_rules,
        hook_engine,
        policy_enforcer,
        task_mgr,
        session_id,
        tx,
        ..
    } = p;
    let mut stream = response.bytes_stream().eventsource();
    let mut full_content = String::new();
    let mut reasoning_content = String::new();
    let mut tool_calls = Vec::new();
    let mut stream_usage = TokenUsage::default();
    let mut last_data_time = std::time::Instant::now();
    let stream_timeout = std::time::Duration::from_secs(proxy::SSE_STREAM_TIMEOUT_SECS);

    loop {
        let sse = match tokio::time::timeout(stream_timeout, stream.next()).await {
            Ok(Some(Ok(sse))) => sse,
            Ok(Some(Err(e))) => {
                send_event!(tx, AppEvent::ApiError(format!("Stream error: {e}").into()));
                break;
            }
            Ok(None) => break,
            Err(_) => {
                handle_sse_timeout(last_data_time.elapsed().as_secs(), full_content.len(), tx)?;
                break;
            }
        };

        last_data_time = std::time::Instant::now();
        if sse.data == "[DONE]" {
            break;
        }

        let json = serde_json::from_str::<Value>(&sse.data)
            .map_err(|err| format!("Failed to parse Responses SSE event: {err}"))?;
        let action = process_responses_sse_event(&json)
            .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;
        let done = dispatch_responses_action(
            action,
            &mut full_content,
            &mut reasoning_content,
            &mut tool_calls,
            &mut stream_usage,
            tx,
        )
        .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;
        if done {
            break;
        }
    }

    let (tool_results, needs_followup) = execute_tool_calls_for_tui(
        run_context,
        &tool_calls,
        memory_db,
        app_config,
        permission_mgr,
        transient_allowed_tool_rules,
        hook_engine,
        policy_enforcer,
        task_mgr,
        session_id.as_deref(),
        model_identity,
        tx,
    )
    .await;
    if !needs_followup {
        send_event!(tx, AppEvent::ResponseDone);
    }
    Ok(TurnResult {
        content: full_content,
        reasoning_content: (!reasoning_content.is_empty()).then_some(reasoning_content),
        tool_calls,
        tool_results,
        usage: stream_usage,
        needs_followup,
        finish_reason: None,
    })
}

fn openai_reasoning_delta_text(delta: &Value) -> Option<String> {
    if let Some(reasoning) = delta.get("reasoning_content").and_then(Value::as_str) {
        return (!reasoning.is_empty()).then(|| reasoning.to_string());
    }
    if let Some(reasoning) = delta.get("reasoning").and_then(Value::as_str) {
        return (!reasoning.is_empty()).then(|| reasoning.to_string());
    }

    let details = delta.get("reasoning_details").and_then(Value::as_array)?;
    let text = details
        .iter()
        .filter_map(|detail| detail.get("text").and_then(Value::as_str))
        .collect::<String>();
    (!text.is_empty()).then_some(text)
}

/// Append a reasoning delta to `buffer` and return only the newly-displayable text.
///
/// Some OpenAI-compatible providers send cumulative reasoning text instead of
/// incremental chunks. This keeps persisted reasoning complete while avoiding
/// duplicate display output.
#[must_use]
pub fn merge_reasoning_delta(buffer: &mut String, text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    if !buffer.is_empty() && text.starts_with(buffer.as_str()) {
        let suffix = text[buffer.len()..].to_string();
        buffer.push_str(&suffix);
        suffix
    } else {
        buffer.push_str(text);
        text.to_string()
    }
}

/// Check whether a tool's declared ceiling reaches the authorization policy.
///
/// This is a catalog helper for UI/tests. Concrete dispatch resolves the
/// invocation through the mandatory host-safety and permission policies.
/// Unknown tools return `true`; omission is never interpreted as safe.
#[must_use]
pub fn tool_needs_permission(tool_name: &str) -> bool {
    crate::tools::effect::lookup(tool_name)
        .is_none_or(|(_, spec)| spec.effect.requires_authorization())
}

/// Execute tool calls and send progress events to the TUI.
///
/// Each tool runs on a blocking thread via `spawn_blocking` so the async
/// event channel stays responsive — the TUI can redraw and show progress
/// while tools execute.
///
/// Outcome of a TUI permission check for a single tool call.
enum PermissionOutcome {
    /// The tool is allowed to proceed.
    Allowed {
        authorization: Option<ExecutionPermit>,
    },
    /// The tool was denied; the caller should push `result_json` and `continue`.
    DeniedWithResult(serde_json::Value),
    /// The permission channel is broken; the caller should `break`.
    ChannelBroken,
}

fn permission_denied_with_result(
    tool_name: &str,
    tool_call_id: &str,
    tool_done_content: &str,
    model_content: &str,
    tx: &mpsc::Sender<AppEvent>,
) -> PermissionOutcome {
    let _ = tx.send(AppEvent::ToolDone {
        name: tool_name.to_string(),
        success: false,
        content: tool_done_content.to_string(),
    });
    PermissionOutcome::DeniedWithResult(serde_json::json!({
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": model_content,
        "is_error": true
    }))
}

fn observe_policy_decision_json(
    run: &crate::tools::ToolRunContext,
    session_id: Option<&str>,
    allowed: bool,
    reason: &str,
) {
    if let Some(session_id) = session_id {
        crate::grounded_loop::observe_policy_decision_for_session(run, session_id, allowed, reason);
    }
}

fn policy_denied_tool_result(
    run: &crate::tools::ToolRunContext,
    tool_name: &str,
    tool_call_id: &str,
    error: &PolicyError,
    session_id: Option<&str>,
    tx: &mpsc::Sender<AppEvent>,
) -> Value {
    let reason = error.to_string();
    observe_policy_decision_json(run, session_id, false, &reason);
    let _ = tx.send(AppEvent::ToolDone {
        name: tool_name.to_string(),
        success: false,
        content: format!("Blocked by policy: {reason}"),
    });
    serde_json::json!({
        "role": "tool",
        "tool_call_id": tool_call_id,
        "content": format!("[POLICY DENIED] {reason}"),
        "is_error": true
    })
}

async fn permission_request_hook_outcome(
    run_context: &Arc<tools::ToolRunContext>,
    tool_name: &str,
    tool_call_id: &str,
    arguments: &str,
    session_id: Option<&str>,
    hook_engine: Option<&crate::hooks::HookEngine>,
    tx: &mpsc::Sender<AppEvent>,
) -> Option<PermissionOutcome> {
    let engine = hook_engine?;
    let tool_input = serde_json::from_str::<Value>(arguments)
        .unwrap_or_else(|_| serde_json::json!({ "raw_arguments": arguments }));
    let mut input =
        crate::hooks::HookInput::for_run(run_context, crate::hooks::HookEvent::PermissionRequest)
            .with_tool(tool_name, tool_input)
            .with_extra(
                "tool_call_id",
                serde_json::Value::String(tool_call_id.to_string()),
            );
    if let Some(session_id) = session_id {
        input = input.with_session_id(session_id);
    }

    let result = engine
        .run(crate::hooks::HookEvent::PermissionRequest, &input)
        .await;
    if result.allowed {
        return None;
    }

    let reason = result
        .outputs
        .iter()
        .find_map(|output| output.reason.as_deref())
        .unwrap_or("Permission request blocked by hook");
    Some(permission_denied_with_result(
        tool_name,
        tool_call_id,
        &format!("Permission request blocked by hook: {reason}"),
        &format!("[DENIED] Permission request blocked by hook: {reason}"),
        tx,
    ))
}

/// Check whether a tool call is permitted in the current session.
///
/// Consults the canonical permission manager first. Exact reusable approval
/// records are consumed there; no frontend-local tool-name cache participates.
/// If no receipt or policy matches, runs `PermissionRequest` hooks and awaits
/// the user's decision via a Tokio oneshot.
///
/// `async` so the reply wait yields the runtime — under
/// `flavor = "current_thread"` a synchronous `mpsc::recv` here would
/// pin the only thread and deadlock the main TUI loop (which is the
/// one that has to deliver the user's response).
#[allow(clippy::too_many_arguments)]
async fn check_tool_permission(
    run_context: &Arc<tools::ToolRunContext>,
    tool_name: &str,
    tool_call_id: &str,
    arguments: &str,
    permission_mgr: &PermissionManager,
    transient_allowed_tool_rules: &[PermissionRule],
    hook_engine: Option<&crate::hooks::HookEngine>,
    session_id: Option<&str>,
    tx: &mpsc::Sender<AppEvent>,
) -> PermissionOutcome {
    let tool_call = ToolCall {
        id: tool_call_id.to_string(),
        call_type: "function".to_string(),
        function: crate::tools::FunctionCall {
            name: tool_name.to_string(),
            arguments: arguments.to_string(),
        },
    };

    match permission_mgr.authorize_tool_call_with_transient_rules(
        &tool_call,
        session_id,
        transient_allowed_tool_rules,
    ) {
        AuthorizationResult::Allowed(permit) => {
            return PermissionOutcome::Allowed {
                authorization: Some(permit),
            };
        }
        AuthorizationResult::Denied(reason) => {
            return permission_denied_with_result(
                tool_name,
                tool_call_id,
                &format!("Permission denied: {reason}"),
                &format!("[DENIED] Permission denied: {reason}"),
                tx,
            );
        }
        AuthorizationResult::NeedsPrompt { .. } => {}
    }

    if let Some(outcome) = permission_request_hook_outcome(
        run_context,
        tool_name,
        tool_call_id,
        arguments,
        session_id,
        hook_engine,
        tx,
    )
    .await
    {
        return outcome;
    }

    let args_preview = if arguments.len() > 200 {
        format!("{}...", crate::tools::safe_truncate(arguments, 197))
    } else {
        arguments.to_string()
    };
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if tx
        .send(AppEvent::PermissionRequest {
            tool_name: tool_name.to_string(),
            tool_args: args_preview,
            reply: reply_tx,
        })
        .is_err()
    {
        return PermissionOutcome::ChannelBroken;
    }
    permission_prompt_response(&reply_rx.await, permission_mgr, session_id, &tool_call, tx)
}

fn permission_prompt_response(
    response: &Result<PermissionResponse, tokio::sync::oneshot::error::RecvError>,
    permission_mgr: &PermissionManager,
    session_id: Option<&str>,
    tool_call: &ToolCall,
    tx: &mpsc::Sender<AppEvent>,
) -> PermissionOutcome {
    let tool_name = &tool_call.function.name;
    let tool_call_id = &tool_call.id;
    match response {
        Ok(PermissionResponse::Allow) => permission_mgr
            .approve_tool_call_once(tool_call, session_id, ApprovalProvenance::InteractiveUser)
            .map_or_else(
                |reason| {
                    permission_denied_with_result(
                        tool_name,
                        tool_call_id,
                        &format!("Permission approval failed: {reason}"),
                        &format!("[DENIED] Permission approval failed: {reason}"),
                        tx,
                    )
                },
                |permit| PermissionOutcome::Allowed {
                    authorization: Some(permit),
                },
            ),
        Ok(PermissionResponse::AlwaysAllow) => session_id.map_or_else(
            || {
                permission_denied_with_result(
                    tool_name,
                    tool_call_id,
                    "A scoped reusable approval requires a permission manager and session",
                    "[DENIED] Scoped reusable approval unavailable.",
                    tx,
                )
            },
            |session_id| {
                permission_mgr
                    .approve_tool_call_for_session(
                        tool_call,
                        session_id,
                        ApprovalProvenance::InteractiveUser,
                    )
                    .map_or_else(
                        |reason| {
                            permission_denied_with_result(
                                tool_name,
                                tool_call_id,
                                &format!("Permission approval failed: {reason}"),
                                &format!("[DENIED] Permission approval failed: {reason}"),
                                tx,
                            )
                        },
                        |permit| PermissionOutcome::Allowed {
                            authorization: Some(permit),
                        },
                    )
            },
        ),
        Ok(PermissionResponse::AlwaysDeny) => {
            if let Some(session_id) = session_id {
                if let Err(error) = permission_mgr.deny_tool_call_for_session(
                    tool_call,
                    session_id,
                    ApprovalProvenance::InteractiveUser,
                ) {
                    tracing::warn!(%error, "Could not retain exact session denial");
                }
            }
            permission_denied_with_result(
                tool_name,
                tool_call_id,
                "Denied (always deny)",
                "[DENIED] User denied permission.",
                tx,
            )
        }
        Ok(PermissionResponse::Deny) | Err(_) => permission_denied_with_result(
            tool_name,
            tool_call_id,
            "Denied by user",
            "[DENIED] User denied permission.",
            tx,
        ),
    }
}

struct ToolPermissionDispatch {
    mgr: Arc<PermissionManager>,
    authorization: Option<ExecutionPermit>,
}

struct SingleToolExecution<'a> {
    run_context: Arc<tools::ToolRunContext>,
    tool_call: &'a ToolCall,
    memory_db: Option<Arc<MemoryDb>>,
    app_config: Option<Arc<AppConfig>>,
    permission: ToolPermissionDispatch,
    policy_enforcer: Option<Arc<PolicyEnforcer>>,
    task_mgr: Arc<Mutex<crate::session::TaskManager>>,
    session_id: Option<&'a str>,
    hook_context: Option<(&'a crate::hooks::HookEngine, Value)>,
    tx: &'a mpsc::Sender<AppEvent>,
}

/// Execute one tool call on a blocking thread, fire `PostToolUse` hooks, and
/// return the canonical typed result for provider projection.
/// Returns `None` when the event channel is broken (caller should `break`).
async fn execute_single_tool(p: SingleToolExecution<'_>) -> Option<tools::ToolResult> {
    let SingleToolExecution {
        run_context,
        tool_call,
        memory_db,
        app_config,
        permission,
        policy_enforcer,
        task_mgr,
        session_id,
        hook_context,
        tx,
    } = p;
    let tool_name = &tool_call.function.name;
    let perm_mgr = permission.mgr;
    let tool_call_clone = tool_call.clone();
    let panic_tool_call = tool_call.clone();
    let mem_db = memory_db;
    let app_config_for_blocking = app_config;
    let authorization_for_blocking = permission.authorization;
    let session_for_blocking = session_id.map(str::to_string);
    let policy_for_blocking = policy_enforcer;
    let task_mgr_for_blocking = task_mgr;
    let run_context_for_blocking = Arc::clone(&run_context);
    let result = tokio::task::spawn_blocking(move || {
        // Lock the TaskManager only inside the blocking thread so we
        // don't hold the mutex across `.await`. Failure-mode parity with
        // the legacy "no session" branch: poisoned mutex → recover the
        // inner data rather than panicking, so a single panicking task
        // tool doesn't take down the entire TUI session.
        let mut task_guard = task_mgr_for_blocking
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::services::tool_executor::ToolExecutor::execute(
            crate::services::tool_executor::ToolExecutorRequest {
                run_context: &run_context_for_blocking,
                tool_call: &tool_call_clone,
                memory_db: mem_db.as_deref(),
                app_config: app_config_for_blocking.as_deref(),
                task_mgr: Some(&mut *task_guard),
                permission_mgr: perm_mgr.as_ref(),
                authorization: authorization_for_blocking,
                session_id: session_for_blocking.as_deref(),
                policy_enforcer: policy_for_blocking.as_deref(),
            },
        )
    })
    .await
    .unwrap_or_else(|e| {
        tools::ToolResult::failure(
            &panic_tool_call,
            tools::ToolFailureCode::Internal,
            format!("Tool execution panicked: {e}"),
            tools::ToolRetryability::Never,
        )
    });
    if tx
        .send(AppEvent::ToolDone {
            name: tool_name.clone(),
            success: !result.is_error(),
            content: result.content().to_string(),
        })
        .is_err()
    {
        return None;
    }
    if let Some((engine, tool_input)) = hook_context {
        crate::services::tool_executor::ToolExecutor::fire_post_tool(
            &run_context,
            engine,
            !result.is_error(),
            tool_name,
            tool_input,
            result.content(),
            session_id,
        )
        .await;
    }
    Some(result)
}

/// Build a human-readable one-line description of what a tool call will do.
fn describe_tool_call(tool_name: &str, args: &Value) -> String {
    match tool_name {
        "read_file" => args
            .get("path")
            .and_then(|v| v.as_str())
            .map_or_else(|| "Reading file".to_string(), |p| format!("Reading {p}")),
        "write_file" => args
            .get("path")
            .and_then(|v| v.as_str())
            .map_or_else(|| "Writing file".to_string(), |p| format!("Writing {p}")),
        "edit_file" => args
            .get("path")
            .and_then(|v| v.as_str())
            .map_or_else(|| "Editing file".to_string(), |p| format!("Editing {p}")),
        "bash" => args.get("command").and_then(|v| v.as_str()).map_or_else(
            || "Running command".to_string(),
            |c| {
                let truncated = if c.len() > 80 {
                    crate::tools::safe_truncate(c, 77)
                } else {
                    c
                };
                format!("$ {truncated}")
            },
        ),
        "list_files" => args
            .get("path")
            .and_then(|v| v.as_str())
            .map_or_else(|| "Listing files".to_string(), |p| format!("Listing {p}")),
        "web_search" => args.get("query").and_then(|v| v.as_str()).map_or_else(
            || "Searching web".to_string(),
            |q| format!("Searching: {q}"),
        ),
        "web_fetch" => args
            .get("url")
            .and_then(|v| v.as_str())
            .map_or_else(|| "Fetching URL".to_string(), |u| format!("Fetching {u}")),
        "crosslink" => args.get("operation").and_then(|v| v.as_str()).map_or_else(
            || "Running crosslink".to_string(),
            |operation| format!("crosslink {operation}"),
        ),
        _ => format!("Running {tool_name}"),
    }
}

fn parse_tool_arguments_for_tui(tool_name: &str, arguments: &str) -> Result<Value, String> {
    crate::services::tool_executor::ToolExecutor::parse_arguments(tool_name, arguments)
}

fn malformed_tool_arguments_result(
    tool_call: &ToolCall,
    msg: &str,
    tx: &mpsc::Sender<AppEvent>,
) -> Result<Value, ()> {
    tx.send(AppEvent::ToolDone {
        name: tool_call.function.name.clone(),
        success: false,
        content: msg.to_string(),
    })
    .map_err(|_| ())?;

    Ok(serde_json::json!({
        "role": "tool",
        "tool_call_id": tool_call.id,
        "content": format!("[ERROR] {msg}"),
        "is_error": true
    }))
}

/// Return a provider-history-safe JSON object string for a tool call's
/// `function.arguments`.
///
/// Tool executors still receive the original model text and can report malformed
/// JSON as a tool error. Conversation history is stricter: providers require
/// historical assistant tool calls to carry valid JSON-object arguments so each
/// following tool result can be paired with its call. When the model emitted an
/// empty or malformed argument stream, `{}` is the only safe neutral object.
#[must_use]
pub fn history_safe_tool_arguments(tool_name: &str, arguments: &str) -> String {
    match serde_json::from_str::<Value>(arguments) {
        Ok(Value::Object(_)) => arguments.to_string(),
        Ok(value) => {
            tracing::warn!(
                tool = tool_name,
                json_type = json_value_type_name(&value),
                "normalizing non-object tool arguments to empty object for provider history"
            );
            "{}".to_string()
        }
        Err(err) => {
            tracing::warn!(
                tool = tool_name,
                error = %err,
                "normalizing malformed tool arguments to empty object for provider history"
            );
            "{}".to_string()
        }
    }
}

/// Normalize historical assistant tool-call arguments in-place so provider
/// adapters do not reject a turn solely because an earlier streamed tool call
/// had empty or malformed arguments.
///
/// Returns the number of tool-call argument fields changed.
pub fn normalize_message_tool_arguments_for_history(messages: &mut [Value]) -> usize {
    let mut changed = 0;
    for msg in messages {
        if msg.get("role").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let Some(tool_calls) = msg.get_mut("tool_calls").and_then(Value::as_array_mut) else {
            continue;
        };
        for call in tool_calls {
            let Some(func) = call.get_mut("function").and_then(Value::as_object_mut) else {
                continue;
            };
            let tool_name = func
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>")
                .to_string();
            match func.get_mut("arguments") {
                Some(Value::String(arguments)) => {
                    let safe = history_safe_tool_arguments(&tool_name, arguments);
                    if safe != *arguments {
                        *arguments = safe;
                        changed += 1;
                    }
                }
                Some(other) => {
                    tracing::warn!(
                        tool = tool_name,
                        json_type = json_value_type_name(other),
                        "normalizing non-string tool arguments to empty object for provider history"
                    );
                    *other = Value::String("{}".to_string());
                    changed += 1;
                }
                None => {
                    tracing::warn!(
                        tool = tool_name,
                        "normalizing missing tool arguments to empty object for provider history"
                    );
                    func.insert("arguments".to_string(), Value::String("{}".to_string()));
                    changed += 1;
                }
            }
        }
    }
    changed
}

fn emit_failed_quality_gate_events(
    run_context: &Arc<tools::ToolRunContext>,
    tx: &mpsc::Sender<AppEvent>,
    session_id: Option<&str>,
    model_identity: &str,
) {
    for gate in crate::guardrails::run_quality_gates(run_context, model_identity) {
        record_quality_gate_verification(run_context, session_id, &gate);
        if gate.passed() {
            continue;
        }
        if tx.send(failed_quality_gate_event(&gate)).is_err() {
            tracing::warn!("TUI channel closed during tool execution");
            break;
        }
    }
}

fn failed_quality_gate_event(gate: &crate::guardrails::QualityCheckResult) -> AppEvent {
    let detail = gate
        .stdout()
        .lines()
        .next()
        .filter(|line| !line.trim().is_empty())
        .or_else(|| {
            gate.stderr()
                .lines()
                .next()
                .filter(|line| !line.trim().is_empty())
        })
        .unwrap_or("failed");
    AppEvent::ToolDone {
        name: format!("quality_gate:{}", gate.name()),
        success: false,
        content: format!("Quality gate '{}' failed: {detail}", gate.name()),
    }
}

fn record_quality_gate_verification(
    run: &crate::tools::ToolRunContext,
    session_id: Option<&str>,
    gate: &crate::guardrails::QualityCheckResult,
) {
    let Some(session_id) = session_id else {
        return;
    };
    let mut ledger = match crate::ledger::RealityLedger::open_project_session(session_id) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                session_id,
                gate = %gate.name(),
                error = %err,
                "failed to open session reality ledger for quality-gate verification"
            );
            return;
        }
    };
    if let Err(err) = crate::grounded_loop::append_quality_gate_observations(run, &mut ledger, gate)
    {
        tracing::warn!(
            session_id,
            gate = %gate.name(),
            error = %err,
            "failed to append quality-gate observations to reality ledger"
        );
    }
}

/// Checks permissions for write/destructive tools via a channel-based
/// handshake: sends `PermissionRequest` to the TUI and blocks until
/// the user responds with y/n/a/d.
///
/// Returns the tool result messages (for appending to conversation history)
/// and a boolean indicating whether there were any tool calls.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn execute_tool_calls_for_tui(
    run_context: Arc<tools::ToolRunContext>,
    tool_calls: &[ToolCall],
    memory_db: Option<Arc<MemoryDb>>,
    app_config: Option<Arc<AppConfig>>,
    permission_mgr: Option<Arc<PermissionManager>>,
    transient_allowed_tool_rules: &[PermissionRule],
    hook_engine: Option<Arc<crate::hooks::HookEngine>>,
    policy_enforcer: Option<Arc<PolicyEnforcer>>,
    task_mgr: Arc<Mutex<crate::session::TaskManager>>,
    session_id: Option<&str>,
    model_identity: &str,
    tx: &mpsc::Sender<AppEvent>,
) -> (Vec<Value>, bool) {
    // Session-level "always allow/deny" cache (lives for this agentic loop)
    if tool_calls.is_empty() {
        return (vec![], false);
    }

    let Some(permission_mgr) = permission_mgr else {
        let mut results = Vec::with_capacity(tool_calls.len());
        for tool_call in tool_calls {
            let result = tools::ToolResult::failure(
                tool_call,
                tools::ToolFailureCode::PermissionDenied,
                "Permission denied: the execution frontend has no permission manager".to_string(),
                tools::ToolRetryability::Never,
            );
            if tx
                .send(AppEvent::ToolDone {
                    name: tool_call.function.name.clone(),
                    success: false,
                    content: result.content().to_string(),
                })
                .is_err()
            {
                break;
            }
            observe_tool_result(&run_context, session_id, &result);
            results.push(result.openai_message());
        }
        return (results, true);
    };

    let mut results = Vec::new();

    for tool_call in tool_calls {
        let tool_name = &tool_call.function.name;
        let tool_args = match parse_tool_arguments_for_tui(tool_name, &tool_call.function.arguments)
        {
            Ok(args) => args,
            Err(msg) => match malformed_tool_arguments_result(tool_call, &msg, tx) {
                Ok(result_json) => {
                    observe_tool_result_json(&run_context, session_id, tool_name, &result_json);
                    results.push(result_json);
                    continue;
                }
                Err(()) => break,
            },
        };

        if let Err(err) = crate::services::tool_executor::ToolExecutor::check_policy_before_prompt(
            policy_enforcer.as_deref(),
            session_id,
            tool_name,
        ) {
            let result_json = policy_denied_tool_result(
                &run_context,
                tool_name,
                &tool_call.id,
                &err,
                session_id,
                tx,
            );
            observe_tool_result_json(&run_context, session_id, tool_name, &result_json);
            results.push(result_json);
            continue;
        }

        if let Some(engine) = hook_engine.as_deref() {
            if let Err(blocked) = crate::services::tool_executor::ToolExecutor::run_pre_tool_use(
                &run_context,
                engine,
                session_id,
                tool_name,
                &tool_args,
            )
            .await
            {
                send_event_or_break!(
                    tx,
                    AppEvent::ToolDone {
                        name: tool_name.clone(),
                        success: false,
                        content: blocked.content.clone(),
                    }
                );
                let result_json = serde_json::json!({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": format!("[BLOCKED] {}", blocked.content),
                    "is_error": true
                });
                observe_tool_result_json(&run_context, session_id, tool_name, &result_json);
                results.push(result_json);
                continue;
            }
        }

        // Every call, including read-only calls, reaches the concrete manager
        // so explicit denials and host safety remain enforceable.
        let authorization = match check_tool_permission(
            &run_context,
            tool_name,
            &tool_call.id,
            &tool_call.function.arguments,
            permission_mgr.as_ref(),
            transient_allowed_tool_rules,
            hook_engine.as_deref(),
            session_id,
            tx,
        )
        .await
        {
            PermissionOutcome::Allowed { authorization } => authorization,
            PermissionOutcome::DeniedWithResult(result_json) => {
                observe_tool_result_json(&run_context, session_id, tool_name, &result_json);
                results.push(result_json);
                continue;
            }
            PermissionOutcome::ChannelBroken => break,
        };

        let args_desc = describe_tool_call(tool_name, &tool_args);
        let hook_context = hook_engine
            .as_ref()
            .map(|engine| (Arc::as_ref(engine), tool_args.clone()));
        send_event_or_break!(
            tx,
            AppEvent::ToolStart {
                name: tool_name.clone(),
                description: args_desc
            }
        );

        let tool_result = execute_single_tool(SingleToolExecution {
            run_context: Arc::clone(&run_context),
            tool_call,
            memory_db: memory_db.clone(),
            app_config: app_config.clone(),
            permission: ToolPermissionDispatch {
                mgr: Arc::clone(&permission_mgr),
                authorization,
            },
            policy_enforcer: policy_enforcer.clone(),
            task_mgr: task_mgr.clone(),
            session_id,
            hook_context,
            tx,
        })
        .await;
        match tool_result {
            None => break, // channel broken
            Some(mut result) => {
                if resolve_tui_follow_up(&mut result, tx).await.is_err() {
                    break;
                }
                observe_tool_result(&run_context, session_id, &result);
                results.push(result.openai_message());
            }
        }
    }

    emit_failed_quality_gate_events(&run_context, tx, session_id, model_identity);

    (results, true)
}

fn observe_tool_result_json(
    run: &crate::tools::ToolRunContext,
    session_id: Option<&str>,
    tool_name: &str,
    result_json: &Value,
) {
    let Some(session_id) = session_id else {
        return;
    };
    let tool_call = ToolCall {
        id: result_json
            .get("tool_call_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        call_type: "function".to_string(),
        function: crate::tools::FunctionCall {
            name: tool_name.to_string(),
            arguments: "{}".to_string(),
        },
    };
    let result = tools::ToolResult::bind(
        &tool_call,
        tool_name,
        tools::ToolHandlerResult::legacy(
            result_json
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            result_json
                .get("is_error")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
    );
    observe_tool_result(run, Some(session_id), &result);
}

fn observe_tool_result(
    run: &crate::tools::ToolRunContext,
    session_id: Option<&str>,
    result: &tools::ToolResult,
) {
    let Some(session_id) = session_id else {
        return;
    };
    crate::services::tool_executor::ToolExecutor::observe_tool_result(
        run,
        Some(session_id),
        result,
    );
}

/// Resolve a trusted typed follow-up through the full-screen TUI. Ordinary
/// tool text is never inspected for control state.
async fn resolve_tui_follow_up(
    result: &mut tools::ToolResult,
    tx: &mpsc::Sender<AppEvent>,
) -> Result<(), ()> {
    let follow_up = result.follow_up().clone();
    let tools::ToolFollowUp::UserQuestion { questions, .. } = follow_up else {
        if result.follow_up().is_pending() {
            let message = "This typed follow-up is not supported by the full-screen TUI";
            *result = result
                .cancel_follow_up(message.to_string(), message.to_string())
                .expect("pending follow-up can be cancelled");
        }
        return Ok(());
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if tx
        .send(AppEvent::UserQuestion {
            questions: questions
                .iter()
                .map(tools::ToolQuestion::widget_value)
                .collect(),
            reply: reply_tx,
        })
        .is_err()
    {
        return Err(());
    }

    // Modal dropped the sender (e.g. user cancelled with Ctrl+C) →
    // surface a structured `_cancelled: true` payload to the agent
    // instead of hanging.
    let answers = reply_rx
        .await
        .unwrap_or_else(|_| "{\"_cancelled\": true}".to_string());
    let response =
        serde_json::from_str(&answers).unwrap_or_else(|_| Value::String(answers.clone()));
    *result = result
        .resolve_follow_up(answers, response)
        .expect("typed user question has one pending follow-up");
    Ok(())
}

/// Build the assistant message with tool calls for appending to conversation history.
#[must_use]
pub fn build_assistant_message_with_tools(
    content: &str,
    reasoning_content: Option<&str>,
    tool_calls: &[ToolCall],
    _provider: &str,
) -> Value {
    let tool_calls_json: Vec<Value> = tool_calls
        .iter()
        .map(|tc| {
            let arguments = history_safe_tool_arguments(&tc.function.name, &tc.function.arguments);
            serde_json::json!({
                "id": tc.id,
                "type": tc.call_type,
                "function": {
                    "name": tc.function.name,
                    "arguments": arguments
                }
            })
        })
        .collect();

    let mut message = serde_json::json!({
        "role": "assistant",
        "content": Value::String(content.to_string()),
        "tool_calls": tool_calls_json
    });
    if let Some(reasoning) = reasoning_content.filter(|text| !text.is_empty()) {
        message["reasoning_content"] = Value::String(reasoning.to_string());
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_run() -> Arc<tools::ToolRunContext> {
        Arc::clone(tools::security::test_run_context())
    }

    fn typed_test_blocks(prefix: &str, suffix: &str) -> crate::prompt::SystemPromptBlocks {
        let mut items = Vec::new();
        if !prefix.is_empty() {
            items.push(crate::context::ContextItem::host_instruction(
                "test.stable",
                crate::context::HostInstructionSource::CorePolicy,
                "compiled:test",
                prefix,
                crate::context::ContextFreshness::Static,
                1,
            ));
        }
        if !suffix.is_empty() {
            items.push(crate::context::ContextItem::host_instruction(
                "test.dynamic",
                crate::context::HostInstructionSource::RuntimePolicy,
                "host:test",
                suffix,
                crate::context::ContextFreshness::Turn,
                2,
            ));
        }
        crate::prompt::SystemPromptBlocks::from_items(
            items,
            crate::context::ContextBudget::default(),
        )
    }

    #[test]
    fn quality_gate_records_command_and_failed_gate_findings() {
        let run = crate::tools::security::test_run_context_for(std::path::Path::new(env!(
            "CARGO_MANIFEST_DIR"
        )));
        let mut ledger = crate::ledger::RealityLedger::new();
        let config = crate::config::GuardrailsConfig {
            quality_gates: Some(crate::config::QualityGatesConfig {
                enabled: true,
                checks: vec![crate::config::QualityCheck {
                    name: "unit".to_string(),
                    command: "sh -c 'printf running-tests; printf one-failed >&2; exit 7'"
                        .to_string(),
                    required: true,
                }],
                ..crate::config::QualityGatesConfig::default()
            }),
            ..crate::config::GuardrailsConfig::default()
        };
        crate::guardrails::configure(&run, &config).expect("configure gate");
        let gate = crate::guardrails::run_quality_gates(&run, "test-model")
            .into_iter()
            .next()
            .expect("gate result");

        let event = failed_quality_gate_event(&gate);
        let AppEvent::ToolDone {
            name,
            success,
            content,
        } = event
        else {
            panic!("failed quality gate must not enter the model-text stream");
        };
        assert_eq!(name, "quality_gate:unit");
        assert!(!success);
        assert!(content.contains("running-tests"));

        let ids = crate::grounded_loop::append_quality_gate_observations(&run, &mut ledger, &gate)
            .expect("append");
        let command_observation = ledger.get(ids.command).expect("command observation");
        assert_eq!(
            command_observation.provenance.trust,
            crate::ledger::EvidenceTrust::RuntimeObserved
        );
        assert!(command_observation.provenance.is_bound_to(&run));
        let crate::ledger::ObservationKind::CommandRun {
            argv,
            exit_code,
            stdout,
            stderr,
            ..
        } = &command_observation.kind
        else {
            panic!("expected command observation");
        };
        assert_eq!(
            argv,
            &vec![
                "sh".to_string(),
                "-c".to_string(),
                "printf running-tests; printf one-failed >&2; exit 7".to_string()
            ]
        );
        assert_eq!(*exit_code, 7);
        assert_eq!(stdout, "running-tests");
        assert_eq!(stderr, "one-failed");

        let observation = ledger.get(ids.verification).expect("observation");
        assert_eq!(
            observation.provenance.trust,
            crate::ledger::EvidenceTrust::TrustedVerifier
        );
        assert!(observation.provenance.is_bound_to(&run));
        assert!(observation.provenance.verification_method.is_some());
        let crate::ledger::ObservationKind::Verification {
            passed,
            command,
            findings,
        } = &observation.kind
        else {
            panic!("expected verification observation");
        };
        assert!(!passed);
        assert_eq!(
            command.as_deref(),
            Some("sh -c 'printf running-tests; printf one-failed >&2; exit 7'")
        );
        assert!(findings
            .iter()
            .any(|finding| finding.contains("quality gate 'unit' failed")));
        assert!(findings.iter().any(|finding| finding.contains("stdout:")));
        assert!(findings.iter().any(|finding| finding.contains("stderr:")));
    }

    #[test]
    fn parse_tool_arguments_for_tui_rejects_malformed_and_non_object_json() {
        let malformed = parse_tool_arguments_for_tui("bash", "{not json")
            .expect_err("malformed tool args must fail before TUI prompting");
        assert!(
            malformed.contains("Invalid tool arguments JSON"),
            "{malformed}"
        );
        assert!(malformed.contains("bash"), "{malformed}");

        let non_object = parse_tool_arguments_for_tui("bash", "[]")
            .expect_err("non-object tool args must fail before TUI prompting");
        assert!(
            non_object.contains("expected a JSON object"),
            "{non_object}"
        );
        assert!(non_object.contains("array"), "{non_object}");
    }

    #[tokio::test]
    async fn execute_tool_calls_for_tui_rejects_malformed_arguments_before_prompting() {
        use std::sync::mpsc as std_mpsc;

        let session_id = "tui-malformed-tool-result-ledger";
        let ledger = Arc::new(Mutex::new(crate::ledger::RealityLedger::new()));
        let _ledger_guard =
            crate::ledger::install_active_ledger_for_session(session_id, Arc::clone(&ledger));
        let tool_call = ToolCall {
            id: "call_bad".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "bash".to_string(),
                arguments: "{not json".to_string(),
            },
        };
        let (tx, rx) = std_mpsc::channel::<AppEvent>();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));
        let permission_mgr = Some(Arc::new(PermissionManager::unrestricted()));

        let (results, has_tools) = execute_tool_calls_for_tui(
            test_run(),
            &[tool_call],
            None,
            None,
            permission_mgr,
            &[],
            None,
            None,
            task_mgr,
            Some(session_id),
            "test-model",
            &tx,
        )
        .await;

        assert!(has_tools);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["is_error"], true);
        assert!(
            results[0]["content"]
                .as_str()
                .is_some_and(|content| content.contains("Invalid tool arguments JSON")),
            "tool result should carry the parse error: {}",
            results[0]
        );

        let mut saw_tool_done = false;
        let mut saw_permission_request = false;
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::ToolDone { content, .. } => {
                    saw_tool_done = content.contains("Invalid tool arguments JSON");
                }
                AppEvent::PermissionRequest { .. } => saw_permission_request = true,
                _ => {}
            }
        }

        assert!(saw_tool_done, "TUI should receive the parse failure");
        assert!(
            !saw_permission_request,
            "malformed arguments must not trigger a permission prompt"
        );

        let observation = {
            let ledger = ledger.lock().expect("ledger lock");
            ledger
                .observations_chronological()
                .into_iter()
                .find(|obs| matches!(obs.kind, crate::ledger::ObservationKind::ToolResult { .. }))
                .cloned()
        }
        .expect("malformed tool result observation");
        let crate::ledger::ObservationKind::ToolResult { tool, result } = &observation.kind else {
            panic!("expected tool result observation");
        };
        assert_eq!(tool, "bash");
        assert_eq!(result["tool_call_id"], "call_bad");
        assert_eq!(result["is_error"], true);
        assert!(
            result["content"]
                .as_str()
                .is_some_and(|content| content.contains("Invalid tool arguments JSON")),
            "ledgered tool result should carry the parse error: {result}"
        );
    }

    #[tokio::test]
    async fn execute_tool_calls_for_tui_one_time_allow_executes_without_nested_prompt() {
        use std::sync::mpsc as std_mpsc;
        use std::time::Duration;
        use tempfile::TempDir;

        let dir = TempDir::new().expect("tempdir");
        let mgr = Arc::new(PermissionManager::new_with_web_fetch_preapproved(
            dir.path().join("permissions.json"),
            true,
            Vec::new(),
            Vec::new(),
        ));
        let tool_call = ToolCall {
            id: "call_allow_once".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command":"printf tui-permission-ok"}"#.to_string(),
            },
        };
        let (tx, rx) = std_mpsc::channel::<AppEvent>();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));

        let handle = tokio::spawn({
            let task_mgr = Arc::clone(&task_mgr);
            let mgr = Arc::clone(&mgr);
            async move {
                let tool_calls = vec![tool_call];
                execute_tool_calls_for_tui(
                    test_run(),
                    &tool_calls,
                    None,
                    None,
                    Some(mgr),
                    &[],
                    None,
                    None,
                    task_mgr,
                    Some("s"),
                    "test-model",
                    &tx,
                )
                .await
            }
        });

        let reply = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match rx.try_recv() {
                    Ok(AppEvent::PermissionRequest { reply, .. }) => break reply,
                    Ok(_) | Err(std_mpsc::TryRecvError::Empty) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(std_mpsc::TryRecvError::Disconnected) => {
                        panic!("tool runner disconnected before permission prompt")
                    }
                }
            }
        })
        .await
        .expect("permission prompt should arrive");

        reply
            .send(PermissionResponse::Allow)
            .expect("tool runner should still be awaiting permission reply");

        let (results, has_tools) = handle.await.expect("tool runner should not panic");
        assert!(has_tools);
        assert_eq!(results.len(), 1);
        let content = results[0]["content"].as_str().unwrap_or_default();
        assert!(
            content.contains("tui-permission-ok"),
            "one-time Allow should execute the tool, got: {content}"
        );
        assert!(
            !content.contains("PERMISSION_PROMPT"),
            "one-time Allow must not leak nested legacy permission prompts: {content}"
        );
        assert_eq!(results[0]["is_error"], false);
    }

    #[tokio::test]
    async fn execute_tool_calls_for_tui_records_denied_tool_result_observation() {
        use std::sync::mpsc as std_mpsc;

        let session_id = "tui-denied-tool-result-ledger";
        let ledger = Arc::new(Mutex::new(crate::ledger::RealityLedger::new()));
        let _ledger_guard =
            crate::ledger::install_active_ledger_for_session(session_id, Arc::clone(&ledger));
        let tool_call = ToolCall {
            id: "call_denied".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command":"cargo test"}"#.to_string(),
            },
        };
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mgr = Arc::new(PermissionManager::new(
            dir.path().join("permissions.json"),
            true,
            Vec::new(),
        ));
        mgr.deny_tool_call_for_session(
            &tool_call,
            session_id,
            crate::permissions::ApprovalProvenance::InteractiveUser,
        )
        .expect("exact session denial");
        let (tx, _rx) = std_mpsc::channel::<AppEvent>();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));
        let run_context = test_run();

        let (results, has_tools) = execute_tool_calls_for_tui(
            Arc::clone(&run_context),
            &[tool_call],
            None,
            None,
            Some(mgr),
            &[],
            None,
            None,
            task_mgr,
            Some(session_id),
            "test-model",
            &tx,
        )
        .await;

        assert!(has_tools);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["is_error"], true);
        assert!(
            results[0]["content"]
                .as_str()
                .is_some_and(|content| content.contains("exact approval-scope denial")),
            "tool result should carry the denial: {}",
            results[0]
        );

        let observation = {
            let ledger = ledger.lock().expect("ledger lock");
            ledger
                .observations_chronological()
                .into_iter()
                .find(|obs| matches!(obs.kind, crate::ledger::ObservationKind::ToolResult { .. }))
                .cloned()
        }
        .expect("denied tool result observation");
        assert_eq!(
            observation.provenance.trust,
            crate::ledger::EvidenceTrust::UntrustedContent
        );
        assert!(observation.provenance.is_bound_to(&run_context));
        let crate::ledger::ObservationKind::ToolResult { tool, result } = &observation.kind else {
            panic!("expected tool result observation");
        };
        assert_eq!(tool, "bash");
        assert_eq!(result["tool_call_id"], "call_denied");
        assert_eq!(result["is_error"], true);
        assert!(
            result["content"]
                .as_str()
                .is_some_and(|content| content.contains("exact approval-scope denial")),
            "ledgered tool result should carry the denial: {result}"
        );
    }

    #[tokio::test]
    async fn execute_tool_calls_for_tui_enforces_policy_tool_cap_before_execution() {
        use std::sync::mpsc as std_mpsc;

        let session_id = "tui-policy-tool-cap-ledger";
        let ledger = Arc::new(Mutex::new(crate::ledger::RealityLedger::new()));
        let _ledger_guard =
            crate::ledger::install_active_ledger_for_session(session_id, Arc::clone(&ledger));
        let policy = crate::services::policy::EnterprisePolicy {
            tool_caps: std::collections::HashMap::from([("bash".to_string(), 0)]),
            ..Default::default()
        };
        let policy_enforcer = Arc::new(crate::services::policy::PolicyEnforcer::new(policy));
        let mgr = Arc::new(PermissionManager::unrestricted());
        let tool_call = ToolCall {
            id: "call_policy_denied".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command":"printf policy-should-not-run"}"#.to_string(),
            },
        };
        let (tx, rx) = std_mpsc::channel::<AppEvent>();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));

        let (results, has_tools) = execute_tool_calls_for_tui(
            test_run(),
            &[tool_call],
            None,
            None,
            Some(mgr),
            &[],
            None,
            Some(policy_enforcer),
            task_mgr,
            Some(session_id),
            "test-model",
            &tx,
        )
        .await;

        assert!(has_tools);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["is_error"], true);
        let content = results[0]["content"].as_str().unwrap_or_default();
        assert!(content.contains("POLICY DENIED"), "{content}");
        assert!(
            !content.contains("policy-should-not-run"),
            "denied tool must not execute command output: {content}"
        );

        let mut saw_policy_done = false;
        let mut saw_tool_start = false;
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::ToolDone { content, .. } => {
                    saw_policy_done = content.contains("Blocked by policy");
                }
                AppEvent::ToolStart { .. } => saw_tool_start = true,
                _ => {}
            }
        }
        assert!(saw_policy_done, "TUI should receive the policy denial");
        assert!(!saw_tool_start, "policy-denied tool must not start");

        let observations = {
            let ledger = ledger.lock().expect("ledger lock");
            ledger
                .observations_chronological()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        assert!(
            observations.iter().any(|obs| {
                matches!(
                    &obs.kind,
                    crate::ledger::ObservationKind::PolicyDecision { allowed: false, reason }
                    if reason.contains("bash")
                )
            }),
            "policy denial should be ledgered"
        );
        assert!(
            observations.iter().any(|obs| {
                matches!(
                    &obs.kind,
                    crate::ledger::ObservationKind::ToolResult { tool, result }
                    if tool == "bash" && result["is_error"] == true
                )
            }),
            "policy-denied tool result should be ledgered"
        );
    }

    #[tokio::test]
    async fn execute_tool_calls_for_tui_runs_pre_tool_use_before_dispatch() {
        use crate::config::{Hook, HookEntry, HooksConfig};
        use crate::hooks::HookEngine;
        use std::sync::mpsc as std_mpsc;

        let mut hooks = HooksConfig::default();
        hooks.pre_tool_use.push(HookEntry {
            matcher: Some("bash".to_string()),
            hooks: vec![Hook::Command {
                command: r#"printf '{"decision":"deny","reason":"prehook veto"}'; exit 2"#
                    .to_string(),
                shell: true,
                timeout: 5,
            }],
        });
        let hook_engine = Arc::new(HookEngine::new(hooks));
        let tool_call = ToolCall {
            id: "call_prehook_denied".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command":"printf prehook-should-not-run"}"#.to_string(),
            },
        };
        let (tx, rx) = std_mpsc::channel::<AppEvent>();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));

        let (results, has_tools) = execute_tool_calls_for_tui(
            test_run(),
            &[tool_call],
            None,
            None,
            Some(Arc::new(PermissionManager::unrestricted())),
            &[],
            Some(hook_engine),
            None,
            task_mgr,
            Some("tui-prehook-session"),
            "test-model",
            &tx,
        )
        .await;

        assert!(has_tools);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["is_error"], true);
        let content = results[0]["content"].as_str().unwrap_or_default();
        assert!(content.contains("prehook veto"), "{content}");
        assert!(
            !content.contains("prehook-should-not-run"),
            "pre-hook denied tool must not execute command output: {content}"
        );

        let mut saw_tool_done = false;
        let mut saw_tool_start = false;
        let mut saw_permission_request = false;
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::ToolDone { content, .. } => {
                    saw_tool_done = content.contains("prehook veto");
                }
                AppEvent::ToolStart { .. } => saw_tool_start = true,
                AppEvent::PermissionRequest { .. } => saw_permission_request = true,
                _ => {}
            }
        }
        assert!(saw_tool_done, "TUI should receive the pre-hook denial");
        assert!(!saw_tool_start, "pre-hook-denied tool must not start");
        assert!(
            !saw_permission_request,
            "pre-hook-denied tool must not prompt for permission"
        );
    }

    #[tokio::test]
    async fn execute_tool_calls_for_tui_records_tool_result_observation() {
        use std::sync::mpsc as std_mpsc;

        let session_id = "toolresultledger";
        let ledger = Arc::new(Mutex::new(crate::ledger::RealityLedger::new()));
        let _ledger_guard =
            crate::ledger::install_active_ledger_for_session(session_id, Arc::clone(&ledger));
        let tool_call = ToolCall {
            id: "call_list".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "list_files".to_string(),
                arguments: r#"{"path":"."}"#.to_string(),
            },
        };
        let (tx, _rx) = std_mpsc::channel::<AppEvent>();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));
        let permission_mgr = Some(Arc::new(PermissionManager::unrestricted()));
        let run_context = test_run();

        let (results, has_tools) = execute_tool_calls_for_tui(
            Arc::clone(&run_context),
            &[tool_call],
            None,
            None,
            permission_mgr,
            &[],
            None,
            None,
            task_mgr,
            Some(session_id),
            "test-model",
            &tx,
        )
        .await;

        assert!(has_tools);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["is_error"], false);

        let observation = {
            let ledger = ledger.lock().expect("ledger lock");
            ledger
                .observations_chronological()
                .into_iter()
                .find(|obs| matches!(obs.kind, crate::ledger::ObservationKind::ToolResult { .. }))
                .cloned()
        }
        .expect("tool result observation");
        assert_eq!(
            observation.provenance.trust,
            crate::ledger::EvidenceTrust::UntrustedContent
        );
        assert!(observation.provenance.is_bound_to(&run_context));
        let crate::ledger::ObservationKind::ToolResult { tool, result } = &observation.kind else {
            panic!("expected tool result observation");
        };
        assert_eq!(tool, "list_files");
        assert_eq!(result["tool_call_id"], "call_list");
        assert_eq!(result["is_error"], false);
        assert_eq!(result["truncated"], false);
        assert!(result["content"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn observe_tool_result_json_records_model_visible_content() {
        let session_id = "tooljsonledger";
        let ledger = Arc::new(Mutex::new(crate::ledger::RealityLedger::new()));
        let _ledger_guard =
            crate::ledger::install_active_ledger_for_session(session_id, Arc::clone(&ledger));
        let result_json = serde_json::json!({
            "tool_call_id": "call_question",
            "content": "{\"answer\":\"use the SSD\"}",
            "is_error": false
        });

        let run = test_run();
        observe_tool_result_json(&run, Some(session_id), "ask_user_question", &result_json);

        let observation = {
            let ledger = ledger.lock().expect("ledger lock");
            ledger
                .observations_chronological()
                .into_iter()
                .find(|obs| matches!(obs.kind, crate::ledger::ObservationKind::ToolResult { .. }))
                .cloned()
        }
        .expect("tool result observation");
        let crate::ledger::ObservationKind::ToolResult { tool, result } = &observation.kind else {
            panic!("expected tool result observation");
        };
        assert_eq!(tool, "ask_user_question");
        assert_eq!(result["tool_call_id"], "call_question");
        assert_eq!(result["content"], "{\"answer\":\"use the SSD\"}");
        assert_eq!(
            observation.provenance.trust,
            crate::ledger::EvidenceTrust::UntrustedContent
        );
        assert!(observation.provenance.is_bound_to(&run));
    }

    #[test]
    fn extract_google_text_concatenates_text_parts_and_allows_tool_calls() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "hello "},
                        {"functionCall": {"name": "bash", "args": {"command": "pwd"}}},
                        {"text": "world"}
                    ]
                }
            }]
        });

        let parts = google_response_parts(&body).expect("parts should parse");
        let text = extract_google_text(parts).expect("mixed text/tool response should parse");

        assert_eq!(text, "hello world");
    }

    #[test]
    fn google_response_parts_rejects_missing_parts() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {}
            }]
        });

        let err = google_response_parts(&body).expect_err("missing parts must fail");

        assert!(err.contains("content.parts"), "{err}");
    }

    #[test]
    fn extract_google_text_rejects_non_string_text_part() {
        let parts = vec![serde_json::json!({"text": 123})];

        let err = extract_google_text(&parts).expect_err("non-string text must fail");

        assert!(err.contains("'text'"), "{err}");
    }

    #[test]
    fn extract_google_text_rejects_unsupported_part_shape() {
        let parts = vec![serde_json::json!({
            "inlineData": {"mimeType": "image/png", "data": "..."}
        })];

        let err = extract_google_text(&parts).expect_err("unsupported part must fail");

        assert!(err.contains("supported text or functionCall"), "{err}");
    }

    #[test]
    fn extract_google_tool_calls_accepts_valid_function_call() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "using a tool"},
                        {"functionCall": {"name": "bash", "args": {"command": "pwd"}}}
                    ]
                }
            }]
        });

        let calls = extract_google_tool_calls(&body).expect("valid Gemini tool call should parse");

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "bash");
        assert_eq!(calls[0].function.arguments, r#"{"command":"pwd"}"#);
    }

    #[test]
    fn extract_google_tool_calls_rejects_missing_name() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"args": {"command": "pwd"}}}
                    ]
                }
            }]
        });

        let err = extract_google_tool_calls(&body).expect_err("missing Gemini tool name must fail");

        assert!(err.contains("functionCall"), "{err}");
        assert!(err.contains("name"), "{err}");
    }

    #[test]
    fn extract_google_tool_calls_rejects_missing_args() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash"}}
                    ]
                }
            }]
        });

        let err = extract_google_tool_calls(&body).expect_err("missing Gemini tool args must fail");

        assert!(err.contains("functionCall"), "{err}");
        assert!(err.contains("args"), "{err}");
    }

    #[test]
    fn extract_google_tool_calls_rejects_non_object_args() {
        let body = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash", "args": []}}
                    ]
                }
            }]
        });

        let err =
            extract_google_tool_calls(&body).expect_err("non-object Gemini tool args must fail");

        assert!(err.contains("args"), "{err}");
        assert!(err.contains("object"), "{err}");
    }

    #[test]
    fn test_build_openai_request() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hello"})];
        let req = build_openai_request("gpt-4", &messages, "medium");
        assert_eq!(req["model"], "gpt-4");
        assert_eq!(req["stream"], true);
        assert!(req["tools"].is_array());
        assert_eq!(req["reasoning_effort"], "medium");

        let minimal = build_openai_request("gpt-4", &messages, "minimal");
        assert_eq!(minimal["reasoning_effort"], "minimal");

        let high = build_openai_request("gpt-4", &messages, "high");
        assert_eq!(high["reasoning_effort"], "high");

        let max = build_openai_request("gpt-4", &messages, "max");
        assert_eq!(max["reasoning_effort"], "xhigh");
    }

    #[test]
    fn build_openai_responses_request_translates_chat_history() {
        let messages = vec![
            serde_json::json!({"role": "system", "content": "You are useful."}),
            serde_json::json!({"role": "user", "content": "hello"}),
            serde_json::json!({
                "role": "assistant",
                "content": "I'll check.",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "bash",
                        "arguments": "{\"command\":\"pwd\"}"
                    }
                }]
            }),
            serde_json::json!({
                "role": "tool",
                "tool_call_id": "call_1",
                "content": "/home/doll/OpenClaudia"
            }),
        ];

        let req = build_request_for_wire(
            WireApi::OpenAiResponses,
            "openai",
            "gpt-5.5",
            &messages,
            "high",
            None,
            None,
        )
        .expect("Responses request should build");

        assert_eq!(req["model"], "gpt-5.5");
        assert_eq!(req["instructions"], "You are useful.");
        assert!(req.get("messages").is_none());
        assert!(req.get("max_output_tokens").is_none());
        assert_eq!(req["stream"], true);
        assert_eq!(req["store"], false);
        assert_eq!(req["reasoning"]["effort"], "high");
        assert_eq!(req["input"][0]["type"], "message");
        assert_eq!(req["input"][0]["role"], "user");
        assert_eq!(req["input"][0]["content"][0]["type"], "input_text");
        assert_eq!(req["input"][1]["role"], "assistant");
        assert_eq!(req["input"][1]["content"][0]["type"], "output_text");
        assert_eq!(req["input"][2]["type"], "function_call");
        assert_eq!(req["input"][2]["call_id"], "call_1");
        assert_eq!(req["input"][3]["type"], "function_call_output");
        assert_eq!(req["input"][3]["call_id"], "call_1");
        assert_eq!(req["tools"][0]["type"], "function");
        assert!(req["tools"][0].get("function").is_none());
    }

    #[test]
    fn process_responses_sse_event_extracts_text_tool_calls_and_usage() {
        let text_event = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": "hello"
        });
        match process_responses_sse_event(&text_event).expect("text event") {
            ResponsesSseAction::Text(text) => assert_eq!(text, "hello"),
            other => panic!("expected text event, got {other:?}"),
        }

        let tool_event = serde_json::json!({
            "type": "response.output_item.done",
            "item": {
                "type": "function_call",
                "call_id": "call_abc",
                "name": "bash",
                "arguments": "{\"command\":\"pwd\"}"
            }
        });
        match process_responses_sse_event(&tool_event).expect("tool event") {
            ResponsesSseAction::ToolCall(call) => {
                assert_eq!(call.id, "call_abc");
                assert_eq!(call.function.name, "bash");
                assert_eq!(call.function.arguments, "{\"command\":\"pwd\"}");
            }
            other => panic!("expected tool event, got {other:?}"),
        }

        let usage_event = serde_json::json!({
            "type": "response.completed",
            "response": {
                "usage": {
                    "input_tokens": 12,
                    "output_tokens": 7,
                    "input_tokens_details": {"cached_tokens": 5}
                }
            }
        });
        match process_responses_sse_event(&usage_event).expect("usage event") {
            ResponsesSseAction::Usage(usage) => {
                assert_eq!(usage.input_tokens, 12);
                assert_eq!(usage.output_tokens, 7);
                assert_eq!(usage.cache_read_tokens, 5);
            }
            other => panic!("expected usage event, got {other:?}"),
        }
    }

    #[test]
    fn test_build_anthropic_request_legacy_single_block() {
        let messages = vec![
            serde_json::json!({"role": "system", "content": "You are helpful."}),
            serde_json::json!({"role": "user", "content": "hello"}),
        ];
        let req = build_anthropic_request("claude-sonnet-4-6", &messages, "medium", None, None)
            .expect("anthropic request should build");
        assert_eq!(req["model"], "claude-sonnet-4-6");
        assert!(req["system"].is_array());
        // Legacy path: single block with cache_control
        assert_eq!(req["system"].as_array().unwrap().len(), 1);
        assert!(req["system"][0]["cache_control"].is_object());
        assert!(req["tools"].is_array());
    }

    #[test]
    fn test_build_anthropic_request_multi_block() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hello"})];
        let blocks = typed_test_blocks("identity and tools", "hooks and env");
        let req = build_anthropic_request(
            "claude-sonnet-4-6",
            &messages,
            "medium",
            None,
            Some(&blocks),
        )
        .expect("anthropic request should build");
        assert_eq!(req["model"], "claude-sonnet-4-6");
        let sys = req["system"].as_array().unwrap();
        // Two blocks: prefix (cached) + suffix (not cached)
        assert_eq!(sys.len(), 2);
        assert_eq!(sys[0]["text"], "identity and tools");
        assert!(
            sys[0]["cache_control"].is_object(),
            "prefix must have cache_control"
        );
        assert_eq!(sys[1]["text"], "hooks and env");
        assert!(
            sys[1].get("cache_control").is_none(),
            "suffix must NOT have cache_control"
        );
    }

    #[test]
    fn test_build_anthropic_request_empty_suffix_single_block() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hello"})];
        let blocks = typed_test_blocks("everything is static", "");
        let req = build_anthropic_request(
            "claude-sonnet-4-6",
            &messages,
            "medium",
            None,
            Some(&blocks),
        )
        .expect("anthropic request should build");
        let sys = req["system"].as_array().unwrap();
        // Empty suffix collapses to single cached block
        assert_eq!(sys.len(), 1);
        assert!(sys[0]["cache_control"].is_object());
    }

    #[test]
    fn test_build_request_dispatches() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];
        let req = build_request("openai", "gpt-4", &messages, "medium", None, None)
            .expect("openai request should build");
        assert_eq!(req["model"], "gpt-4");

        let req = build_request(
            "anthropic",
            "claude-sonnet-4-6",
            &messages,
            "medium",
            None,
            None,
        )
        .expect("anthropic request should build");
        assert_eq!(req["model"], "claude-sonnet-4-6");
    }

    #[test]
    fn build_request_openai_high_effort_uses_reasoning_models_only() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];
        let gpt5 = build_request("openai", "gpt-5.5", &messages, "high", None, None)
            .expect("gpt-5 request should build");
        assert_eq!(gpt5["reasoning_effort"], "high");

        let low = build_request("openai", "gpt-5.5", &messages, "low", None, None)
            .expect("gpt-5 low-effort request should build");
        assert_eq!(low["reasoning_effort"], "low");

        let max = build_request("openai", "gpt-5.5", &messages, "max", None, None)
            .expect("gpt-5 max-effort request should build");
        assert_eq!(max["reasoning_effort"], "xhigh");

        let gpt4 = build_request("openai", "gpt-4o", &messages, "high", None, None)
            .expect("gpt-4o request should build");
        assert!(
            gpt4.get("reasoning_effort").is_none(),
            "non-reasoning OpenAI models must not receive reasoning_effort: {gpt4}"
        );
    }

    #[test]
    fn build_request_provider_specific_thinking_fields_are_used() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];

        let deepseek = build_request("deepseek", "deepseek-v4-pro", &messages, "high", None, None)
            .expect("deepseek request should build");
        assert_eq!(deepseek["thinking"]["type"], "enabled");
        assert_eq!(deepseek["reasoning_effort"], "high");
        assert!(
            deepseek.get("enable_thinking").is_none(),
            "DeepSeek must not receive legacy enable_thinking: {deepseek}"
        );

        let deepseek_max =
            build_request("deepseek", "deepseek-v4-pro", &messages, "max", None, None)
                .expect("deepseek max request should build");
        assert_eq!(deepseek_max["reasoning_effort"], "max");

        let qwen = build_request("qwen", "qwen3.7-plus", &messages, "high", None, None)
            .expect("qwen request should build");
        assert_eq!(qwen["enable_thinking"], true);
        assert!(
            qwen.get("reasoning_effort").is_none(),
            "Qwen must not receive OpenAI reasoning_effort: {qwen}"
        );

        let zai = build_request("zai", "glm-5.2", &messages, "high", None, None)
            .expect("zai request should build");
        assert_eq!(zai["thinking"]["type"], "enabled");
        assert_eq!(zai["reasoning_effort"], "high");

        let zai_legacy = build_request("zai", "glm-4.7", &messages, "max", None, None)
            .expect("zai legacy request should build");
        assert_eq!(zai_legacy["thinking"]["type"], "enabled");
        assert!(
            zai_legacy.get("reasoning_effort").is_none(),
            "non-GLM-5.2 Z.AI models must not receive reasoning_effort: {zai_legacy}"
        );

        let minimax = build_request("minimax", "MiniMax-M3", &messages, "high", None, None)
            .expect("minimax request should build");
        assert_eq!(minimax["thinking"]["type"], "adaptive");
        assert_eq!(minimax["reasoning_split"], true);
        assert!(
            minimax.get("reasoning_effort").is_none(),
            "MiniMax must not receive OpenAI reasoning_effort: {minimax}"
        );
    }

    #[test]
    fn build_request_omits_unsupported_generic_thinking_fields() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];
        for (provider, model) in [("kimi", "kimi-k2.7-code"), ("moonshot", "kimi-k2.7-code")] {
            let body = build_request(provider, model, &messages, "high", None, None)
                .expect("request should build");
            for field in [
                "reasoning_effort",
                "enable_thinking",
                "thinking",
                "clear_thinking",
            ] {
                assert!(
                    body.get(field).is_none(),
                    "{provider} must not receive unsupported field {field}: {body}"
                );
            }
        }
    }

    #[test]
    fn build_request_routes_provider_aliases_to_native_shapes() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];

        let gemini = build_request(
            "gemini",
            "gemini-3.5-flash",
            &messages,
            "medium",
            None,
            None,
        )
        .expect("gemini alias request should build");
        assert!(gemini.get("contents").is_some());
        assert!(
            gemini.get("messages").is_none(),
            "gemini alias must use native Gemini request shape: {gemini}"
        );

        let ollama = build_request("ollama", "llama3", &messages, "medium", None, None)
            .expect("ollama request should build");
        assert_eq!(ollama["stream"], true);
        assert!(ollama["options"]["num_predict"].is_number());
        assert!(
            ollama.get("max_tokens").is_none(),
            "Ollama must use native options.num_predict, not OpenAI max_tokens: {ollama}"
        );
    }

    #[test]
    fn build_request_errors_on_unknown_provider() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];
        let err = build_request("anthrpic", "gpt-5.5", &messages, "medium", None, None)
            .expect_err("unknown provider must not silently fall back to OpenAI");
        assert!(err.contains("Unknown provider"), "{err}");
        assert!(err.contains("anthrpic"), "{err}");
    }

    #[test]
    fn build_request_errors_on_malformed_anthropic_tool_call_arguments() {
        let messages = vec![
            serde_json::json!({"role": "user", "content": "run a tool"}),
            serde_json::json!({
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "id": "toolu_bad",
                    "type": "function",
                    "function": {"name": "bash", "arguments": "{not json"}
                }]
            }),
        ];
        let err = build_request(
            "anthropic",
            "claude-sonnet-4-6",
            &messages,
            "medium",
            None,
            None,
        )
        .expect_err("malformed tool_call arguments must reject Anthropic request build");
        assert!(err.contains("function.arguments"), "{err}");
        assert!(err.contains("invalid JSON"), "{err}");
    }

    #[test]
    fn test_build_assistant_message_with_tools() {
        let tool_calls = vec![ToolCall {
            id: "call_123".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command":"ls"}"#.to_string(),
            },
        }];
        let msg = build_assistant_message_with_tools("hello", None, &tool_calls, "anthropic");
        assert_eq!(msg["role"], "assistant");
        assert_eq!(msg["content"], "hello");
        assert!(msg["tool_calls"].is_array());
        assert_eq!(msg["tool_calls"][0]["id"], "call_123");
    }

    #[test]
    fn build_assistant_message_with_tools_preserves_reasoning_content() {
        let msg = build_assistant_message_with_tools("hello", Some("thought"), &[], "kimi");
        assert_eq!(msg["reasoning_content"], "thought");
    }

    #[test]
    fn build_assistant_message_with_tools_normalizes_bad_arguments_for_history() {
        let tool_calls = vec![ToolCall {
            id: "call_bad".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "todo_read".to_string(),
                arguments: String::new(),
            },
        }];

        let msg = build_assistant_message_with_tools("", None, &tool_calls, "anthropic");

        assert_eq!(msg["tool_calls"][0]["function"]["arguments"], "{}");
    }

    #[test]
    fn normalize_message_tool_arguments_repairs_existing_bad_history() {
        let mut messages = vec![serde_json::json!({
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_bad",
                "type": "function",
                "function": {"name": "todo_read", "arguments": ""}
            }]
        })];

        let changed = normalize_message_tool_arguments_for_history(&mut messages);

        assert_eq!(changed, 1);
        assert_eq!(messages[0]["tool_calls"][0]["function"]["arguments"], "{}");
    }

    #[test]
    fn merge_reasoning_delta_deduplicates_cumulative_chunks() {
        let mut buffer = String::new();

        assert_eq!(merge_reasoning_delta(&mut buffer, "abc"), "abc");
        assert_eq!(merge_reasoning_delta(&mut buffer, "abcdef"), "def");
        assert_eq!(buffer, "abcdef");
        assert_eq!(merge_reasoning_delta(&mut buffer, " + next"), " + next");
        assert_eq!(buffer, "abcdef + next");
    }

    #[test]
    fn test_effort_levels() {
        // Tests read env vars — guard against interference from the ambient
        // MAX_THINKING_TOKENS override.
        // SAFETY: no other test in this module mutates MAX_THINKING_TOKENS.
        let prev = std::env::var("MAX_THINKING_TOKENS").ok();
        unsafe {
            std::env::remove_var("MAX_THINKING_TOKENS");
        }
        let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];

        let high = build_anthropic_request("claude-sonnet-4-6", &messages, "high", None, None)
            .expect("high effort anthropic request should build");
        assert_eq!(
            high["thinking"]["budget_tokens"],
            crate::thinking::ULTRATHINK_BUDGET_TOKENS,
        );
        assert_eq!(high["max_tokens"], 40_000);

        let maxr = build_anthropic_request("claude-sonnet-4-6", &messages, "max", None, None)
            .expect("max effort anthropic request should build");
        assert_eq!(
            maxr["thinking"]["budget_tokens"],
            crate::thinking::ULTRATHINK_BUDGET_TOKENS,
        );

        let opus48 = build_anthropic_request("claude-opus-4-8", &messages, "high", None, None)
            .expect("opus 4.8 high-effort request should build");
        assert_eq!(opus48["thinking"]["type"], "adaptive");
        assert!(
            opus48["thinking"].get("budget_tokens").is_none(),
            "Opus 4.8 rejects manual thinking budgets: {opus48}"
        );
        assert_eq!(opus48["output_config"]["effort"], "high");
        assert_eq!(opus48["max_tokens"], 40_000);

        let opus47 = build_anthropic_request("claude-opus-4-7", &messages, "max", None, None)
            .expect("opus 4.7 max-effort request should build");
        assert_eq!(opus47["thinking"]["type"], "adaptive");
        assert!(
            opus47["thinking"].get("budget_tokens").is_none(),
            "Opus 4.7 rejects manual thinking budgets: {opus47}"
        );
        assert_eq!(opus47["output_config"]["effort"], "max");

        let fable = build_anthropic_request("claude-fable-5", &messages, "high", None, None)
            .expect("fable high-effort request should build");
        assert!(
            fable.get("thinking").is_none(),
            "Fable 5 has implicit adaptive thinking; explicit thinking object is unnecessary: {fable}"
        );
        assert_eq!(fable["output_config"]["effort"], "high");

        let low = build_anthropic_request("claude-sonnet-4-6", &messages, "low", None, None)
            .expect("low effort anthropic request should build");
        assert!(low.get("thinking").is_none());
        assert_eq!(low["max_tokens"], 2048);

        let med = build_anthropic_request("claude-sonnet-4-6", &messages, "medium", None, None)
            .expect("medium effort anthropic request should build");
        assert!(med.get("thinking").is_none());
        assert_eq!(med["max_tokens"], crate::DEFAULT_MAX_TOKENS);
        if let Some(v) = prev {
            unsafe {
                std::env::set_var("MAX_THINKING_TOKENS", v);
            }
        }
    }

    // ── Phase 2 spec-pinning tests (#552 / spec #537) ────────────────────────

    /// B2 — medium effort DOES NOT attach thinking parameters.
    ///
    /// CURRENT CONTRACT: OC only enables thinking for "high"/"max".
    /// Gap #599 tracks enabling adaptive thinking by default (CC behaviour).
    #[test]
    fn b2_medium_effort_no_thinking_pin_gap_599() {
        let prev = std::env::var("MAX_THINKING_TOKENS").ok();
        // SAFETY: single-threaded test, no concurrent writers.
        unsafe {
            std::env::remove_var("MAX_THINKING_TOKENS");
        }
        let messages = vec![serde_json::json!({"role": "user", "content": "hello"})];
        let req = build_anthropic_request("claude-sonnet-4-6", &messages, "medium", None, None)
            .expect("medium effort anthropic request should build");
        // OC does NOT enable thinking for medium — gap #599: CC uses adaptive thinking
        assert!(
            req.get("thinking").is_none(),
            "medium effort must not attach thinking block (gap #599 tracks adaptive default)"
        );
        if let Some(v) = prev {
            unsafe {
                std::env::set_var("MAX_THINKING_TOKENS", v);
            }
        }
    }

    /// B2 — high effort attaches `thinking.type = "enabled"` with budget > 0.
    ///
    /// Pins the exact budget constant (31999 = CC's `ULTRATHINK_BUDGET_TOKENS`).
    #[test]
    fn b2_high_effort_attaches_thinking_budget() {
        let prev = std::env::var("MAX_THINKING_TOKENS").ok();
        // SAFETY: single-threaded test, no concurrent writers.
        unsafe {
            std::env::remove_var("MAX_THINKING_TOKENS");
        }
        let messages = vec![serde_json::json!({"role": "user", "content": "think"})];
        let req = build_anthropic_request("claude-sonnet-4-6", &messages, "high", None, None)
            .expect("high effort anthropic request should build");
        assert_eq!(
            req["thinking"]["type"], "enabled",
            "high effort must set thinking.type = enabled"
        );
        // Budget must be CC's ULTRATHINK constant (31999)
        let budget = req["thinking"]["budget_tokens"].as_u64().unwrap_or(0);
        assert_eq!(
            budget,
            u64::from(crate::thinking::ULTRATHINK_BUDGET_TOKENS),
            "budget_tokens must equal ULTRATHINK_BUDGET_TOKENS"
        );
        // max_tokens must exceed budget_tokens (OC uses 40000)
        let max = req["max_tokens"].as_u64().unwrap_or(0);
        assert!(
            max > budget,
            "max_tokens ({max}) must be > budget_tokens ({budget})"
        );
        if let Some(v) = prev {
            unsafe {
                std::env::set_var("MAX_THINKING_TOKENS", v);
            }
        }
    }

    /// B2 — Google request attaches `thinkingConfig.thinkingBudget` for high effort.
    ///
    /// Gemini thinking is capped at 32768.
    #[test]
    fn b2_google_request_thinking_budget_capped() {
        const GEMINI_CAP: u64 = 32_768;
        let prev = std::env::var("MAX_THINKING_TOKENS").ok();
        // SAFETY: single-threaded test, no concurrent writers.
        unsafe {
            std::env::remove_var("MAX_THINKING_TOKENS");
        }
        let messages = vec![serde_json::json!({"role": "user", "content": "think"})];
        let req =
            build_google_request(&messages, "high").expect("google high-effort request builds");
        let budget = req["generationConfig"]["thinkingConfig"]["thinkingBudget"]
            .as_u64()
            .unwrap_or(0);
        assert!(budget > 0, "high effort must set thinkingBudget > 0");
        assert!(
            budget <= GEMINI_CAP,
            "thinkingBudget ({budget}) must not exceed Gemini cap ({GEMINI_CAP})"
        );
        if let Some(v) = prev {
            unsafe {
                std::env::set_var("MAX_THINKING_TOKENS", v);
            }
        }
    }

    #[test]
    fn google_request_rejects_malformed_message_history() {
        let missing_role = vec![serde_json::json!({"content": "hi"})];
        let err = build_google_request(&missing_role, "medium")
            .expect_err("missing message role must fail");
        assert!(err.contains("'role'"), "{err}");
        assert!(err.contains("index 0"), "{err}");

        let missing_content = vec![serde_json::json!({"role": "user"})];
        let err = build_google_request(&missing_content, "medium")
            .expect_err("missing message content must fail");
        assert!(err.contains("'content'"), "{err}");
        assert!(err.contains("index 0"), "{err}");

        let unsupported_role = vec![serde_json::json!({"role": "developer", "content": "hi"})];
        let err = build_google_request(&unsupported_role, "medium")
            .expect_err("unsupported role must fail");
        assert!(err.contains("unsupported role"), "{err}");
        assert!(err.contains("developer"), "{err}");
    }

    #[test]
    fn google_request_concatenates_all_system_messages() {
        let messages = vec![
            serde_json::json!({"role": "system", "content": "first"}),
            serde_json::json!({"role": "user", "content": "hi"}),
            serde_json::json!({"role": "system", "content": "second"}),
        ];

        let req = build_google_request(&messages, "medium").expect("google request should build");

        assert_eq!(
            req["systemInstruction"]["parts"][0]["text"],
            "first\n\nsecond"
        );
        let contents = req["contents"].as_array().expect("contents array");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["role"], "user");
    }

    /// B5 — `TurnResult.needs_followup` is `true` iff tool calls were accumulated.
    ///
    /// Pure-logic check via `process_sse_event` + `AnthropicToolAccumulator`.
    /// The `needs_followup` field drives whether the caller re-enters the agentic loop.
    #[test]
    fn b5_needs_followup_reflects_tool_accumulator_state() {
        let mut ant = tools::AnthropicToolAccumulator::new();
        let mut oai = tools::ToolCallAccumulator::new();

        // No tool events → no tool use
        let no_tool: serde_json::Value = serde_json::json!({
            "type": "content_block_start",
            "content_block": { "type": "text" }
        });
        let _ = process_sse_event(&no_tool, false, &mut ant, &mut oai);
        // simulate stop with end_turn
        let end_event: serde_json::Value = serde_json::json!({
            "type": "message_delta",
            "delta": { "stop_reason": "end_turn" }
        });
        let _ = process_sse_event(&end_event, false, &mut ant, &mut oai);
        assert!(
            !ant.has_tool_use(),
            "no tool blocks → needs_followup must be false"
        );

        // Now simulate a tool_use block
        let mut ant2 = tools::AnthropicToolAccumulator::new();
        let mut oai2 = tools::ToolCallAccumulator::new();
        for raw in &[
            r#"{"type":"content_block_start","content_block":{"type":"tool_use","id":"c1","name":"bash"}}"#,
            r#"{"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"{}"}}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"}}"#,
        ] {
            let ev: serde_json::Value = serde_json::from_str(raw).unwrap();
            let _ = process_sse_event(&ev, false, &mut ant2, &mut oai2);
        }
        assert!(
            ant2.has_tool_use(),
            "tool_use stop_reason → needs_followup must be true"
        );
    }

    /// B6 - `SSE_STREAM_TIMEOUT_SECS` is long enough for tool-heavy turns.
    ///
    /// Increasing this without a gap issue would silently change user-visible
    /// latency characteristics.
    #[test]
    fn b6_stream_timeout_constant_is_5_minutes() {
        assert_eq!(
            crate::proxy::SSE_STREAM_TIMEOUT_SECS,
            300,
            "SSE_STREAM_TIMEOUT_SECS must stay at 5 minutes unless timeout UX is revalidated"
        );
    }

    #[test]
    fn stream_timeout_emits_event_without_mutating_content() {
        let (tx, rx) = std::sync::mpsc::channel();

        handle_sse_timeout(301, "partial provider text".len(), &tx)
            .expect("timeout event should send while receiver is alive");

        match rx.recv().expect("timeout event should be queued") {
            AppEvent::StreamTimeout {
                elapsed_secs,
                timeout_secs,
            } => {
                assert_eq!(elapsed_secs, 301);
                assert_eq!(timeout_secs, crate::proxy::SSE_STREAM_TIMEOUT_SECS);
            }
            _ => panic!("timeout must be represented as a structured event"),
        }
    }

    /// B1 — request builders keep the streaming flag contract separate from
    /// retry classification.
    #[test]
    fn b1_build_request_stream_flag_always_set() {
        let messages = vec![serde_json::json!({"role": "user", "content": "hi"})];
        let req = build_openai_request("gpt-4", &messages, "medium");
        assert_eq!(
            req["stream"], true,
            "stream must always be true in OC requests"
        );
        let req = build_anthropic_request("claude-sonnet-4-6", &messages, "medium", None, None)
            .expect("anthropic request should build");
        assert_eq!(req["stream"], true);
        let req = build_google_request(&messages, "medium").expect("google medium request builds");
        // Google request body doesn't include "stream" — it's a separate code path
        // The absence is the contract (Gemini uses non-streaming JSON — gap #602)
        assert!(
            req.get("stream").is_none(),
            "Google request must NOT have stream field (non-streaming path — gap #602)"
        );
    }

    /// B3 — `process_sse_event` returns `SseAction::None` for unknown event types.
    #[test]
    fn b3_process_sse_event_unknown_type_returns_none() {
        let event: serde_json::Value = serde_json::json!({"type": "ping"});
        let mut ant = tools::AnthropicToolAccumulator::new();
        let mut oai = tools::ToolCallAccumulator::new();
        let action = process_sse_event(&event, false, &mut ant, &mut oai);
        assert!(
            matches!(action, SseAction::None),
            "unknown SSE event type must return SseAction::None"
        );
    }

    /// B3 — `tool_needs_permission` follows mandatory catalog metadata.
    #[test]
    fn b3_tool_needs_permission_uses_effect_catalog() {
        assert!(!tool_needs_permission("read_file"), "read_file is safe");
        assert!(
            !tool_needs_permission("grounding_context"),
            "grounding_context is safe"
        );
        assert!(!tool_needs_permission("list_files"), "list_files is safe");
        assert!(!tool_needs_permission("grep"), "grep is safe");
        assert!(
            tool_needs_permission("write_file"),
            "write_file needs permission"
        );
        assert!(tool_needs_permission("bash"), "bash needs permission");
        assert!(
            tool_needs_permission("edit_file"),
            "edit_file needs permission"
        );
    }

    #[tokio::test]
    async fn tui_permission_manager_applies_explicit_deny_to_read_only_call() {
        use crate::permissions::{PermissionDecision, PermissionRule};
        use std::sync::mpsc as std_mpsc;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut mgr = PermissionManager::new(dir.path().join("permissions.json"), true, Vec::new());
        mgr.add_session_rule(PermissionRule {
            tool: "Read".to_string(),
            pattern: "/etc/**".to_string(),
            decision: PermissionDecision::Deny,
        });
        let (tx, _rx) = std_mpsc::channel::<AppEvent>();

        let outcome = check_tool_permission(
            &test_run(),
            "read_file",
            "call_read",
            r#"{"path":"/etc/shadow"}"#,
            &mgr,
            &[],
            None,
            None,
            &tx,
        )
        .await;
        assert!(matches!(outcome, PermissionOutcome::DeniedWithResult(_)));
    }

    #[tokio::test]
    async fn tui_unrestricted_manager_denies_unclassified_call_before_prompt() {
        use std::sync::mpsc as std_mpsc;

        let manager = PermissionManager::unrestricted();
        let (tx, rx) = std_mpsc::channel::<AppEvent>();

        let outcome = check_tool_permission(
            &test_run(),
            "unknown_from_model",
            "call_unknown",
            "{}",
            &manager,
            &[],
            None,
            None,
            &tx,
        )
        .await;

        assert!(matches!(outcome, PermissionOutcome::DeniedWithResult(_)));
        assert!(
            rx.try_iter()
                .all(|event| !matches!(event, AppEvent::PermissionRequest { .. })),
            "an unclassified call must not be converted into a user-approvable prompt"
        );
    }

    /// crosslink #724 / S-017 — an exact, bounded session approval survives
    /// across batches without becoming a tool-name-wide bypass.
    #[tokio::test]
    async fn issue_724_check_tool_permission_uses_exact_session_approval() {
        use std::sync::mpsc as std_mpsc;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let mgr = PermissionManager::new(dir.path().join("permissions.json"), true, Vec::new());
        let approved = ToolCall {
            id: "prior_call".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command":"ls"}"#.to_string(),
            },
        };
        let _initial_permit = mgr
            .approve_tool_call_for_session(
                &approved,
                "session-1",
                crate::permissions::ApprovalProvenance::InteractiveUser,
            )
            .expect("exact session approval");

        let (tx, rx) = std_mpsc::channel::<AppEvent>();
        let outcome = check_tool_permission(
            &test_run(),
            "bash",
            "call_1",
            "{\"command\":\"ls\"}",
            &mgr,
            &[],
            None,
            Some("session-1"),
            &tx,
        )
        .await;
        assert!(
            matches!(
                outcome,
                PermissionOutcome::Allowed {
                    authorization: Some(_)
                }
            ),
            "an exact prior approval must return a call-bound permit without a prompt"
        );
        // No PermissionRequest event should have been emitted.
        assert!(
            rx.try_recv().is_err(),
            "#724: no PermissionRequest event must be sent when the session cache allows"
        );
    }

    #[test]
    fn memory_review_prompt_accepts_only_the_one_use_choice() {
        use std::sync::mpsc as std_mpsc;

        let run = test_run();
        let manager = PermissionManager::unrestricted_for_run(&run);
        let call = ToolCall {
            id: "review-call".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "memory_review".to_string(),
                arguments: serde_json::json!({
                    "action": "review",
                    "logical_id": "00000000-0000-0000-0000-000000000001",
                    "expected_record_digest": format!("sha256:{}", "0".repeat(64)),
                })
                .to_string(),
            },
        };
        let (tx, _rx) = std_mpsc::channel::<AppEvent>();

        let allowed = permission_prompt_response(
            &Ok(PermissionResponse::Allow),
            &manager,
            Some("session-review"),
            &call,
            &tx,
        );
        assert!(matches!(
            allowed,
            PermissionOutcome::Allowed {
                authorization: Some(_)
            }
        ));

        let reusable = permission_prompt_response(
            &Ok(PermissionResponse::AlwaysAllow),
            &manager,
            Some("session-review"),
            &call,
            &tx,
        );
        assert!(matches!(reusable, PermissionOutcome::DeniedWithResult(_)));
    }

    /// #603: `web_fetch` is gated, but a configured preapproved host should
    /// be allowed by the permission manager without bothering the TUI.
    #[tokio::test]
    async fn issue_603_check_tool_permission_allows_preapproved_web_fetch_without_prompt() {
        use std::sync::mpsc as std_mpsc;
        use tempfile::TempDir;

        let dir = TempDir::new().expect("tempdir");
        let mgr = PermissionManager::new_with_web_fetch_preapproved(
            dir.path().join("permissions.json"),
            true,
            Vec::new(),
            vec!["docs.python.org".to_string()],
        );
        let (tx, rx) = std_mpsc::channel::<AppEvent>();
        let outcome = check_tool_permission(
            &test_run(),
            "web_fetch",
            "call_web",
            r#"{"url":"https://docs.python.org/3/"}"#,
            &mgr,
            &[],
            None,
            None,
            &tx,
        )
        .await;
        assert!(
            matches!(
                outcome,
                PermissionOutcome::Allowed {
                    authorization: Some(_)
                }
            ),
            "#603: preapproved web_fetch URL must be allowed without a prompt"
        );
        assert!(
            rx.try_recv().is_err(),
            "#603: no PermissionRequest event should be sent for preapproved web_fetch"
        );
    }

    #[tokio::test]
    async fn check_tool_permission_allows_matching_transient_rule_without_prompt() {
        use crate::permissions::{PermissionDecision, PermissionRule};
        use std::sync::mpsc as std_mpsc;
        use tempfile::TempDir;

        let dir = TempDir::new().expect("tempdir");
        let mgr = PermissionManager::new(dir.path().join("permissions.json"), true, Vec::new());
        let transient = [PermissionRule {
            tool: "Bash".to_string(),
            pattern: "git status *".to_string(),
            decision: PermissionDecision::Allow,
        }];
        let (tx, rx) = std_mpsc::channel::<AppEvent>();
        let outcome = check_tool_permission(
            &test_run(),
            "bash",
            "call_git",
            r#"{"command":"git status --short"}"#,
            &mgr,
            &transient,
            None,
            None,
            &tx,
        )
        .await;

        assert!(
            matches!(
                outcome,
                PermissionOutcome::Allowed {
                    authorization: Some(_)
                }
            ),
            "matching transient allowed-tools rule must allow without prompting"
        );
        assert!(
            rx.try_recv().is_err(),
            "transient allowed-tools rule must not emit a PermissionRequest"
        );
    }

    #[tokio::test]
    async fn permission_request_hook_can_deny_before_tui_prompt() {
        use crate::config::{Hook, HookEntry, HooksConfig};
        use crate::hooks::HookEngine;
        use std::sync::mpsc as std_mpsc;

        let mut hooks = HooksConfig::default();
        hooks.permission_request.push(HookEntry {
            matcher: Some("bash".to_string()),
            hooks: vec![Hook::Command {
                command: r#"printf '{"decision":"deny","reason":"hook veto"}'"#.to_string(),
                shell: false,
                timeout: 5,
            }],
        });
        let engine = HookEngine::new(hooks);
        let directory = tempfile::TempDir::new().expect("tempdir");
        let manager =
            PermissionManager::new(directory.path().join("permissions.json"), true, Vec::new());
        let (tx, rx) = std_mpsc::channel::<AppEvent>();

        let outcome = check_tool_permission(
            &test_run(),
            "bash",
            "call_hook",
            r#"{"command":"printf permission-hook-test"}"#,
            &manager,
            &[],
            Some(&engine),
            Some("session-1"),
            &tx,
        )
        .await;

        let PermissionOutcome::DeniedWithResult(result) = outcome else {
            panic!("permission hook denial must return DeniedWithResult");
        };
        assert_eq!(result["tool_call_id"], "call_hook");
        assert!(
            result["content"]
                .as_str()
                .is_some_and(|content| content.contains("hook veto")),
            "model-facing denial must include hook reason: {result}"
        );

        let mut saw_permission_request = false;
        let mut saw_tool_done = false;
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::PermissionRequest { reply, .. } => {
                    saw_permission_request = true;
                    let _ = reply.send(PermissionResponse::Deny);
                }
                AppEvent::ToolDone {
                    name,
                    success,
                    content,
                } => {
                    saw_tool_done = true;
                    assert_eq!(name, "bash");
                    assert!(!success);
                    assert!(content.contains("hook veto"), "{content}");
                }
                _ => {}
            }
        }

        assert!(
            saw_tool_done,
            "hook denial must emit a ToolDone failure event"
        );
        assert!(
            !saw_permission_request,
            "hook denial must short-circuit before the TUI permission prompt"
        );
    }

    /// crosslink #724 / S-017 — an exact session denial short-circuits without
    /// granting denial authority over other Bash invocations.
    #[tokio::test]
    async fn issue_724_check_tool_permission_uses_exact_session_denial() {
        use std::sync::mpsc as std_mpsc;

        let dir = tempfile::TempDir::new().expect("tempdir");
        let mgr = PermissionManager::new(dir.path().join("permissions.json"), true, Vec::new());
        let denied = ToolCall {
            id: "prior_call".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "bash".to_string(),
                arguments: r#"{"command":"cargo test"}"#.to_string(),
            },
        };
        mgr.deny_tool_call_for_session(
            &denied,
            "session-1",
            crate::permissions::ApprovalProvenance::InteractiveUser,
        )
        .expect("exact session denial");

        let (tx, rx) = std_mpsc::channel::<AppEvent>();
        let outcome = check_tool_permission(
            &test_run(),
            "bash",
            "call_1",
            "{\"command\":\"cargo test\"}",
            &mgr,
            &[],
            None,
            Some("session-1"),
            &tx,
        )
        .await;
        assert!(
            matches!(outcome, PermissionOutcome::DeniedWithResult(_)),
            "#724: a prior 'always deny' must short-circuit to Denied without a prompt"
        );
        // A ToolDone event is emitted to inform the TUI, but NOT a PermissionRequest.
        let mut saw_perm_request = false;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, AppEvent::PermissionRequest { .. }) {
                saw_perm_request = true;
            }
        }
        assert!(
            !saw_perm_request,
            "#724: no PermissionRequest event must be sent when the session cache denies"
        );
    }

    #[test]
    fn ultrathink_keyword_promotes_anthropic_thinking() {
        let prev = (
            std::env::var("MAX_THINKING_TOKENS").ok(),
            std::env::var("CLAUDE_CODE_EFFORT_LEVEL").ok(),
        );
        unsafe {
            std::env::remove_var("MAX_THINKING_TOKENS");
            std::env::remove_var("CLAUDE_CODE_EFFORT_LEVEL");
        }
        let messages = vec![serde_json::json!({
            "role": "user",
            "content": "ultrathink and plan this out"
        })];
        // Base effort is medium — dispatcher should see the keyword and
        // bump to high, attaching the ULTRATHINK budget.
        let req = build_request(
            "anthropic",
            "claude-sonnet-4-6",
            &messages,
            "medium",
            None,
            None,
        )
        .expect("anthropic request should build");
        assert_eq!(
            req["thinking"]["budget_tokens"],
            crate::thinking::ULTRATHINK_BUDGET_TOKENS,
        );
        if let Some(v) = prev.0 {
            unsafe {
                std::env::set_var("MAX_THINKING_TOKENS", v);
            }
        }
        if let Some(v) = prev.1 {
            unsafe {
                std::env::set_var("CLAUDE_CODE_EFFORT_LEVEL", v);
            }
        }
    }

    // ─── Crosslink #695: SSE line-cap forensic evidence ──────────────────
    //
    // The SSE reader in `stream_sse_response` previously accumulated upstream
    // bytes into an unbounded `String` until a `\n` was found. A hostile or
    // broken upstream that streams payloads without newlines could grow the
    // accumulator until OOM. `enforce_sse_line_cap` is the pure-function
    // guard that backs the fix; these tests pin its contract.

    /// #695 — `MAX_SSE_LINE_BYTES` constant is pinned at 1 MiB.
    ///
    /// Raising this without an explicit gap issue weakens the OOM defense.
    /// Lowering it could split legitimately-long SSE frames.
    #[test]
    fn issue_695_max_sse_line_bytes_constant_is_1mib() {
        assert_eq!(
            crate::proxy::MAX_SSE_LINE_BYTES,
            1024 * 1024,
            "MAX_SSE_LINE_BYTES must remain at 1 MiB until a gap issue revises it"
        );
    }

    /// #695 — small newline-free buffer stays untouched (no false trip).
    ///
    /// A partial frame mid-flight is normal: the accumulator must hold
    /// pending bytes until the terminator arrives.
    #[test]
    fn issue_695_enforce_sse_line_cap_small_buffer_is_no_op() {
        let mut buffer = "data: {\"partial\":\"frame".to_string();
        let original_len = buffer.len();
        let outcome = enforce_sse_line_cap(&mut buffer);
        assert_eq!(outcome, SseLineCapOutcome::WithinCap);
        assert_eq!(
            buffer.len(),
            original_len,
            "within-cap buffer must not be mutated"
        );
    }

    /// #695 — the buffer is bounded against an unbounded newline-free
    /// upstream simulation.
    ///
    /// Forensic invariant: no matter how many chunks the helper sees,
    /// the buffer size after enforcement never exceeds `MAX_SSE_LINE_BYTES`.
    /// This mirrors the OOM attack scenario described in the issue.
    #[test]
    fn issue_695_enforce_sse_line_cap_bounds_unbounded_input() {
        let mut buffer = String::new();
        // Simulate 8 chunks of 256 KiB of newline-free bytes — together
        // 2 MiB, double the cap.
        let chunk = "A".repeat(256 * 1024);
        let mut total_discarded = 0usize;
        let mut times_tripped = 0usize;
        for _ in 0..8 {
            buffer.push_str(&chunk);
            match enforce_sse_line_cap(&mut buffer) {
                SseLineCapOutcome::WithinCap => {}
                SseLineCapOutcome::Exceeded { discarded_bytes } => {
                    total_discarded += discarded_bytes;
                    times_tripped += 1;
                    // The cap MUST have reset the buffer.
                    assert!(
                        buffer.is_empty(),
                        "Exceeded outcome must leave the buffer empty (was {} bytes)",
                        buffer.len()
                    );
                }
            }
            // After every iteration the live buffer must respect the cap.
            assert!(
                buffer.len() < crate::proxy::MAX_SSE_LINE_BYTES,
                "buffer.len() = {} must stay below MAX_SSE_LINE_BYTES = {}",
                buffer.len(),
                crate::proxy::MAX_SSE_LINE_BYTES
            );
        }
        assert!(
            times_tripped >= 1,
            "2 MiB of newline-free input must trip the cap at least once (tripped {times_tripped} times)"
        );
        let cap = crate::proxy::MAX_SSE_LINE_BYTES;
        assert!(
            total_discarded >= cap,
            "expected at least {cap} bytes discarded in aggregate, got {total_discarded}"
        );
    }

    /// #695 — when a buffer contains a newline the cap MUST NOT fire,
    /// even if total length exceeds the cap.
    ///
    /// The cap only targets unterminated runaway lines; a legitimate
    /// frame larger than the cap is still routed to the line drainer
    /// (it terminates on its own `\n`). This guards against false
    /// positives that would silently drop valid SSE frames.
    #[test]
    fn issue_695_enforce_sse_line_cap_skips_when_newline_present() {
        let mut buffer = String::with_capacity(2 * 1024 * 1024);
        buffer.push_str(&"x".repeat(2 * 1024 * 1024));
        buffer.push('\n');
        let pre_len = buffer.len();
        let outcome = enforce_sse_line_cap(&mut buffer);
        assert_eq!(
            outcome,
            SseLineCapOutcome::WithinCap,
            "newline-terminated frames are the drainer's job, not the cap's"
        );
        assert_eq!(
            buffer.len(),
            pre_len,
            "newline-terminated buffer must not be cleared"
        );
    }

    /// #695 — buffer reset is total: a newline-free overflow is
    /// discarded in full, not truncated.
    ///
    /// Forensic invariant: after the cap trips, the next valid frame
    /// arriving on the wire parses cleanly. Truncation (keeping a
    /// suffix) would corrupt the next line.
    #[test]
    fn issue_695_enforce_sse_line_cap_reset_is_total() {
        let mut buffer = "B".repeat(crate::proxy::MAX_SSE_LINE_BYTES + 7);
        let pre_len = buffer.len();
        let outcome = enforce_sse_line_cap(&mut buffer);
        assert_eq!(
            outcome,
            SseLineCapOutcome::Exceeded {
                discarded_bytes: pre_len
            },
            "discarded count must equal the full pre-reset buffer length"
        );
        assert_eq!(
            buffer.len(),
            0,
            "buffer must be fully cleared, not truncated"
        );

        // After reset, a fresh valid frame must drain normally.
        buffer.push_str("data: {\"ok\":true}\n");
        assert!(buffer.contains('\n'));
        let post_outcome = enforce_sse_line_cap(&mut buffer);
        assert_eq!(post_outcome, SseLineCapOutcome::WithinCap);
    }

    // ── Crosslink #788 — Gemini SAFETY finish-reason handling ────────────

    /// #788-1: `SAFETY` finish reason maps to `safety_blocked` and surfaces
    /// a user-visible error string. Pinning the prior bug: the function
    /// used to drop this signal silently and the TUI saw an empty completion.
    #[test]
    fn issue_788_safety_finish_reason_maps_to_safety_blocked_with_user_error() {
        let body = serde_json::json!({
            "candidates": [{
                "finishReason": "SAFETY",
                "content": { "parts": [] }
            }]
        });
        let out = classify_google_finish_reason(&body, 0);
        assert_eq!(
            out.finish_reason.as_deref(),
            Some("safety_blocked"),
            "SAFETY must normalize to safety_blocked"
        );
        let err = out.user_error.expect("SAFETY must produce a user error");
        assert!(
            err.contains("SAFETY"),
            "user error must name the original Gemini finishReason: {err}"
        );
        assert!(
            err.contains("blocked"),
            "user error must explain that the response was blocked: {err}"
        );
    }

    /// #788-2: `RECITATION` and `BLOCKLIST` map to the same normalized
    /// `safety_blocked` outcome — they are all "suppressed by filter"
    /// from the caller's perspective.
    #[test]
    fn issue_788_recitation_and_blocklist_also_map_to_safety_blocked() {
        for reason in ["RECITATION", "BLOCKLIST"] {
            let body = serde_json::json!({
                "candidates": [{ "finishReason": reason }]
            });
            let out = classify_google_finish_reason(&body, 0);
            assert_eq!(
                out.finish_reason.as_deref(),
                Some("safety_blocked"),
                "{reason} must normalize to safety_blocked"
            );
            assert!(
                out.user_error.is_some(),
                "{reason} must surface a user-visible error"
            );
        }
    }

    /// #788-3: Normal `STOP` and `MAX_TOKENS` must NOT trigger a user
    /// error — they are non-block terminations. `MAX_TOKENS` maps to
    /// `length` (matching OpenAI-side naming used elsewhere); `STOP`
    /// maps to `stop`. Missing `finishReason` yields the default
    /// (all `None`).
    #[test]
    fn issue_788_benign_finish_reasons_do_not_surface_error() {
        let stop = classify_google_finish_reason(
            &serde_json::json!({"candidates":[{"finishReason":"STOP"}]}),
            42,
        );
        assert_eq!(stop.finish_reason.as_deref(), Some("stop"));
        assert!(stop.user_error.is_none(), "STOP must not produce an error");

        let max = classify_google_finish_reason(
            &serde_json::json!({"candidates":[{"finishReason":"MAX_TOKENS"}]}),
            128,
        );
        assert_eq!(max.finish_reason.as_deref(), Some("length"));
        assert!(
            max.user_error.is_none(),
            "MAX_TOKENS must not surface an ApiError (only a warn log)"
        );

        let none = classify_google_finish_reason(&serde_json::json!({"candidates":[{}]}), 0);
        assert_eq!(none, GoogleFinishClassification::default());
    }

    /// #788-4: Unknown finish reasons must pass through verbatim, NOT
    /// silently re-classified as a safety block. Pins behaviour against
    /// accidental over-triggering of user-visible errors if Google adds
    /// a new enum variant.
    #[test]
    fn issue_788_unknown_finish_reason_passes_through_verbatim_without_error() {
        let body = serde_json::json!({
            "candidates": [{ "finishReason": "FUTURE_REASON_X" }]
        });
        let out = classify_google_finish_reason(&body, 0);
        assert_eq!(
            out.finish_reason.as_deref(),
            Some("FUTURE_REASON_X"),
            "unknown finish reasons must pass through unchanged"
        );
        assert!(
            out.user_error.is_none(),
            "unknown finish reasons must NOT trigger a user-visible error"
        );
    }

    // === Crosslink #592 #595 #596 #597 retry-classifier regression =========

    /// #597: every status in the CC-parity transient set retries.
    #[test]
    fn issue_597_retryable_statuses_match_cc_set() {
        for status in [408, 409, 429, 500, 502, 503, 504, 529] {
            assert!(
                is_retryable_status(status),
                "{status} must be classified retryable"
            );
        }
        // Non-transient — must NOT retry (4xx that are caller-bug, 2xx happy).
        for status in [200, 201, 400, 401, 403, 404, 422] {
            assert!(
                !is_retryable_status(status),
                "{status} must NOT be classified retryable"
            );
        }
    }

    /// #596: jitter spread must be non-zero so concurrent retriers don't
    /// land on identical waits. Sample a window of attempts and assert
    /// at least two of them differ.
    #[test]
    fn issue_596_backoff_jitter_produces_non_constant_output() {
        let mut seen = std::collections::HashSet::new();
        // 200 samples at attempt=3 → base=16 → jitter ±4 → 9..=24 range.
        // With a healthy nanos source the set should have at least 3
        // distinct values long before we exhaust the loop.
        for _ in 0..200 {
            seen.insert(backoff_with_jitter(3));
            if seen.len() >= 3 {
                break;
            }
        }
        assert!(
            seen.len() >= 2,
            "backoff_with_jitter must produce >=2 distinct waits across 200 samples, saw {seen:?}"
        );
    }

    /// #596: backoff is always at least 1 second even at attempt=0
    /// (saturating arithmetic must never yield 0 sleep — that would
    /// spin-burn the CPU on a stuck transient).
    #[test]
    fn issue_596_backoff_floor_is_one_second() {
        for _ in 0..50 {
            let wait = backoff_with_jitter(0);
            assert!(wait >= 1, "wait must be >=1, got {wait}");
        }
    }

    #[test]
    fn issue_596_retry_after_zero_keeps_zero_delay() {
        assert_eq!(
            retry_after_with_jitter_from(0, u64::MAX),
            std::time::Duration::ZERO,
            "Retry-After: 0 must stay zero so deterministic tests and immediate retry semantics hold"
        );
    }

    #[test]
    fn issue_596_retry_after_jitter_is_additive_and_bounded() {
        let base = std::time::Duration::from_secs(4);
        let max = std::time::Duration::from_secs(5);

        let no_jitter = retry_after_with_jitter_from(4, 0);
        let max_jitter = retry_after_with_jitter_from(4, 1_000);

        assert_eq!(no_jitter, base);
        assert_eq!(max_jitter, max);
        for seed in [1, 42, 999, 1_001, u64::MAX] {
            let wait = retry_after_with_jitter_from(4, seed);
            assert!(
                (base..=max).contains(&wait),
                "Retry-After jitter must stay within 0-25%; seed={seed}, wait={wait:?}"
            );
        }
    }

    /// #592: `max_retries` cap is the CC-parity value (10). Pins via the
    /// constant being public-via-classifier; if the loop's `MAX_RETRIES`
    /// drifts, future test failures will name the value.
    #[test]
    fn issue_592_retry_classifier_and_helper_are_publicly_accessible() {
        // These are exercise tests for the public surface of #595-#597.
        // The actual MAX_RETRIES const lives inside run_turn but the
        // helpers must be callable from elsewhere so they're testable
        // and reusable across seams.
        assert!(is_retryable_status(429));
        let _ = backoff_with_jitter(0);
    }

    // ── crosslink #598 — overload fallback hint ──────────────────────────────

    /// `#598-a`: opus models fall back to sonnet, sonnet to haiku.
    /// Pins the descent through the Claude tiers.
    #[test]
    fn issue_598_claude_family_downgrade_path() {
        assert_eq!(
            overload_fallback_for("claude-opus-4-8"),
            "claude-sonnet-4-6"
        );
        assert_eq!(
            overload_fallback_for("claude-sonnet-4-6"),
            "claude-haiku-4-5"
        );
        // Haiku has no further downgrade — empty hint, but the event
        // is still emitted by send_with_retry so log consumers see it.
        assert_eq!(overload_fallback_for("claude-haiku-4-5"), "");
    }

    /// `#598-b`: GPT-5 degrades to mini, GPT-4 / o-series degrade to
    /// gpt-4o-mini, Gemini Pro degrades to Gemini Flash, and unknown
    /// model families return the empty hint.
    #[test]
    fn issue_598_cross_provider_fallback_map() {
        assert_eq!(overload_fallback_for("gpt-5.5"), "gpt-5.4-mini");
        assert_eq!(overload_fallback_for("gpt-5.4"), "gpt-5.4-mini");
        assert_eq!(overload_fallback_for("gpt-5"), "gpt-5-mini");
        assert_eq!(overload_fallback_for("gpt-4-turbo"), "gpt-4o-mini");
        assert_eq!(overload_fallback_for("gpt-4o"), "gpt-4o-mini");
        assert_eq!(overload_fallback_for("o1-preview"), "gpt-4o-mini");
        assert_eq!(overload_fallback_for("o3-mini"), "gpt-4o-mini");
        assert_eq!(
            overload_fallback_for("gemini-3.1-pro-preview"),
            "gemini-3.5-flash"
        );
        // Unknown family — empty hint, distinct from a known mapping.
        assert_eq!(overload_fallback_for("llama-3-70b"), "");
        assert_eq!(overload_fallback_for(""), "");
    }

    /// `#598-c`: the `OverloadFallback` `AppEvent` variant carries a
    /// `String` `model_hint` and can round-trip through a channel. Acts
    /// as the type-level pin so a future enum change that drops the
    /// variant (or its field shape) breaks one test instead of cascading
    /// through every match site silently.
    #[test]
    fn issue_598_overload_fallback_event_round_trips() {
        let (tx, rx) = std::sync::mpsc::channel::<AppEvent>();
        tx.send(AppEvent::OverloadFallback {
            model_hint: "claude-haiku-4-5".to_string(),
        })
        .expect("send must succeed on a live channel");
        match rx.recv().expect("event must arrive") {
            AppEvent::OverloadFallback { model_hint } => {
                assert_eq!(model_hint, "claude-haiku-4-5");
            }
            other => panic!(
                "expected OverloadFallback, got {}",
                describe_app_event(&other)
            ),
        }
    }

    fn describe_app_event(ev: &AppEvent) -> &'static str {
        match ev {
            AppEvent::OverloadFallback { .. } => "OverloadFallback",
            _ => "other",
        }
    }
}

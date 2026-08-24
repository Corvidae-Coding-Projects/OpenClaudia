//! API pipeline — builds requests, streams responses, and executes tools.
//!
//! Extracted from the `cmd_chat` function in `main.rs` to enable reuse
//! from both the rustyline REPL and the ratatui TUI.

use crate::config::{AppConfig, ThinkingConfig};
use crate::memory::MemoryDb;
use crate::permissions::{
    ApprovalProvenance, AuthorizationResult, ExecutionPermit, PermissionManager, PermissionRule,
};
use crate::provider_transport::{self, RequestReplaySafety};
use crate::providers::{
    apply_anthropic_adaptive_thinking, convert_messages_to_anthropic_checked,
    convert_tool_definitions_to_anthropic_checked, get_adapter, ReasoningProfile,
};
use crate::proxy::{self, normalize_base_url};
use crate::services::policy::{PolicyEnforcer, PolicyError};
use crate::session::TokenUsage;
use crate::tools::{self, AnthropicToolAccumulator, ToolCall, ToolCallAccumulator};
use crate::tui::events::{
    ApiRetryKind, AppEvent, PermissionResponse, PlanModeReply, PlanModeRequest,
};
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

#[cfg(test)]
mod provider_terminal_outcome_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn done_without_finish_reason_is_not_success() {
        let mut terminal = ChatStreamTerminal::new("openai");
        terminal
            .observe(&json!({"choices": [{"delta": {"content": "partial"}}]}))
            .expect("text delta is valid");
        terminal.observe_done();

        let error = terminal.finish().expect_err("terminal reason is required");
        assert!(error.contains("without a valid terminal reason"), "{error}");
    }

    #[test]
    fn valid_finish_reason_survives_transport_eof() {
        let mut terminal = ChatStreamTerminal::new("openai-compatible");
        terminal
            .observe(&json!({
                "choices": [{"delta": {}, "finish_reason": "stop"}]
            }))
            .expect("known terminal reason");

        assert_eq!(
            terminal.finish().expect("finish reason is terminal"),
            ProviderTerminalOutcome::Completed
        );
    }

    #[test]
    fn anthropic_requires_message_stop_after_stop_reason() {
        let mut terminal = ChatStreamTerminal::new("anthropic");
        terminal
            .observe(&json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"}
            }))
            .expect("known stop reason");

        let error = terminal.finish().expect_err("message_stop is required");
        assert!(error.contains("before message_stop"), "{error}");
    }

    #[test]
    fn anthropic_message_stop_commits_normal_completion() {
        let mut terminal = ChatStreamTerminal::new("anthropic");
        terminal
            .observe(&json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn"}
            }))
            .expect("known stop reason");
        terminal
            .observe(&json!({"type": "message_stop"}))
            .expect("message_stop");

        assert_eq!(
            terminal.finish().expect("complete Anthropic stream"),
            ProviderTerminalOutcome::Completed
        );
    }

    #[test]
    fn length_and_refusal_are_typed_non_success_outcomes() {
        let mut length = ChatStreamTerminal::new("openai");
        length
            .observe(&json!({
                "choices": [{"delta": {}, "finish_reason": "length"}]
            }))
            .expect("known length reason");
        let outcome = length.finish().expect("typed terminal outcome");
        assert_eq!(outcome, ProviderTerminalOutcome::LengthLimited);
        assert!(ensure_provider_turn_succeeded(outcome, 0).is_err());

        let mut refusal = ChatStreamTerminal::new("openai");
        refusal
            .observe(&json!({
                "choices": [{
                    "delta": {"refusal": "cannot comply"},
                    "finish_reason": "stop"
                }]
            }))
            .expect("refusal delta");
        let outcome = refusal.finish().expect("typed terminal outcome");
        assert_eq!(outcome, ProviderTerminalOutcome::Refused);
        assert!(ensure_provider_turn_succeeded(outcome, 0).is_err());
    }

    #[test]
    fn nonstream_chat_requires_terminal_reason_and_matching_tools() {
        let missing = json!({
            "choices": [{"message": {"role": "assistant", "content": "partial"}}]
        });
        assert!(validate_chat_completion_terminal(&missing).is_err());

        let tool_turn = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{"id": "call_1"}]
                },
                "finish_reason": "tool_calls"
            }]
        });
        assert_eq!(
            validate_chat_completion_terminal(&tool_turn).expect("matching tool terminal"),
            ProviderTerminalOutcome::ToolCalls
        );
    }
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

/// Provider-authored terminal state for one completed model turn.
///
/// Text and reasoning deltas are provisional until one of these states has
/// been decoded from the provider protocol. Only [`Self::Completed`] and
/// [`Self::ToolCalls`] are successful application outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderTerminalOutcome {
    /// The provider completed a normal assistant response.
    Completed,
    /// The provider completed the turn by requesting tools.
    ToolCalls,
    /// The provider stopped because its output limit was reached.
    LengthLimited,
    /// The provider explicitly refused the request.
    Refused,
    /// The provider filtered or suppressed the response.
    ContentFiltered,
}

impl std::fmt::Display for ProviderTerminalOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Completed => "completed",
            Self::ToolCalls => "tool_calls",
            Self::LengthLimited => "length_limited",
            Self::Refused => "refused",
            Self::ContentFiltered => "content_filtered",
        })
    }
}

/// Require a provider terminal state that agrees with the decoded tool calls.
///
/// # Errors
///
/// Returns an error for refusal/filter/length outcomes or when the terminal
/// reason disagrees with the response structure.
pub fn ensure_provider_turn_succeeded(
    outcome: ProviderTerminalOutcome,
    tool_call_count: usize,
) -> Result<(), String> {
    match outcome {
        ProviderTerminalOutcome::Completed if tool_call_count == 0 => Ok(()),
        ProviderTerminalOutcome::Completed => Err(format!(
            "Provider reported a normal completion but returned {tool_call_count} tool call(s)"
        )),
        ProviderTerminalOutcome::ToolCalls if tool_call_count > 0 => Ok(()),
        ProviderTerminalOutcome::ToolCalls => {
            Err("Provider reported tool calls but returned no complete tool call".to_string())
        }
        ProviderTerminalOutcome::LengthLimited => {
            Err("Provider response stopped at its output limit".to_string())
        }
        ProviderTerminalOutcome::Refused => Err("Provider refused the request".to_string()),
        ProviderTerminalOutcome::ContentFiltered => {
            Err("Provider filtered the response".to_string())
        }
    }
}

fn classify_provider_finish_reason(
    reason: &str,
    refusal_observed: bool,
) -> Result<ProviderTerminalOutcome, String> {
    let normalized = reason.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "stop" | "end_turn" | "stop_sequence" if refusal_observed => {
            Ok(ProviderTerminalOutcome::Refused)
        }
        "stop" | "end_turn" | "stop_sequence" => Ok(ProviderTerminalOutcome::Completed),
        "tool_calls" | "tool_use" | "function_call" => Ok(ProviderTerminalOutcome::ToolCalls),
        "length" | "max_tokens" | "model_context_window_exceeded" => {
            Ok(ProviderTerminalOutcome::LengthLimited)
        }
        "refusal" | "refused" => Ok(ProviderTerminalOutcome::Refused),
        "content_filter" | "content_filtered" | "safety" | "safety_blocked" | "recitation"
        | "blocklist" => Ok(ProviderTerminalOutcome::ContentFiltered),
        "" => Err("Provider emitted an empty terminal reason".to_string()),
        _ => Err(format!(
            "Provider emitted unknown terminal reason {reason:?}"
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatStreamProtocol {
    Anthropic,
    OpenAiCompatible,
}

/// Shared terminal-state tracker for Anthropic and OpenAI-compatible chat SSE.
///
/// Frontends may render deltas while streaming, but must call [`Self::finish`]
/// before committing them as assistant history or reporting success.
#[derive(Debug)]
pub struct ChatStreamTerminal {
    protocol: ChatStreamProtocol,
    outcome: Option<ProviderTerminalOutcome>,
    refusal_observed: bool,
    protocol_complete: bool,
}

impl ChatStreamTerminal {
    #[must_use]
    pub fn new(provider: &str) -> Self {
        Self {
            protocol: if provider.trim().eq_ignore_ascii_case("anthropic") {
                ChatStreamProtocol::Anthropic
            } else {
                ChatStreamProtocol::OpenAiCompatible
            },
            outcome: None,
            refusal_observed: false,
            protocol_complete: false,
        }
    }

    /// Observe an SSE `event:` name when the frontend parses frames manually.
    /// Eventsource-based callers normally receive the equivalent JSON event.
    ///
    /// # Errors
    ///
    /// Returns an error when a provider error event is observed.
    pub fn observe_event_name(&mut self, event: &str) -> Result<(), String> {
        match event.trim() {
            "message_stop" => {
                self.protocol_complete = true;
                Ok(())
            }
            "error" => Err("Provider emitted an SSE error event".to_string()),
            _ => Ok(()),
        }
    }

    /// Observe one decoded provider SSE data object.
    ///
    /// # Errors
    ///
    /// Returns an error for provider error envelopes, unknown terminal reasons,
    /// or contradictory terminal states.
    pub fn observe(&mut self, json: &Value) -> Result<(), String> {
        if let Some(error) = json.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| error.as_str())
                .filter(|message| !message.is_empty())
                .unwrap_or("provider stream error");
            return Err(format!("Provider stream error: {message}"));
        }

        if let Some(event_type) = json.get("type").and_then(Value::as_str) {
            match event_type {
                "error" => return Err("Provider emitted an SSE error event".to_string()),
                "message_stop" => self.protocol_complete = true,
                "message_delta" => {
                    if let Some(reason) = json
                        .get("delta")
                        .and_then(|delta| delta.get("stop_reason"))
                        .and_then(Value::as_str)
                    {
                        let outcome =
                            classify_provider_finish_reason(reason, self.refusal_observed)?;
                        self.record_outcome(outcome)?;
                    }
                }
                _ => {}
            }
        }

        if let Some(choice) = json
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
        {
            self.refusal_observed |= choice
                .get("delta")
                .and_then(|delta| delta.get("refusal"))
                .and_then(Value::as_str)
                .is_some_and(|refusal| !refusal.is_empty());
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                let outcome = classify_provider_finish_reason(reason, self.refusal_observed)?;
                self.record_outcome(outcome)?;
            }
        }
        Ok(())
    }

    /// Mark an OpenAI-compatible `[DONE]` sentinel.
    pub fn observe_done(&mut self) {
        if self.protocol == ChatStreamProtocol::OpenAiCompatible {
            self.protocol_complete = true;
        }
    }

    /// Return the validated provider terminal outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream ended without a terminal reason, or an
    /// Anthropic stream omitted its required `message_stop` event.
    pub fn finish(self) -> Result<ProviderTerminalOutcome, String> {
        let outcome = self
            .outcome
            .ok_or_else(|| "Provider stream ended without a valid terminal reason".to_string())?;
        if self.protocol == ChatStreamProtocol::Anthropic && !self.protocol_complete {
            return Err("Anthropic stream ended before message_stop".to_string());
        }
        Ok(outcome)
    }

    fn record_outcome(&mut self, outcome: ProviderTerminalOutcome) -> Result<(), String> {
        if let Some(previous) = self.outcome {
            if previous != outcome {
                return Err(format!(
                    "Provider stream emitted contradictory terminal reasons: {previous} then {outcome}"
                ));
            }
        } else {
            self.outcome = Some(outcome);
        }
        Ok(())
    }
}

/// Classify a complete OpenAI-compatible chat response.
///
/// # Errors
///
/// Returns an error when the first choice lacks a terminal reason, carries an
/// unknown/non-success reason, or disagrees with its tool-call payload.
pub fn validate_chat_completion_terminal(
    response: &Value,
) -> Result<ProviderTerminalOutcome, String> {
    let choice = response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .ok_or_else(|| "Provider response is missing choices[0]".to_string())?;
    let message = choice
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| "Provider response choices[0] is missing message".to_string())?;
    let refusal_observed = message
        .get("refusal")
        .and_then(Value::as_str)
        .is_some_and(|refusal| !refusal.is_empty());
    let reason = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "Provider response choices[0] is missing a terminal finish_reason".to_string()
        })?;
    let outcome = classify_provider_finish_reason(reason, refusal_observed)?;
    let tool_call_count = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    ensure_provider_turn_succeeded(outcome, tool_call_count)?;
    Ok(outcome)
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
    /// Validated provider terminal state for this turn.
    pub terminal_outcome: ProviderTerminalOutcome,
    /// Normalized finish reason surfaced to the caller, when the provider
    /// reports one. `None` for normal stop on streams that do not propagate
    /// a distinct termination cause through this layer.
    ///
    /// Values currently emitted by [`decode_provider_native_json_turn`]
    /// (crosslink #788):
    /// - `Some("safety_blocked")` — Gemini set `finishReason` to `SAFETY`,
    ///   `RECITATION`, or `BLOCKLIST`. Text may be empty; callers should
    ///   surface a user-visible error rather than treating this as a normal
    ///   empty completion.
    /// - `Some("length")` — `MAX_TOKENS` truncation.
    /// - `Some("stop")` — explicit `STOP` from the provider.
    /// - `Some(other)` — verbatim pass-through for unrecognized reasons.
    pub finish_reason: Option<String>,
    /// Complete provider-owned continuation after this turn, when the wire
    /// protocol requires native state. Construction and bounds validation
    /// happen before tool effects are dispatched.
    pub provider_native_state: Option<crate::runtime::ProviderNativeState>,
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

/// Return the portable ordinal for the next assistant message.
///
/// Provider-native continuation binds to this stable projection so
/// request-scoped system, grounding, and verifier context cannot shift it.
///
/// # Errors
///
/// Returns an error only if the platform cannot represent the message count as
/// `u64`.
pub fn next_assistant_message_ordinal(messages: &[Value]) -> Result<u64, String> {
    let count = messages
        .iter()
        .filter(|message| message.get("role").and_then(Value::as_str) != Some("system"))
        .count();
    u64::try_from(count).map_err(|_| "portable conversation ordinal overflow".to_string())
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
    build_anthropic_request_with_tools(
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
        &tools::get_all_tool_definitions(true),
    )
}

fn build_anthropic_request_with_tools(
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
    openai_tools: &Value,
) -> Result<Value, String> {
    let anthropic_messages =
        convert_messages_to_anthropic_checked(messages).map_err(|e| e.to_string())?;
    let anthropic_tools =
        convert_tool_definitions_to_anthropic_checked(openai_tools).map_err(|e| e.to_string())?;

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
        crate::claude_credentials::inject_oauth_prefix_only(&mut req)
            .map_err(|error| error.to_string())?;
    }

    // Apply effort level. `high` / `max` switch Anthropic into thinking mode.
    // Models with exact adaptive evidence use adaptive thinking; models with
    // exact manual evidence keep the Claude Code budget path. Unknown models
    // receive no optional thinking fields.
    // MAX_THINKING_TOKENS env var overrides manual budgets outright. See
    // `crate::thinking` for the precedence chain and keyword-trigger logic
    // (ultrathink / think ultra hard).
    match effort_level {
        "high" | "max" | "xhigh" => {
            let profile = crate::providers::resolve_model("anthropic", model)
                .capabilities()
                .reasoning_profile;
            match profile {
                ReasoningProfile::AnthropicAdaptive => {
                    apply_anthropic_adaptive_thinking(&mut req, model, Some(effort_level));
                    req["max_tokens"] = serde_json::json!(40_000);
                }
                ReasoningProfile::AnthropicManual => {
                    if let Some(budget) =
                        crate::thinking::anthropic_thinking_budget(Some(effort_level))
                    {
                        req["thinking"] = serde_json::json!({
                            "type": "enabled",
                            "budget_tokens": budget,
                        });
                        // Headroom for the thinking block plus the answer.
                        req["max_tokens"] = serde_json::json!(40_000);
                    }
                }
                _ => {
                    tracing::warn!(
                        model,
                        "thinking requested without current Anthropic model-capability evidence; omitting thinking controls",
                    );
                }
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
    build_openai_request_with_tools(
        model,
        messages,
        effort_level,
        &tools::get_all_tool_definitions(true),
    )
}

fn build_openai_request_with_tools(
    model: &str,
    messages: &[Value],
    effort_level: &str,
    tool_definitions: &Value,
) -> Value {
    let mut req = serde_json::json!({
        "model": model,
        "messages": messages,
        "max_tokens": crate::DEFAULT_MAX_TOKENS,
        "stream": true,
        "tools": tool_definitions
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

fn response_input_message(role: &str, text: &str, ordinal: u64) -> Value {
    let item_type = if role == "assistant" {
        "output_text"
    } else {
        "input_text"
    };
    serde_json::json!({
        "type": "message",
        "role": role,
        "content": [{"type": item_type, "text": text}],
        "_openclaudia_message_ordinal": ordinal
    })
}

fn responses_input_items(messages: &[Value]) -> Result<(String, Vec<Value>, Vec<Value>), String> {
    let mut instructions = Vec::new();
    let mut input = Vec::new();
    let mut history = Vec::new();
    let mut next_ordinal = 0_u64;

    for (index, msg) in messages.iter().enumerate() {
        let role = msg
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("message at index {index} missing string 'role': {msg}"))?;
        let content_value = msg.get("content").unwrap_or(&Value::Null);
        let content = if role == "assistant" && content_value.is_null() {
            String::new()
        } else {
            text_from_message_content(content_value)?
        };
        match role {
            "system" => {
                if !content.is_empty() {
                    instructions.push(content);
                }
            }
            "user" => {
                let ordinal = next_ordinal;
                next_ordinal = next_ordinal
                    .checked_add(1)
                    .ok_or_else(|| "Responses history ordinal overflow".to_string())?;
                history.push(serde_json::json!({"ordinal": ordinal, "role": role}));
                input.push(response_input_message("user", &content, ordinal));
            }
            "assistant" => {
                let ordinal = next_ordinal;
                next_ordinal = next_ordinal
                    .checked_add(1)
                    .ok_or_else(|| "Responses history ordinal overflow".to_string())?;
                history.push(serde_json::json!({"ordinal": ordinal, "role": role}));
                if !content.is_empty() {
                    input.push(response_input_message("assistant", &content, ordinal));
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
                            "call_id": call_id,
                            "_openclaudia_message_ordinal": ordinal
                        }));
                    }
                }
            }
            "tool" => {
                let ordinal = next_ordinal;
                next_ordinal = next_ordinal
                    .checked_add(1)
                    .ok_or_else(|| "Responses history ordinal overflow".to_string())?;
                history.push(serde_json::json!({"ordinal": ordinal, "role": role}));
                let call_id = msg
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| format!("tool message missing tool_call_id: {msg}"))?;
                input.push(serde_json::json!({
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": content,
                    "_openclaudia_message_ordinal": ordinal
                }));
            }
            other => {
                return Err(format!(
                    "Responses backend does not support message role '{other}' at index {index}"
                ));
            }
        }
    }

    Ok((instructions.join("\n\n"), input, history))
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
    let mut request = build_openai_responses_request_draft_with_tools(
        model,
        messages,
        effort_level,
        &tools::get_all_tool_definitions(true),
    )?;
    crate::providers::finalize_responses_request(&mut request)?;
    Ok(request)
}

fn build_openai_responses_request_draft_with_tools(
    model: &str,
    messages: &[Value],
    effort_level: &str,
    openai_tools: &Value,
) -> Result<Value, String> {
    let (instructions, input, history) = responses_input_items(messages)?;
    let tools = responses_tools_from_openai_tools(openai_tools)?;
    let mut req = serde_json::json!({
        "model": model,
        "input": input,
        "stream": true,
        "store": false,
        "include": ["reasoning.encrypted_content"],
        // Responses owns its opaque compaction continuation. Trigger before
        // the model ceiling so the returned `compaction` item can be replayed
        // losslessly on the next stateless request.
        "context_management": [{
            "type": "compaction",
            "compact_threshold": crate::compaction::get_context_window(model).saturating_mul(4) / 5
        }],
        "_openclaudia_responses_history": history
    });
    if !tools.is_empty() {
        req["tools"] = Value::Array(tools);
        req["tool_choice"] = Value::String("auto".to_string());
        req["parallel_tool_calls"] = Value::Bool(true);
    }
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
    build_chat_completion_request_with_tools(
        model,
        messages,
        &tools::get_all_tool_definitions(true),
    )
}

/// Build the canonical policy-accounting request with the same progressive
/// definitions the exact run will publish to the provider.
///
/// # Errors
///
/// Returns an error if the run-owned catalog cannot be published or a message
/// cannot be represented as a typed chat-completions message.
pub fn build_chat_completion_request_for_run(
    run: &tools::ToolRunContext,
    model: &str,
    messages: &[Value],
) -> Result<proxy::ChatCompletionRequest, String> {
    let snapshot = tools::get_progressive_tool_definitions(run, messages, true)?;
    build_chat_completion_request_with_tools(model, messages, &snapshot.definitions_value())
}

fn build_chat_completion_request_with_tools(
    model: &str,
    messages: &[Value],
    tool_definitions: &Value,
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
    let tools = tool_definitions
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
    tool_definitions: &Value,
) -> Result<Value, String> {
    let mut request = build_chat_completion_request_with_tools(model, messages, tool_definitions)?;
    if provider.trim().eq_ignore_ascii_case("ollama") {
        // The canonical agent loops consume one complete JSON response. Keep
        // Ollama's NDJSON streaming protocol out of this path until the
        // bounded transport slice owns a native stream state machine.
        request.stream = Some(false);
        return crate::providers::OllamaAdapter::transform_request_draft(&request)
            .map_err(|error| error.to_string());
    }
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
    let model = crate::providers::default_model_for_target("google")
        .ok_or_else(|| "Google provider has no maintained default model".to_string())?;
    build_google_request_with_tools(
        model,
        messages,
        effort_level,
        &tools::get_all_tool_definitions(true),
    )
}

fn build_google_request_with_tools(
    model: &str,
    messages: &[Value],
    effort_level: &str,
    openai_tools: &Value,
) -> Result<Value, String> {
    for (message_index, message) in messages.iter().enumerate() {
        if let Some(role) = message.get("role").and_then(Value::as_str) {
            if !matches!(role, "system" | "user" | "assistant" | "tool") {
                return Err(format!(
                    "Google message at index {message_index} has unsupported role {role:?}"
                ));
            }
        }
    }
    let mut request = build_chat_completion_request_with_tools(model, messages, openai_tools)?;
    request.max_tokens = Some(4096);
    let mut thinking = thinking_config_for_pipeline_effort("google", effort_level);
    if let Some(thinking) = thinking.as_mut() {
        // Preserve the established Gemini high/max budget (including the
        // MAX_THINKING_TOKENS override) while using the canonical adapter.
        thinking.budget_tokens = crate::thinking::anthropic_thinking_budget(Some(effort_level));
    }
    crate::providers::GoogleAdapter::transform_request_draft_with_thinking(
        &request,
        thinking.as_ref(),
    )
    .map_err(|error| error.to_string())
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

/// Build a chat-completions request from the exact run-owned progressive tool
/// catalog rather than the compatibility full-catalog baseline.
///
/// # Errors
///
/// Returns an error when catalog publication, provider lookup, or provider
/// request conversion fails.
pub fn build_request_for_run(
    run: &tools::ToolRunContext,
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
) -> Result<Value, String> {
    build_request_for_run_with_state(
        run,
        provider,
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
        None,
    )
}

/// Build a chat-completions request and apply exact provider-native state.
///
/// # Errors
///
/// Returns an error when state identity, protocol, or adapter capabilities do
/// not permit a lossless request.
#[allow(clippy::too_many_arguments)]
pub fn build_request_for_run_with_state(
    run: &tools::ToolRunContext,
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
    provider_native_state: Option<&crate::runtime::ProviderNativeState>,
) -> Result<Value, String> {
    build_request_for_wire_for_run_with_state(
        run,
        WireApi::ChatCompletions,
        provider,
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
        provider_native_state,
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
    build_request_for_wire_with_tools(
        wire_api,
        provider,
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
        &tools::get_all_tool_definitions(true),
        None,
    )
}

/// Build the provider request from one exact run-owned progressive catalog
/// snapshot. This is the production path for TUI and legacy frontends.
///
/// # Errors
///
/// Returns an error when catalog publication, message conversion, provider
/// lookup, or provider-specific request conversion fails.
#[allow(clippy::too_many_arguments)]
pub fn build_request_for_wire_for_run(
    run: &tools::ToolRunContext,
    wire_api: WireApi,
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
) -> Result<Value, String> {
    build_request_for_wire_for_run_with_state(
        run,
        wire_api,
        provider,
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
        None,
    )
}

/// Build the provider request from an exact progressive catalog and optional
/// provider-native state.
///
/// # Errors
///
/// Returns an error when state cannot be applied losslessly or normal request
/// construction fails.
#[allow(clippy::too_many_arguments)]
pub fn build_request_for_wire_for_run_with_state(
    run: &tools::ToolRunContext,
    wire_api: WireApi,
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
    provider_native_state: Option<&crate::runtime::ProviderNativeState>,
) -> Result<Value, String> {
    build_request_for_wire_for_run_with_additional_and_state(
        run,
        wire_api,
        provider,
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
        &[],
        provider_native_state,
    )
}

/// Build a run-owned provider request with already-validated dynamic
/// definitions. The progressive catalog retains source digests and strips
/// host-only registration metadata before provider conversion.
///
/// # Errors
///
/// Returns an error when catalog publication or provider request conversion
/// rejects a malformed, stale, unavailable, or oversized definition set.
#[allow(clippy::too_many_arguments)]
pub fn build_request_for_wire_for_run_with_additional(
    run: &tools::ToolRunContext,
    wire_api: WireApi,
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
    additional: &[Value],
) -> Result<Value, String> {
    build_request_for_wire_for_run_with_additional_and_state(
        run,
        wire_api,
        provider,
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
        additional,
        None,
    )
}

/// Build a run-owned provider request and apply an exact provider-native state
/// envelope after provider conversion.
///
/// # Errors
///
/// Returns an error when catalog publication or provider conversion fails, or
/// when native state cannot be applied losslessly to the selected identity and
/// protocol.
#[allow(clippy::too_many_arguments)]
pub fn build_request_for_wire_for_run_with_additional_and_state(
    run: &tools::ToolRunContext,
    wire_api: WireApi,
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
    additional: &[Value],
    provider_native_state: Option<&crate::runtime::ProviderNativeState>,
) -> Result<Value, String> {
    let snapshot =
        tools::get_progressive_tool_definitions_with_additional(run, messages, true, additional)?;
    build_request_for_wire_with_tools(
        wire_api,
        provider,
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
        &snapshot.definitions_value(),
        provider_native_state,
    )
}

/// Build a provider request from an exact frontend-owned tool definition set.
///
/// ACP and child runs publish capability-filtered catalogs that must not be
/// widened back to the process-wide registry during provider conversion. This
/// entry point shares the canonical wire builder and continuation adapter while
/// preserving that exact catalog boundary.
///
/// # Errors
///
/// Returns an error when the selected wire conversion, tool definitions, or
/// provider-native state cannot be represented losslessly.
#[allow(clippy::too_many_arguments)]
pub fn build_request_for_wire_with_exact_tools_and_state(
    wire_api: WireApi,
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
    tool_definitions: &[Value],
    provider_native_state: Option<&crate::runtime::ProviderNativeState>,
) -> Result<Value, String> {
    let tool_definitions = Value::Array(tool_definitions.to_vec());
    build_request_for_wire_with_tools(
        wire_api,
        provider,
        model,
        messages,
        effort_level,
        claude_code_token,
        prompt_blocks,
        &tool_definitions,
        provider_native_state,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_request_for_wire_with_tools(
    wire_api: WireApi,
    provider: &str,
    model: &str,
    messages: &[Value],
    effort_level: &str,
    claude_code_token: Option<&crate::secrets::OAuthToken>,
    prompt_blocks: Option<&crate::prompt::SystemPromptBlocks>,
    tool_definitions: &Value,
    provider_native_state: Option<&crate::runtime::ProviderNativeState>,
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
    let mut body = if wire_api == WireApi::OpenAiResponses {
        build_openai_responses_request_draft_with_tools(
            model,
            effective_messages,
            effective,
            tool_definitions,
        )?
    } else {
        match provider.to_ascii_lowercase().as_str() {
            "anthropic" => build_anthropic_request_with_tools(
                model,
                effective_messages,
                effective,
                claude_code_token,
                prompt_blocks,
                tool_definitions,
            ),
            "google" | "gemini" => build_google_request_with_tools(
                model,
                effective_messages,
                effective,
                tool_definitions,
            ),
            _ => build_adapter_request(
                provider,
                model,
                effective_messages,
                effective,
                tool_definitions,
            ),
        }?
    };
    if let Some(state) = provider_native_state {
        apply_provider_native_state_to_request(wire_api, provider, model, &mut body, state)?;
    }
    if wire_api == WireApi::OpenAiResponses {
        crate::providers::finalize_responses_request(&mut body)?;
    } else {
        match provider.trim().to_ascii_lowercase().as_str() {
            "google" | "gemini" => {
                crate::providers::GoogleAdapter::finalize_request(&mut body)
                    .map_err(|error| error.to_string())?;
            }
            "ollama" => {
                crate::providers::OllamaAdapter::finalize_request(&mut body)
                    .map_err(|error| error.to_string())?;
            }
            _ => {}
        }
    }
    Ok(body)
}

/// Validate and apply provider-native state to a provider request assembled by
/// a frontend-specific follow-up path.
///
/// # Errors
///
/// Returns an error for provider/model/protocol drift, unsupported facets, or
/// an adapter that has not implemented lossless native-state application.
pub fn apply_provider_native_state_to_request(
    wire_api: WireApi,
    provider: &str,
    model: &str,
    request: &mut Value,
    state: &crate::runtime::ProviderNativeState,
) -> Result<(), String> {
    let protocol = provider_wire_protocol(wire_api, provider);
    state
        .validate_binding(provider, model, protocol)
        .map_err(|error| error.to_string())?;
    let adapter = get_adapter(provider).map_err(|error| error.to_string())?;
    adapter
        .apply_provider_native_state(request, state)
        .map_err(|error| error.to_string())
}

/// Resolve the concrete provider-owned protocol for one outbound request.
#[must_use]
pub fn provider_wire_protocol(
    wire_api: WireApi,
    provider: &str,
) -> crate::runtime::ProviderWireProtocol {
    if wire_api == WireApi::OpenAiResponses {
        return crate::runtime::ProviderWireProtocol::OpenAiResponses;
    }
    match provider.trim().to_ascii_lowercase().as_str() {
        "anthropic" => crate::runtime::ProviderWireProtocol::AnthropicMessages,
        "google" | "gemini" => crate::runtime::ProviderWireProtocol::GeminiGenerateContent,
        "ollama" => crate::runtime::ProviderWireProtocol::OllamaChat,
        _ => crate::runtime::ProviderWireProtocol::OpenAiChatCompletions,
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
    let endpoint = if wire_api == WireApi::OpenAiResponses {
        format!("{}/responses", normalize_base_url(base_url))
    } else if claude_code_token.is_some() {
        crate::claude_credentials::get_oauth_endpoint(model)
            .map_err(|error| crate::providers::ProviderError::Unsupported(error.to_string()))?
    } else {
        let adapter = get_adapter(provider)?;
        format!(
            "{}{}",
            normalize_base_url(base_url),
            adapter.chat_endpoint(model)
        )
    };
    provider_transport::validate_endpoint(provider, &endpoint)
        .map_err(|error| crate::providers::ProviderError::RequestFailed(error.to_string()))?;
    Ok(endpoint)
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
            .map_err(|error| crate::providers::ProviderError::Unsupported(error.to_string()))?
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
    /// Supported subscription transport owned by Anthropic's unmodified
    /// executable. When present, no provider HTTP request is made here.
    pub claude_agent_sdk: Option<&'a crate::claude_agent_sdk::ClaudeAgentSdk>,
    /// Provider reasoning effort forwarded to transports that expose it
    /// outside the request body (currently the Claude Agent SDK).
    pub effort_level: &'a str,
    pub request_body: &'a Value,
    pub provider: &'a str,
    pub model_identity: &'a str,
    /// Native continuation used to construct this request, if any.
    pub provider_native_state: Option<&'a crate::runtime::ProviderNativeState>,
    /// Non-system portable-message ordinal for the assistant turn returned by
    /// this request.
    pub assistant_message_ordinal: u64,
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
/// Preserves the established ten-retry compatibility ceiling. S-048 adds a
/// shared monotonic retry window, so immediate/short provider recovery keeps
/// working while long backoff sequences terminate within a wall-clock budget.
pub const MAX_API_RETRIES: u32 = provider_transport::MAX_PROVIDER_ATTEMPTS - 1;

/// HTTP status codes that warrant a retry. Matches CC's
/// `withRetry.ts` transient-status set:
///   * 408 — Request Timeout
///   * 409 — Conflict (transient concurrent-mutation case)
///   * 429 — Rate Limited
///   * 500 / 502 / 503 / 504 — server-side transient
///   * 529 — Anthropic-specific "service overloaded"
#[must_use]
pub const fn is_retryable_status(status: u16) -> bool {
    let Ok(status) = reqwest::StatusCode::from_u16(status) else {
        return false;
    };
    provider_transport::should_retry_status(status, RequestReplaySafety::Idempotent)
}

/// Transport-layer errors that warrant a retry.
///
/// The broad compatibility classifier is retained for idempotent operations.
/// Model POSTs use the stricter admission-only policy inside
/// [`send_with_retry`] so ambiguous mid-request disconnects are not replayed.
#[must_use]
pub fn is_transient_transport_error(err: &reqwest::Error) -> bool {
    provider_transport::should_retry_error(err, RequestReplaySafety::Idempotent)
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

/// Emit retry metadata without mixing it into model-authored stream content.
fn emit_api_retry(
    tx: &mpsc::Sender<AppEvent>,
    kind: ApiRetryKind,
    attempt: u32,
    wait: std::time::Duration,
    status: Option<u16>,
) {
    let delay_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
    let _ = tx.send(AppEvent::ApiRetry {
        kind,
        attempt,
        max_attempts: MAX_API_RETRIES + 1,
        delay_ms,
        status,
    });
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
#[allow(clippy::too_many_lines)] // Retry admission, diagnostics, and terminal response ownership form one transaction.
async fn send_with_retry(
    run: &tools::ToolRunContext,
    client: &reqwest::Client,
    endpoint: &str,
    headers: &crate::secrets::SensitiveHeaders,
    request_body: &Value,
    tx: &mpsc::Sender<AppEvent>,
) -> Result<reqwest::Response, String> {
    let deadline = tokio::time::Instant::now() + provider_transport::RETRY_WINDOW;
    let mut response = None;
    for attempt in 0..=MAX_API_RETRIES {
        let req = headers
            .apply(client.post(endpoint).json(request_body))
            .map_err(|error| error.to_string())?;
        if attempt > 0 {
            crate::provider_budget::record_provider_retry(run)
                .map_err(|error| format!("Run budget denied provider retry: {error}"))?;
        }

        let resp = match provider_transport::send_until(req, deadline).await {
            Ok(r) => r,
            Err(error)
                if attempt < MAX_API_RETRIES
                    && error.retryable(RequestReplaySafety::AdmissionOnly) =>
            {
                let wait = provider_transport::retry_delay(attempt, None);
                tracing::warn!(
                    target: "openclaudia::retry",
                    event = "api_retry",
                    kind = "transport",
                    attempt = attempt + 1,
                    max_attempts = MAX_API_RETRIES + 1,
                    wait_ms = wait.as_millis(),
                    error = %error,
                    "transient transport error, retrying"
                );
                emit_api_retry(tx, ApiRetryKind::Transport, attempt + 1, wait, None);
                if tokio::time::Instant::now() + wait >= deadline {
                    return Err(
                        "provider retry window exhausted before the next attempt".to_string()
                    );
                }
                tokio::time::sleep(wait).await;
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "Request failed: {}",
                    headers.sanitize_diagnostic(&error.to_string())
                ));
            }
        };
        let status = resp.status().as_u16();

        if provider_transport::should_retry_status(
            resp.status(),
            RequestReplaySafety::AdmissionOnly,
        ) && attempt < MAX_API_RETRIES
        {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let wait = provider_transport::retry_delay(attempt, retry_after.as_deref());
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
            emit_api_retry(tx, ApiRetryKind::Status, attempt + 1, wait, Some(status));
            if tokio::time::Instant::now() + wait >= deadline {
                return Err("provider retry window exhausted before the next attempt".to_string());
            }
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

fn trace_run_turn_request(endpoint: &str, request_body: &Value) {
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
            .is_some_and(|tools| !tools.is_empty()),
        "Sending API request"
    );
}

/// Run one turn of the conversation: send request, stream response, execute tools.
///
/// Sends `AppEvent` variants through `tx` as they occur so the TUI can update
/// in real time. Returns a `TurnResult` describing what happened.
///
/// # Errors
///
/// Returns `Err` if the HTTP request itself fails (network error, etc.).
#[allow(clippy::too_many_lines)] // One provider turn owns reservation, transport, response handling, and settlement.
pub async fn run_turn(p: RunTurnParams<'_>) -> Result<TurnResult, String> {
    let RunTurnParams {
        run_context,
        client,
        endpoint,
        headers,
        claude_agent_sdk,
        effort_level,
        request_body,
        provider,
        model_identity,
        provider_native_state,
        assistant_message_ordinal,
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
    let mut request_body = request_body.clone();
    let configured_max_output = app_config.as_ref().map_or(0, |config| {
        u64::from(config.session.token_tracking.max_output_tokens)
    });
    let provider_budget = crate::provider_budget::reserve_provider_call(
        &run_context,
        provider,
        model_identity,
        &mut request_body,
        configured_max_output,
    )
    .map_err(|error| format!("Run budget denied provider call: {error}"))?;
    if crate::codex_credentials::is_chatgpt_codex_endpoint(endpoint) {
        crate::codex_credentials::finalize_chatgpt_responses_request(&mut request_body);
    }
    trace_run_turn_request(endpoint, &request_body);

    if let Some(sdk) = claude_agent_sdk {
        let sdk_turn = match sdk.complete_turn(&request_body, effort_level).await {
            Ok(turn) => turn,
            Err(error) => {
                provider_budget.finish_unknown().map_err(|budget_error| {
                    format!(
                        "Claude Agent SDK request failed: {error}; budget reconciliation failed: {budget_error}"
                    )
                })?;
                return Err(format!("Claude Agent SDK request failed: {error}"));
            }
        };
        provider_budget
            .reconcile(&sdk_turn.usage)
            .map_err(|error| format!("Provider budget reconciliation failed: {error}"))?;
        if !sdk_turn.content.is_empty() {
            tx.send(AppEvent::StreamText(sdk_turn.content.clone()))
                .map_err(|_| {
                    "API event receiver closed during Claude Agent SDK turn".to_string()
                })?;
        }
        let terminal_outcome = if sdk_turn.tool_calls.is_empty() {
            ProviderTerminalOutcome::Completed
        } else {
            ProviderTerminalOutcome::ToolCalls
        };
        ensure_provider_turn_succeeded(terminal_outcome, sdk_turn.tool_calls.len())?;
        let (tool_results, needs_followup) = execute_tool_calls_for_tui(
            run_context,
            &sdk_turn.tool_calls,
            memory_db,
            app_config,
            permission_mgr,
            transient_allowed_tool_rules,
            hook_engine,
            policy_enforcer,
            task_mgr,
            session_id.as_deref(),
            model_identity,
            &tx,
        )
        .await;
        return Ok(TurnResult {
            content: sdk_turn.content,
            reasoning_content: None,
            tool_calls: sdk_turn.tool_calls,
            tool_results,
            usage: sdk_turn.usage,
            needs_followup,
            terminal_outcome,
            finish_reason: None,
            provider_native_state: None,
        });
    }

    let response =
        match send_with_retry(&run_context, client, endpoint, headers, &request_body, &tx).await {
            Ok(response) => response,
            Err(error) => {
                provider_budget.finish_unknown().map_err(|budget_error| {
                    format!("{error}; budget reconciliation failed: {budget_error}")
                })?;
                return Err(error);
            }
        };

    let result = if matches!(
        provider.trim().to_ascii_lowercase().as_str(),
        "google" | "gemini" | "ollama"
    ) {
        handle_provider_native_json_response(
            run_context,
            response,
            provider,
            provider_native_state,
            assistant_message_ordinal,
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
        .await
    } else if request_body.get("input").is_some() && request_body.get("messages").is_none() {
        stream_responses_sse_response(SseStreamParams {
            run_context,
            response,
            headers,
            provider,
            model_identity,
            provider_native_state,
            assistant_message_ordinal,
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
    } else {
        stream_sse_response(SseStreamParams {
            run_context,
            response,
            headers,
            provider,
            model_identity,
            provider_native_state,
            assistant_message_ordinal,
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
    };
    match result {
        Ok(turn) => {
            provider_budget
                .reconcile(&turn.usage)
                .map_err(|error| format!("Provider budget reconciliation failed: {error}"))?;
            Ok(turn)
        }
        Err(error) => {
            provider_budget.finish_unknown().map_err(|budget_error| {
                format!("{error}; budget reconciliation failed: {budget_error}")
            })?;
            Err(error)
        }
    }
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

#[cfg(test)]
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

#[cfg(test)]
fn extract_google_text(parts: &[Value]) -> Result<String, String> {
    crate::providers::extract_gemini_text_content(parts).map_err(|e| e.to_string())
}

/// Extract structured tool calls from a Gemini non-streaming response.
#[cfg(test)]
fn extract_google_tool_calls(gemini_json: &Value) -> Result<Vec<ToolCall>, String> {
    crate::providers::GeminiGenerateContentTurnOutput::new(gemini_json)
        .and_then(|output| output.tool_calls(0))
        .map_err(|error| error.to_string())
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

/// A completed native-JSON provider turn before frontend-owned effects run.
///
/// This deliberately omits `Debug`: the exact native state may include
/// provider-private reasoning material.
pub struct ProviderNativeJsonDecodedTurn {
    pub content: String,
    pub reasoning_content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
    pub terminal_outcome: ProviderTerminalOutcome,
    pub finish_reason: Option<String>,
    pub provider_native_state: crate::runtime::ProviderNativeState,
}

/// Decode and advance one complete Gemini `GenerateContent` or Ollama Chat JSON
/// response before any frontend dispatches its projected tool calls.
///
/// # Errors
///
/// Returns an error for upstream error envelopes, malformed/incomplete native
/// output, unsupported provider identity, or invalid continuation advancement.
// Keeping both native protocols in one match makes their terminal-state
// differences visible at the shared continuation boundary.
#[allow(clippy::too_many_lines)]
pub fn decode_provider_native_json_turn(
    provider: &str,
    model_identity: &str,
    response: &Value,
    previous_state: Option<&crate::runtime::ProviderNativeState>,
    assistant_message_ordinal: u64,
) -> Result<ProviderNativeJsonDecodedTurn, String> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "google" | "gemini" => {
            if let Some(error) = response.get("error") {
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .filter(|message| !message.is_empty())
                    .ok_or_else(|| "Gemini API error is missing a message".to_string())?;
                let code = error.get("code").and_then(Value::as_u64).unwrap_or(0);
                return Err(format!("Gemini API error ({code}): {message}"));
            }
            let output = crate::providers::GeminiGenerateContentTurnOutput::new(response)
                .map_err(|error| error.to_string())?;
            let content = output.text().map_err(|error| error.to_string())?;
            let tool_calls = output
                .tool_calls(assistant_message_ordinal)
                .map_err(|error| error.to_string())?;
            let provider_native_state = crate::providers::advance_gemini_generate_content_state(
                provider,
                model_identity,
                previous_state,
                assistant_message_ordinal,
                &output,
            )
            .map_err(|error| error.to_string())?;
            let classification = classify_google_finish_reason(response, content.len());
            let finish_reason = classification.finish_reason.as_deref().ok_or_else(|| {
                "Gemini response is missing candidates[0].finishReason".to_string()
            })?;
            let mut terminal_outcome = classify_provider_finish_reason(finish_reason, false)?;
            if terminal_outcome == ProviderTerminalOutcome::Completed && !tool_calls.is_empty() {
                terminal_outcome = ProviderTerminalOutcome::ToolCalls;
            }
            let (input_tokens, output_tokens) = extract_google_usage(response);
            Ok(ProviderNativeJsonDecodedTurn {
                content,
                reasoning_content: None,
                tool_calls,
                usage: TokenUsage {
                    input_tokens,
                    output_tokens,
                    cache_read_tokens: 0,
                    cache_write_tokens: 0,
                },
                terminal_outcome,
                finish_reason: classification.finish_reason,
                provider_native_state,
            })
        }
        "ollama" => {
            if let Some(error) = response.get("error") {
                let message = error
                    .as_str()
                    .or_else(|| error.get("message").and_then(Value::as_str))
                    .filter(|message| !message.is_empty())
                    .ok_or_else(|| "Ollama API error is missing a message".to_string())?;
                return Err(format!("Ollama API error: {message}"));
            }
            let output = crate::providers::OllamaChatTurnOutput::new(response)
                .map_err(|error| error.to_string())?;
            if !output.done() {
                return Err("Ollama response ended before done=true".to_string());
            }
            let tool_calls = output
                .tool_calls(assistant_message_ordinal)
                .map_err(|error| error.to_string())?;
            let provider_native_state = crate::providers::advance_ollama_chat_state(
                provider,
                model_identity,
                previous_state,
                assistant_message_ordinal,
                &output,
            )
            .map_err(|error| error.to_string())?;
            let finish_reason = if tool_calls.is_empty() {
                Some(
                    response
                        .get("done_reason")
                        .and_then(Value::as_str)
                        .filter(|reason| !reason.is_empty())
                        .unwrap_or("stop")
                        .to_string(),
                )
            } else {
                Some("tool_calls".to_string())
            };
            let terminal_outcome = if tool_calls.is_empty() {
                classify_provider_finish_reason(finish_reason.as_deref().unwrap_or("stop"), false)?
            } else {
                ProviderTerminalOutcome::ToolCalls
            };
            Ok(ProviderNativeJsonDecodedTurn {
                content: output.text().to_string(),
                reasoning_content: None,
                tool_calls,
                usage: TokenUsage {
                    input_tokens: response
                        .get("prompt_eval_count")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    output_tokens: response
                        .get("eval_count")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    cache_read_tokens: 0,
                    cache_write_tokens: 0,
                },
                terminal_outcome,
                finish_reason,
                provider_native_state,
            })
        }
        other => Err(format!(
            "provider {other:?} does not use the canonical native JSON decoder"
        )),
    }
}

/// Handle a non-streaming provider-native JSON response.
#[allow(clippy::too_many_arguments)]
async fn handle_provider_native_json_response(
    run_context: Arc<tools::ToolRunContext>,
    response: reqwest::Response,
    provider: &str,
    previous_state: Option<&crate::runtime::ProviderNativeState>,
    assistant_message_ordinal: u64,
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
    let native_json: Value =
        provider_transport::read_json_capped(response, provider_transport::MAX_JSON_RESPONSE_BYTES)
            .await
            .map_err(|error| format!("Failed to parse {provider} JSON response: {error}"))?;
    let decoded = decode_provider_native_json_turn(
        provider,
        model_identity,
        &native_json,
        previous_state,
        assistant_message_ordinal,
    )
    .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;

    if matches!(
        provider.trim().to_ascii_lowercase().as_str(),
        "google" | "gemini"
    ) {
        if let Some(message) =
            classify_google_finish_reason(&native_json, decoded.content.len()).user_error
        {
            send_event!(
                tx,
                AppEvent::ApiError(headers.sanitize_diagnostic(&message))
            );
        }
    }
    if !decoded.content.is_empty() {
        send_event!(tx, AppEvent::StreamText(decoded.content.clone()));
    }

    let ProviderNativeJsonDecodedTurn {
        content,
        reasoning_content,
        tool_calls,
        usage,
        terminal_outcome,
        finish_reason,
        provider_native_state,
    } = decoded;

    ensure_provider_turn_succeeded(terminal_outcome, tool_calls.len())?;

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

    Ok(TurnResult {
        content,
        reasoning_content,
        tool_calls,
        tool_results,
        usage,
        needs_followup,
        terminal_outcome,
        finish_reason,
        provider_native_state: Some(provider_native_state),
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
    provider_native_state: Option<&'a crate::runtime::ProviderNativeState>,
    assistant_message_ordinal: u64,
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

// Streaming, terminal validation, and provisional rendering share one ordered
// state machine; extracting a phase would obscure the commit boundary.
#[allow(clippy::too_many_lines)]
async fn stream_sse_response(p: SseStreamParams<'_>) -> Result<TurnResult, String> {
    let SseStreamParams {
        run_context,
        response,
        headers,
        provider,
        model_identity,
        provider_native_state: _,
        assistant_message_ordinal: _,
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
    let mut stream = provider_transport::bounded_byte_stream(
        response,
        provider_transport::MAX_STREAM_RESPONSE_BYTES,
    )
    .eventsource();
    let mut full_content = String::new();
    let mut reasoning_content = String::new();
    let mut tool_accumulator = ToolCallAccumulator::new();
    let mut anthropic_accumulator = AnthropicToolAccumulator::new();
    let mut stream_usage = TokenUsage::default();
    let mut terminal = ChatStreamTerminal::new(provider);
    let mut in_thinking_block = false;
    let mut last_data_time = std::time::Instant::now();
    let stream_timeout = std::time::Duration::from_secs(proxy::SSE_STREAM_TIMEOUT_SECS);

    loop {
        let sse = match tokio::time::timeout(stream_timeout, stream.next()).await {
            Ok(Some(Ok(sse))) => sse,
            Ok(Some(Err(e))) => {
                let message = format!("Stream error: {e}");
                send_event!(tx, AppEvent::ApiError(message.clone().into()));
                return Err(message);
            }
            Ok(None) => break,
            Err(_) => {
                handle_sse_timeout(last_data_time.elapsed().as_secs(), full_content.len(), tx)?;
                return Err(format!(
                    "Provider stream timed out after {} seconds",
                    proxy::SSE_STREAM_TIMEOUT_SECS
                ));
            }
        };

        last_data_time = std::time::Instant::now();
        if sse.data == "[DONE]" {
            terminal.observe_done();
            break;
        }
        let json = serde_json::from_str::<Value>(&sse.data).map_err(|error| {
            headers
                .sanitize_diagnostic(&format!("Malformed provider SSE event: {error}"))
                .to_string()
        })?;
        terminal
            .observe(&json)
            .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;
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

    let terminal_outcome = terminal
        .finish()
        .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;

    finalize_sse_stream(SseFinalize {
        run_context,
        provider,
        model_identity,
        full_content,
        reasoning_content,
        tool_accumulator,
        anthropic_accumulator,
        terminal_outcome,
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
    terminal_outcome: ProviderTerminalOutcome,
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

/// Drain the streaming accumulators into a `TurnResult` and dispatch any
/// captured tool calls. The frontend orchestrator emits its terminal event
/// only after it has committed the returned portable/native session state.
async fn finalize_sse_stream(f: SseFinalize<'_>) -> Result<TurnResult, String> {
    // Determine tool calls from the appropriate accumulator
    let tool_calls = if f.provider == "anthropic" && f.anthropic_accumulator.has_tool_use() {
        f.anthropic_accumulator.finalize_tool_calls_checked()?
    } else if f.tool_accumulator.has_tool_calls() {
        f.tool_accumulator.finalize_checked()?
    } else if f.provider == "anthropic" {
        f.anthropic_accumulator.finalize_tool_calls_checked()?
    } else if !f.tool_accumulator.tool_calls.is_empty() {
        f.tool_accumulator.finalize_checked()?
    } else {
        vec![]
    };
    ensure_provider_turn_succeeded(f.terminal_outcome, tool_calls.len())?;

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

    Ok(TurnResult {
        content: f.full_content,
        reasoning_content: (!f.reasoning_content.is_empty()).then_some(f.reasoning_content),
        tool_calls,
        tool_results,
        usage: f.stream_usage,
        needs_followup: has_tools,
        terminal_outcome: f.terminal_outcome,
        // The typed terminal outcome above carries the normalized state.
        // This legacy string field remains `None` for Anthropic/OpenAI SSE;
        // only the native JSON path populates it today (crosslink #788).
        finish_reason: None,
        provider_native_state: None,
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

enum ResponsesSseAction {
    Text(String),
    Reasoning(String),
    Created(String),
    OutputItem(Value),
    Completed {
        response_id: String,
        output_items: Option<Vec<Value>>,
        usage: Option<TokenUsage>,
    },
    Error(String),
    None,
}

#[derive(Default)]
struct ResponsesStreamCapture {
    response_id: Option<String>,
    output_items: Vec<Value>,
    output_bytes: usize,
    completed: bool,
}

impl ResponsesStreamCapture {
    fn observe_response_id(&mut self, response_id: String) -> Result<(), String> {
        if response_id.is_empty() {
            return Err("Responses stream emitted an empty response id".to_string());
        }
        if self
            .response_id
            .as_ref()
            .is_some_and(|current| current != &response_id)
        {
            return Err(format!(
                "Responses stream changed response id from {:?} to {response_id:?}",
                self.response_id.as_deref().unwrap_or_default()
            ));
        }
        self.response_id = Some(response_id);
        Ok(())
    }

    fn observe_output_item(&mut self, item: Value) -> Result<(), String> {
        if self.output_items.len() >= crate::runtime::MAX_PROVIDER_NATIVE_ITEMS.saturating_sub(1) {
            return Err(format!(
                "Responses turn exceeds {} native output items",
                crate::runtime::MAX_PROVIDER_NATIVE_ITEMS.saturating_sub(1)
            ));
        }
        let bytes = serde_json::to_vec(&item)
            .map_err(|error| format!("could not size Responses output item: {error}"))?
            .len();
        if bytes > crate::runtime::MAX_PROVIDER_NATIVE_ITEM_BYTES {
            return Err(format!(
                "Responses output item is {bytes} bytes; maximum is {}",
                crate::runtime::MAX_PROVIDER_NATIVE_ITEM_BYTES
            ));
        }
        self.output_bytes = self
            .output_bytes
            .checked_add(bytes)
            .ok_or_else(|| "Responses output byte count overflow".to_string())?;
        if self.output_bytes > crate::runtime::MAX_PROVIDER_NATIVE_STATE_BYTES {
            return Err(format!(
                "Responses output items exceed {} bytes",
                crate::runtime::MAX_PROVIDER_NATIVE_STATE_BYTES
            ));
        }
        self.output_items.push(item);
        Ok(())
    }

    fn replace_completed_output(&mut self, output_items: Vec<Value>) -> Result<(), String> {
        self.output_items.clear();
        self.output_bytes = 0;
        for item in output_items {
            self.observe_output_item(item)?;
        }
        Ok(())
    }
}

fn parse_responses_usage(response: &Value) -> Option<TokenUsage> {
    let usage = response.get("usage")?;
    let raw_input_tokens = usage
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
    let cache_write_tokens = usage
        .get("input_tokens_details")
        .and_then(|details| details.get("cache_write_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if raw_input_tokens == 0
        && output_tokens == 0
        && cache_read_tokens == 0
        && cache_write_tokens == 0
    {
        return None;
    }
    Some(TokenUsage {
        // Responses reports cache reads/writes as a breakdown of its inclusive
        // input total. Keep TokenUsage's buckets disjoint for cost accounting.
        input_tokens: raw_input_tokens
            .saturating_sub(cache_read_tokens)
            .saturating_sub(cache_write_tokens),
        output_tokens,
        cache_read_tokens,
        cache_write_tokens,
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
        .ok_or_else(|| "Responses function_call missing string arguments".to_string())?;
    Ok(Some(ToolCall {
        id: call_id.to_string(),
        call_type: "function".to_string(),
        function: tools::FunctionCall {
            name: name.to_string(),
            arguments: arguments.to_string(),
        },
    }))
}

fn responses_visible_output_text(output_items: &[Value]) -> Result<String, String> {
    let mut text = String::new();
    for (item_index, item) in output_items.iter().enumerate() {
        if item.get("type").and_then(Value::as_str) != Some("message") {
            continue;
        }
        let content = item
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                format!("Responses message output item {item_index} is missing content array")
            })?;
        for (content_index, part) in content.iter().enumerate() {
            if part.get("type").and_then(Value::as_str) != Some("output_text") {
                continue;
            }
            let part_text = part.get("text").and_then(Value::as_str).ok_or_else(|| {
                format!(
                    "Responses output_text part {content_index} in item {item_index} is missing text"
                )
            })?;
            text.push_str(part_text);
        }
    }
    Ok(text)
}

fn responses_contains_refusal(output_items: &[Value]) -> Result<bool, String> {
    for (item_index, item) in output_items.iter().enumerate() {
        if item.get("type").and_then(Value::as_str) != Some("message") {
            continue;
        }
        let content = item
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                format!("Responses message output item {item_index} is missing content array")
            })?;
        if content.iter().any(|part| {
            part.get("type").and_then(Value::as_str) == Some("refusal")
                && part
                    .get("refusal")
                    .and_then(Value::as_str)
                    .is_some_and(|refusal| !refusal.is_empty())
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Validate the terminal state of a complete, non-streaming Responses object.
///
/// # Errors
///
/// Returns an error when `status` is not `completed`, output is malformed, or
/// the response represents refusal rather than a successful terminal turn.
pub fn validate_openai_responses_terminal_json(
    response: &Value,
) -> Result<ProviderTerminalOutcome, String> {
    if response.get("status").and_then(Value::as_str) != Some("completed") {
        return Err(format!(
            "Responses request did not complete successfully (status={:?})",
            response.get("status").and_then(Value::as_str)
        ));
    }
    let output_items = response
        .get("output")
        .and_then(Value::as_array)
        .ok_or_else(|| "Responses completed response is missing output array".to_string())?;
    let refusal_observed = responses_contains_refusal(output_items)?;
    let mut tool_call_count = 0_usize;
    for item in output_items {
        if parse_responses_function_call(item)?.is_some() {
            tool_call_count = tool_call_count.saturating_add(1);
        }
    }
    let outcome = if refusal_observed {
        ProviderTerminalOutcome::Refused
    } else if tool_call_count > 0 {
        ProviderTerminalOutcome::ToolCalls
    } else {
        ProviderTerminalOutcome::Completed
    };
    ensure_provider_turn_succeeded(outcome, tool_call_count)?;
    Ok(outcome)
}

fn process_responses_sse_event(json: &Value) -> Result<ResponsesSseAction, String> {
    match json.get("type").and_then(Value::as_str).unwrap_or_default() {
        "response.created" => {
            let response_id = json
                .get("response")
                .and_then(|response| response.get("id"))
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| "Responses response.created is missing response.id".to_string())?;
            Ok(ResponsesSseAction::Created(response_id.to_string()))
        }
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
            let item = json
                .get("item")
                .filter(|item| item.is_object())
                .cloned()
                .ok_or_else(|| {
                    "Responses response.output_item.done is missing an item object".to_string()
                })?;
            Ok(ResponsesSseAction::OutputItem(item))
        }
        "response.completed" => {
            let response = json
                .get("response")
                .filter(|response| response.is_object())
                .ok_or_else(|| "Responses response.completed is missing response".to_string())?;
            if response.get("status").and_then(Value::as_str) != Some("completed") {
                return Err(
                    "Responses response.completed did not carry status=completed".to_string(),
                );
            }
            let response_id = response
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| "Responses response.completed is missing response.id".to_string())?;
            let output_items = match response.get("output") {
                None | Some(Value::Null) => None,
                Some(Value::Array(output)) => Some(output.clone()),
                Some(_) => {
                    return Err("Responses completed output must be an array or null".to_string());
                }
            };
            Ok(ResponsesSseAction::Completed {
                response_id: response_id.to_string(),
                output_items,
                usage: parse_responses_usage(response),
            })
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
    capture: &mut ResponsesStreamCapture,
    usage: &mut TokenUsage,
    on_text: &mut impl FnMut(&str) -> Result<(), String>,
    on_reasoning: &mut impl FnMut(&str) -> Result<(), String>,
) -> Result<bool, String> {
    match action {
        ResponsesSseAction::Text(text) => {
            on_text(&text)?;
            full_content.push_str(&text);
        }
        ResponsesSseAction::Reasoning(text) => {
            let display_text = merge_reasoning_delta(reasoning_content, &text);
            if !display_text.is_empty() {
                on_reasoning(&display_text)?;
            }
        }
        ResponsesSseAction::Created(response_id) => capture.observe_response_id(response_id)?,
        ResponsesSseAction::OutputItem(item) => capture.observe_output_item(item)?,
        ResponsesSseAction::Completed {
            response_id,
            output_items,
            usage: observed_usage,
        } => {
            capture.observe_response_id(response_id)?;
            if let Some(output_items) = output_items {
                // The account-backed Codex API can omit fields from the
                // completed envelope that were present in output_item.done.
                // Codex itself treats the done events as authoritative. Keep
                // the completed output only as a compatibility fallback for
                // providers that do not emit per-item events.
                if capture.output_items.is_empty() {
                    capture.replace_completed_output(output_items)?;
                }
            }
            if let Some(observed) = observed_usage {
                usage.accumulate(&observed);
            }
            capture.completed = true;
            return Ok(true);
        }
        ResponsesSseAction::Error(message) => return Err(message),
        ResponsesSseAction::None => {}
    }
    Ok(false)
}

fn finalize_responses_capture(
    capture: ResponsesStreamCapture,
    provider: &str,
    model_identity: &str,
    provider_native_state: Option<&crate::runtime::ProviderNativeState>,
    assistant_message_ordinal: u64,
) -> Result<
    (
        crate::runtime::ProviderNativeState,
        Vec<ToolCall>,
        ProviderTerminalOutcome,
    ),
    String,
> {
    if !capture.completed {
        return Err("Responses stream ended before response.completed".to_string());
    }
    let response_id = capture
        .response_id
        .ok_or_else(|| "Responses completed without a response id".to_string())?;
    let refusal_observed = responses_contains_refusal(&capture.output_items)?;
    let provider_output =
        crate::providers::OpenAiResponsesTurnOutput::new(response_id, capture.output_items)?;
    let next_provider_state = crate::providers::advance_openai_responses_state(
        provider,
        model_identity,
        provider_native_state,
        assistant_message_ordinal,
        &provider_output,
    )
    .map_err(|error| error.to_string())?;
    let mut tool_calls = Vec::new();
    let mut call_ids = std::collections::BTreeSet::new();
    for item in provider_output.output_items() {
        if let Some(call) = parse_responses_function_call(item)? {
            if !call_ids.insert(call.id.clone()) {
                return Err(format!(
                    "Responses completion repeated function call id {:?}",
                    call.id
                ));
            }
            tool_calls.push(call);
        }
    }
    let terminal_outcome = if refusal_observed {
        ProviderTerminalOutcome::Refused
    } else if tool_calls.is_empty() {
        ProviderTerminalOutcome::Completed
    } else {
        ProviderTerminalOutcome::ToolCalls
    };
    Ok((next_provider_state, tool_calls, terminal_outcome))
}

/// Inputs for the shared bounded `OpenAI` Responses stream decoder.
///
/// Frontends own rendering and tool execution. The decoder owns provider
/// terminal validation, exact output capture, tool-call parsing, and native
/// continuation advancement so those semantics cannot drift between the TUI,
/// print mode, ACP, and child runs.
pub struct OpenAiResponsesStreamParams<'a> {
    pub response: reqwest::Response,
    pub headers: &'a crate::secrets::SensitiveHeaders,
    pub provider: &'a str,
    pub model_identity: &'a str,
    pub provider_native_state: Option<&'a crate::runtime::ProviderNativeState>,
    pub assistant_message_ordinal: u64,
}

/// A completed, terminal-validated `OpenAI` Responses turn before frontend-owned
/// tool effects are dispatched.
///
/// Deliberately does not implement `Debug`: reasoning text and the native state
/// can contain protected provider material.
pub struct OpenAiResponsesDecodedTurn {
    pub content: String,
    pub reasoning_content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
    pub terminal_outcome: ProviderTerminalOutcome,
    pub provider_native_state: crate::runtime::ProviderNativeState,
}

/// Decode one `OpenAI` Responses SSE stream through the canonical bounded state
/// machine and advance its stateless continuation.
///
/// The callbacks receive provisional display deltas only. A successful return
/// means a matching `response.completed` event was observed and all exact
/// provider output was validated and committed into the returned native state.
/// Callers must append the corresponding portable assistant projection before
/// dispatching any returned tool call.
///
/// # Errors
///
/// Returns an error for transport/timeout/parse failures, incomplete or failed
/// terminal events, inconsistent response identity/output, malformed tool calls,
/// or invalid continuation state.
pub async fn decode_openai_responses_stream(
    p: OpenAiResponsesStreamParams<'_>,
    mut on_text: impl FnMut(&str) -> Result<(), String>,
    mut on_reasoning: impl FnMut(&str) -> Result<(), String>,
    mut on_timeout: impl FnMut(u64, usize) -> Result<(), String>,
) -> Result<OpenAiResponsesDecodedTurn, String> {
    let OpenAiResponsesStreamParams {
        response,
        headers,
        provider,
        model_identity,
        provider_native_state,
        assistant_message_ordinal,
    } = p;
    let mut stream = provider_transport::bounded_byte_stream(
        response,
        provider_transport::MAX_STREAM_RESPONSE_BYTES,
    )
    .eventsource();
    let mut full_content = String::new();
    let mut reasoning_content = String::new();
    let mut capture = ResponsesStreamCapture::default();
    let mut stream_usage = TokenUsage::default();
    let mut last_data_time = std::time::Instant::now();
    let stream_timeout = std::time::Duration::from_secs(proxy::SSE_STREAM_TIMEOUT_SECS);

    loop {
        let sse = match tokio::time::timeout(stream_timeout, stream.next()).await {
            Ok(Some(Ok(sse))) => sse,
            Ok(Some(Err(e))) => {
                return Err(headers
                    .sanitize_diagnostic(&format!("Responses stream error: {e}"))
                    .to_string());
            }
            Ok(None) => break,
            Err(_) => {
                let elapsed = last_data_time.elapsed().as_secs();
                on_timeout(elapsed, full_content.len())?;
                return Err("Responses stream timed out before response.completed".to_string());
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
            &mut capture,
            &mut stream_usage,
            &mut on_text,
            &mut on_reasoning,
        )
        .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;
        if done {
            break;
        }
    }

    if !capture.completed {
        return Err("Responses stream ended before response.completed".to_string());
    }
    let terminal_text = responses_visible_output_text(&capture.output_items)
        .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;
    if full_content.is_empty() && !terminal_text.is_empty() {
        on_text(&terminal_text)?;
        full_content = terminal_text;
    } else if terminal_text != full_content {
        return Err(
            "Responses terminal output text disagrees with streamed output_text deltas".to_string(),
        );
    }

    let (next_provider_state, tool_calls, terminal_outcome) = finalize_responses_capture(
        capture,
        provider,
        model_identity,
        provider_native_state,
        assistant_message_ordinal,
    )
    .map_err(|error| headers.sanitize_diagnostic(&error).to_string())?;

    Ok(OpenAiResponsesDecodedTurn {
        content: full_content,
        reasoning_content: (!reasoning_content.is_empty()).then_some(reasoning_content),
        tool_calls,
        usage: stream_usage,
        terminal_outcome,
        provider_native_state: next_provider_state,
    })
}

async fn stream_responses_sse_response(p: SseStreamParams<'_>) -> Result<TurnResult, String> {
    let SseStreamParams {
        run_context,
        response,
        headers,
        provider,
        model_identity,
        provider_native_state,
        assistant_message_ordinal,
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
    let decoded = decode_openai_responses_stream(
        OpenAiResponsesStreamParams {
            response,
            headers,
            provider,
            model_identity,
            provider_native_state,
            assistant_message_ordinal,
        },
        |text| {
            send_event!(tx, AppEvent::StreamText(text.to_string()));
            Ok(())
        },
        |reasoning| {
            send_event!(tx, AppEvent::StreamThinking(reasoning.to_string()));
            Ok(())
        },
        |elapsed_secs, content_bytes| {
            tracing::error!(
                target: "openclaudia::stream",
                event = "sse_stream_timeout",
                kind = "result",
                is_error = true,
                elapsed_secs,
                timeout_secs = proxy::SSE_STREAM_TIMEOUT_SECS,
                content_so_far_bytes = content_bytes,
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
        },
    )
    .await?;

    let OpenAiResponsesDecodedTurn {
        content,
        reasoning_content,
        tool_calls,
        usage,
        terminal_outcome,
        provider_native_state: next_provider_state,
    } = decoded;

    ensure_provider_turn_succeeded(terminal_outcome, tool_calls.len())?;

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
    Ok(TurnResult {
        content,
        reasoning_content,
        tool_calls,
        tool_results,
        usage,
        needs_followup,
        terminal_outcome,
        finish_reason: None,
        provider_native_state: Some(next_provider_state),
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

const fn tool_result_completed_successfully(result: &tools::ToolResult) -> bool {
    !result.is_error() && !result.is_partial()
}

/// Execute one tool call through its canonical sync or async dispatcher, fire
/// the matching post-tool hook, and retain the typed provider result.
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
    let result = if tool_name.starts_with("mcp__") {
        crate::services::tool_executor::ToolExecutor::execute_mcp(
            crate::services::tool_executor::ToolExecutorRequest {
                run_context: &run_context,
                tool_call,
                memory_db: memory_db.as_deref(),
                app_config: app_config.as_deref(),
                task_mgr: None,
                permission_mgr: perm_mgr.as_ref(),
                authorization: permission.authorization,
                session_id,
                policy_enforcer: policy_enforcer.as_deref(),
            },
        )
        .await
    } else {
        let tool_call_clone = tool_call.clone();
        let panic_tool_call = tool_call.clone();
        let session_for_blocking = session_id.map(str::to_string);
        let run_context_for_blocking = Arc::clone(&run_context);
        let uses_task_graph = tools::uses_canonical_task_graph(tool_name);
        tokio::task::spawn_blocking(move || {
            let execute = |task_mgr: Option<&mut crate::session::TaskManager>| {
                crate::services::tool_executor::ToolExecutor::execute(
                    crate::services::tool_executor::ToolExecutorRequest {
                        run_context: &run_context_for_blocking,
                        tool_call: &tool_call_clone,
                        memory_db: memory_db.as_deref(),
                        app_config: app_config.as_deref(),
                        task_mgr,
                        permission_mgr: perm_mgr.as_ref(),
                        authorization: permission.authorization,
                        session_id: session_for_blocking.as_deref(),
                        policy_enforcer: policy_enforcer.as_deref(),
                    },
                )
            };
            if uses_task_graph {
                // The lock is acquired on the blocking worker only for handlers
                // that consume task state. Unrelated file/process/network tools
                // remain independent of planning persistence.
                let mut task_guard = task_mgr
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                execute(Some(&mut task_guard))
            } else {
                execute(None)
            }
        })
        .await
        .unwrap_or_else(|e| {
            tools::ToolResult::failure(
                &panic_tool_call,
                tools::ToolFailureCode::Internal,
                format!("Tool execution panicked: {e}"),
                tools::ToolRetryability::Never,
            )
        })
    };
    let completed_successfully = tool_result_completed_successfully(&result);
    if tx
        .send(AppEvent::ToolDone {
            name: tool_name.clone(),
            success: completed_successfully,
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
            completed_successfully,
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
) -> Option<Value> {
    let report = crate::guardrails::run_quality_gates_at(
        run_context,
        model_identity,
        crate::config::RunAfter::EveryTurn,
    )?;
    if report.disposition() == crate::guardrails::QualityGateDisposition::Skipped {
        return None;
    }
    let mut findings = Vec::new();
    for gate in report.results() {
        record_quality_gate_verification(run_context, session_id, gate);
        if gate.passed() {
            continue;
        }
        findings.push(format!("{} ({:?})", gate.name(), gate.status()));
        if tx.send(failed_quality_gate_event(gate)).is_err() {
            tracing::warn!("TUI channel closed during tool execution");
            break;
        }
    }
    if findings.is_empty()
        || !matches!(
            report.disposition(),
            crate::guardrails::QualityGateDisposition::Findings
                | crate::guardrails::QualityGateDisposition::Blocked
        )
    {
        return None;
    }
    Some(serde_json::json!({
        "role": "system",
        "content": format!(
            "Configured quality-gate findings must be addressed before finalization: {}",
            findings.join(", ")
        ),
        "metadata": {
            "openclaudia_context_source": "reality"
        }
    }))
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

        if let Err(reason) = run_context.admit_runtime_mode_tool(tool_name, &tool_args) {
            let result = tools::ToolResult::failure(
                tool_call,
                tools::ToolFailureCode::PolicyDenied,
                reason,
                tools::ToolRetryability::Never,
            );
            send_event_or_break!(
                tx,
                AppEvent::ToolDone {
                    name: tool_name.clone(),
                    success: false,
                    content: result.content().to_string(),
                }
            );
            observe_tool_result(&run_context, session_id, &result);
            results.push(result.openai_message());
            continue;
        }

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
                let Ok(approved_plan_context) = resolve_tui_follow_up(&mut result, tx).await else {
                    break;
                };
                observe_tool_result(&run_context, session_id, &result);
                results.push(result.openai_message());
                if let Some(context) = approved_plan_context {
                    results.push(context);
                }
            }
        }
    }

    if let Some(finding) =
        emit_failed_quality_gate_events(&run_context, tx, session_id, model_identity)
    {
        results.push(finding);
    }

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
) -> Result<Option<Value>, ()> {
    let follow_up = result.follow_up().clone();
    let questions = match follow_up {
        tools::ToolFollowUp::None => return Ok(None),
        tools::ToolFollowUp::UserQuestion { questions, .. } => questions,
        tools::ToolFollowUp::EnterPlanMode { .. } => {
            return resolve_tui_plan_follow_up(result, PlanModeRequest::Enter, tx).await;
        }
        tools::ToolFollowUp::ExitPlanMode {
            allowed_prompts, ..
        } => {
            return resolve_tui_plan_follow_up(
                result,
                PlanModeRequest::Exit { allowed_prompts },
                tx,
            )
            .await;
        }
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
    Ok(None)
}

async fn resolve_tui_plan_follow_up(
    result: &mut tools::ToolResult,
    request: PlanModeRequest,
    tx: &mpsc::Sender<AppEvent>,
) -> Result<Option<Value>, ()> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if tx
        .send(AppEvent::PlanModeRequest {
            request,
            reply: reply_tx,
        })
        .is_err()
    {
        return Err(());
    }
    let reply = reply_rx.await.unwrap_or_else(|_| PlanModeReply::Cancelled {
        message: "Plan-mode request cancelled because the TUI closed".to_string(),
    });
    let context_message = match reply {
        PlanModeReply::Completed {
            message,
            response,
            context_message,
        } => {
            *result = result
                .resolve_follow_up(message, response)
                .expect("typed plan follow-up has one pending host action");
            context_message
        }
        PlanModeReply::Cancelled { message } => {
            *result = result
                .cancel_follow_up(message.clone(), message)
                .expect("typed plan follow-up has one pending host action");
            None
        }
    };
    Ok(context_message)
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
    use crate::runtime::{
        ContinuationGeneration, ProviderNativeItem, ProviderNativeItemPurpose, ProviderNativeState,
        ProviderStateFacet, ProviderWireProtocol,
    };

    fn pipeline_native_state(
        provider: &str,
        model: &str,
        protocol: ProviderWireProtocol,
        facet: ProviderStateFacet,
        purpose: ProviderNativeItemPurpose,
    ) -> ProviderNativeState {
        ProviderNativeState::new(
            provider,
            model,
            protocol,
            ContinuationGeneration::new(1).expect("non-zero generation"),
            vec![
                ProviderNativeItem::new(facet, purpose, serde_json::json!({"opaque": "native"}))
                    .expect("valid native item"),
            ],
        )
        .expect("valid native state")
    }

    #[test]
    fn provider_request_state_seam_retains_evidence_outside_prompt() {
        let messages = [serde_json::json!({"role": "user", "content": "hello"})];
        let state = pipeline_native_state(
            "openai",
            "gpt-test",
            ProviderWireProtocol::OpenAiChatCompletions,
            ProviderStateFacet::Usage,
            ProviderNativeItemPurpose::Evidence,
        );
        let body = build_request_for_wire_with_tools(
            WireApi::ChatCompletions,
            "openai",
            "gpt-test",
            &messages,
            "medium",
            None,
            None,
            &serde_json::json!([]),
            Some(&state),
        )
        .expect("evidence-only state is retained outside provider input");
        assert_eq!(body["messages"][0]["content"], "hello");
        assert!(!body.to_string().contains("native"));
    }

    #[test]
    fn provider_request_state_seam_rejects_lossy_or_mismatched_resume() {
        let messages = [serde_json::json!({"role": "user", "content": "hello"})];
        let continuation = pipeline_native_state(
            "openai",
            "gpt-test",
            ProviderWireProtocol::OpenAiChatCompletions,
            ProviderStateFacet::ServerContinuation,
            ProviderNativeItemPurpose::Continuation,
        );
        let build = |provider: &str, model: &str, state: &ProviderNativeState| {
            build_request_for_wire_with_tools(
                WireApi::ChatCompletions,
                provider,
                model,
                &messages,
                "medium",
                None,
                None,
                &serde_json::json!([]),
                Some(state),
            )
        };
        assert!(build("openai", "gpt-test", &continuation)
            .expect_err("unwired continuation must fail")
            .contains("not wired yet"));
        assert!(build("openai", "gpt-other", &continuation)
            .expect_err("model mismatch must fail")
            .contains("belongs to model"));
        assert!(build("anthropic", "gpt-test", &continuation)
            .expect_err("provider mismatch must fail")
            .contains("belongs to provider"));
    }

    fn test_run() -> Arc<tools::ToolRunContext> {
        Arc::clone(tools::security::test_run_context())
    }

    #[tokio::test]
    async fn tui_plan_follow_up_uses_typed_host_reply_and_returns_approved_context() {
        let tool_call = ToolCall {
            id: "plan-enter".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "enter_plan_mode".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let result = tools::ToolResult::bind(
            &tool_call,
            "enter_plan_mode",
            tools::ToolHandlerResult::success_text("Plan mode entry requested".to_string())
                .with_follow_up(tools::ToolFollowUp::EnterPlanMode {
                    state: tools::ToolFollowUpState::Pending,
                }),
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let resolver = tokio::spawn(async move {
            let mut result = result;
            let context = resolve_tui_follow_up(&mut result, &tx)
                .await
                .expect("TUI channel");
            (result, context)
        });

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match rx.try_recv() {
                    Ok(event) => break event,
                    Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        panic!("resolver disconnected before sending plan request")
                    }
                }
            }
        })
        .await
        .expect("typed plan request");
        let AppEvent::PlanModeRequest { request, reply } = event else {
            panic!("expected typed plan request");
        };
        assert_eq!(request, PlanModeRequest::Enter);
        let context = serde_json::json!({
            "role": "system",
            "content": "approved context"
        });
        reply
            .send(PlanModeReply::Completed {
                message: "entered".to_string(),
                response: serde_json::json!({"entered": true}),
                context_message: Some(context.clone()),
            })
            .expect("resolver still waiting");

        let (result, returned_context) = resolver.await.expect("resolver task");
        assert_eq!(returned_context, Some(context));
        assert!(matches!(
            result.follow_up(),
            tools::ToolFollowUp::EnterPlanMode {
                state: tools::ToolFollowUpState::Resolved { response }
            } if response["entered"] == true
        ));
    }

    #[tokio::test]
    async fn tui_plan_follow_up_cancellation_is_reported_as_cancelled_tool_state() {
        let tool_call = ToolCall {
            id: "plan-exit".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "exit_plan_mode".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let result = tools::ToolResult::bind(
            &tool_call,
            "exit_plan_mode",
            tools::ToolHandlerResult::success_text("Plan mode exit requested".to_string())
                .with_follow_up(tools::ToolFollowUp::ExitPlanMode {
                    allowed_prompts: Vec::new(),
                    state: tools::ToolFollowUpState::Pending,
                }),
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let resolver = tokio::spawn(async move {
            let mut result = result;
            let context = resolve_tui_follow_up(&mut result, &tx)
                .await
                .expect("TUI channel");
            (result, context)
        });
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match rx.try_recv() {
                    Ok(event) => break event,
                    Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        panic!("resolver disconnected before sending plan request")
                    }
                }
            }
        })
        .await
        .expect("typed plan request");
        let AppEvent::PlanModeRequest { reply, .. } = event else {
            panic!("expected typed plan request");
        };
        reply
            .send(PlanModeReply::Cancelled {
                message: "user cancelled".to_string(),
            })
            .expect("resolver still waiting");

        let (result, context) = resolver.await.expect("resolver task");
        assert_eq!(context, None);
        assert!(matches!(
            result.follow_up(),
            tools::ToolFollowUp::ExitPlanMode {
                state: tools::ToolFollowUpState::Cancelled { reason },
                ..
            } if reason == "user cancelled"
        ));
    }

    #[test]
    fn partial_tool_outcomes_are_not_reported_as_successful_completion() {
        let call = tools::ToolCall {
            id: "partial-hook-fixture".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "mcp__fixture__remote".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let failure = tools::ToolFailure::new(
            tools::ToolFailureCode::External,
            "remote outcome unknown".to_string(),
            tools::ToolRetryability::Unknown,
        );
        let partial = tools::ToolResult::bind(
            &call,
            "mcp__fixture__remote",
            tools::ToolHandlerResult::partial_text("uncertain", vec![failure]),
        );
        let success = tools::ToolResult::bind(
            &call,
            "mcp__fixture__remote",
            tools::ToolHandlerResult::success_text("done"),
        );

        assert!(!tool_result_completed_successfully(&partial));
        assert!(tool_result_completed_successfully(&success));
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

    #[tokio::test]
    async fn tui_pipeline_propagates_automatic_learning_policy() {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("TUI learning workspace");
        std::fs::create_dir_all(workspace.path().join("src")).expect("source directory");
        let run = crate::tools::security::test_run_context_for(workspace.path());
        let memory = Arc::new(
            crate::memory::MemoryDb::open_for_workspace(host.path(), workspace.path())
                .expect("TUI workspace memory"),
        );
        let config: crate::config::AppConfig = serde_yaml::from_str(
            r"
proxy:
  target: local
providers:
  local:
    base_url: http://localhost:1234/v1
memory:
  automatic_learning_enabled: true
",
        )
        .expect("TUI learning config");
        let permissions = Arc::new(crate::permissions::PermissionManager::unrestricted_for_run(
            &run,
        ));
        let tasks = Arc::new(Mutex::new(
            crate::session::TaskManager::for_run(&run).expect("TUI task manager"),
        ));
        let call = tools::ToolCall {
            id: "tui-learning-write".to_string(),
            call_type: "function".to_string(),
            function: tools::FunctionCall {
                name: "write_file".to_string(),
                arguments: serde_json::json!({
                    "path": "src/tui_learning.rs",
                    "content": "pub const TUI_POLICY_PROPAGATED: bool = true;\n"
                })
                .to_string(),
            },
        };
        let (tx, _rx) = mpsc::channel();

        let result = execute_single_tool(SingleToolExecution {
            run_context: Arc::clone(&run),
            tool_call: &call,
            memory_db: Some(memory),
            app_config: Some(Arc::new(config)),
            permission: ToolPermissionDispatch {
                mgr: permissions,
                authorization: None,
            },
            policy_enforcer: None,
            task_mgr: tasks,
            session_id: Some("tui-learning-policy"),
            hook_context: None,
            tx: &tx,
        })
        .await
        .expect("TUI pipeline result");
        assert!(!result.is_error(), "TUI write failed: {}", result.content());
        assert!(result.observations().iter().any(|observation| {
            observation.kind == "technical_learning_capture" && !observation.authoritative
        }));
        crate::tools::retire_run(&run);
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
    fn native_json_decoder_advances_bound_state_and_rejects_incomplete_ollama() {
        let gemini_response = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{
                        "functionCall": {
                            "id": "gemini-native-call",
                            "name": "bash",
                            "args": {"command": "pwd"}
                        },
                        "thoughtSignature": "opaque-signature"
                    }]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 11,
                "candidatesTokenCount": 7
            }
        });
        let gemini =
            decode_provider_native_json_turn("gemini", "gemini-3.5-pro", &gemini_response, None, 1)
                .expect("Gemini native response decodes");
        assert_eq!(gemini.tool_calls[0].id, "gemini-native-call");
        assert_eq!(gemini.usage.input_tokens, 11);
        assert_eq!(gemini.usage.output_tokens, 7);
        assert_eq!(
            gemini.provider_native_state.protocol(),
            ProviderWireProtocol::GeminiGenerateContent
        );
        gemini
            .provider_native_state
            .validate_binding(
                "gemini",
                "gemini-3.5-pro",
                ProviderWireProtocol::GeminiGenerateContent,
            )
            .expect("decoded state retains exact request identity");

        let incomplete_ollama = serde_json::json!({
            "model": "qwen3",
            "message": {"role": "assistant", "content": "partial"},
            "done": false
        });
        let error =
            decode_provider_native_json_turn("ollama", "qwen3", &incomplete_ollama, None, 1)
                .err()
                .expect("incomplete Ollama output cannot advance continuation");
        assert!(error.contains("before done=true"), "{error}");
    }

    #[test]
    fn canonical_native_json_builder_replays_exact_state_without_private_metadata() {
        let exact_content = serde_json::json!({
            "role": "model",
            "parts": [{
                "functionCall": {
                    "id": "gemini-native-call",
                    "name": "bash",
                    "args": {"command": "pwd"}
                },
                "thoughtSignature": "opaque-signature"
            }]
        });
        let gemini_response = serde_json::json!({
            "candidates": [{"content": exact_content, "finishReason": "STOP"}]
        });
        let decoded =
            decode_provider_native_json_turn("google", "gemini-3.5-pro", &gemini_response, None, 1)
                .expect("Gemini native response decodes");
        let gemini_messages = vec![
            serde_json::json!({"role": "user", "content": "where am I"}),
            build_assistant_message_with_tools("", None, &decoded.tool_calls, "google"),
            serde_json::json!({
                "role": "tool",
                "name": "bash",
                "tool_call_id": "gemini-native-call",
                "content": "{\"cwd\":\"/workspace\"}"
            }),
        ];
        let gemini_request = build_request_for_wire_with_tools(
            WireApi::ChatCompletions,
            "google",
            "gemini-3.5-pro",
            &gemini_messages,
            "medium",
            None,
            None,
            &serde_json::json!([]),
            Some(&decoded.provider_native_state),
        )
        .expect("canonical Gemini request replays state");
        assert_eq!(gemini_request["contents"][1], exact_content);
        assert!(gemini_request
            .get("_openclaudia_gemini_portable_history")
            .is_none());

        let exact_message = serde_json::json!({
            "role": "assistant",
            "content": "",
            "thinking": "private reasoning",
            "tool_calls": [{
                "function": {
                    "index": 12,
                    "name": "read",
                    "arguments": {"path": "Cargo.toml"}
                }
            }]
        });
        let ollama_response = serde_json::json!({
            "model": "qwen3",
            "message": exact_message,
            "done": true
        });
        let decoded =
            decode_provider_native_json_turn("ollama", "qwen3", &ollama_response, None, 1)
                .expect("Ollama native response decodes");
        let ollama_messages = vec![
            serde_json::json!({"role": "user", "content": "read the manifest"}),
            build_assistant_message_with_tools("", None, &decoded.tool_calls, "ollama"),
            serde_json::json!({
                "role": "tool",
                "name": "read",
                "tool_call_id": decoded.tool_calls[0].id,
                "content": "manifest"
            }),
        ];
        let ollama_request = build_request_for_wire_with_tools(
            WireApi::ChatCompletions,
            "ollama",
            "qwen3",
            &ollama_messages,
            "medium",
            None,
            None,
            &serde_json::json!([]),
            Some(&decoded.provider_native_state),
        )
        .expect("canonical Ollama request replays state");
        assert_eq!(ollama_request["messages"][1], exact_message);
        assert_eq!(ollama_request["stream"], false);
        assert!(ollama_request
            .get("_openclaudia_ollama_portable_history")
            .is_none());
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
        assert_eq!(req["context_management"][0]["type"], "compaction");
        assert_eq!(
            req["context_management"][0]["compact_threshold"],
            crate::compaction::get_context_window("gpt-5.5").saturating_mul(4) / 5
        );
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
        assert!(req.get("_openclaudia_responses_history").is_none());
        assert!(req["input"].as_array().is_some_and(|items| items
            .iter()
            .all(|item| item.get("_openclaudia_message_ordinal").is_none())));
    }

    #[test]
    fn responses_request_accepts_null_assistant_content_for_tool_only_turn() {
        let messages = vec![
            serde_json::json!({"role": "user", "content": "inspect"}),
            serde_json::json!({
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_null_content",
                    "type": "function",
                    "function": {"name": "bash", "arguments": "{\"command\":\"pwd\"}"}
                }]
            }),
            serde_json::json!({
                "role": "tool",
                "tool_call_id": "call_null_content",
                "content": "/workspace"
            }),
        ];

        let request = build_request_for_wire_with_tools(
            WireApi::OpenAiResponses,
            "openai",
            "gpt-test",
            &messages,
            "medium",
            None,
            None,
            &serde_json::json!([]),
            None,
        )
        .expect("tool-only assistant history must be representable");

        assert_eq!(request["input"][1]["type"], "function_call");
        assert_eq!(request["input"][2]["type"], "function_call_output");
    }

    fn first_responses_test_output() -> crate::providers::OpenAiResponsesTurnOutput {
        crate::providers::OpenAiResponsesTurnOutput::new(
            "resp_first",
            vec![
                serde_json::json!({
                    "id": "rs_1",
                    "type": "reasoning",
                    "encrypted_content": "encrypted-native-reasoning"
                }),
                serde_json::json!({
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "phase": "commentary",
                    "_openclaudia_message_ordinal": "provider-owned-field",
                    "content": [{"type": "output_text", "text": "I'll check."}]
                }),
                serde_json::json!({
                    "id": "fc_1",
                    "type": "function_call",
                    "status": "completed",
                    "call_id": "call_1",
                    "name": "bash",
                    "arguments": "{\"command\":\"pwd\"}"
                }),
            ],
        )
        .expect("first native output")
    }

    fn second_responses_test_output() -> crate::providers::OpenAiResponsesTurnOutput {
        crate::providers::OpenAiResponsesTurnOutput::new(
            "resp_second",
            vec![
                serde_json::json!({
                    "id": "cmp_2",
                    "type": "compaction",
                    "encrypted_content": "encrypted-native-compaction"
                }),
                serde_json::json!({
                    "id": "msg_2",
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "phase": "final_answer",
                    "content": [{"type": "output_text", "text": "Done."}]
                }),
            ],
        )
        .expect("second native output")
    }

    #[test]
    fn responses_compaction_retires_superseded_native_and_portable_input() {
        let first_output = first_responses_test_output();
        let first_state = crate::providers::advance_openai_responses_state(
            "openai",
            "gpt-5.5",
            None,
            1,
            &first_output,
        )
        .expect("first continuation state");
        let second_output = second_responses_test_output();
        let second_state = crate::providers::advance_openai_responses_state(
            "openai",
            "gpt-5.5",
            Some(&first_state),
            3,
            &second_output,
        )
        .expect("second continuation state");
        assert_eq!(second_state.generation().get(), 2);
        let serialized = serde_json::to_string(&second_state).expect("serialize native state");
        let resumed: ProviderNativeState =
            serde_json::from_str(&serialized).expect("resume native state");

        let messages = vec![
            serde_json::json!({"role": "user", "content": "inspect"}),
            serde_json::json!({
                "role": "assistant",
                "content": "I'll check.",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "bash", "arguments": "{\"command\":\"pwd\"}"}
                }]
            }),
            serde_json::json!({
                "role": "tool",
                "tool_call_id": "call_1",
                "content": "/workspace"
            }),
            serde_json::json!({"role": "assistant", "content": "Done."}),
            serde_json::json!({"role": "user", "content": "continue"}),
        ];
        let request = build_request_for_wire_with_tools(
            WireApi::OpenAiResponses,
            "openai",
            "gpt-5.5",
            &messages,
            "high",
            None,
            None,
            &serde_json::json!([]),
            Some(&resumed),
        )
        .expect("lossless resumed request");

        assert_eq!(request["store"], false);
        assert!(request.get("previous_response_id").is_none());
        assert!(request.get("_openclaudia_responses_history").is_none());
        let input = request["input"].as_array().expect("Responses input");
        assert_eq!(input.len(), 3);
        assert_eq!(input[0], second_output.output_items()[0]);
        assert_eq!(input[1]["phase"], "final_answer");
        assert_eq!(input[2]["role"], "user");
        assert!(input
            .iter()
            .all(|item| item.get("_openclaudia_message_ordinal").is_none()));
        assert!(!serialized.contains("resp_first"));
        assert!(serialized.contains("resp_second"));
        assert!(!serialized.contains("encrypted-native-reasoning"));
        assert!(serialized.contains("encrypted-native-compaction"));
    }

    #[test]
    fn responses_state_rejects_history_that_lost_its_bound_assistant_turn() {
        let output = crate::providers::OpenAiResponsesTurnOutput::new(
            "resp_missing",
            vec![serde_json::json!({
                "id": "msg_missing",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "answer"}]
            })],
        )
        .expect("native output");
        let state =
            crate::providers::advance_openai_responses_state("openai", "gpt-5.5", None, 1, &output)
                .expect("native state");
        let error = build_request_for_wire_with_tools(
            WireApi::OpenAiResponses,
            "openai",
            "gpt-5.5",
            &[serde_json::json!({"role": "user", "content": "rewritten"})],
            "high",
            None,
            None,
            &serde_json::json!([]),
            Some(&state),
        )
        .expect_err("missing assistant binding must fail closed");
        assert!(error.contains("missing assistant ordinal 1"), "{error}");
    }

    #[test]
    fn responses_state_rejects_unrecognized_evidence_instead_of_ignoring_it() {
        let state = ProviderNativeState::new(
            "openai",
            "gpt-5.5",
            ProviderWireProtocol::OpenAiResponses,
            ContinuationGeneration::new(1).expect("non-zero generation"),
            vec![ProviderNativeItem::new(
                ProviderStateFacet::ServerContinuation,
                ProviderNativeItemPurpose::Evidence,
                serde_json::json!({"format": "unrecognized_responses_evidence_v1"}),
            )
            .expect("shape-valid evidence")],
        )
        .expect("shape-valid state");

        let error = build_request_for_wire_with_tools(
            WireApi::OpenAiResponses,
            "openai",
            "gpt-5.5",
            &[serde_json::json!({"role": "user", "content": "continue"})],
            "high",
            None,
            None,
            &serde_json::json!([]),
            Some(&state),
        )
        .expect_err("unknown native evidence must not be silently discarded");

        assert!(
            error.contains("unrecognized OpenAI Responses evidence"),
            "{error}"
        );
    }

    #[test]
    fn responses_state_rejects_output_that_precedes_its_turn_evidence() {
        let output = ProviderNativeItem::new(
            ProviderStateFacet::NativeMessage,
            ProviderNativeItemPurpose::Continuation,
            serde_json::json!({
                "format": "openai_responses_output_item_v1",
                "response_id": "resp_reordered",
                "assistant_ordinal": 1,
                "item": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "answer"}]
                }
            }),
        )
        .expect("shape-valid output");
        let evidence = ProviderNativeItem::new(
            ProviderStateFacet::ServerContinuation,
            ProviderNativeItemPurpose::Evidence,
            serde_json::json!({
                "format": "openai_responses_turn_v1",
                "response_id": "resp_reordered",
                "assistant_ordinal": 1,
                "output_item_count": 1,
                "store": false
            }),
        )
        .expect("shape-valid evidence");
        let state = ProviderNativeState::new(
            "openai",
            "gpt-5.5",
            ProviderWireProtocol::OpenAiResponses,
            ContinuationGeneration::new(1).expect("non-zero generation"),
            vec![output, evidence],
        )
        .expect("generic state shape");

        let error = build_request_for_wire_with_tools(
            WireApi::OpenAiResponses,
            "openai",
            "gpt-5.5",
            &[
                serde_json::json!({"role": "user", "content": "question"}),
                serde_json::json!({"role": "assistant", "content": "answer"}),
            ],
            "high",
            None,
            None,
            &serde_json::json!([]),
            Some(&state),
        )
        .expect_err("native output before evidence must fail closed");

        assert!(error.contains("not contiguous"), "{error}");
    }

    #[test]
    fn responses_state_rejects_generation_and_output_facet_forgery() {
        let evidence = || {
            ProviderNativeItem::new(
                ProviderStateFacet::ServerContinuation,
                ProviderNativeItemPurpose::Evidence,
                serde_json::json!({
                    "format": "openai_responses_turn_v1",
                    "response_id": "resp_structural",
                    "assistant_ordinal": 1,
                    "output_item_count": 1,
                    "store": false
                }),
            )
            .expect("shape-valid evidence")
        };
        let forged_output = ProviderNativeItem::new(
            ProviderStateFacet::NativeMessage,
            ProviderNativeItemPurpose::Continuation,
            serde_json::json!({
                "format": "openai_responses_output_item_v1",
                "response_id": "resp_structural",
                "assistant_ordinal": 1,
                "item": {
                    "type": "function_call",
                    "call_id": "call_structural",
                    "name": "bash",
                    "arguments": "{}"
                }
            }),
        )
        .expect("generic state permits provider-specific facet validation later");
        let forged_facet_state = ProviderNativeState::new(
            "openai",
            "gpt-5.5",
            ProviderWireProtocol::OpenAiResponses,
            ContinuationGeneration::new(1).expect("non-zero generation"),
            vec![evidence(), forged_output],
        )
        .expect("generic state shape");
        let messages = [
            serde_json::json!({"role": "user", "content": "question"}),
            serde_json::json!({"role": "assistant", "content": null, "tool_calls": []}),
        ];
        let error = build_request_for_wire_with_tools(
            WireApi::OpenAiResponses,
            "openai",
            "gpt-5.5",
            &messages,
            "high",
            None,
            None,
            &serde_json::json!([]),
            Some(&forged_facet_state),
        )
        .expect_err("function_call cannot masquerade as a native message facet");
        assert!(error.contains("facet"), "{error}");

        let valid_output = ProviderNativeItem::new(
            ProviderStateFacet::ToolCalls,
            ProviderNativeItemPurpose::Continuation,
            serde_json::json!({
                "format": "openai_responses_output_item_v1",
                "response_id": "resp_structural",
                "assistant_ordinal": 1,
                "item": {
                    "type": "function_call",
                    "call_id": "call_structural",
                    "name": "bash",
                    "arguments": "{}"
                }
            }),
        )
        .expect("valid provider-specific output");
        let forged_generation_state = ProviderNativeState::new(
            "openai",
            "gpt-5.5",
            ProviderWireProtocol::OpenAiResponses,
            ContinuationGeneration::new(2).expect("non-zero generation"),
            vec![evidence(), valid_output],
        )
        .expect("generic state shape");
        let error = build_request_for_wire_with_tools(
            WireApi::OpenAiResponses,
            "openai",
            "gpt-5.5",
            &messages,
            "high",
            None,
            None,
            &serde_json::json!([]),
            Some(&forged_generation_state),
        )
        .expect_err("generation cannot disagree with retained turn count");
        assert!(error.contains("generation 2"), "{error}");
    }

    #[test]
    fn process_responses_sse_event_retains_native_items_identity_and_usage() {
        let text_event = serde_json::json!({
            "type": "response.output_text.delta",
            "delta": "hello"
        });
        match process_responses_sse_event(&text_event).expect("text event") {
            ResponsesSseAction::Text(text) => assert_eq!(text, "hello"),
            _ => panic!("expected text event"),
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
            ResponsesSseAction::OutputItem(item) => assert_eq!(item, tool_event["item"]),
            _ => panic!("expected exact output item"),
        }

        let usage_event = serde_json::json!({
            "type": "response.completed",
            "response": {
                "id": "resp_abc",
                "status": "completed",
                "output": [tool_event["item"].clone()],
                "usage": {
                    "input_tokens": 12,
                    "output_tokens": 7,
                    "input_tokens_details": {
                        "cached_tokens": 5,
                        "cache_write_tokens": 2
                    }
                }
            }
        });
        match process_responses_sse_event(&usage_event).expect("usage event") {
            ResponsesSseAction::Completed {
                response_id,
                output_items,
                usage: Some(usage),
            } => {
                assert_eq!(response_id, "resp_abc");
                assert_eq!(output_items, Some(vec![tool_event["item"].clone()]));
                assert_eq!(usage.input_tokens, 5);
                assert_eq!(usage.output_tokens, 7);
                assert_eq!(usage.cache_read_tokens, 5);
                assert_eq!(usage.cache_write_tokens, 2);
            }
            _ => panic!("expected completed event"),
        }
    }

    #[test]
    fn responses_completed_accepts_null_output_from_chatgpt_backend() {
        let completed = serde_json::json!({
            "type": "response.completed",
            "response": {
                "id": "resp_null_output",
                "status": "completed",
                "output": null
            }
        });
        match process_responses_sse_event(&completed).expect("completed event") {
            ResponsesSseAction::Completed { output_items, .. } => {
                assert!(output_items.is_none());
            }
            _ => panic!("expected completed event"),
        }
    }

    #[test]
    fn responses_done_item_remains_authoritative_over_lean_completed_copy() {
        let rich_item = serde_json::json!({
            "id": "rs_authoritative",
            "type": "reasoning",
            "summary": [],
            "encrypted_content": "encrypted-continuation"
        });
        let lean_item = serde_json::json!({
            "id": "rs_authoritative",
            "type": "reasoning",
            "summary": []
        });
        let mut capture = ResponsesStreamCapture::default();
        capture
            .observe_output_item(rich_item.clone())
            .expect("done item");
        let mut full_content = String::new();
        let mut reasoning_content = String::new();
        let mut usage = TokenUsage::default();

        let done = dispatch_responses_action(
            ResponsesSseAction::Completed {
                response_id: "resp_authoritative".to_string(),
                output_items: Some(vec![lean_item]),
                usage: None,
            },
            &mut full_content,
            &mut reasoning_content,
            &mut capture,
            &mut usage,
            &mut |_: &str| Ok(()),
            &mut |_: &str| Ok(()),
        )
        .expect("completed event");

        assert!(done);
        assert_eq!(capture.output_items, vec![rich_item]);
    }

    #[test]
    fn responses_terminal_output_recovers_text_when_deltas_are_absent() {
        let output = vec![serde_json::json!({
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "output_text", "text": "first"},
                {"type": "refusal", "refusal": "not display text"},
                {"type": "output_text", "text": " second"}
            ]
        })];

        assert_eq!(
            responses_visible_output_text(&output).expect("terminal text"),
            "first second"
        );
    }

    #[test]
    fn responses_terminal_output_rejects_malformed_visible_text() {
        let output = vec![serde_json::json!({
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": 7}]
        })];

        let error = responses_visible_output_text(&output)
            .expect_err("malformed terminal output text must fail closed");
        assert!(error.contains("missing text"), "{error}");
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

        let unknown_zai = build_request("zai", "glm-4.7", &messages, "max", None, None)
            .expect("unknown Z.AI request should still build");
        assert!(
            unknown_zai.get("thinking").is_none()
                && unknown_zai.get("reasoning_effort").is_none(),
            "models without exact capability evidence must not receive optional controls: {unknown_zai}"
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
        assert_eq!(
            ollama["stream"], false,
            "canonical Ollama agent loops require one terminal JSON response"
        );
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

        let unknown_opus = build_anthropic_request("claude-opus-4-7", &messages, "max", None, None)
            .expect("unknown Opus request should still build");
        assert!(
            unknown_opus.get("thinking").is_none()
                && unknown_opus.get("output_config").is_none(),
            "models without exact capability evidence must receive no optional thinking controls: {unknown_opus}"
        );

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
        assert!(err.contains("role"), "{err}");
        assert!(err.contains("index 0"), "{err}");

        let missing_content = vec![serde_json::json!({"role": "user"})];
        let err = build_google_request(&missing_content, "medium")
            .expect_err("missing message content must fail");
        assert!(err.contains("content"), "{err}");
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
    fn durable_memory_prompts_accept_only_the_one_use_choice() {
        use std::sync::mpsc as std_mpsc;

        let run = test_run();
        let manager = PermissionManager::unrestricted_for_run(&run);
        let (tx, _rx) = std_mpsc::channel::<AppEvent>();
        for (name, arguments) in [
            (
                "memory_review",
                serde_json::json!({
                    "action": "review",
                    "logical_id": "00000000-0000-0000-0000-000000000001",
                    "expected_record_digest": format!("sha256:{}", "0".repeat(64)),
                }),
            ),
            (
                "memory_export",
                serde_json::json!({"destination_root": "/tmp/portable-export"}),
            ),
            (
                "memory_import",
                serde_json::json!({"source_root": "/tmp/portable-import"}),
            ),
        ] {
            let call = ToolCall {
                id: format!("{name}-call"),
                call_type: "function".to_string(),
                function: tools::FunctionCall {
                    name: name.to_string(),
                    arguments: arguments.to_string(),
                },
            };
            let allowed = permission_prompt_response(
                &Ok(PermissionResponse::Allow),
                &manager,
                Some("session-durable-memory"),
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
                Some("session-durable-memory"),
                &call,
                &tx,
            );
            assert!(matches!(reusable, PermissionOutcome::DeniedWithResult(_)));
        }
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

    /// S-048: retry delays and total attempts are explicitly bounded.
    #[test]
    fn provider_retry_policy_is_bounded() {
        assert!(is_retryable_status(429));
        assert_eq!(MAX_API_RETRIES, 10);
        assert_eq!(
            provider_transport::retry_delay(0, Some("0")),
            std::time::Duration::ZERO
        );
        assert_eq!(
            provider_transport::retry_delay(20, Some("999999")),
            provider_transport::MAX_RETRY_DELAY
        );
        assert!(provider_transport::should_retry_status(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            RequestReplaySafety::AdmissionOnly
        ));
        assert!(!provider_transport::should_retry_status(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            RequestReplaySafety::AdmissionOnly
        ));
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

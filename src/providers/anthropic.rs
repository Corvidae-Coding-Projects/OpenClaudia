//! Anthropic Messages API adapter.

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::config::ThinkingConfig;
use crate::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};
use crate::session::TokenUsage;

use super::{ApiKey, ProviderAdapter, ProviderError, ReasoningProfile};

/// Whether the model rejects manual extended thinking budgets.
///
/// Anthropic's current docs require adaptive thinking for these models;
/// sending `thinking: {type: "enabled", budget_tokens: ...}` returns 400.
#[must_use]
pub fn anthropic_rejects_manual_thinking(model: &str) -> bool {
    super::resolve_model("anthropic", model)
        .capabilities()
        .reasoning_profile
        == ReasoningProfile::AnthropicAdaptive
}

fn anthropic_rejects_sampling_parameters(model: &str) -> bool {
    anthropic_rejects_manual_thinking(model)
}

fn anthropic_has_implicit_adaptive_thinking(model: &str) -> bool {
    super::resolve_model("anthropic", model)
        .entry
        .is_some_and(|entry| {
            entry.canonical_id.eq_ignore_ascii_case("claude-fable-5")
                || entry.canonical_id.eq_ignore_ascii_case("claude-mythos-5")
        })
}

/// Normalize a user-facing Anthropic effort level for `output_config.effort`.
#[must_use]
pub fn anthropic_output_effort(effort: Option<&str>) -> Option<&'static str> {
    match effort?.to_ascii_lowercase().as_str() {
        "low" | "l" => Some("low"),
        "medium" | "med" | "m" => Some("medium"),
        "high" | "h" => Some("high"),
        "xhigh" => Some("xhigh"),
        "max" | "x" => Some("max"),
        _ => None,
    }
}

/// Apply the adaptive-thinking request shape required by newer Claude models.
pub fn apply_anthropic_adaptive_thinking(body: &mut Value, model: &str, effort: Option<&str>) {
    if !anthropic_has_implicit_adaptive_thinking(model) {
        body["thinking"] = json!({"type": "adaptive"});
    }
    if let Some(effort) = anthropic_output_effort(effort) {
        body["output_config"] = json!({"effort": effort});
    }
}

const ANTHROPIC_TOP_LEVEL_SCHEMA_COMBINATORS: [&str; 3] = ["oneOf", "allOf", "anyOf"];

fn anthropic_input_schema(parameters: Option<&Value>) -> Value {
    sanitize_anthropic_input_schema(
        parameters
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::default())),
    )
}

fn sanitize_anthropic_input_schema(mut schema: Value) -> Value {
    let Value::Object(map) = &mut schema else {
        return schema;
    };

    let mut removed_keywords = Vec::new();
    let mut branches = Vec::new();
    for keyword in ANTHROPIC_TOP_LEVEL_SCHEMA_COMBINATORS {
        if let Some(value) = map.remove(keyword) {
            removed_keywords.push(keyword);
            if let Some(items) = value.as_array() {
                branches.extend(items.iter().cloned());
            }
        }
    }

    if removed_keywords.is_empty() {
        return schema;
    }

    map.entry("type".to_string())
        .or_insert_with(|| Value::String("object".to_string()));
    merge_top_level_schema_branches(map, branches);
    append_anthropic_schema_compatibility_note(map, &removed_keywords);
    schema
}

fn merge_top_level_schema_branches(map: &mut serde_json::Map<String, Value>, branches: Vec<Value>) {
    let entry = map
        .entry("properties".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::default()));
    if !entry.is_object() {
        *entry = Value::Object(serde_json::Map::default());
    }

    let Some(target_props) = entry.as_object_mut() else {
        return;
    };

    for branch in branches {
        let Value::Object(branch_map) = branch else {
            continue;
        };
        let Some(Value::Object(props)) = branch_map.get("properties") else {
            continue;
        };
        for (name, value) in props {
            target_props
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
    }
}

fn append_anthropic_schema_compatibility_note(
    map: &mut serde_json::Map<String, Value>,
    removed_keywords: &[&str],
) {
    let note = format!(
        "Anthropic compatibility note: top-level {} constraints were simplified; exact input semantics are validated when the tool runs.",
        removed_keywords.join("/")
    );
    match map.get_mut("description") {
        Some(Value::String(description))
            if !description.contains("Anthropic compatibility note") =>
        {
            if !description.ends_with(' ') {
                description.push(' ');
            }
            description.push_str(&note);
        }
        Some(Value::String(_)) => {}
        _ => {
            map.insert("description".to_string(), Value::String(note));
        }
    }
}

/// Anthropic Messages API adapter
pub struct AnthropicAdapter;

impl AnthropicAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Extract system message from messages array.
    ///
    /// Crosslink #924: previously `.iter().find(...)` returned only the
    /// FIRST `system` role message; any subsequent system messages were
    /// silently dropped. Anthropic's API takes a single `system` field, so
    /// we now concatenate every system-role text with `\n\n` separators
    /// so callers that route multiple system blocks (e.g. injected prompt
    /// plus host-provided instructions) see all of them. Non-text parts (e.g. `image_url`)
    /// are still dropped but with a `warn!` so the dropping is visible.
    fn extract_system(messages: &[ChatMessage]) -> Option<String> {
        let mut pieces: Vec<String> = Vec::new();
        let mut non_text_seen = false;
        for m in messages.iter().filter(|m| m.role == "system") {
            match &m.content {
                MessageContent::Text(t) => {
                    if !t.is_empty() {
                        pieces.push(t.clone());
                    }
                }
                MessageContent::Parts(parts) => {
                    for p in parts {
                        if let Some(text) = &p.text {
                            if !text.is_empty() {
                                pieces.push(text.clone());
                            }
                        } else {
                            non_text_seen = true;
                        }
                    }
                }
            }
        }
        if non_text_seen {
            tracing::warn!(
                "anthropic::extract_system dropped non-text parts from a system message"
            );
        }
        if pieces.is_empty() {
            None
        } else {
            Some(pieces.join("\n\n"))
        }
    }

    /// Convert `ChatMessage`s to the shape [`convert_messages_to_anthropic`]
    /// expects, then dispatch — the richer converter correctly handles
    /// `role="tool"` → `tool_result` blocks with `tool_use_id` linkage and
    /// assistant `tool_calls` → `tool_use` blocks. Previously this method
    /// had its own simpler conversion that silently dropped tool-result
    /// semantics, causing every agentic tool-loop request to fail with
    /// Anthropic 400 "each `tool_use` must have a matching `tool_result`"
    /// (crosslink #475).
    ///
    /// Crosslink #837: `serde_json::to_value(&ChatMessage)` can only
    /// fail on a panicking `Serialize` impl, which `ChatMessage`
    /// derives — so the conversion is effectively infallible. The
    /// previous `filter_map(.ok())` would silently drop a message on
    /// a serialization bug, masking it; we now log + drop with full
    /// context so the failure is at least diagnosable.
    fn convert_messages(messages: &[ChatMessage]) -> Result<Vec<Value>, ProviderError> {
        let mut as_values: Vec<Value> = Vec::with_capacity(messages.len());
        for (idx, m) in messages.iter().enumerate() {
            match serde_json::to_value(m) {
                Ok(v) => as_values.push(v),
                Err(e) => {
                    tracing::warn!(
                        index = idx,
                        role = %m.role,
                        error = %e,
                        "anthropic::convert_messages: ChatMessage failed to serialize \
                         (should be impossible — please file a bug). \
                         Dropping the message rather than fail the request."
                    );
                }
            }
        }
        convert_messages_to_anthropic_checked(&as_values)
    }

    /// Convert `OpenAI` tools to Anthropic format with optional prompt caching.
    ///
    /// Surfaces malformed entries as `ProviderError::RequestFailed` rather than
    /// silently filtering them out (crosslink #413). Each tool MUST contain a
    /// `function` object with a non-empty string `name`; anything else is an
    /// API contract violation that the caller needs to know about.
    ///
    /// If `cache_last` is true, the last entry gets a `cache_control` marker
    /// for prompt caching.
    ///
    /// # Errors
    ///
    /// Returns `ProviderError::RequestFailed` if any tool is missing the
    /// `function` object or `function.name` is missing/non-string/empty.
    pub(crate) fn convert_tools_checked(
        tools: &[Value],
        cache_last: bool,
    ) -> Result<Vec<Value>, ProviderError> {
        let len = tools.len();
        let mut out = Vec::with_capacity(len);
        for (i, tool) in tools.iter().enumerate() {
            let func = tool.get("function").ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Tool at index {i} missing required 'function' object"
                ))
            })?;
            let name = func
                .get("name")
                .and_then(|n| n.as_str())
                .filter(|n| !n.is_empty())
                .ok_or_else(|| {
                    ProviderError::RequestFailed(format!(
                        "Tool at index {i} missing required 'function.name' string field"
                    ))
                })?;

            let mut tool_def = json!({
                "name": name,
                "description": func.get("description").cloned().unwrap_or_else(|| Value::String(String::new())),
                "input_schema": anthropic_input_schema(func.get("parameters"))
            });

            // Add cache_control to the last tool for prompt caching.
            // This caches all tools since cache applies to everything before the marker.
            if cache_last && i + 1 == len {
                tool_def["cache_control"] = json!({"type": "ephemeral"});
            }

            out.push(tool_def);
        }
        Ok(out)
    }

    /// Backwards-compatible infallible wrapper around [`Self::convert_tools_checked`].
    ///
    /// Used by trusted internal call sites that build tool definitions from
    /// [`crate::tools::get_all_tool_definitions`] (known well-formed). On the
    /// off-chance an internal tool definition is malformed, the entry is
    /// logged at `WARN` rather than silently dropped — so that a regression
    /// in our own builder produces forensic evidence in the logs.
    pub(crate) fn convert_tools(tools: &[Value], cache_last: bool) -> Vec<Value> {
        match Self::convert_tools_checked(tools, cache_last) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    error = %e,
                    "convert_tools encountered malformed tool definition from a trusted internal site (crosslink #413); falling back to best-effort filter"
                );
                // Best-effort: keep well-formed entries, surface dropped ones in logs.
                let len = tools.len();
                tools
                    .iter()
                    .enumerate()
                    .filter_map(|(i, tool)| {
                        let func = tool.get("function").or_else(|| {
                            warn!(index = i, "dropping tool missing 'function' object (crosslink #413)");
                            None
                        })?;
                        let name = func
                            .get("name")
                            .and_then(|n| n.as_str())
                            .filter(|n| !n.is_empty())
                            .or_else(|| {
                                warn!(index = i, "dropping tool missing 'function.name' (crosslink #413)");
                                None
                            })?;
                        let mut tool_def = json!({
                            "name": name,
                            "description": func.get("description").cloned().unwrap_or_else(|| Value::String(String::new())),
                            "input_schema": anthropic_input_schema(func.get("parameters"))
                        });
                        if cache_last && i + 1 == len {
                            tool_def["cache_control"] = json!({"type": "ephemeral"});
                        }
                        Some(tool_def)
                    })
                    .collect()
            }
        }
    }
}

impl Default for AnthropicAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for AnthropicAdapter {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn state_contract(
        &self,
        protocol: crate::runtime::ProviderWireProtocol,
    ) -> Result<&'static crate::runtime::ProviderStateContract, ProviderError> {
        match protocol {
            crate::runtime::ProviderWireProtocol::AnthropicMessages => {
                Ok(&super::ANTHROPIC_STATE_CONTRACT)
            }
            other => Err(super::unsupported_state_protocol(self.name(), other)),
        }
    }

    fn transform_request(&self, request: &ChatCompletionRequest) -> Result<Value, ProviderError> {
        let messages = Self::convert_messages(&request.messages)?;
        let mut body = json!({
            "model": &request.model,
            "messages": messages,
            "max_tokens": request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)
        });

        // Add system message if present - use array format with cache_control for prompt caching
        // See: https://docs.anthropic.com/en/docs/build-with-claude/prompt-caching
        if let Some(system) = Self::extract_system(&request.messages) {
            body["system"] = build_system_blocks_from_string(&system);
        }

        // Add temperature if specified and supported by the target model.
        // Claude Opus 4.7/4.8 and Claude 5-family models reject non-default
        // sampling parameters; omitting them locally avoids an upstream 400.
        if let Some(temp) = request.temperature {
            if anthropic_rejects_sampling_parameters(&request.model) {
                warn!(
                    model = %request.model,
                    temperature = temp,
                    "omitting unsupported Anthropic temperature parameter"
                );
            } else {
                body["temperature"] = json!(temp);
            }
        }

        // Convert tools with cache_control on last tool for prompt caching.
        // Use the *checked* variant: caller-supplied tools that fail validation
        // must surface as ProviderError::RequestFailed rather than be silently
        // dropped (crosslink #413).
        if let Some(tools) = &request.tools {
            let converted = Self::convert_tools_checked(tools, true)?;
            if !converted.is_empty() {
                body["tools"] = json!(converted);
            }
        }

        // Add streaming flag
        if request.stream.unwrap_or(false) {
            body["stream"] = json!(true);
        }

        debug!("Transformed request for Anthropic");
        Ok(body)
    }

    fn transform_request_with_thinking(
        &self,
        request: &ChatCompletionRequest,
        thinking: &ThinkingConfig,
    ) -> Result<Value, ProviderError> {
        let mut body = self.transform_request(request)?;

        // Add Anthropic extended thinking params if enabled
        // See: https://docs.anthropic.com/en/docs/build-with-claude/extended-thinking
        if thinking.enabled {
            let profile = super::resolve_model("anthropic", &request.model)
                .capabilities()
                .reasoning_profile;
            if profile == ReasoningProfile::AnthropicAdaptive {
                apply_anthropic_adaptive_thinking(
                    &mut body,
                    &request.model,
                    thinking.reasoning_effort.as_deref(),
                );
                debug!(
                    model = %request.model,
                    effort = ?thinking.reasoning_effort,
                    "Added Anthropic adaptive thinking params"
                );
                return Ok(body);
            }

            if profile != ReasoningProfile::AnthropicManual {
                warn!(
                    model = %request.model,
                    "thinking requested without current Anthropic model-capability evidence; omitting thinking controls",
                );
                return Ok(body);
            }

            // Crosslink #599: pull the effective budget through
            // ThinkingConfig::effective_budget so a `reasoning_effort`
            // setting of `medium`/`high` (with `adaptive=true`, the
            // default) raises the budget without requiring the user to
            // hand-set `budget_tokens`. Anthropic floors the budget at
            // 1024 — preserved here.
            let budget = thinking.effective_budget(10000).max(1024);
            body["thinking"] = json!({
                "type": "enabled",
                "budget_tokens": budget
            });
            debug!(
                "Added Anthropic thinking params: enabled=true, budget={}",
                budget
            );
        }

        Ok(body)
    }

    fn transform_response(&self, response: Value, _stream: bool) -> Result<Value, ProviderError> {
        // Convert Anthropic response to OpenAI format.
        //
        // Crosslink #413: previously this function injected `"msg_unknown"`,
        // `"unknown"`, and `0` sentinels for missing top-level fields, and
        // used `filter_map` + `?` to silently drop malformed content blocks.
        // Both behaviours masked upstream API contract violations. The
        // refactor now refuses to manufacture data — every missing required
        // field surfaces as `ProviderError::InvalidResponse` via the small
        // helpers defined further down this module.
        let id = require_nonempty_str(&response, "id")?.to_string();
        let model = require_nonempty_str(&response, "model")?.to_string();
        let stop_reason_str = require_str(&response, "stop_reason")?;
        let finish_reason = map_stop_reason(stop_reason_str)?;

        let content_arr = response
            .get("content")
            .and_then(|c| c.as_array())
            .ok_or_else(|| {
                warn!("Anthropic response missing required 'content' array (crosslink #413)");
                ProviderError::InvalidResponse(
                    "Anthropic response missing required 'content' array".to_string(),
                )
            })?;

        let (text_buf, tool_calls) = walk_content_blocks(content_arr)?;

        let mut message = json!({
            "role": "assistant",
            "content": text_buf
        });
        if !tool_calls.is_empty() {
            message["tool_calls"] = json!(tool_calls);
        }

        let (prompt_tokens, completion_tokens) = extract_usage(&response);

        Ok(json!({
            "id": id,
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": model,
            "choices": [{
                "index": 0,
                "message": message,
                "finish_reason": finish_reason,
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            }
        }))
    }

    fn chat_endpoint(&self, _model: &str) -> String {
        "/v1/messages".to_string()
    }

    fn get_headers(&self, api_key: &ApiKey) -> crate::secrets::SensitiveHeaders {
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_header_secret(
            reqwest::header::HeaderName::from_static("x-api-key"),
            api_key.secret(),
        );
        headers.insert_static_literal(
            reqwest::header::HeaderName::from_static("anthropic-version"),
            "2023-06-01",
        );
        headers.insert_static_literal(reqwest::header::CONTENT_TYPE, "application/json");
        headers
    }

    fn supports_model_listing(&self) -> bool {
        true
    }

    fn model_catalog_format(&self) -> Option<super::ModelCatalogFormat> {
        Some(super::ModelCatalogFormat::Anthropic)
    }

    fn models_endpoint(&self) -> &'static str {
        "/v1/models?limit=1000"
    }

    /// Anthropic native shape: `content` is an array of typed blocks;
    /// the assistant text lives in the first `{"type": "text",
    /// "text": "..."}` block. The default `OpenAI` extractor would
    /// return `None` here because the response has no `choices` array.
    /// See crosslink #479.
    fn extract_response_text(&self, response: &Value) -> Option<String> {
        response
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| {
                arr.iter()
                    .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("text"))
            })
            .and_then(|item| item.get("text"))
            .and_then(|t| t.as_str())
            .map(std::string::ToString::to_string)
    }

    /// Anthropic native usage envelope: `input_tokens` /
    /// `output_tokens` / `cache_read_input_tokens` /
    /// `cache_creation_input_tokens`. The trait default already handles
    /// these fields, but overriding here makes the intent explicit and
    /// future-proofs against the default drifting toward `OpenAI`-only
    /// keys.
    fn extract_token_usage(&self, response: &Value) -> Option<TokenUsage> {
        let usage = response.get("usage")?;
        Some(TokenUsage {
            input_tokens: usage
                .get("input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: usage
                .get("output_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            cache_read_tokens: usage
                .get("cache_read_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            cache_write_tokens: usage
                .get("cache_creation_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }
}

impl AnthropicAdapter {
    /// Headers to send when authenticating with an OAuth access token
    /// (Claude Max / Pro subscriptions) rather than a static API key.
    ///
    /// Takes `&str` rather than `&ApiKey` because the bearer token is a
    /// different secret type with different lifetime semantics than the
    /// API key; it is sourced from the OAuth session (`session.credentials
    /// .access_token`) and never flows through config deserialization.
    ///
    /// Replaces the inline magic strings previously embedded in
    /// `proxy::proxy_anthropic_messages` — every Anthropic-specific header
    /// literal now lives in one place. See crosslink #338.
    ///
    /// # Errors
    /// Returns an error unless the legacy protocol was compiled and explicitly
    /// acknowledged for this process.
    ///
    /// # Panics
    /// Panics only if a compile-time Anthropic header literal is invalid.
    pub fn oauth_headers(
        bearer_token: &crate::secrets::OAuthToken,
    ) -> Result<crate::secrets::SensitiveHeaders, crate::claude_credentials::ClaudeCredentialError>
    {
        crate::claude_credentials::require_experimental_direct_subscription()?;
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_header_bearer(reqwest::header::AUTHORIZATION, bearer_token.secret());
        headers
            .insert_literal(
                "anthropic-beta",
                crate::claude_credentials::claude_code_beta_header_value()?,
            )
            .expect("canonical Anthropic beta header must be valid");
        headers.insert_static_literal(
            reqwest::header::HeaderName::from_static("anthropic-version"),
            "2023-06-01",
        );
        headers.insert_static_literal(reqwest::header::CONTENT_TYPE, "application/json");
        Ok(headers)
    }
}

// --- Crosslink #413 helpers --------------------------------------------------
//
// Extracted from `transform_response` so each shape-validation step is its own
// named, testable unit instead of an opaque 150-line function. Every helper
// here surfaces missing/malformed fields as `ProviderError::InvalidResponse`
// and logs the offending payload at `WARN` for forensic traceability.

/// Extract a string field that MUST be present (any string value).
fn require_str<'a>(response: &'a Value, field: &str) -> Result<&'a str, ProviderError> {
    response.get(field).and_then(|v| v.as_str()).ok_or_else(|| {
        warn!(
            field,
            "Anthropic response missing required field (crosslink #413)"
        );
        ProviderError::InvalidResponse(format!(
            "Anthropic response missing required '{field}' field"
        ))
    })
}

/// Extract a string field that MUST be present AND non-empty.
fn require_nonempty_str<'a>(response: &'a Value, field: &str) -> Result<&'a str, ProviderError> {
    let s = require_str(response, field)?;
    if s.is_empty() {
        warn!(
            field,
            "Anthropic response has empty required field (crosslink #413)"
        );
        return Err(ProviderError::InvalidResponse(format!(
            "Anthropic response missing required '{field}' field"
        )));
    }
    Ok(s)
}

/// Map Anthropic `stop_reason` to the `OpenAI` `finish_reason` vocabulary.
fn map_stop_reason(stop_reason: &str) -> Result<&'static str, ProviderError> {
    match stop_reason {
        "tool_use" => Ok("tool_calls"),
        "max_tokens" | "model_context_window_exceeded" => Ok("length"),
        "end_turn" | "stop_sequence" => Ok("stop"),
        "refusal" => Ok("refusal"),
        other => {
            warn!(
                stop_reason = other,
                "Unknown Anthropic stop_reason; rejecting ambiguous terminal state"
            );
            Err(ProviderError::InvalidResponse(format!(
                "Unknown Anthropic stop_reason {other:?}"
            )))
        }
    }
}

/// Walk an Anthropic `content` array, surfacing malformed blocks as errors.
/// Returns `(concatenated_text, tool_call_array)`.
fn walk_content_blocks(content_arr: &[Value]) -> Result<(String, Vec<Value>), ProviderError> {
    let mut text_buf = String::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    for (i, block) in content_arr.iter().enumerate() {
        let block_type = block.get("type").and_then(|t| t.as_str()).ok_or_else(|| {
            warn!(
                index = i,
                "Anthropic content block missing 'type' (crosslink #413)"
            );
            ProviderError::InvalidResponse(format!(
                "Anthropic content block at index {i} missing 'type' field"
            ))
        })?;

        match block_type {
            "text" => text_buf.push_str(extract_text_block(i, block)?),
            "tool_use" => tool_calls.push(extract_tool_use_block(i, block)?),
            // Other block types (e.g. `thinking`, `redacted_thinking`) are
            // intentionally not surfaced into the OpenAI shape; this is a
            // schema-level skip, not a defensive-programming swallow.
            _ => debug!(
                block_type = block_type,
                "skipping Anthropic content block of unmapped type"
            ),
        }
    }
    Ok((text_buf, tool_calls))
}

/// Extract the string body of a `text` content block.
fn extract_text_block(index: usize, block: &Value) -> Result<&str, ProviderError> {
    block.get("text").and_then(|t| t.as_str()).ok_or_else(|| {
        warn!(
            index,
            "Anthropic text block missing string 'text' (crosslink #413)"
        );
        ProviderError::InvalidResponse(format!(
            "Anthropic text block at index {index} missing string 'text' field"
        ))
    })
}

/// Extract an `OpenAI`-shaped `tool_call` object from a `tool_use` content block.
fn extract_tool_use_block(index: usize, block: &Value) -> Result<Value, ProviderError> {
    let tool_id = block.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
        warn!(
            index,
            "Anthropic tool_use block missing 'id' (crosslink #413)"
        );
        ProviderError::InvalidResponse(format!(
            "Anthropic tool_use block at index {index} missing string 'id'"
        ))
    })?;
    let tool_name = block.get("name").and_then(|v| v.as_str()).ok_or_else(|| {
        warn!(
            index,
            "Anthropic tool_use block missing 'name' (crosslink #413)"
        );
        ProviderError::InvalidResponse(format!(
            "Anthropic tool_use block at index {index} missing string 'name'"
        ))
    })?;
    let input = block.get("input").ok_or_else(|| {
        warn!(
            index,
            "Anthropic tool_use block missing 'input' (crosslink #413)"
        );
        ProviderError::InvalidResponse(format!(
            "Anthropic tool_use block at index {index} missing 'input' field"
        ))
    })?;

    // Avoid double-serialization: if input is already a string, use it directly;
    // otherwise serialize the JSON value to a string for the OpenAI format.
    let arguments = if let Some(s) = input.as_str() {
        s.to_string()
    } else {
        serde_json::to_string(input).map_err(|e| {
            ProviderError::InvalidResponse(format!(
                "Anthropic tool_use block at index {index} has unserializable 'input': {e}"
            ))
        })?
    };

    Ok(json!({
        "id": tool_id,
        "type": "function",
        "function": {
            "name": tool_name,
            "arguments": arguments
        }
    }))
}

/// Pull `(input_tokens, output_tokens)` out of an optional `usage` object.
/// When `usage` is absent (e.g. a partial streaming response), zeros are
/// reported but a `DEBUG` log records the case — this is *not* the silent
/// sentinel behaviour the bug report flagged.
fn extract_usage(response: &Value) -> (u64, u64) {
    response.get("usage").map_or_else(
        || {
            debug!("Anthropic response has no 'usage' object; reporting 0/0 token counts");
            (0u64, 0u64)
        },
        |u| {
            let p = u
                .get("input_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let c = u
                .get("output_tokens")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            (p, c)
        },
    )
}

/// Build an Anthropic `system` array from a [`SystemPromptBlocks`].
///
/// Returns two blocks for cache efficiency:
/// - Block 0: stable prefix with `cache_control: { type: "ephemeral" }`
/// - Block 1: dynamic suffix without `cache_control` (reprocessed each turn)
///
/// If the dynamic suffix is empty, only one block is returned.
#[must_use]
pub fn build_system_blocks(blocks: &crate::prompt::SystemPromptBlocks) -> Value {
    if blocks.dynamic_suffix().is_empty() {
        json!([{
            "type": "text",
            "text": blocks.stable_prefix(),
            "cache_control": {"type": "ephemeral"}
        }])
    } else if blocks.stable_prefix().is_empty() {
        json!([{
            "type": "text",
            "text": blocks.dynamic_suffix()
        }])
    } else {
        json!([
            {
                "type": "text",
                "text": blocks.stable_prefix(),
                "cache_control": {"type": "ephemeral"}
            },
            {
                "type": "text",
                "text": blocks.dynamic_suffix()
            }
        ])
    }
}

/// Build an Anthropic `system` array from a single string (legacy path).
///
/// Used by the proxy adapter which receives pre-assembled strings.
#[must_use]
pub fn build_system_blocks_from_string(system: &str) -> Value {
    json!([{
        "type": "text",
        "text": system,
        "cache_control": {"type": "ephemeral"}
    }])
}

/// Convert tools from `OpenAI` format to Anthropic format
///
/// `OpenAI` format: `{ "type": "function", "function": { "name": ..., "parameters": ... } }`
/// Anthropic format: `{ "name": ..., "description": ..., "input_schema": ... }`
#[must_use]
pub fn convert_tools_to_anthropic(tools: &[Value]) -> Vec<Value> {
    AnthropicAdapter::convert_tools(tools, true)
}

/// Checked variant of [`convert_tools_to_anthropic`].
///
/// # Errors
///
/// Returns [`ProviderError::RequestFailed`] if any tool is missing the
/// `function` object or `function.name` is missing/non-string/empty.
pub fn convert_tools_to_anthropic_checked(tools: &[Value]) -> Result<Vec<Value>, ProviderError> {
    AnthropicAdapter::convert_tools_checked(tools, true)
}

/// Convert a JSON value expected to contain an `OpenAI` tools array to
/// Anthropic tool definitions.
///
/// This is intended for call sites that receive tool definitions as a generic
/// [`Value`] from the built-in registry and should fail closed if that registry
/// ever stops returning an array.
///
/// # Errors
///
/// Returns [`ProviderError::RequestFailed`] if the top-level value is not an
/// array or if any contained tool is malformed.
pub fn convert_tool_definitions_to_anthropic_checked(
    tools: &Value,
) -> Result<Vec<Value>, ProviderError> {
    let tool_array = tools.as_array().ok_or_else(|| {
        ProviderError::RequestFailed("Anthropic tool definitions must be a JSON array".to_string())
    })?;
    convert_tools_to_anthropic_checked(tool_array)
}

/// Convert messages from `OpenAI` format to Anthropic format
///
/// Handles the critical differences:
/// - `OpenAI` `role: "tool"` -> Anthropic `role: "user"` with `type: "tool_result"` content
/// - `OpenAI` `tool_calls` array -> Anthropic `type: "tool_use"` content blocks
/// - System messages are filtered out (handled separately at top level)
#[must_use]
pub fn convert_messages_to_anthropic(messages: &[Value]) -> Vec<Value> {
    convert_messages_to_anthropic_impl(messages, false).unwrap_or_else(|e| {
        warn!(
            error = %e,
            "convert_messages_to_anthropic encountered malformed trusted message history; \
             returning an empty Anthropic message list"
        );
        Vec::new()
    })
}

/// Checked variant of [`convert_messages_to_anthropic`].
///
/// This is used by [`AnthropicAdapter::transform_request`], where malformed
/// assistant tool-call arguments must surface as a provider request error
/// instead of being silently replaced with `{}`.
///
/// # Errors
///
/// Returns [`ProviderError::RequestFailed`] when an assistant tool call has
/// missing linkage fields (`id`, `function.name`, `function.arguments`), invalid
/// JSON arguments, non-object JSON arguments, or when a tool result is missing
/// its `tool_call_id`.
pub fn convert_messages_to_anthropic_checked(
    messages: &[Value],
) -> Result<Vec<Value>, ProviderError> {
    convert_messages_to_anthropic_impl(messages, true)
}

fn convert_messages_to_anthropic_impl(
    messages: &[Value],
    strict_tool_arguments: bool,
) -> Result<Vec<Value>, ProviderError> {
    let mut result = Vec::new();

    for (msg_index, msg) in messages.iter().enumerate() {
        let role = message_role_for_anthropic(msg_index, msg, strict_tool_arguments)?;

        // Skip system messages (handled separately)
        if role == "system" {
            continue;
        }

        // Handle tool result messages (OpenAI format: role="tool")
        if role == "tool" {
            result.push(convert_tool_result_message(
                msg_index,
                msg,
                strict_tool_arguments,
            )?);
            continue;
        }

        // Handle assistant messages with tool_calls
        if role == "assistant" {
            if let Some(converted) =
                convert_assistant_tool_call_message(msg_index, msg, strict_tool_arguments)?
            {
                result.push(converted);
                continue;
            }
        }

        // Regular user or assistant message - convert content to array format
        result.push(convert_regular_message(
            msg_index,
            role,
            msg,
            strict_tool_arguments,
        )?);
    }

    Ok(result)
}

fn message_role_for_anthropic(
    msg_index: usize,
    msg: &Value,
    strict: bool,
) -> Result<&str, ProviderError> {
    let Some(role) = msg
        .get("role")
        .and_then(Value::as_str)
        .filter(|role| !role.is_empty())
    else {
        return if strict {
            Err(ProviderError::RequestFailed(format!(
                "Message at index {msg_index} missing non-empty string 'role'"
            )))
        } else {
            Ok("user")
        };
    };

    match role {
        "system" | "tool" | "assistant" | "user" => Ok(role),
        _ if !strict => Ok(role),
        _ => Err(ProviderError::RequestFailed(format!(
            "Message at index {msg_index} has unsupported role"
        ))),
    }
}

fn convert_tool_result_message(
    msg_index: usize,
    msg: &Value,
    strict_tool_arguments: bool,
) -> Result<Value, ProviderError> {
    let tool_use_id = match msg
        .get("tool_call_id")
        .and_then(|v| v.as_str())
        .filter(|id| !id.is_empty())
    {
        Some(id) => id,
        None if strict_tool_arguments => {
            return Err(ProviderError::RequestFailed(format!(
                "Tool result message at index {msg_index} missing non-empty string \
                 'tool_call_id'"
            )));
        }
        None => "",
    };
    let content = match msg.get("content").and_then(|v| v.as_str()) {
        Some(content) => content,
        None if strict_tool_arguments => {
            return Err(ProviderError::RequestFailed(format!(
                "Tool result message at index {msg_index} missing string 'content'"
            )));
        }
        None => "",
    };
    let is_error = msg
        .get("is_error")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    let (attachments, attachment_diagnostic) = match crate::tools::resolve_tool_attachments(
        msg.get(crate::tools::TOOL_ATTACHMENTS_MESSAGE_KEY),
    ) {
        Ok(attachments) => (attachments, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let native_content = if attachments.is_empty() && attachment_diagnostic.is_none() {
        Value::String(content.to_string())
    } else {
        let mut blocks = vec![json!({"type": "text", "text": content})];
        if let Some(diagnostic) = attachment_diagnostic {
            blocks.push(json!({
                "type": "text",
                "text": format!("Native tool attachment unavailable: {diagnostic}")
            }));
        }
        for attachment in attachments {
            if !attachment.media_type.starts_with("image/") {
                blocks.push(json!({
                    "type": "text",
                    "text": format!(
                        "Anthropic cannot replay {} tool attachment {}",
                        attachment.media_type, attachment.digest
                    )
                }));
                continue;
            }
            blocks.push(json!({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": attachment.media_type,
                    "data": base64::engine::general_purpose::STANDARD.encode(&attachment.bytes),
                }
            }));
        }
        Value::Array(blocks)
    };

    let mut tool_result = json!({
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": native_content
    });
    if is_error {
        tool_result["is_error"] = json!(true);
    }

    Ok(json!({
        "role": "user",
        "content": [tool_result]
    }))
}

fn convert_assistant_tool_call_message(
    msg_index: usize,
    msg: &Value,
    strict_tool_arguments: bool,
) -> Result<Option<Value>, ProviderError> {
    let Some(tool_calls) = msg.get("tool_calls").and_then(|v| v.as_array()) else {
        return Ok(None);
    };

    let mut content_blocks: Vec<Value> = Vec::new();
    if let Some(text) = msg.get("content").and_then(|v| v.as_str()) {
        if !text.is_empty() {
            content_blocks.push(json!({"type": "text", "text": text}));
        }
    }

    let empty_obj = json!({});
    for (tool_call_index, tc) in tool_calls.iter().enumerate() {
        let id = match tc
            .get("id")
            .and_then(|v| v.as_str())
            .filter(|id| !id.is_empty())
        {
            Some(id) => id,
            None if strict_tool_arguments => {
                return Err(ProviderError::RequestFailed(format!(
                    "Assistant tool_call at message index {msg_index}, tool_call index \
                     {tool_call_index} missing non-empty string 'id'"
                )));
            }
            None => "",
        };

        let func = match tc.get("function").filter(|v| v.is_object()) {
            Some(func) => func,
            None if strict_tool_arguments => {
                return Err(ProviderError::RequestFailed(format!(
                    "Assistant tool_call at message index {msg_index}, tool_call index \
                     {tool_call_index} missing required 'function' object"
                )));
            }
            None => &empty_obj,
        };

        let name = match func
            .get("name")
            .and_then(|v| v.as_str())
            .filter(|name| !name.is_empty())
        {
            Some(name) => name,
            None if strict_tool_arguments => {
                return Err(ProviderError::RequestFailed(format!(
                    "Assistant tool_call at message index {msg_index}, tool_call index \
                     {tool_call_index} missing non-empty string 'function.name'"
                )));
            }
            None => "",
        };
        let input =
            convert_tool_call_input(msg_index, tool_call_index, func, strict_tool_arguments)?;

        content_blocks.push(json!({
            "type": "tool_use",
            "id": id,
            "name": name,
            "input": input
        }));
    }

    if content_blocks.is_empty() {
        content_blocks.push(json!({"type": "text", "text": ""}));
    }
    Ok(Some(json!({
        "role": "assistant",
        "content": content_blocks
    })))
}

fn convert_tool_call_input(
    msg_index: usize,
    tool_call_index: usize,
    func: &Value,
    strict_tool_arguments: bool,
) -> Result<Value, ProviderError> {
    let Some(args_str) = func.get("arguments").and_then(|v| v.as_str()) else {
        return if strict_tool_arguments {
            Err(ProviderError::RequestFailed(format!(
                "Assistant tool_call at message index {msg_index}, tool_call index \
                 {tool_call_index} missing string 'function.arguments'"
            )))
        } else {
            Ok(json!({}))
        };
    };

    match parse_tool_call_input_for_anthropic(msg_index, tool_call_index, args_str) {
        Ok(input) => Ok(input),
        Err(e) if strict_tool_arguments => Err(e),
        Err(e) => {
            warn!(
                error = %e,
                message_index = msg_index,
                tool_call_index,
                "assistant tool_call has invalid arguments; substituting empty \
                 Anthropic tool_use.input in compatibility converter"
            );
            Ok(json!({}))
        }
    }
}

fn convert_regular_message(
    msg_index: usize,
    role: &str,
    msg: &Value,
    strict: bool,
) -> Result<Value, ProviderError> {
    let content = match msg.get("content") {
        Some(Value::String(text)) => json!([{"type": "text", "text": text}]),
        Some(Value::Array(parts)) => {
            json!(convert_regular_content_parts(msg_index, parts, strict)?)
        }
        None if strict => {
            return Err(ProviderError::RequestFailed(format!(
                "Message at index {msg_index} missing 'content'"
            )));
        }
        Some(other) if strict => {
            return Err(ProviderError::RequestFailed(format!(
                "Message at index {msg_index} has unsupported 'content' type {}",
                json_value_type_name(other)
            )));
        }
        Some(_) | None => json!([{"type": "text", "text": ""}]),
    };

    Ok(json!({
        "role": role,
        "content": content
    }))
}

fn convert_regular_content_parts(
    msg_index: usize,
    parts: &[Value],
    strict: bool,
) -> Result<Vec<Value>, ProviderError> {
    let mut out = Vec::with_capacity(parts.len());

    for (part_index, part) in parts.iter().enumerate() {
        match part.get("type").and_then(Value::as_str) {
            Some("text") => match part.get("text").and_then(Value::as_str) {
                Some(text) => out.push(json!({"type": "text", "text": text})),
                None if strict => {
                    return Err(ProviderError::RequestFailed(format!(
                        "Text content part at message index {msg_index}, part index {part_index} \
                         missing string 'text'"
                    )));
                }
                None => out.push(json!({"type": "text", "text": ""})),
            },
            Some("image" | "image_url") => {
                let source = anthropic_image_source_from_part(part).ok_or_else(|| {
                    ProviderError::RequestFailed(format!(
                        "Image content part at message index {msg_index}, part index {part_index} \
                         missing Anthropic image source"
                    ))
                })?;
                out.push(json!({"type": "image", "source": source}));
            }
            Some(_) => {
                if strict {
                    return Err(ProviderError::RequestFailed(format!(
                        "Unsupported content part type at message index {msg_index}, part index \
                         {part_index}"
                    )));
                }
                warn!(
                    message_index = msg_index,
                    part_index,
                    "dropping unsupported content part in compatibility Anthropic converter"
                );
            }
            None => {
                if !strict {
                    warn!(
                        message_index = msg_index,
                        part_index,
                        "dropping content part missing type in compatibility Anthropic converter"
                    );
                    continue;
                }
                return Err(ProviderError::RequestFailed(format!(
                    "Content part at message index {msg_index}, part index {part_index} missing \
                     string 'type'"
                )));
            }
        }
    }

    if out.is_empty() {
        out.push(json!({"type": "text", "text": ""}));
    }

    Ok(out)
}

fn anthropic_image_source_from_part(part: &Value) -> Option<Value> {
    if let Some(source) = part.get("source").filter(|source| source.is_object()) {
        return Some(source.clone());
    }

    let image_url = part.get("image_url")?;
    if image_url.get("type").is_some() {
        return Some(image_url.clone());
    }

    image_url.get("url").and_then(Value::as_str).map(|url| {
        json!({
            "type": "url",
            "url": url
        })
    })
}

fn parse_tool_call_input_for_anthropic(
    msg_index: usize,
    tool_call_index: usize,
    args_str: &str,
) -> Result<Value, ProviderError> {
    let input: Value = serde_json::from_str(args_str).map_err(|e| {
        ProviderError::RequestFailed(format!(
            "Assistant tool_call at message index {msg_index}, tool_call index \
             {tool_call_index} has invalid JSON in 'function.arguments': {e}"
        ))
    })?;
    if !input.is_object() {
        return Err(ProviderError::RequestFailed(format!(
            "Assistant tool_call at message index {msg_index}, tool_call index \
             {tool_call_index} has non-object 'function.arguments': expected JSON \
             object, got {}",
            json_value_type_name(&input),
        )));
    }
    Ok(input)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{ChatCompletionRequest, ChatMessage, ContentPart, MessageContent};

    fn text_msg(role: &str, text: &str) -> ChatMessage {
        ChatMessage {
            role: role.to_string(),
            content: MessageContent::Text(text.to_string()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        }
    }

    // --- Regression test for crosslink #475 ---
    //
    // The hot path (AnthropicAdapter::transform_request) previously went
    // through a private `convert_messages` that mapped role="tool" to a
    // bare role="user" text block, losing the tool_use_id linkage.
    // Anthropic rejects this with 400 ("each tool_use must have a matching
    // tool_result"). After the fix the adapter routes through
    // convert_messages_to_anthropic, which preserves the linkage.

    #[test]
    fn tool_result_role_becomes_tool_result_block_with_id() {
        let msgs = vec![
            text_msg("user", "what is 2+2?"),
            ChatMessage {
                role: "assistant".to_string(),
                content: MessageContent::Text(String::new()),
                name: None,
                tool_calls: Some(vec![json!({
                    "id": "toolu_abc",
                    "type": "function",
                    "function": {"name": "calc", "arguments": "{\"expr\":\"2+2\"}"}
                })]),
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            },
            ChatMessage {
                role: "tool".to_string(),
                content: MessageContent::Text("4".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: Some("toolu_abc".to_string()),
                extra: std::collections::HashMap::new(),
            },
        ];

        let request = ChatCompletionRequest {
            model: "claude-opus-4-6".to_string(),
            messages: msgs,
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };

        let adapter = AnthropicAdapter::new();
        let body = adapter.transform_request(&request).expect("transform ok");
        let messages = body["messages"].as_array().expect("messages is array");

        assert_eq!(messages.len(), 3, "expected 3 messages, got {messages:?}");

        // Assistant message must carry a tool_use block with id toolu_abc.
        let asst = &messages[1];
        assert_eq!(asst["role"], "assistant");
        let asst_content = asst["content"].as_array().expect("assistant content array");
        let tool_use = asst_content
            .iter()
            .find(|b| b["type"] == "tool_use")
            .expect("assistant message missing tool_use block");
        assert_eq!(tool_use["id"], "toolu_abc");
        assert_eq!(tool_use["name"], "calc");
        assert_eq!(tool_use["input"]["expr"], "2+2");

        // Tool result must be wrapped as a user message with a tool_result
        // block whose tool_use_id matches the preceding tool_use id.
        let tool_result_msg = &messages[2];
        assert_eq!(tool_result_msg["role"], "user");
        let tr_content = tool_result_msg["content"].as_array().expect("tr content");
        let tool_result = tr_content
            .iter()
            .find(|b| b["type"] == "tool_result")
            .expect("tool result block missing — #475 regression");
        assert_eq!(tool_result["tool_use_id"], "toolu_abc");
        assert_eq!(tool_result["content"], "4");
    }

    #[test]
    fn typed_tool_image_becomes_one_native_anthropic_block() {
        let bytes = b"typed-anthropic-image".to_vec();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let attachment = crate::tools::register_transient_attachment(
            "image/png",
            bytes,
            crate::tools::ToolSensitivity::Workspace,
        )
        .expect("register image");
        let call = crate::tools::ToolCall {
            id: "toolu_image".to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "read_file".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let result = crate::tools::ToolResult::bind(
            &call,
            "read_file",
            crate::tools::ToolHandlerResult::success_text("typed image metadata")
                .with_attachment(attachment),
        );
        assert!(!result.provider_content().contains(&encoded));

        let converted = convert_messages_to_anthropic_checked(&[result.openai_message()])
            .expect("convert typed tool image");
        let content = converted[0]["content"][0]["content"]
            .as_array()
            .expect("native tool result content blocks");
        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[1]["type"], "image");
        assert_eq!(content[1]["source"]["data"], encoded);
        assert_eq!(
            serde_json::to_string(&converted)
                .expect("serialize wire body")
                .matches(&encoded)
                .count(),
            1
        );
    }

    fn request_with_assistant_tool_call(tool_call: Value) -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "claude-opus-4-6".to_string(),
            messages: vec![
                text_msg("user", "run a tool"),
                ChatMessage {
                    role: "assistant".to_string(),
                    content: MessageContent::Text(String::new()),
                    name: None,
                    tool_calls: Some(vec![tool_call]),
                    tool_call_id: None,
                    extra: std::collections::HashMap::new(),
                },
            ],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        }
    }

    fn request_with_assistant_tool_arguments(arguments: &str) -> ChatCompletionRequest {
        request_with_assistant_tool_call(json!({
            "id": "toolu_bad",
            "type": "function",
            "function": {"name": "bash", "arguments": arguments}
        }))
    }

    #[test]
    fn convert_messages_checked_errors_on_missing_role() {
        let err = convert_messages_to_anthropic_checked(&[json!({
            "content": "anthropic-message-secret-sentinel"
        })])
        .expect_err("missing role must fail checked Anthropic conversion");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("missing non-empty string 'role'"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
                assert!(!msg.contains("anthropic-message-secret-sentinel"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn convert_messages_checked_errors_on_non_string_role() {
        let err = convert_messages_to_anthropic_checked(&[json!({
            "role": 7,
            "content": "hi"
        })])
        .expect_err("non-string role must fail checked Anthropic conversion");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("missing non-empty string 'role'"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn convert_messages_checked_errors_on_empty_role() {
        let err = convert_messages_to_anthropic_checked(&[json!({
            "role": "",
            "content": "hi"
        })])
        .expect_err("empty role must fail checked Anthropic conversion");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("missing non-empty string 'role'"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn convert_messages_checked_errors_on_unsupported_role() {
        let err = convert_messages_to_anthropic_checked(&[json!({
            "role": "anthropic-role-secret-sentinel",
            "content": "hi"
        })])
        .expect_err("unsupported role must fail checked Anthropic conversion");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("unsupported role"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
                assert!(!msg.contains("anthropic-role-secret-sentinel"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn convert_messages_compat_missing_role_still_defaults_to_user() {
        let converted = convert_messages_to_anthropic(&[json!({"content": "hi"})]);

        assert_eq!(converted.len(), 1);
        assert_eq!(converted[0]["role"], "user");
    }

    #[test]
    fn convert_messages_checked_errors_on_missing_regular_content() {
        let err = convert_messages_to_anthropic_checked(&[json!({"role": "user"})])
            .expect_err("missing regular message content must fail checked conversion");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("'content'"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn convert_messages_checked_errors_on_tool_result_missing_content() {
        let err = convert_messages_to_anthropic_checked(&[json!({
            "role": "tool",
            "tool_call_id": "toolu_123"
        })])
        .expect_err("tool result without content must fail checked conversion");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("'content'"), "{msg}");
                assert!(msg.contains("Tool result message"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn convert_messages_compat_missing_content_still_defaults_to_empty_text() {
        let converted = convert_messages_to_anthropic(&[json!({"role": "user"})]);

        assert_eq!(converted.len(), 1);
        assert_eq!(converted[0]["role"], "user");
        assert_eq!(converted[0]["content"][0]["text"], "");
    }

    #[test]
    fn transform_request_errors_on_malformed_assistant_tool_call_arguments() {
        let request =
            request_with_assistant_tool_arguments("{not json anthropic-tool-secret-sentinel");
        let err = AnthropicAdapter::new()
            .transform_request(&request)
            .expect_err("malformed assistant tool_call arguments must fail request conversion");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.arguments"), "{msg}");
                assert!(msg.contains("invalid JSON"), "{msg}");
                assert!(msg.contains("message index 1"), "{msg}");
                assert!(!msg.contains("anthropic-tool-secret-sentinel"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_non_object_assistant_tool_call_arguments() {
        let request = request_with_assistant_tool_arguments("[]");
        let err = AnthropicAdapter::new()
            .transform_request(&request)
            .expect_err("non-object assistant tool_call arguments must fail request conversion");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.arguments"), "{msg}");
                assert!(msg.contains("expected JSON object"), "{msg}");
                assert!(msg.contains("array"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_missing_assistant_tool_call_id() {
        let request = request_with_assistant_tool_call(json!({
            "type": "function",
            "function": {"name": "bash", "arguments": "{}"}
        }));
        let err = AnthropicAdapter::new()
            .transform_request(&request)
            .expect_err("missing assistant tool_call id must fail request conversion");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("'id'"), "{msg}");
                assert!(msg.contains("message index 1"), "{msg}");
                assert!(msg.contains("tool_call index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_missing_assistant_tool_call_function_object() {
        let request = request_with_assistant_tool_call(json!({
            "id": "toolu_bad",
            "type": "function"
        }));
        let err = AnthropicAdapter::new()
            .transform_request(&request)
            .expect_err("missing assistant tool_call function object must fail request conversion");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("'function' object"), "{msg}");
                assert!(msg.contains("message index 1"), "{msg}");
                assert!(msg.contains("tool_call index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_missing_assistant_tool_call_name() {
        let request = request_with_assistant_tool_call(json!({
            "id": "toolu_bad",
            "type": "function",
            "function": {"arguments": "{}"}
        }));
        let err = AnthropicAdapter::new()
            .transform_request(&request)
            .expect_err("missing assistant tool_call function.name must fail request conversion");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
                assert!(msg.contains("message index 1"), "{msg}");
                assert!(msg.contains("tool_call index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_tool_result_missing_tool_call_id() {
        let request = ChatCompletionRequest {
            model: "claude-opus-4-6".to_string(),
            messages: vec![ChatMessage {
                role: "tool".to_string(),
                content: MessageContent::Text("4".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };
        let err = AnthropicAdapter::new()
            .transform_request(&request)
            .expect_err("tool result without tool_call_id must fail request conversion");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("tool_call_id"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn plain_text_user_message_still_works() {
        let request = ChatCompletionRequest {
            model: "claude-opus-4-6".to_string(),
            messages: vec![text_msg("user", "hi")],
            max_tokens: Some(16),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };
        let body = AnthropicAdapter::new()
            .transform_request(&request)
            .expect("transform ok");
        let messages = body["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
    }

    #[test]
    fn image_content_part_preserved() {
        let parts = vec![
            ContentPart {
                content_type: "text".to_string(),
                text: Some("describe this".to_string()),
                image_url: None,
            },
            ContentPart {
                content_type: "image".to_string(),
                text: None,
                image_url: Some(json!({
                    "type": "base64",
                    "media_type": "image/png",
                    "data": "iVBORw..."
                })),
            },
        ];
        let msg = ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Parts(parts),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        };
        let request = ChatCompletionRequest {
            model: "claude-opus-4-6".to_string(),
            messages: vec![msg],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };
        let body = AnthropicAdapter::new()
            .transform_request(&request)
            .expect("transform ok");
        let messages = body["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 1);
        let content = messages[0]["content"].as_array().expect("content is array");
        assert_eq!(content.len(), 2, "multimodal parts lost: {content:?}");
        assert_eq!(content[0], json!({"type": "text", "text": "describe this"}));
        assert_eq!(content[1]["type"], "image");
        assert_eq!(content[1]["source"]["type"], "base64");
        assert_eq!(content[1]["source"]["media_type"], "image/png");
        assert!(content[1].get("image_url").is_none());
    }

    #[test]
    fn transform_request_errors_on_text_content_part_missing_text() {
        let msg = ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Parts(vec![ContentPart {
                content_type: "text".to_string(),
                text: None,
                image_url: None,
            }]),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        };
        let request = ChatCompletionRequest {
            model: "claude-opus-4-6".to_string(),
            messages: vec![msg],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };

        let err = AnthropicAdapter::new()
            .transform_request(&request)
            .expect_err("missing text part content must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("missing string 'text'"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_unknown_content_part_type() {
        let msg = ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Parts(vec![ContentPart {
                content_type: "input_audio".to_string(),
                text: None,
                image_url: None,
            }]),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        };
        let request = ChatCompletionRequest {
            model: "claude-opus-4-6".to_string(),
            messages: vec![msg],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };

        let err = AnthropicAdapter::new()
            .transform_request(&request)
            .expect_err("unknown content part must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("content part type"), "{msg}");
                assert!(!msg.contains("input_audio"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    // --- Regression tests for crosslink #338 ---

    #[cfg(feature = "experimental-claude-subscription-auth")]
    #[test]
    fn oauth_headers_contains_all_required_fields() {
        std::env::set_var(
            crate::claude_credentials::EXPERIMENTAL_DIRECT_SUBSCRIPTION_ENV,
            crate::claude_credentials::EXPERIMENTAL_DIRECT_SUBSCRIPTION_ACK,
        );
        let token =
            crate::secrets::OAuthToken::try_from_string("access-xyz".to_string()).expect("token");
        let h = AnthropicAdapter::oauth_headers(&token).expect("experimental headers");
        assert!(h.contains_name("authorization"));
        assert!(h.contains_name("anthropic-beta"));
        assert!(h.contains_name("anthropic-version"));
        assert!(h.contains_name("content-type"));
        assert!(h.matches_value("authorization", "Bearer access-xyz"));
        assert!(h.matches_value(
            "anthropic-beta",
            &crate::claude_credentials::claude_code_beta_header_value()
                .expect("experimental beta value")
        ));
    }

    // --- Regression tests for crosslink #413 ---
    //
    // Before the fix, the Anthropic adapter silently swallowed malformed
    // upstream / caller input via `filter_map(|x| x.as_str().map(...))`
    // and substituted `"msg_unknown"` / `"unknown"` / `0` sentinels when
    // top-level fields were missing. That made every contract violation
    // by the Anthropic API (or by an upstream caller) invisible to tests
    // and to downstream clients. The tests below pin the new behaviour:
    // each malformed input must produce a typed error.

    fn anth_request_with_tools(tools: Vec<Value>) -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "claude-opus-4-7".to_string(),
            messages: vec![text_msg("user", "go")],
            max_tokens: Some(64),
            temperature: None,
            tools: Some(tools),
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        }
    }

    /// A tool missing `function.name` MUST surface as
    /// `ProviderError::RequestFailed` — never silently dropped from the
    /// request body sent to Anthropic.
    #[test]
    fn transform_request_errors_on_tool_missing_function_name() {
        let bad_tool = json!({
            "type": "function",
            "function": { "description": "no name here" }
        });
        let req = anth_request_with_tools(vec![bad_tool]);
        let err = AnthropicAdapter::new()
            .transform_request(&req)
            .expect_err("malformed tool must surface (#413)");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(
                    msg.contains("function.name"),
                    "error must name the missing field, got: {msg}"
                );
                assert!(
                    msg.contains("index 0"),
                    "error must locate the offending tool, got: {msg}"
                );
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    /// A tool missing the `function` object entirely also surfaces — this
    /// previously took the `filter_map`'s short-circuit `?` path silently.
    /// The bad tool is the *second* of two; asserting on index 1 proves we
    /// walk the array rather than rejecting any batch indiscriminately.
    #[test]
    fn transform_request_errors_on_tool_missing_function_object() {
        let good_tool = json!({
            "type": "function",
            "function": {"name": "ok_tool", "parameters": {}}
        });
        let bad_tool = json!({"type": "function"});
        let req = anth_request_with_tools(vec![good_tool, bad_tool]);
        let err = AnthropicAdapter::new()
            .transform_request(&req)
            .expect_err("malformed tool must surface (#413)");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(
                    msg.contains("'function' object") && msg.contains("index 1"),
                    "error must name field and index, got: {msg}"
                );
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    /// An empty `function.name` (present but blank string) is just as
    /// malformed as missing — Anthropic would 400 on this anyway and we
    /// should not let it through with a default.
    #[test]
    fn transform_request_errors_on_tool_with_empty_function_name() {
        let bad_tool = json!({
            "type": "function",
            "function": {"name": "", "parameters": {}}
        });
        let req = anth_request_with_tools(vec![bad_tool]);
        let err = AnthropicAdapter::new()
            .transform_request(&req)
            .expect_err("empty function.name must surface (#413)");
        assert!(matches!(err, ProviderError::RequestFailed(_)));
    }

    /// An empty `{}` upstream response — the exact case the issue's
    /// Mandated Refactor item 4 asks us to pin — MUST return Err, not a
    /// successful response laden with `"msg_unknown"` / `"unknown"`.
    #[test]
    fn transform_response_errors_on_empty_object_no_sentinels() {
        let response = json!({});
        let result = AnthropicAdapter::new().transform_response(response, false);
        let err = result.expect_err("empty upstream response must be an error (#413)");
        match err {
            ProviderError::InvalidResponse(msg) => {
                // The first missing required field is `id`; confirm we
                // surface the *field name* not just a generic error.
                assert!(
                    msg.contains("'id'"),
                    "error must name the missing field, got: {msg}"
                );
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    /// A response missing only `model` (but with valid `id`, `stop_reason`,
    /// `content`) must error with the specific missing-field name — proving
    /// we don't fall back to the `"unknown"` sentinel that previously
    /// masked the upstream defect.
    #[test]
    fn transform_response_errors_on_missing_model_no_sentinel() {
        let response = json!({
            "id": "msg_abc",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let err = AnthropicAdapter::new()
            .transform_response(response, false)
            .expect_err("missing 'model' must surface (#413)");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(
                    msg.contains("'model'"),
                    "error must name the missing field, got: {msg}"
                );
                // And critically, no sentinel leaked into the error.
                assert!(!msg.contains("unknown"), "must not fall back to 'unknown'");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    /// A `tool_use` content block missing `id` or `name` previously got
    /// silently `filter_map`'d out, leaving the assistant message with no
    /// `tool_calls` — a state the downstream `OpenAI`-shape client treats as
    /// "no tools were called", which is a security-relevant lie. Pin the
    /// new behaviour: error, with the offending block index.
    #[test]
    fn transform_response_errors_on_tool_use_block_missing_name() {
        let response = json!({
            "id": "msg_xyz",
            "model": "claude-opus-4-7",
            "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "calling..."},
                {"type": "tool_use", "id": "tu_1", "input": {"x": 1}}
            ],
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let err = AnthropicAdapter::new()
            .transform_response(response, false)
            .expect_err("malformed tool_use block must surface (#413)");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(
                    msg.contains("tool_use") && msg.contains("'name'") && msg.contains("index 1"),
                    "error must name field and index, got: {msg}"
                );
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    /// A well-formed response still round-trips cleanly — the strictness
    /// must not break the happy path.
    #[test]
    fn transform_response_happy_path_still_works() {
        let response = json!({
            "id": "msg_happy",
            "model": "claude-opus-4-7",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": "ok"}],
            "usage": {"input_tokens": 3, "output_tokens": 2}
        });
        let out = AnthropicAdapter::new()
            .transform_response(response, false)
            .expect("well-formed response transforms");
        assert_eq!(out["id"], "msg_happy");
        assert_eq!(out["model"], "claude-opus-4-7");
        assert_eq!(out["choices"][0]["message"]["content"], "ok");
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 3);
        assert_eq!(out["usage"]["completion_tokens"], 2);
        assert_eq!(out["usage"]["total_tokens"], 5);
    }

    /// `convert_tools_checked` is the fallible primitive that powers the
    /// strict request path; pin its error shape directly so future
    /// refactors of `transform_request` cannot quietly skip validation.
    #[test]
    fn convert_tools_checked_errors_on_malformed_input() {
        let tools = vec![json!({"type": "function", "function": {}})];
        let err = convert_tools_to_anthropic_checked(&tools)
            .expect_err("missing function.name must surface (#413)");
        assert!(matches!(err, ProviderError::RequestFailed(_)));
    }

    #[test]
    fn convert_tool_definitions_checked_errors_on_non_array() {
        let err = convert_tool_definitions_to_anthropic_checked(&json!({
            "not": "tools",
            "credential": "anthropic-registry-secret-sentinel"
        }))
        .expect_err("non-array tool registry must fail closed");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("JSON array"), "{msg}");
                assert!(!msg.contains("anthropic-registry-secret-sentinel"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn convert_tool_definitions_checked_errors_on_malformed_entry() {
        let err = convert_tool_definitions_to_anthropic_checked(&json!([
            {"type": "function", "function": {}}
        ]))
        .expect_err("malformed tool registry entry must fail closed");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }
}

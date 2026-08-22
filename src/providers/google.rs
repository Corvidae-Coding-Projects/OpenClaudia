//! Google Gemini API adapter.

use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::debug;

use crate::config::ThinkingConfig;
use crate::proxy::{ChatCompletionRequest, ChatMessage, ContentPart, MessageContent};
use crate::session::TokenUsage;

use super::{ProviderAdapter, ProviderError};

/// Build a deterministic Gemini tool-call id from `(ordinal, function name)`.
///
/// Crosslink #785: parsing the same Gemini response twice must produce the
/// same `tool_calls[i].id` so callers can cache / diff / log-correlate
/// without burning an entry per re-parse. The ordinal prefix disambiguates
/// repeated calls to the same function in a single turn.
fn gemini_tool_call_id(ordinal: usize, function_name: &str) -> String {
    format!("call_{ordinal}_{function_name}")
}

/// Adapt the JSON Schema keywords used by the canonical registry to Gemini's
/// `parametersJsonSchema` dialect.
///
/// Gemini does not accept JSON Schema's `const` keyword for function
/// declarations. A one-element `enum` has the same model-facing constraint;
/// canonical host validation remains authoritative when the call returns.
fn normalize_gemini_json_schema(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };

    if let Some(constant) = object.remove("const") {
        object.insert("enum".to_string(), Value::Array(vec![constant]));
    }

    for map_key in ["properties", "$defs", "definitions", "patternProperties"] {
        if let Some(children) = object.get_mut(map_key).and_then(Value::as_object_mut) {
            for child in children.values_mut() {
                normalize_gemini_json_schema(child);
            }
        }
    }

    for schema_key in [
        "items",
        "additionalProperties",
        "not",
        "contains",
        "propertyNames",
        "if",
        "then",
        "else",
    ] {
        if let Some(child) = object.get_mut(schema_key) {
            normalize_gemini_json_schema(child);
        }
    }

    for schema_array_key in ["anyOf", "oneOf", "allOf", "prefixItems"] {
        if let Some(children) = object
            .get_mut(schema_array_key)
            .and_then(Value::as_array_mut)
        {
            for child in children {
                normalize_gemini_json_schema(child);
            }
        }
    }
}

/// Convert `OpenAI` tools to Gemini function declarations.
///
/// # Errors
///
/// Returns [`ProviderError::RequestFailed`] when a tool definition is missing
/// a `function` object, a non-empty `function.name`, or contains malformed
/// optional `function.description` / `function.parameters` fields.
pub fn convert_tools_to_gemini_functions(tools: &[Value]) -> Result<Vec<Value>, ProviderError> {
    let mut functions = Vec::with_capacity(tools.len());

    for (index, tool) in tools.iter().enumerate() {
        let func = tool
            .get("function")
            .filter(|value| value.is_object())
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Tool at index {index} missing required 'function' object"
                ))
            })?;

        let name = func
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Tool at index {index} missing non-empty string 'function.name'"
                ))
            })?;

        let description = match func.get("description") {
            None => json!(""),
            Some(value @ Value::String(_)) => value.clone(),
            Some(_) => {
                return Err(ProviderError::RequestFailed(format!(
                    "Tool at index {index} has non-string 'function.description'"
                )));
            }
        };

        let mut parameters_json_schema = match func.get("parameters") {
            None => json!({}),
            Some(value @ Value::Object(_)) => value.clone(),
            Some(_) => {
                return Err(ProviderError::RequestFailed(format!(
                    "Tool at index {index} has non-object 'function.parameters'"
                )));
            }
        };
        normalize_gemini_json_schema(&mut parameters_json_schema);

        functions.push(json!({
            "name": name,
            "description": description,
            "parametersJsonSchema": parameters_json_schema
        }));
    }

    Ok(functions)
}

/// Convert `OpenAI` tools to Gemini's top-level `tools` array.
///
/// # Errors
///
/// Returns [`ProviderError::RequestFailed`] when any tool definition is
/// malformed.
pub fn convert_tools_to_gemini(tools: &[Value]) -> Result<Value, ProviderError> {
    let functions = convert_tools_to_gemini_functions(tools)?;
    Ok(json!([{"functionDeclarations": functions}]))
}

/// Google Gemini API adapter
pub struct GoogleAdapter;

impl GoogleAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convert `OpenAI` messages to Gemini format
    fn convert_messages(messages: &[ChatMessage]) -> Result<Vec<Value>, ProviderError> {
        let mut converted = Vec::new();

        for (msg_index, message) in messages.iter().enumerate() {
            if message.role == "system" {
                // System handled via systemInstruction.
                continue;
            }

            let role = match message.role.as_str() {
                "assistant" => "model",
                _ => "user",
            };

            let parts = match &message.content {
                MessageContent::Text(text) => json!([{"text": text}]),
                MessageContent::Parts(parts) => {
                    json!(Self::convert_content_parts(
                        msg_index,
                        &message.role,
                        parts
                    )?)
                }
            };

            converted.push(json!({
                "role": role,
                "parts": parts
            }));
        }

        Ok(converted)
    }

    fn convert_content_parts(
        msg_index: usize,
        _role: &str,
        parts: &[ContentPart],
    ) -> Result<Vec<Value>, ProviderError> {
        let mut converted = Vec::with_capacity(parts.len());

        for (part_index, part) in parts.iter().enumerate() {
            match part.content_type.as_str() {
                "text" => {
                    let text = part.text.as_ref().ok_or_else(|| {
                        ProviderError::RequestFailed(format!(
                            "Google message at index {msg_index} text part at \
                             index {part_index} missing 'text'"
                        ))
                    })?;
                    converted.push(json!({"text": text}));
                }
                "image" | "image_url" => {
                    let image = part.image_url.as_ref().ok_or_else(|| {
                        ProviderError::RequestFailed(format!(
                            "Google message at index {msg_index} image part at \
                             index {part_index} missing 'image_url'"
                        ))
                    })?;
                    converted.push(json!({"inlineData": image}));
                }
                _ => {
                    return Err(ProviderError::RequestFailed(format!(
                        "Unsupported Google content part type at message index {msg_index}, \
                         part index {part_index}"
                    )));
                }
            }
        }

        if converted.is_empty() {
            return Err(ProviderError::RequestFailed(format!(
                "Google message at index {msg_index} has no content parts"
            )));
        }

        Ok(converted)
    }

    /// Extract system instruction.
    ///
    /// Crosslink #924: previously `.iter().find(...)` returned only the
    /// FIRST `system` role message. Gemini accepts a single
    /// `systemInstruction.parts[]`, so we concatenate every system-role
    /// text with `\n\n` separators rather than silently dropping later
    /// ones. Non-text parts surface a `warn!`.
    fn extract_system(messages: &[ChatMessage]) -> Option<Value> {
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
            tracing::warn!("google::extract_system dropped non-text parts from a system message");
        }
        if pieces.is_empty() {
            None
        } else {
            let text = pieces.join("\n\n");
            Some(json!({"parts": [{"text": text}]}))
        }
    }
}

impl Default for GoogleAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for GoogleAdapter {
    fn name(&self) -> &'static str {
        "google"
    }

    fn transform_request(&self, request: &ChatCompletionRequest) -> Result<Value, ProviderError> {
        let mut body = json!({
            "contents": Self::convert_messages(&request.messages)?
        });

        // Add system instruction if present
        if let Some(system) = Self::extract_system(&request.messages) {
            body["systemInstruction"] = system;
        }

        // Add generation config
        let mut gen_config = json!({});
        if let Some(temp) = request.temperature {
            gen_config["temperature"] = json!(temp);
        }
        if let Some(max_tokens) = request.max_tokens {
            gen_config["maxOutputTokens"] = json!(max_tokens);
        }
        if gen_config != json!({}) {
            body["generationConfig"] = gen_config;
        }

        // Convert tools
        if let Some(tools) = &request.tools {
            body["tools"] = convert_tools_to_gemini(tools)?;
        }

        debug!("Transformed request for Google");
        Ok(body)
    }

    fn transform_request_with_thinking(
        &self,
        request: &ChatCompletionRequest,
        thinking: &ThinkingConfig,
    ) -> Result<Value, ProviderError> {
        let mut body = self.transform_request(request)?;

        // Add Google Gemini thinking config if enabled
        // See: https://ai.google.dev/gemini-api/docs/thinking
        if thinking.enabled {
            // Crosslink #599: route through effective_budget so the
            // adaptive medium/high preset applies when only
            // `reasoning_effort` is set. Gemini caps at 32768; the
            // adaptive ceiling of 16000 is well under that, and an
            // explicit budget over 32768 is clamped here.
            let budget = thinking.effective_budget(8192).min(32768);

            // Ensure generationConfig exists
            if body.get("generationConfig").is_none() {
                body["generationConfig"] = json!({});
            }

            body["generationConfig"]["thinkingConfig"] = json!({
                "thinkingBudget": budget
            });
            debug!("Added Google thinking params: budget={}", budget);
        }

        Ok(body)
    }

    fn transform_response(&self, response: Value, _stream: bool) -> Result<Value, ProviderError> {
        // Check for API error responses before extracting candidates
        if let Some(error) = response.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .filter(|message| !message.is_empty())
                .ok_or_else(|| {
                    ProviderError::InvalidResponse(
                        "Gemini API error missing non-empty string 'message'".to_string(),
                    )
                })?;
            let code = error
                .get("code")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let _ = message;
            return Err(ProviderError::InvalidResponse(format!(
                "Gemini API returned error code {code}"
            )));
        }

        // Extract content from Gemini response
        let candidate = response
            .get("candidates")
            .and_then(|c| c.get(0))
            .ok_or_else(|| {
                ProviderError::InvalidResponse("No candidates in response".to_string())
            })?;

        let parts = candidate
            .get("content")
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ProviderError::InvalidResponse(
                    "Gemini candidate missing content.parts array".to_string(),
                )
            })?;
        let content = extract_gemini_text_content(parts)?;

        let tool_calls = extract_gemini_tool_calls(parts)?;

        let mut message = json!({
            "role": "assistant",
            "content": content
        });

        if let Some(calls) = tool_calls {
            message["tool_calls"] = json!(calls);
        }

        let finish_reason = candidate
            .get("finishReason")
            .and_then(|r| r.as_str())
            .map_or("stop", |r| match r {
                "MAX_TOKENS" => "length",
                "SAFETY" => "content_filter",
                _ => "stop",
            });

        Ok(json!({
            "id": format!("gemini-{}", uuid::Uuid::new_v4()),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": "gemini",
            "choices": [{
                "index": 0,
                "message": message,
                "finish_reason": finish_reason
            }],
            "usage": {
                "prompt_tokens": response.get("usageMetadata").and_then(|u| u.get("promptTokenCount")).cloned().unwrap_or_else(|| json!(0)),
                "completion_tokens": response.get("usageMetadata").and_then(|u| u.get("candidatesTokenCount")).cloned().unwrap_or_else(|| json!(0)),
                "total_tokens": response.get("usageMetadata").and_then(|u| u.get("totalTokenCount")).cloned().unwrap_or_else(|| json!(0))
            }
        }))
    }

    fn chat_endpoint(&self, model: &str) -> String {
        // Gemini uses model name in the URL path
        format!("/v1beta/models/{model}:generateContent")
    }

    /// Gemini exposes streaming on a distinct URL path
    /// (`:streamGenerateContent?alt=sse`) rather than via a request-body
    /// `stream` flag. The pipeline switches to this endpoint when
    /// streaming is requested. See crosslink #602.
    fn stream_endpoint(&self, model: &str) -> Option<String> {
        Some(format!(
            "/v1beta/models/{model}:streamGenerateContent?alt=sse"
        ))
    }

    fn get_headers(&self, api_key: &super::ApiKey) -> crate::secrets::SensitiveHeaders {
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_header_secret(
            reqwest::header::HeaderName::from_static("x-goog-api-key"),
            api_key.secret(),
        );
        headers.insert_static_literal(reqwest::header::CONTENT_TYPE, "application/json");
        headers
    }

    /// Gemini native shape: `candidates[0].content.parts[].text`. Text
    /// parts are concatenated so the result matches what
    /// [`Self::transform_response`] would surface to the proxy hot
    /// path. See crosslink #479.
    fn extract_response_text(&self, response: &Value) -> Option<String> {
        let parts = response
            .get("candidates")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.as_array())?;
        let joined: String = parts
            .iter()
            .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
            .collect();
        if joined.is_empty() {
            None
        } else {
            Some(joined)
        }
    }

    /// Gemini `usageMetadata` envelope: `promptTokenCount`,
    /// `candidatesTokenCount`, `cachedContentTokenCount` (mapped to
    /// `cache_read_tokens`). Gemini exposes no cache-write counter, so
    /// that field is reported as zero rather than fabricated.
    /// See crosslink #479.
    fn extract_token_usage(&self, response: &Value) -> Option<TokenUsage> {
        let usage = response.get("usageMetadata")?;
        Some(TokenUsage {
            input_tokens: usage
                .get("promptTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: usage
                .get("candidatesTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            cache_read_tokens: usage
                .get("cachedContentTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            cache_write_tokens: 0,
        })
    }
}

fn extract_gemini_tool_calls(parts: &[Value]) -> Result<Option<Vec<Value>>, ProviderError> {
    let mut calls = Vec::new();

    for part in parts {
        let Some(func_call) = part.get("functionCall") else {
            continue;
        };

        if !func_call.is_object() {
            return Err(ProviderError::InvalidResponse(
                "Gemini functionCall must be an object".to_string(),
            ));
        }

        let name = func_call
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                ProviderError::InvalidResponse(
                    "Gemini functionCall missing non-empty string 'name'".to_string(),
                )
            })?;

        let args = func_call.get("args").ok_or_else(|| {
            ProviderError::InvalidResponse("Gemini functionCall missing object 'args'".to_string())
        })?;

        if !args.is_object() {
            return Err(ProviderError::InvalidResponse(format!(
                "Gemini functionCall has non-object 'args': expected JSON object, got {}",
                args_type_name(args)
            )));
        }

        let args = serde_json::to_string(args).map_err(|e| {
            ProviderError::InvalidResponse(format!(
                "Gemini functionCall has unserializable 'args': {e}"
            ))
        })?;

        let ordinal = calls.len();
        calls.push(json!({
            "id": gemini_tool_call_id(ordinal, name),
            "type": "function",
            "function": {
                "name": name,
                "arguments": args,
            }
        }));
    }

    Ok((!calls.is_empty()).then_some(calls))
}

const fn args_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Extract and concatenate text from Gemini `content.parts`.
///
/// Text parts must contain string `text`; native `functionCall` parts are
/// allowed and skipped. Any other part shape is rejected so malformed provider
/// payloads do not become silent empty assistant messages.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidResponse`] when a text part is not a string
/// or when a part has neither supported text nor native function-call content.
pub fn extract_gemini_text_content(parts: &[Value]) -> Result<String, ProviderError> {
    let mut content = String::new();

    for (index, part) in parts.iter().enumerate() {
        if let Some(text_value) = part.get("text") {
            let text = text_value.as_str().ok_or_else(|| {
                ProviderError::InvalidResponse(format!(
                    "Gemini content part at index {index} has non-string 'text'"
                ))
            })?;
            content.push_str(text);
            continue;
        }

        if part.get("functionCall").is_some() {
            continue;
        }

        return Err(ProviderError::InvalidResponse(format!(
            "Gemini content part at index {index} has no supported text or functionCall field"
        )));
    }

    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{ChatCompletionRequest, ChatMessage, ContentPart, MessageContent};

    fn google_request_with_tools(tools: Vec<Value>) -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Text("run a tool".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            max_tokens: Some(64),
            temperature: None,
            tools: Some(tools),
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn convert_tools_to_gemini_functions_accepts_valid_tool() {
        let tools = vec![json!({
            "type": "function",
            "function": {
                "name": "bash",
                "description": "run shell",
                "parameters": {"type": "object"}
            }
        })];

        let functions =
            convert_tools_to_gemini_functions(&tools).expect("valid tool should convert");

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0]["name"], "bash");
        assert_eq!(functions[0]["description"], "run shell");
        assert_eq!(functions[0]["parametersJsonSchema"]["type"], "object");
        assert!(functions[0].get("parameters").is_none());
    }

    #[test]
    fn convert_tools_to_gemini_rewrites_nested_const_constraints() {
        let tools = vec![json!({
            "type": "function",
            "function": {
                "name": "tool_search",
                "parameters": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "catalog_generation": {
                            "type": "string",
                            "const": "sha256:bound"
                        },
                        "policy": {
                            "oneOf": [
                                {"const": "private"},
                                {"const": "team"}
                            ]
                        },
                        "const": {"type": "string"}
                    }
                }
            }
        })];

        let functions =
            convert_tools_to_gemini_functions(&tools).expect("valid tool should convert");
        let schema = &functions[0]["parametersJsonSchema"];

        assert_eq!(
            schema["properties"]["catalog_generation"]["enum"],
            json!(["sha256:bound"])
        );
        assert_eq!(
            schema["properties"]["policy"]["oneOf"][0]["enum"],
            json!(["private"])
        );
        assert_eq!(schema["properties"]["const"]["type"], "string");
        assert!(
            schema
                .pointer("/properties/catalog_generation/const")
                .is_none(),
            "Gemini schema must not retain unsupported const"
        );
        assert_eq!(schema["additionalProperties"], false);
    }

    #[test]
    fn transform_request_errors_on_tool_missing_function_object() {
        let request = google_request_with_tools(vec![json!({
            "type": "function",
            "credential": "google-tool-secret-sentinel"
        })]);
        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("missing function object must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("'function' object"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
                assert!(!msg.contains("google-tool-secret-sentinel"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_tool_missing_function_name() {
        let request = google_request_with_tools(vec![json!({
            "type": "function",
            "function": {"parameters": {}}
        })]);
        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("missing function.name must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_tool_with_malformed_optional_fields() {
        let request = google_request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bad", "description": 123}
        })]);
        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("non-string function.description must fail");
        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("description"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }

        let request = google_request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bad", "parameters": []}
        })]);
        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("non-object function.parameters must fail");
        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("parameters"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_concatenates_text_parts_and_keeps_tool_calls() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "hello "},
                        {"functionCall": {"name": "bash", "args": {"command": "pwd"}}},
                        {"text": "world"}
                    ]
                },
                "finishReason": "STOP"
            }]
        });

        let parsed = GoogleAdapter::new()
            .transform_response(body, false)
            .expect("valid mixed response should parse");

        assert_eq!(parsed["choices"][0]["message"]["content"], "hello world");
        let calls = parsed["choices"][0]["message"]["tool_calls"]
            .as_array()
            .expect("tool calls should be preserved");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["function"]["name"], "bash");
    }

    #[test]
    fn transform_response_errors_on_missing_content_parts() {
        let body = json!({
            "candidates": [{
                "content": {}
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("missing content.parts must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("content.parts"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_non_string_text_part() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": 123}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("non-string text part must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("'text'"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_unsupported_part_shape() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"inlineData": {"mimeType": "image/png", "data": "..."}}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("unsupported response part must fail");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("supported text or functionCall"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    /// #785: parsing the same Gemini response twice must yield identical
    /// `tool_calls[*].id` so callers can correlate / cache / diff across
    /// re-parses. The pre-fix code generated a fresh `Uuid::new_v4()`
    /// every time, so two parses of the same payload never matched.
    #[test]
    fn tool_call_ids_are_deterministic_across_reparses() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash", "args": {"command": "ls"}}},
                        {"functionCall": {"name": "read", "args": {"path": "src/lib.rs"}}}
                    ]
                }
            }]
        });
        let adapter = GoogleAdapter::new();
        let a = adapter.transform_response(body.clone(), false).unwrap();
        let b = adapter.transform_response(body, false).unwrap();
        let ids_a: Vec<&str> = a["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        let ids_b: Vec<&str> = b["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids_a, ids_b, "#785: re-parse must yield identical ids");
        // The shape is `call_<ordinal>_<name>`.
        assert_eq!(ids_a, vec!["call_0_bash", "call_1_read"]);
    }

    /// #785: two consecutive calls to the same function in a single turn
    /// must produce distinct ids — the ordinal disambiguates.
    #[test]
    fn repeated_function_calls_get_distinct_ordinal_ids() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash", "args": {"command": "ls"}}},
                        {"functionCall": {"name": "bash", "args": {"command": "pwd"}}}
                    ]
                }
            }]
        });
        let parsed = GoogleAdapter::new()
            .transform_response(body, false)
            .unwrap();
        let calls = parsed["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["id"], "call_0_bash");
        assert_eq!(calls[1]["id"], "call_1_bash");
        assert_ne!(calls[0]["id"], calls[1]["id"]);
    }

    #[test]
    fn transform_response_errors_on_function_call_missing_name() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"args": {"command": "ls"}}}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("missing Gemini functionCall name must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("functionCall"), "{msg}");
                assert!(msg.contains("name"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_function_call_missing_args() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash"}}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("missing Gemini functionCall args must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("functionCall"), "{msg}");
                assert!(msg.contains("args"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_non_object_function_call_args() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash", "args": []}}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("non-object Gemini functionCall args must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("args"), "{msg}");
                assert!(msg.contains("object"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    /// #850: a `ContentPart` with neither `text` nor `image_url` used to be
    /// silently coerced or dropped. The request boundary now rejects it so the
    /// caller sees the unsupported multimodal contract immediately.
    #[test]
    fn transform_request_converts_text_and_image_parts() {
        let request = ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Parts(vec![
                    ContentPart {
                        content_type: "text".to_string(),
                        text: Some("describe this".to_string()),
                        image_url: None,
                    },
                    ContentPart {
                        content_type: "image_url".to_string(),
                        text: None,
                        image_url: Some(json!({
                            "mimeType": "image/png",
                            "data": "iVBORw..."
                        })),
                    },
                ]),
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

        let body = GoogleAdapter::new()
            .transform_request(&request)
            .expect("valid multimodal Gemini request should transform");
        let parts = body["contents"][0]["parts"]
            .as_array()
            .expect("parts array");
        assert_eq!(parts[0], json!({"text": "describe this"}));
        assert_eq!(parts[1]["inlineData"]["mimeType"], "image/png");
        assert_eq!(parts[1]["inlineData"]["data"], "iVBORw...");
    }

    #[test]
    fn transform_request_errors_on_unknown_content_part_type() {
        let msg = ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Parts(vec![
                ContentPart {
                    content_type: "text".to_string(),
                    text: Some("hello".to_string()),
                    image_url: None,
                },
                ContentPart {
                    // Unrecognized variant — neither text nor image_url set.
                    content_type: "video_url".to_string(),
                    text: None,
                    image_url: None,
                },
            ]),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        };
        let request = ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![msg],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };

        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("unknown Google content part must fail request conversion");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("content part type"), "{msg}");
                assert!(!msg.contains("video_url"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_text_part_missing_text() {
        let request = ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![ChatMessage {
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
            }],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };

        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("missing Google text part text must fail request conversion");

        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("missing 'text'"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_image_part_missing_image_url() {
        let request = ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Parts(vec![ContentPart {
                    content_type: "image_url".to_string(),
                    text: None,
                    image_url: None,
                }]),
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

        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("missing Google image_url must fail request conversion");

        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("image_url"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    // ── crosslink #602 — stream_endpoint / supports_streaming overrides ─────

    /// `#602-a`: Google overrides `stream_endpoint` with the SSE-specific
    /// path (`:streamGenerateContent?alt=sse`) and embeds the model name.
    /// Pins the URL shape so the pipeline can switch endpoints when
    /// streaming is requested.
    #[test]
    fn issue_602_google_stream_endpoint_uses_sse_path() {
        let adapter = GoogleAdapter::new();
        let endpoint = adapter
            .stream_endpoint("gemini-2.5-pro")
            .expect("Google must expose a streaming endpoint");
        assert_eq!(
            endpoint, "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
            "Google streaming URL must include model + :streamGenerateContent + alt=sse"
        );
    }

    /// `#602-b`: the streaming URL is distinct from the non-streaming
    /// `chat_endpoint`, and `supports_streaming` is true.
    #[test]
    fn issue_602_google_streaming_distinct_from_chat_endpoint() {
        let adapter = GoogleAdapter::new();
        let chat = adapter.chat_endpoint("gemini-2.5-flash");
        let stream = adapter.stream_endpoint("gemini-2.5-flash").unwrap();
        assert_ne!(chat, stream, "stream and non-stream endpoints must differ");
        assert!(chat.ends_with(":generateContent"));
        assert!(stream.contains(":streamGenerateContent"));
        assert!(adapter.supports_streaming());
    }

    /// `#602-c`: other providers inherit the default — `stream_endpoint`
    /// returns None, signalling "use the same URL with stream:true".
    /// Pins that Google is the only override.
    #[test]
    fn issue_602_other_providers_default_to_none_stream_endpoint() {
        use crate::providers::{
            AnthropicAdapter, DeepSeekAdapter, KimiAdapter, MiniMaxAdapter, OllamaAdapter,
            OpenAIAdapter, ProviderAdapter, QwenAdapter, ZaiAdapter,
        };
        let anthropic = AnthropicAdapter::new();
        let openai = OpenAIAdapter::new();
        let deepseek = DeepSeekAdapter::new();
        let qwen = QwenAdapter::new();
        let zai = ZaiAdapter::new();
        let kimi = KimiAdapter::new();
        let minimax = MiniMaxAdapter::new();
        let ollama = OllamaAdapter::new();
        let cases: Vec<(&str, &dyn ProviderAdapter)> = vec![
            ("anthropic", &anthropic),
            ("openai", &openai),
            ("deepseek", &deepseek),
            ("qwen", &qwen),
            ("zai", &zai),
            ("kimi", &kimi),
            ("minimax", &minimax),
            ("ollama", &ollama),
        ];
        for (name, adapter) in cases {
            assert!(
                adapter.stream_endpoint("any-model").is_none(),
                "{name}: default stream_endpoint must be None — only Google overrides (#602)"
            );
            assert!(
                adapter.supports_streaming(),
                "{name}: every wired provider must report supports_streaming=true"
            );
        }
    }
}

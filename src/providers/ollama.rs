//! Ollama API adapter for local LLM inference.
//!
//! See: <https://github.com/ollama/ollama/blob/main/docs/api.md>

use async_trait::async_trait;
use serde_json::{json, Value};
use tracing::debug;

use crate::proxy::{ChatCompletionRequest, ChatMessage, ContentPart, MessageContent};
use crate::session::TokenUsage;

use super::{ProviderAdapter, ProviderError};

/// Ollama API adapter for local LLM inference
/// See: <https://github.com/ollama/ollama/blob/main/docs/api.md>
pub struct OllamaAdapter;

impl OllamaAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convert `OpenAI` messages to Ollama format
    fn convert_messages(messages: &[ChatMessage]) -> Result<Vec<Value>, ProviderError> {
        messages
            .iter()
            .enumerate()
            .map(|(msg_index, m)| {
                let content = match &m.content {
                    MessageContent::Text(t) => t.clone(),
                    MessageContent::Parts(parts) => {
                        convert_multipart_message_content(msg_index, &m.role, parts)?
                    }
                };

                Ok(json!({
                    "role": m.role,
                    "content": content
                }))
            })
            .collect()
    }
}

fn convert_multipart_message_content(
    msg_index: usize,
    _role: &str,
    parts: &[ContentPart],
) -> Result<String, ProviderError> {
    let mut text_parts = Vec::new();

    for (part_index, part) in parts.iter().enumerate() {
        if let Some(text) = &part.text {
            text_parts.push(text.clone());
            continue;
        }

        if part.content_type == "text" {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama message at index {msg_index} has text content part at \
                 index {part_index} without string 'text'"
            )));
        }

        if part.content_type == "image_url" || part.image_url.is_some() {
            return Err(ProviderError::Unsupported(format!(
                "Ollama adapter does not support image content parts; message index {msg_index}, \
                 part index {part_index}"
            )));
        }

        return Err(ProviderError::Unsupported(format!(
            "Ollama adapter does not support this content part type at message index \
             {msg_index}, part index {part_index}"
        )));
    }

    Ok(text_parts.join("\n"))
}

impl Default for OllamaAdapter {
    fn default() -> Self {
        Self::new()
    }
}

fn convert_tools_checked(tools: &[Value]) -> Result<Vec<Value>, ProviderError> {
    let mut out = Vec::with_capacity(tools.len());

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

        let parameters = match func.get("parameters") {
            None => json!({}),
            Some(value @ Value::Object(_)) => value.clone(),
            Some(_) => {
                return Err(ProviderError::RequestFailed(format!(
                    "Tool at index {index} has non-object 'function.parameters'"
                )));
            }
        };

        out.push(json!({
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters
            }
        }));
    }

    Ok(out)
}

#[async_trait]
impl ProviderAdapter for OllamaAdapter {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn state_contract(
        &self,
        protocol: crate::runtime::ProviderWireProtocol,
    ) -> Result<&'static crate::runtime::ProviderStateContract, ProviderError> {
        match protocol {
            crate::runtime::ProviderWireProtocol::OllamaChat => Ok(&super::OLLAMA_STATE_CONTRACT),
            other => Err(super::unsupported_state_protocol(self.name(), other)),
        }
    }

    fn transform_request(&self, request: &ChatCompletionRequest) -> Result<Value, ProviderError> {
        let mut body = json!({
            "model": &request.model,
            "messages": Self::convert_messages(&request.messages)?,
            "stream": request.stream.unwrap_or(false)
        });

        // Add options for temperature and other settings
        let mut options = json!({});
        if let Some(temp) = request.temperature {
            options["temperature"] = json!(temp);
        }
        if let Some(max_tokens) = request.max_tokens {
            options["num_predict"] = json!(max_tokens);
        }
        if options != json!({}) {
            body["options"] = options;
        }

        // Convert tools to Ollama format if present
        if let Some(tools) = &request.tools {
            let ollama_tools = convert_tools_checked(tools)?;
            if !ollama_tools.is_empty() {
                body["tools"] = json!(ollama_tools);
            }
        }

        debug!("Transformed request for Ollama");
        Ok(body)
    }

    fn transform_response(&self, response: Value, _stream: bool) -> Result<Value, ProviderError> {
        // Ollama response format:
        // {"model": "...", "message": {"role": "assistant", "content": "..."}, "done": true, ...}
        let model = response
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| !model.is_empty())
            .ok_or_else(|| {
                ProviderError::InvalidResponse(
                    "Ollama response missing non-empty string 'model'".to_string(),
                )
            })?;
        let message = response
            .get("message")
            .filter(|message| message.is_object())
            .ok_or_else(|| {
                ProviderError::InvalidResponse(
                    "Ollama response missing object 'message'".to_string(),
                )
            })?;

        let role = message
            .get("role")
            .and_then(Value::as_str)
            .filter(|role| !role.is_empty())
            .ok_or_else(|| {
                ProviderError::InvalidResponse(
                    "Ollama response message missing non-empty string 'role'".to_string(),
                )
            })?;
        if role != "assistant" {
            return Err(ProviderError::InvalidResponse(
                "Ollama response message has unsupported role; expected 'assistant'".to_string(),
            ));
        }

        let content = message
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::InvalidResponse(
                    "Ollama response message missing string 'content'".to_string(),
                )
            })?;

        let mut openai_message = json!({
            "role": "assistant",
            "content": content
        });

        let tool_calls = convert_ollama_tool_calls(message)?;
        if let Some(calls) = tool_calls {
            openai_message["tool_calls"] = json!(calls);
        }

        // Determine finish reason
        let done = response
            .get("done")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                ProviderError::InvalidResponse("Ollama response missing boolean 'done'".to_string())
            })?;
        let finish_reason = if !done {
            "length"
        } else if openai_message.get("tool_calls").is_some() {
            "tool_calls"
        } else {
            "stop"
        };

        // Extract token counts if available
        let prompt_tokens = response
            .get("prompt_eval_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let completion_tokens = response
            .get("eval_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

        Ok(json!({
            "id": format!("ollama-{}", uuid::Uuid::new_v4()),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": model,
            "choices": [{
                "index": 0,
                "message": openai_message,
                "finish_reason": finish_reason
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens
            }
        }))
    }

    fn chat_endpoint(&self, _model: &str) -> String {
        "/api/chat".to_string()
    }

    fn get_headers(&self, _api_key: &super::ApiKey) -> crate::secrets::SensitiveHeaders {
        // Ollama doesn't require authentication by default
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_static_literal(reqwest::header::CONTENT_TYPE, "application/json");
        headers
    }

    fn supports_model_listing(&self) -> bool {
        true
    }

    fn models_endpoint(&self) -> &'static str {
        // Ollama uses /api/tags for model listing, but also supports /v1/models
        "/v1/models"
    }

    /// Ollama native shape: `message.content`. The default `OpenAI`
    /// extractor would return `None` here because Ollama does not wrap
    /// responses in `choices[]`. See crosslink #479.
    fn extract_response_text(&self, response: &Value) -> Option<String> {
        response
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .map(std::string::ToString::to_string)
    }

    /// Ollama native usage envelope: token counters live at the top
    /// level (`prompt_eval_count` / `eval_count`), not under `usage`.
    /// Ollama has no cache layer, so cache counters are zero.
    /// See crosslink #479.
    fn extract_token_usage(&self, response: &Value) -> Option<TokenUsage> {
        // Require at least one counter to declare "usage was reported"
        // — otherwise an unrelated response with no token data would
        // become an indistinguishable 0/0 record.
        let prompt = response.get("prompt_eval_count").and_then(Value::as_u64);
        let completion = response.get("eval_count").and_then(Value::as_u64);
        if prompt.is_none() && completion.is_none() {
            return None;
        }
        Some(TokenUsage {
            input_tokens: prompt.unwrap_or(0),
            output_tokens: completion.unwrap_or(0),
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        })
    }
}

fn convert_ollama_tool_calls(message: &Value) -> Result<Option<Vec<Value>>, ProviderError> {
    let Some(tool_calls) = message.get("tool_calls") else {
        return Ok(None);
    };
    let calls = tool_calls.as_array().ok_or_else(|| {
        ProviderError::InvalidResponse("Ollama message.tool_calls must be an array".to_string())
    })?;
    if calls.is_empty() {
        return Ok(None);
    }

    calls
        .iter()
        .enumerate()
        .map(convert_ollama_tool_call)
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn convert_ollama_tool_call((index, call): (usize, &Value)) -> Result<Value, ProviderError> {
    let func = call.get("function").ok_or_else(|| {
        ProviderError::InvalidResponse(format!(
            "Ollama tool_call at index {index} missing 'function' object"
        ))
    })?;
    let name = func
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            ProviderError::InvalidResponse(format!(
                "Ollama tool_call at index {index} missing non-empty function.name"
            ))
        })?;
    let arguments = func.get("arguments").ok_or_else(|| {
        ProviderError::InvalidResponse(format!(
            "Ollama tool_call at index {index} missing function.arguments"
        ))
    })?;
    let arguments = stringify_ollama_tool_arguments(index, arguments)?;

    Ok(json!({
        "id": format!("call_{}", uuid::Uuid::new_v4()),
        "type": "function",
        "function": {
            "name": name,
            "arguments": arguments
        }
    }))
}

fn stringify_ollama_tool_arguments(
    index: usize,
    arguments: &Value,
) -> Result<String, ProviderError> {
    let parsed = if let Some(args) = arguments.as_str() {
        serde_json::from_str::<Value>(args).map_err(|e| {
            ProviderError::InvalidResponse(format!(
                "Ollama tool_call at index {index} has invalid JSON function.arguments: {e}"
            ))
        })?
    } else {
        arguments.clone()
    };

    if !parsed.is_object() {
        return Err(ProviderError::InvalidResponse(format!(
            "Ollama tool_call at index {index} has non-object function.arguments: expected JSON \
             object, got {}",
            json_value_type_name(&parsed),
        )));
    }

    serde_json::to_string(&parsed).map_err(|e| {
        ProviderError::InvalidResponse(format!(
            "Ollama tool_call at index {index} has unserializable function.arguments: {e}"
        ))
    })
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
    use std::collections::HashMap;

    fn request_with_messages(messages: Vec<ChatMessage>) -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "llama3".to_string(),
            messages,
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: HashMap::new(),
        }
    }

    fn request_with_tools(tools: Vec<Value>) -> ChatCompletionRequest {
        let mut request = request_with_messages(vec![ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Text("hello".to_string()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        }]);
        request.tools = Some(tools);
        request
    }

    fn message_with_parts(parts: Vec<ContentPart>) -> ChatMessage {
        ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Parts(parts),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        }
    }

    fn text_part(text: Option<&str>) -> ContentPart {
        ContentPart {
            content_type: "text".to_string(),
            text: text.map(str::to_string),
            image_url: None,
        }
    }

    #[test]
    fn transform_request_concatenates_text_content_parts() {
        let request = request_with_messages(vec![message_with_parts(vec![
            text_part(Some("hello")),
            text_part(Some("world")),
        ])]);

        let body = OllamaAdapter::new()
            .transform_request(&request)
            .expect("text parts should convert");

        assert_eq!(body["messages"][0]["content"], "hello\nworld");
    }

    #[test]
    fn transform_request_errors_on_text_part_missing_text() {
        let request = request_with_messages(vec![message_with_parts(vec![text_part(None)])]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("text part without text must fail");

        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("without string"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_rejects_image_content_parts() {
        let request = request_with_messages(vec![message_with_parts(vec![ContentPart {
            content_type: "image_url".to_string(),
            text: None,
            image_url: Some(json!({"url": "data:image/png;base64,abc"})),
        }])]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("image content must not be dropped");

        match err {
            ProviderError::Unsupported(msg) => assert!(msg.contains("image content"), "{msg}"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_rejects_unknown_content_part_type() {
        let request = request_with_messages(vec![message_with_parts(vec![ContentPart {
            content_type: "input_audio".to_string(),
            text: None,
            image_url: None,
        }])]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("unknown content part must not be dropped");

        match err {
            ProviderError::Unsupported(msg) => {
                assert!(msg.contains("content part type"), "{msg}");
                assert!(!msg.contains("input_audio"), "{msg}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    fn base_tool_response(arguments: &Value) -> Value {
        json!({
            "model": "llama3",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "bash",
                        "arguments": arguments
                    }
                }]
            },
            "done": true
        })
    }

    fn base_text_response() -> Value {
        json!({
            "model": "llama3",
            "message": {
                "role": "assistant",
                "content": "hello"
            },
            "done": true
        })
    }

    #[test]
    fn transform_request_converts_valid_tools() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "function": {
                "name": "bash",
                "description": "Run a shell command",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"}
                    }
                }
            }
        })]);

        let body = OllamaAdapter::new()
            .transform_request(&request)
            .expect("valid tool should convert");

        let tool = &body["tools"][0];
        assert_eq!(tool["type"], "function");
        assert_eq!(tool["function"]["name"], "bash");
        assert_eq!(tool["function"]["description"], "Run a shell command");
        assert_eq!(tool["function"]["parameters"]["type"], "object");
    }

    #[test]
    fn transform_request_defaults_optional_tool_fields() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bash"}
        })]);

        let body = OllamaAdapter::new()
            .transform_request(&request)
            .expect("tool without optional fields should convert");

        let function = &body["tools"][0]["function"];
        assert_eq!(function["name"], "bash");
        assert_eq!(function["description"], "");
        assert_eq!(function["parameters"], json!({}));
    }

    #[test]
    fn transform_request_errors_on_tool_missing_function_object() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "credential": "ollama-tool-secret-sentinel"
        })]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("missing function object must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function"), "{msg}");
                assert!(!msg.contains("ollama-tool-secret-sentinel"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_tool_missing_function_name() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "function": {"description": "no name"}
        })]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("missing function.name must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_tool_with_empty_function_name() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": ""}
        })]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("empty function.name must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_malformed_optional_tool_fields() {
        let bad_description = request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bash", "description": {"not": "a string"}}
        })]);
        let err = OllamaAdapter::new()
            .transform_request(&bad_description)
            .expect_err("non-string description must fail");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.description"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }

        let bad_parameters = request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bash", "parameters": []}
        })]);
        let err = OllamaAdapter::new()
            .transform_request(&bad_parameters)
            .expect_err("non-object parameters must fail");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.parameters"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_serializes_object_tool_arguments() {
        let response = base_tool_response(&json!({"command": "pwd"}));
        let out = OllamaAdapter::new()
            .transform_response(response, false)
            .expect("valid tool call should transform");
        let call = &out["choices"][0]["message"]["tool_calls"][0];
        assert_eq!(call["function"]["name"], "bash");
        assert_eq!(call["function"]["arguments"], r#"{"command":"pwd"}"#);
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn transform_response_errors_on_missing_model() {
        let mut response = base_text_response();
        response.as_object_mut().expect("object").remove("model");

        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("missing model must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("'model'"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_missing_message_object() {
        let response = json!({
            "model": "llama3",
            "message": null,
            "done": true
        });

        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("missing message object must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("'message'"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_missing_or_malformed_role() {
        for message in [
            json!({"content": "hello"}),
            json!({"role": "", "content": "hello"}),
            json!({"role": 7, "content": "hello"}),
        ] {
            let response = json!({
                "model": "llama3",
                "message": message,
                "done": true
            });

            let err = OllamaAdapter::new()
                .transform_response(response, false)
                .expect_err("missing or malformed role must fail");

            match err {
                ProviderError::InvalidResponse(msg) => assert!(msg.contains("'role'"), "{msg}"),
                other => panic!("expected InvalidResponse, got {other:?}"),
            }
        }
    }

    #[test]
    fn transform_response_errors_on_unsupported_role() {
        let response = json!({
            "model": "llama3",
            "message": {
                "role": "user",
                "content": "hello"
            },
            "done": true
        });

        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("unsupported response role must fail");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("unsupported role"), "{msg}");
                assert!(msg.contains("assistant"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_missing_or_malformed_content() {
        for message in [
            json!({"role": "assistant"}),
            json!({"role": "assistant", "content": null}),
            json!({"role": "assistant", "content": ["not", "a", "string"]}),
        ] {
            let response = json!({
                "model": "llama3",
                "message": message,
                "done": true
            });

            let err = OllamaAdapter::new()
                .transform_response(response, false)
                .expect_err("missing or malformed content must fail");

            match err {
                ProviderError::InvalidResponse(msg) => assert!(msg.contains("'content'"), "{msg}"),
                other => panic!("expected InvalidResponse, got {other:?}"),
            }
        }
    }

    #[test]
    fn transform_response_errors_on_missing_done() {
        let mut response = base_text_response();
        response.as_object_mut().expect("object").remove("done");

        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("missing done must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("'done'"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_accepts_stringified_object_tool_arguments() {
        let response = base_tool_response(&json!(r#"{"command":"pwd"}"#));
        let out = OllamaAdapter::new()
            .transform_response(response, false)
            .expect("stringified object arguments should transform");
        let call = &out["choices"][0]["message"]["tool_calls"][0];
        assert_eq!(call["function"]["arguments"], r#"{"command":"pwd"}"#);
    }

    #[test]
    fn transform_response_errors_on_malformed_tool_argument_string() {
        let response = base_tool_response(&json!("{not json"));
        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("malformed tool arguments must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("function.arguments"), "{msg}");
                assert!(msg.contains("invalid JSON"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_non_object_tool_arguments() {
        let response = base_tool_response(&json!([]));
        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("non-object tool arguments must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("function.arguments"), "{msg}");
                assert!(msg.contains("expected JSON object"), "{msg}");
                assert!(msg.contains("array"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_missing_tool_function_name() {
        let response = json!({
            "model": "llama3",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {"arguments": {"command": "pwd"}}
                }]
            },
            "done": true
        });
        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("missing tool name must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }
}

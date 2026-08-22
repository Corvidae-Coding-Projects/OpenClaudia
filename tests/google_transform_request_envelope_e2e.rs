//! End-to-end tests for `GoogleAdapter::transform_request` —
//! the Gemini-native body envelope shape:
//! `contents` (renamed from messages), `systemInstruction`
//! (lifted from system role), `generationConfig.temperature`
//! plus `generationConfig.maxOutputTokens` (renamed from
//! `max_tokens`), and the assistant-to-model role rewrite.
//!
//! Sprint 165 of the verification effort. Sprint 164 covered
//! Anthropic + Ollama envelopes; this file pins the Google
//! envelope distinct shape so the wire-level Gemini API
//! contract is verified end-to-end.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::providers::get_adapter;
use openclaudia::proxy::{ChatCompletionRequest, ChatMessage, ContentPart, MessageContent};
use serde_json::{json, Value};
use std::collections::HashMap;

fn msg(role: &str, content: &str) -> ChatMessage {
    ChatMessage {
        role: role.to_string(),
        content: MessageContent::Text(content.to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    }
}

fn req(model: &str, messages: Vec<ChatMessage>) -> ChatCompletionRequest {
    ChatCompletionRequest {
        model: model.to_string(),
        messages,
        temperature: None,
        max_tokens: None,
        stream: None,
        tools: None,
        tool_choice: None,
        extra: HashMap::new(),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Body envelope shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn google_transform_uses_contents_key_not_messages() {
    // PINS WIRE: Gemini's request uses `contents`, NOT `messages`.
    let adapter = get_adapter("google").unwrap();
    let request = req("gemini-2.5-pro", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body["contents"].is_array(),
        "Gemini MUST use contents key; got {body}"
    );
    assert!(
        body.get("messages").is_none(),
        "Gemini MUST NOT use messages key; got {body}"
    );
}

#[test]
fn google_transform_does_not_include_model_field_at_top_level() {
    // PINS WIRE: model is in the URL path (chat_endpoint),
    // NOT in the body.
    let adapter = get_adapter("google").unwrap();
    let request = req("gemini-2.5-pro", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("model").is_none(),
        "Gemini MUST NOT carry model in body (lives in URL); got {body}"
    );
}

#[test]
fn google_transform_does_not_include_max_tokens_at_top_level() {
    // PINS WIRE: maxOutputTokens lives under generationConfig.
    let adapter = get_adapter("google").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.max_tokens = Some(1000);
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("max_tokens").is_none(),
        "Gemini MUST NOT use top-level max_tokens; got {body}"
    );
    assert!(
        body.get("maxOutputTokens").is_none(),
        "Gemini MUST NOT use top-level maxOutputTokens; got {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — systemInstruction lift
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn google_transform_lifts_system_role_to_system_instruction_field() {
    let adapter = get_adapter("google").unwrap();
    let request = req(
        "m",
        vec![msg("system", "you are helpful"), msg("user", "hi")],
    );
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("systemInstruction").is_some(),
        "Gemini MUST lift system to systemInstruction; got {body}"
    );
}

#[test]
fn google_transform_with_no_system_omits_system_instruction() {
    let adapter = get_adapter("google").unwrap();
    let request = req("m", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("systemInstruction").is_none(),
        "absent system MUST NOT emit systemInstruction; got {body}"
    );
}

#[test]
fn google_transform_contents_excludes_system_role() {
    // PINS DOC: system role messages filtered out of contents.
    let adapter = get_adapter("google").unwrap();
    let request = req(
        "m",
        vec![msg("system", "system text"), msg("user", "user text")],
    );
    let body = adapter.transform_request(&request).expect("ok");
    let contents = body["contents"].as_array().expect("array");
    for entry in contents {
        let role = entry["role"].as_str().expect("role");
        assert_ne!(
            role, "system",
            "system role MUST be filtered out; got {entry}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Role rewriting (assistant → model)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn google_transform_rewrites_assistant_role_to_model() {
    // PINS WIRE: Gemini uses "model" not "assistant".
    let adapter = get_adapter("google").unwrap();
    let request = req("m", vec![msg("user", "hi"), msg("assistant", "hello")]);
    let body = adapter.transform_request(&request).expect("ok");
    let contents = body["contents"].as_array().expect("array");
    let assistant_entry = contents
        .iter()
        .find(|e| e["role"] == "model")
        .expect("must have model role");
    assert_eq!(assistant_entry["role"], "model");
    // No literal "assistant" role should remain.
    for entry in contents {
        assert_ne!(
            entry["role"], "assistant",
            "assistant MUST be rewritten to model; got {entry}"
        );
    }
}

#[test]
fn google_transform_keeps_user_role_as_user() {
    let adapter = get_adapter("google").unwrap();
    let request = req("m", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    let contents = body["contents"].as_array().expect("array");
    assert_eq!(contents[0]["role"], "user");
}

#[test]
fn google_transform_unknown_role_defaults_to_user() {
    // PINS DOC: any non-assistant role maps to "user".
    let adapter = get_adapter("google").unwrap();
    let request = req("m", vec![msg("tool", "result")]);
    let body = adapter.transform_request(&request).expect("ok");
    let contents = body["contents"].as_array().expect("array");
    assert_eq!(contents[0]["role"], "user");
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Parts shape inside contents
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn google_transform_text_content_becomes_parts_array_with_text_object() {
    // PINS WIRE: parts = [{"text": "..."}].
    let adapter = get_adapter("google").unwrap();
    let request = req("m", vec![msg("user", "hello world")]);
    let body = adapter.transform_request(&request).expect("ok");
    let parts = body["contents"][0]["parts"]
        .as_array()
        .expect("parts array");
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0]["text"], "hello world");
}

#[test]
fn google_transform_parts_with_image_url_becomes_inline_data() {
    let adapter = get_adapter("google").unwrap();
    let request = req(
        "m",
        vec![ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Parts(vec![
                ContentPart {
                    content_type: "text".to_string(),
                    text: Some("look at this".to_string()),
                    image_url: None,
                },
                ContentPart {
                    content_type: "image_url".to_string(),
                    text: None,
                    image_url: Some(json!({"url": "data:image/png;base64,..."})),
                },
            ]),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        }],
    );
    let body = adapter.transform_request(&request).expect("ok");
    let parts = body["contents"][0]["parts"].as_array().expect("parts");
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0]["text"], "look at this");
    // PINS WIRE: image_url → inlineData (NOT image_url like OpenAI).
    assert!(
        parts[1]["inlineData"].is_object(),
        "image MUST be inlineData; got {:?}",
        parts[1]
    );
}

#[test]
fn google_transform_parts_with_unsupported_type_rejects_instead_of_skipping() {
    // PINS #850 replacement contract: unsupported ContentPart variants fail
    // closed instead of being silently dropped or fabricated as empty text.
    let adapter = get_adapter("google").unwrap();
    let request = req(
        "m",
        vec![ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Parts(vec![
                ContentPart {
                    content_type: "google-content-type-secret-sentinel".to_string(),
                    text: None,
                    image_url: None,
                },
                ContentPart {
                    content_type: "text".to_string(),
                    text: Some("only text part".to_string()),
                    image_url: None,
                },
            ]),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        }],
    );
    let err = adapter
        .transform_request(&request)
        .expect_err("unsupported content part type must reject");
    let err = err.to_string();
    assert_eq!(
        err,
        "Request failed: Unsupported Google content part type at message index 0, part index 0"
    );
    assert!(!err.contains("google-content-type-secret-sentinel"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — generationConfig nesting
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn google_transform_generation_config_omitted_when_no_temp_or_max_tokens() {
    let adapter = get_adapter("google").unwrap();
    let request = req("m", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    // PINS DOC: generationConfig block ONLY when at least one
    // generation parameter present (mirrors Ollama's options).
    assert!(
        body.get("generationConfig").is_none(),
        "generationConfig MUST be absent without params; got {body}"
    );
}

#[test]
fn google_transform_generation_config_temperature_nested() {
    let adapter = get_adapter("google").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.temperature = Some(0.7);
    let body = adapter.transform_request(&request).expect("ok");
    let cfg = &body["generationConfig"];
    assert!(cfg.is_object());
    assert!((cfg["temperature"].as_f64().unwrap() - 0.7).abs() < 1e-6);
}

#[test]
fn google_transform_generation_config_max_output_tokens_camel_case() {
    // PINS WIRE: maxOutputTokens (camelCase) NOT max_tokens.
    let adapter = get_adapter("google").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.max_tokens = Some(512);
    let body = adapter.transform_request(&request).expect("ok");
    let cfg = &body["generationConfig"];
    assert_eq!(cfg["maxOutputTokens"], 512);
    assert!(cfg.get("max_tokens").is_none());
}

#[test]
fn google_transform_generation_config_combines_temp_and_max_output_tokens() {
    let adapter = get_adapter("google").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.temperature = Some(0.3);
    request.max_tokens = Some(100);
    let body = adapter.transform_request(&request).expect("ok");
    let cfg = &body["generationConfig"];
    assert!((cfg["temperature"].as_f64().unwrap() - 0.3).abs() < 1e-6);
    assert_eq!(cfg["maxOutputTokens"], 100);
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Cross-provider distinctness vs Anthropic + Ollama
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn google_body_uses_no_anthropic_keys() {
    let adapter = get_adapter("google").unwrap();
    let mut request = req("m", vec![msg("system", "sys"), msg("user", "hi")]);
    request.max_tokens = Some(100);
    let body = adapter.transform_request(&request).expect("ok");
    // Anthropic-isms must NOT appear.
    assert!(
        body.get("system").is_none(),
        "Google uses systemInstruction not system"
    );
    assert!(
        body.get("max_tokens").is_none(),
        "Google uses maxOutputTokens"
    );
    assert!(body.get("messages").is_none(), "Google uses contents");
}

#[test]
fn google_body_uses_no_ollama_keys() {
    let adapter = get_adapter("google").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.max_tokens = Some(100);
    let body = adapter.transform_request(&request).expect("ok");
    // Ollama-isms must NOT appear.
    assert!(
        body.get("options").is_none(),
        "Google uses generationConfig not options"
    );
    assert!(
        body.get("stream").is_none(),
        "Google has no stream flag at top level"
    );
    assert!(
        body.get("messages").is_none(),
        "Google uses contents not messages"
    );
}

#[test]
fn google_body_byte_distinct_from_anthropic_for_same_request() {
    let request = req("m", vec![msg("user", "hi")]);
    let google_body = get_adapter("google")
        .unwrap()
        .transform_request(&request)
        .expect("ok");
    let anth_body = get_adapter("anthropic")
        .unwrap()
        .transform_request(&request)
        .expect("ok");
    let g_str = serde_json::to_string(&google_body).expect("g");
    let a_str = serde_json::to_string(&anth_body).expect("a");
    assert_ne!(g_str, a_str);
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Edge cases
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn google_transform_with_empty_messages_yields_empty_contents() {
    let adapter = get_adapter("google").unwrap();
    let request = req("m", Vec::new());
    let body = adapter.transform_request(&request).expect("ok");
    assert!(body["contents"].as_array().unwrap().is_empty());
}

#[test]
fn google_transform_with_only_system_message_yields_empty_contents() {
    let adapter = get_adapter("google").unwrap();
    let request = req("m", vec![msg("system", "only system")]);
    let body = adapter.transform_request(&request).expect("ok");
    // System filtered out → contents is empty.
    assert!(body["contents"].as_array().unwrap().is_empty());
    // But systemInstruction is set.
    assert!(body.get("systemInstruction").is_some());
}

#[test]
fn google_transform_serializes_to_valid_json_with_unicode() {
    let adapter = get_adapter("google").unwrap();
    let request = req("m", vec![msg("user", "日本語 🎉")]);
    let body = adapter.transform_request(&request).expect("ok");
    let s = serde_json::to_string(&body).expect("ser");
    // Unicode survives.
    assert!(s.contains("日本語") || s.contains("\\u65e5"));
    let back: Value = serde_json::from_str(&s).expect("round");
    let text = back["contents"][0]["parts"][0]["text"]
        .as_str()
        .expect("text");
    assert!(text.contains("日本語"));
}

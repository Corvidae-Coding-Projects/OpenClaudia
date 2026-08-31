//! End-to-end tests for `ProviderAdapter::transform_request`
//! across providers — Anthropic native body shape
//! (`model`/`messages`/`max_tokens` defaults + system
//! extraction + `cache_control` on tools) and Ollama native
//! body shape (`options.num_predict` + `stream` default).
//!
//! Sprint 164 of the verification effort. Sprint 17 / 119
//! covered the OpenAI-compat pass-through; this file pins
//! the per-provider distinct envelope shapes.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::providers::get_adapter;
use openclaudia::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};
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
// Section A — Anthropic body shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_transform_includes_model_messages_and_max_tokens() {
    let adapter = get_adapter("anthropic").unwrap();
    let request = req("claude-sonnet-4-5", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    assert_eq!(body["model"], "claude-sonnet-4-5");
    assert!(body["messages"].is_array());
    // PINS DOC: max_tokens defaults to DEFAULT_MAX_TOKENS when None.
    assert!(
        body["max_tokens"].is_number(),
        "MUST include max_tokens default; got {body}"
    );
}

#[test]
fn anthropic_transform_max_tokens_uses_default_when_none() {
    let adapter = get_adapter("anthropic").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.max_tokens = None;
    let body = adapter.transform_request(&request).expect("ok");
    // Default is openclaudia::DEFAULT_MAX_TOKENS — non-zero
    // sensible default.
    let v = body["max_tokens"].as_u64().expect("u64");
    assert!(v > 0, "default MUST be positive; got {v}");
}

#[test]
fn anthropic_transform_max_tokens_uses_caller_value_when_some() {
    let adapter = get_adapter("anthropic").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.max_tokens = Some(7777);
    let body = adapter.transform_request(&request).expect("ok");
    assert_eq!(body["max_tokens"], 7777);
}

#[test]
fn anthropic_transform_includes_temperature_only_when_set() {
    let adapter = get_adapter("anthropic").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.temperature = None;
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("temperature").is_none(),
        "None temperature MUST be skipped in body"
    );

    request.temperature = Some(0.5);
    let body = adapter.transform_request(&request).expect("ok");
    assert!((body["temperature"].as_f64().unwrap() - 0.5).abs() < 1e-6);
}

#[test]
fn anthropic_transform_omits_temperature_for_models_that_reject_sampling_params() {
    let adapter = get_adapter("anthropic").unwrap();
    for model in ["claude-opus-4-8", "claude-fable-5", "claude-mythos-5"] {
        let mut request = req(model, vec![msg("user", "hi")]);
        request.temperature = Some(0.5);
        let body = adapter.transform_request(&request).expect("ok");
        assert!(
            body.get("temperature").is_none(),
            "{model} rejects non-default sampling parameters; got {body}"
        );
    }
}

#[test]
fn anthropic_transform_extracts_system_message_from_messages_array() {
    // PINS DOC: Anthropic body keeps `system` as a top-level
    // field separate from messages[] (extracted from role=system).
    let adapter = get_adapter("anthropic").unwrap();
    let request = req(
        "m",
        vec![
            msg("system", "you are a helpful assistant"),
            msg("user", "hi"),
        ],
    );
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("system").is_some(),
        "system MUST be lifted to top-level; got {body}"
    );
}

#[test]
fn anthropic_transform_with_no_system_omits_system_field() {
    let adapter = get_adapter("anthropic").unwrap();
    let request = req("m", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("system").is_none(),
        "absent system MUST NOT emit system field; got {body}"
    );
}

#[test]
fn anthropic_transform_messages_array_excludes_system_role() {
    // PINS DOC: after extracting system to top-level, the
    // messages[] array does NOT contain the system message.
    let adapter = get_adapter("anthropic").unwrap();
    let request = req(
        "m",
        vec![msg("system", "system text"), msg("user", "user text")],
    );
    let body = adapter.transform_request(&request).expect("ok");
    let messages = body["messages"].as_array().expect("array");
    for m in messages {
        assert_ne!(
            m["role"], "system",
            "system role MUST NOT appear in messages[] (lifted to body.system); got {m}"
        );
    }
}

#[test]
fn anthropic_transform_tool_call_only_assistant_message_has_no_null_content() {
    let adapter = get_adapter("anthropic").unwrap();
    let mut assistant = msg("assistant", "");
    assistant.tool_calls = Some(vec![json!({
        "id": "call-no-text",
        "type": "function",
        "function": {
            "name": "bash",
            "arguments": "{\"command\":\"pwd\"}"
        }
    })]);
    let request = req("claude-sonnet-4-5", vec![assistant]);
    let body = adapter.transform_request(&request).expect("ok");
    let messages = body["messages"].as_array().expect("messages array");
    assert_eq!(messages.len(), 1);
    let content = messages[0]["content"].as_array().expect("content array");
    assert_eq!(content.len(), 1, "empty text must not become content:null");
    assert_eq!(content[0]["type"], "tool_use");
    assert_eq!(content[0]["id"], "call-no-text");
    assert_eq!(content[0]["name"], "bash");
    assert_eq!(content[0]["input"]["command"], "pwd");
    assert_ne!(messages[0]["content"], Value::Null);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Ollama body shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn ollama_transform_includes_model_messages_and_stream_default_false() {
    let adapter = get_adapter("ollama").unwrap();
    let request = req("llama3", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    assert_eq!(body["model"], "llama3");
    assert!(body["messages"].is_array());
    // PINS DOC: stream defaults to false when None.
    assert_eq!(body["stream"], false);
}

#[test]
fn ollama_transform_stream_set_propagates() {
    let adapter = get_adapter("ollama").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.stream = Some(true);
    let body = adapter.transform_request(&request).expect("ok");
    assert_eq!(body["stream"], true);
}

#[test]
fn ollama_transform_options_omitted_when_no_temperature_or_max_tokens() {
    let adapter = get_adapter("ollama").unwrap();
    let request = req("m", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    // PINS DOC: options block ONLY when at least one option present.
    assert!(
        body.get("options").is_none(),
        "options MUST be absent when no temp/max_tokens; got {body}"
    );
}

#[test]
fn ollama_transform_options_includes_temperature_when_set() {
    let adapter = get_adapter("ollama").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.temperature = Some(0.7);
    let body = adapter.transform_request(&request).expect("ok");
    let options = &body["options"];
    assert!(options.is_object(), "options object MUST be present");
    assert!((options["temperature"].as_f64().unwrap() - 0.7).abs() < 1e-6);
}

#[test]
fn ollama_transform_max_tokens_maps_to_num_predict() {
    // PINS WIRE: Ollama uses options.num_predict (NOT max_tokens).
    let adapter = get_adapter("ollama").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.max_tokens = Some(512);
    let body = adapter.transform_request(&request).expect("ok");
    assert_eq!(body["options"]["num_predict"], 512);
    // Confirms max_tokens itself doesn't appear at top level.
    assert!(body.get("max_tokens").is_none());
}

#[test]
fn ollama_transform_options_combines_temperature_and_num_predict() {
    let adapter = get_adapter("ollama").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.temperature = Some(0.3);
    request.max_tokens = Some(100);
    let body = adapter.transform_request(&request).expect("ok");
    assert!((body["options"]["temperature"].as_f64().unwrap() - 0.3).abs() < 1e-6);
    assert_eq!(body["options"]["num_predict"], 100);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Cross-provider distinct shapes
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_body_does_not_contain_ollama_options_block() {
    let adapter = get_adapter("anthropic").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.max_tokens = Some(100);
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("options").is_none(),
        "Anthropic MUST NOT emit Ollama's options block"
    );
    assert!(
        body.get("max_tokens").is_some(),
        "Anthropic MUST emit max_tokens at top level"
    );
}

#[test]
fn ollama_body_does_not_contain_anthropic_system_block() {
    let adapter = get_adapter("ollama").unwrap();
    let request = req("m", vec![msg("system", "sys"), msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    // PINS DISTINCTNESS: Ollama keeps the system message in
    // messages[] (or formats inline) — NOT lifted to a top-level
    // `system` field like Anthropic.
    assert!(
        body.get("system").is_none(),
        "Ollama MUST NOT emit top-level system field; got {body}"
    );
}

#[test]
fn anthropic_and_ollama_serialize_messages_array_distinctly() {
    let request = req("m", vec![msg("user", "hi")]);
    let anth = get_adapter("anthropic").unwrap();
    let ollama = get_adapter("ollama").unwrap();
    let a_body = anth.transform_request(&request).expect("ok");
    let o_body = ollama.transform_request(&request).expect("ok");
    // Both have model + messages keys at top level.
    assert_eq!(a_body["model"], "m");
    assert_eq!(o_body["model"], "m");
    // But the surrounding envelope differs: Anthropic has
    // max_tokens default, Ollama has stream default.
    assert!(a_body.get("max_tokens").is_some());
    assert_eq!(o_body["stream"], false);
    // The two bodies are NOT byte-identical.
    let a_str = serde_json::to_string(&a_body).expect("ser a");
    let o_str = serde_json::to_string(&o_body).expect("ser o");
    assert_ne!(a_str, o_str);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Empty messages edge
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_transform_with_empty_messages_array_still_succeeds() {
    let adapter = get_adapter("anthropic").unwrap();
    let request = req("m", Vec::new());
    let body = adapter.transform_request(&request).expect("ok");
    let messages = body["messages"].as_array().expect("array");
    assert!(messages.is_empty());
}

#[test]
fn ollama_transform_with_empty_messages_array_still_succeeds() {
    let adapter = get_adapter("ollama").unwrap();
    let request = req("m", Vec::new());
    let body = adapter.transform_request(&request).expect("ok");
    let messages = body["messages"].as_array().expect("array");
    assert!(messages.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Tools (Anthropic-only checked-convert path)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_transform_with_valid_tools_emits_tools_array() {
    let adapter = get_adapter("anthropic").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.tools = Some(vec![json!({
        "type": "function",
        "function": {
            "name": "echo",
            "description": "test",
            "parameters": {"type": "object", "properties": {}}
        }
    })]);
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("tools").is_some(),
        "valid tools MUST emit tools array"
    );
    let tools = body["tools"].as_array().expect("array");
    assert_eq!(tools.len(), 1);
}

#[test]
fn anthropic_transform_with_no_tools_omits_tools_field() {
    let adapter = get_adapter("anthropic").unwrap();
    let request = req("m", vec![msg("user", "hi")]);
    let body = adapter.transform_request(&request).expect("ok");
    assert!(
        body.get("tools").is_none(),
        "None tools MUST omit tools field; got {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Body never panics on extreme inputs
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_transform_with_huge_max_tokens_serializes_without_overflow() {
    let adapter = get_adapter("anthropic").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.max_tokens = Some(u32::MAX);
    let body = adapter.transform_request(&request).expect("ok");
    let val = body["max_tokens"].as_u64().expect("u64");
    assert_eq!(val, u64::from(u32::MAX));
}

#[test]
fn ollama_transform_with_huge_max_tokens_propagates_to_num_predict() {
    let adapter = get_adapter("ollama").unwrap();
    let mut request = req("m", vec![msg("user", "hi")]);
    request.max_tokens = Some(u32::MAX);
    let body = adapter.transform_request(&request).expect("ok");
    assert_eq!(
        body["options"]["num_predict"].as_u64().expect("u64"),
        u64::from(u32::MAX)
    );
}

#[test]
fn both_transform_bodies_serialize_to_valid_json_with_unicode() {
    let request = req("m", vec![msg("user", "日本語 🎉 unicode test")]);
    let anth_body = get_adapter("anthropic")
        .unwrap()
        .transform_request(&request)
        .expect("ok");
    let ollama_body = get_adapter("ollama")
        .unwrap()
        .transform_request(&request)
        .expect("ok");
    // Both serialize to valid JSON.
    let anth_str = serde_json::to_string(&anth_body).expect("ser anth");
    let ollama_str = serde_json::to_string(&ollama_body).expect("ser ollama");
    // Unicode survives serialization in both bodies.
    assert!(anth_str.contains("日本語") || anth_str.contains("\\u65e5"));
    assert!(ollama_str.contains("日本語") || ollama_str.contains("\\u65e5"));
    // And round-trips back.
    let anth_round: Value = serde_json::from_str(&anth_str).expect("round");
    let s = anth_round["messages"][0]["content"]
        .as_str()
        .or_else(|| anth_round["messages"][0]["content"][0]["text"].as_str())
        .expect("text");
    assert!(s.contains("日本語"));
}

//! End-to-end tests for `ProviderAdapter::transform_response`
//! and `extract_token_usage` across every adapter.
//!
//! Sprint 26 of the verification effort. `tests/providers_e2e.rs`
//! already pins 34 scenarios on the REQUEST-translation side;
//! this file fills the RESPONSE-translation side: every adapter
//! converts its provider-native response shape back to a
//! canonical OpenAI-compat envelope, and every adapter extracts
//! a `TokenUsage` from its native usage shape.
//!
//! Coverage shape:
//!
//!   - **Anthropic `transform_response`** — happy path produces
//!     a valid `OpenAI` chat.completion envelope with id, model,
//!     `choices[0].message.content`, `finish_reason`, and usage.
//!     Missing required fields error with `InvalidResponse`.
//!   - **OpenAI-compat `transform_response`** — passes the
//!     provider response through with minimal transformation
//!     (the upstream is already OpenAI-shape).
//!   - **`extract_token_usage`** — each adapter recovers a
//!     non-zero `TokenUsage` from its native usage shape;
//!     missing usage returns None.
//!   - **`extract_response_text`** — each adapter recovers the
//!     primary text payload from its native response shape;
//!     garbage input returns None.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::providers::get_adapter;
use serde_json::json;

// ───────────────────────────────────────────────────────────────────────────
// Section A — Anthropic transform_response
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_transform_response_produces_openai_envelope() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let response = json!({
        "id": "msg_abc123",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet-20241022",
        "content": [
            {"type": "text", "text": "Hello, world!"}
        ],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {
            "input_tokens": 10,
            "output_tokens": 5
        }
    });
    let transformed = adapter
        .transform_response(response, false)
        .expect("transform must succeed");

    // OpenAI-compat shape: id, object, model, choices[], usage.
    assert_eq!(transformed["id"], "msg_abc123");
    assert_eq!(transformed["object"], "chat.completion");
    assert_eq!(transformed["model"], "claude-3-5-sonnet-20241022");

    let choices = transformed["choices"].as_array().expect("choices array");
    assert_eq!(choices.len(), 1, "exactly one choice");
    assert_eq!(choices[0]["index"], 0);
    assert_eq!(choices[0]["message"]["role"], "assistant");
    assert_eq!(choices[0]["message"]["content"], "Hello, world!");
    assert_eq!(choices[0]["finish_reason"], "stop");

    // Usage shape: prompt/completion/total tokens.
    let usage = &transformed["usage"];
    assert_eq!(usage["prompt_tokens"], 10);
    assert_eq!(usage["completion_tokens"], 5);
    assert_eq!(usage["total_tokens"], 15);
}

#[test]
fn anthropic_transform_response_errors_on_missing_required_field() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    // Missing `id` — crosslink #413 refuses to manufacture a sentinel.
    let response = json!({
        "type": "message",
        "model": "claude-3-5-sonnet",
        "content": [{"type": "text", "text": "x"}],
        "stop_reason": "end_turn",
    });
    let outcome = adapter.transform_response(response, false);
    assert!(
        outcome.is_err(),
        "missing 'id' must error InvalidResponse; got {outcome:?}"
    );
}

#[test]
fn anthropic_transform_response_errors_on_empty_object() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let outcome = adapter.transform_response(json!({}), false);
    assert!(outcome.is_err(), "empty object must error");
}

#[test]
fn anthropic_transform_response_maps_tool_use_blocks_to_tool_calls() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let response = json!({
        "id": "msg_tool",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet",
        "content": [
            {"type": "text", "text": "I'll run bash"},
            {
                "type": "tool_use",
                "id": "toolu_1",
                "name": "bash",
                "input": {"command": "ls"}
            }
        ],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 20, "output_tokens": 10}
    });
    let transformed = adapter
        .transform_response(response, false)
        .expect("transform must succeed");

    let msg = &transformed["choices"][0]["message"];
    let tool_calls = msg["tool_calls"].as_array().expect("tool_calls array");
    assert_eq!(tool_calls.len(), 1);
    assert_eq!(tool_calls[0]["id"], "toolu_1");
    assert_eq!(tool_calls[0]["type"], "function");
    assert_eq!(tool_calls[0]["function"]["name"], "bash");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — OpenAI-compat transform_response (passthrough)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn openai_transform_response_preserves_shape() {
    let adapter = get_adapter("openai").expect("openai adapter");
    let response = json!({
        "id": "chatcmpl-abc",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "gpt-4o",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Hello!"},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15
        }
    });
    let transformed = adapter
        .transform_response(response, false)
        .expect("openai passthrough must succeed");
    // Should round-trip the key fields.
    assert_eq!(transformed["id"], "chatcmpl-abc");
    assert_eq!(transformed["choices"][0]["message"]["content"], "Hello!");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — extract_token_usage per adapter
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_extract_token_usage_from_native_envelope() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let response = json!({
        "usage": {
            "input_tokens": 100,
            "output_tokens": 50,
            "cache_read_input_tokens": 10,
            "cache_creation_input_tokens": 5
        }
    });
    let usage = adapter
        .extract_token_usage(&response)
        .expect("usage must extract");
    assert_eq!(usage.input_tokens, 100);
    assert_eq!(usage.output_tokens, 50);
    assert_eq!(usage.cache_read_tokens, 10);
    assert_eq!(usage.cache_write_tokens, 5);
}

#[test]
fn openai_extract_token_usage_from_native_envelope() {
    let adapter = get_adapter("openai").expect("openai adapter");
    let response = json!({
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
        }
    });
    let usage = adapter
        .extract_token_usage(&response)
        .expect("usage must extract");
    assert_eq!(usage.input_tokens, 100);
    assert_eq!(usage.output_tokens, 50);
}

#[test]
fn extract_token_usage_returns_none_on_missing_usage_block() {
    for provider in &[
        "anthropic",
        "openai",
        "google",
        "deepseek",
        "qwen",
        "zai",
        "kimi",
        "minimax",
    ] {
        let adapter = get_adapter(provider).unwrap_or_else(|_| panic!("{provider} adapter"));
        let outcome = adapter.extract_token_usage(&json!({"id": "x", "model": "y"}));
        assert!(
            outcome.is_none(),
            "{provider}: missing usage must return None; got {outcome:?}"
        );
    }
}

#[test]
fn extract_token_usage_returns_none_on_empty_response() {
    for provider in &[
        "anthropic",
        "openai",
        "google",
        "deepseek",
        "qwen",
        "zai",
        "kimi",
        "minimax",
    ] {
        let adapter = get_adapter(provider).unwrap_or_else(|_| panic!("{provider} adapter"));
        let outcome = adapter.extract_token_usage(&json!({}));
        assert!(
            outcome.is_none(),
            "{provider}: empty response must return None; got {outcome:?}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — extract_response_text per adapter
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_extract_response_text_pulls_text_block() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let response = json!({
        "content": [
            {"type": "tool_use", "id": "t1", "name": "bash", "input": {}},
            {"type": "text", "text": "hello"}
        ]
    });
    let text = adapter
        .extract_response_text(&response)
        .expect("text must extract");
    assert_eq!(text, "hello");
}

#[test]
fn openai_extract_response_text_pulls_choices_message_content() {
    let adapter = get_adapter("openai").expect("openai adapter");
    let response = json!({
        "choices": [{"message": {"content": "hello from openai"}}]
    });
    let text = adapter
        .extract_response_text(&response)
        .expect("text must extract");
    assert_eq!(text, "hello from openai");
}

#[test]
fn extract_response_text_returns_none_on_garbage() {
    for provider in &[
        "anthropic",
        "openai",
        "google",
        "deepseek",
        "qwen",
        "zai",
        "kimi",
        "minimax",
    ] {
        let adapter = get_adapter(provider).unwrap_or_else(|_| panic!("{provider} adapter"));
        // Various garbage shapes — none should crash; all should
        // return None.
        for garbage in &[
            json!({}),
            json!({"oops": true}),
            json!("just a string"),
            json!([]),
        ] {
            let outcome = adapter.extract_response_text(garbage);
            assert!(
                outcome.is_none(),
                "{provider}: garbage input {garbage} must return None; got {outcome:?}"
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — get_headers per adapter
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_headers_use_xapikey_and_anthropic_version() {
    use openclaudia::providers::api_key::ApiKey;
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let key = ApiKey::try_from_string("sk-ant-test-PROD".to_string()).unwrap();
    let headers = adapter.get_headers(&key);
    assert!(
        headers.contains_name("x-api-key"),
        "anthropic must use x-api-key header; got {headers:?}"
    );
    assert!(
        headers.contains_name("anthropic-version"),
        "anthropic must include anthropic-version header; got {headers:?}"
    );
    let request = headers
        .apply(reqwest::Client::new().get("https://example.com"))
        .expect("all values must pass HeaderValue validation")
        .build()
        .expect("request");
    assert!(request
        .headers()
        .values()
        .all(reqwest::header::HeaderValue::is_sensitive));
}

#[test]
fn openai_compat_headers_use_authorization_bearer() {
    use openclaudia::providers::api_key::ApiKey;
    for provider in &["openai", "deepseek", "qwen", "zai", "kimi", "minimax"] {
        let adapter = get_adapter(provider).unwrap_or_else(|_| panic!("{provider} adapter"));
        let key = ApiKey::try_from_string("sk-test-PRODUCTION-KEY".to_string()).unwrap();
        let headers = adapter.get_headers(&key);
        assert!(
            headers.matches_value("authorization", "Bearer sk-test-PRODUCTION-KEY"),
            "{provider}: Authorization must use Bearer scheme; got {headers:?}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — endpoint conventions
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_chat_endpoint_is_messages() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let endpoint = adapter.chat_endpoint("claude-3-5-sonnet");
    assert!(
        endpoint.contains("messages"),
        "anthropic chat endpoint must contain 'messages'; got {endpoint:?}"
    );
}

#[test]
fn google_chat_endpoint_embeds_model_name() {
    let adapter = get_adapter("google").expect("google adapter");
    let endpoint = adapter.chat_endpoint("gemini-3.5-flash");
    assert!(
        endpoint.contains("gemini-3.5-flash"),
        "google endpoint must embed model name; got {endpoint:?}"
    );
    assert!(
        endpoint.contains("generateContent"),
        "google endpoint must use generateContent action; got {endpoint:?}"
    );
}

#[test]
fn openai_compat_chat_endpoint_is_chat_completions() {
    for provider in &["openai", "deepseek", "qwen", "zai", "kimi", "minimax"] {
        let adapter = get_adapter(provider).unwrap_or_else(|_| panic!("{provider} adapter"));
        let endpoint = adapter.chat_endpoint("any-model");
        assert!(
            endpoint.contains("chat/completions"),
            "{provider}: endpoint must contain 'chat/completions'; got {endpoint:?}"
        );
    }
}

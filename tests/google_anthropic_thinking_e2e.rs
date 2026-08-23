//! End-to-end tests for Google + Anthropic thinking-config
//! injection edge cases — budget clamping (Google
//! 32768 ceiling, Anthropic 1024 floor) + disabled-thinking
//! pass-through + adaptive budget derivation through the
//! per-provider adapter.
//!
//! Sprint 112 of the verification effort. Sprint 29 covered
//! the 4 OpenAI-compatible adapters (OpenAI/DeepSeek/Qwen/
//! Z.AI). This file fills the Google + Anthropic-specific
//! thinking edge cases: the 32768 ceiling clamp (#599) and
//! the 1024 floor.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::ThinkingConfig;
use openclaudia::providers::get_adapter;
use openclaudia::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};
use std::collections::HashMap;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn minimal_request(model: &str) -> ChatCompletionRequest {
    ChatCompletionRequest {
        model: model.to_string(),
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Text("hi".to_string()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        }],
        temperature: None,
        max_tokens: None,
        stream: None,
        tools: None,
        tool_choice: None,
        extra: HashMap::new(),
    }
}

const fn enabled_budget(budget: u32) -> ThinkingConfig {
    ThinkingConfig {
        enabled: true,
        budget_tokens: Some(budget),
        preserve_across_turns: false,
        reasoning_effort: None,
        adaptive: true,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Google thinking transform
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn google_thinking_enabled_writes_thinking_config_with_budget() {
    let adapter = get_adapter("google").expect("google adapter");
    let req = minimal_request("gemini-3.7-flash");
    let thinking = enabled_budget(8192);
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert!(
        body["generationConfig"]["thinkingConfig"]["thinkingBudget"].is_number(),
        "MUST inject thinkingBudget; got {body}"
    );
    assert_eq!(
        body["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        8192
    );
}

#[test]
fn google_thinking_disabled_does_not_write_thinking_config() {
    let adapter = get_adapter("google").expect("google adapter");
    let req = minimal_request("gemini-3.7-flash");
    let thinking = ThinkingConfig {
        enabled: false,
        ..ThinkingConfig::default()
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert!(
        body.get("generationConfig")
            .and_then(|g| g.get("thinkingConfig"))
            .is_none(),
        "disabled thinking MUST NOT inject thinkingConfig; got {body}"
    );
}

#[test]
fn google_thinking_budget_clamps_at_32768_ceiling() {
    // PINS GOOGLE CAP: Gemini caps at 32768; an over-budget
    // request MUST be clamped (not error, not pass-through).
    let adapter = get_adapter("google").expect("google adapter");
    let req = minimal_request("gemini-3.7-flash");
    let thinking = enabled_budget(99_999);
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    let budget = body["generationConfig"]["thinkingConfig"]["thinkingBudget"]
        .as_u64()
        .expect("number");
    assert!(
        budget <= 32_768,
        "Google budget MUST be clamped to <= 32768; got {budget}"
    );
}

#[test]
fn google_thinking_with_adaptive_high_effort_derives_budget_from_step_function() {
    // PINS ADAPTIVE: when budget_tokens is None and
    // reasoning_effort=high, adaptive_budget_for derives 16000.
    let adapter = get_adapter("google").expect("google adapter");
    let req = minimal_request("gemini-3.7-flash");
    let thinking = ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: Some("high".to_string()),
        adaptive: true,
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    // adaptive high → 16000.
    assert_eq!(
        body["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        16000
    );
}

#[test]
fn google_thinking_with_adaptive_low_effort_derives_1024_budget() {
    let adapter = get_adapter("google").expect("google adapter");
    let req = minimal_request("gemini-3.7-flash");
    let thinking = ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: Some("low".to_string()),
        adaptive: true,
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert_eq!(
        body["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        1024
    );
}

#[test]
fn google_thinking_with_no_effort_no_explicit_budget_falls_back_to_default() {
    let adapter = get_adapter("google").expect("google adapter");
    let req = minimal_request("gemini-3.7-flash");
    let thinking = ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: None,
        adaptive: true,
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    // Provider default fallback (8192 per code).
    assert_eq!(
        body["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        8192
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Anthropic thinking floor
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_thinking_budget_floors_at_1024() {
    // PINS ANTHROPIC FLOOR: budget below 1024 MUST be raised.
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-sonnet-4-6");
    let thinking = enabled_budget(500); // below floor
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    let budget = body["thinking"]["budget_tokens"].as_u64().expect("number");
    assert!(
        budget >= 1024,
        "Anthropic budget MUST be floored at 1024; got {budget}"
    );
}

#[test]
fn anthropic_thinking_explicit_high_budget_preserved_above_floor() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-sonnet-4-6");
    let thinking = enabled_budget(20_000);
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert_eq!(body["thinking"]["budget_tokens"], 20_000);
}

#[test]
fn anthropic_thinking_object_has_type_enabled_marker() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-sonnet-4-6");
    let thinking = enabled_budget(8000);
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    // PINS API SHAPE: thinking object MUST have type: "enabled".
    assert_eq!(body["thinking"]["type"], "enabled");
}

#[test]
fn anthropic_opus_4_8_uses_adaptive_thinking_not_manual_budget() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-opus-4-8");
    let thinking = ThinkingConfig {
        enabled: true,
        budget_tokens: Some(32_000),
        preserve_across_turns: false,
        reasoning_effort: Some("xhigh".to_string()),
        adaptive: true,
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert_eq!(body["thinking"]["type"], "adaptive");
    assert!(
        body["thinking"].get("budget_tokens").is_none(),
        "Opus 4.8 rejects manual thinking budgets; got {body}"
    );
    assert_eq!(body["output_config"]["effort"], "xhigh");
}

#[test]
fn stale_anthropic_opus_4_7_name_does_not_enable_thinking_controls() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-opus-4-7");
    let thinking = ThinkingConfig {
        enabled: true,
        budget_tokens: Some(32_000),
        preserve_across_turns: false,
        reasoning_effort: Some("max".to_string()),
        adaptive: true,
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert!(body.get("thinking").is_none());
    assert!(body.get("output_config").is_none());
}

#[test]
fn anthropic_fable_5_omits_explicit_thinking_because_adaptive_is_implicit() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-fable-5");
    let thinking = ThinkingConfig {
        enabled: true,
        budget_tokens: Some(32_000),
        preserve_across_turns: false,
        reasoning_effort: Some("high".to_string()),
        adaptive: true,
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert!(
        body.get("thinking").is_none(),
        "Fable 5 has implicit adaptive thinking and rejects manual budgets; got {body}"
    );
    assert_eq!(body["output_config"]["effort"], "high");
}

#[test]
fn anthropic_thinking_disabled_does_not_inject_thinking_field() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-sonnet-4-6");
    let thinking = ThinkingConfig {
        enabled: false,
        ..ThinkingConfig::default()
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert!(
        body.get("thinking").is_none(),
        "disabled thinking MUST NOT inject thinking field; got {body}"
    );
}

#[test]
fn anthropic_thinking_with_adaptive_high_effort_derives_16000() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-sonnet-4-6");
    let thinking = ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: Some("high".to_string()),
        adaptive: true,
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert_eq!(body["thinking"]["budget_tokens"], 16000);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Cross-provider isolation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn google_thinking_does_not_use_anthropic_field_name() {
    let adapter = get_adapter("google").expect("google adapter");
    let req = minimal_request("gemini-3.7-flash");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_budget(8000))
        .expect("transform");
    // Google uses generationConfig.thinkingConfig, not the
    // top-level "thinking" field that Anthropic uses.
    assert!(body.get("thinking").is_none());
}

#[test]
fn anthropic_thinking_does_not_use_google_path() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-sonnet-4-6");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_budget(8000))
        .expect("transform");
    // Anthropic uses top-level "thinking", not the nested
    // generationConfig.thinkingConfig that Google uses.
    assert!(
        body.get("generationConfig").is_none()
            || body["generationConfig"].get("thinkingConfig").is_none()
    );
}

#[test]
fn each_provider_writes_thinking_into_a_documented_distinct_location() {
    // Verify the documented "different field per provider"
    // contract via JSON-pointer reach.
    let google_body = get_adapter("google")
        .unwrap()
        .transform_request_with_thinking(
            &minimal_request("gemini-3.7-flash"),
            &enabled_budget(5000),
        )
        .unwrap();
    let anthropic_body = get_adapter("anthropic")
        .unwrap()
        .transform_request_with_thinking(
            &minimal_request("claude-sonnet-4-6"),
            &enabled_budget(5000),
        )
        .unwrap();

    assert!(google_body["generationConfig"]["thinkingConfig"]["thinkingBudget"].is_number());
    assert!(anthropic_body["thinking"]["budget_tokens"].is_number());
    // Distinct paths.
    assert!(google_body.get("thinking").is_none());
    assert!(anthropic_body.get("generationConfig").is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Disabled-thinking semantics (no-op)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn disabled_thinking_passes_request_through_unchanged_for_both_providers() {
    for provider in &["google", "anthropic"] {
        let adapter = get_adapter(provider).expect("adapter");
        let model = if *provider == "google" {
            "gemini-3.7-flash"
        } else {
            "claude-sonnet-4-6"
        };
        let req = minimal_request(model);
        let baseline = adapter.transform_request(&req).expect("transform");
        let thinking = ThinkingConfig {
            enabled: false,
            ..ThinkingConfig::default()
        };
        let with_thinking = adapter
            .transform_request_with_thinking(&req, &thinking)
            .expect("transform_with_thinking");
        assert_eq!(
            baseline, with_thinking,
            "disabled thinking MUST be byte-identical to transform_request for {provider}"
        );
    }
}

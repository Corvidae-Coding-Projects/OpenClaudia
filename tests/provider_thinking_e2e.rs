//! End-to-end tests for the provider-specific thinking-config
//! injection matrix.
//!
//! Sprint 29 of the verification effort. OpenAI-compatible adapters
//! either inject `thinking` mode into the request body via a documented
//! provider-specific shape, or explicitly no-op when the upstream uses
//! provider-specific thinking controls not modeled here:
//!
//!   - **`OpenAI`**: `reasoning_effort: "none|low|medium|high|xhigh"`,
//!     only for `OpenAI` reasoning-family models.
//!   - **`DeepSeek`**: `thinking: {type: "enabled"|"disabled"}`,
//!     plus `reasoning_effort: "high"|"max"` when enabled.
//!   - **`Qwen`**: `enable_thinking` ALWAYS written (true OR false).
//!   - **`Z.AI`/GLM**: `thinking: {type: "enabled"|"disabled"}`,
//!     plus `thinking.clear_thinking: false` when
//!     `preserve_across_turns=true`, and `GLM-5.2`
//!     `reasoning_effort`.
//!   - **Kimi**: `kimi-k2.6` uses Kimi's documented `thinking` object;
//!     K2.7 code models omit it because thinking is
//!     always on and disabled thinking is rejected upstream.
//!   - **`MiniMax-M3`**: `thinking: {type: "adaptive"|"disabled"}`.
//!
//! This file pins each branch of the dispatch with positive +
//! negative cases.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::ThinkingConfig;
use openclaudia::providers::get_adapter;
use openclaudia::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};
use serde_json::json;

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
        extra: std::collections::HashMap::default(),
    }
}

fn enabled_thinking(reasoning_effort: Option<&str>) -> ThinkingConfig {
    ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: reasoning_effort.map(str::to_string),
        adaptive: true,
    }
}

const fn disabled_thinking() -> ThinkingConfig {
    ThinkingConfig {
        enabled: false,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: None,
        adaptive: true,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A - OpenAI: reasoning_effort gated by reasoning model family
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn stale_openai_o1_name_does_not_enable_reasoning_controls() {
    let adapter = get_adapter("openai").expect("openai adapter");
    let req = minimal_request("o1-preview");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("high")))
        .expect("transform");
    assert!(body.get("reasoning_effort").is_none());
}

#[test]
fn openai_thinking_defaults_reasoning_effort_to_medium() {
    let adapter = get_adapter("openai").expect("openai adapter");
    let req = minimal_request("gpt-5.6-sol");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(None))
        .expect("transform");
    assert_eq!(
        body["reasoning_effort"], "medium",
        "a current OpenAI reasoning model must default to medium; got {body}"
    );
}

#[test]
fn openai_thinking_injects_reasoning_effort_for_gpt5_model() {
    let adapter = get_adapter("openai").expect("openai adapter");
    let req = minimal_request("gpt-5.5");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("high")))
        .expect("transform");
    assert_eq!(
        body["reasoning_effort"], "high",
        "GPT-5 model with thinking enabled MUST set reasoning_effort; got {body}"
    );
}

#[test]
fn unlisted_openai_codex_name_does_not_enable_reasoning_controls() {
    let adapter = get_adapter("openai").expect("openai adapter");
    let req = minimal_request("gpt-5.3-codex");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("high")))
        .expect("transform");
    assert!(body.get("reasoning_effort").is_none());
}

#[test]
fn openai_thinking_supports_none_and_xhigh_reasoning_effort() {
    let adapter = get_adapter("openai").expect("openai adapter");

    let none_req = minimal_request("gpt-5.5");
    let none_body = adapter
        .transform_request_with_thinking(&none_req, &enabled_thinking(Some("none")))
        .expect("transform");
    assert_eq!(
        none_body["reasoning_effort"], "none",
        "OpenAI GPT-5.5 must allow reasoning_effort=none; got {none_body}"
    );

    let xhigh_req = minimal_request("gpt-5.5");
    let xhigh_body = adapter
        .transform_request_with_thinking(&xhigh_req, &enabled_thinking(Some("xhigh")))
        .expect("transform");
    assert_eq!(
        xhigh_body["reasoning_effort"], "xhigh",
        "OpenAI GPT-5.5 must allow reasoning_effort=xhigh; got {xhigh_body}"
    );
}

#[test]
fn openai_thinking_ignored_for_non_reasoning_model() {
    let adapter = get_adapter("openai").expect("openai adapter");
    let req = minimal_request("gpt-4o");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("high")))
        .expect("transform");
    // gpt-4o is not in the reasoning family, so reasoning_effort MUST NOT be set.
    assert!(
        body.get("reasoning_effort").is_none(),
        "non-reasoning model MUST NOT receive reasoning_effort; got {body}"
    );
}

#[test]
fn openai_thinking_disabled_writes_no_reasoning_field() {
    let adapter = get_adapter("openai").expect("openai adapter");
    let req = minimal_request("gpt-5.6-sol");
    let body = adapter
        .transform_request_with_thinking(&req, &disabled_thinking())
        .expect("transform");
    assert!(
        body.get("reasoning_effort").is_none(),
        "disabled thinking MUST NOT set reasoning_effort; got {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B - DeepSeek: thinking object plus high/max effort
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn deepseek_thinking_enabled_sets_thinking_and_default_high_effort() {
    let adapter = get_adapter("deepseek").expect("deepseek adapter");
    let req = minimal_request("deepseek-v4-pro");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(None))
        .expect("transform");
    assert_eq!(
        body["thinking"]["type"], "enabled",
        "DeepSeek with thinking enabled MUST set thinking.type=enabled; got {body}"
    );
    assert_eq!(
        body["reasoning_effort"], "high",
        "DeepSeek with no explicit effort MUST default reasoning_effort to high; got {body}"
    );
    assert!(
        body.get("enable_thinking").is_none(),
        "DeepSeek MUST NOT receive legacy enable_thinking; got {body}"
    );
}

#[test]
fn deepseek_thinking_enabled_maps_max_effort() {
    let adapter = get_adapter("deepseek").expect("deepseek adapter");
    let req = minimal_request("deepseek-v4-pro");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("max")))
        .expect("transform");
    assert_eq!(
        body["reasoning_effort"], "max",
        "DeepSeek max effort MUST map to reasoning_effort=max; got {body}"
    );
}

#[test]
fn deepseek_thinking_disabled_writes_disabled_thinking_object() {
    let adapter = get_adapter("deepseek").expect("deepseek adapter");
    let req = minimal_request("deepseek-v4-pro");
    let body = adapter
        .transform_request_with_thinking(&req, &disabled_thinking())
        .expect("transform");
    assert_eq!(
        body["thinking"]["type"], "disabled",
        "DeepSeek disabled MUST set thinking.type=disabled; got {body}"
    );
    assert!(body.get("reasoning_effort").is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Qwen: enable_thinking always written
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn qwen_thinking_enabled_writes_enable_thinking_true() {
    let adapter = get_adapter("qwen").expect("qwen adapter");
    let req = minimal_request("qwen3.7-plus");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(None))
        .expect("transform");
    assert_eq!(
        body["enable_thinking"], true,
        "Qwen enabled MUST set enable_thinking=true; got {body}"
    );
}

#[test]
fn qwen_thinking_disabled_writes_enable_thinking_false() {
    let adapter = get_adapter("qwen").expect("qwen adapter");
    let req = minimal_request("qwen3.7-plus");
    let body = adapter
        .transform_request_with_thinking(&req, &disabled_thinking())
        .expect("transform");
    // Qwen convention: writes false explicitly (NOT omit).
    assert_eq!(
        body["enable_thinking"], false,
        "Qwen disabled MUST explicitly write enable_thinking=false; got {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Z.AI / GLM: thinking object + clear_thinking + GLM-5.2 effort
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn zai_thinking_enabled_writes_thinking_object_enabled() {
    let adapter = get_adapter("zai").expect("zai adapter");
    let req = minimal_request("glm-5-turbo");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(None))
        .expect("transform");
    assert_eq!(
        body["thinking"],
        json!({"type": "enabled"}),
        "Z.AI enabled MUST set thinking={{type:enabled}}; got {body}"
    );
    // preserve_across_turns=false (the default) means
    // clear_thinking is NOT emitted.
    assert!(
        body["thinking"].get("clear_thinking").is_none(),
        "Z.AI without preserve_across_turns MUST omit clear_thinking; got {body}"
    );
}

#[test]
fn zai_thinking_disabled_writes_thinking_object_disabled() {
    let adapter = get_adapter("zai").expect("zai adapter");
    let req = minimal_request("glm-5-turbo");
    let body = adapter
        .transform_request_with_thinking(&req, &disabled_thinking())
        .expect("transform");
    assert_eq!(
        body["thinking"],
        json!({"type": "disabled"}),
        "Z.AI disabled MUST set thinking={{type:disabled}}; got {body}"
    );
}

#[test]
fn zai_preserve_across_turns_emits_clear_thinking_false() {
    let adapter = get_adapter("zai").expect("zai adapter");
    let req = minimal_request("glm-5-turbo");
    let thinking = ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: true,
        reasoning_effort: None,
        adaptive: true,
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    assert_eq!(
        body["thinking"]["clear_thinking"], false,
        "Z.AI with preserve_across_turns MUST emit thinking.clear_thinking=false; got {body}"
    );
    assert!(
        body.get("clear_thinking").is_none(),
        "Z.AI clear_thinking must be nested inside thinking; got {body}"
    );
}

#[test]
fn zai_glm52_thinking_maps_reasoning_effort() {
    let adapter = get_adapter("zai").expect("zai adapter");
    let req = minimal_request("glm-5.2");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("max")))
        .expect("transform");
    assert_eq!(body["thinking"]["type"], "enabled");
    assert_eq!(
        body["reasoning_effort"], "max",
        "GLM-5.2 must receive supported reasoning_effort; got {body}"
    );
}

#[test]
fn zai_non_glm52_does_not_emit_reasoning_effort() {
    let adapter = get_adapter("zai").expect("zai adapter");
    let req = minimal_request("glm-4.7");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("max")))
        .expect("transform");
    assert!(
        body.get("reasoning_effort").is_none(),
        "non-GLM-5.2 Z.AI models must not receive reasoning_effort; got {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Anthropic: budget_tokens injection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_thinking_injects_budget_tokens() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    let req = minimal_request("claude-sonnet-4-6");
    let thinking = ThinkingConfig {
        enabled: true,
        budget_tokens: Some(8000),
        preserve_across_turns: false,
        reasoning_effort: None,
        adaptive: true,
    };
    let body = adapter
        .transform_request_with_thinking(&req, &thinking)
        .expect("transform");
    // Anthropic uses `thinking: {type, budget_tokens}` shape.
    let thinking_obj = &body["thinking"];
    assert!(
        thinking_obj.is_object(),
        "anthropic thinking field must be an object; got {body}"
    );
    assert_eq!(
        thinking_obj["budget_tokens"], 8000,
        "anthropic budget_tokens MUST be threaded through; got {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Adapter dispatch matrix sanity (each provider produces
// distinct output for the SAME enabled thinking config)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn each_provider_uses_a_distinct_thinking_field() {
    let thinking = enabled_thinking(Some("low"));

    let openai = get_adapter("openai")
        .unwrap()
        .transform_request_with_thinking(&minimal_request("gpt-5.6-sol"), &thinking)
        .unwrap();
    assert_eq!(openai["reasoning_effort"], "low");

    let deepseek = get_adapter("deepseek")
        .unwrap()
        .transform_request_with_thinking(&minimal_request("deepseek-v4-pro"), &thinking)
        .unwrap();
    assert_eq!(deepseek["thinking"]["type"], "enabled");
    assert_eq!(deepseek["reasoning_effort"], "high");

    let qwen = get_adapter("qwen")
        .unwrap()
        .transform_request_with_thinking(&minimal_request("qwen3.7-plus"), &thinking)
        .unwrap();
    assert_eq!(qwen["enable_thinking"], true);

    let zai = get_adapter("zai")
        .unwrap()
        .transform_request_with_thinking(&minimal_request("glm-5-turbo"), &thinking)
        .unwrap();
    assert_eq!(zai["thinking"]["type"], "enabled");

    // No cross-provider equality assertion here: DeepSeek and Z.AI both
    // use a `thinking` object, but DeepSeek also emits `reasoning_effort`.
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Kimi / MiniMax
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn kimi_k27_thinking_omits_explicit_field_because_it_is_always_on() {
    let adapter = get_adapter("kimi").expect("kimi adapter");
    for model in ["kimi-k2.7-code", "kimi-k2.7-code-highspeed"] {
        let req = minimal_request(model);
        let body = adapter
            .transform_request_with_thinking(&req, &enabled_thinking(Some("high")))
            .expect("transform");
        assert!(
            body.get("thinking").is_none(),
            "{model} MUST omit explicit thinking because it is always on; got {body}"
        );

        let disabled = adapter
            .transform_request_with_thinking(&req, &disabled_thinking())
            .expect("transform");
        assert!(
            disabled.get("thinking").is_none(),
            "{model} rejects disabled thinking, so adapter must omit it; got {disabled}"
        );
    }
}

#[test]
fn kimi_k26_thinking_supports_enabled_disabled_and_preserve() {
    let adapter = get_adapter("kimi").expect("kimi adapter");
    let req = minimal_request("kimi-k2.6");

    let enabled = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("high")))
        .expect("transform");
    assert_eq!(enabled["thinking"], json!({"type": "enabled"}));
    assert!(enabled.get("reasoning_effort").is_none());

    let preserved = adapter
        .transform_request_with_thinking(
            &req,
            &ThinkingConfig {
                enabled: true,
                budget_tokens: None,
                preserve_across_turns: true,
                reasoning_effort: None,
                adaptive: true,
            },
        )
        .expect("transform");
    assert_eq!(
        preserved["thinking"],
        json!({"type": "enabled", "keep": "all"})
    );

    let disabled = adapter
        .transform_request_with_thinking(&req, &disabled_thinking())
        .expect("transform");
    assert_eq!(disabled["thinking"], json!({"type": "disabled"}));
}

#[test]
fn stale_kimi_k25_name_does_not_enable_thinking_controls() {
    let adapter = get_adapter("kimi").expect("kimi adapter");
    let req = minimal_request("kimi-k2.5");
    let body = adapter
        .transform_request_with_thinking(
            &req,
            &ThinkingConfig {
                enabled: true,
                budget_tokens: None,
                preserve_across_turns: true,
                reasoning_effort: None,
                adaptive: true,
            },
        )
        .expect("transform");
    assert!(body.get("thinking").is_none());
}

#[test]
fn kimi_moonshot_v1_models_do_not_receive_thinking_fields() {
    let adapter = get_adapter("kimi").expect("kimi adapter");
    let req = minimal_request("moonshot-v1-128k");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("high")))
        .expect("transform");
    assert!(body.get("thinking").is_none());
    assert!(body.get("reasoning_effort").is_none());
}

#[test]
fn minimax_m3_thinking_enabled_writes_adaptive_split_reasoning() {
    let adapter = get_adapter("minimax").expect("minimax adapter");
    let req = minimal_request("MiniMax-M3");
    let body = adapter
        .transform_request_with_thinking(&req, &enabled_thinking(Some("high")))
        .expect("transform");

    assert_eq!(body["thinking"]["type"], "adaptive");
    assert_eq!(body["reasoning_split"], true);
    assert!(
        body.get("reasoning_effort").is_none(),
        "MiniMax must not receive OpenAI reasoning_effort; got {body}"
    );
}

#[test]
fn minimax_m3_thinking_disabled_writes_disabled() {
    let adapter = get_adapter("minimax").expect("minimax adapter");
    let req = minimal_request("MiniMax-M3");
    let body = adapter
        .transform_request_with_thinking(&req, &disabled_thinking())
        .expect("transform");

    assert_eq!(body["thinking"]["type"], "disabled");
    assert!(
        body.get("reasoning_split").is_none(),
        "MiniMax disabled thinking should not request reasoning split; got {body}"
    );
}

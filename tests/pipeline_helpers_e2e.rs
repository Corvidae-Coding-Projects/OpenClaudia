//! End-to-end tests for `pipeline` pure-function helpers:
//! `overload_fallback_for`, `tool_needs_permission`,
//! `enforce_sse_line_cap`, `classify_google_finish_reason`,
//! `build_openai_request` / `build_google_request`.
//!
//! Sprint 70 of the verification effort. Sprint 25's
//! `pipeline_integration` covers SSE-event processing + tool
//! accumulators; this file covers the orthogonal helper
//! surface — model-fallback table, safe-tool catalog, line-cap
//! defence, Gemini finishReason mapping, OpenAI/Google
//! request shapes.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::pipeline::{
    build_google_request, build_openai_request, classify_google_finish_reason,
    enforce_sse_line_cap, overload_fallback_for, tool_needs_permission, SseLineCapOutcome,
};
use serde_json::json;

// ───────────────────────────────────────────────────────────────────────────
// Section A — overload_fallback_for
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn opus_falls_back_to_sonnet() {
    assert_eq!(
        overload_fallback_for("claude-opus-4-7"),
        "claude-sonnet-4-6"
    );
    assert_eq!(
        overload_fallback_for("claude-3-opus-20240229"),
        "claude-sonnet-4-6"
    );
}

#[test]
fn sonnet_falls_back_to_haiku() {
    assert_eq!(
        overload_fallback_for("claude-sonnet-4-6"),
        "claude-haiku-4-5"
    );
    assert_eq!(
        overload_fallback_for("claude-3-5-sonnet-20241022"),
        "claude-haiku-4-5"
    );
}

#[test]
fn haiku_has_no_further_fallback() {
    assert_eq!(overload_fallback_for("claude-haiku-4-5"), "");
}

#[test]
fn gpt_4_family_falls_back_to_gpt_4o_mini() {
    for m in &["gpt-4", "gpt-4-turbo", "gpt-4o"] {
        assert_eq!(overload_fallback_for(m), "gpt-4o-mini");
    }
}

#[test]
fn o_series_falls_back_to_gpt_4o_mini() {
    for m in &["o1", "o1-mini", "o3", "o3-mini", "o4-preview"] {
        assert_eq!(overload_fallback_for(m), "gpt-4o-mini");
    }
}

#[test]
fn gemini_pro_falls_back_to_flash() {
    assert_eq!(overload_fallback_for("gemini-2.5-pro"), "gemini-3.5-flash");
}

#[test]
fn unknown_model_has_no_fallback() {
    for m in &["unknown-model", "qwen-3", "deepseek-r1"] {
        assert_eq!(
            overload_fallback_for(m),
            "",
            "unknown model {m:?} MUST have no fallback"
        );
    }
}

#[test]
fn fallback_is_case_insensitive_via_to_ascii_lowercase() {
    let lower = overload_fallback_for("claude-opus-4-7");
    let upper = overload_fallback_for("CLAUDE-OPUS-4-7");
    assert_eq!(lower, upper);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — tool_needs_permission
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn safe_read_only_tools_do_not_need_permission() {
    for t in &[
        "read_file",
        "grounding_context",
        "list_files",
        "grep",
        "glob",
        "todo_read",
        "task_get",
        "task_list",
        "skill",
    ] {
        assert!(
            !tool_needs_permission(t),
            "safe tool {t:?} MUST NOT need permission"
        );
    }
}

#[test]
fn write_edit_and_non_preapproved_network_tools_need_permission() {
    for t in &[
        "write_file",
        "edit_file",
        "bash",
        "notebook_edit",
        "web_fetch",
        "ask_user_question",
        "task",
        "agent_output",
        "task_stop",
        "enter_plan_mode",
        "exit_plan_mode",
        "crosslink",
        "tool_search",
    ] {
        assert!(
            tool_needs_permission(t),
            "gated tool {t:?} MUST need permission"
        );
    }
    #[cfg(feature = "browser")]
    assert!(
        tool_needs_permission("web_search"),
        "browser-backed web_search leaves the host and needs policy"
    );
}

#[test]
fn unknown_tool_name_needs_permission_by_default() {
    // Default-deny: anything absent from the mandatory catalog needs policy.
    assert!(tool_needs_permission("totally-unknown-tool"));
    assert!(tool_needs_permission(""));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — enforce_sse_line_cap
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enforce_sse_within_cap_returns_within_cap_no_mutation() {
    let mut buf = String::from("partial line without newline");
    let original_len = buf.len();
    let outcome = enforce_sse_line_cap(&mut buf);
    assert_eq!(outcome, SseLineCapOutcome::WithinCap);
    assert_eq!(buf.len(), original_len, "buffer MUST NOT be mutated");
}

#[test]
fn enforce_sse_with_newline_returns_within_cap_regardless_of_size() {
    // A line WITH a newline is always within-cap; the drain
    // logic in the caller takes care of bounded consumption.
    let mut buf = "a".repeat(10_000_000);
    buf.push('\n');
    let outcome = enforce_sse_line_cap(&mut buf);
    assert_eq!(
        outcome,
        SseLineCapOutcome::WithinCap,
        "newline-containing buffer MUST be within-cap"
    );
}

#[test]
fn enforce_sse_no_newline_over_cap_discards_and_reports_bytes() {
    // Grow buffer past MAX_SSE_LINE_BYTES (1 MiB by default).
    let cap = 1024 * 1024;
    let mut buf = "x".repeat(cap + 100);
    let original = buf.len();
    let outcome = enforce_sse_line_cap(&mut buf);
    let SseLineCapOutcome::Exceeded { discarded_bytes } = outcome else {
        panic!("expected Exceeded; got {outcome:?}");
    };
    assert_eq!(discarded_bytes, original);
    assert!(
        buf.is_empty(),
        "buffer MUST be cleared after Exceeded; got {} bytes left",
        buf.len()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — classify_google_finish_reason
// ───────────────────────────────────────────────────────────────────────────

fn gemini_with_finish(reason: &str) -> serde_json::Value {
    json!({"candidates": [{"finishReason": reason}]})
}

#[test]
fn google_safety_finish_reason_maps_to_safety_blocked_with_user_error() {
    for reason in &["SAFETY", "RECITATION", "BLOCKLIST"] {
        let json = gemini_with_finish(reason);
        let c = classify_google_finish_reason(&json, 42);
        assert_eq!(c.finish_reason.as_deref(), Some("safety_blocked"));
        let err = c.user_error.expect("user_error present");
        assert!(
            err.contains(reason),
            "user error MUST mention reason {reason:?}; got {err:?}"
        );
    }
}

#[test]
fn google_max_tokens_maps_to_length_without_user_error() {
    let json = gemini_with_finish("MAX_TOKENS");
    let c = classify_google_finish_reason(&json, 100);
    assert_eq!(c.finish_reason.as_deref(), Some("length"));
    assert!(c.user_error.is_none());
}

#[test]
fn google_stop_maps_to_stop() {
    let json = gemini_with_finish("STOP");
    let c = classify_google_finish_reason(&json, 0);
    assert_eq!(c.finish_reason.as_deref(), Some("stop"));
    assert!(c.user_error.is_none());
}

#[test]
fn google_unknown_finish_reason_passes_through_verbatim() {
    // Documented: unknown reasons pass through (NOT classified
    // as safety_blocked — that would over-trigger errors).
    let json = gemini_with_finish("UNKNOWN_NEW_REASON");
    let c = classify_google_finish_reason(&json, 0);
    assert_eq!(c.finish_reason.as_deref(), Some("UNKNOWN_NEW_REASON"));
    assert!(
        c.user_error.is_none(),
        "unknown MUST NOT trigger user error"
    );
}

#[test]
fn google_missing_finish_reason_returns_none() {
    let json = json!({"candidates": [{"content": {"parts": []}}]});
    let c = classify_google_finish_reason(&json, 0);
    assert!(c.finish_reason.is_none());
    assert!(c.user_error.is_none());
}

#[test]
fn google_classification_default_is_all_none() {
    use openclaudia::pipeline::GoogleFinishClassification;
    let d = GoogleFinishClassification::default();
    assert!(d.finish_reason.is_none());
    assert!(d.user_error.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — build_openai_request
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn build_openai_request_includes_model_and_messages() {
    let msgs = vec![json!({"role": "user", "content": "hi"})];
    let req = build_openai_request("gpt-4o", &msgs, "medium");
    assert_eq!(req["model"], "gpt-4o");
    assert!(req["messages"].is_array());
}

#[test]
fn build_openai_request_high_effort_emits_reasoning_effort() {
    let msgs = vec![json!({"role": "user", "content": "hi"})];
    let req = build_openai_request("o3", &msgs, "high");
    assert_eq!(req["reasoning_effort"], "high");
}

#[test]
fn build_openai_request_max_effort_maps_to_xhigh() {
    // User-facing max is an alias for OpenAI's current xhigh tier.
    let msgs = vec![json!({"role": "user", "content": "hi"})];
    let req = build_openai_request("o3", &msgs, "max");
    assert_eq!(req["reasoning_effort"], "xhigh");
}

#[test]
fn build_openai_request_low_and_none_emit_reasoning_effort() {
    let msgs = vec![json!({"role": "user", "content": "hi"})];
    let low = build_openai_request("gpt-5.5", &msgs, "low");
    assert_eq!(low["reasoning_effort"], "low");
    let none = build_openai_request("gpt-5.5", &msgs, "none");
    assert_eq!(none["reasoning_effort"], "none");
}

#[test]
fn build_openai_request_medium_emits_reasoning_effort() {
    let msgs = vec![json!({"role": "user", "content": "hi"})];
    let req = build_openai_request("gpt-4o", &msgs, "medium");
    assert_eq!(req["reasoning_effort"], "medium");
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — build_google_request
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn build_google_request_returns_well_formed_json() {
    let msgs = vec![json!({"role": "user", "content": "hi"})];
    let req = build_google_request(&msgs, "medium").expect("google request should build");
    // Gemini API expects contents (not messages); the
    // function transforms the OpenAI-shape input into
    // Gemini's contents-shape output.
    assert!(req.is_object(), "MUST be a JSON object");
}

//! End-to-end tests for `tools::execute_tool` — the legacy
//! non-stateful entry point. Pins the documented `ToolResult`
//! envelope shape across known-tool, unknown-tool, malformed-
//! args, and idempotency paths.
//!
//! Sprint 183 of the verification effort. Sprint 166 covered
//! the registry dispatch envelope; this file pins the
//! `execute_tool` legacy wrapper which most older call sites
//! still use.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{
    execute_tool, FunctionCall, ToolCall, ToolFailureCode, ToolOutcome, ToolRetryability,
};
use serde_json::json;

fn call(id: &str, name: &str, args: &serde_json::Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: args.to_string(),
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — ToolResult envelope shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_tool_returns_tool_call_id_in_result() {
    // PINS WIRE: tool_call_id propagates from input to output
    // so the assistant can correlate result with request.
    let tc = call("call_abc_183", "list_files", &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    assert_eq!(
        result.tool_call_id(),
        "call_abc_183",
        "tool_call_id MUST round-trip"
    );
}

#[test]
fn execute_tool_returns_non_empty_content_string() {
    // PINS DIAGNOSTIC: result MUST carry a content string even
    // when the tool errors (model needs feedback).
    let tc = call("c1", "bash", &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    assert!(
        !result.content().is_empty(),
        "ToolResult.content() MUST be non-empty"
    );
}

#[test]
fn execute_tool_result_has_owned_string_fields() {
    let tc = call("c1", "list_files", &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    // tool_call_id and content are owned String, not &str.
    let _: &str = result.tool_call_id();
    let _: &str = result.content();
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Known-tool dispatch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_tool_dispatches_list_files() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let tc = call(
        "c1",
        "list_files",
        &json!({"path": dir.path().to_str().unwrap()}),
    );
    let result = execute_tool(support::shared_run_context(), &tc);
    // Empty dir → empty result content but NOT an error.
    assert!(!result.is_error(), "valid list_files MUST NOT error");
}

#[test]
fn execute_tool_dispatches_bash_output() {
    // bash_output with no shell_id lists (non-error).
    let tc = call("c1", "bash_output", &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    // Listing all shells (possibly empty) — not an error.
    assert!(!result.is_error());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Missing required args → is_error true with diagnostic
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_tool_missing_required_arg_sets_is_error_true() {
    let tc = call("c1", "bash", &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    assert!(
        result.is_error(),
        "missing required arg MUST set is_error=true"
    );
}

#[test]
fn execute_tool_missing_required_arg_carries_diagnostic_content() {
    let tc = call("c1", "read_file", &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    assert!(result.is_error());
    assert!(
        result.content().to_lowercase().contains("file_path")
            || result.content().contains("Missing")
            || result.content().contains("required"),
        "diagnostic MUST mention what's missing; got {:?}",
        result.content()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Unknown tool name
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_tool_unknown_tool_name_returns_error_with_documented_message() {
    let tc = call("c1", "definitely_not_a_real_tool_xyz_183", &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    assert!(result.is_error(), "unknown tool MUST be error");
    assert!(
        result.content().to_lowercase().contains("unknown")
            || result.content().to_lowercase().contains("tool")
            || result
                .content()
                .contains("definitely_not_a_real_tool_xyz_183"),
        "MUST surface unknown-tool diagnostic; got {:?}",
        result.content()
    );
}

#[test]
fn execute_tool_empty_name_returns_error() {
    let tc = call("c1", "", &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    assert!(result.is_error());
}

#[test]
fn execute_tool_unknown_tool_id_still_propagates_to_result() {
    // PINS: even for unknown tools, tool_call_id is preserved
    // so the assistant can match the error to its call.
    let tc = call("call_marker_unknown_183", "xyz", &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    assert_eq!(result.tool_call_id(), "call_marker_unknown_183");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Malformed arguments JSON
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_tool_with_invalid_json_arguments_does_not_panic() {
    // Malformed JSON in arguments must be surfaced as a tool error instead of
    // being treated as empty args. Empty-arg fallback can bypass permission
    // target extraction and produces misleading missing-field diagnostics.
    let tc = ToolCall {
        id: "c1".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "list_files".to_string(),
            arguments: "not valid json {{{".to_string(),
        },
    };
    let result = execute_tool(support::shared_run_context(), &tc);
    // tool_call_id round-trips regardless of arg parse outcome.
    assert_eq!(result.tool_call_id(), "c1");
    assert!(result.is_error());
    assert!(
        result.content().contains("Invalid tool arguments JSON"),
        "malformed arguments must be named directly; got {:?}",
        result.content()
    );
}

#[test]
fn execute_tool_with_empty_arguments_string_handled_gracefully() {
    // Empty arguments string is also malformed JSON.
    let tc = ToolCall {
        id: "c1".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "list_files".to_string(),
            arguments: String::new(),
        },
    };
    let result = execute_tool(support::shared_run_context(), &tc);
    assert_eq!(result.tool_call_id(), "c1");
    assert!(result.is_error());
    assert!(
        result.content().contains("Invalid tool arguments JSON"),
        "empty arguments string is malformed JSON; got {:?}",
        result.content()
    );
}

#[test]
fn execute_tool_with_non_object_json_arguments_errors() {
    let tc = ToolCall {
        id: "c-array".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "list_files".to_string(),
            arguments: "[]".to_string(),
        },
    };
    let result = execute_tool(support::shared_run_context(), &tc);
    assert_eq!(result.tool_call_id(), "c-array");
    assert!(result.is_error());
    assert!(matches!(
        result.outcome(),
        ToolOutcome::Error { failure }
            if failure.code == ToolFailureCode::InvalidArguments
                && failure.retryability == ToolRetryability::Never
    ));
    assert!(
        result.content().contains("expected a JSON object"),
        "non-object arguments must be rejected; got {:?}",
        result.content()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Determinism / idempotency
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_tool_unknown_tool_is_deterministic_across_5_calls() {
    let tc = call("c1", "xyz_unknown", &json!({}));
    let r1 = execute_tool(support::shared_run_context(), &tc);
    for _ in 0..4 {
        let r = execute_tool(support::shared_run_context(), &tc);
        assert_eq!(r.tool_call_id(), r1.tool_call_id());
        assert_eq!(r.is_error(), r1.is_error());
        assert_eq!(r.content(), r1.content());
    }
}

#[test]
fn execute_tool_with_same_args_yields_same_envelope_for_list_files() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let tc = call(
        "c1",
        "list_files",
        &json!({"path": dir.path().to_str().unwrap()}),
    );
    let r1 = execute_tool(support::shared_run_context(), &tc);
    let r2 = execute_tool(support::shared_run_context(), &tc);
    assert_eq!(r1.is_error(), r2.is_error());
    assert_eq!(r1.content(), r2.content());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Robustness: arbitrary extras + huge payload
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_tool_ignores_arbitrary_extra_args_no_panic() {
    let tc = call(
        "c1",
        "list_files",
        &json!({
            "extra_field": "ignored",
            "nested": {"deep": [1, 2, 3]}
        }),
    );
    let _result = execute_tool(support::shared_run_context(), &tc);
    // No panic on unknown args.
}

#[test]
fn execute_tool_with_huge_arguments_string_no_panic() {
    let huge = "x".repeat(100_000);
    let tc = ToolCall {
        id: "c1".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "list_files".to_string(),
            arguments: huge,
        },
    };
    let _result = execute_tool(support::shared_run_context(), &tc);
}

#[test]
fn execute_tool_with_long_tool_name_no_panic() {
    let long_name = "x".repeat(1_000);
    let tc = call("c1", &long_name, &json!({}));
    let result = execute_tool(support::shared_run_context(), &tc);
    // Unknown tool → error, but no panic.
    assert!(result.is_error());
}
mod support;

//! End-to-end tests for `tools::plan_mode::execute_exit_plan_mode`
//! `allowed_prompts` validation arms — pre-state-change checks
//! that gate the plan-approval signal.
//!
//! Sprint 138 of the verification effort. Sprint 39 covered
//! plan-mode policy + tool gating; this file pins the
//! `allowed_prompts` schema validation invoked through the
//! registry dispatch path — crosslink #933 (the bug that
//! silently dropped type errors before perimeter defense
//! was added).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{ToolFollowUp, ToolFollowUpState, ToolResult};
use serde_json::{json, Value};
use std::collections::HashMap;

mod support;

fn dispatch_exit_plan_mode(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("exit_plan_mode", args)
}

fn dispatch_exit_plan_mode_typed(args: &HashMap<String, Value>) -> ToolResult {
    support::dispatch_tool_result("exit_plan_mode", args)
}

fn dispatch_enter_plan_mode_typed() -> ToolResult {
    support::dispatch_tool_result("enter_plan_mode", &HashMap::new())
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — enter_plan_mode dispatch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enter_plan_mode_dispatch_returns_typed_follow_up() {
    let result = dispatch_enter_plan_mode_typed();
    assert!(matches!(
        result.follow_up(),
        ToolFollowUp::EnterPlanMode {
            state: ToolFollowUpState::Pending
        }
    ));
}

#[test]
fn enter_plan_mode_dispatch_is_idempotent_at_tool_level() {
    let first = dispatch_enter_plan_mode_typed();
    let second = dispatch_enter_plan_mode_typed();
    assert_eq!(first.follow_up(), second.follow_up());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — exit_plan_mode happy paths
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn exit_plan_mode_with_no_args_succeeds_with_empty_allowed_prompts() {
    let result = dispatch_exit_plan_mode_typed(&HashMap::new());
    let ToolFollowUp::ExitPlanMode {
        allowed_prompts, ..
    } = result.follow_up()
    else {
        panic!("expected typed exit follow-up");
    };
    assert!(allowed_prompts.is_empty());
}

#[test]
fn exit_plan_mode_with_null_allowed_prompts_succeeds_with_empty() {
    let mut args = HashMap::new();
    args.insert("allowed_prompts".to_string(), Value::Null);
    let result = dispatch_exit_plan_mode_typed(&args);
    let ToolFollowUp::ExitPlanMode {
        allowed_prompts, ..
    } = result.follow_up()
    else {
        panic!("expected typed exit follow-up");
    };
    assert!(allowed_prompts.is_empty());
}

#[test]
fn exit_plan_mode_with_empty_array_succeeds() {
    let mut args = HashMap::new();
    args.insert("allowed_prompts".to_string(), json!([]));
    assert!(matches!(
        dispatch_exit_plan_mode_typed(&args).follow_up(),
        ToolFollowUp::ExitPlanMode { .. }
    ));
}

#[test]
fn exit_plan_mode_with_well_formed_single_prompt_succeeds() {
    let mut args = HashMap::new();
    args.insert(
        "allowed_prompts".to_string(),
        json!([{"tool": "bash", "prompt": "ls -la"}]),
    );
    let result = dispatch_exit_plan_mode_typed(&args);
    let ToolFollowUp::ExitPlanMode {
        allowed_prompts, ..
    } = result.follow_up()
    else {
        panic!("expected typed exit follow-up");
    };
    assert_eq!(allowed_prompts.len(), 1);
    assert_eq!(allowed_prompts[0].tool, "bash");
    assert_eq!(allowed_prompts[0].prompt, "ls -la");
}

#[test]
fn exit_plan_mode_with_multiple_prompts_preserves_order_and_count() {
    let mut args = HashMap::new();
    args.insert(
        "allowed_prompts".to_string(),
        json!([
            {"tool": "bash", "prompt": "ls"},
            {"tool": "read_file", "prompt": "x.txt"},
            {"tool": "edit_file", "prompt": "y.rs"},
        ]),
    );
    let result = dispatch_exit_plan_mode_typed(&args);
    let ToolFollowUp::ExitPlanMode {
        allowed_prompts, ..
    } = result.follow_up()
    else {
        panic!("expected typed exit follow-up");
    };
    assert_eq!(allowed_prompts.len(), 3);
    assert_eq!(allowed_prompts[0].tool, "bash");
    assert_eq!(allowed_prompts[1].tool, "read_file");
    assert_eq!(allowed_prompts[2].tool, "edit_file");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — exit_plan_mode allowed_prompts type errors (#933)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn exit_plan_mode_with_string_allowed_prompts_errors() {
    // PINS #933: previously silently accepted via
    // as_array().unwrap_or_default(); now hard-errors.
    let mut args = HashMap::new();
    args.insert("allowed_prompts".to_string(), json!("Bash"));
    let (msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
    assert!(
        msg.contains("array") && msg.contains("string"),
        "MUST mention expected array + got string; got {msg:?}"
    );
}

#[test]
fn exit_plan_mode_with_boolean_allowed_prompts_errors() {
    let mut args = HashMap::new();
    args.insert("allowed_prompts".to_string(), json!(true));
    let (msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
    assert!(msg.contains("boolean") || msg.contains("array"));
}

#[test]
fn exit_plan_mode_with_number_allowed_prompts_errors() {
    let mut args = HashMap::new();
    args.insert("allowed_prompts".to_string(), json!(42));
    let (msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
    assert!(msg.contains("number") || msg.contains("array"));
}

#[test]
fn exit_plan_mode_with_object_allowed_prompts_errors() {
    let mut args = HashMap::new();
    args.insert(
        "allowed_prompts".to_string(),
        json!({"tool": "bash", "prompt": "ls"}),
    );
    let (msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
    assert!(msg.contains("object") || msg.contains("array"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Per-prompt entry validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn exit_plan_mode_with_non_object_entry_in_array_errors() {
    let mut args = HashMap::new();
    args.insert("allowed_prompts".to_string(), json!(["not an object"]));
    let (msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
    assert!(
        msg.contains("allowed_prompts[0]") && msg.contains("object"),
        "MUST mention indexed error + object expectation; got {msg:?}"
    );
}

#[test]
fn exit_plan_mode_with_entry_missing_tool_field_errors() {
    let mut args = HashMap::new();
    args.insert("allowed_prompts".to_string(), json!([{"prompt": "ls"}]));
    let (msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
    assert!(
        msg.contains("'tool'") || msg.contains("tool"),
        "MUST mention missing tool; got {msg:?}"
    );
}

#[test]
fn exit_plan_mode_with_entry_missing_prompt_field_errors() {
    let mut args = HashMap::new();
    args.insert("allowed_prompts".to_string(), json!([{"tool": "bash"}]));
    let (msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
    assert!(
        msg.contains("'prompt'") || msg.contains("prompt"),
        "MUST mention missing prompt; got {msg:?}"
    );
}

#[test]
fn exit_plan_mode_first_invalid_entry_short_circuits_with_correct_index() {
    // Mix valid + invalid entries — error indexes the first
    // offending position.
    let mut args = HashMap::new();
    args.insert(
        "allowed_prompts".to_string(),
        json!([
            {"tool": "bash", "prompt": "ls"},
            {"tool": "read_file"}, // missing prompt at [1]
        ]),
    );
    let (msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
    assert!(
        msg.contains("allowed_prompts[1]") || msg.contains("[1]"),
        "MUST report index 1; got {msg:?}"
    );
}

#[test]
fn exit_plan_mode_tool_field_with_non_string_type_errors() {
    let mut args = HashMap::new();
    args.insert(
        "allowed_prompts".to_string(),
        json!([{"tool": 42, "prompt": "ls"}]),
    );
    let (_msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
}

#[test]
fn exit_plan_mode_prompt_field_with_non_string_type_errors() {
    let mut args = HashMap::new();
    args.insert(
        "allowed_prompts".to_string(),
        json!([{"tool": "bash", "prompt": ["ls", "pwd"]}]),
    );
    let (_msg, is_err) = dispatch_exit_plan_mode(&args);
    assert!(is_err);
}

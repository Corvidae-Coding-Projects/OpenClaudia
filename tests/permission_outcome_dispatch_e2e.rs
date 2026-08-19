//! End-to-end tests for the mandatory-manager permission outcome APIs.
//!
//! Sprint 83 of the verification effort. The permission-gate
//! is the chokepoint between every model tool-call and the
//! tool body — crosslink #460 mandated point 1 says strict
//! Every callable gate now requires a concrete manager. Explicit prompt
//! bypass is represented by `PermissionManager::unrestricted`, while hard
//! host safety remains active.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::permissions::{PermissionDecision, PermissionManager, PermissionRule};
use openclaudia::tools::{
    check_tool_permission, check_tool_permission_outcome, FunctionCall, PermissionOutcome,
    ToolCall, ToolFailureCode, ToolHandlerResult, ToolResult, ToolRetryability,
};
use serde_json::json;
use tempfile::TempDir;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn tool_call(id: &str, tool_name: &str, args: &serde_json::Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: tool_name.to_string(),
            arguments: args.to_string(),
        },
    }
}

fn fresh_manager() -> (PermissionManager, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let mgr = PermissionManager::new(dir.path().join("permissions.json"), true, Vec::new());
    (mgr, dir)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — explicit prompt-bypass managers
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn outcome_with_explicit_unrestricted_manager_allows_safe_call() {
    let manager = PermissionManager::unrestricted();
    let call = tool_call("c1", "bash", &json!({"command": "ls"}));
    let outcome = check_tool_permission_outcome(&call, &manager);
    assert!(matches!(outcome, PermissionOutcome::Allowed));
}

#[test]
fn outcome_with_disabled_manager_allows_classified_safe_call() {
    let dir = TempDir::new().expect("tempdir");
    let mgr = PermissionManager::new(
        dir.path().join("permissions.json"),
        false, // disabled
        Vec::new(),
    );
    let call = tool_call("c1", "bash", &json!({"command": "git status"}));
    let outcome = check_tool_permission_outcome(&call, &mgr);
    assert!(
        matches!(outcome, PermissionOutcome::Allowed),
        "disabled manager should skip prompts for a classified safe call"
    );
}

#[test]
fn outcome_with_disabled_manager_keeps_hard_safety_denials() {
    let mgr = PermissionManager::unrestricted();
    let call = tool_call("c1", "bash", &json!({"command": "rm -rf /"}));
    assert!(matches!(
        check_tool_permission_outcome(&call, &mgr),
        PermissionOutcome::Denied(_)
    ));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — check_tool_permission_outcome on enabled manager paths
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn outcome_enabled_manager_with_no_rules_returns_needs_prompt() {
    let (mgr, _dir) = fresh_manager();
    let call = tool_call("c1", "bash", &json!({"command": "ls"}));
    let outcome = check_tool_permission_outcome(&call, &mgr);
    let PermissionOutcome::NeedsPrompt { tool_call_id, .. } = outcome else {
        panic!("MUST be NeedsPrompt for no-rules manager + permission-target tool");
    };
    assert_eq!(tool_call_id, "c1", "tool_call_id MUST round-trip");
}

#[test]
fn outcome_unrestricted_manager_returns_allowed() {
    let mgr = PermissionManager::unrestricted();
    let call = tool_call("c1", "bash", &json!({"command": "anything"}));
    let outcome = check_tool_permission_outcome(&call, &mgr);
    assert!(matches!(outcome, PermissionOutcome::Allowed));
}

#[test]
fn outcome_preserves_tool_call_id_into_denied_result() {
    // Construct a manager that explicitly denies bash via a
    // canonical session rule.
    let dir = TempDir::new().expect("tempdir");
    let mut mgr = PermissionManager::new(dir.path().join("p.json"), true, Vec::new());
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "*".to_string(),
        decision: PermissionDecision::Deny,
    });
    let call = tool_call("specific-id-xyz", "bash", &json!({"command": "ls"}));
    let outcome = check_tool_permission_outcome(&call, &mgr);
    if let PermissionOutcome::Denied(result) = outcome {
        assert_eq!(result.tool_call_id(), "specific-id-xyz");
        assert!(result.is_error());
        assert!(
            result.content().contains("denied")
                || result.content().contains("Denied")
                || result.content().contains("DENIED"),
            "denied content MUST mention denial; got {:?}",
            result.content()
        );
    } else {
        panic!("MUST be Denied; got {outcome:?}");
    }
}

#[test]
fn outcome_with_malformed_arguments_json_returns_denied_error() {
    // Malformed arguments are a tool-call protocol error. They must not pass
    // through the permission gate as empty args, because that can hide the
    // actual target from permission rules.
    let call = ToolCall {
        id: "c1".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "bash".to_string(),
            arguments: "not valid json {{".to_string(),
        },
    };
    let manager = PermissionManager::unrestricted();
    let outcome = check_tool_permission_outcome(&call, &manager);
    let PermissionOutcome::Denied(result) = outcome else {
        panic!("malformed arguments MUST deny with a tool error; got {outcome:?}");
    };
    assert_eq!(result.tool_call_id(), "c1");
    assert!(result.is_error());
    assert!(
        result.content().contains("Invalid tool arguments JSON"),
        "diagnostic must name malformed arguments; got {:?}",
        result.content()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — check_tool_permission compatibility projection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn legacy_check_returns_none_when_allowed() {
    let mgr = PermissionManager::unrestricted();
    let call = tool_call("c1", "bash", &json!({"command": "ls"}));
    let outcome = check_tool_permission(&call, &mgr);
    assert!(outcome.is_none());
}

#[test]
fn legacy_check_returns_denied_tool_result_when_denied() {
    let dir = TempDir::new().expect("tempdir");
    let mut mgr = PermissionManager::new(dir.path().join("p.json"), true, Vec::new());
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "*".to_string(),
        decision: PermissionDecision::Deny,
    });
    let call = tool_call("c1", "bash", &json!({"command": "ls"}));
    let result = check_tool_permission(&call, &mgr).expect("Some");
    assert!(result.is_error());
    assert_eq!(result.tool_call_id(), "c1");
}

#[test]
fn legacy_check_synthesises_permission_prompt_stringly_typed_result_on_needs_prompt() {
    // PINS LEGACY CONTRACT: the back-compat shim converts
    // NeedsPrompt into a stringly-typed "PERMISSION_PROMPT: ..."
    // tool result so callers that haven't migrated to the
    // typed enum still see something.
    let (mgr, _dir) = fresh_manager();
    let call = tool_call("c1", "bash", &json!({"command": "ls"}));
    let result = check_tool_permission(&call, &mgr).expect("Some");
    assert!(
        result.content().contains("PERMISSION_PROMPT:"),
        "legacy shim MUST synthesise PERMISSION_PROMPT stringly-typed marker; got {:?}",
        result.content()
    );
    assert!(result.is_error());
    assert_eq!(result.tool_call_id(), "c1");
}

#[test]
fn compatibility_check_with_explicit_unrestricted_manager_allows() {
    let manager = PermissionManager::unrestricted();
    let call = tool_call("c1", "bash", &json!({"command": "ls"}));
    let outcome = check_tool_permission(&call, &manager);
    assert!(outcome.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — ToolCall / ToolResult / FunctionCall serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn tool_call_serde_round_trips_with_type_renamed_to_call_type() {
    let original = tool_call("c-1", "bash", &json!({"command": "ls"}));
    let json = serde_json::to_string(&original).expect("ser");
    // serde rename: call_type → "type" on wire.
    assert!(
        json.contains("\"type\":\"function\""),
        "wire field MUST be 'type' (not call_type); got {json:?}"
    );
    let back: ToolCall = serde_json::from_str(&json).expect("de");
    assert_eq!(back.id, original.id);
    assert_eq!(back.call_type, original.call_type);
    assert_eq!(back.function.name, original.function.name);
    assert_eq!(back.function.arguments, original.function.arguments);
}

#[test]
fn function_call_serde_preserves_arguments_string_verbatim() {
    let call = tool_call(
        "c1",
        "bash",
        &json!({"nested": {"k": [1, 2, 3], "s": "value with spaces"}}),
    );
    let json = serde_json::to_string(&call).expect("ser");
    let back: ToolCall = serde_json::from_str(&json).expect("de");
    assert_eq!(back.function.arguments, call.function.arguments);
}

#[test]
fn tool_result_carries_id_content_is_error() {
    let call = tool_call("id-42", "bash", &json!({}));
    let r = ToolResult::bind(
        &call,
        "bash",
        ToolHandlerResult::success_text("result body"),
    );
    assert_eq!(r.tool_call_id(), "id-42");
    assert_eq!(r.content(), "result body");
    assert!(!r.is_error());
}

#[test]
fn tool_result_clone_preserves_all_fields() {
    let call = tool_call("x", "bash", &json!({}));
    let original = ToolResult::failure(
        &call,
        ToolFailureCode::External,
        "y",
        ToolRetryability::Unknown,
    );
    let cloned = original.clone();
    assert_eq!(cloned.tool_call_id(), original.tool_call_id());
    assert_eq!(cloned.content(), original.content());
    assert_eq!(cloned.is_error(), original.is_error());
}

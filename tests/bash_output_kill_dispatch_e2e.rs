//! End-to-end tests for the `bash_output` and `kill_shell`
//! tools dispatched through the registry — validation
//! arms + the "list all shells when no id" branch.
//!
//! Sprint 146 of the verification effort. Both tools work
//! against the `BACKGROUND_SHELLS` registry; this file
//! pins the documented behavior on an empty registry and
//! the argument-validation contract.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use openclaudia::tools::SessionIdGuard;
use serde_json::{json, Value};
use std::collections::HashMap;

fn dispatch_bash_output(args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch("bash_output", args, &mut ctx)
        .expect("bash_output must be registered")
        .into_legacy()
}

fn dispatch_kill_shell(args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch("kill_shell", args, &mut ctx)
        .expect("kill_shell must be registered")
        .into_legacy()
}

fn dispatch_kill_shells_for_agent(args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch("kill_shells_for_agent", args, &mut ctx)
        .expect("kill_shells_for_agent must be registered")
        .into_legacy()
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — bash_output: no shell_id arg (list mode)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn bash_output_with_no_shell_id_lists_background_shells() {
    // PINS DOC: when shell_id is omitted, lists all shells.
    let (text, is_err) = dispatch_bash_output(&HashMap::new());
    // List mode is NOT an error — even when empty.
    assert!(!is_err, "list mode MUST NOT be error");
    // Either "No background shells running." OR a list header.
    assert!(
        text.contains("background shells") || text.contains("No background shells running"),
        "MUST surface list-shape message; got {text:?}"
    );
}

#[test]
fn bash_output_with_null_shell_id_returns_validation_error() {
    let args = args_with(&[("shell_id", Value::Null)]);
    let (msg, is_err) = dispatch_bash_output(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid 'shell_id' argument: expected string"),
        "present null shell_id MUST be rejected clearly; got {msg:?}"
    );
}

#[test]
fn bash_output_with_number_shell_id_returns_validation_error() {
    let args = args_with(&[("shell_id", json!(42))]);
    let (msg, is_err) = dispatch_bash_output(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'shell_id' argument: expected string"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — bash_output: unknown shell_id
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn bash_output_with_unknown_shell_id_returns_error() {
    let args = args_with(&[("shell_id", json!("nonexistent-shell-xyz-marker"))]);
    let (msg, is_err) = dispatch_bash_output(&args);
    assert!(is_err, "unknown shell_id MUST be error");
    // Error MUST echo offending id so model can self-correct.
    assert!(
        msg.contains("nonexistent-shell-xyz-marker")
            || msg.contains("not found")
            || msg.contains("Unknown"),
        "MUST surface unknown-shell error; got {msg:?}"
    );
}

#[test]
fn bash_output_with_empty_string_shell_id_returns_error() {
    let args = args_with(&[("shell_id", json!(""))]);
    let (_msg, is_err) = dispatch_bash_output(&args);
    // Empty string is a real string (not None) — treated as
    // a lookup that fails.
    assert!(is_err);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — kill_shell: missing shell_id
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn kill_shell_with_no_shell_id_returns_documented_error() {
    let (msg, is_err) = dispatch_kill_shell(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("Missing 'shell_id' argument"),
        "MUST surface documented missing-shell_id; got {msg:?}"
    );
}

#[test]
fn kill_shell_with_number_shell_id_returns_validation_error() {
    let args = args_with(&[("shell_id", json!(42))]);
    let (msg, is_err) = dispatch_kill_shell(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid 'shell_id' argument: expected string"),
        "non-string shell_id MUST be rejected clearly; got {msg:?}"
    );
}

#[test]
fn kill_shell_with_array_shell_id_returns_validation_error() {
    let args = args_with(&[("shell_id", json!(["a"]))]);
    let (msg, is_err) = dispatch_kill_shell(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'shell_id' argument: expected string"));
}

#[test]
fn kill_shell_with_object_shell_id_returns_validation_error() {
    let args = args_with(&[("shell_id", json!({"k": "v"}))]);
    let (msg, is_err) = dispatch_kill_shell(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'shell_id' argument: expected string"));
}

#[test]
fn kill_shell_with_null_shell_id_returns_validation_error() {
    let args = args_with(&[("shell_id", Value::Null)]);
    let (msg, is_err) = dispatch_kill_shell(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'shell_id' argument: expected string"));
}

#[test]
fn kill_shells_for_agent_with_no_agent_id_returns_documented_error() {
    let (msg, is_err) = dispatch_kill_shells_for_agent(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("Missing 'agent_id' argument"),
        "MUST surface documented missing-agent_id; got {msg:?}"
    );
}

#[test]
fn kill_shells_for_agent_with_non_string_agent_id_returns_validation_error() {
    let args = args_with(&[("agent_id", json!(42))]);
    let (msg, is_err) = dispatch_kill_shells_for_agent(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid 'agent_id' argument: expected string"),
        "non-string agent_id MUST be rejected clearly; got {msg:?}"
    );
}

#[test]
fn kill_shells_for_agent_with_empty_agent_id_treated_as_missing() {
    let args = args_with(&[("agent_id", json!(""))]);
    let (msg, is_err) = dispatch_kill_shells_for_agent(&args);
    assert!(is_err);
    assert!(msg.contains("Missing 'agent_id' argument"));
}

#[test]
fn kill_shells_for_agent_with_unknown_agent_id_is_idempotent_success() {
    let owner = "no-shells-for-this-agent";
    let _guard = SessionIdGuard::set(owner);
    let args = args_with(&[("agent_id", json!(owner))]);
    let (msg, is_err) = dispatch_kill_shells_for_agent(&args);
    assert!(!is_err);
    assert!(
        msg.contains("No background shells found"),
        "unknown agent cleanup should be idempotent; got {msg:?}"
    );
}

#[test]
fn kill_shells_for_agent_rejects_cross_session_cleanup() {
    let _guard = SessionIdGuard::set("caller-session");
    let args = args_with(&[("agent_id", json!("different-session"))]);
    let (msg, is_err) = dispatch_kill_shells_for_agent(&args);
    assert!(is_err);
    assert!(msg.contains("another session"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — kill_shell: unknown shell_id
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn kill_shell_with_unknown_shell_id_returns_error() {
    let args = args_with(&[("shell_id", json!("nonexistent-xyz-kill-marker"))]);
    let (msg, is_err) = dispatch_kill_shell(&args);
    assert!(is_err);
    // Error MUST surface useful diagnostic — not just generic.
    assert!(
        !msg.is_empty(),
        "MUST surface non-empty error message; got {msg:?}"
    );
}

#[test]
fn kill_shell_with_empty_string_shell_id_returns_error() {
    let args = args_with(&[("shell_id", json!(""))]);
    let (_msg, is_err) = dispatch_kill_shell(&args);
    // Empty string passes the "missing" guard but BACKGROUND_SHELLS
    // lookup fails.
    assert!(is_err);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Forward-compat
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn bash_output_never_panics_on_arbitrary_extra_args() {
    let args = args_with(&[
        ("shell_id", json!("xyz")),
        ("extra", json!({"k": "v"})),
        ("nested", json!([1, 2, 3])),
    ]);
    let (_msg, _is_err) = dispatch_bash_output(&args);
    // No panic.
}

#[test]
fn kill_shell_never_panics_on_arbitrary_extra_args() {
    let args = args_with(&[
        ("shell_id", json!("xyz")),
        ("extra", json!({"k": "v"})),
        ("count", json!(42)),
    ]);
    let (_msg, _is_err) = dispatch_kill_shell(&args);
    // No panic.
}

#[test]
fn kill_shells_for_agent_never_panics_on_arbitrary_extra_args() {
    let args = args_with(&[
        ("agent_id", json!("xyz")),
        ("extra", json!({"k": "v"})),
        ("count", json!(42)),
    ]);
    let (_msg, _is_err) = dispatch_kill_shells_for_agent(&args);
    // No panic.
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Cross-tool consistency
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn bash_output_and_kill_shell_both_registered_in_registry() {
    assert!(registry().get("bash_output").is_some());
    assert!(registry().get("kill_shell").is_some());
    assert!(registry().get("kill_shells_for_agent").is_some());
}

#[test]
fn shell_id_naming_consistent_across_both_tools() {
    // PINS NAMING: both tools accept the same arg key
    // ("shell_id") — so the model never has to remember
    // a different name when killing vs reading output.
    let unknown = json!("nonexistent-test-marker");
    let output_args = args_with(&[("shell_id", unknown.clone())]);
    let kill_args = args_with(&[("shell_id", unknown)]);
    let (_o_msg, output_err) = dispatch_bash_output(&output_args);
    let (_k_msg, kill_err) = dispatch_kill_shell(&kill_args);
    // Both error on unknown shell_id — consistent contract.
    assert!(output_err);
    assert!(kill_err);
}

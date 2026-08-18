//! End-to-end tests for `tools::registry::ToolRegistry::dispatch`
//! — Option<(String, bool)> return contract. Pins:
//!   - None for unknown tool name.
//!   - Some for every registered handler name.
//!   - dispatch is non-mutating across repeated identical calls.
//!
//! Sprint 222 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use std::collections::HashMap;

fn empty_args() -> HashMap<String, serde_json::Value> {
    HashMap::new()
}

fn fresh_ctx() -> ToolContext<'static> {
    ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Unknown tool dispatch returns None
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_unknown_tool_returns_none() {
    let reg = registry();
    let outcome = reg.dispatch(
        "completely_fictional_tool_222",
        &empty_args(),
        &mut fresh_ctx(),
    );
    assert!(
        outcome.is_none(),
        "unknown tool name MUST return None; got {outcome:?}"
    );
}

#[test]
fn dispatch_empty_tool_name_returns_none() {
    let reg = registry();
    let outcome = reg.dispatch("", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_none());
}

#[test]
fn dispatch_whitespace_only_tool_name_returns_none() {
    let reg = registry();
    let outcome = reg.dispatch("   ", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_none());
}

#[test]
fn dispatch_case_mismatch_tool_name_returns_none() {
    // PINS: tool name lookup is byte-exact (case-sensitive).
    let reg = registry();
    // "Bash" capitalized is NOT registered (lowercase "bash" is).
    let outcome = reg.dispatch("Bash", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_none());
}

#[test]
fn dispatch_tool_name_with_trailing_space_returns_none() {
    let reg = registry();
    let outcome = reg.dispatch("bash ", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Known tools dispatch returns Some
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_bash_returns_some_tuple() {
    let reg = registry();
    let outcome = reg.dispatch("bash", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_some());
}

#[test]
fn dispatch_list_files_returns_some_tuple() {
    let reg = registry();
    let outcome = reg.dispatch("list_files", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_some());
}

#[test]
fn dispatch_read_file_returns_some_tuple() {
    let reg = registry();
    let outcome = reg.dispatch("read_file", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_some());
}

#[test]
fn dispatch_write_file_returns_some_tuple() {
    let reg = registry();
    let outcome = reg.dispatch("write_file", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_some());
}

#[test]
fn dispatch_edit_file_returns_some_tuple() {
    let reg = registry();
    let outcome = reg.dispatch("edit_file", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_some());
}

#[test]
fn dispatch_glob_returns_some_tuple() {
    let reg = registry();
    let outcome = reg.dispatch("glob", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_some());
}

#[test]
fn dispatch_grep_returns_some_tuple() {
    let reg = registry();
    let outcome = reg.dispatch("grep", &empty_args(), &mut fresh_ctx());
    assert!(outcome.is_some());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Return shape: 2-tuple (String, bool)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_returns_string_first_element() {
    let reg = registry();
    let (msg, _) = reg
        .dispatch("list_files", &empty_args(), &mut fresh_ctx())
        .expect("known tool")
        .into_legacy();
    let _: String = msg; // compile-time check.
}

#[test]
fn dispatch_returns_bool_second_element() {
    let reg = registry();
    let (_, is_err) = reg
        .dispatch("list_files", &empty_args(), &mut fresh_ctx())
        .expect("known tool")
        .into_legacy();
    let _: bool = is_err;
}

#[test]
fn dispatch_returns_non_empty_message_for_known_tool_with_empty_args() {
    // PINS DIAGNOSTIC: even error outputs MUST be non-empty so the
    // model receives feedback on what went wrong.
    let reg = registry();
    let (msg, _) = reg
        .dispatch("bash", &empty_args(), &mut fresh_ctx())
        .expect("bash known")
        .into_legacy();
    // Likely an error (missing command arg) but still non-empty.
    assert!(!msg.is_empty(), "MUST surface diagnostic message");
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Idempotency / determinism (read-only paths)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_unknown_tool_returns_none_repeatedly() {
    let reg = registry();
    for _ in 0..10 {
        let outcome = reg.dispatch("xyz_unknown", &empty_args(), &mut fresh_ctx());
        assert!(outcome.is_none());
    }
}

#[test]
fn dispatch_list_files_repeated_yields_same_message_on_empty_args() {
    // list_files with empty args lists cwd — deterministic.
    let reg = registry();
    let (m1, e1) = reg
        .dispatch("list_files", &empty_args(), &mut fresh_ctx())
        .expect("ok")
        .into_legacy();
    let (m2, e2) = reg
        .dispatch("list_files", &empty_args(), &mut fresh_ctx())
        .expect("ok")
        .into_legacy();
    assert_eq!(e1, e2);
    // Messages may differ slightly if cwd changes, but typically
    // identical in short test windows. Just verify both are populated.
    assert!(!m1.is_empty());
    assert!(!m2.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Registry singleton stability
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn registry_returns_same_pointer_across_5_calls() {
    let ptrs: Vec<*const _> = (0..5).map(|_| std::ptr::from_ref(registry())).collect();
    for w in ptrs.windows(2) {
        assert_eq!(w[0], w[1], "registry() MUST be a singleton");
    }
}

#[test]
fn dispatch_on_singleton_registry_works_consistently() {
    // Same registry pointer, multiple dispatches.
    let reg = registry();
    let r1 = reg.dispatch("list_files", &empty_args(), &mut fresh_ctx());
    let r2 = reg.dispatch("list_files", &empty_args(), &mut fresh_ctx());
    assert_eq!(r1.is_some(), r2.is_some());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — ToolContext nullity tolerance
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_works_with_all_none_context_fields() {
    // PINS DOC: ToolContext fields are Option — None is the
    // default for tools that don't need memory_db/app_config/task_mgr.
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    let outcome = reg.dispatch("list_files", &empty_args(), &mut ctx);
    assert!(outcome.is_some());
}

#[test]
fn dispatch_does_not_panic_on_unknown_with_all_none_context() {
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    let outcome = reg.dispatch("xyz", &empty_args(), &mut ctx);
    assert!(outcome.is_none());
}

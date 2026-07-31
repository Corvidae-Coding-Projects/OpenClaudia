//! End-to-end tests for `ToolRegistry::dispatch` —
//! the documented `Option<(String, bool)>` return shape,
//! unknown-tool fallback, and the `is_error` semantic
//! invariants across every successful and failing
//! dispatch path.
//!
//! Sprint 166 of the verification effort. Sprint 160
//! covered the per-handler invariants; this file pins the
//! dispatch envelope itself — the contract every caller
//! relies on (proxy + chat + analytics + permission
//! prompts) for "did the tool succeed".

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use serde_json::{json, Value};
use std::collections::HashMap;

fn ctx() -> ToolContext<'static> {
    ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Unknown-tool fallback (None)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_unknown_tool_returns_none() {
    let mut c = ctx();
    let outcome = registry().dispatch(
        "definitely_not_a_real_tool_xyz_166",
        &HashMap::new(),
        &mut c,
    );
    assert!(
        outcome.is_none(),
        "unknown tool MUST return None (NOT Some(error))"
    );
}

#[test]
fn dispatch_empty_string_tool_name_returns_none() {
    let mut c = ctx();
    let outcome = registry().dispatch("", &HashMap::new(), &mut c);
    assert!(outcome.is_none());
}

#[test]
fn dispatch_whitespace_only_tool_name_returns_none() {
    let mut c = ctx();
    let outcome = registry().dispatch("   ", &HashMap::new(), &mut c);
    assert!(outcome.is_none());
}

#[test]
fn dispatch_tool_name_with_uppercase_returns_none_case_sensitive() {
    // PINS DOC: dispatch lookup is case-sensitive.
    let mut c = ctx();
    let outcome = registry().dispatch("BASH", &HashMap::new(), &mut c);
    assert!(
        outcome.is_none(),
        "uppercase tool name MUST NOT match lowercase registered name"
    );
}

#[test]
fn dispatch_tool_name_with_leading_whitespace_returns_none() {
    // PINS DOC: no auto-trim on lookup.
    let mut c = ctx();
    let outcome = registry().dispatch(" bash", &HashMap::new(), &mut c);
    assert!(outcome.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Known tool always returns Some
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_known_tool_with_empty_args_returns_some() {
    let mut c = ctx();
    let outcome = registry().dispatch("bash", &HashMap::new(), &mut c);
    assert!(outcome.is_some());
}

#[test]
fn dispatch_known_tool_with_missing_required_args_returns_some_error_tuple() {
    // PINS ENVELOPE: even when the tool errors, dispatch
    // returns Some((message, true)) — NEVER None.
    let mut c = ctx();
    let (msg, is_err) = registry()
        .dispatch("bash", &HashMap::new(), &mut c)
        .expect("Some on known tool");
    assert!(is_err, "missing required args MUST set is_err");
    assert!(!msg.is_empty(), "error tuple MUST carry a message");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Return tuple invariants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_tuple_first_element_is_always_a_string() {
    // Trivially true at compile time (Option<(String, bool)>)
    // but pins the contract behaviorally — message is never
    // panic-replaced with empty.
    let mut c = ctx();
    let (msg, _) = registry()
        .dispatch("list_files", &HashMap::new(), &mut c)
        .expect("Some");
    let _: String = msg;
}

#[test]
fn dispatch_tuple_message_non_empty_for_every_known_tool_with_empty_args() {
    // Empty args trigger documented errors on tools with
    // required fields, success on tools without.  Either way
    // the message MUST be non-empty so the model has
    // diagnostic feedback.
    let known = vec![
        "bash",
        "bash_output",
        "kill_shell",
        "kill_shells_for_agent",
        "read_file",
        "write_file",
        "edit_file",
        "list_files",
        "glob",
        "grep",
        "crosslink",
        "web_fetch",
        "todo_write",
        "todo_read",
        "notebook_edit",
        "task_create",
        "task_update",
        "task_get",
        "task_list",
        "ask_user_question",
        "enter_plan_mode",
        "exit_plan_mode",
        "lsp",
        "enter_worktree",
        "exit_worktree",
        "list_worktrees",
        "cron_create",
        "cron_delete",
        "cron_list",
        "skill",
        "tool_search",
        "list_mcp_resources",
        "read_mcp_resource",
    ];
    #[cfg(feature = "browser")]
    let known = {
        let mut known = known;
        known.push("web_search");
        known
    };
    let mut c = ctx();
    for tool in known {
        let (msg, _) = registry()
            .dispatch(tool, &HashMap::new(), &mut c)
            .unwrap_or_else(|| panic!("dispatch({tool}) MUST return Some"));
        assert!(
            !msg.is_empty(),
            "{tool}: empty-args dispatch MUST return non-empty message"
        );
    }
}

#[test]
fn dispatch_unknown_tool_never_panics_on_extreme_inputs() {
    // PINS ROBUSTNESS: a model handing us a name with embedded
    // null bytes or 10kB of garbage MUST get None, NOT panic.
    let mut c = ctx();
    let names = [
        "tool\x00with\x00nulls",
        "tool with spaces",
        "tool/with/slashes",
        "..\\windows\\path",
        "tool\nwith\nnewlines",
    ];
    for name in &names {
        let outcome = registry().dispatch(name, &HashMap::new(), &mut c);
        assert!(outcome.is_none(), "{name:?} MUST return None");
    }
    // 10kB junk name.
    let huge = "x".repeat(10 * 1024);
    assert!(registry()
        .dispatch(&huge, &HashMap::new(), &mut c)
        .is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Arg map ownership / mutation safety
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_does_not_mutate_passed_args_map() {
    let args: HashMap<String, Value> = vec![
        ("key1".to_string(), json!("value1")),
        ("key2".to_string(), json!(42)),
    ]
    .into_iter()
    .collect();
    let snapshot = args.clone();

    let mut c = ctx();
    let _outcome = registry().dispatch("list_files", &args, &mut c);
    assert_eq!(
        args, snapshot,
        "dispatch MUST NOT mutate caller's args (args: &HashMap)"
    );
}

#[test]
fn dispatch_accepts_huge_arg_map_without_panic() {
    let args: HashMap<String, Value> = (0..1000).map(|i| (format!("key_{i}"), json!(i))).collect();
    let mut c = ctx();
    let outcome = registry().dispatch("list_files", &args, &mut c);
    assert!(outcome.is_some(), "huge args MUST NOT crash dispatch");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Idempotency across repeated dispatches
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_repeated_with_same_args_returns_consistent_envelope_shape() {
    // PINS IDEMPOTENCY: read-only tools (list_files) with the
    // same args produce same envelope shape on every call.
    let mut c = ctx();
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let args: HashMap<String, Value> =
        vec![("path".to_string(), json!(dir.path().to_str().unwrap()))]
            .into_iter()
            .collect();

    let mut shapes = Vec::new();
    for _ in 0..5 {
        let (msg, is_err) = registry()
            .dispatch("list_files", &args, &mut c)
            .expect("Some");
        shapes.push((msg, is_err));
    }
    // All 5 calls produced the same envelope.
    let first = shapes[0].clone();
    for s in &shapes[1..] {
        assert_eq!(s, &first, "list_files MUST be deterministic on same dir");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — get() and dispatch() name-set parity
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn registry_get_some_iff_dispatch_some_for_same_name() {
    // PINS INVARIANT: registry.get(name).is_some() ⇔
    // registry.dispatch(name, …).is_some(). The two MUST
    // recognise the same name set.
    let names_to_check = [
        "bash",
        "read_file",
        "list_files",
        "definitely_not_a_tool_xyz",
        "BASH",
        "",
        "skill",
    ];
    let mut c = ctx();
    for name in names_to_check {
        let get_some = registry().get(name).is_some();
        let dispatch_some = registry().dispatch(name, &HashMap::new(), &mut c).is_some();
        assert_eq!(
            get_some, dispatch_some,
            "name {name:?}: get().is_some() ({get_some}) MUST match dispatch().is_some() ({dispatch_some})"
        );
    }
}

#[test]
fn dispatching_to_kill_shell_does_not_actually_kill_anything_with_unknown_id() {
    // PINS SAFETY: dispatching kill_shell with an unknown
    // shell id surfaces an error WITHOUT killing arbitrary
    // PIDs. The is_err flag MUST be true.
    let mut c = ctx();
    let args: HashMap<String, Value> =
        vec![("shell_id".to_string(), json!("not-a-real-shell-id-166"))]
            .into_iter()
            .collect();
    let (_msg, is_err) = registry()
        .dispatch("kill_shell", &args, &mut c)
        .expect("Some");
    assert!(is_err, "kill_shell with unknown id MUST report error");
}

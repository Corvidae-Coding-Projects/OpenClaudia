//! End-to-end tests for the 4 `task_*` tools dispatched
//! through the registry — no-session error path + happy-path
//! validation with a real `TaskManager` in `ToolContext`.
//!
//! Sprint 151 of the verification effort. Sprint 103
//! covered the format functions; this file pins the
//! registry-dispatched path including the "no session"
//! fallback when `ctx.task_mgr` is None.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::session::TaskManager;
use openclaudia::tools::registry::registry;
use serde_json::{json, Value};
use std::collections::HashMap;

mod support;

const NO_SESSION_MARKER: &str = "Task management not available (no session)";

fn dispatch_without_session(name: &str, args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool_with_tasks(name, args, None)
}

fn dispatch_with_session(
    name: &str,
    args: &HashMap<String, Value>,
    tm: &mut TaskManager,
) -> (String, bool) {
    support::dispatch_tool_with_tasks(name, args, Some(tm))
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    if m.contains_key("subject") && m.contains_key("description") {
        m.insert("expected_generation".to_string(), json!(0));
    }
    if m.contains_key("task_id")
        && [
            "status",
            "subject",
            "description",
            "active_form",
            "add_blocks",
            "add_blocked_by",
            "remove_blocks",
            "remove_blocked_by",
            "priority",
            "budget",
            "clear_budget",
        ]
        .iter()
        .any(|field| m.contains_key(*field))
    {
        m.insert("expected_generation".to_string(), json!(1));
        m.insert("expected_task_revision".to_string(), json!(1));
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — No-session fallback for all 4 task tools
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn task_create_without_session_returns_no_session_error() {
    let args = args_with(&[("subject", json!("Test")), ("description", json!("desc"))]);
    let (msg, is_err) = dispatch_without_session("task_create", &args);
    assert!(is_err);
    assert_eq!(
        msg, NO_SESSION_MARKER,
        "PINS NO_SESSION: documented message MUST match exactly"
    );
}

#[test]
fn task_update_without_session_returns_no_session_error() {
    let args = args_with(&[("task_id", json!("task-1"))]);
    let (msg, is_err) = dispatch_without_session("task_update", &args);
    assert!(is_err);
    assert_eq!(msg, NO_SESSION_MARKER);
}

#[test]
fn task_get_without_session_returns_no_session_error() {
    let args = args_with(&[("task_id", json!("task-1"))]);
    let (msg, is_err) = dispatch_without_session("task_get", &args);
    assert!(is_err);
    assert_eq!(msg, NO_SESSION_MARKER);
}

#[test]
fn task_list_without_session_returns_no_session_error() {
    let (msg, is_err) = dispatch_without_session("task_list", &HashMap::new());
    assert!(is_err);
    assert_eq!(msg, NO_SESSION_MARKER);
}

#[test]
fn no_session_path_is_consistent_across_all_4_tools() {
    // PINS NO_SESSION uniformity: all 4 task tools fall back
    // to the same message — model never has to remember
    // different no-session strings per tool.
    let tools_and_args: &[(&str, Value)] = &[
        ("task_create", json!({"subject": "x"})),
        ("task_update", json!({"task_id": "task-1"})),
        ("task_get", json!({"task_id": "task-1"})),
        ("task_list", json!({})),
    ];
    for (name, args_value) in tools_and_args {
        let args: HashMap<String, Value> = args_value
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let (msg, is_err) = dispatch_without_session(name, &args);
        assert!(is_err, "{name} MUST error without session");
        assert_eq!(msg, NO_SESSION_MARKER, "{name} MUST surface NO_SESSION");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — task_create with session
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn task_create_with_session_succeeds_and_returns_task_id() {
    let mut tm = TaskManager::new();
    let args = args_with(&[
        ("subject", json!("Implement feature X")),
        ("description", json!("desc")),
    ]);
    let (msg, is_err) = dispatch_with_session("task_create", &args, &mut tm);
    assert!(!is_err);
    // task_create returns a message that includes the new task id.
    assert!(
        msg.contains("task-1") || msg.contains("Created"),
        "MUST surface created-task confirmation; got {msg:?}"
    );
}

#[test]
fn task_create_missing_subject_errors_with_session() {
    let mut tm = TaskManager::new();
    let (msg, is_err) = dispatch_with_session("task_create", &HashMap::new(), &mut tm);
    assert!(is_err);
    assert_ne!(
        msg, NO_SESSION_MARKER,
        "session present → MUST NOT be no_session error"
    );
}

#[test]
fn task_create_subject_as_number_errors_with_session() {
    let mut tm = TaskManager::new();
    let args = args_with(&[("subject", json!(42)), ("description", json!("desc"))]);
    let (msg, is_err) = dispatch_with_session("task_create", &args, &mut tm);
    assert!(is_err);
    assert_ne!(msg, NO_SESSION_MARKER);
    assert!(msg.contains("Invalid 'subject' argument: expected string"));
}

#[test]
fn task_create_description_as_number_errors_with_session() {
    let mut tm = TaskManager::new();
    let args = args_with(&[("subject", json!("subject")), ("description", json!(42))]);
    let (msg, is_err) = dispatch_with_session("task_create", &args, &mut tm);
    assert!(is_err);
    assert_ne!(msg, NO_SESSION_MARKER);
    assert!(msg.contains("Invalid 'description' argument: expected string"));
}

#[test]
fn task_create_active_form_as_number_errors_with_session() {
    let mut tm = TaskManager::new();
    let args = args_with(&[
        ("subject", json!("subject")),
        ("description", json!("desc")),
        ("active_form", json!(42)),
    ]);
    let (msg, is_err) = dispatch_with_session("task_create", &args, &mut tm);
    assert!(is_err);
    assert_ne!(msg, NO_SESSION_MARKER);
    assert!(msg.contains("Invalid 'active_form' argument: expected string"));
}

#[test]
fn task_create_priority_and_budget_round_trip_through_real_dispatch() {
    let mut tm = TaskManager::new();
    let args = args_with(&[
        ("subject", json!("bounded critical task")),
        ("description", json!("desc")),
        ("priority", json!("critical")),
        ("budget", json!({"max_turns": 5, "max_tokens": 1000})),
    ]);
    let (msg, is_err) = dispatch_with_session("task_create", &args, &mut tm);
    assert!(!is_err, "{msg}");
    let task = tm.get_task("task-1").expect("created task");
    assert_eq!(
        task.priority,
        openclaudia::task_graph::TaskPriority::Critical
    );
    let budget = task.budget.as_ref().expect("bounded planning request");
    assert_eq!(budget.max_turns, Some(5));
    assert_eq!(budget.max_tokens, Some(1000));
}

#[test]
fn invalid_priority_and_empty_budget_are_atomic_dispatch_failures() {
    let mut tm = TaskManager::new();
    for extra in [("priority", json!("urgent")), ("budget", json!({}))] {
        let args = args_with(&[
            ("subject", json!("must not exist")),
            ("description", json!("desc")),
            extra,
        ]);
        let before = serde_json::to_vec(tm.graph()).expect("before graph");
        let (msg, is_err) = dispatch_with_session("task_create", &args, &mut tm);
        assert!(is_err, "invalid input unexpectedly succeeded: {msg}");
        assert_eq!(serde_json::to_vec(tm.graph()).expect("after graph"), before);
    }
}

#[test]
fn oversized_task_fields_and_edge_batches_are_atomic_dispatch_failures() {
    let mut manager = TaskManager::new();
    for (field, value) in [
        (
            "subject",
            "s".repeat(openclaudia::task_graph::MAX_TASK_SUBJECT_BYTES + 1),
        ),
        (
            "description",
            "d".repeat(openclaudia::task_graph::MAX_TASK_DESCRIPTION_BYTES + 1),
        ),
        (
            "active_form",
            "a".repeat(openclaudia::task_graph::MAX_TASK_ACTIVE_FORM_BYTES + 1),
        ),
    ] {
        let mut args = HashMap::from([
            ("expected_generation".to_string(), json!(0)),
            ("subject".to_string(), json!("bounded task")),
            ("description".to_string(), json!("bounded description")),
        ]);
        args.insert(field.to_string(), json!(value));
        let before = serde_json::to_vec(manager.graph()).expect("before field rejection");
        let (message, is_error) = dispatch_with_session("task_create", &args, &mut manager);
        assert!(is_error, "{field} unexpectedly succeeded: {message}");
        assert!(message.contains("exceeds"), "{field}: {message}");
        assert_eq!(
            serde_json::to_vec(manager.graph()).expect("after field rejection"),
            before,
            "{field} changed the graph"
        );
    }

    let (message, is_error) = dispatch_with_session(
        "task_create",
        &args_with(&[
            ("subject", json!("edge owner")),
            ("description", json!("desc")),
        ]),
        &mut manager,
    );
    assert!(!is_error, "{message}");
    let edge_ids = (0..=openclaudia::task_graph::MAX_TASK_EDGES)
        .map(|index| format!("task-{index}"))
        .collect::<Vec<_>>();
    let update = args_with(&[
        ("task_id", json!("task-1")),
        ("add_blocks", json!(edge_ids)),
    ]);
    let before = serde_json::to_vec(manager.graph()).expect("before edge rejection");
    let (message, is_error) = dispatch_with_session("task_update", &update, &mut manager);
    assert!(is_error, "oversized edge batch succeeded: {message}");
    assert!(message.contains("exceeds"), "{message}");
    assert_eq!(
        serde_json::to_vec(manager.graph()).expect("after edge rejection"),
        before
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — task_list with session
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn task_list_empty_manager_returns_documented_empty_message() {
    let mut tm = TaskManager::new();
    let (msg, is_err) = dispatch_with_session("task_list", &HashMap::new(), &mut tm);
    assert!(!is_err);
    assert_ne!(msg, NO_SESSION_MARKER);
}

#[test]
fn task_list_after_create_shows_created_task() {
    let mut tm = TaskManager::new();

    let create_args = args_with(&[
        ("subject", json!("unique_task_subject_marker_151")),
        ("description", json!("desc")),
    ]);
    let (_c_msg, c_err) = dispatch_with_session("task_create", &create_args, &mut tm);
    assert!(!c_err);

    let (l_msg, l_err) = dispatch_with_session("task_list", &HashMap::new(), &mut tm);
    assert!(!l_err);
    assert!(
        l_msg.contains("unique_task_subject_marker_151"),
        "task_list MUST show created task subject; got {l_msg:?}"
    );
}

#[test]
fn task_list_ready_only_uses_priority_order_and_rejects_cursor_mix() {
    let mut tm = TaskManager::new();
    for (generation, subject, priority) in [(0, "medium", "medium"), (1, "critical", "critical")] {
        let args = HashMap::from([
            ("expected_generation".to_string(), json!(generation)),
            ("subject".to_string(), json!(subject)),
            ("description".to_string(), json!("desc")),
            ("priority".to_string(), json!(priority)),
        ]);
        let (msg, is_err) = dispatch_with_session("task_create", &args, &mut tm);
        assert!(!is_err, "{msg}");
    }
    let (ready, is_err) = dispatch_with_session(
        "task_list",
        &HashMap::from([("ready_only".to_string(), json!(true))]),
        &mut tm,
    );
    assert!(!is_err, "{ready}");
    assert!(
        ready.find("critical").expect("critical") < ready.find("medium").expect("medium"),
        "{ready}"
    );

    let (message, is_err) = dispatch_with_session(
        "task_list",
        &HashMap::from([
            ("ready_only".to_string(), json!(true)),
            ("cursor".to_string(), json!("v1:2:1")),
        ]),
        &mut tm,
    );
    assert!(is_err);
    assert!(message.contains("cannot be used"), "{message}");
}

#[test]
fn task_list_rejects_oversized_cursor() {
    let mut manager = TaskManager::new();
    let cursor = "x".repeat(openclaudia::task_graph::MAX_PAGE_CURSOR_BYTES + 1);
    let (message, is_error) = dispatch_with_session(
        "task_list",
        &HashMap::from([("cursor".to_string(), json!(cursor))]),
        &mut manager,
    );
    assert!(is_error);
    assert!(message.contains("cursor is invalid"), "{message}");
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — task_get with session
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn task_get_unknown_task_id_returns_null_not_error() {
    // AUTHORING DISCOVERY: task_get for an unknown id returns
    // ("null", is_err=false) — pins the JSON-null sentinel
    // shape rather than raising an error. Documented contract:
    // `task_mgr.get_task(task_id).map_or_else(|| Value::Null.to_string(), ...)`.
    let mut tm = TaskManager::new();
    let args = args_with(&[("task_id", json!("nonexistent-task-marker"))]);
    let (msg, is_err) = dispatch_with_session("task_get", &args, &mut tm);
    assert!(!is_err, "PINS CONTRACT: get on unknown is null, not error");
    assert_eq!(msg, "null", "MUST return JSON Value::Null literal");
}

#[test]
fn task_get_missing_task_id_arg_errors() {
    let mut tm = TaskManager::new();
    let (msg, is_err) = dispatch_with_session("task_get", &HashMap::new(), &mut tm);
    assert!(is_err);
    assert_ne!(msg, NO_SESSION_MARKER);
}

#[test]
fn task_get_non_string_task_id_arg_errors() {
    let mut tm = TaskManager::new();
    let args = args_with(&[("task_id", json!(42))]);
    let (msg, is_err) = dispatch_with_session("task_get", &args, &mut tm);
    assert!(is_err);
    assert_ne!(msg, NO_SESSION_MARKER);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("malformed arguments"));
    assert!(msg.contains("'task_id'"));
}

#[test]
fn task_get_after_create_returns_created_task_details() {
    let mut tm = TaskManager::new();
    let create_args = args_with(&[
        ("subject", json!("get-test-marker-xyz")),
        ("description", json!("desc")),
    ]);
    let (_, c_err) = dispatch_with_session("task_create", &create_args, &mut tm);
    assert!(!c_err);

    let get_args = args_with(&[("task_id", json!("task-1"))]);
    let (g_msg, g_err) = dispatch_with_session("task_get", &get_args, &mut tm);
    assert!(!g_err, "task_get on existing id MUST succeed");
    assert!(
        g_msg.contains("get-test-marker-xyz"),
        "task_get MUST include subject; got {g_msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — task_update with session
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn task_update_missing_task_id_errors() {
    let mut tm = TaskManager::new();
    let (msg, is_err) = dispatch_with_session("task_update", &HashMap::new(), &mut tm);
    assert!(is_err);
    assert_ne!(msg, NO_SESSION_MARKER);
}

#[test]
fn task_update_non_string_task_id_errors() {
    let mut tm = TaskManager::new();
    let args = args_with(&[("task_id", json!(42))]);
    let (msg, is_err) = dispatch_with_session("task_update", &args, &mut tm);
    assert!(is_err);
    assert_ne!(msg, NO_SESSION_MARKER);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("malformed arguments"));
    assert!(msg.contains("'task_id'"));
}

#[test]
fn task_update_unknown_task_id_errors() {
    let mut tm = TaskManager::new();
    let args = args_with(&[
        ("task_id", json!("nonexistent")),
        ("status", json!("in_progress")),
    ]);
    let (msg, is_err) = dispatch_with_session("task_update", &args, &mut tm);
    assert!(is_err);
    assert_ne!(msg, NO_SESSION_MARKER);
}

#[test]
fn task_update_existing_task_status_succeeds() {
    let mut tm = TaskManager::new();
    let create_args = args_with(&[
        ("subject", json!("update test")),
        ("description", json!("desc")),
    ]);
    let (_, _) = dispatch_with_session("task_create", &create_args, &mut tm);

    let update_args = args_with(&[
        ("task_id", json!("task-1")),
        ("status", json!("in_progress")),
    ]);
    let (msg, is_err) = dispatch_with_session("task_update", &update_args, &mut tm);
    assert!(!is_err, "valid update MUST succeed; got {msg:?}");
}

#[test]
fn task_update_invalid_status_string_errors() {
    let mut tm = TaskManager::new();
    let create_args = args_with(&[
        ("subject", json!("invalid status test")),
        ("description", json!("desc")),
    ]);
    let (_, create_err) = dispatch_with_session("task_create", &create_args, &mut tm);
    assert!(!create_err);

    let update_args = args_with(&[("task_id", json!("task-1")), ("status", json!("doing"))]);
    let (msg, is_err) = dispatch_with_session("task_update", &update_args, &mut tm);
    assert!(is_err);
    assert!(
        msg.contains("Invalid task status") && msg.contains("in_progress"),
        "invalid status must fail with allowed statuses; got {msg:?}"
    );
}

#[test]
fn task_update_non_string_status_errors() {
    let mut tm = TaskManager::new();
    let create_args = args_with(&[
        ("subject", json!("non-string status test")),
        ("description", json!("desc")),
    ]);
    let (_, create_err) = dispatch_with_session("task_create", &create_args, &mut tm);
    assert!(!create_err);

    let update_args = args_with(&[("task_id", json!("task-1")), ("status", json!(42))]);
    let (msg, is_err) = dispatch_with_session("task_update", &update_args, &mut tm);
    assert!(is_err);
    assert!(
        msg.contains("Invalid task status") && msg.contains("non-string"),
        "non-string status must fail clearly; got {msg:?}"
    );
}

#[test]
fn task_update_non_string_subject_errors() {
    let mut tm = TaskManager::new();
    let create_args = args_with(&[
        ("subject", json!("non-string subject test")),
        ("description", json!("desc")),
    ]);
    let (_, create_err) = dispatch_with_session("task_create", &create_args, &mut tm);
    assert!(!create_err);

    let update_args = args_with(&[("task_id", json!("task-1")), ("subject", json!(42))]);
    let (msg, is_err) = dispatch_with_session("task_update", &update_args, &mut tm);
    assert!(is_err);
    assert!(
        msg.contains("Invalid task_update field 'subject'") && msg.contains("expected string"),
        "non-string subject must fail clearly; got {msg:?}"
    );
}

#[test]
fn task_update_add_blocks_non_array_errors() {
    let mut tm = TaskManager::new();
    let create_args = args_with(&[
        ("subject", json!("non-array add_blocks test")),
        ("description", json!("desc")),
    ]);
    let (_, create_err) = dispatch_with_session("task_create", &create_args, &mut tm);
    assert!(!create_err);

    let update_args = args_with(&[
        ("task_id", json!("task-1")),
        ("add_blocks", json!("task-2")),
    ]);
    let (msg, is_err) = dispatch_with_session("task_update", &update_args, &mut tm);
    assert!(is_err);
    assert!(
        msg.contains("Invalid task_update field 'add_blocks'") && msg.contains("array of strings"),
        "non-array add_blocks must fail clearly; got {msg:?}"
    );
}

#[test]
fn task_update_add_blocked_by_non_string_item_errors() {
    let mut tm = TaskManager::new();
    let create_args = args_with(&[
        ("subject", json!("non-string add_blocked_by item test")),
        ("description", json!("desc")),
    ]);
    let (_, create_err) = dispatch_with_session("task_create", &create_args, &mut tm);
    assert!(!create_err);

    let update_args = args_with(&[
        ("task_id", json!("task-1")),
        ("add_blocked_by", json!([42])),
    ]);
    let (msg, is_err) = dispatch_with_session("task_update", &update_args, &mut tm);
    assert!(is_err);
    assert!(
        msg.contains("Invalid task_update field 'add_blocked_by[0]'")
            && msg.contains("expected string"),
        "non-string add_blocked_by item must fail clearly; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Cross-tool: TaskManager state persists across dispatches
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn task_manager_state_persists_across_3_dispatches() {
    // PINS LIFECYCLE: create → update → list shows update.
    let mut tm = TaskManager::new();

    let create_args = args_with(&[
        ("subject", json!("persistence-test")),
        ("description", json!("desc")),
    ]);
    let (_, _) = dispatch_with_session("task_create", &create_args, &mut tm);

    let update_args = args_with(&[("task_id", json!("task-1")), ("status", json!("completed"))]);
    let (_, u_err) = dispatch_with_session("task_update", &update_args, &mut tm);
    assert!(!u_err);

    let (l_msg, l_err) = dispatch_with_session("task_list", &HashMap::new(), &mut tm);
    assert!(!l_err);
    // Updated status MUST be visible in list output.
    assert!(
        l_msg.contains("completed") || l_msg.contains("Completed") || l_msg.contains("DONE"),
        "list MUST reflect completed status; got {l_msg:?}"
    );
}

#[test]
fn distinct_task_managers_have_independent_state() {
    // PINS ISOLATION: separate TaskManager instances → separate
    // task lists; no shared global state via the registry.
    let mut tm_a = TaskManager::new();
    let mut tm_b = TaskManager::new();

    let create_args_a = args_with(&[
        ("subject", json!("ONLY_IN_A_xyz")),
        ("description", json!("desc")),
    ]);
    let (_, _) = dispatch_with_session("task_create", &create_args_a, &mut tm_a);

    let (alpha_list, _) = dispatch_with_session("task_list", &HashMap::new(), &mut tm_a);
    let (other_list, _) = dispatch_with_session("task_list", &HashMap::new(), &mut tm_b);
    assert!(alpha_list.contains("ONLY_IN_A_xyz"));
    assert!(!other_list.contains("ONLY_IN_A_xyz"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Registration
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn all_4_task_tools_registered_in_registry() {
    for name in &["task_create", "task_update", "task_get", "task_list"] {
        assert!(registry().get(name).is_some(), "{name} MUST be registered");
    }
}

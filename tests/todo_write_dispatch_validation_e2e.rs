//! End-to-end tests for the `todo_write` and `todo_read`
//! tools dispatched through the registry — pre-write
//! argument validation + the all-done auto-clear branch
//! (#972) + the 2000-byte content cap.
//!
//! Sprint 150 of the verification effort. Sprint 110 covered
//! the `TodoStatus` serde + `TodoItem` shape directly; this
//! file pins the registry-dispatched path so the wire-facing
//! contract matches.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::clear_all_todo_lists;
use openclaudia::tools::registry::registry;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

mod support;

fn todo_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn dispatch(name: &str, args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool(name, args)
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing/wrong-type todos field
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn todo_write_missing_todos_arg_returns_documented_error() {
    let _l = todo_lock();
    let (msg, is_err) = dispatch("todo_write", &HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("Missing 'todos' argument"),
        "MUST surface documented missing-todos; got {msg:?}"
    );
}

#[test]
fn todo_write_todos_as_string_returns_must_be_array_error() {
    let _l = todo_lock();
    let args = args_with(&[("todos", json!("not an array"))]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert!(
        msg.contains("'todos' must be an array"),
        "MUST surface array-type error; got {msg:?}"
    );
}

#[test]
fn todo_write_todos_as_number_returns_must_be_array_error() {
    let _l = todo_lock();
    let args = args_with(&[("todos", json!(42))]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert!(msg.contains("'todos' must be an array"));
}

#[test]
fn todo_write_todos_as_object_returns_must_be_array_error() {
    let _l = todo_lock();
    let args = args_with(&[("todos", json!({"k": "v"}))]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert!(msg.contains("'todos' must be an array"));
}

#[test]
fn todo_write_todos_as_null_returns_documented_error() {
    let _l = todo_lock();
    let args = args_with(&[("todos", Value::Null)]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    // null is NOT an array → surface "must be an array".
    assert_eq!(msg, "'todos' must be an array");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Per-item field validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn todo_item_as_string_returns_indexed_object_error() {
    let _l = todo_lock();
    let args = args_with(&[("todos", json!(["not an object"]))]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert_eq!(msg, "Todo 0 must be an object");
}

#[test]
fn todo_item_missing_content_field_returns_indexed_error() {
    let _l = todo_lock();
    let args = args_with(&[(
        "todos",
        json!([{
            "status": "pending",
            "activeForm": "Doing"
        }]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert!(
        msg.contains("Todo 0 missing 'content' field"),
        "MUST surface indexed missing-content; got {msg:?}"
    );
}

#[test]
fn todo_item_wrong_type_content_field_returns_indexed_error() {
    let _l = todo_lock();
    let args = args_with(&[(
        "todos",
        json!([{
            "content": 42,
            "status": "pending",
            "activeForm": "Doing"
        }]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert_eq!(msg, "Todo 0 'content' must be a string");
}

#[test]
fn todo_item_missing_status_field_returns_indexed_error() {
    let _l = todo_lock();
    let args = args_with(&[(
        "todos",
        json!([{
            "content": "test task",
            "activeForm": "Testing"
        }]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert!(
        msg.contains("Todo 0 missing 'status' field"),
        "MUST surface indexed missing-status; got {msg:?}"
    );
}

#[test]
fn todo_item_wrong_type_status_field_returns_indexed_error() {
    let _l = todo_lock();
    let args = args_with(&[(
        "todos",
        json!([{
            "content": "test task",
            "status": ["pending"],
            "activeForm": "Testing"
        }]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert_eq!(
        msg,
        "Todo 0 'status' must be a string. Must be: pending, in_progress, completed"
    );
}

#[test]
fn todo_item_missing_active_form_field_returns_indexed_error() {
    let _l = todo_lock();
    let args = args_with(&[(
        "todos",
        json!([{
            "content": "test",
            "status": "pending"
        }]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert!(
        msg.contains("Todo 0 missing 'activeForm' field"),
        "MUST surface indexed missing-activeForm; got {msg:?}"
    );
}

#[test]
fn todo_item_wrong_type_active_form_field_returns_indexed_error() {
    let _l = todo_lock();
    let args = args_with(&[(
        "todos",
        json!([{
            "content": "test",
            "status": "pending",
            "activeForm": null
        }]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert_eq!(msg, "Todo 0 'activeForm' must be a string");
}

#[test]
fn todo_item_invalid_status_value_returns_documented_3_choice_error() {
    let _l = todo_lock();
    let args = args_with(&[(
        "todos",
        json!([{
            "content": "test",
            "status": "not_a_status",
            "activeForm": "Testing"
        }]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert!(
        msg.contains("Todo 0 has invalid status") && msg.contains("not_a_status"),
        "MUST echo offending status; got {msg:?}"
    );
    // PINS DOC: error lists 3 valid statuses.
    assert!(
        msg.contains("pending") && msg.contains("in_progress") && msg.contains("completed"),
        "MUST list 3 documented statuses; got {msg:?}"
    );
}

#[test]
fn todo_item_second_position_error_indexed_correctly() {
    let _l = todo_lock();
    let args = args_with(&[(
        "todos",
        json!([
            {"content": "ok", "status": "pending", "activeForm": "Doing"},
            {"status": "pending", "activeForm": "Doing"},
        ]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert!(
        msg.contains("Todo 1"),
        "second-position error MUST report index 1; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Content length cap (2000 bytes)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn todo_item_content_over_2000_bytes_rejected() {
    let _l = todo_lock();
    let huge = "a".repeat(2500);
    let args = args_with(&[(
        "todos",
        json!([{
            "content": huge,
            "status": "pending",
            "activeForm": "Doing"
        }]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(is_err);
    assert!(
        msg.contains("exceeds maximum length") && msg.contains("2000"),
        "MUST surface 2000-byte cap; got {msg:?}"
    );
}

#[test]
fn todo_item_content_at_exactly_2000_bytes_accepted() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let exact = "a".repeat(2000);
    let args = args_with(&[(
        "todos",
        json!([{
            "content": exact,
            "status": "pending",
            "activeForm": "Doing"
        }]),
    )]);
    let (_msg, is_err) = dispatch("todo_write", &args);
    assert!(
        !is_err,
        "2000-byte content MUST be accepted (cap is strict >)"
    );
    clear_all_todo_lists();
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — All-done auto-clear branch (#972)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn all_completed_items_triggers_auto_clear_with_documented_message() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let args = args_with(&[(
        "todos",
        json!([
            {"content": "task 1", "status": "completed", "activeForm": "Task 1"},
            {"content": "task 2", "status": "completed", "activeForm": "Task 2"},
        ]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(!is_err);
    assert!(
        msg.contains("all 2 items completed") && msg.contains("list cleared"),
        "MUST surface auto-clear message; got {msg:?}"
    );
    clear_all_todo_lists();
}

#[test]
fn mixed_completed_and_pending_does_not_trigger_auto_clear() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let args = args_with(&[(
        "todos",
        json!([
            {"content": "done", "status": "completed", "activeForm": "Done"},
            {"content": "todo", "status": "pending", "activeForm": "Todoing"},
        ]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(!is_err);
    assert!(
        !msg.contains("list cleared"),
        "mixed list MUST NOT trigger auto-clear; got {msg:?}"
    );
    clear_all_todo_lists();
}

#[test]
fn empty_todos_array_does_not_trigger_auto_clear() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let args = args_with(&[("todos", json!([]))]);
    let (msg, is_err) = dispatch("todo_write", &args);
    // Empty list passes validation but is_empty MUST NOT count
    // as "all_done" (#972: empty != all_done).
    assert!(!is_err);
    assert!(
        !msg.contains("list cleared"),
        "empty list MUST NOT trigger auto-clear; got {msg:?}"
    );
    clear_all_todo_lists();
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Multiple in_progress warning
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn multiple_in_progress_items_emits_warning() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let args = args_with(&[(
        "todos",
        json!([
            {"content": "a", "status": "in_progress", "activeForm": "Doing A"},
            {"content": "b", "status": "in_progress", "activeForm": "Doing B"},
            {"content": "c", "status": "in_progress", "activeForm": "Doing C"},
        ]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(!is_err);
    assert!(
        msg.contains("Warning") && msg.contains("3 tasks marked as in_progress"),
        "MUST surface multi-in_progress warning; got {msg:?}"
    );
    clear_all_todo_lists();
}

#[test]
fn single_in_progress_item_does_not_emit_warning() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let args = args_with(&[(
        "todos",
        json!([
            {"content": "a", "status": "in_progress", "activeForm": "Doing A"},
            {"content": "b", "status": "pending", "activeForm": "Doing B"},
        ]),
    )]);
    let (msg, is_err) = dispatch("todo_write", &args);
    assert!(!is_err);
    assert!(
        !msg.contains("Warning"),
        "single in_progress MUST NOT emit warning; got {msg:?}"
    );
    clear_all_todo_lists();
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — todo_read dispatch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn todo_read_with_no_args_succeeds_on_empty_list() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let (_msg, is_err) = dispatch("todo_read", &HashMap::new());
    assert!(!is_err, "todo_read on empty list MUST NOT error");
}

#[test]
fn todo_read_after_write_shows_written_items() {
    let _l = todo_lock();
    clear_all_todo_lists();
    // Write 2 items.
    let write_args = args_with(&[(
        "todos",
        json!([
            {"content": "unique_marker_task_a", "status": "pending", "activeForm": "Doing A"},
            {"content": "unique_marker_task_b", "status": "in_progress", "activeForm": "Doing B"},
        ]),
    )]);
    let (_w_msg, w_err) = dispatch("todo_write", &write_args);
    assert!(!w_err);

    // Read MUST return both items.
    let (r_msg, r_err) = dispatch("todo_read", &HashMap::new());
    assert!(!r_err);
    assert!(
        r_msg.contains("unique_marker_task_a"),
        "todo_read MUST surface written item A; got {r_msg:?}"
    );
    assert!(
        r_msg.contains("unique_marker_task_b"),
        "todo_read MUST surface written item B; got {r_msg:?}"
    );
    clear_all_todo_lists();
}

#[test]
fn todo_read_ignores_arbitrary_args_no_panic() {
    let _l = todo_lock();
    let args = args_with(&[
        ("extra", json!("ignored")),
        ("session_id", json!("anything")),
    ]);
    let (_msg, _is_err) = dispatch("todo_read", &args);
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Registration
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn todo_write_and_todo_read_both_registered() {
    assert!(registry().get("todo_write").is_some());
    assert!(registry().get("todo_read").is_some());
}

//! End-to-end tests for `tools::todo` wire types and explicit per-session
//! bucketing semantics.
//!
//! Sprint 110 of the verification effort. Sprint 49 (via
//! `integration_tests.rs`) covered the basic
//! `execute_todo_*` round-trip; this file pins the
//! `TodoStatus` `snake_case` wire shape, the `TodoItem` `activeForm`
//! camelCase serde rename, and accessor isolation without ambient or
//! thread-local fallback identity.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{
    clear_all_todo_lists, clear_todo_list, execute_tool, get_todo_list, FunctionCall, TodoItem,
    TodoStatus, ToolCall, ToolRunContext,
};
use serde_json::json;
use std::sync::{Mutex, MutexGuard, OnceLock};

mod support;

// ───────────────────────────────────────────────────────────────────────────
// The compatibility graph map is process-wide; serialize legacy adapter
// assertions while production frontends use explicit task managers.
// ───────────────────────────────────────────────────────────────────────────

fn todo_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — TodoStatus serde (snake_case)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn todo_status_pending_serializes_as_snake_case() {
    let json = serde_json::to_string(&TodoStatus::Pending).expect("ser");
    assert_eq!(json, "\"pending\"");
}

#[test]
fn todo_status_in_progress_serializes_as_snake_case() {
    let json = serde_json::to_string(&TodoStatus::InProgress).expect("ser");
    assert_eq!(json, "\"in_progress\"");
}

#[test]
fn todo_status_completed_serializes_as_snake_case() {
    let json = serde_json::to_string(&TodoStatus::Completed).expect("ser");
    assert_eq!(json, "\"completed\"");
}

#[test]
fn todo_status_deserializes_from_snake_case_strings() {
    for (input, expected) in &[
        ("\"pending\"", TodoStatus::Pending),
        ("\"in_progress\"", TodoStatus::InProgress),
        ("\"completed\"", TodoStatus::Completed),
        ("\"failed\"", TodoStatus::Failed),
        ("\"canceled\"", TodoStatus::Canceled),
    ] {
        let parsed: TodoStatus = serde_json::from_str(input).expect("de");
        assert_eq!(parsed, *expected);
    }
}

#[test]
fn todo_status_rejects_uppercase_or_kebab_case() {
    assert!(serde_json::from_str::<TodoStatus>("\"PENDING\"").is_err());
    assert!(serde_json::from_str::<TodoStatus>("\"in-progress\"").is_err());
    assert!(serde_json::from_str::<TodoStatus>("\"done\"").is_err());
}

#[test]
fn todo_status_round_trips_all_variants() {
    for v in &[
        TodoStatus::Pending,
        TodoStatus::InProgress,
        TodoStatus::Completed,
        TodoStatus::Failed,
        TodoStatus::Canceled,
    ] {
        let json = serde_json::to_string(v).expect("ser");
        let back: TodoStatus = serde_json::from_str(&json).expect("de");
        assert_eq!(back, *v);
    }
}

#[test]
fn todo_status_is_copy_and_pairwise_distinct() {
    let p = TodoStatus::Pending;
    let copy = p;
    let again = p;
    assert_eq!(copy, again);
    assert_ne!(TodoStatus::Pending, TodoStatus::InProgress);
    assert_ne!(TodoStatus::InProgress, TodoStatus::Completed);
    assert_ne!(TodoStatus::Pending, TodoStatus::Completed);
    assert_ne!(TodoStatus::Completed, TodoStatus::Failed);
    assert_ne!(TodoStatus::Failed, TodoStatus::Canceled);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — TodoItem serde shape with activeForm rename
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn todo_item_serializes_active_form_as_camel_case_active_form() {
    let item = TodoItem {
        task_id: "task-1".to_string(),
        revision: 1,
        content: "do thing".to_string(),
        status: TodoStatus::Pending,
        active_form: "Doing thing".to_string(),
    };
    let json = serde_json::to_string(&item).expect("ser");
    // PINS WIRE FIELD: active_form ↔ "activeForm" rename.
    assert!(
        json.contains("\"activeForm\":\"Doing thing\""),
        "MUST use 'activeForm' on wire; got {json:?}"
    );
    assert!(
        !json.contains("active_form"),
        "MUST NOT emit snake_case wire name; got {json:?}"
    );
}

#[test]
fn todo_item_deserializes_from_active_form_camel_case() {
    let json = r#"{
        "task_id": "task-1",
        "revision": 1,
        "content": "task",
        "status": "in_progress",
        "activeForm": "Tasking"
    }"#;
    let item: TodoItem = serde_json::from_str(json).expect("de");
    assert_eq!(item.content, "task");
    assert_eq!(item.status, TodoStatus::InProgress);
    assert_eq!(item.active_form, "Tasking");
}

#[test]
fn todo_item_round_trips_full_shape() {
    let original = TodoItem {
        task_id: "task-2".to_string(),
        revision: 7,
        content: "implement feature".to_string(),
        status: TodoStatus::InProgress,
        active_form: "Implementing feature".to_string(),
    };
    let json = serde_json::to_string(&original).expect("ser");
    let back: TodoItem = serde_json::from_str(&json).expect("de");
    assert_eq!(back.content, original.content);
    assert_eq!(back.status, original.status);
    assert_eq!(back.active_form, original.active_form);
    assert_eq!(back.task_id, original.task_id);
    assert_eq!(back.revision, original.revision);
}

#[test]
fn todo_item_clone_preserves_all_fields() {
    let original = TodoItem {
        task_id: "task-3".to_string(),
        revision: 9,
        content: "c".to_string(),
        status: TodoStatus::Completed,
        active_form: "C".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(cloned.content, original.content);
    assert_eq!(cloned.status, original.status);
    assert_eq!(cloned.active_form, original.active_form);
    assert_eq!(cloned.task_id, original.task_id);
    assert_eq!(cloned.revision, original.revision);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — explicit session access and dispatch isolation
// ───────────────────────────────────────────────────────────────────────────

fn write_one(run: &std::sync::Arc<ToolRunContext>, content: &str) {
    let result = execute_tool(
        run,
        &ToolCall {
            id: format!("todo-{content}"),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "todo_write".to_string(),
                arguments: json!({
                    "expected_generation": 0,
                    "todos": [{
                        "content": content,
                        "status": "in_progress",
                        "activeForm": format!("Doing {content}")
                    }]
                })
                .to_string(),
            },
        },
    );
    assert!(!result.is_error(), "todo write failed: {result:?}");
}

#[test]
fn get_todo_list_on_fresh_explicit_session_is_empty() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let list = get_todo_list("fresh-session");
    assert!(list.is_empty());
}

#[test]
fn dispatch_uses_exact_run_session_buckets() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let first = support::test_run_context(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let second = support::test_run_context(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));

    write_one(&first, "first task");
    assert!(get_todo_list(second.session_id()).is_empty());
    write_one(&second, "second task");

    assert_eq!(get_todo_list(first.session_id())[0].content, "first task");
    assert_eq!(get_todo_list(second.session_id())[0].content, "second task");
}

#[test]
fn single_session_clear_cannot_mutate_another_bucket() {
    let _l = todo_lock();
    clear_all_todo_lists();
    let first = support::test_run_context(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let second = support::test_run_context(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    write_one(&first, "first task");
    write_one(&second, "second task");

    clear_todo_list(first.session_id());
    assert!(get_todo_list(first.session_id()).is_empty());
    assert_eq!(get_todo_list(second.session_id())[0].content, "second task");
}

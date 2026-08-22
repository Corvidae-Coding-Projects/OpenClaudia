use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

use crate::session::{TaskManager, TaskStatus};
use crate::task_graph::{
    CanonicalTaskStatus, TaskGraphGeneration, TaskId, TodoTaskDraft, MAX_TASKS,
    MAX_TASK_ACTIVE_FORM_BYTES,
};
use crate::tools::args::ToolArgs as _;

/// Hard cap on a single todo's `content` field, in *bytes* (matches the
/// Claude Code parity limit).
///
/// crosslink #979: this used to be a bare `2000` literal duplicated across
/// the length check and the error message; promoting to a `const` lets
/// future tuning happen in one place and lets the error message read the
/// same value the validator does.
///
/// Note on units: `String::len` returns the UTF-8 byte length, not the
/// grapheme count. The validator error string says "bytes" so the model
/// is not misled by the "characters" mis-naming the prior message used.
pub const TODO_CONTENT_MAX_BYTES: usize = 2000;

/// Lifecycle state of a single todo item. crosslink #973.
///
/// Was previously a `String` validated against the literal slice
/// `["pending", "in_progress", "completed"]` at write time, with every
/// downstream consumer re-comparing the same hardcoded strings. The
/// `#[serde(rename_all = "snake_case")]` attribute keeps the on-wire form
/// identical to the previous string-based representation
/// (`"pending"` / `"in_progress"` / `"completed"`), so existing callers
/// and serialized session state continue to round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TodoStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Canceled,
}

impl TodoStatus {
    const VALID_VALUES: &'static str = "pending, in_progress, completed, failed, canceled";

    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "in_progress" => Some(Self::InProgress),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "canceled" => Some(Self::Canceled),
            _ => None,
        }
    }

    /// Short single-character icon used by `execute_todo_read` to render
    /// the status alongside the content. Moved here from a stringly-typed
    /// `match` over the underlying `&str` so adding a new state is a
    /// single-file edit guarded by the type system.
    const fn icon(self) -> &'static str {
        match self {
            Self::Completed => "[x]",
            Self::InProgress => "[>]",
            Self::Pending => "[ ]",
            Self::Failed => "[!]",
            Self::Canceled => "[-]",
        }
    }
}

/// Todo item for task tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoItem {
    /// Stable canonical identity returned by `todo_read` and required for a
    /// later replacement of an existing row.
    pub task_id: String,
    /// Optimistic task revision paired with `task_id`.
    pub revision: u64,
    pub content: String,
    pub status: TodoStatus,
    #[serde(rename = "activeForm")]
    pub active_form: String,
}

const fn todo_validation_error(message: String) -> (String, bool) {
    (message, true)
}

fn required_todo_string_field<'a>(
    i: usize,
    item: &'a Value,
    field: &'static str,
) -> Result<&'a str, (String, bool)> {
    match item.get(field) {
        None => Err(todo_validation_error(format!(
            "Todo {i} missing '{field}' field"
        ))),
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(todo_validation_error(format!(
            "Todo {i} '{field}' must be a string"
        ))),
    }
}

fn parse_todo_status(i: usize, item: &Value) -> Result<TodoStatus, (String, bool)> {
    let Some(raw) = item.get("status") else {
        return Err(todo_validation_error(format!(
            "Todo {i} missing 'status' field"
        )));
    };

    let Some(status) = raw.as_str() else {
        return Err(todo_validation_error(format!(
            "Todo {i} 'status' must be a string. Must be: {}",
            TodoStatus::VALID_VALUES
        )));
    };

    TodoStatus::from_wire(status).ok_or_else(|| {
        todo_validation_error(format!(
            "Todo {i} has invalid status '{status}'. Must be: {}",
            TodoStatus::VALID_VALUES
        ))
    })
}

/// Write/update the todo list
/// Parse and validate a single `todos[i]` JSON object into a [`TodoItem`].
///
/// Surfaces every per-item validation failure as a `(message, true)`
/// tuple matching the entry-point return shape so the caller can bubble
/// it back to the model without restringing. crosslink #973 / #979.
fn parse_todo_item(i: usize, item: &Value) -> Result<TodoTaskDraft, (String, bool)> {
    if !item.is_object() {
        return Err(todo_validation_error(format!("Todo {i} must be an object")));
    }

    let content = required_todo_string_field(i, item, "content")?;
    if content.trim().is_empty() {
        return Err(todo_validation_error(format!(
            "Todo {i} content must not be empty"
        )));
    }
    if content.len() > TODO_CONTENT_MAX_BYTES {
        return Err(todo_validation_error(format!(
            "Todo {i} content exceeds maximum length of {TODO_CONTENT_MAX_BYTES} bytes"
        )));
    }

    let status = parse_todo_status(i, item)?;
    let active_form = required_todo_string_field(i, item, "activeForm")?;
    if active_form.trim().is_empty() {
        return Err(todo_validation_error(format!(
            "Todo {i} activeForm must not be empty"
        )));
    }
    if active_form.len() > MAX_TASK_ACTIVE_FORM_BYTES {
        return Err(todo_validation_error(format!(
            "Todo {i} activeForm exceeds maximum length of {MAX_TASK_ACTIVE_FORM_BYTES} bytes"
        )));
    }

    let task_id = match item.get("task_id") {
        None => None,
        Some(Value::String(id)) => Some(
            TaskId::parse(id.clone()).map_err(|error| todo_validation_error(error.to_string()))?,
        ),
        Some(_) => {
            return Err(todo_validation_error(format!(
                "Todo {i} 'task_id' must be a string"
            )));
        }
    };
    let expected_task_revision = match item.get("expected_task_revision") {
        None => None,
        Some(Value::Number(value)) => Some(value.as_u64().ok_or_else(|| {
            todo_validation_error(format!(
                "Todo {i} 'expected_task_revision' must be a non-negative integer"
            ))
        })?),
        Some(_) => {
            return Err(todo_validation_error(format!(
                "Todo {i} 'expected_task_revision' must be a non-negative integer"
            )));
        }
    };

    Ok(TodoTaskDraft {
        task_id,
        expected_task_revision,
        content: content.to_string(),
        status: canonical_status(status),
        active_form: active_form.to_string(),
    })
}

/// Apply one generation-checked complete todo projection to the canonical
/// task graph. No process-global todo store participates.
pub fn execute_todo_write(
    task_manager: &mut TaskManager,
    args: &HashMap<String, Value>,
) -> (String, bool) {
    let Some(todos_value) = args.get("todos") else {
        return ("Missing 'todos' argument".to_string(), true);
    };

    let Some(todos_array) = todos_value.as_array() else {
        return ("'todos' must be an array".to_string(), true);
    };
    if todos_array.len() > MAX_TASKS {
        return (
            format!("'todos' exceeds the canonical limit of {MAX_TASKS} items"),
            true,
        );
    }

    let mut new_todos = Vec::with_capacity(todos_array.len());
    for (i, item) in todos_array.iter().enumerate() {
        let todo_item = match parse_todo_item(i, item) {
            Ok(t) => t,
            Err(err) => return err,
        };
        new_todos.push(todo_item);
    }
    let expected_generation = match args.arg_u64_strict("expected_generation") {
        Ok(value) => TaskGraphGeneration::from_u64(value),
        Err(error) => return error.into_tool_error(),
    };
    let total = new_todos.len();
    let completed = new_todos
        .iter()
        .filter(|task| task.status == CanonicalTaskStatus::Completed)
        .count();
    let in_progress = new_todos
        .iter()
        .filter(|task| task.status == CanonicalTaskStatus::InProgress)
        .count();
    let pending = new_todos
        .iter()
        .filter(|task| task.status == CanonicalTaskStatus::Pending)
        .count();
    let failed = new_todos
        .iter()
        .filter(|task| task.status == CanonicalTaskStatus::Failed)
        .count();
    let canceled = new_todos
        .iter()
        .filter(|task| task.status == CanonicalTaskStatus::Canceled)
        .count();
    let current = new_todos
        .iter()
        .find(|task| task.status == CanonicalTaskStatus::InProgress)
        .map(|task| task.active_form.clone());
    let all_completed = total != 0 && completed == total;
    if let Err(error) = task_manager.replace_todos_checked(expected_generation, new_todos) {
        return (error, true);
    }

    let mut output = format!(
        "Todo list updated at canonical generation {}: {} total ({} completed, {} in progress, {} pending, {} failed, {} canceled)",
        task_manager.generation(),
        total,
        completed,
        in_progress,
        pending,
        failed,
        canceled
    );

    // Show current in-progress task if any
    if let Some(current) = current {
        let _ = write!(output, "\n\nCurrently: {current}");
    }

    if all_completed {
        let _ = write!(
            output,
            "\nall {completed} items completed; todo list cleared while canonical completion history is retained."
        );
    }

    (output, false)
}

/// Read the todo projection of the canonical graph with stable identities and
/// optimistic versions needed by a subsequent write.
pub fn execute_todo_read(task_manager: &mut TaskManager) -> (String, bool) {
    if let Err(error) = task_manager.refresh() {
        return (error, true);
    }
    let todos = project_todo_list(task_manager);

    if todos.is_empty() {
        return (
            format!(
                "No todos in view. Canonical graph generation: {}.",
                task_manager.generation()
            ),
            false,
        );
    }

    let mut output = format!(
        "Canonical graph generation: {}\n",
        task_manager.generation()
    );
    for (i, item) in todos.iter().enumerate() {
        let _ = writeln!(
            output,
            "{}. {} {} [task_id={}, revision={}]",
            i + 1,
            item.status.icon(),
            item.content,
            item.task_id,
            item.revision
        );
    }

    // Summary
    let completed = todos
        .iter()
        .filter(|t| t.status == TodoStatus::Completed)
        .count();
    let in_progress = todos
        .iter()
        .filter(|t| t.status == TodoStatus::InProgress)
        .count();
    let pending = todos
        .iter()
        .filter(|t| t.status == TodoStatus::Pending)
        .count();
    let failed = todos
        .iter()
        .filter(|t| t.status == TodoStatus::Failed)
        .count();
    let canceled = todos
        .iter()
        .filter(|t| t.status == TodoStatus::Canceled)
        .count();

    let _ = write!(
        output,
        "\n({completed} completed, {in_progress} in progress, {pending} pending, {failed} failed, {canceled} canceled)"
    );

    (output, false)
}

/// Project all current canonical tasks into the compact todo view. Once every
/// current row is completed the view is empty, while task nodes and immutable
/// completion history remain available through the task view.
#[must_use]
fn project_todo_list(task_manager: &TaskManager) -> Vec<TodoItem> {
    let items = task_manager
        .list_tasks()
        .iter()
        .filter(|task| {
            matches!(
                task.source,
                crate::task_graph::TaskSource::TaskTool | crate::task_graph::TaskSource::TodoView
            )
        })
        .map(|task| TodoItem {
            task_id: task.id.clone(),
            revision: task.revision,
            content: task.subject.clone(),
            status: todo_status(task.status),
            active_form: task
                .active_form
                .clone()
                .unwrap_or_else(|| task.subject.clone()),
        })
        .collect::<Vec<_>>();
    if !items.is_empty()
        && items
            .iter()
            .all(|item| item.status == TodoStatus::Completed)
    {
        Vec::new()
    } else {
        items
    }
}

/// Legacy composition boundary for callers that expose only a run context.
/// Values are canonical task graphs, not an independent todo representation.
/// Production frontends pass an explicit durable [`TaskManager`] instead.
type CompatibilityGraphs = HashMap<String, TaskManager>;

static COMPATIBILITY_GRAPHS: std::sync::LazyLock<Mutex<CompatibilityGraphs>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn compatibility_graphs_guard(
    operation: &'static str,
) -> Result<MutexGuard<'static, CompatibilityGraphs>, String> {
    COMPATIBILITY_GRAPHS.lock().map_err(|error| {
        tracing::error!(operation, %error, "Canonical compatibility graph lock poisoned");
        error.to_string()
    })
}

fn with_run_task_manager<R>(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
    operation: &'static str,
    use_manager: impl FnOnce(&mut TaskManager) -> R,
) -> Result<R, String> {
    let mut graphs = compatibility_graphs_guard(operation)?;
    if !graphs.contains_key(run.session_id()) {
        graphs.insert(run.session_id().to_string(), TaskManager::for_run(run)?);
    }
    graphs
        .get_mut(run.session_id())
        .map(use_manager)
        .ok_or_else(|| "canonical compatibility graph disappeared".to_string())
}

pub fn execute_todo_write_for_run(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> (String, bool) {
    with_run_task_manager(run, "todo_write", |manager| {
        execute_todo_write(manager, args)
    })
    .unwrap_or_else(|error| (error, true))
}

pub fn execute_todo_read_for_run(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
) -> (String, bool) {
    with_run_task_manager(run, "todo_read", execute_todo_read).unwrap_or_else(|error| (error, true))
}

/// Inspect the canonical compatibility graph for one explicit session key.
/// New code should use an explicit task manager and `todo_read` instead.
#[must_use]
pub fn get_todo_list(session_key: &str) -> Vec<TodoItem> {
    compatibility_graphs_guard("get_todo_list")
        .ok()
        .and_then(|graphs| graphs.get(session_key).map(project_todo_list))
        .unwrap_or_default()
}

/// Reset one legacy compatibility graph.
///
/// This is a lifecycle/test operation, not the model-facing clear path;
/// explicit managers submit an empty,
/// generation-checked todo replacement so tombstone history is retained.
pub fn clear_todo_list(session_key: &str) {
    if let Ok(mut graphs) = compatibility_graphs_guard("clear_todo_list") {
        graphs.remove(session_key);
    }
}

/// Reset every legacy compatibility graph during an explicit global teardown.
pub fn clear_all_todo_lists() {
    if let Ok(mut graphs) = compatibility_graphs_guard("clear_all_todo_lists") {
        graphs.clear();
    }
}

const fn canonical_status(status: TodoStatus) -> CanonicalTaskStatus {
    match status {
        TodoStatus::Pending => CanonicalTaskStatus::Pending,
        TodoStatus::InProgress => CanonicalTaskStatus::InProgress,
        TodoStatus::Completed => CanonicalTaskStatus::Completed,
        TodoStatus::Failed => CanonicalTaskStatus::Failed,
        TodoStatus::Canceled => CanonicalTaskStatus::Canceled,
    }
}

const fn todo_status(status: TaskStatus) -> TodoStatus {
    match status {
        TaskStatus::Pending => TodoStatus::Pending,
        TaskStatus::InProgress => TodoStatus::InProgress,
        TaskStatus::Completed => TodoStatus::Completed,
        TaskStatus::Failed => TodoStatus::Failed,
        TaskStatus::Canceled => TodoStatus::Canceled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    const TEST_SESSION: &str = "todo-unit-session";

    /// These compatibility-adapter tests share their local fixture map, so
    /// they serialize to avoid interleaving under Cargo's parallel runner.
    fn task_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn managers() -> &'static Mutex<HashMap<String, TaskManager>> {
        static MANAGERS: OnceLock<Mutex<HashMap<String, TaskManager>>> = OnceLock::new();
        MANAGERS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn clear_all_todo_lists() {
        managers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    fn get_todo_list(session: &str) -> Vec<TodoItem> {
        managers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(session)
            .map(super::project_todo_list)
            .unwrap_or_default()
    }

    fn execute_todo_write(session: &str, args: &HashMap<String, Value>) -> (String, bool) {
        let mut managers = managers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let manager = managers.entry(session.to_string()).or_default();
        let mut versioned = args.clone();
        versioned.insert(
            "expected_generation".to_string(),
            serde_json::json!(manager.generation().get()),
        );
        let result = super::execute_todo_write(manager, &versioned);
        drop(managers);
        result
    }

    fn execute_todo_read(session: &str) -> (String, bool) {
        let mut managers = managers()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        super::execute_todo_read(managers.entry(session.to_string()).or_default())
    }

    fn args_with(v: Value) -> HashMap<String, Value> {
        let mut m = HashMap::new();
        m.insert("todos".to_string(), v);
        m
    }

    #[test]
    fn all_done_clears_the_list() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let args = args_with(json!([
            {"content": "one", "status": "completed", "activeForm": "Doing one"},
            {"content": "two", "status": "completed", "activeForm": "Doing two"},
        ]));
        let (msg, err) = execute_todo_write(TEST_SESSION, &args);
        assert!(!err);
        assert!(msg.contains("2 total"), "got: {msg}");
        assert!(msg.contains("all 2 items completed"));
        assert!(get_todo_list(TEST_SESSION).is_empty());
    }

    #[test]
    fn mixed_statuses_are_preserved() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let args = args_with(json!([
            {"content": "one", "status": "completed", "activeForm": "Doing one"},
            {"content": "two", "status": "in_progress", "activeForm": "Doing two"},
            {"content": "three", "status": "failed", "activeForm": "Doing three"},
            {"content": "four", "status": "canceled", "activeForm": "Doing four"},
        ]));
        let (message, err) = execute_todo_write(TEST_SESSION, &args);
        assert!(!err);
        let stored = get_todo_list(TEST_SESSION);
        assert_eq!(stored.len(), 4, "partial completion must keep the list");
        assert!(message.contains("1 completed"), "got: {message}");
        assert!(message.contains("1 in progress"), "got: {message}");
        assert!(message.contains("0 pending"), "got: {message}");
        assert!(message.contains("1 failed"), "got: {message}");
        assert!(message.contains("1 canceled"), "got: {message}");
        let (read, read_error) = execute_todo_read(TEST_SESSION);
        assert!(!read_error);
        assert!(read.contains("1 failed"), "got: {read}");
        assert!(read.contains("1 canceled"), "got: {read}");
    }

    #[test]
    fn per_session_buckets_do_not_collide() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let (_, err) = execute_todo_write(
            "session-a",
            &args_with(json!([{
                "content": "a task",
                "status": "in_progress",
                "activeForm": "Doing a"
            }])),
        );
        assert!(!err);
        assert!(get_todo_list("session-b").is_empty());

        let (_, err) = execute_todo_write(
            "session-b",
            &args_with(json!([{
                "content": "b task",
                "status": "in_progress",
                "activeForm": "Doing b"
            }])),
        );
        assert!(!err);
        assert_eq!(get_todo_list("session-b")[0].content, "b task");

        let list = get_todo_list("session-a");
        assert_eq!(list.len(), 1, "session-a list must survive session-b edits");
        assert_eq!(list[0].content, "a task");
    }

    #[test]
    fn empty_input_is_not_treated_as_all_done() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let args = args_with(json!([]));
        let (msg, err) = execute_todo_write(TEST_SESSION, &args);
        assert!(!err);
        // Empty input must NOT trigger the "all done" cleared-list
        // message — that message implies the agent finished actual work.
        assert!(!msg.contains("all 0 items completed"));
        assert!(get_todo_list(TEST_SESSION).is_empty());
    }

    // ─── Spec §4: todo_write — full-replacement, atomic, per-session ───────────

    /// Contract: `todos` argument is required; absent → `is_error=true`.
    #[test]
    fn todo_write_requires_todos_argument() {
        let _lock = task_lock();
        let args = HashMap::new(); // no "todos" key
        let (msg, is_err) = execute_todo_write(TEST_SESSION, &args);
        assert!(is_err, "missing 'todos' must be an error");
        assert!(
            msg.contains("Missing 'todos'"),
            "error must mention 'todos'; got: {msg}"
        );
    }

    /// Contract: `todos` must be an array; a scalar → `is_error=true`.
    #[test]
    fn todo_write_requires_todos_to_be_array() {
        let _lock = task_lock();
        let mut args = HashMap::new();
        args.insert("todos".to_string(), json!("not-an-array"));
        let (msg, is_err) = execute_todo_write(TEST_SESSION, &args);
        assert!(is_err);
        assert!(
            msg.contains("must be an array"),
            "error must say 'must be an array'; got: {msg}"
        );
    }

    /// Contract: each item must have a `content` field; absent → `is_error=true`.
    #[test]
    fn todo_write_rejects_item_missing_content() {
        let _lock = task_lock();
        let args = args_with(json!([{"status": "pending", "activeForm": "doing"}]));
        let (msg, is_err) = execute_todo_write(TEST_SESSION, &args);
        assert!(is_err);
        assert!(
            msg.contains("missing 'content'"),
            "error must name missing field; got: {msg}"
        );
    }

    /// Contract: each item must have a `status` field; absent → `is_error=true`.
    #[test]
    fn todo_write_rejects_item_missing_status() {
        let _lock = task_lock();
        let args = args_with(json!([{"content": "task", "activeForm": "doing"}]));
        let (msg, is_err) = execute_todo_write(TEST_SESSION, &args);
        assert!(is_err);
        assert!(
            msg.contains("missing 'status'"),
            "error must name missing field; got: {msg}"
        );
    }

    /// Contract: each item must have an `activeForm` field; absent → `is_error=true`.
    #[test]
    fn todo_write_rejects_item_missing_active_form() {
        let _lock = task_lock();
        let args = args_with(json!([{"content": "task", "status": "pending"}]));
        let (msg, is_err) = execute_todo_write(TEST_SESSION, &args);
        assert!(is_err);
        assert!(
            msg.contains("missing 'activeForm'"),
            "error must name missing field; got: {msg}"
        );
    }

    /// Contract: invalid `status` value → `is_error=true` naming the bad value.
    #[test]
    fn todo_write_rejects_invalid_status_value() {
        let _lock = task_lock();
        let args = args_with(json!([{
            "content": "task",
            "status": "doing",   // not pending/in_progress/completed
            "activeForm": "doing"
        }]));
        let (msg, is_err) = execute_todo_write(TEST_SESSION, &args);
        assert!(is_err);
        assert!(
            msg.contains("invalid status"),
            "error must say 'invalid status'; got: {msg}"
        );
    }

    /// Contract: content > 2000 chars → `is_error=true`.
    #[test]
    fn todo_write_rejects_content_exceeding_2000_chars() {
        let _lock = task_lock();
        let long_content = "x".repeat(2001);
        let args = args_with(json!([{
            "content": long_content,
            "status": "pending",
            "activeForm": "working"
        }]));
        let (msg, is_err) = execute_todo_write(TEST_SESSION, &args);
        assert!(is_err);
        assert!(
            msg.contains("maximum length"),
            "error must mention 'maximum length'; got: {msg}"
        );
    }

    /// Contract: content exactly 2000 chars is accepted.
    #[test]
    fn todo_write_accepts_content_exactly_2000_chars() {
        let _lock = task_lock();
        clear_all_todo_lists();
        let exact_content = "y".repeat(2000);
        let args = args_with(json!([{
            "content": exact_content,
            "status": "pending",
            "activeForm": "working"
        }]));
        let (_, is_err) = execute_todo_write(TEST_SESSION, &args);
        assert!(!is_err, "exactly 2000 chars must be accepted");
    }

    /// Contract: write is a full replacement — a second call with a single item
    /// replaces the entire previous list (no merge/append).
    #[test]
    fn todo_write_is_full_replacement_not_merge() {
        let _lock = task_lock();
        clear_all_todo_lists();

        // First write: two items
        let (_, e1) = execute_todo_write(
            TEST_SESSION,
            &args_with(json!([
                {"content": "first",  "status": "pending",     "activeForm": "A"},
                {"content": "second", "status": "in_progress", "activeForm": "B"},
            ])),
        );
        assert!(!e1);
        assert_eq!(get_todo_list(TEST_SESSION).len(), 2);

        // Second write: one item — must replace, not append
        let (_, e2) = execute_todo_write(
            TEST_SESSION,
            &args_with(json!([
                {"content": "replacement", "status": "pending", "activeForm": "C"},
            ])),
        );
        assert!(!e2);
        let stored = get_todo_list(TEST_SESSION);
        assert_eq!(
            stored.len(),
            1,
            "full replacement: only the new item must remain"
        );
        assert_eq!(stored[0].content, "replacement");
    }

    /// Contract: all-done semantics — when every item is `completed` the stored
    /// list is cleared (not kept as a list of done items).
    #[test]
    fn todo_write_all_done_clears_list_and_confirms_count() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let (msg, is_err) = execute_todo_write(
            TEST_SESSION,
            &args_with(json!([
                {"content": "alpha", "status": "completed", "activeForm": "A"},
                {"content": "beta",  "status": "completed", "activeForm": "B"},
                {"content": "gamma", "status": "completed", "activeForm": "C"},
            ])),
        );
        assert!(!is_err);
        assert!(
            msg.contains("all 3 items completed"),
            "success message must state count; got: {msg}"
        );
        assert!(
            get_todo_list(TEST_SESSION).is_empty(),
            "list must be empty after all-done"
        );
    }

    /// A replacement with multiple active rows violates the canonical actor
    /// lane invariant and must fail without publishing either row.
    #[test]
    fn todo_write_rejects_multiple_in_progress_atomically() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let (msg, is_err) = execute_todo_write(
            TEST_SESSION,
            &args_with(json!([
                {"content": "a", "status": "in_progress", "activeForm": "A"},
                {"content": "b", "status": "in_progress", "activeForm": "B"},
            ])),
        );
        assert!(is_err, "multiple in_progress must be rejected");
        assert!(msg.contains("multiple in-progress"), "got: {msg}");
        assert!(get_todo_list(TEST_SESSION).is_empty());
    }

    /// Contract: a single `in_progress` item produces no warning.
    #[test]
    fn todo_write_no_warning_for_single_in_progress() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let (msg, is_err) = execute_todo_write(
            TEST_SESSION,
            &args_with(json!([
                {"content": "only", "status": "in_progress", "activeForm": "Only"},
            ])),
        );
        assert!(!is_err);
        assert!(
            !msg.contains("Warning"),
            "single in_progress must not warn; got: {msg}"
        );
    }

    /// Contract: `execute_todo_read` on an empty (or cleared) list returns a
    /// non-error "No todos" message.
    #[test]
    fn todo_read_on_empty_list_returns_no_todos() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let (msg, is_err) = execute_todo_read(TEST_SESSION);
        assert!(!is_err);
        assert!(
            msg.contains("No todos"),
            "empty list read must say 'No todos'; got: {msg}"
        );
    }

    /// Contract: `execute_todo_read` after a write returns the stored items.
    #[test]
    fn todo_read_returns_written_items() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let (_, err) = execute_todo_write(
            TEST_SESSION,
            &args_with(json!([
                {"content": "readable task", "status": "pending", "activeForm": "T"},
            ])),
        );
        assert!(!err);

        let (msg, is_err) = execute_todo_read(TEST_SESSION);
        assert!(!is_err);
        assert!(
            msg.contains("readable task"),
            "read must show written content; got: {msg}"
        );
    }
}

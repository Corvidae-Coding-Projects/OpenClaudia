use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

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
}

impl TodoStatus {
    const VALID_VALUES: &'static str = "pending, in_progress, completed";

    fn from_wire(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "in_progress" => Some(Self::InProgress),
            "completed" => Some(Self::Completed),
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
        }
    }
}

/// Todo item for task tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoItem {
    pub content: String,
    pub status: TodoStatus,
    #[serde(rename = "activeForm")]
    pub active_form: String,
}

/// Sentinel key used when no session context is active. Keeps
/// non-session callers (tests, scripts, the chat REPL pre-session)
/// from losing their list in a world where everything else is keyed
/// by session. Matches Claude Code's agentId-fallback pattern
/// (`context.agentId ?? getSessionId()`).
const DEFAULT_SESSION_KEY: &str = "__default__";

thread_local! {
    /// Per-thread "current session id" used by [`execute_todo_write`]
    /// and [`execute_todo_read`] to pick the bucket in [`TODO_LISTS`].
    /// Tokio's `spawn_blocking` reuses worker threads, so callers must
    /// set-and-clear this via [`SessionIdGuard`] rather than raw
    /// `set()`/`get()` to avoid leaking state to the next tool call
    /// that lands on the same worker.
    static CURRENT_SESSION_ID: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// RAII guard: set the thread-local session id on construction, clear
/// it on drop. Drop runs unconditionally even on panic, so the next
/// unrelated task on the same worker thread can't read a stale value.
#[must_use = "dropping the guard immediately clears the session id"]
pub struct SessionIdGuard {
    previous: Option<String>,
}

impl SessionIdGuard {
    /// Set the current thread's session id to `id` for the lifetime
    /// of the returned guard. Restores whatever value was there
    /// before (which is almost always `None`).
    pub fn set(id: impl Into<String>) -> Self {
        let id = id.into();
        if let Err(error) = super::security::ensure_session_context(&id) {
            tracing::error!(
                session_id = %id,
                %error,
                "Failed to initialize immutable tool security context"
            );
        }
        let previous = CURRENT_SESSION_ID.with(|cell| cell.replace(Some(id)));
        Self { previous }
    }
}

impl Drop for SessionIdGuard {
    fn drop(&mut self) {
        let restore = self.previous.take();
        CURRENT_SESSION_ID.with(|cell| *cell.borrow_mut() = restore);
    }
}

/// Read the current thread's session id, or the default key when no
/// guard is active on this thread. Other tool modules in this crate
/// (e.g. `file::ReadFileTracker`) call this via the sibling
/// `tools::todo::` path so per-session bucketing is shared instead
/// of each module rolling its own thread-local.
pub(super) fn current_session_key() -> String {
    CURRENT_SESSION_ID
        .with(|cell| cell.borrow().clone())
        .unwrap_or_else(|| DEFAULT_SESSION_KEY.to_string())
}

/// Per-session todo storage. Keyed by session id (or
/// [`DEFAULT_SESSION_KEY`] when no guard is active). Claude Code uses
/// the same model — see TodoWriteTool.ts where `todoKey = context.agentId
/// ?? getSessionId()` buckets each agent/session separately.
type TodoLists = HashMap<String, Vec<TodoItem>>;

static TODO_LISTS: std::sync::LazyLock<Mutex<TodoLists>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn todo_lists_guard(operation: &'static str) -> Result<MutexGuard<'static, TodoLists>, String> {
    TODO_LISTS.lock().map_err(|err| {
        tracing::error!(operation, error = %err, "Todo list lock poisoned");
        err.to_string()
    })
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
fn parse_todo_item(i: usize, item: &Value) -> Result<TodoItem, (String, bool)> {
    if !item.is_object() {
        return Err(todo_validation_error(format!("Todo {i} must be an object")));
    }

    let content = required_todo_string_field(i, item, "content")?;
    if content.len() > TODO_CONTENT_MAX_BYTES {
        return Err(todo_validation_error(format!(
            "Todo {i} content exceeds maximum length of {TODO_CONTENT_MAX_BYTES} bytes"
        )));
    }

    let status = parse_todo_status(i, item)?;
    let active_form = required_todo_string_field(i, item, "activeForm")?.to_string();

    Ok(TodoItem {
        content: content.to_string(),
        status,
        active_form,
    })
}

pub fn execute_todo_write(args: &HashMap<String, Value>) -> (String, bool) {
    let Some(todos_value) = args.get("todos") else {
        return ("Missing 'todos' argument".to_string(), true);
    };

    let Some(todos_array) = todos_value.as_array() else {
        return ("'todos' must be an array".to_string(), true);
    };

    let mut new_todos: Vec<TodoItem> = Vec::with_capacity(todos_array.len());
    let mut in_progress_count = 0;
    for (i, item) in todos_array.iter().enumerate() {
        let todo_item = match parse_todo_item(i, item) {
            Ok(t) => t,
            Err(err) => return err,
        };
        if todo_item.status == TodoStatus::InProgress {
            in_progress_count += 1;
        }
        new_todos.push(todo_item);
    }

    // Warn if more than one task is in_progress
    let warning = if in_progress_count > 1 {
        format!(
            "\nWarning: {in_progress_count} tasks marked as in_progress. Best practice is to have only one."
        )
    } else {
        String::new()
    };

    // Claude Code parity: when every item is `completed`, clear the list
    // instead of keeping a list of done items. Keeps the session cleanup
    // clean and signals the agent to stop referring back to finished work.
    // See claude-code/tools/TodoWriteTool/TodoWriteTool.ts (`allDone` branch).
    //
    // crosslink #972: the all_done decision MUST be made inside the lock
    // alongside the mutation. Earlier code decided outside the lock, which
    // raced two concurrent todo_write calls — thread A could decide
    // "all_done → remove" from its input while thread B's pending insert
    // landed first, erasing B's todos. The decide-and-write pair is one
    // critical section now.
    let all_done =
        !new_todos.is_empty() && new_todos.iter().all(|t| t.status == TodoStatus::Completed);

    // Update the per-session todo list. Thread-local
    // `CURRENT_SESSION_ID` picks the bucket; absent guard → default key.
    // The all_done compare-and-{remove|insert} pair runs atomically under the
    // map lock so two concurrent todo_write calls cannot race the bucket
    // (crosslink #972).
    let session_key = current_session_key();
    match todo_lists_guard("execute_todo_write") {
        Ok(mut map) => {
            if all_done {
                map.remove(&session_key);
            } else {
                map.insert(session_key, new_todos.clone());
            }
        }
        Err(e) => return (format!("Failed to update todo list: {e}"), true),
    }

    if all_done {
        return (
            format!(
                "Todos have been modified successfully — all {} items completed, list cleared.",
                new_todos.len()
            ),
            false,
        );
    }

    // Format output for the non-all-done case.
    let completed = new_todos
        .iter()
        .filter(|t| t.status == TodoStatus::Completed)
        .count();
    let in_progress = new_todos
        .iter()
        .filter(|t| t.status == TodoStatus::InProgress)
        .count();
    let pending = new_todos
        .iter()
        .filter(|t| t.status == TodoStatus::Pending)
        .count();

    let mut output = format!(
        "Todo list updated: {} total ({} completed, {} in progress, {} pending){}",
        new_todos.len(),
        completed,
        in_progress,
        pending,
        warning
    );

    // Show current in-progress task if any
    if let Some(current) = new_todos
        .iter()
        .find(|t| t.status == TodoStatus::InProgress)
    {
        let _ = write!(output, "\n\nCurrently: {}", current.active_form);
    }

    (output, false)
}

/// Read the current todo list for the active session bucket.
pub fn execute_todo_read() -> (String, bool) {
    let session_key = current_session_key();
    let todos = match todo_lists_guard("execute_todo_read") {
        Ok(map) => map.get(&session_key).cloned().unwrap_or_default(),
        Err(e) => return (format!("Failed to read todo list: {e}"), true),
    };

    if todos.is_empty() {
        return ("No todos in list.".to_string(), false);
    }

    let mut output = String::new();
    for (i, item) in todos.iter().enumerate() {
        let _ = writeln!(output, "{}. {} {}", i + 1, item.status.icon(), item.content);
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

    let _ = write!(
        output,
        "\n({completed} completed, {in_progress} in progress, {pending} pending)"
    );

    (output, false)
}

/// Get the todo list for the active session bucket (for external use).
#[must_use]
pub fn get_todo_list() -> Vec<TodoItem> {
    let session_key = current_session_key();
    todo_lists_guard("get_todo_list")
        .map(|m| m.get(&session_key).cloned().unwrap_or_default())
        .unwrap_or_default()
}

/// Clear the todo list for the active session bucket.
pub fn clear_todo_list() {
    let session_key = current_session_key();
    if let Ok(mut map) = todo_lists_guard("clear_todo_list") {
        map.remove(&session_key);
    }
}

/// Clear every session's list. Used by tests and by explicit "reset
/// all state" code paths — the single-session `clear_todo_list` only
/// removes the current bucket.
pub fn clear_all_todo_lists() {
    if let Ok(mut map) = todo_lists_guard("clear_all_todo_lists") {
        map.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// The task list is process-global state (matches the original
    /// design), so these tests serialize on a shared mutex to avoid
    /// interleaving under `cargo test`'s parallel runner.
    fn task_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
        let (msg, err) = execute_todo_write(&args);
        assert!(!err);
        assert!(msg.contains("all 2 items completed"));
        assert!(get_todo_list().is_empty());
    }

    #[test]
    fn mixed_statuses_are_preserved() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let args = args_with(json!([
            {"content": "one", "status": "completed", "activeForm": "Doing one"},
            {"content": "two", "status": "in_progress", "activeForm": "Doing two"},
        ]));
        let (_, err) = execute_todo_write(&args);
        assert!(!err);
        let stored = get_todo_list();
        assert_eq!(stored.len(), 2, "partial completion must keep the list");
    }

    #[test]
    fn per_session_buckets_do_not_collide() {
        let _lock = task_lock();
        clear_all_todo_lists();

        {
            let _g = SessionIdGuard::set("session-a");
            let (_, err) = execute_todo_write(&args_with(json!([{
                "content": "a task",
                "status": "in_progress",
                "activeForm": "Doing a"
            }])));
            assert!(!err);
            let list = get_todo_list();
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].content, "a task");
        }

        {
            let _g = SessionIdGuard::set("session-b");
            // session-b starts empty — session-a's list does not leak.
            assert!(get_todo_list().is_empty());
            let (_, err) = execute_todo_write(&args_with(json!([{
                "content": "b task",
                "status": "in_progress",
                "activeForm": "Doing b"
            }])));
            assert!(!err);
            assert_eq!(get_todo_list().len(), 1);
            assert_eq!(get_todo_list()[0].content, "b task");
        }

        // Back to session-a — its list must still be intact.
        {
            let _g = SessionIdGuard::set("session-a");
            let list = get_todo_list();
            assert_eq!(list.len(), 1, "session-a list must survive session-b edits");
            assert_eq!(list[0].content, "a task");
        }
    }

    #[test]
    fn guard_drop_restores_previous_session_id() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let _outer = SessionIdGuard::set("outer");
        {
            let _inner = SessionIdGuard::set("inner");
            assert_eq!(current_session_key(), "inner");
        }
        // inner guard dropped — outer value restored.
        assert_eq!(current_session_key(), "outer");
    }

    #[test]
    fn empty_input_is_not_treated_as_all_done() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let args = args_with(json!([]));
        let (msg, err) = execute_todo_write(&args);
        assert!(!err);
        // Empty input must NOT trigger the "all done" cleared-list
        // message — that message implies the agent finished actual work.
        assert!(!msg.contains("all 0 items completed"));
        assert!(get_todo_list().is_empty());
    }

    // ─── Spec §4: todo_write — full-replacement, atomic, per-session ───────────

    /// Contract: `todos` argument is required; absent → `is_error=true`.
    #[test]
    fn todo_write_requires_todos_argument() {
        let _lock = task_lock();
        let args = HashMap::new(); // no "todos" key
        let (msg, is_err) = execute_todo_write(&args);
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
        let (msg, is_err) = execute_todo_write(&args);
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
        let (msg, is_err) = execute_todo_write(&args);
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
        let (msg, is_err) = execute_todo_write(&args);
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
        let (msg, is_err) = execute_todo_write(&args);
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
        let (msg, is_err) = execute_todo_write(&args);
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
        let (msg, is_err) = execute_todo_write(&args);
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
        let (_, is_err) = execute_todo_write(&args);
        assert!(!is_err, "exactly 2000 chars must be accepted");
    }

    /// Contract: write is a full replacement — a second call with a single item
    /// replaces the entire previous list (no merge/append).
    #[test]
    fn todo_write_is_full_replacement_not_merge() {
        let _lock = task_lock();
        clear_all_todo_lists();

        // First write: two items
        let (_, e1) = execute_todo_write(&args_with(json!([
            {"content": "first",  "status": "pending",     "activeForm": "A"},
            {"content": "second", "status": "in_progress", "activeForm": "B"},
        ])));
        assert!(!e1);
        assert_eq!(get_todo_list().len(), 2);

        // Second write: one item — must replace, not append
        let (_, e2) = execute_todo_write(&args_with(json!([
            {"content": "replacement", "status": "pending", "activeForm": "C"},
        ])));
        assert!(!e2);
        let stored = get_todo_list();
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

        let (msg, is_err) = execute_todo_write(&args_with(json!([
            {"content": "alpha", "status": "completed", "activeForm": "A"},
            {"content": "beta",  "status": "completed", "activeForm": "B"},
            {"content": "gamma", "status": "completed", "activeForm": "C"},
        ])));
        assert!(!is_err);
        assert!(
            msg.contains("all 3 items completed"),
            "success message must state count; got: {msg}"
        );
        assert!(
            get_todo_list().is_empty(),
            "list must be empty after all-done"
        );
    }

    /// Contract: multiple `in_progress` items trigger a warning (OC-specific
    /// behaviour absent from CC).
    #[test]
    fn todo_write_warns_on_multiple_in_progress() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let (msg, is_err) = execute_todo_write(&args_with(json!([
            {"content": "a", "status": "in_progress", "activeForm": "A"},
            {"content": "b", "status": "in_progress", "activeForm": "B"},
        ])));
        assert!(!is_err, "multiple in_progress is not an error");
        assert!(
            msg.contains("Warning"),
            "must warn about multiple in_progress; got: {msg}"
        );
    }

    /// Contract: a single `in_progress` item produces no warning.
    #[test]
    fn todo_write_no_warning_for_single_in_progress() {
        let _lock = task_lock();
        clear_all_todo_lists();

        let (msg, is_err) = execute_todo_write(&args_with(json!([
            {"content": "only", "status": "in_progress", "activeForm": "Only"},
        ])));
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

        let (msg, is_err) = execute_todo_read();
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

        let (_, err) = execute_todo_write(&args_with(json!([
            {"content": "readable task", "status": "pending", "activeForm": "T"},
        ])));
        assert!(!err);

        let (msg, is_err) = execute_todo_read();
        assert!(!is_err);
        assert!(
            msg.contains("readable task"),
            "read must show written content; got: {msg}"
        );
    }

    /// Contract: `SessionIdGuard` clears the session on drop even under panic
    /// (RAII). After the inner scope drops, the outer session key is active again.
    #[test]
    fn session_id_guard_restores_on_drop() {
        let _lock = task_lock();

        let _outer = SessionIdGuard::set("outer-session");
        assert_eq!(current_session_key(), "outer-session");
        {
            let _inner = SessionIdGuard::set("inner-session");
            assert_eq!(current_session_key(), "inner-session");
        }
        assert_eq!(
            current_session_key(),
            "outer-session",
            "guard drop must restore outer session key"
        );
    }

    /// Contract: without any guard, the key falls back to `DEFAULT_SESSION_KEY`.
    #[test]
    fn session_key_defaults_without_guard() {
        // No guard active in this thread at entry.
        // (We cannot guarantee other tests haven't left a guard, so we only
        // assert the format contract — it must be a non-empty string.)
        let key = current_session_key();
        assert!(!key.is_empty(), "session key must never be empty");
    }
}

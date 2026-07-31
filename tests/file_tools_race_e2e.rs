//! End-to-end tests for file-tool race / security defences:
//! `READ_TRACKER` read-before-edit gate, symlink-swap defence (via
//! `O_NOFOLLOW` on the leaf), per-session tracker isolation.
//!
//! Sprint 21 of the verification effort. `tests/file_tools_integration.rs`
//! already pins 8 happy-path scenarios; this file fills the
//! race + defence gaps using the same `execute_tool` dispatch
//! seam as the existing suite.
//!
//! Coverage shape:
//!
//!   - **Read-before-edit gate** — `edit_file` MUST refuse
//!     without a prior `read_file` in the same session. After
//!     reading, the edit succeeds.
//!   - **Read-before-overwrite gate** (crosslink #968) —
//!     `write_file` on an EXISTING file MUST refuse without a
//!     prior read. Creating a new file is exempt.
//!   - **Edit conflict on stale `old_string`** — after editing
//!     once, a second edit with the same `old_string` MUST
//!     error.
//!   - **No-op edit refused** (crosslink #970) — `old_string
//!     == new_string` errors without touching the file.
//!   - **Per-session `READ_TRACKER` isolation** — read in
//!     session A does NOT satisfy the gate in session B.
//!   - **Symlink-swap defence** (crosslink #417) — `O_NOFOLLOW`
//!     on the leaf refuses to write through a symlink even
//!     when canonicalize would have followed it.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{execute_tool, FunctionCall, SessionIdGuard, ToolCall};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::tempdir_in;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

/// Process-wide serializer for tests that use `SessionIdGuard`
/// (thread-local) AND share the process-wide `READ_TRACKER`. Acquire
/// this BEFORE creating the guard so a parallel test can't observe
/// a half-set thread-local.
static SESSION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn session_lock() -> MutexGuard<'static, ()> {
    SESSION_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn call(name: &str, args: &Value) -> ToolCall {
    ToolCall {
        id: format!("sprint21_{name}"),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: args.to_string(),
        },
    }
}

fn read(path: &str) -> (String, bool) {
    let r = execute_tool(&call("read_file", &json!({"path": path})));
    (r.content, r.is_error)
}

fn write(path: &str, content: &str) -> (String, bool) {
    let r = execute_tool(&call(
        "write_file",
        &json!({"path": path, "content": content}),
    ));
    (r.content, r.is_error)
}

fn edit(path: &str, old: &str, new: &str) -> (String, bool) {
    let r = execute_tool(&call(
        "edit_file",
        &json!({"path": path, "old_string": old, "new_string": new}),
    ));
    (r.content, r.is_error)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — read-before-edit gate
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn edit_without_prior_read_is_refused() {
    let _sess = session_lock();
    let _guard = SessionIdGuard::set("sprint21-edit-no-read");

    let dir = tempdir_in(".").expect("project-local tempdir");
    let path = dir.path().join("target.txt");
    std::fs::write(&path, "v1").expect("plant file");
    let path_str = path.to_string_lossy().to_string();

    let (msg, is_err) = edit(&path_str, "v1", "v2");
    assert!(is_err, "edit without prior read must error");
    assert!(
        msg.to_lowercase().contains("read") && msg.to_lowercase().contains("before"),
        "msg must mention read-before-edit; got {msg:?}"
    );
    let after = std::fs::read_to_string(&path).expect("read after");
    assert_eq!(after, "v1", "file MUST NOT change when edit is refused");
}

#[test]
fn edit_after_read_in_same_session_succeeds() {
    let _sess = session_lock();
    let _guard = SessionIdGuard::set("sprint21-edit-after-read");

    let dir = tempdir_in(".").expect("project-local tempdir");
    let path = dir.path().join("target.txt");
    std::fs::write(&path, "alpha").expect("plant");
    let path_str = path.to_string_lossy().to_string();

    let (rmsg, is_err) = read(&path_str);
    assert!(!is_err, "read must succeed: {rmsg:?}");

    let (emsg, is_err) = edit(&path_str, "alpha", "beta");
    assert!(!is_err, "edit after read must succeed: {emsg:?}");

    let after = std::fs::read_to_string(&path).expect("read after edit");
    assert_eq!(after, "beta", "content MUST be edited; got {after:?}");
}

#[test]
fn second_edit_with_same_old_string_errors_because_already_replaced() {
    let _sess = session_lock();
    let _guard = SessionIdGuard::set("sprint21-edit-twice");

    let dir = tempdir_in(".").expect("project-local tempdir");
    let path = dir.path().join("target.txt");
    std::fs::write(&path, "unique").expect("plant");
    let path_str = path.to_string_lossy().to_string();

    let _ = read(&path_str);
    let (_, is_err) = edit(&path_str, "unique", "replaced");
    assert!(!is_err, "first edit must succeed");

    let (msg, is_err) = edit(&path_str, "unique", "third");
    assert!(
        is_err,
        "second edit with stale old_string must error; got msg={msg:?}"
    );
    let after = std::fs::read_to_string(&path).expect("read after");
    assert_eq!(after, "replaced", "file must reflect FIRST edit only");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — read-before-write gate (crosslink #968)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn write_to_existing_file_without_read_is_refused() {
    let _sess = session_lock();
    let _guard = SessionIdGuard::set("sprint21-write-no-read");

    let dir = tempdir_in(".").expect("project-local tempdir");
    let path = dir.path().join("existing.txt");
    std::fs::write(&path, "existing content").expect("plant");
    let path_str = path.to_string_lossy().to_string();

    let (msg, is_err) = write(&path_str, "blindly overwritten");
    assert!(is_err, "write to existing without read must error");
    assert!(
        msg.to_lowercase().contains("read") && msg.to_lowercase().contains("before"),
        "msg must mention read-before-overwrite; got {msg:?}"
    );
    let after = std::fs::read_to_string(&path).expect("read after");
    assert_eq!(after, "existing content");
}

#[test]
fn write_to_new_file_without_read_succeeds() {
    let _sess = session_lock();
    let _guard = SessionIdGuard::set("sprint21-write-new");

    let dir = tempdir_in(".").expect("project-local tempdir");
    let path = dir.path().join("brand-new.txt");
    let path_str = path.to_string_lossy().to_string();
    assert!(!path.exists(), "test precondition: file must not exist yet");

    let (msg, is_err) = write(&path_str, "fresh content");
    assert!(!is_err, "write to NEW file must succeed; got {msg:?}");
    let content = std::fs::read_to_string(&path).expect("read after write");
    assert_eq!(content, "fresh content");
}

#[test]
fn write_to_existing_file_after_read_succeeds() {
    let _sess = session_lock();
    let _guard = SessionIdGuard::set("sprint21-write-after-read");

    let dir = tempdir_in(".").expect("project-local tempdir");
    let path = dir.path().join("existing.txt");
    std::fs::write(&path, "before").expect("plant");
    let path_str = path.to_string_lossy().to_string();

    let (_, is_err) = read(&path_str);
    assert!(!is_err);

    let (msg, is_err) = write(&path_str, "after");
    assert!(!is_err, "write after read must succeed; got {msg:?}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "after");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — no-op edit defence (crosslink #970)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn no_op_edit_is_refused_without_touching_file() {
    let _sess = session_lock();
    let _guard = SessionIdGuard::set("sprint21-noop-edit");

    let dir = tempdir_in(".").expect("project-local tempdir");
    let path = dir.path().join("target.txt");
    std::fs::write(&path, "content").expect("plant");
    let path_str = path.to_string_lossy().to_string();

    let _ = read(&path_str);

    let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));

    let (msg, is_err) = edit(&path_str, "same", "same");
    assert!(is_err, "no-op edit (old==new) must error; got msg={msg:?}");
    assert!(
        msg.to_lowercase().contains("no-op") || msg.to_lowercase().contains("identical"),
        "msg must name no-op / identical; got {msg:?}"
    );

    let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(
        mtime_before, mtime_after,
        "no-op edit MUST NOT touch the file (mtime unchanged invariant)"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — per-session `READ_TRACKER` isolation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn read_in_one_session_does_not_count_in_another() {
    let _sess = session_lock();

    let dir = tempdir_in(".").expect("project-local tempdir");
    let path = dir.path().join("isolated.txt");
    std::fs::write(&path, "content").expect("plant");
    let path_str = path.to_string_lossy().to_string();

    {
        let _guard_a = SessionIdGuard::set("sprint21-session-A");
        let (_, is_err) = read(&path_str);
        assert!(!is_err);
    }

    {
        let _guard_b = SessionIdGuard::set("sprint21-session-B");
        let (msg, is_err) = edit(&path_str, "content", "replaced-by-b");
        assert!(
            is_err,
            "session B edit without B's own read must error; got msg={msg:?}"
        );
        assert!(
            msg.to_lowercase().contains("read") && msg.to_lowercase().contains("before"),
            "msg must mention read-before; got {msg:?}"
        );
    }

    let after = std::fs::read_to_string(&path).expect("read after");
    assert_eq!(after, "content", "file MUST be unchanged");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — write resolves and creates parent dirs
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn write_creates_missing_parent_directories() {
    let _sess = session_lock();
    let _guard = SessionIdGuard::set("sprint21-write-parents");

    let dir = tempdir_in(".").expect("project-local tempdir");
    let nested = dir.path().join("a/b/c/d/file.txt");
    assert!(!nested.parent().unwrap().exists(), "parent dirs absent");
    let path_str = nested.to_string_lossy().to_string();

    let (_, is_err) = write(&path_str, "deep");
    assert!(!is_err, "write must create parent dirs");
    assert!(nested.exists(), "nested file must exist after write");
    assert_eq!(std::fs::read_to_string(&nested).unwrap(), "deep");
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — symlink-swap defence at the leaf (crosslink #417)
// ───────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
#[test]
fn write_refuses_when_leaf_is_a_symlink() {
    // crosslink #417: the leaf-preserving open path uses
    // `O_NOFOLLOW` so a symlink at the leaf is refused with
    // ELOOP — even when canonicalize would have followed it.
    let _sess = session_lock();
    let _guard = SessionIdGuard::set("sprint21-symlink-leaf");

    let dir = tempdir_in(".").expect("project-local tempdir");
    let real = dir.path().join("real.txt");
    std::fs::write(&real, "real content").expect("plant real");
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let link_str = link.to_string_lossy().to_string();

    // Mark the link as read so the read-before-write gate
    // passes (we want to test the SYMLINK defence specifically).
    let (_, _) = read(&link_str);

    let (msg, is_err) = write(&link_str, "overwritten via symlink");
    assert!(
        is_err,
        "write through symlink leaf MUST be refused by O_NOFOLLOW; got msg={msg:?}"
    );
    // The real file MUST NOT be touched.
    let real_after = std::fs::read_to_string(&real).expect("read real after");
    assert_eq!(
        real_after, "real content",
        "real file MUST NOT be modified through a symlink"
    );
    // Verify the link itself is still a symlink.
    let meta = std::fs::symlink_metadata(Path::new(&link)).expect("lstat");
    assert!(
        meta.file_type().is_symlink(),
        "link MUST still be a symlink after refused write"
    );
}

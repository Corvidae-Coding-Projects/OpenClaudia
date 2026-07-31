//! End-to-end tests for the cron-tool entry points: create, list,
//! delete + the cron-expression validator.
//!
//! Sprint 20 of the verification effort. `src/tools/cron.rs` has
//! 29 unit tests but no integration coverage that drives the
//! public `execute_cron_*` entry points the way the runtime does.
//!
//! Coverage shape:
//!
//!   - **Cron-expression validator** — driven via
//!     `execute_cron_create` (validation runs BEFORE the disk
//!     write, so the test never has to clean up after itself
//!     for these cases). Adversarial inputs: wrong field count,
//!     out-of-range values, empty atom in a list, malformed
//!     step / range expressions.
//!   - **Missing required args** — `name`, `schedule`, `prompt`
//!     each rejected with the typed-accessor's canonical wording.
//!   - **End-to-end create → list → delete** — uses a per-test
//!     tempdir cwd via the cwd-restore guard. Tests run
//!     single-threaded; the guard restores prior cwd on drop
//!     (even on panic).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{
    execute_cron_create, execute_cron_delete, execute_cron_list, SessionIdGuard,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

/// Process-wide serialization for tests that mutate the process cwd
/// via `CwdGuard`. Each cwd-touching test must acquire this lock
/// BEFORE constructing the guard — otherwise sibling tests in the
/// same binary running in parallel (cargo's default) corrupt each
/// other's cwd state. The lock is held across both the cwd swap and
/// any disk operation that depends on the cwd value.
static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn cwd_lock() -> MutexGuard<'static, ()> {
    CWD_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

/// RAII guard that sets the process cwd for the duration of a scope
/// and restores the prior value on drop (even on panic).
///
/// `std::env::set_current_dir` is process-global, so tests using this
/// helper MUST run single-threaded (`--test-threads=1`).
struct CwdGuard {
    prev: PathBuf,
    _session: SessionIdGuard,
}

impl CwdGuard {
    fn set_to(path: &std::path::Path) -> Self {
        let prev = std::env::current_dir().expect("current_dir");
        std::env::set_current_dir(path).expect("set_current_dir");
        let session = SessionIdGuard::set(format!("cron-e2e-{}", path.display()));
        Self {
            prev,
            _session: session,
        }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        // Best-effort restore; if it fails the process will continue
        // with the test cwd which would surface as a subsequent test
        // failure rather than a silent corruption.
        let _ = std::env::set_current_dir(&self.prev);
    }
}

fn cron_args(name: &str, schedule: &str, prompt: &str) -> HashMap<String, Value> {
    [
        ("name", json!(name)),
        ("schedule", json!(schedule)),
        ("prompt", json!(prompt)),
    ]
    .iter()
    .cloned()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — validator refusals (no disk write)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn invalid_cron_expression_is_refused_before_disk_write() {
    // We don't need a cwd guard here — the refusal happens BEFORE
    // any path is computed.
    let bad_exprs = &[
        ("", "empty schedule"),
        ("not a cron", "wrong field count"),
        ("* * * *", "4 fields (need 5)"),
        ("* * * * * *", "6 fields (too many)"),
        ("60 * * * *", "minute=60 out of range"),
        ("* 24 * * *", "hour=24 out of range"),
        ("* * 32 * *", "day=32 out of range"),
        ("* * * 13 *", "month=13 out of range"),
        ("* * * * 8", "weekday=8 out of range"),
        ("*/0 * * * *", "step=0 invalid"),
        ("1,,2 * * * *", "empty atom in list"),
        ("a * * * *", "non-numeric atom"),
    ];
    for (expr, why) in bad_exprs {
        let (msg, is_err) = execute_cron_create(&cron_args("test", expr, "noop"));
        assert!(
            is_err,
            "{why} ({expr:?}) must be refused; got ok msg={msg:?}"
        );
        assert!(
            msg.to_lowercase().contains("invalid")
                || msg.to_lowercase().contains("cron")
                || msg.to_lowercase().contains("range")
                || msg.to_lowercase().contains("field"),
            "{why}: refusal must name the cron/validation problem; got {msg:?}"
        );
    }
}

#[test]
fn missing_name_arg_errors_before_disk_write() {
    let mut args = HashMap::new();
    args.insert("schedule".to_string(), json!("* * * * *"));
    args.insert("prompt".to_string(), json!("noop"));
    let (msg, is_err) = execute_cron_create(&args);
    assert!(is_err, "missing name must error");
    assert!(
        msg.to_lowercase().contains("name"),
        "msg must mention 'name'; got {msg:?}"
    );
}

#[test]
fn missing_schedule_arg_errors_before_disk_write() {
    let mut args = HashMap::new();
    args.insert("name".to_string(), json!("test"));
    args.insert("prompt".to_string(), json!("noop"));
    let (msg, is_err) = execute_cron_create(&args);
    assert!(is_err, "missing schedule must error");
    assert!(
        msg.to_lowercase().contains("schedule"),
        "msg must mention 'schedule'; got {msg:?}"
    );
}

#[test]
fn missing_prompt_arg_errors_before_disk_write() {
    let mut args = HashMap::new();
    args.insert("name".to_string(), json!("test"));
    args.insert("schedule".to_string(), json!("* * * * *"));
    let (msg, is_err) = execute_cron_create(&args);
    assert!(is_err, "missing prompt must error");
    assert!(
        msg.to_lowercase().contains("prompt"),
        "msg must mention 'prompt'; got {msg:?}"
    );
}

#[test]
fn canonical_cron_expressions_pass_validation() {
    // We exercise validation by checking that the failure (if any)
    // is NOT a validation failure. The create may still error if
    // the cwd has issues, but it MUST NOT mention "invalid cron".
    let canonical = &[
        "* * * * *",      // every minute
        "0 * * * *",      // hourly
        "0 0 * * *",      // daily midnight
        "0 0 1 * *",      // monthly first
        "0 0 * * 0",      // weekly sunday
        "*/15 * * * *",   // every 15 minutes
        "0 0,12 * * *",   // midnight + noon
        "0 9-17 * * 1-5", // hourly weekday business hours
    ];
    let dir = TempDir::new().expect("tempdir");
    let _cwd_lock = cwd_lock();
    let _guard = CwdGuard::set_to(dir.path());
    for (i, expr) in canonical.iter().enumerate() {
        let name = format!("canonical-{i}");
        let (msg, _is_err) = execute_cron_create(&cron_args(&name, expr, "echo"));
        assert!(
            !msg.to_lowercase().contains("invalid cron"),
            "canonical expression {expr:?} flagged as invalid: {msg:?}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — end-to-end create → list → delete round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn create_then_list_then_delete_round_trips() {
    let dir = TempDir::new().expect("tempdir");
    let _cwd_lock = cwd_lock();
    let _guard = CwdGuard::set_to(dir.path());

    // 1. Create.
    let (created_msg, is_err) =
        execute_cron_create(&cron_args("daily-noop", "0 0 * * *", "echo done"));
    assert!(
        !is_err,
        "create must succeed in tempdir cwd; got is_err with msg={created_msg:?}"
    );

    // 2. List — must include the schedule we just created.
    let (list_msg, is_err) = execute_cron_list(&HashMap::new());
    assert!(!is_err, "list must succeed; got msg={list_msg:?}");
    assert!(
        list_msg.contains("daily-noop"),
        "list must contain just-created schedule name; got {list_msg:?}"
    );

    // 3. Delete by name.
    let mut del_args: HashMap<String, Value> = HashMap::new();
    del_args.insert("name".to_string(), json!("daily-noop"));
    let (del_msg, is_err) = execute_cron_delete(&del_args);
    assert!(
        !is_err,
        "delete must succeed; got is_err with msg={del_msg:?}"
    );

    // 4. List again — must NOT contain the deleted schedule.
    let (list_after, _) = execute_cron_list(&HashMap::new());
    assert!(
        !list_after.contains("daily-noop"),
        "list after delete MUST NOT contain 'daily-noop'; got {list_after:?}"
    );
}

#[test]
fn duplicate_schedule_name_is_refused() {
    let dir = TempDir::new().expect("tempdir");
    let _cwd_lock = cwd_lock();
    let _guard = CwdGuard::set_to(dir.path());

    let (_first_msg, is_err) = execute_cron_create(&cron_args("dup-test", "* * * * *", "first"));
    assert!(!is_err, "first create must succeed");

    let (second_msg, is_err) = execute_cron_create(&cron_args("dup-test", "0 * * * *", "second"));
    assert!(
        is_err,
        "duplicate name must error; got is_err=false msg={second_msg:?}"
    );
    assert!(
        second_msg.to_lowercase().contains("already exists")
            || second_msg.to_lowercase().contains("duplicate"),
        "msg must mention duplicate/already-exists; got {second_msg:?}"
    );
}

#[test]
fn delete_nonexistent_schedule_errors_cleanly() {
    let dir = TempDir::new().expect("tempdir");
    let _cwd_lock = cwd_lock();
    let _guard = CwdGuard::set_to(dir.path());

    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!("never-was"));
    let (msg, is_err) = execute_cron_delete(&args);
    assert!(is_err, "delete of nonexistent schedule must error");
    assert!(
        msg.to_lowercase().contains("not found")
            || msg.to_lowercase().contains("no schedule")
            || msg.to_lowercase().contains("never-was"),
        "msg must indicate not-found / name; got {msg:?}"
    );
}

#[test]
fn list_on_empty_store_returns_no_schedules_message() {
    let dir = TempDir::new().expect("tempdir");
    let _cwd_lock = cwd_lock();
    let _guard = CwdGuard::set_to(dir.path());
    let (msg, _is_err) = execute_cron_list(&HashMap::new());
    // The exact wording varies — "no schedules" / "empty" /
    // similar — but it MUST NOT panic and MUST NOT mention any
    // canned schedule name.
    let lowered = msg.to_lowercase();
    assert!(
        lowered.contains("no schedule")
            || lowered.contains("empty")
            || lowered.contains("0 schedule")
            || lowered.is_empty(),
        "empty store must produce a 'no schedules' message; got {msg:?}"
    );
}

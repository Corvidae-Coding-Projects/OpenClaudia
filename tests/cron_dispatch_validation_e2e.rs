//! End-to-end tests for `cron_create` / `cron_delete` /
//! `cron_list` tools dispatched through the registry —
//! pre-disk argument validation.
//!
//! Sprint 152 of the verification effort. Sprint 7 covered
//! direct `execute_cron_*` calls plus cron-schedule shape
//! in sprint 101; this file pins the registry-dispatched
//! path so the wire-facing contract matches.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use openclaudia::tools::SessionIdGuard;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

// Cron tools touch .openclaudia/schedules.json — serialize cwd
// changes process-wide so concurrent tests don't race.
fn cwd_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn run_in_tempdir<R>(f: impl FnOnce() -> R) -> R {
    struct RestoreCwd(std::path::PathBuf);
    impl Drop for RestoreCwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    let prev = std::env::current_dir().expect("cwd");
    let tmp = TempDir::new().expect("tempdir");
    std::env::set_current_dir(tmp.path()).expect("set cwd");
    let _restore = RestoreCwd(prev);
    let _session = SessionIdGuard::set(format!("cron-dispatch-{}", tmp.path().display()));
    f()
}

fn dispatch(name: &str, args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch(name, args, &mut ctx)
        .expect("tool must be registered")
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
// Section A — cron_create: required-arg validation pre-disk
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cron_create_missing_name_arg_errors_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[
            ("schedule", json!("0 9 * * *")),
            ("prompt", json!("Run report")),
        ]);
        let (msg, is_err) = dispatch("cron_create", &args);
        assert!(is_err);
        assert!(
            msg.contains("name") || msg.contains("Missing"),
            "MUST mention missing name; got {msg:?}"
        );
        // Disk untouched: no .openclaudia/schedules.json created.
        assert!(
            !std::path::Path::new(".openclaudia/schedules.json").exists(),
            "missing-arg error MUST NOT write schedules.json"
        );
    });
}

#[test]
fn cron_create_missing_schedule_arg_errors_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[("name", json!("daily")), ("prompt", json!("Run report"))]);
        let (msg, is_err) = dispatch("cron_create", &args);
        assert!(is_err);
        assert!(
            msg.contains("schedule") || msg.contains("Missing"),
            "MUST mention missing schedule; got {msg:?}"
        );
        assert!(!std::path::Path::new(".openclaudia/schedules.json").exists());
    });
}

#[test]
fn cron_create_missing_prompt_arg_errors_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[("name", json!("daily")), ("schedule", json!("0 9 * * *"))]);
        let (msg, is_err) = dispatch("cron_create", &args);
        assert!(is_err);
        assert!(
            msg.contains("prompt") || msg.contains("Missing"),
            "MUST mention missing prompt; got {msg:?}"
        );
    });
}

#[test]
fn cron_create_wrong_type_name_arg_errors_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[
            ("name", json!(42)),
            ("schedule", json!("0 9 * * *")),
            ("prompt", json!("Run report")),
        ]);
        let (msg, is_err) = dispatch("cron_create", &args);
        assert!(is_err);
        assert_eq!(msg, "Invalid 'name' argument: expected string");
        assert!(!std::path::Path::new(".openclaudia/schedules.json").exists());
    });
}

#[test]
fn cron_create_wrong_type_schedule_arg_errors_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[
            ("name", json!("daily")),
            ("schedule", json!(["0 9 * * *"])),
            ("prompt", json!("Run report")),
        ]);
        let (msg, is_err) = dispatch("cron_create", &args);
        assert!(is_err);
        assert_eq!(msg, "Invalid 'schedule' argument: expected string");
        assert!(!std::path::Path::new(".openclaudia/schedules.json").exists());
    });
}

#[test]
fn cron_create_wrong_type_prompt_arg_errors_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[
            ("name", json!("daily")),
            ("schedule", json!("0 9 * * *")),
            ("prompt", Value::Null),
        ]);
        let (msg, is_err) = dispatch("cron_create", &args);
        assert!(is_err);
        assert_eq!(msg, "Invalid 'prompt' argument: expected string");
        assert!(!std::path::Path::new(".openclaudia/schedules.json").exists());
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — cron_create: invalid cron expression rejected pre-disk
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cron_create_invalid_cron_expression_rejected_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[
            ("name", json!("bogus")),
            ("schedule", json!("not a cron expression!!")),
            ("prompt", json!("noop")),
        ]);
        let (_msg, is_err) = dispatch("cron_create", &args);
        assert!(is_err, "invalid cron expression MUST be rejected");
        assert!(
            !std::path::Path::new(".openclaudia/schedules.json").exists(),
            "invalid cron MUST NOT write schedules.json"
        );
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — cron_create full round-trip with cron_list
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cron_create_then_list_round_trips_through_dispatch() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[
            ("name", json!("dispatch_round_trip_152")),
            ("schedule", json!("0 9 * * *")),
            ("prompt", json!("noop")),
        ]);
        let (_c_msg, c_err) = dispatch("cron_create", &args);
        assert!(!c_err);

        let (l_msg, l_err) = dispatch("cron_list", &HashMap::new());
        assert!(!l_err);
        assert!(
            l_msg.contains("dispatch_round_trip_152"),
            "cron_list MUST show created schedule; got {l_msg:?}"
        );
    });
}

#[test]
fn cron_create_duplicate_name_rejected() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[
            ("name", json!("dup_name_152")),
            ("schedule", json!("0 9 * * *")),
            ("prompt", json!("noop")),
        ]);
        let (_msg1, e1) = dispatch("cron_create", &args);
        assert!(!e1);

        let (msg2, e2) = dispatch("cron_create", &args);
        assert!(e2, "duplicate name MUST be rejected");
        let _ = msg2;
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — cron_list: empty store
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cron_list_on_empty_store_returns_non_error_message() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let (msg, is_err) = dispatch("cron_list", &HashMap::new());
        assert!(!is_err, "empty store list MUST NOT error");
        // Returns either "No schedules" or similar empty marker.
        assert!(
            msg.to_lowercase().contains("no") || msg.contains('0') || msg.contains("empty"),
            "MUST surface empty-store message; got {msg:?}"
        );
    });
}

#[test]
fn cron_list_ignores_arbitrary_args() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[("extra", json!("ignored")), ("count", json!(42))]);
        let (_msg, is_err) = dispatch("cron_list", &args);
        assert!(!is_err);
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — cron_delete: missing identifier
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cron_delete_with_no_args_errors() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let (_msg, is_err) = dispatch("cron_delete", &HashMap::new());
        assert!(is_err, "cron_delete with neither id nor name MUST error");
    });
}

#[test]
fn cron_delete_rejects_wrong_type_name_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[("name", json!(42))]);
        let (msg, is_err) = dispatch("cron_delete", &args);
        assert!(is_err);
        assert!(
            msg.contains("Invalid 'name' argument: expected string"),
            "wrong-type name MUST be rejected; got {msg:?}"
        );
        assert!(
            !std::path::Path::new(".openclaudia/schedules.json").exists(),
            "wrong-type identifier MUST NOT touch schedules.json"
        );
    });
}

#[test]
fn cron_delete_rejects_wrong_type_id_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[("id", json!({"legacy": "bad"}))]);
        let (msg, is_err) = dispatch("cron_delete", &args);
        assert!(is_err);
        assert!(
            msg.contains("Invalid 'id' argument: expected string"),
            "wrong-type id MUST be rejected; got {msg:?}"
        );
        assert!(!std::path::Path::new(".openclaudia/schedules.json").exists());
    });
}

#[test]
fn cron_delete_rejects_wrong_type_index_before_disk_write() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        for bad_index in [json!("1"), json!(-1), json!(0)] {
            let args = args_with(&[("index", bad_index)]);
            let (msg, is_err) = dispatch("cron_delete", &args);
            assert!(is_err);
            assert!(
                msg.contains("Invalid 'index' argument"),
                "wrong-type or zero index MUST be rejected; got {msg:?}"
            );
            assert!(!std::path::Path::new(".openclaudia/schedules.json").exists());
        }
    });
}

#[test]
fn cron_delete_rejects_malformed_extra_identifier_even_with_valid_name() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let create_args = args_with(&[
            ("name", json!("keep_on_bad_extra_identifier")),
            ("schedule", json!("0 9 * * *")),
            ("prompt", json!("noop")),
        ]);
        let (_c_msg, c_err) = dispatch("cron_create", &create_args);
        assert!(!c_err);

        let delete_args = args_with(&[
            ("name", json!("keep_on_bad_extra_identifier")),
            ("index", json!("1")),
        ]);
        let (delete_msg, delete_err) = dispatch("cron_delete", &delete_args);
        assert!(delete_err);
        assert!(
            delete_msg.contains("Invalid 'index' argument"),
            "malformed provided index MUST not be ignored; got {delete_msg:?}"
        );

        let (list_msg, list_err) = dispatch("cron_list", &HashMap::new());
        assert!(!list_err);
        assert!(
            list_msg.contains("keep_on_bad_extra_identifier"),
            "schedule MUST remain after rejected delete; got {list_msg:?}"
        );
    });
}

#[test]
fn cron_delete_nonexistent_id_errors_cleanly() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[("id", json!("nonexistent_id_xyz_marker"))]);
        let (msg, is_err) = dispatch("cron_delete", &args);
        assert!(is_err);
        // Error message surfaces useful diagnostic.
        assert!(
            !msg.is_empty(),
            "MUST surface non-empty diagnostic; got {msg:?}"
        );
    });
}

#[test]
fn cron_delete_nonexistent_name_errors_cleanly() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[("name", json!("nonexistent_name_xyz"))]);
        let (_msg, is_err) = dispatch("cron_delete", &args);
        assert!(is_err);
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — cron_delete after cron_create round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cron_create_then_delete_round_trip() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let create_args = args_with(&[
            ("name", json!("delete_round_trip_152")),
            ("schedule", json!("0 9 * * *")),
            ("prompt", json!("noop")),
        ]);
        let (_c_msg, c_err) = dispatch("cron_create", &create_args);
        assert!(!c_err);

        let delete_args = args_with(&[("name", json!("delete_round_trip_152"))]);
        let (_d_msg, d_err) = dispatch("cron_delete", &delete_args);
        assert!(!d_err, "delete by name after create MUST succeed");

        // list MUST NOT show it after delete.
        let (l_msg, _) = dispatch("cron_list", &HashMap::new());
        assert!(
            !l_msg.contains("delete_round_trip_152"),
            "deleted schedule MUST be absent from list; got {l_msg:?}"
        );
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Registration + cross-tool
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn all_3_cron_tools_registered_in_registry() {
    for name in &["cron_create", "cron_delete", "cron_list"] {
        assert!(registry().get(name).is_some(), "{name} MUST be registered");
    }
}

#[test]
fn cron_create_never_panics_on_arbitrary_extra_args() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let args = args_with(&[
            ("name", json!("extras_152")),
            ("schedule", json!("0 9 * * *")),
            ("prompt", json!("noop")),
            ("extra", json!({"k": "v"})),
            ("nested", json!([1, 2, 3])),
        ]);
        let (_msg, _is_err) = dispatch("cron_create", &args);
    });
}

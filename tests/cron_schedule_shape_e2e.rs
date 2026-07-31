//! End-to-end tests for `tools::cron` list-output rendering +
//! `Schedule` JSON shape (read directly from the on-disk store
//! after create) + multi-schedule list semantics.
//!
//! Sprint 101 of the verification effort. Sprint 6 covered the
//! validate + happy-path round-trip; this file pins the
//! rendered list output format (enabled markers ● / ○, prompt
//! truncation at 80 chars, multi-schedule layout) and the
//! on-disk schedule JSON shape (`run_count=0`,
//! `last_run=None`, `enabled=true` defaults set by create).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{execute_cron_create, execute_cron_list, SessionIdGuard};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

// ───────────────────────────────────────────────────────────────────────────
// CWD lock + tempdir helper
// ───────────────────────────────────────────────────────────────────────────

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

    let prev = std::env::current_dir().expect("current_dir");
    let tmp = TempDir::new().expect("tempdir");
    std::env::set_current_dir(tmp.path()).expect("set cwd");
    let _restore = RestoreCwd(prev);
    let _session = SessionIdGuard::set(format!("cron-shape-{}", tmp.path().display()));
    std::fs::create_dir_all(".openclaudia").expect("mkdir");
    f()
}

fn cron_args(name: &str, schedule: &str, prompt: &str) -> HashMap<String, Value> {
    let mut a = HashMap::new();
    a.insert("name".to_string(), json!(name));
    a.insert("schedule".to_string(), json!(schedule));
    a.insert("prompt".to_string(), json!(prompt));
    a
}

fn list_args() -> HashMap<String, Value> {
    HashMap::new()
}

fn read_store() -> Value {
    let path = std::path::Path::new(".openclaudia/schedules.json");
    let content = std::fs::read_to_string(path).expect("read schedule store");
    serde_json::from_str(&content).expect("parse store")
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — On-disk Schedule defaults set by execute_cron_create
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn newly_created_schedule_has_run_count_zero_and_no_last_run() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let (out, err) = execute_cron_create(&cron_args("daily", "0 9 * * *", "do thing"));
        assert!(!err, "create MUST succeed; got {out:?}");
        let store = read_store();
        let s = &store["schedules"][0];
        assert_eq!(s["name"], "daily");
        assert_eq!(s["cron_expression"], "0 9 * * *");
        assert_eq!(s["prompt"], "do thing");
        assert_eq!(s["run_count"], 0, "fresh schedule MUST have run_count = 0");
        assert!(
            s["last_run"].is_null(),
            "fresh schedule MUST have last_run = null"
        );
        assert_eq!(
            s["enabled"], true,
            "fresh schedule MUST default to enabled = true"
        );
        assert_eq!(
            s["recurring"], true,
            "fresh schedule MUST default to recurring = true"
        );
        assert_eq!(
            s["durable"], true,
            "fresh schedule MUST default to durable = true"
        );
    });
}

#[test]
fn cron_create_persists_false_recurring_and_durable_flags() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let mut args = cron_args("one-shot", "0 9 * * *", "do thing");
        args.insert("recurring".to_string(), json!(false));
        args.insert("durable".to_string(), json!(false));

        let (out, err) = execute_cron_create(&args);
        assert!(!err, "create MUST succeed; got {out:?}");
        let store = read_store();
        let s = &store["schedules"][0];
        assert_eq!(s["recurring"], false);
        assert_eq!(s["durable"], false);
    });
}

#[test]
fn schedule_id_field_is_populated_with_hex_token() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let _ = execute_cron_create(&cron_args("daily", "0 9 * * *", "x"));
        let store = read_store();
        let s = &store["schedules"][0];
        let id = s["id"].as_str().expect("id is string");
        // Documented #907: 16 hex chars (64-bit entropy).
        assert!(id.len() >= 8, "id MUST be substantive token; got {id:?}");
        assert!(
            id.chars().all(|c| c.is_ascii_hexdigit() || c == '-'),
            "id MUST be hex/dash; got {id:?}"
        );
    });
}

#[test]
fn schedule_created_at_field_is_populated_with_string() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let _ = execute_cron_create(&cron_args("daily", "0 9 * * *", "x"));
        let store = read_store();
        assert!(
            store["schedules"][0]["created_at"].is_string(),
            "created_at MUST be populated string"
        );
    });
}

#[test]
fn two_distinct_schedules_get_distinct_ids() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let _ = execute_cron_create(&cron_args("alpha", "0 9 * * *", "x"));
        let _ = execute_cron_create(&cron_args("beta", "0 17 * * *", "y"));
        let store = read_store();
        let id_a = store["schedules"][0]["id"].as_str().unwrap();
        let id_b = store["schedules"][1]["id"].as_str().unwrap();
        assert_ne!(id_a, id_b, "ids MUST be unique across schedules");
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — execute_cron_list rendering
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn list_with_one_enabled_schedule_renders_filled_circle_marker() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let _ = execute_cron_create(&cron_args("daily", "0 9 * * *", "morning"));
        let (out, err) = execute_cron_list(&list_args());
        assert!(!err);
        // PINS RENDERING: enabled = ● (U+25CF filled circle).
        assert!(
            out.contains('\u{25cf}'),
            "enabled schedule MUST render with ● marker; got {out:?}"
        );
        assert!(out.contains("daily"));
        assert!(out.contains("0 9 * * *"));
        assert!(out.contains("morning"));
    });
}

#[test]
fn list_includes_run_count_zero_and_last_never_for_fresh_schedule() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let _ = execute_cron_create(&cron_args("daily", "0 9 * * *", "x"));
        let (out, _) = execute_cron_list(&list_args());
        // Fresh schedule: 0 runs, last "never".
        assert!(out.contains("Runs: 0"), "MUST show run count; got {out:?}");
        assert!(out.contains("never"), "MUST show last=never; got {out:?}");
    });
}

#[test]
fn list_truncates_prompt_longer_than_80_chars() {
    // Prompt > 80 chars: documented truncation at 77 + "...".
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let long_prompt = "a".repeat(150);
        let _ = execute_cron_create(&cron_args("long", "0 9 * * *", &long_prompt));
        let (out, _) = execute_cron_list(&list_args());
        // Prompt MUST appear truncated with ellipsis.
        assert!(
            out.contains("..."),
            "long prompt MUST be truncated with '...'; got {out:?}"
        );
        // Full 150-char prompt MUST NOT appear verbatim.
        assert!(
            !out.contains(&long_prompt),
            "full prompt MUST NOT render verbatim"
        );
    });
}

#[test]
fn list_short_prompt_renders_verbatim_no_truncation() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let short = "short prompt under 80";
        let _ = execute_cron_create(&cron_args("short", "0 9 * * *", short));
        let (out, _) = execute_cron_list(&list_args());
        assert!(
            out.contains(short),
            "short prompt MUST render verbatim; got {out:?}"
        );
    });
}

#[test]
fn list_with_multiple_schedules_renders_each_with_its_own_marker_block() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let _ = execute_cron_create(&cron_args("alpha", "0 9 * * *", "first"));
        let _ = execute_cron_create(&cron_args("beta", "0 17 * * *", "second"));
        let _ = execute_cron_create(&cron_args("gamma", "*/15 * * * *", "third"));
        let (out, _) = execute_cron_list(&list_args());
        assert!(out.contains("alpha"));
        assert!(out.contains("beta"));
        assert!(out.contains("gamma"));
        assert!(out.contains("first"));
        assert!(out.contains("second"));
        assert!(out.contains("third"));
        // Count number of ● markers (one per enabled schedule).
        let count = out.matches('\u{25cf}').count();
        assert_eq!(count, 3, "MUST render 3 enabled markers; got {count}");
    });
}

#[test]
fn list_renders_header_when_schedules_present() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let _ = execute_cron_create(&cron_args("x", "0 9 * * *", "x"));
        let (out, _) = execute_cron_list(&list_args());
        assert!(
            out.starts_with("Stored cron schedule metadata:"),
            "header MUST describe stored cron metadata; got {out:?}"
        );
    });
}

#[test]
fn list_on_empty_store_returns_no_schedule_metadata_message() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        // No create — list on empty store.
        let (out, err) = execute_cron_list(&list_args());
        assert!(!err);
        assert_eq!(out.trim(), "No schedule metadata stored.");
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Multi-schedule persistence
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn store_persists_multiple_schedules_each_with_full_shape() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let _ = execute_cron_create(&cron_args("alpha", "0 9 * * *", "first"));
        let _ = execute_cron_create(&cron_args("beta", "0 17 * * *", "second"));
        let store = read_store();
        let schedules = store["schedules"].as_array().expect("array");
        assert_eq!(schedules.len(), 2);
        for (i, expected_name) in ["alpha", "beta"].iter().enumerate() {
            let s = &schedules[i];
            assert_eq!(s["name"], *expected_name);
            assert_eq!(s["run_count"], 0);
            assert_eq!(s["enabled"], true);
            assert!(s["id"].is_string());
            assert!(s["created_at"].is_string());
            assert!(s["last_run"].is_null());
            assert_eq!(s["recurring"], true);
            assert_eq!(s["durable"], true);
        }
    });
}

#[test]
fn store_preserves_creation_order_of_schedules() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let _ = execute_cron_create(&cron_args("first", "0 9 * * *", "x"));
        let _ = execute_cron_create(&cron_args("second", "0 10 * * *", "x"));
        let _ = execute_cron_create(&cron_args("third", "0 11 * * *", "x"));
        let store = read_store();
        let schedules = store["schedules"].as_array().unwrap();
        assert_eq!(schedules[0]["name"], "first");
        assert_eq!(schedules[1]["name"], "second");
        assert_eq!(schedules[2]["name"], "third");
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Cron-expression edge cases (valid expressions accepted)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn create_accepts_minute_range_expressions() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let (_out, err) = execute_cron_create(&cron_args("range-mins", "0-15 * * * *", "x"));
        assert!(!err);
    });
}

#[test]
fn create_accepts_step_expressions() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let (_out, err) = execute_cron_create(&cron_args("step", "*/5 * * * *", "x"));
        assert!(!err);
    });
}

#[test]
fn create_accepts_list_expressions() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let (_out, err) = execute_cron_create(&cron_args("list", "0 9,12,17 * * *", "x"));
        assert!(!err);
    });
}

#[test]
fn create_accepts_weekday_range_expression() {
    let _lock = cwd_lock();
    run_in_tempdir(|| {
        let (_out, err) = execute_cron_create(&cron_args("weekdays", "0 9 * * 1-5", "x"));
        assert!(!err);
    });
}

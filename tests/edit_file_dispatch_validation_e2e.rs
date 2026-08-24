//! End-to-end tests for the `edit_file` tool dispatched
//! through the registry — pre-write validation arms,
//! the must-read-before-edit gate, the no-op refusal
//! (#970), and the multi-occurrence refusal (#687).
//!
//! Sprint 143 of the verification effort. This file pins
//! the registry-dispatched validation paths for `edit_file`:
//! missing `path` / `old_string` / `new_string`, must-read
//! gate, no-op identical-strings refusal, and `replace_all`
//! flag.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod support;

fn dispatch_edit(args: &HashMap<String, Value>) -> (String, bool) {
    support::legacy(&support::dispatch_tool_result_for_run(
        support::shared_run_context(),
        "edit_file",
        args,
    ))
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

fn snapshot_from_read_output(output: &str) -> String {
    output
        .rsplit_once("File snapshot: generation=")
        .and_then(|(_, suffix)| suffix.split(',').next())
        .filter(|generation| generation.starts_with("sha256:"))
        .expect("successful read must expose a snapshot generation")
        .to_string()
}

fn read_snapshot_for_run(
    run: &std::sync::Arc<openclaudia::tools::ToolRunContext>,
    path: &str,
) -> String {
    let result = support::dispatch_tool_result_for_run(
        run,
        "read_file",
        &args_with(&[("path", json!(path))]),
    );
    let (output, is_error) = support::legacy(&result);
    assert!(!is_error, "read_file must succeed: {output}");
    snapshot_from_read_output(&output)
}

fn read_snapshot(path: &str) -> String {
    read_snapshot_for_run(support::shared_run_context(), path)
}

fn with_snapshot(mut args: HashMap<String, Value>, snapshot: &str) -> HashMap<String, Value> {
    args.insert("expected_snapshot".to_string(), json!(snapshot));
    args
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing / wrong-type path arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_path_arg_errors() {
    let args = args_with(&[("old_string", json!("foo")), ("new_string", json!("bar"))]);
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err);
    assert!(
        msg.contains("path") || msg.contains("Missing"),
        "MUST surface missing-path; got {msg:?}"
    );
}

#[test]
fn path_arg_as_number_returns_validation_error() {
    let args = args_with(&[
        ("path", json!(42)),
        ("old_string", json!("foo")),
        ("new_string", json!("bar")),
    ]);
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("malformed arguments"));
    assert!(msg.contains("'path'"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section A2 — Path resolution
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn path_with_parent_dir_traversal_rejected_pre_read_gate() {
    let args = args_with(&[
        ("path", json!("/tmp/../etc/passwd")),
        ("old_string", json!("root")),
        ("new_string", json!("changed")),
    ]);
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err, "../-traversal path MUST be rejected");
    assert!(
        msg.contains("traversal") || msg.contains("Path"),
        "MUST surface path-traversal message before read gate; got {msg:?}"
    );
    assert!(
        !msg.contains("must read"),
        "traversal must fail before must-read gate; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Must-read-before-edit gate
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn edit_existing_file_without_prior_read_errors_with_documented_message() {
    // Create a file that has NOT been read via read_file.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("never_read_unique.txt");
    std::fs::write(&path, "original body").expect("create");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[
        ("path", json!(path_str)),
        ("old_string", json!("original")),
        ("new_string", json!("modified")),
    ]);
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err, "edit without prior read MUST be refused");
    assert!(
        msg.contains("No current snapshot") && msg.contains("read_file"),
        "MUST surface must-read-before-edit gate; got {msg:?}"
    );
    // Suggests corrective action.
    assert!(
        msg.contains("read_file"),
        "MUST suggest read_file; got {msg:?}"
    );
    // Original content preserved when gate fires.
    let preserved = std::fs::read_to_string(&path).expect("read");
    assert_eq!(
        preserved, "original body",
        "gate failure MUST preserve file content"
    );
}

#[test]
fn failed_read_does_not_satisfy_edit_gate() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let run = support::test_run_context(dir.path());
    let path = dir.path().join("empty.png");
    std::fs::write(&path, "").expect("create empty image");
    let path_str = path.to_str().expect("utf8 path");

    let read_args = args_with(&[("path", json!(path_str))]);
    let read_result = support::dispatch_tool_result_for_run(&run, "read_file", &read_args);
    let (read_msg, read_err) = support::legacy(&read_result);
    assert!(read_err, "empty image read must fail: {read_msg}");

    let edit_args = args_with(&[
        ("path", json!(path_str)),
        ("old_string", json!("not present")),
        ("new_string", json!("replacement")),
    ]);
    let edit_result = support::dispatch_tool_result_for_run(&run, "edit_file", &edit_args);
    let (edit_msg, edit_err) = support::legacy(&edit_result);
    assert!(
        edit_err,
        "failed read must not unlock edit gate: {edit_msg}"
    );
    assert!(
        edit_msg.contains("No current snapshot") && edit_msg.contains("read_file"),
        "edit gate should still require a successful read; got {edit_msg:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("read back"),
        "",
        "failed-read path must remain untouched"
    );
}

#[test]
fn edit_after_explicit_read_file_dispatch_passes_must_read_gate() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let run = support::test_run_context(dir.path());
    let path = dir.path().join("read_then_edited_unique.txt");
    std::fs::write(&path, "before").expect("create");
    let path_str = path.to_str().unwrap();

    // Read first via dispatched read_file (populates READ_TRACKER).
    let snapshot = read_snapshot_for_run(&run, path_str);

    // Now edit succeeds.
    let edit_args = with_snapshot(
        args_with(&[
            ("path", json!(path_str)),
            ("old_string", json!("before")),
            ("new_string", json!("after")),
        ]),
        &snapshot,
    );
    let edit_result = support::dispatch_tool_result_for_run(&run, "edit_file", &edit_args);
    let (msg, is_err) = support::legacy(&edit_result);
    assert!(!is_err, "edit after read MUST succeed; got error {msg:?}");

    // Content actually changed on disk.
    let after = std::fs::read_to_string(&path).expect("read");
    assert_eq!(after, "after");
}

#[test]
fn one_byte_change_after_read_dispatch_returns_typed_conflict() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let run = support::test_run_context(dir.path());
    let path = dir.path().join("concurrent.txt");
    std::fs::write(&path, "alpha\n").expect("create fixture");
    let path_str = path.to_str().expect("utf8 path");
    let snapshot = read_snapshot_for_run(&run, path_str);
    std::fs::write(&path, "alphb\n").expect("concurrent one-byte change");

    let args = with_snapshot(
        args_with(&[
            ("path", json!(path_str)),
            ("old_string", json!("alpha")),
            ("new_string", json!("omega")),
        ]),
        &snapshot,
    );
    let result = support::dispatch_tool_result_for_run(&run, "edit_file", &args);

    assert!(matches!(
        result.outcome(),
        openclaudia::tools::ToolOutcome::Error { failure }
            if failure.code == openclaudia::tools::ToolFailureCode::Conflict
                && failure.retryability == openclaudia::tools::ToolRetryability::Safe
    ));
    assert_eq!(
        std::fs::read_to_string(&path).expect("read back"),
        "alphb\n",
        "the concurrent generation must remain untouched"
    );
}

#[test]
fn edit_records_diff_and_stales_prior_read_observation() {
    let run = support::test_run_context(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let session_id = run.session_id().to_string();
    let ledger = Arc::new(Mutex::new(openclaudia::ledger::RealityLedger::new()));
    let _ledger_guard =
        openclaudia::ledger::install_active_ledger_for_session(&session_id, Arc::clone(&ledger));

    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("ledger_edit.txt");
    std::fs::write(&path, "before\n").expect("create");
    let path_str = path.to_str().unwrap();

    let snapshot = read_snapshot_for_run(&run, path_str);
    let read_id = {
        let ledger = ledger.lock().expect("ledger lock");
        assert_eq!(ledger.len(), 1);
        ledger.observation_index(8)[0].id
    };

    let edit_args = with_snapshot(
        args_with(&[
            ("path", json!(path_str)),
            ("old_string", json!("before")),
            ("new_string", json!("after")),
        ]),
        &snapshot,
    );
    let edit_result = support::dispatch_tool_result_for_run(&run, "edit_file", &edit_args);
    let (msg, is_err) = support::legacy(&edit_result);
    assert!(!is_err, "edit after read MUST succeed; got error {msg:?}");

    let (read_is_stale, diff) = {
        let ledger = ledger.lock().expect("ledger lock");
        assert_eq!(ledger.len(), 2);
        let diff = ledger
            .observation_index(8)
            .into_iter()
            .filter_map(|entry| ledger.get(entry.id))
            .find(|obs| {
                matches!(
                    obs.kind,
                    openclaudia::ledger::ObservationKind::DiffObserved { .. }
                )
            })
            .expect("diff observation")
            .clone();
        (ledger.is_stale(read_id), diff)
    };
    assert!(read_is_stale, "prior file read must be stale");
    let openclaudia::ledger::ObservationKind::DiffObserved { files, patch } = &diff.kind else {
        panic!("expected diff observation");
    };
    assert_eq!(
        files,
        &vec![path.canonicalize().unwrap().to_string_lossy().to_string()]
    );
    assert!(patch.contains("-before"));
    assert!(patch.contains("+after"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Missing old_string / new_string
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_old_string_after_read_errors() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("missing_old.txt");
    std::fs::write(&path, "body").expect("create");
    let path_str = path.to_str().unwrap();

    // Read first.
    let _snapshot = read_snapshot(path_str);

    let args = args_with(&[("path", json!(path_str)), ("new_string", json!("bar"))]);
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err);
    assert!(
        msg.contains("old_string"),
        "MUST mention missing old_string; got {msg:?}"
    );
}

#[test]
fn missing_new_string_after_read_errors() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("missing_new.txt");
    std::fs::write(&path, "body").expect("create");
    let path_str = path.to_str().unwrap();

    let _snapshot = read_snapshot(path_str);

    let args = args_with(&[("path", json!(path_str)), ("old_string", json!("foo"))]);
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err);
    assert!(
        msg.contains("new_string"),
        "MUST mention missing new_string; got {msg:?}"
    );
}

#[test]
fn old_string_arg_as_number_after_read_returns_validation_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("wrong_old.txt");
    std::fs::write(&path, "body").expect("create");
    let path_str = path.to_str().unwrap();

    let _snapshot = read_snapshot(path_str);

    let args = args_with(&[
        ("path", json!(path_str)),
        ("old_string", json!(42)),
        ("new_string", json!("bar")),
    ]);
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'old_string' argument: expected string"));
}

#[test]
fn new_string_arg_as_number_after_read_returns_validation_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("wrong_new.txt");
    std::fs::write(&path, "body").expect("create");
    let path_str = path.to_str().unwrap();

    let _snapshot = read_snapshot(path_str);

    let args = args_with(&[
        ("path", json!(path_str)),
        ("old_string", json!("body")),
        ("new_string", json!(42)),
    ]);
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'new_string' argument: expected string"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — No-op refusal (#970)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn no_op_edit_with_identical_old_and_new_strings_refused() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("noop.txt");
    std::fs::write(&path, "body").expect("create");
    let path_str = path.to_str().unwrap();

    let _snapshot = read_snapshot(path_str);

    let args = args_with(&[
        ("path", json!(path_str)),
        ("old_string", json!("identical_marker")),
        ("new_string", json!("identical_marker")),
    ]);
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err, "no-op edit MUST be refused");
    assert!(
        msg.contains("no-op") || msg.contains("identical"),
        "MUST surface no-op message; got {msg:?}"
    );
}

#[test]
fn no_op_edit_with_empty_strings_refused() {
    // PINS #970: empty == empty is also a no-op.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("noop_empty.txt");
    std::fs::write(&path, "body").expect("create");
    let path_str = path.to_str().unwrap();

    let _snapshot = read_snapshot(path_str);

    let args = args_with(&[
        ("path", json!(path_str)),
        ("old_string", json!("")),
        ("new_string", json!("")),
    ]);
    let (_msg, is_err) = dispatch_edit(&args);
    assert!(is_err);
}

#[test]
fn no_op_does_not_modify_file_mtime() {
    // PINS #970 DOC: no-op fails BEFORE any I/O.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("noop_mtime.txt");
    std::fs::write(&path, "body").expect("create");
    let path_str = path.to_str().unwrap();

    let _snapshot = read_snapshot(path_str);

    let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));

    let args = args_with(&[
        ("path", json!(path_str)),
        ("old_string", json!("body")),
        ("new_string", json!("body")),
    ]);
    let (_msg, is_err) = dispatch_edit(&args);
    assert!(is_err);
    let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(mtime_before, mtime_after, "no-op edit MUST NOT touch mtime");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — replace_all flag (#687)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn multi_occurrence_without_replace_all_refused() {
    // PINS #687: when replace_all=false (default), multiple
    // occurrences MUST be rejected so callers provide
    // uniquely-matching context.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("multi_occur.txt");
    std::fs::write(&path, "x\nx\nx\n").expect("create");
    let path_str = path.to_str().unwrap();

    let snapshot = read_snapshot(path_str);

    let args = with_snapshot(
        args_with(&[
            ("path", json!(path_str)),
            ("old_string", json!("x")),
            ("new_string", json!("y")),
        ]),
        &snapshot,
    );
    let (msg, is_err) = dispatch_edit(&args);
    assert!(is_err, "multi-occurrence default-mode edit MUST be refused");
    // File content preserved.
    let preserved = std::fs::read_to_string(&path).expect("read");
    assert_eq!(preserved, "x\nx\nx\n");
    let _ = msg;
}

#[test]
fn multi_occurrence_with_replace_all_true_succeeds() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("multi_replace_all.txt");
    std::fs::write(&path, "x\nx\nx\n").expect("create");
    let path_str = path.to_str().unwrap();

    let snapshot = read_snapshot(path_str);

    let args = with_snapshot(
        args_with(&[
            ("path", json!(path_str)),
            ("old_string", json!("x")),
            ("new_string", json!("y")),
            ("replace_all", json!(true)),
        ]),
        &snapshot,
    );
    let (msg, is_err) = dispatch_edit(&args);
    assert!(!is_err, "replace_all=true MUST succeed; got {msg:?}");

    let after = std::fs::read_to_string(&path).expect("read");
    assert_eq!(after, "y\ny\ny\n", "every occurrence MUST be replaced");
}

#[test]
fn replace_all_false_explicit_matches_default_behavior() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("replace_explicit_false.txt");
    std::fs::write(&path, "a\na\n").expect("create");
    let path_str = path.to_str().unwrap();

    let snapshot = read_snapshot(path_str);

    let args = with_snapshot(
        args_with(&[
            ("path", json!(path_str)),
            ("old_string", json!("a")),
            ("new_string", json!("b")),
            ("replace_all", json!(false)),
        ]),
        &snapshot,
    );
    let (_msg, is_err) = dispatch_edit(&args);
    // Multi-occurrence + replace_all=false → still refused.
    assert!(is_err);
    let preserved = std::fs::read_to_string(&path).expect("read");
    assert_eq!(preserved, "a\na\n");
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Single-occurrence happy path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn single_occurrence_edit_replaces_byte_exact() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("single_occur.txt");
    std::fs::write(&path, "before content\nafter\n").expect("create");
    let path_str = path.to_str().unwrap();

    let snapshot = read_snapshot(path_str);

    let args = with_snapshot(
        args_with(&[
            ("path", json!(path_str)),
            ("old_string", json!("before content")),
            ("new_string", json!("REPLACED")),
        ]),
        &snapshot,
    );
    let (msg, is_err) = dispatch_edit(&args);
    assert!(!is_err, "single-occurrence edit MUST succeed; got {msg:?}");

    let after = std::fs::read_to_string(&path).expect("read");
    assert_eq!(after, "REPLACED\nafter\n");
}

#[test]
fn unicode_old_and_new_strings_round_trip() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("unicode_edit.txt");
    std::fs::write(&path, "before 日本語 content\n").expect("create");
    let path_str = path.to_str().unwrap();

    let snapshot = read_snapshot(path_str);

    let args = with_snapshot(
        args_with(&[
            ("path", json!(path_str)),
            ("old_string", json!("日本語")),
            ("new_string", json!("にほんご 🎉")),
        ]),
        &snapshot,
    );
    let (msg, is_err) = dispatch_edit(&args);
    assert!(!is_err, "unicode edit MUST succeed; got {msg:?}");

    let after = std::fs::read_to_string(&path).expect("read");
    assert!(after.contains("にほんご 🎉"));
    assert!(!after.contains("日本語"));
}

//! End-to-end tests for the `write_file` tool dispatched
//! through the registry — invalidation arms that fire
//! BEFORE any filesystem write.
//!
//! Sprint 142 of the verification effort. This file pins
//! the registry-dispatched validation paths for `write_file`:
//! missing path, wrong-type path, missing content, the
//! "must read before overwrite" gate (#968), and Edit/Write
//! permission-target wiring (#782).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use openclaudia::tools::SessionIdGuard;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn dispatch_write(args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch("write_file", args, &mut ctx)
        .expect("write_file must be registered")
}

fn dispatch_read(args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch("read_file", args, &mut ctx)
        .expect("read_file must be registered")
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing/wrong-type path arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_path_arg_errors_with_documented_message() {
    let (msg, is_err) = dispatch_write(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("Missing 'path' argument"),
        "MUST surface documented missing-path message; got {msg:?}"
    );
}

#[test]
fn path_arg_as_number_returns_validation_error() {
    let args = args_with(&[("path", json!(42)), ("content", json!("body"))]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid 'path' argument: expected string"),
        "non-string path MUST surface path type validation; got {msg:?}"
    );
}

#[test]
fn path_arg_as_array_returns_validation_error() {
    let args = args_with(&[("path", json!(["x"])), ("content", json!("body"))]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'path' argument: expected string"));
}

#[test]
fn path_arg_as_object_returns_validation_error() {
    let args = args_with(&[("path", json!({"k": "v"})), ("content", json!("body"))]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'path' argument: expected string"));
}

#[test]
fn path_arg_as_null_returns_validation_error() {
    let args = args_with(&[("path", Value::Null), ("content", json!("body"))]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'path' argument: expected string"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Relative path rejected by resolve_path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn path_with_parent_dir_traversal_rejected_pre_write() {
    // AUTHORING DISCOVERY: resolve_path REJECTS `..` traversal
    // (Path::Component::ParentDir) but ACCEPTS relative paths
    // (resolves them to cwd-relative).
    // This pins the `..` traversal gate.
    let args = args_with(&[
        ("path", json!("/tmp/../etc/file.txt")),
        ("content", json!("body")),
    ]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err, "../-traversal path MUST be rejected");
    assert!(
        msg.contains("traversal") || msg.contains("Path"),
        "MUST surface path-traversal message; got {msg:?}"
    );
}

#[test]
fn relative_path_is_accepted_and_resolved_to_session_root() {
    // AUTHORING DISCOVERY: relative paths are accepted —
    // secure resolution joins them to the immutable session root.
    // The dispatch must NOT reject for relative-ness alone.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("new_relative_file_xyz.txt");

    let args = args_with(&[
        ("path", json!(path.to_string_lossy())),
        ("content", json!("body")),
    ]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(
        !is_err,
        "relative path MUST be accepted (resolved to session root); got error {msg:?}"
    );
    assert_eq!(std::fs::read_to_string(path).expect("read back"), "body");
}

#[test]
fn write_file_records_diff_observation_when_session_ledger_is_active() {
    let _session_guard = openclaudia::tools::SessionIdGuard::set("writeledger");
    let ledger = Arc::new(Mutex::new(openclaudia::ledger::RealityLedger::new()));
    let _ledger_guard =
        openclaudia::ledger::install_active_ledger_for_session("writeledger", Arc::clone(&ledger));

    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("ledger_write.txt");
    let args = args_with(&[
        ("path", json!(path.to_str().unwrap())),
        ("content", json!("created\n")),
    ]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(!is_err, "write should succeed: {msg}");

    let observation = {
        let ledger = ledger.lock().expect("ledger lock");
        assert_eq!(ledger.len(), 1);
        ledger
            .get(ledger.observation_index(8)[0].id)
            .expect("observation")
            .clone()
    };
    let openclaudia::ledger::ObservationKind::DiffObserved { files, patch } = &observation.kind
    else {
        panic!("expected diff observation");
    };
    assert_eq!(
        files,
        &vec![path.canonicalize().unwrap().to_string_lossy().to_string()]
    );
    assert!(patch.contains("+created"));
    assert_eq!(observation.authority, openclaudia::ledger::Authority::Git);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Missing content arg (for new file with valid path)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_content_arg_on_new_file_errors() {
    // Use a tempdir path so the file path validates successfully
    // and we reach the content check.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("new_unique_file_marker.txt");
    let args = args_with(&[("path", json!(path.to_str().unwrap()))]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err);
    assert!(
        msg.contains("Missing 'content' argument"),
        "MUST surface documented missing-content message; got {msg:?}"
    );
}

#[test]
fn content_arg_as_number_returns_validation_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("test.txt");
    let args = args_with(&[
        ("path", json!(path.to_str().unwrap())),
        ("content", json!(42)),
    ]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid 'content' argument: expected string"),
        "non-string content MUST surface content type validation; got {msg:?}"
    );
}

#[test]
fn content_arg_as_array_returns_validation_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("test.txt");
    let args = args_with(&[
        ("path", json!(path.to_str().unwrap())),
        ("content", json!(["line1", "line2"])),
    ]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'content' argument: expected string"));
}

#[test]
fn content_arg_as_null_returns_validation_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("test.txt");
    let args = args_with(&[
        ("path", json!(path.to_str().unwrap())),
        ("content", Value::Null),
    ]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'content' argument: expected string"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Argument-check ordering
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_both_args_surfaces_path_error_first() {
    // PINS ORDER: path validation runs BEFORE content validation.
    // Missing both → path error message surfaces.
    let (msg, is_err) = dispatch_write(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("'path'"),
        "MUST surface path error before content; got {msg:?}"
    );
    assert!(
        !msg.contains("'content'"),
        "content error MUST NOT fire when path is missing; got {msg:?}"
    );
}

#[test]
fn traversal_path_with_missing_content_surfaces_traversal_error_first() {
    // PINS ORDER: path resolution runs BEFORE content check.
    // A `..` traversal MUST surface path error even if
    // content is missing.
    let args = args_with(&[("path", json!("/tmp/../etc/file.txt"))]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err);
    // Path error MUST fire; content-missing MUST NOT.
    assert!(
        !msg.contains("Missing 'content' argument"),
        "traversal-path error MUST fire before content check; got {msg:?}"
    );
    assert!(
        msg.contains("traversal") || msg.contains("Path"),
        "MUST surface path-traversal message; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Overwrite gate (#968): must read before overwriting
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn overwrite_existing_file_without_prior_read_errors() {
    // PINS #968: an existing file that has NOT been read via
    // read_file in this session cannot be overwritten — model
    // would be hallucinating prior content.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("existing_unique_marker.txt");
    // Pre-create file (existing) without going through read_file.
    std::fs::write(&path, "original content").expect("create");

    let args = args_with(&[
        ("path", json!(path.to_str().unwrap())),
        ("content", json!("new content")),
    ]);
    let (msg, is_err) = dispatch_write(&args);
    assert!(is_err, "overwrite without prior read MUST be refused");
    assert!(
        msg.contains("must read") && msg.contains("before overwriting"),
        "MUST surface #968 message; got {msg:?}"
    );
    // Error MUST hint at the corrective action.
    assert!(
        msg.contains("read_file"),
        "MUST suggest read_file; got {msg:?}"
    );
    // Original content MUST NOT be overwritten when gate fires.
    let preserved = std::fs::read_to_string(&path).expect("read");
    assert_eq!(
        preserved, "original content",
        "gate failure MUST preserve original file content"
    );
}

#[test]
fn failed_read_does_not_satisfy_overwrite_gate() {
    let _session_guard = SessionIdGuard::set("failed-read-overwrite-gate");
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("empty.png");
    std::fs::write(&path, "").expect("create empty image");
    let path_str = path.to_str().expect("utf8 path");

    let (read_msg, read_err) = dispatch_read(&args_with(&[("path", json!(path_str))]));
    assert!(read_err, "empty image read must fail: {read_msg}");

    let (write_msg, write_err) = dispatch_write(&args_with(&[
        ("path", json!(path_str)),
        ("content", json!("new content")),
    ]));
    assert!(
        write_err,
        "failed read must not unlock overwrite gate: {write_msg}"
    );
    assert!(
        write_msg.contains("must read") && write_msg.contains("before overwriting"),
        "overwrite gate should still require a successful read; got {write_msg:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("read back"),
        "",
        "failed-read path must remain untouched"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Empty content is valid (creates empty file)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_string_content_is_accepted_for_new_file() {
    // Empty content string is valid — creates empty file.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("empty_new.txt");
    let args = args_with(&[
        ("path", json!(path.to_str().unwrap())),
        ("content", json!("")),
    ]);
    let (_msg, is_err) = dispatch_write(&args);
    assert!(!is_err, "empty content for new file MUST succeed");
    assert!(path.exists(), "new file MUST be created");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
}

#[test]
fn unicode_content_writes_byte_exact() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("unicode.txt");
    let content = "日本語コンテンツ 🎉";
    let args = args_with(&[
        ("path", json!(path.to_str().unwrap())),
        ("content", json!(content)),
    ]);
    let (_msg, is_err) = dispatch_write(&args);
    assert!(!is_err);
    let written = std::fs::read_to_string(&path).expect("read");
    assert_eq!(written, content, "unicode content MUST round-trip");
}

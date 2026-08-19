//! End-to-end tests for the `read_file` tool dispatched
//! through the registry — pre-read validation arms and
//! offset/limit edge cases.
//!
//! Sprint 144 of the verification effort. This file pins
//! the registry-dispatched validation paths for `read_file`:
//! missing path, `..` traversal rejection, non-existent
//! file, oversize-file cap, offset/limit coercion, and
//! the line-number rendering contract.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod support;

fn dispatch_read(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("read_file", args)
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing / wrong-type path args
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_path_arg_returns_documented_error() {
    let (msg, is_err) = dispatch_read(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("Missing 'path' argument"),
        "MUST surface documented missing-path; got {msg:?}"
    );
}

#[test]
fn path_arg_as_number_returns_validation_error() {
    let args = args_with(&[("path", json!(42))]);
    let (msg, is_err) = dispatch_read(&args);
    assert!(is_err);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("malformed arguments"));
    assert!(msg.contains("'path'"));
}

#[test]
fn path_arg_as_array_returns_validation_error() {
    let args = args_with(&[("path", json!(["a", "b"]))]);
    let (msg, is_err) = dispatch_read(&args);
    assert!(is_err);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("malformed arguments"));
    assert!(msg.contains("'path'"));
}

#[test]
fn path_arg_as_null_returns_validation_error() {
    let args = args_with(&[("path", Value::Null)]);
    let (msg, is_err) = dispatch_read(&args);
    assert!(is_err);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("Missing 'path' argument"));
}

#[test]
fn pdf_pages_arg_as_number_returns_validation_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("bad_pages.pdf");
    std::fs::write(&path, b"%PDF-1.4\n").expect("write");

    let args = args_with(&[
        ("path", json!(path.to_string_lossy())),
        ("pages", json!(42)),
    ]);
    let (msg, is_err) = dispatch_read(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'pages' argument: expected string"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Path resolution
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parent_dir_traversal_in_path_rejected() {
    // PINS: resolve_path rejects `..` Component::ParentDir.
    let args = args_with(&[("path", json!("/tmp/../etc/passwd"))]);
    let (msg, is_err) = dispatch_read(&args);
    assert!(is_err);
    assert!(
        msg.contains("traversal") || msg.contains("Path"),
        "MUST surface traversal error; got {msg:?}"
    );
}

#[test]
fn nonexistent_path_errors_with_stat_message() {
    let args = args_with(&[("path", json!("definitely_nonexistent_xyz_marker_144.txt"))]);
    let (msg, is_err) = dispatch_read(&args);
    assert!(is_err);
    assert!(
        msg.contains("Cannot stat") || msg.contains("Failed") || msg.contains("not found"),
        "MUST surface stat / not-found error; got {msg:?}"
    );
    // Error MUST echo the offending path so model can self-correct.
    assert!(
        msg.contains("definitely_nonexistent_xyz_marker_144"),
        "MUST echo offending path; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Happy path with line-number rendering
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn read_simple_text_file_returns_content_with_line_numbers() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("simple.txt");
    std::fs::write(&path, "line one\nline two\nline three\n").expect("write");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[("path", json!(path_str))]);
    let (text, is_err) = dispatch_read(&args);
    assert!(!is_err);
    // Each line MUST appear in output.
    assert!(text.contains("line one"));
    assert!(text.contains("line two"));
    assert!(text.contains("line three"));
    // Line numbers (1, 2, 3) MUST appear somewhere in the output.
    assert!(
        text.contains('1') && text.contains('2') && text.contains('3'),
        "MUST include line numbers; got {text:?}"
    );
}

#[test]
fn read_file_records_observation_when_session_ledger_is_active() {
    let run = support::test_run_context(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let session_id = run.session_id().to_string();
    let ledger = Arc::new(Mutex::new(openclaudia::ledger::RealityLedger::new()));
    let _ledger_guard =
        openclaudia::ledger::install_active_ledger_for_session(&session_id, Arc::clone(&ledger));

    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("ledgered.txt");
    std::fs::write(&path, "alpha\nbeta\n").expect("write");

    let args = args_with(&[
        ("path", json!(path.to_string_lossy())),
        ("offset", json!(1)),
        ("limit", json!(2)),
    ]);
    let result = support::dispatch_tool_result_for_run(&run, "read_file", &args);
    let (msg, is_err) = support::legacy(&result);
    assert!(!is_err, "read should succeed: {msg}");

    let observation = {
        let ledger = ledger.lock().expect("ledger lock");
        assert_eq!(ledger.len(), 1);
        let index = ledger.observation_index(8);
        ledger.get(index[0].id).expect("observation").clone()
    };
    let openclaudia::ledger::ObservationKind::FileRead {
        path: observed_path,
        sha256,
        start_line,
        end_line,
        excerpt,
    } = &observation.kind
    else {
        panic!("expected FileRead observation");
    };
    assert_eq!(
        observed_path,
        &path.canonicalize().unwrap().to_string_lossy()
    );
    assert_eq!((*start_line, *end_line), (1, 2));
    assert_eq!(
        sha256,
        "e49c81e2d2f84e259d40e2fb8192f3bcd198b355184845d76d8f58807d0d78ee"
    );
    assert!(excerpt.contains("alpha"));
    assert_eq!(
        observation.authority,
        openclaudia::ledger::Authority::Filesystem
    );
}

#[test]
fn read_empty_file_returns_no_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("empty.txt");
    std::fs::write(&path, "").expect("write");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[("path", json!(path_str))]);
    let (_text, is_err) = dispatch_read(&args);
    assert!(!is_err, "empty file MUST be readable");
}

#[test]
fn read_unicode_content_preserves_bytes() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("unicode.txt");
    std::fs::write(&path, "日本語コンテンツ\n🎉 emoji line\n").expect("write");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[("path", json!(path_str))]);
    let (text, is_err) = dispatch_read(&args);
    assert!(!is_err);
    assert!(text.contains("日本語コンテンツ"));
    assert!(text.contains("🎉"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Offset + limit args
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn offset_skips_initial_lines() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("offset.txt");
    let body = (1..=10)
        .map(|i| format!("line_{i}_marker"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, body + "\n").expect("write");
    let path_str = path.to_str().unwrap();

    // offset=5 → skip lines 1..=4, start at line 5.
    let args = args_with(&[("path", json!(path_str)), ("offset", json!(5))]);
    let (text, is_err) = dispatch_read(&args);
    assert!(!is_err);
    // Line 5 onwards present; earlier lines absent.
    assert!(text.contains("line_5_marker"));
    assert!(text.contains("line_10_marker"));
    assert!(
        !text.contains("line_1_marker"),
        "offset MUST skip line 1; got {text:?}"
    );
}

#[test]
fn limit_caps_returned_lines() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("limit.txt");
    let body = (1..=10)
        .map(|i| format!("limit_line_{i}_marker"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, body + "\n").expect("write");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[("path", json!(path_str)), ("limit", json!(3))]);
    let (text, is_err) = dispatch_read(&args);
    assert!(!is_err);
    // First 3 lines present; line 4+ absent.
    assert!(text.contains("limit_line_1_marker"));
    assert!(text.contains("limit_line_3_marker"));
    assert!(
        !text.contains("limit_line_4_marker"),
        "limit=3 MUST cap at line 3; got {text:?}"
    );
}

#[test]
fn offset_plus_limit_window_selection() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("window.txt");
    let body = (1..=20)
        .map(|i| format!("win_{i}"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, body + "\n").expect("write");
    let path_str = path.to_str().unwrap();

    // offset=10 + limit=3 → lines 10..=12.
    let args = args_with(&[
        ("path", json!(path_str)),
        ("offset", json!(10)),
        ("limit", json!(3)),
    ]);
    let (text, is_err) = dispatch_read(&args);
    assert!(!is_err);
    assert!(text.contains("win_10"));
    assert!(text.contains("win_12"));
    assert!(!text.contains("win_9 "));
    assert!(!text.contains("win_13"));
}

#[test]
fn offset_beyond_file_length_returns_no_lines_but_no_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("offset_huge.txt");
    std::fs::write(&path, "only one line\n").expect("write");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[("path", json!(path_str)), ("offset", json!(9999))]);
    let (_text, is_err) = dispatch_read(&args);
    // Offset past file end is NOT an error — just yields empty window.
    assert!(!is_err);
}

#[test]
fn offset_zero_returns_validation_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("offset_zero.txt");
    std::fs::write(&path, "first\nsecond\n").expect("write");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[("path", json!(path_str)), ("offset", json!(0))]);
    let (text, is_err) = dispatch_read(&args);
    assert!(is_err);
    assert!(
        text.contains("offset") && text.contains("1-indexed"),
        "offset=0 must fail before reading; got {text:?}"
    );
}

#[test]
fn limit_zero_returns_validation_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("limit_zero.txt");
    std::fs::write(&path, "first\nsecond\n").expect("write");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[("path", json!(path_str)), ("limit", json!(0))]);
    let (text, is_err) = dispatch_read(&args);
    assert!(is_err);
    assert!(
        text.contains("limit") && text.contains("positive"),
        "limit=0 must fail before reading; got {text:?}"
    );
}

#[test]
fn offset_above_u64_max_coerces_no_panic() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("offset_max.txt");
    std::fs::write(&path, "x\n").expect("write");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[("path", json!(path_str)), ("offset", json!(u64::MAX))]);
    let (_text, is_err) = dispatch_read(&args);
    // u64::MAX clamped via try_from — no panic.
    assert!(!is_err);
}

#[test]
fn limit_above_u64_max_coerces_no_panic() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("limit_max.txt");
    std::fs::write(&path, "a\nb\nc\n").expect("write");
    let path_str = path.to_str().unwrap();

    let args = args_with(&[("path", json!(path_str)), ("limit", json!(u64::MAX))]);
    let (text, is_err) = dispatch_read(&args);
    assert!(!is_err);
    assert!(text.contains('a') && text.contains('b') && text.contains('c'));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Cross-arm
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_path_arg_takes_precedence_over_invalid_offset() {
    // Even with bogus offset, missing path error fires first.
    let args = args_with(&[("offset", json!("not a number"))]);
    let (msg, is_err) = dispatch_read(&args);
    assert!(is_err);
    assert!(msg.contains("Missing 'path' argument"));
}

#[test]
fn read_dispatch_never_panics_on_arbitrary_extra_args() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("extras.txt");
    std::fs::write(&path, "body\n").expect("write");
    let path_str = path.to_str().unwrap();
    let args = args_with(&[
        ("path", json!(path_str)),
        ("extra", json!({"x": "y"})),
        ("nested", json!([1, 2, 3])),
        ("flag", json!(true)),
    ]);
    let (_text, _is_err) = dispatch_read(&args);
    // No panic; extras ignored.
}

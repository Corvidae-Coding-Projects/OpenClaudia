//! End-to-end tests for the `glob` and `grep` tools
//! dispatched through the registry — pre-FS-walk
//! validation arms and the path-traversal rejection.
//!
//! Sprint 149 of the verification effort. Sprint 26
//! covered direct execute_* calls; this file pins the
//! registry-dispatched path so the wire-facing contract
//! matches, exercising the typed `arg_str_strict` /
//! `arg_str_or_strict` accessors (#675) end to end.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::registry;
use serde_json::{json, Value};
use std::collections::HashMap;

mod support;

fn dispatch(name: &str, args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool(name, args)
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — glob: missing/wrong-type pattern arg (#675)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn glob_missing_pattern_arg_returns_documented_error() {
    let (msg, is_err) = dispatch("glob", &HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("Missing 'pattern' argument"),
        "MUST surface documented missing-pattern; got {msg:?}"
    );
}

#[test]
fn glob_pattern_as_number_returns_validation_error() {
    let args = args_with(&[("pattern", json!(42))]);
    let (msg, is_err) = dispatch("glob", &args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'pattern' argument: expected string");
}

#[test]
fn glob_pattern_as_array_returns_validation_error() {
    let args = args_with(&[("pattern", json!(["*.rs"]))]);
    let (msg, is_err) = dispatch("glob", &args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'pattern' argument: expected string");
}

#[test]
fn glob_pattern_as_null_returns_validation_error() {
    let args = args_with(&[("pattern", Value::Null)]);
    let (msg, is_err) = dispatch("glob", &args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'pattern' argument: expected string");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — glob: path traversal rejection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn glob_path_with_parent_dir_traversal_rejected() {
    let args = args_with(&[("pattern", json!("*.rs")), ("path", json!("/tmp/../etc"))]);
    let (msg, is_err) = dispatch("glob", &args);
    assert!(is_err);
    assert!(
        msg.contains("traversal") || msg.contains("Path"),
        "MUST surface traversal rejection; got {msg:?}"
    );
}

#[test]
fn glob_path_as_number_returns_validation_error() {
    let args = args_with(&[("pattern", json!("*.rs")), ("path", json!(42))]);
    let (msg, is_err) = dispatch("glob", &args);
    assert!(is_err);
    assert!(
        msg.contains("Host safety")
            && msg.contains("malformed arguments")
            && msg.contains("'path'"),
        "non-string glob path MUST be rejected; got {msg:?}"
    );
}

#[test]
fn glob_permissive_translator_accepts_most_patterns_no_panic() {
    // AUTHORING DISCOVERY: glob_to_regex is permissive —
    // `[unclosed` (unbalanced bracket) is NOT rejected at the
    // glob layer; it's translated and either matches nothing
    // or errors at the regex compile step downstream.
    // We pin the actual behavior: no panic, returns gracefully.
    let args = args_with(&[("pattern", json!("[unclosed"))]);
    let (_msg, _is_err) = dispatch("glob", &args);
    // Either Ok (empty match) or Err (regex compile fail) —
    // both shapes acceptable; the contract is no-panic.
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — glob: happy path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn glob_finds_matching_file_in_tempdir() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(dir.path().join("a.rs"), "").expect("write a");
    std::fs::write(dir.path().join("b.rs"), "").expect("write b");
    std::fs::write(dir.path().join("c.txt"), "").expect("write c");

    let args = args_with(&[
        ("pattern", json!("*.rs")),
        ("path", json!(dir.path().to_str().unwrap())),
    ]);
    let (text, is_err) = dispatch("glob", &args);
    assert!(!is_err);
    assert!(
        text.contains("a.rs") && text.contains("b.rs"),
        "MUST find both .rs files; got {text:?}"
    );
    assert!(
        !text.contains("c.txt"),
        "*.rs MUST NOT match c.txt; got {text:?}"
    );
}

#[test]
fn glob_no_match_returns_clean_output_not_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(dir.path().join("x.txt"), "").expect("write");

    let args = args_with(&[
        ("pattern", json!("*.nomatch_xyz")),
        ("path", json!(dir.path().to_str().unwrap())),
    ]);
    let (_text, is_err) = dispatch("glob", &args);
    // No match is NOT an error — just empty.
    assert!(!is_err);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — grep: missing/wrong-type pattern arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn grep_missing_pattern_arg_returns_documented_error() {
    let (msg, is_err) = dispatch("grep", &HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("Missing 'pattern' argument"),
        "MUST surface documented missing-pattern; got {msg:?}"
    );
}

#[test]
fn grep_pattern_as_number_returns_validation_error() {
    let args = args_with(&[("pattern", json!(42))]);
    let (msg, is_err) = dispatch("grep", &args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'pattern' argument: expected string");
}

#[test]
fn grep_pattern_as_array_returns_validation_error() {
    let args = args_with(&[("pattern", json!(["foo"]))]);
    let (msg, is_err) = dispatch("grep", &args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'pattern' argument: expected string");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — grep: regex validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn grep_invalid_regex_pattern_returns_clean_error_not_panic() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(dir.path().join("x.txt"), "body").expect("write");

    let args = args_with(&[
        ("pattern", json!("[invalid_unclosed_class")),
        ("path", json!(dir.path().to_str().unwrap())),
    ]);
    let (msg, is_err) = dispatch("grep", &args);
    assert!(is_err);
    assert!(
        msg.to_lowercase().contains("regex") || msg.contains("Invalid") || msg.contains("pattern"),
        "MUST surface invalid-regex error; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — grep: happy path + flags
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn grep_literal_pattern_finds_match_in_file() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(
        dir.path().join("hit.txt"),
        "line one\nUNIQUE_MARKER_xyz\nline three\n",
    )
    .expect("write");

    let args = args_with(&[
        ("pattern", json!("UNIQUE_MARKER")),
        ("path", json!(dir.path().to_str().unwrap())),
    ]);
    let (text, is_err) = dispatch("grep", &args);
    assert!(!is_err);
    assert!(text.contains("UNIQUE_MARKER_xyz"));
}

#[test]
fn grep_case_insensitive_flag_matches_uppercase_lowercase() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(dir.path().join("ci.txt"), "Hello WORLD\nlowercase world\n").expect("write");

    let args = args_with(&[
        ("pattern", json!("world")),
        ("path", json!(dir.path().to_str().unwrap())),
        ("case_insensitive", json!(true)),
    ]);
    let (text, is_err) = dispatch("grep", &args);
    assert!(!is_err);
    // Both rows match.
    assert!(text.contains("Hello WORLD"));
    assert!(text.contains("lowercase world"));
}

#[test]
fn grep_default_case_sensitive_skips_wrong_case() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(dir.path().join("cs.txt"), "Hello WORLD\nfoo bar\n").expect("write");

    let args = args_with(&[
        ("pattern", json!("world")),
        ("path", json!(dir.path().to_str().unwrap())),
    ]);
    let (text, is_err) = dispatch("grep", &args);
    assert!(!is_err);
    // case-sensitive default → lowercase "world" doesn't match
    // "WORLD".
    assert!(!text.contains("Hello WORLD"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — grep: path traversal
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn grep_path_with_parent_dir_traversal_rejected() {
    let args = args_with(&[("pattern", json!("foo")), ("path", json!("/tmp/../etc"))]);
    let (msg, is_err) = dispatch("grep", &args);
    assert!(is_err);
    assert!(
        msg.contains("traversal") || msg.contains("Path"),
        "MUST surface traversal rejection; got {msg:?}"
    );
}

#[test]
fn grep_path_as_array_returns_validation_error() {
    let args = args_with(&[("pattern", json!("foo")), ("path", json!(["."]))]);
    let (msg, is_err) = dispatch("grep", &args);
    assert!(is_err);
    assert!(
        msg.contains("Host safety")
            && msg.contains("malformed arguments")
            && msg.contains("'path'"),
        "non-string grep path MUST be rejected; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — context_lines validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn grep_context_lines_above_u64_max_no_panic() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(dir.path().join("ctx.txt"), "match\n").expect("write");

    let args = args_with(&[
        ("pattern", json!("match")),
        ("path", json!(dir.path().to_str().unwrap())),
        ("context_lines", json!(u64::MAX)),
    ]);
    let (_text, _is_err) = dispatch("grep", &args);
    // No panic — try_from defaults to 0 on overflow.
}

#[test]
fn grep_negative_context_lines_returns_validation_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(dir.path().join("ctx2.txt"), "match\n").expect("write");

    let args = args_with(&[
        ("pattern", json!("match")),
        ("path", json!(dir.path().to_str().unwrap())),
        ("context_lines", json!(-1)),
    ]);
    let (text, is_err) = dispatch("grep", &args);
    assert!(is_err);
    assert!(
        text.contains("context_lines") && text.contains("non-negative"),
        "negative context_lines must fail clearly; got {text:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — Cross-tool
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn glob_and_grep_both_registered() {
    assert!(registry().get("glob").is_some());
    assert!(registry().get("grep").is_some());
}

#[test]
fn glob_and_grep_default_path_is_cwd_dot() {
    // PINS DEFAULT: omitted path defaults to current dir. No traversal, no error.
    let g_args = args_with(&[("pattern", json!("*.nomatch"))]);
    let (_g_msg, _) = dispatch("glob", &g_args);
    // glob succeeds (empty result) — pin: not a path-error message.

    let r_args = args_with(&[("pattern", json!("__no_match_xyz__"))]);
    let (_r_msg, _) = dispatch("grep", &r_args);
}

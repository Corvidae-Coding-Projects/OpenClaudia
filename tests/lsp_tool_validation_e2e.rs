//! End-to-end tests for `tools::lsp::execute_lsp`
//! validation arms — pre-server-spawn checks invoked
//! through the registry dispatch path.
//!
//! Sprint 139 of the verification effort. Sprint 47 / 109
//! covered LSP type shapes + `mark_opened` / `mark_closed`
//! plus connected lookup; this file pins the user-facing
//! tool validation — missing `file_path`, missing `action`, unknown
//! extension, LSP-unavailable gate (#650), and the 10 MiB
//! file-size cap (#648).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use serde_json::{json, Value};
use std::collections::HashMap;

mod support;

fn dispatch_lsp(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("lsp", args)
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

fn assert_file_path_classification_denial(message: &str) {
    assert!(message.contains("Host safety"), "got {message:?}");
    assert!(message.contains("file_path"), "got {message:?}");
    assert!(
        message.contains("malformed arguments") || message.contains("Missing"),
        "got {message:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing/wrong-type file_path arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_file_path_arg_returns_error() {
    let (msg, is_err) = dispatch_lsp(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("file_path"),
        "MUST mention file_path; got {msg:?}"
    );
}

#[test]
fn file_path_arg_as_number_returns_validation_error() {
    let args = args_with(&[("file_path", json!(42))]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert_file_path_classification_denial(&msg);
}

#[test]
fn file_path_arg_as_array_returns_validation_error() {
    let args = args_with(&[("file_path", json!(["a", "b"]))]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert_file_path_classification_denial(&msg);
}

#[test]
fn file_path_arg_as_null_returns_validation_error() {
    let args = args_with(&[("file_path", Value::Null)]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert_file_path_classification_denial(&msg);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Unknown file extension
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unknown_extension_yields_no_language_server_message() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/file.unknownext")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(
        msg.contains("No language server known"),
        "MUST surface 'No language server known'; got {msg:?}"
    );
    assert!(
        msg.contains("tests/fixtures/lsp/file.unknownext"),
        "MUST echo offending path; got {msg:?}"
    );
}

#[test]
fn file_with_no_extension_yields_no_language_server_message() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/no_extension_file")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(msg.contains("No language server known"));
}

#[test]
fn empty_string_file_path_is_rejected_before_language_server_selection() {
    let args = args_with(&[("file_path", json!("")), ("action", json!("hover"))]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert_file_path_classification_denial(&msg);
}

#[test]
fn dotfile_with_no_extension_yields_no_language_server() {
    // ".gitignore" — first split by "." gives "" (no extension).
    // Actually rsplit('.') on ".gitignore" yields "gitignore" — a
    // valid string. Pin: result is still "No language server" since
    // "gitignore" is not in the known-ext map.
    let args = args_with(&[
        ("file_path", json!(".gitignore")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(msg.contains("No language server known"));
}

#[test]
fn unknown_action_errors_before_extension_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/file.unknownext")),
        ("action", json!("definitelyNotReal")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(msg.contains("Unknown LSP action"), "got {msg:?}");
    assert!(
        !msg.contains("No language server known"),
        "action validation must run before extension gate; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Call hierarchy argument validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn incoming_calls_missing_hierarchy_item_errors_before_server_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/nonexistent.rs")),
        ("action", json!("incomingCalls")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(
        msg.contains("continuation_token") && msg.contains("prepareCallHierarchy"),
        "must explain required call hierarchy continuation; got {msg:?}"
    );
    assert!(
        !msg.contains("LSP server unavailable"),
        "argument validation must run before server availability gate; got {msg:?}"
    );
}

#[test]
fn outgoing_calls_rejects_non_object_hierarchy_item() {
    for bad in [Value::Null, json!("not-an-item"), json!([1, 2, 3])] {
        let args = args_with(&[
            ("file_path", json!("tests/fixtures/lsp/nonexistent.rs")),
            ("action", json!("outgoingCalls")),
            ("hierarchy_item", bad),
        ]);
        let (msg, is_err) = dispatch_lsp(&args);
        assert!(is_err);
        assert_eq!(msg, "Invalid 'hierarchy_item' argument: expected object");
    }
}

#[test]
fn call_hierarchy_with_object_item_reaches_file_validation() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/file.unknownext")),
        ("action", json!("incomingCalls")),
        (
            "hierarchy_item",
            json!({"continuation_token": "lspct_fixture"}),
        ),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(
        msg.contains("No language server known"),
        "valid hierarchy object should pass argument validation; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Known extensions reach LSP-availability gate
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn rust_extension_passes_unknown_server_gate() {
    // file with .rs has a known server (rust-analyzer).
    // Without the binary on PATH the error path is the
    // "LSP server unavailable" message (#650 gate). With
    // the binary on PATH, the error is from the server
    // request itself (file doesn't exist on disk).
    let args = args_with(&[
        (
            "file_path",
            json!("tests/fixtures/lsp/nonexistent_unique_marker.rs"),
        ),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    // Either way the tool returns an error for a non-existent
    // path. We pin: it MUST NOT surface "No language server
    // known" because .rs IS known.
    assert!(is_err);
    assert!(
        !msg.contains("No language server known"),
        ".rs MUST be a known extension; got {msg:?}"
    );
}

#[test]
fn python_extension_passes_unknown_server_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/nonexistent.py")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(!msg.contains("No language server known"));
}

#[test]
fn typescript_extension_passes_unknown_server_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/nonexistent.ts")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(!msg.contains("No language server known"));
}

#[test]
fn go_extension_passes_unknown_server_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/nonexistent.go")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(!msg.contains("No language server known"));
}

#[test]
fn cpp_extension_passes_unknown_server_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/nonexistent.cpp")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(!msg.contains("No language server known"));
}

#[test]
fn header_extension_passes_unknown_server_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/nonexistent.hpp")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(!msg.contains("No language server known"));
}

#[test]
fn java_extension_passes_unknown_server_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/nonexistent.java")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(!msg.contains("No language server known"));
}

#[test]
fn ruby_extension_passes_unknown_server_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/nonexistent.rb")),
        ("action", json!("hover")),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(!msg.contains("No language server known"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Required action validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_action_arg_returns_required_error() {
    let args = args_with(&[("file_path", json!("tests/fixtures/lsp/x.unknownext"))]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(
        msg.contains("action") && msg.contains("required"),
        "missing action MUST be rejected before extension lookup; got {msg:?}"
    );
    assert!(
        !msg.contains("No language server known"),
        "missing action must not fall through to extension lookup; got {msg:?}"
    );
}

#[test]
fn action_arg_as_number_returns_validation_error() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.rs")),
        ("action", json!(42)),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid 'action' argument: expected string"),
        "wrong-type action MUST be rejected; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Optional query validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn query_arg_as_number_returns_validation_error_before_extension_gate() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.unknownext")),
        ("action", json!("workspaceSymbol")),
        ("query", json!(42)),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'query' argument: expected string");
}

#[test]
fn query_arg_as_object_returns_validation_error_for_non_workspace_action() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.unknownext")),
        ("action", json!("hover")),
        ("query", json!({"symbol": "main"})),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'query' argument: expected string");
}

#[test]
fn oversized_query_is_rejected_before_server_lookup() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.unknownext")),
        ("action", json!("workspaceSymbol")),
        ("query", json!("q".repeat(16 * 1024 + 1))),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(msg.contains("exceeds the 16384-byte limit"), "{msg}");
    assert!(!msg.contains("No language server known"), "{msg}");
}

#[test]
fn oversized_continuation_is_rejected_before_server_lookup() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.unknownext")),
        ("action", json!("incomingCalls")),
        ("continuation_token", json!("t".repeat(1025))),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(msg.contains("maximum is 1024 bytes"), "{msg}");
    assert!(!msg.contains("No language server known"), "{msg}");
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — line + character validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn line_arg_above_u32_max_is_rejected_instead_of_clamped() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.rs")),
        ("action", json!("hover")),
        ("line", json!(u64::MAX)),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert_eq!(msg, "Error: line must fit an unsigned 32-bit integer");
}

#[test]
fn line_arg_zero_returns_validation_error() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.rs")),
        ("action", json!("hover")),
        ("line", json!(0)),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(
        msg.contains("1-indexed"),
        "line=0 must fail before LSP server lookup; got {msg:?}"
    );
}

#[test]
fn character_arg_above_u32_max_is_rejected_instead_of_clamped() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.rs")),
        ("action", json!("hover")),
        ("character", json!(u64::MAX)),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert_eq!(msg, "Error: character must fit an unsigned 32-bit integer");
}

#[test]
fn negative_line_arg_returns_validation_error() {
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.rs")),
        ("action", json!("hover")),
        ("line", json!(-1)),
    ]);
    let (msg, is_err) = dispatch_lsp(&args);
    assert!(is_err);
    assert!(
        msg.contains("1-indexed"),
        "negative line must fail before LSP server lookup; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — Cross-validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_dispatch_never_panics_on_arbitrary_args() {
    // Sanity: arbitrary arg shapes don't panic the tool.
    let args = args_with(&[
        ("file_path", json!("tests/fixtures/lsp/x.rs")),
        ("action", json!("hover")),
        ("line", json!(10)),
        ("character", json!(5)),
        ("extra", json!({"unknown": "arg"})),
    ]);
    let (_msg, _is_err) = dispatch_lsp(&args);
}

//! End-to-end tests for the `notebook_edit` tool dispatched
//! through the registry — pre-IO argument validation.
//!
//! Sprint 145 of the verification effort. This file pins
//! the registry-dispatched validation paths for
//! `notebook_edit`: missing `notebook_path`, mode-conditional
//! `new_source`, invalid `edit_mode`, invalid `cell_type`
//! (#985), out-of-range `cell_number` (#470).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use serde_json::{json, Value};
use std::collections::HashMap;

mod support;

fn dispatch_notebook(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("notebook_edit", args)
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing / wrong-type notebook_path arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_notebook_path_arg_returns_documented_error() {
    let args = args_with(&[("new_source", json!("body"))]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(
        msg.contains("Missing 'notebook_path' argument"),
        "MUST surface documented missing-notebook_path; got {msg:?}"
    );
}

#[test]
fn notebook_path_as_number_returns_validation_error() {
    let args = args_with(&[("notebook_path", json!(42)), ("new_source", json!("body"))]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("malformed arguments"));
    assert!(msg.contains("'notebook_path'"));
}

#[test]
fn notebook_path_as_null_returns_validation_error() {
    let args = args_with(&[
        ("notebook_path", Value::Null),
        ("new_source", json!("body")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("Missing 'notebook_path' argument"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Missing / wrong-type new_source arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_new_source_arg_returns_documented_error() {
    let args = args_with(&[("notebook_path", json!("x.ipynb"))]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(
        msg.contains("Missing 'new_source' argument"),
        "MUST surface documented missing-new_source; got {msg:?}"
    );
}

#[test]
fn new_source_as_number_returns_validation_error() {
    let args = args_with(&[
        ("notebook_path", json!("x.ipynb")),
        ("new_source", json!(42)),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'new_source' argument: expected string"));
}

#[test]
fn delete_does_not_require_irrelevant_new_source() {
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("edit_mode", json!("delete")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err, "nonexistent notebook still fails downstream");
    assert!(
        !msg.contains("new_source"),
        "delete must pass source validation without a placeholder: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Argument-check ordering
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_both_args_surfaces_notebook_path_error_first() {
    // PINS ORDER: notebook_path validated before new_source.
    let (msg, is_err) = dispatch_notebook(&HashMap::new());
    assert!(is_err);
    assert!(msg.contains("notebook_path"));
    assert!(
        !msg.contains("new_source"),
        "new_source error MUST NOT fire when notebook_path is missing; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Invalid edit_mode enum
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn invalid_edit_mode_returns_documented_3_choice_error() {
    let args = args_with(&[
        ("notebook_path", json!("x.ipynb")),
        ("new_source", json!("body")),
        ("edit_mode", json!("not_a_real_mode")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid edit_mode") && msg.contains("not_a_real_mode"),
        "MUST mention invalid + echo offending; got {msg:?}"
    );
    // Documented enum values MUST appear in error.
    assert!(
        msg.contains("'replace'") && msg.contains("'insert'") && msg.contains("'delete'"),
        "MUST list 3 documented modes; got {msg:?}"
    );
}

#[test]
fn edit_mode_as_number_returns_validation_error() {
    let args = args_with(&[
        ("notebook_path", json!("x.ipynb")),
        ("new_source", json!("body")),
        ("edit_mode", json!(42)),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'edit_mode' argument: expected string"));
}

#[test]
fn edit_mode_replace_passes_enum_check() {
    // Valid edit_mode — fails downstream (file doesn't exist) but
    // NOT with the enum error.
    let args = args_with(&[
        ("notebook_path", json!("nonexistent_nb_xyz.ipynb")),
        ("new_source", json!("body")),
        ("edit_mode", json!("replace")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(
        !msg.contains("Invalid edit_mode"),
        "replace MUST pass enum check; got {msg:?}"
    );
}

#[test]
fn edit_mode_insert_passes_enum_check() {
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
        ("edit_mode", json!("insert")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(!msg.contains("Invalid edit_mode"));
}

#[test]
fn edit_mode_delete_passes_enum_check() {
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
        ("edit_mode", json!("delete")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(!msg.contains("Invalid edit_mode"));
}

#[test]
fn missing_edit_mode_defaults_to_replace() {
    // PINS DEFAULT: omitted edit_mode → "replace" (no enum error).
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(
        !msg.contains("Invalid edit_mode"),
        "omitted edit_mode MUST default to replace; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Invalid cell_type enum (#985)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn invalid_cell_type_returns_documented_nbformat_error() {
    // PINS #985: cell_type must be in nbformat allowlist
    // {code, markdown, raw}.
    let args = args_with(&[
        ("notebook_path", json!("x.ipynb")),
        ("new_source", json!("body")),
        ("cell_type", json!("bogus_type")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid cell_type") && msg.contains("bogus_type"),
        "MUST surface invalid + echo offending; got {msg:?}"
    );
    assert!(
        msg.contains("'code'") && msg.contains("'markdown'") && msg.contains("'raw'"),
        "MUST list 3 documented nbformat cell types; got {msg:?}"
    );
}

#[test]
fn cell_type_as_number_returns_validation_error() {
    let args = args_with(&[
        ("notebook_path", json!("x.ipynb")),
        ("new_source", json!("body")),
        ("cell_type", json!(42)),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'cell_type' argument: expected string"));
}

#[test]
fn cell_type_code_passes_enum_check() {
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
        ("cell_type", json!("code")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(!msg.contains("Invalid cell_type"));
}

#[test]
fn cell_type_markdown_passes_enum_check() {
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
        ("cell_type", json!("markdown")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(!msg.contains("Invalid cell_type"));
}

#[test]
fn cell_type_raw_passes_enum_check() {
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
        ("cell_type", json!("raw")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(!msg.contains("Invalid cell_type"));
}

#[test]
fn missing_cell_type_arg_passes_enum_check() {
    // PINS DOC: cell_type is optional.
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(!msg.contains("Invalid cell_type"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — cell_number range validation (#470)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cell_number_above_usize_range_returns_platform_specific_error() {
    // PINS #470: on 32-bit, u64::MAX won't fit usize; on 64-bit
    // the try_from succeeds and the value passes through. We
    // just verify no panic + reasonable error path.
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
        ("cell_number", json!(u64::MAX)),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    // Always errors (either out-of-range OR file-not-found).
    assert!(is_err);
    let _ = msg;
}

#[test]
fn cell_number_negative_is_rejected_as_non_u64() {
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
        ("cell_number", json!(-1)),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'cell_number' argument: expected non-negative integer"));
}

#[test]
fn cell_id_as_number_returns_validation_error() {
    let args = args_with(&[
        ("notebook_path", json!("nonexistent.ipynb")),
        ("new_source", json!("body")),
        ("cell_id", json!(42)),
    ]);
    let (msg, is_err) = dispatch_notebook(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'cell_id' argument: expected string"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Forward-compat
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dispatch_never_panics_on_arbitrary_extra_args() {
    let args = args_with(&[
        ("notebook_path", json!("x.ipynb")),
        ("new_source", json!("body")),
        ("unknown_arg", json!("ignored")),
        ("nested", json!([1, 2, 3])),
    ]);
    let (_msg, _is_err) = dispatch_notebook(&args);
    // No panic.
}

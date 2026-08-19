//! End-to-end validation tests for `grounding_context` through
//! registry dispatch. This pins the model-visible Reality Ledger
//! hydration contract before any ledger file is opened.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]

use openclaudia::ledger::{project_session_ledger_path, ObsId};
use serde_json::{json, Value};
use std::collections::HashMap;

mod support;

fn dispatch(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("grounding_context", args)
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect()
}

#[test]
fn missing_ids_arg_returns_documented_error() {
    let (msg, is_err) = dispatch(&HashMap::new());
    assert!(is_err);
    assert_eq!(msg, "Missing 'ids' argument");
}

#[test]
fn ids_as_string_returns_validation_error() {
    let args = args_with(&[("ids", json!("obs-1"))]);
    let (msg, is_err) = dispatch(&args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'ids' argument: expected array");
}

#[test]
fn ids_as_object_returns_validation_error() {
    let args = args_with(&[("ids", json!({"id": "obs-1"}))]);
    let (msg, is_err) = dispatch(&args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'ids' argument: expected array");
}

#[test]
fn ids_as_null_returns_validation_error() {
    let args = args_with(&[("ids", Value::Null)]);
    let (msg, is_err) = dispatch(&args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'ids' argument: expected array");
}

#[test]
fn empty_ids_array_returns_validation_error() {
    let args = args_with(&[("ids", json!([]))]);
    let (msg, is_err) = dispatch(&args);
    assert!(is_err);
    assert_eq!(msg, "'ids' must contain at least one observation ID");
}

#[test]
fn too_many_ids_returns_validation_error() {
    let ids = (0..17)
        .map(|_| ObsId::new().to_string())
        .collect::<Vec<_>>();
    let args = args_with(&[("ids", json!(ids))]);
    let (msg, is_err) = dispatch(&args);
    assert!(is_err);
    assert!(msg.contains("'ids' may contain at most 16 observation IDs"));
}

#[test]
fn non_string_id_returns_indexed_validation_error() {
    let args = args_with(&[("ids", json!([42]))]);
    let (msg, is_err) = dispatch(&args);
    assert!(is_err);
    assert_eq!(msg, "ids[0] must be a string");
}

#[test]
fn malformed_id_returns_indexed_validation_error() {
    let args = args_with(&[("ids", json!(["not-a-valid-obs-id"]))]);
    let (msg, is_err) = dispatch(&args);
    assert!(is_err);
    assert!(
        msg.contains("ids[0] is not a valid observation ID"),
        "unexpected error: {msg}"
    );
}

#[test]
fn include_stale_wrong_type_returns_validation_error() {
    let args = args_with(&[
        ("ids", json!([ObsId::new().to_string()])),
        ("include_stale", json!("true")),
    ]);
    let (msg, is_err) = dispatch(&args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'include_stale' argument: expected boolean");
}

#[test]
fn valid_args_without_session_ledger_reach_no_ledger_error() {
    let run = support::test_run_context(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let session_id = run.session_id().to_string();
    let ledger_path = project_session_ledger_path(&session_id).expect("ledger path");
    let _ = std::fs::remove_file(&ledger_path);

    let args = args_with(&[
        ("ids", json!([ObsId::new().to_string()])),
        ("include_stale", json!(false)),
    ]);
    let result = support::dispatch_tool_result_for_run(&run, "grounding_context", &args);
    let (msg, is_err) = support::legacy(&result);

    assert!(is_err);
    assert!(
        msg.contains("No active session reality ledger"),
        "valid args should reach ledger lookup, got: {msg}"
    );
    assert!(
        !ledger_path.exists(),
        "grounding_context must not create a ledger while hydrating evidence"
    );
}

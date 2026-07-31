//! End-to-end validation tests for the registry-dispatched `crosslink`
//! tool argument surface.
//!
//! These cases stop before database open: they pin the model-facing
//! `args` field contract without creating `.crosslink/issues.db`.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use serde_json::{json, Value};
use std::collections::HashMap;

fn dispatch(args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch("crosslink", args, &mut ctx)
        .expect("crosslink must be registered")
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

#[test]
fn crosslink_missing_args_returns_documented_error() {
    let (msg, is_err) = dispatch(&HashMap::new());

    assert!(is_err);
    assert_eq!(msg, "Missing 'args' argument");
}

#[test]
fn crosslink_number_args_returns_validation_error() {
    let args = args_with(&[("args", json!(42))]);
    let (msg, is_err) = dispatch(&args);

    assert!(is_err);
    assert_eq!(msg, "Invalid 'args' argument: expected string");
}

#[test]
fn crosslink_null_args_returns_validation_error() {
    let args = args_with(&[("args", Value::Null)]);
    let (msg, is_err) = dispatch(&args);

    assert!(is_err);
    assert_eq!(msg, "Invalid 'args' argument: expected string");
}

#[test]
fn crosslink_empty_args_returns_missing_subcommand_before_db_open() {
    let args = args_with(&[("args", json!(""))]);
    let (msg, is_err) = dispatch(&args);

    assert!(is_err);
    assert_eq!(msg, "Missing crosslink subcommand");
}

#[test]
fn crosslink_unknown_subcommand_returns_allowlist_error_before_db_open() {
    let args = args_with(&[("args", json!("definitely_not_a_crosslink_command"))]);
    let (msg, is_err) = dispatch(&args);

    assert!(is_err);
    assert!(msg.contains("is not in the crosslink allowlist"));
}

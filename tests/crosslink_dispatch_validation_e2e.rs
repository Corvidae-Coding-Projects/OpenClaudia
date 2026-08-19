//! End-to-end validation tests for the registry-dispatched `crosslink`
//! tool argument surface.
//!
//! These cases stop before database open: they pin the model-facing
//! typed-operation contract without creating `.crosslink/issues.db`.
//!
//! S-016/F-052 replaced the previous `args` string contract. The old cases
//! here pinned the tokenizer's error messages ("Missing crosslink
//! subcommand", "is not in the crosslink allowlist"), which only existed
//! because a whole command line arrived as one opaque field the registry
//! could not classify. What is pinned now is that a call which cannot be
//! classified is rejected before any side effect.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]

use openclaudia::tools::crosslink::{classify_operation, OPERATIONS};
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
        .into_legacy()
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

#[test]
fn crosslink_missing_operation_returns_documented_error() {
    let (msg, is_err) = dispatch(&HashMap::new());

    assert!(is_err);
    assert!(
        msg.contains("missing required 'operation' field"),
        "got {msg:?}"
    );
}

#[test]
fn crosslink_number_operation_returns_validation_error() {
    let args = args_with(&[("operation", json!(42))]);
    let (msg, is_err) = dispatch(&args);

    assert!(is_err);
    assert!(msg.contains("'operation' must be a string"), "got {msg:?}");
}

#[test]
fn crosslink_null_operation_returns_validation_error() {
    let args = args_with(&[("operation", Value::Null)]);
    let (msg, is_err) = dispatch(&args);

    assert!(is_err);
    assert!(msg.contains("'operation' must be a string"), "got {msg:?}");
}

#[test]
fn crosslink_empty_operation_is_unknown_before_db_open() {
    let args = args_with(&[("operation", json!(""))]);
    let (msg, is_err) = dispatch(&args);

    assert!(is_err);
    assert!(msg.contains("unknown operation"), "got {msg:?}");
}

#[test]
fn crosslink_unknown_operation_is_rejected_before_db_open() {
    let args = args_with(&[("operation", json!("definitely_not_a_crosslink_command"))]);
    let (msg, is_err) = dispatch(&args);

    assert!(is_err);
    assert!(msg.contains("unknown operation"), "got {msg:?}");
}

/// F-052 regression guard: the free-form command field is gone, so a legacy
/// `args` payload cannot smuggle an operation past classification.
#[test]
fn legacy_args_string_no_longer_selects_an_operation() {
    let args = args_with(&[("args", json!("create \"pwned\" -p critical"))]);
    let (msg, is_err) = dispatch(&args);

    assert!(is_err, "a legacy argv payload must not execute");
    assert!(
        msg.contains("missing required 'operation' field"),
        "the argv field must carry no dispatch meaning; got {msg:?}"
    );
}

/// A shell-shaped string placed in the typed field is data, not a command.
/// It fails classification before the database is touched.
#[test]
fn shell_shaped_operation_values_are_rejected_before_db_open() {
    for payload in [
        "create \"x\"",
        "list; create \"y\"",
        "close 1 && rm -rf /",
        "list | tee /tmp/x",
    ] {
        let args = args_with(&[("operation", json!(payload))]);
        let (msg, is_err) = dispatch(&args);
        assert!(is_err, "{payload:?} must not execute");
        assert!(msg.contains("unknown operation"), "{payload:?} -> {msg:?}");
    }
}

/// Every advertised operation classifies. This is the pairing that makes the
/// rejections above meaningful: the contract is closed, not merely strict.
#[test]
fn every_declared_operation_classifies_without_touching_the_database() {
    for op in OPERATIONS {
        let classified = classify_operation(&json!({"operation": op.name}))
            .unwrap_or_else(|e| panic!("{}: {e}", op.name));
        assert_eq!(classified.effect, op.effect);
    }
}

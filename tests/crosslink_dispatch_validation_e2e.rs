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

use openclaudia::{
    permissions::PermissionManager,
    session::TaskManager,
    task_graph::{TaskActor, TaskSource},
    tools::{
        crosslink::{classify_operation, OPERATIONS},
        execute_tool_with_tasks,
    },
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

mod support;

fn dispatch(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("crosslink", args)
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

#[test]
fn registry_dispatch_reconciles_crosslink_records_into_bound_canonical_graph() {
    let root = tempfile::tempdir().expect("isolated Crosslink workspace");
    let run = support::test_run_context(root.path());
    let mut manager = TaskManager::open(
        root.path(),
        PathBuf::from("tasks.json"),
        "registry-crosslink-adapter",
        TaskActor::from_run(&run),
    )
    .expect("canonical task manager");
    let args = args_with(&[
        ("operation", json!("create")),
        ("title", json!("Registry-created external work")),
        ("description", json!("Must appear in the canonical graph")),
        ("priority", json!("high")),
    ]);
    let result = execute_tool_with_tasks(
        &run,
        &support::tool_call("crosslink", &args),
        None,
        None,
        Some(&mut manager),
        &PermissionManager::unrestricted(),
    );

    assert!(!result.is_error(), "result: {result:?}");
    assert!(!result.is_partial(), "result: {result:?}");
    assert_eq!(
        result
            .structured()
            .and_then(|value| value.get("task_graph"))
            .and_then(Value::as_str),
        Some("reconciled")
    );
    let projected = manager
        .list_tasks()
        .iter()
        .find(|task| matches!(task.source, TaskSource::ExternalIssue { .. }))
        .expect("registry must pass the bound manager to the Crosslink adapter");
    assert_eq!(projected.subject, "Registry-created external work");
    assert!(root.path().join(".crosslink/issues.db").is_file());
}

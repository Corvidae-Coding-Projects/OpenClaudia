//! Canonical tool-dispatch envelope tests.
//!
//! Registry handlers are metadata-public but executable only with an opaque
//! permit minted after host-safety evaluation. These tests therefore exercise
//! the public unrestricted convenience executor, which still applies the
//! mandatory host ceiling and binds every result to its originating call.

#![allow(clippy::expect_used)]

use std::collections::HashMap;

use openclaudia::tools::registry::registry;
use openclaudia::tools::{ToolFailureCode, ToolOutcome};
use serde_json::{json, Value};

mod support;

#[test]
fn unknown_and_malformed_names_fail_with_a_bound_unavailable_result() {
    for name in [
        "definitely_not_a_real_tool_xyz_166",
        "",
        "   ",
        "BASH",
        " bash",
        "tool\0with\0nulls",
    ] {
        let result = support::dispatch_tool_result(name, &HashMap::new());
        assert!(result.is_error(), "{name:?} must fail");
        assert!(matches!(
            result.outcome(),
            ToolOutcome::Error { failure } if failure.code == ToolFailureCode::PermissionDenied
        ));
        assert!(result.content().contains("Host safety"));
        assert_eq!(result.tool_call_id(), format!("test-{name}"));
        assert_eq!(result.handler(), name);
        assert!(!result.content().is_empty());
    }
}

#[test]
fn extreme_unknown_name_fails_without_panicking() {
    let name = "x".repeat(10 * 1024);
    let result = support::dispatch_tool_result(&name, &HashMap::new());
    assert!(result.is_error());
    assert!(matches!(
        result.outcome(),
        ToolOutcome::Error { failure } if failure.code == ToolFailureCode::PermissionDenied
    ));
    assert!(result.content().contains("Host safety"));
}

#[test]
fn known_tool_validation_failure_is_nonempty_and_bound_to_the_call() {
    let result = support::dispatch_tool_result("bash", &HashMap::new());
    assert!(result.is_error());
    assert_eq!(result.tool_call_id(), "test-bash");
    assert_eq!(result.handler(), "bash");
    assert!(!result.content().is_empty());
}

#[test]
fn every_registered_handler_produces_a_nonempty_canonical_result() {
    for handler in openclaudia::tools::registry::iter_handlers() {
        let result = support::dispatch_tool_result(handler.name(), &HashMap::new());
        assert!(
            !result.content().is_empty(),
            "{} returned an empty result envelope",
            handler.name()
        );
    }
}

#[test]
fn canonical_dispatch_does_not_mutate_the_argument_map() {
    let args = HashMap::from([
        ("key1".to_string(), json!("value1")),
        ("key2".to_string(), json!(42)),
    ]);
    let snapshot = args.clone();
    let _ = support::dispatch_tool_result("list_files", &args);
    assert_eq!(args, snapshot);
}

#[test]
fn canonical_dispatch_accepts_a_large_argument_map_without_panicking() {
    let args: HashMap<String, Value> = (0..1000).map(|i| (format!("key_{i}"), json!(i))).collect();
    let result = support::dispatch_tool_result("list_files", &args);
    assert!(!result.content().is_empty());
}

#[test]
fn repeated_read_only_dispatch_is_deterministic() {
    let directory = tempfile::TempDir::new_in(".").expect("tempdir");
    let args = HashMap::from([(
        "path".to_string(),
        json!(directory.path().to_str().expect("UTF-8 temp path")),
    )]);
    let first = support::dispatch_tool_result("list_files", &args);
    let second = support::dispatch_tool_result("list_files", &args);
    assert_eq!(first.is_error(), second.is_error());
    assert_eq!(first.content(), second.content());
}

#[test]
fn registry_name_lookup_remains_byte_exact() {
    for (name, registered) in [
        ("bash", true),
        ("read_file", true),
        ("skill", true),
        ("BASH", false),
        ("", false),
        ("definitely_not_a_tool_xyz", false),
    ] {
        assert_eq!(registry().get(name).is_some(), registered, "{name:?}");
    }
}

#[test]
fn unknown_kill_shell_id_reports_error_without_touching_processes() {
    let args = HashMap::from([("shell_id".to_string(), json!("not-a-real-shell-id-166"))]);
    let result = support::dispatch_tool_result("kill_shell", &args);
    assert!(result.is_error());
    assert!(!result.content().is_empty());
}

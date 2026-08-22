//! Registry metadata and canonical result-shape invariants.
//!
//! Direct handler execution intentionally requires an unforgeable dispatch
//! permit. Public callers use the canonical executor and receive `ToolResult`,
//! while the registry remains available for schemas and effect metadata.

#![allow(clippy::expect_used)]

use std::collections::HashMap;

use openclaudia::tools::registry::registry;
use openclaudia::tools::{ToolFailureCode, ToolOutcome};

mod support;

#[test]
fn registry_is_a_stable_singleton() {
    let pointers: Vec<*const _> = (0..5).map(|_| std::ptr::from_ref(registry())).collect();
    assert!(pointers.windows(2).all(|pair| pair[0] == pair[1]));
}

#[test]
fn registry_lookup_is_exact_and_non_normalizing() {
    for name in ["bash", "list_files", "read_file", "write_file", "grep"] {
        assert!(registry().get(name).is_some(), "{name} must be registered");
    }
    for name in ["Bash", "bash ", "", "   ", "xyz_unknown"] {
        assert!(
            registry().get(name).is_none(),
            "{name:?} must not normalize"
        );
    }
}

#[test]
fn canonical_unknown_dispatch_is_a_typed_host_safety_failure_not_an_absent_value() {
    let result = support::dispatch_tool_result("xyz_unknown", &HashMap::new());
    assert!(result.is_error());
    assert!(matches!(
        result.outcome(),
        ToolOutcome::Error { failure } if failure.code == ToolFailureCode::PermissionDenied
    ));
    assert!(result.content().contains("Host safety"));
    assert!(!result.content().is_empty());
}

#[test]
fn canonical_known_dispatch_always_returns_a_bound_result() {
    for name in ["bash", "list_files", "read_file", "write_file", "edit_file"] {
        let result = support::dispatch_tool_result(name, &HashMap::new());
        assert_eq!(result.tool_call_id(), format!("test-{name}"));
        assert_eq!(result.handler(), name);
        assert!(!result.content().is_empty());
    }
}

#[test]
fn repeated_registry_lookup_and_dispatch_preserve_shape() {
    for _ in 0..10 {
        assert!(registry().get("list_files").is_some());
        let result = support::dispatch_tool_result("list_files", &HashMap::new());
        assert!(!result.content().is_empty());
    }
}

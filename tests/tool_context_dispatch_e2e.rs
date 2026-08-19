//! `ToolContext` construction and canonical-dispatch integration tests.
//!
//! `ToolContext` remains the internal dependency carrier, while external
//! execution enters through a host-safety-checked executor rather than
//! calling registry handlers directly.

#![allow(clippy::expect_used)]

use std::collections::HashMap;

use openclaudia::tools::registry::{registry, ToolContext};
use openclaudia::tools::{ToolFailureCode, ToolOutcome};
use serde_json::json;

mod support;

#[test]
fn tool_context_struct_literal_supports_absent_optional_services() {
    let context = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    assert!(context.memory_db.is_none());
    assert!(context.app_config.is_none());
    assert!(context.task_mgr.is_none());
}

#[test]
fn tool_context_can_be_borrowed_mutably_by_the_internal_executor() {
    let mut context = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    context.task_mgr = None;
}

#[test]
fn registry_singleton_and_lookup_are_stable() {
    assert!(std::ptr::eq(registry(), registry()));
    assert!(registry().get("bash").is_some());
    assert!(registry().get("no-such-tool").is_none());
}

#[test]
fn canonical_tool_search_returns_a_bound_result() {
    let args = HashMap::from([
        ("query".to_string(), json!("any-search-string")),
        ("max_results".to_string(), json!(5)),
    ]);
    let result = support::dispatch_tool_result("tool_search", &args);
    assert_eq!(result.tool_call_id(), "test-tool_search");
    assert_eq!(result.handler(), "tool_search");
    assert!(!result.content().is_empty());
}

#[test]
fn canonical_unknown_dispatch_returns_a_typed_failure_with_arbitrary_args() {
    let args = HashMap::from([
        ("anything".to_string(), json!("value")),
        ("count".to_string(), json!(42)),
        ("nested".to_string(), json!({"k": "v"})),
    ]);
    let result = support::dispatch_tool_result("__no_such_tool__", &args);
    assert!(result.is_error());
    assert!(matches!(
        result.outcome(),
        ToolOutcome::Error { failure } if failure.code == ToolFailureCode::PermissionDenied
    ));
    assert!(result.content().contains("Host safety"));
}

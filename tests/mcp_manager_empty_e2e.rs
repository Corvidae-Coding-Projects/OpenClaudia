//! End-to-end tests for `mcp::McpManager` on an empty
//! registry — every accessor / disconnect path against
//! zero servers.
//!
//! Sprint 130 of the verification effort. Sprint 36
//! (`mcp_integration`) covered `call_tool` validation;
//! sprint 79 covered `InProcessTransport`; this file pins
//! the empty-registry semantics: `server_count` = 0,
//! `is_connected` = false for any name, `disconnect_all`
//! is a no-op, `get_server_info` returns None,
//! `list_resources(None)` returns empty.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::mcp::{McpError, McpManager};

// ───────────────────────────────────────────────────────────────────────────
// Section A — Constructor + empty state
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn fresh_manager_has_zero_servers() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    assert_eq!(mgr.server_count().await, 0);
}

#[tokio::test]
async fn fresh_manager_is_connected_returns_false_for_any_name() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    assert!(!mgr.is_connected("anything").await);
    assert!(!mgr.is_connected("").await);
    assert!(!mgr.is_connected("server-1").await);
}

#[tokio::test]
async fn fresh_manager_get_server_info_returns_none_for_any_name() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    assert!(mgr.get_server_info("missing").await.is_none());
    assert!(mgr.get_server_info("").await.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Disconnect on empty
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn disconnect_unknown_name_on_empty_manager_returns_ok() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    // PINS DOC: disconnect on missing name is Ok (no-op).
    let outcome = mgr.disconnect("nonexistent").await;
    assert!(outcome.is_ok());
}

#[tokio::test]
async fn disconnect_all_on_empty_manager_returns_ok() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let outcome = mgr.disconnect_all().await;
    assert!(outcome.is_ok());
    // Still zero after disconnect_all on empty.
    assert_eq!(mgr.server_count().await, 0);
}

#[tokio::test]
async fn disconnect_all_called_repeatedly_is_idempotent() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let _ = mgr.disconnect_all().await;
    let _ = mgr.disconnect_all().await;
    let _ = mgr.disconnect_all().await;
    assert_eq!(mgr.server_count().await, 0);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — list_resources on empty
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_resources_none_on_empty_returns_empty_vec() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let resources = mgr.list_resources(None).await.expect("ok");
    assert!(resources.is_empty());
}

#[tokio::test]
async fn list_resources_with_unknown_server_name_errors() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let outcome = mgr.list_resources(Some("missing-server")).await;
    assert!(
        outcome.is_err(),
        "list_resources on unknown server MUST error"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — call_tool on empty
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn call_tool_on_empty_manager_with_valid_format_yields_not_connected() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let outcome = mgr
        .call_tool("mcp__missing__some_tool", serde_json::json!({}))
        .await;
    let err = outcome.expect_err("MUST error on empty manager");
    assert!(matches!(err, McpError::NotConnected { .. }));
}

#[tokio::test]
async fn call_tool_with_invalid_format_yields_error_even_on_empty() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    // PINS DOC: invalid name format (no mcp__ prefix) is its
    // own error class — surfaced regardless of manager state.
    let outcome = mgr
        .call_tool("not_an_mcp_tool", serde_json::json!({}))
        .await;
    assert!(outcome.is_err());
}

#[tokio::test]
async fn call_tool_with_missing_server_separator_yields_error() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    // Missing the `__` between server name and tool name.
    let outcome = mgr
        .call_tool("mcp__justonename", serde_json::json!({}))
        .await;
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — read_resource on empty
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn read_resource_on_empty_manager_errors() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let outcome = mgr.read_resource("missing-server", "file:///x").await;
    assert!(
        outcome.is_err(),
        "read_resource MUST error when server unknown"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Explicit capability binding
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn manager_is_bound_to_one_exact_run_generation() {
    let first = std::sync::Arc::clone(support::shared_run_context());
    let second = support::test_run_context(std::path::Path::new(env!("CARGO_MANIFEST_DIR")));
    let mgr = McpManager::new(std::sync::Arc::clone(&first));
    assert!(mgr.matches_run(&first));
    assert!(!mgr.matches_run(&second));
}

mod support;

// ───────────────────────────────────────────────────────────────────────────
// Section G — Cross-method consistency on empty
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn empty_manager_passes_all_documented_zero_predicates() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    assert_eq!(mgr.server_count().await, 0);
    assert!(!mgr.is_connected("any").await);
    assert!(mgr.get_server_info("any").await.is_none());
    let resources = mgr.list_resources(None).await.expect("ok");
    assert!(resources.is_empty());
}

#[tokio::test]
async fn empty_manager_after_disconnect_all_still_passes_zero_predicates() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let _ = mgr.disconnect_all().await;
    // All zero-state invariants preserved.
    assert_eq!(mgr.server_count().await, 0);
    assert!(!mgr.is_connected("any").await);
    assert!(mgr.get_server_info("any").await.is_none());
}

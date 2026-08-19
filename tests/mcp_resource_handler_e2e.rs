//! End-to-end tests for `list_mcp_resources` and
//! `read_mcp_resource` registry dispatch.
//!
//! These tools are no longer documented stubs: the proxy/TUI startup path
//! installs a process-wide MCP manager and the registry handlers dispatch
//! into it. This file pins the dispatch-layer contract that can be tested
//! without starting an external MCP server: schema publication, argument
//! validation, no-manager diagnostics, and read-only classification.
//!
//! Sprint 155 of the verification effort. Sprint 123
//! covered the underlying `McpResource` / `McpCapabilities`
//! wire shapes; this file pins the tool-dispatch-layer
//! contract distinct from the underlying MCP types.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::effect::ToolEffect;
use openclaudia::tools::registry::{registry, ToolContext};
use serde_json::{json, Value};
use std::collections::HashMap;

fn dispatch(name: &str, args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch(name, args, &mut ctx)
        .expect("tool must be registered")
        .into_legacy()
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — list_mcp_resources: no-manager diagnostics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn list_mcp_resources_no_args_reports_missing_registered_manager() {
    let (msg, is_err) = dispatch("list_mcp_resources", &HashMap::new());
    assert!(
        is_err,
        "without a registered MCP manager the handler must error"
    );
    assert!(
        msg.contains("No MCP manager has been installed for this session"),
        "must explain that no manager is registered; got {msg:?}"
    );
    assert!(
        msg.contains("mcp.servers") && msg.contains(".openclaudia/config.yaml"),
        "must point users at MCP configuration; got {msg:?}"
    );
}

#[test]
fn list_mcp_resources_with_server_arg_reports_missing_registered_manager() {
    let args = args_with(&[("server", json!("any-server-name"))]);
    let (msg, is_err) = dispatch("list_mcp_resources", &args);
    assert!(is_err);
    assert!(msg.contains("No MCP manager has been installed for this session"));
}

#[test]
fn list_mcp_resources_rejects_non_string_server_before_manager_lookup() {
    let args = args_with(&[("server", json!(42))]);
    let (msg, is_err) = dispatch("list_mcp_resources", &args);
    assert!(is_err);
    assert!(
        msg.contains("list_mcp_resources: Invalid 'server' argument: expected string"),
        "server type error should be explicit and precede manager lookup; got {msg:?}"
    );
    assert!(
        !msg.contains("No MCP manager has been installed"),
        "wrong-type server must not fall through to manager lookup; got {msg:?}"
    );
}

#[test]
fn list_mcp_resources_with_arbitrary_args_reports_error_no_panic() {
    let args = args_with(&[
        ("server", json!("x")),
        ("extra", json!({"k": "v"})),
        ("count", json!(42)),
    ]);
    let (msg, is_err) = dispatch("list_mcp_resources", &args);
    assert!(is_err);
    assert!(msg.contains("No MCP manager has been installed for this session"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — read_mcp_resource: argument validation and no-manager diagnostics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn read_mcp_resource_no_args_reports_missing_server_before_manager_lookup() {
    let (msg, is_err) = dispatch("read_mcp_resource", &HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("read_mcp_resource: missing required argument `server`"),
        "must validate required server arg before manager lookup; got {msg:?}"
    );
}

#[test]
fn read_mcp_resource_with_server_but_no_uri_reports_missing_uri() {
    let args = args_with(&[("server", json!("test-server"))]);
    let (msg, is_err) = dispatch("read_mcp_resource", &args);
    assert!(is_err);
    assert!(
        msg.contains("read_mcp_resource: missing required argument `uri`"),
        "must validate required uri arg before manager lookup; got {msg:?}"
    );
}

#[test]
fn read_mcp_resource_rejects_non_string_server_before_uri_lookup() {
    let args = args_with(&[("server", json!(false)), ("uri", json!("file:///example"))]);
    let (msg, is_err) = dispatch("read_mcp_resource", &args);
    assert!(is_err);
    assert!(
        msg.contains("read_mcp_resource: Invalid 'server' argument: expected string"),
        "server type error should be explicit; got {msg:?}"
    );
}

#[test]
fn read_mcp_resource_rejects_non_string_uri_before_manager_lookup() {
    let args = args_with(&[("server", json!("test-server")), ("uri", json!(["bad"]))]);
    let (msg, is_err) = dispatch("read_mcp_resource", &args);
    assert!(is_err);
    assert!(
        msg.contains("read_mcp_resource: Invalid 'uri' argument: expected string"),
        "uri type error should be explicit and precede manager lookup; got {msg:?}"
    );
    assert!(
        !msg.contains("No MCP manager has been installed"),
        "wrong-type uri must not fall through to manager lookup; got {msg:?}"
    );
}

#[test]
fn read_mcp_resource_with_server_and_uri_without_manager_reports_configuration_error() {
    let args = args_with(&[
        ("server", json!("test-server")),
        ("uri", json!("file:///example")),
    ]);
    let (msg, is_err) = dispatch("read_mcp_resource", &args);
    assert!(is_err);
    assert!(msg.contains("No MCP manager has been installed for this session"));
}

#[test]
fn read_mcp_resource_with_arbitrary_args_no_panic() {
    let args = args_with(&[
        ("server", json!("x")),
        ("uri", json!("y")),
        ("extra", json!([1, 2, 3])),
    ]);
    let (msg, is_err) = dispatch("read_mcp_resource", &args);
    assert!(is_err);
    assert!(msg.contains("No MCP manager has been installed for this session"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Schema is still published despite stub dispatch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn list_mcp_resources_definition_includes_optional_server_arg() {
    let handler = registry().get("list_mcp_resources").expect("registered");
    let def = handler.definition();
    let server_prop = &def["function"]["parameters"]["properties"]["server"];
    assert_eq!(server_prop["type"], "string");
    // server is OPTIONAL.
    let required = def["function"]["parameters"]["required"]
        .as_array()
        .expect("required array");
    assert!(
        required.is_empty(),
        "list_mcp_resources MUST have no required fields"
    );
}

#[test]
fn read_mcp_resource_definition_requires_server_and_uri() {
    let handler = registry().get("read_mcp_resource").expect("registered");
    let def = handler.definition();
    let required = def["function"]["parameters"]["required"]
        .as_array()
        .expect("required array");
    let names: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
    // PINS DOC: both server + uri required.
    assert!(names.contains(&"server"));
    assert!(names.contains(&"uri"));
}

#[test]
fn read_mcp_resource_uri_field_is_string() {
    let handler = registry().get("read_mcp_resource").expect("registered");
    let def = handler.definition();
    let uri_prop = &def["function"]["parameters"]["properties"]["uri"];
    assert_eq!(uri_prop["type"], "string");
}

#[test]
fn list_mcp_resources_schema_description_mentions_mcp_servers() {
    let handler = registry().get("list_mcp_resources").expect("registered");
    let def = handler.definition();
    let desc = def["function"]["description"].as_str().expect("string");
    assert!(
        desc.contains("MCP server") || desc.contains("MCP servers"),
        "MUST surface MCP context in description; got {desc:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Current dispatch diagnostics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn mcp_resource_tool_diagnostics_no_longer_claim_unimplemented_stub() {
    let (l_msg, _) = dispatch("list_mcp_resources", &HashMap::new());
    let read_args = args_with(&[
        ("server", json!("test-server")),
        ("uri", json!("file:///example")),
    ]);
    let (r_msg, _) = dispatch("read_mcp_resource", &read_args);

    for msg in [l_msg, r_msg] {
        assert!(
            !msg.contains("not wired into the tool dispatch system yet"),
            "MCP resource handlers are wired now; stale stub message: {msg:?}"
        );
        assert!(
            !msg.contains("schema is published"),
            "schema-only diagnostic is stale now that dispatch is wired: {msg:?}"
        );
    }
}

#[test]
fn read_mcp_resource_argument_errors_name_the_offending_tool() {
    let (r_msg, _) = dispatch("read_mcp_resource", &HashMap::new());
    assert!(r_msg.starts_with("read_mcp_resource"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Registration
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn both_mcp_resource_tools_registered_in_registry() {
    assert!(registry().get("list_mcp_resources").is_some());
    assert!(registry().get("read_mcp_resource").is_some());
}

#[test]
fn both_mcp_resource_handlers_require_authorization() {
    // S-016 reclassification. These tools were pinned as "read-only (no perm
    // target)", but reading an MCP resource contacts a third-party server the
    // host does not own and returns untrusted bytes. McpManager may also
    // reconnect/spawn the long-lived service or mark it disconnected, so the
    // honest ceiling is ExternalMutation. The previous pin asserted the
    // absence of a declaration, which is indistinguishable from never having
    // classified the tool at all (F-001).
    for name in ["list_mcp_resources", "read_mcp_resource"] {
        let spec = registry().get(name).expect("registered").effect_spec();
        assert_eq!(spec.effect, ToolEffect::ExternalMutation, "{name}");
        assert!(spec.effect.requires_authorization());
        assert_eq!(spec.canonical, "McpRead");
    }
}

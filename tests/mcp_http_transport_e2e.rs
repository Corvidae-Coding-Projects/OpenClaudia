//! End-to-end tests for the MCP `HttpTransport` JSON-RPC wire
//! protocol against a real wiremock loopback server.
//!
//! Sprint 45 of the verification effort.
//!
//! `tests/mcp_integration.rs` covers protocol behaviour against
//! a Python echo-server fixture (handshake, tool refresh,
//! `call_tool` error projection). `tests/remote_trigger_mcp_e2e.rs`
//! (sprint 7) covers the SSRF guard at construction time. This
//! file fills the remaining gap: actual HTTP-level JSON-RPC
//! roundtrips through `__test_connect_http_unchecked` — the
//! initialize handshake, the tools/list discovery, and the
//! `call_tool` dispatch all driven against scripted wiremock
//! responses.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::mcp::McpManager;
use serde_json::{json, Value};
use std::collections::HashMap;
use wiremock::matchers::{body_string_contains, header, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn manager_with_allowed_tool(server: &str, tool: &str) -> McpManager {
    let mut permissions = openclaudia::config::PermissionsConfig::default();
    permissions
        .mcp
        .insert(server.to_string(), vec![tool.to_string()]);
    McpManager::new_with_permissions(
        std::sync::Arc::clone(support::shared_run_context()),
        permissions,
    )
}

// ───────────────────────────────────────────────────────────────────────────
// Helpers — JSON-RPC envelope builders
// ───────────────────────────────────────────────────────────────────────────

/// Custom wiremock responder that echoes the JSON-RPC `id` field
/// from the request so `HttpTransport::request` doesn't fail with
/// `ResponseIdMismatch`. The `result_body` template is merged into
/// the response envelope alongside the echoed id.
struct EchoIdResponder {
    /// Body to embed under `result`. `None` means "produce the
    /// `error` envelope from `error_body`".
    result_body: Option<Value>,
    /// Body to embed under `error`. Only one of `result_body` /
    /// `error_body` should be Some at a time.
    error_body: Option<Value>,
}

struct SseEchoIdResponder {
    result_body: Value,
}

struct SessionEchoIdResponder {
    result_body: Value,
    session_id: &'static str,
}

impl Respond for EchoIdResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        // Parse the request body as JSON to extract the id.
        // Notifications (no id) get id=null.
        let body_json: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let id = body_json.get("id").cloned().unwrap_or(Value::Null);

        let mut envelope = serde_json::Map::new();
        envelope.insert("jsonrpc".to_string(), Value::String("2.0".to_string()));
        envelope.insert("id".to_string(), id);
        if let Some(result) = &self.result_body {
            envelope.insert("result".to_string(), result.clone());
        }
        if let Some(error) = &self.error_body {
            envelope.insert("error".to_string(), error.clone());
        }
        ResponseTemplate::new(200).set_body_json(Value::Object(envelope))
    }
}

impl Respond for SseEchoIdResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body_json: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let id = body_json.get("id").cloned().unwrap_or(Value::Null);

        let progress = json!({
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": "tool-call",
                "progress": 0.5
            }
        });

        let mut envelope = serde_json::Map::new();
        envelope.insert("jsonrpc".to_string(), Value::String("2.0".to_string()));
        envelope.insert("id".to_string(), id);
        envelope.insert("result".to_string(), self.result_body.clone());

        let body = format!(
            "event: message\ndata: {}\n\nevent: message\ndata: {}\n\n",
            serde_json::to_string(&progress).expect("progress JSON"),
            serde_json::to_string(&Value::Object(envelope)).expect("response JSON")
        );

        ResponseTemplate::new(200)
            .set_body_string(body)
            .insert_header("content-type", "text/event-stream; charset=utf-8")
    }
}

impl Respond for SessionEchoIdResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        EchoIdResponder {
            result_body: Some(self.result_body.clone()),
            error_body: None,
        }
        .respond(request)
        .insert_header("Mcp-Session-Id", self.session_id)
    }
}

fn init_result_body() -> Value {
    json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": { "listChanged": true }
        },
        "serverInfo": {
            "name": "test-mcp-server",
            "version": "1.0.0"
        }
    })
}

fn tools_list_result_body() -> Value {
    json!({
        "tools": [
            {
                "name": "echo",
                "description": "Echo back the input text.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": {"type": "string"}
                    },
                    "required": ["text"]
                }
            },
            {
                "name": "add",
                "description": "Add two integers.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "integer"},
                        "b": {"type": "integer"}
                    }
                }
            }
        ]
    })
}

fn current_discover_result_body() -> Value {
    json!({
        "resultType": "complete",
        "supportedVersions": ["2026-07-28"],
        "capabilities": {"tools": {"listChanged": false}},
        "ttlMs": 0,
        "cacheScope": "private",
        "_meta": {
            "io.modelcontextprotocol/serverInfo": {
                "name": "current-http-fixture",
                "version": "1.0.0"
            }
        }
    })
}

fn current_tools_list_result_body() -> Value {
    json!({
        "resultType": "complete",
        "ttlMs": 0,
        "cacheScope": "private",
        "tools": [{
            "name": "echo",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "trace": {"type": "string", "x-mcp-header": "Trace-Id"}
                },
                "required": ["trace"]
            }
        }]
    })
}

fn call_tool_success_result(text: &str) -> Value {
    json!({
        "content": [
            {"type": "text", "text": text}
        ]
    })
}

fn call_tool_error_body(code: i64, message: &str) -> Value {
    json!({
        "code": code,
        "message": message
    })
}

const fn echo_result(result: Value) -> EchoIdResponder {
    EchoIdResponder {
        result_body: Some(result),
        error_body: None,
    }
}

const fn echo_error(error: Value) -> EchoIdResponder {
    EchoIdResponder {
        result_body: None,
        error_body: Some(error),
    }
}

const fn sse_echo_result(result: Value) -> SseEchoIdResponder {
    SseEchoIdResponder {
        result_body: result,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — full handshake + tools/list roundtrip
// ───────────────────────────────────────────────────────────────────────────

/// Mount mocks for the standard connect handshake — body-
/// matched on the JSON-RPC method name so wiremock dispatches
/// the right response regardless of mount order. Also mounts
/// a default-OK responder for `notifications/initialized` so
/// the post-handshake notification doesn't 404 (which would
/// still succeed because the transport ignores its response,
/// but cleaner this way).
async fn mount_handshake(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"initialize\""))
        .respond_with(echo_result(init_result_body()))
        .mount(mock)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains(
            "\"method\":\"notifications/initialized\"",
        ))
        .respond_with(echo_result(json!({})))
        .mount(mock)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"tools/list\""))
        .respond_with(echo_result(tools_list_result_body()))
        .mount(mock)
        .await;
}

#[tokio::test]
async fn handshake_and_tools_list_round_trip_against_wiremock() {
    let mock = MockServer::start().await;
    mount_handshake(&mock).await;

    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    mgr.__test_connect_http_unchecked("test-server", &mock.uri())
        .await
        .expect("connect must succeed");

    // After connect: the server's tool list MUST include
    // echo + add.
    let (registered_name, _) = mgr
        .get_server_info("test-server")
        .await
        .expect("server registered");
    // get_server_info returns the NAME we registered the server
    // under (not the remote serverInfo.name). Pin that contract.
    assert_eq!(registered_name, "test-server");
}

#[tokio::test]
async fn legacy_http_json_rpc_method_not_found_at_200_enters_initialize_adapter() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"server/discover\""))
        .respond_with(echo_error(json!({
            "code": -32601,
            "message": "Method not found"
        })))
        .mount(&mock)
        .await;
    mount_handshake(&mock).await;

    let manager = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    manager
        .__test_connect_http_unchecked("legacy-200", &mock.uri())
        .await
        .expect("HTTP 200 method-not-found must select the legacy initialize adapter");
    assert!(manager.is_connected("legacy-200").await);
}

#[tokio::test]
async fn s065_current_http_round_trip_sends_required_routing_headers() {
    let mock = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("MCP-Protocol-Version", "2026-07-28"))
        .and(header("Mcp-Method", "server/discover"))
        .and(body_string_contains(
            "io.modelcontextprotocol/protocolVersion",
        ))
        .and(body_string_contains(
            "io.modelcontextprotocol/clientCapabilities",
        ))
        .respond_with(echo_result(current_discover_result_body()))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(header("MCP-Protocol-Version", "2026-07-28"))
        .and(header("Mcp-Method", "tools/list"))
        .and(body_string_contains("progressToken"))
        .respond_with(echo_result(current_tools_list_result_body()))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(header("MCP-Protocol-Version", "2026-07-28"))
        .and(header("Mcp-Method", "tools/call"))
        .and(header("Mcp-Name", "echo"))
        .and(header("Mcp-Param-Trace-Id", "trace-value"))
        .respond_with(echo_result(json!({
            "resultType": "complete",
            "content": [{"type": "text", "text": "CURRENT"}],
            "structuredContent": {"ok": true}
        })))
        .mount(&mock)
        .await;

    let manager = manager_with_allowed_tool("current", "echo");
    manager
        .__test_connect_http_unchecked("current", &mock.uri())
        .await
        .expect("current HTTP discovery");
    let result = manager
        .call_tool("mcp__current__echo", json!({"trace": "trace-value"}))
        .await
        .expect("current HTTP tool call");
    assert_eq!(result["content"][0]["text"], "CURRENT");
    assert_eq!(result["structuredContent"]["ok"], true);
}

#[tokio::test]
async fn http_connect_sends_static_headers_on_handshake_requests() {
    let mock = MockServer::start().await;

    for method_name in ["initialize", "notifications/initialized", "tools/list"] {
        let responder = if method_name == "tools/list" {
            echo_result(tools_list_result_body())
        } else if method_name == "initialize" {
            echo_result(init_result_body())
        } else {
            echo_result(json!({}))
        };
        Mock::given(method("POST"))
            .and(header("Authorization", "Bearer test-token"))
            .and(header("X-Mcp-Team", "openclaudia"))
            .and(body_string_contains(format!(
                "\"method\":\"{method_name}\""
            )))
            .respond_with(responder)
            .mount(&mock)
            .await;
    }

    let headers = HashMap::from([
        ("Authorization".to_string(), "Bearer test-token".to_string()),
        ("X-Mcp-Team".to_string(), "openclaudia".to_string()),
    ]);
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    mgr.__test_connect_http_unchecked_with_headers("hdr", &mock.uri(), &headers)
        .await
        .expect("connect with headers");

    assert!(mgr.is_live("hdr").await);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — call_tool happy path
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn call_tool_returns_server_result_through_transport() {
    let mock = MockServer::start().await;
    mount_handshake(&mock).await;
    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"tools/call\""))
        .respond_with(echo_result(call_tool_success_result("HELLO")))
        .mount(&mock)
        .await;

    let mgr = manager_with_allowed_tool("srv", "echo");
    mgr.__test_connect_http_unchecked("srv", &mock.uri())
        .await
        .expect("connect");

    // call_tool dispatch through manager — full name is
    // `<server>__<tool>`.
    let result = mgr
        .call_tool("mcp__srv__echo", json!({"text": "hi"}))
        .await
        .expect("call_tool must succeed");
    // The result is the bare JSON-RPC `result.content` payload.
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .expect("content array");
    assert_eq!(content.len(), 1);
    assert_eq!(content[0]["text"], "HELLO");
}

#[tokio::test]
async fn call_tool_accepts_streamable_http_sse_response_body() {
    let mock = MockServer::start().await;
    mount_handshake(&mock).await;
    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"tools/call\""))
        .respond_with(sse_echo_result(call_tool_success_result("STREAMED")))
        .mount(&mock)
        .await;

    let mgr = manager_with_allowed_tool("srv", "echo");
    mgr.__test_connect_http_unchecked("srv", &mock.uri())
        .await
        .expect("connect");

    let result = mgr
        .call_tool("mcp__srv__echo", json!({"text": "hi"}))
        .await
        .expect("SSE JSON-RPC response must parse");
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .expect("content array");
    assert_eq!(content[0]["text"], "STREAMED");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — call_tool error projection
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn call_tool_propagates_jsonrpc_error_response() {
    let mock = MockServer::start().await;
    mount_handshake(&mock).await;
    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"tools/call\""))
        .respond_with(echo_error(call_tool_error_body(
            -32000,
            "tool execution failed",
        )))
        .mount(&mock)
        .await;

    let mgr = manager_with_allowed_tool("srv", "echo");
    mgr.__test_connect_http_unchecked("srv", &mock.uri())
        .await
        .expect("connect");

    let outcome = mgr.call_tool("mcp__srv__echo", json!({"text": "x"})).await;
    let err = outcome.expect_err("JSON-RPC error MUST propagate as McpError");
    let msg = format!("{err}");
    assert!(
        msg.contains("tool execution failed") || msg.contains("-32000"),
        "error message MUST carry server-provided diagnostic; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — call_tool with unknown tool name
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn call_tool_with_unknown_tool_name_returns_error_without_http_call() {
    let mock = MockServer::start().await;
    mount_handshake(&mock).await;
    // No mock for tools/call — if the manager tries to hit
    // the wire, wiremock will refuse + the test would
    // fail with a transport error rather than the
    // "tool not found" error we expect.

    let mgr = manager_with_allowed_tool("srv", "definitely-not-a-tool");
    mgr.__test_connect_http_unchecked("srv", &mock.uri())
        .await
        .expect("connect");

    let outcome = mgr
        .call_tool("mcp__srv__definitely-not-a-tool", json!({}))
        .await;
    let err = outcome.expect_err("unknown tool MUST error");
    let msg = format!("{err}");
    assert!(
        msg.to_lowercase().contains("not found")
            || msg.to_lowercase().contains("unknown")
            || msg.contains("definitely-not-a-tool"),
        "error must indicate the unknown tool; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — call_tool with unknown server name
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn call_tool_with_unknown_server_returns_error() {
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let outcome = mgr
        .call_tool("mcp__nonexistent-server__tool", json!({}))
        .await;
    let err = outcome.expect_err("unknown server MUST error");
    let msg = format!("{err}");
    assert!(
        msg.contains("nonexistent-server") || msg.to_lowercase().contains("not found"),
        "error must mention the missing server; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — disconnect drops the server entry
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn disconnect_removes_server_from_manager() {
    let mock = MockServer::start().await;
    mount_handshake(&mock).await;

    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    mgr.__test_connect_http_unchecked("srv", &mock.uri())
        .await
        .expect("connect");
    assert!(mgr.get_server_info("srv").await.is_some());

    mgr.disconnect("srv").await.expect("disconnect");
    assert!(
        mgr.get_server_info("srv").await.is_none(),
        "disconnect MUST drop the server entry"
    );
}

#[tokio::test]
async fn disconnect_terminates_an_owned_legacy_http_session() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"server/discover\""))
        .respond_with(echo_error(json!({
            "code": -32601,
            "message": "Method not found"
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"initialize\""))
        .respond_with(SessionEchoIdResponder {
            result_body: init_result_body(),
            session_id: "owned-session",
        })
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains(
            "\"method\":\"notifications/initialized\"",
        ))
        .and(header("Mcp-Session-Id", "owned-session"))
        .respond_with(echo_result(json!({})))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("\"method\":\"tools/list\""))
        .and(header("Mcp-Session-Id", "owned-session"))
        .respond_with(echo_result(tools_list_result_body()))
        .mount(&mock)
        .await;
    Mock::given(method("DELETE"))
        .and(header("Mcp-Session-Id", "owned-session"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock)
        .await;

    let manager = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    manager
        .__test_connect_http_unchecked("session", &mock.uri())
        .await
        .expect("session server connects");
    manager
        .disconnect("session")
        .await
        .expect("disconnect terminates the session");
    mock.verify().await;
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — HTTP error response causes McpError
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn http_5xx_during_initialize_propagates_as_mcp_error() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
        .mount(&mock)
        .await;

    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let outcome = mgr.__test_connect_http_unchecked("srv", &mock.uri()).await;
    assert!(
        outcome.is_err(),
        "HTTP 500 during initialize MUST surface as McpError"
    );
}

#[tokio::test]
async fn http_404_during_initialize_propagates_as_mcp_error() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let outcome = mgr.__test_connect_http_unchecked("srv", &mock.uri()).await;
    assert!(outcome.is_err(), "HTTP 404 MUST surface as McpError");
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — non-JSON body during handshake errors
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn non_json_response_body_during_handshake_errors() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
        .mount(&mock)
        .await;
    let mgr = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let outcome = mgr.__test_connect_http_unchecked("srv", &mock.uri()).await;
    assert!(
        outcome.is_err(),
        "non-JSON body MUST error (not silently parse to default)"
    );
}
mod support;

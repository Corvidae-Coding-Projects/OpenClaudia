//! End-to-end tests for `mcp_inprocess::InProcessTransport`
//! adapter + `McpServerCallable` trait dispatch + multi-call
//! semantics + object-safety against `dyn McpTransport`.
//!
//! Sprint 79 of the verification effort. The internal unit tests
//! cover the basic forward + error path; this file pins the
//! shared-Arc semantics (caller can keep their own handle), the
//! concurrent-call ordering, the `McpError` variant pass-through
//! matrix, and owned shutdown semantics.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use openclaudia::mcp::{McpError, McpTransport};
use openclaudia::mcp_inprocess::{InProcessTransport, McpServerCallable};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ───────────────────────────────────────────────────────────────────────────
// Test infrastructure
// ───────────────────────────────────────────────────────────────────────────

/// Counter-keeping server that echoes its call count + the input
/// method + params back as JSON. Lets tests assert call counts
/// directly via shared Arc.
struct CountingEchoServer {
    calls: AtomicUsize,
}

impl CountingEchoServer {
    const fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl McpServerCallable for CountingEchoServer {
    async fn call(&self, method: &str, params: Option<Value>) -> Result<Value, McpError> {
        let prev = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({
            "method": method,
            "params": params,
            "call_index": prev,
        }))
    }
}

/// Server that returns a configurable `McpError` variant — pins
/// the verbatim-passthrough contract for every variant.
struct ErrorServer {
    err_kind: &'static str,
}

#[async_trait]
impl McpServerCallable for ErrorServer {
    async fn call(&self, _method: &str, _params: Option<Value>) -> Result<Value, McpError> {
        match self.err_kind {
            "transport" => Err(McpError::Transport("conn reset".into())),
            "protocol" => Err(McpError::Protocol("bad version".into())),
            "tool_not_found" => Err(McpError::ToolNotFound("ghost".into())),
            "not_connected" => Err(McpError::NotConnected("server-a".into())),
            "unreachable" => Err(McpError::ServerUnreachable("server-b".into())),
            _ => Ok(json!({})),
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Basic request forwarding
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn transport_forwards_method_name_to_callable() {
    let server = Arc::new(CountingEchoServer::new());
    let transport = InProcessTransport::new(server.clone());
    let resp = transport.request("tools/list", None).await.expect("ok");
    assert_eq!(resp["method"], "tools/list");
}

#[tokio::test]
async fn transport_forwards_params_byte_exact() {
    let server = Arc::new(CountingEchoServer::new());
    let transport = InProcessTransport::new(server);
    let params = json!({"nested": {"k": [1, 2, 3], "s": "value"}});
    let resp = transport
        .request("tools/call", Some(params.clone()))
        .await
        .expect("ok");
    assert_eq!(resp["params"], params);
}

#[tokio::test]
async fn transport_forwards_none_params_as_none() {
    let server = Arc::new(CountingEchoServer::new());
    let transport = InProcessTransport::new(server);
    let resp = transport.request("ping", None).await.expect("ok");
    // None serializes to JSON null in our echo; the params
    // field exists but is Value::Null.
    assert!(resp["params"].is_null());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Multi-call call-count tracking via shared Arc
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn caller_can_inspect_call_count_via_shared_arc_after_each_request() {
    let server = Arc::new(CountingEchoServer::new());
    let transport = InProcessTransport::new(server.clone());
    assert_eq!(server.count(), 0);

    transport.request("a", None).await.expect("call 1");
    assert_eq!(server.count(), 1);

    transport.request("b", None).await.expect("call 2");
    assert_eq!(server.count(), 2);

    transport.request("c", None).await.expect("call 3");
    assert_eq!(server.count(), 3);
}

#[tokio::test]
async fn call_index_increments_monotonically_in_response() {
    let server = Arc::new(CountingEchoServer::new());
    let transport = InProcessTransport::new(server);

    let r1 = transport.request("a", None).await.unwrap();
    let r2 = transport.request("b", None).await.unwrap();
    let r3 = transport.request("c", None).await.unwrap();
    assert_eq!(r1["call_index"], 0);
    assert_eq!(r2["call_index"], 1);
    assert_eq!(r3["call_index"], 2);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Concurrent calls
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn concurrent_calls_increment_counter_atomically() {
    let server = Arc::new(CountingEchoServer::new());
    let transport = Arc::new(InProcessTransport::new(server.clone()));

    let mut handles = Vec::new();
    for i in 0..50 {
        let t = transport.clone();
        let h = tokio::spawn(async move {
            let _ = t.request(&format!("method-{i}"), None).await;
        });
        handles.push(h);
    }
    for h in handles {
        h.await.expect("join");
    }
    assert_eq!(
        server.count(),
        50,
        "50 concurrent calls MUST each increment the counter (atomic)"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — McpError verbatim passthrough
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn transport_passes_through_transport_error_verbatim() {
    let server = Arc::new(ErrorServer {
        err_kind: "transport",
    });
    let transport = InProcessTransport::new(server);
    let err = transport.request("x", None).await.unwrap_err();
    assert!(
        matches!(err, McpError::Transport(ref m) if m == "conn reset"),
        "MUST passthrough Transport variant; got {err:?}"
    );
}

#[tokio::test]
async fn transport_passes_through_protocol_error_verbatim() {
    let server = Arc::new(ErrorServer {
        err_kind: "protocol",
    });
    let transport = InProcessTransport::new(server);
    let err = transport.request("x", None).await.unwrap_err();
    assert!(matches!(err, McpError::Protocol(ref m) if m == "bad version"));
}

#[tokio::test]
async fn transport_passes_through_tool_not_found_verbatim() {
    let server = Arc::new(ErrorServer {
        err_kind: "tool_not_found",
    });
    let transport = InProcessTransport::new(server);
    let err = transport.request("x", None).await.unwrap_err();
    assert!(matches!(err, McpError::ToolNotFound(ref m) if m == "ghost"));
}

#[tokio::test]
async fn transport_passes_through_not_connected_verbatim() {
    let server = Arc::new(ErrorServer {
        err_kind: "not_connected",
    });
    let transport = InProcessTransport::new(server);
    let err = transport.request("x", None).await.unwrap_err();
    assert!(matches!(err, McpError::NotConnected(ref m) if m == "server-a"));
}

#[tokio::test]
async fn transport_passes_through_server_unreachable_verbatim() {
    let server = Arc::new(ErrorServer {
        err_kind: "unreachable",
    });
    let transport = InProcessTransport::new(server);
    let err = transport.request("x", None).await.unwrap_err();
    assert!(matches!(err, McpError::ServerUnreachable(ref m) if m == "server-b"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — close semantics
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn close_returns_ok_without_counting_a_request() {
    let server = Arc::new(CountingEchoServer::new());
    let transport = InProcessTransport::new(server.clone());
    transport.close().await.expect("close");
    // Lifecycle shutdown is not an MCP request.
    assert_eq!(server.count(), 0);
}

#[tokio::test]
async fn close_then_request_is_rejected_by_lifecycle_owner() {
    let server = Arc::new(CountingEchoServer::new());
    let transport = InProcessTransport::new(server.clone());
    transport.close().await.expect("close");
    let error = transport
        .request("post-close", None)
        .await
        .expect_err("closed transports must reject new work");
    assert!(matches!(error, McpError::ConnectionClosed(_)));
    assert_eq!(server.count(), 0);
}

#[tokio::test]
async fn multiple_close_calls_are_idempotent() {
    let server = Arc::new(CountingEchoServer::new());
    let transport = InProcessTransport::new(server);
    transport.close().await.expect("close 1");
    transport.close().await.expect("close 2");
    transport.close().await.expect("close 3");
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Object safety / Box<dyn McpTransport>
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn transport_is_usable_behind_box_dyn_mcp_transport() {
    let server = Arc::new(CountingEchoServer::new());
    let boxed: Box<dyn McpTransport> = Box::new(InProcessTransport::new(server.clone()));
    boxed.request("via-box", None).await.expect("ok");
    boxed.close().await.expect("close");
    assert_eq!(server.count(), 1);
}

#[tokio::test]
async fn transport_dropped_does_not_invalidate_caller_held_arc() {
    let server = Arc::new(CountingEchoServer::new());
    {
        let transport = InProcessTransport::new(server.clone());
        transport.request("inside-scope", None).await.unwrap();
    } // transport dropped here
      // Caller's Arc to server is still valid.
    assert_eq!(server.count(), 1);
}

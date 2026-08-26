//! Lifecycle-owned in-process MCP transport.
//!
//! In-process servers use the same manager actor, tool policy, generation
//! checks, deadlines, backpressure, and shutdown path as external servers.
//! The callable receives a deliberately narrow request context rather than a
//! [`crate::tools::ToolRunContext`], so registration does not hand arbitrary
//! host filesystem, process, network, or secret authority to server code.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::mcp::{McpError, McpTransport, McpTransportBinding};

/// Identity and lifecycle data visible to an in-process callable.
#[derive(Clone)]
pub struct McpInProcessRequestContext {
    server_name: String,
    operation_id: String,
    run_id: Option<String>,
    session_id: Option<String>,
    run_generation: Option<u64>,
    cancellation: crate::runtime::CancellationHandle,
}

impl std::fmt::Debug for McpInProcessRequestContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpInProcessRequestContext")
            .field("server_name", &self.server_name)
            .field("operation_id", &self.operation_id)
            .field("run_id", &self.run_id)
            .field("session_id", &self.session_id)
            .field("run_generation", &self.run_generation)
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish()
    }
}

impl McpInProcessRequestContext {
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn run_id(&self) -> Option<&str> {
        self.run_id.as_deref()
    }

    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    #[must_use]
    pub const fn run_generation(&self) -> Option<u64> {
        self.run_generation
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Child cancellation handle for work owned only by this one request.
    #[must_use]
    pub fn cancellation(&self) -> crate::runtime::CancellationHandle {
        self.cancellation.clone()
    }
}

/// Trait implemented by an in-process MCP server.
#[async_trait]
pub trait McpServerCallable: Send + Sync {
    /// Compatibility entry point retained for existing embedders.
    async fn call(&self, method: &str, params: Option<Value>) -> Result<Value, McpError>;

    /// Contextual entry point used by manager-owned transports. Implementors
    /// that need attribution or cancellation should override this method.
    async fn call_with_context(
        &self,
        context: McpInProcessRequestContext,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, McpError> {
        let _ = context;
        self.call(method, params).await
    }

    /// Bounded lifecycle callback invoked exactly once when the transport is
    /// closed. The default is suitable for stateless callables.
    async fn shutdown(&self) -> Result<(), McpError> {
        Ok(())
    }
}

#[derive(Clone)]
struct BoundRun {
    run_id: String,
    session_id: String,
    run_generation: u64,
    budget: crate::runtime::RunBudgetAuthority,
}

/// `McpTransport` adapter for an in-process server.
pub struct InProcessTransport {
    server_name: String,
    server: Arc<dyn McpServerCallable>,
    bound_run: Option<BoundRun>,
    cancellation: crate::runtime::CancellationHandle,
    closed: AtomicBool,
}

impl std::fmt::Debug for InProcessTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InProcessTransport")
            .field("server_name", &self.server_name)
            .field("bound", &self.bound_run.is_some())
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl InProcessTransport {
    /// Compatibility constructor for direct library tests and embedders. This
    /// path carries no run identity or budget authority. Production manager
    /// registration uses [`Self::new_bound`].
    #[must_use]
    pub fn new(server: Arc<dyn McpServerCallable>) -> Self {
        let tree = crate::runtime::CancellationTree::new();
        Self {
            server_name: "detached-in-process".to_string(),
            server,
            bound_run: None,
            cancellation: tree.root(),
            closed: AtomicBool::new(false),
        }
    }

    /// Construct a manager-owned transport bound to one exact run generation.
    #[must_use]
    pub fn new_bound(
        server_name: impl Into<String>,
        run: &Arc<crate::tools::ToolRunContext>,
        server: Arc<dyn McpServerCallable>,
    ) -> Self {
        Self {
            server_name: server_name.into(),
            server,
            bound_run: Some(BoundRun {
                run_id: run.run_id().to_string(),
                session_id: run.session_id().to_string(),
                run_generation: run.generation().get(),
                budget: run.budget().clone(),
            }),
            cancellation: run.runtime().cancellation().child(),
            closed: AtomicBool::new(false),
        }
    }

    fn request_context(&self) -> McpInProcessRequestContext {
        let (run_id, session_id, run_generation) =
            self.bound_run.as_ref().map_or((None, None, None), |bound| {
                (
                    Some(bound.run_id.clone()),
                    Some(bound.session_id.clone()),
                    Some(bound.run_generation),
                )
            });
        McpInProcessRequestContext {
            server_name: self.server_name.clone(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            run_id,
            session_id,
            run_generation,
            cancellation: self.cancellation.child(),
        }
    }
}

#[async_trait]
impl McpTransport for InProcessTransport {
    fn binding(&self) -> McpTransportBinding {
        McpTransportBinding::InProcess
    }

    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, McpError> {
        if self.closed.load(Ordering::Acquire) || self.cancellation.is_cancelled() {
            return Err(McpError::ConnectionClosed(self.server_name.clone()));
        }
        let reservation = self
            .bound_run
            .as_ref()
            .map(|bound| {
                bound
                    .budget
                    .reserve(crate::runtime::BudgetAmounts {
                        concurrent_calls: 1,
                        ..crate::runtime::BudgetAmounts::default()
                    })
                    .map_err(|error| {
                        McpError::Transport(format!(
                            "in-process MCP budget denied request: {error}"
                        ))
                    })
            })
            .transpose()?;
        let context = self.request_context();
        let request_cancellation = context.cancellation();
        let call = self.server.call_with_context(context, method, params);
        tokio::pin!(call);
        let result = tokio::select! {
            _ = request_cancellation.cancelled() => {
                Err(McpError::Cancelled { phase: "in-process-request" })
            }
            result = &mut call => result,
        };
        if let Some(reservation) = reservation {
            reservation.commit().map_err(|error| {
                McpError::Transport(format!(
                    "in-process MCP budget reconciliation failed: {error}"
                ))
            })?;
        }
        result
    }

    async fn close(&self) -> Result<(), McpError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let _receipt = self
            .cancellation
            .cancel(crate::runtime::CancellationReason::ParentTerminated);
        self.server.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::AtomicUsize;

    struct EchoServer {
        calls: AtomicUsize,
        shutdowns: AtomicUsize,
    }

    impl EchoServer {
        const fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                shutdowns: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl McpServerCallable for EchoServer {
        async fn call(&self, method: &str, params: Option<Value>) -> Result<Value, McpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if method == "fail" {
                return Err(McpError::Protocol("test failure".into()));
            }
            Ok(json!({"method": method, "params": params}))
        }

        async fn shutdown(&self) -> Result<(), McpError> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn transport_forwards_request_to_callable() {
        let server = Arc::new(EchoServer::new());
        let transport = InProcessTransport::new(server.clone());
        let response = transport
            .request("tools/list", Some(json!({"foo": 1})))
            .await
            .expect("request");
        assert_eq!(response["method"], "tools/list");
        assert_eq!(response["params"]["foo"], 1);
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn close_revokes_calls_and_shuts_down_once() {
        let server = Arc::new(EchoServer::new());
        let transport = InProcessTransport::new(server.clone());
        transport.close().await.expect("close");
        transport.close().await.expect("idempotent close");
        assert!(matches!(
            transport.request("ping", None).await,
            Err(McpError::ConnectionClosed(_))
        ));
        assert_eq!(server.calls.load(Ordering::SeqCst), 0);
        assert_eq!(server.shutdowns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn contextual_call_has_no_run_authority_when_detached() {
        struct ContextServer;
        #[async_trait]
        impl McpServerCallable for ContextServer {
            async fn call(&self, _method: &str, _params: Option<Value>) -> Result<Value, McpError> {
                unreachable!("context path is overridden")
            }

            async fn call_with_context(
                &self,
                context: McpInProcessRequestContext,
                _method: &str,
                _params: Option<Value>,
            ) -> Result<Value, McpError> {
                Ok(json!({
                    "server": context.server_name(),
                    "run": context.run_id(),
                    "generation": context.run_generation(),
                    "cancelled": context.is_cancelled(),
                }))
            }
        }
        let transport = InProcessTransport::new(Arc::new(ContextServer));
        let response = transport.request("ping", None).await.expect("request");
        assert_eq!(response["server"], "detached-in-process");
        assert!(response["run"].is_null());
        assert!(response["generation"].is_null());
        assert_eq!(response["cancelled"], false);
    }

    struct BlockingServer {
        started: tokio::sync::Notify,
        shutdowns: AtomicUsize,
    }

    #[async_trait]
    impl McpServerCallable for BlockingServer {
        async fn call(&self, _method: &str, _params: Option<Value>) -> Result<Value, McpError> {
            self.started.notify_one();
            std::future::pending().await
        }

        async fn shutdown(&self) -> Result<(), McpError> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn close_cancels_an_in_flight_call_before_shutdown_completes() {
        let server = Arc::new(BlockingServer {
            started: tokio::sync::Notify::new(),
            shutdowns: AtomicUsize::new(0),
        });
        let transport = Arc::new(InProcessTransport::new(server.clone()));
        let request_transport = transport.clone();
        let request = tokio::spawn(async move { request_transport.request("blocked", None).await });
        server.started.notified().await;
        transport.close().await.expect("close");
        let error = request
            .await
            .expect("request task")
            .expect_err("in-flight call must cancel");
        assert!(matches!(
            error,
            McpError::Cancelled {
                phase: "in-process-request"
            }
        ));
        assert_eq!(server.shutdowns.load(Ordering::SeqCst), 1);
    }
}

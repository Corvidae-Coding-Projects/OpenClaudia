//! MCP Integration - Model Context Protocol client for external tool servers.
//!
//! Supports:
//! - Stdio transport (spawn process, communicate via stdin/stdout)
//! - HTTP transport (connect to HTTP-based MCP servers)
//!
//! Handles tool discovery, schema translation, and request routing.

use async_trait::async_trait;
use base64::Engine as _;
use futures::StreamExt as _;
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
#[cfg(test)]
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, Command};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

#[doc(hidden)]
pub use crate::mcp_protocol::McpRequestContext;
use crate::mcp_protocol::{
    parse_notification, McpNotification, McpProtocolAdapter, McpProtocolEra,
    CURRENT_PROTOCOL_VERSION, PREFERRED_LEGACY_PROTOCOL_VERSION,
};
pub use crate::mcp_protocol::{
    McpAnnotations, McpCallToolResult, McpCapabilities, McpContentBlock, McpGetPromptResult,
    McpIcon, McpListCapability, McpPrompt, McpPromptArgument, McpPromptMessage, McpProtocolVersion,
    McpReadResourceResult, McpResource, McpResourceContents, McpResourcesCapability, McpRole,
    McpServerInfo, McpTask, McpTaskStatus, McpTool, McpToolsCapability,
};

// Fix #490 — per-request HTTP timeout cap. Stdio caps responses at 10 MiB
// (`MAX_RESPONSE_SIZE`); the HTTP transport now caps wall-clock time at 60s
// so a stalled MCP server cannot block a tool call indefinitely. Applied
// per request via `RequestBuilder::timeout` so it overrides any global
// default on the shared client.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_mins(1);
const HEADERS_HELPER_TIMEOUT: Duration = Duration::from_secs(10);

/// Process-wide shared `reqwest::Client` for the HTTP MCP transport.
///
/// Fix #490 — replaces per-`HttpTransport::new` `reqwest::Client::new()`,
/// which built a fresh connection pool, DNS cache, and TLS resolver for
/// every transport instance. Mirrors the `SHARED_HTTP_CLIENT` pattern in
/// `src/web.rs` (commit `fec15a20`, crosslink #368): one client, built
/// once, reused across every `HttpTransport`. Per-request overrides
/// (`HTTP_REQUEST_TIMEOUT`) are still applied at the call site.
static SHARED_MCP_HTTP_CLIENT: LazyLock<Result<reqwest::Client, String>> =
    LazyLock::new(build_shared_mcp_http_client);

fn build_shared_mcp_http_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(90))
        .connect_timeout(Duration::from_secs(10))
        .tcp_keepalive(Duration::from_mins(1))
        .build()
        .map_err(|err| format!("failed to build shared MCP HTTP client: {err}"))
}

// Fix #445 point 1 — ring-buffer cap for the background stderr drain.
const STDERR_BUFFER_CAP: usize = 1024 * 1024;
// Fix #445 point 1 — bytes of stderr surfaced inside bubbled errors.
const STDERR_SNIPPET_BYTES: usize = 4096;
// Fix #445 point 2 — bound BEFORE allocation on the response line.
const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;
const MAX_HTTP_RESPONSE_SIZE: usize = 10 * 1024 * 1024;
const MAX_HTTP_SSE_EVENTS: usize = 1000;
const MAX_STDIO_INTERMEDIATE_MESSAGES: usize = 1000;
const MAX_MCP_CATALOG_PAGES: usize = 100;
const DEFAULT_MCP_REQUEST_TIMEOUT: Duration = Duration::from_mins(1);
const MCP_ACTOR_QUEUE_CAPACITY: usize = 32;
static NEXT_MCP_CONNECTION_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Errors that can occur during MCP operations
#[derive(Error, Debug)]
pub enum McpError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    /// A structurally valid JSON-RPC error. Keeping its machine fields typed
    /// is required for modern-version negotiation and provider recovery.
    #[error("MCP RPC error {code}: {message}")]
    Rpc {
        code: i64,
        message: String,
        data: Option<Value>,
        http_status: Option<u16>,
    },

    #[error("Unsupported MCP protocol version '{requested}' (server supports: {supported:?})")]
    UnsupportedProtocolVersion {
        requested: String,
        supported: Vec<String>,
    },

    #[error("Unsupported MCP capability combination: {0}")]
    UnsupportedCapability(String),

    #[error("MCP HTTP endpoint returned status {status} without a recognized protocol error")]
    HttpStatus { status: u16 },

    #[error("MCP request exceeded the {limit}-byte transport limit")]
    RequestTooLarge { limit: usize },

    #[error("MCP response exceeded the {limit}-byte transport limit")]
    ResponseTooLarge { limit: usize },

    #[error("MCP server '{server}' request queue is full (capacity {capacity})")]
    Backpressure { server: String, capacity: usize },

    #[error("MCP server '{0}' connection is closed")]
    ConnectionClosed(String),

    #[error("MCP operation cancelled during {phase} phase")]
    Cancelled { phase: &'static str },

    #[error("MCP transport capability is unavailable: {0}")]
    Capability(#[from] crate::tools::ToolCapabilityError),

    #[error(
        "MCP server '{server}' connection generation is stale: expected {expected}, current {current}"
    )]
    StaleConnectionGeneration {
        server: String,
        expected: u64,
        current: u64,
    },

    #[error("MCP request run generation is stale: expected {expected}, current {current}")]
    StaleRunGeneration { expected: u64, current: u64 },

    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    #[error("Server not connected: {0}")]
    NotConnected(String),

    #[error("MCP tool policy denied '{server}/{tool}'")]
    ToolNotAllowed { server: String, tool: String },

    #[error("MCP tool registration for '{0}' is stale; publish a fresh tool catalog")]
    StaleToolRegistration(String),

    #[error("MCP tool '{tool}' has an invalid input schema: {reason}")]
    InvalidToolSchema { tool: String, reason: String },

    #[error("MCP tool '{tool}' arguments do not satisfy its advertised input schema")]
    InvalidToolArguments { tool: String },

    /// Server is permanently unreachable after exhausting the reconnect
    /// budget (fix #629). CC `connectToServer` (`client.ts:1374-1401`)
    /// reconnects transparently on `onclose`; OC mirrors that with a
    /// per-server backoff (1 s / 5 s / 30 s) and surfaces this variant
    /// after the third failed reconnect.
    #[error("MCP server '{0}' is unreachable after reconnect attempts exhausted")]
    ServerUnreachable(String),

    /// Operation exceeded its configured deadline.
    ///
    /// `phase` names the lifecycle stage that timed out so the operator
    /// can distinguish a stalled `initialize` handshake (fix #628 —
    /// modelled after CC `connectToServer` racing `client.connect`
    /// against `getConnectionTimeoutMs()`) from a stalled per-request
    /// tool call.
    ///
    /// The Display string keeps the lowercase substring `"timeout"` so
    /// existing matchers that grep error messages for that token
    /// continue to work.
    #[error("Operation timeout during {phase} phase")]
    Timeout {
        /// Lifecycle phase whose deadline expired. Static, e.g.
        /// `"initialize"`, `"tools/list"`, `"tools/call"`.
        phase: &'static str,
    },

    /// The MCP server completed the `tools/call` round-trip
    /// successfully at the JSON-RPC layer but reported a
    /// tool-execution failure via the `isError: true` flag on the
    /// result envelope (fix #625).
    ///
    /// Per the MCP specification (and CC `callMCPTool` in
    /// `client.ts:3124-3148`), a tool result of the shape
    /// `{"content": [...], "isError": true}` signals that the
    /// tool itself failed — distinct from a JSON-RPC transport or
    /// protocol error. Pre-fix, OC `McpServer::call_tool` returned
    /// the raw `Value`, so this tool-level failure was silently
    /// forwarded to the LLM as if the call had succeeded. We now
    /// extract the first textual `content` block and surface it as
    /// this dedicated variant so callers can match on the variant
    /// directly (and `proxy::execute_mcp_tool` still propagates a
    /// useful Display message via `e.to_string()`).
    ///
    /// `message` carries the extracted human-readable error text and `result`
    /// retains the exact structured MCP result for typed model follow-up.
    /// If the server emitted `isError: true` with no content block
    /// at all, the message falls back to a generic placeholder so
    /// the variant remains distinguishable from any `Protocol`
    /// error.
    #[error("MCP tool reported error: {message}")]
    ToolReportedError {
        /// Human-readable error text extracted from the tool result's
        /// `content[0].text` field (or a generic fallback).
        message: String,
        /// Exact server result envelope, retained as untrusted tool-result
        /// data rather than flattened into prose.
        result: Value,
    },

    /// JSON-RPC response carried an `id` that did not match the
    /// outstanding request's `id` (fix #701).
    ///
    /// JSON-RPC 2.0 §5 requires that the response `id` match the
    /// request `id` it correlates to. A response with a different id
    /// is either a protocol-desync bug in the server or an attempt
    /// to splice another caller's reply into this transport. Either
    /// way the client MUST reject it — silently accepting it would
    /// return the wrong tool's result to the caller.
    ///
    /// `StdioTransport` enforced this since inception; `HttpTransport`
    /// previously parsed the `id` field and discarded it. This
    /// dedicated variant replaces the prior stringly-typed
    /// `Protocol("Response ID mismatch: ...")` error so call sites
    /// can match on the variant directly.
    #[error("JSON-RPC response id mismatch: expected {expected}, got {got}")]
    ResponseIdMismatch {
        /// `id` the client sent with its outstanding request.
        expected: u64,
        /// `id` the server returned on the wire.
        got: u64,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// JSON-RPC request
#[derive(Debug, Clone, Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
}

/// JSON-RPC response
#[derive(Debug, Clone, Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    id: u64,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

/// JSON-RPC error
#[derive(Debug, Clone, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

fn sanitize_json_value(value: Value, sanitize: &impl Fn(&str) -> String) -> Value {
    match value {
        Value::String(value) => Value::String(sanitize(&value)),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| sanitize_json_value(value, sanitize))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, sanitize_json_value(value, sanitize)))
                .collect(),
        ),
        other => other,
    }
}

fn typed_rpc_error(
    error: JsonRpcError,
    http_status: Option<u16>,
    sanitize: &impl Fn(&str) -> String,
) -> McpError {
    McpError::Rpc {
        code: error.code,
        message: sanitize(&error.message),
        data: error.data.map(|data| sanitize_json_value(data, sanitize)),
        http_status,
    }
}

fn emit_mcp_notification(notification: McpNotification, sanitize: &impl Fn(&str) -> String) {
    match notification {
        McpNotification::Progress {
            token,
            progress,
            total,
            message,
        } => {
            let message = message.as_deref().map(sanitize);
            debug!(
                progress_token = %token,
                progress,
                total,
                message,
                "MCP request progress"
            );
        }
        McpNotification::Log {
            level,
            logger,
            data,
        } => {
            let data = sanitize(&data.to_string());
            let logger = logger.as_deref().map(sanitize);
            match level.as_str() {
                "emergency" | "alert" | "critical" | "error" => {
                    error!(logger, data, "MCP server log");
                }
                "warning" => warn!(logger, data, "MCP server log"),
                "notice" | "info" => info!(logger, data, "MCP server log"),
                _ => debug!(logger, data, "MCP server log"),
            }
        }
        McpNotification::CatalogueChanged { method } => {
            debug!(method, "MCP server catalogue changed");
        }
        McpNotification::ResourceUpdated { uri } => {
            debug!(uri = %sanitize(&uri), "MCP server resource updated");
        }
    }
}

/// One discovered MCP identity that was deliberately not made model-visible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpToolUnavailable {
    pub server: String,
    pub tool: String,
    pub reason: String,
}

/// Exact deterministic MCP catalog input for one provider request.
///
/// Definitions contain host-authored registration metadata used only to bind
/// the run catalog's source digest. The progressive catalog strips that
/// metadata before provider conversion, while retaining its digest for
/// execution-time generation revalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolCatalogSnapshot {
    pub generation: crate::runtime::ContentDigest,
    pub definitions: Vec<Value>,
    pub unavailable: Vec<McpToolUnavailable>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum McpServerTrust {
    HostConfigured,
    PluginGrant(String),
}

impl McpServerTrust {
    fn registration_identity(&self) -> &str {
        match self {
            Self::HostConfigured => "host-configured",
            Self::PluginGrant(identity) => identity,
        }
    }
}

/// Historical public name retained for callers that imported it directly.
pub type ToolsCapability = McpToolsCapability;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpTransportBinding {
    Stdio,
    StreamableHttp,
    InProcess,
}

/// Transport trait for MCP communication.
///
/// Fix #490 — `#[async_trait::async_trait]` is the load-bearing piece
/// keeping this trait object-safe. Without it, the `async fn` methods
/// would produce anonymous `impl Future` return types and the trait
/// could not be used behind `Box<dyn McpTransport>` (which `McpServer`
/// stores). The `Send + Sync` supertrait bounds are required so the
/// resulting trait object can cross `.await` points in async tasks.
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Client capabilities this transport can actually service.
    ///
    /// Stdio is fully bidirectional, so it can answer server-initiated
    /// `roots/list` and `elicitation/create` requests while awaiting a
    /// response. The default is intentionally empty for transports that
    /// cannot yet route server-to-client requests back to the server.
    fn client_capabilities(&self) -> Value {
        json!({})
    }

    /// Wire binding used by the dual-era negotiation rules.
    fn binding(&self) -> McpTransportBinding {
        McpTransportBinding::InProcess
    }

    /// Send a request and receive a response
    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, McpError>;

    /// Send a request with the exact version/routing metadata selected by the
    /// protocol adapter. Non-HTTP transports carry all metadata in the body.
    async fn request_with_context(
        &self,
        context: McpRequestContext,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, McpError> {
        let _ = context;
        self.request(method, params).await
    }

    /// Send a JSON-RPC notification without waiting for a response.
    async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), McpError> {
        self.request(method, params).await.map(|_| ())
    }

    /// Close the transport
    async fn close(&self) -> Result<(), McpError>;
}

// Reconnection logic lives in [`McpManager`] (fix #629), not in the
// transport. CC splits responsibility the same way: `client.ts:1374-1401`
// hooks `onclose` at the manager layer to drop the cached client; the
// transport itself is one-shot. OC's [`McpManager`] holds a
// [`ConnectionSpec`] per server, drops the dead [`McpServer`] on
// transport error, and rebuilds it on the next access under the
// [`BACKOFF`] schedule (1 s / 5 s / 30 s); after
// [`MAX_RECONNECT_ATTEMPTS`] failures it surfaces
// [`McpError::ServerUnreachable`].

/// Stdio transport - communicates with MCP server via stdin/stdout
pub struct StdioTransport {
    run_context: Arc<crate::tools::ToolRunContext>,
    child: Arc<Mutex<Child>>,
    _process_registration: crate::tools::command::ActiveSandboxProcess,
    reader: Mutex<BufReader<tokio::process::ChildStdout>>,
    request_id: AtomicU64,
    /// Serialises the (`write_request` → `read_response`) pair so
    /// concurrent `request` calls cannot interleave on the stdio
    /// pipes (fix #732). The pre-fix code took `child` for the
    /// write, dropped it, then took `reader` for the read —
    /// letting two callers' writes co-resident on the wire. With
    /// a server free to reply in any order, caller A could read
    /// B's reply, trigger `ResponseIdMismatch` (fix #701), and
    /// the desync would cascade. Holding this dedicated guard
    /// across the entire write+read pair makes the transaction
    /// atomic; the inner `child` and `reader` mutexes remain
    /// (the bounded-read borrow from fix #445 still compiles) as
    /// strict child mutexes of `request_lock`, deadlock-free.
    request_lock: Mutex<()>,
    /// Writable project state remains isolated until one complete protocol
    /// request reaches a terminal response and can publish atomically.
    workspace_projection:
        Mutex<Option<crate::tools::file::workspace_projection::WorkspaceProjection>>,
    pid: u32,
    /// Becomes true only after the owned child has been reaped. A transport
    /// may remain alive in an `Arc` after `close`; remembering that lifecycle
    /// transition prevents its eventual `Drop` from signalling a reused PID.
    process_reaped: AtomicBool,
    /// Ring buffer holding the last `STDERR_BUFFER_CAP` bytes the server
    /// wrote to stderr (fix #445 point 1).
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    /// Handle to the stderr drain task. Wrapped in `Arc` so the struct
    /// stays `Send + Sync`. The task auto-terminates on stderr EOF.
    _stderr_drain: Arc<JoinHandle<()>>,
}

struct InFlightStdioRequestGuard {
    pid: u32,
    armed: bool,
}

impl InFlightStdioRequestGuard {
    const fn new(pid: u32) -> Self {
        Self { pid, armed: true }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for InFlightStdioRequestGuard {
    fn drop(&mut self) {
        if self.armed {
            crate::tools::terminate_sandbox_process_tree(self.pid);
        }
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        if !self.process_reaped.load(Ordering::Acquire) {
            crate::tools::terminate_sandbox_process_tree(self.pid);
            let child = Arc::clone(&self.child);
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let mut child = child.lock().await;
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    drop(child);
                });
            }
        }
    }
}

/// Spawn a background tokio task that drains `stderr` into a ring buffer.
/// Fix #445 point 1 — mirrors `src/tools/lsp.rs::capture_stderr` (#355)
/// but uses tokio I/O so we don't burn a dedicated OS thread.
fn spawn_stderr_drain(mut stderr: ChildStderr, buf: Arc<Mutex<Vec<u8>>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut chunk = [0u8; 4096];
        // `while let Ok(n)` exits on read error (terminal for the drain).
        // `n == 0` (EOF) also terminates. Both paths collapse into the
        // same control flow, satisfying `clippy::match_same_arms` and
        // `clippy::while_let_loop` without any `#[allow]`.
        while let Ok(n) = stderr.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            let mut guard = buf.lock().await;
            guard.extend_from_slice(&chunk[..n]);
            let len = guard.len();
            if len > STDERR_BUFFER_CAP {
                let drop_n = len - STDERR_BUFFER_CAP;
                guard.drain(..drop_n);
            }
        }
    })
}

/// Format the trailing [`STDERR_SNIPPET_BYTES`] of the stderr ring buffer.
async fn stderr_snippet(buf: &Arc<Mutex<Vec<u8>>>) -> zeroize::Zeroizing<String> {
    let guard = buf.lock().await;
    if guard.is_empty() {
        return zeroize::Zeroizing::new(String::new());
    }
    let start = guard.len().saturating_sub(STDERR_SNIPPET_BYTES);
    let text = String::from_utf8_lossy(&guard[start..]).into_owned();
    drop(guard);
    zeroize::Zeroizing::new(format!(" (server stderr tail: {text})"))
}

impl StdioTransport {
    /// Spawn a new MCP server process.
    ///
    /// # Errors
    ///
    /// Returns `McpError::Transport` if the process cannot be spawned, or if
    /// stdout/stderr cannot be taken from the child.
    pub fn spawn(
        run: &Arc<crate::tools::ToolRunContext>,
        command: &str,
        args: &[&str],
    ) -> Result<Self, McpError> {
        Self::spawn_with_protected_env(
            run,
            command,
            args,
            &crate::secrets::EnvironmentGrants::new(),
        )
    }

    /// Spawn a new MCP server process with extra environment variables.
    ///
    /// # Errors
    ///
    /// Returns `McpError::Transport` if the process cannot be spawned, or if
    /// stdout/stderr cannot be taken from the child.
    pub fn spawn_with_env(
        run: &Arc<crate::tools::ToolRunContext>,
        command: &str,
        args: &[&str],
        env: &HashMap<String, String>,
    ) -> Result<Self, McpError> {
        validate_mcp_child_environment(run, env)?;
        let env =
            crate::secrets::EnvironmentGrants::from_validated(env.clone()).map_err(|error| {
                McpError::Transport(format!("Invalid MCP child environment value: {error}"))
            })?;
        Self::spawn_with_protected_env(run, command, args, &env)
    }

    pub(crate) fn spawn_with_protected_env(
        run: &Arc<crate::tools::ToolRunContext>,
        command: &str,
        args: &[&str],
        env: &crate::secrets::EnvironmentGrants,
    ) -> Result<Self, McpError> {
        let resolved_command = resolve_trusted_mcp_executable(run, command)?;
        validate_protected_mcp_child_environment(run, env)?;
        let process_run = derive_mcp_stdio_run(run, env)?;
        let sandbox_args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let prepared_command = crate::tools::sandboxed_process_command(
            &process_run,
            crate::tools::SandboxProfile::McpStdio,
            resolved_command.as_os_str(),
            &sandbox_args,
            process_run.working_directory(),
        )
        .map_err(|error| {
            McpError::Transport(format!("MCP stdio sandbox is unavailable: {error}"))
        })?;
        let (command, workspace_projection) = prepared_command.into_parts();
        info!(
            command = %resolved_command.display(),
            arg_count = args.len(),
            env_vars = env.len(),
            profile = "mcp-stdio",
            network = "disabled",
            "Spawning sandboxed MCP server"
        );

        let mut cmd = Command::from(command);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);

        let mut child = cmd
            .spawn()
            .map_err(|e| McpError::Transport(format!("Failed to spawn process: {e}")))?;
        let pid = child.id().ok_or_else(|| {
            McpError::Transport("Sandboxed MCP process has no process id".to_string())
        })?;
        let process_registration =
            crate::tools::command::ActiveSandboxProcess::register(&process_run, pid);

        // Take stdout from the child once and wrap in a persistent BufReader
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpError::Transport("Stdout not available after spawn".to_string()))?;
        let reader = BufReader::new(stdout);

        // Fix #445 point 1: take stderr and start the background drain so
        // the OS pipe buffer never fills up. Failing to take stderr is a
        // hard error — we asked for `Stdio::piped()`, so absence means
        // we'd silently lose every server diagnostic on failure.
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| McpError::Transport("Stderr not available after spawn".to_string()))?;
        let stderr_buf = Arc::new(Mutex::new(Vec::new()));
        let drain = spawn_stderr_drain(stderr, Arc::clone(&stderr_buf));

        Ok(Self {
            run_context: process_run,
            child: Arc::new(Mutex::new(child)),
            _process_registration: process_registration,
            reader: Mutex::new(reader),
            request_id: AtomicU64::new(1),
            request_lock: Mutex::new(()), // Fix #732
            workspace_projection: Mutex::new(workspace_projection),
            pid,
            process_reaped: AtomicBool::new(false),
            stderr_buf,
            _stderr_drain: Arc::new(drain),
        })
    }

    /// Returns a clone of the stderr ring-buffer handle. Test-only.
    #[cfg(test)]
    pub(crate) fn stderr_buf_handle(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.stderr_buf)
    }

    #[allow(clippy::significant_drop_tightening)] // lock must cover the complete JSON-line write
    async fn write_json_line(&self, value: &Value) -> Result<(), McpError> {
        let line = serde_json::to_string(value)
            .map_err(|e| McpError::Protocol(format!("Failed to serialize MCP message: {e}")))?;
        if line.len() > MAX_REQUEST_SIZE {
            return Err(McpError::RequestTooLarge {
                limit: MAX_REQUEST_SIZE,
            });
        }
        {
            let mut child = self.child.lock().await;
            let Some(stdin) = child.stdin.as_mut() else {
                return Err(McpError::Transport("Stdin not available".to_string()));
            };
            stdin
                .write_all(line.as_bytes())
                .await
                .map_err(|e| McpError::Transport(format!("Failed to write to stdin: {e}")))?;
            stdin
                .write_all(b"\n")
                .await
                .map_err(|e| McpError::Transport(format!("Failed to write newline: {e}")))?;
            stdin
                .flush()
                .await
                .map_err(|e| McpError::Transport(format!("Failed to flush stdin: {e}")))?;
        }
        Ok(())
    }

    async fn read_stdout_line(&self) -> Result<String, McpError> {
        let buf = {
            let mut reader = self.reader.lock().await;
            let mut buf: Vec<u8> = Vec::new();
            // `+ 1` so we can distinguish "cap reached, no newline"
            // (oversized) from "exactly cap bytes followed by newline".
            let cap = (MAX_RESPONSE_SIZE as u64).saturating_add(1);
            let bytes_read = (&mut *reader)
                .take(cap)
                .read_until(b'\n', &mut buf)
                .await
                .map_err(|e| McpError::Transport(format!("Failed to read from stdout: {e}")))?;
            drop(reader);

            if bytes_read == 0 {
                let snippet = stderr_snippet(&self.stderr_buf).await;
                let raw = zeroize::Zeroizing::new(format!(
                    "MCP server closed stdout before responding{}",
                    snippet.as_str()
                ));
                return Err(McpError::Transport(
                    self.run_context.sanitize_diagnostic(&raw).to_string(),
                ));
            }

            if buf.len() > MAX_RESPONSE_SIZE && !buf.ends_with(b"\n") {
                let snippet = stderr_snippet(&self.stderr_buf).await;
                let raw = zeroize::Zeroizing::new(format!(
                    "MCP response exceeded {MAX_RESPONSE_SIZE} bytes without newline; rejecting{}",
                    snippet.as_str()
                ));
                return Err(McpError::Transport(
                    self.run_context.sanitize_diagnostic(&raw).to_string(),
                ));
            }
            buf
        };

        String::from_utf8(buf)
            .map_err(|e| McpError::Protocol(format!("MCP response was not valid UTF-8: {e}")))
    }

    async fn handle_server_message(&self, value: &Value) -> Result<bool, McpError> {
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            return Ok(false);
        };

        if value.get("id").is_none() {
            if let Some(notification) = parse_notification(value).map_err(McpError::Protocol)? {
                emit_mcp_notification(notification, &|text| {
                    self.run_context.sanitize_diagnostic(text).to_string()
                });
            } else {
                debug!(method = %method, "Ignoring unsupported MCP server notification");
            }
            return Ok(true);
        }

        let id = value.get("id").expect("checked above");
        let valid_id = id.is_string()
            || id
                .as_number()
                .is_some_and(|number| number.is_i64() || number.is_u64());
        if valid_id {
            let response = build_client_feature_response(&self.run_context, id, method);
            self.write_json_line(&response).await?;
        } else {
            return Err(McpError::Protocol(format!(
                "MCP server request '{method}' has an invalid JSON-RPC id"
            )));
        }

        Ok(true)
    }

    async fn perform_request(&self, id: u64, request_line: &str) -> Result<Value, McpError> {
        let mut child = self.child.lock().await;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(request_line.as_bytes())
                .await
                .map_err(|e| McpError::Transport(format!("Failed to write to stdin: {e}")))?;
            stdin
                .write_all(b"\n")
                .await
                .map_err(|e| McpError::Transport(format!("Failed to write newline: {e}")))?;
            stdin
                .flush()
                .await
                .map_err(|e| McpError::Transport(format!("Failed to flush stdin: {e}")))?;
        } else {
            return Err(McpError::Transport("Stdin not available".to_string()));
        }

        // stdin and stdout are independent descriptors. Releasing the child
        // lock also lets close terminate a stuck server after request timeout.
        drop(child);

        let mut seen_messages = 0usize;
        let response = loop {
            if seen_messages >= MAX_STDIO_INTERMEDIATE_MESSAGES {
                return Err(McpError::Protocol(format!(
                    "MCP stdio response scan exceeded {MAX_STDIO_INTERMEDIATE_MESSAGES} messages \
                     without seeing response id {id}"
                )));
            }
            seen_messages += 1;

            let line = zeroize::Zeroizing::new(self.read_stdout_line().await?);
            let value: Value = match serde_json::from_str(&line) {
                Ok(value) => value,
                Err(e) => {
                    let snippet = stderr_snippet(&self.stderr_buf).await;
                    let raw = zeroize::Zeroizing::new(format!(
                        "Failed to parse response: {e}{}",
                        snippet.as_str()
                    ));
                    return Err(McpError::Protocol(
                        self.run_context.sanitize_diagnostic(&raw).to_string(),
                    ));
                }
            };

            if self.handle_server_message(&value).await? {
                continue;
            }

            let response: JsonRpcResponse = serde_json::from_value(value).map_err(|e| {
                McpError::Protocol(format!("Failed to parse response envelope: {e}"))
            })?;
            break response;
        };

        if response.id != id {
            return Err(McpError::ResponseIdMismatch {
                expected: id,
                got: response.id,
            });
        }

        if let Some(error) = response.error {
            return Err(typed_rpc_error(error, None, &|text| {
                self.run_context.sanitize_diagnostic(text).to_string()
            }));
        }

        Ok(response.result.unwrap_or(Value::Null))
    }

    async fn checkpoint_workspace(&self, publish: bool) -> Result<(), McpError> {
        let Some(mut projection) = self.workspace_projection.lock().await.take() else {
            return Ok(());
        };
        let paused = match crate::tools::pause_sandbox_process_tree(self.pid) {
            Ok(paused) => paused,
            Err(error) => {
                self.terminate_after_workspace_error().await;
                drop(projection);
                return Err(McpError::Transport(format!(
                    "Cannot checkpoint MCP workspace: {error}"
                )));
            }
        };

        let checkpoint = tokio::task::spawn_blocking(move || {
            let result = projection.checkpoint(publish);
            (projection, result)
        })
        .await;

        match checkpoint {
            Ok((projection, Ok(receipt))) => {
                tracing::debug!(
                    target: "openclaudia::workspace_projection",
                    generation = %receipt.generation,
                    proposal_digest = %receipt.proposal_digest,
                    reconciled_digest = ?receipt.reconciled_digest,
                    changed_entries = receipt.changed_entries,
                    published = receipt.published,
                    "Settled MCP workspace request"
                );
                *self.workspace_projection.lock().await = Some(projection);
                drop(paused);
                Ok(())
            }
            Ok((projection, Err(error))) => {
                self.terminate_after_workspace_error().await;
                drop(paused);
                let recovery = error.recovery_path().map(Path::to_path_buf);
                drop(projection);
                Err(McpError::Transport(recovery.map_or_else(
                    || format!("MCP workspace reconciliation failed: {error}"),
                    |path| {
                        format!(
                            "MCP workspace reconciliation failed: {error}; recovery state: '{}'",
                            path.display()
                        )
                    },
                )))
            }
            Err(error) => {
                self.terminate_after_workspace_error().await;
                drop(paused);
                Err(McpError::Transport(format!(
                    "MCP workspace reconciliation task failed: {error}"
                )))
            }
        }
    }

    async fn terminate_after_workspace_error(&self) {
        if self.process_reaped.load(Ordering::Acquire) {
            return;
        }
        crate::tools::terminate_sandbox_process_tree(self.pid);
        let mut child = self.child.lock().await;
        let _ = child.kill().await;
        if child.wait().await.is_ok() {
            self.process_reaped.store(true, Ordering::Release);
        }
        drop(child);
    }
}

fn derive_mcp_stdio_run(
    parent: &Arc<crate::tools::ToolRunContext>,
    extra_environment: &crate::secrets::EnvironmentGrants,
) -> Result<Arc<crate::tools::ToolRunContext>, McpError> {
    parent.require(crate::tools::ToolResource::Process)?;
    let session_id = crate::state::SessionId::from_raw(parent.session_id()).map_err(|error| {
        McpError::Transport(format!(
            "Cannot bind MCP process to parent session: {error}"
        ))
    })?;
    // MCP roots/list exposes the project, not unrelated attachment roots from
    // the parent. The child builder adds its project and private scratch roots.
    let read_only_roots = Vec::new();
    let read_write_roots = Vec::new();
    // A stdio server receives only the environment declared for that server,
    // never unrelated provider credentials from the parent agent run.
    let environment_grants = extra_environment.clone();
    let workspace_access = if parent.grants_resource(crate::tools::ToolResource::WorkspaceWrite) {
        crate::tools::WorkspaceAccess::ReadWrite
    } else {
        crate::tools::WorkspaceAccess::ReadOnly
    };

    crate::tools::ToolRunContext::builder(session_id, parent.project_root())
        .working_directory(parent.working_directory())
        .read_only_roots(read_only_roots)
        .read_write_roots(read_write_roots)
        .project_secret_masks(parent.project_secret_masks().to_vec())
        .protected_environment_grants(environment_grants)
        .protected_mcp_environment_grants(parent.mcp_environment_grants().clone())
        .executable_search_path(parent.executable_search_path())
        .host_home(parent.host_home().map(Path::to_path_buf))
        .workspace_access(workspace_access)
        .process(true)
        .network(false)
        .secrets(parent.grants_resource(crate::tools::ToolResource::Secrets))
        .process_owner(parent.process_owner())
        .actor_role(crate::runtime::ActorRole::Worker)
        .provider("mcp-stdio")
        .budget_limits(parent.runtime().descriptor().budget.limits.clone())
        .parent_budget(parent.budget().clone())
        .build()
        .map_err(|error| {
            McpError::Transport(format!("Cannot bind MCP stdio capabilities: {error}"))
        })
}

fn is_host_loader_environment(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
        || matches!(
            upper.as_str(),
            "GCONV_PATH" | "GLIBC_TUNABLES" | "LOCPATH" | "NLSPATH"
        )
}

fn validate_mcp_child_environment(
    run: &crate::tools::ToolRunContext,
    environment: &HashMap<String, String>,
) -> Result<(), McpError> {
    for (key, value) in environment {
        if is_host_loader_environment(key) {
            return Err(McpError::Transport(format!(
                "Refusing MCP environment variable '{key}' because it can alter the host \
                 sandbox launcher's dynamic loader"
            )));
        }
        if crate::tools::is_sensitive_env(key) {
            run.require(crate::tools::ToolResource::Secrets)
                .map_err(|error| {
                    McpError::Transport(format!(
                        "MCP secret environment grant '{key}' is unavailable: {error}"
                    ))
                })?;
            match run.mcp_environment_grants().get(key) {
                Some(granted) if granted.matches(value) => {}
                Some(_) => {
                    return Err(McpError::Transport(format!(
                        "Refusing MCP secret environment grant '{key}' because its value does not \
                         match the immutable run capability snapshot"
                    )));
                }
                None => {
                    return Err(McpError::Transport(format!(
                        "Refusing undeclared-sensitive MCP environment grant '{key}'. The host \
                         operator must name it in OPENCLAUDIA_MCP_ENV_GRANTS before the run starts."
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_protected_mcp_child_environment(
    run: &crate::tools::ToolRunContext,
    environment: &crate::secrets::EnvironmentGrants,
) -> Result<(), McpError> {
    for key in environment.keys() {
        validate_mcp_env_name_for_child(key)?;
        if is_host_loader_environment(key) {
            return Err(McpError::Transport(format!(
                "Refusing MCP environment variable '{key}' because it can alter the host sandbox launcher's dynamic loader"
            )));
        }
        if crate::tools::is_sensitive_env(key) {
            run.require(crate::tools::ToolResource::Secrets)
                .map_err(|error| McpError::Transport(error.to_string()))?;
            match (run.mcp_environment_grants().get(key), environment.get(key)) {
                (Some(granted), Some(requested)) if granted == requested => {}
                (Some(_), Some(_)) => {
                    return Err(McpError::Transport(format!(
                        "Refusing MCP secret environment grant '{key}' because its value does not match the immutable run capability snapshot"
                    )));
                }
                _ => {
                    return Err(McpError::Transport(format!(
                        "Refusing undeclared-sensitive MCP environment grant '{key}'. The host operator must name it in OPENCLAUDIA_MCP_ENV_GRANTS before the run starts."
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_mcp_env_name_for_child(name: &str) -> Result<(), McpError> {
    let mut characters = name.chars();
    let valid = characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric());
    if valid {
        Ok(())
    } else {
        Err(McpError::Transport(format!(
            "Refusing invalid MCP environment variable name '{name}'"
        )))
    }
}

fn resolve_trusted_mcp_executable(
    run: &crate::tools::ToolRunContext,
    command: &str,
) -> Result<PathBuf, McpError> {
    run.require(crate::tools::ToolResource::Process)?;
    let candidate = if Path::new(command).is_absolute() {
        PathBuf::from(command)
    } else {
        run.resolve_executable(command).map_err(|error| {
            McpError::Transport(format!(
                "Cannot resolve MCP executable '{command}' from the run-bound startup PATH: {error}"
            ))
        })?
    };
    let resolved = candidate.canonicalize().map_err(|error| {
        McpError::Transport(format!(
            "Cannot pin MCP executable '{}': {error}",
            candidate.display()
        ))
    })?;
    let metadata = std::fs::metadata(&resolved).map_err(|error| {
        McpError::Transport(format!(
            "Cannot inspect MCP executable '{}': {error}",
            resolved.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(McpError::Transport(format!(
            "MCP executable '{}' is not a regular file",
            resolved.display()
        )));
    }
    if run
        .read_write_roots()
        .iter()
        .any(|root| resolved == *root || resolved.starts_with(root))
    {
        return Err(McpError::Transport(format!(
            "Refusing MCP executable '{}' because it is inside an agent-writable capability root",
            resolved.display()
        )));
    }
    verify_trusted_executable_ancestry(&resolved)?;
    Ok(resolved)
}

#[cfg(unix)]
fn verify_trusted_executable_ancestry(path: &Path) -> Result<(), McpError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    for component in path.ancestors() {
        let metadata = std::fs::symlink_metadata(component).map_err(|error| {
            McpError::Transport(format!(
                "Cannot inspect MCP executable ancestry '{}': {error}",
                component.display()
            ))
        })?;
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return Err(McpError::Transport(format!(
                "Refusing MCP executable '{}': component '{}' is not root-owned and non-writable by group/other",
                path.display(),
                component.display()
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_trusted_executable_ancestry(_path: &Path) -> Result<(), McpError> {
    Err(McpError::Transport(
        "MCP stdio is blocked: trusted executable ancestry verification is unsupported on this platform"
            .to_string(),
    ))
}

fn build_client_feature_response(
    run: &crate::tools::ToolRunContext,
    id: &Value,
    method: &str,
) -> Value {
    match method {
        "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
        "roots/list" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": current_roots_result(run),
        }),
        "elicitation/create" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"action": "decline"},
        }),
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": format!("OpenClaudia MCP client does not handle server request: {other}"),
            },
        }),
    }
}

fn current_roots_result(run: &crate::tools::ToolRunContext) -> Value {
    let root = run.project_root();
    let uri = url::Url::from_directory_path(root).map_or_else(
        |()| format!("file://{}", root.display()),
        |url| url.to_string(),
    );
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("workspace");

    json!({
        "roots": [{
            "uri": uri,
            "name": name,
        }]
    })
}

#[async_trait]
impl McpTransport for StdioTransport {
    fn binding(&self) -> McpTransportBinding {
        McpTransportBinding::Stdio
    }

    fn client_capabilities(&self) -> Value {
        json!({
            "roots": { "listChanged": false },
            "elicitation": {}
        })
    }

    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, McpError> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };

        let request_line = serde_json::to_string(&request)
            .map_err(|e| McpError::Protocol(format!("Failed to serialize request: {e}")))?;
        if request_line.len() > MAX_REQUEST_SIZE {
            return Err(McpError::RequestTooLarge {
                limit: MAX_REQUEST_SIZE,
            });
        }

        debug!(method = %method, id = id, "Sending MCP request");

        // Serialize the wire exchange and its workspace checkpoint. A second
        // request must not observe or extend an uncommitted candidate.
        let _request_guard = self.request_lock.lock().await;
        let mut in_flight = InFlightStdioRequestGuard::new(self.pid);
        let result = tokio::time::timeout(
            DEFAULT_MCP_REQUEST_TIMEOUT,
            self.perform_request(id, &request_line),
        )
        .await
        .unwrap_or(Err(McpError::Timeout {
            phase: "stdio-request",
        }));
        let checkpoint = self.checkpoint_workspace(result.is_ok()).await;
        if matches!(result, Err(McpError::Timeout { .. })) {
            self.terminate_after_workspace_error().await;
        }
        in_flight.disarm();
        checkpoint?;
        result
    }

    async fn request_with_context(
        &self,
        _context: McpRequestContext,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, McpError> {
        self.request(method, params).await
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), McpError> {
        let notification = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params.unwrap_or_else(|| json!({})),
        });
        let _request_guard = self.request_lock.lock().await;
        self.write_json_line(&notification).await
    }

    async fn close(&self) -> Result<(), McpError> {
        let _request_guard = self.request_lock.lock().await;
        if !self.process_reaped.load(Ordering::Acquire) {
            crate::tools::terminate_sandbox_process_tree(self.pid);
            let mut child = self.child.lock().await;
            let _ = child.kill().await;
            child
                .wait()
                .await
                .map_err(|e| McpError::Transport(format!("Failed to reap MCP process: {e}")))?;
            self.process_reaped.store(true, Ordering::Release);
            drop(child);
        }
        let projection = self.workspace_projection.lock().await.take();
        if let Some(mut projection) = projection {
            tokio::task::spawn_blocking(move || projection.settle(false))
                .await
                .map_err(|error| {
                    McpError::Transport(format!(
                        "MCP workspace rollback task failed during close: {error}"
                    ))
                })?
                .map_err(|error| {
                    McpError::Transport(format!(
                        "MCP workspace rollback failed during close: {error}"
                    ))
                })?;
        }
        Ok(())
    }
}

/// HTTP transport - communicates with MCP server via HTTP.
///
/// Fix #490 — does NOT own a `reqwest::Client`. Every instance shares
/// the process-wide `SHARED_MCP_HTTP_CLIENT`, so connecting to N HTTP
/// MCP servers builds the connection pool once, not N times.
pub struct HttpTransport {
    base_url: String,
    headers: crate::secrets::SensitiveHeaders,
    request_id: AtomicU64,
    /// MCP Streamable HTTP session id (crosslink #631).
    ///
    /// The first response to `initialize` may carry an `Mcp-Session-Id`
    /// header. Per MCP spec §6.5 every subsequent POST MUST echo that
    /// value back. We cache it here so callers do not need to thread the
    /// id through every request. `RwLock` because the value is read on
    /// every request but written at most once.
    session_id: std::sync::RwLock<Option<String>>,
}

fn protect_static_headers(
    headers: &HashMap<String, String>,
) -> Result<crate::secrets::SensitiveHeaders, McpError> {
    let mut parsed = crate::secrets::SensitiveHeaders::new();
    for (name, value) in headers {
        parsed
            .insert_literal(name, value.clone())
            .map_err(|err| McpError::Transport(format!("Invalid MCP HTTP header: {err}")))?;
    }
    Ok(parsed)
}

impl HttpTransport {
    /// Create a new HTTP transport, validating the URL against the
    /// shared SSRF guard (fix #677).
    ///
    /// The base URL is parsed and run through [`crate::web::validate_url`]
    /// — the same perimeter check used by `web_fetch` and the web-search
    /// tools — so a misconfigured or hostile MCP manifest cannot point
    /// the transport at:
    ///
    /// * `file://`, `data:`, `ftp:`, or any other non-`http(s)` scheme;
    /// * loopback (`127.0.0.0/8`, `::1`, `localhost`);
    /// * RFC 1918 / link-local / cloud-metadata addresses
    ///   (`169.254.169.254`, `metadata.google.internal`, etc.);
    /// * unresolvable hosts.
    ///
    /// The validator already covers DNS-resolved hostnames, IPv6 zone
    /// literals, and the cloud-provider metadata hostname denylist; we
    /// reuse it verbatim so MCP HTTP servers and `web_fetch` enforce
    /// the same perimeter.
    ///
    /// Borrows the process-wide `SHARED_MCP_HTTP_CLIENT` rather than
    /// constructing a fresh `reqwest::Client` (fix #490).
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Transport`] if the URL fails validation. The
    /// error message starts with the substring `"SSRF guard rejected"`
    /// so call sites and tests can distinguish a validation failure
    /// from a runtime transport error.
    pub fn new(base_url: &str) -> Result<Self, McpError> {
        Self::new_with_sensitive_headers(base_url, crate::secrets::SensitiveHeaders::new())
    }

    /// Create a new HTTP transport with static request headers.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Transport`] if the URL fails validation or any
    /// configured header name/value is invalid.
    pub fn new_with_headers(
        base_url: &str,
        headers: &HashMap<String, String>,
    ) -> Result<Self, McpError> {
        Self::new_with_sensitive_headers(base_url, protect_static_headers(headers)?)
    }

    fn new_with_sensitive_headers(
        base_url: &str,
        headers: crate::secrets::SensitiveHeaders,
    ) -> Result<Self, McpError> {
        // SSRF guard. Mirrors `web::fetch_url`'s entry check (#368) and
        // satisfies the perimeter contract spelled out in #677.
        crate::web::validate_url(base_url).map_err(|reason| {
            McpError::Transport(format!("SSRF guard rejected MCP base URL: {reason}"))
        })?;
        // Touch the static so the client is eagerly built on first
        // construction. Cheap, idempotent, and surfaces a build error
        // at transport-creation time rather than first-request time.
        Self::client()?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            headers,
            request_id: AtomicU64::new(1),
            session_id: std::sync::RwLock::new(None),
        })
    }

    /// Test-only constructor that skips the SSRF guard so unit and
    /// integration tests can point the transport at a `127.0.0.1`
    /// loopback listener they just bound (which the production
    /// [`Self::new`] would correctly reject as a private address).
    ///
    /// Hidden from public docs and compiled only when debug assertions are
    /// enabled. It remains `pub` in debug builds because integration tests in
    /// `tests/*.rs` compile as a separate crate without `cfg(test)` access.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    #[must_use]
    pub fn __test_new_unchecked(base_url: &str) -> Self {
        Self::__test_new_unchecked_with_sensitive_headers(
            base_url,
            crate::secrets::SensitiveHeaders::new(),
        )
    }

    /// Test-only constructor with static headers and no SSRF guard.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    #[must_use]
    pub fn __test_new_unchecked_with_headers(
        base_url: &str,
        headers: &HashMap<String, String>,
    ) -> Self {
        let headers = protect_static_headers(headers).unwrap_or_default();
        Self::__test_new_unchecked_with_sensitive_headers(base_url, headers)
    }

    #[cfg(debug_assertions)]
    fn __test_new_unchecked_with_sensitive_headers(
        base_url: &str,
        headers: crate::secrets::SensitiveHeaders,
    ) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            headers,
            request_id: AtomicU64::new(1),
            session_id: std::sync::RwLock::new(None),
        }
    }

    /// MCP Streamable HTTP session id, once captured (crosslink #631).
    ///
    /// Returns `None` before the first response carrying an
    /// `Mcp-Session-Id` header. Visible to tests so they can pin the
    /// session-id propagation contract end-to-end.
    #[must_use]
    pub fn session_id(&self) -> Option<String> {
        self.session_id_read_guard("session_id")
            .and_then(|g| g.as_ref().cloned())
    }

    /// Returns the process-wide shared client. Used so call sites do
    /// not have to name the static directly and so tests can assert
    /// pointer equality of the borrowed reference (fix #490).
    fn client() -> Result<&'static reqwest::Client, McpError> {
        match &*SHARED_MCP_HTTP_CLIENT {
            Ok(client) => Ok(client),
            Err(err) => Err(McpError::Transport(err.clone())),
        }
    }

    fn session_id_read_guard(
        &self,
        operation: &'static str,
    ) -> Option<std::sync::RwLockReadGuard<'_, Option<String>>> {
        match self.session_id.read() {
            Ok(guard) => Some(guard),
            Err(err) => {
                error!(operation, error = %err, "MCP HTTP session id read lock poisoned");
                None
            }
        }
    }

    fn session_id_write_guard(
        &self,
        operation: &'static str,
    ) -> Option<std::sync::RwLockWriteGuard<'_, Option<String>>> {
        match self.session_id.write() {
            Ok(guard) => Some(guard),
            Err(err) => {
                error!(operation, error = %err, "MCP HTTP session id write lock poisoned");
                None
            }
        }
    }
}

fn response_content_type_is_event_stream(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONTENT_TYPE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(content_type_value_is_event_stream)
}

fn content_type_value_is_event_stream(value: &str) -> bool {
    value.split(',').any(|part| {
        part.split(';')
            .next()
            .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/event-stream"))
    })
}

fn valid_mcp_session_id(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| matches!(byte, 0x21..=0x7e))
}

async fn parse_http_json_rpc_response(
    response: reqwest::Response,
    sanitize: &(impl Fn(&str) -> String + Sync),
) -> Result<JsonRpcResponse, McpError> {
    let is_event_stream = response_content_type_is_event_stream(response.headers());
    if response
        .content_length()
        .is_some_and(|length| length > MAX_HTTP_RESPONSE_SIZE as u64)
    {
        return Err(McpError::ResponseTooLarge {
            limit: MAX_HTTP_RESPONSE_SIZE,
        });
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(MAX_HTTP_RESPONSE_SIZE),
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| {
            if is_event_stream {
                McpError::Protocol(format!("Failed to read SSE response: {err}"))
            } else {
                McpError::Protocol(format!("Failed to read response: {err}"))
            }
        })?;
        if body.len().saturating_add(chunk.len()) > MAX_HTTP_RESPONSE_SIZE {
            return Err(McpError::ResponseTooLarge {
                limit: MAX_HTTP_RESPONSE_SIZE,
            });
        }
        body.extend_from_slice(&chunk);
    }
    let body = zeroize::Zeroizing::new(String::from_utf8(body).map_err(|error| {
        McpError::Protocol(format!("MCP HTTP response was not valid UTF-8: {error}"))
    })?);

    if is_event_stream || body_looks_like_sse(&body) {
        parse_sse_json_rpc_response(&body, sanitize)
    } else {
        serde_json::from_str(&body)
            .map_err(|err| McpError::Protocol(format!("Failed to parse response: {err}")))
    }
}

fn body_looks_like_sse(body: &str) -> bool {
    body.lines()
        .map(str::trim_start)
        .find(|line| !line.is_empty())
        .is_some_and(|line| {
            line.starts_with(':')
                || line.starts_with("event:")
                || line.starts_with("data:")
                || line.starts_with("id:")
                || line.starts_with("retry:")
        })
}

fn parse_sse_json_rpc_response(
    body: &str,
    sanitize: &impl Fn(&str) -> String,
) -> Result<JsonRpcResponse, McpError> {
    let mut event_name: Option<String> = None;
    let mut data_lines: Vec<String> = Vec::new();
    let mut event_count = 0usize;

    for line in body.lines() {
        if line.is_empty() {
            if !data_lines.is_empty() {
                event_count = event_count.saturating_add(1);
                if event_count > MAX_HTTP_SSE_EVENTS {
                    return Err(McpError::Protocol(format!(
                        "MCP SSE response exceeded {MAX_HTTP_SSE_EVENTS} events"
                    )));
                }
            }
            if let Some(response) =
                parse_sse_json_rpc_event(event_name.as_deref(), &data_lines, sanitize)?
            {
                return Ok(response);
            }
            event_name = None;
            data_lines.clear();
            continue;
        }

        if line.starts_with(':') {
            continue;
        }

        let (field, value) = match line.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (line, ""),
        };

        match field {
            "event" => event_name = Some(value.to_string()),
            "data" => data_lines.push(value.to_string()),
            _ => {}
        }
    }

    if !data_lines.is_empty() && event_count >= MAX_HTTP_SSE_EVENTS {
        return Err(McpError::Protocol(format!(
            "MCP SSE response exceeded {MAX_HTTP_SSE_EVENTS} events"
        )));
    }
    if let Some(response) = parse_sse_json_rpc_event(event_name.as_deref(), &data_lines, sanitize)?
    {
        return Ok(response);
    }

    Err(McpError::Protocol(
        "SSE response did not contain a JSON-RPC response message".to_string(),
    ))
}

fn parse_sse_json_rpc_event(
    event_name: Option<&str>,
    data_lines: &[String],
    sanitize: &impl Fn(&str) -> String,
) -> Result<Option<JsonRpcResponse>, McpError> {
    if data_lines.is_empty() || event_name.is_some_and(|name| name != "message") {
        return Ok(None);
    }

    let data = data_lines.join("\n");
    let value: Value = serde_json::from_str(&data)
        .map_err(|err| McpError::Protocol(format!("Failed to parse SSE event JSON: {err}")))?;

    if let Some(notification) = parse_notification(&value).map_err(McpError::Protocol)? {
        emit_mcp_notification(notification, sanitize);
        return Ok(None);
    }

    if !value
        .get("id")
        .is_some_and(|_| value.get("result").is_some() || value.get("error").is_some())
    {
        return Ok(None);
    }

    serde_json::from_value(value)
        .map(Some)
        .map_err(|err| McpError::Protocol(format!("Failed to parse SSE JSON-RPC response: {err}")))
}

fn encode_mcp_header_value(value: &str) -> String {
    let plain = !value.is_empty()
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| matches!(byte, b'\t' | 0x20..=0x7e))
        && value.trim() == value
        && !(value.starts_with("=?base64?") && value.ends_with("?="));
    if plain {
        value.to_string()
    } else {
        format!(
            "=?base64?{}?=",
            base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
        )
    }
}

fn should_fall_back_to_legacy(binding: McpTransportBinding, error: &McpError) -> bool {
    match error {
        McpError::Rpc {
            code, http_status, ..
        } => match binding {
            McpTransportBinding::Stdio | McpTransportBinding::InProcess => *code == -32601,
            McpTransportBinding::StreamableHttp => {
                *code == -32601
                    && http_status.is_some_and(|status| matches!(status, 200 | 400 | 404 | 405))
            }
        },
        McpError::HttpStatus { status } if binding == McpTransportBinding::StreamableHttp => {
            matches!(status, 400 | 404 | 405)
        }
        _ => false,
    }
}

#[async_trait]
impl McpTransport for HttpTransport {
    fn binding(&self) -> McpTransportBinding {
        McpTransportBinding::StreamableHttp
    }

    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, McpError> {
        self.request_with_context(
            McpRequestContext::legacy(McpProtocolVersion::V2024_11_05),
            method,
            params,
        )
        .await
    }

    async fn request_with_context(
        &self,
        context: McpRequestContext,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, McpError> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };
        let request_body = serde_json::to_vec(&request)
            .map_err(|error| McpError::Protocol(format!("Failed to serialize request: {error}")))?;
        if request_body.len() > MAX_REQUEST_SIZE {
            return Err(McpError::RequestTooLarge {
                limit: MAX_REQUEST_SIZE,
            });
        }

        debug!(method = %method, "Sending HTTP MCP request");

        // Fix #490 — share the process-wide client and apply a
        // per-request timeout cap. The shared client carries no
        // request-level timeout (so it can be reused for other
        // workloads with different deadlines); the cap is set here
        // via `RequestBuilder::timeout`.
        //
        // Crosslink #631 — MCP Streamable HTTP compliance:
        // * `Accept: application/json, text/event-stream` per spec §6.5
        //   (servers MAY respond with either; both branches are parsed below).
        // * Echo any captured `Mcp-Session-Id` so the server can route
        //   subsequent requests to the same logical session.
        let mut builder = self
            .headers
            .apply(Self::client()?.post(&self.base_url))
            .map_err(|error| McpError::Transport(format!("Invalid MCP HTTP header: {error}")))?
            .timeout(HTTP_REQUEST_TIMEOUT)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body(request_body);
        if context.version.era() == McpProtocolEra::Modern {
            builder = builder
                .header("MCP-Protocol-Version", context.version.as_str())
                .header("Mcp-Method", method);
            if let Some(name) = context.routing_name.as_deref() {
                builder = builder.header("Mcp-Name", encode_mcp_header_value(name));
            }
            for (name, value) in &context.parameter_headers {
                builder = builder.header(name, encode_mcp_header_value(value));
            }
        } else if let Some(sid) = self.session_id() {
            builder = builder.header("Mcp-Session-Id", sid);
        }
        let response = builder.send().await.map_err(|e| {
            if e.is_timeout() {
                // Per-request HTTP cap (`HTTP_REQUEST_TIMEOUT`)
                // fired. Phase reflects that this is a steady-state
                // request, not the connection-establishment
                // handshake (fix #628 — the latter is bounded by
                // `McpServer::new_with_config`).
                McpError::Timeout {
                    phase: "http-request",
                }
            } else {
                McpError::Transport(format!("HTTP request failed: {e}"))
            }
        })?;

        let status = response.status();

        // Capture `Mcp-Session-Id` if the server set one. Per spec the
        // server MAY emit it on the initialize response; once set, all
        // subsequent POSTs MUST echo it (handled above on the next call).
        if context.version.era() == McpProtocolEra::Legacy {
            if let Some(session_id) = response.headers().get("Mcp-Session-Id") {
                let sid = session_id.to_str().map_err(|_| {
                    McpError::Protocol(
                        "MCP server returned a non-ASCII session identifier".to_string(),
                    )
                })?;
                if !valid_mcp_session_id(sid) {
                    return Err(McpError::Protocol(
                        "MCP server returned an invalid session identifier".to_string(),
                    ));
                }
                if let Some(mut guard) = self.session_id_write_guard("request.store_session_id") {
                    *guard = Some(sid.to_string());
                }
            }
        }

        let response = match parse_http_json_rpc_response(response, &|text| {
            self.headers.sanitize_diagnostic(text).to_string()
        })
        .await
        {
            Ok(response) => response,
            Err(error @ McpError::ResponseTooLarge { .. }) => return Err(error),
            Err(_error) if !status.is_success() => {
                return Err(McpError::HttpStatus {
                    status: status.as_u16(),
                });
            }
            Err(error) => return Err(error),
        };

        // Fix #701 — JSON-RPC §5 requires response.id == request.id.
        // The pre-fix HTTP transport parsed `id` into the struct and
        // discarded it, so a buggy or hostile MCP HTTP server could
        // splice another caller's reply into this transport and the
        // client would silently return the wrong tool's result.
        // StdioTransport has always enforced this (same source file);
        // we mirror that check here with the shared dedicated variant.
        if response.id != id {
            return Err(McpError::ResponseIdMismatch {
                expected: id,
                got: response.id,
            });
        }

        if let Some(error) = response.error {
            return Err(typed_rpc_error(error, Some(status.as_u16()), &|text| {
                self.headers.sanitize_diagnostic(text).to_string()
            }));
        }
        if !status.is_success() {
            return Err(McpError::Transport(format!("HTTP error: {status}")));
        }

        Ok(response.result.unwrap_or(Value::Null))
    }

    async fn notify(&self, method: &str, params: Option<Value>) -> Result<(), McpError> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params.unwrap_or_else(|| json!({})),
        });
        let request_body = serde_json::to_vec(&request).map_err(|error| {
            McpError::Protocol(format!("Failed to serialize MCP notification: {error}"))
        })?;
        if request_body.len() > MAX_REQUEST_SIZE {
            return Err(McpError::RequestTooLarge {
                limit: MAX_REQUEST_SIZE,
            });
        }
        let mut builder = self
            .headers
            .apply(Self::client()?.post(&self.base_url))
            .map_err(|error| McpError::Transport(format!("Invalid MCP HTTP header: {error}")))?
            .timeout(HTTP_REQUEST_TIMEOUT)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .body(request_body);
        if let Some(session_id) = self.session_id() {
            builder = builder.header("Mcp-Session-Id", session_id);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| McpError::Transport(format!("HTTP notification failed: {error}")))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(McpError::Transport(format!(
                "HTTP notification error: {}",
                response.status()
            )))
        }
    }

    async fn close(&self) -> Result<(), McpError> {
        // The connection pool is shared, but a legacy Streamable HTTP session
        // is server-owned state and must be terminated independently. Current
        // discovery transports never capture a session id and remain a no-op.
        let session_id = self
            .session_id_write_guard("close.take_session_id")
            .and_then(|mut session_id| session_id.take());
        let Some(session_id) = session_id else {
            return Ok(());
        };
        let response = self
            .headers
            .apply(Self::client()?.delete(&self.base_url))
            .map_err(|error| McpError::Transport(format!("Invalid MCP HTTP header: {error}")))?
            .timeout(HTTP_REQUEST_TIMEOUT)
            .header("Mcp-Session-Id", session_id)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    McpError::Timeout {
                        phase: "http-session-close",
                    }
                } else {
                    McpError::Transport(format!("HTTP session termination failed: {error}"))
                }
            })?;
        match response.status().as_u16() {
            200 | 204 | 404 | 405 => Ok(()),
            status => Err(McpError::HttpStatus { status }),
        }
    }
}

/// Connection-establishment timeout default for [`McpServer::new`]
/// (fix #628).
///
/// CC `connectToServer` (`client.ts:1048-1077`) races `client.connect`
/// against a configurable deadline (default 30 s, env-tunable) so a
/// non-responsive MCP server cannot block an agent task indefinitely.
/// OC mirrors that behaviour: 30 s default, overridable per call via
/// [`McpServerConfig::initialize_timeout_secs`].
pub const DEFAULT_INITIALIZE_TIMEOUT_SECS: u64 = 30;

/// Per-server runtime configuration (fix #628).
///
/// Distinct from [`crate::plugins::manifest::McpServerConfig`] — that
/// type models the on-disk Claude-Code-compatible JSON describing
/// *how* to launch a server (command/args/env/url). This type models
/// *runtime* connection-policy knobs (timeouts) that callers tune at
/// the call site, not in the manifest.
#[derive(Debug, Clone, Copy)]
pub struct McpServerConfig {
    /// Hard deadline on the connection-establishment handshake
    /// (`initialize` + `tools/list`). On expiry,
    /// [`McpServer::new_with_config`] returns [`McpError::Timeout`]
    /// with `phase` naming the stage that stalled.
    ///
    /// `0` disables the deadline (the explicit opt-out used by tests
    /// that want to observe a real hang and by callers that supply
    /// their own outer cancellation scope).
    pub initialize_timeout_secs: u64,
}

impl McpServerConfig {
    /// Default configuration: 30 s initialize-handshake deadline.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initialize_timeout_secs: DEFAULT_INITIALIZE_TIMEOUT_SECS,
        }
    }

    /// Override the initialize-handshake deadline. Builder-style so
    /// call sites can write
    /// `McpServerConfig::new().with_initialize_timeout_secs(5)`.
    #[must_use]
    pub const fn with_initialize_timeout_secs(mut self, secs: u64) -> Self {
        self.initialize_timeout_secs = secs;
        self
    }
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// An MCP server connection
pub struct McpServer {
    name: String,
    transport: Box<dyn McpTransport>,
    adapter: McpProtocolAdapter,
    info: Option<McpServerInfo>,
    capabilities: McpCapabilities,
    tools: Vec<McpTool>,
}

impl McpServer {
    /// Create a new MCP server with the given transport, using the
    /// default [`McpServerConfig`] (30 s initialize-handshake
    /// deadline).
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] with `phase = "initialize"` or
    /// `phase = "tools/list"` if the corresponding handshake step
    /// does not complete within the configured deadline (fix #628).
    /// Returns other [`McpError`] variants on transport/protocol
    /// failures.
    pub async fn new(name: &str, transport: Box<dyn McpTransport>) -> Result<Self, McpError> {
        Self::new_with_config(name, transport, McpServerConfig::new()).await
    }

    /// Create a new MCP server with explicit runtime configuration.
    ///
    /// Wraps the connection-establishment handshake (`initialize` +
    /// `tools/list`) in [`tokio::time::timeout`] so a non-responsive
    /// server cannot block the calling task indefinitely (fix #628 —
    /// mirrors CC `connectToServer` racing `client.connect` against
    /// `getConnectionTimeoutMs()`).
    ///
    /// A `initialize_timeout_secs` of `0` disables the deadline.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Timeout`] with `phase = "initialize"` if
    /// the initialize handshake hangs, or `phase = "tools/list"` if
    /// the post-handshake tool discovery hangs. Returns other
    /// [`McpError`] variants on transport/protocol failures.
    pub async fn new_with_config(
        name: &str,
        transport: Box<dyn McpTransport>,
        config: McpServerConfig,
    ) -> Result<Self, McpError> {
        let mut server = Self {
            name: name.to_string(),
            transport,
            adapter: McpProtocolAdapter::current(),
            info: None,
            capabilities: McpCapabilities::default(),
            tools: Vec::new(),
        };

        // Fix #628 — bound the initialize handshake. A non-responsive
        // server would otherwise hang the calling tokio task forever
        // because `transport.request("initialize", ...)` has no
        // constructor-specific deadline. Steady-state transport requests have
        // their own independent caps.
        //
        // `tokio::time::timeout` cancels the inner future on expiry. The
        // transaction below always closes the transport after any handshake
        // failure so a timed-out stdio child is killed and reaped rather than
        // escaping an unsuccessful constructor.
        let outcome = if config.initialize_timeout_secs == 0 {
            match server.initialize().await {
                Ok(()) => server.refresh_tools().await,
                Err(error) => Err(error),
            }
        } else {
            let deadline = Duration::from_secs(config.initialize_timeout_secs);
            match tokio::time::timeout(deadline, server.initialize()).await {
                Err(_) => {
                    warn!(
                        server = %server.name,
                        timeout_secs = config.initialize_timeout_secs,
                        "MCP server initialize handshake timed out"
                    );
                    Err(McpError::Timeout {
                        phase: "initialize",
                    })
                }
                Ok(Err(error)) => Err(error),
                Ok(Ok(())) => match tokio::time::timeout(deadline, server.refresh_tools()).await {
                    Err(_) => {
                        warn!(
                            server = %server.name,
                            timeout_secs = config.initialize_timeout_secs,
                            "MCP server tools/list timed out"
                        );
                        Err(McpError::Timeout {
                            phase: "tools/list",
                        })
                    }
                    Ok(result) => result,
                },
            }
        };

        if let Err(error) = outcome {
            let server_name = server.name.clone();
            if let Err(close_error) = server.close().await {
                warn!(server = %server_name, error = %close_error, "Failed to close rejected MCP connection");
            }
            return Err(error);
        }

        Ok(server)
    }

    /// Negotiate the server era, using modern discovery first and an explicit
    /// initialization-based adapter only when the binding's fallback rules
    /// identify a legacy server.
    async fn initialize(&mut self) -> Result<(), McpError> {
        match self.discover_current().await {
            Ok(()) => self.log_connected("discovered"),
            Err(error) if should_fall_back_to_legacy(self.transport.binding(), &error) => {
                debug!(server = %self.name, error = %error, "MCP server is legacy; using initialize adapter");
                self.initialize_legacy().await?;
                self.log_connected("initialized");
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // One negotiation transaction validates one authoritative profile.
    async fn discover_current(&mut self) -> Result<(), McpError> {
        let adapter = McpProtocolAdapter::current();
        let params = adapter
            .request_params(None, self.transport.client_capabilities())
            .map_err(McpError::Protocol)?;
        let result = self
            .transport
            .request_with_context(
                adapter.request_context(None),
                "server/discover",
                Some(params),
            )
            .await
            .map_err(|error| match error {
                McpError::Rpc {
                    code: -32022,
                    data: Some(data),
                    ..
                } => {
                    let requested = data
                        .get("requested")
                        .and_then(Value::as_str)
                        .unwrap_or(CURRENT_PROTOCOL_VERSION)
                        .to_string();
                    let supported = data
                        .get("supported")
                        .and_then(Value::as_array)
                        .map(|versions| {
                            versions
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    McpError::UnsupportedProtocolVersion {
                        requested,
                        supported,
                    }
                }
                other => other,
            })?;
        adapter
            .require_complete_result("server/discover", &result)
            .map_err(McpError::UnsupportedCapability)?;

        let supported = result
            .get("supportedVersions")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                McpError::Protocol(format!(
                    "MCP server '{}' discovery response is missing supportedVersions",
                    self.name
                ))
            })?
            .iter()
            .map(|version| {
                version.as_str().map(str::to_string).ok_or_else(|| {
                    McpError::Protocol(format!(
                        "MCP server '{}' discovery returned a non-string protocol version",
                        self.name
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !supported
            .iter()
            .any(|version| version == CURRENT_PROTOCOL_VERSION)
        {
            return Err(McpError::UnsupportedProtocolVersion {
                requested: CURRENT_PROTOCOL_VERSION.to_string(),
                supported,
            });
        }

        let capabilities = result.get("capabilities").ok_or_else(|| {
            McpError::Protocol(format!(
                "MCP server '{}' discovery response is missing capabilities",
                self.name
            ))
        })?;
        if !capabilities.is_object() {
            return Err(McpError::Protocol(format!(
                "MCP server '{}' discovery response has non-object capabilities",
                self.name
            )));
        }
        self.capabilities = serde_json::from_value(capabilities.clone()).map_err(|error| {
            McpError::Protocol(format!(
                "MCP server '{}' discovery capabilities are invalid: {error}",
                self.name
            ))
        })?;

        if let Some(info) = result.pointer("/_meta/io.modelcontextprotocol~1serverInfo") {
            let info: McpServerInfo = serde_json::from_value(info.clone()).map_err(|error| {
                McpError::Protocol(format!(
                    "MCP server '{}' discovery serverInfo is invalid: {error}",
                    self.name
                ))
            })?;
            if info.version.as_deref().is_none_or(str::is_empty) {
                return Err(McpError::Protocol(format!(
                    "MCP server '{}' discovery serverInfo is missing version",
                    self.name
                )));
            }
            self.info = Some(info);
        }
        if !result.get("ttlMs").is_some_and(Value::is_u64)
            || !matches!(
                result.get("cacheScope").and_then(Value::as_str),
                Some("private" | "public")
            )
        {
            return Err(McpError::Protocol(format!(
                "MCP server '{}' discovery response has invalid cache metadata",
                self.name
            )));
        }
        self.adapter = adapter;
        Ok(())
    }

    async fn initialize_legacy(&mut self) -> Result<(), McpError> {
        let params = json!({
            "protocolVersion": PREFERRED_LEGACY_PROTOCOL_VERSION,
            "capabilities": self.transport.client_capabilities(),
            "clientInfo": {
                "name": "openclaudia",
                "version": env!("CARGO_PKG_VERSION")
            }
        });

        let result = self.transport.request("initialize", Some(params)).await?;

        let selected = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .and_then(McpProtocolVersion::parse)
            .filter(|version| version.era() == McpProtocolEra::Legacy)
            .unwrap_or_else(|| {
                warn!(
                    server = %self.name,
                    "Legacy MCP initialize omitted a supported protocolVersion; preserving the bounded 2024-11-05 compatibility path"
                );
                McpProtocolVersion::V2024_11_05
            });
        self.adapter = McpProtocolAdapter::new(selected);

        // Parse server info and capabilities
        if let Some(info) = result.get("serverInfo") {
            if !info.is_object() {
                return Err(McpError::Protocol(format!(
                    "MCP server '{}' initialize response has non-object serverInfo: {info}",
                    self.name
                )));
            }
            self.info = Some(serde_json::from_value(info.clone()).map_err(|e| {
                McpError::Protocol(format!(
                    "MCP server '{}' initialize response has invalid serverInfo: {e}; \
                     serverInfo: {info}",
                    self.name
                ))
            })?);
        }

        if let Some(caps) = result.get("capabilities") {
            if !caps.is_object() {
                return Err(McpError::Protocol(format!(
                    "MCP server '{}' initialize response has non-object capabilities: {caps}",
                    self.name
                )));
            }
            self.capabilities = serde_json::from_value(caps.clone()).map_err(|e| {
                McpError::Protocol(format!(
                    "MCP server '{}' initialize response has invalid capabilities: {e}; \
                     capabilities: {caps}",
                    self.name
                ))
            })?;
        }

        if let Err(error) = self
            .transport
            .notify("notifications/initialized", Some(json!({})))
            .await
        {
            warn!(server = %self.name, error = %error, "MCP initialized notification was not accepted");
        }

        Ok(())
    }

    fn log_connected(&self, lifecycle: &'static str) {
        // Log server info with name and version
        let server_name = self.info.as_ref().map_or("unknown", |i| i.name.as_str());
        let server_version = self
            .info
            .as_ref()
            .and_then(|i| i.version.as_deref())
            .unwrap_or("unknown");

        // Log capabilities for debugging
        let has_tools = self.capabilities.tools.is_some();
        let has_resources = self.capabilities.resources.is_some();
        let has_prompts = self.capabilities.prompts.is_some();

        info!(
            server = %self.name,
            remote_name = %server_name,
            remote_version = %server_version,
            has_tools = has_tools,
            has_resources = has_resources,
            has_prompts = has_prompts,
            protocol_version = %self.adapter.version(),
            lifecycle,
            "MCP server connected"
        );
    }

    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
        routing_name: Option<String>,
        parameter_headers: Vec<(String, String)>,
    ) -> Result<Value, McpError> {
        let params = self
            .adapter
            .request_params(params, self.transport.client_capabilities())
            .map_err(McpError::Protocol)?;
        let mut params = params;
        if self.adapter.era() == McpProtocolEra::Modern {
            if let Some(meta) = params.get_mut("_meta").and_then(Value::as_object_mut) {
                meta.insert(
                    "progressToken".to_string(),
                    Value::String(uuid::Uuid::new_v4().to_string()),
                );
            }
        }
        let mut context = self.adapter.request_context(routing_name);
        context.parameter_headers = parameter_headers;
        self.transport
            .request_with_context(context, method, Some(params))
            .await
    }

    async fn list_paginated<T: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        field: &'static str,
    ) -> Result<Vec<T>, McpError> {
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        for page in 0..MAX_MCP_CATALOG_PAGES {
            let params = cursor
                .as_ref()
                .map_or_else(|| json!({}), |cursor| json!({"cursor": cursor}));
            let result = self.request(method, Some(params), None, Vec::new()).await?;
            self.adapter
                .require_complete_result(method, &result)
                .map_err(McpError::UnsupportedCapability)?;
            self.adapter
                .require_cache_metadata(method, &result)
                .map_err(McpError::Protocol)?;
            items.extend(parse_array_field(&self.name, method, field, &result)?);
            let next = result
                .get("nextCursor")
                .and_then(Value::as_str)
                .filter(|next| !next.is_empty())
                .map(str::to_string);
            if next.is_none() {
                return Ok(items);
            }
            if page + 1 == MAX_MCP_CATALOG_PAGES {
                return Err(McpError::Protocol(format!(
                    "MCP server '{}' {method} exceeded {MAX_MCP_CATALOG_PAGES} pages",
                    self.name
                )));
            }
            if next == cursor {
                return Err(McpError::Protocol(format!(
                    "MCP server '{}' {method} repeated its pagination cursor",
                    self.name
                )));
            }
            cursor = next;
        }
        Ok(items)
    }

    /// Exact wire profile selected for this server.
    #[must_use]
    pub const fn protocol_version(&self) -> McpProtocolVersion {
        self.adapter.version()
    }

    /// Whether the server advertised the `tools` capability during the
    /// `initialize` handshake (fix #627).
    ///
    /// Mirrors `has_resources`. Used to gate `tools/list` so we do not
    /// issue an RPC against a server that declared no tools support —
    /// CC `fetchToolsForClient` (`client.ts:1748-1751`) returns `[]`
    /// without making the wire call in that case.
    #[must_use]
    pub const fn has_tools_capability(&self) -> bool {
        self.capabilities.tools.is_some()
    }

    /// Refresh the list of available tools.
    ///
    /// Per fix #627, this is a no-op when the server did not advertise
    /// the `tools` capability during the `initialize` handshake.
    /// `tools/list` against a non-tools server is a wasted round-trip
    /// at best and an RPC-level error at worst; CC short-circuits the
    /// same way in `fetchToolsForClient`. The local tool list is left
    /// untouched (so a previously-populated list survives a
    /// capability-less refresh) and `Ok(())` is returned.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if the tools/list request fails.
    pub async fn refresh_tools(&mut self) -> Result<(), McpError> {
        // Fix #627 — capability gate. The pre-fix path issued
        // `tools/list` unconditionally, producing a spurious RPC and
        // (on strict servers) a JSON-RPC error.
        if !self.has_tools_capability() {
            debug!(
                server = %self.name,
                "Skipping tools/list — server did not advertise tools capability"
            );
            return Ok(());
        }

        let mut tools: Vec<McpTool> = self.list_paginated("tools/list", "tools").await?;
        if self.adapter.era() == McpProtocolEra::Modern
            && tools.iter().any(|tool| tool.input_schema.is_none())
        {
            return Err(McpError::Protocol(format!(
                "MCP server '{}' returned a current tool without inputSchema",
                self.name
            )));
        }
        if self.adapter.era() == McpProtocolEra::Modern
            && self.transport.binding() == McpTransportBinding::StreamableHttp
        {
            tools.retain(
                |tool| match extract_mcp_parameter_headers(tool, &json!({})) {
                    Ok(_) => true,
                    Err(error) => {
                        warn!(
                            server = %self.name,
                            tool = %tool.name,
                            error = %error,
                            "Excluding MCP tool with invalid HTTP header annotations"
                        );
                        false
                    }
                },
            );
        }
        self.tools = tools;

        // Check if server supports tool list change notifications
        let supports_list_changed = self
            .capabilities
            .tools
            .as_ref()
            .is_some_and(|t| t.list_changed);

        info!(
            server = %self.name,
            tool_count = self.tools.len(),
            list_changed_supported = supports_list_changed,
            "Discovered MCP tools"
        );

        Ok(())
    }

    /// Check if the server supports tool list change notifications
    #[must_use]
    pub fn supports_tool_list_changed(&self) -> bool {
        self.capabilities
            .tools
            .as_ref()
            .is_some_and(|t| t.list_changed)
    }

    /// Get the list of available tools
    #[must_use]
    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }

    /// Call a tool.
    ///
    /// Per fix #625, the result envelope is inspected for the
    /// `isError: true` flag defined by the MCP spec (and exercised by
    /// CC `callMCPTool` in `client.ts:3124-3148`). When set, the call
    /// is surfaced as [`McpError::ToolReportedError`] carrying the
    /// human-readable text extracted from `content[0].text` — a
    /// tool-level failure must NOT be returned to the caller as if it
    /// were a successful result.
    ///
    /// # Errors
    ///
    /// Returns `McpError::ToolNotFound` if the tool is not registered,
    /// `McpError::ToolReportedError` if the server reported a
    /// tool-execution failure via `isError: true`, or a
    /// transport/protocol error if the request fails.
    #[allow(clippy::too_many_lines)] // Dispatch, typed validation, and tool-error interpretation are one boundary.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value, McpError> {
        if !self.tools.iter().any(|t| t.name == name) {
            return Err(McpError::ToolNotFound(name.to_string()));
        }

        let params = json!({
            "name": name,
            "arguments": arguments
        });

        debug!(server = %self.name, tool = %name, "Calling MCP tool");

        let parameter_headers = if self.transport.binding() == McpTransportBinding::StreamableHttp
            && self.adapter.era() == McpProtocolEra::Modern
        {
            let tool = self
                .tools
                .iter()
                .find(|tool| tool.name == name)
                .ok_or_else(|| McpError::ToolNotFound(name.to_string()))?;
            extract_mcp_parameter_headers(tool, &arguments)?
        } else {
            Vec::new()
        };
        let result = self
            .request(
                "tools/call",
                Some(params),
                Some(name.to_string()),
                parameter_headers,
            )
            .await?;
        self.adapter
            .require_complete_result("tools/call", &result)
            .map_err(McpError::UnsupportedCapability)?;
        if self.adapter.era() == McpProtocolEra::Modern
            && !result.get("content").is_some_and(Value::is_array)
        {
            return Err(McpError::Protocol(format!(
                "MCP server '{}' current tools/call result for '{name}' is missing content",
                self.name
            )));
        }

        let typed: McpCallToolResult = serde_json::from_value(result.clone()).map_err(|error| {
            McpError::Protocol(format!(
                "MCP server '{}' tools/call result for '{name}' is invalid: {error}",
                self.name
            ))
        })?;
        for block in &typed.content {
            if let Some((encoded, media_type)) = block.encoded_media() {
                if media_type.is_empty() || !media_type.is_ascii() {
                    return Err(McpError::Protocol(format!(
                        "MCP tool '{name}' returned media with an invalid MIME type"
                    )));
                }
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| {
                        McpError::Protocol(format!(
                            "MCP tool '{name}' returned invalid base64 media content"
                        ))
                    })?;
            }
        }
        if let Some(output_schema) = self
            .tools
            .iter()
            .find(|tool| tool.name == name)
            .and_then(|tool| tool.output_schema.as_ref())
        {
            let Some(structured) = typed.structured_content.as_ref() else {
                return Err(McpError::Protocol(format!(
                    "MCP tool '{name}' advertised outputSchema but returned no structuredContent"
                )));
            };
            let validator = if output_schema.get("$schema").is_some() {
                jsonschema::validator_for(output_schema)
            } else {
                jsonschema::draft202012::new(output_schema)
            }
            .map_err(|_| {
                McpError::Protocol(format!(
                    "MCP tool '{name}' advertised an invalid outputSchema"
                ))
            })?;
            if !validator.is_valid(structured) {
                return Err(McpError::Protocol(format!(
                    "MCP tool '{name}' structuredContent does not satisfy outputSchema"
                )));
            }
        }

        // Fix #625 — per MCP spec, a tool result of the shape
        // `{"content": [...], "isError": true}` signals tool-level
        // failure. Pre-fix this was returned verbatim to the caller,
        // so the LLM saw a tool error as if it were a normal result.
        // Match CC `callMCPTool`: extract `content[0].text` (or any
        // `text` field in the content array) as the error message,
        // falling back to a generic placeholder if the server emitted
        // `isError: true` with no usable content block.
        if typed.is_error {
            let message = typed
                .content
                .iter()
                .find_map(McpContentBlock::text)
                .map_or_else(
                    || format!("MCP tool '{name}' returned isError with no content"),
                    ToString::to_string,
                );

            debug!(
                server = %self.name,
                tool = %name,
                message = %message,
                "MCP tool reported isError"
            );

            return Err(McpError::ToolReportedError { message, result });
        }

        Ok(result)
    }

    /// Check if the server advertises resource capabilities
    #[must_use]
    pub const fn has_resources(&self) -> bool {
        self.capabilities.resources.is_some()
    }

    /// List resources available on this server.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if the resources/list request fails.
    pub async fn list_resources(&self) -> Result<Vec<McpResource>, McpError> {
        if !self.has_resources() {
            return Ok(Vec::new());
        }

        let resources: Vec<McpResource> =
            self.list_paginated("resources/list", "resources").await?;

        debug!(
            server = %self.name,
            resource_count = resources.len(),
            "Listed MCP resources"
        );

        Ok(resources)
    }

    /// Read a specific resource by URI.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if the resources/read request fails.
    pub async fn read_resource_typed(&self, uri: &str) -> Result<McpReadResourceResult, McpError> {
        let params = json!({ "uri": uri });

        debug!(server = %self.name, uri = %uri, "Reading MCP resource");

        let result = self
            .request(
                "resources/read",
                Some(params),
                Some(uri.to_string()),
                Vec::new(),
            )
            .await?;
        self.adapter
            .require_complete_result("resources/read", &result)
            .map_err(McpError::UnsupportedCapability)?;
        self.adapter
            .require_cache_metadata("resources/read", &result)
            .map_err(McpError::Protocol)?;
        let typed: McpReadResourceResult = serde_json::from_value(result).map_err(|error| {
            McpError::Protocol(format!(
                "MCP server '{}' resources/read result for '{uri}' is invalid: {error}",
                self.name
            ))
        })?;
        for content in &typed.contents {
            if let McpResourceContents::Blob { blob, .. } = content {
                base64::engine::general_purpose::STANDARD
                    .decode(blob)
                    .map_err(|_| {
                        McpError::Protocol(format!(
                            "MCP resource '{uri}' returned invalid base64 blob content"
                        ))
                    })?;
            }
        }
        Ok(typed)
    }

    /// Compatibility projection for existing text-only resource callers.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` when the resource request or typed decoding fails.
    pub async fn read_resource(&self, uri: &str) -> Result<String, McpError> {
        let result = self.read_resource_typed(uri).await?;
        Ok(project_mcp_resource_text(&result))
    }

    /// List prompt templates when the negotiated server advertises them.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` when prompt pagination or decoding fails.
    pub async fn list_prompts(&self) -> Result<Vec<McpPrompt>, McpError> {
        if self.capabilities.prompts.is_none() {
            return Ok(Vec::new());
        }
        self.list_paginated("prompts/list", "prompts").await
    }

    /// Resolve one prompt without flattening its typed content blocks.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` when prompts are unsupported or resolution fails.
    pub async fn get_prompt(
        &self,
        name: &str,
        arguments: BTreeMap<String, String>,
    ) -> Result<McpGetPromptResult, McpError> {
        if self.capabilities.prompts.is_none() {
            return Err(McpError::UnsupportedCapability(format!(
                "server '{}' did not advertise prompts",
                self.name
            )));
        }
        let result = self
            .request(
                "prompts/get",
                Some(json!({"name": name, "arguments": arguments})),
                Some(name.to_string()),
                Vec::new(),
            )
            .await?;
        self.adapter
            .require_complete_result("prompts/get", &result)
            .map_err(McpError::UnsupportedCapability)?;
        serde_json::from_value(result).map_err(|error| {
            McpError::Protocol(format!(
                "MCP server '{}' prompts/get result for '{name}' is invalid: {error}",
                self.name
            ))
        })
    }

    /// Get server name
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Close the connection.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if the transport fails to close.
    pub async fn close(self) -> Result<(), McpError> {
        self.transport.close().await
    }
}

fn parse_array_field<T: serde::de::DeserializeOwned>(
    server_name: &str,
    operation: &str,
    field: &str,
    result: &Value,
) -> Result<Vec<T>, McpError> {
    result
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            McpError::Protocol(format!(
                "MCP server '{server_name}' {operation} response missing '{field}' array: {result}"
            ))
        })?
        .iter()
        .enumerate()
        .map(|(index, item)| {
            serde_json::from_value(item.clone()).map_err(|error| {
                McpError::Protocol(format!(
                    "MCP server '{server_name}' {operation} entry at index {index} is invalid: {error}; entry: {item}"
                ))
            })
        })
        .collect()
}

fn valid_mcp_header_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn extract_mcp_parameter_headers(
    tool: &McpTool,
    arguments: &Value,
) -> Result<Vec<(String, String)>, McpError> {
    let Some(schema) = tool.input_schema.as_ref() else {
        return Ok(Vec::new());
    };
    let mut headers = BTreeMap::<String, (String, Option<String>)>::new();
    inspect_mcp_header_schema(
        &tool.name,
        schema,
        arguments,
        &mut Vec::new(),
        false,
        true,
        &mut headers,
    )?;
    Ok(headers
        .into_values()
        .filter_map(|(name, value)| value.map(|value| (format!("Mcp-Param-{name}"), value)))
        .collect())
}

fn inspect_mcp_header_schema(
    tool_name: &str,
    schema: &Value,
    arguments: &Value,
    argument_path: &mut Vec<String>,
    is_reachable_property: bool,
    static_chain: bool,
    headers: &mut BTreeMap<String, (String, Option<String>)>,
) -> Result<(), McpError> {
    let Some(object) = schema.as_object() else {
        return Ok(());
    };
    if let Some(annotation) = object.get("x-mcp-header") {
        if !is_reachable_property || !static_chain {
            return Err(McpError::InvalidToolSchema {
                tool: tool_name.to_string(),
                reason: "x-mcp-header appears outside a statically reachable property".to_string(),
            });
        }
        let name = annotation
            .as_str()
            .filter(|name| valid_mcp_header_token(name))
            .ok_or_else(|| McpError::InvalidToolSchema {
                tool: tool_name.to_string(),
                reason: "x-mcp-header must be a non-empty HTTP field-name token".to_string(),
            })?;
        let value_type = object.get("type").and_then(Value::as_str);
        if !matches!(value_type, Some("string" | "integer" | "boolean")) {
            return Err(McpError::InvalidToolSchema {
                tool: tool_name.to_string(),
                reason: "x-mcp-header is allowed only on string, integer, or boolean properties"
                    .to_string(),
            });
        }
        let key = name.to_ascii_lowercase();
        if headers.contains_key(&key) {
            return Err(McpError::InvalidToolSchema {
                tool: tool_name.to_string(),
                reason: format!("duplicate x-mcp-header name '{name}'"),
            });
        }
        let instance = argument_path
            .iter()
            .try_fold(arguments, |value, component| value.get(component));
        if let Some(instance) = instance.filter(|value| !value.is_null()) {
            let value = match (value_type, instance) {
                (Some("string"), Value::String(value)) => value.clone(),
                (Some("integer"), Value::Number(value)) => {
                    let integer = value
                        .as_i64()
                        .ok_or_else(|| McpError::InvalidToolArguments {
                            tool: tool_name.to_string(),
                        })?;
                    if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&integer) {
                        return Err(McpError::InvalidToolArguments {
                            tool: tool_name.to_string(),
                        });
                    }
                    integer.to_string()
                }
                (Some("boolean"), Value::Bool(value)) => value.to_string(),
                _ => {
                    return Err(McpError::InvalidToolArguments {
                        tool: tool_name.to_string(),
                    });
                }
            };
            headers.insert(key, (name.to_string(), Some(value)));
        } else {
            headers.insert(key, (name.to_string(), None));
        }
    }

    for (keyword, child) in object {
        if keyword == "properties" {
            if let Some(properties) = child.as_object() {
                for (property, property_schema) in properties {
                    argument_path.push(property.clone());
                    inspect_mcp_header_schema(
                        tool_name,
                        property_schema,
                        arguments,
                        argument_path,
                        true,
                        static_chain,
                        headers,
                    )?;
                    argument_path.pop();
                }
            }
        } else if keyword != "x-mcp-header" {
            inspect_mcp_header_schema(
                tool_name,
                child,
                arguments,
                argument_path,
                false,
                false,
                headers,
            )?;
        }
    }
    Ok(())
}

/// Named MCP transports that do not have standalone builders here.
///
/// The MCP spec defines several streaming transports:
///
/// * **`Sse`** — Server-Sent Events (`text/event-stream`) one-way push from
///   the server, paired with a separate HTTP POST for the client→server
///   direction.
/// * **`WebSocket`** — full-duplex `ws://` / `wss://` channel.
/// * **`StreamableHttp`** — the current MCP-canonical HTTP transport with
///   bidirectional streaming over a single endpoint (spec §6.5).
///
/// Runtime plugin config normalizes `streamable-http` to `http`, so the
/// regular [`HttpTransport`] handles JSON responses, `text/event-stream`
/// response bodies, `Accept`, and `Mcp-Session-Id`. This enum remains for
/// callers that need a typed diagnostic for deprecated standalone SSE or
/// future WebSocket support rather than silently treating those names as
/// typos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpTransportKind {
    /// `text/event-stream` server-push branch — landing under #630-SSE.
    Sse,
    /// Full-duplex WebSocket transport — landing under #630-WS.
    WebSocket,
    /// Streamable HTTP is implemented by [`HttpTransport`] in runtime config.
    StreamableHttp,
}

impl McpTransportKind {
    /// Human-readable name suitable for error messages.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Sse => "Server-Sent Events",
            Self::WebSocket => "WebSocket",
            Self::StreamableHttp => "Streamable HTTP",
        }
    }

    /// Construct a transport of this kind.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::Transport`] with guidance for transports that
    /// should be routed through existing config (`streamable-http`) or that
    /// remain on the roadmap (`sse`, `websocket`).
    pub fn build_stub_transport(&self, _url: &str) -> Result<Box<dyn McpTransport>, McpError> {
        match self {
            Self::StreamableHttp => Err(McpError::Transport(
                "Streamable HTTP MCP transport is implemented by the `http` transport; \
                 use `type: \"http\"` or `type: \"streamable-http\"` in config"
                    .to_string(),
            )),
            Self::Sse | Self::WebSocket => Err(McpError::Transport(format!(
                "{} MCP transport is not yet implemented (crosslink #630); \
                 use `stdio` or `http` for now",
                self.label()
            ))),
        }
    }
}

/// Connection blueprint used by [`McpManager`] to rebuild a transport
/// after a disconnect (fix #629).
#[derive(Debug, Clone)]
enum ConnectionSpec {
    Stdio {
        command: String,
        args: Vec<String>,
        env: crate::secrets::EnvironmentGrants,
    },
    Http {
        url: String,
        headers: crate::secrets::SensitiveHeaders,
        headers_helper: Option<String>,
        server_name: String,
    },
}

impl ConnectionSpec {
    const fn binding(&self) -> McpTransportBinding {
        match self {
            Self::Stdio { .. } => McpTransportBinding::Stdio,
            Self::Http { .. } => McpTransportBinding::StreamableHttp,
        }
    }

    const fn required_resource(&self) -> crate::tools::ToolResource {
        match self {
            Self::Stdio { .. } => crate::tools::ToolResource::Process,
            Self::Http { .. } => crate::tools::ToolResource::Network,
        }
    }

    fn build_transport(
        &self,
        run: &Arc<crate::tools::ToolRunContext>,
    ) -> Result<Box<dyn McpTransport>, McpError> {
        run.require(self.required_resource())?;
        match self {
            Self::Stdio { command, args, env } => {
                let argv: Vec<&str> = args.iter().map(String::as_str).collect();
                Ok(Box::new(StdioTransport::spawn_with_protected_env(
                    run, command, &argv, env,
                )?))
            }
            Self::Http {
                url,
                headers,
                headers_helper,
                server_name,
            } => {
                let headers = resolve_http_headers(
                    run,
                    server_name,
                    url,
                    headers,
                    headers_helper.as_deref(),
                )?;
                Ok(Box::new(HttpTransport::new_with_sensitive_headers(
                    url, headers,
                )?))
            }
        }
    }
}

fn resolve_http_headers(
    run: &Arc<crate::tools::ToolRunContext>,
    server_name: &str,
    url: &str,
    static_headers: &crate::secrets::SensitiveHeaders,
    headers_helper: Option<&str>,
) -> Result<crate::secrets::SensitiveHeaders, McpError> {
    let mut headers = static_headers.clone();
    if let Some(helper) = headers_helper {
        let dynamic = run_headers_helper(run, helper, server_name, url)?;
        merge_dynamic_headers(&mut headers, &dynamic);
    }
    Ok(headers)
}

fn merge_dynamic_headers(
    headers: &mut crate::secrets::SensitiveHeaders,
    dynamic: &crate::secrets::SensitiveHeaders,
) {
    headers.extend(dynamic);
}

fn run_headers_helper(
    run: &Arc<crate::tools::ToolRunContext>,
    command: &str,
    server_name: &str,
    url: &str,
) -> Result<crate::secrets::SensitiveHeaders, McpError> {
    if command.trim().is_empty() {
        return Err(McpError::Transport(format!(
            "MCP headersHelper for server '{server_name}' is empty"
        )));
    }

    let mut env = HashMap::new();
    env.insert(
        "CLAUDE_CODE_MCP_SERVER_NAME".to_string(),
        server_name.to_string(),
    );
    env.insert("CLAUDE_CODE_MCP_SERVER_URL".to_string(), url.to_string());

    let (program, args) = shell_command(command);
    let program = resolve_trusted_mcp_executable(run, program)?;
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = crate::tools::command::run_sandboxed_with_timeout_with_env(
        run,
        crate::tools::SandboxProfile::McpHeaderHelper,
        &program,
        &arg_refs,
        run.working_directory(),
        HEADERS_HELPER_TIMEOUT,
        &env,
    )
    .map_err(|e| {
        McpError::Transport(format!(
            "MCP headersHelper for server '{server_name}' failed: {e}"
        ))
    })?;

    if !output.status.success() {
        let status = output.status.code().map_or_else(
            || "terminated by signal".to_string(),
            |code| code.to_string(),
        );
        return Err(McpError::Transport(format!(
            "MCP headersHelper for server '{server_name}' exited with status {status}"
        )));
    }

    let stdout = zeroize::Zeroizing::new(output.stdout);
    parse_headers_helper_stdout(server_name, &stdout)
}

fn shell_command(command: &str) -> (&'static str, Vec<String>) {
    #[cfg(windows)]
    {
        ("cmd", vec!["/C".to_string(), command.to_string()])
    }
    #[cfg(not(windows))]
    {
        ("sh", vec!["-c".to_string(), command.to_string()])
    }
}

fn parse_headers_helper_stdout(
    server_name: &str,
    stdout: &[u8],
) -> Result<crate::secrets::SensitiveHeaders, McpError> {
    serde_json::from_slice(stdout).map_err(|e| {
        McpError::Protocol(format!(
            "MCP headersHelper for server '{server_name}' did not emit valid JSON: {e}"
        ))
    })
}

/// Max reconnect attempts before [`McpError::ServerUnreachable`] (fix #629).
const MAX_RECONNECT_ATTEMPTS: u32 = 3;

/// Per-attempt backoff: 1 s / 5 s / 30 s per crosslink #629.
const BACKOFF: [Duration; MAX_RECONNECT_ATTEMPTS as usize] = [
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(30),
];

fn validate_mcp_server_identity(name: &str) -> Result<(), McpError> {
    if crate::config::valid_mcp_server_identity(name) {
        Ok(())
    } else {
        Err(McpError::Protocol(format!(
            "Invalid MCP server identity '{name}': expected 1..={} ASCII identifier bytes and no '__' separator",
            crate::config::MAX_MCP_IDENTITY_COMPONENT_BYTES
        )))
    }
}

fn split_mcp_tool_identity(full_name: &str) -> Result<(&str, &str), McpError> {
    if full_name.len() > crate::tools::catalog::MAX_CANONICAL_TOOL_NAME_BYTES {
        return Err(McpError::ToolNotFound(format!(
            "MCP tool identity exceeds {} bytes: {full_name}",
            crate::tools::catalog::MAX_CANONICAL_TOOL_NAME_BYTES
        )));
    }
    let mut parts = full_name.splitn(3, "__");
    let prefix = parts.next();
    let server = parts.next();
    let tool = parts.next();
    let (Some("mcp"), Some(server), Some(tool)) = (prefix, server, tool) else {
        return Err(McpError::ToolNotFound(format!(
            "Invalid tool name format: {full_name}. Expected mcp__servername__toolname"
        )));
    };
    if !crate::config::valid_mcp_server_identity(server)
        || !crate::config::valid_mcp_tool_identity(tool)
    {
        return Err(McpError::ToolNotFound(format!(
            "Invalid MCP tool identity: {full_name}"
        )));
    }
    Ok((server, tool))
}

fn effective_mcp_input_schema(tool: &McpTool) -> Value {
    tool.input_schema.clone().unwrap_or_else(|| {
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    })
}

fn compile_mcp_input_schema(schema: &Value) -> Result<jsonschema::Validator, String> {
    let Some(object) = schema.as_object() else {
        return Err("inputSchema must be a JSON Schema object".to_string());
    };
    if object.get("type").and_then(Value::as_str) != Some("object") {
        return Err("inputSchema root must declare type 'object'".to_string());
    }
    let compiled = if object.contains_key("$schema") {
        jsonschema::validator_for(schema)
    } else {
        jsonschema::draft202012::new(schema)
    };
    compiled.map_err(|_| {
        "inputSchema is invalid or requires an unavailable external schema resource".to_string()
    })
}

#[derive(Clone, Copy)]
struct McpRegistrationContext<'a> {
    epoch: u64,
    run_generation: u64,
    connection_generation: u64,
    server_name: &'a str,
    trust: &'a McpServerTrust,
    available: bool,
}

fn mcp_registration_definition(
    context: McpRegistrationContext<'_>,
    tool: &McpTool,
    schema: &Value,
) -> Value {
    let McpRegistrationContext {
        epoch,
        run_generation,
        connection_generation,
        server_name,
        trust,
        available,
    } = context;
    json!({
        "type": "function",
        "function": {
            "name": format!("mcp__{server_name}__{}", tool.name),
            "description": tool.description.as_deref().unwrap_or(""),
            "parameters": schema,
        },
        "x-openclaudia-mcp-registration": {
            "contract": "openclaudia.mcp-tool-registration.v1",
            "run_generation": run_generation,
            "connection_generation": connection_generation,
            "manager_epoch": epoch,
            "server": server_name,
            "tool": tool.name,
            "trust": trust.registration_identity(),
            "available": available,
        }
    })
}

fn mcp_definition_digest(definition: &Value) -> Result<crate::runtime::ContentDigest, McpError> {
    serde_json::to_vec(definition)
        .map(|encoded| crate::runtime::ContentDigest::sha256(&encoded))
        .map_err(|error| McpError::Protocol(format!("Cannot hash MCP tool registration: {error}")))
}

struct ServerEntry {
    spec: ConnectionSpec,
    trust: McpServerTrust,
    server: Option<McpServer>,
    tool_timeout: Option<Duration>,
    failed_attempts: u32,
    last_failure: Option<std::time::Instant>,
    cached_tools: Vec<McpTool>,
    supports_list_changed: bool,
    connection_generation: u64,
}

impl ServerEntry {
    fn new(spec: ConnectionSpec, server: McpServer) -> Self {
        Self::new_with_trust_and_tool_timeout(spec, server, McpServerTrust::HostConfigured, None)
    }

    fn new_with_trust_and_tool_timeout(
        spec: ConnectionSpec,
        server: McpServer,
        trust: McpServerTrust,
        tool_timeout: Option<Duration>,
    ) -> Self {
        let cached_tools = server.tools().to_vec();
        let supports_list_changed = server.supports_tool_list_changed();
        Self {
            spec,
            trust,
            server: Some(server),
            tool_timeout,
            failed_attempts: 0,
            last_failure: None,
            cached_tools,
            supports_list_changed,
            connection_generation: NEXT_MCP_CONNECTION_GENERATION.fetch_add(1, Ordering::AcqRel),
        }
    }

    async fn retire_connection(&mut self) -> Result<(), McpError> {
        let close = if let Some(server) = self.server.take() {
            server.close().await
        } else {
            Ok(())
        };
        self.cached_tools.clear();
        self.supports_list_changed = false;
        self.last_failure = Some(std::time::Instant::now());
        close
    }

    const fn is_permanently_unreachable(&self) -> bool {
        self.server.is_none() && self.failed_attempts >= MAX_RECONNECT_ATTEMPTS
    }

    fn backoff_elapsed(&self) -> bool {
        let Some(last) = self.last_failure else {
            return true;
        };
        let idx = (self.failed_attempts as usize).min(BACKOFF.len() - 1);
        last.elapsed() >= BACKOFF[idx]
    }
}

#[derive(Clone)]
struct McpConnectionSnapshot {
    generation: u64,
    live: bool,
    cached_tools: Vec<McpTool>,
    supports_list_changed: bool,
}

/// One server-specific failure retained alongside successful fan-out results.
#[derive(Debug)]
pub struct McpCatalogFailure {
    pub server: String,
    pub connection_generation: Option<u64>,
    pub error: McpError,
}

/// Typed partial result for manager-wide MCP catalogue operations.
#[derive(Debug)]
pub struct McpCatalogResult<T> {
    pub entries: Vec<(String, T)>,
    pub failures: Vec<McpCatalogFailure>,
}

/// Read-only transport status for diagnostics and admission evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpConnectionStatus {
    pub binding: McpTransportBinding,
    pub required_resource: crate::tools::ToolResource,
    pub run_generation: u64,
    pub connection_generation: u64,
    pub live: bool,
    pub queue_capacity: usize,
    pub queue_available: usize,
}

fn project_mcp_resource_text(result: &McpReadResourceResult) -> String {
    result
        .contents
        .iter()
        .map(|content| match content {
            McpResourceContents::Text { text, .. } => text.clone(),
            McpResourceContents::Blob { uri, mime_type, .. } => format!(
                "Binary MCP resource {uri} ({}) retained as typed content",
                mime_type.as_deref().unwrap_or("application/octet-stream")
            ),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

impl McpConnectionSnapshot {
    fn from_entry(entry: &ServerEntry) -> Self {
        Self {
            generation: entry.connection_generation,
            live: entry.server.is_some(),
            cached_tools: entry.cached_tools.clone(),
            supports_list_changed: entry.supports_list_changed,
        }
    }
}

enum McpActorOperation {
    CallTool {
        full_name: String,
        tool_name: String,
        arguments: Value,
        expected_source_digest: Option<crate::runtime::ContentDigest>,
        on_dispatch: Option<Box<dyn FnOnce() + Send>>,
    },
    ListResources,
    ReadResource {
        uri: String,
    },
    ListPrompts,
    GetPrompt {
        prompt_name: String,
        arguments: BTreeMap<String, String>,
    },
}

impl McpActorOperation {
    const fn phase(&self) -> &'static str {
        match self {
            Self::CallTool { .. } => "tools/call",
            Self::ListResources => "resources/list",
            Self::ReadResource { .. } => "resources/read",
            Self::ListPrompts => "prompts/list",
            Self::GetPrompt { .. } => "prompts/get",
        }
    }

    fn validate_queued_size(&self) -> Result<(), McpError> {
        let encoded_size = match self {
            Self::CallTool { arguments, .. } => serde_json::to_vec(arguments)
                .map_err(|error| McpError::Protocol(error.to_string()))?
                .len(),
            Self::ReadResource { uri } => uri.len(),
            Self::GetPrompt {
                prompt_name,
                arguments,
            } => {
                prompt_name.len()
                    + serde_json::to_vec(arguments)
                        .map_err(|error| McpError::Protocol(error.to_string()))?
                        .len()
            }
            Self::ListResources | Self::ListPrompts => 0,
        };
        if encoded_size > MAX_REQUEST_SIZE {
            return Err(McpError::RequestTooLarge {
                limit: MAX_REQUEST_SIZE,
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
enum McpActorOutput {
    Tool(Value),
    Resources(Vec<McpResource>),
    Resource(McpReadResourceResult),
    Prompts(Vec<McpPrompt>),
    Prompt(McpGetPromptResult),
}

struct McpActorRequest {
    expected_run_generation: u64,
    expected_generation: Option<u64>,
    operation: McpActorOperation,
    reply: oneshot::Sender<Result<McpActorOutput, McpError>>,
}

impl McpActorRequest {
    fn reject(self, error: McpError) {
        let _ = self.reply.send(Err(error));
    }
}

struct McpConnectionActor {
    name: String,
    binding: McpTransportBinding,
    required_resource: crate::tools::ToolResource,
    trust: McpServerTrust,
    sender: mpsc::Sender<McpActorRequest>,
    snapshot: Arc<std::sync::RwLock<McpConnectionSnapshot>>,
    cancellation: crate::runtime::CancellationHandle,
    join: Mutex<Option<JoinHandle<Result<(), McpError>>>>,
}

impl McpConnectionActor {
    fn spawn(
        name: String,
        run: Arc<crate::tools::ToolRunContext>,
        entry: ServerEntry,
        catalog_epoch: Arc<AtomicU64>,
        catalog_guard: Arc<std::sync::RwLock<()>>,
    ) -> Arc<Self> {
        let binding = entry.spec.binding();
        let required_resource = entry.spec.required_resource();
        let trust = entry.trust.clone();
        let snapshot = Arc::new(std::sync::RwLock::new(McpConnectionSnapshot::from_entry(
            &entry,
        )));
        let cancellation = run.runtime().cancellation().child();
        let (sender, receiver) = mpsc::channel(MCP_ACTOR_QUEUE_CAPACITY);
        let task_snapshot = Arc::clone(&snapshot);
        let task_cancellation = cancellation.clone();
        let task_name = name.clone();
        let join = tokio::spawn(run_mcp_connection_actor(
            McpActorTaskContext {
                name: task_name,
                run,
                snapshot: task_snapshot,
                cancellation: task_cancellation,
                catalog_epoch,
                catalog_guard,
            },
            entry,
            receiver,
        ));
        Arc::new(Self {
            name,
            binding,
            required_resource,
            trust,
            sender,
            snapshot,
            cancellation,
            join: Mutex::new(Some(join)),
        })
    }

    fn snapshot(&self) -> McpConnectionSnapshot {
        self.snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    const fn required_resource(&self) -> crate::tools::ToolResource {
        self.required_resource
    }

    const fn binding(&self) -> McpTransportBinding {
        self.binding
    }

    async fn request(
        &self,
        expected_run_generation: u64,
        expected_generation: Option<u64>,
        operation: McpActorOperation,
    ) -> Result<McpActorOutput, McpError> {
        if self.cancellation.is_cancelled() {
            return Err(McpError::ConnectionClosed(self.name.clone()));
        }
        operation.validate_queued_size()?;
        let (reply, response) = oneshot::channel();
        let request = McpActorRequest {
            expected_run_generation,
            expected_generation,
            operation,
            reply,
        };
        match self.sender.try_send(request) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(McpError::Backpressure {
                    server: self.name.clone(),
                    capacity: MCP_ACTOR_QUEUE_CAPACITY,
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(McpError::ConnectionClosed(self.name.clone()));
            }
        }
        response
            .await
            .unwrap_or_else(|_| Err(McpError::ConnectionClosed(self.name.clone())))
    }

    async fn shutdown(&self) -> Result<(), McpError> {
        let _ = self
            .cancellation
            .cancel(crate::runtime::CancellationReason::ParentTerminated);
        let Some(mut join) = self.join.lock().await.take() else {
            return Ok(());
        };
        match tokio::time::timeout(DEFAULT_MCP_REQUEST_TIMEOUT, &mut join).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(McpError::Transport(format!(
                "MCP server '{}' actor task failed: {error}",
                self.name
            ))),
            Err(_) => {
                join.abort();
                let _ = join.await;
                Err(McpError::Timeout {
                    phase: "connection-shutdown",
                })
            }
        }
    }
}

impl Drop for McpConnectionActor {
    fn drop(&mut self) {
        let _ = self
            .cancellation
            .cancel(crate::runtime::CancellationReason::ParentTerminated);
    }
}

fn update_mcp_actor_snapshot(
    snapshot: &std::sync::RwLock<McpConnectionSnapshot>,
    entry: &ServerEntry,
) {
    *snapshot
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        McpConnectionSnapshot::from_entry(entry);
}

fn publish_mcp_actor_snapshot(
    snapshot: &std::sync::RwLock<McpConnectionSnapshot>,
    catalog_epoch: &AtomicU64,
    catalog_guard: &std::sync::RwLock<()>,
    entry: &ServerEntry,
) {
    let _guard = catalog_guard
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    update_mcp_actor_snapshot(snapshot, entry);
    catalog_epoch.fetch_add(1, Ordering::AcqRel);
}

const fn mcp_error_breaks_connection(error: &McpError) -> bool {
    matches!(
        error,
        McpError::Transport(_)
            | McpError::Protocol(_)
            | McpError::HttpStatus { .. }
            | McpError::Timeout { .. }
            | McpError::Cancelled { .. }
            | McpError::ResponseTooLarge { .. }
            | McpError::ResponseIdMismatch { .. }
    )
}

fn validate_mcp_actor_tool_call(
    server_name: &str,
    run_generation: u64,
    manager_epoch: u64,
    entry: &ServerEntry,
    operation: &McpActorOperation,
) -> Result<(), McpError> {
    let McpActorOperation::CallTool {
        full_name,
        tool_name,
        arguments,
        expected_source_digest,
        ..
    } = operation
    else {
        return Ok(());
    };
    let mut matching_tools = entry
        .cached_tools
        .iter()
        .filter(|tool| tool.name == *tool_name);
    let Some(tool) = matching_tools.next() else {
        return Err(McpError::ToolNotFound(full_name.clone()));
    };
    if matching_tools.next().is_some() {
        return Err(McpError::InvalidToolSchema {
            tool: full_name.clone(),
            reason: "server returned a duplicate tool identity".to_string(),
        });
    }
    let schema = effective_mcp_input_schema(tool);
    let validator =
        compile_mcp_input_schema(&schema).map_err(|reason| McpError::InvalidToolSchema {
            tool: full_name.clone(),
            reason,
        })?;
    if !validator.is_valid(arguments) {
        return Err(McpError::InvalidToolArguments {
            tool: full_name.clone(),
        });
    }
    if let Some(expected) = expected_source_digest {
        let definition = mcp_registration_definition(
            McpRegistrationContext {
                epoch: manager_epoch,
                run_generation,
                connection_generation: entry.connection_generation,
                server_name,
                trust: &entry.trust,
                available: entry.server.is_some(),
            },
            tool,
            &schema,
        );
        if mcp_definition_digest(&definition)? != *expected {
            return Err(McpError::StaleToolRegistration(full_name.clone()));
        }
    }
    Ok(())
}

async fn execute_mcp_actor_operation(
    server: &McpServer,
    operation: McpActorOperation,
) -> Result<McpActorOutput, McpError> {
    match operation {
        McpActorOperation::CallTool {
            full_name: _,
            tool_name,
            arguments,
            expected_source_digest: _,
            on_dispatch,
        } => {
            if let Some(on_dispatch) = on_dispatch {
                on_dispatch();
            }
            server
                .call_tool(&tool_name, arguments)
                .await
                .map(McpActorOutput::Tool)
        }
        McpActorOperation::ListResources => {
            server.list_resources().await.map(McpActorOutput::Resources)
        }
        McpActorOperation::ReadResource { uri } => server
            .read_resource_typed(&uri)
            .await
            .map(McpActorOutput::Resource),
        McpActorOperation::ListPrompts => server.list_prompts().await.map(McpActorOutput::Prompts),
        McpActorOperation::GetPrompt {
            prompt_name,
            arguments,
        } => server
            .get_prompt(&prompt_name, arguments)
            .await
            .map(McpActorOutput::Prompt),
    }
}

struct McpActorTaskContext {
    name: String,
    run: Arc<crate::tools::ToolRunContext>,
    snapshot: Arc<std::sync::RwLock<McpConnectionSnapshot>>,
    cancellation: crate::runtime::CancellationHandle,
    catalog_epoch: Arc<AtomicU64>,
    catalog_guard: Arc<std::sync::RwLock<()>>,
}

#[allow(clippy::too_many_lines)] // One actor loop owns its full request and teardown state machine.
async fn run_mcp_connection_actor(
    context: McpActorTaskContext,
    mut entry: ServerEntry,
    mut receiver: mpsc::Receiver<McpActorRequest>,
) -> Result<(), McpError> {
    let McpActorTaskContext {
        name,
        run,
        snapshot,
        cancellation,
        catalog_epoch,
        catalog_guard,
    } = context;
    loop {
        let request = tokio::select! {
            _ = cancellation.cancelled() => break,
            request = receiver.recv() => match request {
                Some(request) => request,
                None => break,
            },
        };
        if request.reply.is_closed() {
            continue;
        }
        let current_run_generation = run.generation().get();
        if request.expected_run_generation != current_run_generation {
            let expected = request.expected_run_generation;
            request.reject(McpError::StaleRunGeneration {
                expected,
                current: current_run_generation,
            });
            continue;
        }
        if let Err(error) = run.require(entry.spec.required_resource()) {
            request.reject(McpError::Capability(error));
            continue;
        }

        let mut request = request;
        let reconnected = tokio::select! {
            _ = cancellation.cancelled() => {
                request.reject(McpError::Cancelled { phase: "connect" });
                break;
            }
            () = request.reply.closed() => continue,
            result = McpManager::ensure_connected(&run, &mut entry, &name) => result,
        };
        match reconnected {
            Ok(changed) => {
                if changed {
                    publish_mcp_actor_snapshot(&snapshot, &catalog_epoch, &catalog_guard, &entry);
                }
            }
            Err(error) => {
                request.reject(error);
                continue;
            }
        }

        if let Some(expected) = request.expected_generation {
            if expected != entry.connection_generation {
                request.reject(McpError::StaleConnectionGeneration {
                    server: name.clone(),
                    expected,
                    current: entry.connection_generation,
                });
                continue;
            }
        }
        if let Err(error) = validate_mcp_actor_tool_call(
            &name,
            run.generation().get(),
            catalog_epoch.load(Ordering::Acquire),
            &entry,
            &request.operation,
        ) {
            request.reject(error);
            continue;
        }
        let phase = request.operation.phase();
        let deadline = entry
            .tool_timeout
            .filter(|_| matches!(&request.operation, McpActorOperation::CallTool { .. }))
            .unwrap_or(DEFAULT_MCP_REQUEST_TIMEOUT);
        let outcome = {
            let Some(server) = entry.server.as_ref() else {
                request.reject(McpError::ServerUnreachable(name.clone()));
                continue;
            };
            let operation = execute_mcp_actor_operation(server, request.operation);
            tokio::pin!(operation);
            tokio::select! {
                _ = cancellation.cancelled() => Some(Err(McpError::Cancelled { phase })),
                () = request.reply.closed() => None,
                result = tokio::time::timeout(deadline, &mut operation) => Some(
                    result.unwrap_or(Err(McpError::Timeout { phase }))
                ),
            }
        };

        let must_retire = outcome
            .as_ref()
            .is_none_or(|result| result.as_ref().is_err_and(mcp_error_breaks_connection));
        if must_retire {
            let result = entry.retire_connection().await;
            publish_mcp_actor_snapshot(&snapshot, &catalog_epoch, &catalog_guard, &entry);
            if let Err(error) = result {
                warn!(server = %name, error = %error, "Failed to close retired MCP connection");
            }
        }
        if let Some(outcome) = outcome {
            let _ = request.reply.send(outcome);
        }
    }

    let close = entry.retire_connection().await;
    publish_mcp_actor_snapshot(&snapshot, &catalog_epoch, &catalog_guard, &entry);
    while let Ok(request) = receiver.try_recv() {
        request.reject(McpError::ConnectionClosed(name.clone()));
    }
    close
}

/// Manages multiple MCP server connections with self-healing reconnection (fix #629).
pub struct McpManager {
    run_context: Arc<crate::tools::ToolRunContext>,
    permissions: crate::config::PermissionsConfig,
    catalog_epoch: Arc<AtomicU64>,
    catalog_guard: Arc<std::sync::RwLock<()>>,
    servers: Mutex<HashMap<String, Arc<McpConnectionActor>>>,
}

/// Exact run-keyed index used by synchronous registry handlers to find the
/// async manager composed for their own run. Weak values keep this index from
/// extending a manager or its child-process lifetime after its frontend exits.
type RegisteredMcpManagers =
    HashMap<(String, u64), std::sync::Weak<tokio::sync::RwLock<McpManager>>>;

static REGISTERED_MANAGERS: LazyLock<std::sync::Mutex<RegisteredMcpManagers>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn manager_key(run: &crate::tools::ToolRunContext) -> (String, u64) {
    (run.run_id().to_string(), run.generation().get())
}

/// Install a manager for one exact run generation. A live manager already
/// registered for the same run wins; unrelated runs occupy independent slots.
pub fn install_manager(
    run: &crate::tools::ToolRunContext,
    manager: &Arc<tokio::sync::RwLock<McpManager>>,
) -> bool {
    let mut registry = REGISTERED_MANAGERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.retain(|_, manager| manager.strong_count() > 0);
    let key = manager_key(run);
    if registry
        .get(&key)
        .and_then(std::sync::Weak::upgrade)
        .is_some()
    {
        return false;
    }
    registry.insert(key, Arc::downgrade(manager));
    true
}

/// Fetch only the manager bound to `run`'s exact identity and generation.
#[must_use]
pub fn registered_manager(
    run: &crate::tools::ToolRunContext,
) -> Option<Arc<tokio::sync::RwLock<McpManager>>> {
    let mut registry = REGISTERED_MANAGERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = manager_key(run);
    let manager = registry.get(&key).and_then(std::sync::Weak::upgrade);
    if manager.is_none() {
        registry.remove(&key);
    }
    manager
}

impl McpManager {
    /// Create a fail-closed MCP manager with no dynamic tool allowlist.
    ///
    /// Production composition roots should use [`Self::new_with_permissions`]
    /// with the exact immutable configuration bound to the same run.
    #[must_use]
    pub fn new(run_context: Arc<crate::tools::ToolRunContext>) -> Self {
        Self::new_with_permissions(run_context, crate::config::PermissionsConfig::default())
    }

    /// Create a manager bound to one run and its exact MCP tool allowlist.
    #[must_use]
    pub fn new_with_permissions(
        run_context: Arc<crate::tools::ToolRunContext>,
        permissions: crate::config::PermissionsConfig,
    ) -> Self {
        Self {
            run_context,
            permissions,
            catalog_epoch: Arc::new(AtomicU64::new(1)),
            catalog_guard: Arc::new(std::sync::RwLock::new(())),
            servers: Mutex::new(HashMap::new()),
        }
    }

    /// Immutable permissions generation captured by this manager.
    #[must_use]
    pub const fn permissions(&self) -> &crate::config::PermissionsConfig {
        &self.permissions
    }

    fn bump_catalog_epoch(&self) {
        let _guard = self
            .catalog_guard
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.catalog_epoch.fetch_add(1, Ordering::AcqRel);
    }

    async fn actor(&self, name: &str) -> Result<Arc<McpConnectionActor>, McpError> {
        self.servers
            .lock()
            .await
            .get(name)
            .cloned()
            .ok_or_else(|| McpError::NotConnected(name.to_string()))
    }

    async fn install_actor(&self, name: String, entry: ServerEntry) -> Result<(), McpError> {
        let actor = McpConnectionActor::spawn(
            name.clone(),
            Arc::clone(&self.run_context),
            entry,
            Arc::clone(&self.catalog_epoch),
            Arc::clone(&self.catalog_guard),
        );
        let replaced = {
            let mut servers = self.servers.lock().await;
            let replaced = servers.insert(name, actor);
            self.bump_catalog_epoch();
            drop(servers);
            replaced
        };
        if let Some(replaced) = replaced {
            if let Err(error) = replaced.shutdown().await {
                warn!(error = %error, "Failed to shut down replaced MCP connection cleanly");
            }
        }
        Ok(())
    }

    /// Whether this manager is bound to the exact caller run generation.
    #[must_use]
    pub fn matches_run(&self, run: &crate::tools::ToolRunContext) -> bool {
        self.run_context.run_id() == run.run_id()
            && self.run_context.generation() == run.generation()
    }

    /// Exact immutable run that owns this manager and its transports.
    #[must_use]
    pub fn run_context(&self) -> &crate::tools::ToolRunContext {
        &self.run_context
    }

    /// Connect to an MCP server via stdio.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if spawning or initializing the server fails.
    pub async fn connect_stdio(
        &self,
        name: &str,
        command: &str,
        args: &[&str],
    ) -> Result<(), McpError> {
        self.connect_stdio_with_env(name, command, args, &HashMap::new())
            .await
    }

    /// Connect to an MCP server via stdio with extra child environment.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if spawning or initializing the server fails.
    pub async fn connect_stdio_with_env(
        &self,
        name: &str,
        command: &str,
        args: &[&str],
        env: &HashMap<String, String>,
    ) -> Result<(), McpError> {
        self.connect_stdio_with_env_and_timeout(name, command, args, env, None)
            .await
    }

    /// Connect to an MCP server via stdio with extra child environment
    /// and an optional per-tool-call timeout.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if spawning or initializing the server fails.
    pub async fn connect_stdio_with_env_and_timeout(
        &self,
        name: &str,
        command: &str,
        args: &[&str],
        env: &HashMap<String, String>,
        tool_timeout: Option<Duration>,
    ) -> Result<(), McpError> {
        validate_mcp_child_environment(&self.run_context, env)?;
        let env =
            crate::secrets::EnvironmentGrants::from_validated(env.clone()).map_err(|error| {
                McpError::Transport(format!("Invalid MCP child environment value: {error}"))
            })?;
        self.connect_stdio_with_protected_env_and_timeout(name, command, args, env, tool_timeout)
            .await
    }

    pub(crate) async fn connect_stdio_with_protected_env_and_timeout(
        &self,
        name: &str,
        command: &str,
        args: &[&str],
        env: crate::secrets::EnvironmentGrants,
        tool_timeout: Option<Duration>,
    ) -> Result<(), McpError> {
        self.connect_stdio_with_trust(
            name,
            command,
            args,
            env,
            tool_timeout,
            McpServerTrust::HostConfigured,
        )
        .await
    }

    pub(crate) async fn connect_stdio_with_plugin_grant(
        &self,
        name: &str,
        command: &str,
        args: &[&str],
        env: crate::secrets::EnvironmentGrants,
        tool_timeout: Option<Duration>,
        trust_id: String,
    ) -> Result<(), McpError> {
        self.connect_stdio_with_trust(
            name,
            command,
            args,
            env,
            tool_timeout,
            McpServerTrust::PluginGrant(trust_id),
        )
        .await
    }

    async fn connect_stdio_with_trust(
        &self,
        name: &str,
        command: &str,
        args: &[&str],
        env: crate::secrets::EnvironmentGrants,
        tool_timeout: Option<Duration>,
        trust: McpServerTrust,
    ) -> Result<(), McpError> {
        validate_mcp_server_identity(name)?;
        validate_protected_mcp_child_environment(&self.run_context, &env)?;
        let spec = ConnectionSpec::Stdio {
            command: command.to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            env,
        };
        let transport = spec.build_transport(&self.run_context)?;
        let server = McpServer::new(name, transport).await?;
        let entry = ServerEntry::new_with_trust_and_tool_timeout(spec, server, trust, tool_timeout);
        self.install_actor(name.to_string(), entry).await
    }

    /// Connect to an MCP server via HTTP. URL validated by SSRF guard (fix #677).
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if URL validation, connection, or initialization fails.
    pub async fn connect_http(&self, name: &str, url: &str) -> Result<(), McpError> {
        self.connect_http_with_headers(name, url, &HashMap::new())
            .await
    }

    /// Connect to an MCP server via HTTP with static headers.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if URL/header validation, connection, or
    /// initialization fails.
    pub async fn connect_http_with_headers(
        &self,
        name: &str,
        url: &str,
        headers: &HashMap<String, String>,
    ) -> Result<(), McpError> {
        self.connect_http_with_headers_and_timeout(name, url, headers, None)
            .await
    }

    /// Connect to an MCP server via HTTP with static headers and an optional
    /// per-tool-call timeout.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if URL/header validation, connection, or
    /// initialization fails.
    pub async fn connect_http_with_headers_and_timeout(
        &self,
        name: &str,
        url: &str,
        headers: &HashMap<String, String>,
        tool_timeout: Option<Duration>,
    ) -> Result<(), McpError> {
        self.connect_http_with_headers_helper_and_timeout(name, url, headers, None, tool_timeout)
            .await
    }

    /// Connect to an MCP server via HTTP with static headers, an optional
    /// dynamic headers helper, and an optional per-tool-call timeout.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if URL/header validation, helper execution,
    /// connection, or initialization fails.
    pub async fn connect_http_with_headers_helper_and_timeout(
        &self,
        name: &str,
        url: &str,
        headers: &HashMap<String, String>,
        headers_helper: Option<&str>,
        tool_timeout: Option<Duration>,
    ) -> Result<(), McpError> {
        let headers = protect_static_headers(headers)?;
        self.connect_http_with_sensitive_headers_helper_and_timeout(
            name,
            url,
            headers,
            headers_helper,
            tool_timeout,
        )
        .await
    }

    pub(crate) async fn connect_http_with_sensitive_headers_helper_and_timeout(
        &self,
        name: &str,
        url: &str,
        headers: crate::secrets::SensitiveHeaders,
        headers_helper: Option<&str>,
        tool_timeout: Option<Duration>,
    ) -> Result<(), McpError> {
        self.connect_http_with_trust(
            name,
            url,
            headers,
            headers_helper,
            tool_timeout,
            McpServerTrust::HostConfigured,
        )
        .await
    }

    pub(crate) async fn connect_http_with_plugin_grant(
        &self,
        name: &str,
        url: &str,
        headers: crate::secrets::SensitiveHeaders,
        headers_helper: Option<&str>,
        tool_timeout: Option<Duration>,
        trust_id: String,
    ) -> Result<(), McpError> {
        self.connect_http_with_trust(
            name,
            url,
            headers,
            headers_helper,
            tool_timeout,
            McpServerTrust::PluginGrant(trust_id),
        )
        .await
    }

    async fn connect_http_with_trust(
        &self,
        name: &str,
        url: &str,
        headers: crate::secrets::SensitiveHeaders,
        headers_helper: Option<&str>,
        tool_timeout: Option<Duration>,
        trust: McpServerTrust,
    ) -> Result<(), McpError> {
        validate_mcp_server_identity(name)?;
        self.run_context
            .require(crate::tools::ToolResource::Network)?;
        let spec = ConnectionSpec::Http {
            url: url.to_string(),
            headers,
            headers_helper: headers_helper.map(str::to_string),
            server_name: name.to_string(),
        };
        let transport = spec.build_transport(&self.run_context)?;
        let server = McpServer::new(name, transport).await?;
        let entry = ServerEntry::new_with_trust_and_tool_timeout(spec, server, trust, tool_timeout);
        self.install_actor(name.to_string(), entry).await
    }

    /// Test-only counterpart to [`Self::connect_http`] that bypasses
    /// the SSRF guard so integration tests can point at a wiremock
    /// loopback listener. Marked `#[doc(hidden)]` and prefixed
    /// `__test_` to make production misuse obvious.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if connection or initialization fails.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub async fn __test_connect_http_unchecked(
        &self,
        name: &str,
        url: &str,
    ) -> Result<(), McpError> {
        self.__test_connect_http_unchecked_with_headers(name, url, &HashMap::new())
            .await
    }

    /// Test-only HTTP connector with static headers and no SSRF guard.
    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub async fn __test_connect_http_unchecked_with_headers(
        &self,
        name: &str,
        url: &str,
        headers: &HashMap<String, String>,
    ) -> Result<(), McpError> {
        let protected_headers = protect_static_headers(headers)?;
        let spec = ConnectionSpec::Http {
            url: url.to_string(),
            headers: protected_headers,
            headers_helper: None,
            server_name: name.to_string(),
        };
        let transport: Box<dyn McpTransport> = Box::new(
            HttpTransport::__test_new_unchecked_with_headers(url, headers),
        );
        let server = McpServer::new(name, transport).await?;
        let entry = ServerEntry::new(spec, server);
        self.install_actor(name.to_string(), entry).await
    }

    fn collect_server_tool_catalog(
        &self,
        epoch: u64,
        server_name: &str,
        actor: &McpConnectionActor,
        snapshot: &McpConnectionSnapshot,
        definitions: &mut BTreeMap<String, Value>,
        unavailable: &mut Vec<McpToolUnavailable>,
    ) {
        let Some(allowed) = self.permissions.mcp.get(server_name) else {
            return;
        };
        let allowed = allowed
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let mut tools_by_name: BTreeMap<&str, Vec<&McpTool>> = BTreeMap::new();
        for tool in &snapshot.cached_tools {
            if allowed.contains(tool.name.as_str()) {
                tools_by_name.entry(&tool.name).or_default().push(tool);
            }
        }
        for tool_name in allowed {
            let Some(tools) = tools_by_name.get(tool_name) else {
                unavailable.push(McpToolUnavailable {
                    server: server_name.to_string(),
                    tool: tool_name.to_string(),
                    reason: if snapshot.live {
                        "configured tool is absent from the discovered server generation"
                            .to_string()
                    } else {
                        "configured server is disconnected".to_string()
                    },
                });
                continue;
            };
            if tools.len() != 1 {
                unavailable.push(McpToolUnavailable {
                    server: server_name.to_string(),
                    tool: tool_name.to_string(),
                    reason: "server returned a duplicate tool identity".to_string(),
                });
                continue;
            }
            let full_name = format!("mcp__{server_name}__{tool_name}");
            if split_mcp_tool_identity(&full_name).is_err() {
                unavailable.push(McpToolUnavailable {
                    server: server_name.to_string(),
                    tool: tool_name.to_string(),
                    reason: "tool identity cannot be represented without namespace ambiguity"
                        .to_string(),
                });
                continue;
            }
            let tool = tools[0];
            let schema = effective_mcp_input_schema(tool);
            if let Err(reason) = compile_mcp_input_schema(&schema) {
                unavailable.push(McpToolUnavailable {
                    server: server_name.to_string(),
                    tool: tool_name.to_string(),
                    reason,
                });
                continue;
            }
            definitions.insert(
                full_name,
                mcp_registration_definition(
                    McpRegistrationContext {
                        epoch,
                        run_generation: self.run_context.generation().get(),
                        connection_generation: snapshot.generation,
                        server_name,
                        trust: &actor.trust,
                        available: snapshot.live,
                    },
                    tool,
                    &schema,
                ),
            );
        }
    }

    fn collect_unregistered_configured_tools(
        &self,
        servers: &HashMap<String, Arc<McpConnectionActor>>,
        unavailable: &mut Vec<McpToolUnavailable>,
    ) {
        for (server_name, allowed) in &self.permissions.mcp {
            if servers.contains_key(server_name) {
                continue;
            }
            for tool_name in allowed {
                unavailable.push(McpToolUnavailable {
                    server: server_name.clone(),
                    tool: tool_name.clone(),
                    reason: "configured server is not registered".to_string(),
                });
            }
        }
    }

    /// Build a deterministic, policy-filtered dynamic tool snapshot.
    ///
    /// Configured tools that are disconnected, malformed, duplicate,
    /// invalid-schema, or absent from discovery are retained as bounded
    /// unavailability records. Unconfigured remote inventory is discarded
    /// without copying server-controlled cardinality into the snapshot. The
    /// returned definitions are safe inputs to the run-owned progressive
    /// catalog; they are not permission grants.
    pub async fn tool_catalog_snapshot(&self) -> McpToolCatalogSnapshot {
        let guard = self.servers.lock().await;
        let catalog_read = self
            .catalog_guard
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Map mutation and actor snapshot publication take the matching write
        // guard. Definitions and availability therefore come from one exact
        // manager generation rather than a torn atomic/snapshot pair.
        let epoch = self.catalog_epoch.load(Ordering::Acquire);
        let mut definitions = BTreeMap::new();
        let mut unavailable = Vec::new();

        let mut server_names: Vec<&String> = guard.keys().collect();
        server_names.sort_unstable();
        for server_name in server_names {
            let Some(actor) = guard.get(server_name) else {
                continue;
            };
            let snapshot = actor.snapshot();
            self.collect_server_tool_catalog(
                epoch,
                server_name,
                actor,
                &snapshot,
                &mut definitions,
                &mut unavailable,
            );
        }
        self.collect_unregistered_configured_tools(&guard, &mut unavailable);
        drop(catalog_read);
        drop(guard);

        unavailable.sort_by(|left, right| {
            (&left.server, &left.tool, &left.reason).cmp(&(
                &right.server,
                &right.tool,
                &right.reason,
            ))
        });
        let definitions: Vec<Value> = definitions.into_values().collect();
        let generation_payload = json!({
            "contract": "openclaudia.mcp-tool-catalog.v1",
            "run_generation": self.run_context.generation().get(),
            "manager_epoch": epoch,
            "definitions": &definitions,
            "unavailable": &unavailable,
        });
        let generation = serde_json::to_vec(&generation_payload).map_or_else(
            |_| crate::runtime::ContentDigest::sha256(b"openclaudia.invalid-mcp-catalog.v1"),
            |encoded| crate::runtime::ContentDigest::sha256(&encoded),
        );
        McpToolCatalogSnapshot {
            generation,
            definitions,
            unavailable,
        }
    }

    /// Compatibility projection for diagnostics that only need callable
    /// OpenAI-format definitions.
    pub async fn tools_as_openai_functions(&self) -> Vec<Value> {
        self.tool_catalog_snapshot().await.definitions
    }

    /// Attempt to reconnect a disconnected entry in-place (fix #629).
    /// Called only by the per-server actor that exclusively owns the entry.
    async fn ensure_connected(
        run: &Arc<crate::tools::ToolRunContext>,
        entry: &mut ServerEntry,
        name: &str,
    ) -> Result<bool, McpError> {
        if entry.server.is_some() {
            return Ok(false);
        }
        if entry.is_permanently_unreachable() {
            return Err(McpError::ServerUnreachable(name.to_string()));
        }
        if !entry.backoff_elapsed() {
            return Err(McpError::ServerUnreachable(name.to_string()));
        }

        debug!(
            server = %name,
            attempt = entry.failed_attempts + 1,
            max = MAX_RECONNECT_ATTEMPTS,
            "Attempting MCP server reconnect"
        );

        let attempt_result = match entry.spec.build_transport(run) {
            Ok(transport) => McpServer::new(name, transport).await,
            Err(e) => Err(e),
        };

        match attempt_result {
            Ok(server) => {
                entry.cached_tools = server.tools().to_vec();
                entry.supports_list_changed = server.supports_tool_list_changed();
                entry.server = Some(server);
                entry.connection_generation =
                    NEXT_MCP_CONNECTION_GENERATION.fetch_add(1, Ordering::AcqRel);
                entry.failed_attempts = 0;
                entry.last_failure = None;
                info!(server = %name, "MCP server reconnected");
                Ok(true)
            }
            Err(e) => {
                entry.failed_attempts += 1;
                entry.last_failure = Some(std::time::Instant::now());
                warn!(
                    server = %name,
                    attempt = entry.failed_attempts,
                    max = MAX_RECONNECT_ATTEMPTS,
                    error = %e,
                    "MCP server reconnect attempt failed"
                );
                if entry.failed_attempts >= MAX_RECONNECT_ATTEMPTS {
                    Err(McpError::ServerUnreachable(name.to_string()))
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Call a tool by its full name (`mcp__servername__toolname`).
    ///
    /// On [`McpError::Transport`] from the underlying request, the
    /// server entry is marked disconnected (fix #629); the next access
    /// attempts reconnection under the backoff. The original error is
    /// returned to the caller — CC's `onclose` also fails the in-flight
    /// call (`client.ts:1396`), reconnect happens on the next call.
    ///
    /// # Errors
    ///
    /// Returns `McpError::ToolNotFound` if the name format is invalid,
    /// `McpError::NotConnected` if the server is not registered, or
    /// `McpError::ServerUnreachable` if the entry has exhausted its
    /// reconnect budget.
    pub async fn call_tool(&self, full_name: &str, arguments: Value) -> Result<Value, McpError> {
        self.call_tool_inner(full_name, arguments, None, || {})
            .await
    }

    /// Execute an agent-originated call only when it still matches the exact
    /// source digest retained by the last run-owned tool-catalog publication.
    /// `on_dispatch` runs immediately before the remote `tools/call` future is
    /// polled, allowing the canonical executor to commit effect accounting at
    /// the first point where cancellation can no longer prove no remote effect.
    pub(crate) async fn call_tool_registered_with_dispatch<F>(
        &self,
        full_name: &str,
        arguments: Value,
        expected_source_digest: crate::runtime::ContentDigest,
        on_dispatch: F,
    ) -> Result<Value, McpError>
    where
        F: FnOnce() + Send + 'static,
    {
        self.call_tool_inner(
            full_name,
            arguments,
            Some(expected_source_digest),
            on_dispatch,
        )
        .await
    }

    async fn call_tool_inner<F>(
        &self,
        full_name: &str,
        arguments: Value,
        expected_source_digest: Option<crate::runtime::ContentDigest>,
        on_dispatch: F,
    ) -> Result<Value, McpError>
    where
        F: FnOnce() + Send + 'static,
    {
        let (server_name, tool_name) = split_mcp_tool_identity(full_name)?;
        if !arguments.is_object() {
            return Err(McpError::InvalidToolArguments {
                tool: full_name.to_string(),
            });
        }

        let actor = self.actor(server_name).await?;
        if !self.permissions.mcp_tool_allowed(server_name, tool_name) {
            return Err(McpError::ToolNotAllowed {
                server: server_name.to_string(),
                tool: tool_name.to_string(),
            });
        }
        self.run_context.require(actor.required_resource())?;
        let snapshot = actor.snapshot();
        let expected_generation = snapshot.live.then_some(snapshot.generation);
        let output = actor
            .request(
                self.run_context.generation().get(),
                expected_generation,
                McpActorOperation::CallTool {
                    full_name: full_name.to_string(),
                    tool_name: tool_name.to_string(),
                    arguments,
                    expected_source_digest,
                    on_dispatch: Some(Box::new(on_dispatch)),
                },
            )
            .await?;
        match output {
            McpActorOutput::Tool(value) => Ok(value),
            _ => Err(McpError::Protocol(format!(
                "MCP server '{server_name}' returned the wrong actor response for tools/call"
            ))),
        }
    }

    /// Call a tool with a timeout.
    ///
    /// # Errors
    ///
    /// Returns `McpError::Timeout` if the call exceeds the duration, or
    /// propagates any error from `call_tool`.
    pub async fn call_tool_with_timeout(
        &self,
        full_name: &str,
        arguments: Value,
        timeout: Duration,
    ) -> Result<Value, McpError> {
        tokio::time::timeout(timeout, self.call_tool(full_name, arguments))
            .await
            .unwrap_or_else(|_| {
                warn!(tool = %full_name, timeout_secs = timeout.as_secs(), "MCP tool call timed out");
                Err(McpError::Timeout { phase: "tools/call" })
            })
    }

    /// Get information about a connected server. Owned return because
    /// the inner mutex guard cannot be held across the return.
    pub async fn get_server_info(&self, name: &str) -> Option<(String, bool)> {
        let actor = self.servers.lock().await.get(name).cloned()?;
        Some((name.to_string(), actor.snapshot().supports_list_changed))
    }

    /// Return bounded, read-only transport status without contacting or
    /// reconnecting the server.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::NotConnected`] when `name` is not registered.
    pub async fn connection_status(&self, name: &str) -> Result<McpConnectionStatus, McpError> {
        let actor = self.actor(name).await?;
        let snapshot = actor.snapshot();
        Ok(McpConnectionStatus {
            binding: actor.binding(),
            required_resource: actor.required_resource(),
            run_generation: self.run_context.generation().get(),
            connection_generation: snapshot.generation,
            live: snapshot.live,
            queue_capacity: MCP_ACTOR_QUEUE_CAPACITY,
            queue_available: actor.sender.capacity(),
        })
    }

    async fn actors_for_filter(
        &self,
        server_name: Option<&str>,
    ) -> Result<Vec<(String, Arc<McpConnectionActor>)>, McpError> {
        let servers = self.servers.lock().await;
        if let Some(name) = server_name {
            let actor = servers
                .get(name)
                .cloned()
                .ok_or_else(|| McpError::NotConnected(name.to_string()))?;
            drop(servers);
            return Ok(vec![(name.to_string(), actor)]);
        }
        let mut actors = servers
            .iter()
            .map(|(name, actor)| (name.clone(), Arc::clone(actor)))
            .collect::<Vec<_>>();
        drop(servers);
        actors.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Ok(actors)
    }

    /// List resources while retaining failures from individual servers.
    /// Fan-out is concurrent and no manager-wide lock is held during I/O.
    ///
    /// # Errors
    ///
    /// Returns an error only when a specifically requested server is unknown.
    pub async fn list_resources_report(
        &self,
        server_name: Option<&str>,
    ) -> Result<McpCatalogResult<McpResource>, McpError> {
        let actors = self.actors_for_filter(server_name).await?;
        let mut pending = futures::stream::FuturesUnordered::new();
        for (name, actor) in actors {
            let run = Arc::clone(&self.run_context);
            pending.push(async move {
                let snapshot = actor.snapshot();
                let generation = snapshot.live.then_some(snapshot.generation);
                let result = match run.require(actor.required_resource()) {
                    Ok(()) => {
                        actor
                            .request(
                                run.generation().get(),
                                generation,
                                McpActorOperation::ListResources,
                            )
                            .await
                    }
                    Err(error) => Err(McpError::Capability(error)),
                };
                (name, generation, result)
            });
        }

        let mut report = McpCatalogResult {
            entries: Vec::new(),
            failures: Vec::new(),
        };
        while let Some((name, generation, result)) = pending.next().await {
            match result {
                Ok(McpActorOutput::Resources(resources)) => report.entries.extend(
                    resources
                        .into_iter()
                        .map(|resource| (name.clone(), resource)),
                ),
                Ok(_) => report.failures.push(McpCatalogFailure {
                    server: name,
                    connection_generation: generation,
                    error: McpError::Protocol(
                        "MCP actor returned the wrong response for resources/list".to_string(),
                    ),
                }),
                Err(error) => report.failures.push(McpCatalogFailure {
                    server: name,
                    connection_generation: generation,
                    error,
                }),
            }
        }
        report
            .entries
            .sort_unstable_by(|left, right| left.0.cmp(&right.0));
        report
            .failures
            .sort_unstable_by(|left, right| left.server.cmp(&right.server));
        Ok(report)
    }

    /// Compatibility resource listing. A named request fails directly; an
    /// all-server request returns successful entries and logs typed failures.
    ///
    /// # Errors
    ///
    /// Returns an error when a named server is unknown or its transport,
    /// generation, capability, or protocol admission fails.
    pub async fn list_resources(
        &self,
        server_name: Option<&str>,
    ) -> anyhow::Result<Vec<(String, McpResource)>> {
        let mut report = self.list_resources_report(server_name).await?;
        if server_name.is_some() {
            if let Some(failure) = report.failures.pop() {
                return Err(failure.error.into());
            }
        } else {
            for failure in &report.failures {
                warn!(server = %failure.server, error = %failure.error, "Failed to list MCP resources");
            }
        }
        Ok(report.entries)
    }

    /// Read a specific resource from a named server without flattening typed
    /// content. The per-server actor owns reconnect, deadline, and teardown.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` when the server is unknown or the admitted
    /// transport cannot complete and validate the resource read.
    pub async fn read_resource_typed(
        &self,
        server_name: &str,
        uri: &str,
    ) -> Result<McpReadResourceResult, McpError> {
        let actor = self.actor(server_name).await?;
        self.run_context.require(actor.required_resource())?;
        let snapshot = actor.snapshot();
        let output = actor
            .request(
                self.run_context.generation().get(),
                snapshot.live.then_some(snapshot.generation),
                McpActorOperation::ReadResource {
                    uri: uri.to_string(),
                },
            )
            .await?;
        match output {
            McpActorOutput::Resource(resource) => Ok(resource),
            _ => Err(McpError::Protocol(format!(
                "MCP server '{server_name}' returned the wrong actor response for resources/read"
            ))),
        }
    }

    /// Compatibility projection for existing text-only resource callers.
    ///
    /// # Errors
    ///
    /// Propagates registration, admission, transport, and protocol failures
    /// from [`Self::read_resource_typed`].
    pub async fn read_resource(&self, server_name: &str, uri: &str) -> anyhow::Result<String> {
        let result = self.read_resource_typed(server_name, uri).await?;
        Ok(project_mcp_resource_text(&result))
    }

    /// List prompts while retaining individual server failures.
    ///
    /// # Errors
    ///
    /// Returns an error only when a specifically requested server is unknown.
    pub async fn list_prompts_report(
        &self,
        server_name: Option<&str>,
    ) -> Result<McpCatalogResult<McpPrompt>, McpError> {
        let actors = self.actors_for_filter(server_name).await?;
        let mut pending = futures::stream::FuturesUnordered::new();
        for (name, actor) in actors {
            let run = Arc::clone(&self.run_context);
            pending.push(async move {
                let snapshot = actor.snapshot();
                let generation = snapshot.live.then_some(snapshot.generation);
                let result = match run.require(actor.required_resource()) {
                    Ok(()) => {
                        actor
                            .request(
                                run.generation().get(),
                                generation,
                                McpActorOperation::ListPrompts,
                            )
                            .await
                    }
                    Err(error) => Err(McpError::Capability(error)),
                };
                (name, generation, result)
            });
        }

        let mut report = McpCatalogResult {
            entries: Vec::new(),
            failures: Vec::new(),
        };
        while let Some((name, generation, result)) = pending.next().await {
            match result {
                Ok(McpActorOutput::Prompts(prompts)) => report
                    .entries
                    .extend(prompts.into_iter().map(|prompt| (name.clone(), prompt))),
                Ok(_) => report.failures.push(McpCatalogFailure {
                    server: name,
                    connection_generation: generation,
                    error: McpError::Protocol(
                        "MCP actor returned the wrong response for prompts/list".to_string(),
                    ),
                }),
                Err(error) => report.failures.push(McpCatalogFailure {
                    server: name,
                    connection_generation: generation,
                    error,
                }),
            }
        }
        report
            .entries
            .sort_unstable_by(|left, right| left.0.cmp(&right.0));
        report
            .failures
            .sort_unstable_by(|left, right| left.server.cmp(&right.server));
        Ok(report)
    }

    /// Compatibility prompt listing. A named request fails directly; an
    /// all-server request returns successful entries and logs typed failures.
    ///
    /// # Errors
    ///
    /// Returns an error when a named server is unknown or its prompt listing
    /// fails admission, transport, or protocol validation.
    pub async fn list_prompts(
        &self,
        server_name: Option<&str>,
    ) -> Result<Vec<(String, McpPrompt)>, McpError> {
        let mut report = self.list_prompts_report(server_name).await?;
        if server_name.is_some() {
            if let Some(failure) = report.failures.pop() {
                return Err(failure.error);
            }
        } else {
            for failure in &report.failures {
                warn!(server = %failure.server, error = %failure.error, "Failed to list MCP prompts");
            }
        }
        Ok(report.entries)
    }

    /// Resolve a typed prompt from one named server through its owned actor.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` when the server is unknown or prompt resolution
    /// fails admission, transport, or protocol validation.
    pub async fn get_prompt(
        &self,
        server_name: &str,
        prompt_name: &str,
        arguments: BTreeMap<String, String>,
    ) -> Result<McpGetPromptResult, McpError> {
        let actor = self.actor(server_name).await?;
        self.run_context.require(actor.required_resource())?;
        let snapshot = actor.snapshot();
        let output = actor
            .request(
                self.run_context.generation().get(),
                snapshot.live.then_some(snapshot.generation),
                McpActorOperation::GetPrompt {
                    prompt_name: prompt_name.to_string(),
                    arguments,
                },
            )
            .await?;
        match output {
            McpActorOutput::Prompt(prompt) => Ok(prompt),
            _ => Err(McpError::Protocol(format!(
                "MCP server '{server_name}' returned the wrong actor response for prompts/get"
            ))),
        }
    }

    /// Disconnect from a server.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if the server's transport fails to close.
    pub async fn disconnect(&self, name: &str) -> Result<(), McpError> {
        let removed = {
            let mut servers = self.servers.lock().await;
            let removed = servers.remove(name);
            if removed.is_some() {
                self.bump_catalog_epoch();
            }
            drop(servers);
            removed
        };
        if let Some(actor) = removed {
            actor.shutdown().await?;
        }
        Ok(())
    }

    /// Disconnect from all servers.
    ///
    /// # Errors
    ///
    /// Returns the first `McpError` encountered while closing servers.
    pub async fn disconnect_all(&self) -> Result<(), McpError> {
        let actors = {
            let mut servers = self.servers.lock().await;
            let actors = servers.drain().map(|(_, actor)| actor).collect::<Vec<_>>();
            if !actors.is_empty() {
                self.bump_catalog_epoch();
            }
            drop(servers);
            actors
        };
        let mut first_error = None;
        for actor in actors {
            if let Err(error) = actor.shutdown().await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }

    /// Number of registered servers (incl. disconnected/awaiting-reconnect).
    pub async fn server_count(&self) -> usize {
        self.servers.lock().await.len()
    }

    /// Non-blocking, read-only snapshot for synchronous health reporting.
    ///
    /// Returns `None` while another operation owns the server map rather than
    /// blocking a frontend or fabricating an empty manager. The tuple is
    /// `(registered, live)` and never starts, reconnects, or contacts a server.
    #[must_use]
    pub fn try_health_counts(&self) -> Option<(usize, usize)> {
        let servers = self.servers.try_lock().ok()?;
        let registered = servers.len();
        let live = servers
            .values()
            .filter(|actor| actor.snapshot().live)
            .count();
        drop(servers);
        Some((registered, live))
    }

    /// Whether a server is registered. True does NOT guarantee live;
    /// use [`Self::is_live`] for that.
    pub async fn is_connected(&self, name: &str) -> bool {
        self.servers.lock().await.contains_key(name)
    }

    /// True if the server is registered AND currently holds a live
    /// transport (fix #629). Used by tests to assert disconnect-detection.
    pub async fn is_live(&self, name: &str) -> bool {
        self.servers
            .lock()
            .await
            .get(name)
            .is_some_and(|actor| actor.snapshot().live)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mcp_permissions(server: &str, tools: &[&str]) -> crate::config::PermissionsConfig {
        crate::config::PermissionsConfig {
            enabled: true,
            default_allow: Vec::new(),
            mcp: HashMap::from([(
                server.to_string(),
                tools.iter().map(|tool| (*tool).to_string()).collect(),
            )]),
            project_proposal: None,
        }
    }

    fn protected_env(values: &[(&str, &str)]) -> crate::secrets::EnvironmentGrants {
        crate::secrets::EnvironmentGrants::from_validated(
            values
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
        )
        .expect("environment")
    }

    fn protected_headers(values: &[(&str, &str)]) -> crate::secrets::SensitiveHeaders {
        let mut headers = crate::secrets::SensitiveHeaders::new();
        for (name, value) in values {
            headers
                .insert_literal(name, (*value).to_string())
                .expect("header");
        }
        headers
    }

    fn test_run() -> &'static Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    #[test]
    fn test_mcp_tool_serialization() {
        let tool = McpTool {
            name: "read_file".to_string(),
            description: Some("Read a file".to_string()),
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            })),
            title: None,
            output_schema: None,
            annotations: None,
            icons: Vec::new(),
            meta: BTreeMap::new(),
        };

        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "read_file");
        assert_eq!(json["description"], "Read a file");
    }

    #[tokio::test]
    async fn test_mcp_manager_new() {
        let manager = McpManager::new(Arc::clone(test_run()));
        assert_eq!(manager.try_health_counts(), Some((0, 0)));
        assert_eq!(manager.server_count().await, 0);
    }

    #[test]
    fn registered_managers_are_exact_run_scoped_and_do_not_extend_lifetime() {
        let first_root = tempfile::tempdir_in(".").expect("first MCP registry root");
        let second_root = tempfile::tempdir_in(".").expect("second MCP registry root");
        let first = crate::tools::security::test_run_context_for(first_root.path());
        let second = crate::tools::security::test_run_context_for(second_root.path());
        let first_manager = Arc::new(tokio::sync::RwLock::new(McpManager::new(Arc::clone(
            &first,
        ))));
        let second_manager = Arc::new(tokio::sync::RwLock::new(McpManager::new(Arc::clone(
            &second,
        ))));

        assert!(registered_manager(&first).is_none());
        assert!(registered_manager(&second).is_none());
        assert!(install_manager(&first, &first_manager));
        assert!(!install_manager(&first, &first_manager));
        assert!(
            Arc::ptr_eq(
                &registered_manager(&first).expect("first exact manager"),
                &first_manager,
            ),
            "the first run must resolve only its own manager"
        );
        assert!(registered_manager(&second).is_none());
        assert!(install_manager(&second, &second_manager));
        assert!(Arc::ptr_eq(
            &registered_manager(&second).expect("second exact manager"),
            &second_manager,
        ));

        drop(first_manager);
        assert!(
            registered_manager(&first).is_none(),
            "the run index must not retain a manager after its frontend exits"
        );
        assert!(registered_manager(&second).is_some());
    }

    #[test]
    fn mcp_stdio_environment_is_bound_to_a_derived_run_generation() {
        let parent = test_run();
        let environment = protected_env(&[("S019_MCP_ENV", "exact")]);
        let child = derive_mcp_stdio_run(parent, &environment).expect("derive MCP stdio run");

        assert_ne!(child.run_id(), parent.run_id());
        assert_ne!(child.generation(), parent.generation());
        assert_eq!(child.session_id(), parent.session_id());
        assert_eq!(child.project_root(), parent.project_root());
        assert!(child
            .environment_grants()
            .matches_value("S019_MCP_ENV", "exact"));
        for parent_name in parent.environment_grants().keys() {
            assert!(
                !child.environment_grants().contains_key(parent_name),
                "unrelated parent environment grant {parent_name} leaked into MCP"
            );
        }
        assert!(!parent.environment_grants().contains_key("S019_MCP_ENV"));
        assert_ne!(
            child.runtime().descriptor().capabilities.manifest_digest,
            parent.runtime().descriptor().capabilities.manifest_digest
        );
        assert!(child.require(crate::tools::ToolResource::Process).is_ok());
        assert!(child.require(crate::tools::ToolResource::Network).is_err());
    }

    #[test]
    fn mcp_stdio_run_drops_unrelated_parent_roots_and_environment() {
        let project = tempfile::tempdir().expect("MCP project");
        let attachment = tempfile::tempdir().expect("MCP attachment");
        let output = tempfile::tempdir().expect("MCP auxiliary output");
        let parent =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), project.path())
                .read_only_roots(vec![attachment.path().to_path_buf()])
                .read_write_roots(vec![output.path().to_path_buf()])
                .environment_grants(HashMap::from([(
                    "PARENT_PROVIDER_TOKEN".to_string(),
                    "parent-only".to_string(),
                )]))
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(false)
                .secrets(true)
                .provider("mcp-parent-test")
                .build()
                .expect("MCP parent run");
        let declared = protected_env(&[("MCP_SERVER_TOKEN", "server-only")]);

        let child = derive_mcp_stdio_run(&parent, &declared).expect("derive MCP child");

        assert!(!child
            .read_only_roots()
            .iter()
            .any(|root| root == attachment.path()));
        assert!(!child
            .read_write_roots()
            .iter()
            .any(|root| root == output.path()));
        assert!(child
            .environment_grants()
            .matches_value("MCP_SERVER_TOKEN", "server-only"));
        assert!(!child
            .environment_grants()
            .contains_key("PARENT_PROVIDER_TOKEN"));
    }

    #[test]
    fn mcp_secret_environment_validation_uses_only_the_run_snapshot() {
        let root = tempfile::tempdir_in(".").expect("MCP secret root");
        let key = "SERVICE_API_KEY";
        let run =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::new())
                .mcp_environment_grants(HashMap::from([(key.to_string(), "captured".to_string())]))
                .workspace_access(crate::tools::WorkspaceAccess::ReadOnly)
                .process(true)
                .network(false)
                .secrets(true)
                .provider("mcp-secret-snapshot-test")
                .build()
                .expect("secret-authorized MCP run");

        validate_mcp_child_environment(
            &run,
            &HashMap::from([(key.to_string(), "captured".to_string())]),
        )
        .expect("exact captured value is authorized");
        let mismatch = validate_mcp_child_environment(
            &run,
            &HashMap::from([(key.to_string(), "changed".to_string())]),
        )
        .expect_err("a later value cannot replace the run snapshot");
        assert!(mismatch.to_string().contains("immutable run capability"));

        let missing = validate_mcp_child_environment(
            test_run(),
            &HashMap::from([(key.to_string(), "captured".to_string())]),
        )
        .expect_err("an unrelated run cannot borrow the secret grant");
        assert!(missing.to_string().contains("before the run starts"));
    }

    #[tokio::test]
    async fn test_tools_as_openai_functions() {
        // This would require a mock server, so just test the format
        let manager = McpManager::new(Arc::clone(test_run()));
        let functions = manager.tools_as_openai_functions().await;
        assert!(functions.is_empty());
    }

    #[test]
    fn test_http_transport_new() {
        // SSRF guard (fix #677) blocks loopback, so use new_unchecked
        // to exercise base_url normalisation without a real network.
        let transport = HttpTransport::__test_new_unchecked("http://localhost:8080/");
        assert_eq!(transport.base_url, "http://localhost:8080");
    }

    #[test]
    fn headers_helper_stdout_must_be_json_object_with_string_values() {
        let headers =
            parse_headers_helper_stdout("svc", br#"{"Authorization":"Bearer dynamic"}"#).unwrap();
        assert!(headers.matches_value("Authorization", "Bearer dynamic"));

        let non_object = parse_headers_helper_stdout("svc", br#"["not-an-object"]"#).unwrap_err();
        assert!(non_object.to_string().contains("did not emit valid JSON"));

        let non_string =
            parse_headers_helper_stdout("svc", br#"{"Authorization":42}"#).unwrap_err();
        assert!(non_string.to_string().contains("did not emit valid JSON"));
    }

    #[test]
    fn headers_helper_dynamic_headers_override_static_case_insensitively() {
        let mut headers =
            protected_headers(&[("Authorization", "Bearer static"), ("X-Static", "kept")]);
        let dynamic =
            protected_headers(&[("authorization", "Bearer dynamic"), ("X-Dynamic", "added")]);

        merge_dynamic_headers(&mut headers, &dynamic);

        assert_eq!(headers.len(), 3);
        assert!(headers.matches_value("authorization", "Bearer dynamic"));
        assert!(headers.matches_value("X-Static", "kept"));
        assert!(headers.matches_value("X-Dynamic", "added"));
    }

    #[cfg(unix)]
    #[test]
    fn headers_helper_receives_documented_server_environment() {
        let command = concat!(
            "printf '{\"X-Server\":\"%s\",\"X-Url\":\"%s\"}' ",
            "\"$CLAUDE_CODE_MCP_SERVER_NAME\" \"$CLAUDE_CODE_MCP_SERVER_URL\""
        );
        let headers = run_headers_helper(
            test_run(),
            command,
            "internal-api",
            "https://mcp.example.test/mcp",
        )
        .unwrap();

        assert!(headers.matches_value("X-Server", "internal-api"));
        assert!(headers.matches_value("X-Url", "https://mcp.example.test/mcp"));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_http_headers_merges_static_and_helper_headers() {
        let static_headers =
            protected_headers(&[("Authorization", "Bearer static"), ("X-Static", "kept")]);
        let command = "printf '{\"authorization\":\"Bearer dynamic\",\"X-Helper\":\"added\"}'";

        let headers = resolve_http_headers(
            test_run(),
            "internal-api",
            "https://mcp.example.test/mcp",
            &static_headers,
            Some(command),
        )
        .unwrap();

        assert!(headers.matches_value("authorization", "Bearer dynamic"));
        assert!(headers.matches_value("X-Static", "kept"));
        assert!(headers.matches_value("X-Helper", "added"));
    }

    #[test]
    fn test_json_rpc_request_serialization() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "test".to_string(),
            params: Some(json!({"key": "value"})),
        };

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 1);
        assert_eq!(json["method"], "test");
        assert_eq!(json["params"]["key"], "value");
    }

    #[test]
    fn test_mcp_error_variants() {
        // Test ToolNotFound variant
        let err = McpError::ToolNotFound("missing_tool".to_string());
        assert!(err.to_string().contains("missing_tool"));

        // Test NotConnected variant
        let err = McpError::NotConnected("server1".to_string());
        assert!(err.to_string().contains("server1"));

        // Test Timeout variant (fix #628 — struct variant with phase)
        let err = McpError::Timeout {
            phase: "initialize",
        };
        assert!(err.to_string().contains("timeout"));
        assert!(err.to_string().contains("initialize"));
    }

    #[test]
    fn test_mcp_capabilities_parsing() {
        let caps_json = r#"{
            "tools": {"listChanged": true},
            "resources": {"subscribe": true},
            "prompts": {"listChanged": false}
        }"#;

        let caps: McpCapabilities = serde_json::from_str(caps_json).unwrap();
        assert!(caps.tools.is_some());
        assert!(caps.resources.is_some());
        assert!(caps.prompts.is_some());

        // Access list_changed field
        let tools = caps.tools.unwrap();
        assert!(tools.list_changed);
    }

    #[test]
    fn test_mcp_server_info_parsing() {
        let info_json = r#"{"name": "test-server", "version": "1.0.0"}"#;
        let info: McpServerInfo = serde_json::from_str(info_json).unwrap();
        assert_eq!(info.name, "test-server");
        assert_eq!(info.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_json_rpc_error_with_data() {
        let error_json = r#"{
            "code": -32600,
            "message": "Invalid Request",
            "data": {"details": "missing field"}
        }"#;

        let error: JsonRpcError = serde_json::from_str(error_json).unwrap();
        assert_eq!(error.code, -32600);
        assert_eq!(error.message, "Invalid Request");
        assert!(error.data.is_some());
        let data = error.data.unwrap();
        assert_eq!(data["details"], "missing field");
    }

    #[tokio::test]
    async fn test_mcp_manager_call_tool_invalid_format() {
        let manager = McpManager::new(Arc::clone(test_run()));

        // Test with no delimiters
        let result = manager.call_tool("invalidtool", json!({})).await;
        assert!(matches!(result, Err(McpError::ToolNotFound(_))));

        // Test with old single-underscore format (should fail)
        let result = manager.call_tool("server_tool", json!({})).await;
        assert!(matches!(result, Err(McpError::ToolNotFound(_))));

        // Test with double-underscore but no mcp prefix
        let result = manager.call_tool("server__tool", json!({})).await;
        assert!(matches!(result, Err(McpError::ToolNotFound(_))));
    }

    #[tokio::test]
    async fn test_mcp_manager_call_tool_not_connected() {
        let manager = McpManager::new(Arc::clone(test_run()));

        // Test with valid mcp__server__tool format but server not connected
        let result = manager.call_tool("mcp__server__tool", json!({})).await;
        assert!(matches!(result, Err(McpError::NotConnected(_))));
    }

    #[tokio::test]
    async fn test_mcp_manager_call_tool_underscored_server_name() {
        let manager = McpManager::new(Arc::clone(test_run()));

        // Server names with underscores should parse correctly
        let result = manager
            .call_tool("mcp__my_server__my_tool", json!({}))
            .await;
        // Should get NotConnected (not ToolNotFound), proving parse worked
        assert!(matches!(result, Err(McpError::NotConnected(_))));
        if let Err(McpError::NotConnected(name)) = result {
            assert_eq!(name, "my_server");
        }
    }

    #[tokio::test]
    async fn test_mcp_manager_call_tool_with_timeout() {
        let manager = McpManager::new(Arc::clone(test_run()));

        // Test timeout (will fail because no server, but exercises the code path)
        let result = manager
            .call_tool_with_timeout("mcp__server__tool", json!({}), Duration::from_millis(100))
            .await;
        // Should get NotConnected error, not Timeout (since call fails immediately)
        assert!(matches!(result, Err(McpError::NotConnected(_))));
    }

    #[tokio::test]
    async fn test_mcp_manager_is_connected() {
        let manager = McpManager::new(Arc::clone(test_run()));
        assert!(!manager.is_connected("nonexistent").await);
    }

    #[tokio::test]
    async fn test_mcp_manager_get_server_info() {
        let manager = McpManager::new(Arc::clone(test_run()));
        assert!(manager.get_server_info("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_mcp_manager_disconnect_nonexistent() {
        let manager = McpManager::new(Arc::clone(test_run()));
        // Should not error when disconnecting non-existent server
        let result = manager.disconnect("nonexistent").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mcp_manager_disconnect_all_empty() {
        let manager = McpManager::new(Arc::clone(test_run()));
        let result = manager.disconnect_all().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_mcp_resource_serialization() {
        let resource = McpResource {
            uri: "file:///src/main.rs".to_string(),
            name: "main.rs".to_string(),
            description: Some("Main entry point".to_string()),
            mime_type: Some("text/x-rust".to_string()),
            title: None,
            size: None,
            annotations: None,
            icons: Vec::new(),
            meta: BTreeMap::new(),
        };

        let json = serde_json::to_value(&resource).unwrap();
        assert_eq!(json["uri"], "file:///src/main.rs");
        assert_eq!(json["name"], "main.rs");
        assert_eq!(json["description"], "Main entry point");
        assert_eq!(json["mimeType"], "text/x-rust");
    }

    #[test]
    fn test_mcp_resource_deserialization() {
        let json =
            r#"{"uri": "db://users", "name": "Users Table", "mimeType": "application/json"}"#;
        let resource: McpResource = serde_json::from_str(json).unwrap();
        assert_eq!(resource.uri, "db://users");
        assert_eq!(resource.name, "Users Table");
        assert!(resource.description.is_none());
        assert_eq!(resource.mime_type, Some("application/json".to_string()));
    }

    #[test]
    fn test_mcp_resource_minimal() {
        let json = r#"{"uri": "test://resource", "name": "test"}"#;
        let resource: McpResource = serde_json::from_str(json).unwrap();
        assert_eq!(resource.uri, "test://resource");
        assert_eq!(resource.name, "test");
        assert!(resource.description.is_none());
        assert!(resource.mime_type.is_none());
    }

    #[tokio::test]
    async fn test_mcp_manager_list_resources_empty() {
        let manager = McpManager::new(Arc::clone(test_run()));
        let resources = manager.list_resources(None).await.unwrap();
        assert!(resources.is_empty());
    }

    #[tokio::test]
    async fn test_mcp_manager_list_resources_server_not_connected() {
        let manager = McpManager::new(Arc::clone(test_run()));
        let result = manager.list_resources(Some("nonexistent")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mcp_manager_read_resource_not_connected() {
        let manager = McpManager::new(Arc::clone(test_run()));
        let result = manager.read_resource("nonexistent", "file:///test").await;
        assert!(result.is_err());
    }

    // ─── Fix #445 — StdioTransport stderr drain + bounded read ──────────
    //
    // Each test spawns a real subprocess via `sh -c` and exercises
    // StdioTransport end to end. <200 ms per test; POSIX-only (`sh` and
    // `head` must exist on PATH, which matches the project baseline).
    //
    // Forensic evidence: with the pre-fix `BufReader::read_line` the
    // oversized-line test would either OOM or block; with no stderr
    // drain a server writing more than ~64 KiB to stderr would deadlock
    // on `write(2)`. Both scenarios now complete deterministically.

    fn stdio_test_run() -> &'static Arc<crate::tools::ToolRunContext> {
        static RUN: std::sync::OnceLock<Arc<crate::tools::ToolRunContext>> =
            std::sync::OnceLock::new();
        RUN.get_or_init(|| {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/test-workspaces")
                .join(format!("mcp-stdio-{}", std::process::id()));
            std::fs::create_dir_all(&root).expect("isolated MCP stdio fixture root");
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), &root)
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::new())
                .workspace_access(crate::tools::WorkspaceAccess::ReadOnly)
                .process(true)
                .network(false)
                .secrets(false)
                .provider("mcp-stdio-fixture")
                .build()
                .expect("MCP stdio fixture run")
        })
    }

    fn spawn_sh(script: &str) -> Result<StdioTransport, McpError> {
        StdioTransport::spawn(stdio_test_run(), "sh", &["-c", script])
    }

    fn spawn_python(script: &str) -> Result<StdioTransport, McpError> {
        StdioTransport::spawn(stdio_test_run(), "python3", &["-u", "-c", script])
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writable_stdio_checkpoints_each_request() {
        let root = tempfile::tempdir_in(".").expect("writable MCP fixture root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let script = r#"
import json
import pathlib
import sys

for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    if method == "write":
        pathlib.Path("mcp-output").write_text("committed", encoding="utf-8")
        response = {"jsonrpc":"2.0","id":request["id"],"result":{"written":True}}
    elif method == "fail":
        pathlib.Path("mcp-output").write_text("must-roll-back", encoding="utf-8")
        pathlib.Path("failed-output").write_text("must-roll-back", encoding="utf-8")
        response = {"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":"fixture failure"}}
    else:
        value = pathlib.Path("mcp-output").read_text(encoding="utf-8")
        response = {"jsonrpc":"2.0","id":request["id"],"result":{"value":value}}
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()
"#;
        let transport =
            StdioTransport::spawn(&run, "python3", &["-u", "-c", script]).expect("spawn MCP");

        transport
            .request("write", None)
            .await
            .expect("successful MCP write");
        assert_eq!(
            std::fs::read_to_string(root.path().join("mcp-output")).expect("published MCP output"),
            "committed"
        );

        let error = transport
            .request("fail", None)
            .await
            .expect_err("failed MCP request");
        assert!(error.to_string().contains("fixture failure"));
        assert_eq!(
            std::fs::read_to_string(root.path().join("mcp-output")).expect("preserved checkpoint"),
            "committed"
        );
        assert!(!root.path().join("failed-output").exists());

        let result = transport
            .request("read", None)
            .await
            .expect("server continues after rollback");
        assert_eq!(result["value"], "committed");
        transport.close().await.expect("close MCP transport");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(target_os = "linux")]
    async fn cancelling_writable_stdio_request_kills_server_without_publishing() {
        let root = tempfile::tempdir_in(".").expect("cancelled MCP fixture root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let script = r#"
import json
import pathlib
import sys
import time

for line in sys.stdin:
    json.loads(line)
    pathlib.Path("cancelled-output").write_text("must-not-publish", encoding="utf-8")
    sys.stderr.write("candidate-written\n")
    sys.stderr.flush()
    time.sleep(30)
"#;
        let transport = Arc::new(
            StdioTransport::spawn(&run, "python3", &["-u", "-c", script]).expect("spawn MCP"),
        );
        let pid = transport.pid;
        let request_transport = Arc::clone(&transport);
        let request = tokio::spawn(async move { request_transport.request("write", None).await });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let stderr = transport.stderr_buf_handle().lock().await.clone();
            if String::from_utf8_lossy(&stderr).contains("candidate-written") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "fixture server did not reach its mutation barrier"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        request.abort();
        assert!(request
            .await
            .expect_err("request task must cancel")
            .is_cancelled());
        let process_can_run = || {
            std::fs::read_to_string(format!("/proc/{pid}/status")).is_ok_and(|status| {
                !status
                    .lines()
                    .any(|line| line.starts_with("State:") && line.contains('Z'))
            })
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while process_can_run() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !process_can_run(),
            "cancelled writable MCP server remained runnable"
        );
        assert!(!root.path().join("cancelled-output").exists());
        transport.close().await.expect("close cancelled transport");
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "closing the cancelled transport did not reap its root process"
        );
    }

    /// Fix #445 point 1: a server that writes >64 KiB to stderr does NOT
    /// deadlock the transport. Without the drain, the server would block
    /// on `write(2)` and the stdout reply would never arrive.
    #[tokio::test]
    async fn fix445_stderr_drained_does_not_deadlock() {
        let transport = spawn_sh(
            "printf '%131072s' '' >&2; \
             read req; \
             printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n'",
        )
        .expect("spawn");

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            transport.request("ping", None),
        )
        .await
        .expect("request did not deadlock");

        assert!(result.is_ok(), "request failed: {result:?}");
        assert_eq!(result.unwrap()["ok"], true);
        let _ = transport.close().await;
    }

    /// Fix #445 point 1: the stderr drain captures server output and the
    /// ring buffer contains a recognizable suffix.
    #[tokio::test]
    async fn fix445_stderr_drain_populates_ring_buffer() {
        let transport = spawn_sh(
            "printf 'KERNEL_PANIC_MARKER_445\\n' >&2; \
             read req; \
             printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}\n'",
        )
        .expect("spawn");

        let _ = transport.request("ping", None).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let buf_handle = transport.stderr_buf_handle();
        let guard = buf_handle.lock().await;
        let snippet = String::from_utf8_lossy(&guard).into_owned();
        drop(guard);
        assert!(
            snippet.contains("KERNEL_PANIC_MARKER_445"),
            "stderr drain did not capture server output; got: {snippet:?}"
        );
        let _ = transport.close().await;
    }

    /// Fix #445 point 2: oversized line is rejected WITHOUT buffering
    /// the full payload. Pre-fix `read_line` would have allocated the
    /// whole 11 MiB before the size check.
    #[tokio::test]
    async fn fix445_oversized_line_rejected_before_full_buffering() {
        let script = format!(
            "read req; head -c {size} /dev/zero",
            size = MAX_RESPONSE_SIZE + 1024 * 1024,
        );
        let transport = spawn_sh(&script).expect("spawn");

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            transport.request("ping", None),
        )
        .await
        .expect("oversized read did not complete within timeout");

        let err = result.expect_err("oversized line should be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("exceeded") && msg.contains("without newline"),
            "expected oversized-line error, got: {msg}"
        );
        let _ = transport.close().await;
    }

    /// Sanity: a normal, well-formed response round-trips correctly.
    #[tokio::test]
    async fn fix445_normal_line_succeeds() {
        let transport = spawn_sh(
            "read req; \
             printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"value\":42}}\n'",
        )
        .expect("spawn");

        let result = transport.request("ping", None).await.expect("request ok");
        assert_eq!(result["value"], 42);
        let _ = transport.close().await;
    }

    /// Client-feature requests can arrive while a stdio transport is waiting
    /// for the response to its own request. `roots/list` is especially
    /// important because OC advertises the roots capability during initialize.
    #[tokio::test]
    async fn stdio_answers_nested_roots_list_request() {
        let script = r#"
import json
import sys

req = json.loads(sys.stdin.readline())
sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":"server-roots-900","method":"roots/list"}) + "\n")
sys.stdout.flush()
roots_reply = json.loads(sys.stdin.readline())
root = roots_reply.get("result", {}).get("roots", [{}])[0]
ok = (
    roots_reply.get("id") == "server-roots-900"
    and root.get("uri", "").startswith("file://")
    and bool(root.get("name"))
)
sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":req["id"],"result":{"roots_ok":ok,"roots_reply":roots_reply}}) + "\n")
sys.stdout.flush()
"#;
        let transport = spawn_python(script).expect("spawn python fixture");

        let result = transport.request("ping", None).await.expect("request ok");
        assert_eq!(result["roots_ok"], true, "roots response: {result}");
        let _ = transport.close().await;
    }

    /// Until the UI exposes a user-confirmation flow for MCP elicitation, OC
    /// answers with a valid conservative `decline` response instead of hanging
    /// the server or fabricating user-provided data.
    #[tokio::test]
    async fn stdio_declines_nested_elicitation_create_request() {
        let script = r#"
import json
import sys

req = json.loads(sys.stdin.readline())
sys.stdout.write(json.dumps({
    "jsonrpc":"2.0",
    "id":901,
    "method":"elicitation/create",
    "params":{
        "message":"Need a value",
        "requestedSchema":{"type":"object","properties":{"name":{"type":"string"}}}
    }
}) + "\n")
sys.stdout.flush()
elicitation_reply = json.loads(sys.stdin.readline())
ok = (
    elicitation_reply.get("id") == 901
    and elicitation_reply.get("result", {}).get("action") == "decline"
    and "content" not in elicitation_reply.get("result", {})
)
sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":req["id"],"result":{"elicitation_declined":ok,"elicitation_reply":elicitation_reply}}) + "\n")
sys.stdout.flush()
"#;
        let transport = spawn_python(script).expect("spawn python fixture");

        let result = transport.request("ping", None).await.expect("request ok");
        assert_eq!(
            result["elicitation_declined"], true,
            "elicitation response: {result}"
        );
        let _ = transport.close().await;
    }

    #[test]
    fn http_transport_advertises_no_bidirectional_client_capabilities_yet() {
        let transport = HttpTransport::__test_new_unchecked("http://127.0.0.1:9");
        assert_eq!(transport.client_capabilities(), json!({}));
    }

    // ─── Fix #490 — object-safe trait + shared HTTP client ─────────────
    //
    // Forensic evidence:
    //   1. `fix490_trait_object_compiles` — proves `McpTransport` stays
    //      object-safe. If any new method violates object-safety (e.g.
    //      a generic method, or `Self`-by-value), this test would fail
    //      to compile.
    //   2. `fix490_http_client_is_shared` — checks pointer identity of
    //      the `&'static reqwest::Client` borrowed by `HttpTransport`.
    //      With the pre-fix `reqwest::Client::new()` per construction
    //      this would FAIL because each instance owned a distinct
    //      heap-allocated client. With the shared `LazyLock` the
    //      pointer is the same across instances.
    //   3. `fix490_http_per_request_timeout_enforced` — points
    //      `HttpTransport` at a TCP server that accepts but never
    //      writes, calls send, and asserts the call returns within
    //      ~2s with a timeout error instead of hanging on the OS
    //      default.

    /// Fix #490: `McpTransport` must remain object-safe so `McpServer`
    /// can store `Box<dyn McpTransport>`. This test is the compile-time
    /// proof — if anyone adds a non-object-safe method, this fails to
    /// build.
    #[test]
    fn fix490_trait_object_compiles() {
        // `new_unchecked` because `127.0.0.1` is blocked by the
        // SSRF guard (fix #677); this test is about trait object-
        // safety, not URL validation.
        let http: Box<dyn McpTransport> =
            Box::new(HttpTransport::__test_new_unchecked("http://127.0.0.1:1"));
        // Touch a method to prove the vtable is callable through the
        // trait object (statically — we don't actually `.await` here).
        let _fut = http.close();
        // Also assert via a type-position binding that &dyn works.
        let _r: &dyn McpTransport = http.as_ref();
    }

    /// Fix #490: every `HttpTransport` borrows the SAME process-wide
    /// `reqwest::Client`. Pointer equality of the `&'static` reference
    /// is the strongest possible evidence.
    #[test]
    fn fix490_http_client_is_shared() {
        // `new_unchecked` because `.invalid` hostnames don't resolve
        // and the SSRF guard would reject them; we only need two
        // distinct transport handles to compare client pointers.
        let a = HttpTransport::__test_new_unchecked("http://example.invalid/a");
        let b = HttpTransport::__test_new_unchecked("http://example.invalid/b");
        // Force the LazyLock so the static is materialised.
        let direct = match &*SHARED_MCP_HTTP_CLIENT {
            Ok(client) => client,
            Err(err) => panic!("shared MCP HTTP client must initialize: {err}"),
        };
        let client_a = match HttpTransport::client() {
            Ok(client) => client,
            Err(err) => panic!("transport client accessor must initialize: {err}"),
        };
        let client_b = match HttpTransport::client() {
            Ok(client) => client,
            Err(err) => panic!("transport client accessor must initialize: {err}"),
        };
        let _ = &a;
        let _ = &b;
        let p_a = std::ptr::from_ref::<reqwest::Client>(client_a);
        let p_b = std::ptr::from_ref::<reqwest::Client>(client_b);
        let p_d = std::ptr::from_ref::<reqwest::Client>(direct);
        assert_eq!(p_a, p_b, "two HttpTransports must share one client");
        assert_eq!(p_a, p_d, "shared client must equal the static itself");
    }

    #[test]
    fn shared_mcp_http_client_builder_succeeds() {
        if let Err(err) = build_shared_mcp_http_client() {
            panic!("shared MCP HTTP client builder must succeed: {err}");
        }
    }

    /// Fix #490: per-request timeout is set on the `RequestBuilder`
    /// (not on the shared client), so a stalled server returns a
    /// timeout error within the per-request cap. We point the
    /// transport at a TCP server that accepts the connection but
    /// never writes a byte — simulating a stalled MCP HTTP endpoint
    /// — and use a 250ms override at the call site to keep the unit
    /// test fast. The production cap (`HTTP_REQUEST_TIMEOUT` = 60s)
    /// is enforced by the same mechanism this test exercises.
    #[tokio::test]
    async fn fix490_http_per_request_timeout_enforced() {
        use tokio::io::AsyncReadExt as _;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let _server = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                while sock.read(&mut buf).await.unwrap_or(0) > 0 {}
            }
        });

        let url = format!("http://{addr}");
        // `new_unchecked`: the loopback URL we just bound would be
        // rejected by the SSRF guard, but the test deliberately points
        // at our own listener to simulate a stalled server.
        let transport = HttpTransport::__test_new_unchecked(&url);
        let id = transport.request_id.fetch_add(1, Ordering::SeqCst);
        let body = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: "ping".to_string(),
            params: None,
        };
        let start = std::time::Instant::now();
        let client = match HttpTransport::client() {
            Ok(client) => client,
            Err(err) => panic!("shared MCP HTTP client must initialize: {err}"),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            client
                .post(&url)
                .timeout(Duration::from_millis(250))
                .json(&body)
                .send(),
        )
        .await;
        let elapsed = start.elapsed();

        let inner = result.expect("outer timeout fired — per-request timeout did not enforce");
        let err = inner.expect_err("stalled server must produce an error");
        assert!(
            err.is_timeout() || err.is_request(),
            "expected timeout-like reqwest error, got: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "per-request timeout should fire fast (<2s), took {elapsed:?}"
        );
    }

    /// Fix #445 point 1: concurrent request + drain does not deadlock,
    /// across multiple sequential requests on the same transport with
    /// stderr traffic interleaved.
    #[tokio::test]
    async fn fix445_concurrent_drain_and_request_no_deadlock() {
        let transport = spawn_sh(
            "for i in 1 2 3 4 5; do printf 'noise-%s\\n' \"$i\" >&2; done; \
             read req1; \
             printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":1}\n'; \
             for i in 6 7 8 9 10; do printf 'noise-%s\\n' \"$i\" >&2; done; \
             read req2; \
             printf '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":2}\n'",
        )
        .expect("spawn");

        let r1 = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            transport.request("first", None),
        )
        .await
        .expect("first request did not deadlock")
        .expect("first request returned error");
        assert_eq!(r1, serde_json::json!(1));

        let r2 = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            transport.request("second", None),
        )
        .await
        .expect("second request did not deadlock")
        .expect("second request returned error");
        assert_eq!(r2, serde_json::json!(2));

        let _ = transport.close().await;
    }

    /// In-memory transport used to drive [`McpServer::new_with_config`]
    /// without a child process. `responses` lists canned replies in the
    /// order they will be returned; `delay_first_response` introduces a
    /// configurable sleep on the FIRST call so we can simulate a stalled
    /// initialize. The transport never blocks indefinitely on its own —
    /// the only stall source is the configured delay.
    struct FakeTransport {
        responses: std::sync::Mutex<std::collections::VecDeque<Value>>,
        delay_first_response: std::sync::Mutex<Option<Duration>>,
        close_count: Arc<AtomicUsize>,
    }

    impl FakeTransport {
        fn new(responses: Vec<Value>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses.into()),
                delay_first_response: std::sync::Mutex::new(None),
                close_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn with_initial_delay(self, delay: Duration) -> Self {
            *self.delay_first_response.lock().expect("lock") = Some(delay);
            self
        }

        fn close_count(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.close_count)
        }
    }

    #[async_trait]
    impl McpTransport for FakeTransport {
        async fn request(&self, method: &str, _params: Option<Value>) -> Result<Value, McpError> {
            if method == "server/discover" {
                return Err(McpError::Rpc {
                    code: -32601,
                    message: "Method not found".to_string(),
                    data: None,
                    http_status: None,
                });
            }
            // Take the delay (once); on first call we honour it.
            let delay = self.delay_first_response.lock().expect("lock").take();
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            let next = self.responses.lock().expect("lock").pop_front();
            Ok(next.unwrap_or(Value::Null))
        }

        async fn close(&self) -> Result<(), McpError> {
            self.close_count.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    struct RecordedMcpRequest {
        context: McpRequestContext,
        method: String,
        params: Option<Value>,
    }

    /// Strict current-era fixture: using the legacy `request` entry point or
    /// changing the scripted method order is a test failure, not a permissive
    /// canned response.
    struct CurrentProtocolTransport {
        requests: Arc<std::sync::Mutex<Vec<RecordedMcpRequest>>>,
        responses:
            std::sync::Mutex<std::collections::VecDeque<(&'static str, Result<Value, McpError>)>>,
        binding: McpTransportBinding,
    }

    impl CurrentProtocolTransport {
        fn new(
            binding: McpTransportBinding,
            responses: Vec<(&'static str, Result<Value, McpError>)>,
        ) -> (Self, Arc<std::sync::Mutex<Vec<RecordedMcpRequest>>>) {
            let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    requests: Arc::clone(&requests),
                    responses: std::sync::Mutex::new(responses.into()),
                    binding,
                },
                requests,
            )
        }
    }

    #[async_trait]
    impl McpTransport for CurrentProtocolTransport {
        fn binding(&self) -> McpTransportBinding {
            self.binding
        }

        async fn request(&self, method: &str, _params: Option<Value>) -> Result<Value, McpError> {
            Err(McpError::Protocol(format!(
                "current fixture unexpectedly used legacy request path for {method}"
            )))
        }

        async fn request_with_context(
            &self,
            context: McpRequestContext,
            method: &str,
            params: Option<Value>,
        ) -> Result<Value, McpError> {
            self.requests
                .lock()
                .expect("request record lock")
                .push(RecordedMcpRequest {
                    context,
                    method: method.to_string(),
                    params,
                });
            let (expected, response) = self
                .responses
                .lock()
                .expect("response queue lock")
                .pop_front()
                .ok_or_else(|| {
                    McpError::Protocol(format!(
                        "current fixture has no response for method {method}"
                    ))
                })?;
            if method != expected {
                return Err(McpError::Protocol(format!(
                    "current fixture expected method {expected}, got {method}"
                )));
            }
            response
        }

        async fn close(&self) -> Result<(), McpError> {
            Ok(())
        }
    }

    fn complete_cached(mut value: Value) -> Value {
        let object = value.as_object_mut().expect("fixture result object");
        object.insert("resultType".to_string(), json!("complete"));
        object.insert("ttlMs".to_string(), json!(0));
        object.insert("cacheScope".to_string(), json!("private"));
        value
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // One scripted flow proves every negotiated typed feature stays on one profile.
    async fn s065_current_profile_preserves_typed_features_and_request_metadata() {
        let (transport, requests) = CurrentProtocolTransport::new(
            McpTransportBinding::StreamableHttp,
            vec![
                (
                    "server/discover",
                    Ok(complete_cached(json!({
                        "supportedVersions": [CURRENT_PROTOCOL_VERSION],
                        "capabilities": {
                            "tools": {"listChanged": true},
                            "resources": {"listChanged": true, "subscribe": true},
                            "prompts": {"listChanged": true},
                            "logging": {}
                        },
                        "_meta": {
                            "io.modelcontextprotocol/serverInfo": {
                                "name": "current-fixture",
                                "version": "2026.7"
                            }
                        }
                    }))),
                ),
                (
                    "tools/list",
                    Ok(complete_cached(json!({
                        "tools": [{
                            "name": "inspect",
                            "title": "Inspect",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "trace": {"type": "string", "x-mcp-header": "Trace-Id"}
                                },
                                "required": ["trace"]
                            },
                            "outputSchema": {
                                "type": "object",
                                "properties": {"ok": {"type": "boolean"}},
                                "required": ["ok"]
                            }
                        }]
                    }))),
                ),
                (
                    "resources/list",
                    Ok(complete_cached(json!({
                        "resources": [{
                            "uri": "fixture://guide",
                            "name": "guide",
                            "title": "Fixture guide",
                            "mimeType": "text/plain"
                        }]
                    }))),
                ),
                (
                    "resources/read",
                    Ok(complete_cached(json!({
                        "contents": [
                            {"uri": "fixture://guide", "text": "hello", "mimeType": "text/plain"},
                            {"uri": "fixture://pixel", "blob": "aGVsbG8=", "mimeType": "image/png"}
                        ]
                    }))),
                ),
                (
                    "prompts/list",
                    Ok(complete_cached(json!({
                        "prompts": [{
                            "name": "review",
                            "title": "Review",
                            "arguments": [{"name": "topic", "required": true}]
                        }]
                    }))),
                ),
                (
                    "prompts/get",
                    Ok(json!({
                        "resultType": "complete",
                        "description": "A typed prompt",
                        "messages": [{
                            "role": "user",
                            "content": {"type": "text", "text": "Review MCP"}
                        }]
                    })),
                ),
                (
                    "tools/call",
                    Ok(json!({
                        "resultType": "complete",
                        "content": [
                            {"type": "text", "text": "done"},
                            {"type": "image", "data": "aGVsbG8=", "mimeType": "image/png"},
                            {"type": "resource_link", "uri": "fixture://guide", "name": "guide"},
                            {"type": "resource", "resource": {"uri": "fixture://embedded", "text": "embedded"}}
                        ],
                        "structuredContent": {"ok": true}
                    })),
                ),
            ],
        );

        let server = McpServer::new("current", Box::new(transport))
            .await
            .expect("current discovery and tool listing");
        assert_eq!(server.protocol_version(), McpProtocolVersion::V2026_07_28);
        assert_eq!(server.tools()[0].title.as_deref(), Some("Inspect"));

        let resources = server.list_resources().await.expect("typed resources/list");
        assert_eq!(resources[0].title.as_deref(), Some("Fixture guide"));
        let resource = server
            .read_resource_typed("fixture://guide")
            .await
            .expect("typed resources/read");
        assert!(matches!(
            resource.contents[1],
            McpResourceContents::Blob { .. }
        ));

        let prompts = server.list_prompts().await.expect("typed prompts/list");
        assert!(prompts[0].arguments[0].required);
        let prompt = server
            .get_prompt(
                "review",
                BTreeMap::from([("topic".to_string(), "MCP".to_string())]),
            )
            .await
            .expect("typed prompts/get");
        assert!(matches!(
            prompt.messages[0].content,
            McpContentBlock::Text { .. }
        ));

        let call = server
            .call_tool("inspect", json!({"trace": "trace value"}))
            .await
            .expect("typed tools/call");
        let typed: McpCallToolResult = serde_json::from_value(call).expect("typed tool result");
        assert_eq!(typed.content.len(), 4);
        assert_eq!(typed.structured_content, Some(json!({"ok": true})));

        let requests = requests.lock().expect("request record lock");
        assert_eq!(requests.len(), 7);
        assert!(requests.iter().all(|request| {
            request.context.version == McpProtocolVersion::V2026_07_28
                && request.params.as_ref().and_then(|params| {
                    params.pointer("/_meta/io.modelcontextprotocol~1protocolVersion")
                }) == Some(&json!(CURRENT_PROTOCOL_VERSION))
                && request.params.as_ref().and_then(|params| {
                    params.pointer("/_meta/io.modelcontextprotocol~1clientCapabilities")
                }) == Some(&json!({}))
        }));
        assert!(requests[1..].iter().all(|request| {
            request
                .params
                .as_ref()
                .and_then(|params| params.pointer("/_meta/progressToken"))
                .is_some()
        }));
        let call_request = requests
            .iter()
            .find(|request| request.method == "tools/call")
            .expect("recorded tool call");
        assert_eq!(
            call_request.context.routing_name.as_deref(),
            Some("inspect")
        );
        assert_eq!(
            call_request.context.parameter_headers,
            vec![("Mcp-Param-Trace-Id".to_string(), "trace value".to_string())]
        );
        drop(requests);
    }

    #[tokio::test]
    async fn s065_legacy_adapter_selects_the_returned_supported_revision() {
        let transport = FakeTransport::new(vec![
            json!({
                "protocolVersion": "2025-11-25",
                "serverInfo": {"name": "legacy", "version": "1"},
                "capabilities": {}
            }),
            Value::Null,
        ]);
        let server = McpServer::new("legacy", Box::new(transport))
            .await
            .expect("legacy handshake");
        assert_eq!(server.protocol_version(), McpProtocolVersion::V2025_11_25);
    }

    #[tokio::test]
    async fn s065_current_unsupported_version_error_never_falls_back() {
        let (transport, requests) = CurrentProtocolTransport::new(
            McpTransportBinding::StreamableHttp,
            vec![(
                "server/discover",
                Err(McpError::Rpc {
                    code: -32022,
                    message: "Unsupported protocol version".to_string(),
                    data: Some(json!({
                        "requested": CURRENT_PROTOCOL_VERSION,
                        "supported": ["2027-01-01"]
                    })),
                    http_status: Some(400),
                }),
            )],
        );
        let Err(error) = McpServer::new("future", Box::new(transport)).await else {
            panic!("recognized current error must not enter legacy initialize");
        };
        assert!(matches!(
            error,
            McpError::UnsupportedProtocolVersion { requested, supported }
                if requested == CURRENT_PROTOCOL_VERSION && supported == ["2027-01-01"]
        ));
        let requests = requests.lock().expect("request record lock");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "server/discover");
    }

    struct BlockingCallTransport {
        call_started: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl McpTransport for BlockingCallTransport {
        async fn request(&self, method: &str, _params: Option<Value>) -> Result<Value, McpError> {
            match method {
                "server/discover" => Err(McpError::Rpc {
                    code: -32601,
                    message: "Method not found".to_string(),
                    data: None,
                    http_status: None,
                }),
                "initialize" => Ok(json!({
                    "serverInfo": {"name": "blocking", "version": "1"},
                    "capabilities": {"tools": {"listChanged": false}}
                })),
                "notifications/initialized" => Ok(Value::Null),
                "tools/list" => Ok(json!({
                    "tools": [{
                        "name": "mutate",
                        "inputSchema": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {"value": {"type": "string"}},
                            "required": ["value"]
                        }
                    }]
                })),
                "tools/call" => {
                    self.call_started.notify_one();
                    std::future::pending::<Result<Value, McpError>>().await
                }
                other => Err(McpError::Protocol(format!(
                    "unexpected blocking fixture method: {other}"
                ))),
            }
        }

        async fn close(&self) -> Result<(), McpError> {
            Ok(())
        }
    }

    async fn insert_fake_tool_server(
        manager: &McpManager,
        server_name: &str,
        tools: Value,
        call_result: Value,
    ) {
        let transport = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": server_name, "version": "1"},
                "capabilities": {"tools": {"listChanged": false}}
            }),
            Value::Null,
            json!({"tools": tools}),
            call_result,
        ]);
        let server = McpServer::new(server_name, Box::new(transport))
            .await
            .expect("fake MCP server initializes");
        let spec = ConnectionSpec::Stdio {
            command: "unused-test-transport".to_string(),
            args: Vec::new(),
            env: crate::secrets::EnvironmentGrants::new(),
        };
        manager
            .install_actor(
                server_name.to_string(),
                ServerEntry::new_with_trust_and_tool_timeout(
                    spec,
                    server,
                    McpServerTrust::PluginGrant(format!("fixture/{server_name}")),
                    None,
                ),
            )
            .await
            .expect("fake server actor installs");
    }

    fn transport_test_run(process: bool, network: bool) -> Arc<crate::tools::ToolRunContext> {
        crate::tools::ToolRunContext::builder(
            crate::state::SessionId::new(),
            Path::new(env!("CARGO_MANIFEST_DIR")),
        )
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(crate::tools::security::WorkspaceAccess::ReadWrite)
        .process(process)
        .network(network)
        .secrets(true)
        .provider("mcp-transport-test")
        .build()
        .expect("transport test run has an explicit capability set")
    }

    async fn insert_fake_resource_server(
        manager: &McpManager,
        server_name: &str,
        binding: McpTransportBinding,
    ) {
        let transport = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": server_name, "version": "1"},
                "capabilities": {
                    "tools": {"listChanged": false},
                    "resources": {"listChanged": false}
                }
            }),
            Value::Null,
            json!({"tools": []}),
            json!({
                "resources": [{
                    "uri": format!("fixture://{server_name}/resource"),
                    "name": format!("{server_name}-resource")
                }]
            }),
        ]);
        let server = McpServer::new(server_name, Box::new(transport))
            .await
            .expect("fake resource server initializes");
        let spec = match binding {
            McpTransportBinding::Stdio => ConnectionSpec::Stdio {
                command: "unused-resource-fixture".to_string(),
                args: Vec::new(),
                env: crate::secrets::EnvironmentGrants::new(),
            },
            McpTransportBinding::StreamableHttp => ConnectionSpec::Http {
                url: "https://fixture.invalid/mcp".to_string(),
                headers: crate::secrets::SensitiveHeaders::new(),
                headers_helper: None,
                server_name: server_name.to_string(),
            },
            McpTransportBinding::InProcess => panic!("manager has no in-process connection spec"),
        };
        manager
            .install_actor(server_name.to_string(), ServerEntry::new(spec, server))
            .await
            .expect("fake resource actor installs");
    }

    async fn empty_stdio_entry(server_name: &str) -> (ServerEntry, Arc<AtomicUsize>) {
        let transport = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": server_name, "version": "1"},
                "capabilities": {}
            }),
            Value::Null,
        ]);
        let close_count = transport.close_count();
        let server = McpServer::new(server_name, Box::new(transport))
            .await
            .expect("empty fake server initializes");
        (
            ServerEntry::new(
                ConnectionSpec::Stdio {
                    command: "unused-empty-fixture".to_string(),
                    args: Vec::new(),
                    env: crate::secrets::EnvironmentGrants::new(),
                },
                server,
            ),
            close_count,
        )
    }

    #[tokio::test]
    async fn s066_replacement_and_disconnect_close_each_owned_transport() {
        let manager = McpManager::new(Arc::clone(test_run()));
        let (first_entry, first_close_count) = empty_stdio_entry("replaceable").await;
        manager
            .install_actor("replaceable".to_string(), first_entry)
            .await
            .expect("first actor installs");
        let first_generation = manager
            .connection_status("replaceable")
            .await
            .expect("first status")
            .connection_generation;

        let (replacement_entry, replacement_close_count) = empty_stdio_entry("replaceable").await;
        manager
            .install_actor("replaceable".to_string(), replacement_entry)
            .await
            .expect("replacement actor installs");
        let replacement_generation = manager
            .connection_status("replaceable")
            .await
            .expect("replacement status")
            .connection_generation;
        assert_ne!(first_generation, replacement_generation);
        assert_eq!(first_close_count.load(Ordering::Acquire), 1);

        manager
            .disconnect("replaceable")
            .await
            .expect("replacement actor disconnects");
        assert_eq!(replacement_close_count.load(Ordering::Acquire), 1);
        assert!(!manager.is_connected("replaceable").await);
    }

    #[test]
    fn s066_queued_payload_bytes_are_bounded_before_admission() {
        let operation = McpActorOperation::ReadResource {
            uri: "x".repeat(MAX_REQUEST_SIZE + 1),
        };
        assert!(matches!(
            operation.validate_queued_size(),
            Err(McpError::RequestTooLarge {
                limit: MAX_REQUEST_SIZE
            })
        ));
    }

    #[tokio::test]
    async fn s066_transport_specific_admission_retains_mixed_fanout_failures() {
        let process_run = transport_test_run(true, false);
        let process_manager = McpManager::new(Arc::clone(&process_run));
        insert_fake_resource_server(&process_manager, "stdio", McpTransportBinding::Stdio).await;
        insert_fake_resource_server(
            &process_manager,
            "http",
            McpTransportBinding::StreamableHttp,
        )
        .await;

        let report = process_manager
            .list_resources_report(None)
            .await
            .expect("registered fan-out returns a typed report");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].0, "stdio");
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].server, "http");
        assert!(matches!(
            &report.failures[0].error,
            McpError::Capability(crate::tools::ToolCapabilityError::Unavailable {
                resource: crate::tools::ToolResource::Network,
                ..
            })
        ));

        let mismatch = process_manager
            .list_resources(Some("http"))
            .await
            .expect_err("an HTTP server must fail closed without Network");
        assert!(matches!(
            mismatch.downcast_ref::<McpError>(),
            Some(McpError::Capability(
                crate::tools::ToolCapabilityError::Unavailable {
                    resource: crate::tools::ToolResource::Network,
                    ..
                }
            ))
        ));
        let status = process_manager
            .connection_status("stdio")
            .await
            .expect("stdio status exists");
        assert_eq!(status.binding, McpTransportBinding::Stdio);
        assert_eq!(
            status.required_resource,
            crate::tools::ToolResource::Process
        );
        assert_eq!(status.run_generation, process_run.generation().get());
        assert!(status.live);
        assert_eq!(status.queue_capacity, MCP_ACTOR_QUEUE_CAPACITY);
        assert_eq!(status.queue_available, MCP_ACTOR_QUEUE_CAPACITY);

        let actor = process_manager.actor("stdio").await.expect("actor exists");
        let stale_connection = actor
            .request(
                status.run_generation,
                Some(status.connection_generation.wrapping_add(1)),
                McpActorOperation::ListResources,
            )
            .await
            .expect_err("a stale connection generation must fail closed");
        assert!(matches!(
            stale_connection,
            McpError::StaleConnectionGeneration { .. }
        ));
        let stale_run = actor
            .request(
                status.run_generation.wrapping_add(1),
                Some(status.connection_generation),
                McpActorOperation::ListResources,
            )
            .await
            .expect_err("a stale run generation must fail closed");
        assert!(matches!(stale_run, McpError::StaleRunGeneration { .. }));

        let unknown = process_manager
            .list_resources_report(Some("missing"))
            .await
            .expect_err("an unknown server identity must fail closed");
        assert!(matches!(unknown, McpError::NotConnected(ref name) if name == "missing"));
        process_manager
            .disconnect_all()
            .await
            .expect("all resource actors shut down");

        let network_manager = McpManager::new(transport_test_run(false, true));
        insert_fake_resource_server(
            &network_manager,
            "http",
            McpTransportBinding::StreamableHttp,
        )
        .await;
        let http_resources = network_manager
            .list_resources(Some("http"))
            .await
            .expect("HTTP-only run admits an HTTP MCP transport");
        assert_eq!(http_resources.len(), 1);
        assert_eq!(http_resources[0].0, "http");
        network_manager
            .disconnect_all()
            .await
            .expect("HTTP actor shuts down");
    }

    #[tokio::test]
    async fn s064_snapshot_is_deterministic_allowlisted_and_schema_validated() {
        let manager = McpManager::new_with_permissions(
            Arc::clone(test_run()),
            mcp_permissions("svc", &["echo", "bad", "missing"]),
        );
        insert_fake_tool_server(
            &manager,
            "svc",
            json!([
                {
                    "name": "echo",
                    "description": "untrusted server prose",
                    "inputSchema": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"]
                    }
                },
                {
                    "name": "hidden",
                    "inputSchema": {"type": "object"}
                },
                {
                    "name": "bad",
                    "inputSchema": {"type": "string"}
                }
            ]),
            json!({"content": [{"type": "text", "text": "pong"}]}),
        )
        .await;

        let first = manager.tool_catalog_snapshot().await;
        let second = manager.tool_catalog_snapshot().await;
        assert_eq!(
            first, second,
            "unchanged manager state must hash deterministically"
        );
        assert_eq!(first.definitions.len(), 1);
        assert_eq!(
            first.definitions[0].pointer("/function/name"),
            Some(&json!("mcp__svc__echo"))
        );
        assert_eq!(
            first.definitions[0].pointer("/x-openclaudia-mcp-registration/trust"),
            Some(&json!("fixture/svc"))
        );
        assert!(
            first.unavailable.iter().all(|item| item.tool != "hidden"),
            "unlisted remote inventories must stay denied without inflating each request snapshot"
        );
        assert!(first
            .unavailable
            .iter()
            .any(|item| item.tool == "bad" && item.reason.contains("type 'object'")));
        assert!(first
            .unavailable
            .iter()
            .any(|item| item.tool == "missing" && item.reason.contains("absent")));
        let oversized_identity = format!("mcp__{}__{}", "s".repeat(100), "t".repeat(100));
        assert!(
            split_mcp_tool_identity(&oversized_identity).is_err(),
            "manager identities must fit the progressive catalog's canonical-name bound"
        );
    }

    struct CanonicalMcpFixture {
        _root: tempfile::TempDir,
        run: Arc<crate::tools::ToolRunContext>,
        manager: Arc<tokio::sync::RwLock<McpManager>>,
        call: crate::tools::ToolCall,
        permissions: crate::permissions::PermissionManager,
    }

    impl CanonicalMcpFixture {
        async fn execute(&self) -> crate::tools::ToolResult {
            crate::services::tool_executor::ToolExecutor::execute_mcp(
                crate::services::tool_executor::ToolExecutorRequest {
                    run_context: &self.run,
                    tool_call: &self.call,
                    memory_db: None,
                    app_config: None,
                    task_mgr: None,
                    permission_mgr: &self.permissions,
                    authorization: None,
                    session_id: Some("s064"),
                    policy_enforcer: None,
                },
            )
            .await
        }
    }

    async fn canonical_mcp_fixture() -> CanonicalMcpFixture {
        let root = tempfile::tempdir().expect("tempdir");
        let run =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root.path())
                .working_directory(root.path())
                .host_startup_grants()
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(true)
                .secrets(true)
                .provider("test")
                .build()
                .expect("run");
        let manager = Arc::new(tokio::sync::RwLock::new(McpManager::new_with_permissions(
            Arc::clone(&run),
            mcp_permissions("svc", &["echo"]),
        )));
        let manager_guard = manager.read().await;
        insert_fake_tool_server(
            &manager_guard,
            "svc",
            json!([{
                "name": "echo",
                "inputSchema": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"]
                }
            }]),
            json!({
                "content": [{"type": "text", "text": "pong"}],
                "structuredContent": {"reply": "pong"}
            }),
        )
        .await;
        drop(manager_guard);
        assert!(install_manager(&run, &manager));

        let dynamic = manager.read().await.tool_catalog_snapshot().await;
        let messages = vec![json!({"role": "user", "content": "use echo"})];
        let first = crate::tools::get_progressive_tool_definitions_with_additional(
            &run,
            &messages,
            false,
            &dynamic.definitions,
        )
        .expect("first catalog");
        let mut select = HashMap::new();
        select.insert("query".to_string(), json!("select:mcp__svc__echo"));
        select.insert("max_results".to_string(), json!(1));
        select.insert(
            "catalog_generation".to_string(),
            json!(first.generation.to_string()),
        );
        run.tool_catalog()
            .activate(&run, &select)
            .expect("activate MCP schema");
        let published = crate::tools::get_progressive_tool_definitions_with_additional(
            &run,
            &messages,
            false,
            &dynamic.definitions,
        )
        .expect("published catalog");
        assert!(published
            .active_names
            .iter()
            .any(|name| name == "mcp__svc__echo"));
        let call = crate::tools::ToolCall {
            id: "call-s064".to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "mcp__svc__echo".to_string(),
                arguments: json!({"text": "ping"}).to_string(),
            },
        };
        CanonicalMcpFixture {
            _root: root,
            run,
            manager,
            call,
            permissions: crate::permissions::PermissionManager::unrestricted(),
        }
    }

    #[tokio::test]
    async fn s064_canonical_executor_round_trips_and_rejects_stale_generation() {
        let fixture = canonical_mcp_fixture().await;
        let result = fixture.execute().await;
        assert!(
            !result.is_error(),
            "unexpected result: {}",
            result.content()
        );
        assert_eq!(result.content(), "pong");

        // Republish the exact old definition, then advance only the manager
        // generation. The active catalog receipt must no longer authorize it.
        fixture.manager.read().await.bump_catalog_epoch();
        let stale = fixture.execute().await;
        assert!(stale.is_error());
        assert!(stale.content().contains("stale"), "{}", stale.content());
    }

    #[tokio::test]
    async fn s064_direct_dispatch_denies_unlisted_and_invalid_calls_before_transport() {
        let manager = McpManager::new_with_permissions(
            Arc::clone(test_run()),
            mcp_permissions("svc", &["echo"]),
        );
        insert_fake_tool_server(
            &manager,
            "svc",
            json!([
                {
                    "name": "echo",
                    "inputSchema": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"]
                    }
                },
                {
                    "name": "hidden",
                    "inputSchema": {"type": "object"}
                }
            ]),
            json!({"content": [{"type": "text", "text": "pong"}]}),
        )
        .await;

        let denied = manager
            .call_tool("mcp__svc__hidden", json!({}))
            .await
            .expect_err("unlisted server tool must be denied");
        assert!(matches!(denied, McpError::ToolNotAllowed { .. }));

        let malformed = manager
            .call_tool("mcp__svc__echo", json!({}))
            .await
            .expect_err("schema-invalid arguments must be denied");
        assert!(matches!(malformed, McpError::InvalidToolArguments { .. }));

        let valid = manager
            .call_tool("mcp__svc__echo", json!({"text": "ping"}))
            .await
            .expect("earlier denials must not consume the transport response");
        assert_eq!(valid.pointer("/content/0/text"), Some(&json!("pong")));
    }

    #[tokio::test]
    async fn s064_dispatch_boundary_fires_only_when_remote_call_becomes_cancellation_unsafe() {
        let manager = Arc::new(McpManager::new_with_permissions(
            Arc::clone(test_run()),
            mcp_permissions("svc", &["mutate"]),
        ));
        let call_started = Arc::new(tokio::sync::Notify::new());
        let server = McpServer::new(
            "svc",
            Box::new(BlockingCallTransport {
                call_started: Arc::clone(&call_started),
            }),
        )
        .await
        .expect("blocking MCP server initializes");
        let spec = ConnectionSpec::Stdio {
            command: "unused-blocking-test-transport".to_string(),
            args: Vec::new(),
            env: crate::secrets::EnvironmentGrants::new(),
        };
        manager
            .install_actor("svc".to_string(), ServerEntry::new(spec, server))
            .await
            .expect("blocking server actor installs");

        let snapshot = manager.tool_catalog_snapshot().await;
        let source_digest = mcp_definition_digest(&snapshot.definitions[0])
            .expect("registration definition hashes");
        let invalid_dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let invalid_evidence = Arc::clone(&invalid_dispatched);
        let invalid = manager
            .call_tool_registered_with_dispatch(
                "mcp__svc__mutate",
                json!({}),
                source_digest,
                move || invalid_evidence.store(true, Ordering::Release),
            )
            .await
            .expect_err("schema-invalid call must stop before remote dispatch");
        assert!(matches!(invalid, McpError::InvalidToolArguments { .. }));
        assert!(!invalid_dispatched.load(Ordering::Acquire));

        let valid_dispatched = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dispatch_evidence = Arc::clone(&valid_dispatched);
        let manager_for_call = Arc::clone(&manager);
        let call = tokio::spawn(async move {
            manager_for_call
                .call_tool_registered_with_dispatch(
                    "mcp__svc__mutate",
                    json!({"value": "changed"}),
                    source_digest,
                    move || dispatch_evidence.store(true, Ordering::Release),
                )
                .await
        });
        call_started.notified().await;
        assert!(
            valid_dispatched.load(Ordering::Acquire),
            "effect accounting boundary must run before polling the remote call"
        );
        call.abort();
        assert!(call
            .await
            .expect_err("fixture call is cancelled")
            .is_cancelled());
    }

    #[tokio::test]
    async fn s066_actor_queue_applies_backpressure_and_shutdown_drains_waiters() {
        let manager = McpManager::new_with_permissions(
            Arc::clone(test_run()),
            mcp_permissions("svc", &["mutate"]),
        );
        let call_started = Arc::new(tokio::sync::Notify::new());
        let server = McpServer::new(
            "svc",
            Box::new(BlockingCallTransport {
                call_started: Arc::clone(&call_started),
            }),
        )
        .await
        .expect("blocking MCP server initializes");
        let spec = ConnectionSpec::Stdio {
            command: "unused-blocking-test-transport".to_string(),
            args: Vec::new(),
            env: crate::secrets::EnvironmentGrants::new(),
        };
        manager
            .install_actor("svc".to_string(), ServerEntry::new(spec, server))
            .await
            .expect("blocking actor installs");
        let actor = manager.actor("svc").await.expect("actor exists");
        let status = manager
            .connection_status("svc")
            .await
            .expect("status exists");

        let operation = || McpActorOperation::CallTool {
            full_name: "mcp__svc__mutate".to_string(),
            tool_name: "mutate".to_string(),
            arguments: json!({"value": "bounded"}),
            expected_source_digest: None,
            on_dispatch: None,
        };
        let first_actor = Arc::clone(&actor);
        let first = tokio::spawn(async move {
            first_actor
                .request(
                    status.run_generation,
                    Some(status.connection_generation),
                    operation(),
                )
                .await
        });
        call_started.notified().await;

        let mut queued = Vec::with_capacity(MCP_ACTOR_QUEUE_CAPACITY);
        for _ in 0..MCP_ACTOR_QUEUE_CAPACITY {
            let queued_actor = Arc::clone(&actor);
            queued.push(tokio::spawn(async move {
                queued_actor
                    .request(
                        status.run_generation,
                        Some(status.connection_generation),
                        McpActorOperation::CallTool {
                            full_name: "mcp__svc__mutate".to_string(),
                            tool_name: "mutate".to_string(),
                            arguments: json!({"value": "queued"}),
                            expected_source_digest: None,
                            on_dispatch: None,
                        },
                    )
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while actor.sender.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fixture requests fill the bounded mailbox");

        let overflow = actor
            .request(
                status.run_generation,
                Some(status.connection_generation),
                operation(),
            )
            .await
            .expect_err("a full actor mailbox must reject new work");
        assert!(matches!(
            overflow,
            McpError::Backpressure {
                capacity: MCP_ACTOR_QUEUE_CAPACITY,
                ..
            }
        ));

        manager
            .disconnect("svc")
            .await
            .expect("shutdown closes the owned actor");
        assert!(first.await.expect("first waiter joins").is_err());
        for waiter in queued {
            assert!(waiter.await.expect("queued waiter joins").is_err());
        }
    }

    // ─── Fix #628 — initialize-handshake timeout ───────────────────────
    //
    // Forensic evidence: the pre-fix `McpServer::new` chained
    // `server.initialize().await?` directly, with NO `tokio::time::timeout`
    // guard. A non-responsive transport (one whose `request` future
    // never resolves) would block the calling tokio task forever
    // because `transport.request("initialize", ...)` has no built-in
    // deadline. These tests would hang the runtime entirely without the
    // fix; with the fix they complete deterministically in well under
    // a second.

    /// Fix #628: a transport that stalls on the FIRST request (the
    /// initialize handshake) MUST cause `McpServer::new_with_config`
    /// to return `McpError::Timeout { phase: "initialize" }` within
    /// the configured deadline — not hang forever.
    #[tokio::test]
    async fn fix628_initialize_timeout_fires_on_hanging_server() {
        // 60 s stall on first request simulates a non-responsive server.
        let transport = FakeTransport::new(vec![]).with_initial_delay(Duration::from_mins(1));
        let close_count = transport.close_count();
        let config = McpServerConfig::new().with_initialize_timeout_secs(1);

        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            // Outer belt-and-suspenders. If the inner timeout failed to
            // fire, this catches the bug instead of hanging the test
            // runtime forever.
            std::time::Duration::from_secs(10),
            McpServer::new_with_config("hang", Box::new(transport), config),
        )
        .await
        .expect("outer timeout fired — inner #628 timeout did not enforce");
        let elapsed = start.elapsed();

        // `McpServer` doesn't implement `Debug`, so we pattern-match on
        // the `Result` rather than using `.expect_err()`.
        match result {
            Err(McpError::Timeout {
                phase: "initialize",
            }) => {}
            Err(other) => panic!("expected Timeout {{ phase: \"initialize\" }}, got {other:?}"),
            Ok(_) => panic!("hanging server must produce an error, got Ok"),
        }
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "initialize timeout (1 s) should fire fast; took {elapsed:?}"
        );
        assert_eq!(
            close_count.load(Ordering::Acquire),
            1,
            "a rejected connection must close its owned transport"
        );
    }

    /// Fix #628: a well-behaved transport completes the initialize
    /// handshake well within the deadline and returns a usable
    /// `McpServer`. Proves the timeout wrapper does NOT regress
    /// normal behaviour — the production path returns Ok.
    #[tokio::test]
    async fn fix628_normal_handshake_succeeds_under_timeout() {
        // Canned protocol: (1) initialize reply, (2) notifications/initialized
        // (the production code calls `.ok()` on this so the `Value::Null`
        // returned by FakeTransport is harmless), (3) tools/list reply.
        let transport = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": "ok", "version": "1"},
                "capabilities": {"tools": {"listChanged": false}}
            }),
            Value::Null,
            json!({"tools": []}),
        ]);
        let config = McpServerConfig::new().with_initialize_timeout_secs(10);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            McpServer::new_with_config("ok", Box::new(transport), config),
        )
        .await
        .expect("outer timeout fired — handshake stalled");
        let server = match result {
            Ok(s) => s,
            Err(e) => panic!("handshake must succeed, got error: {e:?}"),
        };

        assert_eq!(server.name(), "ok");
        assert!(server.tools().is_empty());
    }

    #[tokio::test]
    async fn initialize_errors_on_malformed_server_info() {
        let transport = FakeTransport::new(vec![json!({
            "serverInfo": {"version": "1"},
            "capabilities": {}
        })]);

        match McpServer::new_with_config(
            "badinfo",
            Box::new(transport),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        {
            Err(McpError::Protocol(msg)) => {
                assert!(msg.contains("serverInfo"), "{msg}");
                assert!(msg.contains("badinfo"), "{msg}");
            }
            Err(other) => panic!("expected Protocol, got {other:?}"),
            Ok(_) => panic!("malformed serverInfo must fail MCP initialize"),
        }
    }

    #[tokio::test]
    async fn initialize_errors_on_malformed_capabilities() {
        let transport = FakeTransport::new(vec![json!({
            "serverInfo": {"name": "badcaps", "version": "1"},
            "capabilities": []
        })]);

        match McpServer::new_with_config(
            "badcaps",
            Box::new(transport),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        {
            Err(McpError::Protocol(msg)) => {
                assert!(msg.contains("capabilities"), "{msg}");
                assert!(msg.contains("badcaps"), "{msg}");
            }
            Err(other) => panic!("expected Protocol, got {other:?}"),
            Ok(_) => panic!("malformed capabilities must fail MCP initialize"),
        }
    }

    /// Fix #628: the timeout duration is configurable via
    /// [`McpServerConfig::initialize_timeout_secs`]. Verifies the
    /// public-API contract (default = 30 s, builder is monotonic on
    /// the targeted field) AND that a short override is actually
    /// honoured at runtime (a 1 s override fires in < 3 s against a
    /// 60 s stall).
    #[tokio::test]
    async fn fix628_initialize_timeout_is_configurable() {
        assert_eq!(McpServerConfig::default().initialize_timeout_secs, 30);
        assert_eq!(McpServerConfig::new().initialize_timeout_secs, 30);
        assert_eq!(DEFAULT_INITIALIZE_TIMEOUT_SECS, 30);

        let custom = McpServerConfig::new().with_initialize_timeout_secs(5);
        assert_eq!(custom.initialize_timeout_secs, 5);

        let transport = FakeTransport::new(vec![]).with_initial_delay(Duration::from_mins(1));
        let config = McpServerConfig::new()
            .with_initialize_timeout_secs(0)
            .with_initialize_timeout_secs(1);
        assert_eq!(config.initialize_timeout_secs, 1);

        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            McpServer::new_with_config("cfg", Box::new(transport), config),
        )
        .await
        .expect("outer timeout fired — configurable timeout did not enforce");
        let elapsed = start.elapsed();

        match result {
            Err(McpError::Timeout {
                phase: "initialize",
            }) => {}
            Err(other) => panic!("expected Timeout {{ phase: \"initialize\" }}, got {other:?}"),
            Ok(_) => panic!("hanging server must produce an error, got Ok"),
        }
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "configurable 1 s timeout should fire fast; took {elapsed:?}"
        );
    }

    /// Fix #628: `initialize_timeout_secs = 0` disables the deadline —
    /// the explicit opt-out for callers that supply their own outer
    /// cancellation scope. With the timeout disabled, a stalled
    /// transport hangs the call indefinitely; the outer
    /// `tokio::time::timeout` is what fires (NOT an inner
    /// `McpError::Timeout`).
    #[tokio::test]
    async fn fix628_initialize_timeout_zero_disables_deadline() {
        let transport = FakeTransport::new(vec![]).with_initial_delay(Duration::from_mins(1));
        let config = McpServerConfig::new().with_initialize_timeout_secs(0);

        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            McpServer::new_with_config("nocap", Box::new(transport), config),
        )
        .await;

        // `tokio::time::timeout` returns `Err(Elapsed)` when the inner
        // future does not complete. `outcome.is_err()` therefore proves
        // the inner deadline did NOT fire — the `0 = disabled` contract
        // held.
        assert!(
            outcome.is_err(),
            "with initialize_timeout_secs=0, the inner call must hang \
             until the OUTER timeout fires; instead the inner call \
             completed — the `0 = disabled` contract was violated"
        );
    }

    // ─── Fix #677 — HttpTransport SSRF / scheme validation ─────────────
    //
    // Forensic evidence: pre-fix `HttpTransport::new` accepted ANY `&str`,
    // trimmed trailing slashes, and stored it. A caller could register
    // `file:///etc/passwd`, `http://127.0.0.1/admin`,
    // `http://169.254.169.254/latest/meta-data/`, or
    // `http://metadata.google.internal/`, and every subsequent MCP tool
    // call would dial that endpoint. Post-fix, `HttpTransport::new`
    // calls `crate::web::validate_url` and returns
    // `McpError::Transport("SSRF guard rejected ...")` for each of
    // those URLs. The tests below pin exactly that perimeter.

    /// Fix #677: `file://` schemes are rejected at construction time.
    /// Pre-fix the call would have returned `Ok(_)` and only failed at
    /// dial time inside `reqwest`; post-fix it never reaches the wire.
    #[test]
    fn fix677_file_scheme_rejected_at_construction() {
        // Match rather than `.err().expect()` because `HttpTransport`
        // is not `Debug`, which `Result::expect_err` would require.
        let result = HttpTransport::new("file:///etc/passwd");
        let Err(err) = result else {
            panic!("file:// must be rejected by SSRF guard");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("SSRF guard rejected"),
            "expected SSRF-guard rejection, got: {msg}"
        );
    }

    /// Fix #677: loopback IPv4 (`127.0.0.1`) is rejected by the SSRF
    /// guard at construction. Covers the canonical "attacker registers
    /// an MCP server pointing at an internal admin endpoint" path.
    #[test]
    fn fix677_loopback_rejected_at_construction() {
        let result = HttpTransport::new("http://127.0.0.1:8080/admin");
        let Err(err) = result else {
            panic!("loopback must be rejected by SSRF guard");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("SSRF guard rejected"),
            "expected SSRF-guard rejection, got: {msg}"
        );
    }

    /// Fix #677: the cloud-metadata IP literal `169.254.169.254` is
    /// rejected. This is the AWS/GCP IMDS endpoint that exfiltrates
    /// instance credentials when reachable.
    #[test]
    fn fix677_cloud_metadata_ip_rejected() {
        let result = HttpTransport::new("http://169.254.169.254/latest/meta-data/");
        let Err(err) = result else {
            panic!("169.254.169.254 must be rejected by SSRF guard");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("SSRF guard rejected"),
            "expected SSRF-guard rejection, got: {msg}"
        );
    }

    /// Fix #677: a valid public HTTPS URL passes validation and
    /// returns a usable transport. Proves the guard does NOT
    /// regress legitimate traffic. A public IP literal keeps this
    /// construction test independent from the host's DNS availability.
    #[test]
    fn fix677_valid_public_https_accepted() {
        let transport = HttpTransport::new("https://1.1.1.1/mcp")
            .expect("public HTTPS URL must validate without DNS");
        assert_eq!(transport.base_url, "https://1.1.1.1/mcp");
    }

    /// Fix #677: `connect_http` propagates the validator error rather
    /// than silently caching a bad spec or returning Ok. Forensic
    /// evidence that the SSRF check is enforced at the MANAGER layer
    /// (the trust boundary called out in the issue body), not just
    /// inside the transport in isolation.
    #[tokio::test]
    async fn fix677_connect_http_propagates_ssrf_rejection() {
        let manager = McpManager::new(Arc::clone(test_run()));
        let result = manager.connect_http("evil", "http://127.0.0.1:1/").await;
        let Err(err) = result else {
            panic!("connect_http with loopback must be rejected by SSRF guard");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("SSRF guard rejected"),
            "expected SSRF-guard rejection, got: {msg}"
        );
        // And the manager must NOT have stored the entry.
        assert!(!manager.is_connected("evil").await);
    }

    // ─── Fix #629 — McpManager reconnect after transport disconnect ────
    //
    // Forensic evidence: pre-fix, `McpManager` held a
    // `HashMap<String, McpServer>` with no `onclose`/`onerror` hooks
    // (`src/mcp.rs:598-829` in the issue). After a transport
    // disconnect, the dead `McpServer` stayed in the map; future
    // `call_tool` invocations kept returning `McpError::Transport`
    // with no self-healing. Post-fix, the manager holds a
    // `Mutex<HashMap<String, ServerEntry>>`; on
    // `McpError::Transport` from `request()` the entry is marked
    // disconnected (server dropped, cache cleared), and the next
    // access reconnects via the stored `ConnectionSpec` under the
    // 1 s / 5 s / 30 s backoff. After three failed reconnects the
    // entry surfaces `McpError::ServerUnreachable` instead.

    /// `FakeReconnectTransport` returns a configured response on each
    /// `request()`, optionally returning a `Transport` error to drive
    /// the disconnect-detection path. Used by the #629 tests to drive
    /// the manager without a child process or HTTP listener.
    struct FakeReconnectTransport {
        responses: std::sync::Mutex<std::collections::VecDeque<Result<Value, McpError>>>,
    }

    impl FakeReconnectTransport {
        fn from_results(rs: Vec<Result<Value, McpError>>) -> Self {
            Self {
                responses: std::sync::Mutex::new(rs.into()),
            }
        }
    }

    #[async_trait]
    impl McpTransport for FakeReconnectTransport {
        async fn request(&self, method: &str, _params: Option<Value>) -> Result<Value, McpError> {
            if method == "server/discover" {
                return Err(McpError::Rpc {
                    code: -32601,
                    message: "Method not found".to_string(),
                    data: None,
                    http_status: None,
                });
            }
            let next = self.responses.lock().expect("lock").pop_front();
            next.unwrap_or(Ok(Value::Null))
        }
        async fn close(&self) -> Result<(), McpError> {
            Ok(())
        }
    }

    /// Build an `McpServer` over a `FakeReconnectTransport` that has
    /// just enough canned responses to complete the initialize +
    /// tools/list handshake. The first call to `tools/call` then
    /// returns the supplied result (Ok or Err).
    fn handshake_responses(
        tool_name: &str,
        tool_call: Result<Value, McpError>,
    ) -> Vec<Result<Value, McpError>> {
        vec![
            // initialize
            Ok(json!({
                "serverInfo": {"name": "test", "version": "1"},
                "capabilities": {"tools": {"listChanged": false}}
            })),
            // notifications/initialized (FakeReconnectTransport returns null)
            Ok(Value::Null),
            // tools/list
            Ok(json!({"tools": [{"name": tool_name}]})),
            // tools/call
            tool_call,
        ]
    }

    /// Fix #629: a transport error on `call_tool` MUST flip the
    /// server entry into the disconnected state. Pre-fix the entry
    /// stayed live forever; post-fix `is_live` flips to false.
    #[tokio::test]
    async fn fix629_transport_error_marks_disconnected() {
        let manager = McpManager::new_with_permissions(
            Arc::clone(test_run()),
            mcp_permissions("svc", &["echo"]),
        );
        // Manually plant a ServerEntry whose underlying transport
        // returns Ok for the handshake then a Transport error on the
        // tools/call. We bypass connect_stdio/connect_http because
        // those spawn real processes / hit the network.
        let transport = FakeReconnectTransport::from_results(handshake_responses(
            "echo",
            Err(McpError::Transport("simulated socket reset".to_string())),
        ));
        let server = McpServer::new("svc", Box::new(transport))
            .await
            .expect("handshake ok");
        let spec = ConnectionSpec::Stdio {
            command: "/nonexistent/cmd".to_string(),
            args: vec![],
            env: crate::secrets::EnvironmentGrants::new(),
        };
        let entry = ServerEntry::new(spec, server);
        manager
            .install_actor("svc".to_string(), entry)
            .await
            .expect("fixture actor installs");

        assert!(manager.is_live("svc").await, "must start live");

        let err = manager
            .call_tool("mcp__svc__echo", json!({}))
            .await
            .expect_err("transport error must propagate");
        assert!(
            matches!(err, McpError::Transport(_)),
            "expected Transport error, got: {err}"
        );
        assert!(
            !manager.is_live("svc").await,
            "transport error MUST mark entry disconnected (fix #629)"
        );
        // is_connected still true — the entry stays in the map for
        // the reconnect path.
        assert!(manager.is_connected("svc").await);
    }

    /// Fix #629: with the reconnect budget exhausted, the next access
    /// returns `McpError::ServerUnreachable`. We synthesise the
    /// exhausted state directly because driving three real reconnect
    /// failures would require a 30 s+ test (the full backoff
    /// schedule). The state machine is the load-bearing piece.
    #[tokio::test]
    async fn fix629_max_retries_returns_server_unreachable() {
        let manager = McpManager::new_with_permissions(
            Arc::clone(test_run()),
            mcp_permissions("dead", &["anything"]),
        );
        // Plant an entry already in the exhausted state.
        let spec = ConnectionSpec::Stdio {
            command: "/nonexistent/cmd".to_string(),
            args: vec![],
            env: crate::secrets::EnvironmentGrants::new(),
        };
        let entry = ServerEntry {
            spec,
            trust: McpServerTrust::HostConfigured,
            server: None,
            tool_timeout: None,
            failed_attempts: MAX_RECONNECT_ATTEMPTS,
            last_failure: Some(std::time::Instant::now()),
            cached_tools: vec![],
            supports_list_changed: false,
            connection_generation: NEXT_MCP_CONNECTION_GENERATION.fetch_add(1, Ordering::AcqRel),
        };
        manager
            .install_actor("dead".to_string(), entry)
            .await
            .expect("exhausted actor installs");

        let err = manager
            .call_tool("mcp__dead__anything", json!({}))
            .await
            .expect_err("exhausted entry must error");
        assert!(
            matches!(err, McpError::ServerUnreachable(ref n) if n == "dead"),
            "expected ServerUnreachable(\"dead\"), got: {err:?}"
        );
        // And the cached tool list is empty (cleared on disconnect).
        assert!(manager.tools_as_openai_functions().await.is_empty());
    }

    /// Fix #629: backoff gating works. Within the 1 s window after
    /// the FIRST disconnect, an access returns `ServerUnreachable`
    /// without bumping `failed_attempts` (it's not an attempt yet).
    #[tokio::test]
    async fn fix629_backoff_window_blocks_reconnect_before_elapsed() {
        let spec = ConnectionSpec::Stdio {
            command: "/nonexistent/cmd".to_string(),
            args: vec![],
            env: crate::secrets::EnvironmentGrants::new(),
        };
        // Freshly disconnected (failed_attempts = 0), last_failure
        // = now ⇒ BACKOFF[0] = 1 s has NOT elapsed.
        let entry = ServerEntry {
            spec,
            trust: McpServerTrust::HostConfigured,
            server: None,
            tool_timeout: None,
            failed_attempts: 0,
            last_failure: Some(std::time::Instant::now()),
            cached_tools: vec![],
            supports_list_changed: false,
            connection_generation: NEXT_MCP_CONNECTION_GENERATION.fetch_add(1, Ordering::AcqRel),
        };
        let mut entry = entry;
        let err = McpManager::ensure_connected(test_run(), &mut entry, "pending")
            .await
            .expect_err("backoff window must block");
        assert!(
            matches!(err, McpError::ServerUnreachable(_)),
            "expected ServerUnreachable while backoff pending, got: {err:?}"
        );
        // Counter MUST stay at 0 — this wasn't an attempt.
        assert_eq!(
            entry.failed_attempts, 0,
            "backoff-gated access must NOT bump failed_attempts"
        );
    }

    /// Fix #629: a disconnected entry whose backoff window has
    /// elapsed reconnects on the next access and the operation
    /// succeeds against the rebuilt transport.
    ///
    /// This is the CORE self-healing invariant. We can't drive a real
    /// process reconnect in a unit test, so we exercise the
    /// `ensure_connected` state machine directly:
    ///   * plant a disconnected entry with `last_failure = None`
    ///     (so `backoff_elapsed()` returns true);
    ///   * give it a `ConnectionSpec::Stdio` that the reconnect
    ///     attempt cannot actually launch (the `build_transport` call
    ///     errors);
    ///   * confirm `failed_attempts` increments and on the THIRD
    ///     failure the surfaced error is `ServerUnreachable`.
    /// Then re-plant with a working entry (server: Some) and confirm
    /// `is_live` is true and a tool call succeeds — proving the
    /// post-reconnect state machine resumes operation.
    #[tokio::test]
    async fn fix629_reconnect_attempts_then_resumes() {
        let manager = McpManager::new_with_permissions(
            Arc::clone(test_run()),
            mcp_permissions("flaky", &["ping"]),
        );

        // Phase 1: drive three reconnect failures. We use a stdio
        // ConnectionSpec pointing at a definitely-missing command;
        // `StdioTransport::spawn` returns `McpError::Transport` for
        // ENOENT, so each reconnect counts as a failure.
        let spec = ConnectionSpec::Stdio {
            command: "/this/path/definitely/does/not/exist/__fix629__".to_string(),
            args: vec![],
            env: crate::secrets::EnvironmentGrants::new(),
        };
        let entry = ServerEntry {
            spec,
            trust: McpServerTrust::HostConfigured,
            server: None,
            tool_timeout: None,
            failed_attempts: 0,
            last_failure: None, // ⇒ backoff_elapsed() is true
            cached_tools: vec![],
            supports_list_changed: false,
            connection_generation: NEXT_MCP_CONNECTION_GENERATION.fetch_add(1, Ordering::AcqRel),
        };
        let mut entry = entry;

        // Attempt #1: counter goes 0 → 1, error is generic transport
        // failure (not yet ServerUnreachable).
        let r1 = McpManager::ensure_connected(test_run(), &mut entry, "flaky").await;
        assert!(r1.is_err(), "reconnect #1 must fail");
        assert_eq!(entry.failed_attempts, 1);
        // Manually reset last_failure so the next ensure_connected
        // sees the backoff as elapsed without sleeping 1 s.
        entry.last_failure = None;
        let r2 = McpManager::ensure_connected(test_run(), &mut entry, "flaky").await;
        assert!(r2.is_err(), "reconnect #2 must fail");
        assert_eq!(entry.failed_attempts, 2);
        entry.last_failure = None;
        let r3 = McpManager::ensure_connected(test_run(), &mut entry, "flaky").await;
        // Third failure exhausts the budget.
        assert!(
            matches!(r3, Err(McpError::ServerUnreachable(ref n)) if n == "flaky"),
            "reconnect #3 must surface ServerUnreachable, got: {r3:?}"
        );
        assert_eq!(entry.failed_attempts, MAX_RECONNECT_ATTEMPTS);
        // Phase 2: replace with a live entry (simulating a manual
        // disconnect + reconnect by the operator) and confirm normal
        // operation resumes.
        let transport = FakeReconnectTransport::from_results(handshake_responses(
            "ping",
            Ok(json!({
                "content": [{"type": "text", "text": "ok"}],
                "structuredContent": {"ok": true}
            })),
        ));
        let server = McpServer::new("flaky", Box::new(transport))
            .await
            .expect("handshake ok");
        let spec2 = ConnectionSpec::Stdio {
            command: "/bin/true".to_string(),
            args: vec![],
            env: crate::secrets::EnvironmentGrants::new(),
        };
        manager
            .install_actor("flaky".to_string(), ServerEntry::new(spec2, server))
            .await
            .expect("replacement actor installs");

        assert!(manager.is_live("flaky").await);
        let result = manager
            .call_tool("mcp__flaky__ping", json!({}))
            .await
            .expect("post-reconnect call must succeed");
        assert_eq!(result["structuredContent"]["ok"], true);
    }

    /// Fix #629: the BACKOFF schedule is exactly 1 s / 5 s / 30 s.
    /// Locking this down as a unit assertion catches accidental
    /// schedule changes that would diverge from the contract spelled
    /// out in crosslink #629.
    #[test]
    fn fix629_backoff_schedule_is_1_5_30() {
        assert_eq!(BACKOFF[0], Duration::from_secs(1));
        assert_eq!(BACKOFF[1], Duration::from_secs(5));
        assert_eq!(BACKOFF[2], Duration::from_secs(30));
        assert_eq!(MAX_RECONNECT_ATTEMPTS, 3);
    }

    // ─── Fix #701 — response-id mismatch detection across transports ──
    //
    // Forensic evidence: pre-fix `HttpTransport::request` (src/mcp.rs
    // around line 573) parsed `JsonRpcResponse.id` into the struct and
    // then discarded it — only `response.error` and `response.result`
    // were consulted. A buggy or hostile MCP HTTP server that returned
    // a reply carrying any other id (e.g. `9999` when the client just
    // sent `1`) would be silently accepted and `response.result`
    // returned to the caller. `StdioTransport` (around line 407)
    // already enforced the §5 invariant but did so via a
    // stringly-typed `McpError::Protocol("Response ID mismatch: ...")`,
    // forcing call sites and tests to grep error messages instead of
    // matching on a dedicated variant.
    //
    // These tests exercise three vectors and the migration:
    //   1. HTTP matching id        — happy path, request succeeds.
    //   2. HTTP mismatched id      — request returns
    //                                `McpError::ResponseIdMismatch
    //                                { expected, got }`.
    //   3. HTTP non-numeric id     — `JsonRpcResponse.id: u64` causes
    //                                serde to reject the response
    //                                during JSON decode, surfacing
    //                                `McpError::Protocol("Failed to
    //                                parse response: ...")`. This
    //                                pins the layering: the mismatch
    //                                check fires only on a structurally
    //                                valid response.
    //   4. Stdio mismatched id     — the migrated variant is what
    //                                bubbles up (no more
    //                                `Protocol("Response ID mismatch
    //                                ...")`).
    //
    // The HTTP tests use a one-shot raw-TCP mock server (no axum/hyper
    // dependency required, matches the existing test style in this
    // file). The transport is built via `__test_new_unchecked` so the
    // SSRF guard does not reject the loopback URL.

    /// One-shot raw-HTTP mock: accept a single TCP connection, read
    /// the request bytes up to the configured ceiling, then write a
    /// minimal `HTTP/1.1 200 OK` with the supplied body. The server
    /// task exits after the single exchange so the test can be run
    /// without external coordination. Returns the bound `127.0.0.1:N`
    /// URL so the caller can point an `HttpTransport` at it.
    async fn spawn_one_shot_http_mock(response_body: impl Into<String>) -> String {
        use tokio::io::AsyncReadExt as _;
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpListener;

        let response_body = response_body.into();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                // Drain the request enough to release the client.
                // 8 KiB is plenty for the small JSON-RPC bodies the
                // transport sends in these tests.
                let mut buf = [0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        format!("http://{addr}")
    }

    async fn spawn_oversized_chunked_http_mock() -> String {
        use tokio::io::AsyncReadExt as _;
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut request = [0u8; 8192];
                let _ = socket.read(&mut request).await;
                if socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                          Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .is_err()
                {
                    return;
                }
                let chunk = vec![b'x'; 64 * 1024];
                for _ in 0..=((MAX_HTTP_RESPONSE_SIZE / chunk.len()) + 1) {
                    let header = format!("{:x}\r\n", chunk.len());
                    if socket.write_all(header.as_bytes()).await.is_err()
                        || socket.write_all(&chunk).await.is_err()
                        || socket.write_all(b"\r\n").await.is_err()
                    {
                        return;
                    }
                }
                let _ = socket.write_all(b"0\r\n\r\n").await;
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn s066_http_response_without_content_length_is_still_bounded() {
        let url = spawn_oversized_chunked_http_mock().await;
        let transport = HttpTransport::__test_new_unchecked(&url);
        let error = transport
            .request("oversized", None)
            .await
            .expect_err("chunked response above the body cap must fail");
        assert!(matches!(
            error,
            McpError::ResponseTooLarge {
                limit: MAX_HTTP_RESPONSE_SIZE
            }
        ));
    }

    #[test]
    fn s066_sse_event_count_is_bounded() {
        let mut body = String::new();
        for index in 0..=MAX_HTTP_SSE_EVENTS {
            write!(
                &mut body,
                "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notice/{index}\"}}\n\n"
            )
            .expect("write SSE fixture");
        }
        let error = parse_sse_json_rpc_response(&body, &str::to_string)
            .expect_err("an unbounded notification stream must be rejected");
        assert!(matches!(error, McpError::Protocol(message) if message.contains("exceeded")));
    }

    #[test]
    fn s066_http_session_identity_is_validated_before_storage() {
        assert!(valid_mcp_session_id("session-123_ABC"));
        assert!(!valid_mcp_session_id(""));
        assert!(!valid_mcp_session_id("session with space"));
        assert!(!valid_mcp_session_id("session\nheader"));
        assert!(!valid_mcp_session_id("sessión"));
    }

    /// Fix #701 — HTTP transport accepts a response whose `id` matches
    /// the outstanding request. Anchors the happy path so the
    /// mismatch-detection logic cannot regress into a false-positive
    /// reject on correct traffic.
    #[tokio::test]
    async fn fix701_http_matching_id_succeeds() {
        // First HTTP request issued by a fresh transport uses id=1
        // (AtomicU64 starts at 1, fetch_add returns the pre-increment
        // value). Mock returns id=1 with a recognisable payload.
        let url = spawn_one_shot_http_mock(
            r#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"marker":"fix701_match"}}"#,
        )
        .await;
        let transport = HttpTransport::__test_new_unchecked(&url);

        let result = tokio::time::timeout(Duration::from_secs(5), transport.request("ping", None))
            .await
            .expect("request did not deadlock")
            .expect("matching id must succeed");

        assert_eq!(result["ok"], true);
        assert_eq!(result["marker"], "fix701_match");
    }

    /// Fix #701 — HTTP transport rejects a response whose numeric id
    /// differs from the outstanding request. Forensic anchor: pre-fix
    /// this call silently returned `result` instead.
    #[tokio::test]
    async fn fix701_http_mismatched_id_rejected_with_dedicated_variant() {
        // Transport will send id=1; mock returns id=9999.
        let url = spawn_one_shot_http_mock(
            r#"{"jsonrpc":"2.0","id":9999,"result":{"should":"not be returned"}}"#,
        )
        .await;
        let transport = HttpTransport::__test_new_unchecked(&url);

        let err = tokio::time::timeout(Duration::from_secs(5), transport.request("ping", None))
            .await
            .expect("request did not deadlock")
            .expect_err("mismatched id MUST be rejected");

        match err {
            McpError::ResponseIdMismatch { expected, got } => {
                assert_eq!(expected, 1, "client sent id=1");
                assert_eq!(got, 9999, "mock returned id=9999");
            }
            other => panic!(
                "expected McpError::ResponseIdMismatch, got: {other:?} \
                 (pre-fix this returned Ok(result) — regression!)"
            ),
        }
    }

    /// Fix #701 — a response with a non-numeric `id` fails JSON
    /// decoding because `JsonRpcResponse.id: u64`. The error surfaces
    /// as `McpError::Protocol("Failed to parse response: ...")`, NOT
    /// `ResponseIdMismatch` — the mismatch guard runs only on
    /// structurally valid responses. Locking the layering down so a
    /// future refactor doesn't accidentally widen `id` to `Value` and
    /// silently accept string ids.
    #[tokio::test]
    async fn fix701_http_non_numeric_id_rejected_at_decode() {
        let url =
            spawn_one_shot_http_mock(r#"{"jsonrpc":"2.0","id":"not-a-number","result":{}}"#).await;
        let transport = HttpTransport::__test_new_unchecked(&url);

        let err = tokio::time::timeout(Duration::from_secs(5), transport.request("ping", None))
            .await
            .expect("request did not deadlock")
            .expect_err("non-numeric id MUST be rejected");

        match err {
            McpError::Protocol(msg) => {
                assert!(
                    msg.contains("Failed to parse response"),
                    "expected JSON-decode protocol error, got: {msg}"
                );
            }
            McpError::ResponseIdMismatch { .. } => panic!(
                "non-numeric id must fail at JSON decode, NOT reach the \
                 mismatch guard — layering broken"
            ),
            other => panic!("expected Protocol(...) error, got: {other:?}"),
        }
    }

    /// Fix #701 — `StdioTransport` migration: a mismatched id now
    /// surfaces `McpError::ResponseIdMismatch` (the shared variant),
    /// not the prior stringly-typed `Protocol("Response ID mismatch
    /// ...")`. Regression anchor for the DRY refactor.
    #[tokio::test]
    async fn fix701_stdio_mismatched_id_uses_dedicated_variant() {
        // Transport sends id=1; script replies with id=42.
        let transport = spawn_sh(
            "read req; \
             printf '{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"x\":1}}\n'",
        )
        .expect("spawn");

        let err = tokio::time::timeout(Duration::from_secs(5), transport.request("ping", None))
            .await
            .expect("request did not deadlock")
            .expect_err("mismatched id MUST be rejected");

        match err {
            McpError::ResponseIdMismatch { expected, got } => {
                assert_eq!(expected, 1, "client sent id=1");
                assert_eq!(got, 42, "server returned id=42");
            }
            McpError::Protocol(msg) if msg.contains("Response ID mismatch") => {
                panic!(
                    "stdio path still using stringly-typed Protocol error \
                     — DRY migration to ResponseIdMismatch did not land: {msg}"
                );
            }
            other => panic!("expected McpError::ResponseIdMismatch, got: {other:?}"),
        }
        let _ = transport.close().await;
    }

    // ─── Fix #732 — StdioTransport concurrent-request serialisation ────
    //
    // Forensic evidence: pre-fix `StdioTransport::request` took the
    // `child` mutex for the write, dropped it, and only then took
    // the separate `reader` mutex for the read. With concurrent
    // callers and a server free to reply out of arrival order, one
    // caller could read the other's reply line, trigger
    // `ResponseIdMismatch`, and the desync would cascade.
    //
    // Post-fix the `request_lock` guard is held across the entire
    // write+read pair, so the server only ever has one outstanding
    // request and has nothing to reorder.
    //
    // The deterministic forensic anchor is
    // `fix732_concurrent_out_of_order_server_replies_correlate`: a
    // bash mock with non-blocking reads gathers all available
    // request lines then emits replies in REVERSE id order.
    // Verified pre-fix (with the `request_lock` line commented
    // out) that test failed with
    // `ResponseIdMismatch{expected:1,got:4}`; post-fix it passes.

    fn spawn_echo_id_mock() -> Result<StdioTransport, McpError> {
        spawn_sh(
            r#"while IFS= read -r line; do
                  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
                  method=$(printf '%s' "$line" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')
                  sleep 0.01
                  printf '{"jsonrpc":"2.0","id":%s,"result":{"method_echo":"%s","id_echo":%s}}\n' "$id" "$method" "$id"
               done"#,
        )
    }

    /// Fix #732 — four concurrent calls each receive the reply
    /// matching their own caller-distinct method.
    #[tokio::test]
    async fn fix732_four_concurrent_requests_all_correlate() {
        let transport = Arc::new(spawn_echo_id_mock().expect("spawn"));

        let t1 = Arc::clone(&transport);
        let t2 = Arc::clone(&transport);
        let t3 = Arc::clone(&transport);
        let t4 = Arc::clone(&transport);

        let fut_a = tokio::spawn(async move { t1.request("alpha", None).await });
        let fut_b = tokio::spawn(async move { t2.request("bravo", None).await });
        let fut_c = tokio::spawn(async move { t3.request("charlie", None).await });
        let fut_d = tokio::spawn(async move { t4.request("delta", None).await });

        let (ra, rb, rc, rd) = tokio::time::timeout(Duration::from_secs(15), async move {
            tokio::join!(fut_a, fut_b, fut_c, fut_d)
        })
        .await
        .expect("concurrent requests did not deadlock");

        let ra = ra.expect("task a panicked").expect("request a failed");
        let rb = rb.expect("task b panicked").expect("request b failed");
        let rc = rc.expect("task c panicked").expect("request c failed");
        let rd = rd.expect("task d panicked").expect("request d failed");

        assert_eq!(ra["method_echo"], "alpha", "call a got wrong reply");
        assert_eq!(rb["method_echo"], "bravo", "call b got wrong reply");
        assert_eq!(rc["method_echo"], "charlie", "call c got wrong reply");
        assert_eq!(rd["method_echo"], "delta", "call d got wrong reply");

        let _ = transport.close().await;
    }

    /// Fix #732 — per-request id correlation preserved: the four
    /// `AtomicU64` ids {1,2,3,4} round-trip back to their owning
    /// callers.
    #[tokio::test]
    async fn fix732_concurrent_requests_preserve_id_correlation() {
        let transport = Arc::new(spawn_echo_id_mock().expect("spawn"));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let t = Arc::clone(&transport);
            handles.push(tokio::spawn(async move { t.request("ping", None).await }));
        }

        let results = tokio::time::timeout(Duration::from_secs(15), async move {
            let mut out = Vec::with_capacity(4);
            for h in handles {
                out.push(h.await.expect("task panicked"));
            }
            out
        })
        .await
        .expect("concurrent requests did not deadlock");

        let mut ids = Vec::new();
        for r in results {
            let value = r.expect("request failed");
            let id = value["id_echo"]
                .as_u64()
                .expect("server reply must echo numeric id");
            ids.push(id);
        }

        ids.sort_unstable();
        assert_eq!(
            ids,
            vec![1, 2, 3, 4],
            "four concurrent requests must consume ids 1..=4 with each \
             id correlated back to its caller via the echoed reply"
        );

        let _ = transport.close().await;
    }

    /// Fix #732 — FORENSIC deterministic anchor. Mock server uses
    /// non-blocking reads (`read -t 0.05`) to gather all available
    /// request lines then emits replies in REVERSE id order.
    ///
    /// Pre-fix (verified by commenting out the `request_lock`
    /// guard) this test fails with
    /// `ResponseIdMismatch { expected: 1, got: 4 }`. Post-fix the
    /// serialisation ensures the server never sees more than one
    /// in-flight request — reverse-of-one-element is a no-op and
    /// each reply matches.
    #[tokio::test]
    async fn fix732_concurrent_out_of_order_server_replies_correlate() {
        let transport = Arc::new(
            StdioTransport::spawn(
                stdio_test_run(),
                "bash",
                &[
                    "-c",
                    r#"while IFS= read -r line; do
                         lines=("$line")
                         while IFS= read -r -t 0.05 more; do
                             lines+=("$more")
                         done
                         rev=()
                         for ((i=${#lines[@]}-1; i>=0; i--)); do
                             rev+=("${lines[i]}")
                         done
                         for l in "${rev[@]}"; do
                             id=$(printf '%s' "$l" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
                             printf '{"jsonrpc":"2.0","id":%s,"result":{"id_echo":%s}}\n' "$id" "$id"
                         done
                     done"#,
                ],
            )
            .expect("spawn bash"),
        );

        let mut handles = Vec::with_capacity(4);
        for _ in 0..4 {
            let t = Arc::clone(&transport);
            handles.push(tokio::spawn(async move { t.request("ping", None).await }));
        }

        let mut ids = Vec::with_capacity(4);
        for h in handles {
            let value = tokio::time::timeout(Duration::from_secs(15), h)
                .await
                .expect("forensic test deadlocked — fix732 over-corrected")
                .expect("task panicked")
                .expect(
                    "request failed — pre-fix #732 the script's reverse-batch \
                     would cause ResponseIdMismatch when 2+ requests batched",
                );
            ids.push(
                value["id_echo"]
                    .as_u64()
                    .expect("server reply must echo numeric id"),
            );
        }

        ids.sort_unstable();
        assert_eq!(
            ids,
            vec![1, 2, 3, 4],
            "four concurrent callers MUST consume ids 1..=4 with each \
             id correlated back to its caller"
        );

        let _ = transport.close().await;
    }

    /// Fix #732 — forward-progress sanity: three concurrent
    /// callers complete within a bounded deadline. Proves the
    /// serialisation does not introduce starvation.
    #[tokio::test]
    async fn fix732_serialised_requests_make_forward_progress() {
        let transport = Arc::new(
            spawn_sh(
                r#"i=0
                   while IFS= read -r line; do
                       i=$((i + 1))
                       id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
                       sleep 0.05
                       printf '{"jsonrpc":"2.0","id":%s,"result":{"slot":%d}}\n' "$id" "$i"
                   done"#,
            )
            .expect("spawn"),
        );

        let start = std::time::Instant::now();

        let mut handles = Vec::new();
        for _ in 0..3 {
            let t = Arc::clone(&transport);
            handles.push(tokio::spawn(async move { t.request("ping", None).await }));
        }

        let mut slots = Vec::new();
        for h in handles {
            let value = tokio::time::timeout(Duration::from_secs(10), h)
                .await
                .expect("forward-progress deadline exceeded — request starved")
                .expect("task panicked")
                .expect("request failed");
            slots.push(
                value["slot"]
                    .as_u64()
                    .expect("script must echo numeric slot"),
            );
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "three serialised requests took {elapsed:?} — likely starvation"
        );

        slots.sort_unstable();
        assert_eq!(
            slots,
            vec![1, 2, 3],
            "each caller must get a distinct reply"
        );

        let _ = transport.close().await;
    }

    // ─── Fix #625 — call_tool must inspect isError flag ────────────────
    //
    // Forensic evidence: the pre-fix `McpServer::call_tool` returned
    // the raw tool-result `Value` without ever inspecting the
    // `isError` boolean defined by the MCP spec. A tool that failed
    // with `{"content": [{"type":"text","text":"boom"}], "isError": true}`
    // was forwarded to the LLM as if it had succeeded. The fix
    // surfaces this as `McpError::ToolReportedError`.

    /// Build a [`McpServer`] backed by [`FakeTransport`] with a single
    /// registered tool and a canned `tools/call` reply. Centralises the
    /// boilerplate so each fix625 test can focus on its assertion.
    async fn server_with_canned_call_reply(call_reply: Value) -> McpServer {
        let transport = FakeTransport::new(vec![
            // initialize reply — must advertise tools so refresh_tools
            // actually issues tools/list (fix #627 gate).
            json!({
                "serverInfo": {"name": "fake", "version": "1"},
                "capabilities": {"tools": {"listChanged": false}}
            }),
            // notifications/initialized — body ignored.
            Value::Null,
            // tools/list reply — one tool named "boom".
            json!({"tools": [{"name": "boom", "description": "test tool"}]}),
            // tools/call reply — provided by the caller.
            call_reply,
        ]);
        McpServer::new_with_config(
            "fake",
            Box::new(transport),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        .expect("handshake must succeed for fix625 fixture")
    }

    /// Fix #625: when the server reports `isError: true`, `call_tool`
    /// MUST return `McpError::ToolReportedError` carrying the extracted
    /// text from `content[0].text`, NOT the raw value.
    #[tokio::test]
    async fn fix625_call_tool_surfaces_is_error_true_as_typed_error() {
        let server = server_with_canned_call_reply(json!({
            "content": [{"type": "text", "text": "tool exploded: stack overflow"}],
            "isError": true
        }))
        .await;

        let err = server
            .call_tool("boom", json!({}))
            .await
            .expect_err("isError:true MUST surface as Err");

        match err {
            McpError::ToolReportedError { message, result } => {
                assert!(
                    message.contains("tool exploded"),
                    "extracted message must come from content[0].text; got: {message}"
                );
                assert_eq!(result.get("isError"), Some(&json!(true)));
            }
            other => panic!(
                "expected ToolReportedError, got {other:?} \
                 (pre-fix this returned Ok(value) — regression!)"
            ),
        }
    }

    /// Fix #625: when `isError` is absent OR explicitly `false`, the
    /// raw result value is returned unchanged. Pins the happy path so
    /// the new error-extraction logic does not regress successful
    /// tool calls into spurious failures.
    #[tokio::test]
    async fn fix625_call_tool_returns_ok_when_is_error_absent_or_false() {
        // Case 1: isError flag absent entirely.
        let server = server_with_canned_call_reply(json!({
            "content": [{"type": "text", "text": "hello"}]
        }))
        .await;
        let ok = server
            .call_tool("boom", json!({}))
            .await
            .expect("absent isError must succeed");
        assert_eq!(ok["content"][0]["text"], "hello");

        // Case 2: isError explicitly false.
        let server = server_with_canned_call_reply(json!({
            "content": [{"type": "text", "text": "world"}],
            "isError": false
        }))
        .await;
        let ok = server
            .call_tool("boom", json!({}))
            .await
            .expect("isError:false must succeed");
        assert_eq!(ok["content"][0]["text"], "world");
        assert_eq!(ok["isError"], false);
    }

    /// Fix #625: `isError: true` with no usable `content` block still
    /// produces a `ToolReportedError` — never silently `Ok` — and the
    /// fallback message names the offending tool so an operator can
    /// trace it without having to inspect the wire.
    #[tokio::test]
    async fn fix625_call_tool_is_error_without_content_uses_fallback_message() {
        let server = server_with_canned_call_reply(json!({"isError": true})).await;

        let err = server
            .call_tool("boom", json!({}))
            .await
            .expect_err("isError:true MUST surface as Err even without content");

        match err {
            McpError::ToolReportedError { message, result } => {
                assert!(
                    message.contains("boom"),
                    "fallback message must name the tool; got: {message}"
                );
                assert!(
                    message.contains("isError"),
                    "fallback message must mention isError; got: {message}"
                );
                assert_eq!(result, json!({"isError": true}));
            }
            other => panic!("expected ToolReportedError fallback, got {other:?}"),
        }
    }

    // ─── Fix #626 — HttpTransport must preserve JSON-RPC error.data ────
    //
    // Forensic evidence: the pre-fix HTTP transport formatted only
    // `code` and `message` from a JSON-RPC error response, dropping
    // `data` on the floor. `StdioTransport::request` already appended
    // `(data: ...)`, so callers received different debugging context
    // depending on transport — a silent footgun for HTTP MCP servers.

    /// Fix #626: an `error.data` payload returned by an HTTP MCP server
    /// MUST remain available as typed `McpError::Rpc` context.
    #[tokio::test]
    async fn fix626_http_transport_preserves_error_data() {
        let url = spawn_one_shot_http_mock(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params","data":{"missing":"argument","field":"name"}}}"#,
        )
        .await;
        let transport = HttpTransport::__test_new_unchecked(&url);

        let err = tokio::time::timeout(Duration::from_secs(5), transport.request("call", None))
            .await
            .expect("request did not deadlock")
            .expect_err("JSON-RPC error response MUST surface as Err");

        let McpError::Rpc {
            code,
            message,
            data,
            http_status,
        } = err
        else {
            panic!("expected typed Rpc error, got {err:?}");
        };
        assert_eq!(code, -32602);
        assert_eq!(message, "Invalid params");
        assert_eq!(data, Some(json!({"missing": "argument", "field": "name"})));
        assert_eq!(http_status, Some(200));
    }

    #[tokio::test]
    async fn http_transport_redacts_static_header_echoes_from_rpc_errors() {
        const SECRET: &str = "s025-mcp-header-secret-d732e1";
        let url = spawn_one_shot_http_mock(format!(
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"echo {SECRET}","data":{{"authorization":"Bearer {SECRET}"}}}}}}"#,
        ))
        .await;
        let headers = HashMap::from([("Authorization".to_string(), format!("Bearer {SECRET}"))]);
        let transport = HttpTransport::__test_new_unchecked_with_headers(&url, &headers);

        let error = tokio::time::timeout(Duration::from_secs(5), transport.request("call", None))
            .await
            .expect("request did not deadlock")
            .expect_err("JSON-RPC error response must surface as Err");
        let (message, data) = match error {
            McpError::Rpc { message, data, .. } => (message, data),
            other => panic!("expected typed Rpc error, got {other:?}"),
        };
        let diagnostic = format!("{message} {data:?}");

        assert!(
            !diagnostic.contains(SECRET),
            "MCP error leaked header: {diagnostic}"
        );
        assert!(
            diagnostic.contains(crate::secrets::REDACTED_SECRET),
            "{diagnostic}"
        );
        assert!(diagnostic.len() <= crate::secrets::MAX_DIAGNOSTIC_BYTES * 2);
    }

    /// Fix #626: when the server omits `error.data`, the typed field is
    /// `None`, rather than inventing a JSON `null` payload.
    #[tokio::test]
    async fn fix626_http_transport_no_data_field_omits_data_suffix() {
        let url = spawn_one_shot_http_mock(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#,
        )
        .await;
        let transport = HttpTransport::__test_new_unchecked(&url);

        let err = tokio::time::timeout(Duration::from_secs(5), transport.request("call", None))
            .await
            .expect("request did not deadlock")
            .expect_err("error response MUST surface as Err");

        let McpError::Rpc {
            code,
            message,
            data,
            http_status,
        } = err
        else {
            panic!("expected typed Rpc error, got {err:?}");
        };
        assert_eq!(code, -32601);
        assert_eq!(message, "Method not found");
        assert_eq!(data, None);
        assert_eq!(http_status, Some(200));
    }

    /// Fix #626: HTTP and Stdio transports MUST preserve the same JSON-RPC
    /// code, message, and data. HTTP additionally records its status code.
    #[tokio::test]
    async fn fix626_http_and_stdio_error_data_formatting_matches() {
        // HTTP path
        let url = spawn_one_shot_http_mock(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"boom","data":"extra"}}"#,
        )
        .await;
        let http = HttpTransport::__test_new_unchecked(&url);
        let http_err = tokio::time::timeout(Duration::from_secs(5), http.request("m", None))
            .await
            .expect("not deadlocked")
            .expect_err("must be Err");
        let McpError::Rpc {
            code: http_code,
            message: http_message,
            data: http_data,
            http_status,
        } = http_err
        else {
            panic!("HTTP error variant changed unexpectedly: {http_err:?}");
        };

        // Stdio path — a tiny shell script that returns the same JSON-RPC error.
        let stdio = spawn_sh(
            r#"read line; echo '{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"boom","data":"extra"}}'"#,
        )
        .expect("spawn stdio");
        let stdio_err = tokio::time::timeout(Duration::from_secs(5), stdio.request("m", None))
            .await
            .expect("not deadlocked")
            .expect_err("must be Err");
        let McpError::Rpc {
            code: stdio_code,
            message: stdio_message,
            data: stdio_data,
            http_status: stdio_status,
        } = stdio_err
        else {
            panic!("Stdio error variant changed unexpectedly: {stdio_err:?}");
        };

        assert_eq!(http_code, stdio_code);
        assert_eq!(http_message, stdio_message);
        assert_eq!(http_data, stdio_data);
        assert_eq!(http_status, Some(200));
        assert_eq!(stdio_status, None);
        let _ = stdio.close().await;
    }

    // ─── Fix #627 — refresh_tools gated on capabilities.tools ──────────
    //
    // Forensic evidence: pre-fix `refresh_tools` issued `tools/list`
    // unconditionally. Servers that did not advertise `capabilities.tools`
    // either ignored the request (wasted RPC) or returned a JSON-RPC
    // error (-32601 Method not found). CC `fetchToolsForClient` short-
    // circuits in the same case (`client.ts:1748-1751`).

    /// Fix #627: when the server advertises `capabilities.tools`, the
    /// `tools/list` RPC IS issued and the returned tool list is stored.
    /// Anchors the happy path so the gate does not regress into a
    /// false-negative that suppresses legitimate tools.
    #[tokio::test]
    async fn fix627_refresh_tools_issues_rpc_when_capability_present() {
        let transport = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": "withtools", "version": "1"},
                "capabilities": {"tools": {"listChanged": false}}
            }),
            Value::Null,
            json!({"tools": [{"name": "alpha"}, {"name": "beta"}]}),
        ]);
        let server = McpServer::new_with_config(
            "withtools",
            Box::new(transport),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        .expect("handshake must succeed");

        assert!(
            server.has_tools_capability(),
            "server advertised tools capability"
        );
        let names: Vec<&str> = server.tools().iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[tokio::test]
    async fn refresh_tools_errors_when_tools_array_missing() {
        let transport = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": "badtools", "version": "1"},
                "capabilities": {"tools": {"listChanged": false}}
            }),
            Value::Null,
            json!({}),
        ]);

        match McpServer::new_with_config(
            "badtools",
            Box::new(transport),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        {
            Err(McpError::Protocol(msg)) => {
                assert!(msg.contains("tools/list"), "{msg}");
                assert!(msg.contains("'tools' array"), "{msg}");
            }
            Err(other) => panic!("expected Protocol, got {other:?}"),
            Ok(_) => panic!("missing tools array must fail MCP tool discovery"),
        }
    }

    #[tokio::test]
    async fn refresh_tools_errors_on_malformed_tool_entry() {
        let transport = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": "badtoolentry", "version": "1"},
                "capabilities": {"tools": {"listChanged": false}}
            }),
            Value::Null,
            json!({"tools": [{"description": "missing name"}]}),
        ]);

        match McpServer::new_with_config(
            "badtoolentry",
            Box::new(transport),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        {
            Err(McpError::Protocol(msg)) => {
                assert!(msg.contains("tools/list entry"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            Err(other) => panic!("expected Protocol, got {other:?}"),
            Ok(_) => panic!("malformed MCP tool entry must fail discovery"),
        }
    }

    /// Fix #627: when the server does NOT advertise `capabilities.tools`,
    /// `refresh_tools` returns `Ok(())` without issuing the wire call.
    /// We prove the wire was not touched by giving the transport ONLY
    /// the two responses needed for the initialize handshake — if the
    /// gate is missing, `refresh_tools` will call into an empty queue
    /// and the `tools/list` reply will be `Value::Null`, which would
    /// then deserialize to an empty tool list and pass the surface
    /// assertion. So instead we set up a transport that records a
    /// counter of issued requests and assert that count == 2 (init +
    /// notifications/initialized), NOT 3.
    #[tokio::test]
    async fn fix627_refresh_tools_skipped_when_capability_absent() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingTransport {
            inner: FakeTransport,
            count: AtomicUsize,
        }

        #[async_trait]
        impl McpTransport for CountingTransport {
            async fn request(
                &self,
                method: &str,
                params: Option<Value>,
            ) -> Result<Value, McpError> {
                self.count.fetch_add(1, Ordering::SeqCst);
                // Track the LAST method name as well via debug log; the
                // counter alone is the assertion target.
                self.inner.request(method, params).await
            }
            async fn close(&self) -> Result<(), McpError> {
                self.inner.close().await
            }
        }

        let transport = CountingTransport {
            inner: FakeTransport::new(vec![
                json!({
                    "serverInfo": {"name": "notools", "version": "1"},
                    "capabilities": {}  // No tools capability — fix #627 gate.
                }),
                Value::Null,
                // This third reply is a tripwire: if `refresh_tools`
                // mistakenly calls tools/list, it will consume this
                // value and the count will rise to 3. Per spec it
                // MUST NOT.
                json!({"tools": [{"name": "should_not_appear"}]}),
            ]),
            count: AtomicUsize::new(0),
        };

        let server = McpServer::new_with_config(
            "notools",
            Box::new(transport),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        .expect("handshake must succeed even without tools capability");

        assert!(
            !server.has_tools_capability(),
            "server did NOT advertise tools capability"
        );
        assert!(
            server.tools().is_empty(),
            "no tools must be registered when capability is absent"
        );
        // NOTE: we can no longer reach the inner counter through
        // `server` because the transport is Box<dyn>. The empty
        // tools list combined with the "should_not_appear" tripwire
        // proves the wire call was skipped — if it had been issued,
        // the tool would be in the registered list.
    }

    /// Fix #627: `has_tools_capability` is the public accessor used by
    /// callers (and by `refresh_tools` internally) to decide whether
    /// `tools/list` is worth the round-trip. Verify the two-state
    /// contract directly via the initialize-response shape so a future
    /// refactor of `McpCapabilities` does not silently break the gate.
    #[tokio::test]
    async fn fix627_has_tools_capability_reflects_handshake_state() {
        // With tools capability.
        let with = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": "yes", "version": "1"},
                "capabilities": {"tools": {"listChanged": false}}
            }),
            Value::Null,
            json!({"tools": []}),
        ]);
        let s_with = McpServer::new_with_config(
            "yes",
            Box::new(with),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        .expect("handshake");
        assert!(s_with.has_tools_capability());

        // Without tools capability — handshake still succeeds, gate flips.
        let without = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": "no", "version": "1"},
                "capabilities": {}
            }),
            Value::Null,
            // tripwire as in the previous test
            json!({"tools": [{"name": "tripwire"}]}),
        ]);
        let s_without = McpServer::new_with_config(
            "no",
            Box::new(without),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        .expect("handshake");
        assert!(!s_without.has_tools_capability());
        assert!(s_without.tools().is_empty());
    }

    #[tokio::test]
    async fn list_resources_errors_when_resources_array_missing() {
        let transport = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": "badresources", "version": "1"},
                "capabilities": {"resources": {"subscribe": false}}
            }),
            Value::Null,
            json!({}),
        ]);
        let server = McpServer::new_with_config(
            "badresources",
            Box::new(transport),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        .expect("handshake should skip tools/list when tools capability is absent");

        match server.list_resources().await {
            Err(McpError::Protocol(msg)) => {
                assert!(msg.contains("resources/list"), "{msg}");
                assert!(msg.contains("'resources' array"), "{msg}");
            }
            Err(other) => panic!("expected Protocol, got {other:?}"),
            Ok(_) => panic!("missing resources array must fail MCP resource listing"),
        }
    }

    #[tokio::test]
    async fn list_resources_errors_on_malformed_resource_entry() {
        let transport = FakeTransport::new(vec![
            json!({
                "serverInfo": {"name": "badresourceentry", "version": "1"},
                "capabilities": {"resources": {"subscribe": false}}
            }),
            Value::Null,
            json!({"resources": [{"name": "missing-uri"}]}),
        ]);
        let server = McpServer::new_with_config(
            "badresourceentry",
            Box::new(transport),
            McpServerConfig::new().with_initialize_timeout_secs(5),
        )
        .await
        .expect("handshake should skip tools/list when tools capability is absent");

        match server.list_resources().await {
            Err(McpError::Protocol(msg)) => {
                assert!(msg.contains("resources/list entry"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            Err(other) => panic!("expected Protocol, got {other:?}"),
            Ok(_) => panic!("malformed MCP resource entry must fail listing"),
        }
    }
}

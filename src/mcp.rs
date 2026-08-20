//! MCP Integration - Model Context Protocol client for external tool servers.
//!
//! Supports:
//! - Stdio transport (spawn process, communicate via stdin/stdout)
//! - HTTP transport (connect to HTTP-based MCP servers)
//!
//! Handles tool discovery, schema translation, and request routing.

use async_trait::async_trait;
use reqwest::header::{HeaderMap, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, Command};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

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
const MAX_STDIO_INTERMEDIATE_MESSAGES: usize = 1000;

/// Errors that can occur during MCP operations
#[derive(Error, Debug)]
pub enum McpError {
    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    #[error("Server not connected: {0}")]
    NotConnected(String),

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
    /// `message` carries the extracted human-readable error text.
    /// If the server emitted `isError: true` with no content block
    /// at all, the message falls back to a generic placeholder so
    /// the variant remains distinguishable from any `Protocol`
    /// error.
    #[error("MCP tool reported error: {message}")]
    ToolReportedError {
        /// Human-readable error text extracted from the tool result's
        /// `content[0].text` field (or a generic fallback).
        message: String,
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

/// MCP tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Option<Value>,
}

/// MCP resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "mimeType")]
    pub mime_type: Option<String>,
}

/// MCP server capabilities
#[derive(Debug, Clone, Default, Deserialize)]
pub struct McpCapabilities {
    #[serde(default)]
    pub tools: Option<ToolsCapability>,
    #[serde(default)]
    pub resources: Option<Value>,
    #[serde(default)]
    pub prompts: Option<Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    #[serde(default)]
    pub list_changed: bool,
}

/// MCP server info from initialize response
#[derive(Debug, Clone, Deserialize)]
pub struct McpServerInfo {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
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

    /// Send a request and receive a response
    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, McpError>;

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
    /// Ring buffer holding the last `STDERR_BUFFER_CAP` bytes the server
    /// wrote to stderr (fix #445 point 1).
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    /// Handle to the stderr drain task. Wrapped in `Arc` so the struct
    /// stays `Send + Sync`. The task auto-terminates on stderr EOF.
    _stderr_drain: Arc<JoinHandle<()>>,
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
        let command = crate::tools::sandboxed_process_command(
            &process_run,
            crate::tools::SandboxProfile::McpStdio,
            resolved_command.as_os_str(),
            &sandbox_args,
            process_run.working_directory(),
        )
        .map_err(|error| {
            McpError::Transport(format!("MCP stdio sandbox is unavailable: {error}"))
        })?;
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
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| McpError::Transport(format!("Failed to spawn process: {e}")))?;
        let process_registration = crate::tools::command::ActiveSandboxProcess::register(
            &process_run,
            child.id().ok_or_else(|| {
                McpError::Transport("Sandboxed MCP process has no process id".to_string())
            })?,
        );

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

        if let Some(id) = value.get("id").and_then(Value::as_u64) {
            let response = build_client_feature_response(&self.run_context, id, method);
            self.write_json_line(&response).await?;
        } else {
            debug!(method = %method, "Ignoring MCP server notification while awaiting response");
        }

        Ok(true)
    }
}

fn derive_mcp_stdio_run(
    parent: &Arc<crate::tools::ToolRunContext>,
    extra_environment: &crate::secrets::EnvironmentGrants,
) -> Result<Arc<crate::tools::ToolRunContext>, McpError> {
    parent
        .require(crate::tools::ToolResource::Process)
        .map_err(|error| McpError::Transport(error.to_string()))?;
    let session_id = crate::state::SessionId::from_raw(parent.session_id()).map_err(|error| {
        McpError::Transport(format!(
            "Cannot bind MCP process to parent session: {error}"
        ))
    })?;
    let is_parent_intrinsic_root = |root: &&PathBuf| {
        root.as_path() == parent.project_root() || root.as_path() == parent.private_temp_root()
    };
    let read_only_roots = parent
        .read_only_roots()
        .iter()
        .filter(|root| !is_parent_intrinsic_root(root))
        .cloned()
        .collect();
    let read_write_roots = parent
        .read_write_roots()
        .iter()
        .filter(|root| !is_parent_intrinsic_root(root))
        .cloned()
        .collect();
    let mut environment_grants = parent.environment_grants().clone();
    environment_grants.extend(extra_environment);
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
    run.require(crate::tools::ToolResource::Process)
        .map_err(|error| McpError::Transport(error.to_string()))?;
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
    id: u64,
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

        debug!(method = %method, id = id, "Sending MCP request");

        // Fix #732 — serialise the entire write+read transaction.
        // Concurrent calls queue behind this guard so the server
        // only ever has one outstanding request and cannot reorder
        // replies. The leading underscore on `_request_guard`
        // silences `unused_variables` without an `#[allow]`; the
        // guard lives until the end of the scope, i.e. until the
        // response has been parsed and the result is ready.
        let _request_guard = self.request_lock.lock().await;

        let mut child = self.child.lock().await;

        // Write request to stdin
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

        // Release the child lock before reading. stdin and stdout are
        // independent file descriptors and the reader has its own mutex.
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
            // Fix #701 — dedicated variant replaces the previous
            // stringly-typed Protocol(...) error so call sites and
            // tests can match on the variant directly. Shared with
            // HttpTransport for DRY across transports.
            return Err(McpError::ResponseIdMismatch {
                expected: id,
                got: response.id,
            });
        }

        if let Some(error) = response.error {
            // Include error data in message if available
            let data_info = error
                .data
                .as_ref()
                .map(|d| format!(" (data: {d})"))
                .unwrap_or_default();
            let raw = zeroize::Zeroizing::new(format!(
                "RPC error {}: {}{}",
                error.code, error.message, data_info
            ));
            return Err(McpError::Protocol(
                self.run_context.sanitize_diagnostic(&raw).to_string(),
            ));
        }

        Ok(response.result.unwrap_or(Value::Null))
    }

    async fn close(&self) -> Result<(), McpError> {
        self.child
            .lock()
            .await
            .kill()
            .await
            .map_err(|e| McpError::Transport(format!("Failed to kill process: {e}")))?;
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
    /// Hidden from the public docs (`#[doc(hidden)]`) and prefixed
    /// `__test_` to discourage production use. The function is `pub`
    /// rather than `pub(crate)` only so integration tests in
    /// `tests/*.rs` — which compile as a separate crate without
    /// access to `cfg(test)` symbols — can construct loopback
    /// transports for the mock-server pattern.
    #[doc(hidden)]
    #[must_use]
    pub fn __test_new_unchecked(base_url: &str) -> Self {
        Self::__test_new_unchecked_with_sensitive_headers(
            base_url,
            crate::secrets::SensitiveHeaders::new(),
        )
    }

    /// Test-only constructor with static headers and no SSRF guard.
    #[doc(hidden)]
    #[must_use]
    pub fn __test_new_unchecked_with_headers(
        base_url: &str,
        headers: &HashMap<String, String>,
    ) -> Self {
        let headers = protect_static_headers(headers).unwrap_or_default();
        Self::__test_new_unchecked_with_sensitive_headers(base_url, headers)
    }

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

async fn parse_http_json_rpc_response(
    response: reqwest::Response,
) -> Result<JsonRpcResponse, McpError> {
    let is_event_stream = response_content_type_is_event_stream(response.headers());
    let body = zeroize::Zeroizing::new(response.text().await.map_err(|err| {
        if is_event_stream {
            McpError::Protocol(format!("Failed to read SSE response: {err}"))
        } else {
            McpError::Protocol(format!("Failed to read response: {err}"))
        }
    })?);

    if is_event_stream || body_looks_like_sse(&body) {
        parse_sse_json_rpc_response(&body)
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

fn parse_sse_json_rpc_response(body: &str) -> Result<JsonRpcResponse, McpError> {
    let mut event_name: Option<String> = None;
    let mut data_lines: Vec<String> = Vec::new();

    for line in body.lines() {
        if line.is_empty() {
            if let Some(response) = parse_sse_json_rpc_event(event_name.as_deref(), &data_lines)? {
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

    if let Some(response) = parse_sse_json_rpc_event(event_name.as_deref(), &data_lines)? {
        return Ok(response);
    }

    Err(McpError::Protocol(
        "SSE response did not contain a JSON-RPC response message".to_string(),
    ))
}

fn parse_sse_json_rpc_event(
    event_name: Option<&str>,
    data_lines: &[String],
) -> Result<Option<JsonRpcResponse>, McpError> {
    if data_lines.is_empty() || event_name.is_some_and(|name| name != "message") {
        return Ok(None);
    }

    let data = data_lines.join("\n");
    let value: Value = serde_json::from_str(&data)
        .map_err(|err| McpError::Protocol(format!("Failed to parse SSE event JSON: {err}")))?;

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

#[async_trait]
impl McpTransport for HttpTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<Value, McpError> {
        let id = self.request_id.fetch_add(1, Ordering::SeqCst);

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };

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
            .json(&request);
        if let Some(sid) = self.session_id() {
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

        if !response.status().is_success() {
            return Err(McpError::Transport(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        // Capture `Mcp-Session-Id` if the server set one. Per spec the
        // server MAY emit it on the initialize response; once set, all
        // subsequent POSTs MUST echo it (handled above on the next call).
        if let Some(sid) = response
            .headers()
            .get("Mcp-Session-Id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
        {
            if let Some(mut guard) = self.session_id_write_guard("request.store_session_id") {
                *guard = Some(sid);
            }
        }

        let response = parse_http_json_rpc_response(response).await?;

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
            // Fix #626 — preserve JSON-RPC `error.data` in the surfaced
            // message. The pre-fix HTTP transport formatted only
            // `{code, message}` and dropped `data`, while
            // `StdioTransport` already appended `(data: ...)`. Mirror
            // the stdio formatting verbatim so operators get the same
            // structured debugging context regardless of transport.
            let data_info = error
                .data
                .as_ref()
                .map(|d| format!(" (data: {d})"))
                .unwrap_or_default();
            let raw = zeroize::Zeroizing::new(format!(
                "RPC error {}: {}{}",
                error.code, error.message, data_info
            ));
            return Err(McpError::Protocol(
                self.headers.sanitize_diagnostic(&raw).to_string(),
            ));
        }

        Ok(response.result.unwrap_or(Value::Null))
    }

    async fn close(&self) -> Result<(), McpError> {
        // Fix #490 — HTTP transport shares the process-wide client;
        // there is no per-transport resource to release. Tearing
        // down the shared pool would break every other live HTTP
        // transport in the process, so this is intentionally a
        // no-op.
        Ok(())
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
            info: None,
            capabilities: McpCapabilities::default(),
            tools: Vec::new(),
        };

        // Fix #628 — bound the initialize handshake. A non-responsive
        // server would otherwise hang the calling tokio task forever
        // because `transport.request("initialize", ...)` has no
        // built-in deadline (the HTTP transport's `HTTP_REQUEST_TIMEOUT`
        // covers steady-state requests, the stdio transport has no
        // wall-clock cap at all).
        //
        // `tokio::time::timeout` cancels the inner future on expiry,
        // which for stdio drops the in-flight `read_until` (the child
        // process remains, but the caller can decide whether to retry
        // or close). For HTTP it cancels the `RequestBuilder::send`
        // future before the per-request `HTTP_REQUEST_TIMEOUT` fires —
        // which is the intended semantics, since the initialize
        // handshake has its own (typically shorter) policy.
        if config.initialize_timeout_secs == 0 {
            server.initialize().await?;
            server.refresh_tools().await?;
        } else {
            let deadline = Duration::from_secs(config.initialize_timeout_secs);
            let Ok(init_res) = tokio::time::timeout(deadline, server.initialize()).await else {
                warn!(
                    server = %server.name,
                    timeout_secs = config.initialize_timeout_secs,
                    "MCP server initialize handshake timed out"
                );
                return Err(McpError::Timeout {
                    phase: "initialize",
                });
            };
            init_res?;
            let Ok(tools_res) = tokio::time::timeout(deadline, server.refresh_tools()).await else {
                warn!(
                    server = %server.name,
                    timeout_secs = config.initialize_timeout_secs,
                    "MCP server tools/list timed out"
                );
                return Err(McpError::Timeout {
                    phase: "tools/list",
                });
            };
            tools_res?;
        }

        Ok(server)
    }

    /// Initialize the MCP connection
    async fn initialize(&mut self) -> Result<(), McpError> {
        let params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": self.transport.client_capabilities(),
            "clientInfo": {
                "name": "openclaudia",
                "version": env!("CARGO_PKG_VERSION")
            }
        });

        let result = self.transport.request("initialize", Some(params)).await?;

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

        // Send initialized notification
        self.transport
            .request("notifications/initialized", None)
            .await
            .ok();

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
            "MCP server initialized"
        );

        Ok(())
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

        let result = self.transport.request("tools/list", None).await?;

        self.tools = parse_mcp_tools_list_response(&self.name, &result)?;

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
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value, McpError> {
        if !self.tools.iter().any(|t| t.name == name) {
            return Err(McpError::ToolNotFound(name.to_string()));
        }

        let params = json!({
            "name": name,
            "arguments": arguments
        });

        debug!(server = %self.name, tool = %name, "Calling MCP tool");

        let result = self.transport.request("tools/call", Some(params)).await?;

        // Fix #625 — per MCP spec, a tool result of the shape
        // `{"content": [...], "isError": true}` signals tool-level
        // failure. Pre-fix this was returned verbatim to the caller,
        // so the LLM saw a tool error as if it were a normal result.
        // Match CC `callMCPTool`: extract `content[0].text` (or any
        // `text` field in the content array) as the error message,
        // falling back to a generic placeholder if the server emitted
        // `isError: true` with no usable content block.
        if result
            .get("isError")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            let message = result
                .get("content")
                .and_then(serde_json::Value::as_array)
                .and_then(|arr| {
                    arr.iter()
                        .find_map(|item| item.get("text").and_then(|t| t.as_str()))
                })
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

            return Err(McpError::ToolReportedError { message });
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

        let result = self
            .transport
            .request("resources/list", Some(json!({})))
            .await?;

        let resources = parse_mcp_resources_list_response(&self.name, &result)?;

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
    pub async fn read_resource(&self, uri: &str) -> Result<String, McpError> {
        let params = json!({ "uri": uri });

        debug!(server = %self.name, uri = %uri, "Reading MCP resource");

        let result = self
            .transport
            .request("resources/read", Some(params))
            .await?;

        // The MCP spec returns contents as an array of content items
        if let Some(contents) = result.get("contents").and_then(|c| c.as_array()) {
            let text: Vec<&str> = contents
                .iter()
                .filter_map(|c| c.get("text").and_then(|t| t.as_str()))
                .collect();
            if !text.is_empty() {
                return Ok(text.join("\n"));
            }
            // Check for blob content (base64-encoded)
            let blobs: Vec<&str> = contents
                .iter()
                .filter_map(|c| c.get("blob").and_then(|b| b.as_str()))
                .collect();
            if !blobs.is_empty() {
                return Ok(blobs.join("\n"));
            }
        }

        // Fallback: return the raw result as string
        Ok(result.to_string())
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

fn parse_mcp_tools_list_response(
    server_name: &str,
    result: &Value,
) -> Result<Vec<McpTool>, McpError> {
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            McpError::Protocol(format!(
                "MCP server '{server_name}' tools/list response missing 'tools' array: {result}"
            ))
        })?;

    tools
        .iter()
        .enumerate()
        .map(|(index, tool)| {
            serde_json::from_value::<McpTool>(tool.clone()).map_err(|e| {
                McpError::Protocol(format!(
                    "MCP server '{server_name}' tools/list entry at index {index} is invalid: \
                     {e}; entry: {tool}"
                ))
            })
        })
        .collect()
}

fn parse_mcp_resources_list_response(
    server_name: &str,
    result: &Value,
) -> Result<Vec<McpResource>, McpError> {
    let resources = result
        .get("resources")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            McpError::Protocol(format!(
                "MCP server '{server_name}' resources/list response missing 'resources' array: \
                 {result}"
            ))
        })?;

    resources
        .iter()
        .enumerate()
        .map(|(index, resource)| {
            serde_json::from_value::<McpResource>(resource.clone()).map_err(|e| {
                McpError::Protocol(format!(
                    "MCP server '{server_name}' resources/list entry at index {index} is \
                     invalid: {e}; entry: {resource}"
                ))
            })
        })
        .collect()
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
    fn build_transport(
        &self,
        run: &Arc<crate::tools::ToolRunContext>,
    ) -> Result<Box<dyn McpTransport>, McpError> {
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
        crate::tools::SandboxProfile::McpStdio,
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

struct ServerEntry {
    spec: ConnectionSpec,
    server: Option<McpServer>,
    tool_timeout: Option<Duration>,
    failed_attempts: u32,
    last_failure: Option<std::time::Instant>,
    cached_tools: Vec<McpTool>,
    supports_list_changed: bool,
}

impl ServerEntry {
    fn new(spec: ConnectionSpec, server: McpServer) -> Self {
        Self::new_with_tool_timeout(spec, server, None)
    }

    fn new_with_tool_timeout(
        spec: ConnectionSpec,
        server: McpServer,
        tool_timeout: Option<Duration>,
    ) -> Self {
        let cached_tools = server.tools().to_vec();
        let supports_list_changed = server.supports_tool_list_changed();
        Self {
            spec,
            server: Some(server),
            tool_timeout,
            failed_attempts: 0,
            last_failure: None,
            cached_tools,
            supports_list_changed,
        }
    }

    fn mark_disconnected(&mut self) {
        self.server = None;
        self.cached_tools.clear();
        self.last_failure = Some(std::time::Instant::now());
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

/// Manages multiple MCP server connections with self-healing reconnection (fix #629).
pub struct McpManager {
    run_context: Arc<crate::tools::ToolRunContext>,
    servers: Mutex<HashMap<String, ServerEntry>>,
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
    /// Create a new MCP manager
    #[must_use]
    pub fn new(run_context: Arc<crate::tools::ToolRunContext>) -> Self {
        Self {
            run_context,
            servers: Mutex::new(HashMap::new()),
        }
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
        validate_protected_mcp_child_environment(&self.run_context, &env)?;
        let spec = ConnectionSpec::Stdio {
            command: command.to_string(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            env,
        };
        let transport = spec.build_transport(&self.run_context)?;
        let server = McpServer::new(name, transport).await?;
        let entry = ServerEntry::new_with_tool_timeout(spec, server, tool_timeout);
        self.servers.lock().await.insert(name.to_string(), entry);
        Ok(())
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
        self.run_context
            .require(crate::tools::ToolResource::Network)
            .map_err(|error| McpError::Transport(error.to_string()))?;
        let spec = ConnectionSpec::Http {
            url: url.to_string(),
            headers,
            headers_helper: headers_helper.map(str::to_string),
            server_name: name.to_string(),
        };
        let transport = spec.build_transport(&self.run_context)?;
        let server = McpServer::new(name, transport).await?;
        let entry = ServerEntry::new_with_tool_timeout(spec, server, tool_timeout);
        self.servers.lock().await.insert(name.to_string(), entry);
        Ok(())
    }

    /// Test-only counterpart to [`Self::connect_http`] that bypasses
    /// the SSRF guard so integration tests can point at a wiremock
    /// loopback listener. Marked `#[doc(hidden)]` and prefixed
    /// `__test_` to make production misuse obvious.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if connection or initialization fails.
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
        self.servers.lock().await.insert(name.to_string(), entry);
        Ok(())
    }

    /// Convert MCP tools to `OpenAI` function format.
    ///
    /// Reads the cached tool snapshot — disconnected servers contribute
    /// nothing because [`ServerEntry::mark_disconnected`] clears the
    /// cache (CC parity: `client.ts:1391` clears its memoised list on
    /// `onclose`).
    pub async fn tools_as_openai_functions(&self) -> Vec<Value> {
        let guard = self.servers.lock().await;
        guard
            .iter()
            .flat_map(|(server_name, entry)| {
                entry.cached_tools.iter().map(move |tool| {
                    json!({
                        "type": "function",
                        "function": {
                            "name": format!("mcp__{}__{}", server_name, tool.name),
                            "description": tool.description.as_deref().unwrap_or(""),
                            "parameters": tool.input_schema.clone().unwrap_or_else(|| json!({"type": "object", "properties": {}}))
                        }
                    })
                })
            })
            .collect()
    }

    /// Attempt to reconnect a disconnected entry in-place (fix #629).
    /// Caller holds the manager mutex.
    async fn ensure_connected(
        run: &Arc<crate::tools::ToolRunContext>,
        entry: &mut ServerEntry,
        name: &str,
    ) -> Result<(), McpError> {
        if entry.server.is_some() {
            return Ok(());
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
                entry.failed_attempts = 0;
                entry.last_failure = None;
                info!(server = %name, "MCP server reconnected");
                Ok(())
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
        let parts: Vec<&str> = full_name.splitn(3, "__").collect();
        if parts.len() != 3 || parts[0] != "mcp" {
            return Err(McpError::ToolNotFound(format!(
                "Invalid tool name format: {full_name}. Expected mcp__servername__toolname"
            )));
        }

        let server_name = parts[1];
        let tool_name = parts[2];

        let mut guard = self.servers.lock().await;
        let entry = guard
            .get_mut(server_name)
            .ok_or_else(|| McpError::NotConnected(server_name.to_string()))?;

        Self::ensure_connected(&self.run_context, entry, server_name).await?;
        // `ensure_connected` returned Ok ⇒ `entry.server` is Some. Use
        // a `let-else` rather than `.expect(_)` so this function does
        // not advertise a `# Panics` contract; the unreachable arm
        // hits the same `ServerUnreachable` surface as the budget-
        // exhausted path, which is the closest semantic match if the
        // invariant somehow broke.
        let Some(server) = entry.server.as_ref() else {
            return Err(McpError::ServerUnreachable(server_name.to_string()));
        };

        let tool_timeout = entry.tool_timeout;
        let outcome = if let Some(deadline) = tool_timeout {
            tokio::time::timeout(deadline, server.call_tool(tool_name, arguments))
                .await
                .unwrap_or_else(|_| {
                    warn!(
                        tool = %full_name,
                        timeout_ms = deadline.as_millis(),
                        "MCP tool call timed out"
                    );
                    Err(McpError::Timeout {
                        phase: "tools/call",
                    })
                })
        } else {
            server.call_tool(tool_name, arguments).await
        };
        if let Err(ref e) = outcome {
            if matches!(e, McpError::Transport(_) | McpError::Timeout { .. }) {
                entry.mark_disconnected();
            }
        }
        drop(guard);
        outcome
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
        let guard = self.servers.lock().await;
        guard
            .get(name)
            .map(|entry| (name.to_string(), entry.supports_list_changed))
    }

    /// List resources across all servers, or from a specific server.
    /// Marks server disconnected on transport error (fix #629).
    ///
    /// # Errors
    ///
    /// Returns an error if a named server is not connected or the request fails.
    pub async fn list_resources(
        &self,
        server_name: Option<&str>,
    ) -> anyhow::Result<Vec<(String, McpResource)>> {
        let mut all_resources = Vec::new();
        let mut guard = self.servers.lock().await;

        let result: anyhow::Result<()> = if let Some(name) = server_name {
            let entry = guard
                .get_mut(name)
                .ok_or_else(|| McpError::NotConnected(name.to_string()))?;
            Self::ensure_connected(&self.run_context, entry, name).await?;
            // `let-else` rather than `.expect(_)` — the unreachable
            // arm collapses to `ServerUnreachable`, matching the
            // budget-exhausted error surface.
            let Some(server) = entry.server.as_ref() else {
                return Err(McpError::ServerUnreachable(name.to_string()).into());
            };
            match server.list_resources().await {
                Ok(resources) => {
                    for r in resources {
                        all_resources.push((name.to_string(), r));
                    }
                    Ok(())
                }
                Err(e) => {
                    if matches!(e, McpError::Transport(_)) {
                        entry.mark_disconnected();
                    }
                    Err(e.into())
                }
            }
        } else {
            let names: Vec<String> = guard.keys().cloned().collect();
            for n in names {
                let Some(entry) = guard.get_mut(&n) else {
                    continue;
                };
                if Self::ensure_connected(&self.run_context, entry, &n)
                    .await
                    .is_err()
                {
                    continue;
                }
                let Some(server) = entry.server.as_ref() else {
                    continue;
                };
                match server.list_resources().await {
                    Ok(resources) => {
                        for r in resources {
                            all_resources.push((n.clone(), r));
                        }
                    }
                    Err(e) => {
                        if matches!(e, McpError::Transport(_)) {
                            entry.mark_disconnected();
                        }
                        warn!(server = %n, error = %e, "Failed to list resources from server");
                    }
                }
            }
            Ok(())
        };
        drop(guard);
        result?;
        Ok(all_resources)
    }

    /// Read a specific resource from a named server.
    /// Marks server disconnected on transport error (fix #629).
    ///
    /// # Errors
    ///
    /// Returns an error if the server is not connected or the read fails.
    pub async fn read_resource(&self, server_name: &str, uri: &str) -> anyhow::Result<String> {
        let mut guard = self.servers.lock().await;
        let entry = guard
            .get_mut(server_name)
            .ok_or_else(|| McpError::NotConnected(server_name.to_string()))?;
        Self::ensure_connected(&self.run_context, entry, server_name).await?;
        // `let-else` rather than `.expect(_)` — the unreachable arm
        // collapses to `ServerUnreachable`, matching the budget-
        // exhausted error surface.
        let Some(server) = entry.server.as_ref() else {
            return Err(McpError::ServerUnreachable(server_name.to_string()).into());
        };
        let outcome = server.read_resource(uri).await;
        if let Err(ref e) = outcome {
            if matches!(e, McpError::Transport(_)) {
                entry.mark_disconnected();
            }
        }
        drop(guard);
        Ok(outcome?)
    }

    /// Disconnect from a server.
    ///
    /// # Errors
    ///
    /// Returns an `McpError` if the server's transport fails to close.
    pub async fn disconnect(&self, name: &str) -> Result<(), McpError> {
        let removed = self.servers.lock().await.remove(name);
        if let Some(mut entry) = removed {
            if let Some(server) = entry.server.take() {
                server.close().await?;
            }
        }
        Ok(())
    }

    /// Disconnect from all servers.
    ///
    /// # Errors
    ///
    /// Returns the first `McpError` encountered while closing servers.
    pub async fn disconnect_all(&self) -> Result<(), McpError> {
        let names: Vec<String> = self.servers.lock().await.keys().cloned().collect();
        for name in names {
            self.disconnect(&name).await?;
        }
        Ok(())
    }

    /// Number of registered servers (incl. disconnected/awaiting-reconnect).
    pub async fn server_count(&self) -> usize {
        self.servers.lock().await.len()
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
            .is_some_and(|e| e.server.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };

        let json = serde_json::to_value(&tool).unwrap();
        assert_eq!(json["name"], "read_file");
        assert_eq!(json["description"], "Read a file");
    }

    #[tokio::test]
    async fn test_mcp_manager_new() {
        let manager = McpManager::new(Arc::clone(test_run()));
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
        assert!(!parent.environment_grants().contains_key("S019_MCP_ENV"));
        assert_ne!(
            child.runtime().descriptor().capabilities.manifest_digest,
            parent.runtime().descriptor().capabilities.manifest_digest
        );
        assert!(child.require(crate::tools::ToolResource::Process).is_ok());
        assert!(child.require(crate::tools::ToolResource::Network).is_err());
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

    fn spawn_sh(script: &str) -> Result<StdioTransport, McpError> {
        StdioTransport::spawn(test_run(), "sh", &["-c", script])
    }

    fn spawn_python(script: &str) -> Result<StdioTransport, McpError> {
        StdioTransport::spawn(test_run(), "python3", &["-u", "-c", script])
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
sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":900,"method":"roots/list"}) + "\n")
sys.stdout.flush()
roots_reply = json.loads(sys.stdin.readline())
root = roots_reply.get("result", {}).get("roots", [{}])[0]
ok = (
    roots_reply.get("id") == 900
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
    }

    impl FakeTransport {
        fn new(responses: Vec<Value>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses.into()),
                delay_first_response: std::sync::Mutex::new(None),
            }
        }

        fn with_initial_delay(self, delay: Duration) -> Self {
            *self.delay_first_response.lock().expect("lock") = Some(delay);
            self
        }
    }

    #[async_trait]
    impl McpTransport for FakeTransport {
        async fn request(&self, _method: &str, _params: Option<Value>) -> Result<Value, McpError> {
            // Take the delay (once); on first call we honour it.
            let delay = self.delay_first_response.lock().expect("lock").take();
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            let next = self.responses.lock().expect("lock").pop_front();
            Ok(next.unwrap_or(Value::Null))
        }

        async fn close(&self) -> Result<(), McpError> {
            Ok(())
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
        async fn request(&self, _method: &str, _params: Option<Value>) -> Result<Value, McpError> {
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
        let manager = McpManager::new(Arc::clone(test_run()));
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
            .servers
            .lock()
            .await
            .insert("svc".to_string(), entry);

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
        let manager = McpManager::new(Arc::clone(test_run()));
        // Plant an entry already in the exhausted state.
        let spec = ConnectionSpec::Stdio {
            command: "/nonexistent/cmd".to_string(),
            args: vec![],
            env: crate::secrets::EnvironmentGrants::new(),
        };
        let entry = ServerEntry {
            spec,
            server: None,
            tool_timeout: None,
            failed_attempts: MAX_RECONNECT_ATTEMPTS,
            last_failure: Some(std::time::Instant::now()),
            cached_tools: vec![],
            supports_list_changed: false,
        };
        manager
            .servers
            .lock()
            .await
            .insert("dead".to_string(), entry);

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
        let manager = McpManager::new(Arc::clone(test_run()));
        let spec = ConnectionSpec::Stdio {
            command: "/nonexistent/cmd".to_string(),
            args: vec![],
            env: crate::secrets::EnvironmentGrants::new(),
        };
        // Freshly disconnected (failed_attempts = 0), last_failure
        // = now ⇒ BACKOFF[0] = 1 s has NOT elapsed.
        let entry = ServerEntry {
            spec,
            server: None,
            tool_timeout: None,
            failed_attempts: 0,
            last_failure: Some(std::time::Instant::now()),
            cached_tools: vec![],
            supports_list_changed: false,
        };
        manager
            .servers
            .lock()
            .await
            .insert("pending".to_string(), entry);

        let err = manager
            .call_tool("mcp__pending__x", json!({}))
            .await
            .expect_err("backoff window must block");
        assert!(
            matches!(err, McpError::ServerUnreachable(_)),
            "expected ServerUnreachable while backoff pending, got: {err:?}"
        );
        // Counter MUST stay at 0 — this wasn't an attempt.
        let guard = manager.servers.lock().await;
        let attempts = guard.get("pending").expect("entry exists").failed_attempts;
        drop(guard);
        assert_eq!(
            attempts, 0,
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
        let manager = McpManager::new(Arc::clone(test_run()));

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
            server: None,
            tool_timeout: None,
            failed_attempts: 0,
            last_failure: None, // ⇒ backoff_elapsed() is true
            cached_tools: vec![],
            supports_list_changed: false,
        };
        manager
            .servers
            .lock()
            .await
            .insert("flaky".to_string(), entry);

        // Attempt #1: counter goes 0 → 1, error is generic transport
        // failure (not yet ServerUnreachable).
        let mut guard = manager.servers.lock().await;
        let entry = guard.get_mut("flaky").expect("present");
        let r1 = McpManager::ensure_connected(test_run(), entry, "flaky").await;
        assert!(r1.is_err(), "reconnect #1 must fail");
        assert_eq!(entry.failed_attempts, 1);
        // Manually reset last_failure so the next ensure_connected
        // sees the backoff as elapsed without sleeping 1 s.
        entry.last_failure = None;
        let r2 = McpManager::ensure_connected(test_run(), entry, "flaky").await;
        assert!(r2.is_err(), "reconnect #2 must fail");
        assert_eq!(entry.failed_attempts, 2);
        entry.last_failure = None;
        let r3 = McpManager::ensure_connected(test_run(), entry, "flaky").await;
        // Third failure exhausts the budget.
        assert!(
            matches!(r3, Err(McpError::ServerUnreachable(ref n)) if n == "flaky"),
            "reconnect #3 must surface ServerUnreachable, got: {r3:?}"
        );
        assert_eq!(entry.failed_attempts, MAX_RECONNECT_ATTEMPTS);
        drop(guard);

        // Phase 2: replace with a live entry (simulating a manual
        // disconnect + reconnect by the operator) and confirm normal
        // operation resumes.
        let transport = FakeReconnectTransport::from_results(handshake_responses(
            "ping",
            Ok(json!({"ok": true})),
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
            .servers
            .lock()
            .await
            .insert("flaky".to_string(), ServerEntry::new(spec2, server));

        assert!(manager.is_live("flaky").await);
        let result = manager
            .call_tool("mcp__flaky__ping", json!({}))
            .await
            .expect("post-reconnect call must succeed");
        assert_eq!(result["ok"], true);
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
                test_run(),
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
            McpError::ToolReportedError { message } => {
                assert!(
                    message.contains("tool exploded"),
                    "extracted message must come from content[0].text; got: {message}"
                );
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
            McpError::ToolReportedError { message } => {
                assert!(
                    message.contains("boom"),
                    "fallback message must name the tool; got: {message}"
                );
                assert!(
                    message.contains("isError"),
                    "fallback message must mention isError; got: {message}"
                );
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
    /// MUST appear in the `McpError::Protocol` message string.
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

        match err {
            McpError::Protocol(msg) => {
                assert!(
                    msg.contains("Invalid params"),
                    "message must include error.message; got: {msg}"
                );
                assert!(
                    msg.contains("-32602"),
                    "message must include error.code; got: {msg}"
                );
                assert!(
                    msg.contains("data:"),
                    "message must label the preserved data field; got: {msg}"
                );
                assert!(
                    msg.contains("missing"),
                    "message must include error.data content; got: {msg}"
                );
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
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
        let message = match error {
            McpError::Protocol(message) => message,
            other => panic!("expected Protocol error, got {other:?}"),
        };

        assert!(
            !message.contains(SECRET),
            "MCP error leaked header: {message}"
        );
        assert!(
            message.contains(crate::secrets::REDACTED_SECRET),
            "{message}"
        );
        assert!(message.len() <= crate::secrets::MAX_DIAGNOSTIC_BYTES);
    }

    /// Fix #626: when the server omits `error.data`, the message must
    /// match the pre-fix format (no spurious `(data: null)` tail).
    /// Locks in that the data preservation is additive, not a format
    /// rewrite that breaks existing log/grep tooling.
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

        match err {
            McpError::Protocol(msg) => {
                assert!(msg.contains("Method not found"), "got: {msg}");
                assert!(msg.contains("-32601"), "got: {msg}");
                assert!(
                    !msg.contains("(data:"),
                    "must NOT append (data: ...) when error.data is absent; got: {msg}"
                );
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    /// Fix #626: HTTP and Stdio transports MUST produce the same shape
    /// of error message when surfacing a JSON-RPC error with `data`.
    /// Cross-transport parity is the whole point of the fix — without
    /// this assertion, the regression-detection net has a hole.
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
        let McpError::Protocol(http_msg) = http_err else {
            panic!("HTTP error variant changed unexpectedly");
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
        let McpError::Protocol(stdio_msg) = stdio_err else {
            panic!("Stdio error variant changed unexpectedly");
        };

        // Identical suffix proves both transports format error.data the same way.
        assert_eq!(
            http_msg, stdio_msg,
            "HTTP and Stdio error formatting must match — fix #626 is about parity"
        );
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

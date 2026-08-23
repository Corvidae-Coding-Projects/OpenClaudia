//! LSP (Language Server Protocol) integration tool.
//!
//! Provides code intelligence via external language servers:
//! - `goToDefinition`: Find where a symbol is defined
//! - `findReferences`: Find all references to a symbol
//! - hover: Get type/documentation info for a symbol
//! - `documentSymbols`: List symbols in a file
//! - `workspaceSymbol`: Search symbols across the workspace
//! - `goToImplementation`: Find implementations of an interface/trait symbol
//! - `prepareCallHierarchy`, `incomingCalls`, `outgoingCalls`: Traverse call hierarchy

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::hash::BuildHasher;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::process::{Child, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

/// Maximum file size (10 MiB) accepted for LSP analysis.
///
/// Parity with CC `LSPTool.ts` (lines 53 + 264-269): files larger than 10 MB
/// would slow the language server to a crawl and likely time out, so OC short-
/// circuits with a clear error before even spawning the server.  See issue
/// #648.
pub const LSP_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;
const LSP_RESPONSE_READ_TIMEOUT: Duration = Duration::from_secs(30);
const LSP_READINESS_POLL_TIMEOUT: Duration = Duration::from_millis(250);
const LSP_SHUTDOWN_READ_TIMEOUT: Duration = Duration::from_secs(2);
const LSP_GITIGNORE_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve `git` only from the immutable executable search path captured for
/// this run. The returned absolute path is then handed to the sandbox.
fn git_bin(run: &crate::tools::ToolRunContext) -> Result<PathBuf, String> {
    run.resolve_executable("git")
        .map_err(|error| error.to_string())
}

/// Process-wide registry of open files per LSP server binary.
///
/// Parity with CC `LSPServerManager.ts:64,277` (`isFileOpen` map).  OC spawns a
/// fresh server per call today, but mirroring CC's deduplication contract here
/// (a) avoids redundant `textDocument/didOpen` notifications when the same
/// server *is* reused (e.g. tests, future pooled mode) and (b) keeps the public
/// surface ready for #647's eventual move to a long-lived server pool.
///
/// The key is the exact `(run_id, generation, server_cmd)` binding, and the
/// value is the set of canonicalised file paths that server instance has been
/// told about. Different runs must never suppress each other's notifications.
///
/// `mark_opened` is the only call site that should mutate the map; it returns
/// `true` iff the caller is the first to claim the slot and must therefore
/// send the `didOpen` notification.  `mark_closed` flips the flag back when
/// the corresponding `textDocument/didClose` notification is sent (or the
/// session shuts down).
type OpenFileRegistry = HashMap<(String, u64, String), HashSet<PathBuf>>;

fn open_files_registry() -> &'static Mutex<OpenFileRegistry> {
    static REGISTRY: OnceLock<Mutex<OpenFileRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn open_file_key(run: &crate::tools::ToolRunContext, server_cmd: &str) -> (String, u64, String) {
    (
        run.run_id().to_string(),
        run.generation().get(),
        server_cmd.to_string(),
    )
}

/// Record that `server_cmd` has been informed about `path`.
///
/// Returns `true` when the caller is the first to register the file (so the
/// caller MUST send `textDocument/didOpen`); returns `false` when the file is
/// already recorded as open (so the caller MUST skip the notification).
#[must_use]
pub fn mark_opened(run: &crate::tools::ToolRunContext, server_cmd: &str, path: &Path) -> bool {
    let mut guard = open_files_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .entry(open_file_key(run, server_cmd))
        .or_default()
        .insert(path.to_path_buf())
}

/// Mirror of `mark_opened` for `textDocument/didClose`.
///
/// Returns `true` if the entry was present (and thus removed), `false` if the
/// caller was attempting to close a file that was never opened — useful for
/// asserting protocol invariants in tests.
pub fn mark_closed(run: &crate::tools::ToolRunContext, server_cmd: &str, path: &Path) -> bool {
    let mut guard = open_files_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .get_mut(&open_file_key(run, server_cmd))
        .is_some_and(|set| set.remove(path))
}

/// RAII guard pairing `mark_opened` with a guaranteed `mark_closed`.
///
/// Without this guard a `?`-early-return between `mark_opened` and the
/// shutdown sequence would leave the dedup entry stuck in the registry
/// after the spawned server has already been killed by `ChildGuard::drop`,
/// causing the *next* invocation to silently skip `textDocument/didOpen`
/// against a fresh server that has never seen the file.
///
/// On the happy path the caller invokes [`commit`] to acknowledge that a
/// matching `textDocument/didClose` was sent; on the error path Drop
/// performs the same rollback so the registry never leaks a stale slot.
struct OpenFileGuard<'a> {
    run: &'a crate::tools::ToolRunContext,
    server_cmd: &'a str,
    path: &'a Path,
    owns_slot: bool,
}

impl<'a> OpenFileGuard<'a> {
    /// Bind the guard to a `(server_cmd, path)` pair.
    ///
    /// `we_opened_it` reflects the return value of `mark_opened`: when
    /// `false`, the slot was already held by a concurrent caller and this
    /// guard is a no-op (it must not release a slot it doesn't own).
    const fn new(
        run: &'a crate::tools::ToolRunContext,
        server_cmd: &'a str,
        path: &'a Path,
        we_opened_it: bool,
    ) -> Self {
        Self {
            run,
            server_cmd,
            path,
            owns_slot: we_opened_it,
        }
    }

    /// Acknowledge a clean shutdown: a matching `textDocument/didClose`
    /// notification was sent, so free the dedup slot and disarm the Drop
    /// rollback.  Calling `commit` twice is harmless.
    fn commit(&mut self) {
        if self.owns_slot {
            let _ = mark_closed(self.run, self.server_cmd, self.path);
            self.owns_slot = false;
        }
    }
}

impl Drop for OpenFileGuard<'_> {
    fn drop(&mut self) {
        if self.owns_slot {
            let _ = mark_closed(self.run, self.server_cmd, self.path);
        }
    }
}

/// Test-only helper: query whether `(server_cmd, path)` is currently marked as
/// open.  Used by the unit tests to verify dedup state transitions without
/// reaching into the registry directly.
#[cfg(test)]
fn is_marked_open(run: &crate::tools::ToolRunContext, server_cmd: &str, path: &Path) -> bool {
    let guard = open_files_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard
        .get(&open_file_key(run, server_cmd))
        .is_some_and(|set| set.contains(path))
}

/// Returns `true` when the language server for `language_or_ext` is reachable
/// on `PATH`, i.e. when a fresh LSP request would be able to spawn it.
///
/// `language_or_ext` accepts either a bare language name (`"rust"`) or a file
/// extension with or without a leading dot (`".rs"`, `"rs"`).  Unknown values
/// always return `false`.
///
/// Parity with CC `LSPTool.ts:137-139` + `manager.ts:100-110` (`isLspConnected`).
/// OC checks with the `which` crate since it has no long-lived server pool yet;
/// once one exists this function should query the pool's liveness map.
#[must_use]
pub fn is_lsp_connected(run: &crate::tools::ToolRunContext, language_or_ext: &str) -> bool {
    let Some((server_cmd, _)) = resolve_language_server(language_or_ext) else {
        return false;
    };
    run.resolve_executable(server_cmd).is_ok()
}

/// Resolve a bare language name OR a file extension to a server command.
///
/// This is the inverse of [`detect_language_server`] for cases where the
/// caller has a language identifier (e.g. `"rust"`) instead of a file path.
fn resolve_language_server(language_or_ext: &str) -> Option<(&'static str, Vec<&'static str>)> {
    let trimmed = language_or_ext.trim().trim_start_matches('.');
    let ext: &str = match trimmed {
        // Bare language identifiers — map to a representative extension.
        "rust" => "rs",
        "typescript" => "ts",
        "typescriptreact" => "tsx",
        "javascript" => "js",
        "javascriptreact" => "jsx",
        "python" => "py",
        "go" => "go",
        "c" => "c",
        "cpp" | "c++" => "cpp",
        "java" => "java",
        "ruby" => "rb",
        // Already an extension (or unknown) — try as-is.
        other => other,
    };
    detect_language_server(&format!("dummy.{ext}"))
}

/// RAII guard that kills and reaps a child process on drop.
///
/// Fixes the zombie-process leak in the original `run_lsp_request`:
/// any early return via `?` previously skipped `child.wait()`, leaving
/// an un-reaped zombie on Unix and a leaking handle on Windows.
struct ChildGuard {
    child: Option<Child>,
    _registration: Option<crate::tools::command::ActiveSandboxProcess>,
}

impl ChildGuard {
    fn new(run: &crate::tools::security::ToolRunContext, child: Child) -> Self {
        let registration = Some(crate::tools::command::ActiveSandboxProcess::register(
            run,
            child.id(),
        ));
        Self {
            child: Some(child),
            _registration: registration,
        }
    }

    /// Return a mutable reference to the wrapped child.
    fn child_mut(&mut self) -> Result<&mut Child, String> {
        self.child
            .as_mut()
            .ok_or_else(|| "LSP child process handle was already taken".to_string())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            crate::tools::terminate_process_tree(child.id());
            // Best-effort fallback; ignore errors (process may have already exited).
            let _ = child.kill();
            // Reap the zombie; ignore the exit status.
            let _ = child.wait();
        }
    }
}

enum LspReadEvent {
    Chunk(Vec<u8>),
    Eof,
    Error(String),
}

#[derive(Clone)]
struct LspReadTimeout {
    timeout: Arc<Mutex<Duration>>,
}

impl LspReadTimeout {
    fn set(&self, timeout: Duration) {
        let mut guard = self
            .timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = timeout;
    }
}

struct LspDeadlineReader {
    rx: Receiver<LspReadEvent>,
    pending: VecDeque<u8>,
    timeout: Arc<Mutex<Duration>>,
    ended: bool,
}

impl LspDeadlineReader {
    fn spawn<R>(mut reader: R, timeout: Duration) -> (Self, LspReadTimeout)
    where
        R: Read + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => {
                        let _ = tx.send(LspReadEvent::Eof);
                        break;
                    }
                    Ok(n) => {
                        if tx.send(LspReadEvent::Chunk(chunk[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(LspReadEvent::Error(err.to_string()));
                        break;
                    }
                }
            }
        });

        let timeout = Arc::new(Mutex::new(timeout));
        let handle = LspReadTimeout {
            timeout: Arc::clone(&timeout),
        };
        (
            Self {
                rx,
                pending: VecDeque::new(),
                timeout,
                ended: false,
            },
            handle,
        )
    }

    fn current_timeout(&self) -> Duration {
        *self
            .timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Read for LspDeadlineReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        loop {
            if !self.pending.is_empty() {
                let n = out.len().min(self.pending.len());
                for (slot, byte) in out[..n].iter_mut().zip(self.pending.drain(..n)) {
                    *slot = byte;
                }
                return Ok(n);
            }

            if self.ended {
                return Ok(0);
            }

            let timeout = self.current_timeout();
            match self.rx.recv_timeout(timeout) {
                Ok(LspReadEvent::Chunk(bytes)) => self.pending.extend(bytes),
                Ok(LspReadEvent::Eof) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.ended = true;
                    return Ok(0);
                }
                Ok(LspReadEvent::Error(message)) => {
                    self.ended = true;
                    return Err(io::Error::new(ErrorKind::BrokenPipe, message));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        format!("timed out waiting for LSP stdout after {timeout:?}"),
                    ));
                }
            }
        }
    }
}

/// Wait up to `timeout` for `child` to exit, polling with `try_wait`.
///
/// Returns `true` when the child reaped within the budget. On timeout,
/// the caller MUST either kill the child or rely on `ChildGuard::drop`
/// to do so — this helper itself does NOT kill.
///
/// Polling cadence is 25 ms so a fast-exiting server takes a quick
/// path to the next request rather than waiting out the full
/// timeout. crosslink #900.
fn wait_with_timeout(child: &mut Child, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    let poll = std::time::Duration::from_millis(25);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(poll);
            }
            Err(_) => return false,
        }
    }
}

/// Readiness probe: drain server-initiated notifications until the server
/// replies to the `textDocument/documentSymbol` probe we sent with id=1001,
/// or until `deadline` elapses.
///
/// Replaces the 500 ms unconditional sleep at the original line 191.
/// A real server reply (even an empty symbols array or an error result) is
/// sufficient evidence that the server has finished loading the document.
///
/// Returns `Ok(())` on readiness, `Err(String)` on timeout or I/O failure.
fn wait_for_readiness(
    reader: &mut BufReader<impl std::io::Read>,
    deadline: std::time::Instant,
) -> Result<(), String> {
    const READINESS_ID: u64 = 1001;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(
                "LSP server readiness timeout (10 s) — server did not acknowledge didOpen"
                    .to_string(),
            );
        }

        // Read one message from the server. Production child stdout is wrapped
        // in `LspDeadlineReader`; no-data timeouts are treated as readiness
        // polling ticks until the real wall-clock deadline expires.
        let mut content_length: usize = 0;
        loop {
            if std::time::Instant::now() >= deadline {
                return Err("LSP server readiness timeout (10 s) during header read".to_string());
            }
            let mut line = String::new();
            let n = match reader.read_line(&mut line) {
                Ok(n) => n,
                Err(err) if err.kind() == ErrorKind::TimedOut => continue,
                Err(err) => return Err(format!("Readiness read error: {err}")),
            };
            if n == 0 {
                return Err("LSP server closed stdout before sending readiness reply".to_string());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if let Some(len_str) = trimmed.strip_prefix("Content-Length: ") {
                content_length = len_str
                    .parse()
                    .map_err(|e| format!("Bad content-length in readiness probe: {e}"))?;
            }
        }

        if content_length == 0 {
            continue; // skip malformed message and keep trying
        }

        let mut body = vec![0u8; content_length];
        std::io::Read::read_exact(reader, &mut body)
            .map_err(|e| format!("Readiness body read error: {e}"))?;

        let msg: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => continue, // non-JSON framing; skip
        };

        // The probe response carries id=READINESS_ID.
        if let Some(id) = msg.get("id").and_then(serde_json::Value::as_u64) {
            if id == READINESS_ID {
                return Ok(());
            }
        }
        // Any other message (notification, different response) — keep draining.
    }
}

/// Spawn a thread that drains `stderr` into a ring buffer capped at 1 KiB.
///
/// Returns an `Arc<Mutex<Vec<u8>>>` that the caller can inspect after the
/// child exits.  Fixes issue #355 point 5: original code used `Stdio::null()`,
/// discarding all diagnostic information on server crash.
fn capture_stderr(stderr: std::process::ChildStderr) -> Arc<Mutex<Vec<u8>>> {
    let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let buf_clone = Arc::clone(&buf);
    thread::spawn(move || {
        use std::io::Read;
        let mut reader = BufReader::new(stderr);
        let mut chunk = [0u8; 256];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut guard = buf_clone
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.extend_from_slice(&chunk[..n]);
                    // Keep only the last 1024 bytes.
                    let len = guard.len();
                    if len > 1024 {
                        let keep_from = len - 1024;
                        guard.drain(..keep_from);
                    }
                }
            }
        }
    });
    buf
}

/// Extract up to 1 KiB from the stderr ring buffer as a displayable suffix.
fn stderr_snippet(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    let guard = buf
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.is_empty() {
        String::new()
    } else {
        let text = String::from_utf8_lossy(&guard).into_owned();
        drop(guard);
        format!("\nServer stderr (last 1 KiB):\n{text}")
    }
}

/// LSP operation types.
///
/// Crosslink #645 adds five new actions for parity with CC's LSP surface:
/// `WorkspaceSymbol`, `GoToImplementation`, `PrepareCallHierarchy`,
/// `IncomingCalls`, `OutgoingCalls`. These are wired to their canonical LSP
/// methods in [`run_lsp_request`] and parsed through the existing
/// [`parse_locations`] / [`parse_symbols`] helpers (with `LocationLink`
/// normalisation from crosslink #643 applied uniformly).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LspAction {
    GoToDefinition,
    FindReferences,
    Hover,
    DocumentSymbols,
    /// `workspace/symbol` — search project-wide by symbol name. Uses the
    /// `query` argument supplied by the caller; falls back to empty string
    /// (which most servers treat as "all symbols").
    WorkspaceSymbol,
    /// `textDocument/implementation` — jump from an interface/trait to its
    /// implementations. Same position-arg shape as `GoToDefinition`.
    GoToImplementation,
    /// `textDocument/prepareCallHierarchy` — returns the `CallHierarchyItem`
    /// at the cursor.
    PrepareCallHierarchy,
    /// `callHierarchy/incomingCalls` — requires the caller to supply a
    /// previously-obtained `CallHierarchyItem` via the `hierarchy_item`
    /// argument (opaque JSON pass-through).
    IncomingCalls,
    /// `callHierarchy/outgoingCalls` — outgoing side of the same hierarchy
    /// protocol, using the same `hierarchy_item` argument.
    OutgoingCalls,
}

/// Result from an LSP operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspResult {
    pub action: String,
    pub file_path: String,
    pub results: Vec<LspLocation>,
    pub hover_text: Option<String>,
    pub symbols: Vec<LspSymbol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspLocation {
    pub uri: String,
    pub line: u32,
    pub character: u32,
    pub end_line: Option<u32>,
    pub end_character: Option<u32>,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LspSymbol {
    pub name: String,
    pub kind: String,
    pub line: u32,
    pub end_line: Option<u32>,
    pub children: Vec<Self>,
}

/// Spawn a language server with stdin/stdout/stderr piped and the
/// exact environment already installed by the run-bound sandbox builder.
///
/// Extracted from `run_lsp_request` (crosslink #869). Environment clearing and
/// exact grant injection deliberately live in the shared sandbox builder so a
/// language-server-specific allowlist cannot drift back to ambient state.
fn spawn_language_server(
    run: &crate::tools::security::ToolRunContext,
    server_cmd: &str,
    server_args: &[&str],
    project_root: &Path,
) -> Result<Child, String> {
    let args: Vec<OsString> = server_args.iter().map(OsString::from).collect();
    let mut cmd = crate::tools::sandboxed_process_command(
        run,
        crate::tools::SandboxProfile::LanguageServer,
        std::ffi::OsStr::new(server_cmd),
        &args,
        project_root,
    )
    .map_err(|error| format!("Failed to sandbox language server {server_cmd}: {error}"))?;
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn()
        .map_err(|e| format!("Failed to start {server_cmd}: {e}"))
}

/// Known language servers by file extension
fn detect_language_server(file_path: &str) -> Option<(&'static str, Vec<&'static str>)> {
    let ext = file_path.rsplit('.').next().unwrap_or("");
    match ext {
        "rs" => Some(("rust-analyzer", vec![])),
        "ts" | "tsx" | "js" | "jsx" => Some(("typescript-language-server", vec!["--stdio"])),
        "py" => Some(("pylsp", vec![])),
        "go" => Some(("gopls", vec!["serve"])),
        "c" | "cpp" | "h" | "hpp" => Some(("clangd", vec![])),
        "java" => Some(("jdtls", vec![])),
        "rb" => Some(("solargraph", vec!["stdio"])),
        _ => None,
    }
}

/// Execute an LSP action
#[must_use]
pub fn execute_lsp<S: BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool) {
    let file_path = match parse_lsp_file_path_arg(args.get("file_path")) {
        Ok(file_path) => file_path,
        Err(msg) => return (msg, true),
    };

    let action = match parse_lsp_action_arg(args.get("action")) {
        Ok(action) => action,
        Err(msg) => return (msg, true),
    };

    let hierarchy_item = match parse_lsp_hierarchy_item_arg(action, args.get("hierarchy_item")) {
        Ok(hierarchy_item) => hierarchy_item,
        Err(msg) => return (msg, true),
    };

    let line = match parse_lsp_line_arg(args.get("line")) {
        Ok(line) => line,
        Err(msg) => return (msg, true),
    };
    let character = match parse_lsp_character_arg(args.get("character")) {
        Ok(character) => character,
        Err(msg) => return (msg, true),
    };
    let query = match parse_lsp_query_arg(args.get("query")) {
        Ok(query) => query,
        Err(msg) => return (msg, true),
    };

    // Detect language server
    let Some((server_cmd, server_args)) = detect_language_server(file_path) else {
        return (
            format!("No language server known for file: {file_path}"),
            true,
        );
    };

    // Availability gate (#650): refuse early if the server binary isn't
    // reachable on PATH. Parity with CC `LSPTool.ts:137-139` +
    // `manager.ts:100-110` (`isLspConnected`). `is_lsp_connected` uses
    // the `which` crate (in-process PATH walk, crosslink #955) so we
    // never fork+exec a `which(1)` subprocess.
    let language = detect_language_id(file_path);
    if !is_lsp_connected(run, language) {
        return (
            format!(
                "LSP server unavailable for {language}: '{server_cmd}' not found on the run-bound PATH. \
                 Start or install the language server (e.g. `cargo install {server_cmd}` \
                 or your distro's package) before retrying."
            ),
            true,
        );
    }

    // crosslink #645: workspace/symbol takes a `query` string instead of a
    // text-document position; the call-hierarchy follow-up ops require a
    // pre-fetched `hierarchy_item` (the value returned by
    // prepareCallHierarchy). Both are optional pass-through context.
    let extras = LspRequestExtras {
        query,
        hierarchy_item,
    };

    // Run the server, send initialize + request, get response
    match run_lsp_request(
        run,
        server_cmd,
        &server_args,
        file_path,
        line,
        character,
        action,
        &extras,
    ) {
        Ok(result) => (
            serde_json::to_string_pretty(&result).unwrap_or_default(),
            false,
        ),
        Err(e) => (format_lsp_error(server_cmd, &e), true),
    }
}

fn format_lsp_error(server_cmd: &str, error: &str) -> String {
    if server_cmd == "rust-analyzer" && error.contains("Unknown binary 'rust-analyzer'") {
        return "LSP server unavailable for rust: rust-analyzer is not installed in the active \
                Rust toolchain. Run `rustup component add rust-analyzer` and retry."
            .to_string();
    }
    format!("LSP error: {error}")
}

fn parse_lsp_file_path_arg(value: Option<&Value>) -> Result<&str, String> {
    match value {
        None => Err("Error: file_path is required".to_string()),
        Some(Value::String(file_path)) => Ok(file_path),
        Some(_) => Err("Invalid 'file_path' argument: expected string".to_string()),
    }
}

fn parse_lsp_action_arg(value: Option<&Value>) -> Result<LspAction, String> {
    let Some(value) = value else {
        return Err("Error: action is required".to_string());
    };
    let Some(action_str) = value.as_str() else {
        return Err("Invalid 'action' argument: expected string".to_string());
    };

    match action_str {
        "goToDefinition" | "definition" => Ok(LspAction::GoToDefinition),
        "findReferences" | "references" => Ok(LspAction::FindReferences),
        "hover" => Ok(LspAction::Hover),
        "documentSymbols" | "symbols" => Ok(LspAction::DocumentSymbols),
        // crosslink #645: five-op expansion.
        "workspaceSymbol" => Ok(LspAction::WorkspaceSymbol),
        "goToImplementation" | "implementation" => Ok(LspAction::GoToImplementation),
        "prepareCallHierarchy" => Ok(LspAction::PrepareCallHierarchy),
        "incomingCalls" => Ok(LspAction::IncomingCalls),
        "outgoingCalls" => Ok(LspAction::OutgoingCalls),
        _ => Err(format!(
            "Unknown LSP action: {action_str}. Use: goToDefinition, findReferences, \
             hover, documentSymbols, workspaceSymbol, goToImplementation, \
             prepareCallHierarchy, incomingCalls, outgoingCalls"
        )),
    }
}

fn parse_lsp_hierarchy_item_arg(
    action: LspAction,
    value: Option<&Value>,
) -> Result<Option<Value>, String> {
    match value {
        Some(Value::Object(_)) => Ok(value.cloned()),
        Some(_) => Err("Invalid 'hierarchy_item' argument: expected object".to_string()),
        None if matches!(action, LspAction::IncomingCalls | LspAction::OutgoingCalls) => Err(
            "Error: hierarchy_item object is required for incomingCalls/outgoingCalls. \
                 Run prepareCallHierarchy first and pass one returned CallHierarchyItem."
                .to_string(),
        ),
        None => Ok(None),
    }
}

fn parse_lsp_query_arg(value: Option<&Value>) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(Value::String(query)) => Ok(Some(query.clone())),
        Some(_) => Err("Invalid 'query' argument: expected string".to_string()),
    }
}

/// Optional per-call context for the new actions added in crosslink #645.
///
/// `query` is consumed by `workspaceSymbol`; `hierarchy_item` by the two
/// `callHierarchy/*` phase-2 ops. Both default to `None` for backwards
/// compatibility with callers that only use the original four actions.
#[derive(Debug, Default, Clone)]
struct LspRequestExtras {
    query: Option<String>,
    hierarchy_item: Option<Value>,
}

fn parse_lsp_line_arg(value: Option<&Value>) -> Result<u32, String> {
    let Some(value) = value else {
        return Ok(1);
    };
    let Some(line) = value.as_u64() else {
        return Err("Error: line must be a 1-indexed positive integer".to_string());
    };
    if line == 0 {
        return Err("Error: line must be a 1-indexed positive integer".to_string());
    }
    Ok(u64_to_u32_saturating(line))
}

fn parse_lsp_character_arg(value: Option<&Value>) -> Result<u32, String> {
    let Some(value) = value else {
        return Ok(0);
    };
    let Some(character) = value.as_u64() else {
        return Err("Error: character must be a 0-indexed non-negative integer".to_string());
    };
    Ok(u64_to_u32_saturating(character))
}

/// Map an [`LspAction`] to its `(method, params)` JSON-RPC pair. Extracted
/// so [`run_lsp_request`] stays under the project's per-function line
/// budget after the crosslink #645 five-op expansion.
fn build_action_request(
    action: LspAction,
    file_uri: &str,
    line: u32,
    character: u32,
    extras: &LspRequestExtras,
) -> (&'static str, Value) {
    let pos = || json!({"line": line.saturating_sub(1), "character": character});
    let td = || json!({"uri": file_uri});
    match action {
        LspAction::GoToDefinition => (
            "textDocument/definition",
            json!({"textDocument": td(), "position": pos()}),
        ),
        LspAction::FindReferences => (
            "textDocument/references",
            json!({
                "textDocument": td(),
                "position": pos(),
                "context": {"includeDeclaration": true}
            }),
        ),
        LspAction::Hover => (
            "textDocument/hover",
            json!({"textDocument": td(), "position": pos()}),
        ),
        LspAction::DocumentSymbols => {
            ("textDocument/documentSymbol", json!({"textDocument": td()}))
        }
        LspAction::WorkspaceSymbol => (
            "workspace/symbol",
            json!({"query": extras.query.as_deref().unwrap_or("")}),
        ),
        LspAction::GoToImplementation => (
            "textDocument/implementation",
            json!({"textDocument": td(), "position": pos()}),
        ),
        LspAction::PrepareCallHierarchy => (
            "textDocument/prepareCallHierarchy",
            json!({"textDocument": td(), "position": pos()}),
        ),
        LspAction::IncomingCalls => (
            "callHierarchy/incomingCalls",
            json!({"item": extras.hierarchy_item.clone().unwrap_or(Value::Null)}),
        ),
        LspAction::OutgoingCalls => (
            "callHierarchy/outgoingCalls",
            json!({"item": extras.hierarchy_item.clone().unwrap_or(Value::Null)}),
        ),
    }
}

#[allow(clippy::too_many_arguments)] // LSP request fields remain explicit at the process boundary.
fn run_lsp_request(
    run: &crate::tools::security::ToolRunContext,
    server_cmd: &str,
    server_args: &[&str],
    file_path: &str,
    line: u32,
    character: u32,
    action: LspAction,
    extras: &LspRequestExtras,
) -> Result<LspResult, String> {
    // File-resolve and read flow through typed `FileError` so the path and
    // `io::ErrorKind` are preserved through the source chain — see #492. We
    // stringify only at this boundary because `run_lsp_request` returns
    // `Result<_, String>` to its caller; the rendered message now always
    // names the offending file.
    let (abs_path, file) = crate::tools::open_capability_regular_read(run, file_path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Cannot inspect confined LSP input '{file_path}': {error}"))?;
    if metadata.len() > LSP_MAX_FILE_SIZE {
        return Err(format!(
            "File too large for LSP analysis: {} bytes exceeds the {}-byte limit (10 MiB)",
            metadata.len(),
            LSP_MAX_FILE_SIZE
        ));
    }
    let root_uri = format!("file://{}", run.project_root().display());
    let file_uri = format!("file://{}", abs_path.display());

    // Read from the already-confined descriptor. Reopening `abs_path` here
    // would reintroduce a validation/open race.
    let mut content = String::new();
    file.take(LSP_MAX_FILE_SIZE + 1)
        .read_to_string(&mut content)
        .map_err(|error| format!("Cannot read confined LSP input '{file_path}': {error}"))?;

    // Spawn the server.  stderr is captured into a ring buffer (last 1 KiB) so
    // that crash diagnostics survive instead of being silently discarded
    // (original: Stdio::null() — fix #355 point 5). Env is scrubbed inside
    // `spawn_language_server` (crosslink #869).
    let project_root = root_uri
        .strip_prefix("file://")
        .map(Path::new)
        .ok_or_else(|| format!("Invalid LSP root URI: {root_uri}"))?;
    let mut raw_child = spawn_language_server(run, server_cmd, server_args, project_root)?;

    // Take pipes before handing the child to the guard.
    let mut stdin = raw_child.stdin.take().ok_or("Failed to get stdin")?;
    let stdout = raw_child.stdout.take().ok_or("Failed to get stdout")?;
    let stderr_pipe = raw_child.stderr.take().ok_or("Failed to get stderr")?;
    let stderr_buf = capture_stderr(stderr_pipe);

    // The guard now owns the child.  Any early return via `?` — including the
    // original zombie-leak paths (former lines 174 and 224) — will trigger Drop
    // which kills and reaps the process (fix #355 point 3).
    let mut guard = ChildGuard::new(run, raw_child);
    let (stdout, stdout_timeout) = LspDeadlineReader::spawn(stdout, LSP_RESPONSE_READ_TIMEOUT);
    let mut reader = BufReader::new(stdout);

    // Send initialize
    let init_params = json!({
        "processId": std::process::id(),
        "rootUri": root_uri,
        "capabilities": {},
        "workspaceFolders": [{"uri": root_uri, "name": "workspace"}]
    });
    send_lsp_message(&mut stdin, "initialize", 1, init_params)?;
    // #651: answer server→client reverse-requests (e.g.
    // `workspace/configuration`) inline during init — several servers stall
    // until they receive a response. The legacy `read_lsp_response` silently
    // skipped these.
    let _init_response =
        read_lsp_response_with_reverse(&mut reader, 1, Some(&mut stdin)).map_err(|e| {
            let snip = stderr_snippet(&stderr_buf);
            format!("initialize failed: {e}{snip}")
        })?;

    // Send initialized notification
    send_lsp_notification(&mut stdin, "initialized", json!({}))?;

    // didOpen deduplication (#647): only send `textDocument/didOpen` the first
    // time the (server, file) pair is seen.  Parity with CC `LSPServerManager
    // .ts:64,277` (`isFileOpen`).  `mark_opened` returns true iff this caller
    // is the first to claim the slot; subsequent calls (e.g. a repeated tool
    // invocation against the same file) skip the notification.
    //
    // The `OpenFileGuard` ensures that an early `?`-return between here and
    // the explicit `commit()` below clears the dedup entry, so a *failed*
    // run cannot leak a "this file is open" claim into the registry — the
    // child is killed by `ChildGuard::drop`, so the server can no longer
    // honour any didOpen we did send.
    let needs_did_open = mark_opened(run, server_cmd, &abs_path);
    let mut open_guard = OpenFileGuard::new(run, server_cmd, &abs_path, needs_did_open);
    if needs_did_open {
        let did_open = json!({
            "textDocument": {
                "uri": file_uri,
                "languageId": detect_language_id(file_path),
                "version": 1,
                "text": content,
            }
        });
        send_lsp_notification(&mut stdin, "textDocument/didOpen", did_open)?;
    }

    // Readiness probe: send a documentSymbol request (id=1001) and drain
    // server notifications until the server replies.  This replaces the
    // original unconditional 500 ms sleep (fix #355 point 2), which was
    // both insufficient for cold servers and wasteful for warm ones.
    let readiness_params = json!({"textDocument": {"uri": &file_uri}});
    send_lsp_message(
        &mut stdin,
        "textDocument/documentSymbol",
        1001,
        readiness_params,
    )?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    stdout_timeout.set(LSP_READINESS_POLL_TIMEOUT);
    wait_for_readiness(&mut reader, deadline).map_err(|e| {
        let snip = stderr_snippet(&stderr_buf);
        format!("{e}{snip}")
    })?;
    stdout_timeout.set(LSP_RESPONSE_READ_TIMEOUT);

    // Send the actual request
    let (method, params) = build_action_request(action, &file_uri, line, character, extras);

    send_lsp_message(&mut stdin, method, 2, params)?;
    let response = read_lsp_response(&mut reader, 2).map_err(|e| {
        let snip = stderr_snippet(&stderr_buf);
        format!("LSP request failed: {e}{snip}")
    })?;

    // didClose mirror (#647): if we sent didOpen on this call, flip the
    // dedup flag back so the next caller is forced to send a fresh
    // didOpen.  We also notify the server for protocol cleanliness so
    // pooled-server setups don't accumulate stale handles.  This must
    // happen BEFORE the shutdown sequence below because the LSP spec
    // forbids `textDocument/*` notifications after `shutdown`.
    if needs_did_open {
        let did_close = json!({"textDocument": {"uri": &file_uri}});
        let _ = send_lsp_notification(&mut stdin, "textDocument/didClose", did_close);
    }
    // Reaching this point means the request succeeded; commit() prevents
    // the OpenFileGuard from rolling back the dedup entry below.  The
    // explicit `mark_closed` call inside commit mirrors the didClose
    // notification we just sent.
    open_guard.commit();

    // Graceful shutdown; Drop will kill+wait regardless, but we attempt a
    // clean exit first so the server can flush caches.
    //
    // crosslink #965: per LSP spec the `shutdown` request requires a response
    // BEFORE `exit` is sent. Well-behaved servers may buffer further messages
    // until they have replied to `shutdown`; if we skip reading that response,
    // the subsequent `exit` notification can land in a buffer that the server
    // never drains, leaving the child as an orphan. We read (and discard) the
    // shutdown response between the two sends; the result is intentionally
    // dropped because we only care about the protocol sequencing, not the
    // payload, and any read failure is non-fatal (Drop still kills+waits).
    let _ = send_lsp_message(&mut stdin, "shutdown", 3, json!(null));
    stdout_timeout.set(LSP_SHUTDOWN_READ_TIMEOUT);
    let _ = read_lsp_response(&mut reader, 3);
    let _ = send_lsp_notification(&mut stdin, "exit", json!(null));
    drop(stdin); // EOF signals server to exit
                 // crosslink #900: the unbounded `wait()` after `shutdown`/`exit`
                 // could block indefinitely if a misbehaving server ignored the
                 // exit notification (the `ChildGuard` Drop also calls `wait()` so
                 // we still avoid a zombie, but the request thread would be wedged
                 // until then). Bounded poll: if the server hasn't reaped in 2s,
                 // fall through to Drop, which kills + waits.
    wait_with_timeout(guard.child_mut()?, std::time::Duration::from_secs(2));

    // Parse response into our types
    let mut parsed = parse_lsp_response(action, file_path, &response);
    if matches!(
        action,
        LspAction::GoToDefinition
            | LspAction::FindReferences
            | LspAction::GoToImplementation
            | LspAction::WorkspaceSymbol
    ) {
        parsed.results = filter_gitignored(run, parsed.results);
    }
    Ok(parsed)
}

#[allow(clippy::needless_pass_by_value)]
fn send_lsp_message(
    stdin: &mut impl Write,
    method: &str,
    id: u32,
    params: Value,
) -> Result<(), String> {
    let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let body = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin
        .write_all(header.as_bytes())
        .map_err(|e| e.to_string())?;
    stdin
        .write_all(body.as_bytes())
        .map_err(|e| e.to_string())?;
    stdin.flush().map_err(|e| e.to_string())?;
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn send_lsp_notification(
    stdin: &mut impl Write,
    method: &str,
    params: Value,
) -> Result<(), String> {
    let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
    let body = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    stdin
        .write_all(header.as_bytes())
        .map_err(|e| e.to_string())?;
    stdin
        .write_all(body.as_bytes())
        .map_err(|e| e.to_string())?;
    stdin.flush().map_err(|e| e.to_string())?;
    Ok(())
}

/// Default cap for the number of intermediate LSP messages skipped while
/// waiting for a matching response id. Servers like clangd routinely emit
/// dozens of diagnostics before completing — 100 is a reasonable starting
/// point but is overridable via the `OPENCLAUDIA_LSP_MAX_MESSAGES`
/// environment variable for noisy servers (crosslink #886).
const LSP_DEFAULT_MAX_MESSAGES: u32 = 100;

/// Resolve the per-call maximum response-scan budget.
///
/// Crosslink #886: previously a hard-coded `100`. We now respect the
/// `OPENCLAUDIA_LSP_MAX_MESSAGES` env var so an operator can crank the
/// budget up for chatty servers without recompiling, or down for tests
/// that want to exercise the cap path quickly. Invalid / zero values
/// fall back to the default rather than silently disabling the cap.
fn lsp_max_messages() -> u32 {
    std::env::var("OPENCLAUDIA_LSP_MAX_MESSAGES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(LSP_DEFAULT_MAX_MESSAGES)
}

/// Read an LSP response, skipping server-initiated notifications until we find
/// the response matching `expected_id`.
///
/// Crosslink #886: the scan budget is configurable via
/// `OPENCLAUDIA_LSP_MAX_MESSAGES`, and the exhaustion error names the
/// cap so an operator can tell "chatty server → raise the cap" from
/// "hung server → different remedy".
fn read_lsp_response(
    reader: &mut BufReader<impl std::io::Read>,
    expected_id: u32,
) -> Result<Value, String> {
    read_lsp_response_with_reverse(reader, expected_id, None::<&mut std::io::Sink>)
}

/// Like [`read_lsp_response`] but, when `reverse_writer` is supplied,
/// answers server→client reverse-requests inline so the server can
/// finish initialization.
///
/// Reverse-requests are the underbelly of LSP: a server may, mid-stream,
/// send a JSON-RPC request *to the client* (e.g. `workspace/configuration`
/// during init) and stall until it sees a matching response. The legacy
/// loop silently skipped these messages — which is why several servers
/// (clangd, gopls, jdtls) appear to hang under OC today. CC parity here
/// is `LSPServerManager.ts:123-135` (crosslink #651).
///
/// We currently support the bare-minimum response that satisfies the
/// most common reverse-requests:
///
/// | method                       | response shape   | notes                       |
/// |------------------------------|------------------|-----------------------------|
/// | `workspace/configuration`    | `[null, ...]`    | one `null` per requested scope |
/// | `client/registerCapability`  | `null`           | no-op accept                  |
/// | `client/unregisterCapability`| `null`           | no-op accept                  |
/// | `window/workDoneProgress/create` | `null`       | no-op accept                  |
///
/// Anything else gets a JSON-RPC `MethodNotFound` (`-32601`) so the server
/// can fail fast instead of stalling.
pub(crate) fn read_lsp_response_with_reverse<W: std::io::Write>(
    reader: &mut BufReader<impl std::io::Read>,
    expected_id: u32,
    mut reverse_writer: Option<&mut W>,
) -> Result<Value, String> {
    let max_messages = lsp_max_messages();
    for _attempt in 0..max_messages {
        // Read headers
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|e| format!("Read error: {e}"))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if let Some(len_str) = trimmed.strip_prefix("Content-Length: ") {
                content_length = len_str
                    .parse()
                    .map_err(|e| format!("Bad content-length: {e}"))?;
            }
        }

        if content_length == 0 {
            return Err("No content-length in response".to_string());
        }

        let mut body = vec![0u8; content_length];
        std::io::Read::read_exact(reader, &mut body)
            .map_err(|e| format!("Body read error: {e}"))?;
        let msg: Value =
            serde_json::from_slice(&body).map_err(|e| format!("JSON parse error: {e}"))?;

        // If this message has an "id" matching our expected_id, it's the response
        if let Some(id) = msg.get("id").and_then(serde_json::Value::as_u64) {
            if id == u64::from(expected_id) {
                return Ok(msg);
            }
            // Server→client reverse-request: has an id AND a method. The
            // server is waiting for a response from us. Answer it inline so
            // initialization can progress.
            if let (Some(method), Some(writer)) = (
                msg.get("method").and_then(|v| v.as_str()),
                reverse_writer.as_deref_mut(),
            ) {
                let reply = build_reverse_response(id, method, msg.get("params"));
                if let Err(err) = write_lsp_raw(writer, &reply) {
                    tracing::warn!(
                        method,
                        id,
                        error = %err,
                        "failed to answer LSP reverse-request — server may stall",
                    );
                }
            }
        }

        // Otherwise it's a notification (no id) or a response to a different request;
        // skip it and read the next message.
    }
    Err(format!(
        "LSP scan budget exhausted: did not see response id={expected_id} after \
         {max_messages} messages (raise OPENCLAUDIA_LSP_MAX_MESSAGES to relax)"
    ))
}

/// JSON-RPC error code: `MethodNotFound`. Returned to the server for any
/// reverse-request method we don't explicitly handle.
const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;

/// Build a JSON-RPC response to a server→client reverse-request.
///
/// Public-via-`pub(crate)` only so the unit tests can exercise the
/// method-dispatch matrix without spinning up a child process.
pub(crate) fn build_reverse_response(id: u64, method: &str, params: Option<&Value>) -> Value {
    match method {
        // CC parity: every scope receives `null` (i.e. "use server defaults").
        // The number of nulls must match `params.items.len()` or the spec
        // says servers may treat the response as malformed.
        "workspace/configuration" => {
            let n = params
                .and_then(|p| p.get("items"))
                .and_then(|v| v.as_array())
                .map_or(1, Vec::len);
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": vec![Value::Null; n],
            })
        }
        // Capability registration / progress creation: accept silently so
        // the server can move on. CC does the same.
        "client/registerCapability"
        | "client/unregisterCapability"
        | "window/workDoneProgress/create" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": Value::Null,
        }),
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": JSONRPC_METHOD_NOT_FOUND,
                "message": format!("OpenClaudia LSP shim does not handle reverse-request: {other}"),
            },
        }),
    }
}

/// Serialize `msg` with the LSP Content-Length framing and write to
/// `writer`. Mirrors [`send_lsp_message`] minus the `id` synthesis (the
/// caller already chose an id for a reply).
fn write_lsp_raw(writer: &mut impl Write, msg: &Value) -> Result<(), String> {
    let body = serde_json::to_string(msg).map_err(|e| e.to_string())?;
    let header = format!("Content-Length: {}\r\n\r\n", body.len());
    writer
        .write_all(header.as_bytes())
        .map_err(|e| e.to_string())?;
    writer
        .write_all(body.as_bytes())
        .map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
fn find_project_root(file_path: &Path) -> String {
    let mut dir = file_path.parent().unwrap_or(file_path);
    loop {
        if dir.join(".git").exists()
            || dir.join("Cargo.toml").exists()
            || dir.join("package.json").exists()
        {
            return format!("file://{}", dir.display());
        }
        match dir.parent() {
            Some(p) if p != dir => dir = p,
            _ => return format!("file://{}", dir.display()),
        }
    }
}

fn detect_language_id(file_path: &str) -> &str {
    let ext = file_path.rsplit('.').next().unwrap_or("");
    match ext {
        "rs" => "rust",
        "ts" => "typescript",
        "tsx" => "typescriptreact",
        "js" => "javascript",
        "jsx" => "javascriptreact",
        "py" => "python",
        "go" => "go",
        "c" => "c",
        "cpp" | "cc" | "cxx" | "h" | "hpp" => "cpp",
        "java" => "java",
        "rb" => "ruby",
        _ => "plaintext",
    }
}

fn parse_lsp_response(action: LspAction, file_path: &str, response: &Value) -> LspResult {
    let result_data = response.get("result");

    match action {
        LspAction::Hover => {
            // crosslink #895: the original 5-level-nested map_or_else
            // chain compiled but was unreadable. Each shape of the
            // LSP `contents` payload (string / object / array) is now
            // handled by a dedicated helper.
            let hover_text = result_data
                .and_then(|r| r.get("contents"))
                .map(extract_hover_contents);
            LspResult {
                action: "hover".to_string(),
                file_path: file_path.to_string(),
                results: Vec::new(),
                hover_text,
                symbols: Vec::new(),
            }
        }
        LspAction::GoToDefinition | LspAction::FindReferences | LspAction::GoToImplementation => {
            // crosslink #643: parse_locations now normalises LocationLink →
            // Location internally, so the three position-pointing actions
            // share the same parsing path.
            // crosslink #644: drop hits inside gitignored files (build
            // artefacts, vendored deps) — they pollute jump-to-def results.
            let locations = parse_locations(result_data);
            LspResult {
                action: format!("{action:?}"),
                file_path: file_path.to_string(),
                results: locations,
                hover_text: None,
                symbols: Vec::new(),
            }
        }
        LspAction::DocumentSymbols => {
            let symbols = parse_symbols(result_data);
            LspResult {
                action: "documentSymbols".to_string(),
                file_path: file_path.to_string(),
                results: Vec::new(),
                hover_text: None,
                symbols,
            }
        }
        // crosslink #645: `workspace/symbol` returns `WorkspaceSymbol[]` or
        // `SymbolInformation[]` — both carry a `location: Location` field, so
        // we project each entry's location through `parse_locations` to get
        // the same `LspLocation` shape every other ops returns.
        LspAction::WorkspaceSymbol => {
            let locations = match result_data {
                Some(Value::Array(arr)) => {
                    let locs: Vec<Value> = arr
                        .iter()
                        .filter_map(|s| s.get("location").cloned())
                        .collect();
                    parse_locations(Some(&Value::Array(locs)))
                }
                _ => Vec::new(),
            };
            LspResult {
                action: "workspaceSymbol".to_string(),
                file_path: file_path.to_string(),
                results: locations,
                hover_text: None,
                symbols: Vec::new(),
            }
        }
        LspAction::PrepareCallHierarchy => {
            // `CallHierarchyItem[]` — each item has `uri` + `selectionRange`.
            // Render via parse_call_hierarchy by wrapping each item under a
            // synthetic `from` key so it shares the call-edge path.
            let synthetic = result_data.and_then(Value::as_array).map(|items| {
                Value::Array(
                    items
                        .iter()
                        .map(|it| serde_json::json!({"from": it}))
                        .collect(),
                )
            });
            let locations = parse_call_hierarchy(synthetic.as_ref(), "from");
            LspResult {
                action: "prepareCallHierarchy".to_string(),
                file_path: file_path.to_string(),
                results: locations,
                hover_text: None,
                symbols: Vec::new(),
            }
        }
        LspAction::IncomingCalls => {
            let locations = parse_call_hierarchy(result_data, "from");
            LspResult {
                action: "incomingCalls".to_string(),
                file_path: file_path.to_string(),
                results: locations,
                hover_text: None,
                symbols: Vec::new(),
            }
        }
        LspAction::OutgoingCalls => {
            let locations = parse_call_hierarchy(result_data, "to");
            LspResult {
                action: "outgoingCalls".to_string(),
                file_path: file_path.to_string(),
                results: locations,
                hover_text: None,
                symbols: Vec::new(),
            }
        }
    }
}

/// Convert a u64 to u32, saturating at `u32::MAX`.
fn u64_to_u32_saturating(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

/// Convert a zero-based LSP position component to a one-based user-facing
/// coordinate without overflowing on malformed huge server values.
fn lsp_position_to_user_coordinate(v: u64) -> u32 {
    u64_to_u32_saturating(v).saturating_add(1)
}

/// Extract a flat text rendering of a `Hover.contents` payload.
///
/// Per LSP spec, `contents` may be:
///   * a plain string,
///   * a `MarkedString` object `{language, value}` / `MarkupContent`
///     `{kind, value}`,
///   * an array of any of the above.
///
/// All three shapes collapse to text for terminal rendering — array elements
/// are separated by blank lines to preserve distinct hover blocks.
fn extract_hover_contents(contents: &Value) -> String {
    if let Some(s) = contents.as_str() {
        return s.to_string();
    }
    if let Some(obj) = contents.as_object() {
        return extract_value_field(obj);
    }
    if let Some(arr) = contents.as_array() {
        return arr
            .iter()
            .filter_map(extract_hover_array_element)
            .collect::<Vec<_>>()
            .join("\n\n");
    }
    String::new()
}

/// Pull a `"value": "<string>"` field out of an LSP object payload.
///
/// Used for both `MarkupContent` and `MarkedString` object shapes —
/// in both, the rendered text lives under `value`.
fn extract_value_field(obj: &serde_json::Map<String, Value>) -> String {
    obj.get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Extract a single element of a `Hover.contents` array.
///
/// Each element is either a plain string or a `{value: ...}` object;
/// other shapes (numbers, nulls) are skipped.
fn extract_hover_array_element(v: &Value) -> Option<&str> {
    v.as_str()
        .or_else(|| v.get("value").and_then(|x| x.as_str()))
}

/// Normalise either a `Location` or a `LocationLink` JSON object to the
/// `(uri, range)` pair we render downstream (crosslink #643).
///
/// Per LSP §3.17 the goToDefinition / goToImplementation response is
/// `Location | Location[] | LocationLink[] | null`. The shapes differ:
///
/// * `Location`     — `{uri, range}`
/// * `LocationLink` — `{targetUri, targetRange, targetSelectionRange,
///                      originSelectionRange?}`
///
/// CC normalises `LocationLink` → `Location` by treating
/// `targetUri` as `uri` and `targetSelectionRange` (falling back to
/// `targetRange`) as `range`. We mirror that exactly so a server that
/// returns `LocationLink`s (e.g. modern `rust-analyzer`, `gopls`) does not
/// silently produce empty results.
fn normalise_location(loc: &Value) -> Option<(&str, &Value)> {
    // `Location` shape: top-level `uri`.
    if let Some(uri) = loc.get("uri").and_then(Value::as_str) {
        if let Some(range) = loc.get("range") {
            return Some((uri, range));
        }
    }
    // `LocationLink` shape: `targetUri` + `targetSelectionRange` (preferred)
    // or `targetRange` (fallback). `targetSelectionRange` is "the range of
    // the symbol name itself" which is the more useful jump target — it is
    // what CC's normaliser picks.
    if let Some(target_uri) = loc.get("targetUri").and_then(Value::as_str) {
        if let Some(range) = loc
            .get("targetSelectionRange")
            .or_else(|| loc.get("targetRange"))
        {
            return Some((target_uri, range));
        }
    }
    None
}

/// Convert a `file://` URI into an absolute filesystem path, if possible.
///
/// Used by [`filter_gitignored`] (crosslink #644) to feed
/// `git check-ignore` paths it understands. Non-`file://` URIs (e.g. JDT
/// `jdt://` scheme) are returned as `None` so the caller skips the check
/// and keeps the location.
fn uri_to_local_path(uri: &str) -> Option<std::path::PathBuf> {
    let trimmed = uri.strip_prefix("file://")?;
    // Strip a leading `/` on Windows-shaped `file:///C:/...` URIs is wrong, but
    // OC's stored format always begins with `/` on Linux and the LSP servers
    // we target emit POSIX paths inside `file://` even on Windows because the
    // language server itself canonicalises. Treat as POSIX path.
    Some(std::path::PathBuf::from(trimmed))
}

/// Filter out [`LspLocation`]s pointing at gitignored files (crosslink #644).
///
/// Runs `git check-ignore` once per unique path. The check is best-effort:
/// if `git` is not on PATH, the working tree is not a git repo, or
/// `check-ignore` errors, the input list passes through unchanged — we
/// must never silently drop a hit because the gitignore probe failed,
/// since the model relies on the locations to navigate the codebase.
fn filter_gitignored(
    run: &crate::tools::security::ToolRunContext,
    locations: Vec<LspLocation>,
) -> Vec<LspLocation> {
    use std::collections::HashSet;

    if locations.is_empty() {
        return locations;
    }

    // Collect the unique local paths to probe; non-file URIs go through.
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    let mut path_strings: Vec<String> = Vec::new();
    for loc in &locations {
        if let Some(p) = uri_to_local_path(&loc.uri) {
            if !paths.contains(&p) {
                if let Some(s) = p.to_str() {
                    path_strings.push(s.to_string());
                    paths.push(p);
                }
            }
        }
    }
    if path_strings.is_empty() {
        return locations;
    }

    // `git check-ignore --stdin` reads NUL- or newline-separated paths and
    // prints back only the ones that ARE ignored. Exit status 0 = at least one
    // ignored; 1 = none ignored; 128 = error (not a repo etc).
    let input = format!("{}\n", path_strings.join("\n"));
    let output = match git_bin(run).and_then(|git| {
        crate::tools::command::run_sandboxed_with_timeout_with_input(
            run,
            &git,
            &["check-ignore", "--stdin"],
            run.working_directory(),
            LSP_GITIGNORE_TIMEOUT,
            input.as_bytes(),
        )
        .map_err(|e| e.to_string())
    }) {
        Ok(output) => output,
        Err(err) => {
            tracing::debug!(
                error = %err,
                "LSP gitignore filter failed; keeping all candidate locations"
            );
            return locations;
        }
    };

    // Status 128 means "not a git repo" or other error — keep everything.
    if output.status.code() == Some(128) {
        return locations;
    }

    let ignored: HashSet<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect();

    if ignored.is_empty() {
        return locations;
    }

    locations
        .into_iter()
        .filter(|loc| {
            // Per `unnecessary_map_or`: collapse to `.is_none_or` so the
            // "keep when we couldn't probe" semantics are explicit.
            uri_to_local_path(&loc.uri)
                .is_none_or(|p| p.to_str().is_none_or(|s| !ignored.contains(s)))
        })
        .collect()
}

fn parse_locations(data: Option<&Value>) -> Vec<LspLocation> {
    let arr = match data {
        Some(Value::Array(a)) => a.clone(),
        Some(obj @ Value::Object(_)) => vec![obj.clone()],
        _ => return Vec::new(),
    };

    arr.iter()
        .filter_map(|loc| {
            let (uri, range) = normalise_location(loc)?;
            let start = range.get("start")?;
            let end = range.get("end");
            Some(LspLocation {
                uri: uri.to_string(),
                line: start
                    .get("line")
                    .and_then(serde_json::Value::as_u64)
                    .map_or(1, lsp_position_to_user_coordinate),
                character: start
                    .get("character")
                    .and_then(serde_json::Value::as_u64)
                    .map_or(1, lsp_position_to_user_coordinate),
                end_line: end
                    .and_then(|e| e.get("line"))
                    .and_then(serde_json::Value::as_u64)
                    .map(lsp_position_to_user_coordinate),
                end_character: end
                    .and_then(|e| e.get("character"))
                    .and_then(serde_json::Value::as_u64)
                    .map(lsp_position_to_user_coordinate),
                preview: None,
            })
        })
        .collect()
}

/// Parse a `callHierarchy/{incoming,outgoing}Calls` response.
///
/// Each element is a `CallHierarchyIncomingCall` / `OutgoingCall` that
/// wraps a `CallHierarchyItem` under `from` (incoming) or `to` (outgoing).
/// We pull the item's `uri` + `selectionRange` (preferring it over the
/// full `range`, since `selectionRange` is the symbol-name range) and
/// emit a [`LspLocation`] per entry, matching how CC surfaces these.
fn parse_call_hierarchy(data: Option<&Value>, key: &str) -> Vec<LspLocation> {
    let Some(Value::Array(arr)) = data else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|entry| {
            let item = entry.get(key)?;
            let uri = item.get("uri").and_then(Value::as_str)?;
            let range = item.get("selectionRange").or_else(|| item.get("range"))?;
            let start = range.get("start")?;
            let end = range.get("end");
            Some(LspLocation {
                uri: uri.to_string(),
                line: start
                    .get("line")
                    .and_then(serde_json::Value::as_u64)
                    .map_or(1, lsp_position_to_user_coordinate),
                character: start
                    .get("character")
                    .and_then(serde_json::Value::as_u64)
                    .map_or(1, lsp_position_to_user_coordinate),
                end_line: end
                    .and_then(|e| e.get("line"))
                    .and_then(serde_json::Value::as_u64)
                    .map(lsp_position_to_user_coordinate),
                end_character: end
                    .and_then(|e| e.get("character"))
                    .and_then(serde_json::Value::as_u64)
                    .map(lsp_position_to_user_coordinate),
                preview: item.get("name").and_then(Value::as_str).map(str::to_string),
            })
        })
        .collect()
}

const MAX_SYMBOL_DEPTH: usize = 20;

fn parse_symbols(data: Option<&Value>) -> Vec<LspSymbol> {
    parse_symbols_inner(data, 0)
}

fn parse_symbols_inner(data: Option<&Value>, depth: usize) -> Vec<LspSymbol> {
    if depth >= MAX_SYMBOL_DEPTH {
        return Vec::new();
    }

    let Some(Value::Array(arr)) = data else {
        return Vec::new();
    };

    arr.iter()
        .filter_map(|sym| {
            let name = sym.get("name").and_then(|n| n.as_str())?;
            let kind_num = sym
                .get("kind")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let range = sym
                .get("range")
                .or_else(|| sym.get("location").and_then(|l| l.get("range")))?;
            let start = range.get("start")?;
            let end = range.get("end");

            // crosslink #963: `parse_symbols_inner` already returns `Vec::new()`
            // when the value is not an array, so the previous `.and_then(as_array)
            // .map(|_| ...)` gate was a redundant double-fetch that discarded the
            // already-converted array. One call, single fetch.
            let children = parse_symbols_inner(sym.get("children"), depth + 1);

            Some(LspSymbol {
                name: name.to_string(),
                kind: symbol_kind_name(kind_num),
                line: start
                    .get("line")
                    .and_then(serde_json::Value::as_u64)
                    .map_or(0, u64_to_u32_saturating)
                    + 1,
                end_line: end
                    .and_then(|e| e.get("line"))
                    .and_then(serde_json::Value::as_u64)
                    .map(|l| u64_to_u32_saturating(l) + 1),
                children,
            })
        })
        .collect()
}

fn symbol_kind_name(kind: u64) -> String {
    match kind {
        1 => "File",
        2 => "Module",
        3 => "Namespace",
        4 => "Package",
        5 => "Class",
        6 => "Method",
        7 => "Property",
        8 => "Field",
        9 => "Constructor",
        10 => "Enum",
        11 => "Interface",
        12 => "Function",
        13 => "Variable",
        14 => "Constant",
        15 => "String",
        16 => "Number",
        17 => "Boolean",
        18 => "Array",
        19 => "Object",
        20 => "Key",
        21 => "Null",
        22 => "EnumMember",
        23 => "Struct",
        24 => "Event",
        25 => "Operator",
        26 => "TypeParameter",
        _ => "Unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    fn test_run_with_environment(
        root: &Path,
        grants: HashMap<String, String>,
    ) -> std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(grants)
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .provider("lsp-environment-test")
            .build()
            .expect("explicit LSP test run")
    }

    #[test]
    fn production_external_probes_use_resolved_helpers() {
        let git = git_bin(test_run()).expect("lsp tests require git on the run-bound PATH");
        assert!(
            git.is_absolute(),
            "git_bin must resolve git to an absolute path, got {}",
            git.display()
        );

        let src = include_str!("lsp.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"git\")")
                    && !code.contains("std::process::Command::new(\"git\")"),
                "production lsp code must not invoke bare git; line {n}: {raw_line}",
                n = idx + 1,
            );
            assert!(
                !code.contains("Command::new(\"which\")")
                    && !code.contains("std::process::Command::new(\"which\")"),
                "production lsp code must not invoke bare which; line {n}: {raw_line}",
                n = idx + 1,
            );
            assert!(
                !code.contains("wait_with_output("),
                "production lsp subprocess waits must be deadline-bounded; \
                 line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }

    #[test]
    fn child_guard_missing_child_returns_error_not_panic() {
        let mut guard = ChildGuard {
            child: None,
            _registration: None,
        };
        let err = guard
            .child_mut()
            .expect_err("missing child handle should be a normal LSP error");
        assert!(
            err.contains("already taken"),
            "error must explain the invalid child state: {err}"
        );
    }

    #[test]
    fn test_detect_language_server() {
        assert_eq!(
            detect_language_server("main.rs").unwrap().0,
            "rust-analyzer"
        );
        assert_eq!(
            detect_language_server("app.tsx").unwrap().0,
            "typescript-language-server"
        );
        assert_eq!(detect_language_server("script.py").unwrap().0, "pylsp");
        assert!(detect_language_server("readme.md").is_none());
    }

    #[test]
    fn test_detect_language_id() {
        assert_eq!(detect_language_id("main.rs"), "rust");
        assert_eq!(detect_language_id("App.tsx"), "typescriptreact");
        assert_eq!(detect_language_id("unknown.xyz"), "plaintext");
    }

    #[test]
    fn test_parse_hover_response() {
        let resp = json!({"result": {"contents": {"kind": "markdown", "value": "fn main()"}}});
        let result = parse_lsp_response(LspAction::Hover, "test.rs", &resp);
        assert_eq!(result.hover_text, Some("fn main()".to_string()));
    }

    #[test]
    fn test_parse_hover_string_contents() {
        let resp = json!({"result": {"contents": "simple hover text"}});
        let result = parse_lsp_response(LspAction::Hover, "test.rs", &resp);
        assert_eq!(result.hover_text, Some("simple hover text".to_string()));
    }

    #[test]
    fn test_parse_hover_array_contents() {
        let resp = json!({"result": {"contents": ["line1", {"value": "line2"}]}});
        let result = parse_lsp_response(LspAction::Hover, "test.rs", &resp);
        assert_eq!(result.hover_text, Some("line1\n\nline2".to_string()));
    }

    #[test]
    fn test_parse_hover_null_result() {
        let resp = json!({"result": null});
        let result = parse_lsp_response(LspAction::Hover, "test.rs", &resp);
        assert_eq!(result.hover_text, None);
    }

    #[test]
    fn test_parse_locations() {
        let data = json!([{
            "uri": "file:///test.rs",
            "range": {"start": {"line": 10, "character": 5}, "end": {"line": 10, "character": 15}}
        }]);
        let locs = parse_locations(Some(&data));
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].line, 11); // 0-indexed to 1-indexed
        assert_eq!(locs[0].character, 6);
        assert_eq!(locs[0].end_line, Some(11));
        assert_eq!(locs[0].end_character, Some(16));
    }

    #[test]
    fn test_parse_locations_single_object() {
        let data = json!({
            "uri": "file:///test.rs",
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 10}}
        });
        let locs = parse_locations(Some(&data));
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].line, 1);
    }

    #[test]
    fn parse_locations_saturates_huge_lsp_coordinates() {
        let data = json!([{
            "uri": "file:///test.rs",
            "range": {
                "start": {"line": u64::MAX, "character": u64::MAX},
                "end": {"line": u64::MAX, "character": u64::MAX}
            }
        }]);
        let locs = parse_locations(Some(&data));
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].line, u32::MAX);
        assert_eq!(locs[0].character, u32::MAX);
        assert_eq!(locs[0].end_line, Some(u32::MAX));
        assert_eq!(locs[0].end_character, Some(u32::MAX));
    }

    #[test]
    fn test_parse_locations_empty() {
        let locs = parse_locations(None);
        assert!(locs.is_empty());

        let locs = parse_locations(Some(&json!(null)));
        assert!(locs.is_empty());
    }

    #[test]
    fn test_parse_symbols() {
        let data = json!([{
            "name": "main",
            "kind": 12,
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 5, "character": 1}}
        }]);
        let syms = parse_symbols(Some(&data));
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "main");
        assert_eq!(syms[0].kind, "Function");
        assert_eq!(syms[0].line, 1);
        assert_eq!(syms[0].end_line, Some(6));
    }

    #[test]
    fn test_parse_symbols_with_children() {
        let data = json!([{
            "name": "MyStruct",
            "kind": 23,
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 10, "character": 1}},
            "children": [{
                "name": "field_a",
                "kind": 8,
                "range": {"start": {"line": 1, "character": 4}, "end": {"line": 1, "character": 20}}
            }]
        }]);
        let syms = parse_symbols(Some(&data));
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "MyStruct");
        assert_eq!(syms[0].kind, "Struct");
        assert_eq!(syms[0].children.len(), 1);
        assert_eq!(syms[0].children[0].name, "field_a");
        assert_eq!(syms[0].children[0].kind, "Field");
    }

    #[test]
    fn test_parse_symbols_with_location_fallback() {
        // SymbolInformation uses "location" instead of "range"
        let data = json!([{
            "name": "foo",
            "kind": 12,
            "location": {
                "uri": "file:///test.rs",
                "range": {"start": {"line": 5, "character": 0}, "end": {"line": 8, "character": 1}}
            }
        }]);
        let syms = parse_symbols(Some(&data));
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "foo");
        assert_eq!(syms[0].line, 6);
    }

    #[test]
    fn test_symbol_kind_names() {
        assert_eq!(symbol_kind_name(5), "Class");
        assert_eq!(symbol_kind_name(12), "Function");
        assert_eq!(symbol_kind_name(23), "Struct");
        assert_eq!(symbol_kind_name(999), "Unknown");
    }

    #[test]
    fn test_execute_lsp_missing_file_path() {
        let args = HashMap::new();
        let (msg, is_err) = execute_lsp(test_run(), &args);
        assert!(is_err);
        assert!(msg.contains("file_path is required"));
    }

    #[test]
    fn test_execute_lsp_unknown_extension() {
        let mut args = HashMap::new();
        args.insert(
            "file_path".to_string(),
            Value::String("readme.md".to_string()),
        );
        args.insert("action".to_string(), Value::String("hover".to_string()));
        let (msg, is_err) = execute_lsp(test_run(), &args);
        assert!(is_err);
        assert!(msg.contains("No language server known"));
    }

    #[test]
    fn test_execute_lsp_unknown_action() {
        let mut args = HashMap::new();
        args.insert(
            "file_path".to_string(),
            Value::String("test.rs".to_string()),
        );
        args.insert("action".to_string(), Value::String("badAction".to_string()));
        // This will either fail on unknown action or missing server; both are valid error paths
        let (msg, is_err) = execute_lsp(test_run(), &args);
        assert!(is_err);
        assert!(msg.contains("Unknown LSP action") || msg.contains("not found"));
    }

    #[test]
    fn test_find_project_root_with_cargo() {
        // Use this project's own path as a test case
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        if manifest.exists() {
            let root = find_project_root(&manifest);
            assert!(root.starts_with("file://"));
            assert!(root.contains(env!("CARGO_MANIFEST_DIR")));
        }
    }

    #[test]
    fn test_parse_definition_response() {
        let resp = json!({
            "id": 2,
            "result": [{
                "uri": "file:///src/main.rs",
                "range": {
                    "start": {"line": 42, "character": 4},
                    "end": {"line": 42, "character": 20}
                }
            }]
        });
        let result = parse_lsp_response(LspAction::GoToDefinition, "test.rs", &resp);
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].line, 43);
        assert_eq!(result.results[0].uri, "file:///src/main.rs");
    }

    #[test]
    fn test_parse_document_symbols_response() {
        let resp = json!({
            "id": 2,
            "result": [
                {
                    "name": "Config",
                    "kind": 23,
                    "range": {"start": {"line": 0, "character": 0}, "end": {"line": 20, "character": 1}},
                    "children": [
                        {
                            "name": "new",
                            "kind": 6,
                            "range": {"start": {"line": 5, "character": 4}, "end": {"line": 10, "character": 5}}
                        }
                    ]
                }
            ]
        });
        let result = parse_lsp_response(LspAction::DocumentSymbols, "test.rs", &resp);
        assert_eq!(result.symbols.len(), 1);
        assert_eq!(result.symbols[0].name, "Config");
        assert_eq!(result.symbols[0].kind, "Struct");
        assert_eq!(result.symbols[0].children.len(), 1);
        assert_eq!(result.symbols[0].children[0].name, "new");
        assert_eq!(result.symbols[0].children[0].kind, "Method");
    }

    // ── Spec-pinning tests (#550 Phase 2) ─────────────────────────────────────
    //
    // These tests pin OC's CURRENT behavior against the Phase 1 spec (#535).
    // They deliberately assert divergences from the CC reference; each divergence
    // is tracked by a gap issue. Do NOT "fix" these tests by adding features —
    // the purpose is to detect regressions in the existing contracts.

    // Spec B1: goToDefinition — server selection + location return
    // ─────────────────────────────────────────────────────────────

    /// B1a — Coordinate system: OC converts 0-based LSP line/character
    /// positions to 1-based user-facing coordinates.
    #[test]
    fn spec_b1_coordinate_conversion_line_and_character_1based() {
        let data = json!([{
            "uri": "file:///foo.rs",
            "range": {
                "start": {"line": 9, "character": 3},
                "end":   {"line": 9, "character": 12}
            }
        }]);
        let locs = parse_locations(Some(&data));
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].line, 10);
        assert_eq!(locs[0].character, 4);
        assert_eq!(locs[0].end_line, Some(10));
        assert_eq!(locs[0].end_character, Some(13));
    }

    /// B1b — OC stores the raw `file://…` URI, not a workspace-relative path.
    /// Crosslink #643 (closed): `LocationLink` shapes are now normalised
    /// to `Location` via `normalise_location`; see the dedicated test
    /// `location_link_normalised_to_location` below.
    #[test]
    fn spec_b1_raw_uri_stored_not_relative_path() {
        let data = json!([{
            "uri": "file:///home/user/project/src/lib.rs",
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 5}}
        }]);
        let locs = parse_locations(Some(&data));
        assert_eq!(locs.len(), 1);
        // Pinning: OC stores the raw file:// URI, not a relative path.
        assert_eq!(locs[0].uri, "file:///home/user/project/src/lib.rs");
    }

    /// B1c — `LocationLink` objects are normalised to `Location` (crosslink
    /// #643, closed). `targetUri` becomes `uri` and `targetSelectionRange`
    /// (preferred over `targetRange`) becomes `range`. This mirrors CC's
    /// `LocationLink` → `Location` normaliser.
    #[test]
    fn location_link_normalised_to_location() {
        let data = json!([{
            "targetUri": "file:///src/lib.rs",
            "targetRange": {"start": {"line": 5, "character": 0}, "end": {"line": 5, "character": 10}},
            "targetSelectionRange": {"start": {"line": 7, "character": 4}, "end": {"line": 7, "character": 9}},
            "originSelectionRange": {"start": {"line": 1, "character": 0}, "end": {"line": 1, "character": 5}}
        }]);
        let locs = parse_locations(Some(&data));
        assert_eq!(locs.len(), 1, "LocationLink should normalise to Location");
        assert_eq!(locs[0].uri, "file:///src/lib.rs");
        // targetSelectionRange is the symbol name; preferred over targetRange.
        // Line is 0-based at the wire → 1-based here, so 7 → 8.
        assert_eq!(locs[0].line, 8);
        assert_eq!(locs[0].character, 5);
    }

    /// `LocationLink` without `targetSelectionRange` should fall back to
    /// `targetRange`.
    #[test]
    fn location_link_falls_back_to_target_range() {
        let data = json!([{
            "targetUri": "file:///src/lib.rs",
            "targetRange": {"start": {"line": 5, "character": 0}, "end": {"line": 5, "character": 10}}
        }]);
        let locs = parse_locations(Some(&data));
        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].line, 6);
    }

    // Spec B2: hover — hover text extraction
    // ───────────────────────────────────────

    /// B2a — `MarkedString` array items are separated by blank lines so
    /// independent hover blocks do not run together.
    #[test]
    fn spec_b2_array_join_uses_blank_line_between_blocks() {
        let resp = json!({"result": {"contents": ["first", {"value": "second"}, "third"]}});
        let result = parse_lsp_response(LspAction::Hover, "test.rs", &resp);
        let text = result.hover_text.unwrap();
        assert!(
            text.contains("\n\n"),
            "hover blocks must be separated by a blank line"
        );
        assert_eq!(text, "first\n\nsecond\n\nthird");
    }

    /// B2b — OC does NOT prepend a range-qualified prefix even when
    /// `Hover.range` is present. CC prepends "Hover info at <line>:<char>:\n\n".
    /// Pinning the absence of this prefix.
    #[test]
    fn spec_b2_no_range_prefix_when_hover_range_present() {
        let resp = json!({
            "result": {
                "contents": {"kind": "plaintext", "value": "fn foo()"},
                "range": {
                    "start": {"line": 10, "character": 4},
                    "end":   {"line": 10, "character": 7}
                }
            }
        });
        let result = parse_lsp_response(LspAction::Hover, "test.rs", &resp);
        let text = result.hover_text.unwrap();
        // OC ignores the range field entirely; raw value is returned.
        assert_eq!(text, "fn foo()");
        // Pinning absence of CC's range prefix.
        assert!(
            !text.contains("Hover info at"),
            "OC does not emit range-qualified prefix; gap vs CC"
        );
    }

    // Spec B3: findReferences — reference location list
    // ──────────────────────────────────────────────────

    /// B3a — OC's findReferences output uses the same `parse_locations` path as
    /// goToDefinition: produces Vec<LspLocation> with raw URIs, no file-grouping.
    /// Gap: CC groups references by file; OC returns a flat list.
    #[test]
    fn spec_b3_references_flat_raw_uris_no_file_grouping() {
        let resp = json!({
            "id": 2,
            "result": [
                {
                    "uri": "file:///a.rs",
                    "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 5}}
                },
                {
                    "uri": "file:///b.rs",
                    "range": {"start": {"line": 9, "character": 2}, "end": {"line": 9, "character": 8}}
                }
            ]
        });
        let result = parse_lsp_response(LspAction::FindReferences, "test.rs", &resp);
        // OC: flat list of LspLocation, no grouping.
        assert_eq!(result.results.len(), 2);
        // URIs are raw file:// strings, not relative paths. (Gap vs CC.)
        assert_eq!(result.results[0].uri, "file:///a.rs");
        assert_eq!(result.results[1].uri, "file:///b.rs");
        // Symbols vector is empty for references action.
        assert!(result.symbols.is_empty());
        // hover_text is None for references action.
        assert!(result.hover_text.is_none());
    }

    /// B3b — Locations missing `uri` field are silently dropped.
    /// (Gap: CC logs these as errors; OC silently filters.)
    #[test]
    fn spec_b3_locations_missing_uri_silently_dropped() {
        let data = json!([
            {
                "uri": "file:///valid.rs",
                "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}
            },
            {
                "range": {"start": {"line": 5, "character": 0}, "end": {"line": 5, "character": 1}}
                // no "uri" field
            }
        ]);
        let locs = parse_locations(Some(&data));
        // OC: filter_map on `uri` drops the entry with no uri field.
        assert_eq!(locs.len(), 1, "OC silently drops locations missing 'uri'");
        assert_eq!(locs[0].uri, "file:///valid.rs");
    }

    // Spec B4: documentSymbols — nested symbol tree
    // ──────────────────────────────────────────────

    /// B4a — OC enforces `MAX_SYMBOL_DEPTH` = 20. A tree deeper than 20 levels
    /// is truncated: children at depth ≥ 20 are returned as empty.
    #[test]
    fn spec_b4_symbol_depth_limit_at_20() {
        // Build a chain of 22 nested symbols. Each wraps the next as its child.
        fn make_nested(depth: usize) -> serde_json::Value {
            if depth == 0 {
                return json!({
                    "name": "leaf",
                    "kind": 12,
                    "range": {"start": {"line": depth as u64, "character": 0},
                              "end":   {"line": depth as u64, "character": 1}}
                });
            }
            json!({
                "name": format!("node_{depth}"),
                "kind": 2,
                "range": {"start": {"line": depth as u64, "character": 0},
                          "end":   {"line": depth as u64, "character": 1}},
                "children": [make_nested(depth - 1)]
            })
        }

        // Nest 22 levels deep; OC truncates at depth 20.
        let root = json!([make_nested(22)]);
        let syms = parse_symbols(Some(&root));
        assert_eq!(syms.len(), 1, "root symbol present");

        // Walk down the tree counting reachable levels.
        let mut level = 0usize;
        let mut current = &syms[0];
        loop {
            level += 1;
            if current.children.is_empty() {
                break;
            }
            current = &current.children[0];
        }
        // With MAX_SYMBOL_DEPTH = 20 the tree is cut before depth 20,
        // so we can reach at most 20 levels before children become empty.
        assert!(
            level <= MAX_SYMBOL_DEPTH,
            "OC truncates at MAX_SYMBOL_DEPTH={MAX_SYMBOL_DEPTH}; reached {level}"
        );
    }

    /// B4b — All 26 LSP `SymbolKind` integers map to their canonical names.
    /// Pinning the full mapping so renames are caught as regressions.
    #[test]
    fn spec_b4_all_26_symbol_kind_names() {
        let expected: &[(u64, &str)] = &[
            (1, "File"),
            (2, "Module"),
            (3, "Namespace"),
            (4, "Package"),
            (5, "Class"),
            (6, "Method"),
            (7, "Property"),
            (8, "Field"),
            (9, "Constructor"),
            (10, "Enum"),
            (11, "Interface"),
            (12, "Function"),
            (13, "Variable"),
            (14, "Constant"),
            (15, "String"),
            (16, "Number"),
            (17, "Boolean"),
            (18, "Array"),
            (19, "Object"),
            (20, "Key"),
            (21, "Null"),
            (22, "EnumMember"),
            (23, "Struct"),
            (24, "Event"),
            (25, "Operator"),
            (26, "TypeParameter"),
            (0, "Unknown"),
            (27, "Unknown"),
            (999, "Unknown"),
        ];
        for (kind, name) in expected {
            assert_eq!(
                symbol_kind_name(*kind),
                *name,
                "SymbolKind {kind} should map to {name}"
            );
        }
    }

    /// B4c — OC outputs symbols as a Vec<LspSymbol> (JSON-serialisable struct),
    /// NOT as a pre-formatted human-readable text tree.
    /// Gap: CC formats as indented text; OC returns raw structured data.
    #[test]
    fn spec_b4_output_is_structured_not_formatted_text_gap() {
        let resp = json!({
            "result": [{
                "name": "MyFn",
                "kind": 12,
                "range": {"start": {"line": 0, "character": 0}, "end": {"line": 3, "character": 1}}
            }]
        });
        let result = parse_lsp_response(LspAction::DocumentSymbols, "test.rs", &resp);
        // OC: result.symbols is populated; result is serialised to JSON by execute_lsp.
        assert_eq!(result.symbols.len(), 1);
        assert_eq!(result.symbols[0].name, "MyFn");
        // No hover_text or results are populated for this action.
        assert!(result.results.is_empty());
        assert!(result.hover_text.is_none());
        // The action label OC sets for documentSymbols.
        assert_eq!(result.action, "documentSymbols");
    }

    // Spec B5: Unknown action string → explicit error listing valid actions
    // ─────────────────────────────────────────────────────────────────────

    /// B5a — Unknown actions surface a list of every supported action.
    /// Crosslink #645 (closed) added the five call-hierarchy / workspace
    /// ops, so the listed-actions set is now 9 (CC parity).
    #[test]
    fn spec_b5_unknown_action_exact_error_message() {
        // Pick an unambiguously bogus action; this branch is hit before
        // the server-availability probe so test environment doesn't matter.
        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert(
            "file_path".to_string(),
            Value::String("test.rs".to_string()),
        );
        args.insert(
            "action".to_string(),
            Value::String("definitely_not_a_real_action".to_string()),
        );
        let (msg, is_err) = execute_lsp(test_run(), &args);
        assert!(is_err);
        assert!(
            msg.contains("Unknown LSP action"),
            "unexpected message: {msg}"
        );
        // Every supported action must appear in the error listing — pins the
        // CC-parity surface added by crosslink #645.
        for op in [
            "goToDefinition",
            "findReferences",
            "hover",
            "documentSymbols",
            "workspaceSymbol",
            "goToImplementation",
            "prepareCallHierarchy",
            "incomingCalls",
            "outgoingCalls",
        ] {
            assert!(msg.contains(op), "error should list `{op}`; got: {msg}");
        }
    }

    /// B5b — The five new actions are now recognised (crosslink #645 closed).
    /// They will fail downstream when the language server is not installed,
    /// but the error must no longer be "Unknown LSP action". The probe is
    /// driven by file extension; we use `.rs` so the action lookup runs even
    /// if `rust-analyzer` is not installed — the failure point shifts to
    /// the server-availability check, which carries different wording.
    #[test]
    fn five_new_actions_recognised() {
        let new_ops = [
            "workspaceSymbol",
            "goToImplementation",
            "prepareCallHierarchy",
            "incomingCalls",
            "outgoingCalls",
        ];
        for op in new_ops {
            let mut args: HashMap<String, Value> = HashMap::new();
            args.insert(
                "file_path".to_string(),
                Value::String("test.rs".to_string()),
            );
            args.insert("action".to_string(), Value::String(op.to_string()));
            let (msg, _is_err) = execute_lsp(test_run(), &args);
            // The action MUST be recognised now (crosslink #645). The call
            // may still fail downstream when rust-analyzer is missing, but
            // the failure mode MUST NOT be "Unknown LSP action".
            assert!(
                !msg.contains("Unknown LSP action"),
                "op={op} should be recognised but got: {msg}"
            );
        }
    }

    /// `parse_lsp_response` correctly routes each new action through its
    /// parser without going via the network.
    #[test]
    fn parse_response_workspace_symbol() {
        let resp = json!({
            "id": 2,
            "result": [
                {
                    "name": "Foo",
                    "kind": 23,
                    "location": {
                        "uri": "file:///a.rs",
                        "range": {"start": {"line": 0, "character": 0},
                                  "end":   {"line": 0, "character": 3}}
                    }
                }
            ]
        });
        let result = parse_lsp_response(LspAction::WorkspaceSymbol, "test.rs", &resp);
        assert_eq!(result.action, "workspaceSymbol");
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].uri, "file:///a.rs");
    }

    #[test]
    fn parse_response_prepare_call_hierarchy() {
        let resp = json!({
            "id": 2,
            "result": [
                {
                    "name": "foo",
                    "uri": "file:///a.rs",
                    "selectionRange": {
                        "start": {"line": 4, "character": 0},
                        "end":   {"line": 4, "character": 3}
                    },
                    "range": {
                        "start": {"line": 4, "character": 0},
                        "end":   {"line": 6, "character": 1}
                    }
                }
            ]
        });
        let result = parse_lsp_response(LspAction::PrepareCallHierarchy, "test.rs", &resp);
        assert_eq!(result.action, "prepareCallHierarchy");
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].line, 5); // 4 + 1 (1-based)
        assert_eq!(result.results[0].character, 1); // 0 + 1 (1-based)
        assert_eq!(result.results[0].end_character, Some(4));
        assert_eq!(result.results[0].preview.as_deref(), Some("foo"));
    }

    #[test]
    fn parse_response_incoming_outgoing_calls() {
        let resp = json!({
            "id": 2,
            "result": [
                {
                    "from": {
                        "name": "caller",
                        "uri": "file:///caller.rs",
                        "selectionRange": {
                            "start": {"line": 2, "character": 0},
                            "end":   {"line": 2, "character": 6}
                        },
                        "range": {
                            "start": {"line": 2, "character": 0},
                            "end":   {"line": 5, "character": 1}
                        }
                    },
                    "fromRanges": []
                }
            ]
        });
        let result = parse_lsp_response(LspAction::IncomingCalls, "test.rs", &resp);
        assert_eq!(result.action, "incomingCalls");
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].uri, "file:///caller.rs");
        assert_eq!(result.results[0].character, 1);
        assert_eq!(result.results[0].end_character, Some(7));

        let resp_out = json!({
            "id": 2,
            "result": [
                {
                    "to": {
                        "name": "callee",
                        "uri": "file:///callee.rs",
                        "selectionRange": {
                            "start": {"line": 9, "character": 0},
                            "end":   {"line": 9, "character": 6}
                        },
                        "range": {
                            "start": {"line": 9, "character": 0},
                            "end":   {"line": 12, "character": 1}
                        }
                    },
                    "fromRanges": []
                }
            ]
        });
        let result_out = parse_lsp_response(LspAction::OutgoingCalls, "test.rs", &resp_out);
        assert_eq!(result_out.action, "outgoingCalls");
        assert_eq!(result_out.results.len(), 1);
        assert_eq!(result_out.results[0].uri, "file:///callee.rs");
        assert_eq!(result_out.results[0].character, 1);
        assert_eq!(result_out.results[0].end_character, Some(7));
    }

    // Spec B6: Server crash mid-call → explicit error, not hang
    // ──────────────────────────────────────────────────────────

    /// B6a — `read_lsp_response` returns `Err` after exhausting 100 messages
    /// without finding the expected id. This is the OC equivalent of the
    /// "did not respond" path. CC has health-check + retry; OC has neither.
    /// This test drives the function with a reader that yields only mismatched
    /// responses (wrong id), verifying the 100-message limit fires.
    #[test]
    fn spec_b6_read_lsp_response_errors_after_100_mismatches() {
        use std::io::Cursor;

        // Build 101 LSP messages all with id=99 (not the expected id=1).
        let mut bytes = Vec::new();
        for _ in 0..101u8 {
            let body = r#"{"jsonrpc":"2.0","id":99,"result":null}"#;
            let header = format!("Content-Length: {}\r\n\r\n", body.len());
            bytes.extend_from_slice(header.as_bytes());
            bytes.extend_from_slice(body.as_bytes());
        }

        let cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(cursor);

        // OC loops up to 100 messages then returns Err.
        let result = read_lsp_response(&mut reader, 1);
        assert!(
            result.is_err(),
            "expected Err after 100 mismatched messages"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("100"),
            "error should mention the 100-message limit; got: {msg}"
        );
    }

    /// B6b — `read_lsp_response` returns `Err` when the underlying reader
    /// returns zero bytes (simulates a server process that has exited/crashed).
    /// OC has no health-check before send; crash is detected only during read.
    /// Gap #636 closed: OC now errors on EOF and separately bounds silent
    /// open-pipe reads with `LspDeadlineReader`.
    #[test]
    fn spec_b6_read_lsp_response_errors_on_empty_stream_gap636() {
        use std::io::Cursor;

        // Empty reader simulates a server that has closed its stdout.
        let cursor = Cursor::new(Vec::<u8>::new());
        let mut reader = BufReader::new(cursor);

        let result = read_lsp_response(&mut reader, 1);
        // OC: read_line on empty stream returns 0 bytes → content_length stays 0
        // → Err("No content-length in response") or similar.
        assert!(result.is_err(), "empty stream should produce an error");
    }

    #[test]
    fn rustup_proxy_error_is_reported_as_missing_rust_analyzer_component() {
        let msg = format_lsp_error(
            "rust-analyzer",
            "initialize failed: No content-length in response\nServer stderr: error: Unknown binary 'rust-analyzer' in official toolchain",
        );

        assert!(msg.contains("rustup component add rust-analyzer"));
        assert!(!msg.contains("No content-length"));
    }

    /// B6c — Production child stdout reads are deadline-bounded even when the
    /// server keeps stdout open but never writes a byte. This is the actual hang
    /// mode that `Cursor::new(Vec::new())` cannot model because an empty cursor
    /// returns EOF immediately.
    #[cfg(unix)]
    #[test]
    fn spec_b6_lsp_deadline_reader_times_out_on_silent_open_stdout() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn silent child");
        let stdout = child.stdout.take().expect("child stdout should be piped");
        let (stdout, _timeout) =
            LspDeadlineReader::spawn(stdout, std::time::Duration::from_millis(50));
        let mut reader = BufReader::new(stdout);

        let started = std::time::Instant::now();
        let result = read_lsp_response(&mut reader, 1);

        let _ = child.kill();
        let _ = child.wait();

        assert!(result.is_err(), "silent stdout should time out");
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "deadline reader should fail quickly, elapsed={elapsed:?}"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("timed out waiting for LSP stdout"),
            "error should name the stdout timeout; got: {msg}"
        );
    }

    // Spec B1-det: detect_language_server — full extension table
    // ───────────────────────────────────────────────────────────

    /// Pin the full extension→binary mapping table so additions/removals
    /// are caught as regressions.
    #[test]
    fn spec_detect_language_server_full_extension_table() {
        // (extension suffix, expected binary, expected first arg if any)
        let cases: &[(&str, &str, Option<&str>)] = &[
            ("file.rs", "rust-analyzer", None),
            ("file.ts", "typescript-language-server", Some("--stdio")),
            ("file.tsx", "typescript-language-server", Some("--stdio")),
            ("file.js", "typescript-language-server", Some("--stdio")),
            ("file.jsx", "typescript-language-server", Some("--stdio")),
            ("file.py", "pylsp", None),
            ("file.go", "gopls", Some("serve")),
            ("file.c", "clangd", None),
            ("file.cpp", "clangd", None),
            ("file.h", "clangd", None),
            ("file.hpp", "clangd", None),
            ("file.java", "jdtls", None),
            ("file.rb", "solargraph", Some("stdio")),
        ];
        for (path, binary, first_arg) in cases {
            let (cmd, args) =
                detect_language_server(path).unwrap_or_else(|| panic!("no server for {path}"));
            assert_eq!(cmd, *binary, "extension of {path}");
            match first_arg {
                Some(arg) => assert_eq!(args.first().copied(), Some(*arg), "first arg for {path}"),
                None => assert!(args.is_empty(), "expected no args for {path}, got {args:?}"),
            }
        }
    }

    /// Pin: extensions not in the table return None.
    #[test]
    fn spec_detect_language_server_unknown_extensions_return_none() {
        for path in &["file.md", "file.txt", "file.json", "file.yaml", "noext"] {
            assert!(
                detect_language_server(path).is_none(),
                "expected None for {path}"
            );
        }
    }

    // ── Fix #355: ChildGuard, wait_for_readiness, capture_stderr ─────────────

    /// Fix #355-zombie: `ChildGuard::drop` kills and reaps a running child.
    ///
    /// Forensic evidence: original `run_lsp_request` called `child.wait()`
    /// only at line 229 (after the shutdown sequence).  Any `?`-early-return
    /// at line 174 (`read_lsp_response` for initialize) or line 224 (for the
    /// actual request) bypassed that call, leaving an un-reaped zombie on Unix.
    /// `ChildGuard` wraps the child in a Drop impl that always kills+waits.
    #[test]
    fn fix355_child_guard_drop_reaps_child() {
        // Spawn a long-running child (sleep 60) so we can verify it is alive
        // before the guard drops, and dead after.
        let child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn sleep — needs Unix");

        let pid = child.id();

        {
            let _guard = ChildGuard::new(test_run(), child);
            // Child is alive inside the guard scope.
            // /proc/<pid> exists on Linux while the process lives.
            assert!(
                std::path::Path::new(&format!("/proc/{pid}")).exists(),
                "child should be alive while guard is held"
            );
        } // guard drops here → kills + waits

        // After drop the process should be gone.  Give the OS a brief moment
        // to finalize the reap (wait() in Drop is synchronous, so this should
        // be immediate, but we add a tiny yield for robustness).
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "child should be reaped after ChildGuard drops (zombie fix #355)"
        );
    }

    /// Fix #355-sleep: `wait_for_readiness` returns Ok when the probe response
    /// (id=1001) appears in the stream, possibly after skipped notifications.
    ///
    /// Forensic evidence: original line 191 was
    ///   `std::thread::sleep(std::time::Duration::from_millis(500));`
    /// This is a pure guess — too short for cold rust-analyzer (10-60 s index),
    /// wasted latency for fast servers.  The replacement sends a documentSymbol
    /// probe (id=1001) and returns as soon as the server replies.
    #[test]
    fn fix355_wait_for_readiness_returns_ok_after_probe_response() {
        use std::io::Cursor;

        // Simulate: two server-initiated notifications, then the probe reply.
        let mut bytes = Vec::new();

        // Notification 1 (no id) — window/logMessage
        let notif1 = r#"{"jsonrpc":"2.0","method":"window/logMessage","params":{"type":4,"message":"loading"}}"#;
        bytes.extend_from_slice(format!("Content-Length: {}\r\n\r\n", notif1.len()).as_bytes());
        bytes.extend_from_slice(notif1.as_bytes());

        // Notification 2 — publishDiagnostics (no id)
        let notif2 = r#"{"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{"uri":"file:///x.rs","diagnostics":[]}}"#;
        bytes.extend_from_slice(format!("Content-Length: {}\r\n\r\n", notif2.len()).as_bytes());
        bytes.extend_from_slice(notif2.as_bytes());

        // Probe response (id=1001) — documentSymbol reply with empty array
        let probe_reply = r#"{"jsonrpc":"2.0","id":1001,"result":[]}"#;
        bytes
            .extend_from_slice(format!("Content-Length: {}\r\n\r\n", probe_reply.len()).as_bytes());
        bytes.extend_from_slice(probe_reply.as_bytes());

        let cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(cursor);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        let result = wait_for_readiness(&mut reader, deadline);
        assert!(
            result.is_ok(),
            "should return Ok after skipping 2 notifications and finding id=1001; got: {result:?}"
        );
    }

    /// Fix #355-sleep-timeout: `wait_for_readiness` returns Err when the deadline
    /// elapses before the probe response arrives.
    #[test]
    fn fix355_wait_for_readiness_times_out_when_no_probe_response() {
        use std::io::Cursor;

        // Only send a notification with a wrong id — probe reply never arrives.
        let wrong_id = r#"{"jsonrpc":"2.0","id":9999,"result":[]}"#;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(format!("Content-Length: {}\r\n\r\n", wrong_id.len()).as_bytes());
        bytes.extend_from_slice(wrong_id.as_bytes());
        // Then EOF — simulates server that never answers the probe.

        let cursor = Cursor::new(bytes);
        let mut reader = BufReader::new(cursor);
        // Already-expired deadline so the check fires immediately.
        let deadline = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_millis(1))
            .unwrap_or_else(std::time::Instant::now);

        let result = wait_for_readiness(&mut reader, deadline);
        assert!(
            result.is_err(),
            "should return Err when deadline is already past"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("timeout"),
            "error should mention timeout; got: {msg}"
        );
    }

    /// Fix #355-stderr: `capture_stderr` drains bytes into a ring buffer and
    /// truncates to the last 1024 bytes when more arrive.
    #[test]
    fn fix355_capture_stderr_ring_buffer_truncates_to_1024() {
        // Spawn a child that writes 2048 bytes to stderr then exits.
        let mut child = Command::new("sh")
            .args(["-c", "printf '%02048d' 0 >&2; exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn sh");

        let stderr_pipe = child.stderr.take().expect("no stderr");
        let buf = capture_stderr(stderr_pipe);

        // Wait for the child to finish writing.
        let _ = child.wait();

        // Give the drain thread a moment to flush the ring buffer.
        std::thread::sleep(std::time::Duration::from_millis(100));

        let guard = buf.lock().unwrap();
        let len = guard.len();
        let is_empty = guard.is_empty();
        drop(guard);
        assert!(
            len <= 1024,
            "ring buffer should be capped at 1024 bytes; actual len = {len}"
        );
        assert!(
            !is_empty,
            "ring buffer should not be empty after writing 2048 bytes"
        );
    }

    // ── Fix #647: didOpen deduplication via process-wide registry ────────────

    /// #647-a — `mark_opened` returns true the first time and false the
    /// second time for the same `(server_cmd, path)` pair, and the registry
    /// reflects the open state in between.  Parity with CC `LSPServerManager
    /// .ts:64,277` (`isFileOpen`).
    #[test]
    fn fix647_mark_opened_dedupes_repeated_calls() {
        let server = "rust-analyzer-test-647a-unique";
        let path = PathBuf::from("/tmp/openclaudia-647a-unique.rs");
        // Defensive cleanup so a previously aborted run can't poison this one.
        // We use process-unique (server, path) so we never need a global
        // registry reset (which would race with other parallel tests).
        let _ = mark_closed(test_run(), server, &path);

        assert!(!is_marked_open(test_run(), server, &path), "starts empty");
        assert!(
            mark_opened(test_run(), server, &path),
            "first mark_opened should claim the slot"
        );
        assert!(
            is_marked_open(test_run(), server, &path),
            "registry should report the file as open"
        );
        assert!(
            !mark_opened(test_run(), server, &path),
            "second mark_opened should report already-open (skip didOpen)"
        );

        // didClose flips the flag back.
        assert!(
            mark_closed(test_run(), server, &path),
            "first close removes the entry"
        );
        assert!(
            !is_marked_open(test_run(), server, &path),
            "registry now clear"
        );
        assert!(
            !mark_closed(test_run(), server, &path),
            "closing an already-closed file is a no-op"
        );

        // After close, mark_opened claims a fresh slot again.
        assert!(
            mark_opened(test_run(), server, &path),
            "post-close mark_opened claims a fresh slot"
        );
        // Final cleanup so re-runs start clean.
        let _ = mark_closed(test_run(), server, &path);
    }

    #[test]
    fn open_file_dedup_does_not_cross_run_generations() {
        let root = tempfile::tempdir_in(".").expect("foreign LSP run root");
        let foreign =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root.path())
                .working_directory(root.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::new())
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(false)
                .secrets(false)
                .provider("lsp-open-file-isolation-test")
                .build()
                .expect("explicit foreign LSP run");
        let server = "rust-analyzer-s019-run-isolation";
        let path = PathBuf::from("/tmp/openclaudia-s019-shared.rs");

        assert!(mark_opened(test_run(), server, &path));
        assert!(
            mark_opened(&foreign, server, &path),
            "a second run owns a different server/file dedup namespace"
        );
        assert!(mark_closed(test_run(), server, &path));
        assert!(
            is_marked_open(&foreign, server, &path),
            "closing the first run must not clear the second run's slot"
        );
        assert!(mark_closed(&foreign, server, &path));
    }

    /// #647-b — `OpenFileGuard::drop` rolls back the dedup entry when commit
    /// is never called, preventing leaked slots from poisoning future calls
    /// after a `?`-early-return inside `run_lsp_request`.
    #[test]
    fn fix647_open_file_guard_drop_rolls_back_uncommitted_slot() {
        let server = "rust-analyzer-test-647b-unique";
        let path = PathBuf::from("/tmp/openclaudia-647b-unique.rs");
        let _ = mark_closed(test_run(), server, &path);

        // Simulate the prologue inside run_lsp_request.
        let we_opened = mark_opened(test_run(), server, &path);
        assert!(we_opened);
        assert!(is_marked_open(test_run(), server, &path));

        {
            let _guard = OpenFileGuard::new(test_run(), server, &path, we_opened);
            // …imagine `?` returns here without commit…
        }

        assert!(
            !is_marked_open(test_run(), server, &path),
            "Drop must release the slot when commit() was never called (fix #647)"
        );
    }

    /// #647-c — `OpenFileGuard::commit` releases the slot exactly once and
    /// is idempotent under double-call (defensive against future
    /// refactors).
    #[test]
    fn fix647_open_file_guard_commit_is_idempotent() {
        let server = "rust-analyzer-test-647c-unique";
        let path = PathBuf::from("/tmp/openclaudia-647c-unique.rs");
        let _ = mark_closed(test_run(), server, &path);

        let we_opened = mark_opened(test_run(), server, &path);
        assert!(we_opened);
        let mut guard = OpenFileGuard::new(test_run(), server, &path, we_opened);

        guard.commit();
        assert!(
            !is_marked_open(test_run(), server, &path),
            "first commit releases"
        );
        guard.commit();
        assert!(
            !is_marked_open(test_run(), server, &path),
            "second commit is a no-op (no panic, no resurrection)"
        );
        // Drop on `guard` after this point must also be a no-op.
        drop(guard);
        assert!(!is_marked_open(test_run(), server, &path));
    }

    // ── Fix #648: 10 MiB file-size guard before LSP analysis ─────────────────

    /// #648-a — A file larger than `LSP_MAX_FILE_SIZE` (10 MiB) is rejected
    /// with a clear "too large" error before any server is spawned.  Parity
    /// with CC `LSPTool.ts:53,264-269`.
    #[test]
    fn fix648_oversized_file_is_rejected_before_server_spawn() {
        use std::io::Write as _;
        let tmp = tempfile::Builder::new()
            .suffix(".rs")
            .tempfile_in(".")
            .expect("project-local tempfile");
        // Write 10 MiB + 1 byte so we strictly exceed the limit.
        let payload = vec![b'a'; usize::try_from(LSP_MAX_FILE_SIZE).unwrap() + 1];
        {
            let mut f = std::fs::File::create(tmp.path()).expect("create");
            f.write_all(&payload).expect("write payload");
        }

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert(
            "file_path".to_string(),
            Value::String(tmp.path().to_string_lossy().into_owned()),
        );
        args.insert("action".to_string(), Value::String("hover".to_string()));

        let (msg, is_err) = execute_lsp(test_run(), &args);
        assert!(is_err, "oversized file must produce an error");
        // The error must be the size-guard message, not a server-not-found
        // or unknown-action message, regardless of whether rust-analyzer is
        // present on this host.
        if msg.contains("LSP server unavailable") {
            // Server-availability gate fires first when rust-analyzer is
            // absent — that path is exercised by fix650 tests below.  When
            // it does fire we cannot also assert the size-guard path; skip
            // the rest of the assertion in that environment.
            return;
        }
        assert!(
            msg.contains("File too large for LSP analysis"),
            "expected size-guard message; got: {msg}"
        );
        assert!(
            msg.contains("10 MiB"),
            "error should name the 10 MiB limit; got: {msg}"
        );
    }

    /// #648-b — A file exactly at the limit is accepted (boundary check):
    /// the size-guard must not reject `len == LSP_MAX_FILE_SIZE`, only
    /// strictly greater.  We can't verify a full LSP run here without
    /// rust-analyzer, so we assert the rejection path is NOT taken — any
    /// other error (server missing, etc.) is acceptable.
    #[test]
    fn fix648_file_at_limit_is_not_rejected_by_size_guard() {
        use std::io::Write as _;
        let tmp = tempfile::Builder::new()
            .suffix(".rs")
            .tempfile_in(".")
            .expect("project-local tempfile");
        let payload = vec![b'a'; usize::try_from(LSP_MAX_FILE_SIZE).unwrap()];
        {
            let mut f = std::fs::File::create(tmp.path()).expect("create");
            f.write_all(&payload).expect("write payload");
        }

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert(
            "file_path".to_string(),
            Value::String(tmp.path().to_string_lossy().into_owned()),
        );
        args.insert("action".to_string(), Value::String("hover".to_string()));

        let (msg, _is_err) = execute_lsp(test_run(), &args);
        // The size-guard message must NOT appear for a file at the limit.
        assert!(
            !msg.contains("File too large for LSP analysis"),
            "size-guard should accept len == LSP_MAX_FILE_SIZE; got: {msg}"
        );
    }

    // ── Fix #650: Availability gate via is_lsp_connected() ───────────────────

    /// #650-a — `is_lsp_connected` returns false for languages whose servers
    /// are guaranteed-not-installed (we use an unknown identifier so the
    /// resolver short-circuits).  Parity with CC `LSPTool.ts:137-139`.
    #[test]
    fn fix650_is_lsp_connected_false_for_unknown_language() {
        // An identifier that maps to no known server must report disconnected.
        assert!(!is_lsp_connected(test_run(), "brainfuck"));
        assert!(!is_lsp_connected(test_run(), ""));
        assert!(!is_lsp_connected(test_run(), "xyz"));
    }

    /// #650-b — When a real server is genuinely absent, `execute_lsp`
    /// returns the "LSP server unavailable" error naming the language and
    /// binary plus the PATH hint.  We probe with `.java` (jdtls), which is
    /// effectively never installed in CI; if a host *does* happen to have
    /// jdtls on PATH the test short-circuits to a vacuous pass rather than
    /// mutating process-global PATH (which would race with other parallel
    /// tests that spawn external commands).
    #[test]
    fn fix650_execute_lsp_gates_on_missing_server_with_language_hint() {
        // Probe whether jdtls is installed on this host.  If yes, skip the
        // strict assertion (the gate doesn't fire); we still cover the
        // happy "gate fires" path via is_lsp_connected(test_run(), "brainfuck") in
        // fix650_is_lsp_connected_false_for_unknown_language.
        if is_lsp_connected(test_run(), "java") {
            return;
        }

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert(
            "file_path".to_string(),
            Value::String("test_file.java".to_string()),
        );
        args.insert("action".to_string(), Value::String("hover".to_string()));

        let (msg, is_err) = execute_lsp(test_run(), &args);
        assert!(is_err, "missing server must produce an error");
        assert!(
            msg.contains("LSP server unavailable for java"),
            "error should name the language; got: {msg}"
        );
        assert!(
            msg.contains("jdtls"),
            "error should name the server binary; got: {msg}"
        );
        assert!(
            msg.contains("not found on the run-bound PATH"),
            "error should identify the immutable executable search path; got: {msg}"
        );
    }

    /// #650-c — `resolve_language_server` accepts both bare language names
    /// and extension forms (with or without leading dot), so the gate's
    /// input contract matches CC's broader API.
    #[test]
    fn fix650_resolve_language_server_accepts_name_and_extension() {
        assert_eq!(resolve_language_server("rust").unwrap().0, "rust-analyzer");
        assert_eq!(resolve_language_server("rs").unwrap().0, "rust-analyzer");
        assert_eq!(resolve_language_server(".rs").unwrap().0, "rust-analyzer");
        assert_eq!(resolve_language_server("python").unwrap().0, "pylsp");
        assert_eq!(resolve_language_server("py").unwrap().0, "pylsp");
        assert_eq!(
            resolve_language_server("typescript").unwrap().0,
            "typescript-language-server"
        );
        assert!(resolve_language_server("nonsense").is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn language_server_profile_cannot_read_host_or_create_socket() {
        let outside = tempfile::NamedTempFile::new().expect("host sentinel");
        std::fs::write(outside.path(), "lsp-secret").expect("sentinel");
        let root = tempfile::tempdir_in(".").expect("LSP project");
        let security = test_run_with_environment(root.path(), HashMap::new());
        let marker = security.private_temp_root().join("result");
        let script = format!(
            r#"
import errno, pathlib, socket
outside = pathlib.Path({outside:?})
marker = pathlib.Path({marker:?})
file_blocked = not outside.exists()
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    network_blocked = False
except OSError as error:
    network_blocked = error.errno in (errno.EPERM, errno.EACCES)
marker.write_text("confined" if file_blocked and network_blocked else "escaped")
"#,
            outside = outside.path().to_string_lossy(),
            marker = marker.to_string_lossy(),
        );
        let mut child = spawn_language_server(
            &security,
            "python3",
            &["-c", &script],
            security.working_directory(),
        )
        .expect("sandboxed language server");
        let status = child.wait().expect("language server probe");
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(&marker).expect("marker"),
            "confined"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn language_server_receives_exact_run_environment_grant() {
        let root = tempfile::tempdir_in(".").expect("LSP environment root");
        let run = test_run_with_environment(
            root.path(),
            HashMap::from([("S019_LSP_ENV".to_string(), "exact".to_string())]),
        );
        // LSP receives read-only source plus run-owned scratch for caches and
        // diagnostics; the test must not require writable source authority.
        let marker = run.private_temp_root().join("environment-result");
        let script = format!(
            r#"
import os, pathlib
pathlib.Path({marker:?}).write_text(
    os.environ.get("S019_LSP_ENV", "missing")
    + "|"
    + os.environ.get("S019_LSP_UNGRANTED", "missing")
)
"#,
            marker = marker.to_string_lossy(),
        );

        let mut child =
            spawn_language_server(&run, "python3", &["-c", &script], run.working_directory())
                .expect("sandboxed language server");
        let status = child.wait().expect("language server environment probe");

        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(marker).expect("environment marker"),
            "exact|missing"
        );
    }

    // ── #651: workspace/configuration + reverse-request handler ────────────

    /// `build_reverse_response` for `workspace/configuration` returns one
    /// `null` per requested scope item — server treats any mismatch as
    /// malformed.
    #[test]
    fn reverse_workspace_configuration_returns_per_item_nulls() {
        let params = json!({
            "items": [
                {"section": "rust-analyzer"},
                {"section": "rust-analyzer.cargo"},
                {"section": "rust-analyzer.checkOnSave"}
            ]
        });
        let reply = build_reverse_response(7, "workspace/configuration", Some(&params));
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["jsonrpc"], "2.0");
        let result = reply["result"].as_array().expect("result must be array");
        assert_eq!(result.len(), 3, "one null per requested scope");
        assert!(result.iter().all(serde_json::Value::is_null));
    }

    /// Missing / empty `items` is degenerate but must not panic — we return
    /// a single-element null array as a conservative default.
    #[test]
    fn reverse_workspace_configuration_handles_missing_items() {
        let reply = build_reverse_response(1, "workspace/configuration", None);
        assert_eq!(reply["result"].as_array().map(Vec::len), Some(1));
        let reply2 =
            build_reverse_response(2, "workspace/configuration", Some(&json!({"items": []})));
        assert_eq!(reply2["result"].as_array().map(Vec::len), Some(0));
    }

    /// Capability registration / progress create are accepted with a bare
    /// `null` result (the spec's "no-op acknowledgement").
    #[test]
    fn reverse_capability_methods_accept_silently() {
        for method in [
            "client/registerCapability",
            "client/unregisterCapability",
            "window/workDoneProgress/create",
        ] {
            let reply = build_reverse_response(42, method, None);
            assert_eq!(reply["id"], 42);
            assert!(
                reply["result"].is_null(),
                "{method} must reply with null result, got {reply}"
            );
            assert!(
                reply.get("error").is_none(),
                "{method} must not return error",
            );
        }
    }

    /// Unknown reverse-request methods get a JSON-RPC `MethodNotFound` so the
    /// server can fail fast instead of stalling.
    #[test]
    fn reverse_unknown_method_returns_method_not_found() {
        let reply = build_reverse_response(99, "telemetry/queryUserAgent", None);
        assert_eq!(reply["id"], 99);
        assert_eq!(reply["error"]["code"], -32601);
        assert!(reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("telemetry/queryUserAgent"));
    }
}

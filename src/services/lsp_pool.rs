//! Run-owned, stateful Language Server Protocol service.
//!
//! One manager belongs to one [`crate::tools::ToolRunContext`]. It pools an
//! initialized protocol session for each exact workspace/language/executable
//! configuration, serializes access to each server, owns document versions,
//! and invalidates opaque continuations whenever a document or server
//! generation changes.

use crate::plugins::manifest::LspServerConfig;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::io::{self, BufRead as _, BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;

const CLIENT_CAPABILITIES_VERSION: &str = "openclaudia-lsp-client-v1";
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_POLL: Duration = Duration::from_millis(250);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SCANNED_MESSAGES: usize = 100;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_HIERARCHY_ITEMS: usize = 128;
const MAX_HIERARCHY_ITEM_BYTES: usize = 256 * 1024;
const MAX_CONTINUATIONS_PER_SERVER: usize = 256;
const MAX_POOLED_SERVERS: usize = 8;

/// Default idle lifetime for a warm language server.
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_mins(5);

/// One enabled plugin language-server declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginLspServer {
    /// Stable plugin identity used in pool/config provenance.
    pub owner: String,
    /// Manifest language key.
    pub language: String,
    /// Preserved manifest configuration.
    pub config: LspServerConfig,
}

/// Request passed from the model-facing LSP tool to the stateful service.
#[derive(Clone, Debug)]
pub struct LspServiceRequest {
    pub language: String,
    pub document_path: PathBuf,
    pub document_uri: String,
    pub document_text: String,
    pub method: &'static str,
    pub params: Value,
    pub continuation_token: Option<String>,
}

/// Complete call-hierarchy item plus its service-owned continuation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LspCallHierarchyContinuation {
    pub continuation_token: String,
    pub item: Value,
}

/// Raw protocol result and the generations used to produce it.
#[derive(Clone, Debug)]
pub struct LspServiceResponse {
    pub response: Value,
    pub server_generation: u64,
    pub document_version: i32,
    pub continuations: Vec<LspCallHierarchyContinuation>,
}

/// Typed failures from the stateful LSP service.
#[derive(Debug, Error)]
pub enum LspServiceError {
    #[error("language server is unavailable for {language}: {detail}")]
    Unavailable { language: String, detail: String },
    #[error("plugin LSP configuration for {language} is invalid: {detail}")]
    InvalidConfiguration { language: String, detail: String },
    #[error("language server process failed: {0}")]
    Process(String),
    #[error("language server protocol failed: {0}")]
    Protocol(String),
    #[error("language server returned JSON-RPC error {code}: {message}")]
    Server { code: i64, message: String },
    #[error("LSP request was cancelled by the owning run")]
    Cancelled,
    #[error("call-hierarchy continuation is stale or does not belong to this server/document generation")]
    StaleContinuation,
    #[error("call-hierarchy result exceeds the bounded continuation limit: {0}")]
    ContinuationLimit(String),
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct LspPoolKey {
    run_id: String,
    capability_generation: u64,
    workspace: PathBuf,
    language: String,
    executable: PathBuf,
    executable_version: String,
    configuration_digest: String,
    client_capabilities: &'static str,
}

#[derive(Clone, Debug)]
struct ResolvedServerSpec {
    language: String,
    executable: PathBuf,
    args: Vec<String>,
    configuration_digest: String,
    executable_version: String,
}

#[derive(Clone, Debug)]
struct DocumentState {
    uri: String,
    language: String,
    version: i32,
    text: String,
}

#[derive(Clone, Debug)]
struct StoredContinuation {
    document_uri: String,
    document_version: i32,
    server_generation: u64,
    item: Value,
}

struct ServerSlot {
    generation: u64,
    live: Option<LiveServer>,
    documents: HashMap<PathBuf, DocumentState>,
    continuations: HashMap<String, StoredContinuation>,
    continuation_order: VecDeque<String>,
    last_used: Instant,
}

impl Default for ServerSlot {
    fn default() -> Self {
        Self {
            generation: 0,
            live: None,
            documents: HashMap::new(),
            continuations: HashMap::new(),
            continuation_order: VecDeque::new(),
            last_used: Instant::now(),
        }
    }
}

struct LiveServer {
    child: Child,
    stdin: ChildStdin,
    stdout: Option<BufReader<DeadlineReader>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_thread: Option<JoinHandle<()>>,
    next_request_id: u32,
    _registration: crate::tools::command::ActiveSandboxProcess,
}

impl LiveServer {
    fn request(
        &mut self,
        run: &crate::tools::ToolRunContext,
        method: &str,
        params: &Value,
    ) -> Result<Value, LspServiceError> {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).unwrap_or(2);
        write_request(&mut self.stdin, method, id, params)?;
        let stdout = self.stdout.as_mut().ok_or_else(|| {
            LspServiceError::Process("language server stdout is unavailable".to_string())
        })?;
        read_response(run, stdout, &mut self.stdin, id, RESPONSE_TIMEOUT)
            .map_err(|error| with_stderr(error, &self.stderr))
    }

    fn notify(&mut self, method: &str, params: &Value) -> Result<(), LspServiceError> {
        write_notification(&mut self.stdin, method, params)
    }

    fn is_healthy(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn shutdown(mut self, documents: &HashMap<PathBuf, DocumentState>) {
        for document in documents.values() {
            let _ = self.notify(
                "textDocument/didClose",
                &json!({"textDocument": {"uri": document.uri}}),
            );
        }
        let shutdown_id = self.next_request_id;
        let _ = write_request(&mut self.stdin, "shutdown", shutdown_id, &Value::Null);
        let no_cancel = crate::runtime::CancellationTree::new();
        if let Some(stdout) = self.stdout.as_mut() {
            let _ = read_response_with_cancellation(
                &no_cancel.root(),
                stdout,
                &mut self.stdin,
                shutdown_id,
                SHUTDOWN_TIMEOUT,
            );
        }
        let _ = self.notify("exit", &Value::Null);
        if !wait_with_timeout(&mut self.child, SHUTDOWN_TIMEOUT) {
            crate::tools::terminate_process_tree(self.child.id());
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        drop(self.stdout.take());
        join_reader(self.stdout_thread.take());
        join_reader(self.stderr_thread.take());
    }
}

impl Drop for LiveServer {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            crate::tools::terminate_process_tree(self.child.id());
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        drop(self.stdout.take());
        join_reader(self.stdout_thread.take());
        join_reader(self.stderr_thread.take());
    }
}

/// Per-run stateful LSP manager.
pub struct LspServerManager {
    entries: Mutex<HashMap<LspPoolKey, Arc<Mutex<ServerSlot>>>>,
    plugin_servers: Mutex<Vec<PluginLspServer>>,
    idle_ttl: Duration,
}

impl Default for LspServerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LspServerManager {
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_IDLE_TTL)
    }

    #[must_use]
    pub fn with_ttl(idle_ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            plugin_servers: Mutex::new(Vec::new()),
            idle_ttl,
        }
    }

    /// Replace enabled plugin declarations atomically.
    pub fn configure_plugins(&self, mut servers: Vec<PluginLspServer>) {
        servers.sort_by(|left, right| {
            (&left.language, &left.owner).cmp(&(&right.language, &right.owner))
        });
        let changed = {
            let mut current = lock(&self.plugin_servers);
            if *current == servers {
                false
            } else {
                *current = servers;
                true
            }
        };
        if changed {
            self.shutdown();
        }
    }

    /// Snapshot plugin registrations for a capability-derived child run.
    #[must_use]
    pub fn plugin_servers(&self) -> Vec<PluginLspServer> {
        lock(&self.plugin_servers).clone()
    }

    /// Execute one request against the correct warm server generation.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration, process, protocol, cancellation, or
    /// stale-continuation error when the request cannot complete safely.
    pub fn execute(
        &self,
        run: &crate::tools::ToolRunContext,
        request: &LspServiceRequest,
    ) -> Result<LspServiceResponse, LspServiceError> {
        if run.runtime().cancellation().is_cancelled() {
            return Err(LspServiceError::Cancelled);
        }
        let _ = self.reap_idle();
        let spec = self.resolve_server(run, &request.language)?;
        let key = pool_key(run, &spec);
        let slot = self.acquire_slot(key);
        let mut slot = lock(&slot);
        slot.last_used = Instant::now();
        ensure_live(run, &spec, &mut slot)?;
        let document_version = match synchronize_document(request, &mut slot) {
            Ok(version) => version,
            Err(error) => {
                invalidate_generation(&mut slot);
                return Err(error);
            }
        };
        let params = continuation_params(request, &slot, document_version)?;
        let response = slot
            .live
            .as_mut()
            .ok_or_else(|| LspServiceError::Process("server generation is absent".to_string()))?
            .request(run, request.method, &params);
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                if !matches!(error, LspServiceError::Server { .. }) {
                    invalidate_generation(&mut slot);
                }
                return Err(error);
            }
        };
        let continuations =
            store_hierarchy_continuations(request, &response, &mut slot, document_version)?;
        Ok(LspServiceResponse {
            response,
            server_generation: slot.generation,
            document_version,
            continuations,
        })
    }

    /// Whether this exact run can resolve a configured server for `language`.
    #[must_use]
    pub fn is_available(&self, run: &crate::tools::ToolRunContext, language: &str) -> bool {
        self.resolve_server(run, language).is_ok()
    }

    /// Resolve a language name or file extension through enabled plugin
    /// declarations first, then the built-in language table.
    ///
    /// # Errors
    ///
    /// Returns [`LspServiceError::InvalidConfiguration`] when multiple enabled
    /// plugins claim the same language or extension.
    pub fn language_for_input(
        &self,
        language_or_extension: &str,
    ) -> Result<Option<String>, LspServiceError> {
        let input = language_or_extension.trim().trim_start_matches('.');
        let matches = {
            let plugins = lock(&self.plugin_servers);
            plugins
                .iter()
                .filter(|server| {
                    server.language == input
                        || server
                            .config
                            .extensions
                            .iter()
                            .any(|extension| extension.trim().trim_start_matches('.') == input)
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        if matches.len() > 1 {
            return Err(LspServiceError::InvalidConfiguration {
                language: input.to_string(),
                detail: format!(
                    "multiple enabled plugins claim this language/extension: {}",
                    matches
                        .iter()
                        .map(|server| server.owner.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        if let Some(server) = matches.first() {
            return Ok(Some(server.language.clone()));
        }
        let builtin = normalized_language(input);
        Ok((!builtin.is_empty()).then(|| builtin.to_string()))
    }

    /// Number of warm protocol sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.entries).len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Gracefully reap idle sessions.
    #[must_use]
    pub fn reap_idle(&self) -> usize {
        let now = Instant::now();
        let stale = {
            let mut entries = lock(&self.entries);
            let keys = entries
                .iter()
                .filter_map(|(key, slot)| {
                    let last_used = lock(slot).last_used;
                    (now.saturating_duration_since(last_used) > self.idle_ttl).then(|| key.clone())
                })
                .collect::<Vec<_>>();
            let stale = keys
                .into_iter()
                .filter_map(|key| entries.remove(&key))
                .collect::<Vec<_>>();
            drop(entries);
            stale
        };
        let count = stale.len();
        for slot in stale {
            shutdown_slot(&mut lock(&slot));
        }
        count
    }

    /// Gracefully stop and reap every server owned by this run.
    pub fn shutdown(&self) {
        let slots = {
            let mut entries = lock(&self.entries);
            entries.drain().map(|(_, slot)| slot).collect::<Vec<_>>()
        };
        for slot in slots {
            shutdown_slot(&mut lock(&slot));
        }
    }

    fn acquire_slot(&self, key: LspPoolKey) -> Arc<Mutex<ServerSlot>> {
        let mut entries = lock(&self.entries);
        if let Some(slot) = entries.get(&key) {
            return Arc::clone(slot);
        }
        if entries.len() >= MAX_POOLED_SERVERS {
            let oldest = entries
                .iter()
                .min_by_key(|(_, slot)| lock(slot).last_used)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                if let Some(slot) = entries.remove(&oldest) {
                    shutdown_slot(&mut lock(&slot));
                }
            }
        }
        let slot = Arc::new(Mutex::new(ServerSlot::default()));
        entries.insert(key, Arc::clone(&slot));
        slot
    }

    fn resolve_server(
        &self,
        run: &crate::tools::ToolRunContext,
        language: &str,
    ) -> Result<ResolvedServerSpec, LspServiceError> {
        let plugins = lock(&self.plugin_servers);
        let matches = plugins
            .iter()
            .filter(|server| {
                server.language == language
                    || server.config.extensions.iter().any(|extension| {
                        normalized_language(extension) == language
                            || extension.trim_start_matches('.') == language
                    })
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(LspServiceError::InvalidConfiguration {
                language: language.to_string(),
                detail: format!(
                    "multiple enabled plugins claim this language: {}",
                    matches
                        .iter()
                        .map(|server| server.owner.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        let (command, args, configuration_digest) = if let Some(server) = matches.first() {
            validate_plugin_environment(run, server)?;
            (
                server.config.command.clone(),
                server.config.args.clone(),
                plugin_configuration_digest(server),
            )
        } else {
            let (command, args) =
                builtin_server(language).ok_or_else(|| LspServiceError::Unavailable {
                    language: language.to_string(),
                    detail: "no built-in or enabled plugin server is configured".to_string(),
                })?;
            (
                command.to_string(),
                args.iter().map(|arg| (*arg).to_string()).collect(),
                digest_parts([language, command].into_iter()),
            )
        };
        drop(plugins);
        let executable =
            run.resolve_executable(&command)
                .map_err(|error| LspServiceError::Unavailable {
                    language: language.to_string(),
                    detail: format!("'{command}' is not on the run-bound executable path: {error}"),
                })?;
        let executable_version = executable_fingerprint(&executable)?;
        Ok(ResolvedServerSpec {
            language: language.to_string(),
            executable,
            args,
            configuration_digest,
            executable_version,
        })
    }
}

impl Drop for LspServerManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn pool_key(run: &crate::tools::ToolRunContext, spec: &ResolvedServerSpec) -> LspPoolKey {
    LspPoolKey {
        run_id: run.run_id().to_string(),
        capability_generation: run.generation().get(),
        workspace: run.project_root().to_path_buf(),
        language: spec.language.clone(),
        executable: spec.executable.clone(),
        executable_version: spec.executable_version.clone(),
        configuration_digest: spec.configuration_digest.clone(),
        client_capabilities: CLIENT_CAPABILITIES_VERSION,
    }
}

fn ensure_live(
    run: &crate::tools::ToolRunContext,
    spec: &ResolvedServerSpec,
    slot: &mut ServerSlot,
) -> Result<(), LspServiceError> {
    if slot.live.as_mut().is_some_and(LiveServer::is_healthy) {
        return Ok(());
    }
    invalidate_generation(slot);
    slot.generation = slot.generation.checked_add(1).unwrap_or(1);
    let mut live = spawn_server(run, spec)?;
    for document in slot.documents.values() {
        live.notify(
            "textDocument/didOpen",
            &json!({
                "textDocument": {
                    "uri": document.uri,
                    "languageId": document.language,
                    "version": document.version,
                    "text": document.text,
                }
            }),
        )?;
    }
    slot.live = Some(live);
    Ok(())
}

fn synchronize_document(
    request: &LspServiceRequest,
    slot: &mut ServerSlot,
) -> Result<i32, LspServiceError> {
    let live = slot
        .live
        .as_mut()
        .ok_or_else(|| LspServiceError::Process("server generation is absent".to_string()))?;
    if let Some(document) = slot.documents.get_mut(&request.document_path) {
        if document.text != request.document_text {
            invalidate_document_continuations(
                &mut slot.continuations,
                &mut slot.continuation_order,
                &document.uri,
            );
            document.version = document.version.checked_add(1).ok_or_else(|| {
                LspServiceError::Protocol("document version space exhausted".to_string())
            })?;
            document.text.clone_from(&request.document_text);
            live.notify(
                "textDocument/didChange",
                &json!({
                    "textDocument": {"uri": document.uri, "version": document.version},
                    "contentChanges": [{"text": document.text}],
                }),
            )?;
        }
        return Ok(document.version);
    }
    let document = DocumentState {
        uri: request.document_uri.clone(),
        language: request.language.clone(),
        version: 1,
        text: request.document_text.clone(),
    };
    live.notify(
        "textDocument/didOpen",
        &json!({
            "textDocument": {
                "uri": document.uri,
                "languageId": document.language,
                "version": document.version,
                "text": document.text,
            }
        }),
    )?;
    slot.documents
        .insert(request.document_path.clone(), document);
    Ok(1)
}

fn continuation_params(
    request: &LspServiceRequest,
    slot: &ServerSlot,
    document_version: i32,
) -> Result<Value, LspServiceError> {
    let Some(token) = request.continuation_token.as_deref() else {
        return Ok(request.params.clone());
    };
    let continuation = slot
        .continuations
        .get(token)
        .ok_or(LspServiceError::StaleContinuation)?;
    let same_server_generation = continuation.server_generation == slot.generation;
    let same_document = continuation.document_uri == request.document_uri;
    let same_document_version = continuation.document_version == document_version;
    if !(same_server_generation && same_document && same_document_version) {
        return Err(LspServiceError::StaleContinuation);
    }
    Ok(json!({"item": continuation.item}))
}

fn store_hierarchy_continuations(
    request: &LspServiceRequest,
    response: &Value,
    slot: &mut ServerSlot,
    document_version: i32,
) -> Result<Vec<LspCallHierarchyContinuation>, LspServiceError> {
    let Some(results) = response.get("result").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let items = match request.method {
        "textDocument/prepareCallHierarchy" => results.iter().collect::<Vec<_>>(),
        "callHierarchy/incomingCalls" => results
            .iter()
            .filter_map(|edge| edge.get("from"))
            .collect::<Vec<_>>(),
        "callHierarchy/outgoingCalls" => results
            .iter()
            .filter_map(|edge| edge.get("to"))
            .collect::<Vec<_>>(),
        _ => return Ok(Vec::new()),
    };
    if items.len() > MAX_HIERARCHY_ITEMS {
        return Err(LspServiceError::ContinuationLimit(format!(
            "server returned {} items; maximum is {MAX_HIERARCHY_ITEMS}",
            items.len()
        )));
    }
    let mut output = Vec::with_capacity(items.len());
    for item in items {
        let encoded = serde_json::to_vec(item)
            .map_err(|error| LspServiceError::Protocol(error.to_string()))?;
        if encoded.len() > MAX_HIERARCHY_ITEM_BYTES {
            return Err(LspServiceError::ContinuationLimit(format!(
                "one item is {} bytes; maximum is {MAX_HIERARCHY_ITEM_BYTES}",
                encoded.len()
            )));
        }
        let token = continuation_token(
            &request.document_uri,
            document_version,
            slot.generation,
            &encoded,
        );
        while slot.continuation_order.len() >= MAX_CONTINUATIONS_PER_SERVER {
            if let Some(expired) = slot.continuation_order.pop_front() {
                slot.continuations.remove(&expired);
            }
        }
        slot.continuation_order.push_back(token.clone());
        slot.continuations.insert(
            token.clone(),
            StoredContinuation {
                document_uri: request.document_uri.clone(),
                document_version,
                server_generation: slot.generation,
                item: item.clone(),
            },
        );
        output.push(LspCallHierarchyContinuation {
            continuation_token: token,
            item: item.clone(),
        });
    }
    Ok(output)
}

fn continuation_token(uri: &str, version: i32, generation: u64, item: &[u8]) -> String {
    let nonce = uuid::Uuid::new_v4();
    let mut digest = Sha256::new();
    digest.update(uri.as_bytes());
    digest.update(version.to_le_bytes());
    digest.update(generation.to_le_bytes());
    digest.update(nonce.as_bytes());
    digest.update(item);
    format!("lspct_{}", URL_SAFE_NO_PAD.encode(digest.finalize()))
}

fn invalidate_generation(slot: &mut ServerSlot) {
    if let Some(live) = slot.live.take() {
        live.shutdown(&slot.documents);
    }
    slot.continuation_order.clear();
    slot.continuations.clear();
}

fn invalidate_document_continuations(
    continuations: &mut HashMap<String, StoredContinuation>,
    order: &mut VecDeque<String>,
    uri: &str,
) {
    let tokens = continuations
        .iter()
        .filter(|(_, stored)| stored.document_uri == uri)
        .map(|(token, _)| token.clone())
        .collect::<HashSet<_>>();
    order.retain(|token| !tokens.contains(token));
    for token in tokens {
        continuations.remove(&token);
    }
}

fn shutdown_slot(slot: &mut ServerSlot) {
    invalidate_generation(slot);
    slot.documents.clear();
}

fn spawn_server(
    run: &crate::tools::ToolRunContext,
    spec: &ResolvedServerSpec,
) -> Result<LiveServer, LspServiceError> {
    let args = spec.args.iter().map(OsString::from).collect::<Vec<_>>();
    let prepared = crate::tools::sandboxed_process_command(
        run,
        crate::tools::SandboxProfile::LanguageServer,
        spec.executable.as_os_str(),
        &args,
        run.project_root(),
    )
    .map_err(LspServiceError::Process)?;
    let (mut command, projection) = prepared.into_parts();
    if projection.is_some() {
        return Err(LspServiceError::Process(
            "language-server profile unexpectedly produced a writable projection".to_string(),
        ));
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| {
        LspServiceError::Process(format!(
            "cannot start {}: {error}",
            spec.executable.display()
        ))
    })?;
    let stdin = child.stdin.take().ok_or_else(|| {
        LspServiceError::Process("language server stdin is unavailable".to_string())
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        LspServiceError::Process("language server stdout is unavailable".to_string())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        LspServiceError::Process("language server stderr is unavailable".to_string())
    })?;
    let registration = crate::tools::command::ActiveSandboxProcess::register(run, child.id());
    let (stdout, stdout_thread) = DeadlineReader::spawn(stdout);
    let (stderr, stderr_thread) = capture_stderr(stderr);
    let mut live = LiveServer {
        child,
        stdin,
        stdout: Some(BufReader::new(stdout)),
        stdout_thread: Some(stdout_thread),
        stderr,
        stderr_thread: Some(stderr_thread),
        next_request_id: 2,
        _registration: registration,
    };
    let root_uri = url::Url::from_directory_path(run.project_root())
        .map_err(|()| {
            LspServiceError::Protocol("workspace path cannot form a file URI".to_string())
        })?
        .to_string();
    let init = live.request(
        run,
        "initialize",
        &json!({
            "processId": Value::Null,
            "rootUri": root_uri,
            "capabilities": {
                "workspace": {"workspaceFolders": true},
                "textDocument": {
                    "synchronization": {
                        "dynamicRegistration": false,
                        "willSave": false,
                        "willSaveWaitUntil": false,
                        "didSave": false
                    },
                    "callHierarchy": {"dynamicRegistration": false}
                }
            },
            "workspaceFolders": [{"uri": root_uri, "name": "workspace"}],
            "initializationOptions": Value::Null,
            "clientInfo": {"name": "OpenClaudia", "version": env!("CARGO_PKG_VERSION")}
        }),
    )?;
    if init.get("result").is_none() {
        return Err(LspServiceError::Protocol(
            "initialize response omitted result".to_string(),
        ));
    }
    live.notify("initialized", &json!({}))?;
    Ok(live)
}

fn builtin_server(language: &str) -> Option<(&'static str, &'static [&'static str])> {
    match language {
        "rust" => Some(("rust-analyzer", &[])),
        "typescript" | "typescriptreact" | "javascript" | "javascriptreact" => {
            Some(("typescript-language-server", &["--stdio"]))
        }
        "python" => Some(("pylsp", &[])),
        "go" => Some(("gopls", &["serve"])),
        "c" | "cpp" => Some(("clangd", &[])),
        "java" => Some(("jdtls", &[])),
        "ruby" => Some(("solargraph", &["stdio"])),
        _ => None,
    }
}

fn normalized_language(extension: &str) -> &'static str {
    match extension.trim().trim_start_matches('.') {
        "rs" | "rust" => "rust",
        "ts" | "typescript" => "typescript",
        "tsx" | "typescriptreact" => "typescriptreact",
        "js" | "javascript" => "javascript",
        "jsx" | "javascriptreact" => "javascriptreact",
        "py" | "python" => "python",
        "go" => "go",
        "c" => "c",
        "cpp" | "cc" | "cxx" | "h" | "hpp" => "cpp",
        "java" => "java",
        "rb" | "ruby" => "ruby",
        _ => "",
    }
}

fn validate_plugin_environment(
    run: &crate::tools::ToolRunContext,
    server: &PluginLspServer,
) -> Result<(), LspServiceError> {
    let invalid = server.config.env.keys().find(|name| {
        server
            .config
            .env
            .get(name)
            .is_some_and(|expected| run.environment_grants().get(name) != Some(expected))
    });
    if let Some(name) = invalid {
        return Err(LspServiceError::InvalidConfiguration {
            language: server.language.clone(),
            detail: format!(
                "plugin '{}' requests environment value '{name}' that is not an exact run grant",
                server.owner
            ),
        });
    }
    Ok(())
}

fn plugin_configuration_digest(server: &PluginLspServer) -> String {
    let mut parts = vec![
        server.owner.as_str(),
        server.language.as_str(),
        server.config.command.as_str(),
    ];
    parts.extend(server.config.args.iter().map(String::as_str));
    parts.extend(server.config.extensions.iter().map(String::as_str));
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    for (name, value_digest) in server.config.env.sorted_name_digests() {
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(value_digest.as_bytes());
        digest.update([0]);
    }
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn executable_fingerprint(path: &Path) -> Result<String, LspServiceError> {
    let metadata = path.metadata().map_err(|error| {
        LspServiceError::Process(format!(
            "cannot inspect language server executable '{}': {error}",
            path.display()
        ))
    })?;
    let modified = metadata
        .modified()
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path_text = path.as_os_str().to_string_lossy();
    let length = metadata.len().to_string();
    let modified = modified.to_string();
    Ok(digest_parts(
        [path_text.as_ref(), length.as_str(), modified.as_str()].into_iter(),
    ))
}

fn digest_parts<'a>(parts: impl Iterator<Item = &'a str>) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

enum ReadEvent {
    Chunk(Vec<u8>),
    Eof,
    Error(String),
}

struct DeadlineReader {
    rx: Receiver<ReadEvent>,
    pending: VecDeque<u8>,
    ended: bool,
}

impl DeadlineReader {
    fn spawn(mut reader: impl Read + Send + 'static) -> (Self, JoinHandle<()>) {
        let (tx, rx) = mpsc::sync_channel(16);
        let thread = thread::spawn(move || {
            let mut chunk = [0_u8; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => {
                        let _ = tx.send(ReadEvent::Eof);
                        break;
                    }
                    Ok(count) => {
                        if tx.send(ReadEvent::Chunk(chunk[..count].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(ReadEvent::Error(error.to_string()));
                        break;
                    }
                }
            }
        });
        (
            Self {
                rx,
                pending: VecDeque::new(),
                ended: false,
            },
            thread,
        )
    }
}

impl Read for DeadlineReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.pending.is_empty() {
                let count = output.len().min(self.pending.len());
                for (slot, byte) in output[..count].iter_mut().zip(self.pending.drain(..count)) {
                    *slot = byte;
                }
                return Ok(count);
            }
            if self.ended {
                return Ok(0);
            }
            match self.rx.recv_timeout(RESPONSE_POLL) {
                Ok(ReadEvent::Chunk(chunk)) => self.pending.extend(chunk),
                Ok(ReadEvent::Eof) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.ended = true;
                    return Ok(0);
                }
                Ok(ReadEvent::Error(error)) => {
                    self.ended = true;
                    return Err(io::Error::new(ErrorKind::BrokenPipe, error));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "LSP read poll timed out",
                    ));
                }
            }
        }
    }
}

fn read_response(
    run: &crate::tools::ToolRunContext,
    reader: &mut BufReader<DeadlineReader>,
    writer: &mut impl Write,
    expected_id: u32,
    timeout: Duration,
) -> Result<Value, LspServiceError> {
    read_response_with_cancellation(
        &run.runtime().cancellation(),
        reader,
        writer,
        expected_id,
        timeout,
    )
}

fn read_response_with_cancellation(
    cancellation: &crate::runtime::CancellationHandle,
    reader: &mut BufReader<DeadlineReader>,
    writer: &mut impl Write,
    expected_id: u32,
    timeout: Duration,
) -> Result<Value, LspServiceError> {
    let deadline = Instant::now() + timeout;
    for _ in 0..MAX_SCANNED_MESSAGES {
        let message = read_frame(reader, cancellation, deadline)?;
        if message.get("id").and_then(Value::as_u64) == Some(u64::from(expected_id)) {
            if let Some(error) = message.get("error") {
                return Err(LspServiceError::Server {
                    code: error.get("code").and_then(Value::as_i64).unwrap_or(-32_603),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("language server returned an unspecified error")
                        .to_string(),
                });
            }
            return Ok(message);
        }
        if let (Some(id), Some(method)) = (
            message.get("id").and_then(Value::as_u64),
            message.get("method").and_then(Value::as_str),
        ) {
            write_raw(writer, &reverse_response(id, method, message.get("params")))?;
        }
    }
    Err(LspServiceError::Protocol(format!(
        "response id {expected_id} was not received within {MAX_SCANNED_MESSAGES} messages"
    )))
}

fn read_frame(
    reader: &mut BufReader<DeadlineReader>,
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
) -> Result<Value, LspServiceError> {
    let mut content_length = None;
    loop {
        if cancellation.is_cancelled() {
            return Err(LspServiceError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(LspServiceError::Protocol(
                "timed out waiting for language server response".to_string(),
            ));
        }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                return Err(LspServiceError::Process(
                    "language server closed stdout".to_string(),
                ))
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::TimedOut => continue,
            Err(error) => return Err(LspServiceError::Protocol(error.to_string())),
        }
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            let length = value.trim().parse::<usize>().map_err(|error| {
                LspServiceError::Protocol(format!("invalid Content-Length: {error}"))
            })?;
            if length > MAX_FRAME_BYTES {
                return Err(LspServiceError::Protocol(format!(
                    "LSP frame is {length} bytes; maximum is {MAX_FRAME_BYTES}"
                )));
            }
            content_length = Some(length);
        }
    }
    let length = content_length
        .ok_or_else(|| LspServiceError::Protocol("response omitted Content-Length".to_string()))?;
    let mut body = vec![0_u8; length];
    read_exact_until(reader, &mut body, cancellation, deadline)?;
    serde_json::from_slice(&body)
        .map_err(|error| LspServiceError::Protocol(format!("invalid response JSON: {error}")))
}

fn read_exact_until(
    reader: &mut impl Read,
    mut output: &mut [u8],
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
) -> Result<(), LspServiceError> {
    while !output.is_empty() {
        if cancellation.is_cancelled() {
            return Err(LspServiceError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(LspServiceError::Protocol(
                "timed out reading language server frame".to_string(),
            ));
        }
        match reader.read(output) {
            Ok(0) => {
                return Err(LspServiceError::Process(
                    "language server closed stdout mid-frame".to_string(),
                ))
            }
            Ok(count) => output = &mut output[count..],
            Err(error) if error.kind() == ErrorKind::TimedOut => {}
            Err(error) => return Err(LspServiceError::Protocol(error.to_string())),
        }
    }
    Ok(())
}

fn write_request(
    writer: &mut impl Write,
    method: &str,
    id: u32,
    params: &Value,
) -> Result<(), LspServiceError> {
    write_raw(
        writer,
        &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
    )
}

fn write_notification(
    writer: &mut impl Write,
    method: &str,
    params: &Value,
) -> Result<(), LspServiceError> {
    write_raw(
        writer,
        &json!({"jsonrpc": "2.0", "method": method, "params": params}),
    )
}

fn write_raw(writer: &mut impl Write, message: &Value) -> Result<(), LspServiceError> {
    let body = serde_json::to_vec(message)
        .map_err(|error| LspServiceError::Protocol(error.to_string()))?;
    writer
        .write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes())
        .and_then(|()| writer.write_all(&body))
        .and_then(|()| writer.flush())
        .map_err(|error| LspServiceError::Protocol(error.to_string()))
}

fn reverse_response(id: u64, method: &str, params: Option<&Value>) -> Value {
    match method {
        "workspace/configuration" => {
            let count = params
                .and_then(|params| params.get("items"))
                .and_then(Value::as_array)
                .map_or(1, Vec::len);
            json!({"jsonrpc": "2.0", "id": id, "result": vec![Value::Null; count]})
        }
        "client/registerCapability"
        | "client/unregisterCapability"
        | "window/workDoneProgress/create" => {
            json!({"jsonrpc": "2.0", "id": id, "result": Value::Null})
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": format!("unsupported client method: {method}")}
        }),
    }
}

fn capture_stderr(stderr: ChildStderr) -> (Arc<Mutex<Vec<u8>>>, JoinHandle<()>) {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let output = Arc::clone(&buffer);
    let thread = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut chunk = [0_u8; 256];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let mut output = lock(&output);
                    output.extend_from_slice(&chunk[..count]);
                    let remove = output.len().saturating_sub(1024);
                    output.drain(..remove);
                }
            }
        }
    });
    (buffer, thread)
}

fn with_stderr(error: LspServiceError, stderr: &Arc<Mutex<Vec<u8>>>) -> LspServiceError {
    let snippet = {
        let stderr = lock(stderr);
        if stderr.is_empty() {
            return error;
        }
        let snippet = String::from_utf8_lossy(&stderr).into_owned();
        drop(stderr);
        snippet
    };
    match error {
        LspServiceError::Process(detail) => {
            LspServiceError::Process(format!("{detail}; server stderr: {snippet}"))
        }
        LspServiceError::Protocol(detail) => {
            LspServiceError::Protocol(format!("{detail}; server stderr: {snippet}"))
        }
        LspServiceError::Server { code, message } => LspServiceError::Server {
            code,
            message: format!("{message}; server stderr: {snippet}"),
        },
        other => other,
    }
}

fn wait_with_timeout(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) | Err(_) => return false,
        }
    }
}

fn join_reader(thread: Option<JoinHandle<()>>) {
    if let Some(thread) = thread {
        let _ = thread.join();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_resolution_is_complete_for_tool_languages() {
        for language in [
            "rust",
            "typescript",
            "typescriptreact",
            "javascript",
            "javascriptreact",
            "python",
            "go",
            "c",
            "cpp",
            "java",
            "ruby",
        ] {
            assert!(builtin_server(language).is_some(), "missing {language}");
        }
    }

    #[test]
    fn continuation_tokens_are_opaque_and_unique() {
        let first = continuation_token("file:///a.rs", 1, 1, b"{}");
        let second = continuation_token("file:///a.rs", 1, 1, b"{}");
        assert!(first.starts_with("lspct_"));
        assert_ne!(first, second);
        assert!(!first.contains("file:///"));
    }
}

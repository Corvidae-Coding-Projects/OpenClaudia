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
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;

const CLIENT_CAPABILITIES_VERSION: &str = "openclaudia-lsp-client-v1";
const RESPONSE_POLL: Duration = Duration::from_millis(250);
const WRITE_POLL: Duration = Duration::from_millis(10);
const MAX_HIERARCHY_ITEMS: usize = 128;
const MAX_HIERARCHY_ITEM_BYTES: usize = 256 * 1024;
const MAX_HIERARCHY_BYTES: usize = 1024 * 1024;
const MAX_CONTINUATIONS_PER_SERVER: usize = 256;
const MAX_POOLED_SERVERS: usize = 8;
const MAX_RESOURCE_URI_BYTES: usize = 16 * 1024;
const MAX_DIAGNOSTIC_TEXT_BYTES: usize = 16 * 1024;
const MAX_DIAGNOSTIC_METADATA_BYTES: usize = 1024;

/// Hard protocol limits applied to every language-server generation.
///
/// Defaults admit the existing 10 MiB document contract while bounding every
/// queue, frame, turn, semantic result, diagnostic batch, and shutdown phase.
/// Tests may use smaller values to exercise deadlines without sleeping for
/// production durations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LspProtocolLimits {
    pub request_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub max_header_bytes: usize,
    pub max_header_lines: usize,
    pub max_frame_bytes: usize,
    pub max_turn_bytes: usize,
    pub max_messages_per_turn: usize,
    pub max_queued_bytes: usize,
    pub max_outbound_message_bytes: usize,
    pub max_result_bytes: usize,
    pub max_stderr_bytes: usize,
    pub max_diagnostics_per_publication: usize,
    pub max_diagnostic_bytes: usize,
    pub max_reverse_configuration_items: usize,
}

impl Default for LspProtocolLimits {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(2),
            max_header_bytes: 16 * 1024,
            max_header_lines: 64,
            max_frame_bytes: 16 * 1024 * 1024,
            max_turn_bytes: 32 * 1024 * 1024,
            max_messages_per_turn: 100,
            max_queued_bytes: 128 * 1024,
            // Source JSON commonly expands through quote and backslash
            // escaping; keep the 10 MiB source-file contract usable.
            max_outbound_message_bytes: 24 * 1024 * 1024,
            max_result_bytes: 2 * 1024 * 1024,
            max_stderr_bytes: 8 * 1024,
            max_diagnostics_per_publication: 128,
            max_diagnostic_bytes: 256 * 1024,
            max_reverse_configuration_items: 128,
        }
    }
}

impl LspProtocolLimits {
    fn normalized(mut self) -> Self {
        self.request_timeout = self.request_timeout.max(RESPONSE_POLL);
        self.shutdown_timeout = self.shutdown_timeout.max(WRITE_POLL);
        self.max_header_bytes = self.max_header_bytes.max(1);
        self.max_header_lines = self.max_header_lines.max(1);
        self.max_frame_bytes = self.max_frame_bytes.max(1);
        self.max_turn_bytes = self.max_turn_bytes.max(self.max_frame_bytes);
        self.max_messages_per_turn = self.max_messages_per_turn.max(1);
        self.max_queued_bytes = self.max_queued_bytes.max(1);
        self.max_outbound_message_bytes = self.max_outbound_message_bytes.max(1);
        self.max_result_bytes = self.max_result_bytes.max(1);
        self.max_stderr_bytes = self.max_stderr_bytes.max(1);
        self.max_diagnostics_per_publication = self.max_diagnostics_per_publication.max(1);
        self.max_diagnostic_bytes = self.max_diagnostic_bytes.max(1);
        self.max_reverse_configuration_items = self.max_reverse_configuration_items.max(1);
        self
    }
}

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
    pub server_restarted: bool,
    pub continuations: Vec<LspCallHierarchyContinuation>,
    pub diagnostics: Vec<LspDiagnosticPublication>,
    pub partial_reasons: Vec<String>,
}

/// One bounded, capability-validated diagnostic emitted by a language server.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LspPublishedDiagnostic {
    /// 1-based line number for model-facing consistency.
    pub line: u32,
    /// 0-based LSP character offset.
    pub character: u32,
    /// 1-based end line.
    pub end_line: u32,
    /// 0-based LSP end-character offset.
    pub end_character: u32,
    pub severity: super::lsp_diagnostics::DiagnosticSeverity,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// A typed diagnostics replacement tied to one exact server/document state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LspDiagnosticPublication {
    pub resource_id: String,
    pub uri: String,
    pub document_version: Option<i32>,
    pub server_generation: u64,
    pub stale: bool,
    pub untrusted: bool,
    pub diagnostics: Vec<LspPublishedDiagnostic>,
    pub omitted_diagnostics: usize,
    pub truncated_bytes: usize,
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
    #[error("language server protocol deadline expired during {0}")]
    Deadline(&'static str),
    #[error("language server protocol queue is unavailable: {0}")]
    Backpressure(String),
    #[error("language server data exceeds its bounded contract: {0}")]
    ResultLimit(String),
    #[error("language server returned an invalid or unauthorized resource: {0}")]
    InvalidResource(String),
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
    stdin: DeadlineWriter,
    stdout: Option<BufReader<DeadlineReader>>,
    stdout_thread: Option<JoinHandle<()>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_thread: Option<JoinHandle<()>>,
    next_request_id: u32,
    limits: LspProtocolLimits,
    _registration: crate::tools::command::ActiveSandboxProcess,
}

impl LiveServer {
    fn request(
        &mut self,
        run: &crate::tools::ToolRunContext,
        method: &str,
        params: &Value,
        deadline: Instant,
    ) -> Result<ProtocolReply, LspServiceError> {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).unwrap_or(2);
        write_request(
            &self.stdin,
            method,
            id,
            params,
            &run.runtime().cancellation(),
            deadline,
        )?;
        let stdout = self.stdout.as_mut().ok_or_else(|| {
            LspServiceError::Process("language server stdout is unavailable".to_string())
        })?;
        read_response(run, stdout, &self.stdin, id, deadline, &self.limits)
            .map_err(|error| with_stderr(run, error, &self.stderr))
    }

    fn notify(
        &self,
        cancellation: &crate::runtime::CancellationHandle,
        method: &str,
        params: &Value,
        deadline: Instant,
    ) -> Result<(), LspServiceError> {
        write_notification(&self.stdin, method, params, cancellation, deadline)
    }

    fn is_healthy(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn shutdown(mut self, documents: &HashMap<PathBuf, DocumentState>) {
        let deadline = Instant::now() + self.limits.shutdown_timeout;
        let no_cancel = crate::runtime::CancellationTree::new();
        let cancellation = no_cancel.root();
        for document in documents.values() {
            if self
                .notify(
                    &cancellation,
                    "textDocument/didClose",
                    &json!({"textDocument": {"uri": document.uri}}),
                    deadline,
                )
                .is_err()
            {
                break;
            }
        }
        let shutdown_id = self.next_request_id;
        let shutdown_written = write_request(
            &self.stdin,
            "shutdown",
            shutdown_id,
            &Value::Null,
            &cancellation,
            deadline,
        )
        .is_ok();
        if shutdown_written {
            if let Some(stdout) = self.stdout.as_mut() {
                let _ = read_response_with_cancellation(
                    None,
                    &cancellation,
                    stdout,
                    &self.stdin,
                    shutdown_id,
                    deadline,
                    &self.limits,
                );
            }
        }
        let _ = self.notify(&cancellation, "exit", &Value::Null, deadline);
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !wait_with_timeout(&mut self.child, remaining) {
            crate::tools::terminate_process_tree(self.child.id());
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        drop(self.stdout.take());
        self.stdin.shutdown();
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
        self.stdin.shutdown();
        join_reader(self.stdout_thread.take());
        join_reader(self.stderr_thread.take());
    }
}

/// Per-run stateful LSP manager.
pub struct LspServerManager {
    entries: Mutex<HashMap<LspPoolKey, Arc<Mutex<ServerSlot>>>>,
    plugin_servers: Mutex<Vec<PluginLspServer>>,
    idle_ttl: Duration,
    limits: LspProtocolLimits,
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
        Self::with_limits(idle_ttl, LspProtocolLimits::default())
    }

    #[must_use]
    pub fn with_limits(idle_ttl: Duration, limits: LspProtocolLimits) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            plugin_servers: Mutex::new(Vec::new()),
            idle_ttl,
            limits: limits.normalized(),
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
        let deadline = Instant::now() + self.limits.request_timeout;
        let server_restarted = ensure_live(run, &spec, &mut slot, deadline, self.limits)?;
        let document_version = match synchronize_document(run, request, &mut slot, deadline) {
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
            .request(run, request.method, &params, deadline);
        let reply = match response {
            Ok(reply) => reply,
            Err(error) => {
                if !matches!(error, LspServiceError::Server { .. }) {
                    invalidate_generation(&mut slot);
                }
                return Err(error);
            }
        };
        let result_bytes = match reply.response.get("result") {
            Some(result) => encoded_json_len(result)?,
            None => 0,
        };
        if result_bytes > self.limits.max_result_bytes {
            invalidate_generation(&mut slot);
            return Err(LspServiceError::ResultLimit(format!(
                "server result is {result_bytes} bytes; maximum is {}",
                self.limits.max_result_bytes
            )));
        }
        let generation = slot.generation;
        let diagnostics = parse_diagnostic_publications(
            run,
            &slot.documents,
            generation,
            &reply.notifications,
            self.limits,
        )?;
        let (continuations, mut partial_reasons) = store_hierarchy_continuations(
            run,
            request,
            &reply.response,
            &mut slot,
            document_version,
        )?;
        for publication in &diagnostics {
            if publication.omitted_diagnostics > 0 || publication.truncated_bytes > 0 {
                partial_reasons.push(format!(
                    "diagnostics for '{}' were truncated ({} omitted, {} bytes removed)",
                    publication.resource_id,
                    publication.omitted_diagnostics,
                    publication.truncated_bytes
                ));
            }
            if publication.stale {
                partial_reasons.push(format!(
                    "diagnostics for '{}' belong to a stale document version",
                    publication.resource_id
                ));
            }
        }
        Ok(LspServiceResponse {
            response: reply.response,
            server_generation: slot.generation,
            document_version,
            server_restarted,
            continuations,
            diagnostics,
            partial_reasons,
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
    deadline: Instant,
    limits: LspProtocolLimits,
) -> Result<bool, LspServiceError> {
    if slot.live.as_mut().is_some_and(LiveServer::is_healthy) {
        return Ok(false);
    }
    let restarted = slot.generation > 0;
    invalidate_generation(slot);
    slot.generation = slot.generation.checked_add(1).unwrap_or(1);
    let live = spawn_server(run, spec, deadline, limits)?;
    for document in slot.documents.values() {
        live.notify(
            &run.runtime().cancellation(),
            "textDocument/didOpen",
            &json!({
                "textDocument": {
                    "uri": document.uri,
                    "languageId": document.language,
                    "version": document.version,
                    "text": document.text,
                }
            }),
            deadline,
        )?;
    }
    slot.live = Some(live);
    Ok(restarted)
}

fn synchronize_document(
    run: &crate::tools::ToolRunContext,
    request: &LspServiceRequest,
    slot: &mut ServerSlot,
    deadline: Instant,
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
                &run.runtime().cancellation(),
                "textDocument/didChange",
                &json!({
                    "textDocument": {"uri": document.uri, "version": document.version},
                    "contentChanges": [{"text": document.text}],
                }),
                deadline,
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
        &run.runtime().cancellation(),
        "textDocument/didOpen",
        &json!({
            "textDocument": {
                "uri": document.uri,
                "languageId": document.language,
                "version": document.version,
                "text": document.text,
            }
        }),
        deadline,
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
    run: &crate::tools::ToolRunContext,
    request: &LspServiceRequest,
    response: &Value,
    slot: &mut ServerSlot,
    document_version: i32,
) -> Result<(Vec<LspCallHierarchyContinuation>, Vec<String>), LspServiceError> {
    let Some(results) = response.get("result").and_then(Value::as_array) else {
        return Ok((Vec::new(), Vec::new()));
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
        _ => return Ok((Vec::new(), Vec::new())),
    };
    let mut partial_reasons = Vec::new();
    if items.len() > MAX_HIERARCHY_ITEMS {
        partial_reasons.push(format!(
            "call hierarchy returned {} items; retained the first {MAX_HIERARCHY_ITEMS}",
            items.len()
        ));
    }
    let mut output = Vec::with_capacity(items.len().min(MAX_HIERARCHY_ITEMS));
    let mut aggregate_bytes = 0_usize;
    for item in items.into_iter().take(MAX_HIERARCHY_ITEMS) {
        validate_hierarchy_item_resource(run, item)?;
        let encoded = serde_json::to_vec(item)
            .map_err(|error| LspServiceError::Protocol(error.to_string()))?;
        if encoded.len() > MAX_HIERARCHY_ITEM_BYTES {
            return Err(LspServiceError::ContinuationLimit(format!(
                "one item is {} bytes; maximum is {MAX_HIERARCHY_ITEM_BYTES}",
                encoded.len()
            )));
        }
        if aggregate_bytes.saturating_add(encoded.len()) > MAX_HIERARCHY_BYTES {
            partial_reasons.push(format!(
                "call hierarchy continuation data exceeded {MAX_HIERARCHY_BYTES} bytes"
            ));
            break;
        }
        aggregate_bytes += encoded.len();
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
    Ok((output, partial_reasons))
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
    deadline: Instant,
    limits: LspProtocolLimits,
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
    let stdin = DeadlineWriter::spawn(stdin, limits);
    let (stdout, stdout_thread) = DeadlineReader::spawn(stdout, limits.max_queued_bytes);
    let (stderr, stderr_thread) = capture_stderr(stderr, limits.max_stderr_bytes);
    let mut live = LiveServer {
        child,
        stdin,
        stdout: Some(BufReader::new(stdout)),
        stdout_thread: Some(stdout_thread),
        stderr,
        stderr_thread: Some(stderr_thread),
        next_request_id: 2,
        limits,
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
        deadline,
    )?;
    if !init.response.get("result").is_some_and(Value::is_object) {
        return Err(LspServiceError::Protocol(
            "initialize response must carry an object result".to_string(),
        ));
    }
    live.notify(
        &run.runtime().cancellation(),
        "initialized",
        &json!({}),
        deadline,
    )?;
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

pub(crate) fn validate_returned_resource(
    run: &crate::tools::ToolRunContext,
    uri: &str,
) -> Result<(String, String), LspServiceError> {
    if uri.len() > MAX_RESOURCE_URI_BYTES {
        return Err(LspServiceError::InvalidResource(format!(
            "URI is {} bytes; maximum is {MAX_RESOURCE_URI_BYTES}",
            uri.len()
        )));
    }
    let parsed = url::Url::parse(uri)
        .map_err(|error| LspServiceError::InvalidResource(format!("invalid URI: {error}")))?;
    if parsed.scheme() != "file" {
        return Err(LspServiceError::InvalidResource(format!(
            "unsupported URI scheme '{}'",
            parsed.scheme()
        )));
    }
    let path = parsed.to_file_path().map_err(|()| {
        LspServiceError::InvalidResource("file URI cannot be represented as a path".to_string())
    })?;
    let canonical = path.canonicalize().map_err(|error| {
        LspServiceError::InvalidResource(format!(
            "resource '{}' cannot be resolved: {error}",
            path.display()
        ))
    })?;
    if !run.permits_read(&canonical) {
        return Err(LspServiceError::InvalidResource(format!(
            "resource '{}' is outside the run's read capability",
            canonical.display()
        )));
    }
    let relative = canonical.strip_prefix(run.project_root()).map_err(|_| {
        LspServiceError::InvalidResource(format!(
            "resource '{}' is outside workspace '{}'",
            canonical.display(),
            run.project_root().display()
        ))
    })?;
    let resource_id = relative.to_string_lossy().replace('\\', "/");
    if resource_id.is_empty() {
        return Err(LspServiceError::InvalidResource(
            "workspace root is not a file resource".to_string(),
        ));
    }
    let canonical_uri = url::Url::from_file_path(&canonical)
        .map_err(|()| {
            LspServiceError::InvalidResource(
                "canonical resource path cannot form a file URI".to_string(),
            )
        })?
        .to_string();
    Ok((canonical_uri, resource_id))
}

fn validate_hierarchy_item_resource(
    run: &crate::tools::ToolRunContext,
    item: &Value,
) -> Result<(), LspServiceError> {
    let uri = item.get("uri").and_then(Value::as_str).ok_or_else(|| {
        LspServiceError::Protocol("call-hierarchy item omitted a string URI".to_string())
    })?;
    let _ = validate_returned_resource(run, uri)?;
    Ok(())
}

fn parse_diagnostic_publications(
    run: &crate::tools::ToolRunContext,
    documents: &HashMap<PathBuf, DocumentState>,
    server_generation: u64,
    notifications: &[Value],
    limits: LspProtocolLimits,
) -> Result<Vec<LspDiagnosticPublication>, LspServiceError> {
    notifications
        .iter()
        .map(|params| {
            parse_diagnostic_publication(run, documents, server_generation, params, limits)
        })
        .collect()
}

fn parse_diagnostic_publication(
    run: &crate::tools::ToolRunContext,
    documents: &HashMap<PathBuf, DocumentState>,
    server_generation: u64,
    params: &Value,
    limits: LspProtocolLimits,
) -> Result<LspDiagnosticPublication, LspServiceError> {
    let uri = params.get("uri").and_then(Value::as_str).ok_or_else(|| {
        LspServiceError::Protocol("publishDiagnostics omitted a string URI".to_string())
    })?;
    let (canonical_uri, resource_id) = validate_returned_resource(run, uri)?;
    let document_version = params
        .get("version")
        .map(|version| {
            version
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .ok_or_else(|| {
                    LspServiceError::Protocol(
                        "publishDiagnostics version must fit a signed 32-bit integer".to_string(),
                    )
                })
        })
        .transpose()?;
    let current_version = documents
        .values()
        .find(|document| document.uri == canonical_uri)
        .map(|document| document.version);
    let stale = document_version
        .zip(current_version)
        .is_some_and(|(published, current)| published != current);
    let raw = params
        .get("diagnostics")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            LspServiceError::Protocol("publishDiagnostics omitted a diagnostics array".to_string())
        })?;
    let omitted_diagnostics = raw
        .len()
        .saturating_sub(limits.max_diagnostics_per_publication);
    let mut diagnostics = Vec::with_capacity(raw.len().min(limits.max_diagnostics_per_publication));
    let mut retained_bytes = 0_usize;
    let mut truncated_bytes = 0_usize;
    for diagnostic in raw.iter().take(limits.max_diagnostics_per_publication) {
        let encoded_bytes = encoded_json_len(diagnostic)?;
        if retained_bytes.saturating_add(encoded_bytes) > limits.max_diagnostic_bytes {
            truncated_bytes = truncated_bytes.saturating_add(encoded_bytes);
            continue;
        }
        retained_bytes += encoded_bytes;
        diagnostics.push(parse_published_diagnostic(
            run,
            diagnostic,
            &mut truncated_bytes,
        )?);
    }
    for diagnostic in raw.iter().skip(limits.max_diagnostics_per_publication) {
        truncated_bytes = truncated_bytes.saturating_add(encoded_json_len(diagnostic)?);
    }
    Ok(LspDiagnosticPublication {
        resource_id,
        uri: canonical_uri,
        document_version,
        server_generation,
        stale,
        untrusted: true,
        diagnostics,
        omitted_diagnostics,
        truncated_bytes,
    })
}

fn parse_published_diagnostic(
    run: &crate::tools::ToolRunContext,
    diagnostic: &Value,
    truncated_bytes: &mut usize,
) -> Result<LspPublishedDiagnostic, LspServiceError> {
    let range = diagnostic
        .get("range")
        .ok_or_else(|| LspServiceError::Protocol("diagnostic omitted range".to_string()))?;
    let start = range
        .get("start")
        .ok_or_else(|| LspServiceError::Protocol("diagnostic range omitted start".to_string()))?;
    let end = range
        .get("end")
        .ok_or_else(|| LspServiceError::Protocol("diagnostic range omitted end".to_string()))?;
    let message = diagnostic
        .get("message")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            LspServiceError::Protocol("diagnostic omitted a string message".to_string())
        })?;
    let source = match diagnostic.get("source") {
        None => None,
        Some(Value::String(source)) => Some(bounded_untrusted_text(
            run,
            source,
            MAX_DIAGNOSTIC_METADATA_BYTES,
            truncated_bytes,
        )),
        Some(_) => {
            return Err(LspServiceError::Protocol(
                "diagnostic source must be a string".to_string(),
            ))
        }
    };
    let code = diagnostic
        .get("code")
        .map(|code| match code {
            Value::String(code) => code.clone(),
            Value::Number(code) => code.to_string(),
            _ => String::new(),
        })
        .filter(|code| !code.is_empty())
        .map(|code| {
            bounded_untrusted_text(run, &code, MAX_DIAGNOSTIC_METADATA_BYTES, truncated_bytes)
        });
    let severity = diagnostic
        .get("severity")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .map_or(
            super::lsp_diagnostics::DiagnosticSeverity::Information,
            super::lsp_diagnostics::DiagnosticSeverity::from_wire,
        );
    Ok(LspPublishedDiagnostic {
        line: strict_line(start, "line")?,
        character: strict_position(start, "character")?,
        end_line: strict_line(end, "line")?,
        end_character: strict_position(end, "character")?,
        severity,
        message: bounded_untrusted_text(run, message, MAX_DIAGNOSTIC_TEXT_BYTES, truncated_bytes),
        source,
        code,
    })
}

fn strict_line(value: &Value, name: &str) -> Result<u32, LspServiceError> {
    strict_position(value, name)?.checked_add(1).ok_or_else(|| {
        LspServiceError::Protocol(format!(
            "LSP position '{name}' cannot be represented as a 1-indexed line"
        ))
    })
}

fn strict_position(value: &Value, name: &str) -> Result<u32, LspServiceError> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .and_then(|position| u32::try_from(position).ok())
        .ok_or_else(|| {
            LspServiceError::Protocol(format!(
                "LSP position '{name}' must fit an unsigned 32-bit integer"
            ))
        })
}

fn bounded_untrusted_text(
    run: &crate::tools::ToolRunContext,
    raw: &str,
    max_bytes: usize,
    truncated_bytes: &mut usize,
) -> String {
    let sanitized = run.sanitize_diagnostic(raw);
    let bounded = crate::tools::safe_truncate(sanitized.as_str(), max_bytes);
    *truncated_bytes = (*truncated_bytes).saturating_add(sanitized.as_str().len() - bounded.len());
    bounded.to_string()
}

enum ReadEvent {
    Chunk(Vec<u8>),
    Eof,
    Error(String),
}

struct WriteCommand {
    bytes: Vec<u8>,
    completion: SyncSender<Result<(), String>>,
}

struct DeadlineWriter {
    tx: Option<SyncSender<WriteCommand>>,
    thread: Option<JoinHandle<()>>,
    max_message_bytes: usize,
}

impl DeadlineWriter {
    fn spawn(mut writer: ChildStdin, limits: LspProtocolLimits) -> Self {
        // A rendezvous channel leaves no serialized request buffered behind a
        // blocked pipe. The one in-flight message is owned by the writer and
        // bounded separately by `max_outbound_message_bytes`.
        let (tx, rx) = mpsc::sync_channel::<WriteCommand>(0);
        let thread = thread::spawn(move || {
            while let Ok(command) = rx.recv() {
                let result = writer
                    .write_all(&command.bytes)
                    .and_then(|()| writer.flush())
                    .map_err(|error| error.to_string());
                let failed = result.is_err();
                let _ = command.completion.send(result);
                if failed {
                    break;
                }
            }
        });
        Self {
            tx: Some(tx),
            thread: Some(thread),
            max_message_bytes: limits.max_outbound_message_bytes,
        }
    }

    fn write_value(
        &self,
        message: &Value,
        cancellation: &crate::runtime::CancellationHandle,
        deadline: Instant,
    ) -> Result<(), LspServiceError> {
        let body = serde_json::to_vec(message)
            .map_err(|error| LspServiceError::Protocol(error.to_string()))?;
        if body.len() > self.max_message_bytes {
            return Err(LspServiceError::ResultLimit(format!(
                "outbound message is {} bytes; maximum is {}",
                body.len(),
                self.max_message_bytes
            )));
        }
        let header = format!("Content-Length: {}\r\n\r\n", body.len());
        let mut bytes = Vec::with_capacity(header.len().saturating_add(body.len()));
        bytes.extend_from_slice(header.as_bytes());
        bytes.extend_from_slice(&body);
        let (completion, completed) = mpsc::sync_channel(1);
        let mut command = WriteCommand { bytes, completion };
        let tx = self.tx.as_ref().ok_or_else(|| {
            LspServiceError::Backpressure("language server stdin writer is closed".to_string())
        })?;
        loop {
            check_protocol_stop(cancellation, deadline, "queueing a request")?;
            match tx.try_send(command) {
                Ok(()) => break,
                Err(TrySendError::Full(returned)) => {
                    command = returned;
                    thread::sleep(WRITE_POLL);
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(LspServiceError::Backpressure(
                        "language server stdin writer stopped".to_string(),
                    ))
                }
            }
        }
        loop {
            check_protocol_stop(cancellation, deadline, "writing a request")?;
            let remaining = deadline.saturating_duration_since(Instant::now());
            match completed.recv_timeout(remaining.min(RESPONSE_POLL)) {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(error)) => {
                    return Err(LspServiceError::Process(format!(
                        "language server stdin write failed: {error}"
                    )))
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(LspServiceError::Backpressure(
                        "language server stdin writer stopped without a result".to_string(),
                    ))
                }
            }
        }
    }

    fn shutdown(&mut self) {
        drop(self.tx.take());
        join_reader(self.thread.take());
    }
}

struct ProtocolReply {
    response: Value,
    notifications: Vec<Value>,
}

fn check_protocol_stop(
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
    phase: &'static str,
) -> Result<(), LspServiceError> {
    if cancellation.is_cancelled() {
        return Err(LspServiceError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(LspServiceError::Deadline(phase));
    }
    Ok(())
}

fn validate_jsonrpc_version(message: &Value) -> Result<(), LspServiceError> {
    let object = message.as_object().ok_or_else(|| {
        LspServiceError::Protocol("JSON-RPC message must be an object".to_string())
    })?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(LspServiceError::Protocol(
            "JSON-RPC message must declare version 2.0".to_string(),
        ));
    }
    Ok(())
}

fn validate_response_shape(message: &Value) -> Result<(), LspServiceError> {
    let has_result = message.get("result").is_some();
    let has_error = message.get("error").is_some();
    if has_result == has_error {
        return Err(LspServiceError::Protocol(
            "JSON-RPC response must contain exactly one of result or error".to_string(),
        ));
    }
    if has_error && !message.get("error").is_some_and(Value::is_object) {
        return Err(LspServiceError::Protocol(
            "JSON-RPC error member must be an object".to_string(),
        ));
    }
    Ok(())
}

fn validate_reverse_id(id: &Value) -> Result<(), LspServiceError> {
    if id.is_string() || id.as_i64().is_some() || id.as_u64().is_some() {
        return Ok(());
    }
    Err(LspServiceError::Protocol(
        "reverse JSON-RPC request id must be a string or integer".to_string(),
    ))
}

fn sanitize_server_text(run: Option<&crate::tools::ToolRunContext>, raw: &str) -> String {
    run.map_or_else(
        || {
            crate::secrets::sanitize_diagnostic(
                raw,
                std::iter::empty::<&crate::secrets::SecretString>(),
            )
            .as_str()
            .to_string()
        },
        |run| run.sanitize_diagnostic(raw).as_str().to_string(),
    )
}

fn encoded_json_len(value: &Value) -> Result<usize, LspServiceError> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .map_err(|error| LspServiceError::Protocol(error.to_string()))
}

struct DeadlineReader {
    rx: Receiver<ReadEvent>,
    pending: VecDeque<u8>,
    ended: bool,
}

impl DeadlineReader {
    fn spawn(
        mut reader: impl Read + Send + 'static,
        max_queued_bytes: usize,
    ) -> (Self, JoinHandle<()>) {
        let chunk_bytes = max_queued_bytes.clamp(1, 8192);
        let queue_depth = (max_queued_bytes / chunk_bytes).max(1);
        let (tx, rx) = mpsc::sync_channel(queue_depth);
        let thread = thread::spawn(move || {
            let mut chunk = vec![0_u8; chunk_bytes];
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
    writer: &DeadlineWriter,
    expected_id: u32,
    deadline: Instant,
    limits: &LspProtocolLimits,
) -> Result<ProtocolReply, LspServiceError> {
    read_response_with_cancellation(
        Some(run),
        &run.runtime().cancellation(),
        reader,
        writer,
        expected_id,
        deadline,
        limits,
    )
}

fn read_response_with_cancellation(
    run: Option<&crate::tools::ToolRunContext>,
    cancellation: &crate::runtime::CancellationHandle,
    reader: &mut BufReader<DeadlineReader>,
    writer: &DeadlineWriter,
    expected_id: u32,
    deadline: Instant,
    limits: &LspProtocolLimits,
) -> Result<ProtocolReply, LspServiceError> {
    let mut remaining_bytes = limits.max_turn_bytes;
    let mut notifications = Vec::new();
    for _ in 0..limits.max_messages_per_turn {
        let message = read_frame(reader, cancellation, deadline, limits, &mut remaining_bytes)?;
        validate_jsonrpc_version(&message)?;
        let method = message.get("method").and_then(Value::as_str);
        let id = message.get("id");
        if id.and_then(Value::as_u64) == Some(u64::from(expected_id)) && method.is_none() {
            validate_response_shape(&message)?;
            if let Some(error) = message.get("error") {
                let code = error.get("code").and_then(Value::as_i64).ok_or_else(|| {
                    LspServiceError::Protocol(
                        "JSON-RPC error response omitted an integer code".to_string(),
                    )
                })?;
                let raw_message =
                    error
                        .get("message")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            LspServiceError::Protocol(
                                "JSON-RPC error response omitted a string message".to_string(),
                            )
                        })?;
                return Err(LspServiceError::Server {
                    code,
                    message: sanitize_server_text(run, raw_message),
                });
            }
            return Ok(ProtocolReply {
                response: message,
                notifications,
            });
        }
        if let Some(method) = method {
            if let Some(id) = id {
                validate_reverse_id(id)?;
                let response = reverse_response(
                    id,
                    method,
                    message.get("params"),
                    limits.max_reverse_configuration_items,
                )?;
                write_raw(writer, &response, cancellation, deadline)?;
            } else if method == "textDocument/publishDiagnostics" {
                let params = message.get("params").cloned().ok_or_else(|| {
                    LspServiceError::Protocol(
                        "publishDiagnostics notification omitted params".to_string(),
                    )
                })?;
                notifications.push(params);
            }
            continue;
        }
        if id.is_some() {
            return Err(LspServiceError::Protocol(format!(
                "received unexpected JSON-RPC response while waiting for id {expected_id}"
            )));
        }
        return Err(LspServiceError::Protocol(
            "JSON-RPC message has neither a response id nor a method".to_string(),
        ));
    }
    Err(LspServiceError::Protocol(format!(
        "response id {expected_id} was not received within {} messages",
        limits.max_messages_per_turn
    )))
}

fn read_frame(
    reader: &mut BufReader<DeadlineReader>,
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
    limits: &LspProtocolLimits,
    remaining_turn_bytes: &mut usize,
) -> Result<Value, LspServiceError> {
    let mut content_length = None;
    let mut header_bytes = 0_usize;
    for line_index in 0..limits.max_header_lines {
        let line = read_bounded_header_line(
            reader,
            cancellation,
            deadline,
            limits.max_header_bytes.saturating_sub(header_bytes),
        )?;
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > limits.max_header_bytes {
            return Err(LspServiceError::Protocol(format!(
                "LSP header exceeds {} bytes",
                limits.max_header_bytes
            )));
        }
        let line = std::str::from_utf8(&line)
            .map_err(|_| LspServiceError::Protocol("LSP header is not UTF-8".to_string()))?
            .trim();
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(LspServiceError::Protocol(
                "LSP header line omitted ':'".to_string(),
            ));
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            if content_length.is_some() {
                return Err(LspServiceError::Protocol(
                    "LSP frame repeated Content-Length".to_string(),
                ));
            }
            let length = value.trim().parse::<usize>().map_err(|error| {
                LspServiceError::Protocol(format!("invalid Content-Length: {error}"))
            })?;
            if length > limits.max_frame_bytes {
                return Err(LspServiceError::Protocol(format!(
                    "LSP frame is {length} bytes; maximum is {}",
                    limits.max_frame_bytes
                )));
            }
            content_length = Some(length);
        }
        if line_index + 1 == limits.max_header_lines {
            return Err(LspServiceError::Protocol(format!(
                "LSP header exceeds {} lines",
                limits.max_header_lines
            )));
        }
    }
    let length = content_length
        .ok_or_else(|| LspServiceError::Protocol("response omitted Content-Length".to_string()))?;
    let wire_bytes = header_bytes.saturating_add(length);
    if wire_bytes > *remaining_turn_bytes {
        return Err(LspServiceError::ResultLimit(format!(
            "LSP turn exceeded {} aggregate bytes",
            limits.max_turn_bytes
        )));
    }
    *remaining_turn_bytes -= wire_bytes;
    let mut body = vec![0_u8; length];
    read_exact_until(reader, &mut body, cancellation, deadline)?;
    serde_json::from_slice(&body)
        .map_err(|error| LspServiceError::Protocol(format!("invalid response JSON: {error}")))
}

fn read_bounded_header_line(
    reader: &mut impl BufRead,
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
    max_bytes: usize,
) -> Result<Vec<u8>, LspServiceError> {
    let mut line = Vec::new();
    loop {
        check_protocol_stop(cancellation, deadline, "reading a response header")?;
        let available = match reader.fill_buf() {
            Ok([]) => {
                return Err(LspServiceError::Process(
                    "language server closed stdout".to_string(),
                ))
            }
            Ok(available) => available,
            Err(error) if error.kind() == ErrorKind::TimedOut => continue,
            Err(error) => return Err(LspServiceError::Protocol(error.to_string())),
        };
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > max_bytes {
            return Err(LspServiceError::Protocol(format!(
                "LSP header exceeds {max_bytes} remaining bytes"
            )));
        }
        line.extend_from_slice(&available[..take]);
        let complete = available[..take].ends_with(b"\n");
        reader.consume(take);
        if complete {
            return Ok(line);
        }
    }
}

fn read_exact_until(
    reader: &mut impl Read,
    mut output: &mut [u8],
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
) -> Result<(), LspServiceError> {
    while !output.is_empty() {
        check_protocol_stop(cancellation, deadline, "reading a response frame")?;
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
    writer: &DeadlineWriter,
    method: &str,
    id: u32,
    params: &Value,
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
) -> Result<(), LspServiceError> {
    write_raw(
        writer,
        &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}),
        cancellation,
        deadline,
    )
}

fn write_notification(
    writer: &DeadlineWriter,
    method: &str,
    params: &Value,
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
) -> Result<(), LspServiceError> {
    write_raw(
        writer,
        &json!({"jsonrpc": "2.0", "method": method, "params": params}),
        cancellation,
        deadline,
    )
}

fn write_raw(
    writer: &DeadlineWriter,
    message: &Value,
    cancellation: &crate::runtime::CancellationHandle,
    deadline: Instant,
) -> Result<(), LspServiceError> {
    writer.write_value(message, cancellation, deadline)
}

fn reverse_response(
    id: &Value,
    method: &str,
    params: Option<&Value>,
    max_configuration_items: usize,
) -> Result<Value, LspServiceError> {
    let response = match method {
        "workspace/configuration" => {
            let count = params
                .and_then(|params| params.get("items"))
                .and_then(Value::as_array)
                .map_or(1, Vec::len);
            if count > max_configuration_items {
                return Err(LspServiceError::ResultLimit(format!(
                    "reverse workspace/configuration requested {count} items; maximum is {max_configuration_items}"
                )));
            }
            json!({"jsonrpc": "2.0", "id": id, "result": vec![Value::Null; count]})
        }
        "window/workDoneProgress/create" => {
            json!({"jsonrpc": "2.0", "id": id, "result": Value::Null})
        }
        _ => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {"code": -32601, "message": format!("unsupported client method: {method}")}
        }),
    };
    Ok(response)
}

fn capture_stderr(stderr: ChildStderr, max_bytes: usize) -> (Arc<Mutex<Vec<u8>>>, JoinHandle<()>) {
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
                    let remove = output.len().saturating_sub(max_bytes);
                    output.drain(..remove);
                }
            }
        }
    });
    (buffer, thread)
}

fn with_stderr(
    run: &crate::tools::ToolRunContext,
    error: LspServiceError,
    stderr: &Arc<Mutex<Vec<u8>>>,
) -> LspServiceError {
    let snippet = {
        let stderr = lock(stderr);
        if stderr.is_empty() {
            return error;
        }
        let snippet = run
            .sanitize_diagnostic(&String::from_utf8_lossy(&stderr))
            .as_str()
            .to_string();
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
        LspServiceError::Backpressure(detail) => {
            LspServiceError::Backpressure(format!("{detail}; server stderr: {snippet}"))
        }
        LspServiceError::ResultLimit(detail) => {
            LspServiceError::ResultLimit(format!("{detail}; server stderr: {snippet}"))
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

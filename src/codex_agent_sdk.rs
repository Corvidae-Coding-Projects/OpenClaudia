//! Supported Codex account transport through the owning `codex` executable.
//!
//! `OpenClaudia` deliberately never reads, decodes, or forwards Codex OAuth
//! tokens. The official CLI owns login, refresh, account selection, and
//! compliance routing. This adapter constrains each provider turn to an
//! ephemeral, read-only, no-native-tools `codex exec` process and translates
//! its schema-bound result back into `OpenClaudia` host tool calls.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

use crate::session::TokenUsage;
use crate::tools::{FunctionCall, ToolCall};

const CODEX_STATUS_TIMEOUT: Duration = Duration::from_secs(15);
const CODEX_TURN_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_CODEX_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_CODEX_STDERR_BYTES: usize = 64 * 1024;
const MAX_PARALLEL_TOOL_CALL_SLOTS: usize = 16;

const TRANSPORT_INPUT_PREFIX: &str = concat!(
    "OpenClaudia is the host agent harness. The JSON below is one provider request. ",
    "Follow its instructions and conversation history, but do not invoke Codex-native tools. ",
    "Return only the structured response required by the output schema. Tool calls in that ",
    "response are inert requests for OpenClaudia to validate and execute.\n\n",
    "OPENCLAUDIA_PROVIDER_REQUEST_JSON:\n",
);

/// Features that could give the owned subprocess an execution surface outside
/// `OpenClaudia`'s policy, budget, hook, and permission boundaries.
const DISABLED_NATIVE_FEATURES: &[&str] = &[
    "shell_tool",
    "unified_exec",
    "apps",
    "plugins",
    "multi_agent",
    "browser_use",
    "computer_use",
    "image_generation",
    "view_image",
    "hooks",
    "skill_search",
    "skill_mcp_dependency_install",
    "tool_call_mcp_elicitation",
    "request_permissions_tool",
    "code_mode",
    "code_mode_host",
];

/// Pinned capability for the official Codex executable and its owned login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexAgentSdk {
    binary: PathBuf,
}

/// One normalized model turn returned by the Codex SDK transport.
#[derive(Debug, Clone)]
pub struct CodexAgentSdkTurn {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
}

impl CodexAgentSdkTurn {
    #[must_use]
    pub const fn needs_followup(&self) -> bool {
        !self.tool_calls.is_empty()
    }
}

/// Failures at the owning-executable transport boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CodexAgentSdkError {
    #[error("Codex executable was not found; install Codex and run `codex login`")]
    NotInstalled,
    #[error("Codex executable path could not be pinned: {0}")]
    InvalidExecutable(String),
    #[error("Codex login status could not be checked: {0}")]
    Status(String),
    #[error("Codex is not logged in; run `codex login`")]
    NotAuthenticated,
    #[error("Codex SDK request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Codex SDK process could not be started: {0}")]
    Spawn(String),
    #[error("Codex SDK process timed out after {0} seconds")]
    Timeout(u64),
    #[error("Codex SDK process exceeded its caller-owned deadline")]
    Deadline,
    #[error("Codex SDK process was cancelled: {0:?}")]
    Cancelled(crate::runtime::CancellationReason),
    #[error("Codex SDK output exceeded its {0}-byte limit")]
    OutputTooLarge(usize),
    #[error("Codex SDK process failed: {0}")]
    Process(String),
    #[error("Codex SDK attempted a disabled native tool: {0}")]
    NativeToolUse(String),
    #[error("Codex SDK returned invalid JSONL or structured output: {0}")]
    InvalidOutput(String),
}

#[derive(Debug, Deserialize)]
struct StructuredTurn {
    content: String,
    tool_calls: Vec<StructuredToolCall>,
}

#[derive(Debug, Deserialize)]
struct StructuredToolCall {
    name: String,
    arguments_json: String,
}

impl CodexAgentSdk {
    /// Resolve and pin `OpenAI`'s executable through the current startup PATH.
    ///
    /// # Errors
    ///
    /// Returns an error when `codex` is missing or cannot be canonicalized.
    pub fn discover() -> Result<Self, CodexAgentSdkError> {
        let binary = which::which("codex").map_err(|_| CodexAgentSdkError::NotInstalled)?;
        let binary = binary.canonicalize().map_err(|error| {
            CodexAgentSdkError::InvalidExecutable(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        if !binary.is_file() {
            return Err(CodexAgentSdkError::InvalidExecutable(
                "resolved path is not a regular file".to_string(),
            ));
        }
        Ok(Self { binary })
    }

    /// Return the pinned executable path without exposing credential data.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Ask the owning executable whether it has a usable login.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for process, timeout, or unauthenticated status.
    pub async fn require_authenticated(&self) -> Result<(), CodexAgentSdkError> {
        let mut command = Command::new(&self.binary);
        command
            .args(["login", "status"])
            .env_remove("OPENAI_API_KEY")
            .env_remove("CODEX_ACCESS_TOKEN")
            .kill_on_drop(true);
        let output = tokio::time::timeout(CODEX_STATUS_TIMEOUT, command.output())
            .await
            .map_err(|_| CodexAgentSdkError::Timeout(CODEX_STATUS_TIMEOUT.as_secs()))?
            .map_err(|error| {
                CodexAgentSdkError::Status(
                    crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
                )
            })?;
        if !output.status.success() {
            return Err(CodexAgentSdkError::NotAuthenticated);
        }
        Ok(())
    }

    /// Execute one constrained model turn through the official Codex runtime.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed requests, process failures, bounded
    /// I/O violations, native tool attempts, timeouts, or invalid output.
    pub async fn complete_turn(
        &self,
        request: &Value,
        effort: &str,
    ) -> Result<CodexAgentSdkTurn, CodexAgentSdkError> {
        let cancellation = crate::runtime::CancellationTree::new().root();
        match self
            .complete_turn_bounded(
                request,
                effort,
                tokio::time::Instant::now() + CODEX_TURN_TIMEOUT,
                cancellation,
            )
            .await
        {
            Err(CodexAgentSdkError::Deadline) => {
                Err(CodexAgentSdkError::Timeout(CODEX_TURN_TIMEOUT.as_secs()))
            }
            result => result,
        }
    }

    /// Execute one constrained turn under a caller-owned absolute deadline
    /// and cancellation tree. Every terminal branch kills/reaps the child and
    /// joins its bounded output readers before returning.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed requests, process failures, bounded
    /// I/O violations, cancellation, deadline expiry, or invalid output.
    #[allow(clippy::too_many_lines)] // One owned process lifecycle keeps cleanup and I/O limits together.
    pub(crate) async fn complete_turn_bounded(
        &self,
        request: &Value,
        effort: &str,
        deadline: tokio::time::Instant,
        cancellation: crate::runtime::CancellationHandle,
    ) -> Result<CodexAgentSdkTurn, CodexAgentSdkError> {
        let deadline = deadline.min(tokio::time::Instant::now() + CODEX_TURN_TIMEOUT);
        if let Some(receipt) = cancellation.receipt() {
            return Err(CodexAgentSdkError::Cancelled(receipt.reason));
        }
        if deadline <= tokio::time::Instant::now() {
            return Err(CodexAgentSdkError::Deadline);
        }
        let model = request
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| !model.trim().is_empty())
            .ok_or_else(|| {
                CodexAgentSdkError::InvalidRequest("missing non-empty model".to_string())
            })?;
        let prompt = transport_prompt(request)?;
        let (turn_schema, allowed_tool_names) = turn_contract(request)?;
        let mut schema_file = tempfile::NamedTempFile::new().map_err(|error| {
            CodexAgentSdkError::Spawn(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        schema_file
            .write_all(turn_schema.as_bytes())
            .and_then(|()| schema_file.flush())
            .map_err(|error| {
                CodexAgentSdkError::Spawn(
                    crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
                )
            })?;
        let isolation = tempfile::tempdir().map_err(|error| {
            CodexAgentSdkError::Spawn(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;

        let mut command = Command::new(&self.binary);
        command
            .arg("exec")
            .args([
                "--json",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--skip-git-repo-check",
                "--sandbox",
                "read-only",
                "--color",
                "never",
                "--model",
                model,
                "--config",
            ])
            .arg(format!(
                "model_reasoning_effort=\"{}\"",
                normalize_effort(effort)
            ));
        for feature in DISABLED_NATIVE_FEATURES {
            command.args(["--disable", feature]);
        }
        command
            .arg("--output-schema")
            .arg(schema_file.path())
            .arg("-")
            .current_dir(isolation.path())
            .env_remove("OPENAI_API_KEY")
            .env_remove("CODEX_ACCESS_TOKEN")
            .env_remove("OPENAI_BASE_URL")
            .env_remove("OPENAI_ORG_ID")
            .env_remove("OPENAI_PROJECT_ID")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        tracing::info!(
            backend = "codex_agent_sdk",
            model,
            tools = request
                .get("tools")
                .and_then(|value| value.as_array())
                .map_or(0, Vec::len),
            "sending constrained provider request through OpenAI-owned executable"
        );

        if let Some(receipt) = cancellation.receipt() {
            return Err(CodexAgentSdkError::Cancelled(receipt.reason));
        }
        if deadline <= tokio::time::Instant::now() {
            return Err(CodexAgentSdkError::Deadline);
        }

        let mut child = command.spawn().map_err(|error| {
            CodexAgentSdkError::Spawn(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        let Some(mut stdin) = child.stdin.take() else {
            kill_and_reap(&mut child).await;
            return Err(CodexAgentSdkError::Spawn(
                "child stdin was not available".to_string(),
            ));
        };
        match wait_for_sdk_boundary(stdin.write_all(prompt.as_bytes()), deadline, &cancellation)
            .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                kill_and_reap(&mut child).await;
                return Err(CodexAgentSdkError::Process(
                    crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
                ));
            }
            Err(stop) => {
                kill_and_reap(&mut child).await;
                return Err(stop.into_codex_error());
            }
        }
        match wait_for_sdk_boundary(stdin.shutdown(), deadline, &cancellation).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                kill_and_reap(&mut child).await;
                return Err(CodexAgentSdkError::Process(
                    crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
                ));
            }
            Err(stop) => {
                kill_and_reap(&mut child).await;
                return Err(stop.into_codex_error());
            }
        }
        drop(stdin);

        let Some(stdout) = child.stdout.take() else {
            kill_and_reap(&mut child).await;
            return Err(CodexAgentSdkError::Spawn(
                "child stdout was not available".to_string(),
            ));
        };
        let Some(stderr) = child.stderr.take() else {
            kill_and_reap(&mut child).await;
            return Err(CodexAgentSdkError::Spawn(
                "child stderr was not available".to_string(),
            ));
        };
        let mut stdout_task = tokio::spawn(read_bounded(stdout, MAX_CODEX_STDOUT_BYTES));
        let mut stderr_task = tokio::spawn(read_bounded(stderr, MAX_CODEX_STDERR_BYTES));
        let status = match wait_for_sdk_boundary(child.wait(), deadline, &cancellation).await {
            Ok(Ok(status)) => status,
            Ok(Err(error)) => {
                kill_and_reap(&mut child).await;
                abort_and_join_readers(stdout_task, stderr_task).await;
                return Err(CodexAgentSdkError::Process(
                    crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
                ));
            }
            Err(stop) => {
                kill_and_reap(&mut child).await;
                abort_and_join_readers(stdout_task, stderr_task).await;
                return Err(stop.into_codex_error());
            }
        };
        let readers = wait_for_sdk_boundary(
            async { tokio::join!(&mut stdout_task, &mut stderr_task) },
            deadline,
            &cancellation,
        )
        .await;
        let (stdout, stderr) = match readers {
            Ok((stdout, stderr)) => (reader_result(stdout)?, reader_result(stderr)?),
            Err(stop) => {
                abort_and_join_readers(stdout_task, stderr_task).await;
                return Err(stop.into_codex_error());
            }
        };
        if !status.success() {
            return Err(CodexAgentSdkError::Process(process_diagnostic(
                &stdout, &stderr,
            )));
        }
        decode_turn(&stdout, &allowed_tool_names)
    }
}

enum SdkBoundaryStop {
    Deadline,
    Cancelled(crate::runtime::CancellationReason),
}

impl SdkBoundaryStop {
    fn into_codex_error(self) -> CodexAgentSdkError {
        match self {
            Self::Deadline => CodexAgentSdkError::Deadline,
            Self::Cancelled(reason) => CodexAgentSdkError::Cancelled(reason),
        }
    }
}

async fn wait_for_sdk_boundary<F: std::future::Future>(
    future: F,
    deadline: tokio::time::Instant,
    cancellation: &crate::runtime::CancellationHandle,
) -> Result<F::Output, SdkBoundaryStop> {
    tokio::select! {
        biased;
        receipt = cancellation.cancelled() => Err(SdkBoundaryStop::Cancelled(receipt.reason)),
        () = tokio::time::sleep_until(deadline) => Err(SdkBoundaryStop::Deadline),
        output = future => Ok(output),
    }
}

async fn kill_and_reap(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}

async fn abort_and_join_readers(
    stdout: tokio::task::JoinHandle<Result<Vec<u8>, CodexAgentSdkError>>,
    stderr: tokio::task::JoinHandle<Result<Vec<u8>, CodexAgentSdkError>>,
) {
    stdout.abort();
    stderr.abort();
    let _ = tokio::join!(stdout, stderr);
}

fn reader_result(
    result: Result<Result<Vec<u8>, CodexAgentSdkError>, tokio::task::JoinError>,
) -> Result<Vec<u8>, CodexAgentSdkError> {
    result.map_err(|error| {
        CodexAgentSdkError::Process(
            crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
        )
    })?
}

async fn read_bounded<R: AsyncRead + Unpin>(
    reader: R,
    limit: usize,
) -> Result<Vec<u8>, CodexAgentSdkError> {
    let take_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(take_limit)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| {
            CodexAgentSdkError::Process(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
    if bytes.len() > limit {
        return Err(CodexAgentSdkError::OutputTooLarge(limit));
    }
    Ok(bytes)
}

fn process_diagnostic(stdout: &[u8], stderr: &[u8]) -> String {
    let diagnostic = if stderr.is_empty() { stdout } else { stderr };
    crate::secrets::SafeDiagnostic::from_untrusted(&String::from_utf8_lossy(diagnostic)).to_string()
}

fn normalize_effort(effort: &str) -> &'static str {
    match effort.trim().to_ascii_lowercase().as_str() {
        "medium" | "med" => "medium",
        "high" => "high",
        "xhigh" => "xhigh",
        "max" => "max",
        _ => "low",
    }
}

fn transport_prompt(request: &Value) -> Result<String, CodexAgentSdkError> {
    let mut payload = request.clone();
    let object = payload.as_object_mut().ok_or_else(|| {
        CodexAgentSdkError::InvalidRequest("request body must be an object".to_string())
    })?;
    object.remove("stream");
    if let Some(tools) = object.remove("tools") {
        object.insert("openclaudia_host_tools".to_string(), tools);
    }
    object.remove("tool_choice");
    object.remove("parallel_tool_calls");
    object.remove("include");
    serde_json::to_string(&payload)
        .map(|json| format!("{TRANSPORT_INPUT_PREFIX}{json}"))
        .map_err(|error| CodexAgentSdkError::InvalidRequest(error.to_string()))
}

#[cfg(test)]
fn turn_schema(request: &Value) -> Result<String, CodexAgentSdkError> {
    turn_contract(request).map(|(schema, _)| schema)
}

fn turn_contract(request: &Value) -> Result<(String, BTreeSet<String>), CodexAgentSdkError> {
    let tools = match request.get("tools") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(tools)) => tools.as_slice(),
        Some(_) => {
            return Err(CodexAgentSdkError::InvalidRequest(
                "tools must be an array".to_string(),
            ));
        }
    };
    let mut names = BTreeSet::new();
    for tool in tools {
        let function = tool.get("function").unwrap_or(tool);
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                CodexAgentSdkError::InvalidRequest(
                    "tool definition is missing a non-empty name".to_string(),
                )
            })?;
        if !names.insert(name.to_string()) {
            return Err(CodexAgentSdkError::InvalidRequest(format!(
                "tool definition contains duplicate name '{name}'"
            )));
        }
        let arguments = function
            .get("input_schema")
            .or_else(|| function.get("parameters"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "object"}));
        if !arguments.is_object() {
            return Err(CodexAgentSdkError::InvalidRequest(format!(
                "tool '{name}' argument schema must be an object"
            )));
        }
    }

    let name_schema = if names.is_empty() {
        serde_json::json!({"type": "string", "const": "__no_host_tools__"})
    } else {
        serde_json::json!({
            "type": "string",
            "enum": names.iter().collect::<Vec<_>>(),
        })
    };
    let items = serde_json::json!({
        "type": "object",
        "properties": {
            "name": name_schema,
            "arguments_json": {
                "type": "string",
                "description": "A JSON object serialized as a string. It must satisfy the selected tool's argument schema in openclaudia_host_tools."
            },
        },
        "required": ["name", "arguments_json"],
        "additionalProperties": false,
    });
    let max_items = if tools.is_empty() {
        0
    } else {
        MAX_PARALLEL_TOOL_CALL_SLOTS
    };
    let schema = serde_json::to_string(&serde_json::json!({
        "type": "object",
        "properties": {
            "content": {
                "type": "string",
                "description": "Assistant text for this turn. It may be empty when host tool calls are requested."
            },
            "tool_calls": {
                "type": "array",
                "description": "Inert OpenClaudia host operations to validate and execute after this provider turn.",
                "maxItems": max_items,
                "items": items,
            }
        },
        "required": ["content", "tool_calls"],
        "additionalProperties": false,
    }))
    .map_err(|error| CodexAgentSdkError::InvalidRequest(error.to_string()))?;
    Ok((schema, names))
}

fn native_tool_item(item_type: &str) -> bool {
    matches!(
        item_type,
        "command_execution"
            | "file_change"
            | "mcp_tool_call"
            | "dynamic_tool_call"
            | "web_search"
            | "image_generation"
            | "computer_use"
    )
}

#[allow(clippy::too_many_lines)] // Parsing the bounded JSONL transcript as one state machine is easier to audit.
fn decode_turn(
    stdout: &[u8],
    allowed_tool_names: &BTreeSet<String>,
) -> Result<CodexAgentSdkTurn, CodexAgentSdkError> {
    let mut assistant_message = None;
    let mut usage = None;
    let mut completed = false;
    for raw_line in stdout.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        let event: Value = serde_json::from_slice(line).map_err(|error| {
            CodexAgentSdkError::InvalidOutput(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        let event_type = event
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if matches!(event_type, "item.started" | "item.completed") {
            let item = event
                .get("item")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    CodexAgentSdkError::InvalidOutput("item event is missing its item".to_string())
                })?;
            let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
            if native_tool_item(item_type) {
                return Err(CodexAgentSdkError::NativeToolUse(item_type.to_string()));
            }
            if event_type == "item.completed" && item_type == "agent_message" {
                let text = item.get("text").and_then(Value::as_str).ok_or_else(|| {
                    CodexAgentSdkError::InvalidOutput(
                        "completed agent message is missing text".to_string(),
                    )
                })?;
                assistant_message = Some(text.to_string());
            }
        } else if event_type == "turn.completed" {
            completed = true;
            let raw_usage = event.get("usage").cloned().unwrap_or(Value::Null);
            usage = Some(TokenUsage {
                input_tokens: raw_usage
                    .get("input_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                output_tokens: raw_usage
                    .get("output_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                cache_read_tokens: raw_usage
                    .get("cached_input_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                cache_write_tokens: raw_usage
                    .get("cache_write_input_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            });
        } else if matches!(event_type, "turn.failed" | "error") {
            let diagnostic = event
                .pointer("/error/message")
                .or_else(|| event.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("Codex reported an unspecified failure");
            return Err(CodexAgentSdkError::Process(
                crate::secrets::SafeDiagnostic::from_untrusted(diagnostic).to_string(),
            ));
        }
    }
    if !completed {
        return Err(CodexAgentSdkError::InvalidOutput(
            "missing turn.completed event".to_string(),
        ));
    }
    let assistant_message = assistant_message.ok_or_else(|| {
        CodexAgentSdkError::InvalidOutput("missing completed agent message".to_string())
    })?;
    let structured: StructuredTurn = serde_json::from_str(&assistant_message).map_err(|error| {
        CodexAgentSdkError::InvalidOutput(
            crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
        )
    })?;
    if structured.tool_calls.len() > MAX_PARALLEL_TOOL_CALL_SLOTS {
        return Err(CodexAgentSdkError::InvalidOutput(format!(
            "returned {} tool calls, exceeding the {}-call limit",
            structured.tool_calls.len(),
            MAX_PARALLEL_TOOL_CALL_SLOTS
        )));
    }
    let mut tool_calls = Vec::with_capacity(structured.tool_calls.len());
    for call in structured.tool_calls {
        let name = call.name.trim();
        if name.is_empty() {
            return Err(CodexAgentSdkError::InvalidOutput(
                "returned a host tool call with an empty name".to_string(),
            ));
        }
        if !allowed_tool_names.contains(name) {
            return Err(CodexAgentSdkError::InvalidOutput(format!(
                "returned tool '{name}' that was not advertised by OpenClaudia"
            )));
        }
        let arguments: Value = serde_json::from_str(&call.arguments_json).map_err(|error| {
            CodexAgentSdkError::InvalidOutput(format!(
                "returned invalid arguments_json for tool '{name}': {}",
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string())
            ))
        })?;
        if !arguments.is_object() {
            return Err(CodexAgentSdkError::InvalidOutput(format!(
                "returned non-object arguments_json for tool '{name}'"
            )));
        }
        tool_calls.push(ToolCall {
            id: format!("codex_sdk_{}", uuid::Uuid::new_v4()),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: name.to_string(),
                arguments: arguments.to_string(),
            },
        });
    }
    if structured.content.trim().is_empty() && tool_calls.is_empty() {
        return Err(CodexAgentSdkError::InvalidOutput(
            "returned neither assistant content nor host tool calls".to_string(),
        ));
    }
    Ok(CodexAgentSdkTurn {
        content: structured.content,
        tool_calls,
        usage: usage.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn bounded_turn_rejects_cancelled_authority_before_spawn() {
        let sdk = CodexAgentSdk {
            binary: PathBuf::from("must-not-spawn-codex"),
        };
        let cancellation = crate::runtime::CancellationTree::new().root();
        let _receipt = cancellation.cancel(crate::runtime::CancellationReason::User);
        let error = sdk
            .complete_turn_bounded(
                &json!({"model": "gpt-5", "messages": []}),
                "high",
                tokio::time::Instant::now() + Duration::from_secs(30),
                cancellation,
            )
            .await
            .expect_err("cancelled turn");
        assert!(matches!(error, CodexAgentSdkError::Cancelled(_)));
    }

    #[tokio::test]
    async fn bounded_turn_rejects_expired_deadline_before_spawn() {
        let sdk = CodexAgentSdk {
            binary: PathBuf::from("must-not-spawn-codex"),
        };
        let error = sdk
            .complete_turn_bounded(
                &json!({"model": "gpt-5", "messages": []}),
                "high",
                tokio::time::Instant::now(),
                crate::runtime::CancellationTree::new().root(),
            )
            .await
            .expect_err("expired deadline");
        assert!(matches!(error, CodexAgentSdkError::Deadline));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bounded_turn_cancellation_kills_and_reaps_a_running_child() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("fake SDK directory");
        let binary = directory.path().join("codex-blocking");
        let pid_path = directory.path().join("child.pid");
        let script = format!(
            "#!/bin/sh\nset -eu\ncat >/dev/null\nprintf '%s' \"$$\" > '{}'\nexec sleep 30\n",
            pid_path.display()
        );
        std::fs::write(&binary, script).expect("fake SDK executable");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .expect("fake SDK permissions");

        let cancellation = crate::runtime::CancellationTree::new().root();
        let turn_cancellation = cancellation.clone();
        let turn = tokio::spawn(async move {
            CodexAgentSdk { binary }
                .complete_turn_bounded(
                    &json!({
                        "model": "gpt-test",
                        "input": [{
                            "role": "user",
                            "content": [{"type": "input_text", "text": "hello"}],
                        }],
                    }),
                    "high",
                    tokio::time::Instant::now() + Duration::from_secs(30),
                    turn_cancellation,
                )
                .await
        });

        for _ in 0..100 {
            if pid_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let pid = std::fs::read_to_string(&pid_path).expect("running child PID");
        let _receipt = cancellation.cancel(crate::runtime::CancellationReason::User);
        let error = tokio::time::timeout(Duration::from_secs(2), turn)
            .await
            .expect("bounded cancellation return")
            .expect("turn task")
            .expect_err("cancelled turn");
        assert!(matches!(error, CodexAgentSdkError::Cancelled(_)));
        #[cfg(target_os = "linux")]
        assert!(
            !Path::new("/proc").join(pid.trim()).exists(),
            "cancelled child must be reaped"
        );
    }

    #[test]
    fn prompt_removes_native_transport_controls_but_preserves_history() {
        let prompt = transport_prompt(&json!({
            "model": "gpt-test",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "hello"}]}],
            "tools": [{"type": "function", "name": "read_file"}],
            "tool_choice": "auto",
            "parallel_tool_calls": true,
            "stream": true,
        }))
        .expect("transport prompt");
        let payload: Value = serde_json::from_str(
            prompt
                .strip_prefix(TRANSPORT_INPUT_PREFIX)
                .expect("transport prefix"),
        )
        .expect("JSON payload");
        assert!(payload.get("tools").is_none());
        assert_eq!(payload["openclaudia_host_tools"][0]["name"], "read_file");
        assert!(payload.get("tool_choice").is_none());
        assert!(payload.get("parallel_tool_calls").is_none());
        assert!(payload.get("stream").is_none());
        assert_eq!(payload["input"][0]["content"][0]["text"], "hello");
    }

    #[test]
    fn schema_encodes_only_advertised_host_tools() {
        let encoded = turn_schema(&json!({
            "tools": [{
                "type": "function",
                "name": "read_file",
                "description": "Read one file",
                "parameters": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": false
                }
            }]
        }))
        .expect("turn schema");
        let schema: Value = serde_json::from_str(&encoded).expect("schema JSON");
        assert_eq!(
            schema.pointer("/properties/tool_calls/items/properties/name/enum/0"),
            Some(&json!("read_file"))
        );
        assert_eq!(
            schema.pointer("/properties/tool_calls/items/additionalProperties"),
            Some(&json!(false))
        );
    }

    #[test]
    fn decoder_normalizes_structured_turn_and_usage() {
        let transcript = concat!(
            "{\"type\":\"thread.started\",\"thread_id\":\"thread\"}\n",
            "{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"{\\\"content\\\":\\\"working\\\",\\\"tool_calls\\\":[{\\\"name\\\":\\\"read_file\\\",\\\"arguments_json\\\":\\\"{\\\\\\\"path\\\\\\\":\\\\\\\"README.md\\\\\\\"}\\\"}]}\"}}\n",
            "{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":12,\"cached_input_tokens\":4,\"cache_write_input_tokens\":3,\"output_tokens\":7}}\n",
        );
        let turn = decode_turn(
            transcript.as_bytes(),
            &BTreeSet::from(["read_file".to_string()]),
        )
        .expect("decode");
        assert!(turn.needs_followup());
        assert_eq!(turn.content, "working");
        assert_eq!(turn.tool_calls[0].function.name, "read_file");
        assert_eq!(turn.usage.input_tokens, 12);
        assert_eq!(turn.usage.cache_read_tokens, 4);
        assert_eq!(turn.usage.cache_write_tokens, 3);
        assert_eq!(turn.usage.output_tokens, 7);
    }

    #[test]
    fn decoder_rejects_native_tools_and_unadvertised_host_tools() {
        let native = concat!(
            "{\"type\":\"item.started\",\"item\":{\"type\":\"command_execution\"}}\n",
            "{\"type\":\"turn.completed\",\"usage\":{}}\n",
        );
        assert!(matches!(
            decode_turn(native.as_bytes(), &BTreeSet::new()),
            Err(CodexAgentSdkError::NativeToolUse(_))
        ));

        let unadvertised = concat!(
            "{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"{\\\"content\\\":\\\"attempted\\\",\\\"tool_calls\\\":[{\\\"name\\\":\\\"shell\\\",\\\"arguments_json\\\":\\\"{}\\\"}]}\"}}\n",
            "{\"type\":\"turn.completed\",\"usage\":{}}\n",
        );
        let error = decode_turn(
            unadvertised.as_bytes(),
            &BTreeSet::from(["read_file".to_string()]),
        )
        .expect_err("unadvertised tool must fail closed");
        assert!(error.to_string().contains("was not advertised"));
    }

    #[tokio::test]
    async fn bounded_reader_accepts_the_limit_and_rejects_one_extra_byte() {
        assert_eq!(
            read_bounded(&b"abc"[..], 3).await.expect("exact limit"),
            b"abc"
        );
        assert!(matches!(
            read_bounded(&b"abcd"[..], 3).await,
            Err(CodexAgentSdkError::OutputTooLarge(3))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn complete_turn_constrains_the_executable_and_decodes_its_turn() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("fake SDK directory");
        let binary = directory.path().join("codex-fake");
        let args_path = directory.path().join("args.txt");
        let stdin_path = directory.path().join("stdin.txt");
        let script = format!(
            "#!/bin/sh\nset -eu\nif env | grep -q '^OPENAI_API_KEY=' || env | grep -q '^CODEX_ACCESS_TOKEN='; then exit 9; fi\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\nprintf '%s\\n' '{{\"type\":\"item.completed\",\"item\":{{\"type\":\"agent_message\",\"text\":\"{{\\\"content\\\":\\\"routed\\\",\\\"tool_calls\\\":[]}}\"}}}}' '{{\"type\":\"turn.completed\",\"usage\":{{\"input_tokens\":11,\"output_tokens\":3}}}}'\n",
            args_path.display(),
            stdin_path.display(),
        );
        std::fs::write(&binary, script).expect("fake SDK executable");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .expect("fake SDK permissions");

        let sdk = CodexAgentSdk { binary };
        let turn = sdk
            .complete_turn(
                &json!({
                    "model": "gpt-test",
                    "input": [{"role": "user", "content": [{"type": "input_text", "text": "hello"}]}],
                    "tools": [{"type": "function", "name": "read_file", "parameters": {"type": "object"}}],
                    "stream": true,
                }),
                "high",
            )
            .await
            .expect("fake SDK turn");

        assert_eq!(turn.content, "routed");
        assert!(turn.tool_calls.is_empty());
        assert_eq!(turn.usage.input_tokens, 11);
        assert_eq!(turn.usage.output_tokens, 3);

        let args = std::fs::read_to_string(args_path).expect("captured args");
        for required in [
            "exec",
            "--json",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--output-schema",
            "gpt-test",
        ] {
            assert!(
                args.lines().any(|arg| arg == required),
                "missing {required}"
            );
        }
        for feature in DISABLED_NATIVE_FEATURES {
            assert!(args.lines().any(|arg| arg == *feature), "missing {feature}");
        }
        assert!(args.contains("model_reasoning_effort=\"high\""));

        let stdin = std::fs::read_to_string(stdin_path).expect("captured stdin");
        assert!(stdin.starts_with(TRANSPORT_INPUT_PREFIX));
        assert!(stdin.contains("hello"));
        assert!(stdin.contains("openclaudia_host_tools"));
        assert!(stdin.contains("read_file"));
    }
}

//! Supported Claude subscription transport through Anthropic's own executable.
//!
//! The Claude Agent SDK does not currently publish a Rust package. Anthropic's
//! documented integration for other languages is the unmodified `claude -p`
//! executable. This module constrains that executable to model-transport duty:
//! safe mode disables filesystem customizations, Claude's tools are disabled,
//! MCP is empty and strict, and session persistence is off. Tool selections are
//! returned as typed data for `OpenClaudia`'s own policy and execution loop.

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

use crate::session::TokenUsage;
use crate::tools::{FunctionCall, ToolCall, MAX_PARALLEL_TOOL_CALL_SLOTS};

/// Maximum stdout retained from one Agent SDK turn.
pub const MAX_AGENT_SDK_STDOUT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum diagnostic stderr retained from one Agent SDK turn.
pub const MAX_AGENT_SDK_STDERR_BYTES: usize = 64 * 1024;
/// Absolute wall-clock ceiling for one Agent SDK model turn.
pub const AGENT_SDK_TURN_TIMEOUT: Duration = Duration::from_secs(600);
/// Short ceiling for checking the owning executable's login state.
pub const AGENT_SDK_STATUS_TIMEOUT: Duration = Duration::from_secs(10);

const EMPTY_MCP_CONFIG: &str = r#"{"mcpServers":{}}"#;
const TRANSPORT_SYSTEM_PREFIX: &str = "You are the inference backend inside OpenClaudia. OpenClaudia is the sole agent harness and authority for tool execution. The Claude Code native tool interface is not the OpenClaudia tool interface: never invoke an OpenClaudia tool name as a Claude Code tool. The available OpenClaudia operations and their argument schemas are choices inside the required structured_output schema, not Claude Code tools. When an OpenClaudia tool is needed, immediately return it in the structured_output tool_calls array; do not try it through Claude Code first. The only Claude-side action for every turn is returning the required structured output. A non-empty tool_calls array requests tools from OpenClaudia; an empty array is a final assistant response. Follow the host system instructions below.\n\n";
const TRANSPORT_INPUT_PREFIX: &str = "The following JSON is the current Anthropic-style model request assembled by OpenClaudia. Treat messages as ordered conversation history. The tool catalog was moved into the required structured_output schema so only OpenClaudia can execute those operations. Return only the next assistant turn through structured_output.\n\n";

/// A resolved, immutable path to Anthropic's unmodified Agent SDK executable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeAgentSdk {
    binary: PathBuf,
}

/// One normalized model turn returned by the Agent SDK transport.
#[derive(Debug, Clone)]
pub struct ClaudeAgentSdkTurn {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: TokenUsage,
}

impl ClaudeAgentSdkTurn {
    #[must_use]
    pub const fn needs_followup(&self) -> bool {
        !self.tool_calls.is_empty()
    }
}

/// Failures at the owning-executable transport boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClaudeAgentSdkError {
    #[error("Claude Agent SDK executable was not found; install Claude Code and run `claude auth login`")]
    NotInstalled,
    #[error("Claude Agent SDK executable path could not be pinned: {0}")]
    InvalidExecutable(String),
    #[error("Claude Agent SDK login status could not be checked: {0}")]
    Status(String),
    #[error("Claude Agent SDK is not logged in; run `claude auth login`")]
    NotAuthenticated,
    #[error("Claude Agent SDK request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Claude Agent SDK process could not be started: {0}")]
    Spawn(String),
    #[error("Claude Agent SDK process timed out after {0} seconds")]
    Timeout(u64),
    #[error("Claude Agent SDK output exceeded its {0}-byte limit")]
    OutputTooLarge(usize),
    #[error("Claude Agent SDK process failed: {0}")]
    Process(String),
    #[error("Claude Agent SDK returned invalid JSON: {0}")]
    InvalidOutput(String),
}

#[derive(Debug, Deserialize)]
struct ClaudeAuthStatus {
    #[serde(default, rename = "loggedIn", alias = "logged_in")]
    logged_in: bool,
}

#[derive(Debug, Deserialize)]
struct RawSdkOutput {
    #[serde(default)]
    is_error: bool,
    #[serde(default)]
    result: String,
    #[serde(default, alias = "structuredOutput")]
    structured_output: Option<StructuredTurn>,
    #[serde(default)]
    usage: RawSdkUsage,
}

#[derive(Debug, Deserialize)]
struct StructuredTurn {
    content: String,
    tool_calls: Vec<StructuredToolCall>,
}

#[derive(Debug, Deserialize)]
struct StructuredToolCall {
    name: String,
    arguments: serde_json::Map<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[allow(clippy::struct_field_names)] // These names intentionally mirror Claude's JSON usage schema.
struct RawSdkUsage {
    #[serde(default)]
    input_tokens: u64,
    #[serde(default)]
    output_tokens: u64,
    #[serde(default)]
    cache_read_input_tokens: u64,
    #[serde(default)]
    cache_creation_input_tokens: u64,
}

impl ClaudeAgentSdk {
    /// Resolve and pin Anthropic's executable through the current startup PATH.
    ///
    /// # Errors
    ///
    /// Returns an error when `claude` is missing or cannot be canonicalized.
    pub fn discover() -> Result<Self, ClaudeAgentSdkError> {
        let binary = which::which("claude").map_err(|_| ClaudeAgentSdkError::NotInstalled)?;
        let binary = binary.canonicalize().map_err(|error| {
            ClaudeAgentSdkError::InvalidExecutable(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        if !binary.is_file() {
            return Err(ClaudeAgentSdkError::InvalidExecutable(
                "resolved path is not a regular file".to_string(),
            ));
        }
        Ok(Self { binary })
    }

    /// Return the pinned executable path without exposing any credential data.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// Ask the owning executable whether it has a usable login.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for process, timeout, or malformed status output.
    pub async fn require_authenticated(&self) -> Result<(), ClaudeAgentSdkError> {
        let mut command = Command::new(&self.binary);
        command
            .args(["auth", "status", "--json"])
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("ANTHROPIC_AUTH_TOKEN")
            .kill_on_drop(true);
        let output = tokio::time::timeout(AGENT_SDK_STATUS_TIMEOUT, command.output())
            .await
            .map_err(|_| ClaudeAgentSdkError::Timeout(AGENT_SDK_STATUS_TIMEOUT.as_secs()))?
            .map_err(|error| {
                ClaudeAgentSdkError::Status(
                    crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
                )
            })?;
        if !output.status.success() {
            return Err(ClaudeAgentSdkError::NotAuthenticated);
        }
        let status: ClaudeAuthStatus = serde_json::from_slice(&output.stdout).map_err(|error| {
            ClaudeAgentSdkError::Status(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        if !status.logged_in {
            return Err(ClaudeAgentSdkError::NotAuthenticated);
        }
        Ok(())
    }

    /// Execute one constrained model turn through Anthropic's Agent SDK.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed requests, process failures, bounded
    /// I/O violations, timeouts, or invalid structured model output.
    #[allow(clippy::too_many_lines)] // One owned process lifecycle keeps cleanup and I/O limits together.
    pub async fn complete_turn(
        &self,
        request: &Value,
        effort: &str,
    ) -> Result<ClaudeAgentSdkTurn, ClaudeAgentSdkError> {
        let model = request
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| !model.trim().is_empty())
            .ok_or_else(|| {
                ClaudeAgentSdkError::InvalidRequest("missing non-empty model".to_string())
            })?;
        let system = extract_system_prompt(request)?;
        let prompt = transport_prompt(request)?;
        let (turn_schema, allowed_tool_names) = turn_contract(request)?;
        let mut system_file = tempfile::NamedTempFile::new().map_err(|error| {
            ClaudeAgentSdkError::Spawn(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        system_file
            .write_all(format!("{TRANSPORT_SYSTEM_PREFIX}{system}").as_bytes())
            .and_then(|()| system_file.flush())
            .map_err(|error| {
                ClaudeAgentSdkError::Spawn(
                    crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
                )
            })?;

        let mut command = Command::new(&self.binary);
        command
            .arg("-p")
            .args(["--output-format", "json"])
            .args(["--model", model])
            .args(["--effort", normalize_effort(effort)])
            .arg("--safe-mode")
            .args(["--tools", ""])
            .arg("--disable-slash-commands")
            .arg("--no-chrome")
            .arg("--no-session-persistence")
            .arg("--strict-mcp-config")
            .args(["--mcp-config", EMPTY_MCP_CONFIG])
            .arg("--system-prompt-file")
            .arg(system_file.path())
            .args(["--json-schema", turn_schema.as_str()])
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("ANTHROPIC_AUTH_TOKEN")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        tracing::info!(
            backend = "claude_agent_sdk",
            model,
            tools = request
                .get("tools")
                .and_then(|value| value.as_array())
                .map_or(0, Vec::len),
            "sending constrained provider request through Anthropic-owned executable"
        );

        let mut child = command.spawn().map_err(|error| {
            ClaudeAgentSdkError::Spawn(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            ClaudeAgentSdkError::Spawn("child stdin was not available".to_string())
        })?;
        stdin.write_all(prompt.as_bytes()).await.map_err(|error| {
            ClaudeAgentSdkError::Process(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        stdin.shutdown().await.map_err(|error| {
            ClaudeAgentSdkError::Process(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
        drop(stdin);

        let stdout = child.stdout.take().ok_or_else(|| {
            ClaudeAgentSdkError::Spawn("child stdout was not available".to_string())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            ClaudeAgentSdkError::Spawn("child stderr was not available".to_string())
        })?;
        let stdout_task = tokio::spawn(read_bounded(stdout, MAX_AGENT_SDK_STDOUT_BYTES));
        let stderr_task = tokio::spawn(read_bounded(stderr, MAX_AGENT_SDK_STDERR_BYTES));
        let status = if let Ok(status) =
            tokio::time::timeout(AGENT_SDK_TURN_TIMEOUT, child.wait()).await
        {
            status.map_err(|error| {
                ClaudeAgentSdkError::Process(
                    crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
                )
            })?
        } else {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(ClaudeAgentSdkError::Timeout(
                AGENT_SDK_TURN_TIMEOUT.as_secs(),
            ));
        };
        let stdout = join_reader(stdout_task).await?;
        let stderr = join_reader(stderr_task).await?;
        if !status.success() {
            return Err(ClaudeAgentSdkError::Process(process_diagnostic(
                &stdout, &stderr,
            )));
        }
        decode_turn(&stdout, &allowed_tool_names)
    }
}

async fn join_reader(
    task: tokio::task::JoinHandle<Result<Vec<u8>, ClaudeAgentSdkError>>,
) -> Result<Vec<u8>, ClaudeAgentSdkError> {
    task.await.map_err(|error| {
        ClaudeAgentSdkError::Process(
            crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
        )
    })?
}

async fn read_bounded<R: AsyncRead + Unpin>(
    reader: R,
    limit: usize,
) -> Result<Vec<u8>, ClaudeAgentSdkError> {
    let take_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(take_limit)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| {
            ClaudeAgentSdkError::Process(
                crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
            )
        })?;
    if bytes.len() > limit {
        return Err(ClaudeAgentSdkError::OutputTooLarge(limit));
    }
    Ok(bytes)
}

fn process_diagnostic(stdout: &[u8], stderr: &[u8]) -> String {
    let diagnostic = if stderr.is_empty() {
        serde_json::from_slice::<RawSdkOutput>(stdout)
            .ok()
            .map(|output| output.result)
            .filter(|result| !result.trim().is_empty())
            .unwrap_or_else(|| String::from_utf8_lossy(stdout).into_owned())
    } else {
        String::from_utf8_lossy(stderr).into_owned()
    };
    crate::secrets::SafeDiagnostic::from_untrusted(&diagnostic).to_string()
}

fn normalize_effort(effort: &str) -> &'static str {
    match effort.trim().to_ascii_lowercase().as_str() {
        "high" => "high",
        "xhigh" => "xhigh",
        "max" => "max",
        "medium" | "med" => "medium",
        _ => "low",
    }
}

fn extract_system_prompt(request: &Value) -> Result<String, ClaudeAgentSdkError> {
    match request.get("system") {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(system)) => Ok(system.clone()),
        Some(Value::Array(blocks)) => {
            let mut system = String::new();
            for block in blocks {
                let text = block.get("text").and_then(Value::as_str).ok_or_else(|| {
                    ClaudeAgentSdkError::InvalidRequest(
                        "system array contains a non-text block".to_string(),
                    )
                })?;
                if !system.is_empty() {
                    system.push_str("\n\n");
                }
                system.push_str(text);
            }
            Ok(system)
        }
        Some(_) => Err(ClaudeAgentSdkError::InvalidRequest(
            "system must be a string or text-block array".to_string(),
        )),
    }
}

fn transport_prompt(request: &Value) -> Result<String, ClaudeAgentSdkError> {
    let mut payload = request.clone();
    let object = payload.as_object_mut().ok_or_else(|| {
        ClaudeAgentSdkError::InvalidRequest("request body must be an object".to_string())
    })?;
    object.remove("system");
    object.remove("stream");
    object.remove("tools");
    object.remove("tool_choice");
    serde_json::to_string(&payload)
        .map(|json| format!("{TRANSPORT_INPUT_PREFIX}{json}"))
        .map_err(|error| ClaudeAgentSdkError::InvalidRequest(error.to_string()))
}

#[cfg(test)]
fn turn_schema(request: &Value) -> Result<String, ClaudeAgentSdkError> {
    turn_contract(request).map(|(schema, _)| schema)
}

fn turn_contract(request: &Value) -> Result<(String, BTreeSet<String>), ClaudeAgentSdkError> {
    let tools = match request.get("tools") {
        None | Some(Value::Null) => &[][..],
        Some(Value::Array(tools)) => tools.as_slice(),
        Some(_) => {
            return Err(ClaudeAgentSdkError::InvalidRequest(
                "tools must be an array".to_string(),
            ))
        }
    };
    let mut names = BTreeSet::new();
    let mut variants = Vec::with_capacity(tools.len());
    for tool in tools {
        let function = tool.get("function").unwrap_or(tool);
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                ClaudeAgentSdkError::InvalidRequest(
                    "tool definition is missing a non-empty name".to_string(),
                )
            })?;
        if !names.insert(name.to_string()) {
            return Err(ClaudeAgentSdkError::InvalidRequest(format!(
                "tool definition contains duplicate name '{name}'"
            )));
        }
        let arguments = function
            .get("input_schema")
            .or_else(|| function.get("parameters"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "object"}));
        if !arguments.is_object() {
            return Err(ClaudeAgentSdkError::InvalidRequest(format!(
                "tool '{name}' argument schema must be an object"
            )));
        }
        let mut variant = serde_json::json!({
            "type": "object",
            "properties": {
                "name": {"type": "string", "const": name},
                "arguments": arguments,
            },
            "required": ["name", "arguments"],
            "additionalProperties": false,
        });
        if let Some(description) = function.get("description").and_then(Value::as_str) {
            variant["description"] = Value::String(description.to_string());
        }
        variants.push(variant);
    }

    let items = if variants.is_empty() {
        serde_json::json!({"type": "object"})
    } else {
        serde_json::json!({"oneOf": variants})
    };
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
                "minLength": 1,
                "description": "Assistant text for this turn. For a tool request, briefly state the immediate operation. For a terminal turn, return the complete response required by the host system."
            },
            "tool_calls": {
                "type": "array",
                "description": "OpenClaudia host operations to execute before the next model turn. This is data returned to OpenClaudia, not a Claude Code tool invocation.",
                "maxItems": max_items,
                "items": items,
            }
        },
        "required": ["content", "tool_calls"],
        "additionalProperties": false,
    }))
    .map_err(|error| ClaudeAgentSdkError::InvalidRequest(error.to_string()))?;
    Ok((schema, names))
}

fn decode_turn(
    stdout: &[u8],
    allowed_tool_names: &BTreeSet<String>,
) -> Result<ClaudeAgentSdkTurn, ClaudeAgentSdkError> {
    let raw: RawSdkOutput = serde_json::from_slice(stdout).map_err(|error| {
        ClaudeAgentSdkError::InvalidOutput(
            crate::secrets::SafeDiagnostic::from_untrusted(&error.to_string()).to_string(),
        )
    })?;
    if raw.is_error {
        return Err(ClaudeAgentSdkError::Process(
            crate::secrets::SafeDiagnostic::from_untrusted(&raw.result).to_string(),
        ));
    }
    let structured = raw.structured_output.ok_or_else(|| {
        ClaudeAgentSdkError::InvalidOutput("missing structured_output".to_string())
    })?;
    if structured.tool_calls.len() > MAX_PARALLEL_TOOL_CALL_SLOTS {
        return Err(ClaudeAgentSdkError::InvalidOutput(format!(
            "returned {} tool calls, exceeding the {}-call limit",
            structured.tool_calls.len(),
            MAX_PARALLEL_TOOL_CALL_SLOTS
        )));
    }
    let mut tool_calls = Vec::with_capacity(structured.tool_calls.len());
    for call in structured.tool_calls {
        let name = call.name.trim();
        if name.is_empty() {
            return Err(ClaudeAgentSdkError::InvalidOutput(
                "tool call has an empty name".to_string(),
            ));
        }
        if !allowed_tool_names.contains(name) {
            return Err(ClaudeAgentSdkError::InvalidOutput(format!(
                "returned tool '{name}' that was not advertised by OpenClaudia"
            )));
        }
        tool_calls.push(ToolCall {
            id: format!("sdk_{}", uuid::Uuid::new_v4()),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: name.to_string(),
                arguments: Value::Object(call.arguments).to_string(),
            },
        });
    }
    Ok(ClaudeAgentSdkTurn {
        content: structured.content,
        tool_calls,
        usage: TokenUsage {
            input_tokens: raw.usage.input_tokens,
            output_tokens: raw.usage.output_tokens,
            cache_read_tokens: raw.usage.cache_read_input_tokens,
            cache_write_tokens: raw.usage.cache_creation_input_tokens,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn transport_prompt_removes_system_stream_and_tool_catalog_but_preserves_history() {
        let prompt = transport_prompt(&json!({
            "model": "claude-test",
            "system": [{"type": "text", "text": "host"}],
            "stream": true,
            "messages": [{"role": "user", "content": "hello"}],
            "tools": [{"name": "read"}],
            "tool_choice": {"type": "auto"},
        }))
        .expect("transport prompt");
        let json = prompt
            .strip_prefix(TRANSPORT_INPUT_PREFIX)
            .expect("transport prefix");
        let payload: Value = serde_json::from_str(json).expect("JSON payload");
        assert!(payload.get("system").is_none());
        assert!(payload.get("stream").is_none());
        assert!(payload.get("tools").is_none());
        assert!(payload.get("tool_choice").is_none());
        assert_eq!(payload["messages"][0]["content"], "hello");
    }

    #[test]
    fn turn_schema_encodes_each_host_tool_as_structured_output_data() {
        let encoded = turn_schema(&json!({
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read one file",
                    "input_schema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                        "additionalProperties": false
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "grep",
                        "description": "Search text",
                        "parameters": {
                            "type": "object",
                            "properties": {"pattern": {"type": "string"}},
                            "required": ["pattern"]
                        }
                    }
                }
            ]
        }))
        .expect("turn schema");
        let schema: Value = serde_json::from_str(&encoded).expect("schema JSON");
        let variants = schema
            .pointer("/properties/tool_calls/items/oneOf")
            .and_then(Value::as_array)
            .expect("tool variants");
        assert_eq!(variants.len(), 2);
        assert_eq!(
            variants[0].pointer("/properties/name/const"),
            Some(&json!("read_file"))
        );
        assert_eq!(
            variants[0].pointer("/properties/arguments/required/0"),
            Some(&json!("path"))
        );
        assert_eq!(
            variants[1].pointer("/properties/name/const"),
            Some(&json!("grep"))
        );
    }

    #[test]
    fn no_tool_turn_schema_forbids_host_tool_requests() {
        let encoded = turn_schema(&json!({})).expect("turn schema");
        let schema: Value = serde_json::from_str(&encoded).expect("schema JSON");
        assert_eq!(
            schema.pointer("/properties/tool_calls/maxItems"),
            Some(&json!(0))
        );
        assert_eq!(
            schema.pointer("/properties/content/minLength"),
            Some(&json!(1))
        );
    }

    #[test]
    fn nonzero_process_uses_structured_stdout_diagnostic_when_stderr_is_empty() {
        let stdout = serde_json::to_vec(&json!({
            "is_error": true,
            "result": "API rejected the structured output schema"
        }))
        .expect("error output");
        assert_eq!(
            process_diagnostic(&stdout, &[]),
            "API rejected the structured output schema"
        );
    }

    #[test]
    fn system_text_blocks_preserve_order() {
        let system = extract_system_prompt(&json!({
            "system": [
                {"type": "text", "text": "first", "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": "second"}
            ]
        }))
        .expect("system prompt");
        assert_eq!(system, "first\n\nsecond");
    }

    #[test]
    fn decoder_normalizes_structured_tool_calls_and_usage() {
        let raw = json!({
            "is_error": false,
            "result": "",
            "structured_output": {
                "content": "",
                "tool_calls": [{"name": "read", "arguments": {"file_path": "README.md"}}]
            },
            "usage": {
                "input_tokens": 12,
                "output_tokens": 7,
                "cache_read_input_tokens": 4,
                "cache_creation_input_tokens": 3
            }
        });
        let turn = decode_turn(
            &serde_json::to_vec(&raw).expect("serialize"),
            &BTreeSet::from(["read".to_string()]),
        )
        .expect("decode");
        assert!(turn.needs_followup());
        assert_eq!(turn.tool_calls[0].function.name, "read");
        assert_eq!(
            serde_json::from_str::<Value>(&turn.tool_calls[0].function.arguments)
                .expect("arguments"),
            json!({"file_path": "README.md"})
        );
        assert_eq!(turn.usage.input_tokens, 12);
        assert_eq!(turn.usage.output_tokens, 7);
        assert_eq!(turn.usage.cache_read_tokens, 4);
        assert_eq!(turn.usage.cache_write_tokens, 3);
    }

    #[test]
    fn decoder_rejects_unstructured_or_error_outputs() {
        let missing =
            serde_json::to_vec(&json!({"is_error": false, "result": "text"})).expect("serialize");
        assert!(matches!(
            decode_turn(&missing, &BTreeSet::new()),
            Err(ClaudeAgentSdkError::InvalidOutput(_))
        ));

        let failed =
            serde_json::to_vec(&json!({"is_error": true, "result": "failure"})).expect("serialize");
        assert!(matches!(
            decode_turn(&failed, &BTreeSet::new()),
            Err(ClaudeAgentSdkError::Process(_))
        ));
    }

    #[test]
    fn decoder_rejects_tool_names_outside_the_host_catalog() {
        let raw = serde_json::to_vec(&json!({
            "is_error": false,
            "structured_output": {
                "content": "attempted tool request",
                "tool_calls": [{"name": "Bash", "arguments": {"command": "id"}}]
            }
        }))
        .expect("serialize");
        let error = decode_turn(&raw, &BTreeSet::from(["read_file".to_string()]))
            .expect_err("unadvertised tool must fail closed");
        assert!(error.to_string().contains("was not advertised"));
    }

    #[test]
    fn decoder_rejects_more_calls_than_the_host_parallelism_limit() {
        let calls = (0..=MAX_PARALLEL_TOOL_CALL_SLOTS)
            .map(|_| json!({"name": "read_file", "arguments": {"path": "Cargo.toml"}}))
            .collect::<Vec<_>>();
        let raw = serde_json::to_vec(&json!({
            "is_error": false,
            "structured_output": {
                "content": "too many requests",
                "tool_calls": calls
            }
        }))
        .expect("serialize");
        let error = decode_turn(&raw, &BTreeSet::from(["read_file".to_string()]))
            .expect_err("excess tool calls must fail closed");
        assert!(error.to_string().contains("exceeding"));
    }

    #[tokio::test]
    async fn bounded_reader_accepts_the_limit_and_rejects_one_extra_byte() {
        assert_eq!(
            read_bounded(&b"abc"[..], 3).await.expect("exact limit"),
            b"abc"
        );
        assert!(matches!(
            read_bounded(&b"abcd"[..], 3).await,
            Err(ClaudeAgentSdkError::OutputTooLarge(3))
        ));
    }

    #[test]
    fn effort_mapping_is_explicit_and_bounded() {
        assert_eq!(normalize_effort("medium"), "medium");
        assert_eq!(normalize_effort("xhigh"), "xhigh");
        assert_eq!(normalize_effort("max"), "max");
        assert_eq!(normalize_effort("unexpected"), "low");
    }

    #[test]
    fn auth_status_accepts_the_claude_cli_camel_case_shape() {
        let status: ClaudeAuthStatus =
            serde_json::from_value(json!({"loggedIn": true})).expect("Claude auth status");
        assert!(status.logged_in);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn complete_turn_constrains_the_executable_and_decodes_its_turn() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("fake SDK directory");
        let binary = directory.path().join("claude-fake");
        let args_path = directory.path().join("args.txt");
        let stdin_path = directory.path().join("stdin.txt");
        let system_path = directory.path().join("system.txt");
        let script = format!(
            "#!/bin/sh\nset -eu\nif env | grep -q '^ANTHROPIC_API_KEY=' || env | grep -q '^ANTHROPIC_AUTH_TOKEN='; then exit 9; fi\nprintf '%s\\n' \"$@\" > '{}'\ncat > '{}'\nprevious=''\nfor current in \"$@\"; do\n  if [ \"$previous\" = '--system-prompt-file' ]; then cp \"$current\" '{}'; fi\n  previous=\"$current\"\ndone\nprintf '%s' '{{\"is_error\":false,\"structured_output\":{{\"content\":\"routed\",\"tool_calls\":[]}},\"usage\":{{\"input_tokens\":11,\"output_tokens\":3}}}}'\n",
            args_path.display(),
            stdin_path.display(),
            system_path.display(),
        );
        std::fs::write(&binary, script).expect("fake SDK executable");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .expect("fake SDK permissions");

        let sdk = ClaudeAgentSdk { binary };
        let turn = sdk
            .complete_turn(
                &json!({
                    "model": "claude-test",
                    "system": [{"type": "text", "text": "host authority"}],
                    "messages": [{"role": "user", "content": "hello"}],
                    "tools": [{"name": "read_file", "input_schema": {"type": "object"}}],
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
            "-p",
            "--safe-mode",
            "--tools",
            "--disable-slash-commands",
            "--no-chrome",
            "--no-session-persistence",
            "--strict-mcp-config",
            "--system-prompt-file",
            "--json-schema",
        ] {
            assert!(
                args.lines().any(|arg| arg == required),
                "missing {required}"
            );
        }
        assert!(args.lines().any(|arg| arg == "claude-test"));
        assert!(args.lines().any(|arg| arg == "high"));
        assert!(args.contains("\"const\":\"read_file\""));
        let args = args.lines().collect::<Vec<_>>();
        assert!(args.windows(2).any(|pair| pair == ["--tools", ""]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--mcp-config", EMPTY_MCP_CONFIG]));

        let stdin = std::fs::read_to_string(stdin_path).expect("captured stdin");
        assert!(stdin.starts_with(TRANSPORT_INPUT_PREFIX));
        assert!(!stdin.contains("read_file"));
        assert!(stdin.contains("hello"));
        assert!(!stdin.contains("host authority"));
        let system = std::fs::read_to_string(system_path).expect("captured system prompt");
        assert!(system.starts_with(TRANSPORT_SYSTEM_PREFIX));
        assert!(system.contains("never invoke an OpenClaudia tool name as a Claude Code tool"));
        assert!(system.ends_with("host authority"));
    }
}

//! Canonical typed tool execution results.
//!
//! This module is the trust boundary between tool handlers, provider
//! continuation, traces, and frontends.  Control/follow-up state is created by
//! trusted handlers and is never recovered by parsing ordinary tool text.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};

use super::ToolCall;

/// Current serialized tool-result schema.
pub const TOOL_RESULT_SCHEMA_VERSION: u16 = 1;

/// Private message field carrying bounded attachment references between the
/// tool executor and provider adapters. The referenced bytes live only in the
/// process-local sidecar below; serialized transcripts retain metadata, never
/// raw media.
pub const TOOL_ATTACHMENTS_MESSAGE_KEY: &str = "_openclaudia_tool_attachments";

const MAX_TRANSIENT_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;
const MAX_TRANSIENT_ATTACHMENT_STORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSIENT_ATTACHMENT_ENTRIES: usize = 32;

#[derive(Debug)]
struct TransientAttachmentEntry {
    media_type: String,
    digest: String,
    bytes: Arc<[u8]>,
}

#[derive(Default)]
struct TransientAttachmentStore {
    entries: HashMap<String, TransientAttachmentEntry>,
    insertion_order: VecDeque<String>,
    retained_bytes: usize,
}

impl TransientAttachmentStore {
    fn insert(&mut self, token: String, entry: TransientAttachmentEntry) {
        while self.entries.len() >= MAX_TRANSIENT_ATTACHMENT_ENTRIES
            || self.retained_bytes.saturating_add(entry.bytes.len())
                > MAX_TRANSIENT_ATTACHMENT_STORE_BYTES
        {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            if let Some(removed) = self.entries.remove(&oldest) {
                self.retained_bytes = self.retained_bytes.saturating_sub(removed.bytes.len());
            }
        }
        self.retained_bytes = self.retained_bytes.saturating_add(entry.bytes.len());
        self.insertion_order.push_back(token.clone());
        self.entries.insert(token, entry);
    }
}

static TRANSIENT_ATTACHMENTS: LazyLock<Mutex<TransientAttachmentStore>> =
    LazyLock::new(|| Mutex::new(TransientAttachmentStore::default()));

/// Exact invocation identity bound to a tool result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolInvocation {
    /// Provider-assigned call correlation ID.
    pub call_id: String,
    /// Registry-resolved trusted handler identity.
    pub handler: String,
    /// Exact provider argument bytes, retained for provider-native replay.
    pub raw_arguments: String,
    /// Parsed argument object when decoding succeeded.
    pub arguments: Option<Value>,
}

/// Whether a content payload is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolCompleteness {
    Complete,
    Truncated {
        omitted_bytes: u64,
        continuation: Option<Value>,
    },
}

/// Model-visible data produced by a tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolContent {
    pub text: String,
    pub structured: Option<Value>,
    pub completeness: ToolCompleteness,
}

impl ToolContent {
    #[must_use]
    pub const fn text(text: String) -> Self {
        Self {
            text,
            structured: None,
            completeness: ToolCompleteness::Complete,
        }
    }

    #[must_use]
    pub const fn structured(text: String, structured: Value) -> Self {
        Self {
            text,
            structured: Some(structured),
            completeness: ToolCompleteness::Complete,
        }
    }
}

/// Stable failure category for programmatic recovery and policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolFailureCode {
    InvalidArguments,
    InvalidInput,
    PermissionDenied,
    PolicyDenied,
    Unavailable,
    Cancelled,
    DeadlineExceeded,
    Conflict,
    External,
    Internal,
    Legacy,
}

/// Whether repeating a failed operation is meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolRetryability {
    Never,
    Safe,
    AfterBackoff,
    Unknown,
}

/// Typed tool failure.  Source and recovery data remain data, never control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolFailure {
    pub code: ToolFailureCode,
    pub message: String,
    pub source: Option<String>,
    pub retryability: ToolRetryability,
    pub recovery: Option<Value>,
}

impl ToolFailure {
    #[must_use]
    pub const fn new(
        code: ToolFailureCode,
        message: String,
        retryability: ToolRetryability,
    ) -> Self {
        Self {
            code,
            message,
            source: None,
            retryability,
            recovery: None,
        }
    }
}

/// Success, failure, and partial completion are distinct states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolOutcome {
    Success {
        content: ToolContent,
    },
    Error {
        failure: ToolFailure,
    },
    Partial {
        content: ToolContent,
        failures: Vec<ToolFailure>,
        continuation: Option<Value>,
    },
}

/// Sensitivity label retained across adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSensitivity {
    Public,
    Workspace,
    Private,
    Secret,
}

/// A durable or externally addressable product of tool execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolArtifact {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub metadata: Value,
    pub sensitivity: ToolSensitivity,
}

/// A typed attachment.  Data is a native/provider-neutral value rather than
/// base64 prose embedded into ordinary text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAttachment {
    pub media_type: String,
    pub digest: String,
    pub byte_len: u64,
    pub data: Value,
    pub sensitivity: ToolSensitivity,
}

/// Provider-ready bytes recovered from one process-local attachment reference.
/// Cloning this value shares the immutable allocation rather than duplicating
/// a potentially multi-megabyte image.
#[derive(Debug, Clone)]
pub struct ResolvedToolAttachment {
    pub media_type: String,
    pub digest: String,
    pub bytes: Arc<[u8]>,
}

/// Register bounded media without placing its bytes in the canonical result or
/// any serialized message. The returned attachment is durable metadata plus an
/// unguessable process-local capability reference.
pub fn register_transient_attachment(
    media_type: impl Into<String>,
    bytes: Vec<u8>,
    sensitivity: ToolSensitivity,
) -> Result<ToolAttachment, String> {
    if bytes.is_empty() {
        return Err("Transient attachment bytes cannot be empty".to_string());
    }
    if bytes.len() > MAX_TRANSIENT_ATTACHMENT_BYTES {
        return Err(format!(
            "Transient attachment exceeds the {MAX_TRANSIENT_ATTACHMENT_BYTES}-byte item budget"
        ));
    }
    let media_type = media_type.into();
    if media_type.is_empty() || media_type.len() > 127 || !media_type.is_ascii() {
        return Err("Transient attachment MIME type is invalid".to_string());
    }
    let digest = crate::runtime::ContentDigest::sha256(&bytes).to_string();
    let byte_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let token = uuid::Uuid::new_v4().to_string();
    let entry = TransientAttachmentEntry {
        media_type: media_type.clone(),
        digest: digest.clone(),
        bytes: Arc::from(bytes),
    };
    TRANSIENT_ATTACHMENTS
        .lock()
        .map_err(|error| format!("Transient attachment store is unavailable: {error}"))?
        .insert(token.clone(), entry);
    Ok(ToolAttachment {
        media_type,
        digest,
        byte_len,
        data: json!({"kind": "transient_media", "token": token}),
        sensitivity,
    })
}

fn is_transient_attachment(attachment: &ToolAttachment) -> bool {
    attachment.data.get("kind").and_then(Value::as_str) == Some("transient_media")
        && attachment
            .data
            .get("token")
            .and_then(Value::as_str)
            .is_some_and(|token| !token.is_empty())
}

/// Resolve the private attachment references copied into one in-memory tool
/// message. Callers receive an explicit error after eviction or malformed
/// metadata instead of silently sending a text-only result.
pub fn resolve_tool_attachments(
    raw: Option<&Value>,
) -> Result<Vec<ResolvedToolAttachment>, String> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let attachments: Vec<ToolAttachment> = serde_json::from_value(raw.clone())
        .map_err(|error| format!("Invalid typed tool attachment metadata: {error}"))?;
    let store = TRANSIENT_ATTACHMENTS
        .lock()
        .map_err(|error| format!("Transient attachment store is unavailable: {error}"))?;
    attachments
        .into_iter()
        .map(|attachment| {
            let token = attachment
                .data
                .get("token")
                .and_then(Value::as_str)
                .filter(|token| !token.is_empty())
                .ok_or_else(|| "Typed tool attachment is missing its transient token".to_string())?;
            let entry = store.entries.get(token).ok_or_else(|| {
                format!(
                    "Typed tool attachment {} is no longer available in the bounded transient store",
                    attachment.digest
                )
            })?;
            if entry.media_type != attachment.media_type
                || entry.digest != attachment.digest
                || u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX) != attachment.byte_len
            {
                return Err("Typed tool attachment metadata does not match its transient bytes"
                    .to_string());
            }
            Ok(ResolvedToolAttachment {
                media_type: entry.media_type.clone(),
                digest: entry.digest.clone(),
                bytes: Arc::clone(&entry.bytes),
            })
        })
        .collect()
}

/// One authoritative or advisory observation emitted by a handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolObservation {
    pub kind: String,
    pub authoritative: bool,
    pub data: Value,
}

/// Per-call usage retained independently of model-facing text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ToolUsage {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub elapsed_ms: u64,
}

/// Typed diff presentation constructed only by the trusted edit handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDiff {
    pub path: String,
    pub old_text: String,
    pub new_text: String,
    pub before_snapshot: String,
    pub after_snapshot: String,
    pub redacted: bool,
}

/// Frontend presentation hint.  Frontends match this enum; they never scan
/// content for magic markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolDisplay {
    #[default]
    Auto,
    Text {
        max_lines: usize,
    },
    Diff {
        summary: String,
        diff: ToolDiff,
    },
    Hidden,
}

/// One validated option in a user question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolQuestionOption {
    pub label: String,
    pub description: String,
    pub preview: Option<String>,
}

/// A validated, stable question payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolQuestion {
    pub question: String,
    pub header: String,
    pub options: Vec<ToolQuestionOption>,
    pub multi_select: bool,
}

impl ToolQuestion {
    /// Compatibility projection for the existing REPL/TUI widgets.  The
    /// control decision was already made from this typed value.
    ///
    /// # Panics
    ///
    /// Panics only if serde cannot serialize the statically serializable
    /// [`ToolQuestion`] shape.
    #[must_use]
    pub fn widget_value(&self) -> Value {
        let mut value = serde_json::to_value(self).expect("ToolQuestion serialization cannot fail");
        if let Some(object) = value.as_object_mut() {
            if let Some(multi_select) = object.remove("multi_select") {
                object.insert("multiSelect".to_string(), multi_select);
            }
        }
        value
    }
}

/// Typed allowed operation proposed with a plan-mode exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAllowedPrompt {
    pub tool: String,
    pub prompt: String,
}

/// Lifecycle of a trusted follow-up request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolFollowUpState {
    Pending,
    Resolved { response: Value },
    Cancelled { reason: String },
}

/// Host action requested by a trusted handler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolFollowUp {
    #[default]
    None,
    UserQuestion {
        questions: Vec<ToolQuestion>,
        state: ToolFollowUpState,
    },
    EnterPlanMode {
        state: ToolFollowUpState,
    },
    ExitPlanMode {
        allowed_prompts: Vec<ToolAllowedPrompt>,
        state: ToolFollowUpState,
    },
}

impl ToolFollowUp {
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        matches!(
            self,
            Self::UserQuestion {
                state: ToolFollowUpState::Pending,
                ..
            } | Self::EnterPlanMode {
                state: ToolFollowUpState::Pending
            } | Self::ExitPlanMode {
                state: ToolFollowUpState::Pending,
                ..
            }
        )
    }

    fn resolve(&mut self, response: Value) -> Result<(), ToolResultError> {
        let state = match self {
            Self::None => return Err(ToolResultError::NoPendingFollowUp),
            Self::UserQuestion { state, .. }
            | Self::EnterPlanMode { state }
            | Self::ExitPlanMode { state, .. } => state,
        };
        if !matches!(state, ToolFollowUpState::Pending) {
            return Err(ToolResultError::FollowUpAlreadyTerminal);
        }
        *state = ToolFollowUpState::Resolved { response };
        Ok(())
    }

    fn cancel(&mut self, reason: String) -> Result<(), ToolResultError> {
        let state = match self {
            Self::None => return Err(ToolResultError::NoPendingFollowUp),
            Self::UserQuestion { state, .. }
            | Self::EnterPlanMode { state }
            | Self::ExitPlanMode { state, .. } => state,
        };
        if !matches!(state, ToolFollowUpState::Pending) {
            return Err(ToolResultError::FollowUpAlreadyTerminal);
        }
        *state = ToolFollowUpState::Cancelled { reason };
        Ok(())
    }
}

/// Uncorrelated output returned by a trusted registry handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolHandlerResult {
    pub outcome: ToolOutcome,
    pub artifacts: Vec<ToolArtifact>,
    pub attachments: Vec<ToolAttachment>,
    pub observations: Vec<ToolObservation>,
    pub display: ToolDisplay,
    pub follow_up: ToolFollowUp,
    pub usage: ToolUsage,
    pub sensitivity: ToolSensitivity,
}

impl ToolHandlerResult {
    #[must_use]
    pub fn success_text(text: impl Into<String>) -> Self {
        Self {
            outcome: ToolOutcome::Success {
                content: ToolContent::text(text.into()),
            },
            artifacts: Vec::new(),
            attachments: Vec::new(),
            observations: Vec::new(),
            display: ToolDisplay::Auto,
            follow_up: ToolFollowUp::None,
            usage: ToolUsage::default(),
            sensitivity: ToolSensitivity::Workspace,
        }
    }

    #[must_use]
    pub fn success_structured(text: impl Into<String>, structured: Value) -> Self {
        let mut result = Self::success_text(text);
        result.outcome = ToolOutcome::Success {
            content: ToolContent::structured(result.content().to_string(), structured),
        };
        result
    }

    #[must_use]
    pub fn error(failure: ToolFailure) -> Self {
        Self {
            outcome: ToolOutcome::Error { failure },
            artifacts: Vec::new(),
            attachments: Vec::new(),
            observations: Vec::new(),
            display: ToolDisplay::Auto,
            follow_up: ToolFollowUp::None,
            usage: ToolUsage::default(),
            sensitivity: ToolSensitivity::Workspace,
        }
    }

    /// Report an operation that produced a real effect but did not complete.
    #[must_use]
    pub fn partial_text(text: impl Into<String>, failures: Vec<ToolFailure>) -> Self {
        Self {
            outcome: ToolOutcome::Partial {
                content: ToolContent::text(text.into()),
                failures,
                continuation: None,
            },
            artifacts: Vec::new(),
            attachments: Vec::new(),
            observations: Vec::new(),
            display: ToolDisplay::Auto,
            follow_up: ToolFollowUp::None,
            usage: ToolUsage::default(),
            sensitivity: ToolSensitivity::Workspace,
        }
    }

    /// Report a typed partial effect with bounded recovery state.
    #[must_use]
    pub fn partial_structured(
        text: impl Into<String>,
        structured: Value,
        failures: Vec<ToolFailure>,
        continuation: Option<Value>,
    ) -> Self {
        Self {
            outcome: ToolOutcome::Partial {
                content: ToolContent::structured(text.into(), structured),
                failures,
                continuation,
            },
            artifacts: Vec::new(),
            attachments: Vec::new(),
            observations: Vec::new(),
            display: ToolDisplay::Auto,
            follow_up: ToolFollowUp::None,
            usage: ToolUsage::default(),
            sensitivity: ToolSensitivity::Workspace,
        }
    }

    /// Report a bounded page with exact omitted-byte and continuation data.
    #[must_use]
    pub fn partial_truncated_structured(
        text: impl Into<String>,
        structured: Value,
        omitted_bytes: u64,
        continuation: Option<Value>,
    ) -> Self {
        Self {
            outcome: ToolOutcome::Partial {
                content: ToolContent {
                    text: text.into(),
                    structured: Some(structured),
                    completeness: ToolCompleteness::Truncated {
                        omitted_bytes,
                        continuation: continuation.clone(),
                    },
                },
                failures: Vec::new(),
                continuation,
            },
            artifacts: Vec::new(),
            attachments: Vec::new(),
            observations: Vec::new(),
            display: ToolDisplay::Auto,
            follow_up: ToolFollowUp::None,
            usage: ToolUsage::default(),
            sensitivity: ToolSensitivity::Workspace,
        }
    }

    #[must_use]
    pub fn legacy(content: String, is_error: bool) -> Self {
        if is_error {
            Self::error(ToolFailure::new(
                ToolFailureCode::Legacy,
                content,
                ToolRetryability::Unknown,
            ))
        } else {
            Self::success_text(content)
        }
    }

    /// Preserve the structured output/error categories already produced by a
    /// migrated leaf executor instead of collapsing them through the tuple
    /// compatibility seam.
    pub(crate) fn from_migrated(
        result: Result<super::args::ToolOutput, super::args::ToolError>,
    ) -> Self {
        match result {
            Ok(output) => {
                let super::args::ToolOutput {
                    content,
                    structured,
                } = output;
                match structured {
                    Some(structured) => Self::success_structured(content, structured),
                    None => Self::success_text(content),
                }
            }
            Err(error) => {
                let (code, retryability) = match &error {
                    super::args::ToolError::InvalidArgument(_) => {
                        (ToolFailureCode::InvalidArguments, ToolRetryability::Never)
                    }
                    super::args::ToolError::InvalidInput(_) => {
                        (ToolFailureCode::InvalidInput, ToolRetryability::Never)
                    }
                    super::args::ToolError::Unavailable(_) => {
                        (ToolFailureCode::Unavailable, ToolRetryability::Never)
                    }
                    super::args::ToolError::PermissionDenied(_) => {
                        (ToolFailureCode::PermissionDenied, ToolRetryability::Never)
                    }
                    super::args::ToolError::External(_) => {
                        (ToolFailureCode::External, ToolRetryability::Unknown)
                    }
                    super::args::ToolError::PartialExternal(message) => {
                        return Self::partial_text(
                            message.clone(),
                            vec![ToolFailure::new(
                                ToolFailureCode::External,
                                message.clone(),
                                ToolRetryability::Unknown,
                            )],
                        );
                    }
                    super::args::ToolError::Other(_) => {
                        (ToolFailureCode::Internal, ToolRetryability::Unknown)
                    }
                };
                Self::error(ToolFailure::new(code, error.to_string(), retryability))
            }
        }
    }

    #[must_use]
    pub fn with_display(mut self, display: ToolDisplay) -> Self {
        self.display = display;
        self
    }

    #[must_use]
    pub fn with_follow_up(mut self, follow_up: ToolFollowUp) -> Self {
        self.follow_up = follow_up;
        self
    }

    #[must_use]
    pub fn with_artifact(mut self, artifact: ToolArtifact) -> Self {
        self.artifacts.push(artifact);
        self
    }

    #[must_use]
    pub fn with_attachment(mut self, attachment: ToolAttachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    #[must_use]
    pub fn content(&self) -> &str {
        match &self.outcome {
            ToolOutcome::Success { content } | ToolOutcome::Partial { content, .. } => {
                &content.text
            }
            ToolOutcome::Error { failure } => &failure.message,
        }
    }

    /// Temporary leaf-test compatibility projection while legacy executors
    /// are migrated. Application/provider paths must retain the typed value.
    #[must_use]
    pub fn into_legacy(self) -> (String, bool) {
        let is_error = matches!(self.outcome, ToolOutcome::Error { .. });
        (self.content().to_string(), is_error)
    }
}

/// Canonical, call-correlated execution result used by registry consumers,
/// provider continuations, traces, and frontends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolExecutionResult {
    schema_version: u16,
    invocation: ToolInvocation,
    outcome: ToolOutcome,
    artifacts: Vec<ToolArtifact>,
    attachments: Vec<ToolAttachment>,
    observations: Vec<ToolObservation>,
    display: ToolDisplay,
    follow_up: ToolFollowUp,
    usage: ToolUsage,
    sensitivity: ToolSensitivity,
}

/// Existing public name retained as a type alias; its representation is now
/// the canonical typed result rather than `(String, bool)` fields.
pub type ToolResult = ToolExecutionResult;

impl ToolExecutionResult {
    #[must_use]
    pub fn bind(tool_call: &ToolCall, handler: &str, result: ToolHandlerResult) -> Self {
        let arguments = serde_json::from_str::<Value>(&tool_call.function.arguments)
            .ok()
            .filter(Value::is_object);
        Self {
            schema_version: TOOL_RESULT_SCHEMA_VERSION,
            invocation: ToolInvocation {
                call_id: tool_call.id.clone(),
                handler: handler.to_string(),
                raw_arguments: tool_call.function.arguments.clone(),
                arguments,
            },
            outcome: result.outcome,
            artifacts: result.artifacts,
            attachments: result.attachments,
            observations: result.observations,
            display: result.display,
            follow_up: result.follow_up,
            usage: result.usage,
            sensitivity: result.sensitivity,
        }
    }

    #[must_use]
    pub fn failure(
        tool_call: &ToolCall,
        code: ToolFailureCode,
        message: impl Into<String>,
        retryability: ToolRetryability,
    ) -> Self {
        Self::bind(
            tool_call,
            &tool_call.function.name,
            ToolHandlerResult::error(ToolFailure::new(code, message.into(), retryability)),
        )
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn invocation(&self) -> &ToolInvocation {
        &self.invocation
    }

    #[must_use]
    pub fn tool_call_id(&self) -> &str {
        &self.invocation.call_id
    }

    #[must_use]
    pub fn handler(&self) -> &str {
        &self.invocation.handler
    }

    #[must_use]
    pub const fn outcome(&self) -> &ToolOutcome {
        &self.outcome
    }

    #[must_use]
    pub fn content(&self) -> &str {
        match &self.outcome {
            ToolOutcome::Success { content } | ToolOutcome::Partial { content, .. } => {
                &content.text
            }
            ToolOutcome::Error { failure } => &failure.message,
        }
    }

    #[must_use]
    pub const fn structured(&self) -> Option<&Value> {
        match &self.outcome {
            ToolOutcome::Success { content } | ToolOutcome::Partial { content, .. } => {
                content.structured.as_ref()
            }
            ToolOutcome::Error { .. } => None,
        }
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self.outcome, ToolOutcome::Error { .. })
    }

    #[must_use]
    pub const fn is_partial(&self) -> bool {
        matches!(self.outcome, ToolOutcome::Partial { .. })
    }

    /// Restore the exact provider/wire invocation after an adapter executes a
    /// normalized equivalent locally.
    ///
    /// ACP accepts a small set of wire aliases (for example `file_path` for
    /// the registry's canonical `path`). The local executor must authorize and
    /// dispatch the normalized arguments, while provider continuation and
    /// evidence must retain the exact bytes supplied by the provider. This
    /// operation changes only invocation identity; the trusted handler and all
    /// execution outcome data remain untouched.
    #[must_use]
    pub(crate) fn with_wire_invocation(mut self, tool_call: &ToolCall) -> Self {
        self.invocation.call_id.clone_from(&tool_call.id);
        self.invocation
            .raw_arguments
            .clone_from(&tool_call.function.arguments);
        self.invocation.arguments = serde_json::from_str::<Value>(&tool_call.function.arguments)
            .ok()
            .filter(Value::is_object);
        self
    }

    #[must_use]
    pub fn artifacts(&self) -> &[ToolArtifact] {
        &self.artifacts
    }

    #[must_use]
    pub fn attachments(&self) -> &[ToolAttachment] {
        &self.attachments
    }

    #[must_use]
    pub fn observations(&self) -> &[ToolObservation] {
        &self.observations
    }

    /// Digest the immutable execution evidence used by downstream causal
    /// consumers.
    ///
    /// Presentation, follow-up state, and advisory observations are excluded;
    /// authoritative handler observations are included:
    /// a frontend may resolve a follow-up or attach a learning-health receipt
    /// after execution without changing what the handler actually did. The
    /// invocation, typed outcome, artifacts, attachments, usage, and
    /// sensitivity remain bound exactly.
    ///
    /// # Panics
    ///
    /// Panics only if serialization of this statically serializable projection
    /// fails.
    #[must_use]
    pub fn evidence_digest(&self) -> String {
        #[derive(Serialize)]
        struct EvidenceProjection<'a> {
            schema_version: u16,
            invocation: &'a ToolInvocation,
            outcome: &'a ToolOutcome,
            artifacts: &'a [ToolArtifact],
            attachments: &'a [ToolAttachment],
            observations: Vec<&'a ToolObservation>,
            usage: &'a ToolUsage,
            sensitivity: ToolSensitivity,
        }

        let authoritative_observations = self
            .observations
            .iter()
            .filter(|observation| observation.authoritative)
            .collect::<Vec<_>>();
        let encoded = serde_json::to_vec(&EvidenceProjection {
            schema_version: self.schema_version,
            invocation: &self.invocation,
            outcome: &self.outcome,
            artifacts: &self.artifacts,
            attachments: &self.attachments,
            observations: authoritative_observations,
            usage: &self.usage,
            sensitivity: self.sensitivity,
        })
        .expect("ToolExecutionResult evidence projection serialization cannot fail");
        let digest: [u8; 32] = Sha256::digest(encoded).into();
        let mut rendered = String::with_capacity(71);
        rendered.push_str("sha256:");
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(rendered, "{byte:02x}");
        }
        rendered
    }

    /// Attach one advisory observation after execution.
    ///
    /// The observation is model-visible evidence, never control authority, and
    /// deliberately does not affect [`Self::evidence_digest`].
    #[must_use]
    pub(crate) fn with_observation(mut self, observation: ToolObservation) -> Self {
        self.observations.push(observation);
        self
    }

    /// Mark a successful effect as incomplete because a trusted postcondition
    /// failed after publication. Existing errors and partial outcomes retain
    /// their stronger/earlier failure state.
    #[must_use]
    pub(crate) fn with_postcondition_failure(mut self, failure: ToolFailure) -> Self {
        if matches!(self.outcome, ToolOutcome::Success { .. }) {
            let ToolOutcome::Success { content } = std::mem::replace(
                &mut self.outcome,
                ToolOutcome::Error {
                    failure: failure.clone(),
                },
            ) else {
                unreachable!("success outcome was checked before replacement")
            };
            self.outcome = ToolOutcome::Partial {
                content,
                failures: vec![failure],
                continuation: None,
            };
        }
        self
    }

    #[must_use]
    pub const fn display(&self) -> &ToolDisplay {
        &self.display
    }

    #[must_use]
    pub const fn follow_up(&self) -> &ToolFollowUp {
        &self.follow_up
    }

    #[must_use]
    pub const fn usage(&self) -> &ToolUsage {
        &self.usage
    }

    /// Deterministic frontend text projection. Presentation follows trusted
    /// typed metadata and never scans ordinary content for sentinels.
    #[must_use]
    pub fn render_text(&self) -> String {
        match &self.display {
            ToolDisplay::Hidden => String::new(),
            ToolDisplay::Diff { summary, diff } => format!(
                "{summary}\n--- {} (before)\n{}\n+++ {} (after)\n{}",
                diff.path, diff.old_text, diff.path, diff.new_text
            ),
            ToolDisplay::Auto | ToolDisplay::Text { .. } => self.content().to_string(),
        }
    }

    /// Resolve a pending host follow-up while retaining its typed provenance.
    /// The replacement content is the exact response made visible to the
    /// provider after the frontend action completes.
    ///
    /// # Errors
    ///
    /// Returns [`ToolResultError`] when no follow-up is pending or it already
    /// reached a terminal state.
    pub fn resolve_follow_up(
        &self,
        provider_content: String,
        response: Value,
    ) -> Result<Self, ToolResultError> {
        let mut resolved = self.clone();
        resolved.follow_up.resolve(response)?;
        resolved.outcome = ToolOutcome::Success {
            content: ToolContent::text(provider_content),
        };
        resolved.display = ToolDisplay::Auto;
        Ok(resolved)
    }

    /// Cancel a pending host follow-up without converting it back into a text
    /// marker.  The provider still receives an ordinary typed result payload.
    ///
    /// # Errors
    ///
    /// Returns [`ToolResultError`] when no follow-up is pending or it already
    /// reached a terminal state.
    pub fn cancel_follow_up(
        &self,
        provider_content: String,
        reason: String,
    ) -> Result<Self, ToolResultError> {
        let mut cancelled = self.clone();
        cancelled.follow_up.cancel(reason)?;
        cancelled.outcome = ToolOutcome::Error {
            failure: ToolFailure::new(
                ToolFailureCode::Cancelled,
                provider_content,
                ToolRetryability::Never,
            ),
        };
        cancelled.display = ToolDisplay::Auto;
        Ok(cancelled)
    }

    /// Typed model-facing envelope.  Ordinary text inside this value remains
    /// inert data; no consumer scans it for control markers.
    #[must_use]
    pub fn model_payload(&self) -> Value {
        json!({
            "schema": "openclaudia.tool_result.v1",
            "result": self,
        })
    }

    /// Provider-neutral string form for APIs whose tool-result slot accepts
    /// text only.  The canonical in-memory result is retained alongside this
    /// projection by [`super::ToolContinuation`].
    ///
    /// # Panics
    ///
    /// Panics only if serde cannot serialize the statically serializable
    /// canonical result envelope.
    #[must_use]
    pub fn provider_content(&self) -> String {
        serde_json::to_string(&self.model_payload())
            .expect("ToolExecutionResult serialization cannot fail")
    }

    /// OpenAI-compatible tool-result message derived from the typed result.
    #[must_use]
    pub fn openai_message(&self) -> Value {
        let mut message = json!({
            "role": "tool",
            "tool_call_id": self.tool_call_id(),
            "content": self.provider_content(),
            "is_error": self.is_error(),
        });
        let transient = self
            .attachments
            .iter()
            .filter(|attachment| is_transient_attachment(attachment))
            .collect::<Vec<_>>();
        if !transient.is_empty() {
            if let (Some(object), Ok(serialized)) =
                (message.as_object_mut(), serde_json::to_value(transient))
            {
                object.insert(TOOL_ATTACHMENTS_MESSAGE_KEY.to_string(), serialized);
            }
        }
        message
    }
}

/// Invalid follow-up lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ToolResultError {
    #[error("tool result has no pending follow-up")]
    NoPendingFollowUp,
    #[error("tool result follow-up is already resolved or cancelled")]
    FollowUpAlreadyTerminal,
}

#[cfg(test)]
mod evidence_digest_tests {
    use super::*;
    use serde_json::json;

    fn call(id: &str, arguments: &str) -> ToolCall {
        ToolCall {
            id: id.to_string(),
            call_type: "function".to_string(),
            function: super::super::FunctionCall {
                name: "fixture".to_string(),
                arguments: arguments.to_string(),
            },
        }
    }

    #[test]
    fn evidence_digest_is_round_trip_stable_and_binds_execution_identity() {
        let original = ToolExecutionResult::bind(
            &call("call-a", r#"{"value":1}"#),
            "fixture",
            ToolHandlerResult::success_text("completed"),
        );
        let round_trip: ToolExecutionResult = serde_json::from_slice(
            &serde_json::to_vec(&original).expect("serialize canonical result"),
        )
        .expect("deserialize canonical result");
        assert_eq!(original.evidence_digest(), round_trip.evidence_digest());

        let different_call = ToolExecutionResult::bind(
            &call("call-b", r#"{"value":1}"#),
            "fixture",
            ToolHandlerResult::success_text("completed"),
        );
        let different_arguments = ToolExecutionResult::bind(
            &call("call-a", r#"{"value":2}"#),
            "fixture",
            ToolHandlerResult::success_text("completed"),
        );
        let different_outcome = ToolExecutionResult::failure(
            &call("call-a", r#"{"value":1}"#),
            ToolFailureCode::External,
            "failed",
            ToolRetryability::Safe,
        );
        assert_ne!(original.evidence_digest(), different_call.evidence_digest());
        assert_ne!(
            original.evidence_digest(),
            different_arguments.evidence_digest()
        );
        assert_ne!(
            original.evidence_digest(),
            different_outcome.evidence_digest()
        );
    }

    #[test]
    fn digest_binds_authoritative_observations_but_not_advisory_receipts() {
        let tool_call = call("call-observations", r#"{"value":1}"#);
        let mut handler = ToolHandlerResult::success_text("completed");
        handler.observations.push(ToolObservation {
            kind: "handler_state".to_string(),
            authoritative: true,
            data: json!({"generation": 1}),
        });
        let base = ToolExecutionResult::bind(&tool_call, "fixture", handler);
        let base_digest = base.evidence_digest();

        let advisory = base.with_observation(ToolObservation {
            kind: super::super::TECHNICAL_LEARNING_CAPTURE_OBSERVATION_KIND.to_string(),
            authoritative: false,
            data: json!({"status": "evidence_recorded"}),
        });
        assert_eq!(base_digest, advisory.evidence_digest());

        let mut changed_handler = ToolHandlerResult::success_text("completed");
        changed_handler.observations.push(ToolObservation {
            kind: "handler_state".to_string(),
            authoritative: true,
            data: json!({"generation": 2}),
        });
        let changed = ToolExecutionResult::bind(&tool_call, "fixture", changed_handler);
        assert_ne!(base_digest, changed.evidence_digest());
    }
}

//! Hook Engine - Executes hooks at key moments in the agent lifecycle.
//!
//! Supports 12 event types and two hook mechanisms:
//! - Command hooks: Execute shell commands with JSON stdin/stdout
//! - Prompt hooks: Inject prompts into the conversation
//!
//! Also supports loading hooks from Claude Code's .claude/settings.json
//! for compatibility with existing Claude Code hook configurations.
//!
//! Exit codes:
//! - 0: Success (allow)
//! - 2: Block the action

pub mod claude_compat;
pub mod merge;

// Re-export everything public from submodules
pub use claude_compat::{
    load_claude_code_hooks, load_claude_code_hooks_layered, load_claude_settings, ClaudeCodeHook,
    ClaudeCodeHookEntry, ClaudeCodeSettings, LayeredSettings,
};
pub use merge::merge_hooks_config;

use crate::config::{Hook, HookEntry, HookMatcherTarget, HookPolicy, HooksConfig, SandboxMode};
use crate::tools::is_sensitive_env;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Emitted once per process the first time a hook runs without an explicit
/// `HookPolicy`. Prevents repeated log noise while still surfacing the gap.
static ALLOW_ALL_DEPRECATION_WARNED: AtomicBool = AtomicBool::new(false);
const TRUST_UNSANDBOXED_HOOKS_ENV: &str = "OPENCLAUDIA_TRUST_UNSANDBOXED_HOOKS";
static TRUST_UNSANDBOXED_HOOKS: LazyLock<Result<bool, String>> = LazyLock::new(|| {
    std::env::var_os(TRUST_UNSANDBOXED_HOOKS_ENV).map_or(Ok(false), |value| {
        let value = value.to_str().ok_or_else(|| {
            format!(
                "{TRUST_UNSANDBOXED_HOOKS_ENV} contains non-Unicode data; refusing host hook execution"
            )
        })?;
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "off" | "no" => Ok(false),
            "1" | "true" | "on" | "yes" => Ok(true),
            _ => Err(format!(
                "Invalid {TRUST_UNSANDBOXED_HOOKS_ENV} value '{value}'; use 'false' (default) or 'true'"
            )),
        }
    })
});
const MAX_HOOK_OUTPUT_BYTES_PER_STREAM: usize = 1024 * 1024;
const HOOK_OUTPUT_TRUNCATED_MARKER: &[u8] = b"\n[hook output truncated at 1 MiB]\n";

/// All hook event types supported by `OpenClaudia`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookEvent {
    /// Fired when a new session starts
    SessionStart,
    /// Fired when a session ends
    SessionEnd,
    /// Fired before a tool is executed
    PreToolUse,
    /// Fired after a tool executes successfully
    PostToolUse,
    /// Fired after a tool execution fails
    PostToolUseFailure,
    /// Fired when user submits a prompt
    UserPromptSubmit,
    /// Fired when the agent stops
    Stop,
    /// Fired when a subagent starts
    SubagentStart,
    /// Fired when a subagent stops
    SubagentStop,
    /// Fired before context compaction
    PreCompact,
    /// Fired when a permission is requested
    PermissionRequest,
    /// Fired for notifications
    Notification,
    /// Fired before sending builder output to adversary (VDD)
    PreAdversaryReview,
    /// Fired after adversary returns review (VDD)
    PostAdversaryReview,
    /// Fired when adversary finds genuine issues (VDD)
    VddConflict,
    /// Fired when adversary reaches confabulation threshold (VDD)
    VddConverged,
}

impl HookEvent {
    /// Get the config field name for this event
    #[must_use]
    pub const fn config_key(&self) -> &'static str {
        match self {
            Self::SessionStart => "session_start",
            Self::SessionEnd => "session_end",
            Self::PreToolUse => "pre_tool_use",
            Self::PostToolUse => "post_tool_use",
            Self::PostToolUseFailure => "post_tool_use_failure",
            Self::UserPromptSubmit => "user_prompt_submit",
            Self::Stop => "stop",
            Self::SubagentStart => "subagent_start",
            Self::SubagentStop => "subagent_stop",
            Self::PreCompact => "pre_compact",
            Self::PermissionRequest => "permission_request",
            Self::Notification => "notification",
            Self::PreAdversaryReview => "pre_adversary_review",
            Self::PostAdversaryReview => "post_adversary_review",
            Self::VddConflict => "vdd_conflict",
            Self::VddConverged => "vdd_converged",
        }
    }

    /// Parse from Claude Code's `PascalCase` event name
    #[must_use]
    pub fn from_claude_code_name(name: &str) -> Option<Self> {
        match name {
            "PreToolUse" => Some(Self::PreToolUse),
            "PostToolUse" => Some(Self::PostToolUse),
            "PostToolUseFailure" => Some(Self::PostToolUseFailure),
            "UserPromptSubmit" => Some(Self::UserPromptSubmit),
            "Stop" => Some(Self::Stop),
            "SubagentStart" => Some(Self::SubagentStart),
            "SubagentStop" => Some(Self::SubagentStop),
            "PreCompact" => Some(Self::PreCompact),
            "Notification" => Some(Self::Notification),
            // Claude Code doesn't have these but we support them
            "SessionStart" => Some(Self::SessionStart),
            "SessionEnd" => Some(Self::SessionEnd),
            "PermissionRequest" => Some(Self::PermissionRequest),
            "PreAdversaryReview" => Some(Self::PreAdversaryReview),
            "PostAdversaryReview" => Some(Self::PostAdversaryReview),
            "VddConflict" => Some(Self::VddConflict),
            "VddConverged" => Some(Self::VddConverged),
            _ => None,
        }
    }

    /// Whether this event is a *deny-intent* event — one where a hook's
    /// purpose is to gate/block an action (`PreToolUse`, `PermissionRequest`).
    ///
    /// Used by [`HookEngine::matches_entry`] to choose the fail-mode when a
    /// matcher regex fails to compile or evaluate:
    ///
    /// - Deny-intent events (`is_deny_intent() == true`) **fail closed**:
    ///   a malformed matcher is treated as a match so the hook runs and can
    ///   block the action. Crosslink #758 — failing open would silently
    ///   convert deny hooks into no-ops on the slightest regex typo.
    /// - Observe-intent events (everything else, e.g. `PostToolUse`,
    ///   `Notification`) **fail open**: a malformed matcher is treated as
    ///   "does not match" so an audit/observability hook never accidentally
    ///   fires on an unrelated tool. Audit failures are surfaced elsewhere
    ///   (see [`HookEngine::fire_post_tool`]).
    #[must_use]
    pub const fn is_deny_intent(self) -> bool {
        matches!(self, Self::PreToolUse | Self::PermissionRequest)
    }

    /// Default [`HookMatcherTarget`] for this event variant.
    ///
    /// Crosslink #350: replaces the old "first populated field wins"
    /// behaviour, which let a `PreToolUse` matcher like `"rm"` accidentally
    /// match a user-prompt string of `"I want to rm a file"`.
    ///
    /// Tool-lifecycle events default to [`HookMatcherTarget::ToolName`],
    /// [`HookEvent::UserPromptSubmit`] defaults to [`HookMatcherTarget::Prompt`],
    /// and all remaining events (session/notification/subagent/compact/VDD)
    /// default to [`HookMatcherTarget::EventKey`] so their matcher operates
    /// on the event's stable config key (`"session_start"`, etc.).
    #[must_use]
    pub const fn default_matcher_target(self) -> HookMatcherTarget {
        match self {
            Self::PreToolUse
            | Self::PostToolUse
            | Self::PostToolUseFailure
            | Self::PermissionRequest => HookMatcherTarget::ToolName,
            Self::UserPromptSubmit => HookMatcherTarget::Prompt,
            Self::SessionStart
            | Self::SessionEnd
            | Self::Stop
            | Self::SubagentStart
            | Self::SubagentStop
            | Self::PreCompact
            | Self::Notification
            | Self::PreAdversaryReview
            | Self::PostAdversaryReview
            | Self::VddConflict
            | Self::VddConverged => HookMatcherTarget::EventKey,
        }
    }
}

impl HooksConfig {
    /// Check if the hooks config is empty (no hooks defined)
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.session_start.is_empty()
            && self.session_end.is_empty()
            && self.pre_tool_use.is_empty()
            && self.post_tool_use.is_empty()
            && self.post_tool_use_failure.is_empty()
            && self.user_prompt_submit.is_empty()
            && self.stop.is_empty()
            && self.subagent_start.is_empty()
            && self.subagent_stop.is_empty()
            && self.pre_compact.is_empty()
            && self.permission_request.is_empty()
            && self.notification.is_empty()
            && self.pre_adversary_review.is_empty()
            && self.post_adversary_review.is_empty()
            && self.vdd_conflict.is_empty()
            && self.vdd_converged.is_empty()
    }
}

/// Input provided to hooks via stdin
#[derive(Debug, Clone, Serialize)]
pub struct HookInput {
    /// The event type that triggered this hook
    pub event: HookEvent,
    /// Current working directory
    pub cwd: String,
    /// Session ID if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Tool name for tool-related events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Tool input for tool-related events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_input: Option<Value>,
    /// User prompt for `UserPromptSubmit` event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Additional context data
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl HookInput {
    #[must_use]
    pub fn new(event: HookEvent) -> Self {
        Self {
            event,
            cwd: crate::tools::security::current_context()
                .map(|context| context.working_directory().to_string_lossy().to_string())
                .unwrap_or_default(),
            session_id: None,
            tool_name: None,
            tool_input: None,
            prompt: None,
            extra: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    #[must_use]
    pub fn with_tool(mut self, name: impl Into<String>, input: Value) -> Self {
        self.tool_name = Some(name.into());
        self.tool_input = Some(input);
        self
    }

    #[must_use]
    pub fn with_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    #[must_use]
    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    // ── Typed matcher accessors (crosslink #350) ────────────────────────────
    //
    // Each accessor returns the slot of the input that should be tested
    // against a [`HookEntry::matcher`] regex for that target type, or
    // `None` if the field isn't populated. The engine selects which
    // accessor to call from a [`HookMatcherTarget`] derived from either
    // the entry's explicit `target` field or [`HookEvent::default_matcher_target`].

    /// Tool name to match against (`PreToolUse`/`PostToolUse`/...).
    #[must_use]
    pub fn match_tool(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }

    /// User prompt text to match against (`UserPromptSubmit`).
    #[must_use]
    pub fn match_prompt(&self) -> Option<&str> {
        self.prompt.as_deref()
    }

    /// Stable event key (e.g. `"session_start"`) for events with no payload
    /// other than the event itself. Always returns `Some`.
    #[must_use]
    pub const fn match_event(&self) -> Option<&'static str> {
        Some(self.event.config_key())
    }
}

fn notification_input(notification_type: &str, data: Value) -> HookInput {
    HookInput::new(HookEvent::Notification)
        .with_extra(
            "notification_type",
            Value::String(notification_type.to_string()),
        )
        .with_extra("data", data)
}

/// Output from a hook execution
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct HookOutput {
    /// Decision: "allow", "deny", or "ask"
    pub decision: Option<String>,
    /// Reason for the decision
    pub reason: Option<String>,
    /// System message to inject
    #[serde(rename = "systemMessage")]
    pub system_message: Option<String>,
    /// Modified prompt (for `UserPromptSubmit`)
    pub prompt: Option<String>,
    /// Additional context from hook (plain text output or hookSpecificOutput.additionalContext)
    #[serde(rename = "additionalContext")]
    pub additional_context: Option<String>,
    /// Additional data from the hook
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Result of running hooks
#[derive(Debug, Clone)]
pub struct HookResult {
    /// Whether the action should be allowed
    pub allowed: bool,
    /// Combined outputs from all hooks
    pub outputs: Vec<HookOutput>,
    /// Any errors that occurred
    pub errors: Vec<HookError>,
}

impl HookResult {
    #[must_use]
    pub const fn allowed() -> Self {
        Self {
            allowed: true,
            outputs: vec![],
            errors: vec![],
        }
    }

    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            outputs: vec![HookOutput {
                decision: Some("deny".to_string()),
                reason: Some(reason.into()),
                ..Default::default()
            }],
            errors: vec![],
        }
    }

    /// Get all system messages from hook outputs
    #[must_use]
    pub fn system_messages(&self) -> Vec<&str> {
        self.outputs
            .iter()
            .filter_map(|o| o.system_message.as_deref())
            .collect()
    }

    /// Get modified prompt if any hook provided one
    #[must_use]
    pub fn modified_prompt(&self) -> Option<&str> {
        self.outputs.iter().find_map(|o| o.prompt.as_deref())
    }
}

/// Errors that can occur during hook execution
#[derive(Error, Debug, Clone)]
pub enum HookError {
    #[error("Hook timed out after {0} seconds")]
    Timeout(u64),

    #[error("Hook command failed: {0}")]
    CommandFailed(String),

    #[error("Hook output parse error: {0}")]
    ParseError(String),

    #[error("Hook blocked action: {0}")]
    Blocked(String),

    #[error("Invalid matcher regex: {0}")]
    InvalidMatcher(String),

    /// Allowlist enforcement rejected the command's executable.
    #[error("Hook command denied by allowlist: binary '{binary}' is not in allowed_commands")]
    Denied { binary: String },
}

/// Callback for executing model hooks via a provider adapter.
/// This avoids a direct dependency from hooks.rs on providers.rs.
pub type ModelHookCallback = Box<
    dyn Fn(
            String,
            String,
            Option<String>,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

/// The hook engine that executes hooks
#[derive(Clone)]
pub struct HookEngine {
    config: HooksConfig,
    /// Optional callback for executing model hooks.
    /// Takes (prompt, model, provider) and returns the model's response text.
    model_hook_callback: Option<Arc<ModelHookCallback>>,
}

impl HookEngine {
    #[must_use]
    pub fn new(config: HooksConfig) -> Self {
        Self {
            config,
            model_hook_callback: None,
        }
    }

    /// Set a callback for executing model hooks through a provider adapter
    #[must_use]
    pub fn with_model_callback(mut self, callback: ModelHookCallback) -> Self {
        self.model_hook_callback = Some(Arc::new(callback));
        self
    }

    /// Fire a `PostToolUse` hook (success) or `PostToolUseFailure`
    /// (error), depending on `success`. Convenience wrapper around
    /// [`HookEngine::run`] so every tool-execution call site can emit
    /// the post-tool lifecycle events in one line. Silently ignores
    /// missing session IDs (tests / one-shot invocations).
    pub async fn fire_post_tool(
        &self,
        success: bool,
        tool_name: &str,
        tool_input: serde_json::Value,
        tool_output: &str,
        session_id: Option<&str>,
    ) {
        let event = if success {
            HookEvent::PostToolUse
        } else {
            HookEvent::PostToolUseFailure
        };
        let mut input = HookInput::new(event).with_tool(tool_name, tool_input);
        if let Some(sid) = session_id {
            input = input.with_session_id(sid);
        }
        input = input.with_extra(
            "tool_output",
            serde_json::Value::String(tool_output.to_string()),
        );
        // Crosslink #778 (OWASP A09): never silently discard hook errors here.
        // `fire_post_tool` is fire-and-forget by design — failing audit hooks
        // must not abort the tool call — but the error itself MUST hit the
        // audit trail via `tracing::error!` so operator dashboards can alert.
        let result = self.run(event, &input).await;
        for (hook_error_index, hook_error) in result.errors.iter().enumerate() {
            error!(
                event = ?event,
                tool = %tool_name,
                session_id = ?session_id,
                hook_error_index,
                error = %hook_error,
                "fire_post_tool: hook execution failed (not propagated to caller)"
            );
        }
    }

    /// Run all matching hooks for an event
    pub async fn run(&self, event: HookEvent, input: &HookInput) -> HookResult {
        let entries = self.get_entries_for_event(event);

        if entries.is_empty() {
            return HookResult::allowed();
        }

        // Resolve matcher context strictly from the *event variant*.
        //
        // Crosslink #350: previously the context was inferred at runtime from
        // "whichever input field happens to be populated", which let a
        // `PreToolUse` matcher like `"rm"` accidentally match a user-prompt
        // string of `"I want to rm a file"`. Now each event has a fixed
        // [`HookMatcherTarget`] (see [`HookEvent::default_matcher_target`])
        // which selects exactly one typed accessor — `match_tool`,
        // `match_prompt`, or `match_event` — and there is no cross-target
        // fallback.
        //
        // Crosslink #758: `event` is still threaded through to `matches_entry`
        // so a matcher-regex *failure* on a deny-intent event
        // (PreToolUse / PermissionRequest) fails CLOSED — the hook still
        // runs and can block.
        let target = event.default_matcher_target();
        let matcher_context = Self::resolve_matcher_context(input, target);
        let matching_entries: Vec<&HookEntry> = entries
            .iter()
            .filter(|entry| Self::matches_entry(entry, &matcher_context, event))
            .collect();

        if matching_entries.is_empty() {
            return HookResult::allowed();
        }

        info!(
            event = ?event,
            count = matching_entries.len(),
            "Running hooks"
        );

        // Collect all hooks to run
        let mut hooks_to_run: Vec<(&Hook, u64)> = Vec::new();
        for entry in &matching_entries {
            for hook in &entry.hooks {
                let timeout_secs = match hook {
                    Hook::Command { timeout, .. }
                    | Hook::Prompt { timeout, .. }
                    | Hook::Model { timeout, .. } => *timeout,
                };
                hooks_to_run.push((hook, timeout_secs));
            }
        }

        // Run hooks in parallel.
        //
        // Crosslink #835: a serialization failure here previously fell
        // through to String::default() and sent empty stdin to every
        // hook — silently neutralising the entire hook batch. Surface
        // the error via tracing::error! and abort the run with a
        // deny-shaped HookResult so callers see the failure instead of
        // a misleading "hooks ran cleanly" signal.
        let input_json = match serde_json::to_string(input) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(
                    target: "openclaudia::hooks",
                    event = "hook_input_serialize_failed",
                    error = %e,
                    "failed to serialize HookInput; aborting hook batch \
                     (see crosslink #835)"
                );
                let mut failed = HookResult::allowed();
                if event.is_deny_intent() {
                    failed.allowed = false;
                }
                failed.errors.push(HookError::ParseError(format!(
                    "hook input serialize failed: {e}"
                )));
                return failed;
            }
        };
        let futures: Vec<_> = hooks_to_run
            .iter()
            .map(|(hook, timeout_secs)| self.run_hook(hook, &input_json, *timeout_secs))
            .collect();

        let results = futures::future::join_all(futures).await;

        // Combine results
        let mut hook_result = HookResult::allowed();
        for result in results {
            match result {
                Ok((output, exit_code)) => {
                    // Exit code 2 means block
                    if exit_code == 2 {
                        hook_result.allowed = false;
                        let reason = output
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Hook blocked action".to_string());
                        warn!(reason = %reason, "Hook blocked action");
                    }
                    // Check decision field
                    if let Some(decision) = &output.decision {
                        if decision == "deny" || decision == "block" {
                            hook_result.allowed = false;
                        }
                    }
                    hook_result.outputs.push(output);
                }
                Err(e) => {
                    error!(error = %e, "Hook execution failed");
                    hook_result.errors.push(e);
                }
            }
        }
        if event.is_deny_intent() && !hook_result.errors.is_empty() {
            warn!(
                event = ?event,
                error_count = hook_result.errors.len(),
                "Deny-intent hook execution failed; failing closed"
            );
            hook_result.allowed = false;
        }

        hook_result
    }

    /// Get hook entries for a specific event. `PostToolUseFailure` falls
    /// back to `PostToolUse` when no failure-specific handlers are defined
    /// — matches Claude Code's behavior where a single `PostToolUse` hook
    /// sees both success and failure paths unless a dedicated handler
    /// exists.
    fn get_entries_for_event(&self, event: HookEvent) -> &[HookEntry] {
        match event {
            HookEvent::SessionStart => &self.config.session_start,
            HookEvent::SessionEnd => &self.config.session_end,
            HookEvent::PreToolUse => &self.config.pre_tool_use,
            HookEvent::PostToolUse => &self.config.post_tool_use,
            HookEvent::PostToolUseFailure => {
                if self.config.post_tool_use_failure.is_empty() {
                    &self.config.post_tool_use
                } else {
                    &self.config.post_tool_use_failure
                }
            }
            HookEvent::UserPromptSubmit => &self.config.user_prompt_submit,
            HookEvent::Stop => &self.config.stop,
            HookEvent::SubagentStart => &self.config.subagent_start,
            HookEvent::SubagentStop => &self.config.subagent_stop,
            HookEvent::PreCompact => &self.config.pre_compact,
            HookEvent::PermissionRequest => &self.config.permission_request,
            HookEvent::Notification => &self.config.notification,
            // VDD events
            HookEvent::PreAdversaryReview => &self.config.pre_adversary_review,
            HookEvent::PostAdversaryReview => &self.config.post_adversary_review,
            HookEvent::VddConflict => &self.config.vdd_conflict,
            HookEvent::VddConverged => &self.config.vdd_converged,
        }
    }

    /// Resolve the string the matcher regex should be tested against, based
    /// on the [`HookMatcherTarget`] selected for this entry/event.
    ///
    /// Crosslink #350: replaces the legacy `get_matcher_context` helper that
    /// inferred the target at runtime from "whichever input field happens to
    /// be set", which let matchers cross-fire between tool names and user
    /// prompts. Each branch here calls exactly one of the typed accessors
    /// ([`HookInput::match_tool`] / [`HookInput::match_prompt`] /
    /// [`HookInput::match_event`]) — there is no fallback across target
    /// kinds. If the targeted slot is empty, the context is an empty string
    /// and the matcher will simply not match (which is the correct behaviour
    /// when, e.g., a tool-targeted hook fires on an event that carries no
    /// `tool_name`).
    fn resolve_matcher_context(input: &HookInput, target: HookMatcherTarget) -> String {
        match target {
            HookMatcherTarget::ToolName => input.match_tool().unwrap_or("").to_string(),
            HookMatcherTarget::Prompt => input.match_prompt().unwrap_or("").to_string(),
            // `match_event` always returns Some(...), but unwrap_or keeps the
            // shape uniform with the other two arms.
            HookMatcherTarget::EventKey => input.match_event().unwrap_or("").to_string(),
        }
    }

    /// Check if a hook entry matches the current context.
    ///
    /// On matcher-regex failure (compile error, oversize pattern, empty
    /// pattern) the fail-mode is chosen by [`HookEvent::is_deny_intent`]:
    ///
    /// - Deny-intent events (e.g. `PreToolUse`, `PermissionRequest`)
    ///   **fail CLOSED** — return `true` so the hook still runs and can
    ///   enforce its block. A typo in a deny-hook matcher must never silently
    ///   disable the gate. Crosslink #758.
    /// - All other (observe-intent) events **fail OPEN** — return `false` so
    ///   a malformed audit/observability hook does not accidentally fire on
    ///   unrelated tool calls.
    ///
    /// Both paths emit a structured `tracing::warn!` with the event, pattern,
    /// underlying error, and the `fail_closed` flag so operators can spot
    /// silently-misconfigured matchers.
    fn matches_entry(entry: &HookEntry, context: &str, event: HookEvent) -> bool {
        let Some(pattern) = entry.matcher.as_ref() else {
            return true; // No matcher → always matches (unchanged behaviour)
        };

        match Self::validate_and_match(pattern, context) {
            Ok(matched) => matched,
            Err(e) => {
                let fail_closed = event.is_deny_intent();
                warn!(
                    event = ?event,
                    pattern = %pattern,
                    error = %e,
                    fail_closed,
                    "Hook matcher regex failed; defaulting per event intent \
                     (deny-intent events fail closed so the hook still runs)"
                );
                fail_closed
            }
        }
    }

    /// Validate regex pattern and check for match
    /// Maximum pattern length to prevent `ReDoS` via complex expressions.
    const MAX_PATTERN_LEN: usize = 1024;
    /// Maximum compiled regex size (bytes) to limit pathological backtracking.
    const MAX_REGEX_SIZE: usize = 10 * 1024; // 10KB

    fn validate_and_match(pattern: &str, context: &str) -> Result<bool, HookError> {
        if pattern.is_empty() {
            return Err(HookError::InvalidMatcher("Empty pattern".to_string()));
        }
        if pattern.len() > Self::MAX_PATTERN_LEN {
            return Err(HookError::InvalidMatcher(format!(
                "Pattern too long ({} chars, max {})",
                pattern.len(),
                Self::MAX_PATTERN_LEN
            )));
        }

        match RegexBuilder::new(pattern)
            .size_limit(Self::MAX_REGEX_SIZE)
            .build()
        {
            Ok(re) => Ok(re.is_match(context)),
            Err(e) => Err(HookError::InvalidMatcher(e.to_string())),
        }
    }

    /// Parse hook output — matches Claude Code behavior:
    /// - Empty output → default
    /// - Starts with '{' → try JSON parse, fall back to plain text on failure
    /// - Anything else → treat as plain text (`additionalContext` / system-reminder)
    fn parse_hook_output(stdout: &str) -> HookOutput {
        let trimmed = stdout.trim();
        if trimmed.is_empty() {
            return HookOutput::default();
        }

        // Only try JSON parse if it looks like JSON (starts with '{')
        if trimmed.starts_with('{') {
            match serde_json::from_str(trimmed) {
                Ok(output) => return output,
                Err(_) => {
                    // Invalid JSON that starts with { — treat as plain text
                    debug!("Hook output starts with '{{' but is not valid JSON, treating as plain text");
                }
            }
        }

        // Plain text output — wrap as additionalContext (like Claude Code does)
        HookOutput {
            additional_context: Some(trimmed.to_string()),
            ..Default::default()
        }
    }

    /// Check if an action should be blocked based on hook result.
    ///
    /// # Errors
    ///
    /// Returns `HookError::Blocked` if the hook result indicates the action is denied.
    pub fn check_blocked(result: &HookResult) -> Result<(), HookError> {
        if result.allowed {
            Ok(())
        } else {
            let reasons: Vec<String> = result
                .outputs
                .iter()
                .filter_map(|o| o.reason.clone())
                .collect();
            let reason = if reasons.is_empty() {
                "Action blocked by hook".to_string()
            } else {
                reasons.join("; ")
            };
            Err(HookError::Blocked(reason))
        }
    }

    /// Fire a notification event with type and data.
    pub async fn fire_notification(&self, notification_type: &str, data: Value) -> Vec<HookResult> {
        let input = notification_input(notification_type, data);

        debug!(
            notification_type = %notification_type,
            "Firing notification hook"
        );

        vec![self.run(HookEvent::Notification, &input).await]
    }

    /// Run a single hook
    async fn run_hook(
        &self,
        hook: &Hook,
        input_json: &str,
        timeout_secs: u64,
    ) -> Result<(HookOutput, i32), HookError> {
        match hook {
            Hook::Command { command, shell, .. } => {
                self.run_command_hook(
                    command,
                    *shell,
                    self.config.policy.as_ref(),
                    input_json,
                    timeout_secs,
                )
                .await
            }
            Hook::Prompt { prompt, .. } => {
                // Prompt hooks just return the prompt as system message
                Ok((
                    HookOutput {
                        system_message: Some(prompt.clone()),
                        ..Default::default()
                    },
                    0,
                ))
            }
            Hook::Model {
                prompt,
                model,
                provider,
                ..
            } => {
                self.run_model_hook(prompt, model, provider.as_deref(), timeout_secs)
                    .await
            }
        }
    }

    /// Build a [`Command`] for direct-spawn mode (no shell).
    ///
    /// Tokenises `command` with `shlex`, enforces the allowlist, and returns
    /// the ready-to-spawn `Command`. Returns `Err` on tokenisation failure or
    /// allowlist denial.
    fn build_direct_command(
        command: &str,
        policy: Option<&HookPolicy>,
    ) -> Result<Command, HookError> {
        let tokens = shlex::split(command).ok_or_else(|| {
            HookError::CommandFailed(format!(
                "Failed to tokenise hook command (unterminated quote?): {command}"
            ))
        })?;

        if tokens.is_empty() {
            return Err(HookError::CommandFailed(
                "Hook command is empty after tokenisation".to_string(),
            ));
        }

        let binary_path = &tokens[0];
        // Strip to basename so "/usr/bin/python3" matches allowlist entry "python3".
        let binary_name = Path::new(binary_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(binary_path.as_str());

        match policy {
            Some(p) => {
                if let Some(allowed) = &p.allowed_commands {
                    if !allowed.contains(binary_name) {
                        return Err(HookError::Denied {
                            binary: binary_name.to_string(),
                        });
                    }
                }
            }
            None => {
                if !ALLOW_ALL_DEPRECATION_WARNED.swap(true, Ordering::Relaxed) {
                    warn!(
                        "HooksConfig has no `policy` field — allowing every hook \
                         executable name inside the full OS sandbox. Add \
                         `policy: {{allowed_commands: [...]}}` to restrict which \
                         binaries hooks may execute."
                    );
                }
            }
        }

        let mut cmd = Command::new(binary_path);
        if tokens.len() > 1 {
            cmd.args(&tokens[1..]);
        }
        Ok(cmd)
    }

    /// Scrub credential env vars and inject `CLAUDE_PROJECT_DIR` into `cmd`.
    fn apply_hook_env(cmd: &mut Command, project_dir: &std::path::Path) {
        let sensitive: Vec<String> = std::env::vars()
            .map(|(k, _)| k)
            .filter(|k| is_sensitive_env(k))
            .collect();
        for key in &sensitive {
            cmd.env_remove(key);
        }
        cmd.env("CLAUDE_PROJECT_DIR", project_dir);
    }

    fn resolved_hook_shell() -> Result<(PathBuf, &'static str), HookError> {
        let (shell, shell_arg) = if cfg!(windows) {
            ("cmd", "/C")
        } else {
            ("sh", "-c")
        };
        let shell_path = which::which(shell).map_err(|e| {
            HookError::CommandFailed(format!("{shell} binary not found on PATH: {e}"))
        })?;
        Ok((shell_path, shell_arg))
    }

    async fn write_hook_stdin<W>(stdin: &mut W, input_json: &str) -> Result<(), HookError>
    where
        W: AsyncWrite + Unpin,
    {
        stdin.write_all(input_json.as_bytes()).await.map_err(|e| {
            HookError::CommandFailed(format!("failed to write hook input to stdin: {e}"))
        })?;
        stdin
            .shutdown()
            .await
            .map_err(|e| HookError::CommandFailed(format!("failed to close hook input stdin: {e}")))
    }

    async fn terminate_child_after_stdin_failure(child: &mut Child) {
        if let Some(pid) = child.id() {
            let _ = tokio::task::spawn_blocking(move || {
                crate::tools::terminate_process_tree(pid);
            })
            .await;
        }
        if let Err(e) = child.start_kill() {
            debug!(error = %e, "Failed to kill hook process after stdin failure");
        }
        if let Err(e) = child.wait().await {
            debug!(error = %e, "Failed to reap hook process after stdin failure");
        }
    }

    async fn read_bounded_hook_stream<R>(mut stream: R) -> Result<Vec<u8>, std::io::Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut retained = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut truncated = false;
        loop {
            let count = stream.read(&mut chunk).await?;
            if count == 0 {
                break;
            }
            let remaining = MAX_HOOK_OUTPUT_BYTES_PER_STREAM.saturating_sub(retained.len());
            let keep = remaining.min(count);
            retained.extend_from_slice(&chunk[..keep]);
            truncated |= keep < count;
        }
        if truncated {
            retained.extend_from_slice(HOOK_OUTPUT_TRUNCATED_MARKER);
        }
        Ok(retained)
    }

    async fn wait_for_hook_output(
        mut child: Child,
        timeout_secs: u64,
    ) -> Result<std::process::Output, HookError> {
        let pid = child.id();
        let stdout = child.stdout.take().ok_or_else(|| {
            HookError::CommandFailed("hook stdout unavailable after spawn".to_string())
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            HookError::CommandFailed("hook stderr unavailable after spawn".to_string())
        })?;
        let stdout_reader = tokio::spawn(Self::read_bounded_hook_stream(stdout));
        let stderr_reader = tokio::spawn(Self::read_bounded_hook_stream(stderr));
        let status = match timeout(Duration::from_secs(timeout_secs), child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(error)) => {
                if let Some(pid) = pid {
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::tools::terminate_process_tree(pid);
                    })
                    .await;
                }
                return Err(HookError::CommandFailed(error.to_string()));
            }
            Err(_) => {
                if let Some(pid) = pid {
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::tools::terminate_process_tree(pid);
                    })
                    .await;
                }
                let _ = child.start_kill();
                let _ = child.wait().await;
                let _ = stdout_reader.await;
                let _ = stderr_reader.await;
                return Err(HookError::Timeout(timeout_secs));
            }
        };
        let stdout = stdout_reader
            .await
            .map_err(|error| HookError::CommandFailed(error.to_string()))?
            .map_err(|error| HookError::CommandFailed(error.to_string()))?;
        let stderr = stderr_reader
            .await
            .map_err(|error| HookError::CommandFailed(error.to_string()))?
            .map_err(|error| HookError::CommandFailed(error.to_string()))?;
        Ok(std::process::Output {
            status,
            stdout,
            stderr,
        })
    }

    #[cfg(unix)]
    fn isolate_hook_process_group(command: &mut Command) {
        use std::os::unix::process::CommandExt as _;
        command.as_std_mut().process_group(0);
    }

    #[cfg(not(unix))]
    fn isolate_hook_process_group(_command: &mut Command) {
        // The enforced Windows backend uses a Job object when available.
    }

    /// Execute a command hook.
    ///
    /// Two execution paths:
    /// - `use_shell = false` (default): tokenise with `shlex`, exec directly —
    ///   shell metacharacters are inert literal arguments.
    /// - `use_shell = true` (opt-in): pass to `sh -c`, warn loudly on every call.
    ///
    /// Credentials are scrubbed in both paths. See [`Self::build_direct_command`].
    async fn run_command_hook(
        &self,
        command: &str,
        use_shell: bool,
        policy: Option<&HookPolicy>,
        input_json: &str,
        timeout_secs: u64,
    ) -> Result<(HookOutput, i32), HookError> {
        debug!(command = %command, shell = use_shell, "Running command hook");

        // Resolve cwd eagerly — missing cwd is a hard error, not a silent "".
        let security =
            crate::tools::security::current_context().map_err(HookError::CommandFailed)?;
        let project_dir = security.working_directory().to_path_buf();

        let mut child_cmd = if use_shell {
            warn!(
                command = %command,
                "Hook is running with shell:true — shell injection risk. \
                 Consider converting to a direct-spawn hook."
            );
            let (shell_path, shell_arg) = Self::resolved_hook_shell()?;
            let mut cmd = Command::new(shell_path);
            cmd.arg(shell_arg).arg(command);
            cmd
        } else {
            Self::build_direct_command(command, policy)?
        };

        Self::apply_hook_env(&mut child_cmd, &project_dir);
        let sandbox_mode = policy.map_or(SandboxMode::FullSandbox, |hook_policy| {
            hook_policy.sandbox.clone()
        });
        if sandbox_mode == SandboxMode::FullSandbox {
            let sandboxed = crate::tools::sandboxed_hook_command(child_cmd.as_std(), &project_dir)
                .map_err(|error| {
                    HookError::CommandFailed(format!("failed to create full hook sandbox: {error}"))
                })?;
            child_cmd = Command::from(sandboxed);
        } else {
            let trusted = TRUST_UNSANDBOXED_HOOKS
                .as_ref()
                .map_err(Clone::clone)
                .map_err(HookError::CommandFailed)?;
            if !trusted {
                return Err(HookError::CommandFailed(format!(
                    "hook sandbox mode '{sandbox_mode:?}' requests host execution, which is blocked. \
                     A host operator must explicitly start OpenClaudia with \
                     {TRUST_UNSANDBOXED_HOOKS_ENV}=true to trust unsandboxed hooks"
                )));
            }
            warn!(
                mode = ?sandbox_mode,
                env = TRUST_UNSANDBOXED_HOOKS_ENV,
                "Hook OS sandbox explicitly disabled by the host operator"
            );
        }

        Self::isolate_hook_process_group(&mut child_cmd);
        let mut child = child_cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| HookError::CommandFailed(e.to_string()))?;
        let _process_registration = (sandbox_mode == SandboxMode::FullSandbox).then(|| {
            child
                .id()
                .map(crate::tools::command::ActiveSandboxProcess::register)
        });

        let Some(mut stdin) = child.stdin.take() else {
            Self::terminate_child_after_stdin_failure(&mut child).await;
            return Err(HookError::CommandFailed(
                "hook stdin unavailable".to_string(),
            ));
        };
        let stdin_result = Self::write_hook_stdin(&mut stdin, input_json).await;
        drop(stdin);
        if let Err(e) = stdin_result {
            Self::terminate_child_after_stdin_failure(&mut child).await;
            return Err(e);
        }

        match Self::wait_for_hook_output(child, timeout_secs).await {
            Ok(output) => {
                let exit_code = output.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.is_empty() {
                    debug!(stderr = %stderr, "Hook stderr");
                }
                if exit_code != 0 && exit_code != 2 {
                    const MAX_HOOK_ERROR_BYTES: usize = 4096;
                    let diagnostic =
                        crate::tools::safe_truncate(stderr.trim(), MAX_HOOK_ERROR_BYTES);
                    let suffix = if diagnostic.is_empty() {
                        String::new()
                    } else {
                        format!(": {diagnostic}")
                    };
                    return Err(HookError::CommandFailed(format!(
                        "hook process exited with status {exit_code}{suffix}"
                    )));
                }
                Ok((Self::parse_hook_output(&stdout), exit_code))
            }
            Err(e) => Err(e),
        }
    }

    /// Execute a model hook by sending a prompt to a specified model/provider
    async fn run_model_hook(
        &self,
        prompt: &str,
        model: &str,
        provider: Option<&str>,
        timeout_secs: u64,
    ) -> Result<(HookOutput, i32), HookError> {
        debug!(
            model = %model,
            provider = ?provider,
            "Running model hook"
        );

        let callback = self.model_hook_callback.as_ref().ok_or_else(|| {
            HookError::CommandFailed(
                "Model hook requires a model callback to be configured on the HookEngine"
                    .to_string(),
            )
        })?;

        let future = callback(
            prompt.to_string(),
            model.to_string(),
            provider.map(String::from),
        );

        match timeout(Duration::from_secs(timeout_secs), future).await {
            Ok(Ok(response)) => Ok((
                HookOutput {
                    system_message: Some(response),
                    ..Default::default()
                },
                0,
            )),
            Ok(Err(e)) => Err(HookError::CommandFailed(format!("Model hook error: {e}"))),
            Err(_) => Err(HookError::Timeout(timeout_secs)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HooksConfig, SandboxMode};
    use merge::merge_claude_hooks;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct FailingAsyncWrite;

    impl tokio::io::AsyncWrite for FailingAsyncWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "synthetic broken pipe",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn test_hook_event_config_keys() {
        assert_eq!(HookEvent::SessionStart.config_key(), "session_start");
        assert_eq!(HookEvent::PreToolUse.config_key(), "pre_tool_use");
        assert_eq!(
            HookEvent::UserPromptSubmit.config_key(),
            "user_prompt_submit"
        );
    }

    #[test]
    fn test_hook_input_builder() {
        let input = HookInput::new(HookEvent::PreToolUse)
            .with_session_id("test-session")
            .with_tool("Write", serde_json::json!({"path": "/tmp/test"}));

        assert_eq!(input.event, HookEvent::PreToolUse);
        assert_eq!(input.session_id, Some("test-session".to_string()));
        assert_eq!(input.tool_name, Some("Write".to_string()));
    }

    #[test]
    fn notification_input_sets_expected_extra_fields() {
        let input = notification_input("status", serde_json::json!({"ok": true}));

        assert_eq!(input.event, HookEvent::Notification);
        assert_eq!(
            input.extra.get("notification_type"),
            Some(&Value::String("status".to_string()))
        );
        assert_eq!(
            input.extra.get("data"),
            Some(&serde_json::json!({"ok": true}))
        );
    }

    #[test]
    fn test_hook_result_system_messages() {
        let result = HookResult {
            allowed: true,
            outputs: vec![
                HookOutput {
                    system_message: Some("Message 1".to_string()),
                    ..Default::default()
                },
                HookOutput {
                    system_message: Some("Message 2".to_string()),
                    ..Default::default()
                },
            ],
            errors: vec![],
        };

        let messages = result.system_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], "Message 1");
        assert_eq!(messages[1], "Message 2");
    }

    #[tokio::test]
    async fn test_empty_hooks_config() {
        let engine = HookEngine::new(HooksConfig::default());
        let input = HookInput::new(HookEvent::SessionStart);
        let result = engine.run(HookEvent::SessionStart, &input).await;

        assert!(result.allowed);
        assert!(result.outputs.is_empty());
    }

    #[tokio::test]
    async fn hook_stdin_write_failure_returns_command_failed() {
        let mut writer = FailingAsyncWrite;
        let err = HookEngine::write_hook_stdin(&mut writer, "{}")
            .await
            .expect_err("broken stdin write must fail");

        match err {
            HookError::CommandFailed(message) => {
                assert!(message.contains("stdin"), "{message}");
                assert!(message.contains("synthetic broken pipe"), "{message}");
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    // ========================================================================
    // Claude Code Compatibility Tests
    // ========================================================================

    #[test]
    fn test_hook_event_from_claude_code_name() {
        // Test all Claude Code event names
        assert_eq!(
            HookEvent::from_claude_code_name("PreToolUse"),
            Some(HookEvent::PreToolUse)
        );
        assert_eq!(
            HookEvent::from_claude_code_name("PostToolUse"),
            Some(HookEvent::PostToolUse)
        );
        assert_eq!(
            HookEvent::from_claude_code_name("UserPromptSubmit"),
            Some(HookEvent::UserPromptSubmit)
        );
        assert_eq!(
            HookEvent::from_claude_code_name("PreCompact"),
            Some(HookEvent::PreCompact)
        );
        assert_eq!(
            HookEvent::from_claude_code_name("Stop"),
            Some(HookEvent::Stop)
        );
        assert_eq!(
            HookEvent::from_claude_code_name("SubagentStart"),
            Some(HookEvent::SubagentStart)
        );

        // Unknown events should return None
        assert_eq!(HookEvent::from_claude_code_name("UnknownEvent"), None);
        assert_eq!(HookEvent::from_claude_code_name(""), None);
    }

    #[test]
    fn test_parse_claude_code_settings() {
        let json = r#"{
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Write|Edit",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python validate.py"
                            }
                        ]
                    }
                ],
                "PreCompact": [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": "bd prime",
                                "timeout": 30
                            }
                        ]
                    }
                ]
            }
        }"#;

        let settings: ClaudeCodeSettings = serde_json::from_str(json).unwrap();
        assert_eq!(settings.hooks.len(), 2);
        assert!(settings.hooks.contains_key("PreToolUse"));
        assert!(settings.hooks.contains_key("PreCompact"));

        // Check PreToolUse entry
        let pre_tool = &settings.hooks["PreToolUse"][0];
        assert_eq!(pre_tool.matcher, Some("Write|Edit".to_string()));
        assert_eq!(pre_tool.hooks.len(), 1);

        // Check PreCompact entry has no matcher (empty string is treated as None)
        let pre_compact = &settings.hooks["PreCompact"][0];
        assert!(pre_compact.matcher.is_none() || pre_compact.matcher.as_deref() == Some(""));
    }

    #[test]
    fn test_merge_claude_hooks() {
        let json = r#"{
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Write",
                        "hooks": [
                            {"type": "command", "command": "echo test"}
                        ]
                    }
                ],
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            {"type": "command", "command": "python guard.py"}
                        ]
                    }
                ]
            }
        }"#;

        let settings: ClaudeCodeSettings = serde_json::from_str(json).unwrap();
        let mut config = HooksConfig::default();
        merge_claude_hooks(&mut config, &settings);

        // Should have hooks in the appropriate event lists
        assert_eq!(config.pre_tool_use.len(), 1);
        assert_eq!(config.user_prompt_submit.len(), 1);

        // Check the converted hook
        let entry = &config.pre_tool_use[0];
        assert_eq!(entry.matcher, Some("Write".to_string()));
        assert_eq!(entry.hooks.len(), 1);

        match &entry.hooks[0] {
            Hook::Command {
                command, timeout, ..
            } => {
                assert_eq!(command, "echo test");
                assert_eq!(*timeout, 60); // default timeout
            }
            _ => panic!("Expected Command hook"),
        }
    }

    #[test]
    fn test_hooks_config_is_empty() {
        let empty = HooksConfig::default();
        assert!(empty.is_empty());

        let mut non_empty = HooksConfig::default();
        non_empty.pre_tool_use.push(HookEntry {
            matcher: None,
            hooks: vec![],
        });
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_merge_hooks_config() {
        let mut base = HooksConfig::default();
        base.pre_tool_use.push(HookEntry {
            matcher: Some("Read".to_string()),
            hooks: vec![],
        });

        let mut other = HooksConfig::default();
        other.pre_tool_use.push(HookEntry {
            matcher: Some("Write".to_string()),
            hooks: vec![],
        });
        other.user_prompt_submit.push(HookEntry {
            matcher: None,
            hooks: vec![],
        });

        let merged = merge_hooks_config(base, other);

        // Should have entries from both configs
        assert_eq!(merged.pre_tool_use.len(), 2);
        assert_eq!(merged.user_prompt_submit.len(), 1);
    }

    #[test]
    fn test_empty_matcher_filtered() {
        let json = r#"{
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "",
                        "hooks": [
                            {"type": "command", "command": "echo test"}
                        ]
                    }
                ]
            }
        }"#;

        let settings: ClaudeCodeSettings = serde_json::from_str(json).unwrap();
        let mut config = HooksConfig::default();
        merge_claude_hooks(&mut config, &settings);

        // Empty matcher should be converted to None (matches all)
        assert_eq!(config.pre_tool_use[0].matcher, None);
    }

    // ========================================================================
    // Extended HookInput Tests
    // ========================================================================

    #[test]
    fn test_hook_input_with_prompt() {
        let input =
            HookInput::new(HookEvent::UserPromptSubmit).with_prompt("How do I fix this bug?");

        assert_eq!(input.event, HookEvent::UserPromptSubmit);
        assert_eq!(input.prompt, Some("How do I fix this bug?".to_string()));
    }

    #[test]
    fn test_hook_input_with_extra() {
        let input = HookInput::new(HookEvent::PreCompact)
            .with_extra("current_tokens", serde_json::json!(50_000))
            .with_extra("max_tokens", serde_json::json!(100_000));

        assert_eq!(
            input.extra.get("current_tokens"),
            Some(&serde_json::json!(50_000))
        );
        assert_eq!(
            input.extra.get("max_tokens"),
            Some(&serde_json::json!(100_000))
        );
    }

    #[test]
    fn test_hook_input_cwd_populated() {
        let input = HookInput::new(HookEvent::SessionStart);

        // CWD should be populated from env
        assert!(!input.cwd.is_empty());
    }

    #[test]
    fn test_hook_input_serialization() {
        let input = HookInput::new(HookEvent::PreToolUse)
            .with_session_id("session-123")
            .with_tool("bash", serde_json::json!({"command": "ls"}));

        let json = serde_json::to_string(&input).unwrap();

        assert!(json.contains("\"event\":\"pre_tool_use\""));
        assert!(json.contains("\"session_id\":\"session-123\""));
        assert!(json.contains("\"tool_name\":\"bash\""));
    }

    // ========================================================================
    // Extended HookResult Tests
    // ========================================================================

    #[test]
    fn test_hook_result_denied() {
        let result = HookResult::denied("Action not allowed");

        assert!(!result.allowed);
        assert_eq!(result.outputs.len(), 1);
        assert_eq!(result.outputs[0].decision, Some("deny".to_string()));
        assert_eq!(
            result.outputs[0].reason,
            Some("Action not allowed".to_string())
        );
    }

    #[test]
    fn test_hook_result_modified_prompt() {
        let result = HookResult {
            allowed: true,
            outputs: vec![HookOutput {
                prompt: Some("Modified user prompt".to_string()),
                ..Default::default()
            }],
            errors: vec![],
        };

        assert_eq!(result.modified_prompt(), Some("Modified user prompt"));
    }

    #[test]
    fn test_hook_result_no_modified_prompt() {
        let result = HookResult::allowed();
        assert_eq!(result.modified_prompt(), None);
    }

    #[test]
    fn test_hook_result_multiple_system_messages() {
        let result = HookResult {
            allowed: true,
            outputs: vec![
                HookOutput {
                    system_message: Some("Security warning".to_string()),
                    ..Default::default()
                },
                HookOutput::default(), // No message
                HookOutput {
                    system_message: Some("Style guide reminder".to_string()),
                    ..Default::default()
                },
            ],
            errors: vec![],
        };

        let messages = result.system_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], "Security warning");
        assert_eq!(messages[1], "Style guide reminder");
    }

    // ========================================================================
    // HookError Tests
    // ========================================================================

    #[test]
    fn test_hook_error_display() {
        let timeout_err = HookError::Timeout(30);
        assert_eq!(format!("{timeout_err}"), "Hook timed out after 30 seconds");

        let cmd_err = HookError::CommandFailed("Process exited with code 1".to_string());
        assert_eq!(
            format!("{cmd_err}"),
            "Hook command failed: Process exited with code 1"
        );

        let parse_err = HookError::ParseError("Invalid JSON".to_string());
        assert_eq!(
            format!("{parse_err}"),
            "Hook output parse error: Invalid JSON"
        );

        let blocked_err = HookError::Blocked("File write not allowed".to_string());
        assert_eq!(
            format!("{blocked_err}"),
            "Hook blocked action: File write not allowed"
        );

        let matcher_err = HookError::InvalidMatcher("(unclosed".to_string());
        assert_eq!(format!("{matcher_err}"), "Invalid matcher regex: (unclosed");
    }

    // ========================================================================
    // HookEngine Matcher Tests
    // ========================================================================

    #[test]
    fn test_hook_engine_matcher_regex() {
        // Valid pattern match
        let result = HookEngine::validate_and_match("Write|Edit", "Write");
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Valid pattern no match
        let result = HookEngine::validate_and_match("Write|Edit", "Read");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_hook_engine_matcher_invalid_regex() {
        // Invalid regex pattern
        let result = HookEngine::validate_and_match("(unclosed", "test");
        assert!(result.is_err());
        assert!(matches!(result, Err(HookError::InvalidMatcher(_))));
    }

    #[test]
    fn test_hook_engine_matcher_empty_pattern() {
        // Empty pattern is invalid
        let result = HookEngine::validate_and_match("", "test");
        assert!(result.is_err());
    }

    #[test]
    fn test_hook_engine_matcher_complex_patterns() {
        // Case sensitive by default
        let result = HookEngine::validate_and_match("Write", "write");
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should not match (case sensitive)

        // Dot matches any char
        let result = HookEngine::validate_and_match(".*file.*", "read_file_content");
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Character class
        let result = HookEngine::validate_and_match("^(read|write)_.*", "read_file");
        assert!(result.is_ok());
        assert!(result.unwrap());

        let result = HookEngine::validate_and_match("^(read|write)_.*", "delete_file");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // ========================================================================
    // HookEngine Check Blocked Tests
    // ========================================================================

    #[test]
    fn test_check_blocked_allowed() {
        let result = HookResult::allowed();
        assert!(HookEngine::check_blocked(&result).is_ok());
    }

    #[test]
    fn test_check_blocked_denied() {
        let result = HookResult::denied("Not permitted");
        let err = HookEngine::check_blocked(&result);
        assert!(err.is_err());

        match err {
            Err(HookError::Blocked(reason)) => {
                assert_eq!(reason, "Not permitted");
            }
            _ => panic!("Expected Blocked error"),
        }
    }

    #[test]
    fn test_check_blocked_denied_default_reason() {
        let result = HookResult {
            allowed: false,
            outputs: vec![], // No outputs with reason
            errors: vec![],
        };

        let err = HookEngine::check_blocked(&result);
        assert!(err.is_err());

        match err {
            Err(HookError::Blocked(reason)) => {
                assert_eq!(reason, "Action blocked by hook");
            }
            _ => panic!("Expected Blocked error"),
        }
    }

    // ========================================================================
    // HookOutput Tests
    // ========================================================================

    #[test]
    fn test_hook_output_default() {
        let output = HookOutput::default();
        assert!(output.decision.is_none());
        assert!(output.reason.is_none());
        assert!(output.system_message.is_none());
        assert!(output.prompt.is_none());
        assert!(output.extra.is_empty());
    }

    #[test]
    fn test_hook_output_from_json() {
        let json = r#"{
            "decision": "allow",
            "reason": "Validation passed",
            "systemMessage": "Remember to test",
            "prompt": "Modified prompt",
            "customField": "custom value"
        }"#;

        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.decision, Some("allow".to_string()));
        assert_eq!(output.reason, Some("Validation passed".to_string()));
        assert_eq!(output.system_message, Some("Remember to test".to_string()));
        assert_eq!(output.prompt, Some("Modified prompt".to_string()));
        assert_eq!(
            output.extra.get("customField"),
            Some(&serde_json::json!("custom value"))
        );
    }

    #[test]
    fn test_hook_output_partial_json() {
        let json = r#"{"decision": "deny"}"#;

        let output: HookOutput = serde_json::from_str(json).unwrap();
        assert_eq!(output.decision, Some("deny".to_string()));
        assert!(output.reason.is_none());
        assert!(output.system_message.is_none());
    }

    // ========================================================================
    // Parse Hook Output Tests
    // ========================================================================

    #[test]
    fn test_parse_hook_output_empty() {
        let output = HookEngine::parse_hook_output("");
        assert!(output.decision.is_none());
    }

    #[test]
    fn test_parse_hook_output_whitespace() {
        let output = HookEngine::parse_hook_output("   \n\t  ");
        assert!(output.decision.is_none());
    }

    #[test]
    fn test_parse_hook_output_valid_json() {
        let output = HookEngine::parse_hook_output(r#"{"decision": "allow"}"#);
        assert_eq!(output.decision, Some("allow".to_string()));
    }

    #[test]
    fn test_parse_hook_output_plain_text() {
        // Plain text (not starting with '{') is treated as additionalContext, not an error
        let result = HookEngine::parse_hook_output("not valid json {");
        assert_eq!(
            result.additional_context,
            Some("not valid json {".to_string())
        );
    }

    #[test]
    fn test_parse_hook_output_invalid_json_starting_with_brace() {
        // Starts with '{' but invalid JSON — still treated as plain text
        let result = HookEngine::parse_hook_output("{not valid}");
        assert_eq!(result.additional_context, Some("{not valid}".to_string()));
    }

    // ========================================================================
    // All Hook Events Test
    // ========================================================================

    #[test]
    fn test_all_hook_events_have_config_keys() {
        // Verify all events return valid config keys
        let events = vec![
            HookEvent::SessionStart,
            HookEvent::SessionEnd,
            HookEvent::PreToolUse,
            HookEvent::PostToolUse,
            HookEvent::PostToolUseFailure,
            HookEvent::UserPromptSubmit,
            HookEvent::Stop,
            HookEvent::SubagentStart,
            HookEvent::SubagentStop,
            HookEvent::PreCompact,
            HookEvent::PermissionRequest,
            HookEvent::Notification,
        ];

        for event in events {
            let key = event.config_key();
            assert!(
                !key.is_empty(),
                "Event {event:?} should have non-empty config key"
            );
            assert!(
                key.chars().all(|c| c.is_lowercase() || c == '_'),
                "Config key '{key}' should be snake_case"
            );
        }
    }

    // ========================================================================
    // Async Hook Tests
    // ========================================================================

    #[tokio::test]
    async fn test_run_with_matching_entry() {
        let mut config = HooksConfig::default();
        config.pre_tool_use.push(crate::config::HookEntry {
            matcher: Some("Write".to_string()),
            hooks: vec![crate::config::Hook::Prompt {
                prompt: "Remember to backup".to_string(),
                timeout: 30,
            }],
        });

        let engine = HookEngine::new(config);
        let input = HookInput::new(HookEvent::PreToolUse)
            .with_tool("Write", serde_json::json!({"path": "/tmp/test"}));

        let result = engine.run(HookEvent::PreToolUse, &input).await;

        assert!(result.allowed);
        assert_eq!(result.outputs.len(), 1);
        assert_eq!(
            result.outputs[0].system_message,
            Some("Remember to backup".to_string())
        );
    }

    #[tokio::test]
    async fn test_run_with_non_matching_entry() {
        let mut config = HooksConfig::default();
        config.pre_tool_use.push(crate::config::HookEntry {
            matcher: Some("Write".to_string()),
            hooks: vec![crate::config::Hook::Prompt {
                prompt: "Should not appear".to_string(),
                timeout: 30,
            }],
        });

        let engine = HookEngine::new(config);
        let input = HookInput::new(HookEvent::PreToolUse)
            .with_tool("Read", serde_json::json!({"path": "/tmp/test"})); // Different tool

        let result = engine.run(HookEvent::PreToolUse, &input).await;

        assert!(result.allowed);
        assert!(result.outputs.is_empty()); // No matching hooks ran
    }

    #[tokio::test]
    async fn test_run_multiple_hooks() {
        let mut config = HooksConfig::default();
        config.pre_tool_use.push(crate::config::HookEntry {
            matcher: None, // Matches all
            hooks: vec![
                crate::config::Hook::Prompt {
                    prompt: "First instruction".to_string(),
                    timeout: 30,
                },
                crate::config::Hook::Prompt {
                    prompt: "Second instruction".to_string(),
                    timeout: 30,
                },
            ],
        });

        let engine = HookEngine::new(config);
        let input = HookInput::new(HookEvent::PreToolUse).with_tool("bash", serde_json::json!({}));

        let result = engine.run(HookEvent::PreToolUse, &input).await;

        assert!(result.allowed);
        assert_eq!(result.outputs.len(), 2);
    }

    /// `PostToolUseFailure` with no dedicated handlers falls back to the
    /// `PostToolUse` entries. Matches Claude Code's single-handler-sees-both
    /// behavior (see `claude_compat.rs` `PostToolUse` mapping).
    #[tokio::test]
    async fn post_tool_use_failure_falls_back_to_post_tool_use() {
        let config = HooksConfig {
            post_tool_use: vec![HookEntry {
                matcher: None,
                hooks: vec![Hook::Command {
                    command: "true".to_string(),
                    shell: false,
                    timeout: 5,
                }],
            }],
            ..Default::default()
        };
        let engine = HookEngine::new(config);
        let input = HookInput::new(HookEvent::PostToolUseFailure)
            .with_tool("bash", serde_json::json!({}))
            .with_extra("tool_output", serde_json::json!("boom"));

        let result = engine.run(HookEvent::PostToolUseFailure, &input).await;
        assert!(result.allowed);
        assert_eq!(
            result.outputs.len(),
            1,
            "PostToolUseFailure must dispatch to post_tool_use when no dedicated config"
        );
    }

    /// When a `post_tool_use_failure` entry exists, it takes precedence
    /// over `post_tool_use` — no double-fire.
    #[tokio::test]
    async fn post_tool_use_failure_prefers_dedicated_entries() {
        let config = HooksConfig {
            post_tool_use: vec![HookEntry {
                matcher: None,
                hooks: vec![Hook::Command {
                    command: "false".to_string(), // would fail
                    shell: false,
                    timeout: 5,
                }],
            }],
            post_tool_use_failure: vec![HookEntry {
                matcher: None,
                hooks: vec![Hook::Command {
                    command: "true".to_string(),
                    shell: false,
                    timeout: 5,
                }],
            }],
            ..Default::default()
        };
        let engine = HookEngine::new(config);
        let input =
            HookInput::new(HookEvent::PostToolUseFailure).with_tool("bash", serde_json::json!({}));

        let result = engine.run(HookEvent::PostToolUseFailure, &input).await;
        assert_eq!(
            result.outputs.len(),
            1,
            "dedicated handlers run exactly once"
        );
        // Dedicated handler ran `true` — the failing `post_tool_use` entry
        // must not have fired.
        assert!(result.errors.is_empty());
    }

    // ========================================================================
    // HookPolicy / allowlist / secure-spawn tests  (crosslink #254 / #684)
    // ========================================================================

    /// Helper: build a minimal `HooksConfig` with a single `post_tool_use`
    /// `Command` hook wired to the given command string + shell flag.
    fn make_command_config(command: &str, shell: bool, policy: Option<HookPolicy>) -> HooksConfig {
        HooksConfig {
            policy,
            post_tool_use: vec![HookEntry {
                matcher: None,
                hooks: vec![Hook::Command {
                    command: command.to_string(),
                    shell,
                    timeout: 5,
                }],
            }],
            ..Default::default()
        }
    }

    /// Allowlist with a single entry permits a matching binary.
    #[tokio::test]
    async fn allowlist_permits_listed_binary() {
        use std::collections::HashSet;
        let policy = HookPolicy {
            allowed_commands: Some(HashSet::from(["true".to_string()])),
            sandbox: SandboxMode::FullSandbox,
        };
        let engine = HookEngine::new(make_command_config("true", false, Some(policy)));
        let input = HookInput::new(HookEvent::PostToolUse).with_tool("bash", serde_json::json!({}));
        let result = engine.run(HookEvent::PostToolUse, &input).await;
        // `true` succeeds with exit code 0 → hook allowed.
        assert!(result.allowed, "allowlisted binary must be permitted");
        assert!(result.errors.is_empty(), "no errors for allowlisted binary");
    }

    /// Allowlist with no matching entry denies the command and surfaces a
    /// `HookError::Denied` (not a generic `CommandFailed`).
    #[tokio::test]
    async fn allowlist_denies_unlisted_binary() {
        use std::collections::HashSet;
        let policy = HookPolicy {
            allowed_commands: Some(HashSet::from(["python3".to_string()])),
            sandbox: SandboxMode::FullSandbox,
        };
        // Attempt to run `true` which is NOT in the allowlist.
        let engine = HookEngine::new(make_command_config("true", false, Some(policy)));
        let input = HookInput::new(HookEvent::PostToolUse).with_tool("bash", serde_json::json!({}));
        let result = engine.run(HookEvent::PostToolUse, &input).await;
        assert_eq!(
            result.errors.len(),
            1,
            "exactly one error for denied binary"
        );
        assert!(
            matches!(result.errors[0], HookError::Denied { .. }),
            "error must be HookError::Denied, got: {:?}",
            result.errors[0]
        );
    }

    /// Direct spawn: a command containing `; rm -rf /tmp/x` is tokenised so
    /// the semicolon and everything after it become a single extra argument,
    /// NOT a second shell command.  The binary is just `echo`, and the rest
    /// are passed as literal strings — no shell metacharacter interpretation.
    #[tokio::test]
    async fn direct_spawn_injection_is_tokenised_not_interpolated() {
        use std::collections::HashSet;
        // Allow only `echo` — if the semicolon were interpreted by a shell the
        // binary would be `rm`, which is NOT in the allowlist, so the hook
        // would return Denied.  Under direct spawn the whole string after
        // splitting is ["echo", "; rm -rf /tmp/x"] → binary = "echo" → allowed.
        // The string "; rm -rf /tmp/x" is passed as a *literal argument* to echo.
        let policy = HookPolicy {
            allowed_commands: Some(HashSet::from(["echo".to_string()])),
            sandbox: SandboxMode::FullSandbox,
        };
        let engine = HookEngine::new(make_command_config(
            "echo '; rm -rf /tmp/x'",
            false,
            Some(policy),
        ));
        let input = HookInput::new(HookEvent::PostToolUse).with_tool("bash", serde_json::json!({}));
        let result = engine.run(HookEvent::PostToolUse, &input).await;
        // Should succeed: echo exits 0, allowlist check passes.
        assert!(
            result.errors.is_empty(),
            "injected semicolon must not split into a second command; errors: {:?}",
            result.errors
        );
        assert!(result.allowed);
    }

    /// Shell mode (`shell: true`) succeeds but a warning is logged.
    /// We verify it doesn't panic or return a spurious error for a simple pipe.
    #[tokio::test]
    async fn shell_mode_executes_pipeline() {
        // No allowlist needed — shell mode skips the allowlist gate.
        let engine = HookEngine::new(make_command_config(
            "echo hello | cat",
            true, // explicit shell: true
            None, // no policy
        ));
        let input = HookInput::new(HookEvent::PostToolUse).with_tool("bash", serde_json::json!({}));
        let result = engine.run(HookEvent::PostToolUse, &input).await;
        assert!(result.errors.is_empty(), "shell pipeline must succeed");
        assert!(result.allowed);
    }

    #[test]
    fn shell_mode_resolves_platform_shell_binary() {
        let (shell_path, shell_arg) = HookEngine::resolved_hook_shell().expect("platform shell");
        assert!(
            shell_path.is_absolute(),
            "hook shell must resolve to an absolute path, got {}",
            shell_path.display()
        );
        assert_eq!(shell_arg, if cfg!(windows) { "/C" } else { "-c" });

        let source = include_str!("mod.rs");
        let cfg_test = source
            .find("#[cfg(test)]")
            .expect("test marker must be present");
        let production = &source[..cfg_test];
        assert!(
            !production.contains("Command::new(shell)"),
            "hook shell mode must not spawn an unresolved shell binary"
        );
        assert!(
            production.contains("which::which(shell)"),
            "hook shell mode must resolve the platform shell through which"
        );
    }

    /// Env scrub: sensitive vars must not be present in the child's environment.
    /// We run `printenv ANTHROPIC_API_KEY` and expect an empty/missing output.
    #[tokio::test]
    async fn env_scrub_removes_sensitive_vars() {
        // Set a fake key in the current process env so there's something to scrub.
        // Safety: single-threaded test context; no other thread reads this var.
        unsafe { std::env::set_var("ANTHROPIC_API_KEY", "sk-fake-key-for-test") };

        let policy = HookPolicy {
            allowed_commands: Some(std::collections::HashSet::from([
                "printenv".to_string(),
                "sh".to_string(),
            ])),
            sandbox: SandboxMode::FullSandbox,
        };
        let engine = HookEngine::new(make_command_config(
            "printenv ANTHROPIC_API_KEY",
            false,
            Some(policy),
        ));
        let input = HookInput::new(HookEvent::PostToolUse).with_tool("bash", serde_json::json!({}));
        let result = engine.run(HookEvent::PostToolUse, &input).await;

        // printenv exits 1 when the variable is unset — that's expected.
        // Crucially, there should be no output containing the fake key.
        // We inspect hook outputs (stdout) for the key string.
        for out in &result.outputs {
            if let Some(ctx) = &out.additional_context {
                assert!(
                    !ctx.contains("sk-fake-key-for-test"),
                    "sensitive var must not appear in hook stdout"
                );
            }
        }

        // Restore env to not leak into other tests.
        unsafe { std::env::remove_var("ANTHROPIC_API_KEY") };
    }

    /// Backwards-compatible mode (no policy): hook runs without error even
    /// though no allowlist is configured.
    #[tokio::test]
    async fn no_policy_allow_all_backwards_compat() {
        // No policy → allow-all mode.
        let engine = HookEngine::new(make_command_config("true", false, None));
        let input = HookInput::new(HookEvent::PostToolUse).with_tool("bash", serde_json::json!({}));
        let result = engine.run(HookEvent::PostToolUse, &input).await;
        assert!(
            result.errors.is_empty(),
            "no-policy mode must allow any binary"
        );
        assert!(result.allowed);
    }

    // ========================================================================
    // Crosslink #758 — matcher fail-closed for deny intent / fail-open for
    // observe intent, plus structured tracing.
    // Crosslink #778 — fire_post_tool surfaces hook errors via tracing::error!
    // ========================================================================

    use std::sync::{Arc, LazyLock, Mutex};
    use tracing::subscriber;
    use tracing_subscriber::fmt::MakeWriter;

    static TRACE_CAPTURE_LOCK: LazyLock<tokio::sync::Mutex<()>> =
        LazyLock::new(|| tokio::sync::Mutex::new(()));

    /// Shared buffer that satisfies `MakeWriter` so tests can capture the
    /// `tracing` output emitted by the hook engine.
    #[derive(Clone, Default)]
    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl CapturedWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for CapturedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CapturedWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// `HookEvent::is_deny_intent` covers exactly `PreToolUse` and
    /// `PermissionRequest`. Every other event is observe-intent.
    #[test]
    fn is_deny_intent_covers_pre_tool_use_and_permission_request_only() {
        // Deny-intent events
        assert!(HookEvent::PreToolUse.is_deny_intent());
        assert!(HookEvent::PermissionRequest.is_deny_intent());

        // Observe-intent events — must all fail-open on matcher errors
        for ev in [
            HookEvent::SessionStart,
            HookEvent::SessionEnd,
            HookEvent::PostToolUse,
            HookEvent::PostToolUseFailure,
            HookEvent::UserPromptSubmit,
            HookEvent::Stop,
            HookEvent::SubagentStart,
            HookEvent::SubagentStop,
            HookEvent::PreCompact,
            HookEvent::Notification,
            HookEvent::PreAdversaryReview,
            HookEvent::PostAdversaryReview,
            HookEvent::VddConflict,
            HookEvent::VddConverged,
        ] {
            assert!(
                !ev.is_deny_intent(),
                "{ev:?} must NOT be deny-intent (would change fail-mode)"
            );
        }
    }

    #[tokio::test]
    async fn pre_tool_use_command_error_fails_closed() {
        let config = HooksConfig {
            pre_tool_use: vec![HookEntry {
                matcher: None,
                hooks: vec![Hook::Command {
                    command: "__openclaudia_missing_pre_hook_binary__".to_string(),
                    shell: false,
                    timeout: 1,
                }],
            }],
            ..Default::default()
        };
        let engine = HookEngine::new(config);
        let input = HookInput::new(HookEvent::PreToolUse)
            .with_tool("bash", serde_json::json!({"command": "cargo test"}));

        let result = engine.run(HookEvent::PreToolUse, &input).await;

        assert!(
            !result.allowed,
            "PreToolUse hook execution errors must fail closed; got {result:?}"
        );
        assert!(
            !result.errors.is_empty(),
            "spawn failure should be preserved for diagnostics"
        );
        assert!(
            HookEngine::check_blocked(&result).is_err(),
            "deny-intent hook errors must be visible to gate callers"
        );
    }

    #[tokio::test]
    async fn post_tool_use_command_error_stays_allowed_but_records_error() {
        let config = HooksConfig {
            post_tool_use: vec![HookEntry {
                matcher: None,
                hooks: vec![Hook::Command {
                    command: "__openclaudia_missing_post_hook_binary__".to_string(),
                    shell: false,
                    timeout: 1,
                }],
            }],
            ..Default::default()
        };
        let engine = HookEngine::new(config);
        let input = HookInput::new(HookEvent::PostToolUse).with_tool("bash", serde_json::json!({}));

        let result = engine.run(HookEvent::PostToolUse, &input).await;

        assert!(
            result.allowed,
            "observe-intent hook execution errors must still fail open"
        );
        assert!(
            !result.errors.is_empty(),
            "observe-intent errors should still be recorded"
        );
    }

    /// Crosslink #758: a `PreToolUse` (deny-intent) hook whose matcher regex
    /// cannot compile must FAIL CLOSED — the entry still matches so the hook
    /// runs and can block. A malformed matcher must never silently disable a
    /// security gate.
    #[tokio::test]
    async fn pre_tool_use_with_malformed_matcher_fails_closed_and_blocks() {
        let _trace_guard = TRACE_CAPTURE_LOCK.lock().await;
        let entry = HookEntry {
            // `(unclosed` is not a valid regex → validate_and_match returns Err
            matcher: Some("(unclosed".to_string()),
            hooks: vec![Hook::Prompt {
                prompt: "deny".to_string(),
                timeout: 5,
            }],
        };
        // Deny-intent event must treat the bad matcher as a match.
        assert!(
            HookEngine::matches_entry(&entry, "Write", HookEvent::PreToolUse),
            "PreToolUse with malformed matcher MUST fail-closed (return true)"
        );
        assert!(
            HookEngine::matches_entry(&entry, "Write", HookEvent::PermissionRequest),
            "PermissionRequest with malformed matcher MUST fail-closed"
        );
    }

    /// Crosslink #758: observe-intent events (e.g. `PostToolUse`) with a
    /// malformed matcher must FAIL OPEN — the hook is skipped, not fired on
    /// an unrelated tool.
    #[tokio::test]
    async fn post_tool_use_with_malformed_matcher_fails_open_and_skips() {
        let _trace_guard = TRACE_CAPTURE_LOCK.lock().await;
        let entry = HookEntry {
            matcher: Some("(unclosed".to_string()),
            hooks: vec![Hook::Prompt {
                prompt: "observe".to_string(),
                timeout: 5,
            }],
        };
        // Observe-intent → fail-open
        assert!(
            !HookEngine::matches_entry(&entry, "Write", HookEvent::PostToolUse),
            "PostToolUse with malformed matcher MUST fail-open (return false)"
        );
        assert!(
            !HookEngine::matches_entry(&entry, "Write", HookEvent::Notification),
            "Notification with malformed matcher MUST fail-open"
        );
        assert!(
            !HookEngine::matches_entry(&entry, "Write", HookEvent::UserPromptSubmit),
            "UserPromptSubmit with malformed matcher MUST fail-open"
        );
    }

    /// Crosslink #758: on a `PreToolUse` matcher failure the warning carries
    /// the structured fields `event`, `pattern`, `error`, and
    /// `fail_closed=true` so operator dashboards can flag silently broken
    /// deny matchers.
    #[tokio::test]
    async fn pre_tool_use_matcher_failure_emits_warn_with_fail_closed_field() {
        let _trace_guard = TRACE_CAPTURE_LOCK.lock().await;
        let captured = CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();

        subscriber::with_default(subscriber, || {
            let entry = HookEntry {
                matcher: Some("(broken".to_string()),
                hooks: vec![],
            };
            let matched = HookEngine::matches_entry(&entry, "bash", HookEvent::PreToolUse);
            assert!(matched, "deny-intent must fail-closed (return true)");
        });

        let log = captured.contents();
        assert!(log.contains("WARN"), "expected WARN level, got: {log}");
        assert!(
            log.contains("fail_closed=true"),
            "warn must include fail_closed=true; got: {log}"
        );
        assert!(
            log.contains("PreToolUse"),
            "warn must include event=PreToolUse; got: {log}"
        );
        assert!(
            log.contains("(broken"),
            "warn must include the offending pattern; got: {log}"
        );
        assert!(
            log.contains("Hook matcher regex failed"),
            "warn must use the standard message; got: {log}"
        );
    }

    /// Crosslink #758: observe-intent matcher failure emits the same warning
    /// shape but with `fail_closed=false`, so operators can distinguish the
    /// two paths in their log pipelines.
    #[tokio::test]
    async fn post_tool_use_matcher_failure_emits_warn_with_fail_closed_false() {
        let _trace_guard = TRACE_CAPTURE_LOCK.lock().await;
        let captured = CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();

        subscriber::with_default(subscriber, || {
            let entry = HookEntry {
                matcher: Some("(broken".to_string()),
                hooks: vec![],
            };
            let matched = HookEngine::matches_entry(&entry, "bash", HookEvent::PostToolUse);
            assert!(!matched, "observe-intent must fail-open (return false)");
        });

        let log = captured.contents();
        assert!(log.contains("WARN"), "expected WARN level, got: {log}");
        assert!(
            log.contains("fail_closed=false"),
            "warn must include fail_closed=false; got: {log}"
        );
        assert!(
            log.contains("PostToolUse"),
            "warn must include event=PostToolUse; got: {log}"
        );
    }

    /// Crosslink #778 (OWASP A09): when `fire_post_tool` runs hooks that
    /// fail, the errors are not propagated to the caller — but they MUST
    /// land on the audit trail via `tracing::error!` with structured fields
    /// (`event`, `tool`, `session_id`, `hook_error_index`, `error`).
    ///
    /// We force a `HookError::Denied` by configuring an empty allowlist and
    /// running a `post_tool_use` command hook whose binary is not listed.
    #[tokio::test]
    async fn fire_post_tool_surfaces_hook_errors_via_tracing_error() {
        use std::collections::HashSet;

        let _trace_guard = TRACE_CAPTURE_LOCK.lock().await;
        let captured = CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .finish();

        // Empty allowlist (Some(empty)) denies every binary, forcing
        // HookError::Denied on every command-hook invocation.
        let policy = HookPolicy {
            allowed_commands: Some(HashSet::new()),
            sandbox: SandboxMode::FullSandbox,
        };
        let config = HooksConfig {
            policy: Some(policy),
            post_tool_use: vec![HookEntry {
                matcher: None,
                hooks: vec![Hook::Command {
                    command: "true".to_string(),
                    shell: false,
                    timeout: 5,
                }],
            }],
            ..Default::default()
        };
        let engine = HookEngine::new(config);

        // `set_default` returns a guard that installs the subscriber on the
        // current thread until dropped — works inside a tokio runtime where
        // `with_default(... block_on(...))` would double-block.
        let guard = subscriber::set_default(subscriber);
        engine
            .fire_post_tool(
                true,
                "bash",
                serde_json::json!({"command": "ls"}),
                "ok",
                Some("sess-778"),
            )
            .await;
        drop(guard);

        let log = captured.contents();
        assert!(
            log.contains("ERROR"),
            "expected ERROR-level tracing output, got: {log}"
        );
        assert!(
            log.contains("fire_post_tool: hook execution failed"),
            "missing fire_post_tool error message in: {log}"
        );
        assert!(
            log.contains("tool=\"bash\"") || log.contains("tool=bash"),
            "error must mention tool=bash; got: {log}"
        );
        assert!(
            log.contains("sess-778"),
            "error must mention session_id sess-778; got: {log}"
        );
        assert!(
            log.contains("hook_error_index=0"),
            "error must include hook_error_index=0; got: {log}"
        );
        assert!(
            log.contains("denied by allowlist") || log.contains("Denied"),
            "error must include the underlying HookError; got: {log}"
        );
    }

    /// Crosslink #778 counter-test: a successful `fire_post_tool` call must
    /// be SILENT — no spurious ERROR-level output when no hook fails.
    /// Confirms the error-surfacing is gated on `result.errors`, not always-on.
    #[tokio::test]
    async fn fire_post_tool_silent_when_hooks_succeed() {
        let _trace_guard = TRACE_CAPTURE_LOCK.lock().await;
        let captured = CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .finish();

        // A succeeding command hook with no policy gate.
        let config = HooksConfig {
            post_tool_use: vec![HookEntry {
                matcher: None,
                hooks: vec![Hook::Command {
                    command: "true".to_string(),
                    shell: false,
                    timeout: 5,
                }],
            }],
            ..Default::default()
        };
        let engine = HookEngine::new(config);

        let guard = subscriber::set_default(subscriber);
        engine
            .fire_post_tool(
                true,
                "bash",
                serde_json::json!({"command": "true"}),
                "ok",
                Some("sess-happy"),
            )
            .await;
        drop(guard);

        let log = captured.contents();
        assert!(
            !log.contains("ERROR"),
            "fire_post_tool happy path must not emit ERROR; got: {log}"
        );
        assert!(
            !log.contains("fire_post_tool: hook execution failed"),
            "no fire_post_tool failure message expected; got: {log}"
        );
    }

    #[tokio::test]
    async fn fire_post_tool_dispatches_on_success_and_failure() {
        // A single post_tool_use entry sees both paths when no
        // failure-specific handler exists.
        let config = HooksConfig {
            post_tool_use: vec![HookEntry {
                matcher: None,
                hooks: vec![Hook::Command {
                    command: "true".to_string(),
                    shell: false,
                    timeout: 5,
                }],
            }],
            ..Default::default()
        };
        let engine = HookEngine::new(config);

        engine
            .fire_post_tool(true, "bash", serde_json::json!({}), "ok", Some("s1"))
            .await;
        engine
            .fire_post_tool(false, "bash", serde_json::json!({}), "fail", Some("s1"))
            .await;
        // Success assertion: neither call panicked or returned an error
        // that bubbled up — the fire_post_tool helper swallows hook
        // failures by design (tool execution must never fail because of
        // a misbehaving hook).
    }

    // ── crosslink #350: typed matcher targets ────────────────────────────────

    #[test]
    fn default_matcher_target_per_event() {
        // Tool-lifecycle events → ToolName.
        for ev in [
            HookEvent::PreToolUse,
            HookEvent::PostToolUse,
            HookEvent::PostToolUseFailure,
            HookEvent::PermissionRequest,
        ] {
            assert_eq!(
                ev.default_matcher_target(),
                HookMatcherTarget::ToolName,
                "{ev:?} must default to ToolName"
            );
        }
        // UserPromptSubmit → Prompt.
        assert_eq!(
            HookEvent::UserPromptSubmit.default_matcher_target(),
            HookMatcherTarget::Prompt
        );
        // Everything else → EventKey.
        for ev in [
            HookEvent::SessionStart,
            HookEvent::SessionEnd,
            HookEvent::Stop,
            HookEvent::SubagentStart,
            HookEvent::SubagentStop,
            HookEvent::PreCompact,
            HookEvent::Notification,
            HookEvent::PreAdversaryReview,
            HookEvent::PostAdversaryReview,
            HookEvent::VddConflict,
            HookEvent::VddConverged,
        ] {
            assert_eq!(
                ev.default_matcher_target(),
                HookMatcherTarget::EventKey,
                "{ev:?} must default to EventKey"
            );
        }
    }

    #[test]
    fn typed_accessors_return_correct_slot() {
        // match_tool / match_prompt / match_event each look at exactly one
        // slot of HookInput and do not cross-pollinate.
        let with_tool = HookInput::new(HookEvent::PreToolUse)
            .with_tool("rm", serde_json::json!({"path": "/etc"}));
        assert_eq!(with_tool.match_tool(), Some("rm"));
        assert_eq!(with_tool.match_prompt(), None);
        assert_eq!(with_tool.match_event(), Some("pre_tool_use"));

        let with_prompt =
            HookInput::new(HookEvent::UserPromptSubmit).with_prompt("I want to rm a file");
        assert_eq!(with_prompt.match_tool(), None);
        assert_eq!(with_prompt.match_prompt(), Some("I want to rm a file"));
        assert_eq!(with_prompt.match_event(), Some("user_prompt_submit"));

        let bare = HookInput::new(HookEvent::SessionStart);
        assert_eq!(bare.match_tool(), None);
        assert_eq!(bare.match_prompt(), None);
        assert_eq!(bare.match_event(), Some("session_start"));
    }

    #[tokio::test]
    async fn pre_tool_use_matcher_does_not_cross_fire_on_prompt() {
        // Regression for #350: a PreToolUse hook with matcher="rm" must
        // NOT match a user prompt that contains "rm", even when the input
        // happens to have a `prompt` field populated. Under the old
        // "first populated field wins" heuristic this would have fired.
        let config = HooksConfig {
            pre_tool_use: vec![HookEntry {
                matcher: Some("rm".to_string()),
                hooks: vec![Hook::Command {
                    // Exit 2 ⇒ block. If this hook fires, allowed = false.
                    command: "false; exit 2".to_string(),
                    shell: true,
                    timeout: 5,
                }],
            }],
            ..Default::default()
        };
        let engine = HookEngine::new(config);

        // A PreToolUse event for a *different* tool, with a prompt that
        // happens to contain the regex pattern.
        let input = HookInput::new(HookEvent::PreToolUse)
            .with_tool("Write", serde_json::json!({"path": "/tmp/x"}))
            .with_prompt("I want to rm a file");

        let result = engine.run(HookEvent::PreToolUse, &input).await;
        assert!(
            result.allowed,
            "PreToolUse matcher 'rm' targets tool_name='Write', must NOT match prompt"
        );
    }

    #[tokio::test]
    async fn user_prompt_submit_matcher_targets_prompt_only() {
        // Mirror of the above: a UserPromptSubmit hook with matcher="rm"
        // SHOULD fire when the prompt contains "rm" — and conversely should
        // NOT fire just because a leftover tool_name happens to contain it.
        let config = HooksConfig {
            user_prompt_submit: vec![HookEntry {
                matcher: Some("rm".to_string()),
                hooks: vec![Hook::Command {
                    command: "exit 2".to_string(),
                    shell: true,
                    timeout: 5,
                }],
            }],
            ..Default::default()
        };
        let engine = HookEngine::new(config);

        // Case A: prompt contains "rm" ⇒ blocks.
        let hit = HookInput::new(HookEvent::UserPromptSubmit).with_prompt("please rm -rf /tmp/foo");
        let result_a = engine.run(HookEvent::UserPromptSubmit, &hit).await;
        assert!(!result_a.allowed, "matcher must hit the prompt slot");

        // Case B: prompt is benign, but tool_name happens to be "rm"
        // (would have falsely matched under the old heuristic).
        let miss = HookInput::new(HookEvent::UserPromptSubmit)
            .with_tool("rm", serde_json::json!({}))
            .with_prompt("hello world");
        let result_b = engine.run(HookEvent::UserPromptSubmit, &miss).await;
        assert!(
            result_b.allowed,
            "UserPromptSubmit matcher must ignore tool_name slot"
        );
    }

    #[tokio::test]
    async fn session_start_matcher_targets_event_key() {
        // Events with no tool/prompt payload route to event_key.
        // A SessionStart hook matching "session_start" should fire;
        // one matching "pre_tool_use" should not.
        let config = HooksConfig {
            session_start: vec![
                HookEntry {
                    matcher: Some("session_start".to_string()),
                    hooks: vec![Hook::Command {
                        command: "exit 2".to_string(),
                        shell: true,
                        timeout: 5,
                    }],
                },
                HookEntry {
                    matcher: Some("pre_tool_use".to_string()),
                    hooks: vec![Hook::Command {
                        command: "exit 2".to_string(),
                        shell: true,
                        timeout: 5,
                    }],
                },
            ],
            ..Default::default()
        };
        let engine = HookEngine::new(config);
        let input = HookInput::new(HookEvent::SessionStart);

        // Hooks run in parallel and one of them blocks ⇒ allowed = false.
        // We can't distinguish *which* matched from HookResult alone, but we
        // can confirm only one fired: the outputs vector length equals the
        // number of hooks that ran past the matcher filter.
        let result = engine.run(HookEvent::SessionStart, &input).await;
        assert!(!result.allowed, "matching session_start hook must block");
        assert_eq!(
            result.outputs.len(),
            1,
            "only the session_start-matching entry should run; \
             pre_tool_use literal must not cross-fire on EventKey target"
        );
    }
}

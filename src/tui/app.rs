//! Full-screen interactive TUI application.
//!
//! Launched via `openclaudia` when no subcommand, `--print`, or `--tui-mode`
//! is supplied.
//! Provides a scrollable message view, text input area, status bar,
//! and streaming response display wired to the real API pipeline.

use super::events::{
    ApiRetryKind, AppEvent, CallEventBridge, EventHandler, PlanModeReply, PlanModeRequest,
    ProviderSwitch, SpawnTarget,
};
use super::input::TextInput;
use super::messages::{DisplayMessage, EffortLevel, MessageKind, MessageList, Mode};
use super::supervision::{TuiSupervisor, TuiTaskCompletion, TuiTaskKind, TuiTaskOutcome};
use super::{DIM, GOLD, PURPLE, SPINNER_FRAMES};
use crossterm::{
    event::{DisableBracketedPaste, EnableBracketedPaste, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use futures::FutureExt as _;

use crate::file_error::{self, FileError};
use crate::state::{AgentMode, Session};

const INPUT_PROMPT_WIDTH: u16 = 2;
const MIN_INPUT_HEIGHT: u16 = 3;
const MAX_INPUT_HEIGHT: u16 = 8;

fn inserts_newline(modifiers: KeyModifiers) -> bool {
    modifiers.intersects(KeyModifiers::SHIFT | KeyModifiers::ALT | KeyModifiers::CONTROL)
}

fn input_content_width(area_width: u16) -> u16 {
    area_width.saturating_sub(INPUT_PROMPT_WIDTH).max(1)
}

fn format_review_command_output(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        let mut parts = Vec::new();
        let stdout = stdout.trim();
        let stderr = stderr.trim();
        if !stdout.is_empty() {
            parts.push(stdout);
        }
        if !stderr.is_empty() {
            parts.push(stderr);
        }
        let details = parts.join("\n");
        return if details.is_empty() {
            format!("Failed to run git diff: {}", out.status)
        } else {
            format!("Failed to run git diff:\n{details}")
        };
    }

    if stdout.trim().is_empty() {
        return "No changes to review.".to_string();
    }

    let lines = stdout.lines().collect::<Vec<_>>();
    if lines.len() > 100 {
        format!(
            "{}\n... (truncated, {} total lines)",
            lines[..100].join("\n"),
            lines.len()
        )
    } else {
        lines.join("\n")
    }
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

const fn cancellation_reason_label(reason: &crate::runtime::CancellationReason) -> &'static str {
    match reason {
        crate::runtime::CancellationReason::User => "user request",
        crate::runtime::CancellationReason::Deadline => "deadline",
        crate::runtime::CancellationReason::BudgetExhausted => "budget exhausted",
        crate::runtime::CancellationReason::FrontendDisconnected => "frontend shutdown",
        crate::runtime::CancellationReason::ParentTerminated => "parent terminated",
        crate::runtime::CancellationReason::RuntimeFailure { .. } => "runtime failure",
    }
}

/// Signal the TUI event loop to exit at the next tick.
///
/// The request is scoped to the active launch generation. It is not sticky:
/// a later in-process launch receives a fresh supervisor and remains live.
pub fn request_tui_shutdown() {
    super::supervision::request_active_tui_shutdown();
}

/// Owns every terminal mode mutation made by the full-screen renderer.
struct TerminalSession {
    raw_mode: bool,
    alternate_screen: bool,
    bracketed_paste: bool,
}

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        let mut session = Self {
            raw_mode: false,
            alternate_screen: false,
            bracketed_paste: false,
        };
        enable_raw_mode()?;
        session.raw_mode = true;
        execute!(io::stdout(), EnterAlternateScreen)?;
        session.alternate_screen = true;
        execute!(io::stdout(), EnableBracketedPaste)?;
        session.bracketed_paste = true;
        Ok(session)
    }

    fn restore(&mut self) -> io::Result<()> {
        let mut first_error = None;
        if self.bracketed_paste {
            match execute!(io::stdout(), DisableBracketedPaste) {
                Ok(()) => self.bracketed_paste = false,
                Err(error) => first_error = Some(error),
            }
        }
        if self.alternate_screen {
            match execute!(io::stdout(), LeaveAlternateScreen) {
                Ok(()) => self.alternate_screen = false,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if self.raw_mode {
            match disable_raw_mode() {
                Ok(()) => self.raw_mode = false,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            tracing::error!(%error, "failed to restore TUI terminal state");
        }
    }
}

const fn tui_mode_for_agent(mode: crate::state::AgentMode) -> Mode {
    match mode {
        crate::state::AgentMode::Plan => Mode::Plan,
        crate::state::AgentMode::Build
        | crate::state::AgentMode::Extend
        | crate::state::AgentMode::Refactor => Mode::Build,
    }
}

/// Compiled regex for `@"quoted path"` and `@bare-path` file references.
static FILE_REF_RE: std::sync::LazyLock<Option<regex::Regex>> =
    std::sync::LazyLock::new(|| compile_file_ref_regex(FILE_REF_PATTERN));

const FILE_REF_PATTERN: &str = r#"@"([^"]+)"|@(\S+)"#;

fn compile_file_ref_regex(pattern: &str) -> Option<regex::Regex> {
    match regex::Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(error) => {
            tracing::warn!(
                pattern,
                error = %error,
                "Invalid TUI file-reference regex; @file expansion disabled",
            );
            None
        }
    }
}

/// Expand @filename references in user input by inlining file contents.
fn expand_file_refs(run: &crate::tools::ToolRunContext, input: &str) -> String {
    if !input.contains('@') {
        return input.to_string();
    }
    let Some(file_ref_re) = (*FILE_REF_RE).as_ref() else {
        return input.to_string();
    };
    let mut result = input.to_string();
    let mut replacements = Vec::new();

    for cap in file_ref_re.captures_iter(input) {
        let full_match = match cap.get(0) {
            Some(m) => m.as_str(),
            None => continue,
        };
        let raw_path = match cap.get(1).or_else(|| cap.get(2)) {
            Some(m) => m.as_str(),
            None => continue,
        };

        // Use the same immutable capability roots and descriptor-relative
        // secure open as read_file. No process CWD or pathname-only check can
        // grant this context-assembly helper additional authority.
        let (canonical, mut file) = match crate::tools::open_capability_regular_read(run, raw_path)
        {
            Ok(opened) => opened,
            Err(error) => {
                let label = if error.contains("traversal") {
                    "Path traversal blocked"
                } else if error.contains("outside") || error.contains("masked") {
                    "File outside granted roots"
                } else {
                    "Cannot read file"
                };
                replacements.push((full_match.to_string(), format!("[{label}: {raw_path}]")));
                continue;
            }
        };
        let mut content = String::new();
        match std::io::Read::read_to_string(&mut file, &mut content) {
            Ok(_) => {
                replacements.push((
                    full_match.to_string(),
                    format!(
                        "\n<file path=\"{}\">\n{}\n</file>\n",
                        canonical.display(),
                        content.trim()
                    ),
                ));
            }
            Err(e) => {
                replacements.push((
                    full_match.to_string(),
                    format!("[Cannot read {raw_path}: {e}]"),
                ));
            }
        }
    }
    for (from, to) in replacements {
        result = result.replace(&from, &to);
    }
    result
}

fn sessions_dir() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_SESSIONS_DIR.with(|slot| slot.borrow().clone()) {
        return path;
    }

    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("openclaudia")
        .join("chat_sessions")
}

#[cfg(test)]
thread_local! {
    static TEST_SESSIONS_DIR: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Format a [`SystemTime`] as an ISO-8601 date string
/// (`YYYY-MM-DD`). Used only for the log-selector "last activity"
/// column where the exact minute doesn't matter — the picker shows
/// entries newest-first so users orient by relative position, not a
/// wall-clock string. Returns `"?"` on the far-past clock drift case
/// where the timestamp predates the Unix epoch.
fn iso_of_systemtime(t: std::time::SystemTime) -> String {
    match chrono::DateTime::<chrono::Utc>::from(t)
        .format("%Y-%m-%d")
        .to_string()
    {
        s if s.is_empty() => "?".to_string(),
        s => s,
    }
}

fn save_session(session: &Session) -> Result<(), FileError> {
    let dir = sessions_dir();
    crate::state::validate_session_id(&session.id()).map_err(|reason| FileError::Invalid {
        path: dir.clone(),
        reason: reason.to_string(),
    })?;
    file_error::create_dir_all(&dir)?;
    let _ = session.refresh_estimated_tokens();
    let path = dir.join(format!("{}.json", session.id()));
    match file_error::write_json_pretty_atomic(&path, session) {
        Ok(()) => Ok(()),
        Err(err) => {
            // crosslink #889: a single un-serializable message previously
            // failed the *whole* save, losing every message in the buffer.
            // Try a degraded save where messages that fail to serialize
            // are replaced with a placeholder — operator sees the loss
            // explicitly in the saved transcript instead of losing
            // everything silently.
            tracing::warn!(
                error = %err,
                "save_session: full save failed; attempting per-message recovery"
            );
            save_session_with_recovery(session, &path)
        }
    }
}

/// Best-effort recovery save: drop messages that fail individual
/// serialization, replace each with a `{"role":"system","content":"[message
/// lost: ...]"}` marker so the conversation history is reconstructable.
///
/// The path is reused (no second `create_dir_all` needed — the original
/// `save_session` already created the directory).
fn save_session_with_recovery(session: &Session, path: &std::path::Path) -> Result<(), FileError> {
    let salvaged = session.detached_clone();
    let mut messages = salvaged.messages_snapshot();
    let mut lost = 0usize;
    for msg in &mut messages {
        if serde_json::to_string(msg).is_err() {
            *msg = serde_json::json!({
                "role": "system",
                "content": "[message lost during persistence — original was not serializable]",
            });
            lost += 1;
        }
    }
    if lost > 0 {
        tracing::warn!(
            lost,
            session_id = %salvaged.id(),
            "save_session: replaced {lost} unserializable message(s) with placeholders"
        );
    }
    salvaged.replace_messages(messages);
    file_error::write_json_pretty_atomic(path, &salvaged)
}

fn read_tui_session_file(path: &Path) -> Result<Session, FileError> {
    let metadata = std::fs::symlink_metadata(path).map_err(FileError::with_path(path))?;
    if metadata.file_type().is_symlink() {
        return Err(FileError::Invalid {
            path: path.to_path_buf(),
            reason: "saved session must not be a symlink".to_string(),
        });
    }
    let json = file_error::read_file(path)?;
    let session: Session =
        serde_json::from_str(&json).map_err(file_error::FileError::json_with_path(path))?;
    crate::state::validate_session_file(path, &session.id()).map_err(|reason| {
        FileError::Invalid {
            path: path.to_path_buf(),
            reason,
        }
    })?;
    Ok(session)
}

fn list_sessions() -> Vec<Session> {
    let dir = sessions_dir();
    let mut sessions = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                match read_tui_session_file(&path) {
                    Ok(session) => sessions.push(session),
                    Err(err) => tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "Skipped unreadable TUI session"
                    ),
                }
            }
        }
    }
    sessions.sort_by_key(|s| std::cmp::Reverse(s.updated_at));
    sessions
}

/// A pending permission prompt waiting for user input.
struct PendingPermission {
    tool_name: String,
    tool_args: String,
    reply: tokio::sync::oneshot::Sender<super::events::PermissionResponse>,
}

/// A pending `ask_user_question` modal waiting for the user to walk
/// through the question set. Mirrors the REPL flow in
/// `cli::repl::input::handle_user_questions` so the agent-facing
/// answer JSON is byte-identical.
struct PendingUserQuestion {
    /// Full question set as supplied by the tool call. Each entry has
    /// `question`, `header`, `options[]`, and an optional `multiSelect`.
    questions: Vec<serde_json::Value>,
    /// Index of the question currently shown (0-based).
    current_index: usize,
    /// Text the user is typing for the active question. Numeric
    /// (single-select), comma-separated numeric (multi-select), or
    /// free-form (when "Other" is picked).
    input_buffer: String,
    /// Accumulated answers — flushed back to the pipeline as JSON
    /// when the last question is answered.
    answers: serde_json::Map<String, serde_json::Value>,
    /// `true` once the user picked the synthetic "Other" option for
    /// the current question and is now typing their free-form answer.
    other_mode: bool,
    /// Reply channel back to the pipeline. Dropping it (e.g. on
    /// Ctrl+C) surfaces a structured "cancelled" payload to the
    /// model rather than hanging the agent indefinitely.
    reply: tokio::sync::oneshot::Sender<String>,
}

/// Exact plan proposal awaiting an explicit full-screen TUI decision.
struct PendingPlanApproval {
    prepared: crate::session::PreparedPlanApproval,
    allowed_prompts: Vec<crate::tools::ToolAllowedPrompt>,
    scroll_offset: u16,
    reply: tokio::sync::oneshot::Sender<PlanModeReply>,
}

enum ActiveTurnTerminal {
    Succeeded,
    Failed(String),
    PluginAgent {
        label: String,
        result: crate::subagent::SubagentResult,
    },
    Cancelled(crate::runtime::CancellationReason),
}

struct ActiveTurn {
    call_id: crate::runtime::CallId,
    run_context: std::sync::Arc<crate::tools::ToolRunContext>,
    event_bridge: Option<CallEventBridge>,
    terminal: Option<ActiveTurnTerminal>,
    task_outcome: Option<TuiTaskOutcome>,
}

struct CompletedTurnRun {
    call_id: crate::runtime::CallId,
    run_context: std::sync::Arc<crate::tools::ToolRunContext>,
}

const fn tui_supports_key_action(action: &crate::keybindings::KeyAction) -> bool {
    !matches!(
        action,
        crate::keybindings::KeyAction::Editor
            | crate::keybindings::KeyAction::Compact
            | crate::keybindings::KeyAction::None
    )
}

#[derive(Debug)]
struct ProviderSwitchAuth {
    api_key: Option<crate::providers::ApiKey>,
    claude_code_token: Option<crate::secrets::OAuthToken>,
    claude_agent_sdk: Option<crate::claude_agent_sdk::ClaudeAgentSdk>,
    codex_agent_sdk: Option<crate::codex_agent_sdk::CodexAgentSdk>,
}

fn missing_provider_auth_message(target: &str) -> String {
    let env_var = crate::providers::api_key_env_var_for_target(target);
    format!("No API key configured for '{target}'. Set {env_var} or add it to config.")
}

fn resolve_provider_switch_auth(
    target: &str,
    provider: &crate::config::ProviderConfig,
) -> Result<ProviderSwitchAuth, String> {
    if target.eq_ignore_ascii_case("anthropic") && provider.api_key.is_none() {
        if crate::claude_credentials::experimental_direct_subscription_enabled() {
            let creds = crate::claude_credentials::load_credentials().map_err(|e| {
                format!(
                    "Experimental direct Claude credentials unusable: {e}. Run `claude auth login` or set ANTHROPIC_API_KEY."
                )
            })?;
            return Ok(ProviderSwitchAuth {
                api_key: None,
                claude_code_token: Some(creds.access_token),
                claude_agent_sdk: None,
                codex_agent_sdk: None,
            });
        }
        let sdk = crate::claude_agent_sdk::ClaudeAgentSdk::discover().map_err(|error| {
            format!(
                "Claude Agent SDK unavailable: {error}. Install Claude Code and run `claude auth login`, or set ANTHROPIC_API_KEY."
            )
        })?;
        return Ok(ProviderSwitchAuth {
            api_key: None,
            claude_code_token: None,
            claude_agent_sdk: Some(sdk),
            codex_agent_sdk: None,
        });
    }

    if let Some(api_key) = &provider.api_key {
        return Ok(ProviderSwitchAuth {
            api_key: Some(api_key.clone()),
            claude_code_token: None,
            claude_agent_sdk: None,
            codex_agent_sdk: None,
        });
    }

    if target.eq_ignore_ascii_case("openai") {
        let sdk = crate::codex_agent_sdk::CodexAgentSdk::discover()
            .map_err(|error| format!("Codex runtime unavailable: {error}"))?;
        return Ok(ProviderSwitchAuth {
            api_key: None,
            claude_code_token: None,
            claude_agent_sdk: None,
            codex_agent_sdk: Some(sdk),
        });
    }

    if crate::config::is_local_provider_name(target) {
        return Ok(ProviderSwitchAuth {
            api_key: None,
            claude_code_token: None,
            claude_agent_sdk: None,
            codex_agent_sdk: None,
        });
    }

    Err(missing_provider_auth_message(target))
}

fn resolve_provider_switch(
    requested: &str,
    prompt_blocks: Option<crate::prompt::SystemPromptBlocks>,
) -> Result<ProviderSwitch, String> {
    let target = requested.trim().to_ascii_lowercase();
    if target.is_empty() {
        return Err("Usage: /provider <name>".to_string());
    }

    crate::providers::get_adapter(&target).map_err(|e| e.to_string())?;

    let config = crate::config::load_config().map_err(|e| format!("Config load failed: {e}"))?;
    let provider = config
        .get_provider(&target)
        .cloned()
        .ok_or_else(|| format!("No provider config found for '{target}'."))?;
    let auth = resolve_provider_switch_auth(&target, &provider)?;
    let model = provider
        .model
        .clone()
        .or_else(|| crate::providers::default_model_for_target(&target).map(str::to_string))
        .ok_or_else(|| {
            format!("Provider '{target}' has no configured model; set providers.{target}.model")
        })?;
    let extra_headers = provider.headers.clone();
    let wire_api = if auth.codex_agent_sdk.is_some() {
        crate::pipeline::WireApi::OpenAiResponses
    } else {
        crate::pipeline::WireApi::ChatCompletions
    };
    let (endpoint, headers) = if auth.codex_agent_sdk.is_some() {
        let endpoint = crate::pipeline::resolve_endpoint_for_wire(
            wire_api,
            &target,
            &model,
            &provider.base_url,
            None,
        )
        .map_err(|e| e.to_string())?;
        (endpoint, crate::secrets::SensitiveHeaders::new())
    } else {
        let endpoint = crate::pipeline::resolve_endpoint_for_wire(
            wire_api,
            &target,
            &model,
            &provider.base_url,
            auth.claude_code_token.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        let headers = crate::pipeline::resolve_headers(
            &target,
            auth.api_key.as_ref(),
            auth.claude_code_token.as_ref(),
            &extra_headers,
        )
        .map_err(|e| e.to_string())?;
        (endpoint, headers)
    };
    let vdd_builder_auth = provider_switch_auth_to_vdd_auth(&auth);

    Ok(ProviderSwitch {
        provider: target,
        model,
        endpoint,
        headers,
        wire_api,
        claude_code_token: auth.claude_code_token,
        claude_agent_sdk: auth.claude_agent_sdk,
        codex_agent_sdk: auth.codex_agent_sdk,
        vdd_builder_auth,
        prompt_blocks,
    })
}

#[allow(clippy::option_if_let_else)] // Ordered precedence prevents combining incompatible auth modes.
fn provider_switch_auth_to_vdd_auth(auth: &ProviderSwitchAuth) -> crate::vdd::VddProviderAuth {
    if let Some(sdk) = auth.codex_agent_sdk.as_ref() {
        crate::vdd::VddProviderAuth::codex_agent_sdk(sdk.clone())
    } else if let Some(sdk) = auth.claude_agent_sdk.as_ref() {
        crate::vdd::VddProviderAuth::claude_agent_sdk(sdk.clone())
    } else if let Some(token) = auth.claude_code_token.as_ref() {
        crate::vdd::VddProviderAuth::claude_code_token(token.clone())
    } else if let Some(api_key) = auth.api_key.as_ref() {
        crate::vdd::VddProviderAuth::api_key(api_key.clone())
    } else {
        crate::vdd::VddProviderAuth::None
    }
}

fn static_model_strings(provider: &str) -> Vec<String> {
    crate::providers::static_models_for_provider(provider)
        .iter()
        .map(|model| (*model).to_string())
        .collect()
}

fn format_model_list(
    provider: &str,
    current_model: &str,
    models: &[String],
    source: &str,
    fallback_note: Option<&str>,
) -> String {
    let body = if models.is_empty() {
        "  (no models returned)".to_string()
    } else {
        models
            .iter()
            .map(|model| {
                let marker = if model == current_model {
                    " <- current"
                } else {
                    ""
                };
                format!("  {model}{marker}")
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let note = fallback_note.map_or_else(String::new, |note| format!("\n\n{note}"));
    let list_kind = if source.contains("fallback") {
        "this fallback list"
    } else {
        "this list"
    };
    format!(
        "Available models for {provider} ({source}):\n{body}{note}\n\nUse /model <name> to switch. Model names are not limited to {list_kind}."
    )
}

/// Which input mode the TUI is in when a keystroke arrives (crosslink #364).
///
/// The three values map 1:1 to the three explicit `handle_key_*` methods
/// on [`App`]. Computed fresh on every keystroke from `App`'s observable
/// state (overlay open? streaming in flight?) rather than stored as a
/// field, so the mode is always consistent with the data driving it —
/// pinning the mode in a field would create a second source of truth that
/// could drift out of sync with `overlay` / `is_waiting`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyMode {
    /// A modal overlay (help, log selector, …) is open and owns the
    /// keyboard until it returns `OverlayAction::Close`.
    Modal,
    /// A model response is in flight; only `Escape` (cancel) is
    /// meaningful, every other key is dropped.
    Streaming,
    /// Interactive editing — text input, scrolling, slash commands,
    /// permission-prompt acknowledgement.
    Normal,
}

/// HTTP-pipeline transport state used by every API turn (crosslink #253).
///
/// Extracted from the [`App`] god object so the transport bundle is a
/// single, cohesive value the async spawn site can clone in one line. Five
/// of `App`'s original 22 fields collapse into this struct:
///
/// * `client`          — the `reqwest::Client` shared across turns
/// * `endpoint`        — the API URL the proxy/provider exposes
/// * `headers`         — wire-level headers (auth, anthropic-version, …)
/// * `wire_api`        — request/stream protocol selected for this provider
/// * `claude_code_token` — OAuth bearer when running in claude-code-token mode
/// * `claude_agent_sdk` — supported Anthropic-owned subscription transport
/// * `codex_agent_sdk` — supported OpenAI-owned account transport
/// * `prompt_blocks`   — pre-split system prompt blocks for Anthropic caching
///
/// `model` and `provider` are NOT included: they're also shown in the UI
/// status bar and used by display code (`handle_slash_doctor`, status
/// pane, `/cost`). Pulling them through `ApiClient` would force every UI
/// reference to go through a level of indirection without a corresponding
/// cohesion win. The cut here is the actual *transport* bundle.
///
/// Fields are `pub` so the existing `self.api_client.endpoint.clone()`
/// idiom at the spawn site stays one-line. A future iteration can hide
/// these behind a builder once the construction order is firm.
#[derive(Debug, Clone)]
pub struct ApiClient {
    /// HTTP client reused across turns (connection pool, TLS state, …).
    pub client: reqwest::Client,
    /// The provider endpoint URL the proxy will POST to.
    pub endpoint: String,
    /// Wire-level headers carried on every request (auth, anthropic-version, …).
    pub headers: crate::secrets::SensitiveHeaders,
    /// Wire protocol carried by the endpoint.
    pub wire_api: crate::pipeline::WireApi,
    /// OAuth bearer used by the claude-code-token flow. `None` when the
    /// raw `ANTHROPIC_API_KEY` path is taken.
    pub claude_code_token: Option<crate::secrets::OAuthToken>,
    /// Anthropic-owned executable transport. `None` for direct HTTP
    /// providers and the quarantined legacy subscription experiment.
    pub claude_agent_sdk: Option<crate::claude_agent_sdk::ClaudeAgentSdk>,
    /// OpenAI-owned executable transport. `None` for direct HTTP providers.
    pub codex_agent_sdk: Option<crate::codex_agent_sdk::CodexAgentSdk>,
    /// Pre-split system-prompt blocks the Anthropic adapter uses to get
    /// cache hits on the long static tail. `None` when no split has been
    /// computed (non-Anthropic providers).
    pub prompt_blocks: Option<crate::prompt::SystemPromptBlocks>,
}

impl ApiClient {
    /// Construct an [`ApiClient`] on the process-shared provider client with
    /// the remaining fields defaulted (empty endpoint / headers, no token, no
    /// prompt-block split). The pipeline-bootstrap path fills these in via
    /// [`App::set_api_config`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: crate::provider_transport::shared_client_required(),
            endpoint: String::new(),
            headers: crate::secrets::SensitiveHeaders::new(),
            wire_api: crate::pipeline::WireApi::ChatCompletions,
            claude_code_token: None,
            claude_agent_sdk: None,
            codex_agent_sdk: None,
            prompt_blocks: None,
        }
    }
}

impl Default for ApiClient {
    fn default() -> Self {
        Self::new()
    }
}

fn build_startup_session_run_context(
    session: &Session,
    provider: &str,
    budget_limits: crate::runtime::BudgetLimits,
    parent_budget: Option<crate::runtime::RunBudgetAuthority>,
    remote_actions: crate::tools::remote_trigger::WebhookRegistry,
    web_egress_grants: crate::web_egress::WebEgressGrants,
) -> Result<std::sync::Arc<crate::tools::ToolRunContext>, String> {
    let identity = session.inspect_state(|state| state.identity.clone());
    let active_workspace = identity.active_workspace.clone();
    let project_root = active_workspace.as_ref().map_or_else(
        || identity.project_root.clone(),
        |workspace| workspace.repository_root().to_path_buf(),
    );
    let working_directory = active_workspace.as_ref().map_or_else(
        || identity.cwd.clone(),
        |workspace| workspace.repository_root().to_path_buf(),
    );
    let mut builder = crate::tools::ToolRunContext::builder(identity.session_id, project_root)
        .working_directory(working_directory)
        .host_startup_grants()
        .remote_actions(remote_actions)
        .web_egress_grants(web_egress_grants)
        .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
        .process(true)
        .network(true)
        .secrets(true)
        .provider(provider)
        .runtime_mode(runtime_mode_for_tui_session(session))
        .behavior_scope_targets(session.behavior_scope_targets())
        .budget_limits(budget_limits);
    if let Some(parent_budget) = parent_budget {
        builder = builder.parent_budget(parent_budget);
    }
    let base_run = builder.build()?;
    active_workspace
        .as_ref()
        .map_or(Ok(base_run.clone()), |workspace| {
            crate::tools::ToolRunContext::resume_isolated_workspace(&base_run, workspace)
                .map_err(|error| error.to_string())
        })
}

fn runtime_mode_for_tui_session(session: &Session) -> crate::modes::RuntimeMode {
    if session.agent_mode() == AgentMode::Plan {
        crate::modes::RuntimeMode::Plan
    } else {
        crate::modes::RuntimeMode::Behavioral(session.behavior_mode())
    }
}

fn parse_behavior_scope_targets(
    session: &Session,
    values: &[String],
) -> Result<Option<crate::modes::BehaviorScopeTargets>, String> {
    if values.is_empty() {
        return Ok(None);
    }
    let identity = session.inspect_state(|state| state.identity.clone());
    let requested_project = identity
        .active_workspace
        .as_ref()
        .map_or(identity.project_root.as_path(), |workspace| {
            workspace.repository_root()
        });
    let project_root = std::fs::canonicalize(requested_project).map_err(|error| {
        format!(
            "Cannot bind behavioral scope to project '{}': {error}",
            requested_project.display()
        )
    })?;
    let working_directory = std::fs::canonicalize(&identity.cwd).map_err(|error| {
        format!(
            "Cannot bind behavioral scope to working directory '{}': {error}",
            identity.cwd.display()
        )
    })?;
    crate::modes::BehaviorScopeTargets::from_user_values(&project_root, &working_directory, values)
        .map(Some)
}

fn derive_session_run_context(
    parent: &crate::tools::ToolRunContext,
    session: &Session,
    active_provider: &str,
) -> Result<std::sync::Arc<crate::tools::ToolRunContext>, String> {
    if !session.provider.eq_ignore_ascii_case(active_provider) {
        return Err(format!(
            "Saved session provider '{}' differs from the active provider '{}'; switch providers before resuming it",
            session.provider, active_provider
        ));
    }
    let identity = session.inspect_state(|state| state.identity.clone());
    let project_root = std::fs::canonicalize(&identity.project_root).map_err(|error| {
        format!(
            "Cannot resume project root '{}': {error}",
            identity.project_root.display()
        )
    })?;
    if project_root != parent.project_root() {
        return Err(format!(
            "Session project '{}' differs from the authorized launch project '{}'; launch OpenClaudia from that project to resume it",
            project_root.display(),
            parent.project_root().display()
        ));
    }
    let base_cwd = identity
        .active_workspace
        .as_ref()
        .map_or(identity.cwd.as_path(), |workspace| {
            workspace.repository_root()
        });
    let run = parent.derive_frontend_session(
        identity.session_id,
        &project_root,
        base_cwd,
        active_provider,
    )?;
    run.transition_runtime_mode_scoped(
        runtime_mode_for_tui_session(session),
        session.behavior_scope_targets(),
    )?;
    identity
        .active_workspace
        .as_ref()
        .map_or(Ok(run.clone()), |workspace| {
            crate::tools::ToolRunContext::resume_isolated_workspace(&run, workspace)
                .map_err(|error| error.to_string())
        })
}

struct TuiMcpRuntime {
    plugin_manager: std::sync::Arc<crate::plugins::PluginManager>,
    manager: std::sync::Arc<tokio::sync::RwLock<crate::mcp::McpManager>>,
    trusted_servers: std::collections::HashSet<String>,
}

enum PluginTurnInvocation {
    Command(crate::plugins::PluginCommandInvocation),
    Skill(crate::plugins::PluginSkillInvocation),
    Agent(crate::plugins::PluginAgentInvocation),
}

/// Main TUI application state.
pub struct App {
    pub messages: MessageList,
    pub input: TextInput,
    /// Last configured key map compiled into the real terminal event path.
    keybinding_config: crate::config::KeybindingsConfig,
    keybinding_resolver: crate::keybindings::KeybindingResolver,
    /// Original terminal events retained while a multi-key chord is pending.
    pending_key_events: Vec<KeyEvent>,
    pub model: String,
    pub provider: String,
    /// Exact immutable host capabilities for this interactive session.
    run_context: Result<std::sync::Arc<crate::tools::ToolRunContext>, String>,
    /// MCP composition snapshot rebound when the frontend creates a new exact
    /// run generation. Trust and plugin discovery are captured at launch.
    mcp_runtime: Option<TuiMcpRuntime>,
    pub mode: Mode,
    pub should_quit: bool,
    pub is_waiting: bool,
    spinner_frame: usize,
    /// Full assistant text as received from streaming deltas. The visible
    /// Assistant text is buffered until the terminal evidence gate runs.
    streaming_raw_text: String,
    /// Sender for pushing API events into the event loop's channel.
    api_event_tx: Option<std::sync::mpsc::Sender<AppEvent>>,

    // ── API pipeline ──
    /// HTTP transport bundle (crosslink #253). Replaces the five
    /// fields `client`, `endpoint`, `headers`, `claude_code_token`,
    /// `prompt_blocks` that used to live directly on `App`.
    pub api_client: ApiClient,
    next_turn_effort_level: Option<EffortLevel>,
    next_turn_model: Option<String>,
    next_turn_allowed_tool_rules: Vec<crate::permissions::PermissionRule>,
    next_turn_skill_context: Vec<crate::context::ContextItem>,
    next_turn_hook_engine: Option<std::sync::Arc<crate::hooks::HookEngine>>,
    active_turn_hook_engine: Option<std::sync::Arc<crate::hooks::HookEngine>>,
    /// Memory database for auto-learning from tool execution.
    pub memory_db: Option<std::sync::Arc<crate::memory::MemoryDb>>,
    /// Loaded app configuration passed to tools that need provider/config state
    /// (`task`, `web_fetch` prompt distillation, and future config-aware tools).
    pub app_config: Option<std::sync::Arc<crate::config::AppConfig>>,
    /// Library-layer permission manager. When `Some`, every tool call routed
    /// through `pipeline::run_turn` consults this gate in addition to the
    /// UX-layer `PermissionResponse` flow — closes crosslink #505.
    pub permission_mgr: Option<std::sync::Arc<crate::permissions::PermissionManager>>,
    /// VDD engine for full-screen TUI turns when adversarial review is enabled.
    pub vdd_engine: Option<std::sync::Arc<crate::vdd::VddEngine>>,
    /// Auth used by VDD's builder-side verifier for the current chat provider.
    pub vdd_builder_auth: crate::vdd::VddProviderAuth,
    /// Async runtime handle for spawning API tasks from the sync event loop.
    runtime_handle: Option<tokio::runtime::Handle>,
    /// Fresh owner for every async task spawned during one `run()` launch.
    supervisor: Option<TuiSupervisor>,
    /// Exact model/plugin call currently controlling the streaming UI.
    active_turn: Option<ActiveTurn>,
    /// One-shot ancillary calls whose terminal event is still eligible for
    /// this launch. Completion events remove their exact call generation.
    background_calls: std::collections::HashMap<crate::runtime::CallId, TuiTaskKind>,
    /// Latest eligible completion for replacement-style discovery actions.
    latest_background_calls: std::collections::HashMap<TuiTaskKind, crate::runtime::CallId>,
    /// Successfully completed turn generations retained so background jobs
    /// deliberately started by those calls remain session-owned until exit.
    completed_turn_runs: Vec<CompletedTurnRun>,
    /// Persistent chat session (for save/load/resume)
    pub chat_session: Session,
    /// Coalescing transcript writer subscribed to canonical state changes.
    transcript_subscriber: crate::transcript::TranscriptStateSubscriber,
    /// Optional lifecycle analytics subscriber. Production installs the
    /// tracing sink after startup resume; tests and headless users remain
    /// silent unless they explicitly provide a sink.
    analytics_subscriber: Option<crate::services::analytics::StateAnalyticsSubscriber>,
    service_registry: crate::services::ServiceRegistry,
    /// Sole durable scheduler owner for the currently active run generation.
    scheduler_service: Option<crate::tools::SchedulerServiceHandle>,
    /// Active permission prompt (if any). Tool execution blocks until resolved.
    pending_permission: Option<PendingPermission>,
    /// Active `ask_user_question` modal (if any). The pipeline's
    /// post-tool-execution interceptor parks on a oneshot until the
    /// modal completes the question set and sends back the answers
    /// JSON. While `Some`, key dispatch routes to the modal walker.
    pending_user_question: Option<PendingUserQuestion>,
    /// Active digest-bound plan approval modal. This is distinct from direct
    /// `/mode` cancellation and exists only for a typed model follow-up.
    pending_plan_approval: Option<PendingPlanApproval>,
    /// Hook engine for running lifecycle hooks.
    pub hook_engine: Option<std::sync::Arc<crate::hooks::HookEngine>>,
    /// Session-scoped enterprise policy enforcer for tool caps.
    pub policy_enforcer: std::sync::Arc<crate::services::policy::PolicyEnforcer>,
    /// Session-scoped task tracker for the `task_create` / `task_update` /
    /// `task_list` / `task_get` tools. Always populated for the full-screen
    /// TUI so those tools have a place to write — previously the TUI passed
    /// `None` for `task_mgr` and the dispatcher returned
    /// "Task management not available (no session)".
    pub task_mgr: std::sync::Arc<std::sync::Mutex<crate::session::TaskManager>>,
    /// Active modal overlay (help / log picker / …). At most one at a
    /// time. `None` when the main chat UI has focus. Closing an
    /// overlay goes through its `OverlayAction` return value so the
    /// event loop stays the single owner of App-level state changes.
    overlay: Option<ActiveOverlay>,
}

/// Which overlay component is currently open. Each variant owns its
/// component state directly — the enum is the single-slot union the
/// event loop matches on to dispatch draw / key events.
pub enum ActiveOverlay {
    Help(super::components::HelpOverlay),
    LogSelector(super::components::LogSelector),
}

impl App {
    /// Clone the exact run capability after startup/resume has selected the
    /// final session identity.
    ///
    /// # Errors
    ///
    /// Returns the startup/resume capability-construction error when the TUI
    /// could not bind its selected session to an immutable run.
    pub fn tool_run_context(&self) -> Result<std::sync::Arc<crate::tools::ToolRunContext>, String> {
        self.run_context
            .as_ref()
            .map(std::sync::Arc::clone)
            .map_err(Clone::clone)
    }

    #[must_use]
    pub fn new(model: &str, provider: &str) -> Self {
        Self::new_with_policy(
            model,
            provider,
            std::sync::Arc::new(crate::services::policy::PolicyEnforcer::new(
                crate::services::policy::EnterprisePolicy::default(),
            )),
        )
    }

    #[must_use]
    pub fn new_with_policy(
        model: &str,
        provider: &str,
        policy_enforcer: std::sync::Arc<crate::services::policy::PolicyEnforcer>,
    ) -> Self {
        Self::new_with_policy_and_budget(
            model,
            provider,
            policy_enforcer,
            crate::runtime::BudgetLimits::default(),
        )
    }

    #[must_use]
    pub fn new_with_policy_and_budget(
        model: &str,
        provider: &str,
        policy_enforcer: std::sync::Arc<crate::services::policy::PolicyEnforcer>,
        budget_limits: crate::runtime::BudgetLimits,
    ) -> Self {
        Self::new_with_policy_budget_and_remote_actions(
            model,
            provider,
            policy_enforcer,
            budget_limits,
            crate::tools::remote_trigger::WebhookRegistry::new(),
            crate::web_egress::WebEgressGrants::public_only(),
        )
    }

    #[must_use]
    pub fn new_with_policy_budget_and_remote_actions(
        model: &str,
        provider: &str,
        policy_enforcer: std::sync::Arc<crate::services::policy::PolicyEnforcer>,
        budget_limits: crate::runtime::BudgetLimits,
        remote_actions: crate::tools::remote_trigger::WebhookRegistry,
        web_egress_grants: crate::web_egress::WebEgressGrants,
    ) -> Self {
        let chat_session = Session::new(model, provider);
        let transcript_subscriber =
            crate::transcript::TranscriptStateSubscriber::new(chat_session.state_store());
        let run_context = build_startup_session_run_context(
            &chat_session,
            provider,
            budget_limits,
            None,
            remote_actions,
            web_egress_grants,
        );
        let task_manager = run_context
            .as_ref()
            .ok()
            .and_then(|run| crate::session::TaskManager::for_run(run).ok())
            .unwrap_or_default();
        let keybinding_config = crate::config::KeybindingsConfig::default();
        let keybinding_resolver =
            crate::keybindings::KeybindingResolver::from_config(&keybinding_config);
        Self {
            messages: MessageList::new(),
            input: TextInput::new(),
            keybinding_config,
            keybinding_resolver,
            pending_key_events: Vec::new(),
            model: model.to_string(),
            provider: provider.to_string(),
            run_context,
            mcp_runtime: None,
            mode: Mode::Build,
            should_quit: false,
            is_waiting: false,
            spinner_frame: 0,
            streaming_raw_text: String::new(),
            api_event_tx: None,
            api_client: ApiClient::new(),
            next_turn_effort_level: None,
            next_turn_model: None,
            next_turn_allowed_tool_rules: Vec::new(),
            next_turn_skill_context: Vec::new(),
            next_turn_hook_engine: None,
            active_turn_hook_engine: None,
            memory_db: None,
            app_config: None,
            permission_mgr: None,
            vdd_engine: None,
            vdd_builder_auth: crate::vdd::VddProviderAuth::None,
            runtime_handle: None,
            supervisor: None,
            active_turn: None,
            background_calls: std::collections::HashMap::new(),
            latest_background_calls: std::collections::HashMap::new(),
            completed_turn_runs: Vec::new(),
            chat_session,
            transcript_subscriber,
            analytics_subscriber: None,
            service_registry: crate::services::ServiceRegistry::analytics_disabled(),
            scheduler_service: None,
            pending_permission: None,
            pending_user_question: None,
            pending_plan_approval: None,
            hook_engine: None,
            policy_enforcer,
            task_mgr: std::sync::Arc::new(std::sync::Mutex::new(task_manager)),
            overlay: None,
        }
    }

    /// Upgrade the selected startup/resume session to its descriptor-safe
    /// durable canonical task graph.
    ///
    /// # Errors
    /// Returns an error when the run context or durable graph root cannot be
    /// opened and validated.
    pub fn bind_durable_task_graph(&mut self) -> Result<(), String> {
        let run = self.tool_run_context()?;
        let manager = crate::session::TaskManager::open_for_run(&run)?;
        self.task_mgr = std::sync::Arc::new(std::sync::Mutex::new(manager));
        Ok(())
    }

    /// Atomically apply a behavioral mode to runtime authority and session
    /// persistence. An active plan remains the effective hard ceiling.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested behavioral mode conflicts with the
    /// currently enforceable runtime profile.
    pub fn apply_behavior_mode(
        &mut self,
        behavior_mode: crate::modes::BehaviorMode,
    ) -> Result<(), String> {
        let targets = self.chat_session.behavior_scope_targets();
        self.apply_behavior_mode_and_targets(behavior_mode, targets)
    }

    /// Atomically apply behavioral mode and approved scope targets to runtime
    /// authority before publishing them in resumable session state.
    ///
    /// # Errors
    ///
    /// Returns an error when the current run is unavailable or the requested
    /// mode and target set cannot be bound to it.
    pub fn apply_behavior_mode_and_targets(
        &mut self,
        behavior_mode: crate::modes::BehaviorMode,
        targets: crate::modes::BehaviorScopeTargets,
    ) -> Result<(), String> {
        let runtime_mode = if self.chat_session.agent_mode() == AgentMode::Plan {
            crate::modes::RuntimeMode::Plan
        } else {
            crate::modes::RuntimeMode::Behavioral(behavior_mode.clone())
        };
        self.tool_run_context()?
            .transition_runtime_mode_scoped(runtime_mode, targets.clone())?;
        self.chat_session
            .set_behavior_mode_and_targets(behavior_mode, targets);
        Ok(())
    }

    /// Persisted behavioral mode currently projected into prompts.
    #[must_use]
    pub fn behavior_mode(&self) -> crate::modes::BehaviorMode {
        self.chat_session.behavior_mode()
    }

    /// Open the help-cheatsheet overlay. Subsequent keystrokes go to
    /// the overlay until it returns `OverlayAction::Close`.
    pub fn open_help_overlay(&mut self) {
        self.cancel_pending_keybinding();
        self.sync_keybindings();
        let bindings = self
            .keybinding_resolver
            .effective_bindings(crate::keybindings::KeyContext::Chat)
            .into_iter()
            .map(|(chord, action)| {
                let availability = if tui_supports_key_action(&action) {
                    action.description().to_string()
                } else {
                    format!("{} (unavailable in this TUI)", action.description())
                };
                (chord, availability)
            })
            .collect();
        let diagnostics = self.keybinding_resolver.diagnostics().to_vec();
        self.overlay = Some(ActiveOverlay::Help(
            super::components::HelpOverlay::new().with_keybindings(bindings, diagnostics),
        ));
    }

    fn sync_keybindings(&mut self) {
        let configured = self
            .app_config
            .as_ref()
            .map_or_else(crate::config::KeybindingsConfig::default, |config| {
                config.keybindings.clone()
            });
        if configured == self.keybinding_config {
            return;
        }

        self.keybinding_config = configured;
        self.keybinding_resolver =
            crate::keybindings::KeybindingResolver::from_config(&self.keybinding_config);
        self.pending_key_events.clear();
        if !self.keybinding_resolver.diagnostics().is_empty() {
            self.messages.add(DisplayMessage::error(format!(
                "Some keybindings are unavailable:\n{}",
                self.keybinding_resolver.diagnostics().join("\n")
            )));
        }
    }

    fn cancel_pending_keybinding(&mut self) {
        self.keybinding_resolver.cancel();
        self.pending_key_events.clear();
    }

    #[allow(clippy::too_many_lines)] // Session replacement is one atomic frontend transition.
    fn apply_loaded_session(&mut self, loaded: &Session) -> bool {
        let current_run = match self.run_context.as_ref() {
            Ok(run) => std::sync::Arc::clone(run),
            Err(error) => {
                self.messages.add(DisplayMessage::error(format!(
                    "Cannot replace a session whose current run is unavailable: {error}"
                )));
                return false;
            }
        };
        let next_run = match derive_session_run_context(&current_run, loaded, &self.provider) {
            Ok(run) => run,
            Err(error) => {
                self.messages.add(DisplayMessage::error(error));
                return false;
            }
        };
        let durable_tasks = self
            .task_mgr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_durable();
        let next_task_manager = if durable_tasks {
            crate::session::TaskManager::open_for_run(&next_run)
        } else {
            crate::session::TaskManager::for_run(&next_run)
        };
        let next_task_manager = match next_task_manager {
            Ok(manager) => manager,
            Err(error) => {
                self.messages.add(DisplayMessage::error(format!(
                    "Cannot bind the loaded session task graph: {error}"
                )));
                return false;
            }
        };
        let permission_bypass = self.chat_session.permission_bypass_enabled();
        if let Some(config) = self.app_config.as_ref() {
            if let Err(error) = crate::guardrails::configure(&next_run, &config.guardrails) {
                self.messages.add(DisplayMessage::error(format!(
                    "Session guardrails configuration is invalid: {error}"
                )));
                return false;
            }
        }

        // Flush the old snapshot before replacement. Subscribers stay attached
        // because `apply_loaded` replaces the shared store in place.
        self.transcript_subscriber.flush_now();
        self.stop_scheduler_service();
        crate::tools::retire_run(&current_run);
        self.chat_session.apply_loaded(loaded);
        self.chat_session.set_permission_bypass(permission_bypass);
        self.model.clone_from(&loaded.model);
        self.provider.clone_from(&loaded.provider);
        self.run_context = Ok(std::sync::Arc::clone(&next_run));
        self.task_mgr = std::sync::Arc::new(std::sync::Mutex::new(next_task_manager));
        self.rebind_permission_manager(&next_run);
        self.refresh_prompt_context_for_run();
        self.rebind_mcp_runtime(&next_run);
        self.mode = tui_mode_for_agent(loaded.agent_mode());
        self.refresh_app_config_target();
        if let Err(error) = self.rebind_scheduler_service(&next_run) {
            self.messages.add(DisplayMessage::error(format!(
                "Loaded session scheduler could not start: {error}"
            )));
            self.should_quit = true;
            return false;
        }
        let _ = self.chat_session.refresh_estimated_tokens();
        let transcript_cwd = self.run_context.as_ref().map_or_else(
            |_| {
                self.chat_session
                    .inspect_state(|state| state.identity.cwd.clone())
            },
            |run| run.working_directory().to_path_buf(),
        );
        self.chat_session
            .set_transcript_position(transcript_cwd, self.chat_session.message_count());
        // Repaint the transcript.
        self.messages = super::messages::MessageList::new();
        for msg in loaded.messages_snapshot() {
            let role: super::messages::Role = msg
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("system")
                .parse()
                .unwrap_or(super::messages::Role::System);
            let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
            if role == super::messages::Role::System {
                continue;
            }
            let kind = match role {
                super::messages::Role::User => MessageKind::User,
                super::messages::Role::Assistant => MessageKind::Assistant,
                super::messages::Role::Tool => MessageKind::ToolOk {
                    name: String::new(),
                },
                super::messages::Role::System => MessageKind::SystemInfo,
            };
            self.messages.add(DisplayMessage {
                kind,
                content: content.to_string(),
            });
        }
        self.drain_state_subscribers();
        true
    }

    fn refresh_prompt_context_for_run(&mut self) {
        if self.api_client.prompt_blocks.is_none() {
            return;
        }
        let Ok(run) = self.run_context.as_ref() else {
            self.api_client.prompt_blocks = None;
            return;
        };
        self.api_client.prompt_blocks =
            Some(crate::prompt::build_prompt_context_with_items_for_run(
                &self.chat_session.behavior_mode(),
                run,
                self.next_turn_skill_context.clone(),
                crate::context::ContextBudget::default(),
            ));
    }

    fn rebind_mcp_runtime(&mut self, run: &std::sync::Arc<crate::tools::ToolRunContext>) {
        let Some(runtime) = self.mcp_runtime.as_mut() else {
            return;
        };
        runtime.plugin_manager.configure_lsp_service_for_run(run);
        let next_manager = std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::mcp::McpManager::new_with_permissions(
                std::sync::Arc::clone(run),
                self.app_config
                    .as_ref()
                    .map_or_else(crate::config::PermissionsConfig::default, |config| {
                        config.permissions.clone()
                    }),
            ),
        ));
        let _ = crate::mcp::install_manager(run, &next_manager);
        let previous_manager = std::mem::replace(&mut runtime.manager, next_manager.clone());
        let plugin_manager = std::sync::Arc::clone(&runtime.plugin_manager);
        let trusted_servers = runtime.trusted_servers.clone();
        let Some(handle) = self.runtime_handle.clone() else {
            tracing::warn!(
                "MCP session rebind installed without reconnect because the TUI runtime is unavailable"
            );
            return;
        };
        let task = async move {
            if let Err(error) = previous_manager.write().await.disconnect_all().await {
                tracing::warn!(%error, "failed to disconnect MCP servers for retired TUI run");
            }
            crate::proxy::connect_mcp_servers_with_trust(
                &next_manager,
                &plugin_manager,
                &trusted_servers,
            )
            .await;
        };
        let call_id = crate::runtime::CallId::new();
        if let Some(supervisor) = self.supervisor.as_mut() {
            supervisor.spawn(call_id, TuiTaskKind::Mcp, task);
        } else {
            drop(handle.spawn(task));
        }
    }

    fn stop_scheduler_service(&mut self) {
        drop(self.scheduler_service.take());
    }

    fn rebind_scheduler_service(
        &mut self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
    ) -> Result<(), String> {
        if self.runtime_handle.is_none() {
            return Ok(());
        }
        self.stop_scheduler_service();
        let config = self.app_config.clone().ok_or_else(|| {
            "Durable scheduler requires the active application configuration".to_string()
        })?;
        self.scheduler_service = Some(crate::tools::SchedulerServiceHandle::start(
            std::sync::Arc::clone(run),
            config,
            self.api_client.client.clone(),
        )?);
        Ok(())
    }

    fn apply_workspace_run_transition(
        &mut self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
    ) {
        self.stop_scheduler_service();
        // The pipeline has already published this generation, which makes the
        // previous run stale. Rebind the application first so a task-store
        // failure cannot accidentally route later operations through it.
        self.run_context = Ok(std::sync::Arc::clone(run));
        let manager = match crate::session::TaskManager::open_for_run(run) {
            Ok(manager) => manager,
            Err(error) => {
                self.messages.add(DisplayMessage::error(format!(
                    "Workspace changed, but its durable task graph could not be opened; using a run-bound ephemeral graph: {error}"
                )));
                match crate::session::TaskManager::for_run(run) {
                    Ok(manager) => manager,
                    Err(fallback_error) => {
                        self.messages.add(DisplayMessage::error(format!(
                            "Workspace task graph binding failed: {fallback_error}"
                        )));
                        return;
                    }
                }
            }
        };
        self.task_mgr = std::sync::Arc::new(std::sync::Mutex::new(manager));
        self.chat_session.bind_workspace_run(run);
        self.rebind_permission_manager(run);
        self.refresh_prompt_context_for_run();
        self.rebind_mcp_runtime(run);
        if let Err(error) = self.rebind_scheduler_service(run) {
            self.messages.add(DisplayMessage::error(format!(
                "Workspace changed, but its durable scheduler could not start: {error}"
            )));
            self.should_quit = true;
        }
        self.persist_session();
    }

    /// Install the explicit lifecycle-service composition for this frontend.
    ///
    /// # Errors
    ///
    /// Returns an error when a caller attempts to install an analytics-disabled
    /// registry into the interactive TUI.
    pub fn set_service_registry(
        &mut self,
        registry: crate::services::ServiceRegistry,
    ) -> Result<(), &'static str> {
        let Some(subscriber) = registry.analytics_subscriber(self.chat_session.state_store())
        else {
            return Err("interactive TUI service registry has analytics disabled");
        };
        self.service_registry = registry;
        self.analytics_subscriber = Some(subscriber);
        Ok(())
    }

    fn drain_state_subscribers(&mut self) {
        self.transcript_subscriber.drain_pending();
        if let Some(analytics) = self.analytics_subscriber.as_mut() {
            analytics.drain_pending();
        }
    }

    /// Resume the session whose id equals or prefix-matches `id`.
    /// Shared between the log-selector overlay (exact id) and the
    /// `/load` / `/continue` text commands (prefix match). No-op
    /// with a user-visible system message when no match is found.
    fn resume_session_by_id(&mut self, id: &str) {
        let sessions = list_sessions();
        let Some(loaded) = sessions
            .into_iter()
            .find(|session| session.id().starts_with(id))
        else {
            self.messages.add(DisplayMessage::error(format!(
                "No session found with id prefix '{id}'.",
            )));
            return;
        };
        let _ = self.apply_loaded_session(&loaded);
    }

    /// Apply top-level `--resume` / `--session-id` startup options.
    ///
    /// The default full-screen TUI is the primary binary mode, so these
    /// CLI flags must affect it instead of silently applying only to the
    /// legacy line REPL. A specific `--session-id` takes precedence over
    /// `--resume`; otherwise `--resume` loads the most recently updated
    /// saved TUI session.
    pub fn apply_startup_resume(&mut self, resume: bool, session_id: Option<&str>) {
        let _ = self.apply_startup_resume_with_behavior(resume, session_id, None, &[]);
    }

    /// Apply startup resume and launch-time behavioral overrides as one scoped
    /// session selection. Overrides are installed on the candidate session
    /// before its run is derived, so a saved narrow mode can be resumed with a
    /// newly supplied explicit target set.
    ///
    /// # Errors
    ///
    /// Returns an error when target values are invalid or the selected session
    /// cannot be rebound to the authorized launch run.
    pub fn apply_startup_resume_with_behavior(
        &mut self,
        resume: bool,
        session_id: Option<&str>,
        behavior_mode: Option<crate::modes::BehaviorMode>,
        scope_target_values: &[String],
    ) -> Result<(), String> {
        let mut selected = if let Some(id) = session_id {
            let session = list_sessions()
                .into_iter()
                .find(|session| session.id().starts_with(id));
            if session.is_none() {
                self.messages.add(DisplayMessage::error(format!(
                    "No session found with id prefix '{id}'.",
                )));
            }
            session
        } else if resume {
            let session = list_sessions().into_iter().next();
            if session.is_none() {
                self.messages
                    .add(DisplayMessage::system("No saved sessions to resume."));
            }
            session
        } else {
            None
        };

        if let Some(loaded) = selected.as_mut() {
            let scope_targets = parse_behavior_scope_targets(loaded, scope_target_values)?;
            if behavior_mode.is_some() || scope_targets.is_some() {
                loaded.set_behavior_mode_and_targets(
                    behavior_mode.unwrap_or_else(|| loaded.behavior_mode()),
                    scope_targets.unwrap_or_else(|| loaded.behavior_scope_targets()),
                );
            }
            if !self.apply_loaded_session(loaded) {
                return Err("could not bind the selected startup session".to_string());
            }
            return Ok(());
        }

        let scope_targets = parse_behavior_scope_targets(&self.chat_session, scope_target_values)?;
        if behavior_mode.is_some() || scope_targets.is_some() {
            self.apply_behavior_mode_and_targets(
                behavior_mode.unwrap_or_else(|| self.behavior_mode()),
                scope_targets.unwrap_or_else(|| self.chat_session.behavior_scope_targets()),
            )?;
        }
        Ok(())
    }

    /// Apply the current process's permission posture after any startup
    /// resume. This prevents a persisted session from carrying a dangerous
    /// bypass choice into a later invocation that omitted the flag.
    pub fn set_permission_bypass(&mut self, enabled: bool) {
        self.chat_session.set_permission_bypass(enabled);
        if let Ok(run) = self.run_context.as_ref().map(std::sync::Arc::clone) {
            self.rebind_permission_manager(&run);
        }
    }

    fn rebind_permission_manager(&mut self, run: &crate::tools::ToolRunContext) {
        let Some(config) = self.app_config.as_ref() else {
            return;
        };
        let manager = if self.chat_session.permission_bypass_enabled() {
            crate::permissions::PermissionManager::unrestricted_for_run(run)
        } else {
            crate::permissions::PermissionManager::trusted_for_run(
                run,
                config.permissions.enabled,
                config.permissions.default_allow.clone(),
                config.web_fetch.preapproved_domains.clone(),
            )
        };
        self.permission_mgr = Some(std::sync::Arc::new(manager));
    }

    /// Open the log-selector (session picker) overlay seeded with
    /// every transcript for the current project's cwd. No-op when
    /// there are zero saved sessions — the caller should show a
    /// different affordance in that case (current behavior: the
    /// overlay still opens with an empty-state message, matching
    /// Claude Code's `/resume` UX).
    pub fn open_log_selector(&mut self) {
        self.cancel_pending_keybinding();
        let transcripts = crate::transcript::list_transcripts(&self.chat_session.transcript_cwd());
        let rows = transcripts
            .into_iter()
            .map(|info| super::components::log_selector::SessionRow {
                session_id: info.session_id,
                first_prompt: info.first_prompt,
                message_count: info.message_count,
                modified_iso: iso_of_systemtime(info.modified),
            })
            .collect();
        self.overlay = Some(ActiveOverlay::LogSelector(
            super::components::LogSelector::new(rows),
        ));
    }

    /// Fire the `Stop` hook. Invoked when a turn reaches a terminal
    /// assistant response (no further tool-call follow-up). Best-effort
    /// — runtime/engine absence short-circuits silently.
    fn fire_stop_hook_for_run(
        &mut self,
        run_context: std::sync::Arc<crate::tools::ToolRunContext>,
        call_id: crate::runtime::CallId,
    ) {
        let engine = self
            .active_turn_hook_engine
            .take()
            .or_else(|| self.hook_engine.clone());
        if let (Some(engine), Some(handle)) = (engine, self.runtime_handle.clone()) {
            let session_id = self.chat_session.id();
            let task = async move {
                let input =
                    crate::hooks::HookInput::for_run(&run_context, crate::hooks::HookEvent::Stop)
                        .with_session_id(session_id);
                let _ = engine.run(crate::hooks::HookEvent::Stop, &input).await;
            };
            if let Some(supervisor) = self.supervisor.as_mut() {
                supervisor.spawn(call_id, TuiTaskKind::Hook, task);
            } else {
                drop(handle.spawn(task));
            }
        }
    }

    /// Fire the `Notification` hook with a free-form message. Used for
    /// API errors, rate-limit warnings, etc. Best-effort as above.
    fn fire_notification_hook_for_run(
        &mut self,
        run_context: std::sync::Arc<crate::tools::ToolRunContext>,
        call_id: crate::runtime::CallId,
        message: &str,
        level: &str,
    ) {
        let engine = self
            .active_turn_hook_engine
            .as_ref()
            .or(self.hook_engine.as_ref());
        if let (Some(engine), Some(handle)) = (engine, self.runtime_handle.clone()) {
            let engine = engine.clone();
            let session_id = self.chat_session.id();
            let message = message.to_string();
            let level = level.to_string();
            let task = async move {
                let payload = serde_json::json!({
                    "message": message,
                    "level": level.clone(),
                    "session_id": session_id,
                });
                let input = crate::hooks::HookInput::for_run(
                    &run_context,
                    crate::hooks::HookEvent::Notification,
                )
                .with_extra("notification_type", serde_json::Value::String(level))
                .with_extra("data", payload);
                let _ = engine
                    .run(crate::hooks::HookEvent::Notification, &input)
                    .await;
            };
            if let Some(supervisor) = self.supervisor.as_mut() {
                supervisor.spawn(call_id, TuiTaskKind::Hook, task);
            } else {
                drop(handle.spawn(task));
            }
        }
    }

    /// Keep the append-only transcript and JSON session snapshot coherent:
    /// only persist a watermark after the corresponding JSONL appends have
    /// succeeded.
    fn persist_session(&mut self) {
        // An unconditional reconciliation gives failed writes a retry even
        // when no new state event arrived since the last attempt.
        self.transcript_subscriber.flush_now();
        let _ = save_session(&self.chat_session);
    }

    /// Set the API connection details needed to make requests.
    #[allow(clippy::too_many_arguments)] // Transport capabilities must change atomically on provider switch.
    pub fn set_api_config(
        &mut self,
        endpoint: String,
        headers: crate::secrets::SensitiveHeaders,
        wire_api: crate::pipeline::WireApi,
        prompt_blocks: Option<crate::prompt::SystemPromptBlocks>,
        claude_code_token: Option<crate::secrets::OAuthToken>,
        claude_agent_sdk: Option<crate::claude_agent_sdk::ClaudeAgentSdk>,
        codex_agent_sdk: Option<crate::codex_agent_sdk::CodexAgentSdk>,
    ) {
        self.api_client.endpoint = endpoint;
        self.api_client.headers = headers;
        self.api_client.wire_api = wire_api;
        self.api_client.prompt_blocks = prompt_blocks;
        self.api_client.claude_code_token = claude_code_token;
        self.api_client.claude_agent_sdk = claude_agent_sdk;
        self.api_client.codex_agent_sdk = codex_agent_sdk;
    }

    /// Retain the launch-time MCP discovery/trust snapshot so a later session
    /// transition can create a manager for the new exact run generation.
    pub fn set_mcp_runtime(
        &mut self,
        plugin_manager: std::sync::Arc<crate::plugins::PluginManager>,
        manager: std::sync::Arc<tokio::sync::RwLock<crate::mcp::McpManager>>,
        trusted_servers: std::collections::HashSet<String>,
    ) {
        self.mcp_runtime = Some(TuiMcpRuntime {
            plugin_manager,
            manager,
            trusted_servers,
        });
    }

    fn apply_provider_switch(&mut self, switch: ProviderSwitch) {
        let ProviderSwitch {
            provider,
            model,
            endpoint,
            headers,
            wire_api,
            claude_code_token,
            claude_agent_sdk,
            codex_agent_sdk,
            vdd_builder_auth,
            prompt_blocks,
        } = switch;

        let current_run = match self.run_context.as_ref() {
            Ok(run) => std::sync::Arc::clone(run),
            Err(error) => {
                self.messages.add(DisplayMessage::error(format!(
                    "Provider switch cannot create a run capability: {error}"
                )));
                return;
            }
        };
        let identity = self
            .chat_session
            .inspect_state(|state| state.identity.clone());
        let next_run = match current_run.derive_frontend_session(
            identity.session_id,
            &identity.project_root,
            &identity.cwd,
            &provider,
        ) {
            Ok(run) => run,
            Err(error) => {
                self.messages.add(DisplayMessage::error(format!(
                    "Provider switch cannot bind the session run: {error}"
                )));
                return;
            }
        };

        if let Some(config) = self.app_config.as_ref() {
            if let Err(error) = crate::guardrails::configure(&next_run, &config.guardrails) {
                self.messages.add(DisplayMessage::error(format!(
                    "Provider guardrails configuration is invalid: {error}"
                )));
                return;
            }
        }

        self.stop_scheduler_service();
        crate::tools::retire_run(&current_run);
        self.run_context = Ok(std::sync::Arc::clone(&next_run));
        self.chat_session
            .set_provider_and_model(provider.clone(), model.clone());
        self.provider = provider;
        self.model = model;
        self.refresh_app_config_target();
        if let Err(error) = self.rebind_scheduler_service(&next_run) {
            self.messages.add(DisplayMessage::error(format!(
                "Provider scheduler could not start: {error}"
            )));
            self.should_quit = true;
            return;
        }
        self.rebind_permission_manager(&next_run);

        self.set_api_config(
            endpoint,
            headers,
            wire_api,
            prompt_blocks,
            claude_code_token,
            claude_agent_sdk,
            codex_agent_sdk,
        );
        self.refresh_prompt_context_for_run();
        self.rebind_mcp_runtime(&next_run);
        self.vdd_builder_auth = vdd_builder_auth;
        self.persist_session();
        self.messages.add(DisplayMessage::system(format!(
            "Provider switched to {} ({})",
            self.provider, self.model
        )));
    }

    fn refresh_app_config_target(&mut self) {
        let Some(app_config) = self.app_config.as_ref() else {
            return;
        };
        let mut updated = (**app_config).clone();
        updated.proxy.target.clone_from(&self.provider);
        if let Some(provider_config) = updated.providers.get_mut(&self.provider) {
            provider_config.model = Some(self.model.clone());
        }
        self.app_config = Some(std::sync::Arc::new(updated));
    }

    /// Get an event sender for pushing async API events into the TUI loop.
    #[must_use]
    pub fn event_sender(&self) -> Option<std::sync::mpsc::Sender<AppEvent>> {
        self.api_event_tx.clone()
    }

    fn refresh_cancelled_launch_run(&mut self) -> Result<bool, String> {
        let current = self.tool_run_context()?;
        if !current.runtime().cancellation().is_cancelled() {
            return Ok(false);
        }
        let next = if current.isolated_workspace().is_some() {
            let config = self.app_config.as_ref().ok_or_else(|| {
                "Cannot rebuild a cancelled isolated-workspace run without app configuration"
                    .to_string()
            })?;
            let remote_actions = config.remote_actions.build_registry()?;
            let web_egress_grants = config.build_web_egress_grants()?;
            crate::tools::worktree::release_workspace_descriptor_owner(&current)?;
            build_startup_session_run_context(
                &self.chat_session,
                &self.provider,
                config
                    .session
                    .run_budget
                    .limits_for_session(&config.session),
                Some(current.runtime().budget().clone()),
                remote_actions,
                web_egress_grants,
            )?
        } else {
            derive_session_run_context(&current, &self.chat_session, &self.provider)?
        };
        if let Some(config) = self.app_config.as_ref() {
            crate::guardrails::configure(&next, &config.guardrails)?;
        }
        let durable_tasks = self
            .task_mgr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_durable();
        let manager = if durable_tasks {
            crate::session::TaskManager::open_for_run(&next)?
        } else {
            crate::session::TaskManager::for_run(&next)?
        };
        self.run_context = Ok(std::sync::Arc::clone(&next));
        crate::tools::retire_run(&current);
        self.task_mgr = std::sync::Arc::new(std::sync::Mutex::new(manager));
        self.rebind_permission_manager(&next);
        self.refresh_prompt_context_for_run();
        Ok(true)
    }

    fn ensure_live_launch_run(&mut self) -> Result<(), String> {
        if !self.refresh_cancelled_launch_run()? {
            return Ok(());
        }
        let run = self
            .tool_run_context()
            .map_err(|error| format!("Cancelled TUI run could not publish replacement: {error}"))?;
        self.rebind_mcp_runtime(&run);
        self.rebind_scheduler_service(&run)
            .map_err(|error| format!("Cancelled TUI run could not restart its scheduler: {error}"))
    }

    async fn reap_supervised_tasks(&mut self) {
        let completions = match self.supervisor.as_mut() {
            Some(supervisor) => supervisor.reap_finished().await,
            None => Vec::new(),
        };
        for completion in completions {
            self.observe_task_completion(completion);
        }
        self.reap_completed_turn_runs();
    }

    fn reap_completed_turn_runs(&mut self) {
        let supervisor = self.supervisor.as_ref();
        self.completed_turn_runs.retain(|completed| {
            let supervised =
                supervisor.is_some_and(|supervisor| supervisor.contains(completed.call_id));
            let shell_active = !crate::tools::BACKGROUND_SHELLS
                .active_ids_for_run(&completed.run_context)
                .is_empty();
            let agent_active = crate::subagent::BACKGROUND_AGENTS
                .active_ids_for_run(&completed.run_context)
                .map_or(true, |ids| !ids.is_empty());
            let retain = supervised || shell_active || agent_active;
            if !retain {
                crate::tools::retire_run(&completed.run_context);
            }
            retain
        });
    }

    fn retain_completed_turn_run(
        &mut self,
        call_id: crate::runtime::CallId,
        run_context: &std::sync::Arc<crate::tools::ToolRunContext>,
    ) {
        let is_session_generation = self
            .run_context
            .as_ref()
            .is_ok_and(|current| std::sync::Arc::ptr_eq(current, run_context));
        if !is_session_generation {
            self.completed_turn_runs.push(CompletedTurnRun {
                call_id,
                run_context: std::sync::Arc::clone(run_context),
            });
        }
    }

    /// Own one ancillary TUI operation and deliver exactly one terminal event.
    ///
    /// Production launches route the task through the launch supervisor and
    /// tag its result with a typed call ID. The unsupervised branch is retained
    /// for unit fixtures that exercise these helpers without entering `run()`.
    fn spawn_owned_event<F>(
        &mut self,
        kind: TuiTaskKind,
        future: F,
    ) -> Option<tokio::task::JoinHandle<()>>
    where
        F: std::future::Future<Output = AppEvent> + Send + 'static,
    {
        let output = self.event_sender()?;
        let runtime = self.runtime_handle.clone()?;
        let call_id = crate::runtime::CallId::new();
        if let Some(supervisor) = self.supervisor.as_mut() {
            self.background_calls.insert(call_id, kind);
            if kind.supersedes_previous() {
                if let Some(previous) = self.latest_background_calls.insert(kind, call_id) {
                    supervisor.cancel_call(
                        previous,
                        &crate::runtime::CancellationReason::ParentTerminated,
                    );
                }
            }
            supervisor.spawn(call_id, kind, async move {
                let event = future.await;
                let _ = output.send(AppEvent::Correlated {
                    call_id,
                    event: Box::new(event),
                });
            });
            None
        } else {
            Some(runtime.spawn(async move {
                let _ = output.send(future.await);
            }))
        }
    }

    fn remove_background_call(&mut self, call_id: crate::runtime::CallId) -> Option<TuiTaskKind> {
        let kind = self.background_calls.remove(&call_id)?;
        if self.latest_background_calls.get(&kind) == Some(&call_id) {
            self.latest_background_calls.remove(&kind);
        }
        Some(kind)
    }

    fn observe_task_completion(&mut self, completion: TuiTaskCompletion) {
        if let Some(turn) = self
            .active_turn
            .as_mut()
            .filter(|turn| turn.call_id == completion.call_id)
        {
            if let Some(bridge) = turn.event_bridge.as_mut() {
                bridge.finish();
            }
            turn.task_outcome = Some(completion.outcome);
            return;
        }
        if !matches!(&completion.outcome, TuiTaskOutcome::Completed) {
            self.remove_background_call(completion.call_id);
        }
        if let TuiTaskOutcome::Panicked(error) = completion.outcome {
            self.messages.add(DisplayMessage::error(format!(
                "Background {:?} call {} panicked: {error}",
                completion.kind, completion.call_id
            )));
        }
    }

    fn finalize_joined_active_turn(&mut self) {
        if self
            .active_turn
            .as_ref()
            .is_none_or(|turn| turn.task_outcome.is_none())
        {
            return;
        }
        let Some(mut turn) = self.active_turn.take() else {
            return;
        };
        if let Some(bridge) = turn.event_bridge.as_mut() {
            bridge.finish();
        }
        let Some(task_outcome) = turn.task_outcome.take() else {
            self.active_turn = Some(turn);
            return;
        };
        let terminal = match (turn.terminal.take(), task_outcome) {
            (Some(terminal), TuiTaskOutcome::Completed) => terminal,
            (Some(ActiveTurnTerminal::Failed(error)), TuiTaskOutcome::Cancelled(_)) => {
                ActiveTurnTerminal::Failed(error)
            }
            (Some(ActiveTurnTerminal::Cancelled(reason)), _) => {
                ActiveTurnTerminal::Cancelled(reason)
            }
            (_, TuiTaskOutcome::Cancelled(receipt)) => {
                ActiveTurnTerminal::Cancelled(receipt.reason)
            }
            (_, TuiTaskOutcome::Panicked(error)) => ActiveTurnTerminal::Failed(format!(
                "Owned TUI call {} panicked: {error}",
                turn.call_id
            )),
            (None, TuiTaskOutcome::Completed) => ActiveTurnTerminal::Failed(format!(
                "Owned TUI call {} ended without a terminal outcome",
                turn.call_id
            )),
        };

        match terminal {
            ActiveTurnTerminal::Succeeded => {
                self.retain_completed_turn_run(turn.call_id, &turn.run_context);
                self.handle_response_done_for_run(turn.run_context, turn.call_id);
            }
            ActiveTurnTerminal::Failed(error) => {
                self.retain_completed_turn_run(turn.call_id, &turn.run_context);
                self.handle_api_error_for_run(&error, turn.run_context, turn.call_id);
            }
            ActiveTurnTerminal::PluginAgent { label, result } => {
                self.retain_completed_turn_run(turn.call_id, &turn.run_context);
                self.handle_plugin_agent_done(&label, &result);
            }
            ActiveTurnTerminal::Cancelled(reason) => {
                crate::tools::retire_run(&turn.run_context);
                self.cancel_pending_keybinding();
                self.preserve_failed_stream_for_display();
                self.is_waiting = false;
                self.active_turn_hook_engine = None;
                self.messages.add(DisplayMessage::system(format!(
                    "[Response cancelled: {}]",
                    cancellation_reason_label(&reason)
                )));
            }
        }
    }

    fn handle_correlated_event(
        &mut self,
        call_id: crate::runtime::CallId,
        event: AppEvent,
    ) -> bool {
        let is_active_turn = self
            .active_turn
            .as_ref()
            .is_some_and(|turn| turn.call_id == call_id);
        if is_active_turn {
            match event {
                AppEvent::ResponseDone => {
                    if let Some(turn) = self.active_turn.as_mut() {
                        turn.terminal.get_or_insert(ActiveTurnTerminal::Succeeded);
                    }
                }
                AppEvent::ApiError(error) => {
                    if let Some(turn) = self.active_turn.as_mut() {
                        turn.terminal
                            .get_or_insert_with(|| ActiveTurnTerminal::Failed(error.to_string()));
                    }
                    self.cancel_active_turn_resources(
                        &crate::runtime::CancellationReason::RuntimeFailure {
                            detail: "model turn failed".to_string(),
                        },
                    );
                }
                AppEvent::PluginAgentDone { label, result } => {
                    if let Some(turn) = self.active_turn.as_mut() {
                        turn.terminal
                            .get_or_insert(ActiveTurnTerminal::PluginAgent { label, result });
                    }
                }
                AppEvent::WorkspaceTransition { ref run_context } => {
                    if let Some(turn) = self.active_turn.as_mut() {
                        turn.run_context = std::sync::Arc::clone(run_context);
                    }
                    return self.handle_app_event(Ok(event));
                }
                other => return self.handle_app_event(Ok(other)),
            }
            return true;
        }

        if let Some(kind) = self.background_calls.get(&call_id).copied() {
            let is_latest = !kind.supersedes_previous()
                || self.latest_background_calls.get(&kind) == Some(&call_id);
            self.remove_background_call(call_id);
            if is_latest {
                return self.handle_app_event(Ok(event));
            }
            tracing::debug!(%call_id, ?kind, "ignored superseded TUI background completion");
            return true;
        }

        if self
            .supervisor
            .as_ref()
            .is_some_and(|supervisor| supervisor.contains(call_id))
        {
            return self.handle_app_event(Ok(event));
        }
        tracing::debug!(%call_id, "ignored event from completed or cancelled TUI call");
        true
    }

    fn cancel_active_turn_resources(&mut self, reason: &crate::runtime::CancellationReason) {
        let Some(turn) = self.active_turn.as_ref() else {
            return;
        };
        let _ = turn
            .run_context
            .runtime()
            .cancellation()
            .cancel((*reason).clone());
        if let Some(supervisor) = self.supervisor.as_ref() {
            supervisor.cancel_call(turn.call_id, reason);
        }
        if let Some(permission) = self.pending_permission.take() {
            let _ = permission
                .reply
                .send(super::events::PermissionResponse::Deny);
        }
        self.pending_user_question = None;
        if let Some(plan) = self.pending_plan_approval.take() {
            let _ = plan.reply.send(PlanModeReply::Cancelled {
                message: "Plan approval cancelled with its owning turn".to_string(),
            });
        }
    }

    /// Run the interactive TUI event loop.
    ///
    /// `async` so the `SessionEnd` cleanup at the end can `.await` the
    /// hook engine directly instead of `Handle::block_on`-ing the same
    /// current-thread runtime that's already driving it (which panics
    /// with "Cannot start a runtime from within a runtime"). The event
    /// loop body itself is still synchronous — `events.next()` blocks
    /// the main task — so no concurrent async work runs until the loop
    /// exits, but that matches the pre-fix behaviour and is necessary
    /// for the terminal-render loop.
    ///
    /// # Errors
    ///
    /// Returns an error if terminal initialization or rendering fails.
    #[allow(clippy::too_many_lines, clippy::future_not_send)] // Current-thread terminal receiver and async cleanup share one ordered lifecycle boundary.
    pub async fn run(&mut self) -> io::Result<()> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|error| io::Error::other(format!("TUI requires an async runtime: {error}")))?;
        self.runtime_handle = Some(runtime.clone());
        self.should_quit = false;
        self.is_waiting = false;
        self.api_event_tx = None;
        self.active_turn = None;
        self.background_calls.clear();
        self.latest_background_calls.clear();

        let refreshed_run = self
            .refresh_cancelled_launch_run()
            .map_err(io::Error::other)?;
        let launch_run = self.tool_run_context().map_err(io::Error::other)?;
        self.supervisor = Some(TuiSupervisor::new(runtime));

        // Session admission is a runtime lifecycle boundary shared with the
        // proxy, ACP, and legacy frontend. It runs before terminal mutation so
        // a deny, approval request, timeout, or hook failure cannot leave a
        // partially-started UI session behind.
        if let (Some(engine), Ok(run_context)) =
            (self.hook_engine.as_ref(), self.run_context.as_ref())
        {
            let session_id = self.chat_session.id();
            let input = crate::hooks::HookInput::for_run(
                run_context,
                crate::hooks::HookEvent::SessionStart,
            )
            .with_session_id(session_id);
            let receipt = engine
                .run_lifecycle(crate::hooks::HookEvent::SessionStart, &input)
                .await;
            if let Some(reason) = receipt.blocking_reason() {
                if let Some(runtime) = self.mcp_runtime.as_ref() {
                    if let Err(error) = runtime.manager.write().await.disconnect_all().await {
                        tracing::warn!(%error, "failed to disconnect MCP servers after TUI admission denial");
                    }
                }
                crate::tools::retire_run(run_context);
                if let Some(mut supervisor) = self.supervisor.take() {
                    let _ = supervisor
                        .cancel_and_join(crate::runtime::CancellationReason::RuntimeFailure {
                            detail: "TUI session admission denied".to_string(),
                        })
                        .await;
                }
                return Err(io::Error::other(format!(
                    "SessionStart hook blocked TUI startup: {reason}"
                )));
            }
        }

        let scheduler_run = self
            .run_context
            .as_ref()
            .map(std::sync::Arc::clone)
            .map_err(|error| {
                io::Error::other(format!("Durable scheduler run is unavailable: {error}"))
            })?;
        if let Err(error) = self.rebind_scheduler_service(&scheduler_run) {
            if let Some(mut supervisor) = self.supervisor.take() {
                let _ = supervisor
                    .cancel_and_join(crate::runtime::CancellationReason::RuntimeFailure {
                        detail: "TUI scheduler startup failed".to_string(),
                    })
                    .await;
            }
            crate::tools::retire_run(&scheduler_run);
            return Err(io::Error::other(format!(
                "Durable scheduler startup failed: {error}"
            )));
        }
        if refreshed_run {
            self.rebind_mcp_runtime(&launch_run);
        }

        let mut terminal_session = TerminalSession::enter()?;
        let backend = CrosstermBackend::new(io::stdout());
        let mut terminal = Terminal::new(backend)?;
        // Single event handler — two readers would steal each other's input.
        let events = EventHandler::new(Duration::from_millis(100));
        self.api_event_tx = Some(events.sender());

        let loop_outcome = std::panic::AssertUnwindSafe(async {
            loop {
                self.reap_supervised_tasks().await;
                if self
                    .supervisor
                    .as_ref()
                    .is_some_and(TuiSupervisor::is_cancelled)
                {
                    break;
                }

                // Drain ALL pending events before drawing so the next
                // frame reflects the most recent state. The previous
                // "draw → handle one event → loop" order painted the
                // OLD state on every iteration that received an event,
                // and the NEW state only appeared on the iteration
                // after — producing the "responses one turn behind"
                // symptom users reported when streaming events arrived
                // back-to-back. Draining the channel first eliminates
                // that one-frame lag without changing per-event
                // dispatch semantics.
                let mut channel_dead = false;
                loop {
                    match events.try_next() {
                        Ok(event) => {
                            if !self.handle_app_event(Ok(event)) {
                                channel_dead = true;
                                break;
                            }
                            if self.should_quit {
                                break;
                            }
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            let _ = self.handle_app_event(Err(std::sync::mpsc::RecvError));
                            channel_dead = true;
                            break;
                        }
                    }
                }
                self.finalize_joined_active_turn();
                self.drain_state_subscribers();
                if channel_dead || self.should_quit {
                    break;
                }

                // Render once per loop iteration with the post-drain state.
                terminal.draw(|frame| self.draw(frame))?;

                // Yield to the runtime so spawned tasks
                // (`run_api_turn_async`, tool calls, hook execution)
                // can drive their futures. Under
                // `flavor = "current_thread"` this `.await` is the only
                // place the executor regains control between events.
                // 16 ms ≈ 60 fps — keypress echo feels instant without
                // burning CPU between events.
                tokio::time::sleep(Duration::from_millis(16)).await;
            }

            // Save session and any final transcript tail on exit.
            self.chat_session.touch();
            self.persist_session();
            if let Some(analytics) = self.analytics_subscriber.as_mut() {
                analytics.finish();
            }
            debug_assert!(self.service_registry.analytics_is_enabled());
            Ok::<(), io::Error>(())
        })
        .catch_unwind()
        .await;

        let mut outcome = match loop_outcome {
            Ok(outcome) => outcome,
            Err(payload) => Err(io::Error::other(format!(
                "TUI event loop panicked: {}",
                panic_payload_message(payload.as_ref())
            ))),
        };

        // Restore the user's terminal before awaiting potentially slow child
        // cleanup. The guard retries best-effort if explicit restoration fails.
        outcome = outcome.and_then(|()| terminal_session.restore());

        let shutdown_reason = if outcome.is_ok() {
            crate::runtime::CancellationReason::FrontendDisconnected
        } else {
            crate::runtime::CancellationReason::RuntimeFailure {
                detail: "TUI event loop terminated with an error".to_string(),
            }
        };
        if let Some(turn) = self.active_turn.as_mut() {
            turn.terminal
                .get_or_insert_with(|| ActiveTurnTerminal::Cancelled(shutdown_reason.clone()));
        }
        self.cancel_active_turn_resources(&shutdown_reason);
        if let Some(mut supervisor) = self.supervisor.take() {
            let completions = supervisor.cancel_and_join(shutdown_reason).await;
            for completion in completions {
                self.observe_task_completion(completion);
            }
        }
        self.background_calls.clear();
        self.latest_background_calls.clear();
        if let Some(mut turn) = self.active_turn.take() {
            if let Some(bridge) = turn.event_bridge.as_mut() {
                bridge.finish();
            }
            crate::tools::retire_run(&turn.run_context);
            tracing::info!(
                call_id = %turn.call_id,
                "TUI active call joined during launch shutdown"
            );
        }
        for completed in self.completed_turn_runs.drain(..) {
            crate::tools::retire_run(&completed.run_context);
        }
        self.api_event_tx = None;
        drop(events);

        if let Some(scheduler) = self.scheduler_service.take() {
            if let Err(error) = scheduler.shutdown().await {
                outcome = outcome.and_then(|()| {
                    Err(io::Error::other(format!(
                        "Durable scheduler shutdown failed: {error}"
                    )))
                });
            }
        }

        // Fire SessionEnd hooks. Best-effort: the app is already exiting
        // so we can't recover from a failure, and we must not spam the
        // terminal (already restored from alt-screen). The hook engine
        // owns its own error logging via tracing.
        //
        // Awaiting directly (rather than `Handle::block_on`-ing inside the
        // current-thread runtime) avoids the "Cannot start a runtime from
        // within a runtime" panic that surfaced when the TUI was launched
        // via `#[tokio::main(flavor = "current_thread")]`.
        if let Some(engine) = self.hook_engine.as_ref() {
            if let Ok(run_context) = self.run_context.as_ref() {
                let session_id = self.chat_session.id();
                let input = crate::hooks::HookInput::for_run(
                    run_context,
                    crate::hooks::HookEvent::SessionEnd,
                )
                .with_session_id(session_id);
                let _ = engine
                    .run(crate::hooks::HookEvent::SessionEnd, &input)
                    .await;
            }
        }
        if let Some(runtime) = self.mcp_runtime.as_ref() {
            if let Err(error) = runtime.manager.write().await.disconnect_all().await {
                tracing::warn!(%error, "failed to disconnect MCP servers during TUI shutdown");
            }
        }
        if let Ok(run_context) = self.run_context.as_ref() {
            crate::tools::retire_run(run_context);
        }
        outcome
    }

    /// Process one async event from the event loop. Returns `false` when the loop should stop.
    #[allow(clippy::too_many_lines)]
    fn handle_app_event(&mut self, event: Result<AppEvent, std::sync::mpsc::RecvError>) -> bool {
        match event {
            Ok(AppEvent::Correlated { call_id, event }) => {
                return self.handle_correlated_event(call_id, *event);
            }
            Ok(AppEvent::Key(key)) => self.handle_key(key),
            Ok(AppEvent::Paste(text)) => self.handle_paste(&text),
            Ok(AppEvent::Tick) => {
                self.spinner_frame = (self.spinner_frame + 1) % SPINNER_FRAMES.len();
                self.handle_keybinding_timeout();
            }
            Ok(AppEvent::StreamText(text)) => {
                self.messages.finish_thinking();
                self.append_streaming_for_display(&text);
                self.messages.scroll_to_bottom();
            }
            Ok(AppEvent::StreamThinking(text)) => {
                self.messages.push_thinking(&text);
                self.messages.scroll_to_bottom();
            }
            Ok(AppEvent::ToolStart { name, description }) => {
                // Any buffered model text belonged to a tool-bearing turn,
                // not a validated terminal response.
                self.messages.finish_streaming();
                self.streaming_raw_text.clear();
                self.messages.add(DisplayMessage {
                    kind: MessageKind::ToolStart { name },
                    content: description,
                });
            }
            Ok(AppEvent::ToolDone {
                name,
                success,
                content,
            }) => {
                let preview = if content.len() > 300 {
                    format!("{}...", crate::tools::safe_truncate(&content, 297))
                } else {
                    content
                };
                self.messages.add(DisplayMessage {
                    kind: if success {
                        MessageKind::ToolOk { name }
                    } else {
                        MessageKind::ToolErr { name }
                    },
                    content: preview,
                });
            }
            Ok(AppEvent::WorkspaceTransition { run_context }) => {
                self.apply_workspace_run_transition(&run_context);
            }
            Ok(AppEvent::ResponseDone) => self.handle_response_done(),
            Ok(AppEvent::ApiError(msg)) => self.handle_api_error(msg.as_str()),
            Ok(AppEvent::PluginAgentDone { label, result }) => {
                self.handle_plugin_agent_done(&label, &result);
            }
            Ok(AppEvent::ApiRetry {
                kind,
                attempt,
                max_attempts,
                delay_ms,
                status,
            }) => {
                self.messages
                    .add(DisplayMessage::system(format_api_retry_message(
                        kind,
                        attempt,
                        max_attempts,
                        delay_ms,
                        status,
                    )));
                self.messages.scroll_to_bottom();
            }
            Ok(AppEvent::StreamTimeout {
                elapsed_secs,
                timeout_secs,
            }) => {
                self.messages
                    .add(DisplayMessage::system(format_stream_timeout_message(
                        elapsed_secs,
                        timeout_secs,
                    )));
                self.messages.scroll_to_bottom();
            }
            Ok(AppEvent::Resize(_, _)) => {}
            Ok(AppEvent::FollowUp) => {
                self.spawn_api_turn();
            }
            Ok(AppEvent::SyncSession {
                session_id,
                messages,
                provider_native_state,
            }) => {
                if self.chat_session.id() != session_id {
                    tracing::warn!(
                        current_session_id = %self.chat_session.id(),
                        response_session_id = %session_id,
                        "ignored provider continuation for a session that is no longer active"
                    );
                } else if let Err(error) = self
                    .chat_session
                    .replace_messages_and_provider_native_state(messages, provider_native_state)
                {
                    self.messages.add(DisplayMessage::error(format!(
                        "Provider continuation was not committed: {error}"
                    )));
                    self.is_waiting = false;
                }
            }
            Ok(AppEvent::PermissionRequest {
                tool_name,
                tool_args,
                reply,
            }) => {
                self.cancel_pending_keybinding();
                self.pending_permission = Some(PendingPermission {
                    tool_name,
                    tool_args,
                    reply,
                });
            }
            Ok(AppEvent::UserQuestion { questions, reply }) => {
                self.cancel_pending_keybinding();
                // Surface the modal. The pipeline interceptor parks on
                // the reply oneshot and resumes once the user walks
                // every question; on Escape the modal drops `reply`
                // and the interceptor surfaces `_cancelled: true` to
                // the agent.
                self.pending_user_question = Some(PendingUserQuestion {
                    questions,
                    current_index: 0,
                    input_buffer: String::new(),
                    answers: serde_json::Map::new(),
                    other_mode: false,
                    reply,
                });
            }
            Ok(AppEvent::PlanModeRequest { request, reply }) => {
                self.cancel_pending_keybinding();
                self.handle_plan_mode_request(request, reply);
            }
            Ok(AppEvent::ShellDone {
                target,
                stdout,
                stderr,
                exit_code,
            }) => {
                self.handle_shell_done(target, &stdout, &stderr, exit_code);
            }
            Ok(AppEvent::OverloadFallback { model_hint }) => {
                self.handle_overload_fallback(&model_hint);
            }
            Ok(AppEvent::ProviderSwitchReady(switch)) => {
                self.apply_provider_switch(*switch);
            }
            Ok(AppEvent::ProviderSwitchError(msg)) => {
                self.messages.add(DisplayMessage::error(format!(
                    "Provider switch failed: {msg}"
                )));
            }
            Ok(AppEvent::ModelListReady {
                provider,
                current_model,
                models,
                source,
                fallback_note,
            }) => {
                self.messages.add(DisplayMessage::system(format_model_list(
                    &provider,
                    &current_model,
                    &models,
                    &source,
                    fallback_note.as_deref(),
                )));
                self.messages.scroll_to_bottom();
            }
            Ok(AppEvent::ModelListError {
                provider,
                message,
                fallback_models,
            }) => {
                self.messages.add(DisplayMessage::system(format_model_list(
                    &provider,
                    &self.model,
                    &fallback_models,
                    "fallback catalog",
                    Some(&format!("Dynamic model fetch failed: {message}")),
                )));
                self.messages.scroll_to_bottom();
            }
            Err(_) => return false,
        }
        true
    }

    /// Surface sustained upstream overload as advisory UI, without changing
    /// provider/model routing behind the user's back.
    fn handle_overload_fallback(&mut self, model_hint: &str) {
        let msg = if model_hint.is_empty() {
            "Upstream model is sustainedly overloaded (HTTP 529). \
             Consider waiting or switching to a lighter model."
                .to_string()
        } else {
            format!(
                "Upstream model is sustainedly overloaded (HTTP 529). \
                 Consider switching to '{model_hint}' for this session."
            )
        };
        self.messages.add(DisplayMessage::error(msg));
    }

    /// Finalise the turn when the orchestrator emits `ResponseDone` after its
    /// portable/native session commit.
    ///
    /// Extracted from `handle_app_event` to keep that dispatcher under
    /// the clippy `too_many_lines` threshold. Responsible for finishing
    /// any in-flight stream/thinking widgets, flushing the persisted
    /// chat session, refreshing the token estimate, and firing the
    /// Stop hook so external orchestrators get the round-trip signal.
    fn handle_response_done(&mut self) {
        self.finish_response_state();
        if let Ok(run_context) = self.run_context.as_ref().map(std::sync::Arc::clone) {
            self.fire_stop_hook_for_run(run_context, crate::runtime::CallId::new());
        }
    }

    fn handle_response_done_for_run(
        &mut self,
        run_context: std::sync::Arc<crate::tools::ToolRunContext>,
        call_id: crate::runtime::CallId,
    ) {
        self.finish_response_state();
        self.fire_stop_hook_for_run(run_context, call_id);
    }

    fn finish_response_state(&mut self) {
        self.cancel_pending_keybinding();
        self.messages.finish_thinking();
        self.prepare_streaming_final_for_display();
        self.messages.finish_streaming();
        self.streaming_raw_text.clear();
        self.is_waiting = false;
        self.chat_session.update_title();
        self.chat_session.touch();
        let _ = self.chat_session.refresh_estimated_tokens();
        self.persist_session();
    }

    fn handle_api_error(&mut self, error: &str) {
        self.finish_api_error_state(error);
        if let Ok(run_context) = self.run_context.as_ref().map(std::sync::Arc::clone) {
            self.fire_notification_hook_for_run(
                run_context,
                crate::runtime::CallId::new(),
                &format!("API error: {error}"),
                "error",
            );
        }
        self.active_turn_hook_engine = None;
    }

    fn handle_api_error_for_run(
        &mut self,
        error: &str,
        run_context: std::sync::Arc<crate::tools::ToolRunContext>,
        call_id: crate::runtime::CallId,
    ) {
        self.finish_api_error_state(error);
        self.fire_notification_hook_for_run(
            run_context,
            call_id,
            &format!("API error: {error}"),
            "error",
        );
        self.active_turn_hook_engine = None;
    }

    fn finish_api_error_state(&mut self, error: &str) {
        self.cancel_pending_keybinding();
        self.preserve_failed_stream_for_display();
        self.messages
            .add(DisplayMessage::error(format!("Error: {error}")));
        self.is_waiting = false;
    }

    fn handle_plugin_agent_done(&mut self, label: &str, result: &crate::subagent::SubagentResult) {
        self.cancel_pending_keybinding();
        self.is_waiting = false;
        self.active_turn_hook_engine = None;
        if result.success {
            self.messages
                .add(DisplayMessage::assistant(result.output.clone()));
            self.chat_session.push_message(serde_json::json!({
                "role": "assistant",
                "content": result.output,
            }));
        } else {
            self.messages.add(DisplayMessage::error(format!(
                "Plugin agent {label} failed: {}",
                result.output
            )));
            self.chat_session.push_message(serde_json::json!({
                "role": "system",
                "content": format!("Plugin agent {label} failed: {}", result.output),
            }));
        }
        self.chat_session.touch();
        self.persist_session();
    }

    fn preserve_failed_stream_for_display(&mut self) {
        let partial = std::mem::take(&mut self.streaming_raw_text);
        self.messages.finish_thinking();
        self.messages.finish_streaming();
        if partial.trim().is_empty() {
            return;
        }
        self.messages.add(DisplayMessage::system(format!(
            "Partial provider response (not saved to conversation history):\n{}",
            crate::tools::safe_truncate(&partial, 4_000)
        )));
    }

    fn prepare_streaming_final_for_display(&mut self) {
        if !self.messages.is_streaming
            || (self.messages.streaming_text.trim().is_empty()
                && self.streaming_raw_text.trim().is_empty())
        {
            return;
        }
        let content = if self.streaming_raw_text.is_empty() {
            self.messages.streaming_text.clone()
        } else {
            self.streaming_raw_text.clone()
        };
        let Ok(run_context) = self.tool_run_context() else {
            self.messages.streaming_text.clear();
            return;
        };
        match render_live_final_response_for_display(
            &run_context,
            &self.chat_session.id(),
            &content,
            &self.model,
        ) {
            Some(rendered) => self.messages.streaming_text = rendered,
            None => self.messages.streaming_text.clear(),
        }
    }

    fn append_streaming_for_display(&mut self, text: &str) {
        self.streaming_raw_text.push_str(text);
        // Terminal-vs-tool-bearing output is unknown during streaming. Buffer
        // it until ResponseDone can run the evidence gate; ToolStart discards
        // text from a non-terminal iteration.
        self.messages.streaming_text.clear();
        self.messages.is_streaming = true;
    }

    /// Render the result of a backgrounded shell call dispatched via
    /// [`Self::spawn_shell`]. Closes crosslink #371: the same rendering
    /// logic that used to live inline next to a blocking `.output()` call
    /// now runs on the UI thread *after* the child has exited on the
    /// tokio runtime, so the event loop never stalls.
    fn handle_shell_done(
        &mut self,
        target: SpawnTarget,
        stdout: &str,
        stderr: &str,
        exit_code: Option<i32>,
    ) {
        match target {
            SpawnTarget::Diff => {
                let content = if exit_code.is_none() {
                    format!("Failed to run git diff: {stderr}")
                } else if stdout.is_empty() {
                    "No uncommitted changes.".to_string()
                } else {
                    format!("Uncommitted changes:\n{stdout}")
                };
                self.messages.add(DisplayMessage::system(content));
            }
            SpawnTarget::Review => {
                let content = if exit_code.is_none() {
                    format!("Failed to run git diff: {stderr}")
                } else if stdout.is_empty() {
                    "No changes to review.".to_string()
                } else {
                    let total = stdout.lines().count();
                    let lines: Vec<&str> = stdout.lines().take(100).collect();
                    if total > 100 {
                        format!("{}\n... (truncated, {total} total lines)", lines.join("\n"))
                    } else {
                        lines.join("\n")
                    }
                };
                self.messages.add(DisplayMessage::system(content));
            }
            SpawnTarget::Init => {
                let content = if exit_code.is_none() {
                    format!("Init failed: {stderr}")
                } else {
                    stdout.to_string()
                };
                self.messages.add(DisplayMessage::system(content));
            }
            SpawnTarget::Files | SpawnTarget::Doctor => {
                // Reserved for follow-up #371 migration — these branches are
                // not yet routed through spawn_shell (they don't invoke a
                // child process today), so receiving one is a logic bug
                // rather than user-visible state. Render defensively.
                let content = if exit_code.is_none() {
                    format!("Command failed: {stderr}")
                } else {
                    stdout.to_string()
                };
                self.messages.add(DisplayMessage::system(content));
            }
            SpawnTarget::ShellCommand { displayed } => {
                let success = matches!(exit_code, Some(0));
                let mut result = String::new();
                if !stdout.is_empty() {
                    result.push_str(stdout);
                }
                if !stderr.is_empty() {
                    if !result.is_empty() {
                        result.push('\n');
                    }
                    result.push_str(stderr);
                }
                let header = format!("$ {displayed}");
                if exit_code.is_none() {
                    if result.is_empty() {
                        result = "command failed without diagnostic output".to_string();
                    }
                    self.messages.add(DisplayMessage {
                        kind: MessageKind::ToolErr { name: header },
                        content: format!("Failed: {result}"),
                    });
                    return;
                }
                if result.is_empty() {
                    result = "(no output)".to_string();
                }
                self.messages.add(DisplayMessage {
                    kind: if success {
                        MessageKind::ToolOk { name: header }
                    } else {
                        MessageKind::ToolErr { name: header }
                    },
                    content: result,
                });
            }
        }
    }

    /// Three explicit modes share the keyboard (crosslink #364):
    ///
    /// * [`KeyMode::Modal`] — an overlay (help, log selector) is open; it
    ///   owns every keystroke until it returns `OverlayAction::Close`.
    /// * [`KeyMode::Streaming`] — a model response is in flight. Only
    ///   `Escape` (cancel) and `Ctrl+C` are meaningful; every other key is
    ///   dropped.
    /// * [`KeyMode::Normal`] — interactive editing. Text input, scrolling,
    ///   slash-command dispatch live here.
    ///
    /// The permission prompt is a sub-state of Normal mode (it overlays
    /// the input line but does not block scrolling), so it stays inside
    /// the Normal-mode dispatcher.
    ///
    /// Important: a pending permission prompt always wins over the
    /// streaming check. The pipeline emits `PermissionRequest` mid-turn
    /// while `is_waiting == true`; if we routed to Streaming we'd drop
    /// the y/n/a/d keystrokes the user needs to unblock the prompt
    /// (and through it, the entire agent turn).
    const fn current_key_mode(&self) -> KeyMode {
        if self.overlay.is_some() {
            KeyMode::Modal
        } else if self.pending_permission.is_some()
            || self.pending_user_question.is_some()
            || self.pending_plan_approval.is_some()
        {
            // Interactive permission, question, and plan decisions win over
            // the streaming check — they arrive mid-turn while
            // `is_waiting == true`, and the user MUST be able to type
            // y/n/a/d (permission) or numeric option indices
            // (ask_user_question) to unblock the pipeline. Without this
            // routing the streaming dispatcher would silently drop
            // every key.
            KeyMode::Normal
        } else if self.is_waiting {
            KeyMode::Streaming
        } else {
            KeyMode::Normal
        }
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        // The global Ctrl+C interrupt is the single keystroke that
        // crosses every mode boundary: it dismisses overlays, cancels
        // streaming, denies a pending permission prompt, and quits the
        // app. Order-of-precedence is checked first to keep the
        // mode-specific dispatchers focused on their own responsibilities.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.handle_global_ctrl_c();
            return;
        }

        match self.current_key_mode() {
            KeyMode::Modal => {
                if let Some(replay) =
                    self.resolve_configured_key(key, crate::keybindings::KeyContext::Help)
                {
                    for event in replay {
                        self.handle_unbound_key(event);
                    }
                } else {
                    self.handle_key_modal(key);
                }
            }
            KeyMode::Streaming => self.handle_key_streaming(key),
            KeyMode::Normal => self.handle_key_normal(key),
        }
    }

    /// Feed a real terminal event into the configured resolver. `None` means
    /// crossterm cannot represent the event in the configuration grammar;
    /// `Some` contains ordinary events that must be replayed after resolution.
    fn resolve_configured_key(
        &mut self,
        key: KeyEvent,
        context: crate::keybindings::KeyContext,
    ) -> Option<Vec<KeyEvent>> {
        self.sync_keybindings();
        let parsed = crate::keybindings::ParsedKeystroke::from_key_event(&key)?;
        self.pending_key_events.push(key);
        let result = self.keybinding_resolver.resolve_in_context(context, parsed);
        let replay_count = self.keybinding_resolver.take_replay().len();
        match result {
            crate::keybindings::ChordResolveResult::Prefix => Some(Vec::new()),
            crate::keybindings::ChordResolveResult::Match { action } => {
                let replay = self.take_pending_key_replay(replay_count);
                self.dispatch_keybinding_action(&action, context);
                Some(replay)
            }
            crate::keybindings::ChordResolveResult::NoMatch => {
                Some(self.take_pending_key_replay(replay_count))
            }
        }
    }

    fn take_pending_key_replay(&mut self, replay_count: usize) -> Vec<KeyEvent> {
        let split_at = self
            .pending_key_events
            .len()
            .saturating_sub(replay_count.min(self.pending_key_events.len()));
        let replay = self.pending_key_events.split_off(split_at);
        self.pending_key_events.clear();
        replay
    }

    fn handle_keybinding_timeout(&mut self) {
        let Some(result) = self.keybinding_resolver.resolve_timeout() else {
            return;
        };
        let context = if self.overlay.is_some() {
            crate::keybindings::KeyContext::Help
        } else if self.pending_permission.is_some()
            || self.pending_user_question.is_some()
            || self.pending_plan_approval.is_some()
        {
            crate::keybindings::KeyContext::Confirmation
        } else if self.is_waiting {
            crate::keybindings::KeyContext::Streaming
        } else {
            crate::keybindings::KeyContext::Chat
        };
        let replay_count = self.keybinding_resolver.take_replay().len();
        let replay = self.take_pending_key_replay(replay_count);
        if let crate::keybindings::ChordResolveResult::Match { action } = result {
            self.dispatch_keybinding_action(&action, context);
        }
        for event in replay {
            self.handle_unbound_key(event);
        }
    }

    fn dispatch_keybinding_action(
        &mut self,
        action: &crate::keybindings::KeyAction,
        context: crate::keybindings::KeyContext,
    ) {
        if *action == crate::keybindings::KeyAction::None {
            return;
        }
        if *action == crate::keybindings::KeyAction::Cancel {
            match context {
                crate::keybindings::KeyContext::Streaming => self.cancel_streaming_response(),
                crate::keybindings::KeyContext::Confirmation => {
                    self.cancel_pending_confirmation();
                }
                crate::keybindings::KeyContext::Help => self.overlay = None,
                _ => {}
            }
            return;
        }
        if !tui_supports_key_action(action) {
            self.messages.add(DisplayMessage::error(format!(
                "{} is not available in the full-screen TUI",
                action.description()
            )));
            return;
        }
        if let Some(command) = action.command_name() {
            self.handle_input(format!("/{command}"));
        }
    }

    /// Replay a key without passing through the chord resolver again. The
    /// current modal state is re-read because an exact-prefix fallback may
    /// have opened an overlay before the mismatching event is replayed.
    fn handle_unbound_key(&mut self, key: KeyEvent) {
        match self.current_key_mode() {
            KeyMode::Modal => self.handle_key_modal(key),
            KeyMode::Streaming => self.handle_streaming_key_unbound(key),
            KeyMode::Normal if self.pending_permission.is_some() => {
                self.handle_permission_key(key);
            }
            KeyMode::Normal if self.pending_user_question.is_some() => {
                self.handle_user_question_key(key);
            }
            KeyMode::Normal if self.pending_plan_approval.is_some() => {
                self.handle_plan_approval_key(key);
            }
            KeyMode::Normal => self.handle_editing_key(key),
        }
    }

    fn handle_paste(&mut self, text: &str) {
        if self.overlay.is_some()
            || self.is_waiting
            || self.pending_permission.is_some()
            || self.pending_user_question.is_some()
            || self.pending_plan_approval.is_some()
        {
            return;
        }

        self.keybinding_resolver.cancel();
        let pending = std::mem::take(&mut self.pending_key_events);
        for event in pending {
            self.handle_unbound_key(event);
        }
        if self.overlay.is_some() || self.is_waiting {
            return;
        }
        self.input.insert_str(text);
    }

    /// Handle the universal Ctrl+C interrupt. Distinct from the per-mode
    /// dispatchers because Ctrl+C is the single cross-mode keystroke —
    /// it must deny a pending permission prompt before quitting, and it
    /// must close overlays cleanly. Centralising the precedence here is
    /// what lets [`handle_key_modal`] / [`handle_key_streaming`] /
    /// [`handle_key_normal`] each handle one shape without re-asserting
    /// the global escape hatch.
    fn handle_global_ctrl_c(&mut self) {
        self.cancel_pending_keybinding();
        // If permission prompt is active, deny and dismiss without quitting.
        if let Some(perm) = self.pending_permission.take() {
            let _ = perm.reply.send(super::events::PermissionResponse::Deny);
            self.cancel_streaming_response();
            return;
        }
        // If an ask_user_question modal is active, cancel it (drop the
        // reply sender; the pipeline interceptor surfaces a structured
        // `_cancelled: true` to the agent instead of hanging).
        if let Some(pq) = self.pending_user_question.take() {
            drop(pq.reply);
            self.messages.add(DisplayMessage::system(
                "ask_user_question cancelled".to_string(),
            ));
            self.cancel_streaming_response();
            return;
        }
        if let Some(plan) = self.pending_plan_approval.take() {
            let message = "Plan approval cancelled by user".to_string();
            let _ = plan.reply.send(PlanModeReply::Cancelled {
                message: message.clone(),
            });
            self.messages.add(DisplayMessage::system(message));
            self.cancel_streaming_response();
            return;
        }
        // If an overlay is open, close it instead of quitting — matches
        // the pre-#364 behaviour where overlay handling ran before the
        // global Ctrl+C check (so the overlay could swallow it).
        if self.overlay.is_some() {
            self.overlay = None;
            return;
        }
        if self.active_turn.is_some() {
            self.cancel_streaming_response();
        }
        self.should_quit = true;
    }

    /// Modal-mode keystrokes: an overlay owns the input. The keystroke
    /// is forwarded to the active overlay, and its `OverlayAction`
    /// return value drives state changes on the App. This is the only
    /// path that may transition out of `KeyMode::Modal`.
    fn handle_key_modal(&mut self, key: crossterm::event::KeyEvent) {
        use super::components::{Overlay as _, OverlayAction};
        let Some(overlay) = self.overlay.as_mut() else {
            // The mode dispatcher only routes here when an overlay is
            // active, but the explicit early-return keeps this method
            // independently safe to call from tests.
            return;
        };
        let action = match overlay {
            ActiveOverlay::Help(o) => o.handle_key(key),
            ActiveOverlay::LogSelector(o) => o.handle_key(key),
        };
        match action {
            OverlayAction::Consumed => {}
            OverlayAction::Close => {
                self.overlay = None;
            }
            OverlayAction::ResumeSession(id) => {
                self.overlay = None;
                self.resume_session_by_id(&id);
            }
        }
    }

    /// Streaming-mode keystrokes: an API turn is in flight. Only
    /// `Escape` (cancel the stream and re-enable input) is meaningful;
    /// every other key is silently dropped so the user cannot accidentally
    /// type into the input line while a response is being rendered. The
    /// global Ctrl+C handler in [`handle_global_ctrl_c`] still applies.
    fn handle_key_streaming(&mut self, key: crossterm::event::KeyEvent) {
        if let Some(replay) =
            self.resolve_configured_key(key, crate::keybindings::KeyContext::Streaming)
        {
            for event in replay {
                self.handle_unbound_key(event);
            }
            return;
        }
        self.handle_streaming_key_unbound(key);
    }

    fn handle_streaming_key_unbound(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.cancel_streaming_response();
        }
    }

    fn cancel_streaming_response(&mut self) {
        self.cancel_pending_keybinding();
        let Some(turn) = self.active_turn.as_mut() else {
            self.is_waiting = false;
            self.messages.finish_streaming();
            self.streaming_raw_text.clear();
            self.active_turn_hook_engine = None;
            self.messages
                .add(DisplayMessage::system("[Response interrupted]"));
            return;
        };
        turn.terminal.get_or_insert(ActiveTurnTerminal::Cancelled(
            crate::runtime::CancellationReason::User,
        ));
        self.cancel_active_turn_resources(&crate::runtime::CancellationReason::User);
        self.messages
            .add(DisplayMessage::system("[Cancelling response…]"));
    }

    /// Normal-mode keystrokes: interactive editing. Permission, question,
    /// and plan-decision walking are sub-states because the
    /// prompt / modal overlays the input line without taking the App
    /// into modal-overlay state.
    fn handle_key_normal(&mut self, key: crossterm::event::KeyEvent) {
        if self.pending_permission.is_some()
            || self.pending_user_question.is_some()
            || self.pending_plan_approval.is_some()
        {
            if let Some(replay) =
                self.resolve_configured_key(key, crate::keybindings::KeyContext::Confirmation)
            {
                for event in replay {
                    self.handle_unbound_key(event);
                }
                return;
            }
            self.handle_unbound_key(key);
            return;
        }
        if let Some(replay) = self.resolve_configured_key(key, crate::keybindings::KeyContext::Chat)
        {
            for event in replay {
                self.handle_unbound_key(event);
            }
            return;
        }
        self.handle_editing_key(key);
    }

    fn cancel_pending_confirmation(&mut self) {
        if self.pending_permission.is_some() {
            self.handle_permission_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        } else if self.pending_user_question.is_some() {
            self.handle_user_question_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        } else if self.pending_plan_approval.is_some() {
            self.handle_plan_approval_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        }
    }

    /// Dispatch keystrokes when a permission prompt is active.
    fn handle_permission_key(&mut self, key: crossterm::event::KeyEvent) {
        use super::events::PermissionResponse;
        let response = match key.code {
            KeyCode::Char('y' | 'Y') => Some(PermissionResponse::Allow),
            KeyCode::Char('n' | 'N') | KeyCode::Esc => Some(PermissionResponse::Deny),
            KeyCode::Char('a' | 'A') => Some(PermissionResponse::AlwaysAllow),
            KeyCode::Char('d' | 'D') => Some(PermissionResponse::AlwaysDeny),
            _ => None,
        };
        if let Some(resp) = response {
            let cancelled = key.code == KeyCode::Esc;
            if let Some(perm) = self.pending_permission.take() {
                let label = match resp {
                    PermissionResponse::Allow => "Allowed",
                    PermissionResponse::AlwaysAllow => "Always allowed",
                    PermissionResponse::Deny => "Denied",
                    PermissionResponse::AlwaysDeny => "Always denied",
                };
                let denied = matches!(
                    resp,
                    PermissionResponse::Deny | PermissionResponse::AlwaysDeny
                );
                let content = format!("{label}: {}", perm.tool_name);
                self.messages.add(if denied {
                    DisplayMessage::error(content)
                } else {
                    DisplayMessage::system(content)
                });
                let _ = perm.reply.send(resp);
            }
            if cancelled {
                self.cancel_streaming_response();
            }
        }
    }

    /// Dispatch keystrokes for a digest-bound plan approval modal.
    fn handle_plan_approval_key(&mut self, key: crossterm::event::KeyEvent) {
        match key.code {
            KeyCode::Char('y' | 'Y') => self.finish_plan_approval(true),
            KeyCode::Char('n' | 'N') => self.finish_plan_approval(false),
            KeyCode::Esc => {
                if let Some(plan) = self.pending_plan_approval.take() {
                    let message = "Plan approval cancelled by user".to_string();
                    let _ = plan.reply.send(PlanModeReply::Cancelled {
                        message: message.clone(),
                    });
                    self.messages.add(DisplayMessage::system(message));
                }
                self.cancel_streaming_response();
            }
            KeyCode::Up => {
                if let Some(plan) = self.pending_plan_approval.as_mut() {
                    plan.scroll_offset = plan.scroll_offset.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                if let Some(plan) = self.pending_plan_approval.as_mut() {
                    plan.scroll_offset = plan.scroll_offset.saturating_add(1);
                }
            }
            KeyCode::PageUp => {
                if let Some(plan) = self.pending_plan_approval.as_mut() {
                    plan.scroll_offset = plan.scroll_offset.saturating_sub(10);
                }
            }
            KeyCode::PageDown => {
                if let Some(plan) = self.pending_plan_approval.as_mut() {
                    plan.scroll_offset = plan.scroll_offset.saturating_add(10);
                }
            }
            KeyCode::Home => {
                if let Some(plan) = self.pending_plan_approval.as_mut() {
                    plan.scroll_offset = 0;
                }
            }
            KeyCode::End => {
                if let Some(plan) = self.pending_plan_approval.as_mut() {
                    plan.scroll_offset = u16::try_from(
                        plan.prepared
                            .plan_content()
                            .lines()
                            .count()
                            .saturating_sub(1),
                    )
                    .unwrap_or(u16::MAX);
                }
            }
            _ => {}
        }
    }

    fn finish_plan_approval(&mut self, approved: bool) {
        let Some(plan) = self.pending_plan_approval.take() else {
            return;
        };
        if !approved {
            let message = "Plan rejected by user; remaining in plan mode".to_string();
            self.messages.add(DisplayMessage::system(message.clone()));
            let _ = plan.reply.send(PlanModeReply::Completed {
                message: message.clone(),
                response: serde_json::json!({"message": message, "approved": false}),
                context_message: None,
            });
            return;
        }

        let result = self.tool_run_context().and_then(|run| {
            crate::session::commit_interactive_plan_approval(
                &run,
                &self.chat_session,
                self.task_mgr.as_ref(),
                &plan.prepared,
                &plan.allowed_prompts,
                crate::modes::RuntimeMode::Behavioral(self.chat_session.behavior_mode()),
            )
        });
        match result {
            Ok(receipt) => {
                self.mode = tui_mode_for_agent(self.chat_session.agent_mode());
                let message = format!(
                    "Plan approved as digest {} and task {}; build capabilities restored",
                    receipt.plan_digest, receipt.task_id
                );
                self.messages.add(DisplayMessage::system(message.clone()));
                let response = serde_json::json!({
                    "message": message,
                    "approved": true,
                    "plan_digest": receipt.plan_digest,
                    "canonical_task_id": receipt.task_id,
                    "canonical_task_graph_generation": receipt.task_graph_generation,
                    "runtime_mode_generation": receipt.runtime_mode_generation
                });
                let _ = plan.reply.send(PlanModeReply::Completed {
                    message,
                    response,
                    context_message: Some(receipt.context_message),
                });
            }
            Err(error) => {
                let message = format!(
                    "Plan approval could not be committed: {error}; remaining in plan mode"
                );
                self.messages.add(DisplayMessage::error(message.clone()));
                let _ = plan.reply.send(PlanModeReply::Completed {
                    message: message.clone(),
                    response: serde_json::json!({
                        "message": message,
                        "approved": false,
                        "error": true
                    }),
                    context_message: None,
                });
            }
        }
    }

    /// Dispatch keystrokes when an `ask_user_question` modal is active.
    ///
    /// The modal walks the question set one entry at a time:
    /// * Character keys / Backspace edit the `input_buffer`.
    /// * Enter finalises the current question:
    ///   - Single-select: parse the buffer as `usize`, look up the
    ///     matching option (or the synthetic "Other" sentinel that's
    ///     always one past `options.len()`).
    ///   - Multi-select: split the buffer on commas and resolve each
    ///     token the same way.
    /// * Picking "Other" flips into `other_mode`, where the next Enter
    ///   commits the free-form text instead of resolving an option
    ///   index.
    /// * Escape cancels the entire modal — drops the reply sender so
    ///   the parked pipeline task receives a structured `_cancelled`
    ///   payload rather than hanging.
    ///
    /// When the last question is answered the accumulated `answers`
    /// map is serialised to JSON and sent on the reply oneshot,
    /// `pending_user_question` is cleared, and a one-line system
    /// message is added to the visible transcript so the user can see
    /// the modal completed.
    fn handle_user_question_key(&mut self, key: crossterm::event::KeyEvent) {
        // Escape cancels the whole modal.
        if key.code == KeyCode::Esc {
            if let Some(pq) = self.pending_user_question.take() {
                // Drop the reply sender — pipeline interceptor surfaces
                // the cancellation as `_cancelled: true` to the agent.
                drop(pq.reply);
                self.messages.add(DisplayMessage::system(
                    "ask_user_question cancelled".to_string(),
                ));
            }
            self.cancel_streaming_response();
            return;
        }

        match key.code {
            KeyCode::Char(c) => {
                if let Some(pq) = self.pending_user_question.as_mut() {
                    pq.input_buffer.push(c);
                }
            }
            KeyCode::Backspace => {
                if let Some(pq) = self.pending_user_question.as_mut() {
                    pq.input_buffer.pop();
                }
            }
            KeyCode::Enter => self.finalise_current_question(),
            _ => {}
        }
    }

    /// Finalise the active question. Extracted from
    /// [`handle_user_question_key`] to keep the key-dispatch path
    /// readable; encapsulates the single/multi-select + "Other"
    /// resolution logic, advances `current_index`, and on completion
    /// flushes the accumulated answers JSON back through the reply
    /// channel.
    fn finalise_current_question(&mut self) {
        let Some(pq) = self.pending_user_question.as_mut() else {
            return;
        };
        let Some(q) = pq.questions.get(pq.current_index).cloned() else {
            return;
        };
        let question_text = q
            .get("question")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let options = q
            .get("options")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        // Canonicalised key — `ask_user::normalize_question` already
        // rewrites the legacy `multi_select` to `multiSelect`.
        let multi_select = q
            .get("multiSelect")
            .or_else(|| q.get("multi_select"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let other_num = options.len() + 1;

        let input = std::mem::take(&mut pq.input_buffer);
        let was_other_mode = pq.other_mode;

        // "Other" follow-up commit: take whatever the user typed
        // verbatim (single-select) or append to the in-progress
        // multi-select list (multi-select).
        if was_other_mode {
            pq.other_mode = false;
            let trimmed = input.trim().to_string();
            if multi_select {
                let existing = pq
                    .answers
                    .entry(question_text)
                    .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                if let serde_json::Value::Array(arr) = existing {
                    arr.push(serde_json::Value::String(trimmed));
                }
            } else {
                pq.answers
                    .insert(question_text, serde_json::Value::String(trimmed));
            }
            self.advance_or_finish_question();
            return;
        }

        if multi_select {
            let mut selected: Vec<serde_json::Value> = Vec::new();
            let mut other_pending = false;
            for part in input.split(',') {
                let part = part.trim();
                if let Ok(num) = part.parse::<usize>() {
                    if num >= 1 && num <= options.len() {
                        if let Some(opt) = options.get(num - 1) {
                            let label = opt.get("label").and_then(|v| v.as_str()).unwrap_or("?");
                            selected.push(serde_json::Value::String(label.to_string()));
                        }
                    } else if num == other_num {
                        other_pending = true;
                    }
                }
            }
            pq.answers
                .insert(question_text, serde_json::Value::Array(selected));
            if other_pending {
                pq.other_mode = true;
                return; // wait for free-form follow-up
            }
        } else if let Ok(num) = input.trim().parse::<usize>() {
            if num >= 1 && num <= options.len() {
                if let Some(opt) = options.get(num - 1) {
                    let label = opt.get("label").and_then(|v| v.as_str()).unwrap_or("?");
                    pq.answers
                        .insert(question_text, serde_json::Value::String(label.to_string()));
                }
            } else if num == other_num {
                pq.other_mode = true;
                return; // wait for free-form follow-up
            } else {
                // Out-of-range numeric input — treat the raw text as the
                // answer (parity with the REPL `else` branch).
                pq.answers
                    .insert(question_text, serde_json::Value::String(input));
            }
        } else {
            // Non-numeric input → treat as free-form answer (REPL parity).
            pq.answers
                .insert(question_text, serde_json::Value::String(input));
        }

        self.advance_or_finish_question();
    }

    /// Advance to the next question, or — if every question has been
    /// answered — serialise the accumulated answer map and ship it
    /// back through the reply oneshot.
    fn advance_or_finish_question(&mut self) {
        let Some(pq) = self.pending_user_question.as_mut() else {
            return;
        };
        pq.current_index += 1;
        if pq.current_index >= pq.questions.len() {
            // Take ownership so we can move `reply` out of the struct.
            if let Some(done) = self.pending_user_question.take() {
                let payload = serde_json::Value::Object(done.answers).to_string();
                let _ = done.reply.send(payload);
                self.messages.add(DisplayMessage::system(
                    "ask_user_question answered".to_string(),
                ));
            }
        }
    }

    /// Dispatch keystrokes for normal editing / streaming-cancel.
    fn handle_editing_key(&mut self, key: crossterm::event::KeyEvent) {
        // During streaming, Escape cancels
        if self.is_waiting {
            if key.code == KeyCode::Esc {
                self.cancel_streaming_response();
            }
            return;
        }

        match key.code {
            KeyCode::Enter if inserts_newline(key.modifiers) => self.input.insert_newline(),
            KeyCode::Enter if !self.input.is_empty() => {
                let text = self.input.take();
                self.handle_input(text);
            }
            KeyCode::Char('j' | 'J') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.input.insert_newline();
            }
            KeyCode::Char('\n' | '\r') => self.input.insert_newline(),
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.input.insert(c);
            }
            KeyCode::Backspace => self.input.backspace(),
            KeyCode::Delete => self.input.delete(),
            KeyCode::Left => self.input.move_left(),
            KeyCode::Right => self.input.move_right(),
            KeyCode::Home => self.input.home(),
            KeyCode::End => self.input.end(),
            KeyCode::Up => self.messages.scroll_up(3),
            KeyCode::Down => self.messages.scroll_down(3),
            KeyCode::PageUp => self.messages.scroll_up(15),
            KeyCode::PageDown => self.messages.scroll_down(15),
            _ => {}
        }
    }

    /// Handle user input: dispatch to slash commands, shell commands, or API.
    fn handle_input(&mut self, text: String) {
        // Shell commands: !command
        if let Some(cmd) = text.strip_prefix('!') {
            self.handle_shell_command(cmd.trim());
            return;
        }

        // Slash commands: /command
        if text.starts_with('/') || text == "?" {
            if self.handle_slash_command(&text) {
                return;
            }
            // Unknown command — fall through handled inside handle_slash_command
            return;
        }

        // Normal message → send to API
        self.send_user_message(text);
    }

    /// Handle session-management slash commands. Returns true if handled.
    fn handle_session_slash(&mut self, text: &str) -> bool {
        if text == "/sessions" || text == "/list" {
            let sessions = list_sessions();
            if sessions.is_empty() {
                self.messages
                    .add(DisplayMessage::system("No saved sessions."));
            } else {
                let list = sessions
                    .iter()
                    .take(10)
                    .map(|s| {
                        format!(
                            "  {} — {} ({})",
                            crate::tools::safe_truncate(&s.id(), 8),
                            s.title,
                            s.updated_at.format("%Y-%m-%d %H:%M")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                self.messages.add(DisplayMessage::system(format!(
                    "Saved sessions:\n{list}\n\nUse /load <id> to resume."
                )));
            }
            return true;
        }
        if text.starts_with("/load ") || text.starts_with("/continue ") {
            let id = text.split_whitespace().nth(1).unwrap_or("");
            self.resume_session_by_id(id);
            return true;
        }
        if text == "/rewind" || text.starts_with("/rewind ") {
            self.handle_rewind(text);
            return true;
        }
        if text == "/undo" {
            if self.chat_session.undo() {
                if self.messages.len() >= 2 {
                    self.messages.pop_last(2);
                }
                self.messages
                    .add(DisplayMessage::system("Undone last message pair."));
                self.persist_session();
            } else {
                self.messages
                    .add(DisplayMessage::system("Nothing to undo."));
            }
            return true;
        }
        if text == "/redo" {
            if self.chat_session.redo() {
                self.messages
                    .add(DisplayMessage::system("Redone last undone messages."));
                self.persist_session();
            } else {
                self.messages
                    .add(DisplayMessage::system("Nothing to redo."));
            }
            return true;
        }
        false
    }

    /// Handle /rewind subcommand.
    fn handle_rewind(&mut self, text: &str) {
        use std::fmt::Write as _;
        let arg = text.strip_prefix("/rewind").unwrap_or("").trim();
        if arg.is_empty() {
            let mut turn_list = String::new();
            let mut turn_num = 0;
            for msg in self.chat_session.messages_snapshot() {
                if msg.get("role").and_then(|r| r.as_str()) == Some("user") {
                    turn_num += 1;
                    let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
                    let preview = if content.len() > 60 {
                        format!("{}...", crate::tools::safe_truncate(content, 57))
                    } else {
                        content.to_string()
                    };
                    let _ = writeln!(turn_list, "  {turn_num}. {preview}");
                }
            }
            if turn_list.is_empty() {
                turn_list = "  (no conversation turns yet)\n".to_string();
            }
            self.messages.add(DisplayMessage::system(format!("Conversation has {turn_num} turn(s):\n{turn_list}\nUse /rewind N to undo the last N turns.")));
        } else if let Ok(n) = arg.parse::<usize>() {
            if n == 0 {
                self.messages
                    .add(DisplayMessage::system("Nothing to rewind (0 turns)."));
            } else {
                let mut rewound = 0;
                for _ in 0..n {
                    if self.chat_session.undo() {
                        rewound += 1;
                    } else {
                        break;
                    }
                }
                if rewound > 0 {
                    let to_remove = rewound * 2;
                    if self.messages.len() >= to_remove {
                        self.messages.pop_last(to_remove);
                    }
                    self.messages.add(DisplayMessage::system(format!(
                        "Rewound {rewound} turn(s)."
                    )));
                    self.persist_session();
                } else {
                    self.messages
                        .add(DisplayMessage::system("Nothing to rewind."));
                }
            }
        } else {
            self.messages.add(DisplayMessage::system(
                "Usage: /rewind [N] — rewind N turns, or show turn list",
            ));
        }
    }

    /// Handle /export and /effort slash commands. Returns true if handled.
    fn handle_export_effort_slash(&mut self, text: &str) -> bool {
        if text == "/export" {
            // Build the markdown body synchronously — needs `&self` and is
            // bounded by session size. The blocking part is the disk write,
            // which goes onto the tokio blocking-IO pool via spawn_fs
            // (crosslink #270). This unblocks the TUI redraw thread for the
            // duration of the `fs::write` syscall, which can stall on a
            // slow / network-mounted home directory.
            use std::fmt::Write as _;
            let mut md = format!("# {}\n\n", self.chat_session.title);
            let _ = write!(
                md,
                "Model: {} · Provider: {} · {}\n\n---\n\n",
                self.model,
                self.provider,
                self.chat_session.created_at.format("%Y-%m-%d %H:%M")
            );
            for msg in self.chat_session.messages_snapshot() {
                let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("?");
                let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
                if role == "system" {
                    continue;
                }
                let _ = write!(md, "**{role}:**\n{content}\n\n");
            }
            let export_path = format!(
                "conversation-{}.md",
                crate::tools::safe_truncate(&self.chat_session.id(), 8)
            );
            let path_for_render = export_path.clone();
            let run = self.run_context.as_ref().ok().cloned();
            self.spawn_fs(SpawnTarget::Files, move || {
                let run = run.ok_or_else(|| {
                    "Export failed: no active workspace-write capability".to_string()
                })?;
                crate::tools::create_capability_text_file(&run, &export_path, &md)
                    .map(|_| format!("Exported to {path_for_render}"))
                    .map_err(|error| format!("Export failed: {error}"))
            });
            return true;
        }
        if text.starts_with("/effort") {
            let parts: Vec<&str> = text.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let level = parts[1].trim();
                // FromStr for EffortLevel is Infallible; unknown strings map to Medium.
                self.chat_session
                    .set_effort_level(level.parse().unwrap_or(EffortLevel::Medium));
            } else {
                let effort = self
                    .chat_session
                    .effort_level()
                    .cycled_for_provider(&self.provider, &self.model);
                self.chat_session.set_effort_level(effort);
            }
            return true;
        }
        false
    }

    /// Parse and execute a slash command through the shared typed registry.
    /// Frontend-specific behavior remains on [`App`], but names, aliases,
    /// arguments, availability, capabilities, and lifecycle admission do not.
    fn handle_slash_command(&mut self, text: &str) -> bool {
        let registry = crate::command_registry::registry();
        let proposal = match registry.parse(text, crate::command_registry::CommandFrontend::Tui) {
            Ok(proposal) => proposal,
            Err(crate::command_registry::CommandParseError::NotACommand) => return false,
            Err(error) => {
                self.messages.add(DisplayMessage::error(error.to_string()));
                return true;
            }
        };
        let run = self.run_context.as_ref().ok().cloned();
        if let Err(error) = registry.execute(&proposal, run.as_deref(), |proposal| {
            self.dispatch_tui_proposed(proposal);
        }) {
            self.messages.add(DisplayMessage::error(error.to_string()));
        }
        true
    }

    // This exhaustive typed-handler match is intentionally kept together so a
    // new command cannot be silently omitted from TUI dispatch.
    #[allow(clippy::too_many_lines)]
    fn dispatch_tui_proposed(&mut self, proposal: &crate::command_registry::ProposedCommand) {
        use crate::command_registry::CommandId;

        let args = proposal.arguments_text();
        match proposal.id() {
            CommandId::Help => self.slash_help(),
            CommandId::New => self.slash_clear(),
            CommandId::Sessions => {
                self.handle_session_slash("/sessions");
            }
            CommandId::Continue => {
                if args.is_empty() {
                    self.slash_resume();
                } else {
                    self.resume_session_by_id(args);
                }
            }
            CommandId::Exit => self.slash_quit(),
            CommandId::Model => {
                let command = if proposal.invoked_name() == "models" {
                    "/models".to_string()
                } else if args.is_empty() {
                    "/model".to_string()
                } else {
                    format!("/model {args}")
                };
                self.handle_slash_model(&command);
            }
            CommandId::Export => {
                self.handle_export_effort_slash("/export");
            }
            CommandId::Undo => {
                self.handle_session_slash("/undo");
            }
            CommandId::Redo => {
                self.handle_session_slash("/redo");
            }
            CommandId::Rewind => {
                let command = if args.is_empty() {
                    "/rewind".to_string()
                } else {
                    format!("/rewind {args}")
                };
                self.handle_session_slash(&command);
            }
            CommandId::Copy => self.slash_copy(),
            CommandId::Init => self.handle_slash_init(),
            CommandId::Review => self.handle_slash_review(),
            CommandId::Status => self.slash_status(),
            CommandId::Plan | CommandId::Mode => self.slash_mode(),
            CommandId::Keybindings => self.slash_keybindings(),
            CommandId::Rename => {
                self.handle_info_slash(&format!("/rename {args}"));
            }
            CommandId::Doctor => self.handle_slash_doctor(),
            CommandId::Effort => {
                let command = if args.is_empty() {
                    "/effort".to_string()
                } else {
                    format!("/effort {args}")
                };
                self.handle_export_effort_slash(&command);
            }
            CommandId::Skill => {
                if args.is_empty() {
                    self.slash_skill_list();
                } else {
                    self.handle_info_slash(&format!("/skill {args}"));
                }
            }
            CommandId::Cost => self.handle_slash_cost(),
            CommandId::Context => {
                self.handle_diagnostic_slash("/context");
            }
            CommandId::Provider => {
                let command = if args.is_empty() {
                    "/provider".to_string()
                } else {
                    format!("/provider {args}")
                };
                self.handle_slash_provider(&command);
            }
            CommandId::Files => {
                let command = if args.is_empty() {
                    "/files".to_string()
                } else {
                    format!("/files {args}")
                };
                self.handle_slash_files(&command);
            }
            CommandId::Diff => self.handle_slash_diff(),
            CommandId::DynamicPlugin => {
                let namespace = proposal.namespace().unwrap_or_default();
                let component = proposal.component().unwrap_or_default();
                let namespaced_name = format!("{namespace}:{component}");
                if let Some(invocation) = self.resolve_plugin_turn(&namespaced_name, args) {
                    self.apply_plugin_turn(invocation);
                } else {
                    self.messages.add(DisplayMessage::error(format!(
                        "Plugin command /{namespaced_name} is unavailable."
                    )));
                }
            }
            CommandId::DirectSkill => {
                let name = proposal.component().unwrap_or_default();
                let command = if args.is_empty() {
                    format!("/{name}")
                } else {
                    format!("/{name} {args}")
                };
                self.handle_info_slash(&command);
            }
            CommandId::History
            | CommandId::Compact
            | CommandId::Editor
            | CommandId::Teleport
            | CommandId::Thinkback
            | CommandId::Connect
            | CommandId::Theme
            | CommandId::Vim
            | CommandId::Agents
            | CommandId::Version
            | CommandId::Config
            | CommandId::Mcp
            | CommandId::Permissions
            | CommandId::Hooks
            | CommandId::Debug
            | CommandId::Fast
            | CommandId::Find
            | CommandId::Memory
            | CommandId::Activity
            | CommandId::Plugin
            | CommandId::Commit
            | CommandId::CommitPushPr
            | CommandId::Login
            | CommandId::Logout
            | CommandId::AddDir
            | CommandId::Branch
            | CommandId::Btw => {
                self.messages.add(DisplayMessage::error(format!(
                    "Command /{} is unavailable in the full-screen TUI.",
                    proposal.invoked_name()
                )));
            }
        }
    }

    /// Table-handler entry point for `/quit` / `/exit`.
    const fn slash_quit(&mut self) {
        self.should_quit = true;
    }

    /// Table-handler entry point for `/help` and `?`.
    fn slash_help(&mut self) {
        self.open_help_overlay();
    }

    /// Table-handler entry point for `/resume` / `/continue` (no-arg form).
    fn slash_resume(&mut self) {
        self.open_log_selector();
    }

    /// Table-handler entry point for `/clear`.
    fn slash_clear(&mut self) {
        self.messages = MessageList::new();
        // Reset session but keep system prompt.
        self.chat_session.update_state(|state, events| {
            state.conversation.messages.retain(|message| {
                message.get("role").and_then(|role| role.as_str()) == Some("system")
            });
            events.push(crate::state::StateEvent::Cleared);
        });
    }

    /// Table-handler entry point for `/status`.
    fn slash_status(&mut self) {
        self.messages.add(DisplayMessage::system(format!(
            "Model: {}\nProvider: {}\nEffort: {}\nMessages: {}\n~{} tokens",
            self.model,
            self.provider,
            self.chat_session.effort_level(),
            self.chat_session.message_count(),
            self.chat_session.estimated_tokens(),
        )));
    }

    /// Copy the latest committed assistant message through the same command
    /// path used by `/copy` and a configured `copy_response` binding.
    fn slash_copy(&mut self) {
        let response = self
            .chat_session
            .messages_snapshot()
            .into_iter()
            .rev()
            .find(|message| {
                message.get("role").and_then(serde_json::Value::as_str) == Some("assistant")
            })
            .and_then(|message| {
                message
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            });
        let Some(response) = response else {
            self.messages
                .add(DisplayMessage::system("No assistant response to copy."));
            return;
        };
        match arboard::Clipboard::new().and_then(|mut clipboard| clipboard.set_text(response)) {
            Ok(()) => self
                .messages
                .add(DisplayMessage::system("Copied last response.")),
            Err(error) => self.messages.add(DisplayMessage::error(format!(
                "Could not copy the last response: {error}"
            ))),
        }
    }

    /// Render the collision-checked map actually reachable in normal TUI
    /// editing, rather than a second static shortcut table.
    fn slash_keybindings(&mut self) {
        self.sync_keybindings();
        let effective = self
            .keybinding_resolver
            .effective_bindings(crate::keybindings::KeyContext::Chat)
            .into_iter()
            .collect::<Vec<_>>();
        let mut lines = effective
            .iter()
            .filter(|(_, action)| tui_supports_key_action(action))
            .map(|(chord, action)| format!("  {chord:20} {}", action.description()))
            .collect::<Vec<_>>();
        if lines.is_empty() {
            lines.push("  (no reachable bindings)".to_string());
        }
        let unavailable = effective
            .iter()
            .filter(|(_, action)| !tui_supports_key_action(action))
            .map(|(chord, action)| format!("  {chord:20} {}", action.description()))
            .collect::<Vec<_>>();
        if !unavailable.is_empty() {
            lines.push(String::new());
            lines.push("Not available in the full-screen TUI:".to_string());
            lines.extend(unavailable);
        }
        if !self.keybinding_resolver.diagnostics().is_empty() {
            lines.push(String::new());
            lines.push("Unavailable bindings:".to_string());
            lines.extend(
                self.keybinding_resolver
                    .diagnostics()
                    .iter()
                    .map(|diagnostic| format!("  {diagnostic}")),
            );
        }
        self.messages.add(DisplayMessage::system(format!(
            "Effective keybindings:\n{}",
            lines.join("\n")
        )));
    }

    fn handle_plan_mode_request(
        &mut self,
        request: PlanModeRequest,
        reply: tokio::sync::oneshot::Sender<PlanModeReply>,
    ) {
        if self.pending_permission.is_some()
            || self.pending_user_question.is_some()
            || self.pending_plan_approval.is_some()
        {
            let _ = reply.send(PlanModeReply::Cancelled {
                message: "Another TUI decision is already pending".to_string(),
            });
            return;
        }
        let run = match self.tool_run_context() {
            Ok(run) => run,
            Err(error) => {
                let message = format!("Plan-mode request has no valid run capability: {error}");
                self.messages.add(DisplayMessage::error(message.clone()));
                let _ = reply.send(PlanModeReply::Cancelled { message });
                return;
            }
        };
        match request {
            PlanModeRequest::Enter => {
                match crate::session::install_interactive_plan_mode(&run, &self.chat_session) {
                    Ok(plan_file) => {
                        self.mode = tui_mode_for_agent(self.chat_session.agent_mode());
                        let message =
                            format!("Plan mode activated; write only to {}", plan_file.display());
                        self.messages.add(DisplayMessage::system(message.clone()));
                        let _ = reply.send(PlanModeReply::Completed {
                            message: message.clone(),
                            response: serde_json::json!({
                                "message": message,
                                "entered": true,
                                "plan_file": plan_file
                            }),
                            context_message: None,
                        });
                    }
                    Err(error) => {
                        let message = format!("Could not enter plan mode: {error}");
                        self.messages.add(DisplayMessage::error(message.clone()));
                        let _ = reply.send(PlanModeReply::Cancelled { message });
                    }
                }
            }
            PlanModeRequest::Exit { allowed_prompts } => {
                match crate::session::prepare_interactive_plan_approval(&run, &self.chat_session) {
                    Ok(prepared) => {
                        self.messages.add(DisplayMessage::system(format!(
                            "Review plan digest {} and approve or reject it",
                            prepared.plan_digest()
                        )));
                        self.pending_plan_approval = Some(PendingPlanApproval {
                            prepared,
                            allowed_prompts,
                            scroll_offset: 0,
                            reply,
                        });
                    }
                    Err(error) => {
                        let message = format!("Could not prepare plan approval: {error}");
                        self.messages.add(DisplayMessage::error(message.clone()));
                        let _ = reply.send(PlanModeReply::Cancelled { message });
                    }
                }
            }
        }
    }

    /// Table-handler entry point for `/mode`.
    fn slash_mode(&mut self) {
        let run = match self.run_context.as_ref() {
            Ok(run) => run,
            Err(error) => {
                self.messages.add(DisplayMessage::error(format!(
                    "Could not change mode: {error}"
                )));
                return;
            }
        };
        let cancelled_plan = self.chat_session.agent_mode() == AgentMode::Plan;
        if cancelled_plan {
            let restored = self.chat_session.inspect_state(|state| {
                state
                    .conversation
                    .plan_mode
                    .as_ref()
                    .and_then(|plan| plan.previous_mode.as_deref())
                    .map_or(AgentMode::Build, AgentMode::from_token)
            });
            if let Err(error) = run.transition_runtime_mode(crate::modes::RuntimeMode::Behavioral(
                self.chat_session.behavior_mode(),
            )) {
                self.messages.add(DisplayMessage::error(format!(
                    "Could not exit plan mode: {error}"
                )));
                return;
            }
            self.chat_session
                .update_state(|state, _| state.conversation.plan_mode = None);
            self.chat_session.set_agent_mode(restored);
        } else if let Err(error) =
            crate::session::install_interactive_plan_mode(run, &self.chat_session)
        {
            self.messages.add(DisplayMessage::error(format!(
                "Could not enter plan mode: {error}"
            )));
            return;
        }
        self.mode = tui_mode_for_agent(self.chat_session.agent_mode());
        let message = if cancelled_plan {
            "Plan mode cancelled by direct user action; no plan was approved".to_string()
        } else {
            format!(
                "Mode: {} — {}",
                self.chat_session.agent_mode(),
                self.chat_session.mode_description()
            )
        };
        self.messages.add(DisplayMessage::system(message));
    }

    /// Table-handler entry point for `/skill` / `/skills` (no-arg list form).
    fn slash_skill_list(&mut self) {
        let skills = self.session_skills();
        let invocable_skills = skills
            .iter()
            .filter(|skill| skill.user_invocable)
            .collect::<Vec<_>>();
        if invocable_skills.is_empty() {
            self.messages.add(DisplayMessage::system(
                "No skills found. Add .md files to .openclaudia/skills/",
            ));
        } else {
            let list = invocable_skills
                .iter()
                .map(|skill| {
                    let hint = skill
                        .argument_hint
                        .as_deref()
                        .map_or(String::new(), |hint| format!(" {hint}"));
                    format!(
                        "  /{}{} — {} [{:?}]",
                        skill.name,
                        hint,
                        skill.description,
                        skill.provenance().source
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            self.messages
                .add(DisplayMessage::system(format!("Available skills:\n{list}")));
        }
    }

    /// Handle skill invocations and info/diagnostic commands.
    fn handle_info_slash(&mut self, text: &str) {
        let skill_request = if text.starts_with("/skill ") {
            text.strip_prefix("/skill ").unwrap_or("").trim()
        } else {
            text.strip_prefix('/').unwrap_or("")
        };
        let split_at = skill_request
            .find(char::is_whitespace)
            .unwrap_or(skill_request.len());
        let skill_name = &skill_request[..split_at];
        let arguments = skill_request[split_at..].trim();
        if let Some(invocation) = self.resolve_plugin_turn(skill_name, arguments) {
            self.apply_plugin_turn(invocation);
            return;
        }
        let activation = self.run_context.as_ref().ok().and_then(|run| {
            crate::skills::activate_user_invocable_skill_for_run(run, skill_name).ok()
        });
        if let Some(activation) = activation {
            let name = activation.selection().name.clone();
            self.messages
                .add(DisplayMessage::system(format!("Running skill: /{name}")));
            self.apply_skill_turn_metadata(&activation);
            let content = if arguments.is_empty() {
                format!("Use the explicitly selected `/{name}` skill reference for this turn.")
            } else {
                format!(
                    "Use the explicitly selected `/{name}` skill reference for this turn.\n\nUser arguments:\n{arguments}"
                )
            };
            self.chat_session
                .push_message(serde_json::json!({ "role": "user", "content": content }));
            self.is_waiting = true;
            self.spawn_api_turn();
            return;
        }
        if text.starts_with("/rename ") {
            let new_title = text.strip_prefix("/rename ").unwrap_or("").trim();
            if new_title.is_empty() {
                self.messages
                    .add(DisplayMessage::system("Usage: /rename <new title>"));
            } else {
                self.chat_session.title = new_title.to_string();
                self.chat_session.touch();
                self.persist_session();
                self.messages.add(DisplayMessage::system(format!(
                    "Session renamed to: {new_title}"
                )));
            }
            return;
        }
        if self.handle_diagnostic_slash(text) {
            return;
        }
        self.messages.add(DisplayMessage::system(format!(
            "Unknown command: {text}. Type /help for commands."
        )));
    }

    fn resolve_plugin_turn(
        &self,
        namespaced_name: &str,
        arguments: &str,
    ) -> Option<PluginTurnInvocation> {
        let (plugin, component) = namespaced_name.split_once(':')?;
        let manager = self.mcp_runtime.as_ref()?.plugin_manager.as_ref();
        manager
            .invoke_command(plugin, component, arguments)
            .map(PluginTurnInvocation::Command)
            .or_else(|_| {
                manager
                    .invoke_skill(plugin, component, arguments)
                    .map(PluginTurnInvocation::Skill)
            })
            .or_else(|_| {
                manager
                    .invoke_agent(plugin, component, arguments)
                    .map(PluginTurnInvocation::Agent)
            })
            .ok()
    }

    fn apply_plugin_turn(&mut self, invocation: PluginTurnInvocation) {
        if let PluginTurnInvocation::Agent(invocation) = invocation {
            self.spawn_plugin_agent(invocation);
            return;
        }
        let (prompt, allowed_tools, model, effort, hooks, metadata, kind) = match invocation {
            PluginTurnInvocation::Command(invocation) => {
                let registration = invocation.registration;
                (
                    invocation.prompt,
                    registration.command.allowed_tools,
                    registration.command.model,
                    None,
                    None,
                    registration.metadata,
                    "command",
                )
            }
            PluginTurnInvocation::Skill(invocation) => {
                let registration = invocation.registration;
                (
                    invocation.prompt,
                    registration.definition.allowed_tools,
                    registration.definition.model,
                    registration.definition.effort,
                    registration.definition.hooks,
                    registration.metadata,
                    "skill",
                )
            }
            PluginTurnInvocation::Agent(_) => unreachable!("plugin agent handled above"),
        };
        self.next_turn_allowed_tool_rules =
            crate::permissions::allowed_tool_specs_to_permission_rules(allowed_tools.as_deref());
        if let Some(model) = model.filter(|model| self.can_use_prompt_model(model)) {
            self.next_turn_model = Some(model);
        }
        self.next_turn_effort_level = effort.as_deref().and_then(parse_prompt_effort_level);
        self.next_turn_skill_context = vec![crate::context::ContextItem::reference(
            format!("plugin.{kind}.{}", metadata.component_digest),
            crate::context::ReferenceSource::Plugin,
            metadata.canonical_name.clone(),
            format!(
                "Explicit plugin {kind} package={} plugin_id={} publisher={} artifact_digest={} source_revision={} requested_capabilities={:?}",
                metadata.provenance.package,
                metadata.provenance.plugin_id,
                metadata.provenance.publisher,
                metadata.provenance.artifact_digest,
                metadata.provenance.source.resolved_revision,
                metadata.requested_capabilities,
            ),
            crate::context::ContextFreshness::Turn,
            650,
        )];
        self.next_turn_hook_engine = hooks.and_then(|hooks| {
            serde_json::from_value::<crate::config::HooksConfig>(hooks)
                .ok()
                .map(|hooks| {
                    let engine = match self.hook_engine.as_ref() {
                        Some(engine) => engine.with_scoped_hooks(hooks),
                        None => crate::hooks::HookEngine::new(hooks),
                    };
                    std::sync::Arc::new(engine)
                })
        });
        self.messages.add(DisplayMessage::system(format!(
            "Running plugin {kind}: /{}:{}",
            metadata.provenance.package, metadata.component_name
        )));
        self.chat_session
            .push_message(serde_json::json!({ "role": "user", "content": prompt }));
        self.is_waiting = true;
        self.spawn_api_turn();
    }

    fn spawn_plugin_agent(&mut self, invocation: crate::plugins::PluginAgentInvocation) {
        let Some(runtime) = self.runtime_handle.clone() else {
            self.messages.add(DisplayMessage::error(
                "Plugin agents require the async runtime.",
            ));
            return;
        };
        if self.active_turn.is_some() {
            self.messages.add(DisplayMessage::error(
                "Cannot start a plugin agent while another response is active.",
            ));
            return;
        }
        if let Err(error) = self.ensure_live_launch_run() {
            self.handle_api_error(&error);
            return;
        }
        let Some(event_output) = self.event_sender() else {
            self.messages.add(DisplayMessage::error(
                "Plugin agent event delivery is unavailable.",
            ));
            return;
        };
        let Some(app_config) = self.app_config.clone() else {
            self.messages.add(DisplayMessage::error(
                "Plugin agents require active application configuration.",
            ));
            return;
        };
        let Ok(launch_run) = self.run_context.as_ref().map(std::sync::Arc::clone) else {
            self.messages.add(DisplayMessage::error(
                "Plugin agents require an active run context.",
            ));
            return;
        };
        let run_context = if launch_run.isolated_workspace().is_some() {
            launch_run
        } else {
            match derive_session_run_context(&launch_run, &self.chat_session, &self.provider) {
                Ok(run) => run,
                Err(error) => {
                    self.messages.add(DisplayMessage::error(format!(
                        "Cannot create plugin-agent run: {error}"
                    )));
                    return;
                }
            }
        };
        let metadata = &invocation.registration.metadata;
        let label = format!(
            "/{}:{}",
            metadata.provenance.package, metadata.component_name
        );
        self.messages.add(DisplayMessage::system(format!(
            "Running plugin agent: {label}"
        )));
        self.chat_session.push_message(serde_json::json!({
            "role": "user",
            "content": format!("Run plugin agent {label}.\n\nTask:\n{}", invocation.task),
        }));
        self.is_waiting = true;
        let client = self.api_client.client.clone();
        let memory_db = self.memory_db.clone();
        let call_id = crate::runtime::CallId::new();
        let (event_bridge, tx) = CallEventBridge::new(call_id, event_output);
        let active_run = std::sync::Arc::clone(&run_context);
        let task = async move {
            let result = crate::subagent::run_plugin_agent(
                &run_context,
                &invocation,
                app_config.as_ref(),
                &client,
                memory_db.as_deref(),
            )
            .await;
            let _ = tx.send(AppEvent::PluginAgentDone { label, result });
        };
        self.active_turn = Some(ActiveTurn {
            call_id,
            run_context: active_run,
            event_bridge: Some(event_bridge),
            terminal: None,
            task_outcome: None,
        });
        if let Some(supervisor) = self.supervisor.as_mut() {
            supervisor.spawn(call_id, TuiTaskKind::PluginAgent, task);
        } else {
            drop(runtime.spawn(task));
        }
    }

    fn apply_skill_turn_metadata(&mut self, activation: &crate::skills::SkillActivation) {
        self.next_turn_allowed_tool_rules =
            crate::permissions::allowed_tool_specs_to_permission_rules(activation.allowed_tools());

        if let Some(model) = activation
            .model()
            .filter(|model| self.can_use_prompt_model(model))
        {
            self.next_turn_model = Some(model.to_string());
        } else if let Some(model) = activation.model() {
            tracing::debug!(
                model = %model,
                provider = %self.provider,
                "ignoring skill model hint for a different provider in TUI"
            );
        }

        if let Some(level) = activation.effort().and_then(parse_prompt_effort_level) {
            self.next_turn_effort_level = Some(level);
        }
        let name = &activation.selection().name;
        self.next_turn_skill_context =
            vec![activation.context_item(format!("tui.skill.explicit.{name}"))];
        self.next_turn_hook_engine = activation.hooks().cloned().map(|hooks| {
            let engine = match self.hook_engine.as_ref() {
                Some(engine) => engine.with_scoped_hooks(hooks),
                None => crate::hooks::HookEngine::new(hooks),
            };
            std::sync::Arc::new(engine)
        });
    }

    fn can_use_prompt_model(&self, model: &str) -> bool {
        if crate::providers::is_openai_compatible_passthrough_target(&self.provider) {
            return true;
        }
        let detected = crate::providers::ProviderKind::from_model(model);
        detected == crate::providers::ProviderKind::Unknown
            || canonical_provider_name(detected.name()) == canonical_provider_name(&self.provider)
    }

    fn handle_slash_provider(&mut self, text: &str) -> bool {
        if text == "/provider" {
            self.messages.add(DisplayMessage::system(format!(
                "Provider: {}\nModel: {}\nEndpoint: {}\nUsage: /provider <name>\nSupported: {}",
                self.provider,
                self.model,
                self.api_client.endpoint,
                crate::providers::SUPPORTED_PROVIDERS.join(", ")
            )));
            return true;
        }

        let Some(requested) = text.strip_prefix("/provider ") else {
            return false;
        };
        let requested = requested.trim();
        if requested.is_empty() {
            self.messages
                .add(DisplayMessage::system("Usage: /provider <name>"));
            return true;
        }
        if self.is_waiting {
            self.messages.add(DisplayMessage::error(
                "Cannot switch provider while a response is in flight.",
            ));
            return true;
        }

        if self.runtime_handle.is_none() {
            self.messages.add(DisplayMessage::error(
                "No async runtime bound; cannot switch providers.",
            ));
            return true;
        }
        if self.event_sender().is_none() {
            self.messages.add(DisplayMessage::error(
                "No TUI event channel bound; cannot switch providers.",
            ));
            return true;
        }

        let requested = requested.to_string();
        let prompt_blocks = self.api_client.prompt_blocks.clone();
        self.messages.add(DisplayMessage::system(format!(
            "Switching provider to {requested}..."
        )));
        drop(
            self.spawn_owned_event(TuiTaskKind::ProviderDiscovery, async move {
                match resolve_provider_switch(&requested, prompt_blocks) {
                    Ok(switch) => AppEvent::ProviderSwitchReady(Box::new(switch)),
                    Err(err) => AppEvent::ProviderSwitchError(err),
                }
            }),
        );
        true
    }

    fn show_model_list_fallback(&mut self, note: Option<&str>) {
        let models = static_model_strings(&self.provider);
        self.messages.add(DisplayMessage::system(format_model_list(
            &self.provider,
            &self.model,
            &models,
            "fallback catalog",
            note,
        )));
    }

    fn start_model_list_fetch_or_show_fallback(&mut self) {
        let fallback_models = static_model_strings(&self.provider);
        let Ok(adapter) = crate::providers::get_adapter(&self.provider) else {
            self.show_model_list_fallback(Some("No adapter is registered for this provider."));
            return;
        };
        if !adapter.supports_model_listing() {
            self.show_model_list_fallback(None);
            return;
        }

        let Some(app_config) = self.app_config.as_ref() else {
            self.show_model_list_fallback(Some(
                "No active provider config is available for dynamic model listing.",
            ));
            return;
        };
        let Some(provider_config) = app_config.get_provider(&self.provider).cloned() else {
            self.show_model_list_fallback(Some(
                "No provider config was found for dynamic model listing.",
            ));
            return;
        };
        if self.runtime_handle.is_none() {
            self.show_model_list_fallback(Some(
                "No async runtime is bound for dynamic model listing.",
            ));
            return;
        }
        if self.event_sender().is_none() {
            self.show_model_list_fallback(Some(
                "No TUI event channel is bound for dynamic model listing.",
            ));
            return;
        }

        let provider = self.provider.clone();
        let current_model = self.model.clone();
        let extra_headers = provider_config.headers.clone();
        self.messages.add(DisplayMessage::system(format!(
            "Fetching models for {provider} from the configured /models endpoint..."
        )));
        drop(
            self.spawn_owned_event(TuiTaskKind::ModelDiscovery, async move {
                match crate::providers::fetch_models_for_provider_with_headers(
                    &provider,
                    &provider_config.base_url,
                    provider_config.api_key.as_ref(),
                    &extra_headers,
                    adapter,
                )
                .await
                {
                    Ok(models) => {
                        let model_ids: Vec<String> =
                            models.into_iter().map(|model| model.id).collect();
                        AppEvent::ModelListReady {
                            provider,
                            current_model,
                            models: model_ids,
                            source: "provider API".to_string(),
                            fallback_note: None,
                        }
                    }
                    Err(err) => AppEvent::ModelListError {
                        provider,
                        message: err.to_string(),
                        fallback_models,
                    },
                }
            }),
        );
    }

    fn handle_slash_model(&mut self, text: &str) -> bool {
        if text != "/model" && text != "/models" && !text.starts_with("/model ") {
            return false;
        }

        let args = if text == "/models" {
            "list"
        } else {
            text.strip_prefix("/model").unwrap_or("").trim()
        };

        if args.is_empty() {
            self.messages.add(DisplayMessage::system(format!(
                "Model: {}\nProvider: {}\nUse /model list to see fallback models, /model <name> to switch.",
                self.model, self.provider
            )));
            return true;
        }

        if args.eq_ignore_ascii_case("list") {
            self.start_model_list_fetch_or_show_fallback();
            return true;
        }

        if self.is_waiting {
            self.messages.add(DisplayMessage::error(
                "Cannot switch model while a response is in flight.",
            ));
            return true;
        }

        let model = if args.eq_ignore_ascii_case("default") {
            let Some(default) = crate::providers::default_model_for_target(&self.provider) else {
                self.messages.add(DisplayMessage::error(format!(
                    "Provider '{}' has no built-in default; choose an installed model explicitly.",
                    self.provider
                )));
                return true;
            };
            default.to_string()
        } else {
            args.to_string()
        };
        self.chat_session.set_model(model.clone());
        self.model = model;
        self.persist_session();
        self.messages.add(DisplayMessage::system(format!(
            "Model switched to {}",
            self.model
        )));
        true
    }

    /// Handle the `/cost` slash command.
    fn handle_slash_cost(&mut self) {
        let tokens = self.chat_session.refresh_estimated_tokens();
        let tokens_f64 = f64::from(u32::try_from(tokens).unwrap_or(u32::MAX));
        let cost = match self.model.as_str() {
            m if m.contains("opus") => tokens_f64.mul_add(0.000_015, tokens_f64 * 0.000_075),
            m if m.contains("sonnet") => tokens_f64.mul_add(0.000_003, tokens_f64 * 0.000_015),
            m if m.contains("haiku") => tokens_f64.mul_add(0.000_000_25, tokens_f64 * 0.000_001_25),
            _ => 0.0,
        };
        self.messages.add(DisplayMessage::system(format!(
            "Session cost estimate:\n  ~{tokens} tokens\n  ~${cost:.4}"
        )));
    }

    /// Handle the `/files [dir]` slash command.
    ///
    /// Dispatches the directory read through [`Self::spawn_fs`] (crosslink
    /// #270) so a slow disk / network filesystem cannot stall the redraw
    /// thread the way the previous synchronous `std::fs::read_dir` did.
    /// The result is rendered when the matching
    /// `AppEvent::ShellDone { target: SpawnTarget::Files, .. }` arrives.
    fn handle_slash_files(&mut self, text: &str) {
        let dir = text.strip_prefix("/files").unwrap_or("").trim().to_owned();
        let dir = if dir.is_empty() { ".".to_string() } else { dir };
        let dir_for_render = dir.clone();
        let run = self.run_context.as_ref().ok().cloned();
        self.spawn_fs(SpawnTarget::Files, move || {
            let run =
                run.ok_or_else(|| format!("Failed to list {dir}: no active read capability"))?;
            let resolved = crate::tools::resolve_capability_path(&run, &dir)
                .map_err(|error| format!("Failed to list {dir}: {error}"))?;
            let entries = std::fs::read_dir(&resolved)
                .map_err(|error| format!("Failed to list {dir}: {error}"))?;
            let mut items: Vec<String> = entries
                .flatten()
                .map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    let suffix = if e.file_type().is_ok_and(|t| t.is_dir()) {
                        "/"
                    } else {
                        ""
                    };
                    format!("  {name}{suffix}")
                })
                .collect();
            items.sort();
            Ok(format!("Files in {dir_for_render}:\n{}", items.join("\n")))
        });
    }

    /// Handle the `/diff` slash command (shows `git diff --stat`).
    ///
    /// Dispatches to the tokio runtime via [`Self::spawn_shell`] — see
    /// crosslink #371. The rendering of the result happens on the next
    /// `AppEvent::ShellDone` tick handled in `handle_app_event`.
    fn handle_slash_diff(&mut self) {
        // Drop the JoinHandle explicitly: the slash-command call site is
        // fire-and-forget, the receiver lives in the mpsc channel.
        drop(self.spawn_shell(vec!["git", "diff", "--stat"], SpawnTarget::Diff));
    }

    /// Handle the `/doctor` slash command (environment diagnostics).
    fn handle_slash_doctor(&mut self) {
        let mut runtime = self.run_context.as_ref().map_or_else(
            |_| crate::doctor::DoctorRuntimeSnapshot::live_without_run(),
            |run| crate::doctor::DoctorRuntimeSnapshot::from_run(run),
        );
        if !self.api_client.endpoint.is_empty() {
            if let Ok(adapter) = crate::providers::get_adapter(&self.provider) {
                runtime =
                    runtime.with_composed_provider_transport(&self.api_client.client, adapter);
            }
        }
        if let Some(memory) = self.memory_db.as_deref() {
            runtime = runtime.with_composed_memory_store(memory);
        }
        if let Some(mcp) = self.mcp_runtime.as_ref() {
            runtime = runtime
                .with_composed_plugin_manager(mcp.plugin_manager.as_ref())
                .with_composed_mcp_manager(&mcp.manager);
        }

        let config_state = self.app_config.as_deref().map_or(
            crate::doctor::DoctorConfig::Unavailable,
            crate::doctor::DoctorConfig::Attached,
        );
        let report = crate::doctor::diagnose(
            config_state,
            &runtime,
            &crate::doctor::DoctorRequest::default(),
        );
        let rendered = if report.validate().is_ok() {
            report.render_human()
        } else {
            "Diagnostics unavailable: typed report validation failed closed.".to_string()
        };
        self.messages.add(DisplayMessage::system(rendered));
    }

    /// Discover skills through this session's immutable project boundary.
    ///
    /// A failed run construction deliberately yields no project skills rather
    /// than falling back to the process current directory.
    fn session_skills(&self) -> Vec<crate::skills::ResolvedSkill> {
        match self.run_context.as_ref() {
            Ok(run) => crate::skills::load_skills_for_run(run),
            Err(error) => {
                tracing::warn!(%error, "skill discovery unavailable without a valid TUI run");
                Vec::new()
            }
        }
    }

    /// Handle the `/review` slash command (shows truncated `git diff HEAD`).
    fn handle_slash_review(&mut self) {
        let run = match self.run_context.as_ref() {
            Ok(run) => run,
            Err(error) => {
                self.messages.add(DisplayMessage::error(format!(
                    "Review unavailable: {error}"
                )));
                return;
            }
        };
        if let Err(error) = run.admit_runtime_mode_direct_operation("review Git diff") {
            self.messages.add(DisplayMessage::error(error));
            return;
        }
        let content = match run
            .resolve_executable("git")
            .map_err(|error| error.to_string())
            .and_then(|git| {
                std::process::Command::new(git)
                    .current_dir(run.working_directory())
                    .args(["diff", "HEAD"])
                    .output()
                    .map_err(|error| error.to_string())
            }) {
            Ok(out) => format_review_command_output(&out),
            Err(e) => format!("Failed to run git diff: {e}"),
        };
        self.messages.add(DisplayMessage::system(content));
    }

    /// Handle the `/init` slash command (create config if absent).
    fn handle_slash_init(&mut self) {
        let content = match self.run_context.as_deref() {
            Ok(run) => match run.admit_runtime_mode_direct_operation("initialize project") {
                Err(error) => error,
                Ok(()) => match crate::tools::initialize_project_for_run(run) {
                    Ok(crate::tools::ProjectInitOutcome::Created) => {
                        "Initialized OpenClaudia configuration in .openclaudia/".to_string()
                    }
                    Ok(crate::tools::ProjectInitOutcome::AlreadyExists) => {
                        "Config already exists. Use /doctor to check it.".to_string()
                    }
                    Err(error) => format!("Init failed: {error}"),
                },
            },
            Err(error) => format!("Init failed: no valid run capability: {error}"),
        };
        self.messages.add(DisplayMessage::system(content));
    }

    /// Handle diagnostic/info slash commands. Returns true if handled.
    fn handle_diagnostic_slash(&mut self, text: &str) -> bool {
        if self.handle_slash_provider(text) {
            return true;
        }
        if self.handle_slash_model(text) {
            return true;
        }
        if text == "/cost" {
            self.handle_slash_cost();
            return true;
        }
        if text == "/files" || text.starts_with("/files ") {
            self.handle_slash_files(text);
            return true;
        }
        if text == "/diff" {
            self.handle_slash_diff();
            return true;
        }
        if text == "/context" {
            let msg_count = self.chat_session.message_count();
            let tokens = self.chat_session.refresh_estimated_tokens();
            self.messages.add(DisplayMessage::system(format!(
                "Context usage:\n  Messages: {msg_count}\n  Est. tokens: ~{tokens}\n  Model: {}\n  Provider: {}",
                self.model, self.provider
            )));
            return true;
        }
        if text == "/doctor" {
            self.handle_slash_doctor();
            return true;
        }
        if text == "/review" || text.starts_with("/review ") {
            self.handle_slash_review();
            return true;
        }
        if text == "/init" {
            self.handle_slash_init();
            return true;
        }
        false
    }

    /// Execute a shell command and display its output.
    ///
    /// Dispatches the typed user-origin action through the canonical process
    /// capability without blocking the TUI event loop.
    fn handle_shell_command(&mut self, cmd: &str) {
        if cmd.is_empty() {
            return;
        }
        drop(self.spawn_direct_shell(cmd));
    }

    /// Spawn one explicit `!command` action through the shared sandboxed
    /// supervisor and deliver its bounded result through the existing TUI event.
    fn spawn_direct_shell(&mut self, command: &str) -> Option<tokio::task::JoinHandle<()>> {
        let target = SpawnTarget::ShellCommand {
            displayed: command.to_string(),
        };
        let tx = self.api_event_tx.clone()?;
        if self.runtime_handle.is_none() {
            let _ = tx.send(AppEvent::ShellDone {
                target,
                stdout: String::new(),
                stderr: "no async runtime bound — cannot spawn direct shell".to_string(),
                exit_code: None,
            });
            return None;
        }
        let run = match &self.run_context {
            Ok(run) => std::sync::Arc::clone(run),
            Err(error) => {
                let _ = tx.send(AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: format!("session process capability unavailable: {error}"),
                    exit_code: None,
                });
                return None;
            }
        };
        let action = crate::tools::DirectShellAction::new(command, self.chat_session.id());
        self.spawn_owned_event(TuiTaskKind::Process, async move {
            match crate::tools::execute_direct_shell_async(&run, action).await {
                Ok(execution) => {
                    let exit_code = execution.exit_code();
                    let mut stderr = execution.stderr;
                    if exit_code.is_none() {
                        if let Some(status) = execution.status.as_ref() {
                            if !stderr.is_empty() {
                                stderr.push('\n');
                            }
                            let _ = std::fmt::Write::write_fmt(
                                &mut stderr,
                                format_args!("terminal status: {status}"),
                            );
                        }
                    }
                    AppEvent::ShellDone {
                        target,
                        stdout: execution.stdout,
                        stderr,
                        exit_code,
                    }
                }
                Err(error) => {
                    let (stdout, mut stderr) = error.partial_execution().map_or_else(
                        || (String::new(), String::new()),
                        |execution| (execution.stdout.clone(), execution.stderr.clone()),
                    );
                    if !stderr.is_empty() {
                        stderr.push('\n');
                    }
                    stderr.push_str(&error.to_string());
                    AppEvent::ShellDone {
                        target,
                        stdout,
                        stderr,
                        exit_code: None,
                    }
                }
            }
        })
    }

    /// Send a user message to the API.
    fn send_user_message(&mut self, text: String) {
        let expanded = self
            .run_context
            .as_ref()
            .map_or_else(|_| text.clone(), |run| expand_file_refs(run, &text));

        self.messages.add(DisplayMessage::user(text));

        self.chat_session.push_message(serde_json::json!({
            "role": "user",
            "content": expanded
        }));

        self.is_waiting = true;
        self.spawn_api_turn();
    }

    /// Run a synchronous filesystem closure off the TUI event loop on the
    /// tokio blocking pool and emit a [`AppEvent::ShellDone`] when done
    /// (crosslink #270 / #371 follow-up).
    ///
    /// `op` is run on `tokio::task::spawn_blocking` so a slow disk or a
    /// network filesystem cannot stall the redraw thread the way the
    /// previous synchronous `std::fs::read_dir` / `std::fs::write` calls
    /// from `/files` and `/export` did. The closure returns either
    /// `Ok(rendered_text)` or `Err(error_text)` — the helper translates
    /// those into a `ShellDone` event with the right exit-code semantics
    /// (`Some(0)` on success, `None` on error) so the existing receiver
    /// in `handle_app_event` does the rendering with no special-casing.
    ///
    /// If no tokio runtime is bound yet (`runtime_handle == None`), the
    /// helper synthesises an error `ShellDone` directly through the
    /// channel — same shape as `spawn_shell`'s no-runtime branch. Tests
    /// without a runtime still observe the event.
    fn spawn_fs<F>(&mut self, target: SpawnTarget, op: F)
    where
        F: FnOnce() -> Result<String, String> + Send + 'static,
    {
        let tx = self.api_event_tx.clone();

        if self.runtime_handle.is_none() {
            if let Some(tx) = tx {
                let _ = tx.send(AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: "no async runtime bound — cannot spawn fs task".to_string(),
                    exit_code: None,
                });
            }
            return;
        }

        // spawn_blocking puts the closure on the tokio blocking-IO pool
        // (default 512 threads) so a slow read_dir() doesn't take down
        // any of the async-runtime worker threads either.
        drop(self.spawn_owned_event(TuiTaskKind::Filesystem, async move {
            let join = tokio::task::spawn_blocking(op).await;
            match join {
                Ok(Ok(text)) => AppEvent::ShellDone {
                    target,
                    stdout: text,
                    stderr: String::new(),
                    exit_code: Some(0),
                },
                Ok(Err(err)) => AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: err,
                    exit_code: None,
                },
                Err(join_err) => AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: format!("fs task panicked: {join_err}"),
                    exit_code: None,
                },
            }
        }));
    }

    /// Spawn a subprocess on the tokio runtime and post the result back
    /// to the TUI event loop as [`AppEvent::ShellDone`].
    ///
    /// This is the seam that closes crosslink #371. Slash commands like
    /// `/diff` and the `!<cmd>` shell escape used to call
    /// `std::process::Command::new(...).output()` directly on the sync
    /// event loop thread, which blocked rendering for the full lifetime
    /// of the child. The helper instead dispatches the work to
    /// `runtime_handle.spawn(...)` using `tokio::process::Command` so
    /// the loop keeps ticking; results arrive asynchronously via the
    /// existing mpsc channel that already carries streaming API events.
    ///
    /// `cmd[0]` is the program; `cmd[1..]` are its args. The empty
    /// vector is a logic bug — we report it through `ShellDone` instead
    /// of panicking on `split_first` because the caller can be exercised
    /// from outside `run()` (e.g. tests).
    ///
    /// If no runtime is bound yet (`self.runtime_handle == None`) the
    /// helper posts an error `ShellDone` (`exit_code` = None, stderr
    /// explaining the missing runtime) and returns `None`.
    #[allow(clippy::too_many_lines)] // Keep async process lifecycle and its single TUI completion event together.
    fn spawn_shell(
        &mut self,
        cmd: Vec<&str>,
        target: SpawnTarget,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let tx = self.api_event_tx.clone();
        if matches!(target, SpawnTarget::ShellCommand { .. }) {
            if let Some(tx) = tx {
                let _ = tx.send(AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: "direct shell must use the canonical process capability".to_string(),
                    exit_code: None,
                });
            }
            return None;
        }
        // Eagerly own the argv as Strings — the future outlives `&self`.
        let argv: Vec<String> = cmd.into_iter().map(str::to_owned).collect();

        let run_context = match &self.run_context {
            Ok(run_context) => std::sync::Arc::clone(run_context),
            Err(error) => {
                if let Some(tx) = tx {
                    let _ = tx.send(AppEvent::ShellDone {
                        target,
                        stdout: String::new(),
                        stderr: format!("session process capability unavailable: {error}"),
                        exit_code: None,
                    });
                }
                return None;
            }
        };
        if let Err(error) = run_context.require(crate::tools::ToolResource::Process) {
            if let Some(tx) = tx {
                let _ = tx.send(AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: error.to_string(),
                    exit_code: None,
                });
            }
            return None;
        }
        if let Err(error) = run_context.admit_runtime_mode_direct_operation(&format!("{target:?}"))
        {
            if let Some(tx) = tx {
                let _ = tx.send(AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: error,
                    exit_code: None,
                });
            }
            return None;
        }
        let cwd = run_context.working_directory().to_path_buf();
        let environment_grants = run_context.environment_grants().clone();
        let private_temp = run_context.private_temp_root().to_path_buf();
        let executable_search_path = run_context.executable_search_path().to_os_string();

        if self.runtime_handle.is_none() {
            // No runtime — surface as a failed ShellDone so the receiver
            // still gets called.
            if let Some(tx) = tx {
                let _ = tx.send(AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: "no async runtime bound — cannot spawn shell".to_string(),
                    exit_code: None,
                });
            }
            return None;
        }

        let mutation_effect = match &target {
            SpawnTarget::Init => Some(crate::tools::effect::ToolEffect::WorkspaceMutation),
            SpawnTarget::ShellCommand { .. } => unreachable!("direct shell rejected above"),
            SpawnTarget::Diff | SpawnTarget::Review | SpawnTarget::Files | SpawnTarget::Doctor => {
                None
            }
        };
        let mut freshness_reservation = match mutation_effect {
            Some(effect) => match crate::evidence_freshness::reserve_mutation(&run_context, effect)
            {
                Ok(reservation) => reservation,
                Err(error) => {
                    if let Some(tx) = tx {
                        let _ = tx.send(AppEvent::ShellDone {
                            target,
                            stdout: String::new(),
                            stderr: format!("cannot reserve shell mutation freshness: {error}"),
                            exit_code: None,
                        });
                    }
                    return None;
                }
            },
            None => None,
        };

        self.spawn_owned_event(TuiTaskKind::Process, async move {
            let Some((exe, rest)) = argv.split_first() else {
                return AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: "spawn_shell called with empty argv".to_string(),
                    exit_code: None,
                };
            };

            let result = match run_context.resolve_executable(exe) {
                Ok(executable) => {
                    let mut command = tokio::process::Command::new(executable);
                    command
                        .args(rest)
                        .current_dir(&cwd)
                        .kill_on_drop(true)
                        .env_clear()
                        .env("HOME", &private_temp)
                        .env("TMPDIR", &private_temp)
                        .env("TMP", &private_temp)
                        .env("TEMP", &private_temp)
                        .env("PATH", &executable_search_path)
                        .env("CLAUDE_PROJECT_DIR", &cwd);
                    environment_grants.apply_tokio(&mut command);
                    command.output().await
                }
                Err(error) => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("cannot resolve '{exe}': {error}"),
                )),
            };

            if result.is_ok() {
                if let Some(reservation) = freshness_reservation.as_mut() {
                    if let Err(error) = reservation.commit() {
                        tracing::error!(
                            %error,
                            "failed to advance freshness after TUI shell completion"
                        );
                    }
                    crate::ledger::invalidate_verification_receipts_for_run(&run_context);
                }
            }

            match result {
                Ok(out) => AppEvent::ShellDone {
                    target,
                    stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                    exit_code: out.status.code(),
                },
                Err(e) => AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: format!("{e}"),
                    exit_code: None,
                },
            }
        })
    }

    /// Spawn an async API turn on the tokio runtime.
    ///
    /// Sends events through the event handler's mpsc channel so the
    /// synchronous TUI event loop can display streaming output.
    #[allow(clippy::too_many_lines)] // One atomic snapshot composes the exact model-turn capability and transport.
    fn spawn_api_turn(&mut self) {
        if self.runtime_handle.is_none() {
            self.messages.add(DisplayMessage::error(
                "[No async runtime — cannot call API. Run with tokio.]",
            ));
            self.is_waiting = false;
            self.clear_next_turn_metadata();
            return;
        }
        if let Err(error) = self.ensure_live_launch_run() {
            self.handle_api_error(&error);
            self.clear_next_turn_metadata();
            return;
        }
        self.refresh_prompt_context_for_run();

        let Some(event_output) = self.event_sender() else {
            self.is_waiting = false;
            self.clear_next_turn_metadata();
            return;
        };

        // ApiClient owns the transport bundle (#253) — one clone instead of five.
        let api = self.api_client.clone();
        let client = api.client;
        let endpoint = api.endpoint;
        let headers = api.headers;
        let provider = self.provider.clone();
        let model = self
            .next_turn_model
            .take()
            .unwrap_or_else(|| self.model.clone());
        let effort_level = self
            .next_turn_effort_level
            .take()
            .unwrap_or_else(|| self.chat_session.effort_level());
        let transient_allowed_tool_rules = std::mem::take(&mut self.next_turn_allowed_tool_rules);
        let claude_code_token = api.claude_code_token;
        let claude_agent_sdk = api.claude_agent_sdk;
        let codex_agent_sdk = api.codex_agent_sdk;
        let prompt_blocks = api.prompt_blocks;
        let wire_api = api.wire_api;
        let hook_engine = self
            .next_turn_hook_engine
            .take()
            .or_else(|| self.active_turn_hook_engine.clone())
            .or_else(|| self.hook_engine.clone());
        self.active_turn_hook_engine.clone_from(&hook_engine);
        self.next_turn_skill_context.clear();
        let session_id_for_task = self.chat_session.id();
        let launch_run = match &self.run_context {
            Ok(run_context) => std::sync::Arc::clone(run_context),
            Err(error) => {
                self.handle_api_error(&format!("Tool execution is unavailable: {error}"));
                self.is_waiting = false;
                self.clear_next_turn_metadata();
                return;
            }
        };
        let run_context = if launch_run.isolated_workspace().is_some() {
            launch_run
        } else {
            match derive_session_run_context(&launch_run, &self.chat_session, &self.provider) {
                Ok(run) => run,
                Err(error) => {
                    self.handle_api_error(&format!("Cannot create model-turn run: {error}"));
                    self.clear_next_turn_metadata();
                    return;
                }
            }
        };
        let call_id = crate::runtime::CallId::new();
        let (event_bridge, tx) = CallEventBridge::new(call_id, event_output);
        let memory_db = self.memory_db.clone();
        let app_config = self.app_config.clone();
        let permission_mgr = self.permission_mgr.clone();
        let vdd_engine = self.vdd_engine.clone();
        let vdd_builder_auth = self.vdd_builder_auth.clone();
        let policy_enforcer = std::sync::Arc::clone(&self.policy_enforcer);
        let task_mgr = self.task_mgr.clone();
        let turn_mcp = self.mcp_runtime.as_ref().map(|runtime| {
            let manager = std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::mcp::McpManager::new_with_permissions(
                    std::sync::Arc::clone(&run_context),
                    self.app_config
                        .as_ref()
                        .map_or_else(crate::config::PermissionsConfig::default, |config| {
                            config.permissions.clone()
                        }),
                ),
            ));
            let _ = crate::mcp::install_manager(&run_context, &manager);
            (
                manager,
                std::sync::Arc::clone(&runtime.plugin_manager),
                runtime.trusted_servers.clone(),
            )
        });
        let mcp_manager = turn_mcp
            .as_ref()
            .map(|(manager, _, _)| std::sync::Arc::clone(manager));
        // Clone the canonical state snapshot so the async task can build
        // follow-up requests without holding the state lock across awaits.
        let session_messages = self.chat_session.messages_snapshot();
        let provider_native_state = self.chat_session.provider_native_state_snapshot();
        let active_run = std::sync::Arc::clone(&run_context);

        let task = async move {
            if let Some((manager, plugin_manager, trusted_servers)) = turn_mcp.as_ref() {
                plugin_manager.configure_lsp_service_for_run(&run_context);
                crate::proxy::connect_mcp_servers_with_trust(
                    manager,
                    plugin_manager,
                    trusted_servers,
                )
                .await;
            }
            Box::pin(run_api_turn_async(ApiTurnParams {
                run_context,
                session_messages,
                provider_native_state,
                client,
                endpoint,
                headers,
                provider,
                model,
                effort_level,
                wire_api,
                claude_code_token,
                claude_agent_sdk,
                codex_agent_sdk,
                prompt_blocks,
                memory_db,
                app_config,
                permission_mgr,
                vdd_engine,
                vdd_builder_auth,
                transient_allowed_tool_rules,
                hook_engine,
                policy_enforcer,
                task_mgr,
                mcp_manager,
                session_id: session_id_for_task,
                tx,
            }))
            .await;
            if let Some((manager, _, _)) = turn_mcp {
                if let Err(error) = manager.write().await.disconnect_all().await {
                    tracing::warn!(%error, "failed to disconnect model-turn MCP transports");
                }
            }
        };
        self.active_turn = Some(ActiveTurn {
            call_id,
            run_context: active_run,
            event_bridge: Some(event_bridge),
            terminal: None,
            task_outcome: None,
        });
        if let Some(supervisor) = self.supervisor.as_mut() {
            supervisor.spawn(call_id, TuiTaskKind::ModelTurn, task);
        } else if let Some(handle) = self.runtime_handle.as_ref() {
            drop(handle.spawn(task));
        }
    }

    fn clear_next_turn_metadata(&mut self) {
        self.next_turn_effort_level = None;
        self.next_turn_model = None;
        self.next_turn_allowed_tool_rules.clear();
        self.next_turn_skill_context.clear();
        self.next_turn_hook_engine = None;
    }

    fn input_area_height(&self, area_width: u16) -> u16 {
        let content_rows = self
            .input
            .visual_line_count(input_content_width(area_width));
        content_rows
            .saturating_add(1)
            .clamp(MIN_INPUT_HEIGHT, MAX_INPUT_HEIGHT)
    }

    fn draw(&mut self, frame: &mut Frame) {
        let input_height = self.input_area_height(frame.area().width);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),            // Welcome box
                Constraint::Min(3),               // Messages
                Constraint::Length(input_height), // Input
                Constraint::Length(1),            // Status
            ])
            .split(frame.area());

        // ── Welcome box (two-column, bordered) ──
        self.draw_welcome_box(frame, chunks[0]);

        // ── Messages ──
        self.messages.render(frame, chunks[1]);

        // ── Input area ──
        let input_block = Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(DIM));

        let prompt_text = if self.is_waiting {
            format!("{} ", SPINNER_FRAMES[self.spinner_frame])
        } else {
            "\u{203A} ".to_string()
        };
        let display_text = format!("{prompt_text}{}", self.input.content.replace('\n', "\n  "));

        let input_para = Paragraph::new(display_text)
            .block(input_block)
            .style(Style::default().fg(Color::White));
        frame.render_widget(input_para, chunks[2]);

        // Cursor
        if !self.is_waiting {
            let (cursor_row, cursor_col) = self
                .input
                .visual_cursor_position(input_content_width(chunks[2].width));
            let max_cursor_row = chunks[2].height.saturating_sub(2);
            let cx = chunks[2].x + INPUT_PROMPT_WIDTH + cursor_col;
            let cy = chunks[2].y + 1 + cursor_row.min(max_cursor_row);
            frame.set_cursor_position(Position::new(
                cx.min(chunks[2].right().saturating_sub(1)),
                cy,
            ));
        }

        // ── Status bar ──
        let left_text = if self.keybinding_resolver.is_pending() {
            format!("keys: {} …", self.keybinding_resolver.pending_display())
        } else {
            "? for shortcuts".to_string()
        };
        let effort = self.chat_session.effort_level();
        let effort_symbol = effort.symbol();
        let right_text = format!("{effort_symbol} {effort} \u{00B7} /effort");

        let bar_width = chunks[3].width as usize;
        let content_len = left_text.len() + right_text.len() + 2;
        let padding = bar_width.saturating_sub(content_len);
        let status_text = format!(" {left_text}{}{right_text} ", " ".repeat(padding));

        let status = Paragraph::new(status_text).style(Style::default().fg(DIM));
        frame.render_widget(status, chunks[3]);

        // ── Permission prompt overlay ──
        self.draw_permission_overlay(frame);

        // ── ask_user_question modal ──
        self.draw_user_question_overlay(frame);

        // ── typed plan approval modal ──
        self.draw_plan_approval_overlay(frame);

        // ── Modal overlay (rendered last so it floats above everything) ──
        // Use `Clear` to blank the underlying region; both overlays paint
        // their own background via the border-block's default bg.
        if let Some(ref mut overlay) = self.overlay {
            use super::components::Overlay as _;
            let area = super::components::centered_rect(60, 60, frame.area());
            frame.render_widget(ratatui::widgets::Clear, area);
            match overlay {
                ActiveOverlay::Help(o) => o.render(frame, area),
                ActiveOverlay::LogSelector(o) => o.render(frame, area),
            }
        }
    }

    /// Render the permission-prompt dialog when one is pending.
    fn draw_permission_overlay(&self, frame: &mut Frame) {
        let Some(ref perm) = self.pending_permission else {
            return;
        };
        let area = frame.area();
        let dialog_width = area.width.min(70);
        let dialog_height = 8u16;
        let x = (area.width.saturating_sub(dialog_width)) / 2;
        let y = area.height.saturating_sub(dialog_height + 4);
        let dialog_area = Rect::new(x, y, dialog_width, dialog_height);
        let clear = Paragraph::new("").style(Style::default().bg(Color::Black));
        frame.render_widget(clear, dialog_area);
        let args_preview = if perm.tool_args.len() > 50 {
            format!("{}...", crate::tools::safe_truncate(&perm.tool_args, 47))
        } else {
            perm.tool_args.clone()
        };
        let prompt_text = vec![
            Line::from(Span::styled(
                format!("  Tool: {}", perm.tool_name),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                format!("  Args: {args_preview}"),
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                format!(
                    "  Scope: {}",
                    crate::tools::permission_scope_summary(&perm.tool_name)
                ),
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  [y] ", Style::default().fg(Color::Green)),
                Span::raw("Allow  "),
                Span::styled("[n] ", Style::default().fg(Color::Red)),
                Span::raw("Deny  "),
                Span::styled("[a] ", Style::default().fg(Color::Cyan)),
                Span::raw("Always  "),
                Span::styled("[d] ", Style::default().fg(Color::Yellow)),
                Span::raw("Never"),
            ]),
        ];
        let dialog = Paragraph::new(prompt_text)
            .block(
                Block::default()
                    .title(" Permission Required ")
                    .title_style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(GOLD)),
            )
            .style(Style::default().bg(Color::Black));
        frame.render_widget(dialog, dialog_area);
    }

    /// Render the `ask_user_question` modal when one is active.
    ///
    /// Centred box overlaying the bottom of the screen, sized to fit
    /// the option list. Shows the question header, the question text,
    /// each option prefixed by `[N]`, a synthetic `[N+1] Other` row
    /// that triggers free-form follow-up, and the current input
    /// buffer with a `>` prompt.
    ///
    /// All rendering reads from `&self` only — state mutation lives
    /// in [`handle_user_question_key`] / [`finalise_current_question`].
    fn draw_user_question_overlay(&self, frame: &mut Frame) {
        let Some(ref pq) = self.pending_user_question else {
            return;
        };
        let Some(q) = pq.questions.get(pq.current_index) else {
            return;
        };
        let options = q
            .get("options")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let multi_select = q
            .get("multiSelect")
            .or_else(|| q.get("multi_select"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let area = frame.area();
        // Reserve room for header + question + each option + Other + blank
        // + prompt + status footer (8 + N lines).
        let dialog_width = area.width.min(78);
        let dialog_height = u16::try_from(options.len() + 8)
            .unwrap_or(u16::MAX)
            .min(area.height.saturating_sub(2));
        let x = (area.width.saturating_sub(dialog_width)) / 2;
        let y = (area.height.saturating_sub(dialog_height)) / 2;
        let dialog_area = Rect::new(x, y, dialog_width, dialog_height);
        // Blank the underlying region.
        frame.render_widget(ratatui::widgets::Clear, dialog_area);

        let lines = build_user_question_lines(pq, q, &options, multi_select);

        let title = if multi_select {
            " Ask User (multi-select) "
        } else {
            " Ask User "
        };
        let dialog = Paragraph::new(lines)
            .block(
                Block::default()
                    .title(title)
                    .title_style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(GOLD)),
            )
            .style(Style::default().bg(Color::Black));
        frame.render_widget(dialog, dialog_area);
    }

    /// Render the exact digest-bound plan proposal awaiting approval.
    fn draw_plan_approval_overlay(&self, frame: &mut Frame) {
        let Some(ref plan) = self.pending_plan_approval else {
            return;
        };
        let area = super::components::centered_rect(88, 82, frame.area());
        frame.render_widget(ratatui::widgets::Clear, area);
        let mut body = format!(
            "Digest: {}\n\n{}",
            plan.prepared.plan_digest(),
            plan.prepared.plan_content()
        );
        if !plan.allowed_prompts.is_empty() {
            body.push_str("\n\nProposed allowed operations:\n");
            for prompt in &plan.allowed_prompts {
                use std::fmt::Write as _;
                let _ = writeln!(body, "- {}: {}", prompt.tool, prompt.prompt);
            }
        }
        let dialog = Paragraph::new(body)
            .block(
                Block::default()
                    .title(" Plan Approval · [y] approve · [n] reject · Esc cancel · ↑/↓ scroll ")
                    .title_style(Style::default().fg(GOLD).add_modifier(Modifier::BOLD))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(GOLD)),
            )
            .style(Style::default().bg(Color::Black))
            .wrap(ratatui::widgets::Wrap { trim: false })
            .scroll((plan.scroll_offset, 0));
        frame.render_widget(dialog, area);
    }

    /// Render the welcome box — two-column bordered widget matching the old inline UI.
    fn draw_welcome_box(&self, frame: &mut Frame, area: Rect) {
        use ratatui::widgets::Wrap;

        // Title in the border
        let title = Line::from(vec![
            Span::styled(
                "OpenClaudia",
                Style::default().fg(PURPLE).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" v{}", env!("CARGO_PKG_VERSION")),
                Style::default().fg(GOLD),
            ),
        ]);

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(PURPLE));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Two-column layout
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(inner);

        // Left column: greeting, provider, model, cwd
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default();
        let greeting = if username.is_empty() {
            "Welcome to OpenClaudia!".to_string()
        } else {
            format!("Welcome back, {username}!")
        };
        let cwd = self.run_context.as_ref().map_or_else(
            |_| ".".to_string(),
            |run| {
                let p = run.working_directory();
                if let Some(home) = dirs::home_dir() {
                    if let Ok(rel) = p.strip_prefix(&home) {
                        return format!("~/{}", rel.display());
                    }
                }
                p.display().to_string()
            },
        );

        let left = Paragraph::new(vec![
            Line::from(Span::styled(
                greeting,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("Provider: {}", super::capitalize_first(&self.provider)),
                Style::default().fg(PURPLE),
            )),
            Line::from(Span::styled(
                format!("Model: {}", self.model),
                Style::default().fg(GOLD),
            )),
            Line::from(Span::styled(cwd, Style::default().fg(Color::DarkGray))),
        ])
        .wrap(Wrap { trim: true });
        frame.render_widget(left, cols[0]);

        // Right column: tips and recent activity
        let tips = super::get_tips();
        let right = Paragraph::new(vec![
            Line::from(Span::styled("Tips", Style::default().fg(GOLD))),
            Line::from(Span::styled(
                tips[0].to_string(),
                Style::default().fg(Color::White),
            )),
            Line::from(""),
            Line::from(Span::styled("Recent activity", Style::default().fg(GOLD))),
            Line::from(Span::styled(
                "No recent activity",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .wrap(Wrap { trim: true });
        frame.render_widget(right, cols[1]);
    }
}

impl Drop for App {
    fn drop(&mut self) {
        if let Some(turn) = self.active_turn.take() {
            crate::tools::retire_run(&turn.run_context);
        }
        for completed in self.completed_turn_runs.drain(..) {
            crate::tools::retire_run(&completed.run_context);
        }
        if let Ok(run) = self.run_context.as_ref() {
            crate::tools::retire_run(run);
        }
    }
}

/// Owned call parameters for one spawned API turn.
struct ApiTurnParams {
    run_context: std::sync::Arc<crate::tools::ToolRunContext>,
    session_messages: Vec<serde_json::Value>,
    provider_native_state: Option<crate::runtime::ProviderNativeState>,
    client: reqwest::Client,
    endpoint: String,
    headers: crate::secrets::SensitiveHeaders,
    provider: String,
    model: String,
    effort_level: EffortLevel,
    wire_api: crate::pipeline::WireApi,
    claude_code_token: Option<crate::secrets::OAuthToken>,
    claude_agent_sdk: Option<crate::claude_agent_sdk::ClaudeAgentSdk>,
    codex_agent_sdk: Option<crate::codex_agent_sdk::CodexAgentSdk>,
    prompt_blocks: Option<crate::prompt::SystemPromptBlocks>,
    memory_db: Option<std::sync::Arc<crate::memory::MemoryDb>>,
    app_config: Option<std::sync::Arc<crate::config::AppConfig>>,
    permission_mgr: Option<std::sync::Arc<crate::permissions::PermissionManager>>,
    vdd_engine: Option<std::sync::Arc<crate::vdd::VddEngine>>,
    vdd_builder_auth: crate::vdd::VddProviderAuth,
    transient_allowed_tool_rules: Vec<crate::permissions::PermissionRule>,
    hook_engine: Option<std::sync::Arc<crate::hooks::HookEngine>>,
    policy_enforcer: std::sync::Arc<crate::services::policy::PolicyEnforcer>,
    task_mgr: std::sync::Arc<std::sync::Mutex<crate::session::TaskManager>>,
    mcp_manager: Option<std::sync::Arc<tokio::sync::RwLock<crate::mcp::McpManager>>>,
    session_id: String,
    tx: std::sync::mpsc::Sender<super::events::AppEvent>,
}

struct InitialTurnRequest<'a> {
    run_context: &'a std::sync::Arc<crate::tools::ToolRunContext>,
    session_id: &'a str,
    session_messages: &'a [serde_json::Value],
    provider_native_state: Option<&'a crate::runtime::ProviderNativeState>,
    policy_enforcer: &'a std::sync::Arc<crate::services::policy::PolicyEnforcer>,
    model: &'a str,
    wire_api: crate::pipeline::WireApi,
    provider: &'a str,
    effort_level: EffortLevel,
    claude_code_token: Option<&'a crate::secrets::OAuthToken>,
    prompt_blocks: Option<&'a crate::prompt::SystemPromptBlocks>,
    hook_engine: Option<&'a crate::hooks::HookEngine>,
    mcp_manager: Option<&'a std::sync::Arc<tokio::sync::RwLock<crate::mcp::McpManager>>>,
    tx: &'a std::sync::mpsc::Sender<super::events::AppEvent>,
}

struct PreparedInitialTurn {
    task_obs: Option<crate::ledger::ObsId>,
    request_body: serde_json::Value,
}

/// Shared context threaded through the agentic follow-up loop.
struct AgenticCtx<'a> {
    run_context: &'a std::sync::Arc<crate::tools::ToolRunContext>,
    client: &'a reqwest::Client,
    endpoint: &'a str,
    headers: &'a crate::secrets::SensitiveHeaders,
    provider: &'a str,
    model: &'a str,
    effort_level: &'a str,
    wire_api: crate::pipeline::WireApi,
    claude_code_token: Option<&'a crate::secrets::OAuthToken>,
    claude_agent_sdk: Option<&'a crate::claude_agent_sdk::ClaudeAgentSdk>,
    codex_agent_sdk: Option<&'a crate::codex_agent_sdk::CodexAgentSdk>,
    prompt_blocks: Option<&'a crate::prompt::SystemPromptBlocks>,
    memory_db: Option<std::sync::Arc<crate::memory::MemoryDb>>,
    app_config: Option<std::sync::Arc<crate::config::AppConfig>>,
    permission_mgr: Option<std::sync::Arc<crate::permissions::PermissionManager>>,
    transient_allowed_tool_rules: &'a [crate::permissions::PermissionRule],
    hook_engine: Option<std::sync::Arc<crate::hooks::HookEngine>>,
    policy_enforcer: std::sync::Arc<crate::services::policy::PolicyEnforcer>,
    task_mgr: std::sync::Arc<std::sync::Mutex<crate::session::TaskManager>>,
    speculation: std::sync::Arc<crate::speculation::SpeculationCoordinator>,
    mcp_manager: Option<&'a std::sync::Arc<tokio::sync::RwLock<crate::mcp::McpManager>>>,
    session_id: &'a str,
    task_obs: Option<crate::ledger::ObsId>,
    tx: &'a std::sync::mpsc::Sender<super::events::AppEvent>,
}

fn latest_user_message_content(messages: &[serde_json::Value]) -> Option<&str> {
    messages.iter().rev().find_map(|message| {
        (message.get("role").and_then(|role| role.as_str()) == Some("user"))
            .then(|| message.get("content").and_then(|content| content.as_str()))
            .flatten()
    })
}

fn provider_state_after_turn(
    wire_api: crate::pipeline::WireApi,
    requires_responses_native_state: bool,
    previous: Option<&crate::runtime::ProviderNativeState>,
    returned: Option<crate::runtime::ProviderNativeState>,
) -> Result<Option<crate::runtime::ProviderNativeState>, String> {
    if wire_api == crate::pipeline::WireApi::OpenAiResponses && requires_responses_native_state {
        return returned.map(Some).ok_or_else(|| {
            "Responses turn completed without native continuation state".to_string()
        });
    }
    if wire_api == crate::pipeline::WireApi::OpenAiResponses {
        return Ok(returned);
    }
    Ok(returned.or_else(|| previous.cloned()))
}

fn latest_assistant_message_content(messages: &[serde_json::Value]) -> Option<&str> {
    messages.iter().rev().find_map(|message| {
        (message.get("role").and_then(|role| role.as_str()) == Some("assistant"))
            .then(|| message.get("content").and_then(|content| content.as_str()))
            .flatten()
    })
}

fn replace_latest_assistant_message_content(
    messages: &mut [serde_json::Value],
    content: String,
) -> bool {
    let Some(message) = messages.iter_mut().rev().find(|message| {
        message.get("role").and_then(serde_json::Value::as_str) == Some("assistant")
    }) else {
        return false;
    };
    let Some(message) = message.as_object_mut() else {
        return false;
    };
    message.insert("content".to_string(), serde_json::Value::String(content));
    true
}

fn observe_turn_user_task(
    run: &crate::tools::ToolRunContext,
    session_id: &str,
    messages: &[serde_json::Value],
    model_identity: &str,
) -> Option<crate::ledger::ObsId> {
    let content = latest_user_message_content(messages)?;
    crate::grounded_loop::observe_session_user_task(run, session_id, content, model_identity)
}

fn request_messages_with_grounding(
    run: &crate::tools::ToolRunContext,
    session_id: &str,
    task_obs: Option<crate::ledger::ObsId>,
    session_messages: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, String> {
    let mut messages = crate::grounded_loop::request_messages_with_grounding(
        run,
        session_id,
        task_obs,
        session_messages,
    )?;
    let normalized = crate::pipeline::normalize_message_tool_arguments_for_history(&mut messages);
    if normalized > 0 {
        tracing::warn!(
            normalized,
            session_id,
            "normalized malformed historical tool-call arguments before provider request"
        );
    }
    Ok(messages)
}

fn validate_and_render_agentic_final_response(
    run: &crate::tools::ToolRunContext,
    session_id: &str,
    content: &str,
    model_identity: &str,
) -> Result<String, String> {
    crate::grounded_loop::validate_and_render_agentic_final_response(
        run,
        session_id,
        content,
        model_identity,
    )
}

fn render_final_response_for_history(
    run: &crate::tools::ToolRunContext,
    session_id: &str,
    content: &str,
    model_identity: &str,
) -> Result<String, String> {
    if content.trim().is_empty() {
        return Ok(String::new());
    }
    match validate_and_render_agentic_final_response(
        run,
        session_id,
        content.trim(),
        model_identity,
    ) {
        Ok(rendered) => Ok(rendered),
        Err(reason) => {
            tracing::warn!(
                session_id,
                reason = %reason,
                "final answer rejected by grounding gate"
            );
            Err(reason)
        }
    }
}

fn render_live_final_response_for_display(
    run: &crate::tools::ToolRunContext,
    session_id: &str,
    content: &str,
    model_identity: &str,
) -> Option<String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Some(String::new());
    }
    render_final_response_for_history(run, session_id, trimmed, model_identity).ok()
}

fn check_provider_request_policy_for_messages(
    run: &crate::tools::ToolRunContext,
    policy_enforcer: &crate::services::policy::PolicyEnforcer,
    model: &str,
    messages: &[serde_json::Value],
    tx: &std::sync::mpsc::Sender<super::events::AppEvent>,
    session_id: &str,
) -> bool {
    let request = match crate::pipeline::build_chat_completion_request_for_run(run, model, messages)
    {
        Ok(request) => request,
        Err(e) => {
            send_or_warn(
                tx,
                super::events::AppEvent::ApiError(format!("Request build error: {e}").into()),
                session_id,
            );
            return false;
        }
    };
    let estimated_input = crate::compaction::estimate_request_tokens(&request);
    let gate = crate::services::policy::ProviderRequestPolicy::new(policy_enforcer.policy());
    match gate.check(crate::services::policy::ProviderRequestPolicyInput::new(
        &request.model,
        estimated_input,
        request.max_tokens,
        0,
    )) {
        Ok(()) => true,
        Err(err) => {
            send_or_warn(
                tx,
                super::events::AppEvent::ApiError(format!("Blocked by policy: {err}").into()),
                session_id,
            );
            false
        }
    }
}

/// Run the pre-turn `UserPromptSubmit` hook. Returns `false` and sends an
/// `ApiError` event if the hook denies the request; allowed model-visible
/// outputs are appended as typed reference data.
async fn run_preturn_hooks(
    run_context: &std::sync::Arc<crate::tools::ToolRunContext>,
    engine: &crate::hooks::HookEngine,
    session_messages: &mut Vec<serde_json::Value>,
    tx: &std::sync::mpsc::Sender<super::events::AppEvent>,
) -> bool {
    let user_prompt = session_messages
        .last()
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let hook_input =
        crate::hooks::HookInput::for_run(run_context, crate::hooks::HookEvent::UserPromptSubmit)
            .with_prompt(&user_prompt);
    let hook_receipt = engine
        .run_lifecycle(crate::hooks::HookEvent::UserPromptSubmit, &hook_input)
        .await;
    if let Some(reason) = hook_receipt.blocking_reason() {
        let _ = tx.send(super::events::AppEvent::ApiError(
            format!("Blocked by hook: {reason}").into(),
        ));
        return false;
    }
    let hook_result = hook_receipt.into_result();
    let hook_items =
        crate::context::hook_result_reference_items(&hook_result, "user_prompt_submit", 500);
    if !hook_items.is_empty() {
        let projection = crate::context::ContextProjector::project(
            hook_items,
            crate::context::ContextBudget::default(),
        );
        append_context_reference_message(
            session_messages,
            &projection.reference,
            "user_prompt_submit_hook",
        );
    }
    true
}

/// Send an event to the TUI event channel, capturing partial in-flight state
/// when the channel has been closed (e.g. user pressed Esc or the app is
/// shutting down).
///
/// Crosslink #765: previously every `tx.send(...)` site was `let _ = ...`,
/// which silently dropped both the event and any unflushed work — for
/// `SyncSession` that meant the entire accumulated `session_messages` vector
/// vanished, leaving the next turn to retry from a stale baseline. We now
/// `tracing::warn!` with the event kind and any partial-state counts so an
/// operator running with `RUST_LOG=warn` has a forensic trail. We also
/// best-effort persist the messages to disk so a subsequent run can recover.
fn send_or_warn(
    tx: &std::sync::mpsc::Sender<super::events::AppEvent>,
    event: super::events::AppEvent,
    session_id: &str,
) {
    // Snapshot kind/sizes BEFORE moving the event into `send`, so the warn
    // path can describe what was lost without owning the value.
    let descriptor = describe_event(&event);
    let partial_state = match &event {
        super::events::AppEvent::SyncSession {
            session_id: _,
            messages,
            provider_native_state,
        } => Some((messages.clone(), provider_native_state.clone())),
        _ => None,
    };
    if tx.send(event).is_err() {
        tracing::warn!(
            event = %descriptor,
            session_id = %session_id,
            "TUI event channel closed; partial turn state being persisted to recovery file"
        );
        if let Some((messages, provider_native_state)) = partial_state {
            persist_orphan_session(session_id, &messages, provider_native_state.as_ref());
        }
    }
}

fn send_api_error(
    tx: &std::sync::mpsc::Sender<super::events::AppEvent>,
    error: String,
    session_id: &str,
) {
    send_or_warn(
        tx,
        super::events::AppEvent::ApiError(error.into()),
        session_id,
    );
}

/// Build the line list for the `ask_user_question` modal overlay.
///
/// Pure render — no `&self` access, no state mutation. Extracted from
/// `App::draw_user_question_overlay` to keep that method under the
/// clippy `too_many_lines` threshold while still rendering the full
/// REPL-parity option list (question header + numbered options +
/// synthetic "Other" row + prompt buffer + footer hint).
fn build_user_question_lines<'a>(
    pq: &'a PendingUserQuestion,
    q: &'a serde_json::Value,
    options: &'a [serde_json::Value],
    multi_select: bool,
) -> Vec<Line<'a>> {
    let question_text = q.get("question").and_then(|v| v.as_str()).unwrap_or("?");
    let header = q.get("header").and_then(|v| v.as_str()).unwrap_or("");
    let other_num = options.len() + 1;

    let mut lines: Vec<Line<'a>> = Vec::with_capacity(options.len() + 8);

    // Question header line.
    let header_span = if header.is_empty() {
        String::new()
    } else {
        format!("[{header}] ")
    };
    lines.push(Line::from(Span::styled(
        format!(
            "  Question {}/{}: {header_span}{question_text}",
            pq.current_index + 1,
            pq.questions.len()
        ),
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    // Numbered options.
    for (i, opt) in options.iter().enumerate() {
        let label = opt.get("label").and_then(|v| v.as_str()).unwrap_or("?");
        let desc = opt
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        lines.push(Line::from(vec![
            Span::styled(
                format!("  [{}] ", i + 1),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{label}  ")),
            Span::styled(desc.to_string(), Style::default().fg(Color::DarkGray)),
        ]));
    }

    // Synthetic "Other" row.
    lines.push(Line::from(vec![
        Span::styled(
            format!("  [{other_num}] "),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Other "),
        Span::styled(
            "(type your answer)".to_string(),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    lines.push(Line::from(""));

    // Prompt line — show what the user is typing right now.
    let prompt_label = if pq.other_mode {
        "  Your answer: "
    } else if multi_select {
        "  > (comma-separated numbers) "
    } else {
        "  > "
    };
    lines.push(Line::from(vec![
        Span::styled(
            prompt_label,
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(pq.input_buffer.clone()),
        Span::styled("_", Style::default().fg(Color::Green)),
    ]));

    // Footer hint.
    lines.push(Line::from(Span::styled(
        "  Enter = submit   Esc = cancel".to_string(),
        Style::default().fg(Color::DarkGray),
    )));

    lines
}

fn format_api_retry_delay(delay_ms: u64) -> String {
    if delay_ms.is_multiple_of(1_000) {
        format!("{}s", delay_ms / 1_000)
    } else {
        let seconds = delay_ms / 1_000;
        let hundredths = (delay_ms % 1_000) / 10;
        format!("{seconds}.{hundredths:02}s")
    }
}

fn format_api_retry_message(
    kind: ApiRetryKind,
    attempt: u32,
    max_attempts: u32,
    delay_ms: u64,
    status: Option<u16>,
) -> String {
    let delay = format_api_retry_delay(delay_ms);
    match kind {
        ApiRetryKind::Transport => {
            format!("API retry {attempt}/{max_attempts} in {delay} after transport error")
        }
        ApiRetryKind::Status => {
            let status = status.map_or_else(|| "unknown status".to_string(), |s| s.to_string());
            format!("API retry {attempt}/{max_attempts} in {delay} after HTTP {status}")
        }
    }
}

fn format_stream_timeout_message(elapsed_secs: u64, timeout_secs: u64) -> String {
    format!("Stream timed out after {elapsed_secs}s without new data (timeout {timeout_secs}s)")
}

/// One-line human-readable description of an `AppEvent` for the
/// channel-closed warning. We avoid `Debug` since `AppEvent` doesn't derive
/// it and adding the derive would ripple through the rest of the file.
fn describe_event(event: &super::events::AppEvent) -> String {
    match event {
        super::events::AppEvent::Correlated { call_id, event } => {
            format!("Correlated({call_id}, {})", describe_event(event))
        }
        super::events::AppEvent::SyncSession {
            session_id,
            messages,
            provider_native_state,
        } => {
            format!(
                "SyncSession(session={session_id},n={},native={})",
                messages.len(),
                provider_native_state.is_some()
            )
        }
        super::events::AppEvent::ResponseDone => "ResponseDone".to_string(),
        super::events::AppEvent::ApiError(e) => {
            let snippet: String = e.as_str().chars().take(80).collect();
            format!("ApiError({snippet:?})")
        }
        super::events::AppEvent::PluginAgentDone { label, result } => {
            format!("PluginAgentDone({label}, ok={})", result.success)
        }
        super::events::AppEvent::ApiRetry {
            kind,
            attempt,
            max_attempts,
            ..
        } => {
            format!("ApiRetry({kind:?},{attempt}/{max_attempts})")
        }
        super::events::AppEvent::StreamTimeout {
            elapsed_secs,
            timeout_secs,
        } => {
            format!("StreamTimeout({elapsed_secs}/{timeout_secs}s)")
        }
        super::events::AppEvent::StreamText(_) => "StreamText".to_string(),
        super::events::AppEvent::StreamThinking(_) => "StreamThinking".to_string(),
        super::events::AppEvent::ToolStart { name, .. } => format!("ToolStart({name})"),
        super::events::AppEvent::ToolDone { name, success, .. } => {
            format!("ToolDone({name}, ok={success})")
        }
        super::events::AppEvent::WorkspaceTransition { .. } => "WorkspaceTransition".to_string(),
        super::events::AppEvent::FollowUp => "FollowUp".to_string(),
        super::events::AppEvent::PermissionRequest { tool_name, .. } => {
            format!("PermissionRequest({tool_name})")
        }
        super::events::AppEvent::UserQuestion { questions, .. } => {
            format!("UserQuestion(n={})", questions.len())
        }
        super::events::AppEvent::PlanModeRequest { request, .. } => {
            format!("PlanModeRequest({request:?})")
        }
        super::events::AppEvent::Key(_) => "Key".to_string(),
        super::events::AppEvent::Paste(text) => {
            format!("Paste(chars={})", text.chars().count())
        }
        super::events::AppEvent::Resize(w, h) => format!("Resize({w},{h})"),
        super::events::AppEvent::Tick => "Tick".to_string(),
        super::events::AppEvent::ShellDone { target, .. } => {
            format!("ShellDone({target:?})")
        }
        super::events::AppEvent::OverloadFallback { model_hint } => {
            format!("OverloadFallback({model_hint})")
        }
        super::events::AppEvent::ProviderSwitchReady(switch) => {
            format!("ProviderSwitchReady({})", switch.provider)
        }
        super::events::AppEvent::ProviderSwitchError(e) => {
            let snippet: String = e.chars().take(80).collect();
            format!("ProviderSwitchError({snippet:?})")
        }
        super::events::AppEvent::ModelListReady {
            provider, models, ..
        } => {
            format!("ModelListReady({provider}, {} models)", models.len())
        }
        super::events::AppEvent::ModelListError {
            provider, message, ..
        } => {
            let snippet: String = message.chars().take(80).collect();
            format!("ModelListError({provider}, {snippet:?})")
        }
    }
}

/// Best-effort persist both lanes of an orphaned session turn to a recovery
/// file so a later recovery tool cannot replay flattened provider state.
/// Failures here are logged but not propagated — we are already on the
/// shutdown path.
fn persist_orphan_session(
    session_id: &str,
    messages: &[serde_json::Value],
    provider_native_state: Option<&crate::runtime::ProviderNativeState>,
) {
    let Some(data_dir) = dirs::data_dir() else {
        tracing::warn!("no data_dir available; cannot persist orphan session state");
        return;
    };
    let dir = data_dir.join("openclaudia").join("orphan-turns");
    if let Err(e) = create_orphan_recovery_dir(&dir) {
        tracing::warn!(error = %e, dir = %dir.display(), "failed to create orphan-turn dir");
        return;
    }
    let ts = chrono::Utc::now().timestamp_millis();
    let safe_id: String = session_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = dir.join(format!("{safe_id}-{ts}-{}.json", uuid::Uuid::new_v4()));
    let recovery = serde_json::json!({
        "schema_version": 1,
        "session_id": session_id,
        "messages": messages,
        "provider_native_state": provider_native_state
    });
    match serde_json::to_string_pretty(&recovery) {
        Ok(json) => {
            if let Err(e) = write_orphan_recovery_file(&path, json.as_bytes()) {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "failed to write orphan session state"
                );
            } else {
                tracing::warn!(
                    path = %path.display(),
                    n_messages = messages.len(),
                    has_provider_native_state = provider_native_state.is_some(),
                    "persisted orphan session state to recovery file"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to serialize orphan session state for recovery"
            );
        }
    }
}

fn create_orphan_recovery_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "orphan recovery directory is not a real directory",
            ));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "orphan recovery directory is not a real directory",
            ));
        }
    }
    Ok(())
}

fn write_orphan_recovery_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Drive the agentic follow-up loop until the model stops requesting tools
/// or `MAX_ITER` iterations are exhausted.
#[allow(clippy::too_many_lines)]
async fn run_agentic_loop(
    ctx: &AgenticCtx<'_>,
    session_messages: &mut Vec<serde_json::Value>,
    provider_native_state: &mut Option<crate::runtime::ProviderNativeState>,
) -> Result<std::sync::Arc<crate::tools::ToolRunContext>, String> {
    const MAX_ITER: u32 = 25;
    let mut iteration = 0u32;
    let mut run_context = std::sync::Arc::clone(ctx.run_context);
    let mut permission_mgr = ctx.permission_mgr.clone();
    let mut task_mgr = std::sync::Arc::clone(&ctx.task_mgr);
    let mut speculation = std::sync::Arc::clone(&ctx.speculation);
    let mut mcp_manager = ctx.mcp_manager;
    let mut task_obs = ctx.task_obs;
    loop {
        iteration += 1;
        tracing::debug!(iteration, "Agentic loop iteration");
        if iteration > MAX_ITER {
            send_or_warn(
                ctx.tx,
                super::events::AppEvent::ApiError("Reached maximum tool iterations (25)".into()),
                ctx.session_id,
            );
            return Err("Reached maximum tool iterations (25)".to_string());
        }
        let request_messages = match request_messages_with_grounding(
            &run_context,
            ctx.session_id,
            task_obs,
            session_messages,
        ) {
            Ok(messages) => messages,
            Err(e) => {
                tracing::error!(error = %e, "Failed to build grounded agentic follow-up request");
                send_or_warn(
                    ctx.tx,
                    super::events::AppEvent::ApiError(e.clone().into()),
                    ctx.session_id,
                );
                return Err(e);
            }
        };
        if !check_provider_request_policy_for_messages(
            &run_context,
            &ctx.policy_enforcer,
            ctx.model,
            &request_messages,
            ctx.tx,
            ctx.session_id,
        ) {
            return Err("Provider request blocked by policy".to_string());
        }
        let body = match build_request_with_live_mcp(LiveMcpRequest {
            run: &run_context,
            wire_api: ctx.wire_api,
            provider: ctx.provider,
            model: ctx.model,
            messages: &request_messages,
            effort_level: ctx.effort_level,
            claude_code_token: ctx.claude_code_token,
            prompt_blocks: ctx.prompt_blocks,
            provider_native_state: provider_native_state.as_ref(),
            hook_engine: ctx.hook_engine.as_deref(),
            mcp_manager,
        })
        .await
        {
            Ok(body) => body,
            Err(e) => {
                tracing::error!(error = %e, "Failed to build agentic follow-up request");
                send_or_warn(
                    ctx.tx,
                    super::events::AppEvent::ApiError(e.clone().into()),
                    ctx.session_id,
                );
                return Err(e);
            }
        };
        let assistant_message_ordinal =
            match crate::pipeline::next_assistant_message_ordinal(session_messages) {
                Ok(ordinal) => ordinal,
                Err(error) => {
                    send_or_warn(
                        ctx.tx,
                        super::events::AppEvent::ApiError(error.clone().into()),
                        ctx.session_id,
                    );
                    return Err(error);
                }
            };
        match crate::pipeline::run_turn_with_speculation(
            crate::pipeline::RunTurnParams {
                run_context: std::sync::Arc::clone(&run_context),
                client: ctx.client,
                endpoint: ctx.endpoint,
                headers: ctx.headers,
                claude_agent_sdk: ctx.claude_agent_sdk,
                codex_agent_sdk: ctx.codex_agent_sdk,
                effort_level: ctx.effort_level,
                request_body: &body,
                provider: ctx.provider,
                model_identity: ctx.model,
                provider_native_state: provider_native_state.as_ref(),
                assistant_message_ordinal,
                memory_db: ctx.memory_db.clone(),
                app_config: ctx.app_config.clone(),
                permission_mgr: permission_mgr.clone(),
                transient_allowed_tool_rules: ctx.transient_allowed_tool_rules,
                hook_engine: ctx.hook_engine.clone(),
                policy_enforcer: Some(std::sync::Arc::clone(&ctx.policy_enforcer)),
                task_mgr: std::sync::Arc::clone(&task_mgr),
                session_id: Some(ctx.session_id.to_string()),
                tx: ctx.tx.clone(),
            },
            Some(std::sync::Arc::clone(&speculation)),
        )
        .await
        {
            Ok(mut followup) => {
                tracing::debug!(
                    content_len = followup.content.len(),
                    tool_calls = followup.tool_calls.len(),
                    needs_followup = followup.needs_followup,
                    "Follow-up result"
                );
                let next_provider_state = match provider_state_after_turn(
                    ctx.wire_api,
                    ctx.codex_agent_sdk.is_none(),
                    provider_native_state.as_ref(),
                    followup.provider_native_state.take(),
                ) {
                    Ok(state) => state,
                    Err(error) => {
                        send_or_warn(
                            ctx.tx,
                            super::events::AppEvent::ApiError(error.clone().into()),
                            ctx.session_id,
                        );
                        return Err(error);
                    }
                };
                if let Some(bindings) = followup.execution_bindings.take() {
                    let run_changed = !std::sync::Arc::ptr_eq(&run_context, &bindings.run_context);
                    if run_changed {
                        // The application event owns deterministic MCP/LSP
                        // reconstruction for the new run. Until that arrives,
                        // omit the stale manager from this immediate follow-up.
                        mcp_manager = None;
                        task_obs =
                            latest_user_message_content(session_messages).and_then(|content| {
                                crate::grounded_loop::observe_session_user_task(
                                    &bindings.run_context,
                                    ctx.session_id,
                                    content,
                                    ctx.model,
                                )
                            });
                    }
                    run_context = bindings.run_context;
                    permission_mgr = bindings.permission_mgr;
                    task_mgr = bindings.task_mgr;
                    speculation = bindings.speculation;
                }
                if followup.needs_followup {
                    let asst = crate::pipeline::build_assistant_message_with_tools(
                        &followup.content,
                        followup.reasoning_content.as_deref(),
                        &followup.tool_calls,
                        ctx.provider,
                    );
                    session_messages.push(asst);
                    session_messages.extend(followup.tool_results.iter().cloned());
                    *provider_native_state = next_provider_state;
                } else {
                    let reasoning = followup
                        .reasoning_content
                        .as_deref()
                        .filter(|text| !text.is_empty());
                    if followup.content.is_empty() {
                        let error = "Provider completed the follow-up without assistant content";
                        send_or_warn(
                            ctx.tx,
                            super::events::AppEvent::ApiError(error.into()),
                            ctx.session_id,
                        );
                        return Err(error.to_string());
                    }
                    let rendered_content = match render_final_response_for_history(
                        &run_context,
                        ctx.session_id,
                        &followup.content,
                        ctx.model,
                    ) {
                        Ok(rendered) => rendered,
                        Err(reason) => {
                            send_or_warn(
                                ctx.tx,
                                super::events::AppEvent::ApiError(
                                    format!("Final answer failed grounding gate: {reason}").into(),
                                ),
                                ctx.session_id,
                            );
                            return Err(format!("Final answer failed grounding gate: {reason}"));
                        }
                    };
                    let mut message = serde_json::json!({
                        "role": "assistant",
                        "content": rendered_content
                    });
                    if let Some(reasoning) = reasoning {
                        message["reasoning_content"] =
                            serde_json::Value::String(reasoning.to_string());
                    }
                    session_messages.push(message);
                    *provider_native_state = next_provider_state;
                    return Ok(run_context);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Agentic follow-up failed");
                send_or_warn(
                    ctx.tx,
                    super::events::AppEvent::ApiError(e.clone().into()),
                    ctx.session_id,
                );
                // The caller's `SyncSession` send after the loop will trigger
                // recovery persistence if the channel is closed — no extra
                // action needed here for partial-state capture.
                return Err(e);
            }
        }
    }
}

async fn build_initial_turn_request(p: &InitialTurnRequest<'_>) -> Option<PreparedInitialTurn> {
    let task_obs = observe_turn_user_task(p.run_context, p.session_id, p.session_messages, p.model);
    let request_messages = match request_messages_with_grounding(
        p.run_context,
        p.session_id,
        task_obs,
        p.session_messages,
    ) {
        Ok(messages) => messages,
        Err(e) => {
            send_or_warn(
                p.tx,
                super::events::AppEvent::ApiError(e.into()),
                p.session_id,
            );
            return None;
        }
    };
    if !check_provider_request_policy_for_messages(
        p.run_context,
        p.policy_enforcer,
        p.model,
        &request_messages,
        p.tx,
        p.session_id,
    ) {
        return None;
    }
    match build_request_with_live_mcp(LiveMcpRequest {
        run: p.run_context,
        wire_api: p.wire_api,
        provider: p.provider,
        model: p.model,
        messages: &request_messages,
        effort_level: p.effort_level.as_str(),
        claude_code_token: p.claude_code_token,
        prompt_blocks: p.prompt_blocks,
        provider_native_state: p.provider_native_state,
        hook_engine: p.hook_engine,
        mcp_manager: p.mcp_manager,
    })
    .await
    {
        Ok(request_body) => Some(PreparedInitialTurn {
            task_obs,
            request_body,
        }),
        Err(e) => {
            send_or_warn(
                p.tx,
                super::events::AppEvent::ApiError(e.into()),
                p.session_id,
            );
            None
        }
    }
}

struct LiveMcpRequest<'a> {
    run: &'a std::sync::Arc<crate::tools::ToolRunContext>,
    wire_api: crate::pipeline::WireApi,
    provider: &'a str,
    model: &'a str,
    messages: &'a [serde_json::Value],
    effort_level: &'a str,
    claude_code_token: Option<&'a crate::secrets::OAuthToken>,
    prompt_blocks: Option<&'a crate::prompt::SystemPromptBlocks>,
    provider_native_state: Option<&'a crate::runtime::ProviderNativeState>,
    hook_engine: Option<&'a crate::hooks::HookEngine>,
    mcp_manager: Option<&'a std::sync::Arc<tokio::sync::RwLock<crate::mcp::McpManager>>>,
}

// Catalog publication, causal projection, and wire construction are one
// transaction: no intermediate catalog or message view may escape.
#[allow(clippy::too_many_lines)]
async fn build_request_with_live_mcp(
    request: LiveMcpRequest<'_>,
) -> Result<serde_json::Value, String> {
    let definitions = if let Some(manager) = request.mcp_manager {
        let manager = manager.read().await;
        if !manager.matches_run(request.run) {
            return Err("MCP manager belongs to a different run generation".to_string());
        }
        let snapshot = manager.tool_catalog_snapshot().await;
        drop(manager);
        tracing::debug!(
            target: "openclaudia::mcp",
            event = "mcp_tool_catalog_snapshot",
            run_id = %request.run.run_id(),
            capability_generation = %request.run.generation(),
            mcp_catalog_generation = %snapshot.generation,
            callable = snapshot.definitions.len(),
            unavailable = snapshot.unavailable.len(),
            "Built exact MCP dynamic tool snapshot"
        );
        for item in &snapshot.unavailable {
            tracing::warn!(
                target: "openclaudia::mcp",
                server = %item.server,
                tool = %item.tool,
                reason = %item.reason,
                "MCP tool is unavailable in this run generation"
            );
        }
        snapshot.definitions
    } else {
        Vec::new()
    };
    let catalog = crate::tools::get_progressive_tool_definitions_with_additional(
        request.run,
        request.messages,
        true,
        &definitions,
    )?;
    let typed_messages = request
        .messages
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<Vec<crate::proxy::ChatMessage>, _>>()
        .map_err(|error| format!("Invalid context message before compaction: {error}"))?;
    let mut compactable = crate::proxy::ChatCompletionRequest {
        model: request.model.to_string(),
        messages: typed_messages,
        temperature: None,
        max_tokens: Some(4_096),
        stream: Some(true),
        tools: Some(catalog.definitions.clone()),
        tool_choice: None,
        extra: std::collections::HashMap::new(),
    };
    let compactor = crate::services::AutoCompactor::auto(
        crate::compaction::ContextCompactor::for_model(request.model),
    );
    let needs_compaction = compactor.should_compact(&compactable, None);
    match crate::compaction::provider_state_compaction_disposition(
        request.wire_api.is_responses(),
        needs_compaction,
        request.provider_native_state,
    ) {
        crate::compaction::ProviderStateCompactionDisposition::ProviderManaged => {}
        crate::compaction::ProviderStateCompactionDisposition::BlocksPortableCheckpoint => {
            return Err(
                "Context needs compaction, but the provider-native continuation is bound to the exact message history and this protocol has no native compaction contract"
                    .to_string(),
            );
        }
        crate::compaction::ProviderStateCompactionDisposition::Absent
        | crate::compaction::ProviderStateCompactionDisposition::Preserved => {
            if let Some(result) = compactor
                .auto_compact(
                    &mut compactable,
                    None,
                    request.hook_engine,
                    request.run,
                    Some(request.run.session_id()),
                    None,
                )
                .await
                .map_err(|error| format!("Context checkpoint failed: {error}"))?
            {
                if matches!(
                    result.disposition,
                    crate::compaction::CompactionDisposition::Partial
                        | crate::compaction::CompactionDisposition::CannotFit
                ) {
                    return Err(format!(
                        "Context cannot fit after checkpoint: {} tokens remain for target {}",
                        result.new_tokens, result.target_tokens
                    ));
                }
            }
        }
    }
    let projected_messages = compactable
        .messages
        .into_iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Cannot encode compacted context: {error}"))?;
    crate::pipeline::build_request_for_wire_with_exact_tools_and_state(
        request.wire_api,
        request.provider,
        request.model,
        &projected_messages,
        request.effort_level,
        request.claude_code_token,
        request.prompt_blocks,
        &catalog.definitions,
        request.provider_native_state,
    )
}

/// Run a complete API turn: pre-turn hooks, first `run_turn`, and an agentic
/// follow-up loop when tool calls are present.
async fn run_api_turn_async(mut p: ApiTurnParams) {
    if let Some(ref engine) = p.hook_engine {
        if !run_preturn_hooks(&p.run_context, engine, &mut p.session_messages, &p.tx).await {
            return;
        }
    }
    let Some(initial_turn) = build_initial_turn_request(&InitialTurnRequest {
        run_context: &p.run_context,
        session_id: &p.session_id,
        session_messages: &p.session_messages,
        provider_native_state: p.provider_native_state.as_ref(),
        policy_enforcer: &p.policy_enforcer,
        model: &p.model,
        wire_api: p.wire_api,
        provider: &p.provider,
        effort_level: p.effort_level,
        claude_code_token: p.claude_code_token.as_ref(),
        prompt_blocks: p.prompt_blocks.as_ref(),
        hook_engine: p.hook_engine.as_deref(),
        mcp_manager: p.mcp_manager.as_ref(),
        tx: &p.tx,
    })
    .await
    else {
        return;
    };
    let assistant_message_ordinal =
        match crate::pipeline::next_assistant_message_ordinal(&p.session_messages) {
            Ok(ordinal) => ordinal,
            Err(error) => {
                send_api_error(&p.tx, error, &p.session_id);
                return;
            }
        };
    match crate::pipeline::run_turn(crate::pipeline::RunTurnParams {
        run_context: std::sync::Arc::clone(&p.run_context),
        client: &p.client,
        endpoint: &p.endpoint,
        headers: &p.headers,
        claude_agent_sdk: p.claude_agent_sdk.as_ref(),
        codex_agent_sdk: p.codex_agent_sdk.as_ref(),
        effort_level: p.effort_level.as_str(),
        request_body: &initial_turn.request_body,
        provider: &p.provider,
        model_identity: &p.model,
        provider_native_state: p.provider_native_state.as_ref(),
        assistant_message_ordinal,
        memory_db: p.memory_db.clone(),
        app_config: p.app_config.clone(),
        permission_mgr: p.permission_mgr.clone(),
        transient_allowed_tool_rules: &p.transient_allowed_tool_rules,
        hook_engine: p.hook_engine.clone(),
        policy_enforcer: Some(std::sync::Arc::clone(&p.policy_enforcer)),
        task_mgr: p.task_mgr.clone(),
        session_id: Some(p.session_id.clone()),
        tx: p.tx.clone(),
    })
    .await
    {
        Ok(turn_result) => {
            handle_turn_result(
                turn_result,
                p.session_messages,
                TurnContext {
                    run_context: &p.run_context,
                    client: &p.client,
                    endpoint: &p.endpoint,
                    headers: &p.headers,
                    provider: &p.provider,
                    model: &p.model,
                    effort_level: p.effort_level,
                    wire_api: p.wire_api,
                    claude_code_token: p.claude_code_token.as_ref(),
                    claude_agent_sdk: p.claude_agent_sdk.as_ref(),
                    codex_agent_sdk: p.codex_agent_sdk.as_ref(),
                    prompt_blocks: p.prompt_blocks.as_ref(),
                    provider_native_state: p.provider_native_state,
                    memory_db: p.memory_db,
                    app_config: p.app_config,
                    permission_mgr: p.permission_mgr,
                    vdd_engine: p.vdd_engine,
                    vdd_builder_auth: &p.vdd_builder_auth,
                    transient_allowed_tool_rules: &p.transient_allowed_tool_rules,
                    hook_engine: p.hook_engine,
                    policy_enforcer: p.policy_enforcer,
                    task_mgr: p.task_mgr,
                    mcp_manager: p.mcp_manager,
                    session_id: &p.session_id,
                    task_obs: initial_turn.task_obs,
                    tx: &p.tx,
                },
            )
            .await;
        }
        Err(e) => send_api_error(&p.tx, e, &p.session_id),
    }
}

/// Borrowed context bundle for [`handle_turn_result`] — purely a plumbing
/// struct to keep `run_api_turn_async` under the line-count lint while
/// preserving the per-iteration data each branch needs.
struct TurnContext<'a> {
    run_context: &'a std::sync::Arc<crate::tools::ToolRunContext>,
    client: &'a reqwest::Client,
    endpoint: &'a str,
    headers: &'a crate::secrets::SensitiveHeaders,
    provider: &'a str,
    model: &'a str,
    effort_level: EffortLevel,
    wire_api: crate::pipeline::WireApi,
    claude_code_token: Option<&'a crate::secrets::OAuthToken>,
    claude_agent_sdk: Option<&'a crate::claude_agent_sdk::ClaudeAgentSdk>,
    codex_agent_sdk: Option<&'a crate::codex_agent_sdk::CodexAgentSdk>,
    prompt_blocks: Option<&'a crate::prompt::SystemPromptBlocks>,
    provider_native_state: Option<crate::runtime::ProviderNativeState>,
    memory_db: Option<std::sync::Arc<crate::memory::MemoryDb>>,
    app_config: Option<std::sync::Arc<crate::config::AppConfig>>,
    permission_mgr: Option<std::sync::Arc<crate::permissions::PermissionManager>>,
    vdd_engine: Option<std::sync::Arc<crate::vdd::VddEngine>>,
    vdd_builder_auth: &'a crate::vdd::VddProviderAuth,
    transient_allowed_tool_rules: &'a [crate::permissions::PermissionRule],
    hook_engine: Option<std::sync::Arc<crate::hooks::HookEngine>>,
    policy_enforcer: std::sync::Arc<crate::services::policy::PolicyEnforcer>,
    task_mgr: std::sync::Arc<std::sync::Mutex<crate::session::TaskManager>>,
    mcp_manager: Option<std::sync::Arc<tokio::sync::RwLock<crate::mcp::McpManager>>>,
    session_id: &'a str,
    task_obs: Option<crate::ledger::ObsId>,
    tx: &'a std::sync::mpsc::Sender<super::events::AppEvent>,
}

/// Handle the successful `Ok(turn_result)` branch of the first `run_turn`:
/// either drive the agentic follow-up loop (when tool calls are present) or
/// push the plain assistant content. Channel-closed errors on the resulting
/// `SyncSession` / `ResponseDone` sends go through [`send_or_warn`] so
/// partial in-flight state is persisted instead of silently dropped.
async fn handle_turn_result(
    turn_result: crate::pipeline::TurnResult,
    session_messages: Vec<serde_json::Value>,
    ctx: TurnContext<'_>,
) {
    if let Err(error) = crate::pipeline::ensure_provider_turn_succeeded(
        turn_result.terminal_outcome,
        turn_result.tool_calls.len(),
    ) {
        send_api_error(ctx.tx, error, ctx.session_id);
        return;
    }
    tracing::debug!(
        content_len = turn_result.content.len(),
        tool_calls = turn_result.tool_calls.len(),
        needs_followup = turn_result.needs_followup,
        "Turn result"
    );
    if turn_result.needs_followup {
        handle_followup_turn(turn_result, session_messages, &ctx).await;
    } else if !turn_result.content.is_empty() {
        handle_direct_turn(turn_result, session_messages, &ctx).await;
    } else {
        send_api_error(
            ctx.tx,
            "Provider returned no assistant content or tool calls".to_string(),
            ctx.session_id,
        );
    }
}

#[allow(clippy::too_many_lines)] // Keep one follow-up's provider state and run rebinding in wire order.
async fn handle_followup_turn(
    mut turn_result: crate::pipeline::TurnResult,
    mut session_messages: Vec<serde_json::Value>,
    ctx: &TurnContext<'_>,
) {
    let mut provider_native_state = match provider_state_after_turn(
        ctx.wire_api,
        ctx.codex_agent_sdk.is_none(),
        ctx.provider_native_state.as_ref(),
        turn_result.provider_native_state.take(),
    ) {
        Ok(state) => state,
        Err(error) => {
            send_api_error(ctx.tx, error, ctx.session_id);
            return;
        }
    };
    let initial_bindings = turn_result.execution_bindings.take().unwrap_or_else(|| {
        crate::pipeline::TurnExecutionBindings {
            run_context: std::sync::Arc::clone(ctx.run_context),
            permission_mgr: ctx.permission_mgr.clone(),
            task_mgr: std::sync::Arc::clone(&ctx.task_mgr),
            speculation: std::sync::Arc::new(crate::speculation::SpeculationCoordinator::for_run(
                ctx.run_context,
            )),
        }
    });
    let initial_run_changed =
        !std::sync::Arc::ptr_eq(ctx.run_context, &initial_bindings.run_context);
    let followup_mcp_manager = if initial_run_changed {
        None
    } else {
        ctx.mcp_manager.as_ref()
    };
    let followup_task_obs = if initial_run_changed {
        latest_user_message_content(&session_messages).and_then(|content| {
            crate::grounded_loop::observe_session_user_task(
                &initial_bindings.run_context,
                ctx.session_id,
                content,
                ctx.model,
            )
        })
    } else {
        ctx.task_obs
    };
    let assistant = crate::pipeline::build_assistant_message_with_tools(
        &turn_result.content,
        turn_result.reasoning_content.as_deref(),
        &turn_result.tool_calls,
        ctx.provider,
    );
    session_messages.push(assistant);
    session_messages.extend(turn_result.tool_results.iter().cloned());
    tracing::info!(
        tool_count = turn_result.tool_calls.len(),
        result_count = turn_result.tool_results.len(),
        "Starting agentic follow-up loop"
    );
    let agentic = AgenticCtx {
        run_context: &initial_bindings.run_context,
        client: ctx.client,
        endpoint: ctx.endpoint,
        headers: ctx.headers,
        provider: ctx.provider,
        model: ctx.model,
        effort_level: ctx.effort_level.as_str(),
        wire_api: ctx.wire_api,
        claude_code_token: ctx.claude_code_token,
        claude_agent_sdk: ctx.claude_agent_sdk,
        codex_agent_sdk: ctx.codex_agent_sdk,
        prompt_blocks: ctx.prompt_blocks,
        memory_db: ctx.memory_db.clone(),
        app_config: ctx.app_config.clone(),
        permission_mgr: initial_bindings.permission_mgr,
        transient_allowed_tool_rules: ctx.transient_allowed_tool_rules,
        hook_engine: ctx.hook_engine.clone(),
        policy_enforcer: std::sync::Arc::clone(&ctx.policy_enforcer),
        task_mgr: initial_bindings.task_mgr,
        speculation: initial_bindings.speculation,
        mcp_manager: followup_mcp_manager,
        session_id: ctx.session_id,
        task_obs: followup_task_obs,
        tx: ctx.tx,
    };
    let Ok(final_run) =
        run_agentic_loop(&agentic, &mut session_messages, &mut provider_native_state).await
    else {
        send_or_warn(
            ctx.tx,
            super::events::AppEvent::SyncSession {
                session_id: ctx.session_id.to_string(),
                messages: session_messages,
                provider_native_state,
            },
            ctx.session_id,
        );
        return;
    };
    if let Some(content) = latest_assistant_message_content(&session_messages).map(str::to_string) {
        match run_tui_vdd_review(ctx, &final_run, content, &session_messages).await {
            Ok((content, observation)) => {
                if !replace_latest_assistant_message_content(&mut session_messages, content) {
                    send_api_error(
                        ctx.tx,
                        "VDD finalized a response without a terminal assistant message".to_string(),
                        ctx.session_id,
                    );
                    return;
                }
                append_tui_vdd_observation(&mut session_messages, observation);
            }
            Err(reason) => {
                send_api_error(ctx.tx, reason, ctx.session_id);
                return;
            }
        }
    }
    send_or_warn(
        ctx.tx,
        super::events::AppEvent::SyncSession {
            session_id: ctx.session_id.to_string(),
            messages: session_messages,
            provider_native_state,
        },
        ctx.session_id,
    );
    send_or_warn(
        ctx.tx,
        super::events::AppEvent::ResponseDone,
        ctx.session_id,
    );
}

async fn handle_direct_turn(
    mut turn_result: crate::pipeline::TurnResult,
    mut session_messages: Vec<serde_json::Value>,
    ctx: &TurnContext<'_>,
) {
    let provider_native_state = match provider_state_after_turn(
        ctx.wire_api,
        ctx.codex_agent_sdk.is_none(),
        ctx.provider_native_state.as_ref(),
        turn_result.provider_native_state.take(),
    ) {
        Ok(state) => state,
        Err(error) => {
            send_api_error(ctx.tx, error, ctx.session_id);
            return;
        }
    };
    let rendered_content = match render_final_response_for_history(
        ctx.run_context,
        ctx.session_id,
        &turn_result.content,
        ctx.model,
    ) {
        Ok(rendered) => rendered,
        Err(reason) => {
            send_or_warn(
                ctx.tx,
                super::events::AppEvent::ApiError(
                    format!("Final answer failed grounding gate: {reason}").into(),
                ),
                ctx.session_id,
            );
            return;
        }
    };
    let (rendered_content, vdd_observation) =
        match run_tui_vdd_review(ctx, ctx.run_context, rendered_content, &session_messages).await {
            Ok(finalized) => finalized,
            Err(reason) => {
                send_api_error(ctx.tx, reason, ctx.session_id);
                return;
            }
        };
    let mut message = serde_json::json!({ "role": "assistant", "content": rendered_content });
    if let Some(reasoning) = turn_result
        .reasoning_content
        .as_deref()
        .filter(|text| !text.is_empty())
    {
        message["reasoning_content"] = serde_json::Value::String(reasoning.to_string());
    }
    session_messages.push(message);
    append_tui_vdd_observation(&mut session_messages, vdd_observation);
    send_or_warn(
        ctx.tx,
        super::events::AppEvent::SyncSession {
            session_id: ctx.session_id.to_string(),
            messages: session_messages,
            provider_native_state,
        },
        ctx.session_id,
    );
    send_or_warn(
        ctx.tx,
        super::events::AppEvent::ResponseDone,
        ctx.session_id,
    );
}

async fn run_tui_vdd_review(
    ctx: &TurnContext<'_>,
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
    content: String,
    session_messages: &[serde_json::Value],
) -> Result<(String, Option<crate::context::ContextItem>), String> {
    let policy = ctx.app_config.as_ref().map_or_else(
        || crate::vdd::VddFinalizationPolicy::from_config(&crate::config::VddConfig::default()),
        |config| crate::vdd::VddFinalizationPolicy::from_config(&config.vdd),
    );
    if policy.requirement() == crate::vdd::VddFinalizationRequirement::Disabled {
        return Ok((content, None));
    }

    send_or_warn(
        ctx.tx,
        super::events::AppEvent::ToolStart {
            name: "vdd".to_string(),
            description: format!("Reviewing response with VDD adversary for {}", ctx.provider),
        },
        ctx.session_id,
    );

    let user_task = latest_user_message_content(session_messages)
        .unwrap_or_default()
        .to_string();
    let builder = crate::vdd::BuilderProvider::with_auth(ctx.provider, ctx.vdd_builder_auth)
        .with_model(ctx.model);
    let scope = format!("tui:{}:{user_task}", ctx.session_id);
    let finalization = crate::vdd::finalize_text_candidate(
        ctx.vdd_engine.as_deref(),
        run,
        &policy,
        content,
        &scope,
        &user_task,
        builder,
    )
    .await;
    let (publication, observation) = finalization.into_parts();
    match publication {
        crate::vdd::VddPublication::Publish(candidate) => {
            let outcome = candidate.outcome();
            let detail = candidate.detail().to_string();
            let content = candidate.into_candidate();
            send_or_warn(
                ctx.tx,
                super::events::AppEvent::ToolDone {
                    name: "vdd".to_string(),
                    success: !matches!(outcome, crate::vdd::VddFinalizationOutcome::FailOpen),
                    content: format!("VDD finalization {outcome:?}: {detail}"),
                },
                ctx.session_id,
            );
            if !content.is_empty() {
                send_or_warn(
                    ctx.tx,
                    super::events::AppEvent::StreamText(content.clone()),
                    ctx.session_id,
                );
            }
            Ok((content, observation))
        }
        crate::vdd::VddPublication::Withhold(withheld) => {
            let reason = format!(
                "VDD finalization withheld assistant success ({:?}): {}",
                withheld.outcome(),
                withheld.detail()
            );
            send_or_warn(
                ctx.tx,
                super::events::AppEvent::ToolDone {
                    name: "vdd".to_string(),
                    success: false,
                    content: reason.clone(),
                },
                ctx.session_id,
            );
            Err(reason)
        }
    }
}

fn append_tui_vdd_observation(
    session_messages: &mut Vec<serde_json::Value>,
    observation: Option<crate::context::ContextItem>,
) {
    let Some(observation) = observation else {
        return;
    };
    let projection = crate::context::ContextProjector::project(
        vec![observation],
        crate::context::ContextBudget::default(),
    );
    append_context_reference_message(session_messages, &projection.reference, "vdd_reference");
}

fn append_context_reference_message(
    messages: &mut Vec<serde_json::Value>,
    reference: &str,
    source: &str,
) {
    if reference.is_empty() {
        return;
    }
    messages.push(serde_json::json!({
        "role": "user",
        "content": reference,
        "metadata": {
            "openclaudia_context_source": source,
            "authority": "reference"
        }
    }));
}

fn canonical_provider_name(provider: &str) -> &str {
    match provider {
        "gemini" => "google",
        "alibaba" => "qwen",
        "zhipu" | "glm" => "zai",
        "moonshot" => "kimi",
        other => other,
    }
}

fn parse_prompt_effort_level(effort: &str) -> Option<EffortLevel> {
    match effort.trim().to_ascii_lowercase().as_str() {
        "none" | "off" => Some(EffortLevel::None),
        "minimal" | "min" => Some(EffortLevel::Minimal),
        "low" | "l" => Some(EffortLevel::Low),
        "medium" | "m" => Some(EffortLevel::Medium),
        "high" | "h" => Some(EffortLevel::High),
        "max" | "x" => Some(EffortLevel::Max),
        "auto" | "unset" => Some(EffortLevel::Auto),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        append_context_reference_message, create_orphan_recovery_dir, format_api_retry_delay,
        format_api_retry_message, format_review_command_output, format_stream_timeout_message,
        handle_turn_result, list_sessions, provider_state_after_turn, read_tui_session_file,
        resolve_provider_switch_auth, save_session, write_orphan_recovery_file, ApiClient, App,
        AppEvent, EffortLevel, MessageKind, Mode, ProviderSwitch, SpawnTarget, TuiSupervisor,
        TuiTaskKind, TurnContext, TEST_SESSIONS_DIR,
    };
    use super::{compile_file_ref_regex, expand_file_refs};
    use crate::slash_commands::all_tui_commands;
    use crate::state::Session;
    use crate::tui::events::{ApiRetryKind, PermissionResponse, PlanModeReply, PlanModeRequest};
    use crossterm::event::{KeyCode, KeyModifiers};
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, Instant};

    #[test]
    fn tui_review_never_invokes_bare_git() {
        let src = include_str!("app.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"git\")")
                    && !code.contains("std::process::Command::new(\"git\")"),
                "production TUI app code must not invoke bare git; line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }

    #[test]
    fn tui_mode_changes_update_runtime_authority_before_session_state() {
        let project = tempfile::tempdir().expect("TUI plan root");
        let mut app = App::new("test-model", "test-provider");
        let session_id = crate::state::SessionId::from_raw(app.chat_session.id())
            .expect("session id must be UUID-shaped");
        app.run_context = crate::tools::ToolRunContext::builder(session_id, project.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .provider("tui-plan-test")
            .build();
        let initial_generation = app
            .tool_run_context()
            .expect("run")
            .runtime_mode()
            .generation;

        app.slash_mode();
        assert_eq!(app.chat_session.agent_mode(), crate::state::AgentMode::Plan);
        assert!(app
            .chat_session
            .inspect_state(|state| state.conversation.plan_mode.is_some()));
        assert!(app
            .tool_run_context()
            .expect("run")
            .agent_plan_file()
            .is_file());
        let plan = app.tool_run_context().expect("run").runtime_mode();
        assert_eq!(plan.class, crate::modes::RuntimeModeClass::Plan);
        assert!(plan.generation > initial_generation);

        app.slash_mode();
        assert_eq!(
            app.chat_session.agent_mode(),
            crate::state::AgentMode::Build
        );
        assert!(app
            .chat_session
            .inspect_state(|state| state.conversation.plan_mode.is_none()));
        let restored = app.tool_run_context().expect("run").runtime_mode();
        assert_eq!(restored.class, crate::modes::RuntimeModeClass::Standard);
        assert!(restored.generation > plan.generation);
        assert!(app
            .chat_session
            .inspect_state(|state| state.conversation.approved_plan.is_none()));
        assert!(app
            .messages
            .messages
            .iter()
            .any(|message| message.content.contains("no plan was approved")));
    }

    fn plan_follow_up_test_app() -> (tempfile::TempDir, App) {
        let project = tempfile::tempdir().expect("TUI plan root");
        let mut app = App::new("test-model", "test-provider");
        let session_id = crate::state::SessionId::from_raw(app.chat_session.id())
            .expect("session id must be UUID-shaped");
        let run = crate::tools::ToolRunContext::builder(session_id, project.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .provider("tui-plan-follow-up-test")
            .build()
            .expect("plan run");
        app.task_mgr = Arc::new(Mutex::new(
            crate::session::TaskManager::for_run(&run).expect("task manager"),
        ));
        app.run_context = Ok(run);
        (project, app)
    }

    fn enter_plan_through_typed_request(app: &mut App) -> PlanModeReply {
        let (reply, mut response) = tokio::sync::oneshot::channel();
        app.handle_plan_mode_request(PlanModeRequest::Enter, reply);
        response.try_recv().expect("plan entry reply")
    }

    #[test]
    fn typed_tui_plan_follow_up_enters_and_approves_the_displayed_plan() {
        let (_project, mut app) = plan_follow_up_test_app();
        assert!(matches!(
            enter_plan_through_typed_request(&mut app),
            PlanModeReply::Completed { response, .. }
                if response["entered"] == true
        ));
        let run = app.tool_run_context().expect("run");
        std::fs::write(run.agent_plan_file(), "# Implement the feature\n").expect("write plan");

        let (reply, mut response) = tokio::sync::oneshot::channel();
        app.handle_plan_mode_request(
            PlanModeRequest::Exit {
                allowed_prompts: vec![crate::tools::ToolAllowedPrompt {
                    tool: "bash".to_string(),
                    prompt: "cargo test".to_string(),
                }],
            },
            reply,
        );
        assert!(app.pending_plan_approval.is_some());

        // Plan decisions arrive while the model turn is still waiting. The
        // modal must therefore win over streaming key handling.
        app.is_waiting = true;
        app.handle_key(crossterm::event::KeyEvent::new(
            KeyCode::Char('y'),
            KeyModifiers::NONE,
        ));

        let reply = response.try_recv().expect("plan approval reply");
        let PlanModeReply::Completed {
            response,
            context_message: Some(context),
            ..
        } = reply
        else {
            panic!("expected completed approval reply");
        };
        assert_eq!(response["approved"], true);
        assert_eq!(
            context["metadata"]["approved_plan_digest"],
            response["plan_digest"]
        );
        assert_eq!(
            app.chat_session.agent_mode(),
            crate::state::AgentMode::Build
        );
        assert_eq!(app.mode, Mode::Build);
        assert_eq!(
            app.tool_run_context().expect("run").runtime_mode().class,
            crate::modes::RuntimeModeClass::Standard
        );
        assert_eq!(
            app.chat_session
                .inspect_state(|state| state.conversation.approved_plan.clone()),
            Some("# Implement the feature\n".to_string())
        );
    }

    #[test]
    fn typed_tui_plan_reject_cancel_and_stale_decisions_stay_in_plan_mode() {
        let (_project, mut app) = plan_follow_up_test_app();
        let _ = enter_plan_through_typed_request(&mut app);
        let run = app.tool_run_context().expect("run");
        std::fs::write(run.agent_plan_file(), "# First proposal\n").expect("write plan");

        let (reject, mut rejected) = tokio::sync::oneshot::channel();
        app.handle_plan_mode_request(
            PlanModeRequest::Exit {
                allowed_prompts: Vec::new(),
            },
            reject,
        );
        app.handle_plan_approval_key(crossterm::event::KeyEvent::new(
            KeyCode::Char('n'),
            KeyModifiers::NONE,
        ));
        assert!(matches!(
            rejected.try_recv().expect("rejection reply"),
            PlanModeReply::Completed { response, .. } if response["approved"] == false
        ));

        let (cancel, mut cancelled) = tokio::sync::oneshot::channel();
        app.handle_plan_mode_request(
            PlanModeRequest::Exit {
                allowed_prompts: Vec::new(),
            },
            cancel,
        );
        app.handle_plan_approval_key(crossterm::event::KeyEvent::new(
            KeyCode::Esc,
            KeyModifiers::NONE,
        ));
        assert!(matches!(
            cancelled.try_recv().expect("cancellation reply"),
            PlanModeReply::Cancelled { .. }
        ));

        let (stale, mut stale_reply) = tokio::sync::oneshot::channel();
        app.handle_plan_mode_request(
            PlanModeRequest::Exit {
                allowed_prompts: Vec::new(),
            },
            stale,
        );
        std::fs::write(run.agent_plan_file(), "# Changed after display\n").expect("change plan");
        app.finish_plan_approval(true);
        assert!(matches!(
            stale_reply.try_recv().expect("stale reply"),
            PlanModeReply::Completed { response, .. }
                if response["approved"] == false && response["error"] == true
        ));
        assert_eq!(app.chat_session.agent_mode(), crate::state::AgentMode::Plan);
        assert_eq!(
            app.tool_run_context().expect("run").runtime_mode().class,
            crate::modes::RuntimeModeClass::Plan
        );
        assert!(app
            .chat_session
            .inspect_state(|state| state.conversation.approved_plan.is_none()));
    }

    #[test]
    fn tui_behavior_mode_rejects_conflicts_without_mutating_session() {
        let mut app = App::new("test-model", "test-provider");
        let before = app.behavior_mode();
        let mut invalid = before.clone();
        invalid.modifiers = vec![
            crate::modes::Modifier::Readonly,
            crate::modes::Modifier::Director,
        ];

        assert!(app.apply_behavior_mode(invalid).is_err());
        assert_eq!(app.behavior_mode(), before);
    }

    #[test]
    fn context_reference_append_preserves_the_provider_history_prefix() {
        let mut messages = vec![
            serde_json::json!({"role": "user", "content": "original task"}),
            serde_json::json!({"role": "assistant", "content": "original answer"}),
        ];
        let prefix = messages.clone();

        append_context_reference_message(
            &mut messages,
            "hook or review finding",
            "user_prompt_submit_hook",
        );

        assert!(messages.starts_with(&prefix));
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[2]["role"], "user");
        assert_eq!(messages[2]["content"], "hook or review finding");
        assert_eq!(
            messages[2]["metadata"]["openclaudia_context_source"],
            "user_prompt_submit_hook"
        );
    }

    #[cfg(unix)]
    #[test]
    fn orphan_native_state_recovery_is_born_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::TempDir::new().expect("recovery root");
        let directory = root.path().join("orphan-turns");
        create_orphan_recovery_dir(&directory).expect("private recovery directory");
        let path = directory.join("turn.json");
        write_orphan_recovery_file(&path, br#"{"provider_native_state":"opaque"}"#)
            .expect("private recovery file");

        assert_eq!(
            std::fs::metadata(&directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    fn output_with_status(code: i32, stdout: &str, stderr: &str) -> std::process::Output {
        use std::os::unix::process::ExitStatusExt as _;

        std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn tui_review_output_reports_git_failure_stderr() {
        let output = output_with_status(128, "", "fatal: not a git repository");

        let rendered = format_review_command_output(&output);

        assert!(rendered.starts_with("Failed to run git diff:"));
        assert!(rendered.contains("fatal: not a git repository"));
        assert!(
            !rendered.contains("No changes"),
            "git failure must not be rendered as a clean diff"
        );
    }

    #[cfg(unix)]
    #[test]
    fn tui_review_output_reports_no_changes_on_empty_success() {
        let output = output_with_status(0, "", "");

        assert_eq!(
            format_review_command_output(&output),
            "No changes to review."
        );
    }

    #[cfg(unix)]
    #[test]
    fn tui_review_output_truncates_large_successful_diff() {
        let diff = (0..105)
            .map(|line| format!("line {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let output = output_with_status(0, &diff, "");

        let rendered = format_review_command_output(&output);

        assert!(rendered.contains("line 0"));
        assert!(rendered.contains("line 99"));
        assert!(!rendered.contains("line 100\n"));
        assert!(rendered.contains("truncated, 105 total lines"));
    }

    #[test]
    fn tui_module_docs_do_not_advertise_removed_tui_flag() {
        let src = include_str!("app.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        assert!(
            production.contains("Launched via `openclaudia` when no subcommand"),
            "TUI module docs must describe the actual default launch path"
        );
        assert!(
            !production.contains("openclaudia --tui`"),
            "TUI module docs must not advertise the removed --tui flag"
        );
    }

    fn advertised_tui_invocation_roots(invocation: &str) -> Vec<String> {
        invocation
            .split(',')
            .map(str::trim)
            .filter(|form| !form.is_empty())
            .map(|form| form.split_whitespace().next().unwrap_or(form).to_string())
            .collect()
    }

    #[test]
    fn advertised_tui_slash_commands_resolve_through_canonical_registry() {
        let registry = crate::command_registry::registry();
        for command in all_tui_commands() {
            for root in advertised_tui_invocation_roots(command.invocation) {
                let concrete = root
                    .replace("<plugin>", "demo")
                    .replace("<command>", "run")
                    .replace("<skill-name>", "demo-skill");
                let resolves = if root.contains("<plugin>") || root.contains("<skill-name>") {
                    registry
                        .parse(&concrete, crate::command_registry::CommandFrontend::Tui)
                        .is_ok()
                } else {
                    registry
                        .get(root.trim_start_matches('/'))
                        .is_some_and(|spec| {
                            spec.frontends
                                .contains(crate::command_registry::CommandFrontend::Tui)
                        })
                };
                assert!(
                    resolves,
                    "TUI help advertises `{}` but the canonical registry does not resolve {concrete:?}",
                    command.invocation
                );
            }
        }
    }

    #[test]
    fn api_retry_message_formats_retry_metadata() {
        assert_eq!(format_api_retry_delay(0), "0s");
        assert_eq!(format_api_retry_delay(1_250), "1.25s");
        assert_eq!(
            format_api_retry_message(ApiRetryKind::Status, 1, 11, 0, Some(429)),
            "API retry 1/11 in 0s after HTTP 429"
        );
        assert_eq!(
            format_api_retry_message(ApiRetryKind::Transport, 2, 11, 2_000, None),
            "API retry 2/11 in 2s after transport error"
        );
    }

    #[test]
    fn stream_timeout_message_and_descriptor_are_structured() {
        assert_eq!(
            format_stream_timeout_message(301, 300),
            "Stream timed out after 301s without new data (timeout 300s)"
        );
        assert_eq!(
            super::describe_event(&AppEvent::StreamTimeout {
                elapsed_secs: 301,
                timeout_secs: 300,
            }),
            "StreamTimeout(301/300s)"
        );
    }

    // ── ApiClient extraction (crosslink #253) ───────────────────────────

    /// `ApiClient::new` initialises with empty request state — no endpoint,
    /// headers, token, or prompt blocks — on the shared provider transport.
    #[test]
    fn api_client_new_starts_empty() {
        let api = ApiClient::new();
        assert!(
            api.endpoint.is_empty(),
            "endpoint must start empty before set_api_config"
        );
        assert!(api.headers.is_empty(), "no headers until pipeline applied");
        assert!(
            api.claude_code_token.is_none(),
            "no OAuth token until pipeline applied"
        );
        assert!(
            api.prompt_blocks.is_none(),
            "no prompt blocks until pipeline applied"
        );
    }

    /// `App::new` wires `api_client` to a default `ApiClient` so the
    /// constructor stays infallible (no I/O, no panic on missing config).
    #[test]
    fn app_new_initialises_api_client_default() {
        let app = App::new("test-model", "anthropic");
        assert!(app.api_client.endpoint.is_empty());
        assert!(app.api_client.headers.is_empty());
        assert!(app.api_client.claude_code_token.is_none());
        // Sanity: model/provider stay on App (not migrated into ApiClient).
        assert_eq!(app.model, "test-model");
        assert_eq!(app.provider, "anthropic");
    }

    #[test]
    fn tui_doctor_uses_shared_receipts_without_transport_details() {
        let mut app = App::new("doctor-model-canary", "local");
        app.api_client.endpoint = "https://doctor-endpoint-canary.invalid".to_string();
        app.api_client
            .headers
            .insert_literal("x-doctor-secret", "doctor-header-canary".to_string())
            .expect("test header");

        app.handle_slash_doctor();

        let message = app.messages.messages.last().expect("doctor message");
        assert!(message.content.contains("evidence.registry"));
        assert!(message.content.contains("runtime.context"));
        assert!(message.content.contains("runtime.provider_transport"));
        assert!(message
            .content
            .contains("runtime.provider_transport.composed"));
        assert!(!message.content.contains("doctor-model-canary"));
        assert!(!message.content.contains("doctor-endpoint-canary"));
        assert!(!message.content.contains("doctor-header-canary"));
    }

    #[test]
    fn app_constructors_do_not_load_config_from_disk() {
        let src = include_str!("app.rs");
        let constructor_start = src
            .find("pub fn new(model: &str, provider: &str) -> Self")
            .expect("App::new constructor must exist");
        let constructor_end = src[constructor_start..]
            .find("pub fn set_api_config")
            .map(|offset| constructor_start + offset)
            .expect("constructor block must end before set_api_config");
        let constructors = &src[constructor_start..constructor_end];

        assert!(
            !constructors.contains("load_config("),
            "App constructors must not read project config; startup passes policy via new_with_policy"
        );
    }

    fn last_display_content(app: &App) -> &str {
        app.messages
            .messages
            .last()
            .expect("expected a display message")
            .content
            .as_str()
    }

    #[test]
    fn tui_model_slash_reports_current_model() {
        let mut app = App::new("claude-sonnet-4-6", "anthropic");

        assert!(app.handle_slash_model("/model"));

        let content = last_display_content(&app);
        assert!(content.contains("claude-sonnet-4-6"));
        assert!(content.contains("anthropic"));
        assert!(content.contains("/model <name>"));
    }

    #[test]
    fn tui_model_list_uses_static_provider_catalog() {
        let mut app = App::new("claude-opus-4-8", "anthropic");

        assert!(app.handle_slash_model("/model list"));

        let content = last_display_content(&app);
        assert!(content.contains("Available models for anthropic"));
        assert!(content.contains("claude-opus-4-8 <- current"));
        assert!(content.contains("not limited to this fallback list"));
    }

    #[test]
    fn tui_model_list_accepts_extra_spaces_and_case() {
        let mut app = App::new("claude-opus-4-7", "anthropic");

        assert!(app.handle_slash_model("/model    LIST"));

        let content = last_display_content(&app);
        assert!(content.contains("Available models for anthropic"));
        assert_eq!(app.model, "claude-opus-4-7");
    }

    #[test]
    fn tui_models_alias_lists_catalog() {
        let mut app = App::new("MiniMax-M3", "minimax");

        assert!(app.handle_slash_model("/models"));

        let content = last_display_content(&app);
        assert!(content.contains("Available models for minimax"));
        assert!(content.contains("MiniMax-M3 <- current"));
    }

    #[test]
    fn tui_model_slash_switches_to_arbitrary_model_id() {
        let mut app = App::new("claude-sonnet-4-6", "anthropic");

        assert!(app.handle_slash_model("/model claude-opus-4-99-future"));

        assert_eq!(app.model, "claude-opus-4-99-future");
        assert_eq!(app.chat_session.model, "claude-opus-4-99-future");
        assert!(last_display_content(&app).contains("Model switched"));
    }

    #[test]
    fn tui_model_default_uses_provider_default() {
        let mut app = App::new("claude-sonnet-4-6", "anthropic");

        assert!(app.handle_slash_model("/model default"));

        assert_eq!(
            app.model,
            crate::providers::default_model_for_target("anthropic").expect("known default")
        );
        assert_eq!(app.chat_session.model, app.model);
    }

    #[test]
    fn tui_model_slash_rejects_switch_while_waiting() {
        let mut app = App::new("claude-sonnet-4-6", "anthropic");
        app.is_waiting = true;

        assert!(app.handle_slash_model("/model claude-opus-4-7"));

        assert_eq!(app.model, "claude-sonnet-4-6");
        assert_eq!(app.chat_session.model, "claude-sonnet-4-6");
        assert!(last_display_content(&app).contains("in flight"));
    }

    fn skill_activation_fixture(
        allowed_tools: Option<Vec<String>>,
        model: Option<&str>,
        effort: Option<&str>,
    ) -> crate::skills::SkillActivation {
        let root = tempfile::tempdir().expect("skill activation root");
        let directory = root.path().join(".openclaudia/skills/test-skill");
        std::fs::create_dir_all(&directory).expect("skill activation directory");
        let tools_yaml = allowed_tools.as_ref().map_or(String::new(), |tools| {
            format!(
                "allowed_tools:\n{}\n",
                tools
                    .iter()
                    .map(|tool| format!(
                        "  - {}",
                        serde_json::to_string(tool).expect("tool fixture string")
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        });
        let model_yaml = model.map_or(String::new(), |model| format!("model: {model}\n"));
        let effort_yaml = effort.map_or(String::new(), |effort| format!("effort: {effort}\n"));
        std::fs::write(
            directory.join("SKILL.md"),
            format!(
                "---\nname: test-skill\ndescription: test skill\n{tools_yaml}{model_yaml}{effort_yaml}---\nDo the skill work.\n"
            ),
        )
        .expect("skill activation fixture");
        let policy = crate::skills::SkillCapabilityPolicy::project(
            allowed_tools.unwrap_or_default(),
            true,
            true,
            false,
        )
        .expect("skill activation policy");
        let access = crate::skills::SkillRunAccess::host_granted_project(root.path(), policy)
            .expect("skill activation access");
        let run =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(std::collections::HashMap::new())
                .skill_access(access)
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(false)
                .network(false)
                .secrets(false)
                .provider("tui-skill-test")
                .build()
                .expect("TUI skill run");
        crate::skills::activate_user_invocable_skill_for_run(&run, "test-skill")
            .expect("TUI skill activation")
    }

    #[test]
    fn tui_skill_metadata_sets_next_turn_hints() {
        let mut app = App::new("claude-sonnet-4-6", "anthropic");
        let skill = skill_activation_fixture(
            Some(vec!["Bash(git status *)".to_string()]),
            Some("claude-opus-4-7"),
            Some("high"),
        );

        app.apply_skill_turn_metadata(&skill);

        assert_eq!(app.next_turn_allowed_tool_rules.len(), 1);
        assert_eq!(app.next_turn_allowed_tool_rules[0].tool, "Bash");
        assert_eq!(app.next_turn_model.as_deref(), Some("claude-opus-4-7"));
        assert_eq!(
            app.next_turn_effort_level,
            Some(crate::tui::messages::EffortLevel::High)
        );
    }

    #[test]
    fn tui_skill_metadata_ignores_cross_provider_model_hint() {
        let mut app = App::new("claude-sonnet-4-6", "anthropic");
        let skill = skill_activation_fixture(None, Some("gpt-5.5"), Some("future-effort"));

        app.apply_skill_turn_metadata(&skill);

        assert!(app.next_turn_model.is_none());
        assert!(app.next_turn_effort_level.is_none());
    }

    #[test]
    fn tui_effort_slash_updates_status_without_chat_message() {
        let mut app = App::new("claude-sonnet-4-6", "anthropic");

        assert!(app.handle_export_effort_slash("/effort high"));

        assert_eq!(app.chat_session.effort_level(), EffortLevel::High);
        assert!(
            app.messages.is_empty(),
            "/effort is already reflected in the status bar and must not add chat noise"
        );
    }

    fn provider_config_without_key(base_url: &str) -> crate::config::ProviderConfig {
        crate::config::ProviderConfig {
            api_key: None,
            base_url: base_url.to_string(),
            model: None,
            headers: crate::secrets::SensitiveHeaders::new(),
            thinking: crate::config::ThinkingConfig::default(),
        }
    }

    fn reset_project_ledger(session_id: &str) -> PathBuf {
        let path = crate::ledger::project_session_ledger_path(session_id)
            .expect("test session id must be ledger-safe");
        let _ = std::fs::remove_file(&path);
        path
    }

    fn seed_valid_final_ledger(session_id: &str) -> (String, Arc<crate::tools::ToolRunContext>) {
        let run = crate::tools::security::test_run_context_for(std::path::Path::new(env!(
            "CARGO_MANIFEST_DIR"
        )));
        let mut ledger = crate::ledger::RealityLedger::open_project_session(session_id)
            .expect("open test ledger");
        let diff = ledger
            .observe_diff(&run, vec!["src/tui/app.rs".to_string()], "patch")
            .expect("diff");
        let config = crate::config::GuardrailsConfig {
            quality_gates: Some(crate::config::QualityGatesConfig {
                enabled: true,
                checks: vec![crate::config::QualityCheck {
                    name: "tui-check".to_string(),
                    command: "sh -c 'exit 0'".to_string(),
                    required: true,
                }],
                ..crate::config::QualityGatesConfig::default()
            }),
            ..crate::config::GuardrailsConfig::default()
        };
        crate::guardrails::configure(&run, &config).expect("configure gate");
        let gate = crate::guardrails::run_quality_gates(&run, "gpt-test")
            .into_iter()
            .next()
            .expect("gate result");
        let verification =
            crate::grounded_loop::append_quality_gate_observations(&run, &mut ledger, &gate)
                .expect("gate receipts")
                .verification;
        let content = serde_json::json!({
            "kind":"final",
            "claims":[
                {"claim_type":"file_change", "path":"src/tui/app.rs", "evidence":[diff]},
                {"claim_type":"verification", "check":"tui-check", "passed":true, "evidence":[verification]}
            ]
        })
        .to_string();
        (content, run)
    }

    fn direct_turn_result(content: String) -> crate::pipeline::TurnResult {
        crate::pipeline::TurnResult {
            content,
            reasoning_content: None,
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            usage: crate::session::TokenUsage::default(),
            needs_followup: false,
            terminal_outcome: crate::pipeline::ProviderTerminalOutcome::Completed,
            finish_reason: None,
            provider_native_state: None,
            execution_bindings: None,
        }
    }

    #[test]
    fn live_structured_final_display_validates_before_claim_projection() {
        let session_id = "tui-live-structured-final-summary";
        let ledger_path = reset_project_ledger(session_id);
        let content = serde_json::json!({
            "kind": "final",
            "claims": [{
                "claim_type":"unsupported",
                "statement":"Hello - I'm Claudia. What would you like to work on?",
                "reason":"Greeting does not assert an observed runtime fact."
            }]
        })
        .to_string();

        let rendered = super::render_live_final_response_for_display(
            crate::tools::security::test_run_context(),
            session_id,
            &content,
            "test-model",
        )
        .expect("validated structured final should render");

        assert_eq!(
            rendered,
            "Unsupported claim \"Hello - I'm Claudia. What would you like to work on?\"; reason \"Greeting does not assert an observed runtime fact.\"."
        );
        assert!(!rendered.contains("\"evidence\""));
        assert!(!rendered.contains("\"verification\""));
        let _ = std::fs::remove_file(ledger_path);
    }

    #[test]
    fn response_done_sanitizes_streamed_structured_final() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = SessionDirGuard::set(tmp.path().join("chat_sessions"));
        let mut app = App::new("gpt-5.5", "openai");
        app.is_waiting = true;
        app.append_streaming_for_display(
            &serde_json::json!({
                "kind": "final",
                "claims": [{
                    "claim_type":"unsupported",
                    "statement":"Hello - I'm Claudia.",
                    "reason":"Greeting."
                }]
            })
            .to_string(),
        );
        assert!(
            app.messages.streaming_text.is_empty(),
            "unvalidated structured claims must stay hidden while streaming"
        );

        app.handle_response_done();

        let last = app.messages.messages.last().expect("assistant message");
        assert_eq!(last.kind, MessageKind::Assistant);
        assert_eq!(
            last.content,
            "Unsupported claim \"Hello - I'm Claudia.\"; reason \"Greeting.\"."
        );
        assert!(!last.content.contains("\"kind\""));
    }

    #[test]
    fn streamed_structured_final_stays_hidden_until_response_done() {
        let mut app = App::new("gpt-5.5", "openai");
        app.append_streaming_for_display("{\"kind\"");

        assert!(app.messages.is_streaming);
        assert!(app.messages.streaming_text.is_empty());
        assert!(app.streaming_raw_text.contains("\"kind\""));

        app.append_streaming_for_display(
            ":\"final\",\"claims\":[{\"claim_type\":\"unsupported\",\"statement\":\"Hello - I'm Claudia.\",\"reason\":\"Greeting.\"}]}",
        );

        assert!(app.messages.streaming_text.is_empty());
        assert!(app.streaming_raw_text.contains("unsupported"));
    }

    #[test]
    fn streamed_plain_final_stays_hidden_and_is_removed_at_response_done() {
        let mut app = App::new("gpt-5.5", "openai");
        app.is_waiting = true;
        app.append_streaming_for_display("Verified with cargo test.");

        assert!(app.messages.streaming_text.is_empty());
        app.handle_response_done();

        assert!(app.messages.messages.iter().all(|message| {
            message.kind != MessageKind::Assistant
                || !message.content.contains("Verified with cargo test")
        }));
    }

    #[test]
    fn stale_session_sync_cannot_install_portable_or_native_state() {
        let mut app = App::new("gpt-5.5", "openai");
        let current_messages = vec![serde_json::json!({
            "role": "user",
            "content": "current session"
        })];
        app.chat_session
            .replace_messages_and_provider_native_state(current_messages.clone(), None)
            .expect("seed current session");
        let output = crate::providers::OpenAiResponsesTurnOutput::new(
            "resp_stale_tui_sync",
            vec![serde_json::json!({
                "type": "message",
                "id": "msg_stale_tui_sync",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "stale"}]
            })],
        )
        .expect("Responses output");
        let stale_native_state =
            crate::providers::advance_openai_responses_state("openai", "gpt-5.5", None, 1, &output)
                .expect("Responses state");

        assert!(app.handle_app_event(Ok(AppEvent::SyncSession {
            session_id: "a-different-session".to_string(),
            messages: vec![
                serde_json::json!({"role": "user", "content": "stale session"}),
                serde_json::json!({"role": "assistant", "content": "stale"}),
            ],
            provider_native_state: Some(stale_native_state),
        })));

        assert_eq!(app.chat_session.messages_snapshot(), current_messages);
        assert!(app.chat_session.provider_native_state_snapshot().is_none());
    }

    #[test]
    fn bare_effort_cycles_with_provider_capabilities() {
        let mut app = App::new("gpt-5.5", "openai");
        app.chat_session.set_effort_level(EffortLevel::High);

        assert!(app.handle_export_effort_slash("/effort"));
        assert_eq!(app.chat_session.effort_level(), EffortLevel::Max);
        assert!(app.handle_export_effort_slash("/effort"));
        assert_eq!(app.chat_session.effort_level(), EffortLevel::None);

        app.provider = "anthropic".to_string();
        app.model = "claude-sonnet-4-6".to_string();
        app.chat_session.set_effort_level(EffortLevel::High);
        assert!(app.handle_export_effort_slash("/effort"));
        assert_eq!(app.chat_session.effort_level(), EffortLevel::Max);
    }

    #[tokio::test]
    async fn tui_direct_plain_final_denial_is_surfaced_and_not_persisted() {
        let session_id = "tui-direct-final-plain-text";
        let ledger_path = reset_project_ledger(session_id);
        let (tx, rx) = mpsc::channel();
        let client = reqwest::Client::new();
        let headers = crate::secrets::SensitiveHeaders::new();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));
        let policy_enforcer = Arc::new(crate::services::policy::PolicyEnforcer::new(
            crate::services::policy::EnterprisePolicy::default(),
        ));

        handle_turn_result(
            direct_turn_result("Verified with cargo check.".to_string()),
            vec![serde_json::json!({"role":"user","content":"verify this"})],
            TurnContext {
                run_context: crate::tools::security::test_run_context(),
                client: &client,
                endpoint: "https://example.invalid",
                headers: &headers,
                provider: "openai",
                model: "gpt-test",
                effort_level: EffortLevel::Medium,
                wire_api: crate::pipeline::WireApi::ChatCompletions,
                claude_code_token: None,
                claude_agent_sdk: None,
                codex_agent_sdk: None,
                prompt_blocks: None,
                provider_native_state: None,
                memory_db: None,
                app_config: None,
                permission_mgr: None,
                vdd_engine: None,
                mcp_manager: None,
                vdd_builder_auth: &crate::vdd::VddProviderAuth::None,
                transient_allowed_tool_rules: &[],
                hook_engine: None,
                policy_enforcer,
                task_mgr,
                session_id,
                task_obs: None,
                tx: &tx,
            },
        )
        .await;

        let mut saw_error = false;
        let mut synced_messages = None;
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::ApiError(_) => saw_error = true,
                AppEvent::SyncSession { messages, .. } => synced_messages = Some(messages),
                _ => {}
            }
        }
        let _ = std::fs::remove_file(ledger_path);

        assert!(saw_error, "final gate denial must be surfaced to the user");
        assert!(
            synced_messages.is_none(),
            "plain direct final must not be persisted as an assistant result"
        );
    }

    #[tokio::test]
    async fn tui_direct_final_accepts_cited_evidence_and_verification() {
        let session_id = "tui-direct-final-accepted";
        let ledger_path = reset_project_ledger(session_id);
        let (content, run) = seed_valid_final_ledger(session_id);
        let (tx, rx) = mpsc::channel();
        let client = reqwest::Client::new();
        let headers = crate::secrets::SensitiveHeaders::new();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));
        let policy_enforcer = Arc::new(crate::services::policy::PolicyEnforcer::new(
            crate::services::policy::EnterprisePolicy::default(),
        ));

        handle_turn_result(
            direct_turn_result(content.clone()),
            vec![serde_json::json!({"role":"user","content":"verify this"})],
            TurnContext {
                run_context: &run,
                client: &client,
                endpoint: "https://example.invalid",
                headers: &headers,
                provider: "openai",
                model: "gpt-test",
                effort_level: EffortLevel::Medium,
                wire_api: crate::pipeline::WireApi::ChatCompletions,
                claude_code_token: None,
                claude_agent_sdk: None,
                codex_agent_sdk: None,
                prompt_blocks: None,
                provider_native_state: None,
                memory_db: None,
                app_config: None,
                permission_mgr: None,
                vdd_engine: None,
                mcp_manager: None,
                vdd_builder_auth: &crate::vdd::VddProviderAuth::None,
                transient_allowed_tool_rules: &[],
                hook_engine: None,
                policy_enforcer,
                task_mgr,
                session_id,
                task_obs: None,
                tx: &tx,
            },
        )
        .await;

        let mut saw_error = false;
        let mut synced_messages = None;
        while let Ok(event) = rx.try_recv() {
            match event {
                AppEvent::ApiError(_) => saw_error = true,
                AppEvent::SyncSession { messages, .. } => synced_messages = Some(messages),
                _ => {}
            }
        }
        let _ = std::fs::remove_file(ledger_path);

        assert!(!saw_error, "grounded direct final must not be rejected");
        let messages = synced_messages.expect("grounded final should sync messages");
        assert_eq!(
            messages.last().and_then(|msg| msg.get("role")),
            Some(&serde_json::json!("assistant"))
        );
        assert_eq!(
            messages.last().and_then(|msg| msg.get("content")),
            Some(&serde_json::json!(
                "Changed file \"src/tui/app.rs\".\nVerification check \"tui-check\": passed."
            ))
        );
    }

    #[tokio::test]
    async fn tui_responses_turn_syncs_portable_and_native_state_together() {
        let session_id = "tui-responses-native-sync";
        let ledger_path = reset_project_ledger(session_id);
        let (content, run) = seed_valid_final_ledger(session_id);
        let output = crate::providers::OpenAiResponsesTurnOutput::new(
            "resp_tui_sync",
            vec![serde_json::json!({
                "id": "msg_tui_sync",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "phase": "final_answer",
                "content": [{"type": "output_text", "text": content}]
            })],
        )
        .expect("native turn output");
        let native_state = crate::providers::advance_openai_responses_state(
            "openai", "gpt-test", None, 1, &output,
        )
        .expect("native state");
        let mut turn = direct_turn_result(content);
        turn.provider_native_state = Some(native_state.clone());
        let (tx, rx) = mpsc::channel();
        let client = reqwest::Client::new();
        let headers = crate::secrets::SensitiveHeaders::new();
        let policy_enforcer = Arc::new(crate::services::policy::PolicyEnforcer::new(
            crate::services::policy::EnterprisePolicy::default(),
        ));

        handle_turn_result(
            turn,
            vec![serde_json::json!({"role":"user","content":"verify this"})],
            TurnContext {
                run_context: &run,
                client: &client,
                endpoint: "https://example.invalid",
                headers: &headers,
                provider: "openai",
                model: "gpt-test",
                effort_level: EffortLevel::Medium,
                wire_api: crate::pipeline::WireApi::OpenAiResponses,
                claude_code_token: None,
                claude_agent_sdk: None,
                codex_agent_sdk: None,
                prompt_blocks: None,
                provider_native_state: None,
                memory_db: None,
                app_config: None,
                permission_mgr: None,
                vdd_engine: None,
                mcp_manager: None,
                vdd_builder_auth: &crate::vdd::VddProviderAuth::None,
                transient_allowed_tool_rules: &[],
                hook_engine: None,
                policy_enforcer,
                task_mgr: Arc::new(Mutex::new(crate::session::TaskManager::new())),
                session_id,
                task_obs: None,
                tx: &tx,
            },
        )
        .await;

        let events = rx.try_iter().collect::<Vec<_>>();
        let sync_index = events
            .iter()
            .position(|event| matches!(event, AppEvent::SyncSession { .. }))
            .expect("session sync event");
        let response_done_indices = events
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, AppEvent::ResponseDone).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(
            response_done_indices.len(),
            1,
            "one orchestrator-owned terminal event"
        );
        assert!(
            sync_index < response_done_indices[0],
            "portable/native state must sync before ResponseDone"
        );
        let synced = events.into_iter().find_map(|event| match event {
            AppEvent::SyncSession {
                session_id: synced_session_id,
                messages,
                provider_native_state,
            } => Some((synced_session_id, messages, provider_native_state)),
            _ => None,
        });
        let _ = std::fs::remove_file(ledger_path);
        let (synced_session_id, messages, state) = synced.expect("atomic session sync");
        assert_eq!(synced_session_id, session_id);
        assert_eq!(
            messages.last().and_then(|message| message.get("role")),
            Some(&serde_json::json!("assistant"))
        );
        assert_eq!(state, Some(native_state));
    }

    #[test]
    fn direct_responses_transport_requires_native_continuation_state() {
        let result =
            provider_state_after_turn(crate::pipeline::WireApi::OpenAiResponses, true, None, None);

        assert_eq!(
            result.expect_err("direct Responses transport must return native state"),
            "Responses turn completed without native continuation state"
        );
    }

    #[test]
    fn codex_sdk_responses_shape_does_not_require_native_continuation_state() {
        let result =
            provider_state_after_turn(crate::pipeline::WireApi::OpenAiResponses, false, None, None);

        assert_eq!(result.expect("SDK transport owns continuation state"), None);
    }

    #[test]
    fn provider_switch_auth_allows_keyless_local_provider() {
        let provider = provider_config_without_key("http://localhost:1234/v1");

        let auth = resolve_provider_switch_auth("local", &provider)
            .expect("local provider should not require an API key");

        assert!(auth.api_key.is_none());
        assert!(auth.claude_code_token.is_none());
    }

    #[test]
    fn provider_switch_auth_rejects_keyless_remote_provider() {
        let provider = provider_config_without_key("https://api.deepseek.com");

        let err = resolve_provider_switch_auth("deepseek", &provider)
            .expect_err("remote provider should require an API key");

        assert!(
            err.contains("DEEPSEEK_API_KEY"),
            "remote provider auth error should name the env var; got {err:?}"
        );
    }

    /// `set_api_config` writes through to `api_client`, not to ghost
    /// fields on App. Pins the migration: the previous version of this
    /// setter wrote `self.endpoint = ...`, which compiled but stayed in
    /// the old struct shape.
    #[test]
    fn set_api_config_threads_through_api_client() {
        let mut app = App::new("test-model", "anthropic");
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers
            .insert_literal("x-api-key", "secret".to_string())
            .expect("test header");
        app.set_api_config(
            "https://example.com/v1".to_string(),
            headers,
            crate::pipeline::WireApi::OpenAiResponses,
            None,
            Some(
                crate::secrets::OAuthToken::try_from_string("oauth-token".to_string())
                    .expect("test token"),
            ),
            None,
            None,
        );
        assert_eq!(app.api_client.endpoint, "https://example.com/v1");
        assert!(app.api_client.headers.matches_value("x-api-key", "secret"));
        assert!(app.api_client.prompt_blocks.is_none());
        assert!(app
            .api_client
            .claude_code_token
            .as_ref()
            .is_some_and(|token| token.matches("oauth-token")));
        assert_eq!(
            app.api_client.wire_api,
            crate::pipeline::WireApi::OpenAiResponses
        );
    }

    #[test]
    fn apply_provider_switch_updates_metadata_and_transport() {
        let mut app = App::new("old-model", "anthropic");
        let original_session_id = app.chat_session.id();
        let original_run = app.tool_run_context().expect("original run");
        let blocks = crate::prompt::SystemPromptBlocks::from_items(
            vec![
                crate::context::ContextItem::host_instruction(
                    "test.stable",
                    crate::context::HostInstructionSource::CorePolicy,
                    "compiled:test",
                    "stable",
                    crate::context::ContextFreshness::Static,
                    1,
                ),
                crate::context::ContextItem::host_instruction(
                    "test.dynamic",
                    crate::context::HostInstructionSource::RuntimePolicy,
                    "host:test",
                    "dynamic",
                    crate::context::ContextFreshness::Turn,
                    2,
                ),
            ],
            crate::context::ContextBudget::default(),
        );
        let mut old_headers = crate::secrets::SensitiveHeaders::new();
        old_headers
            .insert_literal("x-api-key", "old-key".to_string())
            .expect("header");
        let old_token =
            crate::secrets::OAuthToken::try_from_string("oauth-token".to_string()).expect("token");
        app.set_api_config(
            "https://old.example/v1/messages".to_string(),
            old_headers,
            crate::pipeline::WireApi::ChatCompletions,
            Some(blocks.clone()),
            Some(old_token),
            None,
            None,
        );

        let mut switched_headers = crate::secrets::SensitiveHeaders::new();
        switched_headers
            .insert_literal("Authorization", "Bearer kimi-key".to_string())
            .expect("header");
        app.apply_provider_switch(ProviderSwitch {
            provider: "kimi".to_string(),
            model: "kimi-k2.7-code".to_string(),
            endpoint: "https://api.moonshot.ai/v1/chat/completions".to_string(),
            headers: switched_headers.clone(),
            wire_api: crate::pipeline::WireApi::ChatCompletions,
            claude_code_token: None,
            claude_agent_sdk: None,
            codex_agent_sdk: None,
            vdd_builder_auth: crate::vdd::VddProviderAuth::None,
            prompt_blocks: Some(blocks),
        });

        assert_eq!(app.provider, "kimi");
        assert_eq!(app.model, "kimi-k2.7-code");
        assert_eq!(app.chat_session.id(), original_session_id);
        assert_eq!(app.chat_session.provider, "kimi");
        assert_eq!(app.chat_session.model, "kimi-k2.7-code");
        let switched_run = app.tool_run_context().expect("switched run");
        assert_ne!(switched_run.run_id(), original_run.run_id());
        assert!(original_run.runtime().cancellation().is_cancelled());
        assert_eq!(switched_run.session_id(), original_session_id);
        assert_eq!(
            app.api_client.endpoint,
            "https://api.moonshot.ai/v1/chat/completions"
        );
        assert_eq!(app.api_client.headers, switched_headers);
        assert!(app.api_client.claude_code_token.is_none());
        assert_eq!(app.vdd_builder_auth, crate::vdd::VddProviderAuth::None);
        assert_eq!(
            app.api_client.wire_api,
            crate::pipeline::WireApi::ChatCompletions
        );
        let rebound_prompt = app
            .api_client
            .prompt_blocks
            .as_ref()
            .expect("provider switch must rebuild run-scoped prompt context");
        assert!(rebound_prompt.reference_context().contains(&format!(
            "Working directory: {}",
            switched_run.working_directory().display()
        )));
        assert!(
            app.messages
                .messages
                .iter()
                .any(|msg| msg.content.contains("Provider switched to kimi")),
            "switch should emit a visible status message"
        );
    }

    // ── handle_key mode split (crosslink #364) ─────────────────────────

    fn app_config_with_keybindings(
        bindings: impl IntoIterator<Item = (&'static str, crate::keybindings::KeyAction)>,
    ) -> Arc<crate::config::AppConfig> {
        let mut config: crate::config::AppConfig = serde_yaml::from_str(
            "proxy:\n  port: 8080\n  host: 127.0.0.1\n  target: local\nproviders:\n  local:\n    base_url: http://localhost:1234/v1\n",
        )
        .expect("minimal TUI keybinding config");
        config.keybindings.bindings = bindings
            .into_iter()
            .map(|(chord, action)| (chord.to_string(), action))
            .collect();
        Arc::new(config)
    }

    #[test]
    fn configured_chat_key_dispatches_the_typed_help_command() {
        let mut app = App::new("test", "local");
        app.app_config = Some(app_config_with_keybindings([(
            "f6",
            crate::keybindings::KeyAction::Help,
        )]));

        app.handle_key(crossterm::event::KeyEvent::new(
            KeyCode::F(6),
            KeyModifiers::NONE,
        ));

        assert!(app.overlay.is_some(), "configured F6 must open real help");
    }

    #[test]
    fn unmatched_unicode_chord_is_replayed_into_the_editor() {
        let mut app = App::new("test", "local");
        app.app_config = Some(app_config_with_keybindings([(
            "λ x",
            crate::keybindings::KeyAction::Help,
        )]));

        app.handle_key(crossterm::event::KeyEvent::new(
            KeyCode::Char('λ'),
            KeyModifiers::NONE,
        ));
        assert!(app.input.is_empty(), "prefix must wait for its next key");
        app.handle_key(crossterm::event::KeyEvent::new(
            KeyCode::Char('β'),
            KeyModifiers::NONE,
        ));

        assert_eq!(app.input.content, "λβ");
    }

    #[test]
    fn non_cancel_configured_action_cannot_escape_streaming_context() {
        let mut app = App::new("test", "local");
        app.app_config = Some(app_config_with_keybindings([(
            "f6",
            crate::keybindings::KeyAction::Help,
        )]));
        app.is_waiting = true;

        app.handle_key(crossterm::event::KeyEvent::new(
            KeyCode::F(6),
            KeyModifiers::NONE,
        ));

        assert!(app.is_waiting);
        assert!(app.overlay.is_none());
        assert!(app.input.is_empty());
    }

    #[test]
    fn configured_cancel_binding_denies_a_permission_dialog() {
        let mut app = App::new("test", "local");
        app.app_config = Some(app_config_with_keybindings([(
            "f6",
            crate::keybindings::KeyAction::Cancel,
        )]));
        let (reply, mut response) = tokio::sync::oneshot::channel();
        app.handle_app_event(Ok(AppEvent::PermissionRequest {
            tool_name: "bash".to_string(),
            tool_args: "{}".to_string(),
            reply,
        }));

        app.handle_key(crossterm::event::KeyEvent::new(
            KeyCode::F(6),
            KeyModifiers::NONE,
        ));

        assert!(app.pending_permission.is_none());
        assert_eq!(response.try_recv(), Ok(PermissionResponse::Deny));
    }

    /// `current_key_mode` reports `Normal` for a fresh app — no overlay,
    /// not streaming.
    #[test]
    fn key_mode_normal_by_default() {
        use super::KeyMode;
        let app = App::new("test", "anthropic");
        assert_eq!(app.current_key_mode(), KeyMode::Normal);
    }

    /// `current_key_mode` reports `Streaming` while a turn is in flight.
    /// `is_waiting` is the single observable that drives the mode — pin
    /// that the dispatcher reads the live state and isn't cached.
    #[test]
    fn key_mode_streaming_when_is_waiting() {
        use super::KeyMode;
        let mut app = App::new("test", "anthropic");
        app.is_waiting = true;
        assert_eq!(app.current_key_mode(), KeyMode::Streaming);
    }

    /// `current_key_mode` reports `Modal` while an overlay is open.
    #[test]
    fn key_mode_modal_when_overlay_open() {
        use super::KeyMode;
        let mut app = App::new("test", "anthropic");
        app.open_help_overlay();
        assert_eq!(app.current_key_mode(), KeyMode::Modal);
    }

    /// `handle_key_streaming` accepts `Esc` as the cancel-stream key. The
    /// state transitions back to Normal (`is_waiting` cleared).
    #[test]
    fn streaming_esc_cancels_stream() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = App::new("test", "anthropic");
        app.is_waiting = true;
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.is_waiting, "Esc must clear is_waiting");
    }

    /// `handle_key_streaming` drops every key that isn't Esc — text
    /// keystrokes do NOT land in the input buffer while a response is
    /// streaming. Pins the regression #364 closes: the pre-split flow
    /// would match `KeyCode::Char` and fall through to `input.insert(c)`.
    #[test]
    fn streaming_non_esc_keys_are_dropped() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = App::new("test", "anthropic");
        app.is_waiting = true;
        app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        // Input buffer must be untouched.
        assert!(
            app.input.is_empty(),
            "streaming mode must NOT capture text keystrokes into the input"
        );
        assert!(app.is_waiting, "non-Esc keys must not cancel the stream");
    }

    #[test]
    fn modified_enter_inserts_newline_without_submitting() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = App::new("test", "anthropic");
        app.input.insert_str("first");

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::SHIFT));

        assert_eq!(app.input.content, "first\n");
        assert!(
            app.chat_session.message_count() == 0,
            "modified Enter must not submit the prompt"
        );
    }

    #[test]
    fn ctrl_j_inserts_newline_without_submitting() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = App::new("test", "anthropic");
        app.input.insert_str("first");

        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::CONTROL));

        assert_eq!(app.input.content, "first\n");
        assert!(
            app.chat_session.message_count() == 0,
            "Ctrl+J must not submit the prompt"
        );
    }

    #[test]
    fn bracketed_paste_inserts_multiline_prompt() {
        let mut app = App::new("test", "anthropic");

        app.handle_app_event(Ok(AppEvent::Paste("first\r\nsecond".to_string())));

        assert_eq!(app.input.content, "first\nsecond");
        assert_eq!(app.chat_session.message_count(), 0);
    }

    #[test]
    fn enter_submits_full_multiline_prompt() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = App::new("test", "anthropic");
        app.input.insert_str("first\nsecond");

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(app.input.is_empty());
        let messages = app.chat_session.messages_snapshot();
        assert_eq!(
            messages.last().and_then(|msg| msg.get("content")),
            Some(&serde_json::json!("first\nsecond"))
        );
    }

    /// Global Ctrl+C escape hatch: while a modal overlay is open, Ctrl+C
    /// closes the overlay instead of quitting the app. Pins the
    /// pre-existing observable behaviour where overlay-handling ran
    /// before the global Ctrl+C check.
    #[test]
    fn ctrl_c_in_modal_closes_overlay_without_quitting() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = App::new("test", "anthropic");
        app.open_help_overlay();
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(
            app.overlay.is_none(),
            "Ctrl+C in modal must close the overlay"
        );
        assert!(!app.should_quit, "Ctrl+C in modal must NOT quit the app");
    }

    /// Global Ctrl+C quits when no overlay or permission prompt is
    /// active. The mode-split refactor must preserve this — the
    /// universal quit behaviour was the second-most-load-bearing
    /// observable in `handle_key`.
    #[test]
    fn ctrl_c_in_normal_quits_app() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = App::new("test", "anthropic");
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit, "Ctrl+C in normal mode must quit");
    }

    // =========================================================================
    // Behavior: spawn_shell — closes crosslink #371 by moving subprocess
    // execution off the sync TUI event loop and onto the tokio runtime.
    // =========================================================================

    /// Build an App wired to a tokio runtime handle and a fresh mpsc channel.
    /// Returns the receiver so the test can observe `AppEvent::ShellDone`.
    fn wire_app(app: &mut App) -> mpsc::Receiver<AppEvent> {
        app.runtime_handle = tokio::runtime::Handle::try_current().ok();
        let (tx, rx) = mpsc::channel::<AppEvent>();
        app.api_event_tx = Some(tx);
        rx
    }

    #[tokio::test]
    async fn supervised_background_completion_keeps_its_call_id_until_event_delivery() {
        let mut app = App::new("test-model", "test-provider");
        let rx = wire_app(&mut app);
        app.supervisor = Some(TuiSupervisor::new(tokio::runtime::Handle::current()));

        let detached = app.spawn_owned_event(TuiTaskKind::Filesystem, async {
            AppEvent::ShellDone {
                target: SpawnTarget::Files,
                stdout: "owned result".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
            }
        });
        assert!(
            detached.is_none(),
            "the launch supervisor must own the task"
        );

        let event = loop {
            tokio::task::yield_now().await;
            if let Ok(event) = rx.try_recv() {
                break event;
            }
        };
        let AppEvent::Correlated { call_id, .. } = &event else {
            panic!("supervised background completion must be call-correlated");
        };
        let call_id = *call_id;

        app.reap_supervised_tasks().await;
        assert!(
            app.background_calls.contains_key(&call_id),
            "task completion must not make its already-queued event stale"
        );
        assert!(app.handle_app_event(Ok(event)));
        assert!(!app.background_calls.contains_key(&call_id));
    }

    #[tokio::test]
    async fn newer_discovery_cancels_the_superseded_call_generation() {
        let mut app = App::new("test-model", "test-provider");
        let rx = wire_app(&mut app);
        app.supervisor = Some(TuiSupervisor::new(tokio::runtime::Handle::current()));

        drop(app.spawn_owned_event(TuiTaskKind::ProviderDiscovery, std::future::pending()));
        drop(
            app.spawn_owned_event(TuiTaskKind::ProviderDiscovery, async {
                AppEvent::ProviderSwitchError("latest discovery".to_string())
            }),
        );

        let event = loop {
            tokio::task::yield_now().await;
            app.reap_supervised_tasks().await;
            if let Ok(event) = rx.try_recv() {
                break event;
            }
        };
        assert!(matches!(
            &event,
            AppEvent::Correlated { event, .. }
                if matches!(event.as_ref(), AppEvent::ProviderSwitchError(message) if message == "latest discovery")
        ));
        assert_eq!(
            app.background_calls.len(),
            1,
            "the cancelled discovery generation must be reaped"
        );
        assert!(app.handle_app_event(Ok(event)));
        assert!(app.background_calls.is_empty());
    }

    /// Block the current thread on `rx` for up to `timeout`, returning the
    /// first `ShellDone` event seen — or `None` if nothing arrives in time.
    /// Other event variants are skipped (the sync loop would handle them
    /// separately).
    fn recv_shell_done(
        rx: &mpsc::Receiver<AppEvent>,
        timeout: Duration,
    ) -> Option<(SpawnTarget, String, String, Option<i32>)> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            if let AppEvent::ShellDone {
                target,
                stdout,
                stderr,
                exit_code,
            } = rx.recv_timeout(remaining).ok()?
            {
                return Some((target, stdout, stderr, exit_code));
            }
            // Other event variants belong to the real event loop — skip
            // them and keep waiting for our ShellDone.
        }
    }

    #[test]
    fn spawn_shell_without_runtime_reports_error_without_panicking() {
        let mut app = App::new("test-model", "test-provider");
        let (tx, rx) = mpsc::channel::<AppEvent>();
        app.api_event_tx = Some(tx);

        let join = app.spawn_shell(vec!["echo", "unused"], SpawnTarget::Diff);
        assert!(
            join.is_none(),
            "spawn_shell must not manufacture a task without a runtime"
        );

        let (target, stdout, stderr, exit_code) = recv_shell_done(&rx, Duration::from_millis(100))
            .expect("expected ShellDone error when runtime is unavailable");
        assert!(matches!(target, SpawnTarget::Diff));
        assert!(stdout.is_empty());
        assert!(
            stderr.contains("no async runtime bound"),
            "stderr should explain missing runtime, got {stderr:?}"
        );
        assert_eq!(exit_code, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restricted_mode_blocks_tui_shell_shortcuts_before_spawn() {
        let mut app = App::new("test-model", "test-provider");
        let run = app.tool_run_context().expect("run");
        let targets = crate::modes::BehaviorScopeTargets::from_user_values(
            run.project_root(),
            run.working_directory(),
            &[".".to_string()],
        )
        .expect("explicit explore target");
        app.apply_behavior_mode_and_targets(
            crate::modes::BehaviorMode::from_preset(crate::modes::Preset::Explore),
            targets,
        )
        .expect("explore mode");
        let rx = wire_app(&mut app);

        let join = app
            .spawn_direct_shell("printf must-not-run")
            .expect("mode admission runs in the nonblocking task");
        join.await.expect("direct shell admission task");
        let (_, stdout, stderr, exit_code) =
            recv_shell_done(&rx, Duration::from_millis(100)).expect("mode denial event");
        assert!(stdout.is_empty());
        assert!(stderr.contains("denies direct operation"), "{stderr}");
        assert_eq!(exit_code, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_shell_returns_immediately_and_runs_in_background() {
        // The helper must not block the calling (event-loop) thread. We
        // ask it to launch `sleep 0.4` and measure that the *call itself*
        // returns in < 100ms — well below the child's lifetime — and
        // that the JoinHandle eventually completes.
        let mut app = App::new("test-model", "test-provider");
        let rx = wire_app(&mut app);

        let call_start = Instant::now();
        let join = app
            .spawn_shell(vec!["sleep", "0.4"], SpawnTarget::Diff)
            .expect("runtime-backed spawn_shell should return a task handle");
        let call_elapsed = call_start.elapsed();

        // Pre-#371 implementation blocked for the full child lifetime.
        // 100ms is generous: spawning a tokio task is microseconds.
        assert!(
            call_elapsed < Duration::from_millis(100),
            "spawn_shell blocked the caller for {call_elapsed:?} — should return immediately"
        );

        // The handle must actually resolve once the child exits.
        join.await.expect("spawn_shell task panicked");

        // And the receiver must have observed the ShellDone event.
        let done = recv_shell_done(&rx, Duration::from_millis(500))
            .expect("expected ShellDone event after join");
        assert!(matches!(done.0, SpawnTarget::Diff));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_shell_success_delivers_stdout() {
        // `echo hello-371` writes "hello-371\n" to stdout and exits 0.
        // ShellDone must carry that stdout and an exit_code of Some(0).
        let mut app = App::new("test-model", "test-provider");
        let rx = wire_app(&mut app);

        let join = app
            .spawn_shell(vec!["echo", "hello-371"], SpawnTarget::Diff)
            .expect("runtime-backed spawn_shell should return a task handle");
        join.await.expect("spawn_shell task panicked");

        let (target, stdout, _stderr, exit_code) = recv_shell_done(&rx, Duration::from_millis(500))
            .expect("expected ShellDone event from successful echo");
        assert!(matches!(target, SpawnTarget::Diff));
        assert_eq!(exit_code, Some(0), "echo should exit 0");
        assert!(
            stdout.contains("hello-371"),
            "expected stdout to contain 'hello-371', got {stdout:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn spawn_shell_uses_exact_run_cwd_and_environment() {
        let root = tempfile::tempdir_in(".").expect("TUI shell root");
        let run =
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root.path())
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(std::collections::HashMap::from([(
                    "S019_TUI_ENV".to_string(),
                    "exact".to_string(),
                )]))
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(false)
                .secrets(false)
                .provider("tui-shell-environment-test")
                .build()
                .expect("explicit TUI shell run");
        let expected_cwd = run.working_directory().to_string_lossy().into_owned();
        let mut app = App::new("test-model", "test-provider");
        app.run_context = Ok(run);
        let rx = wire_app(&mut app);
        let ungranted = "S019_TUI_UNGRANTED";
        let command =
            format!("printf '%s|%s|' \"$S019_TUI_ENV\" \"${{{ungranted}:-missing}}\"; pwd");

        let join = app
            .spawn_shell(vec!["bash", "-c", &command], SpawnTarget::Diff)
            .expect("run-bound TUI shell task");
        join.await.expect("TUI shell task panicked");

        let (_, stdout, stderr, exit_code) =
            recv_shell_done(&rx, Duration::from_millis(500)).expect("TUI shell result");
        assert_eq!(exit_code, Some(0), "stderr: {stderr}");
        assert_eq!(stdout.trim(), format!("exact|missing|{expected_cwd}"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_shell_failure_delivers_nonzero_exit() {
        // `bash -c 'exit 7'` exits with code 7. ShellDone must surface
        // exit_code = Some(7) so the renderer picks the ToolErr branch.
        let mut app = App::new("test-model", "test-provider");
        let rx = wire_app(&mut app);

        let join = app
            .spawn_direct_shell("exit 7")
            .expect("runtime-backed direct shell should return a task handle");
        join.await.expect("direct shell task panicked");

        let (target, _stdout, _stderr, exit_code) =
            recv_shell_done(&rx, Duration::from_millis(500))
                .expect("expected ShellDone event from failing bash");
        assert!(matches!(target, SpawnTarget::ShellCommand { .. }));
        assert_eq!(
            exit_code,
            Some(7),
            "bash -c 'exit 7' should report exit_code = Some(7)"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_shell_records_ledger_observation() {
        let mut app = App::new("test-model", "test-provider");
        let rx = wire_app(&mut app);
        let run = Arc::clone(app.run_context.as_ref().expect("TUI run context"));
        let freshness_before =
            crate::evidence_freshness::current_stamp(&run).expect("capture freshness before shell");
        let ledger = Arc::new(Mutex::new(crate::ledger::RealityLedger::new()));
        let _guard =
            crate::ledger::install_active_ledger_for_session(app.chat_session.id(), ledger.clone());

        let join = app
            .spawn_direct_shell("printf tui-ledger")
            .expect("runtime-backed direct shell should return a task handle");
        join.await.expect("direct shell task panicked");

        let (_target, stdout, stderr, exit_code) = recv_shell_done(&rx, Duration::from_millis(500))
            .expect("expected ShellDone event from shell command");
        assert_eq!(stdout, "tui-ledger");
        assert!(stderr.is_empty());
        assert_eq!(exit_code, Some(0));

        let observations = {
            let ledger = ledger.lock().expect("ledger lock");
            ledger
                .observations_chronological()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        let freshness_after =
            crate::evidence_freshness::current_stamp(&run).expect("capture freshness after shell");
        assert_eq!(
            freshness_after.workspace_generation,
            freshness_before.workspace_generation + 1,
            "arbitrary TUI shell execution must advance workspace freshness"
        );
        assert_eq!(observations.len(), 1);
        assert_eq!(
            observations[0].provenance.freshness.as_ref(),
            Some(&freshness_after),
            "command receipt must bind the post-execution freshness generation"
        );
        assert!(observations.iter().any(|obs| {
            matches!(
                &obs.kind,
                crate::ledger::ObservationKind::CommandRun {
                    argv,
                    exit_code,
                    stdout,
                    stderr,
                    ..
                } if argv == &vec![
                    "bash".to_string(),
                    "-c".to_string(),
                    "printf tui-ledger".to_string(),
                ] && *exit_code == 0
                    && stdout == "tui-ledger"
                    && stderr.is_empty()
            )
        }));
    }

    #[test]
    fn legacy_shell_spawn_rejects_direct_shell_targets() {
        let mut app = App::new("test-model", "test-provider");
        let (tx, rx) = mpsc::channel::<AppEvent>();
        app.api_event_tx = Some(tx);

        let join = app.spawn_shell(
            vec!["bash", "-c", "printf bypass"],
            SpawnTarget::ShellCommand {
                displayed: "printf bypass".to_string(),
            },
        );

        assert!(join.is_none());
        let (_, stdout, stderr, exit_code) = recv_shell_done(&rx, Duration::from_millis(100))
            .expect("canonical-route rejection event");
        assert!(stdout.is_empty());
        assert!(stderr.contains("canonical process capability"));
        assert_eq!(exit_code, None);
    }

    #[test]
    fn direct_shell_failure_rendering_preserves_partial_output() {
        let mut app = App::new("test-model", "test-provider");

        app.handle_shell_done(
            SpawnTarget::ShellCommand {
                displayed: "slow-command".to_string(),
            },
            "partial stdout",
            "command timed out",
            None,
        );

        let message = app.messages.messages.last().expect("shell result");
        assert!(message.kind.is_error());
        assert!(message.content.contains("partial stdout"));
        assert!(message.content.contains("command timed out"));
    }

    #[test]
    fn handle_input_routes_bang_prefix_to_shell_command() {
        let mut app = App::new("test-model", "test-provider");
        let (tx, rx) = mpsc::channel::<AppEvent>();
        app.api_event_tx = Some(tx);

        app.handle_input("!echo routed-from-input".to_string());

        let (target, stdout, stderr, exit_code) = recv_shell_done(&rx, Duration::from_millis(100))
            .expect("expected ShellDone event from ! input");
        assert!(
            matches!(target, SpawnTarget::ShellCommand { ref displayed } if displayed == "echo routed-from-input"),
            "expected shell-command target, got {target:?}"
        );
        assert!(stdout.is_empty());
        assert!(
            stderr.contains("no async runtime bound"),
            "missing-runtime shell path should explain the failure, got {stderr:?}"
        );
        assert_eq!(exit_code, None);
        assert!(
            app.chat_session.message_count() == 0,
            "! shell escapes must not be submitted as chat messages"
        );
    }

    // =========================================================================
    // Behavior: expand_file_refs — panic-free regex handling (#292)
    // =========================================================================

    #[test]
    fn expand_file_refs_no_at_sign_returns_input_unchanged() {
        // Fast path: no '@' in input — function returns immediately without
        // touching the regex.  Output must equal the input exactly.
        let input = "hello world, no references here";
        assert_eq!(
            expand_file_refs(crate::tools::security::test_run_context(), input),
            input
        );
    }

    #[test]
    fn handle_input_expands_at_file_reference_before_api_turn() {
        let cwd = std::env::current_dir().expect("cwd");
        let mut file = tempfile::NamedTempFile::new_in(&cwd).expect("temp file in cwd");
        writeln!(file, "included context from tui").expect("write temp file");
        let file_name = file
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("utf-8 temp filename")
            .to_string();

        let mut app = App::new("test-model", "test-provider");
        app.handle_input(format!("please read @{file_name}"));

        let messages = app.chat_session.messages_snapshot();
        let content = messages
            .last()
            .and_then(|message| message.get("content"))
            .and_then(serde_json::Value::as_str)
            .expect("user message content");
        assert!(content.contains("please read "));
        assert!(content.contains("<file path=\""));
        assert!(content.contains("included context from tui"));
        assert!(content.contains("</file>"));
    }

    #[test]
    fn expand_file_refs_cannot_read_a_foreign_run_root() {
        let owner_root = tempfile::tempdir_in(".").expect("owner root");
        let foreign_root = tempfile::tempdir_in(".").expect("foreign root");
        let foreign_file = foreign_root.path().join("secret.txt");
        std::fs::write(&foreign_file, "S019-TUI-FOREIGN-SECRET").expect("foreign fixture");
        let run = crate::tools::security::test_run_context_for(owner_root.path());
        let input = format!("inspect @\"{}\"", foreign_file.display());

        let expanded = expand_file_refs(&run, &input);

        assert!(!expanded.contains("S019-TUI-FOREIGN-SECRET"));
        assert!(
            expanded.contains("outside granted roots"),
            "foreign reference must fail at the run capability boundary: {expanded}"
        );
    }

    #[test]
    fn invalid_file_ref_regex_is_skipped() {
        assert!(compile_file_ref_regex("[").is_none());
    }

    #[test]
    fn expand_file_refs_double_at_does_not_panic() {
        // Regression guard for the old `.unwrap()` on cap.get(0): a bare '@@'
        // or '@ @' must not panic regardless of whether the regex matches.
        let run = crate::tools::security::test_run_context();
        let _ = expand_file_refs(run, "@@");
        let _ = expand_file_refs(run, "@ @");
        let _ = expand_file_refs(run, "email@example.com and @another");
    }

    #[test]
    fn expand_file_refs_unclosed_quote_does_not_panic() {
        // A `@"` with no closing quote must not panic — the regex simply won't
        // match group 1, and the `if let Some` guard skips it cleanly.
        let run = crate::tools::security::test_run_context();
        let _ = expand_file_refs(run, r#"@"unclosed"#);
        let _ = expand_file_refs(run, r#"some text @"no end here and more text"#);
    }

    #[test]
    fn expand_file_refs_many_at_signs_does_not_panic() {
        // Stress: 1 000 '@' characters in a row must not panic or overflow.
        let input = "@".repeat(1_000);
        let _ = expand_file_refs(crate::tools::security::test_run_context(), &input);
    }

    // =========================================================================
    // Behavior: event-driven transcript watermark — crosslink #709
    // =========================================================================

    /// Drop guard restoring `CLAUDE_CONFIG_HOME_DIR` to its previous
    /// value (or unsetting it) when the scope exits, even on panic.
    /// Holds the crate-wide [`crate::transcript::env_lock`] for the
    /// guard's lifetime so concurrent tests in other modules that
    /// mutate the same env var cannot observe a half-mutated state.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
        // Field exists to hold the lock for the EnvGuard's lifetime.
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(key: &'static str, val: &std::path::Path) -> Self {
            let lock = crate::transcript::env_lock();
            let prev = std::env::var(key).ok();
            std::env::set_var(key, val);
            Self {
                key,
                prev,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// Test-only override for TUI JSON session storage. This avoids
    /// process-global `XDG_DATA_HOME` mutations that other parallel tests can
    /// accidentally observe while still exercising `save_session` /
    /// `list_sessions` through the real filesystem.
    struct SessionDirGuard {
        prev: Option<PathBuf>,
    }

    impl SessionDirGuard {
        fn set(path: PathBuf) -> Self {
            let prev = TEST_SESSIONS_DIR.with(|slot| slot.replace(Some(path)));
            Self { prev }
        }
    }

    impl Drop for SessionDirGuard {
        fn drop(&mut self) {
            TEST_SESSIONS_DIR.with(|slot| {
                slot.replace(self.prev.take());
            });
        }
    }

    #[test]
    fn startup_resume_loads_most_recent_saved_session() {
        const OLDER_ID: &str = "11111111-1111-4111-8111-111111111111";
        const NEWER_ID: &str = "22222222-2222-4222-8222-222222222222";
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = SessionDirGuard::set(tmp.path().join("chat_sessions"));

        let mut older = Session::new("old-model", "initial-provider");
        older.set_id(OLDER_ID.to_string());
        older.created_at = chrono::DateTime::parse_from_rfc3339("2025-12-31T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        older.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        older.push_message(serde_json::json!({"role": "user", "content": "older"}));

        let mut newer = Session::new_with_behavior_mode(
            "new-model",
            "initial-provider",
            crate::modes::BehaviorMode::from_preset(crate::modes::Preset::Explore),
        );
        let project_root = std::env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("canonical project root");
        let explore_targets = crate::modes::BehaviorScopeTargets::from_user_values(
            &project_root,
            &project_root,
            &[".".to_string()],
        )
        .expect("explicit explore target");
        newer.set_behavior_mode_and_targets(newer.behavior_mode(), explore_targets);
        newer.set_id(NEWER_ID.to_string());
        newer.created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        newer.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        newer.push_message(serde_json::json!({"role": "user", "content": "newer"}));

        save_session(&older).expect("older session should save");
        save_session(&newer).expect("newer session should save");

        let mut app = App::new("initial-model", "initial-provider");
        let initial_id = app.chat_session.id();
        let mut state_events = app.chat_session.state_store().subscribe_log_lag();
        app.apply_startup_resume(true, None);

        assert_eq!(
            app.chat_session.id(),
            NEWER_ID,
            "resume diagnostics: {:?}",
            app.messages
                .messages
                .iter()
                .map(|message| message.content.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(app.model, "new-model");
        assert_eq!(app.provider, "initial-provider");
        assert_eq!(app.chat_session.messages_snapshot()[0]["content"], "newer");
        assert_eq!(
            app.tool_run_context()
                .expect("resumed run")
                .runtime_mode()
                .class,
            crate::modes::RuntimeModeClass::ReadOnly
        );
        let mut saw_session_switch = false;
        while let Some(event) = state_events.try_recv() {
            if matches!(
                event,
                crate::state::StateEvent::SessionSwitched {
                    from,
                    to,
                    from_messages: 0,
                } if from.as_str() == initial_id && to.as_str() == NEWER_ID
            ) {
                saw_session_switch = true;
            }
        }
        assert!(
            saw_session_switch,
            "resume must publish the session boundary"
        );
    }

    #[test]
    fn startup_resume_can_bind_explicit_targets_before_deriving_a_narrow_run() {
        const SESSION_ID: &str = "33333333-3333-4333-8333-333333333333";
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = SessionDirGuard::set(tmp.path().join("chat_sessions"));
        let project_root = std::env::current_dir()
            .expect("current directory")
            .canonicalize()
            .expect("canonical project root");
        let target_values = ["src/tui/app.rs".to_string()];
        let targets = crate::modes::BehaviorScopeTargets::from_user_values(
            &project_root,
            &project_root,
            &target_values,
        )
        .expect("explicit TUI target");

        let saved = Session::new_with_behavior_mode(
            "saved-model",
            "initial-provider",
            crate::modes::BehaviorMode::from_preset(crate::modes::Preset::Safe),
        );
        saved.set_id(SESSION_ID.to_string());
        save_session(&saved).expect("narrow session should save");

        let mut app = App::new("initial-model", "initial-provider");
        app.apply_startup_resume_with_behavior(true, None, None, &target_values)
            .expect("startup target override should bind the resumed run");

        assert_eq!(app.chat_session.id(), SESSION_ID);
        assert_eq!(app.chat_session.behavior_scope_targets(), targets);
        let snapshot = app
            .tool_run_context()
            .expect("resumed narrow run")
            .runtime_mode();
        assert!(matches!(
            snapshot.mode,
            crate::modes::RuntimeMode::Behavioral(crate::modes::BehaviorMode {
                scope: crate::modes::Scope::Narrow,
                ..
            })
        ));
        assert_eq!(snapshot.scope_targets, targets);
    }

    #[test]
    fn startup_session_id_takes_precedence_over_resume() {
        const OLDER_ID: &str = "11111111-1111-4111-8111-111111111111";
        const NEWER_ID: &str = "22222222-2222-4222-8222-222222222222";
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = SessionDirGuard::set(tmp.path().join("chat_sessions"));

        let mut older = Session::new("old-model", "initial-provider");
        older.set_id(OLDER_ID.to_string());
        older.created_at = chrono::DateTime::parse_from_rfc3339("2025-12-31T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        older.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);

        let mut newer = Session::new("new-model", "initial-provider");
        newer.set_id(NEWER_ID.to_string());
        newer.created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        newer.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);

        save_session(&older).expect("older session should save");
        save_session(&newer).expect("newer session should save");

        let mut app = App::new("initial-model", "initial-provider");
        app.apply_startup_resume(true, Some("11111111"));

        assert_eq!(app.chat_session.id(), OLDER_ID);
        assert_eq!(app.model, "old-model");
    }

    #[test]
    fn startup_resume_rejects_a_different_provider_without_rebinding_transport() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = SessionDirGuard::set(tmp.path().join("chat_sessions"));
        let foreign = Session::new("foreign-model", "foreign-provider");
        let foreign_id = foreign.id();
        save_session(&foreign).expect("foreign session should save");

        let mut app = App::new("initial-model", "initial-provider");
        let initial_id = app.chat_session.id();
        app.apply_startup_resume(false, Some(&foreign_id));

        assert_eq!(app.chat_session.id(), initial_id);
        assert_eq!(app.provider, "initial-provider");
        assert!(app
            .messages
            .messages
            .iter()
            .any(|message| { message.content.contains("differs from the active provider") }));
    }

    #[test]
    fn save_session_rejects_invalid_session_id() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = SessionDirGuard::set(tmp.path().join("chat_sessions"));

        let session = Session::new("model", "provider");
        session.set_id("../outside".to_string());

        let err = save_session(&session).expect_err("path traversal id must be rejected");

        assert!(
            err.to_string().contains("invalid file state")
                && err.to_string().contains("invalid characters"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn list_sessions_skips_invalid_stored_session_id() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let session_dir = tmp.path().join("chat_sessions");
        let _guard = SessionDirGuard::set(session_dir.clone());

        let mut valid = Session::new("valid-model", "provider");
        valid.set_id("abc".to_string());
        valid.created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        valid.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        save_session(&valid).expect("short valid id should save");

        let invalid = Session::new("invalid-model", "provider");
        let mut invalid_value =
            serde_json::to_value(&invalid).expect("serialize structurally valid fixture");
        invalid_value["id"] = serde_json::json!("../outside");
        std::fs::write(
            session_dir.join("invalid.json"),
            serde_json::to_string(&invalid_value).expect("serialize invalid fixture bytes"),
        )
        .expect("write invalid fixture");

        let sessions = list_sessions();

        assert_eq!(sessions.len(), 1, "invalid stored session must be skipped");
        assert_eq!(sessions[0].id(), "abc");
    }

    #[cfg(unix)]
    #[test]
    fn read_tui_session_file_refuses_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        let link = tmp.path().join("linked.json");
        let session = Session::new("model", "provider");
        session.set_id("linked".to_string());
        std::fs::write(&target, serde_json::to_vec(&session).unwrap()).unwrap();
        symlink(target, &link).unwrap();

        let error = read_tui_session_file(&link).expect_err("symlinks must be rejected");
        assert!(error.to_string().contains("must not be a symlink"));
    }

    #[test]
    fn transcript_subscriber_advances_watermark_to_len_on_message_events() {
        // Happy path: every queued message persists successfully, so the
        // watermark moves all the way to session_messages.len(). The
        // Transcript writes land in OpenClaudia-owned storage, redirected to
        // a tempdir so the test cannot pollute the user's data directory.
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set("OPENCLAUDIA_TRANSCRIPT_HOME_DIR", tmp.path());

        let mut app = App::new("test-model", "test-provider");
        app.chat_session
            .set_transcript_position(tmp.path().to_path_buf(), 0);
        app.chat_session
            .push_message(serde_json::json!({"role": "user", "content": "one"}));
        app.chat_session
            .push_message(serde_json::json!({"role": "assistant", "content": "two"}));
        app.chat_session
            .push_message(serde_json::json!({"role": "user", "content": "three"}));

        app.drain_state_subscribers();

        assert_eq!(
            app.chat_session.state_snapshot().transcript.watermark,
            3,
            "watermark advances to len when every append succeeds"
        );
    }

    #[test]
    fn transcript_subscriber_retries_after_a_failed_append() {
        // crosslink #709 regression: when `append_entry` fails, the
        // watermark must NOT jump to session_messages.len() (which would
        // permanently drop the un-persisted tail). Instead it must
        // advance only by the count actually written.
        //
        // Failure is injected by placing a regular FILE at the path
        // `create_dir_all` would otherwise create as a directory
        // (`<OPENCLAUDIA_TRANSCRIPT_HOME_DIR>/projects/`). `create_dir_all`
        // then errors with "Not a directory" on every append, so zero
        // entries persist and the watermark must stay at 0 (the bug
        // jumped it straight to 3).
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("projects"), b"not a directory")
            .expect("write blocker file");
        let _guard = EnvGuard::set("OPENCLAUDIA_TRANSCRIPT_HOME_DIR", tmp.path());

        let mut app = App::new("test-model", "test-provider");
        app.chat_session
            .set_transcript_position(tmp.path().to_path_buf(), 0);
        app.chat_session
            .push_message(serde_json::json!({"role": "user", "content": "one"}));
        app.chat_session
            .push_message(serde_json::json!({"role": "assistant", "content": "two"}));
        app.chat_session
            .push_message(serde_json::json!({"role": "user", "content": "three"}));

        app.drain_state_subscribers();

        assert_eq!(
            app.chat_session.state_snapshot().transcript.watermark,
            0,
            "watermark must NOT advance past entries that failed to persist (was: {})",
            app.chat_session.state_snapshot().transcript.watermark
        );

        std::fs::remove_file(tmp.path().join("projects")).expect("remove blocker file");
        app.transcript_subscriber.flush_now();
        assert_eq!(
            app.chat_session.state_snapshot().transcript.watermark,
            3,
            "a later save boundary must retry the previously failed tail"
        );
    }

    #[test]
    fn transcript_subscriber_clamps_watermark_after_rewind() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set("OPENCLAUDIA_TRANSCRIPT_HOME_DIR", tmp.path());

        let mut app = App::new("test-model", "test-provider");
        app.chat_session.replace_messages(vec![serde_json::json!({
            "role": "user",
            "content": "branched turn"
        })]);
        app.chat_session
            .set_transcript_position(tmp.path().to_path_buf(), 3);

        app.transcript_subscriber.flush_now();

        assert_eq!(
            app.chat_session.state_snapshot().transcript.watermark,
            1,
            "a rewind-shortened message list must reset the offset safely"
        );
    }

    #[test]
    fn transcript_subscriber_reconciles_after_event_channel_lag() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set("OPENCLAUDIA_TRANSCRIPT_HOME_DIR", tmp.path());
        let mut app = App::new("test-model", "test-provider");
        app.chat_session
            .set_transcript_position(tmp.path().to_path_buf(), 0);

        for index in 0..65 {
            app.chat_session.push_message(serde_json::json!({
                "role": "user",
                "content": format!("message-{index}")
            }));
        }
        app.drain_state_subscribers();

        assert_eq!(
            app.chat_session.state_snapshot().transcript.watermark,
            65,
            "lag recovery must reconcile the entire canonical tail"
        );
        let transcript =
            crate::transcript::transcript_path(tmp.path(), app.chat_session.id().as_str());
        assert_eq!(crate::transcript::load_transcript(&transcript).len(), 65);
    }
}

//! Full-screen interactive TUI application.
//!
//! Launched via `openclaudia` when no subcommand, `--print`, or `--tui-mode`
//! is supplied.
//! Provides a scrollable message view, text input area, status bar,
//! and streaming response display wired to the real API pipeline.

use super::events::{ApiRetryKind, AppEvent, EventHandler, ProviderSwitch, SpawnTarget};
use super::input::TextInput;
use super::messages::{DisplayMessage, EffortLevel, MessageKind, MessageList, Mode};
use super::{DIM, GOLD, PURPLE, SPINNER_FRAMES};
use crossterm::{
    event::{DisableBracketedPaste, EnableBracketedPaste, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::LazyLock;
use std::time::Duration;

use crate::file_error::{self, FileError};
use crate::state::Session;

const INPUT_PROMPT_WIDTH: u16 = 2;
const MIN_INPUT_HEIGHT: u16 = 3;
const MAX_INPUT_HEIGHT: u16 = 8;

/// Absolute, PATH-independent location of `git` for synchronous TUI helpers.
static GIT_BIN: LazyLock<Result<PathBuf, String>> =
    LazyLock::new(|| which::which("git").map_err(|e| format!("git binary not found on PATH: {e}")));

fn git_bin() -> Result<&'static Path, String> {
    match &*GIT_BIN {
        Ok(path) => Ok(path.as_path()),
        Err(msg) => Err(msg.clone()),
    }
}

fn git_command() -> Result<Command, String> {
    Ok(Command::new(git_bin()?))
}

fn inserts_newline(modifiers: KeyModifiers) -> bool {
    modifiers.intersects(KeyModifiers::SHIFT | KeyModifiers::ALT | KeyModifiers::CONTROL)
}

fn input_content_width(area_width: u16) -> u16 {
    area_width.saturating_sub(INPUT_PROMPT_WIDTH).max(1)
}

fn current_exe_command() -> Result<Command, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("failed to resolve current executable: {e}"))?;
    Ok(Command::new(exe))
}

fn format_init_command_output(out: &Output) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
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
    if out.status.success() {
        if details.is_empty() {
            "Initialized OpenClaudia configuration in .openclaudia/".to_string()
        } else {
            details
        }
    } else if details.is_empty() {
        format!("Init failed: {}", out.status)
    } else {
        format!("Init failed: {details}")
    }
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

/// Process-wide shutdown flag for the TUI event loop.
///
/// crosslink #910: the original `run()` loop relied entirely on the
/// `should_quit` field plus the event channel — there was no way for
/// out-of-band code (a tokio signal handler, an integration test, the
/// proxy's `/shutdown` endpoint) to ask the loop to exit without
/// synthesising a keypress. This `AtomicBool` is checked at the top of
/// every tick, giving any caller a lock-free, panic-safe way to bring
/// the UI down cleanly.
///
/// Set via [`request_tui_shutdown`]. The flag is sticky for the
/// lifetime of the process — once shutdown is requested, every future
/// TUI invocation will exit immediately. That is intentional: a
/// shutdown request that survives a restart is what an embedded host
/// (or a watchdog) wants.
pub static TUI_SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Signal the TUI event loop to exit at the next tick.
///
/// Safe to call from any thread, including signal handlers — the
/// underlying store is lock-free.
pub fn request_tui_shutdown() {
    TUI_SHUTDOWN.store(true, std::sync::atomic::Ordering::Relaxed);
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
fn expand_file_refs(input: &str) -> String {
    if !input.contains('@') {
        return input.to_string();
    }
    let Some(file_ref_re) = (*FILE_REF_RE).as_ref() else {
        return input.to_string();
    };
    let mut result = input.to_string();
    let mut replacements = Vec::new();

    // Get project root for path traversal validation
    let cwd = std::env::current_dir().unwrap_or_default();

    for cap in file_ref_re.captures_iter(input) {
        let full_match = match cap.get(0) {
            Some(m) => m.as_str(),
            None => continue,
        };
        let raw_path = match cap.get(1).or_else(|| cap.get(2)) {
            Some(m) => m.as_str(),
            None => continue,
        };

        // Resolve and validate path — reject traversal attempts
        let resolved = if std::path::Path::new(raw_path).is_absolute() {
            std::path::PathBuf::from(raw_path)
        } else {
            cwd.join(raw_path)
        };

        // Reject paths with .. components
        if resolved
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            replacements.push((
                full_match.to_string(),
                format!("[Path traversal blocked: {raw_path}]"),
            ));
            continue;
        }

        // #818: open-then-read on a single file descriptor.  The previous
        // canonicalize → read_to_string pair was a TOCTOU window — between
        // the two syscalls the path could be replaced with a symlink to an
        // arbitrary file.  We now open the file first (yielding an fd
        // pinned to one inode), then validate the canonical path of the
        // already-resolved name, then read from the same fd.  Any post-open
        // symlink flip is irrelevant — the kernel keeps reading the
        // originally-opened inode.
        let Ok(mut file) = std::fs::File::open(&resolved) else {
            replacements.push((
                full_match.to_string(),
                format!("[File not found: {raw_path}]"),
            ));
            continue;
        };
        // Canonicalize for the containment check.  Even if the symlink
        // chain is swapped between the open() above and this canonicalize,
        // the file we will actually read is the inode pinned by `file`.
        let Ok(canonical) = std::fs::canonicalize(&resolved) else {
            replacements.push((
                full_match.to_string(),
                format!("[File not found: {raw_path}]"),
            ));
            continue;
        };
        if !canonical.starts_with(&cwd) {
            replacements.push((
                full_match.to_string(),
                format!("[File outside project directory: {raw_path}]"),
            ));
            continue;
        }
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

/// Dispatch table for the TUI's no-argument slash commands (crosslink #259).
///
/// Each entry maps a canonical command spelling (`/quit`, `/help`, …) to
/// the [`App`] method that handles it. The TUI keeps its own table — the
/// CLI's [`command_registry`] cannot be reused directly because CLI
/// handlers print to stdout, which corrupts the TUI's alternate-screen
/// rendering. Mirroring the registry *pattern* here (table-driven
/// dispatch over an if-chain) is the OCP win #232 brought to the CLI;
/// this commit extends it to the TUI for the seven branches below.
///
/// Adding a new no-arg TUI command:
///   1. Add a `slash_<name>` method on [`App`] that takes `&mut self`.
///   2. Append `("/canonical_name", App::slash_<name>)` to this table.
///   3. (Optional) Add aliases by appending more `(alias, App::slash_<name>)`
///      rows pointing at the same handler.
///
/// Commands that take arguments (`/load <id>`, `/rewind N`, `/effort low`,
/// `/rename <title>`, …) bypass the table because their key shape is a
/// prefix, not an exact match — they continue through `handle_session_slash`,
/// `handle_export_effort_slash`, and `handle_info_slash` until a future pass
/// generalises the table to prefix dispatch (documented in
/// [`App::handle_slash_command`]'s rustdoc).
type TuiSlashHandler = fn(&mut App);

const TUI_SLASH_TABLE: &[(&str, TuiSlashHandler)] = &[
    ("/quit", App::slash_quit),
    ("/exit", App::slash_quit),
    ("/help", App::slash_help),
    ("?", App::slash_help),
    ("/resume", App::slash_resume),
    ("/continue", App::slash_resume),
    ("/clear", App::slash_clear),
    ("/status", App::slash_status),
    ("/mode", App::slash_mode),
    ("/skill", App::slash_skill_list),
    ("/skills", App::slash_skill_list),
];

/// O(n) lookup for the TUI slash table. The table is small (≤16 entries
/// in practice) so linear scan beats a `HashMap` on cache locality and
/// avoids the `OnceLock` build the CLI registry needs.
fn lookup_tui_slash(text: &str) -> Option<TuiSlashHandler> {
    TUI_SLASH_TABLE
        .iter()
        .find_map(|(name, handler)| (*name == text).then_some(*handler))
}

#[derive(Debug)]
struct ProviderSwitchAuth {
    api_key: Option<crate::providers::ApiKey>,
    claude_code_token: Option<String>,
    codex_responses_auth: Option<crate::codex_credentials::CodexResponsesAuth>,
}

fn missing_provider_auth_message(target: &str) -> String {
    let env_var = crate::providers::api_key_env_var_for_target(target);
    format!("No API key configured for '{target}'. Set {env_var} or add it to config.")
}

async fn resolve_provider_switch_auth(
    target: &str,
    provider: &crate::config::ProviderConfig,
) -> Result<ProviderSwitchAuth, String> {
    if target.eq_ignore_ascii_case("anthropic") && provider.api_key.is_none() {
        if !crate::claude_credentials::has_claude_code_credentials() {
            return Err(
                "No API key configured for Anthropic. Log in with Claude Code or set ANTHROPIC_API_KEY."
                    .to_string(),
            );
        }
        let creds = crate::claude_credentials::load_credentials()
            .await
            .map_err(|e| {
                format!(
                    "Claude Code credentials unusable: {e}. Log in with Claude Code or set ANTHROPIC_API_KEY."
                )
            })?;
        return Ok(ProviderSwitchAuth {
            api_key: None,
            claude_code_token: Some(creds.access_token),
            codex_responses_auth: None,
        });
    }

    if let Some(api_key) = &provider.api_key {
        return Ok(ProviderSwitchAuth {
            api_key: Some(api_key.clone()),
            claude_code_token: None,
            codex_responses_auth: None,
        });
    }

    if target.eq_ignore_ascii_case("openai") {
        match crate::codex_credentials::load_codex_auth() {
            Ok(Some(crate::codex_credentials::CodexAuthMaterial::ApiKey { api_key, .. })) => {
                let api_key = crate::providers::ApiKey::try_from_string(api_key)
                    .map_err(|e| format!("Codex OpenAI API key is invalid: {e}"))?;
                return Ok(ProviderSwitchAuth {
                    api_key: Some(api_key),
                    claude_code_token: None,
                    codex_responses_auth: None,
                });
            }
            Ok(Some(crate::codex_credentials::CodexAuthMaterial::Responses(auth))) => {
                return Ok(ProviderSwitchAuth {
                    api_key: None,
                    claude_code_token: None,
                    codex_responses_auth: Some(auth),
                });
            }
            Ok(Some(crate::codex_credentials::CodexAuthMaterial::Unsupported { mode, source })) => {
                return Err(format!(
                    "Codex auth found via {}, but {} is not usable for OpenAI Responses in OpenClaudia.",
                    source.display_name(),
                    mode.display_name()
                ));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("Codex credentials unusable: {e}")),
        }
    }

    if crate::config::is_local_provider_name(target) {
        return Ok(ProviderSwitchAuth {
            api_key: None,
            claude_code_token: None,
            codex_responses_auth: None,
        });
    }

    Err(missing_provider_auth_message(target))
}

async fn resolve_provider_switch(
    requested: String,
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
    let auth = resolve_provider_switch_auth(&target, &provider).await?;
    let model = provider
        .model
        .clone()
        .unwrap_or_else(|| crate::providers::default_model_for_target(&target).to_string());
    let extra_headers: Vec<(String, String)> = provider
        .headers
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let wire_api = if auth.codex_responses_auth.is_some() {
        crate::pipeline::WireApi::OpenAiResponses
    } else {
        crate::pipeline::WireApi::ChatCompletions
    };
    let (endpoint, headers) = if let Some(codex_auth) = auth.codex_responses_auth.as_ref() {
        let endpoint = crate::pipeline::resolve_endpoint_for_wire(
            wire_api,
            &target,
            &model,
            crate::codex_credentials::CODEX_CHATGPT_BASE_URL,
            None,
        )
        .map_err(|e| e.to_string())?;
        let mut headers = codex_auth.headers();
        headers.extend(extra_headers);
        (endpoint, headers)
    } else {
        let endpoint = crate::pipeline::resolve_endpoint_for_wire(
            wire_api,
            &target,
            &model,
            &provider.base_url,
            auth.claude_code_token.as_deref(),
        )
        .map_err(|e| e.to_string())?;
        let headers = crate::pipeline::resolve_headers(
            &target,
            auth.api_key.as_ref(),
            auth.claude_code_token.as_deref(),
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
        vdd_builder_auth,
        prompt_blocks,
    })
}

fn provider_switch_auth_to_vdd_auth(auth: &ProviderSwitchAuth) -> crate::vdd::VddProviderAuth {
    match (
        auth.codex_responses_auth.as_ref(),
        auth.claude_code_token.as_ref(),
        auth.api_key.as_ref(),
    ) {
        (Some(codex_auth), _, _) => {
            crate::vdd::VddProviderAuth::codex_responses(codex_auth.clone())
        }
        (None, Some(token), _) => crate::vdd::VddProviderAuth::claude_code_token(token.clone()),
        (None, None, Some(api_key)) => crate::vdd::VddProviderAuth::api_key(api_key.clone()),
        (None, None, None) => crate::vdd::VddProviderAuth::None,
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
    pub headers: Vec<(String, String)>,
    /// Wire protocol carried by the endpoint.
    pub wire_api: crate::pipeline::WireApi,
    /// OAuth bearer used by the claude-code-token flow. `None` when the
    /// raw `ANTHROPIC_API_KEY` path is taken.
    pub claude_code_token: Option<String>,
    /// Pre-split system-prompt blocks the Anthropic adapter uses to get
    /// cache hits on the long static tail. `None` when no split has been
    /// computed (non-Anthropic providers).
    pub prompt_blocks: Option<crate::prompt::SystemPromptBlocks>,
}

impl ApiClient {
    /// Construct an [`ApiClient`] with a fresh `reqwest::Client` and the
    /// remaining fields defaulted (empty endpoint / headers, no token, no
    /// prompt-block split). The pipeline-bootstrap path fills these in via
    /// [`App::set_api_config`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: String::new(),
            headers: Vec::new(),
            wire_api: crate::pipeline::WireApi::ChatCompletions,
            claude_code_token: None,
            prompt_blocks: None,
        }
    }
}

impl Default for ApiClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Main TUI application state.
pub struct App {
    pub messages: MessageList,
    pub input: TextInput,
    pub model: String,
    pub provider: String,
    pub mode: Mode,
    pub should_quit: bool,
    pub is_waiting: bool,
    spinner_frame: usize,
    /// Full assistant text as received from streaming deltas. The visible
    /// streaming text may be suppressed while a structured final envelope is
    /// still incomplete.
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
    pub system_prompt: String,
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
    /// Persistent chat session (for save/load/resume)
    pub chat_session: Session,
    /// Coalescing transcript writer subscribed to canonical state changes.
    transcript_subscriber: crate::transcript::TranscriptStateSubscriber,
    /// Optional lifecycle analytics subscriber. Production installs the
    /// tracing sink after startup resume; tests and headless users remain
    /// silent unless they explicitly provide a sink.
    analytics_subscriber: Option<crate::services::analytics::StateAnalyticsSubscriber>,
    /// Active permission prompt (if any). Tool execution blocks until resolved.
    pending_permission: Option<PendingPermission>,
    /// Active `ask_user_question` modal (if any). The pipeline's
    /// post-tool-execution interceptor parks on a oneshot until the
    /// modal completes the question set and sends back the answers
    /// JSON. While `Some`, key dispatch routes to the modal walker.
    pending_user_question: Option<PendingUserQuestion>,
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
        let chat_session = Session::new(model, provider);
        let transcript_subscriber =
            crate::transcript::TranscriptStateSubscriber::new(chat_session.state_store());
        Self {
            messages: MessageList::new(),
            input: TextInput::new(),
            model: model.to_string(),
            provider: provider.to_string(),
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
            system_prompt: String::new(),
            memory_db: None,
            app_config: None,
            permission_mgr: None,
            vdd_engine: None,
            vdd_builder_auth: crate::vdd::VddProviderAuth::None,
            runtime_handle: None,
            chat_session,
            transcript_subscriber,
            analytics_subscriber: None,
            pending_permission: None,
            pending_user_question: None,
            hook_engine: None,
            policy_enforcer,
            task_mgr: std::sync::Arc::new(
                std::sync::Mutex::new(crate::session::TaskManager::new()),
            ),
            overlay: None,
        }
    }

    /// Open the help-cheatsheet overlay. Subsequent keystrokes go to
    /// the overlay until it returns `OverlayAction::Close`.
    pub fn open_help_overlay(&mut self) {
        self.overlay = Some(ActiveOverlay::Help(super::components::HelpOverlay::new()));
    }

    fn apply_loaded_session(&mut self, loaded: &Session) {
        // Flush the old snapshot before replacement. Subscribers stay attached
        // because `apply_loaded` replaces the shared store in place.
        self.transcript_subscriber.flush_now();
        self.chat_session.apply_loaded(loaded);
        self.model.clone_from(&loaded.model);
        self.provider.clone_from(&loaded.provider);
        self.mode = tui_mode_for_agent(loaded.agent_mode());
        self.refresh_app_config_target();
        let _ = self.chat_session.refresh_estimated_tokens();
        let transcript_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
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
    }

    /// Install the lifecycle analytics sink for the active state store.
    pub fn set_analytics_sink(
        &mut self,
        sink: std::sync::Arc<dyn crate::services::analytics::AnalyticsSink>,
    ) {
        self.analytics_subscriber =
            Some(crate::services::analytics::StateAnalyticsSubscriber::new(
                self.chat_session.state_store(),
                sink,
            ));
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
        self.apply_loaded_session(&loaded);
    }

    /// Apply top-level `--resume` / `--session-id` startup options.
    ///
    /// The default full-screen TUI is the primary binary mode, so these
    /// CLI flags must affect it instead of silently applying only to the
    /// legacy line REPL. A specific `--session-id` takes precedence over
    /// `--resume`; otherwise `--resume` loads the most recently updated
    /// saved TUI session.
    pub fn apply_startup_resume(&mut self, resume: bool, session_id: Option<&str>) {
        if let Some(id) = session_id {
            self.resume_session_by_id(id);
            return;
        }

        if !resume {
            return;
        }

        let Some(loaded) = list_sessions().into_iter().next() else {
            self.messages
                .add(DisplayMessage::system("No saved sessions to resume."));
            return;
        };
        self.apply_loaded_session(&loaded);
    }

    /// Apply the current process's permission posture after any startup
    /// resume. This prevents a persisted session from carrying a dangerous
    /// bypass choice into a later invocation that omitted the flag.
    pub fn set_permission_bypass(&self, enabled: bool) {
        self.chat_session.set_permission_bypass(enabled);
    }

    /// Open the log-selector (session picker) overlay seeded with
    /// every transcript for the current project's cwd. No-op when
    /// there are zero saved sessions — the caller should show a
    /// different affordance in that case (current behavior: the
    /// overlay still opens with an empty-state message, matching
    /// Claude Code's `/resume` UX).
    pub fn open_log_selector(&mut self) {
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
    fn fire_stop_hook(&self) {
        if let (Some(engine), Some(handle)) =
            (self.hook_engine.as_ref(), self.runtime_handle.as_ref())
        {
            let engine = engine.clone();
            let session_id = self.chat_session.id();
            handle.spawn(async move {
                let input = crate::hooks::HookInput::new(crate::hooks::HookEvent::Stop)
                    .with_session_id(session_id);
                let _ = engine.run(crate::hooks::HookEvent::Stop, &input).await;
            });
        }
    }

    /// Fire the `Notification` hook with a free-form message. Used for
    /// API errors, rate-limit warnings, etc. Best-effort as above.
    fn fire_notification_hook(&self, message: &str, level: &str) {
        if let (Some(engine), Some(handle)) =
            (self.hook_engine.as_ref(), self.runtime_handle.as_ref())
        {
            let engine = engine.clone();
            let session_id = self.chat_session.id();
            let message = message.to_string();
            let level = level.to_string();
            handle.spawn(async move {
                let payload = serde_json::json!({
                    "message": message,
                    "level": level.clone(),
                    "session_id": session_id,
                });
                let _ = engine.fire_notification(&level, payload).await;
            });
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
    pub fn set_api_config(
        &mut self,
        endpoint: String,
        headers: Vec<(String, String)>,
        wire_api: crate::pipeline::WireApi,
        system_prompt: String,
        prompt_blocks: Option<crate::prompt::SystemPromptBlocks>,
        claude_code_token: Option<String>,
    ) {
        self.api_client.endpoint = endpoint;
        self.api_client.headers = headers;
        self.api_client.wire_api = wire_api;
        self.system_prompt = system_prompt;
        self.api_client.prompt_blocks = prompt_blocks;
        self.api_client.claude_code_token = claude_code_token;
    }

    fn apply_provider_switch(&mut self, switch: ProviderSwitch) {
        let ProviderSwitch {
            provider,
            model,
            endpoint,
            headers,
            wire_api,
            claude_code_token,
            vdd_builder_auth,
            prompt_blocks,
        } = switch;

        self.provider = provider;
        self.model = model;
        self.chat_session.provider.clone_from(&self.provider);
        self.chat_session.model.clone_from(&self.model);
        self.chat_session.touch();
        self.refresh_app_config_target();

        let system_prompt = self.system_prompt.clone();
        self.set_api_config(
            endpoint,
            headers,
            wire_api,
            system_prompt,
            prompt_blocks,
            claude_code_token,
        );
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
    pub async fn run(&mut self) -> io::Result<()> {
        // Capture the tokio runtime handle (must be called inside an async context).
        self.runtime_handle = tokio::runtime::Handle::try_current().ok();

        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Single event handler — MUST NOT create two, or they steal each other's keypresses
        let events = EventHandler::new(Duration::from_millis(100));
        // Store a sender clone so spawn_api_turn can push events into the same channel
        self.api_event_tx = Some(events.sender());

        // Inject system prompt as the first message
        if !self.system_prompt.is_empty() {
            self.chat_session.push_message(serde_json::json!({
                "role": "system",
                "content": self.system_prompt
            }));
        }

        // No welcome message added to the message list — the welcome
        // box is rendered directly in draw() as a ratatui widget.

        loop {
            // crosslink #910: out-of-band shutdown signal. Any process
            // (signal handler, background task, test fixture) can
            // request a clean exit by flipping TUI_SHUTDOWN — the loop
            // checks it before every tick so we exit promptly without
            // a synthetic keypress.
            if TUI_SHUTDOWN.load(std::sync::atomic::Ordering::Relaxed) {
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

        disable_raw_mode()?;
        execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen)?;

        // Save session and any final transcript tail on exit.
        self.chat_session.touch();
        self.persist_session();
        if let Some(analytics) = self.analytics_subscriber.as_mut() {
            analytics.finish();
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
            let session_id = self.chat_session.id();
            let input = crate::hooks::HookInput::new(crate::hooks::HookEvent::SessionEnd)
                .with_session_id(session_id);
            let _ = engine
                .run(crate::hooks::HookEvent::SessionEnd, &input)
                .await;
        }

        Ok(())
    }

    /// Process one async event from the event loop. Returns `false` when the loop should stop.
    #[allow(clippy::too_many_lines)]
    fn handle_app_event(&mut self, event: Result<AppEvent, std::sync::mpsc::RecvError>) -> bool {
        match event {
            Ok(AppEvent::Key(key)) => self.handle_key(key),
            Ok(AppEvent::Paste(text)) => self.handle_paste(&text),
            Ok(AppEvent::Tick) => {
                self.spinner_frame = (self.spinner_frame + 1) % SPINNER_FRAMES.len();
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
            Ok(AppEvent::ResponseDone) => self.handle_response_done(),
            Ok(AppEvent::ApiError(msg)) => {
                self.messages.finish_streaming();
                self.streaming_raw_text.clear();
                self.messages
                    .add(DisplayMessage::error(format!("Error: {msg}")));
                self.is_waiting = false;
                self.fire_notification_hook(&format!("API error: {msg}"), "error");
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
            Ok(AppEvent::SyncMessages(messages)) => {
                self.chat_session.replace_messages(messages);
            }
            Ok(AppEvent::PermissionRequest {
                tool_name,
                tool_args,
                reply,
            }) => {
                self.pending_permission = Some(PendingPermission {
                    tool_name,
                    tool_args,
                    reply,
                });
            }
            Ok(AppEvent::UserQuestion { questions, reply }) => {
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
                self.apply_provider_switch(switch);
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

    /// Finalise the turn when the pipeline emits `ResponseDone`.
    ///
    /// Extracted from `handle_app_event` to keep that dispatcher under
    /// the clippy `too_many_lines` threshold. Responsible for finishing
    /// any in-flight stream/thinking widgets, flushing the persisted
    /// chat session, refreshing the token estimate, and firing the
    /// Stop hook so external orchestrators get the round-trip signal.
    fn handle_response_done(&mut self) {
        self.messages.finish_thinking();
        self.prepare_streaming_final_for_display();
        self.messages.finish_streaming();
        self.streaming_raw_text.clear();
        self.is_waiting = false;
        self.chat_session.update_title();
        self.chat_session.touch();
        let _ = self.chat_session.refresh_estimated_tokens();
        self.persist_session();
        self.fire_stop_hook();
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
        match render_live_final_response_for_display(&self.chat_session.id(), &content) {
            Some(rendered) => self.messages.streaming_text = rendered,
            None => self.messages.streaming_text.clear(),
        }
    }

    fn append_streaming_for_display(&mut self, text: &str) {
        self.streaming_raw_text.push_str(text);
        if may_be_structured_final_stream(&self.streaming_raw_text) {
            if let Ok(Some(summary)) =
                crate::grounded_loop::structured_final_summary(&self.streaming_raw_text)
            {
                self.messages.streaming_text = summary;
            } else {
                self.messages.streaming_text.clear();
            }
            self.messages.is_streaming = true;
            return;
        }
        self.messages.append_streaming(text);
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
                    self.messages.add(DisplayMessage {
                        kind: MessageKind::ToolErr { name: header },
                        content: format!("Failed: {stderr}"),
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
        } else if self.pending_permission.is_some() || self.pending_user_question.is_some() {
            // Permission prompt + ask_user_question modal both win over
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
            KeyMode::Modal => self.handle_key_modal(key),
            KeyMode::Streaming => self.handle_key_streaming(key),
            KeyMode::Normal => self.handle_key_normal(key),
        }
    }

    fn handle_paste(&mut self, text: &str) {
        if self.overlay.is_some()
            || self.is_waiting
            || self.pending_permission.is_some()
            || self.pending_user_question.is_some()
        {
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
        // If permission prompt is active, deny and dismiss without quitting.
        if let Some(perm) = self.pending_permission.take() {
            let _ = perm.reply.send(super::events::PermissionResponse::Deny);
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
            return;
        }
        // If an overlay is open, close it instead of quitting — matches
        // the pre-#364 behaviour where overlay handling ran before the
        // global Ctrl+C check (so the overlay could swallow it).
        if self.overlay.is_some() {
            self.overlay = None;
            return;
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
        if key.code == KeyCode::Esc {
            self.is_waiting = false;
            self.messages.finish_streaming();
            self.streaming_raw_text.clear();
            self.messages
                .add(DisplayMessage::system("[Response interrupted]"));
        }
    }

    /// Normal-mode keystrokes: interactive editing. Permission-prompt
    /// and `ask_user_question` walking are sub-states because the
    /// prompt / modal overlays the input line without taking the App
    /// into modal-overlay state.
    fn handle_key_normal(&mut self, key: crossterm::event::KeyEvent) {
        if self.pending_permission.is_some() {
            self.handle_permission_key(key);
            return;
        }
        if self.pending_user_question.is_some() {
            self.handle_user_question_key(key);
            return;
        }
        self.handle_editing_key(key);
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
                self.is_waiting = false;
                self.messages.finish_streaming();
                self.streaming_raw_text.clear();
                self.messages
                    .add(DisplayMessage::system("[Response interrupted]"));
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
            KeyCode::Char(c) => self.input.insert(c),
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
    fn handle_export_effort_slash(&self, text: &str) -> bool {
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
            self.spawn_fs(SpawnTarget::Files, move || {
                std::fs::write(&export_path, md.as_bytes())
                    .map(|()| format!("Exported to {path_for_render}"))
                    .map_err(|e| format!("Export failed: {e}"))
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

    /// Handle slash commands. Returns true if the command was recognized.
    ///
    /// No-argument branches (`/quit`, `/exit`, `/help`, `?`, `/resume`,
    /// `/continue`, `/clear`, `/status`, `/mode`, `/skill`, `/skills`) are
    /// dispatched via the [`TUI_SLASH_TABLE`] lookup — the same OCP-clean
    /// dispatch pattern the CLI's [`command_registry::registry`] uses
    /// (crosslink #232 / #259). Branches that take arguments (`/load <id>`,
    /// `/rewind N`, `/effort high`, …) stay in the longer-form
    /// `handle_session_slash` / `handle_export_effort_slash` / etc.
    /// helpers below because their dispatch is on a *prefix*, not a
    /// canonical name, and the table is keyed by full canonical name to
    /// keep the lookup O(1).
    ///
    /// REMAINING IF-BRANCHES (documented for the next migration pass):
    ///
    /// * `/load <id>` / `/continue <id>` — prefix dispatch.
    /// * `/rewind` / `/rewind N` — prefix dispatch.
    /// * `/undo`, `/redo` — would fit the table once helpers exist.
    /// * `/sessions`, `/list` — would fit the table once helpers exist.
    /// * `/export`, `/effort` / `/effort <lvl>` — prefix dispatch.
    /// * `/rename <title>` — prefix dispatch.
    /// * `/provider [name]`, `/model`, `/models`, `/cost`, `/files [dir]`,
    ///   `/diff`, `/context`, `/doctor`, `/review`, and `/init` peers in
    ///   `handle_diagnostic_slash` — would fit the table once helpers exist.
    ///
    /// The next person to touch this file should hoist these remaining
    /// branches into the table; each is a 3-line entry once a sibling
    /// helper exists.
    fn handle_slash_command(&mut self, text: &str) -> bool {
        if let Some(handler) = lookup_tui_slash(text) {
            handler(self);
            return true;
        }

        if self.handle_session_slash(text) {
            return true;
        }

        if self.handle_export_effort_slash(text) {
            return true;
        }

        // Skill invocations and info/diagnostic commands starting with /
        if text.starts_with('/') {
            self.handle_info_slash(text);
            return true;
        }

        false
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

    /// Table-handler entry point for `/mode`.
    fn slash_mode(&mut self) {
        self.chat_session.toggle_mode();
        self.mode = tui_mode_for_agent(self.chat_session.agent_mode());
        self.messages.add(DisplayMessage::system(format!(
            "Mode: {} — {}",
            self.chat_session.agent_mode(),
            self.chat_session.mode_description()
        )));
    }

    /// Table-handler entry point for `/skill` / `/skills` (no-arg list form).
    fn slash_skill_list(&mut self) {
        let skills = crate::skills::load_skills();
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
                .map(|s| format!("  /{} — {}", s.name, s.description))
                .collect::<Vec<_>>()
                .join("\n");
            self.messages
                .add(DisplayMessage::system(format!("Available skills:\n{list}")));
        }
    }

    /// Handle skill invocations and info/diagnostic commands.
    fn handle_info_slash(&mut self, text: &str) {
        let skill_name = if text.starts_with("/skill ") {
            text.strip_prefix("/skill ").unwrap_or("").trim()
        } else {
            text.strip_prefix('/').unwrap_or("")
        };
        if let Some(skill) = crate::skills::get_user_invocable_skill(skill_name) {
            self.messages.add(DisplayMessage::system(format!(
                "Running skill: /{}",
                skill.name
            )));
            self.apply_skill_turn_metadata(&skill);
            self.chat_session
                .push_message(serde_json::json!({ "role": "user", "content": skill.prompt }));
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

    fn apply_skill_turn_metadata(&mut self, skill: &crate::skills::SkillDefinition) {
        self.next_turn_allowed_tool_rules =
            crate::permissions::allowed_tool_specs_to_permission_rules(
                skill.allowed_tools.as_deref(),
            );

        if let Some(model) = skill
            .model
            .as_deref()
            .filter(|model| self.can_use_prompt_model(model))
        {
            self.next_turn_model = Some(model.to_string());
        } else if let Some(model) = skill.model.as_deref() {
            tracing::debug!(
                model = %model,
                provider = %self.provider,
                "ignoring skill model hint for a different provider in TUI"
            );
        }

        if let Some(level) = skill.effort.as_deref().and_then(parse_prompt_effort_level) {
            self.next_turn_effort_level = Some(level);
        }
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

        let Some(handle) = self.runtime_handle.clone() else {
            self.messages.add(DisplayMessage::error(
                "No async runtime bound; cannot switch providers.",
            ));
            return true;
        };
        let Some(tx) = self.event_sender() else {
            self.messages.add(DisplayMessage::error(
                "No TUI event channel bound; cannot switch providers.",
            ));
            return true;
        };

        let requested = requested.to_string();
        let prompt_blocks = self.api_client.prompt_blocks.clone();
        self.messages.add(DisplayMessage::system(format!(
            "Switching provider to {requested}..."
        )));
        handle.spawn(async move {
            let event = match resolve_provider_switch(requested, prompt_blocks).await {
                Ok(switch) => AppEvent::ProviderSwitchReady(switch),
                Err(err) => AppEvent::ProviderSwitchError(err),
            };
            let _ = tx.send(event);
        });
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
        let Some(handle) = self.runtime_handle.clone() else {
            self.show_model_list_fallback(Some(
                "No async runtime is bound for dynamic model listing.",
            ));
            return;
        };
        let Some(tx) = self.event_sender() else {
            self.show_model_list_fallback(Some(
                "No TUI event channel is bound for dynamic model listing.",
            ));
            return;
        };

        let provider = self.provider.clone();
        let current_model = self.model.clone();
        let extra_headers: Vec<(String, String)> = provider_config
            .headers
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        self.messages.add(DisplayMessage::system(format!(
            "Fetching models for {provider} from the configured /models endpoint..."
        )));
        handle.spawn(async move {
            let event = match crate::providers::fetch_models_with_headers(
                &provider_config.base_url,
                provider_config.api_key.as_ref(),
                &extra_headers,
                adapter,
            )
            .await
            {
                Ok(models) => {
                    let model_ids: Vec<String> = models.into_iter().map(|model| model.id).collect();
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
            };
            let _ = tx.send(event);
        });
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
            crate::providers::default_model_for_target(&self.provider).to_string()
        } else {
            args.to_string()
        };
        self.model = model;
        self.chat_session.model.clone_from(&self.model);
        self.chat_session.touch();
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
    fn handle_slash_files(&self, text: &str) {
        let dir = text.strip_prefix("/files").unwrap_or("").trim().to_owned();
        let dir = if dir.is_empty() { ".".to_string() } else { dir };
        let dir_for_render = dir.clone();
        self.spawn_fs(SpawnTarget::Files, move || {
            let entries =
                std::fs::read_dir(&dir).map_err(|e| format!("Failed to list {dir}: {e}"))?;
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
    fn handle_slash_diff(&self) {
        // Drop the JoinHandle explicitly: the slash-command call site is
        // fire-and-forget, the receiver lives in the mpsc channel.
        drop(self.spawn_shell(vec!["git", "diff", "--stat"], SpawnTarget::Diff));
    }

    /// Handle the `/doctor` slash command (environment diagnostics).
    fn handle_slash_doctor(&mut self) {
        let checks = [
            match crate::config::load_config() {
                Ok(_) => "✓ Config: loaded".to_string(),
                Err(e) => format!("✗ Config: {e}"),
            },
            format!("✓ Provider: {}", self.provider),
            format!("✓ Model: {}", self.model),
            format!("✓ Endpoint: {}", self.api_client.endpoint),
            format!("✓ Skills: {} loaded", crate::skills::load_skills().len()),
            if self.memory_db.is_some() {
                "✓ Memory DB: connected".to_string()
            } else {
                "✗ Memory DB: not available".to_string()
            },
        ];
        self.messages.add(DisplayMessage::system(format!(
            "Diagnostics:\n{}",
            checks.join("\n")
        )));
    }

    /// Handle the `/review` slash command (shows truncated `git diff HEAD`).
    fn handle_slash_review(&mut self) {
        let content = match git_command().and_then(|mut cmd| {
            cmd.args(["diff", "HEAD"])
                .output()
                .map_err(|e| e.to_string())
        }) {
            Ok(out) => format_review_command_output(&out),
            Err(e) => format!("Failed to run git diff: {e}"),
        };
        self.messages.add(DisplayMessage::system(content));
    }

    /// Handle the `/init` slash command (create config if absent).
    fn handle_slash_init(&mut self) {
        if crate::config::config_file_exists() {
            self.messages.add(DisplayMessage::system(
                "Config already exists. Use /doctor to check it.",
            ));
        } else {
            let content = match current_exe_command()
                .and_then(|mut cmd| cmd.arg("init").output().map_err(|e| e.to_string()))
            {
                Ok(out) => format_init_command_output(&out),
                Err(e) => format!("Init failed: {e}"),
            };
            self.messages.add(DisplayMessage::system(content));
        }
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
    /// Dispatches to the tokio runtime via [`Self::spawn_shell`] (crosslink
    /// #371). The previous implementation blocked the sync event loop on
    /// `std::process::Command::new("bash").output()` for the full lifetime
    /// of the child — long-running commands froze the spinner and queued
    /// keypresses. We now post the result back via
    /// [`AppEvent::ShellDone`] for the receiver in `handle_app_event` to
    /// render with the same `$ <cmd>` header as before.
    fn handle_shell_command(&self, cmd: &str) {
        if cmd.is_empty() {
            return;
        }
        // Drop the JoinHandle explicitly: the shell escape is
        // fire-and-forget, results arrive via AppEvent::ShellDone.
        drop(self.spawn_shell(
            vec!["bash", "-c", cmd],
            SpawnTarget::ShellCommand {
                displayed: cmd.to_string(),
            },
        ));
    }

    /// Send a user message to the API.
    fn send_user_message(&mut self, text: String) {
        let expanded = expand_file_refs(&text);

        self.messages.add(DisplayMessage::user(text));

        self.chat_session.push_message(serde_json::json!({
            "role": "user",
            "content": expanded
        }));

        crate::guardrails::reset_turn();
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
    fn spawn_fs<F>(&self, target: SpawnTarget, op: F)
    where
        F: FnOnce() -> Result<String, String> + Send + 'static,
    {
        let tx = self.api_event_tx.clone();

        let Some(handle) = self.runtime_handle.clone() else {
            if let Some(tx) = tx {
                let _ = tx.send(AppEvent::ShellDone {
                    target,
                    stdout: String::new(),
                    stderr: "no async runtime bound — cannot spawn fs task".to_string(),
                    exit_code: None,
                });
            }
            return;
        };

        // spawn_blocking puts the closure on the tokio blocking-IO pool
        // (default 512 threads) so a slow read_dir() doesn't take down
        // any of the async-runtime worker threads either.
        handle.spawn(async move {
            let join = tokio::task::spawn_blocking(op).await;
            let evt = match join {
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
            };
            if let Some(tx) = tx {
                let _ = tx.send(evt);
            }
        });
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
    fn spawn_shell(
        &self,
        cmd: Vec<&str>,
        target: SpawnTarget,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let tx = self.api_event_tx.clone();
        let session_id = self.chat_session.id();
        let cwd = std::env::current_dir().ok();
        let ledger_target = target.clone();
        // Eagerly own the argv as Strings — the future outlives `&self`.
        let argv: Vec<String> = cmd.into_iter().map(str::to_owned).collect();

        let Some(handle) = self.runtime_handle.clone() else {
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
        };

        Some(handle.spawn(async move {
            let Some((exe, rest)) = argv.split_first() else {
                if let Some(tx) = tx {
                    let _ = tx.send(AppEvent::ShellDone {
                        target,
                        stdout: String::new(),
                        stderr: "spawn_shell called with empty argv".to_string(),
                        exit_code: None,
                    });
                }
                return;
            };

            let result = tokio::process::Command::new(exe).args(rest).output().await;

            if let (SpawnTarget::ShellCommand { displayed }, Some(cwd), Ok(out)) =
                (&ledger_target, cwd.as_deref(), &result)
            {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                crate::grounded_loop::observe_shell_command_for_session(
                    &session_id,
                    cwd,
                    displayed,
                    out.status.code().unwrap_or(-1),
                    &stdout,
                    &stderr,
                );
            }

            let evt = match result {
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
            };

            if let Some(tx) = tx {
                let _ = tx.send(evt);
            }
        }))
    }

    /// Spawn an async API turn on the tokio runtime.
    ///
    /// Sends events through the event handler's mpsc channel so the
    /// synchronous TUI event loop can display streaming output.
    fn spawn_api_turn(&mut self) {
        let Some(ref handle) = self.runtime_handle else {
            // No async runtime — show fallback message
            self.messages.add(DisplayMessage::error(
                "[No async runtime — cannot call API. Run with tokio.]",
            ));
            self.is_waiting = false;
            self.clear_next_turn_metadata();
            return;
        };

        let Some(tx) = self.event_sender() else {
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
        let prompt_blocks = api.prompt_blocks;
        let wire_api = api.wire_api;
        let hook_engine = self.hook_engine.clone();
        let session_id_for_task = self.chat_session.id();
        let memory_db = self.memory_db.clone();
        let app_config = self.app_config.clone();
        let permission_mgr = self.permission_mgr.clone();
        let vdd_engine = self.vdd_engine.clone();
        let vdd_builder_auth = self.vdd_builder_auth.clone();
        let policy_enforcer = std::sync::Arc::clone(&self.policy_enforcer);
        let task_mgr = self.task_mgr.clone();
        // Clone the canonical state snapshot so the async task can build
        // follow-up requests without holding the state lock across awaits.
        let session_messages = self.chat_session.messages_snapshot();

        handle.spawn(run_api_turn_async(ApiTurnParams {
            session_messages,
            client,
            endpoint,
            headers,
            provider,
            model,
            effort_level,
            wire_api,
            claude_code_token,
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
            session_id: session_id_for_task,
            tx,
        }));
    }

    fn clear_next_turn_metadata(&mut self) {
        self.next_turn_effort_level = None;
        self.next_turn_model = None;
        self.next_turn_allowed_tool_rules.clear();
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
        let left_text = "? for shortcuts";
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
        let cwd = std::env::current_dir().map_or_else(
            |_| ".".to_string(),
            |p| {
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

/// Owned call parameters for one spawned API turn.
struct ApiTurnParams {
    session_messages: Vec<serde_json::Value>,
    client: reqwest::Client,
    endpoint: String,
    headers: Vec<(String, String)>,
    provider: String,
    model: String,
    effort_level: EffortLevel,
    wire_api: crate::pipeline::WireApi,
    claude_code_token: Option<String>,
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
    session_id: String,
    tx: std::sync::mpsc::Sender<super::events::AppEvent>,
}

struct InitialTurnRequest<'a> {
    session_id: &'a str,
    session_messages: &'a [serde_json::Value],
    policy_enforcer: &'a std::sync::Arc<crate::services::policy::PolicyEnforcer>,
    model: &'a str,
    wire_api: crate::pipeline::WireApi,
    provider: &'a str,
    effort_level: EffortLevel,
    claude_code_token: Option<&'a str>,
    prompt_blocks: Option<&'a crate::prompt::SystemPromptBlocks>,
    tx: &'a std::sync::mpsc::Sender<super::events::AppEvent>,
}

struct PreparedInitialTurn {
    task_obs: Option<crate::ledger::ObsId>,
    request_body: serde_json::Value,
}

/// Shared context threaded through the agentic follow-up loop.
struct AgenticCtx<'a> {
    client: &'a reqwest::Client,
    endpoint: &'a str,
    headers: &'a [(String, String)],
    provider: &'a str,
    model: &'a str,
    effort_level: &'a str,
    wire_api: crate::pipeline::WireApi,
    claude_code_token: Option<&'a str>,
    prompt_blocks: Option<&'a crate::prompt::SystemPromptBlocks>,
    memory_db: Option<std::sync::Arc<crate::memory::MemoryDb>>,
    app_config: Option<std::sync::Arc<crate::config::AppConfig>>,
    permission_mgr: Option<std::sync::Arc<crate::permissions::PermissionManager>>,
    transient_allowed_tool_rules: &'a [crate::permissions::PermissionRule],
    hook_engine: Option<std::sync::Arc<crate::hooks::HookEngine>>,
    policy_enforcer: std::sync::Arc<crate::services::policy::PolicyEnforcer>,
    task_mgr: std::sync::Arc<std::sync::Mutex<crate::session::TaskManager>>,
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

fn latest_assistant_message_content(messages: &[serde_json::Value]) -> Option<&str> {
    messages.iter().rev().find_map(|message| {
        (message.get("role").and_then(|role| role.as_str()) == Some("assistant"))
            .then(|| message.get("content").and_then(|content| content.as_str()))
            .flatten()
    })
}

fn observe_turn_user_task(
    session_id: &str,
    messages: &[serde_json::Value],
) -> Option<crate::ledger::ObsId> {
    let content = latest_user_message_content(messages)?;
    crate::grounded_loop::observe_session_user_task(session_id, content)
}

fn request_messages_with_grounding(
    session_id: &str,
    task_obs: Option<crate::ledger::ObsId>,
    session_messages: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, String> {
    let mut messages = crate::grounded_loop::request_messages_with_grounding(
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
    session_id: &str,
    content: &str,
) -> Result<String, String> {
    crate::grounded_loop::validate_and_render_agentic_final_response(session_id, content)
}

fn render_final_response_for_history(session_id: &str, content: &str) -> Option<String> {
    if content.trim().is_empty() {
        return Some(String::new());
    }
    match validate_and_render_agentic_final_response(session_id, content.trim()) {
        Ok(rendered) => Some(rendered),
        Err(reason) => {
            tracing::warn!(
                session_id,
                reason,
                "final answer rejected by grounding gate"
            );
            None
        }
    }
}

fn render_live_final_response_for_display(session_id: &str, content: &str) -> Option<String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Some(String::new());
    }
    match crate::grounded_loop::structured_final_summary(trimmed) {
        Ok(Some(summary)) => return Some(summary),
        Ok(None) => {}
        Err(reason) => {
            tracing::warn!(
                session_id,
                reason,
                "structured final answer rejected before display"
            );
            return None;
        }
    }
    render_final_response_for_history(session_id, trimmed)
}

fn may_be_structured_final_stream(content: &str) -> bool {
    let trimmed = content.trim_start();
    if trimmed.starts_with('{') {
        return true;
    }
    if let Some(fenced) = trimmed.strip_prefix("```") {
        let fenced = fenced
            .strip_prefix("json")
            .or_else(|| fenced.strip_prefix("JSON"))
            .unwrap_or(fenced)
            .trim_start();
        return fenced.starts_with('{');
    }
    false
}

fn check_provider_request_policy_for_messages(
    policy_enforcer: &crate::services::policy::PolicyEnforcer,
    model: &str,
    messages: &[serde_json::Value],
    tx: &std::sync::mpsc::Sender<super::events::AppEvent>,
    session_id: &str,
) -> bool {
    let request = match crate::pipeline::build_chat_completion_request(model, messages) {
        Ok(request) => request,
        Err(e) => {
            send_or_warn(
                tx,
                super::events::AppEvent::ApiError(format!("Request build error: {e}")),
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
                super::events::AppEvent::ApiError(format!("Blocked by policy: {err}")),
                session_id,
            );
            false
        }
    }
}

/// Run the pre-turn `UserPromptSubmit` hook. Returns `false` and sends an
/// `ApiError` event if the hook denies the request; injects any system
/// messages from hook outputs and returns `true` on success.
async fn run_preturn_hooks(
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
    let hook_input = crate::hooks::HookInput::new(crate::hooks::HookEvent::UserPromptSubmit)
        .with_prompt(&user_prompt);
    let hook_result = engine
        .run(crate::hooks::HookEvent::UserPromptSubmit, &hook_input)
        .await;
    if !hook_result.allowed {
        let reason = hook_result.errors.first().map_or_else(
            || "Hook blocked the request".to_string(),
            std::string::ToString::to_string,
        );
        let _ = tx.send(super::events::AppEvent::ApiError(format!(
            "Blocked by hook: {reason}"
        )));
        return false;
    }
    for output in &hook_result.outputs {
        if let Some(ref sys_msg) = output.system_message {
            session_messages.push(serde_json::json!({ "role": "system", "content": sys_msg }));
        }
    }
    true
}

/// Send an event to the TUI event channel, capturing partial in-flight state
/// when the channel has been closed (e.g. user pressed Esc or the app is
/// shutting down).
///
/// Crosslink #765: previously every `tx.send(...)` site was `let _ = ...`,
/// which silently dropped both the event and any unflushed work — for
/// `SyncMessages` that meant the entire accumulated `session_messages` vector
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
    let partial_messages: Option<Vec<serde_json::Value>> = match &event {
        super::events::AppEvent::SyncMessages(msgs) => Some(msgs.clone()),
        _ => None,
    };
    if tx.send(event).is_err() {
        tracing::warn!(
            event = %descriptor,
            session_id = %session_id,
            "TUI event channel closed; partial turn state being persisted to recovery file"
        );
        if let Some(msgs) = partial_messages {
            persist_orphan_messages(session_id, &msgs);
        }
    }
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
        super::events::AppEvent::SyncMessages(msgs) => {
            format!("SyncMessages(n={})", msgs.len())
        }
        super::events::AppEvent::ResponseDone => "ResponseDone".to_string(),
        super::events::AppEvent::ApiError(e) => {
            let snippet: String = e.chars().take(80).collect();
            format!("ApiError({snippet:?})")
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
        super::events::AppEvent::FollowUp => "FollowUp".to_string(),
        super::events::AppEvent::PermissionRequest { tool_name, .. } => {
            format!("PermissionRequest({tool_name})")
        }
        super::events::AppEvent::UserQuestion { questions, .. } => {
            format!("UserQuestion(n={})", questions.len())
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

/// Best-effort persist orphaned session messages to a recovery file so the
/// next run can recover the in-flight turn instead of silently losing it.
/// Failures here are logged but not propagated — we are already on the
/// shutdown path.
fn persist_orphan_messages(session_id: &str, msgs: &[serde_json::Value]) {
    let Some(data_dir) = dirs::data_dir() else {
        tracing::warn!("no data_dir available; cannot persist orphan session state");
        return;
    };
    let dir = data_dir.join("openclaudia").join("orphan-turns");
    if let Err(e) = std::fs::create_dir_all(&dir) {
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
    let path = dir.join(format!("{safe_id}-{ts}.json"));
    match serde_json::to_string_pretty(msgs) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&path, json) {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "failed to write orphan session state"
                );
            } else {
                tracing::warn!(
                    path = %path.display(),
                    n_messages = msgs.len(),
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

/// Drive the agentic follow-up loop until the model stops requesting tools
/// or `MAX_ITER` iterations are exhausted.
#[allow(clippy::too_many_lines)]
async fn run_agentic_loop(ctx: &AgenticCtx<'_>, session_messages: &mut Vec<serde_json::Value>) {
    const MAX_ITER: u32 = 25;
    let mut iteration = 0u32;
    loop {
        iteration += 1;
        tracing::debug!(iteration, "Agentic loop iteration");
        if iteration > MAX_ITER {
            send_or_warn(
                ctx.tx,
                super::events::AppEvent::ApiError(
                    "Reached maximum tool iterations (25)".to_string(),
                ),
                ctx.session_id,
            );
            break;
        }
        let request_messages = match request_messages_with_grounding(
            ctx.session_id,
            ctx.task_obs,
            session_messages,
        ) {
            Ok(messages) => messages,
            Err(e) => {
                tracing::error!(error = %e, "Failed to build grounded agentic follow-up request");
                send_or_warn(ctx.tx, super::events::AppEvent::ApiError(e), ctx.session_id);
                break;
            }
        };
        if !check_provider_request_policy_for_messages(
            &ctx.policy_enforcer,
            ctx.model,
            &request_messages,
            ctx.tx,
            ctx.session_id,
        ) {
            break;
        }
        let body = match crate::pipeline::build_request_for_wire(
            ctx.wire_api,
            ctx.provider,
            ctx.model,
            &request_messages,
            ctx.effort_level,
            ctx.claude_code_token,
            ctx.prompt_blocks,
        ) {
            Ok(body) => body,
            Err(e) => {
                tracing::error!(error = %e, "Failed to build agentic follow-up request");
                send_or_warn(ctx.tx, super::events::AppEvent::ApiError(e), ctx.session_id);
                break;
            }
        };
        match crate::pipeline::run_turn(crate::pipeline::RunTurnParams {
            client: ctx.client,
            endpoint: ctx.endpoint,
            headers: ctx.headers,
            request_body: &body,
            provider: ctx.provider,
            memory_db: ctx.memory_db.clone(),
            app_config: ctx.app_config.clone(),
            permission_mgr: ctx.permission_mgr.clone(),
            transient_allowed_tool_rules: ctx.transient_allowed_tool_rules,
            hook_engine: ctx.hook_engine.clone(),
            policy_enforcer: Some(std::sync::Arc::clone(&ctx.policy_enforcer)),
            task_mgr: ctx.task_mgr.clone(),
            session_id: Some(ctx.session_id.to_string()),
            tx: ctx.tx.clone(),
        })
        .await
        {
            Ok(followup) => {
                tracing::debug!(
                    content_len = followup.content.len(),
                    tool_calls = followup.tool_calls.len(),
                    needs_followup = followup.needs_followup,
                    "Follow-up result"
                );
                if followup.needs_followup {
                    let asst = crate::pipeline::build_assistant_message_with_tools(
                        &followup.content,
                        followup.reasoning_content.as_deref(),
                        &followup.tool_calls,
                        ctx.provider,
                    );
                    session_messages.push(asst);
                    session_messages.extend(followup.tool_results.iter().cloned());
                } else {
                    let reasoning = followup
                        .reasoning_content
                        .as_deref()
                        .filter(|text| !text.is_empty());
                    if !followup.content.is_empty() || reasoning.is_some() {
                        let Some(rendered_content) =
                            render_final_response_for_history(ctx.session_id, &followup.content)
                        else {
                            break;
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
                    }
                    break;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Agentic follow-up failed");
                send_or_warn(ctx.tx, super::events::AppEvent::ApiError(e), ctx.session_id);
                // The caller's `SyncMessages` send after the loop will trigger
                // recovery persistence if the channel is closed — no extra
                // action needed here for partial-state capture.
                break;
            }
        }
    }
}

fn build_initial_turn_request(p: &InitialTurnRequest<'_>) -> Option<PreparedInitialTurn> {
    let task_obs = observe_turn_user_task(p.session_id, p.session_messages);
    let request_messages =
        match request_messages_with_grounding(p.session_id, task_obs, p.session_messages) {
            Ok(messages) => messages,
            Err(e) => {
                send_or_warn(p.tx, super::events::AppEvent::ApiError(e), p.session_id);
                return None;
            }
        };
    if !check_provider_request_policy_for_messages(
        p.policy_enforcer,
        p.model,
        &request_messages,
        p.tx,
        p.session_id,
    ) {
        return None;
    }
    match crate::pipeline::build_request_for_wire(
        p.wire_api,
        p.provider,
        p.model,
        &request_messages,
        p.effort_level.as_str(),
        p.claude_code_token,
        p.prompt_blocks,
    ) {
        Ok(request_body) => Some(PreparedInitialTurn {
            task_obs,
            request_body,
        }),
        Err(e) => {
            send_or_warn(p.tx, super::events::AppEvent::ApiError(e), p.session_id);
            None
        }
    }
}

/// Run a complete API turn: pre-turn hooks, first `run_turn`, and an agentic
/// follow-up loop when tool calls are present.
async fn run_api_turn_async(p: ApiTurnParams) {
    let ApiTurnParams {
        mut session_messages,
        client,
        endpoint,
        headers,
        provider,
        model,
        effort_level,
        wire_api,
        claude_code_token,
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
        session_id,
        tx,
    } = p;
    if let Some(ref engine) = hook_engine {
        if !run_preturn_hooks(engine, &mut session_messages, &tx).await {
            return;
        }
    }
    let initial_request = InitialTurnRequest {
        session_id: &session_id,
        session_messages: &session_messages,
        policy_enforcer: &policy_enforcer,
        model: &model,
        wire_api,
        provider: &provider,
        effort_level,
        claude_code_token: claude_code_token.as_deref(),
        prompt_blocks: prompt_blocks.as_ref(),
        tx: &tx,
    };
    let Some(initial_turn) = build_initial_turn_request(&initial_request) else {
        return;
    };
    match crate::pipeline::run_turn(crate::pipeline::RunTurnParams {
        client: &client,
        endpoint: &endpoint,
        headers: &headers,
        request_body: &initial_turn.request_body,
        provider: &provider,
        memory_db: memory_db.clone(),
        app_config: app_config.clone(),
        permission_mgr: permission_mgr.clone(),
        transient_allowed_tool_rules: &transient_allowed_tool_rules,
        hook_engine: hook_engine.clone(),
        policy_enforcer: Some(std::sync::Arc::clone(&policy_enforcer)),
        task_mgr: task_mgr.clone(),
        session_id: Some(session_id.clone()),
        tx: tx.clone(),
    })
    .await
    {
        Ok(turn_result) => {
            handle_turn_result(
                turn_result,
                session_messages,
                TurnContext {
                    client: &client,
                    endpoint: &endpoint,
                    headers: &headers,
                    provider: &provider,
                    model: &model,
                    effort_level,
                    wire_api,
                    claude_code_token: claude_code_token.as_deref(),
                    prompt_blocks: prompt_blocks.as_ref(),
                    memory_db,
                    app_config,
                    permission_mgr,
                    vdd_engine,
                    vdd_builder_auth: &vdd_builder_auth,
                    transient_allowed_tool_rules: &transient_allowed_tool_rules,
                    hook_engine,
                    policy_enforcer,
                    task_mgr,
                    session_id: &session_id,
                    task_obs: initial_turn.task_obs,
                    tx: &tx,
                },
            )
            .await;
        }
        Err(e) => {
            send_or_warn(&tx, super::events::AppEvent::ApiError(e), &session_id);
        }
    }
}

/// Borrowed context bundle for [`handle_turn_result`] — purely a plumbing
/// struct to keep `run_api_turn_async` under the line-count lint while
/// preserving the per-iteration data each branch needs.
struct TurnContext<'a> {
    client: &'a reqwest::Client,
    endpoint: &'a str,
    headers: &'a [(String, String)],
    provider: &'a str,
    model: &'a str,
    effort_level: EffortLevel,
    wire_api: crate::pipeline::WireApi,
    claude_code_token: Option<&'a str>,
    prompt_blocks: Option<&'a crate::prompt::SystemPromptBlocks>,
    memory_db: Option<std::sync::Arc<crate::memory::MemoryDb>>,
    app_config: Option<std::sync::Arc<crate::config::AppConfig>>,
    permission_mgr: Option<std::sync::Arc<crate::permissions::PermissionManager>>,
    vdd_engine: Option<std::sync::Arc<crate::vdd::VddEngine>>,
    vdd_builder_auth: &'a crate::vdd::VddProviderAuth,
    transient_allowed_tool_rules: &'a [crate::permissions::PermissionRule],
    hook_engine: Option<std::sync::Arc<crate::hooks::HookEngine>>,
    policy_enforcer: std::sync::Arc<crate::services::policy::PolicyEnforcer>,
    task_mgr: std::sync::Arc<std::sync::Mutex<crate::session::TaskManager>>,
    session_id: &'a str,
    task_obs: Option<crate::ledger::ObsId>,
    tx: &'a std::sync::mpsc::Sender<super::events::AppEvent>,
}

/// Handle the successful `Ok(turn_result)` branch of the first `run_turn`:
/// either drive the agentic follow-up loop (when tool calls are present) or
/// push the plain assistant content. Channel-closed errors on the resulting
/// `SyncMessages` / `ResponseDone` sends go through [`send_or_warn`] so
/// partial in-flight state is persisted instead of silently dropped.
async fn handle_turn_result(
    turn_result: crate::pipeline::TurnResult,
    mut session_messages: Vec<serde_json::Value>,
    ctx: TurnContext<'_>,
) {
    tracing::debug!(
        content_len = turn_result.content.len(),
        tool_calls = turn_result.tool_calls.len(),
        needs_followup = turn_result.needs_followup,
        "Turn result"
    );
    if turn_result.needs_followup {
        let asst = crate::pipeline::build_assistant_message_with_tools(
            &turn_result.content,
            turn_result.reasoning_content.as_deref(),
            &turn_result.tool_calls,
            ctx.provider,
        );
        session_messages.push(asst);
        session_messages.extend(turn_result.tool_results.iter().cloned());
        tracing::info!(
            tool_count = turn_result.tool_calls.len(),
            result_count = turn_result.tool_results.len(),
            "Starting agentic follow-up loop"
        );
        let agentic = AgenticCtx {
            client: ctx.client,
            endpoint: ctx.endpoint,
            headers: ctx.headers,
            provider: ctx.provider,
            model: ctx.model,
            effort_level: ctx.effort_level.as_str(),
            wire_api: ctx.wire_api,
            claude_code_token: ctx.claude_code_token,
            prompt_blocks: ctx.prompt_blocks,
            memory_db: ctx.memory_db.clone(),
            app_config: ctx.app_config.clone(),
            permission_mgr: ctx.permission_mgr.clone(),
            transient_allowed_tool_rules: ctx.transient_allowed_tool_rules,
            hook_engine: ctx.hook_engine.clone(),
            policy_enforcer: std::sync::Arc::clone(&ctx.policy_enforcer),
            task_mgr: ctx.task_mgr.clone(),
            session_id: ctx.session_id,
            task_obs: ctx.task_obs,
            tx: ctx.tx,
        };
        run_agentic_loop(&agentic, &mut session_messages).await;
        if let Some(content) =
            latest_assistant_message_content(&session_messages).map(str::to_string)
        {
            run_tui_vdd_review(&ctx, &content, &mut session_messages).await;
        }
        send_or_warn(
            ctx.tx,
            super::events::AppEvent::SyncMessages(session_messages),
            ctx.session_id,
        );
        send_or_warn(
            ctx.tx,
            super::events::AppEvent::ResponseDone,
            ctx.session_id,
        );
    } else if !turn_result.content.is_empty() {
        let Some(rendered_content) =
            render_final_response_for_history(ctx.session_id, &turn_result.content)
        else {
            send_or_warn(
                ctx.tx,
                super::events::AppEvent::ResponseDone,
                ctx.session_id,
            );
            return;
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
        run_tui_vdd_review(&ctx, &rendered_content, &mut session_messages).await;
        send_or_warn(
            ctx.tx,
            super::events::AppEvent::SyncMessages(session_messages),
            ctx.session_id,
        );
    }
}

async fn run_tui_vdd_review(
    ctx: &TurnContext<'_>,
    content: &str,
    session_messages: &mut Vec<serde_json::Value>,
) {
    let Some(engine) = ctx.vdd_engine.as_ref() else {
        return;
    };
    if content.len() < 100 {
        return;
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
    let builder = crate::vdd::BuilderProvider::with_auth(ctx.provider, ctx.vdd_builder_auth);
    match engine.review_text(content, &user_task, builder).await {
        Ok(result) => {
            let genuine_count = result
                .findings
                .iter()
                .filter(|finding| finding.status == crate::vdd::FindingStatus::Genuine)
                .count();
            let summary = if result.findings.is_empty() {
                "VDD review complete: no issues found.".to_string()
            } else {
                format!(
                    "VDD review complete: {} finding(s), {genuine_count} genuine.",
                    result.findings.len()
                )
            };
            send_or_warn(
                ctx.tx,
                super::events::AppEvent::ToolDone {
                    name: "vdd".to_string(),
                    success: true,
                    content: summary,
                },
                ctx.session_id,
            );
            if !result.context_injection.is_empty() {
                session_messages.push(serde_json::json!({
                    "role": "system",
                    "content": format!("<vdd-review>\n{}\n</vdd-review>", result.context_injection),
                }));
            }
        }
        Err(error) => {
            send_or_warn(
                ctx.tx,
                super::events::AppEvent::ToolDone {
                    name: "vdd".to_string(),
                    success: false,
                    content: format!("VDD review failed: {error}"),
                },
                ctx.session_id,
            );
        }
    }
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
    use super::{compile_file_ref_regex, expand_file_refs};
    use super::{
        current_exe_command, format_api_retry_delay, format_api_retry_message,
        format_init_command_output, format_review_command_output, format_stream_timeout_message,
        git_bin, handle_turn_result, list_sessions, lookup_tui_slash, read_tui_session_file,
        resolve_provider_switch_auth, save_session, ApiClient, App, AppEvent, EffortLevel,
        MessageKind, ProviderSwitch, SpawnTarget, TurnContext, TEST_SESSIONS_DIR, TUI_SLASH_TABLE,
    };
    use crate::slash_commands::all_tui_commands;
    use crate::state::Session;
    use crate::tui::events::ApiRetryKind;
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, Instant};

    #[test]
    fn tui_git_helpers_use_resolved_binary_path() {
        let git = git_bin().expect("tui tests require git on PATH");
        assert!(
            git.is_absolute(),
            "git_bin must resolve git to an absolute path, got {}",
            git.display()
        );

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
    fn tui_init_uses_current_executable_path() {
        let cmd = current_exe_command().expect("current executable must resolve in tests");
        assert!(
            std::path::Path::new(cmd.get_program()).is_absolute(),
            "current executable command must use an absolute path, got {:?}",
            cmd.get_program()
        );

        let src = include_str!("app.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"openclaudia\")")
                    && !code.contains("std::process::Command::new(\"openclaudia\")"),
                "production TUI app code must not invoke bare openclaudia; line {n}: {raw_line}",
                n = idx + 1,
            );
        }
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
    fn tui_init_output_uses_stderr_on_success() {
        let output = output_with_status(
            0,
            "",
            "Initialized OpenClaudia configuration in .openclaudia/\nSet your API key",
        );

        let rendered = format_init_command_output(&output);

        assert!(rendered.contains("Initialized OpenClaudia configuration"));
        assert!(rendered.contains("Set your API key"));
    }

    #[cfg(unix)]
    #[test]
    fn tui_init_output_reports_nonzero_status() {
        let output = output_with_status(
            1,
            "",
            "Configuration already exists. Use --force to overwrite.",
        );

        let rendered = format_init_command_output(&output);

        assert!(rendered.starts_with("Init failed:"));
        assert!(rendered.contains("Configuration already exists"));
    }

    #[cfg(unix)]
    #[test]
    fn tui_init_output_never_renders_blank_on_silent_success() {
        let output = output_with_status(0, "", "");

        let rendered = format_init_command_output(&output);

        assert_eq!(
            rendered,
            "Initialized OpenClaudia configuration in .openclaudia/"
        );
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

    fn tui_runtime_command_roots() -> Vec<&'static str> {
        let mut roots = TUI_SLASH_TABLE
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>();
        roots.extend([
            "/sessions",
            "/list",
            "/load",
            "/continue",
            "/rewind",
            "/undo",
            "/redo",
            "/export",
            "/effort",
            "/rename",
            "/provider",
            "/model",
            "/models",
            "/cost",
            "/files",
            "/diff",
            "/context",
            "/doctor",
            "/review",
            "/init",
            "/skill",
            "/skills",
            "/<skill-name>",
        ]);
        roots.sort_unstable();
        roots.dedup();
        roots
    }

    #[test]
    fn advertised_tui_slash_commands_have_runtime_roots() {
        let runtime_roots = tui_runtime_command_roots();
        for command in all_tui_commands() {
            for root in advertised_tui_invocation_roots(command.invocation) {
                assert!(
                    runtime_roots.contains(&root.as_str()),
                    "TUI help advertises `{}` but the default TUI runtime has no handler root for `{root}`",
                    command.invocation
                );
            }
        }

        for (exact, _) in TUI_SLASH_TABLE {
            assert!(
                lookup_tui_slash(exact).is_some(),
                "exact TUI slash root {exact} must resolve through lookup_tui_slash"
            );
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

    /// `ApiClient::new` initialises with empty transport state — no
    /// endpoint, no headers, no token, no prompt blocks. The `reqwest::Client`
    /// is a real fresh client.
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
        let mut app = App::new("claude-opus-4-7", "anthropic");

        assert!(app.handle_slash_model("/model list"));

        let content = last_display_content(&app);
        assert!(content.contains("Available models for anthropic"));
        assert!(content.contains("claude-opus-4-7 <- current"));
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
            crate::providers::default_model_for_target("anthropic")
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

    fn skill_fixture(
        allowed_tools: Option<Vec<String>>,
        model: Option<&str>,
        effort: Option<&str>,
    ) -> crate::skills::SkillDefinition {
        crate::skills::SkillDefinition {
            name: "test-skill".to_string(),
            description: "test skill".to_string(),
            allowed_tools,
            when_to_use: None,
            argument_hint: None,
            model: model.map(str::to_string),
            effort: effort.map(str::to_string),
            paths: None,
            hooks: None,
            user_invocable: true,
            prompt: "Do the skill work.".to_string(),
            path: std::path::PathBuf::new(),
        }
    }

    #[test]
    fn tui_skill_metadata_sets_next_turn_hints() {
        let mut app = App::new("claude-sonnet-4-6", "anthropic");
        let skill = skill_fixture(
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
        let skill = skill_fixture(None, Some("gpt-5.5"), Some("future-effort"));

        app.apply_skill_turn_metadata(&skill);

        assert!(app.next_turn_model.is_none());
        assert!(app.next_turn_effort_level.is_none());
    }

    #[test]
    fn tui_effort_slash_updates_status_without_chat_message() {
        let app = App::new("claude-sonnet-4-6", "anthropic");

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
            headers: std::collections::HashMap::new(),
            thinking: crate::config::ThinkingConfig::default(),
        }
    }

    fn reset_project_ledger(session_id: &str) -> PathBuf {
        let path = crate::ledger::project_session_ledger_path(session_id)
            .expect("test session id must be ledger-safe");
        let _ = std::fs::remove_file(&path);
        path
    }

    fn seed_valid_final_ledger(session_id: &str) -> String {
        let mut ledger = crate::ledger::RealityLedger::open_project_session(session_id)
            .expect("open test ledger");
        let task = ledger
            .observe_user_task("Audit direct TUI final.")
            .expect("task");
        let command = ledger
            .observe_command_run(
                "/repo",
                vec!["cargo".to_string(), "check".to_string()],
                0,
                "ok",
                "",
            )
            .expect("command");
        let verification = ledger
            .append(
                crate::ledger::Authority::Verifier,
                crate::ledger::ObservationKind::Verification {
                    passed: true,
                    command: Some("cargo check".to_string()),
                    findings: Vec::new(),
                },
            )
            .expect("verification");
        format!("Verified direct TUI final using [{task}] [{command}] [{verification}].")
    }

    fn direct_turn_result(content: String) -> crate::pipeline::TurnResult {
        crate::pipeline::TurnResult {
            content,
            reasoning_content: None,
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            usage: crate::session::TokenUsage::default(),
            needs_followup: false,
            finish_reason: None,
        }
    }

    #[test]
    fn live_structured_final_display_renders_summary_only() {
        let content = serde_json::json!({
            "kind": "final",
            "summary": "Hello - I'm Claudia. What would you like to work on?",
            "evidence": ["a20e1686-5990-4f06-a09d-226c5e6778ac"],
            "verification": []
        })
        .to_string();

        let rendered = super::render_live_final_response_for_display(
            "tui-live-structured-final-summary",
            &content,
        )
        .expect("structured final summary should render");

        assert_eq!(
            rendered,
            "Hello - I'm Claudia. What would you like to work on?"
        );
        assert!(!rendered.contains("\"evidence\""));
        assert!(!rendered.contains("\"verification\""));
    }

    #[test]
    fn response_done_sanitizes_streamed_structured_final() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = SessionDirGuard::set(tmp.path().join("chat_sessions"));
        let mut app = App::new("gpt-5.5", "openai");
        app.is_waiting = true;
        app.messages.append_streaming(
            &serde_json::json!({
                "kind": "final",
                "summary": "Hello - I'm Claudia.",
                "evidence": ["a20e1686-5990-4f06-a09d-226c5e6778ac"],
                "verification": []
            })
            .to_string(),
        );

        app.handle_response_done();

        let last = app.messages.messages.last().expect("assistant message");
        assert_eq!(last.kind, MessageKind::Assistant);
        assert_eq!(last.content, "Hello - I'm Claudia.");
        assert!(!last.content.contains("\"kind\""));
    }

    #[test]
    fn streamed_structured_final_never_displays_raw_json() {
        let mut app = App::new("gpt-5.5", "openai");
        app.append_streaming_for_display("{\"kind\"");

        assert!(app.messages.is_streaming);
        assert!(app.messages.streaming_text.is_empty());
        assert!(app.streaming_raw_text.contains("\"kind\""));

        app.append_streaming_for_display(
            ":\"final\",\"summary\":\"Hello - I'm Claudia.\",\"evidence\":[\"a20e1686-5990-4f06-a09d-226c5e6778ac\"],\"verification\":[]}",
        );

        assert_eq!(app.messages.streaming_text, "Hello - I'm Claudia.");
        assert!(!app.messages.streaming_text.contains("\"evidence\""));
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
    async fn tui_direct_plain_final_syncs_without_grounding_citations() {
        let session_id = "tui-direct-final-plain-text";
        let ledger_path = reset_project_ledger(session_id);
        let (tx, rx) = mpsc::channel();
        let client = reqwest::Client::new();
        let headers: Vec<(String, String)> = Vec::new();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));
        let policy_enforcer = Arc::new(crate::services::policy::PolicyEnforcer::new(
            crate::services::policy::EnterprisePolicy::default(),
        ));

        handle_turn_result(
            direct_turn_result("Verified with cargo check.".to_string()),
            vec![serde_json::json!({"role":"user","content":"verify this"})],
            TurnContext {
                client: &client,
                endpoint: "https://example.invalid",
                headers: &headers,
                provider: "openai",
                model: "gpt-test",
                effort_level: EffortLevel::Medium,
                wire_api: crate::pipeline::WireApi::ChatCompletions,
                claude_code_token: None,
                prompt_blocks: None,
                memory_db: None,
                app_config: None,
                permission_mgr: None,
                vdd_engine: None,
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
                AppEvent::SyncMessages(messages) => synced_messages = Some(messages),
                _ => {}
            }
        }
        let _ = std::fs::remove_file(ledger_path);

        assert!(!saw_error, "plain direct final must not be rejected");
        let messages = synced_messages.expect("plain direct final should sync messages");
        assert_eq!(
            messages.last().and_then(|msg| msg.get("content")),
            Some(&serde_json::json!("Verified with cargo check."))
        );
    }

    #[tokio::test]
    async fn tui_direct_final_accepts_cited_evidence_and_verification() {
        let session_id = "tui-direct-final-accepted";
        let ledger_path = reset_project_ledger(session_id);
        let content = seed_valid_final_ledger(session_id);
        let (tx, rx) = mpsc::channel();
        let client = reqwest::Client::new();
        let headers: Vec<(String, String)> = Vec::new();
        let task_mgr = Arc::new(Mutex::new(crate::session::TaskManager::new()));
        let policy_enforcer = Arc::new(crate::services::policy::PolicyEnforcer::new(
            crate::services::policy::EnterprisePolicy::default(),
        ));

        handle_turn_result(
            direct_turn_result(content.clone()),
            vec![serde_json::json!({"role":"user","content":"verify this"})],
            TurnContext {
                client: &client,
                endpoint: "https://example.invalid",
                headers: &headers,
                provider: "openai",
                model: "gpt-test",
                effort_level: EffortLevel::Medium,
                wire_api: crate::pipeline::WireApi::ChatCompletions,
                claude_code_token: None,
                prompt_blocks: None,
                memory_db: None,
                app_config: None,
                permission_mgr: None,
                vdd_engine: None,
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
                AppEvent::SyncMessages(messages) => synced_messages = Some(messages),
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
            Some(&serde_json::json!(content))
        );
    }

    #[tokio::test]
    async fn provider_switch_auth_allows_keyless_local_provider() {
        let provider = provider_config_without_key("http://localhost:1234/v1");

        let auth = resolve_provider_switch_auth("local", &provider)
            .await
            .expect("local provider should not require an API key");

        assert!(auth.api_key.is_none());
        assert!(auth.claude_code_token.is_none());
        assert!(auth.codex_responses_auth.is_none());
    }

    #[tokio::test]
    async fn provider_switch_auth_rejects_keyless_remote_provider() {
        let provider = provider_config_without_key("https://api.deepseek.com");

        let err = resolve_provider_switch_auth("deepseek", &provider)
            .await
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
        app.set_api_config(
            "https://example.com/v1".to_string(),
            vec![("x-api-key".to_string(), "secret".to_string())],
            crate::pipeline::WireApi::OpenAiResponses,
            "system prompt".to_string(),
            None,
            Some("oauth-token".to_string()),
        );
        assert_eq!(app.api_client.endpoint, "https://example.com/v1");
        assert_eq!(
            app.api_client.headers,
            vec![("x-api-key".to_string(), "secret".to_string())]
        );
        assert_eq!(app.system_prompt, "system prompt");
        assert_eq!(
            app.api_client.claude_code_token.as_deref(),
            Some("oauth-token")
        );
        assert_eq!(
            app.api_client.wire_api,
            crate::pipeline::WireApi::OpenAiResponses
        );
    }

    #[test]
    fn apply_provider_switch_updates_metadata_and_transport() {
        let mut app = App::new("old-model", "anthropic");
        let original_session_id = app.chat_session.id();
        let blocks = crate::prompt::SystemPromptBlocks {
            stable_prefix: "stable".to_string(),
            dynamic_suffix: "dynamic".to_string(),
        };
        app.set_api_config(
            "https://old.example/v1/messages".to_string(),
            vec![("x-api-key".to_string(), "old-key".to_string())],
            crate::pipeline::WireApi::ChatCompletions,
            "system prompt".to_string(),
            Some(blocks.clone()),
            Some("oauth-token".to_string()),
        );

        app.apply_provider_switch(ProviderSwitch {
            provider: "kimi".to_string(),
            model: "kimi-k2.7-code".to_string(),
            endpoint: "https://api.moonshot.ai/v1/chat/completions".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer kimi-key".to_string())],
            wire_api: crate::pipeline::WireApi::ChatCompletions,
            claude_code_token: None,
            vdd_builder_auth: crate::vdd::VddProviderAuth::None,
            prompt_blocks: Some(blocks.clone()),
        });

        assert_eq!(app.provider, "kimi");
        assert_eq!(app.model, "kimi-k2.7-code");
        assert_eq!(app.chat_session.id(), original_session_id);
        assert_eq!(app.chat_session.provider, "kimi");
        assert_eq!(app.chat_session.model, "kimi-k2.7-code");
        assert_eq!(
            app.api_client.endpoint,
            "https://api.moonshot.ai/v1/chat/completions"
        );
        assert_eq!(
            app.api_client.headers,
            vec![("Authorization".to_string(), "Bearer kimi-key".to_string())]
        );
        assert!(app.api_client.claude_code_token.is_none());
        assert_eq!(app.vdd_builder_auth, crate::vdd::VddProviderAuth::None);
        assert_eq!(
            app.api_client.wire_api,
            crate::pipeline::WireApi::ChatCompletions
        );
        assert_eq!(
            app.api_client
                .prompt_blocks
                .as_ref()
                .map(crate::prompt::SystemPromptBlocks::to_combined),
            Some(blocks.to_combined())
        );
        assert!(
            app.messages
                .messages
                .iter()
                .any(|msg| msg.content.contains("Provider switched to kimi")),
            "switch should emit a visible status message"
        );
    }

    // ── handle_key mode split (crosslink #364) ─────────────────────────

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
    async fn spawn_shell_failure_delivers_nonzero_exit() {
        // `bash -c 'exit 7'` exits with code 7. ShellDone must surface
        // exit_code = Some(7) so the renderer picks the ToolErr branch.
        let mut app = App::new("test-model", "test-provider");
        let rx = wire_app(&mut app);

        let join = app
            .spawn_shell(
                vec!["bash", "-c", "exit 7"],
                SpawnTarget::ShellCommand {
                    displayed: "exit 7".to_string(),
                },
            )
            .expect("runtime-backed spawn_shell should return a task handle");
        join.await.expect("spawn_shell task panicked");

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
    async fn spawn_shell_command_records_ledger_observation() {
        let mut app = App::new("test-model", "test-provider");
        let rx = wire_app(&mut app);
        let ledger = Arc::new(Mutex::new(crate::ledger::RealityLedger::new()));
        let _guard =
            crate::ledger::install_active_ledger_for_session(app.chat_session.id(), ledger.clone());

        let join = app
            .spawn_shell(
                vec!["bash", "-c", "printf tui-ledger"],
                SpawnTarget::ShellCommand {
                    displayed: "printf tui-ledger".to_string(),
                },
            )
            .expect("runtime-backed spawn_shell should return a task handle");
        join.await.expect("spawn_shell task panicked");

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
        assert_eq!(observations.len(), 1);
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
        assert_eq!(expand_file_refs(input), input);
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
    fn invalid_file_ref_regex_is_skipped() {
        assert!(compile_file_ref_regex("[").is_none());
    }

    #[test]
    fn expand_file_refs_double_at_does_not_panic() {
        // Regression guard for the old `.unwrap()` on cap.get(0): a bare '@@'
        // or '@ @' must not panic regardless of whether the regex matches.
        let _ = expand_file_refs("@@");
        let _ = expand_file_refs("@ @");
        let _ = expand_file_refs("email@example.com and @another");
    }

    #[test]
    fn expand_file_refs_unclosed_quote_does_not_panic() {
        // A `@"` with no closing quote must not panic — the regex simply won't
        // match group 1, and the `if let Some` guard skips it cleanly.
        let _ = expand_file_refs(r#"@"unclosed"#);
        let _ = expand_file_refs(r#"some text @"no end here and more text"#);
    }

    #[test]
    fn expand_file_refs_many_at_signs_does_not_panic() {
        // Stress: 1 000 '@' characters in a row must not panic or overflow.
        let input = "@".repeat(1_000);
        let _ = expand_file_refs(&input);
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
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = SessionDirGuard::set(tmp.path().join("chat_sessions"));

        let mut older = Session::new("old-model", "old-provider");
        older.set_id("older-session".to_string());
        older.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        older.push_message(serde_json::json!({"role": "user", "content": "older"}));

        let mut newer = Session::new("new-model", "new-provider");
        newer.set_id("newer-session".to_string());
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

        assert_eq!(app.chat_session.id(), "newer-session");
        assert_eq!(app.model, "new-model");
        assert_eq!(app.provider, "new-provider");
        assert_eq!(app.chat_session.messages_snapshot()[0]["content"], "newer");
        assert!(matches!(
            state_events.try_recv(),
            Some(crate::state::StateEvent::SessionSwitched {
                from,
                to,
                from_messages: 0,
            }) if from.as_str() == initial_id && to.as_str() == "newer-session"
        ));
    }

    #[test]
    fn startup_session_id_takes_precedence_over_resume() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = SessionDirGuard::set(tmp.path().join("chat_sessions"));

        let mut older = Session::new("old-model", "old-provider");
        older.set_id("older-session".to_string());
        older.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);

        let mut newer = Session::new("new-model", "new-provider");
        newer.set_id("newer-session".to_string());
        newer.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);

        save_session(&older).expect("older session should save");
        save_session(&newer).expect("newer session should save");

        let mut app = App::new("initial-model", "initial-provider");
        app.apply_startup_resume(true, Some("older"));

        assert_eq!(app.chat_session.id(), "older-session");
        assert_eq!(app.model, "old-model");
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
        valid.updated_at = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .expect("valid timestamp")
            .with_timezone(&chrono::Utc);
        save_session(&valid).expect("short valid id should save");

        let invalid = Session::new("invalid-model", "provider");
        invalid.set_id("../outside".to_string());
        std::fs::write(
            session_dir.join("invalid.json"),
            serde_json::to_string(&invalid).expect("serialize invalid fixture"),
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
        // transcript writes land under `CLAUDE_CONFIG_HOME_DIR/projects/...`
        // which we redirect into a tempdir so the test can't pollute
        // the user's real `~/.claude/projects/` tree.
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = EnvGuard::set("CLAUDE_CONFIG_HOME_DIR", tmp.path());

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
        // (`<CLAUDE_CONFIG_HOME_DIR>/projects/`). `create_dir_all`
        // then errors with "Not a directory" on every append, so zero
        // entries persist and the watermark must stay at 0 (the bug
        // jumped it straight to 3).
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("projects"), b"not a directory")
            .expect("write blocker file");
        let _guard = EnvGuard::set("CLAUDE_CONFIG_HOME_DIR", tmp.path());

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
        let _guard = EnvGuard::set("CLAUDE_CONFIG_HOME_DIR", tmp.path());

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
        let _guard = EnvGuard::set("CLAUDE_CONFIG_HOME_DIR", tmp.path());
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

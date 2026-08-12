//! Per-category sub-structs that compose [`super::SessionState`].
//!
//! Each category is plain data (no `Arc`s) so [`super::SessionState`]
//! stays `Clone + Serialize + Deserialize` without reaching through
//! shared handles. The process-scoped handles
//! (`memory_db`, `permission_mgr`, …) live on a separate
//! `AppHandles` struct that callers pass alongside a
//! [`super::StateStore`] when both are needed.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ─── Identity ───────────────────────────────────────────────────────

/// Session identifier — UUID-shaped string.
///
/// Newtype so session ids don't get confused with teammate / agent / transcript
/// ids at call sites (the subagent module already uses raw `String`s for
/// `agent_id`; this one is deliberately typed).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a fresh v4 UUID as a session id.
    #[must_use]
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Borrow the inner string — useful for log fields and for
    /// bridging into modules that still take `&str` (chat session,
    /// transcript writer) until they migrate.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate `s` as a UUID and wrap it. Use this on every
    /// untrusted input path (deserialization, on-disk session files,
    /// IPC arrivals) so the newtype's "UUID-shaped string" invariant
    /// actually holds. See crosslink #810.
    ///
    /// # Errors
    /// Returns `uuid::Error` when `s` is not a parseable UUID.
    pub fn from_raw(s: impl AsRef<str>) -> Result<Self, uuid::Error> {
        let raw = s.as_ref();
        // Validate via `Uuid::parse_str` but store the original string so
        // round-trips preserve formatting (hyphenation, case) chosen by
        // the original writer.
        let _: uuid::Uuid = raw.parse()?;
        Ok(Self(raw.to_string()))
    }

    /// Wrap a caller-supplied string WITHOUT validating it as a UUID.
    ///
    /// Only safe to call on input that was previously the output of
    /// `uuid::Uuid::to_string()` (or any other UUID-emitting source).
    /// Test fixtures that need a stable non-UUID id (e.g. literal
    /// `"abcd-1234"`) are the canonical caller. Production code paths
    /// MUST use [`Self::from_raw`] so the newtype's invariant holds.
    ///
    /// Crosslink #810: split out from the original lenient `from_raw`
    /// so the validating path becomes the default and the lenient path
    /// is opt-in with a name that makes its weakness obvious.
    #[must_use]
    pub fn from_raw_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who / where / which. Seven fields matching the Identity group in
/// Claude Code's state-management REQ-1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub session_id: SessionId,
    /// Parent session id when this session was forked from another
    /// (e.g. the coordinator spawning a teammate). `None` for the
    /// primary user-started session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<SessionId>,
    /// The cwd the user launched the harness in — never mutates
    /// during the session. Used for transcript-path stability when
    /// the user changes dir inside a tool call.
    pub original_cwd: PathBuf,
    /// Current working directory. May drift from `original_cwd`
    /// during a session (a `bash cd` tool call updates this).
    pub cwd: PathBuf,
    /// Project root (git toplevel or `original_cwd` when not in a
    /// repo). Used by MEMORY.md discovery and rules/plugins scope.
    pub project_root: PathBuf,
    /// Where transcripts / session-memory / subagent metadata all
    /// anchor. Today derives from `cwd`; kept separate so a future
    /// `/teleport` command can rebase it without touching the live
    /// cwd.
    pub session_project_dir: PathBuf,
    /// Additional directories whose CLAUDE.md files should be
    /// included in the system prompt. Matches CC's `--add-dir`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_directories_for_claude_md: Vec<PathBuf>,
}

impl Identity {
    /// Build an Identity rooted at `cwd` — every directory field
    /// starts equal to `cwd`, no parent session, no extra dirs.
    #[must_use]
    pub fn rooted_at(cwd: PathBuf) -> Self {
        Self {
            session_id: SessionId::new(),
            parent_session_id: None,
            original_cwd: cwd.clone(),
            cwd: cwd.clone(),
            project_root: cwd.clone(),
            session_project_dir: cwd,
            additional_directories_for_claude_md: Vec::new(),
        }
    }
}

// ─── Conversation ───────────────────────────────────────────────────

/// Messages + undo stack + behavioral mode — everything the agentic
/// loop reads per turn.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conversation {
    /// Wire-format messages. `serde_json::Value` because the provider
    /// adapters (Anthropic / `OpenAI` / Google) each want slightly
    /// different on-wire shapes; we keep the Value and let the
    /// adapter pick what it needs.
    #[serde(default)]
    pub messages: Vec<serde_json::Value>,
    /// Stack of `(user, assistant)` pairs popped by `/undo`. Popping
    /// again via `/redo` pushes them back onto `messages`.
    #[serde(default)]
    pub undo_stack: Vec<(serde_json::Value, serde_json::Value)>,
    /// Plan-mode-approved text injected as system context on the
    /// next turn. `None` when plan mode hasn't been used or the user
    /// has already acted on the plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_plan: Option<String>,
    /// Plan-mode state machine — re-exported from the existing
    /// session module so we don't invalidate on-disk formats that
    /// reference it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_mode: Option<crate::session::PlanModeState>,
    /// Active behavioral mode (agency/quality/scope axes + modifiers).
    #[serde(default)]
    pub behavior_mode: crate::modes::BehaviorMode,
}

// ─── UI state ───────────────────────────────────────────────────────

/// Plan-mode one-shot notification flags, nested inside [`UiState`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlanModeFlags {
    /// True after the user has exited plan mode at least once this
    /// session. Controls whether `/plan` shows the "you were in plan
    /// mode" resumption hint.
    #[serde(default)]
    pub has_exited: bool,
    /// Set to true when plan-mode exit left an un-applied plan that
    /// should be attached to the next user message as context.
    #[serde(default)]
    pub needs_exit_attachment: bool,
    /// Same as `needs_exit_attachment` but for auto mode exit.
    /// Fires once and clears after attachment.
    #[serde(default)]
    pub needs_auto_exit_attachment: bool,
}

/// Session-scoped UI flags persisted with the rest of the session document.
///
/// Matches CC's REQ-1 "UI State" group.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UiState {
    /// Plan-mode one-shot notification flags.
    #[serde(default)]
    pub plan_mode: PlanModeFlags,
    /// True after the LSP recommendation card has been shown this
    /// session. Prevents repeated suggestions on every tool call.
    #[serde(default)]
    pub lsp_recommendation_shown_this_session: bool,
}

impl UiState {
    /// Convenience accessor — `true` after the user has exited plan mode once.
    #[must_use]
    pub const fn has_exited_plan_mode(&self) -> bool {
        self.plan_mode.has_exited
    }
}

// ─── Modes ──────────────────────────────────────────────────────────

/// Canonical agent mode shared by both interactive frontends.
///
/// Lowercase names are the current wire format. `PascalCase` aliases preserve
/// compatibility with sessions written by the legacy REPL enum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    /// Full access — write/edit/bash permitted.
    #[serde(alias = "Build")]
    #[default]
    Build,
    /// Read-only — tools that mutate are blocked.
    #[serde(alias = "Plan")]
    Plan,
    /// Write-enabled work constrained to an existing surface.
    #[serde(alias = "Extend")]
    Extend,
    /// Write-enabled structural cleanup.
    #[serde(alias = "Refactor")]
    Refactor,
}

impl AgentMode {
    #[must_use]
    pub const fn toggled(self) -> Self {
        match self {
            Self::Build | Self::Extend | Self::Refactor => Self::Plan,
            Self::Plan => Self::Build,
        }
    }

    #[must_use]
    pub const fn toggle(self) -> Self {
        self.toggled()
    }

    #[must_use]
    pub const fn display(self) -> &'static str {
        match self {
            Self::Build => "Build",
            Self::Plan => "Plan",
            Self::Extend => "Extend",
            Self::Refactor => "Refactor",
        }
    }

    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Build => "Full access - can make changes",
            Self::Plan => "Read-only - suggestions only",
            Self::Extend => "Write-allowed; scope locked to an existing surface",
            Self::Refactor => "Write-allowed; structural changes expected",
        }
    }

    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Plan => "plan",
            Self::Extend => "extend",
            Self::Refactor => "refactor",
        }
    }

    #[must_use]
    pub fn from_token(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "plan" => Self::Plan,
            "extend" => Self::Extend,
            "refactor" => Self::Refactor,
            _ => Self::Build,
        }
    }
}

impl std::fmt::Display for AgentMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.display())
    }
}

/// Agent / behavior mode toggles that aren't already in
/// [`Conversation::behavior_mode`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModesState {
    /// Coarse agent mode kept for compatibility with existing session files;
    /// new code can use `Conversation::behavior_mode` for finer control.
    #[serde(default)]
    pub agent_mode: AgentMode,
    /// Coordinator mode active — leader orchestrating teammates.
    #[serde(default)]
    pub coordinator: bool,
}

// ─── Permissions ────────────────────────────────────────────────────

/// Permission state for this session. The `permission_mgr` itself
/// lives on `AppHandles`; these flags describe the per-session
/// decisions layered on top of it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionsState {
    /// `--dangerously-skip-permissions` was set for this session.
    /// Does NOT persist across sessions.
    #[serde(default)]
    pub bypass_mode: bool,
    /// The user has accepted the per-project trust prompt. Persists
    /// across sessions via the existing `permission_mgr` storage;
    /// mirrored here so callers can read a coherent snapshot.
    #[serde(default)]
    pub trust_accepted: bool,
    /// When true, no permission decisions made this session get
    /// persisted to the on-disk permissions store. Used by tests
    /// and ephemeral sandboxed sessions.
    #[serde(default)]
    pub persistence_disabled: bool,
}

// ─── Budgets ────────────────────────────────────────────────────────

/// Effort levels for thinking / reasoning budget. Matches the
/// string form accepted by `pipeline::build_request`; a dedicated
/// enum here catches typos at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EffortLevel {
    None,
    Minimal,
    Low,
    #[default]
    Medium,
    High,
    Max,
    Auto,
}

impl EffortLevel {
    /// Stringify for the on-wire request format.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Max => "max",
            Self::Auto => "auto",
        }
    }

    /// Return the Unicode status-bar symbol for this effort level.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::None => "\u{25CC}",
            Self::Minimal | Self::Low => "\u{25CB}",
            Self::Medium => "\u{25D0}",
            Self::High => "\u{25CF}",
            Self::Max => "\u{25C6}",
            Self::Auto => "\u{25C7}",
        }
    }

    /// Cycle through the generic effort sequence used outside a provider
    /// context.
    #[must_use]
    pub const fn cycled(self) -> Self {
        match self {
            Self::None => Self::Minimal,
            Self::Minimal | Self::High | Self::Max | Self::Auto => Self::Low,
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
        }
    }

    /// Cycle through only the levels the active provider can express.
    #[must_use]
    pub fn cycled_for_provider(self, provider: &str, model: &str) -> Self {
        let options = Self::provider_options(provider, model);
        let Some(index) = options.iter().position(|level| *level == self) else {
            return options.first().copied().unwrap_or(Self::Medium);
        };
        options[(index + 1) % options.len()]
    }

    /// Selectable effort levels for a provider/model pair.
    #[must_use]
    pub fn provider_options(provider: &str, model: &str) -> &'static [Self] {
        const OPENAI: &[EffortLevel] = &[
            EffortLevel::None,
            EffortLevel::Minimal,
            EffortLevel::Low,
            EffortLevel::Medium,
            EffortLevel::High,
            EffortLevel::Max,
        ];
        const ANTHROPIC_GEMINI: &[EffortLevel] = &[
            EffortLevel::Low,
            EffortLevel::Medium,
            EffortLevel::High,
            EffortLevel::Max,
        ];
        const DEEPSEEK: &[EffortLevel] = &[EffortLevel::High, EffortLevel::Max];
        const GLM_REASONING: &[EffortLevel] = &[
            EffortLevel::None,
            EffortLevel::Minimal,
            EffortLevel::High,
            EffortLevel::Max,
        ];
        const THINKING_TOGGLE: &[EffortLevel] = &[EffortLevel::Auto, EffortLevel::High];
        const LOCAL: &[EffortLevel] = &[EffortLevel::Auto];

        match provider.to_ascii_lowercase().as_str() {
            "openai" => OPENAI,
            "deepseek" => DEEPSEEK,
            "zai" | "glm" | "zhipu" if model.eq_ignore_ascii_case("glm-5.2") => GLM_REASONING,
            "qwen" | "alibaba" | "zai" | "glm" | "zhipu" | "kimi" | "moonshot" | "minimax" => {
                THINKING_TOGGLE
            }
            "ollama" | "local" | "lmstudio" | "localai" | "text-generation-webui" => LOCAL,
            _ => ANTHROPIC_GEMINI,
        }
    }

    /// Parse from the string form sent over the wire / accepted at
    /// the slash-command layer. Unrecognized inputs return `None`
    /// so the caller can decide whether to error or fall back.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" | "off" => Some(Self::None),
            "minimal" | "min" => Some(Self::Minimal),
            "low" | "l" => Some(Self::Low),
            "medium" | "med" | "m" => Some(Self::Medium),
            "high" | "h" => Some(Self::High),
            "max" | "x" | "xhigh" => Some(Self::Max),
            "auto" | "unset" => Some(Self::Auto),
            _ => None,
        }
    }
}

impl std::fmt::Display for EffortLevel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for EffortLevel {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(value.trim()).unwrap_or(Self::Medium))
    }
}

/// Budgets — tokens, cost, rate limits. All numeric — no `Arc`s.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetsState {
    #[serde(default)]
    pub effort_level: EffortLevel,
    /// When `Some`, overrides the default thinking budget derived
    /// from `effort_level`. Set by `MAX_THINKING_TOKENS` env var at
    /// startup (matches `crate::thinking::anthropic_thinking_budget`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_budget_override: Option<u32>,
    /// Rough running token estimate for the status bar. Not
    /// authoritative — the provider response carries the real count.
    #[serde(default)]
    pub estimated_tokens: usize,
}

// ─── Transcript ─────────────────────────────────────────────────────

/// Per-session transcript bookkeeping.
///
/// The transcript itself lives on disk (via `crate::transcript`); this is
/// just the watermark + cached cwd needed to append new lines without
/// re-enumerating the file on every turn.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TranscriptState {
    /// Count of `conversation.messages` already appended to the
    /// JSONL transcript. Everything past this index gets appended
    /// on the next `persist_transcript_tail` call.
    #[serde(default)]
    pub watermark: usize,
    /// The cwd captured when the transcript first opened. Stays
    /// stable even if the user cd's inside a tool call, so later
    /// appends hit the same project dir.
    #[serde(default)]
    pub transcript_cwd: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_id_is_uuid_shaped() {
        let id = SessionId::new();
        // UUID v4 as a hyphenated string is 36 characters.
        assert_eq!(id.as_str().len(), 36);
        // Survives Display.
        let s = format!("{id}");
        assert_eq!(s, id.as_str());
    }

    #[test]
    fn session_id_round_trips_from_raw_unchecked() {
        // Pre-#810 the lenient path was named `from_raw` and accepted any
        // string. It is now renamed `from_raw_unchecked` and explicitly
        // marked unsafe-by-contract; the validated entry point is the
        // new `from_raw` (UUID-only).
        let raw = "abcd-1234";
        let id = SessionId::from_raw_unchecked(raw);
        assert_eq!(id.as_str(), raw);
    }

    /// #810: `from_raw` validates that the input parses as a UUID.
    /// A real UUID round-trips; a malformed string is rejected.
    #[test]
    fn session_id_from_raw_validates_uuid() {
        // Round-trip for a real UUID — the canonical happy path.
        let canonical = uuid::Uuid::new_v4().to_string();
        let id = SessionId::from_raw(&canonical).expect("real UUID must parse");
        assert_eq!(id.as_str(), canonical);

        // Malformed strings that the pre-#810 newtype silently accepted
        // must now fail. Particularly nasty: a path-traversal payload
        // would have flowed through `session_project_dir.join(id)`
        // unchecked.
        for bad in [
            "",
            "abcd-1234",
            "../../etc/passwd",
            "not-a-uuid",
            "00000000-0000-0000-0000-00000000000Z", // bad final char
        ] {
            assert!(
                SessionId::from_raw(bad).is_err(),
                "#810: {bad:?} must NOT parse as a SessionId"
            );
        }
    }

    #[test]
    fn identity_rooted_sets_every_directory_field() {
        let cwd = PathBuf::from("/home/user/project");
        let id = Identity::rooted_at(cwd.clone());
        assert_eq!(id.original_cwd, cwd);
        assert_eq!(id.cwd, cwd);
        assert_eq!(id.project_root, cwd);
        assert_eq!(id.session_project_dir, cwd);
        assert!(id.additional_directories_for_claude_md.is_empty());
        assert!(id.parent_session_id.is_none());
    }

    #[test]
    fn effort_level_parses_common_aliases() {
        assert_eq!(EffortLevel::parse("off"), Some(EffortLevel::None));
        assert_eq!(EffortLevel::parse("min"), Some(EffortLevel::Minimal));
        assert_eq!(EffortLevel::parse("low"), Some(EffortLevel::Low));
        assert_eq!(EffortLevel::parse("l"), Some(EffortLevel::Low));
        assert_eq!(EffortLevel::parse("MEDIUM"), Some(EffortLevel::Medium));
        assert_eq!(EffortLevel::parse("med"), Some(EffortLevel::Medium));
        assert_eq!(EffortLevel::parse("High"), Some(EffortLevel::High));
        assert_eq!(EffortLevel::parse("max"), Some(EffortLevel::Max));
        assert_eq!(EffortLevel::parse("x"), Some(EffortLevel::Max));
        assert_eq!(EffortLevel::parse("xhigh"), Some(EffortLevel::Max));
        assert_eq!(EffortLevel::parse("auto"), Some(EffortLevel::Auto));
        assert_eq!(EffortLevel::parse("unset"), Some(EffortLevel::Auto));
        assert_eq!(EffortLevel::parse("xxl"), None);
    }

    #[test]
    fn effort_level_as_str_matches_wire_format() {
        // Matches what pipeline::build_request expects.
        assert_eq!(EffortLevel::None.as_str(), "none");
        assert_eq!(EffortLevel::Minimal.as_str(), "minimal");
        assert_eq!(EffortLevel::Low.as_str(), "low");
        assert_eq!(EffortLevel::Medium.as_str(), "medium");
        assert_eq!(EffortLevel::High.as_str(), "high");
        assert_eq!(EffortLevel::Max.as_str(), "max");
        assert_eq!(EffortLevel::Auto.as_str(), "auto");
    }

    #[test]
    fn effort_level_keeps_provider_specific_cycles() {
        assert_eq!(
            EffortLevel::Max.cycled_for_provider("openai", "gpt-5.5"),
            EffortLevel::None
        );
        assert_eq!(
            EffortLevel::Low.cycled_for_provider("deepseek", "deepseek-reasoner"),
            EffortLevel::High
        );
        assert_eq!(
            EffortLevel::High.cycled_for_provider("ollama", "local-model"),
            EffortLevel::Auto
        );
    }

    #[test]
    fn agent_mode_accepts_both_legacy_wire_formats() {
        assert_eq!(
            serde_json::from_str::<AgentMode>(r#""build""#).unwrap(),
            AgentMode::Build
        );
        assert_eq!(
            serde_json::from_str::<AgentMode>(r#""Build""#).unwrap(),
            AgentMode::Build
        );
        assert_eq!(
            serde_json::from_str::<AgentMode>(r#""Plan""#).unwrap(),
            AgentMode::Plan
        );
        assert_eq!(
            serde_json::from_str::<AgentMode>(r#""extend""#).unwrap(),
            AgentMode::Extend
        );
        assert_eq!(
            serde_json::to_string(&AgentMode::Refactor).unwrap(),
            r#""refactor""#
        );
    }

    #[test]
    fn defaults_match_existing_tui_session_defaults() {
        // These defaults match the compatibility session wrappers so resumed
        // sessions look the same to the user.
        let conv = Conversation::default();
        assert!(conv.messages.is_empty());
        assert!(conv.undo_stack.is_empty());
        assert!(conv.approved_plan.is_none());

        let budgets = BudgetsState::default();
        assert_eq!(budgets.effort_level, EffortLevel::Medium);
        assert!(budgets.thinking_budget_override.is_none());

        let perms = PermissionsState::default();
        assert!(!perms.bypass_mode);
        assert!(!perms.trust_accepted);
    }

    #[test]
    fn json_omits_empty_optional_fields() {
        // skip_serializing_if attributes keep the on-disk shape
        // tight. Default state → minimal JSON.
        let id = Identity::rooted_at(PathBuf::from("/x"));
        let json = serde_json::to_string(&id).unwrap();
        assert!(!json.contains("parent_session_id"));
        assert!(!json.contains("additional_directories_for_claude_md"));
    }
}

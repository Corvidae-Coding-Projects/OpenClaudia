//! Session Manager - Tracks agent sessions with initializer/coding agent patterns.
//!
//! Implements two-part session architecture:
//! - Initializer Agent: First session, creates progress files and feature lists
//! - Coding Agent: Subsequent sessions, reads git logs and progress files
//!
//! Treats agents like shift workers with documented handoffs.

mod audit;
mod pricing;
mod state;
mod task;

// Re-export all public types
pub use audit::{AuditError, AuditLogger};
pub use pricing::{
    calculate_cost, calculate_cost_fast_mode, calculate_cost_full, calculate_cost_with_extras,
    calculate_cost_with_ttl, clear_unknown_model_cost, get_pricing, has_unknown_model_cost,
    CacheWriteTtl, ModelPricing, PricingError, FAST_MODE_INPUT_PER_MILLION,
    FAST_MODE_OUTPUT_PER_MILLION, GOOGLE_LONG_CONTEXT_THRESHOLD_TOKENS,
    OPENAI_LONG_CONTEXT_THRESHOLD_TOKENS, OPUS_4_8_FAST_MODE_INPUT_PER_MILLION,
    OPUS_4_8_FAST_MODE_OUTPUT_PER_MILLION,
};
pub use state::{
    get_session_context, is_tool_allowed_in_plan_mode, is_tool_allowed_in_plan_mode_with_policy,
    AllowedPrompt, PlanModePolicy, PlanModeState, TokenUsage, TurnMetrics, UsageExtras,
    MCP_TOOL_PREFIX, PLAN_MODE_ALLOWED_TOOLS, PLUGIN_TOOL_PREFIX,
};
pub use task::{Task, TaskManager, TaskStatus, TaskUpdateParams, TaskUpdateStatus};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Errors produced by [`SessionManager::end_session`].
///
/// Replaces the previous `Option<Session>` return which silently conflated
/// "no current session" with "persist failed".  Callers can now distinguish
/// and react appropriately (see #356).
#[derive(Debug, Error)]
pub enum EndSessionError {
    /// `end_session` was called but no current session was active.
    ///
    /// Previously surfaced as a silent `None`.
    #[error("no current session is active")]
    NotFound,

    /// Persistence of the session (any of `session.id.json`, `latest.json`,
    /// `handoff.md`) failed.  The in-memory session has already been
    /// `take`n from the manager; recovery requires the caller to either
    /// retry persistence externally or accept loss.
    #[error("failed to persist session to disk: {source}")]
    PersistFailed {
        /// The underlying I/O / serialisation error.
        #[source]
        source: anyhow::Error,
    },
}

/// Maximum number of [`TurnMetrics`] entries retained in [`Session::turn_metrics`].
///
/// Once this cap is reached, `record_turn_estimate` evicts the oldest entry
/// (index 0) before pushing the new one, so the vector never grows beyond
/// `MAX_TURN_METRICS` elements.  The [`Session::cumulative_usage`] counter
/// continues to accumulate across all turns regardless of eviction.
///
/// Chosen to cover ~2.8 hours of turns at 10 s/turn while keeping the
/// serialised session JSON under ~500 KB for the default [`TurnMetrics`] size.
pub const MAX_TURN_METRICS: usize = 1_000;

/// Maximum provider/runtime failure reason bytes persisted into chat history.
///
/// Failure bodies can be large HTML/JSON payloads. Persist enough context for
/// diagnosis without allowing a transient provider error to bloat sessions.
pub const FAILED_TURN_REASON_MAX_BYTES: usize = 1_000;

/// Append a local assistant marker for a prompt that failed before a model
/// response was produced.
///
/// Failed turns are part of the user-visible transcript. Recording them as an
/// assistant message keeps the user prompt durable and prevents the next turn
/// from replaying it as an unanswered prompt.
pub fn append_failed_turn_message(messages: &mut Vec<serde_json::Value>, reason: &str) {
    let reason = truncate_reason(reason.trim());
    let reason = if reason.is_empty() {
        "unknown failure"
    } else {
        reason
    };
    messages.push(serde_json::json!({
        "role": "assistant",
        "content": format!(
            "OpenClaudia local runtime status: request failed before a model response was produced. Reason: {reason}"
        )
    }));
}

fn truncate_reason(reason: &str) -> &str {
    if reason.len() <= FAILED_TURN_REASON_MAX_BYTES {
        return reason;
    }
    let mut end = FAILED_TURN_REASON_MAX_BYTES;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

fn validate_session_file_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() {
        return Err("session id must not be empty");
    }

    if id.len() > 128 {
        return Err("session id must be 128 bytes or fewer");
    }

    if id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        Ok(())
    } else {
        Err("session id must contain only ASCII letters, numbers, or '-'")
    }
}

/// Write data to a file atomically and durably: write to a uniquely-named
/// temp file in the same directory, fsync it, then rename.
///
/// The staging name is `<file>.<pid>.<uuid>.tmp` rather than
/// `<file>.tmp`. The previous fixed `.tmp` extension meant two
/// concurrent writers targeting the SAME final path (e.g. an autosave
/// racing `end_session`) overwrote each other's staging file mid-write;
/// the `rename` then surfaced an arbitrary winner's partial bytes
/// (crosslink #949).
///
/// Using `(pid, uuid)` gives a name unique-per-call across every
/// thread / process / async task on the host, so the staging files
/// never collide and the rename always promotes the bytes that *this*
/// caller wrote.
///
/// On any write, sync, or rename failure the staging file is cleaned up so a
/// crashing or erroring caller does not leave `<file>.<pid>.<uuid>.tmp` debris
/// in the persist directory.
fn atomic_write(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let tmp_path = unique_staging_path(path);
    let write_result = (|| -> anyhow::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }

    if let Err(e) = crate::file_error::replace_file_atomic(&tmp_path, path) {
        // Best-effort cleanup; ignore the unlink error so the caller
        // sees the original rename failure, which is the actionable one.
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    sync_parent_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Build `<file>.<pid>.<uuid>.tmp` next to `path`, guaranteed unique
/// across concurrent writers. Returns the staging path; callers rename
/// it onto `path` once the bytes are durable.
fn unique_staging_path(path: &Path) -> PathBuf {
    let file_name = path.file_name().map_or_else(
        || "session".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let staging = format!(
        "{file_name}.{pid}.{uuid}.tmp",
        pid = std::process::id(),
        uuid = Uuid::new_v4().simple(),
    );
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(staging)
}

/// Session state indicating the agent mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    /// First session - creates initial context
    Initializer,
    /// Subsequent sessions - continues from handoff
    Coding,
}

/// Progress tracking for a session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionProgress {
    /// Tasks completed in this session
    pub completed_tasks: Vec<String>,
    /// Tasks in progress
    pub in_progress_tasks: Vec<String>,
    /// Tasks pending
    pub pending_tasks: Vec<String>,
    /// Key decisions made
    pub decisions: Vec<String>,
    /// Files modified
    pub files_modified: Vec<String>,
    /// Notes for next session
    pub handoff_notes: String,
    /// VDD: total findings across all VDD sessions
    #[serde(default)]
    pub vdd_total_findings: u32,
    /// VDD: total genuine findings
    #[serde(default)]
    pub vdd_total_genuine: u32,
    /// VDD: session IDs for VDD sessions in this coding session
    #[serde(default)]
    pub vdd_sessions: Vec<String>,
}

/// Zero-copy read-only view over a [`Session`].
///
/// `SessionView<'a>` borrows the underlying [`Session`] and exposes its
/// fields by reference, allowing callers to read session state without
/// triggering a full struct clone.  Use this in place of `session.clone()`
/// whenever the caller only needs to *read* the session — the major heap
/// fields (`turn_metrics`, `progress.completed_tasks`, …) all become
/// `&[T]` / `&str` slices, so a single 24-hour session with thousands of
/// turn-metrics entries is no longer deep-copied on every read.
///
/// Construction: prefer [`Session::view`] over building this directly so
/// the lifetime tracking against the owning [`Session`] is enforced.
///
/// Issue: crosslink #458 — `Session` is `#[derive(Clone)]` and was cloned
/// on every read in older call sites.  The `Clone` derive is retained for
/// snapshot persistence + tests, but new read-paths should take a
/// `SessionView<'_>` instead.
#[derive(Debug, Clone, Copy)]
pub struct SessionView<'a> {
    inner: &'a Session,
}

impl<'a> SessionView<'a> {
    /// Wrap an existing [`Session`] reference as a read-only view.
    #[must_use]
    pub const fn new(session: &'a Session) -> Self {
        Self { inner: session }
    }

    /// Session ID (borrowed).
    #[must_use]
    pub fn id(&self) -> &'a str {
        &self.inner.id
    }

    /// Session mode (cheap `Copy`).
    #[must_use]
    pub const fn mode(&self) -> SessionMode {
        self.inner.mode
    }

    /// When the session was created.
    #[must_use]
    pub const fn created_at(&self) -> &'a DateTime<Utc> {
        &self.inner.created_at
    }

    /// When the session was last updated.
    #[must_use]
    pub const fn updated_at(&self) -> &'a DateTime<Utc> {
        &self.inner.updated_at
    }

    /// Borrowed reference to session progress.
    #[must_use]
    pub const fn progress(&self) -> &'a SessionProgress {
        &self.inner.progress
    }

    /// Parent session ID, if any (borrowed).
    #[must_use]
    pub fn parent_session_id(&self) -> Option<&'a str> {
        self.inner.parent_session_id.as_deref()
    }

    /// Number of API requests in this session.
    #[must_use]
    pub const fn request_count(&self) -> u64 {
        self.inner.request_count
    }

    /// Total tokens used in this session, derived from
    /// [`Self::cumulative_usage`]. Previously this was a separate
    /// field that drifted from `cumulative_usage` whenever a caller
    /// hit one writer but not the other — see crosslink #854. Kept
    /// as a method on the view so existing callers compile unchanged.
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.inner.total_tokens()
    }

    /// Cumulative token usage across all turns.
    #[must_use]
    pub const fn cumulative_usage(&self) -> &'a TokenUsage {
        &self.inner.cumulative_usage
    }

    /// Per-turn metrics slice (borrowed; capped at [`MAX_TURN_METRICS`]).
    #[must_use]
    pub fn turn_metrics(&self) -> &'a [TurnMetrics] {
        &self.inner.turn_metrics
    }

    /// Monotonically increasing total turn count.
    #[must_use]
    pub const fn total_turns(&self) -> u64 {
        self.inner.total_turns
    }

    /// Borrow the underlying [`Session`] (escape hatch for code that
    /// genuinely needs the full struct — e.g. serde serialisation).
    #[must_use]
    pub const fn as_session(&self) -> &'a Session {
        self.inner
    }
}

/// A single agent session.
///
/// `Session` derives [`Clone`] so it can be snapshot-serialised for
/// persistence and so tests can capture a frozen copy for assertions.
/// **Production read-paths should not clone the whole struct** — use
/// [`Session::view`] (returns a [`SessionView<'_>`]) when you only need
/// to inspect fields.  See crosslink #458 for the historical context:
/// cloning was previously the default and deep-copied multi-kilobyte
/// `turn_metrics`/`progress` vectors on every read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub id: String,
    /// Session mode (initializer or coding)
    pub mode: SessionMode,
    /// When the session started
    pub created_at: DateTime<Utc>,
    /// When the session was last updated
    pub updated_at: DateTime<Utc>,
    /// Session progress tracking
    pub progress: SessionProgress,
    /// Parent session ID if this is a continuation
    pub parent_session_id: Option<String>,
    /// Number of API requests in this session
    pub request_count: u64,
    /// Cumulative token usage across all turns. This is the single
    /// source of truth for "how many tokens have been spent" —
    /// [`Self::total_tokens`] is derived from it (crosslink #854).
    #[serde(default)]
    pub cumulative_usage: TokenUsage,
    /// Deserialize-only escape hatch for sessions persisted before
    /// crosslink #854 removed the parallel `total_tokens` field. Old
    /// JSONL still carries a `total_tokens` integer; serde would
    /// otherwise refuse the unknown field on strict configs. We
    /// accept it and surface the value (best-effort) via
    /// [`Session::legacy_persisted_total_tokens`] so a diagnostic UI
    /// can report it — the source of truth for live updates remains
    /// `cumulative_usage`. Never serialized back out.
    #[serde(default, skip_serializing, rename = "total_tokens")]
    legacy_total_tokens: Option<u64>,
    /// Per-turn metrics history (capped at [`MAX_TURN_METRICS`] entries)
    #[serde(default)]
    pub turn_metrics: Vec<TurnMetrics>,
    /// Monotonically increasing count of all turns ever recorded, including
    /// those evicted from the `turn_metrics` ring.  Never decremented.
    #[serde(default)]
    pub total_turns: u64,
}

impl Session {
    /// Create a new initializer session
    #[must_use]
    pub fn new_initializer() -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            mode: SessionMode::Initializer,
            created_at: now,
            updated_at: now,
            progress: SessionProgress::default(),
            parent_session_id: None,
            request_count: 0,
            cumulative_usage: TokenUsage::default(),
            legacy_total_tokens: None,
            turn_metrics: Vec::new(),
            total_turns: 0,
        }
    }

    /// Create a new coding session continuing from a parent
    #[must_use]
    pub fn new_coding(parent_id: &str) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            mode: SessionMode::Coding,
            created_at: now,
            updated_at: now,
            progress: SessionProgress::default(),
            parent_session_id: Some(parent_id.to_string()),
            request_count: 0,
            cumulative_usage: TokenUsage::default(),
            legacy_total_tokens: None,
            turn_metrics: Vec::new(),
            total_turns: 0,
        }
    }

    /// Borrow this session as a zero-copy read-only [`SessionView`].
    ///
    /// Prefer this over [`Clone::clone`] anywhere you only need to read
    /// session fields — the view holds a single shared reference and
    /// avoids deep-copying `turn_metrics`/`progress`/`cumulative_usage`.
    #[must_use]
    pub const fn view(&self) -> SessionView<'_> {
        SessionView::new(self)
    }

    /// Update the session timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Increment request count
    pub fn increment_requests(&mut self) {
        self.request_count += 1;
        self.touch();
    }

    /// Total tokens spent in this session — input + output, derived
    /// from [`Self::cumulative_usage`]. Crosslink #854: previously a
    /// parallel field that drifted whenever a caller hit `add_tokens`
    /// (which bypassed `cumulative_usage`) but not `record_actual_usage`.
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.cumulative_usage.total()
    }

    /// Read the legacy `total_tokens` value from a session that was
    /// persisted before crosslink #854 split the counter out of
    /// `Session`. Returns `None` for sessions written after the
    /// migration. Provided so diagnostic UIs can still surface the
    /// historical approximation when `cumulative_usage` was never
    /// populated.
    #[must_use]
    pub const fn legacy_persisted_total_tokens(&self) -> Option<u64> {
        self.legacy_total_tokens
    }

    /// Add tokens to the cumulative usage as a coarse input-side
    /// estimate. Crosslink #854: this used to write a separate
    /// `total_tokens` field that diverged from `cumulative_usage`;
    /// it now routes through the single source of truth. Use
    /// [`Self::record_actual_usage`] when a typed [`TokenUsage`] is
    /// available from a provider response.
    pub fn add_tokens(&mut self, tokens: u64) {
        // Treat untyped tokens as input — that's how the old
        // counter accrued for tooling that didn't distinguish.
        let usage = TokenUsage {
            input_tokens: tokens,
            ..TokenUsage::default()
        };
        self.cumulative_usage.accumulate(&usage);
        self.touch();
    }

    /// Record metrics for an API turn (pre-request estimation).
    ///
    /// The in-memory ring is capped at [`MAX_TURN_METRICS`] entries: when the
    /// vector is already at capacity the oldest entry is evicted before the new
    /// one is pushed, so memory usage stays bounded regardless of session
    /// length.  [`Session::cumulative_usage`] is **not** affected by eviction —
    /// it continues to accumulate across all turns.
    pub fn record_turn_estimate(
        &mut self,
        estimated_input_tokens: usize,
        injected_context_tokens: usize,
        system_prompt_tokens: usize,
        tool_def_tokens: usize,
    ) -> u64 {
        // Evict the oldest entry when at capacity so the vec stays bounded.
        if self.turn_metrics.len() >= MAX_TURN_METRICS {
            self.turn_metrics.remove(0);
        }
        // Use the cumulative turn counter so turn_number is monotonically
        // increasing even after old entries are evicted from the ring.
        self.total_turns += 1;
        let turn_number = self.total_turns;
        self.turn_metrics.push(TurnMetrics {
            turn_number,
            estimated_input_tokens,
            actual_usage: None,
            injected_context_tokens,
            system_prompt_tokens,
            tool_def_tokens,
            timestamp: Utc::now(),
            vdd_iterations: None,
            vdd_genuine_findings: None,
            vdd_false_positives: None,
            vdd_adversary_tokens: None,
            vdd_converged: None,
        });
        self.touch();
        turn_number
    }

    /// Record actual usage from provider response for the most recent turn.
    /// Crosslink #854: the redundant `total_tokens += usage.total()`
    /// write has been removed — `total_tokens` is now derived from
    /// `cumulative_usage` so the two cannot drift.
    pub fn record_actual_usage(&mut self, usage: TokenUsage) {
        self.cumulative_usage.accumulate(&usage);
        if let Some(last_turn) = self.turn_metrics.last_mut() {
            last_turn.actual_usage = Some(usage);
        }
        self.touch();
    }

    /// Get session stats summary
    #[must_use]
    pub fn stats_summary(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "Session: {}", self.id);
        let _ = writeln!(s, "Mode: {:?}", self.mode);
        let _ = writeln!(s, "Turns: {}", self.total_turns);
        let _ = writeln!(s, "Requests: {}", self.request_count);
        let _ = writeln!(
            s,
            "Input tokens:  {} (cumulative)",
            self.cumulative_usage.input_tokens
        );
        let _ = writeln!(
            s,
            "Output tokens: {} (cumulative)",
            self.cumulative_usage.output_tokens
        );
        let _ = writeln!(
            s,
            "Cache read:    {}",
            self.cumulative_usage.cache_read_tokens
        );
        let _ = writeln!(
            s,
            "Cache write:   {}",
            self.cumulative_usage.cache_write_tokens
        );
        let _ = writeln!(s, "Total tokens:  {}", self.cumulative_usage.total());

        if let Some(last) = self.turn_metrics.last() {
            let _ = write!(
                s,
                "\nLast turn #{}: estimated {} input tokens",
                last.turn_number, last.estimated_input_tokens
            );
            if let Some(actual) = &last.actual_usage {
                let _ = write!(
                    s,
                    ", actual {}in/{}out",
                    actual.input_tokens, actual.output_tokens
                );
            }
            s.push('\n');
        }

        s
    }

    /// Add a completed task
    pub fn complete_task(&mut self, task: impl Into<String>) {
        self.progress.completed_tasks.push(task.into());
        self.touch();
    }

    /// Add a file to the modified list
    pub fn add_modified_file(&mut self, path: impl Into<String>) {
        let path = path.into();
        if !self.progress.files_modified.contains(&path) {
            self.progress.files_modified.push(path);
            self.touch();
        }
    }

    /// Set handoff notes for the next session
    pub fn set_handoff_notes(&mut self, notes: impl Into<String>) {
        self.progress.handoff_notes = notes.into();
        self.touch();
    }

    /// Generate a handoff summary for the next agent
    #[must_use]
    pub fn generate_handoff(&self) -> String {
        let mut handoff = String::new();

        handoff.push_str("## Session Handoff\n\n");
        let _ = writeln!(handoff, "Previous Session: {}", self.id);
        let _ = writeln!(handoff, "Mode: {:?}", self.mode);
        let _ = write!(
            handoff,
            "Duration: {} to {}\n\n",
            self.created_at.format("%Y-%m-%d %H:%M UTC"),
            self.updated_at.format("%Y-%m-%d %H:%M UTC")
        );

        if !self.progress.completed_tasks.is_empty() {
            handoff.push_str("### Completed Tasks\n");
            for task in &self.progress.completed_tasks {
                let _ = writeln!(handoff, "- [x] {task}");
            }
            handoff.push('\n');
        }

        if !self.progress.in_progress_tasks.is_empty() {
            handoff.push_str("### In Progress\n");
            for task in &self.progress.in_progress_tasks {
                let _ = writeln!(handoff, "- [ ] {task}");
            }
            handoff.push('\n');
        }

        if !self.progress.pending_tasks.is_empty() {
            handoff.push_str("### Pending Tasks\n");
            for task in &self.progress.pending_tasks {
                let _ = writeln!(handoff, "- [ ] {task}");
            }
            handoff.push('\n');
        }

        if !self.progress.decisions.is_empty() {
            handoff.push_str("### Key Decisions\n");
            for decision in &self.progress.decisions {
                let _ = writeln!(handoff, "- {decision}");
            }
            handoff.push('\n');
        }

        if !self.progress.files_modified.is_empty() {
            handoff.push_str("### Files Modified\n");
            for file in &self.progress.files_modified {
                let _ = writeln!(handoff, "- {file}");
            }
            handoff.push('\n');
        }

        if !self.progress.handoff_notes.is_empty() {
            handoff.push_str("### Notes for Next Session\n");
            handoff.push_str(&self.progress.handoff_notes);
            handoff.push('\n');
        }

        // Include token usage stats
        if self.cumulative_usage.total() > 0 {
            handoff.push_str("\n### Token Usage\n");
            let _ = writeln!(
                handoff,
                "- Input: {} tokens",
                self.cumulative_usage.input_tokens
            );
            let _ = writeln!(
                handoff,
                "- Output: {} tokens",
                self.cumulative_usage.output_tokens
            );
            let _ = writeln!(
                handoff,
                "- Cache read: {} tokens",
                self.cumulative_usage.cache_read_tokens
            );
            let _ = writeln!(handoff, "- Turns: {}", self.total_turns);
        }

        handoff
    }
}

/// Manages session lifecycle and persistence
#[derive(Debug, Clone)]
pub struct SessionManager {
    /// Directory for session persistence
    persist_dir: PathBuf,
    /// Current active session
    current_session: Option<Session>,
    /// Typed VDD advisory observation for the next turn.
    vdd_pending_observation: Option<crate::context::ContextItem>,
    /// Structured task manager for `task_create`/`update`/`get`/`list` tools
    pub task_manager: TaskManager,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(persist_dir: impl Into<PathBuf>) -> Self {
        let persist_dir = persist_dir.into();

        // Ensure the directory exists
        if let Err(e) = fs::create_dir_all(&persist_dir) {
            warn!(error = %e, path = ?persist_dir, "Failed to create session directory");
        }

        Self {
            persist_dir,
            current_session: None,
            vdd_pending_observation: None,
            task_manager: TaskManager::new(),
        }
    }

    /// Get the current session, creating one if none exists.
    pub fn get_or_create_session(&mut self) -> &Session {
        let persist_dir = self.persist_dir.clone();
        self.current_session
            .get_or_insert_with(|| Self::create_session_for_persist_dir(&persist_dir))
    }

    /// Get the current session mutably
    pub const fn get_session_mut(&mut self) -> Option<&mut Session> {
        self.current_session.as_mut()
    }

    /// Get the current session immutably
    #[must_use]
    pub const fn get_session(&self) -> Option<&Session> {
        self.current_session.as_ref()
    }

    /// Get a zero-copy [`SessionView`] of the current session.
    ///
    /// Returns `None` when there is no active session.  This is the
    /// preferred read-only accessor: it avoids the historical pattern of
    /// `get_or_create_session().clone()` that deep-copied the entire
    /// [`Session`] struct on every read (crosslink #458).
    #[must_use]
    pub fn current_view(&self) -> Option<SessionView<'_>> {
        self.current_session.as_ref().map(Session::view)
    }

    /// Set the active session mode without replacing the active session.
    ///
    /// ACP's `session/set_mode` targets the current session identity; callers
    /// that need a brand-new initializer/coding session should continue using
    /// [`Self::start_initializer`] or [`Self::start_coding`].
    pub fn set_current_mode(&mut self, mode: SessionMode) -> &Session {
        let persist_dir = self.persist_dir.clone();
        let session = self
            .current_session
            .get_or_insert_with(|| Self::create_session_for_persist_dir(&persist_dir));
        session.mode = mode;
        if mode == SessionMode::Initializer {
            session.parent_session_id = None;
        }
        session.touch();
        session
    }

    /// Store a typed VDD advisory observation for the next turn.
    pub fn store_vdd_observation(&mut self, observation: crate::context::ContextItem) {
        self.vdd_pending_observation = Some(observation);
    }

    /// Take (consume) the pending VDD observation.
    pub const fn take_vdd_observation(&mut self) -> Option<crate::context::ContextItem> {
        self.vdd_pending_observation.take()
    }

    fn create_session_for_persist_dir(persist_dir: &Path) -> Session {
        // Check if there's a previous session to continue from
        let latest_path = persist_dir.join("latest.json");
        if let Some(last_session) = Self::load_session_from_path(&latest_path) {
            info!(
                parent_id = %last_session.id,
                "Creating coding session continuing from previous"
            );
            Session::new_coding(&last_session.id)
        } else {
            info!("Creating new initializer session");
            Session::new_initializer()
        }
    }

    /// Start a fresh initializer session.
    pub fn start_initializer(&mut self) -> &Session {
        let session = Session::new_initializer();
        info!(session_id = %session.id, "Started initializer session");
        self.current_session.insert(session)
    }

    /// Start a coding session from a parent.
    pub fn start_coding(&mut self, parent_id: &str) -> &Session {
        let session = Session::new_coding(parent_id);
        info!(
            session_id = %session.id,
            parent_id = %parent_id,
            "Started coding session"
        );
        self.current_session.insert(session)
    }

    /// End the current session and persist it.
    ///
    /// # Errors
    ///
    /// * [`EndSessionError::NotFound`] — no current session was active
    ///   (previously returned `None` silently, conflating with persist
    ///   failure; see #356).
    /// * [`EndSessionError::PersistFailed`] — persistence of one of the
    ///   session files failed.  The in-memory session has already been
    ///   removed from the manager when this is returned.
    pub fn end_session(&mut self, handoff_notes: Option<&str>) -> Result<Session, EndSessionError> {
        let mut session = self
            .current_session
            .take()
            .ok_or(EndSessionError::NotFound)?;

        if let Some(notes) = handoff_notes {
            session.set_handoff_notes(notes);
        }

        // Persist the session; failure must surface to the caller, not be
        // swallowed via warn!() as it was prior to #356.
        let persist_result = self.persist_session(&session);
        crate::tools::cancel_session_sandbox_processes(&session.id);
        crate::tools::terminate_session_background_jobs(&session.id);
        persist_result.map_err(|source| EndSessionError::PersistFailed { source })?;

        info!(
            session_id = %session.id,
            requests = session.request_count,
            "Ended session"
        );

        Ok(session)
    }

    /// Persist a session to disk using atomic write-to-temp-then-rename.
    ///
    /// Each file is written to a `.tmp` file first, then atomically renamed.
    /// If the process crashes mid-write, the original file remains intact.
    fn persist_session(&self, session: &Session) -> anyhow::Result<()> {
        validate_session_file_id(&session.id)
            .map_err(|reason| anyhow::anyhow!("invalid session id {:?}: {reason}", session.id))?;
        let filename = format!("{}.json", session.id);
        let path = self.persist_dir.join(&filename);

        let json = serde_json::to_string_pretty(session)?;
        atomic_write(&path, json.as_bytes())?;

        debug!(path = ?path, "Persisted session");

        // Also update the "latest" symlink/file
        let latest_path = self.persist_dir.join("latest.json");
        atomic_write(
            &latest_path,
            serde_json::to_string_pretty(session)?.as_bytes(),
        )?;

        // Generate and save handoff document
        let handoff_path = self.persist_dir.join("handoff.md");
        atomic_write(&handoff_path, session.generate_handoff().as_bytes())?;

        Ok(())
    }

    /// Load a session by ID
    #[must_use]
    pub fn load_session(&self, session_id: &str) -> Option<Session> {
        if let Err(reason) = validate_session_file_id(session_id) {
            warn!(session_id = %session_id, reason, "Rejected invalid session id");
            return None;
        }
        let path = self.persist_dir.join(format!("{session_id}.json"));
        Self::load_session_from_path(&path)
    }

    /// Load the most recent session
    #[must_use]
    pub fn load_latest_session(&self) -> Option<Session> {
        let path = self.persist_dir.join("latest.json");
        Self::load_session_from_path(&path)
    }

    /// Load a session from a file path
    fn load_session_from_path(path: &Path) -> Option<Session> {
        if !path.exists() {
            return None;
        }

        match fs::read_to_string(path) {
            Ok(json) => match serde_json::from_str::<Session>(&json) {
                Ok(session) => {
                    if let Err(reason) = validate_session_file_id(&session.id) {
                        warn!(
                            session_id = %session.id,
                            reason,
                            path = ?path,
                            "Rejected session file with invalid embedded id"
                        );
                        None
                    } else {
                        Some(session)
                    }
                }
                Err(e) => {
                    warn!(error = %e, path = ?path, "Failed to parse session file");
                    None
                }
            },
            Err(e) => {
                warn!(error = %e, path = ?path, "Failed to read session file");
                None
            }
        }
    }

    /// Get the handoff context from the last session.
    ///
    /// Returns `Ok(None)` when no handoff file exists. Other read failures
    /// are returned to the caller so diagnostics do not silently treat a
    /// broken handoff file as missing.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when `handoff.md` exists but cannot
    /// be read as a file.
    pub fn get_handoff_context(&self) -> std::io::Result<Option<String>> {
        let handoff_path = self.persist_dir.join("handoff.md");
        match fs::read_to_string(&handoff_path) {
            Ok(context) => Ok(Some(context)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// List all persisted sessions
    #[must_use]
    pub fn list_sessions(&self) -> Vec<Session> {
        let mut sessions = Vec::new();

        if let Ok(entries) = fs::read_dir(&self.persist_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "json") {
                    // Skip latest.json as it's a copy
                    if path.file_stem().is_some_and(|s| s == "latest") {
                        continue;
                    }
                    if let Some(session) = Self::load_session_from_path(&path) {
                        sessions.push(session);
                    }
                }
            }
        }

        // Sort by created_at descending
        sessions.sort_by_key(|s| std::cmp::Reverse(s.created_at));
        sessions
    }

    /// Clean up old sessions, keeping only the most recent N
    pub fn cleanup_old_sessions(&self, keep_count: usize) {
        let sessions = self.list_sessions();

        if sessions.len() <= keep_count {
            return;
        }

        for session in sessions.iter().skip(keep_count) {
            if let Err(reason) = validate_session_file_id(&session.id) {
                warn!(
                    session_id = %session.id,
                    reason,
                    "Skipping cleanup of session with invalid id"
                );
                continue;
            }
            let path = self.persist_dir.join(format!("{}.json", session.id));
            if let Err(e) = fs::remove_file(&path) {
                warn!(error = %e, path = ?path, "Failed to remove old session");
            } else {
                debug!(session_id = %session.id, "Removed old session");
            }
        }
    }

    /// Create a new initializer (or coding-continuation) session and return
    /// an [`OwnedSessionGuard`] whose `Drop` calls [`Self::end_session`].
    ///
    /// This closes the temporal-coupling hole identified in #356: if the
    /// caller panics or returns early without explicitly ending the session,
    /// the guard still attempts to persist on unwind.  Persist failures in
    /// `Drop` are logged via `tracing::error!` (there is no way to return
    /// from `Drop`); callers that need the failure surfaced should call
    /// [`OwnedSessionGuard::end`] explicitly and propagate the `Result`.
    pub fn create_session_guard(&mut self) -> OwnedSessionGuard<'_> {
        // Eagerly materialise the session so the guard's invariant ("a
        // session is active") holds for the lifetime of the borrow.
        self.get_or_create_session();
        OwnedSessionGuard {
            manager: Some(self),
            handoff_notes: None,
        }
    }
}

/// RAII guard that ensures the active session is persisted when dropped.
///
/// Obtain one from [`SessionManager::create_session_guard`].  When the
/// guard goes out of scope it calls [`SessionManager::end_session`] on the
/// borrowed manager; persist failures are logged at `ERROR` level because
/// `Drop` cannot return a `Result`.  Callers that need failure visibility
/// should consume the guard via [`Self::end`] instead.
///
/// See #356 for the temporal-coupling motivation.
#[must_use = "OwnedSessionGuard persists on Drop; bind it to a variable"]
pub struct OwnedSessionGuard<'m> {
    /// `Option` so [`Self::end`] can move the borrow out before `Drop` runs.
    manager: Option<&'m mut SessionManager>,
    /// Handoff notes recorded into the session on end.
    handoff_notes: Option<String>,
}

impl OwnedSessionGuard<'_> {
    /// Set handoff notes that will be applied when the guard ends the
    /// session (either explicitly via [`Self::end`] or implicitly on drop).
    pub fn set_handoff_notes(&mut self, notes: impl Into<String>) {
        self.handoff_notes = Some(notes.into());
    }

    /// Borrow the active session, if the guard still owns one.
    #[must_use]
    pub const fn session(&self) -> Option<&Session> {
        match self.manager.as_ref() {
            Some(m) => m.get_session(),
            None => None,
        }
    }

    /// Explicitly end the session, returning the persisted `Session` or an
    /// [`EndSessionError`].  After this call the guard's `Drop` is a no-op.
    ///
    /// # Errors
    ///
    /// Forwards any error returned by [`SessionManager::end_session`].
    ///
    pub fn end(mut self) -> Result<Session, EndSessionError> {
        let Some(manager) = self.manager.take() else {
            return Err(EndSessionError::NotFound);
        };
        manager.end_session(self.handoff_notes.as_deref())
    }
}

impl Drop for OwnedSessionGuard<'_> {
    fn drop(&mut self) {
        let Some(manager) = self.manager.take() else {
            // `end()` already consumed the manager; nothing to do.
            return;
        };
        match manager.end_session(self.handoff_notes.as_deref()) {
            Ok(_) | Err(EndSessionError::NotFound) => {}
            Err(EndSessionError::PersistFailed { source }) => {
                error!(
                    error = %source,
                    "OwnedSessionGuard: failed to persist session on drop",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn failed_turn_marker_preserves_user_prompt_and_balances_turn() {
        let mut messages = vec![serde_json::json!({
            "role": "user",
            "content": "please call the provider"
        })];

        append_failed_turn_message(&mut messages, "HTTP 503 upstream unavailable");

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "user");
        assert_eq!(messages[0]["content"], "please call the provider");
        assert_eq!(messages[1]["role"], "assistant");
        let marker = messages[1]["content"]
            .as_str()
            .expect("failed-turn marker content must be text");
        assert!(marker.contains("request failed before a model response was produced"));
        assert!(marker.contains("HTTP 503 upstream unavailable"));
    }

    #[test]
    fn failed_turn_marker_truncates_large_reasons_at_char_boundary() {
        let reason = format!("{}é", "a".repeat(FAILED_TURN_REASON_MAX_BYTES));
        let mut messages = Vec::new();

        append_failed_turn_message(&mut messages, &reason);

        let marker = messages[0]["content"]
            .as_str()
            .expect("failed-turn marker content must be text");
        assert!(marker.ends_with(&"a".repeat(FAILED_TURN_REASON_MAX_BYTES)));
        assert!(!marker.ends_with('é'));
    }

    #[test]
    fn test_new_initializer_session() {
        let session = Session::new_initializer();
        assert_eq!(session.mode, SessionMode::Initializer);
        assert!(session.parent_session_id.is_none());
        assert_eq!(session.request_count, 0);
    }

    #[test]
    fn test_new_coding_session() {
        let session = Session::new_coding("parent-123");
        assert_eq!(session.mode, SessionMode::Coding);
        assert_eq!(session.parent_session_id, Some("parent-123".to_string()));
    }

    #[test]
    fn set_current_mode_updates_active_session_without_replacing_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut manager = SessionManager::new(dir.path());
        let initial = manager.start_initializer().clone();

        let coding = manager.set_current_mode(SessionMode::Coding);

        assert_eq!(coding.id, initial.id);
        assert_eq!(coding.mode, SessionMode::Coding);

        let initializer = manager.set_current_mode(SessionMode::Initializer);

        assert_eq!(initializer.id, initial.id);
        assert_eq!(initializer.mode, SessionMode::Initializer);
        assert!(initializer.parent_session_id.is_none());
    }

    #[test]
    fn test_session_progress() {
        let mut session = Session::new_initializer();
        session.complete_task("Task 1");
        session.add_modified_file("src/main.rs");
        session.set_handoff_notes("Continue with task 2");

        assert_eq!(session.progress.completed_tasks.len(), 1);
        assert_eq!(session.progress.files_modified.len(), 1);
        assert!(!session.progress.handoff_notes.is_empty());
    }

    #[test]
    fn test_generate_handoff() {
        let mut session = Session::new_initializer();
        session.complete_task("Implemented feature X");
        session
            .progress
            .pending_tasks
            .push("Test feature X".to_string());
        session.set_handoff_notes("Feature X works but needs tests");

        let handoff = session.generate_handoff();
        assert!(handoff.contains("Implemented feature X"));
        assert!(handoff.contains("Test feature X"));
        assert!(handoff.contains("needs tests"));
    }

    #[test]
    fn test_session_manager_persistence() {
        let dir = TempDir::new().unwrap();
        let mut manager = SessionManager::new(dir.path().join("sessions"));

        // Create and end a session
        let session = manager.get_or_create_session().clone();
        assert_eq!(session.mode, SessionMode::Initializer);

        manager
            .end_session(Some("Test handoff notes"))
            .expect("end_session must succeed for active session");

        // Load it back
        let loaded = manager.load_session(&session.id);
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().id, session.id);
    }

    #[test]
    fn get_handoff_context_reports_missing_saved_and_unreadable_states() {
        let dir = TempDir::new().unwrap();
        let persist_dir = dir.path().join("sessions");
        let mut manager = SessionManager::new(&persist_dir);

        assert!(
            matches!(manager.get_handoff_context(), Ok(None)),
            "missing handoff file should not be an error"
        );

        manager.get_or_create_session();
        manager
            .end_session(Some("handoff notes"))
            .expect("end_session must write handoff");
        let handoff = manager
            .get_handoff_context()
            .expect("saved handoff should be readable")
            .expect("saved handoff should be present");
        assert!(
            handoff.contains("handoff notes"),
            "saved handoff should include explicit notes"
        );

        fs::remove_file(persist_dir.join("handoff.md")).expect("remove handoff file");
        fs::create_dir(persist_dir.join("handoff.md")).expect("create unreadable handoff path");
        let err = manager
            .get_handoff_context()
            .expect_err("directory handoff path must surface as a read error");
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "broken handoff path must not be collapsed into missing"
        );
    }

    #[test]
    fn load_session_rejects_path_traversal_id() {
        let dir = TempDir::new().unwrap();
        let persist_dir = dir.path().join("sessions");
        fs::create_dir_all(&persist_dir).unwrap();
        let outside_path = dir.path().join("outside.json");
        fs::write(
            &outside_path,
            serde_json::to_string(&Session::new_initializer()).unwrap(),
        )
        .unwrap();
        let manager = SessionManager::new(&persist_dir);

        let loaded = manager.load_session("../outside");

        assert!(loaded.is_none(), "path traversal id must be rejected");
    }

    #[test]
    fn persist_session_rejects_invalid_embedded_id_without_writing_outside_dir() {
        let dir = TempDir::new().unwrap();
        let persist_dir = dir.path().join("sessions");
        let mut manager = SessionManager::new(&persist_dir);
        manager.get_or_create_session();
        manager.get_session_mut().unwrap().id = "../outside".to_string();

        let err = manager
            .end_session(None)
            .expect_err("invalid in-memory id must fail persistence");

        assert!(
            matches!(err, EndSessionError::PersistFailed { .. }),
            "expected persist failure, got {err:?}"
        );
        assert!(
            !dir.path().join("outside.json").exists(),
            "invalid session id must not write outside the persist dir"
        );
    }

    #[test]
    fn cleanup_old_sessions_ignores_malicious_embedded_id() {
        let dir = TempDir::new().unwrap();
        let persist_dir = dir.path().join("sessions");
        fs::create_dir_all(&persist_dir).unwrap();
        let outside_path = dir.path().join("outside.json");
        fs::write(&outside_path, b"sentinel").unwrap();

        let mut malicious = Session::new_initializer();
        malicious.id = "../outside".to_string();
        fs::write(
            persist_dir.join("malicious.json"),
            serde_json::to_string(&malicious).unwrap(),
        )
        .unwrap();
        let manager = SessionManager::new(&persist_dir);

        manager.cleanup_old_sessions(0);

        assert_eq!(
            fs::read(&outside_path).unwrap(),
            b"sentinel",
            "cleanup must not remove paths derived from an embedded hostile id"
        );
    }

    fn staging_files_for(path: &Path) -> Vec<PathBuf> {
        let parent = path.parent().expect("path has parent");
        let prefix = path
            .file_name()
            .expect("path has file name")
            .to_string_lossy()
            .into_owned();
        fs::read_dir(parent)
            .expect("read parent")
            .flatten()
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
                    && candidate != path
            })
            .collect()
    }

    #[test]
    fn atomic_write_publishes_final_bytes_without_staging_debris() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("session.json");

        atomic_write(&path, br#"{"ok":true}"#).expect("atomic write succeeds");

        assert_eq!(
            fs::read(&path).expect("read final"),
            br#"{"ok":true}"#,
            "atomic_write must publish the exact payload"
        );
        assert!(
            staging_files_for(&path).is_empty(),
            "successful atomic_write must not leave staging files"
        );
    }

    #[test]
    fn atomic_write_cleans_staging_file_when_rename_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("session.json");
        fs::create_dir(&path).expect("target path is an existing directory");

        let _err = atomic_write(&path, b"payload").expect_err("rename over directory must fail");

        assert!(
            staging_files_for(&path).is_empty(),
            "failed atomic_write must clean its staging file"
        );
    }

    #[test]
    fn test_session_manager_coding_continuation() {
        let dir = TempDir::new().unwrap();
        let mut manager = SessionManager::new(dir.path().join("sessions"));

        // First session
        let first = manager.get_or_create_session().clone();
        manager
            .end_session(None)
            .expect("end_session must succeed for active session");

        // Second session should be coding mode
        let second = manager.get_or_create_session().clone();
        assert_eq!(second.mode, SessionMode::Coding);
        assert_eq!(second.parent_session_id, Some(first.id));
    }

    #[test]
    fn test_session_manager_has_task_manager() {
        let dir = TempDir::new().unwrap();
        let mut manager = SessionManager::new(dir.path().join("sessions"));
        // Verify we can access and use the task manager
        manager
            .task_manager
            .create_task("Test".to_string(), "Test task".to_string(), None);
        assert_eq!(manager.task_manager.list_tasks().len(), 1);
    }

    // ── Phase 2 spec-pinning tests (#552 / spec #537 B-session) ──────────────

    /// Spec — `TokenUsage::total()` is input + output (not cache tokens).
    #[test]
    fn token_usage_total_excludes_cache() {
        let u = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            cache_read_tokens: 200,
            cache_write_tokens: 300,
        };
        assert_eq!(u.total(), 150, "total() must be input + output only");
    }

    /// Spec — `TokenUsage::accumulate` sums all four fields independently.
    #[test]
    fn token_usage_accumulate_sums_all_fields() {
        let mut acc = TokenUsage {
            input_tokens: 10,
            output_tokens: 5,
            cache_read_tokens: 20,
            cache_write_tokens: 30,
        };
        let delta = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            cache_read_tokens: 200,
            cache_write_tokens: 300,
        };
        acc.accumulate(&delta);
        assert_eq!(acc.input_tokens, 110);
        assert_eq!(acc.output_tokens, 55);
        assert_eq!(acc.cache_read_tokens, 220);
        assert_eq!(acc.cache_write_tokens, 330);
    }

    /// Spec — `record_actual_usage` feeds into `cumulative_usage` and `total_tokens`.
    #[test]
    fn session_record_actual_usage_accumulates() {
        let mut session = Session::new_initializer();

        // Simulate a turn estimate first (required before actual usage)
        session.record_turn_estimate(1000, 100, 80, 20);

        let usage = TokenUsage {
            input_tokens: 500,
            output_tokens: 250,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        session.record_actual_usage(usage);

        assert_eq!(session.cumulative_usage.input_tokens, 500);
        assert_eq!(session.cumulative_usage.output_tokens, 250);
        // total_tokens() derives from cumulative_usage (crosslink #854):
        // input + output, no parallel state.
        assert_eq!(
            session.total_tokens(),
            750,
            "total_tokens() must derive input+output from cumulative_usage"
        );

        // Second turn
        session.record_turn_estimate(800, 90, 70, 20);
        session.record_actual_usage(TokenUsage {
            input_tokens: 300,
            output_tokens: 100,
            cache_read_tokens: 50,
            cache_write_tokens: 0,
        });
        assert_eq!(session.cumulative_usage.input_tokens, 800);
        assert_eq!(session.cumulative_usage.output_tokens, 350);
        assert_eq!(session.cumulative_usage.cache_read_tokens, 50);
        assert_eq!(session.total_tokens(), 1150);
    }

    /// Crosslink #854: a session persisted before the parallel
    /// `total_tokens` field was removed still carries the integer in
    /// its JSON. The deserialize-only escape hatch silently absorbs
    /// it; the derived `total_tokens()` then reflects the migrated
    /// `cumulative_usage` (which is zero for an unknown field — that's
    /// the documented trade-off: old persisted state loses the legacy
    /// approximate counter, but no future code can write to a field
    /// that drifts).
    ///
    /// To stay robust against unrelated `SessionProgress` shape
    /// changes, we round-trip a default session, then inject the
    /// legacy `total_tokens` into the serialized form and reload.
    #[test]
    fn legacy_total_tokens_in_persisted_json_is_absorbed() {
        let baseline = Session::new_initializer();
        let mut raw: serde_json::Value =
            serde_json::to_value(&baseline).expect("baseline must serialize");
        raw.as_object_mut()
            .unwrap()
            .insert("total_tokens".into(), serde_json::json!(9999));
        let session: Session = serde_json::from_value(raw).expect("legacy session JSON must parse");
        // Legacy field carried no information we can recover into
        // typed input/output, so total_tokens() is zero — but the
        // session loads, and the legacy figure is still inspectable
        // for diagnostic UIs.
        assert_eq!(session.total_tokens(), 0);
        assert_eq!(session.legacy_persisted_total_tokens(), Some(9999));
    }

    /// Spec — `record_turn_estimate` assigns monotonically increasing turn numbers.
    #[test]
    fn session_turn_numbers_monotonically_increasing() {
        let mut session = Session::new_initializer();
        let t1 = session.record_turn_estimate(100, 10, 8, 2);
        let t2 = session.record_turn_estimate(200, 20, 16, 4);
        let t3 = session.record_turn_estimate(300, 30, 24, 6);
        assert_eq!(t1, 1);
        assert_eq!(t2, 2);
        assert_eq!(t3, 3);
        assert_eq!(session.turn_metrics.len(), 3);
    }

    /// Spec — `get_session_context` returns initializer context for first session.
    #[test]
    fn session_context_initializer_mode() {
        let session = Session::new_initializer();
        let ctx = get_session_context(&session);
        assert!(
            ctx.contains("Initializer"),
            "initializer mode context must identify the agent role"
        );
    }

    /// Spec — `get_session_context` returns coding context including parent ID.
    #[test]
    fn session_context_coding_mode_includes_parent() {
        let session = Session::new_coding("parent-abc");
        let ctx = get_session_context(&session);
        assert!(
            ctx.contains("Coding") || ctx.contains("continuing"),
            "coding mode context must identify continuation"
        );
        assert!(
            ctx.contains("parent-abc"),
            "coding mode context must include parent session ID"
        );
    }

    /// Spec — `add_modified_file` is idempotent (no duplicates).
    #[test]
    fn add_modified_file_is_idempotent() {
        let mut session = Session::new_initializer();
        session.add_modified_file("src/main.rs");
        session.add_modified_file("src/main.rs");
        session.add_modified_file("src/main.rs");
        assert_eq!(
            session.progress.files_modified.len(),
            1,
            "duplicate file paths must not be added"
        );
    }

    /// Spec — `SessionManager::start_initializer` always creates an initializer
    /// session regardless of any persisted history.
    #[test]
    fn start_initializer_overrides_history() {
        let dir = TempDir::new().unwrap();
        let mut manager = SessionManager::new(dir.path().join("sessions"));

        // Create and persist a session so there IS history
        manager.get_or_create_session();
        manager
            .end_session(None)
            .expect("end_session must succeed for active session");

        // Force an initializer even though history exists
        let session = manager.start_initializer().clone();
        assert_eq!(
            session.mode,
            SessionMode::Initializer,
            "start_initializer must override history detection"
        );
        assert!(
            session.parent_session_id.is_none(),
            "forced initializer must have no parent"
        );
    }

    /// Spec — VDD context round-trips through store/take.
    #[test]
    fn vdd_observation_store_and_take() {
        let dir = TempDir::new().unwrap();
        let mut manager = SessionManager::new(dir.path().join("sessions"));

        assert!(
            manager.take_vdd_observation().is_none(),
            "initially no VDD observation"
        );

        manager.store_vdd_observation(crate::context::ContextItem::reference(
            "vdd.test",
            crate::context::ReferenceSource::Vdd,
            "vdd:test",
            "advisory: review tool calls",
            crate::context::ContextFreshness::Turn,
            700,
        ));
        let observation = manager.take_vdd_observation();
        assert_eq!(
            observation
                .as_ref()
                .map(crate::context::ContextItem::content),
            Some("advisory: review tool calls")
        );

        // take is destructive — second take returns None
        assert!(
            manager.take_vdd_observation().is_none(),
            "take_vdd_observation must be destructive"
        );
    }

    // -----------------------------------------------------------------------
    // #285 — Session.turn_metrics grows unbounded — memory leak in long sessions
    //
    // Forensic evidence: every API turn called `session.record_turn_estimate()`
    // which pushed a full `TurnMetrics` struct (11 fields, including
    // `Option<TokenUsage>`) onto `Session.turn_metrics: Vec<TurnMetrics>` with
    // no truncation.  For a 24-hour agent loop at 10 s/turn that is 8 640
    // entries.  `Session` derives `Clone` and is cloned at multiple call sites,
    // each clone duplicating the full history.  On `end_session` the entire vec
    // is serialised to JSON and fsynced, growing proportionally.
    //
    // Fix applied: `MAX_TURN_METRICS = 1_000` cap.  When the vec is at capacity
    // `record_turn_estimate` evicts the oldest entry (`remove(0)`) before
    // pushing the new one.  A separate `total_turns: u64` field tracks the true
    // cumulative turn count so `turn_number` stays monotonically increasing and
    // `cumulative_usage` is unaffected by eviction.
    // -----------------------------------------------------------------------

    /// #285: push 10 000 turns — `turn_metrics` vec must never exceed
    /// `MAX_TURN_METRICS` and `total_turns` must equal exactly 10 000.
    #[test]
    fn issue_285_turn_metrics_stays_bounded_under_push_pressure() {
        let mut session = Session::new_initializer();

        let pushes = MAX_TURN_METRICS * 10; // 10 000 turns
        for _ in 0..pushes {
            session.record_turn_estimate(1_000, 100, 80, 20);
        }

        assert_eq!(
            session.turn_metrics.len(),
            MAX_TURN_METRICS,
            "turn_metrics.len() must be capped at MAX_TURN_METRICS after {pushes} pushes",
        );
        assert_eq!(
            session.total_turns, pushes as u64,
            "total_turns must equal the total number of record_turn_estimate calls"
        );
    }

    /// #285: after eviction, `turn_number` in the remaining entries is still
    /// monotonically increasing (oldest entries were evicted, not shuffled).
    #[test]
    fn issue_285_evicted_turn_numbers_remain_monotonic() {
        let mut session = Session::new_initializer();

        // Push cap + 5 entries so eviction has definitely happened.
        let pushes = MAX_TURN_METRICS + 5;
        for _ in 0..pushes {
            session.record_turn_estimate(500, 50, 40, 10);
        }

        // The ring holds the most-recent MAX_TURN_METRICS entries.
        // Their turn_numbers must be strictly increasing.
        let nums: Vec<u64> = session.turn_metrics.iter().map(|t| t.turn_number).collect();
        for window in nums.windows(2) {
            assert!(
                window[0] < window[1],
                "turn_numbers must be strictly increasing after eviction: {window:?}"
            );
        }

        // The oldest retained entry's turn_number must be > the evicted count.
        let evicted = (pushes - MAX_TURN_METRICS) as u64;
        assert!(
            nums[0] > evicted,
            "first retained turn_number ({}) must be > evicted count ({})",
            nums[0],
            evicted
        );
    }

    /// #285: `cumulative_usage` accumulates across all turns including evicted ones —
    /// it must not be reset when the ring wraps.
    #[test]
    fn issue_285_cumulative_usage_unaffected_by_eviction() {
        let mut session = Session::new_initializer();

        // Push enough turns to trigger eviction, recording actual usage each time.
        let turns = MAX_TURN_METRICS + 50;
        for _ in 0..turns {
            session.record_turn_estimate(100, 10, 8, 2);
            session.record_actual_usage(crate::session::TokenUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            });
        }

        assert_eq!(
            session.cumulative_usage.input_tokens, turns as u64,
            "cumulative input_tokens must count all turns, not just retained ones"
        );
        assert_eq!(
            session.cumulative_usage.output_tokens, turns as u64,
            "cumulative output_tokens must count all turns, not just retained ones"
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // #356 — end_session error orchestration & RAII guard
    //
    // Pre-fix: end_session returned Option<Session>; persist failures were
    // swallowed via warn!() and the caller still received Some(session),
    // unable to distinguish "no session active" from "persist failed".
    //
    // Post-fix: returns Result<Session, EndSessionError> with distinct
    // NotFound / PersistFailed variants.  OwnedSessionGuard provides RAII
    // so panics no longer leak in-memory session state.
    // ──────────────────────────────────────────────────────────────────────

    /// Replace `path` (a directory) with a regular file so subsequent
    /// `fs::write` to anything under it fails with ENOTDIR.  Used to drive
    /// [`SessionManager::persist_session`] into the error branch.
    fn sabotage_persist_dir(path: &Path) {
        fs::remove_dir_all(path).expect("cleanup persist dir");
        fs::write(path, b"sabotage").expect("write sentinel file");
    }

    /// (1) `end_session` on a known/active session returns `Ok(session)`.
    #[test]
    fn end_session_happy_path_returns_ok() {
        let dir = TempDir::new().unwrap();
        let mut manager = SessionManager::new(dir.path().join("sessions"));

        let id = manager.get_or_create_session().id.clone();
        let result = manager.end_session(Some("ok"));
        let session = result.expect("happy path must be Ok");
        assert_eq!(session.id, id, "returned session must be the active one");
        assert_eq!(
            session.progress.handoff_notes, "ok",
            "handoff notes must be applied before persist"
        );
        assert!(
            manager.get_session().is_none(),
            "current_session must be cleared after end_session"
        );
    }

    /// (2) `end_session` with no active session returns `Err(NotFound)`,
    ///     not a silent `None`.  This is the central #356 contract change.
    #[test]
    fn end_session_unknown_returns_not_found() {
        let dir = TempDir::new().unwrap();
        let mut manager = SessionManager::new(dir.path().join("sessions"));

        // No get_or_create_session() — manager has no active session.
        let err = manager
            .end_session(None)
            .expect_err("end_session with no active session must be Err");
        assert!(
            matches!(err, EndSessionError::NotFound),
            "expected EndSessionError::NotFound, got {err:?}"
        );
    }

    #[test]
    fn owned_session_guard_end_without_manager_returns_not_found() {
        let guard = OwnedSessionGuard {
            manager: None,
            handoff_notes: None,
        };

        let err = guard
            .end()
            .expect_err("drained guard should return a typed error, not panic");
        assert!(
            matches!(err, EndSessionError::NotFound),
            "expected EndSessionError::NotFound, got {err:?}"
        );
    }

    #[test]
    fn owned_session_guard_session_returns_none_without_manager() {
        let guard = OwnedSessionGuard {
            manager: None,
            handoff_notes: None,
        };

        assert!(
            guard.session().is_none(),
            "drained guard must not panic when borrowing session"
        );
    }

    /// (3) `end_session` with a broken persist dir returns
    ///     `Err(PersistFailed { .. })` — failures are NOT swallowed.
    #[test]
    fn end_session_persist_failure_surfaces() {
        let dir = TempDir::new().unwrap();
        let persist_dir = dir.path().join("sessions");
        let mut manager = SessionManager::new(&persist_dir);

        manager.get_or_create_session();
        sabotage_persist_dir(&persist_dir);

        let err = manager
            .end_session(Some("will fail"))
            .expect_err("persist failure must surface as Err");
        assert!(
            matches!(err, EndSessionError::PersistFailed { .. }),
            "expected EndSessionError::PersistFailed, got {err:?}"
        );
        // The in-memory session has been consumed; the manager is back to
        // the "no current session" state.
        assert!(
            manager.get_session().is_none(),
            "current_session must be cleared even on persist failure",
        );
    }

    /// (4) `OwnedSessionGuard` `end_session`-on-`Drop` happy path persists.
    #[test]
    fn owned_session_guard_persists_on_drop() {
        let dir = TempDir::new().unwrap();
        let persist_dir = dir.path().join("sessions");
        let mut manager = SessionManager::new(&persist_dir);

        let session_id = {
            let mut guard = manager.create_session_guard();
            guard.set_handoff_notes("drop-persist");
            // Capture the id via the guard while the session is still
            // live (the guard's borrow of `manager` is exclusive).
            guard
                .session()
                .expect("guard must expose the active session")
                .id
                .clone()
        };
        // ^^ `guard` is dropped here; Drop must call end_session and persist.

        assert!(
            manager.get_session().is_none(),
            "guard Drop must clear current_session"
        );

        // The session file must now exist on disk.
        let session_path = persist_dir.join(format!("{session_id}.json"));
        assert!(
            session_path.exists(),
            "guard Drop must have persisted {session_path:?}"
        );

        // And `latest.json` should also be present, with handoff notes
        // applied.
        let latest = persist_dir.join("latest.json");
        let body = fs::read_to_string(&latest).expect("latest.json must exist");
        assert!(
            body.contains("drop-persist"),
            "handoff notes set on the guard must reach the persisted JSON"
        );
    }

    /// (5) `OwnedSessionGuard` `end_session`-on-`Drop` persist-failure logs
    ///     `error!` (captured via a tracing subscriber) — silent loss is
    ///     impossible.
    #[test]
    fn owned_session_guard_drop_logs_persist_failure() {
        use std::sync::{Arc, Mutex};
        use tracing::subscriber;
        use tracing_subscriber::fmt::MakeWriter;

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

        let captured = CapturedWriter::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .finish();

        subscriber::with_default(sub, || {
            let dir = TempDir::new().unwrap();
            let persist_dir = dir.path().join("sessions");
            let mut manager = SessionManager::new(&persist_dir);

            {
                let _guard = manager.create_session_guard();
                // Break the persist dir while the guard is live so Drop's
                // end_session hits PersistFailed.
                sabotage_persist_dir(&persist_dir);
            } // guard drops here

            assert!(
                manager.get_session().is_none(),
                "guard Drop must clear current_session even on failure"
            );
        });

        let log = captured.contents();
        assert!(
            log.contains("ERROR"),
            "Drop must emit an ERROR-level tracing event, got: {log}"
        );
        assert!(
            log.contains("failed to persist session on drop"),
            "Drop's error message must mention persist failure, got: {log}"
        );
    }

    // -----------------------------------------------------------------------
    // #458 — Session is `#[derive(Clone)]` and was deep-copied on every read.
    //
    // Fix landed: `SessionView<'a>` zero-copy wrapper + `Session::view()` +
    // `SessionManager::current_view()`.  The `Clone` derive is retained for
    // snapshot persistence and tests, but production read-paths now borrow
    // through a `SessionView<'_>`.
    //
    // The tests below assert:
    //   1. Multi-reader concurrency over the existing `Arc<RwLock<…>>`
    //      wrapping (see `ProxyState::session_manager`) — many readers can
    //      hold `SessionView`s simultaneously without cloning the session.
    //   2. A writer serialises correctly: while a write guard is held no
    //      reader makes progress; once released, readers see the mutation.
    //   3. `turn_metrics` tracking (#285) still works end-to-end when the
    //      session is accessed exclusively via `SessionView` — i.e. the
    //      view path observes the same monotonic turn numbers and bounded
    //      ring as the direct-field path.
    // -----------------------------------------------------------------------

    /// #458: a `SessionView` is a zero-copy borrow — multiple views can
    /// coexist over the same session without any clones, and all expose
    /// identical field values.
    #[test]
    fn issue_458_session_view_is_zero_copy_multi_borrow() {
        let mut session = Session::new_initializer();
        session.record_turn_estimate(123, 45, 6, 7);
        session.record_actual_usage(TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            cache_read_tokens: 10,
            cache_write_tokens: 5,
        });
        session.complete_task("alpha");
        session.complete_task("beta");

        let v1 = session.view();
        let v2 = session.view();
        let v3 = SessionView::new(&session);

        // All three views point at the same underlying session pointer.
        // (Comparing the raw pointer is the strongest possible assertion
        // that no clone happened — different addresses would mean a copy.)
        assert!(std::ptr::eq(v1.as_session(), v2.as_session()));
        assert!(std::ptr::eq(v1.as_session(), v3.as_session()));

        // Field accessors return borrows, never owned strings/vecs.
        assert_eq!(v1.id(), session.id);
        assert_eq!(v2.turn_metrics().len(), 1);
        assert_eq!(v3.progress().completed_tasks.len(), 2);
        assert_eq!(v1.cumulative_usage().input_tokens, 100);
        assert_eq!(v2.total_turns(), 1);
    }

    /// #458 (test 1 of mandated 3): Multi-reader concurrent access to a
    /// shared `Session` works under `Arc<RwLock<SessionManager>>` — the
    /// production wrapping used by `ProxyState`.  Many concurrent readers
    /// each take a `SessionView` without cloning the session, and all
    /// observe the same field values.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn issue_458_arc_rwlock_supports_concurrent_readers() {
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let dir = TempDir::new().unwrap();
        let mut manager = SessionManager::new(dir.path().join("sessions"));
        // Seed the session with non-trivial state so a clone would be
        // genuinely expensive — that's exactly what `view()` lets us avoid.
        manager.get_or_create_session();
        {
            let s = manager.get_session_mut().unwrap();
            for _ in 0..256 {
                s.record_turn_estimate(1_000, 100, 80, 20);
            }
            s.complete_task("seeded");
        }
        let expected_id = manager.get_session().unwrap().id.clone();
        let expected_turns = manager.get_session().unwrap().turn_metrics.len();

        let manager = Arc::new(RwLock::new(manager));

        // Spawn 16 concurrent readers; each opens a read guard, takes a
        // SessionView, asserts identity + turn count, then drops the
        // guard explicitly so the lock is released as early as possible.
        let mut handles = Vec::with_capacity(16);
        for _ in 0..16 {
            let mgr = Arc::clone(&manager);
            let expected_id = expected_id.clone();
            handles.push(tokio::spawn(async move {
                let guard = mgr.read().await;
                let (id_matches, turns, first_task) = {
                    let view = guard
                        .current_view()
                        .expect("active session must exist for readers");
                    (
                        view.id() == expected_id,
                        view.turn_metrics().len(),
                        view.progress().completed_tasks[0].clone(),
                    )
                };
                drop(guard);
                assert!(id_matches, "view.id() must match the seeded session id");
                assert_eq!(turns, expected_turns);
                assert_eq!(first_task, "seeded");
            }));
        }
        for h in handles {
            h.await.expect("reader task panicked");
        }
    }

    /// #458 (test 2 of mandated 3): Write access serialises correctly.
    /// A long-held write guard blocks new readers until released; once
    /// released, every subsequent reader observes the mutation via a
    /// `SessionView`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn issue_458_arc_rwlock_serialises_writes() {
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::sync::RwLock;

        let dir = TempDir::new().unwrap();
        let mut manager = SessionManager::new(dir.path().join("sessions"));
        manager.get_or_create_session();
        let manager = Arc::new(RwLock::new(manager));

        // Writer task: takes the write guard, sleeps briefly (simulating
        // a non-trivial mutation), records a turn estimate, and releases.
        let writer = {
            let mgr = Arc::clone(&manager);
            tokio::spawn(async move {
                let mut guard = mgr.write().await;
                tokio::time::sleep(Duration::from_millis(50)).await;
                {
                    let s = guard
                        .get_session_mut()
                        .expect("active session must exist for writer");
                    s.record_turn_estimate(42, 4, 3, 2);
                    s.complete_task("written-under-write-lock");
                }
                drop(guard);
            })
        };

        // Reader task: tries to read after the writer has had a head start.
        // The read guard must wait for the writer to finish; when it
        // succeeds, the mutation must be visible via `SessionView`.
        let reader = {
            let mgr = Arc::clone(&manager);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(5)).await;
                let guard = mgr.read().await;
                let (turns_len, total_turns, tasks_len, first_task) = {
                    let view = guard
                        .current_view()
                        .expect("active session must exist for reader");
                    (
                        view.turn_metrics().len(),
                        view.total_turns(),
                        view.progress().completed_tasks.len(),
                        view.progress().completed_tasks[0].clone(),
                    )
                };
                drop(guard);
                // If serialisation worked, the reader saw the writer's
                // mutation — exactly one turn was recorded.
                assert_eq!(turns_len, 1);
                assert_eq!(total_turns, 1);
                assert_eq!(tasks_len, 1);
                assert_eq!(first_task, "written-under-write-lock");
            })
        };

        writer.await.expect("writer task panicked");
        reader.await.expect("reader task panicked");
    }

    /// #458 (test 3 of mandated 3): Functional regression — `turn_metrics`
    /// tracking (the #285 invariant) still works end-to-end when callers
    /// read exclusively through `SessionView`.  The view path must
    /// observe the same monotonic turn numbers and the same
    /// `MAX_TURN_METRICS` ring as the direct-field path.
    #[test]
    fn issue_458_turn_metrics_tracking_visible_through_view() {
        let mut session = Session::new_initializer();

        // Push enough turns to (a) populate the ring and (b) trigger one
        // eviction, so the test exercises both the bounded-ring and the
        // monotonic-total-turns invariants.
        let pushes = MAX_TURN_METRICS + 7;
        for _ in 0..pushes {
            session.record_turn_estimate(1_000, 100, 80, 20);
            session.record_actual_usage(TokenUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            });
        }

        // Read everything we care about *only* via SessionView — no direct
        // field access from this point on.
        let view = session.view();

        // 1. Ring is bounded.
        assert_eq!(
            view.turn_metrics().len(),
            MAX_TURN_METRICS,
            "view must observe the same bounded ring as the direct-field path"
        );

        // 2. total_turns is monotonic and unaffected by eviction.
        assert_eq!(view.total_turns(), pushes as u64);

        // 3. Cumulative usage accumulated across *all* turns (including
        //    evicted ones).
        assert_eq!(view.cumulative_usage().input_tokens, pushes as u64);
        assert_eq!(view.cumulative_usage().output_tokens, pushes as u64);

        // 4. The retained ring is strictly monotonic in turn_number, and
        //    the first retained entry's turn_number is strictly greater
        //    than the evicted count — same #285 invariant, but witnessed
        //    through the view.
        let nums: Vec<u64> = view.turn_metrics().iter().map(|t| t.turn_number).collect();
        for window in nums.windows(2) {
            assert!(
                window[0] < window[1],
                "turn_numbers must be strictly increasing through SessionView"
            );
        }
        let evicted = (pushes - MAX_TURN_METRICS) as u64;
        assert!(nums[0] > evicted);
    }
}

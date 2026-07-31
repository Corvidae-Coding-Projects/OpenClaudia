//! Guardrails module for coding safety enforcement
//!
//! Provides three guardrail mechanisms:
//! - **Blast radius limiting**: constrains file/scope access per request
//! - **Diff size monitoring**: flags when changes exceed expected scope
//! - **Quality gates**: automated code quality checks
//!
//! Also provides language detection utilities shared with the VDD engine.

use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::{
    BlastRadiusConfig, DiffMonitorConfig, GuardrailAction, GuardrailMode, GuardrailsConfig,
    QualityGatesConfig,
};

// ==========================================================================
// Global guardrails instance — crosslink #749 fail-closed refactor
// ==========================================================================

/// Tri-state holder for the global guardrails engine.
///
/// Per the QA mandate in crosslink #749, we distinguish three states
/// explicitly so the security-boundary caller (`check_file_access`)
/// can fail-closed correctly:
///
/// * `Disabled` — no policy is loaded. Either `configure()` was never
///   called, or it ran with all guard families disabled (the project
///   default — see `BlastRadiusConfig::default().enabled == false`).
///   Either way the security boundary has nothing to enforce, so
///   `check_file_access` returns `Ok(())`. This is NOT the same as
///   "I tried to evaluate the policy and could not".
/// * `Enabled(engine)` — `configure()` produced a real engine; the
///   policy is delegated to it.
/// * `Poisoned` — a previous panic left the mutex in an unrecoverable
///   state. Returning success here would let the next write proceed
///   against an unknown rule set; we refuse instead by returning
///   `Err(POISON_ERR)`. This is the fail-closed contract that closes
///   the original bug.
enum GuardrailsState {
    Disabled,
    // Box keeps the variant size small (~16 B vs ~280 B inline). The
    // engine is constructed once at startup and dereferenced on every
    // tool dispatch, so the heap indirection is negligible compared to
    // the regex match it gates.
    Enabled(Box<GuardrailsEngine>),
    Poisoned,
}

static GUARDRAILS: std::sync::LazyLock<Mutex<GuardrailsState>> =
    std::sync::LazyLock::new(|| Mutex::new(GuardrailsState::Disabled));

/// Sentinel error string returned at every security boundary when the
/// guardrails mutex is found poisoned. The exact text is part of the
/// public contract — callers (and tests in #749) match against this
/// substring to distinguish poison-fail-closed from a rule-driven deny.
const POISON_ERR: &str = "guardrails poisoned — refusing access";

/// Lock the global guardrails mutex, transitioning the state to
/// `Poisoned` on OS-level poison. After this point every
/// security-boundary check returns `Err(POISON_ERR)` until the
/// process restarts.
fn lock_or_poison() -> std::sync::MutexGuard<'static, GuardrailsState> {
    match GUARDRAILS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!(
                "Guardrails mutex was poisoned by a previous panic;                  transitioning to fail-closed state"
            );
            let mut guard = poisoned.into_inner();
            *guard = GuardrailsState::Poisoned;
            guard
        }
    }
}

/// True iff a `GuardrailsConfig` has at least one *enabled* guard
/// family. We treat "configure called with everything disabled" the
/// same as "configure never called" — both leave no policy to enforce.
fn config_has_active_guards(config: &GuardrailsConfig) -> bool {
    let br = config.blast_radius.as_ref().is_some_and(|c| c.enabled);
    let dm = config.diff_monitor.as_ref().is_some_and(|c| c.enabled);
    let qg = config.quality_gates.as_ref().is_some_and(|c| c.enabled);
    br || dm || qg
}

/// Initialize the guardrails engine from config. Called once at startup.
///
/// If the state is poisoned, this function does NOT reconfigure — the
/// poisoned state is sticky on purpose so a panic during a write-policy
/// evaluation cannot be papered over by a subsequent `configure()`.
pub fn configure(config: &GuardrailsConfig) {
    // Build the new state OUTSIDE the lock. `GuardrailsEngine::from_config`
    // walks regex / glob compilation and emits structured `info!` events;
    // none of that needs the guardrails mutex held. Tightening the critical
    // section to the swap also lets concurrent `check_file_access` calls
    // make progress while a startup `configure` is mid-flight.
    let (new_state, log_msg) = if config_has_active_guards(config) {
        let engine = GuardrailsEngine::from_config(config);
        (
            GuardrailsState::Enabled(Box::new(engine)),
            "Guardrails engine configured",
        )
    } else {
        (
            GuardrailsState::Disabled,
            "Guardrails configured with no active guard families (Disabled)",
        )
    };

    {
        let mut guard = lock_or_poison();
        if matches!(*guard, GuardrailsState::Poisoned) {
            error!("Refusing to (re)configure guardrails: state is poisoned");
            return;
        }
        *guard = new_state;
        // Drop the guard at the end of this block (before the `info!`
        // below) so concurrent readers do not block while we format the
        // log line. Per `clippy::significant_drop_tightening`.
    }
    info!("{}", log_msg);
}

/// Check if a file path is allowed by blast radius rules.
///
/// # Errors
///
/// Returns an error string when the path is denied:
/// * by an explicit blast-radius rule in strict mode (from the engine), or
/// * because the guardrails mutex is poisoned (`POISON_ERR`).
///
/// `Disabled` returns `Ok(())` — no policy is loaded so there is
/// nothing to enforce. This is the QA-mandated separation between
/// "no policy" (allow) and "cannot evaluate policy" (deny).
///
/// This function is the security boundary for file-write dispatch and
/// MUST fail closed on poison. See crosslink #749.
pub fn check_file_access(path: &str) -> Result<(), String> {
    let guard = lock_or_poison();
    match &*guard {
        GuardrailsState::Enabled(engine) => engine.as_ref().check_file_access(path),
        GuardrailsState::Poisoned => {
            error!(
                path = path,
                "check_file_access: guardrails poisoned — denying"
            );
            Err(POISON_ERR.to_string())
        }
        GuardrailsState::Disabled => Ok(()),
    }
}

/// Record a file modification for diff monitoring.
/// Call after successful `write_file` or `edit_file`.
///
/// Non-security path: silently no-ops when disabled, logs an error
/// when the mutex is poisoned.
pub fn record_file_modification(path: &str, lines_added: u32, lines_removed: u32) {
    let guard = lock_or_poison();
    match &*guard {
        GuardrailsState::Enabled(engine) => {
            engine.record_modification(path, lines_added, lines_removed);
        }
        GuardrailsState::Poisoned => {
            error!(
                path = path,
                "record_file_modification: guardrails poisoned — skipping"
            );
        }
        GuardrailsState::Disabled => {}
    }
}

/// Check diff thresholds. Returns a warning if thresholds exceeded.
pub fn check_diff_thresholds() -> Option<DiffWarning> {
    let guard = lock_or_poison();
    match &*guard {
        GuardrailsState::Enabled(engine) => engine.as_ref().check_diff_thresholds(),
        GuardrailsState::Poisoned => {
            error!("check_diff_thresholds: guardrails poisoned — returning None");
            None
        }
        GuardrailsState::Disabled => None,
    }
}

/// Run quality gate checks. Returns results for each configured check.
pub fn run_quality_gates() -> Vec<QualityCheckResult> {
    let guard = lock_or_poison();
    match &*guard {
        GuardrailsState::Enabled(engine) => engine.as_ref().run_quality_gates(),
        GuardrailsState::Poisoned => {
            error!("run_quality_gates: guardrails poisoned — returning empty");
            Vec::new()
        }
        GuardrailsState::Disabled => Vec::new(),
    }
}

/// Reset per-turn tracking (blast radius file count).
pub fn reset_turn() {
    let guard = lock_or_poison();
    match &*guard {
        GuardrailsState::Enabled(engine) => engine.as_ref().reset_turn(),
        GuardrailsState::Poisoned => {
            error!("reset_turn: guardrails poisoned — skipping");
        }
        GuardrailsState::Disabled => {}
    }
}

/// Get current diff stats summary.
pub fn get_diff_summary() -> Option<DiffStats> {
    let guard = lock_or_poison();
    match &*guard {
        GuardrailsState::Enabled(engine) => engine.as_ref().get_diff_stats(),
        GuardrailsState::Poisoned => {
            error!("get_diff_summary: guardrails poisoned — returning None");
            None
        }
        GuardrailsState::Disabled => None,
    }
}

// ==========================================================================
// Test-only helpers for the global guardrails state.
// ==========================================================================

/// Replace the global guardrails state. Test-only. Used to drive
/// poisoned-state regression tests for crosslink #749.
#[cfg(test)]
fn set_state_for_test(new_state: GuardrailsState) {
    let mut guard = GUARDRAILS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = new_state;
}

/// Snapshot the discriminant of the current state. Test-only.
#[cfg(test)]
fn current_state_kind() -> &'static str {
    let guard = GUARDRAILS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match *guard {
        GuardrailsState::Disabled => "disabled",
        GuardrailsState::Enabled(_) => "enabled",
        GuardrailsState::Poisoned => "poisoned",
    }
}

// ==========================================================================
// Public Types
// ==========================================================================

/// Warning emitted when diff thresholds are exceeded
#[derive(Debug, Clone)]
pub struct DiffWarning {
    pub message: String,
    pub stats: DiffStats,
    pub action: GuardrailAction,
}

/// Accumulated diff statistics for the session
#[derive(Debug, Clone, Default)]
pub struct DiffStats {
    pub lines_added: u32,
    pub lines_removed: u32,
    pub lines_changed: u32,
    pub files_changed: u32,
    pub file_list: Vec<String>,
}

/// Result of running a single quality gate check
#[derive(Debug, Clone)]
pub struct QualityCheckResult {
    pub name: String,
    pub command: String,
    pub passed: bool,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub required: bool,
}

/// Outcome of dispatching a quality-gate command via
/// [`run_shell_command_sync`].
///
/// This typed enum replaces the pre-#395 tuple return
/// `(i32, String, String)` that conflated "the program ran and exited
/// non-zero" with "the program could not be located" and with "the
/// supervisor wrapper killed the child after a wall-clock timeout".
///
/// Callers MUST exhaustively match every variant so a future addition
/// (e.g. a `Cancelled` variant for a future caller-initiated abort)
/// surfaces as a compile-time error rather than a silent
/// `exit_code == -1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellResult {
    /// The child process started and exited with status `0`. Both
    /// stdout and stderr are captured verbatim — note that POSIX
    /// utilities frequently emit progress or warning text on stderr
    /// even on success (`make`, `cargo`, `git`), so callers MUST keep
    /// the stderr payload for forensics.
    Success { stdout: String, stderr: String },
    /// The child process started and exited with a non-zero status
    /// code (or was killed by a signal — see `code == -1`). Stdout and
    /// stderr are still captured so the caller can surface the failure
    /// diagnostic to the user.
    ExitFailed {
        code: i32,
        stdout: String,
        stderr: String,
    },
    /// The program named by the first argv token could not be located
    /// on `PATH` (or at the explicit absolute path given). On
    /// pre-#395 code this collapsed to `(-1, "", "Failed to execute:
    /// No such file or directory")` and the caller had to grep the
    /// stderr string to distinguish it from a real exit-1.
    ///
    /// `tried` is the list of program names the runner attempted —
    /// for argv-direct exec this is a single entry, but a future
    /// shell-fallback path may list `/bin/sh`, `bash`, etc.
    ShellMissing { tried: Vec<String> },
    /// The child process exceeded the wall-clock timeout configured on
    /// the runner. The child has been killed and reaped; any partial
    /// stdout/stderr is discarded.
    Timeout,
}

// ==========================================================================
// GuardrailsEngine
// ==========================================================================

struct GuardrailsEngine {
    blast_radius: Option<BlastRadiusGuard>,
    diff_monitor: Option<DiffMonitor>,
    quality_gates: Option<QualityGateRunner>,
}

impl GuardrailsEngine {
    fn from_config(config: &GuardrailsConfig) -> Self {
        let blast_radius = config.blast_radius.as_ref().filter(|c| c.enabled).map(|c| {
            info!(
                mode = %c.mode,
                allowed = c.allowed_paths.len(),
                denied = c.denied_paths.len(),
                max_files = c.max_files_per_turn,
                "Blast radius guard enabled"
            );
            BlastRadiusGuard::new(c.clone())
        });

        let diff_monitor = config.diff_monitor.as_ref().filter(|c| c.enabled).map(|c| {
            info!(
                max_lines = c.max_lines_changed,
                max_files = c.max_files_changed,
                action = %c.action,
                "Diff monitor enabled"
            );
            DiffMonitor::new(c.clone())
        });

        let quality_gates = config
            .quality_gates
            .as_ref()
            .filter(|c| c.enabled)
            .map(|c| {
                info!(
                    checks = c.checks.len(),
                    run_after = %c.run_after,
                    "Quality gates enabled"
                );
                QualityGateRunner::new(c.clone())
            });

        Self {
            blast_radius,
            diff_monitor,
            quality_gates,
        }
    }

    fn check_file_access(&self, path: &str) -> Result<(), String> {
        if let Some(br) = &self.blast_radius {
            br.check_path(path)?;
            br.record_access(path)?;
        }
        Ok(())
    }

    fn record_modification(&self, path: &str, lines_added: u32, lines_removed: u32) {
        if let Some(dm) = &self.diff_monitor {
            dm.record(path, lines_added, lines_removed);
        }
    }

    fn check_diff_thresholds(&self) -> Option<DiffWarning> {
        self.diff_monitor
            .as_ref()
            .and_then(DiffMonitor::check_thresholds)
    }

    fn run_quality_gates(&self) -> Vec<QualityCheckResult> {
        self.quality_gates
            .as_ref()
            .map(QualityGateRunner::run)
            .unwrap_or_default()
    }

    fn reset_turn(&self) {
        if let Some(br) = &self.blast_radius {
            br.reset_turn();
        }
    }

    fn get_diff_stats(&self) -> Option<DiffStats> {
        self.diff_monitor.as_ref().map(DiffMonitor::get_stats)
    }
}

// ==========================================================================
// Blast Radius Guard
// ==========================================================================

struct BlastRadiusGuard {
    config: BlastRadiusConfig,
    allowed_patterns: Vec<Regex>,
    denied_patterns: Vec<Regex>,
    files_this_turn: Mutex<HashSet<String>>,
}

impl BlastRadiusGuard {
    fn new(config: BlastRadiusConfig) -> Self {
        let allowed_patterns = config
            .allowed_paths
            .iter()
            .filter_map(|p| {
                glob_to_regex(p)
                    .map_err(|e| warn!("Invalid allowed glob '{}': {}", p, e))
                    .ok()
            })
            .collect();

        let denied_patterns = config
            .denied_paths
            .iter()
            .filter_map(|p| {
                glob_to_regex(p)
                    .map_err(|e| warn!("Invalid denied glob '{}': {}", p, e))
                    .ok()
            })
            .collect();

        Self {
            config,
            allowed_patterns,
            denied_patterns,
            files_this_turn: Mutex::new(HashSet::new()),
        }
    }

    fn files_guard(
        &self,
        operation: &'static str,
    ) -> Result<MutexGuard<'_, HashSet<String>>, String> {
        self.files_this_turn.lock().map_err(|err| {
            error!(operation, error = %err, "Blast radius file tracker lock poisoned");
            format!("Blast radius: file access tracker lock poisoned: {err}")
        })
    }

    fn check_path(&self, path: &str) -> Result<(), String> {
        let normalized = normalize_path(path);

        // Denied paths take priority
        for pattern in &self.denied_patterns {
            if pattern.is_match(&normalized) {
                let msg = format!("Blast radius: path '{path}' matches deny list pattern");
                return match self.config.mode {
                    GuardrailMode::Strict => {
                        warn!("{} (BLOCKED)", msg);
                        Err(msg)
                    }
                    GuardrailMode::Advisory => {
                        warn!("{} (advisory)", msg);
                        Ok(())
                    }
                };
            }
        }

        // If allowed_paths configured, path must match at least one
        if !self.allowed_patterns.is_empty() {
            let allowed = self
                .allowed_patterns
                .iter()
                .any(|p| p.is_match(&normalized));
            if !allowed {
                let msg = format!("Blast radius: path '{path}' not in allowed list");
                return match self.config.mode {
                    GuardrailMode::Strict => {
                        warn!("{} (BLOCKED)", msg);
                        Err(msg)
                    }
                    GuardrailMode::Advisory => {
                        warn!("{} (advisory)", msg);
                        Ok(())
                    }
                };
            }
        }

        Ok(())
    }

    fn record_access(&self, path: &str) -> Result<(), String> {
        if self.config.max_files_per_turn == 0 {
            return Ok(());
        }

        let normalized = normalize_path(path);
        let mut files = match self.files_guard("record_access") {
            Ok(files) => files,
            Err(msg) => {
                return match self.config.mode {
                    GuardrailMode::Strict => {
                        warn!("{} (BLOCKED)", msg);
                        Err(msg)
                    }
                    GuardrailMode::Advisory => {
                        warn!("{} (advisory)", msg);
                        Ok(())
                    }
                };
            }
        };
        files.insert(normalized);
        // Crosslink #840: previously `u32::try_from(files.len()).unwrap_or(u32::MAX)`
        // silently saturated when `files.len() > u32::MAX`. The comparison
        // against `max_files_per_turn` (also `u32`) would still trigger
        // — but a single combined "exceeded max" message can't tell an
        // operator whether the cap was breached by a representable count
        // (the normal case) or by a count so absurd it required pinning
        // to `u32::MAX` (a likely bug or attack signal). Surface the
        // overflow distinctly so monitoring dashboards can flag it.
        let count = files.len();
        drop(files);
        let cap = self.config.max_files_per_turn;
        let overflowed = u32::try_from(count).is_err();
        let breached = overflowed || u32::try_from(count).is_ok_and(|n| n > cap);

        if breached {
            let msg = if overflowed {
                format!(
                    "Blast radius: file count {count} overflowed u32 \
                     (cap {cap}/turn) — likely a bug or attack signal"
                )
            } else {
                format!("Blast radius: exceeded max files per turn ({count}/{cap})")
            };
            return match self.config.mode {
                GuardrailMode::Strict => {
                    warn!("{} (BLOCKED)", msg);
                    Err(msg)
                }
                GuardrailMode::Advisory => {
                    warn!("{} (advisory)", msg);
                    Ok(())
                }
            };
        }
        Ok(())
    }

    fn reset_turn(&self) {
        if let Ok(mut files) = self.files_guard("reset_turn") {
            files.clear();
        }
    }
}

// ==========================================================================
// Diff Monitor
// ==========================================================================

struct DiffMonitor {
    config: DiffMonitorConfig,
    stats: Mutex<DiffStatsInternal>,
}

struct DiffStatsInternal {
    lines_added: u32,
    lines_removed: u32,
    files: HashSet<String>,
}

impl DiffMonitor {
    fn new(config: DiffMonitorConfig) -> Self {
        Self {
            config,
            stats: Mutex::new(DiffStatsInternal {
                lines_added: 0,
                lines_removed: 0,
                files: HashSet::new(),
            }),
        }
    }

    fn stats_guard(&self, operation: &'static str) -> Option<MutexGuard<'_, DiffStatsInternal>> {
        match self.stats.lock() {
            Ok(guard) => Some(guard),
            Err(err) => {
                error!(operation, error = %err, "Diff monitor stats lock poisoned");
                None
            }
        }
    }

    fn record(&self, path: &str, lines_added: u32, lines_removed: u32) {
        if let Some(mut stats) = self.stats_guard("record") {
            stats.lines_added += lines_added;
            stats.lines_removed += lines_removed;
            stats.files.insert(normalize_path(path));
            debug!(
                path = path,
                added = lines_added,
                removed = lines_removed,
                total_files = stats.files.len(),
                "Diff monitor: recorded modification"
            );
        }
    }

    fn check_thresholds(&self) -> Option<DiffWarning> {
        let stats = self.stats_guard("check_thresholds")?;
        let total_lines = stats.lines_added + stats.lines_removed;
        let total_files = u32::try_from(stats.files.len()).unwrap_or(u32::MAX);

        let mut warnings = Vec::new();

        if self.config.max_lines_changed > 0 && total_lines > self.config.max_lines_changed {
            warnings.push(format!(
                "lines changed {}/{}",
                total_lines, self.config.max_lines_changed
            ));
        }

        if self.config.max_files_changed > 0 && total_files > self.config.max_files_changed {
            warnings.push(format!(
                "files changed {}/{}",
                total_files, self.config.max_files_changed
            ));
        }

        if warnings.is_empty() {
            return None;
        }

        let message = format!("Diff size threshold exceeded: {}", warnings.join(", "));
        warn!("{}", message);

        Some(DiffWarning {
            message,
            stats: DiffStats {
                lines_added: stats.lines_added,
                lines_removed: stats.lines_removed,
                lines_changed: total_lines,
                files_changed: total_files,
                file_list: stats.files.iter().cloned().collect(),
            },
            action: self.config.action.clone(),
        })
    }

    fn get_stats(&self) -> DiffStats {
        let Some(stats) = self.stats_guard("get_stats") else {
            return DiffStats::default();
        };
        DiffStats {
            lines_added: stats.lines_added,
            lines_removed: stats.lines_removed,
            lines_changed: stats.lines_added + stats.lines_removed,
            files_changed: u32::try_from(stats.files.len()).unwrap_or(u32::MAX),
            file_list: stats.files.iter().cloned().collect(),
        }
    }
}

// ==========================================================================
// Quality Gate Runner
// ==========================================================================

struct QualityGateRunner {
    config: QualityGatesConfig,
}

impl QualityGateRunner {
    const fn new(config: QualityGatesConfig) -> Self {
        Self { config }
    }

    fn run(&self) -> Vec<QualityCheckResult> {
        let mut results = Vec::new();

        for check in &self.config.checks {
            info!(name = %check.name, "Running quality gate");

            let outcome = run_shell_command_sync(&check.command, self.config.timeout_seconds);

            // Translate the typed enum into the (passed, exit_code,
            // stdout, stderr) shape that `QualityCheckResult` still
            // exposes to downstream callers. Every variant is handled
            // explicitly so a future addition forces a recompile.
            let (passed, exit_code, stdout, stderr) = match outcome {
                ShellResult::Success { stdout, stderr } => (true, 0, stdout, stderr),
                ShellResult::ExitFailed {
                    code,
                    stdout,
                    stderr,
                } => (false, code, stdout, stderr),
                ShellResult::ShellMissing { tried } => (
                    false,
                    -1,
                    String::new(),
                    format!("Program not found on PATH: tried {tried:?}"),
                ),
                ShellResult::Timeout => (
                    false,
                    -1,
                    String::new(),
                    format!(
                        "Quality gate timed out after {}s (wall-clock supervisor killed child)",
                        self.config.timeout_seconds
                    ),
                ),
            };

            if !passed && check.required {
                warn!(name = %check.name, exit_code, "Required quality gate FAILED");
            } else if passed {
                debug!(name = %check.name, "Quality gate passed");
            }

            results.push(QualityCheckResult {
                name: check.name.clone(),
                command: check.command.clone(),
                passed,
                exit_code,
                stdout,
                stderr,
                required: check.required,
            });
        }

        results
    }
}

/// Run a quality-gate command synchronously and return a typed
/// [`ShellResult`].
///
/// # Security
///
/// The `command` string is parsed with POSIX `shlex` into argv tokens
/// and executed via `tokio::process::Command::new(argv[0])
/// .args(&argv[1..])` — **no shell is invoked**. Pre-#700 this
/// function fed `format!("timeout {N} {cmd}")` to `bash -c`, allowing
/// any quality-gate author (or anyone who could influence the
/// config-loaded `QualityCheck.command` field) to inject arbitrary
/// shell metacharacters (`$(...)`, `` ` ` ``, `;`, `&&`, `|`,
/// redirections, env-var expansion, etc.). See crosslink #700.
///
/// Pipelines, redirections, and `&&`/`||` are therefore **not
/// supported** in this entry point; quality-gate authors that need
/// them must compose subprocess invocations at the Rust level or split
/// the pipeline into separate checks.
///
/// # Timeout strategy (crosslink #395)
///
/// Pre-#395 this function prepended the GNU `timeout(1)` coreutils
/// binary as an argv prefix on Unix. That binary **does not exist on
/// macOS by default** (it ships only with GNU coreutils, typically as
/// `gtimeout` on macOS via Homebrew), and is absent on minimal Alpine
/// containers without the `coreutils` package. Every quality-gate run
/// on such systems silently failed with `command not found` and the
/// caller could not distinguish that from a real exit-1.
///
/// We now supervise the child entirely in-process via
/// `tokio::time::timeout` on `tokio::process::Command::wait_with_output`.
/// That works identically on macOS, Linux, Alpine, and Windows, with no
/// dependency on any external coreutils binary. When the wall-clock
/// expires the child is killed via `Child::kill()` and reaped before we
/// return [`ShellResult::Timeout`].
///
/// `timeout_seconds == 0` disables the wall-clock supervisor entirely.
///
/// # Sync-wrapper strategy
///
/// The function exposes a synchronous signature because its sole
/// caller — [`QualityGateRunner::run`] — is invoked from sync code
/// paths in `pipeline.rs` and `cli/chat_repl.rs`. We use
/// `tokio::runtime::Handle::try_current()` to detect whether we are
/// already inside a Tokio runtime:
///
/// * Inside a multi-thread runtime: `block_in_place` + `Handle::block_on`
///   is safe (it parks the current worker thread without blocking the
///   reactor).
/// * Inside a current-thread runtime: `block_on` from inside would
///   deadlock the reactor; we therefore spawn the future onto a
///   dedicated short-lived current-thread runtime in a helper thread
///   and join it.
/// * Outside any runtime: build a one-shot current-thread runtime and
///   `block_on` directly.
///
/// # Audit logging
///
/// Every invocation emits a structured `info!` event containing the
/// full argv (program + arguments) and the wall-clock timeout before
/// the process is spawned. Tokenisation failures, spawn errors, and
/// timeouts are logged at `warn!` / `error!` level.
fn run_shell_command_sync(command: &str, timeout_seconds: u64) -> ShellResult {
    let cwd = std::env::current_dir().unwrap_or_else(|e| {
        warn!(
            "Failed to get current directory ({}), falling back to \".\"",
            e
        );
        std::path::PathBuf::from(".")
    });

    // POSIX-tokenise the user-supplied command into an argv. No shell
    // is ever invoked, so $(...), `...`, ;, &&, |, > etc. survive as
    // inert string arguments to the program.
    let argv: Vec<String> = match shlex::split(command) {
        Some(t) if !t.is_empty() => t,
        Some(_) => {
            error!(command = %command, "Quality gate: empty command after tokenisation");
            return ShellResult::ExitFailed {
                code: -1,
                stdout: String::new(),
                stderr: "Empty command".to_string(),
            };
        }
        None => {
            error!(
                command = %command,
                "Quality gate: could not tokenise command (unbalanced quotes?)"
            );
            return ShellResult::ExitFailed {
                code: -1,
                stdout: String::new(),
                stderr: "Could not parse command (unbalanced quotes or unsupported escape)"
                    .to_string(),
            };
        }
    };

    let Some((program, cmd_args)) = argv.split_first() else {
        // Unreachable: shlex returned a non-empty Vec above. Defend
        // against future refactors that drop the empty-check.
        return ShellResult::ExitFailed {
            code: -1,
            stdout: String::new(),
            stderr: "Empty command".to_string(),
        };
    };

    info!(
        program = %program,
        args = ?cmd_args,
        timeout_seconds = timeout_seconds,
        cwd = %cwd.display(),
        "Quality gate: spawning command (argv-level, no shell, in-process timeout)"
    );

    let program_owned: String = program.clone();
    let args_owned: Vec<String> = cmd_args.to_vec();
    let cwd_owned = cwd;

    // Build the async future once; the sync wrapper below decides how
    // to drive it depending on the ambient runtime context.
    let fut = run_shell_command_async(program_owned, args_owned, cwd_owned, timeout_seconds);

    match drive_future_sync(fut) {
        Ok(result) => result,
        Err(error) => {
            error!(error = %error, "Quality gate: async runtime dispatch failed");
            ShellResult::ExitFailed {
                code: -1,
                stdout: String::new(),
                stderr: error,
            }
        }
    }
}

/// Async core of [`run_shell_command_sync`] — extracted so the sync
/// wrapper stays under the function-length lint while keeping the
/// argv-direct exec, `kill_on_drop(true)`-backed timeout, and structured
/// logging from crosslink #395 in one cohesive place.
async fn run_shell_command_async(
    program_owned: String,
    args_owned: Vec<String>,
    cwd_owned: std::path::PathBuf,
    timeout_seconds: u64,
) -> ShellResult {
    // Quality gates execute project-controlled build files, compiler plugins,
    // and test binaries. Running argv directly prevents shell injection but
    // does not prevent those programs from accessing the host, so use the
    // same OS boundary as the model-facing Bash tool.
    let Ok(resolved_program) = which::which(&program_owned) else {
        return ShellResult::ShellMissing {
            tried: vec![program_owned],
        };
    };
    let sandbox_args: Vec<std::ffi::OsString> =
        args_owned.iter().map(std::ffi::OsString::from).collect();
    let sandboxed = match crate::tools::sandboxed_process_command(
        crate::tools::SandboxProfile::QualityGate,
        resolved_program.as_os_str(),
        &sandbox_args,
        &cwd_owned,
    ) {
        Ok(command) => command,
        Err(error) => {
            error!(program = %program_owned, %error, "Quality gate: sandbox setup failed");
            return ShellResult::ExitFailed {
                code: -1,
                stdout: String::new(),
                stderr: error,
            };
        }
    };
    let effective_timeout = Duration::from_secs(if timeout_seconds == 0 {
        300
    } else {
        timeout_seconds
    });
    let program_for_worker = program_owned.clone();
    let result = match tokio::task::spawn_blocking(move || {
        crate::tools::run_prepared_sandboxed_with_timeout(
            sandboxed,
            &program_for_worker,
            effective_timeout,
        )
    })
    .await
    {
        Ok(Ok(output)) => Some(output),
        Ok(Err(crate::tools::CommandError::TimedOut { .. })) => {
            warn!(
                program = %program_owned,
                timeout_seconds = effective_timeout.as_secs(),
                "Quality gate: command timed out; sandbox process tree terminated"
            );
            return ShellResult::Timeout;
        }
        Ok(Err(error)) => {
            error!(%error, "Quality gate: sandboxed command failed");
            None
        }
        Err(error) => {
            error!(%error, "Quality gate: blocking worker failed");
            None
        }
    };

    match result {
        Some(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            if output.status.success() {
                ShellResult::Success { stdout, stderr }
            } else {
                ShellResult::ExitFailed {
                    code: output.status.code().unwrap_or(-1),
                    stdout,
                    stderr,
                }
            }
        }
        None => ShellResult::ExitFailed {
            code: -1,
            stdout: String::new(),
            stderr: "wait_with_output failed".to_string(),
        },
    }
}

/// Drive an async future to completion from a synchronous caller,
/// regardless of whether a Tokio runtime is already active on the
/// current thread.
///
/// The discipline is the same as in `subagent::run_subagent_sync` and
/// is required because the guardrails caller is sync but the
/// underlying I/O (`tokio::process::Command::spawn`,
/// `tokio::time::timeout`) is async.
///
/// * Multi-thread runtime in scope: `block_in_place` + `Handle::block_on`.
/// * Current-thread runtime in scope: spawning a thread + its own
///   one-shot runtime, then joining — calling `Handle::block_on` on a
///   current-thread runtime from within itself would deadlock.
/// * No runtime in scope: build a one-shot current-thread runtime and
///   `block_on` directly.
fn build_quality_gate_runtime(context: &'static str) -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("guardrails: failed to build {context} tokio runtime: {e}"))
}

fn drive_future_sync<F, T>(fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                Ok(tokio::task::block_in_place(|| handle.block_on(fut)))
            }
            // Current-thread or any other flavour: cannot block_on
            // from inside without deadlocking the single worker. Offload
            // to a dedicated short-lived runtime in a helper thread.
            _ => std::thread::spawn(move || {
                let rt = build_quality_gate_runtime("helper")?;
                Ok(rt.block_on(fut))
            })
            .join()
            .map_err(|_| {
                "guardrails: helper thread panicked while driving quality-gate command".to_string()
            })?,
        };
    }
    // No ambient runtime — build one just for this call.
    let rt = build_quality_gate_runtime("quality-gate")?;
    Ok(rt.block_on(fut))
}

// ==========================================================================
// Language Detection (shared with VDD)
// ==========================================================================

/// Detected project language
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProjectLanguage {
    Rust,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Java,
    Kotlin,
    Ruby,
    PHP,
    CSharp,
    Cpp,
    C,
}

impl std::fmt::Display for ProjectLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rust => write!(f, "Rust"),
            Self::JavaScript => write!(f, "JavaScript"),
            Self::TypeScript => write!(f, "TypeScript"),
            Self::Python => write!(f, "Python"),
            Self::Go => write!(f, "Go"),
            Self::Java => write!(f, "Java"),
            Self::Kotlin => write!(f, "Kotlin"),
            Self::Ruby => write!(f, "Ruby"),
            Self::PHP => write!(f, "PHP"),
            Self::CSharp => write!(f, "C#"),
            Self::Cpp => write!(f, "C++"),
            Self::C => write!(f, "C"),
        }
    }
}

/// Detect project languages by checking for marker files in the working directory.
#[must_use]
pub fn detect_project_languages() -> Vec<ProjectLanguage> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    detect_languages_in_dir(&cwd)
}

/// Detect languages in a specific directory.
pub fn detect_languages_in_dir(dir: &Path) -> Vec<ProjectLanguage> {
    let mut languages = Vec::new();

    let markers: &[(ProjectLanguage, &[&str])] = &[
        (ProjectLanguage::Rust, &["Cargo.toml"]),
        (ProjectLanguage::TypeScript, &["tsconfig.json"]),
        (ProjectLanguage::JavaScript, &["package.json"]),
        (
            ProjectLanguage::Python,
            &["pyproject.toml", "setup.py", "requirements.txt", "Pipfile"],
        ),
        (ProjectLanguage::Go, &["go.mod"]),
        (
            ProjectLanguage::Java,
            &["pom.xml", "build.gradle", "build.gradle.kts"],
        ),
        (ProjectLanguage::Ruby, &["Gemfile"]),
        (ProjectLanguage::PHP, &["composer.json"]),
        (ProjectLanguage::Cpp, &["CMakeLists.txt"]),
    ];

    for (lang, files) in markers {
        for file in *files {
            if dir.join(file).exists() {
                if !languages.contains(lang) {
                    languages.push(lang.clone());
                }
                break;
            }
        }
    }

    // TypeScript detection: if we found package.json but also have tsconfig,
    // the TypeScript entry was already added by the marker check above.
    // If we found package.json but NOT tsconfig, it's JavaScript.
    // Remove JavaScript if TypeScript is already detected (tsconfig present).
    if languages.contains(&ProjectLanguage::TypeScript)
        && languages.contains(&ProjectLanguage::JavaScript)
    {
        languages.retain(|l| l != &ProjectLanguage::JavaScript);
    }

    // Kotlin: if build.gradle.kts exists, add Kotlin alongside Java
    if dir.join("build.gradle.kts").exists() && !languages.contains(&ProjectLanguage::Kotlin) {
        languages.push(ProjectLanguage::Kotlin);
    }

    // C# detection: .sln or .csproj files
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let name = entry.file_name().to_string_lossy().to_string();
            if ext.eq_ignore_ascii_case("sln")
                || name.eq_ignore_ascii_case(".csproj")
                || ext.eq_ignore_ascii_case("csproj")
            {
                if !languages.contains(&ProjectLanguage::CSharp) {
                    languages.push(ProjectLanguage::CSharp);
                }
                break;
            }
        }
    }

    // C detection: Makefile with .c/.h files but no CMakeLists
    if languages.is_empty() && dir.join("Makefile").exists() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext.eq_ignore_ascii_case("c") || ext.eq_ignore_ascii_case("h") {
                    if !languages.contains(&ProjectLanguage::C) {
                        languages.push(ProjectLanguage::C);
                    }
                    break;
                }
                if ext.eq_ignore_ascii_case("cpp")
                    || ext.eq_ignore_ascii_case("cc")
                    || ext.eq_ignore_ascii_case("hpp")
                {
                    if !languages.contains(&ProjectLanguage::Cpp) {
                        languages.push(ProjectLanguage::Cpp);
                    }
                    break;
                }
            }
        }
    }

    debug!("Detected project languages: {:?}", languages);
    languages
}

/// Get default static analysis commands for a detected language.
/// Returns Vec<(name, command)>.
#[must_use]
pub fn get_default_analysis_commands(lang: &ProjectLanguage) -> Vec<(String, String)> {
    match lang {
        ProjectLanguage::Rust => vec![
            (
                "clippy".to_string(),
                "cargo clippy -- -D warnings".to_string(),
            ),
            ("test".to_string(), "cargo test --no-fail-fast".to_string()),
        ],
        ProjectLanguage::JavaScript => {
            vec![("eslint".to_string(), "npx eslint .".to_string())]
        }
        ProjectLanguage::TypeScript => {
            let mut cmds = vec![("tsc".to_string(), "npx tsc --noEmit".to_string())];
            cmds.push(("eslint".to_string(), "npx eslint .".to_string()));
            cmds
        }
        ProjectLanguage::Python => {
            vec![
                ("ruff".to_string(), "ruff check .".to_string()),
                ("pytest".to_string(), "pytest --tb=short -q".to_string()),
            ]
        }
        ProjectLanguage::Go => vec![
            ("vet".to_string(), "go vet ./...".to_string()),
            ("test".to_string(), "go test ./...".to_string()),
        ],
        ProjectLanguage::Java => {
            if Path::new("pom.xml").exists() {
                vec![("maven".to_string(), "mvn compile -q".to_string())]
            } else {
                vec![("gradle".to_string(), "gradle build -q".to_string())]
            }
        }
        ProjectLanguage::Kotlin => {
            vec![("gradle".to_string(), "gradle build -q".to_string())]
        }
        ProjectLanguage::Ruby => {
            vec![("rubocop".to_string(), "rubocop".to_string())]
        }
        ProjectLanguage::PHP => {
            vec![("phpstan".to_string(), "phpstan analyse".to_string())]
        }
        ProjectLanguage::CSharp => {
            vec![(
                "dotnet".to_string(),
                "dotnet build --no-restore".to_string(),
            )]
        }
        ProjectLanguage::Cpp | ProjectLanguage::C => {
            if Path::new("CMakeLists.txt").exists() {
                vec![("cmake".to_string(), "cmake --build build".to_string())]
            } else if Path::new("Makefile").exists() {
                vec![("make".to_string(), "make".to_string())]
            } else {
                Vec::new()
            }
        }
    }
}

/// Get auto-detected static analysis commands for the current project.
/// Used by VDD when `auto_detect` is enabled and no explicit commands are configured.
pub fn get_auto_detected_commands() -> Vec<String> {
    let languages = detect_project_languages();
    let mut commands = Vec::new();

    for lang in &languages {
        for (_name, cmd) in get_default_analysis_commands(lang) {
            if !commands.contains(&cmd) {
                commands.push(cmd);
            }
        }
    }

    if !commands.is_empty() {
        info!(
            languages = ?languages.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
            commands = ?commands,
            "Auto-detected static analysis commands"
        );
    }

    commands
}

// ==========================================================================
// Glob Pattern Matching Utilities
// ==========================================================================

/// Convert a glob pattern to a regex.
fn glob_to_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let mut regex = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '*' => {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    if i + 2 < chars.len() && chars[i + 2] == '/' {
                        // **/ matches zero or more directories
                        regex.push_str("(.*/)?");
                        i += 3;
                    } else {
                        // ** at end matches everything
                        regex.push_str(".*");
                        i += 2;
                    }
                } else {
                    // * matches everything except /
                    regex.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                regex.push_str("[^/]");
                i += 1;
            }
            '.' | '(' | ')' | '[' | ']' | '{' | '}' | '+' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(chars[i]);
                i += 1;
            }
            c => {
                regex.push(c);
                i += 1;
            }
        }
    }

    regex.push('$');
    regex::RegexBuilder::new(&regex)
        .size_limit(10 * 1024) // 10KB limit to prevent ReDoS
        .build()
}

/// Normalize a file path for matching (forward slashes, no leading ./).
fn normalize_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    normalized.to_string()
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::QualityCheck;

    // ====== Glob matching tests ======

    #[test]
    fn test_glob_exact_match() {
        let re = glob_to_regex("src/main.rs").unwrap();
        assert!(re.is_match("src/main.rs"));
        assert!(!re.is_match("src/lib.rs"));
    }

    #[test]
    fn test_glob_star() {
        let re = glob_to_regex("src/*.rs").unwrap();
        assert!(re.is_match("src/main.rs"));
        assert!(re.is_match("src/lib.rs"));
        assert!(!re.is_match("src/sub/mod.rs"));
        assert!(!re.is_match("tests/test.rs"));
    }

    #[test]
    fn test_glob_double_star() {
        let re = glob_to_regex("src/**").unwrap();
        assert!(re.is_match("src/main.rs"));
        assert!(re.is_match("src/sub/mod.rs"));
        assert!(re.is_match("src/a/b/c.rs"));
    }

    #[test]
    fn test_glob_double_star_prefix() {
        let re = glob_to_regex("**/*.rs").unwrap();
        assert!(re.is_match("src/main.rs"));
        assert!(re.is_match("tests/test.rs"));
        assert!(re.is_match("a/b/c.rs"));
    }

    #[test]
    fn test_glob_dot_env() {
        let re = glob_to_regex(".env*").unwrap();
        assert!(re.is_match(".env"));
        assert!(re.is_match(".env.local"));
        assert!(re.is_match(".envrc"));
        assert!(!re.is_match("src/.env"));
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("src\\main.rs"), "src/main.rs");
        assert_eq!(normalize_path("./src/main.rs"), "src/main.rs");
        assert_eq!(normalize_path("src/main.rs"), "src/main.rs");
    }

    // ── #576 regression battery ────────────────────────────────────────────
    //
    // Lock in shell-glob semantics for `*` and `**` so the translation stays
    // consistent with how every other path-glob system (POSIX `fnmatch`,
    // `.gitignore`, `globset`) treats the path separator:
    //
    //   `*`  → `[^/]*`   (single path segment, never crosses `/`)
    //   `**` → `.*`      (multi-segment, freely crosses `/`)
    //
    // CC's `matchWildcardPattern` (shellRuleMatching.ts) collapses `*` to
    // `.*` because it operates on bash command strings, not paths — there
    // are no path segments to respect. OC's glob runs against real
    // filesystem paths (write_file, edit_file, blast radius), so the
    // single-star rule MUST stop at `/` or `Bash(rm -rf *)` accidentally
    // matches `rm -rf /etc/passwd`. The tests below pin that down.

    /// #576-1: bare `*` matches a single path-segment filename.
    #[test]
    fn issue_576_star_matches_single_segment_filename() {
        let re = glob_to_regex("*").unwrap();
        assert!(
            re.is_match("foo.rs"),
            "#576: `*` must match single-segment `foo.rs`"
        );
    }

    /// #576-2: bare `*` does NOT cross a path separator (shell semantics).
    /// This is the load-bearing case — without it, `Bash(rm -rf *)`-style
    /// rules silently match absolute paths like `/etc/passwd`.
    #[test]
    fn issue_576_star_does_not_match_multi_segment_path() {
        let re = glob_to_regex("*").unwrap();
        assert!(
            !re.is_match("dir/foo.rs"),
            "#576: `*` must NOT match multi-segment `dir/foo.rs` (would cross `/`)"
        );
    }

    /// #576-3: `**` is the explicit opt-in to multi-segment matching.
    #[test]
    fn issue_576_double_star_matches_multi_segment_path() {
        let re = glob_to_regex("**").unwrap();
        assert!(
            re.is_match("dir/foo.rs"),
            "#576: `**` must match multi-segment `dir/foo.rs`"
        );
    }

    /// #576-4: `**` also matches a zero-directory (single-segment) path.
    #[test]
    fn issue_576_double_star_matches_zero_segment_path() {
        let re = glob_to_regex("**").unwrap();
        assert!(
            re.is_match("foo.rs"),
            "#576: `**` must match zero-directory `foo.rs`"
        );
    }

    /// #576-5: `dir/*` matches one level deep but stops at the next `/`.
    #[test]
    fn issue_576_dir_star_matches_one_level_only() {
        let re = glob_to_regex("dir/*").unwrap();
        assert!(
            re.is_match("dir/foo.rs"),
            "#576: `dir/*` must match `dir/foo.rs`"
        );
        assert!(
            !re.is_match("dir/sub/foo.rs"),
            "#576: `dir/*` must NOT match nested `dir/sub/foo.rs`"
        );
    }

    /// #576-6: `dir/**` matches arbitrarily deep paths under `dir/`.
    #[test]
    fn issue_576_dir_double_star_matches_any_depth() {
        let re = glob_to_regex("dir/**").unwrap();
        assert!(
            re.is_match("dir/foo.rs"),
            "#576: `dir/**` must match shallow `dir/foo.rs`"
        );
        assert!(
            re.is_match("dir/sub/foo.rs"),
            "#576: `dir/**` must match nested `dir/sub/foo.rs`"
        );
    }

    // ====== Blast radius tests ======

    #[test]
    fn test_blast_radius_denied_strict() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            allowed_paths: vec![],
            denied_paths: vec![".env*".to_string(), ".git/**".to_string()],
            max_files_per_turn: 0,
        };
        let guard = BlastRadiusGuard::new(config);

        assert!(guard.check_path("src/main.rs").is_ok());
        assert!(guard.check_path(".env").is_err());
        assert!(guard.check_path(".env.local").is_err());
        assert!(guard.check_path(".git/config").is_err());
    }

    #[test]
    fn test_blast_radius_allowed_strict() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            allowed_paths: vec!["src/**".to_string(), "tests/**".to_string()],
            denied_paths: vec![],
            max_files_per_turn: 0,
        };
        let guard = BlastRadiusGuard::new(config);

        assert!(guard.check_path("src/main.rs").is_ok());
        assert!(guard.check_path("tests/test.rs").is_ok());
        assert!(guard.check_path("config.yaml").is_err());
    }

    #[test]
    fn test_blast_radius_advisory_allows() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Advisory,
            allowed_paths: vec!["src/**".to_string()],
            denied_paths: vec![],
            max_files_per_turn: 0,
        };
        let guard = BlastRadiusGuard::new(config);

        // Advisory mode warns but doesn't block
        assert!(guard.check_path("config.yaml").is_ok());
    }

    #[test]
    fn test_blast_radius_max_files() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            allowed_paths: vec![],
            denied_paths: vec![],
            max_files_per_turn: 2,
        };
        let guard = BlastRadiusGuard::new(config);

        assert!(guard.record_access("file1.rs").is_ok());
        assert!(guard.record_access("file2.rs").is_ok());
        assert!(guard.record_access("file3.rs").is_err());
    }

    /// Crosslink #840: when the breach is by a representable count, the
    /// error message is the plain `(count/cap)` form — not the overflow
    /// form — so monitoring dashboards can distinguish the two cases.
    #[test]
    fn blast_radius_breach_reports_distinct_message_for_representable_count() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            allowed_paths: vec![],
            denied_paths: vec![],
            max_files_per_turn: 1,
        };
        let guard = BlastRadiusGuard::new(config);
        assert!(guard.record_access("a.rs").is_ok());
        let err = guard
            .record_access("b.rs")
            .expect_err("must reject second file under cap=1");
        assert!(
            err.contains("exceeded max files per turn"),
            "representable breach must use the plain message; got: {err}"
        );
        assert!(
            !err.contains("overflowed"),
            "representable breach must NOT use the overflow message; got: {err}"
        );
    }

    #[test]
    fn test_blast_radius_reset_turn() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            allowed_paths: vec![],
            denied_paths: vec![],
            max_files_per_turn: 1,
        };
        let guard = BlastRadiusGuard::new(config);

        assert!(guard.record_access("file1.rs").is_ok());
        assert!(guard.record_access("file2.rs").is_err());

        guard.reset_turn();
        assert!(guard.record_access("file3.rs").is_ok());
    }

    // ====== Diff monitor tests ======

    #[test]
    fn test_diff_monitor_basic() {
        let config = DiffMonitorConfig {
            enabled: true,
            max_lines_changed: 100,
            max_files_changed: 5,
            action: GuardrailAction::Warn,
        };
        let monitor = DiffMonitor::new(config);

        monitor.record("file1.rs", 10, 5);
        monitor.record("file2.rs", 20, 10);

        let stats = monitor.get_stats();
        assert_eq!(stats.lines_added, 30);
        assert_eq!(stats.lines_removed, 15);
        assert_eq!(stats.lines_changed, 45);
        assert_eq!(stats.files_changed, 2);
    }

    #[test]
    fn test_diff_monitor_threshold_not_exceeded() {
        let config = DiffMonitorConfig {
            enabled: true,
            max_lines_changed: 100,
            max_files_changed: 5,
            action: GuardrailAction::Warn,
        };
        let monitor = DiffMonitor::new(config);

        monitor.record("file1.rs", 10, 5);
        assert!(monitor.check_thresholds().is_none());
    }

    #[test]
    fn test_diff_monitor_threshold_exceeded() {
        let config = DiffMonitorConfig {
            enabled: true,
            max_lines_changed: 20,
            max_files_changed: 5,
            action: GuardrailAction::Warn,
        };
        let monitor = DiffMonitor::new(config);

        monitor.record("file1.rs", 15, 10);

        let warning = monitor.check_thresholds();
        assert!(warning.is_some());
        let w = warning.unwrap();
        assert!(w.message.contains("lines changed"));
        assert_eq!(w.stats.lines_changed, 25);
    }

    #[test]
    fn test_diff_monitor_files_threshold() {
        let config = DiffMonitorConfig {
            enabled: true,
            max_lines_changed: 0,
            max_files_changed: 2,
            action: GuardrailAction::Block,
        };
        let monitor = DiffMonitor::new(config);

        monitor.record("a.rs", 1, 0);
        monitor.record("b.rs", 1, 0);
        assert!(monitor.check_thresholds().is_none());

        monitor.record("c.rs", 1, 0);
        let warning = monitor.check_thresholds();
        assert!(warning.is_some());
        assert!(warning.unwrap().message.contains("files changed"));
    }

    // ====== Quality gates tests ======

    #[test]
    fn test_quality_gate_passing_command() {
        let config = QualityGatesConfig {
            enabled: true,
            run_after: crate::config::RunAfter::EveryTurn,
            fail_action: GuardrailAction::Warn,
            checks: vec![QualityCheck {
                name: "echo".to_string(),
                command: "echo ok".to_string(),
                required: true,
            }],
            timeout_seconds: 30,
        };
        let runner = QualityGateRunner::new(config);
        let results = runner.run();

        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
        assert_eq!(results[0].exit_code, 0);
        assert!(results[0].stdout.contains("ok"));
    }

    #[test]
    fn quality_gate_runtime_builder_succeeds() {
        let runtime = build_quality_gate_runtime("test").expect("quality gate runtime builds");
        drop(runtime);
    }

    #[test]
    fn test_quality_gate_failing_command() {
        // `false` is a real binary on every POSIX system that exits 1.
        // The previous `exit 1` test relied on bash -c being invoked, which
        // is exactly the vulnerability crosslink #700 closes.
        let config = QualityGatesConfig {
            enabled: true,
            run_after: crate::config::RunAfter::EveryTurn,
            fail_action: GuardrailAction::Warn,
            checks: vec![QualityCheck {
                name: "fail".to_string(),
                command: "false".to_string(),
                required: false,
            }],
            timeout_seconds: 30,
        };
        let runner = QualityGateRunner::new(config);
        let results = runner.run();

        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
        assert_ne!(results[0].exit_code, 0);
    }

    // ====== Quality-gate shell-injection tests (crosslink #700) ======
    //
    // These tests pin the post-fix behaviour: the runner MUST NOT route
    // through `bash -c` / `sh -c`. Shell metacharacters in the command
    // string must survive as inert literal argv tokens to the program.

    #[test]
    fn test_quality_gate_shell_metacharacters_are_literal_args() {
        // Pre-fix: `echo a; rm -rf /tmp/openclaudia-#700-sentinel` would be
        // split by bash into TWO commands and the `rm` would actually run.
        // Post-fix: `;` is a literal argument to `echo`, so the sentinel
        // file must still exist after the gate runs.
        let dir = tempfile::TempDir::new().unwrap();
        let sentinel = dir.path().join("sentinel.txt");
        std::fs::write(&sentinel, b"do-not-delete").unwrap();

        let injection = format!("echo a; rm -rf {}", sentinel.display());
        let config = QualityGatesConfig {
            enabled: true,
            run_after: crate::config::RunAfter::EveryTurn,
            fail_action: GuardrailAction::Warn,
            checks: vec![QualityCheck {
                name: "inject-semicolon".to_string(),
                command: injection,
                required: false,
            }],
            timeout_seconds: 30,
        };
        let runner = QualityGateRunner::new(config);
        let results = runner.run();

        assert_eq!(results.len(), 1);
        // The sentinel file MUST still exist. If the runner shelled out
        // via `bash -c`, the `;` would have terminated the echo and run
        // `rm -rf <sentinel>`, deleting it.
        assert!(
            sentinel.exists(),
            "shell injection succeeded: sentinel was deleted (bash -c regression)"
        );
        // And the echo argument list must contain the literal `;` and
        // `rm` tokens as data.
        assert!(results[0].stdout.contains(';'));
        assert!(results[0].stdout.contains("rm"));
    }

    #[test]
    fn test_quality_gate_command_substitution_is_literal() {
        // Pre-fix: `echo $(whoami)` under bash -c would expand to the
        // current user's name. Post-fix: `$(whoami)` is a literal arg.
        let config = QualityGatesConfig {
            enabled: true,
            run_after: crate::config::RunAfter::EveryTurn,
            fail_action: GuardrailAction::Warn,
            checks: vec![QualityCheck {
                name: "inject-cmdsub".to_string(),
                command: "echo $(whoami)".to_string(),
                required: false,
            }],
            timeout_seconds: 30,
        };
        let runner = QualityGateRunner::new(config);
        let results = runner.run();

        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
        // Literal `$(whoami)` must appear in stdout, NOT the resolved
        // user name. (We don't know what the test user is named, but we
        // do know `$(whoami)` is the precise input string.)
        assert!(
            results[0].stdout.contains("$(whoami)"),
            "command substitution was evaluated by a shell: stdout = {:?}",
            results[0].stdout
        );
    }

    #[test]
    fn test_quality_gate_timeout_enforced_on_long_running_command() {
        // `sleep 30` with a 1-second timeout must exit non-zero in well
        // under 30 seconds. This pins the argv-level `timeout 1 sleep 30`
        // wrapper produced by run_shell_command_sync.
        #[cfg(not(windows))]
        {
            let config = QualityGatesConfig {
                enabled: true,
                run_after: crate::config::RunAfter::EveryTurn,
                fail_action: GuardrailAction::Warn,
                checks: vec![QualityCheck {
                    name: "sleeper".to_string(),
                    command: "sleep 30".to_string(),
                    required: false,
                }],
                timeout_seconds: 1,
            };
            let runner = QualityGateRunner::new(config);
            let start = std::time::Instant::now();
            let results = runner.run();
            let elapsed = start.elapsed();

            assert_eq!(results.len(), 1);
            assert!(
                !results[0].passed,
                "long-running command was not killed by timeout wrapper"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(10),
                "timeout did not fire: elapsed = {elapsed:?}"
            );
        }
    }

    #[test]
    fn test_quality_gate_rejects_malformed_command() {
        // Unbalanced quotes must surface as a structured failure (exit
        // code -1 with a non-empty stderr) rather than being passed to
        // a shell that would silently mangle the argv.
        let config = QualityGatesConfig {
            enabled: true,
            run_after: crate::config::RunAfter::EveryTurn,
            fail_action: GuardrailAction::Warn,
            checks: vec![QualityCheck {
                name: "broken".to_string(),
                command: "echo 'unterminated".to_string(),
                required: false,
            }],
            timeout_seconds: 30,
        };
        let runner = QualityGateRunner::new(config);
        let results = runner.run();

        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
        assert_eq!(results[0].exit_code, -1);
        assert!(!results[0].stderr.is_empty());
    }

    #[test]
    fn test_quality_gate_valid_multi_arg_command_executes() {
        // Confirms the happy path: a multi-argument command tokenises
        // correctly and runs as the real binary with the expected argv.
        let config = QualityGatesConfig {
            enabled: true,
            run_after: crate::config::RunAfter::EveryTurn,
            fail_action: GuardrailAction::Warn,
            checks: vec![QualityCheck {
                name: "printf".to_string(),
                command: "printf %s hello".to_string(),
                required: true,
            }],
            timeout_seconds: 30,
        };
        let runner = QualityGateRunner::new(config);
        let results = runner.run();

        assert_eq!(results.len(), 1);
        assert!(results[0].passed);
        assert_eq!(results[0].exit_code, 0);
        assert_eq!(results[0].stdout, "hello");
    }

    // ====== Language detection tests ======

    #[test]
    fn test_detect_rust_project() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();

        let langs = detect_languages_in_dir(dir.path());
        assert!(langs.contains(&ProjectLanguage::Rust));
    }

    #[test]
    fn test_detect_python_project() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "flask\n").unwrap();

        let langs = detect_languages_in_dir(dir.path());
        assert!(langs.contains(&ProjectLanguage::Python));
    }

    #[test]
    fn test_detect_typescript_project() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("tsconfig.json"), "{}").unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let langs = detect_languages_in_dir(dir.path());
        assert!(langs.contains(&ProjectLanguage::TypeScript));
        // JavaScript should be deduped when TypeScript is present
        assert!(!langs.contains(&ProjectLanguage::JavaScript));
    }

    #[test]
    fn test_detect_javascript_only() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let langs = detect_languages_in_dir(dir.path());
        assert!(langs.contains(&ProjectLanguage::JavaScript));
        assert!(!langs.contains(&ProjectLanguage::TypeScript));
    }

    #[test]
    fn test_detect_go_project() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("go.mod"), "module test").unwrap();

        let langs = detect_languages_in_dir(dir.path());
        assert!(langs.contains(&ProjectLanguage::Go));
    }

    #[test]
    fn test_detect_empty_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let langs = detect_languages_in_dir(dir.path());
        assert!(langs.is_empty());
    }

    #[test]
    fn test_detect_multi_language() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "").unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();

        let langs = detect_languages_in_dir(dir.path());
        assert!(langs.contains(&ProjectLanguage::Rust));
        assert!(langs.contains(&ProjectLanguage::JavaScript));
    }

    #[test]
    fn test_default_commands_rust() {
        let cmds = get_default_analysis_commands(&ProjectLanguage::Rust);
        assert_eq!(cmds.len(), 2);
        assert!(cmds[0].1.contains("clippy"));
        assert!(cmds[1].1.contains("cargo test"));
    }

    #[test]
    fn test_default_commands_python() {
        let cmds = get_default_analysis_commands(&ProjectLanguage::Python);
        assert!(!cmds.is_empty());
        assert!(cmds.iter().any(|(name, _)| name == "ruff"));
    }

    #[test]
    fn test_project_language_display() {
        assert_eq!(ProjectLanguage::Rust.to_string(), "Rust");
        assert_eq!(ProjectLanguage::TypeScript.to_string(), "TypeScript");
        assert_eq!(ProjectLanguage::CSharp.to_string(), "C#");
        assert_eq!(ProjectLanguage::Cpp.to_string(), "C++");
    }

    // ====== Global API tests ======
    //
    // These tests mutate the process-global `GUARDRAILS` static, so
    // they must serialize against one another. We use a dedicated
    // mutex because each test wants to start from a known state.
    //
    // Every #749 test restores the state to `Disabled` on the way
    // out so concurrent tools tests (write.rs / edit.rs / notebook.rs)
    // that call `check_file_access` against the global keep observing
    // the "no policy" allow path.

    static GLOBAL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_global_for_test() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn make_strict_engine_with_deny(deny_glob: &str) -> GuardrailsEngine {
        let cfg = GuardrailsConfig {
            blast_radius: Some(BlastRadiusConfig {
                enabled: true,
                mode: GuardrailMode::Strict,
                allowed_paths: vec![],
                denied_paths: vec![deny_glob.to_string()],
                max_files_per_turn: 0,
            }),
            diff_monitor: None,
            quality_gates: None,
        };
        GuardrailsEngine::from_config(&cfg)
    }

    #[test]
    fn test_disabled_guardrails_allow_all() {
        // "Disabled" == no policy loaded. The security boundary must
        // return Ok so default-install installs behave the same as the
        // pre-#749 codebase. Fail-closed only applies to Poisoned.
        let _serialize = lock_global_for_test();
        set_state_for_test(GuardrailsState::Disabled);

        assert!(check_file_access("any/file.rs").is_ok());
        assert!(check_diff_thresholds().is_none());
        assert!(run_quality_gates().is_empty());
        assert!(get_diff_summary().is_none());
    }

    // ====== Crosslink #749 regression: fail-closed on bad state ======

    #[test]
    fn test_749_check_file_access_returns_err_when_poisoned() {
        // BEFORE THE FIX: a poisoned mutex was swallowed by
        // `if let Ok(guard) = ...lock()` and the function returned
        // Ok(()). After the fix the security boundary must refuse.
        let _serialize = lock_global_for_test();
        set_state_for_test(GuardrailsState::Poisoned);
        assert_eq!(current_state_kind(), "poisoned");

        let result = check_file_access("/etc/shadow");
        assert!(
            result.is_err(),
            "poisoned guardrails must fail-closed at the security              boundary, got: {result:?}"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("poisoned"),
            "error must identify the poisoned cause: got {msg:?}"
        );

        set_state_for_test(GuardrailsState::Disabled);
    }

    #[test]
    fn test_749_check_file_access_happy_path_with_enabled_engine() {
        // After the fix, a properly configured engine still routes
        // through `Enabled(engine).check_file_access(...)`. The
        // tri-state refactor must not regress the allow-decision path.
        let _serialize = lock_global_for_test();
        let engine = make_strict_engine_with_deny(".env*");
        set_state_for_test(GuardrailsState::Enabled(Box::new(engine)));
        assert_eq!(current_state_kind(), "enabled");

        assert!(
            check_file_access("src/main.rs").is_ok(),
            "enabled engine should allow non-denied paths"
        );

        let blocked = check_file_access(".env.local");
        assert!(blocked.is_err(), "deny rule must fire");
        let msg = blocked.unwrap_err();
        assert!(
            msg.contains("Blast radius"),
            "blocked-by-rule error should come from the engine, not              the poisoned-state sentinel: got {msg:?}"
        );
        assert!(!msg.contains("poisoned"));

        set_state_for_test(GuardrailsState::Disabled);
    }

    #[test]
    fn test_749_configure_refuses_when_poisoned() {
        // Sticky-poison contract: once poisoned, configure() must NOT
        // silently re-arm the engine.
        let _serialize = lock_global_for_test();
        set_state_for_test(GuardrailsState::Poisoned);

        let cfg = GuardrailsConfig::default();
        configure(&cfg);

        assert_eq!(
            current_state_kind(),
            "poisoned",
            "configure() must be a no-op once the state is poisoned"
        );

        set_state_for_test(GuardrailsState::Disabled);
    }

    #[test]
    fn test_749_non_security_paths_safe_when_poisoned() {
        // Non-security accessors must not panic or hang on poison.
        let _serialize = lock_global_for_test();
        set_state_for_test(GuardrailsState::Poisoned);

        assert!(check_diff_thresholds().is_none());
        assert!(run_quality_gates().is_empty());
        assert!(get_diff_summary().is_none());
        record_file_modification("any.rs", 1, 0);
        reset_turn();

        set_state_for_test(GuardrailsState::Disabled);
    }

    #[test]
    fn test_749_configure_with_all_disabled_yields_disabled_state() {
        // A `GuardrailsConfig::default()` has every guard disabled.
        // configure() must therefore leave the state as Disabled and
        // not allocate a real engine. This is what makes the global
        // API safe for the existing tools tests.
        let _serialize = lock_global_for_test();
        set_state_for_test(GuardrailsState::Disabled);
        configure(&GuardrailsConfig::default());
        assert_eq!(current_state_kind(), "disabled");
        assert!(check_file_access("any/file.rs").is_ok());
    }

    // ====== crosslink #395: cross-platform shell ======
    //
    // These tests pin the four ShellResult variants and prove the
    // pre-#395 Unix-only `timeout coreutils + bash hardcode` is gone:
    // no shell is invoked (verified by special chars surviving as
    // inert arguments to a binary that doesn't expand them), and the
    // wall-clock cap is enforced by tokio::time::timeout via
    // kill_on_drop, not by the absent `timeout(1)` binary on macOS.

    /// Successful command surfaces Success { stdout, stderr } with
    /// stdout populated. Uses `printf` (POSIX-portable, present on
    /// every supported target — no Windows path needed because the
    /// runner shells out to argv directly, not /bin/sh).
    #[cfg(unix)]
    #[test]
    fn cl395_run_shell_success_captures_stdout() {
        let outcome = run_shell_command_sync("printf %s hello", 5);
        match outcome {
            ShellResult::Success { stdout, .. } => assert_eq!(stdout, "hello"),
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// Non-zero exit surfaces `ExitFailed { code, stdout, stderr }` with
    /// the real exit code (NOT the pre-#395 sentinel `-1`) so callers can
    /// distinguish 'tool ran and failed' from 'tool not found'.
    #[cfg(unix)]
    #[test]
    fn cl395_run_shell_nonzero_exit_returns_exit_failed_with_code() {
        let outcome = run_shell_command_sync("sh -c \"exit 7\"", 5);
        match outcome {
            ShellResult::ExitFailed { code, .. } => assert_eq!(code, 7),
            other => panic!("expected ExitFailed{{code:7,..}}, got {other:?}"),
        }
    }

    /// A command that exceeds the wall-clock timeout returns
    /// `ShellResult::Timeout` (not `ExitFailed`). The pre-#395 `timeout`
    /// coreutil prefix silently failed with 'command not found' on
    /// macOS; the in-process `tokio::time::timeout` + `kill_on_drop` now
    /// enforces the cap on every platform.
    #[cfg(unix)]
    #[test]
    fn cl395_run_shell_long_running_returns_timeout() {
        let start = std::time::Instant::now();
        let outcome = run_shell_command_sync("sleep 30", 1);
        let elapsed = start.elapsed();
        assert!(
            matches!(outcome, ShellResult::Timeout),
            "expected Timeout, got {outcome:?}"
        );
        assert!(
            elapsed.as_secs() < 5,
            "Timeout must fire well under the 30s sleep — elapsed={elapsed:?} \
             (kill_on_drop reaping the child is the load-bearing invariant)"
        );
    }

    /// A program name that does not exist on PATH surfaces `ShellMissing`
    /// rather than the pre-#395 `ExitFailed(-1, "", "...No such file or
    /// directory")`. The caller is now structurally able to tell 'tool
    /// not installed' apart from 'tool ran and failed'.
    #[cfg(unix)]
    #[test]
    fn cl395_run_shell_missing_program_returns_shell_missing() {
        let outcome = run_shell_command_sync(
            "openclaudia-cl395-definitely-not-a-real-binary-name --version",
            5,
        );
        match outcome {
            ShellResult::ShellMissing { tried } => {
                assert!(
                    tried
                        .iter()
                        .any(|t| t.contains("openclaudia-cl395-definitely-not-a-real-binary-name")),
                    "tried list must mention the program that was missing, got {tried:?}"
                );
            }
            other => panic!("expected ShellMissing, got {other:?}"),
        }
    }

    /// stderr is captured on a Success path too — POSIX tools commonly
    /// emit progress / warning text on stderr even when they exit 0
    /// (`cargo`, `make`, `git`), and a caller that throws away the
    /// stderr payload loses forensic context.
    #[cfg(unix)]
    #[test]
    fn cl395_run_shell_success_captures_stderr_alongside_stdout() {
        // sh -c 'echo out; echo err >&2' — both streams populated, exit 0.
        let outcome = run_shell_command_sync("sh -c \"echo out; echo err 1>&2\"", 5);
        match outcome {
            ShellResult::Success { stdout, stderr } => {
                assert!(stdout.contains("out"), "stdout missing payload: {stdout:?}");
                assert!(stderr.contains("err"), "stderr missing payload: {stderr:?}");
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn quality_gate_project_code_cannot_write_host_temp_files() {
        let host_dir = tempfile::TempDir::new().expect("quality-gate host tempdir");
        let host_file = host_dir.path().join("escape.txt");
        let command = format!("sh -c \"printf escaped > {}\"", host_file.to_string_lossy());

        let _ = run_shell_command_sync(&command, 5);

        assert!(
            !host_file.exists(),
            "project-controlled quality gate escaped its OS sandbox"
        );
    }

    /// Shell-metacharacter survival check: the pre-#395 code used
    /// `format!("timeout {n} {cmd}")` and shelled out via `bash -c`,
    /// so `$(...)`, backticks, and `;` were *interpreted*. The new
    /// argv-direct exec must treat them as inert string arguments.
    /// We use `printf %s` so the literal `$(date)` is echoed verbatim
    /// rather than substituted.
    #[cfg(unix)]
    #[test]
    fn cl395_run_shell_does_not_invoke_a_shell_for_argv_expansion() {
        let outcome = run_shell_command_sync("printf %s $(date)", 5);
        match outcome {
            ShellResult::Success { stdout, .. } => {
                assert_eq!(
                    stdout, "$(date)",
                    "shell substitution leaked: argv-direct exec must \
                     preserve `$(date)` as a literal token"
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }
}

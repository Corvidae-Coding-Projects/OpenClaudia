//! Startup migration framework for on-disk format changes.
//!
//! Port of Claude Code's `migrations/` directory. Each migration is a
//! small, self-contained unit that checks whether it applies, and if
//! so, upgrades one on-disk artifact (settings file, transcript, memory
//! DB, etc.). Migrations run in registration order at startup.
//!
//! # Kinds
//!
//! - **Idempotent** migrations inspect current state each run and
//!   short-circuit when there's nothing to do. Preferred, because they
//!   survive disk rollbacks and partial applies without a separate
//!   completion ledger.
//! - **Once-only** migrations are marked done after their first
//!   successful run via [`CompletionLedger`]. Use only when the
//!   migration can't introspect the target state to detect whether it
//!   already ran (e.g. a one-time notification, an analytics event).
//!
//! # Failure model
//!
//! A migration failure must never crash startup. The runner logs the
//! error and continues with the remaining migrations. Callers get the
//! full per-migration result via [`run_all`]'s return value if they
//! want to surface it.

use anyhow::Context as _;
use std::io;
use std::path::{Path, PathBuf};

mod ledger;
mod registry;
mod session_state_v1;
mod stamp_transcript_schema_v1;

#[cfg(test)]
mod tests;

pub use ledger::CompletionLedger;

/// What a migration does when invoked.
///
/// `Failed` carries a `String` rather than `anyhow::Error` so the outcome is
/// `Clone`-able and easy to ship through channels / fan out across reporters
/// (crosslink #894). Producers of `Failed` are expected to call `to_string()`
/// on the underlying error (or use [`From<anyhow::Error>`]) at the failure
/// site; the structured chain is lost on purpose — by the time a migration
/// has returned `Failed`, downstream code only needs a stable human-readable
/// summary for logs and the `migrate --dry-run` report.
#[derive(Clone)]
pub enum MigrationOutcome {
    /// Target state is already current — no action taken.
    Skipped,
    /// Migration ran and changed state. Message is surfaced in logs.
    Applied(String),
    /// Migration failed. Startup continues; error is logged. The payload
    /// is the formatted error message (chain flattened to a single
    /// `Display` string).
    Failed(String),
}

impl From<anyhow::Error> for MigrationOutcome {
    fn from(err: anyhow::Error) -> Self {
        Self::Failed(format!("{err:#}"))
    }
}

impl From<std::io::Error> for MigrationOutcome {
    fn from(err: std::io::Error) -> Self {
        Self::Failed(err.to_string())
    }
}

/// Whether the runner needs to consult the completion ledger before
/// running this migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPolicy {
    /// Always invoke — the migration decides itself whether to act.
    Idempotent,
    /// Invoke at most once per machine; subsequent runs are skipped.
    OnceOnly,
}

/// Contract a migration implements. Stateless and side-effect free on
/// construction — all work happens inside [`Migration::run`].
pub trait Migration: Send + Sync {
    /// Stable identifier. Used as the ledger key for once-only
    /// migrations and in log output. Must not change between releases.
    fn id(&self) -> &'static str;

    /// Short human-readable summary for logs / `openclaudia migrate --dry-run`.
    fn description(&self) -> &'static str;

    /// Run policy — see [`RunPolicy`].
    fn run_policy(&self) -> RunPolicy {
        RunPolicy::Idempotent
    }

    /// Execute the migration. Must not panic; return
    /// [`MigrationOutcome::Failed`] for recoverable errors.
    fn run(&self, ctx: &MigrationContext) -> MigrationOutcome;
}

/// Read-only context handed to every migration. Carries the paths the
/// migration is allowed to touch, so the unit under test doesn't resolve
/// `dirs::home_dir()` itself.
pub struct MigrationContext {
    /// `~/.claude` (or `$CLAUDE_CONFIG_HOME_DIR` if set).
    pub claude_home: PathBuf,
    /// `~/.local/share/openclaudia` (or the platform equivalent).
    pub openclaudia_data: PathBuf,
}

impl MigrationContext {
    /// Build a context from the user's real directories. Falls back to
    /// `.` if any lookup fails — migrations must tolerate missing dirs.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            claude_home: crate::transcript::claude_config_home_dir(),
            openclaudia_data: dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("openclaudia"),
        }
    }

    /// Explicit constructor for tests that need to sandbox writes.
    #[must_use]
    pub const fn with_paths(claude_home: PathBuf, openclaudia_data: PathBuf) -> Self {
        Self {
            claude_home,
            openclaudia_data,
        }
    }

    /// Where the once-only completion ledger lives.
    ///
    /// crosslink #960: scoped to `pub(crate)` so external callers cannot
    /// reach in and mutate ledger state through a path they fabricated.
    /// The ledger itself is a private detail of [`run_all`]; callers that
    /// need to inspect what has run should consume the [`MigrationReport`]
    /// stream instead of reading the file directly.
    #[must_use]
    pub(crate) fn ledger_path(&self) -> PathBuf {
        self.openclaudia_data.join("migrations.json")
    }
}

/// Per-migration outcome record returned by [`run_all`].
pub struct MigrationReport {
    pub id: &'static str,
    pub description: &'static str,
    pub outcome: MigrationOutcome,
}

/// Run every registered migration against `ctx` in declaration order.
/// Never panics and never returns an error — individual migration
/// failures are captured in the returned `Vec<MigrationReport>`.
pub fn run_all(ctx: &MigrationContext) -> Vec<MigrationReport> {
    // load() now returns Result so corruption is no longer silently
    // coerced to "empty" inside the ledger itself (#741b). We preserve
    // run_all's contract (never panic, never bubble up) by logging the
    // failure here and degrading to an empty ledger — the signal is
    // emitted at the boundary, not swallowed at the source.
    let mut ledger = match CompletionLedger::load(&ctx.ledger_path()) {
        Ok(l) => l,
        Err(err) => {
            tracing::warn!(
                path = %ctx.ledger_path().display(),
                error = %err,
                "migration ledger unreadable; once-only migrations may replay"
            );
            CompletionLedger::default()
        }
    };
    let mut out = Vec::new();
    for migration in registry::all() {
        let id = migration.id();
        let description = migration.description();
        if migration.run_policy() == RunPolicy::OnceOnly && ledger.contains(id) {
            out.push(MigrationReport {
                id,
                description,
                outcome: MigrationOutcome::Skipped,
            });
            continue;
        }
        let outcome = migration.run(ctx);
        match &outcome {
            MigrationOutcome::Applied(msg) => {
                tracing::info!(id, description, msg = %msg, "migration applied");
                if migration.run_policy() == RunPolicy::OnceOnly {
                    ledger.mark(id);
                }
            }
            MigrationOutcome::Skipped => {
                tracing::debug!(id, description, "migration skipped");
            }
            MigrationOutcome::Failed(err) => {
                tracing::warn!(id, description, error = %err, "migration failed");
            }
        }
        out.push(MigrationReport {
            id,
            description,
            outcome,
        });
    }
    // Best-effort ledger flush; failure here means next run may repeat
    // a once-only migration, which is the failure mode we already
    // accept for the whole framework.
    if let Err(err) = ledger.save(&ctx.ledger_path()) {
        tracing::warn!(error = %err, "failed to persist migration ledger");
    }
    out
}

/// Utility: convenience wrapper around [`run_all`] that returns only
/// the count of applied migrations. Callers that don't care about per-
/// migration details use this.
#[must_use]
pub fn run_all_count_applied(ctx: &MigrationContext) -> usize {
    run_all(ctx)
        .into_iter()
        .filter(|r| matches!(r.outcome, MigrationOutcome::Applied(_)))
        .count()
}

/// Convenience for migrations that just need to read a JSON file into
/// a `serde_json::Value`. Returns `Ok(None)` only when the file is
/// genuinely absent (`io::ErrorKind::NotFound`) — every other I/O
/// failure (permission denied, I/O error, busy device, etc.) is
/// propagated as `Err`.
///
/// This distinction matters for migrations that use the marker-file
/// fast-path: silently treating "can't read the marker" as "marker
/// is absent" would either re-run a destructive migration or — worse,
/// per crosslink #734 — silently skip a needed migration when the
/// caller pattern-matched on `Ok(_)` only.
pub(crate) fn read_json_if_exists(path: &Path) -> anyhow::Result<Option<serde_json::Value>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!("reading {}", path.display())));
        }
    };
    let value = serde_json::from_str(&text)
        .with_context(|| format!("parsing JSON from {}", path.display()))?;
    Ok(Some(value))
}

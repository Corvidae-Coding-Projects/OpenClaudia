//! Preserved background-job mechanics — unavailable in production.
//!
//! `OpenClaudia` does not construct or tick this scheduler in a production
//! frontend. The synchronous scheduler lacks lifecycle ownership, durable
//! leases, cancellation, budgets, and safe transactional job semantics, so
//! [`crate::services::lifecycle_service_catalog`] classifies it as
//! `Unavailable`. The implementation remains available for isolated tests and
//! the follow-up slices that will complete it.
//!
//! The module contains a scheduling skeleton and one concrete background job:
//! **memory consolidation** (prune expired short-term entries and produce a
//! bounded, non-destructive review trace for possible semantic duplicates).
//!
//! ## Design
//!
//! - [`BackgroundJob`] is the trait every periodic job implements.
//!   A job receives an [`Arc<MemoryDb>`] (the only shared resource
//!   needed for Phase 1) and returns a [`JobOutcome`] describing what
//!   happened.
//! - [`JobScheduler`] holds a list of registered jobs plus a monotonic clock of
//!   when each last ran. Its synchronous [`JobScheduler::tick`] method is a
//!   testable primitive, not a production lifecycle.
//! - [`MemoryConsolidationJob`] is the only concrete job shipped in
//!   Phase 1. It:
//!   1. Prunes expired short-term sessions and activities via
//!      [`MemoryDb::cleanup_expired_short_term`].
//!   2. Preserves distinct logical memories even when their content is
//!      byte-for-byte identical. Equal prose is not an equivalence proof.
//!
//! ## Phase 2 follow-up
//!
//! See crosslink issue filed alongside this change for:
//! - Auto-documentation maintenance (CLAUDE.md / MEMORY.md writers).
//! - Periodic agent summarization using the coordinator infrastructure.
//! - Async `tokio::spawn`-based dispatch loop so jobs run off the main
//!   thread without blocking the proxy.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::memory::MemoryDb;

// ── Outcome ─────────────────────────────────────────────────────────────────

/// What a job accomplished during a single run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobOutcome {
    /// Human-readable label identifying which job ran.
    pub job_name: &'static str,
    /// Number of records that were removed or merged.
    pub records_pruned: usize,
    /// Number of causally proven revision reconciliations or summaries. Equal
    /// prose is never counted as a merge.
    pub records_deduped: usize,
}

// ── Trait ────────────────────────────────────────────────────────────────────

/// A periodic background task that operates on the memory database.
///
/// Implementors must be `Send + Sync` so the scheduler can hold
/// them behind `Arc<dyn BackgroundJob>` and share them across thread
/// boundaries (Phase 2 will dispatch via `tokio::spawn`).
///
/// # Errors
///
/// The `run` method returns `anyhow::Result<JobOutcome>`. Transient
/// failures (lock contention, `SQLite` busy) should be surfaced as errors
/// so the scheduler can log them without crashing the host process.
pub trait BackgroundJob: Send + Sync {
    /// Name used in log output and [`JobOutcome::job_name`].
    fn name(&self) -> &'static str;

    /// Execute one pass of this job against `db`. Must finish in bounded
    /// time — the scheduler calls this synchronously on the tick thread.
    ///
    /// # Errors
    ///
    /// Returns an error if the database operation fails.
    fn run(&self, db: &Arc<MemoryDb>) -> Result<JobOutcome>;
}

// ── Memory consolidation job ─────────────────────────────────────────────────

/// Prunes expired short-term memory and reviews possible archival duplicates.
///
/// Runs two passes:
/// 1. **Expiry pass** — delegates to [`MemoryDb::cleanup_expired_short_term`]
///    which deletes sessions and activities older than 48 hours.
/// 2. **Review pass** — loads a bounded set of archival memories and reports
///    equal-content records that intentionally remain separate logical facts.
///
/// Revision retries and replicas already converge idempotently by immutable
/// record digest in [`MemoryDb`]. Consolidation does not invent an equivalence
/// relation from prose or timestamps.
pub struct MemoryConsolidationJob;

impl BackgroundJob for MemoryConsolidationJob {
    fn name(&self) -> &'static str {
        "memory_consolidation"
    }

    fn run(&self, db: &Arc<MemoryDb>) -> Result<JobOutcome> {
        // Pass 1 — prune expired short-term entries.
        let (sessions_pruned, activities_pruned) = db.cleanup_expired_short_term()?;
        let records_pruned = sessions_pruned + activities_pruned;
        tracing::debug!(
            sessions_pruned,
            activities_pruned,
            "memory_consolidation: short-term prune complete"
        );

        // Pass 2 — bounded, non-destructive duplicate review.
        let records_deduped = review_archival_equivalence(db)?;
        tracing::debug!(
            records_deduped,
            "memory_consolidation: archival equivalence review complete"
        );

        Ok(JobOutcome {
            job_name: self.name(),
            records_pruned,
            records_deduped,
        })
    }
}

// ── Plugin auto-update job (#652) + delisting auto-uninstall (#658) ─────────

/// Preserved plugin-update job shape (CC parity, crosslink #652).
///
/// Walks the supplied snapshot and emits an explicit *unavailable* diagnostic;
/// it performs no marketplace request and never claims that it polled or
/// updated a plugin.
///
/// The actual version check and signed transactional update remain owned by
/// S-061/S-062/S-084. Production does not schedule this job.
pub struct PluginAutoupdateJob {
    /// Discovery snapshot supplied by the caller — a list of
    /// `(plugin_id, current_version)` pairs. Cloned out of the live
    /// [`PluginManager`][crate::plugins::manager::PluginManager] at job
    /// construction time so the scheduler stays free of plugin-layer
    /// borrow lifetimes.
    plugins: Vec<(String, Option<String>)>,
}

impl PluginAutoupdateJob {
    /// Build a job that will check `plugins` on every tick.
    #[must_use]
    pub const fn new(plugins: Vec<(String, Option<String>)>) -> Self {
        Self { plugins }
    }
}

impl BackgroundJob for PluginAutoupdateJob {
    fn name(&self) -> &'static str {
        "plugin_autoupdate"
    }

    fn run(&self, _db: &Arc<MemoryDb>) -> Result<JobOutcome> {
        for (plugin_id, version) in &self.plugins {
            tracing::debug!(
                event = "plugin_autoupdate_check",
                plugin_id,
                current_version = version.as_deref().unwrap_or("unknown"),
                "plugin update check unavailable; no marketplace request was made"
            );
        }
        Ok(JobOutcome {
            job_name: "plugin_autoupdate",
            records_pruned: 0,
            records_deduped: 0,
        })
    }
}

/// Preserved plugin-delisting job shape (CC parity, crosslink #658).
///
/// Emits an explicit *unavailable* diagnostic for each supplied snapshot. It
/// performs no marketplace request and never claims that it checked or removed
/// a plugin.
///
/// Phase 1 scope mirrors [`PluginAutoupdateJob`]: scheduling slot now,
/// marketplace transport later. The job is parameterised with the same
/// `(plugin_id, source)` snapshot the auto-update job consumes so the
/// caller wires a single discovery pass through both.
pub struct PluginDelistingJob {
    plugins: Vec<(String, String)>,
}

impl PluginDelistingJob {
    /// Construct from `(plugin_id, source_url_or_marketplace_name)` pairs.
    #[must_use]
    pub const fn new(plugins: Vec<(String, String)>) -> Self {
        Self { plugins }
    }
}

impl BackgroundJob for PluginDelistingJob {
    fn name(&self) -> &'static str {
        "plugin_delisting_check"
    }

    fn run(&self, _db: &Arc<MemoryDb>) -> Result<JobOutcome> {
        for (plugin_id, source) in &self.plugins {
            tracing::debug!(
                event = "plugin_delisting_check",
                plugin_id,
                source,
                "plugin delisting check unavailable; no marketplace request was made"
            );
        }
        Ok(JobOutcome {
            job_name: "plugin_delisting_check",
            records_pruned: 0,
            records_deduped: 0,
        })
    }
}

/// Review equal-content records without calling them equivalent.
///
/// The immutable revision layer handles exact retry identity. Separate logical
/// IDs are preserved even if their content bytes match because source, scope,
/// authorship, and applicability can differ. A future explicit merge operation
/// must carry a reviewed equivalence proof; this background job has none.
fn review_archival_equivalence(db: &Arc<MemoryDb>) -> Result<usize> {
    use std::collections::HashMap;

    const REVIEW_LIMIT: usize = 4_096;
    let all = db.memory_list(REVIEW_LIMIT + 1)?;
    anyhow::ensure!(
        all.len() <= REVIEW_LIMIT,
        "memory consolidation review budget exceeded"
    );
    let mut groups: HashMap<String, Vec<crate::memory::LogicalMemoryId>> = HashMap::new();
    for entry in all {
        groups
            .entry(entry.content.clone())
            .or_default()
            .push(entry.logical_id);
    }
    for logical_ids in groups.values().filter(|ids| ids.len() > 1) {
        tracing::debug!(
            event = "memory_consolidation_distinct_equal_content",
            record_count = logical_ids.len(),
            "equal content retained because logical identity/provenance differ"
        );
        if logical_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            anyhow::bail!("duplicate logical identity escaped revision reconciliation");
        }
    }
    Ok(0)
}

// ── AgentSummary job (crosslink #635) ───────────────────────────────────────

/// Preserved background summarisation prototype for subagent state.
///
/// Crosslink #635 — subagents accumulate per-task state (task lists, tool
/// outputs, intermediate notes) that the parent agent rarely re-reads
/// verbatim. This job condenses each completed subagent task's metadata
/// into a single archival memory row tagged `agent-summary`, so the
/// parent's `memory_search` can recall "what did the subagent do for
/// task X?" without paging through the original turns.
///
/// This is not a production summarizer. It walks the
/// memory database for rows tagged with `subagent-task:*` (the
/// established subagent-record tag) and folds same-task rows into a
/// single archival row. The prototype concatenates bounded source bodies; it
/// does not perform a semantic summary. Safe activation requires the canonical
/// task evidence, provenance, review, and transactional work in
/// S-052/S-053/S-055.
pub struct AgentSummaryJob;

impl BackgroundJob for AgentSummaryJob {
    fn name(&self) -> &'static str {
        "agent_summary"
    }

    fn run(&self, db: &Arc<MemoryDb>) -> Result<JobOutcome> {
        // Pull every row currently in archival memory and pick out the
        // ones carrying a `subagent-task:*` tag. This unbounded list pass is
        // preserved prototype behavior and must not be production-scheduled.
        let rows = db.memory_list(usize::MAX)?;
        let mut by_task: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        let mut existing_summary: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for row in rows {
            // Pre-existing summary rows are identified by the
            // `agent-summary` tag — collect them so we don't write a
            // duplicate on the next pass.
            if row.tags.iter().any(|t| t == "agent-summary") {
                for tag in &row.tags {
                    if let Some(task) = tag.strip_prefix("subagent-task:") {
                        existing_summary.insert(task.to_string());
                    }
                }
                continue;
            }
            for tag in &row.tags {
                if let Some(task) = tag.strip_prefix("subagent-task:") {
                    by_task
                        .entry(task.to_string())
                        .or_default()
                        .push(row.content.clone());
                }
            }
        }

        let mut summarised = 0usize;
        for (task, contents) in by_task {
            if existing_summary.contains(&task) {
                continue;
            }
            if contents.is_empty() {
                continue;
            }
            // Join with double-newline so the resulting body reads as
            // paragraphs in the agent's archival view. Cap at 4 KiB so
            // a runaway log doesn't bloat the row.
            let mut body = contents.join("\n\n");
            if body.len() > 4096 {
                let mut end = 4096;
                while end > 0 && !body.is_char_boundary(end) {
                    end -= 1;
                }
                body.truncate(end);
                body.push('…');
            }
            let tags = vec!["agent-summary".to_string(), format!("subagent-task:{task}")];
            match db.memory_save(&body, &tags) {
                Ok(_) => summarised += 1,
                Err(e) => tracing::warn!(
                    task = %task,
                    error = %e,
                    "AgentSummaryJob: failed to persist summary"
                ),
            }
        }

        Ok(JobOutcome {
            job_name: self.name(),
            records_pruned: 0,
            records_deduped: summarised,
        })
    }
}

// ── Scheduler ────────────────────────────────────────────────────────────────

/// Entry in the scheduler's job table.
struct ScheduledJob {
    job: Arc<dyn BackgroundJob>,
    interval: Duration,
    last_run: Option<Instant>,
}

/// Runs registered [`BackgroundJob`]s on a time-based schedule.
///
/// This type is an unavailable library/test primitive, not a production
/// scheduler. It is **synchronous** — callers drive it by calling
/// [`tick`][`JobScheduler::tick`] from their own event / idle loop.
/// This keeps the implementation free of `tokio` dependencies so it
/// compiles in unit-test harnesses that don't start a runtime.
///
/// ```rust
/// use std::sync::Arc;
/// use std::time::Duration;
/// use openclaudia::services::background::{JobScheduler, MemoryConsolidationJob};
/// use openclaudia::memory::MemoryDb;
///
/// let db = Arc::new(MemoryDb::open_for_project(std::path::Path::new("/tmp")).unwrap());
/// let mut sched = JobScheduler::new(Arc::clone(&db));
/// sched.register(Arc::new(MemoryConsolidationJob), Duration::from_secs(3600));
/// // Call `sched.tick()` from your idle loop; it only runs jobs whose
/// // interval has elapsed.
/// let outcomes = sched.tick();
/// ```
pub struct JobScheduler {
    db: Arc<MemoryDb>,
    jobs: Vec<ScheduledJob>,
}

impl JobScheduler {
    /// Create a new scheduler backed by `db`.
    #[must_use]
    pub const fn new(db: Arc<MemoryDb>) -> Self {
        Self {
            db,
            jobs: Vec::new(),
        }
    }

    /// Register a job to run at most once per `interval`.
    /// Jobs are checked in registration order; all due jobs run per
    /// [`tick`][`JobScheduler::tick`] call.
    pub fn register(&mut self, job: Arc<dyn BackgroundJob>, interval: Duration) {
        self.jobs.push(ScheduledJob {
            job,
            interval,
            last_run: None,
        });
    }

    /// Run every job whose interval has elapsed since its last run.
    ///
    /// Jobs that error are logged at `warn` level; their `last_run`
    /// timestamp is still updated so a persistently failing job doesn't
    /// spin-loop on every tick. Returns the outcomes of successful runs.
    pub fn tick(&mut self) -> Vec<JobOutcome> {
        let now = Instant::now();
        let mut outcomes = Vec::new();

        for entry in &mut self.jobs {
            let due = match entry.last_run {
                None => true,
                Some(last) => now.duration_since(last) >= entry.interval,
            };
            if !due {
                continue;
            }

            entry.last_run = Some(now);

            match entry.job.run(&self.db) {
                Ok(outcome) => {
                    tracing::info!(
                        job = outcome.job_name,
                        records_pruned = outcome.records_pruned,
                        records_deduped = outcome.records_deduped,
                        "background job completed"
                    );
                    outcomes.push(outcome);
                }
                Err(err) => {
                    tracing::warn!(
                        job = entry.job.name(),
                        error = %err,
                        "background job failed — will retry after interval"
                    );
                }
            }
        }

        outcomes
    }

    /// How many jobs are registered.
    #[must_use]
    pub const fn job_count(&self) -> usize {
        self.jobs.len()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// One hour; used by scheduler tests that need a "very long" interval.
    const ONE_HOUR: Duration = Duration::from_hours(1);

    fn make_db(tmp: &TempDir) -> Arc<MemoryDb> {
        Arc::new(MemoryDb::open_for_project(tmp.path()).unwrap())
    }

    // ── BackgroundJob trait ──────────────────────────────────────────────────

    /// The trait object is constructible and callable without a concrete type
    /// in scope — required for the scheduler's `Arc<dyn BackgroundJob>` storage.
    #[test]
    fn background_job_trait_is_object_safe() {
        // `accepts_job` takes a bare `&dyn BackgroundJob`.  If the trait were
        // not object-safe (e.g., a generic associated type or `Self` return)
        // this function would fail to compile.  The body is empty because the
        // assertion is purely a compile-time one: reaching this line without a
        // compiler error proves object safety.
        fn accepts_job(_job: &dyn BackgroundJob) {
            // Compile-time proof only — no runtime assertion needed.
        }
        accepts_job(&MemoryConsolidationJob);
    }

    /// `BackgroundJob` implementors must be `Send + Sync` (required for the
    /// `Arc<dyn BackgroundJob>` stored by the scheduler).
    #[test]
    fn background_job_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MemoryConsolidationJob>();
    }

    // ── MemoryConsolidationJob ───────────────────────────────────────────────

    #[test]
    fn consolidation_job_on_empty_db_succeeds() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let job = MemoryConsolidationJob;
        let outcome = job.run(&db).expect("run on empty db must not fail");
        assert_eq!(outcome.job_name, "memory_consolidation");
        assert_eq!(outcome.records_pruned, 0);
        assert_eq!(outcome.records_deduped, 0);
    }

    #[test]
    fn consolidation_job_name_is_stable() {
        let job = MemoryConsolidationJob;
        assert_eq!(job.name(), "memory_consolidation");
    }

    #[test]
    fn consolidation_prunes_expired_sessions() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);

        // Insert a session with a very old ended_at so it's beyond the
        // 48-hour expiry window.  We inject it via raw SQL since the
        // public API always sets ended_at = datetime('now').
        db.execute_raw(
            "INSERT INTO recent_sessions \
             (session_id, summary, files_modified, issues_worked, started_at, ended_at) \
             VALUES ('old-sess', 'old summary', '', '', \
             datetime('now', '-72 hours'), datetime('now', '-72 hours'))",
        )
        .unwrap();

        let stats_before = db.get_recent_sessions(100).unwrap();
        // The expired session falls outside the query window — confirming
        // the session is genuinely old and will be pruned.
        assert!(
            stats_before.is_empty(),
            "expired session must not appear in get_recent_sessions"
        );

        let outcome = MemoryConsolidationJob.run(&db).unwrap();
        // 1 session + 0 activities pruned.
        assert_eq!(outcome.records_pruned, 1);
    }

    #[test]
    fn consolidation_preserves_equal_content_with_distinct_identity() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);

        // Insert three entries: two with identical content, one unique.
        let id_a = db
            .memory_save("duplicate content", &["tag".to_string()])
            .unwrap();
        let id_b = db
            .memory_save("duplicate content", &["tag".to_string()])
            .unwrap();
        let id_unique = db.memory_save("unique content", &[]).unwrap();

        let outcome = MemoryConsolidationJob.run(&db).unwrap();
        assert_eq!(outcome.records_deduped, 0);

        let left = db.memory_get(id_a).unwrap().unwrap();
        let right = db.memory_get(id_b).unwrap().unwrap();
        assert_ne!(left.logical_id, right.logical_id);
        let survivor_count = [id_a, id_b, id_unique]
            .iter()
            .filter_map(|&id| db.memory_get(id).unwrap())
            .count();
        assert_eq!(survivor_count, 3);
    }

    #[test]
    fn consolidation_never_uses_timestamp_as_equivalence_proof() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);

        let id_older = db.memory_save("same content", &[]).unwrap();
        let id_newer = db.memory_save("temporary", &[]).unwrap();
        db.memory_update(id_newer, "same content").unwrap();

        let outcome = MemoryConsolidationJob.run(&db).unwrap();
        assert_eq!(outcome.records_deduped, 0);

        assert!(db.memory_get(id_older).unwrap().is_some());
        assert!(db.memory_get(id_newer).unwrap().is_some());
    }

    #[test]
    fn consolidation_leaves_unique_entries_intact() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);

        let id1 = db.memory_save("alpha", &[]).unwrap();
        let id2 = db.memory_save("beta", &[]).unwrap();
        let id3 = db.memory_save("gamma", &[]).unwrap();

        let outcome = MemoryConsolidationJob.run(&db).unwrap();
        assert_eq!(outcome.records_deduped, 0);

        assert!(db.memory_get(id1).unwrap().is_some());
        assert!(db.memory_get(id2).unwrap().is_some());
        assert!(db.memory_get(id3).unwrap().is_some());
    }

    // ── JobOutcome ───────────────────────────────────────────────────────────

    #[test]
    fn job_outcome_equality_and_debug() {
        let a = JobOutcome {
            job_name: "x",
            records_pruned: 1,
            records_deduped: 2,
        };
        let b = a.clone();
        assert_eq!(a, b);
        // Debug must not panic.
        let _ = format!("{a:?}");
    }

    // ── JobScheduler ─────────────────────────────────────────────────────────

    #[test]
    fn scheduler_registers_jobs() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let mut sched = JobScheduler::new(Arc::clone(&db));
        assert_eq!(sched.job_count(), 0);
        sched.register(Arc::new(MemoryConsolidationJob), Duration::from_secs(1));
        assert_eq!(sched.job_count(), 1);
    }

    #[test]
    fn scheduler_runs_job_on_first_tick() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let mut sched = JobScheduler::new(Arc::clone(&db));
        sched.register(Arc::new(MemoryConsolidationJob), ONE_HOUR);
        // First tick: job has never run, so it's always due.
        let outcomes = sched.tick();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].job_name, "memory_consolidation");
    }

    #[test]
    fn scheduler_skips_job_before_interval_elapses() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let mut sched = JobScheduler::new(Arc::clone(&db));
        // Very long interval — job won't be due on the second tick.
        sched.register(Arc::new(MemoryConsolidationJob), ONE_HOUR);
        let first = sched.tick();
        assert_eq!(first.len(), 1, "first tick must run the job");

        let second = sched.tick();
        assert!(
            second.is_empty(),
            "second tick must skip job (interval not elapsed)"
        );
    }

    #[test]
    fn scheduler_runs_multiple_jobs_independently() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let mut sched = JobScheduler::new(Arc::clone(&db));
        sched.register(Arc::new(MemoryConsolidationJob), ONE_HOUR);
        sched.register(Arc::new(MemoryConsolidationJob), ONE_HOUR);
        let outcomes = sched.tick();
        assert_eq!(outcomes.len(), 2, "both jobs must run on first tick");
    }

    #[test]
    fn scheduler_with_zero_interval_always_runs() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let mut sched = JobScheduler::new(Arc::clone(&db));
        // Zero interval → every tick is due.
        sched.register(Arc::new(MemoryConsolidationJob), Duration::ZERO);
        let first = sched.tick();
        let second = sched.tick();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1, "zero interval means always due");
    }

    // ── Custom job implementation ────────────────────────────────────────────

    /// Verify that user-defined jobs implementing the trait integrate cleanly
    /// with the scheduler — this is the contract third-party callers depend on.
    #[test]
    fn custom_job_integrates_with_scheduler() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingJob {
            runs: Arc<AtomicUsize>,
        }

        impl BackgroundJob for CountingJob {
            fn name(&self) -> &'static str {
                "counting"
            }

            fn run(&self, _db: &Arc<MemoryDb>) -> Result<JobOutcome> {
                self.runs.fetch_add(1, Ordering::SeqCst);
                Ok(JobOutcome {
                    job_name: self.name(),
                    records_pruned: 0,
                    records_deduped: 0,
                })
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let mut sched = JobScheduler::new(Arc::clone(&db));
        sched.register(
            Arc::new(CountingJob {
                runs: Arc::clone(&counter),
            }),
            Duration::ZERO,
        );

        sched.tick();
        sched.tick();
        sched.tick();
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    // ── #635 AgentSummaryJob tests ────────────────────────────────────────────

    #[test]
    fn agent_summary_job_name_is_stable() {
        assert_eq!(AgentSummaryJob.name(), "agent_summary");
    }

    #[test]
    fn agent_summary_job_emits_summary_for_subagent_task() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);

        // Two rows for the same subagent task — must be folded into ONE
        // summary row tagged `agent-summary` + `subagent-task:T1`.
        db.memory_save(
            "step 1 — looked up the user",
            &["subagent-task:T1".to_string(), "tool-output".to_string()],
        )
        .unwrap();
        db.memory_save(
            "step 2 — applied the patch",
            &["subagent-task:T1".to_string(), "tool-output".to_string()],
        )
        .unwrap();

        let outcome = AgentSummaryJob.run(&db).unwrap();
        assert_eq!(outcome.job_name, "agent_summary");
        assert_eq!(outcome.records_deduped, 1, "one summary row created");

        // The summary must be queryable via memory_search.
        let hits = db.memory_search("applied the patch", 10).unwrap();
        assert!(hits
            .iter()
            .any(|r| r.tags.contains(&"agent-summary".to_string())
                && r.tags.contains(&"subagent-task:T1".to_string())));
    }

    #[test]
    fn agent_summary_job_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        db.memory_save("subagent step", &["subagent-task:T2".to_string()])
            .unwrap();

        let first = AgentSummaryJob.run(&db).unwrap();
        assert_eq!(first.records_deduped, 1);

        // Second pass must NOT create a new summary row because the task
        // already has one.
        let second = AgentSummaryJob.run(&db).unwrap();
        assert_eq!(
            second.records_deduped, 0,
            "AgentSummaryJob must be idempotent across passes"
        );
    }

    // ── #652 / #658: plugin auto-update + delisting jobs ───────────────────

    /// `PluginAutoupdateJob::run` is a no-op for an empty plugin list and
    /// produces an outcome that the scheduler can ingest.
    #[test]
    fn plugin_autoupdate_job_runs_on_empty_list() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let job = PluginAutoupdateJob::new(vec![]);
        let outcome = job.run(&db).expect("empty list run must succeed");
        assert_eq!(outcome.job_name, "plugin_autoupdate");
        assert_eq!(outcome.records_pruned, 0);
        assert_eq!(outcome.records_deduped, 0);
        assert_eq!(job.name(), "plugin_autoupdate");
    }

    /// `PluginDelistingJob::run` is a no-op for an empty plugin list.
    #[test]
    fn plugin_delisting_job_runs_on_empty_list() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let job = PluginDelistingJob::new(vec![]);
        let outcome = job.run(&db).expect("empty list run must succeed");
        assert_eq!(outcome.job_name, "plugin_delisting_check");
        assert_eq!(job.name(), "plugin_delisting_check");
    }

    /// Both jobs satisfy the `BackgroundJob` object-safety contract so the
    /// scheduler can hold them behind `Arc<dyn BackgroundJob>`.
    #[test]
    fn plugin_jobs_are_object_safe() {
        let _: Arc<dyn BackgroundJob> = Arc::new(PluginAutoupdateJob::new(vec![]));
        let _: Arc<dyn BackgroundJob> = Arc::new(PluginDelistingJob::new(vec![]));
    }

    /// Carrying a small plugin list through the run path doesn't panic and
    /// returns the same outcome shape (only the log volume changes).
    #[test]
    fn plugin_autoupdate_job_runs_with_populated_list() {
        let tmp = TempDir::new().unwrap();
        let db = make_db(&tmp);
        let job = PluginAutoupdateJob::new(vec![
            ("p1".into(), Some("1.0.0".into())),
            ("p2".into(), None),
        ]);
        assert!(job.run(&db).is_ok());
    }
}

//! Guardrails module for coding safety enforcement
//!
//! Provides three guardrail mechanisms:
//! - **Blast radius limiting**: atomically constrains effects/resources per run
//! - **Diff size monitoring**: flags when changes exceed expected scope
//! - **Quality gates**: automated code quality checks
//!
//! Also provides language detection utilities shared with the VDD engine.

use regex::Regex;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::{
    BlastRadiusConfig, DiffMonitorConfig, GuardrailAction, GuardrailMode, GuardrailsConfig,
    QualityGatesConfig, RunAfter,
};

// ==========================================================================
// Explicit run-scoped guardrails registry
// ==========================================================================

/// Tri-state holder for one exact run generation's guardrails engine.
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
enum GuardrailsState {
    Disabled,
    // Box keeps the variant size small (~16 B vs ~280 B inline). The
    // engine is constructed once at startup and dereferenced on every
    // tool dispatch, so the heap indirection is negligible compared to
    // the regex match it gates.
    Enabled(Box<GuardrailsEngine>),
}

#[derive(Default)]
struct GuardrailsRegistry {
    /// A poisoned registry is sticky and fail-closed for every run,
    /// including runs not yet inserted into `runs`.
    poisoned: bool,
    runs: HashMap<(crate::runtime::RunId, crate::runtime::CapabilityGeneration), GuardrailsState>,
}

static GUARDRAILS: std::sync::LazyLock<Mutex<GuardrailsRegistry>> =
    std::sync::LazyLock::new(|| Mutex::new(GuardrailsRegistry::default()));

fn run_key(
    run: &crate::tools::ToolRunContext,
) -> (crate::runtime::RunId, crate::runtime::CapabilityGeneration) {
    (run.run_id(), run.generation())
}

/// Sentinel error string returned at every security boundary when the
/// guardrails mutex is found poisoned. The exact text is part of the
/// public contract — callers (and tests in #749) match against this
/// substring to distinguish poison-fail-closed from a rule-driven deny.
const POISON_ERR: &str = "guardrails poisoned — refusing access";

/// Lock the process registry mutex, transitioning the registry to a sticky
/// poisoned state on OS-level poison. After this point every
/// security-boundary check returns `Err(POISON_ERR)` until the
/// process restarts.
fn lock_or_poison() -> std::sync::MutexGuard<'static, GuardrailsRegistry> {
    match GUARDRAILS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!(
                "Guardrails mutex was poisoned by a previous panic;                  transitioning to fail-closed state"
            );
            let mut guard = poisoned.into_inner();
            guard.poisoned = true;
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

/// Initialize the guardrails engine for one explicit run at startup.
///
/// If the state is poisoned, this function does NOT reconfigure — the
/// poisoned state is sticky on purpose so a panic during a write-policy
/// evaluation cannot be papered over by a subsequent `configure()`.
///
/// # Errors
///
/// Returns an error when policy compilation fails, the registry is poisoned,
/// or policy is already immutably bound to this exact run generation.
pub fn configure(
    run: &Arc<crate::tools::ToolRunContext>,
    config: &GuardrailsConfig,
) -> Result<(), String> {
    // Build the new state OUTSIDE the lock. `GuardrailsEngine::try_from_config`
    // walks regex / glob compilation and emits structured `info!` events;
    // none of that needs the guardrails mutex held. Tightening the critical
    // section to the swap also lets concurrent `check_file_access` calls
    // make progress while a startup `configure` is mid-flight.
    let engine = GuardrailsEngine::try_from_config(run, config)?;
    let policy_sha256 = guardrails_policy_sha256(config)?;
    let (new_state, log_msg) = if config_has_active_guards(config) {
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
        if guard.poisoned {
            error!("Refusing to (re)configure guardrails: state is poisoned");
            return Err(POISON_ERR.to_string());
        }
        if guard.runs.contains_key(&run_key(run)) {
            return Err(format!(
                "Guardrails are already bound to run {} generation {}; derive a new run generation to change policy",
                run.run_id(),
                run.generation()
            ));
        }
        let policy_changed = crate::evidence_freshness::bind_policy(run, policy_sha256)?;
        if policy_changed {
            crate::ledger::invalidate_verification_receipts_for_run(run);
        }
        guard.runs.insert(run_key(run), new_state);
        // Drop the guard at the end of this block (before the `info!`
        // below) so concurrent readers do not block while we format the
        // log line. Per `clippy::significant_drop_tightening`.
    }
    info!("{}", log_msg);
    Ok(())
}

fn guardrails_policy_sha256(config: &GuardrailsConfig) -> Result<String, String> {
    let encoded = serde_json::to_vec(config)
        .map_err(|error| format!("cannot serialize guardrails policy identity: {error}"))?;
    let mut digest = Sha256::new();
    digest.update(crate::evidence_freshness::VERIFICATION_POLICY_VERSION.to_le_bytes());
    digest.update(encoded);
    let digest = digest.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
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
/// Compatibility boundary for host-mediated file operations. Model tool
/// dispatch uses [`reserve_tool_effect`] so all effect families share one
/// atomic admission path. This function still fails closed on poison.
pub fn check_file_access(run: &crate::tools::ToolRunContext, path: &str) -> Result<(), String> {
    let blast_radius = blast_radius_for_run(run)?;
    let Some(blast_radius) = blast_radius else {
        return Ok(());
    };
    let (resource, policy_path) = normalize_capability_path(run, path)?;
    let resources = if blast_radius.tracks_resources() {
        HashSet::from([resource])
    } else {
        HashSet::new()
    };
    let mut reservation = blast_radius.reserve(
        PendingReservation {
            tool_calls: 0,
            mutations: 0,
            lines: 0,
            resources,
        },
        Some(&policy_path),
    )?;
    reservation.commit();
    Ok(())
}

fn blast_radius_for_run(
    run: &crate::tools::ToolRunContext,
) -> Result<Option<Arc<BlastRadiusGuard>>, String> {
    let guard = lock_or_poison();
    if guard.poisoned {
        error!(
            session_id = run.session_id(),
            "Blast radius lookup found poisoned registry — denying"
        );
        return Err(POISON_ERR.to_string());
    }
    Ok(match guard.runs.get(&run_key(run)) {
        Some(GuardrailsState::Enabled(engine)) => engine.blast_radius.clone(),
        Some(GuardrailsState::Disabled) | None => None,
    })
}

fn normalize_capability_path(
    run: &crate::tools::ToolRunContext,
    target: &str,
) -> Result<(PathBuf, String), String> {
    let canonical = crate::tools::resolve_capability_path(run, target)?;
    let policy_path = canonical.strip_prefix(run.project_root()).map_or_else(
        |_| normalize_path(&canonical.to_string_lossy()),
        |relative| {
            if relative.as_os_str().is_empty() {
                ".".to_string()
            } else {
                normalize_path(&relative.to_string_lossy())
            }
        },
    );
    Ok((canonical, policy_path))
}

/// Pending admission for one classified tool invocation.
///
/// Dropping without [`Self::commit`] releases the reservation, which covers
/// policy denial, cancellation, handler errors, and early returns. Successful
/// and typed-partial results commit before the token leaves the executor.
pub(crate) struct EffectReservation {
    inner: Option<LedgerReservation>,
    freshness: Option<crate::evidence_freshness::MutationReservation>,
    run_id: crate::runtime::RunId,
    generation: crate::runtime::CapabilityGeneration,
    effect: crate::tools::effect::ToolEffect,
    canonical: String,
    target: String,
}

impl EffectReservation {
    /// Commit the effect after a successful or explicitly partial outcome.
    pub(crate) fn commit(&mut self) {
        if let Some(mut freshness) = self.freshness.take() {
            if let Err(error) = freshness.commit() {
                tracing::error!(
                    target: "openclaudia::guardrails",
                    run_id = %self.run_id,
                    generation = %self.generation,
                    %error,
                    "Failed to advance evidence freshness after a completed mutation"
                );
            }
            crate::ledger::invalidate_verification_receipts_for_binding(
                self.run_id,
                self.generation,
            );
        }
        if let Some(mut inner) = self.inner.take() {
            let reservation_id = inner.id();
            inner.commit();
            tracing::info!(
                target: "openclaudia::guardrails",
                event = "blast_radius_reservation_committed",
                run_id = %self.run_id,
                generation = %self.generation,
                reservation_id,
                effect = self.effect.as_str(),
                capability = self.canonical,
                resource = self.target,
                "Committed run-scoped blast radius reservation"
            );
        }
    }
}

impl Drop for EffectReservation {
    fn drop(&mut self) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        tracing::info!(
            target: "openclaudia::guardrails",
            event = "blast_radius_reservation_released",
            run_id = %self.run_id,
            generation = %self.generation,
            reservation_id = inner.id(),
            effect = self.effect.as_str(),
            capability = self.canonical,
            resource = self.target,
            "Released uncommitted run-scoped blast radius reservation"
        );
    }
}

/// Reserve one mandatory effect classification before handler dispatch.
///
/// # Errors
///
/// Returns a denial when the exact run policy is unavailable, the path target
/// cannot be capability-normalized, path policy refuses the canonical target,
/// or any atomic quota would be exceeded.
pub(crate) fn reserve_tool_effect(
    run: &crate::tools::ToolRunContext,
    resolved: &crate::tools::effect::ResolvedEffect,
) -> Result<EffectReservation, String> {
    let blast_radius = blast_radius_for_run(run)?;
    let Some(blast_radius) = blast_radius else {
        let freshness = crate::evidence_freshness::reserve_mutation(run, resolved.effect)?;
        return Ok(EffectReservation {
            inner: None,
            freshness,
            run_id: run.run_id(),
            generation: run.generation(),
            effect: resolved.effect,
            canonical: resolved.canonical.clone(),
            target: resolved.target.clone(),
        });
    };

    let (resources, policy_path, trace_target) = if matches!(
        resolved.target_kind,
        crate::tools::effect::ToolTargetKind::Path
            | crate::tools::effect::ToolTargetKind::PathScope
    ) {
        let (resource, policy_path) = normalize_capability_path(run, &resolved.target)?;
        let trace_target = resource.to_string_lossy().into_owned();
        let resources = if resolved.target_kind == crate::tools::effect::ToolTargetKind::Path
            && blast_radius.tracks_resources()
        {
            HashSet::from([resource])
        } else {
            HashSet::new()
        };
        (resources, Some(policy_path), trace_target)
    } else {
        (HashSet::new(), None, resolved.target.clone())
    };
    let pending = PendingReservation {
        tool_calls: 1,
        mutations: u64::from(resolved.effect.is_mutation()),
        lines: 0,
        resources,
    };
    let inner = if resolved.target_kind == crate::tools::effect::ToolTargetKind::PathScope {
        if let Some(path) = policy_path.as_deref() {
            blast_radius.check_scope(path)?;
        }
        blast_radius.reserve(pending, None)?
    } else {
        blast_radius.reserve(pending, policy_path.as_deref())?
    };
    let reservation_id = inner.id();
    let freshness = crate::evidence_freshness::reserve_mutation(run, resolved.effect)?;
    tracing::info!(
        target: "openclaudia::guardrails",
        event = "blast_radius_effect_reserved",
        run_id = %run.run_id(),
        generation = %run.generation(),
        reservation_id,
        effect = resolved.effect.as_str(),
        capability = resolved.canonical,
        resource = trace_target,
        "Reserved classified effect against exact run quota"
    );
    Ok(EffectReservation {
        inner: Some(inner),
        freshness,
        run_id: run.run_id(),
        generation: run.generation(),
        effect: resolved.effect,
        canonical: resolved.canonical.clone(),
        target: trace_target,
    })
}

/// Reserve one host-mediated workspace mutation that occurs below a tool
/// handler (for example, creating the exact run's plan file).
pub(crate) fn reserve_workspace_mutation(
    run: &crate::tools::ToolRunContext,
    path: &str,
) -> Result<EffectReservation, String> {
    let blast_radius = blast_radius_for_run(run)?;
    let Some(blast_radius) = blast_radius else {
        let freshness = crate::evidence_freshness::reserve_mutation(
            run,
            crate::tools::effect::ToolEffect::WorkspaceMutation,
        )?;
        return Ok(EffectReservation {
            inner: None,
            freshness,
            run_id: run.run_id(),
            generation: run.generation(),
            effect: crate::tools::effect::ToolEffect::WorkspaceMutation,
            canonical: "HostWorkspaceWrite".to_string(),
            target: path.to_string(),
        });
    };
    let (resource, policy_path) = normalize_capability_path(run, path)?;
    let trace_target = resource.to_string_lossy().into_owned();
    let resources = if blast_radius.tracks_resources() {
        HashSet::from([resource])
    } else {
        HashSet::new()
    };
    let inner = blast_radius.reserve(
        PendingReservation {
            mutations: 1,
            resources,
            ..PendingReservation::default()
        },
        Some(&policy_path),
    )?;
    let freshness = crate::evidence_freshness::reserve_mutation(
        run,
        crate::tools::effect::ToolEffect::WorkspaceMutation,
    )?;
    Ok(EffectReservation {
        inner: Some(inner),
        freshness,
        run_id: run.run_id(),
        generation: run.generation(),
        effect: crate::tools::effect::ToolEffect::WorkspaceMutation,
        canonical: "HostWorkspaceWrite".to_string(),
        target: trace_target,
    })
}

/// Reservation for exact changed-line impact prepared by a file handler.
pub(crate) struct ChangedLineReservation {
    inner: Option<LedgerReservation>,
}

impl ChangedLineReservation {
    /// Commit after the descriptor-backed write succeeds.
    pub(crate) fn commit(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            inner.commit();
        }
    }

    /// Replace the predicted line impact with the observable partial effect,
    /// then commit it even if the write itself returned a failure.
    pub(crate) fn reconcile_and_commit(&mut self, changed_lines: u64) {
        let Some(mut inner) = self.inner.take() else {
            return;
        };
        inner.reconcile_lines(changed_lines);
        inner.commit();
    }
}

/// Atomically reserve exact inserted-plus-deleted line impact before writing.
///
/// # Errors
///
/// Returns a denial if the exact run ledger is poisoned or the concurrent
/// projected changed-line total would exceed the configured per-run limit.
pub(crate) fn reserve_changed_lines(
    run: &crate::tools::ToolRunContext,
    changed_lines: u64,
) -> Result<ChangedLineReservation, String> {
    let Some(blast_radius) = blast_radius_for_run(run)? else {
        return Ok(ChangedLineReservation { inner: None });
    };
    let inner = blast_radius.reserve(
        PendingReservation {
            lines: changed_lines,
            ..PendingReservation::default()
        },
        None,
    )?;
    Ok(ChangedLineReservation { inner: Some(inner) })
}

/// One atomic batch of concrete file identities discovered by a recursive
/// read/search handler.
///
/// The root argument is classified as a
/// [`crate::tools::effect::ToolTargetKind::PathScope`] and
/// checked by the canonical executor without consuming a file slot. Each leaf
/// that the handler will disclose or read is added here before access. The
/// whole batch commits only when the handler succeeds; denial or early return
/// drops one ledger reservation and releases every pending identity together.
pub(crate) struct PathResourceBatch {
    inner: Option<LedgerReservation>,
    guard: Option<Arc<BlastRadiusGuard>>,
    run_id: crate::runtime::RunId,
    generation: crate::runtime::CapabilityGeneration,
    resource_count: u64,
}

impl PathResourceBatch {
    fn ensure_run(&self, run: &crate::tools::ToolRunContext) -> Result<(), String> {
        if self.run_id == run.run_id() && self.generation == run.generation() {
            Ok(())
        } else {
            Err("Blast radius: resource batch used with a different run generation".to_string())
        }
    }

    /// Check one directory/path scope against canonical policy without
    /// charging it as a file identity.
    pub(crate) fn check_scope(
        &self,
        run: &crate::tools::ToolRunContext,
        target: &Path,
    ) -> Result<(), String> {
        self.ensure_run(run)?;
        let Some(guard) = self.guard.as_ref() else {
            return Ok(());
        };
        let (_, policy_path) = normalize_capability_path(run, &target.to_string_lossy())?;
        guard.check_scope(&policy_path)
    }

    /// Check a directory identity before returning its name to the caller.
    /// This is stricter than traversal admission: a traversal may pass through
    /// a wildcard-bearing branch to reach an allowed leaf, but `list_files`
    /// must not disclose an unrelated directory merely because it was opened.
    pub(crate) fn check_disclosed_scope(
        &self,
        run: &crate::tools::ToolRunContext,
        target: &Path,
    ) -> Result<(), String> {
        self.ensure_run(run)?;
        let Some(guard) = self.guard.as_ref() else {
            return Ok(());
        };
        let (_, policy_path) = normalize_capability_path(run, &target.to_string_lossy())?;
        guard.check_disclosed_scope(&policy_path)
    }

    /// Atomically add one concrete file identity before the handler discloses
    /// or reads it.
    pub(crate) fn reserve_file(
        &mut self,
        run: &crate::tools::ToolRunContext,
        target: &Path,
    ) -> Result<(), String> {
        self.ensure_run(run)?;
        let Some(guard) = self.guard.as_ref() else {
            return Ok(());
        };
        let (resource, policy_path) = normalize_capability_path(run, &target.to_string_lossy())?;
        let Some(inner) = self.inner.as_ref() else {
            guard.check_path(&policy_path)?;
            return Ok(());
        };
        let inserted = guard.add_resource(inner.id(), resource.clone(), &policy_path)?;
        if inserted {
            self.resource_count = self.resource_count.saturating_add(1);
            tracing::info!(
                target: "openclaudia::guardrails",
                event = "blast_radius_resource_reserved",
                run_id = %self.run_id,
                generation = %self.generation,
                reservation_id = inner.id(),
                resource = %resource.display(),
                "Reserved concrete file identity in run-scoped batch"
            );
        }
        Ok(())
    }

    /// Commit all concrete identities after the enclosing handler succeeds.
    pub(crate) fn commit(&mut self) {
        let Some(mut inner) = self.inner.take() else {
            return;
        };
        let reservation_id = inner.id();
        inner.commit();
        tracing::info!(
            target: "openclaudia::guardrails",
            event = "blast_radius_resource_batch_committed",
            run_id = %self.run_id,
            generation = %self.generation,
            reservation_id,
            resource_count = self.resource_count,
            "Committed concrete file identities for recursive tool"
        );
    }
}

impl Drop for PathResourceBatch {
    fn drop(&mut self) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        tracing::info!(
            target: "openclaudia::guardrails",
            event = "blast_radius_resource_batch_released",
            run_id = %self.run_id,
            generation = %self.generation,
            reservation_id = inner.id(),
            resource_count = self.resource_count,
            "Released concrete file identities for failed recursive tool"
        );
    }
}

/// Begin an empty concrete-resource batch for one exact run.
pub(crate) fn begin_path_resource_batch(
    run: &crate::tools::ToolRunContext,
) -> Result<PathResourceBatch, String> {
    let guard = blast_radius_for_run(run)?;
    let inner = guard
        .as_ref()
        .filter(|guard| guard.tracks_resources())
        .map(|guard| guard.reserve(PendingReservation::default(), None))
        .transpose()?;
    Ok(PathResourceBatch {
        inner,
        guard,
        run_id: run.run_id(),
        generation: run.generation(),
        resource_count: 0,
    })
}

/// Record a file modification for diff monitoring.
/// Call after successful `write_file` or `edit_file`.
///
/// Non-security path: silently no-ops when disabled, logs an error
/// when the mutex is poisoned.
pub fn record_file_modification(
    run: &crate::tools::ToolRunContext,
    path: &str,
    _lines_added: u32,
    _lines_removed: u32,
) {
    run.record_skill_path_touch(std::path::Path::new(path));
}

/// Pre-publication permit for one exact diff candidate. Dropping the permit
/// releases it without advancing the run's diff revision; committing records
/// the exact candidate that was actually published.
pub(crate) struct DiffChangePermit {
    monitor: Option<Arc<DiffMonitor>>,
    stats: Option<Result<DiffStats, String>>,
    edit_revision: Option<Arc<AtomicU64>>,
    _lease: Option<DiffMutationLease>,
}

impl DiffChangePermit {
    pub(crate) fn commit(mut self) {
        if let (Some(monitor), Some(stats)) = (self.monitor.take(), self.stats.take()) {
            monitor.commit_stats(stats);
        }
        if let Some(revision) = self.edit_revision.take() {
            revision.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub(crate) fn reconcile_live(mut self) {
        if let Some(monitor) = self.monitor.take() {
            monitor.commit_stats(monitor.evaluate_live());
        }
        self.stats = None;
        if let Some(revision) = self.edit_revision.take() {
            revision.fetch_add(1, Ordering::AcqRel);
        }
    }
}

/// Run-bound handle carried by a transactional workspace projection. The
/// candidate tree is evaluated before its bytes are published to the host.
#[derive(Clone)]
#[cfg(target_os = "linux")]
pub(crate) struct WorkspaceDiffGate {
    monitor: Option<Arc<DiffMonitor>>,
    edit_revision: Arc<AtomicU64>,
}

#[cfg(target_os = "linux")]
impl WorkspaceDiffGate {
    pub(crate) fn admit_candidate(&self, candidate: &Path) -> Result<DiffChangePermit, String> {
        let Some(monitor) = &self.monitor else {
            return Ok(DiffChangePermit {
                monitor: None,
                stats: None,
                edit_revision: Some(Arc::clone(&self.edit_revision)),
                _lease: None,
            });
        };
        let lease = monitor.begin_change()?;
        admit_diff_candidate(
            Arc::clone(monitor),
            monitor.evaluate_root(candidate),
            Arc::clone(&self.edit_revision),
            lease,
        )
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn workspace_diff_gate(
    run: &crate::tools::ToolRunContext,
) -> Result<Option<WorkspaceDiffGate>, String> {
    let guard = lock_or_poison();
    if guard.poisoned {
        return Err(POISON_ERR.to_string());
    }
    Ok(match guard.runs.get(&run_key(run)) {
        Some(GuardrailsState::Enabled(engine)) => Some(WorkspaceDiffGate {
            monitor: engine.diff_monitor.clone(),
            edit_revision: Arc::clone(&engine.workspace_edits),
        }),
        Some(GuardrailsState::Disabled) | None => None,
    })
}

pub(crate) fn admit_file_change(
    run: &crate::tools::ToolRunContext,
    canonical_path: &Path,
    content: &[u8],
) -> Result<DiffChangePermit, String> {
    let guard = lock_or_poison();
    if guard.poisoned {
        return Err(POISON_ERR.to_string());
    }
    let Some(GuardrailsState::Enabled(engine)) = guard.runs.get(&run_key(run)) else {
        return Ok(DiffChangePermit {
            monitor: None,
            stats: None,
            edit_revision: None,
            _lease: None,
        });
    };
    let monitor = engine.diff_monitor.clone();
    let edit_revision = Arc::clone(&engine.workspace_edits);
    drop(guard);
    let Some(monitor) = monitor else {
        return Ok(DiffChangePermit {
            monitor: None,
            stats: None,
            edit_revision: Some(edit_revision),
            _lease: None,
        });
    };
    let lease = monitor.begin_change()?;
    let stats = monitor.evaluate_file_overlay(canonical_path, content);
    admit_diff_candidate(monitor, stats, edit_revision, lease)
}

fn admit_diff_candidate(
    monitor: Arc<DiffMonitor>,
    stats: Result<DiffStats, String>,
    edit_revision: Arc<AtomicU64>,
    lease: DiffMutationLease,
) -> Result<DiffChangePermit, String> {
    let refusal = match &stats {
        Ok(stats) => monitor.threshold_warning(stats).and_then(|warning| {
            (warning.action == GuardrailAction::Block).then_some(warning.message)
        }),
        Err(error) if monitor.config.action == GuardrailAction::Block => Some(format!(
            "Diff block could not evaluate the proposed workspace generation: {error}"
        )),
        Err(_) => None,
    };
    if let Some(reason) = refusal {
        return Err(reason);
    }
    Ok(DiffChangePermit {
        monitor: Some(monitor),
        stats: Some(stats),
        edit_revision: Some(edit_revision),
        _lease: Some(lease),
    })
}

fn diff_monitor_for_run(
    run: &crate::tools::ToolRunContext,
) -> Result<Option<Arc<DiffMonitor>>, String> {
    let guard = lock_or_poison();
    if guard.poisoned {
        return Err(POISON_ERR.to_string());
    }
    Ok(match guard.runs.get(&run_key(run)) {
        Some(GuardrailsState::Enabled(engine)) => engine.diff_monitor.clone(),
        Some(GuardrailsState::Disabled) | None => None,
    })
}

pub(crate) fn diff_revision(run: &crate::tools::ToolRunContext) -> u64 {
    let guard = lock_or_poison();
    if guard.poisoned {
        return 0;
    }
    match guard.runs.get(&run_key(run)) {
        Some(GuardrailsState::Enabled(engine)) => engine.workspace_edits.load(Ordering::Acquire),
        Some(GuardrailsState::Disabled) | None => 0,
    }
}

/// Check diff thresholds. Returns a warning if thresholds exceeded.
pub fn check_diff_thresholds(run: &crate::tools::ToolRunContext) -> Option<DiffWarning> {
    let monitor = match diff_monitor_for_run(run) {
        Ok(monitor) => monitor?,
        Err(error) => {
            error!(%error, "check_diff_thresholds: registry unavailable");
            return None;
        }
    };
    match monitor.evaluate_live() {
        Ok(stats) => monitor.threshold_warning(&stats),
        Err(error) => Some(DiffWarning {
            message: format!("Diff policy could not evaluate the live workspace: {error}"),
            stats: DiffStats::default(),
            action: monitor.config.action.clone(),
        }),
    }
}

/// Run quality gate checks. Returns results for each configured check.
pub fn run_quality_gates(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
    model_identity: &str,
) -> Vec<QualityCheckResult> {
    run_quality_gates_at(run, model_identity, RunAfter::EveryTurn)
        .map_or_else(Vec::new, |report| report.results)
}

/// Evaluate quality gates at an exact configured lifecycle cadence.
/// `None` means quality gates are disabled for the run; a configured but
/// non-matching cadence returns an explicit skipped report.
pub fn run_quality_gates_at(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
    model_identity: &str,
    cadence: RunAfter,
) -> Option<QualityGateReport> {
    let guard = lock_or_poison();
    if guard.poisoned {
        error!("run_quality_gates: registry poisoned — blocking configured verification");
        return Some(QualityGateReport {
            cadence: cadence.clone(),
            configured_cadence: cadence,
            action: GuardrailAction::Block,
            disposition: QualityGateDisposition::Blocked,
            results: Vec::new(),
            reason: Some(POISON_ERR.to_string()),
        });
    }
    let runner = match guard.runs.get(&run_key(run)) {
        Some(GuardrailsState::Enabled(engine)) => engine.quality_gates.clone(),
        Some(GuardrailsState::Disabled) | None => None,
    };
    drop(guard);
    runner.map(|runner| runner.run_at(run, model_identity, cadence))
}

/// Bind the model identity used by post-mutation quality-gate execution in
/// the shared tool executor.
pub(crate) fn bind_quality_gate_model(
    run: &crate::tools::ToolRunContext,
    model_identity: &str,
) -> Result<(), String> {
    let Some(runner) = quality_runner_for_run(run)? else {
        return Ok(());
    };
    runner.bind_model(model_identity)
}

/// Evaluate the configured cadence with the model identity already bound to
/// this exact run. Returns `None` only when quality gates are disabled.
pub fn run_bound_quality_gates_at(
    run: &crate::tools::ToolRunContext,
    cadence: RunAfter,
) -> Option<QualityGateReport> {
    match quality_runner_for_run(run) {
        Ok(Some(runner)) => Some(runner.run_bound_at(cadence)),
        Ok(None) => None,
        Err(error) => Some(registry_failure_report(cadence, &error)),
    }
}

pub(crate) fn quality_gate_report_for_finalization(
    run: &crate::tools::ToolRunContext,
    model_identity: &str,
) -> Option<QualityGateReport> {
    match quality_runner_for_run(run) {
        Ok(Some(runner)) => Some(runner.for_finalization(model_identity)),
        Ok(None) => None,
        Err(error) => Some(registry_failure_report(RunAfter::EveryTurn, &error)),
    }
}

fn registry_failure_report(cadence: RunAfter, error: &str) -> QualityGateReport {
    QualityGateReport {
        cadence: cadence.clone(),
        configured_cadence: cadence,
        action: GuardrailAction::Block,
        disposition: QualityGateDisposition::Blocked,
        results: Vec::new(),
        reason: Some(error.to_string()),
    }
}

fn quality_runner_for_run(
    run: &crate::tools::ToolRunContext,
) -> Result<Option<Arc<QualityGateRunner>>, String> {
    let guard = lock_or_poison();
    if guard.poisoned {
        return Err(POISON_ERR.to_string());
    }
    Ok(match guard.runs.get(&run_key(run)) {
        Some(GuardrailsState::Enabled(engine)) => engine.quality_gates.clone(),
        Some(GuardrailsState::Disabled) | None => None,
    })
}

/// Get current diff stats summary.
pub fn get_diff_summary(run: &crate::tools::ToolRunContext) -> Option<DiffStats> {
    diff_monitor_for_run(run)
        .ok()
        .flatten()
        .and_then(|monitor| monitor.evaluate_live().ok())
}

// ==========================================================================
// Test-only helpers for the run-scoped guardrails registry.
// ==========================================================================

/// Replace one run's guardrails state. Test-only. Used to drive
/// poisoned-state regression tests for crosslink #749.
#[cfg(test)]
fn set_state_for_test(run: &crate::tools::ToolRunContext, new_state: GuardrailsState) {
    let mut guard = GUARDRAILS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.poisoned = false;
    guard.runs.insert(run_key(run), new_state);
}

#[cfg(test)]
fn set_poisoned_for_test() {
    let mut guard = GUARDRAILS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.poisoned = true;
}

/// Snapshot the discriminant of the current state. Test-only.
#[cfg(test)]
fn current_state_kind(run: &crate::tools::ToolRunContext) -> &'static str {
    let guard = GUARDRAILS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.poisoned {
        return "poisoned";
    }
    match guard.runs.get(&run_key(run)) {
        Some(GuardrailsState::Enabled(_)) => "enabled",
        Some(GuardrailsState::Disabled) | None => "disabled",
    }
}

/// Release policy and mutable diff state for one completed run generation.
///
/// Called from the last-`Arc` lifecycle boundary so a long-lived process does
/// not retain stale policy buckets or accidentally associate them with a
/// resumed session generation.
pub(crate) fn release_run(run: &crate::tools::ToolRunContext) {
    {
        let mut guard = lock_or_poison();
        guard.runs.remove(&run_key(run));
    }
    crate::evidence_freshness::release_run(run);
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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffStats {
    pub lines_added: u32,
    pub lines_removed: u32,
    pub lines_changed: u32,
    pub files_changed: u32,
    pub file_list: Vec<String>,
}

/// Why a configured quality check reached its terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityCheckStatus {
    Passed,
    Failed,
    Skipped,
    Stale,
    Error,
}

/// Aggregate policy outcome for one configured quality-gate cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityGateDisposition {
    Passed,
    Warning,
    Findings,
    Blocked,
    Skipped,
}

/// Typed result of evaluating the configured quality checks at one lifecycle
/// boundary. A skipped cadence is distinct from an empty successful run.
#[derive(Debug, Clone)]
pub struct QualityGateReport {
    cadence: RunAfter,
    configured_cadence: RunAfter,
    action: GuardrailAction,
    disposition: QualityGateDisposition,
    results: Vec<QualityCheckResult>,
    reason: Option<String>,
}

impl QualityGateReport {
    #[must_use]
    pub const fn cadence(&self) -> &RunAfter {
        &self.cadence
    }

    #[must_use]
    pub const fn configured_cadence(&self) -> &RunAfter {
        &self.configured_cadence
    }

    #[must_use]
    pub const fn action(&self) -> &GuardrailAction {
        &self.action
    }

    #[must_use]
    pub const fn disposition(&self) -> QualityGateDisposition {
        self.disposition
    }

    #[must_use]
    pub fn results(&self) -> &[QualityCheckResult] {
        &self.results
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    #[must_use]
    pub const fn prevents_progress(&self) -> bool {
        matches!(
            self.disposition,
            QualityGateDisposition::Findings | QualityGateDisposition::Blocked
        )
    }
}

/// Result of running a single quality gate check
#[derive(Debug, Clone)]
pub struct QualityCheckResult {
    name: String,
    command: String,
    status: QualityCheckStatus,
    exit_code: i32,
    stdout: String,
    stderr: String,
    required: bool,
    evidence: QualityGateEvidence,
}

#[derive(Debug, Clone)]
pub(crate) struct QualityGateEvidence {
    pub(crate) run_id: crate::runtime::RunId,
    pub(crate) capability_generation: crate::runtime::CapabilityGeneration,
    pub(crate) normalized_argv: Vec<String>,
    pub(crate) resolved_executable: Option<String>,
    pub(crate) executable_sha256: Option<String>,
    pub(crate) verification_binding:
        Option<crate::evidence_freshness::VerificationFreshnessBinding>,
    pub(crate) freshness_error: Option<String>,
}

impl QualityCheckResult {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(self.status, QualityCheckStatus::Passed)
    }

    #[must_use]
    pub const fn status(&self) -> QualityCheckStatus {
        self.status
    }

    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }

    #[must_use]
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    #[must_use]
    pub(crate) const fn evidence(&self) -> &QualityGateEvidence {
        &self.evidence
    }
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
    blast_radius: Option<Arc<BlastRadiusGuard>>,
    diff_monitor: Option<Arc<DiffMonitor>>,
    quality_gates: Option<Arc<QualityGateRunner>>,
    workspace_edits: Arc<AtomicU64>,
}

impl GuardrailsEngine {
    fn try_from_config(
        run: &Arc<crate::tools::ToolRunContext>,
        config: &GuardrailsConfig,
    ) -> Result<Self, String> {
        // Compile even a disabled supplied section. A malformed policy must
        // never sit latent until a later reload enables it.
        let compiled_blast = config
            .blast_radius
            .as_ref()
            .map(|guard| BlastRadiusGuard::try_new(guard.clone()))
            .transpose()?;
        let blast_radius = compiled_blast
            .filter(|_| {
                config
                    .blast_radius
                    .as_ref()
                    .is_some_and(|guard| guard.enabled)
            })
            .map(Arc::new);

        if let Some(guard) = config.blast_radius.as_ref().filter(|guard| guard.enabled) {
            info!(
                mode = %guard.mode,
                allowed = guard.allowed_paths.len(),
                denied = guard.denied_paths.len(),
                max_files = ?guard.max_files_per_run,
                max_lines = ?guard.max_lines_per_run,
                max_tools = ?guard.max_tool_calls_per_run,
                max_mutations = ?guard.max_mutations_per_run,
                "Run-scoped blast radius guard enabled"
            );
        }

        let diff_monitor = config
            .diff_monitor
            .as_ref()
            .filter(|c| c.enabled)
            .map(|c| {
                info!(
                    max_lines = c.max_lines_changed,
                    max_files = c.max_files_changed,
                    action = %c.action,
                    "Diff monitor enabled"
                );
                DiffMonitor::try_new(run, c.clone()).map(Arc::new)
            })
            .transpose()?;

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
                QualityGateRunner::try_new(c.clone(), Arc::downgrade(run)).map(Arc::new)
            })
            .transpose()?;

        Ok(Self {
            blast_radius,
            diff_monitor,
            quality_gates,
            workspace_edits: Arc::new(AtomicU64::new(0)),
        })
    }
}

// ==========================================================================
// Blast Radius Guard
// ==========================================================================

struct BlastRadiusGuard {
    config: BlastRadiusConfig,
    allowed_patterns: Vec<CompiledPathPattern>,
    denied_patterns: Vec<CompiledPathPattern>,
    ledger: Mutex<ReservationLedger>,
}

impl BlastRadiusGuard {
    fn try_new(config: BlastRadiusConfig) -> Result<Self, String> {
        let allowed_patterns = compile_path_patterns("allowed", &config.allowed_paths)?;
        let denied_patterns = compile_path_patterns("denied", &config.denied_paths)?;

        Ok(Self {
            config,
            allowed_patterns,
            denied_patterns,
            ledger: Mutex::new(ReservationLedger::default()),
        })
    }

    fn ledger_guard(
        &self,
        operation: &'static str,
    ) -> Result<MutexGuard<'_, ReservationLedger>, String> {
        self.ledger.lock().map_err(|err| {
            error!(operation, error = %err, "Blast radius reservation ledger lock poisoned");
            format!("Blast radius: reservation ledger lock poisoned: {err}")
        })
    }

    const fn tracks_resources(&self) -> bool {
        self.config.max_files_per_run.is_some()
    }

    fn check_path(&self, normalized: &str) -> Result<(), String> {
        // Denied paths take priority
        for pattern in &self.denied_patterns {
            if pattern.regex.is_match(normalized) {
                return self.violation(format!(
                    "Blast radius: canonical path '{normalized}' matches deny list pattern"
                ));
            }
        }

        // If allowed_paths configured, path must match at least one
        if !self.allowed_patterns.is_empty() {
            let allowed = self
                .allowed_patterns
                .iter()
                .any(|pattern| pattern.regex.is_match(normalized));
            if !allowed {
                return self.violation(format!(
                    "Blast radius: canonical path '{normalized}' not in allowed list"
                ));
            }
        }

        Ok(())
    }

    fn check_scope(&self, normalized: &str) -> Result<(), String> {
        // A recursive root is a traversal scope, not a concrete file. Permit
        // ancestors and wildcard-bearing branches that may reach an allowed
        // leaf, but prune a statically denied subtree before opening it.
        for pattern in &self.denied_patterns {
            if pattern.denies_scope(normalized) {
                return self.violation(format!(
                    "Blast radius: canonical scope '{normalized}' matches deny list pattern"
                ));
            }
        }
        if !self.allowed_patterns.is_empty()
            && !self
                .allowed_patterns
                .iter()
                .any(|pattern| pattern.may_reach_from(normalized))
        {
            return self.violation(format!(
                "Blast radius: canonical scope '{normalized}' cannot reach the allowed list"
            ));
        }
        Ok(())
    }

    fn check_disclosed_scope(&self, normalized: &str) -> Result<(), String> {
        for pattern in &self.denied_patterns {
            if pattern.denies_scope(normalized) {
                return self.violation(format!(
                    "Blast radius: canonical scope '{normalized}' matches deny list pattern"
                ));
            }
        }
        if !self.allowed_patterns.is_empty()
            && !self
                .allowed_patterns
                .iter()
                .any(|pattern| pattern.covers_disclosed_scope(normalized))
        {
            return self.violation(format!(
                "Blast radius: canonical scope '{normalized}' not in allowed list"
            ));
        }
        Ok(())
    }

    fn violation(&self, message: String) -> Result<(), String> {
        match self.config.mode {
            GuardrailMode::Strict => {
                warn!("{} (BLOCKED)", message);
                Err(message)
            }
            GuardrailMode::Advisory => {
                warn!("{} (advisory)", message);
                Ok(())
            }
        }
    }

    fn reserve(
        self: &Arc<Self>,
        pending: PendingReservation,
        policy_path: Option<&str>,
    ) -> Result<LedgerReservation, String> {
        if let Some(path) = policy_path {
            self.check_path(path)?;
        }

        let mut ledger = self.ledger_guard("reserve")?;
        let projected_tools = ledger.projected_tool_calls(&pending)?;
        let projected_mutations = ledger.projected_mutations(&pending)?;
        let projected_lines = ledger.projected_lines(&pending)?;
        let projected_files = ledger.projected_files(&pending);

        self.check_limit(
            "tool calls",
            projected_tools,
            self.config
                .max_tool_calls_per_run
                .map(std::num::NonZeroU32::get),
        )?;
        self.check_limit(
            "mutations",
            projected_mutations,
            self.config
                .max_mutations_per_run
                .map(std::num::NonZeroU32::get),
        )?;
        self.check_limit(
            "changed lines",
            projected_lines,
            self.config.max_lines_per_run.map(std::num::NonZeroU32::get),
        )?;
        self.check_limit(
            "files",
            projected_files,
            self.config.max_files_per_run.map(std::num::NonZeroU32::get),
        )?;

        let id = ledger.next_reservation_id()?;
        ledger.pending.insert(id, pending);
        drop(ledger);
        Ok(LedgerReservation {
            guard: Arc::clone(self),
            id: Some(id),
        })
    }

    fn check_limit(&self, label: &str, projected: u64, limit: Option<u32>) -> Result<(), String> {
        let Some(limit) = limit else {
            return Ok(());
        };
        if projected <= u64::from(limit) {
            return Ok(());
        }
        self.violation(format!(
            "Blast radius: run-scoped {label} limit exceeded ({projected}/{limit})"
        ))
    }

    fn add_resource(
        &self,
        reservation_id: u64,
        resource: PathBuf,
        policy_path: &str,
    ) -> Result<bool, String> {
        self.check_path(policy_path)?;
        let mut ledger = self.ledger_guard("reserve_batch_resource")?;
        let Some(pending) = ledger.pending.get(&reservation_id) else {
            return Err(format!(
                "Blast radius: resource batch reservation {reservation_id} is unavailable"
            ));
        };
        if pending.resources.contains(&resource) {
            return Ok(false);
        }
        let candidate = PendingReservation {
            resources: HashSet::from([resource.clone()]),
            ..PendingReservation::default()
        };
        let projected_files = ledger.projected_files(&candidate);
        self.check_limit(
            "files",
            projected_files,
            self.config.max_files_per_run.map(std::num::NonZeroU32::get),
        )?;
        let Some(pending) = ledger.pending.get_mut(&reservation_id) else {
            return Err(format!(
                "Blast radius: resource batch reservation {reservation_id} disappeared"
            ));
        };
        pending.resources.insert(resource);
        drop(ledger);
        Ok(true)
    }

    fn commit(&self, id: u64) {
        let Ok(mut ledger) = self.ledger_guard("commit") else {
            return;
        };
        let Some(pending) = ledger.pending.remove(&id) else {
            error!(
                reservation_id = id,
                "Blast radius reservation missing at commit"
            );
            return;
        };
        ledger.committed_tool_calls = ledger
            .committed_tool_calls
            .saturating_add(pending.tool_calls);
        ledger.committed_mutations = ledger.committed_mutations.saturating_add(pending.mutations);
        ledger.committed_lines = ledger.committed_lines.saturating_add(pending.lines);
        ledger.committed_resources.extend(pending.resources);
    }

    fn release(&self, id: u64) {
        let Ok(mut ledger) = self.ledger_guard("release") else {
            return;
        };
        ledger.pending.remove(&id);
    }
}

#[derive(Default)]
struct ReservationLedger {
    next_id: u64,
    committed_tool_calls: u64,
    committed_mutations: u64,
    committed_lines: u64,
    committed_resources: HashSet<PathBuf>,
    pending: HashMap<u64, PendingReservation>,
}

#[derive(Default)]
struct PendingReservation {
    tool_calls: u64,
    mutations: u64,
    lines: u64,
    resources: HashSet<PathBuf>,
}

impl ReservationLedger {
    fn pending_sum(&self, field: impl Fn(&PendingReservation) -> u64) -> Result<u64, String> {
        self.pending.values().try_fold(0_u64, |total, pending| {
            total.checked_add(field(pending)).ok_or_else(|| {
                "Blast radius: pending reservation accounting overflowed".to_string()
            })
        })
    }

    fn projected_tool_calls(&self, candidate: &PendingReservation) -> Result<u64, String> {
        self.committed_tool_calls
            .checked_add(self.pending_sum(|pending| pending.tool_calls)?)
            .and_then(|value| value.checked_add(candidate.tool_calls))
            .ok_or_else(|| "Blast radius: tool-call accounting overflowed".to_string())
    }

    fn projected_mutations(&self, candidate: &PendingReservation) -> Result<u64, String> {
        self.committed_mutations
            .checked_add(self.pending_sum(|pending| pending.mutations)?)
            .and_then(|value| value.checked_add(candidate.mutations))
            .ok_or_else(|| "Blast radius: mutation accounting overflowed".to_string())
    }

    fn projected_lines(&self, candidate: &PendingReservation) -> Result<u64, String> {
        self.committed_lines
            .checked_add(self.pending_sum(|pending| pending.lines)?)
            .and_then(|value| value.checked_add(candidate.lines))
            .ok_or_else(|| "Blast radius: changed-line accounting overflowed".to_string())
    }

    fn projected_files(&self, candidate: &PendingReservation) -> u64 {
        let mut resources = self.committed_resources.clone();
        for pending in self.pending.values() {
            resources.extend(pending.resources.iter().cloned());
        }
        resources.extend(candidate.resources.iter().cloned());
        u64::try_from(resources.len()).unwrap_or(u64::MAX)
    }

    fn next_reservation_id(&mut self) -> Result<u64, String> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| "Blast radius: reservation ID space exhausted".to_string())?;
        Ok(self.next_id)
    }
}

struct LedgerReservation {
    guard: Arc<BlastRadiusGuard>,
    id: Option<u64>,
}

impl LedgerReservation {
    fn id(&self) -> u64 {
        self.id.unwrap_or(0)
    }

    fn commit(&mut self) {
        if let Some(id) = self.id.take() {
            self.guard.commit(id);
        }
    }

    fn reconcile_lines(&self, changed_lines: u64) {
        let Ok(mut ledger) = self.guard.ledger_guard("reconcile_partial_lines") else {
            return;
        };
        let Some(pending) = ledger.pending.get_mut(&self.id()) else {
            error!(
                reservation_id = self.id(),
                "Blast radius reservation missing during partial-effect reconciliation"
            );
            return;
        };
        pending.lines = changed_lines;
        let projected = ledger
            .projected_lines(&PendingReservation::default())
            .unwrap_or(u64::MAX);
        if self
            .guard
            .config
            .max_lines_per_run
            .is_some_and(|limit| projected > u64::from(limit.get()))
        {
            warn!(
                reservation_id = self.id(),
                projected_lines = projected,
                "A partial file effect exceeded its pre-execution line reservation; reconciled actual impact after the effect"
            );
        }
    }
}

impl Drop for LedgerReservation {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            self.guard.release(id);
        }
    }
}

// ==========================================================================
// Diff Monitor
// ==========================================================================

struct DiffMonitor {
    config: DiffMonitorConfig,
    workspace_root: PathBuf,
    baseline: WorkspaceDiffSnapshot,
    current: Mutex<DiffMonitorState>,
    mutation_in_flight: Arc<AtomicBool>,
}

struct DiffMutationLease {
    active: Arc<AtomicBool>,
}

impl Drop for DiffMutationLease {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

#[derive(Debug, Clone)]
struct DiffMonitorState {
    stats: Result<DiffStats, String>,
}

const MAX_DIFF_SNAPSHOT_ENTRIES: usize = 100_000;
const MAX_DIFF_TEXT_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DIFF_BASELINE_TEXT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkspaceDiffEntry {
    kind: u8,
    digest: [u8; 32],
    text: Option<Arc<str>>,
}

#[derive(Debug, Clone)]
struct WorkspaceDiffSnapshot {
    entries: BTreeMap<PathBuf, WorkspaceDiffEntry>,
}

impl WorkspaceDiffSnapshot {
    fn capture(root: &Path) -> Result<Self, String> {
        let mut entries = BTreeMap::new();
        let mut queue = VecDeque::from([root.to_path_buf()]);
        let mut retained_text_bytes = 0_u64;
        while let Some(directory) = queue.pop_front() {
            let mut children = std::fs::read_dir(&directory)
                .map_err(|error| format!("cannot enumerate diff snapshot: {error}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("cannot enumerate diff snapshot: {error}"))?;
            children.sort_by_key(std::fs::DirEntry::file_name);
            for child in children {
                let path = child.path();
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| format!("diff snapshot escaped workspace: {error}"))?
                    .to_path_buf();
                if crate::evidence_freshness::artifact_path_is_excluded(&relative) {
                    continue;
                }
                let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                    format!("cannot inspect diff artifact '{}': {error}", path.display())
                })?;
                if metadata.is_dir() {
                    queue.push_back(path);
                    continue;
                }
                if entries.len() >= MAX_DIFF_SNAPSHOT_ENTRIES {
                    return Err(format!(
                        "diff snapshot exceeds {MAX_DIFF_SNAPSHOT_ENTRIES} files"
                    ));
                }
                let entry = if metadata.file_type().is_symlink() {
                    let target = std::fs::read_link(&path).map_err(|error| {
                        format!("cannot read diff symlink '{}': {error}", path.display())
                    })?;
                    WorkspaceDiffEntry::from_bytes(
                        b'l',
                        target.as_os_str().as_encoded_bytes(),
                        &mut retained_text_bytes,
                    )?
                } else if metadata.is_file() {
                    WorkspaceDiffEntry::from_file(&path, metadata.len(), &mut retained_text_bytes)?
                } else {
                    return Err(format!(
                        "diff snapshot contains unsupported special file '{}'",
                        path.display()
                    ));
                };
                entries.insert(relative, entry);
            }
        }
        Ok(Self { entries })
    }

    fn with_text_override(mut self, relative: PathBuf, content: &[u8]) -> Result<Self, String> {
        let mut retained = self
            .entries
            .values()
            .filter_map(|entry| entry.text.as_ref())
            .map(|text| u64::try_from(text.len()).unwrap_or(u64::MAX))
            .fold(0_u64, u64::saturating_add);
        if let Some(previous) = self
            .entries
            .get(&relative)
            .and_then(|entry| entry.text.as_ref())
        {
            retained = retained.saturating_sub(u64::try_from(previous.len()).unwrap_or(u64::MAX));
        }
        let replacement = WorkspaceDiffEntry::from_bytes(b'f', content, &mut retained)?;
        self.entries.insert(relative, replacement);
        Ok(self)
    }
}

impl WorkspaceDiffEntry {
    fn from_file(path: &Path, len: u64, retained: &mut u64) -> Result<Self, String> {
        let mut file = std::fs::File::open(path)
            .map_err(|error| format!("cannot open diff artifact '{}': {error}", path.display()))?;
        let mut digest = Sha256::new();
        let mut bytes = if len <= MAX_DIFF_TEXT_FILE_BYTES {
            Vec::with_capacity(usize::try_from(len).unwrap_or(0))
        } else {
            Vec::new()
        };
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(|error| {
                format!("cannot read diff artifact '{}': {error}", path.display())
            })?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            if len <= MAX_DIFF_TEXT_FILE_BYTES {
                bytes.extend_from_slice(&buffer[..count]);
            }
        }
        let text = if len <= MAX_DIFF_TEXT_FILE_BYTES {
            std::str::from_utf8(&bytes).ok().map(Arc::<str>::from)
        } else {
            None
        };
        if let Some(text) = &text {
            *retained = retained.saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX));
            if *retained > MAX_DIFF_BASELINE_TEXT_BYTES {
                return Err(format!(
                    "diff snapshot text exceeds {MAX_DIFF_BASELINE_TEXT_BYTES} bytes"
                ));
            }
        }
        Ok(Self {
            kind: b'f',
            digest: digest.finalize().into(),
            text,
        })
    }

    fn from_bytes(kind: u8, bytes: &[u8], retained: &mut u64) -> Result<Self, String> {
        let text = if u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_DIFF_TEXT_FILE_BYTES {
            std::str::from_utf8(bytes).ok().map(Arc::<str>::from)
        } else {
            None
        };
        if let Some(text) = &text {
            *retained = retained.saturating_add(u64::try_from(text.len()).unwrap_or(u64::MAX));
            if *retained > MAX_DIFF_BASELINE_TEXT_BYTES {
                return Err(format!(
                    "diff snapshot text exceeds {MAX_DIFF_BASELINE_TEXT_BYTES} bytes"
                ));
            }
        }
        Ok(Self {
            kind,
            digest: Sha256::digest(bytes).into(),
            text,
        })
    }
}

impl DiffMonitor {
    fn try_new(
        run: &crate::tools::ToolRunContext,
        config: DiffMonitorConfig,
    ) -> Result<Self, String> {
        let workspace_root = run.project_root().to_path_buf();
        let baseline = WorkspaceDiffSnapshot::capture(&workspace_root)?;
        Ok(Self {
            config,
            workspace_root,
            baseline,
            current: Mutex::new(DiffMonitorState {
                stats: Ok(DiffStats::default()),
            }),
            mutation_in_flight: Arc::new(AtomicBool::new(false)),
        })
    }

    fn begin_change(&self) -> Result<DiffMutationLease, String> {
        self.mutation_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                "another workspace mutation is awaiting diff-policy settlement; retry after it completes"
                    .to_string()
            })?;
        Ok(DiffMutationLease {
            active: Arc::clone(&self.mutation_in_flight),
        })
    }

    fn state_guard(&self, operation: &'static str) -> Option<MutexGuard<'_, DiffMonitorState>> {
        match self.current.lock() {
            Ok(guard) => Some(guard),
            Err(err) => {
                error!(operation, error = %err, "Diff monitor state lock poisoned");
                None
            }
        }
    }

    fn evaluate_root(&self, root: &Path) -> Result<DiffStats, String> {
        let current = WorkspaceDiffSnapshot::capture(root)?;
        diff_snapshot_stats(&self.workspace_root, &self.baseline, &current, &self.config)
    }

    fn evaluate_file_overlay(&self, path: &Path, content: &[u8]) -> Result<DiffStats, String> {
        let relative = path.strip_prefix(&self.workspace_root).map_err(|_| {
            format!(
                "diff policy cannot evaluate path '{}' outside workspace '{}'",
                path.display(),
                self.workspace_root.display()
            )
        })?;
        let current = WorkspaceDiffSnapshot::capture(&self.workspace_root)?
            .with_text_override(relative.to_path_buf(), content)?;
        diff_snapshot_stats(&self.workspace_root, &self.baseline, &current, &self.config)
    }

    fn threshold_warning(&self, stats: &DiffStats) -> Option<DiffWarning> {
        let total_lines = stats.lines_changed;
        let total_files = stats.files_changed;

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
            stats: stats.clone(),
            action: self.config.action.clone(),
        })
    }

    fn evaluate_live(&self) -> Result<DiffStats, String> {
        let result = self.evaluate_root(&self.workspace_root);
        if let Some(mut state) = self.state_guard("evaluate_live") {
            state.stats.clone_from(&result);
        }
        result
    }

    fn commit_stats(&self, stats: Result<DiffStats, String>) {
        if let Some(mut state) = self.state_guard("commit_stats") {
            state.stats = stats;
        }
    }
}

fn diff_snapshot_stats(
    workspace_root: &Path,
    baseline: &WorkspaceDiffSnapshot,
    current: &WorkspaceDiffSnapshot,
    config: &DiffMonitorConfig,
) -> Result<DiffStats, String> {
    let paths = baseline
        .entries
        .keys()
        .chain(current.entries.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut stats = DiffStats::default();
    for path in paths {
        let before = baseline.entries.get(&path);
        let after = current.entries.get(&path);
        if before == after {
            continue;
        }
        stats.files_changed = stats.files_changed.saturating_add(1);
        stats
            .file_list
            .push(workspace_root.join(&path).to_string_lossy().to_string());
        if config.max_lines_changed == 0 {
            continue;
        }
        let before_text = before.and_then(|entry| entry.text.as_deref()).unwrap_or("");
        let after_text = after.and_then(|entry| entry.text.as_deref()).unwrap_or("");
        if before.is_some_and(|entry| entry.text.is_none())
            || after.is_some_and(|entry| entry.text.is_none())
        {
            return Err(format!(
                "cannot count changed lines for large or non-UTF-8 artifact '{}'",
                workspace_root.join(&path).display()
            ));
        }
        for change in similar::TextDiff::from_lines(before_text, after_text).iter_all_changes() {
            match change.tag() {
                similar::ChangeTag::Insert => {
                    stats.lines_added = stats.lines_added.saturating_add(1);
                }
                similar::ChangeTag::Delete => {
                    stats.lines_removed = stats.lines_removed.saturating_add(1);
                }
                similar::ChangeTag::Equal => {}
            }
        }
    }
    stats.lines_changed = stats.lines_added.saturating_add(stats.lines_removed);
    Ok(stats)
}

// ==========================================================================
// Quality Gate Runner
// ==========================================================================

struct QualityGateRunner {
    config: QualityGatesConfig,
    run: std::sync::Weak<crate::tools::ToolRunContext>,
    bound_model: Mutex<Option<String>>,
    cache: Mutex<Option<CachedQualityGateReport>>,
}

#[derive(Debug, Clone)]
struct CachedQualityGateReport {
    diff_revision: u64,
    report: QualityGateReport,
}

impl QualityGateRunner {
    fn try_new(
        config: QualityGatesConfig,
        run: std::sync::Weak<crate::tools::ToolRunContext>,
    ) -> Result<Self, String> {
        if config.checks.is_empty() {
            return Err("enabled quality_gates requires at least one check".to_string());
        }
        if config.timeout_seconds == 0 {
            return Err(
                "enabled quality_gates timeout_seconds must be greater than zero".to_string(),
            );
        }
        let mut names = BTreeSet::new();
        for check in &config.checks {
            if check.name.trim().is_empty() {
                return Err("quality-gate check name must not be empty".to_string());
            }
            if check.command.trim().is_empty() {
                return Err(format!(
                    "quality-gate check '{}' command must not be empty",
                    check.name
                ));
            }
            if !names.insert(check.name.clone()) {
                return Err(format!(
                    "quality-gate check name '{}' is duplicated",
                    check.name
                ));
            }
            shlex::split(&check.command)
                .filter(|argv| !argv.is_empty())
                .ok_or_else(|| {
                    format!(
                        "quality-gate check '{}' command has invalid quoting",
                        check.name
                    )
                })?;
        }
        Ok(Self {
            config,
            run,
            bound_model: Mutex::new(None),
            cache: Mutex::new(None),
        })
    }

    fn bind_model(&self, model_identity: &str) -> Result<(), String> {
        let model_identity = model_identity.trim();
        if model_identity.is_empty() {
            return Err("quality-gate model identity must not be empty".to_string());
        }
        let changed = {
            let mut bound = self
                .bound_model
                .lock()
                .map_err(|error| format!("quality-gate model binding lock poisoned: {error}"))?;
            let changed = bound.as_deref() != Some(model_identity);
            if changed {
                *bound = Some(model_identity.to_string());
            }
            changed
        };
        if changed {
            self.cache
                .lock()
                .map_err(|error| format!("quality-gate cache lock poisoned: {error}"))?
                .take();
        }
        Ok(())
    }

    fn run_bound_at(&self, cadence: RunAfter) -> QualityGateReport {
        let Some(run) = self.run.upgrade() else {
            return self.failure_report(
                cadence,
                "quality-gate run generation was released before execution",
            );
        };
        let model = self.bound_model.lock().ok().and_then(|model| model.clone());
        match model {
            Some(model) => self.run_at(&run, &model, cadence),
            None => self.failure_report(cadence, "quality-gate model identity is not bound"),
        }
    }

    fn run_at(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        model_identity: &str,
        cadence: RunAfter,
    ) -> QualityGateReport {
        if cadence != self.config.run_after {
            return QualityGateReport {
                cadence,
                configured_cadence: self.config.run_after.clone(),
                action: self.config.fail_action.clone(),
                disposition: QualityGateDisposition::Skipped,
                results: Vec::new(),
                reason: Some("quality gates are not due at this lifecycle boundary".to_string()),
            };
        }
        if let Err(error) = self.bind_model(model_identity) {
            return self.failure_report(cadence, &error);
        }
        let results = self.run_checks(run, model_identity);
        let report = self.report_from_results(cadence, results);
        let diff_revision = diff_revision(run);
        if let Ok(mut cache) = self.cache.lock() {
            *cache = Some(CachedQualityGateReport {
                diff_revision,
                report: report.clone(),
            });
        }
        report
    }

    fn for_finalization(&self, model_identity: &str) -> QualityGateReport {
        let Some(run) = self.run.upgrade() else {
            return self.failure_report(
                self.config.run_after.clone(),
                "quality-gate run generation was released before finalization",
            );
        };
        if let Err(error) = self.bind_model(model_identity) {
            return self.failure_report(self.config.run_after.clone(), &error);
        }
        let diff_revision = diff_revision(&run);
        if let Some(cached) = self.current_cached_report(&run, diff_revision) {
            return cached;
        }
        match self.config.run_after {
            RunAfter::EveryTurn => self.run_at(&run, model_identity, RunAfter::EveryTurn),
            RunAfter::EveryEdit if diff_revision == 0 => QualityGateReport {
                cadence: RunAfter::EveryEdit,
                configured_cadence: RunAfter::EveryEdit,
                action: self.config.fail_action.clone(),
                disposition: QualityGateDisposition::Skipped,
                results: Vec::new(),
                reason: Some("no workspace edit occurred in this run".to_string()),
            },
            RunAfter::EveryEdit => self.failure_report(
                RunAfter::EveryEdit,
                "the edited workspace has no current every_edit quality-gate receipt",
            ),
            RunAfter::OnCommit => QualityGateReport {
                cadence: RunAfter::OnCommit,
                configured_cadence: RunAfter::OnCommit,
                action: self.config.fail_action.clone(),
                disposition: QualityGateDisposition::Skipped,
                results: Vec::new(),
                reason: Some("on_commit checks are enforced before commit operations".to_string()),
            },
        }
    }

    fn current_cached_report(
        &self,
        run: &crate::tools::ToolRunContext,
        diff_revision: u64,
    ) -> Option<QualityGateReport> {
        let cache = self.cache.lock().ok()?.clone()?;
        if cache.diff_revision != diff_revision {
            return None;
        }
        for result in &cache.report.results {
            let binding = result.evidence.verification_binding.as_ref()?;
            if crate::evidence_freshness::validate_verification_binding(run, binding).is_err() {
                return None;
            }
        }
        Some(cache.report)
    }

    fn failure_report(&self, cadence: RunAfter, reason: &str) -> QualityGateReport {
        let disposition = match self.config.fail_action {
            GuardrailAction::Warn => QualityGateDisposition::Warning,
            GuardrailAction::InjectFindings => QualityGateDisposition::Findings,
            GuardrailAction::Block => QualityGateDisposition::Blocked,
        };
        QualityGateReport {
            cadence,
            configured_cadence: self.config.run_after.clone(),
            action: self.config.fail_action.clone(),
            disposition,
            results: Vec::new(),
            reason: Some(reason.to_string()),
        }
    }

    fn report_from_results(
        &self,
        cadence: RunAfter,
        results: Vec<QualityCheckResult>,
    ) -> QualityGateReport {
        let required_failure = results
            .iter()
            .any(|result| result.required && result.status != QualityCheckStatus::Passed);
        let optional_failure = results
            .iter()
            .any(|result| !result.required && result.status != QualityCheckStatus::Passed);
        let disposition = if required_failure {
            match self.config.fail_action {
                GuardrailAction::Warn => QualityGateDisposition::Warning,
                GuardrailAction::InjectFindings => QualityGateDisposition::Findings,
                GuardrailAction::Block => QualityGateDisposition::Blocked,
            }
        } else if optional_failure {
            QualityGateDisposition::Warning
        } else {
            QualityGateDisposition::Passed
        };
        QualityGateReport {
            cadence,
            configured_cadence: self.config.run_after.clone(),
            action: self.config.fail_action.clone(),
            disposition,
            results,
            reason: None,
        }
    }

    fn run_checks(
        &self,
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        model_identity: &str,
    ) -> Vec<QualityCheckResult> {
        let mut results = Vec::new();

        let model_error = crate::ledger::sync_model_identity(run, model_identity).err();

        for check in &self.config.checks {
            info!(name = %check.name, "Running quality gate");

            let prepared = model_error.as_ref().map_or_else(
                || quality_gate_seed(run, &check.name, &check.command),
                |error| Err(error.to_string()),
            );
            let (outcome, evidence) = match prepared {
                Ok(seed) => {
                    let outcome =
                        run_shell_command_sync(run, &check.command, self.config.timeout_seconds);
                    match quality_gate_seed(run, &check.name, &check.command) {
                        Ok(after) if after == seed => {
                            let evidence = QualityGateEvidence {
                                run_id: run.run_id(),
                                capability_generation: run.generation(),
                                normalized_argv: seed.normalized_argv,
                                resolved_executable: Some(seed.resolved_executable),
                                executable_sha256: Some(seed.executable_sha256),
                                verification_binding: Some(seed.binding),
                                freshness_error: None,
                            };
                            (Some(outcome), evidence)
                        }
                        Ok(_) => (
                            None,
                            failed_quality_gate_evidence(
                                run,
                                &check.command,
                                "workspace, environment, model, policy, or verifier changed while the quality gate ran",
                            ),
                        ),
                        Err(error) => (
                            None,
                            failed_quality_gate_evidence(run, &check.command, &error),
                        ),
                    }
                }
                Err(error) => (
                    None,
                    failed_quality_gate_evidence(run, &check.command, &error),
                ),
            };

            let (status, exit_code, stdout, stderr) =
                classify_quality_check_outcome(outcome, &evidence, self.config.timeout_seconds);

            if status != QualityCheckStatus::Passed && check.required {
                warn!(name = %check.name, exit_code, "Required quality gate FAILED");
            } else if status == QualityCheckStatus::Passed {
                debug!(name = %check.name, "Quality gate passed");
            }

            results.push(QualityCheckResult {
                name: check.name.clone(),
                command: check.command.clone(),
                status,
                exit_code,
                stdout,
                stderr,
                required: check.required,
                evidence,
            });
        }

        results
    }
}

fn classify_quality_check_outcome(
    outcome: Option<ShellResult>,
    evidence: &QualityGateEvidence,
    timeout_seconds: u64,
) -> (QualityCheckStatus, i32, String, String) {
    match outcome {
        Some(ShellResult::Success { stdout, stderr }) => {
            (QualityCheckStatus::Passed, 0, stdout, stderr)
        }
        Some(ShellResult::ExitFailed {
            code,
            stdout,
            stderr,
        }) => (QualityCheckStatus::Failed, code, stdout, stderr),
        Some(ShellResult::ShellMissing { tried }) => (
            QualityCheckStatus::Error,
            -1,
            String::new(),
            format!("Program not found on PATH: tried {tried:?}"),
        ),
        Some(ShellResult::Timeout) => (
            QualityCheckStatus::Error,
            -1,
            String::new(),
            format!(
                "Quality gate timed out after {timeout_seconds}s (wall-clock supervisor killed child)"
            ),
        ),
        None => (
            if evidence
                .freshness_error
                .as_deref()
                .is_some_and(|error| error.contains("changed while the quality gate ran"))
            {
                QualityCheckStatus::Stale
            } else {
                QualityCheckStatus::Error
            },
            -1,
            String::new(),
            format!(
                "Quality gate evidence rejected: {}",
                evidence
                    .freshness_error
                    .as_deref()
                    .unwrap_or("freshness proof unavailable")
            ),
        ),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct QualityGateSeed {
    normalized_argv: Vec<String>,
    resolved_executable: String,
    executable_sha256: String,
    binding: crate::evidence_freshness::VerificationFreshnessBinding,
}

fn quality_gate_seed(
    run: &crate::tools::ToolRunContext,
    check: &str,
    command: &str,
) -> Result<QualityGateSeed, String> {
    let normalized_argv = shlex::split(command)
        .filter(|argv| !argv.is_empty())
        .ok_or_else(|| "quality-gate command is empty or has invalid quoting".to_string())?;
    let resolved_executable = normalized_argv
        .first()
        .ok_or_else(|| "quality-gate command has no executable".to_string())
        .and_then(|program| {
            run.resolve_executable(program)
                .map_err(|error| error.to_string())
        })?;
    let executable_sha256 = sha256_file(&resolved_executable)
        .ok_or_else(|| "quality-gate executable could not be hashed".to_string())?;
    let resolved_executable = resolved_executable.to_string_lossy().to_string();
    let verifier_identity_sha256 = crate::evidence_freshness::verifier_identity_sha256(
        check,
        &normalized_argv,
        Some(&resolved_executable),
        Some(&executable_sha256),
    );
    let binding =
        crate::evidence_freshness::capture_verification_binding(run, verifier_identity_sha256)?;
    Ok(QualityGateSeed {
        normalized_argv,
        resolved_executable,
        executable_sha256,
        binding,
    })
}

fn failed_quality_gate_evidence(
    run: &crate::tools::ToolRunContext,
    command: &str,
    error: &str,
) -> QualityGateEvidence {
    let normalized_argv = shlex::split(command)
        .filter(|argv| !argv.is_empty())
        .unwrap_or_default();
    QualityGateEvidence {
        run_id: run.run_id(),
        capability_generation: run.generation(),
        normalized_argv,
        resolved_executable: None,
        executable_sha256: None,
        verification_binding: None,
        freshness_error: Some(error.to_string()),
    }
}

fn sha256_file(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let digest = digest.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    Some(hex)
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
fn run_shell_command_sync(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
    command: &str,
    timeout_seconds: u64,
) -> ShellResult {
    let cwd = run.working_directory().to_path_buf();

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
    let fut = run_shell_command_async(
        std::sync::Arc::clone(run),
        program_owned,
        args_owned,
        cwd_owned,
        timeout_seconds,
    );

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
    run: std::sync::Arc<crate::tools::ToolRunContext>,
    program_owned: String,
    args_owned: Vec<String>,
    cwd_owned: std::path::PathBuf,
    timeout_seconds: u64,
) -> ShellResult {
    // Quality gates execute project-controlled build files, compiler plugins,
    // and test binaries. Running argv directly prevents shell injection but
    // does not prevent those programs from accessing the host, so use the
    // same OS boundary as the model-facing Bash tool.
    let resolved_program = match run.resolve_executable(&program_owned) {
        Ok(path) => path,
        Err(error) => {
            warn!(program = %program_owned, %error, "Quality gate: executable resolution failed");
            return ShellResult::ShellMissing {
                tried: vec![program_owned],
            };
        }
    };
    let sandbox_args: Vec<std::ffi::OsString> =
        args_owned.iter().map(std::ffi::OsString::from).collect();
    let sandboxed = match crate::tools::sandboxed_process_command(
        &run,
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
    let result = match crate::tools::command::run_prepared_run_owned(
        &run,
        sandboxed,
        &program_owned,
        crate::tools::command::ProcessLimits::new(effective_timeout),
        None,
    )
    .await
    {
        Ok(output) => Some(output.into_std_output()),
        Err(crate::tools::CommandError::TimedOut { .. }) => {
            warn!(
                program = %program_owned,
                timeout_seconds = effective_timeout.as_secs(),
                "Quality gate: command timed out; sandbox process tree terminated"
            );
            return ShellResult::Timeout;
        }
        Err(error) => {
            error!(%error, "Quality gate: sandboxed command failed");
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
pub fn detect_project_languages(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
) -> Vec<ProjectLanguage> {
    detect_languages_in_dir(run.working_directory())
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
pub fn get_default_analysis_commands(
    lang: &ProjectLanguage,
    project_dir: &Path,
) -> Vec<(String, String)> {
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
            if project_dir.join("pom.xml").exists() {
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
            if project_dir.join("CMakeLists.txt").exists() {
                vec![("cmake".to_string(), "cmake --build build".to_string())]
            } else if project_dir.join("Makefile").exists() {
                vec![("make".to_string(), "make".to_string())]
            } else {
                Vec::new()
            }
        }
    }
}

/// Get auto-detected static analysis commands for the current project.
/// Used by VDD when `auto_detect` is enabled and no explicit commands are configured.
pub fn get_auto_detected_commands(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
) -> Vec<String> {
    let languages = detect_project_languages(run);
    let mut commands = Vec::new();

    for lang in &languages {
        for (_name, cmd) in get_default_analysis_commands(lang, run.working_directory()) {
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

struct CompiledPathPattern {
    regex: Regex,
    literal_prefix: String,
    denied_subtree_root: Option<String>,
}

impl CompiledPathPattern {
    fn denies_scope(&self, scope: &str) -> bool {
        self.regex.is_match(scope)
            || self.denied_subtree_root.as_ref().is_some_and(|root| {
                scope == root
                    || scope
                        .strip_prefix(root)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            })
    }

    fn may_reach_from(&self, scope: &str) -> bool {
        if self.regex.is_match(scope) || scope == "." || self.literal_prefix.is_empty() {
            return true;
        }
        path_is_same_or_descendant(&self.literal_prefix, scope)
            || path_is_same_or_descendant(scope, &self.literal_prefix)
    }

    fn covers_disclosed_scope(&self, scope: &str) -> bool {
        self.regex.is_match(scope)
            || (!self.literal_prefix.is_empty()
                && path_is_same_or_descendant(&self.literal_prefix, scope))
    }
}

fn path_is_same_or_descendant(path: &str, ancestor: &str) -> bool {
    path == ancestor
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn compile_path_patterns(
    kind: &str,
    patterns: &[String],
) -> Result<Vec<CompiledPathPattern>, String> {
    patterns
        .iter()
        .map(|pattern| {
            let normalized = normalize_path(pattern.trim());
            if normalized.is_empty() {
                return Err(format!(
                    "Blast radius: {kind} path pattern must not be empty"
                ));
            }
            if normalized.split('/').any(|component| component == "..") {
                return Err(format!(
                    "Blast radius: {kind} path pattern '{pattern}' contains ambiguous parent traversal"
                ));
            }
            let regex = glob_to_regex(&normalized).map_err(|error| {
                format!("Blast radius: invalid {kind} path pattern '{pattern}': {error}")
            })?;
            let wildcard_offset = normalized
                .char_indices()
                .find_map(|(offset, character)| matches!(character, '*' | '?').then_some(offset))
                .unwrap_or(normalized.len());
            let literal_prefix = normalized[..wildcard_offset]
                .trim_end_matches('/')
                .to_string();
            let denied_subtree_root = normalized
                .strip_suffix("/**")
                .filter(|root| !root.is_empty() && !root.contains(['*', '?']))
                .map(str::to_string);
            Ok(CompiledPathPattern {
                regex,
                literal_prefix,
                denied_subtree_root,
            })
        })
        .collect()
}

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

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    fn run_test_quality_gate(config: QualityGatesConfig) -> Vec<QualityCheckResult> {
        let root = tempfile::TempDir::new().expect("isolated quality-gate workspace");
        let run = crate::tools::security::test_run_context_for(root.path());
        crate::evidence_freshness::bind_policy(&run, "guardrails-unit-test-policy".to_string())
            .expect("bind test verification policy");
        let cadence = config.run_after.clone();
        QualityGateRunner::try_new(config, Arc::downgrade(&run))
            .expect("valid quality config")
            .run_at(&run, "test-model", cadence)
            .results
    }
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
            ..BlastRadiusConfig::default()
        };
        let guard = BlastRadiusGuard::try_new(config).expect("valid strict policy");

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
            ..BlastRadiusConfig::default()
        };
        let guard = BlastRadiusGuard::try_new(config).expect("valid allow policy");

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
            ..BlastRadiusConfig::default()
        };
        let guard = BlastRadiusGuard::try_new(config).expect("valid advisory policy");

        // Advisory mode warns but doesn't block
        assert!(guard.check_path("config.yaml").is_ok());
    }

    #[test]
    fn test_blast_radius_max_files() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            max_files_per_run: std::num::NonZeroU32::new(2),
            ..BlastRadiusConfig::default()
        };
        let guard = Arc::new(BlastRadiusGuard::try_new(config).expect("valid quota"));

        for file in ["file1.rs", "file2.rs"] {
            let mut reservation = guard
                .reserve(
                    PendingReservation {
                        resources: HashSet::from([PathBuf::from(file)]),
                        ..PendingReservation::default()
                    },
                    Some(file),
                )
                .expect("within unique-file cap");
            reservation.commit();
        }
        assert!(guard
            .reserve(
                PendingReservation {
                    resources: HashSet::from([PathBuf::from("file3.rs")]),
                    ..PendingReservation::default()
                },
                Some("file3.rs")
            )
            .is_err());
    }

    #[test]
    fn denied_reservation_does_not_consume_run_quota() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            max_files_per_run: std::num::NonZeroU32::new(1),
            ..BlastRadiusConfig::default()
        };
        let guard = Arc::new(BlastRadiusGuard::try_new(config).expect("valid quota"));
        let pending = guard
            .reserve(
                PendingReservation {
                    resources: HashSet::from([PathBuf::from("a.rs")]),
                    ..PendingReservation::default()
                },
                Some("a.rs"),
            )
            .expect("first pending reservation");
        assert!(guard
            .reserve(
                PendingReservation {
                    resources: HashSet::from([PathBuf::from("b.rs")]),
                    ..PendingReservation::default()
                },
                Some("b.rs")
            )
            .is_err());
        drop(pending);
        assert!(guard
            .reserve(
                PendingReservation {
                    resources: HashSet::from([PathBuf::from("b.rs")]),
                    ..PendingReservation::default()
                },
                Some("b.rs")
            )
            .is_ok());
    }

    #[test]
    fn concurrent_reservations_cannot_oversubscribe_one_run() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            max_tool_calls_per_run: std::num::NonZeroU32::new(1),
            ..BlastRadiusConfig::default()
        };
        let guard = Arc::new(BlastRadiusGuard::try_new(config).expect("valid quota"));
        let start = Arc::new(std::sync::Barrier::new(2));
        let finish = Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let guard = Arc::clone(&guard);
            let start = Arc::clone(&start);
            let finish = Arc::clone(&finish);
            workers.push(std::thread::spawn(move || {
                start.wait();
                let mut reservation = guard.reserve(
                    PendingReservation {
                        tool_calls: 1,
                        ..PendingReservation::default()
                    },
                    None,
                );
                // The winning reservation remains pending until both threads
                // have attempted admission, so the loser cannot slip through
                // between reserve and commit.
                finish.wait();
                reservation.as_mut().is_ok_and(|reservation| {
                    reservation.commit();
                    true
                })
            }));
        }
        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().expect("reservation worker"))
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 1, "atomic quota must admit exactly one caller");
    }

    #[test]
    fn invalid_policy_patterns_fail_compilation() {
        let config = BlastRadiusConfig {
            enabled: true,
            mode: GuardrailMode::Strict,
            allowed_paths: vec!["src/../secrets/**".to_string()],
            ..BlastRadiusConfig::default()
        };
        let Err(error) = BlastRadiusGuard::try_new(config) else {
            panic!("ambiguous traversal policy must fail closed");
        };
        assert!(error.contains("parent traversal"), "{error}");
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
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("file1.rs"), "old\n").expect("baseline");
        let run = crate::tools::security::test_run_context_for(root.path());
        let monitor = DiffMonitor::try_new(&run, config).expect("monitor");
        std::fs::write(root.path().join("file1.rs"), "new\nextra\n").expect("change");
        std::fs::write(root.path().join("file2.rs"), "added\n").expect("new file");

        let stats = monitor.evaluate_live().expect("exact live diff");
        assert_eq!(stats.lines_added, 3);
        assert_eq!(stats.lines_removed, 1);
        assert_eq!(stats.lines_changed, 4);
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
        let root = tempfile::tempdir().expect("root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let monitor = DiffMonitor::try_new(&run, config).expect("monitor");
        std::fs::write(root.path().join("file1.rs"), "one\n").expect("change");
        let stats = monitor.evaluate_live().expect("live diff");
        assert!(monitor.threshold_warning(&stats).is_none());
    }

    #[test]
    fn test_diff_monitor_threshold_exceeded() {
        let config = DiffMonitorConfig {
            enabled: true,
            max_lines_changed: 20,
            max_files_changed: 5,
            action: GuardrailAction::Warn,
        };
        let root = tempfile::tempdir().expect("root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let monitor = DiffMonitor::try_new(&run, config).expect("monitor");
        let mut content = String::new();
        for line in 0..21 {
            writeln!(content, "{line}").expect("write fixture line");
        }
        std::fs::write(root.path().join("file1.rs"), content).expect("change");
        let stats = monitor.evaluate_live().expect("live diff");
        let warning = monitor.threshold_warning(&stats);
        assert!(warning.is_some());
        let w = warning.unwrap();
        assert!(w.message.contains("lines changed"));
        assert_eq!(w.stats.lines_changed, 21);
    }

    #[test]
    fn test_diff_monitor_files_threshold() {
        let config = DiffMonitorConfig {
            enabled: true,
            max_lines_changed: 0,
            max_files_changed: 2,
            action: GuardrailAction::Block,
        };
        let root = tempfile::tempdir().expect("root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let monitor = DiffMonitor::try_new(&run, config).expect("monitor");
        std::fs::write(root.path().join("a.rs"), "a").expect("a");
        std::fs::write(root.path().join("b.rs"), "b").expect("b");
        let stats = monitor.evaluate_live().expect("two files");
        assert!(monitor.threshold_warning(&stats).is_none());

        std::fs::write(root.path().join("c.rs"), "c").expect("c");
        let stats = monitor.evaluate_live().expect("three files");
        let warning = monitor.threshold_warning(&stats);
        assert!(warning.is_some());
        assert!(warning.unwrap().message.contains("files changed"));
    }

    #[test]
    fn diff_block_rejects_proposed_file_before_publication() {
        let _serialize = lock_global_for_test();
        let root = tempfile::tempdir_in(".").expect("root");
        let run = isolated_run(root.path());
        configure(
            &run,
            &GuardrailsConfig {
                diff_monitor: Some(DiffMonitorConfig {
                    enabled: true,
                    max_lines_changed: 1,
                    max_files_changed: 0,
                    action: GuardrailAction::Block,
                }),
                ..GuardrailsConfig::default()
            },
        )
        .expect("configure diff block");
        let path = root.path().join("blocked.rs");
        let Err(error) = admit_file_change(&run, &path, b"one\ntwo\n") else {
            panic!("oversized proposal must be blocked");
        };
        assert!(error.contains("Diff size threshold exceeded"), "{error}");
        assert!(
            !path.exists(),
            "pre-publication block must not create the file"
        );
    }

    #[test]
    fn diff_admission_serializes_concurrent_workspace_publication() {
        let _serialize = lock_global_for_test();
        let root = tempfile::tempdir_in(".").expect("root");
        let run = isolated_run(root.path());
        configure(
            &run,
            &GuardrailsConfig {
                diff_monitor: Some(DiffMonitorConfig {
                    enabled: true,
                    max_lines_changed: 10,
                    max_files_changed: 10,
                    action: GuardrailAction::Block,
                }),
                ..GuardrailsConfig::default()
            },
        )
        .expect("configure diff block");
        let first = admit_file_change(&run, &root.path().join("first.rs"), b"first\n")
            .expect("first proposal");
        let Err(busy) = admit_file_change(&run, &root.path().join("second.rs"), b"second\n") else {
            panic!("a second proposal must wait for exact diff settlement");
        };
        assert!(busy.contains("mutation is awaiting diff-policy settlement"));
        drop(first);
        let retry = admit_file_change(&run, &root.path().join("second.rs"), b"second\n")
            .expect("released proposal can be retried");
        drop(retry);
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
        let results = run_test_quality_gate(config);

        assert_eq!(results.len(), 1);
        assert!(results[0].passed());
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
        let results = run_test_quality_gate(config);

        assert_eq!(results.len(), 1);
        assert!(!results[0].passed());
        assert_ne!(results[0].exit_code, 0);
    }

    #[test]
    fn quality_gate_cadence_mismatch_is_typed_skipped() {
        let root = tempfile::tempdir().expect("root");
        let run = crate::tools::security::test_run_context_for(root.path());
        crate::evidence_freshness::bind_policy(&run, "cadence-policy".to_string()).expect("policy");
        let runner = QualityGateRunner::try_new(
            QualityGatesConfig {
                enabled: true,
                run_after: RunAfter::OnCommit,
                fail_action: GuardrailAction::Block,
                checks: vec![QualityCheck {
                    name: "must-not-run".to_string(),
                    command: "false".to_string(),
                    required: true,
                }],
                timeout_seconds: 30,
            },
            Arc::downgrade(&run),
        )
        .expect("runner");
        let report = runner.run_at(&run, "test-model", RunAfter::EveryTurn);
        assert_eq!(report.disposition(), QualityGateDisposition::Skipped);
        assert!(report.results().is_empty());
    }

    #[test]
    fn required_failure_honors_every_configured_action() {
        let cases = [
            (GuardrailAction::Warn, QualityGateDisposition::Warning),
            (
                GuardrailAction::InjectFindings,
                QualityGateDisposition::Findings,
            ),
            (GuardrailAction::Block, QualityGateDisposition::Blocked),
        ];
        for (action, expected) in cases {
            let root = tempfile::tempdir().expect("root");
            let run = crate::tools::security::test_run_context_for(root.path());
            crate::evidence_freshness::bind_policy(&run, "action-policy".to_string())
                .expect("policy");
            let runner = QualityGateRunner::try_new(
                QualityGatesConfig {
                    enabled: true,
                    run_after: RunAfter::EveryTurn,
                    fail_action: action,
                    checks: vec![QualityCheck {
                        name: "required-failure".to_string(),
                        command: "false".to_string(),
                        required: true,
                    }],
                    timeout_seconds: 30,
                },
                Arc::downgrade(&run),
            )
            .expect("runner");
            let report = runner.run_at(&run, "test-model", RunAfter::EveryTurn);
            assert_eq!(report.disposition(), expected);
            assert_eq!(report.results()[0].status(), QualityCheckStatus::Failed);
        }
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
        let results = run_test_quality_gate(config);

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
        let results = run_test_quality_gate(config);

        assert_eq!(results.len(), 1);
        assert!(results[0].passed());
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
            let start = std::time::Instant::now();
            let results = run_test_quality_gate(config);
            let elapsed = start.elapsed();

            assert_eq!(results.len(), 1);
            assert!(
                !results[0].passed(),
                "long-running command was not killed by timeout wrapper"
            );
            assert!(
                elapsed < std::time::Duration::from_secs(10),
                "timeout did not fire: elapsed = {elapsed:?}"
            );
        }
    }

    #[test]
    fn test_quality_gate_rejects_malformed_command_at_configuration() {
        // Unbalanced quotes fail the run configuration instead of remaining
        // latent until the first configured cadence.
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
        let root = tempfile::tempdir().expect("root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let Err(error) = QualityGateRunner::try_new(config, Arc::downgrade(&run)) else {
            panic!("invalid command must fail configuration");
        };
        assert!(error.contains("invalid quoting"), "{error}");
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
        let results = run_test_quality_gate(config);

        assert_eq!(results.len(), 1);
        assert!(results[0].passed());
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
        let cmds =
            get_default_analysis_commands(&ProjectLanguage::Rust, test_run().working_directory());
        assert_eq!(cmds.len(), 2);
        assert!(cmds[0].1.contains("clippy"));
        assert!(cmds[1].1.contains("cargo test"));
    }

    #[test]
    fn test_default_commands_python() {
        let cmds =
            get_default_analysis_commands(&ProjectLanguage::Python, test_run().working_directory());
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

    // ====== Run-scoped registry API tests ======
    //
    // These tests mutate the process-global `GUARDRAILS` static, so
    // they must serialize against one another. We use a dedicated
    // mutex because each test wants to start from a known state.
    //
    // Every #749 test restores the state to `Disabled` on the way out so
    // concurrent canonical-executor and file-reservation tests keep observing
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
                ..BlastRadiusConfig::default()
            }),
            diff_monitor: None,
            quality_gates: None,
        };
        GuardrailsEngine::try_from_config(test_run(), &cfg).expect("valid test guardrails")
    }

    fn isolated_run(root: &Path) -> std::sync::Arc<crate::tools::ToolRunContext> {
        isolated_run_for_session(crate::state::SessionId::new(), root)
    }

    fn isolated_run_for_session(
        session_id: crate::state::SessionId,
        root: &Path,
    ) -> std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::ToolRunContext::builder(session_id, root)
            .working_directory(root)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .provider("guardrails-isolation-test")
            .build()
            .expect("explicit isolated guardrails run")
    }

    #[test]
    fn guardrail_policy_and_diff_state_are_session_scoped() {
        let _serialize = lock_global_for_test();
        let root_a = tempfile::tempdir_in(".").expect("first guardrail root");
        let root_b = tempfile::tempdir_in(".").expect("second guardrail root");
        let run_a = isolated_run(root_a.path());
        let run_b = isolated_run(root_b.path());
        let config_a = GuardrailsConfig {
            blast_radius: Some(BlastRadiusConfig {
                enabled: true,
                mode: GuardrailMode::Strict,
                allowed_paths: Vec::new(),
                denied_paths: vec!["**/secret.txt".to_string()],
                ..BlastRadiusConfig::default()
            }),
            diff_monitor: Some(DiffMonitorConfig {
                enabled: true,
                ..Default::default()
            }),
            quality_gates: None,
        };
        let config_b = GuardrailsConfig {
            blast_radius: Some(BlastRadiusConfig {
                enabled: true,
                mode: GuardrailMode::Strict,
                allowed_paths: Vec::new(),
                denied_paths: Vec::new(),
                ..BlastRadiusConfig::default()
            }),
            diff_monitor: Some(DiffMonitorConfig {
                enabled: true,
                ..Default::default()
            }),
            quality_gates: None,
        };
        configure(&run_a, &config_a).expect("first run config");
        configure(&run_b, &config_b).expect("second run config");

        assert!(check_file_access(&run_a, "nested/secret.txt").is_err());
        assert!(check_file_access(&run_b, "nested/secret.txt").is_ok());
        std::fs::create_dir_all(root_a.path().join("src")).expect("src");
        std::fs::write(root_a.path().join("src/a.rs"), "one\ntwo\nthree\nfour\n")
            .expect("workspace change");
        let first = get_diff_summary(&run_a).expect("first session diff state");
        let second = get_diff_summary(&run_b).expect("second session diff state");
        assert_eq!(first.files_changed, 1);
        assert_eq!(first.lines_changed, 4);
        assert_eq!(second.files_changed, 0);
        assert_eq!(second.lines_changed, 0);
    }

    #[test]
    fn guardrail_state_is_generation_scoped_and_last_arc_cleanup_is_exact() {
        let _serialize = lock_global_for_test();
        let root_a = tempfile::tempdir_in(".").expect("first generation root");
        let root_b = tempfile::tempdir_in(".").expect("second generation root");
        let session_id = crate::state::SessionId::new();
        let run_a = isolated_run_for_session(session_id.clone(), root_a.path());
        let run_b = isolated_run_for_session(session_id, root_b.path());
        let denied = GuardrailsConfig {
            blast_radius: Some(BlastRadiusConfig {
                enabled: true,
                mode: GuardrailMode::Strict,
                allowed_paths: Vec::new(),
                denied_paths: vec!["**/generation-secret.txt".to_string()],
                ..BlastRadiusConfig::default()
            }),
            diff_monitor: None,
            quality_gates: None,
        };
        let allowed = GuardrailsConfig {
            blast_radius: Some(BlastRadiusConfig {
                enabled: true,
                mode: GuardrailMode::Strict,
                allowed_paths: Vec::new(),
                denied_paths: Vec::new(),
                ..BlastRadiusConfig::default()
            }),
            diff_monitor: None,
            quality_gates: None,
        };
        configure(&run_a, &denied).expect("denied generation config");
        configure(&run_b, &allowed).expect("allowed generation config");

        assert!(check_file_access(&run_a, "generation-secret.txt").is_err());
        assert!(check_file_access(&run_b, "generation-secret.txt").is_ok());
        assert_ne!(run_key(&run_a), run_key(&run_b));

        drop(run_a);
        assert_eq!(
            current_state_kind(&run_b),
            "enabled",
            "dropping one generation must preserve the other generation's policy"
        );
    }

    #[test]
    fn test_disabled_guardrails_allow_all() {
        // "Disabled" == no policy loaded. The security boundary must
        // return Ok so default-install installs behave the same as the
        // pre-#749 codebase. Fail-closed only applies to Poisoned.
        let _serialize = lock_global_for_test();
        set_state_for_test(test_run(), GuardrailsState::Disabled);

        assert!(check_file_access(test_run(), "any/file.rs").is_ok());
        assert!(check_diff_thresholds(test_run()).is_none());
        assert!(run_quality_gates(test_run(), "test-model").is_empty());
        assert!(get_diff_summary(test_run()).is_none());
    }

    // ====== Crosslink #749 regression: fail-closed on bad state ======

    #[test]
    fn test_749_check_file_access_returns_err_when_poisoned() {
        // BEFORE THE FIX: a poisoned mutex was swallowed by
        // `if let Ok(guard) = ...lock()` and the function returned
        // Ok(()). After the fix the security boundary must refuse.
        let _serialize = lock_global_for_test();
        set_poisoned_for_test();
        assert_eq!(current_state_kind(test_run()), "poisoned");

        let result = check_file_access(test_run(), "/etc/shadow");
        assert!(
            result.is_err(),
            "poisoned guardrails must fail-closed at the security              boundary, got: {result:?}"
        );
        let msg = result.unwrap_err();
        assert!(
            msg.contains("poisoned"),
            "error must identify the poisoned cause: got {msg:?}"
        );

        set_state_for_test(test_run(), GuardrailsState::Disabled);
    }

    #[test]
    fn test_749_check_file_access_happy_path_with_enabled_engine() {
        // After the fix, a properly configured engine still routes
        // through `Enabled(engine).check_file_access(...)`. The
        // tri-state refactor must not regress the allow-decision path.
        let _serialize = lock_global_for_test();
        let engine = make_strict_engine_with_deny(".env*");
        set_state_for_test(test_run(), GuardrailsState::Enabled(Box::new(engine)));
        assert_eq!(current_state_kind(test_run()), "enabled");

        assert!(
            check_file_access(test_run(), "src/main.rs").is_ok(),
            "enabled engine should allow non-denied paths"
        );

        let blocked = check_file_access(test_run(), ".env.local");
        assert!(blocked.is_err(), "deny rule must fire");
        let msg = blocked.unwrap_err();
        assert!(
            msg.contains("Blast radius"),
            "blocked-by-rule error should come from the engine, not              the poisoned-state sentinel: got {msg:?}"
        );
        assert!(!msg.contains("poisoned"));

        set_state_for_test(test_run(), GuardrailsState::Disabled);
    }

    #[test]
    fn test_749_configure_refuses_when_poisoned() {
        // Sticky-poison contract: once poisoned, configure() must NOT
        // silently re-arm the engine.
        let _serialize = lock_global_for_test();
        set_poisoned_for_test();

        let cfg = GuardrailsConfig::default();
        assert!(configure(test_run(), &cfg).is_err());

        assert_eq!(
            current_state_kind(test_run()),
            "poisoned",
            "configure() must be a no-op once the state is poisoned"
        );

        set_state_for_test(test_run(), GuardrailsState::Disabled);
    }

    #[test]
    fn test_749_non_security_paths_safe_when_poisoned() {
        // Non-security accessors must not panic or hang on poison.
        let _serialize = lock_global_for_test();
        set_poisoned_for_test();

        assert!(check_diff_thresholds(test_run()).is_none());
        assert!(run_quality_gates(test_run(), "test-model").is_empty());
        assert!(get_diff_summary(test_run()).is_none());
        record_file_modification(test_run(), "any.rs", 1, 0);

        set_state_for_test(test_run(), GuardrailsState::Disabled);
    }

    #[test]
    fn test_749_configure_with_all_disabled_yields_disabled_state() {
        // A `GuardrailsConfig::default()` has every guard disabled.
        // configure() must therefore leave the state as Disabled and
        // not allocate a real engine. This is what makes the global
        // API safe for the existing tools tests.
        let _serialize = lock_global_for_test();
        release_run(test_run());
        configure(test_run(), &GuardrailsConfig::default()).expect("disabled config");
        assert_eq!(current_state_kind(test_run()), "disabled");
        assert!(check_file_access(test_run(), "any/file.rs").is_ok());
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
        let outcome = run_shell_command_sync(test_run(), "printf %s hello", 5);
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
        let outcome = run_shell_command_sync(test_run(), "sh -c \"exit 7\"", 5);
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
        let outcome = run_shell_command_sync(test_run(), "sleep 30", 1);
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
            test_run(),
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
        let outcome = run_shell_command_sync(test_run(), "sh -c \"echo out; echo err 1>&2\"", 5);
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

        let _ = run_shell_command_sync(test_run(), &command, 5);

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
        let outcome = run_shell_command_sync(test_run(), "printf %s $(date)", 5);
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

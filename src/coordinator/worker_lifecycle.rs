//! Durable records for one coordinator-owned semantic worker slice.
//!
//! This module deliberately does not own execution, persistence, budgets,
//! cancellation, workspace access, or retry scheduling. Those authorities
//! remain with the canonical run descriptor, planner checkpoint, task graph,
//! and background-agent manager. It records only the semantic assignment and
//! the terminal artifact handoff that those existing authorities cannot
//! otherwise reconstruct after planner rotation.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::planner::{PlannerAttemptId, PlannerSourceId};
use crate::runtime::{ContentDigest, RunId};
use crate::task_graph::TaskId;

/// Maximum exact source links retained by one assignment.
pub const MAX_WORKER_SLICE_SOURCES: usize = 32;
/// Maximum exact prerequisite task links retained by one assignment.
pub const MAX_WORKER_SLICE_DEPENDENCIES: usize = 32;
/// Maximum acceptance digests retained by one assignment.
pub const MAX_WORKER_SLICE_ACCEPTANCE: usize = 32;
const MAX_MODEL_FINGERPRINT_BYTES: usize = 128;
const MAX_ARTIFACT_GENERATION_BYTES: usize = 128;
const MAX_ARTIFACT_LOCATOR_BYTES: usize = 4 * 1024;

/// Host-enforced worker profile selected for a semantic slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerProfile {
    GeneralPurpose,
    Explore,
    Plan,
    Guide,
}

/// Existing evidence-freshness generation for the exact selected model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerModelBinding {
    pub generation: u64,
    pub identity_sha256: String,
}

impl WorkerModelBinding {
    /// Bind the model generation already maintained by evidence freshness.
    ///
    /// # Errors
    /// Returns an error for an uninitialized generation or malformed digest.
    pub fn new(
        generation: u64,
        identity_sha256: impl Into<String>,
    ) -> Result<Self, WorkerLifecycleError> {
        let identity_sha256 = identity_sha256.into();
        if generation == 0 {
            return Err(WorkerLifecycleError::InvalidModelBinding(
                "model generation must be non-zero",
            ));
        }
        if identity_sha256.len() != 64
            || identity_sha256.len() > MAX_MODEL_FINGERPRINT_BYTES
            || !identity_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(WorkerLifecycleError::InvalidModelBinding(
                "model fingerprint must be a 64-byte hexadecimal SHA-256 digest",
            ));
        }
        Ok(Self {
            generation,
            identity_sha256,
        })
    }
}

/// Immutable semantic context given to one fresh supervised worker attempt.
///
/// The task graph retains the corresponding objective text, dependencies, and
/// budget. This record binds only exact digests and identities so a rotating
/// planner can prove which slice an attempt received without copying another
/// planning framework into the worker lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSliceAssignment {
    pub task_id: TaskId,
    pub task_revision: u64,
    pub profile: WorkerProfile,
    pub objective_digest: ContentDigest,
    pub sources: BTreeSet<PlannerSourceId>,
    pub dependencies: BTreeSet<TaskId>,
    pub acceptance_digests: BTreeSet<ContentDigest>,
    pub model: WorkerModelBinding,
    /// Host-local review locator only; it conveys no workspace authority.
    pub artifact_locator: Option<String>,
}

impl WorkerSliceAssignment {
    /// Create one immutable bounded assignment.
    ///
    /// # Errors
    /// Returns an error when the task revision is uninitialized, no source or
    /// acceptance contract was supplied, or a bounded set is oversized.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: TaskId,
        task_revision: u64,
        profile: WorkerProfile,
        objective_digest: ContentDigest,
        sources: BTreeSet<PlannerSourceId>,
        dependencies: BTreeSet<TaskId>,
        acceptance_digests: BTreeSet<ContentDigest>,
        model: WorkerModelBinding,
    ) -> Result<Self, WorkerLifecycleError> {
        if task_revision == 0 {
            return Err(WorkerLifecycleError::InvalidAssignment(
                "task revision must be non-zero",
            ));
        }
        validate_set_size(
            "assignment sources",
            sources.len(),
            MAX_WORKER_SLICE_SOURCES,
        )?;
        validate_set_size(
            "assignment dependencies",
            dependencies.len(),
            MAX_WORKER_SLICE_DEPENDENCIES,
        )?;
        validate_set_size(
            "assignment acceptance criteria",
            acceptance_digests.len(),
            MAX_WORKER_SLICE_ACCEPTANCE,
        )?;
        if sources.is_empty() {
            return Err(WorkerLifecycleError::InvalidAssignment(
                "at least one exact source is required",
            ));
        }
        if acceptance_digests.is_empty() {
            return Err(WorkerLifecycleError::InvalidAssignment(
                "at least one acceptance digest is required",
            ));
        }
        Ok(Self {
            task_id,
            task_revision,
            profile,
            objective_digest,
            sources,
            dependencies,
            acceptance_digests,
            model,
            artifact_locator: None,
        })
    }

    /// Bind the review location selected by the existing worktree authority.
    ///
    /// # Errors
    /// Returns an error for an empty or oversized locator.
    pub fn with_artifact_locator(
        mut self,
        locator: impl Into<String>,
    ) -> Result<Self, WorkerLifecycleError> {
        let locator = locator.into();
        if locator.is_empty() || locator.len() > MAX_ARTIFACT_LOCATOR_BYTES {
            return Err(WorkerLifecycleError::InvalidAssignment(
                "artifact locator must be a bounded non-empty value",
            ));
        }
        self.artifact_locator = Some(locator);
        Ok(self)
    }
}

/// Explicit state of artifacts left by one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerArtifactState {
    Clean,
    Untracked,
    Unstaged,
    Staged,
    Committed,
    Conflicted,
    Partial,
    Failed,
    Cancelled,
    Orphaned,
    InspectionFailed,
}

/// Supervisor decision for preserved worker artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerArtifactDisposition {
    None,
    ReviewRequired,
    Apply,
    Discard,
}

/// Exact, reviewable handoff of artifacts left by one worker attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerArtifactHandoff {
    pub generation: String,
    pub locator: Option<String>,
    pub states: BTreeSet<WorkerArtifactState>,
    pub disposition: WorkerArtifactDisposition,
    pub handed_off: bool,
}

impl WorkerArtifactHandoff {
    /// Construct an exact artifact observation.
    ///
    /// # Errors
    /// Returns an error when the generation or state set is absent/oversized.
    pub fn observed(
        generation: impl Into<String>,
        states: BTreeSet<WorkerArtifactState>,
    ) -> Result<Self, WorkerLifecycleError> {
        let generation = generation.into();
        if generation.is_empty() || generation.len() > MAX_ARTIFACT_GENERATION_BYTES {
            return Err(WorkerLifecycleError::InvalidArtifact(
                "artifact generation must be a bounded non-empty value",
            ));
        }
        if states.is_empty() || states.len() > 11 {
            return Err(WorkerLifecycleError::InvalidArtifact(
                "artifact state set must be non-empty and bounded",
            ));
        }
        let clean = states.len() == 1 && states.contains(&WorkerArtifactState::Clean);
        Ok(Self {
            generation,
            locator: None,
            states,
            disposition: if clean {
                WorkerArtifactDisposition::None
            } else {
                WorkerArtifactDisposition::ReviewRequired
            },
            handed_off: clean,
        })
    }

    /// Attach a bounded host-local locator for a preserved artifact set.
    ///
    /// # Errors
    /// Returns an error for an empty or oversized locator.
    pub fn with_locator(
        mut self,
        locator: impl Into<String>,
    ) -> Result<Self, WorkerLifecycleError> {
        let locator = locator.into();
        if locator.is_empty() || locator.len() > MAX_ARTIFACT_LOCATOR_BYTES {
            return Err(WorkerLifecycleError::InvalidArtifact(
                "artifact locator must be a bounded non-empty value",
            ));
        }
        self.locator = Some(locator);
        Ok(self)
    }

    /// Record that the preserved location and exact generation were returned
    /// to the supervising planner. This does not imply review or application.
    pub const fn mark_handed_off(&mut self) {
        self.handed_off = true;
    }

    /// Cleanup is safe only when the exact observation proves there is no
    /// worker-authored state to retain.
    #[must_use]
    pub fn cleanup_allowed(&self) -> bool {
        self.states.len() == 1 && self.states.contains(&WorkerArtifactState::Clean)
    }
}

/// Terminal lifecycle of one immutable attempt result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerTerminalState {
    Succeeded,
    Failed,
    Cancelled,
    Orphaned,
}

/// Runtime result captured before the planner allocates its canonical attempt
/// identity. The planner checkpoint converts this into [`WorkerSliceResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkerSliceOutcome {
    pub terminal: WorkerTerminalState,
    pub output_digest: ContentDigest,
    pub artifact: WorkerArtifactHandoff,
    pub recorded_at: DateTime<Utc>,
}

/// Durable result linked to the existing planner attempt and child run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSliceResult {
    pub attempt_id: PlannerAttemptId,
    pub run_id: RunId,
    pub task_id: TaskId,
    pub task_revision: u64,
    pub model: WorkerModelBinding,
    pub terminal: WorkerTerminalState,
    pub output_digest: ContentDigest,
    pub evidence: BTreeSet<PlannerSourceId>,
    pub artifact: WorkerArtifactHandoff,
    pub recorded_at: DateTime<Utc>,
}

impl WorkerSliceResult {
    #[must_use]
    pub(crate) fn from_outcome(
        attempt_id: PlannerAttemptId,
        run_id: RunId,
        assignment: &WorkerSliceAssignment,
        outcome: WorkerSliceOutcome,
    ) -> Self {
        let mut artifact = outcome.artifact;
        artifact.mark_handed_off();
        Self {
            attempt_id,
            run_id,
            task_id: assignment.task_id.clone(),
            task_revision: assignment.task_revision,
            model: assignment.model.clone(),
            terminal: outcome.terminal,
            output_digest: outcome.output_digest,
            evidence: assignment.sources.clone(),
            artifact,
            recorded_at: outcome.recorded_at,
        }
    }
}

/// Focused validation failures for semantic lifecycle records.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkerLifecycleError {
    #[error("invalid worker model binding: {0}")]
    InvalidModelBinding(&'static str),
    #[error("invalid worker assignment: {0}")]
    InvalidAssignment(&'static str),
    #[error("invalid worker artifact handoff: {0}")]
    InvalidArtifact(&'static str),
    #[error("worker lifecycle capacity exceeded for {resource}: {count} > {limit}")]
    Capacity {
        resource: &'static str,
        count: usize,
        limit: usize,
    },
}

const fn validate_set_size(
    resource: &'static str,
    count: usize,
    limit: usize,
) -> Result<(), WorkerLifecycleError> {
    if count > limit {
        return Err(WorkerLifecycleError::Capacity {
            resource,
            count,
            limit,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_requires_an_exact_clean_observation() {
        let clean = WorkerArtifactHandoff::observed(
            "sha256:clean",
            BTreeSet::from([WorkerArtifactState::Clean]),
        )
        .expect("clean handoff");
        let changed = WorkerArtifactHandoff::observed(
            "sha256:changed",
            BTreeSet::from([WorkerArtifactState::Untracked]),
        )
        .expect("changed handoff");

        assert!(clean.cleanup_allowed());
        assert!(!changed.cleanup_allowed());
        assert!(!changed.handed_off);
    }

    #[test]
    fn model_binding_rejects_uninitialized_generation() {
        let error = WorkerModelBinding::new(0, "0".repeat(64)).expect_err("generation zero");
        assert!(matches!(
            error,
            WorkerLifecycleError::InvalidModelBinding(_)
        ));
    }
}

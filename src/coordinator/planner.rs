//! Durable, capability-limited planner state and lease rotation.
//!
//! A planner context is disposable. This module persists the typed state that
//! a replacement planner is allowed to recover: the immutable user objective
//! and amendments, the canonical task graph, attempts, accepted decisions and
//! sources, artifact identities, approval evidence, aggregate budget state,
//! contradictions, and owned child runs. It deliberately stores neither a
//! predecessor transcript nor executable approval, secret, or capability
//! handles.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::persistence::{
    CommitReceipt, FileClass, PersistenceError, PersistentStorage, StorageGeneration,
};
use crate::runtime::{
    Actor, ActorId, ActorRole, BudgetId, BudgetLimits, BudgetSnapshot, CancellationId,
    CancellationReceipt, CapabilityBinding, CapabilityKind, ContentDigest, ProviderContinuation,
    RunBudget, RunDescriptor, RunDescriptorParts, RunId, WorkspaceBinding,
};
use crate::task_graph::{
    CanonicalTaskStatus, FieldUpdate, TaskActor, TaskGraph, TaskGraphError, TaskId, TaskSource,
    UpdateTask,
};

pub const PLANNER_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
pub const MAX_PLANNER_AMENDMENTS: usize = 256;
pub const MAX_PLANNER_RECORDS: usize = 2_048;
pub const MAX_PLANNER_CHILDREN: usize = 512;
pub const MAX_PLANNER_LEASE_HISTORY: usize = 1_024;
pub const MAX_OBJECTIVE_BYTES: usize = 64 * 1_024;
pub const MAX_AMENDMENT_BYTES: usize = 32 * 1_024;
pub const MAX_PLANNER_TEXT_BYTES: usize = 32 * 1_024;
pub const MAX_PLANNER_REFERENCE_BYTES: usize = 4 * 1_024;
pub const MAX_PLANNER_KIND_BYTES: usize = 128;
pub const MAX_PLANNER_CHECKPOINT_ID_BYTES: usize = 128;

macro_rules! planner_uuid_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

planner_uuid_id!(
    PlannerObjectiveId,
    "Identity of one immutable user objective."
);
planner_uuid_id!(
    PlannerAmendmentId,
    "Identity of one user objective amendment."
);
planner_uuid_id!(
    PlannerSourceId,
    "Identity of one accepted planner evidence source."
);
planner_uuid_id!(
    PlannerDecisionId,
    "Identity of one accepted planner decision."
);
planner_uuid_id!(PlannerArtifactId, "Identity of one artifact generation.");
planner_uuid_id!(
    PlannerApprovalId,
    "Identity of approval evidence visible to a planner."
);
planner_uuid_id!(PlannerAttemptId, "Identity of one task execution attempt.");
planner_uuid_id!(
    PlannerContradictionId,
    "Identity of one unresolved or resolved contradiction."
);
planner_uuid_id!(PlannerLeaseId, "Fencing identity of one planner lease.");

/// Monotonic version of the complete planner checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlannerCheckpointGeneration(u64);

impl PlannerCheckpointGeneration {
    #[must_use]
    pub const fn initial() -> Self {
        Self(1)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Result<Self, PlannerCheckpointError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(PlannerCheckpointError::GenerationExhausted)
    }
}

impl fmt::Display for PlannerCheckpointGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Immutable user-authored objective. The digest binds the exact text bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerObjective {
    pub id: PlannerObjectiveId,
    pub text: String,
    pub content_digest: ContentDigest,
    pub recorded_at: DateTime<Utc>,
}

impl PlannerObjective {
    #[must_use]
    pub fn new(text: impl Into<String>, recorded_at: DateTime<Utc>) -> Self {
        let text = text.into();
        let content_digest = ContentDigest::sha256(text.as_bytes());
        Self {
            id: PlannerObjectiveId::new(),
            text,
            content_digest,
            recorded_at,
        }
    }
}

/// Append-only user-authored amendment to the immutable objective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerAmendment {
    pub id: PlannerAmendmentId,
    pub text: String,
    pub content_digest: ContentDigest,
    pub recorded_at: DateTime<Utc>,
}

impl PlannerAmendment {
    #[must_use]
    pub fn new(text: impl Into<String>, recorded_at: DateTime<Utc>) -> Self {
        let text = text.into();
        let content_digest = ContentDigest::sha256(text.as_bytes());
        Self {
            id: PlannerAmendmentId::new(),
            text,
            content_digest,
            recorded_at,
        }
    }
}

/// Authority classification of evidence accepted into planner state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerEvidenceSource {
    User,
    Runtime,
    Tool,
    Artifact,
    HostPolicy,
    Verifier,
    ExternalReference,
}

/// Bounded source reference. The reference is navigation data and does not
/// become instruction authority when a fresh planner reconstructs its view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerEvidenceSourceRecord {
    pub id: PlannerSourceId,
    pub source: PlannerEvidenceSource,
    pub content_digest: ContentDigest,
    pub reference: String,
    pub observed_by: RunId,
    pub recorded_at: DateTime<Utc>,
}

/// Accepted decision with exact source links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerDecision {
    pub id: PlannerDecisionId,
    pub statement: String,
    pub sources: BTreeSet<PlannerSourceId>,
    pub accepted_by: RunId,
    pub recorded_at: DateTime<Utc>,
}

/// Immutable identity of an output artifact generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerArtifact {
    pub id: PlannerArtifactId,
    pub kind: String,
    pub generation: u64,
    pub digest: ContentDigest,
    pub producing_attempt: Option<PlannerAttemptId>,
    pub sources: BTreeSet<PlannerSourceId>,
    pub recorded_at: DateTime<Utc>,
}

/// Lifecycle of evidence about an approval. This is intentionally not an
/// execution permit: no value in this module can authorize a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerApprovalState {
    Observed,
    Consumed,
    Revoked,
    Expired,
}

/// Non-authoritative projection of a host approval receipt. The originating
/// run binding is immutable across rotation, preventing a successor planner
/// from treating persisted evidence as its own grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerApprovalEvidence {
    pub id: PlannerApprovalId,
    pub scope_digest: ContentDigest,
    pub evidence_digest: ContentDigest,
    pub originating_run: RunId,
    pub state: PlannerApprovalState,
    pub recorded_at: DateTime<Utc>,
}

/// Typed lifecycle of one task attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerAttemptState {
    Queued,
    Active,
    PartiallyDelivered,
    Succeeded,
    Failed,
    Cancelled,
}

impl PlannerAttemptState {
    const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Queued, Self::Active | Self::Failed | Self::Cancelled)
                    | (
                        Self::Active,
                        Self::PartiallyDelivered | Self::Succeeded | Self::Failed | Self::Cancelled
                    )
                    | (
                        Self::PartiallyDelivered,
                        Self::Succeeded | Self::Failed | Self::Cancelled
                    )
            )
    }
}

/// One canonical execution attempt bound to exact run and authority
/// generations. Attempt records carry provenance only; they do not rehydrate
/// any referenced capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerAttempt {
    pub id: PlannerAttemptId,
    pub task_id: TaskId,
    pub run_id: RunId,
    pub actor_id: ActorId,
    pub workspace_generation: u64,
    pub capability_generation: u64,
    pub budget_id: crate::runtime::BudgetId,
    pub budget_generation: u64,
    pub state: PlannerAttemptState,
    pub evidence: BTreeSet<PlannerSourceId>,
    pub artifacts: BTreeSet<PlannerArtifactId>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Child lifecycle visible at a planner handoff boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlannerChildState {
    Starting,
    Active,
    PartiallyDelivered,
    Succeeded,
    Failed,
    Cancelled { receipt: CancellationReceipt },
}

impl PlannerChildState {
    const fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Starting | Self::Active | Self::PartiallyDelivered
        )
    }

    fn can_transition_to(&self, next: &Self) -> bool {
        if self == next {
            return true;
        }
        matches!(
            (self, next),
            (
                Self::Starting,
                Self::Active | Self::Failed | Self::Cancelled { .. }
            ) | (
                Self::Active,
                Self::PartiallyDelivered | Self::Succeeded | Self::Failed | Self::Cancelled { .. }
            ) | (
                Self::PartiallyDelivered,
                Self::Succeeded | Self::Failed | Self::Cancelled { .. }
            )
        )
    }
}

/// Lease ownership of a live child. `Orphaned` is explicit recoverable state,
/// never an implicit fallback to the most recently loaded planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "owner", content = "lease_id", rename_all = "snake_case")]
pub enum PlannerChildOwner {
    Lease(PlannerLeaseId),
    Orphaned,
}

/// Durable child handle. The cancellation root lets rotation require evidence
/// that a child selected for cancellation was actually stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerChild {
    pub run_id: RunId,
    pub attempt_id: PlannerAttemptId,
    pub task_id: TaskId,
    pub delegation_agent_id: String,
    pub cancellation_root: CancellationId,
    pub workspace_generation: u64,
    pub capability_generation: u64,
    pub owner: PlannerChildOwner,
    pub state: PlannerChildState,
    pub updated_at: DateTime<Utc>,
}

/// Resolution state for conflicting accepted sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "decision_id", rename_all = "snake_case")]
pub enum PlannerContradictionState {
    Open,
    Resolved(PlannerDecisionId),
}

/// A contradiction remains first-class state until an accepted decision cites
/// its resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerContradiction {
    pub id: PlannerContradictionId,
    pub statement: String,
    pub sources: BTreeSet<PlannerSourceId>,
    pub state: PlannerContradictionState,
    pub recorded_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Complete typed state projected into each disposable planner context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerState {
    pub objective: PlannerObjective,
    pub amendments: Vec<PlannerAmendment>,
    pub task_graph: TaskGraph,
    pub attempts: BTreeMap<PlannerAttemptId, PlannerAttempt>,
    pub sources: BTreeMap<PlannerSourceId, PlannerEvidenceSourceRecord>,
    pub decisions: BTreeMap<PlannerDecisionId, PlannerDecision>,
    pub artifacts: BTreeMap<PlannerArtifactId, PlannerArtifact>,
    pub approvals: BTreeMap<PlannerApprovalId, PlannerApprovalEvidence>,
    pub budget: BudgetSnapshot,
    pub contradictions: BTreeMap<PlannerContradictionId, PlannerContradiction>,
    pub children: BTreeMap<RunId, PlannerChild>,
}

impl PlannerState {
    /// Create an empty typed planning ledger around the canonical task graph
    /// and aggregate budget snapshot. Subsequent checkpoints append accepted
    /// records or advance their explicit lifecycles.
    #[must_use]
    pub const fn new(
        objective: PlannerObjective,
        task_graph: TaskGraph,
        budget: BudgetSnapshot,
    ) -> Self {
        Self {
            objective,
            amendments: Vec::new(),
            task_graph,
            attempts: BTreeMap::new(),
            sources: BTreeMap::new(),
            decisions: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            approvals: BTreeMap::new(),
            budget,
            contradictions: BTreeMap::new(),
            children: BTreeMap::new(),
        }
    }
}

/// Current capability-limited planner lease. These values are immutable
/// descriptor metadata, not live handles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerLease {
    pub id: PlannerLeaseId,
    pub planner_run_id: RunId,
    pub planner_actor_id: ActorId,
    pub session_id: crate::state::SessionId,
    pub workspace: WorkspaceBinding,
    pub capabilities: CapabilityBinding,
    pub budget: RunBudget,
    pub cancellation_root: CancellationId,
    pub checkpoint_generation: PlannerCheckpointGeneration,
    pub acquired_at: DateTime<Utc>,
}

impl PlannerLease {
    fn from_descriptor(
        descriptor: &RunDescriptor,
        checkpoint_generation: PlannerCheckpointGeneration,
        acquired_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: PlannerLeaseId::new(),
            planner_run_id: descriptor.run_id,
            planner_actor_id: descriptor.actor.id,
            session_id: descriptor.session_id.clone(),
            workspace: descriptor.workspace.clone(),
            capabilities: descriptor.capabilities.clone(),
            budget: descriptor.budget.clone(),
            cancellation_root: descriptor.cancellation_root,
            checkpoint_generation,
            acquired_at,
        }
    }
}

/// Immutable record that an older planner lease reached a rotation boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerLeaseTombstone {
    pub lease_id: PlannerLeaseId,
    pub planner_run_id: RunId,
    pub planner_actor_id: ActorId,
    pub terminal_generation: PlannerCheckpointGeneration,
    pub successor_lease_id: PlannerLeaseId,
    pub rotated_at: DateTime<Utc>,
}

/// Strict persisted planner checkpoint. Its digest covers every field except
/// the digest itself and chains to the exact predecessor generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerCheckpoint {
    schema_version: u16,
    checkpoint_id: String,
    generation: PlannerCheckpointGeneration,
    previous_checkpoint_digest: Option<ContentDigest>,
    state: PlannerState,
    lease: PlannerLease,
    lease_history: Vec<PlannerLeaseTombstone>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    checkpoint_digest: ContentDigest,
}

impl PlannerCheckpoint {
    /// Create generation one for a fresh capability-limited planner.
    ///
    /// # Errors
    /// Returns an error for invalid typed state, a non-planner descriptor,
    /// provider continuation, mutating capability, or reset budget.
    pub fn new(
        checkpoint_id: impl Into<String>,
        state: PlannerState,
        planner: &RunDescriptor,
        now: DateTime<Utc>,
    ) -> Result<Self, PlannerCheckpointError> {
        let checkpoint_id = checkpoint_id.into();
        validate_checkpoint_id(&checkpoint_id)?;
        validate_planner_descriptor(planner)?;
        validate_budget_snapshot(&state.budget)?;
        validate_run_budget_within_snapshot(&planner.budget, &state.budget)?;
        let generation = PlannerCheckpointGeneration::initial();
        let lease = PlannerLease::from_descriptor(planner, generation, now);
        let mut checkpoint = Self {
            schema_version: PLANNER_CHECKPOINT_SCHEMA_VERSION,
            checkpoint_id,
            generation,
            previous_checkpoint_digest: None,
            state,
            lease,
            lease_history: Vec::new(),
            created_at: now,
            updated_at: now,
            checkpoint_digest: ContentDigest::sha256([]),
        };
        checkpoint.validate_without_digest()?;
        checkpoint.checkpoint_digest = checkpoint.compute_digest()?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    #[must_use]
    pub fn checkpoint_id(&self) -> &str {
        &self.checkpoint_id
    }

    #[must_use]
    pub const fn generation(&self) -> PlannerCheckpointGeneration {
        self.generation
    }

    #[must_use]
    pub const fn previous_checkpoint_digest(&self) -> Option<ContentDigest> {
        self.previous_checkpoint_digest
    }

    #[must_use]
    pub const fn checkpoint_digest(&self) -> ContentDigest {
        self.checkpoint_digest
    }

    #[must_use]
    pub const fn state(&self) -> &PlannerState {
        &self.state
    }

    #[must_use]
    pub const fn lease(&self) -> &PlannerLease {
        &self.lease
    }

    #[must_use]
    pub fn lease_history(&self) -> &[PlannerLeaseTombstone] {
        &self.lease_history
    }

    /// Build the next durable state checkpoint while retaining the current
    /// lease. The objective and every prior amendment/accepted record remain
    /// immutable; lifecycle records may only advance through typed states.
    ///
    /// # Errors
    /// Returns an error for stale input, rewritten immutable state, invalid
    /// transitions, budget rollback/reset, or an invalid complete snapshot.
    pub fn propose_state(
        &self,
        expected_generation: PlannerCheckpointGeneration,
        state: PlannerState,
        now: DateTime<Utc>,
    ) -> Result<Self, PlannerCheckpointError> {
        self.require_generation(expected_generation)?;
        self.validate()?;
        validate_state_evolution(&self.state, &state)?;
        let generation = self.generation.next()?;
        let mut lease = self.lease.clone();
        lease.checkpoint_generation = generation;
        self.finish_next(state, lease, self.lease_history.clone(), generation, now)
    }

    /// Build a generation-checked lease transfer to a fresh planner. Every
    /// live or orphaned child must be explicitly adopted or cancelled. A
    /// cancellation disposition must carry the child's exact runtime receipt.
    ///
    /// # Errors
    /// Returns an error for stale ownership, predecessor continuation,
    /// capability widening, budget reset, incomplete child reconciliation, or
    /// an invalid resulting checkpoint.
    pub fn propose_rotation(
        &self,
        rotation: &PlannerRotation,
    ) -> Result<Self, PlannerCheckpointError> {
        self.require_generation(rotation.expected_generation)?;
        self.validate()?;
        if rotation.expected_lease != self.lease.id {
            return Err(PlannerCheckpointError::StaleLease);
        }
        validate_successor(&self.lease, &self.state.budget, &rotation.successor)?;
        if rotation.rotated_at < self.updated_at {
            return Err(PlannerCheckpointError::InvalidField {
                field: "rotation time",
                reason: "rotation time precedes the current checkpoint",
            });
        }

        let generation = self.generation.next()?;
        let successor_lease =
            PlannerLease::from_descriptor(&rotation.successor, generation, rotation.rotated_at);
        let mut state = self.state.clone();
        reconcile_children(
            &mut state,
            &self.lease,
            &successor_lease,
            &rotation.child_dispositions,
            rotation.rotated_at,
        )?;

        let mut lease_history = self.lease_history.clone();
        if lease_history.len() >= MAX_PLANNER_LEASE_HISTORY {
            return Err(PlannerCheckpointError::Capacity {
                resource: "planner lease history",
                limit: MAX_PLANNER_LEASE_HISTORY,
            });
        }
        lease_history.push(PlannerLeaseTombstone {
            lease_id: self.lease.id,
            planner_run_id: self.lease.planner_run_id,
            planner_actor_id: self.lease.planner_actor_id,
            terminal_generation: self.generation,
            successor_lease_id: successor_lease.id,
            rotated_at: rotation.rotated_at,
        });
        self.finish_next(
            state,
            successor_lease,
            lease_history,
            generation,
            rotation.rotated_at,
        )
    }

    /// Validate schema, causal digest, state closure, lease authority, and all
    /// bounded relationships after deserialization.
    ///
    /// # Errors
    /// Returns the first unsupported, malformed, widened, or inconsistent
    /// persisted field.
    pub fn validate(&self) -> Result<(), PlannerCheckpointError> {
        self.validate_without_digest()?;
        if self.compute_digest()? != self.checkpoint_digest {
            return Err(PlannerCheckpointError::DigestMismatch);
        }
        Ok(())
    }

    fn finish_next(
        &self,
        state: PlannerState,
        lease: PlannerLease,
        lease_history: Vec<PlannerLeaseTombstone>,
        generation: PlannerCheckpointGeneration,
        now: DateTime<Utc>,
    ) -> Result<Self, PlannerCheckpointError> {
        if now < self.updated_at {
            return Err(PlannerCheckpointError::InvalidField {
                field: "checkpoint time",
                reason: "checkpoint time is not monotonic",
            });
        }
        let mut checkpoint = Self {
            schema_version: self.schema_version,
            checkpoint_id: self.checkpoint_id.clone(),
            generation,
            previous_checkpoint_digest: Some(self.checkpoint_digest),
            state,
            lease,
            lease_history,
            created_at: self.created_at,
            updated_at: now,
            checkpoint_digest: ContentDigest::sha256([]),
        };
        checkpoint.validate_without_digest()?;
        checkpoint.checkpoint_digest = checkpoint.compute_digest()?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    fn validate_without_digest(&self) -> Result<(), PlannerCheckpointError> {
        if self.schema_version != PLANNER_CHECKPOINT_SCHEMA_VERSION {
            return Err(PlannerCheckpointError::UnsupportedSchema {
                observed: self.schema_version,
                expected: PLANNER_CHECKPOINT_SCHEMA_VERSION,
            });
        }
        validate_checkpoint_id(&self.checkpoint_id)?;
        if self.generation.get() == 0 {
            return Err(PlannerCheckpointError::InvalidField {
                field: "checkpoint generation",
                reason: "generation must be non-zero",
            });
        }
        if (self.generation == PlannerCheckpointGeneration::initial())
            != self.previous_checkpoint_digest.is_none()
        {
            return Err(PlannerCheckpointError::InvalidField {
                field: "checkpoint predecessor",
                reason: "only generation one may omit its predecessor digest",
            });
        }
        if self.updated_at < self.created_at {
            return Err(PlannerCheckpointError::InvalidField {
                field: "checkpoint time",
                reason: "update time precedes creation",
            });
        }
        if self.lease.checkpoint_generation != self.generation {
            return Err(PlannerCheckpointError::InvalidField {
                field: "planner lease",
                reason: "lease fencing generation differs from checkpoint generation",
            });
        }
        if self.lease_history.len() > MAX_PLANNER_LEASE_HISTORY {
            return Err(PlannerCheckpointError::Capacity {
                resource: "planner lease history",
                limit: MAX_PLANNER_LEASE_HISTORY,
            });
        }
        validate_planner_lease(&self.lease)?;
        validate_state(&self.state, &self.lease)?;
        validate_lease_history(&self.lease_history, &self.lease)?;
        Ok(())
    }

    fn require_generation(
        &self,
        expected: PlannerCheckpointGeneration,
    ) -> Result<(), PlannerCheckpointError> {
        if expected == self.generation {
            Ok(())
        } else {
            Err(PlannerCheckpointError::StaleCheckpoint {
                expected,
                observed: self.generation,
            })
        }
    }

    fn compute_digest(&self) -> Result<ContentDigest, PlannerCheckpointError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            domain: &'static str,
            schema_version: u16,
            checkpoint_id: &'a str,
            generation: PlannerCheckpointGeneration,
            previous_checkpoint_digest: Option<ContentDigest>,
            state: &'a PlannerState,
            lease: &'a PlannerLease,
            lease_history: &'a [PlannerLeaseTombstone],
            created_at: DateTime<Utc>,
            updated_at: DateTime<Utc>,
        }

        let bytes = serde_json::to_vec(&DigestInput {
            domain: "openclaudia.planner-checkpoint.v1",
            schema_version: self.schema_version,
            checkpoint_id: &self.checkpoint_id,
            generation: self.generation,
            previous_checkpoint_digest: self.previous_checkpoint_digest,
            state: &self.state,
            lease: &self.lease,
            lease_history: &self.lease_history,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
        .map_err(|_| PlannerCheckpointError::InvalidJson)?;
        Ok(ContentDigest::sha256(bytes))
    }
}

/// Required disposition for each live child at rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannerChildDisposition {
    Adopt,
    Cancel { receipt: CancellationReceipt },
}

/// One atomic planner-lease transfer request.
#[derive(Debug, Clone)]
pub struct PlannerRotation {
    pub expected_generation: PlannerCheckpointGeneration,
    pub expected_lease: PlannerLeaseId,
    pub successor: RunDescriptor,
    pub child_dispositions: BTreeMap<RunId, PlannerChildDisposition>,
    pub rotated_at: DateTime<Utc>,
}

/// Descriptor-safe durable store for one exact planner checkpoint document.
#[derive(Clone, Debug)]
pub struct PlannerCheckpointStore {
    storage: PersistentStorage,
    target: PathBuf,
    checkpoint_id: String,
}

/// Loaded checkpoint plus the exact storage generation required for publish.
#[derive(Debug)]
pub struct StoredPlannerCheckpoint {
    pub checkpoint: PlannerCheckpoint,
    pub storage_generation: StorageGeneration,
}

impl PlannerCheckpointStore {
    /// Open the private host-local checkpoint document for one session run.
    ///
    /// The store identity follows the canonical session identity rather than
    /// a disposable planner run, so a replacement process finds the same
    /// checkpoint before acquiring a fresh lease.
    ///
    /// # Errors
    /// Returns an error when the host data root is unavailable or unsafe.
    pub fn open_for_run(
        run: &crate::tools::ToolRunContext,
    ) -> Result<Self, PlannerCheckpointError> {
        let root = dirs::data_local_dir()
            .ok_or(PlannerCheckpointError::HostDataUnavailable)?
            .join("openclaudia")
            .join("planner_checkpoints");
        prepare_private_checkpoint_root(&root)?;
        Self::open(
            &root,
            format!("{}.json", run.session_id()),
            format!("session:{}", run.session_id()),
        )
    }

    /// Bind an existing host-authorized persistence root and one checkpoint
    /// identity.
    ///
    /// # Errors
    /// Returns an error for an invalid identity or persistence root.
    pub fn open(
        root: impl AsRef<Path>,
        target: impl Into<PathBuf>,
        checkpoint_id: impl Into<String>,
    ) -> Result<Self, PlannerCheckpointError> {
        let checkpoint_id = checkpoint_id.into();
        validate_checkpoint_id(&checkpoint_id)?;
        Ok(Self {
            storage: PersistentStorage::open(root)?,
            target: target.into(),
            checkpoint_id,
        })
    }

    /// Strictly load and validate an existing checkpoint. Missing state is an
    /// explicit error because an objective cannot be synthesized on resume.
    ///
    /// # Errors
    /// Returns an error for missing, malformed, future, identity-mismatched,
    /// causally invalid, or widened state.
    pub fn load(&self) -> Result<StoredPlannerCheckpoint, PlannerCheckpointError> {
        let read = self.storage.read(&self.target, FileClass::State)?;
        let storage_generation = read.generation();
        let checkpoint = read.expose_bytes(|bytes| {
            let bytes = bytes.ok_or(PlannerCheckpointError::MissingCheckpoint)?;
            serde_json::from_slice::<PlannerCheckpoint>(bytes)
                .map_err(|_| PlannerCheckpointError::InvalidJson)
        })?;
        if checkpoint.checkpoint_id != self.checkpoint_id {
            return Err(PlannerCheckpointError::IdentityMismatch);
        }
        checkpoint.validate()?;
        Ok(StoredPlannerCheckpoint {
            checkpoint,
            storage_generation,
        })
    }

    /// Atomically publish a validated checkpoint under the exact observed
    /// storage generation.
    ///
    /// # Errors
    /// Returns an error for invalid state, identity mismatch, stale storage,
    /// or failed durable publication.
    pub fn commit(
        &self,
        expected: StorageGeneration,
        checkpoint: &PlannerCheckpoint,
    ) -> Result<CommitReceipt, PlannerCheckpointError> {
        checkpoint.validate()?;
        if checkpoint.checkpoint_id != self.checkpoint_id {
            return Err(PlannerCheckpointError::IdentityMismatch);
        }
        let bytes =
            serde_json::to_vec(checkpoint).map_err(|_| PlannerCheckpointError::InvalidJson)?;
        self.storage
            .commit(&self.target, FileClass::State, expected, bytes)
            .map_err(PlannerCheckpointError::from)
    }

    /// Validate, reconcile, and atomically publish one lease rotation against
    /// the storage generation loaded by the caller.
    ///
    /// # Errors
    /// Returns any proposal or durable compare-and-swap failure without
    /// changing the previously stored checkpoint.
    pub fn rotate_and_commit(
        &self,
        stored: &StoredPlannerCheckpoint,
        rotation: &PlannerRotation,
    ) -> Result<(PlannerCheckpoint, CommitReceipt), PlannerCheckpointError> {
        let checkpoint = stored.checkpoint.propose_rotation(rotation)?;
        let receipt = self.commit(stored.storage_generation, &checkpoint)?;
        Ok((checkpoint, receipt))
    }

    /// Validate and atomically publish one non-rotation state checkpoint.
    ///
    /// # Errors
    /// Returns any state-evolution or durable compare-and-swap failure without
    /// changing the previously stored checkpoint.
    pub fn checkpoint_and_commit(
        &self,
        stored: &StoredPlannerCheckpoint,
        expected_generation: PlannerCheckpointGeneration,
        state: PlannerState,
        now: DateTime<Utc>,
    ) -> Result<(PlannerCheckpoint, CommitReceipt), PlannerCheckpointError> {
        let checkpoint = stored
            .checkpoint
            .propose_state(expected_generation, state, now)?;
        let receipt = self.commit(stored.storage_generation, &checkpoint)?;
        Ok((checkpoint, receipt))
    }
}

/// Live frontend binding for one durable, disposable-planner lineage.
///
/// The frontend remains the supervisor that owns concrete provider and worker
/// handles. The planner lease records only its non-mutating authority subset;
/// it cannot be rehydrated into frontend capabilities after restart.
pub struct PlannerRuntime {
    store: PlannerCheckpointStore,
    stored: Option<StoredPlannerCheckpoint>,
    budget_observation: BudgetSnapshot,
}

impl PlannerRuntime {
    /// Open any existing session checkpoint without acquiring its lease yet.
    /// A fresh lease is acquired atomically by [`Self::prepare_turn`].
    ///
    /// # Errors
    /// Returns an error for an unsafe store, malformed checkpoint, or budget
    /// authority that cannot be observed.
    pub fn open_for_run(
        run: &crate::tools::ToolRunContext,
    ) -> Result<Self, PlannerCheckpointError> {
        let store = PlannerCheckpointStore::open_for_run(run)?;
        let stored = match store.load() {
            Ok(stored) => Some(stored),
            Err(PlannerCheckpointError::MissingCheckpoint) => None,
            Err(error) => return Err(error),
        };
        let budget_observation = run
            .budget()
            .snapshot()
            .map_err(|_| PlannerCheckpointError::BudgetUnavailable)?;
        Ok(Self {
            store,
            stored,
            budget_observation,
        })
    }

    /// Checkpoint current typed state and transfer the lease before a new
    /// coordinator provider turn. The first user instruction creates the
    /// immutable objective; later instructions are append-only amendments.
    ///
    /// # Errors
    /// Returns an error without publishing a successor lease when state,
    /// authority, storage, or aggregate budget validation fails.
    pub fn prepare_turn(
        &mut self,
        supervisor: &crate::tools::ToolRunContext,
        task_graph: &TaskGraph,
        user_instruction: &str,
        now: DateTime<Utc>,
        admit: impl Fn(&crate::context::ContextItem) -> bool,
    ) -> Result<crate::context::ContextItem, PlannerCheckpointError> {
        if self.stored.is_none() {
            let aggregate = supervisor
                .budget()
                .snapshot()
                .map_err(|_| PlannerCheckpointError::BudgetUnavailable)?;
            let limits = remaining_limits(&aggregate)?;
            let descriptor = planner_descriptor(supervisor, limits)?;
            let state = PlannerState::new(
                PlannerObjective::new(user_instruction, now),
                task_graph.clone(),
                aggregate.clone(),
            );
            let checkpoint = PlannerCheckpoint::new(
                format!("session:{}", supervisor.session_id()),
                state,
                &descriptor,
                now,
            )?;
            let context = checkpoint_context_item(&checkpoint)?;
            if !admit(&context) {
                return Err(PlannerCheckpointError::ProjectionNotAdmitted);
            }
            let receipt = self.store.commit(StorageGeneration::Missing, &checkpoint)?;
            self.stored = Some(StoredPlannerCheckpoint {
                checkpoint,
                storage_generation: receipt.generation(),
            });
            self.budget_observation = aggregate;
            return Ok(context);
        }
        self.checkpoint_state(
            supervisor,
            task_graph,
            Some(PlannerAmendment::new(user_instruction, now)),
            now,
        )?;
        self.rotate(supervisor, now, admit)
    }

    /// Publish task and aggregate-budget progress after the coordinator turn.
    ///
    /// # Errors
    /// Returns an error if the durable generation changed concurrently or the
    /// proposed task/budget state is not a monotonic extension.
    pub fn checkpoint_progress(
        &mut self,
        supervisor: &crate::tools::ToolRunContext,
        task_graph: &TaskGraph,
        now: DateTime<Utc>,
    ) -> Result<(), PlannerCheckpointError> {
        if self.stored.is_none() {
            return Err(PlannerCheckpointError::MissingCheckpoint);
        }
        self.checkpoint_state(supervisor, task_graph, None, now)
    }

    fn checkpoint_state(
        &mut self,
        supervisor: &crate::tools::ToolRunContext,
        task_graph: &TaskGraph,
        amendment: Option<PlannerAmendment>,
        now: DateTime<Utc>,
    ) -> Result<(), PlannerCheckpointError> {
        let live_budget = supervisor
            .budget()
            .snapshot()
            .map_err(|_| PlannerCheckpointError::BudgetUnavailable)?;
        let stored = self
            .stored
            .as_ref()
            .ok_or(PlannerCheckpointError::MissingCheckpoint)?;
        validate_supervisor_binding(supervisor, &stored.checkpoint)?;
        let mut state = stored.checkpoint.state().clone();
        state.task_graph = task_graph.clone();
        synchronize_children(&mut state, stored.checkpoint.lease().id, supervisor, now)?;
        state.budget = accumulate_budget(&state.budget, &self.budget_observation, &live_budget)?;
        if let Some(amendment) = amendment {
            state.amendments.push(amendment);
        }
        let (checkpoint, receipt) =
            self.store
                .checkpoint_and_commit(stored, stored.checkpoint.generation(), state, now)?;
        self.stored = Some(StoredPlannerCheckpoint {
            checkpoint,
            storage_generation: receipt.generation(),
        });
        self.budget_observation = live_budget;
        Ok(())
    }

    fn rotate(
        &mut self,
        supervisor: &crate::tools::ToolRunContext,
        now: DateTime<Utc>,
        admit: impl Fn(&crate::context::ContextItem) -> bool,
    ) -> Result<crate::context::ContextItem, PlannerCheckpointError> {
        let stored = self
            .stored
            .as_ref()
            .ok_or(PlannerCheckpointError::MissingCheckpoint)?;
        validate_supervisor_binding(supervisor, &stored.checkpoint)?;
        let successor = planner_descriptor(
            supervisor,
            remaining_limits(&stored.checkpoint.state().budget)?,
        )?;
        let child_dispositions = stored
            .checkpoint
            .state()
            .children
            .iter()
            .filter_map(|(run_id, child)| {
                child
                    .state
                    .is_live()
                    .then_some((*run_id, PlannerChildDisposition::Adopt))
            })
            .collect();
        let rotation = PlannerRotation {
            expected_generation: stored.checkpoint.generation(),
            expected_lease: stored.checkpoint.lease().id,
            successor,
            child_dispositions,
            rotated_at: now,
        };
        let checkpoint = stored.checkpoint.propose_rotation(&rotation)?;
        let context = checkpoint_context_item(&checkpoint)?;
        if !admit(&context) {
            return Err(PlannerCheckpointError::ProjectionNotAdmitted);
        }
        let receipt = self.store.commit(stored.storage_generation, &checkpoint)?;
        self.stored = Some(StoredPlannerCheckpoint {
            checkpoint,
            storage_generation: receipt.generation(),
        });
        Ok(context)
    }
}

fn checkpoint_context_item(
    checkpoint: &PlannerCheckpoint,
) -> Result<crate::context::ContextItem, PlannerCheckpointError> {
    let content =
        serde_json::to_string(checkpoint).map_err(|_| PlannerCheckpointError::InvalidJson)?;
    Ok(crate::context::ContextItem::reference(
        "repl.planner_checkpoint",
        crate::context::ReferenceSource::Session,
        format!(
            "planner-checkpoint:{}:{}",
            checkpoint.checkpoint_id(),
            checkpoint.generation()
        ),
        content,
        crate::context::ContextFreshness::Snapshot {
            generation: checkpoint.generation().get(),
        },
        10,
    )
    .with_truncation(false))
}

/// Typed planner checkpoint failure. Error messages never contain objective,
/// decision, source, artifact, or child-result prose.
#[derive(Debug, Error)]
pub enum PlannerCheckpointError {
    #[error("planner checkpoint schema {observed} is unsupported; expected {expected}")]
    UnsupportedSchema { observed: u16, expected: u16 },
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("planner checkpoint capacity exceeded for {resource} (limit {limit})")]
    Capacity {
        resource: &'static str,
        limit: usize,
    },
    #[error("planner checkpoint generation space is exhausted")]
    GenerationExhausted,
    #[error("stale planner checkpoint generation: expected {expected}, observed {observed}")]
    StaleCheckpoint {
        expected: PlannerCheckpointGeneration,
        observed: PlannerCheckpointGeneration,
    },
    #[error("planner lease is stale")]
    StaleLease,
    #[error("planner checkpoint digest does not match its typed contents")]
    DigestMismatch,
    #[error("planner checkpoint JSON is invalid")]
    InvalidJson,
    #[error("planner checkpoint does not exist")]
    MissingCheckpoint,
    #[error("host-local planner checkpoint directory is unavailable")]
    HostDataUnavailable,
    #[error("host-local planner checkpoint directory is unsafe or inaccessible")]
    UnsafeStorageRoot,
    #[error("live planner budget state is unavailable")]
    BudgetUnavailable,
    #[error("live subagent ownership state is unavailable")]
    SubagentStateUnavailable,
    #[error("the complete planner checkpoint projection was not admitted")]
    ProjectionNotAdmitted,
    #[error("planner checkpoint identity differs from its store binding")]
    IdentityMismatch,
    #[error("planner capability profile contains a forbidden effect")]
    ForbiddenPlannerCapability,
    #[error("successor planner capability profile widens the current lease")]
    CapabilityWidening,
    #[error("successor planner budget exceeds remaining aggregate authority")]
    BudgetWidening,
    #[error("live child lacks an explicit adopt or cancel disposition")]
    MissingChildDisposition,
    #[error("rotation contains a disposition for a non-live or unknown child")]
    UnexpectedChildDisposition,
    #[error("child cancellation receipt is not bound to its exact run root")]
    InvalidChildCancellation,
    #[error("planner state rewrites an immutable accepted record")]
    ImmutableRecordChanged,
    #[error("planner lifecycle transition is invalid")]
    InvalidTransition,
    #[error(transparent)]
    TaskGraph(#[from] TaskGraphError),
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

fn prepare_private_checkpoint_root(root: &Path) -> Result<(), PlannerCheckpointError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(PlannerCheckpointError::UnsafeStorageRoot);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder
                    .create(root)
                    .map_err(|_| PlannerCheckpointError::UnsafeStorageRoot)?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(root).map_err(|_| PlannerCheckpointError::UnsafeStorageRoot)?;
        }
        Err(_) => return Err(PlannerCheckpointError::UnsafeStorageRoot),
    }

    let metadata =
        fs::symlink_metadata(root).map_err(|_| PlannerCheckpointError::UnsafeStorageRoot)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PlannerCheckpointError::UnsafeStorageRoot);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        // SAFETY: `geteuid` has no preconditions and retains no pointer.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(PlannerCheckpointError::UnsafeStorageRoot);
        }
    }
    Ok(())
}

fn validate_supervisor_binding(
    supervisor: &crate::tools::ToolRunContext,
    checkpoint: &PlannerCheckpoint,
) -> Result<(), PlannerCheckpointError> {
    let descriptor = supervisor.runtime().descriptor();
    if descriptor.session_id != checkpoint.lease().session_id
        || descriptor.workspace.root() != checkpoint.lease().workspace.root()
        || descriptor.workspace.digest != checkpoint.lease().workspace.digest
    {
        return Err(PlannerCheckpointError::InvalidField {
            field: "planner supervisor binding",
            reason: "session or workspace identity differs from the durable lease",
        });
    }
    Ok(())
}

fn planner_descriptor(
    supervisor: &crate::tools::ToolRunContext,
    limits: BudgetLimits,
) -> Result<RunDescriptor, PlannerCheckpointError> {
    let supervisor_descriptor = supervisor.runtime().descriptor();
    let run_id = RunId::new();
    let grants = supervisor_descriptor
        .capabilities
        .grants
        .iter()
        .copied()
        .filter(|capability| {
            matches!(
                capability,
                CapabilityKind::ContextAssembly
                    | CapabilityKind::Provider
                    | CapabilityKind::WorkspaceRead
                    | CapabilityKind::Hooks
                    | CapabilityKind::Memory
                    | CapabilityKind::Trace
            )
        })
        .collect::<BTreeSet<_>>();
    let manifest_bytes = serde_json::to_vec(&(
        "openclaudia.planner-capability.v1",
        run_id,
        supervisor_descriptor.capabilities.generation,
        &grants,
    ))
    .map_err(|_| PlannerCheckpointError::InvalidJson)?;
    let provider = match &supervisor_descriptor.provider_continuation {
        ProviderContinuation::Fresh { provider }
        | ProviderContinuation::Resume { provider, .. } => provider.clone(),
    };
    RunDescriptor::new(RunDescriptorParts {
        run_id,
        session_id: supervisor_descriptor.session_id.clone(),
        actor: Actor {
            id: ActorId::new(),
            role: ActorRole::Planner,
        },
        workspace: supervisor_descriptor.workspace.clone(),
        capabilities: CapabilityBinding {
            generation: supervisor_descriptor.capabilities.generation,
            manifest_digest: ContentDigest::sha256(manifest_bytes),
            grants,
        },
        budget: RunBudget {
            id: BudgetId::new(),
            generation: supervisor_descriptor.budget.generation,
            limits,
        },
        provider_continuation: ProviderContinuation::Fresh { provider },
        cancellation_root: CancellationId::new(),
        initial_state: supervisor_descriptor.initial_state.clone(),
    })
    .map_err(|_| PlannerCheckpointError::InvalidField {
        field: "planner descriptor",
        reason: "derived planner authority is invalid",
    })
}

fn accumulate_budget(
    aggregate: &BudgetSnapshot,
    previous: &BudgetSnapshot,
    current: &BudgetSnapshot,
) -> Result<BudgetSnapshot, PlannerCheckpointError> {
    if previous.budget_id != current.budget_id
        || previous.generation != current.generation
        || previous.limits != current.limits
        || current.elapsed_millis < previous.elapsed_millis
    {
        return Err(PlannerCheckpointError::BudgetWidening);
    }
    let add = |total: u64, prior: u64, observed: u64| {
        observed
            .checked_sub(prior)
            .and_then(|delta| total.checked_add(delta))
            .ok_or(PlannerCheckpointError::BudgetWidening)
    };
    let mut next = aggregate.clone();
    next.used.input_tokens = add(
        aggregate.used.input_tokens,
        previous.used.input_tokens,
        current.used.input_tokens,
    )?;
    next.used.output_tokens = add(
        aggregate.used.output_tokens,
        previous.used.output_tokens,
        current.used.output_tokens,
    )?;
    next.used.turns = add(
        aggregate.used.turns,
        previous.used.turns,
        current.used.turns,
    )?;
    next.used.provider_calls = add(
        aggregate.used.provider_calls,
        previous.used.provider_calls,
        current.used.provider_calls,
    )?;
    next.used.tool_calls = add(
        aggregate.used.tool_calls,
        previous.used.tool_calls,
        current.used.tool_calls,
    )?;
    next.used.retries = add(
        aggregate.used.retries,
        previous.used.retries,
        current.used.retries,
    )?;
    next.used.child_runs = add(
        aggregate.used.child_runs,
        previous.used.child_runs,
        current.used.child_runs,
    )?;
    next.used.cost_microusd = add(
        aggregate.used.cost_microusd,
        previous.used.cost_microusd,
        current.used.cost_microusd,
    )?;
    next.elapsed_millis = add(
        aggregate.elapsed_millis,
        previous.elapsed_millis,
        current.elapsed_millis,
    )?;
    next.remaining_elapsed_millis = next
        .limits
        .elapsed_millis
        .saturating_sub(next.elapsed_millis);
    validate_budget_snapshot(&next)?;
    Ok(next)
}

fn synchronize_children(
    state: &mut PlannerState,
    lease_id: PlannerLeaseId,
    supervisor: &crate::tools::ToolRunContext,
    now: DateTime<Utc>,
) -> Result<(), PlannerCheckpointError> {
    let snapshots = crate::subagent::BACKGROUND_AGENTS
        .child_snapshots_for_run(supervisor)
        .map_err(|_| PlannerCheckpointError::SubagentStateUnavailable)?;
    let observed = snapshots
        .iter()
        .map(|snapshot| snapshot.descriptor.run_id)
        .collect::<BTreeSet<_>>();
    for child in state.children.values_mut() {
        if child.state.is_live() && !observed.contains(&child.run_id) {
            child.owner = PlannerChildOwner::Orphaned;
            child.updated_at = now;
        }
    }

    for snapshot in snapshots {
        synchronize_child_snapshot(state, lease_id, supervisor, snapshot, now)?;
    }
    Ok(())
}

fn synchronize_child_snapshot(
    state: &mut PlannerState,
    lease_id: PlannerLeaseId,
    supervisor: &crate::tools::ToolRunContext,
    snapshot: crate::subagent::BackgroundChildSnapshot,
    now: DateTime<Utc>,
) -> Result<(), PlannerCheckpointError> {
    let descriptor = snapshot.descriptor;
    if descriptor.actor.role != ActorRole::Worker
        || descriptor.session_id.as_str() != supervisor.session_id()
    {
        return Err(PlannerCheckpointError::SubagentStateUnavailable);
    }
    let task_id = TaskId::parse(snapshot.task_id)
        .map_err(|_| PlannerCheckpointError::SubagentStateUnavailable)?;
    let task = state
        .task_graph
        .task(&task_id)
        .ok_or(PlannerCheckpointError::SubagentStateUnavailable)?;
    let TaskSource::Delegation { agent_id } = &task.source else {
        return Err(PlannerCheckpointError::SubagentStateUnavailable);
    };
    if agent_id != &snapshot.agent_id {
        return Err(PlannerCheckpointError::SubagentStateUnavailable);
    }
    let (attempt_state, child_state) = child_snapshot_states(
        snapshot.finished,
        snapshot.failed,
        snapshot.cancellation_receipt,
        task.status,
    )?;
    let run_id = descriptor.run_id;
    if let Some(child) = state.children.get_mut(&run_id) {
        let attempt = state
            .attempts
            .get_mut(&child.attempt_id)
            .ok_or(PlannerCheckpointError::SubagentStateUnavailable)?;
        if child.task_id != task_id
            || child.delegation_agent_id != snapshot.agent_id
            || child.cancellation_root != descriptor.cancellation_root
            || attempt.run_id != run_id
            || !attempt.state.can_transition_to(attempt_state)
            || !child.state.can_transition_to(&child_state)
        {
            return Err(PlannerCheckpointError::SubagentStateUnavailable);
        }
        attempt.state = attempt_state;
        attempt.updated_at = now;
        child.state = child_state;
        if child.state.is_live() {
            child.owner = PlannerChildOwner::Lease(lease_id);
        }
        child.updated_at = now;
        return Ok(());
    }

    let attempt_id = PlannerAttemptId::new();
    state.attempts.insert(
        attempt_id,
        PlannerAttempt {
            id: attempt_id,
            task_id: task_id.clone(),
            run_id,
            actor_id: descriptor.actor.id,
            workspace_generation: descriptor.workspace.generation.get(),
            capability_generation: descriptor.capabilities.generation.get(),
            budget_id: descriptor.budget.id,
            budget_generation: descriptor.budget.generation.get(),
            state: attempt_state,
            evidence: BTreeSet::new(),
            artifacts: BTreeSet::new(),
            started_at: task.created_at,
            updated_at: now,
        },
    );
    state.children.insert(
        run_id,
        PlannerChild {
            run_id,
            attempt_id,
            task_id,
            delegation_agent_id: snapshot.agent_id,
            cancellation_root: descriptor.cancellation_root,
            workspace_generation: descriptor.workspace.generation.get(),
            capability_generation: descriptor.capabilities.generation.get(),
            owner: if child_state.is_live() {
                PlannerChildOwner::Lease(lease_id)
            } else {
                PlannerChildOwner::Orphaned
            },
            state: child_state,
            updated_at: now,
        },
    );
    Ok(())
}

fn child_snapshot_states(
    finished: bool,
    failed: bool,
    cancellation_receipt: Option<CancellationReceipt>,
    task_status: CanonicalTaskStatus,
) -> Result<(PlannerAttemptState, PlannerChildState), PlannerCheckpointError> {
    match (finished, failed, cancellation_receipt, task_status) {
        (false, false, None, CanonicalTaskStatus::InProgress) => {
            Ok((PlannerAttemptState::Active, PlannerChildState::Active))
        }
        (true, false, None, CanonicalTaskStatus::Completed) => {
            Ok((PlannerAttemptState::Succeeded, PlannerChildState::Succeeded))
        }
        (true, true, None, CanonicalTaskStatus::Failed) => {
            Ok((PlannerAttemptState::Failed, PlannerChildState::Failed))
        }
        (true, true, Some(receipt), CanonicalTaskStatus::Canceled) => Ok((
            PlannerAttemptState::Cancelled,
            PlannerChildState::Cancelled { receipt },
        )),
        _ => Err(PlannerCheckpointError::SubagentStateUnavailable),
    }
}

fn validate_checkpoint_id(value: &str) -> Result<(), PlannerCheckpointError> {
    if value.is_empty()
        || value.len() > MAX_PLANNER_CHECKPOINT_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(PlannerCheckpointError::InvalidField {
            field: "planner checkpoint id",
            reason: "identity must contain only bounded ASCII identifier bytes",
        });
    }
    Ok(())
}

const fn validate_text(
    field: &'static str,
    value: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), PlannerCheckpointError> {
    if (!allow_empty && value.is_empty()) || value.len() > maximum {
        return Err(PlannerCheckpointError::InvalidField {
            field,
            reason: "text is empty or exceeds its byte bound",
        });
    }
    Ok(())
}

fn validate_planner_descriptor(descriptor: &RunDescriptor) -> Result<(), PlannerCheckpointError> {
    descriptor
        .validate()
        .map_err(|_| PlannerCheckpointError::InvalidField {
            field: "planner descriptor",
            reason: "runtime descriptor is invalid",
        })?;
    if descriptor.actor.role != ActorRole::Planner {
        return Err(PlannerCheckpointError::InvalidField {
            field: "planner role",
            reason: "lease owner must have the planner role",
        });
    }
    if !matches!(
        &descriptor.provider_continuation,
        ProviderContinuation::Fresh { .. }
    ) {
        return Err(PlannerCheckpointError::InvalidField {
            field: "planner continuation",
            reason: "a rotating planner must start without predecessor provider context",
        });
    }
    let required = [
        CapabilityKind::ContextAssembly,
        CapabilityKind::Provider,
        CapabilityKind::Trace,
    ];
    if required
        .iter()
        .any(|capability| !descriptor.capabilities.grants.contains(capability))
    {
        return Err(PlannerCheckpointError::InvalidField {
            field: "planner capabilities",
            reason: "context, provider, and trace capabilities are required",
        });
    }
    if descriptor.capabilities.grants.iter().any(|capability| {
        matches!(
            capability,
            CapabilityKind::WorkspaceWrite
                | CapabilityKind::Process
                | CapabilityKind::Network
                | CapabilityKind::Secrets
                | CapabilityKind::Mcp
        )
    }) {
        return Err(PlannerCheckpointError::ForbiddenPlannerCapability);
    }
    Ok(())
}

fn validate_planner_lease(lease: &PlannerLease) -> Result<(), PlannerCheckpointError> {
    let descriptor = RunDescriptor {
        run_id: lease.planner_run_id,
        session_id: lease.session_id.clone(),
        actor: Actor {
            id: lease.planner_actor_id,
            role: ActorRole::Planner,
        },
        workspace: lease.workspace.clone(),
        capabilities: lease.capabilities.clone(),
        budget: lease.budget.clone(),
        provider_continuation: ProviderContinuation::Fresh {
            provider: crate::runtime::ProviderId::new("checkpoint-validation").map_err(|_| {
                PlannerCheckpointError::InvalidField {
                    field: "planner provider",
                    reason: "internal validation provider identity is invalid",
                }
            })?,
        },
        cancellation_root: lease.cancellation_root,
        initial_state: crate::runtime::StateSnapshot {
            generation: crate::runtime::StateGeneration::new(1).ok_or(
                PlannerCheckpointError::InvalidField {
                    field: "planner state generation",
                    reason: "internal validation generation is invalid",
                },
            )?,
            digest: ContentDigest::sha256([]),
        },
    };
    validate_planner_descriptor(&descriptor)
}

fn validate_successor(
    current: &PlannerLease,
    aggregate_budget: &BudgetSnapshot,
    successor: &RunDescriptor,
) -> Result<(), PlannerCheckpointError> {
    validate_planner_descriptor(successor)?;
    if successor.run_id == current.planner_run_id
        || successor.actor.id == current.planner_actor_id
        || successor.cancellation_root == current.cancellation_root
    {
        return Err(PlannerCheckpointError::InvalidField {
            field: "successor identity",
            reason: "rotation requires fresh run, actor, and cancellation identities",
        });
    }
    if successor.session_id != current.session_id
        || successor.workspace.root() != current.workspace.root()
        || successor.workspace.digest != current.workspace.digest
    {
        return Err(PlannerCheckpointError::InvalidField {
            field: "successor authority binding",
            reason: "session and workspace identity must match the transferred lease",
        });
    }
    if !successor
        .capabilities
        .grants
        .is_subset(&current.capabilities.grants)
    {
        return Err(PlannerCheckpointError::CapabilityWidening);
    }
    if successor.budget.id == current.budget.id {
        return Err(PlannerCheckpointError::InvalidField {
            field: "successor budget",
            reason: "a fresh planner run requires a distinct budget identity",
        });
    }
    validate_run_budget_within_snapshot(&successor.budget, aggregate_budget)
}

fn validate_budget_snapshot(snapshot: &BudgetSnapshot) -> Result<(), PlannerCheckpointError> {
    let limits = &snapshot.limits;
    let used = snapshot.used;
    let used_total = used
        .input_tokens
        .checked_add(used.output_tokens)
        .ok_or(PlannerCheckpointError::BudgetWidening)?;
    if used.input_tokens > limits.input_tokens
        || used.output_tokens > limits.output_tokens
        || used_total > limits.total_tokens
        || used.turns > limits.turns
        || used.provider_calls > limits.provider_calls
        || used.tool_calls > limits.tool_calls
        || used.retries > limits.retries
        || used.concurrent_calls > limits.concurrent_calls
        || used.child_runs > limits.child_runs
        || used.cost_microusd > limits.cost_microusd
        || snapshot.elapsed_millis > limits.elapsed_millis
        || snapshot.remaining_elapsed_millis
            != limits
                .elapsed_millis
                .saturating_sub(snapshot.elapsed_millis)
    {
        return Err(PlannerCheckpointError::InvalidField {
            field: "aggregate budget",
            reason: "usage or remaining time is inconsistent with limits",
        });
    }
    Ok(())
}

fn validate_run_budget_within_snapshot(
    budget: &RunBudget,
    aggregate: &BudgetSnapshot,
) -> Result<(), PlannerCheckpointError> {
    validate_budget_snapshot(aggregate)?;
    let available = remaining_limits(aggregate)?;
    validate_run_budget_within_limits(budget, &available)
}

const fn validate_run_budget_within_limits(
    budget: &RunBudget,
    available: &BudgetLimits,
) -> Result<(), PlannerCheckpointError> {
    let requested = &budget.limits;
    if requested.input_tokens > available.input_tokens
        || requested.output_tokens > available.output_tokens
        || requested.total_tokens > available.total_tokens
        || requested.turns > available.turns
        || requested.provider_calls > available.provider_calls
        || requested.tool_calls > available.tool_calls
        || requested.elapsed_millis > available.elapsed_millis
        || requested.retries > available.retries
        || requested.concurrent_calls > available.concurrent_calls
        || requested.child_runs > available.child_runs
        || requested.cost_microusd > available.cost_microusd
        || requested.trace_bytes > available.trace_bytes
    {
        return Err(PlannerCheckpointError::BudgetWidening);
    }
    Ok(())
}

fn remaining_limits(snapshot: &BudgetSnapshot) -> Result<BudgetLimits, PlannerCheckpointError> {
    let used_total = snapshot
        .used
        .input_tokens
        .checked_add(snapshot.used.output_tokens)
        .ok_or(PlannerCheckpointError::BudgetWidening)?;
    Ok(BudgetLimits {
        input_tokens: snapshot
            .limits
            .input_tokens
            .saturating_sub(snapshot.used.input_tokens),
        output_tokens: snapshot
            .limits
            .output_tokens
            .saturating_sub(snapshot.used.output_tokens),
        total_tokens: snapshot.limits.total_tokens.saturating_sub(used_total),
        turns: snapshot.limits.turns.saturating_sub(snapshot.used.turns),
        provider_calls: snapshot
            .limits
            .provider_calls
            .saturating_sub(snapshot.used.provider_calls),
        tool_calls: snapshot
            .limits
            .tool_calls
            .saturating_sub(snapshot.used.tool_calls),
        elapsed_millis: snapshot.remaining_elapsed_millis,
        retries: snapshot
            .limits
            .retries
            .saturating_sub(snapshot.used.retries),
        concurrent_calls: snapshot
            .limits
            .concurrent_calls
            .saturating_sub(snapshot.used.concurrent_calls),
        child_runs: snapshot
            .limits
            .child_runs
            .saturating_sub(snapshot.used.child_runs),
        cost_microusd: snapshot
            .limits
            .cost_microusd
            .saturating_sub(snapshot.used.cost_microusd),
        trace_bytes: snapshot.limits.trace_bytes,
    })
}

fn validate_state(
    state: &PlannerState,
    lease: &PlannerLease,
) -> Result<(), PlannerCheckpointError> {
    validate_planner_objective(state)?;
    state.task_graph.validate()?;
    validate_map_bounds(state)?;
    validate_budget_snapshot(&state.budget)?;
    validate_run_budget_within_limits(&lease.budget, &state.budget.limits)?;
    validate_planner_evidence(state)?;
    validate_planner_execution(state)?;
    validate_children(state, lease)
}

fn validate_planner_objective(state: &PlannerState) -> Result<(), PlannerCheckpointError> {
    validate_text(
        "planner objective",
        &state.objective.text,
        MAX_OBJECTIVE_BYTES,
        false,
    )?;
    if ContentDigest::sha256(state.objective.text.as_bytes()) != state.objective.content_digest {
        return Err(PlannerCheckpointError::DigestMismatch);
    }
    if state.amendments.len() > MAX_PLANNER_AMENDMENTS {
        return Err(PlannerCheckpointError::Capacity {
            resource: "objective amendments",
            limit: MAX_PLANNER_AMENDMENTS,
        });
    }
    let mut amendment_ids = BTreeSet::new();
    for amendment in &state.amendments {
        validate_text(
            "objective amendment",
            &amendment.text,
            MAX_AMENDMENT_BYTES,
            false,
        )?;
        if ContentDigest::sha256(amendment.text.as_bytes()) != amendment.content_digest
            || !amendment_ids.insert(amendment.id)
        {
            return Err(PlannerCheckpointError::DigestMismatch);
        }
    }
    Ok(())
}

fn validate_planner_evidence(state: &PlannerState) -> Result<(), PlannerCheckpointError> {
    for (id, source) in &state.sources {
        if id != &source.id {
            return Err(PlannerCheckpointError::InvalidField {
                field: "evidence source",
                reason: "map key differs from embedded identity",
            });
        }
        validate_text(
            "evidence reference",
            &source.reference,
            MAX_PLANNER_REFERENCE_BYTES,
            false,
        )?;
    }
    for (id, decision) in &state.decisions {
        if id != &decision.id || decision.sources.is_empty() {
            return Err(PlannerCheckpointError::InvalidField {
                field: "accepted decision",
                reason: "identity or source set is invalid",
            });
        }
        validate_text(
            "accepted decision",
            &decision.statement,
            MAX_PLANNER_TEXT_BYTES,
            false,
        )?;
        require_sources(&decision.sources, &state.sources)?;
    }
    for (id, artifact) in &state.artifacts {
        if id != &artifact.id || artifact.generation == 0 {
            return Err(PlannerCheckpointError::InvalidField {
                field: "artifact",
                reason: "identity or generation is invalid",
            });
        }
        validate_text(
            "artifact kind",
            &artifact.kind,
            MAX_PLANNER_KIND_BYTES,
            false,
        )?;
        require_sources(&artifact.sources, &state.sources)?;
        if artifact
            .producing_attempt
            .is_some_and(|attempt| !state.attempts.contains_key(&attempt))
        {
            return Err(PlannerCheckpointError::InvalidField {
                field: "artifact attempt",
                reason: "producing attempt is missing",
            });
        }
    }
    Ok(())
}

fn validate_planner_execution(state: &PlannerState) -> Result<(), PlannerCheckpointError> {
    for (id, approval) in &state.approvals {
        if id != &approval.id {
            return Err(PlannerCheckpointError::InvalidField {
                field: "approval evidence",
                reason: "map key differs from embedded identity",
            });
        }
    }
    for (id, attempt) in &state.attempts {
        if id != &attempt.id
            || attempt.workspace_generation == 0
            || attempt.capability_generation == 0
            || attempt.budget_generation == 0
            || attempt.updated_at < attempt.started_at
            || state.task_graph.task(&attempt.task_id).is_none()
        {
            return Err(PlannerCheckpointError::InvalidField {
                field: "task attempt",
                reason: "identity, generation, time, or task binding is invalid",
            });
        }
        require_sources(&attempt.evidence, &state.sources)?;
        if attempt
            .artifacts
            .iter()
            .any(|artifact| !state.artifacts.contains_key(artifact))
        {
            return Err(PlannerCheckpointError::InvalidField {
                field: "attempt artifacts",
                reason: "attempt references a missing artifact",
            });
        }
    }
    for (id, contradiction) in &state.contradictions {
        if id != &contradiction.id
            || contradiction.sources.len() < 2
            || contradiction.updated_at < contradiction.recorded_at
        {
            return Err(PlannerCheckpointError::InvalidField {
                field: "contradiction",
                reason: "identity, source count, or time is invalid",
            });
        }
        validate_text(
            "contradiction",
            &contradiction.statement,
            MAX_PLANNER_TEXT_BYTES,
            false,
        )?;
        require_sources(&contradiction.sources, &state.sources)?;
        if let PlannerContradictionState::Resolved(decision) = contradiction.state {
            if !state.decisions.contains_key(&decision) {
                return Err(PlannerCheckpointError::InvalidField {
                    field: "contradiction resolution",
                    reason: "resolution decision is missing",
                });
            }
        }
    }
    Ok(())
}

fn validate_map_bounds(state: &PlannerState) -> Result<(), PlannerCheckpointError> {
    for (resource, count, limit) in [
        ("attempts", state.attempts.len(), MAX_PLANNER_RECORDS),
        ("sources", state.sources.len(), MAX_PLANNER_RECORDS),
        ("decisions", state.decisions.len(), MAX_PLANNER_RECORDS),
        ("artifacts", state.artifacts.len(), MAX_PLANNER_RECORDS),
        ("approvals", state.approvals.len(), MAX_PLANNER_RECORDS),
        (
            "contradictions",
            state.contradictions.len(),
            MAX_PLANNER_RECORDS,
        ),
        ("children", state.children.len(), MAX_PLANNER_CHILDREN),
    ] {
        if count > limit {
            return Err(PlannerCheckpointError::Capacity { resource, limit });
        }
    }
    Ok(())
}

fn require_sources(
    required: &BTreeSet<PlannerSourceId>,
    sources: &BTreeMap<PlannerSourceId, PlannerEvidenceSourceRecord>,
) -> Result<(), PlannerCheckpointError> {
    if required.iter().any(|source| !sources.contains_key(source)) {
        return Err(PlannerCheckpointError::InvalidField {
            field: "source link",
            reason: "record references a missing accepted source",
        });
    }
    Ok(())
}

fn validate_children(
    state: &PlannerState,
    lease: &PlannerLease,
) -> Result<(), PlannerCheckpointError> {
    for (run_id, child) in &state.children {
        let Some(attempt) = state.attempts.get(&child.attempt_id) else {
            return Err(PlannerCheckpointError::InvalidField {
                field: "child attempt",
                reason: "child references a missing attempt",
            });
        };
        let task =
            state
                .task_graph
                .task(&child.task_id)
                .ok_or(PlannerCheckpointError::InvalidField {
                    field: "child task",
                    reason: "child references a missing task",
                })?;
        let TaskSource::Delegation { agent_id } = &task.source else {
            return Err(PlannerCheckpointError::InvalidField {
                field: "child task",
                reason: "child task is not a supervised delegation",
            });
        };
        if run_id != &child.run_id
            || attempt.run_id != child.run_id
            || attempt.task_id != child.task_id
            || attempt.workspace_generation != child.workspace_generation
            || attempt.capability_generation != child.capability_generation
            || agent_id != &child.delegation_agent_id
            || child.workspace_generation == 0
            || child.capability_generation == 0
        {
            return Err(PlannerCheckpointError::InvalidField {
                field: "child binding",
                reason: "child identity or generation binding is inconsistent",
            });
        }
        let lifecycle_is_consistent = match &child.state {
            PlannerChildState::Starting => {
                matches!(
                    attempt.state,
                    PlannerAttemptState::Queued | PlannerAttemptState::Active
                ) && task.status == CanonicalTaskStatus::InProgress
            }
            PlannerChildState::Active => {
                attempt.state == PlannerAttemptState::Active
                    && task.status == CanonicalTaskStatus::InProgress
            }
            PlannerChildState::PartiallyDelivered => {
                attempt.state == PlannerAttemptState::PartiallyDelivered
                    && task.status == CanonicalTaskStatus::InProgress
            }
            PlannerChildState::Succeeded => {
                attempt.state == PlannerAttemptState::Succeeded
                    && task.status == CanonicalTaskStatus::Completed
            }
            PlannerChildState::Failed => {
                attempt.state == PlannerAttemptState::Failed
                    && task.status == CanonicalTaskStatus::Failed
            }
            PlannerChildState::Cancelled { .. } => {
                attempt.state == PlannerAttemptState::Cancelled
                    && task.status == CanonicalTaskStatus::Canceled
            }
        };
        if !lifecycle_is_consistent {
            return Err(PlannerCheckpointError::InvalidField {
                field: "child lifecycle",
                reason: "child, attempt, and canonical task states disagree",
            });
        }
        if child.state.is_live()
            && !matches!(child.owner, PlannerChildOwner::Lease(id) if id == lease.id)
            && child.owner != PlannerChildOwner::Orphaned
        {
            return Err(PlannerCheckpointError::InvalidField {
                field: "child ownership",
                reason: "live child is owned by neither the current lease nor orphan recovery",
            });
        }
        if let PlannerChildState::Cancelled { receipt } = &child.state {
            validate_child_cancellation(child, receipt)?;
        }
        if child.updated_at < attempt.started_at {
            return Err(PlannerCheckpointError::InvalidField {
                field: "child time",
                reason: "child update precedes its attempt",
            });
        }
    }
    Ok(())
}

fn validate_child_cancellation(
    child: &PlannerChild,
    receipt: &CancellationReceipt,
) -> Result<(), PlannerCheckpointError> {
    if receipt.root != child.cancellation_root || receipt.node != child.cancellation_root {
        return Err(PlannerCheckpointError::InvalidChildCancellation);
    }
    Ok(())
}

fn validate_state_evolution(
    current: &PlannerState,
    next: &PlannerState,
) -> Result<(), PlannerCheckpointError> {
    if current.objective != next.objective
        || next.amendments.len() < current.amendments.len()
        || next.amendments[..current.amendments.len()] != current.amendments
        || current.task_graph.graph_id() != next.task_graph.graph_id()
        || next.task_graph.generation() < current.task_graph.generation()
    {
        return Err(PlannerCheckpointError::ImmutableRecordChanged);
    }
    require_unchanged_entries(&current.sources, &next.sources)?;
    require_unchanged_entries(&current.decisions, &next.decisions)?;
    require_unchanged_entries(&current.artifacts, &next.artifacts)?;
    validate_budget_evolution(&current.budget, &next.budget)?;
    validate_attempt_evolution(&current.attempts, &next.attempts)?;
    validate_approval_evolution(&current.approvals, &next.approvals)?;
    validate_contradiction_evolution(&current.contradictions, &next.contradictions)?;
    validate_child_evolution(&current.children, &next.children)
}

fn require_unchanged_entries<K: Ord, V: PartialEq>(
    current: &BTreeMap<K, V>,
    next: &BTreeMap<K, V>,
) -> Result<(), PlannerCheckpointError> {
    if current
        .iter()
        .any(|(key, value)| next.get(key) != Some(value))
    {
        return Err(PlannerCheckpointError::ImmutableRecordChanged);
    }
    Ok(())
}

fn validate_budget_evolution(
    current: &BudgetSnapshot,
    next: &BudgetSnapshot,
) -> Result<(), PlannerCheckpointError> {
    if current.budget_id != next.budget_id
        || current.generation != next.generation
        || current.limits != next.limits
        || next.used.input_tokens < current.used.input_tokens
        || next.used.output_tokens < current.used.output_tokens
        || next.used.turns < current.used.turns
        || next.used.provider_calls < current.used.provider_calls
        || next.used.tool_calls < current.used.tool_calls
        || next.used.retries < current.used.retries
        || next.used.child_runs < current.used.child_runs
        || next.used.cost_microusd < current.used.cost_microusd
        || next.elapsed_millis < current.elapsed_millis
        || next.remaining_elapsed_millis > current.remaining_elapsed_millis
    {
        return Err(PlannerCheckpointError::BudgetWidening);
    }
    validate_budget_snapshot(next)
}

fn validate_attempt_evolution(
    current: &BTreeMap<PlannerAttemptId, PlannerAttempt>,
    next: &BTreeMap<PlannerAttemptId, PlannerAttempt>,
) -> Result<(), PlannerCheckpointError> {
    for (id, prior) in current {
        let Some(updated) = next.get(id) else {
            return Err(PlannerCheckpointError::ImmutableRecordChanged);
        };
        if prior.id != updated.id
            || prior.task_id != updated.task_id
            || prior.run_id != updated.run_id
            || prior.actor_id != updated.actor_id
            || prior.workspace_generation != updated.workspace_generation
            || prior.capability_generation != updated.capability_generation
            || prior.budget_id != updated.budget_id
            || prior.budget_generation != updated.budget_generation
            || prior.started_at != updated.started_at
            || !prior.state.can_transition_to(updated.state)
            || updated.updated_at < prior.updated_at
            || !prior.evidence.is_subset(&updated.evidence)
            || !prior.artifacts.is_subset(&updated.artifacts)
        {
            return Err(PlannerCheckpointError::InvalidTransition);
        }
    }
    Ok(())
}

fn validate_approval_evolution(
    current: &BTreeMap<PlannerApprovalId, PlannerApprovalEvidence>,
    next: &BTreeMap<PlannerApprovalId, PlannerApprovalEvidence>,
) -> Result<(), PlannerCheckpointError> {
    for (id, prior) in current {
        let Some(updated) = next.get(id) else {
            return Err(PlannerCheckpointError::ImmutableRecordChanged);
        };
        let state_allowed = prior.state == updated.state
            || matches!(
                (prior.state, updated.state),
                (
                    PlannerApprovalState::Observed,
                    PlannerApprovalState::Consumed
                        | PlannerApprovalState::Revoked
                        | PlannerApprovalState::Expired
                )
            );
        if prior.id != updated.id
            || prior.scope_digest != updated.scope_digest
            || prior.evidence_digest != updated.evidence_digest
            || prior.originating_run != updated.originating_run
            || prior.recorded_at != updated.recorded_at
            || !state_allowed
        {
            return Err(PlannerCheckpointError::InvalidTransition);
        }
    }
    Ok(())
}

fn validate_contradiction_evolution(
    current: &BTreeMap<PlannerContradictionId, PlannerContradiction>,
    next: &BTreeMap<PlannerContradictionId, PlannerContradiction>,
) -> Result<(), PlannerCheckpointError> {
    for (id, prior) in current {
        let Some(updated) = next.get(id) else {
            return Err(PlannerCheckpointError::ImmutableRecordChanged);
        };
        let state_allowed = prior.state == updated.state
            || matches!(
                (prior.state, updated.state),
                (
                    PlannerContradictionState::Open,
                    PlannerContradictionState::Resolved(_)
                )
            );
        if prior.id != updated.id
            || prior.statement != updated.statement
            || prior.sources != updated.sources
            || prior.recorded_at != updated.recorded_at
            || updated.updated_at < prior.updated_at
            || !state_allowed
        {
            return Err(PlannerCheckpointError::InvalidTransition);
        }
    }
    Ok(())
}

fn validate_child_evolution(
    current: &BTreeMap<RunId, PlannerChild>,
    next: &BTreeMap<RunId, PlannerChild>,
) -> Result<(), PlannerCheckpointError> {
    for (run_id, prior) in current {
        let Some(updated) = next.get(run_id) else {
            return Err(PlannerCheckpointError::ImmutableRecordChanged);
        };
        if prior.run_id != updated.run_id
            || prior.attempt_id != updated.attempt_id
            || prior.task_id != updated.task_id
            || prior.delegation_agent_id != updated.delegation_agent_id
            || prior.cancellation_root != updated.cancellation_root
            || prior.workspace_generation != updated.workspace_generation
            || prior.capability_generation != updated.capability_generation
            || !prior.state.can_transition_to(&updated.state)
            || updated.updated_at < prior.updated_at
        {
            return Err(PlannerCheckpointError::InvalidTransition);
        }
        if prior.owner != updated.owner && prior.state.is_terminal() {
            return Err(PlannerCheckpointError::InvalidTransition);
        }
    }
    Ok(())
}

impl PlannerChildState {
    const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled { .. }
        )
    }
}

fn validate_lease_history(
    history: &[PlannerLeaseTombstone],
    current: &PlannerLease,
) -> Result<(), PlannerCheckpointError> {
    let mut lease_ids = BTreeSet::new();
    let mut prior_generation = None;
    for tombstone in history {
        if !lease_ids.insert(tombstone.lease_id)
            || tombstone.lease_id == tombstone.successor_lease_id
            || prior_generation.is_some_and(|prior| tombstone.terminal_generation <= prior)
        {
            return Err(PlannerCheckpointError::InvalidField {
                field: "planner lease history",
                reason: "lease identity or terminal generation is not causal",
            });
        }
        prior_generation = Some(tombstone.terminal_generation);
    }
    if history
        .windows(2)
        .any(|pair| pair[0].successor_lease_id != pair[1].lease_id)
    {
        return Err(PlannerCheckpointError::InvalidField {
            field: "planner lease history",
            reason: "lease tombstones do not form one successor chain",
        });
    }
    if let Some(last) = history.last() {
        if last.successor_lease_id != current.id
            || last.terminal_generation >= current.checkpoint_generation
        {
            return Err(PlannerCheckpointError::InvalidField {
                field: "planner lease history",
                reason: "last tombstone does not lead to the current lease",
            });
        }
    }
    Ok(())
}

fn reconcile_children(
    state: &mut PlannerState,
    current_lease: &PlannerLease,
    successor_lease: &PlannerLease,
    dispositions: &BTreeMap<RunId, PlannerChildDisposition>,
    now: DateTime<Utc>,
) -> Result<(), PlannerCheckpointError> {
    let live = state
        .children
        .iter()
        .filter_map(|(run_id, child)| child.state.is_live().then_some(*run_id))
        .collect::<BTreeSet<_>>();
    if dispositions.keys().any(|run_id| !live.contains(run_id)) {
        return Err(PlannerCheckpointError::UnexpectedChildDisposition);
    }
    if live.iter().any(|run_id| !dispositions.contains_key(run_id)) {
        return Err(PlannerCheckpointError::MissingChildDisposition);
    }

    for run_id in live {
        let disposition = dispositions
            .get(&run_id)
            .ok_or(PlannerCheckpointError::MissingChildDisposition)?;
        let child = state
            .children
            .get_mut(&run_id)
            .ok_or(PlannerCheckpointError::MissingChildDisposition)?;
        if !matches!(child.owner, PlannerChildOwner::Lease(id) if id == current_lease.id)
            && child.owner != PlannerChildOwner::Orphaned
        {
            return Err(PlannerCheckpointError::StaleLease);
        }
        match disposition {
            PlannerChildDisposition::Adopt => {
                child.owner = PlannerChildOwner::Lease(successor_lease.id);
                child.updated_at = now;
            }
            PlannerChildDisposition::Cancel { receipt } => {
                validate_child_cancellation(child, receipt)?;
                child.state = PlannerChildState::Cancelled {
                    receipt: receipt.clone(),
                };
                child.updated_at = now;
                let attempt = state.attempts.get_mut(&child.attempt_id).ok_or(
                    PlannerCheckpointError::InvalidField {
                        field: "child attempt",
                        reason: "cancelled child attempt is missing",
                    },
                )?;
                if attempt.state.is_terminal() && attempt.state != PlannerAttemptState::Cancelled {
                    return Err(PlannerCheckpointError::InvalidTransition);
                }
                attempt.state = PlannerAttemptState::Cancelled;
                attempt.updated_at = now;
                cancel_delegation_task(&mut state.task_graph, current_lease, child, now)?;
            }
        }
    }
    Ok(())
}

fn cancel_delegation_task(
    graph: &mut TaskGraph,
    lease: &PlannerLease,
    child: &PlannerChild,
    now: DateTime<Utc>,
) -> Result<(), PlannerCheckpointError> {
    let task = graph
        .task(&child.task_id)
        .ok_or(PlannerCheckpointError::InvalidField {
            field: "child task",
            reason: "cancelled child task is missing",
        })?;
    if task.status == CanonicalTaskStatus::Canceled {
        return Ok(());
    }
    let update = UpdateTask {
        expected_generation: graph.generation(),
        task_id: child.task_id.clone(),
        expected_task_revision: task.revision,
        status: Some(CanonicalTaskStatus::Canceled),
        priority: None,
        subject: FieldUpdate::Keep,
        description: FieldUpdate::Keep,
        active_form: FieldUpdate::Keep,
        budget: FieldUpdate::Keep,
        blocks: None,
        blocked_by: None,
    };
    let actor = TaskActor::with_session(
        Actor {
            id: lease.planner_actor_id,
            role: ActorRole::Planner,
        },
        lease.planner_run_id,
        lease.session_id.to_string(),
    );
    let proposal =
        graph.propose_update_delegation(update, &actor, now, &child.delegation_agent_id)?;
    *graph = proposal.into_parts().0;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone as _, Utc};

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(second, 0).single().expect("test time")
    }

    fn budget_snapshot() -> BudgetSnapshot {
        let limits = BudgetLimits::default();
        BudgetSnapshot {
            budget_id: BudgetId::new(),
            generation: crate::runtime::BudgetGeneration::new(1).expect("budget generation"),
            limits: limits.clone(),
            used: crate::runtime::BudgetAmounts::default(),
            elapsed_millis: 0,
            remaining_elapsed_millis: limits.elapsed_millis,
        }
    }

    fn planner_descriptor(
        root: &Path,
        session_id: crate::state::SessionId,
        workspace_digest: ContentDigest,
        limits: BudgetLimits,
    ) -> RunDescriptor {
        RunDescriptor::new(RunDescriptorParts {
            run_id: RunId::new(),
            session_id,
            actor: Actor {
                id: ActorId::new(),
                role: ActorRole::Planner,
            },
            workspace: WorkspaceBinding::from_existing_root(
                root,
                crate::runtime::WorkspaceGeneration::new(1).expect("workspace generation"),
                workspace_digest,
            )
            .expect("workspace binding"),
            capabilities: CapabilityBinding {
                generation: crate::runtime::CapabilityGeneration::new(1)
                    .expect("capability generation"),
                manifest_digest: ContentDigest::sha256("planner-capabilities"),
                grants: BTreeSet::from([
                    CapabilityKind::ContextAssembly,
                    CapabilityKind::Provider,
                    CapabilityKind::Trace,
                ]),
            },
            budget: RunBudget {
                id: BudgetId::new(),
                generation: crate::runtime::BudgetGeneration::new(1).expect("budget generation"),
                limits,
            },
            provider_continuation: ProviderContinuation::Fresh {
                provider: crate::runtime::ProviderId::new("planner-test").expect("provider id"),
            },
            cancellation_root: CancellationId::new(),
            initial_state: crate::runtime::StateSnapshot {
                generation: crate::runtime::StateGeneration::new(1).expect("state generation"),
                digest: ContentDigest::sha256("planner-state"),
            },
        })
        .expect("planner descriptor")
    }

    fn checkpoint_fixture() -> (tempfile::TempDir, PlannerCheckpoint) {
        let root = tempfile::tempdir().expect("workspace");
        let budget = budget_snapshot();
        let descriptor = planner_descriptor(
            root.path(),
            crate::state::SessionId::new(),
            ContentDigest::sha256("workspace"),
            budget.limits.clone(),
        );
        let checkpoint = PlannerCheckpoint::new(
            "planner-test",
            PlannerState::new(
                PlannerObjective::new("finish the feature", at(1)),
                TaskGraph::new("planner-test-graph").expect("task graph"),
                budget,
            ),
            &descriptor,
            at(1),
        )
        .expect("initial checkpoint");
        (root, checkpoint)
    }

    fn successor(root: &Path, checkpoint: &PlannerCheckpoint) -> RunDescriptor {
        planner_descriptor(
            root,
            checkpoint.lease().session_id.clone(),
            checkpoint.lease().workspace.digest,
            remaining_limits(&checkpoint.state().budget).expect("remaining budget"),
        )
    }

    fn checkpoint_with_live_child() -> (
        tempfile::TempDir,
        PlannerCheckpoint,
        RunId,
        PlannerAttemptId,
        CancellationId,
    ) {
        let (root, checkpoint) = checkpoint_fixture();
        let mut state = checkpoint.state().clone();
        let task_actor = TaskActor::with_session(
            Actor {
                id: checkpoint.lease().planner_actor_id,
                role: ActorRole::Planner,
            },
            checkpoint.lease().planner_run_id,
            checkpoint.lease().session_id.to_string(),
        );
        let task_id = state
            .task_graph
            .create(
                crate::task_graph::CreateTask {
                    expected_generation: state.task_graph.generation(),
                    subject: "delegated work".to_string(),
                    description: String::new(),
                    active_form: Some("working".to_string()),
                    status: CanonicalTaskStatus::InProgress,
                    priority: crate::task_graph::TaskPriority::High,
                    source: TaskSource::Delegation {
                        agent_id: "worker-1".to_string(),
                    },
                    budget: None,
                },
                &task_actor,
                at(2),
            )
            .expect("delegation task")
            .affected[0]
            .clone();
        let child_run = RunId::new();
        let attempt_id = PlannerAttemptId::new();
        state.attempts.insert(
            attempt_id,
            PlannerAttempt {
                id: attempt_id,
                task_id: task_id.clone(),
                run_id: child_run,
                actor_id: ActorId::new(),
                workspace_generation: 1,
                capability_generation: 1,
                budget_id: BudgetId::new(),
                budget_generation: 1,
                state: PlannerAttemptState::Active,
                evidence: BTreeSet::new(),
                artifacts: BTreeSet::new(),
                started_at: at(2),
                updated_at: at(2),
            },
        );
        let child_cancellation = CancellationId::new();
        state.children.insert(
            child_run,
            PlannerChild {
                run_id: child_run,
                attempt_id,
                task_id,
                delegation_agent_id: "worker-1".to_string(),
                cancellation_root: child_cancellation,
                workspace_generation: 1,
                capability_generation: 1,
                owner: PlannerChildOwner::Lease(checkpoint.lease().id),
                state: PlannerChildState::Active,
                updated_at: at(2),
            },
        );
        let with_child = checkpoint
            .propose_state(checkpoint.generation(), state, at(2))
            .expect("checkpoint child");
        (root, with_child, child_run, attempt_id, child_cancellation)
    }

    #[test]
    fn fresh_rotation_preserves_typed_state_without_provider_transcript() {
        let (root, checkpoint) = checkpoint_fixture();
        let next_descriptor = successor(root.path(), &checkpoint);
        let next = checkpoint
            .propose_rotation(&PlannerRotation {
                expected_generation: checkpoint.generation(),
                expected_lease: checkpoint.lease().id,
                successor: next_descriptor.clone(),
                child_dispositions: BTreeMap::new(),
                rotated_at: at(2),
            })
            .expect("rotation");

        assert_eq!(next.generation().get(), 2);
        assert_eq!(
            next.previous_checkpoint_digest(),
            Some(checkpoint.checkpoint_digest())
        );
        assert_eq!(next.state(), checkpoint.state());
        assert_eq!(next.lease_history().len(), 1);
        assert_eq!(next.lease().planner_run_id, next_descriptor.run_id);
        let json = serde_json::to_string(&next).expect("checkpoint JSON");
        assert!(!json.contains("provider_native_state"));
        assert!(!json.contains("messages"));
    }

    #[test]
    fn rotation_rejects_predecessor_provider_continuation() {
        let (root, checkpoint) = checkpoint_fixture();
        let mut next_descriptor = successor(root.path(), &checkpoint);
        next_descriptor.provider_continuation = ProviderContinuation::Resume {
            provider: crate::runtime::ProviderId::new("planner-test").expect("provider id"),
            generation: crate::runtime::ContinuationGeneration::new(1)
                .expect("continuation generation"),
            state_digest: ContentDigest::sha256("predecessor-provider-state"),
        };
        let error = checkpoint
            .propose_rotation(&PlannerRotation {
                expected_generation: checkpoint.generation(),
                expected_lease: checkpoint.lease().id,
                successor: next_descriptor,
                child_dispositions: BTreeMap::new(),
                rotated_at: at(2),
            })
            .expect_err("resume continuation must be rejected");
        assert!(matches!(
            error,
            PlannerCheckpointError::InvalidField {
                field: "planner continuation",
                ..
            }
        ));
    }

    #[test]
    fn live_child_requires_explicit_adoption_or_bound_cancellation() {
        let (root, with_child, child_run, attempt_id, child_cancellation) =
            checkpoint_with_live_child();
        let next_descriptor = successor(root.path(), &with_child);
        let base_rotation = PlannerRotation {
            expected_generation: with_child.generation(),
            expected_lease: with_child.lease().id,
            successor: next_descriptor,
            child_dispositions: BTreeMap::new(),
            rotated_at: at(3),
        };
        assert!(matches!(
            with_child.propose_rotation(&base_rotation),
            Err(PlannerCheckpointError::MissingChildDisposition)
        ));

        let mut adopt = base_rotation.clone();
        adopt
            .child_dispositions
            .insert(child_run, PlannerChildDisposition::Adopt);
        let adopted = with_child
            .propose_rotation(&adopt)
            .expect("explicit adoption");
        assert!(matches!(
            adopted.state().children[&child_run].owner,
            PlannerChildOwner::Lease(id) if id == adopted.lease().id
        ));

        let mut cancel = base_rotation;
        cancel.child_dispositions.insert(
            child_run,
            PlannerChildDisposition::Cancel {
                receipt: CancellationReceipt {
                    root: child_cancellation,
                    node: child_cancellation,
                    source: child_cancellation,
                    reason: crate::runtime::CancellationReason::ParentTerminated,
                },
            },
        );
        let cancelled = with_child
            .propose_rotation(&cancel)
            .expect("bound cancellation");
        assert!(matches!(
            cancelled.state().children[&child_run].state,
            PlannerChildState::Cancelled { .. }
        ));
        assert_eq!(
            cancelled.state().attempts[&attempt_id].state,
            PlannerAttemptState::Cancelled
        );
    }
}

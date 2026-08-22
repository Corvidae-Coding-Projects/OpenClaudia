//! Canonical transactional planning and task state.
//!
//! The graph is data, never authority. Actor and run identifiers describe who
//! proposed a mutation; they do not grant filesystem, process, network, or
//! approval capability. Every mutation is built against an expected graph
//! generation, validated as a complete proposed snapshot, and only then
//! committed. Persisted graphs use [`crate::persistence::PersistentStorage`]
//! so a stale or failed write cannot partially replace live state.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::persistence::{
    CommitReceipt, FileClass, PersistenceError, PersistentStorage, StorageGeneration,
};
use crate::runtime::{Actor, RunId};
#[cfg(test)]
use crate::runtime::{ActorId, ActorRole};

pub const TASK_GRAPH_SCHEMA_VERSION: u32 = 1;
pub const MAX_TASKS: usize = 512;
pub const MAX_HISTORY_EVENTS: usize = 4_096;
pub const MAX_TASK_EDGES: usize = 128;
pub const MAX_TASK_SUBJECT_BYTES: usize = 2_000;
pub const MAX_TASK_DESCRIPTION_BYTES: usize = 8_192;
pub const MAX_TASK_ACTIVE_FORM_BYTES: usize = 512;
pub const MAX_TASK_ID_BYTES: usize = 96;
pub const MAX_GRAPH_ID_BYTES: usize = 128;
pub const MAX_EXTERNAL_SYSTEM_BYTES: usize = 64;
pub const MAX_EXTERNAL_ID_BYTES: usize = 128;
pub const MAX_PLAN_ID_BYTES: usize = 128;
pub const MAX_PLAN_VERSION_BYTES: usize = 128;
pub const MAX_AGENT_ID_BYTES: usize = 128;
pub const MAX_TASK_SESSION_ID_BYTES: usize = 128;
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_PAGE_CURSOR_BYTES: usize = 64;

type ExternalDrafts = BTreeMap<String, ExternalTaskDraft>;
type ExternalProjectionIds = BTreeMap<String, TaskId>;
pub const MAX_TASK_BUDGET_TURNS: u64 = 1_000_000;
pub const MAX_TASK_BUDGET_TOKENS: u64 = 1_000_000_000;
pub const MAX_TASK_BUDGET_ELAPSED_MILLIS: u64 = 31_536_000_000;
pub const MAX_TASK_BUDGET_COST_MICROUSD: u64 = 1_000_000_000_000;
pub const MAX_TASK_BUDGET_CHILD_RUNS: u64 = 10_000;
pub const MAX_TASK_BUDGET_CONCURRENT_CALLS: u64 = 1_024;
const HISTORY_DIGEST_HEX_BYTES: usize = 64;
const HISTORY_DIGEST_DOMAIN: &[u8] = b"openclaudia.task-history.v1\0";

/// Monotonic version of the complete graph snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskGraphGeneration(u64);

impl TaskGraphGeneration {
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    fn next(self) -> Result<Self, TaskGraphError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(TaskGraphError::GenerationExhausted)
    }
}

impl std::fmt::Display for TaskGraphGeneration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Stable graph-scoped task identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TaskId(String);

impl TaskId {
    /// Parse and validate one canonical task identifier.
    ///
    /// # Errors
    /// Returns an error when the identifier is empty, oversized, or contains
    /// non-canonical bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self, TaskGraphError> {
        let value = value.into();
        validate_identifier("task id", &value, MAX_TASK_ID_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TaskId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// One actor/run binding recorded as provenance for a graph mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskActor {
    pub actor: Actor,
    pub run_id: RunId,
    /// Stable sharing/lane scope across resume. Actor/run IDs remain exact
    /// event provenance but intentionally rotate with each runtime instance.
    pub session_id: String,
}

impl TaskActor {
    #[must_use]
    pub fn new(actor: Actor, run_id: RunId) -> Self {
        Self::with_session(actor, run_id, format!("run:{run_id}"))
    }

    #[must_use]
    pub fn with_session(actor: Actor, run_id: RunId, session_id: impl Into<String>) -> Self {
        Self {
            actor,
            run_id,
            session_id: session_id.into(),
        }
    }

    /// Derive task provenance from the immutable canonical run descriptor.
    #[must_use]
    pub fn from_run(run: &crate::tools::ToolRunContext) -> Self {
        let descriptor = run.runtime().descriptor();
        Self {
            actor: descriptor.actor.clone(),
            run_id: descriptor.run_id,
            session_id: run.session_id().to_string(),
        }
    }

    #[cfg(test)]
    fn fixture(role: ActorRole) -> Self {
        Self::new(
            Actor {
                id: ActorId::new(),
                role,
            },
            RunId::new(),
        )
    }
}

/// Source view that created a canonical task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TaskSource {
    TaskTool,
    TodoView,
    Plan {
        plan_id: String,
        observed_version: String,
    },
    Delegation {
        agent_id: String,
    },
    ExternalIssue {
        system: String,
        external_id: String,
        observed_version: String,
    },
}

/// Current lifecycle state of a canonical task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalTaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Canceled,
    Deleted,
}

/// Scheduling priority carried by every task projection.
///
/// Priority affects deterministic readiness ordering only. It is planning
/// data, not permission, admission, or provider authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskPriority {
    Critical,
    High,
    Medium,
    Low,
}

impl TaskPriority {
    const fn rank(self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::High => 1,
            Self::Medium => 2,
            Self::Low => 3,
        }
    }
}

impl std::fmt::Display for TaskPriority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => formatter.write_str("critical"),
            Self::High => formatter.write_str("high"),
            Self::Medium => formatter.write_str("medium"),
            Self::Low => formatter.write_str("low"),
        }
    }
}

impl std::fmt::Display for CanonicalTaskStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => formatter.write_str("pending"),
            Self::InProgress => formatter.write_str("in_progress"),
            Self::Completed => formatter.write_str("completed"),
            Self::Failed => formatter.write_str("failed"),
            Self::Canceled => formatter.write_str("canceled"),
            Self::Deleted => formatter.write_str("deleted"),
        }
    }
}

/// Run ownership is provenance and task-sharing scope, not security identity.
/// External issue projections deliberately have no owner binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TaskOwnership {
    Run { owner: TaskActor },
    ExternalProjection,
}

/// Bounded execution request attached to a task plan.
///
/// This is planning data, not an allocation or permission. S-051 binds an
/// admitted worker run to the canonical runtime budget tree; copying or
/// editing this value cannot create provider, process, network, or child-run
/// authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskBudgetSpec {
    pub max_turns: Option<u64>,
    pub max_tokens: Option<u64>,
    pub max_elapsed_millis: Option<u64>,
    pub max_cost_microusd: Option<u64>,
    pub max_child_runs: Option<u64>,
    pub max_concurrent_calls: Option<u64>,
}

/// One node in the canonical task graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskNode {
    pub id: TaskId,
    pub sequence: u64,
    pub revision: u64,
    pub subject: String,
    pub description: String,
    pub active_form: Option<String>,
    pub status: CanonicalTaskStatus,
    pub priority: TaskPriority,
    pub blocks: BTreeSet<TaskId>,
    pub blocked_by: BTreeSet<TaskId>,
    pub ownership: TaskOwnership,
    pub source: TaskSource,
    pub budget: Option<TaskBudgetSpec>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub terminal_at: Option<DateTime<Utc>>,
}

/// Kind of immutable history event retained with the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskHistoryKind {
    Created,
    Updated,
    TodoReplaced,
    PlanReconciled,
    ExternalReconciled,
}

/// Bounded history for causal resume and later learning attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskHistoryEvent {
    pub generation: TaskGraphGeneration,
    pub kind: TaskHistoryKind,
    pub actor: TaskActor,
    pub affected: Vec<TaskId>,
    pub recorded_at: DateTime<Utc>,
}

/// Causal anchor for history events compacted out of the retained tail.
///
/// The digest is an integrity/continuity aid, not an authorization token. The
/// complete current graph remains the checkpoint state; this value commits to
/// the ordered event prefix so long-running sessions stay bounded without
/// pretending their earlier history never happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskHistoryCheckpoint {
    through_generation: TaskGraphGeneration,
    event_count: u64,
    chain_digest: String,
}

impl TaskHistoryCheckpoint {
    fn initial() -> Self {
        Self {
            through_generation: TaskGraphGeneration::initial(),
            event_count: 0,
            chain_digest: "0".repeat(HISTORY_DIGEST_HEX_BYTES),
        }
    }

    #[must_use]
    pub const fn through_generation(&self) -> TaskGraphGeneration {
        self.through_generation
    }

    #[must_use]
    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    #[must_use]
    pub fn chain_digest(&self) -> &str {
        &self.chain_digest
    }

    fn include(&mut self, event: &TaskHistoryEvent) -> Result<(), TaskGraphError> {
        let expected = self.through_generation.next()?;
        if event.generation != expected {
            return Err(TaskGraphError::Invariant {
                reason: "compacted history event is not the next generation",
            });
        }
        let previous_digest = decode_digest(&self.chain_digest)?;
        let event_bytes = serde_json::to_vec(event).map_err(|_| TaskGraphError::InvalidJson)?;
        let event_len = u64::try_from(event_bytes.len()).map_err(|_| TaskGraphError::Capacity {
            resource: "serialized history event bytes",
            limit: usize::MAX,
        })?;
        let mut hasher = Sha256::new();
        hasher.update(HISTORY_DIGEST_DOMAIN);
        hasher.update(previous_digest);
        hasher.update(event_len.to_be_bytes());
        hasher.update(event_bytes);
        self.chain_digest = encode_digest(hasher.finalize().as_slice());
        self.through_generation = event.generation;
        self.event_count = self
            .event_count
            .checked_add(1)
            .ok_or(TaskGraphError::GenerationExhausted)?;
        Ok(())
    }
}

/// Strict persisted representation of one task graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskGraph {
    schema_version: u32,
    graph_id: String,
    generation: TaskGraphGeneration,
    next_sequence: u64,
    tasks: BTreeMap<TaskId, TaskNode>,
    history_checkpoint: TaskHistoryCheckpoint,
    history: Vec<TaskHistoryEvent>,
}

/// Input for creating a native task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTask {
    pub expected_generation: TaskGraphGeneration,
    pub subject: String,
    pub description: String,
    pub active_form: Option<String>,
    pub status: CanonicalTaskStatus,
    pub priority: TaskPriority,
    pub source: TaskSource,
    pub budget: Option<TaskBudgetSpec>,
}

/// Explicit field update; `Clear` is distinct from omission.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum FieldUpdate<T> {
    #[default]
    Keep,
    Set(T),
    Clear,
}

/// Complete graph-aware task patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateTask {
    pub expected_generation: TaskGraphGeneration,
    pub task_id: TaskId,
    pub expected_task_revision: u64,
    pub status: Option<CanonicalTaskStatus>,
    pub priority: Option<TaskPriority>,
    pub subject: FieldUpdate<String>,
    pub description: FieldUpdate<String>,
    pub active_form: FieldUpdate<String>,
    pub budget: FieldUpdate<TaskBudgetSpec>,
    /// When supplied, replaces the complete outgoing edge set.
    pub blocks: Option<BTreeSet<TaskId>>,
    /// When supplied, replaces the complete incoming edge set.
    pub blocked_by: Option<BTreeSet<TaskId>>,
}

/// One row supplied by the complete todo-list adapter. Existing rows carry
/// both their stable task identifier and the exact revision observed by the
/// caller; new rows omit both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TodoTaskDraft {
    pub task_id: Option<TaskId>,
    pub expected_task_revision: Option<u64>,
    pub content: String,
    pub status: CanonicalTaskStatus,
    pub active_form: String,
}

/// Generation-checked complete replacement of one actor's todo projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceTodoList {
    pub expected_generation: TaskGraphGeneration,
    pub items: Vec<TodoTaskDraft>,
}

/// One issue supplied by a complete external-store projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalTaskDraft {
    pub external_id: String,
    pub observed_version: String,
    pub subject: String,
    pub description: String,
    pub status: CanonicalTaskStatus,
    pub priority: TaskPriority,
    pub blocked_by_external_ids: BTreeSet<String>,
}

/// Generation-checked complete replacement of one external task namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileExternalTasks {
    pub expected_generation: TaskGraphGeneration,
    pub system: String,
    pub items: Vec<ExternalTaskDraft>,
}

/// Host-derived binding between an approved plan artifact and its canonical
/// execution checkpoint. The version must be the digest of the exact approved
/// bytes, computed outside model control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileApprovedPlan {
    pub expected_generation: TaskGraphGeneration,
    pub plan_id: String,
    pub observed_version: String,
}

/// Immutable receipt for a validated in-memory proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskGraphReceipt {
    pub previous_generation: TaskGraphGeneration,
    pub generation: TaskGraphGeneration,
    pub affected: Vec<TaskId>,
}

/// Fully validated proposed replacement. It has not necessarily been
/// published to durable storage yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskGraphProposal {
    graph: TaskGraph,
    receipt: TaskGraphReceipt,
}

impl TaskGraphProposal {
    #[must_use]
    pub const fn graph(&self) -> &TaskGraph {
        &self.graph
    }

    #[must_use]
    pub const fn receipt(&self) -> &TaskGraphReceipt {
        &self.receipt
    }

    #[must_use]
    pub fn into_parts(self) -> (TaskGraph, TaskGraphReceipt) {
        (self.graph, self.receipt)
    }
}

/// Generation-bound page cursor. A cursor from a changed graph is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskPageCursor {
    generation: TaskGraphGeneration,
    after_sequence: u64,
}

impl TaskPageCursor {
    #[must_use]
    pub const fn generation(self) -> TaskGraphGeneration {
        self.generation
    }

    #[must_use]
    pub const fn after_sequence(self) -> u64 {
        self.after_sequence
    }

    /// Encode the cursor for a tool response. The schema tag makes later
    /// cursor migrations explicit instead of silently reinterpreting bytes.
    #[must_use]
    pub fn encode(self) -> String {
        format!("v1:{}:{}", self.generation, self.after_sequence)
    }

    /// Parse an opaque cursor previously returned by [`Self::encode`].
    ///
    /// # Errors
    /// Returns an error when the cursor is oversized, malformed, or uses an
    /// unsupported schema tag.
    pub fn parse(value: &str) -> Result<Self, TaskGraphError> {
        if value.len() > MAX_PAGE_CURSOR_BYTES {
            return Err(TaskGraphError::InvalidCursor);
        }
        let mut parts = value.split(':');
        let version = parts.next();
        let generation = parts.next().and_then(|part| part.parse::<u64>().ok());
        let after_sequence = parts.next().and_then(|part| part.parse::<u64>().ok());
        let (Some(generation), Some(after_sequence)) = (generation, after_sequence) else {
            return Err(TaskGraphError::InvalidCursor);
        };
        if version != Some("v1") || parts.next().is_some() {
            return Err(TaskGraphError::InvalidCursor);
        }
        Ok(Self {
            generation: TaskGraphGeneration::from_u64(generation),
            after_sequence,
        })
    }
}

/// One bounded page of current (non-deleted) tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPage<'a> {
    pub tasks: Vec<&'a TaskNode>,
    pub next: Option<TaskPageCursor>,
    pub generation: TaskGraphGeneration,
}

/// Bounded deterministic view of tasks that can start now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyTaskPage<'a> {
    pub tasks: Vec<&'a TaskNode>,
    pub generation: TaskGraphGeneration,
}

/// Typed task graph failure. Errors never contain task prose.
#[derive(Debug, Error)]
pub enum TaskGraphError {
    #[error("task graph schema {observed} is unsupported; expected {expected}")]
    UnsupportedSchema { observed: u32, expected: u32 },
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("task graph capacity exceeded for {resource} (limit {limit})")]
    Capacity {
        resource: &'static str,
        limit: usize,
    },
    #[error("task graph generation space is exhausted")]
    GenerationExhausted,
    #[error("task sequence space is exhausted")]
    SequenceExhausted,
    #[error("stale task graph generation: expected {expected}, observed {observed}")]
    StaleGraph {
        expected: TaskGraphGeneration,
        observed: TaskGraphGeneration,
    },
    #[error("task {task_id} was not found")]
    NotFound { task_id: TaskId },
    #[error("task {task_id} is not mutable by this actor's todo view")]
    ForeignTodoTask { task_id: TaskId },
    #[error("task {task_id} belongs to another session lane")]
    ForeignTask { task_id: TaskId },
    #[error("external task projection {task_id} is read-only outside its reconciliation adapter")]
    ExternalProjectionReadOnly { task_id: TaskId },
    #[error("delegation task {task_id} is read-only outside its child-lifecycle adapter")]
    DelegationProjectionReadOnly { task_id: TaskId },
    #[error("stale task revision for {task_id}: expected {expected}, observed {observed}")]
    StaleTask {
        task_id: TaskId,
        expected: u64,
        observed: u64,
    },
    #[error("task {task_id} cannot start while blocker {blocker_id} is {blocker_status}")]
    Blocked {
        task_id: TaskId,
        blocker_id: TaskId,
        blocker_status: CanonicalTaskStatus,
    },
    #[error("task graph contains a dependency cycle")]
    Cycle,
    #[error("task graph invariant failed: {reason}")]
    Invariant { reason: &'static str },
    #[error("task page size must be between 1 and {MAX_PAGE_SIZE}")]
    InvalidPageSize,
    #[error("task page cursor is stale: cursor {cursor}, graph {graph}")]
    StaleCursor {
        cursor: TaskGraphGeneration,
        graph: TaskGraphGeneration,
    },
    #[error("task page cursor is invalid")]
    InvalidCursor,
    #[error("task graph JSON is invalid")]
    InvalidJson,
    #[error(transparent)]
    Persistence(#[from] PersistenceError),
}

impl TaskGraph {
    pub(crate) fn empty_for_compatibility() -> Self {
        Self {
            schema_version: TASK_GRAPH_SCHEMA_VERSION,
            graph_id: "ephemeral".to_string(),
            generation: TaskGraphGeneration::initial(),
            next_sequence: 1,
            tasks: BTreeMap::new(),
            history_checkpoint: TaskHistoryCheckpoint::initial(),
            history: Vec::new(),
        }
    }

    /// Construct an empty validated graph. The identifier is host-selected and
    /// names a persistence/reconciliation scope; it grants no authority.
    ///
    /// # Errors
    /// Returns an error when `graph_id` is not a canonical bounded identifier.
    pub fn new(graph_id: impl Into<String>) -> Result<Self, TaskGraphError> {
        let graph_id = graph_id.into();
        validate_identifier("graph id", &graph_id, MAX_GRAPH_ID_BYTES)?;
        Ok(Self {
            schema_version: TASK_GRAPH_SCHEMA_VERSION,
            graph_id,
            generation: TaskGraphGeneration::initial(),
            next_sequence: 1,
            tasks: BTreeMap::new(),
            history_checkpoint: TaskHistoryCheckpoint::initial(),
            history: Vec::new(),
        })
    }

    #[must_use]
    pub fn graph_id(&self) -> &str {
        &self.graph_id
    }

    #[must_use]
    pub const fn generation(&self) -> TaskGraphGeneration {
        self.generation
    }

    #[must_use]
    pub fn task(&self, id: &TaskId) -> Option<&TaskNode> {
        self.tasks
            .get(id)
            .filter(|task| task.status != CanonicalTaskStatus::Deleted)
    }

    pub fn all_tasks(&self) -> impl Iterator<Item = &TaskNode> {
        self.tasks.values()
    }

    #[must_use]
    pub fn history(&self) -> &[TaskHistoryEvent] {
        &self.history
    }

    #[must_use]
    pub const fn history_checkpoint(&self) -> &TaskHistoryCheckpoint {
        &self.history_checkpoint
    }

    /// Build a complete create proposal without mutating `self`.
    ///
    /// # Errors
    /// Returns an error when the request is stale or invalid, graph capacity
    /// is exhausted, or the resulting graph violates an invariant.
    pub fn propose_create(
        &self,
        input: CreateTask,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<TaskGraphProposal, TaskGraphError> {
        self.require_generation(input.expected_generation)?;
        validate_text("subject", &input.subject, MAX_TASK_SUBJECT_BYTES, false)?;
        validate_text(
            "description",
            &input.description,
            MAX_TASK_DESCRIPTION_BYTES,
            true,
        )?;
        validate_optional_text(
            "active form",
            input.active_form.as_deref(),
            MAX_TASK_ACTIVE_FORM_BYTES,
        )?;
        if input.status == CanonicalTaskStatus::Deleted {
            return Err(TaskGraphError::InvalidField {
                field: "initial task status",
                reason: "new tasks cannot start deleted",
            });
        }
        validate_source(&input.source)?;
        match &input.source {
            TaskSource::Delegation { .. } if input.status != CanonicalTaskStatus::InProgress => {
                return Err(TaskGraphError::InvalidField {
                    field: "initial delegation status",
                    reason: "a supervised child must start in progress",
                });
            }
            TaskSource::ExternalIssue { .. } => {
                return Err(TaskGraphError::InvalidField {
                    field: "initial task source",
                    reason: "external issue projections must be created by reconciliation",
                });
            }
            _ => {}
        }
        if let Some(budget) = &input.budget {
            validate_budget(budget)?;
        }
        if self.tasks.len() >= MAX_TASKS {
            return Err(TaskGraphError::Capacity {
                resource: "tasks",
                limit: MAX_TASKS,
            });
        }

        let mut proposed = self.clone();
        let sequence = proposed.next_sequence;
        proposed.next_sequence = sequence
            .checked_add(1)
            .ok_or(TaskGraphError::SequenceExhausted)?;
        let id = TaskId::parse(format!("task-{sequence}"))?;
        let ownership = if matches!(&input.source, TaskSource::ExternalIssue { .. }) {
            TaskOwnership::ExternalProjection
        } else {
            TaskOwnership::Run {
                owner: actor.clone(),
            }
        };
        let task = TaskNode {
            id: id.clone(),
            sequence,
            revision: 1,
            subject: input.subject,
            description: input.description,
            active_form: input.active_form,
            status: input.status,
            priority: input.priority,
            blocks: BTreeSet::new(),
            blocked_by: BTreeSet::new(),
            ownership,
            source: input.source,
            budget: input.budget,
            created_at: now,
            updated_at: now,
            completed_at: (input.status == CanonicalTaskStatus::Completed).then_some(now),
            terminal_at: is_terminal(input.status).then_some(now),
        };
        proposed.tasks.insert(id.clone(), task);
        proposed.finish_proposal(TaskHistoryKind::Created, actor, vec![id], now)
    }

    /// Build a complete update proposal without mutating `self`.
    ///
    /// # Errors
    /// Returns an error when the target is missing, foreign, stale, invalid,
    /// or the complete proposed graph violates an invariant.
    pub fn propose_update(
        &self,
        update: UpdateTask,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<TaskGraphProposal, TaskGraphError> {
        self.propose_update_inner(update, actor, now, None)
    }

    /// Update one exact child-lifecycle projection after the caller has bound
    /// the canonical agent id through the supervised delegation manager.
    pub(crate) fn propose_update_delegation(
        &self,
        update: UpdateTask,
        actor: &TaskActor,
        now: DateTime<Utc>,
        expected_agent_id: &str,
    ) -> Result<TaskGraphProposal, TaskGraphError> {
        if matches!(
            update.status,
            Some(CanonicalTaskStatus::Pending | CanonicalTaskStatus::Deleted)
        ) {
            return Err(TaskGraphError::InvalidField {
                field: "delegation status",
                reason: "a supervised child may only be running, completed, failed, or canceled",
            });
        }
        self.propose_update_inner(update, actor, now, Some(expected_agent_id))
    }

    fn propose_update_inner(
        &self,
        update: UpdateTask,
        actor: &TaskActor,
        now: DateTime<Utc>,
        delegated_agent_authority: Option<&str>,
    ) -> Result<TaskGraphProposal, TaskGraphError> {
        self.require_generation(update.expected_generation)?;
        let current = self
            .tasks
            .get(&update.task_id)
            .filter(|task| task.status != CanonicalTaskStatus::Deleted)
            .ok_or_else(|| TaskGraphError::NotFound {
                task_id: update.task_id.clone(),
            })?;
        if current.revision != update.expected_task_revision {
            return Err(TaskGraphError::StaleTask {
                task_id: update.task_id,
                expected: update.expected_task_revision,
                observed: current.revision,
            });
        }
        if matches!(current.ownership, TaskOwnership::ExternalProjection) {
            return Err(TaskGraphError::ExternalProjectionReadOnly {
                task_id: current.id.clone(),
            });
        }
        if matches!(
            &current.ownership,
            TaskOwnership::Run { owner } if owner.session_id != actor.session_id
        ) {
            return Err(TaskGraphError::ForeignTask {
                task_id: current.id.clone(),
            });
        }
        if let TaskSource::Delegation { agent_id } = &current.source {
            if delegated_agent_authority != Some(agent_id.as_str()) {
                return Err(TaskGraphError::DelegationProjectionReadOnly {
                    task_id: current.id.clone(),
                });
            }
        } else if delegated_agent_authority.is_some() {
            return Err(TaskGraphError::DelegationProjectionReadOnly {
                task_id: current.id.clone(),
            });
        }

        validate_field_update("subject", &update.subject, MAX_TASK_SUBJECT_BYTES, false)?;
        validate_field_update(
            "description",
            &update.description,
            MAX_TASK_DESCRIPTION_BYTES,
            true,
        )?;
        validate_field_update(
            "active form",
            &update.active_form,
            MAX_TASK_ACTIVE_FORM_BYTES,
            false,
        )?;
        if let FieldUpdate::Set(budget) = &update.budget {
            validate_budget(budget)?;
        }
        validate_edge_set(update.blocks.as_ref())?;
        validate_edge_set(update.blocked_by.as_ref())?;

        let mut proposed = self.clone();
        proposed.apply_update(&update, now)?;

        // Reciprocal edge changes, deletion cleanup, and same-lane demotion
        // are first-class mutations. Advance every indirectly changed node's
        // revision and name every changed node in the immutable receipt.
        let mut affected = Vec::new();
        for (id, proposed_task) in &mut proposed.tasks {
            let original = self.tasks.get(id).ok_or(TaskGraphError::Invariant {
                reason: "updated graph introduced a task outside create",
            })?;
            if proposed_task != original {
                if proposed_task.revision == original.revision {
                    proposed_task.revision = proposed_task
                        .revision
                        .checked_add(1)
                        .ok_or(TaskGraphError::GenerationExhausted)?;
                    proposed_task.updated_at = now;
                }
                affected.push(id.clone());
            }
        }
        if affected.is_empty() {
            return Ok(TaskGraphProposal {
                graph: proposed,
                receipt: TaskGraphReceipt {
                    previous_generation: self.generation,
                    generation: self.generation,
                    affected,
                },
            });
        }
        proposed.finish_proposal(TaskHistoryKind::Updated, actor, affected, now)
    }

    /// Reconcile one actor's complete todo projection in a single validated
    /// graph transaction. Omitted owned tasks become tombstones, but tasks
    /// owned by another run/actor and external issue projections are never
    /// interpreted as deletions. Existing rows require stable ids/revisions;
    /// content matching is deliberately not an identity mechanism.
    ///
    /// # Errors
    /// Returns an error when the replacement is stale, invalid, foreign, over
    /// capacity, or would violate a complete graph invariant.
    pub fn propose_replace_todos(
        &self,
        replacement: ReplaceTodoList,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<TaskGraphProposal, TaskGraphError> {
        self.require_generation(replacement.expected_generation)?;
        if replacement.items.len() > MAX_TASKS {
            return Err(TaskGraphError::Capacity {
                resource: "todo items",
                limit: MAX_TASKS,
            });
        }
        if replacement
            .items
            .iter()
            .filter(|item| item.status == CanonicalTaskStatus::InProgress)
            .count()
            > 1
        {
            return Err(TaskGraphError::Invariant {
                reason: "one todo view cannot contain multiple in-progress tasks",
            });
        }

        let (mut proposed, retained, created) =
            self.apply_todo_replacement_items(replacement.items, actor, now)?;

        let omitted = self
            .tasks
            .values()
            .filter(|task| {
                task.status != CanonicalTaskStatus::Deleted
                    && owned_by_todo_view(task, actor)
                    && !retained.contains(&task.id)
            })
            .map(|task| task.id.clone())
            .collect::<Vec<_>>();
        for id in omitted {
            let task = proposed
                .tasks
                .get_mut(&id)
                .ok_or(TaskGraphError::Invariant {
                    reason: "omitted todo task disappeared from proposed graph",
                })?;
            task.status = CanonicalTaskStatus::Deleted;
            task.completed_at = None;
            task.terminal_at = Some(now);
            task.blocks.clear();
            task.blocked_by.clear();
        }

        let live_ids = proposed
            .tasks
            .values()
            .filter(|task| task.status != CanonicalTaskStatus::Deleted)
            .map(|task| task.id.clone())
            .collect::<BTreeSet<_>>();
        for task in proposed.tasks.values_mut() {
            if task.status != CanonicalTaskStatus::Deleted {
                task.blocks.retain(|id| live_ids.contains(id));
                task.blocked_by.retain(|id| live_ids.contains(id));
            }
        }

        let mut affected = Vec::new();
        for (id, proposed_task) in &mut proposed.tasks {
            let changed = self.tasks.get(id) != Some(&*proposed_task);
            if changed {
                if !created.contains(id) {
                    let original = self.tasks.get(id).ok_or(TaskGraphError::Invariant {
                        reason: "todo replacement changed an unknown task",
                    })?;
                    proposed_task.revision = original
                        .revision
                        .checked_add(1)
                        .ok_or(TaskGraphError::GenerationExhausted)?;
                    proposed_task.updated_at = now;
                }
                affected.push(id.clone());
            }
        }
        if affected.is_empty() {
            return Ok(TaskGraphProposal {
                graph: proposed,
                receipt: TaskGraphReceipt {
                    previous_generation: self.generation,
                    generation: self.generation,
                    affected,
                },
            });
        }
        proposed.finish_proposal(TaskHistoryKind::TodoReplaced, actor, affected, now)
    }

    fn apply_todo_replacement_items(
        &self,
        items: Vec<TodoTaskDraft>,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<(Self, BTreeSet<TaskId>, BTreeSet<TaskId>), TaskGraphError> {
        let mut proposed = self.clone();
        let mut retained = BTreeSet::new();
        let mut created = BTreeSet::new();
        for item in items {
            self.apply_todo_replacement_item(
                &mut proposed,
                &mut retained,
                &mut created,
                item,
                actor,
                now,
            )?;
        }
        Ok((proposed, retained, created))
    }

    fn apply_todo_replacement_item(
        &self,
        proposed: &mut Self,
        retained: &mut BTreeSet<TaskId>,
        created: &mut BTreeSet<TaskId>,
        item: TodoTaskDraft,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<(), TaskGraphError> {
        validate_text("todo content", &item.content, MAX_TASK_SUBJECT_BYTES, false)?;
        validate_text(
            "todo active form",
            &item.active_form,
            MAX_TASK_ACTIVE_FORM_BYTES,
            false,
        )?;
        if item.status == CanonicalTaskStatus::Deleted {
            return Err(TaskGraphError::InvalidField {
                field: "todo status",
                reason: "deleted is represented by omitting an existing row",
            });
        }
        match (&item.task_id, item.expected_task_revision) {
            (Some(_), Some(_)) => self.update_retained_todo(proposed, retained, item, actor, now),
            (None, None) => {
                let id = proposed.insert_new_todo(item, actor, now)?;
                retained.insert(id.clone());
                created.insert(id);
                Ok(())
            }
            _ => Err(TaskGraphError::InvalidField {
                field: "todo identity",
                reason: "task id and expected revision must be supplied together",
            }),
        }
    }

    fn update_retained_todo(
        &self,
        proposed: &mut Self,
        retained: &mut BTreeSet<TaskId>,
        item: TodoTaskDraft,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<(), TaskGraphError> {
        let id = item.task_id.ok_or(TaskGraphError::Invariant {
            reason: "validated retained todo has no task id",
        })?;
        let expected_revision = item
            .expected_task_revision
            .ok_or(TaskGraphError::Invariant {
                reason: "validated retained todo has no expected revision",
            })?;
        if !retained.insert(id.clone()) {
            return Err(TaskGraphError::Invariant {
                reason: "todo replacement contains a duplicate task id",
            });
        }
        let current = self
            .tasks
            .get(&id)
            .filter(|task| task.status != CanonicalTaskStatus::Deleted)
            .ok_or_else(|| TaskGraphError::NotFound {
                task_id: id.clone(),
            })?;
        if !owned_by_todo_view(current, actor) {
            return Err(TaskGraphError::ForeignTodoTask { task_id: id });
        }
        if current.revision != expected_revision {
            return Err(TaskGraphError::StaleTask {
                task_id: id,
                expected: expected_revision,
                observed: current.revision,
            });
        }
        let task = proposed
            .tasks
            .get_mut(&current.id)
            .ok_or(TaskGraphError::Invariant {
                reason: "todo task disappeared from proposed graph",
            })?;
        task.subject = item.content;
        task.active_form = Some(item.active_form);
        if task.status != item.status {
            task.status = item.status;
            task.completed_at = (item.status == CanonicalTaskStatus::Completed).then_some(now);
            task.terminal_at = is_terminal(item.status).then_some(now);
        }
        Ok(())
    }

    fn insert_new_todo(
        &mut self,
        item: TodoTaskDraft,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<TaskId, TaskGraphError> {
        if self.tasks.len() >= MAX_TASKS {
            return Err(TaskGraphError::Capacity {
                resource: "tasks",
                limit: MAX_TASKS,
            });
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or(TaskGraphError::SequenceExhausted)?;
        let id = TaskId::parse(format!("task-{sequence}"))?;
        self.tasks.insert(
            id.clone(),
            TaskNode {
                id: id.clone(),
                sequence,
                revision: 1,
                subject: item.content,
                description: String::new(),
                active_form: Some(item.active_form),
                status: item.status,
                priority: TaskPriority::Medium,
                blocks: BTreeSet::new(),
                blocked_by: BTreeSet::new(),
                ownership: TaskOwnership::Run {
                    owner: actor.clone(),
                },
                source: TaskSource::TodoView,
                budget: None,
                created_at: now,
                updated_at: now,
                completed_at: (item.status == CanonicalTaskStatus::Completed).then_some(now),
                terminal_at: is_terminal(item.status).then_some(now),
            },
        );
        Ok(id)
    }

    /// Reconcile a bounded, dependency-closed observation from one external
    /// task store. Existing projection identities are stable and only this
    /// adapter may change their external fields. Omission is not deletion:
    /// the external store remains authoritative and callers may intentionally
    /// supply an active window rather than its unbounded historical archive.
    ///
    /// # Errors
    /// Returns an error when the observation is stale, invalid, incomplete,
    /// over capacity, or would violate a complete graph invariant.
    pub fn propose_reconcile_external(
        &self,
        reconciliation: ReconcileExternalTasks,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<TaskGraphProposal, TaskGraphError> {
        let ReconcileExternalTasks {
            expected_generation,
            system,
            items,
        } = reconciliation;
        self.require_generation(expected_generation)?;
        let (drafts, mut projected_ids) = self.prepare_external_reconciliation(&system, items)?;

        let (mut proposed, created) =
            self.apply_external_drafts(&system, &drafts, &mut projected_ids, now)?;
        proposed.reconcile_external_edges(&system, &drafts, &projected_ids)?;

        let mut affected = Vec::new();
        for (id, proposed_task) in &mut proposed.tasks {
            match self.tasks.get(id) {
                None if created.contains(id) => affected.push(id.clone()),
                Some(original) if proposed_task != original => {
                    proposed_task.revision = proposed_task
                        .revision
                        .checked_add(1)
                        .ok_or(TaskGraphError::GenerationExhausted)?;
                    proposed_task.updated_at = now;
                    affected.push(id.clone());
                }
                None => {
                    return Err(TaskGraphError::Invariant {
                        reason: "external reconciliation created an untracked task",
                    });
                }
                Some(_) => {}
            }
        }
        if affected.is_empty() {
            return Ok(TaskGraphProposal {
                graph: proposed,
                receipt: TaskGraphReceipt {
                    previous_generation: self.generation,
                    generation: self.generation,
                    affected,
                },
            });
        }
        proposed.finish_proposal(TaskHistoryKind::ExternalReconciled, actor, affected, now)
    }

    fn prepare_external_reconciliation(
        &self,
        system: &str,
        items: Vec<ExternalTaskDraft>,
    ) -> Result<(ExternalDrafts, ExternalProjectionIds), TaskGraphError> {
        validate_identifier("external system", system, MAX_EXTERNAL_SYSTEM_BYTES)?;
        if items.len() > MAX_TASKS {
            return Err(TaskGraphError::Capacity {
                resource: "external task observations",
                limit: MAX_TASKS,
            });
        }
        let mut drafts = BTreeMap::new();
        for draft in items {
            validate_identifier("external id", &draft.external_id, MAX_EXTERNAL_ID_BYTES)?;
            validate_identifier(
                "external version",
                &draft.observed_version,
                MAX_EXTERNAL_ID_BYTES,
            )?;
            validate_text("subject", &draft.subject, MAX_TASK_SUBJECT_BYTES, false)?;
            validate_text(
                "description",
                &draft.description,
                MAX_TASK_DESCRIPTION_BYTES,
                true,
            )?;
            if matches!(
                draft.status,
                CanonicalTaskStatus::InProgress | CanonicalTaskStatus::Deleted
            ) {
                return Err(TaskGraphError::InvalidField {
                    field: "external task status",
                    reason: "external projections cannot be in progress or deleted",
                });
            }
            if draft.blocked_by_external_ids.len() > MAX_TASK_EDGES {
                return Err(TaskGraphError::Capacity {
                    resource: "external task blockers",
                    limit: MAX_TASK_EDGES,
                });
            }
            for blocker in &draft.blocked_by_external_ids {
                validate_identifier("external blocker id", blocker, MAX_EXTERNAL_ID_BYTES)?;
                if blocker == &draft.external_id {
                    return Err(TaskGraphError::Invariant {
                        reason: "external task cannot block itself",
                    });
                }
            }
            if drafts.insert(draft.external_id.clone(), draft).is_some() {
                return Err(TaskGraphError::Invariant {
                    reason: "external reconciliation contains a duplicate id",
                });
            }
        }
        let mut projected_ids = BTreeMap::new();
        for task in self.tasks.values() {
            if let TaskSource::ExternalIssue {
                system: task_system,
                external_id,
                ..
            } = &task.source
            {
                if task_system == system
                    && projected_ids
                        .insert(external_id.clone(), task.id.clone())
                        .is_some()
                {
                    return Err(TaskGraphError::Invariant {
                        reason: "external projection contains a duplicate source identity",
                    });
                }
            }
        }
        let new_count = drafts
            .keys()
            .filter(|external_id| !projected_ids.contains_key(*external_id))
            .count();
        if self.tasks.len().saturating_add(new_count) > MAX_TASKS {
            return Err(TaskGraphError::Capacity {
                resource: "tasks",
                limit: MAX_TASKS,
            });
        }
        Ok((drafts, projected_ids))
    }

    fn apply_external_drafts(
        &self,
        system: &str,
        drafts: &ExternalDrafts,
        projected_ids: &mut ExternalProjectionIds,
        now: DateTime<Utc>,
    ) -> Result<(Self, BTreeSet<TaskId>), TaskGraphError> {
        let mut proposed = self.clone();
        let mut created = BTreeSet::new();
        for draft in drafts.values() {
            let task_id = if let Some(id) = projected_ids.get(&draft.external_id) {
                id.clone()
            } else {
                let sequence = proposed.next_sequence;
                proposed.next_sequence = sequence
                    .checked_add(1)
                    .ok_or(TaskGraphError::SequenceExhausted)?;
                let id = TaskId::parse(format!("task-{sequence}"))?;
                projected_ids.insert(draft.external_id.clone(), id.clone());
                created.insert(id.clone());
                proposed.tasks.insert(
                    id.clone(),
                    external_task_node(id.clone(), sequence, system, draft, now),
                );
                id
            };
            let task = proposed
                .tasks
                .get_mut(&task_id)
                .ok_or(TaskGraphError::Invariant {
                    reason: "external projection disappeared during reconciliation",
                })?;
            let status_changed = task.status != draft.status;
            task.subject.clone_from(&draft.subject);
            task.description.clone_from(&draft.description);
            task.active_form = None;
            task.status = draft.status;
            task.priority = draft.priority;
            task.ownership = TaskOwnership::ExternalProjection;
            task.source = TaskSource::ExternalIssue {
                system: system.to_string(),
                external_id: draft.external_id.clone(),
                observed_version: draft.observed_version.clone(),
            };
            task.budget = None;
            if status_changed {
                task.completed_at = (draft.status == CanonicalTaskStatus::Completed).then_some(now);
                task.terminal_at = is_terminal(draft.status).then_some(now);
            }
        }
        Ok((proposed, created))
    }

    fn reconcile_external_edges(
        &mut self,
        system: &str,
        drafts: &ExternalDrafts,
        projected_ids: &ExternalProjectionIds,
    ) -> Result<(), TaskGraphError> {
        let target_ids = drafts
            .keys()
            .filter_map(|external_id| projected_ids.get(external_id).cloned())
            .collect::<BTreeSet<_>>();
        let mut removed_edges = Vec::new();
        for target_id in &target_ids {
            let target = self.tasks.get(target_id).ok_or(TaskGraphError::Invariant {
                reason: "external target disappeared before edge reconciliation",
            })?;
            for blocker_id in &target.blocked_by {
                if self
                    .tasks
                    .get(blocker_id)
                    .is_some_and(|blocker| is_external_system(blocker, system))
                {
                    removed_edges.push((blocker_id.clone(), target_id.clone()));
                }
            }
        }
        for (blocker_id, target_id) in removed_edges {
            self.tasks
                .get_mut(&blocker_id)
                .ok_or(TaskGraphError::Invariant {
                    reason: "external blocker disappeared during edge removal",
                })?
                .blocks
                .remove(&target_id);
            self.tasks
                .get_mut(&target_id)
                .ok_or(TaskGraphError::Invariant {
                    reason: "external target disappeared during edge removal",
                })?
                .blocked_by
                .remove(&blocker_id);
        }
        for (external_id, draft) in drafts {
            let target_id = projected_ids
                .get(external_id)
                .ok_or(TaskGraphError::Invariant {
                    reason: "external target identity was not projected",
                })?;
            for blocker_external_id in &draft.blocked_by_external_ids {
                let blocker_id =
                    projected_ids
                        .get(blocker_external_id)
                        .ok_or(TaskGraphError::InvalidField {
                            field: "external blocker id",
                            reason: "blocker is outside the dependency-closed observation",
                        })?;
                self.tasks
                    .get_mut(blocker_id)
                    .ok_or(TaskGraphError::Invariant {
                        reason: "external blocker projection is missing",
                    })?
                    .blocks
                    .insert(target_id.clone());
                self.tasks
                    .get_mut(target_id)
                    .ok_or(TaskGraphError::Invariant {
                        reason: "external target projection is missing",
                    })?
                    .blocked_by
                    .insert(blocker_id.clone());
            }
        }
        Ok(())
    }

    /// Bind one exact user-approved plan version to a stable canonical task.
    /// Plan prose remains in the session artifact and is never parsed into
    /// authority or guessed subtasks. Structured subtasks use the ordinary
    /// graph tools; this node provides lifecycle/version continuity.
    ///
    /// # Errors
    /// Returns an error when the plan identity/version is stale or invalid,
    /// capacity is exhausted, or reconciliation violates an invariant.
    pub fn propose_reconcile_approved_plan(
        &self,
        reconciliation: ReconcileApprovedPlan,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<TaskGraphProposal, TaskGraphError> {
        self.require_generation(reconciliation.expected_generation)?;
        let existing_id = self.resolve_plan_projection(&reconciliation)?;
        if let Some(existing_id) = &existing_id {
            let existing = self
                .tasks
                .get(existing_id)
                .ok_or(TaskGraphError::Invariant {
                    reason: "plan projection disappeared during reconciliation",
                })?;
            let same_version = matches!(
                &existing.source,
                TaskSource::Plan { observed_version, .. }
                    if observed_version == &reconciliation.observed_version
            );
            if same_version && is_terminal(existing.status) {
                return Ok(TaskGraphProposal {
                    graph: self.clone(),
                    receipt: TaskGraphReceipt {
                        previous_generation: self.generation,
                        generation: self.generation,
                        affected: Vec::new(),
                    },
                });
            }
        }

        let mut proposed = self.clone();
        let (task_id, created) =
            proposed.ensure_plan_task(existing_id, &reconciliation, actor, now)?;
        proposed.apply_plan_projection(&task_id, reconciliation, actor)?;

        let mut affected = Vec::new();
        for (id, proposed_task) in &mut proposed.tasks {
            match self.tasks.get(id) {
                None if created.as_ref() == Some(id) => affected.push(id.clone()),
                Some(original) if proposed_task != original => {
                    proposed_task.revision = proposed_task
                        .revision
                        .checked_add(1)
                        .ok_or(TaskGraphError::GenerationExhausted)?;
                    proposed_task.updated_at = now;
                    affected.push(id.clone());
                }
                None => {
                    return Err(TaskGraphError::Invariant {
                        reason: "plan reconciliation created an untracked task",
                    });
                }
                Some(_) => {}
            }
        }
        if affected.is_empty() {
            return Ok(TaskGraphProposal {
                graph: proposed,
                receipt: TaskGraphReceipt {
                    previous_generation: self.generation,
                    generation: self.generation,
                    affected,
                },
            });
        }
        proposed.finish_proposal(TaskHistoryKind::PlanReconciled, actor, affected, now)
    }

    fn resolve_plan_projection(
        &self,
        reconciliation: &ReconcileApprovedPlan,
    ) -> Result<Option<TaskId>, TaskGraphError> {
        validate_identifier("plan id", &reconciliation.plan_id, MAX_PLAN_ID_BYTES)?;
        validate_identifier(
            "plan observed version",
            &reconciliation.observed_version,
            MAX_PLAN_VERSION_BYTES,
        )?;
        let matches = self
            .tasks
            .values()
            .filter(|task| {
                matches!(
                    &task.source,
                    TaskSource::Plan { plan_id, .. } if plan_id == &reconciliation.plan_id
                )
            })
            .map(|task| task.id.clone())
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(TaskGraphError::Invariant {
                reason: "plan projection contains a duplicate plan identity",
            });
        }
        if matches.is_empty() && self.tasks.len() >= MAX_TASKS {
            return Err(TaskGraphError::Capacity {
                resource: "tasks",
                limit: MAX_TASKS,
            });
        }
        Ok(matches.into_iter().next())
    }

    fn ensure_plan_task(
        &mut self,
        existing_id: Option<TaskId>,
        reconciliation: &ReconcileApprovedPlan,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<(TaskId, Option<TaskId>), TaskGraphError> {
        if let Some(id) = existing_id {
            return Ok((id, None));
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence
            .checked_add(1)
            .ok_or(TaskGraphError::SequenceExhausted)?;
        let id = TaskId::parse(format!("task-{sequence}"))?;
        self.tasks.insert(
            id.clone(),
            plan_task_node(id.clone(), sequence, reconciliation, actor, now),
        );
        Ok((id.clone(), Some(id)))
    }

    fn apply_plan_projection(
        &mut self,
        task_id: &TaskId,
        reconciliation: ReconcileApprovedPlan,
        actor: &TaskActor,
    ) -> Result<(), TaskGraphError> {
        let blockers_ready = self
            .tasks
            .get(task_id)
            .ok_or(TaskGraphError::Invariant {
                reason: "plan task disappeared before readiness evaluation",
            })?
            .blocked_by
            .iter()
            .all(|blocker_id| {
                self.tasks
                    .get(blocker_id)
                    .is_some_and(|blocker| blocker.status == CanonicalTaskStatus::Completed)
            });
        let desired_status = if blockers_ready {
            CanonicalTaskStatus::InProgress
        } else {
            CanonicalTaskStatus::Pending
        };
        if desired_status == CanonicalTaskStatus::InProgress {
            for task in self.tasks.values_mut() {
                if task.id != *task_id
                    && task.status == CanonicalTaskStatus::InProgress
                    && owner_lane(&task.ownership) == Some(actor.session_id.as_str())
                    && !matches!(task.source, TaskSource::Delegation { .. })
                {
                    task.status = CanonicalTaskStatus::Pending;
                    task.completed_at = None;
                    task.terminal_at = None;
                }
            }
        }
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or(TaskGraphError::Invariant {
                reason: "plan task disappeared during reconciliation",
            })?;
        task.subject = "Execute approved implementation plan".to_string();
        task.description.clear();
        task.active_form = Some("Executing approved implementation plan".to_string());
        task.status = desired_status;
        task.priority = TaskPriority::High;
        task.ownership = TaskOwnership::Run {
            owner: actor.clone(),
        };
        task.source = TaskSource::Plan {
            plan_id: reconciliation.plan_id,
            observed_version: reconciliation.observed_version,
        };
        task.budget = None;
        task.completed_at = None;
        task.terminal_at = None;
        Ok(())
    }

    /// Apply a create atomically to this in-memory graph.
    ///
    /// # Errors
    /// Returns an error under the same conditions as [`Self::propose_create`].
    pub fn create(
        &mut self,
        input: CreateTask,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<TaskGraphReceipt, TaskGraphError> {
        let (graph, receipt) = self.propose_create(input, actor, now)?.into_parts();
        *self = graph;
        Ok(receipt)
    }

    /// Apply an update atomically to this in-memory graph.
    ///
    /// # Errors
    /// Returns an error under the same conditions as [`Self::propose_update`].
    pub fn update(
        &mut self,
        update: UpdateTask,
        actor: &TaskActor,
        now: DateTime<Utc>,
    ) -> Result<TaskGraphReceipt, TaskGraphError> {
        let (graph, receipt) = self.propose_update(update, actor, now)?.into_parts();
        *self = graph;
        Ok(receipt)
    }

    /// Return a generation-bound bounded page in creation order.
    ///
    /// # Errors
    /// Returns an error for an invalid page size or stale cursor generation.
    pub fn page(
        &self,
        cursor: Option<TaskPageCursor>,
        limit: usize,
    ) -> Result<TaskPage<'_>, TaskGraphError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(TaskGraphError::InvalidPageSize);
        }
        let after = if let Some(cursor) = cursor {
            if cursor.generation != self.generation {
                return Err(TaskGraphError::StaleCursor {
                    cursor: cursor.generation,
                    graph: self.generation,
                });
            }
            cursor.after_sequence
        } else {
            0
        };
        let mut tasks = self
            .tasks
            .values()
            .filter(|task| task.status != CanonicalTaskStatus::Deleted && task.sequence > after)
            .collect::<Vec<_>>();
        tasks.sort_unstable_by_key(|task| task.sequence);
        let has_more = tasks.len() > limit;
        tasks.truncate(limit);
        let next = if has_more {
            tasks.last().map(|task| TaskPageCursor {
                generation: self.generation,
                after_sequence: task.sequence,
            })
        } else {
            None
        };
        Ok(TaskPage {
            tasks,
            next,
            generation: self.generation,
        })
    }

    /// Return pending tasks whose blockers are all completed, ordered by
    /// priority and then stable creation identity.
    ///
    /// # Errors
    /// Returns an error when `limit` is outside the canonical page bound.
    pub fn ready(&self, limit: usize) -> Result<ReadyTaskPage<'_>, TaskGraphError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(TaskGraphError::InvalidPageSize);
        }
        let mut tasks = self
            .tasks
            .values()
            .filter(|task| {
                task.status == CanonicalTaskStatus::Pending
                    && task.blocked_by.iter().all(|blocker_id| {
                        self.tasks
                            .get(blocker_id)
                            .is_some_and(|blocker| blocker.status == CanonicalTaskStatus::Completed)
                    })
            })
            .collect::<Vec<_>>();
        tasks.sort_unstable_by(|left, right| {
            left.priority
                .rank()
                .cmp(&right.priority.rank())
                .then_with(|| left.sequence.cmp(&right.sequence))
                .then_with(|| left.id.cmp(&right.id))
        });
        tasks.truncate(limit);
        Ok(ReadyTaskPage {
            tasks,
            generation: self.generation,
        })
    }

    /// Validate every persisted/live invariant over a bounded graph.
    ///
    /// # Errors
    /// Returns the first schema, bound, identity, lifecycle, ownership,
    /// history, or edge invariant violation.
    pub fn validate(&self) -> Result<(), TaskGraphError> {
        if self.schema_version != TASK_GRAPH_SCHEMA_VERSION {
            return Err(TaskGraphError::UnsupportedSchema {
                observed: self.schema_version,
                expected: TASK_GRAPH_SCHEMA_VERSION,
            });
        }
        validate_identifier("graph id", &self.graph_id, MAX_GRAPH_ID_BYTES)?;
        if self.tasks.len() > MAX_TASKS {
            return Err(TaskGraphError::Capacity {
                resource: "tasks",
                limit: MAX_TASKS,
            });
        }
        if self.history.len() > MAX_HISTORY_EVENTS {
            return Err(TaskGraphError::Capacity {
                resource: "history events",
                limit: MAX_HISTORY_EVENTS,
            });
        }

        let mut maximum_sequence = 0_u64;
        let mut active_lanes = BTreeSet::new();
        for (key, task) in &self.tasks {
            validate_task(key, task)?;
            maximum_sequence = maximum_sequence.max(task.sequence);
            if task.status == CanonicalTaskStatus::InProgress {
                if matches!(task.ownership, TaskOwnership::ExternalProjection) {
                    return Err(TaskGraphError::Invariant {
                        reason: "external projections cannot be in progress",
                    });
                }
                if let Some(lane) = active_lane(task) {
                    if !active_lanes.insert(lane) {
                        return Err(TaskGraphError::Invariant {
                            reason: "one actor lane has multiple in-progress tasks",
                        });
                    }
                }
            }
            for blocked in &task.blocks {
                let other = self.tasks.get(blocked).ok_or(TaskGraphError::Invariant {
                    reason: "edge references a missing task",
                })?;
                if other.status == CanonicalTaskStatus::Deleted || !other.blocked_by.contains(key) {
                    return Err(TaskGraphError::Invariant {
                        reason: "dependency edges are not symmetric current nodes",
                    });
                }
            }
            for blocker in &task.blocked_by {
                let other = self.tasks.get(blocker).ok_or(TaskGraphError::Invariant {
                    reason: "edge references a missing blocker",
                })?;
                if other.status == CanonicalTaskStatus::Deleted || !other.blocks.contains(key) {
                    return Err(TaskGraphError::Invariant {
                        reason: "blocker edges are not symmetric current nodes",
                    });
                }
                if task.status == CanonicalTaskStatus::InProgress
                    && other.status != CanonicalTaskStatus::Completed
                {
                    return Err(TaskGraphError::Blocked {
                        task_id: key.clone(),
                        blocker_id: blocker.clone(),
                        blocker_status: other.status,
                    });
                }
            }
        }
        if self.next_sequence <= maximum_sequence {
            return Err(TaskGraphError::Invariant {
                reason: "next task sequence is not above every stored sequence",
            });
        }
        validate_history(
            &self.history_checkpoint,
            &self.history,
            self.generation,
            &self.tasks,
        )?;
        if graph_has_cycle(&self.tasks) {
            return Err(TaskGraphError::Cycle);
        }
        Ok(())
    }

    fn require_generation(&self, expected: TaskGraphGeneration) -> Result<(), TaskGraphError> {
        if expected == self.generation {
            Ok(())
        } else {
            Err(TaskGraphError::StaleGraph {
                expected,
                observed: self.generation,
            })
        }
    }

    fn apply_update(
        &mut self,
        update: &UpdateTask,
        now: DateTime<Utc>,
    ) -> Result<(), TaskGraphError> {
        let id = &update.task_id;
        let desired_status = update.status;
        let current = self
            .tasks
            .get(id)
            .cloned()
            .ok_or_else(|| TaskGraphError::NotFound {
                task_id: id.clone(),
            })?;

        if desired_status == Some(CanonicalTaskStatus::InProgress) {
            if matches!(current.ownership, TaskOwnership::ExternalProjection) {
                return Err(TaskGraphError::Invariant {
                    reason: "external projections cannot be started",
                });
            }
            if let Some(lane) = active_lane(&current) {
                for task in self.tasks.values_mut() {
                    if task.id != *id
                        && task.status == CanonicalTaskStatus::InProgress
                        && active_lane(task) == Some(lane)
                    {
                        task.status = CanonicalTaskStatus::Pending;
                        task.completed_at = None;
                        task.terminal_at = None;
                    }
                }
            }
        }

        let task = self
            .tasks
            .get_mut(id)
            .ok_or_else(|| TaskGraphError::NotFound {
                task_id: id.clone(),
            })?;
        apply_required_string(&mut task.subject, &update.subject)?;
        apply_optional_string(&mut task.active_form, &update.active_form);
        apply_optional_description(&mut task.description, &update.description);
        apply_optional_value(&mut task.budget, &update.budget);
        if let Some(priority) = update.priority {
            task.priority = priority;
        }
        if let Some(blocks) = &update.blocks {
            task.blocks.clone_from(blocks);
        }
        if let Some(blocked_by) = &update.blocked_by {
            task.blocked_by.clone_from(blocked_by);
        }
        if let Some(status) = desired_status.filter(|status| *status != task.status) {
            task.status = status;
            task.completed_at = (status == CanonicalTaskStatus::Completed).then_some(now);
            task.terminal_at = is_terminal(status).then_some(now);
        }

        if desired_status == Some(CanonicalTaskStatus::Deleted) {
            task.blocks.clear();
            task.blocked_by.clear();
            for other in self.tasks.values_mut() {
                other.blocks.remove(id);
                other.blocked_by.remove(id);
            }
        } else {
            self.rebuild_symmetric_edges(id)?;
        }
        Ok(())
    }

    fn rebuild_symmetric_edges(&mut self, changed_id: &TaskId) -> Result<(), TaskGraphError> {
        for task in self.tasks.values_mut() {
            if task.id != *changed_id {
                task.blocks.remove(changed_id);
                task.blocked_by.remove(changed_id);
            }
        }
        let changed = self
            .tasks
            .get(changed_id)
            .ok_or_else(|| TaskGraphError::NotFound {
                task_id: changed_id.clone(),
            })?;
        let blocks = changed.blocks.clone();
        let blocked_by = changed.blocked_by.clone();
        for id in &blocks {
            let other = self
                .tasks
                .get_mut(id)
                .filter(|task| task.status != CanonicalTaskStatus::Deleted)
                .ok_or_else(|| TaskGraphError::NotFound {
                    task_id: id.clone(),
                })?;
            other.blocked_by.insert(changed_id.clone());
        }
        for id in &blocked_by {
            let other = self
                .tasks
                .get_mut(id)
                .filter(|task| task.status != CanonicalTaskStatus::Deleted)
                .ok_or_else(|| TaskGraphError::NotFound {
                    task_id: id.clone(),
                })?;
            other.blocks.insert(changed_id.clone());
        }
        Ok(())
    }

    fn finish_proposal(
        mut self,
        kind: TaskHistoryKind,
        actor: &TaskActor,
        affected: Vec<TaskId>,
        now: DateTime<Utc>,
    ) -> Result<TaskGraphProposal, TaskGraphError> {
        let previous_generation = self.generation;
        self.generation = self.generation.next()?;
        let event = TaskHistoryEvent {
            generation: self.generation,
            kind,
            actor: actor.clone(),
            affected: affected.clone(),
            recorded_at: now,
        };
        if self.history.len() == MAX_HISTORY_EVENTS {
            let compacted = self.history.remove(0);
            self.history_checkpoint.include(&compacted)?;
        }
        self.history.push(event);
        self.validate()?;
        Ok(TaskGraphProposal {
            graph: self,
            receipt: TaskGraphReceipt {
                previous_generation,
                generation: previous_generation.next()?,
                affected,
            },
        })
    }
}

/// Descriptor-safe durable store for one exact task graph document.
#[derive(Clone, Debug)]
pub struct TaskGraphStore {
    storage: PersistentStorage,
    target: PathBuf,
    graph_id: String,
}

/// Loaded graph plus the exact storage generation required for publication.
#[derive(Debug)]
pub struct StoredTaskGraph {
    pub graph: TaskGraph,
    pub storage_generation: StorageGeneration,
}

impl TaskGraphStore {
    /// Open an existing host-authorized persistence root. The graph document
    /// itself may be absent and is created only by a later successful commit.
    ///
    /// # Errors
    /// Returns an error when the graph identity or descriptor-safe root is
    /// invalid or unsupported.
    pub fn open(
        root: impl AsRef<Path>,
        target: impl Into<PathBuf>,
        graph_id: impl Into<String>,
    ) -> Result<Self, TaskGraphError> {
        let graph_id = graph_id.into();
        validate_identifier("graph id", &graph_id, MAX_GRAPH_ID_BYTES)?;
        Ok(Self {
            storage: PersistentStorage::open(root)?,
            target: target.into(),
            graph_id,
        })
    }

    /// Read, strictly decode, and validate the current graph. A missing file
    /// yields an empty generation-zero graph without writing anything.
    ///
    /// # Errors
    /// Returns an error when storage cannot be read or the document is
    /// malformed, unsupported, identity-mismatched, or invalid.
    pub fn load(&self) -> Result<StoredTaskGraph, TaskGraphError> {
        let read = self.storage.read(&self.target, FileClass::State)?;
        let storage_generation = read.generation();
        let graph = read.expose_bytes(|bytes| {
            bytes.map_or_else(
                || TaskGraph::new(self.graph_id.clone()),
                |bytes| {
                    serde_json::from_slice::<TaskGraph>(bytes)
                        .map_err(|_| TaskGraphError::InvalidJson)
                },
            )
        })?;
        if graph.graph_id != self.graph_id {
            return Err(TaskGraphError::Invariant {
                reason: "persisted graph identity differs from requested graph",
            });
        }
        graph.validate()?;
        Ok(StoredTaskGraph {
            graph,
            storage_generation,
        })
    }

    /// Publish one already validated proposal under the exact observed file
    /// generation. A conflict leaves both caller state and stored state intact.
    ///
    /// # Errors
    /// Returns an error when the graph is invalid or identity-mismatched, the
    /// expected storage generation is stale, or publication fails.
    pub fn commit(
        &self,
        expected: StorageGeneration,
        graph: &TaskGraph,
    ) -> Result<CommitReceipt, TaskGraphError> {
        graph.validate()?;
        if graph.graph_id != self.graph_id {
            return Err(TaskGraphError::Invariant {
                reason: "proposal graph identity differs from store identity",
            });
        }
        let bytes = serde_json::to_vec(graph).map_err(|_| TaskGraphError::InvalidJson)?;
        self.storage
            .commit(&self.target, FileClass::State, expected, bytes)
            .map_err(TaskGraphError::from)
    }
}

fn validate_identifier(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), TaskGraphError> {
    if value.is_empty() {
        return Err(TaskGraphError::InvalidField {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > max_bytes {
        return Err(TaskGraphError::InvalidField {
            field,
            reason: "exceeds its byte limit",
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(TaskGraphError::InvalidField {
            field,
            reason: "contains a noncanonical character",
        });
    }
    Ok(())
}

fn validate_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), TaskGraphError> {
    if !allow_empty && value.trim().is_empty() {
        return Err(TaskGraphError::InvalidField {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > max_bytes {
        return Err(TaskGraphError::InvalidField {
            field,
            reason: "exceeds its byte limit",
        });
    }
    if value.contains('\0') {
        return Err(TaskGraphError::InvalidField {
            field,
            reason: "contains a NUL byte",
        });
    }
    Ok(())
}

fn validate_optional_text(
    field: &'static str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), TaskGraphError> {
    if let Some(value) = value {
        validate_text(field, value, max_bytes, false)?;
    }
    Ok(())
}

fn validate_source(source: &TaskSource) -> Result<(), TaskGraphError> {
    match source {
        TaskSource::TaskTool | TaskSource::TodoView => {}
        TaskSource::Plan {
            plan_id,
            observed_version,
        } => {
            validate_identifier("plan id", plan_id, MAX_PLAN_ID_BYTES)?;
            validate_identifier(
                "plan observed version",
                observed_version,
                MAX_PLAN_VERSION_BYTES,
            )?;
        }
        TaskSource::Delegation { agent_id } => {
            validate_identifier("delegated agent id", agent_id, MAX_AGENT_ID_BYTES)?;
        }
        TaskSource::ExternalIssue {
            system,
            external_id,
            observed_version,
        } => {
            validate_identifier("external system", system, MAX_EXTERNAL_SYSTEM_BYTES)?;
            validate_identifier("external id", external_id, MAX_EXTERNAL_ID_BYTES)?;
            validate_identifier("external version", observed_version, MAX_EXTERNAL_ID_BYTES)?;
        }
    }
    Ok(())
}

fn validate_field_update(
    field: &'static str,
    update: &FieldUpdate<String>,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), TaskGraphError> {
    if let FieldUpdate::Set(value) = update {
        validate_text(field, value, max_bytes, allow_empty)?;
    }
    Ok(())
}

fn validate_budget(budget: &TaskBudgetSpec) -> Result<(), TaskGraphError> {
    let limits = [
        ("task budget turns", budget.max_turns, MAX_TASK_BUDGET_TURNS),
        (
            "task budget tokens",
            budget.max_tokens,
            MAX_TASK_BUDGET_TOKENS,
        ),
        (
            "task budget elapsed milliseconds",
            budget.max_elapsed_millis,
            MAX_TASK_BUDGET_ELAPSED_MILLIS,
        ),
        (
            "task budget cost microusd",
            budget.max_cost_microusd,
            MAX_TASK_BUDGET_COST_MICROUSD,
        ),
        (
            "task budget child runs",
            budget.max_child_runs,
            MAX_TASK_BUDGET_CHILD_RUNS,
        ),
        (
            "task budget concurrent calls",
            budget.max_concurrent_calls,
            MAX_TASK_BUDGET_CONCURRENT_CALLS,
        ),
    ];
    if limits.iter().all(|(_, value, _)| value.is_none()) {
        return Err(TaskGraphError::InvalidField {
            field: "task budget",
            reason: "must declare at least one finite limit",
        });
    }
    for (field, value, maximum) in limits {
        if value.is_some_and(|value| value == 0 || value > maximum) {
            return Err(TaskGraphError::InvalidField {
                field,
                reason: "must be non-zero and within its hard maximum",
            });
        }
    }
    Ok(())
}

fn validate_edge_set(edges: Option<&BTreeSet<TaskId>>) -> Result<(), TaskGraphError> {
    if edges.is_some_and(|edges| edges.len() > MAX_TASK_EDGES) {
        return Err(TaskGraphError::Capacity {
            resource: "task edges",
            limit: MAX_TASK_EDGES,
        });
    }
    Ok(())
}

fn apply_required_string(
    target: &mut String,
    update: &FieldUpdate<String>,
) -> Result<(), TaskGraphError> {
    match update {
        FieldUpdate::Keep => {}
        FieldUpdate::Set(value) => target.clone_from(value),
        FieldUpdate::Clear => {
            return Err(TaskGraphError::InvalidField {
                field: "required task string",
                reason: "cannot be cleared",
            });
        }
    }
    Ok(())
}

fn apply_optional_description(target: &mut String, update: &FieldUpdate<String>) {
    match update {
        FieldUpdate::Keep => {}
        FieldUpdate::Set(value) => target.clone_from(value),
        FieldUpdate::Clear => target.clear(),
    }
}

fn apply_optional_string(target: &mut Option<String>, update: &FieldUpdate<String>) {
    match update {
        FieldUpdate::Keep => {}
        FieldUpdate::Set(value) => {
            target.replace(value.clone());
        }
        FieldUpdate::Clear => {
            target.take();
        }
    }
}

fn apply_optional_value<T: Clone>(target: &mut Option<T>, update: &FieldUpdate<T>) {
    match update {
        FieldUpdate::Keep => {}
        FieldUpdate::Set(value) => {
            target.replace(value.clone());
        }
        FieldUpdate::Clear => {
            target.take();
        }
    }
}

const fn owner_lane(ownership: &TaskOwnership) -> Option<&str> {
    match ownership {
        TaskOwnership::Run { owner } => Some(owner.session_id.as_str()),
        TaskOwnership::ExternalProjection => None,
    }
}

fn is_external_system(task: &TaskNode, expected_system: &str) -> bool {
    matches!(
        &task.source,
        TaskSource::ExternalIssue { system, .. } if system == expected_system
    )
}

fn external_task_node(
    id: TaskId,
    sequence: u64,
    system: &str,
    draft: &ExternalTaskDraft,
    now: DateTime<Utc>,
) -> TaskNode {
    TaskNode {
        id,
        sequence,
        revision: 1,
        subject: draft.subject.clone(),
        description: draft.description.clone(),
        active_form: None,
        status: draft.status,
        priority: draft.priority,
        blocks: BTreeSet::new(),
        blocked_by: BTreeSet::new(),
        ownership: TaskOwnership::ExternalProjection,
        source: TaskSource::ExternalIssue {
            system: system.to_string(),
            external_id: draft.external_id.clone(),
            observed_version: draft.observed_version.clone(),
        },
        budget: None,
        created_at: now,
        updated_at: now,
        completed_at: (draft.status == CanonicalTaskStatus::Completed).then_some(now),
        terminal_at: is_terminal(draft.status).then_some(now),
    }
}

fn plan_task_node(
    id: TaskId,
    sequence: u64,
    reconciliation: &ReconcileApprovedPlan,
    actor: &TaskActor,
    now: DateTime<Utc>,
) -> TaskNode {
    TaskNode {
        id,
        sequence,
        revision: 1,
        subject: "Execute approved implementation plan".to_string(),
        description: String::new(),
        active_form: Some("Executing approved implementation plan".to_string()),
        status: CanonicalTaskStatus::InProgress,
        priority: TaskPriority::High,
        blocks: BTreeSet::new(),
        blocked_by: BTreeSet::new(),
        ownership: TaskOwnership::Run {
            owner: actor.clone(),
        },
        source: TaskSource::Plan {
            plan_id: reconciliation.plan_id.clone(),
            observed_version: reconciliation.observed_version.clone(),
        },
        budget: None,
        created_at: now,
        updated_at: now,
        completed_at: None,
        terminal_at: None,
    }
}

const fn active_lane(task: &TaskNode) -> Option<&str> {
    if matches!(task.source, TaskSource::Delegation { .. }) {
        None
    } else {
        owner_lane(&task.ownership)
    }
}

fn owned_by(task: &TaskNode, actor: &TaskActor) -> bool {
    matches!(
        &task.ownership,
        TaskOwnership::Run { owner } if owner.session_id == actor.session_id
    )
}

fn owned_by_todo_view(task: &TaskNode, actor: &TaskActor) -> bool {
    owned_by(task, actor) && matches!(task.source, TaskSource::TaskTool | TaskSource::TodoView)
}

fn validate_task(key: &TaskId, task: &TaskNode) -> Result<(), TaskGraphError> {
    if key != &task.id {
        return Err(TaskGraphError::Invariant {
            reason: "task map key differs from embedded id",
        });
    }
    TaskId::parse(task.id.0.clone())?;
    if task.sequence == 0 || task.revision == 0 {
        return Err(TaskGraphError::Invariant {
            reason: "task sequence and revision must be non-zero",
        });
    }
    validate_text("subject", &task.subject, MAX_TASK_SUBJECT_BYTES, false)?;
    validate_text(
        "description",
        &task.description,
        MAX_TASK_DESCRIPTION_BYTES,
        true,
    )?;
    validate_optional_text(
        "active form",
        task.active_form.as_deref(),
        MAX_TASK_ACTIVE_FORM_BYTES,
    )?;
    validate_source(&task.source)?;
    if let Some(budget) = &task.budget {
        validate_budget(budget)?;
    }
    validate_edge_set(Some(&task.blocks))?;
    validate_edge_set(Some(&task.blocked_by))?;
    if task.blocks.contains(key) || task.blocked_by.contains(key) {
        return Err(TaskGraphError::Invariant {
            reason: "task cannot depend on itself",
        });
    }
    if task.updated_at < task.created_at {
        return Err(TaskGraphError::Invariant {
            reason: "task update time precedes creation",
        });
    }
    match task.status {
        CanonicalTaskStatus::Completed if task.completed_at.is_none() => {
            return Err(TaskGraphError::Invariant {
                reason: "completed task lacks completion time",
            });
        }
        CanonicalTaskStatus::Completed => {}
        _ if task.completed_at.is_some() => {
            return Err(TaskGraphError::Invariant {
                reason: "non-completed task has a completion time",
            });
        }
        _ => {}
    }
    if is_terminal(task.status) != task.terminal_at.is_some() {
        return Err(TaskGraphError::Invariant {
            reason: "task terminal state and terminal time disagree",
        });
    }
    if task.status == CanonicalTaskStatus::Completed && task.completed_at != task.terminal_at {
        return Err(TaskGraphError::Invariant {
            reason: "completed task times disagree",
        });
    }
    if task.status == CanonicalTaskStatus::Deleted
        && (!task.blocks.is_empty() || !task.blocked_by.is_empty())
    {
        return Err(TaskGraphError::Invariant {
            reason: "deleted task retains dependency edges",
        });
    }
    if matches!(task.source, TaskSource::ExternalIssue { .. })
        != matches!(task.ownership, TaskOwnership::ExternalProjection)
    {
        return Err(TaskGraphError::Invariant {
            reason: "external issue source/ownership are inconsistent",
        });
    }
    validate_source_projection_invariants(task)?;
    if let TaskOwnership::Run { owner } = &task.ownership {
        validate_identifier(
            "task owner session id",
            &owner.session_id,
            MAX_TASK_SESSION_ID_BYTES,
        )?;
    }
    Ok(())
}

const fn validate_source_projection_invariants(task: &TaskNode) -> Result<(), TaskGraphError> {
    match &task.source {
        TaskSource::ExternalIssue { .. } => {
            if matches!(
                task.status,
                CanonicalTaskStatus::InProgress | CanonicalTaskStatus::Deleted
            ) {
                return Err(TaskGraphError::Invariant {
                    reason: "external projection has an internal-only lifecycle state",
                });
            }
            if task.active_form.is_some() || task.budget.is_some() {
                return Err(TaskGraphError::Invariant {
                    reason: "external projection carries internal execution metadata",
                });
            }
        }
        TaskSource::Delegation { .. }
            if matches!(
                task.status,
                CanonicalTaskStatus::Pending | CanonicalTaskStatus::Deleted
            ) =>
        {
            return Err(TaskGraphError::Invariant {
                reason: "delegation projection has an unsupervised lifecycle state",
            });
        }
        _ => {}
    }
    Ok(())
}

const fn is_terminal(status: CanonicalTaskStatus) -> bool {
    matches!(
        status,
        CanonicalTaskStatus::Completed
            | CanonicalTaskStatus::Failed
            | CanonicalTaskStatus::Canceled
            | CanonicalTaskStatus::Deleted
    )
}

fn validate_history(
    checkpoint: &TaskHistoryCheckpoint,
    history: &[TaskHistoryEvent],
    graph_generation: TaskGraphGeneration,
    tasks: &BTreeMap<TaskId, TaskNode>,
) -> Result<(), TaskGraphError> {
    let checkpoint_digest = decode_digest(&checkpoint.chain_digest)?;
    if checkpoint.event_count != checkpoint.through_generation.get() {
        return Err(TaskGraphError::Invariant {
            reason: "history checkpoint count differs from its generation",
        });
    }
    if checkpoint.event_count == 0 && checkpoint_digest != [0_u8; 32] {
        return Err(TaskGraphError::Invariant {
            reason: "empty history checkpoint has a non-zero digest",
        });
    }
    let mut expected = checkpoint
        .through_generation
        .get()
        .checked_add(1)
        .ok_or(TaskGraphError::GenerationExhausted)?;
    for event in history {
        validate_identifier(
            "history actor session id",
            &event.actor.session_id,
            MAX_TASK_SESSION_ID_BYTES,
        )?;
        if event.generation.get() != expected {
            return Err(TaskGraphError::Invariant {
                reason: "history generations are not contiguous",
            });
        }
        if event.affected.is_empty() || event.affected.len() > MAX_TASKS {
            return Err(TaskGraphError::Invariant {
                reason: "history event has invalid affected-task count",
            });
        }
        if event.affected.iter().any(|id| !tasks.contains_key(id)) {
            return Err(TaskGraphError::Invariant {
                reason: "history references a missing task",
            });
        }
        expected = expected
            .checked_add(1)
            .ok_or(TaskGraphError::GenerationExhausted)?;
    }
    let retained_count = u64::try_from(history.len()).map_err(|_| TaskGraphError::Capacity {
        resource: "history events",
        limit: MAX_HISTORY_EVENTS,
    })?;
    if checkpoint
        .event_count
        .checked_add(retained_count)
        .ok_or(TaskGraphError::GenerationExhausted)?
        != graph_generation.get()
    {
        return Err(TaskGraphError::Invariant {
            reason: "checkpointed and retained history differ from graph generation",
        });
    }
    Ok(())
}

fn decode_digest(value: &str) -> Result<[u8; 32], TaskGraphError> {
    if value.len() != HISTORY_DIGEST_HEX_BYTES {
        return Err(TaskGraphError::Invariant {
            reason: "history checkpoint digest has an invalid length",
        });
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = decode_hex_nibble(pair[0]).ok_or(TaskGraphError::Invariant {
            reason: "history checkpoint digest is not lowercase hexadecimal",
        })?;
        let low = decode_hex_nibble(pair[1]).ok_or(TaskGraphError::Invariant {
            reason: "history checkpoint digest is not lowercase hexadecimal",
        })?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

const fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn encode_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn graph_has_cycle(tasks: &BTreeMap<TaskId, TaskNode>) -> bool {
    let mut indegree = BTreeMap::<TaskId, usize>::new();
    for (id, task) in tasks {
        if task.status != CanonicalTaskStatus::Deleted {
            indegree.insert(id.clone(), task.blocked_by.len());
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(id.clone()))
        .collect::<Vec<_>>();
    let mut visited = 0_usize;
    while let Some(id) = ready.pop() {
        visited += 1;
        if let Some(task) = tasks.get(&id) {
            for blocked in &task.blocks {
                if let Some(count) = indegree.get_mut(blocked) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        ready.push(blocked.clone());
                    }
                }
            }
        }
    }
    visited != indegree.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn at(second: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 22, 5, 0, second)
            .single()
            .expect("valid fixture time")
    }

    fn create_input(generation: TaskGraphGeneration, subject: &str) -> CreateTask {
        CreateTask {
            expected_generation: generation,
            subject: subject.to_string(),
            description: String::new(),
            active_form: Some(format!("Working on {subject}")),
            status: CanonicalTaskStatus::Pending,
            priority: TaskPriority::Medium,
            source: TaskSource::TaskTool,
            budget: None,
        }
    }

    fn create_two(graph: &mut TaskGraph, actor: &TaskActor) -> (TaskId, TaskId) {
        let first = graph
            .create(create_input(graph.generation(), "first"), actor, at(1))
            .expect("first create")
            .affected[0]
            .clone();
        let second = graph
            .create(create_input(graph.generation(), "second"), actor, at(2))
            .expect("second create")
            .affected[0]
            .clone();
        (first, second)
    }

    fn update_for(graph: &TaskGraph, id: TaskId) -> UpdateTask {
        UpdateTask {
            expected_generation: graph.generation(),
            expected_task_revision: graph.task(&id).expect("task").revision,
            task_id: id,
            status: None,
            priority: None,
            subject: FieldUpdate::Keep,
            description: FieldUpdate::Keep,
            active_form: FieldUpdate::Keep,
            budget: FieldUpdate::Keep,
            blocks: None,
            blocked_by: None,
        }
    }

    fn external_draft(
        id: &str,
        status: CanonicalTaskStatus,
        priority: TaskPriority,
        blockers: &[&str],
    ) -> ExternalTaskDraft {
        ExternalTaskDraft {
            external_id: id.to_string(),
            observed_version: format!("version-{id}"),
            subject: format!("external {id}"),
            description: String::new(),
            status,
            priority,
            blocked_by_external_ids: blockers
                .iter()
                .map(|blocker| (*blocker).to_string())
                .collect(),
        }
    }

    fn external_task_ids(graph: &TaskGraph) -> BTreeMap<String, TaskId> {
        graph
            .all_tasks()
            .filter_map(|task| match &task.source {
                TaskSource::ExternalIssue { external_id, .. } => {
                    Some((external_id.clone(), task.id.clone()))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn failed_combined_cycle_update_leaves_graph_byte_exact() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("session-cycle").expect("graph");
        let (first, second) = create_two(&mut graph, &actor);
        let before = serde_json::to_vec(&graph).expect("encode before");
        let mut update = update_for(&graph, first);
        update.blocks = Some(BTreeSet::from([second.clone()]));
        update.blocked_by = Some(BTreeSet::from([second]));

        assert!(matches!(
            graph.update(update, &actor, at(3)),
            Err(TaskGraphError::Cycle)
        ));
        assert_eq!(serde_json::to_vec(&graph).expect("encode after"), before);
    }

    #[test]
    fn external_projection_is_stable_read_only_and_drives_ranked_readiness() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("external-ranking").expect("graph");
        let initial = vec![
            external_draft("1", CanonicalTaskStatus::Pending, TaskPriority::Medium, &[]),
            external_draft(
                "2",
                CanonicalTaskStatus::Pending,
                TaskPriority::Critical,
                &["1"],
            ),
            external_draft("3", CanonicalTaskStatus::Pending, TaskPriority::High, &[]),
        ];
        let (projected, first_receipt) = graph
            .propose_reconcile_external(
                ReconcileExternalTasks {
                    expected_generation: graph.generation(),
                    system: "crosslink".to_string(),
                    items: initial.clone(),
                },
                &actor,
                at(1),
            )
            .expect("initial reconcile")
            .into_parts();
        graph = projected;
        assert_eq!(first_receipt.affected.len(), 3);

        let external_ids = external_task_ids(&graph);
        let ready = graph.ready(10).expect("ready page");
        assert_eq!(
            ready
                .tasks
                .iter()
                .map(|task| task.id.clone())
                .collect::<Vec<_>>(),
            vec![external_ids["3"].clone(), external_ids["1"].clone()]
        );

        let mut closed = initial;
        closed[0].status = CanonicalTaskStatus::Completed;
        closed[0].observed_version = "version-1-closed".to_string();
        let (projected, _) = graph
            .propose_reconcile_external(
                ReconcileExternalTasks {
                    expected_generation: graph.generation(),
                    system: "crosslink".to_string(),
                    items: closed.clone(),
                },
                &actor,
                at(2),
            )
            .expect("closed reconcile")
            .into_parts();
        graph = projected;
        let completed = graph.task(&external_ids["1"]).expect("completed issue");
        assert_eq!(completed.completed_at, Some(at(2)));
        assert_eq!(completed.terminal_at, Some(at(2)));
        assert_eq!(
            graph
                .ready(10)
                .expect("ready after close")
                .tasks
                .iter()
                .map(|task| task.id.clone())
                .collect::<Vec<_>>(),
            vec![external_ids["2"].clone(), external_ids["3"].clone()]
        );

        let before_noop = serde_json::to_vec(&graph).expect("before no-op");
        let noop = graph
            .propose_reconcile_external(
                ReconcileExternalTasks {
                    expected_generation: graph.generation(),
                    system: "crosslink".to_string(),
                    items: closed,
                },
                &actor,
                at(3),
            )
            .expect("no-op reconcile");
        assert_eq!(noop.receipt().generation, graph.generation());
        assert!(noop.receipt().affected.is_empty());
        assert_eq!(
            serde_json::to_vec(noop.graph()).expect("no-op graph"),
            before_noop
        );

        let before_direct_update = serde_json::to_vec(&graph).expect("before direct update");
        let update = update_for(&graph, external_ids["2"].clone());
        assert!(matches!(
            graph.update(update, &actor, at(4)),
            Err(TaskGraphError::ExternalProjectionReadOnly { .. })
        ));
        assert_eq!(
            serde_json::to_vec(&graph).expect("after direct update"),
            before_direct_update
        );
    }

    #[test]
    fn external_cycle_and_incomplete_dependency_closure_leave_graph_byte_exact() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let graph = TaskGraph::new("external-invalid").expect("graph");
        let before = serde_json::to_vec(&graph).expect("before");
        let cycle = vec![
            external_draft(
                "1",
                CanonicalTaskStatus::Pending,
                TaskPriority::Medium,
                &["2"],
            ),
            external_draft(
                "2",
                CanonicalTaskStatus::Pending,
                TaskPriority::Medium,
                &["1"],
            ),
        ];
        assert!(matches!(
            graph.propose_reconcile_external(
                ReconcileExternalTasks {
                    expected_generation: graph.generation(),
                    system: "crosslink".to_string(),
                    items: cycle,
                },
                &actor,
                at(1)
            ),
            Err(TaskGraphError::Cycle)
        ));
        let missing = vec![external_draft(
            "1",
            CanonicalTaskStatus::Pending,
            TaskPriority::Medium,
            &["missing"],
        )];
        assert!(matches!(
            graph.propose_reconcile_external(
                ReconcileExternalTasks {
                    expected_generation: graph.generation(),
                    system: "crosslink".to_string(),
                    items: missing,
                },
                &actor,
                at(1)
            ),
            Err(TaskGraphError::InvalidField {
                field: "external blocker id",
                ..
            })
        ));
        assert_eq!(serde_json::to_vec(&graph).expect("after"), before);
    }

    #[test]
    fn approved_plan_digest_has_stable_lifecycle_without_parsing_prose() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("approved-plan").expect("graph");
        let ordinary = graph
            .create(create_input(graph.generation(), "ordinary"), &actor, at(1))
            .expect("ordinary create")
            .affected[0]
            .clone();
        let mut start = update_for(&graph, ordinary.clone());
        start.status = Some(CanonicalTaskStatus::InProgress);
        graph.update(start, &actor, at(2)).expect("ordinary start");

        let (projected, receipt) = graph
            .propose_reconcile_approved_plan(
                ReconcileApprovedPlan {
                    expected_generation: graph.generation(),
                    plan_id: "plan-session-1".to_string(),
                    observed_version: "a".repeat(64),
                },
                &actor,
                at(3),
            )
            .expect("approved plan")
            .into_parts();
        graph = projected;
        assert_eq!(receipt.affected.len(), 2);
        assert_eq!(
            graph.task(&ordinary).expect("ordinary task").status,
            CanonicalTaskStatus::Pending
        );
        let plan_id = graph
            .all_tasks()
            .find_map(|task| {
                matches!(task.source, TaskSource::Plan { .. }).then_some(task.id.clone())
            })
            .expect("plan task");
        let plan = graph.task(&plan_id).expect("plan task");
        assert_eq!(plan.status, CanonicalTaskStatus::InProgress);
        assert!(plan.description.is_empty(), "plan prose must not be copied");

        let before_noop = serde_json::to_vec(&graph).expect("before no-op");
        let noop = graph
            .propose_reconcile_approved_plan(
                ReconcileApprovedPlan {
                    expected_generation: graph.generation(),
                    plan_id: "plan-session-1".to_string(),
                    observed_version: "a".repeat(64),
                },
                &actor,
                at(4),
            )
            .expect("same approved plan");
        assert!(noop.receipt().affected.is_empty());
        assert_eq!(
            serde_json::to_vec(noop.graph()).expect("no-op graph"),
            before_noop
        );

        let mut complete = update_for(&graph, plan_id.clone());
        complete.status = Some(CanonicalTaskStatus::Completed);
        graph
            .update(complete, &actor, at(5))
            .expect("complete approved plan");
        let completed_generation = graph.generation();
        let same_completed = graph
            .propose_reconcile_approved_plan(
                ReconcileApprovedPlan {
                    expected_generation: graph.generation(),
                    plan_id: "plan-session-1".to_string(),
                    observed_version: "a".repeat(64),
                },
                &actor,
                at(6),
            )
            .expect("same completed plan");
        assert_eq!(same_completed.receipt().generation, completed_generation);
        assert_eq!(
            same_completed.graph().task(&plan_id).expect("plan").status,
            CanonicalTaskStatus::Completed
        );

        let (revised, _) = graph
            .propose_reconcile_approved_plan(
                ReconcileApprovedPlan {
                    expected_generation: graph.generation(),
                    plan_id: "plan-session-1".to_string(),
                    observed_version: "b".repeat(64),
                },
                &actor,
                at(7),
            )
            .expect("revised plan")
            .into_parts();
        assert_eq!(
            revised.task(&plan_id).expect("same stable plan id").status,
            CanonicalTaskStatus::InProgress
        );
        assert!(matches!(
            &revised.task(&plan_id).expect("plan").source,
            TaskSource::Plan { observed_version, .. } if observed_version == &"b".repeat(64)
        ));
    }

    #[test]
    fn todo_view_cannot_delete_or_rewrite_plan_and_delegation_lifecycles() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("todo-view-boundary").expect("graph");
        let (with_plan, _) = graph
            .propose_reconcile_approved_plan(
                ReconcileApprovedPlan {
                    expected_generation: graph.generation(),
                    plan_id: "plan-session".to_string(),
                    observed_version: "a".repeat(64),
                },
                &actor,
                at(1),
            )
            .expect("plan")
            .into_parts();
        graph = with_plan;
        let plan = graph
            .all_tasks()
            .find(|task| matches!(task.source, TaskSource::Plan { .. }))
            .expect("plan task")
            .clone();

        let empty = graph
            .propose_replace_todos(
                ReplaceTodoList {
                    expected_generation: graph.generation(),
                    items: Vec::new(),
                },
                &actor,
                at(2),
            )
            .expect("empty todo view");
        assert!(empty.receipt().affected.is_empty());
        assert_eq!(empty.graph().task(&plan.id), Some(&plan));

        let before = serde_json::to_vec(&graph).expect("before forged todo");
        let forged = TodoTaskDraft {
            task_id: Some(plan.id.clone()),
            expected_task_revision: Some(plan.revision),
            content: "rewrite plan lifecycle".to_string(),
            status: CanonicalTaskStatus::Completed,
            active_form: "Rewriting plan lifecycle".to_string(),
        };
        assert!(matches!(
            graph.propose_replace_todos(
                ReplaceTodoList {
                    expected_generation: graph.generation(),
                    items: vec![forged],
                },
                &actor,
                at(2)
            ),
            Err(TaskGraphError::ForeignTodoTask { .. })
        ));
        assert_eq!(
            serde_json::to_vec(&graph).expect("after forged todo"),
            before
        );
    }

    #[test]
    fn identical_terminal_todo_replacement_is_byte_exact_noop() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let graph = TaskGraph::new("todo-terminal-noop").expect("graph");
        let (graph, _) = graph
            .propose_replace_todos(
                ReplaceTodoList {
                    expected_generation: graph.generation(),
                    items: vec![TodoTaskDraft {
                        task_id: None,
                        expected_task_revision: None,
                        content: "completed work".to_string(),
                        status: CanonicalTaskStatus::Completed,
                        active_form: "Completing work".to_string(),
                    }],
                },
                &actor,
                at(1),
            )
            .expect("create completed todo")
            .into_parts();
        let task = graph.all_tasks().next().expect("completed task").clone();
        let replacement = TodoTaskDraft {
            task_id: Some(task.id.clone()),
            expected_task_revision: Some(task.revision),
            content: task.subject.clone(),
            status: task.status,
            active_form: task.active_form.clone().expect("active form"),
        };
        let before = serde_json::to_vec(&graph).expect("before no-op");
        let noop = graph
            .propose_replace_todos(
                ReplaceTodoList {
                    expected_generation: graph.generation(),
                    items: vec![replacement.clone()],
                },
                &actor,
                at(2),
            )
            .expect("identical replacement");
        assert!(noop.receipt().affected.is_empty());
        assert_eq!(noop.receipt().generation, graph.generation());
        assert_eq!(serde_json::to_vec(noop.graph()).expect("no-op"), before);

        let mut changed = replacement;
        changed.content = "completed work with corrected label".to_string();
        let changed = graph
            .propose_replace_todos(
                ReplaceTodoList {
                    expected_generation: graph.generation(),
                    items: vec![changed],
                },
                &actor,
                at(3),
            )
            .expect("content correction");
        let changed_task = changed.graph().task(&task.id).expect("changed task");
        assert_eq!(changed_task.revision, task.revision + 1);
        assert_eq!(changed_task.completed_at, task.completed_at);
        assert_eq!(changed_task.terminal_at, task.terminal_at);
    }

    #[test]
    fn resumed_session_reuses_todo_ownership_and_active_lane_without_cross_session_access() {
        let actor_for = |session_id: &str| {
            TaskActor::with_session(
                Actor {
                    id: ActorId::new(),
                    role: ActorRole::Planner,
                },
                RunId::new(),
                session_id,
            )
        };
        let first_run = actor_for("stable-session");
        let resumed_run = actor_for("stable-session");
        let foreign_run = actor_for("other-session");
        let graph = TaskGraph::new("resume-ownership").expect("graph");
        let (mut graph, _) = graph
            .propose_replace_todos(
                ReplaceTodoList {
                    expected_generation: graph.generation(),
                    items: vec![TodoTaskDraft {
                        task_id: None,
                        expected_task_revision: None,
                        content: "resumable todo".to_string(),
                        status: CanonicalTaskStatus::InProgress,
                        active_form: "Resuming todo".to_string(),
                    }],
                },
                &first_run,
                at(1),
            )
            .expect("first run todo")
            .into_parts();
        let todo = graph.all_tasks().next().expect("todo").clone();
        let replacement = TodoTaskDraft {
            task_id: Some(todo.id.clone()),
            expected_task_revision: Some(todo.revision),
            content: todo.subject.clone(),
            status: todo.status,
            active_form: todo.active_form.clone().expect("active form"),
        };
        let resumed = graph
            .propose_replace_todos(
                ReplaceTodoList {
                    expected_generation: graph.generation(),
                    items: vec![replacement.clone()],
                },
                &resumed_run,
                at(2),
            )
            .expect("resumed view owns the same session lane");
        assert!(resumed.receipt().affected.is_empty());

        let before_foreign = serde_json::to_vec(&graph).expect("before foreign view");
        assert!(matches!(
            graph.propose_replace_todos(
                ReplaceTodoList {
                    expected_generation: graph.generation(),
                    items: vec![replacement],
                },
                &foreign_run,
                at(2),
            ),
            Err(TaskGraphError::ForeignTodoTask { .. })
        ));
        assert_eq!(
            serde_json::to_vec(&graph).expect("after foreign view"),
            before_foreign
        );

        let next = graph
            .create(
                create_input(graph.generation(), "resumed active task"),
                &resumed_run,
                at(3),
            )
            .expect("resumed task create")
            .affected[0]
            .clone();
        let mut start = update_for(&graph, next.clone());
        start.status = Some(CanonicalTaskStatus::InProgress);
        graph
            .update(start, &resumed_run, at(4))
            .expect("resume start");
        assert_eq!(
            graph.task(&todo.id).expect("prior active todo").status,
            CanonicalTaskStatus::Pending
        );
        assert_eq!(
            graph.task(&next).expect("resumed active task").status,
            CanonicalTaskStatus::InProgress
        );

        let before_foreign_update = serde_json::to_vec(&graph).expect("before foreign update");
        assert!(matches!(
            graph.propose_update(update_for(&graph, next), &foreign_run, at(5)),
            Err(TaskGraphError::ForeignTask { .. })
        ));
        assert_eq!(
            serde_json::to_vec(&graph).expect("after foreign update"),
            before_foreign_update
        );
    }

    #[test]
    fn delegation_lifecycle_requires_exact_supervised_agent_binding() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("delegation-binding").expect("graph");
        let mut create = create_input(graph.generation(), "delegated work");
        create.status = CanonicalTaskStatus::InProgress;
        create.source = TaskSource::Delegation {
            agent_id: "agent-1".to_string(),
        };
        let delegation_id = graph
            .create(create, &actor, at(1))
            .expect("delegation create")
            .affected[0]
            .clone();
        let before = serde_json::to_vec(&graph).expect("before forged transition");
        let mut complete = update_for(&graph, delegation_id.clone());
        complete.status = Some(CanonicalTaskStatus::Completed);
        assert!(matches!(
            graph.propose_update(complete.clone(), &actor, at(2)),
            Err(TaskGraphError::DelegationProjectionReadOnly { .. })
        ));
        assert!(matches!(
            graph.propose_update_delegation(complete.clone(), &actor, at(2), "agent-2"),
            Err(TaskGraphError::DelegationProjectionReadOnly { .. })
        ));
        let mut delete = complete.clone();
        delete.status = Some(CanonicalTaskStatus::Deleted);
        assert!(matches!(
            graph.propose_update_delegation(delete, &actor, at(2), "agent-1"),
            Err(TaskGraphError::InvalidField {
                field: "delegation status",
                ..
            })
        ));
        assert_eq!(
            serde_json::to_vec(&graph).expect("after forged transition"),
            before
        );

        let (completed, _) = graph
            .propose_update_delegation(complete, &actor, at(2), "agent-1")
            .expect("bound transition")
            .into_parts();
        assert_eq!(
            completed
                .task(&delegation_id)
                .expect("delegation task")
                .status,
            CanonicalTaskStatus::Completed
        );
    }

    #[test]
    fn projection_sources_reject_forged_creation_and_persisted_execution_state() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let graph = TaskGraph::new("projection-invariants").expect("graph");

        let mut pending_delegation = create_input(graph.generation(), "delegated work");
        pending_delegation.source = TaskSource::Delegation {
            agent_id: "agent-1".to_string(),
        };
        assert!(matches!(
            graph.propose_create(pending_delegation, &actor, at(1)),
            Err(TaskGraphError::InvalidField {
                field: "initial delegation status",
                ..
            })
        ));

        let mut direct_external = create_input(graph.generation(), "external work");
        direct_external.source = TaskSource::ExternalIssue {
            system: "crosslink".to_string(),
            external_id: "42".to_string(),
            observed_version: "version-42".to_string(),
        };
        assert!(matches!(
            graph.propose_create(direct_external, &actor, at(1)),
            Err(TaskGraphError::InvalidField {
                field: "initial task source",
                ..
            })
        ));

        let (projected, _) = graph
            .propose_reconcile_external(
                ReconcileExternalTasks {
                    expected_generation: graph.generation(),
                    system: "crosslink".to_string(),
                    items: vec![external_draft(
                        "42",
                        CanonicalTaskStatus::Pending,
                        TaskPriority::High,
                        &[],
                    )],
                },
                &actor,
                at(1),
            )
            .expect("external projection")
            .into_parts();
        let external_id = external_task_ids(&projected)["42"].clone();
        let mutations: [fn(&mut TaskNode); 3] = [
            |task| task.status = CanonicalTaskStatus::InProgress,
            |task| task.active_form = Some("Forged work".to_string()),
            |task| {
                task.budget = Some(TaskBudgetSpec {
                    max_turns: Some(1),
                    max_tokens: None,
                    max_elapsed_millis: None,
                    max_cost_microusd: None,
                    max_child_runs: None,
                    max_concurrent_calls: None,
                });
            },
        ];

        for mutate in mutations {
            let mut forged = projected.clone();
            mutate(forged.tasks.get_mut(&external_id).expect("external task"));
            assert!(matches!(
                forged.validate(),
                Err(TaskGraphError::Invariant { .. })
            ));
        }
    }

    #[test]
    fn same_call_blocker_prevents_in_progress_without_partial_demotion() {
        let actor = TaskActor::fixture(ActorRole::Worker);
        let mut graph = TaskGraph::new("session-blocker").expect("graph");
        let (first, second) = create_two(&mut graph, &actor);
        let mut start_first = update_for(&graph, first.clone());
        start_first.status = Some(CanonicalTaskStatus::InProgress);
        graph
            .update(start_first, &actor, at(3))
            .expect("start first");

        let before = serde_json::to_vec(&graph).expect("encode before");
        let mut blocked_start = update_for(&graph, second);
        blocked_start.status = Some(CanonicalTaskStatus::InProgress);
        blocked_start.blocked_by = Some(BTreeSet::from([first]));
        assert!(matches!(
            graph.update(blocked_start, &actor, at(4)),
            Err(TaskGraphError::Blocked { .. })
        ));
        assert_eq!(serde_json::to_vec(&graph).expect("encode after"), before);
    }

    #[test]
    fn deletion_removes_edges_but_retains_tombstone_and_history() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("session-delete").expect("graph");
        let (first, second) = create_two(&mut graph, &actor);
        let mut edge = update_for(&graph, first.clone());
        edge.blocks = Some(BTreeSet::from([second.clone()]));
        graph.update(edge, &actor, at(3)).expect("add edge");

        let mut delete = update_for(&graph, first.clone());
        delete.status = Some(CanonicalTaskStatus::Deleted);
        graph.update(delete, &actor, at(4)).expect("delete");

        assert!(graph.task(&first).is_none());
        assert!(graph
            .all_tasks()
            .find(|task| task.id == first)
            .is_some_and(|task| task.status == CanonicalTaskStatus::Deleted));
        assert!(graph.task(&second).expect("second").blocked_by.is_empty());
        assert_eq!(graph.history.len(), 4);
        graph.validate().expect("valid graph");
    }

    #[test]
    fn stale_graph_and_task_versions_leave_state_unchanged() {
        let actor = TaskActor::fixture(ActorRole::Worker);
        let mut graph = TaskGraph::new("session-stale").expect("graph");
        let task = graph
            .create(create_input(graph.generation(), "task"), &actor, at(1))
            .expect("create")
            .affected[0]
            .clone();
        let before = serde_json::to_vec(&graph).expect("before");

        let mut stale_graph = update_for(&graph, task.clone());
        stale_graph.expected_generation = TaskGraphGeneration::initial();
        assert!(matches!(
            graph.update(stale_graph, &actor, at(2)),
            Err(TaskGraphError::StaleGraph { .. })
        ));

        let mut stale_task = update_for(&graph, task);
        stale_task.expected_task_revision = 99;
        assert!(matches!(
            graph.update(stale_task, &actor, at(2)),
            Err(TaskGraphError::StaleTask { .. })
        ));
        assert_eq!(serde_json::to_vec(&graph).expect("after"), before);
    }

    #[test]
    fn one_active_task_per_actor_lane_allows_parallel_workers() {
        let first_actor = TaskActor::fixture(ActorRole::Worker);
        let second_actor = TaskActor::fixture(ActorRole::Worker);
        let mut graph = TaskGraph::new("session-parallel").expect("graph");
        let first = graph
            .create(
                create_input(graph.generation(), "first"),
                &first_actor,
                at(1),
            )
            .expect("first")
            .affected[0]
            .clone();
        let second = graph
            .create(
                create_input(graph.generation(), "second"),
                &second_actor,
                at(2),
            )
            .expect("second")
            .affected[0]
            .clone();
        let mut start_first = update_for(&graph, first.clone());
        start_first.status = Some(CanonicalTaskStatus::InProgress);
        graph
            .update(start_first, &first_actor, at(3))
            .expect("start first");
        let mut start_second = update_for(&graph, second.clone());
        start_second.status = Some(CanonicalTaskStatus::InProgress);
        graph
            .update(start_second, &second_actor, at(4))
            .expect("start second");

        assert_eq!(
            graph.task(&first).expect("first").status,
            CanonicalTaskStatus::InProgress
        );
        assert_eq!(
            graph.task(&second).expect("second").status,
            CanonicalTaskStatus::InProgress
        );
        graph.validate().expect("parallel lanes valid");
    }

    #[test]
    fn pagination_is_bounded_and_generation_bound() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("session-page").expect("graph");
        create_two(&mut graph, &actor);
        let first = graph.page(None, 1).expect("first page");
        assert_eq!(first.tasks.len(), 1);
        let cursor = first.next.expect("next cursor");
        assert_eq!(
            TaskPageCursor::parse(&cursor.encode()).expect("cursor round trip"),
            cursor
        );
        assert!(matches!(
            TaskPageCursor::parse("v2:1:1"),
            Err(TaskGraphError::InvalidCursor)
        ));
        let second = graph.page(Some(cursor), 1).expect("second page");
        assert_eq!(second.tasks.len(), 1);
        assert!(second.next.is_none());

        graph
            .create(create_input(graph.generation(), "third"), &actor, at(3))
            .expect("third");
        assert!(matches!(
            graph.page(Some(cursor), 1),
            Err(TaskGraphError::StaleCursor { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_safe_store_rejects_stale_publication_and_loads_exact_graph() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temp root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let store =
            TaskGraphStore::open(root.path(), "tasks.json", "session-store").expect("open store");
        let first_snapshot = store.load().expect("missing snapshot");
        let second_snapshot = store.load().expect("second missing snapshot");
        let actor = TaskActor::fixture(ActorRole::Planner);
        let proposal = first_snapshot
            .graph
            .propose_create(
                create_input(first_snapshot.graph.generation(), "persisted"),
                &actor,
                at(1),
            )
            .expect("proposal");
        store
            .commit(first_snapshot.storage_generation, proposal.graph())
            .expect("first commit");

        let stale_proposal = second_snapshot
            .graph
            .propose_create(
                create_input(second_snapshot.graph.generation(), "stale writer"),
                &actor,
                at(2),
            )
            .expect("stale proposal");

        assert!(matches!(
            store.commit(second_snapshot.storage_generation, stale_proposal.graph()),
            Err(TaskGraphError::Persistence(
                PersistenceError::Conflict { .. }
            ))
        ));
        let loaded = store.load().expect("loaded");
        assert_eq!(loaded.graph, *proposal.graph());
    }

    #[cfg(unix)]
    #[test]
    fn malformed_or_future_persisted_graph_fails_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("temp root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let storage = PersistentStorage::open(root.path()).expect("storage");
        let malformed_receipt = storage
            .commit(
                "tasks.json",
                FileClass::State,
                StorageGeneration::Missing,
                br#"{"schema_version":1}"#,
            )
            .expect("seed malformed");
        let store =
            TaskGraphStore::open(root.path(), "tasks.json", "session-store").expect("open store");
        assert!(matches!(store.load(), Err(TaskGraphError::InvalidJson)));

        let mut future =
            serde_json::to_value(TaskGraph::new("session-store").expect("valid current graph"))
                .expect("encode future fixture");
        future["schema_version"] = serde_json::json!(999);
        storage
            .commit(
                "tasks.json",
                FileClass::State,
                malformed_receipt.generation(),
                serde_json::to_vec(&future).expect("encode future bytes"),
            )
            .expect("seed future");
        assert!(matches!(
            store.load(),
            Err(TaskGraphError::UnsupportedSchema {
                observed: 999,
                expected: TASK_GRAPH_SCHEMA_VERSION
            })
        ));
    }

    #[test]
    fn reciprocal_edge_mutations_advance_every_revision_and_receipt() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("session-revisions").expect("graph");
        let (first, second) = create_two(&mut graph, &actor);
        let first_revision = graph.task(&first).expect("first").revision;
        let second_revision = graph.task(&second).expect("second").revision;
        let mut edge = update_for(&graph, first.clone());
        edge.blocks = Some(BTreeSet::from([second.clone()]));
        let receipt = graph.update(edge, &actor, at(3)).expect("add edge");

        assert_eq!(
            graph.task(&first).expect("first").revision,
            first_revision + 1
        );
        assert_eq!(
            graph.task(&second).expect("second").revision,
            second_revision + 1
        );
        assert_eq!(receipt.affected, vec![first, second]);
    }

    #[test]
    fn long_running_history_compacts_to_a_causal_bounded_checkpoint() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("session-history-checkpoint").expect("graph");
        let task = graph
            .create(
                create_input(graph.generation(), "long-running task"),
                &actor,
                at(1),
            )
            .expect("create")
            .affected[0]
            .clone();

        for iteration in 0..MAX_HISTORY_EVENTS {
            let mut update = update_for(&graph, task.clone());
            update.description = FieldUpdate::Set(format!("checkpoint event {iteration}"));
            graph.update(update, &actor, at(2)).expect("update");
        }

        assert_eq!(graph.history().len(), MAX_HISTORY_EVENTS);
        assert_eq!(graph.history_checkpoint().event_count(), 1);
        assert_eq!(graph.history_checkpoint().through_generation().get(), 1);
        assert_ne!(
            graph.history_checkpoint().chain_digest(),
            "0".repeat(HISTORY_DIGEST_HEX_BYTES)
        );
        assert_eq!(graph.history()[0].generation.get(), 2);
        assert_eq!(
            graph.history().last().expect("history tail").generation,
            graph.generation()
        );
        graph.validate().expect("checkpointed graph remains valid");

        let encoded = serde_json::to_vec(&graph).expect("encode");
        let round_trip: TaskGraph = serde_json::from_slice(&encoded).expect("decode");
        assert_eq!(round_trip, graph);
        round_trip.validate().expect("round-trip validates");
    }

    #[test]
    fn semantic_noop_update_preserves_graph_bytes_generation_and_history() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("semantic-noop").expect("graph");
        let task = graph
            .create(create_input(graph.generation(), "stable"), &actor, at(1))
            .expect("create")
            .affected[0]
            .clone();
        let before = serde_json::to_vec(&graph).expect("before");
        let receipt = graph
            .update(update_for(&graph, task), &actor, at(2))
            .expect("no-op update");
        assert!(receipt.affected.is_empty());
        assert_eq!(receipt.previous_generation, receipt.generation);
        assert_eq!(serde_json::to_vec(&graph).expect("after"), before);
    }

    #[test]
    fn task_budget_is_bounded_and_can_be_cleared_without_authority() {
        let actor = TaskActor::fixture(ActorRole::Planner);
        let mut graph = TaskGraph::new("session-task-budget").expect("graph");
        let before = serde_json::to_vec(&graph).expect("before");
        let mut invalid = create_input(graph.generation(), "invalid budget");
        invalid.budget = Some(TaskBudgetSpec {
            max_turns: None,
            max_tokens: None,
            max_elapsed_millis: None,
            max_cost_microusd: None,
            max_child_runs: None,
            max_concurrent_calls: None,
        });
        assert!(matches!(
            graph.create(invalid, &actor, at(1)),
            Err(TaskGraphError::InvalidField {
                field: "task budget",
                ..
            })
        ));
        assert_eq!(serde_json::to_vec(&graph).expect("unchanged"), before);

        let budget = TaskBudgetSpec {
            max_turns: Some(32),
            max_tokens: Some(100_000),
            max_elapsed_millis: Some(60_000),
            max_cost_microusd: Some(500_000),
            max_child_runs: Some(4),
            max_concurrent_calls: Some(2),
        };
        let mut create = create_input(graph.generation(), "bounded task");
        create.budget = Some(budget.clone());
        let task = graph
            .create(create, &actor, at(2))
            .expect("bounded task")
            .affected[0]
            .clone();
        assert_eq!(graph.task(&task).expect("task").budget, Some(budget));

        let mut clear = update_for(&graph, task.clone());
        clear.budget = FieldUpdate::Clear;
        graph.update(clear, &actor, at(3)).expect("clear budget");
        assert!(graph.task(&task).expect("task").budget.is_none());
    }
}

//! Compatibility facade over the canonical transactional task graph.
//!
//! Existing tool and frontend callers keep the `TaskManager` vocabulary while
//! every operation reads and writes [`crate::task_graph::TaskGraph`]. There is
//! no second task representation inside this manager: [`Task`] values are
//! rebuilt read-only projections after a graph commit.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::persistence::{CommitState, StorageGeneration};
use crate::runtime::{Actor, ActorId, ActorRole, RunId};
use crate::task_graph::{
    CanonicalTaskStatus, CreateTask, ExternalTaskDraft, FieldUpdate, ReconcileApprovedPlan,
    ReconcileExternalTasks, TaskActor, TaskBudgetSpec, TaskGraph, TaskGraphGeneration,
    TaskGraphProposal, TaskGraphReceipt, TaskGraphStore, TaskId, TaskNode, TaskOwnership,
    TaskPageCursor, TaskPriority, TaskSource, TodoTaskDraft, UpdateTask,
};

/// Status exposed by the established task-tool compatibility surface.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Canceled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => formatter.write_str("pending"),
            Self::InProgress => formatter.write_str("in_progress"),
            Self::Completed => formatter.write_str("completed"),
            Self::Failed => formatter.write_str("failed"),
            Self::Canceled => formatter.write_str("canceled"),
        }
    }
}

/// Read-only compatibility projection of one canonical task node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub id: String,
    pub subject: String,
    pub description: String,
    pub active_form: Option<String>,
    pub status: TaskStatus,
    pub priority: TaskPriority,
    pub blocks: Vec<String>,
    pub blocked_by: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub terminal_at: Option<DateTime<Utc>>,
    pub revision: u64,
    pub ownership: TaskOwnership,
    pub source: TaskSource,
    pub budget: Option<TaskBudgetSpec>,
}

/// Status values accepted by task updates. `Deleted` creates a canonical
/// tombstone and transactionally removes reciprocal edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskUpdateStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Canceled,
    Deleted,
}

impl TaskUpdateStatus {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "in_progress" => Some(Self::InProgress),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "canceled" => Some(Self::Canceled),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// Parameters for a graph-aware task update.
#[derive(Debug, Clone, Default)]
pub struct TaskUpdateParams {
    pub status: Option<TaskUpdateStatus>,
    pub priority: Option<TaskPriority>,
    pub subject: Option<String>,
    pub description: Option<String>,
    pub active_form: Option<String>,
    pub clear_active_form: bool,
    pub budget: Option<TaskBudgetSpec>,
    pub clear_budget: bool,
    pub add_blocks: Option<Vec<String>>,
    pub remove_blocks: Option<Vec<String>>,
    pub add_blocked_by: Option<Vec<String>>,
    pub remove_blocked_by: Option<Vec<String>>,
    /// Required by model-facing mutations. Omission is retained only for
    /// direct compatibility callers operating on the manager they just read.
    pub expected_generation: Option<TaskGraphGeneration>,
    /// Required by model-facing updates. Omission uses the current task
    /// revision only for direct compatibility callers.
    pub expected_task_revision: Option<u64>,
}

/// Last committed mutation receipt exposed to adapters and tool renderers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskManagerReceipt {
    pub graph: TaskGraphReceipt,
    pub persistence: Option<CommitState>,
}

/// Bounded task-list page carrying an opaque generation-bound cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskManagerPage {
    pub tasks: Vec<Task>,
    pub next_cursor: Option<String>,
    pub generation: TaskGraphGeneration,
}

/// Established manager name backed by exactly one canonical graph.
#[derive(Debug, Clone)]
pub struct TaskManager {
    graph: TaskGraph,
    actor: TaskActor,
    projection: Vec<Task>,
    store: Option<TaskGraphStore>,
    storage_generation: StorageGeneration,
    last_receipt: Option<TaskManagerReceipt>,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskManager {
    /// Create an ephemeral compatibility manager. Production frontends should
    /// use [`Self::for_run`] or [`Self::open`] so provenance and persistence
    /// are explicit.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: TaskGraph::empty_for_compatibility(),
            actor: TaskActor::new(
                Actor {
                    id: ActorId::new(),
                    role: ActorRole::Planner,
                },
                RunId::new(),
            ),
            projection: Vec::new(),
            store: None,
            storage_generation: StorageGeneration::Missing,
            last_receipt: None,
        }
    }

    /// Create an ephemeral manager bound to one immutable run identity.
    ///
    /// # Errors
    /// Returns an error when the run's session identity is not a valid graph
    /// identity.
    pub fn for_run(run: &crate::tools::ToolRunContext) -> Result<Self, String> {
        let graph = TaskGraph::new(format!("session:{}", run.session_id()))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            graph,
            actor: TaskActor::from_run(run),
            projection: Vec::new(),
            store: None,
            storage_generation: StorageGeneration::Missing,
            last_receipt: None,
        })
    }

    /// Open a descriptor-safe graph document under an existing host-authorized
    /// root and reject malformed, future, or identity-mismatched state.
    ///
    /// # Errors
    /// Returns an error when the root, graph identity, or persisted document
    /// fails validation or cannot be read.
    pub fn open(
        root: impl AsRef<Path>,
        target: impl Into<std::path::PathBuf>,
        graph_id: impl Into<String>,
        actor: TaskActor,
    ) -> Result<Self, String> {
        let store =
            TaskGraphStore::open(root, target, graph_id).map_err(|error| error.to_string())?;
        let loaded = store.load().map_err(|error| error.to_string())?;
        let mut manager = Self {
            graph: loaded.graph,
            actor,
            projection: Vec::new(),
            store: Some(store),
            storage_generation: loaded.storage_generation,
            last_receipt: None,
        };
        manager.rebuild_projection();
        Ok(manager)
    }

    /// Open the durable host-local graph for one exact frontend run. Every
    /// frontend uses the same session-derived document path, so resuming the
    /// same session reconciles through storage-generation conflicts instead
    /// of creating another in-memory planning store.
    ///
    /// # Errors
    /// Returns an error when the host-local data root is unavailable or not
    /// private, or when the durable graph cannot be opened and validated.
    pub fn open_for_run(run: &crate::tools::ToolRunContext) -> Result<Self, String> {
        let data_root = dirs::data_local_dir()
            .ok_or_else(|| "host-local data directory is unavailable".to_string())?
            .join("openclaudia")
            .join("task_graphs");
        prepare_private_graph_root(&data_root)?;
        let target = format!("{}.json", run.session_id());
        Self::open(
            &data_root,
            target,
            format!("session:{}", run.session_id()),
            TaskActor::from_run(run),
        )
    }

    #[must_use]
    pub const fn generation(&self) -> TaskGraphGeneration {
        self.graph.generation()
    }

    #[must_use]
    pub const fn graph(&self) -> &TaskGraph {
        &self.graph
    }

    #[must_use]
    pub const fn actor(&self) -> &TaskActor {
        &self.actor
    }

    #[must_use]
    pub const fn last_receipt(&self) -> Option<&TaskManagerReceipt> {
        self.last_receipt.as_ref()
    }

    #[must_use]
    pub const fn is_durable(&self) -> bool {
        self.store.is_some()
    }

    /// Refresh a durable manager before a read or proposed mutation. Ephemeral
    /// managers are already the complete source of truth and do nothing.
    ///
    /// # Errors
    /// Returns an error when the persisted graph cannot be read or validated.
    pub fn refresh(&mut self) -> Result<(), String> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let loaded = store.load().map_err(|error| error.to_string())?;
        self.graph = loaded.graph;
        self.storage_generation = loaded.storage_generation;
        self.last_receipt = None;
        self.rebuild_projection();
        Ok(())
    }

    /// Create a task against the manager's currently observed generation.
    ///
    /// # Errors
    /// Returns an error when validation or durable publication fails.
    pub fn create_task(
        &mut self,
        subject: String,
        description: String,
        active_form: Option<String>,
    ) -> Result<&Task, String> {
        let expected = self.graph.generation();
        self.create_task_from_input(CreateTask {
            expected_generation: expected,
            subject,
            description,
            active_form,
            status: CanonicalTaskStatus::Pending,
            priority: TaskPriority::Medium,
            source: TaskSource::TaskTool,
            budget: None,
        })
    }

    /// Publish one host-constructed creation request. Model-facing task
    /// creation builds pending-only input above; trusted plan/delegation
    /// adapters use this seam to publish an already-running child or a
    /// reconciled terminal record without a second, racy mutation.
    ///
    /// # Errors
    /// Returns an error when the request is stale or invalid, or when durable
    /// publication fails.
    pub fn create_task_from_input(&mut self, input: CreateTask) -> Result<&Task, String> {
        self.refresh()?;
        let proposal = self
            .graph
            .propose_create(input, &self.actor, Utc::now())
            .map_err(|error| error.to_string())?;
        let id = proposal.receipt().affected[0].clone();
        self.publish(proposal)?;
        self.get_task(id.as_str())
            .ok_or_else(|| "committed task disappeared from the canonical projection".to_string())
    }

    /// Update a task transactionally. Every field and edge is applied to a
    /// cloned snapshot, the complete graph is validated, durable publication
    /// succeeds, and only then does the live projection change.
    ///
    /// # Errors
    /// Returns an error when the task is missing, the request is stale or
    /// invalid, or durable publication fails.
    pub fn update_task(
        &mut self,
        task_id: &str,
        params: TaskUpdateParams,
    ) -> Result<Option<&Task>, String> {
        if params.clear_budget && params.budget.is_some() {
            return Err("task budget replacement and clearing are mutually exclusive".to_string());
        }
        self.refresh()?;
        let id = TaskId::parse(task_id.to_string()).map_err(|error| error.to_string())?;
        let current = self
            .graph
            .task(&id)
            .ok_or_else(|| format!("Task '{task_id}' not found"))?;
        let expected_generation = params
            .expected_generation
            .unwrap_or_else(|| self.graph.generation());
        let expected_task_revision = params.expected_task_revision.unwrap_or(current.revision);
        let blocks = apply_edge_changes(
            &current.blocks,
            params.add_blocks.as_deref(),
            params.remove_blocks.as_deref(),
        )?;
        let blocked_by = apply_edge_changes(
            &current.blocked_by,
            params.add_blocked_by.as_deref(),
            params.remove_blocked_by.as_deref(),
        )?;
        let active_form = if params.clear_active_form {
            FieldUpdate::Clear
        } else {
            params
                .active_form
                .map_or(FieldUpdate::Keep, FieldUpdate::Set)
        };
        let status = params.status.map(canonical_status);
        let budget = if params.clear_budget {
            FieldUpdate::Clear
        } else {
            params.budget.map_or(FieldUpdate::Keep, FieldUpdate::Set)
        };
        let deleted = status == Some(CanonicalTaskStatus::Deleted);
        let proposal = self
            .graph
            .propose_update(
                UpdateTask {
                    expected_generation,
                    task_id: id,
                    expected_task_revision,
                    status,
                    priority: params.priority,
                    subject: params.subject.map_or(FieldUpdate::Keep, FieldUpdate::Set),
                    description: params
                        .description
                        .map_or(FieldUpdate::Keep, FieldUpdate::Set),
                    active_form,
                    budget,
                    blocks,
                    blocked_by,
                },
                &self.actor,
                Utc::now(),
            )
            .map_err(|error| error.to_string())?;
        if proposal.receipt().affected.is_empty()
            && proposal.receipt().generation == proposal.receipt().previous_generation
        {
            self.last_receipt = Some(TaskManagerReceipt {
                graph: proposal.receipt().clone(),
                persistence: None,
            });
            return Ok(self.get_task(task_id));
        }
        self.publish(proposal)?;
        if deleted {
            Ok(None)
        } else {
            Ok(self.get_task(task_id))
        }
    }

    /// Transition one exact supervised child lifecycle. General task/todo
    /// mutations cannot forge this projection because the stable agent id is
    /// checked against the task source before proposal construction.
    ///
    /// # Errors
    /// Returns an error for an unknown or mismatched delegation, stale
    /// revision, invalid transition, or failed durable publication.
    pub fn update_delegation_task(
        &mut self,
        task_id: &str,
        expected_agent_id: &str,
        expected_task_revision: Option<u64>,
        status: TaskUpdateStatus,
        budget: Option<TaskBudgetSpec>,
    ) -> Result<&Task, String> {
        self.refresh()?;
        let id = TaskId::parse(task_id.to_string()).map_err(|error| error.to_string())?;
        let current = self
            .graph
            .task(&id)
            .ok_or_else(|| format!("Task '{task_id}' not found"))?;
        let proposal = self
            .graph
            .propose_update_delegation(
                UpdateTask {
                    expected_generation: self.graph.generation(),
                    task_id: id,
                    expected_task_revision: expected_task_revision.unwrap_or(current.revision),
                    status: Some(canonical_status(status)),
                    priority: None,
                    subject: FieldUpdate::Keep,
                    description: FieldUpdate::Keep,
                    active_form: FieldUpdate::Keep,
                    budget: budget.map_or(FieldUpdate::Keep, FieldUpdate::Set),
                    blocks: None,
                    blocked_by: None,
                },
                &self.actor,
                Utc::now(),
                expected_agent_id,
            )
            .map_err(|error| error.to_string())?;
        if proposal.receipt().affected.is_empty()
            && proposal.receipt().generation == proposal.receipt().previous_generation
        {
            self.last_receipt = Some(TaskManagerReceipt {
                graph: proposal.receipt().clone(),
                persistence: None,
            });
            return self
                .get_task(task_id)
                .ok_or_else(|| "delegation task disappeared from the canonical view".to_string());
        }
        self.publish(proposal)?;
        self.get_task(task_id)
            .ok_or_else(|| "delegation task disappeared from the canonical view".to_string())
    }

    /// Atomically replace the caller's complete todo projection. Existing
    /// rows must carry stable task ids and revisions obtained from a read.
    ///
    /// # Errors
    /// Returns an error when the replacement is stale or invalid, or when
    /// durable publication fails.
    pub fn replace_todos_checked(
        &mut self,
        expected_generation: TaskGraphGeneration,
        items: Vec<TodoTaskDraft>,
    ) -> Result<(), String> {
        self.refresh()?;
        let proposal = self
            .graph
            .propose_replace_todos(
                crate::task_graph::ReplaceTodoList {
                    expected_generation,
                    items,
                },
                &self.actor,
                Utc::now(),
            )
            .map_err(|error| error.to_string())?;
        if proposal.receipt().affected.is_empty()
            && proposal.receipt().generation == proposal.receipt().previous_generation
        {
            self.last_receipt = Some(TaskManagerReceipt {
                graph: proposal.receipt().clone(),
                persistence: None,
            });
            return Ok(());
        }
        self.publish(proposal)
    }

    /// Reconcile a dependency-closed external issue observation into the
    /// canonical graph. The external identifiers remain provenance only.
    ///
    /// # Errors
    /// Returns an error when the observation is stale, incomplete, invalid,
    /// or cannot be durably published.
    pub fn reconcile_external_checked(
        &mut self,
        expected_generation: TaskGraphGeneration,
        system: String,
        items: Vec<ExternalTaskDraft>,
    ) -> Result<(), String> {
        self.refresh()?;
        let proposal = self
            .graph
            .propose_reconcile_external(
                ReconcileExternalTasks {
                    expected_generation,
                    system,
                    items,
                },
                &self.actor,
                Utc::now(),
            )
            .map_err(|error| error.to_string())?;
        if proposal.receipt().affected.is_empty()
            && proposal.receipt().generation == proposal.receipt().previous_generation
        {
            self.last_receipt = Some(TaskManagerReceipt {
                graph: proposal.receipt().clone(),
                persistence: None,
            });
            return Ok(());
        }
        self.publish(proposal)
    }

    /// Bind the exact digest of a host-read, user-approved plan artifact to a
    /// stable graph lifecycle checkpoint.
    ///
    /// # Errors
    /// Returns an error when the plan identity or digest is invalid, graph
    /// reconciliation fails, or durable publication fails.
    pub fn reconcile_approved_plan(
        &mut self,
        plan_id: &str,
        observed_version: String,
    ) -> Result<&Task, String> {
        self.refresh()?;
        let proposal = self
            .graph
            .propose_reconcile_approved_plan(
                ReconcileApprovedPlan {
                    expected_generation: self.graph.generation(),
                    plan_id: plan_id.to_string(),
                    observed_version,
                },
                &self.actor,
                Utc::now(),
            )
            .map_err(|error| error.to_string())?;
        let task_id = proposal
            .graph()
            .all_tasks()
            .find_map(|task| match &task.source {
                TaskSource::Plan {
                    plan_id: candidate, ..
                } if candidate == plan_id => Some(task.id.clone()),
                _ => None,
            })
            .ok_or_else(|| "approved plan projection disappeared".to_string())?;
        if proposal.receipt().affected.is_empty()
            && proposal.receipt().generation == proposal.receipt().previous_generation
        {
            self.last_receipt = Some(TaskManagerReceipt {
                graph: proposal.receipt().clone(),
                persistence: None,
            });
        } else {
            self.publish(proposal)?;
        }
        self.get_task(task_id.as_str())
            .ok_or_else(|| "approved plan task disappeared from the canonical view".to_string())
    }

    /// Return a bounded deterministic readiness ranking.
    ///
    /// # Errors
    /// Returns an error when `limit` exceeds the canonical page bound or the
    /// graph fails validation.
    pub fn ready_tasks(&self, limit: usize) -> Result<TaskManagerPage, String> {
        let page = self.graph.ready(limit).map_err(|error| error.to_string())?;
        Ok(TaskManagerPage {
            tasks: page.tasks.into_iter().filter_map(project_task).collect(),
            next_cursor: None,
            generation: page.generation,
        })
    }

    /// External ids already projected for one system. This supports bounded
    /// refresh without requiring an unbounded external history scan.
    #[must_use]
    pub fn projected_external_ids(&self, expected_system: &str) -> Vec<String> {
        self.graph
            .all_tasks()
            .filter_map(|task| match &task.source {
                TaskSource::ExternalIssue {
                    system,
                    external_id,
                    ..
                } if system == expected_system => Some(external_id.clone()),
                _ => None,
            })
            .collect()
    }

    #[must_use]
    pub fn get_task(&self, task_id: &str) -> Option<&Task> {
        self.projection.iter().find(|task| task.id == task_id)
    }

    #[must_use]
    pub fn list_tasks(&self) -> &[Task] {
        &self.projection
    }

    /// Read one bounded creation-ordered page. A cursor from an older graph
    /// generation is rejected instead of returning a mixed snapshot.
    ///
    /// # Errors
    /// Returns an error for malformed or stale cursors, invalid limits, or an
    /// invalid graph.
    pub fn page_tasks(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<TaskManagerPage, String> {
        let cursor = cursor
            .map(TaskPageCursor::parse)
            .transpose()
            .map_err(|error| error.to_string())?;
        let page = self
            .graph
            .page(cursor, limit)
            .map_err(|error| error.to_string())?;
        let tasks = page.tasks.into_iter().filter_map(project_task).collect();
        Ok(TaskManagerPage {
            tasks,
            next_cursor: page.next.map(TaskPageCursor::encode),
            generation: page.generation,
        })
    }

    #[must_use]
    pub fn current_task(&self) -> Option<&Task> {
        self.projection
            .iter()
            .find(|task| task.status == TaskStatus::InProgress)
    }

    #[must_use]
    pub fn format_task_summary(task: &Task) -> String {
        let status_icon = match task.status {
            TaskStatus::Pending => "[ ]",
            TaskStatus::InProgress => "[>]",
            TaskStatus::Completed => "[x]",
            TaskStatus::Failed => "[!]",
            TaskStatus::Canceled => "[-]",
        };
        let mut summary = format!(
            "{status_icon} {} {} ({}, {})",
            task.id, task.subject, task.status, task.priority
        );
        if let Some(active_form) = &task.active_form {
            let _ = write!(summary, " -- {active_form}");
        }
        if !task.blocks.is_empty() {
            let _ = write!(summary, "\n    blocks: {}", task.blocks.join(", "));
        }
        if !task.blocked_by.is_empty() {
            let _ = write!(summary, "\n    blocked_by: {}", task.blocked_by.join(", "));
        }
        summary
    }

    #[must_use]
    pub fn format_task_detail(task: &Task) -> String {
        let mut detail = String::new();
        let _ = writeln!(detail, "ID: {}", task.id);
        let _ = writeln!(detail, "Subject: {}", task.subject);
        let _ = writeln!(detail, "Status: {}", task.status);
        let _ = writeln!(detail, "Priority: {}", task.priority);
        let _ = writeln!(detail, "Version: {}", task.revision);
        let _ = writeln!(detail, "Description: {}", task.description);
        if let Some(active_form) = &task.active_form {
            let _ = writeln!(detail, "Active form: {active_form}");
        }
        let _ = writeln!(
            detail,
            "Created: {}",
            task.created_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        let _ = writeln!(
            detail,
            "Updated: {}",
            task.updated_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        if let Some(terminal_at) = task.terminal_at {
            let _ = writeln!(
                detail,
                "Terminal: {}",
                terminal_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }
        if !task.blocks.is_empty() {
            let _ = writeln!(detail, "Blocks: {}", task.blocks.join(", "));
        }
        if !task.blocked_by.is_empty() {
            let _ = writeln!(detail, "Blocked by: {}", task.blocked_by.join(", "));
        }
        detail
    }

    fn publish(&mut self, proposal: TaskGraphProposal) -> Result<(), String> {
        let persistence = if let Some(store) = &self.store {
            let receipt = store
                .commit(self.storage_generation, proposal.graph())
                .map_err(|error| error.to_string())?;
            self.storage_generation = receipt.generation();
            Some(receipt.state())
        } else {
            None
        };
        let (graph, graph_receipt) = proposal.into_parts();
        self.graph = graph;
        self.last_receipt = Some(TaskManagerReceipt {
            graph: graph_receipt,
            persistence,
        });
        self.rebuild_projection();
        Ok(())
    }

    fn rebuild_projection(&mut self) {
        self.projection = self.graph.all_tasks().filter_map(project_task).collect();
        self.projection.sort_unstable_by(|left, right| {
            numeric_task_sequence(&left.id)
                .cmp(&numeric_task_sequence(&right.id))
                .then_with(|| left.id.cmp(&right.id))
        });
    }
}

fn project_task(node: &TaskNode) -> Option<Task> {
    let status = match node.status {
        CanonicalTaskStatus::Pending => TaskStatus::Pending,
        CanonicalTaskStatus::InProgress => TaskStatus::InProgress,
        CanonicalTaskStatus::Completed => TaskStatus::Completed,
        CanonicalTaskStatus::Failed => TaskStatus::Failed,
        CanonicalTaskStatus::Canceled => TaskStatus::Canceled,
        CanonicalTaskStatus::Deleted => return None,
    };
    Some(Task {
        id: node.id.to_string(),
        subject: node.subject.clone(),
        description: node.description.clone(),
        active_form: node.active_form.clone(),
        status,
        priority: node.priority,
        blocks: node.blocks.iter().map(ToString::to_string).collect(),
        blocked_by: node.blocked_by.iter().map(ToString::to_string).collect(),
        created_at: node.created_at,
        updated_at: node.updated_at,
        completed_at: node.completed_at,
        terminal_at: node.terminal_at,
        revision: node.revision,
        ownership: node.ownership.clone(),
        source: node.source.clone(),
        budget: node.budget.clone(),
    })
}

const fn canonical_status(status: TaskUpdateStatus) -> CanonicalTaskStatus {
    match status {
        TaskUpdateStatus::Pending => CanonicalTaskStatus::Pending,
        TaskUpdateStatus::InProgress => CanonicalTaskStatus::InProgress,
        TaskUpdateStatus::Completed => CanonicalTaskStatus::Completed,
        TaskUpdateStatus::Failed => CanonicalTaskStatus::Failed,
        TaskUpdateStatus::Canceled => CanonicalTaskStatus::Canceled,
        TaskUpdateStatus::Deleted => CanonicalTaskStatus::Deleted,
    }
}

fn apply_edge_changes(
    current: &BTreeSet<TaskId>,
    additions: Option<&[String]>,
    removals: Option<&[String]>,
) -> Result<Option<BTreeSet<TaskId>>, String> {
    if additions.is_none() && removals.is_none() {
        return Ok(None);
    }
    let mut edges = current.clone();
    if let Some(additions) = additions {
        for id in additions {
            edges.insert(TaskId::parse(id.clone()).map_err(|error| error.to_string())?);
        }
    }
    if let Some(removals) = removals {
        for id in removals {
            edges.remove(&TaskId::parse(id.clone()).map_err(|error| error.to_string())?);
        }
    }
    Ok(Some(edges))
}

fn numeric_task_sequence(id: &str) -> u64 {
    id.strip_prefix("task-")
        .and_then(|value| value.parse().ok())
        .unwrap_or(u64::MAX)
}

fn prepare_private_graph_root(root: &Path) -> Result<(), String> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err("task graph persistence root is not a real directory".to_string());
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
                    .map_err(|error| format!("creating task graph root failed: {error}"))?;
            }
            #[cfg(not(unix))]
            fs::create_dir_all(root)
                .map_err(|error| format!("creating task graph root failed: {error}"))?;
        }
        Err(error) => {
            return Err(format!("inspecting task graph root failed: {error}"));
        }
    }

    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("re-inspecting task graph root failed: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("task graph persistence root is not a real directory".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        // SAFETY: `geteuid` has no preconditions and retains no pointer.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "task graph persistence root must be owner-only and owned by the effective user"
                    .to_string(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(manager: &mut TaskManager, subject: &str) -> String {
        manager
            .create_task(subject.to_string(), "description".to_string(), None)
            .expect("create task")
            .id
            .clone()
    }

    #[test]
    fn compatibility_manager_projects_canonical_versions() {
        let mut manager = TaskManager::new();
        let id = create(&mut manager, "Implement feature");
        let task = manager.get_task(&id).expect("task");
        assert_eq!(task.revision, 1);
        assert_eq!(manager.generation().get(), 1);
        assert!(matches!(task.source, TaskSource::TaskTool));
        assert!(matches!(task.ownership, TaskOwnership::Run { .. }));
    }

    #[test]
    fn invalid_update_does_not_demote_the_current_task() {
        let mut manager = TaskManager::new();
        let first = create(&mut manager, "first");
        let second = create(&mut manager, "second");
        manager
            .update_task(
                &first,
                TaskUpdateParams {
                    status: Some(TaskUpdateStatus::InProgress),
                    ..TaskUpdateParams::default()
                },
            )
            .expect("start first");
        let before = serde_json::to_vec(manager.graph()).expect("before");
        let result = manager.update_task(
            &second,
            TaskUpdateParams {
                status: Some(TaskUpdateStatus::InProgress),
                add_blocked_by: Some(vec![first]),
                ..TaskUpdateParams::default()
            },
        );
        assert!(result.is_err());
        assert_eq!(serde_json::to_vec(manager.graph()).expect("after"), before);
    }

    #[test]
    fn delete_keeps_canonical_tombstone_and_hides_projection() {
        let mut manager = TaskManager::new();
        let id = create(&mut manager, "delete me");
        manager
            .update_task(
                &id,
                TaskUpdateParams {
                    status: Some(TaskUpdateStatus::Deleted),
                    ..TaskUpdateParams::default()
                },
            )
            .expect("delete");
        assert!(manager.get_task(&id).is_none());
        assert!(manager
            .graph()
            .all_tasks()
            .any(|node| node.id.as_str() == id && node.status == CanonicalTaskStatus::Deleted));
    }

    #[cfg(unix)]
    #[test]
    fn private_graph_root_is_created_owner_only_and_never_repairs_public_paths() {
        use std::os::unix::fs::PermissionsExt as _;

        let host = tempfile::tempdir().expect("host root");
        let created = host.path().join("state").join("task_graphs");
        prepare_private_graph_root(&created).expect("create private graph root");
        assert_eq!(
            fs::symlink_metadata(&created)
                .expect("created metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        fs::set_permissions(&created, fs::Permissions::from_mode(0o755)).expect("make root public");
        let error = prepare_private_graph_root(&created).expect_err("reject public root");
        assert!(error.contains("owner-only"));
        assert_eq!(
            fs::symlink_metadata(&created)
                .expect("rejected metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "validation must not mutate an untrusted pathname"
        );
    }
}

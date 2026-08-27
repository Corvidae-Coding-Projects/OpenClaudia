//! Multi-agent coordinator — crosslink #507.
//!
//! Phased rollout (see `docs/designs/507-coordinator.md`):
//!
//! - **Phase 1 (landed)**: infrastructure only — types, queue, teammate
//!   registry, and tests. `Coordinator::dispatch` returns an error because no
//!   teammate-spawn path is wired yet; nothing in the harness calls it.
//! - **Phase 2**: spawn one teammate per task sequentially via the existing
//!   `subagent::run_subagent`, fire `SubagentStart` / `SubagentStop` hooks
//!   (already defined in #513).
//! - **Phase 3**: parallel teammates, leader permission bridge, agent color
//!   assignment.
//!
//! Process-scoped handles (`hook_engine`, `permission_mgr`, service
//! registry) arrive via the `Coordinator::new` constructor rather
//! than living on the coordinator struct long-term — Phase 2 will
//! convert them to an `AppHandles` param passed per dispatch.
pub mod permission;
pub mod planner;
pub mod task_queue;
pub mod tasks;
pub mod teammate;

pub use permission::{LeaderPermissionBridge, QueuedPermission};
pub use planner::{
    PlannerAmendment, PlannerAmendmentId, PlannerApprovalEvidence, PlannerApprovalId,
    PlannerApprovalState, PlannerArtifact, PlannerArtifactId, PlannerAttempt, PlannerAttemptId,
    PlannerAttemptState, PlannerCheckpoint, PlannerCheckpointError, PlannerCheckpointGeneration,
    PlannerCheckpointStore, PlannerChild, PlannerChildDisposition, PlannerChildOwner,
    PlannerChildState, PlannerContradiction, PlannerContradictionId, PlannerContradictionState,
    PlannerDecision, PlannerDecisionId, PlannerEvidenceSource, PlannerEvidenceSourceRecord,
    PlannerLease, PlannerLeaseId, PlannerLeaseTombstone, PlannerObjective, PlannerObjectiveId,
    PlannerRotation, PlannerRuntime, PlannerSourceId, PlannerState, StoredPlannerCheckpoint,
};
pub use task_queue::{Task, TaskId, TaskQueue, TaskQueueError, TaskState};
pub use teammate::{AgentColor, Teammate, TeammateId, TeammateState, TransitionError};

use std::collections::HashMap;

/// Errors the coordinator itself can surface (distinct from
/// per-task / per-teammate errors, which are carried inside
/// [`TaskState::Failed`] and [`TeammateState::Dead`]).
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("dispatch called before Phase 2 wires the teammate spawn path")]
    NotImplemented,
    #[error("task queue error: {0}")]
    Queue(#[from] TaskQueueError),
}

/// What the coordinator owns: a task graph + live teammates + permission bridge.
///
/// Phase 1 lands the shape only; Phase 2 adds the async `dispatch` loop that
/// pulls from `queue.next_ready()` and spawns teammates.
pub struct Coordinator {
    queue: TaskQueue,
    teammates: HashMap<TeammateId, Teammate>,
    permission_bridge: LeaderPermissionBridge,
}

impl Coordinator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: TaskQueue::new(),
            teammates: HashMap::new(),
            permission_bridge: LeaderPermissionBridge::new(),
        }
    }

    /// Read-only view of the queue. Mutation goes through the focused
    /// [`Self::submit`] and [`Self::add_dependency`] methods instead
    /// of exposing `&mut TaskQueue` across the module boundary
    /// (crosslink #852).
    #[must_use]
    pub const fn queue(&self) -> &TaskQueue {
        &self.queue
    }

    /// Submit a task to the queue and return its [`TaskId`].
    ///
    /// Focused mutator that replaces direct external access to
    /// [`Self::queue_mut`]: callers describe *what* they want to do
    /// (submit a task) without grabbing the entire queue handle.
    ///
    /// # Errors
    ///
    /// Returns [`TaskQueueError`] if submission fails (e.g. cycle
    /// detection via dependency declarations).
    pub fn submit(&mut self, task: Task) -> Result<TaskId, TaskQueueError> {
        self.queue.submit(task)
    }

    /// Declare that `from` depends on `to`. Same `TaskQueueError` surface
    /// as the underlying queue method — cycles are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`TaskQueueError::CycleDetected`] if the new edge would
    /// close a cycle, or [`TaskQueueError::UnknownTask`] if either id
    /// is not present in the queue.
    pub fn add_dependency(&mut self, from: TaskId, to: TaskId) -> Result<(), TaskQueueError> {
        self.queue.add_dependency(from, to)
    }

    /// Live teammate registry (empty in Phase 1).
    #[must_use]
    pub const fn teammates(&self) -> &HashMap<TeammateId, Teammate> {
        &self.teammates
    }

    /// Permission bridge that serializes prompts across teammates.
    #[must_use]
    pub const fn permission_bridge(&self) -> &LeaderPermissionBridge {
        &self.permission_bridge
    }

    /// Kick off task execution. Phase 1 always errors — wiring the
    /// spawn path is Phase 2's scope. Exposed now so downstream
    /// callers can compile against the intended signature without
    /// behavior dependencies.
    ///
    /// # Errors
    ///
    /// Returns `CoordinatorError::NotImplemented` until Phase 2.
    pub const fn dispatch(&mut self) -> Result<(), CoordinatorError> {
        Err(CoordinatorError::NotImplemented)
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subagent::AgentType;

    #[test]
    fn default_coordinator_is_empty() {
        let co = Coordinator::new();
        assert_eq!(co.queue().len(), 0);
        assert!(co.teammates().is_empty());
        assert!(co.permission_bridge().is_idle());
    }

    #[test]
    fn phase_one_dispatch_errors_not_implemented() {
        let mut co = Coordinator::new();
        let err = co.dispatch().unwrap_err();
        assert!(matches!(err, CoordinatorError::NotImplemented));
    }

    #[test]
    fn queue_accepts_linear_chain() {
        let mut co = Coordinator::new();
        let a = co.submit(Task::new(AgentType::Explore, "scan")).unwrap();
        let b = co
            .submit(Task::new(AgentType::Plan, "design").depends_on(vec![a]))
            .unwrap();
        let _c = co
            .submit(Task::new(AgentType::GeneralPurpose, "implement").depends_on(vec![b]))
            .unwrap();
        assert_eq!(co.queue().len(), 3);
    }

    #[test]
    fn queue_rejects_cycle() {
        let mut co = Coordinator::new();
        let a = co.submit(Task::new(AgentType::Explore, "a")).unwrap();
        // Submit `b` with `a` as a dep, then try to re-parent `a`
        // on top of `b` — that closes the loop.
        let b = co
            .submit(Task::new(AgentType::Plan, "b").depends_on(vec![a]))
            .unwrap();
        let err = co.add_dependency(a, b).expect_err("cycle must be rejected");
        assert!(matches!(err, TaskQueueError::CycleDetected { .. }));
    }
}

/// Phase 2 spec pins — #532 behavioral contracts for [`Coordinator`].
///
/// These tests pin the CURRENT Phase 1 contracts so regressions are
/// caught before Phase 2 wires the dispatch loop. They must not be
/// changed to make dispatch succeed — that is Phase 2's scope.
#[cfg(test)]
mod phase2_spec_pins {
    use super::*;
    use crate::subagent::AgentType;

    // ── B2: dispatch always returns NotImplemented ───────────────────

    /// B2a: empty coordinator returns `NotImplemented` immediately.
    #[test]
    fn b2_empty_coordinator_dispatch_not_implemented() {
        let mut co = Coordinator::new();
        let result = co.dispatch();
        assert!(
            matches!(result, Err(CoordinatorError::NotImplemented)),
            "dispatch must return NotImplemented in Phase 1 — got {result:?}",
        );
    }

    /// B2b: coordinator with pending tasks still returns `NotImplemented`
    /// without touching the queue (#532 B2 side-effect: none).
    #[test]
    fn b2_pending_tasks_not_executed_by_dispatch() {
        let mut co = Coordinator::new();
        co.submit(Task::new(AgentType::Explore, "task-a")).unwrap();
        let len_before = co.queue().len();

        let result = co.dispatch();

        assert!(matches!(result, Err(CoordinatorError::NotImplemented)));
        // Queue must be untouched — dispatch must not pop or mutate.
        assert_eq!(
            co.queue().len(),
            len_before,
            "dispatch must not mutate the queue in Phase 1",
        );
    }

    /// B2c: Display text is the exact string specified in #532 B2.
    #[test]
    fn b2_not_implemented_display_text() {
        let msg = CoordinatorError::NotImplemented.to_string();
        assert_eq!(
            msg,
            "dispatch called before Phase 2 wires the teammate spawn path",
        );
    }

    /// B2d: the Queue error variant round-trips through `CoordinatorError`.
    /// Uses a `TaskId` from a side queue — `TaskId`'s inner field is private
    /// and not accessible from this module's scope.
    #[test]
    fn b2_queue_error_wraps_correctly() {
        // Obtain a real TaskId from an isolated queue; never touch the
        // private tuple field directly from this module.
        let mut side = TaskQueue::new();
        let id = side.submit(Task::new(AgentType::Explore, "dummy")).unwrap();
        let queue_err = TaskQueueError::UnknownTask { missing: id };
        let coord_err = CoordinatorError::Queue(queue_err);
        let msg = coord_err.to_string();
        assert!(msg.contains("task queue error"), "got: {msg}");
    }
}

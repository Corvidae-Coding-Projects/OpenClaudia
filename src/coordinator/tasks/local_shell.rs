//! `LocalShellTask` — coordinator-visible wrapper over a
//! `BACKGROUND_SHELLS` background shell (crosslink #611).
//!
//! Claude Code routes every background shell through its coordinator
//! so observers (TUI, hooks, `/tasks`) can see which agent owns each
//! shell. `OpenClaudia`'s bash subsystem keeps its own
//! `BACKGROUND_SHELLS` registry (see [`crate::tools::BACKGROUND_SHELLS`])
//! for runtime accounting; this module layers a coordinator view on
//! top:
//!
//! - records the **owning agent** (so we can filter shells per
//!   teammate via [`tasks_for_agent`]),
//! - mirrors the **running/finished** state without taking a lock on
//!   the shell manager,
//! - is `Serialize`/`Deserialize` so the coordinator registry can be
//!   snapshotted.
//!
//! Note the inversion of responsibility: `BackgroundShellManager`
//! owns the OS process; `LocalShellTask` owns the *coordinator*
//! metadata. The two are joined by the shell id string.

use serde::{Deserialize, Serialize};

use super::TaskTransitionError;
use crate::coordinator::teammate::TeammateId;
use crate::tools::BACKGROUND_SHELLS;

/// Coordinator-visible state of a background shell.
///
/// Mirrors the subset of `BackgroundShellManager` state the
/// coordinator cares about — full exit-code metadata still lives in
/// the manager and is read on demand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalShellTaskState {
    /// Shell process is alive.
    Running,
    /// Shell process has exited.
    Finished,
}

impl LocalShellTaskState {
    /// Static label used in error messages.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Running => "Running",
            Self::Finished => "Finished",
        }
    }
}

/// Coordinator wrapper for a background shell, with an owning agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalShellTask {
    /// Shell id assigned by [`crate::tools::BACKGROUND_SHELLS`].
    pub shell_id: String,
    /// Command that was launched. Stored once so the coordinator can
    /// display the prompt without touching the manager mutex.
    pub command: String,
    /// Agent that asked for the shell to be spawned. `None` means the
    /// shell predates coordinator wiring (e.g. spawned from a raw
    /// `bash` tool call before #611 landed); the filter functions
    /// treat `None` as "unowned" and never match agent-id queries.
    pub owner: Option<TeammateId>,
    state: LocalShellTaskState,
}

impl LocalShellTask {
    /// Build a new running shell task — the caller has already
    /// `BACKGROUND_SHELLS.spawn`-ed the underlying process.
    #[must_use]
    pub fn new(
        shell_id: impl Into<String>,
        command: impl Into<String>,
        owner: Option<TeammateId>,
    ) -> Self {
        Self {
            shell_id: shell_id.into(),
            command: command.into(),
            owner,
            state: LocalShellTaskState::Running,
        }
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> &LocalShellTaskState {
        &self.state
    }

    /// Mark the shell as finished. Idempotent.
    pub const fn mark_finished(&mut self) {
        self.state = LocalShellTaskState::Finished;
    }

    /// Refresh local state from [`BACKGROUND_SHELLS`].
    ///
    /// Returns `true` if a status change was applied. If the shell
    /// has been GC'd out of the manager (e.g. its output was drained
    /// and a subsequent spawn evicted it), this is a no-op — the
    /// coordinator-side record is preserved so observers don't see a
    /// disappearing task.
    pub fn refresh_from_manager(&mut self, run: &crate::tools::ToolRunContext) -> bool {
        for (id, _cmd, running) in BACKGROUND_SHELLS.list(run) {
            if id == self.shell_id {
                let new_state = if running {
                    LocalShellTaskState::Running
                } else {
                    LocalShellTaskState::Finished
                };
                if new_state != self.state {
                    self.state = new_state;
                    return true;
                }
                return false;
            }
        }
        false
    }

    /// Transition Running → Finished (idempotent).
    ///
    /// Provided in addition to [`Self::mark_finished`] so the failure
    /// surface mirrors the other task types — `mark_finished` is the
    /// "I observed it externally" path; this is the "I assert the
    /// transition" path with explicit error reporting.
    ///
    /// # Errors
    ///
    /// This method is currently infallible (Running → Finished and
    /// Finished → Finished are both legal) but returns `Result` to
    /// stay shape-compatible with the other task types; future
    /// states (e.g. `Reaping`) can introduce illegal edges without a
    /// public API break.
    pub const fn finish(&mut self) -> Result<(), TaskTransitionError> {
        self.state = LocalShellTaskState::Finished;
        Ok(())
    }
}

/// Filter a registry of shell tasks down to the ones owned by `agent_id`.
///
/// Returns an iterator-collected `Vec` so the caller can keep the slice
/// they passed in (the coordinator's registry) immutable. Shells with
/// `owner == None` never match — `tasks_for_agent` is an
/// agent-attribution filter, not a "show me unowned shells" query.
#[must_use]
pub fn tasks_for_agent<'a>(
    tasks: &'a [LocalShellTask],
    agent_id: &TeammateId,
) -> Vec<&'a LocalShellTask> {
    tasks
        .iter()
        .filter(|t| t.owner.as_ref() == Some(agent_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_task_starts_running() {
        let task = LocalShellTask::new("abc12345", "echo hi", None);
        assert_eq!(task.state(), &LocalShellTaskState::Running);
        assert_eq!(task.shell_id, "abc12345");
        assert_eq!(task.command, "echo hi");
        assert!(task.owner.is_none());
    }

    #[test]
    fn mark_finished_is_idempotent() {
        let mut task = LocalShellTask::new("id", "cmd", None);
        task.mark_finished();
        assert_eq!(task.state(), &LocalShellTaskState::Finished);
        task.mark_finished();
        assert_eq!(task.state(), &LocalShellTaskState::Finished);
    }

    #[test]
    fn tasks_for_agent_filters_by_owner() {
        let a = TeammateId::new();
        let b = TeammateId::new();
        let tasks = vec![
            LocalShellTask::new("s1", "c1", Some(a.clone())),
            LocalShellTask::new("s2", "c2", Some(b.clone())),
            LocalShellTask::new("s3", "c3", Some(a.clone())),
            LocalShellTask::new("s4", "c4", None), // unowned — never matches
        ];
        let for_a = tasks_for_agent(&tasks, &a);
        let ids_a: Vec<&str> = for_a.iter().map(|t| t.shell_id.as_str()).collect();
        assert_eq!(ids_a, vec!["s1", "s3"]);

        let for_b = tasks_for_agent(&tasks, &b);
        assert_eq!(for_b.len(), 1);
        assert_eq!(for_b[0].shell_id, "s2");
    }

    #[test]
    fn tasks_for_agent_skips_unowned() {
        let a = TeammateId::new();
        let tasks = vec![
            LocalShellTask::new("s1", "c1", None),
            LocalShellTask::new("s2", "c2", None),
        ];
        assert!(tasks_for_agent(&tasks, &a).is_empty());
    }

    #[test]
    fn refresh_from_manager_no_op_when_shell_unknown() {
        // shell_id that won't exist in BACKGROUND_SHELLS — refresh
        // must leave the local state untouched.
        let mut task = LocalShellTask::new("ghost-id-zzzz", "cmd", None);
        assert!(!task.refresh_from_manager(crate::tools::security::test_run_context()));
        assert_eq!(task.state(), &LocalShellTaskState::Running);
    }

    #[test]
    fn finish_is_infallible_idempotent_transition() {
        let mut task = LocalShellTask::new("s", "c", None);
        task.finish().unwrap();
        assert_eq!(task.state(), &LocalShellTaskState::Finished);
        task.finish().unwrap();
        assert_eq!(task.state(), &LocalShellTaskState::Finished);
    }

    #[test]
    fn serde_roundtrip_preserves_owner_and_state() {
        let owner = TeammateId::new();
        let mut original = LocalShellTask::new("s", "c", Some(owner.clone()));
        original.mark_finished();
        let json = serde_json::to_string(&original).unwrap();
        let back: LocalShellTask = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
        assert_eq!(back.owner, Some(owner));
        assert_eq!(back.state(), &LocalShellTaskState::Finished);
    }
}

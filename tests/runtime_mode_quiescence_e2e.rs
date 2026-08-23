//! Restrictive runtime-mode transitions must not coexist with background
//! mutation authority already owned by the same exact run generation.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Barrier};

use openclaudia::modes::{BehaviorMode, RuntimeMode, RuntimeModeClass};
use openclaudia::subagent::{AgentType, BACKGROUND_AGENTS};
use openclaudia::tools::{RuntimeModeTransitionError, ToolRunContext};
use serde_json::{json, Value};

fn args(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect()
}

fn standard_mode() -> RuntimeMode {
    RuntimeMode::Behavioral(BehaviorMode::default())
}

struct ShellCleanup {
    run: Arc<ToolRunContext>,
    id: Option<String>,
}

impl ShellCleanup {
    fn stop(&mut self) {
        let Some(id) = self.id.as_ref() else {
            return;
        };
        self.run
            .transition_runtime_mode(standard_mode())
            .expect("cleanup can restore standard mode");
        let result = support::dispatch_canonical_tool_result_for_run(
            &self.run,
            "kill_shell",
            &args(&[("shell_id", json!(id))]),
        );
        assert!(!result.is_error(), "shell cleanup failed: {result:?}");
        self.id = None;
    }
}

impl Drop for ShellCleanup {
    fn drop(&mut self) {
        let Some(id) = self.id.take() else {
            return;
        };
        let _ = self.run.transition_runtime_mode(standard_mode());
        let _ = support::dispatch_canonical_tool_result_for_run(
            &self.run,
            "kill_shell",
            &args(&[("shell_id", json!(id))]),
        );
    }
}

#[test]
fn active_shell_blocks_plan_until_explicitly_stopped() {
    let workspace = tempfile::tempdir().expect("workspace");
    let run = support::test_run_context(workspace.path());
    let result = support::dispatch_canonical_tool_result_for_run(
        &run,
        "bash",
        &args(&[
            ("command", json!("sleep 30")),
            ("run_in_background", json!(true)),
        ]),
    );
    assert!(!result.is_error(), "background shell failed: {result:?}");
    let shell_id = result
        .content()
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("Background shell started with ID: "))
        .expect("background response contains shell id")
        .to_string();
    let mut cleanup = ShellCleanup {
        run: Arc::clone(&run),
        id: Some(shell_id.clone()),
    };
    let before = run.runtime_mode();

    let error = run
        .try_transition_runtime_mode(RuntimeMode::Plan)
        .expect_err("active shell must block Plan");
    assert_eq!(
        error,
        RuntimeModeTransitionError::InFlightBackgroundEffects {
            requested_mode: "plan".to_string(),
            shell_count: 1,
            agent_count: 0,
            shell_ids: vec![shell_id],
            agent_ids: Vec::new(),
        }
    );
    assert_eq!(
        run.runtime_mode(),
        before,
        "refusal must not publish a mode"
    );

    cleanup.stop();
    let installed = run
        .try_transition_runtime_mode(RuntimeMode::Plan)
        .expect("Plan succeeds after explicit shell cleanup");
    assert_eq!(installed.class, RuntimeModeClass::Plan);
}

#[test]
fn active_worker_blocks_readonly_until_task_stop() {
    let workspace = tempfile::tempdir().expect("workspace");
    let run = support::test_run_context(workspace.path());
    let agent_id = BACKGROUND_AGENTS
        .register(&run, AgentType::Explore, "inspect current implementation")
        .expect("register active worker");
    let before = run.runtime_mode();

    let error = run
        .try_transition_runtime_mode(RuntimeMode::Initializer)
        .expect_err("active worker must block ReadOnly");
    assert_eq!(
        error,
        RuntimeModeTransitionError::InFlightBackgroundEffects {
            requested_mode: "initializer".to_string(),
            shell_count: 0,
            agent_count: 1,
            shell_ids: Vec::new(),
            agent_ids: vec![agent_id.clone()],
        }
    );
    assert_eq!(run.runtime_mode(), before, "refusal must be atomic");

    let stopped = support::dispatch_canonical_tool_result_for_run(
        &run,
        "task_stop",
        &args(&[
            ("agent_id", json!(agent_id)),
            ("reason", json!("entering read-only mode")),
        ]),
    );
    assert!(!stopped.is_error(), "task_stop failed: {stopped:?}");
    let installed = run
        .try_transition_runtime_mode(RuntimeMode::Initializer)
        .expect("ReadOnly succeeds after explicit worker stop");
    assert_eq!(installed.class, RuntimeModeClass::ReadOnly);
}

#[test]
fn another_runs_worker_does_not_block_transition() {
    let workspace = tempfile::tempdir().expect("workspace");
    let owner = support::test_run_context(workspace.path());
    let other = support::test_run_context(workspace.path());
    let agent_id = BACKGROUND_AGENTS
        .register(&owner, AgentType::Explore, "owner-only work")
        .expect("register owner worker");

    let installed = other
        .try_transition_runtime_mode(RuntimeMode::Plan)
        .expect("foreign run activity cannot block this run");
    assert_eq!(installed.class, RuntimeModeClass::Plan);

    let stopped = support::dispatch_canonical_tool_result_for_run(
        &owner,
        "task_stop",
        &args(&[("agent_id", json!(agent_id))]),
    );
    assert!(!stopped.is_error(), "task_stop failed: {stopped:?}");
}

#[test]
fn background_spawn_and_plan_publication_cannot_both_succeed() {
    let workspace = tempfile::tempdir().expect("workspace");
    let run = support::test_run_context(workspace.path());
    let barrier = Arc::new(Barrier::new(3));

    let spawn_run = Arc::clone(&run);
    let spawn_barrier = Arc::clone(&barrier);
    let spawn = std::thread::spawn(move || {
        spawn_barrier.wait();
        let result = support::dispatch_canonical_tool_result_for_run(
            &spawn_run,
            "bash",
            &args(&[
                ("command", json!("sleep 30")),
                ("run_in_background", json!(true)),
            ]),
        );
        (result.content().to_string(), result.is_error())
    });

    let transition_run = Arc::clone(&run);
    let transition_barrier = Arc::clone(&barrier);
    let transition = std::thread::spawn(move || {
        transition_barrier.wait();
        transition_run.try_transition_runtime_mode(RuntimeMode::Plan)
    });

    barrier.wait();
    let (spawn_message, spawn_failed) = spawn.join().expect("spawn thread");
    let transition_result = transition.join().expect("transition thread");

    if spawn_failed {
        let installed = transition_result.expect("Plan won the lifecycle gate");
        assert_eq!(installed.class, RuntimeModeClass::Plan);
        assert!(
            spawn_message.contains("denies tool 'bash'")
                || spawn_message.contains("does not grant this tool"),
            "background spawn must be denied by Plan: {spawn_message}"
        );
    } else {
        let shell_id = spawn_message
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("Background shell started with ID: "))
            .expect("successful spawn contains shell id")
            .to_string();
        assert!(
            matches!(
                transition_result,
                Err(RuntimeModeTransitionError::InFlightBackgroundEffects { .. })
            ),
            "successful spawn must force transition refusal: {transition_result:?}"
        );
        run.transition_runtime_mode(standard_mode())
            .expect("cleanup can restore standard mode");
        let stopped = support::dispatch_canonical_tool_result_for_run(
            &run,
            "kill_shell",
            &args(&[("shell_id", json!(shell_id))]),
        );
        assert!(!stopped.is_error(), "shell cleanup failed: {stopped:?}");
    }
}

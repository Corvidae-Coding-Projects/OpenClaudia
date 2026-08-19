//! End-to-end tests for the run-scoped `BackgroundAgentManager` lifecycle.
//!
//! The manager is process-global in production, so every operation that can
//! observe or mutate an agent must carry the exact owning run generation.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

use openclaudia::state::SessionId;
use openclaudia::subagent::{AgentType, BackgroundAgentManager};
use openclaudia::tools::{ToolRunContext, WorkspaceAccess};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{atomic::Ordering, Arc};

fn test_run(provider: &str) -> Arc<ToolRunContext> {
    ToolRunContext::builder(SessionId::new(), Path::new(env!("CARGO_MANIFEST_DIR")))
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(WorkspaceAccess::ReadOnly)
        .process(false)
        .network(false)
        .secrets(false)
        .provider(provider)
        .build()
        .expect("build explicit test run")
}

fn register(
    manager: &BackgroundAgentManager,
    owner: &ToolRunContext,
    agent_type: AgentType,
    task: &str,
) -> String {
    manager
        .register(owner, agent_type, task)
        .expect("register agent")
}

#[test]
fn manager_new_starts_empty_for_run() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("empty");
    assert!(manager.list_for_run(&owner).is_empty());
    assert!(manager.get_for_run(&owner, "missing").is_none());
    assert!(manager.remove_for_run(&owner, "missing").is_none());
    assert_eq!(manager.gc(), 0);
    assert_eq!(manager.cleanup_finished_for_run(&owner), 0);
}

#[test]
fn register_returns_distinct_run_visible_agents() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("register");
    let first = register(&manager, &owner, AgentType::Explore, "find files");
    let second = register(&manager, &owner, AgentType::Plan, "design API");

    assert!(!first.is_empty());
    assert_ne!(first, second);
    let agent = manager
        .get_for_run(&owner, &second)
        .expect("owner sees agent");
    assert_eq!(agent.id, second);
    assert_eq!(agent.agent_type, AgentType::Plan);
    assert_eq!(agent.task, "design API");
    assert!(!agent.finished.load(Ordering::SeqCst));
    assert_eq!(agent.turns.load(Ordering::SeqCst), 0);
}

#[test]
fn register_with_id_reattaches_only_within_same_run() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("resume-owner");
    let foreign = test_run("resume-foreign");

    assert!(manager
        .register_with_id(&owner, AgentType::Explore, "first", "shared-id")
        .expect("fresh registration"));
    assert!(!manager
        .register_with_id(&owner, AgentType::Plan, "replacement", "shared-id")
        .expect("same-run reattach"));
    assert_eq!(
        manager.register_with_id(&foreign, AgentType::Plan, "steal", "shared-id"),
        Err("Agent 'shared-id' not found".to_string())
    );

    let original = manager
        .get_for_run(&owner, "shared-id")
        .expect("original preserved");
    assert_eq!(original.agent_type, AgentType::Explore);
    assert_eq!(original.task, "first");
    assert!(manager.get_for_run(&foreign, "shared-id").is_none());
}

#[test]
fn finish_and_fail_store_terminal_state_for_owner() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("terminal");
    let finished_id = register(&manager, &owner, AgentType::Explore, "finish");
    let failed_id = register(&manager, &owner, AgentType::Plan, "fail");

    manager.finish(&owner, &finished_id, "result body".to_string());
    manager.fail(&owner, &failed_id, "execution error".to_string());

    let finished = manager
        .get_for_run(&owner, &finished_id)
        .expect("finished agent retained");
    assert!(finished.finished.load(Ordering::SeqCst));
    assert_eq!(
        finished.result.lock().unwrap().as_deref(),
        Some("result body")
    );
    let failed = manager
        .get_for_run(&owner, &failed_id)
        .expect("failed agent retained");
    assert!(failed.finished.load(Ordering::SeqCst));
    assert_eq!(
        failed.error.lock().unwrap().as_deref(),
        Some("execution error")
    );
}

#[test]
fn foreign_terminal_mutations_fail_closed() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("terminal-owner");
    let foreign = test_run("terminal-foreign");
    let id = register(&manager, &owner, AgentType::Explore, "owned");

    manager.finish(&foreign, &id, "stolen result".to_string());
    manager.fail(&foreign, &id, "stolen failure".to_string());
    assert_eq!(manager.increment_turns(&foreign, &id), 0);
    assert!(manager.remove_for_run(&foreign, &id).is_none());
    assert!(manager.list_for_run(&foreign).is_empty());

    let agent = manager
        .get_for_run(&owner, &id)
        .expect("foreign run could not remove owner state");
    assert!(!agent.finished.load(Ordering::SeqCst));
    assert!(agent.result.lock().unwrap().is_none());
    assert!(agent.error.lock().unwrap().is_none());
    assert_eq!(agent.turns.load(Ordering::SeqCst), 0);
}

#[test]
fn unknown_terminal_mutations_are_noops() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("unknown");
    manager.finish(&owner, "missing", "result".to_string());
    manager.fail(&owner, "missing", "error".to_string());
    assert_eq!(manager.increment_turns(&owner, "missing"), 0);
}

#[test]
fn increment_turns_is_monotonic_and_visible() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("turns");
    let id = register(&manager, &owner, AgentType::Explore, "task");
    assert_eq!(manager.increment_turns(&owner, &id), 1);
    assert_eq!(manager.increment_turns(&owner, &id), 2);
    assert_eq!(manager.increment_turns(&owner, &id), 3);
    assert_eq!(
        manager
            .get_for_run(&owner, &id)
            .expect("agent retained")
            .turns
            .load(Ordering::SeqCst),
        3
    );
}

#[test]
fn list_reports_only_owner_agents_and_terminal_status() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("list-owner");
    let foreign = test_run("list-foreign");
    let running = register(&manager, &owner, AgentType::Explore, "running");
    let done = register(&manager, &owner, AgentType::Plan, "done");
    let _foreign_id = register(&manager, &foreign, AgentType::Guide, "foreign");
    manager.finish(&owner, &done, "result".to_string());

    let listed = manager.list_for_run(&owner);
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().any(|entry| entry.0 == running && !entry.3));
    assert!(listed.iter().any(|entry| entry.0 == done && entry.3));
    assert_eq!(manager.list_for_run(&foreign).len(), 1);
}

#[test]
fn remove_is_exactly_run_scoped() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("remove-owner");
    let foreign = test_run("remove-foreign");
    let id = register(&manager, &owner, AgentType::Explore, "task");

    assert!(manager.remove_for_run(&foreign, &id).is_none());
    assert!(manager.get_for_run(&owner, &id).is_some());
    assert!(manager.remove_for_run(&owner, &id).is_some());
    assert!(manager.get_for_run(&owner, &id).is_none());
}

#[test]
fn cleanup_finished_removes_only_owner_finished_agents() {
    let manager = BackgroundAgentManager::new();
    let owner = test_run("cleanup-owner");
    let foreign = test_run("cleanup-foreign");
    let owner_running = register(&manager, &owner, AgentType::Explore, "running");
    let owner_done = register(&manager, &owner, AgentType::Plan, "done");
    let foreign_done = register(&manager, &foreign, AgentType::Guide, "foreign done");
    manager.finish(&owner, &owner_done, "done".to_string());
    manager.finish(&foreign, &foreign_done, "done".to_string());

    assert_eq!(manager.cleanup_finished_for_run(&owner), 1);
    assert!(manager.get_for_run(&owner, &owner_running).is_some());
    assert!(manager.get_for_run(&owner, &owner_done).is_none());
    assert!(manager.get_for_run(&foreign, &foreign_done).is_some());
    assert_eq!(manager.cleanup_finished_for_run(&foreign), 1);
}

#[test]
fn default_and_new_both_start_empty() {
    let owner = test_run("default");
    assert!(BackgroundAgentManager::default()
        .list_for_run(&owner)
        .is_empty());
    assert!(BackgroundAgentManager::new()
        .list_for_run(&owner)
        .is_empty());
}

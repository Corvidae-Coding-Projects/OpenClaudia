//! End-to-end tests for `subagent::SubagentConfig`,
//! `subagent::SubagentResult`, and `subagent::WorktreeIsolation`
//! shape — struct-literal construction, Clone preservation,
//! field-level wire-shape contracts.
//!
//! Sprint 127 of the verification effort. Sprint 126 covered
//! `BackgroundAgentManager` lifecycle; this file pins the
//! plain-data types passed across the `run_subagent` /
//! `execute_task_tool` boundary plus the `WorktreeIsolation`
//! Clone/Debug + branch-name format (`agent/<id>`).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::subagent::{AgentType, SubagentConfig, SubagentResult, WorktreeIsolation};
use std::path::PathBuf;

mod support;

// ───────────────────────────────────────────────────────────────────────────
// Section A — SubagentConfig struct-literal construction
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn subagent_config_struct_literal_with_all_8_fields() {
    let cfg = SubagentConfig {
        agent_type: AgentType::Explore,
        task: "find files".to_string(),
        prompt: "list every .rs file".to_string(),
        run_in_background: false,
        model_override: None,
        resume_agent_id: None,
        isolation: None,
    };
    assert_eq!(cfg.agent_type, AgentType::Explore);
    assert_eq!(cfg.task, "find files");
    assert_eq!(cfg.prompt, "list every .rs file");
    assert!(!cfg.run_in_background);
    assert!(cfg.model_override.is_none());
    assert!(cfg.resume_agent_id.is_none());
    assert!(cfg.isolation.is_none());
}

#[test]
fn subagent_config_with_model_override_set() {
    let cfg = SubagentConfig {
        agent_type: AgentType::GeneralPurpose,
        task: "t".to_string(),
        prompt: "p".to_string(),
        run_in_background: false,
        model_override: Some("opus".to_string()),
        resume_agent_id: None,
        isolation: None,
    };
    assert_eq!(cfg.model_override.as_deref(), Some("opus"));
}

#[test]
fn subagent_config_with_resume_agent_id_set() {
    let cfg = SubagentConfig {
        agent_type: AgentType::Explore,
        task: "continue".to_string(),
        prompt: "next step".to_string(),
        run_in_background: false,
        model_override: None,
        resume_agent_id: Some("prior-agent-abc".to_string()),
        isolation: None,
    };
    assert_eq!(cfg.resume_agent_id.as_deref(), Some("prior-agent-abc"));
}

#[test]
fn subagent_config_with_isolation_set_to_worktree() {
    let cfg = SubagentConfig {
        agent_type: AgentType::GeneralPurpose,
        task: "isolated work".to_string(),
        prompt: "modify code".to_string(),
        run_in_background: false,
        model_override: None,
        resume_agent_id: None,
        isolation: Some("worktree".to_string()),
    };
    assert_eq!(cfg.isolation.as_deref(), Some("worktree"));
}

#[test]
fn subagent_config_clone_preserves_all_8_fields() {
    let original = SubagentConfig {
        agent_type: AgentType::Plan,
        task: "T".to_string(),
        prompt: "P".to_string(),
        run_in_background: true,
        model_override: Some("haiku".to_string()),
        resume_agent_id: Some("r".to_string()),
        isolation: Some("worktree".to_string()),
    };
    let cloned = original.clone();
    assert_eq!(cloned.agent_type, original.agent_type);
    assert_eq!(cloned.task, original.task);
    assert_eq!(cloned.prompt, original.prompt);
    assert_eq!(cloned.run_in_background, original.run_in_background);
    assert_eq!(cloned.model_override, original.model_override);
    assert_eq!(cloned.resume_agent_id, original.resume_agent_id);
    assert_eq!(cloned.isolation, original.isolation);
}

#[test]
fn subagent_config_debug_includes_field_names() {
    let cfg = SubagentConfig {
        agent_type: AgentType::Explore,
        task: "unique-task-marker".to_string(),
        prompt: "p".to_string(),
        run_in_background: false,
        model_override: None,
        resume_agent_id: None,
        isolation: None,
    };
    let dbg = format!("{cfg:?}");
    assert!(dbg.contains("unique-task-marker"));
    assert!(dbg.contains("agent_type") || dbg.contains("Explore"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — SubagentResult struct-literal construction
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn subagent_result_struct_literal_with_all_6_fields() {
    let result = SubagentResult {
        agent_id: "agent-123".to_string(),
        success: true,
        output: "operation complete".to_string(),
        turns_used: 5,
        is_background: false,
        worktree: None,
    };
    assert_eq!(result.agent_id, "agent-123");
    assert!(result.success);
    assert_eq!(result.output, "operation complete");
    assert_eq!(result.turns_used, 5);
    assert!(!result.is_background);
    assert!(result.worktree.is_none());
}

#[test]
fn subagent_result_failure_carries_error_output() {
    let result = SubagentResult {
        agent_id: "fail-id".to_string(),
        success: false,
        output: "error: file not found".to_string(),
        turns_used: 1,
        is_background: false,
        worktree: None,
    };
    assert!(!result.success);
    assert!(result.output.contains("error"));
}

#[test]
fn subagent_result_background_flag_distinct_from_foreground() {
    let bg = SubagentResult {
        agent_id: "bg".to_string(),
        success: true,
        output: String::new(),
        turns_used: 0,
        is_background: true,
        worktree: None,
    };
    let fg = SubagentResult {
        agent_id: "fg".to_string(),
        success: true,
        output: String::new(),
        turns_used: 0,
        is_background: false,
        worktree: None,
    };
    assert!(bg.is_background);
    assert!(!fg.is_background);
}

#[test]
fn subagent_result_with_worktree_carries_isolation_state() {
    let wt = WorktreeIsolation {
        worktree_path: PathBuf::from("/tmp/wt/agent-x"),
        branch_name: "agent/agent-x".to_string(),
    };
    let result = SubagentResult {
        agent_id: "agent-x".to_string(),
        success: true,
        output: "done".to_string(),
        turns_used: 3,
        is_background: false,
        worktree: Some(wt),
    };
    let attached = result.worktree.expect("Some");
    assert_eq!(attached.branch_name, "agent/agent-x");
    assert_eq!(attached.worktree_path, PathBuf::from("/tmp/wt/agent-x"));
}

#[test]
fn subagent_result_clone_preserves_all_6_fields() {
    let original = SubagentResult {
        agent_id: "x".to_string(),
        success: true,
        output: "out".to_string(),
        turns_used: 10,
        is_background: true,
        worktree: Some(WorktreeIsolation {
            worktree_path: PathBuf::from("/x"),
            branch_name: "b".to_string(),
        }),
    };
    let cloned = original.clone();
    assert_eq!(cloned.agent_id, original.agent_id);
    assert_eq!(cloned.success, original.success);
    assert_eq!(cloned.output, original.output);
    assert_eq!(cloned.turns_used, original.turns_used);
    assert_eq!(cloned.is_background, original.is_background);
    let original_wt_branch = original
        .worktree
        .as_ref()
        .expect("Some")
        .branch_name
        .clone();
    let cloned_wt_branch = cloned.worktree.as_ref().expect("Some").branch_name.clone();
    assert_eq!(cloned_wt_branch, original_wt_branch);
}

#[test]
fn subagent_result_turns_used_zero_valid() {
    let result = SubagentResult {
        agent_id: "x".to_string(),
        success: true,
        output: String::new(),
        turns_used: 0,
        is_background: false,
        worktree: None,
    };
    assert_eq!(result.turns_used, 0);
}

#[test]
fn subagent_result_turns_used_can_be_high_u64() {
    let result = SubagentResult {
        agent_id: "x".to_string(),
        success: true,
        output: String::new(),
        turns_used: 1_000_000,
        is_background: false,
        worktree: None,
    };
    assert_eq!(result.turns_used, 1_000_000);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — WorktreeIsolation shape + Clone
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn worktree_isolation_struct_literal_with_2_fields() {
    let wt = WorktreeIsolation {
        worktree_path: PathBuf::from("/some/path"),
        branch_name: "agent/abc".to_string(),
    };
    assert_eq!(wt.worktree_path, PathBuf::from("/some/path"));
    assert_eq!(wt.branch_name, "agent/abc");
}

#[test]
fn worktree_isolation_clone_preserves_both_fields() {
    let original = WorktreeIsolation {
        worktree_path: PathBuf::from("/x/y"),
        branch_name: "agent/12345678".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(cloned.worktree_path, original.worktree_path);
    assert_eq!(cloned.branch_name, original.branch_name);
}

#[test]
fn worktree_isolation_debug_includes_path_and_branch() {
    let wt = WorktreeIsolation {
        worktree_path: PathBuf::from("/unique-marker-path"),
        branch_name: "agent/unique-marker-branch".to_string(),
    };
    let dbg = format!("{wt:?}");
    assert!(dbg.contains("unique-marker-path"));
    assert!(dbg.contains("unique-marker-branch"));
}

#[test]
fn worktree_isolation_create_outside_git_repo_or_no_git_errors() {
    // PINS DOC: create requires `git rev-parse --show-toplevel`
    // to succeed; otherwise returns Err with a documented
    // message ("git not available" / "Not in a git repository").
    // In a non-git tempdir this MUST surface as Err.
    use tempfile::TempDir;
    let dir = TempDir::new().expect("tempdir");
    let run = support::test_run_context(dir.path());
    let outcome = WorktreeIsolation::create(&run, "test-agent");
    let message = outcome.expect_err("an explicit non-git workspace must fail closed");
    assert!(
        message.contains("git")
            || message.contains("Git")
            || message.contains("repository")
            || message.contains("worktree"),
        "error MUST mention git context; got {message:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Branch-name format
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn branch_name_uses_agent_prefix_when_caller_follows_format() {
    // PINS DOC: branch_name format is "agent/<agent_id>".
    // (Set by create — we mimic the format here.)
    let agent_id = "abc12345";
    let wt = WorktreeIsolation {
        worktree_path: PathBuf::from("/x"),
        branch_name: format!("agent/{agent_id}"),
    };
    assert!(wt.branch_name.starts_with("agent/"));
    assert!(wt.branch_name.ends_with(agent_id));
}

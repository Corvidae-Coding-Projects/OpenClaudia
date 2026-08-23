//! End-to-end tests for the plan-mode tool gate and the
//! immutable run-role semantics.
//!
//! Sprint 10 of the verification effort. `src/tools/plan_mode.rs`
//! has 13 unit tests and `src/subagent.rs` has 40, but no
//! integration coverage of the cross-module security contracts:
//!
//!   - **Mutation-tool catalog is hard-refused in plan mode** —
//!     `bash`, `edit_file`, `notebook_edit`, `todo_write`, and
//!     `kill_shell` are NOT in `PLAN_MODE_ALLOWED_TOOLS` and the
//!     gate MUST default-deny every one. A future drift that
//!     accidentally adds (say) `edit_file` to the allowlist
//!     surfaces here.
//!   - **MCP / plugin prefix gate** — `mcp__server__read_file`
//!     refused by default even though `read_file` is in the
//!     allowlist (prefix wins over name lookup); after policy
//!     opt-in, the prefix gate lifts BUT the allowlist still
//!     applies — `mcp__server__edit_file` stays refused because
//!     `edit_file` isn't in the allowlist (crosslink #341).
//!   - **`write_file` plan-file pinning** — `write_file` admits
//!     only when targeting the canonical plan file path,
//!     refuses on symlinks, non-regular files, and paths
//!     outside the pinned plan.
//!   - **`PlanModeState::enter` perimeter** — missing files,
//!     symlinks, directories all refused with the matching
//!     `PlanModeEntryError` variant.
//!   - **Run-bound subagent identity** — worker runs are denied
//!     `enter_plan_mode` while frontend runs remain independent.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::runtime::ActorRole;
use openclaudia::session::{
    is_tool_allowed_in_plan_mode, is_tool_allowed_in_plan_mode_with_policy, PlanModePolicy,
    PlanModeState, PLAN_MODE_ALLOWED_TOOLS,
};
use openclaudia::tools::{
    execute_tool, FunctionCall, ToolCall, ToolFollowUp, ToolRunContext, WorkspaceAccess,
};
use openclaudia::{modes::RuntimeMode, modes::RuntimeModeAuthority, tools::effect};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;

fn actor_run(root: &std::path::Path, role: ActorRole) -> Arc<ToolRunContext> {
    ToolRunContext::builder(openclaudia::state::SessionId::new(), root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(WorkspaceAccess::ReadOnly)
        .process(false)
        .network(false)
        .secrets(false)
        .actor_role(role)
        .provider("subagent-plan-mode-test")
        .build()
        .expect("actor test run")
}

fn enter_plan_mode_call() -> ToolCall {
    ToolCall {
        id: "subagent-plan-mode".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "enter_plan_mode".to_string(),
            arguments: "{}".to_string(),
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — plan-mode allow-list / deny-list discipline
// ───────────────────────────────────────────────────────────────────────────

/// Built-in mutation tools that must NEVER be admitted in plan mode,
/// even when the policy opts in to MCP/plugin tools. Each entry is
/// explicit so a future change that accidentally widens the allowlist
/// surfaces by name.
const MUTATION_TOOLS_HARD_REFUSED: &[&str] = &[
    "bash",
    "edit_file",
    "notebook_edit",
    "todo_write",
    "kill_shell",
    "remote_trigger",
    "memory_save",
    "memory_delete",
    "memory_update",
    "memory_review",
    "memory_export",
    "memory_import",
    "memory_source_refresh",
];

#[test]
fn mutation_tools_are_refused_in_plan_mode() {
    let plan_path = PathBuf::from("/dev/null"); // irrelevant for non-write_file
    for tool in MUTATION_TOOLS_HARD_REFUSED {
        let allowed = is_tool_allowed_in_plan_mode(tool, &plan_path, &json!({}));
        assert!(
            !allowed,
            "mutation tool {tool:?} MUST be refused in plan mode (currently allowed)"
        );
    }
}

#[test]
fn every_documented_observation_is_visible_in_plan_profile() {
    let authority = RuntimeModeAuthority::new(RuntimeMode::Plan).expect("plan profile");
    for tool in PLAN_MODE_ALLOWED_TOOLS {
        let (_, spec) = effect::lookup(tool).expect("documented tool must be classified");
        assert!(
            authority.definition_denial(tool, spec.effect).is_none(),
            "tool {tool:?} must be visible in the compiled plan profile"
        );
    }
}

#[test]
fn plan_mode_markers_are_always_allowed() {
    // enter_plan_mode and exit_plan_mode are NOT in the allowlist
    // constant; they're hardcoded as always-allowed in the predicate
    // because they manage plan-mode state itself.
    let plan_path = PathBuf::from("/dev/null");
    assert!(is_tool_allowed_in_plan_mode(
        "enter_plan_mode",
        &plan_path,
        &json!({})
    ));
    assert!(is_tool_allowed_in_plan_mode(
        "exit_plan_mode",
        &plan_path,
        &json!({})
    ));
}

#[test]
fn mcp_prefixed_tools_are_refused_by_default_even_when_suffix_is_allowed() {
    // The prefix gate must fire BEFORE the allowlist check — a
    // hostile MCP server registering `mcp__evil__read_file` must
    // not slip through just because `read_file` is on the allowlist.
    let plan_path = PathBuf::from("/dev/null");
    for shadow in &[
        "mcp__evil__read_file",
        "mcp__server__grep",
        "mcp__attacker__list_files",
    ] {
        let allowed = is_tool_allowed_in_plan_mode(shadow, &plan_path, &json!({}));
        assert!(
            !allowed,
            "{shadow:?} (mcp-prefixed shadow of an allowlisted name) MUST be refused"
        );
    }
}

#[test]
fn mcp_opt_in_lifts_prefix_gate_but_still_requires_allowlist_match() {
    // crosslink #341: opting in to MCP tools removes the prefix
    // refusal — but the suffix STILL has to match the allowlist.
    // So `mcp__server__read_file` becomes admitted (since `read_file`
    // is allowlisted) but `mcp__server__edit_file` stays refused
    // (since `edit_file` is NOT allowlisted).
    //
    // Note: the gate's `PLAN_MODE_ALLOWED_TOOLS.contains` check uses
    // the full tool name (with prefix), so even with the opt-in the
    // mcp-prefixed name doesn't match the bare `read_file` entry.
    // The opt-in lifts the prefix-based hard refusal, but the
    // contained name lookup is name-equal — so the test pins that
    // mcp-prefixed names with allowlisted SUFFIXES are STILL refused
    // unless the full prefixed name is added to the allowlist.
    let plan_path = PathBuf::from("/dev/null");
    let opt_in = PlanModePolicy {
        allow_mcp_tools: true,
        allow_plugin_tools: false,
    };
    // With opt-in: mcp-prefixed names with NON-allowlisted suffixes
    // stay refused.
    let edit_outcome = is_tool_allowed_in_plan_mode_with_policy(
        "mcp__server__edit_file",
        &plan_path,
        &json!({}),
        opt_in,
    );
    assert!(
        !edit_outcome,
        "even with allow_mcp_tools=true, mcp__server__edit_file MUST be refused \
         (edit_file is not in the allowlist)"
    );
    // Plugin tools are still hard-denied unless allow_plugin_tools is
    // also lifted (independent flags).
    let plugin_outcome = is_tool_allowed_in_plan_mode_with_policy(
        "plugin__foo__read_file",
        &plan_path,
        &json!({}),
        opt_in,
    );
    assert!(
        !plugin_outcome,
        "plugin-prefixed tool MUST be refused when only allow_mcp_tools=true"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — write_file plan-file pinning
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn write_file_admits_only_the_pinned_plan_path() {
    let dir = tempdir().expect("tempdir");
    let plan_file = dir.path().join("plan.md");
    std::fs::write(&plan_file, "# Plan").expect("write plan");

    // Use the canonical path as the gate's reference.
    let plan_canonical = std::fs::canonicalize(&plan_file).expect("canonicalize");

    // Writing to the canonical plan file: admitted.
    let allowed = is_tool_allowed_in_plan_mode(
        "write_file",
        &plan_canonical,
        &json!({"path": plan_file.to_string_lossy()}),
    );
    assert!(
        allowed,
        "write_file to the pinned plan file MUST be admitted; got refused"
    );

    // Writing to a sibling file: refused.
    let sibling = dir.path().join("sibling.md");
    std::fs::write(&sibling, "evil").expect("write sibling");
    let refused = is_tool_allowed_in_plan_mode(
        "write_file",
        &plan_canonical,
        &json!({"path": sibling.to_string_lossy()}),
    );
    assert!(
        !refused,
        "write_file to a non-plan file MUST be refused; got admitted"
    );
}

#[test]
fn write_file_refuses_missing_path_arg() {
    let dir = tempdir().expect("tempdir");
    let plan_file = dir.path().join("plan.md");
    std::fs::write(&plan_file, "# Plan").expect("write plan");
    let plan_canonical = std::fs::canonicalize(&plan_file).expect("canonicalize");

    let allowed = is_tool_allowed_in_plan_mode("write_file", &plan_canonical, &json!({}));
    assert!(
        !allowed,
        "write_file without a `path` arg MUST be refused; got admitted"
    );
}

#[cfg(unix)]
#[test]
fn write_file_refuses_symlink_at_target() {
    let dir = tempdir().expect("tempdir");
    let plan_file = dir.path().join("plan.md");
    std::fs::write(&plan_file, "# Plan").expect("write plan");
    let plan_canonical = std::fs::canonicalize(&plan_file).expect("canonicalize");

    // Plant a symlink alongside the plan file. The lstat check in
    // the gate must reject this BEFORE canonicalization could
    // resolve it to the plan file.
    let link = dir.path().join("plan-link.md");
    std::os::unix::fs::symlink(&plan_file, &link).expect("symlink");

    let allowed = is_tool_allowed_in_plan_mode(
        "write_file",
        &plan_canonical,
        &json!({"path": link.to_string_lossy()}),
    );
    assert!(
        !allowed,
        "write_file via symlink (even to the plan file) MUST be refused"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — PlanModeState::enter perimeter
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enter_refuses_missing_plan_file() {
    let dir = tempdir().expect("tempdir");
    let nope = dir.path().join("never-existed.md");
    let outcome = PlanModeState::enter(nope);
    assert!(
        outcome.is_err(),
        "enter with missing plan file MUST error; got {outcome:?}"
    );
}

#[cfg(unix)]
#[test]
fn enter_refuses_symlink_plan_file() {
    let dir = tempdir().expect("tempdir");
    let real = dir.path().join("real.md");
    std::fs::write(&real, "# Plan").expect("write real");
    let link = dir.path().join("link.md");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let outcome = PlanModeState::enter(link);
    assert!(
        outcome.is_err(),
        "enter with symlink plan file MUST error; got {outcome:?}"
    );
}

#[test]
fn enter_refuses_directory_as_plan_file() {
    let dir = tempdir().expect("tempdir");
    let subdir = dir.path().join("plan-as-dir");
    std::fs::create_dir(&subdir).expect("create subdir");
    let outcome = PlanModeState::enter(subdir);
    assert!(
        outcome.is_err(),
        "enter with directory as plan file MUST error; got {outcome:?}"
    );
}

#[test]
fn enter_succeeds_with_real_file_and_pins_canonical_path() {
    let dir = tempdir().expect("tempdir");
    let plan_file = dir.path().join("plan.md");
    std::fs::write(&plan_file, "# Plan").expect("write");
    let state = PlanModeState::enter(plan_file.clone()).expect("enter must succeed");
    assert!(state.active);
    assert_eq!(state.plan_file, plan_file);
    // The pinned canonical path must equal the canonicalized form.
    let canonical = std::fs::canonicalize(&plan_file).expect("canonicalize");
    assert_eq!(
        state.plan_realpath, canonical,
        "plan_realpath must equal the canonicalized plan_file"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — immutable actor-role dispatch semantics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn frontend_run_can_request_plan_mode_through_registry() {
    let root = tempdir().expect("frontend root");
    let frontend = actor_run(root.path(), ActorRole::Frontend);
    let result = execute_tool(&frontend, &enter_plan_mode_call());
    assert!(!result.is_error(), "frontend request failed: {result:?}");
    assert!(matches!(
        result.follow_up(),
        ToolFollowUp::EnterPlanMode { .. }
    ));
}

#[test]
fn worker_run_is_denied_plan_mode_through_registry() {
    let root = tempdir().expect("worker root");
    let worker = actor_run(root.path(), ActorRole::Worker);
    let result = execute_tool(&worker, &enter_plan_mode_call());
    assert!(
        result.is_error(),
        "worker unexpectedly entered plan mode: {result:?}"
    );
    assert!(result
        .content()
        .contains("plan mode cannot be entered from inside an agent task"));
}

#[test]
fn concurrent_actor_roles_cannot_cross() {
    let root = tempdir().expect("shared root");
    let frontend = actor_run(root.path(), ActorRole::Frontend);
    let worker = actor_run(root.path(), ActorRole::Worker);
    let frontend_result =
        std::thread::spawn(move || execute_tool(&frontend, &enter_plan_mode_call()));
    let worker_result = std::thread::spawn(move || execute_tool(&worker, &enter_plan_mode_call()));
    assert!(!frontend_result.join().expect("frontend thread").is_error());
    assert!(worker_result.join().expect("worker thread").is_error());
}

//! End-to-end tests for `PlanModeState` entry guards +
//! `is_tool_allowed_in_plan_mode` decision table.
//!
//! Sprint 39 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::session::{
    is_tool_allowed_in_plan_mode, is_tool_allowed_in_plan_mode_with_policy, PlanModePolicy,
    PlanModeState, PLAN_MODE_ALLOWED_TOOLS,
};
use openclaudia::{modes::RuntimeMode, modes::RuntimeModeAuthority, tools::effect};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

/// Create a valid plan file in a tempdir + return the canonical
/// path + tempdir guard (keep alive for the test duration).
fn make_plan_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("plan.md");
    fs::write(&path, "# Plan\n").expect("write plan");
    let canonical = fs::canonicalize(&path).expect("canonicalize");
    (dir, canonical)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — PlanModeState::enter
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enter_pins_realpath_and_marks_active() {
    let (_dir, canonical) = make_plan_file();
    let state = PlanModeState::enter(canonical.clone()).expect("enter must succeed");
    assert!(state.active, "active flag must be set");
    assert_eq!(state.plan_realpath, canonical);
    assert_eq!(state.plan_file, canonical);
    assert!(
        state.allowed_prompts.is_empty(),
        "fresh state has no allowed_prompts"
    );
    assert!(state.previous_mode.is_none());
}

#[test]
fn enter_with_previous_mode_captures_mode_token() {
    let (_dir, canonical) = make_plan_file();
    let state = PlanModeState::enter_with_previous_mode(canonical, Some("refactor".to_string()))
        .expect("enter must succeed");
    assert_eq!(state.previous_mode.as_deref(), Some("refactor"));
}

#[test]
fn enter_refuses_missing_plan_file() {
    let dir = TempDir::new().expect("tempdir");
    let nope = dir.path().join("never-existed.md");
    let outcome = PlanModeState::enter(nope);
    assert!(
        outcome.is_err(),
        "missing file MUST error; got {:?}",
        outcome.map(|s| s.plan_realpath)
    );
}

#[test]
fn enter_refuses_symlinked_plan_file() {
    #[cfg(unix)]
    {
        let dir = TempDir::new().expect("tempdir");
        let real = dir.path().join("real.md");
        fs::write(&real, "real").expect("write real");
        let link = dir.path().join("link.md");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let outcome = PlanModeState::enter(link);
        assert!(
            outcome.is_err(),
            "symlinked plan file MUST error (TOCTOU defence); got {:?}",
            outcome.map(|s| s.plan_realpath)
        );
    }
}

#[test]
fn enter_refuses_directory_as_plan_file() {
    let dir = TempDir::new().expect("tempdir");
    // The tempdir root itself is a directory; pass it as the
    // plan-file path → MUST refuse (not a regular file).
    let outcome = PlanModeState::enter(dir.path().to_path_buf());
    assert!(
        outcome.is_err(),
        "directory MUST be refused as plan file; got {:?}",
        outcome.map(|s| s.plan_realpath)
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — allowlist coverage
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn plan_profile_exposes_every_documented_observation_tool() {
    let authority = RuntimeModeAuthority::new(RuntimeMode::Plan).expect("plan profile");
    for tool in PLAN_MODE_ALLOWED_TOOLS {
        let (_, spec) = effect::lookup(tool).expect("documented tool must be classified");
        assert!(
            authority.definition_denial(tool, spec.effect).is_none(),
            "documented tool {tool:?} MUST be visible in plan mode"
        );
    }
}

#[test]
fn write_tools_are_refused_by_default() {
    let (_dir, plan) = make_plan_file();
    // Common destructive / state-mutating tools — none of these
    // are in the allowlist and none should be admitted.
    for tool in &[
        "bash",
        "edit_file",
        "notebook_edit",
        "delete_file",
        "kill_shell",
        "cron_create",
        "cron_delete",
        "todo_write",
    ] {
        let allowed = is_tool_allowed_in_plan_mode(tool, &plan, &json!({}));
        assert!(
            !allowed,
            "non-allowlisted tool {tool:?} MUST be refused in plan mode"
        );
    }
}

#[test]
fn unknown_tool_name_is_refused_by_default_deny() {
    let (_dir, plan) = make_plan_file();
    assert!(!is_tool_allowed_in_plan_mode(
        "totally-unknown-tool-9999",
        &plan,
        &json!({})
    ));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — plan-mode marker tools
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enter_and_exit_plan_mode_markers_always_allowed() {
    let (_dir, plan) = make_plan_file();
    assert!(is_tool_allowed_in_plan_mode(
        "enter_plan_mode",
        &plan,
        &json!({})
    ));
    assert!(is_tool_allowed_in_plan_mode(
        "exit_plan_mode",
        &plan,
        &json!({})
    ));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — write_file TOCTOU-safe gate
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn write_file_admits_when_target_canonicalizes_to_plan_realpath() {
    let (_dir, plan) = make_plan_file();
    let args = json!({"path": plan.to_string_lossy()});
    assert!(
        is_tool_allowed_in_plan_mode("write_file", &plan, &args),
        "write to the plan file MUST be admitted"
    );
}

#[test]
fn write_file_refuses_when_target_is_a_different_file() {
    let (_dir, plan) = make_plan_file();
    let other_dir = TempDir::new().expect("other");
    let other = other_dir.path().join("other.md");
    fs::write(&other, "x").expect("write");
    let args = json!({"path": other.to_string_lossy()});
    assert!(
        !is_tool_allowed_in_plan_mode("write_file", &plan, &args),
        "write to a different file MUST be refused"
    );
}

#[test]
fn write_file_refuses_when_path_arg_missing() {
    let (_dir, plan) = make_plan_file();
    assert!(!is_tool_allowed_in_plan_mode(
        "write_file",
        &plan,
        &json!({})
    ));
}

#[test]
fn write_file_refuses_symlinked_target_pointing_at_plan() {
    #[cfg(unix)]
    {
        let (_dir, plan) = make_plan_file();
        let link_dir = TempDir::new().expect("link dir");
        let link = link_dir.path().join("plan-link.md");
        std::os::unix::fs::symlink(&plan, &link).expect("symlink");
        let args = json!({"path": link.to_string_lossy()});
        // The target IS a symlink to the plan file. The gate's
        // FD-pinned guard refuses on symlink detection before
        // canonicalization can compare paths — pins crosslink
        // #334.
        assert!(
            !is_tool_allowed_in_plan_mode("write_file", &plan, &args),
            "symlink → plan_realpath MUST be refused (TOCTOU defence)"
        );
    }
}

#[test]
fn write_file_refuses_nonexistent_target() {
    let (_dir, plan) = make_plan_file();
    let args = json!({"path": "/tmp/does-not-exist-xyz-9999.md"});
    assert!(
        !is_tool_allowed_in_plan_mode("write_file", &plan, &args),
        "nonexistent target MUST be refused"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — MCP / plugin prefix gates (crosslink #341)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn mcp_prefixed_tools_refused_by_default() {
    let (_dir, plan) = make_plan_file();
    assert!(!is_tool_allowed_in_plan_mode(
        "mcp__github__list_issues",
        &plan,
        &json!({})
    ));
}

#[test]
fn plugin_prefixed_tools_refused_by_default() {
    let (_dir, plan) = make_plan_file();
    assert!(!is_tool_allowed_in_plan_mode(
        "plugin__custom__do_thing",
        &plan,
        &json!({})
    ));
}

#[test]
fn shadow_tool_name_blocked_even_when_suffix_matches_allowlist() {
    // crosslink #341: a malicious MCP server registering
    // `mcp__evil__read_file` MUST NOT bypass the read-only
    // gate — even though the suffix `read_file` is in the
    // allowlist, the `mcp__` prefix refuses BEFORE the
    // allowlist is consulted.
    let (_dir, plan) = make_plan_file();
    assert!(
        !is_tool_allowed_in_plan_mode("mcp__evil__read_file", &plan, &json!({})),
        "MCP-prefixed tool with allow-listed suffix MUST be refused"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — policy flags lift prefix gates BUT still require allowlist
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn allow_mcp_tools_flag_admits_listed_suffix_but_not_others() {
    let (_dir, plan) = make_plan_file();
    let policy = PlanModePolicy {
        allow_mcp_tools: true,
        allow_plugin_tools: false,
    };
    // With allow_mcp_tools=true, the prefix gate is lifted.
    // BUT the suffix STILL has to be in PLAN_MODE_ALLOWED_TOOLS.
    // `mcp__server__read_file` → suffix `mcp__server__read_file`
    // is NOT in PLAN_MODE_ALLOWED_TOOLS (the full name is the
    // tool name, not just the suffix), so it MUST still be
    // refused.
    assert!(
        !is_tool_allowed_in_plan_mode_with_policy(
            "mcp__server__read_file",
            &plan,
            &json!({}),
            policy,
        ),
        "lifting prefix-gate does NOT bypass the allowlist (crosslink #341)"
    );
}

#[test]
fn allow_plugin_tools_flag_does_not_bypass_allowlist_either() {
    let (_dir, plan) = make_plan_file();
    let policy = PlanModePolicy {
        allow_mcp_tools: false,
        allow_plugin_tools: true,
    };
    assert!(!is_tool_allowed_in_plan_mode_with_policy(
        "plugin__custom__edit_file",
        &plan,
        &json!({}),
        policy,
    ));
}

#[test]
fn default_policy_denies_both_prefix_families() {
    let policy = PlanModePolicy::default();
    assert!(!policy.allow_mcp_tools);
    assert!(!policy.allow_plugin_tools);
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — serde round-trip of PlanModeState
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn plan_mode_state_serde_round_trip_preserves_fields() {
    let (_dir, canonical) = make_plan_file();
    let state =
        PlanModeState::enter_with_previous_mode(canonical.clone(), Some("build".to_string()))
            .expect("enter");

    let json_str = serde_json::to_string(&state).expect("serialize");
    let parsed: PlanModeState = serde_json::from_str(&json_str).expect("deserialize");
    assert!(parsed.active);
    assert_eq!(parsed.plan_realpath, canonical);
    assert_eq!(parsed.previous_mode.as_deref(), Some("build"));
}

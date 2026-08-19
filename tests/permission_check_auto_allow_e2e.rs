//! End-to-end tests for `permissions::PermissionManager::check_auto_allow`
//! — the threshold-based classifier gate that auto-Allows when
//! the score meets the threshold, falls through to normal
//! `check()` otherwise, and short-circuits to Denied when an
//! explicit deny rule matches. Pins #571 contract.
//!
//! Sprint 214 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::permissions::{
    CheckResult, PermissionDecision, PermissionManager, PermissionRule,
};
use serde_json::json;
use tempfile::TempDir;

fn fresh_manager() -> (PermissionManager, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("rules.json");
    let mgr = PermissionManager::new(path, true, Vec::new());
    (mgr, dir)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Read-only tool (score 1.0) auto-allows at any threshold
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn read_only_tool_auto_allows_at_threshold_1_0() {
    // PINS DOC: read-only tools (no permission target) → score 1.0.
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("list_files", &json!({}), 1.0);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn read_only_tool_auto_allows_at_threshold_0_5() {
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("list_files", &json!({}), 0.5);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn read_only_tool_auto_allows_even_with_threshold_just_under_1() {
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("list_files", &json!({}), 0.99);
    assert_eq!(outcome, CheckResult::Allowed);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Bash safe-verb (score 0.95) threshold boundary
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn bash_ls_meets_threshold_0_9() {
    // PINS DOC: Bash with "ls" prefix → score 0.95.
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "ls /tmp"}), 0.9);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn bash_cat_meets_threshold_0_9() {
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "cat /etc/hostname"}), 0.9);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn bash_pwd_meets_threshold_0_9() {
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "pwd"}), 0.9);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn bash_echo_meets_threshold_0_9() {
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "echo hello"}), 0.9);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn bash_git_status_meets_threshold_0_9() {
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "git status"}), 0.9);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn bash_ls_does_not_meet_threshold_0_96() {
    // PINS BOUND: ls score is 0.95 < 0.96 → falls through.
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "ls /tmp"}), 0.96);
    // Falls through to check() → NeedsPrompt (no matching rule).
    assert!(matches!(outcome, CheckResult::NeedsPrompt { .. }));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Unsafe Bash (score 0.0) never auto-allows
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn bash_rm_rf_is_hard_denied_before_classifier_allows() {
    // PINS DOC: hard safety beats classifier scoring.
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "rm -rf /tmp/x"}), 0.1);
    assert!(matches!(outcome, CheckResult::Denied(_)));
}

#[test]
fn bash_sudo_does_not_auto_allow() {
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "sudo something"}), 0.5);
    assert!(matches!(outcome, CheckResult::NeedsPrompt { .. }));
}

#[test]
fn bash_zero_score_at_threshold_0_does_not_auto_allow() {
    // PINS BOUND: zero is a veto score, not a valid auto-allow score,
    // even when the configured threshold is exactly 0.0.
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "sudo something"}), 0.0);
    assert!(matches!(outcome, CheckResult::NeedsPrompt { .. }));
}

#[test]
fn bash_dangerous_construct_does_not_auto_allow_despite_safe_prefix() {
    // `echo` is a high-scoring safe prefix by itself, but piping it into
    // an interpreter is a Bash-policy dangerous construct and must prompt.
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "echo hi | sh"}), 0.9);
    assert!(matches!(outcome, CheckResult::NeedsPrompt { .. }));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Edit/Write src/ paths (score 0.6)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn edit_src_path_meets_threshold_0_5() {
    // PINS DOC: Edit/Write under src/ → score 0.6.
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("edit_file", &json!({"path": "src/main.rs"}), 0.5);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn write_tests_path_meets_threshold_0_5() {
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("write_file", &json!({"path": "tests/foo.rs"}), 0.5);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn edit_src_path_does_not_meet_threshold_0_7() {
    // PINS BOUND: 0.6 < 0.7 → falls through.
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("edit_file", &json!({"path": "src/main.rs"}), 0.7);
    // Falls through to check() → NeedsPrompt.
    assert!(matches!(outcome, CheckResult::NeedsPrompt { .. }));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Explicit deny rule short-circuits classifier
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn explicit_deny_rule_overrides_high_score() {
    // PINS DOC: Deny rule short-circuits regardless of score.
    let (mut mgr, _dir) = fresh_manager();
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "ls*".to_string(),
        decision: PermissionDecision::Deny,
    });
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "ls"}), 0.5);
    // ls has score 0.95 but deny wins.
    assert!(matches!(outcome, CheckResult::Denied(_)));
}

#[test]
fn explicit_deny_rule_overrides_read_only_tool_score_1_0() {
    let (mut mgr, _dir) = fresh_manager();
    // Read-only is now a positive effect declaration with a concrete `Read`
    // capability and path target. The deny must be evaluated before the 1.0
    // score/default-read allowance.
    mgr.add_session_rule(PermissionRule {
        tool: "Read".to_string(),
        pattern: "/secret/**".to_string(),
        decision: PermissionDecision::Deny,
    });
    let outcome = mgr.check_auto_allow("list_files", &json!({"path": "/secret/data"}), 0.5);
    assert!(
        matches!(outcome, CheckResult::Denied(_)),
        "a declared read-only effect must not make an explicit path denial unreachable"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Determinism + boundary semantics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn check_auto_allow_with_threshold_exactly_equal_to_score_allows() {
    // PINS BOUND: `score >= threshold` is inclusive.
    let (mgr, _dir) = fresh_manager();
    // ls = 0.95. threshold 0.95 means exactly equal → allow.
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "ls"}), 0.95);
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn check_auto_allow_is_deterministic() {
    let (mgr, _dir) = fresh_manager();
    let args = json!({"command": "ls"});
    let r1 = mgr.check_auto_allow("bash", &args, 0.5);
    let r2 = mgr.check_auto_allow("bash", &args, 0.5);
    let r3 = mgr.check_auto_allow("bash", &args, 0.5);
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

#[test]
fn check_auto_allow_does_not_mutate_manager_state() {
    let (mgr, _dir) = fresh_manager();
    let _ = mgr.check_auto_allow("bash", &json!({"command": "ls"}), 0.5);
    // No rule was added.
    assert!(mgr.session_rules().is_empty());
    assert!(mgr.persisted_rules().is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Threshold extremes
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn check_auto_allow_with_threshold_1_0_only_allows_perfect_score() {
    // PINS BOUND: threshold 1.0 means only score=1.0 (read-only) allows.
    let (mgr, _dir) = fresh_manager();
    // Bash ls = 0.95 < 1.0 → falls through.
    let outcome = mgr.check_auto_allow("bash", &json!({"command": "ls"}), 1.0);
    assert!(matches!(outcome, CheckResult::NeedsPrompt { .. }));
}

#[test]
fn check_auto_allow_with_threshold_above_1_0_never_allows_via_classifier() {
    // Even threshold 1.5 — the highest possible classifier
    // score is 1.0 → no score meets the bar.
    let (mgr, _dir) = fresh_manager();
    let outcome = mgr.check_auto_allow("list_files", &json!({}), 1.5);
    // list_files positively declares ReadOnly, so the underlying policy allows
    // it independently of whether the classifier threshold was attainable.
    assert_eq!(outcome, CheckResult::Allowed);
}

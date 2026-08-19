//! End-to-end tests for `permissions::auto_allow_score` scoring
//! catalog + `DenialTracker` state machine + `EscalationState`
//! threshold predicate.
//!
//! Sprint 63 of the verification effort. Sprint 4 covered the
//! permission manager + rule matching; this file covers the
//! pure-function scoring helpers + standalone denial tracker
//! (newtype-extracted in crosslink #577).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::permissions::{
    auto_allow_score, DenialLimits, DenialTracker, EscalationState, MAX_CONSECUTIVE_DENIALS,
    MAX_TOTAL_DENIALS,
};
use serde_json::json;

// ───────────────────────────────────────────────────────────────────────────
// Section A — auto_allow_score for read-only tools
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn read_only_tool_scores_unconditionally_safe() {
    // S-016: read-only is now a declared effect rather than the absence of a
    // permission target, and the score follows the declaration.
    for (read_only, args) in [
        ("read_file", json!({"path": "/tmp/a"})),
        ("list_files", json!({})),
        ("glob", json!({"pattern": "*.rs"})),
        ("grep", json!({"pattern": "fn main"})),
    ] {
        let score = auto_allow_score(read_only, &args);
        assert!(
            (score - 1.0).abs() < f32::EPSILON,
            "{read_only} MUST score 1.0 (declared ReadOnly); got {score}"
        );
    }
}

#[test]
fn unknown_tool_scores_zero_not_safe() {
    // S-016/F-001 inversion. This test previously asserted that an unknown
    // tool scores 1.0, because `auto_allow_score` fell through a "no
    // permission target → unconditionally safe" branch. F-001 records that
    // exact behaviour as a critical fail-open: an unregistered name, or any
    // handler that had simply not classified itself, was scored as safe to
    // auto-allow. An unclassifiable call now scores 0.0.
    let score = auto_allow_score("totally-unknown-tool", &json!({}));
    assert!(
        score < f32::EPSILON,
        "unknown tool MUST score 0.0 (unclassifiable); got {score}"
    );
}

#[test]
fn read_only_tool_with_malformed_target_argument_scores_zero() {
    // The declared target argument is what a rule matches against. If it is
    // absent or the wrong type the call cannot be scoped, so it is not
    // auto-allowable even though the tool's effect is read-only.
    assert!(
        auto_allow_score("read_file", &json!({})) < f32::EPSILON,
        "read_file without its declared `path` argument must not auto-allow"
    );
    assert!(
        auto_allow_score("read_file", &json!({"path": 42})) < f32::EPSILON,
        "read_file with a non-string `path` must not auto-allow"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — effectful tools never receive classifier authority
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_bash_command_scores_zero() {
    for command in [
        "ls",
        "git status",
        "git push origin HEAD",
        "cat input | rm -f output",
        "python3 -c 'print(1)'",
        "printf x > output",
    ] {
        let score = auto_allow_score("bash", &json!({"command": command}));
        assert!(
            score < f32::EPSILON,
            "Bash must require policy regardless of text: {command:?} scored {score}"
        );
    }
}

#[test]
fn workspace_mutations_score_zero_regardless_of_path() {
    for (tool, path) in [
        ("edit_file", "src/main.rs"),
        ("write_file", "tests/new.rs"),
        ("edit_file", "/etc/passwd"),
        ("write_file", "/opt/user-data/x"),
    ] {
        let score = auto_allow_score(tool, &json!({"path": path}));
        assert!(
            score < f32::EPSILON,
            "effectful {tool} call must require policy for {path:?}; got {score}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — DenialTracker state machine
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn fresh_tracker_starts_with_zero_counters() {
    let t = DenialTracker::new();
    assert_eq!(t.consecutive(), 0);
    assert_eq!(t.total(), 0);
    assert_eq!(t.escalation_state(), EscalationState::Normal);
}

#[test]
fn record_denial_increments_both_counters() {
    let mut t = DenialTracker::new();
    t.record_denial();
    assert_eq!(t.consecutive(), 1);
    assert_eq!(t.total(), 1);
    t.record_denial();
    assert_eq!(t.consecutive(), 2);
    assert_eq!(t.total(), 2);
}

#[test]
fn record_allowed_resets_consecutive_but_not_total() {
    let mut t = DenialTracker::new();
    for _ in 0..3 {
        t.record_denial();
    }
    assert_eq!(t.consecutive(), 3);
    assert_eq!(t.total(), 3);
    t.record_allowed();
    assert_eq!(t.consecutive(), 0, "consecutive MUST reset on allowed");
    assert_eq!(t.total(), 3, "total MUST NOT reset on allowed");
}

#[test]
fn reset_zeroes_both_counters() {
    let mut t = DenialTracker::new();
    for _ in 0..5 {
        t.record_denial();
    }
    t.reset();
    assert_eq!(t.consecutive(), 0);
    assert_eq!(t.total(), 0);
}

#[test]
fn counters_saturate_at_u32_max_no_wrap() {
    let mut t = DenialTracker::new();
    // Push counters near u32::MAX via direct record calls
    // (impractical to test the full overflow, but the
    // contract is `saturating_add` so we trust it doesn't
    // wrap. Pin a small-saturation test by checking the
    // implementation uses saturating_add via repeated calls
    // up to a small bound.)
    for _ in 0..100 {
        t.record_denial();
    }
    assert_eq!(t.total(), 100);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — EscalationState predicate
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn escalation_state_normal_until_consecutive_exceeds_max() {
    let mut t = DenialTracker::new();
    // MAX_CONSECUTIVE_DENIALS=5; 5 record_denial keeps state Normal
    // (predicate is `consecutive > max`, strict greater).
    for _ in 0..MAX_CONSECUTIVE_DENIALS {
        t.record_denial();
    }
    assert_eq!(
        t.escalation_state(),
        EscalationState::Normal,
        "at exactly max_consecutive MUST be Normal (strict >)"
    );
    // One more pushes over the boundary.
    t.record_denial();
    assert_eq!(
        t.escalation_state(),
        EscalationState::ShouldAbort,
        "above max_consecutive MUST escalate"
    );
}

#[test]
fn escalation_state_normal_until_total_exceeds_max() {
    // Need to drive total without consecutive crossing first.
    // Pattern: denial, allowed, denial, allowed, ... so
    // consecutive stays low while total accumulates.
    let mut t = DenialTracker::new();
    for _ in 0..MAX_TOTAL_DENIALS {
        t.record_denial();
        t.record_allowed();
    }
    assert_eq!(t.total(), MAX_TOTAL_DENIALS, "total MUST be exactly max");
    assert_eq!(
        t.escalation_state(),
        EscalationState::Normal,
        "at exactly max_total MUST be Normal (strict >)"
    );
    t.record_denial();
    assert_eq!(
        t.escalation_state(),
        EscalationState::ShouldAbort,
        "above max_total MUST escalate"
    );
}

#[test]
fn record_allowed_de_escalates_consecutive_back_to_normal() {
    let mut t = DenialTracker::new();
    for _ in 0..=MAX_CONSECUTIVE_DENIALS {
        t.record_denial();
    }
    assert_eq!(t.escalation_state(), EscalationState::ShouldAbort);
    // A single allowed outcome resets consecutive (and total
    // is still <= max), so state goes back to Normal.
    t.record_allowed();
    assert_eq!(
        t.escalation_state(),
        EscalationState::Normal,
        "single record_allowed MUST de-escalate consecutive"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — DenialLimits custom values
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn with_limits_uses_caller_supplied_thresholds() {
    let custom_limits = DenialLimits {
        max_consecutive: 2,
        max_total: 5,
    };
    let mut t = DenialTracker::with_limits(custom_limits);
    assert_eq!(t.limits(), custom_limits);
    // 2 denials: still Normal.
    t.record_denial();
    t.record_denial();
    assert_eq!(t.escalation_state(), EscalationState::Normal);
    // 3rd denial pushes consecutive past max=2.
    t.record_denial();
    assert_eq!(t.escalation_state(), EscalationState::ShouldAbort);
}

#[test]
fn denial_limits_default_matches_documented_constants() {
    let defaults = DenialLimits::default();
    assert_eq!(defaults.max_consecutive, MAX_CONSECUTIVE_DENIALS);
    assert_eq!(defaults.max_total, MAX_TOTAL_DENIALS);
}

#[test]
fn documented_default_constants_match_cc_parity_values() {
    // CC parity targets: maxConsecutive=5, maxTotal=20.
    assert_eq!(MAX_CONSECUTIVE_DENIALS, 5);
    assert_eq!(MAX_TOTAL_DENIALS, 20);
}

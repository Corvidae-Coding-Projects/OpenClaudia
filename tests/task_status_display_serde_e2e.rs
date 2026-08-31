//! End-to-end tests for `session::TaskStatus` —
//! `Display`, `snake_case` serde, and the complete typed lifecycle.
//!
//! Sprint 206 of the verification effort. Sprint 30/etc.
//! covered `Task` management via `TaskManager`; this file
//! pins the `TaskStatus` enum surface directly.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::session::TaskStatus;
use serde_json::{json, Value};

const ALL_STATUSES: [TaskStatus; 5] = [
    TaskStatus::Pending,
    TaskStatus::InProgress,
    TaskStatus::Completed,
    TaskStatus::Failed,
    TaskStatus::Canceled,
];

// ───────────────────────────────────────────────────────────────────────────
// Section A — Display
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn display_pending_renders_lowercase_pending() {
    assert_eq!(TaskStatus::Pending.to_string(), "pending");
}

#[test]
fn display_in_progress_renders_snake_case_in_progress() {
    // PINS DOC: in_progress (snake_case, NOT camelCase).
    assert_eq!(TaskStatus::InProgress.to_string(), "in_progress");
}

#[test]
fn display_completed_renders_lowercase_completed() {
    assert_eq!(TaskStatus::Completed.to_string(), "completed");
}

#[test]
fn display_failure_states_use_canonical_lowercase_strings() {
    assert_eq!(TaskStatus::Failed.to_string(), "failed");
    assert_eq!(TaskStatus::Canceled.to_string(), "canceled");
}

#[test]
fn display_format_macro_works_with_task_status() {
    let s = format!("Status: {}", TaskStatus::InProgress);
    assert_eq!(s, "Status: in_progress");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — snake_case serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn pending_serializes_as_lowercase_pending() {
    let v: Value = serde_json::to_value(TaskStatus::Pending).expect("ser");
    assert_eq!(v, json!("pending"));
}

#[test]
fn in_progress_serializes_with_snake_case_underscore() {
    // PINS WIRE: "in_progress" (NOT "InProgress" or "inProgress").
    let v: Value = serde_json::to_value(TaskStatus::InProgress).expect("ser");
    assert_eq!(v, json!("in_progress"));
}

#[test]
fn completed_serializes_as_lowercase_completed() {
    let v: Value = serde_json::to_value(TaskStatus::Completed).expect("ser");
    assert_eq!(v, json!("completed"));
}

#[test]
fn failure_states_round_trip_from_canonical_strings() {
    for (status, wire) in [
        (TaskStatus::Failed, "failed"),
        (TaskStatus::Canceled, "canceled"),
    ] {
        assert_eq!(serde_json::to_value(status).expect("ser"), json!(wire));
        assert_eq!(
            serde_json::from_value::<TaskStatus>(json!(wire)).expect("de"),
            status
        );
    }
}

#[test]
fn pending_deserializes_from_lowercase_string() {
    let s: TaskStatus = serde_json::from_value(json!("pending")).expect("de");
    assert_eq!(s, TaskStatus::Pending);
}

#[test]
fn in_progress_deserializes_from_snake_case() {
    let s: TaskStatus = serde_json::from_value(json!("in_progress")).expect("de");
    assert_eq!(s, TaskStatus::InProgress);
}

#[test]
fn completed_deserializes_from_lowercase() {
    let s: TaskStatus = serde_json::from_value(json!("completed")).expect("de");
    assert_eq!(s, TaskStatus::Completed);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Rejection of non-snake-case forms
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn camel_case_in_progress_rejected_on_deserialize() {
    // PINS: snake_case strict — "inProgress" MUST NOT match.
    let outcome: Result<TaskStatus, _> = serde_json::from_value(json!("inProgress"));
    assert!(outcome.is_err());
}

#[test]
fn pascal_case_in_progress_rejected_on_deserialize() {
    let outcome: Result<TaskStatus, _> = serde_json::from_value(json!("InProgress"));
    assert!(outcome.is_err());
}

#[test]
fn uppercase_pending_rejected_on_deserialize() {
    let outcome: Result<TaskStatus, _> = serde_json::from_value(json!("PENDING"));
    assert!(outcome.is_err());
}

#[test]
fn unknown_status_rejected_on_deserialize() {
    let outcome: Result<TaskStatus, _> = serde_json::from_value(json!("not_a_status"));
    assert!(outcome.is_err());
}

#[test]
fn empty_string_rejected_on_deserialize() {
    let outcome: Result<TaskStatus, _> = serde_json::from_value(json!(""));
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Round-trip across the complete lifecycle
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn all_variants_round_trip_through_json() {
    for variant in ALL_STATUSES {
        let json = serde_json::to_value(variant).expect("ser");
        let back: TaskStatus = serde_json::from_value(json).expect("de");
        assert_eq!(back, variant, "round-trip failed for {variant:?}");
    }
}

#[test]
fn display_and_serde_agree_on_wire_string_for_every_variant() {
    // PINS: Display string equals the JSON wire string.
    for variant in ALL_STATUSES {
        let display_str = variant.to_string();
        let serde_str = serde_json::to_value(variant)
            .expect("ser")
            .as_str()
            .expect("str")
            .to_string();
        assert_eq!(display_str, serde_str);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — PartialEq + Copy
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn copy_preserves_variant() {
    let original = TaskStatus::InProgress;
    let copied = original;
    assert_eq!(copied, original);
}

#[test]
fn variants_are_pairwise_distinct_under_partial_eq() {
    for (index, left) in ALL_STATUSES.iter().enumerate() {
        for right in &ALL_STATUSES[index + 1..] {
            assert_ne!(left, right);
        }
    }
}

#[test]
fn debug_format_includes_variant_name() {
    let d = format!("{:?}", TaskStatus::InProgress);
    assert!(d.contains("InProgress"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Determinism
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn display_is_deterministic_across_repeated_calls() {
    let variant = TaskStatus::InProgress;
    let s1 = variant.to_string();
    let s2 = variant.to_string();
    assert_eq!(s1, s2);
}

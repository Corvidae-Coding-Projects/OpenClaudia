//! End-to-end tests for `coordinator::permission::LeaderPermissionBridge`
//! FIFO queue + per-teammate/tool/target always-allow cache +
//! Debug-redaction of `QueuedPermission`.
//!
//! Sprint 76 of the verification effort. The internal unit tests
//! cover basic flow; this file pins the multi-teammate
//! cache-isolation behaviour, FIFO ordering across many enqueues,
//! the `is_idle` predicate's BOTH-conditions invariant, and the
//! `Debug` impl's `tool_args` redaction (length-only, not the
//! actual JSON).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::coordinator::permission::{LeaderPermissionBridge, QueuedPermission};
use openclaudia::coordinator::teammate::TeammateId;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn req(teammate: &TeammateId, tool: &str, args: &str) -> QueuedPermission {
    QueuedPermission {
        teammate: teammate.clone(),
        tool_name: tool.to_string(),
        tool_args: args.to_string(),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Fresh bridge state
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn fresh_bridge_starts_idle_with_zero_pending() {
    let bridge = LeaderPermissionBridge::new();
    assert!(bridge.is_idle());
    assert_eq!(bridge.pending_count(), 0);
}

#[test]
fn default_matches_new() {
    let new = LeaderPermissionBridge::new();
    let def = LeaderPermissionBridge::default();
    assert_eq!(new.is_idle(), def.is_idle());
    assert_eq!(new.pending_count(), def.pending_count());
}

#[test]
fn dequeue_on_empty_bridge_returns_none() {
    let mut bridge = LeaderPermissionBridge::new();
    assert!(bridge.dequeue().is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — FIFO ordering
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enqueue_preserves_insertion_order_across_5_requests() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    for i in 0..5 {
        bridge.enqueue(req(&alpha, &format!("tool-{i}"), "{}"));
    }
    assert_eq!(bridge.pending_count(), 5);
    for i in 0..5 {
        let popped = bridge.dequeue().expect("MUST be Some");
        assert_eq!(
            popped.tool_name,
            format!("tool-{i}"),
            "FIFO MUST preserve insertion order; got {:?} at position {i}",
            popped.tool_name
        );
    }
    assert_eq!(bridge.pending_count(), 0);
}

#[test]
fn enqueue_across_multiple_teammates_preserves_arrival_order() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    let beta = TeammateId::new();
    bridge.enqueue(req(&alpha, "a-1", "{}"));
    bridge.enqueue(req(&beta, "b-1", "{}"));
    bridge.enqueue(req(&alpha, "a-2", "{}"));
    // Dequeue order MUST match enqueue order regardless of
    // which teammate issued each.
    let pop1 = bridge.dequeue().unwrap();
    let pop2 = bridge.dequeue().unwrap();
    let pop3 = bridge.dequeue().unwrap();
    assert_eq!(pop1.tool_name, "a-1");
    assert_eq!(pop2.tool_name, "b-1");
    assert_eq!(pop3.tool_name, "a-2");
}

#[test]
fn pending_count_tracks_queue_depth_across_enqueue_dequeue() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    assert_eq!(bridge.pending_count(), 0);
    bridge.enqueue(req(&alpha, "a", "{}"));
    assert_eq!(bridge.pending_count(), 1);
    bridge.enqueue(req(&alpha, "b", "{}"));
    assert_eq!(bridge.pending_count(), 2);
    bridge.dequeue();
    assert_eq!(bridge.pending_count(), 1);
    bridge.dequeue();
    assert_eq!(bridge.pending_count(), 0);
    // Dequeue past empty: count stays 0 (saturating).
    bridge.dequeue();
    assert_eq!(bridge.pending_count(), 0);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Always-allow cache: per-teammate isolation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn always_allow_for_teammate_a_does_not_leak_to_teammate_b() {
    // Documented contract: per-teammate isolation matches
    // CC's "a (allow once) doesn't carry across teammates".
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    let beta = TeammateId::new();
    bridge.always_allow(alpha.clone(), "bash", "git status");
    assert!(bridge.is_always_allowed(&alpha, "bash", "git status"));
    assert!(
        !bridge.is_always_allowed(&beta, "bash", "git status"),
        "always-allow for alpha MUST NOT bypass beta's gate"
    );
}

#[test]
fn always_allow_tracks_multiple_tools_per_teammate() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    bridge.always_allow(alpha.clone(), "bash", "git status");
    bridge.always_allow(alpha.clone(), "read_file", "README.md");
    bridge.always_allow(alpha.clone(), "write_file", "src/main.rs");
    assert!(bridge.is_always_allowed(&alpha, "bash", "git status"));
    assert!(bridge.is_always_allowed(&alpha, "read_file", "README.md"));
    assert!(bridge.is_always_allowed(&alpha, "write_file", "src/main.rs"));
    assert!(!bridge.is_always_allowed(&alpha, "edit_file", "src/main.rs"));
}

#[test]
fn always_allow_for_one_target_does_not_leak_to_another_target() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    bridge.always_allow(alpha.clone(), "bash", "git status");
    assert!(bridge.is_always_allowed(&alpha, "bash", "git status"));
    assert!(
        !bridge.is_always_allowed(&alpha, "bash", "rm -rf /"),
        "always-allow for one target MUST NOT bypass another target"
    );
}

#[test]
fn always_allow_for_write_path_does_not_leak_to_different_content() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    let approved = r#"{"content":"approved","path":"src/main.rs"}"#;
    let changed = r#"{"path":"src/main.rs","content":"changed"}"#;
    bridge.always_allow(alpha.clone(), "write_file", approved);

    // JSON key order is normalized, but a changed argument remains distinct.
    assert!(bridge.is_always_allowed(
        &alpha,
        "write_file",
        r#"{"path":"src/main.rs","content":"approved"}"#
    ));
    assert!(!bridge.is_always_allowed(&alpha, "write_file", changed));
}

#[test]
fn always_allow_is_idempotent_repeated_calls_no_effect() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    bridge.always_allow(alpha.clone(), "bash", "git status");
    bridge.always_allow(alpha.clone(), "bash", "git status");
    bridge.always_allow(alpha.clone(), "bash", "git status");
    // Idempotent — the exact bounded receipt is replaced, not widened.
    assert!(bridge.is_always_allowed(&alpha, "bash", "git status"));
}

#[test]
fn always_allow_unknown_teammate_lookup_returns_false() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    assert!(!bridge.is_always_allowed(&alpha, "bash", "git status"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — is_idle reflects BOTH queue + cache
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn is_idle_false_when_anything_queued() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    bridge.enqueue(req(&alpha, "bash", "{}"));
    assert!(
        !bridge.is_idle(),
        "is_idle MUST be false when queue non-empty"
    );
}

#[test]
fn is_idle_false_when_always_allow_cache_has_entry() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    bridge.always_allow(alpha, "bash", "git status");
    assert!(
        !bridge.is_idle(),
        "is_idle MUST be false when cache has entries (per docstring)"
    );
}

#[test]
fn is_idle_true_only_when_both_queue_and_cache_empty() {
    let mut bridge = LeaderPermissionBridge::new();
    let alpha = TeammateId::new();
    // Add + drain queue.
    bridge.enqueue(req(&alpha, "x", "{}"));
    bridge.dequeue();
    // Queue empty, but no cache entries yet → idle.
    assert!(bridge.is_idle());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — QueuedPermission Debug-redaction
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn debug_format_redacts_tool_args_to_length_only() {
    // PINS DOCUMENTED CONTRACT: tool_args may contain secrets
    // (env vars, file contents), so Debug shows the LENGTH
    // only, never the raw JSON.
    let alpha = TeammateId::new();
    let secret_args = r#"{"command":"echo $AWS_SECRET_ACCESS_KEY"}"#;
    let request = req(&alpha, "bash", secret_args);
    let debug = format!("{request:?}");
    assert!(
        !debug.contains("AWS_SECRET_ACCESS_KEY"),
        "Debug MUST NOT leak tool_args content; got {debug:?}"
    );
    // Length field MUST be present.
    assert!(
        debug.contains("tool_args_len"),
        "Debug MUST include tool_args_len; got {debug:?}"
    );
    let len = secret_args.len();
    assert!(
        debug.contains(&len.to_string()),
        "Debug MUST surface the actual length {len}; got {debug:?}"
    );
}

#[test]
fn debug_format_includes_teammate_and_tool_name_for_correlation() {
    let alpha = TeammateId::new();
    let request = req(&alpha, "edit_file", "{}");
    let debug = format!("{request:?}");
    // Tool name is non-sensitive — present for log correlation.
    assert!(
        debug.contains("edit_file"),
        "Debug MUST include tool_name for log correlation; got {debug:?}"
    );
}

#[test]
fn debug_format_for_empty_args_shows_zero_length() {
    let alpha = TeammateId::new();
    let request = req(&alpha, "x", "");
    let debug = format!("{request:?}");
    assert!(
        debug.contains("tool_args_len: 0"),
        "empty args MUST surface tool_args_len: 0; got {debug:?}"
    );
}

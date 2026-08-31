//! Leader permission bridge.
//!
//! Parallel teammates would otherwise race to prompt the user —
//! N simultaneous `[y/n/a/d]?` dialogs collide. The bridge queues
//! incoming permission requests per-teammate and serves them in
//! arrival order so the user sees exactly one prompt at a time.
//! An "always-allow for this run" cache records `a` replies per
//! teammate, tool, and exact normalized arguments so one teammate or
//! invocation can't widen
//! permissions for another.
//!
//! Phase 1 ships the queue data structures + tests. Phase 3 wires
//! the bridge into the event loop as the sole receiver of teammate
//! `PermissionRequest` events.

use std::collections::{HashMap, VecDeque};

use super::teammate::TeammateId;
use crate::permissions::{ApprovalProvenance, LocalApprovalCache, LocalApprovalDecision};

/// A permission request from a specific teammate, parked in the leader
/// bridge's FIFO until a decision is made.
///
/// **Fire-and-forget at this phase (crosslink #793).** The struct
/// intentionally has no reply channel: no `oneshot::Sender`, no
/// `Notify`, no correlation id. Phase 1 only ships the queue data
/// structures, and there is no async machinery yet that could await
/// a reply, so a channel here would be dead state with no consumer.
///
/// Phase 3 (which wires the bridge into the event loop) will need a
/// resume path for the teammate task. The two options on the table
/// are: (a) add `reply: oneshot::Sender<PermissionDecision>` to this
/// struct and require callers to construct one, or (b) keep
/// `QueuedPermission` as plain data and key replies through a parallel
/// correlation map on the bridge. Either way, the current shape
/// (plain data, no channel) is honest about Phase 1 limits but cannot
/// resume teammates as-is — callers must not assume `enqueue` carries
/// a future reply.
pub struct QueuedPermission {
    pub teammate: TeammateId,
    pub tool_name: String,
    pub tool_args: String,
}

impl std::fmt::Debug for QueuedPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedPermission")
            .field("teammate", &self.teammate)
            .field("tool_name", &self.tool_name)
            .field("tool_args_len", &self.tool_args.len())
            .finish()
    }
}

/// Permission bridge state. Pure data — the async machinery that
/// actually serves the queue (receive `PermissionRequest` → push →
/// pop when user replies) lands in Phase 3.
#[derive(Debug, Default)]
pub struct LeaderPermissionBridge {
    /// FIFO of pending prompts.
    pending: VecDeque<QueuedPermission>,
    /// Per-teammate exact, expiring approval receipts. Raw commands, paths,
    /// and arguments are never retained as map keys.
    always_allowed: HashMap<TeammateId, LocalApprovalCache>,
}

impl LeaderPermissionBridge {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// True when nothing is queued and no prior teammate has an
    /// always-allow cache entry. Used by the idle-state check in
    /// `Coordinator::teammates` tests.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty() && self.always_allowed.is_empty()
    }

    /// How many requests are waiting for a decision.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Enqueue a new request. Preserves arrival order.
    pub fn enqueue(&mut self, request: QueuedPermission) {
        self.pending.push_back(request);
    }

    /// Pop the head of the queue. `None` when empty.
    pub fn dequeue(&mut self) -> Option<QueuedPermission> {
        self.pending.pop_front()
    }

    /// Record an "always allow" decision for one teammate, tool, and complete
    /// normalized argument object. Future requests bypass the queue only when
    /// every argument is identical; changing file content while retaining the
    /// same path still requires permission.
    pub fn always_allow(
        &mut self,
        teammate: TeammateId,
        tool_name: impl Into<String>,
        arguments: impl Into<String>,
    ) {
        self.always_allowed
            .entry(teammate)
            .or_default()
            .remember_allowed(
                &tool_name.into(),
                &arguments.into(),
                ApprovalProvenance::CoordinatorLeader,
            );
    }

    /// Check the always-allow cache. True → the request should
    /// skip enqueuing and resolve immediately as `Allow`.
    ///
    #[must_use]
    pub fn is_always_allowed(
        &mut self,
        teammate: &TeammateId,
        tool_name: &str,
        arguments: &str,
    ) -> bool {
        self.always_allowed
            .get_mut(teammate)
            .and_then(|approvals| approvals.decision(tool_name, arguments))
            == Some(LocalApprovalDecision::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(tm: &TeammateId, tool: &str) -> QueuedPermission {
        QueuedPermission {
            teammate: tm.clone(),
            tool_name: tool.into(),
            tool_args: "{}".into(),
        }
    }

    #[test]
    fn fresh_bridge_is_idle() {
        let bridge = LeaderPermissionBridge::new();
        assert!(bridge.is_idle());
        assert_eq!(bridge.pending_count(), 0);
    }

    #[test]
    fn enqueue_preserves_arrival_order() {
        let mut bridge = LeaderPermissionBridge::new();
        let t1 = TeammateId::new();
        let t2 = TeammateId::new();
        bridge.enqueue(make_request(&t1, "bash"));
        bridge.enqueue(make_request(&t2, "write_file"));
        bridge.enqueue(make_request(&t1, "edit_file"));
        assert_eq!(bridge.pending_count(), 3);

        let first = bridge.dequeue().unwrap();
        assert_eq!(first.teammate, t1);
        assert_eq!(first.tool_name, "bash");

        let second = bridge.dequeue().unwrap();
        assert_eq!(second.teammate, t2);

        let third = bridge.dequeue().unwrap();
        assert_eq!(third.teammate, t1);
        assert_eq!(third.tool_name, "edit_file");

        assert!(bridge.dequeue().is_none());
    }

    #[test]
    fn always_allow_is_per_teammate() {
        let mut bridge = LeaderPermissionBridge::new();
        let t1 = TeammateId::new();
        let t2 = TeammateId::new();
        bridge.always_allow(t1.clone(), "bash", "git status");

        // t1 + bash + target hits the cache; t1 + edit_file does
        // not; t2 + bash does NOT — decisions are per-teammate to
        // match CC.
        assert!(bridge.is_always_allowed(&t1, "bash", "git status"));
        assert!(!bridge.is_always_allowed(&t1, "edit_file", "src/main.rs"));
        assert!(!bridge.is_always_allowed(&t2, "bash", "git status"));
    }

    #[test]
    fn always_allow_tracks_distinct_tools() {
        let mut bridge = LeaderPermissionBridge::new();
        let tm = TeammateId::new();
        bridge.always_allow(tm.clone(), "bash", "git status");
        bridge.always_allow(tm.clone(), "write_file", "src/main.rs");
        assert!(bridge.is_always_allowed(&tm, "bash", "git status"));
        assert!(bridge.is_always_allowed(&tm, "write_file", "src/main.rs"));
        assert!(!bridge.is_always_allowed(&tm, "edit_file", "src/main.rs"));
        assert!(!bridge.is_always_allowed(&tm, "bash", "rm -rf /"));
    }

    #[test]
    fn is_idle_reflects_cache_entries_too() {
        let mut bridge = LeaderPermissionBridge::new();
        bridge.always_allow(TeammateId::new(), "bash", "git status");
        // Pending is empty but cache isn't — not idle. Matches the
        // semantic used by the default-coordinator-is-empty test
        // in mod.rs.
        assert!(!bridge.is_idle());
    }
}

/// Phase 2 spec-pinning tests for issue #546, B4 behaviours.
///
/// Pins the CURRENT `LeaderPermissionBridge` data-structure contracts
/// against the Phase 1 spec (crosslink #531 §B4). No production code
/// is changed — divergences from CC are documented with comments.
///
/// Denial paths dominate, matching the permission-system test philosophy.
/// Security-critical divergences are marked `// SECURITY: #<issue>`.
#[cfg(test)]
mod phase2_spec_pins {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────

    fn req(tm: &TeammateId, tool: &str) -> QueuedPermission {
        QueuedPermission {
            teammate: tm.clone(),
            tool_name: tool.into(),
            tool_args: r#"{"command":"ls"}"#.into(),
        }
    }

    // ── B4-1 · Fresh bridge is idle and empty ─────────────────────────────

    /// B4-deny-1: fresh bridge has nothing queued and no always-allow cache.
    #[test]
    fn b4_fresh_bridge_idle_and_empty() {
        let bridge = LeaderPermissionBridge::new();
        assert!(bridge.is_idle(), "B4: fresh bridge must be idle");
        assert_eq!(bridge.pending_count(), 0);
    }

    /// B4-deny-2: dequeue on empty bridge returns None (caller must not hang).
    #[test]
    fn b4_dequeue_empty_returns_none() {
        let mut bridge = LeaderPermissionBridge::new();
        assert!(
            bridge.dequeue().is_none(),
            "B4: dequeue on empty must return None"
        );
    }

    // ── B4-2 · FIFO enqueue/dequeue order ────────────────────────────────

    /// B4-allow-1: requests are served in arrival order (FIFO).
    #[test]
    fn b4_fifo_order_preserved() {
        let mut bridge = LeaderPermissionBridge::new();
        let t1 = TeammateId::new();
        let t2 = TeammateId::new();
        let t3 = TeammateId::new();

        bridge.enqueue(req(&t1, "bash"));
        bridge.enqueue(req(&t2, "write_file"));
        bridge.enqueue(req(&t3, "edit_file"));

        assert_eq!(bridge.pending_count(), 3);

        let first = bridge.dequeue().unwrap();
        assert_eq!(first.teammate, t1, "B4: first dequeue must be t1");
        assert_eq!(first.tool_name, "bash");

        let second = bridge.dequeue().unwrap();
        assert_eq!(second.teammate, t2, "B4: second dequeue must be t2");

        let third = bridge.dequeue().unwrap();
        assert_eq!(third.teammate, t3, "B4: third dequeue must be t3");

        assert!(
            bridge.dequeue().is_none(),
            "B4: queue must be empty after all dequeued"
        );
    }

    /// B4-allow-2: `pending_count` tracks enqueue/dequeue correctly.
    #[test]
    fn b4_pending_count_tracks_mutations() {
        let mut bridge = LeaderPermissionBridge::new();
        let tm = TeammateId::new();
        assert_eq!(bridge.pending_count(), 0);
        bridge.enqueue(req(&tm, "bash"));
        assert_eq!(bridge.pending_count(), 1);
        bridge.enqueue(req(&tm, "bash"));
        assert_eq!(bridge.pending_count(), 2);
        bridge.dequeue();
        assert_eq!(bridge.pending_count(), 1);
        bridge.dequeue();
        assert_eq!(bridge.pending_count(), 0);
    }

    // ── B4-3 · always-allow cache isolation ───────────────────────────────

    /// B4-deny-1: `always_allow` for t1+bash+target must NOT grant t2+bash+target.
    /// Per-teammate isolation matches CC's "a reply doesn't leak across teammates".
    #[test]
    fn b4_always_allow_does_not_cross_teammate_boundary() {
        let mut bridge = LeaderPermissionBridge::new();
        let t1 = TeammateId::new();
        let t2 = TeammateId::new();

        bridge.always_allow(t1.clone(), "bash", "git status");

        assert!(
            bridge.is_always_allowed(&t1, "bash", "git status"),
            "t1+bash+target must be cached"
        );
        assert!(
            !bridge.is_always_allowed(&t2, "bash", "git status"),
            "B4: t2+bash+target must NOT be cached (per-teammate isolation)"
        );
    }

    /// B4-deny-2: `always_allow` for t1+bash+target must NOT grant `t1+edit_file`.
    #[test]
    fn b4_always_allow_does_not_cross_tool_boundary() {
        let mut bridge = LeaderPermissionBridge::new();
        let tm = TeammateId::new();
        bridge.always_allow(tm.clone(), "bash", "git status");

        assert!(bridge.is_always_allowed(&tm, "bash", "git status"));
        assert!(
            !bridge.is_always_allowed(&tm, "edit_file", "git status"),
            "B4: always_allow for bash must not grant edit_file"
        );
        assert!(
            !bridge.is_always_allowed(&tm, "write_file", "git status"),
            "B4: always_allow for bash must not grant write_file"
        );
    }

    /// B4-deny-3: `always_allow` for unknown tool name → not cached.
    #[test]
    fn b4_always_allow_unknown_tool_not_cached() {
        let mut bridge = LeaderPermissionBridge::new();
        let tm = TeammateId::new();
        assert!(
            !bridge.is_always_allowed(&tm, "nonexistent_tool", "anything"),
            "B4: no always_allow entry must return false for any teammate+tool+target"
        );
    }

    /// B4-allow-1: distinct (teammate, tool, target) entries are tracked independently.
    #[test]
    fn b4_multiple_always_allow_pairs_tracked_independently() {
        let mut bridge = LeaderPermissionBridge::new();
        let t1 = TeammateId::new();
        let t2 = TeammateId::new();

        bridge.always_allow(t1.clone(), "bash", "git status");
        bridge.always_allow(t1.clone(), "write_file", "src/main.rs");
        bridge.always_allow(t2.clone(), "edit_file", "src/lib.rs");

        assert!(bridge.is_always_allowed(&t1, "bash", "git status"));
        assert!(bridge.is_always_allowed(&t1, "write_file", "src/main.rs"));
        assert!(bridge.is_always_allowed(&t2, "edit_file", "src/lib.rs"));

        // Cross-checks must still fail.
        assert!(!bridge.is_always_allowed(&t1, "edit_file", "src/lib.rs"));
        assert!(!bridge.is_always_allowed(&t2, "bash", "git status"));
        assert!(!bridge.is_always_allowed(&t2, "write_file", "src/main.rs"));
        assert!(!bridge.is_always_allowed(&t1, "bash", "rm -rf /"));
    }

    // ── B4-4 · is_idle semantics ──────────────────────────────────────────

    /// B4-deny-1: bridge with only always-allow cache (no pending) is NOT idle.
    /// Spec §B4 edge case: `is_idle()` = `pending.is_empty()` && `always_allowed.is_empty()`.
    #[test]
    fn b4_is_idle_false_when_only_cache_populated() {
        let mut bridge = LeaderPermissionBridge::new();
        bridge.always_allow(TeammateId::new(), "bash", "git status");
        assert!(
            !bridge.is_idle(),
            "B4: bridge with non-empty always_allowed cache must not be idle"
        );
    }

    /// B4-deny-2: bridge with only pending (no cache) is NOT idle.
    #[test]
    fn b4_is_idle_false_when_only_pending_populated() {
        let mut bridge = LeaderPermissionBridge::new();
        let tm = TeammateId::new();
        bridge.enqueue(req(&tm, "bash"));
        assert!(
            !bridge.is_idle(),
            "B4: bridge with pending queue must not be idle"
        );
    }

    /// B4-allow-1: dequeuing all items but leaving cache populated → still not idle.
    #[test]
    fn b4_is_idle_false_after_drain_if_cache_nonempty() {
        let mut bridge = LeaderPermissionBridge::new();
        let tm = TeammateId::new();
        bridge.enqueue(req(&tm, "bash"));
        bridge.always_allow(tm, "bash", "git status");
        bridge.dequeue();

        // Pending is now empty, but cache still has an entry.
        assert!(
            !bridge.is_idle(),
            "B4: cache entry alone keeps bridge non-idle after pending drain"
        );
    }

    // ── B4-5 · always_allow target/pattern isolation ──────────────────────

    /// B4-deny-4: `always_allow` for one bash target must NOT grant a
    /// different bash target.
    #[test]
    fn b4_always_allow_does_not_cross_target_boundary() {
        let mut bridge = LeaderPermissionBridge::new();
        let tm = TeammateId::new();

        bridge.always_allow(tm.clone(), "bash", "git status");

        assert!(
            bridge.is_always_allowed(&tm, "bash", "git status"),
            "B4: original bash target must be cached"
        );
        assert!(
            !bridge.is_always_allowed(&tm, "bash", "rm -rf /"),
            "B4: always_allow for one bash target must not grant another"
        );
    }

    // ── B4-6 · tool_args preserved in queued request ──────────────────────

    /// B4-allow-1: `tool_args` string is preserved through enqueue→dequeue round-trip.
    #[test]
    fn b4_tool_args_preserved_in_queue() {
        let mut bridge = LeaderPermissionBridge::new();
        let tm = TeammateId::new();
        let args = r#"{"command":"cargo test","timeout":60}"#;

        bridge.enqueue(QueuedPermission {
            teammate: tm,
            tool_name: "bash".into(),
            tool_args: args.into(),
        });

        let popped = bridge.dequeue().unwrap();
        assert_eq!(
            popped.tool_args, args,
            "B4: tool_args must be preserved through the queue"
        );
    }

    // ── Crosslink #793 — `QueuedPermission` is fire-and-forget at Phase 1 ──

    /// #793-1: The struct must remain plain data with only the three
    /// public fields it ships today. If a `reply` channel is added in
    /// Phase 3, this test will need to be updated *and* the doc comment
    /// updated in lockstep — preventing a recurrence of the doc/impl
    /// mismatch that filed #793.
    #[test]
    fn issue_793_queued_permission_has_no_reply_channel_field() {
        let tm = TeammateId::new();
        let q = QueuedPermission {
            teammate: tm,
            tool_name: "bash".into(),
            tool_args: "{}".into(),
        };
        // Field-by-name access proves the struct shape at compile time.
        let _ = &q.teammate;
        let _ = &q.tool_name;
        let _ = &q.tool_args;

        // Render via Debug; the formatter only lists the three known
        // fields. If a reply/sender/notify field is added later, this
        // assertion will fail and force the doc comment to be updated
        // alongside the new field.
        let dbg = format!("{q:?}");
        assert!(
            !dbg.contains("reply"),
            "QueuedPermission Debug output must not mention 'reply' until Phase 3 \
             actually wires one in (crosslink #793): {dbg}"
        );
        assert!(
            !dbg.contains("sender"),
            "QueuedPermission must not carry a Sender field at Phase 1: {dbg}"
        );
        assert!(
            !dbg.contains("notify"),
            "QueuedPermission must not carry a Notify field at Phase 1: {dbg}"
        );
        // Sanity: the three documented fields ARE present.
        assert!(
            dbg.contains("teammate"),
            "Debug must include teammate: {dbg}"
        );
        assert!(
            dbg.contains("tool_name"),
            "Debug must include tool_name: {dbg}"
        );
    }

    /// #793-2: Once a request has been dequeued, the bridge has no way
    /// to deliver a decision back to the originating teammate — the
    /// dequeue is the end of the bridge's responsibility. Pins the
    /// honest Phase 1 contract: enqueue → dequeue, no reply.
    #[test]
    fn issue_793_enqueue_dequeue_round_trip_has_no_reply_handle() {
        let mut bridge = LeaderPermissionBridge::new();
        let tm = TeammateId::new();
        bridge.enqueue(QueuedPermission {
            teammate: tm.clone(),
            tool_name: "edit_file".into(),
            tool_args: r#"{"path":"/etc/passwd"}"#.into(),
        });
        let popped = bridge.dequeue().expect("just enqueued");

        // The popped value yields plain data — there is no `.reply(...)`,
        // no `.send(...)`, no `.respond(...)` method on the bridge for
        // the dequeued request.
        assert_eq!(popped.teammate, tm);
        assert_eq!(popped.tool_name, "edit_file");

        // After dequeue the bridge has no record of the in-flight
        // request — there is nothing for a reply to address. Phase 3
        // will need either a separate in-flight map keyed by a
        // correlation id, or a reply channel on QueuedPermission. The
        // current shape supports neither.
        assert_eq!(bridge.pending_count(), 0);
    }
}

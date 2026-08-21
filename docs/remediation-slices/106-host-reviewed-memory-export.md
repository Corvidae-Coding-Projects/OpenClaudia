# S-106: Add host-reviewed technical-memory authority and portable export

Status: Planned
Effort: Medium
Primary findings: Design requirement from W5
Workstreams: W2, W5, W15
Depends on: [S-017](./017-deny-precedence-and-approval-receipts.md), [S-054](./054-memory-authority-and-schema.md), [S-056](./056-operational-memdir-lifecycle.md)
Crosslink: #1078

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give users a real authority-bearing review transition and a complete portable
export for codebase technical lessons. A model cannot self-assert review, and a
context-limited `memory_list` response is not mislabeled as an export.

## Implementation boundary

- Bind `HostReviewed` transitions to an exact, consumed host approval receipt,
  lesson logical ID, expected revision digest, workspace, run, actor, and policy
  generation. Preserve candidate evidence and causal correction history.
- Define correction, supersession, expiry, review revocation, and deletion
  interactions without silently increasing a claim's confidence or authority.
- Export the complete selected workspace memory set through a bounded,
  resumable host-owned workflow. Include schemas, stable identities, revisions,
  tombstones, provenance, citations, retention, review state, integrity digest,
  and typed partial/error receipts.
- Define privacy/redaction, destination capabilities, atomic publication,
  cancellation, pagination/checkpoints, and import round-trip compatibility.
- Wire every supported frontend through the canonical permission/effect/runtime
  path. Keep team authority and replication in S-103/S-104.

## Acceptance

- Unauthorized, forged, replayed, cross-workspace, and stale review receipts
  fail before mutation; exact authorized replay is idempotent.
- Revocation and later corrections cannot retain stale reviewed authority.
- A maximum-size export is bounded and resumable, publishes atomically, and
  round-trips without losing causal or privacy metadata.
- Tampered, truncated, oversized, interrupted, symlinked, or wrong-destination
  exports fail closed with typed recovery evidence.
- Deterministic frontend tests and an independent artifact-bound VDD receipt
  prove the user—not the model—controls review and export authority.

## Handoff

Record exact receipt schemas, artifact generations, commands/tests, privacy
decisions, interoperability fixtures, and remaining S-103/S-104/S-105 work.

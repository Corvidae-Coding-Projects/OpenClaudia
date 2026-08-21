# S-107: Add complete portable technical-memory export and import

Status: Planned
Effort: Medium
Primary findings: Design requirement from W5
Workstreams: W2, W5, W15
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md), [S-054](./054-memory-authority-and-schema.md), [S-056](./056-operational-memdir-lifecycle.md), [S-106](./106-host-reviewed-memory-export.md)
Crosslink: #1079

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give users a complete, portable, privacy-explicit export and strict round-trip
import for one workspace's codebase technical memory. A bounded model-facing
`memory_list` page is not an export, and free-form prose/transcripts are never
added to the format.

## Implementation boundary

- Define a versioned canonical package containing workspace/schema identity,
  every selected logical identity, immutable revision, head, tombstone,
  provenance, citation, retention/review state, host-review audit record, and
  deterministic integrity digest.
- Stream deterministic bounded parts under an immutable snapshot/checkpoint;
  never materialize the maximum store in RAM. Resume only when the store,
  destination, prior parts, and expected checkpoint still match.
- Require a fresh host-authorized export/import call and an explicit
  destination/source capability. Use descriptor-relative owner-private files,
  bounded part sizes/counts, atomic part commits, and a final manifest commit
  that alone marks the package complete.
- Return typed progress, completion, cancellation, stale-snapshot, conflict,
  partial-publication, and recovery receipts without including lesson prose in
  traces or tool summaries.
- Import only complete canonical packages. Verify every digest, order, bound,
  causal edge, workspace policy, privacy/scope rule, and host-review audit before
  an atomic store mutation; exact replay is idempotent.
- Wire supported host frontends through the canonical effect/resource/runtime
  path. Keep authenticated team synchronization in S-103/S-104 rather than
  treating a portable file as a replication protocol.

## Acceptance

- A maximum-size valid export remains within fixed memory, part, file-count,
  time/checkpoint, and output-receipt budgets and resumes after interruption.
- Tampered, truncated, reordered, oversized, symlinked, stale, conflicted, or
  wrong-workspace/destination packages fail closed with actionable typed state.
- Publication is invisible until the final durable manifest; failure never
  mislabels partial parts as a complete export.
- Export then import preserves every causal identity, revision/head/tombstone,
  provenance/citation, retention, sensitivity, and host-review audit field.
- Deterministic cross-platform compilation and independent artifact-bound VDD
  evidence cover the final format and recovery protocol.

## Handoff

Record schema fixtures, digest vectors, maximum-size budgets, checkpoint and
atomic-publication generations, commands/tests, privacy decisions, and the
remaining S-103/S-104/S-105 work.

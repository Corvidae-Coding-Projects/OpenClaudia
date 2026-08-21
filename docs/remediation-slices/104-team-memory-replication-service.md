# S-104: Wire the team-memory replication service

Status: Planned
Effort: Medium
Primary findings: Design requirement from F-006, F-075, and W5
Workstreams: W5, W10, W15
Depends on: [S-051](./051-token-turn-and-cost-budgets.md), [S-053](./053-memory-record-identity-and-merge.md), [S-054](./054-memory-authority-and-schema.md), [S-103](./103-authenticated-team-memory-authority.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make authenticated team technical memory operational through a bounded service
and the same canonical tools and lifecycle as private technical memory.

## Implementation boundary

- Define a versioned bounded protocol for causal lesson revisions, tombstones,
  conflict heads, cursors, acknowledgements, retry keys, and typed terminal
  outcomes. Authenticate every request through S-103 before reading or writing.
- Encrypt transport and protected persisted replicas, pin service/team identity,
  and reject downgrade, replay, cross-team, and store-replacement attempts.
- Reuse S-053 logical identities and immutable revision graph. Synchronize in
  bounded parent-before-child batches with durable idempotent outbox/inbox state;
  offline or concurrent branches remain visible until explicit typed resolution.
- Wire approved team configuration into startup and all five canonical memory
  tools without treating repository content or a shared path as authority.
  Private lessons never leave their scope; team results remain untrusted cited
  evidence and never enter prompts ambiently.
- Apply explicit time, byte, record, concurrency, retry, and shutdown budgets.
  Distinguish unavailable, partial, stale, conflicted, unauthorized, and corrupt
  states rather than silently falling back to a different scope.

## Acceptance

- Authenticated members can retrieve and mutate permitted team lessons through
  every supported frontend; unauthorized callers learn no team content.
- Lost responses and process restarts replay idempotently. Offline concurrent
  edits converge without row-ID aliasing, private-data leakage, hidden heads, or
  last-writer data loss.
- Network interruption, tampered messages, wrong keys, revoked membership,
  bounded-queue exhaustion, and service/store replacement fail visibly with
  recoverable durable state.
- Relevant deterministic tests and trace assertions pass; attach an
  artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence
receipts, unresolved risks, and any newly proposed slice. Completion of this
slice does not imply completion of its parent workstream.

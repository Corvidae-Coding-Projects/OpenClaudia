# S-080: Make plan approval an atomic capability transition

Status: Planned
Effort: Medium
Primary findings: F-114
Workstreams: W2, W12, W17
Depends on: [S-017](./017-deny-precedence-and-approval-receipts.md), [S-024](./024-artifact-verification-invalidation.md), [S-052](./052-canonical-task-graph.md), [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Bind the reviewed plan bytes, task state, artifact generation, and granted execution authority in one transaction.

## Implementation boundary

- Represent a plan as an immutable versioned artifact with task graph, proposed effects, budgets, expiry, actor, and evidence.
- Approve exact plan digest and atomically activate its capability generation; amendments, artifact changes, or mode changes invalidate the grant.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- The agent cannot execute different plan bytes or broader effects than the user approved.
- Concurrent edits, stale approvals, partial persistence, cancellation, and resume cannot split plan state from authority.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

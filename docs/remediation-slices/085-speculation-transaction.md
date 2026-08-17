# S-085: Implement or remove speculation by measurement

Status: Planned
Effort: Medium
Primary findings: F-104
Workstreams: W7
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-019](./019-explicit-session-capabilities.md), [S-051](./051-token-turn-and-cost-budgets.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace speculation scaffolding with a safe artifact-bound optimization that survives only if it beats a simpler baseline.

## Implementation boundary

- Limit predictions to deterministic idempotent read-only operations in disposable snapshots with exact arguments/input generations, confidence, deadline, budget, cancellation, and result handle.
- Require exact later-call match and complete successful receipt for reuse; otherwise cancel/join and discard without side effects.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Speculative work has no network, secrets, writes, approvals, external effects, or run-independent lifetime.
- Measured task correctness, latency, hit rate, waste, and cost beat demand cache/prefetch; otherwise the mechanism is removed with evidence.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

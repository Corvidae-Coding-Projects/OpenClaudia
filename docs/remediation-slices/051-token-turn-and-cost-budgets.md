# S-051: Unify token, turn, cost, retry, and concurrency budgets

Status: Planned
Effort: Medium
Primary findings: F-017, F-062, F-066
Workstreams: W10
Depends on: [S-010](./010-canonical-run-context-and-events.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Enforce one atomic run budget before work starts and reconcile exact or unknown usage without races or silent saturation.

## Implementation boundary

- Define hierarchical reservations for input/output tokens, turns, cost, elapsed time, retries, tool/model/process concurrency, and child runs.
- Use checked wide accounting with provider/model/pricing provenance; reserve before calls, cap provider output, and reconcile actual/unknown usage after terminal state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Concurrent calls cannot oversubscribe a hard cap, and integer saturation or missing usage never becomes free allowance.
- Every frontend, worker, verifier, hook, MCP call, process, and background task shares the same cancellation-aware budget tree.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

# S-084: Turn cron metadata into a scheduler service

Status: Planned
Effort: Medium
Primary findings: F-051
Workstreams: W2, W10, W12, W15, W18, W19
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-029](./029-oauth-session-lifecycle.md), [S-031](./031-descriptor-safe-persistence.md), [S-040](./040-supervised-foreground-process-io.md), [S-051](./051-token-turn-and-cost-budgets.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve scheduling as durable authorized agent runs instead of inert cron-shaped records.

## Implementation boundary

- Define schedule/timezone/DST/misfire/overlap/retry/max-run/expiry semantics and bind owner, task, capabilities, budgets, notification, and revocable approval.
- Use trusted storage, leases/fencing, idempotent run IDs, canonical runtime dispatch, supervised effects, and exact run/delivery history.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Virtual-time, restart, concurrent scheduler, DST, catch-up, overlap, cancellation, revoked permission, and crash-transition tests pass.
- The product either executes and reports schedules end to end or labels stored metadata explicitly non-executing.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

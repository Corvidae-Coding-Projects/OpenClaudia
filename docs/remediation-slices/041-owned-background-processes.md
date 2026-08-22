# S-041: Own background process lifetime and output

Status: Planned
Effort: Medium
Primary findings: F-047
Workstreams: W10, W18
Depends on: [S-040](./040-supervised-foreground-process-io.md), [S-051](./051-token-turn-and-cost-budgets.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Turn background shells into generation-safe supervised jobs with bounded durable output and explicit ownership.

## Implementation boundary

- Bind each job to run/session/workspace, command capability, process generation, budgets, output artifact, retention, and cancellation tree.
- Replace global PID maps and in-memory ring ambiguity with typed start/status/read/cancel/join operations and restart reconciliation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Session end, cancellation, timeout, and restart cannot orphan a child or confuse a reused PID with an old job.
- Output caps apply during draining and callers can distinguish running, exited, killed, truncated, lost, and delivery-failed states.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

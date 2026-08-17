# S-021: Make blast-radius guardrails atomic and run scoped

Status: Planned
Effort: Medium
Primary findings: F-084
Workstreams: W2
Depends on: [S-016](./016-mandatory-tool-effect-classification.md), [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Apply file, line, tool, and mutation limits as atomic reservations against canonical run effects.

## Implementation boundary

- Replace lexical traversal and process-global counters with normalized capability targets and per-run/session reservations.
- Fail configuration atomically on invalid patterns or zero/ambiguous limits and reconcile reservations on success, denial, cancellation, and partial effects.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Concurrent runs cannot consume or reset each other's quotas, and traversal/symlink aliases resolve to one protected resource identity.
- All mutating tool families are covered and exceeding a limit prevents the effect before execution.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

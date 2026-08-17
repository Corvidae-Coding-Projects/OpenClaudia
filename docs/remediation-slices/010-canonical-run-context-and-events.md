# S-010: Create the canonical run context and event kernel

Status: Planned
Effort: Medium
Primary findings: F-004
Workstreams: W12
Depends on: [S-008](./008-typed-context-authority-and-budget.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Establish one run identity, context, event model, cancellation tree, and terminal-state contract shared by every frontend.

## Implementation boundary

- Define typed run/call IDs, actor/role, workspace and capability generations, budgets, provider continuation, cancellation, trace sink, and terminal outcomes.
- Implement the runtime kernel without migrating all frontends in this slice; provide a test adapter and invariants for one terminal result per run.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A reference run can be replayed from typed events and cannot emit success after cancellation, partial failure, or uncommitted state.
- The kernel has no optional security object, ambient CWD, frontend-global mutable session, or string control marker.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

# S-052: Consolidate task and planning state

Status: Planned
Effort: Medium
Primary findings: F-057, F-065
Workstreams: W20
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace todos, TaskManager, Crosslink planning views, and mode-local task state with one versioned transactional graph.

## Implementation boundary

- Define stable IDs, actor/run ownership, statuses, dependencies, blockers, active forms, versions, history, pagination, and persistence.
- Validate complete proposed mutations for cycles, missing nodes, blocker readiness, edge symmetry, and expected generation before atomic commit.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A failed or stale update leaves the previous graph unchanged and emits no misleading success event.
- Todos, planning, delegation, and external issue views reconcile through explicit adapters and cannot carry security identity.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

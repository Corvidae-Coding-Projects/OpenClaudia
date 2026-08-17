# S-055: Rebuild automatic learning around causal evidence

Status: Planned
Effort: Medium
Primary findings: F-076
Workstreams: W5
Depends on: [S-023](./023-reality-evidence-boundary.md), [S-052](./052-canonical-task-graph.md), [S-054](./054-memory-authority-and-schema.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Capture observations without turning correlation or convenient wording into durable truth.

## Implementation boundary

- Associate candidate learning with exact task, call, command, artifact/workspace generation, outcome, source, and contradiction state.
- Require deterministic evidence or explicit user confirmation before promoting preferences/fixes, and add review, expiry, correction, and deletion.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- An unrelated later successful command cannot be stored as the resolution of an earlier failure.
- Evaluation measures downstream task benefit, false-learning rate, harmful-memory rate, and user correction across frontends.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

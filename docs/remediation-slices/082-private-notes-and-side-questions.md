# S-082: Give private notes and side questions correct semantics

Status: Planned
Effort: Medium
Primary findings: F-116
Workstreams: W8, W12
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-010](./010-canonical-run-context-and-events.md), [S-052](./052-canonical-task-graph.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Keep private notes out of provider-visible system history and execute side questions without reordering or corrupting the parent conversation.

## Implementation boundary

- Store notes as private typed events with explicit projection/consent, sensitivity, retention, and deletion policy.
- Run side questions as bounded child attempts over an immutable parent snapshot and attach results through causal event IDs.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Private seeded text never reaches provider requests, ordinary exports, memory, or system context without explicit user action.
- Side-question success/failure/cancellation cannot reorder parent messages or steal provider/tool continuation state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

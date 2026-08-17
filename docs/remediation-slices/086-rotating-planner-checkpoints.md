# S-086: Implement rotating planner checkpoints

Status: Planned
Effort: Medium
Primary findings: F-120
Workstreams: W8, W12, W20
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-052](./052-canonical-task-graph.md), [S-057](./057-causal-compaction-checkpoints.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace prompt-only coordinator mode and ever-growing planner context with a capability-limited planner that rotates through durable typed state.

## Implementation boundary

- Define the planner role as task decomposition, leasing, evidence inspection, reconciliation, and user escalation without direct workspace/external mutation.
- Checkpoint immutable objective/amendments, task attempts, accepted decisions/sources, artifacts, approvals, budgets, contradictions, and child ownership; validate before lease transfer.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A fresh planner resumes from the checkpoint without predecessor prose and reaches the same task/authority state.
- Rotation during active, failed, cancelled, and partial delivery adopts or cancels every child and never inherits extra secrets, approvals, or capabilities.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

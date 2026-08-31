# S-086: Implement rotating planner checkpoints

Status: Implemented and deterministically verified; artifact-bound VDD receipt not recorded
Effort: Medium
Primary findings: F-120
Workstreams: W8, W12, W20
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-052](./052-canonical-task-graph.md), [S-057](./057-causal-compaction-checkpoints.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Delivered — 2026-08-27

Commit `399a19e9` made coordinator mode rotate through durable bounded typed
checkpoints. Rotation excludes predecessor transcript and provider-native state,
validates immutable objective/amendments/task/evidence/artifact/approval/budget
and contradiction state, and explicitly adopts or cancels every live child
before transferring a fresh capability-limited lease.

## Verification evidence

Crosslink issue #1164 records Rust 1.98 formatting and strict
all-target/all-feature Clippy as passing, together with planner (3), coordinator
(101), subagent (82), configuration (147), and selected coordinator/session and
subagent integration tests. The contemporaneous serialized library run's
unrelated dirty-worktree fixture boundary was tracked separately.

## Residual boundary

The rotating checkpoint path is implemented. An independent artifact-bound VDD
receipt was not recorded for this slice.

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

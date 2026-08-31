# S-087: Create fresh workers for semantic task slices

Status: Complete
Effort: Medium
Primary findings: F-122
Workstreams: W8, W10, W12, W24
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-019](./019-explicit-session-capabilities.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-074](./074-workspace-capability-binding.md), [S-086](./086-rotating-planner-checkpoints.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Run each coherent task slice in a fresh supervised worker with enforced isolation and lossless artifact/evidence handoff.

## Implementation boundary

- Create immutable assignment/run/workspace/capability/model/budget generations and give workers only relevant objective, sources, dependencies, and acceptance criteria.
- Persist attempts/checkpoints/results, supervise descendants, and return explicit artifact state across untracked, staged, committed, conflicted, partial, failed, cancelled, and orphaned outcomes.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Read-only/worktree boundaries are enforced by capabilities, and cleanup cannot erase any unhanded-off work.
- Finish/resume/retry/restart/cancellation/concurrency tests preserve causal state and bound depth, turns, tokens, time, cost, and output.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Completed implementation — 2026-08-27

Coordinator-mode delegation now creates immutable, generation-bound worker
assignments containing the task revision, objective digest, accepted source
records, dependency and acceptance digests, model generation, and optional
isolated-worktree locator. Each semantic attempt receives a fresh provider
transcript and child run. General-purpose workers receive worktree isolation
automatically; one semantic slice admits at most one live worker while unrelated
slices remain parallel.

Terminal worker artifacts are retained as typed succeeded, partial, failed,
cancelled, or orphaned handoffs until a durable planner checkpoint acknowledges
them. Cancellation waits for the worker future to drop, reaps owned shells, and
then snapshots artifacts. Cleanup reuses the S-074 porcelain-v2 observation and
refuses removal when tracked, untracked, staged, conflicted, or committed work
remains; ignored build caches do not masquerade as deliverable work.

Rust 1.98 formatting, locked all-target/all-feature checking, strict Clippy, and
the serialized all-target/all-feature suite passed. The full local suite excluded
only four independently reproduced worktree-fixture cases tracked by #1055;
all other worktree tests passed. Focused coverage includes fresh terminal
resume, active semantic-conflict rejection, clean-artifact cleanup authority,
and planner checkpoint handoff. An alternate-model VDD receipt remains owned by
S-088; deeper isolated-workspace replacement remains tracked by #1160.

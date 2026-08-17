# S-073: Make worktree apply and cleanup transactional

Status: Planned
Effort: Medium
Primary findings: F-060
Workstreams: W15, W18, W24
Depends on: [S-024](./024-artifact-verification-invalidation.md), [S-031](./031-descriptor-safe-persistence.md), [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Never destroy worktree changes after failed or ambiguous preservation, commit, or apply operations.

## Implementation boundary

- Separate preview, stage, commit, merge, discard, and remove effects and bind each approval to exact diff/base/target/worktree generations.
- Retain recoverable refs/snapshots and reconcile every commit/sign/filter/merge failure before any cleanup; make retries idempotent.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- No failure path force-removes untracked, unstaged, staged, committed, conflicted, or inspection-failed work.
- Crash/failure tests at every transition preserve recoverable state and report exact next actions.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

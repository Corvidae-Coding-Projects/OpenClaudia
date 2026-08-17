# S-077: Bind Git review and commit to exact generations

Status: Planned
Effort: Medium
Primary findings: F-110
Workstreams: W2, W15, W18, W24
Depends on: [S-024](./024-artifact-verification-invalidation.md), [S-031](./031-descriptor-safe-persistence.md), [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md), [S-074](./074-workspace-capability-binding.md), [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure CLI review/commit stages and publishes exactly the bytes approved under canonical workspace capabilities.

## Implementation boundary

- Review a bounded diff tied to HEAD, index, worktree, path set, filters/config, and workspace generations; approve explicit paths and destination.
- Use a run-owned index and least-privilege Git profile, return/verify commit identity, and separate local commit from push/PR publication receipts.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Concurrent file/index/HEAD changes invalidate approval and cannot stage an unreviewed generation.
- Hook/filter/signing/staging/commit/push failures leave visible recoverable state and never report clean success.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

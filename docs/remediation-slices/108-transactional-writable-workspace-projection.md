# S-108: Make writable sandbox workspace projection transactional

Status: Planned
Effort: Medium
Primary findings: F-049
Workstreams: W15, W18, W24
Depends on: [S-031](./031-descriptor-safe-persistence.md), [S-042](./042-least-privilege-sandbox-profiles.md)
Crosslink: #1118

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Writable sandboxed processes can perform their intended project edits without
receiving a broad host bind that permits creation of absent protected control
paths or races policy checks.

## Implementation boundary

- Project writable state through a transactional overlay, broker, or equivalent
  descriptor-safe mechanism and reconcile only authorized changes to the host.
- Reject additions or replacements of protected control paths, symlink escapes,
  mount substitutions, and generation changes before reconciliation.
- Preserve normal shell, repository-hook, Git, and MCP project workflows and
  report rollback, conflict, cancellation, and uncertain durability explicitly.
- Keep S-073 worktree apply/cleanup and unrelated sandbox policy changes outside
  this slice.

## Acceptance

- A sandbox cannot create an absent protected control path or denied leaf merely
  because an ancestor project directory is writable.
- Concurrent rename, symlink, and mount changes cannot turn a validated edit
  into an unvalidated host write.
- Successful ordinary source edits reconcile exactly; denied, failed, timed-out,
  and cancelled work leaves the host project unchanged or returns a precise
  recoverable state.
- Linux runtime tests exercise real sandbox projection and reconciliation;
  non-Linux behavior remains explicit and fail-closed where unsupported.
- Relevant deterministic tests and trace assertions pass; attach an
  artifact-bound VDD receipt once S-088 is available.

## Handoff

Record the projection generation, proposed and reconciled diff digests,
commands/tests run, typed evidence receipts, unresolved risks, and any newly
proposed slice. Completion of this slice does not imply completion of its parent
workstream.

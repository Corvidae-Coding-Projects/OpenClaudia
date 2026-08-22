# S-074: Bind isolated workspaces to run capabilities

Status: Planned
Effort: Medium
Primary findings: F-061
Workstreams: W12, W15, W24
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-031](./031-descriptor-safe-persistence.md), [S-073](./073-transactional-worktree-apply.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make the selected worktree a typed session/run capability rather than a path copied into prompts or ambient CWD.

## Implementation boundary

- Create an opaque workspace handle with repository identity, roots, base/target commits, branch, owner, generation, and lifecycle.
- Rebind file, process, LSP, task, ledger, verification, relative-path, and child-run capabilities atomically on enter/exit/resume.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- All operations in an isolated run resolve through its descriptor-bound workspace and cannot mutate the main tree accidentally.
- Concurrent enter/exit/resume, stale handle, removed tree, symlink, and cross-agent ownership tests fail safely.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

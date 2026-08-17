# S-031: Build descriptor-safe persistent storage

Status: Planned
Effort: Medium
Primary findings: F-014, F-083
Workstreams: W15
Depends on: [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Provide one authorized atomic storage API resistant to parent-symlink races and ambiguous post-rename failures.

## Implementation boundary

- Resolve trusted roots and targets descriptor-relatively with owner/type/mode/link checks, bounded files, expected generation, and explicit file classes.
- Return unchanged, committed-durable, published-durability-uncertain, or recovered states and reconcile uncertainty before retry.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Parent and leaf symlink swaps cannot redirect reads/writes outside the capability root.
- Crash, rename, directory-fsync, disk-full, concurrent-writer, and retry tests preserve a knowable committed generation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

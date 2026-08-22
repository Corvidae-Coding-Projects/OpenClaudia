# S-097: Contain TUI file attachments

Status: Planned
Effort: Small
Primary findings: F-131
Workstreams: W12, W15
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-031](./031-descriptor-safe-persistence.md), [S-096](./096-tui-run-cancellation-supervision.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Resolve TUI `@file` attachments through stable workspace snapshots and aggregate context limits.

## Implementation boundary

- Parse references without race-prone prechecks, open descriptor-relatively, and bind content to workspace/file generation, sensitivity, encoding, and truncation.
- Reserve per-file and total attachment byte/token budgets before reading and context inclusion.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Outside-root, parent/leaf symlink race, changed-after-check, special file, oversized, and cancellation cases fail safely.
- Attachment content remains source-labeled data and cannot gain user/system authority by string expansion.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

# S-097: Contain TUI file attachments

Status: Delivered; artifact-bound VDD pending S-088
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

## Delivered architecture — 2026-08-30

TUI `@file` references now remain literal user instructions while their bytes
enter the model context as source-labeled reference data. Parsing requires a
real attachment boundary, so ordinary addresses such as `agent@example.com`
are not misclassified. References resolve through the active run's workspace
capability, open descriptor-relatively, reject directories and special files,
and never trust an ambient current directory or an XML-like text wrapper.

Attachment admission reserves reference count, per-file bytes, aggregate bytes,
and conservative token/projected-context budgets before inclusion. Reads are
asynchronous, cancellation-aware, descriptor-pinned, bounded before EOF, and
verified against the admitted metadata and a repeated byte snapshot so a
rename, rewrite, symlink escape, FIFO, or other unstable object cannot become
context. Invalid UTF-8, binary-like content, duplicates, outside-workspace
paths, and budget violations fail explicitly.

Focused Rust 1.98 verification passed the five parser, containment, oversize,
cancellation, and authority-projection tests plus the changed-after-admission
stable-read test and 17 descriptor-race integration tests. The all-target,
all-feature check, strict Clippy gate, and complete serialized native suite also
pass with zero failures.

## Residual boundaries

- The TUI intentionally rejects rather than truncates an attachment that does
  not fit its declared context budget; silent partial authority is not exposed.
- S-088 still owns the independent artifact-bound VDD receipt.

# S-035: Make notebook editing transactional

Status: Planned
Effort: Medium
Primary findings: F-042
Workstreams: W15
Depends on: [S-031](./031-descriptor-safe-persistence.md), [S-032](./032-snapshot-bound-file-edits.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve valid notebooks and the original file across validation, interruption, and write failure.

## Implementation boundary

- Parse and validate nbformat version, cells, stable IDs, metadata, source/output bounds, and requested operation before mutation.
- Write through snapshot-bound atomic persistence with backup/recovery and round-trip against representative Jupyter notebooks.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Invalid edits never replace the original notebook and interrupted writes recover a valid prior or committed generation.
- Created/updated cells satisfy modern nbformat and stable-ID requirements without dropping unrelated content.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

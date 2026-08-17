# S-032: Bind file edits and diffs to snapshots

Status: Planned
Effort: Medium
Primary findings: F-036, F-039
Workstreams: W15
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure an edit applies only to the bytes reviewed and cannot create unbounded or secret-bearing output.

## Implementation boundary

- Return immutable read snapshots with identity/digest and require edit/write requests to name the expected snapshot generation.
- Preflight replacement growth, match count, file/result size, diff compute/output, encoding, and sensitivity before atomic commit.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A concurrent one-byte change produces a typed conflict rather than overwriting newer content.
- Expansion bombs and sensitive oversized diffs are rejected or returned as bounded redacted artifacts before allocation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

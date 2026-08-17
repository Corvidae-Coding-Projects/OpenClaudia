# S-056: Complete the memdir lifecycle

Status: Planned
Effort: Medium
Primary findings: F-094
Workstreams: W5
Depends on: [S-054](./054-memory-authority-and-schema.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Turn the tested memdir loader into an operational, bounded, reviewable memory source.

## Implementation boundary

- Define discovery scope, file identity/version, ignore/link rules, size/count budgets, incremental refresh, deletion, conflicts, citations, and user controls.
- Integrate memdir through canonical retrieval and context provenance rather than startup prompt concatenation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Create/change/delete/rename, oversized, symlink, corrupt, stale, and concurrent refresh scenarios have typed outcomes.
- Representative retrieval demonstrates cited task value and no automatic instruction authority.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

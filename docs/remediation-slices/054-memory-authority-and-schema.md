# S-054: Make memory untrusted, versioned evidence

Status: Planned
Effort: Medium
Primary findings: F-073, F-074
Workstreams: W5, W15
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-031](./031-descriptor-safe-persistence.md), [S-053](./053-memory-record-identity-and-merge.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop repository/inferred memory from becoming system authority and reject unsupported or partially migrated stores.

## Implementation boundary

- Define strict current/minimum/future schemas, bounded migrations, source/scope/consent/retention/correction metadata, and transactional validation.
- Retrieve memory as cited reference evidence under context budgets and trust policy; host-reviewed preferences use a separate explicit authority grant.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Project, imported, inferred, team, or future-schema memory cannot become instructions through loading or migration.
- Corrupt/partial/future stores fail visibly without writes, while supported migrations preserve identity and provenance.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

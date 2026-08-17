# S-038: Repair session schema migration and ownership

Status: Planned
Effort: Medium
Primary findings: F-070, F-071
Workstreams: W0, W12, W15
Depends on: [S-004](./004-startup-migrations-fail-closed.md), [S-031](./031-descriptor-safe-persistence.md), [S-037](./037-atomic-session-finalization.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make every supported old schema migrate through one owned store without writing unverified claims into another application's directory.

## Implementation boundary

- Define strict minimum/current/future schema handling and chain every supported version through transactional validators.
- Move schema metadata to OpenClaudia-owned storage and make foreign transcript compatibility an explicit bounded importer.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Every old version either migrates to a validated current record or fails without modification; unsupported future versions never open writable.
- Startup performs no unconsumed write in shared transcript directories.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

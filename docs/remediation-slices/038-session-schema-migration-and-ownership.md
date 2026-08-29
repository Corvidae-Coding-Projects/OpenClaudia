# S-038: Repair session schema migration and ownership

Status: Implemented; artifact-bound VDD pending S-088
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

## Delivered — 2026-08-29

- Session persistence now dispatches schema 0 through a deterministic migration,
  accepts schema 1 as current, and rejects future schemas without modifying the
  source. Migration preflights every candidate before descriptor-safe,
  generation-checked publication and validates the published bytes.
- Legacy sessions retain their causal identity, provider state, coordinator
  state, budgets, transcript watermark, and IDE state. Migration strips only
  live invocation authority such as permission receipts, active workspace
  handles, additional roots, and plan approvals.
- Schema metadata and new transcript writes now live under OpenClaudia-owned
  application data. Claude transcript storage is read-only: startup records an
  exact bounded import observation, runtime rejects stale observations, and an
  approved foreign transcript is copied into owned storage before append.
- Transcript reads, discovery, and append paths are bounded and reject links or
  non-regular files. Owned records take precedence when the same session is
  present in both stores.

## Verification evidence

- Rust 1.98 formatting and locked all-target checking passed.
- Strict locked all-feature/all-target Clippy with `-D warnings` passed.
- Migration unit tests passed 24/24, persistence tests passed 14/14,
  migration-runner E2E passed 7/7, transcript unit tests passed 12/12, and
  transcript path E2E passed 22/22, all serialized.
- The foreign-import integration test proves the original Claude JSONL remains
  byte-exact, OpenClaudia seeds owned storage before append, and a changed
  foreign marker makes further foreign reads fail closed.

No VDD receipt is claimed here. S-088 remains the independent artifact-bound
verification boundary.

# S-004: Make startup migrations fail closed

Status: Planned
Effort: Small
Primary findings: F-010
Workstreams: W0, W13, W15
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent startup from continuing with unknown, partially migrated, or failed persistent state.

## Implementation boundary

- Return typed migration outcomes from every startup path and stop or enter an explicit read-only recovery mode on failure.
- Make migrations transactional and idempotent, and expose actionable recovery information without leaking persisted content.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Injected migration failures never start a normal writable agent session.
- Restart, partial-write, old-schema, and already-migrated tests produce deterministic terminal states.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

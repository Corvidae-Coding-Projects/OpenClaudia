# S-037: Make session mutation and finalization atomic

Status: Planned
Effort: Medium
Primary findings: F-067, F-069
Workstreams: W12, W15
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent failed persistence or panicking mutations from discarding session state or leaving invisible partial changes.

## Implementation boundary

- Validate proposed state off to the side, publish one monotonic generation transactionally, and emit events only after commit.
- Represent ending, durability uncertainty, recovery, and terminal outcomes explicitly; retain the last committed state on panic/error.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Injected panic, serialization, disk, fsync, and notification failures never partially mutate the committed session.
- A failed end operation remains recoverable and cannot report successful deletion or completion.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

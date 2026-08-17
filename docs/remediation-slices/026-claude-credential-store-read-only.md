# S-026: Stop mutating the shared Claude credential store

Status: Planned
Effort: Small
Primary findings: F-080
Workstreams: W3, W15
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent OpenClaudia from corrupting or racing another application's credential document.

## Implementation boundary

- Remove write/refresh ownership of the foreign Claude credential file and use an official owning-client interface or a bounded read-only compatibility adapter.
- Store OpenClaudia metadata separately and make credential acquisition cancellable, deadlined, link-safe, mode-checked, and schema-preserving.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Login/refresh/logout tests never rewrite, truncate, normalize, or drop unknown fields from the shared Claude file.
- Concurrent foreign updates and symlink/path changes yield typed unavailable/stale states without holding an unbounded lock.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

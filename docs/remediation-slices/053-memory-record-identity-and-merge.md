# S-053: Give memory stable identity and merge semantics

Status: Planned
Effort: Medium
Primary findings: F-063, F-075
Workstreams: W5
Depends on: [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent consolidation and team synchronization from deleting distinct records or confusing local row IDs with logical identity.

## Implementation boundary

- Introduce global logical IDs, versions, content/source digests, provenance, authorship, conflict/tombstone state, and deterministic merge rules.
- Make consolidation preserve distinct metadata and perform conflict-aware idempotent transactions across local/team stores.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Records with shared text but different source/scope/metadata remain distinct unless an explicit merge rule proves equivalence.
- Concurrent/offline replicas converge without row-ID collisions, silent deletion, or last-writer data loss.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

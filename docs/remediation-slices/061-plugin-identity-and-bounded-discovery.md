# S-061: Bind plugin identity and discovery to trusted scope

Status: Planned
Effort: Medium
Primary findings: F-097, F-101
Workstreams: W26
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent project metadata, collisions, and attacker-controlled links from impersonating trusted plugins.

## Implementation boundary

- Discover through descriptor-safe bounded walks and assign identity from host scope, canonical source, immutable revision/digest, manifest schema, and owner.
- Reject ambiguous names, duplicate components, path/scope forgery, unsupported links, oversized trees/files, and changed trusted packages.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A project plugin cannot claim user/system installation scope or shadow a trusted name nondeterministically.
- Discovery is deterministic, bounded, symlink-safe, provenance-bearing, and invalidates trust on mutation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

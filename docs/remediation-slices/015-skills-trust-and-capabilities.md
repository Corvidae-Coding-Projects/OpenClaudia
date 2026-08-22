# S-015: Finish skills as scoped capabilities

Status: Planned
Effort: Medium
Primary findings: F-028
Workstreams: W16
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-018](./018-non-bypassable-host-safety-policy.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve skills while making discovery, activation, instructions, hooks, and tool grants provenance-aware and enforceable.

## Implementation boundary

- Bound and deterministically cache skill discovery by trusted scope, path identity, digest, schema, and workspace generation.
- Treat skill text as reviewed context data and compile declared tool/hook/file/network needs into explicit capabilities instead of automatic project authority.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Project skills cannot activate or gain instruction/tool authority without the configured trust decision.
- Invocation, conditional activation, freshness, containment, size, collision, and revoked-capability tests pass across frontends.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

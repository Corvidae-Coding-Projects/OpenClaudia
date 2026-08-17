# S-039: Bind resume and branches to causal state

Status: Planned
Effort: Medium
Primary findings: F-072, F-117
Workstreams: W12, W15
Depends on: [S-031](./031-descriptor-safe-persistence.md), [S-038](./038-session-schema-migration-and-ownership.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent project-controlled snapshots or ambiguous transcript IDs from replacing canonical session state.

## Implementation boundary

- Give sessions/branches immutable logical IDs, parent event/generation, provider/workspace/capability generations, digest, provenance, and schema.
- Treat imported branch files as untrusted proposals requiring bounded validation and explicit atomic selection.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Forged, stale, cross-workspace, cross-provider, or cyclic branch/resume data cannot become the active transcript.
- Resume restores one causally closed tool/provider state or returns a typed conflict/unavailable result.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

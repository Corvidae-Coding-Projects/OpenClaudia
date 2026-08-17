# S-036: Provide cross-platform secure file capabilities

Status: Planned
Effort: Medium
Primary findings: F-035
Workstreams: W15
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace the intentional Windows failure with equivalent containment and race-resistant semantics on every supported platform.

## Implementation boundary

- Define platform-neutral filesystem capability contracts and implement Windows handle/reparse-point containment alongside Unix descriptor paths.
- Feature-detect unavailable primitives and fail with an honest platform capability state rather than compile-time product overclaim.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- The same containment, symlink/reparse, file-type, owner/permission, snapshot, and atomic-write conformance suite passes on supported platforms.
- Unsupported environments are rejected at startup/capability registration rather than during ordinary file use.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

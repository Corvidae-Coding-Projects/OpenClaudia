# S-068: Create a stateful workspace LSP service

Status: Planned
Effort: Medium
Primary findings: F-053, F-055
Workstreams: W18, W21
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve complete LSP continuation data and document state in a supervised per-workspace server generation.

## Implementation boundary

- Pool servers by workspace, language, binary/config/version, capability, and generation; own initialize, health, restart, cancellation, and didOpen/change/close versions.
- Return complete bounded call-hierarchy items and opaque continuation tokens tied to the server/document generation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Call hierarchy prepare and follow-up round-trip without losing server data, and stale tokens fail explicitly.
- Fresh/restarted servers receive correct document lifecycle instead of process-global deduplication.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

# S-011: Preserve typed tool results end to end

Status: Planned
Effort: Medium
Primary findings: F-032, F-043, F-121
Workstreams: W2, W12
Depends on: [S-008](./008-typed-context-authority-and-budget.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make tool calls and results a typed control plane that ordinary model or tool text cannot impersonate.

## Implementation boundary

- Carry structured success, error, partial, artifact, display, and follow-up data from handler through provider continuation and frontend rendering.
- Retire XML-like interception and sentinel-text parsing; add an explicit reduced-assurance typed adapter only where a provider truly lacks native calls.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Marker-shaped file, shell, web, and model text is rendered as data and never dispatches a tool or terminal event.
- Provider round-trip tests preserve call IDs, arguments, typed results, parallel ordering, errors, and follow-up state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

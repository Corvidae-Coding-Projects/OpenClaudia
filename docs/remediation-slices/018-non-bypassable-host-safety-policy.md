# S-018: Make host safety non-bypassable

Status: Planned
Effort: Medium
Primary findings: F-016, F-031
Workstreams: W2, W14
Depends on: [S-016](./016-mandatory-tool-effect-classification.md), [S-017](./017-deny-precedence-and-approval-receipts.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Keep hard host safety active even when user permissions are disabled or repository configuration requests unrestricted behavior.

## Implementation boundary

- Separate non-bypassable host policy from user convenience approvals and project proposals; remove optional-manager dispatch semantics.
- Validate configuration provenance and prevent repository files, resume state, alternate dispatch APIs, or `enabled=false` from weakening the ceiling.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Catastrophic and protected-resource tests are denied through every public dispatch path under unrestricted/user-disabled settings.
- Project configuration can request but never silently grant broader host authority.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

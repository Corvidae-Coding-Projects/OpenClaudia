# S-023: Rebuild Reality grounding as an evidence boundary

Status: Planned
Effort: Medium
Primary findings: F-003, F-023, F-046
Workstreams: W4, W18
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-011](./011-canonical-typed-tool-results.md), [S-016](./016-mandatory-tool-effect-classification.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Represent claims and observations as provenance-bound evidence that text cannot forge and final prose cannot bypass.

## Implementation boundary

- Replace public string append/authority APIs with typed evidence receipts tied to run, tool call, artifact, source, and verification method.
- Make finalization query required claim/evidence policy and treat shell/model/tool text labeled “Verifier” as untrusted content.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Plain final text cannot satisfy a required evidence gate and arbitrary command output cannot create authoritative verification.
- Every promoted claim is traceable to a current typed receipt or is explicitly unresolved/unsupported.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

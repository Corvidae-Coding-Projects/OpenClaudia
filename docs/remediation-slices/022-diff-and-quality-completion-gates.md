# S-022: Enforce diff blocks and quality gates

Status: Planned
Effort: Medium
Primary findings: F-085
Workstreams: W2, W28
Depends on: [S-021](./021-run-scoped-blast-radius-guardrails.md), [S-024](./024-artifact-verification-invalidation.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make configured diff review and quality checks actual mutation/finalization gates rather than inert settings.

## Implementation boundary

- Bind a proposed diff and quality-check plan to exact artifact generations before mutation or completion.
- Run checks through canonical bounded process/review capabilities and return typed pass, fail, skipped, stale, and error states.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A configured blocking gate prevents mutation/final success on failure, absence, parse error, or stale artifact.
- Tests cover every configured cadence/action and prove no alternate frontend bypasses the gate.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

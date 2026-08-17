# S-024: Invalidate verification after artifact changes

Status: Planned
Effort: Small
Primary findings: F-024
Workstreams: W4, W15, W28
Depends on: [S-023](./023-reality-evidence-boundary.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Bind verification freshness to exact artifacts and automatically invalidate it after relevant mutation.

## Implementation boundary

- Define artifact sets, digests/generations, dependency closure, verifier identity, and policy version on every receipt.
- Invalidate or supersede receipts atomically on writes, Git changes, task amendments, policy/model changes, and imported state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A one-byte relevant change makes the prior verification unusable for completion.
- Unrelated changes follow an explicit dependency policy, and races between verify and mutate cannot publish a fresh verdict.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

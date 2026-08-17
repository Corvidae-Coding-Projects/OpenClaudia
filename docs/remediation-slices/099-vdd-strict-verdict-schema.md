# S-099: Make VDD verdict parsing strict and fail closed

Status: Planned
Effort: Small
Primary findings: F-134
Workstreams: W28
Depends on: [S-011](./011-canonical-typed-tool-results.md), [S-023](./023-reality-evidence-boundary.md), [S-088](./088-canonical-vdd-verifier-role.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent parse failures, empty output, malformed ranges, and partial responses from being certified as clean.

## Implementation boundary

- Define a strict versioned structured verdict schema with bounded findings, identities, paths, ranges, evidence, uncertainty, and terminal status.
- Normalize and validate model-supplied paths/ranges without panics and fuzz the parser/triage boundary.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Malformed, contradictory, truncated, missing, out-of-range, duplicate, and empty verdicts return error/inconclusive, never clean.
- Known clean and defect fixtures round-trip with stable finding identities and checked citations.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

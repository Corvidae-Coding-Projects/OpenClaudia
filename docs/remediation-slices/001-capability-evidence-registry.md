# S-001: Build the capability evidence registry

Status: Planned
Effort: Medium
Primary findings: F-008, F-142, F-143
Workstreams: W0, W13
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace documentation strings, issue closure, and structural test counts as readiness evidence with a typed capability registry backed by executable scenarios.

## Implementation boundary

- Define capability, maturity, entrypoint, required-effect, trace, and evidence records, including explicit unsupported and experimental states.
- Move user-facing capability tables to registry-derived data and create a reviewed multi-trial evaluation corpus whose graders inspect final environment state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A capability cannot be marked operational without linked executable receipts for its supported entrypoints and failure modes.
- Changing documentation text alone cannot satisfy a capability test, and the evaluation corpus has an independent quality-review record.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

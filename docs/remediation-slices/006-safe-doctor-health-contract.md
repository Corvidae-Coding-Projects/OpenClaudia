# S-006: Rebuild doctor as evidence-safe diagnostics

Status: Planned
Effort: Medium
Primary findings: F-108
Workstreams: W0, W13
Depends on: [S-001](./001-capability-evidence-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make `doctor` report real readiness evidence without spending credentials, mutating state, or fabricating health.

## Implementation boundary

- Classify each diagnostic as offline, read-only, or explicitly active; make offline/non-mutating behavior the default.
- Probe the real composition root with bounded typed checks and return pass, fail, degraded, or skipped receipts with redacted causes.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Default doctor runs do not refresh auth, contact providers, write files, or create runtime state.
- Synthetic empty managers cannot produce a healthy result, and active probes require an explicit scoped grant.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

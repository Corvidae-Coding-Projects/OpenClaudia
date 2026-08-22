# S-089: Isolate ACP sessions and calls

Status: Planned
Effort: Medium
Primary findings: F-123
Workstreams: W12
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-019](./019-explicit-session-capabilities.md), [S-038](./038-session-schema-migration-and-ownership.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give every ACP session independent transcript, provider continuation, model, mode, IDE state, configuration, budget, workspace, and cancellation.

## Implementation boundary

- Map known wire session IDs to canonical run/session handles with owner and exact generation; reject unknown IDs and create truly independent state on new.
- Correlate updates, questions, approvals, configuration, tool results, and cancellation to session plus call ID.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Adversarially interleaved clients cannot read, mutate, cancel, reconfigure, or receive events from another session.
- Load restores the exact persisted generation rather than manufacturing a blank/shared child.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

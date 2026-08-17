# S-059: Unify the hook lifecycle across frontends

Status: Planned
Effort: Medium
Primary findings: F-087
Workstreams: W12, W25
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-058](./058-explicit-hook-import-trust.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Run hooks at one canonical set of typed lifecycle events with consistent decision and output semantics.

## Implementation boundary

- Define supported pre/post run/model/tool/compaction/session events, typed inputs/outputs, ordering, denial, modification, observation, timeout, and partial-failure policy.
- Move orchestration from TUI/proxy/legacy paths into the runtime and make frontends render the same hook receipts.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A conformance fixture produces identical lifecycle ordering and effective decisions through every supported frontend.
- Unwired event/config fields are implemented or rejected during validation rather than silently ignored.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

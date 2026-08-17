# S-013: Implement real progressive tool discovery

Status: Planned
Effort: Medium
Primary findings: F-005, F-058
Workstreams: W11
Depends on: [S-001](./001-capability-evidence-registry.md), [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Advertise a bounded task-relevant tool subset without bypassing policy or pretending the full catalog is deferred.

## Implementation boundary

- Build a generation-keyed catalog over core, MCP, plugin, skill, and dynamic tools with deterministic retrieval and a measured full-catalog fallback.
- Require selected schemas to pass the same classification, capability, approval, and execution checks as directly named tools.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Prompt/tool-schema bytes fall on representative tasks without reducing needed-tool recall below the accepted baseline.
- Unknown, stale, over-cap, or directly requested names cannot bypass catalog generation or effect policy.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

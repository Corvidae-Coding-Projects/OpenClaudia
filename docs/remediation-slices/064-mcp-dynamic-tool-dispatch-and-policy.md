# S-064: Complete MCP dynamic tool dispatch and allowlists

Status: Planned
Effort: Medium
Primary findings: F-090, F-138
Workstreams: W2, W6, W11
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-013](./013-progressive-tool-catalog.md), [S-016](./016-mandatory-tool-effect-classification.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Advertise only callable MCP tools and enforce configured server/tool policy through the canonical executor.

## Implementation boundary

- Register discovered schemas with stable server/tool identity, trust, generation, availability, typed effects, and capability requirements.
- Dispatch calls through the owned MCP manager and revalidate server/tool allowlists, schema, arguments, approval, and generation at execution.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Every advertised MCP tool can complete a model call/result round trip or is removed with an explicit unavailable state.
- Unlisted, renamed, stale, direct-selected, or plugin-provided tools cannot bypass the configured allowlist.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

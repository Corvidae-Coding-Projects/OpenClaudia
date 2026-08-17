# S-091: Make ACP modes and advertised tools effective

Status: Planned
Effort: Medium
Primary findings: F-125
Workstreams: W2, W17
Depends on: [S-014](./014-runtime-enforced-behavioral-modes.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-089](./089-acp-session-isolation.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure ACP advertises only tools and modes whose capability profiles are actually enforced by its canonical session.

## Implementation boundary

- Generate capabilities/modes/tool schemas from the active registry and bind negotiated changes to a new validated run capability generation.
- Route Initializer, Coding, planning, read-only, dynamic MCP/plugin, and unavailable-tool behavior through the same policy as other frontends.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- An ACP client cannot call a tool or effect forbidden by the displayed mode/capability set.
- Advertised schemas exactly match executable registered generations under concurrent configuration changes.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

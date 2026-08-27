# S-091: Make ACP modes and advertised tools effective

Status: Complete
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

## Completed implementation — 2026-08-27

ACP now advertises initializer, coding, plan, and read-only modes from canonical
runtime policy and derives its tool catalog from the exact run capability and
mode generation. Negotiating a mode validates the transition before mutating
live state, installs that generation's MCP and plugin integrations, and only
then replaces the session run. Calls published by an older catalog generation
are rejected after a mode or dynamic-integration change.

Tool execution now carries the exact run context through admission, so an ACP
client cannot execute effects omitted by its advertised mode. Per-run dynamic
MCP/plugin schemas participate in the same catalog generation rather than
forming an ACP-only bypass.

Rust 1.98 formatting, locked all-target/all-feature checking, strict Clippy, and
the serialized all-target/all-feature suite passed with only the unrelated
#1055 local fixture exclusions. Focused tests cover canonical plan-mode
advertisement, mode-generation rotation, denial of unadvertised effects, and
rejection of calls published before a runtime generation change. VDD remains
owned by S-088; the broader isolated-workspace transition is tracked by #1160.

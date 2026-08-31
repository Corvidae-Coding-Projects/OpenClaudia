# S-075: Create one typed command registry

Status: Implemented; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-105
Workstreams: W12
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-011](./011-canonical-typed-tool-results.md), [S-016](./016-mandatory-tool-effect-classification.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace manual command catalogs and side-effecting parsers with one schema/effect/capability-backed registry.

## Implementation boundary

- Define canonical names, aliases, typed arguments, effects, required capabilities, frontend availability, and help/completion metadata beside handlers.
- Make parsing pure and route proposed actions through canonical authorization, execution, budget, trace, and typed rendering.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Construction rejects duplicate aliases and unsupported combinations, and generated help/completion/matrices match dispatch.
- No slash, CLI, plugin, or legacy command performs side effects during parsing or bypasses the normal lifecycle.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered — 2026-08-29

- One collision-checked typed registry now owns command identity, aliases,
  argument schema, effect ceiling, required capabilities, frontend availability,
  completion type, and help rows for both interactive frontends.
- Parsing is pure. Execution resolves the concrete effect and capabilities,
  requires a run for external/workspace/network/destructive effects, and applies
  capability, mode, budget, and trace admission before invoking a handler.
- Legacy REPL and TUI dispatch, streaming key actions, generated help, and
  completion now consume the canonical registry. The former handwritten
  `chat_repl` effect list is removed, and README's TUI command table is guarded
  against runtime drift.
- Dynamic plugin commands remain namespaced typed proposals and direct TUI
  skills remain explicit proposals; neither performs work during parsing.

## Verification evidence

- Rust 1.98 formatting, locked all-target checking, and strict locked
  all-feature/all-target Clippy with `-D warnings` passed.
- Registry unit tests passed 5/5, generated slash catalogue tests passed 4/4,
  subagent/slash E2E passed 27/27, and the TUI application suite passed 86/86,
  all serialized. Exact README/runtime command-table parity also passed.

S-077 may now build generation-bound Git review/commit execution on the typed
command boundary. No VDD receipt is claimed here; S-088 remains the independent
artifact-bound verification boundary.

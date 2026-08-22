# S-075: Create one typed command registry

Status: Planned
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

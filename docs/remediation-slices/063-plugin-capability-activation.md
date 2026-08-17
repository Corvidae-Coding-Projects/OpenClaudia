# S-063: Activate plugin capabilities through canonical registries

Status: Planned
Effort: Medium
Primary findings: F-100
Workstreams: W2, W6, W16, W21, W25, W26
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-013](./013-progressive-tool-catalog.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-059](./059-canonical-hook-lifecycle.md), [S-061](./061-plugin-identity-and-bounded-discovery.md), [S-062](./062-plugin-supply-chain-transactions.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make declared plugin commands, hooks, skills, agents, MCP, and LSP components either operational with provenance or honestly unavailable.

## Implementation boundary

- Compile reviewed package components into namespaced generation-bound registrations with exact effects, schemas, capabilities, and lifecycle ownership.
- Route each component through its canonical subsystem and atomically remove schemas/context plus cancel owned work on disable/update.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- The capability registry proves invocation and shutdown for every advertised component type.
- The working command path retains package/source/capability provenance and no declared component bypasses normal policy.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

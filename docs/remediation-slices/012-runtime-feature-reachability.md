# S-012: Wire or honestly classify lifecycle services

Status: Planned
Effort: Medium
Primary findings: F-006
Workstreams: W9, W13
Depends on: [S-001](./001-capability-evidence-registry.md), [S-010](./010-canonical-run-context-and-events.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give every configured service one real production consumer or an explicit unavailable/experimental classification.

## Implementation boundary

- Inventory analytics, flags, background jobs, compaction, MCP, memory, guardrail, and related service registrations against the actual composition root.
- Wire selected services through the canonical runtime with lifecycle ownership; remove only duplicate scaffolding after its intended outcome is represented elsewhere.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- The capability registry can prove the construction-to-shutdown path for every advertised service.
- Configured-but-unconsumed fields fail validation or are visibly experimental rather than silently doing nothing.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

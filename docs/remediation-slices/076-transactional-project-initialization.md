# S-076: Make project initialization transactional

Status: Planned
Effort: Medium
Primary findings: F-107
Workstreams: W1, W14, W15, W25
Depends on: [S-007](./007-remove-legacy-rule-injector.md), [S-031](./031-descriptor-safe-persistence.md), [S-058](./058-explicit-hook-import-trust.md), [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent initialization from overwriting existing state or scaffolding deprecated and implicitly trusted authority paths.

## Implementation boundary

- Generate a bounded typed plan, detect every collision, show exact files/effects, and commit through an atomic staged directory transaction with explicit force semantics.
- Generate schema-valid minimal configuration and inert examples; do not install rule injection, executable hooks, fictitious endpoints, or unsupported claims.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Default init leaves any existing file untouched and a failed/interrupting init leaves no partial project state.
- Generated trees deserialize under current schemas and grant no executable/instruction authority merely by existing.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

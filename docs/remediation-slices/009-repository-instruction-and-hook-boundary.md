# S-009: Remove repository-owned control authority

Status: Planned
Effort: Medium
Primary findings: F-140
Workstreams: W1, W12, W25
Depends on: [S-007](./007-remove-legacy-rule-injector.md), [S-008](./008-typed-context-authority-and-budget.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop inherited prompts and repository hooks from impersonating host policy or silently controlling agent behavior.

## Implementation boundary

- Replace the inherited monolithic Claude prompt with minimal accurate host-owned policy and remove identity/tool claims that do not match the runtime.
- Make repository hook/settings discovery an explicit reviewed import; repository content remains data until a host capability grants a typed extension.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A malicious checkout cannot activate executable hooks or add system instructions merely by containing recognized files.
- Compatibility imports display source, digest, requested events/effects, and require reapproval after mutation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

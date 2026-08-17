# S-058: Require explicit trust for hook imports

Status: Planned
Effort: Medium
Primary findings: F-086
Workstreams: W25
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-018](./018-non-bypassable-host-safety-policy.md), [S-025](./025-end-to-end-secret-types-and-redaction.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop ambient Claude/user/project settings from granting executable or instruction authority.

## Implementation boundary

- Make compatibility discovery a bounded proposal containing source scope/path/digest/owner, events, executables, outputs, and requested capabilities.
- Store host approval outside the repository and require reapproval on content, path, owner, workspace, or capability change.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Checking out a repository cannot activate a hook or weaken host policy without an explicit receipt.
- Malformed, ambiguous, oversized, symlinked, foreign, and changed imports fail atomically and visibly.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

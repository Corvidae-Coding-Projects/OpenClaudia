# S-060: Sandbox and budget hook execution

Status: Planned
Effort: Medium
Primary findings: F-088
Workstreams: W10, W18, W25
Depends on: [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-058](./058-explicit-hook-import-trust.md), [S-059](./059-canonical-hook-lifecycle.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent hook command-policy bypass and concurrent unbudgeted execution.

## Implementation boundary

- Resolve trusted executable identity and arguments without shell-string reinterpretation; run under the declared least-privilege profile.
- Reserve aggregate process/model/time/byte/cost/concurrency budgets before launching matching hooks and cancel/join all work on denial or run end.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Aliases, wrappers, quoting, environment, path changes, and repository executables cannot bypass hook policy.
- A deny result cannot arrive after unbounded sibling side effects, and overload produces a typed skipped/degraded state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

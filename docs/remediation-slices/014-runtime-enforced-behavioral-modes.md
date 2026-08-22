# S-014: Make behavioral modes enforce capabilities

Status: Planned
Effort: Medium
Primary findings: F-029, F-064, F-119
Workstreams: W2, W17
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Turn planning, read-only, scope, and coordinator modes into validated runtime capability profiles rather than prompt labels.

## Implementation boundary

- Define each mode as allowed effects, tools, budgets, transitions, conflicts, and approval semantics; compile prompts only as explanatory projections.
- Route CLI, TUI, ACP, proxy, and resumed sessions through one atomic mode transition with negative tests for every prohibited facade.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Plan/read-only modes deny task, todo, Crosslink, shell, Git, worktree, network, and indirect mutation unless explicitly permitted by the profile.
- `/plan`, flags, and ACP mode changes all install the same effective capability generation or fail visibly.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

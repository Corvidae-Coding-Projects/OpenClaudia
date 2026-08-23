# S-014: Make behavioral modes enforce capabilities

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
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

## Implementation record — 2026-08-23

- Signed commit `6dc02af1` installs typed runtime capability profiles and routes
  TUI, legacy REPL, ACP, proxy, session restore, tools, and child runs through
  the same atomic mode authority.
- Signed follow-ups `e6944c69`, `5738f231`, and `6f31d170` bind explicit
  adjacent/narrow targets, complete typed full-screen TUI plan follow-ups, and
  serialize restrictive transitions with exact-run background-effect
  registration. Active shells or workers now produce a typed refusal without
  publishing a new generation; explicit `kill_shell`/`task_stop` preserves
  user choice.
- Rust 1.98 formatting, strict all-target/all-feature Clippy, complete
  serialized workspace tests, Windows GNU compilation, and focused mode,
  target-binding, TUI, shell, worker, and transition-race tests passed.
- Registry generation 4 therefore classifies behavioral modes as `partial`
  rather than `experimental`. `Operational` remains withheld until canonical
  artifact-bound VDD receipts cover the production entrypoints and failures.

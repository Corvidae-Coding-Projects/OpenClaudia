# S-052: Consolidate task and planning state

Status: Implemented and adversarially reviewed; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-057, F-065
Workstreams: W20
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace todos, TaskManager, Crosslink planning views, and mode-local task state with one versioned transactional graph.

## Implementation boundary

- Define stable IDs, actor/run ownership, statuses, dependencies, blockers, active forms, versions, history, pagination, and persistence.
- Validate complete proposed mutations for cycles, missing nodes, blocker readiness, edge symmetry, and expected generation before atomic commit.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A failed or stale update leaves the previous graph unchanged and emits no misleading success event.
- Todos, planning, delegation, and external issue views reconcile through explicit adapters and cannot carry security identity.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implemented architecture — 2026-08-22

`TaskGraph` schema version 1 is now the single durable representation behind
the task, todo, approved-plan, supervised-delegation, and external-issue
surfaces. A graph carries stable monotonic task IDs, graph generation and
per-task revision counters, exact actor/run/session provenance, priorities,
active forms, finite planning-budget requests, reciprocal dependency edges,
terminal timestamps, and the complete current lifecycle. Provenance is data:
no actor, run, plan, task, or external-issue identifier grants filesystem,
process, provider, network, approval, or child-run authority.

Every write builds a complete proposal from an expected graph generation and,
for updates, an expected task revision. Validation covers missing endpoints,
edge symmetry, cycles, blocker readiness, ownership, one non-delegated active
task per session lane, source-specific lifecycle rules, terminal timestamps,
capacity, and every bounded string/value before publication. A failed, stale,
or semantic no-op proposal cannot partially demote another task or append a
misleading history event. Durable managers refresh before proposals and commit
through the S-031 descriptor-safe, generation-checked persistence layer before
replacing live state.

The graph is deliberately finite: 512 retained nodes, 128 edges per task,
100 rows per page, bounded cursors and fields, and 4,096 retained history
events. Older history advances a SHA-256 causal checkpoint in the
`openclaudia.task-history.v1` domain; current task state remains complete and
resumable. Pagination cursors bind the observed generation, so a caller cannot
silently continue across a concurrent mutation. Task budget fields are bounded
planning requests only; S-051 remains responsible for runtime admission and
enforcement.

## Wired projections

- `task_create`, `task_update`, `task_get`, and `task_list` use the canonical
  manager and expose generation/revision conflicts, pagination, priority,
  readiness, failure, cancellation, and tombstones through typed results.
- `todo_write` performs one complete generation-checked reconciliation;
  `todo_read` is a compatibility projection over the same graph. It cannot
  rewrite plan, delegation, or external-issue lifecycles.
- Plan approval binds the exact approved-plan digest as typed provenance and
  reconciles its lifecycle without parsing prose into authority or hidden task
  identity.
- Subagent launch creates an in-progress delegation projection bound to the
  exact supervised agent ID. Completion, cancellation, failure, drop, and
  resume transition that same node; ordinary task APIs cannot forge those
  transitions. Delegated workers may run in parallel without violating the
  one-active-task rule for ordinary session lanes.
- Crosslink queries and mutations reconcile a dependency-closed external view.
  External rows are read-only projections with no active form or execution
  budget. The block/unblock adapter now uses the database's actual
  `(target, blocker)` contract, and a real SQLite regression proves dependency
  direction, readiness, close transitions, and graph edges agree.
- Legacy CLI, TUI/pipeline, ACP, and subagent frontends open or bind a durable
  manager for their exact run/session. ACP uses independent per-session locks;
  planning in one session does not serialize unrelated sessions.

Compatibility entry points remain adapters over canonical managers rather than
a second task representation. Existing task and todo features were wired, not
removed.

## Artifact generations

- `src/task_graph.rs` schema version 1 SHA-256:
  `2f361571fdf9e145c30b9bab6e116efc36240ecdd73b16c395e7b938bf99c17f`.
- S-052 changed a source file cited by the S-105 final-environment retrieval
  corpus. The citation now honestly uses `worktree:s052`; the checked-in
  evaluator regenerated the evidence and the deliberately rejected review was
  rebound. Held-out, evaluation, and review SHA-256 values are respectively
  `6cc7bd6028c8c01fe73a4836c4fe80972ebce63f78f7290d3237974742ad8173`,
  `7f9765542cf8041b77d431e21077bd6ad7a77faa3117f507dc5e9a66bf13a9f8`,
  and `fae2ac9f8e87f950c92b2e0d2099b918776dcfda3bc07c14b3d43feac89339c4`.
  The sorted manifest digest for S-105's 15 non-slice artifacts is
  `70c9b9c793e3089cb2291f9ae4a395a1ab88902302b69e2d1007b14f41006c7c`.

## Verification evidence

All Rust commands used Rust 1.98.0 with `CARGO_BUILD_JOBS=4`; every test command
used `--test-threads=1`.

- Formatting and format checking passed.
- Canonical graph unit tests passed 20/20, including stale graph/task versions,
  cycle rollback, byte-exact no-ops, session-lane resume, delegation binding,
  forged projection state, pagination, descriptor-safe persistence, and
  history beyond 4,096 generations.
- Tool registry schema passed 27/27, task dispatch passed 33/33, and subagent
  configuration/result coverage passed 18/18.
- Retrieval evidence unit tests passed 7/7 and final-environment evidence E2E
  passed 9/9 after regeneration.
- Locked all-feature/all-target Clippy with `-D warnings` passed without lint
  suppression. The repair cycle removed oversized transaction/handler bodies
  and fixed all slice-caused diagnostics at their source.
- The complete locked all-feature/all-target native suite exited successfully.
  The library harness discovered 2,747 tests; all 2,746 non-ignored tests
  passed, one was ignored, and every binary, integration, example, and other
  test target passed.
- Locked all-feature/all-target Windows GNU `cargo check` passed. Its warnings
  were pre-existing target-conditional findings outside S-052; no S-052 path
  emitted a warning.

The skeptical repair cycle additionally corrected stale plan-mode tool
descriptions, terminal todo summaries, unsafe existing-root permission repair,
unbounded tree/schema inputs, cross-session ACP locking, retry
misclassification, reversed Crosslink dependency arguments, and S-105's
overly specific provenance label. Tests assert final graph/database state and
atomic byte stability rather than treating an error count or lack of panic as
success.

## Residual boundaries

- Crosslink 0.9.0-beta.1 materializes unbounded `Vec<Issue>` values inside its
  database API before OpenClaudia can enforce its adapter limits. SQL-level
  limit/cursor support is tracked as #1085; local result, projection, tree
  depth/node, and output caps remain enforced meanwhile.
- The 512-node lifetime cap fails closed rather than silently dropping history,
  but a very long-lived session can exhaust it through terminal tombstones.
  Causal compaction without ID reuse is tracked as #1087.
- S-051 owns runtime budget reservation/enforcement; these task budget fields
  cannot allocate authority.
- S-088 owns the independent alternate-model, artifact-bound VDD verdict. This
  slice does not claim that review has occurred.

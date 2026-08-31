# S-059: Unify the hook lifecycle across frontends

Status: Implemented and deterministically verified; artifact-bound VDD receipt not recorded
Effort: Medium
Primary findings: F-087
Workstreams: W12, W25
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-058](./058-explicit-hook-import-trust.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Delivered — 2026-08-27

Commit `399a19e9` wired canonical typed hook receipts through ACP new/load,
legacy REPL, print mode, TUI, proxy, and subagent lifecycle paths. Blocked starts
retire run state, terminal paths emit `SessionEnd` or `SubagentStop`, TUI terminal
state is restored consistently, and per-run sequence state is pruned.

## Verification evidence

Crosslink issue #1163 records Rust 1.98 formatting and strict
all-target/all-feature Clippy as passing, together with focused hook (82), ACP
(105), subagent (82), proxy (50), TUI (82), configuration (147), and selected
frontend integration tests. The serialized library run passed 2,948 tests and
exposed four separate dirty-real-worktree fixture failures tracked outside this
slice rather than lifecycle regressions.

## Residual boundary

Hook process admission, sandboxing, and aggregate reservation are intentionally
separate S-060 work. An independent artifact-bound VDD receipt was not recorded
for this slice.

## Outcome

Run hooks at one canonical set of typed lifecycle events with consistent decision and output semantics.

## Implementation boundary

- Define supported pre/post run/model/tool/compaction/session events, typed inputs/outputs, ordering, denial, modification, observation, timeout, and partial-failure policy.
- Move orchestration from TUI/proxy/legacy paths into the runtime and make frontends render the same hook receipts.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A conformance fixture produces identical lifecycle ordering and effective decisions through every supported frontend.
- Unwired event/config fields are implemented or rejected during validation rather than silently ignored.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

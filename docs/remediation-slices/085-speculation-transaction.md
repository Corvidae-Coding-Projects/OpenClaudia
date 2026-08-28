# S-085: Implement or remove speculation by measurement

Status: Complete
Effort: Medium
Primary findings: F-104
Workstreams: W7
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-019](./019-explicit-session-capabilities.md), [S-051](./051-token-turn-and-cost-budgets.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace speculation scaffolding with a safe artifact-bound optimization that survives only if it beats a simpler baseline.

## Implementation boundary

- Limit predictions to deterministic idempotent read-only operations in disposable snapshots with exact arguments/input generations, confidence, deadline, budget, cancellation, and result handle.
- Require exact later-call match and complete successful receipt for reuse; otherwise cancel/join and discard without side effects.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Speculative work has no network, secrets, writes, approvals, external effects, or run-independent lifetime.
- Measured task correctness, latency, hit rate, waste, and cost beat demand cache/prefetch; otherwise the mechanism is removed with evidence.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Completed implementation — 2026-08-27

Speculation is now a run-owned optimization for one narrow operation: the exact
next page of a successful partial `read_file`. A complete authoritative result
may seed one bounded prediction whose call ID, run ID, capability generation,
path, cursor, limit, content digest, stable file snapshot, deadline, and
cancellation handle are fixed before capture. It receives no network, secret,
write, process, approval, or run-independent authority.

The TUI follow-up loop carries the coordinator through canonical run
transitions and the normal tool executor admits a matching precomputed read
through the same policy, permission, guardrail, accounting, and typed-result
boundary as an on-demand read. Consumption reopens the exact confined file and
compares stable metadata to reject mutation without performing a second full
read. Mismatch, expiry, cancellation, incomplete/error results, or stale run
generation joins and discards the artifact.

A bounded measurement window records correctness, hits, waste, critical-path
latency, and byte-cost against the demand baseline. Speculation remains enabled
only after sufficient exact hits, zero correctness loss, bounded waste, lower
critical-path latency, and no greater I/O cost. The skeptical parent review
repaired the worker version's second full demand read, which had made every hit
self-defeating and forced admission to disable.

## Evidence

- Deterministic speculation tests passed 8/8: trusted prediction shape,
  rejection of error/non-read seeds, exact argument matching, successful
  canonical commit and admission, mutation invalidation, measurement gates,
  disable behavior, and bounded history.
- The all-feature library, pipeline, file, executor, and TUI integration tests
  passed under the complete serialized Rust 1.98.0 suite.
- `cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
  passed with zero diagnostics.
- `cargo +1.98.0 test --quiet --locked --all-targets --all-features --
  --test-threads=1` passed every non-ignored target.

## Residual boundaries

- The predictor deliberately handles only final-page continuation reads. New
  operation classes require their own evidence that they are deterministic,
  effect-free, and measurably better than demand execution.
- Metrics are run-local and conservative; a fresh run earns admission again
  rather than inheriting an unverifiable historical win.
- S-100 retains canonical finalization authority. No alternate-model VDD pass
  receipt is represented here.
- Completion applies only to S-085; parent issue #1071 remains open.

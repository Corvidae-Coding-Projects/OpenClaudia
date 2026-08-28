# S-084: Turn cron metadata into a scheduler service

Status: Complete
Effort: Medium
Primary findings: F-051
Workstreams: W2, W10, W12, W15, W18, W19
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-029](./029-oauth-session-lifecycle.md), [S-031](./031-descriptor-safe-persistence.md), [S-040](./040-supervised-foreground-process-io.md), [S-051](./051-token-turn-and-cost-budgets.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve scheduling as durable authorized agent runs instead of inert cron-shaped records.

## Implementation boundary

- Define schedule/timezone/DST/misfire/overlap/retry/max-run/expiry semantics and bind owner, task, capabilities, budgets, notification, and revocable approval.
- Use trusted storage, leases/fencing, idempotent run IDs, canonical runtime dispatch, supervised effects, and exact run/delivery history.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Virtual-time, restart, concurrent scheduler, DST, catch-up, overlap, cancellation, revoked permission, and crash-transition tests pass.
- The product either executes and reports schedules end to end or labels stored metadata explicitly non-executing.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Completed implementation — 2026-08-27

`cron_create` now requires a fresh exact host approval and writes a bounded
durable schedule into trusted user state rather than executable project
metadata. The record binds actor, workspace, capability generation, provider,
model, exact tool allowlist, turn/output/tool/cost budgets, UTC timezone,
misfire and overlap policy, retry/backoff, maximum runtime, expiry, and run
limit. Legacy `.openclaudia/schedules.json` records remain readable and
deletable but are labeled unapproved and are never executed automatically.

The full-screen TUI owns one `SchedulerServiceHandle` for its active immutable
run generation. The service uses compare-and-swap storage generations,
monotonic fences, deterministic occurrence run IDs, durable leases, bounded
history, and concurrent dispatch for distinct schedules. Each occurrence runs
through the canonical scheduled-child harness with its exact capabilities,
budgets, cancellation tree, provider configuration, and terminal outcome.
Startup is fail-closed; normal TUI shutdown cancels, drains, settles, and joins
the scheduler before session retirement. Provider, workspace, and loaded
session transitions cancel the prior owner before rebinding.

The skeptical parent review repaired production lifecycle wiring, accidental
serialization of independent schedules, active-provider model selection,
typed argument diagnostics, the exact approval-aware dispatch test path, and
stale lifecycle/classification assertions.

## Evidence

All Cargo verification used Rust 1.98.0 with `CARGO_BUILD_JOBS=4`; the complete
repository suite was serialized.

- Scheduler policy tests passed 7/7: deterministic occurrence identity,
  explicit UTC/DST behavior, one-winner concurrent claims, concurrent distinct
  leases, overlap recording, capability revocation, and abandoned-lease retry.
- Approval-aware cron registry tests passed 21/21, including durable
  create/list/delete, duplicate rejection, malformed calls, and proof that
  read-only listing does not create legacy lock or data files.
- Lifecycle catalog and service-registry tests pass with the scheduler marked
  wired only where its construction, consumer, and shutdown paths are named.
- `cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
  passed with zero diagnostics.
- `cargo +1.98.0 test --quiet --locked --all-targets --all-features --
  --test-threads=1` passed every non-ignored library, binary, example,
  and integration target selected by the command.

## Residual boundaries

- OpenClaudia is not installed as an always-on system daemon. Due occurrences
  execute while the full-screen TUI owns the scheduler; durable state and
  expired-lease recovery preserve restart behavior between launches.
- Notification delivery is durable in-product history. External notification
  transports require a separate explicit destination and authority contract.
- S-100 retains canonical finalization authority. This slice records
  deterministic evidence and does not claim an alternate-model VDD pass
  receipt.
- Completion applies only to S-084; parent issue #1071 remains open.

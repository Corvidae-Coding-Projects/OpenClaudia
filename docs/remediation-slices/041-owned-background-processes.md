# S-041: Own background process lifetime and output

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-047
Workstreams: W10, W18
Depends on: [S-040](./040-supervised-foreground-process-io.md), [S-051](./051-token-turn-and-cost-budgets.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Turn background shells into generation-safe supervised jobs with bounded durable output and explicit ownership.

## Implementation boundary

- Bind each job to run/session/workspace, command capability, process generation, budgets, output artifact, retention, and cancellation tree.
- Replace global PID maps and in-memory ring ambiguity with typed start/status/read/cancel/join operations and restart reconciliation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Session end, cancellation, timeout, and restart cannot orphan a child or confuse a reused PID with an old job.
- Output caps apply during draining and callers can distinguish running, exited, killed, truncated, lost, and delivery-failed states.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record (2026-08-23)

- Background shells are now owned jobs identified by full UUIDs and bound to the exact run, session, stable process owner, workspace and capability generations, and run-budget generation. Normal frontends persist private job records under the user data directory; hermetic tests use run-private ephemeral storage. First-use recovery is serialized so parallel tool calls cannot observe a partially hydrated session.
- Each job has typed `starting`, `running`, `exited`, `killed`, `timed_out`, `cancelled`, `delivery_failed`, and restart-reconciled `lost` states. Recovery never reattaches to a persisted PID, so PID reuse cannot transfer process authority.
- The supervisor holds the process budget and freshness reservation until terminal completion, applies the smaller of the requested timeout and remaining run budget, terminates the sandbox process tree on timeout or cancellation, reaps the root process, and drains both output pipes before publishing the terminal receipt.
- Stdout and stderr are persisted as sequenced fixed-size read events. Retained output is capped at 2 MiB per job, reads are capped at 256 KiB per page, explicit cursors provide read-only replay, and legacy cursorless polls advance a durable compatibility cursor. Terminal records remain readable after completion or cancellation.
- Run, process-owner, and session cleanup act only on matching active jobs. Cross-run access is denied except for restart-reconciled lost records presented by the same session, workspace, and stable process owner.
- The `bash` schema now applies `timeout` to background work, and `bash_output` exposes the cursor contract with matching read-only/session-mutation effect classification.

Verification used Rust 1.98.0 with `CARGO_BUILD_JOBS=4` and serialized test execution:

- `cargo +1.98.0 test --locked --workspace --all-targets --all-features -- --test-threads=1`
- `cargo +1.98.0 clippy --locked --workspace --all-targets --all-features -- -D warnings`
- `cargo +1.98.0 fmt --all -- --check`
- Windows GNU all-target/all-feature compilation passed; the existing target-conditional warning cleanup remains tracked by Crosslink #1099.

Technical-memory retrieval evidence is bound to `src/tools/bash/mod.rs` at `sha256:300ac7a4c9f5129ecbbccd4a02e8d2efb730f45b7592881ba99241708a20e317` and `tests/bash_background_e2e.rs` at `sha256:79a96744947ff169593aab982b11c398590663ea9b89c04631e6b2051e7d98b9`. The generated evaluation digest is recorded with the checked-in evaluation artifact; independent artifact-bound VDD remains deferred to S-088.

This slice intentionally does not introduce platform cgroups or redesign process supervision around an async runtime. Those are not required for the application-level ownership, timeout, bounded-output, restart, and isolation guarantees delivered here.

# S-040: Supervise foreground process I/O

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-044
Workstreams: W18
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-025](./025-end-to-end-secret-types-and-redaction.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Apply deadlines, cancellation, and byte limits to process creation, stdin writing, output draining, and descendant cleanup.

## Implementation boundary

- Use one async supervisor with bounded input/output queues, aggregate deadline, process-group/job ownership, cancellation, and typed partial outcomes.
- Make blocked stdin, inherited handles, stderr floods, exit races, and cancellation join the same terminal-state machine.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A child that never reads stdin cannot outlive the deadline or block the runtime thread.
- Timeout/cancellation reaps descendants and reports exact exit, truncation, and delivery state without detached work.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record — 2026-08-23

`src/tools/command.rs` now owns one Tokio lifecycle for run-owned foreground
children. Stdin delivery, bounded stdout/stderr drain, root exit, the aggregate
deadline, and the run cancellation receipt advance concurrently. Every Unix
child leads an owned process group. Deadline, cancellation, or I/O failure
force-stops the tree, reaps the root, aborts and joins every I/O task, and
returns a typed partial snapshot containing root status, retained bytes,
per-stream truncation, and exact stdin delivery state. Input is capped at 64
MiB; normal capture is capped at 10 MiB per stream and hooks retain their
existing 1 MiB per-stream contract.

Synchronous PDF, Git/worktree, short MCP-helper, LSP-ignore, subagent-helper,
and Bash callers use a runtime-aware bridge to that same lifecycle. Async
command hooks, guardrail quality gates, and VDD static analysis now call the
supervisor directly; their former independent spawn/write/wait/reader loops and
blocking-worker adapters are gone. Long-lived MCP and LSP transports remain
with S-066, S-068, and S-069 rather than being conflated with foreground
commands.

The Bash tool now exposes and enforces its previously ignored `timeout`
argument as 1 through 600,000 milliseconds, with a 300,000 millisecond
default. Timeout is intentionally rejected for background mode until S-041
gives jobs a complete duration/budget contract. Started commands that time out
remain canonical partial outcomes and include bounded retained diagnostics.

The shared lifecycle fixes #1020 at its observed cause: reader completion after
root exit remains inside the same deadline, so a descendant-held pipe cannot
hang the caller. The adjacent #1067 cleanup now force-stops a tracked background
sandbox when either the root is live or a reader has not reached EOF, then
waits for the existing waiter/readers to publish reap/drain completion. This is
the minimum shared-cause repair; global job identity, persistence, output
cursors, resource budgets, and restart reconciliation remain S-041.

Deterministic regressions cover blocked stdin, a root that exits while a
descendant retains its output pipe, run cancellation with `/proc` reap proof,
bounded high-volume output, hook stdin blockage, the public Bash timeout, and
background sandbox PID disappearance. Focused hook, guardrail, VDD,
tool-registry, process, Bash, and technical-memory evidence tests pass. Rust
1.98 formatting and strict locked workspace/all-target/all-feature Clippy pass;
locked Windows GNU workspace/all-target/all-feature compilation also passes
with only the pre-existing target-conditional warnings tracked by #1099. The
complete locked workspace/all-target/all-feature native suite passes with
serialized test execution; the main library harness reports 2,867 passed and
one ignored, with no failures anywhere in the suite.

Because the technical-memory tuning corpus cites the exact Bash source bytes,
the checked-in S-105 generator rebuilt its evaluation after the source change.
The deliberately rejected review remains rejected and was rebound without
promotion. Exact SHA-256 receipts are tuning corpus
`f2a905299eab6addce6d7112a2c6a90db1c509ffb37352c4a9c186f993e09bcf`,
held-out corpus
`cb35d6f11af8fb1c281b4d97fa7ce5be1344b1a37f414389bf43d884df8cfe32`,
evaluation
`ccdae0aa3e55e80db9a5f1097709e9b54226f43325e53ee7c361ca040afb5eb9`,
and rejected review
`30a2c1d106051afb6c94e6ad2cfc2debfac45cb602c09dee670cf84762fb348f`.

Artifact-bound alternate-model verification remains S-088. S-041 still owns
the full background-job service, S-042 owns profile-specific least privilege,
and S-096 owns frontend cancellation/shutdown propagation. None is claimed by
this slice.

# S-096: Make TUI cancellation and shutdown real

Status: Delivered; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-130
Workstreams: W10, W12
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-040](./040-supervised-foreground-process-io.md), [S-041](./041-owned-background-processes.md), [S-050](./050-provider-terminal-outcome-state.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure Escape, cancel, errors, terminal teardown, and shutdown stop and join the active run and descendants.

## Implementation boundary

- Give each TUI launch a fresh supervisor/cancellation generation and call-correlate model, tool, process, approval, question, render, and background work.
- Use RAII cleanup for raw mode, alternate screen, paste, reader/render tasks, channels, sessions, and child resources on return/error/panic.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Escape cannot merely hide a still-running request, and repeated in-process launches do not inherit sticky shutdown state.
- Cancellation and panic tests restore the terminal, join descendants, and publish one truthful terminal outcome.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered architecture — 2026-08-30

Every TUI launch now owns a fresh non-sticky supervisor and launch cancellation
generation. Model turns, plugin agents, hooks, MCP calls, provider/model
discovery, filesystem work, and direct processes are registered with exact run
and call identities. Replacement-style discovery cancels its superseded
generation, stale completion is rejected, and background call identities remain
valid until their queued terminal event is consumed.

Escape cancels the active turn and its supervised task rather than only hiding
the response. Shutdown cancels and joins supervised descendants before run
retirement. Per-turn runs preserve the parent cumulative budget, while the
launch run remains alive for the TUI itself. Terminal raw mode, alternate
screen, paste mode, reader ownership, and panic restoration are guarded by RAII
cleanup; repeated in-process launches do not inherit a previous shutdown flag.

Focused Rust 1.98 verification passed supervisor ownership, call-event
delivery, and superseded-discovery cancellation tests. The locked
all-feature/all-target check, strict Clippy gate, and complete serialized native
suite pass; the library harness reported 3,090 passed, zero failed, and one
ignored test before every binary, integration, and example target passed.

## Residual boundaries

- Issue #1160 remains open for complete isolated-workspace capability ownership
  transfer. This slice preserves and rebinds the existing workspace capability
  across cancellation without claiming that broader transfer is complete.
- S-088 still owns the independent artifact-bound VDD receipt.

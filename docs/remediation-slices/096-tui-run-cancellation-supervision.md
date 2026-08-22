# S-096: Make TUI cancellation and shutdown real

Status: Planned
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

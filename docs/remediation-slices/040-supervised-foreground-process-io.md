# S-040: Supervise foreground process I/O

Status: Planned
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

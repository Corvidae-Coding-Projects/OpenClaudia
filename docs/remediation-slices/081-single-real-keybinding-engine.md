# S-081: Use one real keybinding engine

Status: Planned
Effort: Medium
Primary findings: F-089, F-115
Workstreams: W12
Depends on: [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Connect configurable contextual keybindings to actual frontend input and remove the disconnected shadow Vim state machine.

## Implementation boundary

- Compile normalized chords into the typed command registry with exact/prefix precedence, context/modal conditions, collision checks, timeout, and input replay.
- Preserve Rustyline Vi behavior until a tested replacement exists; source displayed mode/status from real input state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Configured chords execute through the same command path in supported contexts and help is generated from the effective map.
- Prefix timeout, unreachable defaults, Unicode input, permission dialogs, streaming, submission, cancellation, and Vi mode tests pass.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

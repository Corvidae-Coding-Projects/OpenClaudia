# S-081: Use one real keybinding engine

Status: Implemented — awaiting independent VDD review
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

Implemented in the wave-three artifact. The shared resolver now parses and
normalizes bounded chords, rejects normalized collisions, applies contextual
availability, resolves exact-versus-prefix precedence with a bounded timeout,
and replays unmatched Unicode-safe input in order. The TUI feeds real terminal
events through that resolver before its ordinary editor/modal handlers and
generates help from the effective binding map.

The legacy REPL installs supported configured chords into its real Rustyline
editor. Native Rustyline Vi insert/command behavior remains authoritative; the
disconnected synthetic Vim state machine was removed. Explicit `none` bindings
are consuming no-ops, so disabling a key cannot fall through to a frontend
default. Streaming and confirmation contexts expose cancellation without
allowing ordinary command bindings to bypass those modes.

Verification used Rust 1.98.0 with `CARGO_BUILD_JOBS=4`:

- Canonical resolver coverage passed 32/32, including prefix timeout, ordered
  replay, collisions, context restrictions, and Unicode input.
- `tests/keybindings_e2e.rs` passed 16/16, including YAML `tab: none` disable
  semantics; focused TUI, help-overlay, permission-cancellation, and real
  Rustyline editor tests passed.
- `cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
  passed.
- `cargo +1.98.0 test --quiet --locked --all-targets --all-features --
  --test-threads=1` passed every non-ignored target.

No alternate-model VDD receipt is claimed for this bootstrap wave. Completion
of this slice does not imply completion of its parent workstream.

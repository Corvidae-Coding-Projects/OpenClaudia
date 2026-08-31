# S-083: Make terminal rendering bounded and inert

Status: Implemented and verified (2026-08-30)
Effort: Medium
Primary findings: F-106, F-133
Workstreams: W12
Depends on: [S-011](./011-canonical-typed-tool-results.md), [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent untrusted model/tool text from forging UI controls, crashing diff layout, emitting terminal control sequences, or exhausting rendering.

## Implementation boundary

- Render typed events only; sanitize ANSI/OSC/control characters and remove parsing of ordinary text for diff, approval, question, plan, or terminal markers.
- Apply byte/line/node/compute limits before Markdown/diff/layout work and use grapheme/terminal-cell-correct virtualization.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Hostile control strings and marker-shaped content display inertly and cannot create actions or raw terminal effects.
- Malformed diffs, huge lines, Unicode graphemes, long transcripts, and channel failure remain bounded and visible.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- A shared terminal-safety module admits untrusted text under explicit input,
  output, line, and per-line byte budgets before parsing or layout. C0/C1,
  ANSI/OSC introducers, bidirectional controls, and row-forming characters in
  labels are rendered as visible inert data with bounded UTF-8-safe
  truncation.
- CLI diff/tool-result/print projections and TUI messages, overlays, status
  labels, streamed assistant/reasoning text, welcome metadata, and Markdown
  rendering use the shared boundary. Errors propagate as typed I/O/results
  instead of being silently treated as successful rendering.
- TUI question handling now carries a typed question value rather than
  reconstructing authority from display text. Message/transcript retention,
  streaming accumulators, diff lines, terminal columns, Markdown scans, and
  syntax-highlighter source are bounded before allocation or repeated parse.
- Input editing and cursor/layout calculations operate on Unicode grapheme and
  terminal-cell boundaries, including multiline paste and narrow terminal
  widths, so display movement cannot split a user-visible character.

## Verification

- Dedicated hostile-text tests cover terminal/OSC/bidi controls, row-forging
  labels, pre-parse oversized lines, and UTF-8-safe raw accumulation. All 164
  TUI-focused tests pass, including the bounded contextual-syntax fallback,
  typed overlays, Unicode input, streaming, and review rendering.
- Rust 1.98 format, all-target/all-feature compilation, strict Clippy, the
  3,116-test library harness, and every integration harness pass at the
  integration gate.

## Residual boundary

The renderer deliberately truncates display projections while retaining typed
terminal state; it does not claim that a terminal can display an unbounded
provider payload. Raw protocol/file bytes remain owned by their transport or
artifact layer and are sanitized only when projected into a human terminal.

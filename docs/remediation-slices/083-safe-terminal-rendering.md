# S-083: Make terminal rendering bounded and inert

Status: Planned
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

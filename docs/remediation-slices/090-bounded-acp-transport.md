# S-090: Bound and validate ACP transport

Status: Delivered; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-124
Workstreams: W10, W12
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-040](./040-supervised-foreground-process-io.md), [S-050](./050-provider-terminal-outcome-state.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-089](./089-acp-session-isolation.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent unbounded or partial ACP protocol data from becoming normal committed agent output.

## Implementation boundary

- Validate JSON-RPC version, IDs, methods, schemas, framing, and ownership with pre-allocation caps on input, history, tool, error, update, and output bytes.
- Use bounded queues/backpressure and keep streamed output provisional until a provider-native terminal event and durable run commit.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Malformed, oversized, drip-fed, EOF-partial, duplicate-ID, slow-client, disconnect, and cancellation fixtures terminate predictably.
- Partial transport data cannot enter assistant history or produce successful ACP completion.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered architecture — 2026-08-30

ACP stdio now admits newline-delimited JSON through a pre-allocation frame
decoder with one assembly deadline, a bounded input queue, and duplicate active
request-ID rejection. JSON-RPC core fields and supported method schemas are
validated before dispatch while compatible extension members remain allowed.
The output path uses bounded serialization and queue backpressure, reports
writer failure to the owning transport, and bounds errors, updates, history,
assistant output, tool calls, tool arguments, tool results, IDE paths, and
diagnostics.

Provider streams now require a typed terminal outcome before the turn can
commit. Visible assistant chunks are labeled provisional on the ACP wire while
the transcript and provider continuation remain staged; malformed or partial
provider streams roll the provisional state back and cannot produce a
successful prompt result. Prompt failure, cancellation, EOF, stalled frame
assembly, client disconnect, and output backpressure terminate through explicit
bounded failure paths.

Focused Rust 1.98 verification passed the four bounded-transport framing,
deadline, JSON-RPC, and duplicate-ID tests; the provisional-output test; and the
31 related ACP configuration and IDE-state integration tests. The all-target,
all-feature check, strict Clippy gate, and complete serialized native suite also
pass with zero failures.

## Residual boundaries

- S-091 owns exact effective capability advertisement and execution parity; it
  is not claimed by this transport slice.
- S-088 still owns the independent artifact-bound VDD receipt; no unavailable
  verifier result is claimed here.

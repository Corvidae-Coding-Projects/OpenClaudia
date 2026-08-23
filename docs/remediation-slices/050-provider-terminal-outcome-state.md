# S-050: Make provider terminal outcomes truthful

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-096
Workstreams: W3, W12
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-044](./044-provider-native-state-contract.md), [S-048](./048-hardened-provider-http-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent partial streams, loop aborts, and provider failures from being recorded as successful assistant completion.

## Implementation boundary

- Define provider terminal events and map finish reason, refusal, length, tool continuation, transport error, cancellation, and protocol error to canonical run outcomes.
- Keep streamed deltas provisional until terminal validation and commit; preserve partial display separately from canonical assistant history.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Disconnect, malformed SSE, missing terminal event, tool-loop abort, timeout, and cancellation cannot yield `ResponseDone`, normal history, or zero-status success.
- Every frontend receives the same committed/partial/failed terminal classification.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record — 2026-08-23

Signed commit `684a812` delivers one typed provider terminal contract across
TUI, legacy REPL, print, ACP, child-agent, and VDD paths. Incomplete streams,
truncation, refusal, filtering, malformed or partial tool calls, cancellation,
and loop aborts cannot become committed assistant success. Rust 1.98 formatting,
native all-target/all-feature checks, strict Clippy, focused negative tests, and
the complete serialized all-feature test suite passed. Canonical artifact-bound
VDD promotion remains pending S-088.

# S-078: Move print mode onto the canonical runtime

Status: Implemented and deterministically verified; artifact-bound VDD receipt pending
Effort: Medium
Primary findings: F-109
Workstreams: W3, W10, W12
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-044](./044-provider-native-state-contract.md), [S-050](./050-provider-terminal-outcome-state.md), [S-051](./051-token-turn-and-cost-budgets.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make noninteractive print a bounded runtime profile rather than a direct fourth provider loop.

## Implementation boundary

- Define an explicit tool/persistence capability profile, input/output framing, provider continuation, budgets, cancellation, and stdout/stderr contract.
- Emit zero exit only after a committed provider-native terminal success; expose typed refused, partial, length, cancelled, protocol, and delivery failures.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Print mode shares provider/request/trace/finalization semantics with other frontends and cannot bypass policy hooks accidentally.
- Oversized output, broken pipe, partial stream, timeout, and missing terminal event produce bounded nonzero outcomes.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Print mode now constructs the canonical `RuntimeKernel` with a bounded inference profile instead of entering the interactive chat loop. The profile carries no tool grants, persistence authority, MCP/process/secrets access, or workspace roots.
- Provider requests reuse the established client configuration, request builders, stream decoders, native continuation state, terminal-state validation, hook execution, VDD finalization, cancellation, and token/turn/cost budget machinery.
- Output remains buffered until the run reaches a valid committed terminal success. Refusal, partial output, length limits, cancellation, timeouts, malformed or missing terminal events, provider errors, and stdout delivery failures are returned as typed nonzero outcomes.
- Missing provider usage remains unknown rather than being reconciled as fabricated zero-token usage. The bounded output and stream limits prevent unbounded buffering.
- Both direct API transports and the supported SDK-backed provider routes retain their existing authentication and model-selection behavior.

## Verification

- `cargo +1.98.0 fmt --check`
- `CARGO_BUILD_JOBS=2 cargo +1.98.0 check --locked --all-targets --all-features`
- `CARGO_BUILD_JOBS=2 cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
- All 18 focused print-mode tests pass, including bounded output, broken-pipe delivery, timeout/cancellation, partial or absent terminal events, provider-native terminal handling, hooks, VDD, and unknown-usage accounting.
- `CARGO_BUILD_JOBS=2 cargo +1.98.0 test --locked --all-targets --all-features -- --test-threads=1` passes.
- Because this slice changes `src/main.rs`, the technical-memory retrieval artifacts were regenerated and rebound to the new source digest. Their nine focused evidence tests pass; the review receipt remains deliberately rejected until an independent reviewer is assigned.

## Residual boundary

The implementation is locally verified, but the independent alternate-model, artifact-bound VDD receipt remains pending. Print mode deliberately retains small provider-specific transport adapters while sharing the canonical request, decoding, runtime, and finalization contracts; replacing those working adapters is outside this slice.

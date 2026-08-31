# S-069: Bound and validate LSP JSON-RPC

Status: Complete
Effort: Medium
Primary findings: F-054
Workstreams: W10, W18, W21
Depends on: [S-040](./040-supervised-foreground-process-io.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-068](./068-stateful-lsp-service.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace unbounded threaded LSP framing and empty-success error handling with typed bounded protocol execution.

## Implementation boundary

- Add header/frame/message/queue/result/stderr limits, aggregate deadlines, backpressure, cancellation, reverse-request handling, and status/process validation.
- Map server/protocol errors, partial results, restarts, and truncation to explicit outcomes while validating all returned URIs/resources.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Oversized, drip-fed, malformed, server-error, blocked-stdin, reverse-request, and cancellation fixtures terminate within limits.
- No JSON-RPC error can become a successful empty result.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Added one `LspProtocolLimits` contract across process startup, stdin writes,
  response framing, aggregate turns, diagnostics, reverse requests, semantic
  results, model-facing output, stderr capture, shutdown, and process reaping.
  Each request uses one absolute deadline; zero-capacity writer handoff prevents
  blocked pipes from accumulating serialized requests.
- LSP framing now rejects oversized headers and bodies before allocation,
  bounds queued and aggregate bytes, validates JSON-RPC version and envelope
  shape, requires the exact response ID, preserves typed server errors, and
  explicitly answers supported or unsupported reverse requests.
- Server publications are parsed as typed, versioned, bounded diagnostics and
  remain marked as untrusted language-server data. The legacy prompt-injection
  staging helper remains compatibility-only and is not used by production LSP
  dispatch.
- Tool projection now validates action-specific result shapes, collection size,
  tree depth, text size, and every returned resource. Only canonical files
  admitted by the active run and workspace become stable root-relative resource
  IDs. Invalid resources fail explicitly; bounded valid tails become typed
  partial outcomes with continuation and partial-reason metadata.
- Registry dispatch preserves complete, partial, and error outcomes instead of
  converting protocol failures or truncation into empty success. Existing S-068
  server reuse, document lifecycle, crash recovery, and call-hierarchy behavior
  remain covered and operational.

## Evidence

All Cargo commands used Rust/Cargo 1.98.0 with `CARGO_BUILD_JOBS=2`, one Cargo
process at a time, and serialized execution for the complete suite. The hostile
LSP server is a compiled local fixture and uses no network or external
credentials.

| Gate | Result |
|---|---|
| Compiled hostile LSP fixture | Passed 10/10: oversized headers/frames, drip deadline, malformed envelopes and IDs, typed server errors, reverse requests, typed diagnostics, message/result caps, blocked stdin with reaping, invalid resources, explicit partial results, and bounded stderr |
| Preserved S-068 stateful LSP fixture | Passed 9/9 |
| Focused LSP protocol, validation, and serialization tests | Passed 65/65 |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed across every native library, binary, example, and integration target; only explicitly ignored tests remained ignored |
| Focused sandbox escape and session-filesystem tests | Passed 13/13 |
| Fuzz-workspace check, Clippy, and library tests | Passed; 4/4 hermetic harness tests |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics |
| Repository-policy unit tests and hygiene checker | Passed; 27 policy tests and zero forbidden tracked artifacts |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |

Artifact generation `S069-G1` is based on
`3659d3d67108550a943f573d7679faf9ca67f956`. The SHA-256 digest of the sorted
per-file SHA-256 manifest for all changed source and test artifacts is
`b65bfe2b72e76452730cec0eec7c979eeb1abe7cc01ff19e8be77411f5531cbd`.

## VDD handoff

Queue artifact generation `S069-G1`, its base revision, manifest digest, and
the evidence above for S-088. The independent verifier must receive the same
harness, guardrails, run capabilities, resource budgets, reality grounding,
and supervised-process contract used by the implementation. S-088 is not yet
available, so this document records a verifier-ready handoff and does not claim
an independent approval or receipt.

## Residual boundaries

- Diagnostic notifications are surfaced during bounded protocol turns; this
  slice does not add an independent unsolicited push stream.
- Production projection accepts canonical workspace file resources. Virtual
  documents and non-file URI schemes fail explicitly rather than acquiring
  ambient authority.
- No new remediation slice was required by the verified implementation.
- Completion applies only to S-069. Parent issue #1071 remains open.

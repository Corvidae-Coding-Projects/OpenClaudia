# S-049: Separate reasoning continuation from display

Status: Implemented and deterministically verified; artifact-bound VDD receipt pending
Effort: Medium
Primary findings: F-118
Workstreams: W3, W12
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-044](./044-provider-native-state-contract.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve reasoning needed for provider correctness without flattening or exposing raw chain-of-thought as ordinary transcript text.

## Implementation boundary

- Model opaque provider continuation, provider-sanctioned user summaries, and protected monitoring as distinct typed channels.
- Define consent, access, encryption, persistence, retention/deletion, export, redaction, and frontend rendering for each channel.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Raw seeded reasoning cannot appear in normal history, logs, exports, ACP/TUI events, or provider switches.
- Provider continuation still round-trips correctly after resume and compaction.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Reasoning is represented by distinct typed channels: opaque provider
  continuation, provider-sanctioned user-visible summaries, and protected
  monitoring observations. Raw continuation is not represented as ordinary
  assistant transcript text.
- OpenAI Responses summary events are rendered through the summary channel;
  private reasoning deltas are ignored. Generic OpenAI-compatible raw
  continuation is held in zeroizing memory only for the immediate tool
  follow-up request and is never inserted into portable history.
- Provider-native state structurally removes plaintext `thinking`,
  `reasoning`, and `reasoning_content` from continuation and evidence items
  while preserving encrypted/signature continuations, visible output, and
  tool arguments that merely use those words as domain keys.
- Persisted legacy native state is validated against its original digest and
  causal envelope before privacy sanitization produces the replacement
  generation. Provider switches and portable exports cannot inherit raw
  reasoning bytes.

## Verification

- Rust 1.98 format and strict all-target/all-feature Clippy gates pass.
- All 10 provider-state unit tests pass, including evidence-item redaction,
  opaque continuation round trips, tamper rejection, and preservation of tool
  argument objects.
- The complete locked all-target/all-feature suite passes with 3,126 library
  tests passed and one intentional ignore, 208 binary tests passed, and every
  integration target green under one test thread.

## Residual boundary

Provider APIs may require opaque continuation tokens for correct immediate
follow-up behavior; those tokens remain provider-bound and are not presented
as user-visible reasoning. An artifact-bound alternate-model VDD receipt is
still required for final `Verified` status.

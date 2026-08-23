# S-048: Centralize hardened provider HTTP transport

Status: Implemented and verified on Rust 1.98.0
Effort: Medium
Primary findings: F-021
Workstreams: W3
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-044](./044-provider-native-state-contract.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give every provider request one bounded, cancellable, redacting HTTP policy.

## Implementation boundary

- Centralize TLS, proxy provenance, redirect policy, DNS/connect/read/write/total deadlines, retries/backoff/idempotency, body/stream limits, and status validation.
- Normalize typed provider errors and usage while stripping credentials on redirects and preventing raw body/header logging.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Every provider and auth path uses the shared transport or documents a tested reason it cannot.
- Slow, oversized, retryable, partial, redirect, proxy, cancellation, and secret-echo fixtures terminate within budgets with redacted errors.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

- Added `src/provider_transport.rs` as the canonical provider/auth transport
  policy and migrated the pipeline, proxy, provider discovery, OAuth and Claude
  credential refresh, ACP, CLI, TUI, subagents, provider-backed web
  distillation, and VDD production paths.
- The shared policy uses Rustls with TLS 1.2+, disables credential-bearing
  redirects, preserves explicit system-proxy provenance, reuses one connection
  pool, validates resolved endpoints, bounds header/read/total time, caps JSON
  and raw stream bytes, and returns sanitized typed failures.
- Model POST retries retain the established ten-retry compatibility ceiling but
  share a 60-second monotonic window, cap retry delays at 15 seconds, and only
  replay explicit pre-admission statuses or connection-stage failures. Raw SSE
  bytes are charged before framing, so an upstream that never emits a newline
  cannot grow a parser buffer without bound.
- Verification passed with `cargo +1.98.0 fmt --all -- --check`,
  `CARGO_BUILD_JOBS=4 cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`,
  focused redirect/deadline/oversize/retry/redaction/provider/VDD/auth tests,
  and `CARGO_BUILD_JOBS=4 cargo +1.98.0 test --locked --all-features -- --test-threads=1`
  with zero failures.
- Updated the checked-in technical-memory retrieval corpus citations and
  regenerated evaluation evidence required by the changed `src/main.rs` and
  `src/oauth.rs` artifact digests. S-088 is still planned, so no artifact-bound
  VDD receipt is yet available.
- Residual provider terminal-state semantics remain owned by S-050; aggregate
  VDD lifecycle budgets, identity receipts, and cancellation remain owned by
  S-101. Completion of this slice does not imply completion of its parent
  workstream.

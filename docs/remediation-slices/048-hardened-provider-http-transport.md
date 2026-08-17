# S-048: Centralize hardened provider HTTP transport

Status: Planned
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

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

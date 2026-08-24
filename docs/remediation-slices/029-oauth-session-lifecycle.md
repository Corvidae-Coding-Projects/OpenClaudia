# S-029: Implement a complete OAuth session lifecycle

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-095
Workstreams: W3, W15
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md), [S-048](./048-hardened-provider-http-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give OAuth sessions protected storage, expiry, refresh, rotation, revocation, and client binding from authorization through use.

## Implementation boundary

- Model pending grants and active sessions with owner, client/browser binding, scopes, issued/expiry times, single-use state, generation, and revocation.
- Store secrets through the capability-safe secret store and serialize refresh so stale results cannot overwrite newer credentials.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Expired, revoked, replayed, cross-client, and concurrently refreshed sessions fail deterministically.
- Logout/revocation prevents further use and persisted secrets have restrictive modes, atomic writes, and redacted errors.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record (2026-08-24)

The native OAuth store is now a versioned, descriptor-safe credential document
backed by the S-031 persistence boundary. Legacy unversioned session maps remain
readable and migrate on the next successful commit. Active records carry a
monotonic generation and optional client-binding digest; revocation removes
their access token, refresh token, API key, and bearer identifier from the
document and leaves only a one-way tombstone so a stale writer cannot restore
the revoked credential. Persistent files remain private (`0600` on Unix),
atomic, symlink resistant, and durability checked.

Every production use now performs a durable reread and validates browser
binding, the `user:inference` scope, revocation, and expiry. Tokens within the
60-second refresh window are refreshed under a bounded cross-process file lock,
then committed with compare-and-swap generation checks; independently running
frontends cannot allow an older refresh result to overwrite a newer one.
Refresh rotation persists the returned access token, refresh token, expiry,
and API key together. Explicit ephemeral stores isolate deterministic tests
from the user's real credential files.

The browser device flow now issues a bounded, expiring, single-use PKCE grant
bound to an `HttpOnly`, `SameSite=Strict` loopback client cookie. Submission
requires the matching state and binding, and neither HTML nor JSON exposes the
created bearer session identifier. Status returns only validity, and logout
persists revocation before clearing cookies. The proxy resolves OAuth at use
time and cannot silently fall back to a configured API key when the caller
supplies an invalid OAuth cookie. API-key and bearer sessions retain their
correct provider authentication modes.

CLI logout uses the same revocation path for valid native sessions while
preserving the established recovery behavior for malformed native state.
Existing Claude Code and Codex credential files remain compatible and are not
rewritten by ordinary agent use. A related live-test defect in the Codex
ChatGPT Responses adapter was also repaired: account-auth requests omit the
unsupported public output-limit field, and streamed completed responses now
accept the provider's current authoritative output-item sequence without
requiring a second byte-identical terminal copy.

Verification used Rust/Cargo 1.98.0, `CARGO_BUILD_JOBS=4`, one Cargo process at
a time, and serialized test execution:

- focused OAuth, proxy, CLI status/logout, Codex request projection, Responses
  decoding, child-run, pipeline, and persistence suites passed;
- the locked workspace/all-target/all-feature native suite passed, including
  2,911 library tests with one existing ignored test, 228 binary tests, and all
  integration and example targets;
- strict all-target/all-feature Clippy, formatting, diff checks, and locked
  Windows GNU all-target/all-feature compilation passed; existing
  target-conditional test warnings remain tracked by Crosslink #1099;
- a built OpenClaudia binary completed real conversations through the existing
  Claude Code and Codex ChatGPT logins and returned the requested exact markers;
  all three credential stores remained byte-identical and private afterward;
- a launched loopback proxy passed health, device-start, cookie/state, status,
  and logout route probes without modifying those credential stores.

Changing the S-105-cited `src/oauth.rs` correctly invalidated its retrieval
corpus. The held-out citation was rebound to the current source digest, the
checked-in generator rebuilt the evaluation, and the independent-review
artifact remains explicitly rejected pending a new independent reviewer.

## Residual boundaries

- Logout revokes the local OpenClaudia session and prevents resurrection by a
  stale local writer. Upstream-provider token revocation is not claimed where
  the provider exposes no supported revocation operation to this client.
- The loopback proxy is currently plain HTTP, so its cookies are intentionally
  not marked `Secure`; S-092 owns authenticated/TLS proxy deployment. S-093
  owns broader proxy tenant isolation.
- The manual proxy probe exercised the launched authorization routes but did
  not approve a new external provider grant. Grant exchange, binding, refresh,
  rotation, replay, concurrent writers, and revocation are covered by the
  deterministic suites, while the compatibility conversations used the user's
  already-authorized Claude Code and Codex stores.
- Read-only ownership of the foreign Claude credential store and provider
  compliance metadata remain in S-026 through S-028. MCP OAuth elicitation
  remains in S-067. Completion applies only to S-029 and the related Codex
  compatibility defect; parent workstream #1071 remains open.

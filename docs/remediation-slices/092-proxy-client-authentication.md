# S-092: Authenticate proxy callers before credential spend

Status: Delivered; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-126
Workstreams: W2, W3, W27
Depends on: [S-018](./018-non-bypassable-host-safety-policy.md), [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-048](./048-hardened-provider-http-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent unauthenticated local or network clients from spending configured provider credentials or accessing agent state.

## Implementation boundary

- Define secure default bind, client identity/authentication, TLS/origin policy, rate/cost limits, scopes, and explicit external-bind acknowledgement.
- Authenticate and authorize before body buffering, provider selection, credential access, session creation, hooks, MCP, or VDD work.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Unauthenticated, wrong-scope, cross-origin, replayed, and rate-exceeded requests consume no provider/tool budget or secret.
- Loopback and external deployment conformance tests report honest ready/degraded states.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered architecture — 2026-08-30

Protected proxy routes now require a configured caller identity and an
HMAC-SHA-256 request signature before request-body admission or any provider,
credential, session, hook, MCP, or VDD path can run. The canonical signature
binds identity, timestamp, nonce, method, path/query, required scope, and body
digest. Verification uses constant-time comparison, bounded replay state,
per-caller request and cost limits, explicit scopes, and a maximum request
body. Unsupported routes are classified and rejected before body or credential
inspection.

Loopback remains the secure default. External plaintext binding requires an
exact operator acknowledgement and is reported as degraded rather than secure;
invalid security configuration is not ready and prevents startup. Device-flow
browser requests use the same caller contract through WebCrypto, configuration
and init templates expose deliberate caller provisioning, and README examples
document the signing and deployment boundary.

Focused Rust 1.98 verification passed proxy authentication, startup-security,
signed device-flow, 22 proxy-configuration tests, the 64-test CLI lifecycle
target with real signed proxy traffic, and the 5-test typed-environment target.
The locked all-feature/all-target check, strict Clippy gate, and complete
serialized native suite pass; the library harness reported 3,090 passed, zero
failed, and one ignored test before every binary, integration, and example
target passed.

## Residual boundaries

- TLS termination for an external deployment remains an operator-owned ingress
  concern; OpenClaudia reports acknowledged plaintext external binding as
  degraded and never calls it secure.
- Standard API clients require a local signing adapter or equivalent header
  support; unauthenticated compatibility is deliberately not retained.
- S-088 still owns the independent artifact-bound VDD receipt.

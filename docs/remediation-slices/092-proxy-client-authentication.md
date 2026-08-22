# S-092: Authenticate proxy callers before credential spend

Status: Planned
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

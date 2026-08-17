# S-067: Complete MCP OAuth, elicitation, and in-process semantics

Status: Planned
Effort: Medium
Primary findings: F-093
Workstreams: W3, W6, W15
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-029](./029-oauth-session-lifecycle.md), [S-031](./031-descriptor-safe-persistence.md), [S-065](./065-mcp-current-protocol-adapter.md), [S-066](./066-mcp-owned-bounded-transports.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace schema-only secret-unsafe MCP extensions with current authorized, correlated, lifecycle-owned implementations.

## Implementation boundary

- Implement current authorization discovery/PKCE/state/scope/refresh/revocation through protected secret storage and bound pending sessions.
- Implement correlated multi-round elicitation and make in-process servers obey the same identity, capability, budget, cancellation, and shutdown contract as external servers.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Replay, redirect, state, scope escalation, expiry, revocation, secret-log, and concurrent-flow tests pass.
- Elicitation cannot overwrite another request, and in-process code receives no implicit host authority.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

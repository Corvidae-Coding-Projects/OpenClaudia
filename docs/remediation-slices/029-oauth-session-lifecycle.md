# S-029: Implement a complete OAuth session lifecycle

Status: Planned
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

# S-071: Enforce web policy at the connection boundary

Status: Planned
Effort: Medium
Primary findings: F-102
Workstreams: W23
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-048](./048-hardened-provider-http-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Apply DNS, address, redirect, proxy, and origin policy to the actual connection used by fetch, search, browser, and distillation.

## Implementation boundary

- Resolve/classify/pin allowed addresses while preserving TLS host verification; recheck redirects and proxies and deny private/metadata/local schemes without exact grants.
- Broker browser navigation, subresources, frames, fetch/XHR, WebSockets, workers, and downloads through the same policy.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- DNS rebinding, alternate IP, redirect, proxy, userinfo, IPv6, and browser private-network fixtures cannot escape the granted origin/address set.
- Every network receipt records redacted origin, redirect chain, final peer, policy generation, byte/time limits, and backend.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

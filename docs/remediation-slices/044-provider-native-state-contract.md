# S-044: Define the provider-native state contract

Status: Planned
Effort: Medium
Primary findings: F-019
Workstreams: W3, W12
Depends on: [S-010](./010-canonical-run-context-and-events.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve provider-native messages, tool state, reasoning continuation, caching, usage, and terminal semantics behind lossless adapters.

## Implementation boundary

- Define a neutral event envelope plus provider-owned opaque continuation items and capability negotiation; prohibit flattening when round-trip data would be lost.
- Build conformance fixtures for every provider covering multi-turn tools, parallel calls, reasoning blocks/signatures, refusals, usage, cache, and resume.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Every supported adapter round-trips its required native state or explicitly declares the unsupported capability.
- Generic chat-message conversion is never used as silent fallback when it loses protocol state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

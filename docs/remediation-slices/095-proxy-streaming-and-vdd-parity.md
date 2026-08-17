# S-095: Fix proxy streaming and VDD delivery parity

Status: Planned
Effort: Medium
Primary findings: F-129
Workstreams: W3, W12, W27, W28
Depends on: [S-088](./088-canonical-vdd-verifier-role.md), [S-094](./094-proxy-canonical-lifecycle-routing.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stream protocol-correct responses while applying VDD and terminal delivery semantics consistently.

## Implementation boundary

- Translate each provider's events to the declared client protocol incrementally with bounded backpressure, usage, finish reasons, errors, and disconnect cancellation.
- Run configured VDD against the exact candidate response before blocking success and expose advisory/blocking/degraded outcomes without buffering a fake stream.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- OpenAI/Anthropic/Google fixtures cover successful, tool, refusal, length, usage, midstream error, slow/disconnected client, and VDD paths.
- No raw foreign-provider SSE or unreviewed response is labeled as the advertised protocol success.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

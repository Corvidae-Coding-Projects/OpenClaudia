# S-066: Own and bound MCP transports

Status: Planned
Effort: Medium
Primary findings: F-092
Workstreams: W6, W10, W18
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-040](./040-supervised-foreground-process-io.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-065](./065-mcp-current-protocol-adapter.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give each MCP connection request correlation, framing limits, deadlines, cancellation, backpressure, and supervised process/network ownership.

## Implementation boundary

- Implement bounded stdio/HTTP transport actors with connection generations, request IDs, frame/body/queue limits, status validation, and one terminal response.
- Serialize or multiplex safely per transport; cancellation and shutdown stop/reap only the owned request/server and reconcile pending calls.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A stalled, oversized, malformed, reordered, disconnected, or cancelled server cannot block the subsystem or satisfy another request.
- Session/plugin shutdown joins MCP processes/connections without orphans or cross-server state confusion.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

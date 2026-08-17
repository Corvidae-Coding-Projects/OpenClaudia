# S-069: Bound and validate LSP JSON-RPC

Status: Planned
Effort: Medium
Primary findings: F-054
Workstreams: W10, W18, W21
Depends on: [S-040](./040-supervised-foreground-process-io.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-068](./068-stateful-lsp-service.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace unbounded threaded LSP framing and empty-success error handling with typed bounded protocol execution.

## Implementation boundary

- Add header/frame/message/queue/result/stderr limits, aggregate deadlines, backpressure, cancellation, reverse-request handling, and status/process validation.
- Map server/protocol errors, partial results, restarts, and truncation to explicit outcomes while validating all returned URIs/resources.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Oversized, drip-fed, malformed, server-error, blocked-stdin, reverse-request, and cancellation fixtures terminate within limits.
- No JSON-RPC error can become a successful empty result.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

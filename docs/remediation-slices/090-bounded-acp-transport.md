# S-090: Bound and validate ACP transport

Status: Planned
Effort: Medium
Primary findings: F-124
Workstreams: W10, W12
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-040](./040-supervised-foreground-process-io.md), [S-050](./050-provider-terminal-outcome-state.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-089](./089-acp-session-isolation.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent unbounded or partial ACP protocol data from becoming normal committed agent output.

## Implementation boundary

- Validate JSON-RPC version, IDs, methods, schemas, framing, and ownership with pre-allocation caps on input, history, tool, error, update, and output bytes.
- Use bounded queues/backpressure and keep streamed output provisional until a provider-native terminal event and durable run commit.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Malformed, oversized, drip-fed, EOF-partial, duplicate-ID, slow-client, disconnect, and cancellation fixtures terminate predictably.
- Partial transport data cannot enter assistant history or produce successful ACP completion.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

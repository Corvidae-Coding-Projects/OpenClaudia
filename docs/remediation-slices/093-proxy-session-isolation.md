# S-093: Isolate proxy tenant and session state

Status: Planned
Effort: Medium
Primary findings: F-127
Workstreams: W3, W12, W27
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-019](./019-explicit-session-capabilities.md), [S-029](./029-oauth-session-lifecycle.md), [S-089](./089-acp-session-isolation.md), [S-092](./092-proxy-client-authentication.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace process-global proxy transcript, model, auth, accounting, VDD, hook, MCP, and plugin state with authenticated canonical sessions.

## Implementation boundary

- Resolve every route to tenant/client/session/call IDs and exact provider/workspace/capability/budget generations.
- Own per-session continuation, compaction, memory, approvals, hooks, tools, OAuth, usage, cancellation, and lifecycle resources.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Concurrent adversarial tenants cannot mix credentials, prompts, tool results, budgets, VDD evidence, cancellation, or provider state.
- Session expiry/logout/shutdown revokes and joins only the owned resources.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

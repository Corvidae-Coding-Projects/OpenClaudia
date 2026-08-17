# S-094: Route every proxy API through the canonical lifecycle

Status: Planned
Effort: Medium
Primary findings: F-128
Workstreams: W3, W12, W27
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-050](./050-provider-terminal-outcome-state.md), [S-093](./093-proxy-session-isolation.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Eliminate route-dependent policy where only one proxy handler receives the advertised agent lifecycle.

## Implementation boundary

- Normalize supported chat, legacy completion, Anthropic-compatible, and passthrough routes into canonical requests with explicit capability profiles.
- Apply context, provider state, tools, policy, hooks, budgets, compaction, evidence, finalization, and delivery semantics uniformly.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Equivalent requests across supported routes produce equivalent lifecycle traces and effect decisions.
- Catch-all/body/query forwarding is exact and bounded or the route is rejected as unsupported before credential use.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

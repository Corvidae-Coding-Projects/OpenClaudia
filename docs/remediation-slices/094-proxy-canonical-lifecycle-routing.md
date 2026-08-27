# S-094: Route every proxy API through the canonical lifecycle

Status: Complete
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

## Completed implementation — 2026-08-27

The proxy now admits exactly four route families—OpenAI chat completions,
legacy completions, Anthropic messages, and OpenAI responses—and rejects unknown
paths or methods before reading request bodies or resolving credentials. Every
supported route passes through shared normalization, provider selection,
session ownership, context, compaction, hooks, token/provider budgets, evidence,
and finalization.

Anthropic and Responses requests retain provider-native opaque fields, including
thinking, reasoning, tool, and continuation state. Canonical reference context
is projected back into those native wire shapes rather than being lost after
normalization. Route and finalization failures remain typed, query strings are
preserved, and budget reservations are released by lifecycle ownership.

Rust 1.98 formatting, locked all-target/all-feature checking, strict Clippy, and
the serialized all-target/all-feature suite passed with only the unrelated
#1055 local fixture exclusions. Focused tests cover all supported-route
admission, rejection before credentials/body access, opaque native-field
preservation, reference projection, and canonical finalization. Streaming and
VDD delivery parity remain explicitly assigned to S-095, with alternate-model
verification owned by S-088.

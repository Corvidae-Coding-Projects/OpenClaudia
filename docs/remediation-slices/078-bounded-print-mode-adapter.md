# S-078: Move print mode onto the canonical runtime

Status: Planned
Effort: Medium
Primary findings: F-109
Workstreams: W3, W10, W12
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-044](./044-provider-native-state-contract.md), [S-050](./050-provider-terminal-outcome-state.md), [S-051](./051-token-turn-and-cost-budgets.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make noninteractive print a bounded runtime profile rather than a direct fourth provider loop.

## Implementation boundary

- Define an explicit tool/persistence capability profile, input/output framing, provider continuation, budgets, cancellation, and stdout/stderr contract.
- Emit zero exit only after a committed provider-native terminal success; expose typed refused, partial, length, cancelled, protocol, and delivery failures.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Print mode shares provider/request/trace/finalization semantics with other frontends and cannot bypass policy hooks accidentally.
- Oversized output, broken pipe, partial stream, timeout, and missing terminal event produce bounded nonzero outcomes.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

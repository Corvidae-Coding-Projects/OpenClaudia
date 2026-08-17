# S-100: Enforce VDD blocking at canonical finalization

Status: Planned
Effort: Medium
Primary findings: F-135
Workstreams: W4, W12, W28
Depends on: [S-024](./024-artifact-verification-invalidation.md), [S-050](./050-provider-terminal-outcome-state.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-099](./099-vdd-strict-verdict-schema.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make required VDD review a non-bypassable finalization gate across every frontend.

## Implementation boundary

- Attach review policy to the candidate response/artifact generation and withhold committed success until deterministic and VDD criteria pass.
- Represent pass, fail, inconclusive, verifier error, unavailable, stale, unconverged, cancelled, and explicit host-selected fail-open distinctly.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- TUI, ACP, proxy, print, legacy, worker, and integration paths cannot emit normal success when blocking review is absent or failed.
- The planner/worker cannot waive, self-author, reuse stale, or race a VDD receipt.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

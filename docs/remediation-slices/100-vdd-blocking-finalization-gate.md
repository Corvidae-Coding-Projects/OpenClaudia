# S-100: Enforce VDD blocking at canonical finalization

Status: Implemented and deterministically verified; receipt publication follow-up tracked by #1201
Effort: Medium
Primary findings: F-135
Workstreams: W4, W12, W28
Depends on: [S-024](./024-artifact-verification-invalidation.md), [S-050](./050-provider-terminal-outcome-state.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-099](./099-vdd-strict-verdict-schema.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Delivered — 2026-08-28

Commit `b5630331` installed a host-owned blocking finalization gate across text,
proxy, TUI, ACP, print, and worker publication. Required review binds the exact
candidate generation and digest before promotion and withholds normal success
for failed, stale, unavailable, cancelled, inconclusive, or unconverged review.
Planner and worker paths cannot self-author or waive the canonical receipt.

## Verification evidence

Crosslink issue #1197 records Rust 1.98 formatting, checking, strict Clippy,
focused VDD tests, the complete locked all-target/all-feature suite (3,051
library tests plus integration and example targets), repository policy, and
dependency policy as passing. Parent review corrected dirty statistical
convergence, live TUI leakage, missing prior-candidate context during revision,
and background proposal promotion before closure.

## Residual boundary

The blocking gate is implemented. Publishing the post-finalization receipt as a
durable user-visible artifact is a distinct follow-up tracked by Crosslink issue
#1201; that follow-up does not reopen the finalization-gate implementation.

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

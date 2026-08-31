# S-101: Bound and validate VDD provider work

Status: Implemented and deterministically verified; artifact-bound VDD receipt not recorded
Effort: Medium
Primary findings: F-136
Workstreams: W3, W10, W28
Depends on: [S-048](./048-hardened-provider-http-transport.md), [S-050](./050-provider-terminal-outcome-state.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-099](./099-vdd-strict-verdict-schema.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Delivered — 2026-08-28

Commit `b5630331` gave VDD one aggregate review budget across provider calls,
processes, bytes, tokens, cost, time, concurrency, and storage. Codex and Claude
SDK subprocesses are supervised under deterministic cancellation and reap;
terminal state, model identity, usage, and strict one-verdict-per-finding JSON
are validated before a typed provider receipt is accepted.

## Verification evidence

Crosslink issue #1198 records Rust 1.98 formatting, checking, strict Clippy,
focused transport and real mid-process cancellation tests, the complete locked
all-target/all-feature suite, fuzz targets, and dependency-policy gates as
passing. Parent review corrected an impossible per-call reservation,
prose-wrapped JSON acceptance, placeholder model routing, and cancellation tests
that did not spawn real children.

## Residual boundary

The bounded provider transport is implemented. An independent artifact-bound
VDD receipt was not separately recorded for this slice.

## Outcome

Give adversary, verifier, revision, and analyzer calls status-validating transport, aggregate budgets, and one cancellation tree.

## Implementation boundary

- Reserve total model/process/token/cost/time/retry/concurrency/input/output/storage budgets before review and use canonical provider/process transports.
- Require valid provider terminal state, bounded structured output, model identity receipt, and joined cancellation for every stage.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Oversize, slow, rate-limited, partial, malformed, missing-usage, unavailable-model, cancellation, and analyzer-failure tests terminate truthfully.
- One review cannot exceed aggregate limits by spawning multiple verifier/revision/static calls.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

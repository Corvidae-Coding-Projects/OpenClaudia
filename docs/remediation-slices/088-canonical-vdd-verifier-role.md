# S-088: Run VDD as the canonical alternate-model verifier

Status: Planned
Effort: Medium
Primary findings: Design requirement (no primary audit finding)
Workstreams: W2, W3, W4, W10, W12, W28
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-023](./023-reality-evidence-boundary.md), [S-024](./024-artifact-verification-invalidation.md), [S-044](./044-provider-native-state-contract.md), [S-050](./050-provider-terminal-outcome-state.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-087](./087-fresh-worker-slice-lifecycle.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make VDD a normal canonical agent run with the same harness and guardrails but separate context, enforced alternate-model identity, and stricter authority.

## Implementation boundary

- Create a verifier capability profile over canonical typed tools, grounding/evidence, provider adapters, filesystem/process/network policy, budgets, cancellation, traces, and terminal states.
- Provide exact task criteria, artifact/diff digest, source snapshot, deterministic receipts, and worker uncertainties; enforce resolved endpoint/model-family separation with no silent fallback.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- VDD can inspect and run bounded tests in disposable scratch but cannot modify the reviewed artifact, approve itself, publish, commit, or close the task.
- Model collision/unavailability, parse/transport error, timeout, truncation, and later artifact mutation yield fail/inconclusive/error, never pass.
- Relevant deterministic tests and trace assertions pass; bootstrap this slice with an independent external/manual review because VDD cannot establish its own initial trust.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

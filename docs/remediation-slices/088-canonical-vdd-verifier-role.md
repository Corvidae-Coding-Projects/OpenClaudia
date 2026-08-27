# S-088: Run VDD as the canonical alternate-model verifier

Status: Implemented — bootstrap independent review pending
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

Implemented in the wave-three artifact. `CanonicalVddRequest` binds the exact
worker assignment and result, objective and acceptance digests, artifact
generation, source receipts, deterministic check receipts, worker model
identity, and disclosed uncertainty. Preflight rejects partial or stale
handoffs, missing evidence, ambiguous models, and provider/endpoint/model-family
collisions before dispatch.

`VddEngine::verify_worker_artifact` runs a host-only verifier role through the
canonical child-agent harness. It receives the same provider adapters, hook and
guardrail machinery, Reality grounding, typed tool path, budgets,
cancellation, trace, and terminal-state handling as other agents. The reviewed
artifact is read-only and separate scratch is private and bounded. The role has
no model-facing spawn path and cannot publish, commit, close, approve, mutate
the artifact, use secret/network/MCP tools, or delegate.

Verifier output uses a strict bounded JSON schema. A pass requires exact
acceptance-criterion coverage and current Reality evidence; mutation during the
run, timeout, truncation, parse/transport failure, budget exhaustion,
unavailability, unresolved uncertainty, or incomplete deterministic evidence
maps to a typed non-pass receipt. Receipts are permanently `ProposedOnly`;
later S-100/S-102 work retains finalization and transactional persistence
authority.

Verification used Rust 1.98.0 with `CARGO_BUILD_JOBS=4`:

- Canonical VDD acceptance coverage passed 7/7, including exact handoff,
  partial/stale rejection, alternate-model collision, strict JSON, exact
  criterion coverage, current Reality citations, and terminal failure mapping.
- Host-only/read-only verifier-role tests passed.
- `cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
  passed.
- `cargo +1.98.0 test --quiet --locked --all-targets --all-features --
  --test-threads=1` passed every non-ignored target.

This slice cannot honestly bootstrap its own trust. No external alternate-model
verifier was run during the parent integration pass, so independent manual or
external review remains required and no VDD pass receipt is claimed.
Completion of this slice does not imply completion of its parent workstream.

# S-088: Run VDD as the canonical alternate-model verifier

Status: Implemented — bootstrap manual review and repair complete
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

## Bootstrap manual review and repair — 2026-08-27

The independent manual bootstrap review at Crosslink #1182 returned
`CHANGES REQUIRED`. It found that production tool observations were split
across ledger keys (#1183), receipt identity described the requested rather
than resolved verifier route (#1184), successful verifier completion could
leave detached process work live (#1185), selected source bytes were absent
from the verifier contract (#1187), and the tests did not exercise the real
child/tool harness (#1186).

Those findings are repaired. The verifier now has one immutable
capability-bound evidence key; artifact citations must bind to the review root;
the transport records and pins the resolved route/model used by receipts;
detached verifier bash is forbidden and owned processes are reaped before
publication; exact bounded source snapshots are digest-checked and delivered;
and a two-turn provider fixture drives the real child harness, `read_file`,
Reality grounding, strict report parsing, and the unchanged-artifact fence in
a linked Git worktree. The integration test also keeps verifier ledger state in
private scratch and covers OpenAI-compatible null assistant content between
tool turns.

Rust 1.98.0 formatting and strict all-target/all-feature Clippy pass. The full
all-feature suite passes across 2,991 library tests, every integration/example
target, and doc tests. Regenerating the technical-memory evaluation after the
`src/tools/bash/mod.rs` evidence-key correction preserves its deliberately
rejected independent-review verdict.

This manual review satisfies the bootstrap review requirement; it is not
represented as an alternate-model VDD pass receipt. Completion of this slice
does not imply completion of its parent workstream.

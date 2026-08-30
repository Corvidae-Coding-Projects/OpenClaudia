# S-080: Make plan approval an atomic capability transition

Status: Implemented and deterministically verified; artifact-bound VDD receipt pending
Effort: Medium
Primary findings: F-114
Workstreams: W2, W12, W17
Depends on: [S-017](./017-deny-precedence-and-approval-receipts.md), [S-024](./024-artifact-verification-invalidation.md), [S-052](./052-canonical-task-graph.md), [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Bind the reviewed plan bytes, task state, artifact generation, and granted execution authority in one transaction.

## Implementation boundary

- Represent a plan as an immutable versioned artifact with task graph, proposed effects, budgets, expiry, actor, and evidence.
- Approve exact plan digest and atomically activate its capability generation; amendments, artifact changes, or mode changes invalidate the grant.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- The agent cannot execute different plan bytes or broader effects than the user approved.
- Concurrent edits, stale approvals, partial persistence, cancellation, and resume cannot split plan state from authority.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Plan approval now prepares exact bounded plan bytes and their digest before the
user decision. Approval publishes an immutable, versioned
`ApprovedPlanArtifact` containing the canonical task identity and graph
generation, proposed typed effects and prompt digests, budget snapshot, expiry,
actor, interactive evidence, run identity, capability generation and manifest
digest, and the prepared and activated runtime-mode generations.

The transition holds the background-lifecycle and runtime-mode write guards
while one session transaction revalidates the plan, persists the canonical
task, constructs the artifact and approval receipt, and changes session state.
Only after that transaction succeeds is the already-constructed capability
binding published. Plan edits, capability or budget drift, mode-generation
changes, expiry, and run cancellation fail closed. Generic mode changes clear
the binding, and successor/resumed runs do not reconstruct live authority from
persisted plan prose.

Tool admission enforces the live binding for both model-dispatched and direct
operations. Provider-visible tool definitions also omit effects denied by the
approved plan. The CLI and TUI display the exact plan and allowed operations;
an empty effect list is explicitly presented as the current run's existing
capabilities rather than as an accidental deny-all or escalation.

Verification used Rust 1.98.0 with `CARGO_BUILD_JOBS=2` and serialized tests:

- `cargo +1.98.0 fmt --check` passed.
- `cargo +1.98.0 check --locked --all-targets --all-features` passed.
- `cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
  passed.
- Focused approval, rejection, cancellation, successor-run, stale-artifact,
  effect-ceiling, and provider-catalog tests passed.
- `cargo +1.98.0 test --locked --all-targets --all-features --
  --test-threads=1` passed every non-ignored target.

An independent alternate-model, artifact-bound VDD receipt was not recorded for
this implementation pass. That missing evidence is not represented as a VDD
pass. Post-finalization receipt publication remains tracked by Crosslink #1201.
Completion of this slice does not imply completion of its parent workstream.

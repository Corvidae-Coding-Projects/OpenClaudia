# S-082: Give private notes and side questions correct semantics

Status: Implemented and deterministically verified; artifact-bound VDD receipt pending
Effort: Medium
Primary findings: F-116
Workstreams: W8, W12
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-010](./010-canonical-run-context-and-events.md), [S-052](./052-canonical-task-graph.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Keep private notes out of provider-visible system history and execute side questions without reordering or corrupting the parent conversation.

## Implementation boundary

- Store notes as private typed events with explicit projection/consent, sensitivity, retention, and deletion policy.
- Run side questions as bounded child attempts over an immutable parent snapshot and attach results through causal event IDs.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Private seeded text never reaches provider requests, ordinary exports, memory, or system context without explicit user action.
- Side-question success/failure/cancellation cannot reorder parent messages or steal provider/tool continuation state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Private notes are typed local events stored outside the provider conversation, ordinary transcript export, prompt assembly, and memory systems. Projection into provider-visible context requires an explicit consent transition, and deletion records a tombstone while removing retained note bytes.
- Legacy private-note state migrates transactionally: every note is validated before the replacement state is published, so an invalid or oversized entry cannot leave a partial migration behind.
- Per-note, count, and aggregate byte limits bound local retention. Causal references are validated before notes or side-question results are accepted.
- `/btw` runs a side question as a detached child attempt over an immutable parent snapshot. The child inherits the parent's cancellation tree and a bounded inference budget, but receives no tools, roots, persistence, memory, MCP, process, or secret authority.
- Child events are drained independently, terminal output is sanitized, and the typed result remains local and causally attached. Success, failure, or cancellation does not mutate or reorder parent messages, native continuation state, or tool state.
- A failed durable note write removes the corresponding retained bytes in memory rather than reporting a note that was not persisted.

## Verification

- `cargo +1.98.0 fmt --check`
- `CARGO_BUILD_JOBS=2 cargo +1.98.0 check --locked --all-targets --all-features`
- `CARGO_BUILD_JOBS=2 cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
- Focused verification passes for both side-question paths, all three private-note semantics tests, transactional migration rollback, hierarchical cancellation propagation, and unknown-usage accounting.
- `CARGO_BUILD_JOBS=2 cargo +1.98.0 test --locked --all-targets --all-features -- --test-threads=1` passes.
- The technical-memory retrieval artifacts affected by the shared `src/main.rs` change were regenerated and their nine evidence tests pass. The review receipt remains deliberately rejected until an independent reviewer is assigned.

## Residual boundary

The implementation is locally verified, but the independent alternate-model, artifact-bound VDD receipt remains pending. Private-note projection is intentionally explicit and local-first; broader user-interface management beyond the `/btw` entry point and existing session persistence is outside this slice.

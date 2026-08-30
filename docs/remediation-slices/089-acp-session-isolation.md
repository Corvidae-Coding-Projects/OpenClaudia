# S-089: Isolate ACP sessions and calls

Status: Delivered; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-123
Workstreams: W12
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-019](./019-explicit-session-capabilities.md), [S-038](./038-session-schema-migration-and-ownership.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give every ACP session independent transcript, provider continuation, model, mode, IDE state, configuration, budget, workspace, and cancellation.

## Implementation boundary

- Map known wire session IDs to canonical run/session handles with owner and exact generation; reject unknown IDs and create truly independent state on new.
- Correlate updates, questions, approvals, configuration, tool results, and cancellation to session plus call ID.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Adversarially interleaved clients cannot read, mutate, cancel, reconfigure, or receive events from another session.
- Load restores the exact persisted generation rather than manufacturing a blank/shared child.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered architecture — 2026-08-30

ACP now admits each wire session ID into an independently owned canonical run
and legacy-session generation. A durable envelope under the descriptor-safe
application data store binds the canonical session, legacy lifecycle state,
model, mode, configuration, IDE state, transcript, native continuation, and
generation. Unknown IDs fail closed, loading validates the exact stored
generation, and same-generation persistence is idempotent only for identical
bytes.

Each prompt receives a session-scoped call identity and child cancellation
handle while sharing the session's cumulative parent budget. The bounded call
registry correlates updates, configuration, approvals, questions, tool results,
completion, and cancellation to the exact session and call. Interleaved
sessions cannot cancel or reconfigure one another, and a denied session-start
hook cannot replace the active session.

Focused Rust 1.98 verification passed the 46-test ACP session/mode module, the
16-test ACP IDE-state integration target, and the 15-test ACP configuration
default target. The 64-test CLI lifecycle target also proves ACP can create its
private application-data persistence hierarchy from a clean account. The
locked all-feature/all-target check, strict Clippy gate, and complete serialized
native suite pass; the library harness reported 3,090 passed, zero failed, and
one ignored test before every binary, integration, and example target passed.

## Residual boundaries

- S-088 still owns the independent artifact-bound VDD receipt; no unavailable
  verifier result is claimed here.
- ACP state intentionally shares the existing canonical workspace capability
  model. S-1160 remains responsible for transferring complete isolated
  workspace ownership across every frontend lifecycle.

# S-039: Bind resume and branches to causal state

Status: Implemented and deterministically verified; artifact-bound VDD receipt pending
Effort: Medium
Primary findings: F-072, F-117
Workstreams: W12, W15
Depends on: [S-031](./031-descriptor-safe-persistence.md), [S-038](./038-session-schema-migration-and-ownership.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent project-controlled snapshots or ambiguous transcript IDs from replacing canonical session state.

## Implementation boundary

- Give sessions/branches immutable logical IDs, parent event/generation, provider/workspace/capability generations, digest, provenance, and schema.
- Treat imported branch files as untrusted proposals requiring bounded validation and explicit atomic selection.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Forged, stale, cross-workspace, cross-provider, or cyclic branch/resume data cannot become the active transcript.
- Resume restores one causally closed tool/provider state or returns a typed conflict/unavailable result.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Sessions now carry a versioned causal envelope with an immutable logical
  identity, ordered event digests, parent generations, provider/model binding,
  workspace and capability generations, provenance, branch anchors, and
  selected-branch receipts.
- Session schema version 2 migrates version 0/1 state without silently
  inventing repeatable authority. A legacy session receives one explicit
  resume binding; subsequent resumes must match its established causal run.
- TUI, legacy REPL, ACP, session loading, fresh-session transitions, and
  subagent restoration prepare and validate resume state before activating the
  loaded transcript. Provider, project, workspace, or run-generation drift is
  returned as a typed refusal.
- `/branch` writes a bounded untrusted proposal bound to the source event and
  `/teleport` validates and atomically selects that proposal. Cycles, stale
  sources, forged messages, cross-session identities, and mismatched run
  bindings cannot replace the active conversation.

## Verification

- Rust 1.98 format and strict all-target/all-feature Clippy gates pass.
- The complete locked all-target/all-feature suite passes with 3,126 library
  tests passed and one intentional ignore, 208 binary tests passed, and every
  integration target green under one test thread.
- Focused migration, startup resume, provider-history, branch validation, and
  session serialization tests pass. Test fixtures that need a chosen ID now
  use the causal `Session::set_id` transition instead of manufacturing
  internally inconsistent state.

## Residual boundary

The implementation and deterministic integration evidence are complete. An
artifact-bound alternate-model VDD receipt is still required before this slice
can claim the repository's final `Verified` status; no receipt is fabricated
here.

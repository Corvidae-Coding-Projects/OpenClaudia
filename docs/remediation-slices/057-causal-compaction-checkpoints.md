# S-057: Replace lossy compaction with causal checkpoints

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-077, F-078
Workstreams: W5, W10, W12
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-010](./010-canonical-run-context-and-events.md), [S-031](./031-descriptor-safe-persistence.md), [S-044](./044-provider-native-state-contract.md), [S-051](./051-token-turn-and-cost-budgets.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give every frontend one typed, provider-valid, artifact-cited checkpoint operation instead of truncating transcripts into system prose.

## Implementation boundary

- Compact a causally closed event generation preserving user intent, tool pairs, unresolved tasks, decisions, provider-native continuation, evidence, budgets, and citations.
- Validate fit and required-state retention before atomically publishing checkpoint/archive/memory watermark under an idempotency ID.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Repeated compaction retains required facts and protocol chains and never promotes the summary to instruction authority.
- TUI, ACP, proxy, legacy REPL, workers, and rotating planners consume the same success/partial/cannot-fit/error semantics.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record — 2026-08-23

Signed commit `135d425` delivers one canonical causal checkpoint projection
across proxy, legacy REPL, TUI, ACP, and subagents. Exact transcripts remain the
canonical archive; only causally closed groups compact; cited summaries remain
non-authoritative historical evidence; stale measurements fail; and typed
committed, partial, and cannot-fit outcomes publish atomically. OpenAI Responses
uses provider-managed compaction with monotonic continuation state, while
incompatible ordinal-bound protocols fail explicitly. Rust 1.98 formatting,
strict all-target/all-feature Clippy, and the complete serialized workspace test
suite passed. Canonical artifact-bound VDD promotion remains pending S-088.

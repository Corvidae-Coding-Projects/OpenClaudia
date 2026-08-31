# S-102: Persist VDD evidence and issues transactionally

Status: Complete
Effort: Medium
Primary findings: F-137
Workstreams: W15, W20, W28
Depends on: [S-024](./024-artifact-verification-invalidation.md), [S-031](./031-descriptor-safe-persistence.md), [S-052](./052-canonical-task-graph.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-099](./099-vdd-strict-verdict-schema.md), [S-100](./100-vdd-blocking-finalization-gate.md), [S-101](./101-vdd-bounded-provider-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Store resumable redacted review evidence and promote only checked unresolved findings to task state.

## Implementation boundary

- Persist artifact/model/prompt/policy generations, verdicts, citations, sensitivity, revisions, disagreement, retention, and history through capability-safe atomic storage.
- Create/update/resolve W20 issues under explicit policy with idempotent transactional reconciliation; never trust model-supplied paths or prose as authority.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Crash/retry/concurrent review cannot duplicate issues, lose evidence, overwrite newer status, or publish a finding for the wrong artifact.
- Export/delete/redaction and fix-verification flows preserve history while marking exact findings resolved.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Implemented

- Replaced raw VDD session dumps with a versioned, bounded, redacted evidence ledger. Each attempt is bound to the exact artifact generation, task scope, policy and prompt digests, canonical finalization receipt, provider/model accounting, deterministic checks, host-derived finding identities, citations, observations, sensitivity, retention, and lifecycle history.
- Routed ledger access through descriptor-safe persistent storage. The default `.openclaudia/vdd` root is resolved through host-control capabilities, rejects traversal and symlink substitution, and is created or tightened to owner-only access.
- Moved evidence persistence and finding promotion behind the host's terminal decision. Required reviews fail closed on a persistence error unless the existing explicit host fail-open policy applies; stale, cancelled, inconclusive, and unavailable outcomes cannot create task state.
- Added explicit `vdd.tracking.promote_verified_findings` and `vdd.tracking.retention_days` policy, with environment overrides. Finding promotion is opt-in by review mode, requires persistence, and defaults to redacted evidence rather than raw provider-response logging.
- Added idempotent Crosslink reconciliation: persist intent first, transact the issue mutation, then persist the receipt. Stable scope-bound markers, monotonic revisions, generation compare-and-swap, and recovery markers make retries and crash recovery converge without duplicate issues or stale reopenings.
- Added evidence export and deletion. Retention expiry and explicit deletion redact bounded prose to a tombstone while preserving artifact binding and lifecycle history.

## Verification

Verified with Rust 1.98.0 and `CARGO_BUILD_JOBS=4`:

- `cargo +1.98.0 fmt --all -- --check`
- `cargo +1.98.0 check --locked --all-targets`
- `cargo +1.98.0 check --locked --all-features --all-targets`
- `cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
- `cargo +1.98.0 test --locked --all-targets --all-features --quiet -- --test-threads=1` (all test binaries passed; the library result was 3,063 passed and one ignored)
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v` (27 passed)
- `python3 scripts/check_repository_hygiene.py --repo-root .`
- both locked root/fuzz `cargo metadata` checks
- both root/fuzz `cargo deny --locked ... check advisories licenses sources bans` checks
- locked fuzz `check`, strict `clippy`, and library tests (four passed)

Focused evidence-ledger coverage exercises crash-window recovery, ordinary and concurrent retries, scope isolation, stale-outcome suppression, monotonic resolution, unsafe citation normalization, exact-generation compare-and-swap, owner-only storage, retention export, and deletion redaction without retaining raw provider bodies or credentials.

## Handoff

The canonical VDD finalization receipt is now part of the attempt identity and durable ledger. Pre-existing legacy raw `vdd-session-*.json` artifacts are deliberately not deleted or silently migrated by this slice, and hook publication of the post-finalization receipt remains separate follow-up work. Completion of this slice does not imply completion of its parent workstream.

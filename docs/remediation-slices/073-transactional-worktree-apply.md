# S-073: Make worktree apply and cleanup transactional

Status: Implemented and adversarially reviewed; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-060
Workstreams: W15, W18, W24
Depends on: [S-024](./024-artifact-verification-invalidation.md), [S-031](./031-descriptor-safe-persistence.md), [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Never destroy worktree changes after failed or ambiguous preservation, commit, or apply operations.

## Implementation boundary

- Separate preview, stage, commit, merge, discard, and remove effects and bind each approval to exact diff/base/target/worktree generations.
- Retain recoverable refs/snapshots and reconcile every commit/sign/filter/merge failure before any cleanup; make retries idempotent.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- No failure path force-removes untracked, unstaged, staged, committed, conflicted, or inspection-failed work.
- Crash/failure tests at every transition preserve recoverable state and report exact next actions.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

`exit_worktree` now exposes one explicit operation per call: `preview`,
`stage`, `commit`, `merge`, `discard`, or `remove`. The former composite
`apply_changes` and `discard_changes` booleans remain schema-visible only so
old callers receive a typed migration error; they cannot trigger a composite
mutation.

`preview` returns a versioned transaction snapshot containing canonical
repository and worktree identities and paths, source and target branches and
heads, staged/unstaged/untracked/ignored/conflicted path sets, whole-worktree
content and index fingerprints, target-change state, and an exact generation.
Every mutating operation must repeat that generation and the canonical target
it reviewed. Stage also requires the complete reviewed non-ignored path set;
commit requires a bounded message and a fully staged snapshot; discard and
remove require the exact canonical cleanup target. A stale or incomplete
approval fails before mutation.

Stage, commit, and merge verify their postconditions against a fresh
inspection. Commit and merge create immutable generation-addressed recovery
refs without overwriting an existing mismatched ref. Merge success proves the
approved commit is an ancestor of the target; a conflict is aborted and the
source worktree and recovery ref are retained. Discard and remove create a
repository-and-path-bound durable cleanup receipt before deletion and claim
success only when both the path and Git worktree registration are absent.
Retries use those receipts and refs to recognize only the exact completed
transaction.

All production Git commands retain the existing shared sandboxed process
boundary, immutable executable resolution, disabled prompts/hooks/credential
helpers, bounded output, a 30-second timeout, cancellation, and child reaping.
Failed, timed-out, cancelled, ambiguous, partially successful, conflicted, or
inspection-failed operations return typed error/partial outcomes with the
retained state and exact recovery action. No such path force-removes the
worktree.

The tool registry now classifies `preview` as read/process and every mutation
as read/write/process before dispatch. The quality gate recognizes the
explicit `commit` operation. README and dispatch/effect/blast-radius contracts
describe and enforce the same public protocol.

## Skeptical evidence

The tests use real repositories and linked worktrees, and changed tests were
reviewed as potentially wrong rather than accepted merely because they passed.
They prove:

- preview to stage to commit to merge to removal survives fresh run-context
  boundaries, and exact merge/removal retries are idempotent;
- a missing commit identity retains the staged work and worktree;
- a required clean-filter/quality-gate failure never reaches cleanup;
- a real merge conflict is aborted in the target while the source commit,
  worktree, and recovery ref remain available;
- a same-path edit changes the generation, so stale discard approval cannot
  destroy newer bytes;
- porcelain-v2 parsing distinguishes ordinary, rename, untracked, ignored,
  and conflicted entries without treating partial inspection as clean;
- all six explicit operations have their declared authorization effect and
  the deprecated composite modes remain destructive fail-safe classifications.

## Artifact generation and VDD handoff

`S073-G1` is the exact seven-file implementation/test artifact set below. The
SHA-256 digest of its sorted `sha256sum` manifest is
`4857652caf8a1c802977be00cee7f5a8c12b022d030db2c4a3c7c72ec646380c`.

| Artifact | SHA-256 |
| --- | --- |
| `README.md` | `8b8f89d6292d4610fa19289603df6c1027445a41868b2ee86e029d4cabcdbaf4` |
| `src/services/tool_executor.rs` | `0f96ed5e0ddf50b3e580d721c008244b67bab2716ff463e4a1d44c4cd4e1e650` |
| `src/tools/registry.rs` | `4e8e9d08f3d1b606695eafe03a714797e34c437ae594e8d53702ee1262c5047d` |
| `src/tools/worktree.rs` | `c4a959beb24f941c768a5588165853660f7a3974f23ae63a1fa2b06f1971b282` |
| `tests/mandatory_tool_effect_classification_e2e.rs` | `16f1ada4675704ed06f703fda135fa78a12c1075fcbab48c5a625083023baefb` |
| `tests/run_scoped_blast_radius_guardrails_e2e.rs` | `29232eb9847193ed1dbb1855055b97df7f3ba56b51c3e3cd0f050efdb69c4be3` |
| `tests/worktree_dispatch_validation_e2e.rs` | `2bc208ac11645e1d61bac39c1675d140547971e3f6efd516b01bd0565d37e1ca` |

Queue `S073-G1` for S-088's genuinely independent alternate-model review.
That verifier must receive the exact criteria, manifest, source snapshot, and
deterministic receipts through the same canonical harness, guardrails,
reality-grounding boundary, provider adapters, budgets, cancellation, and
traces as other agents, but with separate context and stricter read-only
authority. Model-family collision, stale artifact bytes, unavailable verifier,
or inconclusive/error outcomes must never become approval. This slice does not
fabricate a VDD receipt before S-088 exists.

## Verification record

All Rust commands used exactly Rust 1.98.0 with `CARGO_BUILD_JOBS=2`; test
commands were serialized with `--test-threads=1` where applicable.

- Focused transaction tests passed, including the fresh-run happy path and
  commit-identity, clean-filter, merge-conflict, and stale-discard failures.
  The complete worktree module passed 33/33 tests.
- Updated integration contracts passed: worktree dispatch 36/36, mandatory
  effect classification 52/52, tool schema 29/29, blast-radius guardrails
  14/14, and worktree/LSP 9/9.
- `cargo fmt --all -- --check`, locked all-target checking, and locked strict
  all-target/all-feature Clippy with `-D warnings` passed.
- The complete locked all-target/all-feature native test matrix exited zero.
  The library ran 2,933 tests: 2,932 passed and one intentional test was
  ignored; all main, integration, and example targets also passed.
- The fuzz workspace passed locked check, strict Clippy, and all four library
  tests. Root and fuzz locked metadata and cargo-deny 0.20.2 advisory, license,
  source, and duplicate policies passed.
- Repository-policy tests passed 27/27 and repository hygiene returned
  `status: verified`. `git diff --check` and the changed-code debug/stub scan
  were clean.

## Residual boundaries

- The canonical artifact-bound VDD receipt remains owned by S-088. Any change
  to an `S073-G1` artifact invalidates this queued generation.
- The exact snapshot intentionally refuses transactions above its path,
  aggregate path-byte, entry, or logical-byte bounds. Refusal preserves the
  worktree for narrower or manual recovery rather than silently weakening the
  reviewed generation.
- macOS and Windows fail-closed contracts cannot execute on this Linux host;
  the exact-head PR runners remain the evidence source after publication.
- S-074 workspace-capability binding, S-075 typed command registry, and S-077
  general Git review/commit remain separate slices. Parent issue #1071 remains
  open.

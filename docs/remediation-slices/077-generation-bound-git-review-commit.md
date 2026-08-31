# S-077: Bind Git review and commit to exact generations

Status: Implemented and verified (2026-08-30)
Effort: Medium
Primary findings: F-110
Workstreams: W2, W15, W18, W24
Depends on: [S-024](./024-artifact-verification-invalidation.md), [S-031](./031-descriptor-safe-persistence.md), [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md), [S-074](./074-workspace-capability-binding.md), [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure CLI review/commit stages and publishes exactly the bytes approved under canonical workspace capabilities.

## Implementation boundary

- Review a bounded diff tied to HEAD, index, worktree, path set, filters/config, and workspace generations; approve explicit paths and destination.
- Use a run-owned index and least-privilege Git profile, return/verify commit identity, and separate local commit from push/PR publication receipts.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Concurrent file/index/HEAD changes invalidate approval and cannot stage an unreviewed generation.
- Hook/filter/signing/staging/commit/push failures leave visible recoverable state and never report clean success.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- `/review`, `/commit`, and the local stage of `/commit-push-pr` now share one
  generation-bound Git transaction. Review binds the run and workspace
  generations, canonical repository root, HEAD/destination ref, user index,
  NUL-safe path set, repository config/attributes, candidate index/tree, and
  exact bounded binary diff.
- Candidate staging uses a run-owned index and object quarantine. Approval is
  an opaque one-shot value binding the displayed path set, destination,
  message, and complete review generation; every mutable input is recomputed
  before commit-object creation and again before ref publication.
- Git runs from a pinned executable with an empty explicit environment,
  bounded output/deadline, cancellation, disabled hooks/credentials/external
  diff/textconv/signing and protocol/file transports, and no child or network
  authority. Repository-selected clean filters are rejected rather than run.
  Repository-local identity is read from a bounded snapshot as data.
- Normal and linked worktrees have separate least-privilege commit mounts.
  Commit publication advances only the approved ref from its reviewed parent,
  reconciles and verifies the exact user index, and returns typed recovery
  state if an irreversible local boundary cannot be proven complete.
- Push and pull-request creation remain distinct follow-on effects and cannot
  start without the verified local-commit receipt. The former ambient
  `git add -A`/bare-process pipeline was removed after every live frontend was
  routed through the replacement transaction.

## Verification

- Five real-repository transaction tests pass for exact tracked/untracked
  commits, post-approval mutation invalidation without ref/index mutation,
  hostile control-shaped byte paths, active clean-filter refusal, and
  linked-worktree ref/common-object-store publication.
- Existing TUI review and sandbox-policy suites pass, as do Rust 1.98 format,
  all-target/all-feature compilation, strict Clippy, the 3,116-test library
  harness, and every integration harness at the integration gate.

## Residual boundary

Application-created commits intentionally do not inherit ambient signing
agents or user/global Git configuration; the transaction produces a verified
local commit rather than claiming a configured external signature. Push and
forge behavior still rely on their separate receipt-bearing frontends and are
not authority granted by a local commit receipt.

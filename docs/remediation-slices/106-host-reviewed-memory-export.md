# S-106: Bind technical-memory review to host approval

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: Design requirement from W5
Workstreams: W2, W5, W15
Depends on: [S-017](./017-deny-precedence-and-approval-receipts.md), [S-054](./054-memory-authority-and-schema.md), [S-056](./056-operational-memdir-lifecycle.md)
Crosslink: #1078

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give users a real authority-bearing review and revocation transition for exact
codebase technical-lesson revisions. A model, policy default, reusable approval,
or coordinator cannot self-assert `HostReviewed`.

The originally combined portable-export boundary is preserved as
[S-107](./107-portable-technical-memory-export.md). Splitting the permission/
causal-state transition from the multi-artifact filesystem protocol keeps both
units medium-sized without reducing the requested end state.

## Implementation boundary

- Carry the exact consumed permission capability from authorization through
  canonical registry dispatch without a global lookup or serializable bypass.
- Admit review or revocation only from a fresh one-use `InteractiveUser`
  decision or a trusted composition root that vouches for an authenticated
  `AcpClient` or `HostAdministrator` decision. Reject policy defaults, reusable
  grants, coordinator decisions, missing evidence, stale/replayed permits, and
  mismatched calls before memory mutation.
- Bind the immutable review audit to receipt ID and kind, permission scope,
  logical ID, expected revision digest, workspace, run, actor, workspace and
  capability generations, host-safety generation, operation, and timestamp.
- Publish the review/revocation successor and its unique audit record inside
  one immediate SQLite transaction. Exact authorized retries are idempotent;
  receipt reuse for another transition is a typed conflict.
- Preserve candidate evidence and causal history. Correction, repository-source
  refresh, restoration, expiry, revocation, conflict, and deletion must never
  inherit stale reviewed authority or increase evidence confidence.
- Wire interactive chat and TUI through the canonical
  tool/effect/resource/runtime path and a fresh interactive decision. Print
  mode remains read-only and advertises no tools. Route ACP through the same
  executor but fail closed until S-090/S-091 supply an authenticated
  permission-response channel. No current subagent role may review because none
  receives a direct host decision; a worker must ask its parent/main agent to
  perform the review. Read-only/plan roles may inspect review state but may not
  mutate it. Never put lesson prose into ambient prompts.

## Explicit exclusions

- Complete portable export/import is S-107.
- Automatic causal learning is S-055; retrieval evaluation is S-105.
- Team authentication and replication are S-103/S-104.
- Host review marks an exact evidence revision as reviewed; it does not turn a
  lesson into a system/developer instruction or raise its evidence confidence.

## Acceptance

- Unauthorized, forged, policy-default, reusable, coordinator, replayed,
  cross-call, cross-run, cross-workspace, generation-stale, and revision-stale
  review attempts fail before mutation.
- Exact authorized replay is idempotent; one receipt cannot review or revoke a
  second lesson or revision.
- Revocation creates a candidate successor, later correction/source refresh
  remains candidate, and expired/deleted/conflicted lessons expose no effective
  reviewed state.
- Store reopening verifies every reviewed head against its immutable audit
  record; missing/tampered/mismatched audit data fails closed.
- Deterministic executor/frontend tests and an independent artifact-bound VDD
  receipt prove the user—not the model—controls review authority.

## Implemented contract

- `ExecutionPermit::consume_for` now produces an opaque, one-call dispatch
  capability. Its `HostApprovalEvidence` binds the receipt and grant kind,
  provenance, actor, workspace and generation, capability generation, run and
  session, tool, effect, operation, target, arguments, call, policy, scope, and
  a digest over the complete evidence record.
- Reusable approval scopes remain run-neutral so persisted approvals retain
  their prior semantics. The ephemeral execution permit alone acquires the run
  binding at mint time. `memory_review` nevertheless requires a fresh one-use
  grant with host provenance, so a policy, session grant, persisted grant,
  coordinator, or model cannot confer review authority.
- `MemoryDb::transition_technical_lesson_review` uses an immediate SQLite
  transaction, exact-head compare-and-swap, a unique immutable review-audit
  record, and one atomic publication of the causal successor and audit. An
  exact authorized retry is idempotent; receipt reuse for any other transition
  is rejected.
- A reviewed head is effective only while its retention state remains valid and
  its immutable audit still verifies. Correction, repository refresh,
  revocation, conflict, tombstone, expiry, or retention review resets or hides
  reviewed authority without raising evidence confidence.
- General revision APIs reject review successors and review-audit tags. Future
  import/replication work must use a dedicated validated atomic path rather
  than bypassing the authenticated review transaction.
- Tool results, observations, permission diagnostics, and audit receipts expose
  identities, states, and digests only. Technical-lesson prose remains confined
  to explicit memory retrieval tool calls and is never injected ambiently.

## Adversarial review corrections

- Removed run identity from reusable approval scopes after tracing persisted
  receipt behavior; run binding now exists only on the consumed permit.
- Added a self-binding evidence digest after finding that a structurally valid
  receipt did not itself authenticate every run/policy field used by review.
- Bound the opened memory database to the same canonical workspace digest as
  the approval after finding that a permit for workspace A could otherwise be
  presented to a database opened for workspace B.
- Closed the raw revision-publication bypass for authority-looking review
  records and added negative tests for forged successors and audit roots.
- Kept ACP and subagent paths fail-closed instead of fabricating host authority:
  current ACP has no authenticated permission response, and current subagents
  have no direct host prompt.

## Verification evidence

- `cargo +1.98.0 fmt --all -- --check`: pass.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 check --locked --all-features --all-targets`:
  pass.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 clippy --locked --all-features --all-targets -- -D warnings`:
  pass after resolving all slice-caused diagnostics without suppression.
- Focused permission, review, frontend, registry, technical-memory, and source
  suites: 104/104, 9/9, 7/7, 23/23, 16/16, 22/22, 20/20, 11/11, 15/15,
  18/18, and 12/12 pass respectively. ACP and TUI route tests pass 1/1 each;
  the combined integration harness passes 131 with two network tests ignored.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 test --locked --all-features --all-targets -- --test-threads=1`:
  pass. This includes the real linked-worktree tests and every S-106 negative
  path; browser-dependent tests remain explicitly ignored by their harness.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 check --locked --all-features --all-targets --target x86_64-pc-windows-gnu`:
  pass; the final cached rerun completed in 9.79 seconds. Emitted warnings are
  pre-existing target-conditional unused test/helper code outside S-106; no
  S-106 path warned.
- The SHA-256 of the sorted `sha256sum` manifest for all 18 changed Rust source
  and test artifacts is
  `5ce5c478429a0ce5f7078fd6f22af107b9f0013a847dca1840c2577ff1084ccc`.

## Residual boundaries

- S-088 owns the independent alternate-model VDD receipt; this slice does not
  claim that pending evidence.
- S-090/S-091 own authenticated ACP permission responses and effective ACP
  capability advertisement. ACP currently reaches the canonical executor and
  refuses review before mutation.
- S-103/S-104 own authenticated team authority and replication, S-105 owns
  retrieval evaluation, S-107 owns complete portable export/import, and S-055
  owns evidence-bound automatic learning.

## Handoff

Record the exact consumed-capability and audit schemas, artifact generations,
commands/tests, frontend evidence, residual permission risks, and the S-107,
S-103, S-104, and S-105 boundaries.

## Corrective follow-up: source lifecycle coherence (#1080)

Host review and revocation now also advance an exact source-owned member digest
when the reviewed lesson belongs to the active technical-memory source. The
source membership is prepared before mutation and the lesson successor, review
audit, and source-state successor commit atomically. The resulting source state
keeps its repository generation and source digest while naming the new reviewed
head; unchanged source refresh remains idempotent.

Acceptance is deliberately narrower than accepting any descendant head. A
member is source-owned only when its current revision is an exact import or a
bounded chain of immutable, audit-validated host-review transitions ending at
an exact import. Agent corrections and deletions do not acquire source
authority and continue to surface a source conflict. An injected failure on the
source-state insert proves that the preceding lesson and audit writes roll back.

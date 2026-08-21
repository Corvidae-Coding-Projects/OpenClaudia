# S-053: Give memory stable identity and merge semantics

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-063, F-075
Workstreams: W5
Depends on: [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent consolidation and team synchronization from deleting distinct records or confusing local row IDs with logical identity.

S-053 now makes a physical SQLite row ID a compatibility locator only. Every
archival memory has a global UUID identity and an immutable causal revision
graph. Equal prose is never an identity or merge rule. Cross-store retries use
the exact same revision, offline team-shared branches are exchanged into both
stores, and concurrent heads remain visible. The later typed resolution action
belongs to S-054 and cannot be simulated by last-writer-wins here.

This is the identity layer for the intended memory product: structured,
repository-specific technical lessons retrieved through a tool. It does not
legitimize free-form transcript/prose capture. S-054 owns the typed lesson
schema, evidence-only authority, host-owned storage, bounded retrieval tool,
and production activation.

## Implementation boundary

- Introduce global logical IDs, versions, content/source digests, provenance, authorship, conflict/tombstone state, and deterministic merge rules.
- Make consolidation preserve distinct metadata and perform conflict-aware idempotent transactions across local/team stores.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

### Delivered contract

- `LogicalMemoryId` is store-independent; v5 migration deterministically maps
  each complete legacy row (row ID, content, tags, and timestamps), so records
  that merely share prose retain distinct identity.
- Every physical database receives a persistent `MemoryStoreId`. New revisions
  bind their known origin store, the user/team sync sidecar binds the exact
  store pair, and a replacement database at the same path fails closed before
  tombstone filtering or replay. User and team roles cannot alias the same
  physical store, including through path aliases or copied store identities.
- `MemoryRevision` binds logical ID, non-zero monotonic version, exact parent,
  content/source/record digests, canonical tags, provenance, author, workspace,
  sharing scope, and active/tombstone state. Deserialized/tampered or
  non-canonical revisions fail validation before writes, and a logical ID can
  never acquire a second root or change replication scope mid-lineage.
- `memory_revisions` is immutable history and `memory_heads` is the causal head
  set. Descendants supersede ancestors; equal digests are idempotent; concurrent
  branches remain multiple heads with a deterministic visible projection and
  typed conflict metadata. Version-bound deletes retain tombstone revisions.
- `TeamMemoryStore` records a `Both` operation durably before applying the same
  revision to user and team stores. Startup replays incomplete operations.
  Completed operation rows are retired while a separate bounded logical-ID
  enrollment survives for later offline reconciliation, so successful writes
  do not consume a lifetime operation-log cap.
  Replica-history reconciliation exchanges parent-before-child team-shared
  revisions into both stores; partial exchange is retryable and private
  revisions are never copied to the team store. Conflict heads, per-logical-ID
  histories, enrollment, pending operations, and overlay tombstones all use
  sentinel-row bounds; a cap breach rolls back before publishing excess state.
- Merged reads collapse only identical logical revisions, recognize causal
  descendants, expose divergent heads, globally order once, and apply the limit
  once. User overlay tombstones bind logical ID, exact version, and digest, so a
  stale tombstone cannot hide a later team revision.
- Background consolidation is bounded and non-destructive. It traces
  equal-content/different-ID candidates but deletes nothing without an explicit
  equivalence proof. This removes the former timestamp-based data-loss test.

### Compatibility and failure semantics

- Existing `memory_save/get/update/delete/list` callers retain local numeric IDs.
  Updates and deletes now create causal revisions behind that API; list/search/
  stats exclude sole tombstone heads and surface conflicts.
- Existing v1-v4 rows migrate through schema v5 without content/tag loss. The
  legacy row stays in place and gains a logical projection plus immutable root.
- Missing/mismatched parents, invalid versions/digests/provenance, oversized
  reconciliation sets, physical-store replacement, poisoned mutexes, SQLite
  failures, and partial team writes return visible errors. A `Both` deletion
  refuses private memory and reconciles an enrolled offline parent before
  publishing its tombstone. There is no last-write-wins or failure-as-empty
  path in revision/replica merge.
- Production `team_memory_path` remains fail-closed. S-053 removes identity and
  replay as blockers; S-054 provides capability-safe host storage, strict
  migration/recovery, and evidence-only local retrieval. S-103/S-104 must add
  authenticated membership and bounded replication before team activation.

## Acceptance

- Records with shared text but different source/scope/metadata remain distinct unless an explicit merge rule proves equivalence.
- Concurrent/offline replicas converge without row-ID collisions, silent deletion, or last-writer data loss.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

Acceptance is covered by `memory::record` and `memory` unit tests,
`team_memory` crash/replay and offline-conflict tests, and
`tests/memory_identity_e2e.rs`. Existing memory, team-memory, automatic-learning,
short-term-memory, statistics, eviction, and background-job suites remain part
of the compatibility gate.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

### Verification record

- Rust/Cargo: 1.98.0 only; build jobs 4; Rust test threads 1.
- Focused memory/config/team unit gate: 91/91 passed.
- S-053 adversarial unit gate: 20/20 passed, including second-root and
  mid-lineage scope-change rejection, physical-store persistence/replacement/
  alias rejection, fail-before-effect capacity limits, bounded operation-log
  retirement, partial-conflict preservation, stale overlays, crash replay,
  offline-parent repair, and private-memory non-replication. The record-level
  scope-construction negative is also included in the 91-test gate.
- S-053 integration gate: 5/5 passed, including physical team-store replacement.
- Existing integrations: memory 13/13; eviction 12/12; short-term 29/29;
  statistics 17/17; automatic learning 24/24; team/thinking 37/37;
  background-job registry 16/16. The full gate also exercised the remaining
  background job suites.
- Strict all-feature/all-target Clippy with `-D warnings`: passed with no
  warnings.
- Full locked all-feature/all-target test command with `--no-fail-fast`:
  passed. The library harness reported 2,697 passed and one explicitly ignored;
  the binary and every eligible integration target also passed.
- Windows GNU locked all-feature/all-target check: passed. Its warnings are
  pre-existing target-conditional unused/dead-code warnings outside S-053.
- `cargo fmt --all -- --check` and `git diff --check`: passed.

The pre-commit candidate was rejected twice during skeptical review. The first
review found second-root reuse, lifetime operation-log exhaustion, missing
physical-store binding, and a hidden conflict head. The second found unbounded
history materialization, post-effect cap checks, same-store role aliasing, and
scope-changing successors. Each defect was repaired at its transaction or
validation boundary and received a negative test before the full gates above.

The final ordered source/test artifact manifest has SHA-256
`f1bad306c719a18e4cd05bf1ee65e2f536d4672d8cf8b48a472ac2f29b00398c`:

- `README.md`: `6718ca71a4982c3432a43a236c26fcdf21e79027c5870eeba62cf23dd6492155`
- `docs/remediation-slices/012-runtime-feature-reachability.md`: `47883bff115c5713e7b3d8737520cfec0c83996f0fae89ec41fab6a5c2fd8244`
- `src/config/memory.rs`: `f396468e3fea5f4142eb01d69874c2a9cb65c4b4253618c8ffb92aa3e7f44a4c`
- `src/config/mod.rs`: `5b207dcb3c9061766889800d0554df6e2c029e52c9d3f06585b5c2fb8fe2f505`
- `src/memory.rs`: `c930ae95f79d65ec2f62235fc67112e53d3fbf04436692e165a369e2f051a3b5`
- `src/memory/record.rs`: `46ba27f068f3784f8dd2b4db5851956cc1b55b51dc6ddec485353548bfbc800a`
- `src/services/background.rs`: `2faf7d1f72956dd617ccecb91c7eca08eb4c8e82f8a409b318c4edeef5d886c8`
- `src/services/lifecycle.rs`: `434142c9ec05c1df886b63df64337e048cc0c980e8cb77dfcfac1446b7ebfd1d`
- `src/subagent.rs`: `ddb380cf15b1812a63100ef5ed267a65027e39104b552ddaa50b04b83acc0080`
- `src/team_memory.rs`: `b0ed26d1d0f200fb04d50bfde9103da780e9819f02e7dba27905f733ef9c0302`
- `tests/lifecycle_service_reachability_e2e.rs`: `3098d955a5977382dfb1e130885ba8eccd67d81222add1f0291c53ba4564c081`
- `tests/memory_identity_e2e.rs`: `b9b4078e18c6ebd514ebca4618dffff523111c71a371c0525f312c236e74f239`
- `tests/service_registry_jobs_e2e.rs`: `9b2bac07a9b19f6ac72545c735f8737607a00092590e0a25b5f8c70a84e85c3a`

The slice document is commit-tracked and its stable digest is recorded in the
Crosslink result receipt to avoid self-reference.

Unresolved work is intentionally assigned, not hidden: S-054 owns local memory
authority/schema and the bounded lexical retrieval baseline; S-055 owns
evidence-bound automatic learning; S-056 owns memdir lifecycle; S-103/S-104 own
authenticated team authority and replication; S-105 owns evaluated advanced
retrieval; S-084 owns the supervised background scheduler; S-088 owns
artifact-bound VDD.

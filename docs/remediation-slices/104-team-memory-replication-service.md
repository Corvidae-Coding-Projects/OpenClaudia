# S-104: Wire the team-memory replication service

Status: Implemented and adversarially reviewed; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: Design requirement from F-006, F-075, and W5
Workstreams: W5, W10, W15
Depends on: [S-051](./051-token-turn-and-cost-budgets.md), [S-053](./053-memory-record-identity-and-merge.md), [S-054](./054-memory-authority-and-schema.md), [S-103](./103-authenticated-team-memory-authority.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make authenticated team technical memory operational through a bounded service
and the same canonical tools and lifecycle as private technical memory.

## Implementation boundary

- Define a versioned bounded protocol for causal lesson revisions, tombstones,
  conflict heads, cursors, acknowledgements, retry keys, and typed terminal
  outcomes. Authenticate every request through S-103 before reading or writing.
- Encrypt transport and protected persisted replicas, pin service/team identity,
  and reject downgrade, replay, cross-team, and store-replacement attempts.
- Reuse S-053 logical identities and immutable revision graph. Synchronize in
  bounded parent-before-child batches with durable idempotent outbox/inbox state;
  offline or concurrent branches remain visible until explicit typed resolution.
- Wire approved team configuration into startup and the canonical memory
  tools without treating repository content or a shared path as authority.
  Private lessons never leave their scope; team results remain untrusted cited
  evidence and never enter prompts ambiently.
- Apply explicit time, byte, record, concurrency, retry, and shutdown budgets.
  Distinguish unavailable, partial, stale, conflicted, unauthorized, and corrupt
  states rather than silently falling back to a different scope.

## Acceptance

- Authenticated members can retrieve and mutate permitted team lessons through
  every supported frontend; unauthorized callers learn no team content.
- Lost responses and process restarts replay idempotently. Offline concurrent
  edits converge without row-ID aliasing, private-data leakage, hidden heads, or
  last-writer data loss.
- Network interruption, tampered messages, wrong keys, revoked membership,
  bounded-queue exhaustion, and service/store replacement fail visibly with
  recoverable durable state.
- Relevant deterministic tests and trace assertions pass; attach an
  artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence
receipts, unresolved risks, and any newly proposed slice. Completion of this
slice does not imply completion of its parent workstream.

## Implemented architecture — 2026-08-22

The implementation adds a separate encrypted host-owned team replica rather
than sharing the private SQLite database. It reuses S-103 grants for exact
operations and S-053 immutable causal revisions, persists bounded idempotent
outbox/inbox state, pins the team, service, certificate, and replica identities,
and exposes typed freshness, conflict, authorization, corruption, and capacity
outcomes. A replica identity anchor without its encryption key is a recovery
error; only the genuine legacy state where both artifacts are absent may create
them lazily. The transport owns a bounded TLS server and supervised client
worker. Cancellation is independent of the bounded command queue, so a full
queue cannot make supervisor destruction wait forever.

The canonical technical-memory tools now share one explicit scope model:
reads accept `user`, `team`, or `both`; writes require exactly `user` or `team`
and reject `both`. Team records remain typed, cited technical lessons retrieved
only by tool call. They are neither prompt prose nor ambient context. Private
records cannot enter the team outbox, and combined reads disclose partial or
revoked team state instead of silently pretending the private result was the
whole requested scope.

Startup wiring is present in the TUI, legacy REPL, ACP, and subagent paths.
Subagents reopen the exact already-authorized replica identity rather than
deriving authority from repository content. The host-only CLI provides replica
status, synchronization, bounded TLS service ownership, and a two-step service
configuration exchange. `service-descriptor` mints a short-lived signed public
descriptor without exporting the TLS private key; `configure-service`
authenticates its one-time grant and pins the exact endpoint, certificate,
principal, and replica. Replaying a consumed descriptor is unauthorized, while
a freshly minted descriptor for the same pinned identity is an authenticated
idempotent refresh. A changed pin or identity fails closed.

Every pull and push rechecks a fresh exact-operation permit immediately before
its protected effect. Service requests likewise recheck a fresh local Admin
permit at their final effect boundary. Client startup requires active local
membership and service startup requires an active Owner. Pull responses are
bounded, require strictly consistent revision/digest pairs, and advance only a
durable causal cursor; batches commit parent before child and preserve every
concurrent head, including tombstone-only conflicts.

Issue #1081 adds an explicit `Resolve` operation available only to maintainers
and owners. Conflict inspection consumes the same authenticated read grants as
other team reads. A resolution names the complete current head set, publishes
one multi-parent active revision under signed exact-operation grants, queues it
exactly once, and converges
offline clients and the service without last-writer-wins. Active/tombstone and
tombstone-only conflicts remain inspectable until that resolution commits.

## Verification evidence

All Rust commands used Rust 1.98.0 and `CARGO_BUILD_JOBS=4`; every test command
used `--test-threads=1`.

- Replica unit scenarios: 21 passed. They cover durable lost-response replay,
  restart recovery, offline concurrent heads, tombstone conflicts, encrypted
  persisted bytes, exact capacity, parent ordering, cursor/digest tampering,
  wrong teams and keys, missing key/anchor state, revocation, and grant races.
- Transport unit scenarios: 7 passed. They use a real pinned TLS client/service,
  exercise synchronization and interruption-to-stale outcomes, reject pin and
  identity replacement, and prove bounded shutdown with a saturated queue.
- Team-authority E2E: 17 passed; real-binary authority CLI E2E: 5 passed. The
  latter covers descriptor creation, configuration, authenticated refresh, and
  consumed-descriptor replay rejection across isolated host processes.
- Public team-memory E2E: 5 passed. The tests exercise every canonical
  tool, private-data non-replication, explicit invalid write scope, revoked
  combined-read partial status, and registry schema exposure.
- TUI/REPL startup, ACP startup, and exact subagent replica reopening each
  passed their production-route regression. Lifecycle reachability passed 6/6;
  team-memory thinking/boundary coverage passed 34/34.
- Locked all-feature/all-target native `cargo check` passed. Strict all-target
  Clippy with `-D warnings` passed without suppression. The complete locked
  all-feature/all-target native test suite passed with exit status 0, including
  2,731 library tests plus all integration, binary, and doctest targets.
- Locked all-feature/all-target Windows GNU `cargo check` passed. One
  S-104-specific conditional import warning was found, fixed at its source, and
  the gate passed again without warnings from S-104 paths. Remaining Windows
  unused/dead-code warnings are pre-existing platform-test findings owned by
  their existing remediation issues.
- Issue #1081 follow-on verification passed all seven private conflict E2Es,
  the 17-test team-role matrix, five public team-scope E2Es, six portable E2Es,
  and the offline active/tombstone convergence scenarios in the library suite.
  Strict Rust 1.98.0 Clippy, Windows GNU all-target check, and the complete
  native all-feature/all-target test matrix also passed.

The SHA-256 digest of the sorted `sha256sum` manifest for the 28 changed
non-slice artifacts is
`3aad53120f698c54216851d17029518e2939dcce7302b0488bde1d451f720009`.

The skeptical repair cycle also rejected weaker tests and implementation
shortcuts: an initial missing-key fixture asserted failure at handle creation
instead of the first replica-state read and was corrected; a duplicate
applicability fixture was normalized by deserialization and was replaced with
an actually invalid empty applicability case; failure-counting and
no-panic-only assertions were not used. Clippy findings were resolved through
named authorization structures and helper extraction rather than allowances.

## Residual boundaries

- S-088 owns the independent artifact-bound VDD receipt; this status does not
  claim that future review has already occurred.
- The encrypted replica detects rollback inside one live trust lineage, but
  preventing a privileged full-host snapshot rollback requires an external
  monotonic anchor. That deployment capability remains explicit rather than
  being represented as solved locally.
- A cancelled blocking SQLite operation may finish after its async waiter is
  aborted; the shared bounded blocking-task lifecycle is owned by S-041.
- Non-Unix descriptor-safe private storage remains owned by S-036. Windows is
  compile-gated here and the runtime fails closed where that backend is absent.
- Concurrent causal heads remain visible until the explicit typed resolution
  operation delivered by issue #1081; replication does not discard any head.

The implementation completes S-104 only. It does not imply completion of the
parent dormant-feature workstream or of later technical-memory evaluation work.

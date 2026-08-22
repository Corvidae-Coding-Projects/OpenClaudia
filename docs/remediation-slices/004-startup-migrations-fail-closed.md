# S-004: Make startup migrations fail closed

Status: Implemented and adversarially reviewed; VDD pending
Effort: Small
Primary findings: F-010
Workstreams: W0, W13, W15
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent startup from continuing with unknown, partially migrated, or failed persistent state.

## Implementation boundary

- Return typed migration outcomes from every startup path and stop or enter an explicit read-only recovery mode on failure.
- Make migrations transactional and idempotent, and expose actionable recovery information without leaking persisted content.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Injected migration failures never start a normal writable agent session.
- Restart, partial-write, old-schema, and already-migrated tests produce deterministic terminal states.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

### Architecture decision

The selected design is a fatal composition-root gate. `run_startup` resolves
absolute host paths without an ambient-CWD fallback and returns one typed
`StartupMigrationStatus`: `Writable` only after every registered migration is
current, or `RecoveryRequired` with a stable diagnostic category, affected
store, content-free operation, atomic-publication count, and recovery action.
`main` consumes that state before sandbox, provider, proxy, ACP, loop, print,
REPL, or TUI construction. The runner holds a bounded `OpenClaudia` data-store
lock, rejects once-only registrations, catches panic control flow, and stops at
the first failure. Every recovery state emits one typed terminal trace.
Migration error rendering and that terminal trace omit persisted paths, bytes,
parser excerpts, and panic payloads. Rust invokes the process-global panic hook
before `catch_unwind` returns; no process-global hook is temporarily replaced
because doing so would race other threads. Migration implementations therefore
remain forbidden from formatting persisted paths or bytes into panic payloads.

An explicit read-only recovery frontend was considered but not selected:
there is no canonical startup composition root that can prove every current
frontend/store handle is read-only. Reusing a normal frontend under a mode
label would therefore weaken the required gate. This slice stops instead and
returns an actionable recovery state.

The two live migrations use the S-031 descriptor-safe persistence capability.
The saved-session migration enumerates at most 8,192 total directory entries,
4,096 JSON artifacts, and 256 MiB of desired bytes. It validates the complete
deterministic input set before publication, and then reconciles every observed
generation through locked, atomic, durable per-artifact commits. A later commit
failure reports the exact number of visible atomic publications and stops
startup; restart validates the already-current prefix and continues
idempotently. The legacy transcript marker preserves unrelated object fields,
migrates only explicit version 0, rejects malformed/missing-field/future
versions, generation-checks current bytes, and no longer creates a foreign
transcript directory when that store is absent.

### Changed artifacts

- `src/main.rs`: mandatory fail-stop gate before any agent-capable subsystem.
- `src/migrations/mod.rs`: typed terminal/failure/report API, explicit context,
  bounded store lock, panic containment, stop-first-failure runner, and typed
  applied-count adapter.
- `src/migrations/registry.rs`: idempotent append-only registry contract.
- `src/migrations/ledger.rs`: compatibility boundary documenting that the
  non-transactional legacy ledger is not startup authority.
- `src/migrations/session_state_v1.rs`: bounded complete preflight plus
  generation-checked descriptor-safe publication and partial/restart state.
- `src/migrations/stamp_transcript_schema_v1.rs`: strict old/current/future
  dispatch, unknown-field preservation, atomic publication, and absent-store
  no-op behavior.
- `src/migrations/tests.rs` and `tests/migrations_runner_e2e.rs`: adversarial
  runner, real filesystem, restart, partial-prefix, malformed/future, lock,
  panic, redaction, and real binary startup tests.

No generated projection is affected. `.crosslink/rules/*.md` were confirmed to
remain zero-byte loader inputs. The final post-format SHA-256 artifact digests
are:

- `bf405f11ff25a945898f68c9fa678154b100b1819692d980c9e0d18fe3c57622`
  — `src/main.rs`
- `7a3b9b42f08b39f239794cb0d320f8a8fcd495f8b9969ddab07bba24bd614fc3`
  — `src/migrations/ledger.rs`
- `71a8f4f2edf115d463b6f29daa4751e2c5a2e534711990a21d2b40599c5fc42d`
  — `src/migrations/mod.rs`
- `6d01a60c40e527412e83fa075f1df90135318016a9a27f070b4bd7a97219b90b`
  — `src/migrations/registry.rs`
- `085b7b5618d505ad287498d468c0d7479e351f5b98320496c46eb207c4c34220`
  — `src/migrations/session_state_v1.rs`
- `942f5c7545f1cd28df3d7b6ee1ed112016ccdd71778de2719aa777b9ee037d27`
  — `src/migrations/stamp_transcript_schema_v1.rs`
- `718b11953f9bca719d6dd436a94b0611311ed62f3aee10137dbbd5e426844eb4`
  — `src/migrations/tests.rs`
- `d70230a137c6cd67e37be47911a4c56d30a7459f548d7313422e8ceb26049e6c`
  — `tests/migrations_runner_e2e.rs`

The SHA-256 of the ordered `sha256sum` manifest above is
`1fec41e64efd88edcc57f2529d90fd1a7da4cf71b05c4fb09d8520d7dfe435fe`.
The slice document itself is commit-tracked rather than self-digested.

### Test skepticism and acceptance evidence design

The former integration suite accepted `applied + skipped + failed == total`,
allowed failures to count as success, asserted only that repeated calls did not
panic, and tested a count wrapper that erased failure. Those assertions were
removed. Replacement tests require terminal `Writable` or
`RecoveryRequired` states and inspect real end state:

- a valid legacy session sorted before a malformed session proves complete
  preflight leaves both original generations unchanged;
- a pre-existing canonical/legacy mixed prefix converges on one run and is
  byte-stable/current on restart;
- malformed and future markers remain byte-identical and terminal;
- supported old marker state migrates once while preserving another
  producer's field;
- a held OS lock reaches bounded recovery and permits a later retry;
- a caught panic closes startup and its typed returned diagnostic omits the
  payload; a rejected once-only registration never permits its side effect;
- a relative explicit context is rejected before a lock, store creation, or
  migration effect;
- a malformed real store emits a stable migration/version/failure/recovery
  trace while omitting the persisted bytes;
- the built `openclaudia --print` binary, with a malformed real session store,
  must exit non-zero before provider output and must not render the sensitive
  filename or bytes.

These are pre-VDD executable evidence scenarios, not canonical VDD evidence.
S-088 remains pending and is queued below.

### Verification record

- Non-Cargo preflight: assigned branch/worktree and exact baseline
  `9194ac26e08e899a2acb7336523f5f9bafb463fd` confirmed; worktree was clean;
  Crosslink session #1 and child issue #1050 confirmed; issue lock is owned by
  `s004-wave` (reported stale because the coordinating owner does not
  heartbeat through this worker).
- `git diff --check`: passed both during implementation and after the final
  document update.
- Repository searches: one production startup migration caller (`main`), two
  registered migrations, and all Rust callers/tests were traced.
- The first `cargo fmt --all -- --check` reported only formatting differences;
  the authorized `cargo fmt --all` repair and repeated check passed. Later
  formatting/check passes also completed with no output.
- `CARGO_BUILD_JOBS=1 cargo test --locked --all-features --test migrations_runner_e2e -- --test-threads=1`:
  final corrective run passed 5/5 real integration tests, zero failed, in
  0.01s after compiling in 14.30s. An earlier run also passed 5/5 after a
  compile-only retry for a missing `Path` import introduced during
  Clippy-driven decomposition.
- `CARGO_BUILD_JOBS=1 cargo test --locked --all-features --lib 'migrations::' -- --test-threads=1`:
  final corrective run passed 19/19 migration tests, zero failed, 2,626
  filtered, in 0.11s after compiling in 22.62s. The first corrective attempt
  was compile-only and exposed that the trace capture writer lacked the
  standard `MakeWriter` adapter; the adapter was implemented and the same
  command then passed. An earlier pre-correction run passed 18/18.
- The first locked all-feature/all-target check failed before checking project
  source because the earlier faulty PostToolUse provider invocation had left a
  truncated generated `headless_chrome` `protocol.rs` cache (533,933 bytes
  versus the intact 1,134,808-byte generated peer). The exact two broken cache
  directories were moved recoverably to `/tmp/s004-headless-cache.J7obSb`;
  no source or dependency was deleted. The unchanged command regenerated the
  cache and passed in 1m05s; a later all-target check passed in 26.11s.
- The first strict Clippy pass found eight local issues across const
  qualification, redundant closures, and two overlong functions. They were
  fixed at cause by decomposing planning/publication/lock operations; no allow
  was added. The
  repeated `CARGO_BUILD_JOBS=1 cargo clippy --locked --all-features --all-targets -- -D warnings`
  passed in 1m18s. The final corrective rerun passed without warnings in
  57.18s. The final locked all-feature/all-target check also passed in 28.41s.
- `CARGO_BUILD_JOBS=1 cargo test --locked --all-features --all-targets -- --test-threads=1`
  initially compiled successfully and ran the library suite, where 2,637
  passed, six failed, and one was ignored. The final corrective run compiled in
  3m13s and ran 2,645 library tests: 2,638 passed, the same six failed, and one
  was ignored. All six failures are pre-existing
  `tools::worktree` tests: their test `ToolRunContext` exposes only the linked
  checkout, while its `.git` file points to the common Git directory outside
  the sandbox capability, so sandboxed Git reports “not inside a repository.”
  Host `git rev-parse` succeeds. The independent defect is tracked as #1055;
  no unrelated test or sandbox authority was weakened, and the final failure
  set did not expand. The repository-wide suite therefore is not green, but it
  has no new or S-004-attributable failure. The unchanged failures are
  `enter_and_exit_worktree_bump_cwd_cache_generation_624`,
  `enter_worktree_duplicate_call_is_no_op_624`,
  `exit_worktree_clean_worktree_exits_without_discard_flag_623`,
  `exit_worktree_refuses_to_destroy_dirty_worktree_without_discard_623`,
  `test_get_current_branch_at_cwd`, and `test_list_worktrees`.
- `CARGO_BUILD_JOBS=1 cargo check --locked --all-features --all-targets --target x86_64-pc-windows-gnu`:
  initially passed in 4m00s. The final corrective run passed in 39.98s and
  emitted ten existing unrelated Windows-cfg test-only unused/dead-code
  warnings; it emitted no S-004 warning. The installed target compiled the
  S-004 `LockFileEx` path.
- PostToolUse `TEST REMINDER`/`file - no issues detected` messages performed no
  Cargo or linter work and are not counted as verification. The earlier actual
  implicit `headless_chrome` compile diagnostics were reported separately and
  led to the generated-cache recovery above.

### Residual boundaries and retrospective queue

- S-038 owns the canonical session-version chain, removal of the unconsumed
  foreign Claude marker, and a bounded read-only foreign transcript importer.
  S-004 keeps that compatibility migration strict and fail-closed without
  claiming S-038's ownership redesign.
- S-036 owns a race-safe Windows descriptor-relative persistence backend. The
  S-004 API and lock compile path cover Windows, but a Windows runtime with an
  existing migrated store remains dependent on S-036's backend.
- Advisory locks serialize cooperating `OpenClaudia` processes; they cannot
  stop an unrelated same-user writer that bypasses the storage capability.
- `catch_unwind` contains migration panic control flow but cannot suppress a
  process-global panic hook that runs first. Registered migration code must
  never include persisted paths/bytes in panic payloads; replacing the hook
  temporarily would introduce a cross-thread diagnostic race.
- S-088 retrospective VDD queue: bind the final S-004 artifact digest to an
  independent review of fail-stop ordering, partial/restart convergence,
  content redaction, and the real binary injected-failure end state. No
  canonical VDD receipt is claimed before S-088 exists.

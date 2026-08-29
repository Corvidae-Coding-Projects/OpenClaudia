# S-037: Make session mutation and finalization atomic

Status: Complete
Effort: Medium
Primary findings: F-067, F-069
Workstreams: W12, W15
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent failed persistence or panicking mutations from discarding session state or leaving invisible partial changes.

## Implementation boundary

- Validate proposed state off to the side, publish one monotonic generation transactionally, and emit events only after commit.
- Represent ending, durability uncertainty, recovery, and terminal outcomes explicitly; retain the last committed state on panic/error.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Injected panic, serialization, disk, fsync, and notification failures never partially mutate the committed session.
- A failed end operation remains recoverable and cannot report successful deletion or completion.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- `StateStore` mutations now run against a private cloned proposal. A panic
  discards that proposal and its notifications, leaves the lock usable, and
  preserves the last committed snapshot. Successful updates publish exactly
  one increasing in-memory generation before emitting granular events and a
  final commit boundary.
- Complete snapshot replacement is visible even when the session identifier is
  unchanged. Transcript reconciliation now consumes that replacement event,
  while lagged or failed notification delivery remains recoverable from the
  canonical snapshot and generation.
- `SessionManager` now owns a private descriptor-pinned finalization head under
  `.session-transactions/`. The head records the schema, monotonic generation,
  explicit terminal outcome, complete session, and handoff. It uses the S-031
  generation-checked commit path and retries a visible durability-uncertain
  publication before reporting success.
- `end_session` proposes handoff changes on a clone and removes the live
  session or terminates its owned processes only after the authoritative head
  is durable. Validation, serialization, storage, generation-conflict, and
  unresolved durability failures leave the original active session available
  for retry and cannot produce the normal completion log.
- Existing `<id>.json`, `latest.json`, and `handoff.md` behavior remains
  operational as a compatibility projection. Projection failure cannot hide a
  committed head; startup and the next finalization repair projections from
  the newest authoritative generation, with a post-write generation check so
  a slower concurrent writer cannot regress `latest.json`.
- Proxy shutdown now surfaces finalization failure to its caller and cannot
  emit the loop-completed outcome after a failed session commit. The new
  machine-local default session directory is explicitly ignored by Git.

## Evidence

All Cargo commands used Rust/Cargo 1.98.0 with `CARGO_BUILD_JOBS=4`, one heavy
Cargo process at a time, and `--test-threads=1` for test execution.

| Gate | Result |
|---|---|
| Focused atomic-state tests | Passed 9/9, including panic rollback, usable follow-up mutation, monotonic generation, event ordering, lag reconciliation, and zero-subscriber commit |
| Focused session tests | Passed 63/63, including retained state after persistence failure, monotonic authoritative heads, stale projection rejection, missing-projection repair, guard failure visibility, and legacy round trips |
| Proxy and compatibility regressions | Passed 64/64 proxy unit tests plus 20/20 proxy-config, 21/21 proxy-error, 17/17 translation, and 16/16 session-manager integration tests |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed every native library, binary, example, and integration target; the library result was 3,067 passed and one ignored, with only seven explicitly ignored cases across the complete run |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics |
| Default and all-feature native checks | Passed all targets |
| Windows GNU all-feature/all-target check | Passed; only the existing target-conditional warnings tracked by #1099 were emitted |
| Fuzz workspace | Locked check and strict Clippy passed; 4/4 finite hermetic library tests passed |
| Repository and dependency policy | Passed 27/27 policy tests, verified hygiene with zero forbidden tracked artifacts, both locked metadata graphs, and both root/fuzz `cargo deny` policies |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |

Artifact generation `S037-G1` is based on
`bf6e57c41e243faaa66edaa70885ea8b2845119f`. The SHA-256 digest of the sorted
per-file SHA-256 manifest for the six changed product/configuration artifacts,
excluding this self-referential completion record and the later
machine-generated changelog entry, is
`661f6790cc2a2a120e791a1ccb9f6fe635216fa1dc81d795dc14a48933423f2f`.

## VDD handoff

Queue `S037-G1`, its base revision, manifest digest, the acceptance criteria,
and the evidence above through the canonical S-088 verifier with a configured
alternate model. The verifier must use the same harness, guardrails,
descriptor-pinned storage authority, runtime capabilities, resource budgets,
reality grounding, and terminal-state rules used here. A post-finalization
hook receipt cannot yet be published because that product integration remains
tracked by #1201; no independent receipt is fabricated or claimed here.

## Residual boundaries

- The three legacy session files remain supported projections rather than
  being removed or redefined as the commit authority.
- Windows GNU warning cleanup remains assigned to #1099 and was not expanded
  into this functional slice.
- Completion applies only to S-037. Parent issue #1071 remains open.

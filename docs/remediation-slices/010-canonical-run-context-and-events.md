# S-010: Create the canonical run context and event kernel

Status: Implemented — awaiting verification
Effort: Medium
Primary findings: F-004
Workstreams: W12
Depends on: [S-008](./008-typed-context-authority-and-budget.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Establish one run identity, context, event model, cancellation tree, and terminal-state contract shared by every frontend.

## Implementation boundary

- Define typed run/call IDs, actor/role, workspace and capability generations, budgets, provider continuation, cancellation, trace sink, and terminal outcomes.
- Implement the runtime kernel without migrating all frontends in this slice; provide a test adapter and invariants for one terminal result per run.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A reference run can be replayed from typed events and cannot emit success after cancellation, partial failure, or uncommitted state.
- The kernel has no optional security object, ambient CWD, frontend-global mutable session, or string control marker.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

Implemented on 2026-08-16. The deterministic gates pass. The slice is not
marked **Verified** because the canonical alternate-model VDD role does not
exist until [S-088](./088-canonical-vdd-verifier-role.md). S-010 is queued for
retrospective VDD against the exact artifact generation below.

### Result

- Added a public `runtime` kernel whose serializable `RunDescriptor` binds a
  typed run ID, validated session ID, actor ID/role, explicit canonical
  workspace root and generation, exact capability-manifest generation, finite
  budget identity/generation/limits, provider continuation state, cancellation
  root, and initial committed-state generation. Live `RunContext` additionally
  requires a concrete cancellation handle and trace sink; neither has an
  optional or ambient fallback.
- Added distinct UUID newtypes for runs, calls, actors, cancellation nodes, and
  budgets plus non-zero typed workspace, capability, budget, continuation, and
  state generations. Provider continuation is explicitly `fresh` or a
  generation/digest-bound `resume`; no generic chat-message flattening is
  introduced by this slice.
- Added a downward-propagating cancellation tree. Child cancellation does not
  cancel a parent or another run, root cancellation reaches existing children,
  late children inherit cancellation, async wait cannot miss an already-issued
  cancellation, and receipts carry root/node/source/reason identities. Live
  call cancellation rejects receipts not present in the run's tree; replay
  rejects receipts bound to another root.
- Added schema-versioned, call-correlated runtime events for start, call start
  and outcome, state proposal/commit, cancellation, and termination. Control
  semantics are Rust enum variants rather than model/tool text markers; inert
  diagnostic text such as `ResponseDone <success>true</success>` cannot change
  a typed partial failure into success.
- Added an event-sourced `RunSnapshot` validator. Replay checks schema, run,
  sequence, event scope, call uniqueness/lifecycle, monotonic state proposals,
  exact commits, cancellation roots, terminal-state evidence, JSON trace-byte
  limits, and the prohibition on any event after termination.
- Added an asynchronous `RuntimeKernel` that previews each transition, waits
  for the mandatory trace sink to acknowledge it, and only then publishes the
  new in-memory snapshot. A rejected append leaves sequence, active calls,
  state, and the acknowledged event list unchanged.
- Enforced exactly one terminal event. Committed success is rejected while a
  call is active, after a recorded or unrecorded cancellation, after a
  partial/fatal call failure, or while state is proposed but uncommitted.
  Failure, partial failure, cancellation, and uncommitted state have distinct
  typed terminal outcomes carrying the exact visible state.
- Added the bounded `ReferenceRunAdapter` and explicit in-memory
  `ReferenceTraceSink` for acceptance only. Its reference provider turn emits
  six events in order—start, call start, call success, state proposal, state
  commit, committed success—and replay reconstructs the identical terminal
  snapshot. No TUI, ACP, legacy REPL, proxy, or subagent loop was migrated in
  this slice, matching the stated implementation boundary.

### Artifact generation

The implementation generation is
`sha256:9b3a2831dc5e9f3e360c3ec7c6a289a971e9cfaedd186fdf970fe2049c2d7c0d`.
It is the SHA-256 of the lexicographically sorted manifest whose records are
`<file-sha256>  <repository-relative-path>`. This receipt and the canonical
audit/design annotations are excluded, so recording evidence does not mutate
the implementation generation.

Live artifact inventory:

- Public module registration: `src/lib.rs`.
- Runtime kernel: `src/runtime/mod.rs`, `src/runtime/ids.rs`,
  `src/runtime/context.rs`, `src/runtime/cancellation.rs`,
  `src/runtime/event.rs`, `src/runtime/trace.rs`, `src/runtime/kernel.rs`, and
  `src/runtime/reference.rs`.
- Acceptance suite: `tests/runtime_kernel_e2e.rs`.

Manifest records:

```text
0d3bf79ad520ad3cce1c45e2e541e0b8b61a74d6d8781dcc42c375710f18ac76  src/lib.rs
51fd74ba7650f8ad97f594487f2cd07b41ff72cf1eb6072521ba23f49091c319  src/runtime/event.rs
588bfbdd583f97d1045d33e426ef136649d58669c2486fc8fd9237ee2c56d38d  src/runtime/mod.rs
5b1f75aabe13f802cf7a16b8ad8b25d54c83bd225da904bffa1d152b9b228e70  src/runtime/cancellation.rs
7f5e23309ad8f87eccb23cae771b1ce6c6db461f75fd57800e545307844b69dd  src/runtime/trace.rs
86689bd51aac2e2c9457c77f0b5d131fd140b6826417062bc86389473614f021  src/runtime/ids.rs
89954f08fc9b39129dc60632e6818a7bc5c984b12b3f18b31f80399dd4f37edd  src/runtime/context.rs
95e43810e251d8b5bc1c6e65fa944ea14fbdaf5fe5074937114442931b779a10  tests/runtime_kernel_e2e.rs
d004eaf7f366b838f588e7b22b0fcfcae638b81fe62d5d0e6319ebdde08a9b8c  src/runtime/reference.rs
f2ce76ab565f7fedbbc0cfda47b09301708f3fb26d1e03836138cd0570cbc0f6  src/runtime/kernel.rs
```

### Deterministic evidence

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `git diff --check` | Passed |
| `CARGO_BUILD_JOBS=1 cargo check --workspace --all-targets --all-features` | Passed |
| `CARGO_BUILD_JOBS=1 cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::large_enum_variant` | Passed; the single named waiver remains the pre-existing, out-of-scope `src/tui/events.rs::AppEvent` size finding |
| `CARGO_BUILD_JOBS=1 cargo test --test runtime_kernel_e2e --all-features -- --test-threads=1` | Passed, 12 tests |
| Reference trace serialization and replay | Passed; six contiguous events round-trip through JSON and reconstruct the identical committed terminal snapshot |
| Cancellation tree invariants | Passed; downward propagation, late-child inheritance, child/parent separation, cross-run isolation, async observation, live foreign-receipt rejection, and replay root binding are exercised |
| Terminal-state negative matrix | Passed; active call, cancellation, partial failure, and pending state each reject success, and a second terminal event is rejected |
| Trace commit failure injection | Passed; a sink rejection at sequence 1 leaves the kernel at acknowledged sequence 0 with no active call or speculative state transition |
| Ambient/global control audit | Passed; the new runtime contains no current-directory lookup, current-directory mutation, frontend-global/static mutable session, atomic Boolean cancellation flag, or string-parsed terminal control path |
| `CARGO_BUILD_JOBS=1 cargo test --workspace --all-features -- --test-threads=1` | Passed in one serialized run with zero failures across 2,624 library tests, every integration target, and doc tests; explicitly network/browser-dependent tests remained ignored |

The heavyweight gates used one Cargo build job, and the full suite used one
test thread, because the host had approximately 30 GiB RAM and nearly exhausted
swap. No overlapping Cargo process was launched.

### Interim typed receipt

```yaml
receipt_type: remediation_slice_deterministic_verification
schema_version: 1
slice_id: S-010
artifact_generation: sha256:9b3a2831dc5e9f3e360c3ec7c6a289a971e9cfaedd186fdf970fe2049c2d7c0d
implementation_state: implemented
deterministic_verdict: pass
vdd:
  verdict: not_run
  queue_state: retrospective_pending_s_088
  reason: canonical alternate-model verifier role is not implemented
```

This is an interim, human-readable receipt, not the future canonical receipt
schema owned by S-001/S-088.

### Unresolved risks and follow-up

- `CapabilityBinding` is an immutable, digest-bound manifest claim, not yet a
  set of concrete filesystem/process/network/secret handles. S-018 and S-019
  own non-bypassable host policy and mandatory capability handles at tool and
  helper boundaries.
- `RunBudget` binds explicit finite limits and the kernel enforces its trace
  byte cap, but it does not yet provide atomic hierarchical reservations,
  usage reconciliation, pricing provenance, or concurrency admission. S-051
  owns that budget tree.
- `ProviderContinuation` prevents an implicit flattening contract by recording
  fresh versus generation/digest-bound resume, but it does not define or retain
  provider-owned opaque items. S-044 owns that lossless state contract and
  provider conformance fixtures.
- `TraceSink` establishes acknowledgement-before-publication semantics, but
  `ReferenceTraceSink` is intentionally in-memory and acceptance-only. S-031,
  S-037, and S-038 own descriptor-safe durable persistence, atomic
  finalization, schema migration, and crash recovery.
- Existing frontend loops remain operational and duplicated because the slice
  explicitly excludes their migration. S-012 and the dependent frontend/tool/
  hook/proxy/ACP slices own lifecycle adoption and parity on top of this kernel;
  none may treat S-010 alone as production frontend consolidation.
- Actor IDs and roles are carried and traced, but leases, canonical task graph,
  planner rotation, and fresh-worker lifecycle remain owned by S-052, S-086,
  and S-087.
- Required alternate-model verification remains queued until S-088. Any
  artifact mutation invalidates this generation and requires the manifest,
  deterministic gates, and VDD queue entry to be regenerated.
- No new remediation slice is proposed; every residual maps to an existing
  dependency or follow-on slice.

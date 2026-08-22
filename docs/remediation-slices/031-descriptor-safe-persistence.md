# S-031: Build descriptor-safe persistent storage

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-014, F-083
Workstreams: W15
Depends on: [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Provide one authorized atomic storage API resistant to parent-symlink races and ambiguous post-rename failures.

## Implementation boundary

- Resolve trusted roots and targets descriptor-relatively with owner/type/mode/link checks, bounded files, expected generation, and explicit file classes.
- Return unchanged, committed-durable, published-durability-uncertain, or recovered states and reconcile uncertainty before retry.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Parent and leaf symlink swaps cannot redirect reads/writes outside the capability root.
- Crash, rename, directory-fsync, disk-full, concurrent-writer, and retry tests preserve a knowable committed generation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Added `PersistentStorage`, one explicit storage-root capability whose Unix
  backend opens every absolute root component and every root-relative target
  component with no-follow descriptor operations. The pinned root and every
  reopened parent are checked for owner, directory type, and group/world
  mutation; leaves are checked for owner, regular-file type, mode, hard-link
  count, and class-specific byte ceilings.
- Added six explicit file classes with fixed bounds and owner-only `0600`
  publication. Existing `0644` configuration, session, and artifact files have
  a deliberate read-compatibility path and are narrowed to `0600` on their next
  commit. Credential, canonical state, and evidence files never admit that
  broader legacy mode.
- Reads create no directory, lock, or sidecar. Returned bytes live in a
  non-clonable, zeroizing allocation; ordinary `Debug` output is redacted and
  exact materialization requires an explicit closure. Credential generations
  remain available to the authorized caller for concurrency, but automatic
  read/commit traces and receipt debug output redact their content digest.
- Commits require an exact SHA-256 content generation. A fixed per-target
  sidecar lock serializes cooperating writers with a bounded two-second
  production wait. The staged file is owner-only, bounded, synchronized, and
  checked again for descriptor metadata, exact content digest, parent binding,
  lock binding, and stage-name/inode binding immediately before publication.
  All target and sidecar opens are nonblocking before file-type validation.
- Publication uses descriptor-relative `renameat`, followed by parent-directory
  `fsync`. `CommitReceipt` distinguishes `Unchanged`, `CommittedDurable`,
  `PublishedDurabilityUncertain`, and `Recovered`. A post-rename failure never
  becomes an ordinary error; retrying the same desired generation reconciles
  and synchronizes it without republishing. A true no-op remains `Unchanged`
  and does not falsely claim a new uncertain publication.
- Receipts bind the pinned root device/inode, exact canonical relative target,
  file class, previous/current generations, state, and bounded durability
  diagnostic. Receipt targets serialize losslessly as tagged Unix-byte or
  Windows-UTF-16 hexadecimal rather than failing or becoming lossy for a valid
  non-UTF path. Receipts are output-only and cannot be deserialized into a
  fabricated live result.
- Removed the public generic `write_file_atomic` contract that caused F-083.
  The legacy-named JSON adapter is preserved for current session frontends, but
  it is explicitly session-classed and delegates to `PersistentStorage` while
  retaining a typed uncertain receipt. The lower-level crate-private rename
  primitive remains only for stores assigned to later migration slices and no
  longer claims authority or durability.
- Preserved first-save behavior in the line REPL by explicitly creating its
  compatibility session directory before invoking the new adapter. Existing
  TUI and migration callers remain operational and their real filesystem tests
  pass. Full session transactions and secure directory bootstrap remain S-037,
  rather than being implied by this compatibility bridge.
- Reclassified configuration path validation as a diagnostic precheck and made
  it report every existing parent or leaf symlink. Its documentation and load
  boundary now state that it cannot authorize later path-based I/O; the
  descriptor capability is the security boundary.
- Non-Unix construction fails with `UnsupportedPlatform`; no path-based
  fallback preserves a false security claim. S-036 owns the Windows handle and
  reparse-point backend plus startup capability negotiation.

## Architecture decision

The selected design treats the opened directory object—not a canonicalized
string—as authority:

`host-selected root` → pinned root descriptor → validated parent descriptors →
bounded observation/generation → locked staged commit → rename → directory
durability receipt.

This keeps path containment, generation exclusion, and durability state in one
reusable boundary. Parent creation is intentionally separate: a data commit
cannot silently expand its filesystem scope. The constructor is a host
composition operation; choosing which existing root is authorized remains
host policy rather than something a model-supplied path can decide.

The rejected compatibility design was to retain `canonicalize`/lexical checks
plus a sibling temp file and `rename`. It cannot close a check/use parent race
and cannot distinguish a failed pre-rename write from a published replacement
whose directory sync failed. Merely adding a random stage name or another
final-component symlink check leaves both findings intact.

Linux `openat2` resolution flags or a new capability-filesystem dependency
could reduce syscall code on one platform, but would add kernel/version or
dependency policy before solving the Windows handle contract. Iterative
`openat`/`renameat` provides the required Unix object binding with existing
dependencies; S-036 remains the explicit place to implement and test the
platform-neutral backend rather than disguising a path fallback as parity.

## Artifact generation

- Generation: `S031-G1`.
- Baseline commit: `76c03f924c3db4e25a5ab9bdf87633169062fc4d`.
- Source/test artifact digest: SHA-256
  `f1af9b0c162cbaf19b21c29681c9681b27fa51c8fdbafc771857a4877a2fbdf8`
  over `git diff --cached --binary HEAD -- src tests` after the skeptical
  implementation/test review, formatting, strict linting, complete test run,
  and explicit staging. Any source or test change invalidates this generation.
- Scope: eight source/test paths; 3,693 insertions and 138 deletions. The
  generation includes the new 3,314-line implementation/unit-test module and
  the 149-line public-contract integration suite.

## Acceptance evidence

| Receipt | Evidence | Result |
| --- | --- | --- |
| `S031-E1` | `parent_and_leaf_symlinks_cannot_redirect_reads_or_writes`, deterministic read parent/leaf swaps, publication-boundary parent swaps, root-ancestor symlink rejection, and the public outside-root symlink suite use real filesystem objects and prove outside sentinels remain unchanged. | Pass |
| `S031-E2` | `commit_receipts_distinguish_durable_unchanged_and_recovered`, `unchanged_content_does_not_claim_a_new_uncertain_publication`, and `directory_fsync_failure_is_uncertain_then_retry_recovers` assert the four typed states, exact generations, and idempotent reconciliation. | Pass |
| `S031-E3` | The subprocess crash test exits at real pre- and post-rename boundaries, then proves the old generation can be committed or the published generation recovered. Injected ENOSPC, rename, and directory-fsync failures prove unchanged versus uncertain outcomes without inferring them from an error string. | Pass |
| `S031-E4` | Real same-process concurrent writers and two independently opened public capabilities produce exactly one durable winner and one typed stale-generation conflict; the final bytes and generation equal the winner. Lock acquisition has a bounded deadline and succeeds after release. | Pass |
| `S031-E5` | Target depth/length/traversal/reserved-name cases, owner/type/mode/link checks, inclusive class ceilings, legacy-mode narrowing, FIFO leaves, FIFO lock/stage sidecars, and non-UTF targets exercise actual OS behavior. Oversized input is rejected before any sidecar or target appears. | Pass |
| `S031-E6` | Parent mode mutation, detached-namespace conflict, lock-name rebinding, stage content mutation, transient hard linking, and stage-name/inode substitution all stop before publication. The rebound-stage test retains both the validated and substituted bytes and proves neither became the target. | Pass |
| `S031-E7` | Receipt target serialization round-trips exact non-UTF identity through tagged hexadecimal. Credential read allocations are non-clonable/zeroizing, read and receipt debug surfaces omit both the seeded secret and its generation, error display omits generations, and automatic traces use `[REDACTED]`; state traces retain exact resource/generation/class/state fields. | Pass |
| `S031-E8` | The session adapter, first line-REPL save, TUI save/list/startup paths, and session-state V1 migration tests execute the real filesystem bridge. Session files remain valid JSON at mode `0600`; a linked parent cannot create an outside file. | Pass |
| `S031-E9` | Unit and public path-validation suites exercise a real linked parent and require the exact offending component while retaining lexical/system-root diagnostics. Documentation and code explicitly deny that the returned path is an authority capability. | Pass |
| `S031-E10` | The non-Unix public contract test and Windows GNU cross-target build prove the implementation fails closed instead of compiling a path fallback. This is compile evidence only, not Windows runtime containment evidence. | Pass with the stated platform limit |

## Verification record

Every Cargo compilation used `CARGO_BUILD_JOBS=1`; every test command used
`--test-threads=1`.

- `cargo fmt --all -- --check` and `git diff --check` — pass.
- `CARGO_BUILD_JOBS=1 cargo check --locked --all-features --all-targets` —
  pass on Linux.
- `CARGO_BUILD_JOBS=1 cargo clippy --locked --all-features --all-targets -- -D warnings`
  — pass with the repository's strict lint profile.
- `CARGO_BUILD_JOBS=1 cargo test --quiet --locked --all-features --all-targets -- --test-threads=1`
  — pass for the complete repository: 2,647 active library tests, 228 binary
  tests, and every integration/all-target test binary; zero failures. The one
  ignored library entry is the subprocess-only crash worker, which the active
  recovery test invokes twice and requires to exit with status 91. Existing
  explicit external/browser ignored cases in integration suites remained
  ignored.
- Focused gates passed for persistence unit tests (32 active plus one
  subprocess-only worker), the public persistence contract (4), file-error
  compatibility (8), line-REPL session behavior (10), session-state migration
  (8), path validation (12), and file-error/output-style compatibility (24),
  plus the TUI save/list regressions.
- `CARGO_BUILD_JOBS=1 cargo check --locked --all-features --all-targets --target x86_64-pc-windows-gnu`
  — pass for the fail-closed platform surface. The remaining warnings are
  pre-existing Windows-only unused/dead-code findings outside the S-031 diff;
  the final S-031 and changed path-validator files add no cross-target warning.
- `cargo miri --version` — unavailable because Miri is not installed for the
  active stable toolchain. This is recorded as unavailable, not a pass. Unsafe
  syscall regions retain explicit safety invariants and are exercised through
  real descriptor, FIFO, link, race, crash, and process tests.
- `RUSTDOCFLAGS='-D warnings' CARGO_BUILD_JOBS=1 cargo doc --locked --all-features --no-deps`
  — failed on the repository's pre-existing private/broken intra-doc links and
  invalid HTML tags outside S-031. No S-031 item appeared in the failures;
  Crosslink #1045 tracks the independent repository-wide repair without
  weakening warnings.

## Unresolved risks and queues

- S-088 is still planned, so no honest artifact-bound alternate-model VDD
  receipt exists for `S031-G1`. Queue the exact digest above for retrospective
  verification using the same harness, guardrails, reality grounding, and
  capabilities. Any source/test change invalidates the queued generation.
- The Windows backend and supported-platform startup negotiation remain S-036.
  The Windows check above proves type/feature compilation and fail-closed
  behavior only; it is not runtime evidence for reparse containment, handle
  identity, ACLs, replacement, or directory durability. This host also cannot
  supply macOS/BSD runtime filesystem evidence.
- POSIX `flock` is advisory. Generation exclusion is guaranteed only when all
  writers for one target use this API. A deliberate same-user process can
  bypass advisory locking and race any userspace implementation; the S-019
  sandbox/control-path mask and host process policy remain the authority
  against that peer. Name/inode checks narrow and detect substitution but do
  not pretend to revoke the operating-system user's ambient power.
- The session JSON adapter preserves current behavior but observes the expected
  generation internally, so it cannot give a legacy caller a multi-step stale
  snapshot contract. Current CLI/TUI directory bootstrap still uses
  path-based `create_dir_all`. S-037 owns secure store bootstrap, proposed-state
  validation, atomic session mutation/finalization, and explicit recovery
  across the complete session transaction.
- This slice supplies the common storage primitive; it does not claim every
  existing persistence surface has migrated. Session/migration transactions,
  memory, plugins, MCP OAuth, initialization, cron, and VDD/evidence remain in
  their named dependent W15 slices. The crate-private rename helper remains
  greppable and explicitly non-durable until those store-specific migrations.
- Reads have per-file bounds and zeroize the owned source buffer, but a caller
  can deliberately copy bytes while inside `expose_bytes`; parsers and external
  libraries may also allocate. Store adapters must keep that exposure bounded
  and typed. Aggregate store quotas and transaction-level admission remain the
  responsibility of their owning slices.
- The synchronous lock wait is bounded at two seconds, but async callers must
  still isolate it from executor worker threads. Hardware/filesystem behavior
  ultimately defines what a successful `fsync` guarantees; the receipt records
  the syscall boundary rather than overclaiming protection from defective
  storage firmware.

No new remediation slice was added. The only newly discovered independent
maintenance item is the repository rustdoc gate tracked by Crosslink #1045.

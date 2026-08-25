# S-036: Provide cross-platform secure file capabilities

Status: Implemented and verified; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-035
Workstreams: W15
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace the intentional Windows failure with equivalent containment and race-resistant semantics on every supported platform.

## Implementation boundary

- Define platform-neutral filesystem capability contracts and implement Windows handle/reparse-point containment alongside Unix descriptor paths.
- Feature-detect unavailable primitives and fail with an honest platform capability state rather than compile-time product overclaim.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- The same containment, symlink/reparse, file-type, owner/permission, snapshot, and atomic-write conformance suite passes on supported platforms.
- Unsupported environments are rejected at startup/capability registration rather than during ordinary file use.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Added a shared Windows filesystem primitive layer built on pinned directory
  handles and component-by-component `NtCreateFile` traversal. Each component
  is opened without processing reparse points, then checked for disk-object
  type, directory/regular-file type, reparse attributes, hard-link count where
  applicable, and stable volume/file identity. UNC and device-namespace roots
  are rejected during capability construction because the publication contract
  cannot be guaranteed consistently there.
- Made `ToolRunContext` pin Windows read and write roots during run creation.
  File reads, edits, writes, notebook transactions, host-control files, IDE
  buffer validation, bounded discovery, and private run-temporary storage now
  use the same capability boundary as Unix. Platforms without either backend
  fail during run construction instead of deferring the failure to an ordinary
  file operation.
- Added a Windows `PersistentStorage` backend preserving the S-031 contract:
  bounded typed reads, expected SHA-256 generations, owner/ACL and regular-file
  validation, private lock/stage sidecars, bounded `LockFileEx` exclusion,
  synchronized staging, handle-relative publication, directory synchronization,
  and explicit `Unchanged`, `CommittedDurable`,
  `PublishedDurabilityUncertain`, and `Recovered` receipts.
- Added Windows permission handling for private session state, credential state,
  persistence sidecars, and run-temporary roots. Private objects receive an
  explicit protected DACL for the current user, SYSTEM, and administrators;
  existing roots and leaves reject an unexpected owner, null DACL, or effective
  broad mutation rights. General file-tool replacements preserve the prior
  DACL, while new workspace files inherit their authorized parent policy.
- Made protected provider credentials and the legacy session JSON adapter use
  the descriptor-safe store on Windows. Root identity serialization retains the
  complete 128-bit Windows file identifier with a compatibility default for
  receipts produced before this field existed.
- Kept directory discovery bounded while native directory records are decoded;
  Windows no longer accumulates an unbounded intermediate entry vector before
  applying the S-033 entry/name limits. Directory entries classified as devices
  or reparse points remain visible only as non-traversable `Other` entries.
- Extended the shared persistence, file-tool, notebook, credential, and private
  session tests to Windows. The Windows workflow now runs the real runtime
  contracts for reparse containment, stale/concurrent writers, atomic
  create/replace, interruption cleanup, uncertain-durability recovery, private
  ACLs, and file-tool lifecycle behavior rather than treating cross-compilation
  as runtime proof.

The existing Unix descriptor and atomic-persistence implementations were not
removed or weakened.

## Architecture decision

The selected Windows design mirrors the authority model of the Unix backend:

`host-selected root` → pinned root handle → no-reparse component handles →
bounded observation/generation → exclusive staged handle → handle-relative
rename → directory flush/typed durability state.

The rejected alternative was to use canonicalized Win32 path strings followed
by ordinary `OpenOptions`, `rename`, or `replace_file`. That would reintroduce
the parent reparse race S-019 and S-031 removed and would make a successful
precheck look like continuing authority. A third-party capability filesystem
crate was also unnecessary: `windows-sys` was already present, and the small
native layer keeps handle ownership, access masks, and failure translation
visible for review.

The implementation intentionally does not claim a cross-process compare-and-
swap primitive that Windows does not provide for arbitrary workspace files.
All in-process file-tool writers are serialized by bounded striped locks and
revalidate the visible digest immediately before publication. Persistent stores
add a fixed per-target OS lock, so every cooperating OpenClaudia writer receives
the exact stale-generation contract. Host process/sandbox policy remains the
authority against a deliberate same-user process that bypasses both APIs.

## Artifact generation

- Generation: `S036-G3`, superseding the source/test generations invalidated by
  the hosted-Windows TokenOwner and native rename repairs.
- Baseline commit: `c4bd8decf7982798769f9df6b5a68f419977e110`.
- Verified implementation commit: `4bc7ce345147ac1c342d891ed654f626537a9645`.
- Source/test artifact digest: SHA-256
  `a788c459d8a0cd82f3f8a231e7a21bf1816d4320d67afb86905f35ef925b4be2`
  over `git diff --binary c4bd8decf7982798769f9df6b5a68f419977e110..4bc7ce345147ac1c342d891ed654f626537a9645 -- src tests`
  after the skeptical implementation/test review and both native Windows
  repairs. Any source or test change invalidates this generation.
- Scope: fourteen source/test paths; 3,484 insertions and 105 deletions. The
  complete delivery also updates the Windows dependency features, authoritative
  runner matrix, and this handoff document.

## Acceptance evidence

| Receipt | Evidence | Result |
| --- | --- | --- |
| `S036-E1` | Rust 1.98 Windows GNU all-target/all-feature compilation covers every library, binary, unit-test, and integration-test target with the new Windows backend enabled. | Pass |
| `S036-E2` | Shared descriptor persistence (4), file-tool lifecycle (9), and session filesystem capability (2) suites execute the existing Unix backend after the shared-contract changes. Parent links preserve the outside sentinel, stale writers conflict, deep creation works, and private temp links cannot escape. | Pass |
| `S036-E3` | The complete locked Linux all-target/all-feature suite runs serialized: 2,937 active library tests and 227 binary tests pass, followed by every integration target with zero failures. The one ignored library entry is the subprocess-only persistence crash worker, which its active recovery test invokes. | Pass |
| `S036-E4` | Strict Linux all-target/all-feature Clippy passes with `-D warnings`. Windows Clippy identifies no S-036-local finding after the FFI/alignment and bounded-enumeration review; independent pre-existing Windows lint debt remains tracked by Crosslink #1099 without weakening lint settings. | Pass for changed surface |
| `S036-E5` | PR #66 run `32843208084` executes shared persistence, session capability, file-tool, persistence interruption/validation, notebook reparse/interruption, credential ACL, and session-adapter contracts on `windows-latest` at exact commit `4bc7ce345147ac1c342d891ed654f626537a9645`. All Windows runtime steps and the enclosing job pass. | Pass |
| `S036-E6` | No S-088 verifier is operational, so no alternate-model receipt is represented as present. `S036-G3` and its exact digest are queued for future verification with the canonical harness and guardrails. | Pending S-088 by design |

## Verification record

Every Cargo command used Rust `1.98.0`, `CARGO_BUILD_JOBS=4`, and no overlapping
OpenClaudia Cargo invocation. Test commands used `--test-threads=1`.

- `cargo fmt --all` followed by `cargo fmt --all -- --check` — pass.
- `cargo check --locked --target x86_64-pc-windows-gnu --all-targets --all-features`
  — pass. Remaining messages are pre-existing Windows-only warning debt under
  Crosslink #1099; no S-036 backend file emits a warning.
- `cargo clippy --locked --target x86_64-pc-windows-gnu --lib --all-features`
  — the changed S-036 surface is clean after review; the command remains
  repository-red because of #1099 findings in unrelated Windows-only paths.
- `cargo test --locked --all-features --test descriptor_safe_persistence_e2e
  --test session_filesystem_capabilities_e2e --test file_tools_integration --
  --test-threads=1` — pass, 15 tests.
- `cargo check --locked --all-targets --all-features` — pass.
- `cargo clippy --locked --all-targets --all-features -- -D warnings` — pass.
- `cargo test --quiet --locked --all-targets --all-features --
  --test-threads=1` — pass for the complete repository, with zero failures.
- `git diff --check` — pass.
- PR #66 run `32843208084` at `4bc7ce345147ac1c342d891ed654f626537a9645`
  — pass: repository policy, Rust 1.98 MSRV, Linux, macOS, and Windows jobs all
  completed successfully. The Windows job passed its all-target/all-feature
  check, platform fail-closed test, and every Windows-specific runtime contract.

## Unresolved risks and queues

- Windows filesystems and storage drivers ultimately define what a successful
  directory flush guarantees. Persistent storage reports a failed flush as
  `PublishedDurabilityUncertain` and reconciles it on retry. The workspace
  file-tool API has no durability receipt surface, so it logs a warning after
  publication rather than falsely converting visible success into an unchanged
  error.
- Arbitrary non-cooperating same-user processes can bypass advisory locks or
  mutate names between a final observation and replacement. This is the same
  ambient-authority boundary documented by S-031: OpenClaudia writers are
  generation-bound and serialized, while sandbox/process policy controls hostile
  peers. No stronger arbitrary-file Windows compare-and-swap primitive is
  claimed.
- ACL validation proves current-user ownership and rejects effective mutation
  rights for the broad built-in Everyone, Authenticated Users, and Users groups.
  Private OpenClaudia objects use an explicit protected DACL. Hosts with custom
  enterprise group policy remain responsible for authorizing the selected
  workspace root.
- UNC shares and Windows device namespaces fail at capability registration
  because consistent handle-relative rename/durability behavior is unavailable
  across redirectors. Local drive-backed Windows roots are the supported S-036
  contract.
- S-088 remains planned. Queue `S036-G1` for a future artifact-bound verifier
  receipt using the same harness, guardrails, reality grounding, capabilities,
  and an enforced alternate model. No receipt is fabricated or required to
  merge this slice.

No new remediation slice was added. Crosslink #1031 is resolved by the Windows
`SecureDirectory` backend consuming its pinned context; #1099 remains open for
the independent Windows lint backlog.

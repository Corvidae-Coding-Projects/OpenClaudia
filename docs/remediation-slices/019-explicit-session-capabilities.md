# S-019: Eliminate ambient session capabilities

Status: Complete
Effort: Medium
Primary findings: F-033
Workstreams: W2, W15
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-018](./018-non-bypassable-host-safety-policy.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Require explicit workspace, filesystem, process, network, and secret capabilities instead of granting ambient CWD access when context is missing.

## Implementation boundary

- Make capability-bearing run context mandatory at every tool and helper boundary and remove thread/process-global fallback identity.
- Return typed unavailable errors for absent resources and bind descriptor roots and scratch space to the run generation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Calling any tool without a valid run capability fails closed and cannot read or write the process CWD.
- Concurrent sessions with different roots cannot observe or mutate each other's files, processes, environment, or cancellation state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- `ToolRunContext` is now the required capability object at registry, executor,
  hook, MCP, VDD, subagent, frontend, and leaf-helper boundaries. The former
  `current_context`, `SessionIdGuard`, todo thread-local identity, implicit
  `__default__` session, process-CWD fallback, and globally installable Bash
  path-constraint slot are gone.
- The host composition boundary must explicitly decide workspace access,
  read-only/read-write roots, process, network, secrets, environment grants,
  provider identity, actor role, process owner, and working directory before a
  run can be built. Each successful build pins root descriptors and private
  scratch space to a unique capability generation and binds a digest of the
  complete manifest into the canonical `RunDescriptor`.
- Read-only runs carry no workspace-write grant or writable project handle.
  Missing run context or a missing filesystem/process/network/secret resource
  returns a typed unavailable result before any effect. Capability-backed
  filesystem traversal retains the exact authorizing run instead of
  rediscovering policy from ambient state.
- Background shells, active sandbox processes, LSP open-file state, file-read
  markers, MCP managers, subagent transcripts/agents, todo lists, cancellation,
  and lifecycle cleanup are addressed by exact run/session ownership as
  appropriate to their persistence contract. Cross-run observe, mutate, kill,
  resume, or cancel operations fail closed.
- Child environment and executable lookup come from the immutable run
  snapshot. MCP secret environment values are captured at composition time,
  included by digest in the capability manifest, require secret authority, and
  cannot be changed for an existing run by later host-environment mutation.
- Project skill discovery is rooted in the exact run project/working directory.
  A run cannot discover a sibling run's project skills through process CWD.
  Prompt catalogs, slash-command skill lookup, and model-dispatched skill
  execution use the same exact run boundary. Context-free prompt compatibility
  APIs expose only host-managed and user layers; a display-only CWD string
  cannot authorize repository content.
- Plan-mode admission now uses the immutable actor role. The former
  `AgentContextGuard` test-only thread-local never existed on the production
  subagent path and was removed; real registry dispatch admits frontends and
  rejects worker runs, including under concurrency.
- Legacy `@file` expansion, shell/editor launches, quality gates, `/find`,
  `/doctor`, `/mcp`, `/add-dir`, `/init`, `/branch`, and `/teleport` now resolve
  against the exact frontend run. Plugin discovery, plugin MCP environment
  expansion, and approval receipts/managers are also generation-bound rather
  than rediscovering process CWD, environment, or cache identity.
- Agent-visible filesystem helpers keep `.openclaudia` masked except for one
  exact, non-overwriting session plan file carried in the capability manifest.
  Host-owned initialization and branch snapshots use a separate pinned
  host-control descriptor path, so control storage remains unavailable to
  ordinary agent file tools while still being rooted in the active run.
- Frontend session/provider transitions replace their run generation and retire
  the old one. Retirement cancels the exact run tree and cleans up its sandbox
  processes, background shells, and background agents without affecting a
  sibling run. TUI permission-bypass changes likewise rebuild the manager for
  the active generation instead of retaining stale approval identity.

## Artifact generation

- Generation: `S019-G1`.
- Baseline commit: `08f4ef2747d8d9a9af30fcfa0bf3b769175eccc6`.
- Source/test artifact digest: SHA-256
  `642c773eb89a73bc093003cad2062c75d9d3529884190890c8323bf1e7d89fd8`
  over `git diff --cached --binary HEAD -- src tests` after formatting,
  strict Clippy repair, and explicit staging. The cached-tree form is required
  so the two newly added test files are part of the receipt.
- Scope: 71 source files and 46 test files; 11,134 insertions and 5,423
  deletions. The obsolete
  `tests/path_constraints_global_slot_e2e.rs` was replaced by
  `tests/path_constraints_run_scoped_e2e.rs`; the new cross-subsystem adversarial
  suite is `tests/session_capability_isolation_e2e.rs`.

### S019-G2 hosted-runner portability repair

- Baseline commit: `0316e0f6f8fe725bdcc6c8432b675b465a212f5a` (`S019-G1`).
- Source/test artifact digest: SHA-256
  `ea8e1aefafdbcc7012937b470c06184853dc0ae8ca414571ae8484588a5bf077`
  over `git diff --binary 0316e0f6f8fe725bdcc6c8432b675b465a212f5a -- src tests`
  after formatting and the complete local verification record below.
- Scope: four source files and two test files; 117 insertions and 15
  deletions. `ToolRunContext` now binds the composition-time host-home
  snapshot into its manifest and carries it into frontend, subagent, and MCP
  child generations. Linux sandbox construction uses that immutable snapshot
  for its narrow read-only Cargo/Rustup mounts instead of rediscovering the
  process home during tool execution.
- The integration fixture now distinguishes deterministic test runs from a
  deliberately host-toolchain-bound run. Its probe requires the exact Cargo
  executable resolved by the immutable run PATH, verifies credentials are
  absent both from private `HOME` and the mounted Cargo home, and tests the
  actual resolved binary directory for read-only confinement.

## Acceptance evidence

| Receipt | Evidence | Result |
| --- | --- | --- |
| `S019-E1` | `missing_run_fails_closed_without_reading_or_writing_cwd` dispatches read/write calls through the context-free compatibility entry, asserts `ToolFailureCode::Unavailable`, proves secret bytes are absent, and proves no file was created. | Pass |
| `S019-E2` | `absent_resource_grants_return_typed_unavailable_results` covers write, process, PDF helper process, MCP, network, subagent provider access, and direct secret-resource admission on one restricted run. `read_only_workspace_omits_write_capability_and_handle` verifies the descriptor and pinned handles. | Pass |
| `S019-E3` | `concurrent_roots_and_environment_grants_do_not_cross` runs two sessions simultaneously, permits own-root writes, rejects both cross reads/writes, and observes only each run's environment grant. | Pass |
| `S019-E4` | `background_processes_are_exact_run_scoped`, `cancellation_and_descriptor_bindings_are_run_scoped`, and the background-agent/transcript suites prove foreign output, kill, cancellation, resume, and cleanup cannot cross run ownership. Descriptor generation/root equality and distinct manifest digests are asserted directly. | Pass |
| `S019-E5` | `project_skill_lookup_is_bound_to_the_exact_run_root`, the 14-test skill dispatch suite, and the 16-test skill execution suite prove canonical project discovery without CWD mutation or sibling visibility. | Pass |
| `S019-E6` | `mcp_secret_environment_validation_uses_only_the_run_snapshot` and `mcp_secret_environment_is_generation_bound_and_requires_secret_authority` prove exact name/value snapshotting, secret gating, and post-build host mutation resistance. | Pass |
| `S019-E7` | The 3-test run-scoped path-constraint suite proves own-root/private-temp admission, foreign-root denial, and concurrent non-replaceability. The 11-test sandbox escape suite independently proves lexical path denial and runtime host-mount, kernel, network, inherited-FD, syscall, and resource-limit confinement. | Pass |
| `S019-E8` | The 15-test subagent plan-mode suite uses real registry dispatch to prove frontend admission, worker denial, and concurrent actor-role isolation; no test-only ambient guard participates. | Pass |
| `S019-E9` | `prompt_skill_catalog_is_concurrently_bound_to_each_run_root`, slash-command skill tests, and the context-free prompt compatibility assertion prove project skill metadata cannot cross roots or be authorized by a CWD display string. | Pass |
| `S019-E10` | Legacy attachment and shell tests prove `@file` reads, child CWD, environment, and executable lookup use the exact run. Plugin MCP snapshot and approval-binding tests prove later ambient CWD/environment/cache changes cannot alter an existing generation. | Pass |
| `S019-E11` | `entering_plan_mode_creates_only_the_exact_session_plan_capability` and `project_initialization_is_exact_run_scoped_and_control_state_stays_masked` prove the one-file plan exception, sibling/control-file masking, secure non-overwrite, and exact-root host initialization. Branch snapshot cross-root tests cover the same host-control boundary. | Pass |
| `S019-E12` | `retiring_one_run_cancels_only_its_owned_lifecycle_resources`, frontend transition tests, and TUI provider-switch tests prove replacement generations retire exact owned state while sibling runs remain live. | Pass |
| `S019-E13` | `derived_frontend_session_narrows_roots_and_never_rediscovers_host_grants` proves the host-home/toolchain snapshot survives derivation. `toolchain_mounts_are_read_only_and_exclude_user_credentials` resolves Cargo through the run-bound PATH, requires the sandbox to use that exact executable, checks both credential locations are absent, and attempts a write in the resolved Cargo binary directory. | Pass |

## Verification record

All Cargo invocations were constrained with `CARGO_BUILD_JOBS=1`; all test
commands used `--test-threads=1`.

- `cargo fmt --all -- --check` — pass.
- `git diff --check` — pass.
- `CARGO_BUILD_JOBS=1 cargo check --workspace --all-targets --all-features` —
  pass.
- `CARGO_BUILD_JOBS=1 cargo clippy --workspace --all-targets --all-features -- -D warnings`
  — pass with the repository's strict lint profile.
- `CARGO_BUILD_JOBS=1 cargo test --workspace --all-features -- --test-threads=1`
  — pass for the complete workspace: 2,646 library tests, 226 binary tests,
  every integration-test binary, and doc tests. Only tests explicitly marked
  ignored for external network/browser requirements remained ignored.
- Focused gates also passed for `session_capability_isolation_e2e` (11),
  `path_constraints_run_scoped_e2e` (3), `sandbox_escape_e2e` (11),
  `todo_write_dispatch_validation_e2e` (25), `todo_session_isolation_e2e`
  (14), `skill_dispatch_validation_e2e` (14), `skill_execute_e2e` (16), and
  `subagent_plan_mode_e2e` (15).

The full gates exposed four misleading legacy fixtures rather than production
regressions. Sandbox probes used literal host paths now rejected before process
launch; they were rewritten to assert lexical denial separately and then
exercise the OS sandbox at runtime. Todo dispatch minted a new run for each
call while claiming same-session persistence; it now reuses one explicit
frontend run, while the separate isolation suite proves foreign-run denial.
The LSP assertion now requires the run-bound PATH diagnostic. Finally, the ACP
session fixture formerly injected an unrestricted manager directly; after
managers became run-derived, it accidentally fell back to an impossible
headless prompt. Its configuration now explicitly disables prompts for local
routing/cancellation tests, while hard host-safety and exact-run binding remain
active and separate permission-gate tests retain deny-by-default coverage.

The first hosted `S019-G1` run (`32284515796`) passed formatting, strict
Clippy, and the macOS and Windows fail-closed jobs, then exposed a Linux-only
false portability assumption in the Cargo toolchain probe: its explicit test
run used the deterministic system PATH, so it passed locally only because
`/usr/bin/cargo` existed and failed where GitHub installed Cargo under the
runner home. Investigation also found that Linux sandbox construction still
read the ambient home at execution time even though PATH was generation-bound.
`S019-G2` fixes both causes rather than weakening the probe.

The `S019-G2` gates, all constrained with `CARGO_BUILD_JOBS=1` and one test
thread where applicable, passed:

- `cargo test --lib tools::security::tests::derived_frontend_session_narrows_roots_and_never_rediscovers_host_grants -- --exact --test-threads=1`;
- the exact Cargo toolchain confinement probe and all 11
  `sandbox_escape_e2e` tests;
- `cargo check --workspace --all-targets --all-features`;
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`;
- `cargo test --workspace --all-features -- --test-threads=1`, covering all
  library, binary, integration, and doc-test targets with only the repository's
  explicitly ignored external-network/browser cases remaining ignored; and
- `cargo fmt --all -- --check` plus `git diff --check`.

Hosted confirmation of `S019-G2` is intentionally recorded on Crosslink issue
`#1027` after publication rather than predicted in this artifact receipt.

## Unresolved risks and queues

- S-088 is still planned, so an artifact-bound alternate-model VDD receipt
  cannot yet be produced without pretending that today's VDD path has the
  required verifier identity and authority. Queue `S019-G2` and its
  source/test digest above for retrospective VDD as soon as S-088 is
  operational; any artifact change invalidates that queued generation.
- Crosslink issue #1026 records a least-privilege follow-up for S-064/S-066:
  MCP resource handlers conservatively require both Process and Network before
  the selected server transport is known. Transport-specific admission should
  require Process for stdio and Network for HTTP while remaining fail closed
  for missing or stale transport metadata.
- Durable canonical trace persistence remains owned by S-031/S-037. This slice
  binds capability generation and manifest digest into the runtime descriptor
  and tests them directly; it does not overclaim that the current tracing sink
  is a durable audit store.
- Project/user skill trust and activation policy remains S-015. Ambient Git/GH
  slash operations and the long-term typed slash-command registry remain in
  S-074/S-075 (with commit workflow hardening in S-043); S-019 binds the
  file/prompt/process paths required for capability isolation without claiming
  those later command-system outcomes.
- Secret zeroization/redacting storage hardening, cross-platform secure-file
  backends, bounded lifecycle stores, and typed file snapshots remain in their
  existing remediation slices. S-019 establishes explicit authority and
  isolation but does not claim those parent-workstream outcomes.

No new remediation slice was added. The only newly discovered work is tracked
as #1026 against the existing S-064/S-066 boundaries.

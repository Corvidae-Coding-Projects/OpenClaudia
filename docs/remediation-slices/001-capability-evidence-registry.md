# S-001: Build the capability evidence registry

Status: Implemented/adversarially reviewed with VDD pending
Effort: Medium
Primary findings: F-008, F-142, F-143
Workstreams: W0, W13
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace documentation strings, issue closure, and structural test counts as readiness evidence with a typed capability registry backed by executable scenarios.

## Implementation boundary

- Define capability, maturity, entrypoint, required-effect, trace, and evidence records, including explicit unsupported and experimental states.
- Move user-facing capability tables to registry-derived data and create a reviewed multi-trial evaluation corpus whose graders inspect final environment state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A capability cannot be marked operational without linked executable receipts for its supported entrypoints and failure modes.
- Changing documentation text alone cannot satisfy a capability test, and the evaluation corpus has an independent quality-review record.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Delivered architecture

- `src/capability_evidence.rs` defines strict typed records for capability
  maturity, entrypoints, reachability, required effects, provenance, evidence,
  executable receipts, trace contracts, evaluation scenarios, final-state
  graders, and corpus quality review. Maturity distinguishes `unsupported`,
  `experimental`, `schema-only`, `unreachable`, `partial`, and `operational`.
- Operational validation fails closed unless every reachable entrypoint has
  reviewed multi-trial success receipts and receipts for every declared failure
  mode. `must_occur` effects require a grader-derived occurrence proof,
  `must_not_occur` effects require an absence proof in every linked scenario,
  and `may_occur` is disclosure-only rather than promotion evidence. All
  final-state, effect-observation, trace, corpus, and independent-review digests
  must agree.
- The grader accepts only bounded normal relative paths beneath a disposable
  evaluation root, rejects symlinks/non-regular files, limits paths, file bytes,
  trace events, trials, artifact bytes, collection counts, and string sizes,
  and hashes state read back after execution. Model output and documentation
  prose are not grader inputs.
- Trace receipts hash a schema-versioned envelope containing the exact scenario
  identity, typed terminal outcome (including rejection code), and ordered
  events. The grader itself appends final-environment inspection after reading
  state, so rejection traces cannot be relabeled or satisfied by a generic
  `RegistryRejected` event.
- Effect observations are typed and proof-bound to a verified final file,
  forbidden-path absence, typed trace event, or completed grader execution.
  The internal operational capability also requires every scenario to prove
  that no `release/operational.json` projection was published.
- `capabilities/registry.json` is the canonical release-data artifact. The
  generated `docs/binary-capability-matrix.md` is a deterministic projection of
  validated user-facing records. Current binary routes remain honestly
  `partial`, `experimental`, or `unsupported`; implementing the registry does
  not promote them.
- `capabilities/evaluation-corpus.json` runs one success and two adversarial
  failure scenarios three times each. The negative scenarios prove a marketing
  document cannot promote a capability and an operational record cannot omit a
  declared failure receipt. Each scenario declares `in_process_no_child`;
  concurrent or child-process evaluation requires descriptor-safe traversal
  before admission. `capabilities/evaluation-corpus-review.json` records the
  independent primary review of the exact frozen corpus digest and all six
  required review dimensions.

The credible alternative was a Rust-only constant table with Markdown
substring tests. It was rejected because it is harder to artifact-bind and
review independently, cannot serve downstream health/release tooling as strict
versioned data, and repeats the circular documentation evidence identified in
F-142.

## Reviewed artifact generation

Schema/generation 1 artifacts currently hash to:

| Artifact | SHA-256 |
|---|---|
| `capabilities/registry.json` | `da036dbd7c7533d9cc65ff83a29476eb83e3ffe69cd002d535349473310eaa69` |
| `capabilities/evaluation-corpus.json` | `1f8b05b210fe641ebdfcce22b4af7fe20570e6b88ca1dee037ccd1182ab31304` |
| `capabilities/evaluation-corpus-review.json` | `af3aec5046d3fdc6c4138f96d5de0667610c8b68c32967705ab183371372f2b4` |
| `docs/binary-capability-matrix.md` | `5720c3b11c874f595ba18537e63f16e5fcfbaba7a9c765b67b8580fc50a7e502` |

The approved review and all evidence records bind the exact corpus digest
above. Independent reviewer `primary-orchestrator-6vw9` approved the frozen
registry/corpus generation after inspecting the typed proof contract, graders,
trace identity, bounds, executor, adversarial tests, projection, restored
documentation checks, and stated isolation limits.

## Test skepticism and verification state

- Removed the old binary-matrix test that accepted `works:`/`unsupported:`
  prose shapes as readiness evidence. Independent review correctly required all
  other README/model/slash/tool/web/worktree accuracy tests to remain until
  their respective tables gain deterministic runtime-owned projections; those
  tests were restored unchanged.
- The replacement integration suite executes nine isolated trials and compares
  their final-environment, typed-effect, and versioned trace receipts with the
  registry. It also rejects altered corpus-review digests, self-review identity,
  relabeled/tampered traces, fabricated and missing effect observations,
  forbidden effects, symlinked final state, and oversized artifacts,
  collections, and strings.
- JSON syntax, embedded digest consistency, `git diff --check`, exact baseline,
  branch/session/lock, and zero-byte projected Crosslink rules were inspected.

### Cargo command record

Every compilation used `CARGO_BUILD_JOBS=1`; every Rust test used
`-- --test-threads=1`. Commands were serialized under the global queue, which
was explicitly released after the Windows gate. No `cargo clean` ran.

| Command | Result |
|---|---|
| `cargo fmt --all` | Passed with no output; repeated after the Clippy corrections and passed. |
| `cargo fmt --all -- --check` | Passed with no output; corrective repeat also passed. |
| `cargo test --locked --all-features --test capability_evidence_e2e -- --test-threads=1` | Passed: 11 passed, 0 failed, 0 ignored, 0 measured, 0 filtered; 0.04s tests after the 4m06s initial single-job build. The corpus test executed 3 scenarios × 3 fresh trials. |
| `cargo test --locked --all-features --test cli_exit_status_e2e -- --test-threads=1` | Passed: 60 passed, 0 failed, 0 ignored, 0 measured, 0 filtered; 2.00s. |
| `cargo check --locked --all-features --all-targets` | Passed in 2m33s. |
| `cargo clippy --locked --all-features --all-targets -- -D warnings` | Initial run failed on exactly three new diagnostics: `needless_borrow`, `match_like_matches_macro`, and `collapsible_str_replace`. The mechanical root-cause corrections did not alter artifacts or behavior. Strict rerun passed with 0 warnings in 1m21s. |
| `cargo test --locked --all-features --all-targets -- --test-threads=1` | Library harness failed: 2641 passed, 6 failed, 1 ignored, 0 measured, 0 filtered; 54.69s after a 4m43s build. All six failures are the existing worktree-test defect tracked by #1055; Cargo stopped before later targets. A focused reproduction of `test_get_current_branch_at_cwd` also failed with 0 passed, 1 failed, 2647 filtered. No S-001 test failed. |
| `cargo check --locked --target x86_64-pc-windows-gnu --all-features --all-targets` | Passed in 3m31s. It emitted 28 pre-existing target-conditional warning diagnostics and no warning in an S-001 path. |

The six #1055 failures were
`enter_and_exit_worktree_bump_cwd_cache_generation_624`,
`enter_worktree_duplicate_call_is_no_op_624`,
`exit_worktree_clean_worktree_exits_without_discard_flag_623`,
`exit_worktree_refuses_to_destroy_dirty_worktree_without_discard_623`,
`test_get_current_branch_at_cwd`, and `test_list_worktrees`. The focused
reproduction confirmed the defect independently of S-001, so this slice did
not edit worktree or sandbox code.

The Windows warnings were emitted by existing conditional code: library
`SecureDirectory.context` (1); `session_filesystem_capabilities_e2e` (3);
`legacy_rule_injector_removed_e2e` (3); `hooks_permissions_e2e` (2);
`end_to_end_secret_redaction_e2e` (2); the `openclaudia` binary test (1);
`session_capability_isolation_e2e` (4); `bash_integration` (1);
`file_tools_race_e2e` (1); and the library-test target (10). This is an
available-toolchain compile pass, not Windows runtime-containment evidence.

## Scope and unresolved risks

- `src/lib.rs` is the only likely shared projection point; no overlap was found
  with the concurrent S-004 migration or S-005 configuration implementation.
  S-006 and S-012 are downstream consumers of this registry, not part of this
  slice.
- The first corpus intentionally proves only the S-001 registry/release
  boundary. It does not claim that TUI, proxy, ACP, doctor, provider, tool, or
  other runtime capabilities are operational.
- The first independent review returned `changes required`: effect IDs were
  self-asserted rather than observed, trace hashes omitted scenario/schema and
  rejection identity, source artifacts were unbounded, and the initial review
  identity was not independent. Those implementation defects were corrected,
  and the mandatory independent re-review passed for the frozen registry,
  corpus, and generated-matrix digests recorded above.
- Three deterministic trials prove repeatability only; they do not add
  stochastic model coverage. The path resolver also remains TOCTOU-prone under
  concurrent mutation, which is why this corpus admits only in-process,
  no-child actions. Descriptor-safe traversal is required before expanding
  that execution boundary.
- S-088 is still planned. Queue the final committed S-001 artifact generation
  for retrospective canonical VDD; this document does not claim local review or
  ordinary tests are a VDD receipt.
- The repository-wide all-target test gate remains red because of independent
  existing issue #1055. Focused S-001 acceptance, CLI regression, native
  all-target check, strict Clippy, and Windows cross-target compilation passed.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

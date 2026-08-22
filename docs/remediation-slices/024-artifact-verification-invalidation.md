# S-024: Invalidate verification after artifact changes

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Small
Primary findings: F-024
Workstreams: W4, W15, W28
Depends on: [S-023](./023-reality-evidence-boundary.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Bind verification freshness to exact artifacts and automatically invalidate it after relevant mutation.

## Implementation boundary

- Define artifact sets, digests/generations, dependency closure, verifier identity, and policy version on every receipt.
- Invalidate or supersede receipts atomically on writes, Git changes, task amendments, policy/model changes, and imported state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A one-byte relevant change makes the prior verification unusable for completion.
- Unrelated changes follow an explicit dependency policy, and races between verify and mutate cannot publish a fresh verdict.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Trusted evidence now carries a typed freshness stamp with shared workspace,
  task, model, guardrail-policy, imported-state, and policy-schema generations,
  plus task/model/policy digests. Verification provenance uses the new
  `GuardrailsQualityGateSnapshotV2` receipt; the previous direct-exec shape
  remains deserializable but cannot authorize a current verification claim.
- Workspace generations and pending mutation counts are coordinated by exact
  canonical project root across independent runs. Task, model, policy, and
  import state remain exact-run bindings. This prevents one run from issuing a
  verifier receipt while another run is mutating the same workspace.
- Canonical tool effects reserve freshness before execution. Workspace,
  external, and destructive effects advance the shared workspace generation;
  session mutations advance task state. Successful and typed-partial outcomes
  commit the reservation and invalidate all verifier receipts for the exact
  run. Rejected/pre-execution failures release it without claiming a change.
- Background Bash owns an additional mutation reservation until its child is
  reaped, rather than releasing freshness when the shell ID is returned. A
  wait failure deliberately retains the reservation fail-closed. The TUI `!`
  shell path is also covered, kills its child when the async owner is dropped,
  advances freshness after any executed outcome, and records command evidence
  against the post-execution generation.
- Every quality gate resolves and hashes its exact executable, captures a
  bounded deterministic project-source snapshot before execution, executes
  directly under the run capability, and captures the complete seed again.
  Any workspace, environment, model, policy, verifier, or generation change
  turns the result into a non-authoritative failure. Receipt append and final
  claim validation independently rehash the executable and live artifact set.
- The original versioned `ProjectSourceTreeV1` dependency policy hashes file type,
  relative path, permissions, byte length, regular-file contents, and symlink
  target for at most 100,000 entries / 1 GiB. It fails closed on special files,
  escaping/unresolved symlinks, excluded-subtree aliases, read races, and
  oversized trees. Root `.git`, `target`, `.openclaudia/reality-ledgers`,
  `.crosslink/.cache`, and `.crosslink/.hub-cache` are explicit unrelated
  VCS/runtime/build exclusions; tracked configuration and untracked source
  remain included.
- Post-integration maintenance issue #1057 advances the active policy and
  guardrail-policy generation to `ProjectSourceTreeV2`. V2 additionally
  excludes only the repository-root `.worktrees` control subtree, whose linked
  checkouts contain independent Git metadata and build caches. Nested paths
  such as `src/.worktrees` remain verified source. V1 remains deserializable,
  but its receipts cannot authorize a current claim under policy version 2.
- S-003 advances the active policy to `ProjectSourceTreeV3` and policy version
  3. V3 excludes only the fuzz package's declared runtime/build outputs:
  `fuzz/target`, `fuzz/artifacts`, `fuzz/coverage`, and non-`seed-*` corpus
  discoveries. Reviewed `fuzz/corpus/*/seed-*` files remain hashed evidence;
  V1 and V2 tags remain deserializable but cannot authorize a current claim.
- ACP, CLI chat, the TUI, pipeline streaming paths, and subagents now pass the
  model actually used for the turn into task observation, quality gates, and
  final validation. Model changes invalidate old verification before a new
  gate; immutable guardrail policy is hashed, and a policy/import transition
  requires a replacement run generation.
- Runtime-issued receipt state propagates verifier invalidation across every
  open ledger in the process. Reloaded or tampered persisted rows still lose
  verifier authority, and released run generations cannot be recreated by a
  late binding-only background observer.
- The skeptical full-suite review also found two pre-existing positive URL
  tests that depended on live public DNS. Their public-HTTPS policy fixtures
  now use a public IP literal without changing fail-closed production DNS
  behavior; Crosslink issue #1039 tracks deterministic injected-resolver
  coverage for the remaining hostname-specific tests.

## Architecture decision

Freshness is split between a shared workspace coordinator and exact-run
context:

`tool reservation` → shared pending workspace state → executed outcome →
generation advance → verifier invalidation.

`quality-gate seed` → direct verifier execution → identical post-seed → typed
receipt → live final revalidation.

The global mutex is intentionally held only while coordinating generations or
hashing a verifier snapshot. It serializes snapshot capture against every
managed mutation, including mutations from another run on the same workspace.
The verifier command itself runs without that lock; its post-seed must match
the pre-seed exactly, so a mutation during execution cannot publish a fresh
verdict. Run-specific task/model/policy changes are compared alongside the
shared workspace generation.

The artifact set is conservative and source-oriented rather than inferred from
one language's build graph. This makes the dependency rule deterministic for a
multi-language agent workspace and ensures a one-byte relevant change is
observable. Only enumerated machine-local VCS/runtime/build subtrees are
unrelated. Environment identity additionally binds the immutable capability
manifest, OS/architecture, working directory, granted environment, and
executable search path; verifier identity binds the check name, normalized
argv, resolved executable path, and executable digest.

Effective imported hook/policy state is immutable for a live run. Its import
generation is the capability generation; applying different imported state or
guardrail policy requires a replacement run, whose exact binding rejects all
old receipts. Merely changing an approval store does not retroactively change
the already-instantiated hook engine.

## Artifact generation

- Generation: `S024-G1`.
- Baseline commit: `5d9c8ef79476fde28ceb1e59c3122a6254c2434f`.
- Source/test artifact digest: SHA-256
  `77434909d5b684f8bb4281c4490743af489cc44475dcee24bf98f7dd762ffc19`
  over `git diff --cached --binary HEAD -- src tests` after formatting, strict
  Clippy, full serialized tests, skeptical review, and explicit staging. Any
  source/test artifact change invalidates it.
- Scope: shared workspace/run freshness coordination; immutable artifact,
  environment, verifier, model, task, policy, and import bindings; canonical
  and background mutation invalidation; live verification revalidation; and
  adversarial race/dependency tests.

## Acceptance evidence

| Receipt | Evidence | Result |
| --- | --- | --- |
| `S024-E1` | `one_byte_project_source_change_invalidates_prior_verification` changes exactly one byte after a passing gate and proves final validation rejects the old artifact binding. | Pass |
| `S024-E2` | `excluded_runtime_and_build_cache_changes_preserve_versioned_verification` changes one byte in both `target` and Crosslink hook cache, asserts policy/import/environment/verifier metadata, and proves enumerated unrelated caches do not stale source verification. | Pass |
| `S024-E3` | `task_model_and_policy_changes_stale_prior_verification_receipts` proves task amendment and model replacement invalidate exact-run receipts, while an immutable policy transition rejects the old receipt under its replacement run generation. | Pass |
| `S024-E4` | `background_bash_mutation_blocks_verification_until_reaped` starts a real delayed mutation in run A and proves run B on the same workspace cannot mint verifier evidence until the child is reaped and a new gate runs. | Pass |
| `S024-E5` | `spawn_shell_command_records_ledger_observation` exercises the TUI shell bypass, proves its workspace generation advances exactly once, and proves the command receipt binds the post-execution freshness stamp. | Pass |
| `S024-E6` | Existing exact-run reservation trace assertions, typed-partial Bash tests, cross-run proof rejection, persisted-row tampering, and arbitrary-shell non-verifier tests all pass with freshness enabled. | Pass |
| `S024-E7` | Full final validation rehashes the source artifact set and verifier executable; pre-snapshot direct-exec, persisted, or internally inconsistent receipts are rejected by construction and adversarial ledger tests. | Pass |

## Verification record

All Cargo compilation used `CARGO_BUILD_JOBS=1`; all tests used
`--test-threads=1` to respect host RAM limits.

- `cargo fmt --all -- --check` — pass.
- `git diff --check` — pass.
- `CARGO_BUILD_JOBS=1 cargo check --all-features --all-targets` — pass.
- `CARGO_BUILD_JOBS=1 cargo clippy --all-features --all-targets -- -D warnings`
  — pass with the repository's strict lint profile.
- `CARGO_BUILD_JOBS=1 cargo test --all-features --all-targets -- --test-threads=1`
  — pass on the final production implementation: 2,604 library tests and
  every main/integration/binary target.
- Final focused `CARGO_BUILD_JOBS=1 cargo test --test ledger_decision_e2e --
  --test-threads=1` — 19 passed after adding the policy-generation metadata
  assertions; the cross-run race and TUI shell freshness tests also passed
  independently during adversarial review.

Post-integration maintenance issue #1057 was verified separately after all
linked-worktree Cargo caches were removed. Every rebuild used
`CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0`, and every test command remained
single-threaded:

- `cargo test --locked --all-features --test ledger_decision_e2e --
  --test-threads=1` — 19 passed, including root `.worktrees` exclusion,
  nested `.worktrees` inclusion, V2 policy binding, and V1 compatibility.
- All four clusters containing the nine failures that originally exposed the
  oversized artifact scan passed after the V2 correction: 11 grounded-loop
  tests, 7 guardrail-quality tests, the exact pipeline regression, and the
  exact TUI regression.
- `cargo check --locked --all-features --all-targets` and strict
  `cargo clippy --locked --all-features --all-targets -- -D warnings` — pass.
- `cargo test --locked --all-features --all-targets -- --test-threads=1` —
  exit 0: 2,653 library tests and every integration/binary target passed. The
  six linked-worktree sandbox tests tracked by #1055 also pass from the
  canonical repository checkout.
- `cargo check --locked --all-features --all-targets --target
  x86_64-pc-windows-gnu` — pass. It emitted only the previously recorded
  target-conditional unused/dead-code warnings outside the #1057 paths.

The pre-verification cleanup removed 539.6 GiB of Cargo artifacts from the
canonical checkout and the three isolated slice worktrees. The final rebuilt
cache is removed again only after all Cargo evidence has been captured.

The skeptical review did not trust positive fixtures merely because they
passed. It caught and repaired a mismatched TUI model fixture, Crosslink's
machine-local hook cache being treated as source, direct command receipts that
silently lacked initial freshness, a TUI shell path outside canonical effect
reservation, and the original run-only coordinator that could not see an
independent run mutating the same workspace. Repeated full serialized runs
also exposed the two DNS-dependent tests recorded above. Each production
defect was fixed before the final green run; no positive assertion was removed
or weakened to conceal a freshness failure.

## Unresolved risks and queues

- S-088 is still planned, so no honest canonical alternate-model VDD receipt
  exists for `S024-G1`. Queue the final staged source/test digest below for
  retrospective VDD; any source/test artifact change invalidates that queue.
- The source snapshot is deliberately bounded and may be expensive near its
  100,000-entry / 1-GiB ceiling. Trees above either limit fail closed rather
  than silently sampling. More language-specific dependency closures can be
  added only as new versioned policies with equally adversarial coverage.
- Managed OpenClaudia mutations, including independent runs sharing a root,
  are serialized against snapshot capture. An external host actor that changes
  and restores the exact same bytes/type/mode entirely between the pre/post
  snapshots is outside the process coordinator and is not distinguishable
  without an OS/VCS snapshot. S-032/S-074 own stronger descriptor/snapshot
  workspace boundaries; this slice does not claim control over arbitrary host
  writers.
- `ProjectSourceTreeV3` intentionally treats non-enumerated runtime files as
  relevant. This can conservatively reject a gate if another local service
  changes such a file, but it cannot make stale source appear fresh.
- Crosslink issue #1039 tracks a deterministic resolver seam for the remaining
  hostname-specific SSRF tests. The two failures encountered here are fixed;
  production DNS resolution remains fail-closed.

No additional remediation slice was created. The canonical VDD follow-up is
already S-088, snapshot/capability strengthening is already S-032/S-074, and
the newly discovered DNS-test design gap is tracked by Crosslink issue #1039.

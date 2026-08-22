# S-054: Make memory untrusted, versioned evidence

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-073, F-074
Workstreams: W5, W15
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-031](./031-descriptor-safe-persistence.md), [S-053](./053-memory-record-identity-and-merge.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop repository/inferred memory from becoming system authority and reject unsupported or partially migrated stores.

S-054 implements private memory as strict, codebase-specific technical lessons.
It does not capture transcripts, prompt fragments, scratch prose, or user-profile
blobs. A model can propose, retrieve, inspect, and resolve a lesson only through
typed tools; every returned record remains untrusted cited evidence. Neither legacy
memory nor typed lessons are loaded ambiently into system/developer prompts.

## Implementation boundary

- Define strict current/minimum/future schemas, bounded migrations, source/scope/consent/retention/correction metadata, and transactional validation.
- Retrieve memory as cited reference evidence under context budgets and trust policy; host-reviewed preferences use a separate explicit authority grant.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

### Delivered local-memory contract

- `TechnicalLesson` is a strict versioned envelope with a host-derived workspace
  identity, bounded title/observation/guidance, typed kind, canonical
  applicability, digest-bound citations, evidence confidence, sensitivity,
  explicit retention/review state, correction metadata, and capture time.
  Unknown fields, noncanonical collections/identifiers, invalid paths/ranges,
  missing evidence, future schemas, and oversized values fail validation.
- Model-facing `TechnicalLessonDraft` deliberately omits host authority,
  workspace, actor, source, review, correction, and capture-time fields. Tool
  dispatch supplies source/run/generation/call identity and stores proposals as
  private untrusted candidates. Exact invocation replay is idempotent; reuse of
  a call identity with different evidence is a typed conflict.
- Production local storage is keyed by the canonical workspace under the
  host-owned `~/.openclaudia/memory/workspaces/<digest>/memory.db` hierarchy.
  Unix state directories and database files require exact owner-private modes,
  links are rejected, SQLite opens use `SQLITE_OPEN_NOFOLLOW`, and store plus
  workspace identities are checked when reopened by subagents. Platforms that
  lack S-031's race-safe private-storage backend fail closed until S-036.
- Store schema v7 carries one exact schema/reader/lesson version, authority and
  workspace binding, manifest digest, and ready marker. Read-only preflight
  rejects corrupt, unversioned-nonempty, partial, future, oversized, or
  semantically inconsistent stores before a writer opens. Supported v5/v6
  migration takes a bounded recovery snapshot and publishes the schema change
  in one immediate transaction; v6 linear revisions retain their exact wire
  shape and digest, and concurrent openers deterministically converge.
- Mutable archival projections are checked against every immutable causal head.
  Corrections and deletes are compare-and-swap successors/tombstones, conflicts
  remain visible, and malformed provenance, changed projections, missing
  parents, or noncanonical digests fail closed.
- Retrieval scans a bounded record/byte set, enforces one aggregate serialized
  result budget, applies deterministic lexical scoring and ordering, excludes
  expired/conflicted/legacy prose, and distinguishes complete, no-hit, and
  truthful partial results. S-105 owns evaluated semantic/task-conditioned
  retrieval rather than claiming the safe lexical baseline is optimal.
- `memory_conflicts` returns the complete canonical head set plus a cited branch
  page bounded by both item count and serialized bytes. `memory_update` accepts
  exactly one linear expected digest or one complete two-to-64-head set; stale,
  incomplete, duplicate, or forged resolution requests commit no revision.
- `memory_save`, `memory_search`, `memory_list`, `memory_conflicts`,
  `memory_update`, and `memory_delete` are registered with typed resources/effects and strict JSON
  schemas. TUI, legacy REPL, ACP, the canonical tool executor, and role-scoped
  subagents receive the same host store. Definitions disappear when a subagent
  has no memory service; plan/read-only roles receive retrieval and conflict
  inspection but not mutation.
- All prompt-builder entry points structurally lack a memory-database argument.
  Legacy archival/session/auto-learning tables remain compatibility data only;
  they are neither searched by the technical tools nor inserted into prompts.

### Team and retrieval boundary

The prior roadmap text incorrectly bundled production team activation into this
local schema slice. The preserved `team_memory_path` proposal remains rejected:
a shared SQLite path is not authentication, authorization, encryption, audit,
or a consistency protocol. S-103 establishes authenticated team authority,
S-104 provides bounded encrypted replication and canonical production wiring,
and S-105 evaluates advanced retrieval. This split preserves W5 rather than
declaring unsafe or unevaluated behavior complete.

## Acceptance

- Project, imported, inferred, team, or future-schema memory cannot become instructions through loading or migration.
- Corrupt/partial/future stores fail visibly without writes, while supported migrations preserve identity and provenance.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

### Verification record

- Toolchain policy: Rust/Cargo 1.98.0; build jobs 4; Rust test threads 1.
- Focused technical-memory integration gate: 18/18 passed, including all five
  canonical operations, exact replay/collision, CAS correction races, bounded
  output/scan behavior, no ambient prompt injection, private host modes,
  symlink rejection, current/superseded/tombstone revision tampering,
  future/partial/corrupt stores, supported migration recovery, concurrent
  migration openers, and rejection of a typed lineage imported under the wrong
  authority scope.
- Memory-related library gate: 107/107 passed, including ACP dispatch and
  subagent service/role/reopen coverage.
- Prompt, rule-removal, session-isolation, registry, subagent-definition, and
  lifecycle focused gates passed (64 tests total). Lifecycle reachability passed
  6/6 after replacing stale construction/consumer names and the stale S-054
  team-path ownership with the actual explicit-tool and S-103/S-104 boundaries.
- Locked all-feature/all-target `cargo check` passed. Strict all-feature/
  all-target Clippy with `-D warnings` passed cleanly.
- The final locked native all-feature/all-target suite passed with 2,705/2,705
  library tests and every integration target green; only tests explicitly gated
  on live network or headless-browser access remained ignored. It used four
  build jobs and one Rust test thread. The Windows GNU all-feature/all-target
  check passed; its warnings were pre-existing target-conditional unused/dead
  test helpers outside S-054, and no S-054 path warned.
- `cargo +1.98.0 fmt --all -- --check` and `git diff --check` passed. No new
  placeholder, ignored-test, debug-output, ambient-memory, or secret-bearing
  path survived the changed-artifact scan. Generated capability assets were not
  changed by this slice.

Issue #1081 follow-on verification used the same Rust 1.98.0, four-job,
single-test-thread policy. Conflict, migration, portability, team authority,
registry, and tool-schema targets passed 117/117; artifact-bound retrieval
evidence passed 9/9 and the runtime retrieval target passed 4/4. Strict
all-feature/all-target Clippy, Windows GNU all-feature/all-target check, and the
complete native all-feature/all-target test matrix all passed.

The repair history is retained as evidence. Review caught and corrected ACP's
missing `memory_update` route and literal replacement call ID, absent SQLite
no-follow, permissive host-store modes, noncanonical persisted identity
normalization, a tagged-row scan that could misclassify corruption as partial,
and stale lifecycle claims. The pre-commit pass additionally brought every
superseded revision and typed tombstone inside bounded reopen validation,
rejected wrong-scope typed lineage imports under the same transaction, and
replaced adapter serialization panics with typed internal failures.

The final ordered source/test/document artifact manifest has SHA-256
`e841d8202df1cb98c7c2018f06f248747c0418786b661aaf636f5e7589c6bd45`:

- `Cargo.toml`: `3120f886445765022c20a1c2e34311f2953c73fd949e3afd58a6cd8638c965a2`
- `README.md`: `3c2fbbb85d1c0412c6bee85869eb6e790615e29132607d1caf16a2814dcaeae2`
- `docs/remediation-slices/012-runtime-feature-reachability.md`: `854c84aa810f8eac573a0a0f7b396b736433ec5fb47c0ae4e6be7c672d607902`
- `docs/remediation-slices/053-memory-record-identity-and-merge.md`: `e0cc86fd18e54512438674de1bdb8b30f92b610a9c99baec7b8ba51e525881fd`
- `docs/remediation-slices/103-authenticated-team-memory-authority.md`: `c03a0957ccfe96bd4d4e0a678787cec8d52879eae0085d797b4cbf3f485f7dab`
- `docs/remediation-slices/104-team-memory-replication-service.md`: `d27f79e9f6870243a5790db5032ed2ded956c6624cc66f5f326b962db081e3f7`
- `docs/remediation-slices/105-evaluated-technical-memory-retrieval.md`: `17a2af23cc71deb2cee258c4185dd0a409c46a7045178deb5648fe72949aec47`
- `docs/remediation-slices/README.md`: `b23d01f0edd69c9ed7f3db13185fd6c5194065fd919e257f5e4b50d0f2786ce9`
- `src/acp.rs`: `86f40e94bd7210730fcccff4ea349375e4fd2805d5c4e61d55cfbd0f234f93be`
- `src/cli/chat_repl.rs`: `d9f9334318115180485860d19bb9b2752deb8bc288cfd767777379b230f99d7a`
- `src/cli/print_mode.rs`: `43f9a72834f3117253fc2553782c789baee685386975316d88e9ce8d184c8829`
- `src/config/memory.rs`: `ff67e6b2549ad501b1b384a04bba8551210c505698aef0caf726814d693c7bc1`
- `src/config/mod.rs`: `893148ca684bbde096e4e8e6effd71c9a720bb930407e261a34b7f3703791ad6`
- `src/main.rs`: `473ab59f328b1125303ce4a52ea36817854e5f08d8ea2185f76b296575eb0408`
- `src/memory.rs`: `4dcc13795ee084abd1556b40d7158bd46fd96360f85c8ab4794569e36a395eeb`
- `src/memory/lesson.rs`: `15286847b60194da7ebb3e3e8193c2e7e7404150c22eed0c26828575b0ca06c3`
- `src/memory/record.rs`: `4e65f7b8e0f81f20a301239f8125d2ac764a331e064dcaae7dc4f005837ce602`
- `src/prompt.rs`: `63c2fdb5bd3bb6600ddb066e51faf6c9dcf83de8b45986d6e16d41d02b27446c`
- `src/services/lifecycle.rs`: `5edd7563a76d76110877d9708e962d0a5e45dd97de88db8ffb89a99565282a38`
- `src/session/state.rs`: `63b207b356d5392aff14fbc50854ad9685a08318fe8f2232589baaa726b1fd3c`
- `src/subagent.rs`: `3af2c0ca7f3af8a9b9a741697f0e66645303dd97d780e9b65f9dd10e484f6be7`
- `src/team_memory.rs`: `eff00f63fc260bf5eb128702cdad31e3ef2fa7992770069e291b50c07abca807`
- `src/tools/memory.rs`: `57f2f7143fe1fe4a9580dca1ff80f9a09c04a9803e4a756778746c9f91964249`
- `src/tools/mod.rs`: `490e72bdaec3fa41566f8192434f452f3ad969bcdc09083fbfdfd004126d3862`
- `src/tools/registry.rs`: `a9683f0f77b3dfcf5a92bf78a901f2059b1e267a7edb4435aa61170b8a5829dc`
- `src/tools/security.rs`: `a64cc728a33c69d55cabf36de8aeb50f14b2a8c400e94b2748e336713fb3747a`
- `src/tui/app.rs`: `af430add433bf54bad4f9e5a9ad22961aeb2fe2ba49d1e2d32f7573462311e14`
- `tests/get_all_tool_definitions_subagents_e2e.rs`: `29ec093c3a76e5a2e249ef14a0b8da1577a69673a9e9717b91a180c033d05eef`
- `tests/integration_tests.rs`: `f82644256c225f9970108c28d77caf1405980c4e8c6e49aa50ac8cf5b94c70b4`
- `tests/legacy_rule_injector_removed_e2e.rs`: `908839629cfae6c72e5f9856693c2c63757b8d685d0f8b55a49c400b86ee7da0`
- `tests/lifecycle_service_reachability_e2e.rs`: `ae519baea81e069bf3388ae64b282eb56282cf22df28b29f26390f9cce001568`
- `tests/prompt_builder_e2e.rs`: `64aaaccfadfd45675a97d89ad8eb5ab489e472486faf10a20648e7f705193728`
- `tests/registry_global_invariants_e2e.rs`: `5f1fafb77d3caf1493afaa83d41649a3f5695185aea9168fb2afb5e3354de669`
- `tests/session_capability_isolation_e2e.rs`: `b3578da3dd073f0c3bd18c4541d325d99b65c5b01baf7a09184615d76d5fc685`
- `tests/technical_memory_e2e.rs`: `374f5c892ce9cc741f39dabf08ee30ff458c0e72ad6c6ee942289a22e933eace`

The slice document is commit-tracked and its stable digest is recorded in the
Crosslink result receipt to avoid self-reference.

### Assigned unresolved work

Issue #1081 completed the previously missing typed conflict inspection and
resolution path, including schema-v7 migration, exact replay, tombstones,
frontends, and private/team authority boundaries.

- S-036: implement equivalent Windows handle/reparse/owner permission
  containment so host-owned technical memory can activate there safely.
- S-055: replace the legacy prose/correlation learner with causal typed lesson
  capture and measured false/harmful-learning behavior.
- S-056 delivers strict explicit `MEMORY.md` source status/refresh/prune without
  granting file prose instruction authority; S-106/#1078 owns the remaining
  host-authorized review transition and complete portable export.
- S-103/#1074 and S-104/#1075: authenticated team authority and bounded
  replication; the direct shared-path proposal stays rejected.
- S-105/#1076: artifact-bound evaluation of semantic/task-conditioned retrieval.
- S-088: attach the independent alternate-model artifact-bound VDD receipt.

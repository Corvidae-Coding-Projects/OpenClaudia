# S-012: Wire or honestly classify lifecycle services

Status: Implemented and adversarially reviewed; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-006
Workstreams: W9, W13
Depends on: [S-001](./001-capability-evidence-registry.md), [S-010](./010-canonical-run-context-and-events.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Every inventoried lifecycle-service implementation now has one typed,
unambiguous production disposition. Operational services have concrete owners
and consumers. Incomplete implementations remain in the repository and are
classified as unavailable, experimental, or test-only rather than being
deleted or silently installed. Configuration cannot claim that an unavailable
team-memory or arbitrary feature-rollout service is active.

## Architecture decision

`ServiceRegistry` is not a heterogeneous global service locator. Different
services carry different run authority, cancellation, persistence, and
shutdown requirements; hiding all of them behind one cloneable bag would make
those boundaries harder to audit. The runtime therefore uses a hybrid explicit
composition model:

- `ServiceRegistry` constructs the one genuinely injected cross-frontend
  service, analytics, and has no `Default` or silent production no-op path;
- model-specific auto-compaction remains a typed per-request owner in the
  proxy;
- MCP, project memory, guardrails, enterprise policy, and tool execution keep
  their existing typed owners at their real composition roots;
- `lifecycle_service_catalog()` is an immutable typed reachability inventory,
  not an execution locator;
- incomplete implementations remain callable for library/test development but
  are not admitted to production or represented as operational.

This preserves the intended capabilities while removing only false wiring and
duplicate authority. In particular, the transport-neutral plugin MCP mirror,
feature-flag source, background scheduler, team-memory prototype, LSP staging,
and rate-limit state machine remain present for their owning follow-up slices.

## Audited lifecycle catalog

| Service | Classification | Production construction / consumer / completion or owner |
|---|---|---|
| Analytics | Wired | `ServiceRegistry::interactive` / `analytics_subscriber` + `drain_pending` / `StateAnalyticsSubscriber::finish` and `Drop` |
| Feature rollout | Unavailable | No declared production flag catalog; unknown `OPENCLAUDIA_FEATURE_*` keys fail validation; S-014/S-047 |
| Background jobs | Unavailable | Preserved synchronous prototype lacks ownership, durable leases, cancellation, budgets, and transactional jobs; S-053/S-054/S-061/S-084 |
| Auto-compaction | Wired | `proxy::compact_request_context` / `AutoCompactor::auto_compact` / request-future completion |
| Plugin MCP runtime | Wired | Real `PluginManager` + `McpManager` owners in proxy/TUI / MCP dispatch / `disconnect_all` |
| Plugin MCP shadow registry | Experimental | Preserved transport-neutral migration mirror; never a runtime authority or secret store; S-063/S-064/S-066 |
| Project memory | Wired | Project memory composition roots / prompt and tool consumers / frontend completion then `MemoryDb` drop |
| Team memory | Unavailable | Production config rejects the proposed shared path until stable cross-store identity and atomic reconciliation exist; S-053/S-054 |
| Guardrails | Wired | `guardrails::configure` / tool, diff, and quality boundaries / last-`Arc` run retirement |
| Enterprise policy | Wired | `PolicyEnforcer::new` / provider and tool policy consumers / frontend owner drop |
| Tool executor | Wired | typed `ToolExecutorRequest` / `ToolExecutor::execute` / typed result publication |
| LSP pool | Unavailable | Language-only prototype is not workspace/generation safe; S-068/S-069 |
| LSP diagnostics | Unavailable | Staging registry lacks workspace/version identity and aggregate bounds; S-068/S-069 |
| Rate-limit failure injection | Test-only | Preserved deterministic state machine is not installed in provider/proxy transport; S-048/S-050 |

`validate_lifecycle_service_catalog()` rejects duplicate or missing service IDs,
incomplete wired paths, fake paths on unwired services, and unavailable entries
without remediation ownership.

## Production wiring and honest failure boundaries

### Analytics

- The TUI and legacy REPL construct `ServiceRegistry::interactive` and obtain
  their state subscriber through the registry instead of directly assembling a
  nominal service bag.
- The subscriber records session start, session-generation switches, and one
  exactly-once final session end. Sink panics are contained at the optional
  analytics boundary.
- Local analytics is debug-level opt-in through `--verbose` or explicit
  `RUST_LOG`. Default info logging emits none of these records.
- Session identity is emitted only as a SHA-256 content digest. Current records
  contain no prompt content and no remote exporter exists. The README records
  the fields, opt-in behavior, lack of upload/export, and log retention/deletion
  boundary.

### Compaction

The proxy now routes its real request decision through `AutoCompactor`. A
skeptical review caught and fixed a boundary error where an attempted but
non-reducing compaction would have been logged and hooked as successful; only a
`CompactionResult { compacted: true, .. }` now emits the success path.

### Guardrails

ACP previously derived a run capability without binding the loaded guardrail
policy. Every ACP session/new, session/load, and prompt generation now uses
`build_run_context`, which binds the exact configured policy before the run is
published. The regression test loads a real strict `.env` deny policy and
proves that the resulting ACP run rejects access.

### Unavailable configuration

- `memory.team_memory_path`, from YAML or its typed environment name, fails at
  production config loading with its S-053/S-054 ownership instead of being
  silently ignored.
- Arbitrary `OPENCLAUDIA_FEATURE_*` variables no longer bypass the finite typed
  environment registry and fail as unknown names.
- The library/test prototypes remain available so later slices can complete
  their intent rather than reconstructing deleted work.

### Preserved process and maintenance prototypes

- Dropping any LSP `ChildHandle` now kills and waits for the child, including
  handles displaced by the unsafe competing-generation prototype. Tests prove
  the OS process is gone; no `sleep` residue remained after the suites.
- Plugin update and delisting prototypes now state at debug level that no
  marketplace request was made. Tests reject the former false “polled” claims.
- Background-memory documentation now describes its deletion/concatenation
  prototypes honestly and does not promote them as transactional merges or
  semantic summaries.

## Capability evidence

Capability registry generation: **3**.

The internal `lifecycle-service-reachability` record is deliberately
`partial`. It exposes the validated typed catalog and names its unpromoted
services. It is not marked operational because artifact-bound construction,
consumer, shutdown, and negative-activation receipts require S-088's canonical
VDD verifier.

Final artifact SHA-256 digests:

- `capabilities/registry.json`:
  `ba4166f9a20edb768966ae41970e3d7c840f321ea4d2fa84360d3e80939b0f27`
- `capabilities/evaluation-corpus.json`:
  `2025ebed47e67138f703c09918b11384cb758a0adb4a7d0cf17de7450cde963a`
- `capabilities/evaluation-corpus-review.json`:
  `26c04b7929c130808f872b7f0473889649fc7586f5b41ee3ccb475d49ea1ddd0`
- `docs/binary-capability-matrix.md`:
  `40a50c35164ac8eb000376979f6e71511523dff1ffa92cfae48967198d69407d`

The S-012 corpus change is limited to the deterministic generation-3 matrix
projection and final-environment digest. All executable scenarios, typed trace
and effect proofs, failure graders, and three-trial receipts remain unchanged.

## Verification evidence

All Rust commands used Rust/Cargo **1.98.0**, `CARGO_BUILD_JOBS=4`, and
single-threaded test execution where applicable.

- `cargo fmt --all` and `cargo fmt --all -- --check`: pass.
- `git diff --check`: pass.
- JSON parse validation for all three capability artifacts: pass.
- `cargo test --locked --all-features --test lifecycle_service_reachability_e2e -- --test-threads=1`: **6 passed**.
- `cargo test --locked --all-features --test service_registry_jobs_e2e -- --test-threads=1`: **16 passed**.
- `cargo test --locked --all-features --test service_registry_lsp_pool_e2e -- --test-threads=1`: **14 passed**.
- `cargo test --locked --all-features --lib services:: -- --test-threads=1`: **93 passed**, 2,579 filtered.
- `cargo test --locked --all-features --lib production_session_run_binds_the_loaded_guardrail_policy -- --test-threads=1`: **1 passed**, 2,671 filtered.
- `cargo test --locked --all-features --test auto_compactor_e2e -- --test-threads=1`: **13 passed**.
- `cargo test --locked --all-features --lib proxy::tests -- --test-threads=1`: **44 passed**, 2,628 filtered.
- `cargo test --locked --all-features --test capability_evidence_e2e -- --test-threads=1`: **11 passed**.
- `cargo check --locked --all-features --all-targets`: pass.
- `cargo clippy --locked --all-features --all-targets -- -D warnings`: pass with no warnings.
- `cargo test --locked --all-features --all-targets -- --test-threads=1`: exit 0; the library harness enumerated 2,672 tests and every executed library/integration harness passed. Existing explicitly ignored network-only cases remained ignored.
- `cargo check --locked --all-features --all-targets --target x86_64-pc-windows-gnu`: pass in 56.66 seconds. It emitted only existing target-conditional unused/dead-code warnings outside S-012; no S-012 path warned.

The repair cycle was retained as evidence rather than erased:

1. The initial process-level feature-variable test failed before reaching env
   validation because its isolated project had no config; adding a minimal
   config made it test the intended boundary.
2. Static review found ACP guardrails were absent despite configuration and
   execution support; the shared run builder now binds them.
3. Static review found the proxy's new `Some(result)` match could falsely report
   a non-reducing compaction as successful; the success guard was restored.
4. Test review replaced no-panic/PID-placeholder checks with exact maintenance
   diagnostics and child-death assertions.
5. Strict Clippy found only one new nested-or-pattern style issue after the
   semantic repairs; it was corrected without suppression and the strict gate
   then passed.

## Acceptance audit

- **Per-service disposition:** proven by the exhaustive typed enum/catalog,
  duplicate/completeness validator, and exact expected classification test.
- **Construction-to-completion path:** present for every `Wired` record and
  exercised by focused analytics, compaction, MCP/project-memory existing
  suites, ACP guardrail, policy/tool-executor, and lifecycle tests. Operational
  artifact-bound promotion remains intentionally withheld pending S-088.
- **Configured-but-unconsumed behavior:** process tests prove unknown feature
  variables and YAML/environment team-memory activation fail visibly.
- **Preservation over deletion:** incomplete feature flags, background jobs,
  team memory, shadow MCP, LSP, and rate-limit implementations remain present
  under explicit classifications and follow-up owners.
- **Deterministic tests and traces:** focused trace/privacy/fail-closed/process
  assertions and the complete Rust gate pass.

## Unresolved risks and follow-up ownership

- S-088 must attach the independent artifact-bound VDD receipt before the
  internal capability can be considered for operational promotion.
- Analytics currently has production consumers in the TUI and legacy REPL;
  S-078, S-089, S-093, and S-094 own convergence of print, ACP, and proxy
  frontends onto canonical lifecycle routing rather than parallel S-012
  adapters.
- S-053/S-054 own safe team-memory identity, provenance, and cross-store
  transactions. S-061/S-062/S-084 own plugin maintenance and durable job
  scheduling. S-068/S-069 own workspace/generation-safe LSP. S-048/S-050 own
  real provider-transport failure injection. S-014/S-047 own declared rollout
  semantics.
- The current typed lifecycle path uses stable Rust entrypoint identities plus
  deterministic runtime tests. It intentionally makes no VDD-quality claim
  until S-088 can bind those paths to artifact generations and traces.
- The Windows gate's target-conditional warnings are pre-existing and remain
  outside S-012; the strict native all-target Clippy gate is clean.

Completion of this slice does not imply completion of its parent workstreams or
the capabilities owned by the follow-up slices.

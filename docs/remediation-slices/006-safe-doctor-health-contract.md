# S-006: Rebuild doctor as evidence-safe diagnostics

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-108
Workstreams: W0, W13
Depends on: [S-001](./001-capability-evidence-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make `doctor` report real readiness evidence without spending credentials, mutating state, or fabricating health.

## Implementation boundary

- Classify each diagnostic as offline, read-only, or explicitly active; make offline/non-mutating behavior the default.
- Probe the real composition root with bounded typed checks and return pass, fail, degraded, or skipped receipts with redacted causes.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Default doctor runs do not refresh auth, contact providers, write files, or create runtime state.
- Synthetic empty managers cannot produce a healthy result, and active probes require an explicit scoped grant.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implemented contract

- `src/doctor.rs` is the single library-layer contract used by the standalone
  command, legacy REPL, and TUI. Schema version 1 / evidence generation 1 emits
  ten deterministic receipts with stable identifiers, offline/read-only/active
  classes, declared and observed effects, required-for-aggregate state, and
  pass/fail/degraded/skipped outcomes.
- Report validation binds schema, generation, exact receipt order, active
  grants, class/effect/outcome/code tuples, aggregate state, every static
  explanation, and canonical bounded numeric summaries. Forged effects,
  relabelled outcomes, or injected detail fail closed.
- Standalone `doctor` validates active authority before reading configuration,
  bypasses the writable startup-migration gate, and constructs no run context,
  session, plugin manager, MCP manager, HTTP client, or subprocess. Missing
  live composition is reported as unavailable and makes the aggregate nonzero.
- `--json` emits the typed envelope. `--allow-active
  provider.reachability` accepts only that exact grant; the receipt remains
  skipped and required because no safe broker exists yet. Unknown grants are
  rejected without echoing their value and before configuration reads.
- Interactive frontends attach their already-validated configuration and real
  composition. Concrete provider client/adapter, plugin-manager, MCP-manager,
  run-context, and memory-store handles are required before the corresponding
  receipt can claim composition. MCP state is sampled without blocking,
  reconnecting, or starting a server. Empty plugin/MCP managers are degraded,
  never healthy.
- Human and JSON projections never include provider/model names, origins,
  paths, headers, credential contents, or foreign-store errors. The standalone
  command never reads or refreshes the foreign Claude credential store.

## Preserved intent

The redesign removes false diagnostic mechanisms, not the underlying product
capabilities:

- Configuration and provider-auth diagnostics remain as typed validation and
  credential-presence receipts; values and remote validity are not exposed or
  guessed.
- Provider reachability remains an explicit active diagnostic request. The old
  arbitrary authenticated `GET` is replaced by an honest broker-unavailable
  receipt until [S-048](./048-hardened-provider-http-transport.md) and
  [S-071](./071-web-egress-connection-broker.md) supply trusted-origin,
  redirect, secret, deadline, and cost controls.
- Sandbox/run, provider transport, plugins, MCP, memory, and session identity
  continue to operate in their production subsystems. Doctor now inspects the
  already-composed frontend objects instead of constructing empty test objects
  or mutating plugin/session state. Deeper subsystem health remains owned by
  its existing remediation slices.
- The former hook-directory check asserted only path existence, not hook
  execution health. Hook lifecycle functionality is untouched; the unsupported
  directory-as-health claim is not carried forward. The deprecated rule
  injector remains the separately authorized removal boundary.
- The old local fabricated provider-response transform is no longer presented
  as live provider health. Real provider adapters and transports remain wired
  to normal turns and are represented only as composed, never remotely ready.

## Changed artifacts

- Capability registry generation: 2
- Doctor report schema/evidence generation: 1 / 1
- `capabilities/registry.json` SHA-256:
  `a8c7c0eef8cf3d088998f8673402b7d5a013f3862f1e8ab6dfd1fe84f5a54b05`
- `capabilities/evaluation-corpus.json` SHA-256:
  `0a3e910522c1db0ec54472ffa727d5630337516ef13d26062fcf7c4183bc7c6e`
- `capabilities/evaluation-corpus-review.json` SHA-256:
  `f77d1bcee4f8a1fdbe210836b0380af073cef83abd0d8a848ceb09ae9ab9f468`
- Generated `docs/binary-capability-matrix.md` SHA-256:
  `7fc7b5ec3b470befc7bf29afa3cba886d0c8083f836aa136fea72648882af631`
- Reviewed `src/doctor.rs` SHA-256 before this documentation update:
  `953ba2d196c4803d2b5e885f60b96e305b70ae4face5dcd7aafb9b9fba3539c6`

The capability remains `partial`, with no operational evidence IDs. The
generation-2 matrix and corpus projection were regenerated deterministically;
the executable three-trial registry scenario and negative graders remained
unchanged and passed.

## Verification evidence

All Rust commands used `rustc 1.98.0`, Cargo 1.98.0, Clippy 0.1.98, a locked
dependency graph, four build jobs, and serial Rust test execution where tests
were run.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed with no diff |
| `cargo test --locked --all-features --all-targets doctor -- --test-threads=1` | Passed: 8 doctor/TUI library tests, 2 REPL/startup-gate binary tests, and 5 CLI doctor E2Es; other targets were filtered |
| `cargo check --locked --all-features --all-targets` | Passed |
| `cargo clippy --locked --all-features --all-targets -- -D warnings` | Passed with no warnings |
| `cargo test --quiet --locked --all-features --all-targets -- --test-threads=1` | Exit 0; library 2666 passed/1 ignored, binary 219 passed, the 133-test integration target 131 passed/2 ignored, and every remaining integration target passed |
| `cargo check --locked --all-features --all-targets --target x86_64-pc-windows-gnu` | Passed; emitted only pre-existing target-conditional unused/dead-code warnings outside S-006 |
| `git diff --check` | Passed |

Adversarial coverage uses isolated project/home/data roots, a proxy listener
that fails on any connection and returns a redirect canary, custom-origin/API
key/header/foreign-credential/plugin-tracker/migration-state canaries, and
recursive before/after tree snapshots that bind paths, kinds, contents,
lengths, permissions, and modification times. Default and exact-active runs
prove no network connection, no project or home mutation, redacted output,
typed validation, skipped active/migration receipts, and a non-healthy exit.
Unknown active grants prove rejection before reads without reflecting input.

## Skeptical repair record

- Initial review found that report validation accepted a forged canonical
  aggregate with a relabelled result. Exact per-check semantic tuples and a
  negative forgery test were added.
- Final pre-commit review found two further slice defects: TUI composition was
  promoted from boolean/string presence instead of concrete handles, and
  receipt detail text was not integrity-bound. TUI now requires the actual
  objects, all details are exact or canonically parsed, and injected detail has
  a negative test.
- The active-grant E2E originally snapshotted only the project tree. It now
  also snapshots the isolated home tree so a credential-refresh regression
  cannot pass.
- Rustfmt, focused tests, all-target check, strict Clippy, the full suite, and
  Windows GNU were rerun after these corrections.

## Remaining boundaries

- Active provider reachability is intentionally skipped until S-048/S-071
  provide the canonical broker. No substitute direct provider path was added.
- The alternate-model, artifact-bound verifier receipt remains pending
  [S-088](./088-canonical-vdd-verifier-role.md). This status is not represented
  as operational evidence.
- No newly discovered S-006 defect requires a separate slice or issue.
- Completing S-006 does not complete W0, W13, or the parent remediation plan.

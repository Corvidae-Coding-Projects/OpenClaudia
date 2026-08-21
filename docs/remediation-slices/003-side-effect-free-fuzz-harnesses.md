# S-003: Make fuzz targets side-effect free

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Small
Primary findings: F-139
Workstreams: W13
Depends on: [S-001](./001-capability-evidence-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure arbitrary fuzzer input cannot execute host commands, touch ambient files, or reach external services.

## Implementation boundary

- Replace production side-effect handlers in fuzz targets with hermetic temp capabilities, fake transports, and deterministic bounded fixtures.
- Upgrade no-panic smoke targets to assert protocol, containment, terminal-state, and allocation invariants.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Every fuzz target runs with network and ambient process effects unavailable and writes only beneath its owned temporary root.
- A regression test demonstrates that command/path-shaped fuzzer input cannot escape the fake harness.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

Crosslink issue: #1064.

The fuzz crate now has one shared, bounded implementation surface in `fuzz/src/lib.rs`. All nine `libfuzzer_sys` entrypoints are thin delegates to those functions, and every target has a checked-in `seed-*` corpus input that is executed by ordinary Rust tests. The harnesses use deterministic fixtures, an owned temporary root, and a `ToolRunContext` that denies process, network, secret, and ambient-environment authority. The JSON-tool harness classifies effects without dispatching tools. The Markdown harness writes to a bounded in-memory sink with an explicit theme and terminal width.

The production code exposes the minimum pure seams required by the harnesses:

- cron validation and hook-matcher validation are independently callable and bounded;
- path resolution remains capability-rooted and does not dispatch a file operation;
- streaming Markdown supports an explicit theme, width, and caller-owned writer;
- SSE, truncation, provider conversion, and request construction are exercised as deterministic state transitions.

The sandbox-security workflow now compiles, strictly lints, and executes the fuzz harness library on Rust 1.98. Repository policy tests require those commands and reject a fuzz manifest whose Rust version diverges from the root manifest.

### Artifact generations

- Verification policy generation is `ProjectSourceTreeV3` with policy version 3.
- V3 excludes only generated fuzz cache roots (`fuzz/target`, `fuzz/artifacts`, and `fuzz/coverage`) and non-seed fuzzer discoveries. It retains checked-in `fuzz/corpus/*/seed-*` files as reviewed source evidence.
- V1 and V2 still deserialize for historical evidence, but neither can authorize a current verification receipt.
- The fuzz crate lockfile and all nine curated seed files are part of the reviewed artifact set.

### Adversarial coverage

- A structural test enumerates the exact nine target files and requires every target to delegate to its assigned shared harness.
- Source scans reject command execution, network clients, environment access, ambient filesystem access, and tool dispatch in both thin targets and production harness code.
- Hostile command- and path-shaped bytes are exercised through all 256 selector values and cannot modify a sentinel outside the owned temporary root.
- Semantic assertions verify converter bytes, provider request shape, cron and matcher results, mandatory effect classification, contained path resolution, Unicode-safe truncation, terminal SSE state, and whole-versus-chunked Markdown output and state equality.
- Bounds cover 64 KiB raw inputs, 8 MiB derived data, 256 JSON values, a 1 KiB matcher, a 10 KiB compiled-regex limit, and 512 rendered columns.
- The cache-policy regression creates sparse generated fuzz artifacts larger than 1 GiB, proves they neither exceed the source-evidence budget nor stale a receipt, proves a curated seed mutation does stale it, and proves similarly named nested source paths still stale it.

### Verification evidence

All Rust commands used the repository-selected Rust and Clippy 1.98 toolchain. Builds used four jobs; tests were serialized within each test binary because parallel-test isolation remains tracked separately in #1062.

- `cargo check --locked --manifest-path fuzz/Cargo.toml --all-targets`: passed.
- `cargo clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings`: passed.
- `cargo test --locked --manifest-path fuzz/Cargo.toml --lib -- --test-threads=1`: 4 passed, including execution of every curated seed.
- Focused root tests: cron 32 passed; hook matcher 4 passed; TUI theme/welcome 24 passed; the V3 ledger regression passed; all previously affected grounded-loop, guardrail, pipeline, and TUI quality-gate groups passed unchanged.
- `cargo check --locked --all-features --all-targets`: passed.
- `cargo clippy --locked --all-features --all-targets -- -D warnings`: passed.
- `cargo test --locked --all-features --all-targets -- --test-threads=1`: passed in full on the final run; the library harness ran 2,659 tests and all integration binaries completed successfully.
- `cargo check --locked --all-features --all-targets --target x86_64-pc-windows-gnu`: passed after installing the Windows standard-library target into the same Rust 1.98 toolchain. Only known target-conditional warnings outside S-003 were emitted.
- Root and fuzz `cargo deny --locked ... check`: advisories, bans, licenses, and sources all passed.
- Root and fuzz formatting checks passed; `git diff --check` passed.
- `python3 -m unittest scripts.tests.test_repository_policy`: 27 passed.
- `python3 scripts/check_repository_hygiene.py`: returned schema version 1 with status `verified`.

The first full-suite attempt exposed a real evidence-freshness defect rather than a product-test failure: a 3.1 GiB generated `fuzz/target` tree was being hashed as project source, exceeded the 1 GiB evidence budget, and invalidated nine quality-gate tests. V3 fixes that at the exact generated paths without broad `target` matching; the focused groups and the full suite then passed without weakening their assertions.

After verification, `cargo clean` removed 42.4 GiB from the root target and 6.3 GiB from the fuzz target by Cargo's accounting. The full zram device was safely recycled from 8.0 GiB used to effectively empty. Five stale `bwrap` processes left by `tests/bash_background_e2e.rs` were also reaped; the underlying successful-test teardown leak is tracked independently as #1067.

### Residual boundaries

- A canonical artifact-bound alternate-model VDD receipt remains pending S-088; this slice cannot bootstrap that verifier.
- No nightly `cargo fuzz run` campaign was performed because the repository is intentionally standardized on the single Rust 1.98 toolchain. The exact fuzz entry functions, target binaries, hostile-input regression, and curated corpus were compiled and executed through deterministic stable tests.
- Provider-hook false positives for legitimate Rust module and fixture text remain tracked as #1065 and #1066.
- S-006 is the next independent remediation slice. Completion here does not complete W13.

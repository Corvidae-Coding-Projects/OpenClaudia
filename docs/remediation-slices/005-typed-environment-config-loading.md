# S-005: Replace generic environment-key rewriting

Status: Implemented and adversarially reviewed; VDD pending
Effort: Small
Primary findings: F-013
Workstreams: W14
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Load environment configuration through an explicit typed map so multiword fields and provider namespaces resolve correctly.

## Implementation boundary

- Declare supported environment variables beside the typed configuration fields, including parse, secrecy, precedence, and deprecation metadata.
- Reject ambiguous/unknown keys and test environment, file, CLI, and default precedence for every supported field.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- All documented multiword settings round-trip from environment variables to the intended typed field.
- Unknown or malformed security-relevant variables fail visibly rather than being ignored or mapped elsewhere.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

Architecture generation: `s005-typed-environment-v1`.

- `src/config/environment.rs` is the single finite conformance map for main
  configuration. It binds 204 typed fields (60 application fields plus nine
  fields for each of 16 built-in provider namespaces) to exact canonical and
  compatibility names. Every descriptor carries parser, secrecy, source
  precedence, deprecation, and security-relevance metadata. Together with the
  independently consumed ACP field, the public projection contains 437 unique
  exact environment names.
- Canonical names use `__` only between typed nesting levels and `_` within a
  field or provider segment. Exact pre-S-005 spellings remain deprecated
  migration aliases; provider ecosystem key names remain compatibility
  aliases. More than one exact name for a field is an error rather than an
  implicit priority rule.
- Process input is collected through `vars_os`, sorted deterministically,
  bounded to 64 KiB per value, and parsed before it enters configuration
  state. Secret diagnostics carry the exact variable and typed field but not
  the rejected bytes. Unknown `OPENCLAUDIA_` names fail unless they are an
  explicitly enumerated variable owned by another subsystem or a documented
  dynamic feature/test namespace.
- Project and trusted-home files are first merged into untyped state. Typed
  environment values then replace their exact field in that state, retaining
  the exact environment-variable origin, before the one `AppConfig`
  deserialization/validation pass. Exact replacement avoids `config`'s deep
  table merge, so map-valued fields receive ordinary whole-field precedence;
  it also permits a valid environment value to replace a malformed lower-file
  value. Explicit CLI mutation remains later and therefore higher precedence.
- `AcpConfig::max_iterations` now uses
  `OPENCLAUDIA_ACP__MAX_ITERATIONS`, accepts the exact former spelling with a
  warning, rejects simultaneous aliases, and installs a valid environment
  value before ACP typed YAML deserialization.
- Hooks and keybindings remain file-owned configuration. The former generic
  source did not parse hook arrays/objects into their typed shapes, while the
  flattened keybinding namespace has no finite unambiguous environment-key
  grammar. This slice does not create a new executable-hook environment
  channel or preserve undocumented dynamic key names that would contradict
  required unknown-key rejection.

Changed artifact set and stable SHA-256 digests:

- `README.md`: `018cba630d0f45e8bd5e094392f0f7fcfb02bfcfce9d3733662bf8bf01540cc1`
- `src/acp.rs`: `a8567394e216c47ca451c53cdbe94a1b9e32f3d1764a5e0c1214cb1d4cb3df53`
- `src/config/acp.rs`: `085662f47241a6d1f915bcf3927fe7cd8b0d8d7c795727ac41c119c87fdf4663`
- `src/config/environment.rs`: `f583274997ff94288cdc897aa4c48ea82a9739f8e5696f211c77c34c3f62da9a`
- `src/config/memory.rs`: `47dee313f3ac065fbf708f3799c20dbae76300af5cde283c2859bc61b32a1c96`
- `src/config/mod.rs`: `44551a4bd8b329cb881cddc8fd105144ee5b4ee2c37562fd6b0108791025c7bd`
- `tests/typed_environment_config_e2e.rs`: `fb8517084b4695c2172a837cadec9368839d924c64a701e4dd63d5c85abf28da`

This slice record's digest is recorded in Crosslink result receipt #1051 after
the record is stable, avoiding a self-referential digest.

## Test design and skepticism record

- Exhaustive typed tests apply all 435 main-config canonical/deprecated/
  ecosystem names to their intended typed field. Samples deliberately differ
  from defaults, including boolean fields, so success cannot be inferred from
  unchanged state.
- A second exhaustive test loads a complete, different file value for every
  one of the 204 main-config fields, applies each canonical environment name
  individually, deserializes `AppConfig`, and asserts the intended typed field.
  Map/list assertions also prove lower-file members are replaced rather than
  silently retained.
- Process-boundary acceptance tests exercise default, project-file,
  trusted-home, environment, and explicit CLI precedence; valid environment
  repair of malformed lower-file scalar and secret values; unknown and
  ambiguous names; and a malformed API key with a non-disclosure assertion.
- Negative unit cases cover every security-relevant canonical field with an
  empty value, every declared parser family, non-finite floats, non-zero
  budgets, typed enum rejection, malformed JSON shapes, and the input-size
  bound. ACP retains separate default/file/environment parser tests because it
  is consumed lazily by the ACP runtime.
- Removed tests that asserted the behavior of generic underscore rewriting or
  ad-hoc first-key priority; those tests were implementation-shaped and
  encoded the defect/ambiguity being removed.

## Verification record

The remediation-wave coordinator granted a serialized Cargo queue. Every
compilation used `CARGO_BUILD_JOBS=1`; every Rust test invocation retained
`-- --test-threads=1`. Final command evidence:

- `cargo fmt --all` -> pass, no output; rerun after each repair.
- `cargo fmt --all -- --check` -> final pass, no output.
- `cargo test --locked --all-features --lib config::environment::tests -- --test-threads=1`
  -> 11 passed, zero failed, zero ignored, 2,645 filtered out in 0.65s.
- `cargo test --locked --all-features --lib config::acp::tests -- --test-threads=1`
  -> 17 passed, zero failed, zero ignored, 2,639 filtered out in 0.00s.
- `cargo test --locked --all-features --test typed_environment_config_e2e -- --test-threads=1`
  -> five passed, zero failed in 1.12s.
- `cargo test --locked --all-features --test config_validation_e2e -- --test-threads=1`
  -> 31 passed, zero failed in 0.27s.
- `cargo check --locked --all-features --all-targets` -> pass in 1m14s with
  no warnings.
- `cargo clippy --locked --all-features --all-targets -- -D warnings` -> pass
  in 1m05s with no warnings.
- `cargo test --locked --all-features --all-targets -- --test-threads=1` ->
  2,649 passed, six failed, one ignored in 61.48s before Cargo stopped after
  the library target. The six failures were exactly the linked-worktree
  `tools::worktree` failures tracked by #1055: the two enter tests, two exit
  tests, current-branch test, and list-worktrees test. They fail because the
  fixture reports that the linked checkout is not a Git repository. No S-005
  test failed; this independent defect was not duplicated or expanded here.
- `cargo check --locked --all-features --all-targets --target x86_64-pc-windows-gnu`
  -> pass in 3m35s. The target was available. It emitted only pre-existing
  Windows-conditional unused/dead-code warnings outside S-005 in secure file
  handling, bash integration/helpers, hooks permission tests, legacy-rule
  removal tests, plan mode, file-race tests, session capability/filesystem
  tests, secret-redaction tests, plugin Git/manager tests, TUI tests, OAuth,
  and LSP. No S-005 path emitted a warning.

An unrelated user-owned Cargo pipeline in `/home/doll/Palimpsest` overlapped
the already-running OpenClaudia full suite after its compile began. It caused
no observed resource-pressure failure. The Windows gate was held until both
repositories were idle.

The repair cycle was retained as negative evidence rather than hidden:

- The first environment-unit compile failed with one under-constrained JSON
  source type and two negative-test `Debug` bounds. The source was typed
  explicitly and the tests now destructure `Err` without adding secret-bearing
  debug surfaces.
- The first executable environment-unit run passed nine tests and failed two
  because the exhaustive fixture used an invalid reasoning-effort sample. The
  sample now uses the accepted non-default `high` value, and both exhaustive
  tests pass.
- The first integration build passed all five process tests but exposed
  test-only ACP wrappers as production dead code. They are now `cfg(test)`,
  and the rerun was warning-free.
- Successive strict Clippy attempts exposed documentation/line-count, raw
  string delimiter, branch-semicolon, borrowed-parser, duplicate match-arm,
  and exact-float-test findings in the new code. Each was corrected at cause
  without weakening assertions or adding lint suppressions; the final strict
  all-target gate is clean.

Non-Cargo provenance and integrity checks:

- `git branch --show-current` -> `agent/refactor-s005-typed-environment`
- `git rev-parse HEAD` -> `9194ac26e08e899a2acb7336523f5f9bafb463fd`
- `git diff --check` -> pass (no output)
- static registry enumeration -> 59 application fields, 16 providers, nine
  provider fields, 437 exact names, 437 unique names, zero duplicates
- source audit of `OPENCLAUDIA_` consumers -> every non-config subsystem name
  is explicitly routed; generic underscore environment loading and ad-hoc API
  key repair are absent from the changed loader

## Scope boundary and unresolved verification

- F-013 environment ambiguity is in this slice. W14's broader unification of
  the main and ACP file loaders, per-value runtime provenance API, and uniform
  unknown-YAML rejection are separate architectural work and are not silently
  expanded here. ACP is aligned only for its one supported environment field.
- The only independently observed repository defect is the already-tracked
  linked-worktree test failure in #1055; S-005 created no duplicate issue.
- Canonical artifact-bound VDD evidence does not yet exist. Queue this slice's
  retrospective artifact and runtime receipt under S-088 after S-088 exists;
  do not treat the local exhaustive/adversarial tests as canonical VDD.

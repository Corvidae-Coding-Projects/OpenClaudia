# S-016: Require effect classification for every tool

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-001, F-052
Workstreams: W2, W20
Depends on: [S-011](./011-canonical-typed-tool-results.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make unknown or omitted tool effects fail closed, including shell-like Crosslink mutations.

The implementation now classifies a concrete invocation before policy or
auto-allow evaluation. Only a declared `ReadOnly` effect bypasses
authorization. Unknown tools, malformed envelopes, missing/malformed effect
targets, and unrecognized typed operations deny instead of inheriting a safe
default.

## Implementation boundary

- Require every static and dynamic handler to declare typed effect targets before registration; eliminate default `None`/safe behavior.
- Replace Crosslink argv dispatch with typed operations whose exact reads and mutations are known before policy evaluation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Delivered design

- `ToolHandler::effect_spec` is mandatory. Registry construction validates
  canonical names, schema identity, target field type/requiredness, typed
  resolver/table consistency, duplicate operations, and per-operation effect
  ceilings.
- The generated all-feature effect matrix contains 41 surface rows derived
  from live declarations: 36 registry handlers, three subagent tools, the
  dynamic MCP surface, and an explicit unavailable plugin surface. The
  Crosslink row carries 25 typed operations from the same operation table used
  for dispatch.
- Read-only, session mutation, workspace mutation, network read, external
  mutation, and destructive are explicit effect levels. Permission traces
  record the classification before policy without adding raw target data to
  the new classification event.
- Dynamic MCP calls receive a conservative destructive ceiling. Plugin-prefixed
  names remain unavailable until their capability surface is implemented.
- Crosslink no longer accepts opaque argv. It accepts a typed `operation` enum,
  retains the established `ready`, `help`, `--help`, and `-h` spellings, and
  dispatches all 25 operations through the library API. Store-backed queries
  are workspace mutations because opening the store can initialize schema;
  true help is a no-store read.
- Frontend hard-coded safe lists were removed. REPL, main, pipeline, proxy, and
  dynamic MCP dispatch consult the shared effect classifier. Explicit denials
  now precede read-only and session-local defaults.

## Adversarial review corrections

The inherited implementation was not accepted on its focused tests. Reviewing
changed tests against real schemas and call paths found and corrected:

- A deny-precedence test inserted the deny rule first and therefore did not
  prove precedence. It now inserts a broad allow first and a narrower deny
  second.
- A read-denial test used the noncanonical identity `list_files`; it now drives
  the production `Read` capability with a concrete denied path.
- Subagent effect coverage compared names copied from the same implementation.
  It now independently compares published wire schemas and effect targets.
- Every `exit_worktree` mode was initially understated. The executor ends in
  `git worktree remove --force`, and argument-only classification cannot prove
  ignored files are absent, so all modes are destructive. The operation label
  still distinguishes apply, discard, and nominally clean requests.
- Canonical registry calls use names such as `write_file` and argument `path`,
  while older tests fabricated `Write` and `file_path`. Canonical calls are now
  traced while compatibility aliases remain supported.
- Crosslink compatibility spellings were missing from the typed table and were
  restored. Every declared operation now runs against an isolated real store.
- Early effect denial had regressed established missing-argument diagnostics
  for `kill_shell` and `task`. Missing targets remain fail-closed and now report
  that the named argument is required.
- Two glob tests accidentally used an invalid empty Bash command to test the
  pure matcher. Pure glob empty-string semantics are now pinned independently;
  permission checks prove that neither an empty pattern nor `**` authorizes an
  empty required effect target.

## Acceptance

- Registry construction fails for an unclassified handler and unknown dynamic tools are unavailable.
- A generated matrix proves every tool path, including task, cron, worktree, process, MCP, plugin, and Crosslink actions, has an enforced effect.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Verification evidence

All Cargo commands were serialized with `CARGO_BUILD_JOBS=1`; test commands
also used `--test-threads=1` to respect host RAM limits.

- The nine modified integration binaries passed together: 213 tests.
- `mandatory_tool_effect_classification_e2e`: 52 passed.
- Permission-manager filters: 100 passed; Crosslink units: 9 passed;
  worktree units: 26 passed; direct tool tests: 54 passed; Bash integration:
  40 passed; effect resolver units: 8 passed; permission glob semantics:
  27 passed.
- `cargo check --all-features --all-targets`: passed.
- `cargo clippy --all-features --all-targets -- -D warnings -A
  clippy::large_enum_variant`: passed.
- Strict Clippy reports only four pre-existing `large_enum_variant` findings in
  `runtime/event.rs`, `tools/mod.rs` (two enums), and `tui/events.rs`. No other
  warning category remains.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
- The complete all-feature suite was run repeatedly because it exposed stale
  integration assumptions. The S-016 regressions it found were repaired and
  their containing binaries pass. A pre-existing ACP cancellation test remains
  timing-flaky: it has both passed and failed unchanged across full runs, most
  recently leaving 2,608/2,609 library tests passing; the exact failed test
  passed immediately in isolation. This is recorded as unresolved rather than
  represented as a green full-suite receipt.

## Unresolved and downstream work

- S-017 owns normalized, generation-bound approval receipts, trusted storage,
  expiry/use limits, and redaction of existing raw permission-decision logs.
  This slice only establishes the deny-first prerequisite.
- S-018 owns eliminating optional-manager and unchecked dispatch paths and
  enforcing a hard host-side ceiling at every frontend.
- S-052 owns blocker-aware Crosslink coordination and fully agent-scoped
  session operations. Crosslink path capability/migration transactions,
  create-plus-label atomicity, bounded results/tree traversal, cycle handling,
  and approval granularity remain outside this slice.
- S-064 owns proving activated dynamic MCP reachability and dispatch rather
  than only its conservative policy surface.
- S-073 owns transactional worktree exit and ignored-file-aware cleanup; the
  destructive classification is intentionally conservative until then.
- The `agent_output` wire schema requires an id although its executor supports
  no-id listing; the effect target permits that behavior conservatively.
- The ACP daemonized-descendant cancellation race should receive a separate
  lifecycle slice; this change neither weakens nor rewrites that test.
- S-088 must attach the canonical artifact-bound VDD receipt using the same
  harness, guardrails, and reality-grounding facilities as the builder.

## Handoff

The matrix and Crosslink operation inventory are generated at runtime from the
same declarations used by dispatch; no second tracked snapshot was added that
could drift. Record the final staged-diff digest and commit in Crosslink issue
#1005. Completion of this slice does not imply completion of its parent
workstream.

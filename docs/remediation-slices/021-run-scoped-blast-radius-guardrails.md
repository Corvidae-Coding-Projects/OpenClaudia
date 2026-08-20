# S-021: Make blast-radius guardrails atomic and run scoped

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-084
Workstreams: W2
Depends on: [S-016](./016-mandatory-tool-effect-classification.md), [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Apply file, line, tool, and mutation limits as atomic reservations against canonical run effects.

## Implementation boundary

- Replace lexical traversal and process-global counters with normalized capability targets and per-run/session reservations.
- Fail configuration atomically on invalid patterns or zero/ambiguous limits and reconcile reservations on success, denial, cancellation, and partial effects.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Concurrent runs cannot consume or reset each other's quotas, and traversal/symlink aliases resolve to one protected resource identity.
- All mutating tool families are covered and exceeding a limit prevents the effect before execution.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Blast-radius state is now keyed by the exact `RunId` and capability
  generation instead of process-global turn counters. Starting, ending, or
  consuming quota in one run cannot reset or consume another run's ledger, and
  an exact live run cannot be reconfigured to regain spent quota.
- Guardrail configuration is compiled completely before publication. Empty or
  invalid patterns, zero limits, and ambiguous simultaneous legacy/current
  file-limit keys fail without replacing the prior valid policy. The legacy
  `max_files_per_turn` spelling remains a deserialization alias for
  `max_files_per_run`, rather than a second source of truth.
- Tool calls, mutation capacity, changed-line capacity, and unique canonical
  file resources use pending/committed reservations. RAII release protects
  definite pre-effect failures and cancellation; successful and typed partial
  effects commit. Reservation, commit, and release trace events carry the exact
  run and resource identity without logging file contents.
- Mandatory effect metadata now declares whether a target is an exact path, a
  recursive path scope, a tool-only effect, or opaque. The canonical dispatcher
  resolves that metadata and acquires the reservation before invoking every
  registered tool, including the special subagent path and remote MCP calls.
  Registry validation prevents a handler from silently omitting the metadata.
- Capability-relative path normalization resolves existing ancestors and
  symlink aliases to a stable resource identity. Relative and absolute aliases
  therefore share one file charge. Recursive `list_files`, `glob`, and `grep`
  enumerate through descriptor-safe filesystem operations, check each
  discovered leaf against policy, distinguish traversal from directory-name
  disclosure, and reserve their unique-file batch atomically before
  disclosure. Statically denied subtrees are pruned before opening.
- `write_file`, `edit_file`, and notebook edits compute exact changed-line
  counts from the old and proposed content and reserve line/mutation capacity
  before publishing the effect. Their reconciliation distinguishes definite
  no-effect failures from writes that may already have reached the filesystem;
  a denied new write does not create its target.
- Bash now reports timeout, wait failure, and nonzero exit after process start
  as typed partial external outcomes. Subagent registration/consumption and
  remote MCP dispatch likewise preserve causal receipts where an effect has
  begun or its remote result is unknowable, so quotas cannot be regained by
  presenting uncertainty as a clean failure.
- Every run-producing frontend configures guardrails before making the new run
  visible or retiring its predecessor. Subagent provider turns receive the same
  run-scoped policy boundary as primary chat, proxy, pipeline, and TUI paths.

## Architecture decision

The selected design puts one transaction boundary around the canonical effect
dispatcher:

`ToolEffectSpec` → normalized target → atomic reservation → handler → typed
outcome → commit/release.

This boundary is earlier than the effect and shared by all frontends. It avoids
the former split design in which pipeline-only read checks, tool-name guesses,
and process-global mutable counters could disagree or be bypassed by another
dispatcher. It also makes uncertainty explicit: a definite pre-effect denial
releases capacity, while a started or remotely published effect commits unless
a handler can prove otherwise.

Recursive tools use a two-stage reservation deliberately. The call-level
reservation is obtained before execution; descriptor-safe enumeration then
produces concrete canonical leaves, which are policy-checked and batch-reserved
before their names or content are returned. This preserves pre-effect denial
for disclosure while avoiding lexical guesses about a directory's eventual
contents.

## Artifact generation

- Generation: `S021-G1`.
- Baseline commit: `b4bb498691a1c20a653a0713787b26da9402b9a6`.
- Source/test artifact digest: SHA-256
  `d2c9232b14b01c107bbba0ad69ef04571753ca88603a64207facc24ab970e07e` over
  `git diff --cached --binary HEAD -- src tests` after formatting, strict
  Clippy, the complete test suite, and explicit staging. Any source/test
  artifact change invalidates it.
- Scope: run lifecycle integration; guardrail configuration and ledgers;
  mandatory tool target metadata and dispatch; Bash, subagent, and MCP partial
  receipts; descriptor-safe recursive reads; exact changed-line accounting;
  and adversarial unit/integration coverage.

## Acceptance evidence

| Receipt | Evidence | Result |
| --- | --- | --- |
| `S021-E1` | `path_normalization_is_declared_metadata_not_tool_name_guessing` and the mandatory-effect registry suite prove exact path, recursive scope, tool-only, and opaque targets come from validated handler metadata. | Pass |
| `S021-E2` | `reservation_trace_records_exact_run_resource_and_terminal_state` proves reservation, release, and commit telemetry identifies the exact run/resource and terminal state. | Pass |
| `S021-E3` | Invalid reconfiguration and config-deserialization tests prove malformed patterns, zero limits, and ambiguous old/new keys fail atomically while the preceding valid policy remains authoritative. | Pass |
| `S021-E4` | Relative/absolute and symlink-alias tests prove equivalent paths consume one canonical unique-file identity. | Pass |
| `S021-E5` | Exact-run quota isolation, same-run immutability, and failed-call reuse tests prove one run cannot reset another and definite no-effect failures release their pending reservations. | Pass |
| `S021-E6` | Recursive read-family, allowed-scope, directory-disclosure, and atomic batch-denial tests drive `list_files`, `glob`, and `grep` through public dispatch and prove concrete children are checked and charged before disclosure. Empty denied subtrees and unrelated directory names outside an allow-list are not returned. | Pass |
| `S021-E7` | Changed-line and cross-family mutation tests prove denial occurs before target creation/effect and a released denial can be used by a later admissible call. | Pass |
| `S021-E8` | Partial Bash, subagent, file-write, and MCP paths preserve causal uncertainty as committed reservations; the Linux sandbox tests separately prove the attempted host-file, network, control-state, and namespace effects did not escape containment. | Pass |
| `S021-E9` | Startup and subagent tests prove every run context is configured before provider/tool activity and is removed when its final context is dropped. | Pass |

## Verification record

All Cargo compilation used `CARGO_BUILD_JOBS=1`; all tests used
`--test-threads=1` to respect host RAM limits.

- `cargo fmt --all -- --check` — pass.
- `CARGO_BUILD_JOBS=1 cargo check --all-features --all-targets` — pass.
- `CARGO_BUILD_JOBS=1 cargo clippy --all-features --all-targets -- -D warnings`
  — pass with the repository's strict lint profile.
- `CARGO_BUILD_JOBS=1 cargo test --all-features -- --test-threads=1` — pass
  for the complete project: 2,618 library tests, every binary and integration
  target, and doc tests; only explicitly ignored cases remained ignored.
- Focused gates passed for `run_scoped_blast_radius_guardrails_e2e` (14),
  `config_guardrails_session_e2e` (26),
  `mandatory_tool_effect_classification_e2e` (52), guardrail library tests
  (57), subagent module tests (68), `bash_integration` (40), and the broad
  integration target (131 passed, 2 ignored).
- `git diff --check` — pass.

The complete-suite review initially exposed five stale sandbox assertions and
one broad Bash assertion that equated a started process's nonzero exit with a
definite no-effect error. They were corrected only after verifying the concrete
sandbox non-effects remained independently asserted. The final complete run
above is clean after those test corrections.

## Unresolved risks and queues

- S-088 remains planned, so no canonical artifact-bound alternate-model VDD
  receipt can honestly be issued yet. Queue `S021-G1` and its final staged
  digest for retrospective VDD; any artifact change invalidates that queue.
- S-031 owns descriptor-safe persistent publication and typed filesystem
  uncertainty. In particular, parent-directory creation followed by a later
  create/write failure cannot yet express every partial filesystem mutation in
  `secure_fs`'s string error surface. S-021 conservatively commits observed or
  possible published writes but does not duplicate S-031's storage redesign.
- S-022 owns final-state diff reconciliation. Arbitrary Bash and worktree
  execution are conservatively one opaque mutation reservation here because
  the guardrail layer cannot yet enumerate their exact final file/line delta.
- S-073 owns worktree runtime isolation and S-040 through S-042 own deeper
  process I/O, background ownership, and sandbox profiles. This slice preserves
  their existing containment boundary without claiming those outcomes.

No additional remediation slice or Crosslink issue was created. The only
newly exposed uncertainty is already owned by S-022/S-031, while the stale Bash
test expectations were an in-scope compatibility correction rather than a new
product defect.

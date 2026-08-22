# S-020: Replace Bash auto-approval heuristics

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-045, F-050
Workstreams: W2, W18
Depends on: [S-016](./016-mandatory-tool-effect-classification.md), [S-018](./018-non-bypassable-host-safety-policy.md), [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop classifying arbitrary shell text as read-only and remove the bypassable optional path gate as an authority boundary.

## Implementation boundary

- Parse only a deliberately small typed command facade for auto-approved read effects; classify general shell execution as process/workspace mutation requiring policy.
- Enforce filesystem/process capabilities in the sandbox rather than lexical path substrings, retaining lexical checks only as defense-in-depth.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Mutation hidden behind aliases, interpreters, quoting, substitutions, redirection, scripts, or mixed pipelines cannot receive read-only approval.
- The optional path-gate flag and its security claims are removed or reduced to an explicitly non-authoritative lint.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Auto-approval now derives exclusively from the mandatory typed effect
  resolver introduced by S-016. A concrete invocation declared `ReadOnly`
  scores `1.0`; every effectful, malformed, or unknown invocation scores
  `0.0`. The former Bash program-name prefixes, destructive substrings, edit
  path prefixes, and intermediate confidence values are gone.
- The registered `bash` handler remains conservatively declared
  `Destructive`. `ls`, `cat`, VCS/package commands, interpreters, aliases,
  substitutions, redirects, scripts, and pipelines therefore all require an
  explicit policy decision. Users retain the intended shell feature: exact
  user policy and one-use approval receipts still authorize non-catastrophic
  Bash calls, and the sandbox still bounds the resulting process.
- Typed `read_file`, `list_files`, `glob`, and `grep` operations are the small
  read facade. Their argument envelopes and targets must parse successfully
  before their positive `ReadOnly` declaration can admit them.
- The public rejecting `PathConstraints` surface and its allow/deny tests were
  removed. A private run-scoped lexical scan now emits only the structured
  `non_authoritative_path_lint` telemetry event. It returns no permit or error,
  logs no raw command/path, and cannot influence permission or dispatch.
- Linux filesystem/process enforcement remains in the descriptor-pinned
  bubblewrap sandbox built from `ToolRunContext`. The escape suite now passes a
  literal external host path through the linter and proves that the sandboxed
  process cannot observe it. macOS, Windows, and unsupported platforms retain
  the S-018 fail-closed behavior unless the host user explicitly disables the
  sandbox outside model/project authority.

## Architecture decision

The selected design reuses one authority vocabulary from registration through
dispatch:

`ToolHandler::effect_spec` → `resolve_for_call` → `PermissionManager` → exact
dispatch permit → `ToolRunContext`/OS sandbox.

The credible alternative was to parse a nominally safe subset of shell syntax
and downgrade recognized commands. That would still depend on executable
behavior, shell expansion, aliases/functions, project scripts/configuration,
plugins, environment, pipelines, and platform-specific parsing after the
classification point. It would require an open-ended parser and executable
semantics database, create unsafe migration/rollback pressure whenever the
shell evolved, and duplicate the already typed read tools. The selected design
has a smaller maintenance and security surface: unknown/general shell text is
effectful, typed reads are explicit, and rollback cannot silently restore the
unsafe heuristic.

Compatibility is preserved at the real product boundary. Explicit Bash rules,
bounded receipts, unrestricted host policy subject to the hard safety ceiling,
foreground/background execution, and result formatting are unchanged. The
legacy numeric compatibility API remains binary and fail-closed; source-wide
search found that it has no production caller, which is tracked honestly as
Crosslink issue #1030 rather than being presented as an operational auto-mode.

## Artifact generation

- Generation: `S020-G1`.
- Baseline commit: `9bc74ceb1404f0d23f44dfd0f032510617449eed`.
- Source/test artifact digest: SHA-256
  `1700eb04920f15b8e4c633e6f54d781fd2998443e1e9fedc1974085b37e13caa`
  over `git diff --cached --binary HEAD -- src tests` after formatting, strict
  Clippy, and explicit staging. Any source/test artifact change invalidates it.
- Scope: six source files and seven test files; 617 insertions and 1,780
  deletions. This covers permission classification, Bash policy/path
  diagnostics and exports, adversarial classifier/dispatch tests, and the
  Linux sandbox escape proof. The Crosslink-generated S-019 changelog residue
  and the user's previously requested removal of one tracked generated
  `__pycache__` artifact are preserved and identified separately rather than
  hidden inside the security implementation.

## Acceptance evidence

| Receipt | Evidence | Result |
| --- | --- | --- |
| `S020-E1` | `arbitrary_shell_text_is_always_destructive_and_requires_policy` resolves benign-looking Bash plus VCS, package, interpreter, nested-shell, alias, wrapper, quoting, substitution, redirect, script, and mixed-pipeline families through the real registry. Every call remains `Destructive`, scores zero, and cannot become `Allowed` at thresholds 0.0, 0.5, or 1.0. | Pass |
| `S020-E2` | `public_dispatch_does_not_execute_hidden_mutation_without_policy` drives seven mutation families through the public gated executor, requires typed `PermissionDenied`, and proves each workspace canary remains absent. | Pass |
| `S020-E3` | `only_declared_typed_reads_receive_auto_approval`, malformed/unknown cases, explicit read denial, invalid thresholds, and workspace mutation tests prove positive classification requires a valid typed `ReadOnly` envelope and cannot override a denial. | Pass |
| `S020-E4` | `explicit_user_policy_still_authorizes_non_catastrophic_bash` proves heuristic removal did not remove the intended shell feature or explicit user authority. | Pass |
| `S020-E5` | Private path-lint unit tests prove useful literal/traversal diagnostics and explicitly pin variable, redirect-attached, script, and sourced-path misses so the test suite cannot misrepresent the scanner as complete. | Pass |
| `S020-E6` | `host_file_network_and_kernel_trees_are_absent` sends a literal external path into Bash, observes successful process execution, and proves the host file is absent inside the namespace; all eleven Linux escape probes pass. | Pass |
| `S020-E7` | The mandatory effect-classification suite proves the production registry matrix and authorization boundary still classify and gate every tool surface. | Pass |

## Verification record

All Cargo compilation used `CARGO_BUILD_JOBS=1`; all tests used
`--test-threads=1` to respect host RAM limits.

- `cargo fmt --all -- --check` — pass.
- `CARGO_BUILD_JOBS=1 cargo check --workspace --all-targets --all-features` —
  pass.
- `CARGO_BUILD_JOBS=1 cargo clippy --workspace --all-targets --all-features -- -D warnings`
  — pass with the repository's strict lint profile.
- `CARGO_BUILD_JOBS=1 cargo test --workspace --all-features -- --test-threads=1`
  — pass for the complete workspace: 2,618 library tests, every binary and
  integration target, and doc tests; only explicitly ignored cases remained
  ignored.
- `CARGO_BUILD_JOBS=1 cargo check --target x86_64-pc-windows-gnu --all-features --lib`
  — build pass; exposed one unrelated pre-existing target-only warning tracked
  as #1031.
- Focused gates passed for Bash path-lint unit tests (3),
  `bash_effect_classification_e2e` (7), `permissions_score_denial_e2e` (16),
  `bash_policy_validate_e2e` (21), `tools_security_e2e` (6),
  `sandbox_escape_e2e` (11), and
  `mandatory_tool_effect_classification_e2e` (52).

## Unresolved risks and queues

- S-088 remains planned, so no canonical artifact-bound alternate-model VDD
  receipt can honestly be issued yet. Queue `S020-G1` and its final staged
  digest for retrospective VDD; any artifact change invalidates that queue.
- Crosslink issue #1030 records the newly confirmed dormant threshold API.
  S-020 secures it and the production dispatcher, but does not silently invent
  an auto-mode product/configuration contract or delete a public compatibility
  surface without a migration decision.
- Crosslink issue #1031 records a pre-existing Windows-only dead-code warning
  on `SecureDirectory.context` exposed by the successful cross-target library
  check. It belongs to the secure-files portability boundary, not Bash
  classification; this slice did not hide it or weaken warnings.
- S-040, S-041, and S-042 still own foreground I/O supervision, background
  process ownership/output, and least-privilege sandbox profiles. S-020 does
  not claim those broader W18 outcomes.
- The deny-only Bash string scanner intentionally remains bypassable and may
  produce false positives. It cannot grant authority; removing or replacing
  that diagnostic is not required for F-045/F-050 once typed effects and OS
  containment are decisive.

No additional remediation slice was created. Newly discovered work is tracked
on #1030 within the typed-policy/runtime-mode boundary and #1031 within the
existing secure-files portability boundary.

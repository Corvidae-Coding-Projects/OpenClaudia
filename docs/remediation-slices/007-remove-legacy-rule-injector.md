# S-007: Remove the legacy rule injector completely

Status: Implemented — awaiting verification
Effort: Medium
Primary findings: F-007
Workstreams: W1
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Delete automatic language/project rule injection while preserving neutral file-type detection needed by unrelated features.

## Implementation boundary

- Apply the complete removal manifest from audit Section 6 across Rust callers, hooks, settings, initialization, diagnostics, prompts, assets, and dedicated tests.
- Relocate the neutral extension registry to a non-authority module and add negative tests proving repository rule files cannot enter model context.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- No rule engine symbol, activation hook, generated rule path, product claim, or prompt insertion remains reachable or tracked.
- Auto-learning file recognition still works through the relocated neutral helper, with no instruction-loading behavior.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

Implemented on 2026-08-16. The deterministic gates and an independent review
pass. The slice is deliberately not marked **Verified** because the canonical
alternate-model VDD role does not exist until [S-088](./088-canonical-vdd-verifier-role.md).
S-007 is queued for retrospective VDD against this exact artifact generation.

### Result

- Removed `RulesEngine`, its Markdown loading/combination/reload behavior, and
  every rule prompt insertion from the main/TUI, legacy chat REPL, ACP, proxy,
  shared tool-executor, doctor, and initialization paths.
- Added the private neutral `src/file_types.rs` registry for auto-learning and
  lifecycle-hook extension metadata. It recognizes canonical OpenClaudia names
  and arguments (`write_file`/`edit_file`/`read_file` with `path`) plus bounded
  compatibility aliases; it has no filesystem or prompt access.
- Removed rule directories, templates, generators, startup tips, health claims,
  Python injectors, repository activation settings, rule-hook examples, marker
  helpers, and the four dedicated positive rule-engine suites.
- Repository-local `.openclaudia/output-style.md` is no longer a source of
  authority. User-owned `~/.openclaudia/output-style.md` remains supported.
- Added negative context/source/config tests and a serialized canonical
  `write_file` hook trace proving extension metadata is flat data rather than
  an instruction payload. Updated the existing `/init` and output-style tests
  to assert the removed behavior stays absent.
- Preserved skills, direct user instructions, hook/plugin infrastructure,
  permissions, sandboxing, auto-learning, and user-owned output preferences.
  Replacement of `src/claude_code_prompt.txt` remains assigned to W12 and was
  intentionally not pulled into this slice.

### Artifact generation

The implementation generation is `sha256:0d3b75a6d4f8f06ab0d9841f0fe9c0cf05d48e0f37fa14425265e5b59bf87a16`. It is the
SHA-256 of the lexicographically sorted manifest whose live records are
`<file-sha256>  <repository-relative-path>` and whose removal records are
`ABSENT  <repository-relative-path>`. The receipt itself and the canonical
audit/design annotations are excluded, so recording evidence cannot invalidate
the implementation generation.

Live artifact inventory:

- Runtime: `src/file_types.rs`, `src/lib.rs`, `src/main.rs`, `src/acp.rs`,
  `src/proxy.rs`, `src/tui/app.rs`, `src/cli/chat_repl.rs`,
  `src/services/tool_executor.rs`, `src/auto_learn.rs`, `src/context.rs`,
  `src/output_style.rs`, `src/cli/commands/doctor.rs`,
  `src/cli/commands/init.rs`, `src/cli/display/tips.rs`,
  `src/cli/repl/slash.rs`, `src/slash_commands.rs`,
  `src/providers/anthropic.rs`, `src/session/state.rs`, and
  `src/state/categories.rs`.
- Configuration and migration documentation: `.claude/settings.json`,
  `.claude/hooks/crosslink_config.py`, `.openclaudia/config.yaml`, `.gitignore`,
  `README.md`, `ARCHITECTURE.md`, `CLAUDE.md`, and `CHANGELOG.md`.
- Tests: `tests/legacy_rule_injector_removed_e2e.rs`,
  `tests/output_style_lifecycle_e2e.rs`, and `tests/cli_exit_status_e2e.rs`.

Removal inventory:

- `src/rules.rs`, `.claude/hooks/prompt-guard.py`,
  `.claude/hooks/pre-web-check.py`, and `.openclaudia/rules/global.md`.
- `.chainlink/rules/{c,cpp,csharp,elixir-phoenix,elixir,global,go,java,`
  `javascript-react,javascript,kotlin,odin,php,project,python,ruby,rust,scala,`
  `swift,typescript-react,typescript,web,zig}.md`.
- `tests/{rules_context_e2e,rules_accessors_e2e,rules_engine_deep_e2e,`
  `extract_extensions_matrix_e2e}.rs`.

### Deterministic evidence

| Gate | Result |
|---|---|
| `cargo clean` in the root and fuzz crates | Passed before implementation; removed the stale build products requested for this audit |
| `cargo check --workspace --all-targets --all-features` | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed |
| `cargo fmt --all -- --check` | Passed |
| S-007, output-style, and `/init` targeted suites | Passed, 65 tests |
| `.claude/settings.json` JSON and `.openclaudia/config.yaml` YAML parsing | Passed |
| Residual loader/activation/path scan | Passed; matches are confined to negative tests and removal/migration documentation |
| `git diff --check` | Passed |
| Independent fresh-context review | Passed after two caught-and-fixed gaps; no blocking implementation finding remains |
| `cargo test --workspace --all-features -- --test-threads=1` | Passed in one final run: 2,661 library tests, 215 binary tests, all 231 integration targets, and doc tests; environment-dependent ignored tests remained ignored |

Two parallel repository-wide attempts each exposed a different timing-sensitive,
out-of-scope ACP test; each exact isolated rerun passed, and both pass under the
serialized final gate. The first serialized pass then exposed README contract
sections removed during the earlier documentation audit. The current provider,
tool, worktree, and scheduler catalogs were restored with explicit
non-production-readiness caveats, their exact contract tests pass, and the
single-command final rerun above is green. These events are retained here so
the receipt does not hide failed attempts or substitute targeted results for the
full gate.

### Interim typed receipt

```yaml
receipt_type: remediation_slice_deterministic_verification
schema_version: 1
slice_id: S-007
artifact_generation: sha256:0d3b75a6d4f8f06ab0d9841f0fe9c0cf05d48e0f37fa14425265e5b59bf87a16
implementation_state: implemented
deterministic_verdict: pass
independent_review:
  context: fresh
  verdict: pass
  blocking_findings: 0
vdd:
  verdict: not_run
  queue_state: retrospective_pending_s_088
  reason: canonical alternate-model verifier role is not implemented
```

This is an interim, human-readable receipt, not the future canonical receipt
schema owned by S-001/S-088.

### Review findings resolved

1. The reviewer found a stale positive `/init` integration assertion that still
   expected `.openclaudia/rules/global.md`. The test now preserves its
   config/hooks/plugins assertions while requiring the rule path to be absent.
2. The reviewer found that the first neutral-helper version only recognized
   Claude-style `Write`/`file_path`, while real OpenClaudia callers provide
   `write_file`/`path`. Canonical names and argument keys are now first-class,
   compatibility aliases remain bounded, and the hook trace uses the canonical
   dispatch shape.

### Unresolved risks and follow-up

- Required VDD remains queued until S-088; artifact mutation after this receipt
  must invalidate this generation and require the deterministic gates and VDD
  queue entry to be regenerated.
- Negative runtime coverage uses one prompt-builder execution plus structural
  assertions over every removed frontend rather than dynamically booting TUI,
  REPL, ACP, and proxy separately. The independent reviewer rated this low and
  non-blocking because the removed symbols/activation paths are also checked
  structurally.
- No new defect or adjacent remediation slice was discovered. The existing W12
  prompt replacement, W13 generated-artifact hygiene, and S-088 verifier work
  retain their original ownership.

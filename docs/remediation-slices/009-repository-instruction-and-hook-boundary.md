# S-009: Remove repository-owned control authority

Status: Implemented — awaiting verification
Effort: Medium
Primary findings: F-140
Workstreams: W1, W12, W25
Depends on: [S-007](./007-remove-legacy-rule-injector.md), [S-008](./008-typed-context-authority-and-budget.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop inherited prompts and repository hooks from impersonating host policy or silently controlling agent behavior.

## Implementation boundary

- Replace the inherited monolithic Claude prompt with minimal accurate host-owned policy and remove identity/tool claims that do not match the runtime.
- Make repository hook/settings discovery an explicit reviewed import; repository content remains data until a host capability grants a typed extension.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A malicious checkout cannot activate executable hooks or add system instructions merely by containing recognized files.
- Compatibility imports display source, digest, requested events/effects, and require reapproval after mutation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

Implemented on 2026-08-16. The deterministic gates pass. The slice is not
marked **Verified** because the canonical alternate-model VDD role does not
exist until [S-088](./088-canonical-vdd-verifier-role.md). S-009 is queued for
retrospective VDD against the exact artifact generation below.

### Result

- Replaced the inherited persona/tool monolith with four small, accurate
  host-owned policy fragments. The base prompt no longer asserts a Claudia
  identity override, a provider/model identity, a static tool catalog, XML
  invocation syntax, browser availability, chainlink availability, or
  permissions that the current request did not supply. Runtime-attached tool
  schemas are explicitly authoritative.
- Removed ambient repository hook authority from both recognized families.
  The `hooks:` block in `.openclaudia/config.yaml` is stripped before ordinary
  project-config deserialization, while `.claude/settings.json` and
  `.claude/settings.local.json` no longer enter the trusted Claude settings
  merge merely because they exist.
- Added a bounded compatibility-import proposal for those three repository
  sources. A proposal records canonical workspace/source paths, kind, source
  SHA-256, deterministic proposal SHA-256, requested events/effects, exact
  command strings, action count, and the path/size/SHA-256 of repository
  program sources. Unknown fields/events, partial schemas, repository policy,
  `shell:true`, invalid timeouts, oversized inputs, symlink escapes, and
  currently unwired model hooks fail atomically and visibly.
- Added exact approval and revocation receipts in a host data-directory store,
  with no repository-relative production fallback. Receipts bind the
  canonical workspace, source bytes, events, effects, commands, and repository
  source files. Mutation changes the proposal to `changed` and leaves it
  inert. Generated Python `__pycache__`/bytecode is excluded from recursive
  package binding so running a hook cannot invalidate its own receipt.
- Preserved command hooks as direct-spawn actions under the existing full OS
  sandbox with a static executable allowlist. Approved lower-authority imports
  are composed below user, managed, and native host hooks; host matchers and
  policy win, and an import allowlist cannot accidentally disable an existing
  host command hook.
- Routed TUI, legacy REPL, ACP, proxy, loop, and slash-status composition
  through the same effective hook loader. Added `openclaudia hooks status`,
  `approve`, and `revoke`; status displays the complete review contract and the
  exact digest command without activating anything.
- Kept the tracked operational hook package. The settings now use direct-spawn
  commands, remove nonexistent heartbeat and ambient tool/MCP enablement,
  recognize canonical OpenClaudia tool names, and emit post-edit observations
  through the typed top-level additional-context field. The work-check hook no
  longer tells an agent to conceal a block from the user.
- Updated the CLI architecture/README/capability inventory and replaced two
  stale positive tests: repository Stop-hook behavior is still exercised after
  an explicit host approval, and human browser documentation remains while the
  model-facing base prompt stays capability-neutral.

### Artifact generation

The implementation generation is
`sha256:6a2337d90765bdf953fdeb5a7b6a7eeaa012a247efd37f6e84c59f29d24157cd`. It
is the SHA-256 of the lexicographically sorted manifest whose records are
`<file-sha256>  <repository-relative-path>`. This receipt and the canonical
audit/design sources are excluded, so recording evidence does not mutate the
implementation generation.

Live artifact inventory:

- Compatibility package: `.claude/settings.json`,
  `.claude/hooks/crosslink_config.py`, `.claude/hooks/post-edit-check.py`,
  `.claude/hooks/session-start.py`, and `.claude/hooks/work-check.py`.
- Minimal host prompt: `prompts/base/identity.md`, `prompts/base/tools.md`,
  `prompts/base/principles.md`, `prompts/base/comms.md`, `src/prompt.rs`, and
  `src/modes/fragments.rs`.
- Trust boundary and composition: `src/config/hooks.rs`, `src/config/mod.rs`,
  `src/hooks/compat_import.rs`, `src/hooks/claude_compat.rs`,
  `src/hooks/merge.rs`, `src/hooks/mod.rs`, `src/main.rs`, `src/acp.rs`,
  `src/proxy.rs`, `src/cli/commands/hooks.rs`, `src/cli/commands/mod.rs`, and
  `src/cli/repl/slash.rs`.
- User-facing inventory: `README.md`, `ARCHITECTURE.md`, and
  `docs/binary-capability-matrix.md`.
- Tests: `tests/repository_hook_import_e2e.rs`,
  `tests/claude_compat_hooks_e2e.rs`, `tests/prompt_builder_e2e.rs`,
  `tests/cli_exit_status_e2e.rs`, and `tests/tool_registry_handler_e2e.rs`.

Removal inventory: none. Operational hook outcomes were repaired and retained;
only stale prompt claims, ambient activation paths, and unsupported repository
authority were removed.

### Deterministic evidence

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| JSON parse of `.claude/settings.json` and AST parse of every `.claude/hooks/*.py` | Passed |
| `cargo check --workspace --all-targets --all-features` | Passed with `CARGO_BUILD_JOBS=1` |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::large-enum-variant` | Passed with `CARGO_BUILD_JOBS=1`; the single named waiver is the pre-existing, out-of-scope `src/tui/events.rs::AppEvent` size finding |
| Repository import trust suite | Passed, 13 tests: inert discovery, exact CLI display/approval, source and bound-script mutation, generated-cache stability, host precedence, direct-spawn behavior, prompt demotion, schema/policy/model/symlink rejection, and canonical hook inputs |
| Claude compatibility suite | Passed, 18 tests |
| Typed prompt integration and unit suites | Passed, 10 integration tests and 3 unit tests |
| CLI contract suite | Passed, 61 tests; the Stop-hook fixture now obtains and approves an exact proposal before exercising shutdown |
| Live tracked proposal trace | Passed; source `sha256:f57858c9cedc7cb0331f65c8c7b26d706aca86955350fd9da5685c51ec624c10`, proposal `sha256:8608b34e8f65a5986ba2715266cdf3133beab9ab82c705be5346875e69cb99b6`, three events, six requested effects, three direct-spawn commands, and four bound source files were displayed as pending |
| Residual prompt/ambient-loader scans | Passed; removed persona, override, static-tool, XML, and ambient repository-loader claims are absent from the active base/composition paths |
| `git diff --check` | Passed |
| `cargo test --workspace --all-features -- --test-threads=1` | Passed in the final serialized run with zero failures across 2,624 library tests, every integration target, and doc tests; explicitly network-dependent tests remained ignored |

The full suite first exposed two obsolete positive claims: one expected an
unapproved repository `shell:true` Stop hook to execute, and one expected the
base prompt to hard-code browser search availability. Both tests were changed
to preserve the real operational outcome under the new boundary, then the
entire suite passed from the top. All heavyweight Cargo gates used one build
job, and the full test gate used one test thread because host swap was nearly
exhausted.

### Interim typed receipt

```yaml
receipt_type: remediation_slice_deterministic_verification
schema_version: 1
slice_id: S-009
artifact_generation: sha256:6a2337d90765bdf953fdeb5a7b6a7eeaa012a247efd37f6e84c59f29d24157cd
implementation_state: implemented
deterministic_verdict: pass
vdd:
  verdict: not_run
  queue_state: retrospective_pending_s_088
  reason: canonical alternate-model verifier role is not implemented
```

This is an interim, human-readable receipt, not the future canonical receipt
schema owned by S-001/S-088.

### Unresolved risks and follow-up

- This slice establishes the required repository boundary, but S-058 still
  owns the complete cross-source trust model: approval-store ownership and
  parent-path checks, source-owner/foreign-source policy, stronger generation
  and TOCTOU binding, and removal of the remaining ambient user-global Claude
  compatibility assumption.
- Approval is re-evaluated when a hook engine is constructed. S-060 owns
  per-invocation revocation/mutation checks, resolved executable and argument
  identity (including PATH, aliases, wrappers, and interpreter/module loads),
  aggregate process/model/time/byte/cost/concurrency admission, and joined
  cancellation. The current bounded direct-spawn/full-sandbox path does not
  claim those later guarantees.
- Repository model hooks are rejected visibly because their provider path is
  not canonical. S-059 owns model-hook wiring and one lifecycle/event ordering
  contract across every frontend; composition through one loader here does not
  prove lifecycle parity.
- The exact provider-required Anthropic OAuth compatibility prefix remains
  outside this prompt cleanup and is owned by S-027, as recorded by S-008.
- Required alternate-model verification remains queued until S-088. Any
  artifact mutation invalidates this generation and requires the manifest,
  deterministic gates, and VDD queue entry to be regenerated.
- No new remediation slice is proposed; all residual work maps to existing
  S-027, S-058, S-059, S-060, and S-088 boundaries.

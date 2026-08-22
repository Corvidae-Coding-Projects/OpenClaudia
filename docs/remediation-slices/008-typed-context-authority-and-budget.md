# S-008: Introduce typed context authority and budgets

Status: Implemented — awaiting verification
Effort: Medium
Primary findings: F-011, F-025, F-026, F-027
Workstreams: W12, W17, W25
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Represent context by provenance, authority, sensitivity, freshness, and budget instead of concatenating arbitrary strings into system instructions.

## Implementation boundary

- Create typed context items and deterministic inclusion/truncation policy; only host-authorized sources may carry instruction authority.
- Convert output-style, hook, memory, skill, project, web, MCP, and tool inputs to source-labeled data and remove raw prompt prefix/suffix APIs.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Untrusted repository or tool text cannot become a system instruction through escaping, wrapping, or source omission.
- Trace fixtures account for every included, omitted, truncated, or promoted context item within a hard token/byte budget.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

Implemented on 2026-08-16. The deterministic gates pass. The slice is not
marked **Verified** because the canonical alternate-model VDD role does not
exist until [S-088](./088-canonical-vdd-verifier-role.md). S-008 is queued for
retrospective VDD against the exact artifact generation below.

### Result

- Replaced raw prompt concatenation with `ContextItem`, `ContextProjection`,
  `ContextBudget`, and `ContextTrace`. Provenance, authority, sensitivity,
  freshness, lane, byte cost, deterministic token upper bound, promotion,
  truncation, inclusion, and omission are explicit receipt fields.
- Made context constructors the authority boundary. Compiled host policy and
  explicit user instructions may enter stable/dynamic instruction lanes;
  hook, memory, skill, project, web, MCP, tool, VDD, IDE, Reality, plugin, and
  session sources default to escaped source-labeled reference envelopes.
- Enforced exact hard system/reference/item byte ceilings and a conservative
  one-token-per-UTF-8-byte total ceiling. Stable/dynamic join bytes and
  reference-envelope overhead are charged. Invalid, duplicate, unavailable,
  empty, secret, truncated, and budget-exhausted candidates all receive
  deterministic dispositions.
- Removed the raw prefix/suffix and system-reminder APIs. Unknown historical
  system messages are demoted to Session reference data. Explicitly
  user-approved plans retain bounded user instruction authority; Reality and
  compaction records retain reference authority. Reference observations append
  causally and no longer rewrite an earlier user turn.
- Migrated main/TUI, legacy REPL, print mode, ACP, proxy, subagents, provider
  request construction, output style, memory/skills/project/IDE context,
  hooks, VDD advisory results, plugin command metadata, Reality grounding, and
  live web-fetch distillation. Provider-native web/MCP/local tool results keep
  their structured tool role and call ID and cannot become system text.
- Preserved operational hooks as typed decisions and observations. A deny
  suppresses every model-visible hook field atomically; legacy
  `systemMessage`, prompt suggestions, model-hook text, and additional context
  are reference-only and multipart user content is preserved.
- Preserved user-owned `~/.openclaudia/output-style.md` as confidential user
  instruction input while repository output-style files remain ignored.
- Closed a proxy ordering bypass discovered during the residual audit:
  compaction now runs before typed preparation, and its model-authored summary
  is a bounded Session reference rather than a new instruction. Raw summary
  text is no longer emitted in debug logs.
- Removed the second, stale `claude_code_prompt.txt` behavioral/identity prompt
  and retained only the exact OAuth compatibility prefix pending S-027. Removed
  three positive suites for the retired unsafe raw APIs; their authority,
  budgeting, multipart, provider-cache, hook, and VDD contracts are covered by
  the replacement typed suites.

### Artifact generation

The implementation generation is
`sha256:7a83e0db4aadcc6a1e7f261440cb2954bfd8c7a3811e3509dfee6d85647898ea`. It is
the SHA-256 of the lexicographically sorted manifest whose live records are
`<file-sha256>  <repository-relative-path>` and whose removal records are
`ABSENT  <repository-relative-path>`. This receipt and the canonical
audit/design annotations are excluded, so recording evidence does not mutate
the implementation generation.

Live artifact inventory:

- Typed context and prompt core: `src/context.rs`, `src/prompt.rs`,
  `src/output_style.rs`, and `src/providers/anthropic.rs`.
- Runtime/frontends: `src/main.rs`, `src/acp.rs`, `src/proxy.rs`,
  `src/pipeline.rs`, `src/grounded_loop.rs`, `src/subagent.rs`,
  `src/tui/app.rs`, `src/cli/chat_repl.rs`, `src/cli/print_mode.rs`,
  `src/cli/repl/plan_mode.rs`, `src/session/mod.rs`, `src/hooks/mod.rs`, and
  `src/tools/web.rs`.
- Authentication/VDD: `src/claude_credentials.rs`, `src/vdd/engine.rs`,
  `src/vdd/error.rs`, `src/vdd/helpers.rs`, `src/vdd/mod.rs`, and
  `src/vdd/transport.rs`.
- Tests: `tests/anthropic_builder_helpers_e2e.rs`,
  `tests/hooks_event_input_e2e.rs`, `tests/integration_tests.rs`,
  `tests/legacy_rule_injector_removed_e2e.rs`,
  `tests/output_style_lifecycle_e2e.rs`, `tests/prompt_builder_e2e.rs`,
  `tests/system_prompt_blocks_to_combined_e2e.rs`, and
  `tests/vdd_triage_e2e.rs`.

Removal inventory:

- `src/claude_code_prompt.txt`.
- `tests/context_injector_e2e.rs`, `tests/prompt_legacy_builders_e2e.rs`, and
  `tests/wrap_system_reminder_deeper_e2e.rs`.

### Deterministic evidence

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets --all-features` | Passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::large_enum_variant` | Passed; the single waiver is for the pre-existing, out-of-scope `src/tui/events.rs::AppEvent` size finding |
| Typed context unit suite | Passed, 9 tests |
| Prompt authority/budget integration suite | Passed, 10 tests |
| Hook, VDD, output-style, legacy-rule-negative, prompt-block, and Anthropic targeted suites | Passed, 96 tests |
| Live web-distillation provenance tests | Passed, 2 tests |
| Proxy client/compaction authority regressions | Passed, 2 tests |
| Removed-API and residual system-role audit | Passed; removed symbols are absent and remaining production system constructors are typed serialization, compiled subrequest policy, or compatibility transcript records reclassified before dispatch |
| `git diff --check` | Passed |
| `cargo test --workspace --all-features -- --test-threads=1` | Passed in one serialized run with zero failures across 2,624 library tests, 215 binary tests, every integration target, and doc tests; explicitly network/browser-dependent tests remained ignored |

The first strict clippy run also reported style warnings in the new context
module; those were corrected before the passing gate above. The unwaived
repository command remains blocked only by the pre-existing large TUI event
enum, which was not changed because it is outside this slice. The full suite
was serialized to avoid false confidence from tests that mutate process-wide
environment/current-directory state and to respect host RAM limits.

### Interim typed receipt

```yaml
receipt_type: remediation_slice_deterministic_verification
schema_version: 1
slice_id: S-008
artifact_generation: sha256:7a83e0db4aadcc6a1e7f261440cb2954bfd8c7a3811e3509dfee6d85647898ea
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

- Anthropic OAuth compatibility still prepends the exact provider-required
  Claude Code identity block outside `ContextTrace`. It is no longer a generic
  behavioral prompt API, but it remains model-visible bytes outside the typed
  budget and an application-identity problem. S-027 owns complete removal and
  supported-auth migration.
- Provider-native web/MCP/local tool results remain typed by role and call ID,
  not yet by the canonical cross-provider result/event schema. S-011 owns that
  end-to-end representation; S-051 owns aggregate conversation/tool/provider
  token and concurrency budgets.
- Legacy transcript storage still represents approved plans, Reality packets,
  and compaction boundaries as JSON system-role compatibility records. Every
  audited provider path reclassifies them before dispatch in this generation;
  S-010 owns the typed event log and S-057 owns removal of prose compaction
  markers/summaries.
- `ContextPromotion` is an explicit compiled-host API with a visible receipt,
  but it is not yet bound to a canonical run/capability issuer or immutable
  evidence generation. There is no production promotion call in this slice.
  S-010 and S-023 own those stronger issuance and evidence bindings.
- Required alternate-model verification remains queued until S-088. Any
  artifact mutation invalidates this generation and requires the manifest,
  deterministic gates, and VDD queue entry to be regenerated.
- No new remediation slice is proposed; all residual work maps to existing
  S-010, S-011, S-023, S-027, S-051, S-057, and S-088 boundaries.

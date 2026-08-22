# S-011: Preserve typed tool results end to end

Status: Implemented — awaiting verification
Effort: Medium
Primary findings: F-032, F-043, F-121
Workstreams: W2, W12
Depends on: [S-008](./008-typed-context-authority-and-budget.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make tool calls and results a typed control plane that ordinary model or tool text cannot impersonate.

## Implementation boundary

- Carry structured success, error, partial, artifact, display, and follow-up data from handler through provider continuation and frontend rendering.
- Retire XML-like interception and sentinel-text parsing; add an explicit reduced-assurance typed adapter only where a provider truly lacks native calls.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Marker-shaped file, shell, web, and model text is rendered as data and never dispatches a tool or terminal event.
- Provider round-trip tests preserve call IDs, arguments, typed results, parallel ordering, errors, and follow-up state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

Implemented on 2026-08-18. Deterministic verification passes. The slice is
not marked **Verified** because the canonical alternate-model VDD role does
not exist until [S-088](./088-canonical-vdd-verifier-role.md). S-011 is queued
for retrospective VDD against the exact artifact generation below.

### Result

- Replaced the lossy string/Boolean result boundary with a schema-versioned
  `ToolExecutionResult`. Every result binds the exact call ID, handler name,
  and raw argument bytes and retains typed success, error, and partial
  outcomes; structured content and completeness; typed failure category and
  retryability; artifacts, attachments, observations, display metadata,
  follow-up lifecycle, usage, and sensitivity.
- Changed the registry's public handler and dispatch contract to
  `ToolHandlerResult`, then binds that result once to the originating
  `ToolCall`. Bash's existing typed `ToolOutput.structured` data now survives
  the migration boundary instead of being discarded. Permission, policy, and
  invalid-argument failures are bound typed failures rather than uncorrelated
  tuples.
- Added `ToolContinuation`, an ordered call/result envelope that rejects
  length, duplicate-ID, call-ID, handler, exact-argument, and pending-follow-up
  mismatches. OpenAI, Anthropic, and Gemini projections retain canonical result
  envelopes; round-trip fixtures prove parallel ordering, errors, raw
  arguments, IDs, and resolved follow-up state.
- Converted user questions and enter/exit-plan requests to trusted typed
  follow-ups with explicit pending, resolved, and cancelled states. CLI and TUI
  paths act on those variants directly and never rediscover control by parsing
  ordinary content.
- Converted edit rendering to trusted `ToolDisplay::Diff` metadata. File,
  shell, web, MCP, plugin, and model text containing old JSON, diff, or XML
  marker shapes remains ordinary data and is rendered/persisted as such.
- Removed the 2,249-line pseudo-XML interceptor and its positive execution
  tests. Anthropic uses its native structured tool loop. Every currently
  supported provider has native structured calls, so no reduced-assurance text
  adapter was necessary or added.
- Migrated live CLI, full-screen TUI, ACP, grounded-loop, tool-executor, and
  subagent result consumers to the typed boundary. Provider-visible text is a
  serialized typed envelope, while frontend presentation is a deterministic
  projection of trusted metadata.

### Artifact generation

The implementation generation is
`sha256:c6bfbb46ac688ea7b4b24e3a81f26296496e43be0ee810984c891d2fe8463060`.
It is the SHA-256 of the lexicographically sorted manifest whose records are
`<artifact-sha256>  <repository-relative-path>`. Live paths use their file
SHA-256. Deleted paths use the tombstone SHA-256
`9874b622c72842b17de99c326a8fd21a7d949afea639c7f259db02bb09ba2c28`,
the hash of the exact bytes `S-011 DELETED\n`. This receipt and canonical
audit/design annotations are excluded, so recording evidence does not mutate
the implementation generation.

Primary artifact inventory:

- Canonical result and continuation: `src/tools/result.rs`,
  `src/tools/continuation.rs`, `src/tools/mod.rs`, and
  `src/tools/registry.rs`.
- Typed producers/renderers: `src/tools/ask_user.rs`,
  `src/tools/plan_mode.rs`, `src/tools/file/edit.rs`, and
  `src/cli/display/tool_result.rs`.
- Live consumers: `src/cli/chat_repl.rs`, `src/cli/repl/plan_mode.rs`,
  `src/pipeline.rs`, `src/acp.rs`, `src/grounded_loop.rs`,
  `src/services/tool_executor.rs`, and `src/subagent.rs`.
- Acceptance suite: `tests/canonical_typed_tool_results_e2e.rs`.
- Retired unsafe control paths: `src/tool_intercept.rs`,
  `tests/tool_control_signal_e2e.rs`, and
  `tests/tool_intercept_buffer_e2e.rs`.

Manifest records:

```text
01b668ca865359344f3ddec5f4c327bd57ba605fd2c54a082429bdabe487dade  tests/permission_outcome_dispatch_e2e.rs
030d065d71af7f8d057ae9ca1bf8f285ffae1b2b17a6b6e3e64efcc6d64fc8af  tests/ask_user_question_validation_e2e.rs
041dc6564a1a36f17bd6610d90e43723b74cb79a838c1c216a0ed9d4fded09e8  tests/integration_tests.rs
0793ecaf4a99105bbf41ebc83dc7e82d4147dcf4410a12144126527f5b00783b  tests/sandbox_escape_e2e.rs
0d95d068e8e83267f3a55a1719928c7a8935a9c412ffe148b12e5e27f2f0722e  tests/file_search_e2e.rs
0faa6ddb2f0cb1c8f5d6d48974b4e42605ff6d03933a23d4e8008bae4b6284c1  tests/bash_dispatch_validation_e2e.rs
16d597cd80642511c2002ecc3c16edd32beae0d38268664eeca16564554f3195  tests/crosslink_dispatch_validation_e2e.rs
22f7a16ba564a74349feb61c11129d084b9718aa76da379114fc52c851026100  tests/registry_dispatch_options_e2e.rs
244745e2d8b66d569cd563cc7e0d0755b548ad38cd0fdc832f7cf12c947138c2  src/tools/continuation.rs
267a86eae3f9ebe8fb025d89294f4efc9cd56a06a4cea1da632510ff3562f801  tests/notebook_edit_dispatch_validation_e2e.rs
2760d1bf720cc8d799f09ee7177b86cd8928c3e4928c54655502f2d5c9e89dd5  src/grounded_loop.rs
2889f33212400dc55b776b8bb900d40175756caf9e53da4bdaad6527383d3787  tests/registry_dispatch_envelope_e2e.rs
2e8d895c419c8b725f69e1a9d38e8c4f1b59101ed3f4bdc8ccb77d8ba1d3a7aa  tests/write_file_dispatch_validation_e2e.rs
34f5297128353b09bb16b48f5b30f4286f38e0cee1a72481d088e7293febf18f  tests/skill_dispatch_validation_e2e.rs
3de85ac0b5ca25bf5fe557ed99dd52f3c08fc9cfb112556628f99a41b026bfad  tests/tools_security_e2e.rs
4744bba9afa18841ce07408ee528fe2998626f3a9c12e8a6e03842b2da39c7b5  tests/task_dispatch_validation_e2e.rs
4c773959fbba1bbea6591989a822f5f9d283500a1ca97e703b1d3f5a59ab07c9  src/cli/repl/plan_mode.rs
4cd9623545029364ceb0e3974f90d49c5ef9213f61e8d5b04b6c8656049a9da5  tests/execute_tool_envelope_e2e.rs
4cf5286e2002264e9ff216d05dfee3f2e95fb6842f91fb15205a05387c2c08f5  src/subagent.rs
4f01144df9b23f34d98982b8e6e4b09532341818031349d078735899035ed908  tests/bash_output_kill_dispatch_e2e.rs
51402b084245a062373ee690b14934d02ed93e961a19ab93cc20dfe3f6286a15  src/acp.rs
53b33e029ee96edf7a0a74c920af4757d213c39652cd95929f8d7b3d81cad159  tests/mcp_resource_handler_e2e.rs
5830ac2c942afaf15e603763efb024515ed1dc0e3ba2bef918322ae465eb9bfe  tests/session_filesystem_capabilities_e2e.rs
5efecaa0967633ba1a7ce9da4e71c26e419bfa001ed10565a75e83892ff2e752  tests/worktree_dispatch_validation_e2e.rs
5fa8f9ca53b61f9f3bbcbad589851f3c89c426322f4b299593bf436062033fc8  tests/file_tools_integration.rs
610cae6c0e9d6fdd0ed9626726c7cc769e597600d8ed446298895715959c5d4d  src/tools/bash/mod.rs
64c9685ec99c427e4784c25ea139d75b00bc5c374af709bc5ed74dfd30de1403  src/tools/mod.rs
689ab28fe26bdc7b5577353d1f0783950022398d7e3848e8f6fc9e99bd74cbe4  src/tui/events.rs
69e8b8477b713d04f0eafd95fd355f4881237f24e50aa862c29b594f22100939  src/tools/ask_user.rs
6bfb15977c61f6c169bd35fef115f00ba00f24e02618cbc1afd60e55f01a94e8  tests/cron_dispatch_validation_e2e.rs
6e1d60dfee3b5794136b0f2d7cf6b2f896db3d11e208ddc3b05d459da7a6f47e  src/tools/plan_mode.rs
70d97fbd236d62916407a0977a867ea748eccb1cfc86ea96885278f926e455fd  src/tools/file/edit.rs
765e476307b465be5be79bf3223c25ec3716206fb470b431197383959dca0a5a  tests/read_file_dispatch_validation_e2e.rs
7a984a3218e93c8f381437092ef5f8699e74530b745ab567d7d1f0ec4f3f1180  tests/plan_mode_exit_validation_e2e.rs
7fd42e76beb90b830e78637c85079c852ad864c63faaec9afde8334687c1a82d  tests/web_tool_url_validation_e2e.rs
8163bdd26b7368f224b8de68f238c023be8f792dd6aa450490c08b7f9e4f39e8  tests/todo_write_dispatch_validation_e2e.rs
9001991b9548963ed99729aa8998b6f4a48ca8eb39502e442289abc2dadb4247  tests/glob_grep_dispatch_validation_e2e.rs
939d9fbff8b334e6353d24132835bb6bd278fcbbfa26dea2be7290a9c578675c  src/tools/registry.rs
95bd648eaba431b5a75aeb41fd712002b0af1b476973e70117231d85cf44ae45  src/services/tool_executor.rs
95cb11ea60f5178df065c3544e18a89f3aa5b65a61c0f52b1d9d48e6496bddcb  src/lib.rs
9874b622c72842b17de99c326a8fd21a7d949afea639c7f259db02bb09ba2c28  src/tool_intercept.rs
9874b622c72842b17de99c326a8fd21a7d949afea639c7f259db02bb09ba2c28  tests/tool_control_signal_e2e.rs
9874b622c72842b17de99c326a8fd21a7d949afea639c7f259db02bb09ba2c28  tests/tool_intercept_buffer_e2e.rs
98fce2a6f819c1023399aae8379cab68f6125d951c659186c209d8261936743d  tests/list_files_dispatch_validation_e2e.rs
a2293cf07894d8196c99780b6f77a940f99b4d83b76d7244a48f9ecbda856eba  tests/file_tools_race_e2e.rs
a411405d269f8aa37c8ebe072bb8f2cf381ba4bc95baf3d4ea4b565eefc3dfa0  tests/notebook_edit_e2e.rs
a71311721b77fff02042be9d53e81bcb0ac6bc9ef604c208cc3b423cb4d9adc6  tests/bash_background_e2e.rs
b9c2f40cfd77702b52d8245e0046e1b0e25b4466e54ce2571e2a568da99000ab  src/tools/args.rs
bde3bb9ec544a9e34bbdbf3e5860f792f4d1b1d86e9965c60e1afe4b7778cbe1  src/tools/result.rs
c4e17f23ef770e3c1828ff6309b727b1a15c1fdb79f7328aaef2511c34e99bbc  tests/web_integration.rs
cb0500102f4a39d1a109ae7004920b9a9208028ed34b06fb9b6bfd6faa030949  tests/bash_integration.rs
d024c0f4b4a7beca14a12d941eb287d783a0c6d877fdbc0a0b5a7c8cbda55bde  tests/ledger_decision_e2e.rs
d8eb80b2bec8cafd7713ceaacf93c54ce729b8d5b1f442c26651bb30b1611e23  src/cli/chat_repl.rs
d911527b12a72dee6a0187bc62a8c95bb44be79d39ded4c3540fb3f1a838daa1  src/pipeline.rs
dcbd8fe8c0c2b1131fb9f3142072121a5ec469099e5c722843db382138e87f29  tests/lsp_tool_validation_e2e.rs
de555de289127f1774029454da409808118f848dcce06cabd8304174a1cfbe89  tests/canonical_typed_tool_results_e2e.rs
e9a1267b7d50551ee7756b1466675aba9758e713bdd08f0d40f9d84fa6fd3c4c  tests/tool_context_dispatch_e2e.rs
f222e307c28aa0a1cf975beb7e6f6d00abb1c140892a2c8defd9f44f4d016fed  tests/edit_file_dispatch_validation_e2e.rs
f6792b6fb0280e987c94e06be980af78605f59de88f1c7db665a61ce25ada15a  tests/grounding_context_dispatch_validation_e2e.rs
f92b504f2697b215aea527d62692bef8178eb7ddf7a2e951afa662cff0df0ef8  tests/tool_search_dispatch_e2e.rs
fb93dfa514874fec4fb91f119a6d350844fda28bf2b4d484b35ef1f616e3c2fc  src/cli/display/tool_result.rs
```

### Deterministic evidence

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `git diff --check` | Passed |
| Legacy-control residual search | Passed; no production XML interceptor, generic control parser, marker constants, or diff sentinel remains. The only marker-shaped text is inert adversarial input in the acceptance suite |
| `CARGO_BUILD_JOBS=1 cargo check --workspace --all-targets --all-features` | Passed |
| `CARGO_BUILD_JOBS=1 cargo clippy --workspace --all-targets --all-features -- -D warnings -A clippy::large_enum_variant` | Passed; the single named waiver remains the pre-existing, out-of-scope `src/tui/events.rs::AppEvent` size finding |
| `CARGO_BUILD_JOBS=1 cargo test --test canonical_typed_tool_results_e2e --all-features -- --test-threads=1` | Passed, 4 tests |
| Marker-imitation matrix | Passed for file, shell, web, model, legacy JSON-control, diff-sentinel, and pseudo-XML-shaped content; text remained data and no follow-up or tool dispatch was synthesized |
| Canonical result serialization | Passed; success/error/partial state, structured content, truncation continuation, artifacts, attachments, observations, display, usage, sensitivity, invocation binding, and schema version round-trip without loss |
| Provider continuation trace | Passed; OpenAI, Anthropic, and Gemini projections preserve three-call parallel order, exact IDs/arguments, typed error content, and resolved follow-up state; mismatched call identity/arguments and pending follow-ups are rejected |
| `CARGO_BUILD_JOBS=1 cargo test --workspace --all-features -- --test-threads=1` | Passed in the final serialized run with zero failures across 2,588 library tests, every integration target, and doc tests; explicitly network/browser-dependent tests remained ignored |

One intervening full run exposed an unrelated timing-sensitive ACP process-tree
cancellation test: `acp_foreground_bash_cancellation_terminates_descendants_promptly`
reported that its one-second marker process survived. The same test had passed
in earlier full runs, passed immediately when rerun alone (1/1), and passed in
the final complete artifact-current suite. No out-of-scope ACP code was changed.

The heavyweight gates used one Cargo build job, and every full suite used one
test thread, because the host had approximately 30 GiB RAM and exhausted swap.
No overlapping Cargo process was launched.

### Interim typed receipt

```yaml
receipt_type: remediation_slice_deterministic_verification
schema_version: 1
slice_id: S-011
artifact_generation: sha256:c6bfbb46ac688ea7b4b24e3a81f26296496e43be0ee810984c891d2fe8463060
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

- Existing leaf executors that only produce text and an error bit remain
  behind the registry's hidden `execute_legacy` migration seam. That tuple
  never crosses the canonical registry/provider/frontend boundary, and the
  existing structured Bash producer is retained without loss. The seam and
  test-only compatibility projection must be removed only after every leaf and
  its legacy assertion suite migrates, as F-043 requires; neither is a control
  parser or provider contract.
- `ToolExecutionResult` binds exact call identity, handler, and raw arguments,
  but canonical run identity, actor authority, cancellation tree, capability
  generation, and durable trace binding become universal only as the S-010
  kernel is adopted by S-012 and its dependent frontend/provider slices.
- Provider projections are deterministic typed-envelope adapters, not the
  final provider-owned opaque continuation contract. S-044 and S-045 own
  lossless native continuation state and OpenAI Responses follow-up parity.
- The full-screen TUI resolves typed user questions. A pending plan transition
  unsupported by that frontend is explicitly cancelled as a typed error rather
  than silently interpreted from text; canonical plan proposal/approval parity
  remains with the later plan/front-end lifecycle work.
- Required alternate-model verification remains queued until S-088. Any
  artifact mutation invalidates this generation and requires the manifest,
  deterministic gates, and VDD queue entry to be regenerated.
- No new remediation slice is proposed; every residual maps to an existing
  dependency or follow-on slice.

### ACP boundary follow-up — 2026-08-22

Crosslink #1090 repaired a later ACP-specific regression that had projected the
canonical result back to `{content, is_error}`. ACP now carries one
`ToolExecutionResult` through normalized local execution, restores the exact
provider call ID and raw argument bytes, routes `partial` to
`PostToolUseFailure`, sends the typed envelope to provider history and UI
`rawOutput`, and appends that same value to grounded evidence. Integrated tests
cover typed early argument failure, alias normalization without provenance
drift, nonzero Bash, and a real mutation followed by process failure. This
follow-up does not claim completion of ACP session isolation, bounded transport,
or effective capability advertisement in S-089 through S-091.

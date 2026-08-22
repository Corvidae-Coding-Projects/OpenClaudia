# S-044: Define the provider-native state contract

Status: Complete
Effort: Medium
Primary findings: F-019
Workstreams: W3, W12
Depends on: [S-010](./010-canonical-run-context-and-events.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve provider-native messages, tool state, reasoning continuation, caching, usage, and terminal semantics behind lossless adapters.

## Implementation boundary

- Define a neutral event envelope plus provider-owned opaque continuation items and capability negotiation; prohibit flattening when round-trip data would be lost.
- Build conformance fixtures for every provider covering multi-turn tools, parallel calls, reasoning blocks/signatures, refusals, usage, cache, and resume.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Every supported adapter round-trips its required native state or explicitly declares the unsupported capability.
- Generic chat-message conversion is never used as silent fallback when it loses protocol state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- A versioned `ProviderNativeState` lane now retains ordered opaque JSON items
  beside portable conversation history. Its identity is bound to the exact
  provider, model, wire protocol, monotonic continuation generation, and a
  canonical SHA-256 digest. Construction and deserialization reject unknown
  fields, invalid identities, sequence drift, digest tampering, non-object
  payloads, more than 256 items, payloads above 256 KiB each or 4 MiB total,
  and JSON nesting deeper than 64 levels. Debug output reports only metadata
  and encoded size; it never renders the opaque payload.
- The provider adapter trait requires an explicit native-state contract. Every
  registered provider and alias declares one concrete protocol contract,
  including Anthropic Messages, OpenAI Chat Completions and Responses, Gemini
  GenerateContent and Interactions, and Ollama Chat. Refusal, usage, cache, and
  terminal evidence can be retained without becoming provider input. Native
  messages, tool calls, parallel ordering, reasoning, compaction, and server
  continuation remain explicitly unsupported until their owning follow-up
  slice adds both extraction and a lossless request applicator; generic chat
  conversion cannot silently accept them.
- Canonical session persistence carries the native lane with schema defaults
  for older sessions and validates provider/model identity on load and save.
  Installation is atomic and monotonic: exact replay is idempotent, stale
  generations and same-generation digest conflicts fail without mutation, and
  protocol changes require an explicit clear. Provider/model switches, undo,
  redo, compaction, clear, teleport, and other history rewrites invalidate the
  lane, while append-only user/system/tool input preserves a valid
  continuation prefix.
- TUI and legacy REPL initial request builders now snapshot and apply the same
  state through the canonical pipeline after provider conversion. TUI agentic
  follow-ups and the legacy Gemini, Anthropic, OpenAI-compatible, and Ollama
  follow-up paths use the same fail-closed applicator. Evidence-only state is
  excluded from prompt and request JSON, and provider, model, protocol, or
  unwired-continuation mismatches stop request construction.
- Deterministic tests cover opaque provider payload round trips, redacted
  diagnostics, hostile persisted values, every registered adapter and state
  facet, request exclusion/fail-closed behavior, persistence identity,
  monotonic installation, model/provider transitions, and append-only versus
  branched history.

## Evidence

All commands used Rust/Cargo 1.98.0 with at most four Cargo build jobs, and test
execution was serialized where applicable.

| Gate | Result |
|---|---|
| Focused provider-state, adapter-contract, pipeline, persistence, and session-invalidation tests | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed across every native library, binary, example, and integration target; only explicitly network-dependent tests remained ignored |
| `cargo check --locked --target x86_64-pc-windows-gnu --all-features --all-targets` | Passed; existing target-conditional warning debt is tracked separately as Crosslink #1099 |
| Locked fuzz-crate check, strict Clippy, and library tests | Passed; all four finite hermetic harness tests succeeded |
| Repository-policy unit tests and hygiene checker | Passed; 27 policy tests and zero forbidden tracked artifacts |
| Root and fuzz locked metadata plus `cargo deny` advisories/licenses/sources/bans | Passed |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |

| Artifact | SHA-256 |
|---|---|
| `src/runtime/provider_state.rs` | `07c1720f6c1278315066ac8fb1ff99f09a7ddaf8510c1a410a7de8df22fbfc22` |
| `src/providers/mod.rs` | `d19664ce8df56cc4eece2abea415bf2348bb634460c1935c84d04d03a9b5a4c7` |
| `src/pipeline.rs` | `4395a61c14e90fcff92da25920e9ab021ff3bd4d1ba295c892376ed30a4d288b` |
| `src/state/session.rs` | `f0ccd2be8713c2d415c0f0eb51265e016472a5c7abe5820ba6db0e97605b87a5` |
| `src/state/persist.rs` | `90d206b5d683d25233176e6abafa39ac51ea92fffb6cb088c39052b9330e3eef` |

The skeptical review directly repaired missing JSON-depth enforcement,
standalone-item deserialization validation, stale/conflicting generation
replacement, history-branch invalidation, and persistence after direct
identity drift before this evidence was recorded.

## Residual boundaries

- S-045 owns OpenAI Responses response IDs and required native output items,
  including advancing state after each tool/reasoning response and sharing that
  adapter with proxy, print, ACP, TUI, and child-run paths.
- S-046 owns Gemini and Ollama native tool call/result pairing, identifiers,
  ordering, parallel behavior, and multi-round fixtures. S-047 owns negotiated
  model capability discovery and selection between available native protocols.
- S-049 owns protected reasoning persistence, access, retention, export, and
  redaction. S-050 owns truthful provider terminal outcomes. This slice does
  not represent any of those currently unsupported facets as operational.
- S-057 owns causal compaction that can preserve a valid native checkpoint;
  until then, portable-history rewrites deliberately clear native state rather
  than risk resuming the wrong provider history.
- S-038 owns a fully version-chained session schema and downgrade protection.
  The optional native-state field loads older V1 sessions safely, but this
  slice does not claim that an older binary can round-trip a session written by
  the newer binary without discarding fields it does not understand.
- S-088 must attach the canonical alternate-model VDD receipt with the same
  harness, guardrails, capability boundary, and reality-grounding services.
  The deterministic self-tests here are not represented as independent VDD.
- Completion applies only to S-044. The parent dormant-feature workstream
  remains open.

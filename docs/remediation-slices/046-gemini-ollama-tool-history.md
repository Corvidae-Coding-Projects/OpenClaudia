# S-046: Repair Gemini and Ollama tool history

Status: Complete
Effort: Small
Primary findings: F-018
Workstreams: W3
Depends on: [S-044](./044-provider-native-state-contract.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve the provider-specific call/result pairing needed for multi-turn Gemini and Ollama tool execution.

## Implementation boundary

- Implement native request conversion for assistant tool calls, call IDs, arguments, tool results, ordering, and parallel/batched behavior.
- Reject histories that cannot be represented rather than silently dropping tool protocol state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Two consecutive tool rounds succeed against recorded provider fixtures with exact call/result correlation.
- Malformed, missing, duplicated, and reordered call IDs produce typed protocol errors.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Gemini GenerateContent and Ollama Chat now retain each completed native
  assistant message in bounded provider-native state. Follow-up requests replay
  exact provider call IDs, arguments, order, parallel-call grouping, Gemini
  thought signatures, Ollama call indexes, Ollama thinking, and unknown native
  extension fields without copying provider-private data into portable chat
  prose.
- A private construction-time binding joins portable assistant/tool messages to
  their native turns. It is removed before transport and rejects missing,
  duplicate, reordered, orphaned, or mutated calls/results instead of emitting
  lossy history. Older Gemini responses without provider call IDs receive
  stable turn-scoped portable IDs while native replay correctly omits those
  synthetic IDs.
- The canonical pipeline builds and decodes non-streaming native JSON turns for
  both protocols and advances continuation state before tool effects. The TUI,
  legacy CLI loop, ACP server, and child-agent path all use that shared
  conversion and decoding behavior rather than reconstructing independent
  provider histories.
- Deterministic tests cover two consecutive tool rounds, parallel calls,
  provider-owned extension fields, private reasoning/signature retention,
  incomplete output, malformed native state, duplicate IDs/indexes, missing or
  reordered results, portable/native argument drift, and illegal interruptions
  of a pending tool batch.

## Evidence

All Rust commands used Rust/Cargo 1.98.0 with at most four Cargo build jobs,
and test execution was serialized where applicable.

| Gate | Result |
|---|---|
| Focused Google, Ollama, pipeline, ACP, child-run, and CLI regressions | Passed: 25 Google, 23 Ollama, 88 pipeline, 103 ACP, 82 child-run, and 32 CLI tests |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics after the final lifecycle review |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed across every native library, binary, example, and integration target before the final localized CLI ordering correction; the affected 32-test CLI module was then rerun and passed |
| `cargo check --locked --target x86_64-pc-windows-gnu --all-features --all-targets` | Passed; existing target-conditional warning debt remains tracked as Crosslink #1099 |
| Locked fuzz-crate check, strict Clippy, and library tests | Passed; all four finite hermetic harness tests succeeded |
| Repository-policy unit tests, hygiene checker, locked metadata, and `cargo deny` | Passed; 27 policy tests and zero forbidden tracked artifacts |
| `cargo fmt --all -- --check` and `git diff --check` | Passed after the final lifecycle review |

| Artifact | SHA-256 |
|---|---|
| `src/providers/google.rs` | `113a098fb3faccbeb3b5775f0573fa184a617061589aa6a9f7399e2c6188db16` |
| `src/providers/ollama.rs` | `2b386334ff1654f33c52804d5a0fd79d4fb4f02005fae4efccdc4f098bbb8244` |
| `src/providers/mod.rs` | `028ca5e8c98ae1d5cb5142991d1039fa198e07f1a32bdb196d37b18c9476c42d` |
| `src/pipeline.rs` | `aec43f753edfde2e60890e41fa119b3c55737e9822be7c9b3dc7505bb2d16e0d` |
| `src/cli/chat_repl.rs` | `259838ba56adc27c25c8c0d530fbd603abf1d9092fdc9e71355075a303cc41c7` |
| `src/acp.rs` | `4f60434a52abaecf5535fed3cbf94de0ef9f23323b70cefb26a0789d0c83f89d` |
| `src/subagent.rs` | `d279db7ff3a53b647430f3ae06b3f64f78dac11d5640b7e34ef8a41871c1e24c` |
| `tests/google_transform_request_envelope_e2e.rs` | `56ec821a284fa03cbe2dce6e68f951bbc22b53b909d4198008bafc724091820d` |

The final skeptical review also corrected two realistic CLI state-lifecycle
failures: a max-turn stop no longer persists a newly unresolved tool-call turn,
and a final response rejected by the evidence gate is no longer written into
session history.

## Residual boundaries

- The alternate-model artifact-bound VDD receipt remains intentionally pending
  until S-088 provides that verifier. The deterministic acceptance evidence for
  this slice is complete.
- Gemini Interactions, dynamic model discovery, protected reasoning access,
  session-correlated terminal outcomes, hardened transport, and proxy lifecycle
  work remain in their owning slices; this slice does not claim them.
- Durable atomic persistence around a tool side effect remains part of the
  causal persistence work. This slice establishes the required ordering by
  installing native continuation before dispatch.
- Completion applies only to S-046. The parent dormant-feature workstream
  remains open.

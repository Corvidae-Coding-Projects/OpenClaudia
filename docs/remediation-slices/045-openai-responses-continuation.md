# S-045: Preserve OpenAI Responses continuation

Status: Complete
Effort: Small
Primary findings: F-002
Workstreams: W3
Depends on: [S-044](./044-provider-native-state-contract.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Retain response identity and required output items across OpenAI Responses tool and reasoning turns.

## Implementation boundary

- Persist response IDs and provider output items, including encrypted/native reasoning or compaction items required for stateless continuation.
- Make TUI, proxy, print, ACP, and child-run follow-ups consume the same OpenAI continuation adapter.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A multi-turn tool fixture sends valid continuation without reconstructing lossy chat history.
- Resume and compaction preserve required native items while user-visible history exposes only sanctioned summaries.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- OpenAI Responses turns now retain the response identity and every exact,
  ordered provider output object needed for stateless continuation with
  `store: false`. Message `phase`, function-call identity and arguments,
  parallel-call classification, encrypted reasoning, and provider compaction
  objects survive without being flattened into portable chat prose. Response
  IDs remain correlation evidence and are never misused as
  `previous_response_id` while server storage is disabled.
- Native replay is fail closed. It binds provider, model, protocol, monotonic
  generation, assistant-history ordinal, response identity, output count,
  contiguous item ordering, and the expected native-state facet. Unknown
  evidence, malformed output, duplicate identities, forged generations,
  reordered groups, mismatched facets, and attempts to mix stateless replay
  with server-managed `conversation` or `previous_response_id` state are
  rejected before a request is sent.
- The canonical pipeline owns one bounded Responses stream decoder and exact
  request applicator. TUI, ACP, print mode, and child runs now use that shared
  transport behavior; they require a completed terminal response, reconcile
  terminal output against streamed deltas, advance native state before
  dispatching returned tools, preserve the child output-token cap, and omit
  empty tool catalogs. Raw `/v1/responses` proxy traffic remains client-owned
  but now preserves the bounded request body and query string instead of
  discarding them.
- Session state atomically replaces an append-only portable-history prefix and
  its matching provider-native continuation. Provider/model/session switches
  clear both lanes, stale session events cannot install foreign state, and TUI
  terminal completion is emitted only after the synchronized state update.
  Crash recovery writes exact native state into collision-resistant private
  files under a private, non-symlink recovery directory.
- Deterministic adversarial tests cover exact multi-turn replay, tool-only
  turns, response/tool identity, forged ordering/facets/generation, unknown
  evidence, provider-owned fields that resemble private construction markers,
  incomplete and contradictory SSE streams, session correlation, child
  continuation, print-mode authentication/request shape, ACP conversation
  switches, proxy passthrough, and private orphan recovery.

## Evidence

All commands used Rust/Cargo 1.98.0 with at most four Cargo build jobs, and test
execution was serialized where applicable.

| Gate | Result |
|---|---|
| Focused Responses library, pipeline-integration, and orphan-permission regressions | Passed: 20 library tests, 4 pipeline tests, and the Unix private-file test |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed across every native library, binary, example, and integration target; only explicitly opt-in network/browser tests remained ignored |
| `cargo check --locked --target x86_64-pc-windows-gnu --all-features --all-targets` | Passed; existing target-conditional warning debt remains tracked as Crosslink #1099 |
| Locked fuzz-crate check, strict Clippy, and library tests | Passed; all four finite hermetic harness tests succeeded |
| Repository-policy unit tests and hygiene checker | Passed; 27 policy tests and zero forbidden tracked artifacts |
| Root and fuzz locked metadata plus `cargo deny` advisories/licenses/sources/bans | Passed with cargo-deny 0.20.2 |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |

| Artifact | SHA-256 |
|---|---|
| `src/providers/openai.rs` | `2d060d85ef8e9bb78cd63983f529397c24b69d378677d39482f08f56c401a883` |
| `src/pipeline.rs` | `8987ddfade07d622428d7c803baf25a9f97c7d9344fe0eaa9637836a92534963` |
| `src/state/session.rs` | `799e12a7c7c1f2156998185c16776b1572a58fcaeb0433c56bc98d75132b637e` |
| `src/tui/app.rs` | `76973c78a4cf5c9f1cb792a331fe5c80cdec191ab669ebb2afe5b793c7537c29` |
| `src/acp.rs` | `4ec13124396b6903ad3069710af4466a42087871afaa778247131eaada04e6e1` |
| `src/cli/print_mode.rs` | `cd2d9ae691a1ee03b9706ee9b12b793156785c0cb8af340c4409db21a93bc6af` |
| `src/subagent.rs` | `dde5dc2940f315a8821390fd43c9b608afd73162eba20c43294a1b6b65111d1f` |
| `src/proxy.rs` | `555c9d165a6732b7ff7b54bc7378488931279a0058b7831a46bbf1ccc50bde62` |

The final skeptical review directly repaired structural replay forgery,
provider-field marker collisions, a dropped child output-token cap, overly
broad orphan-state permissions, ACP credential diagnostics, and verification
snapshot instability caused by live Crosslink runtime state before this
evidence was recorded.

## Residual boundaries

- Portable-history mutation is prevented by the append-only session commit.
  The native envelope binds ordinals and roles but does not independently hash
  every portable message body; the fully version-chained persistence work in
  S-038/S-039 owns that broader historical integrity contract.
- Provider-native `compaction` output objects are preserved exactly. Local
  application compaction still invalidates continuation rather than replaying
  it against rewritten history; S-057 owns a causal native checkpoint across
  that rewrite.
- TUI state is advanced before a returned tool is dispatched, but durable
  session persistence and the tool side effect are not one crash-atomic
  transaction. S-037/S-038 own that larger causal persistence boundary.
- ACP now continues within its active in-memory session, but durable ACP
  multi-session resume remains W12/S-089. Print mode is deliberately one-shot
  with no tools or continuation persistence. Raw proxy Responses traffic
  remains client-owned; proxy tenant/auth/streaming boundaries remain in
  S-048 and S-092 through S-095.
- Protected reasoning retention/access belongs to S-049; session-correlated
  terminal outcomes belong to S-050; capability-driven reasoning-effort
  negotiation belongs to S-047; and the alternate-model artifact-bound VDD
  receipt belongs to S-088. This slice does not claim those adjacent features.
- Completion applies only to S-045. The parent dormant-feature workstream
  remains open.

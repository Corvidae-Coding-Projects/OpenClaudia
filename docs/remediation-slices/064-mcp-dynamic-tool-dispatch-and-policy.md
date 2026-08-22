# S-064: Complete MCP dynamic tool dispatch and allowlists

Status: Complete
Effort: Medium
Primary findings: F-090, F-138
Workstreams: W2, W6, W11
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-013](./013-progressive-tool-catalog.md), [S-016](./016-mandatory-tool-effect-classification.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Advertise only callable MCP tools and enforce configured server/tool policy through the canonical executor.

## Implementation boundary

- Register discovered schemas with stable server/tool identity, trust, generation, availability, typed effects, and capability requirements.
- Dispatch calls through the owned MCP manager and revalidate server/tool allowlists, schema, arguments, approval, and generation at execution.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Every advertised MCP tool can complete a model call/result round trip or is removed with an explicit unavailable state.
- Unlisted, renamed, stale, direct-selected, or plugin-provided tools cannot bypass the configured allowlist.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- `permissions.mcp` is validated as a bounded, explicit server/tool allowlist.
  Invalid identities, duplicate tools, excessive entries, and overlong canonical
  names fail configuration. Project-local non-empty MCP permissions remain an
  inert proposal until the repository authority workflow approves them; an
  absent server grant fails closed.
- Healthy allowlisted tools are snapshotted under the stable
  `mcp__<server>__<tool>` identity with their exact run, manager generation,
  source digest, schema, trust, availability, required MCP capability, and a
  conservative destructive effect. Duplicate trusted plugin ownership of a
  server namespace fails closed instead of depending on map iteration order.
- Remote descriptions, annotations, and schema prose remain untrusted data.
  Prompt-visible host instructions do not inherit that prose, including nested
  array and schema annotation positions. Discovery scans only the finite
  configured allowlist rather than copying an arbitrary remote inventory.
- Dynamic calls enter the same canonical async executor as built-in tools. The
  executor requires catalog admission, an exact publication receipt, current
  run/manager generation, current allowlist membership, a JSON object matching
  the published schema, enterprise capacity, MCP capability, permission,
  host-safety checks, and blast-radius reservation before transport dispatch.
  Stale, renamed, direct-selected, or unregistered calls receive typed failures.
- TUI request and follow-up generations publish the live MCP snapshot and bind
  the exact manager to the run. ACP recognizes canonical MCP calls but does not
  advertise them without an owned manager, so it fails explicitly unavailable.
  The transparent proxy likewise does not claim a local dynamic tool/result
  loop it does not own; its public compatibility helper remains host-tool-only.
- Cancellation is checked immediately before transport polling, partial remote
  results retain their typed status and route failure hooks, and an admitted
  side effect remains charged once dispatch begins. Built-in blocking dispatch
  keeps its existing compatibility behavior.

## Evidence

All commands used Rust/Cargo 1.98.0 with at most four Cargo build jobs, and test
execution was serialized where applicable.

| Gate | Result |
|---|---|
| Focused S-064 catalog, policy, dispatch, collision, schema, cancellation, partial-result, configuration, and transport tests | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed across every native library, binary, example, and integration target; only explicitly network-dependent tests remained ignored |
| `cargo check --locked --all-features --all-targets --target x86_64-pc-windows-gnu` | Passed; emitted only existing target-conditional warnings |
| Locked fuzz-crate check, strict Clippy, and library tests | Passed; all four finite hermetic harness tests succeeded |
| Repository-policy unit tests and hygiene checker | Passed; 27 policy tests and zero forbidden tracked artifacts |
| Root and fuzz locked metadata plus `cargo deny` advisories/licenses/sources/bans | Passed |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |

The complete native run exposed a legitimate final-environment citation
failure after `src/main.rs` changed. The held-out S-105 corpus was rebound to
`worktree:s064`, the evaluation was rebuilt with the checked-in canonical
generator, and the exact review record was rebound while retaining its
deliberately fail-closed `rejected` verdict. No independent approval was
fabricated.

| Artifact | SHA-256 |
|---|---|
| `src/main.rs` | `ae0fe24999ad3ca165fa2acd41935adcfeab89aa32b20955af9299b23aa6ef1e` |
| `capabilities/technical-memory-retrieval-heldout.json` | `6471612b4ddd5c9e06134ee8ba4f740b8eb5dc187f87921004e800680db65592` |
| `capabilities/technical-memory-retrieval-evaluation.json` | `239db50819b322a8469166a671778dd487ec6d601ad4fb6f69c0090ce94ab673` |
| `capabilities/technical-memory-retrieval-review.json` | `1a35f98595846c37f4428dd4292b47170f2e09d67f6d8a6098f731f194ebb0cc` |

Crosslink #1097 records the CI-hermetic automatic-learning fixture correction
found during this work. Its real Rust-toolchain case now uses the host
toolchain context and rejects both error and partial outcomes.

## Residual boundaries

- S-065 owns the current MCP protocol adapter, including broader protocol
  negotiation, change notifications, pagination, and output-schema behavior.
- S-066 owns bounded transport supervision and can remove the manager's current
  internal serialization across network I/O. This slice does not represent
  that follow-up as complete.
- S-088 must attach the canonical alternate-model VDD receipt with the same
  harness, guardrails, capability boundary, and reality-grounding services.
  The deterministic self-tests here are not represented as independent VDD.
- Completion applies only to S-064. The parent dormant-feature workstream
  remains open.

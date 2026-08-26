# S-068: Create a stateful workspace LSP service

Status: Complete
Effort: Medium
Primary findings: F-053, F-055
Workstreams: W18, W21
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve complete LSP continuation data and document state in a supervised per-workspace server generation.

## Implementation boundary

- Pool servers by workspace, language, binary/config/version, capability, and generation; own initialize, health, restart, cancellation, and didOpen/change/close versions.
- Return complete bounded call-hierarchy items and opaque continuation tokens tied to the server/document generation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Call hierarchy prepare and follow-up round-trip without losing server data, and stale tokens fail explicitly.
- Fresh/restarted servers receive correct document lifecycle instead of process-global deduplication.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Replaced the preserved bare-child prototype and per-call production shim
  with one stateful `LspServerManager` owned by each exact
  `ToolRunContext`. Pool identity binds run and capability generation,
  canonical workspace, language, resolved executable and metadata
  fingerprint, plugin configuration and environment digest, and client
  capability version.
- The manager owns initialize/initialized, health detection, serialized
  requests, document text and monotonic didOpen/didChange/didClose versions,
  crash restart with document rehydration, cancellation, graceful
  shutdown/exit, forced process-tree termination, idle reaping, and bounded
  warm-server count. The LSP sandbox receives a protocol-valid null parent PID
  because its host PID is not meaningful inside the isolated PID namespace.
- Production LSP dispatch in the TUI, REPL, proxy, and capability-derived
  frontend runs consumes the run-owned manager. Enabled plugin LSP manifests
  are installed and refreshed without granting environment authority beyond
  the exact run; built-in language mappings remain available.
- `prepareCallHierarchy`, `incomingCalls`, and `outgoingCalls` now preserve
  complete server-owned items, including opaque `data`, behind unguessable
  continuation tokens bound to the same manager, server generation, document
  URI, and document version. Document changes and restarts make old tokens
  fail explicitly. Workspace-symbol results retain name, kind, container,
  URI, and complete range coordinates.
- Removed the process-global didOpen registry and spawn-per-call protocol
  machinery only after their working behavior was replaced by the stateful
  service. Existing actions, URI normalization, file-size admission,
  capability-confined reads, plugin configuration, sandboxing, gitignore
  filtering, location links, and result shapes remain supported.

## Evidence

All Cargo commands used Rust/Cargo 1.98.0 with `CARGO_BUILD_JOBS=4`, one Cargo
process at a time, and serialized execution for the complete suite. The local
LSP server is a compiled fixture and uses no network or external credentials.
The implementation was checked against the official LSP 3.17 initialize,
shutdown, text-document synchronization, and call-hierarchy contracts.

| Gate | Result |
|---|---|
| Compiled stateful LSP fixture | Passed 9/9: warm reuse, document versions, concurrent serialization, complete multi-step call hierarchy, stale tokens, crash restart/rehydration, typed server errors, cancellation, balanced shutdown/reaping, configuration replacement, run isolation, and plugin environment denial |
| Focused LSP validation, serde, lifecycle, worktree, and plugin composition tests | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed across every native library, binary, example, and integration target; only explicitly ignored tests remained ignored |
| Repository-policy unit tests and hygiene checker | Passed; 27 policy tests and zero forbidden tracked artifacts |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |

Changing `src/main.rs` correctly invalidated the S-105 final-environment
citation. The held-out corpus was rebound to `worktree:s068`, the checked-in
canonical evaluator regenerated the exact evaluation, and the review record
was rebound while retaining its deliberately fail-closed `rejected` verdict.

| Artifact | SHA-256 |
|---|---|
| `src/main.rs` | `6627317cb13e7ffeb4da3608e82052d494e646ff0ddcfa3cbfa5b03eafe2d89b` |
| `capabilities/technical-memory-retrieval-heldout.json` | `3aed8f5b0f4b25da024e9f1e7951fe09cdffe21bbc0ad9f8f2d13b035326f4af` |
| `capabilities/technical-memory-retrieval-evaluation.json` | `9cbfc3c957a8b698db62e25cb19582e602230577b1e54e12fa010158b0e1a2d4` |
| `capabilities/technical-memory-retrieval-review.json` | `84e1319fbcd1b4b69308daeac8fa8ef963dfa51fa52057578d0b7ca2c0753d35` |

## Residual boundaries

- S-069 remains responsible for the broader bounded JSON-RPC transport,
  blocked-write and hostile-frame fixtures, returned-resource validation,
  bounded semantic results and diagnostics. S-068 does not claim those
  adjacent requirements complete.
- S-088 remains responsible for an independent artifact-bound VDD receipt
  using the same harness, guardrails, capabilities, budgets, grounding, and
  process supervision. No independent approval is represented here.
- Completion applies only to S-068. Parent issue #1071 remains open.

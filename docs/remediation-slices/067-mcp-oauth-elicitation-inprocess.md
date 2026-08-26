# S-067: Complete MCP OAuth, elicitation, and in-process semantics

Status: Complete
Effort: Medium
Primary findings: F-093
Workstreams: W3, W6, W15
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-029](./029-oauth-session-lifecycle.md), [S-031](./031-descriptor-safe-persistence.md), [S-065](./065-mcp-current-protocol-adapter.md), [S-066](./066-mcp-owned-bounded-transports.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace schema-only secret-unsafe MCP extensions with current authorized, correlated, lifecycle-owned implementations.

## Implementation boundary

- Implement current authorization discovery/PKCE/state/scope/refresh/revocation through protected secret storage and bound pending sessions.
- Implement correlated multi-round elicitation and make in-process servers obey the same identity, capability, budget, cancellation, and shutdown contract as external servers.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Replay, redirect, state, scope escalation, expiry, revocation, secret-log, and concurrent-flow tests pass.
- Elicitation cannot overwrite another request, and in-process code receives no implicit host authority.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Added opt-in MCP HTTP OAuth with protected-resource and authorization-server
  discovery, PKCE S256, single-use expiring state, exact redirect and issuer
  validation, resource/client/scope binding, protected token persistence,
  serialized proactive refresh, refresh-token rotation, invalid-token retry,
  expiry, and revocation tombstones. Provider OAuth and existing unauthenticated
  MCP configurations remain unchanged.
- Added bounded, correlated multi-round request-time elicitation for current
  tool, resource, and prompt operations. Form and URL modes retain opaque
  request state, isolate concurrent operations, validate restricted schemas and
  responses, generate a new request/progress identity for each round, and fail
  closed on decline, cancellation, unsupported input, or excess rounds.
- Made managed in-process MCP servers use the same per-server actor lifecycle,
  run identity, capability admission, generation checks, operation budgets,
  cancellation, and shutdown ownership as external servers. The callable sees
  only a narrow request context and receives no ambient tool or host authority.
- Preserved the current and legacy protocol adapters, existing stdio roots,
  Claude/Codex provider authentication, configured static headers, and MCP
  configurations without OAuth. Plugin OAuth secrets expand through protected
  secret types and never enter public diagnostics or serialized configuration.

## Evidence

Dependencies were consumed from S-065 / Crosslink #1140 at `a5102b7b` and
S-066 / Crosslink #1141 at `6934cfb2`; neither slice was reimplemented. The
implementation was checked against the official MCP 2026-07-28
[authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization),
[elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation),
and [multi-round tool result](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)
contracts.

All Cargo commands used Rust/Cargo 1.98.0 with `CARGO_BUILD_JOBS=4`, no
overlapping Cargo invocation, and serialized execution for the complete suite.
Local wire fixtures used synthetic credentials only.

| Gate | Result |
|---|---|
| Focused OAuth discovery, PKCE, state/replay, redirect/issuer, scope, expiry, refresh-race, rotation, revocation, persistence, and redaction tests | Passed |
| Focused concurrent elicitation, cancellation, round isolation, schema, URL-consent, and in-process lifecycle tests | Passed |
| Compiled current and legacy stdio plus current HTTP fixture round trips | Passed |
| `cargo check --locked --tests` | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed across every native library, binary, example, and integration target with zero failures |
| Repository-policy unit tests and hygiene checker | Passed; 27 policy tests and zero forbidden tracked artifacts |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |

## Residual boundaries

- A frontend that chooses to complete an OAuth authorization request owns the
  visible browser interaction and redirect delivery through the manager's
  explicit begin/complete API. The MCP transport does not gain ambient browser
  or credential authority.
- S-088 remains responsible for the artifact-bound alternate-model VDD receipt
  using the same harness, guardrails, capabilities, budgets, and
  reality-grounding services. No independent verification receipt is
  represented here.
- Completion applies only to S-067. Parent issue #1071 remains open.

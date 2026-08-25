# S-066: Own and bound MCP transports

Status: Complete
Effort: Medium
Primary findings: F-092
Workstreams: W6, W10, W18
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-040](./040-supervised-foreground-process-io.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-065](./065-mcp-current-protocol-adapter.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give each MCP connection request correlation, framing limits, deadlines, cancellation, backpressure, and supervised process/network ownership.

## Implementation boundary

- Implement bounded stdio/HTTP transport actors with connection generations, request IDs, frame/body/queue limits, status validation, and one terminal response.
- Serialize or multiplex safely per transport; cancellation and shutdown stop/reap only the owned request/server and reconcile pending calls.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A stalled, oversized, malformed, reordered, disconnected, or cancelled server cannot block the subsystem or satisfy another request.
- Session/plugin shutdown joins MCP processes/connections without orphans or cross-server state confusion.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Replaced manager-wide remote-I/O serialization with one actor per registered
  MCP server. Each actor exclusively owns its connection, reconnect state,
  cancellation handle, connection generation, and supervised shutdown path.
  The manager lock now protects metadata only, so unrelated servers can make
  progress independently.
- Added a 32-request fail-fast mailbox, 10 MiB request/frame/body limits, a
  1,000-event SSE limit, default 60-second operation and shutdown deadlines,
  and typed backpressure, cancellation, closed-connection, stale-run, and
  stale-connection failures. Caller cancellation retires the affected remote
  connection before the actor accepts more work.
- Made stdio teardown kill and reap the owned process tree on request timeout,
  failed construction, replacement, disconnect, run cancellation, and actor
  abort fallback. PID reuse is not signalled after the child has already been
  reaped.
- Made HTTP response reads bounded even without `Content-Length`, retained
  response-size failures across non-success statuses, validated legacy session
  identifiers before header reuse, and terminate owned legacy sessions with a
  bounded `DELETE`. The shared HTTP connection pool remains process-owned.
- Bound every operation to the exact run and connection generations. Catalog
  snapshots publish generation, availability, and tool definitions coherently;
  multi-server resource and prompt listings retain typed per-server failures
  while executing concurrently.
- Completed Crosslink #1026 by selecting `Process` for stdio and `Network` for
  HTTP only after resolving the registered server transport. Stdio-only,
  HTTP-only, mismatched, stale-generation, unknown-server, and mixed-server
  behavior now fail or succeed at the exact transport boundary.
- Kept the current S-065 protocol path and explicit legacy adapters operational.
  MCP OAuth, elicitation, and in-process semantics remain owned by S-067.

## Evidence

All Cargo commands used Rust 1.98.0, `CARGO_BUILD_JOBS=4`, no overlapping Cargo
invocation, and serialized test execution for the complete repository gate.

| Gate | Result |
|---|---|
| Focused MCP actor, backpressure, generation, admission, body/framing, session shutdown, and handler tests | Passed |
| Compiled stdio round trip against the Python MCP fixture | Passed |
| Compiled current-HTTP round trip against the routing-header fixture | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed across every native library, binary, example, and integration target with zero failures |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |

Artifact generation `S066-G1` is based on
`a5102b7b2e2f24fc1ba2a5c9fbd094c7fcda9e7e`. The source/test diff digest is
SHA-256 `ed36b00c263b4ca09b95d30845fb8490823bbc9d44393bd45b28a0abb1731f3c`.
Any later change under `src/` or `tests/` invalidates this generation.

## Residual boundaries

- S-067 remains responsible for MCP OAuth, elicitation, and in-process
  transport semantics; none are represented as completed here.
- The full repository suite must remain serialized until Crosslink #1062 makes
  its shared workspace-projection fixtures safe under parallel execution.
- S-088 is not yet available, so no alternate-model VDD receipt is represented
  as present. Queue `S066-G1` for verification with the same harness,
  guardrails, capabilities, and reality-grounding services once it is.
- No new remediation issue was discovered. Completion applies only to S-066;
  parent issue #1071 remains open.

# S-095: Fix proxy streaming and VDD delivery parity

Status: Complete
Effort: Medium
Primary findings: F-129
Workstreams: W3, W12, W27, W28
Depends on: [S-088](./088-canonical-vdd-verifier-role.md), [S-094](./094-proxy-canonical-lifecycle-routing.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stream protocol-correct responses while applying VDD and terminal delivery semantics consistently.

## Implementation boundary

- Translate each provider's events to the declared client protocol incrementally with bounded backpressure, usage, finish reasons, errors, and disconnect cancellation.
- Run configured VDD against the exact candidate response before blocking success and expose advisory/blocking/degraded outcomes without buffering a fake stream.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- OpenAI/Anthropic/Google fixtures cover successful, tool, refusal, length, usage, midstream error, slow/disconnected client, and VDD paths.
- No raw foreign-provider SSE or unreviewed response is labeled as the advertised protocol success.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Completed implementation — 2026-08-27

Successful live proxy streams now pass through a bounded incremental SSE
decoder and a route-aware protocol translator instead of forwarding foreign
provider bytes. OpenAI chat/completions, Anthropic messages, Google generate
content, and OpenAI Responses events preserve text, tool calls, refusal,
length/stop reasons, usage, and terminal semantics in the client-declared
protocol. Malformed frames, oversized lines/streams, idle timeouts, provider
errors, missing terminal events, and foreign markers produce protocol-shaped
errors rather than advertised success.

Delivery is pull-driven through Axum backpressure. Provider budget and
lifecycle ownership remain open until the translated terminal event; upstream
transport error, timeout, or client-body drop settles unknown usage, releases
the lifecycle trace, and drops the reqwest stream to cancel upstream work.

When VDD is configured, a client request for streaming is explicitly changed
to non-streaming upstream delivery. The exact bounded candidate is reviewed
before delivery; the proxy never buffers a response and then replays it as a
fake live stream. Advisory results are labeled, while blocking skip, error,
unconverged review, or translation failure fails closed. Existing VDD hook and
typed result semantics are preserved.

## Evidence

- Proxy tests passed 63/63 in the focused gate and again in the complete suite.
  New fixtures cover OpenAI, Anthropic, Google, and Responses text/tool/refusal/
  length/usage terminals; malformed or missing terminals; fragmented and
  oversized SSE; pull-driven delivery; disconnect cancellation; and honest VDD
  buffering.
- Existing bounded body, provider-budget, route, hook, model-policy, MCP
  shutdown, and VDD result tests remain green.
- `cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
  passed with zero diagnostics.
- `cargo +1.98.0 test --quiet --locked --all-targets --all-features --
  --test-threads=1` passed every non-ignored target.

## Residual boundaries

- VDD-reviewed responses are intentionally buffered, because blocking review
  cannot honestly deliver unreviewed deltas. Live streaming remains available
  when VDD is not configured.
- S-100 owns canonical blocking finalization and durable independent-verifier
  receipt publication. This slice uses the existing VDD engine and does not
  claim an alternate-model approval receipt.
- Completion applies only to S-095; parent issue #1071 remains open.

# S-093: Isolate proxy tenant and session state

Status: Delivered; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-127
Workstreams: W3, W12, W27
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-019](./019-explicit-session-capabilities.md), [S-029](./029-oauth-session-lifecycle.md), [S-089](./089-acp-session-isolation.md), [S-092](./092-proxy-client-authentication.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace process-global proxy transcript, model, auth, accounting, VDD, hook, MCP, and plugin state with authenticated canonical sessions.

## Implementation boundary

- Resolve every route to tenant/client/session/call IDs and exact provider/workspace/capability/budget generations.
- Own per-session continuation, compaction, memory, approvals, hooks, tools, OAuth, usage, cancellation, and lifecycle resources.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Concurrent adversarial tenants cannot mix credentials, prompts, tool results, budgets, VDD evidence, cancellation, or provider state.
- Session expiry/logout/shutdown revokes and joins only the owned resources.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered architecture — 2026-08-30

Proxy startup now creates one owned canonical state for every configured,
authenticated caller rather than sharing a process-global transcript. An
optional stable tenant identifier defaults to the caller identity, preserving
existing S-092 configurations without manufacturing ambient tenancy. Admission
resolves the authenticated caller to its exact tenant, caller, session, and new
call generation before protected handlers run, serializes conflicting calls
within that session, and permits unrelated callers to proceed independently.

Each owner has independent run, session manager, transcript, provider/model
binding, token and cost budget, context and compaction state, hooks, MCP,
plugins, OAuth store, VDD engine, and cancellation tree. Response headers expose
the resolved session and generation, OAuth challenge binding incorporates the
canonical owner, and startup/shutdown hooks and resource retirement operate
over the owned session registry. Streaming responses retain the exact call
lease until their body lifecycle ends.

Focused Rust 1.98 verification passed the caller-state, concurrent call-gate,
session-mutation, and OAuth-owner isolation test plus the 53 related proxy
configuration, error, and translation integration tests. The all-target,
all-feature check, strict Clippy gate, and complete serialized native suite also
pass with zero failures.

## Residual boundaries

- S-094 still owns routing every compatibility endpoint through one canonical
  request lifecycle, and S-095 owns provider streaming/VDD delivery parity.
- The service-level loop count remains an operator-owned server lifecycle
  control; it is not mutable caller session state.
- S-088 still owns the independent artifact-bound VDD receipt.

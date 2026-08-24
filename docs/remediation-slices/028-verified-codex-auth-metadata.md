# S-028: Verify Codex account and compliance metadata

Status: Implemented
Effort: Medium
Primary findings: F-082
Workstreams: W3
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop using unverified token payloads to choose account and compliance routing headers. Codex account sessions now stay inside the official Codex runtime, which owns login, token refresh, account selection, and routing metadata.

## Implementation boundary

- OpenClaudia discovers and pins the installed `codex` executable, verifies that its owned login is usable with `codex login status`, and runs provider turns through constrained, ephemeral `codex exec` processes.
- OpenClaudia no longer reads Codex `auth.json`, decodes JWT claims, handles bearer or refresh tokens, synthesizes account/FedRAMP headers, or calls the private `chatgpt.com/backend-api/codex` endpoint.
- The official runtime is the sole authority for issuer, audience, expiry, account, scope, refresh, and compliance routing. Those values are deliberately not copied into OpenClaudia state.
- Native Codex tools and extension surfaces are disabled. The subprocess runs in an empty temporary working directory with a read-only sandbox, ignored user/rule configuration, bounded output, and a ten-minute deadline.
- Codex returns schema-bound, inert requests for only the host tools OpenClaudia advertised. OpenClaudia continues to execute those requests through its existing permission, policy, hook, budget, task, and reality-grounding layers.
- Configured OpenAI API keys remain a separate direct-API capability and keep their existing endpoint and typed-secret path.

## Acceptance

- Forged or expired token claims cannot influence OpenClaudia account selection or compliance headers because OpenClaudia no longer parses or forwards them.
- Normal OpenAI API keys and Codex/ChatGPT account login remain separate transport capabilities.
- The Codex account runtime is wired through startup authentication, print mode, full-screen TUI and its tool-follow-up loop, ACP, child agents, pipelines, and all VDD builder/adversary/verifier paths.
- VDD uses the same constrained runtime boundary and provider-budget accounting as the main agent path. VDD remains a no-host-tools verification turn by design.
- Deterministic tests cover executable/argument/environment constraints, bounded output, schema construction, structured result decoding, native/unadvertised tool rejection, and the direct-Responses-versus-runtime continuation distinction.
- Hermetic CLI tests cover successful keyless OpenAI startup in ACP and print mode, case-insensitive provider selection, and fail-before-turn behavior when the owned Codex login is unavailable. Test processes use a fake executable and never consult the developer's real Codex credentials.
- Live validation compiled OpenClaudia, used the existing ChatGPT login with OpenAI credential environment variables removed, completed two print-mode probes, and completed a full-screen TUI turn that requested `read_file`, consumed the host result, requested `grounding_context`, and produced an accepted grounded answer for package `openclaudia` version `0.5.0`.
- The Codex credential-store digest was unchanged by successful print-mode probes. Attach an artifact-bound VDD receipt when S-088 is available.
- The Rust 1.98 all-target/all-feature check, Clippy gate, and serialized full test suite pass. Because this slice changes `src/main.rs`, the checked-in S-105 retrieval evaluation was regenerated with its canonical generator and its deliberately rejected review record was rebound to the exact new artifacts.

## Upstream interface

- [Codex App Server authentication](https://developers.openai.com/codex/app-server/#authentication) documents Codex-owned ChatGPT authentication, persistence, refresh, and account inspection for embedded clients.
- [Codex SDK](https://developers.openai.com/codex/sdk/) documents programmatic embedding through the local Codex runtime.

## Handoff

The runtime boundary intentionally depends on the installed Codex executable's supported command surface. A future migration from constrained `codex exec` to a persistent App Server client may improve latency, but is not required for credential correctness and must preserve OpenClaudia-owned tools, policy, hooks, budgets, and grounding. Completion of this slice does not imply completion of its parent workstream.

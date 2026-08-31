# S-098: Make TUI provider switching and resume atomic

Status: Implemented and verified (2026-08-30)
Effort: Medium
Primary findings: F-132
Workstreams: W3, W12
Depends on: [S-029](./029-oauth-session-lifecycle.md), [S-044](./044-provider-native-state-contract.md), [S-093](./093-proxy-session-isolation.md), [S-096](./096-tui-run-cancellation-supervision.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent displayed provider/model/session state from diverging from the credentials and transport actually used.

## Implementation boundary

- Represent provider selection as one immutable adapter/auth/model/capability/continuation generation and validate complete transitions off-state.
- Resume verifies stored provider-native identity and either restores exactly or performs an explicit compatible migration/new branch.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Injected transition failures retain the previous complete provider binding; no mixed label/credential/transport state is observable.
- Concurrent switch/resume/cancel and incompatible provider histories return typed conflicts without sending a request.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- The TUI now represents its active provider as one generation-bound
  `ProviderBinding`: provider/adapter, model, endpoint, headers, wire protocol,
  Claude/Codex SDK or account authentication, prompt context, VDD builder
  authentication, session identity, and provider-native continuation contract.
- Provider/model switches and session resume prepare every fallible run,
  guardrail, task, scheduler, transport, authentication, and continuation
  dependency off-state. Publication occurs only after validation succeeds;
  failure leaves the previous complete binding active.
- Pending transitions are typed and mutually exclusive. Cancellation retires
  the pending transition, stale or superseded continuation events cannot
  publish, same-provider resume validates exact native history, and switching
  provider/model clears incompatible native state before publishing the new
  generation.
- Every outbound turn revalidates the displayed provider/model and the complete
  API/VDD projection before transcript mutation or request spawn. Startup binds
  an explicit provider target before applying resume state.

## Verification

- Focused TUI coverage passed 90 tests, including failed authentication,
  provider/model switching, same-provider resume, incompatible history,
  pending and stale transitions, cancellation, native continuation state, and
  rejection before transcript mutation.
- Rust 1.98 format and strict all-target/all-feature Clippy gates pass. The
  complete all-target/all-feature suite is also run at the integration commit.

## Residual boundary

Provider calls remain externally effectful once their supervised request has
started, so cancellation can prevent publication but cannot prove a remote
service performed no work. The binding prevents that response from changing a
superseded local session and does not claim stronger remote cancellation.

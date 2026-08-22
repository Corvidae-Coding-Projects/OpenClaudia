# S-098: Make TUI provider switching and resume atomic

Status: Planned
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

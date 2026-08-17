# S-025: Keep secrets typed and redacted end to end

Status: Planned
Effort: Medium
Primary findings: F-015, F-022, F-034, F-079
Workstreams: W3, W14, W18
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent credentials and granted environment values from becoming clonable/debuggable strings or raw logs.

## Implementation boundary

- Introduce non-`Debug`, redacting, zeroizing secret/header/environment capability types through config, auth, provider, TUI, event, error, and transport layers.
- Centralize error/body/header logging policy with field sensitivity, size limits, structured redaction, and secret-scanning tests.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Debug, trace, serialization, channel-error, and provider-failure tests cannot expose seeded secrets.
- Sensitive headers are materialized only at the hardened transport boundary and secret values have bounded ownership/lifetime.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

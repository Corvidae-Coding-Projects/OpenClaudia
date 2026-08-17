# S-027: Replace Anthropic client impersonation

Status: Planned
Effort: Medium
Primary findings: F-081
Workstreams: W3
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Use only provider-supported Anthropic authentication with OpenClaudia's honest application identity.

## Implementation boundary

- Remove Claude Code client identifiers, false identity prompts, private subscription routing assumptions, and copied beta behavior not authorized for this application.
- Implement supported API-key/cloud/gateway auth and add a registered native-client flow only if Anthropic documents one for third parties.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Requests never claim OpenClaudia is Anthropic's official CLI or spend subscription credentials through an unapproved route.
- Unsupported legacy credentials fail with a clear migration path and cannot silently fall back.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

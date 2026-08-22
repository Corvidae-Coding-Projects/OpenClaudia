# S-028: Verify Codex account and compliance metadata

Status: Planned
Effort: Small
Primary findings: F-082
Workstreams: W3
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop using unverified token payloads to choose account and FedRAMP routing headers.

## Implementation boundary

- Use an official credential interface that returns verified issuer, audience, expiry, account, scope, and compliance metadata.
- Treat raw JWT payloads as opaque unless cryptographically verified and reject conflicts or unknown auth schemas.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Forged or expired token claims cannot influence account-selection or compliance headers.
- Normal OpenAI API keys and Codex/ChatGPT credentials remain separate typed endpoint capabilities.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

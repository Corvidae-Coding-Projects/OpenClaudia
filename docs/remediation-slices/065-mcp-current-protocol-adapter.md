# S-065: Implement the current MCP protocol adapter

Status: Complete
Effort: Medium
Primary findings: F-091
Workstreams: W6
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-048](./048-hardened-provider-http-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Use the current MCP specification as the core typed model while isolating older wire revisions behind explicit adapters.

## Implementation boundary

- Implement initialization/version negotiation, capabilities, tools, resources, prompts, content blocks, logging, progress, tasks, and current error/cancellation semantics used by OpenClaudia.
- Keep compatibility fixtures versioned and reject unsupported capability combinations rather than flattening them into strings.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Conformance tests pass against current protocol fixtures and every accepted older version takes an explicit adapter path.
- Images/resources/structured content and protocol errors remain typed through provider and frontend delivery.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

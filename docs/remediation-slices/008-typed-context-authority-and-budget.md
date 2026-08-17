# S-008: Introduce typed context authority and budgets

Status: Planned
Effort: Medium
Primary findings: F-011, F-025, F-026, F-027
Workstreams: W12, W17, W25
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Represent context by provenance, authority, sensitivity, freshness, and budget instead of concatenating arbitrary strings into system instructions.

## Implementation boundary

- Create typed context items and deterministic inclusion/truncation policy; only host-authorized sources may carry instruction authority.
- Convert output-style, hook, memory, skill, project, web, MCP, and tool inputs to source-labeled data and remove raw prompt prefix/suffix APIs.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Untrusted repository or tool text cannot become a system instruction through escaping, wrapping, or source omission.
- Trace fixtures account for every included, omitted, truncated, or promoted context item within a hard token/byte budget.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

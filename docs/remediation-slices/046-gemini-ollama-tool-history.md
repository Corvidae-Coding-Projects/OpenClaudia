# S-046: Repair Gemini and Ollama tool history

Status: Planned
Effort: Small
Primary findings: F-018
Workstreams: W3
Depends on: [S-044](./044-provider-native-state-contract.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve the provider-specific call/result pairing needed for multi-turn Gemini and Ollama tool execution.

## Implementation boundary

- Implement native request conversion for assistant tool calls, call IDs, arguments, tool results, ordering, and parallel/batched behavior.
- Reject histories that cannot be represented rather than silently dropping tool protocol state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Two consecutive tool rounds succeed against recorded provider fixtures with exact call/result correlation.
- Malformed, missing, duplicated, and reordered call IDs produce typed protocol errors.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

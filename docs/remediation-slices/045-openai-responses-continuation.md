# S-045: Preserve OpenAI Responses continuation

Status: Planned
Effort: Small
Primary findings: F-002
Workstreams: W3
Depends on: [S-044](./044-provider-native-state-contract.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Retain response identity and required output items across OpenAI Responses tool and reasoning turns.

## Implementation boundary

- Persist response IDs and provider output items, including encrypted/native reasoning or compaction items required for stateless continuation.
- Make TUI, proxy, print, ACP, and child-run follow-ups consume the same OpenAI continuation adapter.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A multi-turn tool fixture sends valid continuation without reconstructing lossy chat history.
- Resume and compaction preserve required native items while user-visible history exposes only sanctioned summaries.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

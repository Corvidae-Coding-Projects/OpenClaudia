# S-049: Separate reasoning continuation from display

Status: Planned
Effort: Medium
Primary findings: F-118
Workstreams: W3, W12
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-044](./044-provider-native-state-contract.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve reasoning needed for provider correctness without flattening or exposing raw chain-of-thought as ordinary transcript text.

## Implementation boundary

- Model opaque provider continuation, provider-sanctioned user summaries, and protected monitoring as distinct typed channels.
- Define consent, access, encryption, persistence, retention/deletion, export, redaction, and frontend rendering for each channel.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Raw seeded reasoning cannot appear in normal history, logs, exports, ACP/TUI events, or provider switches.
- Provider continuation still round-trips correctly after resume and compaction.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

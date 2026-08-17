# S-102: Persist VDD evidence and issues transactionally

Status: Planned
Effort: Medium
Primary findings: F-137
Workstreams: W15, W20, W28
Depends on: [S-024](./024-artifact-verification-invalidation.md), [S-031](./031-descriptor-safe-persistence.md), [S-052](./052-canonical-task-graph.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-099](./099-vdd-strict-verdict-schema.md), [S-100](./100-vdd-blocking-finalization-gate.md), [S-101](./101-vdd-bounded-provider-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Store resumable redacted review evidence and promote only checked unresolved findings to task state.

## Implementation boundary

- Persist artifact/model/prompt/policy generations, verdicts, citations, sensitivity, revisions, disagreement, retention, and history through capability-safe atomic storage.
- Create/update/resolve W20 issues under explicit policy with idempotent transactional reconciliation; never trust model-supplied paths or prose as authority.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Crash/retry/concurrent review cannot duplicate issues, lose evidence, overwrite newer status, or publish a finding for the wrong artifact.
- Export/delete/redaction and fix-verification flows preserve history while marking exact findings resolved.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

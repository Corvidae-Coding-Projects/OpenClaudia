# S-017: Fix deny precedence and approval scope

Status: Planned
Effort: Medium
Primary findings: F-012, F-030, F-068
Workstreams: W2, W12
Depends on: [S-016](./016-mandatory-tool-effect-classification.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure hard policy and explicit denials dominate, while approvals are narrow, expiring, generation-bound receipts.

## Implementation boundary

- Define deterministic precedence with host hard deny first and migrate broad first-match/tool-wide caches to normalized resource/effect receipts.
- Bind persisted approvals to actor, workspace, tool, exact target/arguments, capability generation, expiry, use count, and provenance in trusted state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A later or more-specific denial cannot be overridden by an old broad allow, including after session resume.
- One approved Bash/path/network operation cannot authorize a different invocation, target, workspace, or generation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

# S-016: Require effect classification for every tool

Status: Planned
Effort: Medium
Primary findings: F-001, F-052
Workstreams: W2, W20
Depends on: [S-011](./011-canonical-typed-tool-results.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make unknown or omitted tool effects fail closed, including shell-like Crosslink mutations.

## Implementation boundary

- Require every static and dynamic handler to declare typed effect targets before registration; eliminate default `None`/safe behavior.
- Replace Crosslink argv dispatch with typed operations whose exact reads and mutations are known before policy evaluation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Registry construction fails for an unclassified handler and unknown dynamic tools are unavailable.
- A generated matrix proves every tool path, including task, cron, worktree, process, MCP, plugin, and Crosslink actions, has an enforced effect.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

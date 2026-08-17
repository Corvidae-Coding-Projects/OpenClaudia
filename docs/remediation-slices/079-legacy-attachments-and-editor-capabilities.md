# S-079: Route legacy attachments and editor input through capabilities

Status: Planned
Effort: Medium
Primary findings: F-113
Workstreams: W12, W15, W18
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-031](./031-descriptor-safe-persistence.md), [S-040](./040-supervised-foreground-process-io.md), [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent `@file` and external editor input from bypassing workspace containment, context budgets, process supervision, and source authority.

## Implementation boundary

- Represent attachments as snapshot-bound typed events with encoding, sensitivity, truncation, per-file and aggregate byte/token limits.
- Run editors through the supervised user-origin process profile and import saved bytes as a reviewed user/evidence event, not system text.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Outside-root, symlink-raced, oversized, binary, changing, and cancelled attachments cannot enter context ambiguously.
- Editor timeout/failure leaves conversation and files consistent and no input gains higher authority through interpolation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

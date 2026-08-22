# S-072: Supervise browser and web work

Status: Planned
Effort: Medium
Primary findings: F-059, F-103
Workstreams: W10, W18, W23
Depends on: [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-071](./071-web-egress-connection-broker.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure web timeout/cancellation stops real work and browser descendants cannot inherit persistent project authority.

## Implementation boundary

- Launch verified browser artifacts in ephemeral restrictive profiles behind a bounded pool with session/tab/process/request/DOM/download/CPU/memory/disk/time limits.
- Tie fetch/search/browser/distillation futures and descendants to the run cancellation tree; make persistent cookies/login an explicit encrypted capability.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Timeout or cancellation closes pages, stops network/model work, reaps descendants, and waits for terminal reconciliation.
- Hostile pages, decompression/DOM bombs, profile links, downloads, bot challenges, and backend markup changes return bounded typed outcomes.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

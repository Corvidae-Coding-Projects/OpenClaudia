# S-019: Eliminate ambient session capabilities

Status: Planned
Effort: Medium
Primary findings: F-033
Workstreams: W2, W15
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-018](./018-non-bypassable-host-safety-policy.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Require explicit workspace, filesystem, process, network, and secret capabilities instead of granting ambient CWD access when context is missing.

## Implementation boundary

- Make capability-bearing run context mandatory at every tool and helper boundary and remove thread/process-global fallback identity.
- Return typed unavailable errors for absent resources and bind descriptor roots and scratch space to the run generation.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Calling any tool without a valid run capability fails closed and cannot read or write the process CWD.
- Concurrent sessions with different roots cannot observe or mutate each other's files, processes, environment, or cancellation state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

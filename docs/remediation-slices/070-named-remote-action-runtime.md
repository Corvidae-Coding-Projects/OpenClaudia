# S-070: Implement named remote actions safely

Status: Planned
Effort: Medium
Primary findings: F-056
Workstreams: W22
Depends on: [S-016](./016-mandatory-tool-effect-classification.md), [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-048](./048-hardened-provider-http-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make symbolic host-registered remote actions callable without exposing arbitrary endpoints, methods, headers, or credentials to the model.

## Implementation boundary

- Define each action's input/result schema, destination policy, effect, approval, idempotency/retry, deadline, cost/rate/body limits, and secret source.
- Register available actions in the canonical catalog and execute through hardened egress with typed delivery/partial-success receipts.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A model can invoke an available reviewed action end to end but cannot choose or smuggle a different endpoint/method/header.
- SSRF, redirect, retry, timeout, cancellation, secret-redaction, and ambiguous external-success tests pass.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

# S-003: Make fuzz targets side-effect free

Status: Planned
Effort: Small
Primary findings: F-139
Workstreams: W13
Depends on: [S-001](./001-capability-evidence-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure arbitrary fuzzer input cannot execute host commands, touch ambient files, or reach external services.

## Implementation boundary

- Replace production side-effect handlers in fuzz targets with hermetic temp capabilities, fake transports, and deterministic bounded fixtures.
- Upgrade no-panic smoke targets to assert protocol, containment, terminal-state, and allocation invariants.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Every fuzz target runs with network and ambient process effects unavailable and writes only beneath its owned temporary root.
- A regression test demonstrates that command/path-shaped fuzzer input cannot escape the fake harness.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

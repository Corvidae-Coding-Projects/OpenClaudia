# S-033: Bound and stabilize file discovery and grep

Status: Planned
Effort: Medium
Primary findings: F-037, F-038
Workstreams: W15
Depends on: [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make listing, globbing, and searching deterministic, paginated, cancellation-aware, and bounded before allocation.

## Implementation boundary

- Use one secure walker with ignore policy, stable ordering, cycle/link containment, cursors, and aggregate file/path/byte/time limits.
- Stream grep matches under pre-allocation caps for files, decoded bytes, regex work, matches, line length, context, and rendered output.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Large trees and match-heavy files return explicit partial pages without unbounded collection or silent truncation.
- Traversal order and pagination are repeatable, and cancellation stops walker/regex work promptly.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

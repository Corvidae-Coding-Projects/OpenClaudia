# S-034: Implement typed multimodal and partial reads

Status: Planned
Effort: Medium
Primary findings: F-040, F-041
Workstreams: W3, W15
Depends on: [S-011](./011-canonical-typed-tool-results.md), [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Return bounded text/binary/image content in provider-usable typed form with working continuation semantics.

## Implementation boundary

- Define text ranges/cursors by stable byte or line units and return next-position, truncation, encoding, MIME, sensitivity, and artifact identity.
- Route image/media blocks through provider-native inputs or a declared unsupported state instead of embedding base64 in prose.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A caller can retrieve every bounded segment of an oversized text file without gaps or impossible offsets.
- Image tests reach supported providers as typed media and never duplicate large base64 into the model transcript.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

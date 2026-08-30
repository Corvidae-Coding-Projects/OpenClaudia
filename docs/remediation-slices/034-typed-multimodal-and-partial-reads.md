# S-034: Implement typed multimodal and partial reads

Status: Implemented and deterministically verified; artifact-bound VDD receipt not recorded
Effort: Medium
Primary findings: F-040, F-041
Workstreams: W3, W15
Depends on: [S-011](./011-canonical-typed-tool-results.md), [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Delivered — 2026-08-25

Commits `db72f6d8` and `ec205a36` delivered descriptor-pinned bounded text and
binary pages with generation-bound cursors, typed MIME/encoding/sensitivity and
artifact metadata, transient non-durable image payloads, provider-native media
projection where supported, and explicit unsupported outcomes elsewhere. Raw
attachment bytes do not enter durable tool results or transcripts.

## Verification evidence

Crosslink issue #1136 records Rust 1.98 formatting, strict all-target/all-feature
Clippy, the complete serialized workspace suite, focused read/registry/provider
and integration tests, fuzz and dependency-policy gates, and Windows GNU checks
as passing. PR #66 head `ec205a36` subsequently passed repository-policy, MSRV,
Linux, macOS fail-closed, and Windows fail-closed runners.

## Residual boundary

The typed read and transport behavior is complete. An independent,
artifact-bound VDD receipt was not recorded with this slice.

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

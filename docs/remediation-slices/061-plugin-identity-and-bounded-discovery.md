# S-061: Bind plugin identity and discovery to trusted scope

Status: Implemented and verified (2026-08-30)
Effort: Medium
Primary findings: F-097, F-101
Workstreams: W26
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent project metadata, collisions, and attacker-controlled links from impersonating trusted plugins.

## Implementation boundary

- Discover through descriptor-safe bounded walks and assign identity from host scope, canonical source, immutable revision/digest, manifest schema, and owner.
- Reject ambiguous names, duplicate components, path/scope forgery, unsupported links, oversized trees/files, and changed trusted packages.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A project plugin cannot claim user/system installation scope or shadow a trusted name nondeterministically.
- Discovery is deterministic, bounded, symlink-safe, provenance-bearing, and invalidates trust on mutation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Discovery roots now carry host-selected scope: global catalogues accept only
  managed/user entries and project catalogues accept only project/local
  entries. Project bindings are canonical and repository metadata cannot
  rebind an install to another scope or root.
- Tracked installs validate every path component without following symlinks,
  remain under their selected catalogue, and bind manifest schema, canonical
  source, immutable tree digest/revision, scope, and owner into one stable
  package identity carried through activation and lifecycle receipts.
- Convention discovery is deterministic and bounded before allocation: each
  tree shares an 8,192-entry budget and each search root admits at most 4,096
  candidates. Oversized files/trees, duplicate or ambiguous names, duplicate
  components, unsupported links, receipt drift, and identity changes fail the
  package closed.
- Foreign Claude plugin caches are no longer ambient discovery authority.
  Compatibility packages remain available through an explicit import path;
  normal discovery is limited to OpenClaudia user and project roots.

## Verification

- Focused plugin coverage passed 179 tests, including scope forgery,
  cross-catalogue rebinding, mutation invalidation, manifest strictness,
  symlink rejection, deterministic conflicts, bounded discovery, and the
  exclusion of ambient foreign cache paths.
- Rust 1.98 format and strict all-target/all-feature Clippy gates pass. The
  complete all-target/all-feature suite is also run at the integration commit.

## Residual boundary

The compatibility `disabledPlugins` projection remains name-only, and legacy
flat catalogue entries are digest-bound but do not have the newer generation
receipt. Neither surface can claim a stronger scope or bypass the bound
activation identity; migrating their persisted schema remains separate work.

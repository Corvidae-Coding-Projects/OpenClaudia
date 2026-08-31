# S-107: Add complete portable technical-memory export and import

Status: Implemented and adversarially reviewed; independent VDD pending
Effort: Medium
Primary findings: Design requirement from W5
Workstreams: W2, W5, W15
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md), [S-054](./054-memory-authority-and-schema.md), [S-056](./056-operational-memdir-lifecycle.md), [S-106](./106-host-reviewed-memory-export.md)
Crosslink: #1079

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Users can export and strictly round-trip one workspace's complete selected
technical-memory causal set through the canonical `memory_export` and
`memory_import` tools. The format contains typed codebase lessons, source
lifecycle records, and host-review audit roots only. It does not capture legacy
memory prose, prompts, messages, sessions, transcripts, or ambient context.

The operations are explicit tool calls rather than prompt injection. Every call
requires a fresh one-use decision from an interactive user, ACP client, or host
administrator and the exact source/destination filesystem capability. Session,
persisted, policy-default, coordinator, model, and subagent grants cannot create
this authority.

## Implemented format

Package schema v1 is canonical JSON with unknown fields rejected. It carries:

- the exact workspace and source-store identities;
- package, snapshot, manifest, part, entry-array, record, content, citation,
  source, and approval-evidence digests;
- every immutable revision and exact causal head for the selected user-private
  technical-lesson, source-lifecycle, and host-review-audit lineages;
- tombstones, applicability, citations, sensitivity, retention, review state,
  provenance, attribution, and original store identity without rewriting;
- the internal source-store schema for diagnostics. Packages emitted by the
  multi-parent implementation declare memory reader schema 7; legacy packages
  may still declare schema 6 only when every revision has the linear v6 shape.
  Unrelated future internal migrations do not invalidate this portable contract.

Entries are ordered by logical identity, version, and record digest. Each
length-prefixed canonical entry contributes to the snapshot digest. Parts are
ordered, sequence-contiguous, chained by the previous part digest, and bound to
the package identity. A final manifest is the sole completion marker.

The checked-in empty-manifest schema vector is:

`sha256:402f53d475bb34e2ef4b24ac47a0588a6f47614a612cc670af285e0be0817b10`

## Fixed bounds and recovery

- 96 KiB maximum canonical entry.
- 3 MiB target part payload and 4 MiB hard part/file allocation ceiling.
- 512 parts and 2 GiB declared package-part bytes maximum.
- 2,000,000 entries maximum, derived from at most 1,000,000 validated
  revisions plus one head per lineage.
- 60-second per-invocation work deadline with cancellation checked throughout
  snapshot, validation, replay, and application loops.
- Owner-private descriptor-safe package leaves; canonical package files are
  created as 0600 and links, non-regular leaves, unsafe roots, or wider
  existing modes are rejected before bytes are trusted.
- Checkpoints bind schema, package/snapshot/workspace/store identities, pinned
  destination root identity, counts, exact next sequence, and the completed
  descriptor prefix. Resume requires the exact checkpoint digest returned to
  the host. Matching prior parts are validated but not needlessly rewritten or
  re-synchronized; missing exact prior parts can be deterministically
  republished, while divergent bytes fail closed.
- Partial results carry typed cancellation, deadline, uncertain-durability,
  checkpoint, and continuation state without lesson text or filesystem paths.
  A pre-snapshot stop leaves package and snapshot identities absent rather than
  fabricating them.

The exporter reads one deferred SQLite snapshot, streams bounded parts, then
opens an immediate transaction and recomputes the complete selected snapshot.
That writer fence remains held through final-manifest publication, preventing a
memory mutation between the final comparison and completion marker. The
manifest is committed only after all parts and a parts-complete checkpoint are
durable. A final-manifest or checkpoint durability uncertainty is reported as
partial, never as complete.

The importer first verifies the final manifest and every bounded part without
mutating the store. It then opens one immediate transaction, verifies that the
target selected causal set is empty or an exact replay, rereads and validates
every part, applies all revisions/heads, rebuilds projections, and recomputes
the full snapshot before one commit. Cancellation, deadline, validation, or
causal failure drops the transaction without a partial memory mutation. Exact
replay, including an empty package, is idempotent. Legacy rows already in the
target remain untouched and are neither compared nor imported.

## Frontend and lifecycle wiring

- Chat/TUI use the canonical registry, effect resolver, permission receipts,
  run cancellation, memory capability, and structured tool results.
- ACP routes both operations through that same registry. Its current headless
  execution path correctly fails closed when no authenticated interactive host
  prompt is available.
- Subagent roles and plan mode exclude export/import because they have no
  direct host-approval channel. Read-only lesson retrieval remains available
  where already authorized.
- Tool catalogs now contain 48 base tools with the browser feature (46 without)
  and 51 with the three subagent tools (49 without browser).
- Imported source provenance remains exact. A later source refresh may
  legitimately contain preserved foreign-origin and newly local-origin
  revisions; source authority is validated by workspace, deterministic member
  identity, exact head/digest, source evidence, and non-empty origin rather
  than incorrectly requiring one physical-store UUID for all history.

## Adversarial coverage

`tests/technical_memory_portable_e2e.rs` proves:

- complete round trip of source state, reviewed lesson/audit, ordinary lesson,
  immutable history, heads, tombstone, provenance, citations, sensitivity, and
  retention;
- complete round trip of a resolved branching history, including every causal
  parent and the graph-derived sole head;
- exclusion of a recognizable legacy prose row from package files and tool
  receipts while leaving a target legacy row untouched;
- exact replay idempotence and deterministic snapshot equality after
  re-export;
- continued source refresh after import with mixed preserved/local origin
  provenance;
- fresh exact host approval on every call, rejection of session/persisted/
  coordinator grants, changed-argument rejection, and truthful pre-snapshot
  cancellation with no final manifest;
- rejection before target mutation of tampered, oversized, incomplete,
  noncanonical, symlinked, and wrong-workspace packages;
- exact empty-package idempotence.

Unit and surrounding integration coverage additionally proves checkpoint
prefix reconciliation, the final writer fence, deadline behavior, canonical
schema digest/budgets, source and review invariants, dedicated persistence
class bounds, ACP dispatch, one-use TUI prompt choices, registry effects and
resources, plan/subagent exclusion, and both catalog counts.

The first full-suite run correctly exposed stale 44/47 catalog assertions in
`tests/get_all_tool_definitions_subagents_e2e.rs`. They were updated to the
actual 46/49 catalog only after the tests were inspected and the two new
canonical registry entries were confirmed; the focused binary then passed
16/16 and the complete suite rerun passed.

## Verification record

All Rust commands used the repository-pinned Rust 1.98.0 toolchain,
`CARGO_BUILD_JOBS=4`, `--locked`, and `-- --test-threads=1` for test commands.

- `cargo fmt --all -- --check`: pass.
- `git diff --check`: pass.
- Portable unit tests: 4 passed.
- Portable end-to-end tests: 5 passed.
- Technical-memory source end-to-end tests: 12 passed.
- Host-review end-to-end tests: 7 passed.
- Permission unit filter: 48 passed.
- Dedicated persistence-class unit filter: 1 passed.
- Registry-global invariants: 21 passed.
- Subagent/plan-mode invariants: 15 passed.
- Tool-definition integration filter: 5 passed.
- Catalog/subagent definitions: 16 passed.
- ACP typed-memory route: 1 passed.
- Durable-memory prompt-choice route: 1 passed.
- `cargo check --all-features --all-targets`: pass.
- strict `cargo clippy --all-features --all-targets -- -D warnings`: pass with
  no warnings.
- full `cargo test --all-features --all-targets`: pass. Library result was
  2,697 passed, 0 failed, 1 ignored; binary result was 219 passed, 0 failed;
  every integration binary passed.
- Windows GNU `cargo check --all-features --all-targets`: pass. It emitted only
  previously tracked target-conditional unused/dead-code warnings outside
  S-107; the three initially observed S-107 conditional imports were corrected
  and the rerun emitted no S-107 warning.
- Issue #1081 follow-on: portable units passed 6/6 and portable E2Es passed 6/6,
  including truthful v6-reader rejection of multi-parent data and exact
  root/branches/merge export-import. The focused affected integration set
  passed 117/117, strict Rust 1.98.0 Clippy passed, and the complete native
  all-feature/all-target matrix plus Windows GNU all-target check passed.

The SHA-256 manifest of the 20 implementation/test artifacts is
`81a3eda0a15cbf484b6835a7d720c8c183d40d18141e8879e34b25b1bd65b35b`.
The individual path digests are retained in the S-107 Crosslink result receipt.

## Privacy and residual boundaries

The package is a user-private portability/backup boundary for one exact
workspace identity, not a team synchronization protocol. S-103 owns
authenticated team authority and S-104 owns replication, conflict, and
revocation behavior. S-105 owns evaluated ranking and usefulness of explicit
technical-memory retrieval. Newly discovered issue #1080 owns atomic source
lifecycle advancement when a host directly reviews a source-managed lesson;
ordinary source refresh after portable import is fixed and covered here. Issue
#1081 extends the same package schema with truthful schema-v7 multi-parent
history while retaining strict reads of linear schema-v6 packages.

The descriptor-safe persistent backend remains Unix-only until S-036 provides
the Windows implementation. Windows compilation is deterministic, but runtime
memory/package persistence continues to fail closed there. Independent
artifact-bound verification remains queued under S-088; this slice does not
self-assert that separate-model verdict.

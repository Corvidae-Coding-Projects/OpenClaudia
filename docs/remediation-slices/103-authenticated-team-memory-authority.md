# S-103: Establish authenticated team-memory authority

Status: Implemented and adversarially reviewed; artifact-bound VDD pending
Effort: Medium
Primary findings: Design requirement from F-075 and W5
Workstreams: W3, W5
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-029](./029-oauth-session-lifecycle.md), [S-031](./031-descriptor-safe-persistence.md), [S-053](./053-memory-record-identity-and-merge.md), [S-054](./054-memory-authority-and-schema.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Give team technical memory a real authenticated authority model instead of
treating knowledge of a shared filesystem path as membership.

## Implementation boundary

- Define stable team, workspace, principal, membership, role, grant, and
  revocation identities. Bind every grant to an authenticated principal, exact
  team/workspace scope, permitted memory operations, expiry, and key generation.
- Store credentials and private key material through the typed secret boundary;
  repository configuration may select a host-approved team identity but cannot
  create membership, widen roles, or redirect authority to a repository path.
- Require authorization before listing, searching, proposing, correcting,
  deleting, exporting, or administering team lessons. Emit redacted, bounded,
  causally linked audit receipts for successful and denied operations.
- Define enrollment, key rotation, revocation, recovery, and lost/offline
  credential behavior. Fail closed when identity, membership, role, workspace,
  clock/expiry, or audit state cannot be validated.
- Keep replication transport and offline data synchronization in S-104; this
  slice creates the authority contract and host-owned credential lifecycle.

## Acceptance

- Possessing or configuring a database/directory path never grants team access.
- Cross-team, cross-workspace, expired, revoked, downgraded, replayed, and
  repository-forged grants fail before data or metadata is disclosed or changed.
- Role matrices and credential/key rotation are exercised through each canonical
  team-memory operation with redacted audit receipts and restart tests.
- Relevant deterministic tests and trace assertions pass; attach an
  artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence
receipts, unresolved risks, and any newly proposed slice. Completion of this
slice does not imply completion of its parent workstream.

## Implementation record

Architecture generations: `team-authority-state-v1` and
`team-authority-artifact-v1`.

- `src/team_memory/authority.rs` establishes strict team, workspace,
  principal, membership, grant, invitation, enrollment-request, and authority
  key identities. An Ed25519 trust anchor signs a bounded key-epoch chain and
  current membership document. Principal keys sign short-lived, one-use grants
  bound to the exact team, workspace, role, operation, request digest, expiry,
  authority generation, membership generation, and principal-key generation.
- Credentials live in the descriptor-safe host workspace state root as
  `FileClass::Credentials`, never in repository configuration or a public
  artifact. Secret serialization is confined to a zeroizing buffer; ordinary
  `SecretString` display/serialization remains redacted. Repository and
  environment configuration can select only a strict `TeamId`.
- Authorization durably consumes the grant and appends a bounded causally
  linked redacted audit event before returning an opaque permit. The permit
  retains every signed generation binding and is revalidated inside authority
  mutations and at the downstream operation boundary, so a concurrent
  downgrade, revocation, or key rotation invalidates it.
- Reader, contributor, maintainer, and owner roles cover every canonical
  technical-memory operation, including S-104 pull/push operations. Listing
  public authority state or audit receipts also requires current local
  membership; expired and revoked callers receive no team metadata.
- Manual public-artifact enrollment, renewal, revocation, role changes,
  principal-key rotation, authority-key rotation, signed-bundle import, and
  redacted audit inspection are reachable through `openclaudia team`. Artifact
  commands infer the signed team identity when safe, while an explicitly
  supplied mismatching identity fails closed.
- Interrupted pending enrollment can restart atomically with a fresh private
  credential. A revoked principal can re-enroll only from a newly issued
  invitation and receives a new membership and key. An expired local owner may
  use the narrowly scoped break-glass path only on the authority-signing host;
  the successor document and `recovery_allowed` audit event commit together.
  Revocation cannot use that path. An expired owner does not satisfy the
  last-active-owner invariant.
- Losing an ordinary principal credential requires fresh owner-approved
  enrollment. Losing the sole authority signing credential has no insecure
  reset path: existing members remain bounded by their signed roles/expiries
  and must migrate permitted lessons through explicit typed reads and writes
  into a newly bootstrapped team. Offline hosts retain signed state and fail
  stale/revoked grants after
  importing a newer bundle.
- The legacy `memory.team_memory_path` input remains parseable only to produce
  a permanent migration error. `TeamMemoryStore::open` rejects it before
  creating a directory or database. S-104 now exposes the causal replica only
  through authenticated encrypted host-owned storage, never as path-based
  authority.

## Adversarial evidence

- `tests/team_memory_authority_e2e.rs` covers all four roles across every
  operation, success and durable denial receipts, exact scope/request/expiry,
  replay across restart, forged signatures, downgrade, revocation, both key
  rotations, generation-bound permit invalidation, active-owner preservation,
  clock rollback, recovery, interrupted and revoked re-enrollment, concurrent
  consumption, corrupt credential state, and public artifact bounds.
- `tests/team_memory_authority_cli_e2e.rs` executes the real binary to create,
  inspect, and invite from a team; completes enrollment across two isolated
  host stores using only public JSON artifacts; verifies credential mode and
  output redaction; and proves a repository selector creates no membership.
- `tests/memory_identity_e2e.rs` and
  `tests/team_memory_thinking_e2e.rs` retain direct causal-identity coverage
  while asserting that production path activation is rejected without side
  effects. S-104 separately binds the authenticated encrypted data plane to the
  public tools, host CLI, startup frontends, and transport tests.

Current focused Rust 1.98.0 evidence (`CARGO_BUILD_JOBS=4`, tests with
`--test-threads=1`):

- authority E2E: 15 passed;
- authority CLI E2E: 3 passed;
- memory identity E2E: 5 passed;
- team-memory boundary and thinking E2E: 34 passed;
- capability corpus: 11 passed; lifecycle reachability: 6 passed; CLI/docs:
  60 passed; configuration contracts: 27 passed; typed environment process
  tests: 5 passed;
- locked all-feature/all-target `cargo check`: passed;
- locked all-feature/all-target strict Clippy with `-D warnings`: passed;
- locked all-feature/all-target native test suite with one test thread: passed
  with exit status 0, including every unit, integration, binary, and doctest
  target selected by Cargo;
- locked all-feature/all-target Windows GNU cross-target `cargo check`: passed
  with exit status 0 in 1m 01s. Its warnings were pre-existing
  target-conditional unused/dead-code findings outside the S-103 paths; no
  team-authority warning was emitted.

After the final audit-helper API cleanup, the authority and real-binary CLI
suites were rerun (15/15 and 3/3) and the strict all-target Clippy gate passed
again. All commands used Rust 1.98.0 and `CARGO_BUILD_JOBS=4`; tests used
`--test-threads=1`.

The SHA-256 digest of the sorted `sha256sum` manifest for the 19 changed
non-slice artifacts is
`053a6f52232942afa8c355b478a2bb77f092d67345d94ae3ee4af72b73f9efbd`.

The capability registry was deliberately not regenerated or promoted by this
slice. Its final-state receipts bind the reviewed S-001 corpus; changing that
artifact requires a new independent corpus review rather than fabricated hash
updates. S-088 owns artifact-bound VDD. S-104 implements encrypted bounded
lesson replication and tool/frontend data access. Non-Unix private-memory runtime
availability remains dependent on the descriptor-safe platform backend from
S-036; cross-target compilation is still required here.

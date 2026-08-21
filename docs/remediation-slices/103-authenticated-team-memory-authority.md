# S-103: Establish authenticated team-memory authority

Status: Planned
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

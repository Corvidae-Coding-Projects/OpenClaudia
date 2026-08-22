# S-062: Make plugin install and update verifiable transactions

Status: Planned
Effort: Medium
Primary findings: F-098, F-099
Workstreams: W15, W26
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md), [S-061](./061-plugin-identity-and-bounded-discovery.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace nominal inline signatures and partial Git mutations with artifact-bound verification and atomic activation.

## Implementation boundary

- Define source pinning, digest, signer policy, provenance, dependency closure, rollback/freeze protection, offline cache, and revocation using established supply-chain semantics.
- Stage download/checkout/validation separately, verify the complete immutable package, then atomically switch the active generation with crash recovery.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Self-authored metadata cannot validate itself, and tag/branch movement or partial download cannot become trusted activation.
- Install/update crash points preserve either the old complete generation or the new verified one, never a mixed package.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

# S-030: Make interactive API-key setup secret safe

Status: Planned
Effort: Small
Primary findings: F-111
Workstreams: W3, W14, W15
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Collect and store API keys without terminal echo or accidental repository persistence.

## Implementation boundary

- Use hidden input and an explicit destination chooser backed by the trusted secret/config store.
- Reject project-local plaintext destinations by default and show scope, provider, overwrite, and persistence consequences before commit.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Terminal transcripts, errors, debug output, shell history, and repository files do not contain the entered test key.
- Interrupted, invalid, and overwrite flows leave previous credentials unchanged.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

# S-005: Replace generic environment-key rewriting

Status: Planned
Effort: Small
Primary findings: F-013
Workstreams: W14
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Load environment configuration through an explicit typed map so multiword fields and provider namespaces resolve correctly.

## Implementation boundary

- Declare supported environment variables beside the typed configuration fields, including parse, secrecy, precedence, and deprecation metadata.
- Reject ambiguous/unknown keys and test environment, file, CLI, and default precedence for every supported field.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- All documented multiword settings round-trip from environment variables to the intended typed field.
- Unknown or malformed security-relevant variables fail visibly rather than being ignored or mapped elsewhere.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

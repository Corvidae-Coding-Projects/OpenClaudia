# S-047: Replace static model-name capability guesses

Status: Planned
Effort: Medium
Primary findings: F-020
Workstreams: W3
Depends on: [S-044](./044-provider-native-state-contract.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Resolve models and features from current provider capabilities with a dated fallback rather than substring assumptions.

## Implementation boundary

- Add provider discovery/metadata adapters and a cache with provenance, expiry, access-state, unknown-cost, and deprecation handling.
- Separate canonical model identity from aliases and validate thinking, tools, context, output, streaming, and pricing capabilities at selection.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Unknown/new/deprecated/limited-access models produce accurate selectable, unavailable, or unknown states without mapping to an unrelated default.
- Tests pin fallback age/provenance and prevent stale names from silently enabling unsupported features.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

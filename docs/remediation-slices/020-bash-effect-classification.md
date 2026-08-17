# S-020: Replace Bash auto-approval heuristics

Status: Planned
Effort: Medium
Primary findings: F-045, F-050
Workstreams: W2, W18
Depends on: [S-016](./016-mandatory-tool-effect-classification.md), [S-018](./018-non-bypassable-host-safety-policy.md), [S-019](./019-explicit-session-capabilities.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop classifying arbitrary shell text as read-only and remove the bypassable optional path gate as an authority boundary.

## Implementation boundary

- Parse only a deliberately small typed command facade for auto-approved read effects; classify general shell execution as process/workspace mutation requiring policy.
- Enforce filesystem/process capabilities in the sandbox rather than lexical path substrings, retaining lexical checks only as defense-in-depth.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Mutation hidden behind aliases, interpreters, quoting, substitutions, redirection, scripts, or mixed pipelines cannot receive read-only approval.
- The optional path-gate flag and its security claims are removed or reduced to an explicitly non-authoritative lint.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

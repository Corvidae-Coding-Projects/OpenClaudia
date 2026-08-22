# S-043: Route direct shell through the process capability

Status: Planned
Effort: Small
Primary findings: F-112
Workstreams: W18
Depends on: [S-020](./020-bash-effect-classification.md), [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Remove the legacy `!command` executor as a second unsandboxed permission system.

## Implementation boundary

- Represent user-origin direct shell as a typed command action using the same policy, sandbox, budgets, supervision, trace, and cancellation as agent shell.
- Preserve streamlined user consent without granting unrestricted ambient machine authority or bypassing hard host policy.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- No public legacy helper can execute a process outside the canonical supervisor.
- Direct-shell tests cover quoting, case, protected paths, secrets, network, timeout, cancellation, and terminal status.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

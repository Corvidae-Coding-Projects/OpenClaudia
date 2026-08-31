# S-060: Sandbox and budget hook execution

Status: Implemented and verified (2026-08-30)
Effort: Medium
Primary findings: F-088
Workstreams: W10, W18, W25
Depends on: [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-058](./058-explicit-hook-import-trust.md), [S-059](./059-canonical-hook-lifecycle.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent hook command-policy bypass and concurrent unbudgeted execution.

## Implementation boundary

- Resolve trusted executable identity and arguments without shell-string reinterpretation; run under the declared least-privilege profile.
- Reserve aggregate process/model/time/byte/cost/concurrency budgets before launching matching hooks and cancel/join all work on denial or run end.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Aliases, wrappers, quoting, environment, path changes, and repository executables cannot bypass hook policy.
- A deny result cannot arrive after unbounded sibling side effects, and overload produces a typed skipped/degraded state.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Direct hooks resolve an exact executable and argv before aggregate admission;
  shell compatibility resolves and authorizes the platform shell itself. Bare
  allowlist names use the run-bound search path, approved repository imports
  pin canonical executable paths, and unavailable unrelated allowlist entries
  cannot mask a later valid identity.
- Command hooks default to the repository-hook OS sandbox. Weaker modes require
  an explicit host startup trust decision, and child environments contain only
  run-granted non-secret values plus the documented project-directory value.
- A matching batch reserves process, model, token, cost, time, concurrency,
  input, and output capacity before launch. One child cancellation tree and
  shared process supervisor enforce deadlines, bounded pipes, process-tree
  reaping, sibling cancellation, joining, and typed skipped/failed receipts.
- The shared pre-tool gate now consumes the canonical lifecycle receipt
  directly, preserving exact denial and admission-failure reasons across ACP
  and the other frontend callers.

## Verification

- Focused hook unit coverage passed 83 tests, including shell resolution,
  allowlist identity, sandbox publication/rollback, blocked stdin, deadline,
  cancellation, and lifecycle ordering cases.
- Repository hook import coverage passed 19 tests after pinning assertions to
  the canonical executable path carried by the approval proposal.
- Rust 1.98 format and strict all-target/all-feature Clippy gates pass. The
  complete all-target/all-feature suite is also run at the integration commit.

## Residual boundary

Executable identity is checked immediately before ordinary path-based spawn;
the supported platforms do not yet expose a portable descriptor-based exec
operation. Model-hook reservations therefore remain deliberately conservative
when a provider cannot return exact usage. Both limits are explicit and do not
restore ambient execution authority.

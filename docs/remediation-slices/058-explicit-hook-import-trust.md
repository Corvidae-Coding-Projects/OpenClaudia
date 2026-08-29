# S-058: Require explicit trust for hook imports

Status: Implemented; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-086
Workstreams: W25
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-018](./018-non-bypassable-host-safety-policy.md), [S-025](./025-end-to-end-secret-types-and-redaction.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Stop ambient Claude/user/project settings from granting executable or instruction authority.

## Implementation boundary

- Make compatibility discovery a bounded proposal containing source scope/path/digest/owner, events, executables, outputs, and requested capabilities.
- Store host approval outside the repository and require reapproval on content, path, owner, workspace, or capability change.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Checking out a repository cannot activate a hook or weaken host policy without an explicit receipt.
- Malformed, ambiguous, oversized, symlinked, foreign, and changed imports fail atomically and visibly.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered — 2026-08-29

- User, project, and local Claude hook files are discovered as inert proposals.
  Ordinary unrelated Claude settings remain compatible, while the imported hook
  subtree is parsed strictly and malformed sibling sources disable activation
  atomically.
- Host-owned approval receipts live outside the repository and bind workspace,
  source scope/path/owner/digest, events, effects, capabilities, output contract,
  executable path/digest/owner, exact argv, and every referenced file. Any
  mutation requires explicit reapproval.
- Approval never widens managed host policy. Repository-resident, ambiguous,
  tampered, oversized, linked, foreign-owner, or explicitly denied proposals
  remain inert and produce review diagnostics through `openclaudia hooks status`.

## Verification evidence

- Rust 1.98 formatting, locked all-target checking, and strict locked
  all-feature/all-target Clippy with `-D warnings` passed.
- Repository hook-import E2E passed 19/19 and Claude compatibility hook E2E
  passed 18/18, serialized. Coverage includes approval, source mutation,
  workspace binding, user-global imports, malformed siblings, forged receipts,
  pinned executables, host denial precedence, and unrelated settings.

No VDD receipt is claimed here. S-088 remains the independent artifact-bound
verification boundary.

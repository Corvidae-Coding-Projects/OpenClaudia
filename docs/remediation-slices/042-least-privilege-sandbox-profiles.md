# S-042: Enforce least-privilege sandbox profiles

Status: Planned
Effort: Medium
Primary findings: F-048, F-049
Workstreams: W18
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-040](./040-supervised-foreground-process-io.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make each process profile grant only its declared filesystem, network, environment, device, and process capabilities.

## Implementation boundary

- Compile profile-specific OS restrictions and protected descriptor roots before spawn; remove profile names that all map to the same authority.
- Create protected control files/directories before delegation and eliminate writable-tree pre-scan races through descriptor/mount policy.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Document parsing, LSP, hooks, Git, shell, MCP, browser, and analyzers fail conformance tests when attempting undeclared effects.
- Missing protected paths, symlink swaps, child processes, and writable mounts cannot bypass the profile.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

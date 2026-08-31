# S-042: Enforce least-privilege sandbox profiles

Status: Implemented and deterministically verified; structural writable projection pending S-108 and artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-048
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

- Wired document parsing, LSP, hooks, Git, shell, MCP, and analyzers fail conformance tests when attempting undeclared profile effects.
- Environment, root, network, device, and child-process grants are compiled from the selected profile and exposed in redacted trace evidence.
- Browser process conformance remains with S-071/S-072, and transactional protection of absent leaves within writable project trees remains with S-108.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record (2026-08-23)

Sandbox authority is now compiled from typed policies rather than being inferred
from a profile name after spawn. Every wired subprocess path receives only the
filesystem roots, environment names, executable lookup behavior, and child
process capability declared for that profile.

| Profile | Workspace | Environment | Child processes |
|---|---|---|---|
| Shell | Run-authorized roots and modes | Exact run grants | Allowed |
| Repository hook | Project and private scratch; run-authorized project mode | Non-secret run grants plus validated harness-owned values | Allowed |
| LSP, static analyzer, quality gate | Read-only project and private scratch | Non-secret run grants | Allowed |
| Document parser | Private scratch only | Empty | Denied |
| MCP stdio | Project and private scratch; run-authorized project mode | Exact server-declared values | Allowed |
| MCP header helper | Private scratch only | Validated helper values | Allowed |
| Git worktree | Project and private scratch; run-authorized project mode | Validated Git-specific values | Allowed |

Descriptor-duplicated roots are filtered before sandbox construction. Project
profiles no longer inherit unrelated attachment or output roots, read-only
profiles force the source tree read-only, and parser work ignores the caller's
working directory. Read-only developer tools receive private Cargo and Python
cache locations so normal analysis can run without mutating source. Shell,
hook, MCP, and Git paths retain their intended project-write behavior.

Explicit child environment values are admitted only for the profiles that need
them. Names are validated, loader and sandbox-owned variables are rejected, MCP
children receive only their server declaration, and secrets are not copied into
hooks, analyzers, parsers, or helpers. The same environment rules apply when a
user explicitly disables host sandboxing. Effective grants are emitted as a
structured trace containing counts and policy decisions, never values.

Linux runtime tests prove that parsers cannot observe the project or an API key,
that LSP/static-analysis/quality processes cannot modify the project, and that
normal shell cache behavior remains unchanged. Unit and integration coverage
also exercises the policy matrix, compiled bind/environment arguments, explicit
environment rejection, hook behavior, MCP child narrowing, network denial, and
host-escape attempts.

Verification used Rust 1.98.0 with `CARGO_BUILD_JOBS=4` and serialized test
execution:

- `cargo +1.98.0 check --locked --all-features --all-targets`
- `cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
- `cargo +1.98.0 test --locked --workspace --all-targets --all-features -- --test-threads=1`
- `cargo +1.98.0 fmt --all -- --check`
- Windows GNU all-target/all-feature compilation passed; existing
  target-conditional warnings remain tracked by Crosslink #1099.

Browser execution is intentionally not represented by a dormant profile:
[S-071](./071-web-egress-connection-broker.md) and
[S-072](./072-supervised-browser-and-web-cancellation.md) own its connection
broker, process attachment, and conformance tests. The remaining structural
part of F-049 cannot be made race-safe with another pathname pre-scan while a
broad writable project bind remains. [S-108](./108-transactional-writable-workspace-projection.md)
therefore owns the transactional writable projection required to prevent
creation of absent protected leaves without breaking ordinary project edits.
Crosslink #1118 tracks that work. Independent artifact-bound VDD remains S-088.

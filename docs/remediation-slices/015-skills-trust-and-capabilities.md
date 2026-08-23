# S-015: Finish skills as scoped capabilities

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-028
Workstreams: W16
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-018](./018-non-bypassable-host-safety-policy.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Preserve skills while making discovery, activation, instructions, hooks, and tool grants provenance-aware and enforceable.

## Implementation boundary

- Bound and deterministically cache skill discovery by trusted scope, path identity, digest, schema, and workspace generation.
- Treat skill text as reviewed context data and compile declared tool/hook/file/network needs into explicit capabilities instead of automatic project authority.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Project skills cannot activate or gain instruction/tool authority without the configured trust decision.
- Invocation, conditional activation, freshness, containment, size, collision, and revoked-capability tests pass across frontends.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered architecture

- Discovery now produces a deterministic, bounded catalog with explicit managed, project, and user provenance. Managed packages take precedence over project packages, which take precedence over user packages; collisions are reported rather than resolved by filesystem order.
- Repository skills are proposals until the host records an exact-workspace trust receipt. Trust is stored outside the repository, written atomically with owner-only permissions, checked against the current catalog digest, and explicitly revocable.
- Skill text enters model context only as source-labelled reference data. Model-selected and path-selected skills cannot grant effects. Explicit user invocation may request one-turn tools, model, effort, and hooks only after intersection with the run capability and host policy.
- Skill lookup, prompt catalogs, conditional path activation, file-touch observation, slash commands, the `skill` tool, CLI trust management, print mode, the legacy REPL, and the TUI all use the same run-bound catalog and activation contract.
- Skill hooks merge below host hooks and host policy. Project skill roots and entries reject symlinks and workspace escape, including a symlinked `.openclaudia/skills` root.

## Verification evidence

- `cargo +1.98.0 fmt --all -- --check`: passed.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 clippy --locked --workspace --all-targets --all-features -- -D warnings`: passed.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 test --locked --workspace --all-targets --all-features -- --test-threads=1`: passed with zero failures. The first audit run exposed one changed documented parse-error string; the stable wording was restored and the complete gate was rerun successfully.
- Focused trust/capability, skill dispatch/execution, hook precedence, session isolation, and technical-memory evidence suites passed, including the project-root symlink containment regression.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 check --locked --target x86_64-pc-windows-gnu --workspace --all-targets --all-features`: passed. Existing target-conditional warning debt remains tracked by Crosslink #1099.
- The 27 repository-policy unit tests and `scripts/check_repository_hygiene.py --repo-root .` passed; the hygiene receipt reported `status: verified` and zero forbidden tracked artifacts.
- Root and fuzz `cargo deny --locked ... check advisories licenses sources bans` passed, and `git diff --check` was clean.

The technical-memory retrieval corpus was regenerated after `src/main.rs` became a cited S-015 artifact. The current held-out corpus digest is `8c91f83d3a3960edc882260c781735a790ffe44ac1fa378cb6490aee6389c2a8`; the evaluation digest is `3f08ca33e551c8aca501d2a6cde40297f59c8df93d7558752a5916496fc70457`; and the review record digest is `ab1c75bf031bd32b904175b6c0310941c5915297c677101ed5d9f7a7b028a4a9`. The review remains explicitly rejected with no assigned independent reviewer rather than fabricating VDD completion. S-088 remains responsible for the artifact-bound independent receipt.

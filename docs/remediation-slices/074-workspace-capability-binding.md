# S-074: Bind isolated workspaces to run capabilities

Status: Implemented and adversarially reviewed; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-061
Workstreams: W12, W15, W24
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-031](./031-descriptor-safe-persistence.md), [S-073](./073-transactional-worktree-apply.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make the selected worktree a typed session/run capability rather than a path copied into prompts or ambient CWD.

## Implementation boundary

- Create an opaque workspace handle with repository identity, roots, base/target commits, branch, owner, generation, and lifecycle.
- Rebind file, process, LSP, task, ledger, verification, relative-path, and child-run capabilities atomically on enter/exit/resume.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- All operations in an isolated run resolve through its descriptor-bound workspace and cannot mutate the main tree accidentally.
- Concurrent enter/exit/resume, stale handle, removed tree, symlink, and cross-agent ownership tests fail safely.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record

`enter_worktree` and `exit_worktree` retain their existing worktree creation,
inspection, transaction, preservation, and cleanup behavior. The application
registry now wraps those operations in a host-only workspace transition. Its
durable descriptor binds an opaque handle and lifecycle generation to exact
repository/worktree content identities, storage-root identities, canonical
roots, base and target commits, branch, session, actor, run, and owner label.
Provider-visible output contains only the opaque handle and useful status; the
transition authority is an in-memory sidecar that serialization cannot mint or
replay.

Publishing enter suspends the source run and derives one immutable run rooted
at the isolated worktree. Publishing terminal exit retires that generation and
reactivates the retained parent. A shared transition gate drains ordinary tool
operations before publication, rejects competing transitions, and refuses a
transition while background shells or agents remain active. Every later
capability check revalidates both canonical roots and their storage identities,
so removed or symlink-replaced trees fail closed. Resume deserializes only the
descriptor, reinspects Git and filesystem identity, reacquires ownership, and
issues a fresh run and workspace generation while retaining the opaque handle.

The TUI, CLI REPL, and ACP loops install the replacement run before any
fallible secondary setup. They then rebind permission state without carrying
exact approvals, task storage with a run-bound ephemeral fallback, guardrails,
LSP, session identity, prompt roots, local approval caches, and the current
user-task observation in the new reality ledger. The TUI carries the resulting
run, task graph, and permission manager into the immediate agentic follow-up;
it never resumes that follow-up on the suspended source generation. A stale MCP
manager is omitted during that immediate boundary until the application event
reconstructs it for the new run.

Isolated reality ledgers are stored in a host-local directory keyed by the
opaque workspace handle. They therefore survive resume without writing ignored
SQLite files into a removable Git worktree. File paths, process working
directories, verification evidence, grounding, relative paths, LSP definitions,
and child-run derivation all resolve from the replacement run. Registered
worktrees reject cross-owner enter and exit, and a bound run rejects nested
enter before creating another tree.

## Skeptical evidence

The changed tests use real temporary Git repositories and linked worktrees.
They prove:

- a relative file write and a real `bash pwd` use the isolated root without
  modifying the main tree, while the source run becomes unusable;
- exactly one concurrent publication succeeds and the competing generation is
  rejected;
- stale source handles, cross-owner enter, cross-owner exit, nested enter,
  removed roots, and symlink replacement fail without the forbidden mutation;
- terminal preview/removal restores the exact parent and retires the isolated
  generation without contaminating the worktree with its ledger;
- a serialized descriptor resumes only after exact repository, worktree,
  commit, branch, root, owner, and storage identity reinspection, with the same
  opaque handle and a fresh generation; and
- the real TUI tool batch returns the replacement run-scoped services and emits
  the same generation to the application, rather than dropping the capability
  before the immediate follow-up.

## Artifact generation and VDD handoff

`S074-G1` is the exact 23-file implementation and embedded-test artifact set
below, based on parent commit `95137ef2530f1d3044e7456556b69290b39c21a6`.
The SHA-256 digest of its sorted `sha256sum` manifest is
`90a92a8317871eb391529ee1378528321425fb356bded378e951f79db6609701`.

| Artifact | SHA-256 |
| --- | --- |
| `src/acp.rs` | `6ed1c327b94bdec0770e53f9a6da94d678b405de98f14858f4ab1ee06f72c01a` |
| `src/cli/chat_repl.rs` | `4bcaef0a99503b1c7ffecfd9b7eb080f812b0aff998af6b5f44beafe10182b59` |
| `src/cli/repl/slash.rs` | `ddd938b29b6dadfdb2cbf291136ebdf0e94778ef6f520360f0e71a9c48b178ec` |
| `src/compaction.rs` | `c59867085ff6a29ccebcbeea1ed6bcce64026e62609c63114d83cc3ec5040343` |
| `src/grounded_loop.rs` | `4670f8fe709affb26447539ae645d533779cda82205a16b2be558960b36c0826` |
| `src/ledger.rs` | `8517a5c0cfccf94ca3a1e06a4e68f749c7ca7ab16cb4c49dda5f1365232bf829` |
| `src/permissions.rs` | `3a4ff0027f2c50051ab3dc3b2ade065d249bb82f1291dc56614d29381255a889` |
| `src/pipeline.rs` | `ddea4ad1d82871922670969b8914c62535438c4b8d93a75bd6df7ba5003d93a2` |
| `src/runtime/context.rs` | `7d8fdf61832554ad205246ad20b3d9012ff5023954e9f67d366fdad6dadb23f5` |
| `src/runtime/ids.rs` | `f005b01b15b441b3e897ea8f0bcf514be34b054d13be9641dc666fb28cb4c5be` |
| `src/runtime/mod.rs` | `774f8190379f3d7fc77cfd344d9f1fe127b901669a66a84d97c0a60419d143c4` |
| `src/services/tool_executor.rs` | `d35dc471ff459e3756527c3d1c27f18e97ba46313b97501d666842a3c126f007` |
| `src/state/categories.rs` | `3fe085daa65116f7b8cdf18221edc120ecb961ead47b232837ec546f8e4d2881` |
| `src/state/session.rs` | `659f83de2a8578cad2b04e32a391034b44cd2bf9c7920fc13502b2c5b473fd00` |
| `src/subagent.rs` | `ea7ed90cf237ba5a8df6ef77762c94e2600eecdefb71ca7b2f8f205140efc6f9` |
| `src/tools/grounding.rs` | `dc65606a58c79371ee8080993e9d39e896988cb20c6500e6c10fe95bd5e972cf` |
| `src/tools/mod.rs` | `4fbd7e3570ed30a3db0e437a3bb9f7924db6c03d660346fa761d54be0530263d` |
| `src/tools/registry.rs` | `ea110cb26f669c94b9b9805678788d998954096a0161388207c605ae0ed250b3` |
| `src/tools/result.rs` | `9be65ee32b504cd2919547848a4757b036e2bf62e2a73a6cfabf6ae2d1a09428` |
| `src/tools/security.rs` | `4589adb78938c98d1a1e0a196d65f39c2bad1613d1fdcff8fbd73c4bea47bae3` |
| `src/tools/worktree.rs` | `22f689adb10ac8a4e8516944652c56943990a3ad7b48a086819db7e9b41fd457` |
| `src/tui/app.rs` | `ce49adf452164a0310ebc5154d9cf50c2b063220dbe95a4571f793f6d1e74a3f` |
| `src/tui/events.rs` | `4ca4482f3e4d0acc9021200feee20b44006aa657a817aa07125f657bcd3140c9` |

Queue `S074-G1` for S-088's genuinely independent alternate-model review.
No VDD approval was run or claimed for this slice. The canonical verifier must
receive these exact bytes, criteria, deterministic receipts, and source
snapshot through the same harness, guardrails, reality-grounding boundary,
provider adapters, budgets, cancellation, and traces as other agents, with
separate context and stricter read-only authority. Any artifact mutation makes
this generation stale.

## Verification record

All Rust commands used exactly Rust 1.98.0 with `CARGO_BUILD_JOBS=2`; test
commands were serialized with `--test-threads=1` where applicable.

- The final S-074 filter passed 10/10 functional tests. Existing worktree
  dispatch validation passed 36/36 and worktree/LSP passed 9/9.
- Pipeline integration, helper, and endpoint/header regressions passed 16/16,
  26/26, and 16/16 respectively.
- `cargo fmt --all -- --check` and strict locked all-target/all-feature Clippy
  with `-D warnings` passed.
- The complete locked all-target/all-feature native test matrix exited zero.
  The library ran 2,945 tests: 2,944 passed and one intentional test was
  ignored; the 227-test binary and every integration and example target also
  passed.
- Root and fuzz locked metadata and cargo-deny 0.20.2 advisory, license,
  source, and duplicate policies passed. The fuzz workspace passed locked
  check, strict Clippy, and all four library tests.
- Repository-policy tests passed 27/27 and repository hygiene returned
  `status: verified`. `git diff --check` and the changed-code debug/stub and
  assertion-weakening scans were clean.

## Residual boundaries

- The canonical artifact-bound VDD receipt remains owned by S-088. Any change
  to an `S074-G1` artifact invalidates this queued generation.
- Provider/session replacement while already isolated remains the separate
  issue #1160; it is not silently folded into this slice.
- macOS and Windows fail-closed contracts cannot execute on this Linux host.
  Exact-head PR #66 runners remain the evidence source after publication.
- S-075 typed command registration, S-076 command execution routing, and S-077
  general Git review/commit remain separate slices. Parent issue #1071 remains
  open.

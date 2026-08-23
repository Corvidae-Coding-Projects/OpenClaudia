# S-108: Make writable sandbox workspace projection transactional

Status: Complete; alternate-model artifact VDD pending S-088
Effort: Medium
Primary findings: F-049
Workstreams: W15, W18, W24
Depends on: [S-031](./031-descriptor-safe-persistence.md), [S-042](./042-least-privilege-sandbox-profiles.md)
Crosslink: #1118

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Writable sandboxed processes can perform their intended project edits without
receiving a broad host bind that permits creation of absent protected control
paths or races policy checks.

## Implementation boundary

- Project writable state through a transactional overlay, broker, or equivalent
  descriptor-safe mechanism and reconcile only authorized changes to the host.
- Reject additions or replacements of protected control paths, symlink escapes,
  mount substitutions, and generation changes before reconciliation.
- Preserve normal shell, repository-hook, Git, and MCP project workflows and
  report rollback, conflict, cancellation, and uncertain durability explicitly.
- Keep S-073 worktree apply/cleanup and unrelated sandbox policy changes outside
  this slice.

## Acceptance

- A sandbox cannot create an absent protected control path or denied leaf merely
  because an ancestor project directory is writable.
- Concurrent rename, symlink, and mount changes cannot turn a validated edit
  into an unvalidated host write.
- Successful ordinary source edits reconcile exactly; denied, failed, timed-out,
  and cancelled work leaves the host project unchanged or returns a precise
  recoverable state.
- Linux runtime tests exercise real sandbox projection and reconciliation;
  non-Linux behavior remains explicit and fail-closed where unsupported.
- Relevant deterministic tests and trace assertions pass; attach an
  artifact-bound VDD receipt once S-088 is available.

## Handoff

Record the projection generation, proposed and reconciled diff digests,
commands/tests run, typed evidence receipts, unresolved risks, and any newly
proposed slice. Completion of this slice does not imply completion of its parent
workstream.

## Implemented architecture — 2026-08-23

Linux writable process profiles now receive a private workspace generation
instead of a writable bind to the host project. Each generation lives in a
private `.openclaudia/sandbox-transactions/<uuid>` directory with immutable
baseline, writable candidate, and rollback backup trees. Snapshot reads are
rooted in pinned descriptors, use reflinks with bounded streaming fallback,
preserve internal hardlink groups, reject special nodes and external hardlink
aliases, and enforce the one-million-entry/64-GiB logical snapshot bounds.

The transaction watches candidate changes with recursive inotify and
reconciles dirty top-level entries only after the child has stopped mutating
the tree. Reconciliation rejects protected or denied paths, unsafe symlinks,
special nodes, mount/type substitutions, and host-generation conflicts before
publishing. `renameat2(RENAME_NOREPLACE)` moves each validated entry through a
backup/apply sequence; failures roll already-applied entries back, while
durability uncertainty retains an explicit recovery directory. The journal is
synced at prepared, applying, committed, rolled-back, conflict, and recovery
states. Failed, timed-out, cancelled, and nonzero commands discard their
candidate without changing the host project.

`.openclaudia`, `.claude`, denied leaves, and non-Git-profile `.git` state are
masked from candidates. Cargo `target` directories are masked at every nested
Cargo root, not only the repository root; builds already use a run-private
`CARGO_TARGET_DIR`. This keeps generated caches out of snapshots and restored
one-second hook timeout behavior from 3.46 seconds to 1.88–2.20 seconds in the
real repository fixture without exposing or deleting the host cache.

`PreparedProcessCommand` carries the workspace generation through the shared
bounded supervisor. Foreground/direct shell, background shell, command hooks,
Git/worktree helpers, language servers, ACP paths, and MCP stdio servers use
that typed route. Successful background jobs publish before becoming terminal;
capacity reservations are made while holding the manager lock, closing the
concurrent preparation race. Full-sandbox command hooks serialize workspace
publication while prompt/model hooks remain parallel.

Long-lived MCP stdio servers pause their owned process tree and checkpoint one
request at a time: a successful JSON-RPC request publishes and rebases its
candidate, while a failed or cancelled request rolls back and cannot become the
next request's baseline. Close, cancellation, transport failure, and workspace
reconciliation errors kill and reap the process tree. A reaped lifecycle flag
prevents a transport retained in an `Arc` after close from later signalling a
reused PID. Non-Linux writable projection remains explicitly unavailable and
fails closed; read-only profiles retain their existing portable behavior.

## Evidence and verification

The technical-memory tuning source citation for `src/tools/bash/mod.rs` is
bound to `worktree:s108` and exact digest
`sha256:b2c24912b50c85b7ba2ac9cedcfd48e6f230d23ce3381340cd0910219308da58`.
The regenerated artifacts are:

- tuning corpus:
  `4e8cf9baa5250f4234202aa435c7c4021e3c100cfb5602201c30fe207d9816ab`;
- held-out corpus:
  `cb35d6f11af8fb1c281b4d97fa7ce5be1344b1a37f414389bf43d884df8cfe32`;
- evaluation:
  `56a06c70fce3abc216c7964ec826aea2cc0785ec2d0dd8f4e29d79940ce0266b`;
- deliberately rejected independent review:
  `db61de2456ae699016988e8d41baa19f07220c9041c07723b9c15dc06b6a758a`.

The SHA-256 digest of the sorted `sha256sum` manifest for the 24 changed
non-slice artifacts is
`8adc4a735d9b0fa38b2ce327a8ab35f02dc5bbb2c74117694eac1548201e5e9d`.
All Rust commands used exactly Rust 1.98.0 with `CARGO_BUILD_JOBS=4`; test
commands used `--test-threads=1`.

- Focused transactional tests cover successful source edits, nonzero rollback,
  protected and denied paths, symlink and hardlink rejection, host conflicts,
  file/directory replacement, cancellation, MCP request checkpoints, Git,
  hooks, direct shell, and background shell behavior. The hook suite passed
  22/22, sandbox-escape suite 11/11, session-filesystem suite 2/2, and Bash
  integration suite 40/40.
- Technical-memory ablation validation passed, retrieval routing passed 4/4,
  and evidence validation passed 9/9 after canonical regeneration and exact
  review-digest rebinding. The review remains deliberately rejected pending
  S-088; no evaluation self-promoted its policy.
- Strict locked all-target/all-feature Clippy passed with `-D warnings` and
  formatting/diff checks passed. The final complete locked native matrix exited
  zero: the library discovered 2,902 tests (2,901 passed, one intentional crash
  worker ignored), and every binary, integration, and example target passed.
- Locked Windows GNU all-target/all-feature checking passed. Its target-only
  warnings remain owned by #1099. The locked fuzz workspace check, strict
  Clippy, and four library tests passed; root and fuzz locked metadata passed.
- Repository-policy tests passed 27/27, hygiene verification reported
  `status: verified`, and cargo-deny 0.20.2 passed advisories, licenses, sources,
  and bans for both root and fuzz workspaces.

## Residual boundaries

- S-088 owns the alternate-model artifact-bound VDD receipt; this slice does
  not claim that independent verdict has occurred.
- Transaction snapshots are intentionally whole-workspace semantic views. Very
  large non-generated source trees cost proportionally more to prepare; entry
  and logical-byte bounds reject pathological workspaces instead of silently
  weakening isolation.
- A durability failure after host publication returns the retained recovery
  directory and does not claim rollback. Routine validation, command failure,
  timeout, and cancellation paths leave the host unchanged.

This implementation completes S-108 only. Parent issue #1071 remains open for
the remaining dormant-feature slices.

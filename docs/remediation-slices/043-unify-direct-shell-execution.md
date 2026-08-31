# S-043: Route direct shell through the process capability

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
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

## Implementation record (2026-08-23)

The line-oriented CLI and full-screen TUI now translate explicit `!command`
input into one public `DirectShellAction`. The library action—not either
frontend—owns Process-capability admission, runtime-mode admission, the hard
Bash command policy, the S-042 Shell sandbox profile, concurrent-process budget
reservation, destructive freshness reservation, verifier invalidation,
structured tracing, and reality-ledger observation.

Both synchronous and asynchronous frontends use the S-040 run-owned process
supervisor. Output is drained into bounded stdout/stderr captures, the action
has a bounded deadline, run cancellation terminates the sandbox process tree,
and a started timeout/cancellation/wait failure returns a typed partial result
with retained output. Normal nonzero exits remain completed terminal results
with their exact status. The TUI remains nonblocking and preserves partial
output in its failure rendering.

The former CLI helper that called `sh`/`cmd` with ambient host process
authority has been removed. Its case-sensitive substring prompt was not kept
as an authorization boundary: typing `!command` is the explicit one-use user
request, while runtime mode, hard host policy, and OS containment remain
authoritative. The generic TUI subprocess helper now rejects
`SpawnTarget::ShellCommand`, preventing a future caller from restoring the old
route accidentally. Unrelated `/diff`, `/review`, and `/init` process cleanup
remains outside this slice.

Linux production-path tests cover quoted/mixed-case commands, intended project
writes, hidden `.openclaudia` control state, exact environment grants and absent
ambient API keys, inability to reach a live host TCP listener, deadline and
cancellation descendant cleanup, nonzero status, bounded/truncated output, and
pre-spawn budget denial. Frontend tests cover nonblocking TUI delivery, mode
denial, ledger/freshness updates, partial rendering, rejection of the legacy
TUI route, and absence of a process executor in CLI display glue.

Changing the still-cited `src/tools/bash/mod.rs` invalidated the S-105
technical-memory retrieval corpus exactly as designed. Its citation was
rebound to `worktree:s043`, the checked-in generator rebuilt the evaluation,
and the deliberately rejected independent-review artifact was rebound without
changing its rejected verdict. Retrieval evidence unit tests passed 7/7 and
tamper-validation E2E passed 9/9.

Verification used Rust 1.98.0, `CARGO_BUILD_JOBS=4`, serialized Cargo commands,
and `--test-threads=1` for test runs:

- focused direct-shell behavior passed 10/10, with focused CLI/TUI routing and
  ledger tests passing;
- strict all-target/all-feature Clippy with `-D warnings`, formatting, and diff
  checks passed;
- the locked workspace/all-target/all-feature native suite passed, including
  2,886 library tests with one ignored, 223 binary tests, and every integration
  and example target;
- locked Windows GNU all-target/all-feature compilation passed. Its existing
  target-conditional warnings remain tracked by Crosslink #1099; S-043 adds no
  Windows-only warning after gating Linux sandbox tests at the module boundary.

Independent artifact-bound alternate-model VDD remains owned by S-088. This
slice completes S-043 only and does not imply completion of parent #1071.

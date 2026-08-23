# S-022: Enforce diff blocks and quality gates

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: F-085
Workstreams: W2, W28
Depends on: [S-021](./021-run-scoped-blast-radius-guardrails.md), [S-024](./024-artifact-verification-invalidation.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make configured diff review and quality checks actual mutation/finalization gates rather than inert settings.

## Implementation boundary

- Bind a proposed diff and quality-check plan to exact artifact generations before mutation or completion.
- Run checks through canonical bounded process/review capabilities and return typed pass, fail, skipped, stale, and error states.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A configured blocking gate prevents mutation/final success on failure, absence, parse error, or stale artifact.
- Tests cover every configured cadence/action and prove no alternate frontend bypasses the gate.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered architecture

- Diff limits now compare a bounded, deterministic run-start workspace snapshot with the exact proposed or live source tree. Direct file writes and transactional subprocess projections obtain a serialized pre-publication permit, so `block` rejects oversized changes before host bytes are published and concurrent proposals cannot oversubscribe one threshold.
- Workspace edit generations are tracked independently of diff monitoring. This makes `every_edit` quality checks run after actual publication even when no diff monitor is configured, while failed or partial writes reconcile against observable host state.
- Quality checks now expose typed pass, fail, skipped, stale, and error states; validate enabled configuration at startup; bind executable and artifact freshness evidence; cache only generation-current receipts; and distinguish `warn`, `inject_findings`, and `block` outcomes.
- `every_turn` checks run after tool batches in the legacy REPL, TUI pipeline, ACP, and subagent loops. Findings enter model context as bounded typed reality messages without promoting raw command output to authority.
- `on_commit` checks run at the last reversible boundary in both slash-command commit flows, before worktree apply/merge commits, and before any permitted Bash commit attempt. Required blocking failures prevent Git dispatch.
- The shared grounded-final boundary revalidates live diff limits and current quality receipts for every agent frontend. Blocking and injected findings prevent successful finalization; advisory warnings remain non-blocking.

## Verification evidence

- `cargo +1.98.0 fmt --all -- --check`: passed.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 check --locked --workspace --all-targets --all-features`: passed.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 clippy --locked --workspace --all-targets --all-features -- -D warnings`: passed.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 test --locked --workspace --all-features -- --test-threads=1`: passed with zero failures, including 2,898 library tests, all integration binaries, and doc tests.
- Focused guardrail, canonical tool-executor, grounded-finalization, and commit-pipeline suites passed. They prove pre-publication diff blocking, serialized concurrent admission, `every_edit` operation without diff monitoring, all configured action dispositions, real commit-boundary denial, and shared final denial/advisory behavior.
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 check --locked --target x86_64-pc-windows-gnu --workspace --all-targets --all-features`: passed. Existing target-conditional warning debt remains tracked by Crosslink #1099; S-022 added no Windows-only warning.
- The 27 repository-policy unit tests and `scripts/check_repository_hygiene.py --repo-root .` passed; the hygiene receipt reported `status: verified` and zero forbidden tracked artifacts.
- `git diff --check` was clean. S-088 remains responsible for the independent artifact-bound VDD receipt.

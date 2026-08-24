# S-032: Bind file edits and diffs to snapshots

Status: Complete
Effort: Medium
Primary findings: F-036, F-039
Workstreams: W15
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure an edit applies only to the bytes reviewed and cannot create unbounded or secret-bearing output.

## Implementation boundary

- Return immutable read snapshots with identity/digest and require edit/write requests to name the expected snapshot generation.
- Preflight replacement growth, match count, file/result size, diff compute/output, encoding, and sensitivity before atomic commit.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A concurrent one-byte change produces a typed conflict rather than overwriting newer content.
- Expansion bombs and sensitive oversized diffs are rejected or returned as bounded redacted artifacts before allocation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

- `read_file` now hashes the exact stable bytes used for rendering and ledger evidence, records the resulting `sha256:<64 hex>` generation per run and canonical path, and returns that generation plus the byte length to the caller.
- `edit_file` and existing-file `write_file` require that returned generation, revalidate the reviewed bytes, preflight encoding, match count, growth, file size, changed-line reservations, sensitivity, and a bounded sanitized diff, then publish through a synchronized staged file. Successful mutations publish the next generation; realistic stale reads return `Conflict` with `Safe` retryability and preserve the newer bytes.
- Linux and macOS replacements use atomic exchange/swap so the displaced generation can be verified before the old inode is removed. New-file publication is no-replace. Existing non-Unix file mutation remains fail-closed pending its separately tracked handle-relative backend work.
- ACP and automatic-learning paths now forward generations returned by their actual `read_file` call; test-only read wrappers continue to exercise the individual renderers without adding a second production read.
- Deterministic evidence includes one-byte edit/write races, create races, per-run snapshot isolation, mode preservation, chained mutations, expansion rejection, secret redaction, and exact read/ledger digest agreement. Focused edit/write/read/race/integration/ACP suites passed.
- Final local gates passed with Rust 1.98: `cargo +1.98.0 fmt --all -- --check`; `CARGO_BUILD_JOBS=4 cargo +1.98.0 check --locked --all-targets --all-features`; `CARGO_BUILD_JOBS=4 cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`; and `CARGO_BUILD_JOBS=4 cargo +1.98.0 test --locked --all-targets --all-features -- --test-threads=1`.
- S-088's artifact-bound VDD receipt is not yet available, so no receipt is claimed. Completion of this slice does not imply completion of its parent workstream.

# S-026: Stop mutating the shared Claude credential store

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
Effort: Small
Primary findings: F-080
Workstreams: W3, W15
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent OpenClaudia from corrupting or racing another application's credential document.

## Implementation boundary

- Remove write/refresh ownership of the foreign Claude credential file and use an official owning-client interface or a bounded read-only compatibility adapter.
- Store OpenClaudia metadata separately and make credential acquisition cancellable, deadlined, link-safe, mode-checked, and schema-preserving.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Login/refresh/logout tests never rewrite, truncate, normalize, or drop unknown fields from the shared Claude file.
- Concurrent foreign updates and symlink/path changes yield typed unavailable/stale states without holding an unbounded lock.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record (2026-08-24)

Claude Code compatibility is now a bounded read-only adapter. On Unix it uses
the descriptor-pinned S-031 persistence boundary to require a private regular
file owned by the current user, cap the document at one MiB, zeroize the read
buffer, and compare storage generations across two reads. OpenClaudia performs
no credential refresh request, lock-file protocol, temporary-file replacement,
or write to Claude Code's credential document. Unknown fields and exact source
bytes therefore remain owned by Claude Code.

Credential failures are typed without exposing secrets. Missing credentials,
malformed documents, missing OAuth data, missing `user:inference` scope,
expired or near-expiry tokens, unsafe paths, oversized files, and concurrent
foreign replacement all fail with an actionable `claude auth login` recovery.
The compatibility loader is synchronous because it performs no network work.
ACP, print mode, TUI startup and provider switching, and `/connect` use that
same boundary. Native OpenClaudia OAuth setup persists only to OpenClaudia's
own session store and explicitly states that Claude Code's store is unchanged.

Deterministic coverage uses realistic foreign documents and checks the exact
bytes after success and failure. It covers unknown-field preservation, stale
tokens, missing scope, unsafe Unix permissions, symlinks, and a controlled file
replacement between the two reads. CLI integration coverage verifies valid ACP
login, malformed and expired status reporting, and logout without mutation.

Verification used Rust/Cargo 1.98.0, `CARGO_BUILD_JOBS=4`, one Cargo process at
a time, and serialized test execution:

- focused credential unit tests passed (25 tests), along with credential
  constants/auth integration suites and 15 focused CLI auth tests;
- the locked workspace/all-target/all-feature native test suite passed,
  including all 2,916 library cases (2,915 passed and one ignored) and every
  binary, integration, and example target;
- strict all-target/all-feature Clippy, formatting, diff checks, and locked
  Windows GNU all-target/all-feature compilation passed; existing
  target-conditional test warnings remain tracked by Crosslink #1099;
- a freshly built OpenClaudia binary authenticated through the user's existing
  Claude Code login and returned `S026_LOGIN_OK`. Before and after the live
  conversation, Claude's file retained the same SHA-256 digest, regular-file
  type, `0600` mode, owner/group, byte size, and inode.

Changing the S-105-cited `src/main.rs` correctly invalidated its retrieval
corpus. The held-out citation was rebound to the S-026 source digest, the
checked-in generator rebuilt the evaluation, and the independent-review
artifact remains explicitly rejected pending a new independent reviewer.

## Residual boundaries

- Claude Code remains responsible for refreshing and rewriting its own login.
  When its token is stale, OpenClaudia asks the user to run `claude auth login`
  instead of impersonating that owner.
- The portable fallback is also read-only, but S-036 owns equivalent
  descriptor/ACL hardening on non-Unix platforms.
- S-027 and S-028 own provider client-identity and compatibility-policy work;
  S-088 owns the independent VDD receipt. Parent workstream #1071 remains open.

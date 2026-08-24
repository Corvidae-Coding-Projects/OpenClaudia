# S-030: Make interactive API-key setup secret safe

Status: Implemented and deterministically verified; artifact-bound VDD pending S-088
Effort: Small
Primary findings: F-111
Workstreams: W3, W14, W15
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-031](./031-descriptor-safe-persistence.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Collect and store API keys without terminal echo or accidental repository persistence.

## Implementation boundary

- Use hidden input and an explicit destination chooser backed by the trusted secret/config store.
- Reject project-local plaintext destinations by default and show scope, provider, overwrite, and persistence consequences before commit.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Terminal transcripts, errors, debug output, shell history, and repository files do not contain the entered test key.
- Interrupted, invalid, and overwrite flows leave previous credentials unchanged.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implementation record (2026-08-24)

Interactive startup now presents the selected provider, scope, and destination
before reading a secret. Session-only use is the default and performs no write;
the alternative is an explicit user-scoped OpenClaudia credential store. Key
entry uses a controlling-terminal password prompt with echo disabled. Existing
saved keys are detected and replacement consent is obtained before the new key
is requested, so cancellation and denied-overwrite paths cannot mutate the
credential.

Saved keys use a versioned `provider_api_keys.json` document beneath the host's
local application-data directory. The S-031 persistence boundary provides
bounded reads, owner-private `0600` files on Unix, descriptor-safe path
resolution, generation-checked atomic commits, and durability recovery. Newly
created OpenClaudia credential directories use mode `0700`. There is no CWD or
project-file fallback. Existing malformed or insecure stores fail visibly,
while an absent store behaves as an empty, lowest-priority configuration
source. Project, home, and typed environment credentials continue to win.

The live `/connect` command no longer echoes keys or rewrites YAML. It derives
remote API-key targets from the current typed provider registry, displays the
provider, user scope, protected destination, and project-file effect, obtains
save and overwrite confirmation, then uses the same hidden-input and protected
storage path. It tells the user to start a new chat after a successful save.

Verification used Rust/Cargo 1.98.0, `CARGO_BUILD_JOBS=4`, one Cargo process at
a time, and serialized test execution:

- protected-store transaction, restrictive-mode, redaction, registry-target,
  config-discovery, and source-precedence tests passed;
- startup destination parsing and the live `/connect` regression check passed;
- the locked workspace/all-target/all-feature native suite, strict
  all-target/all-feature Clippy, formatting, diff checks, and Windows GNU
  all-target/all-feature compilation passed;
- PTY runs of the built binary proved that startup session-only entry did not
  echo or persist a canary, protected save created a `0600` store, a subsequent
  launch discovered it, denied overwrite preserved the file byte-for-byte and
  did not prompt for a key, and live `/connect` saved without echo while the
  project config remained byte-identical;
- the S-105 held-out citation to changed `src/main.rs` was rebound to its
  current digest, the checked-in generator rebuilt the evaluation, and the
  independent-review artifact remains explicitly rejected pending a new
  independent reviewer.

## Residual boundaries

- Protected local persistence is not offered on platforms where the current
  descriptor-safe backend cannot uphold its contract. Session/config/environment
  authentication remains available there; cross-platform secure-file work is
  owned by S-036.
- Artifact-bound VDD remains owned by S-088. Completion applies to interactive
  API-key collection and persistence only; parent workstream #1071 remains
  open.

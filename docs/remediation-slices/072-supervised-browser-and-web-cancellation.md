# S-072: Supervise browser and web work

Status: Complete
Effort: Medium
Primary findings: F-059, F-103
Workstreams: W10, W18, W23
Depends on: [S-040](./040-supervised-foreground-process-io.md), [S-042](./042-least-privilege-sandbox-profiles.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-071](./071-web-egress-connection-broker.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure web timeout/cancellation stops real work and browser descendants cannot inherit persistent project authority.

## Implementation boundary

- Launch verified browser artifacts in ephemeral restrictive profiles behind a bounded pool with session/tab/process/request/DOM/download/CPU/memory/disk/time limits.
- Tie fetch/search/browser/distillation futures and descendants to the run cancellation tree; make persistent cookies/login an explicit encrypted capability.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Timeout or cancellation closes pages, stops network/model work, reaps descendants, and waits for terminal reconciliation.
- Hostile pages, decompression/DOM bombs, profile links, downloads, bot challenges, and backend markup changes return bounded typed outcomes.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Bound fetch, search, browser, and model-backed distillation to one child of
  the exact run cancellation tree. Operation deadlines are clamped to the
  remaining run budget; cancellation propagates through DNS, dial, request,
  proxy, browser, and distillation work; and the synchronous tool seam waits
  for owned work to reconcile before returning a terminal outcome.
- Added an owned Chromium supervisor with a two-session admission pool and
  hard per-operation ceilings for tabs, requests, DOM bytes/nodes, downloads,
  descendant processes, aggregate RSS/CPU, profile disk, and elapsed time.
  It launches an exact run-resolved browser with a cleared restrictive
  environment, an owner-private ephemeral profile, and only the S-071 broker
  proxy. Cancellation or failure terminates the process tree, joins the owner
  worker, drains bounded sanitized diagnostics, and removes the profile.
- Bound browser receipts to the exact running Chromium artifact on Linux
  rather than the distribution's launcher script. Every terminal receipt
  records the SHA-256 identity, configured limits, maximum observations,
  persistent/ephemeral state, terminal reason, and descendant-reap result.
- Kept downloads denied and intercepted page requests behind the connection
  broker. DOM and tab observations are collected from the actual browser, and
  profile measurement refuses symbolic links instead of following page-owned
  filesystem indirection.
- Added explicit encrypted login continuity without making normal browsing
  persistent. Only trusted host configuration can grant a named profile and
  at most 32 exact HTTP(S) origins; project values are stripped, the grant is
  part of the immutable run authority digest, and use requires Secrets
  authority. At most 256 matching cookies and 512 KiB are stored under the
  host local-data directory with AES-256-GCM, random nonces, origin/profile/time
  associated data, retention checks, owner-private descriptor-safe storage,
  and generation-checked commits. Each browser operation still receives a new
  ephemeral Chromium profile.
- Added skeptical tests for trusted/project configuration separation, grant
  inheritance, encryption and tamper/retention failures, link-safe profile
  measurement, resource decisions, deadline reconciliation, typed failure
  receipts, real brokered Chromium escape attempts, stalled cancellation and
  reap, and cookie restoration across two fresh profiles.

## Evidence

All Cargo commands used Rust/Cargo 1.98.0 with `CARGO_BUILD_JOBS=2` and one
heavy Cargo process at a time. Complete native test execution was serialized
to respect system memory and the repository's process-global test-state limit.

| Gate | Result |
|---|---|
| Browser-supervisor unit tests | Passed 8/8 |
| Focused cancellation and typed policy-denial tests | Passed, including reconciliation before timeout return and preservation of both network and browser receipts |
| Configuration and persistence fixtures | Passed 27/27 web-fetch configuration tests plus trusted-host/project-stripping coverage |
| Real installed-Chromium production paths | Passed 3/3: brokered success with blocked private descendants/download, stalled cancellation with descendant reap, and encrypted-cookie restoration across fresh ephemeral profiles |
| Complete native library, binary, example, and integration coverage | Passed under `cargo test --locked --all-targets --all-features -- --test-threads=1`: 8,122 passed, zero failed, and seven intentionally ignored across 260 result blocks; the library target passed 2,926 with one ignored |
| Native strict Clippy | Passed with zero diagnostics under all targets and features before the final documentation-only update |
| Feature-surface compilation | Passed both all-feature and no-default-feature all-target checks |
| Windows GNU all-target/all-feature check | Passed; only the pre-existing target-specific warning set tracked by #1099 was emitted |
| Fuzz workspace | Check and strict Clippy passed; all 4 hermetic harness tests passed |
| Repository policy, metadata, and dependency policy | Passed 27/27 policy tests, both locked metadata graphs, and both `cargo deny` policies |
| `cargo fmt --all -- --check` and `git diff --check` | Passed; repeated in the final pre-commit gate |

The first complete native sweep exposed one stale exact-shape assertion that
expected a policy denial to carry only network receipts. Production now
correctly reconciles and returns the browser supervisor receipt as well. The
test retained its exact typed-denial and source assertions while accepting
both evidence arrays; the clean complete rerun then passed.

Artifact generation `S072-G1` is based on
`36fb8d253a63e87710b5aa67b22ee52d64c6a740`. The SHA-256 digest of the sorted
per-file SHA-256 manifest for the 11 changed product and test artifacts,
excluding this self-referential completion record and the later
machine-generated changelog entry, is
`14fb73d90831d3e321c9e2510f588c26e5a38f7cf903f43cca0546d137dea67e`.

## VDD handoff

Queue artifact generation `S072-G1`, its base revision, manifest digest, and
the evidence above for S-088. The independent verifier must receive the same
harness, guardrails, exact run capabilities, budgets, reality grounding,
S-071 connection broker, browser supervisor, cancellation tree, encrypted
persistence grants, and typed receipts used by the implementation. S-088
should use another model where available. It must not treat an implementation
model's own report as independent approval. S-088 is not yet available, so
this document records a verifier-ready handoff and does not claim independent
verification.

## Residual boundaries

- Linux enforces and reports descendant process count, aggregate RSS, and CPU
  time from the owned process tree. Windows and macOS retain elapsed/profile/
  request/DOM/tab/download bounds and process-tree termination, but equivalent
  OS-native process/RSS/CPU accounting is not yet implemented or proven. That
  bounded follow-up is tracked by #1155 rather than hidden in this completion
  claim.
- Browser protocol changes, challenge pages, and backend markup changes may
  still return bounded typed failures. This slice guarantees supervision and
  reconciliation, not universal site compatibility.
- Persistent login state is deliberately cookies-only and exact-origin. It
  does not persist cache, local storage, extensions, arbitrary profiles, or
  ambient browser credentials.
- Completion applies only to S-072. Parent issue #1071 remains open.

# S-017: Fix deny precedence and approval scope

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-012, F-030, F-068
Workstreams: W2, W12
Depends on: [S-016](./016-mandatory-tool-effect-classification.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Ensure hard policy and explicit denials dominate, while approvals are narrow, expiring, generation-bound receipts.

The permission path now resolves one canonical effect scope, applies every
non-bypassable denial before any approval/default, and mints an opaque one-use
execution permit for the exact call. Conversation/session documents carry no
permission authority. Reusable approvals live only in bounded runtime state or
the trusted per-user store.

## Implementation boundary

- Define deterministic precedence with host hard deny first and migrate broad first-match/tool-wide caches to normalized resource/effect receipts.
- Bind persisted approvals to actor, workspace, tool, exact target/arguments, capability generation, expiry, use count, and provenance in trusted state.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A later or more-specific denial cannot be overridden by an old broad allow, including after session resume.
- One approved Bash/path/network operation cannot authorize a different invocation, target, workspace, or generation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Delivered design

- Precedence is deterministic: mandatory effect classification, host hard
  safety, explicit deny rules, exact deny receipts, exact reusable approval
  receipts, effect defaults, compatibility policy, scoped config defaults,
  then `NeedsPrompt`. A broad or older allow cannot outrank a matching denial.
- Approval receipt schema generation 1 binds the actor digest, canonical
  workspace digest and generation, capability generation, optional session,
  canonical tool, effect, typed operation, normalized target digest, canonical
  argument digest, timestamps, remaining uses, and trusted provenance. Raw
  commands, paths, URLs, targets, and arguments are not persisted.
- Interactive one-time approval mints a five-minute, exact-call
  `ExecutionPermit`. The permit is opaque to frontends, atomically one-use,
  checked again against the current call and generation immediately before
  unchecked dispatch, and cannot be replayed with another call id or scope.
- Session approvals last at most eight hours and 128 total uses including the
  approving call. Persisted approvals last at most 30 days and 64 total uses.
  Runtime and disk collections are capped at 1,024 records; the trusted store
  is capped at 1 MiB and rejects unknown schema fields and invalid records.
- Persisted authority uses the per-user
  `openclaudia/permissions-v1.json` store, not project or conversation state.
  The store rejects symlinked or non-regular targets, verifies Unix ownership
  and mode, uses an exclusive sibling lock, reloads before each generation/use
  mutation, writes through a unique synced temporary file, and atomically
  replaces the destination. Unix additionally syncs the parent directory;
  platforms whose portable file API cannot open directories stop at synced
  file plus atomic replacement.
- Any exact denial or permission-policy mutation rotates the capability
  generation. Managers synchronize the on-disk generation under the store
  lock, so an old approval or permit cannot survive a later denial or a second
  live manager's rotation.
- TUI, line REPL, pipeline, proxy, ACP, coordinator, subagent, and shared
  `ToolExecutor` paths carry typed permits instead of Boolean
  `permission_already_checked` authority. The local and coordinator caches are
  exact normalized receipt caches; legacy broad allow rules are not migrated
  into persisted approvals.
- Default allow entries are tool-scoped. Legacy unqualified patterns apply
  only to Bash instead of silently authorizing unrelated path or network
  capabilities.
- Enterprise tool caps now dry-run before prompts, record atomically only
  after exact authorization, and cannot count denied calls or race concurrent
  callers past a cap.
- Permission decisions and permit consumption emit redacted structured trace
  evidence (`tool_effect_classified`, `permission_decision`,
  `approval_permit_consumed`, and `local_approval_cache_decision`) keyed by
  digests/receipt ids rather than sensitive scope text.

## Adversarial review corrections

The implementation was not accepted on focused tests alone. Full-suite,
cross-target, and changed-test review found and corrected:

- A Windows receipt write could report failure after a successful replacement
  because directory handles are not portable. File replacement now uses the
  repository's Windows-aware atomic helper and directory sync is Unix-only.
- Permission-denied calls consumed enterprise tool quota, and separate
  check/increment locks let concurrent calls exceed the cap. Authorization now
  precedes one atomic capped increment.
- Persisted receipt validation enforced nonzero uses and forward expiry but
  did not reject records widened beyond the documented 64-use/30-day bounds
  or records whose issuance time was still in the future. Load-time validation
  now rejects all three cases, and generation exhaustion fails closed instead
  of allowing the underlying atomic counter to wrap.
- Permit validation once released the trusted-store lock between generation
  synchronization and one-use consumption. Generation refresh, exact-denial
  recheck, expected-scope reconstruction, and permit consumption now share one
  in-process and cross-process critical section, giving concurrent revocation
  a deterministic ordering against dispatch.
- Linux-only OAuth and secure-filesystem helpers produced hidden Windows
  unreachable/dead-code warnings. Their compilation boundaries now match the
  platforms that use them.
- A session round-trip test still expected serialized permission bypass/trust
  authority. It now proves all non-authority state survives while permission
  fields decode to safe invocation-local defaults.
- The ACP descendant-cancellation test exposed a real load-sensitive escape.
  Tree-managed Unix subprocesses now lead their own process group and ACP has
  an exact-session cancellation watcher independent of async-runtime polling;
  the daemonized descendant can no longer mutate the project after cancel.
- Two web-search tests expected handler validation for unclassifiable inputs.
  They now independently prove empty/null/non-string targets fail closed before
  dispatch while a classifiable one-character query still reaches the tool's
  minimum-length validator.
- Tests asserting old denial text or constructing shell-shaped cancellation
  commands were updated only after the production contract was traced: denial
  assertions now name exact approval scope, and cancellation uses an
  executable project fixture that passes hard safety without weakening the
  descendant check.

These corrections are tracked and resolved by Crosslink issues #1009 through
#1016 (with #1014 recording and closing a reviewed ACP false alarm). The
separate provider PostToolUse timeout remains #1008.

## Verification evidence

All Cargo work was serialized with `CARGO_BUILD_JOBS=1`; test runs used
`--test-threads=1` and no heavy commands overlapped.

- `cargo test --quiet --all-features -- --test-threads=1`: passed the complete
  library, binary, integration, and doc-test matrix. The principal targets
  report 2,615 library tests, 218 binary tests, and 131/133 deterministic
  integration tests with two network-dependent tests ignored; all remaining
  integration binaries and doc tests passed.
- The all-feature ACP daemonized-descendant cancellation test passed ten
  consecutive exact repetitions and passed inside the complete suite.
- `permission_manager_tui_remember_e2e`: 23 passed; filtered permission units:
  101 passed; the focused hooks, unrestricted-manager, permission-outcome,
  coordinator, policy, and executor suites passed.
- `cargo check --all-features --all-targets`: passed.
- `cargo clippy --all-features --all-targets -- -D warnings`: passed.
- `cargo check --target x86_64-pc-windows-gnu --all-features --lib`: passed
  without target-specific warnings.
- `cargo fmt --all -- --check` and `git diff --check`: passed at the final
  review gate.

Typed pre-VDD evidence consists of exact-scope decision traces, receipt ids,
scope digests, generation transitions, and permit-consumption events exercised
by the tests above. The artifact-bound alternate-model verifier receipt remains
queued for S-088; this document does not represent local self-review as VDD.

## Unresolved and downstream work

- S-018 still owns eliminating the remaining optional-manager/unchecked public
  dispatch compatibility paths and enforcing the hard host ceiling at every
  frontend boundary. S-017 makes approvals exact; it does not claim that
  downstream slice complete.
- S-088 must run the canonical alternate-model verifier against the committed
  artifact using the same harness, guardrails, reality grounding, and bounded
  tool access as the builder.
- Crosslink issue #1008 remains open: the provider PostToolUse integration has
  a five-second outer timeout but invokes a longer serial Clippy check. That
  workflow defect is separate from product hook execution and was not hidden
  or folded into this permission slice.
- Non-Unix hosts receive synced-file plus atomic-replacement durability for the
  receipt store, but Rust's portable API cannot provide the Unix parent
  directory fsync guarantee.

## Handoff

Approval receipt schema generation 1 and the current capability generation are
the artifact generations for this slice; capability generation is deliberately
runtime/store-specific and rotates on authority changes. Record the final
staged-diff digest and commit in Crosslink issue #1007. Completion of this
slice does not imply completion of its parent workstream.

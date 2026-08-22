# S-018: Make host safety non-bypassable

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-016, F-031
Workstreams: W2, W14
Depends on: [S-016](./016-mandatory-tool-effect-classification.md), [S-017](./017-deny-precedence-and-approval-receipts.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Keep hard host safety active even when user permissions are disabled or repository configuration requests unrestricted behavior.

## Implementation boundary

- Separate non-bypassable host policy from user convenience approvals and project proposals; remove optional-manager dispatch semantics.
- Validate configuration provenance and prevent repository files, resume state, alternate dispatch APIs, or `enabled=false` from weakening the ceiling.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Catastrophic and protected-resource tests are denied through every public dispatch path under unrestricted/user-disabled settings.
- Project configuration can request but never silently grant broader host authority.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Delivered design

- `HostSafetyPolicy` is a generation-bearing, non-configurable policy evaluated before user permission settings, project proposals, approvals, and handler dispatch. It rejects catastrophic shell commands, model requests to disable the sandbox, and writes to protected control resources.
- The executable registry boundary is crate-private and requires an opaque `ToolDispatchPermit` bound to the policy generation, exact wire tool name, and deterministic argument digest. A permit cannot be reused for another tool or argument envelope.
- All public dispatcher paths use the same authorization and final-dispatch checks. ACP, CLI, subagent, TUI, pipeline, and service execution no longer obtain a managerless bypass; a lifecycle without a permission manager fails closed for non-empty tool calls.
- Repository permission configuration is provenance-separated into an inert, versioned `ProjectPermissionProposal`. Grant-like project fields, including nested and dotted `enabled=false`, permissive defaults, and web preapprovals, cannot weaken host policy or silently broaden authority. Restrictive project settings remain effective unless a higher-trust operator source deliberately overrides them; trusted home and environment configuration retain their documented user-owned behavior.
- Host-safety traces include the policy generation, decision, reason, tool, and target digest without emitting the raw protected target.

## Artifact generations and typed evidence

| Artifact | Generation/schema | Evidence |
| --- | ---: | --- |
| Host safety policy | `HOST_SAFETY_POLICY_GENERATION = 1` | Every executable entry point and the final registry boundary evaluate or consume evidence from this generation. |
| Project permission proposal | `PROJECT_PERMISSION_PROPOSAL_SCHEMA_VERSION = 1` | Extracted before trusted/project configuration merge and exposed as non-authoritative provenance. |
| Tool dispatch permit | Host-safety generation + exact tool/argument digest | Opaque permit construction is internal to authorization; mismatched use is denied before handler dispatch. |

Pre-VDD evidence receipts are typed test outcomes and structured trace assertions rather than prose-only claims. `tests/non_bypassable_host_safety_e2e.rs` exercises all seven public execution APIs under user-disabled, unrestricted settings and asserts denials for catastrophic commands, protected writes, and sandbox-disable requests. Unit and integration tests assert permit mismatch rejection, provenance extraction, trusted-source behavior, invalid-envelope typing, and trace redaction. S-088 remains responsible for issuing the canonical artifact-bound cross-model VDD receipt.

## Adversarial review corrections

- Registry tests were migrated to the canonical public executor because direct registry dispatch is no longer an externally executable API. The replacement support helper preserves handler-envelope and option coverage while traversing real authorization.
- A full-suite failure showed that malformed non-object arguments could be classified as permission failures. Production authorization now validates the JSON envelope first, and tests require the typed `InvalidArguments`/`Never` outcome rather than accepting either error.
- Compound shell and sandbox tests had relied on the retired managerless bypass. They now exercise an exact, one-use interactive approval, preserving their original behavioral claims without weakening host safety.
- Web-search classifier tests had stale exact provenance expectations. They now require the host-safety provenance and the typed `PermissionDenied`/`Never` outcome.
- QA found that Win32's trailing-dot/space normalization could spell protected controls as `.git.` or `settings.json `. The policy now folds those aliases on every host, and tests pin both forms. Descriptor and reparse-point containment remains assigned to S-036.
- Repeated ACP session-mode execution exposed a pre-existing cancellation escape: a sandbox child could react to termination by daemonizing a replacement while inherited pipes kept the invocation alive. Cancellation now freezes the process tree, discovers descendants to stability, and force-kills the frozen set. An adversarial TERM-trap test attempts the escape, and the ACP session-mode module passed twenty consecutive serial repetitions after the fix. Normal user-requested background termination retains its existing graceful path.
- Signal-boundary review found that the public process-tree helpers accepted PID `0`, which Unix interprets as the caller's entire process group. Both helpers now reject that sentinel before platform dispatch, and a regression test pins the fail-closed behavior under Crosslink issue #1022.

## Verification evidence

All Cargo work used `CARGO_BUILD_JOBS=1`; test execution used `--test-threads=1` to respect host RAM limits.

- `cargo test --quiet --all-features -- --test-threads=1` passed as one uninterrupted full run after final QA corrections: 2,632 library tests, 220 binary tests, 131 core integration tests with 2 ignored, and every remaining integration target (including 29 web tests with 2 ignored) passed.
- `cargo check --all-features --all-targets` passed.
- `cargo clippy --all-features --all-targets -- -D warnings` passed without suppressions.
- `cargo check --target x86_64-pc-windows-gnu --all-features --lib` passed.
- Focused host-safety, permission, configuration, dispatch-envelope, sandbox, web, and ACP suites passed. The ACP session-mode module additionally passed twenty consecutive serial repetitions after the cancellation fix.
- `cargo fmt --all -- --check` and `git diff --check` are final pre-commit gates; their result and the staged artifact digest are recorded on Crosslink issue #1019.

## Unresolved risks and ownership

- The canonical artifact-bound VDD receipt is pending S-088; this status is not equivalent to formal VDD verification.
- Capability-rooted path resolution, symlink/reparse-point containment, cross-platform secure file handles, and cross-session workspace isolation are intentionally owned by S-019, S-036, and S-074. S-018 folds obvious Win32 trailing-dot/space aliases into its protected-control ceiling, but host safety is not a substitute for descriptor-bound filesystem capabilities.
- Crosslink issue #1020 tracks the separate Bash-timeout behavior where descendant-held pipes can delay completion; it was not hidden or folded into this slice.
- Crosslink issue #1021 tracks the ACP cancellation escape found during adversarial verification and is closed only after its production fix and evidence are committed.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

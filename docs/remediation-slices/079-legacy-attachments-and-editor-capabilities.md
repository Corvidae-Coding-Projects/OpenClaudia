# S-079: Route legacy attachments and editor input through capabilities

Status: Implemented and deterministically verified; artifact-bound VDD receipt pending
Effort: Medium
Primary findings: F-113
Workstreams: W12, W15, W18
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-031](./031-descriptor-safe-persistence.md), [S-040](./040-supervised-foreground-process-io.md), [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent `@file` and external editor input from bypassing workspace containment, context budgets, process supervision, and source authority.

## Implementation boundary

- Represent attachments as snapshot-bound typed events with encoding, sensitivity, truncation, per-file and aggregate byte/token limits.
- Run editors through the supervised user-origin process profile and import saved bytes as a reviewed user/evidence event, not system text.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Outside-root, symlink-raced, oversized, binary, changing, and cancelled attachments cannot enter context ambiguously.
- Editor timeout/failure leaves conversation and files consistent and no input gains higher authority through interpolation.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Legacy REPL input preparation now separates user instruction text from
  capability-read attachment projections. Each attachment is a stable UTF-8
  snapshot with source, digest, encoding, sensitivity, and byte metadata;
  per-file and aggregate limits apply before conversation mutation.
- Outside-root, masked, binary, oversized, changing, and cancelled attachment
  reads fail before the prompt is admitted. `@` text that is not an admitted
  path remains ordinary user instruction rather than gaining file authority.
- External editors run as supervised user-origin processes with inherited
  terminal I/O, a deadline, run cancellation, bounded concurrency, no network
  or secrets, and only the run's private scratch filesystem. Saved input is
  routed back through the ordinary user-input preparation path with explicit
  reviewed provenance.
- Plan editing uses a scratch copy because `.openclaudia` is not exposed to
  the editor sandbox. A successful zero exit atomically replaces only the
  previously observed plan generation; a failed editor or concurrent plan
  change leaves the published plan untouched.

## Verification

- Rust 1.98 format and strict all-target/all-feature Clippy gates pass.
- Operational Linux sandbox tests prove successful staged plan publication
  and prove that a nonzero editor leaves the original plan unchanged. The
  existing authority test confirms ordinary workspace files are rejected.
- The complete locked all-target/all-feature suite passes with 3,126 library
  tests passed and one intentional ignore, 208 binary tests passed, and every
  integration target green under one test thread.

## Residual boundary

Interactive editor usability still depends on a maintained host sandbox
backend and the user-selected editor executable. Lack of that backend fails
closed. An artifact-bound alternate-model VDD receipt remains required for
final `Verified` status.

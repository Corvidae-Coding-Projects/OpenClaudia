# S-023: Rebuild Reality grounding as an evidence boundary

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-003, F-023, F-046
Workstreams: W4, W18
Depends on: [S-008](./008-typed-context-authority-and-budget.md), [S-011](./011-canonical-typed-tool-results.md), [S-016](./016-mandatory-tool-effect-classification.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Represent claims and observations as provenance-bound evidence that text cannot forge and final prose cannot bypass.

## Implementation boundary

- Replace public string append/authority APIs with typed evidence receipts tied to run, tool call, artifact, source, and verification method.
- Make finalization query required claim/evidence policy and treat shell/model/tool text labeled “Verifier” as untrusted content.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Plain final text cannot satisfy a required evidence gate and arbitrary command output cannot create authoritative verification.
- Every promoted claim is traceable to a current typed receipt or is explicitly unresolved/unsupported.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Ledger observations now carry typed provenance, an exact run/generation
  binding, a source, and a typed artifact identity. Tool observations also bind
  the call ID, canonical handler identity, and argument digest. Public callers
  cannot construct authoritative observations or mutate verification results.
- Authority is issued only by process-owned observer paths. Reloaded database
  rows retain authority only when their complete digest matches a receipt
  issued by this process; otherwise they are explicitly
  `UnverifiedPersisted`. Legacy authority fields deserialize only as
  `LegacyUnbound` and cannot authorize a claim.
- File evidence compares one exact project-root-relative resource identity.
  Production observers may record canonical absolute paths while claims use
  relative paths, without accepting basename or suffix matches. Reads and
  diffs become stale when the same resource is changed.
- Final decisions use a closed `FinalClaim` vocabulary for file changes,
  command results, verification, unsupported claims, and unresolved claims.
  The final gate requires exact, current, non-stale receipts and requires a
  trusted verification receipt before runtime file or command claims can be
  promoted.
- Quality-gate receipts are created only from the private direct-execution
  proof returned by guardrails. The proof binds the run/generation, normalized
  argument vector, resolved executable, streamed-output digest, exit status,
  and pass/fail result. Ordinary Bash output, including verifier-looking text,
  remains an ordinary command observation.
- Final envelopes, claims, receipt lists, command vectors, and rendered fields
  are bounded. Deterministic rendering quotes control-sensitive content while
  preserving ordinary prose. Unsupported and unresolved results remain
  visibly labeled instead of being converted into asserted outcomes.
- The grounding tool is now a bounded navigation surface. It exposes typed
  provenance and integrity metadata, labels summaries as navigation-only, and
  cannot mint or publish a generic authoritative Boolean.
- ACP, CLI providers, the TUI, the pipeline, and subagents all buffer possible
  terminal model text until its typed envelope passes the same final gate.
  Invalid finals are not printed or persisted as completed answers; TUI and
  quality-gate denials are surfaced as typed errors instead of being discarded
  or mixed into the following model response.
- Compaction and model-produced summaries are typed as derived summaries,
  current task specifications are typed as user input, and the file, diff,
  generic tool, background Bash, and registry paths propagate the exact run
  binding through the canonical dispatch boundary.

## Architecture decision

The selected boundary separates observations from authority:

`runtime event` → typed observer → process-issued receipt → exact claim
policy → deterministic final renderer.

Text is payload at every stage, never proof. An observation becomes usable for
a final claim only when its typed provenance, artifact binding, receipt digest,
run/generation, and freshness satisfy that claim's exact policy. Persistence is
useful for audit navigation but does not survive as self-authenticating
authority across a process boundary.

Verification is intentionally narrower than command execution. Only the
guardrails quality-gate runner can return the private proof consumed by the
ledger's verification observer. This prevents command names, stdout labels,
model prose, database mutation, or public struct construction from promoting
an ordinary event into verifier authority.

The same terminal gate is shared across frontends. Potential final text is held
until the model either starts a tool call or completes the turn; only a valid
typed final is rendered and persisted. This closes display-before-validation
without changing nonterminal tool-call streaming.

## Artifact generation

- Generation: `S023-G1`.
- Baseline commit: `79d237175889984d47b3d91f33de1a52fc8f50eb`.
- Source/test artifact digest: SHA-256
  `2f336b2a1cb734a88e31abe48006f3464bd2fda23652cc4e931e8aef250405e1`
  over `git diff --cached --binary HEAD -- src tests` after formatting, strict
  Clippy, the complete test suite, and explicit staging. Any source/test
  artifact change invalidates it.
- Scope: typed ledger provenance and persistence trust; exact evidence and
  final-claim policy; private quality-gate proof; bounded grounding and final
  rendering; run propagation through canonical tools; and terminal validation
  in ACP, CLI, pipeline, TUI, and subagent frontends.

## Acceptance evidence

| Receipt | Evidence | Result |
| --- | --- | --- |
| `S023-E1` | Legacy-authority, persisted-row mutation, and task-input/tool-result separation tests prove text and mutable SQLite state cannot manufacture current runtime authority. | Pass |
| `S023-E2` | Ordinary-shell and verifier-shaped-output tests prove Bash produces command evidence only; a private guardrails execution proof is required for verification. | Pass |
| `S023-E3` | Exact run, cross-run, stale-read, changed-diff, path-mismatch, and canonical-absolute-observer/relative-claim tests prove claims require the intended current resource receipt rather than UUID presence or suffix matching. | Pass |
| `S023-E4` | Final-envelope tests prove plain prose, trailing prose, broad outcome claims, forged receipts, cross-run verification, oversized receipt vectors, oversized command vectors, and control-character rendering attacks are denied. | Pass |
| `S023-E5` | File/command finals require a matching trusted verifier receipt, while explicit unsupported and unresolved claims render without asserting completion. | Pass |
| `S023-E6` | Grounding hydration tests prove summaries remain navigation-only, provenance and receipt integrity are visible, and both per-requirement and aggregate response budgets are enforced. | Pass |
| `S023-E7` | ACP, CLI, TUI, pipeline, and subagent tests prove terminal model text is validated before display/persistence and gate denials cannot contaminate or silently disappear from the turn. | Pass |
| `S023-E8` | Canonical read, write, diff, tool-result, background-command, compaction, and task-spec tests trace the exact run/source/artifact metadata through real dispatch paths. | Pass |

## Verification record

All Cargo compilation used `CARGO_BUILD_JOBS=1`; all tests used
`--test-threads=1` to respect host RAM limits.

- `cargo fmt --all -- --check` — pass.
- `CARGO_BUILD_JOBS=1 cargo check --all-features --all-targets` — pass.
- `CARGO_BUILD_JOBS=1 cargo clippy --all-features --all-targets -- -D warnings`
  — pass with the repository's strict lint profile.
- `CARGO_BUILD_JOBS=1 cargo test --all-features -- --test-threads=1` — pass
  for the complete project: 2,604 library tests, 227 main-binary tests, every
  integration target, and doc tests; only explicitly ignored cases remained
  ignored.
- Focused serialized gates passed for `ledger_decision_e2e` (15), TUI app
  tests (67), final-gate tests (2), the pipeline quality-gate denial path (1),
  `bash_dispatch_validation_e2e` (19),
  `read_file_dispatch_validation_e2e` (21), and
  `write_file_dispatch_validation_e2e` (18).
- `git diff --check` — pass.

The skeptical review treated changed tests as untrusted implementation work.
It exposed and repaired mutable verifier results, database-row self-forgery,
arbitrary outcome claims, cross-run partial receipt publication,
display-before-validation in three frontends, silent TUI denial, quality-gate
text contaminating the next final envelope, renderer injection and apostrophe
regressions, unbounded grounding/final fields, synthetic path tests that hid
the production absolute/relative identity mismatch, and stale positive
subagent expectations. The final complete run above is clean after those
corrections.

## Unresolved risks and queues

- S-024 owns live snapshot, diff, executable, and workspace revalidation after
  later mutations. S-023 records and consumes exact stale markers but does not
  claim a continuously refreshed external-state snapshot.
- S-088 remains planned, so no canonical artifact-bound alternate-model VDD
  receipt can honestly be issued yet. Queue `S023-G1` and its final staged
  digest for retrospective VDD; any artifact change invalidates that queue.
- F-036 and S-032 own durable evidence retention, sensitivity, descriptor-safe
  publication, and related lifecycle policy. S-023 deliberately downgrades
  reloaded rows instead of claiming that the current SQLite store is a durable
  trust root.
- Crosslink issue #1000 separately tracks the pre-existing unbounded upstream
  SSE buffer. Terminal final buffering is bounded here, but this slice does not
  close the transport-level issue.

No additional remediation slice or Crosslink issue was created. Each residual
risk discovered during this slice is already owned by the canonical audit,
S-024/S-032/S-088, or existing issue #1000.

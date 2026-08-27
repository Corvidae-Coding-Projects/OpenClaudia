# S-105: Evaluate and improve technical-memory retrieval

Status: Implemented and adversarially reviewed; artifact-bound VDD pending S-088
Effort: Medium
Primary findings: Design requirement from F-073 and W5
Workstreams: W4, W5, W10
Depends on: [S-001](./001-capability-evidence-registry.md), [S-023](./023-reality-evidence-boundary.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-054](./054-memory-authority-and-schema.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Replace the safe deterministic lexical baseline with an evaluated,
task-conditioned retrieval pipeline only where measured evidence shows that it
improves work on the current codebase.

## Implementation boundary

- Build a versioned, artifact-bound corpus of repository-specific technical
  lessons, tasks, expected citations, contradictions, stale lessons, sensitive
  records, and no-hit cases. Keep training/tuning cases separate from final
  evaluation and bind reviewer/model/config digests.
- Add bounded metadata filtering and candidate generation, then evaluate lexical,
  semantic, task-conditioned, hybrid, reranking, diversity, freshness, and
  threshold policies against the S-054 lexical/no-memory baselines.
- Return only typed S-054 records with citations and explicit no-hit, partial,
  stale, conflicted, or store-error state. Retrieval scores never change lesson
  truth, review state, sensitivity, scope, or authority.
- Enforce input, candidate, embedding, CPU/device, latency, token, output, and
  monetary budgets. Define deterministic fallback when an optional semantic
  backend is absent or fails, and never send private lessons to an unapproved
  remote embedding service.
- Measure recall/precision, citation accuracy, stale/harmful-memory rate,
  downstream task success, latency, tokens, and cost. Retain only mechanisms
  whose bounded final-environment evaluation beats the simpler baseline without
  unacceptable harm.

## Acceptance

- The selected policy has reproducible multi-trial evidence over held-out tasks
  and adversarial no-hit/stale/contradiction/privacy cases; prose claims alone
  cannot promote it.
- The runtime cannot exceed declared context/resource budgets or silently turn
  partial/error states into no-hit.
- Relabelled, tampered, self-reviewed, missing-baseline, under-trial, and
  digest-mismatched evaluation artifacts fail validation.
- Relevant deterministic tests and trace assertions pass; attach an
  artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence
receipts, unresolved risks, and any newly proposed slice. Completion of this
slice does not imply completion of its parent workstream.

## Implemented architecture — 2026-08-22

Technical memory remains explicit, typed, repository-specific evidence. It is
retrieved only when an agent calls a canonical memory tool; the implementation
does not capture conversation prose, infer lessons from hidden context, or add
memory to prompts ambiently. Existing lesson authority, sensitivity, review,
scope, causal revision, conflict, and citation fields remain authoritative.
Retrieval scores can order eligible evidence, but cannot make a lesson true or
override those fields.

`memory_search` now accepts an optional bounded task context containing an
explicit task kind, repository-relative paths, technical symbols, required
evidence kinds, and query terms. The caller supplies this context at the tool
boundary. Values are canonicalized and bounded before retrieval; transcripts
and provider-private state are never consulted. `memory_list` remains a
context-free lexical listing operation. User, team, and combined scopes share
the same retrieval policy, with combined results reranked through one bounded
fusion pass rather than concatenated as independently ranked lists.

The production implementation exposes deterministic no-memory, lexical,
field-weighted, task-conditioned, freshness-aware, thresholded, and diverse
policies. The evaluation isolates those mechanisms as an ablation chain rather
than attributing a bundled result to every component. Semantic and hybrid
retrieval are explicitly unavailable mechanisms: no private technical lesson
is sent to a remote embedding service, and no unavailable backend is credited
with a result. Candidate count, result count, context size, output bytes,
conservative evidence-token upper bounds, deterministic work, latency, and
remote monetary cost are all bounded and artifact-bound.

Runtime policy promotion consumes the strict evaluation and independent-review
artifacts. Missing, malformed, tampered, under-trial, self-reviewed, rejected,
or digest-mismatched evidence fails closed to the lexical baseline with a typed
trace. The bundled review intentionally has reviewer
`unassigned-independent-reviewer`, no approved dimensions, and verdict
`rejected`. Consequently the measured task-conditioned policy is not silently
enabled before S-088 performs a genuinely independent review.

## Evaluation and verification evidence

The checked-in tuning and held-out corpora use separate cases and include
relevant lessons, field/task decoys, no-hit queries, stale and expired records,
contradictions, private records, and explicit expected citations. The evaluator
runs three deterministic trials and binds its schema, policy chain, limits,
metric definitions, and conservative one-byte/one-token accounting through
evaluator configuration digest
`sha256:127969295a539ae27223a5a9cb76c342aa1453a5277383fc9e5bbca67c7deded`.

The selected `task_conditioned_diverse_v1` policy produced these exact
aggregate results:

| Split | Policy | Recall | Precision | Task/state successes | Harmful returns | Stale returns | Citations | Evidence bytes/token upper bound | Work units |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Tuning | `lexical_v1` | 4/8 | 4/9 | 6/8 | 5 | 2 | 9/9 | 14,419 | 50 |
| Tuning | `task_conditioned_diverse_v1` | 8/8 | 8/8 | 10/10 | 0 | 1 | 8/8 | 12,646 | 84 |
| Held out | `lexical_v1` | 2/7 | 2/8 | 5/7 | 6 | 2 | 8/8 | 12,961 | 44 |
| Held out | `task_conditioned_diverse_v1` | 7/7 | 7/7 | 10/10 | 0 | 1 | 7/7 | 11,142 | 73 |

Nineteen unique citation receipts bind exact repository-relative paths, byte
lengths, and SHA-256 digests. Evaluation construction verifies each citation
against the current repository through bounded, non-symlink regular-file reads;
the validator requires exact sorted receipt coverage. The artifacts and their
SHA-256 digests are:

- tuning corpus:
  `4e8cf9baa5250f4234202aa435c7c4021e3c100cfb5602201c30fe207d9816ab`;
- held-out corpus:
  `cb35d6f11af8fb1c281b4d97fa7ce5be1344b1a37f414389bf43d884df8cfe32`;
- evaluation:
  `56a06c70fce3abc216c7964ec826aea2cc0785ec2d0dd8f4e29d79940ce0266b`;
- deliberately rejected review:
  `db61de2456ae699016988e8d41baa19f07220c9041c07723b9c15dc06b6a758a`.

S-052 subsequently changed the still-cited `src/main.rs` while preserving the
tested migration-doctor contract. S-055 later removed only the unrelated legacy
prose-learning startup/finalization callbacks from that file. The current
final-environment citation therefore carries the honest bounded provenance
label `worktree:s055`; the checked-in generator rebuilt the evaluation and the
deliberately rejected review was rebound to the new exact artifacts. Canonical
`worktree:sNNN` labels allow later slices to do the same without falsely
retaining a historical Git generation.

S-108 subsequently made writable process workspaces transactional and changed
the still-cited `src/tools/bash/mod.rs`. Its source citation is therefore
rebound to `worktree:s108` and digest
`sha256:b2c24912b50c85b7ba2ac9cedcfd48e6f230d23ce3381340cd0910219308da58`;
the checked-in generator rebuilt the evaluation and the deliberately rejected
review remains rejected while binding the new exact corpus and evaluation
digests above.

S-091 subsequently changed the still-cited `src/main.rs` while preserving the
tested migration-doctor behavior. That citation is rebound to `worktree:s091`
and digest
`sha256:cbfd7d33778b03af36dc0fa0e295f11f0e6612f35f511d1447b591710175aeab`.
The checked-in generator rebuilt the evaluation, and the deliberately rejected
review remains rejected. The current tuning, held-out, evaluation, and review
artifact digests are respectively
`a97e53b6b0c63638ad1daf41d1c912669f8590781d8b3feeb29bf729b869c768`,
`c7bcfe253411ff1b4f22c639bc00327fff57c637261f276d610b3d150162f256`,
`34f94c71e6759af48bca9f3462e7a1149a401f74c6e21dbae73175da3547e6e9`,
and `632939ab2c00a762500ed9dccbcb5ccd91fee3b9cf02eda1a6032634ed175e91`.

The SHA-256 digest of the sorted `sha256sum` manifest for the 24 changed
non-slice artifacts is
`8adc4a735d9b0fa38b2ce327a8ab35f02dc5bbb2c74117694eac1548201e5e9d`.

All Rust commands used Rust 1.98.0 and `CARGO_BUILD_JOBS=4`; every test command
used `--test-threads=1`.

- Retrieval unit tests passed 7/7; production-route retrieval E2E passed 4/4;
  evidence validation E2E passed 9/9.
- Team replication retrieval passed 5/5. Technical-memory behavior passed
  18/18, source lifecycle passed 17/17, host review passed 7/7, portable package
  coverage passed 5/5, and team-authority CLI coverage passed 5/5.
- Tool registry handler and schema coverage passed 48/48, including the new
  bounded context contract.
- Formatting passed. Strict locked all-feature/all-target Clippy with
  `-D warnings` passed without suppression after one oversized citation helper
  was decomposed at its source.
- The complete locked all-feature/all-target native suite passed with exit
  status 0: the library harness discovered 2,738 tests, all non-ignored tests
  passed, one test was ignored, and every binary, integration, example, and
  documentation target passed. An earlier run reached an unrelated LMStudio
  CLI fixture timeout under full-suite load; its exact isolated rerun passed,
  the clean complete rerun passed, and the fixture defect is tracked as #1082.
- Locked all-feature/all-target Windows GNU `cargo check` passed. Its warnings
  were pre-existing target-conditional findings outside S-105; no S-105 path
  emitted a warning.

The skeptical repair cycle added true field/task/freshness/threshold/diversity
ablations, a held-out task decoy, production-derived stale and expiry fixtures,
runtime/corpus query-limit parity, score/sort/diversity work accounting,
production-like persisted-record fixtures, and exact partial, stale, conflict,
and fallback assertions. Final review also bounded the complete public
scope/retrieval envelope, not merely the inner database result, and added
parent-traversal and symbolic-link citation rejection tests. It rejects
fabricated citation receipts, false source generations, missing receipt
coverage, forged reviews, relabelled artifacts, privacy leakage, and forbidden
final states rather than counting failures or a lack of panics as success.

## Residual boundaries

- S-088 owns the independent artifact-bound VDD review, including the required
  alternate-model verdict. This slice does not claim that review has occurred.
- Citation verification assumes a trusted, quiescent checkout while evaluation
  artifacts are generated. Descriptor-safe verification during concurrent
  repository mutation remains a release/VDD boundary.
- A future semantic or hybrid backend must independently prove bounded benefit
  and approved private-data handling before it can become eligible. None is
  represented as operational here.
- S-055 still owns evidence-bound automatic learning, and S-057 owns causal
  compaction checkpoints. Their legacy prose compatibility paths are not
  treated as proof that automatic capture is complete.
- Typed resolution of concurrent technical-memory heads is tracked by issue
  #1081. S-036 retains the cross-platform secure persistent-backend boundary.

The implementation completes S-105 only. It does not imply completion of the
parent dormant-feature workstream.

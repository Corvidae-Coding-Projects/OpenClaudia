# S-055: Rebuild automatic learning around causal evidence

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-076
Workstreams: W5
Depends on: [S-023](./023-reality-evidence-boundary.md), [S-052](./052-canonical-task-graph.md), [S-054](./054-memory-authority-and-schema.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Capture observations without turning correlation or convenient wording into durable truth.

## Implementation boundary

- Associate candidate learning with exact task, call, command, artifact/workspace generation, outcome, source, and contradiction state.
- Require deterministic evidence or explicit user confirmation before promoting preferences/fixes, and add review, expiry, correction, and deletion.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- An unrelated later successful command cannot be stored as the resolution of an earlier failure.
- Evaluation measures downstream task benefit, false-learning rate, harmful-memory rate, and user correction across frontends.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Implemented architecture — 2026-08-22

Automatic learning is now one opt-in consumer of the canonical
post-authorization `ToolResult` boundary. It does not receive user messages,
assistant messages, prompt-expanded repository text, or arbitrary command
output prose. The former REPL-only `AutoLearner` callbacks and their imperative
preference/error/co-edit heuristics are gone. Their database tables and explicit
legacy inspection APIs remain available as labeled compatibility views; they
are not inputs to the new learner.

`memory.automatic_learning_enabled` is a strict typed configuration field with
canonical and deprecated environment aliases. It defaults to `false`. When it
is enabled and the exact workspace-bound memory store is available, the shared
tool executor can propose a lesson only from this bounded sequence:

1. one allowlisted foreground verification invocation returns a typed error or
   partial outcome;
2. up to 16 successful `edit_file` or `write_file` results occur in the same
   exact run/task binding; and
3. the byte-exact original invocation arguments later return success in that
   binding.

The matcher binds run and capability generation, workspace identity and
generation, canonical task graph identity/revision when available (otherwise
the run's task generation/digest), raw invocation digest, provider tool-call
digest, typed result digest, successful mutation paths, and failure class.
Every stored citation is a `tool_result` citation whose digest covers the
invocation, typed outcome, artifacts, attachments, authoritative observations,
usage, and sensitivity. The advisory learning receipt is intentionally excluded
from that evidence digest, so attaching it cannot make its own citation change.

The persisted object is an S-054 `TechnicalLesson` candidate, not a preference
or instruction. It is workspace-private, `observed_once`, `internal`, due for
review after 30 days, and explicitly says that the edit/success sequence is
correlation rather than proof of causation. Raw failure/success output is never
stored. The retained command is bounded, single-line, masked through the run's
secret sanitizer, and redacts sensitive assignments and option values; its raw
arguments remain bound only by digest. A recurrence of the same check in the
retained causal run/task writes an immutable correction that contradicts the
candidate. Existing `memory_update`, `memory_delete`, and host-review tools
provide explicit correction, deletion, and review after the run ends.

The process-local matcher is bounded to 128 run generations, 32 pending checks
per run, 16 mutations per check, and 32 learned check heads per run. Capacity
evictions increment degraded health. Mutation overflow is surfaced immediately
and makes the pending sequence ineligible, so incomplete evidence cannot create
a partial lesson. Compound or asynchronous shell expressions are rejected,
including newline, sequencing, pipe, redirection, command substitution,
backtick, and background operators.

CLI, TUI, ACP, and subagent execution now pass the effective application
configuration through the shared executor rather than maintaining frontend
learning callbacks. ACP normalization preserves the provider's exact call ID.
The read-only `memory_learning_status` tool is in the registry, relevant role
catalogs, and plan mode; it returns bounded run-local policy, pending,
candidate, contradiction, and degradation metadata. `/memory` reports the same
causal policy/status and lists typed lessons explicitly while labeling legacy
pattern/error/preference/file views as compatibility data.

## Evaluation and verification evidence

The checked-in corpus executes the production state machine and canonical
memory tools under fixed input/work budgets. It includes hostile prose,
unrelated success, success without mutation, failed edits, compound shell,
later contradiction, deterministic downstream retrieval, and explicit user
correction under CLI, TUI, ACP, and subagent session identities. Its exact
metrics are:

| Measure | Result |
|---|---:|
| Downstream deterministic retrieval benefit | 1/1 |
| False-learning candidates | 0/5 negative cases |
| Harmful retained records | 0/6 stored records inspected |
| Causal contradiction success | 1/1 |
| Explicit user correction success | 4/4 frontend trials |

This benefit measure proves that a later `memory_search` tool call can retrieve
the exact cited candidate; it does not claim model-task uplift. Separate direct
adapter tests prove that CLI, TUI, ACP, and subagent paths propagate the
effective opt-in policy. The true canonical execution test performs an actual
broken Rust write, nonzero `rustc`, required read, exact edit, and successful
rerun, then proves failure/edit/success citations carry their real workspace
generations. ACP independently proves those citations bind provider call IDs.

Artifact SHA-256 values before this self-referential slice record are:

- `src/auto_learn.rs`:
  `7c7ce9e112abb7aaf213fefc14907bff24b118627a1fb70948b4c8d712ceb94e`;
- `src/tools/result.rs`:
  `67af60f4d90a2e8e4ccc0936038b1bdbf20f431c359b999a963368cc9380823f`;
- automatic-learning corpus:
  `0447cf505b9e721d7f44348b55589b9ed4766f986b743ca7a0f60805ddbf76b1`;
- causal E2E suite:
  `49b105e5fd7b7ec1c21538b7a7a967b1a09374ac4f53cd27c68f14ae74ffeda6`;
- deterministic evaluation suite:
  `25437ac30f19f4c84c50374d7934cbf0859f1a12b5a9768b0d7571f603dd7804`.

All Cargo commands used Rust 1.98.0 with `CARGO_BUILD_JOBS=4`; all test commands
used `--test-threads=1`.

- Automatic-learning unit tests passed 4/4 and causal E2E passed 13/13.
- The deterministic evaluation passed with the exact metrics above.
- Direct CLI, TUI, ACP, and subagent propagation tests passed; ACP's real
  fail/read/edit/succeed citation test passed.
- Registry invariants, tool definitions, environment configuration, typed
  technical memory, memory statistics, source lifecycle, and subagent planning
  suites passed in focused runs.
- `cargo fmt --all -- --check`, `git diff --check`, and locked strict
  all-feature/all-target Clippy with `-D warnings` passed.
- The complete locked all-feature/all-target native suite passed: the library
  harness reported 2,725 passed, zero failed, and one ignored out of 2,726;
  every binary, integration, example, and documentation target also passed.
- Locked all-feature/all-target Windows GNU `cargo check` passed. Its warnings
  are pre-existing target-conditional findings outside S-055; S-055 emitted no
  Windows warning.

Changing `src/main.rs` invalidated an S-105 final-environment citation exactly
as designed. The held-out corpus now binds `worktree:s055` and the current
source digest; the canonical generator rebuilt the evaluation and the
deliberately rejected independent-review artifact was rebound without changing
its fail-closed verdict.

## Residual boundaries

- S-088 owns canonical alternate-model VDD. No implementation or self-authored
  test in this slice is represented as that independent receipt.
- The matcher never carries causal inference across a retired run generation.
  Durable candidates remain retrievable across runs, but later cross-run
  correction requires an explicit typed memory correction rather than guessing
  that two superficially similar tasks are identical.
- The allowlist classifies bounded command structure; it is not verifier binary
  attestation. Automatic output therefore remains an untrusted, review-due
  candidate and can never promote itself.
- ACP currently collapses typed `partial` during its provider-facing result
  projection. Internal canonical capture and exact call citations work, but
  provider/UI parity is not claimed; the production defect is tracked as
  Crosslink #1090.
- The evaluation proves deterministic retrieval and correction behavior, not
  downstream model uplift. A broader independently reviewed task benchmark can
  strengthen this evidence after S-088 exists.

The implementation completes S-055 only. It does not imply completion of the
parent dormant-feature workstream.

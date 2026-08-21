# S-105: Evaluate and improve technical-memory retrieval

Status: Planned
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

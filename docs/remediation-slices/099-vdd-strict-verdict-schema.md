# S-099: Make VDD verdict parsing strict and fail closed

Status: Complete
Effort: Small
Primary findings: F-134
Workstreams: W28
Depends on: [S-011](./011-canonical-typed-tool-results.md), [S-023](./023-reality-evidence-boundary.md), [S-088](./088-canonical-vdd-verifier-role.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent parse failures, empty output, malformed ranges, and partial responses from being certified as clean.

## Implementation boundary

- Define a strict versioned structured verdict schema with bounded findings, identities, paths, ranges, evidence, uncertainty, and terminal status.
- Normalize and validate model-supplied paths/ranges without panics and fuzz the parser/triage boundary.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Malformed, contradictory, truncated, missing, out-of-range, duplicate, and empty verdicts return error/inconclusive, never clean.
- Known clean and defect fixtures round-trip with stable finding identities and checked citations.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Completed implementation — 2026-08-28

Canonical VDD reports now use a bounded version-2 JSON contract. Findings carry
a normalized cause code, repository-relative path, checked one-indexed source
range, current-ledger evidence, and a SHA-256 identity derived by the host from
the normalized location and cause rather than verifier prose. Deserialization
rejects unknown fields, forged identities, duplicate findings or citations,
absolute or traversing paths, invalid or excessive ranges, unsupported schema
versions, oversized output, and contradictory terminal states.

Clean, defect, and inconclusive outcomes are mutually consistent. A clean
verdict cannot carry findings or failed criteria, a defect verdict must carry
both, and an inconclusive verdict cannot smuggle either. Finding locations must
be covered by cited current-file observations from the review's exact reality
ledger. Malformed, empty, prose-only, truncated, and partially structured model
output therefore remain typed parse/validation failures and cannot become a
clean certification.

The still-live legacy VDD engine now consumes an equally strict terminal JSON
shape while S-100 replaces its finalization path. Its former relaxed prose
inference is gone, invalid source windows return errors before slicing, and
truncated windows cannot validate a finding. Duplicate and pattern matches are
retained as hints for an evidence-backed verifier; they no longer demote a
finding on their own. If verification cannot complete, the finding stays
genuine.

## Evidence

- Artifact generation `S099-G1` is based on commit
  `8f7950aa4e41bc6325e20f97e442e4da9b73b514`; its source/test diff digest is
  SHA-256 `ea2dd3aa754372bd7de07bd59f1108c94a3c1c5b11f1596afcfe79dd2b13be5b`.
  Any change to the listed VDD source or test artifacts invalidates it.
- Canonical schema and real-child-harness tests passed 14/14; legacy triage
  unit tests passed 17/17, and both VDD end-to-end suites passed 25/25.
- VDD session/config, pipeline, and integration selections passed 86/86.
- Rust 1.98 formatting, locked all-feature/all-target check, and strict Clippy
  passed. The complete locked all-feature/all-target test suite passed with
  serialized test execution, including all 3,022 library tests and every
  integration target.
- Repository hygiene and its 27 policy regressions passed. Root and fuzz
  dependency-policy audits passed; fuzz check, strict Clippy, and its four
  deterministic library tests also passed.

## Residual boundary

- S-100 owns the single blocking finalization gate that consumes this verdict;
  S-101 owns bounded provider transport, and S-102 owns transactional evidence
  and issue publication. S-099 does not claim those later lifecycle guarantees.
- The canonical schema is exercised through the real child/tool harness, but an
  artifact-bound alternate-model production receipt depends on S-100 making
  this parser the mandatory finalization path. No such receipt is fabricated.
- Completion applies only to S-099; parent issue #1071 remains open.

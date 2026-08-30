# S-076: Make project initialization transactional

Status: Implemented and verified (2026-08-30)
Effort: Medium
Primary findings: F-107
Workstreams: W1, W14, W15, W25
Depends on: [S-007](./007-remove-legacy-rule-injector.md), [S-031](./031-descriptor-safe-persistence.md), [S-058](./058-explicit-hook-import-trust.md), [S-075](./075-typed-command-registry.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent initialization from overwriting existing state or scaffolding deprecated and implicitly trusted authority paths.

## Implementation boundary

- Generate a bounded typed plan, detect every collision, show exact files/effects, and commit through an atomic staged directory transaction with explicit force semantics.
- Generate schema-valid minimal configuration and inert examples; do not install rule injection, executable hooks, fictitious endpoints, or unsupported claims.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Default init leaves any existing file untouched and a failed/interrupting init leaves no partial project state.
- Generated trees deserialize under current schemas and grant no executable/instruction authority merely by existing.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- CLI `init`, legacy-REPL `/init`, and TUI `/init` now use one typed plan and
  commit API. The plan binds the run/capability generation, exact observed
  destination kinds and content, complete effects, collision policy, and a
  generation-specific recovery location before any write.
- The emitted tree is deliberately minimal: schema-valid inert
  `.openclaudia/config.yaml` plus `.openclaudia/skills/`. It installs no rule
  source, executable hook, plugin authority, credential, fake endpoint, or
  unsupported model claim merely by existing.
- Default initialization refuses every incompatible existing entry without
  mutation and reports the exact paths plus `--force` recovery guidance.
  Forced initialization replaces only the scaffold generation while retaining
  the displaced bytes and entry types in the receipt-named backup; unrelated
  project files remain untouched.
- Linux publication uses pinned directory descriptors, a private
  same-filesystem staged tree, no-replace renames, directory synchronization,
  stale-plan revalidation, rollback before publication, and a typed retained
  recovery state if durability cannot be proven after an irreversible step.

## Verification

- Five focused transaction tests cover schema validity/inertness, fresh
  publication, collision refusal, exact force backup, and stale-plan refusal.
  The compiled CLI executable tests additionally exercise fresh init, repeat
  refusal, force replacement, broken-symlink handling, schema loading, and the
  absence of deprecated scaffold paths.
- Rust 1.98 formatting, all-target/all-feature compilation, strict Clippy, the
  3,116-test library harness, and every integration harness pass at the
  integration gate. The changed `src/main.rs` citation was rebound through the
  checked-in S-105 generator; independent retrieval review remains explicitly
  rejected/unassigned rather than being fabricated.

## Residual boundary

Transactional publication currently has a Linux descriptor-relative
implementation and fails closed as unsupported elsewhere. Force backups are
intentionally retained for human-directed recovery; automatic retention or
deletion policy is outside this initialization slice.

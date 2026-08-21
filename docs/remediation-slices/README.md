# OpenClaudia Remediation Slices

This directory turns the canonical [full audit](../full-codebase-audit-2026-08-16.md) and [production remediation design](../production-remediation-design.md) into bounded implementation units. The canonical documents remain the source of findings and architecture; these files are the execution backlog.

There are **102 slices** covering all **143 findings exactly once as a primary responsibility** and every design workstream W0–W28. A slice may support adjacent findings, but primary ownership does not overlap.

## How to execute a slice

1. Select a slice whose listed dependencies are Verified.
2. Give a fresh worker only that slice, the immutable user objective, its dependency receipts, and the cited source/code needed for the boundary.
3. Keep work inside the stated implementation boundary. Create a new slice for discovered work rather than silently expanding scope.
4. Run the deterministic acceptance checks and record exact artifact generations and evidence.
5. After S-088 exists, run VDD through the canonical alternate-model verifier against the exact artifact. Earlier implemented slices must be queued for retrospective VDD verification.
6. Mark the slice Verified only after deterministic and required VDD/integration evidence passes. Completing a slice never marks a parent workstream production-ready by itself.

The planner orchestrates and reconciles state; it does not absorb worker transcripts or perform unscoped implementation. VDD shares the canonical harness and guardrails but receives separate context, identity, budgets, and normally read-only capabilities. S-088 itself requires external/manual independent verification because it cannot bootstrap trust by verifying itself.

## Status and effort

Status values are **Planned**, **Ready**, **In progress**, **Implemented — awaiting verification**, **Verified**, and **Blocked**. Blocked must name the unmet dependency or required user/external decision.

Effort is relative: **Small** is a narrow contract or subsystem repair with focused tests; **Medium** is an end-to-end boundary spanning several cooperating files. If a slice grows beyond medium, split it before implementation.

## Dependency layers

IDs are stable references, not execution order. Dependencies are authoritative. The current acyclic graph has 15 topological layers:

1. [S-001](./001-capability-evidence-registry.md), [S-002](./002-repository-artifact-dependency-policy.md), [S-004](./004-startup-migrations-fail-closed.md), [S-005](./005-typed-environment-config-loading.md), [S-007](./007-remove-legacy-rule-injector.md), [S-008](./008-typed-context-authority-and-budget.md), [S-025](./025-end-to-end-secret-types-and-redaction.md)
2. [S-003](./003-side-effect-free-fuzz-harnesses.md), [S-006](./006-safe-doctor-health-contract.md), [S-009](./009-repository-instruction-and-hook-boundary.md), [S-010](./010-canonical-run-context-and-events.md), [S-011](./011-canonical-typed-tool-results.md), [S-027](./027-supported-anthropic-authentication.md), [S-028](./028-verified-codex-auth-metadata.md)
3. [S-012](./012-runtime-feature-reachability.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-044](./044-provider-native-state-contract.md), [S-051](./051-token-turn-and-cost-budgets.md)
4. [S-013](./013-progressive-tool-catalog.md), [S-017](./017-deny-precedence-and-approval-receipts.md), [S-023](./023-reality-evidence-boundary.md), [S-045](./045-openai-responses-continuation.md), [S-046](./046-gemini-ollama-tool-history.md), [S-047](./047-dynamic-model-capability-catalog.md), [S-048](./048-hardened-provider-http-transport.md), [S-049](./049-reasoning-state-privacy.md), [S-075](./075-typed-command-registry.md)
5. [S-018](./018-non-bypassable-host-safety-policy.md), [S-024](./024-artifact-verification-invalidation.md), [S-050](./050-provider-terminal-outcome-state.md), [S-064](./064-mcp-dynamic-tool-dispatch-and-policy.md), [S-065](./065-mcp-current-protocol-adapter.md), [S-070](./070-named-remote-action-runtime.md), [S-081](./081-single-real-keybinding-engine.md), [S-083](./083-safe-terminal-rendering.md)
6. [S-015](./015-skills-trust-and-capabilities.md), [S-019](./019-explicit-session-capabilities.md), [S-058](./058-explicit-hook-import-trust.md), [S-078](./078-bounded-print-mode-adapter.md), [S-092](./092-proxy-client-authentication.md)
7. [S-014](./014-runtime-enforced-behavioral-modes.md), [S-020](./020-bash-effect-classification.md), [S-021](./021-run-scoped-blast-radius-guardrails.md), [S-031](./031-descriptor-safe-persistence.md), [S-033](./033-bounded-file-discovery-and-grep.md), [S-034](./034-typed-multimodal-and-partial-reads.md), [S-040](./040-supervised-foreground-process-io.md), [S-059](./059-canonical-hook-lifecycle.md), [S-071](./071-web-egress-connection-broker.md), [S-085](./085-speculation-transaction.md)
8. [S-022](./022-diff-and-quality-completion-gates.md), [S-026](./026-claude-credential-store-read-only.md), [S-029](./029-oauth-session-lifecycle.md), [S-030](./030-safe-interactive-api-key-setup.md), [S-032](./032-snapshot-bound-file-edits.md), [S-036](./036-cross-platform-secure-files.md), [S-037](./037-atomic-session-finalization.md), [S-041](./041-owned-background-processes.md), [S-042](./042-least-privilege-sandbox-profiles.md), [S-052](./052-canonical-task-graph.md), [S-053](./053-memory-record-identity-and-merge.md), [S-057](./057-causal-compaction-checkpoints.md), [S-061](./061-plugin-identity-and-bounded-discovery.md), [S-066](./066-mcp-owned-bounded-transports.md), [S-076](./076-transactional-project-initialization.md), [S-079](./079-legacy-attachments-and-editor-capabilities.md)
9. [S-035](./035-transactional-notebook-editing.md), [S-038](./038-session-schema-migration-and-ownership.md), [S-043](./043-unify-direct-shell-execution.md), [S-054](./054-memory-authority-and-schema.md), [S-060](./060-hook-execution-admission.md), [S-062](./062-plugin-supply-chain-transactions.md), [S-067](./067-mcp-oauth-elicitation-inprocess.md), [S-068](./068-stateful-lsp-service.md), [S-072](./072-supervised-browser-and-web-cancellation.md), [S-073](./073-transactional-worktree-apply.md), [S-080](./080-atomic-plan-approval.md), [S-082](./082-private-notes-and-side-questions.md), [S-084](./084-cron-scheduler-service.md), [S-086](./086-rotating-planner-checkpoints.md), [S-096](./096-tui-run-cancellation-supervision.md)
10. [S-039](./039-causal-resume-and-branch-identity.md), [S-055](./055-evidence-bound-automatic-learning.md), [S-056](./056-operational-memdir-lifecycle.md), [S-063](./063-plugin-capability-activation.md), [S-069](./069-bounded-lsp-jsonrpc.md), [S-074](./074-workspace-capability-binding.md), [S-089](./089-acp-session-isolation.md), [S-097](./097-tui-attachment-containment.md), [S-103](./103-authenticated-team-memory-authority.md), [S-105](./105-evaluated-technical-memory-retrieval.md)
11. [S-077](./077-generation-bound-git-review-commit.md), [S-087](./087-fresh-worker-slice-lifecycle.md), [S-090](./090-bounded-acp-transport.md), [S-091](./091-acp-effective-capabilities.md), [S-093](./093-proxy-session-isolation.md), [S-104](./104-team-memory-replication-service.md)
12. [S-088](./088-canonical-vdd-verifier-role.md), [S-094](./094-proxy-canonical-lifecycle-routing.md), [S-098](./098-atomic-tui-provider-resume.md)
13. [S-095](./095-proxy-streaming-and-vdd-parity.md), [S-099](./099-vdd-strict-verdict-schema.md)
14. [S-100](./100-vdd-blocking-finalization-gate.md), [S-101](./101-vdd-bounded-provider-transport.md)
15. [S-102](./102-vdd-transactional-evidence-and-issues.md)

## Slice catalog

### Evidence, configuration, and runtime foundations

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-001 — Build the capability evidence registry](./001-capability-evidence-registry.md) | Medium | F-008, F-142, F-143 | W0, W13 | None |
| [S-002 — Enforce repository artifact and dependency hygiene](./002-repository-artifact-dependency-policy.md) | Small | F-009, F-141 | W0, W13 | None |
| [S-003 — Make fuzz targets side-effect free](./003-side-effect-free-fuzz-harnesses.md) | Small | F-139 | W13 | S-001 |
| [S-004 — Make startup migrations fail closed](./004-startup-migrations-fail-closed.md) | Small | F-010 | W0, W13, W15 | None |
| [S-005 — Replace generic environment-key rewriting](./005-typed-environment-config-loading.md) | Small | F-013 | W14 | None |
| [S-006 — Rebuild doctor as evidence-safe diagnostics](./006-safe-doctor-health-contract.md) | Medium | F-108 | W0, W13 | S-001 |
| [S-007 — Remove the legacy rule injector completely](./007-remove-legacy-rule-injector.md) | Medium | F-007 | W1 | None |
| [S-008 — Introduce typed context authority and budgets](./008-typed-context-authority-and-budget.md) | Medium | F-011, F-025, F-026, F-027 | W12, W17, W25 | None |
| [S-009 — Remove repository-owned control authority](./009-repository-instruction-and-hook-boundary.md) | Medium | F-140 | W1, W12, W25 | S-007, S-008 |
| [S-010 — Create the canonical run context and event kernel](./010-canonical-run-context-and-events.md) | Medium | F-004 | W12 | S-008 |
| [S-011 — Preserve typed tool results end to end](./011-canonical-typed-tool-results.md) | Medium | F-032, F-043, F-121 | W2, W12 | S-008 |
| [S-012 — Wire or honestly classify lifecycle services](./012-runtime-feature-reachability.md) | Medium | F-006 | W9, W13 | S-001, S-010 |
| [S-013 — Implement real progressive tool discovery](./013-progressive-tool-catalog.md) | Medium | F-005, F-058 | W11 | S-001, S-010, S-016 |
| [S-014 — Make behavioral modes enforce capabilities](./014-runtime-enforced-behavioral-modes.md) | Medium | F-029, F-064, F-119 | W2, W17 | S-010, S-016, S-019 |
| [S-015 — Finish skills as scoped capabilities](./015-skills-trust-and-capabilities.md) | Medium | F-028 | W16 | S-008, S-018 |

### Authority, permissions, and grounding

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-016 — Require effect classification for every tool](./016-mandatory-tool-effect-classification.md) | Medium | F-001, F-052 | W2, W20 | S-011 |
| [S-017 — Fix deny precedence and approval scope](./017-deny-precedence-and-approval-receipts.md) | Medium | F-012, F-030, F-068 | W2, W12 | S-016 |
| [S-018 — Make host safety non-bypassable](./018-non-bypassable-host-safety-policy.md) | Medium | F-016, F-031 | W2, W14 | S-016, S-017 |
| [S-019 — Eliminate ambient session capabilities](./019-explicit-session-capabilities.md) | Medium | F-033 | W2, W15 | S-010, S-018 |
| [S-020 — Replace Bash auto-approval heuristics](./020-bash-effect-classification.md) | Medium | F-045, F-050 | W2, W18 | S-016, S-018, S-019 |
| [S-021 — Make blast-radius guardrails atomic and run scoped](./021-run-scoped-blast-radius-guardrails.md) | Medium | F-084 | W2 | S-016, S-019 |
| [S-022 — Enforce diff blocks and quality gates](./022-diff-and-quality-completion-gates.md) | Medium | F-085 | W2, W28 | S-021, S-024 |
| [S-023 — Rebuild Reality grounding as an evidence boundary](./023-reality-evidence-boundary.md) | Medium | F-003, F-023, F-046 | W4, W18 | S-008, S-011, S-016 |
| [S-024 — Invalidate verification after artifact changes](./024-artifact-verification-invalidation.md) | Small | F-024 | W4, W15, W28 | S-023 |

### Secrets and authentication

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-025 — Keep secrets typed and redacted end to end](./025-end-to-end-secret-types-and-redaction.md) | Medium | F-015, F-022, F-034, F-079 | W3, W14, W18 | None |
| [S-026 — Stop mutating the shared Claude credential store](./026-claude-credential-store-read-only.md) | Small | F-080 | W3, W15 | S-025, S-031 |
| [S-027 — Replace Anthropic client impersonation](./027-supported-anthropic-authentication.md) | Medium | F-081 | W3 | S-025 |
| [S-028 — Verify Codex account and compliance metadata](./028-verified-codex-auth-metadata.md) | Small | F-082 | W3 | S-025 |
| [S-029 — Implement a complete OAuth session lifecycle](./029-oauth-session-lifecycle.md) | Medium | F-095 | W3, W15 | S-025, S-031, S-048 |
| [S-030 — Make interactive API-key setup secret safe](./030-safe-interactive-api-key-setup.md) | Small | F-111 | W3, W14, W15 | S-025, S-031 |

### Filesystem, persistence, and processes

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-031 — Build descriptor-safe persistent storage](./031-descriptor-safe-persistence.md) | Medium | F-014, F-083 | W15 | S-019 |
| [S-032 — Bind file edits and diffs to snapshots](./032-snapshot-bound-file-edits.md) | Medium | F-036, F-039 | W15 | S-019, S-031 |
| [S-033 — Bound and stabilize file discovery and grep](./033-bounded-file-discovery-and-grep.md) | Medium | F-037, F-038 | W15 | S-019 |
| [S-034 — Implement typed multimodal and partial reads](./034-typed-multimodal-and-partial-reads.md) | Medium | F-040, F-041 | W3, W15 | S-011, S-019 |
| [S-035 — Make notebook editing transactional](./035-transactional-notebook-editing.md) | Medium | F-042 | W15 | S-031, S-032 |
| [S-036 — Provide cross-platform secure file capabilities](./036-cross-platform-secure-files.md) | Medium | F-035 | W15 | S-019, S-031 |
| [S-037 — Make session mutation and finalization atomic](./037-atomic-session-finalization.md) | Medium | F-067, F-069 | W12, W15 | S-010, S-031 |
| [S-038 — Repair session schema migration and ownership](./038-session-schema-migration-and-ownership.md) | Medium | F-070, F-071 | W0, W12, W15 | S-004, S-031, S-037 |
| [S-039 — Bind resume and branches to causal state](./039-causal-resume-and-branch-identity.md) | Medium | F-072, F-117 | W12, W15 | S-031, S-038 |
| [S-040 — Supervise foreground process I/O](./040-supervised-foreground-process-io.md) | Medium | F-044 | W18 | S-019, S-025 |
| [S-041 — Own background process lifetime and output](./041-owned-background-processes.md) | Medium | F-047 | W10, W18 | S-040, S-051 |
| [S-042 — Enforce least-privilege sandbox profiles](./042-least-privilege-sandbox-profiles.md) | Medium | F-048, F-049 | W18 | S-019, S-040 |
| [S-043 — Route direct shell through the process capability](./043-unify-direct-shell-execution.md) | Small | F-112 | W18 | S-020, S-040, S-042 |

### Provider adapters and terminal semantics

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-044 — Define the provider-native state contract](./044-provider-native-state-contract.md) | Medium | F-019 | W3, W12 | S-010 |
| [S-045 — Preserve OpenAI Responses continuation](./045-openai-responses-continuation.md) | Small | F-002 | W3 | S-044 |
| [S-046 — Repair Gemini and Ollama tool history](./046-gemini-ollama-tool-history.md) | Small | F-018 | W3 | S-044 |
| [S-047 — Replace static model-name capability guesses](./047-dynamic-model-capability-catalog.md) | Medium | F-020 | W3 | S-044 |
| [S-048 — Centralize hardened provider HTTP transport](./048-hardened-provider-http-transport.md) | Medium | F-021 | W3 | S-025, S-044 |
| [S-049 — Separate reasoning continuation from display](./049-reasoning-state-privacy.md) | Medium | F-118 | W3, W12 | S-025, S-044 |
| [S-050 — Make provider terminal outcomes truthful](./050-provider-terminal-outcome-state.md) | Medium | F-096 | W3, W12 | S-010, S-044, S-048 |

### Budgets, task state, memory, and compaction

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-051 — Unify token, turn, cost, retry, and concurrency budgets](./051-token-turn-and-cost-budgets.md) | Medium | F-017, F-062, F-066 | W10 | S-010 |
| [S-052 — Consolidate task and planning state](./052-canonical-task-graph.md) | Medium | F-057, F-065 | W20 | S-010, S-016, S-031 |
| [S-053 — Give memory stable identity and merge semantics](./053-memory-record-identity-and-merge.md) | Medium | F-063, F-075 | W5 | S-031 |
| [S-054 — Make memory untrusted, versioned evidence](./054-memory-authority-and-schema.md) | Medium | F-073, F-074 | W5, W15 | S-008, S-031, S-053 |
| [S-055 — Rebuild automatic learning around causal evidence](./055-evidence-bound-automatic-learning.md) | Medium | F-076 | W5 | S-023, S-052, S-054 |
| [S-056 — Complete the memdir lifecycle](./056-operational-memdir-lifecycle.md) | Medium | F-094 | W5 | S-054 |
| [S-057 — Replace lossy compaction with causal checkpoints](./057-causal-compaction-checkpoints.md) | Medium | F-077, F-078 | W5, W10, W12 | S-008, S-010, S-031, S-044, S-051 |
| [S-103 — Establish authenticated team-memory authority](./103-authenticated-team-memory-authority.md) | Medium | Design requirement from F-075 and W5 | W3, W5 | S-025, S-029, S-031, S-053, S-054 |
| [S-104 — Wire the team-memory replication service](./104-team-memory-replication-service.md) | Medium | Design requirement from F-006, F-075, and W5 | W5, W10, W15 | S-051, S-053, S-054, S-103 |
| [S-105 — Evaluate and improve technical-memory retrieval](./105-evaluated-technical-memory-retrieval.md) | Medium | Design requirement from F-073 and W5 | W4, W5, W10 | S-001, S-023, S-051, S-054 |

### Hooks and plugins

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-058 — Require explicit trust for hook imports](./058-explicit-hook-import-trust.md) | Medium | F-086 | W25 | S-008, S-018, S-025 |
| [S-059 — Unify the hook lifecycle across frontends](./059-canonical-hook-lifecycle.md) | Medium | F-087 | W12, W25 | S-010, S-058 |
| [S-060 — Sandbox and budget hook execution](./060-hook-execution-admission.md) | Medium | F-088 | W10, W18, W25 | S-040, S-042, S-051, S-058, S-059 |
| [S-061 — Bind plugin identity and discovery to trusted scope](./061-plugin-identity-and-bounded-discovery.md) | Medium | F-097, F-101 | W26 | S-019, S-025, S-031 |
| [S-062 — Make plugin install and update verifiable transactions](./062-plugin-supply-chain-transactions.md) | Medium | F-098, F-099 | W15, W26 | S-025, S-031, S-061 |
| [S-063 — Activate plugin capabilities through canonical registries](./063-plugin-capability-activation.md) | Medium | F-100 | W2, W6, W16, W21, W25, W26 | S-010, S-013, S-016, S-059, S-061, S-062 |

### MCP, LSP, remote actions, and web

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-064 — Complete MCP dynamic tool dispatch and allowlists](./064-mcp-dynamic-tool-dispatch-and-policy.md) | Medium | F-090, F-138 | W2, W6, W11 | S-010, S-013, S-016 |
| [S-065 — Implement the current MCP protocol adapter](./065-mcp-current-protocol-adapter.md) | Medium | F-091 | W6 | S-025, S-048 |
| [S-066 — Own and bound MCP transports](./066-mcp-owned-bounded-transports.md) | Medium | F-092 | W6, W10, W18 | S-019, S-040, S-051, S-065 |
| [S-067 — Complete MCP OAuth, elicitation, and in-process semantics](./067-mcp-oauth-elicitation-inprocess.md) | Medium | F-093 | W3, W6, W15 | S-025, S-029, S-031, S-065, S-066 |
| [S-068 — Create a stateful workspace LSP service](./068-stateful-lsp-service.md) | Medium | F-053, F-055 | W18, W21 | S-019, S-040, S-042 |
| [S-069 — Bound and validate LSP JSON-RPC](./069-bounded-lsp-jsonrpc.md) | Medium | F-054 | W10, W18, W21 | S-040, S-051, S-068 |
| [S-070 — Implement named remote actions safely](./070-named-remote-action-runtime.md) | Medium | F-056 | W22 | S-016, S-025, S-048 |
| [S-071 — Enforce web policy at the connection boundary](./071-web-egress-connection-broker.md) | Medium | F-102 | W23 | S-019, S-048 |
| [S-072 — Supervise browser and web work](./072-supervised-browser-and-web-cancellation.md) | Medium | F-059, F-103 | W10, W18, W23 | S-040, S-042, S-051, S-071 |

### Workspaces and user workflows

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-073 — Make worktree apply and cleanup transactional](./073-transactional-worktree-apply.md) | Medium | F-060 | W15, W18, W24 | S-024, S-031, S-040, S-042 |
| [S-074 — Bind isolated workspaces to run capabilities](./074-workspace-capability-binding.md) | Medium | F-061 | W12, W15, W24 | S-019, S-031, S-073 |
| [S-075 — Create one typed command registry](./075-typed-command-registry.md) | Medium | F-105 | W12 | S-010, S-011, S-016 |
| [S-076 — Make project initialization transactional](./076-transactional-project-initialization.md) | Medium | F-107 | W1, W14, W15, W25 | S-007, S-031, S-058, S-075 |
| [S-077 — Bind Git review and commit to exact generations](./077-generation-bound-git-review-commit.md) | Medium | F-110 | W2, W15, W18, W24 | S-024, S-031, S-040, S-042, S-074, S-075 |
| [S-078 — Move print mode onto the canonical runtime](./078-bounded-print-mode-adapter.md) | Medium | F-109 | W3, W10, W12 | S-010, S-044, S-050, S-051 |
| [S-079 — Route legacy attachments and editor input through capabilities](./079-legacy-attachments-and-editor-capabilities.md) | Medium | F-113 | W12, W15, W18 | S-019, S-031, S-040, S-075 |
| [S-080 — Make plan approval an atomic capability transition](./080-atomic-plan-approval.md) | Medium | F-114 | W2, W12, W17 | S-017, S-024, S-052, S-075 |
| [S-081 — Use one real keybinding engine](./081-single-real-keybinding-engine.md) | Medium | F-089, F-115 | W12 | S-075 |
| [S-082 — Give private notes and side questions correct semantics](./082-private-notes-and-side-questions.md) | Medium | F-116 | W8, W12 | S-008, S-010, S-052 |
| [S-083 — Make terminal rendering bounded and inert](./083-safe-terminal-rendering.md) | Medium | F-106, F-133 | W12 | S-011, S-075 |
| [S-084 — Turn cron metadata into a scheduler service](./084-cron-scheduler-service.md) | Medium | F-051 | W2, W10, W12, W15, W18, W19 | S-010, S-016, S-029, S-031, S-040, S-051 |
| [S-085 — Implement or remove speculation by measurement](./085-speculation-transaction.md) | Medium | F-104 | W7 | S-010, S-016, S-019, S-051 |

### Rotating agents, frontends, proxy, TUI, and VDD

| Slice | Effort | Primary findings | Workstreams | Dependencies |
|---|---|---|---|---|
| [S-086 — Implement rotating planner checkpoints](./086-rotating-planner-checkpoints.md) | Medium | F-120 | W8, W12, W20 | S-010, S-052, S-057 |
| [S-087 — Create fresh workers for semantic task slices](./087-fresh-worker-slice-lifecycle.md) | Medium | F-122 | W8, W10, W12, W24 | S-010, S-016, S-019, S-051, S-074, S-086 |
| [S-088 — Run VDD as the canonical alternate-model verifier](./088-canonical-vdd-verifier-role.md) | Medium | Design requirement | W2, W3, W4, W10, W12, W28 | S-010, S-023, S-024, S-044, S-050, S-051, S-087 |
| [S-089 — Isolate ACP sessions and calls](./089-acp-session-isolation.md) | Medium | F-123 | W12 | S-010, S-019, S-038 |
| [S-090 — Bound and validate ACP transport](./090-bounded-acp-transport.md) | Medium | F-124 | W10, W12 | S-010, S-040, S-050, S-051, S-089 |
| [S-091 — Make ACP modes and advertised tools effective](./091-acp-effective-capabilities.md) | Medium | F-125 | W2, W17 | S-014, S-016, S-089 |
| [S-092 — Authenticate proxy callers before credential spend](./092-proxy-client-authentication.md) | Medium | F-126 | W2, W3, W27 | S-018, S-025, S-048 |
| [S-093 — Isolate proxy tenant and session state](./093-proxy-session-isolation.md) | Medium | F-127 | W3, W12, W27 | S-010, S-019, S-029, S-089, S-092 |
| [S-094 — Route every proxy API through the canonical lifecycle](./094-proxy-canonical-lifecycle-routing.md) | Medium | F-128 | W3, W12, W27 | S-010, S-050, S-093 |
| [S-095 — Fix proxy streaming and VDD delivery parity](./095-proxy-streaming-and-vdd-parity.md) | Medium | F-129 | W3, W12, W27, W28 | S-088, S-094 |
| [S-096 — Make TUI cancellation and shutdown real](./096-tui-run-cancellation-supervision.md) | Medium | F-130 | W10, W12 | S-010, S-040, S-041, S-050 |
| [S-097 — Contain TUI file attachments](./097-tui-attachment-containment.md) | Small | F-131 | W12, W15 | S-019, S-031, S-096 |
| [S-098 — Make TUI provider switching and resume atomic](./098-atomic-tui-provider-resume.md) | Medium | F-132 | W3, W12 | S-029, S-044, S-093, S-096 |
| [S-099 — Make VDD verdict parsing strict and fail closed](./099-vdd-strict-verdict-schema.md) | Small | F-134 | W28 | S-011, S-023, S-088 |
| [S-100 — Enforce VDD blocking at canonical finalization](./100-vdd-blocking-finalization-gate.md) | Medium | F-135 | W4, W12, W28 | S-024, S-050, S-088, S-099 |
| [S-101 — Bound and validate VDD provider work](./101-vdd-bounded-provider-transport.md) | Medium | F-136 | W3, W10, W28 | S-048, S-050, S-051, S-088, S-099 |
| [S-102 — Persist VDD evidence and issues transactionally](./102-vdd-transactional-evidence-and-issues.md) | Medium | F-137 | W15, W20, W28 | S-024, S-031, S-052, S-088, S-099, S-100, S-101 |

## Finding ownership

| Finding | Primary slice |
|---|---|
| F-001 | [S-016 — Require effect classification for every tool](./016-mandatory-tool-effect-classification.md) |
| F-002 | [S-045 — Preserve OpenAI Responses continuation](./045-openai-responses-continuation.md) |
| F-003 | [S-023 — Rebuild Reality grounding as an evidence boundary](./023-reality-evidence-boundary.md) |
| F-004 | [S-010 — Create the canonical run context and event kernel](./010-canonical-run-context-and-events.md) |
| F-005 | [S-013 — Implement real progressive tool discovery](./013-progressive-tool-catalog.md) |
| F-006 | [S-012 — Wire or honestly classify lifecycle services](./012-runtime-feature-reachability.md) |
| F-007 | [S-007 — Remove the legacy rule injector completely](./007-remove-legacy-rule-injector.md) |
| F-008 | [S-001 — Build the capability evidence registry](./001-capability-evidence-registry.md) |
| F-009 | [S-002 — Enforce repository artifact and dependency hygiene](./002-repository-artifact-dependency-policy.md) |
| F-010 | [S-004 — Make startup migrations fail closed](./004-startup-migrations-fail-closed.md) |
| F-011 | [S-008 — Introduce typed context authority and budgets](./008-typed-context-authority-and-budget.md) |
| F-012 | [S-017 — Fix deny precedence and approval scope](./017-deny-precedence-and-approval-receipts.md) |
| F-013 | [S-005 — Replace generic environment-key rewriting](./005-typed-environment-config-loading.md) |
| F-014 | [S-031 — Build descriptor-safe persistent storage](./031-descriptor-safe-persistence.md) |
| F-015 | [S-025 — Keep secrets typed and redacted end to end](./025-end-to-end-secret-types-and-redaction.md) |
| F-016 | [S-018 — Make host safety non-bypassable](./018-non-bypassable-host-safety-policy.md) |
| F-017 | [S-051 — Unify token, turn, cost, retry, and concurrency budgets](./051-token-turn-and-cost-budgets.md) |
| F-018 | [S-046 — Repair Gemini and Ollama tool history](./046-gemini-ollama-tool-history.md) |
| F-019 | [S-044 — Define the provider-native state contract](./044-provider-native-state-contract.md) |
| F-020 | [S-047 — Replace static model-name capability guesses](./047-dynamic-model-capability-catalog.md) |
| F-021 | [S-048 — Centralize hardened provider HTTP transport](./048-hardened-provider-http-transport.md) |
| F-022 | [S-025 — Keep secrets typed and redacted end to end](./025-end-to-end-secret-types-and-redaction.md) |
| F-023 | [S-023 — Rebuild Reality grounding as an evidence boundary](./023-reality-evidence-boundary.md) |
| F-024 | [S-024 — Invalidate verification after artifact changes](./024-artifact-verification-invalidation.md) |
| F-025 | [S-008 — Introduce typed context authority and budgets](./008-typed-context-authority-and-budget.md) |
| F-026 | [S-008 — Introduce typed context authority and budgets](./008-typed-context-authority-and-budget.md) |
| F-027 | [S-008 — Introduce typed context authority and budgets](./008-typed-context-authority-and-budget.md) |
| F-028 | [S-015 — Finish skills as scoped capabilities](./015-skills-trust-and-capabilities.md) |
| F-029 | [S-014 — Make behavioral modes enforce capabilities](./014-runtime-enforced-behavioral-modes.md) |
| F-030 | [S-017 — Fix deny precedence and approval scope](./017-deny-precedence-and-approval-receipts.md) |
| F-031 | [S-018 — Make host safety non-bypassable](./018-non-bypassable-host-safety-policy.md) |
| F-032 | [S-011 — Preserve typed tool results end to end](./011-canonical-typed-tool-results.md) |
| F-033 | [S-019 — Eliminate ambient session capabilities](./019-explicit-session-capabilities.md) |
| F-034 | [S-025 — Keep secrets typed and redacted end to end](./025-end-to-end-secret-types-and-redaction.md) |
| F-035 | [S-036 — Provide cross-platform secure file capabilities](./036-cross-platform-secure-files.md) |
| F-036 | [S-032 — Bind file edits and diffs to snapshots](./032-snapshot-bound-file-edits.md) |
| F-037 | [S-033 — Bound and stabilize file discovery and grep](./033-bounded-file-discovery-and-grep.md) |
| F-038 | [S-033 — Bound and stabilize file discovery and grep](./033-bounded-file-discovery-and-grep.md) |
| F-039 | [S-032 — Bind file edits and diffs to snapshots](./032-snapshot-bound-file-edits.md) |
| F-040 | [S-034 — Implement typed multimodal and partial reads](./034-typed-multimodal-and-partial-reads.md) |
| F-041 | [S-034 — Implement typed multimodal and partial reads](./034-typed-multimodal-and-partial-reads.md) |
| F-042 | [S-035 — Make notebook editing transactional](./035-transactional-notebook-editing.md) |
| F-043 | [S-011 — Preserve typed tool results end to end](./011-canonical-typed-tool-results.md) |
| F-044 | [S-040 — Supervise foreground process I/O](./040-supervised-foreground-process-io.md) |
| F-045 | [S-020 — Replace Bash auto-approval heuristics](./020-bash-effect-classification.md) |
| F-046 | [S-023 — Rebuild Reality grounding as an evidence boundary](./023-reality-evidence-boundary.md) |
| F-047 | [S-041 — Own background process lifetime and output](./041-owned-background-processes.md) |
| F-048 | [S-042 — Enforce least-privilege sandbox profiles](./042-least-privilege-sandbox-profiles.md) |
| F-049 | [S-042 — Enforce least-privilege sandbox profiles](./042-least-privilege-sandbox-profiles.md) |
| F-050 | [S-020 — Replace Bash auto-approval heuristics](./020-bash-effect-classification.md) |
| F-051 | [S-084 — Turn cron metadata into a scheduler service](./084-cron-scheduler-service.md) |
| F-052 | [S-016 — Require effect classification for every tool](./016-mandatory-tool-effect-classification.md) |
| F-053 | [S-068 — Create a stateful workspace LSP service](./068-stateful-lsp-service.md) |
| F-054 | [S-069 — Bound and validate LSP JSON-RPC](./069-bounded-lsp-jsonrpc.md) |
| F-055 | [S-068 — Create a stateful workspace LSP service](./068-stateful-lsp-service.md) |
| F-056 | [S-070 — Implement named remote actions safely](./070-named-remote-action-runtime.md) |
| F-057 | [S-052 — Consolidate task and planning state](./052-canonical-task-graph.md) |
| F-058 | [S-013 — Implement real progressive tool discovery](./013-progressive-tool-catalog.md) |
| F-059 | [S-072 — Supervise browser and web work](./072-supervised-browser-and-web-cancellation.md) |
| F-060 | [S-073 — Make worktree apply and cleanup transactional](./073-transactional-worktree-apply.md) |
| F-061 | [S-074 — Bind isolated workspaces to run capabilities](./074-workspace-capability-binding.md) |
| F-062 | [S-051 — Unify token, turn, cost, retry, and concurrency budgets](./051-token-turn-and-cost-budgets.md) |
| F-063 | [S-053 — Give memory stable identity and merge semantics](./053-memory-record-identity-and-merge.md) |
| F-064 | [S-014 — Make behavioral modes enforce capabilities](./014-runtime-enforced-behavioral-modes.md) |
| F-065 | [S-052 — Consolidate task and planning state](./052-canonical-task-graph.md) |
| F-066 | [S-051 — Unify token, turn, cost, retry, and concurrency budgets](./051-token-turn-and-cost-budgets.md) |
| F-067 | [S-037 — Make session mutation and finalization atomic](./037-atomic-session-finalization.md) |
| F-068 | [S-017 — Fix deny precedence and approval scope](./017-deny-precedence-and-approval-receipts.md) |
| F-069 | [S-037 — Make session mutation and finalization atomic](./037-atomic-session-finalization.md) |
| F-070 | [S-038 — Repair session schema migration and ownership](./038-session-schema-migration-and-ownership.md) |
| F-071 | [S-038 — Repair session schema migration and ownership](./038-session-schema-migration-and-ownership.md) |
| F-072 | [S-039 — Bind resume and branches to causal state](./039-causal-resume-and-branch-identity.md) |
| F-073 | [S-054 — Make memory untrusted, versioned evidence](./054-memory-authority-and-schema.md) |
| F-074 | [S-054 — Make memory untrusted, versioned evidence](./054-memory-authority-and-schema.md) |
| F-075 | [S-053 — Give memory stable identity and merge semantics](./053-memory-record-identity-and-merge.md) |
| F-076 | [S-055 — Rebuild automatic learning around causal evidence](./055-evidence-bound-automatic-learning.md) |
| F-077 | [S-057 — Replace lossy compaction with causal checkpoints](./057-causal-compaction-checkpoints.md) |
| F-078 | [S-057 — Replace lossy compaction with causal checkpoints](./057-causal-compaction-checkpoints.md) |
| F-079 | [S-025 — Keep secrets typed and redacted end to end](./025-end-to-end-secret-types-and-redaction.md) |
| F-080 | [S-026 — Stop mutating the shared Claude credential store](./026-claude-credential-store-read-only.md) |
| F-081 | [S-027 — Replace Anthropic client impersonation](./027-supported-anthropic-authentication.md) |
| F-082 | [S-028 — Verify Codex account and compliance metadata](./028-verified-codex-auth-metadata.md) |
| F-083 | [S-031 — Build descriptor-safe persistent storage](./031-descriptor-safe-persistence.md) |
| F-084 | [S-021 — Make blast-radius guardrails atomic and run scoped](./021-run-scoped-blast-radius-guardrails.md) |
| F-085 | [S-022 — Enforce diff blocks and quality gates](./022-diff-and-quality-completion-gates.md) |
| F-086 | [S-058 — Require explicit trust for hook imports](./058-explicit-hook-import-trust.md) |
| F-087 | [S-059 — Unify the hook lifecycle across frontends](./059-canonical-hook-lifecycle.md) |
| F-088 | [S-060 — Sandbox and budget hook execution](./060-hook-execution-admission.md) |
| F-089 | [S-081 — Use one real keybinding engine](./081-single-real-keybinding-engine.md) |
| F-090 | [S-064 — Complete MCP dynamic tool dispatch and allowlists](./064-mcp-dynamic-tool-dispatch-and-policy.md) |
| F-091 | [S-065 — Implement the current MCP protocol adapter](./065-mcp-current-protocol-adapter.md) |
| F-092 | [S-066 — Own and bound MCP transports](./066-mcp-owned-bounded-transports.md) |
| F-093 | [S-067 — Complete MCP OAuth, elicitation, and in-process semantics](./067-mcp-oauth-elicitation-inprocess.md) |
| F-094 | [S-056 — Complete the memdir lifecycle](./056-operational-memdir-lifecycle.md) |
| F-095 | [S-029 — Implement a complete OAuth session lifecycle](./029-oauth-session-lifecycle.md) |
| F-096 | [S-050 — Make provider terminal outcomes truthful](./050-provider-terminal-outcome-state.md) |
| F-097 | [S-061 — Bind plugin identity and discovery to trusted scope](./061-plugin-identity-and-bounded-discovery.md) |
| F-098 | [S-062 — Make plugin install and update verifiable transactions](./062-plugin-supply-chain-transactions.md) |
| F-099 | [S-062 — Make plugin install and update verifiable transactions](./062-plugin-supply-chain-transactions.md) |
| F-100 | [S-063 — Activate plugin capabilities through canonical registries](./063-plugin-capability-activation.md) |
| F-101 | [S-061 — Bind plugin identity and discovery to trusted scope](./061-plugin-identity-and-bounded-discovery.md) |
| F-102 | [S-071 — Enforce web policy at the connection boundary](./071-web-egress-connection-broker.md) |
| F-103 | [S-072 — Supervise browser and web work](./072-supervised-browser-and-web-cancellation.md) |
| F-104 | [S-085 — Implement or remove speculation by measurement](./085-speculation-transaction.md) |
| F-105 | [S-075 — Create one typed command registry](./075-typed-command-registry.md) |
| F-106 | [S-083 — Make terminal rendering bounded and inert](./083-safe-terminal-rendering.md) |
| F-107 | [S-076 — Make project initialization transactional](./076-transactional-project-initialization.md) |
| F-108 | [S-006 — Rebuild doctor as evidence-safe diagnostics](./006-safe-doctor-health-contract.md) |
| F-109 | [S-078 — Move print mode onto the canonical runtime](./078-bounded-print-mode-adapter.md) |
| F-110 | [S-077 — Bind Git review and commit to exact generations](./077-generation-bound-git-review-commit.md) |
| F-111 | [S-030 — Make interactive API-key setup secret safe](./030-safe-interactive-api-key-setup.md) |
| F-112 | [S-043 — Route direct shell through the process capability](./043-unify-direct-shell-execution.md) |
| F-113 | [S-079 — Route legacy attachments and editor input through capabilities](./079-legacy-attachments-and-editor-capabilities.md) |
| F-114 | [S-080 — Make plan approval an atomic capability transition](./080-atomic-plan-approval.md) |
| F-115 | [S-081 — Use one real keybinding engine](./081-single-real-keybinding-engine.md) |
| F-116 | [S-082 — Give private notes and side questions correct semantics](./082-private-notes-and-side-questions.md) |
| F-117 | [S-039 — Bind resume and branches to causal state](./039-causal-resume-and-branch-identity.md) |
| F-118 | [S-049 — Separate reasoning continuation from display](./049-reasoning-state-privacy.md) |
| F-119 | [S-014 — Make behavioral modes enforce capabilities](./014-runtime-enforced-behavioral-modes.md) |
| F-120 | [S-086 — Implement rotating planner checkpoints](./086-rotating-planner-checkpoints.md) |
| F-121 | [S-011 — Preserve typed tool results end to end](./011-canonical-typed-tool-results.md) |
| F-122 | [S-087 — Create fresh workers for semantic task slices](./087-fresh-worker-slice-lifecycle.md) |
| F-123 | [S-089 — Isolate ACP sessions and calls](./089-acp-session-isolation.md) |
| F-124 | [S-090 — Bound and validate ACP transport](./090-bounded-acp-transport.md) |
| F-125 | [S-091 — Make ACP modes and advertised tools effective](./091-acp-effective-capabilities.md) |
| F-126 | [S-092 — Authenticate proxy callers before credential spend](./092-proxy-client-authentication.md) |
| F-127 | [S-093 — Isolate proxy tenant and session state](./093-proxy-session-isolation.md) |
| F-128 | [S-094 — Route every proxy API through the canonical lifecycle](./094-proxy-canonical-lifecycle-routing.md) |
| F-129 | [S-095 — Fix proxy streaming and VDD delivery parity](./095-proxy-streaming-and-vdd-parity.md) |
| F-130 | [S-096 — Make TUI cancellation and shutdown real](./096-tui-run-cancellation-supervision.md) |
| F-131 | [S-097 — Contain TUI file attachments](./097-tui-attachment-containment.md) |
| F-132 | [S-098 — Make TUI provider switching and resume atomic](./098-atomic-tui-provider-resume.md) |
| F-133 | [S-083 — Make terminal rendering bounded and inert](./083-safe-terminal-rendering.md) |
| F-134 | [S-099 — Make VDD verdict parsing strict and fail closed](./099-vdd-strict-verdict-schema.md) |
| F-135 | [S-100 — Enforce VDD blocking at canonical finalization](./100-vdd-blocking-finalization-gate.md) |
| F-136 | [S-101 — Bound and validate VDD provider work](./101-vdd-bounded-provider-transport.md) |
| F-137 | [S-102 — Persist VDD evidence and issues transactionally](./102-vdd-transactional-evidence-and-issues.md) |
| F-138 | [S-064 — Complete MCP dynamic tool dispatch and allowlists](./064-mcp-dynamic-tool-dispatch-and-policy.md) |
| F-139 | [S-003 — Make fuzz targets side-effect free](./003-side-effect-free-fuzz-harnesses.md) |
| F-140 | [S-009 — Remove repository-owned control authority](./009-repository-instruction-and-hook-boundary.md) |
| F-141 | [S-002 — Enforce repository artifact and dependency hygiene](./002-repository-artifact-dependency-policy.md) |
| F-142 | [S-001 — Build the capability evidence registry](./001-capability-evidence-registry.md) |
| F-143 | [S-001 — Build the capability evidence registry](./001-capability-evidence-registry.md) |

## Workstream coverage

| Workstream | Contributing slices |
|---|---|
| W0 | [S-001](./001-capability-evidence-registry.md), [S-002](./002-repository-artifact-dependency-policy.md), [S-004](./004-startup-migrations-fail-closed.md), [S-006](./006-safe-doctor-health-contract.md), [S-038](./038-session-schema-migration-and-ownership.md) |
| W1 | [S-007](./007-remove-legacy-rule-injector.md), [S-009](./009-repository-instruction-and-hook-boundary.md), [S-076](./076-transactional-project-initialization.md) |
| W2 | [S-011](./011-canonical-typed-tool-results.md), [S-014](./014-runtime-enforced-behavioral-modes.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-017](./017-deny-precedence-and-approval-receipts.md), [S-018](./018-non-bypassable-host-safety-policy.md), [S-019](./019-explicit-session-capabilities.md), [S-020](./020-bash-effect-classification.md), [S-021](./021-run-scoped-blast-radius-guardrails.md), [S-022](./022-diff-and-quality-completion-gates.md), [S-063](./063-plugin-capability-activation.md), [S-064](./064-mcp-dynamic-tool-dispatch-and-policy.md), [S-077](./077-generation-bound-git-review-commit.md), [S-080](./080-atomic-plan-approval.md), [S-084](./084-cron-scheduler-service.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-091](./091-acp-effective-capabilities.md), [S-092](./092-proxy-client-authentication.md) |
| W3 | [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-026](./026-claude-credential-store-read-only.md), [S-027](./027-supported-anthropic-authentication.md), [S-028](./028-verified-codex-auth-metadata.md), [S-029](./029-oauth-session-lifecycle.md), [S-030](./030-safe-interactive-api-key-setup.md), [S-034](./034-typed-multimodal-and-partial-reads.md), [S-044](./044-provider-native-state-contract.md), [S-045](./045-openai-responses-continuation.md), [S-046](./046-gemini-ollama-tool-history.md), [S-047](./047-dynamic-model-capability-catalog.md), [S-048](./048-hardened-provider-http-transport.md), [S-049](./049-reasoning-state-privacy.md), [S-050](./050-provider-terminal-outcome-state.md), [S-067](./067-mcp-oauth-elicitation-inprocess.md), [S-078](./078-bounded-print-mode-adapter.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-092](./092-proxy-client-authentication.md), [S-093](./093-proxy-session-isolation.md), [S-094](./094-proxy-canonical-lifecycle-routing.md), [S-095](./095-proxy-streaming-and-vdd-parity.md), [S-098](./098-atomic-tui-provider-resume.md), [S-101](./101-vdd-bounded-provider-transport.md), [S-103](./103-authenticated-team-memory-authority.md) |
| W4 | [S-023](./023-reality-evidence-boundary.md), [S-024](./024-artifact-verification-invalidation.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-100](./100-vdd-blocking-finalization-gate.md), [S-105](./105-evaluated-technical-memory-retrieval.md) |
| W5 | [S-053](./053-memory-record-identity-and-merge.md), [S-054](./054-memory-authority-and-schema.md), [S-055](./055-evidence-bound-automatic-learning.md), [S-056](./056-operational-memdir-lifecycle.md), [S-057](./057-causal-compaction-checkpoints.md), [S-103](./103-authenticated-team-memory-authority.md), [S-104](./104-team-memory-replication-service.md), [S-105](./105-evaluated-technical-memory-retrieval.md) |
| W6 | [S-063](./063-plugin-capability-activation.md), [S-064](./064-mcp-dynamic-tool-dispatch-and-policy.md), [S-065](./065-mcp-current-protocol-adapter.md), [S-066](./066-mcp-owned-bounded-transports.md), [S-067](./067-mcp-oauth-elicitation-inprocess.md) |
| W7 | [S-085](./085-speculation-transaction.md) |
| W8 | [S-082](./082-private-notes-and-side-questions.md), [S-086](./086-rotating-planner-checkpoints.md), [S-087](./087-fresh-worker-slice-lifecycle.md) |
| W9 | [S-012](./012-runtime-feature-reachability.md) |
| W10 | [S-041](./041-owned-background-processes.md), [S-051](./051-token-turn-and-cost-budgets.md), [S-057](./057-causal-compaction-checkpoints.md), [S-060](./060-hook-execution-admission.md), [S-066](./066-mcp-owned-bounded-transports.md), [S-069](./069-bounded-lsp-jsonrpc.md), [S-072](./072-supervised-browser-and-web-cancellation.md), [S-078](./078-bounded-print-mode-adapter.md), [S-084](./084-cron-scheduler-service.md), [S-087](./087-fresh-worker-slice-lifecycle.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-090](./090-bounded-acp-transport.md), [S-096](./096-tui-run-cancellation-supervision.md), [S-101](./101-vdd-bounded-provider-transport.md), [S-104](./104-team-memory-replication-service.md), [S-105](./105-evaluated-technical-memory-retrieval.md) |
| W11 | [S-013](./013-progressive-tool-catalog.md), [S-064](./064-mcp-dynamic-tool-dispatch-and-policy.md) |
| W12 | [S-008](./008-typed-context-authority-and-budget.md), [S-009](./009-repository-instruction-and-hook-boundary.md), [S-010](./010-canonical-run-context-and-events.md), [S-011](./011-canonical-typed-tool-results.md), [S-017](./017-deny-precedence-and-approval-receipts.md), [S-037](./037-atomic-session-finalization.md), [S-038](./038-session-schema-migration-and-ownership.md), [S-039](./039-causal-resume-and-branch-identity.md), [S-044](./044-provider-native-state-contract.md), [S-049](./049-reasoning-state-privacy.md), [S-050](./050-provider-terminal-outcome-state.md), [S-057](./057-causal-compaction-checkpoints.md), [S-059](./059-canonical-hook-lifecycle.md), [S-074](./074-workspace-capability-binding.md), [S-075](./075-typed-command-registry.md), [S-078](./078-bounded-print-mode-adapter.md), [S-079](./079-legacy-attachments-and-editor-capabilities.md), [S-080](./080-atomic-plan-approval.md), [S-081](./081-single-real-keybinding-engine.md), [S-082](./082-private-notes-and-side-questions.md), [S-083](./083-safe-terminal-rendering.md), [S-084](./084-cron-scheduler-service.md), [S-086](./086-rotating-planner-checkpoints.md), [S-087](./087-fresh-worker-slice-lifecycle.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-089](./089-acp-session-isolation.md), [S-090](./090-bounded-acp-transport.md), [S-093](./093-proxy-session-isolation.md), [S-094](./094-proxy-canonical-lifecycle-routing.md), [S-095](./095-proxy-streaming-and-vdd-parity.md), [S-096](./096-tui-run-cancellation-supervision.md), [S-097](./097-tui-attachment-containment.md), [S-098](./098-atomic-tui-provider-resume.md), [S-100](./100-vdd-blocking-finalization-gate.md) |
| W13 | [S-001](./001-capability-evidence-registry.md), [S-002](./002-repository-artifact-dependency-policy.md), [S-003](./003-side-effect-free-fuzz-harnesses.md), [S-004](./004-startup-migrations-fail-closed.md), [S-006](./006-safe-doctor-health-contract.md), [S-012](./012-runtime-feature-reachability.md) |
| W14 | [S-005](./005-typed-environment-config-loading.md), [S-018](./018-non-bypassable-host-safety-policy.md), [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-030](./030-safe-interactive-api-key-setup.md), [S-076](./076-transactional-project-initialization.md) |
| W15 | [S-004](./004-startup-migrations-fail-closed.md), [S-019](./019-explicit-session-capabilities.md), [S-024](./024-artifact-verification-invalidation.md), [S-026](./026-claude-credential-store-read-only.md), [S-029](./029-oauth-session-lifecycle.md), [S-030](./030-safe-interactive-api-key-setup.md), [S-031](./031-descriptor-safe-persistence.md), [S-032](./032-snapshot-bound-file-edits.md), [S-033](./033-bounded-file-discovery-and-grep.md), [S-034](./034-typed-multimodal-and-partial-reads.md), [S-035](./035-transactional-notebook-editing.md), [S-036](./036-cross-platform-secure-files.md), [S-037](./037-atomic-session-finalization.md), [S-038](./038-session-schema-migration-and-ownership.md), [S-039](./039-causal-resume-and-branch-identity.md), [S-054](./054-memory-authority-and-schema.md), [S-062](./062-plugin-supply-chain-transactions.md), [S-067](./067-mcp-oauth-elicitation-inprocess.md), [S-073](./073-transactional-worktree-apply.md), [S-074](./074-workspace-capability-binding.md), [S-076](./076-transactional-project-initialization.md), [S-077](./077-generation-bound-git-review-commit.md), [S-079](./079-legacy-attachments-and-editor-capabilities.md), [S-084](./084-cron-scheduler-service.md), [S-097](./097-tui-attachment-containment.md), [S-102](./102-vdd-transactional-evidence-and-issues.md), [S-104](./104-team-memory-replication-service.md) |
| W16 | [S-015](./015-skills-trust-and-capabilities.md), [S-063](./063-plugin-capability-activation.md) |
| W17 | [S-008](./008-typed-context-authority-and-budget.md), [S-014](./014-runtime-enforced-behavioral-modes.md), [S-080](./080-atomic-plan-approval.md), [S-091](./091-acp-effective-capabilities.md) |
| W18 | [S-020](./020-bash-effect-classification.md), [S-023](./023-reality-evidence-boundary.md), [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-040](./040-supervised-foreground-process-io.md), [S-041](./041-owned-background-processes.md), [S-042](./042-least-privilege-sandbox-profiles.md), [S-043](./043-unify-direct-shell-execution.md), [S-060](./060-hook-execution-admission.md), [S-066](./066-mcp-owned-bounded-transports.md), [S-068](./068-stateful-lsp-service.md), [S-069](./069-bounded-lsp-jsonrpc.md), [S-072](./072-supervised-browser-and-web-cancellation.md), [S-073](./073-transactional-worktree-apply.md), [S-077](./077-generation-bound-git-review-commit.md), [S-079](./079-legacy-attachments-and-editor-capabilities.md), [S-084](./084-cron-scheduler-service.md) |
| W19 | [S-084](./084-cron-scheduler-service.md) |
| W20 | [S-016](./016-mandatory-tool-effect-classification.md), [S-052](./052-canonical-task-graph.md), [S-086](./086-rotating-planner-checkpoints.md), [S-102](./102-vdd-transactional-evidence-and-issues.md) |
| W21 | [S-063](./063-plugin-capability-activation.md), [S-068](./068-stateful-lsp-service.md), [S-069](./069-bounded-lsp-jsonrpc.md) |
| W22 | [S-070](./070-named-remote-action-runtime.md) |
| W23 | [S-071](./071-web-egress-connection-broker.md), [S-072](./072-supervised-browser-and-web-cancellation.md) |
| W24 | [S-073](./073-transactional-worktree-apply.md), [S-074](./074-workspace-capability-binding.md), [S-077](./077-generation-bound-git-review-commit.md), [S-087](./087-fresh-worker-slice-lifecycle.md) |
| W25 | [S-008](./008-typed-context-authority-and-budget.md), [S-009](./009-repository-instruction-and-hook-boundary.md), [S-058](./058-explicit-hook-import-trust.md), [S-059](./059-canonical-hook-lifecycle.md), [S-060](./060-hook-execution-admission.md), [S-063](./063-plugin-capability-activation.md), [S-076](./076-transactional-project-initialization.md) |
| W26 | [S-061](./061-plugin-identity-and-bounded-discovery.md), [S-062](./062-plugin-supply-chain-transactions.md), [S-063](./063-plugin-capability-activation.md) |
| W27 | [S-092](./092-proxy-client-authentication.md), [S-093](./093-proxy-session-isolation.md), [S-094](./094-proxy-canonical-lifecycle-routing.md), [S-095](./095-proxy-streaming-and-vdd-parity.md) |
| W28 | [S-022](./022-diff-and-quality-completion-gates.md), [S-024](./024-artifact-verification-invalidation.md), [S-088](./088-canonical-vdd-verifier-role.md), [S-095](./095-proxy-streaming-and-vdd-parity.md), [S-099](./099-vdd-strict-verdict-schema.md), [S-100](./100-vdd-blocking-finalization-gate.md), [S-101](./101-vdd-bounded-provider-transport.md), [S-102](./102-vdd-transactional-evidence-and-issues.md) |

## Backlog integrity

The validation contract for this folder is:

- slice IDs are unique and contiguous from S-001 through S-102;
- every dependency resolves and the dependency graph is acyclic;
- every F-001 through F-143 has exactly one primary slice;
- every W0 through W28 has at least one contributing slice;
- every relative Markdown link resolves;
- all slice files remain Small or Medium and retain explicit acceptance criteria.

Changing ownership, dependencies, or slice count requires rerunning these checks and updating this index in the same change.

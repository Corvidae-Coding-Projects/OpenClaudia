# OpenClaudia Production Remediation Design

Status: Complete audit-derived implementation design; update when remediation evidence changes
Owner intent: Repair and prove intended capabilities. Do not remove a capability merely because its current implementation is incomplete.
Companion evidence: `docs/full-codebase-audit-2026-08-16.md`

## 1. Purpose

OpenClaudia has repeatedly accumulated implementations that were described as
production-ready before their end-to-end wiring was demonstrated. This design
defines how to turn those intended features into operational, testable product
capabilities while reducing only mechanisms that are obsolete, unsafe, or
contrary to current agent-system engineering practice.

This document is a design and implementation plan. The current audit does not
authorize runtime code changes. Findings and affected files will be added as
the file-by-file audit progresses.

## 2. Non-negotiable principles

1. **Preserve product intent.** An incomplete memory, MCP, coordination,
   speculation, grounding, or service feature is a repair target unless the
   capability itself has no defensible user value.
2. **Remove mechanisms, not promised outcomes.** Duplicate loops, fail-open
   compatibility APIs, obsolete prompt injection, and unused abstraction
   layers may be removed after the canonical replacement preserves the useful
   behavior.
3. **No production claim without evidence.** A feature is production-ready
   only when it has a reachable entrypoint, an end-to-end success test, failure
   and cancellation tests, permissions and resource limits, observability, and
   representative task evals.
4. **One policy path.** Provider requests, model turns, tool calls, approvals,
   hooks, ledger observations, budgets, and trace events must not be
   independently reimplemented by each frontend.
5. **Fail closed at authority boundaries.** A missing tool risk
   classification, missing permission manager, malformed capability, or
   unavailable sandbox is a denial, not an implicit allow.
6. **Treat context as data with provenance.** Untrusted tool, web, MCP,
   repository, and remembered content must not gain system/developer authority
   merely by being interpolated into a prompt.
7. **Prefer progressive disclosure.** Load only the instructions, tools, and
   context needed for the current task. Measure quality before and after every
   prompt reduction.
8. **Make limits explicit.** Every agent loop has typed turn, tool, token,
   elapsed-time, cost, concurrency, retry, and cancellation budgets.
9. **Frontends are adapters.** TUI, legacy REPL, ACP, print mode, proxy mode,
   and subagents render and transport events; they do not own competing agent
   semantics.
10. **Documentation is an assertion surface.** Capability tables and README
    claims are tested against runtime behavior or labeled experimental.

### 2.1 Current external engineering baseline

The design is source-driven, but it is checked against current primary
standards and maintained runtime guidance as of the audit date:

- The current OpenAI Agents SDK centers one runner-managed agent loop with
  typed tools, per-tool input/output guardrails, human approval, sessions,
  tracing and evaluation. This supports—not dictates—the canonical W2/W12
  lifecycle and the requirement to check every invocation rather than only a
  workflow boundary ([Agents SDK overview](https://openai.github.io/openai-agents-python/),
  [tool guardrails](https://openai.github.io/openai-agents-python/guardrails/)).
- The current MCP `2026-07-28` specification is the interoperability baseline;
  older wire profiles are explicit compatibility adapters, not the core model
  ([MCP specification](https://modelcontextprotocol.io/specification/2026-07-28)).
- SLSA 1.2 provenance, TUF 1.0.33 update security and Sigstore's artifact-bound
  bundle format inform W26's plugin supply-chain design. OpenClaudia need not
  mandate those exact services, but it must provide equivalent artifact
  identity, signer policy, provenance, rollback/freeze resistance and verified
  update semantics ([SLSA 1.2](https://slsa.dev/spec/v1.2/),
  [TUF specification](https://theupdateframework.io/spec/),
  [Sigstore bundle format](https://docs.sigstore.dev/about/bundle/)).
- Reasoning data needs separate product and control-plane treatment. OpenAI's
  Responses protocol distinguishes reasoning summaries and encrypted/native
  continuation items, while current research finds chain-of-thought useful for
  narrowly scoped monitoring and explicitly distinguishes that from showing raw
  chains to users. W12 therefore preserves provider continuation and monitoring
  value without flattening either into the user transcript
  ([Responses streaming reasoning items](https://platform.openai.com/docs/api-reference/responses-streaming/response/refusal/delta),
  [reasoning visibility rationale](https://openai.com/index/learning-to-reason-with-llms/),
  [2026 monitorability research](https://openai.com/index/evaluating-chain-of-thought-monitorability/)).
- Current evaluation guidance distinguishes an agent's words from the actual
  end state it produced, preserves complete multi-turn tool traces, and repeats
  stochastic trials. OpenAI's July 2026 audit also shows why benchmark prompts,
  tests and reference outcomes need independent expert review instead of being
  accepted as self-validating evidence. W0/W13 therefore grade state and
  policy effects, retain redacted causal traces, run repeated trials, and audit
  the eval corpus itself
  ([Anthropic agent-eval guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents),
  [OpenAI coding-eval audit](https://openai.com/index/separating-signal-from-noise-coding-evaluations/)).
- Long-horizon agent security cannot be reduced to repeating a safety prompt.
  Current primary research tests cumulative intent hijacking, tool chaining,
  task injection, objective drift and memory poisoning, and reports that
  common one-shot defenses do not transfer reliably. W2/W5/W12/W23 therefore
  enforce typed authority at every effect boundary and include multi-turn
  adversarial evaluation
  ([AgentLAB preprint](https://arxiv.org/abs/2602.16901)).
- An emerging production-reliability benchmark evaluates repeated-run
  consistency, semantically equivalent task perturbations and injected tool/API
  failures rather than pass@1 alone. It is a useful test-design signal, not an
  established standard; W0 uses those dimensions without treating this single
  preprint as proof
  ([ReliabilityBench preprint](https://arxiv.org/abs/2601.06112)).
- Current trustworthy-agent guidance emphasizes human control, secure
  interactions, transparency and privacy as the autonomy loop grows longer.
  Those properties map directly to explicit approval receipts, inspectable
  traces, least-authority capabilities and non-authoritative retrieved context
  in W2/W4/W5/W12
  ([Anthropic trustworthy-agent guidance](https://www.anthropic.com/research/trustworthy-agents)).

These sources are comparison baselines, not evidence that OpenClaudia already
implements the properties. The repository findings and executable acceptance
tests remain the deciding evidence.

## 3. Definition of operational

A capability is operational only when all applicable rows are satisfied:

| Requirement | Required evidence |
|---|---|
| Reachability | A supported user/API entrypoint reaches the implementation without test-only construction |
| Success behavior | End-to-end test exercises the real orchestration path and verifies externally observable state |
| Failure behavior | Invalid input, provider failure, timeout, cancellation, and partial-state handling are tested |
| Security | Tool risk, permission, sandbox, trust provenance, secret handling, and prompt-injection exposure are documented and tested |
| Resource safety | Finite defaults or explicit operator opt-in for turns, tokens, cost, time, retries, and concurrency |
| State continuity | Resume, persistence, compaction, and provider-native continuation preserve required state |
| Observability | A redacted trace identifies model requests, tool calls, approvals, hooks, state changes, and terminal outcome |
| Evaluation | Representative multi-turn tasks measure final environment state, correctness, side effects, tool efficiency, latency, tokens, repeated-run consistency, equivalent-input robustness, injected failure recovery, adversarial behavior, and regressions; the dataset and graders are independently reviewed |
| Frontend parity | Supported entrypoints share semantics or explicitly document a deliberate limitation |
| Documentation | User-facing claim matches the tested capability and maturity level |

Unit tests for serialization, traits, helpers, or no-op implementations do not
by themselves satisfy this definition.

## 4. Target architecture

### 4.1 Canonical agent runtime

Introduce one asynchronous runtime with a narrow public surface:

```text
FrontendAdapter
    -> AgentRuntime::run(request, RunContext)
        -> ContextAssembler
        -> ProviderAdapter
        -> TurnController
        -> ToolExecutionPipeline
        -> StateStore / TraceSink
        -> FinalizationPolicy
    -> typed RuntimeEvent stream
```

`RunContext` carries concrete capabilities, not optional security objects or
booleans such as `permission_already_checked`. It includes session identity,
frontend capabilities, provider capabilities, workspace roots, permission
policy, sandbox, hooks, memory, MCP registry, budget, cancellation, and trace
sink.

The runtime owns the only agentic loop. Frontends may request different tool
sets and render different events, but they cannot bypass lifecycle stages.

### 4.2 Typed tool execution lifecycle

Every tool implements a required classification with no default:

```text
ToolRisk = ReadOnly | SessionMutation | WorkspaceMutation |
           NetworkRead | ExternalMutation | Destructive
```

The canonical lifecycle is:

1. Resolve registered tool and validate its schema.
2. Parse arguments into a typed value.
3. Resolve concrete capability target(s).
4. Enforce hard safety and enterprise policy.
5. Enforce mode and budget restrictions.
6. Run pre-tool hooks as data-producing policy extensions.
7. Request approval when risk and policy require it.
8. Execute through the sandbox/capability broker.
9. Record state mutation and authoritative observations.
10. Run post-tool hooks and emit a typed result event.

Unknown tools, missing classifications, missing capabilities, and malformed
targets deny. An explicit unrestricted policy remains possible, but it is a
concrete capability chosen by the host rather than a missing argument.

### 4.3 Provider-native conversation state

The canonical session stores provider-neutral messages plus provider-native
continuation items. Provider adapters own lossless conversion and declare a
capability descriptor for reasoning effort, native tools, parallel calls,
structured output, state continuation, caching, compaction, and usage fields.

For OpenAI Responses, the adapter must retain the response identifier and every
required output item, including encrypted reasoning or compaction items for
stateless operation. It must not flatten state into chat messages when that
loses provider semantics.

Static model catalogues are fallbacks, not truth. Capability negotiation and
unknown-cost handling replace model-name substring assumptions.

### 4.4 Context and authority model

Context items carry source and trust metadata:

```text
ContextItem {
  source: User | Project | Skill | Memory | Tool | Web | MCP | Hook,
  authority: Instruction | ReferenceData | Observation,
  sensitivity: Public | Workspace | Secret,
  freshness,
  token_cost,
  content
}
```

Only explicitly trusted configuration can become instructions. External and
retrieved material remains quoted/reference data. Structured extraction is
used before untrusted material can affect control flow or high-impact tools.
Escaping or wrapping content never changes its authority. Hook output is a
typed observation or policy result and cannot rewrite a user message or become
system guidance merely because a hook was configured. Any host-authorized
instruction extension is a distinct capability with provenance, limits,
redaction, and an auditable approval path.

Context assembly applies a deterministic token budget and priority policy.
Every inclusion, truncation, omission, and promotion is traceable. Working
directory metadata, memory, recent work, skill descriptions, and tool output
are structured data, not free-form system-prompt extensions. Tool descriptions
are generated from the same runtime registry that dispatches them.

### 4.5 Trace and evaluation system

Every run emits a redacted causal trace with stable identifiers for model
calls, output items, tool calls, approvals, hooks, state transitions,
compactions, handoffs, retries, and final outcome. Traces support deterministic
state assertions and rubric graders.

The initial evaluation corpus covers:

- repository exploration and code modification;
- correct and unnecessary tool use;
- approval and destructive-action behavior;
- indirect prompt injection through web, MCP, files, hooks, and memory;
- long-horizon context and compaction;
- cancellation, provider errors, and partial tool failure;
- resume and provider-native state continuity;
- subagent delegation, concurrency, and budget enforcement;
- parity across TUI, ACP, legacy REPL, and supported proxy modes;
- tokens, cost, latency, turns, retries, and task success.

### 4.6 Rotating planner, worker, and verifier runs

Long-running work uses disposable agent contexts over durable canonical state;
it does not preserve one ever-growing transcript as the agent's memory. The
runtime exposes three capability profiles over the same execution harness:

```text
Canonical AgentRuntime
    ├── Planner: decompose, schedule, reconcile, escalate
    ├── Worker: execute one bounded semantic task slice
    └── VDD Verifier: independently inspect and test an exact artifact
```

The planner compiles the immutable user objective and amendments into W20's
versioned task graph. Its runtime capabilities permit planning, delegation,
evidence inspection and user escalation, but not direct workspace, process,
network or external mutation. Each ready semantic slice receives a fresh worker
run containing only the objective/constraints relevant to that slice, selected
source evidence, exact workspace/artifact generation, explicit capabilities and
budgets, dependencies, and executable acceptance criteria. Do not create a
worker for every mechanical operation: slicing is used where the task has a
coherent deliverable and verification boundary.

Workers return typed artifacts, changed-state receipts, evidence, validation
results, uncertainties, blockers and proposed follow-up tasks. Their full
transcripts are retained only according to trace/privacy policy and are not
concatenated into planner context. Worker text cannot close a task or become
system authority; the task graph records a proposed result tied to exact run,
artifact and capability generations.

Planner continuity comes from a durable causally closed checkpoint containing
the immutable objective, task DAG and attempts, accepted decisions and their
sources, unresolved contradictions, artifact identities, approvals, evidence,
budgets and owned child handles. A successor planner reconstructs a bounded
projection from that state and validates its generation before acquiring the
lease. It does not trust a predecessor-authored prose autobiography. Rotation
occurs at phase/checkpoint boundaries and configured context pressure, and may
also be triggered by tool-result volume, decision/source drift, repeated fact
retrieval or detected contradictions. Replacement must adopt or cancel every
live child explicitly and cannot inherit approvals, secrets or broader
capabilities merely by inheriting the task.

Every proposed slice result is checked first by deterministic acceptance gates
and then, where policy requires, by a fresh VDD verifier run. VDD uses the same
canonical provider adapters, typed tool lifecycle, hard guardrails, evidence/
Reality grounding, filesystem and process brokers, network/MCP policy, budgets,
cancellation, traces and terminal-state rules as other agents. “Same harness”
does not mean the same transcript or authority: VDD has a separate run/context,
an enforced alternate endpoint/model-family identity, independent budgets and
a stricter normally read-only capability profile. It may run bounded tests and
analysis in disposable scratch state, but cannot modify the reviewed artifact,
approve itself, publish, commit or mutate task completion.

The verifier receives the acceptance criteria, exact artifact/diff digest,
source snapshot, deterministic receipts and worker uncertainties. Worker claims
enter the grounding/evidence graph only as provisional observations. VDD emits
a typed `pass`, `fail`, `inconclusive` or `verifier_error` receipt with checked
citations and the exact generations reviewed. Parse failure, timeout,
truncation, unavailable alternate model, model-identity ambiguity or later
artifact mutation cannot become a pass. Routing enforces real model/endpoint
separation and never silently falls back to the worker model.

Slice verification is followed by integration verification over the assembled
artifact and global acceptance criteria, because locally correct slices can
still conflict. Cross-model review reduces self-confirmation but does not make
the shared harness independent; high-risk gates therefore combine VDD with
compiler/test/CI/static-analysis receipts and independently implemented digest
checks. Evaluation compares this rotating hierarchy with a canonical
single-agent baseline for task success, global coherence, handoff loss,
repeated discovery, security, latency, tokens and cost.

## 5. Required remediation workstreams

### W0. Establish an evidence baseline

- Finish the file-by-file audit and runtime reachability map.
- Convert capability claims into executable acceptance scenarios.
- Establish trace schema and a representative evaluation dataset.
- Replace frontend-local raw JSONL with a canonical run/call trace whose events
  carry schema, actor, workspace, policy, capability, and causal generations.
  Store it in host-owned capability-safe storage with field-level sensitivity,
  redaction, bounded payloads, retention/export/deletion policy, integrity and
  crash-tail recovery; define an explicit fail-closed or degraded-mode response
  when mandatory security evidence cannot be durably recorded.
- Classify every feature as operational, partial, schema-only, unreachable, or
  intentionally experimental.
- Treat historical issue closure, implementation comments and passing test
  totals as claims to verify, never as release evidence. Export the tracked
  `.chainlink/issues.db` and stale session marker to a reviewable, redacted,
  immutable history before removing mutable runtime state from version control;
  retain a hash-addressed archive only under an explicit retention decision.
- Rebuild `doctor`/health reporting from these same executable assertions.
  Checks declare read/mutation/network/process/credential/cost effects and are
  non-mutating/offline by default. Active probes require explicit scoped
  capabilities, run through the canonical secret/egress/deadline path, inspect
  the real composition root, and return typed pass/fail/degraded/skipped
  evidence; constructed empty managers or local serialization tests are never
  presented as live health.

### W1. Remove the legacy rule injector completely

The project/rule injector is deprecated product behavior and is the one
capability explicitly selected for removal.

The implementation phase must:

1. Enumerate every discovery path, configuration key, environment variable,
   prompt insertion, file-extension matcher, hook payload, proxy injection,
   ACP injection, test, example, and user-facing claim related to rules.
2. Remove automatic loading and injection from every frontend and subagent.
3. Remove rule-specific context mutation and extension extraction that has no
   other security purpose.
4. Remove `.openclaudia/rules` and `.chainlink/rules` product support, migration
   shims, examples, and tests.
5. Preserve separately selected mechanisms—skills, explicit user
   instructions, tool schemas, permissions, and sandbox policy—without
   silently rebranding them as rules.
6. Add negative tests proving repository rule files cannot alter model context
   or tool authority.
7. Document the removal and a safe migration path to explicit skills or host
   configuration where appropriate.
8. Remove the equivalent automatic authority escalation from project
   `output-style.md`; retain output preferences only as user/host configuration
   or a visibly approved, scope-limited project capability.
9. Remove `.openclaudia/rules` creation, default/global/project rule templates,
   language-heuristic rule generation, `/init` rule behavior and startup tips.
   Preserve project detection only if the typed W14 scaffold has a measured use
   outside prompt instruction generation.
10. Delete `.claude/hooks/prompt-guard.py` and
    `.claude/hooks/pre-web-check.py`, their marker/state files, and the
    `UserPromptSubmit`/pre-Web activation entries in `.claude/settings.json`.
    Remove rule-hook examples from checked-in and generated configuration.
11. Replace `src/claude_code_prompt.txt` as part of W12—not because it is named
    a rule file, but because its inherited identity claims, tag conventions,
    stale tool mandates and prompt-only permission policy repeat the same unsafe
    authority model. The replacement is a small accurate host-owned policy;
    repository/hook/tool content remains typed untrusted context.

The audit will supply the exact deletion manifest. No rule-injector runtime
files are modified during this documentation-only pass.

Implementation follow-up (2026-08-16): W1 is implemented under
[S-007](remediation-slices/007-remove-legacy-rule-injector.md). Deterministic
gates and independent review pass; the slice remains queued for the canonical
alternate-model VDD receipt after S-088, so this note is not a claim that the
parent remediation program is verified or production-ready.

### W2. Canonicalize permissions and tool execution

- Replace default-safe classification with a mandatory `ToolRisk` declaration.
- Reclassify worktree, scheduling, process-control, task, memory, MCP, and
  external tools based on actual effects.
- Remove fail-open and stringly typed compatibility dispatch after all callers
  use the canonical pipeline.
- Make approval receipts scoped, single-use, auditable capabilities.
- Define precedence as host hard deny → current explicit deny → scoped approval
  capability → policy default. A persisted or earlier broad allow can never
  override a newer/more-specific denial.
- Bind approvals to normalized tool identity, arguments/resource scope, actor,
  workspace snapshot, expiry, and intended reuse. Never represent “always
  allow Bash” as a bare tool-name set.
- Replace `permission_already_checked` and every unchecked dispatcher with an
  unforgeable receipt bound to schema version, normalized arguments/effects/
  resources, call/run/actor/workspace, expiry, and permitted reuse. The
  executor consumes and records it atomically; an internal caller cannot create
  bypass authority with a Boolean.
- Move approval persistence to trusted user/host state with bounded schema,
  symlink-safe atomic writes, restrictive permissions, and redacted audit
  events. Repository config may request policy but cannot grant itself access.
- Conversation/session documents never contain executable approval, trust,
  bypass, sandbox, or persistence authority. Resume derives all capabilities
  anew from the current authenticated invocation and records prior decisions
  only as non-authoritative audit history.
- Replace target-string auto-allow scoring with evaluated typed policies over
  parsed operations. Unknown classifications and invalid thresholds fail
  closed; read access, data egress, mutation, scheduling, process control, and
  external side effects are distinct risks.
- Ensure MCP tools and resources pass through the same classification,
  approval, budget, trace, and prompt-injection controls.
- Wire configured MCP server/tool policy into that path before schemas become
  visible. Unknown, absent, typoed or renamed server/tool identities fail
  closed; the current isolated `mcp_tool_allowed` predicate is not an
  enforcement boundary and must not retain its absent-server allow-all default.
- Replace `PermissionTarget` with mandatory typed effect metadata covering
  resource identity, sensitive reads, mutation, external egress, process and
  schedule control, reversibility, destructive variants, and capability
  prerequisites. Registry construction fails on missing/duplicate/incoherent
  metadata.
- Construct the advertised registry per run from available capabilities.
  Unconfigured session, MCP, browser, LSP, memory, or scheduler tools are not
  sent merely to fail when called.
- Make dispatch asynchronous and cancellation/deadline aware. Tool handlers
  receive explicit filesystem/network/process/state capabilities instead of
  consulting process globals or treating a successful context construction as
  authorization.
- Make hook denial atomic across execution, prompt mutation, and context
  insertion. Remove arbitrary string-based system prefix/suffix APIs from
  untrusted callers, preserve multipart user messages, and prohibit raw prompt
  logging by default.
- Remove every optional-manager/unchecked public dispatch overload after
  callers migrate. One executor always evaluates non-bypassable host policy,
  then scoped approval policy, then executes the exact normalized operation
  covered by the decision.
- Return a typed `ToolExecutionResult` with data, errors, observations,
  attachments, control events, redaction/sensitivity, retryability, and usage.
  Control events are constructed by trusted handlers and can never be inferred
  by parsing arbitrary result text.
- Make this typed result the actual handler/registry/provider/frontend contract,
  not an executor-local type collapsed into `(String, bool)`. Preserve error
  sources, partial/truncation metadata, retry and recovery state across every
  adapter; remove legacy bridges only after round-trip tests prove every field
  survives.
- Model binary/media results as bounded typed attachments with verified format,
  dimensions/size, digest, sensitivity, and provider capability negotiation.
  Native adapter blocks carry supported images; base64 is transport encoding,
  never ordinary prompt prose.
- Bring subagent, plugin, MCP, memory, and control tools into the same registry
  and lifecycle. No special match arm or process-global adapter may bypass
  risk metadata, policy, hooks, budgets, trace, or cancellation.
- Replace process-global guardrails with run/workspace/policy-generation scoped
  effect and resource reservations. Compile every strict path/resource policy
  all-or-nothing against W15 canonical identities; invalid policy fails startup,
  and lexical aliases/traversal/symlinks cannot change the resolved target.
- Evaluate blast radius across every file/process/worktree/LSP/plugin/subagent/
  MCP/remote effect, not selected handler names. Reserve atomically before work,
  commit actual unique resources/effects after success and release failures;
  frontend loop boundaries never define security quota semantics.
- Compute diff/change policy from an exact versioned workspace snapshot and
  staged transaction. Implement `warn`, `block` and explicit findings as typed
  pre-commit/finalization outcomes with recovery; do not append post-write prose
  and call it enforcement.
- Treat quality verification as an approved deterministic tool effect bound to
  exact workspace, command, toolchain/config and output receipts. Honor the
  configured cadence/failure action or reject it, apply network/dependency/
  process budgets, and never infer verifier authority from arbitrary output or
  a zero exit status.

### W3. Repair provider adapters

- Preserve native OpenAI Responses output items and continuation state.
- Preserve Anthropic thinking/refusal blocks, Gemini thought signatures and
  interaction IDs, and every provider's native function-call/result linkage.
- Prove a complete model → tool → result → model round trip, parallel calls,
  cancellation, resume, and compaction for every supported adapter.
- Make reasoning effort and request parameters capability-driven.
- Audit Anthropic, Google, DeepSeek, Qwen, Z.ai, Kimi, MiniMax, Ollama, and
  OpenAI-compatible conversions for lossy history, tool-call, usage, and
  streaming behavior.
- Unify error, cancellation, retry, timeout, and partial-stream semantics.
- Parse provider streams into a bounded typed state machine and require the
  negotiated terminal event plus closed/validated tool structures before
  dispatch or history commit. Malformed events, transport EOF/error, timeout,
  cancellation, filtering and length limits remain distinct; partial output is
  recoverable evidence and never an ordinary successful assistant turn.
- Test every adapter against recorded protocol fixtures and live opt-in smoke
  tests.
- Replace large static model-name lists with authenticated discovery plus a
  small, versioned, provenance-labeled fallback.
- Use one hardened HTTP client policy for chat, streaming, model discovery,
  OAuth, and secondary-model calls; enforce deadlines, response limits,
  redirect/DNS destination checks, and cross-origin credential stripping.
- Represent API keys/tokens as non-`Debug`, zeroizing capabilities and construct
  redacting sensitive headers only at the transport edge. Sanitization precedes
  every error/log/trace sink; automated tests scan logs and failure paths for
  token/header/body disclosure.
- Use only documented provider-authorized OAuth/delegation flows registered to
  OpenClaudia. Do not reuse another client's ID or false identity system prompt
  to unlock subscription access. Treat Claude/Codex stores as bounded read-only
  compatibility inputs unless their owning application exposes a versioned
  transactional API; never overwrite a foreign partial schema.
- Source account, audience, scope, expiry and enterprise/FedRAMP routing from a
  verified issuer/provider response, not unsigned JWT payload bytes or
  unvalidated sidecar fields. Reject unknown auth schemas/modes and conflicts;
  isolate API-key, ChatGPT/Codex, enterprise and local-provider auth contracts.
- Make credential acquisition/refresh cancellable, deadlined and generation-
  safe without holding a blocking filesystem lock across network I/O. Use
  capability-safe owner/mode/link-checked storage, bounded reads/responses,
  idempotent refresh and explicit stale/unavailable/scope/relogin states.
- Credential setup uses non-echoing terminal/UI secret entry and writes a
  redacting, zeroizing secret to an OS keyring or host-owned restrictive store;
  typed configuration holds only its reference. Missing home/keyring never
  falls back to a project file. Updating that reference follows W14/W15 without
  truncating YAML, following links, losing unrelated data or exposing the value
  through process arguments, logs, panic/debug or terminal history.
- Replace the mislabeled pasted-code “device” flow with the exact registered
  provider grant. Pending state is expiring, count-bounded, single-use and bound
  to the initiating client; browser sessions use rotating server-set HttpOnly/
  Secure/SameSite credentials with explicit audience and revocation. Never
  return or log the bearer session value. Use single-flight proactive refresh,
  propagate rotation/logout to every live process and upstream, and remove dead
  `ApiKey`/`ProxyMode` branches only after the supported replacement migrates
  their intended users.

### W4. Complete the Reality Ledger or narrow its claim

The intended evidence-grounding capability is retained. It must become a
single enforced protocol rather than optional structured output beside an
unvalidated prose path.

- Define which actions and final claims require evidence.
- Replace the single “authoritative” Boolean with typed provenance, observation
  domain, trust/source, freshness/resource version, confidence, sensitivity,
  and claim applicability. User intent, untrusted external/tool content,
  command output, host policy, and trusted verification are not interchangeable.
- Hydrate evidence through aggregate source/read/result budgets and typed
  structured results. Stream or summarize only with traceable source IDs;
  never allocate an unbounded observation and then truncate its rendering.
- Treat ledger entries as trace records with provenance, not proof merely
  because an enum says `Tool`, `Filesystem`, or `Verifier`.
- Bind mutable observations and verification to exact workspace snapshot/diff
  digests; later relevant mutations invalidate derived verification.
- Require typed decisions in all supported agent loops, not only subagents.
- Prevent plain-text final responses from bypassing the finalization policy.
- Distinguish authoritative observations from untrusted text.
- Replace English keyword/path heuristics with typed claim-to-observation
  links and runtime-derived command/test outcomes.
- Define failure recovery when required evidence is unavailable.
- Measure whether ledger enforcement improves correctness enough to justify
  its context, I/O, and latency cost.

If an eval shows that a particular ledger mechanism harms quality, replace the
mechanism while preserving evidence-grounded outcomes; do not keep a placebo
gate for compatibility.

### W5. Complete memory as one coherent subsystem

- Wire configured team memory into actual memory tools and session startup.
- Give every memory a stable global logical ID and version independent of any
  physical database row. User overlays/tombstones bind the team/store/workspace
  identity and exact source version; merged retrieval has one global ranking/
  limit and explicit conflict semantics. Cross-store writes use durable
  idempotent operations with retry/reconciliation rather than pretending two
  SQLite commits are atomic.
- Treat team memory as an authenticated service/capability with membership,
  roles, audit, encryption and offline/concurrent conflict policy. A configured
  shared filesystem path alone is not an authorization or consistency model.
- Move private user/session memory to host-owned capability-safe storage. Treat
  repository, team, MCP, web, tool, model and imported memory as untrusted typed
  evidence with source/actor/workspace/generation, sensitivity, confidence basis,
  timestamps, retention and citations—never as system/developer instructions.
- Make capture policy explicit: user-approved preference facts, task/run outcomes
  and host observations have different schemas and trust. Support review,
  correction, contradiction/supersession, expiry, export/delete and tombstones;
  repeated text alone never raises truth confidence.
- Build a bounded retrieval pipeline (metadata filters plus evaluated lexical/
  semantic/task-conditioned retrieval, reranking, diversity and thresholding)
  that returns cited records under a context budget and distinguishes no-hit,
  partial, stale and store-error states. Evaluate recall, harmful-memory rate,
  task success, latency, tokens and cost against no-memory/simple baselines.
- Register typed memory read/write/update/delete operations through W2's normal
  permission/effect/runtime lifecycle. Do not advertise `memory_search` until it
  is actually callable in every supported frontend; compaction retains a host-
  resolvable archive reference rather than telling a model to use an absent tool.
- Wire `MEMORY.md` only if retained after trust/provenance review; loading
  remembered text must not grant it instruction authority.
- Define user/team precedence, tombstones, durability, privacy, deletion,
  corruption recovery, and concurrent access.
- Connect background consolidation through bounded jobs with explicit
  permissions, cancellation, traceability, and evals.
- Define semantic duplicate identity separately from equal text. Consolidation
  first produces a reviewable bounded plan, then transactionally merges tags,
  ownership, source, confidence, timestamps, retention, and provenance under
  expected versions with tombstones/recovery; it never calls deletion a merge
  or silently erases distinctions.
- Build subagent summaries from canonical completed task/run evidence with
  citations and source generations, not forgeable tags or concatenated tool
  prose. Refresh incrementally when evidence changes; bound/privacy-filter input
  and output and evaluate retrieval/task value against storing indexed sources.
- Unify duplicate memory and session-note representations.
- Ensure auto-learned preferences are attributable, reviewable, expirable, and
  removable rather than permanent system instructions.
- Rebuild auto-learning as a canonical consumer of typed W12 message/tool/run
  receipts, not a legacy-REPL callback. Store observations separately from
  inferred claims and bind exact call, artifact, workspace and generation IDs.
  A later successful command, generic edit error, co-edit, or imperative-shaped
  sentence is evidence—not proof of a resolution, coding rule, relationship or
  durable preference. Require explicit confirmation or a defined evidence gate,
  retain the cited source, and expose correction/contradiction/review/expiry.
- Run capture only after authorization and hook acceptance, on the original
  user-authored message rather than expanded repository text. Surface partial
  capture/store degradation in canonical session state and apply the same
  consent, privacy, retention and deletion policy across REPL, TUI and ACP.
- Parse typed compiler/tool diagnostics across complete bounded outputs rather
  than line-local English heuristics. Evaluate preference precision, causal
  resolution accuracy, retrieval usefulness, harmful-memory rate, latency and
  cost against no-learning and explicit-only baselines before enabling inferred
  durable learning by default.
- Fold `memdir` into this service instead of creating another memory truth. Load
  project/user memory only through bounded regular-file capabilities, retain
  source scope/trust/generation/truncation, and present task-relevant cited
  evidence rather than injecting the first file as privileged instructions.
  Implement one consented, cancellable session capture → extraction → review →
  consolidation lifecycle, or explicitly support safe manual import only; do
  not leave background-agent phases implied by a tested loader.

### W6. Complete MCP end to end

- Make the official `2026-07-28` protocol the current adapter: stateless
  self-describing requests, routing metadata, `server/discover`, deterministic
  cacheable catalogues and multi-round-trip `input_required` results. Keep only
  explicit, bounded older-version adapters with conformance fixtures; retire
  initialize/session, roots and server-initiated elicitation shapes only after
  their intended workspace/input capabilities have current replacements.
- Define one supported surface—dynamic tools, resources, typed content,
  structured output, schemas, annotations and optionally prompts—and preserve
  that information through provider conversion, trace and follow-up. Validate
  names, input/output schemas, pagination and result types with aggregate item,
  byte, event and time budgets.
- Register every live server generation in W2/W12's per-run registry. Wire
  discovery, progressive schema exposure, risk classification, invocation,
  permissions, partial availability, reconnection, cancellation and shutdown
  identically in proxy, TUI, ACP and any retained legacy frontend. Never
  advertise a schema without its exact authorized dispatcher.
- Give each server a supervised connection actor with bounded queues and no
  manager lock held over I/O. Cancellation must reconcile or replace protocol
  state; replacement/disconnect must close and reap; catalogue fan-out must
  return typed partial results. Remove release-built unchecked network paths and
  put HTTP/stdio/in-process transports behind W18/W22 capabilities.
- Replace the schema-only OAuth module with current protected-resource and
  authorization-server discovery, issuer/resource/audience binding, current
  client metadata, refresh/rotation/revocation and OS-protected persistence.
  Tokens, client secrets, codes and PKCE verifiers use redacting, non-Debug,
  zeroizing secret types. Bind MRTR input to an attributed, visible user consent
  interaction with schema validation, replay protection and cancellation.
- Make in-process servers obey the identical trust, policy, budget, typed-result,
  cancellation and revocation contract as external servers; remove the unused
  adapter if no measured first-party use remains after migration.
- Turn plugin declarations into validated versioned runtime registrations only
  after plugin trust/approval. Use redacting secret references rather than raw
  cloned env/header strings; bind each transport to W18/W22 process/network
  capabilities and reconcile load, reload, disable, and uninstall atomically.
- Apply trust provenance and indirect-prompt-injection defenses to MCP data.
- Add real server fixtures, official-version interoperability suites and an
  acceptance scenario for every frontend covering discovery → schema exposure →
  approval → dispatch → typed/MRTR result → model follow-up → cancellation →
  shutdown. Treat “connected” as a typed state, never as proof of this chain.

### W7. Complete speculation safely

- First measure the non-speculative latency distribution and identify exact
  operations whose critical-path delay is material. Do not create background
  work merely because a tool name can be guessed.
- Replace the unwired no-op/feedback trait before implementation. A speculation
  transaction binds run ID, prediction ID, typed tool/arguments, immutable
  workspace/provider/policy/budget generations, content inputs, confidence
  calibration, deadline/cancellation and a supervised result handle. Feedback
  compares a retained prior prediction with the later actual call; it never
  predicts after an outcome and labels that same outcome a hit.
- Allow only deterministic, idempotent, side-effect-free operations with an
  explicit speculative classification. Execute them in a read-only snapshot or
  disposable isolated overlay with no network, secrets, user-visible state,
  external effects or approval consumption. A normal tool's risk label cannot
  be downgraded by prediction confidence.
- Reserve W10 concurrency, CPU, memory, I/O, token/cost and time before start.
  Deduplicate equivalent predictions, cap context/argument/result bytes and
  cancel/join work on divergence, run cancellation or deadline. No global
  background worker outlives its owning run.
- Reuse requires exact canonical tool arguments, input artifact generations,
  policy/capability generation and a complete successful result receipt. Any
  mismatch, partial/error result, stale snapshot or nondeterminism discards the
  result; overlay promotion is an atomic validated transaction, never copied
  guessed state.
- Measure calibrated precision/recall, end-to-end latency benefit, cache overlap,
  hit/partial/miss rate, wasted CPU/I/O/tokens/cost, cancellation latency,
  correctness and side-effect isolation on representative tasks. Include a
  simpler demand cache/prefetch baseline.
- If safe speculation cannot beat the non-speculative baseline, remove the
  mechanism as contrary to simplicity and resource-efficiency best practice,
  while documenting that the intended latency benefit was not demonstrated.

### W8. Complete coordination and subagents

- Make one supported delegation mechanism; coordinator CLI behavior must reach
  the coordinator runtime rather than only changing a prompt profile.
- Implement the rotating hierarchy in Section 4.6. The coordinator is a
  planner capability profile, not a more privileged general worker: it may
  decompose, lease, schedule, inspect typed evidence and escalate to the user,
  but workspace/external mutation requires a bounded worker attempt. Create a
  fresh worker for each coherent semantic slice and require an explicit
  artifact/evidence handoff before the attempt can become terminal.
- Rotate planners through durable versioned checkpoints rather than transcript
  compaction. A successor validates the immutable user objective, accepted
  decisions, task/artifact/evidence generations, approvals, budgets and live
  child ownership before taking the coordinator lease. Tests must cover
  replacement during active, failed, cancelled and partially delivered work,
  including the absence of privilege/secret/approval inheritance.
- Use W20's versioned task graph and W12's run executor rather than maintaining
  another coordinator-only task truth. A supervised coordinator run actor owns
  typed child handles, immutable assignment/workspace/capability generations,
  atomic claim/lease/start/result transitions, joins and cleanup.
- Define ownership, worktree isolation, shared-state rules, dependency graphs,
  cancellation, result collection, nesting, retry/idempotency, leases,
  deadlines, resumability and failure propagation. A failed/cancelled
  dependency produces an explicit blocked/cancelled downstream state rather
  than a task that remains Pending forever.
- Represent every child as a new canonical attempt with a collision-resistant
  typed ID and immutable parent/task/role/model/workspace/capability generations.
  Resume reads a durable causally closed checkpoint including the terminal
  response, then atomically acquires a fresh lease; it never reuses terminal
  flags or silently changes a prior read-only role into a mutating capability
  set. Provider cache reuse is an optimization receipt, not a claim inferred
  from an in-process transcript key.
- Make worktree isolation an enforced capability boundary, not a path embedded
  in a prompt. Rebind the child's descriptor-rooted file APIs, subprocess cwd,
  sandbox and artifact identity to the owned worktree. Handoff classifies
  untracked, unstaged, staged, committed, conflicted and inspection-failed state
  and returns an explicit review/apply/discard operation; never force-remove a
  worktree or branch merely because `git diff` is empty.
- Route child tool requests through W2's exact permission receipts and W10's
  atomic budget reservations. One correlated user-interaction broker handles
  simultaneous approval/question requests with cancellation and fairness; it
  does not create a second raw-string “always allow” policy cache.
- Bound and source-label prompts, child outputs, errors, shell metadata and
  summaries. Results cite child run and artifact generations and cannot gain
  leader/system authority by concatenation. Unknown/lost processes reconcile
  to a typed orphaned state, never remain Running indefinitely.
- Persist one exact versioned coordinator/task/run state transactionally, or
  declare process-local operation honestly. Serializable leaf wrappers are not
  evidence of resumability.
- Permit parallelism only for independent work; serialize shared mutable work.
- Bound concurrency, depth, turns, tokens, time, retries, and total cost.
- Own every child future and descendant resource. Cancellation and every
  success/failure/timeout path stop and join provider requests, tools, shells,
  worktrees and maintenance tasks, then publish one typed terminal outcome.
  Transcript/checkpoint limits are causal byte/token/event budgets, not a raw
  message-count head drop that can split tool pairs or erase task authority.
- Prove read-only roles with runtime effect denials, not prompt prose, and test
  public finish/resume, crash/restart, collision, capability-escalation,
  cancellation and staged/untracked/committed artifact preservation paths.
- Prove task success and wall-clock benefit against a single-agent baseline.

### W9. Make lifecycle services real

- Decide whether `ServiceRegistry` is the actual composition root. If yes,
  construct it once and inject real analytics, feature flags, MCP registry,
  diagnostics, background jobs, and compaction services. If not, remove the
  unused registry abstraction after preserving each operational service.
- Replace no-op defaults in production construction with explicit disabled or
  configured states.
- Merge feature rollout into W14's declared typed configuration: unknown names
  are errors, effective values expose source/generation, environment decoding is
  non-panicking, and reload atomically publishes one immutable snapshot.
- Ensure background services start, stop, drain, and report failure cleanly.
- Give each job typed resources/effects, owner, interval/misfire/retry/backoff,
  deadline/cancellation/budget, idempotency and durable outcome. Use leases/
  fencing across processes, persist generations/last success, reconcile crashes,
  prevent duplicates/zero-interval spins, and never block the frontend tick.
- Plugin update/delisting jobs use current trusted marketplace state, verified
  manifests/signatures, staged rollback, approval policy, and honest outcomes;
  log-only snapshots never claim they polled or updated anything.
- Make analytics/telemetry an explicit privacy setting with documented fields,
  pseudonymous identities, redaction, retention/export/deletion, and opt-in/out
  behavior. Emit one canonical run trace across frontends; sinks are bounded,
  nonblocking, panic-isolated, and never rely on repository-local storage for
  private host telemetry.
- Give hooks a typed lifecycle contract: declared source and effects, timeout,
  cancellation, output and context limits, redacted trace events, and explicit
  failure semantics. Hook success is not evidence that its text is trusted.

### W10. Unify budgets and stop conditions

- One `RunBudget` covers turns, model tokens, total tokens, output tokens,
  tool calls, per-tool caps, cost, elapsed time, retries, subagents, and
  concurrency.
- Reserve the maximum permitted next-call spend before dispatch and clamp
  provider output limits to the remaining budget; post-call accounting alone
  is not a hard ceiling.
- Reservations are atomic across concurrent calls and carry call/run/policy-
  generation IDs. Commit actual usage, release unused capacity, persist/recover
  promised session limits, and fail closed on corrupt/poisoned budget state.
- The same semantics apply to all frontends; defaults and overrides are
  deliberate rather than hard-coded per path.
- A process deadline covers spawn, bounded stdin delivery, bounded concurrent
  output drainage, exit, descendant termination, and reap. Cancellation is a
  per-run generation token, not a global Boolean keyed by a reusable session
  name; child environments start cleared and receive only scoped grants.
- The same owned lifecycle covers HTTP, DNS, proxy, browser/renderer,
  `spawn_blocking`, secondary-model, MCP, and LSP work. Timeouts cancel and join
  underlying work (or return an explicit supervised handle); synchronous tool
  bridges never park an async executor and admission/concurrency are budgeted.
- Budget exhaustion emits one typed terminal reason and leaves resumable state.
- Cost is checked fixed-point accounting, never floating-point control state.
  A versioned manifest records currency, provider source, effective interval,
  account/region/service tier, cache semantics, and non-token billables; request
  receipts retain the exact manifest/tier and provider-reported usage used.
  Estimates are explicitly labeled and reconciled to billed/provider receipts;
  unknown pricing is canonical run state, not a thread-local Boolean.
- Include a context budget with reserved space for the user's request, current
  state, tool schemas, and provider output. Context selection must be stable,
  source-aware, and observable rather than silently dropping memory or letting
  hooks consume the window.
- Obtain or calibrate exact provider/model input accounting with source and
  effective-version metadata; never apply a previous call's actual count to a
  newly mutated request. Reserve the configured maximum output/reasoning budget
  and all provider wrappers before dispatch, then return a typed cannot-fit state
  rather than forwarding a request whose fit is unknown.
- Make compaction a versioned W12 transaction over causally linked message,
  task, tool, artifact and observation events. Selection must keep tool pairs and
  unresolved decisions closed, summaries cite exact source generations, and
  retained user/model/tool prose stays evidence rather than becoming system
  authority. Atomically commit checkpoint, archive, summary and watermark under
  one idempotency ID; rollback leaves no extracted-memory residue.
- Validate that the post-compaction request satisfies the exact target and
  provider message schema. If one pass is insufficient, iterate within an
  explicit budget or report partial/cannot-fit; do not define success as merely
  reducing a heuristic. Calibrate token estimation and evaluate factual,
  requirement, artifact-version and tool-causality retention plus downstream
  task success over repeated compactions and adversarial inputs.
- Expose one canonical compaction transition to proxy, REPL, TUI, ACP and
  subagents. Preserve hooks, partial compaction, archival and user-directed
  retention only through that path. Remove the duplicate legacy preview
  algorithm and unused compactor service/config surfaces after parity tests pass.

### W11. Implement real progressive tool discovery

- Stop sending the entire tool catalogue alongside a redundant prose catalogue.
- Bootstrap a small evaluated set and expose dynamic search over core, MCP,
  plugin, skill, and subagent tools through a trusted, versioned catalog filtered
  by run capabilities, configured integrations, provider support, and health.
- Keep catalog summaries separate from callable API definitions. Return
  machine-readable selections, not prompt-spliced pseudo-XML; a trusted runtime
  transition installs a bounded schema set on the next request or uses a
  provider-native mechanism. Ordinary result text never registers a tool.
- Return typed selection receipts with catalog generation, canonical namespace,
  schema hash, risk/effect summary, expiry, and explicit misses. Loading a
  schema is not approval; effects and arguments are revalidated at execution.
- Bound query bytes/tokens, requested names, duplicates, candidate work,
  definitions, aggregate schema bytes, and active tools. Resolve namespace
  collisions deterministically and report unavailable/degraded tools honestly.
- Give filesystem/tool discovery deterministic typed pagination with stable
  resource IDs/cursors and explicit completeness. Enforce result bytes,
  visits, time, depth, open handles, and context cost; never select a capped
  subset from nondeterministic enumeration order.
- Stream grep/search results directly into the global page/byte/time budget.
  Bound context and line size, merge overlapping ranges, stop before allocating
  discarded hits, and return structured skipped/truncated diagnostics.
- Use the same secure deterministic walker and ignore-policy engine for fuzzy
  file navigation. Bind indices to workspace generations, reject outside-root
  symlink traversal, handle non-UTF-8/Unicode safely, and return explicit stale/
  partial state rather than silently presenting a best-effort index as complete.
- Track selected tools, capabilities, catalog generations, and schema versions
  in the trace; cache only by catalog/capability generation.
- Compare lexical, semantic, task-conditioned, and curated discovery against
  the full-catalog baseline using needed-tool recall, false activation,
  invocation success, task quality, tokens, latency, and cost. Retain an
  evaluated full-catalog fallback for retrieval failures.

### W12. Consolidate session and frontend architecture

- Resolve the two public `Session` domains and establish one ownership model.
- Define a versioned canonical run/session record with call-correlated transcript
  events, provider-native continuation, task/plan references, workspace and
  capability generations, typed local failures, usage/cost receipts, VDD/review
  evidence, checkpoints, and explicit active/ending/ended/recovery states.
- Make agent contexts disposable views over that record. Planner, worker and
  verifier runs have separate context, role, model, budget, capability and lease
  identities while sharing canonical lifecycle semantics. A context projection
  is bounded, provenance-bearing and reproducible from committed state; neither
  raw child transcripts nor model-authored handoff summaries become durable
  authority.
- Implement atomic planner rotation and fresh-slice worker creation as normal
  run transitions. Rotation reconciles every owned child and pending approval,
  records the old terminal generation, validates the successor projection and
  then transfers the planner lease. Crashes between steps recover to one visible
  owner or an explicit orphaned state, never two active planners.
- Treat handoff as a typed, source-linked projection of committed state rather
  than a second Markdown source of truth. A continuation resolves the exact
  parent generation and evidence; local/provider failures never masquerade as
  assistant-authored transcript messages.
- Mutations validate a proposed snapshot, then atomically publish one monotonic
  generation with causal call/actor IDs. Panics or invariant failures retain the
  last committed generation; lossy notifications are merely wakeups and every
  subscriber reconciles an exact versioned snapshot.
- Replace generic JSON message vectors and pairwise undo with a typed append-only
  conversation/run event log supporting user, assistant, reasoning, tool call,
  tool result, attachment, local failure, compaction and rewind events. Derived
  provider views and UI projections cannot corrupt the canonical history.
- Move provider/tool/policy logic out of TUI, ACP, legacy REPL, proxy, and
  subagent controllers.
- Define one typed frontend-command registry for session, model, mode, export,
  edit, cancel, undo/redo, compaction, authentication, project/plugin/skill
  management, help and exit actions. Each descriptor owns canonical name,
  aliases, typed argument schema, effect/risk, required capabilities, frontend
  availability and help/documentation metadata. Construction atomically rejects
  duplicate names/aliases and unsupported combinations; the effective registry
  generates parsing, completion, help and capability assertions. Dynamic
  plugin/skill commands use a namespaced generation, never a bypass.
- Command parsing is pure: it returns a typed proposed action and never prints,
  mutates history/files/credentials or starts a process. W2/W12 authorizes and
  executes that action transactionally with budgets, cancellation and trace,
  then a frontend renders the typed result. Ambient CWD/environment/globals are
  replaced by explicit run capabilities. Authentication actions use W3 and do
  not mutate foreign credential stores.
- A validated contextual key resolver maps terminal events to these commands in
  every interactive frontend; it canonicalizes and collision-checks chords,
  defines exact/prefix precedence and bounded timeout/input replay, respects
  modal and permission states, and generates help from the effective map.
- Preserve the working Rustyline Vi mode and connect shared status/commands to
  its real key and buffer events. Keep only one modal implementation; replace
  Rustyline only after a candidate has complete Unicode/grapheme-safe parity.
  Remove the disconnected shadow parser after consolidation, and test actual
  keys, displayed state, configured chords, submission, cancellation and
  history end to end.
- Treat user attachments and questions as typed call-correlated events. File
  references resolve through W15 snapshots with source/sensitivity/encoding,
  per-file and aggregate byte/token limits and explicit truncation; repository
  bytes never gain user/system authority merely by string interpolation.
  Questions have stable IDs, schemas, typed answers, cancellation and replay
  protection instead of blocking global stdin or keying answers by display text.
- Store private notes outside provider-visible conversation state and require
  an explicit user choice before projecting one into context, always at user/
  evidence authority. Execute side questions as bounded child requests over an
  immutable parent snapshot and attach their result without reordering or
  silently teaching the parent session.
- Model branch/teleport/rewind as versioned operations over the typed event log,
  not generic project JSON message arrays. Branches bind parent generation,
  causal event IDs, workspace/capability generation, schema, provenance and
  digest; import remains untrusted until bounded validation/user review, and
  switching is one recoverable atomic transition.
- Make ACP a thin bounded transport over these same handles. Every wire request
  resolves a known session and exact call/generation; per-session transcript,
  provider continuation, model, mode, IDE snapshot, configuration, budget,
  cancellation and workspace authority never live in server-global mutable
  fields. Unknown IDs fail, `session/new` always creates independent state, and
  load restores that exact generation rather than manufacturing a blank child.
  Bind updates/cancel/config to call and session ownership and prove isolation
  with adversarially interleaved sessions.
- Keep three distinct reasoning views: opaque/encrypted provider continuation
  required for protocol correctness, explicitly provider-sanctioned summaries
  the user may view, and privacy-protected monitoring available only to a
  declared control plane. Do not persist/replay/reveal generic raw chain-of-
  thought as ordinary message text; define consent, access, encryption,
  retention/deletion and provider-specific round-trip behavior.
- One async run executor owns parse/normalize, hard policy, scoped approval,
  pre-hook, budget reservation, dispatch, cancellation, post-hook, typed
  observation/audit/ledger, analytics, and result/control delivery in a fixed
  tested order. Frontends submit requests; they do not assemble phases.
- The executor alone emits terminal completion after committing a typed final
  state. Iteration/budget exhaustion, hook/policy/final-gate block, partial
  provider stream, cancelled blocking work and frontend-channel loss cannot be
  translated into `ResponseDone` or a normal assistant-history entry.
- Frontend transports use bounded frames and queues with backpressure and
  explicit disconnect/write-failure state. ACP validates JSON-RPC version,
  request IDs and method schemas, caps stdin/SSE/history/tool/error/update bytes
  before allocation, requires a provider-native terminal event, and keeps
  streamed deltas provisional until commit. Cancellation stops and joins HTTP,
  stream, blocking tools and process descendants; a short wait followed by a
  detached worker is not cancellation.
- Give each interactive frontend a run-scoped supervisor and RAII terminal
  guard. Enabling raw mode, alternate screen, bracketed paste, a terminal reader,
  render tasks, or child operations registers an inverse action that runs on
  ordinary return, error, cancellation and panic. Repeated in-process launches
  create fresh shutdown generations rather than consulting sticky process
  state. Concurrent permission/question requests are call-correlated and queued
  or rejected explicitly; a singleton UI slot never drops a live reply channel.
- Frontend rendering consumes typed runtime events and never reparses ordinary
  model/tool text for diff, approval, question, plan or other control markers.
  Apply byte/line/compute limits before layout/diff allocation, sanitize ANSI/
  OSC and other terminal controls in untrusted fields, preserve an explicit raw
  data export path where useful, and surface renderer/channel failure as typed
  frontend state instead of silently discarding it.
- Virtualize long transcripts and make input/Markdown/layout Unicode grapheme-
  and terminal-cell-correct with bounded incremental work per frame. All
  terminal output, including legacy/print presentation, goes through one
  control-sequence policy. File/session/process I/O is admitted and bounded
  before allocation, runs off the render loop, and remains cancellable.
- Make provider-native structured tool calls the only normal execution control
  plane. A temporary compatibility adapter for a provider without structured
  calls must be an explicit reduced-assurance profile using a real strict
  parser/schema, typed allowlisted operations, complete-generation binding,
  one-call-at-a-time continuation and the identical W2/W10 lifecycle. Never
  scan/delete ordinary content by XML-like markers or embed forgeable
  `system_note` text. Retire the pseudo-XML interceptor after parity fixtures
  prove local tools work through supported typed adapters.
- Split large files at domain boundaries after the canonical runtime exists;
  do not perform cosmetic file splitting that preserves duplicated behavior.
- Publish and test an executable frontend capability matrix.
- Model noninteractive print mode as the same runtime with an explicit no-tools/
  no-persistence profile, not a direct provider implementation. Define stdout
  framing/backpressure and terminal status so automation can distinguish
  committed success from partial/refused/length/cancelled/protocol-failed output;
  bound response/error/event bytes and require the provider-native terminal
  event before a zero exit status.

### W13. Test, dependency, build, and documentation hygiene

- Consolidate hundreds of separately linked integration crates into coherent
  suites without losing meaningful coverage.
- Remove derive/Debug/Clone/tautological wrapper tests that do not protect a
  user-visible contract.
- Retain and strengthen security, state-machine, protocol, property, fuzz, and
  end-to-end tests.
- Prohibit fuzz harnesses from calling ambient filesystem, process, network,
  scheduler, task or database effects. Fuzz pure parsing/validation directly,
  or provide a disposable capability root plus deterministic fake transports
  and assert that no unmodeled host effect occurred.
- Give every fuzz target a stated semantic/state-machine invariant, finite
  resource limits, tracked seed corpus and minimized regression artifacts;
  no-panic-only coverage is supplemental rather than release evidence.
- Add browser-enabled and network interoperability CI lanes.
- Make CI reproducible and finite: use a declared MSRV/current toolchain
  matrix, `--locked`, job timeouts, pinned third-party actions, controlled
  system packages, and supported Linux/macOS/Windows capability assertions.
  Add dependency advisory/license/source policy, agent evals and provider
  protocol conformance without treating a compiler-only platform job as
  sandbox evidence.
- Put deterministic provider fault injection at the real HTTP/stream transport
  seam under test-support configuration. Cover provider-specific 429 bodies and
  headers, HTTP-date/malformed retry hints, retry/jitter/idempotency, concurrent
  requests, cancellation, budgets, and mid-stream failure; do not ship an
  unwired stateful mock as a nominal production service.
- Remove unused direct dependencies, define license policy, review copyleft
  build dependencies, and track unmaintained transitive crates.
- Generate user-facing capability documentation from tested feature metadata
  where practical.

### W14. Make configuration one typed, provenance-aware system

- Replace the independent main and ACP loaders with one schema, one source
  precedence order, one validation pass, and one diagnostic report.
- Track the provenance of every effective value: safe built-in, user/host,
  project, managed policy, environment, or explicit CLI argument.
- Define separate nesting and word separators for environment variables and
  test every documented field. Reject unknown YAML and environment keys.
- Host safety policy (permission bypass, sandbox weakening, external bind,
  trusted roots, secret locations) cannot be weakened by project-controlled
  configuration.
- Wrap all credential-bearing values, including custom headers, in redacting
  types and prohibit secret-bearing `Debug` output.
- Validate finite numeric ranges and coherent combinations before any
  subsystem starts; report disabled, invalid, and unsupported features
  distinctly.

### W15. Move persistent I/O behind filesystem capabilities

- Do not use lexical path checks as the security boundary. Resolve and create
  state beneath trusted directory handles without following symlinks.
- Use atomic writes, restrictive creation modes, bounded sizes, and explicit
  durability policy for sessions, memory, VDD, ledger, transcripts, and other
  agent state.
- Treat multi-file initialization as one versioned scaffold transaction. Build
  and validate in private same-filesystem staging, inventory every destination,
  refuse any collision by default, and require an explicit scoped force action
  with recoverable backups. Publish one generation or report an exact partial/
  recovery state; never delete the current config before a replacement is
  durable or overwrite sibling hook/plugin assets merely because config is
  absent.
- Migrations acquire a store-scoped lock/lease, snapshot the prior generation,
  dispatch exact source versions through bounded deterministic transforms,
  validate the complete target, and atomically publish target plus durable
  migration receipt. Required-store failure prevents that surface from opening;
  recovery/resume/rollback is explicit after failure or crash at every boundary.
- Version each OpenClaudia-owned artifact or transactional store manifest with
  producer/schema identity. Never stamp an uninspected shared directory or
  overwrite another producer's metadata to manufacture a migration baseline;
  foreign data is discovered/imported read-only under an explicit compatibility
  path.
- Transcripts are an append-only, causally sequenced typed run-event log with
  idempotency IDs, integrity links, sensitivity/redaction metadata and an atomic
  checkpoint. Resume validates identity, schema, continuity, tool-call/result
  relationships and compaction source generations; corruption produces an
  explicit partial/recovery state rather than silently skipping history.
- Test parent symlinks, races, replacement, cross-platform path casing,
  corruption, disk-full behavior, and concurrent writers against real I/O.
- Treat external-path opt-out as a host-granted directory capability, not an
  environment-variable exception to a string denylist.
- Construct `RunContext` capabilities exactly once at the explicit session
  boundary and pass them directly through async tasks and tool dispatch.
  Missing context, implicit default session, or a capability mismatch fails
  closed; process CWD and thread-locals never determine authority.
- Represent read-only project access without opening writable project handles.
  Detect the actual user-home/system breadth, distinguish sensitive reads from
  ordinary reads, and protect control paths using handle-relative policy.
- Keep environment grants in redacting/zeroizing secret values, expose only
  deliberately redacted diagnostics, and select the minimum variables for each
  child process. Create private state/temp directories with restrictive mode
  atomically.
- Bind every opened file/directory handle to the authorizing `RunContext` and
  its quotas; do not reconsult ambient session state during traversal. Use
  typed partial/error results and content-size ceilings.
- Implement a race-safe handle-relative Windows backend and test supported
  Unix fallbacks. If a platform/kernel lacks required primitives, fail a
  startup capability check and do not advertise file tools; publish the exact
  support matrix.
- Replace the global read tracker with per-run typed `FileSnapshot` records
  containing normalized resource identity, handle metadata/version, digest,
  observed range, sensitivity, and the exact bounded bytes returned. Writes
  require a matching current snapshot/precondition and emit a new version.
- Detect external/worktree/Bash mutations through version checks or workspace
  snapshot generations. Use one resource identity for permission receipts,
  read gates, diffs, ledger evidence, diagnostics, and UI paths.
- Apply writes through capability-bound snapshot preconditions and atomic
  replacement where platform semantics allow, preserving intended metadata and
  reporting durability. A failed/cancelled write must leave the old version
  intact or surface a typed recovery state.
- Distinguish unchanged failure, committed-and-durable success, published-but-
  durability-uncertain state and recovered reconciliation. A directory-fsync
  failure after rename is not an ordinary failure; callers must resolve the
  observed generation before retrying. Generic helpers take an explicit storage
  class/mode/bounds policy rather than applying secret-file permissions to every
  artifact.
- Represent targeted edits as typed patch operations. Reject degenerate
  matches, precompute occurrence/result limits, and return a bounded redacted
  diff object or durable observation reference—not magic markers containing
  complete old/new strings.
- Stream file reads by authorized byte/line range and expose resource version,
  returned range, EOF, encoding, truncation, and continuation cursor. Partial
  read must work for files above the full-read ceiling and for single very long
  lines without reading the whole file.
- Treat notebooks as validated, versioned documents over the same snapshot and
  atomic-write substrate. Make edit-mode arguments conditional; validate the
  supported nbformat and affected cell shapes; generate collision-checked
  stable IDs for modern notebooks; preserve compatible metadata; bound cells,
  embedded outputs, parsing, and serialization; and verify writes with real
  Jupyter round-trips plus failure/concurrency tests.

### W16. Finish skills as scoped capabilities

- Preserve explicit user skills and supported invocation from every frontend.
- Distinguish managed, user, and project sources. Project skills require a
  visible repository trust decision before any metadata or body reaches model
  context; source priority is deterministic and auditable.
- Validate package layout and schema, enforce canonical containment and size
  limits, reject ambiguous duplicates, and fingerprint actual content so
  in-place edits cannot leave stale instructions active.
- Either implement conditional `paths`, activation hooks, `when_to_use`, and
  argument hints end to end with tests, or revise the public schema and
  documentation through an explicit compatibility decision. Do not silently
  discard intended behavior.
- Apply model, effort, allowed-tool, and hook changes as scoped, reversible
  runtime capabilities. Skill text remains source-labeled context and cannot
  bypass permission, hook, budget, or prompt-authority boundaries.
- Return an explicit skill selection/context object; do not wrap Markdown in an
  XML string or splice tool output into system authority. Test real invocation
  through every supported frontend and provider with project-trust and budget
  boundaries active.

### W17. Make behavioral modes honest and enforceable

- Preserve agency, quality, scope, and modifier preferences, but declare which
  fields are style guidance and which alter host capabilities.
- Compile readonly and narrow-scope modes into the canonical permission,
  filesystem, and tool-registry policy. A prompt sentence is never the safety
  boundary.
- Plan mode uses operation/effect metadata, never a static name allowlist. Split
  mixed read/write facades or require an exact read-only variant; task/Crosslink
  mutation, egress, paid distillation, and user/external effects need separate
  scoped approval. Dynamic MCP/plugin opt-in selects reviewed concrete effects.
- Route director mode through the real coordinator with explicit delegation,
  concurrency, cost, and verification budgets. Route context pacing through
  actual context measurement, compaction, checkpoints, and resumable state.
- Define a compatibility/precedence matrix and reject contradictory modifier
  combinations rather than concatenating mutually inconsistent prose.
- Drive CLI tokens, persisted tokens, descriptions, prompt fragments, and
  capability effects from one tested registry. Evaluate representative tasks
  for each mode instead of relying on marker-presence tests.
- Represent plan enter/exit/proposal/edit/approve as typed run-state
  transitions bound to plan version and actor. Prompt suggestions never become
  approvals; only explicit scoped receipts change tool capabilities. Eliminate
  marker parsing and thread-local subagent gates.
- Route `/plan`, model tool requests, TUI actions, ACP and resume through that
  one transition. UI mode is derived from active plan/capability state, so no
  entrypoint can set a “Plan” label without installing the exact restrictions.
  Parse supported arguments or reject them; never silently discard intent.
- Apply the same rule to ACP's Initializer/Coding modes: configuration is bound
  to the named canonical session and atomically changes its catalog/effect
  generation. An Initializer label cannot reach Bash or mutation through a
  separate permissive dispatcher, and advertised options are generated from
  the capabilities execution will actually enforce.
- Represent the plan file as a capability-bound resource/snapshot with version
  and descriptor-safe write, not a serialized canonical path. Revalidate loaded
  state and bind enter/exit/approval to current run/plan generations. Approval
  cites the exact reviewed digest and atomically publishes plan state plus the
  requested scoped capabilities; plan prose remains source-labeled evidence,
  never a synthetic system instruction.

### W18. Rebuild subprocess execution around scoped process capabilities

- Preserve foreground shell, background jobs, hooks, quality gates, language
  servers, static analyzers, document parsing, MCP stdio, external editors, and
  worktree helpers, but compile a distinct least-privilege capability set for
  each invocation. Editors receive only a run-owned temporary/resource
  descriptor and sanitized environment with supervised cleanup/recovery.
- Keep Linux namespace/descriptor/seccomp containment. Default every profile to
  no filesystem, environment, network, IPC, or process authority, then grant
  only exact input/output descriptors, roots and write modes, redacted secrets,
  executable identity, syscall/IPC needs, and aggregate quotas.
- Shell string/path denylists are warning/defense-in-depth only. They never
  grant access. Replace first-program auto-allow with typed operation/effect
  analysis; unknown, compound, interpreter, VCS, build, package, and network
  effects require a scoped approval and remain bounded by the sandbox.
- Route the direct user `!` shell path through these same capabilities. User
  origin may change how an approval is presented, but it never bypasses hard
  host policy, sandboxing, resource bounds, cancellation, supervision, or
  audit. Classify the parsed/resolved operation and effective resources rather
  than case-sensitive substrings, and expose no public unchecked executor.
- Enforce protected and negative paths even when nonexistent. Eliminate
  scan-then-bind races and repeated full-project scans; bind capability
  generations or broker mutations through race-safe handles/overlays.
- Resolve trusted runtime binaries from host-managed absolute provenance and
  bind executable/version/digest to the trace. Project executables and build
  scripts are code execution, never read-only inspection.
- One async job supervisor owns spawn, bounded stdin/output, ordered events,
  deadlines, aggregate CPU/memory/process/file/I/O quotas, cancellation,
  termination, reap, durable cursor-based output, retention, resume, and
  session shutdown. Background jobs use collision-safe run-bound IDs.
- Ordinary shell output creates untrusted command observations. Only dedicated
  trusted quality-gate runners may issue Verifier evidence, bound to executable,
  arguments, workspace snapshot, unmasked status, bounded artifacts, and trace.
- Preflight the effective context/profile path actually used, and publish an
  honest platform/backend/functionality matrix. Explicit host opt-out remains a
  visible host decision and cannot be selected by project/model input.

### W19. Finish scheduling as durable, authorized agent runs

- Preserve create/list/delete and add update/pause/resume/run-now/history as a
  versioned schedule service. Project content may propose a schedule, but only
  a user/host approval can store an executable noninteractive grant.
- Define schedule type (cron versus one-shot), IANA timezone, DST behavior,
  next fire, expiry, misfire/catch-up, overlap/concurrency, retry/backoff,
  maximum runs, cancellation, and retention. Reject incoherent combinations.
- Bind every schedule to owner, trusted prompt/task spec, provider/model policy,
  exact allowed tools/resources/network/secrets, per-run and aggregate budgets,
  notification destination, and revocable approval receipt. Never persist a
  bare future prompt with ambient authority.
- Use trusted user/host storage through the capability-safe atomic persistence
  layer: bounded strict schema, restrictive permissions, symlink safety,
  cross-platform locking, directory durability, corruption recovery, and
  migrations. Repository schedule files are import/proposal data only.
- A scheduler service uses durable leases/fencing and idempotent run IDs so
  restarts or multiple processes cannot duplicate execution. It dispatches the
  canonical agent runtime and W18 sandbox, records exact scheduled/started/
  finished states, costs/effects/evidence, and redacted outputs atomically.
- Surface failures, skipped/missed runs, permission revocation, budget
  exhaustion, and delivery errors to the user. Test virtual-time DST/misfire
  behavior, crashes at every state transition, concurrent schedulers, retries,
  cancellation, malicious project prompts, and end-to-end result delivery.

### W20. Make structured task state a first-class agent capability

- Preserve Crosslink issue, comment, label, dependency, subissue, work-session,
  search, and recommendation workflows as externalized durable task state.
- Replace the shell-like argv facade with versioned typed operations and
  schemas. Declare exact read/mutation/workspace/session effects before policy;
  unknown operations fail closed and every mutation returns its typed changed
  record/version.
- Bind task stores and work sessions to canonical workspace and actor/run IDs.
  Define deliberate sharing/delegation rules so subagents can coordinate without
  collapsing every session into a global default bucket.
- Move SQLite beneath trusted capability-safe state storage with bounded schema,
  WAL/backup-aware migrations, integrity checks, transactions, optimistic
  concurrency, restrictive permissions, corruption recovery, and an explicit
  repository/version-control policy.
- Make multi-record actions transactional; report partial/retry/conflict states
  if the backend cannot guarantee atomicity. Validate priority/status/labels and
  bound all fields, result pages, graph depth/nodes, queries, and database size.
- Validate each complete proposed status/edge mutation before commit under an
  expected graph version. Same-call blockers participate in readiness; failure
  leaves no demotions/partial edges; edge removal/field clearing are explicit;
  deletion transactionally reconciles edges or retains a tombstone and history.
- Implement true readiness from the dependency graph with cycle detection and
  deterministic ranking. Add stable pagination/cursors and typed graph/query
  results rather than context-sized rendered prose.
- Trace task-state changes into planning, delegation, verification, resume, and
  finalization without treating repository text as system authority. Evaluate
  long-horizon recovery and multi-agent coordination against simpler task-list
  baselines.
- Consolidate ephemeral todos and `TaskManager` into this graph or make them
  explicit views with one source of truth. Preserve lightweight status/active-
  form UX, but add stable IDs, versions, provenance, history/checkpoints,
  session cleanup, durable resume, and conflict-safe updates.
- Security/run identity is an immutable runtime capability passed separately;
  task/todo modules never own thread-local identity or default authority.

### W21. Make LSP a bounded, stateful code-intelligence service

- Preserve definition, references, hover, document/workspace symbols,
  implementation, and call-hierarchy operations. Advertise each language only
  when a configured server passes sandboxed version/initialize/health checks.
- A per-workspace server manager owns a trusted executable identity, least-
  privilege W18 profile, PID-namespace-correct lifecycle, initialization
  options, caches, restart/backoff, cancellation, request multiplexing, and
  document open/change/close state keyed by URI and version.
- Pool identity includes workspace/run sharing policy, canonical root, language,
  exact server binary/config/version, capabilities, environment, and generation.
  Checked-out handles have RAII supervision that kills/reaps on abandonment;
  health and protocol state are verified before reuse, and concurrent acquires
  cannot publish stale generations.
- Replace the ad hoc threaded parser with bounded async JSON-RPC framing:
  header/frame/queue/message/result limits, aggregate wall deadlines,
  backpressure, typed server/protocol errors, cancellation, and supervised
  stdin/stdout/stderr/exit. Handle reverse requests honestly at every phase.
- Use a standards-compliant URI/path library and validate every input/output
  resource against session capabilities and workspace identity. Return
  root-relative resource IDs plus source/server/document-version provenance;
  language-server text is untrusted project-derived data.
- Preserve complete bounded `CallHierarchyItem`/server opaque data in a scoped
  continuation token tied to server generation. Return symbol name, kind,
  container, ranges, and stable paginated locations rather than lossy prose/
  location-only projections.
- Integrate real editor/disk snapshots, ignore policy, result budgets, partial
  diagnostics, and workspace generation invalidation. Do not reread/start a
  document server for workspace-only operations unnecessarily.
- Preserve publish diagnostics as typed untrusted evidence keyed by workspace,
  server and document generations. Bound files/count/message/source/aggregate
  bytes before allocation, prioritize deterministically, retain full useful LSP
  fields, deduplicate/debounce, mark stale/partial, and deliver through typed
  result/context state—never raw XML/system-prompt injection or global drain.
- Test recorded protocol fixtures plus opt-in real servers across languages:
  cold/warm latency, concurrent requests, errors/restarts, reverse requests,
  malformed/oversized/drip frames, blocked writes, URI edge cases, project
  plugin attacks, write/network/secret isolation, multi-step continuations,
  cancellation, and bounded large-workspace results.

### W22. Implement named remote actions safely

- Preserve the idea that models select a host-registered symbolic action and
  never receive endpoint URLs, credentials, or arbitrary methods/headers.
- Define each action as a typed payload/result schema plus owner, destination
  policy, effect/risk, approval scope, rate/cost/deadline/response budgets,
  idempotency key, retry rules, and redacted audit/delivery behavior. Advertise
  only registrations available to the run.
- Store endpoints and authentication in trusted redacting secret/config types.
  Reject credentials in URLs and validate header names/values without logging
  values.
- Reuse the hardened HTTP policy: HTTPS and certificate validation, proxy
  provenance, DNS resolution/IP filtering against loopback/private/link-local/
  metadata ranges unless an exact host grant permits them, rebinding defense,
  redirect limits, cross-origin credential stripping, response/body limits,
  cancellation, and egress trace.
- Plaintext is limited to an explicit exact loopback/test capability and visible
  host acknowledgement, never a general public constructor selected by project
  state. Test SSRF, redirects, DNS changes, secret redaction, idempotent retry,
  timeouts, cancellation, partial external success, and end-to-end invocation.

### W23. Preserve web retrieval, search and browser automation behind one egress capability

- Keep direct fetch, search, JavaScript rendering/browser automation and
  focused model distillation. Present them as separate typed effects with
  explicit availability, trust, cost and failure states; do not delete them
  because the current browser lifecycle is unsafe.
- Put every HTTP client, DNS resolver, configured proxy and browser request
  behind a W22-compatible egress broker. Resolve and classify all candidate
  addresses, pin the allowed address to the actual connection while preserving
  TLS hostname verification, re-check every redirect/proxy hop and record the
  final peer/origin. Deny userinfo, loopback/private/link-local/metadata and
  non-HTTP schemes unless an exact host capability grants them.
- Intercept Chromium top-level navigation, redirects, frames, subresources,
  fetch/XHR, WebSockets, workers/service workers and downloads through the same
  broker. Disable file/local/custom schemes and private-network access by
  default; strip credentials on origin changes. A safe initial URL never grants
  its page arbitrary intranet access.
- Use an operator-installed or verified pinned browser artifact, never an
  implicit runtime download in an agent tool call. Launch with minimal OS/
  filesystem/process/network capabilities and ephemeral restrictive profiles
  in host-owned storage. Cross-call cookies/cache/login state is a separate,
  visible encrypted capability with origin, owner, retention and revocation—not
  a project-local default.
- Supervise a bounded browser pool through W10/W18: cap sessions/tabs/processes,
  redirects/requests/response bytes, decoded resources, DOM nodes/bytes, CPU,
  memory, downloads, elapsed time and concurrent work. Enforce before and during
  rendering; cancellation closes pages, terminates descendants and waits for
  reconciliation before reporting terminal completion.
- Make search backends explicit adapters with bounded query/result fields,
  stable partial/error/bot-challenge states and policy applied before filling
  the requested result count. Scraping changes cannot silently become “no
  results.” Keep fetched/search/browser output as typed untrusted evidence with
  URL, redirect chain, retrieval time, content type, truncation and backend
  provenance.
- Distillation consumes attributed evidence, preserves citations and never
  treats page instructions as policy. It reserves provider tokens/cost/time,
  uses the canonical provider/cancellation/trace path and returns its own typed
  provenance. Raw/sensitive URLs, query parameters, page data and provider
  bodies are redacted by default.
- Test with controlled DNS rebinding between validation and dial, hostile
  redirects/proxies, browser private-network attempts across every channel,
  oversized/decompression/DOM/CPU bombs, profile symlink/state attacks,
  cancellation and descendant reap, backend markup/bot changes, concurrent
  sessions, indirect prompt injection and frontend parity.

### W24. Finish isolated workspaces as transactional run capabilities

- Preserve worktree creation, listing, dirty-state protection, applying changes,
  discard, and cleanup. Replace path-in-prose handoff with a typed opaque
  workspace handle bound to run/actor, canonical repository identity, base and
  target commits, branch, filesystem roots, generation, and durable lifecycle.
- Creating/entering a workspace atomically transitions the canonical W12 run
  context. File, process, LSP, task, ledger, verification, and relative-path
  operations all receive the same workspace capability; no model-copied `cd`
  or ambient CWD is required. Exiting restores the prior capability explicitly.
- Separate preview/stage/commit/merge/discard/remove effects and permissions.
  A model boolean is never destructive acknowledgement. Bind approvals to the
  exact diff, worktree generation, expected base/target HEAD, target branch,
  actor, and expiry; revalidate clean/concurrent main-tree state before mutation.
- Stage only reviewed run-owned paths. Distinguish clean-tree status from every
  commit failure, verify the saved commit/object reachability before cleanup,
  retain recoverable snapshots/refs, and never force-remove after ambiguous or
  partial preservation. Make retries idempotent and surface exact recovery steps.
- Apply the same transaction to direct `/review`, `/commit`, `/commit-push-pr`
  and future forge actions. Review a bounded exact diff; approve explicit paths
  and destination; stage only that set in a run-owned index under expected
  HEAD/index/worktree generations; return/verify the commit SHA; and require a
  separate publication receipt before push/PR. Cancellation or staging failure
  cannot leave hidden index mutations or be mislabeled clean.
- Treat repository Git config, attributes, filters, merge drivers, signing,
  submodules, and hooks as untrusted executable policy. Use a least-privilege
  W18 Git profile or a library/explicit configuration that prevents project-
  selected helpers, network, secrets, and outside-root effects.
- Serialize by canonical repository/worktree identity with leases/fencing;
  recover/reconcile on restart; use descriptor-bound path validation and reject
  symlink/identity changes between checks and effects. Bound names, paths,
  command output, worktree count, disk usage, and lifetime.
- Test commit/signing/filter failures, arbitrary foreign worktrees, dirty and
  concurrently changing main trees, protected targets, symlink swaps, duplicate
  creates, crashes between every transition, restart recovery, non-UTF-8 paths,
  multi-agent ownership, and end-to-end tool/ledger routing inside isolation.

### W25. Preserve hooks as explicit, typed runtime extensions

- Keep command, policy/decision, notification and evidence-producing hooks as
  supported capabilities. Do not delete them because current event wiring is
  partial. Remove only implicit trust, prompt-authority shortcuts, duplicate
  frontend orchestration and contract fields that have no selected semantics.
- The checked-in `.claude/hooks` programs are legacy development integrations,
  not the security implementation. Do not carry forward raw shell-text
  classification, spoofable path/file agent identity, implicit issue mutations,
  unbounded file scans, download-capable project tools, swallowed failures, or
  instructions to conceal policy feedback from the user. If a workflow or
  quality-check outcome is retained, re-express it through the typed capability
  and event contracts below.
- Project initialization does not install or activate an executable example
  hook. Examples live as inert documentation/templates; explicit installation
  shows requested events/effects/capabilities and follows the same W25 approval
  and provenance path as every other hook.
- Replace ambient automatic import of Claude/user/project settings with an
  explicit compatibility-import capability. Validate a bounded exact schema,
  record source path/digest/owner/layer/workspace and show the user which hooks
  will run. Repository presence alone grants no execution or instruction
  authority; changed imports require policy-defined reapproval.
- Compose host/managed policy as a non-bypassable typed ceiling. It is evaluated
  after lower-trust requests and can deny executable identities, hook kinds,
  events, outputs and capabilities. Invalid, ambiguous, oversized or partially
  unsupported configuration fails atomically with a visible typed state; array
  order/capacity can never neutralize a higher-trust policy.
- Make hooks part of W12's canonical event transaction rather than frontend
  callbacks. Publish one conformance matrix for session, prompt, tool,
  permission, compaction, subagent, VDD, notification and termination events,
  including exact payload schema, ordering, idempotency, blocking/failure mode,
  timeout/cancellation and supported output. Frontends only render these events.
- Separate outputs into typed decisions, approval requests, prompt suggestions,
  observations, notifications and explicitly host-authorized instruction
  extensions. Untrusted text never becomes system/developer authority or
  silently replaces user content. Conflicts use a deterministic declared merge
  policy and every applied/rejected output receives a trace receipt.
- Execute command hooks through W2/W18 with an approved executable identity and
  digest, parsed arguments, least-privilege workspace/network/secret grants and
  no basename or shell escape. Treat shell mode as its own high-risk capability.
  Default absence of execution policy denies executable hooks while still
  permitting explicitly safe declarative/observational hook kinds.
- Apply W10 admission to the whole event batch: hook count, queue/concurrency,
  processes, input/output bytes, wall time, provider tokens/cost, retries and
  cancellation. A deny stops unscheduled ordered work and supervises/reaps work
  already started. Model hooks, if retained after evaluation, use the canonical
  provider path rather than an optional callback that no composition root sets.
- Use sensitivity-aware payload projection and logging. Raw prompts, tool
  arguments/results, commands, stderr, secrets and model output are minimized,
  bounded and redacted; hooks receive only fields granted for their exact use.
- Prove compatibility with import fixtures and end-to-end tests for every
  supported frontend, source-precedence/managed-deny behavior, project attacks,
  prompt injection, secret exfiltration, malformed config, concurrency/resource
  exhaustion, cancellation, retries, resume/idempotency and hook upgrades.

### W26. Preserve plugins as verified, scoped extension packages

- Keep the intended plugin outcomes: commands, hooks, skills, agents, MCP and
  LSP registrations, offline installation, marketplaces and supported package
  sources. Consolidate or remove only duplicate loaders, unsafe compatibility
  shortcuts and placeholder source/cache shapes after their useful behavior is
  implemented in this package lifecycle.
- Make the host-owned catalogue the sole authority for install scope and
  activation. Project files may request project plugins but cannot self-assert
  user/managed scope, arbitrary install paths or foreign identities. Importing
  Claude/other caches is an explicit read-only migration with source/digest
  provenance, never ambient activation.
- Identify a package by normalized publisher/name/version plus immutable tree
  digest and resolved source revision. Trust and MCP/process/network grants bind
  that identity and declared capability set—not a mutable path, branch, display
  name or `plugin-id/server-name` string. Name/case/Unicode collisions fail
  deterministically.
- Define a bounded, versioned exact manifest with explicit capabilities,
  secrets, executable identities, network origins, workspace access, tools,
  hooks, models and runtime dependencies. Unknown/unsupported fields or broken
  declared components fail the staged package atomically rather than silently
  producing a partially “loaded” plugin.
- Use detached artifact signatures/attestations over canonical bytes. Host
  policy maps signer/publisher identity to package namespaces and capabilities,
  with threshold/rotation/revocation/expiry support. No local, marketplace,
  direct-git, offline or future registry path bypasses verification policy, and
  verification finishes before registration or code/process activation.
- Fetch/build/copy only through W18/W15 with a minimal environment, pinned
  executable/toolchain identities, no ambient Git/SSH credential inheritance,
  redirect/ref/commit verification, bounded bytes/files/depth/output/time and
  cancellation. Stage on the destination filesystem, validate the complete
  tree, then atomically publish package plus catalogue generation with locking,
  durable commit semantics and recoverable rollback.
- Treat updates as new artifacts. Protect against rollback, freeze and
  mix-and-match; verify current trusted metadata, signer revocation, exact
  digest and provenance; show capability/publisher diffs; require policy-defined
  renewed consent; retain a safe rollback generation. A marketplace update
  cannot silently change active package authority.
- Activation creates typed W2/W12 registrations carrying package provenance.
  Plugin command text remains attributed untrusted instruction/reference data;
  declared allowed tools or model choices are requests constrained by host/user
  policy. Hooks use W25, MCP uses W6, skills use W16, LSP uses W21, and agents
  use W8—none receives a private bypass path.
- Persist enable/disable/revoke as generation-safe state. Revocation immediately
  removes schemas/context, cancels and joins plugin work, closes MCP/LSP/process
  resources and invalidates outstanding approvals. Discovery itself performs
  bounded no-follow metadata reads and has no executable side effect.
- Publish a component/frontend/source capability matrix. NPM, Pip, ZIP/offline,
  hook, agent, skill, MCP and LSP support remains visibly unavailable or
  experimental until install → approve → execute → update/revoke → restart/
  recovery tests pass. Add adversarial tests for project scope forgery, package
  substitution, symlinks/TOCTOU, mutable refs, malicious Git config/helpers,
  signature/key rotation, rollback/freeze, partial writes, concurrency, huge
  archives/manifests and capability escalation.

### W27. Preserve the proxy as an authenticated, session-safe gateway

- Define two explicit deployment profiles. A local developer bridge binds an
  OS-authenticated socket or loopback plus an unguessable per-launch credential;
  a network service refuses startup without authenticated TLS, caller/tenant
  identity, scoped authorization, secure forwarded-header policy, rate/
  concurrency/cost admission and operational key rotation/revocation. Merely
  setting a non-loopback host is never enough.
- Separate client authentication from provider credentials. Upstream keys,
  OAuth sessions and custom headers are scoped server capabilities selected
  only after caller authorization; malformed, missing or conflicting client
  credentials cannot fall through to operator-funded access. Scope/redact
  health, models and stats and harden browser auth with exact redirect/origin/
  CSRF/session-cookie/rate-limit policy.
- Resolve every canonical request to a W12 session and fresh call generation
  before context, policy, compaction, hooks, usage, VDD or tools run. A
  stateless compatibility profile injects no implicit global session context.
  Concurrent clients cannot share transcripts, model/mode state, VDD advice,
  usage, compaction hints, hook identity, cancellation or loop counters.
- Classify every route as a canonical agent API or explicitly raw provider
  passthrough. Canonical chat, completions and native-provider shapes use the
  same W2/W10/W12 lifecycle and provider adapters. Raw passthrough is separately
  authorized, receives no agent authority, and preserves validated method,
  path, query, bounded body, status and safe end-to-end headers exactly.
- Implement bidirectional provider streaming translation with bounded frames
  and queues, downstream backpressure, idle/total deadlines, disconnect
  cancellation, provider-native terminal validation and call-attributed usage.
  Do not buffer a nominal stream or return native Anthropic/Google SSE from an
  OpenAI-compatible endpoint.
- Preserve VDD review independently of telemetry. Advisory/blocking modes
  declare exact failure policy; review/static/model work has W10 reservations
  and cancellation; findings and next-turn evidence bind the reviewed call and
  response digest. Oversize, parse, hook, engine or serialization failure is a
  typed outcome, never an empty successful response.
- Own listener, request, provider, MCP, plugin, OAuth, hook, session and review
  shutdown as one supervised lifecycle. Stop accepting, drain/cancel by policy,
  join descendants, persist exact terminal state and report delivery failure.
  Health is readiness evidence, not an unconditional process-alive string.
- Add end-to-end tests for hostile local callers, external bind refusal, TLS/
  authentication, cross-tenant isolation/spend, credential confusion, route
  parity, exact passthrough, every provider's stream conversion, slow clients,
  midstream failure, disconnect, VDD modes, graceful shutdown and restart.

### W28. Make adversarial review evidence-bound and operational

- Preserve VDD's independent-provider review, verifier, sandboxed static
  analysis, revision, issue-promotion and session-evidence goals as one typed
  W12 review operation. Advisory, blocking, required-evidence, skipped-by-policy,
  degraded, failed, unconverged and cancelled are distinct terminal outcomes;
  every frontend applies the same configured semantics.
- Run adversary and verifier roles through the canonical AgentRuntime, tool
  executor, guardrails, Reality/evidence graph, grounding, sandbox, filesystem,
  network/MCP brokers, budgets, cancellation and trace pipeline. Do not maintain
  a privileged VDD side harness or a reduced lifecycle. The verifier receives a
  capability-filtered view of the same typed registry, normally read-only with
  bounded disposable test/analyzer scratch; shared mechanisms never imply
  inherited worker transcript, memory, approvals, secrets or mutation rights.
- Enforce model independence in routing and receipts. Record resolved provider,
  endpoint, model family/version and policy generation and reject a worker/
  verifier collision. Alias resolution, fallback or alternate-model
  unavailability produces `inconclusive`/`verifier_error`, never silent reuse of
  the worker model or a clean verdict. Higher-risk policy may require distinct
  worker, adversary and final-verifier families.
- Use VDD as the required slice verifier for the Section 4.6 hierarchy and run
  a separate integration review after accepted slices are assembled. A worker
  result remains proposed until deterministic gates and the configured VDD
  receipt pass against the exact artifact generation; any later mutation
  invalidates the receipt. The planner cannot waive or manufacture its own
  verification, and a verifier cannot repair the artifact it is judging.
- Bind each review to the exact call, response digest, immutable workspace/
  artifact generation, provider/model/prompt versions and review-policy
  generation. Model-supplied paths, lines, descriptions, reasoning and verdicts
  are untrusted bounded claims until checked against cited evidence. They never
  become system instructions or global session context.
- Replace prose/relaxed “clean” inference with a strict versioned schema and
  provider-native structured output where available. Parse failure, empty or
  partial terminal output, contradictory fields, missing findings, verifier
  absence and evidence truncation cannot count as clean. Normalize arbitrary
  ranges without panics and fuzz the entire parser/triage boundary.
- Specify convergence over versioned finding identities and status transitions.
  A clean pass cannot inherit an older false-positive rate; duplicate matching
  cannot collapse distinct causes; heuristic hints cannot silently demote a
  possible genuine defect. Calibrate adversary/verifier independence by actual
  endpoint, model family and prompt—not provider label alone—and retain a human/
  deterministic disputed state.
- In blocking mode, withhold success until the reviewed response digest meets
  the declared acceptance policy. Revisions receive the exact prior artifact,
  findings and causal history. They run without tools by default; any tool work
  is a separately authorized/budgeted canonical child run. Revision failure,
  exhaustion or static-analysis failure cannot be serialized as an ordinary
  clean response unless the host explicitly selected and surfaces fail-open.
- Admit the complete review under W10 reservations for model/static calls,
  tokens, cost, time, concurrency, bytes, storage and retries. Reuse W3's
  status-validating bounded provider transport and W18's supervised analyzer;
  one cancellation tree joins HTTP, verifier, revision, processes, persistence
  and issue publication. Missing usage is unknown cost, not zero.
- Store a redacted, resumable, versioned evidence record through W15 with field
  sensitivity, integrity, atomic publication, retention/export/delete and crash
  recovery. Promote only unresolved evidence-bound final findings to W20 issues
  under explicit policy/approval and transactional/idempotent reconciliation;
  later revisions can mark a finding fixed without erasing its history.
- Evaluate VDD against labeled real defects, clean outputs, prompt injection,
  adversarial malformed responses and long/multi-file tasks. Gate defaults on
  defect recall, false-negative/positive rates, fix success, regression rate,
  task quality, latency, token/cost overhead and reviewer disagreement. A second
  model's confidence is not proof of production readiness.

## 6. Allowed removal criteria

Runtime code may be removed in the future only when at least one is true:

1. The behavior is explicitly deprecated and selected for removal, such as the
   legacy rule injector.
2. The code creates an unsafe authority boundary, such as fail-open permission
   APIs, and a safe canonical path preserves legitimate behavior.
3. It duplicates canonical behavior and every supported caller has migrated.
4. It is an optimization whose measured quality, safety, latency, or resource
   result is worse than the simpler baseline.
5. It exposes no coherent user capability and retaining it would create a
   misleading production claim; the intended capability is first relocated to
   an active implementation plan or explicitly rejected with evidence.

Being unfinished, unused, or poorly wired is not by itself grounds for deleting
an intended capability.

## 7. Delivery sequence

1. Complete audit, reachability graph, and documentation reconciliation.
2. Establish traces, evaluation corpus, and executable capability assertions.
3. Close permission and destructive-action gaps.
4. Repair provider-native state and shared budget/cancellation behavior.
5. Introduce the canonical runtime and rotating planner/worker/VDD role
   profiles, harden proxy identity/session boundaries, and migrate one frontend
   at a time.
6. Remove the rule injector and obsolete compatibility paths with negative and
   migration tests.
7. Finish memory, MCP, grounding, lifecycle services, delegation, and VDD
   against explicit acceptance matrices.
8. Implement and evaluate progressive tools and safe speculation.
9. Consolidate tests, dependencies, files, and documentation.
10. Publish production-readiness evidence, not an assurance-only declaration.

## 8. Release gates

No remediated subsystem is labeled production-ready until:

- its operational checklist is complete;
- all supported frontend scenarios pass;
- security and indirect-prompt-injection scenarios pass;
- cancellation and resource ceilings pass;
- trace assertions prove the intended policy path ran;
- rotating planner handoff, fresh-worker slice isolation, deterministic slice
  gates, alternate-model VDD receipts and final integration verification pass;
- verifier routing proves model/endpoint separation and fail-closed behavior for
  unavailable, ambiguous, truncated, stale or malformed verification;
- documentation is generated or verified against those tests;
- the before/after evaluation shows no unacceptable quality regression.

## 9. Audit-driven amendments

This section will record material design changes caused by the full file audit.
Each amendment must cite the audited files and the evidence that changed the
plan.

- 2026-08-16: Initial design created from confirmed cross-path findings. The
  file-level verification and Markdown reconciliation are now complete; no
  runtime code was changed in this audit/cleanup pass.
- 2026-08-16: Complete non-Rust audit found two additional automatic Python
  rule injectors, repository settings that activate them, an unsafe inherited
  Claude behavioral prompt, bypassable legacy hook controls, stale generated
  bytecode, and a tracked historical SQLite/session pair whose completion claims
  contradict later issues and live reachability. W0/W1/W12/W13/W25 now require
  evidence export, exact injector deletion, a minimal provenance-aware host
  policy, reproducible CI and typed hook reconstruction rather than deletion of
  the intended extension outcomes.
- 2026-08-16: Configuration audit found broken multiword environment mapping,
  a second ACP-only loader, project-controlled permission bypass, and secret
  custom headers exposed by `Debug`. Added W14 and strengthened the host versus
  project authority boundary.
- 2026-08-16: Persistence-path review found a parent-symlink escape around the
  lexical validator. Added W15; intended persistence remains, but safe storage
  must be enforced through filesystem capabilities.
- 2026-08-16: Token stop conditions were proven test-only and disconnected.
  W10 now requires preflight reservation as well as post-call accounting so a
  single response cannot overshoot the configured hard limit unchecked.
- 2026-08-16: Notebook editing was confirmed operational but capable of
  persisting incomplete modern cell records and losing the original on an
  interrupted in-place rewrite. W15 now explicitly preserves the feature while
  requiring nbformat validation, stable IDs, budgets, snapshots, atomic writes,
  and Jupyter round-trip evidence.
- 2026-08-16: The Bash/sandbox audit found a strong Linux containment base but
  unsound auto-approval and non-profiled authority, plus incomplete background
  supervision and forgeable verification evidence. Added W18 to preserve and
  finish every intended subprocess capability behind least-privilege profiles
  and a canonical job supervisor.
- 2026-08-16: Cron was confirmed as honest metadata-only CRUD rather than an
  executing feature. Added W19 to preserve it and supply the missing trusted,
  durable, budgeted scheduler and noninteractive authorization model.
- 2026-08-16: Crosslink was confirmed as useful durable task state hidden
  behind an unsafe unclassified argv facade. Added W20 for typed transactional
  effects, per-run sharing, capability-safe SQLite, bounded graph operations,
  and real blocker-aware planning.
- 2026-08-16: LSP contains meaningful protocol work but fresh-server global
  deduplication, lossy continuation/results, unbounded framing, ignored server
  errors, and broad sandbox grants prevent production use. Added W21 for a
  bounded per-workspace manager and spec-complete typed client lifecycle.
- 2026-08-16: Control/state audit found plan and skill marker protocols,
  multiple conflicting task stores with todo-owned security identity, and an
  entirely unwired remote-trigger registry. W16/W17/W20 now require typed
  transitions and one task source of truth; W22 defines safe named external
  actions rather than deleting the intended capability.
- 2026-08-16: `tool_search` was confirmed to defer nothing because every API
  path still sends all schemas; it returns duplicate schemas as text and direct
  selection bypasses its result cap. W11 preserves progressive discovery but
  moves activation into a typed trusted runtime transition with evaluation and
  strict aggregate budgets.
- 2026-08-16: The web-tool adapter reports timeout while spawned futures and
  blocking browser/search work continue, and its sync bridge can park an async
  executor. W10 now applies one cancellation/admission/deadline lifecycle to
  network, browser, resolver, model-distillation, and process work—not just Bash.
- 2026-08-16: The lower web layer has useful body caps and IP checks, but DNS
  validation is separate from the real dial and Chromium page activity bypasses
  it. The default browser also persists its profile under project control,
  auto-downloads executable content and checks DOM size only after allocation.
  Added W23 to preserve fetch/search/browser/distillation through one pinned,
  intercepted, supervised and provenance-aware egress capability.
- 2026-08-16: The speculation module is entirely unwired/no-op and its current
  API cannot express execution ownership, snapshot identity, result retrieval,
  promotion, discard or cancellation; its feedback compares a prediction with
  the already-finished same turn. W7 now requires a typed run-owned transaction
  and measured simpler baseline before preserving this as an optimization.
- 2026-08-16: Slash-command review found separate static legacy/TUI help tables,
  a third legacy handler registry, TUI-local dispatch and plugin bypass. Legacy
  handlers mix parsing with ambient side effects and silently overwrite alias
  collisions. W12 now specifies one typed collision-checked command registry
  that generates help/completion/docs and routes proposed effects through the
  canonical capability lifecycle.
- 2026-08-16: Legacy result presentation was proven to parse magic diff markers
  from any tool text, panic on reversed markers, compute full unbounded diffs
  and emit untrusted terminal controls. W12 now makes presentation a bounded,
  control-sanitizing projection of trusted typed runtime events.
- 2026-08-16: Project initialization deletes config before replacement,
  overwrites existing sibling hook/rule files, publishes partial multi-file
  state, creates the deprecated rule subsystem and installs an authority-seeking
  executable hook example. W1 now removes all rule scaffolding; W15 makes setup
  transactional/recoverable; W25 keeps examples inert until explicit approval.
- 2026-08-16: `doctor` was found to send real credentials/custom headers to a
  project-selectable inference URL, mutate credential/plugin state, and report
  fabricated empty-manager/local-transform checks as live health. W0/W13 now
  require effect-declared, non-mutating-by-default diagnostics backed by the
  same executable capability evidence as production claims.
- 2026-08-16: Print mode was confirmed as another direct provider frontend with
  no canonical context/run state, deadlines, aggregate bounds or usage/cost
  accounting; it writes partial stdout and treats EOF after text as success.
  W12 now preserves it as a framed no-tools profile of the shared runtime.
- 2026-08-16: CLI review/commit was found to run ambient Git helpers, buffer
  unbounded output and race a vague/all-file stage decision against changing
  state; credential setup echoes API keys and may truncate a symlinked project
  config when home resolution fails. W24 now covers direct Git/forge commands,
  while W3/W14/W15 own masked referenced-secret setup and safe config mutation.
- 2026-08-16: Worktree review found a real force-removal data-loss path after
  any commit failure and confirmed that created worktrees never become session
  state. W24 preserves the intended isolation/apply/discard features behind an
  owned, recoverable, capability-bound, transactional lifecycle.
- 2026-08-16: The nominal `ServiceRegistry` was proven unused and its plugin MCP
  registry is explicitly transport-less Phase 1 with raw `Debug` secrets. W9
  requires one real composition root or consolidation; W6 now carries validated,
  redacted, capability-bound plugin registration through unload/reload/runtime.
- 2026-08-16: Service reachability review found auto-compaction/feature flags
  entirely unused, a `Default` path that skips documented env flags, and direct
  lifecycle analytics in only two frontends. W9 now requires explicit typed
  rollout state and privacy-bounded canonical run telemetry, while W10 owns the
  actual compaction decision/budget lifecycle.
- 2026-08-16: The shared `ToolExecutor` is widely used but still exposes
  caller-assembled lifecycle phases and a Boolean unchecked-dispatch bypass. W2
  now requires an exact consumable receipt, while W12 makes this executor own
  hook/policy/permission/dispatch/observation/result ordering for every frontend.
- 2026-08-16: Enterprise tool caps were proven racy and poison-fail-open, while
  missing state disables them and token projections reserve nothing. W2/W10/W14
  now require authenticated mandatory policy plus atomic durable reservation,
  commit/release, and identical coverage for every primary and auxiliary call.
- 2026-08-16: The rate-limit mock was proven to test only itself and connect to
  no request path. W13 preserves its intended deterministic failure testing at
  the actual transport seam and removes the production-only mock surface after
  equivalent provider/retry/cancellation coverage exists.
- 2026-08-16: Both proposed LSP services are unwired and unsafe to connect
  directly: language-only pooling crosses workspace authority and leaks dropped
  children; diagnostics lack global budgets/version scope and inject raw server
  text. W21 now specifies generation-safe RAII pooling and typed bounded
  diagnostic evidence while preserving both intended capabilities.
- 2026-08-16: No background job is wired, and the implemented memory dedup loses
  metadata while “summaries” concatenate/stale and plugin jobs only log polling.
  W5 now makes consolidation/summarization transactional and provenance-aware;
  W9 supplies durable leased lifecycle and honest plugin maintenance outcomes.
- 2026-08-16: Session review found plan mode name-allows mutating task/Crosslink
  facades and its dynamic opt-ins cannot pass, while task updates can partially
  demote, ignore same-call blockers, and leave dangling delete edges. W17 now
  gates exact typed effects/resources; W20 mandates whole-graph versioned
  validation and atomic commit.
- 2026-08-16: The audit logger was found to cover only the legacy REPL, capture
  raw tool arguments in project-writable symlink-following JSONL, and permit
  execution after security-write failure. W0 now makes redacted, host-owned,
  integrity-aware causal run tracing an explicit release prerequisite.
- 2026-08-16: Pricing review found token components silently capped at
  `u32::MAX`, floating/provenance-free rates, invented cross-provider cache
  multipliers, and an unconsumed thread-local “session” warning. W10 preserves
  cost visibility through checked fixed-point, provider-attributed receipts and
  session-safe uncertainty/reconciliation.
- 2026-08-16: `SessionManager::end_session` was proven to remove its only state
  before a three-file commit and return an error that cannot be retried; ACP
  “load” creates a blank child and production never consumes the handoff. W12
  now requires a versioned call-correlated canonical session, typed handoff and
  failure evidence, and recoverable transactional lifecycle states; W15 owns
  the capability-safe durable commit mechanics.
- 2026-08-16: The newer session state serializes a live permission-bypass flag
  and resume replaces the current launch policy with it. Its store also retains
  partial panicking mutations without events, and persistence accepts old
  versions without migration. W2 now forbids authority in conversation files;
  W12 requires typed generation-atomic state/events; W15/W13 require bounded,
  exact-version, recoverable migrations.
- 2026-08-16: Migration review found startup discards all failure reports,
  once-only effects and ledger marks are not one transaction, concurrent ledger
  saves lose marks, and an unconsumed migration writes an unverified marker into
  the shared Claude transcript tree. W15 now requires store-scoped transactional
  migration gates and OpenClaudia-owned per-artifact versions; the global stamp
  is explicitly retired after its safe replacement exists.
- 2026-08-16: Transcript review found unvalidated filename IDs, symlink-following
  shared-directory writes, non-transactional watermark/appends, lossy event
  reconciliation, silent corrupt-line skips and a forgeable text compaction
  boundary. W12/W15 now define an owned typed causal event log and explicit
  read-only foreign import rather than claimed shared-format co-ownership.
- 2026-08-16: Core memory review found a repository-local SQLite file and
  automatically inferred preferences promoted into system context, advertised
  memory tools absent, phrase-only lossy retrieval, no provenance/retention and
  unsupported future schemas accepted. W5 now defines host-owned evidence,
  reviewable preferences, bounded evaluated retrieval and canonical typed tools;
  W15 applies transactional exact-schema store migration.
- 2026-08-16: Team memory is entirely unwired and was found to use independent
  SQLite row counters as cross-store identity, causing wrong tombstones after
  divergence; seeded user placeholders also mask team core values. W5 now
  requires global logical IDs, version-bound overlays, one merged retrieval
  budget, authenticated sharing and durable cross-store reconciliation.
- 2026-08-16: Auto-learning is wired only in the legacy REPL and currently
  treats language/correlation heuristics as durable truth: blocked or expanded
  inputs may be learned, any subsequent shell success can be called a fix, and
  ordinary Clippy output is not parsed. W5 now preserves the intended learning
  feature as a typed, causal, reviewable, consent-aware cross-frontend pipeline
  with measured benefit and harm. The neutral file-extension registry moves out
  of `rules` before W1 deletes the deprecated injector.
- 2026-08-16: Compaction is live in proxy but is truncated concatenation rather
  than a faithful summary, promotes transcript text to system authority, uses a
  previous-turn count for a changed request, and writes archive/memory rows
  before commit. REPL has a second weaker algorithm and TUI/ACP do not compact.
  W10/W12 now require one provider-calibrated, causally closed, transactional,
  cited and evaluated compaction/checkpoint lifecycle across every frontend.
- 2026-08-16: Credential review found raw refresh response logging despite known
  token echo, unredacted derived `Debug`, lossy mutation of Claude Code's store,
  blocking unbounded refresh locks, false Claude Code identity injection, and
  unverified JWT-derived Codex account/FedRAMP routing. W3 now requires official
  app-specific auth, secret-safe types/sinks, read-only foreign compatibility,
  verified claims and cancellable generation-safe refresh.
- 2026-08-16: The typed file-error helper improves cause preservation but its
  generic path APIs are unbounded and the atomic writer can report failure after
  rename already published bytes. W15 now requires explicit partial-publication
  outcomes, reconciliation and per-artifact mode/bounds policy.
- 2026-08-16: Guardrails review found lexical traversal bypass, invalid strict
  patterns dropped fail-open, process-global cross-session quotas, partial tool
  coverage, and entirely unused diff/quality action and cadence settings. W2 now
  makes blast radius, staged diffs and quality checks typed run-scoped effect
  reservations/gates over canonical resources and artifact generations.
- 2026-08-16: Hook review found a useful but unsafe and incomplete extension
  surface: all runtimes ambiently import foreign/project executable hooks,
  concatenation does not make managed policy dominant, prompt output gains
  instruction authority, event/output semantics differ by frontend, model hooks
  are unwired, and execution lacks aggregate admission. Added W25 to preserve
  hooks through explicit trust, typed canonical lifecycle events, least-
  privilege execution, bounded provider/process work and conformance evidence.
- 2026-08-16: Keybinding review found the newer contextual resolver entirely
  unwired, legacy configuration active only during streaming, default chords
  impossible on that path, and TUI dispatch hard-coded. W12 now preserves the
  feature through a shared typed command registry and validated contextual
  event resolver rather than deleting the unfinished runtime module.
- 2026-08-16: Full plugin review found project-controlled scope/path forgery,
  mutable string-based trust, an unusable/bypassable inline signature design,
  non-transactional supply-chain mutation and mostly disconnected declared
  components. Added W26 to preserve the complete plugin product intent behind
  verified immutable packages, host-owned scope, explicit capabilities,
  atomic activation/update and canonical runtime registration. The design is
  checked against current SLSA, TUF, Sigstore and OpenAI agent-runtime guidance.
- 2026-08-16: The legacy REPL's direct `!command` path was confirmed as a
  second full-host executor with only a bypassable case-sensitive substring
  warning list, no sandbox, no deadline/output bounds, and a public unchecked
  helper. W18 now preserves direct user shell access through the same scoped,
  supervised process capability as agent-requested execution; user origin can
  streamline approval UX but cannot confer unrestricted machine authority.
- 2026-08-16: The remaining small REPL helpers showed that `@file`, external
  editing and blocking questions bypass canonical run capabilities/budgets;
  plan approval can consume different bytes than those pinned and publishes
  system authority through split mutations; and a shadow Vim parser is not
  connected to the working Rustyline Vi input path. W12/W15/W17/W18 now
  preserve and finish those features with typed bounded events, snapshot-bound
  approval and one real modal implementation.
- 2026-08-16: Full legacy REPL controller review confirmed provider-specific
  lifecycle ordering, duplicate Gemini history, false terminal states, a
  tracing-only turn-limit “result,” private notes sent as system instructions,
  and `/btw` transcript reordering. W12 now explicitly preserves private notes
  and side questions with correct privacy/child-run semantics while all model/
  tool loops migrate to its canonical executor and terminal state machine.
- 2026-08-16: Full legacy slash review found project-forgeable branch resume,
  generic raw reasoning disclosure and a `/plan` label transition that never
  activates the real gate. W12 now separates provider continuation, user
  summaries and protected monitoring and makes branching typed/transactional;
  W17 requires every planning entrypoint to install identical capabilities.
- 2026-08-16: Full coordinator review proved the formal runtime has no consumer
  and cannot dispatch, while `--coordinator` only changes prompt text. W8 now
  preserves the intended queue/teammate/permission UX by merging it into the
  canonical task, run, capability and budget services with supervised child
  handles, explicit dependency failure and honest persistence.
- 2026-08-16: Full XML-interceptor review found that ordinary assistant prose
  becomes executable control, marker-shaped text is deleted, ambiguous aliases
  resolve nondeterministically and call batches have no aggregate admission.
  W12 now preserves local-tool compatibility through provider-native typed
  adapters and permits only an explicit bounded migration profile before the
  pseudo-XML control mechanism is retired.
- 2026-08-16: The live subagent tool was confirmed to launch workers, but its
  worktree and read-only boundaries are prompt-advisory, cleanup can erase
  staged/untracked/committed work, and the in-memory transcript/terminal tracker
  cannot provide the advertised resume contract. W8 now requires canonical
  child attempts with immutable capability generations, enforced workspace
  binding, durable causal checkpoints, aggregate budgets, owned cancellation
  and lossless typed artifact handoff.
- 2026-08-16: Complete ACP review found that nominal wire sessions share one
  transcript/model/mode/IDE/config/cancel state, unknown IDs become runtime
  identities, transport buffers are unbounded, EOF can commit partial output,
  raw thinking is forwarded, and Initializer/Coding does not constrain tools.
  W10/W11/W12/W17 now make ACP a bounded call-correlated transport over isolated
  canonical sessions and effective runtime capabilities.
- 2026-08-16: Complete proxy review found no client authentication before use
  of configured provider credentials, process-global session/VDD/accounting,
  route-dependent policy, broken catch-all body/query forwarding, buffered raw
  cross-provider streams and VDD coupled to token telemetry. Added W27 to
  preserve the proxy as an authenticated, tenant/session-safe, streaming,
  delivery-aware gateway over the canonical runtime.
- 2026-08-16: Complete TUI-family review showed that Escape changes only visual
  state while the old run continues, terminal modes/event threads and detached
  work lack owned cleanup, `@file` can race containment and read outside the
  workspace, resume can combine one provider label with another provider's
  transport credentials, and rendering is unbounded/Unicode-incorrect with raw
  terminal and reasoning paths. W3/W10/W12/W15/W17 now preserve the intended
  TUI behind call-correlated cancellation, atomic session/transport rebinding,
  typed bounded attachments, RAII terminal supervision, safe incremental
  presentation, and enforceable modes.
- 2026-08-16: Complete VDD review found that live engine paths collapse parse
  failure into “clean,” verifier range input can panic, claimed truncation
  safety is not applied, blocking mode is advisory/fail-open by frontend, and
  review transport/effects have no aggregate evidence or resource transaction.
  Added W28 to preserve the intended independent review, verifier, static
  analysis, revision and issue workflow with exact artifact binding, strict
  typed outcomes, calibrated convergence, canonical budgets/cancellation,
  non-authoritative findings and transactional resumable evidence.
- 2026-08-16: Post-audit product direction selected disposable agent contexts
  over ever-growing transcripts: a capability-limited planner decomposes work
  into fresh semantic-slice workers and is itself rotated through durable typed
  checkpoints. VDD is the mandatory alternate-model slice/integration verifier
  on the same canonical harness, guardrails and grounding/evidence system, but
  with separate context, identity, budgets and normally read-only authority.
  Section 4.6 and W8/W12/W28 now define fail-closed handoff, model separation,
  artifact-bound receipts and deterministic evidence requirements.

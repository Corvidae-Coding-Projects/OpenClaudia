# OpenClaudia Architecture — Audited Current State

Status: descriptive snapshot after the 2026-08-16 file-by-file audit. This is
not a production-readiness statement. The target architecture and acceptance
criteria live in `docs/production-remediation-design.md`.

## High-Level Overview

The binary exposes several independently composed frontends:

```text
User/client
  ├─ default full-screen TUI
  ├─ legacy line REPL
  ├─ one-shot print
  ├─ HTTP proxy
  ├─ ACP stdio server
  └─ iteration/loop mode
         │
         ├─ provider request adapters
         ├─ prompt/context/mode assembly
         ├─ local and extension tool dispatch
         ├─ session/transcript/memory stores
         └─ hooks, permissions, policy, grounding, VDD, budgets
```

Subcommands: init, auth, start,
acp, config, doctor, hooks, loop.

The important current fact is duplication: those frontends do not all use one
request state machine, one tool executor, one event log, one budget/cancellation
tree, or one final-state protocol. A type or service existing in `src/` does not
prove that every entrypoint calls it.

## Existing module groups

| Area | Representative paths | Audited status |
|---|---|---|
| Composition/frontends | `src/main.rs`, `src/tui/`, `src/cli/`, `src/acp.rs`, `src/proxy.rs` | Multiple orchestration roots with different semantics |
| Provider transport | `src/providers/`, `src/services/provider*.rs` | Real adapters, but native state and error/retry policy are lossy/inconsistent |
| Tool registry/execution | `src/tools/`, `src/services/tool_executor.rs`, `src/tool_intercept.rs` | Broad real surface with duplicate gates and unsafe compatibility paths |
| State/persistence | `src/state/`, `src/session/`, `src/transcript.rs`, `src/memory.rs` | Substantial implementation, but ownership/durability/provenance are incomplete |
| Extensions | `src/hooks/`, `src/plugins/`, `src/mcp.rs`, `src/skills.rs` | Intended outcomes retained; trust, protocol, wiring, and lifecycle need repair |
| Agent behavior | `src/modes/`, `src/subagent.rs`, `src/coordinator/`, `src/speculation/` | Modes are mostly prose; coordinator/speculation are incomplete or unused |
| Assurance | `src/permissions.rs`, `src/guardrails.rs`, `src/grounded_loop.rs`, `src/vdd/` | Useful components, not one fail-closed authority boundary |
| Web/code intelligence | `src/web.rs`, `src/tools/web/`, `src/tools/lsp.rs` | Real handlers with egress, cancellation, lifetime, and result-contract gaps |

## Current data-flow problem

```text
frontend-local request construction
  → frontend/provider-specific streaming
  → frontend-local tool parsing and loop
  → optional subset of permission/hook/policy/VDD/final checks
  → frontend-local persistence and terminal status
```

This makes security and correctness fixes non-compositional. The remediation
target is one typed run state machine:

```text
authenticated run + immutable capabilities
  → provider-native request/response events
  → typed tool-effect reservation and execution
  → causally ordered evidence/state log
  → explicit completed / cancelled / blocked / failed terminal state
```

Frontends should render and transport that state machine rather than implement
it independently.

## Provider adapters

Adapters currently translate a shared OpenAI-shaped representation to/from
provider-specific protocols. That convenience also destroys provider-native
continuation, tool, reasoning, refusal, usage, and stream semantics. The repair
keeps a typed provider-neutral event envelope while preserving opaque native
state needed for correct continuation.

## Tool boundary

The registry publishes many schemas, but schema publication, authorization,
execution, cancellation, observation, and result shaping are not one atomic
operation. The legacy XML interceptor can turn ordinary model prose into tool
control. The target design removes that executable text fallback and routes all
effects—including MCP, hooks, LSP, worktrees, web, scheduling, and subagents—
through explicit capabilities and budgets.

## Web backend note

The explicit `browser` build feature contains browser-backed free search using
DuckDuckGo / Bing. It is opt-in, uses an operator-installed browser, and cannot
download Chromium at runtime. This describes the current backend, not a
security guarantee: browser activity does not yet share one complete egress
capability with direct HTTP fetches.

## Rule-injector removal

The legacy filesystem rule injector is removed across Rust frontends, project
initialization, diagnostics, repository hooks, configuration, assets, and
dedicated tests. Repository rule files and project-local output styles cannot
acquire automatic prompt authority. Neutral extension recognition remains in
`src/file_types.rs` for auto-learning filters and lifecycle-hook metadata; that
module does not read instructions or construct prompts. Explicit user
instructions, reviewed skills, permissions, and sandbox policy remain separate
mechanisms.

## Canonical references

- `docs/full-codebase-audit-2026-08-16.md`: evidence and per-file findings.
- `docs/production-remediation-design.md`: target architecture and release gates.
- `capabilities/registry.json`: typed entrypoint maturity, required effects,
  limitations, and executable evidence links.
- `docs/binary-capability-matrix.md`: generated user projection of that
  validated registry.

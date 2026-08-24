# S-027: Isolate Anthropic subscription compatibility

Status: Implemented
Effort: Medium
Primary findings: F-081
Workstreams: W3
Depends on: [S-025](./025-end-to-end-secret-types-and-redaction.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Anthropic subscription use now defaults to Anthropic's unmodified `claude`
executable. Claude Code owns login, logout, credential refresh, protocol details,
and its credential store. OpenClaudia uses `claude -p` as a bounded model
transport while retaining its own agent harness, tool execution, permissions,
policy, budgets, hooks, reality ledger, and grounded-final gate.

The earlier direct subscription protocol remains available for the research
experiment, but it cannot activate in a normal build or through credential
discovery. It requires both:

1. Cargo feature `experimental-claude-subscription-auth`.
2. Exact runtime acknowledgement
   `OPENCLAUDIA_EXPERIMENTAL_DIRECT_CLAUDE_SUBSCRIPTION=I_ACCEPT_UNSUPPORTED`.

API-key, cloud, gateway, local-provider, and Codex authentication behavior is
unchanged.

## Deterministic transport boundary

The supported subscription backend resolves and pins the canonical `claude`
executable at startup, removes Anthropic API credential environment variables,
and invokes it with process-level restrictions:

- `--safe-mode` disables filesystem customization discovery;
- `--tools ""` disables every Claude Code native tool;
- `--strict-mcp-config` with an empty MCP configuration disables inherited MCP
  servers;
- slash commands, Chrome integration, and session persistence are disabled;
- the host system prompt is passed through a private temporary file; and
- stdout and stderr are read with fixed limits and the process has an absolute
  turn timeout.

OpenClaudia's currently advertised tool names and exact argument schemas are
encoded as variants in Claude's required structured-output schema. A no-tool
turn has `maxItems: 0`. The decoder independently rejects unstructured output,
excess calls, blank names, and names absent from the exact host catalog even if
the executable were to violate that schema. Surviving requests are still
handled by OpenClaudia's existing tool catalog, argument parsing, policy,
permission, hook, and run-budget checks. The boundary therefore does not depend
on Claude following a prose request not to use a tool.

## Surface coverage

- Default TUI conversations use the supported backend when Anthropic has no API
  key and the direct experiment is not explicitly enabled.
- Print mode uses the same supported login in a bounded no-tool turn.
- ACP uses the supported backend while preserving ACP's existing tool and
  grounded-result loop.
- VDD builder, adversary, and verifier turns use the same backend and the same
  run budgets and grounding harness as other providers. VDD continues to reject
  verifier-side tool requests.
- `openclaudia auth` delegates login, status, and logout to `claude auth`; it
  does not parse the private credential file in the supported configuration.
- The legacy line-oriented `--tui-mode` path fails with a clear instruction to
  use the default TUI or print mode because that frontend does not implement the
  shared agentic tool loop.

## Experimental containment

Direct credential loading, private OAuth headers and endpoint selection, the
Claude Code identity compatibility block, native OAuth client construction,
and proxy device-flow activation all fail closed unless both experiment gates
are satisfied. Diagnostics identify the direct route as experimental. The
foreign Claude Code credential store remains read-only as established by
S-026; Claude Code remains its sole refresh and write owner.

## Adjacent grounded-result repair

Live testing exposed a separate real defect: the final gate could not express a
claim grounded in an exact successful file read. Crosslink #1127 adds the narrow
`file_observation` final claim. It requires an exact fresh `FileRead` evidence
receipt for the same path and retains the existing run, trust, and freshness
checks. This allows ordinary read-only tasks to complete without weakening
quality-gate claims.

## Verification

Rust 1.98 verification covered both default and experimental builds. Focused
tests exercise the process flags, empty MCP/native-tool boundary, dynamic tool
schema, unadvertised-tool rejection, output limits, auth-status decoding,
direct-protocol gates, OAuth behavior, pipeline integration, and exact
file-observation grounding.

A compiled default-TUI manual run used the existing Claude Code login. Claude
selected `read_file` as structured data, OpenClaudia executed it through its own
harness, the follow-up cited the fresh ledger receipt, and the grounded-final
gate accepted the exact file observation. A compiled print-mode run also
returned the requested sentinel, and `openclaudia auth --status` successfully
delegated to Claude Code. No credential value was copied into OpenClaudia.

A separately compiled feature-enabled print-mode run set the exact experimental
acknowledgement and returned its requested sentinel through the preserved direct
route. That live check first exposed and then verified a fix for the typed
environment validator: the acknowledgement is now recognized as an external
control variable and reaches its dedicated exact-value gate instead of being
rejected as unknown. The direct test did not refresh or rewrite Claude Code's
credential store.

## Remaining boundary

This slice does not claim that Anthropic will preserve every current Claude CLI
flag or subscription policy indefinitely. Unsupported CLI versions fail
explicitly instead of falling back to the direct protocol. The experimental
implementation is retained for research and can be removed separately if the
user decides the supported backend has made it unnecessary.

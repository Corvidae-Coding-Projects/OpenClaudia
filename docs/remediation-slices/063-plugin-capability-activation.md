# S-063: Activate plugin capabilities through canonical registries

Status: Implemented — awaiting independent VDD review
Effort: Medium
Primary findings: F-100
Workstreams: W2, W6, W16, W21, W25, W26
Depends on: [S-010](./010-canonical-run-context-and-events.md), [S-013](./013-progressive-tool-catalog.md), [S-016](./016-mandatory-tool-effect-classification.md), [S-059](./059-canonical-hook-lifecycle.md), [S-061](./061-plugin-identity-and-bounded-discovery.md), [S-062](./062-plugin-supply-chain-transactions.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make declared plugin commands, hooks, skills, agents, MCP, and LSP components either operational with provenance or honestly unavailable.

## Implementation boundary

- Compile reviewed package components into namespaced generation-bound registrations with exact effects, schemas, capabilities, and lifecycle ownership.
- Route each component through its canonical subsystem and atomically remove schemas/context plus cancel owned work on disable/update.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- The capability registry proves invocation and shutdown for every advertised component type.
- The working command path retains package/source/capability provenance and no declared component bypasses normal policy.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Implemented in the wave-three artifact. `PluginCapabilityRegistry` is now the
single activation catalogue for plugin commands, hooks, skills, agents, MCP
servers, and LSP servers. Registrations are namespaced and bound to immutable
package/source generation, effects, requested capabilities, schemas, and
lifecycle ownership. A component compilation failure prevents the entire
plugin generation from being published.

The CLI and TUI invoke plugin commands and skills through typed registrations;
plugin agents enter the canonical child-agent harness with host-intersected
capabilities. Plugin hooks compose into the CLI, TUI, proxy, and ACP hook
engines. MCP and LSP retain generation-bound ownership, and disable/update
produces explicit revocation work before the transition is acknowledged.
Project disable decisions are persisted in the host plugin catalogue and
survive manager reconstruction.

Verification used Rust 1.98.0 with `CARGO_BUILD_JOBS=4`:

- Plugin integration coverage passed 31/31, including activation, provenance,
  atomic rejection, command/hook/skill/agent routing, revocation, and durable
  disable behavior.
- `cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
  passed.
- `cargo +1.98.0 test --quiet --locked --all-targets --all-features --
  --test-threads=1` passed every non-ignored target.

Because this slice changed a cited `src/main.rs` generation, the S-105
technical-memory held-out and evaluation artifacts were regenerated against
`worktree:s063`. Their independent-review record remains rejected rather than
self-promoted. No alternate-model VDD receipt is claimed for this bootstrap
wave. Completion of this slice does not imply completion of its parent
workstream.

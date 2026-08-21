# Vendor Compatibility Research Status

The former “Claude Code Features Analysis” was a January 2026
reverse-engineering snapshot that counted strings in a vendor bundle and then
marked similarly named OpenClaudia modules as implemented. The full audit shows
that this produced false parity claims, especially for MCP, planning, sessions,
hooks, permissions, subagents, memory, reasoning, and tool loops.

This file is no longer a feature checklist or implementation authority.

## Current compatibility rules

- Compatibility is defined at an explicit protocol/schema boundary, not by
  copying identity text, private prompt wording, paths, or UI behavior.
- A compatibility claim requires a versioned fixture and an end-to-end
  conformance test through every supported frontend.
- Unsupported fields and events are rejected or surfaced, not silently parsed
  and ignored.
- Provider authentication uses documented provider flows. Subscription-client
  impersonation and inherited vendor identity prompts are not supported target
  architecture.
- Project, hook, tool, memory, plugin, MCP, and fetched text keep their real
  provenance and do not become system authority merely because a vendor prompt
  once used a reminder tag.

## Current web-search note

The default feature set contains free DuckDuckGo/Bing browser scraping and no
search-key requirement. This sentence records a backend fact needed by the
current build documentation test; it is not evidence that browser egress,
cancellation, result provenance, or completion semantics are production-ready.

## Where capability status lives

- `capabilities/registry.json` records typed maturity, entrypoints, effects,
  limitations, and executable evidence links.
- `capabilities/evaluation-corpus.json` and its digest-bound quality review
  record define repeated final-environment graders.
- `docs/binary-capability-matrix.md` is generated from the validated registry.
- `docs/full-codebase-audit-2026-08-16.md` records the detailed findings.
- `docs/production-remediation-design.md` defines the preserved outcomes and
  target contracts.
- Future compatibility matrices must add released conformance scenarios to the
  same evidence boundary rather than reintroduce prose checklists.

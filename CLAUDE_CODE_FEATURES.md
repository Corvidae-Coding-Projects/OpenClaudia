# Vendor Compatibility Research Status

The former “Claude Code Features Analysis” was a January 2026
reverse-engineering snapshot that counted strings in a vendor bundle and then
marked similarly named OpenClaudia modules as implemented. The full audit shows
that this produced false parity claims, especially for MCP, planning, sessions,
hooks, permissions, subagents, memory, reasoning, and tool loops.

This file remains because a compile-time documentation test includes it. It is
no longer a feature checklist or implementation authority.

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

- `docs/full-codebase-audit-2026-08-16.md` records current evidence.
- `docs/production-remediation-design.md` defines the preserved outcomes and
  target contracts.
- Future compatibility matrices must be generated from released conformance
  tests rather than maintained as prose checklists.

# S-047: Replace static model-name capability guesses

Status: Completed (2026-08-23)
Effort: Medium
Primary findings: F-020
Workstreams: W3
Depends on: [S-044](./044-provider-native-state-contract.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Resolve models and features from current provider capabilities with a dated fallback rather than substring assumptions.

## Implementation boundary

- Add provider discovery/metadata adapters and a cache with provenance, expiry, access-state, unknown-cost, and deprecation handling.
- Separate canonical model identity from aliases and validate thinking, tools, context, output, streaming, and pricing capabilities at selection.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Unknown/new/deprecated/limited-access models produce accurate selectable, unavailable, or unknown states without mapping to an unrelated default.
- Tests pin fallback age/provenance and prevent stale names from silently enabling unsupported features.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Implemented a typed, bounded model-catalog snapshot that separates canonical identity, aliases, account access, lifecycle, feature support, limits, pricing state, completeness, and evidence provenance. Provider-native discovery now covers Anthropic, Gemini, Ollama, and OpenAI-compatible formats with a six-hour endpoint cache; a small `2026-08-22.v1` emergency manifest expires after 30 days and cannot enable features once stale. Exact catalog evidence now drives request controls, context limits, `/models`, `/fast`, startup defaults, and proxy request validation. Local/custom providers no longer inherit an unrelated OpenAI model.

The proxy model response exposes typed catalog metadata and rejects known unavailable/retired selections, explicitly unsupported chat/tool/stream requests, and known output-limit violations while allowing genuinely unknown models without invented capabilities. The Kimi and MiniMax highspeed variants remain distinct selectable models, preserving `/fast` semantics instead of collapsing models with different operational/pricing identities.

Verification performed with Rust 1.98.0, `CARGO_BUILD_JOBS=4`, and serial test execution:

- `cargo +1.98.0 fmt --all -- --check`
- `CARGO_BUILD_JOBS=4 cargo +1.98.0 clippy --locked --all-targets --all-features -- -D warnings`
- the complete library, binary, and integration-test matrix with `--test-threads=1`; stale model-name fixtures found by the run were corrected and their affected targets rerun to green
- focused provider discovery, capability gating, proxy, pipeline, context-window, pricing, selector, CLI-process, and technical-memory evidence tests
- `git diff --check`

The artifact-bound technical-memory evaluation and rejected-review fixture were deterministically regenerated after their cited source bytes changed; validation still fails closed at the intended independent-review boundary. S-088 remains responsible for the later alternate-model VDD receipt. Completion of this slice does not imply completion of its parent workstream.

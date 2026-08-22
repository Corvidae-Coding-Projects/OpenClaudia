# S-013: Implement real progressive tool discovery

Status: Implemented and deterministically verified; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-005, F-058
Workstreams: W11
Depends on: [S-001](./001-capability-evidence-registry.md), [S-010](./010-canonical-run-context-and-events.md), [S-016](./016-mandatory-tool-effect-classification.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Advertise a bounded task-relevant tool subset without bypassing policy or pretending the full catalog is deferred.

## Implementation boundary

- Build a generation-keyed catalog over core, MCP, plugin, skill, and dynamic tools with deterministic retrieval and a measured full-catalog fallback.
- Require selected schemas to pass the same classification, capability, approval, and execution checks as directly named tools.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Prompt/tool-schema bytes fall on representative tasks without reducing needed-tool recall below the accepted baseline.
- Unknown, stale, over-cap, or directly requested names cannot bypass catalog generation or effect policy.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered architecture

- Each exact `ToolRunContext` now owns a `RunToolCatalog`. The catalog derives
  a deterministic generation from the immutable run capability generation,
  canonical name, source order, source and published schema digests, mandatory
  effect classification, and unavailable-definition records. A source change,
  including one to a currently unavailable plugin definition or to MCP prose
  removed during sanitization, rotates the generation and clears old leases.
- Provider requests publish at most 24 definitions and 32 KiB of serialized
  schemas. The stable bootstrap is `tool_search`, file read/search/mutation,
  Bash, and user-question support. At most six current-task matches and six
  bounded historical tool names are added after explicit selections. Current
  task recall precedes stale history. A catalog of at most 24 tools and 32 KiB
  may use the measured full-catalog fallback.
- The source catalog is capped at 512 definitions, 2 MiB, JSON depth 64, and
  32,768 JSON nodes per definition. Every function must have a canonical name
  and an object argument schema. Case-folded collisions are rejected before
  capability filtering, so an unavailable or malicious definition cannot
  reserve an ambiguous name.
- `tool_search` is a bounded host state transition rather than a schema-text
  injector. Its schema carries the exact catalog generation as a one-value
  `enum`; calls must echo it. Direct selection is atomic and case-insensitive,
  keyword selection is deterministic, one call activates at most eight tools
  and 16 KiB, and a run retains at most twelve explicit selections. Selection
  becomes callable only after the next host-built provider request.
- The result is a typed receipt containing catalog and selection generations,
  lease expiry semantics, canonical name, source namespace, published schema
  digest, effect, authorization requirement, misses, count, and byte totals.
  It contains no XML, function schema, or model-interpreted activation marker.
- The canonical `ToolExecutor` rejects any model-originated call absent from
  the last exact published set before argument parsing or policy admission.
  ACP applies the same admission at its outer dispatch boundary. Capability,
  effect classification, approval, hooks, blast-radius guardrails, and handler
  validation still execute normally after catalog admission; discovery grants
  no host authority.
- TUI initial and follow-up turns, the legacy REPL's OpenAI/Responses,
  Anthropic, and Gemini paths, ACP, and subagents all publish run-owned catalog
  snapshots. Subagent role allowlists are already below the fallback bounds,
  so they remain complete rather than accidentally losing role capabilities.
  The old public full-catalog builders remain explicit compatibility and
  evaluation baselines; no internal production frontend calls them.
- OpenAI, Responses, Anthropic, and Gemini receive the same canonical active
  name set. Gemini uses its current `parametersJsonSchema` declaration field
  and rewrites JSON Schema `const` constraints to equivalent one-value
  `enum`s without changing an argument property literally named `const`.
- MCP schemas accepted through the additional-definition API are treated as
  untrusted reference metadata: remote descriptions, defaults, examples,
  comments, titles, and vendor prompt extensions are removed recursively.
  Argument property names and validation constraints remain, and execution is
  conservatively classified destructive. Production MCP registration and
  dispatch remains owned by S-064; this slice does not claim it is wired.
  Plugin schema publication and execution remains owned by S-063.

## Acceptance evidence

The representative recall corpus covers Rust inspection/edit/test work,
codebase technical-memory retrieval, subagent review, cron scheduling, LSP
navigation, MCP resource discovery, and skill loading. Every required tool is
present, each request publishes at most 14 tools, and every scenario uses less
than half the serialized schema bytes of the full catalog. All four provider
request shapes publish the same exact names and generation binding.

Adversarial tests additionally prove:

- unknown, stale, malformed, duplicate, over-count, over-byte, and cumulative
  over-cap selections fail atomically;
- selection cannot be used in the same provider batch and becomes admissible
  only after the next snapshot;
- a dynamic source/schema or capability-generation change invalidates the old
  selection and published set;
- unavailable definitions still count toward catalog bounds and their schema
  changes rotate the generation;
- task relevance cannot be crowded out by historical continuity or a full
  explicit-selection lease;
- dynamic MCP prompt-like prose cannot enter host tool instructions or search
  ranking; and
- publication and selection traces carry exact run, capability, catalog,
  count, byte, selection-generation, and expiry fields.

### Rust 1.98 runner record

All Cargo commands used Rust/Cargo 1.98.0, `CARGO_BUILD_JOBS=4`, serialized
execution, and `--test-threads=1` for test harnesses. The repository policy
gate also passed its 27 Python tests, hygiene validation, locked root/fuzz
metadata, and both `cargo-deny` policies.

| Gate | Result |
|---|---|
| `cargo check --locked --all-targets` | Passed |
| `cargo check --locked --all-features --all-targets` | Passed |
| `cargo check --locked --manifest-path fuzz/Cargo.toml --all-targets` | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed with zero diagnostics after root-cause corrections |
| `cargo clippy --locked --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings` | Passed with zero diagnostics |
| `cargo fmt --all -- --check` and `git diff --check` | Passed |
| `cargo test --locked --all-targets --all-features -- --test-threads=1` | Passed across the library (2,749 passed, 0 failed, 1 ignored), binary (225 passed), every integration target, and doc targets; network-dependent tests remained explicitly ignored |
| `cargo test --locked --manifest-path fuzz/Cargo.toml --lib -- --test-threads=1` | Passed: 4 finite hermetic fuzz-harness tests |
| `cargo test --locked --all-features --test sandbox_escape_e2e -- --test-threads=1` | Passed: 11 tests |
| `cargo test --locked --all-features --test session_filesystem_capabilities_e2e -- --test-threads=1` | Passed: 2 tests |
| `cargo check --locked --all-features --all-targets --target x86_64-pc-windows-gnu` | Passed; emitted only existing target-conditional unused-code warnings |

The first complete run exposed a test-only direct process constructor in the
ACP Rust-toolchain resolver delivered for #1093. It was not a production
sandbox escape, but it violated the shared test subprocess boundary. #1095
routes it through the existing bounded `cfg(test)` command helper. The focused
boundary and ACP citation tests passed, followed by a clean complete rerun.

## Technical-memory artifact continuity

Making the old `src/main.rs` full-catalog wrapper test-only changed the exact
source digest cited by the held-out technical-memory retrieval corpus. The
evaluation was regenerated with the repository generator rather than edited by
hand. The independent-review record remains deliberately fail-closed and
`rejected`; no approval was fabricated.

| Artifact | SHA-256 |
|---|---|
| `src/main.rs` | `ef26e86a7b14e771e3444313850d10094040ae0f0c170c1708fd8076c8edcf0d` |
| `capabilities/technical-memory-retrieval-heldout.json` | `306cd701a7a015a25a4b68e5e074322a18a6095e706d0befcb81e7d1de08720a` |
| `capabilities/technical-memory-retrieval-evaluation.json` | `7ef6fad68500410590d9211a7cd854da22a5aa3fe534d5cdc30aa5397f975fbf` |
| `capabilities/technical-memory-retrieval-review.json` | `b50f5dc2083ecd73e713c5d18f728ac740da2ce63d9950350d1af88cfe5dd906` |

## Remaining boundaries

- S-064 must connect healthy MCP discovery, registration, and canonical
  dispatch to the additional-definition catalog API and prove generation
  rotation across connection health changes. S-063 owns the corresponding
  plugin/skill component publication path. Intended capabilities were not
  removed or represented as complete.
- The full-catalog builder APIs remain public compatibility/evaluation
  surfaces. A future public API version may make run ownership mandatory, but
  doing that here would be an unrelated breaking interface change.
- Keyword recall is a deterministic lexical baseline with a measured corpus,
  not an embedding service. It deliberately excludes untrusted dynamic prose.
  Additional retrieval methods must retain the same bounds, provenance,
  generation binding, and held-out recall evaluation.
- S-088 must attach the canonical alternate-model VDD receipt using the same
  harness, guardrails, capability boundary, and reality-grounding facilities
  as the builder. This deterministic verification is not represented as that
  future VDD receipt.

# S-070: Implement named remote actions safely

Status: Complete
Effort: Medium
Primary findings: F-056
Workstreams: W22
Depends on: [S-016](./016-mandatory-tool-effect-classification.md), [S-025](./025-end-to-end-secret-types-and-redaction.md), [S-048](./048-hardened-provider-http-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Make symbolic host-registered remote actions callable without exposing arbitrary endpoints, methods, headers, or credentials to the model.

## Implementation boundary

- Define each action's input/result schema, destination policy, effect, approval, idempotency/retry, deadline, cost/rate/body limits, and secret source.
- Register available actions in the canonical catalog and execute through hardened egress with typed delivery/partial-success receipts.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- A model can invoke an available reviewed action end to end but cannot choose or smuggle a different endpoint/method/header.
- SSRF, redirect, retry, timeout, cancellation, secret-redaction, and ambiguous external-success tests pass.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Replaced the disconnected webhook map with an immutable, host-owned named
  action registry that is built only from trusted home configuration. Project
  configuration cannot grant destinations or credentials, and malformed
  actions fail startup validation instead of disappearing.
- Registered `remote_trigger` in the canonical effect registry as an external
  mutation requiring the run's network and secret capabilities plus an exact,
  one-use host approval. Progressive publication exposes only the symbolic
  action name, description, and input schema; an empty registry remains
  explicitly unavailable.
- Bound the action registry into every production run root and derived
  subagent run. Registry contents participate in the capability-generation
  digest, while each run owns fresh call and concurrency counters.
- Fixed every transport-controlled field at the host boundary: POST method,
  endpoint, headers, credentials, schemas, deadline, request/response bytes,
  call count, in-flight count, attempts, and optional idempotency header. Model
  arguments cannot supply or override transport data.
- Added direct TLS transport with ambient proxies and redirects disabled,
  complete DNS-address classification before dispatch, and connection pinning
  to the validated address set. Plaintext remains an explicit opt-in for exact
  loopback services only; public, private, link-local, metadata, userinfo, and
  fragment-bearing targets fail closed.
- Added bounded retry with one stable idempotency key, cancellation and
  aggregate deadlines, capped response reads, optional output-schema
  validation, and typed complete/partial/error receipts. Once a request may
  have reached the remote service, timeout, cancellation, redirect, malformed
  response, or transport loss is reported as ambiguous partial delivery rather
  than false success or safe retry.
- Documented the trusted configuration surface and synchronized the canonical
  registry-count, tool-inventory, and progressive-catalog invariants.

## Evidence

All Cargo commands used Rust/Cargo 1.98.0 with `CARGO_BUILD_JOBS=2` and one
heavy Cargo process at a time. Complete native test execution was serialized
because the repository's process-global test-state limitation is already
tracked by issue #1062.

| Gate | Result |
|---|---|
| Named remote-action runtime fixture | Passed 10/10: progressive availability, fixed request shape, exact approval, schema and smuggling rejection, redirect ambiguity, stable idempotent retry, deadline, output validation, cancellation, concurrency/call bounds, and redaction |
| Focused remote-action/config/registry compatibility tests | Passed 145/145 before the full sweep; final catalog invariant targets also pass |
| Complete native library, binary, example, and integration coverage | Passed with only explicitly ignored network/browser tests remaining ignored. One existing worktree reconciliation test detected concurrent `.git` metadata activity during the aggregate run and passed 1/1 in isolation; the rest of the complete suite was run with that test excluded |
| Fuzz workspace check, strict Clippy, and library tests | Passed; 4/4 hermetic harness tests |
| Native strict Clippy | Passed with zero diagnostics before final documentation; repeated in the final gate |
| Windows GNU all-target/all-feature check | Passed; only the pre-existing target-specific warning set tracked by #1099 was emitted |
| Sandbox and session-filesystem capability tests | Passed 13/13; the Linux build correctly has zero Windows/macOS fail-closed cases |
| Repository policy, hygiene, metadata, and dependency policy | Passed 27/27 policy tests, zero forbidden tracked artifacts, both locked metadata graphs, and both `cargo deny` policies |
| Retrieval evidence binding | Passed 7/7 after regenerating the held-out and evaluation artifacts against the current cited source digest; the review remains explicitly rejected/unassigned rather than claiming unavailable independent verification |
| `cargo fmt --all -- --check` and `git diff --check` | Repeated in the final gate |

Artifact generation `S070-G1` is based on
`58b0845fb2dbcd0201ce83b773e720be8f6eb2ad`. The SHA-256 digest of the sorted
per-file SHA-256 manifest for all changed product, test, and generated
capability artifacts is
`825f3118bd32067eee6b28768433e8a497b883132c847dcae4d1089244896b20`.

## VDD handoff

Queue artifact generation `S070-G1`, its base revision, manifest digest,
retrieval-artifact digests, and the evidence above for S-088. The independent
verifier must run through the same harness, immutable registry, guardrails,
exact run capabilities, approval policy, budgets, reality grounding,
supervised transport, cancellation tree, and typed receipts used by the
implementation. S-088 should use another model where available. It is not yet
available, so this document records a verifier-ready handoff and does not claim
an independent approval.

The bound retrieval artifacts are:

- held-out corpus SHA-256
  `1d731329ea794e9db2d79047b6bf7c9411587d9df6f757a23691ec4a8559b8c9`;
- evaluation SHA-256
  `6401002628c4de27052ed817022d6c963fc17d2c41a75a1201c2f9bdc8de6b6f`.

## Residual boundaries

- Named actions intentionally support external-mutation POST operations, not
  arbitrary methods or destructive remote administration. A future product
  need for a different effect must define a separate reviewed contract rather
  than widening this one.
- Host configuration is the secret source in this slice. Credentials remain
  redacting typed values in memory, but operators are responsible for securing
  `~/.openclaudia/config.yaml`; project and model input cannot supply them.
- Per-run call and concurrency caps bound rate and cost exposure. This slice
  does not add a durable cross-run billing or wall-clock rate service.
- Shared web retrieval/browser egress consolidation remains S-071; S-070 does
  not claim to retrofit those independent transports.
- Completion applies only to S-070. Parent issue #1071 remains open.

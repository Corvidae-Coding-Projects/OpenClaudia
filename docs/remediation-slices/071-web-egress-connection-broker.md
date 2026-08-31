# S-071: Enforce web policy at the connection boundary

Status: Complete
Effort: Medium
Primary findings: F-102
Workstreams: W23
Depends on: [S-019](./019-explicit-session-capabilities.md), [S-048](./048-hardened-provider-http-transport.md)

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Apply DNS, address, redirect, proxy, and origin policy to the actual connection used by fetch, search, browser, and distillation.

## Implementation boundary

- Resolve/classify/pin allowed addresses while preserving TLS host verification; recheck redirects and proxies and deny private/metadata/local schemes without exact grants.
- Broker browser navigation, subresources, frames, fetch/XHR, WebSockets, workers, and downloads through the same policy.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- DNS rebinding, alternate IP, redirect, proxy, userinfo, IPv6, and browser private-network fixtures cannot escape the granted origin/address set.
- Every network receipt records redacted origin, redirect chain, final peer, policy generation, byte/time limits, and backend.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Added one operation-scoped `WebEgressBroker` for direct fetch, search,
  Chromium browser work, and model-backed distillation. Every production run
  root receives immutable exact-origin grants from trusted host configuration,
  derived subagents inherit the same authority, and the grant set participates
  in the run capability digest. Project configuration cannot widen egress.
- Made the broker authoritative for the actual direct connection: it parses
  and normalizes the requested origin, rejects userinfo and ungranted local or
  private targets, resolves and classifies every DNS answer, pins the admitted
  address set, disables ambient proxies and automatic redirects, preserves the
  TLS hostname, verifies the connected peer against the pinned set, and
  re-admits each redirect hop.
- Forced Chromium through a broker-owned loopback forward proxy for
  navigation, subresources, frames, fetch/XHR, WebSockets, workers, and
  downloads. The proxy performs the authoritative resolution and direct dial;
  browser flags disable bypass, QUIC, asynchronous DNS, and DNS-over-HTTPS,
  keep certificate verification enabled, and CDP rejects non-network schemes
  or userinfo before dispatch.
- Gave distillation a separate narrower grant derived from the configured
  provider endpoint instead of silently borrowing arbitrary browsing
  authority. Fetch, search, browser, and distillation now emit bounded typed
  results carrying redacted origin, redirect chain, actual final peer, policy
  generation, byte/time limits, and backend evidence.
- Preserved legitimate explicit local development through exact origin grants
  while default behavior remains public-network only. Documented the trusted
  configuration surface and kept capability denials typed as policy denials
  rather than misreporting them as external failures.
- Added skeptical deterministic fixtures for rebinding, mixed DNS answers,
  redirects, proxy host smuggling, userinfo, IPv4/IPv6, WSS, response bounds,
  and a real Chromium page that attempts private subresource, XHR, frame,
  WebSocket, worker, and download connections.

## Evidence

All Cargo commands used Rust/Cargo 1.98.0 with `CARGO_BUILD_JOBS=2` and one
heavy Cargo process at a time. Complete native test execution was serialized
to respect system memory and the repository's process-global test-state limit.

| Gate | Result |
|---|---|
| Canonical broker unit tests | Passed 15/15 |
| Web tool unit tests | Passed 21/21, including typed missing-authority denial |
| Web integration, SSRF, URL-validation, fetch-config, and config-validation fixtures | Passed 122/124; the two intentionally ignored browser cases passed 2/2 in the explicit real-Chromium run |
| Real Chromium escape fixture | Passed 2/2 with `OPENCLAUDIA_TEST_BROWSER=1`, covering navigation and private descendant connection attempts |
| Complete native library, binary, example, and integration coverage | Passed under `cargo test --locked --all-targets --all-features -- --test-threads=1`; the library target passed 2918 tests with one intentionally ignored live-network test and all subsequent targets exited successfully |
| Native strict Clippy | Passed with zero diagnostics under all targets and features before the final documentation-only update |
| Windows GNU all-target/all-feature check | Passed; only the pre-existing target-specific warning set tracked by #1099 was emitted |
| Fuzz workspace check, strict Clippy, and library tests | Passed; 4/4 hermetic harness tests |
| Sandbox and session-filesystem capability tests | Passed 13/13 |
| Repository policy, hygiene, metadata, and dependency policy | Passed 27/27 policy tests, zero forbidden tracked artifacts, both locked metadata graphs, and both `cargo deny` policies |
| Retrieval evidence binding | Passed 9/9 after canonical regeneration against the changed `src/main.rs`; review remains explicitly rejected/unassigned rather than claiming unavailable independent verification |
| `cargo fmt --all -- --check` and `git diff --check` | Passed; repeated in the final pre-commit gate |

The first complete native sweep found one stale source digest in the bundled
technical-memory held-out corpus after `src/main.rs` changed. The canonical
generator refreshed the held-out/evaluation binding, the focused evidence test
then passed 9/9, and a clean complete sweep passed.

Artifact generation `S071-G1` is based on
`96e465666234d6af0dbb293b2a119aece5b0a481`. The SHA-256 digest of the sorted
per-file SHA-256 manifest for the 23 changed product, test, documentation, and
generated capability artifacts, excluding this self-referential completion
record and the later machine-generated changelog entry, is
`b610008475830e2746a646d3a7fc4e388b026a2c7a60893198c303adb06a2ccc`.

## VDD handoff

Queue artifact generation `S071-G1`, its base revision, manifest digest,
retrieval-artifact digests, and the evidence above for S-088. The independent
verifier must use the same harness, immutable egress grants, connection broker,
guardrails, exact run capabilities, budgets, reality grounding, supervision,
cancellation behavior, and typed receipts used by the implementation. S-088
should use another model where available. It is not yet available, so this
document records a verifier-ready handoff and does not claim independent
approval.

The bound retrieval artifacts are:

- held-out corpus SHA-256
  `82b849adf2ced593ac0c2b5008ca2adac664ccdc5c1a7849ebbdeae36527d6c7`;
- evaluation SHA-256
  `9b546873aa713b796a6e3ebb2e8bca22f91a0121c1d5e38fa3092cff40755bb1`.

## Residual boundaries

- S-072 owns browser profile pooling, process/session resource ceilings, and
  cancellation-tree reconciliation across browser and web descendants. S-071
  establishes the connection boundary and locally supervises its broker work;
  it does not claim S-072 complete.
- Exact private origins are an explicit development/host capability. They are
  intentionally not inferred from project files, DNS aliases, browser state,
  or ambient proxy configuration.
- Browser protocol evolution and challenge pages can still produce bounded
  typed failures. This slice guarantees policy at the brokered connection, not
  universal site compatibility.
- Completion applies only to S-071. Parent issue #1071 remains open.

# S-025: Keep secrets typed and redacted end to end

Status: Implemented and adversarially reviewed; canonical VDD receipt pending S-088
Effort: Medium
Primary findings: F-015, F-022, F-034, F-079
Workstreams: W3, W14, W18
Depends on: None

Canonical sources: [full audit](../full-codebase-audit-2026-08-16.md) and [remediation design](../production-remediation-design.md).

## Outcome

Prevent credentials and granted environment values from becoming clonable/debuggable strings or raw logs.

## Implementation boundary

- Introduce non-`Debug`, redacting, zeroizing secret/header/environment capability types through config, auth, provider, TUI, event, error, and transport layers.
- Centralize error/body/header logging policy with field sensitivity, size limits, structured redaction, and secret-scanning tests.
- Keep adjacent cleanup out of this change unless it is required to preserve compilation or the stated contract.

## Acceptance

- Debug, trace, serialization, channel-error, and provider-failure tests cannot expose seeded secrets.
- Sensitive headers are materialized only at the hardened transport boundary and secret values have bounded ownership/lifetime.
- Relevant deterministic tests and trace assertions pass; attach an artifact-bound VDD receipt once S-088 is available.

## Handoff

Record changed artifact generations, commands/tests run, typed evidence receipts, unresolved risks, and any newly proposed slice. Completion of this slice does not imply completion of its parent workstream.

## Delivered implementation

- Added a central secret-capability layer. `SecretString` owns one
  reference-counted, zeroizing allocation; cloning shares the allocation;
  `Debug`, `Display`, and generic serialization emit only an opaque marker;
  deserialization rejects that marker. `OAuthToken` and `ApiKey` add their
  protocol-specific validation without exposing public string accessors.
- Replaced raw credential strings across provider configuration, Claude and
  Codex credential loading, native and MCP OAuth flows, proxy/TUI/ACP/print
  dispatch, subagents, VDD, plugins, MCP, and persistence DTOs. OAuth
  authorization codes, PKCE verifiers, and both native and MCP CSRF state
  nonces remain protected until their exact protocol boundary.
- Generic credential serialization is deliberately lossy. The few durable
  credential stores use explicit owner-only serializer DTOs whose raw access
  sites are greppable and closure-bounded. Whole credential/config file reads
  are held in zeroizing buffers while parsing or merging.
- `SensitiveHeaders` owns typed exact/bearer templates, validates values on
  insertion, hides values in formatting/serialization, and materializes
  sensitive `HeaderValue`s only while building the final request. Provider,
  OAuth, MCP, proxy, web-distillation, subagent, and VDD transports now share
  that boundary. Custom header names remain observable; values do not.
- `EnvironmentGrants` keeps policy-granted environment values opaque and
  zeroizing until installation in an authorized child command. Capability
  bindings use deterministic name/digest pairs, never raw values. Plugin MCP
  environment expansion can consume granted values only through the bounded
  capability operation.
- `SafeDiagnostic` centralizes structured JSON field redaction, common
  credential-assignment/bearer patterns, exact active-secret scanning,
  JSON-escaped secret scanning, and UTF-8-safe size limits. HTTP failure bodies
  read at most 64 KiB and retain at most 4 KiB after sanitization. Provider,
  proxy, subagent, VDD, OAuth, MCP, ACP, REPL, and print-mode failure paths use
  the policy before logging, displaying, retaining, or forwarding text.
- Provider converters no longer log complete requests/responses or embed
  malformed tool/message/content payloads, roles, token types, or function
  calls in errors. Response-stream failures are sanitized against the exact
  request headers, including the Responses SSE path. Provider base URLs and
  webhook URLs are redacted in debug/error surfaces; oversized web-response
  errors retain size/cap information without retaining a signed URL.
- Webhook registry URLs are opaque capabilities with behavioral comparison,
  and webhook error variants no longer retain the rejected URL or scheme.
  Provider configurations use custom redacting `Debug` and opaque custom
  headers.
- Updated `h2` from 0.4.15 to 0.4.16 after the final dependency audit found
  RUSTSEC-2026-0258, eliminating an unbounded empty-DATA-frame queue/panic
  path relevant to both transport safety and the host RAM constraint.

## Architecture decision

Secret flow is split into four explicit stages:

`untrusted bytes` → validated typed capability → bounded materialization →
immediate transport/persistence operation.

Secret types do not implement raw-reference conversion, public `Deref`, or
reversible generic serialization. Raw bytes are borrowed only by a
crate-internal closure at a named transport, subprocess, cryptographic, or
owner-only persistence site. This does not pretend external libraries can
zeroize every copy they make; it minimizes and identifies where those copies
can exist and ensures OpenClaudia-owned allocations zeroize when their final
capability is dropped.

Diagnostics follow a separate fail-safe path:

`untrusted error/body` → bounded read → structured/pattern/exact redaction →
bounded `SafeDiagnostic` → log/UI/channel/retained state.

The exact active request secrets travel beside the request as opaque header or
environment capabilities, allowing response failures to be scanned without
turning credentials back into application strings. Generic pattern redaction
is defense in depth, not the authority for known secrets.

## Artifact generation

- Generation: `S025-G1`.
- Baseline commit: `4c851558987f92b378464bf55265ed8e41f2eeef`.
- Source/test/manifest artifact digest: SHA-256
  `22022117f2de4c29ff7c2e9834c622d4c93de32dd9a1a26847770d1c324a133a`
  over `git diff --cached --binary HEAD -- Cargo.toml Cargo.lock src tests`
  after formatting, strict Clippy, repeated full serialized tests, residual
  searches, skeptical test review, and explicit staging. Any change in that
  artifact set invalidates this generation.
- Scope: secret ownership and validation, credential persistence, header and
  environment materialization, OAuth/PKCE state, diagnostic redaction and
  bounds, provider/converter failure paths, signed webhook/URL diagnostics,
  adversarial end-to-end tests, and the patched HTTP/2 dependency graph.

## Acceptance evidence

| Receipt | Evidence | Result |
| --- | --- | --- |
| `S025-E1` | `typed_config_auth_and_channel_surfaces_never_expose_seeded_secrets` sends seeded API keys, OAuth tokens, custom headers, and environment grants through config/auth/channel formatting and serialization surfaces. | Pass |
| `S025-E2` | `provider_failure_redacts_echoed_header_while_wire_receives_exact_value` proves the server receives the exact materialized credential while the returned failure cannot retain it. | Pass |
| `S025-E3` | `responses_stream_failure_redacts_bare_echoed_request_secret` exercises a real Responses SSE failure whose provider payload echoes the active request secret without a sensitive field label. | Pass |
| `S025-E4` | `malformed_provider_response_trace_and_error_omit_untrusted_payload` and provider-specific sentinel tests prove malformed tools, roles, content types, messages, and responses are not copied into errors or traces. | Pass |
| `S025-E5` | `environment_grant_materializes_only_for_child_process` proves an authorized child receives the exact value while debug/serialization/capability surfaces remain opaque. | Pass |
| `S025-E6` | OAuth suites prove access/refresh/code/verifier/state values are typed, state mismatch/token-type/failure diagnostics do not echo inputs, pending state is take-once without a raw map key, and generic serialization cannot reactivate a redaction marker. | Pass |
| `S025-E7` | Webhook, provider-base-URL, and bounded-web-response tests seed signed URL/query values and prove actionable diagnostics omit them. | Pass |
| `S025-E8` | `cargo deny check advisories` no longer reports RUSTSEC-2026-0258 after the locked `h2 0.4.16` update. | Pass for vulnerabilities; known unmaintained-transitive policy remains assigned to S-002. |

## Verification record

All Cargo compilation used `CARGO_BUILD_JOBS=1`; all tests used
`--test-threads=1` to respect host RAM limits.

- `cargo fmt --all -- --check` — pass.
- `git diff --check` and `git diff --cached --check` — pass.
- `CARGO_BUILD_JOBS=1 cargo check --locked --all-features --all-targets` —
  pass.
- `CARGO_BUILD_JOBS=1 cargo clippy --locked --all-features --all-targets -- -D warnings`
  — pass with the repository's strict lint profile.
- `CARGO_BUILD_JOBS=1 cargo test --locked --all-features --all-targets -- --test-threads=1`
  — pass on the final `S025-G1` implementation and dependency graph: 2,615
  library tests plus every main, integration, and binary target.
- `CARGO_BUILD_JOBS=1 cargo test --locked --all-features --test end_to_end_secret_redaction_e2e -- --test-threads=1`
  — 5 passed.
- `CARGO_BUILD_JOBS=1 cargo test --locked --all-features --test oauth_pkce_flow_e2e -- --test-threads=1`
  — 33 passed; `oauth_store_session_e2e` — 22 passed.
- Targeted provider, proxy, subagent, VDD, MCP, webhook, config, credential,
  and web suites were run repeatedly while hardening their boundaries; all
  passed before the final complete run.
- Residual searches for raw `access_token`, `refresh_token`, `api_key`,
  `client_secret`, PKCE verifier/state, header-map, environment-map, payload
  logging, and raw-exposure patterns were reviewed manually. The remaining
  raw map/string parameters are compatibility inputs converted immediately at
  their boundary; every remaining `.expose(...)` is a transport,
  subprocess/cryptographic operation, explicit persistence DTO, protected
  plugin expansion, or sanitizer scan.

The skeptical review treated changed and pre-existing tests as potentially
wrong. Repeated full runs found tests that positively required partial API-key
fingerprints, complete rejected provider URLs, and arbitrary Google content
types in errors. Those unsafe product claims were replaced with sentinel
non-disclosure assertions. That review also found a production oversized-web
error that retained signed URLs and a primary PKCE state nonce that remained a
debuggable/raw map key after the MCP path had been fixed. Both production
defects were repaired before the final green run.

## Unresolved risks and queues

- S-088 is still planned, so no honest canonical alternate-model VDD receipt
  exists for `S025-G1`. Queue the exact digest above for retrospective VDD
  using the same harness, guardrails, reality grounding, and capabilities;
  any source/test/manifest change invalidates that queue.
- External HTTP/process/serialization libraries necessarily make bounded
  copies after final materialization. OpenClaudia marks request header values
  sensitive and minimizes its own raw lifetime, but cannot claim those
  external buffers are synchronously zeroized.
- Exact scanning removes active secrets and their JSON-escaped spelling.
  Arbitrarily transformed encodings produced solely by a malicious upstream
  cannot be recognized without unsafe over-redaction or retaining more secret
  derivatives. Structured and common-pattern redaction remain defense in
  depth around the exact inventory.
- Authorization URLs must contain the PKCE state and challenge for the browser
  and callback protocol. Their internal state/verifier capabilities are
  protected and omitted from diagnostics; callers must still treat a complete
  authorization URL as sensitive transient data.
- `cargo deny check advisories` still exits nonzero for the already-audited
  unmaintained `bincode`/`yaml-rust` chain through `syntect`; the missing policy
  and migration are the canonical scope of S-002/F-009. No duplicate issue or
  new slice was created.

No additional remediation slice was created. Canonical alternate-model
verification remains S-088, and dependency/advisory policy remains S-002.

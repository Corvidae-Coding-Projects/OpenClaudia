# OpenClaudia Full Codebase Audit — 2026-08-16

Status: Complete; evidence ledger and cleanup record
Companion plan: `docs/production-remediation-design.md`
Scope: Every tracked production source, test, fuzz target, script,
configuration, prompt, documentation file, and tracked runtime artifact
Constraint: No runtime code changes in this audit pass

## 1. Audit standard

This audit does not infer production readiness from names, documentation,
types, unit tests, or successful compilation. Each file is read and its claims
are traced through callers, state, permissions, failure behavior, and
user-visible entrypoints. Cross-file behavior is recorded only after both the
producer and consumer paths have been inspected.

The audit records:

- purpose and ownership;
- production reachability;
- input, output, and state contracts;
- security and authority boundaries;
- cancellation, timeout, retry, and resource limits;
- error and partial-failure behavior;
- tests that exercise the real path;
- documentation claims and discrepancies;
- dependencies and duplicate implementations;
- action: keep, repair, consolidate, remove mechanism, or investigate.

“No finding” means the file was read and no material issue was identified. It
does not mean the subsystem is production-ready without its end-to-end evidence.

## 2. Progress ledger

| Area | Files reviewed | Files in scope | Status |
|---|---:|---:|---|
| Root manifests and build configuration | 4 | 4 (`Cargo.toml`, two locks, fuzz manifest) | Complete |
| Production Rust source | 206 | 206 | Complete |
| Integration tests | 234 | 234 | Complete |
| Fuzz targets and crate files | 12 | 12 | Complete |
| Scripts, hooks, and non-prompt configuration | 20 | 20 | Complete |
| Prompt assets | 22 | 22 (21 embedded Markdown fragments plus `src/claude_code_prompt.txt`) | Complete |
| Markdown and product claims | 68 | 68 tracked Markdown files | Complete |
| Tracked binary/runtime artifacts | 3 | 3 confirmed (`.db`, `.pyc`, `.jpg`) | Complete |

The audit contains a file-level disposition for every item in scope. Because
this was maintained as an append-only working ledger, stage-local statements
such as “pending the X audit” record what was unknown at that point in the
read; the completion reconciliation at the end of this document supersedes
those progress notes.

## 3. Validation log

| Date | Operation | Result |
|---|---|---|
| 2026-08-16 | Pre-audit `cargo fmt --check` | Passed in preliminary survey |
| 2026-08-16 | Pre-audit strict Clippy, all targets/features | Passed in preliminary survey |
| 2026-08-16 | Pre-audit full tests, all features | Passed in preliminary survey |
| 2026-08-16 | Pre-audit `cargo audit` | No vulnerabilities; informational unmaintained warnings recorded below |
| 2026-08-16 | Root and fuzz `cargo clean` | Completed; root `target` reduced from about 82 GiB to an empty directory and fuzz removed 4,310 files / 1.3 GiB |
| 2026-08-16 | Post-clean docs-only validation | Passed: exact claim checks, 23-row README/matrix parity, README YAML parse, both locked Cargo metadata graphs, formatting, and changed-file scope checks |

Pre-audit validation establishes compiler/test health only. It is not evidence
that runtime features are reachable or operational.

## 4. Confirmed findings carried into full verification

These findings were directly observed during the preliminary architecture
survey. They remain in this section until their complete producer/consumer
paths are re-read during the file audit.

### F-001 — Tool safety classification is fail-open

Severity: Critical
Status: Confirmed across the complete permission manager, registry, handlers, and frontend reads

`ToolHandler::permission_target` has a default of `None`, and missing targets
are treated as read-only/safe. Tests pin exactly five permission-target tools.
Worktree creation/removal and schedule mutations do not declare targets even
though worktree removal can merge, discard, and delete state. Comments say
these operations are “gated separately,” but the preliminary cross-path search
found no separate interactive approval gate.

The manager also scores an unknown tool—or any registered handler without a
target—as `1.0` safe for auto-allow. Its test allowlist classifies task and todo
mutation, process killing, worktree create/remove, cron create/delete,
Crosslink mutation, and MCP reads as safe or “gated separately.” This is a
manual exception list rather than a type-enforced safety declaration.

Required outcome: Mandatory risk classification with no default; deny unknown
classification; reclassify every handler; eliminate optional-manager
fail-open dispatch.

### F-030 — Permission precedence and approval scope can override a later denial

Severity: Critical
Status: Confirmed across `src/permissions.rs` and every frontend approval consumer

Persisted `AlwaysAllow` rules are evaluated before session denials, and tests
explicitly require the old allow to win. Session rules use first-match order,
so a later, more specific denial also loses to an earlier broad allow. TUI
“always” decisions store only the tool name; accepting one Bash invocation can
therefore approve every later Bash command if the frontend applies the cache
as documented. `default_allow` patterns are target-only and not paired with a
tool category.

The persistence path is normally project-local, loaded without a trust source,
size limit, symlink-safe I/O, or atomic/restrictive writes. Permission audit
events log raw command/URL/path targets and patterns at info level.

Required outcome: Explicit deny and hard host policy always dominate; approval
receipts bind tool identity, normalized arguments/resource scope, actor,
workspace, expiry, and single-use/session persistence. Store user approvals in
trusted user state, not repository-controlled files. Validate and bound rules,
write atomically, redact logs, and show effective precedence to the user.

### F-031 — “Unrestricted” tool dispatch bypasses its documented hard safety

Severity: Critical
Status: Confirmed in `src/tools/mod.rs` and `src/permissions.rs`

`PermissionManager::check` performs hard-safety checks before its
`enabled=false` shortcut, and both its documentation and tests claim that an
unrestricted/disabled manager still blocks catastrophic Bash, protected-file
writes, and model-supplied sandbox escalation. The shared tool wrapper never
calls `check` for a disabled manager: `check_tool_permission_outcome` returns
`Allowed` immediately. Every wrapper built on it—including the function named
`execute_tool_with_permission_required`—therefore bypasses those hard checks.

Required outcome: The canonical executor always evaluates typed hard host
policy, regardless of approval/bypass mode. “Unrestricted” may suppress user
prompts only for operations the host capability set actually permits. Add
end-to-end denial tests through the public executor, not only direct manager
unit tests.

### F-032 — Arbitrary tool-result text can impersonate a control-plane signal

Severity: High
Status: Confirmed in `src/tools/mod.rs` and legacy result rendering

Plan-mode entry/exit and user-question control are returned as JSON text. The
new typed enum is produced by parsing any result content's `type` string,
without binding it to the originating handler, a trusted result variant, or a
successful execution. A file, web page, MCP result, plugin tool, or ordinary
handler that returns the marker-shaped JSON can therefore be confused with a
host control event wherever callers use this parser generically.

The legacy result renderer repeats the same data-to-control mistake for
presentation: any tool text containing `@@DIFF_START@@`/`@@DIFF_END@@` is
reparsed as a privileged full-content diff, independent of the originating
handler or typed result.

Required outcome: Tool execution returns a typed result enum created by the
trusted handler/host dispatcher. Data content is never reparsed to discover
control instructions. Control events bind call ID, handler identity, current
state transition, authorization, and payload schema.

### F-033 — Missing session capabilities silently become read/write access to ambient CWD

Severity: Critical
Status: Confirmed across `src/tools/security.rs` and complete lifecycle/caller coverage

`current_context` does not require a context established at the session
boundary. It derives identity from a todo-list thread-local and, when absent,
creates a global `__default__` context whose project and working directory are
the process's current directory. `SessionIdGuard::set` similarly initializes a
named context from ambient CWD before callers can supply explicit roots. Every
new context automatically adds its project root to writable roots, so the type
cannot represent a genuinely read-only project session.

Required outcome: Session creation must explicitly construct immutable typed
capabilities before any tool becomes available; missing context fails closed.
Pass the `Arc<RunContext>` directly through async/tool calls—never infer
security identity from a todo thread-local or process CWD. Readonly modes omit
write handles. Exact capability mismatch on re-registration is an error.

### F-034 — Security context debug output contains granted environment secrets

Severity: High
Status: Confirmed in `src/tools/security.rs`

`ToolSecurityContext` derives `Debug` while storing environment grant names and
raw values in `HashMap<String, String>`. Host-approved variables can include
API tokens and cloud credentials. Any diagnostic/debug formatting of the
context exposes them, along with private paths.

Required outcome: Store granted values in redacting/zeroizing secret types;
implement a deliberate redacted debug view; pass secrets to child processes
without copying them into general traces or serializable context.

### F-035 — File tools are intentionally nonfunctional on Windows

Severity: High
Status: Confirmed in `src/tools/file/secure_fs.rs` and the completed documentation audit

Every non-Unix secure open, directory traversal, and directory-creation path
returns an error saying no race-safe backend exists. This is the safe failure
mode, but it means core read/write/edit/list/glob/grep behavior cannot be
production-ready on Windows. Meanwhile the Bash tool schema says Unix-style
commands work normally on Windows, presenting a cross-platform agent surface.
Linux additionally requires `openat2` with no compatibility fallback.

Required outcome: Publish an honest supported-platform matrix. Implement and
adversarially test handle-relative Windows filesystem capabilities (and a
safe Linux compatibility decision), or reject unsupported platforms at
startup rather than advertising tools whose calls all fail.

### F-036 — “Read before write” is not bound to the bytes being changed

Severity: High
Status: Confirmed across `src/tools/file/mod.rs` and all concrete write/edit paths

The read tracker stores only canonical path and insertion order. It does not
record inode/file identity, content hash, version, or the descriptor used for
the read. After returning content, it canonicalizes the pathname again; the
Reality Ledger then opens the pathname a third time to hash it. A concurrent
or external replacement can make the tracker approve a different file and
make the ledger's hash disagree with the content shown to the model. Only
OpenClaudia's own successful diff calls stale a marker.

Required outcome: A read observation owns a bounded snapshot identity
(capability root, normalized resource ID, descriptor metadata, full content
digest/version, range, and bytes actually returned). Mutations use optimistic
concurrency/preconditions against that snapshot and emit a new version
atomically. External changes invalidate the precondition. All ledger/tracker
paths use the same typed resource identity.

### F-037 — File discovery can be unbounded, nondeterministic, and silently partial

Severity: Medium
Status: Confirmed in `src/tools/file/list.rs`, `glob.rs`, and `grep.rs`

`list_files` has no entry/output limit. `glob` caps matches and visited entries,
but selects the first filesystem-enumeration matches before sorting, so the
returned subset is nondeterministic. It accumulates sibling directory handles
and uses recursive calls, risking descriptor exhaustion or stack depth. Failed
subdirectories are logged but the successful result does not say it is
partial. The default path `"."` is mistakenly treated as an explicit hidden
path, so root `.git`, `.cache`, and other skipped directories are traversed.

Required outcome: Discovery returns typed, deterministic, paginated results
with stable cursors, root-relative resource IDs, explicit completeness/errors,
and enforced visit/byte/time/descriptor/depth budgets. Use iterative traversal
and deterministic selection before limiting. Hidden/ignored policy is explicit
and tested from default and named roots.

### F-038 — Grep applies its match cap after potentially explosive allocation

Severity: High
Status: Confirmed in `src/tools/file/grep.rs`

`grep_one` builds every hit in a file before the caller enforces the 200-match
cap. Each hit owns its matched line and cloned before/after context. The
unbounded `context_lines` value can expand every hit to nearly the full 5 MiB
file, producing quadratic-scale memory before 200 results are selected. Even
with zero context, a file with many matching lines allocates all hits.

Required outcome: Stream matches through a global result/byte/time budget;
bound context, pattern, file count, and per-line bytes; deduplicate overlapping
context ranges; stop reading/allocating as soon as the deterministic page is
full; return typed truncation and skipped-file reasons.

### F-039 — Edit replacement and diff output have no expansion or secrecy bound

Severity: High
Status: Confirmed in `src/tools/file/edit.rs`

`edit_file` accepts an empty or arbitrarily small `old_string`, unbounded
replacement text, and `replace_all`. It first collects every match offset and
then constructs the full replacement, so a dense match can multiply file size
and memory dramatically. The success result embeds the complete old and new
strings in JSON between magic markers, returning potentially sensitive or
huge content to the model/frontend even though the file was already read.

Required outcome: Reject empty/degenerate matches, calculate replacement count
and resulting byte size before allocation, enforce file/result/diff budgets,
and apply a typed patch with snapshot preconditions plus atomic replacement.
Return a bounded redacted diff summary/reference, not full content in an
in-band marker protocol.

### F-040 — Image reads return base64 prose, not a provider image input

Severity: High
Status: Confirmed in `src/tools/file/read.rs` and string-only `ToolResult`

An image is extension-classified, base64-encoded, and embedded in ordinary
text beginning `[Image: ...]`. The tool result has no image/attachment content
block, so provider adapters cannot reliably send it as a vision input; the
model instead receives a very large base64 string. File signatures/dimensions
are not validated, and a 10 MiB file expands beyond 13 MiB before surrounding
JSON/context overhead.

Required outcome: Return a typed, signature-validated bounded attachment with
MIME, dimensions, digest, sensitivity, and provider capability negotiation.
Adapters encode native image blocks or return an explicit unsupported error;
base64 never becomes ordinary model-visible prose.

### F-041 — The suggested partial-read recovery for large files cannot work

Severity: Medium
Status: Confirmed in `src/tools/file/read.rs`

Files above 10 MiB are rejected before text offset/limit processing, yet the
error explicitly tells the agent to use `offset+limit`. For accepted files the
entire file is still read and split before selecting lines. A single line over
the 100,000-byte rendered budget yields no content because truncation happens
only at line boundaries, and there is no byte/column continuation.

Required outcome: Stream bounded line/byte ranges from the authorized handle,
support stable continuation for large/long-line files, and return typed range,
EOF, truncation, encoding, and resource-version metadata. Error recovery must
be executable and tested end to end.

### F-042 — Notebook editing can create invalid notebooks and lose the original on write failure

Severity: High
Status: Confirmed in `src/tools/file/notebook.rs`

Notebook edits are a real implemented feature, but the current contract is not
production-safe. New cells omit the stable `id` required by modern nbformat
4.5 notebooks, while individual existing cells are not schema-validated before
indexed mutation. Delete calls still require an irrelevant `new_source`
argument. The tool reads and pretty-serializes the whole notebook without a
notebook/result budget, then seeks, truncates, and rewrites the sole original
file descriptor. Disk-full, cancellation, crash, or a short write can destroy
the original notebook, and the path-only read marker cannot detect an external
change between observation and mutation.

Required outcome: Preserve notebook editing, but validate the supported
nbformat and every affected cell before mutation; generate collision-checked
stable IDs and maintain compatible format metadata; make arguments conditional
on edit mode; enforce input, cell, output, and serialized-result budgets; bind
the operation to a typed file snapshot; and atomically replace the notebook
with explicit durability/recovery semantics. Add real Jupyter round-trip,
malformed-shape, concurrency, disk-failure, and cancellation tests.

### F-043 — The advertised typed tool-result migration discards its typed data

Severity: High
Status: Confirmed in `src/tools/args.rs` and production use search

`ToolOutput` adds an optional structured JSON value and `ToolError` adds a few
categories, but Bash is the only production executor using the types. Its
public path immediately calls `into_legacy`, whose conversion retains only
`content` and drops `structured`. No production consumer reads the structured
field. Errors similarly become `(message, true)`, losing category, cause, and
retry/cancellation/partial-state semantics before registry or provider code can
act on them. This type is therefore migration scaffolding, not an operational
structured tool-result surface.

Required outcome: Preserve the migration intent, but change the canonical
handler/registry/provider/frontend boundary itself to a typed execution result.
Carry structured data, typed errors with sources and retryability, attachments,
control events, observations, redaction, usage, truncation, and partial state
end to end. Remove tuple bridges only after every caller migrates and trace/
round-trip tests prove no field is dropped.

### F-044 — Subprocess deadlines do not cover blocking stdin writes

Severity: High
Status: Confirmed across `src/tools/command.rs` and all sandbox/process callers

The shared command helper starts its deadline only after synchronously writing
the entire optional input to a pipe. A child that never reads stdin can fill
the pipe and block the agent thread forever, bypassing the advertised timeout
and cancellation polling. Input size is unbounded at this layer. “Explicit”
environment grants are applied with `Command::envs` without clearing inherited
variables here, so whether secrets are actually restricted depends on the
still-pending sandbox-command construction path.

Required outcome: Use an async or coordinated I/O supervisor whose deadline
and cancellation token cover spawn, stdin, stdout/stderr draining, exit, tree
termination, and reap. Bound stdin/output rates and bytes; return typed
truncation and timeout phases. Start children from a minimal cleared
environment plus scoped redacted grants, and bind process ownership to an
immutable run/cancellation generation rather than global session-name state.

### F-045 — Bash “read-only” auto-approval includes arbitrary mutation and execution

Severity: Critical
Status: Confirmed in `src/tools/bash/policy.rs` and permission-manager use

The auto-allow check examines the first whitespace-delimited program name, not
the semantic operation. Its “read-only” list includes unrestricted `git`,
`mount`, `ip`, `env`, `command`, Cargo/npm/build tools, and Python/Node/Ruby/
Java interpreters. It checks a few shell constructs but accepts a non-
interpreter pipeline based only on the leftmost name. Consequently operations
such as `git reset --hard`, `git push`, `npm install`, arbitrary interpreter
code, and `cat x | rm file` can be rated safe. The permissions manager uses
this result as real auto-approval evidence.

Required outcome: Never infer effects from a program-name/string denylist.
Keep shell heuristics only for warnings/defense-in-depth. Auto-approval requires
a parsed, normalized typed operation with exact subcommand/argument/resource
effects, or a sandbox capability that makes the attempted effect impossible;
unknown/compound/interpreter/build/VCS operations require scoped authorization.
Add adversarial end-to-end public-executor tests for every former false-safe
family.

### F-046 — Arbitrary shell text can manufacture “Verifier” evidence

Severity: Critical
Status: Confirmed in `src/tools/bash/mod.rs` and Reality Ledger API

Any Bash command whose normalized string contains a verification substring
such as `cargo test` receives a Reality Ledger observation with
`Authority::Verifier`. Exit code zero alone sets `passed=true`; the detector
does not prove the named quality tool was the executed operation or that its
output is authentic. `echo cargo test`, a wrapper that lies, or a command that
masks failure can therefore manufacture verifier-authority evidence. The same
path applies to background commands.

Required outcome: Verifier authority can be emitted only by a trusted,
capability-scoped quality-gate runner with a normalized executable/version,
argument set, workspace snapshot, unmasked exit status, bounded artifacts, and
trace binding. Ordinary shell commands remain untrusted command observations
regardless of their text. Grounded finalization must cite the exact trusted
verification event, not a substring-derived label.

### F-047 — Background shells have incomplete budgets, cancellation, and durable output

Severity: High
Status: Confirmed in `src/tools/bash/mod.rs`, `output.rs`, `kill.rs`, and all lifecycle callers

The process-global manager permits 50 jobs but provides no per-run duration,
CPU/memory/process/output-total budget. Line readers allocate an entire line
before applying the 1 MiB retained-output cap, so a newline-free stream is
unbounded. Output is destructively drained with no cursor/durable replay, and
stdout/stderr ordering is lost. Wait/read errors or descendants retaining pipe
descriptors can leave unreapable/uncollectable slots. Kill removes tracking
before a supervised join/reap result, and ownership relies on a todo-list
thread-local session key.

Required outcome: Preserve background work through a run-owned job supervisor
with immutable identity, scoped process capabilities, aggregate concurrency/
time/process/memory/I/O budgets, chunk-bounded streaming, durable cursor-based
output, ordered typed events, cancellation generations, confirmed tree
termination/reap, and session shutdown/resume semantics. Collision-safe opaque
job IDs and backpressure replace truncated UUID prefixes and detached threads.

### F-048 — Sandbox profiles do not enforce profile-specific least privilege

Severity: Critical
Status: Confirmed in `src/tools/bash/sandbox.rs` and all profile callers

The Linux containment foundation is substantial, but every named profile loops
over and mounts all session bind roots with their original writable/read-only
mode, and every profile receives every environment grant. Profile selection
mostly changes project entries in `PATH`, control-directory visibility, and one
Git metadata exception. A document parser, MCP stdio server, static analyzer,
hook, or quality gate can therefore receive the shell's writable project and
secret environment capabilities. The diagnostics count session grants but do
not report the effective per-profile grant set.

Required outcome: Compile each process invocation from a typed profile plus
its exact resource/effect request. Default to an empty filesystem/environment/
network set; document parsers get only input/output descriptors, analyzers get
explicit read/scratch access, hooks and MCP get declared capabilities, and
shell/worktree writes are separately authorized. Preflight and trace the exact
effective mounts, descriptors, secrets, network, syscalls, and quotas without
revealing values.

### F-049 — Protected control paths are writable when absent and writable-tree scanning races

Severity: High
Status: Confirmed in `src/tools/bash/sandbox.rs`

`.git`, `.openclaudia`, `.claude`, and other denied paths are overmounted only
when they already exist. If absent when the command is constructed, the
writable project bind lets a child create them, enabling persistent repository
or agent control state for later host execution. The up-to-one-million-entry
hardlink/mount scan runs before bind-root duplication/mount and can race a host
writer inserting an outside hardlink afterward. It is also repeated for every
command and occurs while the background manager lock is held.

Required outcome: Enforce negative/control-path capabilities structurally even
for nonexistent leaves using a race-safe mount/overlay/landlock or brokered
filesystem design. Bind a verified tree generation or remove writable broad-
tree exposure; never rely on scan-then-mount as the mutation boundary. Cache
only immutable validated capabilities and keep expensive preparation outside
job-manager locks.

### F-050 — The optional Bash path gate is both uninstalled and intrinsically bypassable

Severity: Medium
Status: Confirmed in `src/tools/bash/path_constraints.rs` and source-wide caller search

The process-global path constraint defaults disabled, and no production source
calls its exported installer. Even if installed, it whitespace-tokenizes the
shell string and recognizes only tokens beginning `/`, `~`, `./`, or `../`.
Redirection prefixes, option-attached paths, variables, expansions, separators,
symlinks, and many ordinary shell forms bypass it. Its docs claim roots are
canonicalized at check time, but implementation is lexical. It cannot safely
represent multiple concurrent sessions and can create false assurance beside
the real OS sandbox.

Required outcome: Remove this mechanism after callers use canonical typed
capabilities/OS containment; it may not be marketed or tested as a security
boundary. If a preflight UX linter remains, label it non-authoritative,
session-scope it, and prove it cannot grant or override permission.

### F-051 — Cron tools persist schedule-shaped records but never schedule or run an agent

Severity: High
Status: Confirmed in `src/tools/cron.rs`, registry schema, and source-wide consumer search

Create/list/delete metadata is implemented and the registry does disclose that
an external scheduler is required. No production component consumes
`.openclaudia/schedules.json`; `enabled`, `recurring`, `durable`, `last_run`,
and `run_count` have no behavioral path. There is no timezone, next-run,
one-shot semantic, lease, overlap/misfire policy, run identity, permission
receipt, budget, sandbox, retry, cancellation, result delivery, or audit link.
The project-local prompt store is also an untrusted instruction source, while
cron mutation is one of the registry handlers missing mandatory permission
classification.

Required outcome: Preserve and finish scheduled agent runs through a trusted
scheduler service. Store validated versioned schedule specs in user/host state
with source/provenance; bind each run to an explicit scoped noninteractive
capability and budget; define timezone/DST/misfire/overlap/retry/expiry rules;
use durable leases and idempotent run IDs; execute through the canonical agent
lifecycle/sandbox; update status atomically; and deliver redacted results and
failures. Project files may propose schedules but cannot self-authorize future
execution.

### F-052 — Crosslink mutations bypass effect classification through one argv string

Severity: Critical
Status: Confirmed in `src/tools/crosslink.rs` and registry/permission paths

Crosslink is a useful durable issue/task store, but one handler accepts a
shell-like `args` string for read and mutating subcommands. Registry permission
classification runs before this private parsing and the handler declares no
target/effect, so create, update, close, comments, dependencies, labels, and
session mutation inherit the fail-open safe classification. The storage path is
opened directly under a writable project control directory, outside secure
filesystem capabilities.

Required outcome: Preserve structured task state, but expose typed operations
whose exact database/project/session effects are known before canonical policy
and approval. Bind records/sessions to workspace and run identities; use
transactional, bounded, capability-safe storage; return typed partial/conflict
results; and prove blocker-aware planning, graph integrity, concurrency,
migration, and multi-agent isolation end to end.

### F-053 — LSP call-hierarchy follow-up actions cannot consume the preparation result

Severity: High
Status: Confirmed in `src/tools/lsp.rs`

`incomingCalls` and `outgoingCalls` require the caller to pass a complete
opaque `CallHierarchyItem`, often including server-specific `data`, from
`prepareCallHierarchy`. The preparation parser projects each item down to URI,
range, and name preview, discarding the object and `data`. The advertised
two-step tool workflow therefore cannot round-trip its own result. Similarly,
`workspaceSymbol` discards symbol names and returns locations only.

Required outcome: Preserve full bounded typed continuation objects with server/
workspace/document-version identity and opaque data, while rendering a safe
summary alongside them. Follow-up requests validate that token against the same
live server generation. Return symbol identity/kind/container and paginated
locations; add real multi-step fixtures and live opt-in tests.

### F-054 — LSP framing is unbounded and server errors become successful empty results

Severity: Critical
Status: Confirmed in `src/tools/lsp.rs`

The language server is project-influenced code. Its stdout reader sends chunks
through an unbounded channel, header lines are unbounded, and arbitrary
`Content-Length` values allocate a vector directly. Per-read timeouts and a
message-count cap do not bound bytes or a drip-fed total duration. Matching
JSON-RPC responses are returned without checking the `error` member, so failed
initialize/action requests proceed or surface as successful empty results.
Synchronous writes of a full didOpen document also sit outside a write deadline.

Required outcome: Use a spec-complete bounded async JSON-RPC transport with
maximum header/frame/queued/turn bytes, total deadlines, backpressure,
cancellation, and supervised process lifetime. Validate protocol/version/IDs;
surface server errors as typed errors; handle or explicitly reject reverse
requests at every phase; bound parsed/result structures; and never grant trust
to language-server content.

### F-055 — Process-global didOpen deduplication is invalid for fresh per-call servers

Severity: High
Status: Confirmed in `src/tools/lsp.rs`

Every request spawns a new server, but a process-global registry keyed only by
server command and path suppresses concurrent `didOpen` notifications. If two
calls overlap, the second fresh server is recorded as already knowing a file it
has never seen. Empty per-server sets are retained, and session/workspace/server
instance/generation are absent from the key.

Required outcome: Remove cross-process-instance deduplication until a real
per-workspace server manager exists. A pooled manager owns document state keyed
by server instance, workspace, URI, version, and run access; serializes or
multiplexes requests correctly; sends didOpen/didChange/didClose from actual
buffer state; and invalidates continuations on restart.

### F-002 — OpenAI Responses continuation loses native state

Severity: Critical
Status: Confirmed across request builder, stream parser, TUI loop and chat-message persistence

The request asks for encrypted reasoning content, but the session is rebuilt
from chat messages, function calls, and function results. The stream handler
does not retain general output items or the response identifier. Native
reasoning/compaction state therefore cannot be replayed as required for
lossless stateless continuation. `max` reasoning is silently mapped to
`xhigh`.

The completed pipeline trace confirms `store:false`, no `previous_response_id`,
no retention of general output items, and no persistence of returned encrypted
reasoning despite explicitly requesting it. The TUI stores only visible content,
a reasoning string and flattened function calls/results before rebuilding the
next Responses input.

Required outcome: Provider-native item persistence, response identifiers,
capability-driven parameters, protocol fixtures, and multi-turn tests.

### F-003 — Reality Ledger enforcement can be bypassed with plain final text

Severity: High
Status: Confirmed across all frontend finalization paths

Structured final decisions are validated, while ordinary assistant text is
accepted and recorded as allowed. Typed mutation decisions are added to only a
subset of subagent tool schemas. Documentation currently claims a working
structured/cited final gate across agentic entrypoints.

Required outcome: Enforce one typed finalization protocol across claimed paths
or replace the mechanism while preserving evidence-grounded output.

### F-004 — Agent/tool lifecycle remains duplicated across frontends

Severity: High
Status: Confirmed by detailed composition-root and pipeline call graph

The shared executor centralizes final local dispatch and some helper stages,
but TUI, ACP, legacy REPL, pipeline, subagent, and interception paths still own
different combinations and ordering of parsing, policy, mode restriction,
approval, hooks, execution, observation, state, and finalization.

`src/pipeline.rs` owns the TUI's provider/permission/tool path only. Legacy REPL
reuses selected request/history helpers but keeps a separate permission and tool
loop; ACP, proxy and subagents keep other dispatch paths. Even within TUI,
pre-turn orchestration and the 25-iteration loop live in `tui/app.rs`, while the
pipeline executes per-response tools and the shared executor owns only a subset.

The complete legacy controller confirms different lifecycle order even inside
one frontend: its pre-tool hook runs before hard enterprise policy, the XML
fallback bypasses the normal hook/audit/auto-learning sequence, one OpenAI path
is explicitly “unaudited,” and Gemini appends a processed result twice. Provider
follow-ups independently rebuild static tool catalogues and request settings.

Required outcome: One canonical asynchronous runtime and lifecycle pipeline.

### F-005 — Advertised deferred tool loading is not deferred

Severity: Medium
Status: Confirmed across prompt construction, provider requests, and accounting paths

Provider request builders send the complete static tool set while
`tool_search` searches that same already-supplied registry. The stable prompt
also contains a large prose tool catalogue. Its registry schema claims that a
returned XML-shaped schema makes deferred tools callable, but this handler
cannot mutate the provider's active tool set; it only returns text.

Required outcome: Real progressive discovery across core, MCP, plugin, and
skill tools, evaluated against the full-catalog baseline.

### F-006 — Multiple configured or documented features have no production consumer

Severity: High
Status: Confirmed by the exhaustive source and configuration inventory

Initial examples include team memory configuration, token stop conditions,
managed settings, MEMORY.md discovery, MCP elicitation/in-process/OAuth
surfaces, coordinator task types, and several lifecycle services. These are
repair commitments unless the audit demonstrates that the intended behavior
is obsolete or unsafe.

Required outcome: Per-feature reachability and operational acceptance matrix;
complete the feature through canonical paths rather than deleting its intent.

### F-007 — Rule injection is deprecated and selected for removal

Severity: Product decision
Status: Complete removal inventory across implementation, consumers, hooks, configuration, tests, and assets

The user has explicitly selected the legacy rule injector for complete
removal. The audit must enumerate every source, prompt, hook, config, example,
test, and documentation path before the implementation phase. Runtime code is
not modified in this audit.

The core implementation is `src/rules.rs`. Production construction/consumption
exists in the TUI launcher, ACP, chat REPL, proxy, service tool executor, and
doctor command. Four dedicated integration-test files plus unit tests preserve
the deprecated behavior. A neutral language/extension registry is also housed
in the module and is used by auto-learning; that utility must be relocated,
not accidentally deleted with the injector.

### F-008 — Structural test volume obscures missing product evals

Severity: Medium
Status: Confirmed; every test file will be classified

The repository has hundreds of separately linked integration-test files,
including many tests of derives, formatting, trivial wrappers, or source-text
shape. Conventional tests pass, but there is no equivalent representative
task-success and trace-evaluation suite for agent behavior.

Required outcome: Retain meaningful protocol/security/property coverage,
consolidate low-value structural tests, and add trace-based product evals.

### F-009 — Dependency and artifact hygiene needs an explicit policy

Severity: Medium
Status: Confirmed across both manifests, both complete lock graphs, feature trees and policy checks

Both version-4 locks parse under `cargo metadata --locked`: the root graph has
608 packages (607 checksummed crates.io packages) and the fuzz graph has 590
(588 checksummed crates.io packages plus two local packages). There are no Git
or other non-registry package sources. The root lock contains 52 names at more
than one version, adding 67 duplicate-version nodes, while Clippy globally
allows all `multiple_crate_versions` drift. Direct `axum-extra`, `tower`, and
`tower-http` have no source/test consumers; `tokio-test` and `predicates` have
no executable test consumers. The second reqwest/tower-http generations come
through the beta `crosslink` dependency. `syntect` brings the unmaintained
`bincode 1.3.3` and `yaml-rust 0.4.5` advisories.

The browser feature is on by default and increases the default dependency tree
from 498 to 560 unique packages. Its `fetch` feature permits runtime Chromium
download. Its build dependency `auto_generate_cdp 0.4.6` supplies no SPDX
expression, ships a GPL-3.0 license file, describes itself as experimental and
documents build-time retrieval from raw GitHub (the currently selected default
also enables its offline mode, which needs an explicit reproducibility test).
This is a legal/reproducibility review requirement, not a legal conclusion.
There is no `deny.toml`; `cargo deny` therefore has no license allow policy and
rejects every license under its empty default, making the license check
non-operational. Advisories still reproduce only the two unmaintained syntect
transitives; default bans and sources checks pass. The root build directory had
grown to approximately 82 GiB and the fuzz build directory to approximately
1.3 GiB before the requested clean.

Required outcome: Remove confirmed unused direct entries, set an owned MSRV and
feature/release profile, adopt an explicit reviewed license/source/advisory/
duplicate policy in CI, replace or formally resolve the experimental GPL-file
build dependency, migrate the unmaintained syntect chain, decide whether browser
download belongs in an explicit opt-in distribution, align duplicated direct/
Crosslink transport generations where upstream permits, and consolidate link
units. Record fresh build time/space for each supported profile after repair.

### F-010 — Startup intentionally ignores migration failures

Severity: High
Status: Confirmed across the crate entrypoint and every migration implementation

`main` runs all on-disk migrations before subsystem initialization but discards
the aggregate result. The comment explicitly says failures never abort startup.
Continuing into memory, ledger, transcript, or session stores after a failed
schema migration risks operating on a partially upgraded state and turns a
clear startup failure into later, harder-to-diagnose corruption or data loss.

Required outcome: Classify migrations as required or optional by store. Required
store failures stop the affected agent surface before it opens that store;
optional features become explicitly unavailable. Record migration version and
failure in the startup diagnostic trace.

### F-011 — VDD-generated text is promoted to system authority

Severity: High
Status: Confirmed across the complete VDD producer, legacy REPL, TUI, and proxy session consumers

`run_vdd_review` takes `result.context_injection` produced by the adversarial
review subsystem and appends it as a raw `role: system` message. A secondary
model output therefore gains instruction authority over subsequent tool use.
XML-like wrapping does not create an authority boundary. The TUI repeats this
promotion with a `<vdd-review>` system message. Proxy advisory mode stores the
same model-generated directive as global session context, allowing it to affect
later requests and, under F-127, unrelated callers. The producer explicitly
formats untrusted descriptions as “Address these issues” instructions.

Required outcome: Keep VDD findings as typed reference observations with
provenance. The canonical runtime decides whether a validated finding changes
the plan; model-produced text is never inserted as a system instruction.

### F-012 — Startup and legacy permission policy is duplicated and contradictory

Severity: High
Status: Confirmed across `main.rs` and all downstream legacy call sites

`main.rs` maintains a hard-coded read-only tool list separate from the registry
risk metadata. Its “always allow” cache is keyed only by tool name, so one
approval can authorize all later targets for that tool in the legacy session.
The unrestricted helper claims to allow every tool, while downstream hard
safety checks may still deny because the returned `checked` bit is false.

Required outcome: Remove frontend-specific tool classification and approval
caches. Use canonical, target-scoped approval receipts and render the actual
enforced scope to the user.

### F-013 — Generic environment configuration is broken for multiword fields

Severity: High
Status: Confirmed in `config` 0.15.25 behavior and `src/config/mod.rs`

The environment source replaces every underscore after `OPENCLAUDIA_` with a
path separator. Consequently, names such as `SESSION_PERSIST_PATH`,
`VDD_TRACKING_LOG_ADVERSARY_RESPONSES`, and provider `BASE_URL` deserialize as
`session.persist.path`, `vdd.tracking.log.adversary.responses`, and
`base.url`, not the Rust fields `persist_path`, `log_adversary_responses`, and
`base_url`. The code explicitly repairs only provider API keys. Existing tests
exercise a single-word field (`proxy.target`) and therefore do not detect the
general failure.

Required outcome: Define and test one unambiguous environment naming scheme
(normally a distinct nesting separator such as double underscore), include
every documented field in a config conformance matrix, and reject unknown
keys rather than silently accepting misspellings.

### F-014 — Persistence path validation is bypassable through a parent symlink

Severity: Critical
Status: Confirmed in `src/config/path_validation.rs`

The guard performs lexical root checks and inspects only the final target with
`symlink_metadata`. A path such as `<project>/linked-dir/state.json` passes if
`linked-dir` is a symlink to an outside directory and `state.json` does not yet
exist; the later filesystem write follows the parent symlink. This defeats both
the project-root restriction and the system-directory denylist. There is also
a check/use race even for an existing final component, and the Windows
denylist comparison is not normalized for case.

Required outcome: Open a trusted root directory and resolve/create components
without following links (platform-appropriate `openat`/handle APIs), then write
atomically through that capability. Treat a string path validator only as a
diagnostic precheck, not the security boundary.

### F-015 — Provider secrets outside `api_key` are exposed by debug output

Severity: High
Status: Confirmed in `src/config/provider.rs` and complete logging/transport call-site review

`ProviderConfig` derives `Debug`. Its typed `api_key` is redacted, but the
arbitrary `headers` map is rendered verbatim. A supported custom
`Authorization`, `x-api-key`, cookie, or signed header can therefore leak in
diagnostics or panic reports. The nearby comment claims the redaction
guarantee is structural for the configuration as a whole, which is not true.

Required outcome: Use a secret-bearing header type with redacted formatting,
centralize outbound authentication construction, and add negative logging
tests for every supported credential location.

### F-016 — Repository configuration can disable permissions

Severity: Critical
Status: Confirmed across configuration and every runtime enforcement path

`permissions.enabled: false` is accepted from `.openclaudia/config.yaml`, a
project-controlled file, and is documented as removing permission checks and
persisted deny rules. The recommended replacement,
`dangerously_disable_permissions`, does not exist anywhere in the repository.
An untrusted checkout can therefore request that the host agent discard its
approval boundary before running repository-influenced tools.

Required outcome: Permission bypass must be a host/startup decision outside
repository authority, visually persistent, auditable, and impossible to
activate through project files, hooks, model output, or tool results.

### F-017 — Token stop conditions are an unreachable feature

Severity: High
Status: Confirmed by exhaustive production-reference search

`StopConditionsConfig`, `TokenTotals`, and `StopReason` are used only in their
own unit tests and a test file named `stop_conditions_e2e.rs`. They are not a
field of `AppConfig` and no production loop invokes the predicate, despite the
module documentation saying the pipeline is its consumer. Even if wired as
written, checking only after a response can overshoot a cap by an entire model
generation.

Required outcome: Preserve token-budget stopping as a product feature. Add it
to the canonical run budget, reserve output before each provider call, enforce
wall-clock/tool/turn/cost limits too, emit a typed terminal reason, and test it
through real runtime traces.

### F-018 — Gemini and Ollama tool loops lose the call/result protocol

Severity: Critical
Status: Confirmed in request converters and the complete TUI follow-up loop

The Gemini response converter creates OpenAI-shaped tool calls, but its request
converter ignores assistant `tool_calls`, maps `role: tool` to an ordinary
Gemini user message, and never creates a native `functionResponse`. The Ollama
request converter similarly preserves only role and text, dropping assistant
tool calls, call IDs, and tool names. Both adapters can pass single-response
unit tests while failing the second request of a real agentic tool loop.

Required outcome: Store provider-native typed call/result items and test at
least a full model-call → tool execution → function-result → model-call
round trip for every provider. Native IDs, names, thought signatures, ordering,
parallel calls, errors, and resume must survive.

The pipeline additionally dispatches native Google responses only when the
provider string equals lowercase `google`; the supported `gemini` alias builds a
native Gemini request but is then parsed as SSE. Google responses receive
invented local call IDs, and the very next pipeline build discards those calls
and maps their results to ordinary user text, proving the live second turn is
broken rather than merely missing an isolated converter feature.

### F-019 — The provider abstraction destroys native agent state

Severity: Critical
Status: Confirmed across the provider module

All adapters are forced through a Chat-Completions-shaped message and response
abstraction. Anthropic thinking/redacted-thinking blocks are intentionally
skipped, Gemini thought signatures and interaction identifiers have no storage
shape, Ollama-native call structure is flattened, and the OpenAI adapter still
targets Chat Completions. This prevents lossless continuation and makes future
model behavior depend on name-based JSON patches.

Current Google guidance requires thought-signature continuity and recommends
stateful interaction IDs for efficient continuation; current OpenAI guidance
places the latest agentic models on Responses. These are protocol state, not
optional display metadata.

Required outcome: The neutral session owns user-visible semantics while each
provider adapter persists an opaque, typed native continuation lane. Protocol
fixtures must prove lossless multi-turn and compaction behavior.

### F-020 — Static model catalogues are already operationally stale

Severity: High
Status: Confirmed against official provider documentation dated 2026-08-16

The OpenAI catalogue and default fallback stop at GPT-5.5 although the current
recommended family is GPT-5.6 Sol/Terra/Luna. Google's catalogue omits stable
Gemini 3.6 Flash and 3.5 Flash-Lite. DeepSeek still advertises
`deepseek-chat`/`deepseek-reasoner` after their documented 2026-07-24
discontinuation. Anthropic's list mixes generally available and limited-access
models and retains deprecated Mythos Preview without availability metadata.
Tests assert hundreds of volatile literal names, making a passing suite
evidence of internal consistency rather than provider validity.

Required outcome: Prefer authenticated model/capability discovery with cache
age and provenance. Keep only a small versioned emergency fallback, label
availability/deprecation, and test schema/capability behavior rather than a
hand-maintained marketing list.

### F-021 — Provider HTTP policy is incomplete and duplicated

Severity: High
Status: Confirmed for model listing, chat send/retry and streaming transports

`fetch_models_with_headers` constructs a new default `reqwest::Client` per
call with no explicit request timeout, response byte limit, redirect policy,
or pagination. It forwards arbitrary custom headers, which can contain
credentials, through this separate transport. Base URL safety is assumed from
an external caller rather than enforced at the network boundary.

Required outcome: One hardened HTTP transport enforces validated destinations,
DNS/redirect policy, cross-origin secret stripping, deadlines, body/stream
limits, retry semantics, cancellation, connection reuse, and redacted traces.

The chat pipeline retries up to eleven POST attempts without a total deadline,
idempotency/cost receipt or cancellation; accepts an unbounded numeric
`Retry-After`; and returns the complete unbounded upstream error body. Gemini
JSON and all SSE text/reasoning/tool accumulators are likewise aggregate-
unbounded. Mid-stream failures are not retried or typed as partial failure.

### F-022 — Typed secrets are immediately converted back to ordinary strings

Severity: High
Status: Confirmed in provider headers and OAuth helpers

`ApiKey` protects its own formatting, but every adapter returns headers as
`Vec<(String, String)>`, recreating bearer/API credentials in cloneable,
printable strings. OAuth helpers do the same. Generic serialization emits
`[REDACTED]`, and deserialization accepts that marker as a valid real key, so a
generic config round-trip can silently replace credentials with the marker.

Required outcome: Secret values stay in a redacting/zeroizing type through the
HTTP boundary; they are inserted directly into sensitive header values and
never returned in debug-capable collections. Redacted values cannot
deserialize as credentials.

### F-023 — The Reality Ledger's “authority” is not an authority boundary

Severity: Critical
Status: Confirmed in ledger/evidence implementation

Any non-summary authority is accepted as proof, including generic `ToolResult`
JSON containing web/MCP/model-influenced text. Public append methods allow
callers to label arbitrary values `Verifier`, `Policy`, or `Filesystem`; file
hashes are not rechecked when cited; and the project-local SQLite file is
ordinary mutable workspace state. The enum records a claimed source but does
not prove provenance, freshness, relevance, or truth.

Required outcome: Treat the ledger as a trace/index, not self-authenticating
proof. Only the runtime's typed observation producers can issue provenance;
untrusted content remains data. Revalidate mutable facts at decision time and
bind evidence to the exact claim/action it supports.

### F-024 — Verification remains “fresh” after later mutations

Severity: Critical
Status: Confirmed in ledger invalidation behavior

`observe_diff` stales matching file reads and older diffs only. It never stales
command or verifier observations. An agent can run tests, edit the code, then
cite the pre-edit passing test and verifier IDs as if they validate the new
state. The final gate accepts that sequence.

Required outcome: Verification observations reference an immutable workspace
snapshot/diff digest, command, environment, and scope. Any relevant mutation
invalidates the derived verification; finalization checks that the verified
snapshot is the current one.

### F-025 — Project output style is an automatic system-instruction injector

Severity: Critical
Status: Confirmed in `src/output_style.rs` and prompt contract

`.openclaudia/output-style.md` takes precedence over the user's home style and
is inserted as system-prompt instructions. XML escaping prevents a closing-tag
trick but does not change the content's authority: a hostile checkout can put
arbitrary instructions in the style itself. This is the same unsafe trust
pattern as repository rule injection even though it has a different filename.

Required outcome: Preserve output-style preferences as explicit user/host
settings or a visibly approved project capability. Repository content cannot
silently become system authority. Include this mechanism in the rule-injector
trust-boundary removal audit without conflating legitimate user preferences
with deprecated rules.

### F-026 — Hook output is mistaken for trusted system guidance

Severity: Critical
Status: Confirmed in `src/context.rs`; call-site reachability still being traced

`ContextInjector` wraps allowed hook output in XML-escaped
`<system-reminder>` text and tells the model to treat it as harness guidance.
Escaping delimiters prevents an output string from closing the wrapper, but it
does not make commands, model output, repository text, or other hook-derived
content trusted. In the no-user-message branch the wrapper is an actual system
message; otherwise it is appended to the user's content with a system-looking
label. The same source therefore receives inconsistent and unsafe authority.

The prompt-replacement path also does not check the hook's `allowed` result. If
a caller applies both operations independently, a denied hook that returned a
`prompt` field can still replace the user's prompt. Replacement converts a
multipart user message to plain text, dropping images and other non-text
parts, while logging prompt excerpts at info level.

Required outcome: Hook results are typed observations or policy decisions, not
instructions. Denial blocks every mutation produced by that hook. Only an
explicitly trusted host capability may propose a system-instruction change,
with provenance, approval, size limits, redaction, and an audit event. User
message transformations must preserve content parts and never log raw prompt
content by default.

### F-027 — The central prompt builder has no source-authority or size model

Severity: Critical
Status: Confirmed in `src/prompt.rs`

The main prompt assembler concatenates hook output, learned preferences,
recent-work memory, discovered skill descriptions, custom instructions, and an
unescaped working-directory string into system blocks. It represents these
different sources only with Markdown headings, not enforceable provenance or
authority. Hook text is explicitly introduced as project instructions to
“follow carefully,” and learned preferences are also commands to “follow.”
The code comment acknowledges that custom instructions can originate in
project-root files and hook output, but its only control is XML character
escaping. Content later in a system string can still contradict or socially
override earlier content; position and escaping are not authority controls.

There is no request-context budget or deterministic truncation policy. Memory
read errors are silently ignored, the static tool prose is checked against
runtime registration only for the browser tool, and the test named as a
hook-override defense deliberately accepts a duplicate fake tool section.

Required outcome: Build prompts from typed `ContextItem`s with explicit source,
authority, sensitivity, freshness, and token cost. Only host/user-approved
instruction sources may enter the system/developer layer. Memory, recent work,
repository data, hook results, and tool-derived skill metadata remain bounded
reference data unless a distinct trusted capability says otherwise. Generate
tool availability from the runtime registry and test semantic authority and
budget behavior, not just substring ordering.

### F-028 — Skills are partly implemented and automatically trust project data

Severity: High
Status: Confirmed in `src/skills.rs`, `src/prompt.rs`, and source-wide consumer search

The loader automatically discovers skills from every `.openclaudia/skills`
directory between the current directory and the user's home. Their names and
descriptions then enter the system prompt. This makes merely entering a
checkout sufficient for repository-controlled text to gain system-prompt
placement, without a trust or approval step.

Several advertised fields are only parsed, not operational. `paths` has no
production caller, so automatic conditional activation is absent. Skill
`hooks` are retained as loose JSON but have no production consumer despite the
field documentation saying the host wires them on activation. `when_to_use`
and `argument_hint` likewise have no confirmed runtime behavior in the core
skills path. Model, effort, allowed-tools, and user-invocable controls do have
frontend consumers and must be preserved.

The cache fingerprints only top-level directory mtimes; editing an existing
bare skill or `SKILL.md` commonly leaves that directory mtime unchanged, so a
process can keep stale instructions until explicit invalidation. Directory
iteration is unsorted, making same-layer duplicate-name winners dependent on
filesystem order. Reads follow symlinks and accept unbounded files, names,
descriptions, and prompts.

Required outcome: Keep skills as an explicit, provenance-aware capability.
Define trusted user/managed sources and a visible project trust decision;
validate and bound packages; canonicalize contained paths; deterministically
resolve collisions; use content/file fingerprints or watchers; and implement
or remove each advertised field based on the documented product contract.
Skill activation applies scoped tool/model/effort capabilities through the
canonical runtime and cannot silently add hook or system authority.

### F-029 — Behavioral modes present prompt suggestions as operational controls

Severity: High
Status: Confirmed in the mode implementation, prompt builder, and all 19 included prompt assets

Agency, quality, scope, readonly, director, and context-pacing modes are
implemented as concatenated Markdown fragments. The `Readonly` modifier does
not itself restrict the tool registry or permission policy; the code comments
explicitly keep write-tool descriptions present and rely on the model to obey
the prose. `Director` and context pacing similarly request orchestration and
budget behavior without changing scheduler or budget capabilities.

Arbitrary modifier combinations are allowed, including all six simultaneously,
and tests celebrate that state rather than rejecting conflicts such as
readonly plus autonomous/unrestricted/director behavior. This can make the UI
claim a safety or execution mode that the host does not enforce.

Required outcome: Keep modes as useful user preferences, but separate style
from capability. Readonly/narrow scope must compile into host-enforced tool and
filesystem policy; director mode must activate the canonical coordinator with
explicit budgets; context pacing must use real context/compaction thresholds.
Reject or define precedence for incompatible combinations. The UI must label
purely stylistic axes as preferences, never safety controls.

## 5. File-by-file findings

### Root manifests and build configuration

#### `Cargo.toml`

Status: Read
Disposition: Keep and repair

Initial findings:

- Default feature set enables the heavy browser/Chromium chain for every
  ordinary build; validate whether browser support belongs in the default
  product profile.
- `axum-extra`, direct `tower`, and direct `tower-http` have no confirmed source
  consumers in the preliminary search; revalidate after complete source read.
- `multiple_crate_versions` is globally allowed with a historical explanatory
  count, so new duplicate-version drift is not detected.
- There is no repository license/dependency policy file such as `deny.toml`.
- Package description promises a universal agent harness; every provider and
  frontend therefore requires an explicit support/maturity matrix.

#### `fuzz/Cargo.toml`

Status: Read
Disposition: Keep and repair

Initial findings:

- Nine fuzz binaries are declared for truncation, SSE, request building, cron,
  path resolution, tool arguments, hooks, Anthropic conversion, and streaming
  Markdown.
- The full audit must verify that targets call production parsers rather than
  copies and that CI or a documented periodic process executes them.
- Because the fuzz crate depends on root defaults, fuzz builds may pull the
  browser feature unless `default-features = false` is set deliberately.

#### `Cargo.lock`

Status: Read completely by Cargo's locked metadata parser and an independent
package-block/source/checksum/duplicate traversal
Disposition: Keep generated lock; repair the dependency graph under F-009

- Lock format 4 contains 608 package blocks: one local package and 607
  checksummed crates.io packages. No Git/path dependency other than the root is
  hidden in the graph.
- Fifty-two crate names have multiple versions, representing 67 additional
  version nodes. The largest families are four `windows-sys` generations and
  three generations each of `getrandom`, `nix`, `rand`, `rand_core`, `syn` and
  `windows-targets` plus their platform packages.
- `crosslink 0.9.0-beta.1` retains reqwest 0.12/tower-http 0.6 beside the root's
  reqwest 0.13/tower-http 0.7 generation. `syntect 5.3.0` is the sole path to
  the two recorded unmaintained crates.
- A successful locked metadata traversal proves structural consistency, not
  package provenance, license suitability, reproducibility or runtime safety.

#### `fuzz/Cargo.lock`

Status: Read completely by Cargo's locked metadata parser and an independent
package-block/source/checksum traversal
Disposition: Keep generated lock only with an isolated fuzz profile

- Lock format 4 contains 590 package blocks: `openclaudia`,
  `openclaudia-fuzz`, and 588 checksummed crates.io packages, with no other
  source type.
- The fuzz root adds `libfuzzer-sys 0.4.13` but otherwise inherits the root's
  normal default/browser dependency surface. Dev dependencies are absent, which
  explains its smaller graph; this is still an unnecessarily broad authority
  and supply-chain surface for parser fuzzing.

#### `fuzz/.gitignore`

Status: Read in full
Disposition: Keep; extend only alongside the redesigned fuzz workflow

- Ignores `target`, `corpus`, `artifacts`, and `coverage`. No corpus or minimized
  regression artifact is tracked anywhere, so the current setup discards the
  evidence needed to make fuzz discoveries repeatable.

#### Fuzz-target file dispositions

| File | What it actually exercises | Disposition/findings |
|---|---|---|
| `fuzz/fuzz_targets/fuzz_anthropic_convert.rs` | Anthropic conversion for valid UTF-8 JSON arrays or one generic JSON value | Keep intent; add typed message generators, size bounds and semantic provider invariants |
| `fuzz/fuzz_targets/fuzz_build_request.rs` | Four provider strings × four effort strings, but only after a valid JSON-array parse | Keep intent; validate schema/capability/error properties rather than no-panic only |
| `fuzz/fuzz_targets/fuzz_cron_validate.rs` | Real public `cron_create` dispatch | Replace harness: call a pure cron/config validator or an isolated fake scheduler; current target can mutate ambient schedule state |
| `fuzz/fuzz_targets/fuzz_hook_matcher.rs` | `regex::RegexBuilder` directly, not OpenClaudia hook matching | Remove this non-product harness after replacing it with production matcher/config/event fuzzing |
| `fuzz/fuzz_targets/fuzz_json_tool_args.rs` | Real public dispatch for filesystem, shell, web, Crosslink, todo and process-control tools | Disable/remove current unsafe harness; replace with pure schema/argument parsing or a fully fake disposable capability host (F-139) |
| `fuzz/fuzz_targets/fuzz_path_resolve.rs` | Real `read_file` and `list_files` dispatch on arbitrary ambient paths | Replace with descriptor-rooted pure resolution/state-machine fuzzing and assert non-escape; do not probe the host |
| `fuzz/fuzz_targets/fuzz_safe_truncate.rs` | UTF-8 truncation at twelve fixed bounds | Keep; add prefix/equivalence/monotonic properties and arbitrary bounds |
| `fuzz/fuzz_targets/fuzz_sse_event.rs` | One parsed JSON value twice against shared Anthropic/generic accumulators | Keep intent; generate event sequences and assert bounded protocol/terminal/idempotency invariants |
| `fuzz/fuzz_targets/fuzz_streaming_markdown.rs` | One renderer with repeating fixed chunk sizes | Keep intent; fix early UTF-8-boundary termination and compare every partition with one-shot rendering under byte/time bounds |

### Crate roots and startup composition

#### `src/lib.rs`

Status: Read in full
Disposition: Keep and narrow after remediation

Findings:

- Every subsystem, including schema-only and experimental modules, is exported
  as an equally public library module. The public API communicates no maturity
  boundary and makes later consolidation unnecessarily compatibility-sensitive.
- `DEFAULT_MAX_TOKENS` is a global chat-completions-era constant; audit each
  consumer before deciding whether it belongs in provider capabilities or
  run-budget configuration.
- The rule module export is part of the rule-injector removal manifest.

#### `src/main.rs`

Status: Read in full, including unit tests
Disposition: Keep entrypoint; move orchestration into canonical runtime

Findings:

- Startup migrations are best-effort and their result is discarded; recorded
  as F-010.
- TUI startup constructs memory, prompt, hooks, plugins, MCP, rules, policy,
  permissions, VDD, analytics, and app state manually. This is a second
  composition root beside proxy/ACP/legacy paths.
- Team-memory configuration is not consulted; project memory always opens the
  ordinary `MemoryDb`.
- Rule injection is explicit: `RulesEngine` reads `.openclaudia/rules`, combines
  a hard-coded extension list, and stores the resulting text on the TUI app.
- MCP startup discovers plugin-declared servers and connects best-effort. The
  process-wide manager installation result is ignored; later installation
  failure or an already-installed manager is not surfaced.
- Full-screen TUI logging falls back to `io::sink` if its log file cannot be
  opened, eliminating all diagnostics without a user-visible warning.
- Legacy permissions use a separate hard-coded classification and broad
  tool-name “always allow” cache; recorded as F-012.
- VDD context is inserted as a raw system message; recorded as F-011.
- Authentication/provider selection and default model literals occupy a large
  fraction of the binary and are tightly coupled to current provider catalogs.
  Tests deliberately pin rapidly changing model strings rather than
  capability behavior.
- The binary uses a current-thread Tokio runtime because the Markdown renderer
  is non-`Send`. Background services and agent concurrency must be audited
  against this execution constraint.
- `chdir_to_git_root` silently changes process-global working directory and
  ignores failure. Startup configuration and relative project paths therefore
  resolve from the detected Git root rather than necessarily the invocation
  directory; this behavior needs an explicit user contract.
- The main test module includes useful cross-frontend session round trips, but
  also source-text shape checks and stale model-literal assertions that will
  obstruct provider capability modernization.

### Configuration subsystem

#### `src/config/mod.rs`

Status: Read in full, including unit tests
Disposition: Keep and repair as the canonical configuration root

Findings:

- Source insertion order is defaults, project file, home file, then
  environment; `config` 0.15.25 merges later sources over earlier ones. The
  home-level file therefore overrides the project file. That surprising trust
  order is not made explicit to users and prevents a project from overriding
  a global preference.
- The generic environment mapping breaks every multiword field; recorded as
  F-013. Provider API keys are special-cased, leaving the rest of the schema
  inconsistent.
- `API_KEY`, a generic ambient variable, is accepted as the credential for the
  OpenAI-compatible provider. Unrelated build/deployment tooling commonly uses
  that name, so provider selection can silently consume the wrong secret.
- `managed_settings_path` is skipped during deserialization and tests
  explicitly assert that enterprise managed settings are not implemented.
- App configuration does not use `deny_unknown_fields`; misspelled or obsolete
  values can be ignored instead of producing an actionable startup failure.
- Only session and VDD persistence paths are passed through filesystem path
  validation. Other configured paths require consumer-by-consumer review.
- Provider URLs are validated eagerly for every configured provider, including
  inactive providers. This is a defensible fail-fast choice but needs a clear
  support contract for offline/local configurations.
- Test-local mutexes serialize environment mutation only within this module;
  other test modules use different locks around the same process-global
  environment, so the suite is not globally race-free.

#### `src/config/provider.rs`

Status: Read in full, including unit tests
Disposition: Keep and repair

Findings:

- Base URL validation delegates remote targets to the web SSRF guard and
  deliberately permits loopback/LAN for provider names classified as local;
  the underlying DNS and redirect behavior remains to be verified in the web
  and provider clients.
- A provider called `ollama`, `local`, `lmstudio`, `localai`, or
  `text-generation-webui` may nevertheless point at any public HTTP(S) host.
  The type/name therefore does not actually establish the local trust boundary
  described by the API.
- Arbitrary header credentials are not redacted by derived `Debug`; recorded
  as F-015.
- Thinking budgets and effort strings are not validated here. The documented
  `xhigh`/`max` efforts do not receive an adaptive budget and fall back to the
  provider default, while zero explicit budgets are accepted.
- Unit tests cover URL classes and API-key redaction well, but do not cover
  secret headers, redirect/DNS changes, or the mismatch between local names
  and remote hosts.

#### `src/config/path_validation.rs`

Status: Read in full, including unit tests
Disposition: Replace the security mechanism while preserving safe configurable persistence

Findings:

- Lexical traversal and explicit system paths are tested thoroughly.
- Only the final component is checked for being a symlink. Parent-symlink and
  check/use bypasses are recorded as F-014.
- The escape hatch permits arbitrary paths outside trusted roots (other than a
  string denylist) based on a process environment variable. It logs a warning
  but does not establish filesystem authority safely.
- Tests validate string/path examples but do not execute an attempted write
  through an adversarial directory tree, which is the security property that
  matters.

#### `src/config/vdd.rs`

Status: Read in full, including unit tests
Disposition: Keep intended adversarial review; repair configuration and authority model

Findings:

- Validation rejects equal provider-name strings, but aliases or different
  provider labels can still resolve to the same endpoint/model; independence
  is not actually established.
- `max_tokens` and `request_timeout_seconds` are described as required request
  controls but accept zero. YAML non-finite floats can also evade the ordinary
  `< 0 || > limit` checks.
- Full adversary-response logging is enabled by default. Persistence,
  redaction, retention, and user visibility must be verified in the VDD
  implementation before this can be considered safe.
- Static-analysis commands are arbitrary shell strings from configuration; the
  later complete VDD audit confirmed their execution is not protected by a
  canonical capability or aggregate review budget (F-136/F-137).
- The tests cover basic defaults and scalar ranges but not provider aliasing,
  zero resource limits, non-finite numbers, or persistence confidentiality.

#### `src/config/acp.rs`

Status: Read in full, including unit tests
Disposition: Consolidate into canonical configuration; preserve the ACP limit

Findings:

- The module deliberately bypasses `AppConfig` and reparses only the project
  YAML plus one bespoke environment variable because adding a field would
  require fixing test literals. This creates a second precedence/schema system:
  it ignores the home configuration and all validation performed by
  `load_config`.
- `deny_unknown_fields` is correctly used for this isolated block, unlike the
  main schema.
- A positive iteration cap is enforced, but there is no upper bound and no
  corresponding time, token, tool, or cost budget. ACP's default 50 also
  differs from the main session default of unlimited.
- The comments present fixture churn as an architectural constraint. The
  repair is builders/fixtures and one configuration object, not another loader.

#### `src/config/guardrails.rs`

Status: Read in full
Disposition: Keep intended protections; integrate and validate canonically

Findings:

- This file is schema-only and has no validation tests. The later complete
  consumer audit confirmed partial, bypassable enforcement (F-084/F-085).
- Empty allowed paths and zero limits mean unlimited access, while all three
  top-level guardrails are absent/disabled by default. That may be compatible
  behavior but is not a production safety baseline.
- `InjectFindings` can turn generated check output into model context; its
  provenance and authority must follow the same repair as VDD findings.
- Quality gates accept arbitrary shell command strings and a zero timeout;
  repository versus host authority must be explicit at execution.

#### `src/config/hooks.rs`

Status: Read in full, including unit tests
Disposition: Keep hooks; repair schema, trust, and lifecycle integration

Findings:

- Documentation says a user can explicitly select a matcher target, but
  `HookEntry` contains only `matcher` and `hooks`. `HookMatcherTarget` is a
  standalone enum with no deserializable field connecting it to an entry.
  Searches confirm production always uses the event default.
- A project file can request `sandbox: none` or `env_scrub` in the schema even
  though comments say weakening isolation requires a separate host-startup
  trust decision. The complete executor audit confirmed repository hooks can
  weaken the effective boundary without a trustworthy host grant (F-140).
- Absent policy permits every executable name. The safety of that posture
  depends entirely on the sandbox implementation, which will be audited with
  the hook consumer.
- Command, prompt, and model hooks accept zero timeouts and unknown fields are
  not rejected.
- The schema exposes thirteen lifecycle events, but reachability and consistent
  ordering across all agent frontends remain unproven.

#### `src/config/keybindings.rs`

Status: Read in full
Disposition: Keep and repair as one validated contextual input-command map

Findings:

- The schema is a flattened string-to-action map with sensible defaults.
- Runtime trace is now complete. User map keys are not normalized on load, so
  the lookup helper's case-insensitivity claim is false for mixed-case
  configured keys. Supplying a map also replaces rather than overlays the
  defaults. The resolver/parser/consumer disconnect is recorded in F-089.

#### `src/config/memory.rs`

Status: Read in full, including unit tests
Disposition: Keep and finish team-memory integration

Findings:

- The schema promises user/team merged reads and scoped writes. A
  `TeamMemory` implementation can consume it, but startup constructs the
  ordinary `MemoryDb` and no production composition path passes loaded memory
  configuration to `TeamMemory::open`.
- The documented environment variable is broken by F-013.
- The team path is not included in `load_config`'s path validation; safe store
  opening must be capability-based as described in F-014.
- Current tests deserialize the field or instantiate `TeamMemory` directly;
  they do not prove a configured agent can use it.

#### `src/config/permissions.rs`

Status: Read in full, including unit tests
Disposition: Replace configuration authority model; preserve scoped approvals

Findings:

- Project-controlled permission disablement is recorded as F-016.
- The supposedly preferred `dangerously_disable_permissions` field exists only
  in comments, so the deprecation guidance is not actionable.
- The MCP map is fail-open for every unmentioned server. It is an optional
  allowlist layered over generic classification, not a closed capability grant.
- `default_allow` patterns are global across unlike target types (shell command
  text and filesystem paths) and are not tied to a tool, operation, root, or
  approval provenance.
- Validation rejects only exact `*` and `**` spellings as unbounded. Equivalent
  glob constructions and semantically broad scoped strings must be evaluated
  by the eventual matcher audit.
- Unit tests prove the declared fail-open semantics but do not exercise a real
  tool request from policy through execution.

#### `src/config/proxy.rs`

Status: Read in full, including unit tests
Disposition: Keep; validate at the authenticated server boundary

Findings:

- Loopback is the safe default, but host, target, and response-size values are
  not validated here. A zero response cap and externally reachable bind are
  accepted.
- The complete proxy audit confirmed non-loopback binding has no client
  authentication/origin boundary or explicit danger acknowledgement (F-126).
- Tests assert defaults only; they do not exercise binding or response limit
  enforcement.

#### `src/config/session.rs`

Status: Read in full, including unit tests
Disposition: Fold into a canonical bounded-run policy

Findings:

- The default `max_turns` is unlimited. Only legacy chat loops were found as
  consumers; ACP uses an independent default of 50 and other runtimes remain
  to be checked.
- `timeout_minutes`, the token warning threshold, and output token limit are
  not validated. Zero timeout and non-finite/out-of-range YAML floats are
  accepted.
- Token tracking is observation/warning configuration, not a hard budget. The
  unreachable stop-condition feature is recorded as F-017.
- Tests cover two fields and do not verify timeouts, limits, provider usage
  accounting, cancellation, or persistence.

#### `src/config/stop_conditions.rs`

Status: Read in full, including unit tests
Disposition: Keep the intended feature; replace the disconnected predicate with canonical budgets

Findings:

- The production consumer claimed by module documentation does not exist;
  recorded as F-017.
- Exact-cap totals do not stop the run, and checks occur only after spend.
  This is accounting semantics, not a hard preflight budget.
- Zero caps are accepted and would allow one call/response before stopping if
  wired literally.
- Tests called end-to-end elsewhere exercise the pure predicate only.

#### `src/config/webfetch.rs`

Status: Read in full, including unit tests
Disposition: Keep distillation as an explicit data-boundary feature; consolidate domain logic

Findings:

- Host parsing/domain matching is knowingly duplicated from `tools::web`, so
  security behavior can drift between prompt bypass and actual fetching.
- Distillation may send fetched content to a second provider/model. The config
  exposes no explicit cross-provider data disclosure policy, redaction, or
  provenance behavior.
- `max_distillation_bytes` accepts zero and is a byte cap rather than a token or
  cost budget.
- The built-in domain list bypasses user approval for all content on exact
  hosts and subdomains. Domain ownership does not imply that every page is
  trusted against prompt injection; SSRF safety and content authority must
  remain independent checks.
- Tests cover local normalization/truncation, not redirects, DNS changes,
  permission prompts, content isolation, or actual secondary-model dispatch.

### Provider subsystem

#### `src/providers/mod.rs`

Status: Read in full, including unit tests
Disposition: Replace the flattening trait with explicit protocol capabilities

Findings:

- The trait defaults `supports_streaming` to true and silently ignores thinking
  configuration unless overridden. New adapters therefore claim a capability
  and discard configuration by default rather than failing closed.
- `ProviderKind` is described as the typed set of providers but omits Ollama
  and every generic/aggregate provider. Separate string lists, aliases, model
  prefix inference, passthrough exceptions, default models, and adapter
  singletons can and do drift.
- All OpenAI-compatible aliases resolve to the same adapter reporting the name
  `openai`; the runtime cannot distinguish OpenRouter, local servers, or
  OpenCode when choosing capabilities and reasoning controls.
- Provider authentication exits the typed secret at `get_headers`; recorded as
  F-022.
- Model-list fetching lacks transport hardening and pagination; recorded as
  F-021.
- Default response-text helpers discard non-text/native output items. Usage
  extraction mixes provider-specific meanings in one four-counter structure.
- The tests are extensive at conversion-unit level but do not make live or
  recorded multi-turn protocol traces the support boundary.

#### `src/providers/api_key.rs`

Status: Read in full, including unit tests
Disposition: Keep secret validation; replace exposure/serialization design

Findings:

- Empty, control, non-ASCII, and overlong values are rejected and direct
  `Debug`/`Display` formatting is redacted.
- Raw access remains a safe public `as_str`, while a second accessor is marked
  Rust `unsafe` despite having no memory-safety invariant. That annotation
  cannot enforce the logging promise.
- The type is cloneable and does not zeroize memory.
- Redacted serialization followed by valid deserialization can silently create
  the credential `[REDACTED]`; recorded with the ordinary-string header issue
  in F-022.

#### `src/providers/model_catalog.rs`

Status: Read in full, including unit tests; compared with official current docs
Disposition: Replace large volatile lists with discovery and a small sourced fallback

Findings:

- Confirmed catalogue drift is recorded in F-020. Primary evidence:
  [OpenAI current models](https://developers.openai.com/api/docs/models),
  [Google current models](https://ai.google.dev/gemini-api/docs/models),
  [DeepSeek change log](https://api-docs.deepseek.com/updates), and
  [Anthropic model deprecations](https://platform.claude.com/docs/en/about-claude/model-deprecations).
- Entries carry no capability, context/output limit, API surface, access tier,
  release status, retirement date, or last-verified provenance.
- The fallback for an unknown provider is an OpenAI model ID, which is unlikely
  to be meaningful for an arbitrary compatible server.
- The bulk of this file and its tests is hand-maintained data churn that does
  not improve protocol correctness. The useful fallback behavior should be
  preserved in a smaller verified mechanism.

#### `src/providers/openai_compat.rs`

Status: Read in full, including unit tests
Disposition: Keep shared behavior, replace model-name JSON patching with capability descriptors

Findings:

- A single chat-completions body is mutated with provider-specific fields based
  on model-name string tests. This overwrites same-named caller extras and
  cannot negotiate changing provider capabilities.
- OpenAI `max` effort is always rewritten to `xhigh`, although current GPT-5.6
  exposes `max` as a distinct supported setting; older models differ.
- Non-stream responses are only shallowly validated: any non-empty role is
  accepted and even an empty `tool_calls` array counts as message payload.
  Streaming chunks are entirely pass-through.
- Invalid-response errors interpolate complete provider payloads, which can
  disclose user/model content in logs or diagnostics.
- Bearer headers are materialized as ordinary strings (F-022).

#### `src/providers/openai.rs`

Status: Read in full
Disposition: Replace Chat Completions wrapper with a Responses-native adapter

Findings:

- This is a 75-line delegation wrapper around `OpenAiCompatibleAdapter`; it
  adds no native OpenAI state behavior.
- It targets `/v1/chat/completions`, while current frontier models and agentic
  features are documented on Responses. The separate, lossy Responses path
  identified in F-002 is not represented by this adapter.
- After callers migrate to a capability-driven adapter, this boilerplate
  wrapper is a legitimate consolidation candidate; OpenAI support itself is
  not.

#### `src/providers/deepseek.rs`

Status: Read in full
Disposition: Consolidate wrapper after preserving DeepSeek protocol behavior

Findings:

- This thin wrapper selects endpoint, thinking injector, and model-list flag.
- Its behavior is tested through shared JSON-shape tests rather than recorded
  DeepSeek protocol fixtures. The catalogue includes now-discontinued aliases.

#### `src/providers/qwen.rs`

Status: Read in full
Disposition: Consolidate wrapper after preserving Qwen protocol behavior

Findings:

- This thin wrapper selects an explicit `enable_thinking` injector and reports
  model listing unsupported.
- Model-version capability differences are delegated to one unconditional
  boolean field, with no server negotiation or full tool-loop fixture.

#### `src/providers/zai.rs`

Status: Read in full
Disposition: Consolidate wrapper after preserving Z.AI protocol behavior

Findings:

- This thin wrapper selects a versionless endpoint and name-based GLM thinking
  behavior.
- Preserved thinking is represented only as outgoing config; no provider-native
  reasoning state is stored across turns.

#### `src/providers/kimi.rs`

Status: Read in full
Disposition: Consolidate wrapper after preserving Kimi protocol behavior

Findings:

- This thin wrapper delegates all behavior to hard-coded K2.5/K2.6/K2.7 model
  name branches.
- Unsupported thinking requests produce warnings rather than typed capability
  feedback to the caller, and no end-to-end continuation test is present.

#### `src/providers/minimax.rs`

Status: Read in full
Disposition: Consolidate wrapper after preserving MiniMax protocol behavior

Findings:

- This thin wrapper delegates adaptive/reasoning-split fields for exactly one
  name, `MiniMax-M3`.
- There is no negotiated behavior or recorded provider fixture to establish
  that current tool, reasoning, usage, and streaming semantics remain valid.

#### `src/providers/anthropic.rs`

Status: Read in full, including unit tests
Disposition: Keep Anthropic support; preserve native blocks instead of flattening

Findings:

- The checked conversion path correctly preserves ordinary Anthropic
  `tool_use`/`tool_result` linkage and rejects malformed tool arguments.
- Thinking and redacted-thinking response blocks are intentionally skipped
  during normalization. They therefore cannot be replayed for native
  continuation (F-019).
- Unknown stop reasons are rewritten to ordinary `stop`. Current Claude Fable
  5 returns `stop_reason: refusal` as a successful response, so refusal can be
  misrepresented as normal completion; see
  [Anthropic's Fable/Mythos integration guide](https://platform.claude.com/docs/en/about-claude/models/introducing-claude-fable-5-and-claude-mythos-5).
- The adapter logs complete transformed requests at debug and complete invalid
  responses/blocks at warning, exposing workspace/user content to logs.
- Top-level JSON Schema combinators are removed and their branch properties
  merged. This changes `oneOf`/`anyOf`/`allOf` semantics and can teach the model
  an invalid tool contract even if execution later validates strictly.
- Public compatibility helpers still substitute empty/default values or return
  an empty message list on malformed history, while the hot path is stricter.
  Their remaining callers must be migrated or removed.
- Transformed usage drops cache counters and manufactures a local creation
  timestamp; the raw extractor and normalized response expose different
  accounting fidelity.

#### `src/providers/google.rs`

Status: Read in full, including unit tests
Disposition: Rebuild around current Gemini interaction/function-call protocol

Findings:

- Multi-turn tool protocol loss is recorded as F-018.
- The current default Gemini 3.5 model is sent legacy `thinkingBudget`; Google's
  current migration guide says to use `thinking_level`, preserve encrypted
  thought signatures, and include matching function call/response IDs. See
  [Google's Gemini 3.5 migration checklist](https://ai.google.dev/gemini-api/docs/whats-new-gemini-3.5).
- The adapter uses stateless `generateContent` only and has no shape for
  `previous_interaction_id` or native thought signatures (F-019).
- Synthesized IDs repeat as `call_0_<name>` across turns, are not native IDs,
  and can contain unvalidated function-name text. The response envelope itself
  receives a random ID on each parse.
- Only the first candidate is used. Most finish reasons are rewritten to
  `stop`, and the normalized model is the literal `gemini`, losing the actual
  model and termination detail.
- Model text is interpolated directly into an endpoint path without a typed or
  encoded path-segment boundary.
- The raw text extractor silently ignores unsupported parts while the normal
  transformer rejects them, producing consumer-dependent behavior.
- Debug logging records the complete request body.

#### `src/providers/ollama.rs`

Status: Read in full, including unit tests
Disposition: Keep local inference; repair native tool/multimodal/auth semantics

Findings:

- Multi-turn tool history loss is recorded as F-018.
- Response tool IDs and normalized response IDs are newly random on every
  parse, undermining deterministic persistence and replay.
- The adapter rejects image content even though current Ollama models/API can
  support vision; support should be capability-driven rather than globally
  discarded.
- It always ignores the supplied API key. A configured LAN/remote Ollama server
  that requires authentication cannot use the common credential path.
- Non-stream `done: false` is presented as a `length` finish instead of a
  partial/incomplete state.
- Full request bodies are debug-logged, and invalid response errors embed
  complete model payloads.

### Grounding, decisions, and response policy

#### `src/evidence.rs`

Status: Read in full
Disposition: Keep evidence hydration API only after provenance semantics are repaired

Findings:

- “Authoritative” means only “not model summary and not marked stale.” User,
  generic tool, policy, filesystem, command, git, and verifier records are all
  accepted without claim-specific provenance; recorded as F-023.
- Staleness is a stored flag rather than a revalidation of mutable state.
- The optional variant makes an empty evidence set valid by construction;
  callers must not mistake it for proof.

#### `src/decision.rs`

Status: Read in full
Disposition: Keep typed decisions; replace textual patch/evidence heuristics

Findings:

- Typed inspect/edit/command/final variants are a useful control shape.
- An edit requires at least one file observation, but path matching accepts
  either path as a suffix of the other. Reading `foo.rs` can therefore satisfy
  a patch claim for `src/foo.rs`, and distinct same-named paths are ambiguous.
- Patch targets are extracted from a few textual diff markers. Renames,
  alternate patch formats, path normalization, and actual applied targets are
  not bound to the validated decision.
- Any unrelated authoritative evidence is enough for `RunCommand`; relevance,
  command risk, permissions, and target capabilities are outside this gate.
- The patch itself is a model-provided string rather than a typed mutation
  plan linked to the execution result.

#### `src/task_spec.rs`

Status: Read in full
Disposition: Keep the typed user-task reference

Findings:

- Construction correctly requires a user-authority `UserTask` observation.
- The later renderer embeds task content inside a system message, undoing the
  useful authority distinction; the task itself should remain user-authority
  context.

#### `src/thinking.rs`

Status: Read in full, including unit tests
Disposition: Replace keyword/env compatibility magic with explicit run effort

Findings:

- The presence of `ultrathink` or related phrases anywhere in a user string
  silently changes resource use. Quoted file/data content can trigger it
  accidentally, and multipart user content is not scanned consistently.
- Generic `MAX_THINKING_TOKENS` and Claude-Code-specific environment variables
  form another configuration path outside `AppConfig`, with invalid values
  silently ignored.
- Effort aliases and a fixed 31,999-token Anthropic budget duplicate and
  conflict with `ThinkingConfig` and each provider's current capabilities.
- Tests mutate process-global environment without a mutex and incorrectly
  claim tests in a module run single-threaded; they can race under Rust's normal
  parallel test runner.
- Preserve explicit “spend more reasoning” user intent through a typed run
  setting and visible budget impact, not magic substring detection.

#### `src/output_style.rs`

Status: Read in full, including unit tests
Disposition: Keep user style preferences; remove automatic project authority

Findings:

- Project-to-system instruction escalation is recorded as F-025.
- Project style takes precedence over the user's style, reversing the safer
  trust order.
- XML escaping is documented as an injection defense, but the entire payload
  is intentionally an instruction; escaping delimiters does not constrain its
  meaning.
- Save/clear use ordinary relative filesystem paths and check-then-act logic,
  inheriting the safe-storage work in F-014/W15.
- Read errors are reduced to no style after a log warning, so the user can
  unknowingly receive a different response contract.
- CWD-mutating tests restore manually rather than with an RAII guard, leaving
  process state vulnerable if setup panics.

#### `src/ledger.rs`

Status: Read in full
Disposition: Keep an evidence trace; replace claims of self-authenticating authority

Findings:

- Authority/provenance defects are recorded as F-023 and stale verification as
  F-024.
- Path equality again uses ambiguous bidirectional suffix matching, so
  mutations can stale the wrong same-named path or fail to model exact roots.
- Full user tasks, file excerpts, command output, diffs, and tool JSON are
  persisted without encryption, retention, redaction, or aggregate size
  limits. This is a long-lived secret/privacy and disk-growth surface.
- The project ledger falls back to a per-user path keyed only by session ID;
  project identity is absent, permitting cross-project collision if IDs are
  reused.
- Fallback occurs only when directory creation fails, not when opening the
  SQLite file fails after successful directory creation.
- Schema initialization writes version 1 unconditionally rather than rejecting
  or migrating a future/incompatible schema.
- A process-global `Arc<Mutex<...>>` registry and synchronous SQLite I/O sit on
  async agent paths. Concurrent, out-of-order guards for the same session can
  restore the wrong active ledger.
- The redundant SQL authority/timestamp columns are not cross-checked against
  deserialized JSON on load.

#### `src/final_gate.rs`

Status: Read in full, including unit tests
Disposition: Replace natural-language keyword policing with typed claims and trace assertions

Findings:

- Natural-language success detection is a short English keyword/negation
  heuristic. Equivalent wording bypasses it and innocent words can trigger it.
- Test-command matching uses substring search over joined argv. Commands such
  as `echo cargo test`, lookalike executable text, `--no-run`, or a limited
  subset can be misclassified as a successful test of the claimed state.
- File claims are guessed from whitespace tokens and a fixed extension list;
  claims without literal paths are invisible, while suffix path matching is
  ambiguous.
- A public `Verifier` boolean is treated as proof, and its command/snapshot is
  not cryptographically or structurally linked to the cited command result.
- The gate requires verification even for tasks where verification is not
  meaningful, encouraging fabricated “not run” records rather than a typed
  not-applicable outcome.
- Most factual claims are not parsed at all. The large test suite pins the
  heuristic examples, not general grounded truthfulness.

#### `src/grounded_loop.rs`

Status: Read in full, including unit tests
Disposition: Keep provenance-aware context intent; integrate it in the canonical runtime

Findings:

- Plain final text explicitly bypasses grounded validation and is recorded as
  an allowed policy decision; this is F-003's direct implementation.
- Pre-edit verification remains eligible after edits (F-024).
- `request_messages_with_grounding` embeds raw user task content and ledger
  labels into a newly created `role: system` message, elevating lower-authority
  data rather than representing it as typed reference context.
- `GroundedPromptPacket` contains memory, summaries, and provider history, but
  the renderer does not render those fields. The advertised hierarchy is
  mostly prose rather than a complete context assembler.
- Ledger setup/observation failures are often warnings returning `None`; the
  same API value can mean already installed or failed to install.
- Generic tool results are truncated to 16 KiB but then labeled Tool authority
  even when their content came from untrusted web/MCP sources (F-023).
- Empty final content returns success without opening or recording the ledger.
- A quality-gate shell string is reconstructed with `shlex` for evidence,
  which may not represent the command semantics actually executed.

#### `src/context.rs`

Status: Read in full, including unit tests
Disposition: Keep typed context assembly intent; replace instruction-splicing APIs

Findings:

- XML escaping in `wrap_system_reminder` is a serialization measure, not a
  semantic prompt-injection defense. Allowed hook output can still contain
  hostile or irrelevant instructions and is explicitly described to the
  model as trusted harness guidance (F-026).
- `ContextInjector::inject` ignores denied hook payloads, but
  `apply_prompt_modification` has no equivalent `allowed` check. Its safety
  depends on every caller remembering an unstated ordering invariant.
- Hook prompt replacement discards multipart user content by replacing the
  entire message with one text part. Its info log includes up to 512 bytes from
  both the old and new prompt, creating an avoidable privacy/secret leak.
- There is no aggregate or per-hook context-size limit. A hook can substantially
  inflate a request or crowd out higher-priority context.
- The same reminder becomes a real system-role message when no user message is
  present, but user-role embedded text otherwise. Authority therefore depends
  on incidental message shape.
- `inject_system_prefix`, `inject_system_suffix`, and `inject_all` accept
  arbitrary strings for direct system-context insertion. `inject_all` is
  explicitly documented for a rules engine or plugin and belongs in the rule
  injector removal manifest.
- Denial information is removed from model context entirely. The durable
  replacement is a typed policy event and frontend status, not denial text
  masquerading as model guidance.
- The 1,370-line file contains extensive escaping and shape tests, but no test
  that establishes source authority, denied prompt-mutation behavior,
  multipart preservation, log redaction, or a context budget.

#### `src/prompt.rs`

Status: Read in full, including unit tests
Disposition: Replace string concatenation with typed, budgeted context assembly

Findings:

- Hook output is inserted as `## Active Instructions` with a direct instruction
  to follow project hook text carefully. This confirms F-026 at the central
  system-prompt boundary.
- Learned preferences and recent-work memory are inserted into the system
  suffix without source, confidence, sensitivity, staleness, or size metadata.
  A stored inference can therefore become a durable instruction.
- Skill descriptions are loaded during prompt construction and tell the model
  to inject a skill prompt as its next action. Exact loading trust, ordering,
  and activation behavior must be traced through `src/skills.rs` and callers.
- The comment for `custom_instructions` states that input may come from session
  config, CLI arguments, hook outputs, and user-controlled project-root files.
  All are promoted to system authority. XML escaping only protects the
  serializer; it does not neutralize instruction content (F-027).
- The working-directory value is interpolated directly into Markdown three
  times. Filesystem names can contain newlines, so even nominal environment
  metadata can alter prompt structure. It should be a structured, quoted
  observation rather than an instruction string.
- There is no aggregate token/context budget, priority-based selection,
  sensitivity filter, truncation record, or diagnostic for omitted dynamic
  context. Memory database failures are silently treated as empty context.
- Tool instructions come from static prompt fragments rather than the actual
  tool registry. The only feature-parity assertion removes/checks
  `web_search`; every other tool can be advertised when absent or omitted when
  present.
- The no-browser variant finds section boundaries with a runtime `expect`, so
  a prose edit can make production prompt construction panic.
- The test claiming later hook content cannot override identity or tools checks
  only relative string order. Another test explicitly accepts an injected
  duplicate `## Your Tools` section and fake tool description.
- The stable/dynamic Anthropic caching split is structurally sensible, but
  cache correctness and actual adapter use still require call-site and
  provider tracing. The hard-coded byte capacities are allocation hints, not
  model-context limits.
- The 874-line file devotes most of its tests to marker presence, ordering, and
  preset differences. It lacks adversarial authority, provenance, context
  exhaustion, secret redaction, stale-memory, and registry-parity coverage.

#### `src/skills.rs`

Status: Read in full, including unit tests
Disposition: Keep and complete skills; replace automatic project trust and stale cache

Findings:

- Discovery walks all ancestors from the current directory to the user's home,
  then the prompt builder includes every discovered name and description in a
  system block. There is no repository trust grant, capability receipt, or
  source label at the model boundary (F-028).
- The module claims project skills override user skills and managed policy
  overrides both. Within a layer, however, `read_dir` output is unsorted and
  first-name-wins deduplication makes duplicate resolution nondeterministic.
- Managed “policy” skills can be disabled by an ordinary process environment
  variable. That may be an intentional host escape hatch, but it is not an
  enforceable administrator policy boundary as the comments claim.
- The mtime cache watches only each top-level skills directory. In-place edits
  inside packaged subdirectories—and usually edits to existing bare files—do
  not update that directory mtime, so live sessions retain stale skill content
  unless another component calls `invalidate_cache`.
- Directory enumeration failures return an empty vector without a diagnostic.
  Parse failures warn, but a missing/unreadable skill directory and a genuinely
  empty directory are indistinguishable.
- Candidate directory and Markdown symlinks are followed. There is no
  canonical containment check, file-type policy, maximum file/frontmatter/body
  size, maximum skill count, or validation of name, description, model, effort,
  allowed-tool identifiers, and hook schema.
- Frontmatter termination uses the first `---` substring rather than a complete
  delimiter line, so valid scalar content containing that sequence can be
  split incorrectly.
- Non-string entries in `allowed_tools` and non-sequence/non-string values are
  silently discarded. Unknown YAML fields are accepted, making misspellings
  look successful.
- Source-wide consumer tracing found no production use of
  `skill_matches_path`, `SkillDefinition.paths`, or `SkillDefinition.hooks`.
  The conditional-activation and activation-hook claims are therefore
  incomplete, not stale features to delete. `when_to_use` and
  `argument_hint` also lack a confirmed core-skills consumer.
- `allowed_tools`, `model`, `effort`, and `user_invocable` do have TUI/CLI
  consumers. Exact restoration/scoping behavior remains to be audited in those
  frontends.
- Tests use fixed global temporary filenames and mutate process-global
  environment variables while incorrectly claiming Rust's default test runner
  is single-threaded. They can race with sibling tests and conceal cache state
  leakage.

#### `src/rules.rs`

Status: Read in full, including unit tests; all production/test symbol consumers searched
Disposition: Remove the rule injector; relocate only the neutral file-type utility

Findings:

- `RulesEngine`, `Rule`, filename-to-language dispatch, Markdown loading,
  combination, reload, and tool-input extension inference exist solely to
  select and inject project rule text. They are the deprecated mechanism the
  user explicitly selected for removal.
- Unknown rule filenames become global rules. Entering a project therefore
  causes every arbitrary `.openclaudia/rules/*.md` file to apply broadly,
  without frontmatter, trust approval, size limits, deterministic ordering, or
  symlink containment.
- Directory enumeration is unsorted and flattened I/O errors are discarded, so
  prompt order and partial loading can vary without a complete diagnostic.
- Rule files are unbounded and read verbatim. Language association is inferred
  from a filename prefix, making typos silently global rather than invalid.
- Tool recognition uses Claude-style case-sensitive names (`Write`, `Edit`,
  `Read`, `Glob`) while this repository's core tool names are generally
  lowercase/snake_case. Whether each frontend normalizes names must be checked
  at its consumer; otherwise conditional rule inference is nonfunctional on
  some canonical paths.
- `LANGUAGES`, `extension_to_language`, and `is_known_extension` are neutral
  file-type utilities. `auto_learn.rs` consumes `is_known_extension`, so these
  must move to a non-rule module with their relevant tests rather than being
  deleted.
- `extract_extensions_from_tool_input` is consumed only by rule-selection
  paths in proxy/tool-executor code and should leave with those paths. Its large
  dedicated test matrix does not justify retaining the deprecated feature.
- Source-wide search enumerated constructors/consumers in `src/main.rs`,
  `src/acp.rs`, `src/cli/chat_repl.rs`, `src/proxy.rs`,
  `src/services/tool_executor.rs`, and `src/cli/commands/doctor.rs`.
- Dedicated integration suites are `tests/rules_context_e2e.rs`,
  `tests/rules_accessors_e2e.rs`, `tests/rules_engine_deep_e2e.rs`, and
  `tests/extract_extensions_matrix_e2e.rs`. Their contents still require full
  file-by-file reading before final deletion/migration decisions.

#### `src/modes/mod.rs`

Status: Read in full, including unit tests
Disposition: Keep user-facing modes; enforce capability-bearing modes in the host

Findings:

- `BehaviorMode` only assembles prompt fragments. No permission, registry,
  filesystem, coordination, or budget capability is produced here, so
  readonly/director/context-pacing semantics depend on model compliance
  (F-029).
- `BehaviorMode::default` is autonomous/pragmatic/adjacent. Autonomy is safe
  only when the canonical host policy—not a prompt—still bounds side effects.
- `add_modifier` accepts every combination and preserves insertion order. No
  compatibility matrix or precedence exists; a test intentionally stacks
  bold, debug, methodical, director, readonly, and context-pacing together.
- Preset metadata is duplicated across `SUPPORTED_PRESETS`, `FromStr`,
  `from_preset`, descriptions, and `list_presets`. Tests cover several pairings
  but not one canonical registry spanning CLI token, serde token, axes,
  capability effects, and description.
- Preset/modifier serde tokens intentionally differ from their display and
  `FromStr` tokens (`preset-debug` versus `debug`, for example). This may be
  valid wire compatibility, but persisted/config consumers must document and
  test the distinction.
- The garbage-input test lists several near misses but only asserts a subset
  selected by a conditional, so its prose overstates what it actually covers.
- Most tests prove enum/substring uniqueness and prompt order, not that modes
  produce the advertised agent behavior or safety properties.

#### `src/modes/fragments.rs`

Status: Read in full, including unit tests and all included Markdown assets
Disposition: Keep a typed preference registry; generate capabilities and prompt context separately

Findings:

- The Rust layer embeds 19 Markdown prompt assets at compile time and exposes
  exhaustive mappings correctly; the content of each asset remains separately
  in scope for the prompt/Markdown audit.
- `BASE_TOOLS` is static prose and therefore duplicates the runtime tool
  registry. This is the drift risk already recorded in F-027.
- Fragment tables provide good compile-time exhaustiveness, but they contain no
  metadata distinguishing stylistic guidance from host-enforced capability
  requirements.
- Tests protect headings, registry membership, and lack of template tokens.
  They cannot show that readonly blocks a write, director mode delegates, or
  context pacing responds to actual context usage.

#### `src/permissions.rs`

Status: Read in full, including both unit-test modules
Disposition: Keep permission intent; replace precedence, classification, storage, and heuristics

Findings:

- Permission classification fails open: unknown tools and registered tools
  whose handler inherits `permission_target() == None` return `Allowed` and
  receive auto-allow score `1.0` (F-001).
- The manual “known safe” test list includes mutation and control-plane tools:
  task/todo writes, shell killing, worktree create/remove, cron create/delete,
  Crosslink, plan-mode changes, skill loading, and MCP reads. Comments about
  separate gates are not an enforceable type or shared lifecycle.
- Persisted always-allow rules outrank session denials. Within session rules,
  the first matching rule wins. Both behaviors let an old/broad allow defeat a
  newer or more specific denial (F-030).
- TUI remembered decisions are `HashSet<String>` values keyed only by tool
  name, with independent allow and deny sets that can both contain the same
  tool. The frontend—not this manager—must resolve the contradiction and may
  apply a Bash-wide approval to unrelated commands.
- `default_allow` contains patterns only, so a match is not scoped to a tool.
  A string shape permitted for Bash can also permit a write path or URL that
  happens to match.
- `unrestricted()` and `enabled=false` allow every operation except a small set
  of name-based hard checks. New aliases/handlers do not inherit protected-file
  or Bash checks from their declared risk category.
- Protected-write checks normalize path strings lexically. Symlinks, races,
  alternate filesystem references, and newly added sensitive control files
  bypass that narrow `.git`/`.claude/settings.json` list.
- Reads—including `/etc` through `read_file` and network/MCP retrieval—are
  unconditionally safe in this model. Read sensitivity, secret access,
  external data flow, and prompt-injection risk need distinct policies even
  when no user prompt is required.
- The auto-allow classifier is a substring/prefix heuristic. For example,
  `starts_with("ls")` is broader than an executable parse, relative edits get
  a fixed score, and threshold validation is not local. Shell parser/hardening
  behavior must be reconciled with the Bash subsystem before this feature can
  support production auto-mode.
- Skill/command `allowed-tools` supports only Bash, Write, Edit, and WebFetch.
  Unknown/malformed/unsupported entries are silently discarded rather than
  producing an activation error and scoped capability report.
- Permission JSON is read unbounded and accepts unvalidated tool/pattern
  values. Writes use `create_dir_all` plus direct `fs::write`, with no
  canonical containment, symlink protection, atomic replacement, restrictive
  mode, locking, or durability policy.
- `add_always_allow` retains an in-memory allow and logs “added and persisted”
  even if the save failed. Corrupt/unreadable persistence silently becomes an
  empty set apart from logs.
- Structured audit logs include raw target arguments and patterns at info
  level. Commands and URLs can contain credentials or user data.
- Denial state is duplicated in `PermissionManager` and `DenialTracker`.
  `check` does not update either automatically; callers must remember to record
  outcomes. A “spec pin” test still asserts repeated prompts never escalate,
  contradicting nearby claims that the gap is closed.
- The global compiled-pattern cache is unbounded. The comment calls regex
  compilation bounded despite accepting arbitrary-length user patterns.
- The file is 3,038 lines, much of it repetitive issue-specific tests. Several
  tests deliberately pin unsafe precedence/fail-open behavior, so passing the
  suite cannot be interpreted as a secure permission contract.

#### `src/tools/registry.rs`

Status: Read in full
Disposition: Keep one registry; require typed risk, capability-aware availability, and async dispatch

Findings:

- Co-locating schemas and dispatch handlers is a sound direction, but
  `ToolHandler::permission_target` defaults to `None`, explicitly defining
  omission as read-only/safe. This is the root of F-001.
- The registry has no typed effects beyond one canonical string argument.
  It cannot express sensitive reads, network egress, process control,
  scheduling, persistent internal-state mutation, destructive variants, data
  classification, reversibility, or required runtime capabilities.
- Mutating/control handlers without targets include Crosslink create/update/
  close operations, todo/task writes, worktree create/remove/commit/merge/
  discard, cron create/delete, shell termination, plan-mode changes, and skill
  instruction loading. They are therefore invisible to the central permission
  rules even though some have separate checks elsewhere.
- Read/network handlers are also not uniformly low risk. `read_file` advertises
  arbitrary absolute paths, browser/search can contact external or internal
  destinations, LSP can start external language-server processes, and MCP
  resources can expose sensitive data. The current binary safe/unsafe target
  does not model these effects.
- `ToolContext.security` is a `Result` used by `dispatch` only as a global
  availability check. None of this file's handlers receives a concrete
  capability from it; most ignore the context entirely and call free
  functions. Exact downstream/global filesystem enforcement remains to be
  traced.
- `ToolContext` makes memory/config/task state optional while the registry is
  unconditional. Task tools are advertised even when they will return “no
  session”; MCP resource tools are advertised even without an installed MCP
  manager; other capability-dependent tools use similar runtime failure
  messages. Availability should be constructed per run.
- MCP resource handlers use a process-wide manager and synchronously
  `block_on` its async API, relying on the undocumented caller invariant that
  dispatch is already inside `spawn_blocking`. The registry trait itself is
  synchronous, which obstructs native cancellation, deadlines, and streaming.
- Skill loading advertises project and user files as “user-authored” and says
  its XML envelope should be spliced into the next system prompt. It uses the
  unrestricted-by-UI `get_skill` path; this confirms the unsafe authority
  design in F-028.
- `tool_search` returns XML-wrapped JSON schema text. It has no mechanism to
  add a schema to the provider request or change the runtime registry, while
  the full handler list is already emitted by `get_tool_definitions` (F-005).
- Plan-mode prose calls Crosslink read-only even though the same handler
  supports mutation. It references `task` and `agent_output`, which are not
  handlers in this registry, and makes enforcement claims that live in a
  different subsystem.
- Cron's schema accurately says it writes metadata for an external scheduler
  and OpenClaudia does not execute it. That is an incomplete scheduling
  feature to finish through a real lifecycle service, not a stale tool to
  delete (F-006).
- Tool schemas omit `additionalProperties: false`, and host execution accepts
  a generic argument map. The schema is model guidance, not input validation;
  handlers must perform complete typed decoding independently.
- `build_registry` silently overwrites a duplicate handler name, while schema
  iteration would still emit both entries. Construction should validate
  unique names, definition/handler identity, schema validity, risk metadata,
  and required capabilities.
- The registry covers only static core handlers. Dynamic MCP/plugin/subagent
  tools are composed elsewhere and must enter the same typed lifecycle rather
  than bypassing this otherwise useful centralization.

#### `src/tools/mod.rs`

Status: Read in full, including unit tests
Disposition: Replace overloads with one typed executor; preserve operational tools

Findings:

- Public `execute_tool`, `execute_tool_with_memory`, `execute_tool_full`, and
  `execute_tool_with_tasks` accept no permission manager and deliberately
  execute fail-open. `execute_tool_gated` is also optional/fail-open. Passing
  `None` logs only the first process-wide occurrence, so later unsafe callers
  are hidden by the warning suppression.
- `check_tool_permission_outcome` returns `Allowed` for a disabled manager
  before invoking `PermissionManager::check`. This skips the manager's
  supposedly non-negotiable hard safety and makes
  `execute_tool_with_permission_required(..., unrestricted())` less safe than
  direct manager checks (F-031).
- Subagent `task`, `agent_output`, and `task_stop` bypass the registry through
  special match arms. The permission manager cannot find them in the registry,
  classifies them as safe/unknown, and allows them. They also bypass registry
  metadata/uniqueness/capability checks.
- `execute_tool_with_permission_required` is strict only about manager
  presence. A real `NeedsPrompt` is converted back into a stringly error rather
  than an approval continuation, while `execute_tool_gated` offers a typed
  prompt outcome but still accepts a missing manager. The public names obscure
  rather than clarify the safe path.
- Permission arguments are decoded as generic JSON twice and checked only
  against the selected target string before per-handler parsing. There is no
  shared schema validation, unknown-field rejection, typed normalization, or
  binding between the approved argument value and the value later acted on.
- `permission_scope_summary` tells users that filesystem roots, masked control
  paths, subprocess network denial, and SSRF redirect/IP policy constrain an
  approval, but this layer does not carry or verify a receipt proving those
  claims. Each underlying subsystem still requires audit.
- Control-plane state is encoded in ordinary JSON result content and then
  reparsed into `ToolControlSignal` solely by the `type` field. It is not bound
  to the source tool or success state (F-032).
- `parse_exit_plan_mode_prompts` silently drops malformed entries and returns
  free-form tool/prompt pairs. Those descriptions are not normalized approval
  capabilities and must not grant access on their own.
- `ToolCall.call_type` is accepted but not validated, and unknown tool names
  reach an error only after the permission layer has treated them as allowed.
- The module header advertises `memory_save`, `memory_search`,
  `memory_update`, and `core_memory_update` tools. None is registered or
  dispatched anywhere in production source. Other modules still tell the
  model to use `memory_search`, confirming an incomplete archival-memory tool
  surface under F-006.
- Tool definitions are always the full static registry, with optional
  subagent definitions appended through a separate unvalidated path. This
  confirms F-005 and preserves duplicate/lifecycle drift.
- Dispatch remains synchronous and returns unstructured `(String, bool)` or
  `ToolResult`. It cannot natively represent typed observations, attachments,
  secret/redaction metadata, streaming output, retryability, cancellation,
  approval continuation, or control events.
- The module's large mixed test block combines dispatcher, accumulator,
  notebook/file, task, image, schema, and permission tests. Several tests
  explicitly execute legacy fail-open paths; none catches F-031 through the
  public executor or marker spoofing through a non-control tool.

#### `src/tools/security.rs`

Status: Read in full, including unit tests
Disposition: Keep descriptor-capability direction; remove ambient/global initialization

Findings:

- `current_context` uses the todo subsystem's thread-local session key. With no
  guard it calls `ensure_session_context("__default__")`, which canonicalizes
  and grants read/write access to ambient process CWD (F-033).
- Setting a `SessionIdGuard` also calls the same ambient-CWD initializer. If an
  explicit context has not already been registered, the guard—not session
  construction—chooses the project's security boundary.
- Every context appends `project_root` to `read_write_roots`, even when only
  read-only roots were requested. Readonly/explore mode therefore cannot be
  represented by this capability object (F-029/F-033).
- Re-registering a session validates only the canonical project root. A
  different working directory, read-only roots, read-write roots, masks,
  environment grants, or network policy silently reuses the old context.
- Failed context construction is cached as an error for that session until
  explicit release; transient startup problems cannot recover. The global map
  is unbounded if lifecycle paths miss release.
- Context creation holds the process-wide map mutex across canonicalization,
  directory creation, environment parsing, and opening every root. One slow
  filesystem can block all session capability operations.
- The working-directory containment precheck compares its canonical path to
  caller-supplied additional roots before those roots are canonicalized. A
  relative or symlinked legitimate grant can be rejected inconsistently.
- The broad-root denylist rejects `/home` but not the actual user home such as
  `/home/alice`. Launching in the home directory therefore grants the entire
  home tree read/write except two project-relative masks.
- Default denied project paths cover `.openclaudia` and `.claude`, but not
  `.git` or common secret-bearing files such as `.env`. Risk-aware sensitive
  read and control-path write policy must supplement directory containment.
- `ToolSecurityContext` derives `Debug` over raw `environment_grants` values,
  allowing API/cloud credentials to leak through diagnostics (F-034).
- Environment values are copied into ordinary `String`s and retained for the
  entire context lifetime. There is no redacting/zeroizing type or per-command
  least-privilege grant selection.
- The private temp directory is created and then chmodded to `0700`; Unix mode
  should be restrictive at creation to avoid a transient overly broad mode.
- Descriptor-pinned Unix roots, no-follow root opens, longest-root selection,
  private temp identity checks, and delayed cleanup through `Arc` ownership
  are good primitives worth preserving in W15.
- The network policy intentionally supports only `Denied`, but this context is
  not consulted by registry web/browser/MCP handlers. The distinction between
  sandboxed subprocess network denial and brokered host network tools must be
  explicit in the canonical runtime.
- The two unit tests cover distinct temp roots and root replacement only. They
  do not test missing-context denial, readonly capability construction,
  re-registration mismatch, secret-redacted debug, async/session isolation,
  masked files, root grants, or lifecycle cleanup.

#### `src/tools/file/secure_fs.rs`

Status: Read in full, including unit test
Disposition: Keep handle-relative design; complete platform, context binding, and tests

Findings:

- Linux uses pinned roots plus `openat2` with `RESOLVE_BENEATH`,
  `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_SYMLINKS`; other Unix uses a
  component-wise `openat`/`O_NOFOLLOW` walk. These are strong primitives and
  materially better than lexical canonicalization.
- All non-Unix implementations fail closed. On Windows, core file and
  directory tools are therefore unavailable despite cross-platform-facing
  schemas and likely product claims (F-035).
- Linux has no fallback when `openat2` is unavailable or blocked by an older
  kernel/seccomp profile. The error is reported per tool call rather than as a
  startup capability failure.
- `SecureDirectory` retains the directory descriptor but not the
  `Arc<ToolSecurityContext>` that authorized it. Entry filtering calls ambient
  `current_context()` for every entry, so authorization/masking is not
  structurally bound to the opened handle and inherits F-033's session lookup.
- Direct child-open methods do not independently consult denied paths. Current
  walkers appear intended to call `entries()` first (which omits masks), but
  the type does not enforce that invariant and a future caller can name a
  masked regular child directly.
- Existing files with any hardlink are rejected for both reads and writes.
  This prevents aliases outside/masked within a capability but also makes
  legitimate multiply-linked files unusable even when every link is inside
  the same granted root. The behavior needs an explicit compatibility and
  threat-model decision.
- `read_to_string` is unbounded at this layer. Every caller must independently
  cap metadata and content before allocation; a capability should carry size
  quotas so omissions cannot create memory/context denial of service.
- Not-found classification is encoded as a string prefix and reparsed by the
  create path. Use typed filesystem errors so message changes cannot alter
  control flow.
- Parent directories use `0777` and new files `0666` subject to process umask.
  That is normal for workspace outputs but cannot serve secret/private agent
  state; persistent private stores require distinct restrictive capabilities.
- Directory enumeration warns and skips entries that disappear, producing a
  partial result without a structured partial/completeness flag.
- Only one Linux test exists. It verifies `.openclaudia` hiding, but not
  symlink races, rename races, hardlinks, masked direct-child opens, nested
  roots, readonly denial, quotas, `openat2` unavailability, macOS fallback,
  Windows behavior, or concurrent session/context isolation.

#### `src/tools/file/mod.rs`

Status: Read in full, including unit tests
Disposition: Keep file-tool facade and grounding intent; move state into typed run/snapshot context

Findings:

- `READ_TRACKER` is a process-wide singleton keyed by the todo subsystem's
  thread-local session ID, with a shared default bucket when absent. It is not
  owned by `ToolContext` or the file capability (F-033/F-036).
- A read marker contains only canonical path and a monotonically increasing
  stamp. It does not bind the bytes, range, digest, inode, modification time,
  descriptor, or workspace version the model actually observed.
- `execute_read_file` resolves a pathname, opens/reads it, then `mark_read`
  canonicalizes the path again and ledger recording reopens it again. Path
  replacement between those operations can produce three different objects
  under one claimed observation (F-036).
- Only successful in-process `record_active_diff_observation` calls invalidate
  reads. External editors, git operations, other sessions, Bash commands, LSP
  edits, worktree merge, and crashes leave stale markers eligible.
- `reset_read_tracker` claims to run at session start, but source-wide search
  found no production caller. There is no per-session clear/release; completed
  session buckets remain indefinitely, each with up to 10,000 paths.
- The tracker mutex fails closed after poison, while the Reality Ledger mutex
  recovers its inner state. The inconsistent failure models are not surfaced
  as a run-health/correctness event.
- Existing-path resolution follows symlinks during diagnostic
  canonicalization and then opens the canonical target handle-relatively.
  This is contained by roots/masks, but provenance loses the user-visible
  alias and policy should explicitly define permitted in-capability symlinks.
- Both read and write resolution prohibit every `..` component even when the
  normalized result would remain inside a granted root. This is conservative
  but is a user-visible path compatibility restriction that schemas do not
  mention.
- Active file reads store up to 100,000 bytes of rendered tool output as a
  ledger excerpt and reread up to the file cap for hashing. There is no
  aggregate ledger/context retention budget or sensitivity/redaction filter.
- File-read ledger failures merely warn and the tool still reports success;
  later write behavior then changes depending on whether the global ledger was
  installed and whether observation append happened to succeed.
- The fresh-ledger check compares exact strings. `read_file` stores canonical
  absolute paths, but `write_file` passes the original path into the check and
  diff recorder. Relative overwrites can fail after a valid read and diffs can
  use a different resource identity.
- Diff construction is unbounded and happens in memory before ledger append.
  Large replacements can consume substantial memory/database/context even
  though only read excerpts have a local cap.
- `ledger_line_range` derives range partly from requested args and rendered
  output rather than a typed result from the file reader, making binary/PDF/
  notebook and truncation semantics approximate.
- Tests heavily cover tracker bucket isolation and canonical path mechanics,
  but not content-version invalidation, external mutation, rename races,
  read/hash consistency, per-session cleanup, relative-path ledger parity,
  sensitive excerpts, or aggregate quotas.

#### `src/tools/file/list.rs`

Status: Read in full, including unit test
Disposition: Keep directory listing; add bounded typed pagination and real partial tests

Findings:

- The implementation reads every directory entry, allocates every lossy name,
  sorts the whole set, and returns one unbounded string. A large directory can
  exhaust memory or consume the model context window (F-037).
- It omits entry type except a trailing slash for directories; “other” kinds
  and regular files are indistinguishable, and there is no metadata,
  pagination/cursor, byte limit, or explicit root/resource identity.
- Non-UTF-8 filenames are lossy-converted, so distinct entries can collide in
  output and the returned name may be unusable in a subsequent string-based
  tool call.
- An empty directory returns an empty successful string, which is weaker than
  a typed empty result and easy for provider/frontends to conflate with absent
  output.
- The doc/test claims this function logs unreadable entries. The real warning
  is inside `secure_fs::entries`; the test does not provoke that path and
  simply emits a synthetic `tracing::warn!` itself. It would keep passing if
  production logging were removed, making it a concrete F-008 cruft example.

#### `src/tools/file/glob.rs`

Status: Read in full, including unit tests
Disposition: Keep glob discovery; replace traversal/limit/result contract

Findings:

- Matches are appended in `readdir` order until 100, then sorted. Filesystem
  enumeration order determines which valid matches survive the cap, so the
  result subset is not deterministic across filesystems/runs.
- The walker recursively calls itself and accumulates all child directory
  handles for a directory before descending. A wide tree can hold thousands
  of descriptors; a deeply nested tree can overflow the Rust stack despite
  the 50,000-entry ceiling.
- Unreadable/changed subdirectories warn and are skipped, but `truncated` is
  set only for count/visit caps. The tool reports success without any
  machine-readable indication that its result is incomplete.
- `raw_path.starts_with('.')` treats the ordinary default `"."` as an explicit
  hidden root. Root-level `.git`, `.cache`, and other dot/vendor directories
  are therefore traversed contrary to the module docs and schema.
- Glob pattern size is unbounded, and conversion builds multiple proportional
  allocations before regex compilation. Compile failure is collapsed to
  “invalid pattern” even when it reflects size/resource limits.
- The glob-to-regex dialect duplicates permission and skill implementations.
  They can—and already do—evolve separately despite comments claiming one
  mental model.
- Returned paths are relative to the supplied search root, with no root ID.
  The same string can name different files in subsequent calls with a
  different root/CWD.
- Symlinks and other file kinds are silently excluded, which is safe for
  traversal but should be reported as policy/completeness metadata when
  relevant.
- Tests cover basic pattern semantics and type errors only. They omit default
  hidden behavior, deterministic capping, deep/wide trees, descriptor budget,
  partial errors, output budget, non-UTF-8 names, and session/context changes.

#### `src/tools/file/grep.rs`

Status: Read in full, including unit tests
Disposition: Keep native search; replace eager hit collection with bounded streaming

Findings:

- The 200-match limit is enforced only in `append_hits`, after `grep_one` has
  allocated a `Vec<Hit>` for every matching line in the current file. This can
  far exceed the claimed cap (F-038).
- `context_lines` accepts any `u64`, converting overflow to `usize::MAX`. For
  every hit, it clones all before/after lines in that window. Many matches with
  a large window can multiply a 5 MiB file into enormous memory/output.
- Context ranges for adjacent matches are duplicated rather than merged.
  Before-context numbering uses `hit.line_no - 1` for every line in a
  multi-line before window, so reported line numbers are wrong when context is
  greater than one.
- Traversal has the same recursion and sibling-descriptor accumulation as glob,
  with stack/FD risks and nondeterministic first-match capping (F-037).
- Oversized files are silently treated as having zero hits. Invalid UTF-8,
  hardlinks, changed files, and unreadable directories warn and disappear from
  the successful result; `truncated` does not represent these partial errors.
- `files_scanned` increments before a file is securely opened and successfully
  decoded, so the header overstates completed coverage.
- There is no output-byte/time budget, pagination, stable cursor, file/glob
  filter, binary policy, long-line cap, or cancellation check. A 200-line
  result can still be many megabytes.
- Pattern length is unbounded. Rust regex avoids backtracking explosions, but
  compilation and automaton size still need a budget and typed limit error.
- Returned paths are relative to the chosen root and traversal order is not
  stable, inheriting the resource-identity problem from glob.
- Tests cover basic matches, one context line, invalid regex, and argument
  types. They miss the eager-allocation path, context >1 numbering, overlapping
  context, caps, partial files, binaries, long lines, traversal budgets, and
  deterministic pagination.

#### `src/tools/file/write.rs`

Status: Read in full, including unit tests
Disposition: Keep write capability; make it atomic and snapshot-conditional

Findings:

- Existing files are opened read/write before the read-tracker and active-
  ledger preconditions are checked. No bytes change before denial, but the
  authorization decision is not structurally part of handle acquisition.
- Read-before-overwrite relies on F-036's path-only global marker. Tests mostly
  call `READ_TRACKER.mark_read` directly rather than proving the content read
  by `read_file` is the version overwritten.
- Overwrite seeks, truncates to zero, then writes in place. A disk-full, I/O,
  cancellation, crash, or short-write failure can leave the original file
  empty or partially replaced with no recovery.
- There is no temporary sibling + atomic rename, preserved permissions/
  ownership policy, optional durability, file lock, or snapshot hash/version
  precondition. External changes between read and write are lost silently.
- Input content and old-content reads are unbounded locally. New content may
  be constrained by provider request size, but internal/plugin callers and old
  files still need explicit capability quotas.
- New-file creation correctly uses exclusive no-follow descriptor-relative
  open after secure parent creation, and leaf symlink rejection is tested.
- Guardrail and ledger updates happen after filesystem mutation. If either
  state update fails or the process crashes, the write succeeds without a
  corresponding audit/diff record.
- Successful modification invalidates the read marker, but Bash/external/
  other-session changes do not. The ledger path is canonical here because
  `path` is derived from resolved `p`, clarifying the earlier preliminary
  concern: this specific write implementation does use the canonical path for
  its fresh-read check and diff. F-036's central snapshot race remains.
- Tests cover common creation/overwrite/read-gate and final-leaf symlink cases,
  but not atomic-failure recovery, external version conflict, concurrent
  writers, size quotas, permissions preservation, durability, or audit-state
  failure after mutation.

#### `src/tools/file/edit.rs`

Status: Read in full, including unit tests
Disposition: Keep targeted editing; replace in-place/string-marker implementation

Findings:

- The implementation correctly requires a prior read, exact match, unique
  occurrence by default, and a no-follow single file descriptor. Those user-
  protective semantics should be preserved with F-036 snapshot binding.
- It reads the whole file into memory without a local quota, collects every
  match offset, then allocates the full replaced content. The result-size cost
  is not calculated before allocation.
- Empty `old_string` is not rejected. `match_indices("")` yields every UTF-8
  boundary; with `replace_all` this can insert replacement text throughout the
  file and magnify memory/output unexpectedly (F-039).
- A small frequently occurring old string plus a large new string can produce
  arbitrary expansion. Permission and guardrail decisions occur before the
  host knows the resulting size/blast radius.
- Like `write_file`, `rewrite_in_place` truncates and rewrites the original
  descriptor. I/O failure/cancellation can destroy the prior version; there is
  no atomic replacement or rollback.
- Success content uses magic `@@DIFF_START@@`/`@@DIFF_END@@` strings and embeds
  complete old/new text as JSON. This duplicates potentially sensitive data,
  has no byte limit, and requires downstream result parsing. Escaping changes
  literal marker text in the displayed diff rather than preserving an exact
  typed payload.
- The debug event reports lengths as `old_chars`/`new_chars` but uses UTF-8
  byte length, an observability/schema mismatch.
- Path conversion is lossy for non-UTF-8 paths, consistent with the broader
  string-only tool contract but unable to identify all valid filesystem
  resources exactly.
- Line-blast accounting counts only replacement fragments rather than a typed
  parsed diff and is recorded after the write. Guardrail warnings do not
  prevent a high-blast edit unless an earlier check elsewhere does so.
- The “curly quote” test writes a straight apostrophe while claiming the file
  contains a curly one, so it does not test the documented parity gap.
- Many edit tests use the process-global default read bucket without the shared
  tracker mutex. Tests that call `clear_all` under a lock can still race these
  unlocked tests, making the suite's isolation claim incomplete.
- Tests do not cover empty-match behavior, expansion quota, large files,
  atomic failure recovery, external snapshot conflict, sensitive/bounded diff
  results, cancellation, or audit failure.

#### `src/tools/file/read.rs`

Status: Read in full, including unit tests
Disposition: Keep multi-format reading; replace prose attachments/truncation with typed bounded results

Findings:

- Regular-file/no-follow handle checks and a 10 MiB growth-aware cap are useful
  defenses. The cap is applied to the same opened object, avoiding a metadata/
  read pathname race.
- Images are detected only by filename extension and their complete base64 is
  returned as plain text. No magic, dimensions, decode-bomb, MIME/content
  consistency, provider vision capability, or typed attachment validation
  exists (F-040).
- Base64 expands a permitted 10 MiB image to roughly 13.3 MiB before tool-result
  and provider encoding. There is no per-provider/context budget at this path.
- Text reads reject every file over 10 MiB before considering offset/limit,
  contradicting the error's recovery instruction. Accepted files are read and
  split in full even for a one-line range (F-041).
- The 100,000 “char” budget is actually bytes. It preserves line boundaries,
  but a single oversized line returns zero content and no byte/column cursor.
- Truncation is an XML-shaped string sentinel. Source-wide search found no
  production parser despite comments claiming downstream dispatchers can
  detect it programmatically.
- Offset beyond EOF produces a successful empty body with a potentially
  inverted range such as “showing lines 99-98 of 2,” rather than typed EOF and
  next-range metadata.
- On narrower `usize` platforms, huge `u64` offsets are coerced to
  `usize::MAX`; later unchecked `offset + 1` can overflow. Range inputs need
  explicit portable maxima.
- Notebook parsing reads the full JSON and builds full rendered source/text
  output with no cell/output/result byte cap. Malformed elements and unsupported
  binary/image outputs are warned/dropped but success has no partial flag.
- PDF extraction reads the entire PDF and invokes cached PATH-resolved Poppler
  binaries. The page-count guard is best-effort: absent/failing `pdfinfo` lets
  an unbounded-page extraction proceed, and page ranges have no page-count/
  output-budget ceiling at this layer.
- PATH resolution at first use can select an unintended executable and caches
  success/absence for the process lifetime. External parser provenance,
  version, trusted path, sandbox profile, and output capture caps must be
  verified with `tools/command.rs`/sandbox audit.
- Filename flag rejection is defense-in-depth but normally redundant because
  the facade passes a resolved absolute path and parser input through stdin.
- The test claiming to assert `pdfinfo`'s `let info_args = ["--", path]`
  source shape searches the entire source including that exact string inside
  the test itself. Production now uses stdin (`["--", "-"]`), so the test is
  self-satisfying and proves nothing (F-008).
- Tests explicitly pin base64-as-text as a known parity gap rather than an
  operational vision round trip. There are no provider-native image tests,
  file-signature tests, decompression/dimension limits, large-file partial-read
  recovery tests, long-line continuation tests, malformed-notebook partial
  metadata, or Poppler output-budget tests.

#### `src/tools/file/notebook.rs`

Status: Read in full, including unit tests
Disposition: Keep notebook editing; repair schema, snapshot, and atomic-write contracts

Findings:

- The validate/resolve/dispatch helpers and closed edit/cell-type enums are a
  useful refactor. The same descriptor is used for the initial read and final
  rewrite, and final-leaf symlinks are rejected. Those behaviors should remain.
- `parse_args` requires `new_source` before it knows the edit mode, so a delete
  call fails unless the model supplies a meaningless empty string. Tool schemas
  and parsing should express mode-specific required fields instead.
- The root `cells` member is checked only for being an array. Existing elements
  are not validated as cell objects with a supported `cell_type` and valid
  source/metadata fields before indexed mutation. Invalid/mixed notebook shapes
  can therefore be silently normalized in some branches or reach `Value` index
  mutation that is not an intentional typed error path.
- Inserted cells have no `id`. Cell IDs are required for nbformat 4.5, and the
  tool neither generates a collision-checked ID nor negotiates/updates the
  notebook's `nbformat_minor`. This contradicts the module's own claim that IDs
  are stable modern Jupyter locators and can persist a structurally incomplete
  notebook (F-042).
- Replace defaults a missing or unknown existing cell type to code and then
  adds/clears code fields. A malformed or future cell type is mutated rather
  than rejected or preserved through an explicit compatibility policy.
- The replace-at-`cells.len()` promotion to insert is surprising overload: the
  nominal replace operation can change notebook structure. If retained for
  compatibility, this must be explicit in the schema/UI and tested as a
  versioned behavior rather than described as a silent promotion.
- The entire notebook is read to a `String`, parsed to a second full tree, and
  serialized to another full pretty string with no local input, cell, output,
  or result quota. Pretty serialization also rewrites formatting for the whole
  document when one cell changes.
- Persistence seeks to zero, truncates the only original file, and writes the
  new JSON in place. Failure after truncation loses or corrupts the original;
  there is no atomic sibling replacement, fsync/durability policy, rollback,
  or optimistic snapshot/version check (F-036/F-042).
- Guardrail and ledger observations are recorded after the filesystem change,
  so an observation failure or crash can leave a mutation without matching
  evidence. There is no typed recovery state.
- Tests mostly insert read markers directly rather than obtaining a versioned
  snapshot through `read_file`. They cover common cell operations and leaf
  symlinks, but omit required generated IDs, nbformat/version compatibility,
  malformed cell shapes, large notebooks/outputs, external version conflicts,
  atomic-write failure, cancellation, durability, and Jupyter client
  round-trips.

#### `src/tools/args.rs`

Status: Read in full, including unit tests
Disposition: Keep typed argument/result intent; replace transitional public contract

Findings:

- Central string/bool extraction does reduce inconsistent missing/type errors,
  but the accessor set covers only strings and one optional Boolean. Numeric,
  array, object, enum, size/range, mutually exclusive, and conditional schema
  rules remain manually reimplemented throughout handlers.
- `ToolArgError::MissingOrWrongType` is now returned only for absence while a
  present wrong type uses `WrongType`; the variant name/docs retain transitional
  semantics and the outer string map still prevents schema-derived validation.
- `ToolOutput.structured` has no production reader. Bash is the sole typed
  executor and immediately collapses through `into_legacy`; that conversion
  deliberately discards `structured` (F-043).
- `ToolError::External(String)` stringifies rather than retains an error source,
  while cancellation, deadline, unavailable capability, conflict, partial,
  retryable/transient, redaction, and recovery-state variants are absent.
- The tuple bridge erases even the categories that do exist. Tests assert this
  lossy collapse rather than an end-to-end registry/provider/frontend typed
  round-trip.

#### `src/tools/accumulator.rs`

Status: Read in full
Disposition: Keep bounded streaming assembly; redesign around provider-native typed events

Findings:

- The 512-slot OpenAI cap correctly prevents a malicious index from directly
  resizing a vector to host-memory exhaustion.
- IDs, call types, function names, argument fragments, Anthropic text, and
  partial JSON remain unbounded. A stream can stay within 512 slots while
  consuming arbitrary memory; there is no per-item/turn/context byte budget or
  cancellation state.
- Out-of-cap slots and incomplete calls are warned/dropped, but finalization has
  no typed partial/protocol error. An apparently successful turn can therefore
  omit tool work silently.
- Empty arguments are normalized to `{}` without distinguishing a genuinely
  empty object from missing/truncated upstream arguments, and JSON validity is
  deferred to later string parsing.
- Anthropic assembly ignores content-block indices and appends deltas only to
  the last block of the expected variant. It flattens native ordered blocks to
  concatenated text plus OpenAI-shaped calls, losing the richer provider state
  called out in W3.
- There are no module tests for split/interleaved/malformed/oversized protocol
  events, incomplete streams, index gaps, memory limits, cancellation, or
  preservation of provider-native block ordering.

#### `src/tools/ask_user.rs`

Status: Read in full, including unit tests
Disposition: Keep interactive clarification; return a trusted typed control event

Findings:

- Question/option counts, required fields, header width, duplicate labels/text,
  and legacy `multi_select` normalization are validated and tested.
- Question, label, description, and preview strings have no byte/character or
  aggregate result/context limits. Unknown object fields are cloned into the
  emitted payload, allowing unnecessary arbitrary data to cross the control
  boundary.
- If both canonical and legacy multi-select keys are supplied, both survive
  normalization and could disagree; validation checks their types but not
  conflict/precedence.
- The result is ordinary JSON text containing `USER_QUESTION_MARKER`, inheriting
  F-032: the dispatcher later rediscovers a host UI transition by parsing
  content rather than receiving a trusted handler-created event.
- This layer binds no call ID, run ID, UI capability, response schema, timeout,
  cancellation, or resume token. Consumer and frontend audits must verify how
  answers are correlated and persisted.
- Tests validate the JSON formatter in isolation but do not exercise a real
  model call → trusted pause → frontend response → exact continuation cycle.

#### `src/tools/command.rs`

Status: Read in full, including unit tests
Disposition: Keep a shared subprocess supervisor; make its deadline/capability contract complete

Findings:

- Central wall deadlines, concurrent stdout/stderr drainage, bounded retained
  bytes, child reaping, and process-tree termination intent are all useful.
- Optional stdin is written synchronously before `deadline` is constructed. A
  non-reading child can block after pipe capacity is exhausted forever; input
  is also unbounded (F-044).
- Retention is capped at 10 MiB per stream, but readers continue draining
  unlimited bytes until exit/deadline and return an in-band marker rather than
  typed truncation/total-byte metadata. Concurrency can still allocate roughly
  20 MiB plus threads per process without a run-wide budget.
- `cmd.envs(env)` does not itself call `env_clear`; the later sandbox constructor
  audit confirmed its positive allowlist clears inheritance, while direct and
  alternate process paths still require W18 consolidation.
- Cancellation ownership uses `todo::current_session_key()` and two process-
  global maps. A Boolean cancelled-session set is not a generation token;
  reused session IDs/new prompts can race old workers, and cancelled keys are
  retained until an explicit clear.
- The timeout polling can overshoot by the current backoff interval and uses
  blocking sleeps. Spawn, stdin write, output-reader join, tree shutdown, and
  reap are not separately phase-bounded or observable.
- Test-only host execution intentionally skips tree termination. Production
  tests cover fast exit, timeout, spawn failure, stdin echo, and retained-output
  cap, but not blocked stdin, inherited-secret isolation, descendants holding
  pipes, cancellation generations, concurrent process budgets, kill/reap
  failure, or typed partial output.

#### `src/tools/bash/kill.rs`

Status: Read in full, including unit tests
Disposition: Keep process cancellation; move it into the canonical job supervisor

Findings:

- Agent-facing single-shell and agent-wide cleanup are owner-checked, but
  ownership is the mutable/todo thread-local session key rather than the
  immutable run capability (F-033/F-047).
- Linux descendant enumeration repeatedly walks `/proc`, then signals raw PIDs
  and a process group. PID reuse and fork races are inherent; errors are logged
  at debug or ignored and the public helper returns no termination/reap result.
- Non-Linux Unix waits up to two blocking seconds and may treat a zombie as
  alive. Windows locates and invokes `taskkill` without the shared sandbox,
  timeout, bounded output, verified binary provenance, or result check.
- The manager removes tracking before a supervised join/reap confirmation;
  caller success therefore means signals were attempted, not that the entire
  tree is gone.
- Tests cover IDs and ordinary Unix kills but omit hostile descendants,
  daemonization, PID reuse, permission errors, kill/reap failures, cancellation
  races/generations, Windows timeout/provenance, and session teardown.

#### `src/tools/bash/output.rs`

Status: Read in full, including unit tests
Disposition: Keep job observation; replace destructive text drain with typed cursors

Findings:

- Listing and output access are filtered by manager ownership, and type errors
  are handled consistently.
- Lists inherit nondeterministic `HashMap` order and return plain text without
  pagination, start time, resource usage, truncation, retention, or durable job
  identity.
- Polling destructively drains process buffers. A successful call followed by
  frontend/model failure or compaction loses the consumed output, and no cursor
  permits replay/resume.
- stdout and stderr are presented in two blocks rather than event order; empty
  output, reader failure, truncation, and “no new bytes” are not distinct typed
  states.
- Tests pin formatting and destructive drain behavior instead of a durable
  multi-frontend lifecycle with cancellation/reconnection/backpressure.

#### `src/tools/bash/path_constraints.rs`

Status: Read in full, including unit tests
Disposition: Remove security mechanism after canonical sandbox capability migration

Findings:

- The gate is process-global and defaults disabled. Source-wide search finds
  public re-exports but no production installer, so the execution call is
  currently always a no-op outside tests (F-050).
- Comments explicitly concede shell expansion and symlink bypass, while the
  actual tokenizer also misses redirection-attached, option-attached,
  separator-adjacent, variable-derived, globbed, brace-expanded, and many bare
  paths.
- Documentation says roots are canonicalized lazily, but `allows` only joins
  against the first root and performs lexical component normalization.
- Empty constraints mean allow-all and missing installation means allow-all,
  preventing a fail-closed distinction between “intentionally unrestricted”
  and “security setup forgotten.”
- A single global root list cannot safely serve concurrent projects/sessions.
  Error text directs model-visible callers to edit `.claude/settings.json`,
  which is not a host authority source.
- Unit tests validate only the intentionally narrow tokenizer and disabled
  global state; there is no production wiring test, concurrency/isolation test,
  or proof that the gate cannot grant access.

#### `src/tools/bash/policy.rs`

Status: Read in full, including unit tests
Disposition: Keep environment minimization and defensive warnings; replace effect authorization

Findings:

- Command length limits, fail-closed built-in regex compilation, `env_clear`,
  and positive environment allowlisting are useful defense-in-depth.
- The hard denylist is necessarily evadable and also rejects quoted harmless
  strings. It must not be the authorization boundary; its error dangerously
  tells the model-visible caller to edit the source denylist.
- `SAFE_READ_ONLY_COMMANDS` contains unrestricted VCS, networking/system tools,
  build/package tools, and interpreters. Only the first program name is checked
  and a non-interpreter pipeline's later programs are not classified, producing
  the critical false-safe operations in F-045.
- Specific examples accepted as auto-safe include `git reset --hard`, `git
  push`, mutation-capable `mount`/`ip`, `npm install`, Python/Node code, `env`
  or `command` launching another executable, and `cat x | rm file`.
- Treating `cargo check` and package/test commands as read-only ignores build
  scripts, compiler/plugin execution, downloads, target/cache writes, and
  repository-controlled configuration.
- The environment allowlist inherits `PATH` and executable-selection variables
  such as `CC`, `LD`, and `AR`; the sandbox later narrows PATH, but exact binary
  provenance and per-profile grants remain required. HOME/toolchain paths can
  also expose configuration unless mounts prevent it.
- Tests extensively pin string patterns, including the false premise that a
  safe left side makes a pipeline safe. They do not drive each candidate
  through permission → sandbox → observed effects.

#### `src/tools/bash/sandbox.rs`

Status: Read in full, including unit tests
Disposition: Keep Linux OS-containment foundation; redesign profiles/capability mounting

Findings:

- Bubblewrap namespaces, empty-root construction, descriptor-pinned session
  roots, capability dropping, FD closure, seccomp, private temp, minimized Git
  metadata, resource-limit intent, explicit host opt-out, and fail-closed
  unsupported platforms are valuable foundations.
- Every profile mounts every session root with its session-wide write bit and
  receives every environment grant. Profiles therefore do not implement the
  least-privilege distinctions their names imply (F-048).
- DocumentParser and MCP/analysis processes can receive writable project roots;
  `permits_project_path` changes only PATH selection, not mounted authority.
- Control/denied paths are hidden only if they exist. An absent `.git`,
  `.openclaudia`, `.claude`, or denied leaf can be created inside the broad
  writable bind (F-049).
- `validate_writable_project_tree` traverses as many as one million entries on
  every invocation. It detects existing external hardlinks/nested mounts but
  races changes after the scan and before/use during the broad bind. Background
  spawn performs this work while holding the global shell-manager mutex.
- Home Cargo/Rustup trees and runtime trees use pathname binds rather than the
  descriptor-pinned helper. The trusted-host assumption and mutation/provenance
  policy for those executable/config trees is unstated.
- `sandbox_path` derives executables from host PATH and permits user Cargo and,
  for some profiles, project entries. Exact executable digests/ownership are
  not bound to the authorization decision (F-049's broader provenance issue).
- The Bubblewrap probe has no deadline/output cap and does not execute the full
  context-specific mount scan, rlimits, environment, cwd, or program path, so
  “preflight passed” can precede first-call failure.
- `setrlimit` assigns both soft and hard limits without clamping to an already
  lower host hard limit. `RLIMIT_NPROC` is a host-UID absolute snapshot, not a
  per-run process budget; CPU/address-space/file-size limits are per process or
  per file rather than aggregate containment.
- The seccomp fallback intentionally denies all socket/socketpair calls,
  reducing network/IPC risk but potentially breaking Unix-socket-based tools;
  profile-specific functional tests and an explicit support contract are
  absent.
- Unit tests check helpers/constructed arguments and a few metadata cases but
  do not verify effective mount writability for every profile, absent denied
  paths, scan races, secret isolation, aggregate resource attacks, real network
  denial, seccomp functionality, or host-opt-out UI acknowledgement.

#### `src/tools/bash/mod.rs`

Status: Read in full, including unit tests
Disposition: Keep shell and background-job capabilities; replace global/threaded lifecycle

Findings:

- Foreground execution does use sandbox construction and the shared process
  timeout; background execution uses the same sandbox and tracks owner, output,
  status, and process ID. These intended capabilities remain in scope.
- `bash` is resolved once from host PATH. An executable named `bash` earlier in
  a user/project-influenced PATH can become the cached interpreter; absolute
  path alone is not trusted provenance.
- Background capacity is process-global (50), not per-run or aggregate resource
  budgeting. Jobs have no deadline and can each fork/process/allocate up to
  weak per-process sandbox limits.
- The manager mutex is held across garbage collection, the entire million-
  entry-capable sandbox tree scan, command construction, and spawn. During that
  interval output, listing, cancellation, and other spawns are blocked.
- `BufRead::lines` allocates an entire line before the 1 MiB retained and 100 KB
  ledger caps. A newline-free stream can exhaust memory; invalid UTF-8/read
  failure silently ends collection (F-047).
- Detached reader/wait threads have no handles or cancellation. `child.wait`
  failure never sets terminal state, while descendants holding pipes can keep
  `wait_for_output_readers` alive forever. Slots/jobs are not durably owned.
- Eight-character UUID prefixes are not collision-checked; collision overwrites
  a tracked entry and can orphan its process.
- Polling drains buffers irreversibly and reorders stdout before stderr. Kill
  removes the entry before supervised reaping and includes raw command/PID in
  result/audit text.
- Foreground capture retains up to 20 MiB, then renders only roughly 50,000
  bytes using an in-band truncation message. Nonzero command exit is classified
  as an external tool infrastructure error rather than typed command status.
- Verification detection is a substring search over the raw shell string. It
  grants `Authority::Verifier` from exit code alone, allowing fabricated
  verification evidence (F-046).
- Ledger creation/append is best-effort after execution. Commands/output may
  contain secrets, yet error/debug/ledger paths carry raw strings without an
  explicit sensitivity/redaction contract.
- Tests include useful owner/race regressions but also tautologically construct
  the capacity error string instead of reaching the cap and contain many
  sleep/timing-heavy process tests. They omit false-safe auto-approval through
  the public executor, output line bombs, job durability/resume, thread/wait
  errors, ID collision, binary provenance, verifier spoofing, and full
  lifecycle shutdown.

#### `src/tools/cron.rs`

Status: Read in full, including unit tests
Disposition: Keep schedule CRUD intent; implement the missing scheduler and harden storage

Findings:

- Metadata create/list/delete is reachable and works. On Unix the full
  load-modify-save sequence takes an advisory lock, corrupt JSON is preserved,
  and temp-file fsync plus rename avoids ordinary partial destination writes.
- There is no scheduler consumer anywhere in production. All operational
  fields (`enabled`, `recurring`, `durable`, `last_run`, `run_count`) are dead
  metadata, and registry copy is the only place clearly admitting that
  OpenClaudia never runs the schedule (F-051).
- A non-recurring schedule still requires a recurring cron expression, while a
  `durable=false` record is still durably persisted. Enabled cannot be toggled;
  next run/timezone/DST/day-field semantics are absent.
- The persisted prompt is arbitrary future agent instruction in a repository-
  local control file. There is no provenance/trust decision, user-scoped
  authorization, exact allowed-tool/resource capability, budget, expiry, or
  prompt-injection boundary for a future noninteractive run.
- `cron_create`/delete are mutating handlers without mandatory registry
  permission effects (F-001). They directly use `std::fs` rather than the
  secure capability filesystem, allowing parent symlink/control-path races and
  bypassing canonical resource identity/read-write policy.
- The non-Unix claim that a writable open “provides serialization” is false;
  no locking is performed there. Windows rename-over-existing semantics also
  differ from the POSIX guarantee described by the module.
- Unix `flock(LOCK_EX)` can block indefinitely without cancellation/deadline.
  Lock and data files use ambient umask rather than explicit restrictive modes.
- Temp data is fsynced but the parent directory is not synced after rename, so
  the stated power-loss durability is incomplete. Write/sync failures before
  rename leave orphan UUID temp files, and replacement does not deliberately
  preserve/set metadata.
- Store reads, names, prompts, expressions, and serialized bytes are unbounded.
  The 50-record creation cap is not enforced when loading an externally edited
  store; list bounds only prompt previews, not other fields/total output.
- Loaded records are not revalidated for duplicate names/IDs, cron validity,
  timestamps, field coherence, or maximum sizes. Delete by name removes every
  duplicate, and supplying multiple identifiers silently uses name then index
  then ID despite schema text requiring exactly one.
- Cron validation covers basic five-field numeric/range/step syntax but has no
  execution semantics, timezone, Sunday-7 compatibility decision, next-fire
  calculation, or property tests against a scheduler implementation.
- Several tests duplicate argument checks. The “atomic reader” test never runs
  a concurrent reader, directory durability/disk-full/cancellation/symlink/
  Windows locking are untested, and no test observes a scheduled run because no
  run path exists.

#### `src/tools/crosslink.rs`

Status: Read in full; no module-local tests
Disposition: Keep durable issue/task state; replace argv facade and unsafe storage/migration

Findings:

- Direct library/SQLite use avoids a subprocess and the issue, dependency,
  comment, label, tree, and work-session concepts are valuable externalized
  agent state.
- All read and mutation operations share one `args: String` mini-CLI. The
  registry cannot know which effect will occur before permission evaluation;
  `permission_target` is absent, so every mutation is currently classified as
  safe (F-001/F-052).
- `help` still calls `open_db` first, creating `.crosslink`, migrating legacy
  data, and opening/migrating SQLite for a nominally pure documentation call.
- `.crosslink` is created with direct `std::fs::create_dir_all`; parent/leaf
  symlinks, permissions, trusted root, quotas, and canonical capability/resource
  policy are not enforced. It is not among the sandbox/file-control paths
  protected elsewhere.
- Legacy migration byte-copies a possibly live SQLite main file rather than
  using SQLite backup/transaction semantics; WAL content can be missed. A copy
  failure is called nonfatal, but a partial destination may remain and cause
  the subsequent open to fail rather than start cleanly.
- The repository currently tracks `.chainlink/issues.db` but has no
  `.crosslink/issues.db`; first tool use would create an untracked migrated
  store. Ownership, source-of-truth, version control, backup, and migration
  policy are unresolved.
- Input strings/tokens, titles, descriptions, comments, labels, searches, and
  database size are not bounded here. List/search cap rendered rows only after
  the database API has materialized all results; show/tree/comments and total
  output are unbounded and unpaginated.
- Multi-step create+labels is not transactional and intentionally ignores every
  label error, returning success with partial state. Other mutation results do
  not expose optimistic conflicts or exact changed records.
- Parsers often ignore extra positional arguments and allow arbitrary priority/
  status values to reach the library. Mutually exclusive/options schema and
  canonical normalized operation types are absent.
- `session` always calls Crosslink's `*_for_agent(None)` APIs, placing all
  frontends, sessions, and subagents into the same default work-session bucket.
- `next`/`ready` comments and help claim a highest-priority ready/no-blocker
  recommendation, but the implementation never queries dependencies; it merely
  sorts every open issue by a hard-coded priority map and ID.
- Recursive tree rendering has no visited set, depth/node/output cap, or cursor.
  Corrupt/cyclic imported graph data can recurse indefinitely/overflow; broad
  graphs can exhaust context.
- No module-local tests cover parsing, permission effects, transactions,
  migration/WAL/corruption, symlinks, per-agent sessions, graph cycles,
  blocker-aware `next`, pagination, limits, or concurrency. The complete
  integration-test read found no end-to-end coverage that closes these gaps.

#### `src/tools/file_index.rs`

Status: Read in full, including unit tests
Disposition: Keep fuzzy file navigation; rebuild on secure deterministic discovery

Findings:

- Iterative traversal, a depth cap, cycle detection intent, and precomputed
  match data are useful. The index is currently used by the legacy REPL slash
  surface rather than registered as a model tool.
- The module claims to respect `.gitignore` but never reads ignore files. It
  hard-codes a few directory names and skips every dot-prefixed entry, producing
  both false inclusions and false exclusions.
- Traversal uses direct pathname `read_dir`, `is_dir`, and `canonicalize`, not
  secure session capabilities. It follows directory symlinks—including targets
  outside the root—and indexes their filenames under the lexical symlink path.
- There is no visit/file/byte/time/memory/output or cancellation budget, no
  partial/error metadata, and no total file cap. Unreadable directories/entries
  and depth truncation disappear silently.
- Filesystem enumeration order is retained. Search sorts only by score, so ties
  inherit nondeterministic traversal order; a limited top page is unstable.
- Search materializes and clones every match before sorting/truncating. Query
  and limit are not bounded locally, and results lack root/resource identity,
  version, cursor, completeness, or stale-index metadata.
- Lowercasing can expand or otherwise change Unicode scalar alignment, while
  scoring indexes the original-character vector using lowercase indices.
  Certain non-ASCII filenames/queries can produce incorrect bonuses or an
  out-of-bounds panic.
- Tests cover basic scoring, one cycle, and depth termination, but not actual
  ignore semantics, outside-root symlinks, deterministic caps/ties, Unicode
  expansion, non-UTF-8 names, partial errors, budgets, cancellation, or index
  freshness after workspace changes.

#### `src/tools/grounding.rs`

Status: Read in full, including unit tests
Disposition: Keep selective evidence hydration; replace binary authority and string result

Findings:

- Observation-ID validation, deduplication, stale filtering, and explicit
  missing/omitted lists are useful selective-context behavior.
- `authoritative_evidence` is simply every non-stale observation whose authority
  is not `ModelSummary`. This collapses user intent, arbitrary tool/web/MCP
  results, shell output, policy decisions, and trusted verification into one
  Boolean even though they have different domains and prompt-injection risk.
- F-046 makes the binary particularly unsafe: substring-detected shell commands
  can already receive Verifier authority and are then presented here as
  authoritative evidence.
- The nominal 12 KiB constant is per selected text field, not per result. Up to
  16 observations can each carry multiple capped fields; verification findings,
  argv, paths, labels, and other arrays/scalars are not aggregate-bounded.
- `truncate_json_value` serializes the entire value before checking size and
  clones it when under limit, so it does not bound source allocation/work.
- The successful response is pretty JSON converted to ordinary text rather
  than the canonical structured tool result (F-043). Hard-coded `rules` prose
  inside the data payload is another instruction-like string rather than typed
  provenance/evidence policy.
- Ledger selection depends on the todo thread-local session key and direct
  project-session persistence, inheriting F-033 and the pending ledger storage
  audit. Raw errors may reveal storage details.
- Tests prove ordinary/stale/summary behavior and non-creation on missing state,
  but not aggregate caps, hostile tool content, domain-specific evidence,
  verifier spoofing, corrupted stores, concurrency, typed round-trip, or
  frontend final-gate enforcement.

#### `src/tools/lsp.rs`

Status: Read all 3,371 lines, including unit tests
Disposition: Keep code intelligence; replace per-call shim with a bounded per-workspace LSP client

Findings:

- Capability-confined same-handle file reads, a file-size ceiling, child RAII,
  stdout read timeouts, stderr drainage, readiness/shutdown sequencing,
  LocationLink normalization, coordinate conversion, and nine intended actions
  are useful implementation work to preserve.
- `is_lsp_connected` means only “a binary name resolves on host PATH.” It does
  not represent a connection, sandbox availability, compatible version,
  successful initialization, or health. The registry advertises LSP regardless
  of per-language availability.
- Every call starts and indexes a new server, making cold requests expensive
  and losing server caches. The process-global didOpen registry is keyed only
  by binary/path and is incorrect for concurrent fresh server instances
  (F-055).
- The LSP `processId` sent from the host is not a valid client PID inside the
  new PID namespace. Parent-liveness semantics are therefore incoherent; send
  null or a namespace-correct supervisor identity.
- Language servers execute project code/config/plugins/build scripts. Because
  SandboxProfile::LanguageServer receives every session write root (F-048), a
  supposedly read-only intelligence query can modify the repository.
- Server availability and executable selection use host PATH/bare names, not a
  configured trusted executable/version/digest bound to policy. Extension and
  server/argument tables are static, case-sensitive, and lack user-managed
  initialization/configuration capability.
- LSP-safe environment prefixes allow any `LC_*` or `XDG_*` name without the
  sensitive-name backstop used by Bash; custom `XDG_SECRET`/`LC_TOKEN`-style
  values could cross the boundary. Tests mutate process-global environment
  without synchronization while claiming no readers race.
- URI creation is string concatenation over display paths, not standards-
  compliant file-URI encoding. Spaces, `%`, `#`, non-UTF-8 paths, and Windows
  forms are mishandled; the reverse converter is explicitly POSIX-only.
- Returned URIs from a project-controlled server are neither normalized nor
  checked against session read capabilities. They are emitted as navigation
  targets without provenance/completeness metadata.
- File metadata is checked at 10 MiB, then up to 10 MiB+1 is read from the
  descriptor without checking the post-read size. A growing file can be sent
  truncated; the read is not recorded as the same typed snapshot/evidence used
  by file tools.
- Line/character overflows saturate rather than reject. Query and hierarchy
  payloads are unbounded. Actions that do not need a document/position still
  require/read/open a file and cold-start a server.
- `prepareCallHierarchy` discards the full opaque item required by its follow-
  ups, and workspace symbol projection discards name/kind/container (F-053).
- stdout transport uses a detached reader and unbounded MPSC channel. Header
  lines, Content-Length, frames, queued chunks, parsed JSON, hover text,
  locations, symbols at each width, hierarchy objects, and final pretty JSON
  have no aggregate byte/result limit (F-054).
- Read timeouts are per receive, not total. A server can drip bytes forever;
  readiness checks the wall deadline around headers but not during an
  arbitrarily sized body. Up to 100 messages is host-env configurable without
  a byte cap.
- didOpen sends as much as 10 MiB through synchronous `write_all` with no write
  deadline/cancellation. A non-reading server can block the caller (F-044).
- Reverse requests are answered only while waiting for initialize. During
  readiness, the actual action, and shutdown they are ignored/unanswered; a
  server awaiting configuration/applyEdit/workspace folders/user interaction
  can stall. Registration requests are acknowledged despite capabilities not
  actually being implemented.
- Matching JSON-RPC responses are accepted without validating `jsonrpc` or
  checking `error`; request/initialize failure becomes an empty successful
  `LspResult` or proceeds into later protocol phases (F-054).
- Result parsing silently drops malformed locations/symbols, truncates symbol
  depth without a partial flag, loses call-range details, and returns no stable
  pagination/cursor/document version. `parse_symbols` adds one after a
  saturating u32 conversion with ordinary `+`, which can overflow on a hostile
  maximum coordinate.
- Gitignore filtering uses another PATH-resolved Git process after materializing
  all unique paths/input, with naive newline path framing and F-044's blocking
  stdin helper. It is best-effort and only applied to three actions; filtered/
  failed coverage is not returned as typed metadata.
- Server stderr and all semantic output are project-controlled untrusted text,
  yet are directly embedded in model-facing error/result prose without source
  labeling, prompt-injection handling, sensitivity policy, or aggregate budget.
- Tests are broad at helper/shape level, but many explicitly pin known gaps or
  permit environment-dependent/vacuous success. They omit concurrent real-
  server didOpen, server error objects, huge/drip-fed frames, blocked writes,
  full reverse-request lifecycle, project-write denial, URI conformance,
  continuation round-trip, restart/generation, aggregate result caps, and a
  representative live server matrix.

#### `src/tools/plan_mode.rs`

Status: Read in full, including unit tests
Disposition: Keep plan approval workflow; replace markers/thread-local gating with typed runtime state

Findings:

- Argument shape checks and the intended top-level-only plan transition are
  useful, but enter/exit remain ordinary JSON marker strings (F-032) rather
  than trusted state transitions.
- The tool is stateless: it cannot validate current mode, transition ID,
  session/run, actor, pending plan version, approval, or whether an exit is
  legal. Enforcement is deferred inconsistently to frontends.
- Subagent detection is a thread-local Boolean. It is not async-task/run safe;
  explicitly dropping an owning outer guard before a nested non-owning guard
  clears the flag early, and only enter—not exit—is guarded here.
- `allowed_prompts` is an unbounded cloned array. Strings/entry count/aggregate
  bytes, duplicate/conflicting entries, tool existence, normalized operation,
  effect scope, and unknown fields are not validated.
- The name can be mistaken for permission, but values are prompt descriptions,
  not scoped approval receipts. Consumer audit must ensure they never grant
  capabilities.
- Tests assert marker formatting and thread-local behavior. A section title
  claims plan mode blocks write/edit/Bash, but no test here exercises public
  executor permission enforcement, frontend parity, spoof resistance, async
  subagents, or approval/version round-trip.

#### `src/tools/remote_trigger.rs`

Status: Read in full, including unit tests; all production consumers searched
Disposition: Keep named external-action intent; replace unwired in-memory registry

Findings:

- HTTPS-default parsing and name-based indirection are reasonable starting
  ideas for keeping endpoint URLs out of model arguments.
- There is no production consumer or executor; the file explicitly leaves tool
  wiring elsewhere, but source-wide search finds none (F-056).
- Endpoint and registry derive `Debug` while header values are plain strings;
  auth tokens can leak through diagnostics/clones. Errors include raw URLs,
  which may contain userinfo/query credentials.
- HTTPS alone does not prevent SSRF. Loopback, private/link-local/cloud metadata,
  IPv6, DNS rebinding, redirects, cross-origin header forwarding, proxy policy,
  and host allowlists are absent.
- A public plaintext constructor is not bound to host-only authority and is not
  actually restricted to the localhost/air-gapped use described by docs.
- URL validation accepts userinfo, query, fragments, arbitrary ports/IDNs, and
  unbounded inputs. Names/headers/counts are unvalidated/unbounded and names
  iterate nondeterministically.
- There is no configured provenance/persistence, payload schema, HTTP method,
  content type, timeout, cancellation, response cap, redirect policy,
  idempotency, retry, rate limit, permission classification, audit, or result
  delivery.
- Unit tests only cover registry/URL mechanics; no network or agent lifecycle
  exists to test.

#### `src/tools/skill.rs`

Status: Read in full, including unit tests
Disposition: Keep explicit skill invocation; remove XML/system-splice fiction

Findings:

- Explicit named lookup is useful and missing/type/empty arguments are handled.
- The result wraps project/user-authored Markdown in an XML-shaped ordinary
  string. Escaping the name attribute does not make the raw body trusted or
  create an instruction authority boundary.
- Comments and registry schema say an orchestrator will splice the envelope
  into the next system prompt. Source-wide search finds no production envelope
  parser/consumer; it is currently just a normal tool result. Implementing the
  documented splice literally would create the authority flaw W16 prohibits.
- Source trust, allowed tools/model/effort/hooks, conditional activation,
  budgets, freshness, and project approval remain issues in `skills.rs`; this
  facade applies none of them as scoped runtime capabilities.
- Result size is not bounded here and name lookup/listing is not a typed
  registry selection. The XML wrapper duplicates content/tokens without a
  machine-readable result.
- Tests avoid a real installed-skill invocation and only pin wrapper strings;
  no provider/frontend invocation, project-trust, capability application,
  injection, freshness, or budget test exists.

#### `src/tools/task.rs`

Status: Read in full; unit coverage in the related modules was also audited
Disposition: Keep structured tasks; consolidate with canonical task graph

Findings:

- Create/update/get/list expose stable task IDs, statuses, dependencies, and
  active-form intent through `TaskManager`, a richer model than todos.
- Registry handlers mutate task state without a mandatory permission effect
  (F-001), and availability depends on an optional manager in `ToolContext`
  while the tool is advertised unconditionally.
- Subjects, descriptions, active forms, dependency-array counts/bytes, total
  tasks, and rendered list/result size are unbounded at this facade.
- Update accepts an unversioned patch. Concurrent/stale agents have no expected
  version, conflict result, actor, or transaction identity. The later complete
  `TaskManager` audit confirmed invalid graph/state transitions and persistence
  gaps (F-057/F-065).
- Missing get returns the literal text `null`; other results are rendered prose.
  Neither survives as canonical structured output (F-043).
- The feature overlaps todos and Crosslink with no documented source-of-truth,
  synchronization, migration, or selection boundary (F-057/W20).

#### `src/tools/testutil.rs`

Status: Read in full
Disposition: Keep shared test lock while process-global CWD dependencies remain

Findings:

- A single shared lock is better than per-module locks for tests that must
  mutate process CWD. Current source search finds participating calls in output
  style, plugin manager, tools tests, and worktree helpers.
- The contract is voluntary and cannot protect external/integration tests or
  code that forgets the helper. It recovers poisoning, allowing later tests to
  continue after potentially incomplete restoration.
- Long-term removal of process-CWD-derived production behavior and
  path-explicit test helpers should make this workaround unnecessary; until
  then it is useful test infrastructure, not runtime cruft.

#### `src/tools/todo.rs`

Status: Read in full, including unit tests
Disposition: Consolidate useful lightweight planning into the canonical versioned task graph

Findings:

- Per-item status typing, a 2,000-byte content cap, full-call validation before
  mutation, and nominal per-session buckets are useful behaviors.
- `SessionIdGuard` calls security-context setup but logs and continues on
  failure. The same todo thread-local and `__default__` fallback determine
  security, file snapshots, process ownership, and ledger identity throughout
  the codebase (F-033/F-057).
- Thread-local identity is not stable across async task movement/spawned work.
  Only ACP/shared executor sites install it; legacy paths can share the default
  bucket. No production session-end call clears todo buckets, so the global map
  and completed/inactive session keys can grow for process lifetime.
- `activeForm` and todo count/aggregate bytes are unbounded; read/output clones
  the entire list. Unknown fields are ignored and there are no stable item IDs,
  versions, timestamps, provenance, dependencies, ownership, or durable resume.
- Full replacement makes concurrent or stale writes last-writer-wins. Holding
  one mutex makes each replace atomic but does not prevent an older all-done
  write from clearing a newer pending list; comments overstate the race fix.
- Multiple in-progress tasks produce only an English warning. Parallelism and
  the one-active-task invariant are not represented structurally.
- Automatically deleting all completed items discards history/checkpoint
  evidence needed for long-horizon resume and evaluation.
- Getter/clear helpers suppress poisoned-lock failure into empty/no-op results,
  concealing lost planning state.
- Todo mutation is unclassified in permissions and duplicates TaskManager,
  Crosslink, and plan-mode state without reconciliation (F-057).
- Unit tests serialize on a private lock that other modules do not share and
  pin process-global/full-replacement behavior. They omit async identity,
  security-setup failure, session cleanup/leak, version conflicts, large lists,
  persistence/resume, and cross-representation consistency.

#### `src/tools/tool_search.rs`

Status: Read in full, including unit tests; API tool-definition callers searched
Disposition: Preserve progressive tool discovery; replace text-envelope fiction with provider/runtime-supported activation

Findings:

- Deterministic keyword ranking, required name terms, and a result ceiling are
  useful primitives for reducing a large tool surface.
- The feature does not defer any schemas in current production paths. Every
  provider, pipeline, ACP request, REPL request, and subagent still receives
  `get_all_tool_definitions`; the search tool then returns duplicate definitions
  as ordinary result text (F-058).
- A `<functions>` string cannot itself register callable tools with an API or
  the trusted executor. No production consumer parses the envelope, and adding
  a generic parser would repeat the unsafe data-to-control transition in F-032.
- `select:` ignores `max_results` and has no independent count/query/output-byte
  limit. An unbounded comma list, including duplicate names, can reproduce
  schemas repeatedly and flood model context despite the advertised hard cap.
- Unknown direct selections are silently ignored and all-unknown/empty searches
  are reported as successful ordinary text. This prevents reliable discovery,
  availability, and typo handling through typed state.
- Search rebuilds definitions repeatedly and ranks only names/descriptions by
  ASCII substring. It has no capability/effect/risk/provider/availability
  metadata, namespace collision handling, semantic index, invocation telemetry,
  or measured retrieval-quality baseline.
- Tests validate rendered XML-like strings and the keyword cap, but omit the
  direct-selection bypass, aggregate bytes, duplicate selection, actual schema
  activation/invocation, capability filtering, frontend parity, or context and
  task-quality improvement.

#### `src/tools/web.rs` and `src/web.rs`

Status: Both read in full, including unit tests; all direct consumers traced
Disposition: Keep fetch, search, browser rendering, and focused distillation; repair execution, trust, budgets, and policy

Findings:

- The feature has substantial working implementation: strict basic argument
  types, bounded search count, fetch-output truncation, provider-adapter reuse,
  HTTP/body deadlines in several layers, deterministic domain filtering, and
  network-independent unit/integration seams.
- `run_blocking_with_timeout` drops its receiver on timeout but never aborts the
  spawned future. Browser/search `spawn_blocking` work also continues after the
  Tokio timeout because blocking tasks are not cancelled. Repeated slow calls
  can accumulate HTTP work, threads, browsers, processes, and side effects after
  the agent was told the operation ended (F-059).
- The bridge parks the calling OS thread with `std::sync::mpsc::recv_timeout`.
  Comments explicitly place a synchronous handler on a current-thread Tokio
  executor, so one web call can stop unrelated async progress/cancellation on
  that runtime for up to 90 seconds. The process-wide runtime has no admission,
  per-run ownership, concurrency, or shutdown accounting.
- The lower direct-HTTP implementation adds useful scheme/hostname/IP checks,
  async initial DNS validation, redirect-hop validation and a streamed 10 MiB
  cap. The facade's prefix check is therefore not the only defense. However,
  validation and connection perform separate DNS resolution, redirect hostnames
  receive only the DNS-free check, and the configured proxy/resolver is not
  bound to an approved address. Rebinding remains an acknowledged bypass
  (F-102); no scoped network capability or typed egress receipt exists.
- Search query, prompt, domain-list count/bytes, and domain strings are
  unbounded. Domain entries are not parsed/normalized, unparseable result URLs
  bypass both allow and block filters, and filtering only after fetching the
  requested limit can return an avoidably empty/partial allowed set.
- Search/backend result field bytes and formatted aggregate output are not
  capped here. Fetch first materializes underlying content and an assembled
  output before truncating to 50,000 bytes, creating a larger allocation peak
  than the model-facing cap suggests.
- The default-enabled Chromium fallback executes hostile page JavaScript after
  only top-level prevalidation. Browser redirects, subresources, fetch/XHR,
  WebSockets, workers and downloads are not routed through the SSRF guard. It
  uses a persistent `.openclaudia/browser_profile` under attacker-controlled
  project state, can auto-download a browser binary at runtime, and materializes
  the whole DOM before checking its size. There is no owned browser pool,
  per-run profile, process/resource budget, credential isolation or network
  interception (F-102/F-103).
- Fetched pages, titles, URLs, snippets, provider error bodies, and distilled
  answers are ordinary unlabeled result prose. Delimiter-shaped page content
  can inject the secondary-model prompt; the fixed instruction is not a
  security boundary, and distillation can erase source context/provenance.
- Distillation creates a separate paid model call without a run-budget
  reservation, usage accounting, trace linkage, cancellation token, cache, or
  typed citation/grounding record. The declared output-token cap does not bound
  the full response body parsed from the provider.
- Unknown arguments are ignored and every result is flattened to `(String,
  bool)`, losing URL/redirect/source/query/filter/truncation/model/usage and
  partial-result structure (F-043).
- Tests strongly cover formatter boundaries, injected search filtering,
  runtime reuse, timeout reporting, and a mock distillation call. They omit
  proof that timed-out work is killed, current-thread executor liveness,
  concurrency/admission, cancellation, DNS rebinding/dial pinning, browser
  subresource/private-network access, profile attacks, hostile rendered-resource
  growth, malformed domain policies, indirect prompt injection, usage
  accounting, and provider/frontend parity. Several purported async-DNS tests
  use IP literals and therefore never exercise DNS; another depends on live
  `example.com`, so neither is deterministic proof of the claimed property.

#### `src/tools/worktree.rs`

Status: Read in full, including unit tests; all non-test consumers searched
Disposition: Keep isolated-workspace intent; repair as a typed, owned, transactional lifecycle before relying on it

Findings:

- Explicit subprocess working directories, branch validation, an absolute Git
  binary, disabled hooks/global configuration/interactive credentials, shared
  timeouts, dirty-tree refusal, and merge-abort handling are meaningful safety
  improvements worth preserving.
- The file explicitly stops at “Phase 1.” No caller records the returned path
  as the run's active workspace, no file/Bash/LSP context switches to it, and
  `cwd_cache_generation` has no production consumer. Isolation therefore
  depends on the model copying a path from prose into later calls (F-061).
- Enter/exit/list have no permission targets (F-001). A model can set
  `discard_changes=true` itself; this is not user acknowledgement or a scoped
  destructive approval. `exit_worktree` does not require that the path be in
  the in-memory active set or was created by this run, so any accessible linked
  Git worktree can be force-removed.
- The `apply_changes=true` preservation path has a critical data-loss error:
  every non-successful `git commit` is treated as the expected “nothing to
  commit” case. Missing identity, signing/config/filter failure, timeout, or
  any other commit error then proceeds to `git worktree remove --force`,
  destroying the changes the caller asked to merge (F-060).
- `git add -A` stages and commits every preexisting tracked/untracked change,
  not only agent-owned edits. Merge targets whatever branch/HEAD happens to be
  checked out in the main worktree, without checking expected base/target HEAD,
  main-tree cleanliness, concurrent user activity, protected branches, or a
  merge approval/preview.
- Repository-local Git configuration and attributes remain authoritative.
  Staging, committing, and merging can invoke configured clean filters, signing
  programs, or custom merge drivers inside the broad Git sandbox (F-048), so
  disabling hooks/global config alone does not prevent project-controlled
  subprocess execution.
- Validation is a multi-command path/string sequence with no descriptor or
  repository-identity binding. The caller-supplied path can be a symlink and
  can change between `rev-parse`, status, merge, and force-removal (TOCTOU).
  Raw `git_dir == common_dir` string comparison is not a canonical identity.
- Duplicate-enter checking releases its global mutex before creation and only
  registers after success. It is neither atomic nor durable/per-run; poison is
  logged and ignored, restarts lose ownership, existing worktrees are not
  reconciled, and two concurrent calls can both pass the guard.
- `--show-toplevel` failure or non-UTF-8 output silently falls back to the
  session working directory. Path conversion later uses `to_str().unwrap_or("")`.
  This can create/operate at the wrong location or issue Git an empty path
  instead of failing closed.
- Existing-branch retry depends on an English stderr substring and reports the
  first failure even if the retry fails for a different reason. Git stderr,
  paths, branches, and complete worktree lists are returned as ordinary
  unbounded prose rather than typed repository/operation state.
- Tests exercise real create/remove/dirty refusal, branch hardening, no CWD
  mutation, timeout plumbing, and source-shape invariants. They omit commit-
  failure data preservation, dirty/concurrent main worktrees, arbitrary foreign
  linked worktrees, symlink replacement, concurrent enter/exit, restart
  recovery, repository config/attribute execution, non-UTF-8 paths, scoped
  approval, and end-to-end tool routing into the new workspace.

#### `src/services/mod.rs`

Status: Read in full, including unit tests; all production consumers searched
Disposition: Keep a composition root only if it becomes the canonical runtime owner; otherwise consolidate after preserving real services

Findings:

- Arc-backed explicit service interfaces and redacted manual `Debug` are useful
  composition primitives, but the registry contains only analytics, flags, and
  plugin MCP declarations despite presenting the entire services layer.
- Source-wide production search finds no construction or use of
  `ServiceRegistry`; all references outside this file are comments. Analytics,
  flags, and plugin MCP declarations installed here therefore affect no product
  path (F-006/W9).
- `Default`/`noop` silently disables every contained service. That is convenient
  for tests, but a dangerous production composition default because a missing
  installation is indistinguishable from an intentional disabled state.
- `wire_plugin_mcp_servers` only replaces plugin IDs present in the supplied
  iterator; it does not reconcile registrations for plugins that disappeared.
  There is no registry-level unload method or consumer invoking the underlying
  removal, so stale declarations would survive a partial reload even if wired.
- Poisoned locks are recovered without reporting potentially inconsistent
  service state. Registration count/input size, plugin trust, provenance,
  generation, conflict handling, and deterministic publication are absent.
- Unit tests cover clone/accessor/no-op mechanics, not product construction,
  lifecycle start/drain/stop, missing-service failure, plugin load/unload, or any
  end-to-end service effect.

#### `src/services/mcp_registry.rs`

Status: Read in full, including unit tests; all production consumers searched
Disposition: Keep plugin-declared MCP capability; replace the unwired secret-bearing mirror with validated runtime registrations

Findings:

- Per-plugin replacement/removal and retaining owner attribution are sensible
  registry semantics.
- The module explicitly labels itself Phase 1 and says transport wiring is a
  future step. No production code consumes `PluginMcpRegistry`, registrations,
  or specs outside the unused `ServiceRegistry` (F-006/W6).
- `McpServerSpec` and `McpRegistration` derive `Debug`, `Clone`, and equality
  while storing raw environment values, static authentication headers, endpoint
  URLs, and a header-helper command. Logs/assertion failures can expose secrets,
  and cloning spreads ordinary secret strings (F-015/F-022).
- `from_plugin_config` deliberately performs no validation. Transport strings,
  command/args/env/headers/URL/helper, timeouts, names, counts, and aggregate
  bytes are unbounded; contradictory stdio/HTTP combinations are retained for a
  nonexistent later spawner to reject.
- Registrations do not encode plugin trust/install generation, approval,
  filesystem/process/network capabilities, secret provenance, schema/result
  budgets, lifecycle health, or whether tools should actually be callable.
- `replace_plugin` trusts each record's embedded `plugin_id` even when it
  disagrees with the map key. Enumeration is intentionally nondeterministic,
  has no generation/snapshot receipt, and clones every secret-bearing record.
- Unit tests cover basic collection mechanics and one raw config copy, but not
  validation, redaction, ownership mismatch, concurrency, reload/uninstall,
  runtime MCP connection, or malicious plugin configuration.

#### `src/services/auto_compactor.rs`

Status: Read in full, including unit tests; all production consumers searched
Disposition: Keep automatic/micro-compaction intent; consolidate this unwired wrapper into the canonical run budget after mechanism audit

Findings:

- Separating the decision policy from the compaction mechanism is reasonable,
  and `Option<CompactionResult>` honestly distinguishes a skipped operation.
- No production caller constructs or invokes `AutoCompactor`; its only external
  references are a re-export and a `ContextCompactor` doc comment. The file
  acknowledges it is not in `ServiceRegistry`, despite claiming the hook is
  “now reachable through this service” (F-006/W9).
- `auto_microcompact` decides using the compactor's normal maximum-context
  threshold and passes no actual token hint. It ignores `target_tokens` while
  deciding, so a request above the desired micro target but below the normal
  max is skipped despite the method's partial-budget claim.
- The wrapper has no run/context generation, reservation, cancellation,
  concurrency/idempotency, trace, or frontend binding. The later complete
  compaction audit confirmed nontransactional mutation, authority, retrieval,
  and token-estimation defects (F-077/F-078).
- Tests cover two predicates and the small-request no-op only. They never run a
  successful full/micro compaction, target-driven decision, hook, memory,
  rollback/error, token hint, or production request path.

#### `src/services/feature_flags.rs`

Status: Read in full, including unit tests; all production consumers searched
Disposition: Keep explicit rollout/config gates if needed; consolidate the currently unused implementation into typed configuration

Findings:

- A small injectable boolean source with environment-over-static precedence is
  understandable, and snapshotting avoids repeated environment access.
- No production feature checks use this trait or implementation. Outside this
  file, only the unused `ServiceRegistry` constructs it (F-006/W9).
- `StaticFlags` derives `Default`, which creates empty maps rather than calling
  `new()`. `ServiceRegistry::noop()` uses that default, so the one documented
  composition path does not snapshot or honor any `OPENCLAUDIA_FEATURE_*`
  environment overrides.
- `snapshot_env_overrides` uses `std::env::vars`, which can panic when the host
  environment contains non-Unicode keys or values. Names/suffixes are not
  validated or canonicalized; map lookups remain case-sensitive while env
  lookups uppercase, allowing ambiguous/colliding identities.
- Unknown flags and malformed values silently become false. There is no typed
  declared-flag registry, source/provenance, unknown-name diagnostic, immutable
  generation, change audit, safe reload distribution, or exposure of effective
  configuration for production-readiness evidence.
- Runtime reload requires `&mut StaticFlags`, but the trait exposes only lookup
  and the registry stores an `Arc<dyn FeatureFlagSource>`; the documented future
  live-reload behavior cannot be performed through the actual abstraction.
- Tests thoroughly pin local truthiness/snapshot semantics, but mutate the
  process environment under a module-private mutex that cannot serialize other
  test modules. They do not test `Default`, non-Unicode environment entries,
  registry use, typo diagnostics, concurrent readers/reload, or any real gate.

#### `src/services/analytics.rs`

Status: Read in full, including unit tests; lifecycle consumers inspected
Disposition: Keep typed lifecycle telemetry; consolidate with redacted run traces and make policy explicit

Findings:

- Typed events, sink injection, subscriber state-switch events, exactly-once
  local `finish`, and keeping prompt content out of `PromptSubmitted` are useful.
- Unlike the surrounding registry, `StateAnalyticsSubscriber` is operational:
  the legacy REPL and TUI install `TracingAnalytics`, drain it, and finish it.
  They bypass `ServiceRegistry` directly. Only session start/end are emitted by
  production source; the other five event variants are test-only despite the
  file claiming they cover events actually emitted.
- `TracingAnalytics` logs raw session IDs at info level, and both current
  frontends install it unconditionally. The process default enables
  `openclaudia=info`; TUI data goes to a repository-local log and REPL data to
  stderr. There is no telemetry/privacy configuration, retention/redaction
  policy, consent surface, or stable pseudonymous run/workspace identity.
- `AnalyticsSink::record` is synchronous and the “must not panic”/buffer network
  guidance is only prose. A blocking sink stalls the frontend; a panicking sink
  propagates through construction, drain, finish, or `Drop` (and can abort on a
  double panic during unwinding).
- The event model omits duration, provider usage/cost, tool call/run IDs,
  retries, cancellation, partial/error category, effects, budgets, compaction
  provenance, and evaluation correlation. The comment saying headers are
  logged elsewhere normalizes unsafe secret logging rather than defining a
  redaction boundary.
- Manual polling means observability depends on each frontend reaching drain;
  the later state-store audit confirmed that no canonical runtime owner
  starts, drains, and stops the subscriber across every frontend.
- Tests validate variants, ordering, thread bounds, no-op calls, and one state
  switch, but not production installation policy, sink failure/latency, queue
  lag, abrupt termination, multiple frontends, redaction/retention, or trace
  correlation.

#### `src/services/tool_executor.rs`

Status: Read in full, including unit tests; all production call sites inspected at dispatch boundary
Disposition: Keep and expand into the only canonical typed execution lifecycle; remove optional/bypass-shaped entry paths during migration

Findings:

- This is operational and widely used by ACP, pipelines/TUI, legacy REPL,
  subagents, and intercepted tools. Central argument parsing, policy counting,
  session/ledger guards, task-manager injection, and dispatch are valuable
  convergence work.
- It is not yet the claimed complete lifecycle. Pre-hook, execution, post-hook,
  result observation, interactive permission, analytics, audit, cancellation,
  and rendering are independent public functions or caller-owned steps.
  Callers select different subsets and ordering, preserving F-004 rather than
  enforcing one state machine.
- `permission_already_checked: bool` is an ambient bypass assertion with no
  approval ID, normalized tool/arguments/effect binding, actor/session/workspace,
  scope, expiry, or single-use proof. Any internal caller can set it and reach
  `execute_tool_with_tasks_unchecked`; ACP and tests do so (F-030/F-031).
- Permission manager, policy enforcer, session ID, app config, memory, and task
  manager are all optional even when the registry advertises dependent tools.
  Missing values cause fail-open policy/permission behavior or late tool-level
  errors rather than capability-filtered non-advertisement.
- Policy checks only a caller-supplied tool-name/session counter and records the
  attempt before dispatch. Effects/arguments, denials, idempotent retry IDs,
  concurrency, nested calls, and check-before-prompt races await policy audit;
  ACP deliberately passes no policy enforcer on its local execution path.
- `SessionIdGuard::set` inherits todo-thread-local/ambient-CWD authority and can
  continue after security-context setup failure (F-033/F-057). Session IDs and
  tool call IDs are unvalidated strings, not immutable run/call capabilities.
- Argument JSON bytes/depth are unbounded; object parsing is cloned into both a
  map and value. Hook inputs clone the whole object and post hooks receive the
  full raw output. Hook block reasons are logged/returned unbounded and can
  contain project-controlled or sensitive text.
- The pre-hook imports extension inference from the deprecated rule-injector
  module. Extension/language metadata remains useful, but this dependency must
  move before complete rule removal (W1).
- Execution is synchronous; async frontends wrap it in `spawn_blocking`, while
  underlying tools create their own runtimes/threads/processes. This prevents a
  coherent cancellation/deadline/resource lifecycle (F-044/F-059/W10).
- Result state remains the lossy legacy `ToolResult` string/Boolean. Structured
  data, effects, approval receipt, policy decision, hooks, usage, provenance,
  truncation, observations, and terminal reason cannot be returned atomically
  (F-043).
- Tests cover JSON object rejection, a zero-cap policy block, and unchecked Bash
  execution. They do not prove the public path always enforces hard policy,
  exact approval binding, hook/permission/policy/observation ordering, missing-
  context failure, frontend parity, cancellation, effect accounting, or typed
  result preservation.

#### `src/services/policy.rs`

Status: Read in full, including unit tests; production provider/tool/reset consumers searched
Disposition: Keep hard policy; rebuild it as trusted, atomic, durable run-budget/capability enforcement

Findings:

- Model allowlisting, projected request/session token checks, typed errors, and
  per-session tool ceilings are useful operator controls and are wired into
  multiple provider and tool entrypoints.
- The supposedly atomic `check_and_record_tool` calls `check_tool` and then
  `increment` under two separate mutex acquisitions. Concurrent calls can both
  observe the last available slot and both execute, exceeding the hard cap
  (F-062).
- A poisoned counter mutex fails open: reads report zero and increments/resets
  silently do nothing after logging. The policy is then permanently bypassed
  for that enforcer. Increment can also overflow rather than saturating.
- `ToolExecutionPolicy` intentionally no-ops if either enforcer or session is
  absent, and a unit test pins that fail-open legacy behavior. Existing callers
  do omit the enforcer (including an ACP local-tool worker), so “enterprise”
  enforcement is frontend/call-path dependent.
- `reset_session` has no production caller. Counter keys grow for process
  lifetime; reused session IDs retain prior counts, while process restart loses
  all counters and restores the cap. Neither behavior is a durable per-session
  enterprise guarantee.
- Request token policy is a pure projection with no reservation/lease. Concurrent
  provider calls can all pass against the same cumulative count and overshoot;
  actual usage is not atomically committed here. The per-request check covers
  estimated input only, despite the module's broad “per-request token ceiling”
  wording, while output is included only in session projection.
- Estimates and configured `max_tokens` are trusted without estimator/model
  provenance or safety margin. There is no cost/rate/concurrency/elapsed/retry/
  subagent/tool-effect budget, idempotency key, or typed remaining-budget state
  shared with compaction and scheduling (W10).
- Tool caps use a bare tool name, so aliases/new names/compound argv operations
  and effects are invisible; unknown tools are unlimited. Model policy uses a
  bare model string without provider/endpoint/account/data-residency identity.
- The “enterprise” block is loaded from ordinary project configuration, not an
  authenticated host/managed policy source. Schema values/counts are unbounded,
  unknown YAML fields are not rejected here, and no provenance/signature/
  immutable generation or denial-dominance is encoded (W14/F-016).
- Public split evaluate/record APIs invite check/use races and missed records.
  Decisions have no receipt/reservation ID, call/run binding, trace/audit event,
  denial source, remaining allowance, or release/rollback semantics.
- Tests cover sequential boundaries, parsing, projection, reset, and the no-op
  compatibility behavior. They omit concurrent final-slot calls, poison,
  overflow, missing frontend enforcement, restart/durability, concurrent token
  reservation, project policy tampering, unknown fields, auxiliary model calls,
  and end-to-end hard-deny precedence.

#### `src/services/rate_limit_mock.rs`

Status: Read in full, including unit tests; all production/test consumers searched
Disposition: Preserve deterministic rate-limit fault injection; relocate/replace this unwired production module with a real transport test seam

Findings:

- Deterministic throttle counts, retry delays, call recording, enable/disable,
  and reset are useful test concepts.
- The file explicitly says proxy wiring is future work. Source-wide search finds
  no consumer at all outside its re-export and own unit tests, so it exercises
  neither the proxy's rate-limit behavior nor a provider adapter (F-006).
- Compiling a stateful mock into the normal production library without any
  guarded installation path increases public surface while providing no user
  capability. The right preservation target is an injectable HTTP/provider
  transport under test-support configuration, not a dormant nominal service.
- Lock poison returns `Proceed`, zero recorded calls, or silently ignores
  configuration, which can make a fault-injection test falsely pass. Call
  counters can overflow, and count/reason/duration inputs are unbounded.
- `next_response` consumes a throttle before any request is recorded, while
  `record_call` is independent. The seam cannot atomically represent attempted,
  sent, rejected, retried, or completed requests and has no request/session/
  provider identity.
- Only a numeric delay and reason are modeled. It cannot test HTTP-date or
  malformed `Retry-After`, provider JSON/header variants, streaming mid-response
  throttles, retries/jitter, cancellation, idempotency, concurrent requests,
  budget interaction, or exhaustion surfacing.
- Unit tests prove only the mock's private counter mechanics, not the product
  behavior the module claims it exists to verify.

#### `src/services/lsp_pool.rs`

Status: Read in full, including unit tests; all production consumers searched
Disposition: Keep warm managed LSP servers; replace this unwired unsafe pool under W21

Findings:

- Acquire/release, injectable spawning, idle reaping, and explicit shutdown are
  useful lifecycle concepts; reusing initialized servers is the correct
  performance direction.
- The module explicitly defers tool wiring and has no production consumer. LSP
  tools continue to spawn a fresh server per call (F-006/W21).
- The pool key is only a free-form language string. It omits workspace/session,
  canonical root, server binary/config/version, capabilities, environment,
  trust, and process generation. If connected, it could reuse one server and
  its indexed/open-document state across unrelated projects or security
  contexts.
- Documentation says dropping an acquired `ChildHandle` will SIGKILL its
  process, but Rust's `std::process::Child` has no such drop behavior. Forgetting
  to release leaks a live child; a poisoned `release` lock also drops the handle
  without killing/waiting, and a poisoned `kill_all` abandons every pooled child.
- Concurrent acquisition for one key spawns multiple servers. `release` always
  makes the last-released handle win and kills the previously pooled one; it
  cannot identify which generation is newer/healthy, contrary to its comment.
- No health/exit/protocol-state check occurs on acquire or release; handles with
  no child or an exited/desynchronized child can be reinserted and returned.
  The type owns only `Child`, not framed stdin/stdout, request multiplexing,
  document versions, pending calls, or initialization state.
- Kill and wait run synchronously while holding the global pool mutex, ignore
  failures, have no deadline/descendant cleanup, and can block all languages.
  Spawning is synchronous, unsupervised, and the trait itself encodes no W18
  capability or cancellation.
- Language count/name bytes, total processes/memory, acquire duration, TTL, and
  per-run concurrency are unbounded. There is no background reaper consumer,
  restart recovery, metrics, or shutdown registration.
- Tests launch bare PATH-resolved `sleep`/`timeout` processes and cover only
  sequential reuse, language separation, idle reap, and explicit kill. They omit
  dropped-handle leaks, poison, concurrent generations, dead servers, workspace
  isolation, protocol state, kill stalls/failure, descendants, and integration
  with the actual LSP client.

#### `src/services/lsp_diagnostics.rs`

Status: Read in full, including unit tests; all production consumers searched
Disposition: Keep diagnostic feedback; implement it as bounded versioned LSP data, not prompt injection

Findings:

- Replacing per-document diagnostics and surfacing compiler/linter failures to
  the agent are valuable. Severity typing and deterministic rendering are useful
  local primitives.
- The file explicitly ships only Stage A and has no producer or consumer. The
  LSP client still discards notifications, and no conversation path owns the
  registry/injector (F-006/W21).
- The claimed “wire-compatible” diagnostic is not LSP wire compatible: severity
  serializes as lowercase text rather than an optional integer and full range,
  end coordinate, code, code description, tags, related information, data, and
  document version are lost.
- Only diagnostic count per file is capped. URI/file count, URI/message/source
  bytes, aggregate diagnostics/output, and input allocation before truncation
  are unbounded. Replacement truncates the first entries in server order rather
  than preserving errors or a documented stable priority; it is not the
  “most-recent bounded FIFO” claimed by comments.
- State is not scoped by workspace/session/server/document URI capability or
  server/document generation. It can surface stale diagnostics after edits or
  restarts, mix projects if shared, and cannot prove an empty publish belongs to
  the current document version.
- `drain` destructively removes all projects/files for one consumer. Concurrent
  frontends/agents can steal each other's state, and failure after drain loses
  diagnostics. Poison silently converts reads to empty and writes to dropped.
- The default renderer embeds raw server-controlled URI, message, and source in
  an XML-like string. A diagnostic can close/forge the wrapper and inject prompt
  instructions; generic prompt splicing would repeat F-032/F-027. Diagnostics
  must remain typed, untrusted evidence with provenance.
- The “safe” headless default silently discards all feedback. There are no
  change correlation, deduplication, debouncing, publication timestamps,
  partial/stale flags, secure URI normalization, result paging, or evidence
  links to the relevant snapshot.
- Tests cover conversion helpers, collection mechanics, caps, drain, and string
  rendering only. They omit real publish notifications, hostile/large text,
  workspace/version isolation, error-priority truncation, injection, multiple
  consumers, staleness, poison, and model-facing task outcomes.

#### `src/services/background.rs`

Status: Read in full, including unit tests; all production consumers searched
Disposition: Keep maintenance/consolidation/summarization goals; replace unwired synchronous skeleton with W9 lifecycle and transactional W5/plugin jobs

Findings:

- A typed job interface, monotonic intervals, explicit outcomes, and tested
  expiry cleanup/deduplication are useful starting points.
- Source-wide search finds no production scheduler construction, registration,
  or tick. The only external reference is an LSP-pool comment about a future
  reaper. None of the four named jobs runs in the product (F-006/W9).
- “Deduplication” groups archival rows by exact content and deletes all but one
  without merging tags or other provenance/ownership metadata. Equal text used
  for different purposes loses distinctions; `records_deduped` calls deletion a
  merge although no merge occurs (F-063).
- Expiry and dedup passes are not one transaction, and dedup deletes row by row.
  A failure returns after partial deletion; a concurrent update between the
  unversioned full read and delete can erase newly changed state. No recovery,
  snapshot, dry-run, tombstone, or audit exists.
- `memory_list(usize::MAX)` loads/clones every row/content/tag, then content is
  cloned again into an unbounded map. Per-group ID accumulation performs an
  unnecessary linear `contains`, and textual timestamp comparison chooses the
  survivor without validating a common normalized time format.
- `AgentSummaryJob` does no semantic summary or the claimed first/last-paragraph
  heuristic. It joins all matching memory content, truncates the first 4 KiB,
  and stores that as archival truth. Ordering/provenance is unclear and the
  conclusion can be cut off.
- Any row can opt into summaries by carrying a `subagent-task:*` tag; task IDs,
  content volume, and tag count are unbounded. Raw tool output may be copied into
  long-term memory without task completion verification, ownership, privacy/
  sensitivity policy, user review, or retention authorization.
- Once any summary tag exists for a task, later evidence is ignored forever.
  Concurrent job runs can both create a summary. Individual save failures are
  only logged and the job returns success, and summary creation is misleadingly
  reported in `records_deduped`.
- Plugin auto-update and delisting jobs are log-only static snapshots. They do
  not poll, compare, verify signatures, update, detect delisting, or uninstall,
  yet logs say sources were polled. Source URLs (possibly credential-bearing)
  and plugin IDs are logged at info; `JobOutcome` cannot represent their work.
- The scheduler synchronously runs arbitrary jobs on the caller thread with no
  deadline/cancellation/admission, despite a non-enforced “must finish bounded”
  contract. It permits duplicate jobs/zero intervals, runs everything on first
  tick/restart, and sets last-run before success with only fixed-interval retry.
- Schedule state is in-memory `Instant` only. Multiple processes/restarts can
  duplicate destructive jobs; there are no leases/fencing, durable generations,
  idempotency keys, misfire/backoff policy, dependencies, permissions, budgets,
  shutdown/drain, per-job resources, or outcome/error persistence.
- Tests strongly exercise the isolated memory mutations and basic intervals but
  also spend cases on object safety/derive behavior. They omit production
  startup/tick, metadata-preserving dedup, partial failure, concurrency, stale
  summaries, privacy, real plugin transport, retry/backoff, cancellation,
  multi-process/restart, resource limits, and end-to-end surfaced outcomes.

#### `src/session/audit.rs`

Status: Read in full, including unit tests; all production consumers inspected
Disposition: Keep security auditability; replace frontend-local JSONL with canonical redacted tamper-evident run tracing

Findings:

- Typed setup/write errors, validated single-component session filenames, an
  always-open logger, structured JSONL, and explicitly surfaced security-write
  failures are useful improvements over silent swallowing.
- Only the legacy chat REPL constructs this logger. TUI, ACP, proxy, subagents,
  scheduled/background runs, MCP, and other local execution paths use different
  or no audit mechanisms (F-004).
- The REPL records complete raw tool argument JSON, including commands, URLs,
  file content, prompts, tokens embedded in arguments, and other sensitive data.
  There is no schema-aware redaction/classification, encryption, user privacy
  policy, or retention/export/deletion control.
- The preferred destination is repository-local `.openclaudia/logs`. Direct
  `create_dir_all`/append follows parent/final symlinks and uses ambient umask,
  not filesystem capabilities, no-follow opening, or restrictive explicit
  permissions. Project content can redirect, read, modify, truncate, delete, or
  accidentally commit the security log (F-014/W15).
- Fallback happens only after project-local failure; if fallback also fails the
  first project error is returned, hiding the real terminal cause. Choosing a
  writable repository sink first also means read-only workspaces get a safer
  host path than normal workspaces.
- `writeln!` does not flush or sync despite error documentation mentioning
  flush. There is no sequence/run/call/schema/policy generation, hash chain,
  integrity/signature, durable commit boundary, rotation/quota, disk-full
  reservation, multi-process framing/locking, or crash-tail recovery.
- `log_security` logs and returns an error, but every production call site logs
  again and continues dispatch/result processing. The “security-critical” audit
  is therefore neither mandatory nor a typed degraded-session state.
- Event/data bytes and nesting are unbounded. Multiple writes/processes sharing
  a session filename can interleave or reorder entries, timestamps can regress,
  and session-file identity is not bound to actor/workspace/run capabilities.
- Tests cover basic JSONL, traversal ID rejection, setup/write failure, and
  error-level escalation. They omit symlink/hardlink attacks, file modes,
  redaction, concurrent writers, crash/flush, tamper detection, quota/rotation,
  fallback-cause reporting, frontend coverage, and mandatory failure policy.

#### `src/session/state.rs`

Status: Read in full, including unit tests; plan-policy consumers searched
Disposition: Keep metrics and plan workflow; replace static/path-check policy with typed state/effects and secure file capabilities

Findings:

- Token/turn metrics, prior-mode capture, hard default-deny for unknown names,
  and deliberate plan-file restriction are valuable intended state.
- `TokenUsage::total` and `accumulate` use unchecked addition. Corrupt/provider-
  hostile or repeated persisted values can panic debug builds or wrap release
  usage/cost/policy totals. `UsageExtras` is an empty production placeholder.
- The plan-mode list is described as read-only, but includes `task` and
  `crosslink`, whose single tool names cover mutation/deletion/database migration,
  plus network/paid-model `web_fetch` and user interaction. Static name
  allowlisting cannot distinguish read versus mutation variants (F-064).
- MCP/plugin opt-in flags are operationally ineffective: dynamic names retain
  `mcp__...`/`plugin__...` prefixes and can never equal any bare static allowed
  name. No concrete prefixed registration can be added at runtime to the const
  list, so lifting the prefix rejection still reaches final deny.
- Enter/check are not TOCTOU-safe as claimed. They open one file descriptor but
  separately canonicalize the pathname without comparing descriptor identity;
  checks drop the descriptor before execution reopens the path. The file or a
  parent can change between metadata/open/canonicalize/check/use. Actual secure
  write behavior depends on lower filesystem code, not this gate's guarantee.
- Stored identity is a path, not a descriptor/resource capability or inode/file
  generation. Plan state derives unrestricted `Deserialize`; resumed/corrupt
  data can construct `active`, paths, previous mode, and prompt allowances
  without rerunning `enter` validation. Full persistence behavior awaits
  `session/mod.rs`.
- Marker tools are name-allowed regardless of current state/transition ID.
  Allowed prompts and previous-mode strings are unbounded/unvalidated here, and
  static tool lists can drift from runtime availability/effects.
- `get_session_context` represents roles/resume guidance as untyped system prose
  and embeds a parent session ID directly. It has no provenance, budget,
  capability, or actual handoff/task/evidence binding.
- Tests heavily pin pathname checks and static names, but do not perform a
  check/use race, descriptor identity validation, deserialization revalidation,
  actual task/Crosslink mutation in plan mode, provider cost/egress, dynamic
  effect metadata, config opt-in success, usage overflow, or end-to-end parity.

#### `src/session/task.rs`

Status: Read in full, including unit tests; production ownership/consumers searched
Disposition: Preserve tasks/dependencies; migrate through W20 as one versioned transactional graph

Findings:

- Stable display IDs, typed statuses, reciprocal edges, iterative cycle checks,
  blocker enforcement, and user-facing summaries are valuable task semantics.
- The graph update is not transactional. `apply_status_transition` demotes the
  existing in-progress task before later dependency validation. If a new edge is
  invalid/cyclic, the call returns error but the prior active task remains
  silently demoted (F-065).
- Blocker enforcement examines only preexisting `blocked_by`. A single update
  can request `status=in_progress` while adding pending blockers; the status
  check passes on the old empty list and the later field application creates an
  in-progress task that is blocked.
- Deletion immediately removes the task but never removes its ID from other
  tasks' `blocks`/`blocked_by`. The advertised symmetric invariant is broken and
  dependents can become permanently unable to start due to a nonexistent
  blocker. There are no tombstones/history/recovery.
- Edge updates are add-only; callers cannot remove/correct dependencies.
  `active_form` cannot be cleared because `Option<String>` conflates omitted and
  null. There are no expected versions, updated/completed timestamps, owners,
  actors, provenance, comments/results, priorities, retry/conflict states, or
  parallel/multi-agent status semantics.
- `TaskManager` derives `Clone` and unrestricted `Deserialize`. Duplicate IDs,
  stale/colliding `next_id`, cycles, asymmetric/missing edges, multiple active
  tasks, timestamps, and field/count limits are not validated on load. ID
  increment can overflow.
- Subjects/descriptions/forms/edges/task count/graph traversal and formatted
  output are unbounded. Storage is a vector with repeated scans/copies; cycle
  checks can allocate/traverse the full adversarial graph per edge.
- Task state is operational only in TUI/pipeline through a separately created
  process-memory mutex. Legacy REPL, ACP, intercepted tools, and subagents pass
  no manager; `SessionManager` owns another independent manager. No persistence
  or sharing connects these instances (F-057).
- The outer TUI execution path locks this manager across every tool dispatch,
  even non-task tools, serializing unrelated work and expanding poison impact.
  Poison recovery accepts potentially invalid partially mutated graph state.
- Tests cover many sequential happy/error graph cases, including combined-edge
  cycles and blockers, but omit the partial-mutation bugs above, deletion edge
  cleanup, edge removal, load validation, stale concurrent versions, persistence,
  multiple actors/frontends, large graphs/budgets, poison, and canonical task-
  state integration.

#### `src/session/pricing.rs`

Status: Read in full, including the complete static catalog and unit tests; all production consumers searched
Disposition: Preserve cost visibility; replace approximate static arithmetic with provider-attributed, versioned accounting

Findings:

- The module usefully distinguishes input, output, cache-read, cache-write TTL,
  long-context, and selected fast-mode rates, returns an error for unknown model
  IDs instead of displaying `$0.00`, and has extensive regression tests for its
  current catalog and arithmetic.
- `f64_from_tokens` converts through `u32::try_from` and substitutes
  `u32::MAX` on overflow. Every usage component above 4,294,967,295 tokens is
  therefore silently *reduced* to that ceiling before costing, despite the
  comment claiming it produces a very large cost. This can materially
  understate a persisted, accumulated, corrupt, or hostile count (F-066).
- All monetary rates and totals are `f64`, without a currency, precision/
  rounding contract, price source, effective interval, provider/account/region,
  batch/flex/service tier, or billed-usage receipt. A large ordered prefix table
  accepts arbitrary suffixes and conflates model recognition with pricing;
  source changes require a code release and tests mostly pin the same embedded
  assertions rather than independent provider evidence (F-020).
- `ModelPricing::other` fabricates uniform cache-read/write multipliers for
  non-Anthropic providers even when a provider may not report or charge those
  categories. `UsageExtras` deliberately discards legacy web-search counts and
  represents no non-token charges, so provider-billed search, audio/image,
  hosted tools, storage, or other usage cannot be reconciled when applicable.
- Long-context selection sums ordinary input plus cache-read and cache-write
  tokens, but the module does not carry the provider's precise usage semantics
  or pricing tier returned with the response. Fast mode unconditionally skips
  long-context rates, and unsupported fast-mode models silently fall back to
  standard rates. These are policy assumptions, not provider-attributed facts.
- The “session flag” for an unknown model is a thread-local Boolean. It is never
  consumed by production code, never cleared by a production caller, can bleed
  between sessions that reuse a thread, and can be missed when an async task
  resumes on another thread. The public re-export and comments overstate an
  operational UI signal.
- The only production cost displays are in the legacy chat REPL. Two paths
  estimate prompt/output tokens from character counts or take maxima against
  partial provider usage, so their displayed value is neither a billed turn
  cost nor a clearly labeled full-session estimate. TUI, ACP, proxy, and other
  execution paths have no corresponding canonical accounting.
- Each successful calculation emits model, token counts, and cost at info; a
  miss is logged by lookup and again by calculation. There is no run/call/
  provider receipt, privacy policy, aggregation, or single surfaced typed
  uncertainty reason.
- Tests cover table ordering, expected sample arithmetic, cache multipliers,
  long context, fast mode, unknown models, and the thread-local flag. They omit
  overflow above `u32::MAX`, fixed-point rounding/reconciliation, provider-
  reported tier/price provenance, concurrent sessions/tasks, catalog effective
  dates, non-token billables, frontend parity, and billed-invoice comparison.

#### `src/session/mod.rs`

Status: Read in full, including all unit/concurrency tests; every production consumer searched
Disposition: Preserve durable sessions, metrics, and handoffs; merge them into the canonical transactional run/session model

Findings:

- Validated filename components, unique same-directory staging files, file and
  parent-directory sync, surfaced end errors, bounded turn-detail retention,
  cumulative totals, typed modes, and zero-copy read views are useful building
  blocks. The tests exercise these isolated contracts thoroughly.
- `end_session` takes the only in-memory `Session` before persistence. If any of
  the three writes fails, `EndSessionError` carries only the source—not the
  session—so its documentation's suggestion to retry externally is impossible.
  It also tears down process/security state before surfacing the failure. The
  session and unsaved progress are irrecoverably lost to the manager (F-067).
- Persistence is three independent replacements: `<id>.json`, `latest.json`,
  then `handoff.md`. A failure or crash can publish mutually inconsistent
  generations. Concurrent writers avoid staging-name collision but still race
  last-writer-wins; an older writer can become `latest`, and no expected version,
  lock, manifest/commit point, journal, or recovery reconciliation exists.
- Direct filesystem operations inherit parent/final symlink, hardlink, ambient-
  permission, and configured-path authority problems from F-014/W15. The
  constructor logs directory-creation failure and returns an apparently usable
  manager. Reads and JSON/Markdown writes have no file/session/count/field
  aggregate bounds, confidentiality policy, schema version, or migration
  transaction.
- Deserialization validates only the embedded ID character set. It accepts
  impossible/regressing timestamps, invalid parent IDs, oversized progress and
  VDD strings/vectors, more than `MAX_TURN_METRICS`, duplicate/out-of-order turn
  numbers, counter/usage inconsistencies, and unchecked-overflow values. Loaded
  state never runs an invariant/migration validator.
- Cleanup trusts a loaded record's embedded ID rather than its containing file
  identity. A second old JSON file whose body names a valid victim ID can cause
  cleanup to delete the victim's real file. It loads and sorts all JSON without
  a scan/byte/count budget, silently ignores directory errors, and has no
  retention tombstone, trash/recovery, or coordination with active sessions.
- The advertised initializer/coding “shift-worker” architecture is mostly
  labels. A continuation creates a blank child containing only the parent ID;
  production code never reads `handoff.md` (only `doctor` does), and does not
  inherit or resolve progress. Generated Markdown is untrusted, unbounded text
  with no typed evidence references.
- ACP's load path reads a stored session and then creates a fresh blank coding
  session from its ID; the ACP transcript/session map are separate process
  memory. ACP has no production `end_session` call. Proxy owns another manager,
  while the legacy REPL and `state::Session` use separate session domains. The
  nested `TaskManager`, progress vectors, and VDD slot add further duplicate
  state (F-006/F-057/W12).
- `record_actual_usage` assigns completion usage to whichever turn happens to
  be last. Concurrent/out-of-order proxy requests have no call ID, so per-turn
  metrics can be misattributed even though cumulative totals rise. Request and
  turn counters use unchecked increment; ring eviction is repeated O(n)
  `Vec::remove(0)`; coarse `add_tokens` classifies all unknown usage as input.
- A failed provider/runtime turn is appended to the model transcript as an
  `assistant` message containing the raw reason. This changes future model
  context and falsely attributes local/untrusted failure text to the assistant,
  instead of retaining a typed local failure event with sensitivity/provenance.
- RAII drop performs synchronous multi-file serialization/fsync and teardown;
  its failure is only logged. The guard has no production consumer. Neither the
  active manager nor VDD/task state is automatically checkpointed during normal
  operation, so a long session/process crash loses everything since its last
  separately implemented frontend save.
- Tests omit transactional multi-file/crash recovery, concurrent/stale writers,
  symlink/hardlink and restrictive-mode checks, malformed loaded invariants,
  duplicate embedded IDs during cleanup, active-session retention, call-ID
  usage correlation, process-crash checkpoints, actual cross-frontend resume,
  handoff consumption/evidence, and provider-failure provenance isolation.

#### `src/state/mod.rs`

Status: Read in full, including unit tests; production composition searched
Disposition: Keep categorized state, but make it the validated canonical run record promised by W12

Findings:

- Grouping identity, conversation, UI, modes, permissions, budgets, IDE, and
  transcript concerns is clearer than a large frontend struct, and a single
  construction point is useful.
- The module-level claim that all migration phases are complete and both
  interactive frontends use one canonical state overstates the result. TUI and
  legacy REPL share this handle, but ACP holds a raw `StateStore` alongside the
  separate `session::SessionManager`; proxy, subagents, tasks, and other run
  state remain separate (F-004/F-057/F-067).
- `SessionState` derives unrestricted `Deserialize` and `Debug`. It accepts
  invalid security/path/plan/message state without a constructor or invariant
  check, and debug formatting can expose the entire conversation, IDE selection,
  diagnostics, plans, and private paths.
- The description calls whole-state clones cheap, although arbitrary JSON
  messages, undo history, plans, IDE diagnostics and path lists are unbounded.
  Snapshot/serialization cost grows with the complete context.
- `Default` creates a real new UUID rooted at relative `.`. Production code that
  accidentally uses it acquires ambient working-directory identity rather than
  an explicit validated workspace/run capability.

#### `src/state/categories.rs`

Status: Read in full, including unit tests; field consumers searched
Disposition: Preserve useful newtypes/enums; separate durable data from live authority and validate every decoded category

Findings:

- `SessionId::from_raw` validates UUIDs, but the newtype's derived transparent
  `Deserialize` bypasses it. The public unchecked constructor accepts arbitrary
  strings, and migration code uses it. The stated “every untrusted input”
  invariant is therefore not type-enforced.
- Identity stores unrestricted deserialized path authority, including project,
  current/original cwd, transcript root and extra CLAUDE.md directories. Paths
  are neither canonical capabilities nor bounded and can be inconsistent with
  each other or the session file's trusted origin.
- Conversation is unbounded provider-shaped `serde_json::Value`, losing typed
  roles/items/provenance and provider-native continuity. Undo assumes pairs;
  approved plans are raw future system context; behavior mode duplicates the
  coarser agent mode without a consistency invariant.
- `PermissionsState::bypass_mode` explicitly says it does not persist, yet the
  field is serializable and is written in every session snapshot. On resume it
  is honored by the legacy executor and can overwrite the current launch's
  permission setting (F-068). Mirrored trust can be stale/forged and even
  `persistence_disabled` is itself persisted.
- `BudgetsState` is not a run budget: it contains effort, an optional thinking
  override and a rough UI token estimate, but no actual/reserved token, turn,
  cost, time, tool, retry, subagent or concurrency limits.
- Agent-mode unknown tokens silently become write-enabled `Build`; effort's
  infallible `FromStr` silently becomes `Medium`. Unknown providers default to
  the Anthropic/Gemini effort menu, and hard-coded provider/model cases already
  require the same provenance/version repair as F-020.
- IDE paths, selection text, recent files, diagnostic keys/messages/source and
  aggregate counts are unbounded untrusted client/server data. They can enter
  prompts later without sensitivity or indirect-injection provenance.
- Transcript watermark/cwd are deserializable unchecked path/index state. A
  hostile watermark can suppress append reconciliation, while a hostile cwd can
  redirect ambient transcript operations unless the storage layer independently
  re-establishes capability ownership.

#### `src/state/session.rs`

Status: Read in full, including unit tests; all mutation/persistence consumers searched
Disposition: Keep a shared session façade; rebuild mutations as typed versioned transactions and projections

Findings:

- One façade for TUI/REPL state, detached snapshots, ID/file-name validation,
  state inspection closures, and explicit events are useful consolidation work.
- `Session`'s derived `Clone` aliases the same mutable `StateStore`, while
  `detached_clone` copies. That nonstandard distinction is easy to misuse in
  persistence, rewind, async work, and tests; no generation says what a snapshot
  represents.
- `push_message`, `update_messages`, mode/effort/permission mutations and state
  replacement do not update the outer `updated_at`; only selected `&mut self`
  helpers do. Session picker order/metadata can remain stale despite extensive
  conversation changes.
- `replace_messages` emits events only for positions beyond the old length.
  Same-length rewrites, truncations other than fully empty, and edits to existing
  messages are invisible. `update_messages` emits none. Event-driven transcript
  and analytics consumers therefore cannot reconstruct canonical state.
- Undo pops exactly two arbitrary JSON entries without validating roles or
  preserving a complete user/assistant/tool transaction. It emits no removal or
  rewind event; redo emits append events and can duplicate already persisted
  transcript entries. Tool-call/result and multipart provider invariants can be
  broken.
- Token estimation ignores non-string content, tools, system/provider overhead,
  images and structured blocks, adds a constant per message, and sums unchecked
  `usize`. It is UI estimation presented inside a structure named budgets.
- Permission bypass is read directly by tool execution and can be changed by a
  loaded session (F-068). Working directories are added without canonicalizing,
  validating, bounding, checking existence/ownership, or creating scoped
  filesystem capabilities; the field remains tied to deprecated CLAUDE.md
  injection and belongs in the rule-removal/migration inventory.
- Public deserialization uses ambient process cwd to upgrade legacy state.
  Results vary with where the process happens to run, and generic deserialization
  has no trusted session-file identity to validate against.
- Tests assert a single runtime location and top-level shape, but omit aliased-
  clone misuse, timestamp freshness, typed provider/tool histories, undo across
  tool chains, replacement/truncation events, transcript reconciliation, loaded
  bypass denial, path capabilities, state-size ceilings and concurrent versions.

#### `src/state/store.rs`

Status: Read in full, including unit tests; analytics/transcript subscriber construction searched
Disposition: Preserve shared snapshot access; replace poison recovery/best-effort events with versioned transactional commits

Findings:

- Closure-scoped locks prevent a guard escaping across `await`, and emitting
  events after releasing the lock avoids subscriber reentrancy. A bounded lag-
  aware channel plus snapshot reconciliation can be useful for optional views.
- The documented panic guarantee is false. A mutation closure can partially
  change state and panic; Rust poisons the lock, but later reads/writes recover
  and keep those mutations. No events were sent, no invariant validation runs,
  and the included poison test explicitly requires the partial change to remain
  (F-069).
- There is no monotonic state version, transaction/call ID, expected-version
  check, write-ahead record or rollback. Shared `Clone` handles can overwrite
  each other, and a complete replacement emits only when the session ID changes,
  hiding same-session rewrites from subscribers.
- The 64-event broadcast is explicitly best effort. Lost events are acceptable
  only if every consumer reconciles a versioned snapshot; current transcript
  behavior depends mainly on `MessageAppended`, while many mutation APIs emit no
  event. Delivery failures are ignored.
- `Debug` clones and formats the complete state, creating a convenient accidental
  disclosure path and potentially expensive blocking work. Standard lock poison
  is silently treated as trustworthy rather than a typed degraded/recovery state.
- Tests validate mechanics and deliberately pin poison recovery, but omit panic
  rollback, invariant checks, concurrent stale writers, versions, lost-event
  end-to-end reconciliation, subscriber shutdown/ownership and sensitive debug.

#### `src/state/persist.rs`

Status: Read in full, including unit tests; all decoder/migration consumers searched
Disposition: Preserve explicit schema migration; enforce exact versions, bounded validation and authority stripping

Findings:

- A single document envelope, explicit version, transitional identity-consistency
  check and rejection of versions newer than the binary are good foundations.
- The decoder accepts version `0` (and any version below current) directly as
  the V1 Rust shape. `into_state` checks only `>` and `decode` likewise parses
  old values straight into `SessionStateV1`; neither routes them through the
  promised migration framework. Version therefore does not define an exact
  schema/migration contract (F-070).
- Derived `Deserialize` on flattened state accepts unknown fields and unchecked
  `SessionId`, paths, bypass authority, plans, message graphs, indexes and
  unbounded aggregates. Same-version forward fields can be silently discarded
  and later overwritten.
- Legacy upgrade intentionally wraps its arbitrary ID unchecked and roots all
  missing identity fields at ambient caller cwd. File-based callers later check
  name equality, but generic public `Session` deserialization does not carry a
  trusted containing path and can produce authority-bearing inconsistent state.
- Ephemeral authority (`bypass_mode`, mirrored trust, persistence controls),
  client-derived paths and volatile transcript indexes are persisted alongside
  durable conversation data with no reauthorization/sanitization on resume
  (F-068).
- Decode materializes unrestricted JSON and canonical decode clones the complete
  document/state. There are no byte/depth/item limits, checksums, encryption,
  retention metadata, expected generation, crash recovery, or post-migration
  invariant validation.
- Tests prove shape round trips and future-version rejection but explicitly use
  non-UUID IDs. They omit old-version routing, unknown-field preservation/
  rejection, authority stripping, corrupt invariants, size/depth limits,
  deterministic trusted-root migration and migration/write crash recovery.

#### `src/migrations/registry.rs`

Status: Read in full; registered implementations and only startup caller inspected
Disposition: Keep a small ordered registry, but declare store dependencies, exact versions and release compatibility

Findings:

- A short explicit order is understandable, but two boxed entries provide no
  dependency/store scope, source/target schema, reversibility, minimum binary,
  transactional group, or required-versus-optional classification.
- There is no startup assertion for duplicate IDs, ordering constraints,
  migration graph continuity, or a requirement that every persisted schema bump
  has a registered path. Append-only comments are the only guard.
- One entry is an unused global transcript marker rather than a transformation;
  the other partially rewrites interactive session files. Both run for every
  startup regardless of which product surface will open the corresponding data.

#### `src/migrations/mod.rs`

Status: Read in full; main startup and all framework consumers inspected
Disposition: Preserve migrations; replace unconditional best-effort startup with store-scoped transactional gating

Findings:

- Ordered reports, explicit idempotent/once-only policy, surfaced missing-versus-
  corrupt reads, and outcome collection are useful framework intentions.
- The top-level “must never crash startup” policy is unsafe for required stores.
  Failures merely warn, later dependent migrations still run, and `main` discards
  every report before opening the stores (F-010). A migration can also panic;
  the trait comment says it must not, but the runner has no containment.
- `MigrationContext` contains ordinary paths, not enforced read/write
  capabilities. Environment discovery falls back to `.`, so a missing platform
  data directory can redirect migrations into the process's ambient workspace.
- Corrupt ledger load deliberately degrades to empty, allowing once-only work to
  replay. Applied entries are marked only in memory and the ledger is saved once
  after all migrations; crash/save failure also replays already committed side
  effects. “Once only” is therefore neither transactional nor durable.
- Multiple processes can run and rewrite the same stores/ledger concurrently.
  There is no store lock, lease/fencing token, pre-migration snapshot, commit
  journal, recovery/rollback, disk-space reservation, or compatibility lockout.
- Outcomes flatten error structure into strings and have no affected artifact,
  old/new generation, partial-change manifest, recovery action, or operator-
  visible health state. The unused applied-count helper discards even more.
- JSON helper reads unlimited files/depth. Tests live in a duplicated fake runner
  rather than exercising panic, real report handling, dependent failures,
  concurrent processes, ledger-save crashes or startup surface disablement.

#### `src/migrations/ledger.rs`

Status: Read in full, including framework tests; all consumers inspected
Disposition: Keep durable migration history only as part of the transactional store migration protocol

Findings:

- Sorted IDs, missing/corrupt distinction, same-filesystem replacement, pre-
  publish `0600`, and file sync are sound individual-file improvements.
- Save clones then replaces a whole set with no expected generation or lock.
  Concurrent processes/writers can each load different histories and the last
  rename silently loses every other newly marked migration. Existing concurrency
  tests check only parseability and explicitly do not check union preservation.
- Temp names are predictable PID/process counters and created with truncating
  `fs::write`, not `create_new`/no-follow. Parent paths are created/followed
  ambiently; final/parent symlink and local pre-created-temp attacks are not
  excluded. The parent directory is not synced after rename.
- An applied side effect and its mark are separate durability operations. Crash
  between them replays once-only work; marking before a truly durable external
  effect would cause the opposite loss. The structure has no versions, checksums,
  timestamps, binary/build IDs, target digests or recovery evidence.
- Loads and ID strings are unbounded; unknown fields are ignored. Comments about
  users committing this host-data ledger to Git conflict with the location and
  privacy goal and should not drive format choices.

#### `src/migrations/session_state_v1.rs`

Status: Read in full, including unit tests; decoder, file I/O and startup caller inspected
Disposition: Preserve legacy-session import, but make it bounded, transactional and deterministic

Findings:

- It rejects final-component symlinks/non-files, checks embedded ID against the
  filename, sorts paths, preserves malformed original bytes, and uses individual
  atomic replacement. Those are useful migration safeguards.
- Each file commits independently; a later failure returns one aggregate
  `Failed` after earlier sessions have already changed. Startup ignores it and
  opens the partially migrated directory (F-010). There is no directory/store
  generation, manifest, backup, rollback, quarantine or resume checkpoint.
- Legacy identity is rooted at `std::env::current_dir()` rather than a trusted
  migration/session context. The same saved file migrated from a different
  launch directory gains different cwd/project/transcript authority.
- Directory/parent symlinks are followed, and inspect/read/rewrite is a TOCTOU
  path sequence rather than descriptor-relative no-follow I/O. Files/count/
  bytes/JSON depth/messages/paths and aggregate error strings are unbounded.
- The rewrite carries persisted permission bypass and all unchecked state from
  F-068/F-070 into the “canonical” output. It wraps/reformats data but does not
  perform a full semantic invariant or authorization migration.
- One directory-entry error aborts discovery, while per-file failures do not.
  Concurrent application saves/multiple migrators can race and last-writer-win.
- Tests cover good, malformed, future, mismatched-name and final symlink cases,
  but omit crash boundaries, partial-directory recovery, concurrent writers,
  directory symlinks, hostile size/depth, trusted cwd mapping, permission
  stripping, restrictive modes and end-to-end startup refusal.

#### `src/migrations/stamp_transcript_schema_v1.rs`

Status: Read in full, including framework tests; source-wide consumer search complete
Disposition: Remove this global stamp after replacing it with truthful OpenClaudia-owned per-artifact/version metadata

Findings:

- The migration writes `~/.claude/projects/.schema-version.json`, a shared
  Claude directory, asserting every transcript there is schema V1 without
  reading any transcript or identifying which files OpenClaudia owns (F-071).
- No production code reads this marker. It cannot guide a future migration as
  claimed, and stamping today cannot prove the prior format of files later added
  or modified by another program.
- A malformed/older marker is overwritten with only `{transcripts: 1}`, silently
  discarding unknown fields that may belong to another/current producer. The
  write is non-atomic, unsynced, ambient-permission and symlink-following; a
  crash can truncate the shared marker.
- Serialization's theoretically impossible error is reported as `Skipped`,
  falsely signaling current state. An unreadable marker is a migration failure,
  but startup ignores that result (F-010).
- Tests only prove creation/idempotent text and a permission error. They do not
  establish transcript ownership/schema, marker consumption, preservation of
  other fields, symlink safety, crash durability, concurrency or compatibility
  with the other program sharing the directory.

#### `src/migrations/tests.rs`

Status: Read in full
Disposition: Consolidate around real transactional migration acceptance tests; remove duplicated/tautological fixtures only after coverage replacement

Findings:

- Missing-versus-corrupt ledger, restrictive file mode and parseable concurrent
  replacement are useful checks, but the concurrency test permits lost marks
  and therefore does not establish ledger correctness.
- `run_fake` duplicates production runner logic and differs on corrupt-ledger
  behavior, making it capable of passing while `run_all` regresses. “Across
  processes” is simulated by two loads in one process with no process race.
- The local environment mutex cannot serialize tests in the separate transcript
  module and is unnecessary for the explicit test context used by this stamp;
  its explanatory comment no longer matches the implementation.
- Tests pin creation of the unconsumed, ownership-unsafe global marker rather
  than proving a migration consumer. Several checks are smoke/constructibility
  tests, while crash injection, panic containment, store gates, exact-version
  graph, rollback/recovery and multi-process preservation are absent.

#### `src/transcript.rs`

Status: Read in full, including unit tests; all production consumers searched
Disposition: Preserve transcripts/resume; make them an owned typed event log with explicit foreign import/export

Findings:

- Per-line envelopes, UUIDs/timestamps, append mode, restricted creation modes,
  collision-resistant project keys, bounded subscriber notifications and retry-
  aware watermarks are valuable intentions.
- The module claims Claude Code-compatible path layout, but `sanitize_path`
  appends an OpenClaudia-specific digest absent from the documented layout. It
  writes into `$CLAUDE_CONFIG_HOME_DIR/projects` while neither proving current
  external schema/path compatibility nor preserving arbitrary outer fields.
  `SerializedMessage`'s free-form kind does not make unknown metadata round-trip.
- This co-ownership caused the unconsumed global stamp in F-071. OpenClaudia
  should own its durable log and treat foreign transcripts as version-detected,
  read-only import/export sources rather than modifying their directory.
- `transcript_path`, `append_entry`, and `find_transcript_by_id` accept an
  unvalidated session string in a filename. Separators/dot segments can escape
  the project directory; `find` also follows project-directory/candidate
  symlinks, returns the first nondeterministic cross-project match, and uses
  `exists` rather than binding identity to a trusted file handle (F-072).
- Project identity hashes `Path::to_string_lossy()` without canonical workspace
  identity, so non-UTF-8-distinct paths can collide and symlink/relative/casing
  aliases split one project. The config-home fallback is ambient `./.claude`.
- Existing parent directories/files are not checked or tightened; recursive
  creation and append follow parent/final symlinks. `O_APPEND` applies per
  underlying write, not an arbitrary `writeln!` JSON line as one transaction;
  large/concurrent writers can interleave. There is no append lock, sequence,
  checksum/hash chain, flush/fsync policy, quota/rotation or crash-tail repair.
- Transcript content includes raw conversation/tool data without sensitivity,
  redaction, encryption, consent, retention/export/delete, or size/depth limits.
  The filename/path and envelope expose workspace, session, branch, version and
  timing metadata.
- The subscriber clones the entire conversation on every flush and has no state
  generation. It appends first and updates an independently persisted watermark
  later, so a crash creates duplicates; concurrent replace/undo can make its
  snapshot/watermark stale. Same-length edits/truncation often emit no event
  (F-069/state findings), and retry creates new UUID/timestamp metadata.
- Missing/unknown roles are written as `system`. The compact boundary is a
  duplicated magic string detected inside ordinary system-message content;
  forged/imported text can cause resume to discard all earlier history. It is
  not a typed, signed or causal compaction/checkpoint event (F-072).
- Load follows symlinks, reads unlimited lines/bytes, returns empty for every
  open failure, and skips every malformed line—including middle corruption—then
  resumes a discontinuous history. It never validates UUID/time/version,
  envelope/message role agreement, cwd/session/file identity, sequence or
  provider item/tool-call continuity.
- Listing loads and parses every full transcript merely to count messages/find
  a first prompt, with no file/count/byte/text budget or index. It silently skips
  directory/metadata errors. First prompts are retained unbounded in picker
  state.
- Git metadata runs a synchronous, no-timeout subprocess on first/cache-invalid
  lookup. The process-global cwd cache is unbounded and poison disables caching;
  project `.git` indirection is read without workspace capability checks. Caching
  reduces frequency but does not create a bounded subprocess lifecycle.
- Tests cover basic path hashing, append/load, listing, text marker slicing and
  source-text use of an absolute Git binary. They omit traversal/symlinks,
  interleaved writers, crash duplicate recovery, corruption continuity,
  schema/foreign compatibility, unknown-field retention, privacy/retention,
  hostile sizes, state replacement/undo, typed compaction and Git timeout.

#### `src/memory.rs`

Status: Read in full, including all 1,533 lines of unit tests; every production consumer searched
Disposition: Preserve durable searchable memory; rebuild trust, provenance, lifecycle and retrieval around W5

Findings:

- Parameterized SQL, an allowlisted prune enum, normalized exact tags, foreign
  keys, transactional memory+tag writes/reset, FTS query quoting, explicit
  poison errors, typed returned records and project isolation are substantial
  useful implementation work.
- Normal startup opens `.openclaudia/memory.db` beneath the project and
  automatically inserts learned preferences/recent work into the system prompt.
  A repository-controlled/pre-existing database is therefore an instruction-
  authority and persistent prompt-injection channel (F-073). Open/folder
  creation follows symlinks and uses ambient permissions; private conversations,
  preferences, paths, errors and activity can be read/changed/committed with the
  project.
- Escaping `<`, `>` and `&` prevents only delimiter break-out, not semantic
  prompt injection. Stored text such as “ignore prior instructions” retains its
  meaning under a system heading that says “Follow them.” Moreover,
  `format_learned_preferences` performs no escaping at all; file-path attribute
  escaping omits quotes; arbitrary core section names are used as XML tag names.
  XML-like text is not an authority boundary (F-073).
- The model-facing tool module advertises memory save/search/update/core-update,
  and compaction explicitly tells the model to call `memory_search`, but no
  memory handler is registered or dispatched. Manual legacy prompt injection
  and slash commands are operational; archival recall by the agent is not
  (F-006).
- Memory records lack source observation/call/run IDs, actor, workspace/resource
  generation, evidence references, sensitivity, confidence derivation,
  contradiction/supersession, expiry/retention, ownership/sharing, review status
  and tombstones. Repeated identical strings blindly increment unbounded signed
  confidence/occurrence counters, so popularity is mistaken for truth.
- Project/user/team/core/archival/recent/auto-learn/compaction memory have no
  canonical precedence or conflict semantics. `core_memory` can contain
  arbitrary additional sections that are always formatted; learned preferences
  cannot be approved, corrected, expired or individually deleted through this
  API.
- Search forces the entire user query into one exact FTS phrase, which has poor
  recall for reordered/related terms. Parse/query failures silently become an
  empty hit list, indistinguishable from no relevant memory. There is no hybrid/
  semantic retrieval, metadata/time/source filters, reranking, diversity,
  relevance threshold, citation, retrieval trace, context budget or task-quality
  evaluation.
- Every input content/tag/query/path/source/summary/list and most output methods
  are unbounded. Public `usize` limits saturate to `i64::MAX`; some queries return
  all rows; N+1 tag hydration and full pattern scans run under one synchronous
  connection mutex. Production async paths call the synchronous API directly;
  a test merely demonstrates that callers *can* remember `spawn_blocking`.
- Database open has no restrictive creation mode, no-follow capability,
  busy-timeout/WAL/concurrent-process policy, encryption, integrity check,
  backup/recovery, quota, cancellation/deadline or corruption quarantine.
  Multiple process instances can contend while the in-process mutex gives a
  misleading concurrency boundary.
- Internal migration accepts a database whose `MAX(schema_version)` is greater
  than supported and opens it as current. V1–V3 and final version marking are
  not one transaction; `CREATE IF NOT EXISTS` can bless malformed partial
  schemas. V4 is savepointed, but its commit and version record are separate
  (F-074).
- V4 necessarily splits legacy comma text and cannot recover original comma-
  bearing tag intent despite comments about preservation. It reads all legacy
  tag rows into memory, rebuilds the entire FTS table, and has no disk/time/row
  budget, backup, cross-process lock or crash/fault-injection tests.
- Update/delete/clear/prune/cleanup have no expected versions, actor/audit,
  review/dry-run, tombstone/recovery or transaction across related operations.
  Short-term cleanup deletes sessions then activities in separate statements;
  background exact-text dedup compounds this with F-063.
- `recent_sessions` stores JSON lists in TEXT with a heuristic legacy decoder;
  `INSERT OR REPLACE` destroys/recreates existing identity. Activity type and
  entity IDs are untyped strings without foreign keys; started/ended/timestamp
  strings are not validated, and ordering at equal second precision is unstable.
- Glob matching is a four-case string approximation, not glob semantics; it
  loads every pattern before filtering. Co-edit pairs treat raw path spellings
  as identity, generate potentially quadratic inputs upstream, and lack
  workspace/version/time decay.
- Default seeded persona/project/preference text presents placeholder assertions
  as core memory. The formatter for core memory is unused in production, while
  recent/preferences are automatically injected, reflecting an incoherent
  product contract rather than intentional retrieval tiers.
- The test block is nearly as large as production and repeats many operator/
  CRUD/derive-level cases with forensic prose. One test title still says schema
  V3 while asserting only core rows under current V4. Tests accept 10 KiB hostile
  queries instead of enforcing a budget and extensively pin XML prompting.
  Missing are project-DB injection, semantic-instruction isolation, permission/
  provenance/consent, future/malformed schemas, file modes/symlinks, corruption/
  recovery, multi-process contention, cancellation, bounded large data,
  retrieval quality and end-to-end registered memory tools.

#### `src/team_memory.rs`

Status: Read in full, including unit tests; source-wide production consumer search complete
Disposition: Preserve shared-memory intent; redesign around stable logical identity, authenticated sharing and reconciled operations

Findings:

- Explicit user/team/both scope, source-tagged returned rows, user-local
  tombstones and optional team configuration are useful product concepts.
- No production code constructs `TeamMemoryStore`; startup always creates the
  ordinary project `MemoryDb`. The configured team feature and its tests are
  isolated implementation, not an operational shared agent memory (F-006).
- Archival row IDs are independent SQLite counters in user and team stores, but
  `Both` returns only the user ID and later delete uses that same number for the
  user deletion and team tombstone. Once counters diverge, it hides an unrelated
  team row and leaves the copied target visible (F-075).
- The documented archival “user overrides team by id” is not implemented.
  Merged list simply concatenates all user rows and all non-tombstoned team rows;
  equal IDs or content are both returned. A `Both` write commonly appears twice.
  `limit` applies independently, so up to `2 * limit` rows return in user-then-
  team order rather than one globally ranked/dated result.
- Every new user database seeds the three core sections. Consequently a merged
  core read always finds user placeholders and never reaches real team values
  for persona/project info/preferences. “Last-write-wins” is actually unconditional
  user-presence precedence and does not compare versions/timestamps (F-075).
- User-then-team writes are not atomic/recoverable. A second-store failure leaves
  partial duplicated archival/core data but returns an error without an operation
  ID or reconciliation path. Reads can combine unrelated generations while other
  processes write either database.
- Tombstones contain only a numeric ID or section. They are not bound to team
  store identity, workspace, logical record/version or content digest; changing,
  restoring or replacing the configured team database can hide unrelated data.
  There is no unhide/supersede API, provenance, expiry, reason or actor.
- The tombstone sidecar has no schema version, restrictive/no-follow storage,
  transaction with user memory, backup/integrity check, busy policy, bounds or
  migration. Every list loads the complete tombstone set into memory.
- An arbitrary configured path is created and opened as a shared writable SQLite
  file with no authenticated team identity, ACL/role/capability negotiation,
  encryption, server protocol, locking ownership, offline conflict strategy,
  audit or permission classification. Direct file sharing is not a robust
  multi-user memory service.
- `Both` availability semantics differ by operation: writes error without a team,
  but reads silently degrade to user-only. Deleting `Both` reports only whether
  the user row was removed even when it changed the team view via tombstone.
- The façade exposes list/save/delete and core get/update but no scoped archival
  search, get/update, citations, conflict/history or retrieval merge. It inherits
  all trust, prompt, schema, sync-I/O and quota issues in `MemoryDb` (F-073/F-074).
- Tests verify isolated scope mechanics but pin the flawed numeric-ID/tombstone
  model. They omit divergent IDs, merged `Both` duplicates/global limits, team-
  only core hidden by defaults, second-write failure/reconciliation, concurrent
  users/processes, store replacement, access control, unhide, privacy and actual
  startup/tool/prompt integration.

#### `src/auto_learn.rs`

Status: Read in full, including unit tests; source-wide production consumer search complete
Disposition: Preserve automatic observation/learning intent; replace heuristic truth promotion with typed, reviewable evidence capture

Findings:

- The implementation is operational only in the legacy readline chat path:
  that frontend constructs the learner, supplies user messages and tool results,
  and finalizes it. TUI and ACP do not construct or feed it. The feature is
  therefore neither canonical nor frontend-equivalent despite module-level
  claims that OpenClaudia automatically captures these signals (F-076).
- Every qualifying user imperative/correction is immediately persisted as a
  learned preference. There is no confirmation, actor/message/run identity,
  workspace scope, source quotation, contradiction handling, confidence basis,
  expiry or review state. `previous_assistant` is collected at the caller but
  deliberately ignored, so the code cannot establish what a supposed
  correction corrected. These records are later promoted to system context by
  `memory.rs`, turning a brittle language heuristic into durable authority
  (F-073/F-076).
- Preference capture occurs after `@file` expansion but before
  `UserPromptSubmit` hooks. A message that is subsequently blocked can still be
  learned, and classification may inspect expanded repository content rather
  than the user's original utterance. Sentence/prefix denylists reduce known
  false positives but cannot establish intent or safe persistence.
- Failure/success attribution is causally unsound. Only one pending shell error
  exists; a later unrelated successful `bash` command consumes it and is stored
  as the resolution. A later failure overwrites the prior unresolved error.
  File errors retain raw relative paths while edit successes normalize to
  canonical absolute paths, so the purported same-file edit match commonly
  cannot succeed. There are no call IDs, command equivalence, process result
  types, test evidence or explicit resolution confirmation.
- Edit failures containing generic `not found`/`no match` are converted into the
  universal instruction that the file changes frequently and should be reread.
  The signal does not prove either assertion and conflates stale-content,
  missing-file, malformed arguments, permissions and tool implementation
  failures.
- Clippy learning is effectively inert for ordinary Rust output. The result is
  processed one line at a time, but `parse_clippy_warning` requires the warning
  description and file reference on that same line; normal Clippy diagnostics
  put the `--> path:line:column` on a following line. It also discards common
  lint classes without a demonstrated retrieval/use contract.
- File co-edit capture has useful bounded batching (50 production-observed files
  and one SQL transaction), but co-occurrence alone is stored as a relationship
  without run/task/generation, timestamps, reason, negative evidence or decay.
  The performance test bypasses the production 50-file cap by directly filling
  the private set with 200 entries, so it does not validate the advertised
  production bound/path.
- Database work is synchronous on the interactive async request path. Errors
  increment a counter, but production never reads `error_count`; users see no
  degraded state, retry/reconciliation result or partial-capture receipt.
- Pruning hard-deletes fixed row counts during session teardown. It is not tied
  to a retention/consent policy, storage budget, workspace, provenance, logical
  record history or tombstones, and teardown does not report lost/failed
  capture to canonical session state.
- Source/config extension recognition is neutral metadata and genuinely used
  here. It currently calls `crate::rules::is_known_extension`, so the registry
  must move to a non-instruction file-type module before the deprecated rule
  injector is deleted. Retaining that table does not justify retaining rule
  loading, selection or injection.
- Tests heavily exercise helper heuristics and SQL mechanics but do not run a
  real frontend/tool lifecycle or prompt retrieval. Missing are frontend parity,
  blocked-hook behavior, expanded-input isolation, unrelated command success,
  multiple/interleaved errors, relative/canonical path identity, real multiline
  Clippy output, privacy/consent/review, degraded-store visibility and measured
  downstream task benefit/harm.

#### `src/compaction.rs`

Status: Read in full, including all 3,862 lines and unit tests; all production consumers traced
Disposition: Preserve context management; replace lossy prose promotion and converge every frontend on a typed, evaluated compaction transaction

Findings:

- Production proxy compaction is real, but `generate_summary` does not
  summarize. It concatenates at most 500 characters from each text message (200
  per multipart text item), replaces tool calls/results with generic markers,
  and discards the rest. Decisions, exact requirements, unresolved work,
  artifact versions, errors and causal tool evidence can silently disappear.
  Tests explicitly pin this as “local keyword concatenation” rather than
  measuring retention or downstream task correctness (F-077).
- The concatenated transcript is inserted as a `system` message. Escaping XML
  punctuation prevents a closing-tag trick but does not remove the semantic
  force of untrusted user/tool/model text. All preserved system messages are
  also moved to the front regardless of their original position, changing
  conversation order and authority semantics (F-077).
- The model/context registry is a large hand-maintained substring table,
  separate from provider/model catalogs and without provider source, effective
  date, account/tier/capability negotiation or exact-match precedence. Unknown
  models silently receive 128K. Broad substrings can classify unrelated names,
  and a changed provider limit can produce either premature compaction or an
  oversized rejected request.
- The token estimator is not a conservative bound. ASCII whitespace contributes
  zero and short messages such as `hi` estimate to zero; provider wrappers,
  message/request `extra`, exact tokenizer differences, reasoning/output needs
  and most media properties are ignored. Conversely, user text containing the
  literal `<image_data>` incurs a fake 1,600-token image cost, while every real
  image receives that same flat cost independent of provider, size/detail or
  tiling. The fixed 4,096 response reserve ignores the requested/provider output
  budget and other run context consumers.
- Proxy compaction supplies the previous turn's provider input count as if it
  measured the newly prepared request. It then compares that actual historical
  value to a fresh heuristic estimate after rewriting, so the trigger, reported
  savings and “did reduce” check use incompatible populations. Changed
  messages, tools, hooks, rules or model make the hint still less comparable.
- Success means only that the post-rewrite heuristic is smaller than the
  pre-count. The result may remain over the provider/context target. Partial
  compaction estimates freed raw-message tokens without subtracting generated
  summary/boundary cost, accepts any reduction, and does not iterate or return a
  typed cannot-fit state.
- Message preservation is positional, not causal. With tool preservation off,
  the recent-count boundary can separate a tool call from its result and emit a
  provider-invalid history. With it on, all historical tool traffic is immune
  to compaction and can make fitting impossible. No message IDs, dependency
  graph, task status, artifact references or exact resumability invariants
  drive selection.
- Archival and heuristic memory extraction happen before the rewrite is proven
  useful. Each message/derived snippet is independently committed; failures are
  warnings, successful rows remain even when the request is rolled back, and
  repeated attempts duplicate data. The first user paragraph and last assistant
  paragraph are promoted as durable “memories” without provenance, review or
  truth checks. A retrieval hint is emitted whenever a session ID exists even if
  no database was provided or every archive write failed, and it names the
  unregistered `memory_search` tool (F-073/F-077).
- Boundary/archive metadata uses forgeable prose markers and physical SQLite
  row IDs rather than a typed host event and stable record IDs. This compounds
  the transcript and memory identity problems in F-072/F-075.
- Reality-ledger summary recording does not link the summarized messages. It
  attaches the current bounded ledger index wholesale as navigation sources,
  regardless of which observations the truncated prose actually covers, and
  failure is only logged. This cannot establish a faithful causal summary.
- `CompactionConfig::summary_prompt` is stored, overridden and tested but never
  read by summary generation. `microcompact`, archival/extraction, configuration
  overrides and the nominal `AutoCompactor` service have no live production
  caller. Proxy always uses default overrides and passes no memory/session ID.
- Frontends implement different products. Proxy uses `ContextCompactor`; the
  legacy REPL has a second 200-character-per-message compactor without hooks,
  archive or boundary metadata; TUI and ACP only use token estimates/policy and
  do not invoke compaction. The advertised automatic context-management feature
  is therefore not frontend-equivalent (F-004/F-078).
- Hook denial or compaction failure is nonfatal in proxy: the original oversized
  request continues to provider dispatch with only a warning. This may be a
  legitimate fallback below the hard limit, but there is no exact provider-fit
  check or typed user-visible blocked/cannot-fit outcome.
- The very large test suite mostly pins local arithmetic, data shapes and past
  issue prose. It does not evaluate tokenizer error against provider counts,
  factual/requirement/tool-causality retention, prompt-injection behavior,
  provider-valid message histories, task success after repeated compactions,
  archival crash/idempotency, cross-frontend parity or hard fit guarantees.

#### `src/claude_credentials.rs`

Status: Read in full, including all 1,406 lines and unit tests; all production consumers traced
Disposition: Preserve convenient Anthropic authentication only through a provider-supported, non-impersonating credential boundary

Findings:

- A failed refresh response body is logged verbatim at debug level immediately
  after the code warns that Anthropic may echo the refresh token in that body.
  Only the returned error is redacted. `CredentialsFile`, `ClaudeAiOauth` and
  `LoadedCredentials` also derive `Debug` while containing bearer/refresh
  tokens, and headers are exposed as ordinary clonable `String` tuples
  (F-079).
- OpenClaudia writes another application's `~/.claude/.credentials.json` using
  a partial schema. Refresh and login serialize only `claudeAiOauth` and only
  the fields known here, so unknown top-level/OAuth fields from newer Claude
  versions are destroyed. A malformed existing file is silently treated as no
  existing metadata during login and then overwritten. There is no backup or
  schema/producer negotiation (F-080).
- Final-component symlinks are checked before path-based reads/writes, leaving a
  check/use race and parent-symlink redirection. Config directory environment
  values may be relative/arbitrary; existing file owner/type/mode/link count and
  parent trust are not validated. Reads are unbounded. The lock file is likewise
  opened by path without no-follow/owner checks.
- The advisory lock blocks synchronously inside an async function, is held
  across an OAuth network request, and has no acquisition deadline. The refresh
  client also has no explicit request deadline, response-size limit,
  cancellation or retry policy. One stalled refresh can park an executor thread
  and indefinitely serialize all cooperating processes; the claim that Claude
  Code cooperates with this OpenClaudia-specific lock is not established.
- Atomic 0600 temp-file replacement and parent sync are useful, but sync failure
  is downgraded to success. The transaction does not re-read/merge an expected
  source generation before replacement, so noncooperating producers can lose a
  concurrent refresh/update.
- Refresh output is only loosely validated: empty tokens are accepted, returned
  scopes are not rechecked for `user:inference` before returning success, and
  stale subscription/tier fields are copied from the pre-request snapshot. The
  policy treats omitted refresh tokens as invalid unless a process-global env
  escape hatch is set and inaccurately states all its chosen response fields are
  OAuth-required instead of negotiating the actual provider contract.
- Existence alone is advertised as available credentials. `peek_credentials`
  can return a status without inference scope and the `/login` path prints
  “Authenticated” for any parsed OAuth section, even when it cannot authorize a
  chat. Availability, freshness, scope and successful request capability are
  conflated.
- The module reuses Claude Code's client ID, subscriber bearer token, beta
  headers and an identity assertion saying OpenClaudia is “Anthropic's official
  CLI.” A public client identifier and an observed wire requirement do not by
  themselves establish authorization for a different application to impersonate
  that client. The compatibility path has no cited/versioned provider contract,
  capability discovery or conformance check; hard-coded dated betas and identity
  prose can drift (F-081).
- Prefix/persona insertion is not idempotent and silently replaces invalid
  non-string/non-array `system` values rather than rejecting the request.
  Credential handling owns an included behavioral prompt, mixing authentication,
  product identity and agent policy across multiple prompt builders.
- Tests cover JSON shape, simple final symlinks, modes and recursive TTL stripping
  but never exercise the real refresh endpoint seam, secret-safe logging,
  timeout/cancellation, lock contention, foreign-field preservation, parent/
  race attacks, permissions/ownership, concurrent producers, reduced scopes,
  empty/oversized responses or supported-provider conformance.

#### `src/codex_credentials.rs`

Status: Read in full, including all 495 lines and unit tests; all production consumers traced
Disposition: Preserve OpenAI/Codex login discovery only behind an official, verified credential adapter

Findings:

- `CodexResponsesAuth` implements redacted `Debug`, but the encompassing
  `CodexAuthMaterial` derives `Debug`; its `ApiKey` variant therefore prints the
  full OpenAI API key. Private deserialization structs also derive secret-bearing
  `Debug`, and header construction again exports bearer tokens as plain strings
  (F-079).
- The code parses JWT payload bytes without verifying signature, issuer,
  audience, expiry or nonce, then uses those claims (or unvalidated JSON fields)
  for `ChatGPT-Account-ID` and `X-OpenAI-Fedramp`. Authentication still occurs
  upstream, but account selection and a compliance-sensitive routing assertion
  must not be derived from unauthenticated claims (F-082).
- It is deliberately coupled to another application's evolving `auth.json`
  shape and a hard-coded ChatGPT backend URL. It does not use that application's
  keyring or refresh lifecycle; stale tokens are knowingly forwarded. Unknown
  explicit auth modes fall through to field-based inference, so a future schema
  can be silently misclassified rather than rejected as unsupported.
- `CODEX_ACCESS_TOKEN` is always interpreted as ChatGPT external-token mode
  without an explicit audience/auth-kind contract. Explicit `account_id` wins
  over token claims without consistency validation. Token/JWT/file sizes are
  unbounded, decoded payload allocation is unbounded, and no expiry check is
  performed before selection.
- Final symlink rejection is subject to the same parent-symlink and check/use
  races; file owner/mode/type/links are not checked and the whole file is read
  without a cap. `has_codex_auth_json` follows symlinks and can advertise an auth
  choice that the actual loader then refuses.
- Access tokens/API keys are clonable ordinary strings without zeroization or a
  capability handle. Callers copy them into frontend/provider state, expanding
  lifetime and accidental logging/crash-dump exposure.
- Tests cover only API-key parsing, one ChatGPT object and a static symlink.
  They omit environment precedence, unknown/future modes, JWT validation and
  expiry, claim/account conflicts, FedRAMP routing, size/mode/ownership/races,
  secret logs, stale-token UX, official backend/auth compatibility and real
  Responses request scopes.

#### `src/file_error.rs`

Status: Read in full, including all 448 lines and unit tests; consumers searched
Disposition: Keep typed errors; replace generic path-based I/O helpers with bounded capability/store transactions

Findings:

- Retaining path and structured I/O/JSON/YAML causes is a useful improvement
  over string errors. Adoption is narrow, however: most source files still use
  direct `std::fs` plus strings/`anyhow`, so this is not the canonical storage
  boundary its module documentation implies.
- `read_file`, JSON and YAML helpers follow symlinks/parent redirection and read
  the entire file without a byte/depth/schema budget. `write_file` truncates in
  place, follows path resolution and creates with ambient permissions. These
  ergonomics are unsafe defaults for agent-controlled or secret/state paths.
- The “atomically and durably” helper uses a unique 0600 sibling and fsync, which
  is valuable, but creates/follows parent paths by name without an authorized
  root descriptor or symlink/owner/type checks. A parent can redirect between
  resolution steps, so atomic replacement does not establish target authority.
- On Unix the destination is already published before parent-directory fsync.
  If that fsync fails, the function returns ordinary `Err` even though visible
  state changed. Callers cannot distinguish unchanged failure from published-
  but-not-durability-confirmed partial success, encouraging unsafe retries
  (F-083).
- The generic atomic helper always publishes mode 0600 rather than preserving
  an expected existing mode or taking a storage-class policy. That is sensible
  for secrets but surprising for a generic file/config/export helper and can
  change interoperability. Windows/non-Unix durability and directory semantics
  are not equivalent to the Unix claim.
- The `Utf8` variant is unused: `std::fs::read_to_string` reports invalid UTF-8
  as an `io::Error`, so current helpers cannot produce the advertised typed
  variant. YAML support depends on the already recorded unmaintained legacy
  parser chain.
- Tests establish simple replacement, cleanup and 0600 mode but omit parent/
  final symlink races, ownership/hardlinks, concurrent writers, crash/power-loss
  injection at every boundary, disk-full/dir-fsync partial publication,
  Windows behavior, mode-preservation policy, size/depth limits and recovery.

#### `src/guardrails.rs`

Status: Read in full, including all 2,254 lines and unit tests; every production consumer traced
Disposition: Preserve blast-radius, change-budget and quality-verification intent; consolidate into canonical capability/effect/budget enforcement

Findings:

- Strict blast-radius decisions match a minimally normalized caller string, not
  the resolved resource identity. Only backslashes and one leading `./` are
  changed. An allowed `src/**` path such as `src/../.env` matches before normal
  filesystem resolution reaches the denied file; absolute/relative aliases,
  repeated separators, case rules and symlink targets likewise disagree
  (F-084).
- Invalid allow and deny globs are warned and silently dropped. If every strict
  allow pattern is invalid, the compiled allow list is empty and the code
  interprets that as “no allow restriction,” failing open. Configuration does
  not surface an unusable policy as startup failure.
- Enforcement is a mutable process-global singleton, not bound to run,
  workspace, authenticated policy generation or frontend. Reconfiguration by
  one server/session changes all others; file-count state is shared. Proxy
  setup never calls `reset_turn`, while TUI/legacy call it at different loop
  boundaries, so the same cap can be per-process-forever or reset multiple
  times depending on entrypoint (F-084).
- Only direct file handlers and the TUI pipeline's read/search precheck call the
  blast guard. Bash, worktree, LSP/process tools, ACP's direct filesystem path,
  plugin/subagent effects and alternate frontend dispatch do not share this
  control. It cannot represent a real request blast radius over typed effects.
- File quota is charged before the underlying operation succeeds, and uses path
  spellings rather than stable file identity. Failed/nonexistent aliases consume
  slots while multiple aliases to one resource can consume many. No atomic
  reservation/commit/release spans concurrent effect execution.
- Diff monitoring trusts handler-supplied counts rather than committed workspace
  snapshots. Full writes report all old lines removed and all new lines added
  even when most content is unchanged; outside/Bash/worktree changes are absent.
  Counters use unchecked `u32` addition and the file set is unbounded and
  nondeterministically rendered.
- `GuardrailAction::Block` and `InjectFindings` are never enforced for diff
  thresholds. The check occurs after mutation and file/notebook handlers merely
  append “Warning” text regardless of action, so a configured block cannot stop
  or roll back the oversized change (F-085).
- `QualityGatesConfig::run_after` and `fail_action` are unused. TUI and legacy
  run all gates after tool batches regardless of `every_edit`/`every_turn`/
  `on_commit`; required failures do not block/finalize/rollback. TUI streams a
  minimal warning, while legacy promotes bounded raw stdout/stderr into a system
  message. This is incomplete configuration, not an operational gate (F-085).
- Quality commands are project/config-controlled executable code. Direct argv
  avoids accidental shell-metacharacter interpretation, but an explicit
  `sh -c` remains supported and tests depend on it. The existing quality-gate
  sandbox inherits the broad/non-profiled process authority recorded in F-048;
  no per-command permission, network/dependency policy, idempotency or run budget
  exists. Auto-detected `npx` commands may download/execute unpinned packages.
- Full command arguments are logged and can carry secrets. Although shared
  process capture is bounded, gate stdout/stderr is retained in result strings
  and can become prompt/ledger “verification” without source/artifact generation
  or a trusted verifier definition, compounding F-046.
- Documentation says timeout zero disables supervision, while the implementation
  silently changes zero to 300 seconds. The sync API parks or creates threads/
  runtimes around blocking workers instead of participating in canonical async
  cancellation/admission.
- Language detection is ambient-CWD and marker-existence heuristics. It misses
  C/C++ in polyglot roots, labels every CMake project C++, may run Gradle twice
  for Kotlin/Java and chooses build commands using global CWD rather than a
  workspace capability. It does not inspect project-defined scripts/toolchain
  locks or availability before execution.
- Poison fail-closed behavior for file access and bounded subprocess capture are
  useful. Tests, however, mostly pin regex/helper/global states. They omit
  traversal/symlink aliases, invalid-all strict configs, concurrent sessions,
  proxy reset behavior, failed reservations, real diff snapshots, each action/
  cadence, ACP/Bash/worktree parity, dependency/network policy, secret output,
  rollback/finalization and evidence authenticity.

#### `src/hooks/claude_compat.rs`

Status: Read in full; settings loaders and every production consumer traced
Disposition: Preserve explicit hook interoperability, but remove ambient foreign/project trust and make imports provenance-aware and capability-gated

Findings:

- Every CLI/TUI, ACP, and proxy construction automatically reads Claude Code's
  user settings plus committed and local repository settings from ambient paths.
  No run-level trust decision distinguishes a file the user intentionally
  enabled for OpenClaudia from repository content merely present on disk. A
  compatible project file can therefore register workspace-writing commands or
  model-facing instruction output before the user approves that authority
  (F-086).
- The claimed four-layer precedence is not an enforceable policy hierarchy.
  Hook arrays concatenate, so managed entries normally run alongside rather
  than replace lower-trust entries. A lower layer can fill the 8,192-element
  concatenation cap before later entries are considered; a post-merge size
  failure clears the entire tree, including managed settings (F-086).
- Individual files are read and parsed without a pre-read byte bound. The caps
  act only during some merge shapes or after the complete tree has already been
  allocated. Read/parse/depth failures are logged and skipped, and a malformed
  or unsupported hook variant can make conversion of the whole merged `hooks`
  object silently produce no hooks. `managed_settings_path` records existence,
  not successful validation/application.
- `allowedTools` is extracted and exposed in `LayeredSettings` but has no
  production consumer. It grants no actual permission and constrains no
  advertised or dispatched tool, despite presenting as a loaded policy result.
- The compatibility schema accepts only command hooks. Imported entries lose
  source/layer provenance, signer/owner information, explicit matcher target,
  and policy identity before being merged into ordinary `HooksConfig`.

#### `src/hooks/merge.rs`

Status: Read in full, including tests; producer and consumer semantics traced
Disposition: Replace trust-blind JSON/config merging with validated, source-preserving hook policy composition

Findings:

- Hook precedence is keyed only by normalized matcher. Distinct entries with
  the same matcher are treated as replacements regardless of hook purpose or
  source; duplicate keys already present in the base leave earlier duplicates
  behind because the index retains only one position. The replacement warning
  logs complete command, prompt, and model-prompt strings, potentially exposing
  secrets or private instructions (F-088).
- Deep merge concatenates arrays and keeps earlier elements when the cap is
  reached. This contradicts the stated later-source/managed precedence exactly
  where capacity pressure is adversarial. Scalar/object precedence cannot turn
  this into a host deny over accumulated executable hooks (F-086).
- Each file is read wholesale, parsed wholesale, and the entire accumulated
  tree cloned for rollback. A first array inserted into a null/missing slot is
  cloned without the array-concatenation cap; aggregate size is measured by a
  second full serialization only after allocation. There are no per-file,
  per-event, per-entry, or total-command admission limits.
- Claude conversion hard-codes direct-spawn mode and a default timeout, but
  discards source provenance and cannot attach the importing trust policy. All
  supported foreign lifecycle names are appended even when the corresponding
  OpenClaudia lifecycle event is never emitted by a caller (F-087).
- Tests verify merge mechanics and rollback, not managed-deny dominance,
  source provenance, malformed mixed entries, lower-layer crowd-out, secret
  redaction, executable trust approval, or end-to-end frontend behavior.

#### `src/hooks/mod.rs`

Status: Read in full, including all 2,809 lines and tests; every event producer, engine construction, and output consumer traced
Disposition: Preserve hooks as typed, explicitly authorized runtime extensions; repair lifecycle, trust, budgets, and output authority in the canonical runtime

Findings:

- The engine turns prompt/model hook text and JSON `systemMessage` into model
  guidance; proxy hooks can replace the user's prompt. XML wrapping changes
  delimiters, not semantic authority. Combined with automatic repository and
  foreign settings discovery, untrusted configuration is promoted to control-
  plane instruction/execution authority (F-086).
- Lifecycle coverage is materially incomplete and frontend-dependent. Proxy is
  the only SessionStart producer; TUI is the only SessionEnd producer; ACP does
  not run UserPromptSubmit; SubagentStart/SubagentStop are never emitted;
  PermissionRequest, Stop, notification, compaction and VDD events each have
  different or absent entrypoint coverage. Several denial results are merely
  logged or discarded (F-087).
- Output contracts also diverge. Only proxy applies `prompt`; only the legacy
  REPL consumes plain-text `additionalContext`; TUI appends `systemMessage` as
  a late system-role message; legacy persists it at the beginning; pre-tool and
  permission callers discard instruction/context fields. Conflicting output
  from multiple hooks has no typed composition policy (F-087).
- `HookMatcherTarget` is documented as user-overridable, but `HookEntry` has no
  target field and the engine always selects the event default. `ask` decisions
  have no behavior. Prompt timeouts are unused because prompt hooks return
  immediately. `with_model_callback` has no production caller, so every model
  hook currently fails. The public module says 12 events while defining 16
  (F-087).
- UserPromptSubmit is treated as observe-only for error policy even though
  callers use it to deny and rewrite user requests. Matcher, command, or model
  failures therefore fail open. SessionStart denial is logged but startup
  proceeds; TUI Stop denial is ignored while proxy Stop denial changes loop
  control. Post-tool failures are logged but deliberately cannot affect the
  already-completed action.
- `run` launches every matching hook concurrently before evaluating any deny.
  There is no aggregate hook count, process/model concurrency, input/output
  byte, total wall-time, cost, or cancellation budget. One hook retains up to
  1 MiB on each output stream; thousands can be admitted, and raw tool outputs
  are cloned/serialized into stdin before any aggregate bound (F-088).
- An absent policy allows every executable basename inside the default sandbox.
  Direct-spawn allowlisting checks only basename, so an arbitrary path can
  masquerade as an allowed binary; `shell:true` skips the allowlist entirely.
  The Linux repository-hook sandbox is valuable, but it grants project write
  access and cannot substitute for user authorization to execute repository
  automation.
- Debug/warn logging includes complete hook commands, shell commands, model and
  provider identifiers, matcher patterns, up to 1 MiB stderr, and replacement
  prompts. Errors can therefore expose secrets embedded in command arguments,
  prompts, provider responses, or subprocess diagnostics (F-088).
- Tests are extensive at helper/unit level and validate useful fail-closed
  PreToolUse behavior, process-tree timeout, environment scrubbing, and Linux
  sandbox use. They also enshrine no-policy allow-all and shell allowlist bypass,
  and omit automatic-project trust consent, aggregate exhaustion, cancellation,
  all-frontend lifecycle parity, model-hook reachability, prompt-authority
  safety, source precedence, and denial/failure semantics for every event.

#### `src/keybindings/actions.rs`

Status: Read in full; every variant consumer traced
Disposition: Keep the user-facing action vocabulary, but bind it to real shared commands

Findings:

- The enum describes useful actions, but reachability is not established by
  serialization. The legacy adapter maps several actions to messages telling
  the user to type a slash command instead of performing the action, merges
  NewSession with Clear, and the TUI never consumes this enum (F-089).
- `None` is represented as an ordinary action. The unused resolver returns an
  exact `Match { action: None }`, while lookup helpers treat it as unbound;
  callers would need another frontend-specific semantic distinction.
- Tests only round-trip enum names; they do not prove any action reaches its
  intended command or has equivalent behavior across UI states/frontends.

#### `src/keybindings/lookup.rs`

Status: Read in full; all production consumers traced
Disposition: Consolidate into the validated resolver/shared command dispatcher

Findings:

- `get_action` lowercases the query but configuration keys are stored exactly
  as deserialized. Contrary to its documentation, a user key such as
  `Ctrl-X N` is not found under `ctrl-x n`; only built-in lowercase defaults
  make the unit test pass.
- Reverse lookup returns HashMap iteration order, making `/keybindings` display
  nondeterministic. There is no normalized collision detection or record of
  whether a user disabled, replaced, or accidentally shadowed a default.
- Production uses these helpers only in the legacy REPL's streaming poll and
  display command. They do not provide TUI or normal-input binding behavior.

#### `src/keybindings/mod.rs`

Status: Read in full; exports traced
Disposition: Keep a single public keybinding facade after the runtime is wired

Findings:

- This facade publicly re-exports a resolver and context enum that have no
  production consumer, making compiled API shape look like an integrated
  feature. The useful intended behavior should be wired before duplicate legacy
  helpers are removed (F-089).

#### `src/keybindings/parser.rs`

Status: Read in full, including tests
Disposition: Keep after strict terminal-key grammar, canonicalization, and bounds

Findings:

- Parsing lowercases and structures chords, but accepts arbitrary key strings,
  duplicate modifiers, empty/dashed key fragments and unbounded chord length.
  It cannot tell users that a terminal/frontend can never emit a configured
  key. There is no canonical collision check across modifier order/casing.
- Tests cover only well-formed examples and empty/all-modifier strings. They
  omit hostile/large config, terminal event round trips, unsupported keys,
  duplicate-equivalent chords and platform keyboard behavior.

#### `src/keybindings/resolver.rs`

Status: Read in full, including tests; source-wide search confirms no production construction
Disposition: Finish and integrate the resolver; remove older string dispatch only after parity

Findings:

- `KeybindingResolver`, `KeyContext`, and `ChordResolveResult` are test-only/
  public scaffolding. Context is not stored or evaluated, so the advertised
  Global/Chat/Confirmation/overlay separation does nothing (F-089).
- Bindings come from a HashMap. Multiple spellings that parse to the same chord
  produce nondeterministic winners. If one chord is both an exact action and a
  prefix of a longer chord, exact match fires immediately, making the longer
  chord unreachable.
- A prefix has no deadline. It remains pending indefinitely; the next unrelated
  keystroke produces `NoMatch`, clears state and consumes that key rather than
  replaying it as ordinary input. Silent parse skips leave invalid configured
  bindings unavailable with no startup or UI diagnostic.
- The legacy path does not use this resolver: it always converts one event with
  `leader_active=false`, so configured multi-key defaults cannot resolve there.
  That path runs only while streaming; normal legacy input is owned elsewhere.
  TUI editing uses hard-coded key matches and ignores `AppConfig.keybindings`.
- Unit tests exercise synthetic resolver calls but no real crossterm event,
  app/REPL state, timeout, collision, context, input replay, configuration
  reload, help display, or action execution.

### F-089 — Configurable keybindings are largely disconnected and the unused resolver is ambiguous

Severity: Medium
Status: Confirmed in schema, runtime keybinding modules, legacy adapter, and TUI dispatch

The configured action map affects the legacy streaming poll and help display,
not ordinary input, while the TUI hard-codes keys and ignores it. Default
multi-key chords cannot resolve in the only legacy event converter because its
leader state is always false. The newer parser/resolver is never constructed;
if wired unchanged it has nondeterministic normalized collisions, unreachable
long chords, indefinite prefix state, and consumes a mismatching input key.

Required outcome: Preserve configurable shortcuts through one frontend-neutral
command registry and contextual resolver. Canonicalize/validate the entire map
at startup, overlay defaults deliberately, reject duplicate/unemittable chords,
define exact-versus-prefix precedence and a visible bounded timeout with safe
input replay, and dispatch the same typed action in TUI and legacy states.
Generate help from the effective map and prove crossterm event-to-command parity,
modal/permission safety, reload behavior and every advertised action end to end.

### F-086 — Ambient hook compatibility grants repository and foreign settings executable/instruction authority

Severity: Critical
Status: Confirmed in all hook modules, composition roots, and context/output consumers

Every main runtime automatically imports user and ambient repository Claude
settings without an OpenClaudia-specific trust capability. Project command
hooks receive raw lifecycle data and can write the workspace; prompt/model
output can become model guidance or replace a user request. Layered array merge
does not make managed policy dominant: lower-trust hooks accumulate alongside
managed entries, can crowd later entries out at the cap, and an aggregate-size
failure clears all layers. Provenance is discarded before execution.

Required outcome: Keep explicit compatibility import, but make it a bounded,
versioned, user-visible opt-in that records exact source identity/digest/owner,
workspace, policy generation and approved capabilities. Host/managed policy
must be an unforgeable final deny/allow ceiling, not another concatenated JSON
layer. Repository automation receives no execution, mutation, secret, network,
prompt-rewrite or instruction authority merely by existing. Imported output is
typed untrusted evidence unless a separate host-authorized extension capability
permits a narrow instruction/policy result. Reject malformed/oversize/conflicting
config atomically and expose a typed unavailable/degraded state.

### F-087 — The advertised hook lifecycle is incomplete and semantically different across frontends

Severity: High
Status: Confirmed by source-wide event producer and output-consumer trace

Several of the 16 declared events are never emitted or exist in only one
frontend. ACP omits prompt-submit hooks, subagent events are wholly unwired,
session start/end are split between proxy/TUI, and denial behavior varies by
call site. Proxy alone supports prompt replacement, legacy alone consumes plain
text context, and system-message placement/persistence differs. Model hooks
have no callback construction, prompt timeout is inert, `ask` is inert, and the
documented matcher-target override has no configuration field.

Required outcome: Define one typed event/result matrix in the canonical W12
runtime and emit it at causal transaction boundaries for every supported
frontend and subagent. Each event declares whether failure/deny blocks,
observes, retries or degrades; outputs have explicit composition and authority,
and unsupported fields fail validation rather than becoming assurances. Wire
model hooks through the same provider budget/policy/cancellation path only if a
measured use case justifies them. Generate documentation and conformance tests
from the implemented matrix.

### F-088 — Hook execution has bypassable command policy and no aggregate admission budget

Severity: Critical
Status: Confirmed in hook execution, merge, sandbox, and logging paths

All matching hooks launch concurrently before denial is evaluated. Native and
foreign configuration has no effective total command/process/input/output/
time/cost budget; per-hook stream retention multiplied by thousands of hooks is
large, and raw tool output is cloned into hook input. No-policy mode admits
every executable inside the sandbox, basename-only allowlisting accepts an
arbitrary same-named path, and `shell:true` bypasses that allowlist. Raw command,
prompt, replacement, matcher, stderr and model metadata reach logs.

Required outcome: Admit hooks through W2/W10 as typed effects with explicit
source trust, executable identity/digest, arguments, filesystem/network/secret
capabilities, concurrency, byte, time, token/cost and cancellation budgets.
Resolve binaries from host-approved identities; shell execution is a distinct
high-risk capability, never an allowlist escape. Stop scheduling after a
blocking result when ordering requires it, supervise already-started work, bind
outputs to call/event IDs, redact by sensitivity at type boundaries, and prove
resource/secret behavior with adversarial end-to-end tests.

#### `src/mcp_elicitation.rs`

Status: Read in full, including tests; source-wide search confirms no consumer
Disposition: Preserve interactive input/consent through current MCP multi-round-trip requests; retire this obsolete callback shape after compatibility migration

Findings:

- This is explicitly a trait skeleton. No transport, manager, TUI, ACP, proxy,
  or legacy frontend constructs a handler. Meanwhile stdio separately advertises
  elicitation and hard-codes `decline`, so even the safe no-op's `Cancel`
  semantics are not used (F-093).
- `Accept(Value)` and requests are ordinary `Debug`/cloneable values even though
  module documentation names credentials/scopes as likely content. There is no
  schema validation, sensitivity classification, attribution receipt, UI,
  permission binding, replay protection, cancellation, or input budget.
- The latest official MCP revision replaced server-initiated
  `elicitation/create` callbacks with multi-round-trip `input_required` tool
  results. Preserve the intended user-interaction capability by implementing
  that current flow; do not extend this deprecated mechanism as new architecture
  ([MCP 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/)).

#### `src/mcp_inprocess.rs`

Status: Read in full, including tests; source-wide search confirms no construction
Disposition: Preserve an in-process transport only behind the same trust/runtime contract as external MCP

Findings:

- The adapter is public but entirely unwired. It forwards arbitrary method and
  JSON values without protocol-version metadata, capability negotiation, schema
  validation, deadlines, cancellation, admission, panic isolation, permission,
  trace, or sensitivity handling (F-093).
- `close` is a no-op and later requests continue to succeed, so the transport
  cannot represent a closed/revoked generation. Dropping one Arc does not notify
  or finalize the server and there is no lifecycle hook for owned state.
- Tests prove forwarding/object safety only; they do not exercise manager
  registration, revocation, concurrent work, cancellation, trust isolation or
  a real in-process tool/resource server.

#### `src/mcp_oauth.rs`

Status: Read in full, including tests; source-wide search confirms only the module export
Disposition: Replace schema-only legacy flow with current MCP authorization and hardened secret types

Findings:

- This file is explicit scaffolding: no HTTP discovery/exchange, 401 challenge,
  browser/redirect listener, refresh, persistence, keyring, transport attachment,
  scope escalation, revocation or caller exists. MCP HTTP authentication is not
  operational (F-093).
- `TokenBundle`, `OAuthConfig`, `PkcePair`, and `OAuthFlow` derive `Debug` or
  contain ordinary cloneable/serializable strings holding access tokens, refresh
  tokens, client secrets, authorization codes and PKCE verifiers. A JSON round-
  trip test explicitly serializes live secrets without storage protection.
- Security-critical state and PKCE values are caller-supplied; entropy, S256
  derivation/method, URL/redirect security, issuer, resource/audience, scopes,
  token provenance and future timestamps are not validated. The state machine
  has no refresh/rotation path, and `fail` also converts an already Authorized
  state despite documentation saying non-terminal states.
- Current MCP authorization requires protected-resource and authorization-server
  discovery, resource indicators, issuer validation, credential-to-issuer
  binding, and current client registration metadata behavior—not manually
  configured endpoints plus a token struct. Implement against the
  [official 2026-07-28 authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

#### `src/mcp.rs`

Status: Read in full, including all 4,845 lines and tests; every startup, schema, dispatch, resource, and shutdown consumer traced
Disposition: Preserve MCP tools/resources and trust gating; rebuild protocol/runtime integration around current versioned adapters

Findings:

- MCP tools are not operational end to end. Proxy alone appends dynamic schemas,
  but `handle_mcp_tool_call` has no caller and the proxy returns model tool calls
  to a downstream client that did not register those injected tools. TUI installs
  the manager but never adds dynamic MCP schemas to pipeline requests. ACP routes
  `mcp__*` into the static registry, where no dynamic handler exists. Resource
  tools use a separate process-global manager installed only by TUI; proxy/ACP/
  legacy therefore advertise handlers that report no manager (F-090).
- The implementation speaks fixed `2024-11-05`: initialize/session state,
  nested server requests and legacy response assumptions. The official current
  `2026-07-28` protocol is stateless, self-describing per request, retires the
  initialize/session exchange, uses `server/discover`, moves elicitation to
  multi-round-trip results, requires routing metadata, and adds cacheable lists.
  OpenClaudia neither negotiates nor implements that profile
  ([release summary](https://blog.modelcontextprotocol.io/posts/2026-07-28/),
  [current specification](https://modelcontextprotocol.io/specification/2026-07-28))
  (F-091).
- Even for the legacy profile, `notifications/initialized` is sent through the
  request API with an ID and awaited response. The returned error/result is
  discarded. The response `jsonrpc` value and negotiated protocol version are
  never validated; only numeric IDs are supported; notifications such as tool-
  list changes are ignored while the cached list is presented as current.
- Tool/resource list pagination is ignored and responses have no item/schema/
  aggregate limits or deterministic normalization. Names are interpolated into
  `mcp__server__tool` without validating length/characters/separator collisions.
  Arguments and structured output are not schema-validated. Current tool title,
  icons, annotations, output schema, typed text/image/audio/resource content,
  structured content, input-required results and cache metadata are lost or
  collapsed to raw JSON/text; resource reads discard mixed content and return
  base64 blobs as prose ([current MCP tools contract](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)).
- HTTP validates the initial URL once but exposes public release-built
  `__test_*_unchecked` constructors/connectors that bypass the SSRF guard. It
  follows the shared web transport's unresolved redirect/DNS lifecycle, accepts
  arbitrary static/dynamic headers as ordinary cloneable strings, logs the URL,
  and reads JSON/SSE bodies wholly through `response.text()` with no byte/event
  cap. It does not implement current request metadata/headers, cancellation or
  subscription semantics (F-092).
- Stdio bounds one line and stderr retention and uses a valuable sandbox, but
  has no default steady-state deadline, request-size bound, cancellation message,
  graceful close/reap, or recovery after a partial/oversized/cancelled frame.
  Timeout drops can leave a stale response on the stream. Executable trust
  requires every path ancestor to be root-owned, rejecting ordinary explicitly
  trusted user-installed servers instead of using an approved identity/digest.
- One manager mutex is held across reconnect, tool calls, resource calls and
  full list-all loops, serializing every unrelated server and all metadata reads.
  A stalled default stdio call can block the whole MCP subsystem. Outer timeout
  cancellation can leave the entry marked live and protocol-desynchronized;
  inner timeout/transport failure drops a live server without calling close,
  risking orphan subprocesses. Replacing a duplicate server name also drops the
  previous connection without shutdown (F-092).
- Reconnect reports the same permanently-unreachable error while merely waiting
  for backoff, reruns secret/header helpers, has no jitter/cancellation or durable
  generation, and clears tool state without a typed availability event. Listing
  all resources silently skips failed servers and returns an apparently complete
  unbounded result. Disconnect removes state before close, and disconnect-all
  stops at the first failure.
- Connection specs derive `Debug` while holding raw environment/header secrets.
  Header-helper shell commands get project read/write authority and dynamic
  values override static headers without count/byte/reserved-header policy.
  Elicitation and roots are advertised from stdio, but the former ignores the
  separate handler and the latter exposes ambient process CWD rather than the
  exact session capability.
- Plugin/server trust requires an exact host environment grant, sandboxing and
  sensitive-env grants—valuable foundations to preserve. But connection is
  best-effort, eager, startup-only and keyed by non-unique server name; failed
  connections are warnings, and user status/docs cite a nonexistent
  `.openclaudia/config.yaml` `mcp.servers` path while actual connections come
  from enabled plugin declarations.
- Tests heavily exercise isolated fixes, including stdio framing, error IDs,
  timeouts, SSRF validation and reconnect counters. Several encode legacy
  behavior or bypass security through public unchecked APIs; none proves one
  real server's discovery → provider schema → user approval → dispatch → typed
  result → follow-up → cancellation/shutdown across each claimed frontend.

#### `src/memdir/entrypoint.rs`

Status: Read in full, including every test; all production consumers searched
Disposition: Preserve bounded project-memory loading, but integrate it as attributed memory evidence rather than ambient system authority

Findings:

- Discovery, precedence, UTF-8-safe truncation and error propagation are real
  and well unit-tested. The implementation is nevertheless library-only:
  production code never calls `load_entrypoint`; only a dedicated integration
  test does. Its own module documentation and changelog explicitly say the
  prompt wiring is a follow-up (F-094).
- The function reads the entire file into memory before applying the 25,000-byte
  display limit. A huge or special file can therefore consume unbounded memory
  or block. Path access follows symlinks and does not bind the candidate to a
  regular file, workspace generation, trusted owner/mode, descriptor-relative
  root or maximum on-disk size. `EntrypointFile.path` is documented as absolute
  although a relative `cwd` produces a relative path.
- The intended consumer is direct system-prompt injection. A repository
  `MEMORY.md`, foreign-compatible root file and home-global fallback have
  different provenance and trust, yet first-hit selection erases that
  distinction except for a path. An untrusted checkout must not silently turn
  durable prose into system-level instructions. Truncation keeps the first
  lines rather than selecting relevant/current evidence and its suffix can push
  the returned value beyond the nominal byte cap.
- Empty/whitespace behavior and claimed parity are pinned as intentional
  divergences in tests. They demonstrate local string behavior, not correct
  authority, retrieval, lifecycle, privacy, correction, or agent-task outcomes.

#### `src/memdir/mod.rs`

Status: Read in full; export and every source/test reference traced
Disposition: Preserve the memory namespace; replace the abandoned phased promise with one implemented lifecycle

Findings:

- The module exports only the entrypoint loader. It explicitly says nothing
  calls it and lists the session-notes writer, extractor, autoDream consolidation
  and prompt suggestions as future phases. None of those modules exists, while
  the referenced design describes a 13-file subsystem (F-094).
- This is useful, honest evidence that the capability is incomplete—not a reason
  to delete the intended feature. Completion should converge with the existing
  memory/auto-learning/session stores rather than add another independent truth
  representation or background model loop.

### F-094 — Memdir has a tested loader but no operational memory lifecycle

Severity: High
Status: Confirmed by full module read and source-wide consumer search

Only MEMORY.md discovery/truncation exists, and no production caller invokes it.
The promised notes, extraction, consolidation and suggestion agents are absent.
Wiring the current loader literally would read an unbounded, symlink-following
file and promote repository/home prose of mixed trust directly into the system
prompt, duplicating the already-fragmented memory system.

Required outcome: Preserve project memory by folding it into W5's canonical,
attributed memory service. Read only bounded regular files through authorized
workspace/user capabilities; retain exact source, scope, generation, trust and
truncation metadata; treat contents as potentially adversarial evidence, never
implicit policy. Retrieve task-relevant entries with citations and expose
review/correction/expiry/deletion. Implement one typed session capture/extraction/
consolidation lifecycle with consent, privacy, cost and cancellation budgets,
or explicitly narrow the user-facing feature to safe manual memory import.

#### `src/oauth.rs`

Status: Read in full, including every test; CLI, proxy, credential-store and provider consumers traced
Disposition: Preserve user authentication, but remove this unauthorized client-impersonation path and replace its session runtime

Findings:

- This is operational code, not a stub: CLI and browser/proxy flows generate
  PKCE, exchange a pasted authorization code, optionally request an API key,
  persist sessions and authenticate proxy requests. Strong local pieces include
  cryptographic PKCE/state generation, take-once state, explicit token-type
  validation, redacted caller errors, `O_NOFOLLOW` reads, owner-only exclusive
  temp files, fsync-before-rename and interprocess merge locking.
- It is mislabeled as OAuth device flow but implements a manually pasted
  authorization-code flow; there is no device-authorization grant/polling. More
  importantly, it hard-codes Claude Code's client ID, redirect, scopes, user
  agent and private-looking token/API-key endpoints. Provider requests then add
  Claude Code identity prompt/header material. This is the confirmed prohibited
  impersonation architecture in F-081, not a supported OpenClaudia OAuth client.
- The comments promise auto-refresh, but refresh occurs only once immediately
  after initial exchange. `get_session` never rechecks expiry, no proxy path
  refreshes/rotates credentials, and no request uses the created `api_key` or
  `auth_mode`; every OAuth proxy request sends the access token. Thus ApiKey and
  ProxyMode are dead operational states while expired sessions keep being used
  until restart (F-095).
- CLI state validation is optional: a pasted code without `#state` is accepted.
  Proxy pending challenges have no age, owner/browser binding or count limit and
  unauthenticated start requests can grow the map. Submit consumes state before
  a transient exchange error, preventing a safe retry.
- All credential, session, token request/response and PKCE values are ordinary
  cloneable strings and several derive `Debug`/Serialize. Raw OAuth error bodies
  are deliberately emitted at debug level despite the redaction helper. HTTP
  success/error bodies are read without a byte cap. Plaintext access/refresh
  tokens and unused API keys are persisted in JSON rather than protected by an
  OS credential facility.
- Disk parsing is unbounded and unversioned. The parent/lock path is not bound
  descriptor-relatively or validated for owner/mode/link ancestry, and rename is
  not followed by a parent-directory fsync/typed uncertain-commit state. The
  compatibility `store_session` logs persistence failure but the proxy still
  returns authentication success.
- A UUID session ID is a bearer credential exposed to browser JavaScript, JSON,
  command examples and full info/debug logs; no server-set HttpOnly/Secure/
  SameSite cookie, expiry, rotation, revocation or per-client/session audience
  exists. Logout only removes the JSON file and cannot revoke in-memory proxy
  sessions or upstream tokens.
- Expiry clamping turns an upstream zero/invalid lifetime into 60 seconds of
  local validity instead of rejecting it, while request use has no proactive
  skew. Tests heavily verify data shapes, string parsing and file modes but do
  not run an authorized-provider flow, expiry/refresh races, revocation, browser
  attack model, crash recovery or proxy request after restart.

#### `src/pipeline.rs`

Status: Read in full, including all 5,177 lines and every test; every production builder, turn, tool, permission and history caller traced
Disposition: Preserve the working turn/tool components, but migrate them into W12's single typed runtime rather than treating this TUI-specific layer as canonical

Findings:

- The module is operational for TUI provider turns and contains valuable work:
  provider-specific request dispatch, strict tool-argument object parsing,
  policy denial before dispatch, asynchronous TUI approval, pre/post hooks,
  offloading sync tools, structured UI events, usage collection and several
  focused malformed/protocol tests. Legacy reuses only request/history helpers;
  its execution loop remains separate, while ACP/proxy/subagents use still other
  paths. This completes the F-004 call graph.
- Every request builder obtains the full static registry directly. Per-run
  availability, plugin/MCP tools, progressive selection, capability health and
  exact dispatcher reachability are absent (F-005/F-090). Public legacy helpers
  such as `build_openai_request` are test-visible but not used by the live turn
  path, increasing parallel request-shape contracts.
- Responses requests ask for encrypted reasoning but retain neither general
  output items, response IDs nor encrypted continuation; the TUI persists only
  chat-shaped visible/reasoning strings and flattened calls/results (F-002).
  Anthropic history similarly retains no native thinking/redacted/signature
  blocks. Normalizing malformed model arguments to `{}` makes the provider-safe
  projection look like a call the model did not actually make unless the raw
  failed call remains separately authoritative.
- Gemini assistant calls are ignored on request rebuild and tool results become
  ordinary user text, so the operational second tool-loop request is broken
  (F-018/F-019). The `gemini` alias builds native Gemini JSON but `run_turn`
  recognizes only exact lowercase `google` and tries to parse the response as
  SSE; Anthropic accumulator selection has the same exact-string fragility.
- Stream state is not trustworthy (F-096). Chat SSE silently ignores malformed
  JSON. Transport parse errors, timeout, EOF without a terminal event and
  `[DONE]` all break the loop and finalize accumulated content/tool state as
  success. Responses stream transport errors/timeouts do the same. SSE finish
  reasons are always discarded; only Google's non-stream path populates one.
- The advertised one-MiB `enforce_sse_line_cap` defense is never called. Its own
  test explicitly permits a multi-megabyte line if any newline is present, and
  the actual `eventsource` parser owns framing before the helper could inspect a
  buffer. Visible text, reasoning, tool arguments, event count and total stream
  bytes have no aggregate limit. Gemini/error bodies use unbounded `.text()`;
  one Gemini read error becomes an empty body and a misleading parse failure.
- Retry can issue eleven POST attempts with exponential waits exceeding tens of
  minutes, no total run deadline/cancellation, idempotency/cost receipt or
  retry-budget reservation. Numeric `Retry-After` is not capped. Full upstream
  error bodies are unbounded and returned verbatim. A lost response after
  provider acceptance can duplicate charge/generation; mid-stream failures are
  instead presented as partial success (F-021/W10).
- A hard-coded `SAFE_TOOLS` name list bypasses `PermissionManager` entirely for
  read, network search, LSP process startup, memory, task/subagent/control and
  Crosslink operations even though their actual effects and sensitivity vary.
  It diverges from the legacy list and registry risk metadata. Unknown names
  prompt, but known safe-by-name calls have no approval receipt (F-004/W2).
- Executable `PreToolUse` hooks run on raw model arguments before the user
  approves the requested tool. Permission hooks likewise execute before the
  prompt. Thus a model request denied by the user may already have triggered a
  repository/foreign hook side effect (F-086/F-088). Hook/result data and UI/
  ledger copies remain stringly typed and potentially sensitive.
- Tools execute sequentially and synchronously inside non-cancellable
  `spawn_blocking`; every tool unnecessarily holds the shared `TaskManager`
  mutex for its whole execution. There is no batch call/byte/time/cost limit.
  Channel loss returns partial results with `needs_followup=true`, and quality
  gates run after any nonempty batch—including entirely malformed/denied calls—
  while failures remain advisory (F-085).
- The real 25-iteration loop, provider policy projection and final-state writes
  live in `tui/app.rs`, not this module. The loop has no shared token/cost/time/
  retry/tool/subagent budget or stop-condition integration. Exhaustion, policy
  block, final-gate rejection or follow-up error breaks locally, after which the
  outer handler can sync partial history and emit `ResponseDone` without a typed
  terminal reason.
- Tests are extensive but dominated by isolated JSON/helpers, hard-coded model
  literals and source-local channels. The line-cap suite proves only an unwired
  helper. No representative transport trace proves bounded request → partial/
  error classification → permission receipt → tool execution → native provider
  continuation → cancellation/finalization across the supported frontends.

### F-096 — Streaming failures and loop aborts are finalized as successful completion

Severity: Critical
Status: Confirmed in both SSE implementations and the TUI agentic-loop caller

Malformed chat events are ignored, while stream parser errors, five-minute
stalls and premature EOF finalize partial text and possibly partial tool calls
as `Ok(TurnResult)`. The documented SSE size defense is unwired and aggregate
buffers are unlimited. Separately, iteration exhaustion and follow-up failure
are followed by partial-history sync and `ResponseDone`. Users, history, VDD and
later grounding can therefore consume an incomplete generation as an ordinary
finished assistant turn.

The legacy controller repeats this for every provider path. Its advertised
`error_max_turns` result is only a `tracing::error!` record with no canonical
session/frontend event; loops then continue finalization. Initial and follow-up
SSE error/timeout/EOF break normally, several HTTP/parse failures return `None`
or an empty buffer, and the caller can persist or review the remaining state as
though the agent reached a terminal response.

Required outcome: Make the provider transport emit a typed state machine with
terminal success, provider refusal/filter, length, retryable failure, partial
failure, cancelled and protocol-corrupt outcomes. Bound bytes/events/text/
reasoning/tool arguments before allocation; require the negotiated terminal
event and valid closed call structures before tool dispatch. One W10 deadline
and cancellation token must stop/join HTTP and tool work. W12 commits history
and emits frontend completion only after typed finalization; partial output is
visibly recoverable evidence, never a successful assistant message.

### F-095 — The wired OAuth session runtime does not refresh, expire, revoke or protect credentials end to end

Severity: Critical
Status: Confirmed across OAuth store, auth CLI, proxy routes and provider dispatch

The live runtime contradicts its auto-refresh claim: access tokens are refreshed
only during login, expired sessions are returned, generated API keys/auth modes
are ignored, and proxy login can report success after failed persistence. Raw
secrets are Debug/clone/JSON values and raw error bodies reach logs. Pending
browser flows and bearer session IDs lack lifetime, binding and revocation, and
logout cannot invalidate live processes or upstream credentials.

Required outcome: Replace this path as part of W3 with an officially supported,
OpenClaudia-identified provider integration. Centralize credentials in a
redacting/zeroizing, OS-protected capability service with verified account,
audience, scope and expiry; bounded responses/storage; generation-safe
single-flight proactive refresh; rotation/revocation/logout propagation; and
typed stale/relogin states. Browser auth must use an exact registered flow,
expiring client-bound state, server-set hardened cookies and no bearer values in
URLs/JSON/logs. Remove dead auth modes and duplicate stores only after their
intended supported login behavior is replaced and migrated.

### F-090 — MCP dynamic tools are connected or advertised but have no complete execution path

Severity: High
Status: Confirmed across composition roots, provider schema assembly, dispatcher, ACP, TUI and resource handlers

Proxy advertises plugin MCP tools but never dispatches them; TUI connects the
manager but does not advertise dynamic tools; ACP recognizes the prefix but
routes to a registry with no dynamic entry. The two static resource tools are
advertised broadly but depend on a process-global manager installed only in the
TUI path. “Connected” therefore means different partial capabilities in each
frontend, not an operational MCP agent loop.

Required outcome: Preserve MCP by registering validated dynamic tools/resources
in W2/W12's per-run registry. One typed call path owns discovery, progressive
schema activation, current provider conversion, risk classification, consent,
invocation, content validation, trace, follow-up, cancellation and shutdown.
Every frontend gets the same explicit capability matrix and unavailable/partial
states; no schema is sent unless its exact dispatcher and authorized server
generation are live.

### F-091 — MCP is fixed to a retired protocol model and loses current typed semantics

Severity: High
Status: Confirmed against source and official MCP 2026-07-28 specification

The client hard-codes `2024-11-05` initialize/session/server-request behavior.
The current protocol uses stateless self-describing requests, current routing
metadata, discovery, multi-round-trip input, cache metadata and richer typed
tool/resource results. The implementation also ignores legacy pagination/change
notifications and collapses mixed media, resource, annotation, structured and
schema information into raw JSON or text.

Required outcome: Implement a versioned MCP adapter with `2026-07-28` as the
current profile and explicit bounded compatibility profiles for supported older
servers. Preserve typed schema/content/cache/provenance end to end, deterministic
catalogues and MRTR user input. Retire legacy roots/initialize/elicitation
mechanisms only on the official compatibility schedule and with migration tests;
do not delete the intended workspace/input capabilities without replacement.

### F-092 — MCP transport cancellation, resource limits and connection ownership are unsafe

Severity: Critical
Status: Confirmed in HTTP/stdio transports and manager lifecycle

HTTP response bodies are unbounded and public unchecked constructors bypass its
nominal SSRF guard. Stdio calls can run forever by default. The manager holds one
mutex across network/process awaits, timeout cancellation can desynchronize a
still-live stream, and several error/replacement paths drop transports without
close/reap. One stalled or malicious server can exhaust memory, block every
other MCP server, leave orphan processes, or return stale/mis-correlated state.

Required outcome: Give each authorized server generation its own supervised
connection actor, bounded queues/concurrency and W10 cancellation/deadline/byte/
item budgets. Use the hardened W18/W22 network/process brokers with per-hop SSRF
validation and no release-built unchecked bypass. Cancellation follows the
negotiated protocol and always reconciles or replaces transport state; close is
idempotent, reaps children, and manager-wide catalogue operations return typed
partial results without holding global locks over I/O.

### F-093 — OAuth, elicitation, and in-process MCP are schema-only and secret-unsafe

Severity: High (Critical if wired unchanged)
Status: Confirmed by full reads and zero production consumers

The three modules expose plausible APIs and unit tests but no runtime feature.
OAuth secrets/codes/verifiers derive Debug, clone and raw serialization;
security values are caller-supplied and the current discovery/audience/issuer/
refresh contract is absent. Elicitation's handler is bypassed by hard-coded
transport behavior and models a mechanism replaced in the current protocol.
In-process close cannot revoke calls and bypasses the normal lifecycle.

Required outcome: Complete these capabilities through W6 rather than calling
their schemas production-ready. Use non-Debug zeroizing secret references,
current protected-resource/auth-server discovery and issuer/resource binding;
bind MRTR input to an attributed visible user interaction; and register
in-process servers through the identical trust, policy, budget, cancellation,
result and revocation pipeline as external servers.

### F-097 — Project plugin metadata can cross trust scopes and impersonate a trusted installation

Severity: Critical
Status: Confirmed across all plugin discovery, tracking and MCP startup paths

The project-owned `installed_plugins.json` is merged without restricting its
entries to project scope. Each entry may self-declare `User` or `Managed`, name
an arbitrary `install_path`, and is later redistributed into global files by
`save`. Discovery then loads that arbitrary path as enabled code-bearing plugin
state. Automatic scans also import project and foreign `~/.claude/plugins`
directories; name collisions are nondeterministic. MCP trust grants bind only a
mutable `plugin-id/server-name` string, so replacement project content can reuse
a previously trusted identity without matching an approved artifact digest.

Required outcome: Preserve project and user plugins through W26, but make scope
an attribute of the trusted store, never untrusted JSON. Resolve packages from a
host-owned catalogue keyed by canonical workspace, publisher/package/version
and immutable artifact digest. Treat foreign caches as explicit read-only
imports. A project may request only project-scoped activation, and no path,
manifest name or tracker entry may manufacture managed/user scope or inherit a
grant issued to different bytes.

### F-098 — Plugin signature and source policy are nominal, bypassable and not capable of validating normal packages

Severity: Critical
Status: Confirmed in every signature, policy and production install caller

`PluginPolicy.actions` is skipped by Serde and no production composition root
populates trusted keys; the REPL always constructs the permissive default.
Local installs bypass policy, and public base installers remain callable. Path
installs verify the raw manifest including its own inline signature field,
creating a circular signed-byte contract. Structured marketplace installs have
no pre-clone manifest signature and therefore always fail when signatures are
required. Direct-git policy verification happens only after the base installer
has cloned, registered, reloaded and reported the plugin active. No test proves
a valid signed package installation. Allowlisting a mutable URL/ref is also not
artifact verification.

Required outcome: Verify a detached signature/attestation over a canonical
package digest before any registration or activation. Configure trust only from
host-owned policy, bind signer identity and permitted package namespace, support
rotation/revocation/expiry, and make every install/import/update path use the
same fail-closed gate. Follow current artifact-verification practice rather
than inventing an inline self-signing format: Sigstore bundles bind verification
material to an artifact digest, while SLSA provenance records where/how an
artifact was produced ([Sigstore bundle format](https://docs.sigstore.dev/about/bundle/),
[SLSA 1.2 provenance](https://slsa.dev/spec/v1.2/provenance)).

### F-099 — Plugin installation and updates are partial, non-transactional supply-chain mutations

Severity: Critical
Status: Confirmed across git, copy, tracker, marketplace and cache implementations

Git inherits ambient environment/configuration, SSH agents and credential
helpers with no sandbox, timeout, cancellation or output limit. A requested
branch/tag is cloned shallowly without proving the requested ref is an immutable
commit; marketplace pull is not fast-forward-only and activates changed content
without artifact verification or renewed capability consent. Recursive copy has
stat/canonicalize/use races, accepts uncontrolled tree size/types and writes the
live destination incrementally. Registration failures are logged while install
still succeeds. Tracker writes have predictable non-exclusive temporary names,
a symlink/permission window, no interprocess lock or parent fsync, and global
plus project files are not one transaction. The unused ZIP cache similarly
claims atomicity while publishing archive and index as ordinary separate writes,
and accepts unvalidated path-like hashes.

Required outcome: W26 stages bounded content through W18/W15, resolves and
records an immutable commit/digest, verifies source/signature/provenance, scans
the exact capability manifest, and atomically activates package plus catalogue
generation only after consent. Failures roll back or expose an explicit
recoverable staged state. Updates must detect rollback/freeze/mix-and-match,
re-check revocation and require renewed consent for capability or publisher
changes, following an established update framework rather than mutable `git
pull` ([TUF security model](https://theupdateframework.io/docs/security/)).

### F-100 — Most advertised plugin capabilities are disconnected, while the working command path loses provenance

Severity: High
Status: Confirmed by full plugin read and source-wide consumer search

REPL plugin commands work by replacing the slash input with manifest/Markdown
text and applying plugin-declared model/allowed-tool metadata, but the next run
does not retain a typed package identity or capability receipt. Proxy exposes
only command names as system context. Plugin hooks have no production consumer;
agents, skills and LSP registrations are stored but never consumed; enable/
disable is process-local and disappears on reload. Plugin MCP is connected only
in proxy/TUI under string grants and is already subject to F-090's incomplete
schema/dispatch split. NPM/Pip sources and ZIP extraction are declared shapes
without implementations. Validation and UI counts therefore make a package
look substantially more operational than it is.

Required outcome: Preserve commands, hooks, agents, skills, LSP, MCP, offline
packages and supported registries as explicit W26 completion commitments. Each
capability receives a truthful support state and joins the same W2/W12 registry,
provenance, approval, budget, cancellation, trace and revocation lifecycle in
every supported frontend. Persist enablement and terminate active resources on
disable/revoke. Do not advertise source kinds or components until their real
end-to-end acceptance matrix passes.

### F-101 — Plugin discovery and parsing are unbounded and still follow several attacker-controlled links

Severity: High
Status: Confirmed across manifests, convention discovery and resolved component reads

Manifests, marketplaces, commands, hooks, MCP maps, environment/header values,
directory entries and recursive package trees have no aggregate size/count/
depth limits. Search and marketplace discovery use `is_dir`, so symlinked
directories are followed. Convention-discovered command Markdown can itself be
a symlink and is later read with ordinary `read_to_string`; marketplace
manifests are also ordinary reads. Several schemas accept unknown fields and
malformed optional components are warned and silently skipped, allowing a
package to be reported loaded with only part of its declared behavior. Unicode/
case-normalized identity and deterministic collision policy are absent.

Required outcome: Discovery reads bounded metadata without executing or
activating it, uses descriptor-relative no-follow traversal and exact versioned
schemas, normalizes identities and rejects collisions deterministically. A
declared component that is invalid or unsupported prevents atomic activation
with a visible diagnostic. Package file/count/depth/expanded-byte and metadata
limits are checked before allocation/copy, then enforced again at runtime.

### F-102 — Web validation is not the network connection boundary, and Chromium bypasses it for page activity

Severity: Critical
Status: Confirmed in direct HTTP, redirect and default browser paths

The initial hostname is resolved and checked, then reqwest or Chromium resolves
and dials it independently; an attacker can change DNS between those operations.
Redirect hostnames receive only scheme/name/literal checks because the callback
cannot perform DNS. The Chromium fallback validates the top-level URL once but
does not mediate redirects, frames, page JavaScript, subresources, fetch/XHR,
WebSockets, workers or downloads. A public page can therefore cause the browser
to contact loopback, private, link-local or metadata services despite the tool's
SSRF claim. Proxy behavior and the eventual connected peer are not verified or
recorded.

Required outcome: Preserve web/browser access through W23's egress broker. The
broker resolves, classifies and pins the actual dial address; re-evaluates every
redirect and proxy hop; applies origin/credential rules; and emits a typed
receipt for the connected peer. Chromium request interception must cover every
navigation and subresource channel, deny private-network/file/local schemes and
downloads by default, and make exact internal access an explicit host-granted
capability. Tests must control DNS answers across validation/dial and run hostile
pages that attempt each browser channel.

### F-103 — Default browser execution has persistent-project trust and unbounded descendant resource exposure

Severity: High
Status: Confirmed in browser launch, search and fetch lifecycle

The default feature may auto-download Chromium at first use and launches a new
browser for each operation with a persistent profile inside the current
project. Repository-controlled paths/symlinks can influence that profile; state
and cookies can cross calls, while concurrent launches contend for it. Hostile
JavaScript executes before the full DOM is allocated and only then compared to
the 10 MiB cap, leaving page resources, DOM growth, CPU, memory, children and
browser lifetime effectively unbounded. Timeout wrappers report completion
without stopping this work (F-059), and URLs with sensitive query data enter
logs/errors.

Required outcome: W23 uses a host-installed/pinned browser identity, ephemeral
private per-run profiles outside project control, no ambient cookies/credentials,
an explicit persistence grant when state is desired, and a supervised reusable
pool with tab/process/CPU/memory/network/DOM/download/time budgets. Cancellation
must close tabs and reap descendants. Results remain typed untrusted evidence
with source/redirect/truncation/freshness metadata; sensitive URLs and page data
are redacted from logs and traces.

### F-104 — Speculation is an unwired no-op whose contract cannot implement its documented lifecycle

Severity: High
Status: Confirmed by full module read and zero-consumer source search

The module explicitly ships only `NoOpSpeculationEngine`; `enabled=true` still
returns it. Contrary to its module and hook documentation, neither pipeline nor
any production composition root constructs the engine, configuration is absent
from `AppConfig`, and no caller invokes `after_turn`. The trait has prediction,
feedback and a Boolean pending probe, but no capability/snapshot identity,
execution handle, result retrieval, exact match, promotion/discard,
cancellation, deadline or shutdown operation, so the promised later phases
cannot be safely added behind this contract.

Even as a metric seam, `after_turn` predicts after the actual turn and compares
that new prediction with the same turn's tool names rather than retaining the
previous prediction. Tool calls with no prediction are mislabeled
`NoToolCall`; arguments are never compared despite hit/partial-miss claims;
only the first tool is summarized; `pending_tool_names` is always empty; and
confidence/config/input sizes are not validated. The 256-byte prefix can exceed
256 for a multibyte character beginning near the boundary.

Required outcome: Preserve the intended latency experiment through W7, but
replace this Phase-1-shaped API with an owned typed speculation transaction
before any action can run. It must bind run/tool/typed args, immutable workspace
snapshot and policy/budget generations; restrict candidates to proven
side-effect-free deterministic operations in an isolated overlay; reserve
resources; return a cancellable handle; and validate exact result reuse or
discard. Establish a non-speculative baseline and adversarial eval first. If no
safe implementation shows net task/latency benefit after wasted work and risk,
remove the speculative optimization while retaining the measured latency goal.

### F-105 — The “canonical” command system is multiple manual catalogues and side-effecting dispatch paths

Severity: High
Status: Structural split confirmed; individual command semantics remain under file audit

`src/slash_commands.rs` is two manually maintained display tables, not an
executable registry. The legacy `CommandRegistry` separately lists handlers and
aliases; the TUI keeps its own dispatcher; plugin commands explicitly bypass
the catalogue. Descriptions, invocation syntax, aliases, availability and
actual dispatch can therefore drift while README tests continue to pass. The
registry silently overwrites duplicate names/aliases and has no construction-
time collision or catalogue parity check.

Handlers expose only `name`, aliases and a synchronous `handle`. They carry no
typed arguments, effect/risk, required capability, frontend support, cancellation,
help metadata or trace contract. Several perform I/O/process/auth/state effects
and print directly during parsing instead of returning a proposed typed action
for the canonical policy/execution path. The context is only raw messages plus
provider/model strings, forcing ambient CWD/environment/global state. `/logout`
does not revoke an OpenClaudia session; it tells the user to manually delete the
foreign Claude Code credential file implicated in F-080.

Required outcome: W12 owns one typed command descriptor/handler registry whose
metadata generates parsing, completion, help and documentation for supported
frontends. Construction rejects duplicate canonical names/aliases and invalid
availability atomically. Parsing is pure and returns a typed proposed action;
W2/W12 applies capabilities, approval, budget, cancellation, state transaction
and trace before rendering a result. Plugin/skill commands join a namespaced
dynamic generation rather than bypassing the registry. Authentication commands
call the supported W3 credential lifecycle and never instruct deletion of
another application's store.

### F-106 — Tool output can forge terminal UI structure, crash diff parsing and emit raw control sequences

Severity: High
Status: Confirmed in legacy tool-result and diff rendering

`display_tool_result` discovers an edit diff by searching arbitrary result text
for magic markers, then parses attacker/model-controlled JSON without binding it
to an edit handler or successful typed result. If `@@DIFF_END@@` appears before
`@@DIFF_START@@`, the resulting reversed string slice panics. Valid forged
blocks can trigger an unbounded full-text diff whose time/memory cost is paid
before line display caps. Error/normal formatting first collects every line,
and all paths/content are printed without escaping terminal control characters,
allowing ANSI/OSC spoofing or terminal side effects. Nearly every terminal I/O
error is discarded.

Required outcome: W2 returns typed edit/result structures and W12 renders only
the variant created by the trusted dispatcher—ordinary text is never reparsed
as UI control data. Enforce input/diff/display byte, line and compute budgets
before allocation; use a bounded diff algorithm or explicit truncation; sanitize
or visibly encode terminal controls and paths; propagate typed renderer failure
where it affects interaction state. Add hostile marker ordering, huge-line/diff,
ANSI/OSC, Unicode and closed-terminal tests.

### F-107 — Project initialization can destroy existing state and scaffolds deprecated/unsafe authority paths

Severity: Critical
Status: Confirmed in both CLI and slash-command initialization paths

`cmd_init --force` deletes the existing config before the replacement is safely
prepared, so a later directory/file write failure loses the original. Even
without `--force`, if `.openclaudia` exists without `config.yaml`, ordinary
`fs::write` silently overwrites an existing `hooks/session-start.py` and
`rules/global.md`. The multi-file initialization is not a transaction, does not
reject parent-directory symlinks, provides no backup/recovery state and may
leave a partially initialized project while reporting only the first error.

The command actively creates the deprecated rule-injector directory/content.
The separate REPL `/init` does not initialize configuration at all: it detects
file names and generates generic rule text into `rules/project.md`, despite the
shared help claim. The default config also scaffolds a project-controlled
executable Python hook whose output requests `systemMessage` authority, and
documents guardrail actions/quality semantics already proven unwired or
advisory. Initialization therefore manufactures unsafe/misleading state rather
than merely documenting an optional example.

Required outcome: Preserve project setup as a W14/W15 transactional scaffold.
Build and validate a complete versioned configuration in a private same-
filesystem staging directory, inventory every existing destination, refuse
collisions by default, and on explicit force show scope and create recoverable
backups before atomic generation publication. Use descriptor-relative no-follow
writes, restrictive modes, fsync/reconciliation and exact partial-publication
reporting. W1 removes all rule directories/templates/generators. W25 examples
are inert documentation or explicit opt-in installations; initialization never
activates executable/instruction hooks. Generate defaults from the same typed
schema/capability matrix and test that every documented option is implemented.

### F-108 — `doctor` performs secret-bearing mutations/probes while reporting synthetic checks as runtime health

Severity: Critical
Status: Confirmed in full diagnostic entrypoint and its called subsystem behavior

The command sends a real GET with resolved authorization plus arbitrary custom
headers to the configured provider endpoint. Project configuration can select a
custom base URL; the probe has no trusted-origin/SSRF/egress capability and
default redirects can forward nonstandard secret headers. Nearly every status
other than 401/403/404/5xx—including 400, 405 and 429—is called reachable, so
this credential disclosure is not even a valid inference readiness test.
Loading Claude credentials can refresh and rewrite the foreign store, and
plugin tracker loading can rename corrupt state, making a nominal diagnostic
mutating.

Other checks instantiate empty/test objects or inspect declarations: a fresh
MCP manager is always asked about literal `test-server`; provider health is a
local fabricated JSON transform; plugin MCP output prints an asserted sandbox/
trust profile without connecting it; hook/rule directories are treated as
health; plugins are “OK” when parsing succeeds even though components are
partial. It also logs derived plugin script paths. These results can reassure an
operator about paths the real runtime has not executed.

Required outcome: Make W0/W13 diagnostics read-only and evidence-based by
default. Each check declares whether it reads, mutates, uses credentials,
contacts a network, starts a process or incurs cost; active probes require an
explicit scoped capability and use W22/W23 trusted-origin, redirect, secret and
deadline controls. Use provider-supported lightweight auth/model capability
endpoints where available, never arbitrary GET against an inference URL. Probe
the actual configured composition root or label a check static/unavailable;
return typed per-check pass/fail/degraded/skipped with evidence generation and
an honest nonzero aggregate result. Add canary-secret/custom-origin/redirect,
no-mutation, offline and parity tests.

### F-109 — Print mode is a fourth direct provider path with no bounded terminal or run-state contract

Severity: High
Status: Confirmed in full one-shot frontend read

Print mode builds, authenticates and sends a provider request itself rather than
using the canonical pipeline/runtime. It deliberately has no tools, but it also
omits canonical context, hooks, memory, session/trace, usage/cost accounting,
cancellation and finalization. Its policy check supplies zero accumulated usage
and reserves nothing. The HTTP client has no request/stream deadline; JSON,
error bodies and individual/aggregate SSE events are unbounded. Accumulators
still collect ignored tool/reasoning state.

SSE text is written to stdout before the operation is known to be complete. EOF
after any text succeeds without requiring `[DONE]` or a provider terminal event;
later malformed/protocol errors return failure only after partial text has
already entered pipelines/files. JSON extraction likewise loses provider-native
terminal/usage/refusal semantics. Provider selection, endpoint/header assembly,
OAuth identity injection and response handling therefore remain another
divergent behavior surface under F-004/F-096.

Required outcome: Preserve noninteractive one-shot use as a thin W12 frontend
requesting an explicit no-tools/no-persistence capability profile. Use W3's
lossless provider adapter plus W10 deadlines, byte/event/token/cost reservations,
cancellation, trace and typed terminal states. Buffer or frame stdout so scripts
can distinguish committed success, partial failure/refusal/length/cancel and
diagnostics; an explicit low-latency raw-stream option must still emit a
machine-readable terminal status and nonzero failure without calling EOF
success. Add pipe/backpressure/closed-stdout, stalled/oversized/malformed stream,
partial output, refusal/length, usage and all-provider fixtures.

### F-110 — CLI Git review/commit bypasses capabilities and can stage a different, unreviewed generation

Severity: Critical
Status: Confirmed across the shared commit pipeline, review helpers, and push/PR continuation

The “interactive” stage prompt shows only the literal text `(see git diff
--stat)`, then `git add -A` stages every current change. Automatic commit/PR
stages everything without a preview. Status, approval, staging, file listing and
commit are separate racy subprocesses with no repository/index/worktree
generation precondition; concurrent or hook changes can enter the commit after
the user's decision. Staging errors are discarded and an empty later list is
reported `NothingToCommit`; cancellation after staging leaves the index mutated.
Untracked-only repositories are misclassified clean before staging because
`git diff --stat` excludes them.

Git is resolved from mutable PATH on first use and every subprocess inherits
ambient Git config, environment, signing agents and credentials. Commit hooks,
filters, textconv/external diff, fsmonitor and related helpers may execute
outside the agent sandbox. Review is therefore not reliably read-only. No call
has a deadline/cancellation/output budget; `.output()` buffers full status,
diff, log and error data before display truncation, paths use lossy newline
parsing rather than `-z`, and raw repository text reaches the terminal.

Required outcome: Preserve review/commit/push/PR through W2/W18/W24 as distinct
typed effects. Build a bounded exact snapshot/diff, let the user approve the
specific paths/content and destination, then stage only those paths in a
run-owned index/workspace under expected HEAD/index/worktree generations.
Disable untrusted hooks/helpers/config or grant each explicitly; use a pinned
Git identity, minimal environment, bounded NUL-safe output, cancellation and
typed partial states. Return and verify the new commit SHA before any push; a
failure never hides index mutation or advances to publication.

### F-111 — Interactive API-key setup echoes secrets and may write them into the repository unsafely

Severity: Critical
Status: Confirmed in legacy `/connect` configuration path

The prompt reads an API key with normal echoed `stdin`. If no home directory is
resolved, it silently falls back to `.openclaudia/config.yaml`, placing the
secret in repository-controlled state. It reads and rewrites the full YAML via
generic `serde_yaml`, then uses ordinary `fs::write`: symlinks are followed,
creation mode is not restricted, the old file is truncated in place, disk/full
or interruption can destroy it, and comments/formatting are lost. The key lives
in ordinary `String`/YAML values and the provider list is another manual subset.

Required outcome: W3 owns masked/secure secret entry and stores a redacting,
zeroizing credential in an OS keyring or host-owned restrictive secret store;
configuration contains only a secret reference. Missing home/keyring is a
visible unavailable state, never project fallback. W14/W15 update typed config
transactionally with no-follow/durability/backups and preserve unrelated data.
Provider choices come from the live registry. Add terminal-echo, process/log/
panic redaction, symlink, permissions, disk-full, comment-preservation,
concurrency and no-home tests.

### F-112 — The legacy direct-shell escape is a second unsandboxed permission system

Severity: Critical
Status: Confirmed in implementation and live REPL caller

Lines beginning with `!` reach a standalone shell executor, not the canonical
tool permission/sandbox pipeline. A case-sensitive substring list decides
whether to prompt; ordinary commands run automatically with full ambient CWD,
environment, network, credentials and host process privileges. Trivial casing,
spacing, variables, aliases, alternate utilities/interpreters or encoded
commands bypass the destructive patterns. The public internal executor bypasses
even that prompt.

The shell binary is resolved from current PATH on every call. Execution has no
deadline, cancellation, output/memory/process/descendant limit or cleanup and
buffers stdout/stderr to completion before printing/storing duplicate strings.
Raw output/control sequences reach the terminal. “Always” decisions are
process-local exact raw strings with no actor/workspace/executable/resource/
generation/expiry receipt. Startup tips nevertheless promise dangerous shell
commands will prompt, which is false for unrecognized danger.

Required outcome: Preserve explicit user shell convenience through W18 as a
distinct user-originated typed action, but always apply hard host capabilities,
workspace/network/secret boundaries, process supervision and audit. Risk comes
from parsed/resolved executable/effects and policy, never substring absence.
Approval binds exact normalized argv/shell mode, cwd, environment grants,
resources and generation; direct shell syntax cannot call a public unchecked
executor. Stream bounded sanitized output with cancellation/kill/reap and test
obfuscation, interpreters, aliases, child processes, output bombs and frontend
parity.

### F-113 — Legacy file attachment and editor input bypass run capabilities and aggregate context budgets

Severity: High
Status: Confirmed in implementation and live legacy REPL callers

`@file` expansion reads through ambient process CWD and ordinary filesystem
APIs rather than the run's file capability. It reads each complete UTF-8 file
without per-file, aggregate-byte, file-count or token limits and immediately
splices repository text into the user message using forgeable XML-like tags.
The lexical parent check and canonical-prefix check do not supply sensitivity,
snapshot, provenance or explicit partial-result semantics. Repeated global
string replacement can also treat matching text introduced by an earlier
expansion as another replacement target.

External composition and plan editing directly launch the host-selected editor
with ambient environment/process authority, no deadline/cancellation/resource
bounds or run ownership. Temporary-file creation/permissions are delegated to
the editor; several error paths leave the file behind. Interactive questions
block directly on global stdin, use question text as the answer-map identity
(so duplicates overwrite), and convert malformed/out-of-range input or EOF into
plausible answer strings rather than typed cancellation/validation states.

Required outcome: Preserve attachments, external editing and structured user
questions through W12/W15/W18. Attachments are explicit bounded snapshots with
source identity, sensitivity, encoding, truncation and token cost; their
contents remain untrusted evidence. Editors receive only a capability-bound
temporary descriptor/resource under a supervised user-process profile, with
cleanup/recovery. Questions use stable IDs, schema-validated typed answers,
frontend-agnostic async delivery, cancellation and replay-safe call binding.

### F-114 — Plan approval does not bind the reviewed bytes, state transition and granted authority atomically

Severity: Critical
Status: Confirmed across the legacy plan-mode implementation and prior session/tool reads

Entry creates or writes a Markdown path before the pinned identity is accepted,
does not require the canonical plans directory to remain inside the authorized
workspace, and sanitizes distinct session IDs into potentially colliding names.
The external editor can replace the file after identity pinning; approval then
uses an ordinary path read without checking the pinned descriptor, digest or
generation. Mode, plan state, approved content and the synthetic system message
are published through separate mutations, so failure/concurrency can expose
partially transitioned authority.

The approved repository/model-derived Markdown is promoted to a system message.
Model-returned `allowedPrompts` prose is parsed from the same ordinary result
payload and displayed as though approval restored a coherent capability set,
while the actual gate remains a static tool-name list with known mutators. The
generic marker parser still lets arbitrary result text request plan/user-input
control transitions (F-032/F-064).

Required outcome: Preserve interactive planning through W17 as a typed proposal
and explicit user approval receipt bound to exact plan resource generation,
digest, actor, run and requested capability effects. Re-read/verify the same
snapshot at approval; publish the plan transition and scoped capabilities as
one monotonic state transaction. Keep plan text source-labeled evidence rather
than system authority, and never derive approval or grants from model/tool text.

### F-115 — Vim editing works through Rustyline, but a second incomplete state machine fabricates its status

Severity: Medium
Status: Confirmed by full file read and source-wide consumer search

The user-visible toggle does install Rustyline's operational Vi edit mode, so
the feature itself is not stale and must be preserved. In parallel, the code
ships a sizeable separate tested `VimState` parser which is not connected to
Rustyline's key or buffer events. Production only sends it synthetic
`Escape`/`i` transitions after a complete line has already been submitted and
uses it to print a status label; `describe_action(None)` and field reads merely
keep the duplicate surface referenced. The displayed state is therefore not
the actual editor state. Inside that unused parser, find and replace are TODO
no-ops, count-prefixed delete-char does not repeat, and no action has a buffer
adapter.

Required outcome: Preserve the working Rustyline Vi mode. Choose one real
editor/event implementation: integrate missing shared commands/status through
Rustyline's actual APIs, or replace it only after a complete Unicode/grapheme-
safe buffer adapter has parity. Remove the disconnected shadow parser after
that consolidation, not the user feature. Test real keys, displayed mode,
configured chord conflicts, submission, cancellation and history end to end.

### F-116 — “Private” notes and side questions corrupt source authority and conversation state

Severity: High
Status: Confirmed in the complete legacy REPL controller read

The `# note` path says the note is “not sent to AI,” but stores it as a system
message. The next request includes the message directly and also gathers all
non-persona system messages as prompt instructions, so a supposedly private
note is sent and promoted above user authority. This is a privacy and behavior
contract violation, not merely a label issue.

The `/btw` aside path snapshots history, replaces the conversation with the
aside, immediately appends the saved history behind it, then falls through so
normal preparation can append the slash input again. It never restores the
prior canonical ordering after a separate bounded aside run, despite printing
that the main flow will be restored. Provider continuations, undo, titles,
memory/learning and later compaction can all observe the corrupted sequence.

Required outcome: Preserve both workflows as typed W12 operations. Notes are a
separate user-owned annotation store with an explicit “include in model
context” choice and user-level source when included. Side questions execute as
a bounded child request over a cited parent snapshot; their result is attached
without mutating/reordering the parent transcript or learning/memory state
unless the user explicitly promotes it. Add privacy and exact history-before/
after end-to-end tests.

### F-117 — Branch snapshots are an untrusted project file that can replace the canonical transcript

Severity: Critical
Status: Confirmed in branch/teleport implementation and live caller

`/branch` serializes the full generic message vector into
`.openclaudia/branches/<name>.json` using check-then-write ordinary filesystem
operations. Parent/file symlinks are followed, collision checking races,
publication is non-atomic, permissions/durability are unspecified, and message
count/bytes are unbounded. `/teleport` performs an unbounded ordinary read and
only checks that `messages` is an array; it accepts arbitrary roles, system
instructions, tool calls/results and malformed causal order from a
repository-controlled file, then replaces the live transcript and persists it
as canonical session state.

Required outcome: Preserve branching/teleport as a W12 snapshot operation over
the typed event log. A branch record carries schema, session/run, parent
generation, event IDs, capability/workspace generation, digest and provenance;
W15 stores it in host-owned or explicitly shared capability-safe storage with
bounded transactional publication. Project files can be explicitly imported
only as untrusted data after full schema/causal validation and user review; they
cannot manufacture system/tool authority. Teleport is an atomic versioned
transition with recovery and exact before/after tests.

### F-118 — Provider reasoning is flattened into plaintext transcript fields and exposed as raw “thinking”

Severity: High
Status: Confirmed in legacy streaming/persistence/`/thinkback`, ACP streaming, and both TUI render paths

OpenAI-compatible reasoning deltas are accumulated into a generic
`reasoning_content` string, persisted with assistant messages in the ordinary
session JSON, and printed verbatim by `/thinkback`. The representation does not
distinguish a provider-sanctioned user summary, opaque/encrypted continuation
state, raw chain of thought, or a security-monitoring signal. It has no consent,
sensitivity label, encryption, retention/deletion rule or redaction, and generic
provider conversion can replay it outside the protocol that produced it.
ACP separately forwards every Anthropic `thinking_delta` verbatim to the client
as a `thinking` session update, without negotiating whether the provider permits
disclosure or applying a sensitivity, access, retention or redaction policy.
The full-screen TUI accumulates every reasoning delta without a byte/token cap
and renders it verbatim while live, then the turn loop persists the same generic
`reasoning_content` field in normal session JSON. The legacy streaming renderer
also prints those chunks directly to the terminal. Finishing the full-screen
widget merely clears its display buffer; it does not repair the persisted
privacy/protocol ambiguity.

Current reasoning-agent guidance makes both sides important: provider-native
reasoning state may be required for correct continuation and research supports
carefully controlled chain-of-thought monitoring, while raw chain of thought is
not generally a user-facing transcript. Required outcome: preserve all useful
objectives through separate typed views—opaque provider continuation, explicit
user-visible reasoning summaries, and tightly scoped privacy-protected security
monitoring. Never label or reveal a generic raw field as model thinking. Define
consent, access, encryption, retention/deletion, redacted tracing and provider-
specific round-trip tests.

### F-119 — The user-facing `/plan` command changes a label without enabling plan-mode restrictions

Severity: Critical
Status: Confirmed across command registry, slash handler, REPL dispatcher and plan gate

`/plan`, including any ignored arguments, returns `ToggleMode`. The live
dispatcher calls only `Session::toggle_mode`; it does not create
`conversation.plan_mode`, pin a plan resource or invoke the entry transition.
The actual gate immediately allows every tool unless that separate state is
present and active. The prompt/UI can therefore say “Plan” while Bash, writes
and all other tools remain unrestricted by plan mode. Unit tests explicitly pin
the toggle/ignored-argument behavior rather than executing a mutating tool
through the public command.

Required outcome: Preserve `/plan` and model-requested planning, but route every
entrypoint through the same W17 typed transition and exact state/capability
generation. A mode label is derived from that state, never set independently.
Add end-to-end tests proving `/plan` denies each mutating effect, permits only
declared read effects and the version-bound plan write, and exits only with an
explicit user approval receipt. Reject/implement arguments honestly rather than
silently ignoring them.

### F-120 — The coordinator product surface is a prompt profile over an unused, non-executable Phase-1 model

Severity: High
Status: Confirmed across all nine coordinator files and every production consumer

The formal `Coordinator` owns a queue, teammate map and permission bridge, but
`dispatch()` always returns `NotImplemented`; no production code constructs or
calls it. `--coordinator` instead prepends a coordinator system prompt to the
legacy REPL. Its underlying task tool explicitly rejects the Coordinator agent
type, so the formal dependency queue, teammate lifecycle, permission
serialization, colors and wrapper tasks do not govern the prompt-driven
delegation that can occur.

The nine files are honest scaffolding but cannot satisfy the promised runtime:
the permission queue has no call/correlation ID, reply path, in-flight state,
cancellation or bound; its raw-string “always” cache lacks policy/workspace/
resource generation and expiry. The task queue has no blocked-on-failed,
cancellation, retry, lease or result-provenance state. Token consumption is a
manually called `u32` counter with no execution owner. Unknown background-shell
IDs stay “Running” forever. Free-form prompts/results/reasons/commands are
unbounded and several derive `Debug`. Although comments say the registry can be
persisted, the central `Coordinator`, `TaskQueue`, `Task`, `TaskState`,
`Teammate` and `TeammateState` are not serializable. These types also introduce
another task truth beside todo/task/Crosslink/subagent state.

Required outcome: Preserve real multi-agent coordination through W8, merging
the useful dependency/lifecycle intent into W20's one task graph and W12's run
executor. The coordinator is a supervised run actor with typed child handles,
immutable assignments/snapshots, atomic claim/lease/result transitions,
dependency failure/cancellation propagation and bounded joins. Every child uses
W2 permission receipts and W10 reservations; a single user-interaction broker
correlates requests without inventing another policy cache. Persist exact
versioned state or make it explicitly process-local—never claim resumability
from serializable leaf wrappers. Evaluate parallel delegation against a
single-agent baseline before enabling it by default.

### F-121 — The XML fallback turns ordinary model prose into an executable control plane

Severity: Critical
Status: Confirmed in complete interceptor and live legacy Anthropic fallback reads

When native structured `tool_use` is absent, arbitrary assistant text containing
`<invoke>` or one of nine shorthand tags becomes a local tool call. The parser
also deletes every marker-shaped `function_results` region as “hallucinated,”
so legitimate model/user-derived text can disappear. It extracts and executes
all complete calls in a 4 MiB buffer before another model turn, with no
aggregate call/count/result/time budget; thousands of small calls can fit.
Truncation merely drops bytes and does not invalidate the generation.

The hand-written pseudo-XML parser is ambiguous rather than schema-validating:
duplicate aliases such as `path` plus `file_path` collapse in randomized
`HashMap` iteration order, unknown tool/parameter names pass through, malformed
or capped nested input becomes a synthetic ordinary parameter, and tag-like
file/command content can terminate fields. Tool results are wrapped back into
another XML-shaped user message ending in a forgeable `system_note`. This path
also has different hooks/audit/learning behavior from structured tools and
prints unsanitized result previews. Buffer/attribute/depth caps are useful
defense in depth but cannot turn free-form text into a trustworthy protocol.

Required outcome: Native typed provider tool calls are the W12 control plane.
For a provider that genuinely cannot support them during migration, expose an
explicit compatibility profile with a strict real parser/schema, allowlisted
typed operations, one-call-at-a-time semantics, complete-generation binding,
aggregate W10 budgets and the identical W2 lifecycle; clearly label it reduced
assurance. Ordinary content and tool output are never scanned for commands or
deleted by marker text. Retire this pseudo-XML execution mechanism after
provider/frontend parity fixtures pass—this is removal of an unsafe control
design, not removal of local tools.

### F-122 — Live subagent delegation has advisory isolation, broken resume semantics, and lossy supervision

Severity: Critical
Status: Confirmed in all 4,644 lines of `src/subagent.rs` and its production dispatch callers

The `task`, `agent_output`, and `task_stop` tools do launch, observe, and abort
background workers, so delegation is an intended live feature. However,
`isolation: "worktree"` creates a worktree and adds its path to a system
message; it never rebinds the child tool executor's security context, working
directory, file capabilities, or shell profile. Correct isolation therefore
depends on the model remembering to prepend the advertised path. The Explore
profile is likewise described as read-only while being given unrestricted
`bash` within the ambient process capability; its typed decision proves cited
intent, not a read-only effect set.

Cleanup can destroy valid child work. `has_changes()` runs only
`git diff --stat`, treats inspection errors as clean, and therefore misses
untracked files, staged-only changes, and commits. A “clean” result triggers
forced worktree removal followed by forced branch deletion; a child that
commits its work can have that commit made unreachable instead of returned for
review. Normal completion/failure also does not own and drain all descendant
shells; only explicit `task_stop` attempts shell cleanup.

The advertised resume/prompt-cache continuity is not implemented end to end.
Every terminal assistant response is omitted from the stored transcript.
Storage is process-memory-only with a 30-minute TTL, 50-record/500-message caps
but no byte/token cap; head truncation can remove the system/task context or
split tool-call/result causality. The previous agent type is loaded and ignored,
so the caller can resume a read-only transcript under a mutation-capable tool
set/model while retaining the old system prompt. More immediately, reattaching
to an existing finished manager entry is deliberately a no-op, so the run loop
sees `finished=true` and rejects the resumed turn until another path happens to
remove the entry. Tests pin the component-level no-op and hand-built transcript
round trips rather than the public finish-then-resume behavior. Eight-character
IDs also provide only 32 bits of collision space and collisions silently attach
new work to the existing entry.

Supervision is otherwise fragmented: limits are fixed at 50 turns and 8,192
output tokens per request with no aggregate token/cost/time/tool/concurrency
reservation; request/task/result/transcript bytes are not globally bounded;
provider and tool activity uses another bespoke loop; synchronous dispatch can
fail solely because it was invoked on a current-thread runtime; and
`agent_output(block=true)` still sleeps on that runtime's only worker. The
transcript sweeper consumes its one-shot initializer even when first called
without a runtime and has no owned shutdown handle. Tool schemas come from the
static core list and child execution passes no application configuration, so
the implementation cannot safely grow into nested/capability-aware delegation
through this loop.

Required outcome: Preserve and complete subagents through W8. A child is a W12
run with a collision-resistant typed ID, immutable parent/task/role/model/
workspace/capability generations, W2 least-authority effect set, and W10 atomic
budget reservation. Worktree mode binds every filesystem/process operation to
an owned descriptor/cwd and publishes a typed artifact/commit result; dirty,
staged, untracked, committed, unknown, or inspection-failed states are never
discarded. Resume loads one durable causally valid checkpoint including the
terminal response, requires an authorized monotonic capability transition, and
atomically creates a fresh attempt/lease rather than reusing terminal flags.
Cancellation owns and joins model, tool, shell, worktree and sweeper children;
all terminal paths reconcile them. Add public-path tests for finish/resume,
role-escalation denial, tool-pair compaction, collision handling, crash/restart,
cancel during provider/tool work, and preservation of staged/untracked/committed
work.

### F-123 — ACP session IDs do not isolate transcript, authority, configuration, or cancellation

Severity: Critical
Status: Confirmed in all 4,950 lines of `src/acp.rs` and its session/runtime callers

The stdio server advertises `session/new`, `session/load`, per-session prompt,
mode, config and cancel operations, but one `AcpServer` owns a single
`messages` vector, `SessionManager` current session, model, mode source, IDE
snapshot, config map and cancellation flag. `session/new` calls
`get_or_create_session`, so subsequent “new” sessions reuse the current
OpenClaudia session while clearing the shared transcript. Switching/loading a
mapping never restores a corresponding transcript, model, IDE state, config or
budget snapshot. Evicting one of the 64 mappings does not reconcile the active
state it names.

`session/prompt` accepts any nonempty ID; an unknown value falls back to using
the attacker/client-chosen string as the OpenClaudia security/ledger identity
while continuing with whichever global transcript is active. It does not
require the ID to be mapped or activate the mapped persisted session.
`session/set_mode` does not identify a session, the v1 config handler checks
only that `sessionId` is a string rather than that it exists/currently owns the
state, and `session/cancel` ignores its parameters and cancels the one global
flag. Tool execution receives the text ID for some policy/ledger bucketing but
never installs a matching explicit `RunContext`; filesystem and process
authority can therefore fall back to the ambient default context. Tests prove
component parsing and the map's LRU cap, not two interleaved sessions with
distinct state/capabilities.

Required outcome: Preserve ACP as a W12 transport over canonical run/session
handles. Every request resolves a known typed session and exact generation or
fails; each transcript, provider continuation, model, mode, IDE data, config,
budget, cancellation token, workspace and capability belongs to that handle.
`session/new` always creates an independent record; load restores that exact
record without a blank-child substitution; eviction drops only a transport
cache. Bind request/cancel/config/update IDs to the active call and authorize
client/session ownership. Add adversarial interleaving tests proving no
cross-session messages, tools, cancellation, modes, IDE data, usage or ledger
identity can leak.

### F-124 — ACP accepts unbounded partial protocol data as normal agent output

Severity: Critical
Status: Confirmed in the complete ACP stdio, HTTP/SSE, tool and shutdown paths

Stdin is read with unbounded `BufRead::lines` into an unbounded channel; stdout
uses another unbounded channel, and writer failure is ignored by producers.
Prompts/history, client IDE paths and diagnostic collections, provider error
bodies, SSE lines/buffer, accumulated visible content, tool-call count/index/
arguments and emitted updates lack aggregate byte/event/token limits. Prompt
rendering caps only selected IDE fields after unbounded state has already been
accepted, with nondeterministic `HashMap` diagnostic selection.

Provider HTTP clients have no total/connect/idle deadline. Malformed SSE JSON is
silently skipped and EOF without a provider terminal event calls
`finish_acp_stream`, so truncated text or tool arguments can be treated as a
valid turn. Visible deltas are sent before the final grounding gate, making a
later rejection unable to retract the purported answer. Raw reasoning is also
forwarded as recorded in F-118. Cancellation is detected by the reader thread,
but cannot interrupt a stalled `send()`; a cancelled `spawn_blocking` tool is
waited for briefly and then abandoned while it may continue running. Iteration
exhaustion is a normal string stop reason, tool updates say `completed` even for
errors, and server shutdown globally cancels sandbox processes without joining
all outstanding work.

Required outcome: Put ACP on W10/W12's bounded framed async transport and owned
run executor. Apply maximum frame/queue/history/event/tool/error bytes and
backpressure before allocation; require JSON-RPC version/ID/method schemas;
require provider-native terminal events and causal tool completeness; stage
streamed output as provisional until final commit; and emit typed truncated,
protocol-error, cancelled, budget-exhausted, client-disconnected and writer-
failed states. Cancellation must stop and join HTTP, stream, blocking tool and
descendant process work. Test oversized/drip-fed frames, sparse tool indexes,
malformed/mid-event EOF, stalled connect/body, output backpressure, disconnect,
and cancellation at every phase.

### F-125 — ACP advertises modes and tools that its execution path does not enforce

Severity: High
Status: Confirmed across ACP initialization, schema emission, dispatch and tests

Initialization unconditionally reports prompt, tool, read/write filesystem and
terminal capabilities. Every request then sends the full static core registry,
even though ACP's dispatch match supports only a subset and its local executor
passes no application config, memory database or task manager. Memory/control/
integration tools may therefore be advertised yet fail or reduce to ordinary
text; dynamic MCP schemas are not installed despite an unreachable-looking
`mcp__` dispatch arm. `enter_plan_mode`/`exit_plan_mode` results are never
applied as trusted transitions.

The advertised Initializer versus Coding mode changes only session metadata and
display options. It never filters schemas or denies mutating effects: an
Initializer turn reaches the same Bash/write/edit path as Coding if the
separate permission rules allow it. Tests explicitly demonstrate mode mutation
without attempting a forbidden effect, and static-registry tests prove shape,
not executable capability parity. Several substantial search/security helpers
and their tests are now `cfg(test)`-only remnants of an older shell-delegation
implementation, so they do not protect the current registry path.

Required outcome: Generate ACP capabilities/config options/tool schemas from
the same W11 effective catalog and W17 run-capability generation actually used
by execution. Unavailable dependencies and unsupported platform/provider
features are absent or explicitly degraded. Mode transitions bind the named
session and atomically replace its allowed typed effects; execution revalidates
the same generation. Replace obsolete test-only implementations with end-to-end
tests at the real dispatcher/transport seam after equivalent security coverage
exists.

### F-126 — The proxy spends configured credentials for unauthenticated callers

Severity: Critical
Status: Confirmed across every proxy route and server entrypoint

The default loopback bind reduces exposure but is not an authentication
boundary, and configuration accepts a non-loopback host without requiring an
explicit remote-service profile. The router has no client-authentication or
authorization middleware. Chat, legacy completions, Anthropic messages and
catch-all requests accept a caller key but otherwise fall back to the
operator's configured provider key; any process that can reach the listener can
therefore spend the operator's quota and select any configured provider via
model routing. A syntactically malformed caller key is converted to `None` and
then also falls back to the configured key. Stats exposes the active session ID
and detailed usage, while provider model discovery and device-auth endpoints
share the same unauthenticated surface. There is no tenant/caller identity,
rate/concurrency/cost admission, CSRF/origin policy for the browser flow, TLS,
or trusted-forwarder boundary.

Required outcome: Preserve the proxy through W27 with an explicit deployment
contract. Local mode binds an OS-authenticated Unix socket or loopback with a
per-launch secret and never treats reachability as identity. Network mode
refuses startup without authenticated TLS, caller/tenant identity, scoped
provider/model/cost permissions, rate/concurrency budgets and secure OAuth
browser/session controls. Upstream credentials remain server capabilities and
are never a fallback for a malformed/unauthorized caller credential. Scope and
redact health/stats/models; test local hostile processes, external binds,
credential confusion, cross-tenant spend, replay, CSRF and quota exhaustion.

### F-127 — Every HTTP client shares one mutable proxy session and context

Severity: Critical
Status: Confirmed in `ProxyState`, all handlers, context preparation and accounting

Startup creates one current `SessionManager` session, and proxy requests carry
no canonical session/call handle. Concurrent or sequential callers all inject
that session's context, mutate its request/turn/token counters and read the same
stats. The prior turn's token usage drives another request's compaction hint.
VDD advisory context is taken from and stored into the same current session, so
one response can become system context for an unrelated caller; taking it
before a request succeeds can also lose it. Loop iteration/shutdown counts are
process-global. Hooks, MCP/plugin catalogs, OAuth store and VDD engine likewise
lack caller/run generations in this routing layer.

Required outcome: W12/W27 require each request to authenticate and resolve an
explicit canonical session and new call generation before context, policy,
compaction, usage, VDD, hooks or tools run. Stateless compatibility is a
separate profile with no implicit transcript/session context. All mutable
updates use call-correlated atomic receipts, and concurrency cannot consume or
attribute another call's state. Add simultaneous multi-client tests for prompt,
VDD, usage, hook, compaction, model, cancel and shutdown isolation.

### F-128 — Only one proxy route receives the advertised agent lifecycle

Severity: Critical
Status: Confirmed across chat, legacy completions, Anthropic and catch-all handlers

`/v1/chat/completions` alone performs model/token policy, prompt hooks, context,
rule/MCP/plugin/VDD injection, compaction and selected accounting. The legacy
`/v1/completions`, native `/v1/messages`, and `/v1/*` catch-all forward through
separate paths without that lifecycle. Thus enterprise model/token policy,
context authority, hook decisions, compaction and usage behavior depend on URL
rather than the requested effect. The proxy's named PreToolUse pass merely
rescans tool calls already supplied in client history; the proxy does not own
their execution and its three public MCP/tool-error/shutdown helpers have no
production caller.

The catch-all is not faithful passthrough: it drops the query string and never
forwards the request body, while adding the configured provider credential. It
therefore both bypasses controls and breaks most non-GET provider endpoints.
SessionStart hook denial is logged but ignored; ordinary server shutdown does
not call the provided MCP shutdown helper or publish a recoverable SessionEnd.

Required outcome: W27 defines each route as either a typed canonical agent
operation or an explicitly isolated raw upstream proxy. Canonical routes share
W2/W10/W12 policy, context, accounting, cancellation and terminal semantics.
Raw passthrough is separately authorized, receives no agent/session authority,
and preserves validated method/path/query/body/status/headers under strict
bounds. Remove unused helper surfaces only after their intended MCP error and
shutdown behavior is owned by the real runtime. Add route-parity and exact
wire-round-trip tests for every supported endpoint.

### F-129 — Proxy streaming and adversarial review are not the advertised response pipeline

Severity: Critical
Status: Confirmed in chat forwarding, conversion, usage and VDD control flow

For `stream=true`, the proxy reads the entire upstream body into memory before
returning an Axum response. This removes real-time delivery/backpressure and the
shared five-minute request timeout becomes a whole-stream deadline. More
critically, non-OpenAI provider SSE is returned raw from the OpenAI-compatible
endpoint because only non-streaming responses call the adapter's response
transform. Although OpenAI-style usage events are requested upstream, the
buffered streaming branch never parses or records them.

VDD review is applied only to non-streaming chat and, accidentally, only when
token tracking is enabled. An enabled blocking/advisory review is silently
skipped when that unrelated metric flag is false. Oversized/unreadable VDD
bodies return an empty response with the original status rather than a typed
review failure; advisory output is global session context as described in
F-127. VDD holds one engine mutex across its entire multi-model workflow, has no
per-call cancellation/budget reservation here, and hook denials are explicitly
observational. Loop mode counts an upstream response as a completed iteration
without requiring a successful provider/adapter/review/client-delivery terminal
state.

Required outcome: W3/W10/W27 provide provider-specific bidirectional streaming
adapters with bounded frame/queue memory, backpressure, idle and total
deadlines, disconnect cancellation, terminal-event validation and usage
receipts. Preserve VDD through its audited W27/VDD work: its enablement is
independent of telemetry, modes declare fail-open/fail-closed behavior, every
model/static-analysis call is budgeted/cancellable, findings bind the exact
call/response generation, and review failure never becomes an empty success.
Test Anthropic/Google/OpenAI streaming translation, midstream errors, usage,
slow clients, disconnects, review modes and delivery-aware loop termination.

### F-130 — TUI interruption and shutdown do not cancel or supervise the active run

Severity: Critical
Status: Confirmed across `tui/app.rs`, `tui/events.rs`, and the complete API-turn loop

Escape during streaming only clears `is_waiting`, finalizes the visible widget,
and discards its local raw buffer. It does not cancel or join the spawned API
task, HTTP stream, tool calls, blocking work, or descendants. The user can
therefore submit another turn while the abandoned task continues writing
uncorrelated `StreamText`, tool, `SyncMessages`, and `ResponseDone` events into
the same channel. Those late events can repaint or replace the newer session.
The event channel is unbounded and carries unbounded paste, stream, tool,
history, model-list, shell-output, and error payloads. The UI drains until the
channel is empty before drawing, so a fast producer can starve rendering and
input while growing memory without backpressure.

Terminal state is also not supervised. Raw mode, alternate screen, and
bracketed paste are restored only on the normal return path; initialization,
draw, or later `?` errors can leave the user's terminal altered. The terminal
reader thread has no owned shutdown/join handle, API/filesystem/shell and hook
tasks are detached, and simultaneous permission or question events overwrite
the single pending slot, dropping the previous reply channel. The process-wide
`TUI_SHUTDOWN` flag is never reset, so a later in-process TUI exits immediately;
its claim that the flag “survives a restart” is impossible for process memory.

Required outcome: Preserve the TUI through W10/W12 as a projection of one
call-correlated run handle. Escape and shutdown cancel, drain according to a
declared policy, and join the exact request plus descendants before permitting
a conflicting generation. Use bounded/coalescing event lanes with payload
limits and fair render/input scheduling. Queue or reject concurrent interactive
requests by call ID. An RAII terminal guard restores every enabled mode on all
errors and panics; a supervised reader and child-task set has an explicit stop,
join, and restart lifecycle. Test cancellation races, late events, event floods,
multiple prompts, draw failure, panic cleanup, repeated invocation, and clean
shutdown.

### F-131 — TUI `@file` expansion can read outside the workspace and has no context boundary

Severity: Critical
Status: Confirmed in `tui/app.rs::expand_file_refs` and its live input caller

The function opens a path first and canonicalizes its name second. If a symlink
initially points outside the workspace, is opened, and is then swapped to an
inside target before `canonicalize`, containment passes while the already-open
descriptor still reads the outside inode—the exact opposite of the comment's
safety claim. A failed current-directory lookup becomes an empty root, and the
check is tied to ambient CWD rather than the run's workspace capability.

Each match is synchronously read to EOF on the UI/runtime thread with no file,
aggregate, token, encoding, sensitivity, or reference-count limit. Contents
and an attacker-controlled display path are interpolated into XML-like text
without escaping and stored as the user's message, changing both semantics and
authority rather than representing a typed attachment. Multiple textual
replacements can duplicate large data.

Required outcome: Keep file references through W12/W15 as typed immutable
attachments opened descriptor-relatively beneath the authorized workspace.
Validate the opened object itself, bind its identity/digest and generation,
classify sensitivity/encoding, reserve per-file and aggregate byte/token
budgets, and represent truncation/errors explicitly. Perform bounded I/O off
the render loop with cancellation. Provider projections quote attachment data
at user/reference authority; no XML wrapper or path race is treated as an
authority boundary. Add adversarial symlink-swap, rename, special-file,
oversize, binary/invalid-UTF-8, duplicate-reference, cancellation, and prompt-
injection tests.

### F-132 — Resuming a TUI session can display one provider while sending through another

Severity: Critical
Status: Confirmed in session load/resume, provider switching, and API-turn spawn

`apply_loaded_session` copies the saved model/provider into display and session
metadata and updates a cloned app-config target, but it does not resolve or
replace the `ApiClient` endpoint, headers, wire protocol, OAuth token, prompt
blocks, or VDD builder authentication. Loading a session created for another
provider can therefore show provider B and build requests with provider-B
conversion/model rules while transmitting them to provider A with provider-A
credentials and protocol state. Prefix load selects the first match rather than
rejecting ambiguity, and listing/loading performs unbounded synchronous
directory enumeration, file reads, and JSON parsing.

Loaded messages are reduced to string content for display, losing multipart
and provider-native items, while `run()` appends its current system prompt on
every invocation/resume. The UI mode is copied from a label that remains
separate from enforceable tool capabilities (F-119/W17). Session identity,
transport identity, prompt generation, workspace, and authority are therefore
not one atomic resumable state.

Required outcome: W3/W12 resume an exact versioned session generation only
after atomically resolving and validating its provider adapter, credential
capability, endpoint, native continuation, prompt/context generation, mode,
workspace, budgets, and frontend projection. Credential material is referenced
by host capability, not persisted into the session. Unknown/ambiguous prefixes
fail with bounded choices; storage reads are bounded/cancellable. A failed
rebind leaves the old session untouched. Test cross-provider resume, expired or
missing credentials, protocol changes, ambiguous IDs, multipart/native state,
duplicate prompts, and crash recovery.

### F-133 — TUI presentation is unbounded, Unicode-incorrect, and includes direct terminal output of untrusted text

Severity: High
Status: Confirmed in `tui/messages.rs`, `tui/input.rs`, `tui/mod.rs`, and overlays

The full-screen renderer reconstructs and wraps the entire transcript on every
frame rather than virtualizing a bounded viewport; streaming text, thinking,
input, question buffers, session titles, shell results, and most errors have no
admission cap. Cursor/layout calculations count Unicode scalar values rather
than grapheme clusters and terminal cell widths, so combining and wide
characters produce incorrect editing and placement. The inline Markdown parser
repeatedly searches delimiter tails and can become quadratic; its streaming
line buffer grows without limit until a newline.

The legacy renderer and thinking helpers are live in the REPL and pass model,
tool, path, error, and raw reasoning strings directly to Crossterm `Print` or
`print!`, permitting terminal control sequences. Full-screen messages and log
selector data likewise lack a common sanitizer. Some review output is truncated
only after the subprocess has already been captured without a byte limit, and
`/review` and `/init` still call blocking `.output()` on the UI thread despite
nearby migration comments. The module retains two presentation systems and
multiple command/help surfaces; this duplication is removable only after the
canonical frontend projection preserves their useful theme, Markdown, welcome,
and interactive behavior.

Required outcome: W12 keeps the intended UI while introducing bounded event
payloads, transcript virtualization, incremental linear-time Markdown/layout,
grapheme/cell-width-correct editing, a single terminal-control sanitizer, and
an explicit safe raw export. Process output is bounded while being captured,
never only after allocation; every blocking operation is cancellable and off
the render loop. Consolidate the two renderers and duplicate command/help code
only after parity tests cover themes, Markdown, Unicode, streaming, resize,
large histories, hostile control bytes, and terminal restoration.

### F-134 — VDD can certify parse failures as clean and its verifier can panic on adversary line ranges

Severity: Critical
Status: Confirmed across VDD parsing, triage, confabulation, and engine convergence

The detailed parser distinguishes `NO_FINDINGS` from invalid output, but every
live engine path calls the legacy `parse_findings` wrapper, which converts
not-JSON, invalid/missing findings, and intentional clean output to the same
empty vector. Advisory callers then report “No issues found”; blocking mode
counts zero genuine findings and can finalize a clean pass. Normal provider
transport also accepts missing/empty extracted text. Conversely, an exact
`assessment: NO_FINDINGS` wins even if the same response contains findings, and
the relaxed parser treats broad substrings such as “no issues” or “looks good”
anywhere in prose as authoritative clean output.

The verifier's code-window builder trusts model-supplied `usize` line ranges
and slices `lines[start..end]` without clamping the start or validating order.
Out-of-file or reversed ranges can panic the VDD worker. When the view is
truncated, comments and logs claim affected findings stay genuine, but the
boolean is never used and all parsed verifier verdicts are still applied.
Verification sees only the builder's response string—not an immutable snapshot
of the cited workspace file—so “checks against actual code” is an overclaim.

Confabulation convergence also skips a current zero-finding `None` and reuses
the most recent earlier numeric rate; a clean pass after a high-FP pass can
therefore terminate as confabulation. Hard-coded text patterns automatically
demote categories such as “deprecated api” or poisoned-mutex findings without
binding the claim to executable evidence, while strong duplicate signatures
collapse any same file/severity/CWE/range tuple regardless of distinct cause.

Required outcome: W28 makes parse, schema, empty response, explicit clean,
findings, disputed, verifier unavailable, and truncated evidence distinct typed
states. Only a schema-valid, terminal, contradiction-free clean result can
contribute to convergence. Treat every model line/path as untrusted; normalize
and bound it without panics, resolve a cited immutable artifact snapshot, and
bind verdicts to exact finding/evidence digests. Remove automatic semantic
demotion heuristics unless calibrated evidence shows acceptable false-negative
risk; otherwise use them only as review hints. Specify convergence math and add
property/fuzz tests for malformed JSON, contradictory assessment, arbitrary
ranges, Unicode/braces, truncation, clean-after-FP sequences, and duplicate
causes.

### F-135 — VDD “blocking mode” is advisory or fail-open on every supported frontend

Severity: Critical
Status: Confirmed in all VDD entrypoints, the revision loop, and proxy delivery

TUI and both legacy chat paths call `review_text`, which unconditionally runs
one advisory pass regardless of configured `VddMode`; their startup banner can
say blocking while the response has already streamed to the user. TUI/legacy
then inject findings only into future context. Only the proxy calls
`process_response`, and F-129 shows that happens only for buffered non-streaming
chat under an unrelated telemetry flag.

Even there, “blocking” does not require a clean result. Unknown builder
adapters are `Skipped`; VDD errors return the original response; builder
revision failure or maximum-iteration exhaustion returns the last response with
`converged=false`, and the proxy serializes it as ordinary success. Revision
requests clone the original user request and append findings but omit the exact
response being revised and all prior revision history. They retain tool schemas
and tool choice although VDD never executes returned tool calls; empty text is
accepted as the next revision. Static-analysis failures do not independently
block or require revision. A length heuristic silently excludes every response
under 100 bytes irrespective of risk or task.

Required outcome: W28 exposes one review operation with explicit advisory,
blocking, required-evidence, skipped-by-policy, degraded, failed, unconverged,
and cancelled terminal outcomes in W12. Blocking delivery is impossible until
the exact response digest reaches the configured acceptance policy; fail-open
is an explicit host choice surfaced to the caller. Revision consumes the exact
prior artifact and causal history, disables tools unless a separately budgeted
canonical child run owns them, validates nonempty terminal output, and binds
static evidence. All frontends share this lifecycle, including streaming via a
declared provisional/holdback protocol. Replace the byte-length shortcut with
task/content/risk policy and test every mode and failure at the real frontend.

### F-136 — VDD transport has no bounded, status-validating review-call contract

Severity: Critical
Status: Confirmed in all adversary, verifier, builder, Responses, and static-analysis transports

For normal provider adapters, VDD never checks HTTP success status before
parsing the response as JSON. Error envelopes can therefore become empty
successful model output. `response.json()` and the Codex `response.text()` path
read bodies without byte limits; request and response construction likewise
have no aggregate context cap. URL parsing merely warns and still sends. Send
and body reads each receive a fresh full timeout, so the documented per-request
limit can take twice that duration, and a zero timeout is accepted. Codex SSE
parsing does not require a completed terminal event and accepts EOF with partial
or empty text.

There is no VDD-run reservation for tokens, cost, elapsed time, calls, static
commands, output bytes, or cancellation. `max_iterations` and model
`max_tokens` can be enormous (or tokens/timeouts zero), command lists are
unbounded and sequential, missing usage is charged as zero, and proxy holds one
global engine mutex through the entire multi-model/static-analysis workflow.
Timeout drops the immediate future but there is no run-owned join tree tying
HTTP, blocking analyzers, revisions, issue writes, and frontend disconnect to a
single cancellation outcome.

Required outcome: W10/W28 admit the entire review before work with finite
aggregate call/token/cost/time/concurrency/static-process/storage reservations.
Use the canonical provider transport: validated endpoint and status, bounded
request/frame/body/error sizes, one monotonic deadline, provider-native terminal
validation, attributed usage, retries/idempotency policy, and cancellation that
joins descendants. Each reviewed call owns independent engine state; queueing
is bounded and tenant/session-safe. Validate finite configuration ceilings and
test oversized/error/partial bodies, slow drip, zero/huge settings, missing
usage, cancellation, concurrent callers, and budget exhaustion.

### F-137 — VDD evidence, persistence, and issue creation are untrusted and nontransactional

Severity: Critical
Status: Confirmed in VDD prompts, session model, persistence sink, static analysis, and consumers

Adversary descriptions and reasoning are model output, yet advisory formatting
turns them into imperative prompt text and three frontends promote/store it as
system or global session authority (F-011). Configured static-analysis commands
execute automatically on every review and blocking mode creates Crosslink
issues without routing either effect through the canonical approval/audit
lifecycle. Project configuration can influence these operations.

When tracking is enabled, ordinary `create_dir_all`/`write` publishes a
project-path JSON file containing every full builder response, raw adversary
response/reasoning, static stdout/stderr, paths, timestamps, and usage. There
are no per-field sensitivity labels, redaction, size/retention/access policy,
atomic durability, collision/generation handling, or recovery; the session is
serialize-only and cannot actually resume. Optional response-preview logging
also emits unredacted model content. All findings ever labeled genuine are
turned into issues after the loop, including duplicates and findings a later
revision may have fixed. Issue creation, label, and comment are separate writes;
label/comment failure still returns the issue ID as success, and repeated runs
have no idempotency key or response/evidence digest.

Required outcome: W2/W15/W28 keep static analysis and durable review evidence as
typed effects under host-approved capabilities. Findings remain bounded
reference observations with producer/model, reviewed response digest, artifact
snapshot, verifier evidence, status history, sensitivity and expiry. Persist a
redacted resumable schema atomically in capability-safe storage with retention,
export/delete, integrity and crash recovery. Issue promotion requires explicit
policy/approval and only an unresolved evidence-bound final finding; publish it
transactionally or reconcile partial state under an idempotency key. Test prompt
injection through findings, project-config authority, fixed/duplicate findings,
partial database writes, crashes, redaction, access, resume, and retention.

### F-138 — Configured MCP tool allowlists are never enforced

Severity: Critical
Status: Confirmed by source-wide consumer search after reading `permissions_mcp_tool_allowed_e2e.rs`

`PermissionsConfig::mcp_tool_allowed` exists only in its implementation and
tests; no production MCP discovery, schema publication, manager call, resource
read, proxy or TUI path invokes it. The extensive integration suite therefore
tests an isolated predicate, not a permission boundary. Even if it were wired
as written, its security default is fail-open: an absent, misspelled or
case-mismatched server name allows every tool, and empty server/tool names are
allowed. The tests explicitly require all of these behaviors while describing
the overall permission default as deny-by-default.

Required outcome: Under W2/W6, compile reviewed MCP server identity, trust
source, capabilities and allowed concrete effects into the session's canonical
permission policy before publishing any tool/resource schema. Unconfigured or
unknown server/tool identity fails closed; discovery changes invalidate prior
receipts; normalized names cannot bypass policy by case/alias differences.
Every call and resource read passes through the same typed effect reservation,
approval, audit, timeout and cancellation path as local tools. Add end-to-end
tests at the public dispatcher with a live fake server for absent, typoed,
renamed, newly discovered, revoked and explicitly empty policies.

### F-139 — Fuzz targets execute real side effects with attacker-generated arguments

Severity: Critical
Status: Confirmed in all nine fuzz targets, the fuzz manifest, and its complete lockfile

`fuzz_json_tool_args` sends arbitrary fuzzer bytes to the public executor for
`write_file`, `edit_file`, `bash`, `web_fetch`, `web_search`, Crosslink, todo,
background-output and process-kill tools. It installs no isolated run,
permission policy, fake transports, disposable workspace, process sandbox or
effect assertion. A generated valid tool argument can therefore modify files,
start commands or network work, mutate the tracked issue database/task state,
or target ambient processes during an ostensibly pure fuzz run.
`fuzz_cron_validate` similarly calls the real `cron_create` dispatcher rather
than a validator, and `fuzz_path_resolve` asks real file/list handlers to inspect
arbitrary paths under the ambient default session. Fuzzer execution is thus a
host-authority path, not merely a crash detector.

The remaining targets are no-panic smoke tests with weak or misleading oracles:
the hook target fuzzes the `regex` crate instead of OpenClaudia's matcher; SSE
processing reuses mutated accumulators without checking protocol invariants or
bounds; provider targets admit only valid UTF-8/JSON and assert no semantic
properties; the Markdown chunker can stop at the first inconvenient UTF-8
boundary and leave the rest untested. No tracked seed corpus or regression
artifact exists, and the manifest does not define deterministic resource or
side-effect isolation.

Required outcome: Under W13, fuzz only pure parsers/validators or adapters whose
entire effect boundary is replaced with deterministic in-memory fakes. Every
harness gets finite input/time/allocation/call limits, a stated invariant, a
seed corpus covering valid and adversarial states, and minimized crashes kept
as regression tests. Effectful executor fuzzing must run inside an ephemeral
capability root with fake network/process/database services and an assertion
that no unmodeled host effect occurred; otherwise remove that harness and fuzz
the typed argument/parser layer directly. Add semantic/state-machine properties
for provider streams, paths, tool schemas, hook matching, Markdown chunk
equivalence and VDD parsing—not merely “did not panic.”

### F-140 — Repository hooks and the inherited Claude prompt confuse data, extensions, and control authority

Severity: Critical
Status: Confirmed in all tracked Python hooks, `.claude/settings.json`,
`src/claude_code_prompt.txt`, and their production include/call sites

The checked-in Claude settings automatically execute repository-controlled
Python at session start, before web calls, after edits, before selected shell
commands, and on every user prompt. Two of those programs are the deprecated
rule injector: `prompt-guard.py` reads every Markdown file in project/local
rule directories and promotes the content into every prompt, while
`pre-web-check.py` injects a prompt-only web rule instead of enforcing egress at
the connection boundary. The settings also reference a missing
`heartbeat.py`, silently treat absence as success, enable every project MCP
server, and grant broad command patterns. Their 5–30 second internal subprocess
budgets exceed several 5–10 second outer hook timeouts, so cancellation can
interrupt the wrapper while leaving ambiguous child work.

The remaining hooks contain useful intended outcomes but are not production
boundaries. `work-check.py` classifies raw shell text with spacing/prefix
heuristics that substitutions, redirections, wrappers, alternate separators,
project configuration, or spoofed agent state can bypass. It explicitly tells
the agent to conceal workflow advice from the user. `post-edit-check.py` can
run project/PATH tools, including download-capable `npx`, against a root derived
from model-supplied file input; errors and spoofed agent state frequently fail
open. `session-start.py` ignores the hook event, mutates and comments on a
separate issue workflow automatically, parses human CLI text, and injects raw
issue/handoff/status content as authority. `crosslink_config.py` silently
suppresses configuration and I/O failures, trusts project-controlled executable
paths, and infers agent identity from mutable files/path substrings.

The production credential path also includes the 11.5 KiB
`claude_code_prompt.txt` as a monolithic behavioral system prompt. It asserts a
false Claude Code identity requirement, treats `<system-reminder>` and hook
text as privileged instructions, mandates an external issue workflow, names
stale/unavailable tools, and tries to implement permissions and coding policy
through prose. Its assumptions contradict the typed runtime and turn ordinary
compatibility content into control authority.

Required outcome: W1 removes both rule-injector programs, their settings
entries, generated rule assets, rule loading, and rule-specific documentation
and tests. W12/W25 retain hooks only as explicit, typed, user-visible extension
capabilities with exact provenance, bounded inputs/effects, host-enforced
policy, cancellation and auditable decisions. W2/W23 enforce filesystem,
process and network policy at the actual capability/connection boundary. Replace
the inherited prompt with a small host-owned policy that accurately describes
the runtime and preserves provenance; repository, tool, issue, hook and model
text remain bounded untrusted observations unless an explicit typed mechanism
grants otherwise. Add negative tests for every removed injection path and for
prompt-tag/control-signal impersonation.

### F-141 — Mutable historical state and generated bytecode are tracked as source

Severity: High
Status: Confirmed by complete SQLite/schema/row/content audit and bytecode header inspection

`.chainlink/issues.db` is a valid SQLite v7 database containing 226 issues, 165
comments, 100 labels, 22 dependencies and three sessions. It has no issue
descriptions; 208 issues are closed, yet many comments record “fully
implemented,” “fully integrated,” “all complete,” or test-count assurances for
paths this audit proves unwired, fail-open, frontend-specific, or otherwise
incomplete. The sequence is internally contradictory: VDD was called fully
integrated, then a later issue says the module was not imported or called by
the main loop; structured tools were added, then removed for the unsupported
OAuth path; guardrails were declared complete shortly before the final audit
recorded only seven findings. The last active session (ID 3, issue 226) has
remained open since 2026-01-11 and is mirrored by the tracked
`.chainlink/session.json`. Closed status and passing test counts are therefore
historical claims, not production evidence.

The database is ignored by `.gitignore` despite already being tracked, and a
production helper will copy it into a new untracked `.crosslink/issues.db` on
first use. Keeping a mutable runtime database and stale active-session marker
in source control creates split-brain state, noisy diffs, accidental migration,
and ambiguous ownership. It is also valuable evidence of what was promised, so
blind deletion would lose audit history. A targeted sensitive-text scan found
seven API-key *references* and no obvious bearer/access/refresh/client-secret,
password or `sk-` token pattern; one already-read comment contains a reused
OAuth client identifier and identity-emulation plan, which reinforces the need
for a reviewed export rather than treating the binary as harmless source.

The tracked CPython 3.13 bytecode file was compiled from an older 7,580-byte
version of `crosslink_config.py`; the current source is 11,260 bytes. Its header
timestamp/size no longer matches, its code objects stop before current
functions, and it embeds an absolute `/home/doll/OpenClaudia/...` path. Python
will ignore or regenerate it, potentially dirtying the repository. It has no
source or runtime value.

Required outcome: Before cleanup, export the database to a stable, reviewable,
redacted Markdown/JSON history that preserves issue/comment IDs, timestamps,
relationships and the contradictions relevant to remediation. Hash and archive
the original outside normal source control according to an explicit retention
decision, then remove the tracked database/session marker and prevent automatic
legacy copying. Remove the tracked `.pyc` and ignore generated bytecode. Do not
use historical closure or test totals as release evidence; W0 requires live
entrypoint capability tests and traceable acceptance criteria.

### F-142 — Documentation tests turn marketing text into circular “evidence”

Severity: Critical
Status: Confirmed by full read of all 68 Markdown files and every compile-time documentation consumer

The active documentation repeatedly labels type/schema presence or isolated
unit coverage as a working product capability. `README.md`, `COMPARISON.md`,
`CLAUDE_CODE_FEATURES.md` and `ARCHITECTURE.md` advertise cross-provider tool
loops, automatic memory, enforcement-grade modes, MCP, hooks, VDD, guardrails,
worktrees, sandboxing and OAuth behavior that the production audit proves
partial, unreachable, unsafe or frontend-specific. `CHANGELOG.md` is an
unreleased issue dump containing duplicate entries, audit task titles and
“fixed” security claims that remain present in current source. The binary
capability matrix calls a route `works` when a startup or structural assertion
exists even when the advertised lifecycle, isolation or final gate does not.

Tests reinforce this drift by `include_str!`-ing the documents and asserting
literal marketing phrases, provider/model catalog strings, command rows and
descriptions. They do not prove the described runtime path. Several integration
files reproduce helper logic or exercise an isolated predicate and then use the
documentation assertion as parity evidence. The result is circular: prose says
a feature works, a test asserts that the prose still says it, and the passing
test total is cited as proof that the feature works.

Required outcome: Under W0/W13, make one generated capability registry describe
entrypoint reachability, supported state, limitations and acceptance-test IDs.
Documentation consumes only released registry states; end-to-end traces produce
the evidence, never substring tests over prose. Replace the current root docs
with concise audit-honest status/reference material now, and later generate the
operational matrices after canonical runtime tests exist. Changelog entries
describe shipped user-visible deltas tied to releases, not promises, issue
titles or audit findings. An unavailable/partial capability is labeled as such
even when types and unit tests exist.

### F-143 — Parity and “evidence-based” reports promote stale reverse engineering and unproven review claims

Severity: High
Status: Confirmed by complete source/citation/content read of the affected Markdown reports

The January/February Claude Code analysis files are snapshots of a reverse-
engineered vendor bundle and count text references as feature evidence. They
normalize cloning another product's identity, reminder tags, hook authority,
tool prose and compatibility state instead of defining OpenClaudia's own
capability contracts. The original `.claude/OPENCLAUDIA.md` makes prompt/rule
injection the product vision, specifies nonexistent Python/VS Code APIs and
files, recommends `npx @latest`, asserts an anecdotal contract/cost result, and
ends by celebrating that the model cannot tell it is being harnessed. That is
the opposite of explicit provenance and user-visible authority.

`docs/evidence-based-coding-guardrails.md` contains some valid directions—real
effect boundaries, deterministic analysis, bounded scope and independent
evaluation—but overstates the literature. It calls VDD and a confabulation-rate
stopping rule “proven,” treats a different model/fresh context as intrinsically
independent, generalizes from secondary industry reports, and presents an
unpublished project audit as validation. Current VDD source can classify parse
failure as clean, promotes reviewer prose, is fail-open at frontends and lacks
an evidence-bound artifact snapshot, so the document's strongest product claim
is directly contradicted by the implementation.

Required outcome: Under W0/W28, maintain a dated research register that
distinguishes primary experiment/specification, vendor guidance, secondary
analysis, anecdote and local hypothesis. Record population, task, comparator,
effect, uncertainty and applicability before turning a result into a design
requirement. Evaluate reviewer diversity/context, deterministic analyzers,
formal methods and stopping policies against OpenClaudia tasks; do not call a
second model proof. Vendor compatibility is an explicit typed adapter with
conformance tests, not an identity/prompt cloning strategy. The superseded
reports are deleted after their valid requirements are carried into the
canonical remediation design.

### Non-Rust scripts, configuration, prompt, fixtures, and artifacts

All tracked non-Markdown/non-Rust files other than the four Cargo files and the
already-audited fuzz `.gitignore` were read or inspected in full. This table is
the per-file disposition record; `Repair` means preserve the intended outcome,
not the current mechanism.

| Path | Audit result | Disposition |
|---|---|---|
| `.chainlink/issues.db` | Integrity and foreign-key checks pass; complete schema and all 226 issue titles/165 comments read; mutable legacy state and contradictory completion ledger described in F-141 | Export/archive evidence, then remove binary runtime state from VCS |
| `.chainlink/session.json` | Stale active session 3/issue 226 from January 2026; duplicates the database state | Preserve in history export, then remove from VCS |
| `.claude/hooks/__pycache__/crosslink_config.cpython-313.pyc` | Stale CPython 3.13 artifact with source-size mismatch and absolute local path | Delete generated cruft |
| `.claude/hooks/crosslink_config.py` | Shared helper silently fails open, trusts project executable/state, caches across roots and uses spoofable/Unix-only identity inference | Repair hook support under W25; remove legacy rule helpers/coupling |
| `.claude/hooks/post-edit-check.py` | Executes project/PATH tools under mismatched budgets, can invoke download-capable `npx`, trusts tool-supplied roots, and reports skips/failures ambiguously | Replace example mechanism with explicit typed quality-hook capability |
| `.claude/hooks/pre-web-check.py` | Deprecated prompt-only web rule injector, not an egress boundary | Delete completely with settings entry |
| `.claude/hooks/prompt-guard.py` | Unbounded all-rule prompt injector with fake budget/compaction claims, stale tool names and non-atomic shared state | Delete completely with settings entry |
| `.claude/hooks/session-start.py` | Ignores event input, mutates external workflow implicitly, exceeds outer timeout and injects raw issue state as authority | Remove automatic activation; redesign only as explicit typed integration |
| `.claude/hooks/work-check.py` | Bypassable shell-text/workflow heuristic, stale DB query (`comments.kind` does not exist), extensive fail-open behavior and anti-transparency output | Remove as security/control boundary; preserve workflow intent only through typed policy |
| `.claude/settings.json` | Auto-activates repository hooks, references missing `heartbeat.py`, enables all project MCP servers and grants broad commands | Remove rule entries; replace with inert/least-authority development config or stop tracking user-tool runtime settings |
| `.github/dependabot.yml` | Broad stale suppression of `rand <0.11` no longer matches the lock graph and can conceal future fixes | Narrow/remove ignore with documented compatibility bound |
| `.github/workflows/sandbox-security.yml` | Only CI workflow; live unpinned toolchain/packages, no `--locked`, no job timeouts, weak non-Linux matrix and no audit/deny/fuzz/eval/provider evidence | Repair as W13 release-evidence matrix |
| `.gitignore` | Duplicate legacy entries; simultaneously ignores already-tracked state and tracked hook source; mixes `.chainlink`/`.crosslink` generations | Consolidate after explicit state/hook ownership decision |
| `.openclaudia/config.yaml` | Placeholder repository/tool claims, old paths and likely ignored unknown `session` key; advertised provider/guardrail state drifts from runtime | Replace with schema-valid minimal example generated from canonical config metadata |
| `.openclaudia/hooks/session-start.py` | Example turns arbitrary current-directory text into `systemMessage` | Remove auto-installed copy; retain only inert typed-hook documentation if hooks remain |
| `.openclaudia/plugins/example-plugin/.claude-plugin/plugin.json` | Impersonates Anthropic/support metadata and claims a comprehensive plugin absent from the tree | Replace with honest OpenClaudia-owned minimal fixture |
| `.openclaudia/plugins/example-plugin/.mcp.json` | Points to fictitious `https://mcp.example.com/api` without trust/auth/capability semantics | Replace with local deterministic fixture or remove from installed example |
| `LICENSE` | Standard MIT license text; no defect found | Keep |
| `assets/device_flow.html` | Live legacy subscription-auth UI; remote asset proxy, unsafe `innerHTML`, cookie/curl exposure and `window.open` without isolation | Remove with prohibited OAuth/identity-emulation path; replace only if a supported provider-owned flow exists |
| `images/logo.jpg` | Valid 1024×564 OpenClaudia logo, referenced by README; Picasa EXIF and embedded thumbnail but no personal identity metadata observed | Keep; optionally strip unnecessary metadata in a later asset-hygiene change |
| `src/claude_code_prompt.txt` | Live monolithic inherited behavioral prompt with false identity/tool/authority assumptions (F-140) | Replace with minimal accurate host-owned policy; do not delete until include path changes in implementation |
| `tests/fixtures/mcp_echo_server.py` | Deterministic line-JSON fixture pinned to retired MCP `2024-11-05`; lacks current protocol lifecycle/capabilities | Keep concept, replace with current conformance fixture under W6 |
| `tests/fixtures/session_legacy_tui.json` | Small legacy-session migration fixture with `/tmp/shared` path; no sensitive content | Keep while the represented migration remains supported; version/name it explicitly |
| `tests/tools_e2e.proptest-regressions` | Valid tracked minimized regression seeds for tool property tests | Keep |

The logo SHA-256 at audit time is
`6fe6ea7a647ed4f23746e6cd36f519335f9f91268dea6787c90a93bdb586bf5e`;
the historical database SHA-256 is
`8ee52062c20e12f346973402a46462c212b0785ea4cfd56ce7ec735273699748`.

### Repository inventory

Status: Complete; every inventoried file was classified

- 546 tracked files total.
- 449 Rust files: 206 production/library/binary files, 234 integration-test
  files, and nine fuzz targets.
- 68 Markdown files, including product documentation, design snapshots,
  prompts, rule content, examples, and generated/audit reports.
- Eight Python files plus one tracked CPython 3.13 bytecode file.
- Five JSON files, two YAML/YML files, two TOML manifests, two lockfiles, and
  several repository/tool configuration files.
- One tracked SQLite database (`.chainlink/issues.db`), one tracked JPEG logo,
  and no symlinks or Git submodules.
- Tracked source content is approximately 12 MiB; build artifacts were vastly
  larger than source before cleanup.

## 6. Rule-injector removal inventory

Status: Complete for audit and Markdown asset cleanup. Runtime removal remains
an implementation workstream and was intentionally not performed in this pass.

| Path or symbol | Role | Replacement/impact | Verified |
|---|---|---|---|
| `.openclaudia/rules/` | Project rule content | Product rule asset deleted; explicit skills/configuration remain separate | Deleted in this pass |
| `.chainlink/rules/` | Crosslink-managed rule content | All 23 assets deleted; later implementation removes OpenClaudia injection dependency | Deleted in this pass |
| `src/lib.rs` module export | Publishes rule subsystem | Remove export when implementation is removed | Verified |
| `src/main.rs::tui_launch` | Reads `.openclaudia/rules` with a hard-coded extension list and stores combined content on `App` | Remove construction, app field wiring, and downstream injection; add negative tests | Verified |
| `src/services/tool_executor.rs` extension extraction import | Reuses language/extension inference for hook metadata | Relocate the neutral metadata helper outside `rules`; preserve hook inputs without preserving injection | Verified |
| `src/rules.rs::{Rule, RulesEngine, extract_extensions_from_tool_input}` | Loads, selects, combines, and conditionally infers project rules | Remove; move only neutral `LANGUAGES`/known-extension support used by auto-learning to a file-type module | Verified |
| `src/auto_learn.rs::{has_source_extension, has_file_extension}` | Uses only the neutral known-extension predicate while parsing possible paths | Point at the replacement file-type registry; do not preserve any rule selection/injection behavior | Verified in full |
| `src/acp.rs` | Owns `RulesEngine`, scans every shared transcript message for extension-like text on every loop iteration, combines project rules, and supplies them to the system-prompt builder | Remove field, construction, scan/combine argument and deprecated tests; preserve only typed IDE/cwd evidence through W12 | Verified in full |
| `src/cli/chat_repl.rs` | Owns and constructs a `RulesEngine`, scans every stored message for extension-like text, and inserts combined rule text as a system message once by substring heuristic | Remove field, construction, scan/injection path, and deprecated checks | Verified in full |
| `src/cli/repl/slash.rs` | Imports and invokes `init_project_rules()` after every `/init`, even when config already exists | Remove the import/call; preserve `/init` through the transactional non-rule initializer | Verified in full |
| `src/proxy.rs` | Owns `RulesEngine`, scans up to 64 KiB of all request message text for 32 extension-like tokens, combines project rules, and prefixes the system prompt | Remove field, construction, regex/scanner/limits and injection; retain neutral hook file-type metadata via W1's replacement registry | Verified in full |
| `src/services/tool_executor.rs` | Infers extensions for rule selection | Remove rule coupling; preserve tool lifecycle service | Verified in full |
| `src/cli/commands/doctor.rs` | Loads/reloads/diagnoses rules as if their presence were healthy | Remove rule checks and user-facing claims; preserve unrelated diagnostics only through F-108's evidence-safe redesign | Verified in full |
| `src/cli/display/tips.rs` startup tips | Advertises `/init`-generated rules and `.openclaudia/rules/global.md` as active product features | Remove rule-specific tips; retain only claims proven by executable capability tests | Verified in full |
| `src/cli/commands/init.rs` rule directory/template and `detect_project_type`/`generate_project_rules`/`init_project_rules` path | Creates global/project rule Markdown from static language heuristics in both CLI and REPL initialization | Delete rule generation and directory creation; preserve general config/project setup as a transactional typed scaffold | Verified in full |
| `src/tui/app.rs` prompt/context insertion | Stores launcher-provided rule text and inserts it as a leading system message on the first normal user turn | Remove fields, first-turn insertion and deprecated tests; preserve typed attachments/skills separately | Verified in full |
| `.claude/hooks/pre-web-check.py` | Reads project/local web-rule Markdown and emits it as a pre-web prompt block | Delete file and replace egress intent at W23's network boundary | Verified in full |
| `.claude/hooks/prompt-guard.py` | Reads all project/local rules and injects them on every user prompt | Delete file, markers/state and all activation paths | Verified in full |
| `.claude/settings.json` | Automatically activates both Python rule injectors | Delete the PreToolUse Web and UserPromptSubmit rule entries; verify no repository config reactivates them | Verified in full |
| `.openclaudia/config.yaml` and generated init template | Advertise a `prompt-guard.py` hook path | Remove deprecated example/reference while preserving schema-valid hook examples separately | Verified in full |
| `src/context.rs::inject_all` and direct system prefix/suffix APIs | Generic arbitrary-string instruction splicing; `inject_all` names rules/plugins as intended callers | Replace with typed context items; delete rule-specific callers and prevent project/hook data from gaining system authority | Verified |
| Four dedicated integration files plus `src/rules.rs` unit tests | Assert deprecated loading, accessors, dispatch, reload, and extension inference | Delete rule tests; migrate only neutral extension-registry coverage that protects auto-learning | Verified in full |
| Documentation and repository rule assets | Assert, explain, or supply rule behavior | Delete the 24 tracked rule assets in this cleanup; remove remaining claims/callers in implementation | Verified in full |

## 7. Markdown disposition ledger

No Markdown file will be deleted merely for being old. A file becomes deletion
cruft when it is superseded, materially contradicts audited behavior, is a
generated one-time report without ongoing ownership, or documents a removed
mechanism. User-facing reference, history, security threat models, and active
design material remain unless the audit establishes a specific reason.

All 68 originally tracked Markdown files were read in full before cleanup.
“Deleted in this pass” means the file was superseded and unreferenced or was a
selected rule asset; Git history still retains it. “Rewritten in this pass”
means an active/build-sensitive reference was replaced with audit-honest
content. “Retain live” means changing it would alter compiled/runtime prompt
behavior, so its remediation belongs to the implementation phase.

| File | Disposition | File-level reason |
|---|---|---|
| `.chainlink/rules/c.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/cpp.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/csharp.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/elixir-phoenix.md` | Deleted in this pass | Version-bound prompt advice, not an enforcement/eval asset |
| `.chainlink/rules/elixir.md` | Deleted in this pass | Generic/stale tool advice under selected W1 mechanism |
| `.chainlink/rules/global.md` | Deleted in this pass | Forces hidden issue mutations and rule authority; historical failure source |
| `.chainlink/rules/go.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/java.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/javascript-react.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/javascript.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/kotlin.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/odin.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/php.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/project.md` | Deleted in this pass | Empty template for deprecated automatic authority |
| `.chainlink/rules/python.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/ruby.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/rust.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/scala.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/swift.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/typescript-react.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.chainlink/rules/typescript.md` | Deleted in this pass | Absolute/stale package advice under selected W1 mechanism |
| `.chainlink/rules/web.md` | Deleted in this pass | Prompt-only egress/injection policy; W23 preserves outcome at real boundary |
| `.chainlink/rules/zig.md` | Deleted in this pass | Generic prompt-only language rules; selected W1 mechanism |
| `.openclaudia/rules/global.md` | Deleted in this pass | Explicit every-conversation rule injector asset |
| `.claude/OPENCLAUDIA.md` | Deleted in this pass | Obsolete injection-first product design with nonexistent APIs/assets (F-143) |
| `.design/acp-protocol-server.md` | Deleted in this pass | Unchecked pre-implementation design superseded by W2/W12/W27 |
| `.openclaudia/plugins/example-plugin/README.md` | Retain live; repair later | Runtime example content; false “comprehensive”/vendor claim handled by W26 |
| `.openclaudia/plugins/example-plugin/commands/example-command.md` | Retain live; repair later | Runtime plugin command; parsed permissions are not enforced as claimed |
| `.openclaudia/plugins/example-plugin/skills/example-skill/SKILL.md` | Retain live; repair later | Runtime skill asset; W16/W26 preserve and correct the example |
| `ARCHITECTURE.md` | Rewritten in this pass | Active compile-time doc; replaced false pipeline with audit-honest topology |
| `CHANGELOG.md` | Rewritten in this pass | Unreleased issue/assurance dump replaced with a trustworthy audit/cleanup entry |
| `CLAUDE.md` | Rewritten in this pass | Active contributor context no longer promotes rule/injection architecture |
| `CLAUDE_CODE_FEATURES.md` | Rewritten in this pass | Build-sensitive obsolete parity catalogue replaced with an audited status reference |
| `COMPARISON.md` | Rewritten in this pass | Build-sensitive marketing claims replaced with current adapter caveats |
| `QA_REPORT.md` | Deleted in this pass | April “full” audit is incomplete, path-stale and superseded by this audit |
| `README.md` | Rewritten in this pass | Active entrypoint now distinguishes implemented routes from production readiness |
| `docs/binary-capability-matrix.md` | Rewritten in this pass | Build-sensitive matrix now describes reachable routes without treating them as readiness evidence |
| `docs/claude-code-system-prompt-analysis.md` | Deleted in this pass | Stale reverse-engineered vendor snapshot; F-143 |
| `docs/designs/507-coordinator.md` | Deleted in this pass | Non-executable phase plan superseded by W8; intended coordinator retained |
| `docs/designs/508-memdir.md` | Deleted in this pass | Unsafe automatic-memory plan superseded by W5/W7/W15 |
| `docs/designs/510-session-state.md` | Deleted in this pass | “Complete” snapshot contradicts cross-frontend audit; superseded by W12/W15 |
| `docs/designs/README.md` | Deleted in this pass | Index only for the three superseded issue designs |
| `docs/evidence-based-coding-guardrails.md` | Deleted in this pass | Research overclaims and VDD self-validation; valid directions carried into design |
| `docs/production-audit-problems.md` | Deleted in this pass | Partial June audit superseded by the complete living ledger |
| `docs/sandbox-threat-model.md` | Deleted in this pass | Present-tense enforcement claims contradicted by F-033/F-035/F-048/F-049 |
| `docs/subprocess-inventory.md` | Deleted in this pass | Calls unsafe/direct paths enforced; superseded by W18 and full source audit |
| `prompts/axis/agency/autonomous.md` | Retain live; repair later | Embedded runtime mode prompt; broadens scope without typed authority |
| `prompts/axis/agency/collaborative.md` | Retain live; repair later | Embedded runtime mode prompt; W17 will bind semantics |
| `prompts/axis/agency/surgical.md` | Retain live; repair later | Embedded runtime mode prompt; contradictions need evaluated contract |
| `prompts/axis/quality/architect.md` | Retain live; repair later | Embedded runtime mode prompt; style-only behavior |
| `prompts/axis/quality/minimal.md` | Retain live; repair later | Embedded runtime mode prompt; can suppress required boundary handling |
| `prompts/axis/quality/pragmatic.md` | Retain live; repair later | Embedded runtime mode prompt; style-only behavior |
| `prompts/axis/scope/adjacent.md` | Retain live; repair later | Embedded runtime mode prompt; W17 must enforce scope |
| `prompts/axis/scope/narrow.md` | Retain live; repair later | Embedded runtime mode prompt; not an actual blast-radius boundary |
| `prompts/axis/scope/unrestricted.md` | Retain live; repair later | Embedded runtime mode prompt; dangerously broad prose authority |
| `prompts/base/comms.md` | Retain live; repair later | Embedded runtime prompt; harmless style but part of monolithic authority |
| `prompts/base/identity.md` | Retain live; repair later | Embedded identity override/impersonation text; replace under W12 |
| `prompts/base/principles.md` | Retain live; repair later | Embedded prompt-only safety/quality rules; host controls must enforce them |
| `prompts/base/tools.md` | Retain live; repair later | Embedded obsolete XML tool protocol; direct deletion breaks build |
| `prompts/modifiers/bold.md` | Retain live; repair later | Embedded confidence prompt can discourage uncertainty reporting |
| `prompts/modifiers/context-pacing.md` | Retain live; repair later | Embedded pacing claim is disconnected from budgets/compaction |
| `prompts/modifiers/debug.md` | Retain live; repair later | Embedded mode can implement despite diagnosis-only user intent |
| `prompts/modifiers/director.md` | Retain live; repair later | Embedded coordinator prose over unused/non-executable subsystem |
| `prompts/modifiers/methodical.md` | Retain live; repair later | Embedded style prompt; W17 will define semantics |
| `prompts/modifiers/readonly.md` | Retain live; repair later | Embedded prose is not an effect boundary |
| `sandbox-followups.md` | Deleted in this pass | Every-box-checked assurance conflicts with audited sandbox behavior |
| `src/vdd/prompts/adversary.md` | Retain live; repair later | Embedded runtime verifier prompt; W28 requires evidence-bound schema/evals |
| `src/vdd/prompts/verifier.md` | Retain live; repair later | Embedded runtime prompt; binary verdict and same-artifact limits need repair |

## 8. Chronological audit log

- 2026-08-16: Living design and audit documents created before cleanup.
- 2026-08-16: `Cargo.toml` and `fuzz/Cargo.toml` read and initial findings
  recorded.
- 2026-08-16: Root and separate fuzz build artifacts cleaned with Cargo. Root
  `target` was reduced from approximately 82 GiB to an empty Cargo directory;
  fuzz cleanup reported 4,310 files and 1.3 GiB removed.
- 2026-08-16: Initial tracked-file inventory recorded: 546 files, including
  206 production Rust files, 234 integration-test Rust files, nine fuzz
  targets, and 68 Markdown files.
- 2026-08-16: Read `src/lib.rs` and all 2,878 lines of `src/main.rs`, including
  unit tests. Recorded migration fail-open startup, VDD system-authority
  promotion, duplicate legacy permissions, TUI rule construction, and manual
  composition-root findings.
- 2026-08-16: Runtime code remains unchanged.
- 2026-08-16: Read `src/context.rs` in full. Recorded the false XML-escaping
  authority boundary, denied-hook prompt-mutation gap, multipart prompt loss,
  prompt logging, missing context budgets, and rule-oriented arbitrary system
  insertion APIs.
- 2026-08-16: Read `src/prompt.rs` in full. Confirmed that the central prompt
  assembler promotes hook, memory, skill, project/custom, and environment text
  into an untyped system string and has no context budget or full tool-registry
  parity check.
- 2026-08-16: Read `src/skills.rs` in full and traced every public skill field
  across production source. Recorded automatic project authority, stale and
  nondeterministic caching, missing containment/limits, and parsed-but-unwired
  conditional activation and hooks while preserving working invocation
  controls in the remediation scope.
- 2026-08-16: Read `src/rules.rs` in full and enumerated all source and test
  consumers. The injector has a complete core removal target; its shared
  language/extension table is operationally used by auto-learning and is
  explicitly preserved for relocation.
- 2026-08-16: Read both behavioral-mode Rust files in full. Recorded that
  readonly, director, and context pacing are currently prompt-only claims,
  incompatible modifiers are accepted, and static tool prose is disconnected
  from runtime capability registration. All 19 included prompt assets were
  subsequently read in full and retained for runtime-aware W17 remediation.
- 2026-08-16: Read all 3,038 lines of `src/permissions.rs`. Confirmed fail-open
  classification, allow-before-deny precedence, tool-wide TUI approvals,
  heuristic auto-allow, repository-local unsafe persistence, raw audit logging,
  and duplicate/manual denial tracking. The permission feature remains a
  required repair, not a removal target.
- 2026-08-16: Read `src/tools/registry.rs` in full. Preserved its useful
  schema/handler co-location but recorded missing typed effects, unsafe default
  classification, unconditional advertisement of unavailable tools,
  synchronous/process-global MCP coupling, fake deferred loading, and the
  exact set of mutating/control handlers not represented in permissions.
- 2026-08-16: Read `src/tools/mod.rs` in full. Confirmed that legacy and even
  “gated” public dispatch remains optional/fail-open, disabled managers bypass
  their own hard safety, subagent tools sit outside classification, memory
  tools are advertised in comments but absent, and ordinary result text can
  spoof typed control markers.
- 2026-08-16: Read `src/tools/security.rs` in full. Preserved its useful
  descriptor-root and private-temp primitives, but recorded ambient-CWD
  auto-grants, todo-thread-local security identity, unavoidable project write
  access, incomplete re-registration checks, home-root exposure, secret-bearing
  `Debug`, and weak lifecycle coverage.
- 2026-08-16: Read `src/tools/file/secure_fs.rs` in full. The descriptor-
  relative Linux/Unix approach is worth keeping, but Windows is entirely
  blocked, Linux assumes `openat2`, directory handles are not bound to the
  authorizing context, reads are unbounded at this layer, and race/platform
  coverage is almost absent.
- 2026-08-16: Read `src/tools/file/mod.rs` in full. Recorded that read-before-
  write tracks a global/thread-local path rather than a file snapshot, ledger
  hashes reopen potentially different bytes, external changes never stale the
  marker, session buckets never clear, and relative write paths disagree with
  canonical ledger identities.
- 2026-08-16: Read `src/tools/file/list.rs` and `glob.rs` in full. Recorded
  unbounded listing, nondeterministic capped glob subsets, recursive/FD-heavy
  traversal, silent partial success, a default-hidden-directory logic error,
  and a test that fabricates the warning it claims to verify.
- 2026-08-16: Read `src/tools/file/grep.rs` and `write.rs` in full. Grep's cap
  occurs after unbounded per-hit/context allocation and its recursive search
  silently reports partial coverage; write uses strong no-follow creation but
  path-only stale reads and in-place truncation can lose concurrent/original
  content on failure.
- 2026-08-16: Read `src/tools/file/edit.rs` in full. Its exact/unique matching
  intent is useful, but empty/dense replace-all can expand without bounds,
  rewrites are non-atomic, and full old/new content is returned through a
  magic-string diff protocol with no secrecy or result budget.
- 2026-08-16: Read `src/tools/file/read.rs` in full. Confirmed that image support
  is base64 prose rather than a native attachment, large-file offset/limit
  recovery is impossible, long lines can yield no content, notebook/PDF output
  lacks complete budgets, and another source-shape test passes by matching its
  own assertion string.
- 2026-08-16: Read `src/tools/file/notebook.rs` in full. Preserved the intended
  notebook-edit feature but recorded mode-independent argument requirements,
  missing modern cell IDs/schema validation, unbounded whole-document
  processing, path-only concurrency checks, and destructive in-place rewrite.
- 2026-08-16: Read `src/tools/args.rs`, `accumulator.rs`, `ask_user.rs`, and
  `command.rs` in full. Confirmed that the typed result migration currently
  discards its structured data, streaming item bytes are unbounded, user
  questions are string-marker control events, and subprocess deadlines do not
  cover potentially blocking stdin writes.
- 2026-08-16: Read the complete six-file Bash subsystem in full. Preserved its
  useful Linux namespace/descriptor/seccomp containment and intended shell/job
  features, but found unsound first-program auto-approval, substring-forged
  Verifier evidence, non-profiled sandbox grants, absent control-path creation,
  scan/mount races, and incomplete background-job supervision.
- 2026-08-16: Read `src/tools/cron.rs` in full. Confirmed functional metadata
  CRUD but no scheduling/execution consumer, inert operational fields,
  unclassified future-agent mutation, repository-controlled prompts, and
  incomplete cross-platform/durable capability-safe storage.
- 2026-08-16: Read `src/tools/crosslink.rs` in full. Preserved structured
  issue/task state, but found all effects hidden behind one unclassified argv
  string, nontransactional partial mutation, unsafe/live SQLite migration,
  shared default agent sessions, unbounded graph output, and a false
  blocker-aware `next` claim.
- 2026-08-16: Read `src/tools/file_index.rs` and `grounding.rs` in full. The
  former does not implement its claimed gitignore semantics and traverses
  outside-root symlink targets without budgets; the latter usefully hydrates
  selected IDs but treats nearly every non-stale source as equally
  authoritative and lacks an aggregate result budget.
- 2026-08-16: Read all 3,371 lines of `src/tools/lsp.rs`. Preserved the intended
  nine-operation code-intelligence surface and several protocol hardening
  pieces, but confirmed broken call-hierarchy continuation, lossy workspace
  symbols, unbounded framing/results, ignored JSON-RPC errors, invalid
  per-call-server didOpen deduplication, and overly broad process capabilities.
- 2026-08-16: Read `src/tools/plan_mode.rs`, `remote_trigger.rs`, `skill.rs`,
  `task.rs`, `testutil.rs`, and `todo.rs` in full. Confirmed string-marker plan/
  skill control, wholly unwired remote triggering, duplicated unversioned task
  systems, and the unsafe coupling of todo thread-local identity to security,
  filesystem, process, and ledger state.
- 2026-08-16: Read `src/tools/tool_search.rs` in full and traced schema emission
  across providers, ACP, pipelines, REPL, and subagents. The claimed deferred
  loading is not active: every schema is still sent up front and search merely
  returns duplicate definitions as untrusted text, with an uncapped direct-
  selection path.
- 2026-08-16: Read all of `src/tools/web.rs`. Fetch/search/distillation are real
  capabilities with useful local bounds and tests, but their synchronous bridge
  blocks an executor thread and reports timeouts without cancelling spawned or
  blocking work; source/provenance, policy, aggregate budgets, and secondary-
  model accounting are incomplete.
- 2026-08-16: Read all 1,647 lines of `src/tools/worktree.rs` and searched every
  consumer. The intended isolation never becomes session state, destructive
  operations are unclassified, arbitrary linked worktrees are accepted, and a
  failed commit on the apply path is mislabeled as empty before force-removal.
- 2026-08-16: Read `src/services/mod.rs` and `mcp_registry.rs` and searched all
  production consumers. The service registry has none; plugin MCP registration
  is explicitly transport-less Phase 1, with unvalidated secret-bearing specs
  that derive `Debug` and never reach the existing MCP client.
- 2026-08-16: Read `src/services/auto_compactor.rs`, `feature_flags.rs`, and
  `analytics.rs` in full and traced consumers. Auto-compaction and flags have no
  production caller (and flag `Default` skips env loading); lifecycle analytics
  is real in two frontends but bypasses the nominal registry and logs session
  identifiers by default without a declared telemetry policy.
- 2026-08-16: Read `src/services/tool_executor.rs` and inspected every dispatch
  caller. It is real convergence infrastructure, but permission is bypassed by
  a bare Boolean and hooks, policy, observation, audit, cancellation, and result
  handling remain caller-selected phases with frontend-specific omissions.
- 2026-08-16: Read all of `src/services/policy.rs` and searched enforcement and
  cleanup callers. Policy is broadly used, but tool cap check/increment is
  racy, poison fails open, missing policy/session no-ops, resets are test-only,
  and provider token projections have no concurrent reservation.
- 2026-08-16: Read `src/services/rate_limit_mock.rs`; it is a self-tested,
  production-compiled fake with no proxy/provider/test consumer. The plan keeps
  deterministic throttling coverage but moves it to the real transport/runtime
  seam with provider-shaped and concurrency/cancellation scenarios.
- 2026-08-16: Read `src/services/lsp_pool.rs` and `lsp_diagnostics.rs` and
  searched all consumers. Both are explicitly unwired; the pool would cross
  workspace boundaries and leak dropped children, while diagnostics are
  globally/unboundedly stored and raw-rendered as prompt-shaped text.
- 2026-08-16: Read all 874 lines of `src/services/background.rs` and searched
  consumers. No job ever runs; exact-text memory dedup deletes metadata, agent
  summaries are stale concatenations, plugin jobs only emit false polling logs,
  and scheduling has no durable/concurrent/cancellable lifecycle.
- 2026-08-16: Read `src/session/audit.rs`, `state.rs`, and all 1,140 lines of
  `task.rs`. Audit is legacy-REPL-only and stores raw arguments unsafely;
  plan mode's read-only names include mutators and its dynamic opt-ins cannot
  succeed; task updates/deletion can leave partial or dangling graph state.
- 2026-08-16: Read all 1,467 lines of `src/auto_learn.rs` and traced every
  production caller. Automatic learning exists only in the legacy REPL;
  preference capture promotes unconfirmed heuristics, error fixes lack causal
  identity, normal multiline Clippy output cannot be learned, and degradation
  is unobserved. The intended feature is retained for a typed, reviewable,
  evaluated redesign; its neutral extension lookup is explicitly relocated
  before rule-injector removal.
- 2026-08-16: Read all 3,862 lines of `src/compaction.rs` and traced both the
  proxy path and alternate frontend paths. Proxy compaction is operational but
  replaces history with truncated prose promoted to system authority, uses a
  previous-turn count for the current request, and can commit orphan archives;
  REPL has a second weaker implementation while TUI/ACP do not compact.
- 2026-08-16: Read `src/claude_credentials.rs` and `src/codex_credentials.rs`
  in full and traced every consumer. Found raw refresh-token-bearing error logs,
  secret-bearing `Debug`, lossy writes to Claude Code's foreign store,
  synchronous unbounded refresh locking, unverified JWT-derived account/
  FedRAMP headers, and unsupported identity/private-schema coupling.
- 2026-08-16: Read `src/file_error.rs` and searched adoption. Typed causes are
  useful but generic helpers remain unbounded path-based I/O; “durable atomic”
  replacement can return failure after publishing and cannot communicate that
partial outcome.
- 2026-08-16: Read all 4,644 lines of `src/subagent.rs` and traced its live tool
  dispatch. Delegation is operational but worktree/read-only isolation is
  advisory, cleanup can delete staged, untracked or committed child work, final
  replies are absent from resumable transcripts, and terminal manager state
  breaks ordinary resume. Added F-122; the feature remains a W8 repair
  commitment with capability-bound workspaces, causal durable checkpoints,
  aggregate reservations and lossless artifact handoff.
- 2026-08-16: Read all 4,950 lines of `src/acp.rs`, including every unit test,
  and traced its session/tool runtime. Added F-123 through F-125: multiple ACP
  IDs share one mutable transcript/config/cancel authority, unbounded partial
  stdio/SSE is accepted as completion, and advertised modes/tools do not match
  enforced capabilities. The exact rule scan/injection path is now fully
  verified for W1 removal; ACP remains a supported W12 transport repair.
- 2026-08-16: Read all 3,635 lines of `src/proxy.rs`, including every test, and
  traced all public helpers. Added F-126 through F-129: configured provider
  credentials fund unauthenticated callers, all HTTP clients share one session,
  lifecycle controls vary by route, passthrough drops query/body, streaming is
  buffered/untranslated, and VDD depends on token tracking. The final live rule
  consumer flow is verified; W27 preserves and hardens the proxy gateway.
- 2026-08-16: Read all eight TUI-family production files in full, including all
  6,055 lines of `tui/app.rs` and every embedded test. Added F-130 through
  F-133: visual interruption does not cancel the live run; terminal/events and
  interactive prompts are unsupervised and unbounded; `@file` has an exploitable
  descriptor/name containment race; resume can mix displayed provider B with
  provider-A transport credentials; and both render paths lack production
  resource, Unicode, reasoning-privacy, and terminal-control boundaries. The
  working TUI, attachments, resume, themes, Markdown, and questions remain
  explicit W3/W10/W12/W15/W17 repair commitments. TUI rule injection is now
  fully located, and F-079/F-118 were expanded with its secret/reasoning paths.
- 2026-08-16: Read all 13 VDD production files in full (4,775 lines including
  every embedded test) and traced configuration, legacy/TUI/proxy consumers,
  provider transport, static analyzers, persistence and Crosslink effects.
  Added F-134 through F-137: live parsing converts malformed output to clean;
  adversary ranges can panic verification and the advertised truncation
  fail-safe is unwired; blocking mode is advisory or fail-open by frontend;
  transports lack status/body/aggregate review bounds; and model-generated
  evidence is promoted and persisted through nontransactional effects. F-011
  is now confirmed end to end. The useful adversarial review, verification,
  static-analysis and issue-tracking intent is preserved as W28 rather than
  removed.
- 2026-08-16: Reconciled the deterministic `find src -type f -name '*.rs'`
  inventory against every completed file/group entry. All 206 production Rust
  paths are covered. The prior 205 counter was a bookkeeping undercount in a
  grouped section, not an unread source file; no finding or disposition was
  inferred from the counter.
- 2026-08-16: Read the first 20 integration files alphabetically, from
  `acp_config_default_e2e.rs` through `bash_output_kill_dispatch_e2e.rs`, in
  full. Useful API-key validation, ask-user validation, real background-shell
  isolation and command-ledger checks coexist with extensive derive/serde/
  constructor duplication and false “end-to-end” labels. Specific weak tests
  accept either parse outcome, call a trait object without observing dispatch,
  condition assertions on whether expected output happened, or treat no panic
  as the contract. Others pin unsafe/incomplete behavior already found in
  production: `u32::MAX` loop caps, raw `AllowedPrompt` Debug, silent malformed
  tool/protocol normalization, unconfirmed preference learning, broken terminal
  subagent re-registration, partial API-key fingerprinting/lossy sentinel
  round-trips, and provider-independent compaction constants. Disposition is
  deferred until all test files are read and mapped.
- 2026-08-16: Reconciled that initial test batch against an independently
  numbered alphabetical inventory and found that the earlier “first 20” note
  had skipped file 20, `bash_integration.rs`; the files on either side had been
  read, so the label—not the source inventory—was wrong. Read all 1,224 lines
  of the missing file and completed test files 21–29 through
  `cli_exit_status_e2e.rs`, bringing the contiguous prefix to 29/234. The Bash
  integration file contains valuable real process, environment, Linux sandbox,
  symlink, network and agent-scoped cleanup checks, while also explicitly pins
  missing path validation/PowerShell support and permits race-dependent GC
  outcomes. The CLI suite contains substantial subprocess/protocol coverage,
  but also compiles README, architecture, comparison and capability-matrix
  prose into runtime acceptance and still requires `init` to create the rule
  injector tree. Claude-compat tests include no-assertion and either-outcome
  cases; credential tests pin unsupported client-impersonation literals already
  covered by F-081. These tests must be migrated with the corresponding repair,
  not cited as evidence that the current mechanisms are production-safe.
- 2026-08-16: Read integration files 30–40, from
  `compact_boundary_helpers_e2e.rs` through
  `coordinator_struct_methods_e2e.rs`, in full. Useful compaction persistence,
  request/config validation, hook-context escaping, task-DAG and permission-
  cache checks coexist with tests that accept either outcome, make no
  assertion, or only prove a constructor does not panic. The suite pins
  malformed compact-boundary metadata becoming `None`, unconstrained
  `usize::MAX` metadata, heuristic/static context-window assumptions, ignored
  operator compaction fields, best-effort memory extraction with no observable
  result, raw-target “always allow” caching and global environment/current-dir
  mutation. Most importantly, the coordinator façade suite explicitly asserts
  that `dispatch()` always returns the Phase-1 `NotImplemented` error; this
  directly corroborates F-120 and the W8 commitment to finish the intended
  coordinator rather than remove it. Context-injector tests cover hook-result
  handling and remain distinct from the deprecated filesystem rule injector
  slated for removal.
- 2026-08-16: Read integration files 41–50, from
  `cron_dispatch_validation_e2e.rs` through
  `estimate_tokens_boundaries_e2e.rs`, in full. Cron tests confirm a usable
  create/list/delete metadata store but no scheduler/executor; persisted
  `enabled`, `last_run` and `run_count` fields never demonstrate a run, and
  mutating registry dispatch remains outside mandatory permission targeting.
  Edit tests provide real disk/read-ledger coverage but do not test replacement
  against the exact bytes/generation that were approved and read. Enterprise
  policy tests thoroughly exercise isolated data structures without proving the
  runtime calls them. Three token-estimator suites heavily duplicate and pin a
  non-conservative heuristic—including zero tokens for one-to-three ASCII
  characters and all ASCII whitespace, fixed image costs and guessed context
  windows—that the production compaction audit already found unsafe as an
  admission/budget boundary. These are repair/evaluation inputs, not production
  readiness evidence.
- 2026-08-16: Read integration files 51–60, from
  `execute_tool_envelope_e2e.rs` through `file_index_scoring_e2e.rs`, in full.
  The legacy tool-wrapper suite tests correlation and malformed JSON but also
  treats arbitrarily large arguments and unknown extras as a no-panic contract,
  without proving canonical permission/state/budget enforcement. The rule-
  extension suite pins the deprecated injector's case-sensitive four-tool,
  filename-suffix heuristic and fail-empty behavior; it will be removed with
  that mechanism. Provider extraction tests pin first-block/first-candidate
  loss, malformed numeric usage becoming zero/absent, unvalidated `u64::MAX`
  accounting and permissive cross-shape fallback instead of typed protocol
  failures. File-index tests are useful for real traversal, cycles and depth,
  but omit the already-confirmed outbound-symlink case, ignore-list truth,
  deterministic limits and hostile Unicode alignment; several Unicode and
  whitespace cases explicitly accept any outcome/no panic. Feature-flag and
  analytics suites primarily test otherwise unwired abstractions. These results
  corroborate the existing provider, budget, rule-removal and secure-discovery
  workstreams.
- 2026-08-16: Read integration files 61–70, from `file_search_e2e.rs` through
  `grounding_context_dispatch_validation_e2e.rs`, in full. Real file-tool tests
  confirm useful read/write/edit/search behavior and leaf-symlink refusal, but
  explicitly pin silent large-read truncation, invalid-image pass-through and a
  raw-path `/.` heuristic that disables hidden/skip filtering; they do not cover
  ancestor symlinks, read-to-write generation identity or external replacement
  races. Glob validation and context-line overflow again accept ambiguous or
  silently defaulted outcomes. Tool-catalog tests pin counts/schema order rather
  than per-tool capability/permission/effect contracts. The context-window
  suite hard-codes a large, rapidly changing model table and permissive
  substring/default guesses rather than negotiated provider capabilities.
  Google transformation tests prove wire reshaping but also require unknown/tool
  roles to become ordinary `user` content and permit empty conversations,
  corroborating the lossy protocol-conversion findings. Grounding-context
  argument validation is bounded and comparatively strong, while still not an
  end-to-end ledger hydration/restart test.
- 2026-08-16: Read integration files 71–80, from `hook_error_display_e2e.rs`
  through `ledger_decision_e2e.rs`, in full. The hook suites exercise real
  subprocesses, output bounds, descendant termination and the strongest
  sandbox default, but deliberately preserve two unsafe policy contracts:
  only `PreToolUse` and `PermissionRequest` are deny-intent while all other
  lifecycle failures fail open, and an absent command allowlist means
  allow-all. Configuration merging replaces equal matchers with the later
  entry, and permission evaluation remains first-match, so broad allows can
  outrank later denials. Timeout coverage does not require a timeout result or
  blocked outcome. The 3,575-line omnibus `integration_tests.rs` mixes useful
  real filesystem/process coverage with duplicates and materially weak
  assertions: traversal, timeouts, background execution, binary reads,
  subagents and large output frequently accept either outcome, any non-empty
  output, or only no error. Its ignored network checks and construction-only
  VDD/engine checks do not substantiate the file's end-to-end production
  claims; its auto-learning tests instead pin automatic unconfirmed preference
  storage. The two keybinding files substantially duplicate unit/integration
  cases and intentionally require malformed binding strings to be silently
  skipped rather than surfaced as configuration errors. The ledger/decision
  suite provides useful authority, freshness, path-target and persistence
  checks, but its final-answer rule establishes only that verification and
  command observation IDs are present; it does not establish that a passing
  verifier semantically supports the final claim. These suites are retained as
  repair inputs, then consolidated around observable safety and product
  contracts rather than sprint-era coverage counts.
- 2026-08-16: Read integration files 81–100, from
  `list_files_dispatch_validation_e2e.rs` through
  `model_pricing_accessor_methods_e2e.rs`, in full. LSP coverage is validation
  and serde coverage only: no test completes an operation against a real
  language server, the advertised 10 MiB limit is tested only as a constant,
  and overflow cases merely require an error/no panic. Marketplace cache tests
  prove digest integrity after local tampering, not signed provenance,
  authorized publisher identity or safe extraction. The MCP suites contain
  valuable real stdio/HTTP handshakes, exact repository-server trust and
  revocation, Linux host-file/network sandboxing, timeout/disconnect handling,
  and error projection. However, they label the 2024-11-05 protocol version as
  current, define in-process `close()` as a no-op that permits post-close
  requests, advertise elicitation even though the tested default always
  cancels, and mainly test MCP resource handlers with no installed manager.
  Those resource handlers are explicitly classified permission-free because
  they are called read-only, despite accessing externally controlled resources
  through a process-wide manager. MCP specs/types also preserve raw secret
  headers/environment in `Debug`-capable values and permissively ignore unknown
  fields, corroborating F-093 and the typed secret/capability repair.

  The diagnostic renderer tests require untrusted paths/messages to be placed
  inside prompt-like XML tags without testing escaping or authority labeling.
  MEMORY.md discovery has a no-assertion test contaminated by a real user-global
  file, and its elicitation half is schema/no-op coverage. Four SQLite memory
  suites provide useful CRUD, persistence, concurrency and escaping evidence,
  but also cement automatic unconfirmed pattern/preference storage and
  confidence inflation; several purported ordering, eviction, expiry and empty
  value tests have no observation, tautological bounds or only row-id side
  effects. Recent-context prompt formatting is not given the escaping test that
  core memory receives. Migration tests allow every migration to fail while
  still passing the reported-outcome partition, save the ledger regardless,
  and never require the supposedly first-run migration to apply; this directly
  reinforces F-010. Proxy content tests cover untagged serde shapes but allow
  arbitrary content kinds/payload combinations without semantic, URI or size
  validation. Finally, pricing tests freeze mutable vendor rates and invented
  model identifiers, with nested `if let` branches that pass without exercising
  a fast tier, reinforcing F-066. Preserve the strong behavioral cases, replace
  the false operational claims, and consolidate the duplicated shape/constant
  suites.
- 2026-08-16: Read integration files 101–120, from
  `modes_axis_display_fromstr_e2e.rs` through
  `permission_outcome_dispatch_e2e.rs`, in full. Four behavior-mode files test
  enum parsing, serde and distinct embedded prompt fragments, but never prove
  that `Readonly`, scope, agency or quality changes a host capability or
  execution policy. This confirms the prompt-only mode problem rather than the
  advertised behavioral isolation. Notebook tests include useful real
  read/edit/write, schema-preservation and leaf-symlink refusal coverage, while
  relying on the legacy any-prior-read marker rather than an exact generation
  and omitting ancestor-symlink, concurrent replacement, atomic write and
  rollback cases. Validation tests accept `u64::MAX` on 64-bit and ignore
  arbitrary extra fields.

  OAuth tests pin unsupported Anthropic client-impersonation constants and
  state-machine/serde shapes without a real supported token exchange. The MCP
  OAuth flow remains disconnected from its client, and plain token bundles are
  round-tripped directly. More seriously, `oauth_store_session_e2e.rs` admits
  that `OAuthStore::new()` uses the shared real-user persistence file, writes a
  synthetic process-ID session there, and never removes it; the suite is not
  hermetic and can pollute or collide with user credentials/state. The OpenAI
  streaming accumulator silently defaults missing indices to zero, drops
  malformed fields, preallocates hundreds of empty slots on an index jump and
  finalizes those empty slots without completeness/schema/aggregate-byte
  checks. Output-style tests show that repository-relative prompt instructions
  are treated as trusted once XML metacharacters are escaped; escaping markup
  does not neutralize instruction authority, and file writes are direct,
  ambient-CWD based and unbounded. The session guard's only implicit-drop
  persistence test conditionally reads a directory and asserts nothing, so it
  does not test the irreversible failure path in F-067.

  Path-constraint tests explicitly require an absent or empty process-global
  constraint slot to allow `rm -rf /`, and therefore corroborate the global,
  fail-open boundary. Persistence-path tests exercise useful lexical and leaf-
  symlink refusals but use a process-global environment escape hatch without
  actually serializing the tests, and do not cover symlink ancestors or
  descriptor-relative creation. Permission tests then freeze multiple unsafe
  contracts: no-target tools cannot be denied; raw command globs and heuristic
  scores auto-allow `cat /etc/hostname` and lexical `src/` edits; sticky TUI
  allow/deny sets can contain the same or empty tool name; unrestricted mode
  ignores session denials and allows unknown/malformed targets. Most
  decisively, the public permission-wrapper suite requires a disabled manager
  to return `Allowed` for `rm -rf /` and requires even the `strict` wrapper to
  honor that bypass, while direct-manager tests claim hard safety still applies.
  This is direct executable evidence for F-031, not production readiness.
- 2026-08-16: Read integration files 121–140, from
  `permission_rule_serde_shape_e2e.rs` through
  `pricing_catalog_deeper_e2e.rs`, in full. Permission-rule tests accept empty
  names/patterns and unbounded values, and scoring tests again require unknown
  tools to receive a perfect safe score. Most importantly, source-wide tracing
  after the MCP permission suite proved `mcp_tool_allowed` has no production
  consumer. Its tests require absent, case-mismatched and empty identities to
  allow all, despite calling the configuration deny-by-default; this is now
  F-138 and has a W2/W6 repair commitment.

  Pipeline tests expose rather than close the stream boundary: the nominal
  one-MiB line-cap helper explicitly accepts a 10 MB buffer containing a
  newline and is absent from live stream parsing, while retry tests require up
  to eleven POSTs without a total deadline/reservation. The safe-tool name list
  exempts task/subagent/control/network operations independently of effect
  metadata. Accumulator tests check concatenation but not terminal closure,
  bounded arguments or malformed-event failure. Endpoint/header tests require
  any provider name to succeed when a Claude OAuth token is present and do not
  verify extra-header conflicts; plan-mode marker tests continue to encode
  trusted control as stateless JSON text. Plan policy tests prove configured
  MCP/plugin opt-ins can never admit a concrete dynamic tool and exercise only
  path checks before the eventual write, not a descriptor-bound transaction.

  Plugin suites provide useful real local discovery/git, leaf-symlink refusal,
  Ed25519 primitive and strict parsing cases. They also require local plugins
  to load enabled by default, missing/corrupt installed state to degrade to
  empty, unspecified refs to wildcard all revisions, and default marketplace
  policy to admit every source. A GitHub block/allow identity is deliberately
  distinct from the equivalent raw Git URL, enabling alias-dependent policy;
  signatures cover caller-supplied bytes rather than a canonical package tree,
  publisher identity and update chain. One hostile-URL test only prints when
  the diagnostic lacks its asserted security marker, and documents an empty-
  host parser gap without testing it. The omnibus skill test mutates process-
  global home/CWD under a mutex no other test shares, silently drops invalid
  skills, and requires repository skills to override user skills; its installed
  registry assertion is a tautology. Policy-enforcer tests are sequential and
  cannot detect the production check/record race. Pricing suites pin hundreds
  of mutable vendor/model constants, arbitrary-suffix prefix matching and
  conditional branches, while audit logging tests require arbitrary raw JSON
  to append without sensitivity, redaction, byte, retention or safe-session-ID
  coverage. These are consolidation/evaluation inputs, not reliable currency
  or extension-supply-chain evidence.
- 2026-08-16: Read integration files 141–160, from `prompt_builder_e2e.rs`
  through `rules_accessors_e2e.rs`, in full. Prompt-builder tests incorrectly
  equate XML metacharacter escaping with resistance to semantic instruction
  injection: repository output styles and hook bodies remain elevated as
  active instructions, while the working directory and other dynamic context
  lack typed authority/provenance and aggregate context limits. The legacy
  builder suite is mostly duplicate wrapper equivalence and permits either
  result for an empty working directory.

  Provider suites contain useful serialization, secret-redaction, header,
  endpoint and response-shape regression cases, but their repeated `E2E`
  label is materially misleading. Most mirror static implementation tables or
  feed synthetic JSON directly into an adapter. The wiremock cases accept any
  POST at a broad path and do not validate request body/header compatibility,
  so they cannot support the claim that an upstream parser would accept the
  request. Mutable vendor endpoints, model-prefix routing, model-listing
  support, reasoning controls and future model identifiers are frozen into
  duplicated local matrices. Unknown model routing silently falls back to a
  configured provider, Ollama is absent from `ProviderKind`, arbitrary model
  text is interpolated into Google's endpoint, malformed/empty roles and
  one-MiB content are accepted as no-panic cases, and several response tests
  preserve first-choice/first-block lossy extraction. Replace the duplication
  with a versioned capability catalog, schema/fixture conformance tests, and a
  small opt-in live compatibility matrix; retain the adapter behavior rather
  than deleting provider support.

  Proxy-config tests explicitly require unknown YAML fields to be ignored,
  making obsolete or misspelled security settings silent. Proxy translation
  preserves arbitrary flattened request fields and routes by brittle model
  name inference. Rate-limit/background coverage proves only a synchronous
  mock and tick scheduler, not async cancellation, overlap, persistence,
  backpressure or shutdown behavior. Read-file tests exercise useful real
  reads and ledger recording but their header falsely claims an oversize-file
  case that does not exist; they omit ancestor symlinks/races and allow
  `u64::MAX` limits. Registry-envelope suites are heavily duplicated and call
  handlers under the process-global current security context. The catalog
  invariant explicitly requires only five handlers to expose a permission
  target, thereby freezing permission-free treatment for other network,
  process, worktree, scheduling, task and external-resource effects instead of
  checking effect metadata and policy coverage for every published tool.

  Remote-trigger tests validate schemes but preserve byte-exact arbitrary
  headers and do not apply the MCP transport's network-destination controls to
  webhooks; HTTPS loopback/private/metadata destinations and redirect/header
  forwarding behavior are untested. MCP transport construction performs a
  live-DNS policy check, but the suite cannot prove the subsequently connected
  peer is the validated address or exclude rebinding. The final rules suite is
  entirely for the deprecated rule injector and even accepts either
  loaded/skipped behavior for empty rules. Remove those rule tests with the
  mechanism; preserve their useful UTF-8/file-loader lessons only where they
  apply to the typed skill/instruction system. These files reinforce the
  existing W2/W3/W6/W10/W18/W22 provider, prompt-authority, capability,
  configuration and egress repairs.
- 2026-08-16: Read integration files 161–180, from
  `rules_context_e2e.rs` through `subagent_config_result_shape_e2e.rs`, in
  full. The remaining rule-engine suites confirm that arbitrary top-level
  Markdown becomes global imperative context, unknown filename prefixes
  become global rules, bodies are preserved verbatim, and XML escaping is
  mislabeled a prompt-injection defense. They and their production mechanism
  are removal targets; generic prompt escaping must not be represented as an
  authority boundary.

  Linux sandbox tests are high-value, adversarial, locally contained evidence:
  they exercise host-file/network/kernel isolation, special files, external
  hard links, inherited descriptors, seccomp, resource limits, environment
  filtering and toolchain mounts. The per-session filesystem suite also races
  intermediate directory swaps and proves descriptor-relative confinement for
  reads and writes. Preserve these tests, while coordinating process-global
  session/CWD/environment fixtures under one harness. The macOS/Windows test
  only checks that unsupported production backends fail closed; it does not
  supply those platforms with a usable sandbox.

  Service tests show plugin autoupdate is explicitly a phase-one trace-only
  stub, not an updater. The background scheduler is synchronous and the LSP
  pool permits another process for the same language while one is checked out;
  its alleged displaced-child death is never observed. There are no pool
  admission limits, protocol initialization/health checks, cancellation or
  shutdown-race tests. Session compaction coverage never compacts or evaluates
  a summary: it checks heuristic token arithmetic, a forgeable formatted
  boundary marker and static model-window substring lookups. Session-manager
  tests claim in-flight mutation coverage but explicitly perform none, accept
  `<= keep_count` cleanup, and omit atomic/crash/corrupt/concurrent recovery.
  Usage recording has no idempotency/duplicate-event/overflow tests, the
  metric ring uses a fixed count rather than a byte budget, legacy total usage
  is deliberately not restored into live totals, and raw task/file/note text
  is rendered into handoff Markdown without provenance or authority handling.

  Skill suites contain useful parser/alias/walker cases but intentionally
  accept unknown frontmatter, unknown effort values and invalid globs that are
  silently skipped. Hooks remain arbitrary untyped YAML, skill names and
  envelope attributes are not tested with hostile values, and several suites
  duplicate the same dispatch errors. CWD-changing tests use local-only locks
  and non-RAII restoration. The production review already established which
  model/effort/tool/user controls are connected; preserve and finish skills as
  typed, provenance-aware instruction packages rather than treating their raw
  XML-shaped envelope as security. Stop-condition tests pin post-hoc strict
  `>` thresholds, so exactly the configured budget is admitted and the next
  request may overshoot without a reservation; only token totals are modeled.
  Streaming tests again require malformed or out-of-order events to disappear
  silently and omit byte/index/terminal-state bounds. Finally, the subagent
  suite is almost entirely public-struct construction: it permits unvalidated
  model/isolation/resume identifiers and million-turn results, asserts secret-
  capable task/output/path values appear in `Debug`, and never runs an agent or
  proves worktree cleanup/isolation. These results reinforce W2/W4/W7/W8/W10,
  while the strong sandbox/filesystem evidence should remain as a regression
  foundation.
- 2026-08-16: Read integration files 181–200, from
  `subagent_plan_mode_e2e.rs` through
  `tool_call_accumulator_finalize_filter_e2e.rs`, in full. Plan-mode tests
  explicitly document that MCP/plugin opt-in remains unable to admit any
  concrete prefixed tool because the subsequent allowlist compares the full
  dynamic name to bare static names. Plan-file authorization is checked before
  the eventual write instead of being a descriptor-bound capability, and
  subagent identity is a thread-local Boolean that tests celebrate as
  thread-isolated even though async work may move threads. Subagent taxonomy,
  slash-command and tool-schema suites are static catalog checks using stale
  three-tier model aliases; they do not run, resume, cancel or contain an
  agent, enforce argument limits, or prove that advertised per-agent tools are
  runtime capabilities. The source-text subprocess boundary test is useful as
  a tripwire but is bypassable by aliases/wrappers/format changes and guards
  only a hand-maintained path/string list; replace it with an architecture
  boundary/lint plus the already-strong runtime sandbox probes. Prompt-block
  coverage is trivial concatenation duplication.

  The session task dispatcher and manager provide useful real create/update/
  dependency behavior, but unknown `task_get` is a successful `null`, user
  fields have no count/byte/control limits, no suite rejects a multi-node cycle
  in this manager, and direct completion can bypass the only tested blocker
  guard on entering `in_progress`. Automatic demotion enforces one active task
  even when the agent architecture supports parallel work. Rendering tests
  insert raw task text into model-facing summaries. The separate coordinator
  queue does detect cycles, but `next_ready` does not atomically claim work,
  public `get_mut` bypasses transition invariants, a failed dependency leaves
  descendants stuck without a propagated terminal decision, and this more
  formal system is disconnected from real dispatch. Multiple task-builder,
  formatter and status suites substantially duplicate shape/Display tests.
  Consolidate and finish one durable, evidence-linked DAG rather than remove
  planning.

  Team memory tests prove isolated SQLite scopes in direct construction, but
  the `Both` write is not tested for transactionality/partial failure and the
  production startup remains unwired. The same file freezes legacy
  `ultrathink` magic phrases, Claude-Code environment compatibility and a
  31,999-token constant as configuration behavior. Teammate suites only build
  otherwise-disconnected state objects; they allow arbitrary transcript paths
  and unbounded terminal reasons and omit cancellation, timeout, heartbeat,
  recovery and actual worker ownership. Two thinking-budget suites are near
  duplicates and explicitly allow a zero explicit budget, `u32::MAX` provider
  default, unrecognized effort fallback and effective budgets independent of
  the `enabled` flag; provider configs accept arbitrary base URLs and
  colliding secret-capable headers. Replace magic inference/static vendor
  guesses with negotiated typed provider capabilities and validated bounds.

  Todo “session isolation” tests never write data to two sessions, so they
  prove only that empty reads are empty. The implementation's thread-local
  identity/default bucket remains shared with security and ledger authority.
  Todo validation caps each `content` field but not item count, aggregate size
  or `activeForm`; multiple active items are accepted after a warning and an
  all-completed write erases the plan/history. Pricing tests duplicate mutable
  unversioned rates and floating-point math without provenance or timestamp.
  Finally, the tool-call accumulator requires incomplete calls to disappear
  silently, preserves arbitrary call types, accepts unvalidated argument text,
  retains state after finalization, and has no index/count/byte/duplicate-ID or
  terminal-completeness bounds. These findings reinforce W2/W4/W6/W7/W8/W9/
  W10/W12 while preserving functional planning, memory, thinking and
  delegation goals.
- 2026-08-16: Read integration files 201–220, from
  `tool_call_function_call_serde_e2e.rs` through `vdd_triage_e2e.rs`, in
  full. The tool-call serde suite requires a few fields but deliberately
  accepts arbitrary call types, empty/Unicode identifiers and raw unvalidated
  argument strings. The dispatch-context suite mostly repeats registry shape
  checks and confirms handlers can receive an absent thread-local security
  context outside the canonical permission lifecycle. Control signals remain
  forgeable JSON embedded in ordinary tool-result text: legacy marker shims
  survive, signal type/source/success are not consistently required, malformed
  entries disappear, and question/plan approval payloads remain arbitrary JSON
  or free-form strings. The interceptor suite explicitly preserves the
  pseudo-XML mechanism that executes marker-shaped assistant prose, deletes
  marker-shaped result content and silently drops chunks after a 4 MiB cap;
  this is the unsafe obsolete control design already scheduled for retirement
  in F-121, not a reason to remove native local tools.

  Registry handler/schema/search tests provide useful catalog drift checks but
  freeze several incomplete designs: only five handlers expose permission
  targets; all supposedly deferred schemas are already sent; `tool_search`
  returns redundant XML text, silently ignores unknown requested names and
  cannot make a newly returned tool callable; schemas generally lack closed
  objects, aggregate limits, effect metadata and provider-dialect conformance.
  Cron descriptions admit that OpenClaudia stores only metadata while an
  external scheduler must execute it, so scheduling remains a preserve-and-
  finish commitment. Five legacy product Markdown files are compile-time
  `include_str!` inputs and their wording is asserted here. Deleting them in
  this documentation-only pass would break the Rust build; W29 must first
  replace those marketing-text assertions and decouple or migrate the build
  inputs.

  The broad `tools_e2e` header claims file/background-shell coverage its body
  does not contain, while accumulator tests normalize or silently discard
  malformed/incomplete state and can allocate 512 slots for one high-index
  delta. The security suite calls lexical validators rather than the claimed
  execution path, manually reimplements an “atomic write” instead of testing
  production code, treats empty path constraints as unrestricted and locks in
  a session/thread-local read-before-write marker with no artifact-generation
  binding. Analytics coverage proves only no-panic tracing calls, not durable
  metrics, redaction or bounded cardinality. Transcript helpers write beneath
  the real Claude configuration home despite constructing a temporary current
  directory; hostile IDs, concurrency, crash recovery, existing symlinks/
  permissions, redaction, retention and size are absent, corrupt JSONL is
  silently skipped, and raw prompts/results are persisted. Provider request
  transforms again test synthetic object shapes while accepting empty messages,
  unbounded token requests and unvalidated temperatures/models; hard-coded
  speculative model names are not live compatibility evidence.

  The base-URL suite's header promises decimal/hex IP coverage but contains no
  such cases. It allows HTTP, does not exercise redirects, resolved-peer
  binding, DNS rebinding, credentials in diagnostic URLs or less familiar
  non-global address classes. The command-denylist suite locks in a short,
  trivially bypassable substring catalog, accepts empty commands and permits
  destructive operations outside those spellings; the real sandbox/capability
  boundary must remain authoritative. Transition/TUI tests are honest narrow
  data/format and no-panic checks, not orchestration or terminal rendering
  evidence.

  VDD confabulation tests explicitly terminate on only the latest numeric
  false-positive rate and preserve weak 32-byte-prefix collisions. The session
  suite is public-struct/serde coverage rather than a lifecycle test and admits
  mutually inconsistent counters/status plus durable raw builder/adversary
  content. VDD configuration tests check defaults but not rejection of unknown,
  contradictory, zero, huge, non-finite or secret-bearing settings; arbitrary
  analyzer commands and paths are accepted and raw adversary logging defaults
  on. Finally, triage tests prove the detailed parser distinguishes malformed
  output, then explicitly preserve the legacy wrapper that collapses parse
  error and valid clean output to the same empty vector. Injection tests promote
  untrusted model findings into XML-shaped imperative text without adversarial
  escaping cases. This directly corroborates F-134–F-137 and W28 rather than
  supporting a production-ready VDD claim.

- 2026-08-16: Read integration files 221–234, from
  `web_config_search_e2e.rs` through
  `write_file_dispatch_validation_e2e.rs`, in full. The web output/shape suites
  preserve unescaped titles, snippets, URLs, HTML and scripts as model-facing
  Markdown. A 50 KiB body cap and UTF-8-safe truncation are useful, but title,
  URL and aggregate search output are not bounded; the tests explicitly call
  byte passthrough a content-safety property rather than marking retrieved text
  as untrusted evidence. The default preapproval catalog is a mutable ambient
  domain trust list covering all subdomains; tests accept URL userinfo and do
  not prove that preapproval is separate from the non-bypassable SSRF/connect-
  peer policy. Distillation provider/model/size/domain values have only default
  and serde tests, with no validation or real distillation lifecycle.

  `web_integration.rs` contains valuable real calls into the SSRF validator and
  parser, but much alleged success/filter coverage reconstructs private
  production formatting and hostname parsing in the test itself. Such copies
  cannot prove the actual implementation. That copied hostname parser is also
  not a URL parser and its `None` branch retains malformed results under both
  allow and block filters. The “citation” regression injects an imperative
  all-caps reminder into ordinary untrusted search output. Browser tests are
  ignored by default and return success when the opt-in variable is absent or
  the actual fetch fails, so they cannot act as a compatibility gate. The SSRF
  suites strongly cover many literal ranges, yet headers promise hex/octal and
  public-IP counter-cases that are absent, explicitly note a NUL-normalization
  issue without testing it, and do not exercise redirects, DNS rebinding,
  validated-peer binding, credential-bearing URLs or bounded response reads.
  The registry URL suite mainly proves a case-sensitive prefix gate, executes
  with no permission manager and even accepts either outcome for uppercase
  schemes.

  Four webhook suites are almost entirely in-memory struct, display and map
  lifecycle tests. They freeze secret-capable headers as freely cloned,
  comparable and `Debug`-printable strings, include raw URLs in errors, accept
  userinfo, and explicitly allow plaintext loopback when a constructor flag is
  selected. They do not send a webhook or test permission, payload schema,
  secret resolution, persistence, destination/redirect/DNS/IP enforcement,
  response bounds, retry/idempotency, concurrency or audit. This corroborates
  F-056: remote triggers are an incomplete capability to finish, while the
  current registry-only surface must never be advertised as operational.

  Worktree dispatch tests provide useful wrong-type, control-character and
  option-injection cases, but directly dispatch without permission context,
  ignore unknown arguments, run `list_worktrees` against the audit repository
  and never create/remove/merge/discard a real isolated worktree. A hand-built
  character denylist is more restrictive and less authoritative than Git's
  ref grammar; real containment, dirty-state, rollback and failure behavior are
  absent. README wording is another compile-time test dependency. The combined
  LSP suite only checks a process-global open-path set and binary-presence
  heuristic: it does not connect to, initialize, supervise or shut down an LSP
  server, and its memory-ordering claim performs no write.

  The reminder suite repeatedly labels XML entity escaping as prompt-injection
  resistance, while deliberately preserving control bytes, NUL and unbounded
  imperative text inside a `system-reminder` authority label. Escaping is only
  serialization correctness and does not make external instructions trusted.
  Finally, write-file tests do exercise actual new-file writes and a failed-
  read overwrite gate, but bypass the permission lifecycle, use the shared
  default session for most cases, omit the permission-target coverage claimed
  by their header, and do not bind read approval to an exact file generation.
  Size/resource limits, ancestor swaps, symlinks, concurrent writers, modes,
  durability and successful-read-then-changed-file races remain absent. The
  ledger test classifies a direct tool write as Git authority, reinforcing the
  provenance conflation already scheduled for W12/W15 repair.

### F-084 — Blast-radius guardrails are bypassable, partial and cross-session global

Severity: Critical
Status: Confirmed in `src/guardrails.rs` and all dispatch consumers

Strict globs run against raw lexical strings, so an allowed path such as
`src/../.env` can resolve outside its matched scope. Invalid strict patterns are
silently discarded, potentially turning an allowlist into allow-all. One mutable
process-global engine/file set serves every run; resets differ by frontend and
proxy never resets. Only selected file handlers/TUI reads are checked, leaving
other mutation/read mechanisms outside the advertised blast radius.

Required outcome: Express blast radius as typed capabilities and atomic effect/
resource reservations in W2/W10, scoped to one run/workspace/policy generation.
Match canonical descriptor-backed resource identities and resolved operations,
not user path prose; configuration compilation is all-or-nothing. Cover file,
process, worktree, LSP, plugin, subagent, MCP and remote effects identically,
commit/release quotas on actual outcomes, and prove traversal/symlink/alias plus
concurrent-session isolation end to end.

### F-085 — Configured diff blocks and quality gates do not gate completion or mutation

Severity: High
Status: Confirmed in `src/guardrails.rs`, file handlers and frontend callers

Diff thresholds are checked only after writes and every action becomes warning
text; `Block` and `InjectFindings` do not have distinct effects. Quality
`run_after` and `fail_action` are never read: gates run after batches, required
failures remain advisory, and results can be injected as system/verification
text. Counts are handler guesses rather than committed snapshot diffs, while
Bash/worktree/outside changes are missing.

Required outcome: Compute a versioned workspace change set at the canonical
transaction boundary and evaluate typed policy before commit/finalization.
Implement each documented cadence/action deliberately, including user-visible
blocked/recovery states, or reject unsupported configuration at startup. Run
approved deterministic quality checks as scoped budgeted effects against the
exact artifact generation; bind results to command/toolchain/config/input/output
receipts and never grant verifier authority to arbitrary prose or exit code.
- 2026-08-16: Read all 2,254 lines of `src/guardrails.rs` and traced every
  caller. Strict path controls are lexical/global/partial, invalid policies fail
  open, diff block actions and quality cadence/failure actions are unused, and
  configurable verification commands remain advisory noncanonical effects.
- 2026-08-16: Read all three hook modules in full (3,764 lines total) and
  traced every construction, lifecycle producer and output consumer. Hooks are
  a capability to repair, not delete, but ambient Claude/project imports
  currently gain executable/instruction authority; managed merge is not
  dominant; command admission is unbounded/bypassable; and event/output/failure
  semantics differ across proxy, TUI, legacy REPL, ACP and subagent paths.
- 2026-08-16: Read all five runtime keybinding files and traced configuration,
  TUI, and legacy consumers. The public contextual resolver is unwired; TUI
  ignores configured bindings; legacy consults them only while streaming and
  cannot resolve its default chords; normalization/collision/prefix behavior is
  incomplete. The intended configuration feature remains a repair commitment.
- 2026-08-16: Read all four MCP implementation files in full (5,693 lines
  total), including every test, and traced startup, schema advertisement,
  dispatch, resource, global-manager and shutdown consumers across every
  frontend. Compared the implementation with the official MCP `2026-07-28`
  release/specification. Dynamic MCP is not end-to-end reachable; the fixed
  legacy wire model loses current semantics; transport ownership and bounds are
  unsafe; and OAuth/elicitation/in-process modules are scaffolds. Findings
  preserve MCP as a repair commitment while retiring only superseded protocol
  shapes after current replacements exist.
- 2026-08-16: Read both `src/memdir` production files in full (806 lines)
  and searched every consumer. The loader/truncation implementation and tests
  are real, but its own documentation confirms zero production wiring and the
  promised background memory lifecycle is absent. Recorded safe integration
  into the canonical memory service rather than deleting the intended feature.
- 2026-08-16: Read all 1,569 lines of `src/oauth.rs`, every unit test, and
  the CLI/proxy/provider call chain. Confirmed real PKCE/persistence work but no
  operational refresh/expiry/revocation, dead API-key/auth-mode state and unsafe
  secret/session handling. Current official Anthropic guidance also confirms
  the reused Claude Code identity path is prohibited for third-party software;
  recorded an authorized replacement, not removal of supported login intent.
- 2026-08-16: Read all 5,177 lines of `src/pipeline.rs`, every test, and
  traced request, turn, tool, permission, history and TUI-loop consumers. The
  useful TUI turn engine is not canonical across frontends; native continuation
  is lossy, its SSE cap is unwired, partial streams/loop aborts become completion,
  and static safe-tool/retry policy is not effect- or budget-bound. Updated
  existing architecture/provider findings and added the distinct false-terminal
  finding F-096.
- 2026-08-16: Read all nine plugin production files in full (9,305 lines,
  including every embedded unit test) and traced every non-test caller for
  discovery, installation, updates, commands, hooks, MCP, LSP, agents and
  skills. The capability is retained, but project metadata can cross trust
  scopes, signature enforcement is non-operational, package mutation is not a
  secure transaction, and most declared components remain disconnected.
  Compared the repair with current SLSA 1.2, TUF 1.0.33, Sigstore bundle and
  OpenAI agent runtime guidance; added F-097 through F-101 and W26.
- 2026-08-16: Read all 2,173 lines of `src/web.rs`, including every unit test,
  and re-traced its already-audited tool facade. Direct fetching has meaningful
  streamed bounds and SSRF checks, but validation is not tied to the actual
  dial, browser page activity bypasses it, and default Chromium uses persistent
  project state with unsupervised resource exposure. Added F-102/F-103 and W23;
  fetch/search/browser/distillation remain repair commitments.
- 2026-08-16: Read all 698 lines of `src/speculation/mod.rs`, including every
  unit test, and searched all production consumers. Despite documented pipeline
  integration it has none; enabled construction is always a no-op, and the
  current trait cannot own safe execution/promotion/cancellation. Added F-104
  and strengthened W7 while preserving the latency objective as an evaluated
  optimization rather than deleting it for being unfinished.
- 2026-08-16: Read all 510 lines of `src/slash_commands.rs`, including every
  unit test. It is a pair of manually maintained legacy/TUI help catalogues,
  not an executable canonical registry; plugin dispatch is explicitly outside
  it, and its tests prove table/README agreement rather than parser/dispatcher
  reachability. Final command-lifecycle findings are deferred until the legacy
  command registry and TUI dispatch files are fully read.
- 2026-08-16: Read all 873 lines of
  `src/cli/repl/command_registry.rs` and traced its production dispatch caller.
  Together with the help catalogue it confirms F-105: metadata is duplicated,
  alias collisions overwrite silently, handlers mix parsing with ambient
  side effects, and the TUI/plugin paths remain separate. The user-facing
  command outcomes are preserved for migration into W12, not removed.
- 2026-08-16: Read the eight small CLI module/config/display files in full:
  `src/cli/mod.rs`, `src/cli/commands/mod.rs`, `config_cmd.rs`, and all five
  `src/cli/display` files. Recorded deprecated rule tips in the removal ledger.
  The result renderer reparses arbitrary text as magic-marker diffs, can panic
  on reversed markers, computes unbounded diffs and prints raw terminal control
  sequences; added F-106. Basic config/theme/tip presentation remains useful.
- 2026-08-16: Read `src/cli/commands/acp.rs`, `loop_cmd.rs`, and `start.rs` in
  full. These are thin live entrypoints, but ACP directly selects the unsupported
  foreign Claude credential path (F-081), loop mode explicitly accepts an
  unlimited iteration value outside W10, and proxy-facing bind/auth claims need
  reconciliation during the full proxy read. The entrypoints are retained for
  migration into the canonical runtime.
- 2026-08-16: Read all 390 lines of `src/cli/commands/auth.rs`, including its
  source-shape tests. It confirms the previously recorded OAuth findings: state
  validation is optional, the command mutates Claude Code's foreign credential
  store, native sessions are unbounded plaintext state, generated auth mode is
  not honored downstream, and success promises automatic subscription use.
  W3 preserves supported login/logout/status while removing impersonation and
  foreign-store mutation.
- 2026-08-16: Read all 438 lines of `src/cli/commands/init.rs` and traced both
  callers. It is a real project setup feature to preserve, but it deletes config
  before replacement, overwrites pre-existing hook/rule assets, publishes a
  partial multi-file generation, installs the deprecated rule injector, and
  scaffolds unsafe/misleading hook/guardrail claims. Added F-107 and exact W1/
  W15/W25 cleanup requirements.
- 2026-08-16: Read all 679 lines of `src/cli/commands/doctor.rs`, including unit
  tests. It sends real credentials/custom headers to project-selectable provider
  URLs, can mutate credential/plugin state, and labels fabricated/empty/local
  checks as runtime health. Added F-108; useful diagnostics remain a repair
  commitment, while rule-engine health claims are now fully verified for W1
  deletion.
- 2026-08-16: Read all 505 lines of `src/cli/print_mode.rs`, including tests.
  The useful one-shot feature bypasses canonical context/run state and owns an
  unbounded provider request/stream; EOF after partial text is success and
  partial stdout precedes protocol failure. Added F-109 and retained print mode
  as a thin no-tools W12 frontend.
- 2026-08-16: Read all 616 lines of `src/cli/commit_pipeline.rs` and all 512
  lines of `src/cli/repl/review.rs`, including tests. Git review/commit operates
  outside capabilities with untrusted Git helpers, unbounded subprocesses and
  racy all-file staging; API-key setup echoes secrets and can write/truncate a
  repository config through symlinks. Added F-110/F-111 while preserving Git
  workflow and credential setup behind W24 and W3/W14/W15 respectively.
- 2026-08-16: Read `src/cli/repl/keybindings.rs`, `models.rs`, `permissions.rs`
  and `session_io.rs` in full (766 lines including tests) and traced their live
  callers. Existing keybinding/model/compaction/memory findings remain; the
  direct `!` shell is a second full-host executor gated only by bypassable
  substrings, so F-112 was added. Export/short-term summaries remain useful but
  require W5/W12/W15 bounds, provenance, consent and atomic storage.
- 2026-08-16: Read `src/cli/repl/input.rs`, `mod.rs`, `plan_mode.rs` and
  `vim.rs` in full (1,862 lines including tests) and searched all consumers.
  Added F-113 through F-115: attachment/editor/question I/O bypasses the run
  capability and budgets; approval is not bound atomically to reviewed plan
  bytes; and Vim's shadow state machine is not connected to real key/buffer
  events (the working Rustyline Vi mode is preserved).
  All three user-facing capabilities remain explicit repair commitments.
- 2026-08-16: Read all 4,800 lines of `src/cli/chat_repl.rs`, including every
  test, and traced its setup, provider loops, tool lifecycle, commands and
  persistence. It confirms F-004/F-096 end to end: three provider loops and an
  XML fallback differ in hooks/audit/history/failure handling; stream/follow-up
  errors and turn caps do not become canonical terminal states. Gemini stores
  each processed tool result twice. Rule injection is fully located. Added
  F-116 for the private-note authority leak and broken `/btw` transcript flow;
  corrected F-115 to preserve the genuinely working Rustyline Vi feature while
  consolidating its disconnected shadow state machine.
- 2026-08-16: Read all 4,409 lines of `src/cli/repl/slash.rs`, including every
  test, and traced each result into the completed controller/registry reads.
  Added F-117 through F-119: project branch files can forge canonical message
  authority; generic raw reasoning is persisted/revealed without protocol or
  privacy semantics; and `/plan` changes only the label while the real gate
  remains inactive. Dynamic model fetching is unreachable in the async legacy
  REPL, cost remains a hard-coded per-token guess, MCP/hook status overclaims
  health, and direct Git/plugin/filesystem side effects reinforce F-105/W12.
  The exact `/init` rule-injector call is now fully verified.
- 2026-08-16: Read all nine `src/coordinator` files in full (3,042 lines,
  including every test) and searched all consumers. The formal coordinator is
  entirely unused and `dispatch` is deliberately `NotImplemented`; the CLI
  flag only changes the system prompt. Added F-120. The queue/state/permission
  ideas are retained for consolidation into the canonical task/run runtime,
  while the duplicate disconnected representations are removed only after
  functional delegation, failure, permission and resume parity exists.
- 2026-08-16: Read all 2,249 lines of `src/tool_intercept.rs`, including every
  test, and re-traced its live legacy fallback. Added F-121. The bounded scanner
  contains real defensive work, but the fundamental mechanism reparses prose as
  execution, deletes marker-shaped content, ambiguously maps parameters and
  admits unbounded call batches. Local tool compatibility is preserved through
  typed provider adapters; only the text-as-control fallback is selected for
  retirement after parity.

### F-056 — Remote trigger is registry-only scaffolding with no invocation path

Severity: High
Status: Confirmed in `src/tools/remote_trigger.rs` and source-wide consumer search

The module validates and stores named webhook URLs/headers in memory, but no
production code constructs the registry, registers it as a tool, configures
endpoints, or sends a request. It has no payload/result contract, permission
effect, SSRF/redirect/DNS policy, deadline/response limit, retry/idempotency,
audit, or secret type. Documentation presents a remote-trigger tool while the
feature is unreachable.

Required outcome: Preserve named external actions only as host-configured typed
capabilities. Resolve secrets outside model context; enforce destination and
redirect/DNS/IP policy, exact payload schema, scoped approval, deadlines,
response limits, idempotency/retry semantics, redacted audit, and typed result.
Do not advertise unavailable registrations.

### F-057 — Planning/task state is duplicated and todo state carries security identity

Severity: High
Status: Confirmed across todo/task/plan tools, Crosslink, security consumers, and manager persistence

At least four planning/task representations exist: full-replacement process-
memory todos, `session::TaskManager`, Crosslink issues/work sessions, and plan-
mode state. They have different IDs, status/dependency semantics, persistence,
frontends, and cleanup. The todo module's thread-local session key is also the
identity source for filesystem trackers, subprocesses, ledger, and security.
Failed security-context creation only logs and still installs the ID; absent
guards use a shared `__default__` bucket.

Required outcome: Separate immutable run/security context from planning data.
Choose one canonical versioned task graph with stable IDs, ownership/sharing,
optimistic updates, checkpoints/history, budgets, and frontend views; migrate
useful todo/TaskManager/Crosslink semantics through explicit compatibility.
Missing run context fails closed and no task helper determines host authority.

### F-058 — Deferred tool loading is not implemented and direct selection bypasses its cap

Severity: High
Status: Confirmed in `src/tools/tool_search.rs`, registry, and all production API schema callers

All current model request paths send the complete tool registry. `tool_search`
returns selected schemas only as ordinary XML-shaped text, which neither the
provider API nor the executor treats as a newly registered tool set. Its direct
selection path also ignores the result ceiling and permits an unbounded list of
duplicate schemas. The feature therefore adds a tool and tokens without
delivering the advertised context reduction, while its suggested envelope-
parsing implementation would create a data-to-authority injection boundary.

Required outcome: Keep progressive discovery, but make the host/runtime own an
availability- and capability-filtered catalog and activate schemas through an
explicit provider-supported or next-request runtime transition. Bound queries,
selection count, schema bytes, and namespaces; return typed misses/availability;
never interpret arbitrary result text as tool authority. Measure token, latency,
retrieval, and task-success effects against the full-registry baseline.

### F-059 — Web-tool timeouts report completion without stopping the work

Severity: High
Status: Confirmed across `src/tools/web.rs` and the complete descendant browser lifecycle in `src/web.rs`

The synchronous dispatcher times out only its channel receive and drops the
receiver; the spawned future keeps running. Browser and search work execute in
`spawn_blocking`, whose timeout likewise cannot cancel work that has begun.
Meanwhile the caller is synchronously parked, including on a documented async
runtime path. The reported tool lifetime therefore disagrees with the actual
network/process lifetime and can starve the runtime or accumulate orphan work.

Required outcome: Make tool dispatch async end to end with per-run cancellation,
admission/concurrency limits, aggregate deadlines, supervised browser/process
ownership, and join/reap semantics. A terminal result is emitted only after work
and descendants stop or a typed still-running handle is deliberately returned;
trace late effects and test cancellation under stalled DNS, body, provider,
renderer, and blocking-backend phases.

### F-060 — Worktree “apply changes” can destroy changes after any commit failure

Severity: Critical
Status: Confirmed in `src/tools/worktree.rs::merge_into_main` and exit orchestration

After `git add -A`, the code treats every failed/timed-out commit as
`NothingToMerge`, not just Git's clean-tree status. Exit then calls `git
worktree remove --force`. A routine missing author identity, signing failure,
filter/config error, lock contention, or timeout can therefore erase all work
despite `apply_changes=true` explicitly requesting preservation.

Required outcome: Classify every Git outcome structurally and fail closed on
anything except a proven clean index/worktree. Snapshot/recovery state before
mutation; bind expected repo/worktree/base/target identities and generations;
stage only reviewed run-owned changes; preview and separately authorize commit,
merge, and removal; never force-remove until the intended commit is verified
reachable from the approved target and all retained data has a recovery path.

### F-061 — Worktree isolation never becomes an owned session capability

Severity: High
Status: Confirmed in `src/tools/worktree.rs` and source-wide consumer search

Enter returns a filesystem path in prose, but no runtime stores it as the active
workspace or rebinds file, Bash, LSP, task, and ledger capabilities. Exit accepts
any accessible linked worktree rather than a handle owned by the run. The
process-global active set and exported generation are not consumed by the
runtime. The feature creates directories/branches but does not provide the
claimed isolated agent workspace lifecycle.

Required outcome: Return an opaque typed workspace handle registered to the
run, repository identity, base commit, branch, path capability, and generation.
All subsequent tools resolve relative resources through that immutable active
workspace until an authorized transition. Reconcile/recover durable ownership
after restart, enforce exclusive operations, and make preview/apply/discard/
close explicit idempotent states with typed partial-failure recovery.

### F-062 — Hard enterprise caps race and fail open

Severity: Critical
Status: Confirmed in `src/services/policy.rs` and production caller search

Tool-cap check and increment are separate locked operations, permitting
concurrent calls to over-consume the final slot. A poisoned mutex makes counts
read as zero and all future increments no-op. Missing enforcer or session also
deliberately disables enforcement, and token checks reserve nothing against
concurrent requests. These behaviors contradict a hard enterprise boundary.

Required outcome: Load immutable policy only from authenticated host-managed
state and make it mandatory at the canonical runtime boundary. Atomically
reserve named/effect/token/cost/concurrency capacity under a run/call receipt;
commit actual usage or release unused reservation; fail closed on state error;
persist/reconcile durable limits where promised; enforce the same policy on all
frontends, auxiliary model calls, subagents, MCP, browsers, and scheduled runs.

### F-063 — Memory consolidation deletes distinct metadata instead of merging it

Severity: High
Status: Confirmed in `src/services/background.rs::dedup_archival`; job is currently unwired

Rows with byte-identical content are treated as duplicates even when tags and
provenance differ. The job keeps the newest row and deletes the others without
merging metadata, transactionality, version checks, tombstones, or recovery.
Failures can leave partial deletion, and concurrent changes can be erased after
the initial unversioned read.

Required outcome: Define semantic identity and retention policy before any
automatic merge. Produce a bounded dry-run/trace, merge all approved metadata
with provenance and conflict rules in one transaction using expected versions,
retain tombstones/recovery, and test concurrent updates/partial crashes. If
exact-text dedup cannot demonstrate safe value over indexed duplicate retrieval,
do not run destructive consolidation.

### F-064 — Plan mode's read-only gate explicitly allows mutating facades

Severity: Critical
Status: Confirmed in `src/session/state.rs` against registry/tool implementations

The static plan-mode allowlist includes `task` and `crosslink`. Those names each
dispatch read and mutation operations, including task creation/update/deletion
and SQLite migration; no argument/effect classification narrows them. Web fetch
also permits external egress and optional paid distillation. The gate therefore
does not enforce its read-only claim, and MCP/plugin opt-in flags cannot make a
dynamically prefixed name pass the separate static list.

Required outcome: Plan mode is a typed runtime state whose advertised and
executable tools are filtered by exact predeclared effects/capabilities. Allow
only read/query variants by construction; separately request scoped approval
for any state mutation/egress/cost. Bind enter/exit/plan approval to run and plan
versions, and test every registered operation through the public executor.

### F-065 — Task graph updates can return failure after corrupting state

Severity: High
Status: Confirmed in `src/session/task.rs`

Status transition demotes the current task before dependency validation, so a
later cycle/missing-edge error leaves a partial mutation. New blockers are not
considered when validating a same-call transition to in-progress. Deleting a
task leaves reciprocal edge references dangling. These violate the manager's
documented single-active, blocker, and symmetric-edge invariants.

Required outcome: Validate the complete proposed graph/status change against a
snapshot first, then atomically commit under an expected version. Deletion uses
tombstones or transactionally removes/reconciles all edges; updates can remove
edges and clear fields; every result returns new version/conflict and invariant
checks run on deserialize/recovery as well as live mutation.

### F-066 — Cost accounting silently caps large usage and has no session-safe provenance

Severity: High
Status: Confirmed in `src/session/pricing.rs` and every production consumer

Each token component above `u32::MAX` is reduced to `u32::MAX` before cost
calculation, so extreme accumulated/provider-hostile values are underbilled.
Rates and totals use provenance-free `f64`; non-Anthropic cache rates are
fabricated defaults; provider tiers and non-token billables are absent. The
unknown-model warning called session state is an unconsumed thread-local flag,
while actual displays exist only in the legacy REPL and mix estimates with
partial reported usage.

Required outcome: Preserve visible cost controls, but account checked `u64`
usage using fixed-point currency units and a versioned price manifest with
provider/source/effective-date/tier metadata. Prefer provider-returned billed
usage and reconcile it to request receipts; represent estimates and unknown
categories explicitly. Store uncertainty and totals in canonical run/session
state, apply atomic cost reservations from W10, and test overflow, concurrency,
frontend parity, price changes, and invoice samples.

### F-067 — Ending a session can irrecoverably discard the state it failed to persist

Severity: Critical
Status: Confirmed in `src/session/mod.rs`; all production lifecycle consumers searched

`end_session` removes the sole active `Session` before attempting three separate
file writes. On any failure it returns only an error source, not the removed
session, while teardown still runs. The caller therefore cannot perform the
documented retry and progress may be lost. Successful individual atomic renames
do not make the session JSON, `latest.json`, and handoff one transaction, so
crash/concurrent generations can disagree.

Required outcome: Checkpoint immutable versioned session snapshots without
releasing the active generation; publish a transaction manifest/commit point
and reconcile partial writes on recovery. Only transition to ended and release
run capabilities after the durable commit is confirmed. Return recoverable
state plus typed partial outcome on failure, use host-owned capability-safe
storage, and test injected failure/crash after every write and sync boundary.

### F-068 — Permission bypass is persisted and reactivated by session resume

Severity: Critical
Status: Confirmed across `src/state/categories.rs`, `state/session.rs`, persistence, TUI and legacy REPL execution

`PermissionsState::bypass_mode` says it does not persist, but derives normal
serialization inside every session document. Resuming calls `apply_loaded`,
which replaces the state set from the current command-line invocation; legacy
tool execution then directly honors the loaded Boolean. A session saved under
an earlier unrestricted launch can silently reactivate bypass during a later
normal launch. Mirrored trust and persistence-control flags share the same
authority/data confusion.

Required outcome: Never deserialize live authority from a conversation file.
Derive bypass, trust, approvals, policy and capabilities only from the current
authenticated host invocation/configuration. Persistent documents may retain
non-authoritative historical audit facts, explicitly typed as such; resume
revalidates all resources and the UI shows the newly effective policy.

### F-069 — Panicking state mutations retain partial changes without emitting events

Severity: High
Status: Confirmed and explicitly test-pinned in `src/state/store.rs`

`StateStore::update` mutates the live value in place. If its closure panics, the
lock is poisoned and event emission is skipped, but all later accesses recover
the poisoned inner value and preserve whatever partial mutation occurred. This
contradicts the comment that subscribers never act on partial updates and makes
event-driven transcript/analytics state diverge silently.

Required outcome: Validate a proposed immutable snapshot/transaction first,
then atomically publish it with a monotonic generation and corresponding events.
Panic/corruption leaves the previous committed generation intact or moves the
run into explicit recovery; subscribers reconcile exact versions, never infer
durable state from a lossy notification count.

### F-070 — Session schema versions below current bypass the migration framework

Severity: High
Status: Confirmed in `src/state/persist.rs`

The persistence layer rejects only versions greater than one. Version zero or
any older value is deserialized directly into the current flattened Rust shape,
despite documentation promising version-specific migrations. Unknown fields
are accepted, unvalidated IDs/paths/authority survive, and same-version data can
be silently lost on the next write.

Required outcome: Dispatch every exact supported version to a bounded,
deterministic migration that takes an explicit trusted storage/workspace
context, validates the complete result, strips live authority, and preserves or
rejects unknown data deliberately. Never overwrite the source until a durable,
recoverable migrated generation is verified.

### F-071 — Startup writes an unverified, unconsumed schema claim into another shared transcript directory

Severity: High
Status: Confirmed in `src/migrations/stamp_transcript_schema_v1.rs` and source-wide consumer search

Every startup may write `~/.claude/projects/.schema-version.json` claiming all
transcripts are V1 without inspecting or owning them. No OpenClaudia code reads
the marker. Malformed/older content is replaced non-atomically with a two-field
object, potentially destroying metadata written by another producer sharing
the directory. This is not a meaningful migration boundary.

Required outcome: Put an exact schema and producer identity in each
OpenClaudia-owned transcript/envelope or an OpenClaudia-owned transactional
manifest. Discover/import foreign transcripts read-only through explicit
version detection. Stop writing the shared global marker and remove its tests
only after the truthful migration/compatibility path is operational.

### F-072 — Transcript resume has no trustworthy causal or filesystem identity

Severity: High
Status: Confirmed in `src/transcript.rs`, state event/watermark producers and TUI consumers

Session IDs are interpolated into paths without validation; append/read/find
follow symlinks and scanning can pick the first cross-project match. Appended
lines and watermarks commit separately, so crashes duplicate entries, while
same-length rewrites and undo may never trigger reconciliation. Resume skips
corrupt middle lines and treats a magic string in ordinary system content as a
compaction boundary capable of discarding all prior context.

Required outcome: Use capability-bound transcript IDs and descriptor-relative
storage. Append typed causally sequenced events with idempotency IDs, integrity
links and a transactional checkpoint/watermark; represent compaction as a host-
created event referencing exact source generations. Validate complete continuity
on resume and return typed partial/recovery states. Keep OpenClaudia storage
owned; import foreign logs read-only through explicit schema/provenance checks.

### F-073 — Project-controlled and inferred memory is promoted to system authority

Severity: Critical
Status: Confirmed in `src/memory.rs`, startup, prompt assembly and auto-memory consumers

Interactive startup opens a repository-local SQLite database and places learned
preferences/recent work in the system prompt, explicitly telling the model to
follow them. Repository/pre-existing and automatically inferred text therefore
acquires instruction authority. XML delimiter escaping does not neutralize
instruction meaning, and the learned-preference formatter does not even apply
that escaping.

Required outcome: Store private durable memory in host-owned capability-safe
storage and treat project/team imports as untrusted evidence. Retrieval returns
typed bounded records with source, actor, workspace/generation, sensitivity,
confidence basis, age and citations. The canonical runtime—not stored prose—
decides how evidence informs a plan. Preferences require explicit attribution,
review/correction/expiry and never become invisible system authority.

### F-074 — Memory opens unsupported future schemas and can bless partial migrations

Severity: High
Status: Confirmed in `src/memory.rs::ensure_schema_on` / `run_migrations_on`

Only versions below four trigger migration; a database reporting a greater
`MAX(schema_version)` is opened without compatibility rejection. Earlier schema
steps and the final version record are not one transaction, and `IF NOT EXISTS`
can accept malformed leftovers before marking the database current. V4 has a
savepoint but commits separately from the version marker.

Required outcome: Acquire an exclusive store migration lease, reject future or
unknown exact schemas, verify the source schema/integrity, snapshot/backup,
perform bounded migration plus semantic validation in one recoverable commit,
and open the store only after its durable version receipt matches. Test crash,
disk-full and corruption at every step.

### F-075 — Team memory uses unrelated database row IDs as shared record identity

Severity: Critical
Status: Confirmed in `src/team_memory.rs`; feature is currently unwired

User and team databases allocate IDs independently, but a `Both` write returns
only the user ID and `Both` deletion uses that number as the team tombstone. As
soon as counters differ, deletion hides the wrong team record. Merged archival
reads do not implement documented override/deduplication, and seeded user core
placeholders ensure real team core values are never reached.

Required outcome: Assign a stable globally unique logical memory ID plus store/
workspace/version identity at capture. Use explicit user overlay records and
version-bound tombstones, not counter coincidence. Cross-scope writes have a
durable idempotent operation/reconciliation log; merged retrieval applies a
documented version/conflict policy and one global budget/rank. Authenticate team
membership/roles and test concurrent/offline conflicts and store replacement.

### F-076 — Automatic learning converts correlation and wording into durable truth

Severity: Critical
Status: Confirmed in `src/auto_learn.rs`, its legacy-REPL callers, and the memory prompt path

The only wired frontend persists preference-shaped text without confirmation
and stores any later successful shell command as the resolution of the last
failure. Blocked/expanded messages can be captured, previous assistant context
is ignored, normal Clippy diagnostics cannot satisfy the line-local parser, and
relative versus canonical path identities defeat same-file resolution. These
records lack causal IDs/provenance/review and are later presented as system
instructions. TUI and ACP omit the entire capture lifecycle, while database
degradation is counted but never surfaced.

Required outcome: Preserve learning as a canonical post-event pipeline over W12
typed run/tool/message receipts. Capture observations separately from claims;
associate exact call, artifact, workspace and generation IDs; require evidence
or explicit user confirmation before a preference/fix becomes durable; retain
source citations and contradiction/review/expiry/delete state. Retrieval remains
untrusted bounded evidence under W5. Apply one consent/privacy/retention policy
and visible partial/degraded outcome in every frontend, and evaluate downstream
task benefit, false-learning rate and harmful-memory rate before default enablement.

### F-077 — Compaction silently loses causal state and promotes the remainder to system authority

Severity: Critical
Status: Confirmed in `src/compaction.rs` and proxy integration

The live proxy path calls a function labeled summary that merely truncates and
concatenates messages, replaces exact tool traffic with generic markers, and
inserts the result as a system message. It uses the previous turn's provider
count to trigger rewriting the current request, compares that historical count
to a new heuristic estimate, and accepts any decrease even if the request still
does not fit. Archival/extracted-memory writes precede validation and are
nontransactional, so failed/no-op/retried compactions can leave partial durable
claims that the canonical request never committed.

Required outcome: Compact a versioned typed conversation/task/tool-event graph,
not role prose. Reserve a verified provider-specific context/output budget,
select a causally closed source generation, produce a bounded summary/checkpoint
with citations to exact events/artifacts and explicit unresolved state, validate
required-fact/tool-chain retention and provider message invariants, then atomically
publish request checkpoint, archive and watermark under an idempotency ID. Stored
or summarized data remains non-authoritative evidence. Return a typed cannot-fit/
partial/retry state and prove quality with tokenizer calibration, repeated-
compaction retention, injection and downstream task-success evals.

### F-078 — Automatic compaction is three incompatible frontend behaviors

Severity: High
Status: Confirmed by source-wide consumer trace

Proxy invokes `ContextCompactor`; legacy REPL separately clips the oldest JSON
messages to 200-character previews without hooks/archive/boundaries; TUI and ACP
estimate tokens but do not compact. The richer microcompaction, custom summary
prompt, archive/extraction and `AutoCompactor` service paths are otherwise
unwired. A session's survival semantics therefore depend on entrypoint, while
configuration fields imply control they do not exercise.

Required outcome: Put one compaction/checkpoint transition in the canonical W12
run runtime and make every frontend request/display the same typed outcome.
Delete the duplicate REPL algorithm and unused service/config surfaces only
after their intended partial compaction, hooks, archival, user-instruction and
observability behavior is implemented or deliberately rejected with evidence.

### F-079 — Authentication secrets can be emitted by logs and derived `Debug`

Severity: Critical
Status: Confirmed in credential modules and TUI provider/transport event bundles

Claude refresh failure bodies are logged raw even though the adjacent comment
says they may echo refresh tokens. Claude credential structs derive `Debug`, as
does `CodexAuthMaterial`, whose API-key variant contains the unredacted key.
Both adapters turn tokens into ordinary string header tuples that are freely
cloned through frontend/provider state. The TUI compounds this by deriving
`Debug` for `ProviderSwitchAuth`, `ProviderSwitch`, and `ApiClient`, which hold
raw API-key capability material, resolved authorization/custom headers, Claude
tokens, and VDD authentication. These secret-bearing values also cross the
unbounded application event channel as ordinary clonable strings.

Required outcome: Use a non-`Debug`, zeroizing secret/capability type end to end;
construct redacting sensitive headers only at the hardened transport boundary;
forbid body/header/token logging by type and apply structured secret scanning in
tests. Sanitize provider errors before every sink, bound retained error text,
minimize token lifetime/copies, and add incident guidance for existing debug logs.

### F-080 — OpenClaudia can corrupt the shared Claude Code credential store

Severity: Critical
Status: Confirmed in `src/claude_credentials.rs`

Refresh/login overwrites `~/.claude/.credentials.json` from a partial Rust
schema, dropping all unknown fields owned by the other application. The local
advisory lock does not prove coordination with that producer, path checks race
and ignore parent symlinks, and a network refresh is performed while a blocking
unbounded lock is held. A successful rename can therefore be secure in mode yet
still commit stale, lossy or redirected foreign state.

Required outcome: Do not mutate another application's credential document
unless its supported API provides a versioned transactional contract. Prefer an
official provider login/delegation/keyring integration and keep OpenClaudia-owned
metadata separately. If shared-store compatibility remains read-only, use a
bounded descriptor/capability read with owner/mode/link checks and exact schema
handling; refresh through the owning client/service. Make async credential
acquisition cancellable/deadlined and expose typed unavailable/stale/scope states.

### F-081 — Anthropic subscription auth is implemented through client impersonation

Severity: Critical
Status: Confirmed in source and against Anthropic's current official third-party authentication guidance

OpenClaudia reuses Claude Code's client ID, subscriber token and dated beta
headers and inserts the false identity assertion that it is Anthropic's official
CLI. The repository treats a public identifier and observed request behavior as
permission, without a supported third-party OAuth/delegation contract or
capability negotiation. Anthropic's current guidance says third-party and open-
source tools should use API-key authentication through Claude Console, a
supported cloud provider, or an authorized Agent SDK path, and explicitly
prohibits identity misrepresentation or routing third-party traffic against
subscription limits
([official authentication guidance](https://support.claude.com/en/articles/13189465-log-in-to-your-claude-account)).

Required outcome: Preserve subscription login only if Anthropic offers a
documented third-party/native-client or Agent SDK flow authorizing this
application and use OpenClaudia's registered identity, redirect/scopes and
current capabilities. Otherwise require an officially supported API credential,
cloud provider or gateway endpoint. Never claim another product's identity to
unlock access; fail with a clear migration path rather than silently falling
back or chasing private beta literals.

### F-082 — Unverified Codex token payloads control account and FedRAMP headers

Severity: High
Status: Confirmed in `src/codex_credentials.rs`

JWT payloads are base64-decoded without signature, issuer, audience or expiry
verification. Their fields, or conflicting unvalidated JSON fields, determine
the account-selection and `X-OpenAI-Fedramp` headers sent to a hard-coded ChatGPT
backend. The adapter also infers through unknown future auth modes and knowingly
forwards stale tokens because it does not participate in the owning client's
refresh/keyring lifecycle.

Required outcome: Use an official supported Codex/OpenAI credential interface
that returns verified account/audience/compliance metadata and renewable scoped
capabilities. Treat token payloads as opaque unless verified against the proper
issuer/keys/claims; reject conflicts and unknown schema/modes. Keep normal OpenAI
API-key auth separate from ChatGPT/Codex backend auth, with explicit endpoint,
scope, refresh, expiry and enterprise-boundary tests.

### F-083 — Generic “durable atomic” writes can fail after publishing new state

Severity: High
Status: Confirmed in `src/file_error.rs::write_file_atomic`

The Unix helper renames the staged file over the destination and only then
fsyncs the parent directory. If that sync fails it returns an undifferentiated
error although readers already see new bytes. Combined with path-based parent
resolution and no generation/target identity, callers cannot know whether to
retry, reconcile or preserve the previous logical operation.

Required outcome: Put each store behind an authorized descriptor-relative
transaction API with expected generation/content identity, explicit file class
and bounds. Return a typed state machine such as unchanged, committed-durable,
published-durability-uncertain or recovered; reconcile uncertain publication
before retry. Validate owner/type/mode/link/root, preserve or deliberately set
permissions, and test concurrent writers plus crash/disk/fsync faults on every
supported platform.

## 9. Completion reconciliation

The audit is complete. Every one of the original 546 tracked paths was read or,
for lock/database/binary structures, fully parsed and inspected with the
appropriate format-aware tooling. This includes all 206 production Rust files,
234 integration-test files, nine fuzz targets plus their crate files, 68
Markdown files, hooks/scripts/configuration, the complete root and fuzz lock
graphs, and all tracked runtime/binary artifacts. No sample-based file review
was used.

The ledger contains 143 unique findings: 68 Critical, 65 High, one High that
becomes Critical if wired unchanged, eight Medium, and one explicit product
decision. Severity reflects potential impact and boundary failure, not an
assertion that every path is reachable in every frontend. Each finding records
the observed mechanism and a repair outcome; incomplete intended features are
preserved in the companion design rather than treated as deletion candidates.

Cleanup performed in this pass:

- deleted 37 fully read, individually justified, superseded Markdown files;
- rewrote seven active/build-sensitive Markdown references so they no longer
  present route existence or circular string assertions as production-readiness
  evidence;
- created this audit and the canonical remediation design;
- retained all 21 compiled prompt fragments and all three runtime plugin
  Markdown assets for implementation-aware repair;
- retained the historical SQLite/session artifacts and generated bytecode
  because this pass authorized Markdown cleanup only; F-141/W0/W13 specify
  export, redaction, archival and later source-control removal without silently
  destroying historical evidence.

The 24 tracked Markdown rule assets are deleted. The runtime rule engine,
Python hook injectors, activation settings, generated-init behavior, callers,
and tests remain unchanged in this documentation-only pass. Section 6 and W1
are the complete, verified deletion manifest for stripping that mechanism in an
implementation change while relocating the neutral file-extension helper that
auto-learning still uses.

Implementation follow-up (2026-08-16): that manifest has now been applied in
[S-007](remediation-slices/007-remove-legacy-rule-injector.md). The slice records
the exact artifact generation, deterministic gates, independently reviewed
corrections, unresolved coverage note, and retrospective VDD queue. The
paragraph above remains the historical scope statement for the audit pass, not
a description of the post-S-007 worktree.

The research cross-check strengthened rather than replaced the source findings:
current agent-evaluation guidance favors multi-turn traces, repeated trials and
grading actual environment outcomes; a July 2026 coding-benchmark audit shows
that prompts, tests and reference outcomes themselves require independent
review; current long-horizon security work includes cumulative tool, task,
intent and memory attacks; and emerging reliability work exercises equivalent
input perturbations and injected API/tool failures. These are now explicit W0,
W2, W5, W12, W13 and W23 acceptance dimensions in the companion design
([agent-eval guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents),
[coding-eval audit](https://openai.com/index/separating-signal-from-noise-coding-evaluations/),
[AgentLAB](https://arxiv.org/abs/2602.16901),
[ReliabilityBench](https://arxiv.org/abs/2601.06112)).

Validation and scope reconciliation:

- before cleanup, formatting, strict Clippy for all targets/features, and the
  full all-features test suite passed; `cargo audit` found no known
  vulnerabilities and did identify the two unmaintained transitive packages
  recorded under F-009;
- `cargo clean` removed approximately 82 GiB from the root target and 1.3 GiB
  (4,310 files) from the separate fuzz target;
- after cleanup, formatting, both locked metadata graphs, README YAML parsing,
  exact documentation assertions, and README/matrix command parity passed;
- the final changed-file check contains only Markdown: 37 deletions, seven
  rewrites, and two new canonical documents. No Rust, Python, configuration,
  database, image, manifest, lockfile, or other runtime file was changed;
- the complete test suite was deliberately not rebuilt after `cargo clean`,
  because this pass changed documentation only and rebuilding would immediately
  recreate the stale 80-plus-GiB artifact tree the user asked to remove.

## 10. Post-audit architectural decision: rotating agents and canonical VDD

After completion of the source audit, the product direction was clarified for
long-horizon context management. OpenClaudia should not depend on one agent
transcript growing until attention, authority and causal state degrade. The
canonical runtime will instead support a capability-limited planner that creates
fresh workers for bounded semantic task slices and is itself replaced at typed
checkpoints. Durable user intent, task/decision state, artifact generations,
approvals, evidence and budgets survive; agent contexts do not become the source
of truth. Rotation and handoff are runtime state transitions, not model-written
summary conventions.

VDD is selected as the verifier for this hierarchy. It must run through the
same canonical harness, hard guardrails, Reality/grounding evidence graph, typed
tools, provider adapters, filesystem/process/network policy, budgets,
cancellation, tracing and terminal-state rules as every other agent. It receives
a separate run and context, enforced alternate provider/endpoint/model-family
identity, independent budgets and a normally read-only capability profile. The
verifier can inspect the exact snapshot and run bounded tests or analyzers in
disposable scratch state, but cannot modify the reviewed artifact, approve
itself, publish, commit or set task completion.

Worker claims remain provisional evidence. Deterministic checks run first; VDD
then returns an artifact-generation-bound `pass`, `fail`, `inconclusive` or
`verifier_error` receipt with checked citations. Parser/transport failure,
truncation, timeout, model-identity collision, alternate-model unavailability or
later artifact mutation cannot become a pass. Each slice is verified before
acceptance and the assembled result receives a separate integration review.
Because worker and verifier still share harness code, high-risk gates also
require independent compiler/test/CI/static-analysis and digest evidence.

This is a user-directed target architecture recorded in Section 4.6 and
W8/W12/W28 of the companion design, not a claim about current implementation.
No runtime code or configuration was changed when recording it.

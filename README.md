# OpenClaudia

OpenClaudia is an experimental Rust agent harness with multiple frontends,
provider adapters, local tools, sessions, extensions, and review machinery.

> Production status (audited 2026-08-16): **not production-ready**. Compilation,
> linting, and the existing test suite pass, but the full file-by-file audit found
> critical reachability, authority, isolation, cancellation, provider-state, and
> persistence gaps. Do not use the current build with sensitive repositories,
> credentials, an externally reachable proxy, or unattended destructive work.
> See [the full audit](docs/full-codebase-audit-2026-08-16.md) and
> [remediation design](docs/production-remediation-design.md).

![OpenClaudia Logo](images/logo.jpg)

## Current implementation surface

The repository contains real implementations for the following outcomes, but
presence is not a production-readiness claim. Support differs by frontend and
provider; the audit records the exact gaps.

- Provider adapters for Anthropic, OpenAI, Google, DeepSeek, Qwen, Z.AI, Kimi,
  MiniMax, Ollama, and OpenAI-compatible endpoints.
- A full-screen TUI, legacy line REPL, one-shot print path, HTTP proxy, ACP
  server, and loop mode. These currently duplicate orchestration behavior.
- File, process, web, LSP, task, worktree, durable-scheduling, MCP-resource,
  skill, and subagent surfaces. Several are partial or do not yet pass through
  one canonical capability boundary.
- Sessions, transcripts, compaction, memory, hooks, plugins, guardrails,
  grounding, and VDD types/paths. Their intended outcomes are retained in the
  remediation plan; current implementations must not be treated as complete.
- **Git Worktrees** — Create, list, and safely remove isolated git worktrees without mutating the process CWD. Current cleanup/transaction/capability gaps are documented in the audit.
- **Thinking Mode** — Extended reasoning for Anthropic, OpenAI GPT-5/o1/o3/o4, Gemini 3.x/2.5, DeepSeek V4, Qwen QwQ, Z.AI/GLM, and MiniMax-M3. This describes adapter configuration branches, not uniform preservation or privacy of native reasoning state.
- **Cron Scheduling** — Create, list, execute, and delete durable UTC schedules with explicit approval, bounded child-agent capabilities, retries, overlap policy, cancellation, and run history. The full-screen TUI owns the scheduler lifecycle; legacy metadata remains visible but inert until recreated with fresh authorization.
- **Web Search** — Free DuckDuckGo/Bing browser scraping is available through
  the explicit `browser` build feature. It remains opt-in while its documented
  egress/isolation gaps are remediated; default builds expose direct
  `web_fetch` but do not register `web_search` or `web_browser`.

The legacy filesystem rule injector has been removed. Repository files under
`.openclaudia/rules` and deprecated provider-compatibility rule directories are
not loaded or inserted into model context, and `/init` no longer creates them.
Migrate intentional guidance to an explicitly reviewed skill, a direct user
instruction, or host-owned configuration. Project-local `output-style.md` is
also ignored; a user-owned style may be placed at
`~/.openclaudia/output-style.md`.

## Build

```bash
git clone https://github.com/dollspace-gay/openclaudia.git
cd openclaudia
cargo build --release
```

The default build does not include browser process integration. Build it
explicitly with `cargo build --release --features browser`. Browser-enabled
builds use an operator-installed compatible Chromium/Chrome executable and do
not download one during an agent tool call. `web_search` and `web_browser` are
unavailable when the feature is omitted; direct `web_fetch` remains available.
The [repository artifact and dependency policy](docs/repository-artifact-dependency-policy.md)
defines the MSRV, locked supply-chain gates, retained historical evidence, and
safe cache cleanup procedure.

## Available Tools

This is the current compiled registry, not a claim that every tool has finished
capability, isolation, cancellation, or frontend wiring. Those gaps remain
owned by the audit and remediation slices.

| Tool | Current outcome |
|---|---|
| `bash` | Execute shell commands with optional timeout and background mode |
| `bash_output` | Get output from background shells or list running shells |
| `kill_shell` | Terminate a background shell by ID |
| `kill_shells_for_agent` | Terminate background shells owned by an agent or session |
| `read_file` | Read text, image, PDF, or notebook content with optional offset/limit |
| `grounding_context` | Hydrate selected Reality Ledger observations |
| `write_file` | Create files; overwrites require a successful `read_file` first and its `expected_snapshot` generation |
| `edit_file` | Replace exact text; requires a successful `read_file` first and its `expected_snapshot` generation |
| `list_files` | List directory contents |
| `glob` | Find files by glob pattern |
| `grep` | Search file contents by regular expression |
| `notebook_edit` | Edit notebook cells; requires a successful `read_file` first |
| `remote_trigger` | Invoke a typed host-registered remote action without exposing its destination or credentials to the model |
| `web_fetch` | Fetch an allowed web page |
| `web_search` | Search through the browser-backed implementation when built with `browser` |
| `web_browser` | Use the opt-in `browser` feature's headless-browser surface |
| `memory_save` | Propose one cited, codebase-specific technical lesson as untrusted private evidence |
| `memory_search` | Retrieve bounded cited technical lessons for the exact workspace; results are evidence, not instructions |
| `memory_list` | List recent typed technical lessons for the exact workspace |
| `memory_learning_status` | Inspect bounded run-local causal capture, candidate, contradiction, and degradation metadata; it never captures conversation prose |
| `memory_conflicts` | Inspect a byte-bounded page of cited conflict branches while returning the complete canonical head set |
| `memory_update` | Correct one exact lesson revision, or resolve every current conflict head through an explicit multi-parent compare-and-swap revision |
| `memory_delete` | Delete one exact lesson revision by writing an immutable causal tombstone |
| `memory_review` | Review or revoke one exact lesson revision using a fresh one-use host approval; review never raises confidence or creates instruction authority |
| `memory_export` | Publish a bounded resumable package of typed workspace technical-memory history using a fresh one-use host approval |
| `memory_import` | Strictly verify and atomically restore a complete same-workspace technical-memory package using a fresh one-use host approval |
| `memory_source_status` | Inspect and verify the explicit repository technical-lesson source without loading it into a prompt |
| `memory_source_refresh` | Atomically import, update, rename, restore, or explicitly prune a verified repository lesson source |
| `crosslink` | Use the embedded issue-tracking integration |
| `lsp` | Run goToDefinition, findReferences, hover, documentSymbols, workspaceSymbol, goToImplementation, and call hierarchy operations |
| `ask_user_question` | Request structured clarification |
| `enter_plan_mode` | Enter the current prompt-oriented planning mode |
| `exit_plan_mode` | Leave planning mode |
| `task_create` | Create a tracked task |
| `task_update` | Update task state or dependencies |
| `task_get` | Read one task |
| `task_list` | List tracked tasks |
| `todo_write` | Replace the fallback to-do list |
| `todo_read` | Read the fallback to-do list |
| `skill` | Load a discovered prompt skill by name |
| `tool_search` | Select deferred tool schemas by name or keyword |
| `enter_worktree` | Create an isolated Git worktree record |
| `exit_worktree` | Preview and transactionally stage, commit, merge, discard, or remove an isolated worktree |
| `list_worktrees` | List tracked worktrees |
| `cron_create` | Create a durable authorized agent schedule |
| `cron_delete` | Delete an authorized schedule or inert legacy metadata |
| `cron_list` | List authorized schedules, policy, and run history |
| `list_mcp_resources` | List resources from connected MCP servers |
| `read_mcp_resource` | Read a named MCP resource |

### Repository technical-lesson sources

`MEMORY.md` remains a compatibility filename, but it is not a prose prompt or
instruction file. When present at the workspace root or at
`.openclaudia/MEMORY.md`, it must contain the exact versioned JSON manifest
defined by [S-056](docs/remediation-slices/056-operational-memdir-lifecycle.md).
Each entry is a bounded `TechnicalLessonDraft` with a stable `lesson_id` and at
least one digest-bound citation to a regular workspace source, test,
configuration, or documentation file. Arbitrary Markdown, home-directory
fallbacks, links, control-state citations, ambiguous dual files, and
unverified/oversized artifacts are rejected.

Use `memory_source_status` to inspect the discovered and persisted generations.
Use its current `source_digest` as `expected_source_digest` when calling
`memory_source_refresh`; removals additionally require `prune_missing: true`.
Refresh publishes lesson changes and source state in one causal transaction.
The agent can retrieve imported lessons only with `memory_search` or
`memory_list`; source contents are never appended to system, developer, or user
prompts automatically.

Automatic learning uses that same typed lesson authority. It ignores user,
assistant, and repository prose. A private review-due candidate can be proposed
only when one allowlisted verification command fails, successful file mutations
occur in the same exact run/task, and the exact command and arguments later
succeed. The candidate cites each typed tool receipt, states that correlation is
not causation, and remains untrusted until separately reviewed. A later failure
of the same check creates a causal correction. Use `memory_learning_status` (or
`/memory`) for bounded health metadata and `memory_search`/`memory_list` to
retrieve the actual codebase lessons explicitly.

Use `memory_export` with an existing writable package directory to publish the
workspace's complete typed technical-memory history. If publication stops, the
partial receipt supplies the exact `expected_checkpoint_digest` required by a
freshly approved resume call; only the final manifest marks the package
complete. `memory_import` accepts an existing readable package directory for
the same workspace, verifies every bounded canonical part, and commits the
causal state atomically. Both operations require a new one-use host decision on
every call, and neither exports nor imports legacy prose, prompts, sessions, or
transcripts.

## Supported Models

Model pickers discover the account-scoped provider catalog at runtime and
cache it for six hours. The short lists below are the dated emergency selector
fallbacks used when discovery is unavailable; they are neither an allowlist nor
a claim of account access. Optional request features and context limits are
enabled only from fresh provider metadata or an exact entry in that dated
fallback. Unknown local/custom targets require an explicitly configured model.

### Anthropic

- `claude-opus-4-8`, `claude-sonnet-4-6`, `claude-haiku-4-5`, `claude-fable-5`, `claude-mythos-5`

### OpenAI

- `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna`, `gpt-5.5`

### Google Gemini

- `gemini-3.7-flash`, `gemini-3.6-flash`, `gemini-3.5-flash`, `gemini-3.5-flash-lite`

### DeepSeek

- `deepseek-v4-pro`, `deepseek-v4-flash`

### Qwen

- `qwen3.7-max`, `qwen3.7-plus`, `qwen3.6-flash`

### Z.AI (GLM)

- `glm-5.2`, `glm-5-turbo`

### Kimi

- `kimi-k2.7-code`, `kimi-k2.7-code-highspeed`, `kimi-k2.6`

### MiniMax

- `MiniMax-M3`, `MiniMax-M2.7-highspeed`

## Behavioral Modes

OpenClaudia currently exposes prompt-oriented mode presets. They are useful
presentation hints, not enforceable capability boundaries; the remediation
plan preserves the user outcome while moving authority into host enforcement.

## Configuration

Project configuration lives at `.openclaudia/config.yaml`; trusted host
configuration may also live at `~/.openclaudia/config.yaml` or in the
environment. The broader schema still has inconsistent provenance and
unknown-field behavior, so use this as a syntax example rather than a complete
secure-deployment profile. Environment keys and custom headers can carry
secrets and must be reviewed carefully.

Permission grants are an exception to ordinary project configuration. A
project file cannot disable approval prompts, add `default_allow` entries, or
preapprove web-fetch domains; those requests are retained as an inert,
digest-bound proposal visible in `/permissions`. Put host-selected grants in
`~/.openclaudia/config.yaml`, the trusted environment, or the explicit
`--dangerously-skip-permissions` launch flag. Effect classification and hard
host safety remain active even when prompts are disabled.

Environment configuration uses `OPENCLAUDIA_`, with `__` between configuration
levels and `_` between words inside one level. Names are matched against an
explicit typed registry; unknown names and duplicate aliases for one field are
startup errors. Exact pre-0.5 single-underscore names remain deprecated aliases
for migration. Array and map values use JSON. Environment values override both
project and trusted-home files; explicit CLI arguments override the
environment.

| Typed field | Canonical environment variable | Parse / sensitivity |
|---|---|---|
| `proxy.port` | `OPENCLAUDIA_PROXY__PORT` | unsigned 16-bit integer / public |
| `session.timeout_minutes` | `OPENCLAUDIA_SESSION__TIMEOUT_MINUTES` | unsigned integer / public |
| `session.persist_path` | `OPENCLAUDIA_SESSION__PERSIST_PATH` | non-empty path string / sensitive |
| `vdd.tracking.promote_verified_findings` | `OPENCLAUDIA_VDD__TRACKING__PROMOTE_VERIFIED_FINDINGS` | `true` or `false` / external-mutation policy |
| `vdd.tracking.retention_days` | `OPENCLAUDIA_VDD__TRACKING__RETENTION_DAYS` | bounded unsigned integer / public |
| `vdd.tracking.log_adversary_responses` | `OPENCLAUDIA_VDD__TRACKING__LOG_ADVERSARY_RESPONSES` | `true` or `false` / sensitive |
| `providers.openai-compatible.base_url` | `OPENCLAUDIA_PROVIDERS__OPENAI_COMPATIBLE__BASE_URL` | non-empty URL string / sensitive |
| `providers.openai-compatible.api_key` | `OPENCLAUDIA_PROVIDERS__OPENAI_COMPATIBLE__API_KEY` | validated API key / secret |
| `memory.team_id` | `OPENCLAUDIA_MEMORY__TEAM_ID` | strict host-enrolled team selector / authority-sensitive; cannot create membership |
| `memory.team_memory_path` | `OPENCLAUDIA_MEMORY__TEAM_MEMORY_PATH` | permanently rejected legacy path proposal; a path is never team authority |
| `web_fetch.preapproved_domains` | `OPENCLAUDIA_WEB_FETCH__PREAPPROVED_DOMAINS` | JSON string array / authority-sensitive |
| `web_fetch.exact_private_origins` | `OPENCLAUDIA_WEB_FETCH__EXACT_PRIVATE_ORIGINS` | JSON array of exact `http(s)`/`ws(s)` origins / authority-sensitive |

The complete supported-name matrix, including provider aliases, parser,
secrecy, precedence, and deprecation metadata, is exposed by
`openclaudia::config::environment_variable_metadata()`.
Arbitrary `OPENCLAUDIA_FEATURE_*` variables are not a supported rollout
mechanism: no production flag catalog exists, so those names fail as unknown
instead of silently doing nothing.

### Config File

```yaml
proxy:
  port: 8080
  host: "127.0.0.1"
  # Provider aliases accepted by the current parser include:
  # google/gemini, qwen/alibaba, zai/glm/zhipu, kimi/moonshot
  # opencode/opencode-go share the OpenCode Go provider configuration
  target: anthropic

providers:
  anthropic:
    base_url: https://api.anthropic.com
    thinking:
      enabled: false
      reasoning_effort: "high"
      # budget_tokens: 10000
  openai:
    base_url: https://api.openai.com
    thinking:
      reasoning_effort: "medium"  # OpenAI GPT-5/o1/o3/o4: none, low, medium, high, xhigh
  google:
    base_url: https://generativelanguage.googleapis.com
    thinking:
      budget_tokens: 10000        # Google Gemini thinking budget
  deepseek:
    base_url: https://api.deepseek.com
  qwen:
    base_url: https://dashscope.aliyuncs.com/compatible-mode
  zai:
    base_url: https://api.z.ai/api/paas/v4
  kimi:
    base_url: https://api.moonshot.ai/v1
  minimax:
    base_url: https://api.minimax.io/v1
  ollama:
    base_url: http://localhost:11434
  local:
    base_url: http://localhost:1234/v1
  lmstudio:
    base_url: http://localhost:1234/v1
  localai:
    base_url: http://localhost:8080/v1
  text-generation-webui:
    base_url: http://localhost:5000/v1
  openrouter:
    base_url: https://openrouter.ai/api/v1
  opencode:
    base_url: https://opencode.ai/zen/go/v1
  openai-compatible:
    base_url: https://example.com/v1

session:
  timeout_minutes: 30
  persist_path: .openclaudia/session
  max_turns: 0

# Select only a team already enrolled through `openclaudia team`. This does
# not create membership, and team lesson access remains unavailable until the
# bounded replication service is enabled.
# memory:
#   # Explicit consent for causal, receipt-bound technical-lesson candidates.
#   # Conversation prose is never captured.
#   automatic_learning_enabled: true
#   team_id: team-0123456789abcdef0123456789abcdef

# Current permission schema. The audit recommends a finite turn limit and a
# canonical fail-closed policy before production use.
# permissions:
#   enabled: true
#   default_allow:
#     - "Bash(git status)"
#     - "Write(src/**)"
#     - "Edit(src/**)"
#   mcp:
#     filesystem: ["read_file", "list_directory"]
```

Named remote actions are authority-bearing host configuration. A
`remote_actions` block in `.openclaudia/config.yaml` is ignored; place it in
`~/.openclaudia/config.yaml`. The model sees only the
symbolic name, description, and payload schema. OpenClaudia fixes the POST
destination and headers, requires the run's network and secret capabilities
plus host approval, and enforces the configured deadline, byte, call,
concurrency, idempotency, and retry bounds.

Private/local web access is also authority-bearing host configuration. Put
`web_fetch.exact_private_origins` only in `~/.openclaudia/config.yaml` or its
typed environment variable; project values are ignored. Each entry must be a
bare, exact origin such as `http://127.0.0.1:8787` or
`wss://dev.example.test:9443`—userinfo, paths, queries, fragments, and broad
host patterns are rejected. These grants are snapshotted into each run and
apply to model-selected fetch/browser traffic. A configured local
distillation provider receives a narrower provider-only grant and does not
become a general browsing destination. `preapproved_domains` controls prompts;
it does not grant connection-boundary access.

```yaml
web_fetch:
  exact_private_origins:
    - http://127.0.0.1:8787
```

```yaml
remote_actions:
  # Optional and restricted to exact localhost/loopback destinations.
  allow_loopback_plaintext: false
  actions:
    deploy:
      url: https://actions.example.com/deploy
      headers:
        Authorization: Bearer replace-with-host-secret
      description: Deliver one deployment event
      input_schema:
        type: object
        additionalProperties: false
        properties:
          revision: {type: string, minLength: 1}
        required: [revision]
      output_schema:
        type: object
        additionalProperties: false
        properties:
          accepted: {type: boolean}
        required: [accepted]
      idempotency: key_header
      timeout_milliseconds: 10000
      max_request_bytes: 65536
      max_response_bytes: 262144
      max_calls_per_run: 4
      max_in_flight: 1
      max_attempts: 2
```

## CLI Commands

The following command shapes exist. “Exists” does not imply feature parity or
safe unattended operation; consult the [generated capability
matrix](docs/binary-capability-matrix.md) and audit. Capability maturity comes
from the typed registry and executable receipts, never from this prose block.

```bash
openclaudia                    # Start full-screen interactive TUI (default)
openclaudia -m <model>         # Use specific model (auto-detects provider)
openclaudia -v                 # Verbose logging
openclaudia --resume           # Resume last session
openclaudia --session-id <id>  # Resume specific session
openclaudia --coordinator --tui-mode  # Legacy REPL coordinator prompt mode
openclaudia --tui-mode         # Legacy line-oriented REPL
openclaudia --mode <preset>    # Start with a behavioral mode preset
openclaudia --print "prompt"   # Send one prompt, print the response, and exit
openclaudia init               # Initialize config in current directory
openclaudia init --force       # Overwrite existing config
openclaudia auth               # Start legacy native OAuth flow (not approved for production use)
openclaudia auth --status      # Check native auth cache status
openclaudia auth --logout      # Clear native OAuth session cache
openclaudia start              # Start proxy server (bind/auth audit required)
openclaudia start -p 9090      # Custom port
openclaudia start -t openai    # Target specific provider
openclaudia acp                # Start ACP server on stdin/stdout
openclaudia acp -m <model>     # ACP with specific model
openclaudia loop               # Start iteration mode with Stop hooks
openclaudia loop -n 10         # Max 10 iterations
openclaudia config             # Show current configuration
openclaudia doctor             # Run offline, non-mutating typed diagnostics
openclaudia doctor --json      # Emit machine-readable diagnostic receipts
openclaudia hooks status       # Review inert repository hook proposals and exact digests
openclaudia hooks approve <sha256:...>  # Approve one current, digest-bound proposal
openclaudia hooks revoke <sha256:...>   # Revoke one exact approval receipt
openclaudia team create --principal-id <id>  # Create host-owned team authority
openclaudia team status [--team-id <id>]     # Show redacted local enrollment state
openclaudia team invite [--team-id <id>]     # Emit a signed public invitation
openclaudia team audit [--team-id <id>]      # Show bounded redacted authorization receipts
```

`openclaudia team --help` exposes the complete manual enrollment, role,
revocation, renewal, recovery, and key-rotation lifecycle. The exchanged JSON
artifacts contain signed public state only; private credentials stay in the
descriptor-safe host store. This authority surface does not ambiently inject
memory into prompts and does not enable team lesson transport by itself.

`--verbose` opts the TUI and legacy REPL into local lifecycle analytics at
debug level. Current lifecycle records contain an event name, a SHA-256 digest
of the session identifier, and the final message count; they do not contain the
raw session identifier or prompt content. Nothing is uploaded or exported. TUI
records share the ordinary `.openclaudia/logs/` file lifecycle and remain until
the user deletes those logs; the legacy REPL writes them to stderr. Without
`--verbose` (or an equivalent explicit `RUST_LOG` debug filter), these records
are not emitted.

## Slash Commands (Default TUI)

The default TUI and legacy REPL use one typed registry for parsing, help,
completion, effect classification, capability checks, and dispatch admission.
The table below is checked against that runtime registry.

| Command | Current surface |
|---|---|
| `/help, ?` | Show the TUI help overlay |
| `/new, /clear` | Clear the visible transcript and start a new conversation |
| `/exit, /quit` | Exit the TUI |
| `/model [list\|name], /models` | Show, list, or switch models |
| `/copy` | Copy last assistant response to clipboard |
| `/status` | Show model, provider, effort, and token estimate |
| `/plan` | Toggle between Build and Plan modes |
| `/mode` | Toggle between Build and Plan modes |
| `/keybindings, /keys, /bindings` | Show effective keyboard shortcuts |
| `/effort [low\|medium\|high\|max\|xhigh\|auto]` | Set or cycle effort level |
| `/provider [name]` | Show or switch provider |
| `/sessions, /list` | List saved sessions |
| `/resume, /continue, /load <id>` | Open the session picker or resume by ID |
| `/export` | Export the current conversation to markdown |
| `/undo` | Undo the last message exchange |
| `/redo` | Redo the last undone message exchange |
| `/rewind [N]` | Show turns or rewind the last N turns |
| `/rename <title>` | Rename the current session |
| `/init` | Initialize project config if absent |
| `/review` | Show a truncated git diff for review |
| `/doctor` | Run inline diagnostics |
| `/cost` | Show session cost estimate |
| `/context` | Show context usage breakdown |
| `/files [dir]` | List files in the current or given directory |
| `/diff` | Show git diff summary |
| `/skill [name], /skills` | List or invoke a trusted skill |
| `/<plugin>:<command> [args]` | Run a namespaced plugin command, skill, or agent |
| `/<skill-name> [args]` | Invoke a trusted skill by name |

## Keyboard Shortcuts (Default TUI)

| Shortcut | Current action |
|---|---|
| `Enter` | Send input |
| `Esc` | Dismiss overlay or request interruption |
| `Ctrl-C` | Request cancellation or exit when idle |
| Arrow/Page keys | Edit input or scroll depending on focus |

The `keybindings:` config map customizes the legacy line-oriented REPL, not the
default full-screen TUI.

## Remediation policy

OpenClaudia aims to preserve these user outcomes while replacing duplicated or
unsafe mechanisms. Unfinished code is a repair commitment, not a deletion
reason. The legacy automatic rule injector is the first product mechanism
removed under that policy; its implementation evidence is recorded in
[S-007](docs/remediation-slices/007-remove-legacy-rule-injector.md).

## Documentation

- [Full file-by-file audit](docs/full-codebase-audit-2026-08-16.md)
- [Production remediation design](docs/production-remediation-design.md)
- [Binary entrypoint status](docs/binary-capability-matrix.md)

## License

MIT; see [LICENSE](LICENSE).

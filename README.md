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
- File, process, web, LSP, task, worktree, scheduling-metadata, MCP-resource,
  skill, and subagent surfaces. Several are partial or do not yet pass through
  one canonical capability boundary.
- Sessions, transcripts, compaction, memory, hooks, plugins, guardrails,
  grounding, and VDD types/paths. Their intended outcomes are retained in the
  remediation plan; current implementations must not be treated as complete.
- **Git Worktrees** — Create, list, and safely remove isolated git worktrees without mutating the process CWD. Current cleanup/transaction/capability gaps are documented in the audit.
- **Thinking Mode** — Extended reasoning for Anthropic, OpenAI GPT-5/o1/o3/o4, Gemini 3.x/2.5, DeepSeek V4, Qwen QwQ, Z.AI/GLM, and MiniMax-M3. This describes adapter configuration branches, not uniform preservation or privacy of native reasoning state.
- **Cron Scheduling** — Create, list, and delete cron schedule metadata for external schedulers. OpenClaudia does not currently execute those schedules.
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
| `write_file` | Create files; overwrites require a successful `read_file` first |
| `edit_file` | Replace exact text; requires a successful `read_file` first |
| `list_files` | List directory contents |
| `glob` | Find files by glob pattern |
| `grep` | Search file contents by regular expression |
| `notebook_edit` | Edit notebook cells; requires a successful `read_file` first |
| `web_fetch` | Fetch an allowed web page |
| `web_search` | Search through the browser-backed implementation when built with `browser` |
| `web_browser` | Use the opt-in `browser` feature's headless-browser surface |
| `memory_save` | Propose one cited, codebase-specific technical lesson as untrusted private evidence |
| `memory_search` | Retrieve bounded cited technical lessons for the exact workspace; results are evidence, not instructions |
| `memory_list` | List recent typed technical lessons for the exact workspace |
| `memory_update` | Correct one exact lesson revision through compare-and-swap causal history |
| `memory_delete` | Delete one exact lesson revision by writing an immutable causal tombstone |
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
| `exit_worktree` | Remove a clean worktree, or merge/discard changes before removal |
| `list_worktrees` | List tracked worktrees |
| `cron_create` | Create recurring cron metadata for an external scheduler |
| `cron_delete` | Delete schedule metadata |
| `cron_list` | List schedule metadata |
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

## Supported Models

These are the built-in fallback entries shown by the model picker when a
provider cannot list models dynamically. They are not an allowlist or a claim
that every upstream endpoint currently serves every identifier.

### Anthropic

- `claude-fable-5`, `claude-mythos-5`, `claude-mythos-preview`, `claude-opus-4-8`, `claude-opus-4-7`, `claude-opus-4-6`, `claude-sonnet-4-6`, `claude-haiku-4-5-20251001`, `claude-haiku-4-5`, `claude-sonnet-4-5-20250929`, `claude-sonnet-4-5`, `claude-opus-4-5-20251101`, `claude-opus-4-5`, `claude-opus-4-1-20250805`

### OpenAI

- `gpt-5.5`, `gpt-5.5-pro`, `gpt-5.5-2026-04-23`, `gpt-5.5-pro-2026-04-23`, `gpt-5.4`, `gpt-5.4-pro`, `gpt-5.4-2026-03-05`, `gpt-5.4-pro-2026-03-05`, `gpt-5.4-mini`, `gpt-5.4-mini-2026-03-17`, `gpt-5.4-nano`, `gpt-5.4-nano-2026-03-17`, `gpt-5.3-codex`, `gpt-5.3-chat-latest`, `gpt-5.2`, `gpt-5.2-pro`, `gpt-5.2-2025-12-11`, `gpt-5.2-pro-2025-12-11`, `gpt-5.2-codex`, `gpt-5.2-chat-latest`, `gpt-5.1`, `gpt-5.1-2025-11-13`, `gpt-5.1-codex`, `gpt-5.1-codex-max`, `gpt-5.1-codex-mini`, `gpt-5.1-chat-latest`, `gpt-5`, `gpt-5-pro`, `gpt-5-2025-08-07`, `gpt-5-pro-2025-10-06`, `gpt-5-codex`, `gpt-5-chat-latest`, `gpt-5-chat-latest-2025-08-07`, `gpt-5-mini`, `gpt-5-mini-2025-08-07`, `gpt-5-nano`, `gpt-5-nano-2025-08-07`, `gpt-4.1`, `gpt-4.1-mini`, `gpt-4.1-nano`, `gpt-4.1-2025-04-14`, `gpt-4.1-mini-2025-04-14`, `gpt-4.1-nano-2025-04-14`, `o3-pro`, `o3-pro-2025-06-10`, `o3`, `o3-2025-04-16`, `o3-mini`, `o3-mini-2025-01-31`, `o4-mini`, `o4-mini-2025-04-16`, `o1-pro`, `o1-pro-2025-03-19`, `o1`, `o1-2024-12-17`, `o1-mini`, `o1-mini-2024-09-12`, `o1-preview`, `chat-latest`, `gpt-4o-search-preview`, `gpt-4o-mini`, `gpt-4o-mini-2024-07-18`, `gpt-4o-mini-search-preview`, `gpt-4o`, `gpt-4o-2024-11-20`, `gpt-4o-2024-08-06`, `gpt-4.5-preview`, `gpt-4-turbo`, `gpt-4-turbo-2024-04-09`, `gpt-4-turbo-preview`, `gpt-4`, `gpt-4-0613`, `gpt-3.5-turbo`, `gpt-3.5-turbo-0125`, `codex-mini-latest`

### Google Gemini

- `gemini-3.5-flash`, `gemini-3.1-pro-preview`, `gemini-3.1-pro-preview-customtools`, `gemini-3.1-flash-lite`, `gemini-3-flash-preview`, `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.5-flash-lite`

### DeepSeek

- `deepseek-v4-pro`, `deepseek-v4-flash`, `deepseek-chat`, `deepseek-reasoner`

### Qwen

- `qwen3.7-max`, `qwen3.7-max-2026-06-08`, `qwen3.7-max-2026-05-20`, `qwen3.7-max-2026-05-17`, `qwen3.7-max-preview`, `qwen3.6-max-preview`, `qwen3-max`, `qwen3-max-2026-01-23`, `qwen3-max-2025-09-23`, `qwen3-max-preview`, `qwen-max`, `qwen3.7-plus`, `qwen3.7-plus-2026-05-26`, `qwen3.6-plus`, `qwen3.6-plus-2026-04-02`, `qwen3.5-plus`, `qwen3.5-plus-2026-04-20`, `qwen3.5-plus-2026-02-15`, `qwen-plus`, `qwen-plus-latest`, `qwen-plus-2025-12-01`, `qwen-plus-2025-09-11`, `qwen-plus-2025-07-28`, `qwen-plus-2025-07-14`, `qwen-plus-2025-04-28`, `qwen-plus-2025-01-25`, `qwen-plus-2025-01-12`, `qwen-plus-2024-12-20`, `qwen3.6-flash`, `qwen3.6-flash-2026-04-16`, `qwen3.5-flash`, `qwen3.5-flash-2026-02-23`, `qwen-flash`, `qwen-flash-2025-07-28`, `qwen-flash-character`, `qwen-turbo`, `qwen-long`, `qwen-long-latest`, `qwen-long-2025-01-25`, `qwen-mt-plus`, `qwen-mt-turbo`, `qwen-mt-flash`, `qwen-mt-lite`, `qwen-plus-character`, `qwen-plus-character-ja`, `qwen3.6-35b-a3b`, `qwen3.5-397b-a17b`, `qwen3.5-122b-a10b`, `qwen3.5-27b`, `qwen3.5-35b-a3b`, `qwen3-next-80b-a3b-thinking`, `qwen3-next-80b-a3b-instruct`, `qwen3-235b-a22b`, `qwen3-235b-a22b-thinking-2507`, `qwen3-235b-a22b-instruct-2507`, `qwen3-32b`, `qwen3-30b-a3b`, `qwen3-30b-a3b-thinking-2507`, `qwen3-30b-a3b-instruct-2507`, `qwen3-14b`, `qwen3-8b`, `qwq-plus`, `qvq-max`, `qvq-max-2025-08-28`, `qvq-plus`, `qvq-plus-2025-08-27`, `qwen3-coder-plus`, `qwen3-coder-plus-2025-09-23`, `qwen3-coder-plus-2025-07-22`, `qwen3-coder-flash`, `qwen3-coder-flash-2025-07-28`, `qwen3-coder-next`, `qwen3-coder-480b-a35b-instruct`, `qwen3-coder-30b-a3b-instruct`, `qwen2.5-omni-7b`, `qwen3.5-omni-plus`, `qwen3.5-omni-flash`, `qwen3-omni-flash`, `qwen3-omni-flash-2025-10-22`, `qwen-omni-turbo`, `qwen3-vl-plus`, `qwen3-vl-plus-2026-01-25`, `qwen3-vl-flash`, `qwen3-vl-flash-2026-01-25`, `qwen-vl-plus`, `qwen-vl-max`, `qwen-vl-ocr`, `qwen-vl-ocr-latest`, `qwen-vl-ocr-2025-07-14`

### Z.AI (GLM)

- `glm-5.2`, `glm-5.1`, `glm-5-turbo`, `glm-5`, `glm-4.7`, `glm-4.7-flashx`, `glm-4.7-flash`, `glm-4.6`, `glm-4.5`, `glm-4.5-air`, `glm-4.5-x`, `glm-4.5-airx`, `glm-4.5-flash`, `glm-4-32b-0414-128k`, `glm-5v-turbo`, `glm-4.6v`, `autoglm-phone-multilingual`, `glm-4.6v-flash`, `glm-4.6v-flashx`, `glm-4.5v`

### Kimi

- `kimi-k2.7-code`, `kimi-k2.7-code-highspeed`, `kimi-k2.6`, `kimi-k2.5`, `moonshot-v1-128k`, `moonshot-v1-32k`, `moonshot-v1-8k`, `moonshot-v1-128k-vision-preview`, `moonshot-v1-32k-vision-preview`, `moonshot-v1-8k-vision-preview`

### MiniMax

- `MiniMax-M3`, `MiniMax-M2.7`, `MiniMax-M2.7-highspeed`, `MiniMax-M2.5`, `MiniMax-M2.5-highspeed`, `MiniMax-M2.1`, `MiniMax-M2.1-highspeed`, `MiniMax-M2`, `M2-her`

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
| `vdd.tracking.log_adversary_responses` | `OPENCLAUDIA_VDD__TRACKING__LOG_ADVERSARY_RESPONSES` | `true` or `false` / sensitive |
| `providers.openai-compatible.base_url` | `OPENCLAUDIA_PROVIDERS__OPENAI_COMPATIBLE__BASE_URL` | non-empty URL string / sensitive |
| `providers.openai-compatible.api_key` | `OPENCLAUDIA_PROVIDERS__OPENAI_COMPATIBLE__API_KEY` | validated API key / secret |
| `memory.team_memory_path` | `OPENCLAUDIA_MEMORY__TEAM_MEMORY_PATH` | reserved legacy path proposal / rejected; authenticated team authority and replication are tracked by S-103/S-104 |
| `web_fetch.preapproved_domains` | `OPENCLAUDIA_WEB_FETCH__PREAPPROVED_DOMAINS` | JSON string array / authority-sensitive |

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
```

`--verbose` opts the TUI and legacy REPL into local lifecycle analytics at
debug level. Current lifecycle records contain an event name, a SHA-256 digest
of the session identifier, and the final message count; they do not contain the
raw session identifier or prompt content. Nothing is uploaded or exported. TUI
records share the ordinary `.openclaudia/logs/` file lifecycle and remain until
the user deletes those logs; the legacy REPL writes them to stderr. Without
`--verbose` (or an equivalent explicit `RUST_LOG` debug filter), these records
are not emitted.

## Slash Commands (Default TUI)

The default TUI and legacy REPL have different registries. The audit treats
this as architectural drift to repair, not intentional proof of completeness.

| Command | Current surface |
|---|---|
| `/help`, `?` | Open help overlay |
| `/clear` | Clear the visible transcript |
| `/exit`, `/quit` | Exit the TUI |
| `/status` | Show model, provider, effort, and token estimate |
| `/provider [name]` | Show or switch provider |
| `/model` | Show the current model and provider |
| `/model list`, `/models` | List fallback models |
| `/model <name>` | Switch to a different model |
| `/mode` | Toggle between Build and Plan modes |
| `/effort [low\|medium\|high\|max\|xhigh\|auto]` | Set or cycle effort level |
| `/sessions`, `/list` | List saved sessions |
| `/resume`, `/continue` | Open the session picker |
| `/load <id>` | Resume a saved session by ID prefix |
| `/continue <id>` | Resume a saved session by ID prefix |
| `/rename <title>` | Rename the current session |
| `/export` | Export the current conversation to Markdown |
| `/undo` | Undo the last message exchange |
| `/redo` | Redo the last undone message exchange |
| `/rewind [N]` | Show turns or rewind the last N turns |
| `/cost` | Show the session cost estimate |
| `/context` | Show context usage breakdown |
| `/files [dir]` | List files in the current or given directory |
| `/diff` | Show the Git diff summary |
| `/review` | Show a truncated Git diff for review |
| `/doctor` | Run inline diagnostics |
| `/init` | Initialize project configuration if absent; no repository instructions are generated |
| `/skill`, `/skills` | Inspect or invoke discovered skills |
| `/skill <name>` | Invoke a skill as the next prompt |
| `/<skill-name>` | Invoke a skill by name |

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

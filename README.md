# OpenClaudia

**Open-source universal agent harness** — Claude Code-like coding workflows for many AI providers.

OpenClaudia is a Rust-based CLI that transforms any LLM into an agentic coding assistant with tools, memory, hooks, and multi-provider support.

![OpenClaudia Logo](images/logo.jpg)

## Features

- **Behavioral Modes** — Three-axis model (agency, quality, scope) with 8 presets and 6 modifiers for fine-grained control over AI behavior
- **Multi-Provider Support** — Anthropic, OpenAI, Google Gemini, DeepSeek, Qwen, Z.AI/GLM, Kimi/Moonshot, MiniMax, OpenRouter, OpenCode Go, Ollama, and OpenAI-compatible servers
- **Local/Custom LLM Support** — Run with Ollama, LM Studio, LocalAI, OpenRouter, OpenCode Go, or any OpenAI-compatible endpoint
- **Auto-Detect Provider** — Pass `-m gemini-3.5-flash` and the provider is detected automatically
- **30+ Agentic Tools** — Bash, file ops, LSP, web search, notebooks, task tracking, plan mode, worktrees, cron scheduling, MCP resources
- **Tool Execution Loop** — Multi-turn tool calling with automatic result feedback (works across all providers)
- **Web Search** — Free DuckDuckGo/Bing browser scraping in default builds; no search API key required
- **Auto-Learning Memory** — Automatically captures coding patterns, error resolutions, file relationships, and user preferences across sessions
- **Background Shells** — Run long-running processes, check output, and kill them on demand
- **Thinking Mode** — Extended reasoning for Anthropic, OpenAI GPT-5/o1/o3/o4, Gemini 3.x/2.5, DeepSeek V4, Qwen QwQ, Z.AI/GLM, and MiniMax-M3
- **VDD Adversarial Review** — Verification-Driven Development: a separate adversary model reviews code for bugs/vulnerabilities
- **Hooks System** — Run custom scripts at key moments (session start, tool use, prompt submit, etc.)
- **Guardrails** — Configurable code quality gates, blast radius limiting, and diff size monitoring
- **Plan Mode** — Toggle between Build and Plan modes; plan mode restricts destructive tools
- **Permissions** — Granular tool-level allow/deny rules with glob patterns
- **Task Management** — Built-in task tracking with dependencies and status workflow
- **LSP Integration** — Language Server Protocol support for go-to-definition, find-references, hover, and more
- **Subagent System** — Spawn autonomous agents from the agent loop; coordinator infrastructure is experimental and not wired into the default TUI yet
- **ACP Server** — Agent Control Protocol server for agent interoperability via stdin/stdout
- **Git Worktrees** — Create, list, and safely remove isolated git worktrees without mutating the process CWD
- **Cron Scheduling** — Create, list, and delete cron schedule metadata for external schedulers
- **Skills System** — Load and invoke reusable prompt skills from markdown files
- **Cross-Platform** — Windows, macOS, Linux with Git Bash for consistent shell behavior
- **Interactive TUI** — Rich terminal interface with keybindings, themes, and session management
- **Context Compaction** — Automatic summarization when conversations get long
- **Notebook Support** — Read and edit Jupyter notebooks
- **MCP Integration** — Browse and read resources from MCP servers
- **Plugin System** — Install, manage, and extend with plugins (commands, hooks, MCP servers)
- **OAuth Support** — Use your Claude Max subscription via built-in OAuth proxy

## Prerequisites

### Required

- **Rust** — Install via [rustup](https://rustup.rs/)
- **bubblewrap** (Linux) — Required for OS containment of agent Bash and
  project-controlled quality-gate processes (`apt install bubblewrap`,
  `dnf install bubblewrap`, or your distribution equivalent)
- **Git Bash** (Windows compatibility mode only) — Comes with [Git for Windows](https://git-scm.com/download/win)
  - OpenClaudia can use Git Bash when the host explicitly opts out of sandboxing
  - Ensure Git is in your PATH

Agent subprocesses fail closed when a supported OS sandbox is unavailable.
For emergency compatibility only, a host user can explicitly opt out before
startup with `OPENCLAUDIA_BASH_SANDBOX=off`; models cannot set this through
tool arguments, and OpenClaudia logs a warning when the opt-out is active.

## Installation

```bash
# Clone the repository
git clone https://github.com/dollspace-gay/openclaudia.git
cd openclaudia

# Build release version (includes browser/web search support by default)
cargo build --release

# Build without browser feature (lighter binary, no headless Chrome)
cargo build --release --no-default-features

# The binary is at target/release/openclaudia
```

## Quick Start

```bash
# Set your API key (choose your provider)
export ANTHROPIC_API_KEY="your-key-here"
# or: export OPENAI_API_KEY="your-key-here"
# or: export GOOGLE_API_KEY="your-key-here"  # GEMINI_API_KEY also works
# or: export DEEPSEEK_API_KEY="your-key-here"

# Initialize configuration in your project
openclaudia init

# Start chatting (uses default provider from config)
openclaudia

# Use a specific model (provider auto-detected from model name)
openclaudia -m gemini-3.5-flash
openclaudia -m gpt-5.5
openclaudia -m claude-sonnet-4-6

# Start with a behavioral mode
openclaudia --mode create     # Autonomous architect — build from scratch
openclaudia --mode safe       # Collaborative minimal — surgical precision
openclaudia --mode debug      # Investigation-first debugging
```

## Configuration

### Environment Variables

| Variable | Provider | Required |
|----------|----------|----------|
| `ANTHROPIC_API_KEY` | Anthropic (Claude) | For Anthropic |
| `OPENAI_API_KEY` | OpenAI (GPT) | For OpenAI |
| `GOOGLE_API_KEY` or `GEMINI_API_KEY` | Google (Gemini) | For Google |
| `DEEPSEEK_API_KEY` | DeepSeek | For DeepSeek |
| `QWEN_API_KEY`, `DASHSCOPE_API_KEY`, or `ALIYUN_API_KEY` | Qwen/Alibaba | For Qwen |
| `ZAI_API_KEY` | Z.AI (GLM) | For Z.AI |
| `KIMI_API_KEY` or `MOONSHOT_API_KEY` | Kimi/Moonshot | For Kimi |
| `MINIMAX_API_KEY` | MiniMax | For MiniMax |
| `OPENROUTER_API_KEY` or `OPEN_ROUTER_API_KEY` | OpenRouter | For OpenRouter |
| `OPENCODE_API_KEY` or `OPENCODE_GO_API_KEY` | OpenCode Go | For OpenCode Go |
| `OPENAI_COMPATIBLE_API_KEY` or `API_KEY` | Generic OpenAI-compatible endpoint | For `openai-compatible` |

Sandbox policy is fixed at host startup:

| Variable | Effect |
|---|---|
| `OPENCLAUDIA_PROJECT_SECRET_MASKS` | Comma-separated project-relative paths hidden from agent file tools and subprocesses |
| `OPENCLAUDIA_AGENT_READ_ONLY_ROOTS` | Platform path-list of additional immutable session roots |
| `OPENCLAUDIA_AGENT_READ_WRITE_ROOTS` | Platform path-list of additional writable session roots |
| `OPENCLAUDIA_AGENT_ENV_GRANTS` | Comma-separated exact environment names granted to sandboxed agent processes |
| `OPENCLAUDIA_AGENT_NETWORK` | Must be `denied` (default); unsupported grants fail closed |
| `OPENCLAUDIA_TRUST_MCP_SERVERS` | Comma-separated exact `plugin/server` names approved from repository MCP config |
| `OPENCLAUDIA_MCP_ENV_GRANTS` | Comma-separated exact sensitive environment names an approved MCP server may receive |
| `OPENCLAUDIA_TRUST_UNSANDBOXED_HOOKS` | Set to `true` only to authorize hook `none`/`env_scrub` modes |
| `OPENCLAUDIA_BASH_SANDBOX` | `on` by default; `off` is an explicit host-wide emergency opt-out |

### Config File

Configuration is stored in `.openclaudia/config.yaml`:

```yaml
proxy:
  port: 8080
  host: "127.0.0.1"
  # Provider: anthropic, openai, google/gemini, deepseek, qwen/alibaba,
  # zai/glm/zhipu, kimi/moonshot, minimax, ollama, local, lmstudio,
  # localai, text-generation-webui, openrouter, opencode/opencode-go,
  # openai-compatible
  target: anthropic

providers:
  anthropic:
    base_url: https://api.anthropic.com
    thinking:
      enabled: false
      reasoning_effort: "high"    # Claude Opus 4.8/4.7/Fable/Mythos adaptive effort
      # budget_tokens: 10000      # Manual-thinking Claude models only
  openai:
    base_url: https://api.openai.com
    thinking:
      reasoning_effort: "medium"  # OpenAI GPT-5/o1/o3/o4: none, low, medium, high, xhigh
  google:
    base_url: https://generativelanguage.googleapis.com
    thinking:
      budget_tokens: 10000        # Google Gemini thinking budget
  zai:
    base_url: https://api.z.ai/api/paas/v4
    # Coding Plan users: https://api.z.ai/api/coding/paas/v4
  deepseek:
    base_url: https://api.deepseek.com
  qwen:
    base_url: https://dashscope.aliyuncs.com/compatible-mode
  kimi:
    base_url: https://api.moonshot.ai/v1
  minimax:
    base_url: https://api.minimax.io/v1
  # OpenRouter (OpenAI-compatible aggregator)
  openrouter:
    base_url: https://openrouter.ai/api/v1
    # api_key: ${OPENROUTER_API_KEY}  # or ${OPEN_ROUTER_API_KEY}
    # headers:
    #   HTTP-Referer: https://example.com
    #   X-OpenRouter-Title: OpenClaudia
  # OpenCode Go OpenAI-compatible endpoint subset
  opencode:
    base_url: https://opencode.ai/zen/go/v1
    # api_key: ${OPENCODE_API_KEY}  # or ${OPENCODE_GO_API_KEY}
  # Generic OpenAI-compatible endpoint
  openai-compatible:
    base_url: https://example.com/v1
    # api_key: ${OPENAI_COMPATIBLE_API_KEY}
    # model: my-model-name
  # Ollama for local LLM inference
  ollama:
    base_url: http://localhost:11434
  # Any OpenAI-compatible local server (LM Studio, LocalAI, text-generation-webui, etc.)
  local:
    base_url: http://localhost:1234/v1
  lmstudio:
    base_url: http://localhost:1234/v1
  localai:
    base_url: http://localhost:8080/v1
  text-generation-webui:
    base_url: http://localhost:5000/v1

session:
  timeout_minutes: 30
  persist_path: .openclaudia/session
  max_turns: 0  # 0 = unlimited agentic loop iterations; set nonzero to cap tool loops

# Verification-Driven Development (VDD) - Adversarial code review
# vdd:
#   enabled: true
#   mode: advisory           # advisory (single pass) or blocking (loop until clean)
#   adversary:
#     provider: google       # Must differ from proxy.target
#     model: gemini-3.5-flash

# Granular tool permissions
# permissions:
#   enabled: true
#   default_allow:
#     - "git status"
#     - "src/**"
#   mcp:
#     filesystem: ["read_file", "list_directory"]

# Legacy line REPL keybindings (`openclaudia --tui-mode`)
keybindings:
  ctrl-x n: new_session
  ctrl-x x: export
  tab: toggle_mode
  escape: cancel
```

## Sandbox Security

Linux agent subprocesses run inside named Bubblewrap profiles with filesystem
capabilities, network denial, seccomp, resource/output limits, inherited-FD
closure, and complete process-tree cancellation. File operations use
descriptor-relative resolution, and ACP routes filesystem/search operations
through those same local primitives.

The project root is readable and writable by agent code by default, so secrets
stored in `.env`, fixtures, or generated files are in scope unless masked.
`.openclaudia` and `.claude` stay hidden. macOS and Windows agent subprocesses
currently fail closed; they never silently fall back to host execution.

Run `openclaudia doctor` to inspect the effective redacted policy. See the
[agent sandbox threat model](docs/sandbox-threat-model.md) and
[subprocess inventory](docs/subprocess-inventory.md) for platform support,
trust boundaries, limitations, and incident response.

## CLI Commands

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

openclaudia auth               # Authenticate with Claude Max (OAuth)
openclaudia auth --status      # Check auth status
openclaudia auth --logout      # Clear native OAuth session cache

openclaudia start              # Start as proxy server
openclaudia start -p 9090      # Custom port
openclaudia start -t openai    # Target specific provider

openclaudia acp                # Start ACP server on stdin/stdout
openclaudia acp -m <model>     # ACP with specific model

openclaudia loop               # Start iteration mode with Stop hooks
openclaudia loop -n 10         # Max 10 iterations

openclaudia config             # Show current configuration
openclaudia doctor             # Check connectivity and API keys
```

## Slash Commands (Default TUI)

The default full-screen TUI intentionally exposes a focused slash-command set. The legacy line-oriented REPL (`openclaudia --tui-mode`) has additional commands; type `/help` there for that registry.

### TUI Core

| Command | Description |
|---------|-------------|
| `/help`, `?` | Show the TUI help overlay |
| `/clear` | Clear the visible transcript |
| `/exit`, `/quit` | Exit the TUI |
| `/status` | Show model, provider, effort, and token estimate |
| `/provider [name]` | Show or switch provider |
| `/model` | Show current model and provider |
| `/model list`, `/models` | List fallback models for the current provider |
| `/model <name>` | Switch to a different model |
| `/mode` | Toggle between Build and Plan modes |
| `/effort [low\|medium\|high\|max\|xhigh\|auto]` | Set or cycle effort level |

### TUI Sessions

| Command | Description |
|---------|-------------|
| `/sessions`, `/list` | List saved sessions |
| `/resume`, `/continue` | Open the session picker |
| `/load <id>` | Resume a saved session by ID prefix |
| `/continue <id>` | Resume a saved session by ID prefix |
| `/rename <title>` | Rename the current session |
| `/export` | Export conversation to markdown |
| `/undo` | Undo last message exchange |
| `/redo` | Redo last undone message exchange |
| `/rewind [N]` | Show turns or rewind the last N turns |

### TUI Diagnostics

| Command | Description |
|---------|-------------|
| `/cost` | Show session cost estimate |
| `/context` | Show context usage breakdown |
| `/files [dir]` | List files in the current or given directory |
| `/diff` | Show git diff summary |
| `/review` | Show a truncated git diff for review |
| `/doctor` | Run inline diagnostics |
| `/init` | Initialize project config if absent |

### TUI Skills

| Command | Description |
|---------|-------------|
| `/skill`, `/skills` | List available skills |
| `/skill <name>` | Invoke a skill as the next prompt |
| `/<skill-name>` | Invoke a skill by name |

### TUI Shell & Files

| Command | Description |
|---------|-------------|
| `!<command>` | Run shell command directly |
| `@<file>` | Attach file to prompt |

## Keyboard Shortcuts (Default TUI)

| Shortcut | Action |
|----------|--------|
| `Enter` | Send message |
| `Backspace`, `Delete` | Edit input |
| `Left`, `Right`, `Home`, `End` | Move input cursor |
| `Up`, `Down`, `PageUp`, `PageDown` | Scroll transcript |
| `Esc` | Close overlays, dismiss prompts, or cancel streaming |
| `Ctrl-C` | Cancel current turn or exit when idle |

The `keybindings:` config map customizes the legacy line-oriented REPL (`openclaudia --tui-mode`). The default full-screen TUI currently uses the shortcuts above.

## Available Tools

### Core Tools

| Tool | Description |
|------|-------------|
| `bash` | Execute shell commands with optional timeout and background mode |
| `bash_output` | Get output from background shells or list all running shells |
| `kill_shell` | Terminate a background shell by ID |
| `kill_shells_for_agent` | Terminate all background shells owned by an agent or session |
| `read_file` | Read file contents (supports images, PDFs, Jupyter notebooks) with optional offset/limit |
| `grounding_context` | Hydrate selected Reality Ledger observation IDs for evidence-grounded decisions |
| `write_file` | Create files; overwrites require a successful `read_file` first |
| `edit_file` | Targeted string replacement edits; requires a successful `read_file` first |
| `list_files` | List directory contents |
| `glob` | Find files by glob pattern |
| `grep` | Search file contents by regex |
| `notebook_edit` | Edit Jupyter notebook cells; requires a successful `read_file` first |
| `web_fetch` | Fetch web pages as markdown |
| `web_search` | Search the web through free DuckDuckGo/Bing browser scraping; no search API key required |
| `web_browser` | Full headless browser for JavaScript-heavy pages (default `browser` feature) |
| `crosslink` | Issue tracking and cross-session work memory via the embedded Crosslink library |

### Code Intelligence

| Tool | Description |
|------|-------------|
| `lsp` | Language Server Protocol operations (goToDefinition, findReferences, hover, documentSymbols, workspaceSymbol, goToImplementation, call hierarchy) |

### Planning and Task Tools

| Tool | Description |
|------|-------------|
| `ask_user_question` | Prompt the user for clarification with multiple-choice options |
| `enter_plan_mode` | Switch to plan mode (restricts destructive tools) |
| `exit_plan_mode` | Exit plan mode and proceed with implementation |
| `task_create` | Create a tracked task with subject, description, and active form |
| `task_update` | Update task status (pending/in_progress/completed), add dependencies |
| `task_get` | Get full details of a task by ID |
| `task_list` | List all tasks with status summary |
| `todo_write` | Simple to-do list (fallback when Crosslink issue tracking is unavailable) |
| `todo_read` | Read current to-do list |
| `skill` | Load a reusable prompt skill by name |
| `tool_search` | Fetch deferred tool schemas by name or keyword |

### Git Worktree Tools

| Tool | Description |
|------|-------------|
| `enter_worktree` | Create an isolated git worktree for parallel work |
| `exit_worktree` | Remove a clean worktree, or merge/discard changes before removal |
| `list_worktrees` | List all active worktrees |

### Scheduling Tools

| Tool | Description |
|------|-------------|
| `cron_create` | Create recurring cron metadata for an external scheduler |
| `cron_delete` | Delete stored cron schedule metadata |
| `cron_list` | List stored cron schedule metadata |

### MCP Tools

| Tool | Description |
|------|-------------|
| `list_mcp_resources` | Browse resources from connected MCP servers |
| `read_mcp_resource` | Read a specific MCP resource by URI |

## Supported Models

The lists below are the built-in `/model list` fallback catalog. Model names are not limited to this catalog: `openclaudia -m <model>` and `/model <model>` accept any upstream chat model ID that the selected provider endpoint supports.

### Anthropic
- `claude-fable-5`, `claude-mythos-5`, `claude-mythos-preview` — Latest/highest-capability Claude 5 family
- `claude-opus-4-8`, `claude-opus-4-7`, `claude-opus-4-6`, `claude-sonnet-4-6` — Claude 4 family
- `claude-haiku-4-5-20251001`, `claude-haiku-4-5` — Fast, near-frontier
- `claude-sonnet-4-5-20250929`, `claude-sonnet-4-5`, `claude-opus-4-5-20251101`, `claude-opus-4-5`, `claude-opus-4-1-20250805` — Legacy

### OpenAI
- `gpt-5.5`, `gpt-5.5-pro`, `gpt-5.5-2026-04-23`, `gpt-5.5-pro-2026-04-23` — Latest frontier family
- `gpt-5.4`, `gpt-5.4-pro`, `gpt-5.4-2026-03-05`, `gpt-5.4-pro-2026-03-05`, `gpt-5.4-mini`, `gpt-5.4-mini-2026-03-17`, `gpt-5.4-nano`, `gpt-5.4-nano-2026-03-17` — Current GPT-5.4 family
- `gpt-5.3-codex`, `gpt-5.3-chat-latest`, `gpt-5.2`, `gpt-5.2-pro`, `gpt-5.2-2025-12-11`, `gpt-5.2-pro-2025-12-11`, `gpt-5.2-codex`, `gpt-5.2-chat-latest` — Codex/previous frontier family
- `gpt-5.1`, `gpt-5.1-2025-11-13`, `gpt-5.1-codex`, `gpt-5.1-codex-max`, `gpt-5.1-codex-mini`, `gpt-5.1-chat-latest` — GPT-5.1 family
- `gpt-5`, `gpt-5-pro`, `gpt-5-2025-08-07`, `gpt-5-pro-2025-10-06`, `gpt-5-codex`, `gpt-5-chat-latest`, `gpt-5-chat-latest-2025-08-07`, `gpt-5-mini`, `gpt-5-mini-2025-08-07`, `gpt-5-nano`, `gpt-5-nano-2025-08-07` — GPT-5 family
- `gpt-4.1`, `gpt-4.1-mini`, `gpt-4.1-nano`, `gpt-4.1-2025-04-14`, `gpt-4.1-mini-2025-04-14`, `gpt-4.1-nano-2025-04-14`, `o3-pro`, `o3-pro-2025-06-10`, `o3`, `o3-2025-04-16`, `o3-mini`, `o3-mini-2025-01-31`, `o4-mini`, `o4-mini-2025-04-16`, `o1-pro`, `o1-pro-2025-03-19`, `o1`, `o1-2024-12-17`, `o1-mini`, `o1-mini-2024-09-12`, `o1-preview` — Legacy chat/reasoning models
- `chat-latest`, `gpt-4o-search-preview`, `gpt-4o-mini`, `gpt-4o-mini-2024-07-18`, `gpt-4o-mini-search-preview`, `gpt-4o`, `gpt-4o-2024-11-20`, `gpt-4o-2024-08-06`, `gpt-4.5-preview`, `gpt-4-turbo`, `gpt-4-turbo-2024-04-09`, `gpt-4-turbo-preview`, `gpt-4`, `gpt-4-0613`, `gpt-3.5-turbo`, `gpt-3.5-turbo-0125`, `codex-mini-latest` — Compatibility and deprecated chat models

### Google Gemini
- `gemini-3.5-flash`, `gemini-3.1-pro-preview`, `gemini-3.1-pro-preview-customtools`, `gemini-3.1-flash-lite`, `gemini-3-flash-preview` — Gemini 3 family
- `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.5-flash-lite` — Stable GA

### DeepSeek
- `deepseek-v4-pro`, `deepseek-v4-flash` — DeepSeek V4 family
- `deepseek-chat`, `deepseek-reasoner` — Compatibility aliases for V4 Flash through 2026-07-24

### Qwen
- `qwen3.7-max`, `qwen3.7-max-2026-06-08`, `qwen3.7-max-2026-05-20`, `qwen3.7-max-2026-05-17`, `qwen3.7-max-preview`, `qwen3.6-max-preview`, `qwen3-max`, `qwen3-max-2026-01-23`, `qwen3-max-2025-09-23`, `qwen3-max-preview`, `qwen-max` — Qwen Max family
- `qwen3.7-plus`, `qwen3.7-plus-2026-05-26`, `qwen3.6-plus`, `qwen3.6-plus-2026-04-02`, `qwen3.5-plus`, `qwen3.5-plus-2026-04-20`, `qwen3.5-plus-2026-02-15`, `qwen-plus`, `qwen-plus-latest`, `qwen-plus-2025-12-01`, `qwen-plus-2025-09-11`, `qwen-plus-2025-07-28`, `qwen-plus-2025-07-14`, `qwen-plus-2025-04-28`, `qwen-plus-2025-01-25`, `qwen-plus-2025-01-12`, `qwen-plus-2024-12-20` — Qwen Plus family
- `qwen3.6-flash`, `qwen3.6-flash-2026-04-16`, `qwen3.5-flash`, `qwen3.5-flash-2026-02-23`, `qwen-flash`, `qwen-flash-2025-07-28`, `qwen-flash-character`, `qwen-turbo`, `qwen-long`, `qwen-long-latest`, `qwen-long-2025-01-25` — Qwen Flash/Turbo/Long family
- `qwen-mt-plus`, `qwen-mt-turbo`, `qwen-mt-flash`, `qwen-mt-lite`, `qwen-plus-character`, `qwen-plus-character-ja` — Translation and character-role models
- `qwen3.6-35b-a3b`, `qwen3.5-397b-a17b`, `qwen3.5-122b-a10b`, `qwen3.5-27b`, `qwen3.5-35b-a3b`, `qwen3-next-80b-a3b-thinking`, `qwen3-next-80b-a3b-instruct`, `qwen3-235b-a22b`, `qwen3-235b-a22b-thinking-2507`, `qwen3-235b-a22b-instruct-2507`, `qwen3-32b`, `qwen3-30b-a3b`, `qwen3-30b-a3b-thinking-2507`, `qwen3-30b-a3b-instruct-2507`, `qwen3-14b`, `qwen3-8b` — Qwen dense/MoE models
- `qwq-plus`, `qvq-max`, `qvq-max-2025-08-28`, `qvq-plus`, `qvq-plus-2025-08-27`, `qwen3-coder-plus`, `qwen3-coder-plus-2025-09-23`, `qwen3-coder-plus-2025-07-22`, `qwen3-coder-flash`, `qwen3-coder-flash-2025-07-28`, `qwen3-coder-next`, `qwen3-coder-480b-a35b-instruct`, `qwen3-coder-30b-a3b-instruct` — Reasoning, visual reasoning, and coding specialists
- `qwen2.5-omni-7b`, `qwen3.5-omni-plus`, `qwen3.5-omni-flash`, `qwen3-omni-flash`, `qwen3-omni-flash-2025-10-22`, `qwen-omni-turbo`, `qwen3-vl-plus`, `qwen3-vl-plus-2026-01-25`, `qwen3-vl-flash`, `qwen3-vl-flash-2026-01-25`, `qwen-vl-plus`, `qwen-vl-max`, `qwen-vl-ocr`, `qwen-vl-ocr-latest`, `qwen-vl-ocr-2025-07-14` — Omni, vision, and OCR chat models

### Z.AI (GLM)
- `glm-5.2`, `glm-5.1`, `glm-5-turbo`, `glm-5` — GLM-5 text family
- `glm-4.7`, `glm-4.7-flashx`, `glm-4.7-flash` — GLM-4.7 family
- `glm-4.6`, `glm-4.5`, `glm-4.5-air`, `glm-4.5-x`, `glm-4.5-airx`, `glm-4.5-flash`, `glm-4-32b-0414-128k` — Previous generation
- `glm-5v-turbo`, `glm-4.6v`, `autoglm-phone-multilingual`, `glm-4.6v-flash`, `glm-4.6v-flashx`, `glm-4.5v` — GLM vision chat family

### Kimi
- `kimi-k2.7-code`, `kimi-k2.7-code-highspeed` — Coding-focused Kimi K2.7 models
- `kimi-k2.6`, `kimi-k2.5` — General Kimi K-series models
- `moonshot-v1-128k`, `moonshot-v1-32k`, `moonshot-v1-8k` — Moonshot V1 text models
- `moonshot-v1-128k-vision-preview`, `moonshot-v1-32k-vision-preview`, `moonshot-v1-8k-vision-preview` — Moonshot V1 vision previews

### MiniMax
- `MiniMax-M3` — Latest M-series language model
- `MiniMax-M2.7`, `MiniMax-M2.7-highspeed` — M2.7 family
- `MiniMax-M2.5`, `MiniMax-M2.5-highspeed` — M2.5 family
- `MiniMax-M2.1`, `MiniMax-M2.1-highspeed` — M2.1 family
- `MiniMax-M2` — Earlier agentic reasoning model
- `M2-her` — Dialogue-focused chat model

### Ollama (Local)
- Popular: `llama3.1`, `deepseek-r1`, `gemma3`, `qwen3`, `mistral`, `phi4`, `llava`
- Any model installed — run `ollama list` to see available models

### OpenAI-Compatible (Custom)
- Works with OpenRouter, OpenCode Go, LM Studio, LocalAI, text-generation-webui, vLLM, and any OpenAI-compatible server
- Set `base_url` to the provider root (for example, `https://openrouter.ai/api/v1` or `http://localhost:1234/v1`)
- Run `/model list` or `/models` to fetch model IDs from the configured `/models` endpoint when the provider supports it

## Behavioral Modes

Control how the AI behaves with a three-axis model. Each axis is independent, and presets are named combinations for common workflows.

### The Axis Model

| Axis | Values | Controls |
|------|--------|----------|
| **Agency** | `autonomous`, `collaborative`, `surgical` | How much initiative the AI takes |
| **Quality** | `architect`, `pragmatic`, `minimal` | What code quality standard to target |
| **Scope** | `unrestricted`, `adjacent`, `narrow` | How far beyond the request to go |

### Presets

| Preset | Agency | Quality | Scope | Use when... |
|--------|--------|---------|-------|-------------|
| `create` | autonomous | architect | unrestricted | Building from scratch with proper structure |
| `extend` | autonomous | pragmatic | adjacent | Extending existing projects, improving as you go |
| `safe` | collaborative | minimal | narrow | Surgical changes to production code |
| `refactor` | autonomous | pragmatic | unrestricted | Moving files, consolidating modules |
| `explore` | collaborative | architect | narrow | Read-only code understanding (+ readonly modifier) |
| `debug` | collaborative | pragmatic | narrow | Investigation-first debugging (+ debug modifier) |
| `methodical` | surgical | architect | narrow | Step-by-step precision (+ methodical modifier) |
| `director` | collaborative | architect | unrestricted | Orchestrate subagents (+ director modifier) |

### Modifiers

Modifiers are behavioral overlays that stack on top of any preset:

| Modifier | Effect |
|----------|--------|
| `bold` | Confident, idiomatic code with no hedging or over-engineering |
| `debug` | Investigation-first: gather evidence, form hypotheses, trace data flow |
| `methodical` | Step-by-step precision, complete each step before the next |
| `director` | Orchestrate subagents, delegate implementation, verify results |
| `readonly` | No file modifications, explain what you would do instead |
| `context-pacing` | Pace work to context limits with clean pause points |

### Usage

```bash
# CLI flag
openclaudia --mode create
openclaudia --mode safe

# In-session switching
/mode                        # Show current mode and list presets
/mode create                 # Switch to create preset
/mode create +bold           # Create preset with bold modifier
/mode debug +context-pacing  # Debug with pacing
/mode safe +bold +readonly   # Stack multiple modifiers
```

The mode system integrates with Anthropic's prompt caching: behavioral axes and modifiers are part of the stable prompt prefix (cached across turns), while hooks, memory, and environment info are in the dynamic suffix (reprocessed each turn). Mode switches naturally invalidate the prefix cache.

## Verification-Driven Development (VDD)

OpenClaudia includes a built-in adversarial code review system. When enabled, a separate AI model (the "adversary") reviews every response for bugs, security vulnerabilities, and logic errors.

```yaml
vdd:
  enabled: true
  mode: advisory        # Single-pass review, findings injected as context
  adversary:
    provider: google    # Use a different provider than your builder
    model: gemini-3.1-pro-preview
  static_analysis:
    auto_detect: true   # Automatically runs cargo clippy, cargo test, etc.
```

**Two modes:**
- **Advisory** — Single adversary pass after each response. Findings are displayed and injected into context for the next turn.
- **Blocking** — Full adversarial loop. The builder must revise until the adversary's findings converge to false positives (confabulation threshold).

Findings include CWE classifications, severity levels (CRITICAL/HIGH/MEDIUM/LOW/INFO), and can automatically create Crosslink issues for tracking.

## Hooks

Configure hooks in `.openclaudia/config.yaml` to run scripts at key moments:

```yaml
hooks:
  session_start:
    - hooks:
        - type: command
          command: python .openclaudia/hooks/session-start.py
          timeout: 30

  user_prompt_submit:
    - hooks:
        - type: command
          command: python .openclaudia/hooks/prompt-guard.py

  pre_tool_use:
    - matcher: "Write|Edit"
      hooks:
        - type: command
          command: python .openclaudia/hooks/validate-write.py
```

### Hook Events

- `session_start` — When a session begins
- `session_end` — When a session ends
- `user_prompt_submit` — Before processing user input
- `pre_tool_use` — Before executing a tool (with matcher for specific tools)
- `post_tool_use` — After executing a tool
- `stop` — For iteration/loop mode control

## Auto-Learning Memory

OpenClaudia automatically learns from your coding sessions without any flags or model intervention. A SQLite database (`.openclaudia/memory.db`) captures knowledge from tool execution signals:

- **Coding Patterns** — Conventions, pitfalls, and architecture observed from lint output and edit failures
- **Error Resolutions** — Errors encountered and how they were fixed, matched automatically when subsequent commands succeed
- **File Relationships** — Files frequently edited together (co-edit tracking), surfaced when you touch related code
- **User Preferences** — Style and workflow preferences detected from corrections ("no, use tabs") and explicit statements ("always use snake_case")
- **Session Continuity** — Recent session summaries and activity logs for context across restarts

Knowledge is injected into the model's context automatically — file-specific patterns when you read/edit a file, and preferences in every system prompt. Use `/memory` commands to inspect what's been learned.

Background memory agents such as autoDream consolidation, MagicDocs, SessionMemory, PromptSuggestion, and automatic `MEMORY.md` injection are design-stage work, not production behavior yet.

## Project Structure

```
.openclaudia/
├── config.yaml        # Main configuration
├── session/           # Persisted chat sessions
├── memory.db          # Auto-learning memory database
├── hooks/             # Custom hook scripts
├── rules/             # Language-specific rules (*.md)
├── plugins/           # Plugin manifests
├── logs/              # Audit logs
└── vdd/               # VDD session logs (if tracking enabled)
```

## Building from Source

```bash
# Development build (includes browser feature by default)
cargo build

# Release build
cargo build --release

# Without browser feature (smaller binary; web_search is unavailable)
cargo build --release --no-default-features

# Run all tests
cargo test

# Run integration tests (tests real tool execution)
cargo test --test integration_tests

# Lint
cargo clippy -- -D warnings

# Run with verbose logging
RUST_LOG=debug cargo run
```

## Dependencies

OpenClaudia is built with:

- **tokio** — Async runtime
- **axum** — HTTP server (for proxy mode)
- **reqwest** — HTTP client
- **rusqlite** — SQLite for memory
- **ratatui** — Terminal UI
- **rustyline** — Line editing with history
- **crossterm** — Terminal manipulation
- **serde** — Serialization
- **clap** — CLI argument parsing
- **tracing** — Structured logging

Default features (can be disabled with `--no-default-features`):
- **headless_chrome** — Headless browser fallback for web_fetch and no-key DuckDuckGo/Bing web search
- **scraper** — HTML parsing for search result extraction

## License

MIT License — See [LICENSE](LICENSE)

---

*Built with Rust. Powered by curiosity.*

# Subprocess boundary inventory

This inventory was generated from every `Command::new`,
`tokio::process::Command`, launcher helper, and process-spawn call in `src/`.
`tests/subprocess_boundary_e2e.rs` prevents new direct constructors from
appearing in agent modules without an explicit review.

| Location | Trust class | Boundary |
|---|---|---|
| `tools/bash/sandbox.rs` | Enforcement core | The only production constructor for agent subprocess commands; constructs named Linux Bubblewrap profiles or the explicit host-startup opt-out. |
| `tools/command.rs` | Enforcement core | Bounded stdout/stderr, timeout, process-tree termination, and session cancellation. Its unsandboxed constructor is compiled only for unit tests. |
| `tools/bash/mod.rs` | Agent-operated | Foreground/background Bash receives `Shell`; background buffers and ownership are bounded. |
| `guardrails.rs` | Agent-operated | Quality gates receive `QualityGate` and the bounded runner. |
| `hooks/mod.rs` | Agent-operated unless explicitly trusted | Direct/shell argv is constructed, then replaced with `RepositoryHook`; weak modes require immutable host-startup trust. |
| `tools/lsp.rs` | Agent-operated | File input comes from a confined descriptor; server command receives `LanguageServer`; child is process-tree guarded and session-registered. |
| `vdd/static_analysis.rs` | Agent-operated | Receives `StaticAnalyzer` and the bounded runner. |
| `tools/file/read.rs` | Agent-operated | PDF helpers receive `DocumentParser` and consume a confined file descriptor through stdin. |
| `mcp.rs` | Trusted extension with sandbox | Exact host approval and pinned executable, then `McpStdio`; child is session-registered. HTTP MCP uses the SSRF/credential broker instead of a subprocess. |
| `tools/worktree.rs`, `subagent.rs` | Agent-operated administrative capability | Hardened Git argv/environment under `GitWorktree`; metadata write access is explicit and audited. |
| `tools/bash/kill.rs` | Enforcement core | Unix uses syscalls; Windows `taskkill` is a fail-closed cleanup fallback and is not model-selected. |
| `services/lsp_pool.rs` | Test/injected service | Production accepts an `LspSpawner`; direct sleep/timeout constructors occur only in its test module. Agent LSP uses `tools/lsp.rs`. |
| `cli/repl/input.rs`, `cli/repl/permissions.rs` | User-operated | Interactive editor and `!` command launch paths; not registered as model tools. |
| `tui/app.rs`, `tui/events.rs` | User-operated | Explicit interactive shell/editor/application actions; isolated from tool dispatch. |
| `cli/repl/slash.rs`, `cli/repl/review.rs`, `cli/commit_pipeline.rs`, `main.rs` | User/administrator GitHub workflow | Resolved Git/GitHub binaries used only from CLI commands. |
| `plugins/git.rs` | User-operated plugin administration | Installation/update Git operations reached from explicit plugin management, not the model registry. |
| `cli/commands/auth.rs` | User-operated | Opens the OAuth URL in a desktop browser. |
| `transcript.rs` | User-operated presentation | Read-only resolved Git metadata for transcript display. |

The model tool registry exposes no generic host-process API. ACP maps Bash,
file, edit, list, glob, and grep requests back through the same local tool
registry and cannot delegate unrestricted filesystem or terminal access to
the client.

//! Tool handler registry — OCP-clean dispatch for tools, mirroring #232's
//! `CommandRegistry` pattern.
//!
//! Adding a new tool is now:
//!   1. Define a unit struct and implement [`ToolHandler`] for it.
//!   2. Add one line to [`HANDLERS`].
//!
//! The central match arms in `execute_tool_with_memory`, `execute_tool_full`,
//! and `execute_tool_with_tasks` have been replaced by
//! [`ToolRegistry::dispatch`].
//!
//! Each handler also owns its OpenAI-format schema via
//! [`ToolHandler::definition`], so the model-facing tool list emitted by
//! `tools::get_tool_definitions` is now composed from the same place the
//! tool's execute logic lives. This closes the schema/handler drift identified
//! in crosslink #463 (schemas were previously hand-maintained in a 684-line
//! `json!` macro far from the code that interpreted the arguments).

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::config::AppConfig;
use crate::memory::MemoryDb;
use crate::session::TaskManager;
use serde_json::{json, Value};

// ─── Context ─────────────────────────────────────────────────────────────────

/// Everything a [`ToolHandler`] may need at dispatch time.
///
/// Bundles the three optional context objects that the old 3-function overload
/// set threaded independently. Handlers that don't need a field ignore it.
pub struct ToolContext<'a> {
    /// Immutable filesystem/process capabilities for this session.
    pub security: Result<std::sync::Arc<super::security::ToolSecurityContext>, String>,
    /// Optional archival memory database (stateful mode).
    pub memory_db: Option<&'a MemoryDb>,
    /// Optional application configuration (subagent tools).
    pub app_config: Option<&'a AppConfig>,
    /// Optional mutable session task manager (task_* tools).
    pub task_mgr: Option<&'a mut TaskManager>,
}

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Permission-checking metadata for a tool (crosslink #782).
///
/// Each tool that can mutate user state must declare a [`PermissionTarget`]
/// from its [`ToolHandler::permission_target`] method. The
/// `PermissionManager` consults this metadata at dispatch time instead of
/// pattern-matching on a hard-coded list of tool names. Tools that return
/// `None` from `permission_target` are treated as read-only / safe and
/// bypass permission checks.
///
/// Why this exists: prior to #782, `PermissionManager::extract_target` held
/// an `_ => None` catch-all `match` over three tool names. Any new tool
/// added to the registry — `delete_file`, `chmod`, `run_subprocess`, an MCP
/// write tool — would silently fail-open. Inverting the dependency closes
/// that gap: a new mutating tool must either declare its target or
/// explicitly opt out by returning `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionTarget {
    /// Canonical capability name used in `PermissionRule::tool` — e.g.
    /// `"Bash"`, `"Edit"`, `"Write"`. Multiple wire-level tool names may
    /// share a canonical capability (e.g. a future `bash_persistent` could
    /// canonicalise to `"Bash"` so existing rules continue to cover it).
    pub canonical: &'static str,
    /// JSON argument key whose string value is the pattern-match target.
    /// For `bash` this is `"command"`; for file tools it is the path arg
    /// (`"path"` for `edit_file`/`write_file`, `"notebook_path"` for
    /// `notebook_edit`).
    pub arg_key: &'static str,
}

/// A single tool that the agent can invoke.
///
/// Implementations are unit structs stored as `&'static dyn ToolHandler`
/// inside the registry map, avoiding any heap allocation per dispatch.
/// The `execute` method receives context by `&mut` so that task handlers
/// can access the mutable `TaskManager` field.
pub trait ToolHandler: Send + Sync {
    /// The canonical tool name sent by the model.
    fn name(&self) -> &'static str;

    /// The OpenAI-format function definition for this tool — the JSON the
    /// upstream API sees as a tool description. Returned as a `Value` because
    /// every tool ultimately serialises to JSON; constructing via `json!` here
    /// keeps the schema next to the execute logic that interprets it.
    fn definition(&self) -> Value;

    /// Declare this tool's permission-check target (crosslink #782).
    ///
    /// Return `Some(PermissionTarget { canonical, arg_key })` if the tool
    /// mutates user state and should be gated by the permission system. The
    /// permission manager will look up `arg_key` in the tool's arguments
    /// and match its string value against rules keyed by `canonical`.
    ///
    /// The default returns `None`, which treats the tool as read-only /
    /// safe and lets it bypass permission checks. Override this method on
    /// every new mutating tool — leaving the default in place on a
    /// destructive tool is the bug class #782 closed.
    fn permission_target(&self) -> Option<PermissionTarget> {
        None
    }

    /// Execute the tool through the canonical typed result boundary.
    ///
    /// Existing leaf executors are adapted here while they migrate one by one;
    /// registry/provider/frontend callers never receive their tuple shape.
    fn execute(
        &self,
        args: &HashMap<String, Value>,
        ctx: &mut ToolContext<'_>,
    ) -> ToolHandlerResult {
        let (content, is_error) = self.execute_legacy(args, ctx);
        ToolHandlerResult::legacy(content, is_error)
    }

    /// Temporary leaf-executor compatibility seam.  It is deliberately below
    /// the handler contract: dispatch always calls [`Self::execute`].
    #[doc(hidden)]
    fn execute_legacy(
        &self,
        _args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        unreachable!("typed handler must override execute")
    }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

/// Maps tool names to static handler references.
pub struct ToolRegistry {
    handlers: HashMap<&'static str, &'static dyn ToolHandler>,
}

impl ToolRegistry {
    /// Look up a handler by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&'static dyn ToolHandler> {
        self.handlers.get(name).copied()
    }

    /// Dispatch `tool_name` with `args` to the registered handler, or return
    /// `None` if no handler is registered (caller handles unknown-tool path).
    pub fn dispatch(
        &self,
        tool_name: &str,
        args: &HashMap<String, Value>,
        ctx: &mut ToolContext<'_>,
    ) -> Option<ToolHandlerResult> {
        if let Err(error) = &ctx.security {
            return Some(ToolHandlerResult::error(ToolFailure::new(
                ToolFailureCode::Unavailable,
                format!("Tool execution is blocked because session capabilities are unavailable: {error}"),
                ToolRetryability::Never,
            )));
        }
        self.handlers.get(tool_name).map(|h| h.execute(args, ctx))
    }
}

// ─── Handler implementations ──────────────────────────────────────────────────

use super::crosslink as crosslink_tool;
use super::{
    ask_user, bash, cron, file, grounding, lsp, plan_mode, skill, task, todo, tool_search, web,
    worktree, ToolFailure, ToolFailureCode, ToolHandlerResult, ToolRetryability,
};

// ── bash ─────────────────────────────────────────────────────────────────────

struct BashHandler;
impl ToolHandler for BashHandler {
    fn name(&self) -> &'static str {
        "bash"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "bash",
                "description": "Execute a bash shell command and return the output. On Windows, Git Bash is used so standard Unix commands (ls, grep, find, cat, etc.) work normally. Use this for running commands, installing packages, git operations, file exploration, etc. Use run_in_background for long-running commands.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The bash command to execute. Unix-style commands work on all platforms."
                        },
                        "run_in_background": {
                            "type": "boolean",
                            "description": "If true, run the command in the background and return a shell_id. Use bash_output to retrieve output later."
                        }
                    },
                    "required": ["command"]
                }
            }
        })
    }
    fn permission_target(&self) -> Option<PermissionTarget> {
        // #782: Bash is the canonical "run-anything" capability — gated.
        Some(PermissionTarget {
            canonical: "Bash",
            arg_key: "command",
        })
    }
    fn execute(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> ToolHandlerResult {
        ToolHandlerResult::from_migrated(bash::try_execute_bash(args))
    }
}

struct BashOutputHandler;
impl ToolHandler for BashOutputHandler {
    fn name(&self) -> &'static str {
        "bash_output"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "bash_output",
                "description": "Retrieve output from a background shell. Returns new output since last check, along with status (running/finished) and exit code if finished.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "shell_id": {
                            "type": "string",
                            "description": "The shell ID returned from a bash command with run_in_background=true. Omit this field to list all background shells."
                        }
                    }
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        bash::execute_bash_output(args)
    }
}

struct KillShellHandler;
impl ToolHandler for KillShellHandler {
    fn name(&self) -> &'static str {
        "kill_shell"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "kill_shell",
                "description": "Terminate a background shell process.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "shell_id": {
                            "type": "string",
                            "description": "The shell ID to terminate"
                        }
                    },
                    "required": ["shell_id"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        bash::execute_kill_shell(args)
    }
}

struct KillShellsForAgentHandler;
impl ToolHandler for KillShellsForAgentHandler {
    fn name(&self) -> &'static str {
        "kill_shells_for_agent"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "kill_shells_for_agent",
                "description": "Terminate all background shell processes owned by a specific subagent or session.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "The agent or session ID whose background shells should be terminated"
                        }
                    },
                    "required": ["agent_id"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        bash::execute_kill_shells_for_agent(args)
    }
}

// ── file ─────────────────────────────────────────────────────────────────────

struct ReadFileHandler;
impl ToolHandler for ReadFileHandler {
    fn name(&self) -> &'static str {
        "read_file"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read the contents of a file. Returns the file content as text with line numbers. Supports images (PNG, JPG, GIF, WebP) via base64 encoding, PDFs via pdftotext extraction, and Jupyter notebooks (.ipynb) with formatted cell output.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path to read. Absolute paths are accepted; relative paths are resolved against the current working directory."
                        },
                        "offset": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Line number to start reading from (1-indexed). Defaults to 1."
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum number of lines to read. Defaults to reading entire file."
                        },
                        "pages": {
                            "type": "string",
                            "description": "Page range for PDF files (e.g., '1-5', '3', '10-20'). Required for PDFs with more than 10 pages."
                        }
                    },
                    "required": ["path"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        file::execute_read_file(args)
    }
}

struct GroundingContextHandler;
impl ToolHandler for GroundingContextHandler {
    fn name(&self) -> &'static str {
        "grounding_context"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "grounding_context",
                "description": "Hydrate selected Reality Ledger observation IDs from the current session. Use this to inspect evidence from the grounding index before citing detailed file, command, diff, tool, or verification facts.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ids": {
                            "type": "array",
                            "description": "Observation IDs to hydrate, as strings from the Reality Ledger index.",
                            "items": {
                                "type": "string"
                            },
                            "minItems": 1,
                            "maxItems": 16
                        },
                        "include_stale": {
                            "type": "boolean",
                            "description": "If true, include stale observations for historical navigation. Stale observations are never authoritative evidence."
                        }
                    },
                    "required": ["ids"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        grounding::execute_grounding_context(args)
    }
}

struct WriteFileHandler;
impl ToolHandler for WriteFileHandler {
    fn name(&self) -> &'static str {
        "write_file"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "Write content to a file. Creates the file if it doesn't exist. To overwrite an existing file, first read it successfully with read_file in the same session; failed reads do not satisfy the overwrite gate.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path to write. Absolute paths are accepted; relative paths are resolved against the current working directory."
                        },
                        "content": {
                            "type": "string",
                            "description": "The content to write to the file"
                        }
                    },
                    "required": ["path", "content"]
                }
            }
        })
    }
    fn permission_target(&self) -> Option<PermissionTarget> {
        // #782: file-write capability — gated on the destination path.
        Some(PermissionTarget {
            canonical: "Write",
            arg_key: "path",
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        file::execute_write_file(args)
    }
}

struct EditFileHandler;
impl ToolHandler for EditFileHandler {
    fn name(&self) -> &'static str {
        "edit_file"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "edit_file",
                "description": "Make a targeted edit to a file by replacing old_string with new_string. The file must first be read successfully with read_file in the same session, and old_string must match exactly.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path to edit. Absolute paths are accepted; relative paths are resolved against the current working directory."
                        },
                        "old_string": {
                            "type": "string",
                            "description": "The exact string to find and replace"
                        },
                        "new_string": {
                            "type": "string",
                            "description": "The string to replace it with"
                        },
                        "replace_all": {
                            "type": "boolean",
                            "description": "If true, replace every occurrence of old_string. Defaults to false, which requires old_string to match exactly once."
                        }
                    },
                    "required": ["path", "old_string", "new_string"]
                }
            }
        })
    }
    fn permission_target(&self) -> Option<PermissionTarget> {
        // #782: file-edit capability — gated on the path being edited.
        Some(PermissionTarget {
            canonical: "Edit",
            arg_key: "path",
        })
    }
    fn execute(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> ToolHandlerResult {
        file::execute_edit_file(args)
    }
}

struct NotebookEditHandler;
impl ToolHandler for NotebookEditHandler {
    fn name(&self) -> &'static str {
        "notebook_edit"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "notebook_edit",
                "description": "Edit a Jupyter notebook (.ipynb file). Supports replacing cell contents, inserting new cells, and deleting cells. The notebook must be read successfully with read_file in the same session before editing. Accepts either `cell_id` (Claude Code-compatible stable ID from the notebook's cell metadata) or `cell_number` (0-indexed position). For `insert`, `cell_id` means 'insert after this cell' and omitting it inserts at the beginning.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "notebook_path": {
                            "type": "string",
                            "description": "Notebook path to edit. Absolute paths are accepted; relative paths are resolved against the current working directory."
                        },
                        "cell_id": {
                            "type": "string",
                            "description": "Claude Code-compatible stable cell ID (preferred over cell_number). For `insert`, new cell is added after this one; omit to insert at the beginning."
                        },
                        "cell_number": {
                            "type": "integer",
                            "description": "Legacy 0-indexed cell position. Use `cell_id` when possible — `cell_number` is kept only for back-compat with earlier OpenClaudia sessions."
                        },
                        "new_source": {
                            "type": "string",
                            "description": "The new source content for the cell. For delete mode, this can be empty."
                        },
                        "cell_type": {
                            "type": "string",
                            "enum": ["code", "markdown", "raw"],
                            "description": "The type of cell. Required when inserting a new cell."
                        },
                        "edit_mode": {
                            "type": "string",
                            "enum": ["replace", "insert", "delete"],
                            "description": "The edit operation: 'replace' (default) overwrites cell source, 'insert' adds a new cell at the index, 'delete' removes the cell."
                        }
                    },
                    "required": ["notebook_path", "new_source"]
                }
            }
        })
    }
    fn permission_target(&self) -> Option<PermissionTarget> {
        // #782: notebook_edit mutates .ipynb files on disk — the pre-#782
        // hardcoded match in `extract_target` silently fail-opened this
        // handler. Canonicalising as "Edit" lets existing Edit session
        // rules (e.g. "src/**") naturally cover notebook edits.
        Some(PermissionTarget {
            canonical: "Edit",
            arg_key: "notebook_path",
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        file::execute_notebook_edit(args)
    }
}

struct ListFilesHandler;
impl ToolHandler for ListFilesHandler {
    fn name(&self) -> &'static str {
        "list_files"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "list_files",
                "description": "List files and directories at a given path. Returns a list of entries.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Directory path to list. Absolute paths are accepted; relative paths are resolved against the current working directory. Defaults to the current working directory."
                        }
                    },
                    "required": []
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        file::execute_list_files(args)
    }
}

struct GlobHandler;
impl ToolHandler for GlobHandler {
    fn name(&self) -> &'static str {
        "glob"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "glob",
                "description": "Find files by glob pattern. Supports `*` (any non-/), `**` (any including /), and `?`. Returns up to 100 paths sorted lexicographically. Vendor directories (.git, node_modules, target, dist, build) are skipped by default. Crosslink #567.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Glob pattern matched against paths relative to `path`. Examples: '*.rs', 'src/**/*.rs', '**/Cargo.toml'."
                        },
                        "path": {
                            "type": "string",
                            "description": "Directory to walk (defaults to current working directory). Must lie within the project root."
                        }
                    },
                    "required": ["pattern"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        file::execute_glob(args)
    }
}

struct GrepHandler;
impl ToolHandler for GrepHandler {
    fn name(&self) -> &'static str {
        "grep"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "grep",
                "description": "Search file contents by regex. Returns matching lines as `file:line:text` with optional ±N context lines emitted as `file-N-text`. Vendor dirs are skipped. Capped at 200 matches. Crosslink #568.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Regex pattern (Rust `regex` crate dialect)."
                        },
                        "path": {
                            "type": "string",
                            "description": "Directory to search (defaults to current working directory)."
                        },
                        "context_lines": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Number of ±N context lines to include around each match (default 0)."
                        },
                        "case_insensitive": {
                            "type": "boolean",
                            "description": "If true, prepend `(?i)` to the pattern (default false)."
                        }
                    },
                    "required": ["pattern"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        file::execute_grep(args)
    }
}

// ── crosslink ─────────────────────────────────────────────────────────────────
//
// Deep library-backed replacement for the legacy `chainlink` tool. Same
// argv-string contract for prompt compatibility, but the underlying calls
// go through `crosslink::db::Database::*` instead of forking a subprocess.

struct CrosslinkHandler;
impl ToolHandler for CrosslinkHandler {
    fn name(&self) -> &'static str {
        "crosslink"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "crosslink",
                "description": "Persistent issue tracker + session memory backed by the crosslink library (local SQLite, no subprocess). Subcommands: 'create \"<title>\" [-p priority] [-l label] [-d desc]', 'close <id>', 'reopen <id>', 'comment <id> \"<text>\"', 'label <id> <label>' / 'unlabel <id> <label>', 'list [-s status] [-l label] [-p priority]', 'show <id>', 'search \"<query>\"', 'subissue <parent_id> \"<title>\" [-p priority]', 'relate <id1> <id2>', 'block <blocker_id> <blocked_id>' / 'unblock ...', 'session start | end [--notes \"...\"] | work <id> | action \"...\" | status', 'next' (suggest highest-priority ready issue), 'tree [<root_id>]', 'update <id> [-t title] [-d desc] [-p priority]'. Use this for cross-session memory: track open work, leave handoff notes, mark dependencies. Survives context compression and session restarts.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "args": {
                            "type": "string",
                            "description": "The crosslink subcommand + arguments (e.g. 'create \"Fix auth bug\" -p high -l bug' or 'session end --notes \"PR ready for review\"')."
                        }
                    },
                    "required": ["args"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        crosslink_tool::execute_crosslink(args)
    }
}

// ── web ───────────────────────────────────────────────────────────────────────

#[cfg(feature = "browser")]
const WEB_FETCH_DESCRIPTION: &str = "Fetch the content of a web page and return it as markdown. Uses direct HTTP first, then a headless Chromium fallback for JavaScript-rendered pages or browser challenges. Use this to read documentation, articles, or other web content.";

#[cfg(not(feature = "browser"))]
const WEB_FETCH_DESCRIPTION: &str = "Fetch the content of a web page and return it as markdown using direct HTTP. This build does not include JavaScript rendering or headless-browser challenge handling; rebuild with the default `browser` feature for that fallback.";

#[cfg(feature = "browser")]
const WEB_SEARCH_DESCRIPTION: &str = "Search the web and return relevant results using free DuckDuckGo/Bing browser scraping. No search API key is required. Returns titles, snippets, and URLs. `allowed_domains` / `blocked_domains` mirror Claude Code's WebSearchTool — results are filtered to domains that match (or don't match) the respective list.";

struct WebFetchHandler;
impl ToolHandler for WebFetchHandler {
    fn name(&self) -> &'static str {
        "web_fetch"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "web_fetch",
                "description": WEB_FETCH_DESCRIPTION,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The URL to fetch (must be a valid http:// or https:// URL)"
                        },
                        "prompt": {
                            "type": "string",
                            "description": "Optional question to answer from the fetched page. Used when web_fetch.distillation_enabled=true; otherwise the fetched raw markdown is returned."
                        }
                    },
                    "required": ["url"]
                }
            }
        })
    }
    fn permission_target(&self) -> Option<PermissionTarget> {
        Some(PermissionTarget {
            canonical: "WebFetch",
            arg_key: "url",
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        web::execute_web_fetch_with_config(args, ctx.app_config)
    }
}

#[cfg(feature = "browser")]
struct WebSearchHandler;
#[cfg(feature = "browser")]
impl ToolHandler for WebSearchHandler {
    fn name(&self) -> &'static str {
        "web_search"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "web_search",
                "description": WEB_SEARCH_DESCRIPTION,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "The search query (must be at least 2 characters)"
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 10,
                            "description": "Maximum number of results to return (1-10, default: 5)"
                        },
                        "allowed_domains": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Only include search results from these domains. Matches the hostname suffix, so 'docs.python.org' would match both 'docs.python.org' and 'foo.docs.python.org'."
                        },
                        "blocked_domains": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Never include search results from these domains. Same hostname-suffix matching as `allowed_domains`. Takes precedence when a result matches both lists."
                        }
                    },
                    "required": ["query"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        web::execute_web_search(args)
    }
}

// Only registered when the `browser` feature is compiled in — offering the
// model a tool whose every invocation fails ("rebuild with --features
// browser") pollutes tool selection and wastes a turn.
#[cfg(feature = "browser")]
struct WebBrowserHandler;
#[cfg(feature = "browser")]
impl ToolHandler for WebBrowserHandler {
    fn name(&self) -> &'static str {
        "web_browser"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "web_browser",
                "description": "Fetch a web page using a full headless Chrome browser. Use this as a fallback when web_fetch fails due to complex JavaScript, authentication, or strict bot protection. Requires the 'browser' feature to be enabled at build time.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "The URL to fetch (must be a valid http:// or https:// URL)"
                        }
                    },
                    "required": ["url"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        web::execute_web_browser(args)
    }
}

// ── lsp ───────────────────────────────────────────────────────────────────────

struct LspHandler;
impl ToolHandler for LspHandler {
    fn name(&self) -> &'static str {
        "lsp"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "lsp",
                "description": "Perform code intelligence operations via Language Server Protocol. Communicates with external language servers (rust-analyzer, typescript-language-server, pylsp, gopls, clangd, etc.). Automatically detects the appropriate language server based on file extension. Line numbers are 1-indexed.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": [
                                "goToDefinition",
                                "findReferences",
                                "hover",
                                "documentSymbols",
                                "workspaceSymbol",
                                "goToImplementation",
                                "prepareCallHierarchy",
                                "incomingCalls",
                                "outgoingCalls"
                            ],
                            "description": "The LSP operation to perform"
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Absolute path to the source file"
                        },
                        "line": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "1-indexed line number of the symbol (required for position-pointing ops)"
                        },
                        "character": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "0-indexed character offset within the line (required for position-pointing ops)"
                        },
                        "query": {
                            "type": "string",
                            "description": "Symbol-name query for workspaceSymbol (empty string lists all)"
                        },
                        "hierarchy_item": {
                            "type": "object",
                            "description": "Previously-fetched CallHierarchyItem (returned by prepareCallHierarchy); required by incomingCalls / outgoingCalls"
                        }
                    },
                    "required": ["action", "file_path"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        lsp::execute_lsp(args)
    }
}

// ── todo ─────────────────────────────────────────────────────────────────────

struct TodoWriteHandler;
impl ToolHandler for TodoWriteHandler {
    fn name(&self) -> &'static str {
        "todo_write"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "todo_write",
                "description": "Create and manage a structured task list. Use this as a fallback when crosslink is unavailable. Helps track progress and show the user what you're working on. Only one task should be 'in_progress' at a time.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "todos": {
                            "type": "array",
                            "description": "The complete todo list (replaces existing list)",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "content": {
                                        "type": "string",
                                        "description": "Task description in imperative form (e.g., 'Fix the bug')"
                                    },
                                    "status": {
                                        "type": "string",
                                        "enum": ["pending", "in_progress", "completed"],
                                        "description": "Task status"
                                    },
                                    "activeForm": {
                                        "type": "string",
                                        "description": "Task in present continuous form (e.g., 'Fixing the bug')"
                                    }
                                },
                                "required": ["content", "status", "activeForm"]
                            }
                        }
                    },
                    "required": ["todos"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        todo::execute_todo_write(args)
    }
}

struct TodoReadHandler;
impl ToolHandler for TodoReadHandler {
    fn name(&self) -> &'static str {
        "todo_read"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "todo_read",
                "description": "Read the current todo list. Returns all tasks with their status.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        _args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        todo::execute_todo_read()
    }
}

// ── ask_user ─────────────────────────────────────────────────────────────────

struct AskUserQuestionHandler;
impl ToolHandler for AskUserQuestionHandler {
    fn name(&self) -> &'static str {
        "ask_user_question"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "ask_user_question",
                "description": "Ask the user one or more structured questions with predefined options. Use this when you need clarification or want the user to make a choice before proceeding. Each question can have 2-4 options plus an automatic 'Other' option. Supports single- or multi-select (via `multiSelect`). Question texts must be unique across the array, and option labels must be unique within each question.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "questions": {
                            "type": "array",
                            "description": "1-4 questions to ask the user",
                            "minItems": 1,
                            "maxItems": 4,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "question": {
                                        "type": "string",
                                        "description": "The question text to display"
                                    },
                                    "header": {
                                        "type": "string",
                                        "description": "Short label (max 12 chars) shown as a tag",
                                        "maxLength": 12
                                    },
                                    "options": {
                                        "type": "array",
                                        "description": "2-4 answer options",
                                        "minItems": 2,
                                        "maxItems": 4,
                                        "items": {
                                            "type": "object",
                                            "properties": {
                                                "label": {
                                                    "type": "string",
                                                    "description": "Option name (e.g., 'PostgreSQL')"
                                                },
                                                "description": {
                                                    "type": "string",
                                                    "description": "Brief description of this option"
                                                },
                                                "preview": {
                                                    "type": "string",
                                                    "description": "Optional preview content (mockup, code snippet, comparison) rendered when this option is focused. Claude Code-compatible."
                                                }
                                            },
                                            "required": ["label", "description"]
                                        }
                                    },
                                    "multiSelect": {
                                        "type": "boolean",
                                        "description": "If true, user can select multiple options (comma-separated). Claude Code-compatible name; `multi_select` is also accepted for back-compat."
                                    }
                                },
                                "required": ["question", "header", "options"]
                            }
                        }
                    },
                    "required": ["questions"]
                }
            }
        })
    }
    fn execute(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> ToolHandlerResult {
        ask_user::execute_ask_user_question(args)
    }
}

// ── worktree ─────────────────────────────────────────────────────────────────

struct EnterWorktreeHandler;
impl ToolHandler for EnterWorktreeHandler {
    fn name(&self) -> &'static str {
        "enter_worktree"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "enter_worktree",
                "description": "Create an isolated git worktree under .worktrees/<branch>/ based on the current HEAD. Returns the new worktree path. Does NOT change the process working directory — pass the returned path to subsequent bash/file calls (and to exit_worktree) to operate inside the worktree.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "branch": {
                            "type": "string",
                            "description": "The branch name to create for the worktree (e.g., 'agent/fix-bug-123')"
                        }
                    },
                    "required": ["branch"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        worktree::execute_enter_worktree(args)
    }
}

struct ExitWorktreeHandler;
impl ToolHandler for ExitWorktreeHandler {
    fn name(&self) -> &'static str {
        "exit_worktree"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "exit_worktree",
                "description": "Remove an isolated git worktree previously created by enter_worktree. Optionally commits and merges changes back, or explicitly discards dirty work. Does NOT change the process working directory.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the worktree to exit (as returned by enter_worktree)."
                        },
                        "apply_changes": {
                            "type": "boolean",
                            "description": "If true, commit any uncommitted changes and merge the worktree branch into the main branch before removal. If false (default), removal succeeds only when the worktree is clean unless discard_changes=true is also passed."
                        },
                        "discard_changes": {
                            "type": "boolean",
                            "description": "If true with apply_changes=false, explicitly discard uncommitted work and remove the worktree. Defaults to false to prevent accidental data loss."
                        }
                    },
                    "required": ["path"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        worktree::execute_exit_worktree(args)
    }
}

struct ListWorktreesHandler;
impl ToolHandler for ListWorktreesHandler {
    fn name(&self) -> &'static str {
        "list_worktrees"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "list_worktrees",
                "description": "List all active git worktrees in the current repository, showing their paths and branches.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        _args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        worktree::execute_list_worktrees()
    }
}

// ── cron ─────────────────────────────────────────────────────────────────────

struct CronCreateHandler;
impl ToolHandler for CronCreateHandler {
    fn name(&self) -> &'static str {
        "cron_create"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "cron_create",
                "description": "Create recurring schedule metadata with a cron expression. Schedules are stored in .openclaudia/schedules.json for external schedulers; OpenClaudia does not run them automatically.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Unique name for the schedule (e.g., 'daily-cleanup')"
                        },
                        "schedule": {
                            "type": "string",
                            "description": "Standard 5-field cron expression: minute hour day month weekday (e.g., '0 9 * * 1-5' for weekdays at 9am)"
                        },
                        "prompt": {
                            "type": "string",
                            "description": "The prompt or command to execute on each trigger"
                        },
                        "recurring": {
                            "type": "boolean",
                            "description": "Whether downstream schedulers should recur after each trigger (default: true)"
                        },
                        "durable": {
                            "type": "boolean",
                            "description": "Whether downstream schedulers should treat this as durable schedule metadata (default: true)"
                        }
                    },
                    "required": ["name", "schedule", "prompt"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        cron::execute_cron_create(args)
    }
}

struct CronDeleteHandler;
impl ToolHandler for CronDeleteHandler {
    fn name(&self) -> &'static str {
        "cron_delete"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "cron_delete",
                "description": "Delete stored cron schedule metadata by name, list index, or legacy ID.",
                "parameters": {
                    "type": "object",
                    "description": "Provide exactly one identifier: name, index, or id. Prefer name when available; use index from cron_list output or legacy id only when name is unavailable.",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Preferred schedule name to delete"
                        },
                        "index": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "1-based index from the cron_list output"
                        },
                        "id": {
                            "type": "string",
                            "description": "Legacy persisted schedule ID (16-character hex string)"
                        }
                    },
                    "required": []
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        cron::execute_cron_delete(args)
    }
}

struct CronListHandler;
impl ToolHandler for CronListHandler {
    fn name(&self) -> &'static str {
        "cron_list"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "cron_list",
                "description": "List stored cron schedule metadata, including enabled status, cron expressions, prompts, and any recorded run counters.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        _args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        cron::execute_cron_list(&HashMap::new())
    }
}

// ── plan_mode ────────────────────────────────────────────────────────────────

#[cfg(feature = "browser")]
const ENTER_PLAN_MODE_DESCRIPTION: &str = "Switch to plan mode. In plan mode, only read-only/navigation tools (read_file, grounding_context, list_files, grep, web_fetch, web_search, web_browser, bash_output, todo_read, crosslink), ask_user_question, and subagent tools (task, agent_output) are available. Write/Edit/Bash are blocked except write_file may write only to the plan file. This is useful when you want to analyze the codebase and create a structured implementation plan before making changes.";

#[cfg(not(feature = "browser"))]
const ENTER_PLAN_MODE_DESCRIPTION: &str = "Switch to plan mode. In plan mode, only read-only/navigation tools (read_file, grounding_context, list_files, grep, web_fetch, bash_output, todo_read, crosslink), ask_user_question, and subagent tools (task, agent_output) are available. Write/Edit/Bash are blocked except write_file may write only to the plan file. Browser-backed web_search and web_browser are unavailable in this build. This is useful when you want to analyze the codebase and create a structured implementation plan before making changes.";

struct EnterPlanModeHandler;
impl ToolHandler for EnterPlanModeHandler {
    fn name(&self) -> &'static str {
        "enter_plan_mode"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "enter_plan_mode",
                "description": ENTER_PLAN_MODE_DESCRIPTION,
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        })
    }
    fn execute(
        &self,
        _args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> ToolHandlerResult {
        plan_mode::execute_enter_plan_mode()
    }
}

struct ExitPlanModeHandler;
impl ToolHandler for ExitPlanModeHandler {
    fn name(&self) -> &'static str {
        "exit_plan_mode"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "exit_plan_mode",
                "description": "Exit plan mode and return to build mode. The plan file content will be shown to the user for approval. If approved, full tool access is restored and the plan is injected as context. If rejected, you stay in plan mode.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "allowed_prompts": {
                            "type": "array",
                            "description": "Optional list of allowed tool+prompt pairs that constrain what operations are permitted after plan approval",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "tool": {
                                        "type": "string",
                                        "description": "Tool name (e.g., 'write_file', 'bash')"
                                    },
                                    "prompt": {
                                        "type": "string",
                                        "description": "Description of the allowed operation"
                                    }
                                },
                                "required": ["tool", "prompt"]
                            }
                        }
                    },
                    "required": []
                }
            }
        })
    }
    fn execute(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> ToolHandlerResult {
        plan_mode::execute_exit_plan_mode(args)
    }
}

// ── task (session task management) ────────────────────────────────────────────

const NO_SESSION: (&str, bool) = ("Task management not available (no session)", true);

struct TaskCreateHandler;
impl ToolHandler for TaskCreateHandler {
    fn name(&self) -> &'static str {
        "task_create"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "task_create",
                "description": "Create a new structured task with dependency tracking. Tasks are stored in the session and support blocking/blocked_by relationships. Only one task can be in_progress at a time.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "subject": {
                            "type": "string",
                            "description": "Brief title in imperative form (e.g., 'Add permission system')"
                        },
                        "description": {
                            "type": "string",
                            "description": "Detailed description of the task"
                        },
                        "active_form": {
                            "type": "string",
                            "description": "Present continuous form for spinner display (e.g., 'Adding permission system')"
                        }
                    },
                    "required": ["subject", "description"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        ctx.task_mgr.as_deref_mut().map_or_else(
            || (NO_SESSION.0.to_string(), NO_SESSION.1),
            |tm| task::execute_task_create(args, tm),
        )
    }
}

struct TaskUpdateHandler;
impl ToolHandler for TaskUpdateHandler {
    fn name(&self) -> &'static str {
        "task_update"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "task_update",
                "description": "Update an existing task's status, subject, description, or dependencies. Setting status to 'in_progress' will demote any currently in-progress task to 'pending'. Setting status to 'deleted' removes the task entirely.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "task_id": {
                            "type": "string",
                            "description": "The task ID (e.g., 'task-1')"
                        },
                        "status": {
                            "type": "string",
                            "enum": ["pending", "in_progress", "completed", "deleted"],
                            "description": "New task status"
                        },
                        "subject": {
                            "type": "string",
                            "description": "Updated task title"
                        },
                        "description": {
                            "type": "string",
                            "description": "Updated task description"
                        },
                        "active_form": {
                            "type": "string",
                            "description": "Updated spinner text (present continuous form)"
                        },
                        "add_blocks": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Task IDs that this task blocks (downstream dependencies)"
                        },
                        "add_blocked_by": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Task IDs that block this task (upstream dependencies)"
                        }
                    },
                    "required": ["task_id"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        ctx.task_mgr.as_deref_mut().map_or_else(
            || (NO_SESSION.0.to_string(), NO_SESSION.1),
            |tm| task::execute_task_update(args, tm),
        )
    }
}

struct TaskGetHandler;
impl ToolHandler for TaskGetHandler {
    fn name(&self) -> &'static str {
        "task_get"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "task_get",
                "description": "Get full details of a specific task including its dependencies, status, and timestamps.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "task_id": {
                            "type": "string",
                            "description": "The task ID (e.g., 'task-1')"
                        }
                    },
                    "required": ["task_id"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        ctx.task_mgr.as_deref_mut().map_or_else(
            || (NO_SESSION.0.to_string(), NO_SESSION.1),
            |tm| task::execute_task_get(args, tm),
        )
    }
}

struct TaskListHandler;
impl ToolHandler for TaskListHandler {
    fn name(&self) -> &'static str {
        "task_list"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "task_list",
                "description": "List all tasks with their status and dependency summary. Shows pending, in-progress, and completed counts.",
                "parameters": {
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        _args: &HashMap<String, Value>,
        ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        ctx.task_mgr.as_deref_mut().map_or_else(
            || (NO_SESSION.0.to_string(), NO_SESSION.1),
            |tm| task::execute_task_list(tm),
        )
    }
}

// ── mcp resource tools ────────────────────────────────────────────────────────
//
// These tools dispatch through the process-wide MCP manager installed by the
// proxy/TUI startup path. Keeping schema and dispatch in the registry prevents
// MCP resource support from drifting back into an advertised-but-unreachable
// tool surface.

struct ListMcpResourcesHandler;
impl ToolHandler for ListMcpResourcesHandler {
    fn name(&self) -> &'static str {
        "list_mcp_resources"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "list_mcp_resources",
                "description": "List resources available from connected MCP servers. Resources are data sources (files, database tables, API endpoints) that MCP servers expose for reading.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "server": {
                            "type": "string",
                            "description": "Optional: filter resources to a specific MCP server by name. If omitted, lists resources from all connected servers."
                        }
                    },
                    "required": []
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        let server_filter = match optional_registry_string_arg(args, "server") {
            Ok(server) => server.map(str::to_string),
            Err(err) => return (format!("list_mcp_resources: {err}"), true),
        };
        let Some(mgr) = crate::mcp::registered_manager() else {
            return (
                "No MCP manager has been installed for this session. \
                 Configure MCP servers under `mcp.servers` in \
                 `.openclaudia/config.yaml` and re-launch."
                    .to_string(),
                true,
            );
        };
        // We're already inside `pipeline::execute_single_tool`'s
        // `spawn_blocking` thread, so blocking on the runtime here
        // does NOT pin the current_thread executor. See the docstring
        // on `REGISTERED_MANAGER` in `src/mcp.rs` for the architecture.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return (
                "list_mcp_resources requires an active tokio runtime to \
                 dispatch into the async MCP manager."
                    .to_string(),
                true,
            );
        };
        let mgr = mgr.clone();
        let result = handle.block_on(async move {
            let guard = mgr.read().await;
            guard.list_resources(server_filter.as_deref()).await
        });
        match result {
            Ok(entries) if entries.is_empty() => (
                "No MCP resources are exposed by the connected servers.".to_string(),
                false,
            ),
            Ok(entries) => {
                let body = entries
                    .iter()
                    .map(|(server, res)| {
                        format!(
                            "{server}\t{uri}\t{name}{desc}",
                            uri = res.uri,
                            name = res.name,
                            desc = res
                                .description
                                .as_deref()
                                .map(|d| format!("\t{d}"))
                                .unwrap_or_default(),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let header = format!(
                    "{count} resource(s) across MCP servers:\nserver\turi\tname[\tdescription]\n",
                    count = entries.len()
                );
                (format!("{header}{body}"), false)
            }
            Err(e) => (format!("list_mcp_resources failed: {e}"), true),
        }
    }
}

struct ReadMcpResourceHandler;
impl ToolHandler for ReadMcpResourceHandler {
    fn name(&self) -> &'static str {
        "read_mcp_resource"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "read_mcp_resource",
                "description": "Read the content of a specific resource from an MCP server. Use list_mcp_resources first to discover available resources and their URIs.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "server": {
                            "type": "string",
                            "description": "The name of the MCP server that provides the resource"
                        },
                        "uri": {
                            "type": "string",
                            "description": "The URI of the resource to read (as returned by list_mcp_resources)"
                        }
                    },
                    "required": ["server", "uri"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        let server = match required_registry_string_arg(args, "read_mcp_resource", "server") {
            Ok(server) => server,
            Err(result) => return result,
        };
        let uri = match required_registry_string_arg(args, "read_mcp_resource", "uri") {
            Ok(uri) => uri,
            Err(result) => return result,
        };
        let Some(mgr) = crate::mcp::registered_manager() else {
            return (
                "No MCP manager has been installed for this session. \
                 Configure MCP servers under `mcp.servers` in \
                 `.openclaudia/config.yaml` and re-launch."
                    .to_string(),
                true,
            );
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return (
                "read_mcp_resource requires an active tokio runtime to \
                 dispatch into the async MCP manager."
                    .to_string(),
                true,
            );
        };
        let server_owned = server.to_string();
        let uri_owned = uri.to_string();
        let mgr = mgr.clone();
        let result = handle.block_on(async move {
            let guard = mgr.read().await;
            guard.read_resource(&server_owned, &uri_owned).await
        });
        match result {
            Ok(content) => (content, false),
            Err(e) => (format!("read_mcp_resource failed: {e}"), true),
        }
    }
}

fn optional_registry_string_arg<'a>(
    args: &'a HashMap<String, Value>,
    key: &'static str,
) -> Result<Option<&'a str>, String> {
    args.get(key).map_or(Ok(None), |value| {
        value
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("Invalid '{key}' argument: expected string"))
    })
}

fn required_registry_string_arg<'a>(
    args: &'a HashMap<String, Value>,
    tool: &str,
    key: &'static str,
) -> Result<&'a str, (String, bool)> {
    args.get(key).map_or_else(
        || Err((format!("{tool}: missing required argument `{key}`"), true)),
        |value| {
            value.as_str().ok_or_else(|| {
                (
                    format!("{tool}: Invalid '{key}' argument: expected string"),
                    true,
                )
            })
        },
    )
}

// ── skill (crosslink #612) ───────────────────────────────────────────────────
//
// Wraps `skills::get_skill` so the model can pull a user-authored skill
// into context by name. Response is an XML-shaped `<skill>...</skill>`
// envelope; see `skill::execute_skill` for the contract.

struct SkillHandler;
impl ToolHandler for SkillHandler {
    fn name(&self) -> &'static str {
        "skill"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "skill",
                "description": "Load a user-authored skill by name and return its body wrapped in a <skill name=\"...\">...</skill> envelope. Skills live under .openclaudia/skills/ (project) and ~/.openclaudia/skills/ (user). The returned envelope is intended to be spliced into the next turn's system prompt by the orchestrator.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Name of the skill to load (matches the `name:` field in the skill's YAML frontmatter)"
                        }
                    },
                    "required": ["name"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        skill::execute_skill(args)
    }
}

// ── tool_search (crosslink #614) ────────────────────────────────────────────
//
// Deferred tool-schema lookup. Supports the `select:Name1,Name2` form and
// keyword search. Returns a `<functions>...</functions>` envelope identical
// to the bootstrap tool-list encoding.

struct ToolSearchHandler;
impl ToolHandler for ToolSearchHandler {
    fn name(&self) -> &'static str {
        "tool_search"
    }
    fn definition(&self) -> Value {
        json!({
            "type": "function",
            "function": {
                "name": "tool_search",
                "description": "Fetch full schema definitions for deferred tools so they can be called. Two query forms: `select:Read,Edit,Grep` returns those exact tools by name; a keyword query like `notebook jupyter` returns ranked matches. A leading `+term` forces the term to appear in the tool name. Returns `<function>{...}</function>` blocks inside a `<functions>` envelope.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Query to find deferred tools. Use `select:<tool_name>` for direct selection, or keywords to search."
                        },
                        "max_results": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50,
                            "description": "Maximum number of results to return (default: 5, ceiling: 50)"
                        }
                    },
                    "required": ["query"]
                }
            }
        })
    }
    fn execute_legacy(
        &self,
        args: &HashMap<String, Value>,
        _ctx: &mut ToolContext<'_>,
    ) -> (String, bool) {
        tool_search::execute_tool_search(args)
    }
}

// ─── Registry construction ────────────────────────────────────────────────────

/// All registered handlers as static references, in **JSON-output order** —
/// `tools::get_tool_definitions()` emits the schema list in this order, and
/// the registry map is built from the same slice so handler-name and schema
/// stay co-located. Adding a new tool: append a single line here.
static HANDLERS: &[&dyn ToolHandler] = &[
    // bash
    &BashHandler,
    &BashOutputHandler,
    &KillShellHandler,
    &KillShellsForAgentHandler,
    // file
    &ReadFileHandler,
    &GroundingContextHandler,
    &WriteFileHandler,
    &EditFileHandler,
    &ListFilesHandler,
    &GlobHandler,
    &GrepHandler,
    // crosslink — library-backed issue tracker / session memory.
    // (Phase 4: legacy ChainlinkHandler removed; see commit history.)
    &CrosslinkHandler,
    // web
    &WebFetchHandler,
    #[cfg(feature = "browser")]
    &WebSearchHandler,
    #[cfg(feature = "browser")]
    &WebBrowserHandler,
    // todo
    &TodoWriteHandler,
    &TodoReadHandler,
    // notebook (file)
    &NotebookEditHandler,
    // task (session task management) — note: task_create precedes
    // ask_user_question in the legacy JSON output; preserved for byte-for-byte
    // back-compat with #463 baseline.
    &TaskCreateHandler,
    &AskUserQuestionHandler,
    &TaskUpdateHandler,
    &TaskGetHandler,
    &TaskListHandler,
    // plan_mode
    &EnterPlanModeHandler,
    &ExitPlanModeHandler,
    // mcp resources — dispatch into the registered async MCP manager
    // (src/mcp.rs); they error at runtime if no `mcp.servers` are configured.
    &ListMcpResourcesHandler,
    &ReadMcpResourceHandler,
    // lsp
    &LspHandler,
    // worktree
    &EnterWorktreeHandler,
    &ExitWorktreeHandler,
    &ListWorktreesHandler,
    // cron
    &CronCreateHandler,
    &CronDeleteHandler,
    &CronListHandler,
    // skill (crosslink #612)
    &SkillHandler,
    // tool_search (crosslink #614)
    &ToolSearchHandler,
];

/// Iterate every registered handler in JSON-output order. The public
/// `tools::get_tool_definitions` calls this to build the API-facing schema
/// list without duplicating the order or the schema bodies.
pub(crate) fn iter_handlers() -> impl Iterator<Item = &'static dyn ToolHandler> {
    HANDLERS.iter().copied()
}

fn build_registry() -> ToolRegistry {
    let mut handlers: HashMap<&'static str, &'static dyn ToolHandler> =
        HashMap::with_capacity(HANDLERS.len());
    for &handler in HANDLERS {
        handlers.insert(handler.name(), handler);
    }
    ToolRegistry { handlers }
}

/// Global registry, initialised exactly once.
pub fn registry() -> &'static ToolRegistry {
    static REGISTRY: OnceLock<ToolRegistry> = OnceLock::new();
    REGISTRY.get_or_init(build_registry)
}

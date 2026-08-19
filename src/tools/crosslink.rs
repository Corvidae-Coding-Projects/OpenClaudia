//! Crosslink tool — deep library integration.
//!
//! Replaces the legacy `chainlink` tool (which shelled out to a
//! separate binary). Calls the `crosslink` crate's library API
//! directly, so:
//!
//! * No subprocess fork+exec per command.
//! * No `chainlink` (or `crosslink`) binary required on `$PATH`.
//! * The agent and the `OpenClaudia` process share the same
//!   `sqlite`-backed `Database`.
//!
//! # Typed operations (S-016; F-052)
//!
//! This tool used to take a single shell-like `args` string —
//! `args = "create \"title\" -p high"` — which the handler split with
//! `shlex` and matched against a subcommand allowlist. Every read and every
//! mutation therefore looked identical to the registry, which ran permission
//! classification *before* that private parse and saw only an unclassified
//! string. Issue creation, closure, comments, dependency edits and session
//! mutation all inherited the fail-open safe classification.
//!
//! The wire contract is now a closed `operation` enum plus typed fields. The
//! effect of a call is decided by [`classify_operation`] from the declared
//! operation alone, before the database is opened and before authorization
//! runs. There is no argv string, no tokenizer, and no allowlist of
//! stringly-typed subcommands: an unknown operation is not a parse failure
//! that falls through to a default, it is an unclassifiable call that denies.

use crate::tools::args::ToolArgs as _;
use crate::tools::effect::{ToolEffect, TypedEffect};
use crosslink::db::Database;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::BuildHasher;
use std::path::PathBuf;

/// Project-local crosslink data directory. Matches crosslink's own
/// convention (`crosslink init` creates `.crosslink/issues.db`).
const CROSSLINK_DIR: &str = ".crosslink";

/// Legacy chainlink data directory. Migrated on first use — see
/// [`migrate_chainlink_if_needed`].
const LEGACY_CHAINLINK_DIR: &str = ".chainlink";

/// One Crosslink operation, with its effect fixed at declaration.
///
/// This table is the single source of truth for the accepted operation set and
/// its pre-authorization effects. [`execute_crosslink`] dispatches only the
/// operation label returned by [`classify_operation`] and denies a classified
/// label that has no implementation. A catalog-wide execution test drives
/// every row so an added-but-unimplemented operation fails before release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrosslinkOperation {
    /// Wire-level operation name.
    pub name: &'static str,
    /// Effect of performing it.
    pub effect: ToolEffect,
    /// Whether the operation writes issue records, as opposed to only
    /// querying them.
    ///
    /// This is documentation, not authorization: it is *not* the effect.
    /// Store query operations still declare [`ToolEffect::WorkspaceMutation`]
    /// because reaching the store at all can materialize it — see
    /// [`OPERATIONS`].
    pub mutates_records: bool,
    /// Whether execution needs to open the Crosslink store at all. Help is a
    /// real typed operation but is purely static documentation, so it must not
    /// create `.crosslink/` or run `SQLite` schema initialization.
    pub requires_store: bool,
}

/// Every operation the tool accepts.
///
/// **Every store operation declares [`ToolEffect::WorkspaceMutation`], including
/// the queries.** That is deliberate and was corrected during adversarial
/// review. The queries were briefly declared [`ToolEffect::ReadOnly`], which
/// was not truthful: reaching the issue store goes through [`open_db`], and
/// `crosslink::db::Database::open` calls `init_schema()` on every open, which
/// executes DDL against the `SQLite` file. Before this change the write path
/// additionally ran `create_dir_all` and copied a legacy `.chainlink`
/// database. A `list` could therefore create a directory, copy a database and
/// write a schema into the workspace while declaring that it observed state
/// without changing it — the same shape of dishonest classification F-001
/// records.
///
/// Two things follow. Queries no longer create or migrate the store
/// ([`open_db_for_query`] refuses when it is absent), so they do strictly less
/// than their declared ceiling. And `mutates_records` keeps the read/write
/// distinction visible in the generated matrix without pretending it is an
/// authorization boundary. The help aliases are the exception: they read only
/// static text and declare `ReadOnly` with `requires_store = false`.
pub const OPERATIONS: &[CrosslinkOperation] = &[
    // ── queries: read records, but opening the store initializes it ──
    CrosslinkOperation {
        name: "list",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: false,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "show",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: false,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "search",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: false,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "tree",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: false,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "next",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: false,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "session_status",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: false,
        requires_store: true,
    },
    CrosslinkOperation {
        // Compatibility alias retained from the previous argv surface.
        name: "ready",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: false,
        requires_store: true,
    },
    // ── record mutations ──
    CrosslinkOperation {
        name: "create",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "close",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "reopen",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "comment",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "label",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "unlabel",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "subissue",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "relate",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "block",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "unblock",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "update",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "session_start",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "session_end",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "session_work",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    CrosslinkOperation {
        name: "session_action",
        effect: ToolEffect::WorkspaceMutation,
        mutates_records: true,
        requires_store: true,
    },
    // ── static documentation: no store access ──
    CrosslinkOperation {
        name: "help",
        effect: ToolEffect::ReadOnly,
        mutates_records: false,
        requires_store: false,
    },
    CrosslinkOperation {
        name: "--help",
        effect: ToolEffect::ReadOnly,
        mutates_records: false,
        requires_store: false,
    },
    CrosslinkOperation {
        name: "-h",
        effect: ToolEffect::ReadOnly,
        mutates_records: false,
        requires_store: false,
    },
];

/// Look up an operation by name.
#[must_use]
pub fn operation(name: &str) -> Option<CrosslinkOperation> {
    OPERATIONS.iter().copied().find(|op| op.name == name)
}

/// Classify one invocation before authorization (S-016; F-052).
///
/// Reads only the `operation` field, which is a closed enum. No database is
/// opened, no argument string is tokenized, and no filesystem access occurs.
///
/// # Errors
///
/// Returns `Err` when `operation` is missing, not a string, or not a
/// recognized operation. Each is a denial: an unrecognized operation must not
/// fall through to a permissive default.
pub fn classify_operation(args: &Value) -> Result<TypedEffect, String> {
    let name = match args.get("operation") {
        Some(Value::String(name)) => name.as_str(),
        Some(_) => return Err("'operation' must be a string".to_string()),
        None => return Err("missing required 'operation' field".to_string()),
    };

    operation(name).map_or_else(
        || {
            Err(format!(
                "unknown operation '{name}'; supported operations: {}",
                OPERATIONS
                    .iter()
                    .map(|op| op.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        },
        |op| Ok(TypedEffect::new(op.effect, op.name, op.name)),
    )
}

/// Resolve the crosslink DB path under the current working directory.
/// Creates `.crosslink/` if missing so `Database::open` succeeds
/// without a separate `crosslink init` step. When `.chainlink/issues.db`
/// exists and `.crosslink/issues.db` does not, copies the legacy DB
/// into the new location so existing project history survives the
/// chainlink→crosslink migration.
fn db_path_for_cwd(run: &crate::tools::security::ToolRunContext) -> Result<PathBuf, String> {
    run.require(crate::tools::security::ToolResource::WorkspaceWrite)
        .map_err(|error| error.to_string())?;
    let cwd = run.working_directory().to_path_buf();
    let dir = cwd.join(CROSSLINK_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create {CROSSLINK_DIR}/: {e}"))?;
    let db = dir.join("issues.db");
    migrate_chainlink_if_needed(&cwd, &db);
    Ok(db)
}

/// Resolve the DB path for a query operation **without creating anything**.
///
/// Queries must not be the reason a store, a directory, or a migrated copy of
/// a legacy database comes into existence. When the store is absent the
/// operation reports that instead of materializing it, so a query does
/// strictly less than the [`ToolEffect::WorkspaceMutation`] ceiling every
/// Crosslink operation declares.
///
/// # Errors
///
/// Returns an error when session capabilities are unavailable or when no
/// store exists yet.
fn db_path_for_query(run: &crate::tools::security::ToolRunContext) -> Result<PathBuf, String> {
    run.require(crate::tools::security::ToolResource::WorkspaceWrite)
        .map_err(|error| error.to_string())?;
    let cwd = run.working_directory().to_path_buf();
    let db = cwd.join(CROSSLINK_DIR).join("issues.db");
    if db.exists() {
        Ok(db)
    } else {
        Err(format!(
            "no crosslink store at {CROSSLINK_DIR}/issues.db; run a crosslink mutation \
             (for example session_start) or `crosslink init` to create one"
        ))
    }
}

/// One-shot import of the legacy `.chainlink/issues.db` (if present)
/// into `.crosslink/issues.db` (if absent). The schema shape is a
/// superset — crosslink's `Database::open` runs idempotent
/// `IF NOT EXISTS` + `ALTER TABLE ADD COLUMN` migrations on first
/// open, so a byte-copy of the chainlink `SQLite` file is enough;
/// the `schema_version` gap is filled in on the next call.
///
/// Safety: only runs when the destination does NOT exist. We never
/// overwrite an existing `.crosslink/issues.db`. Failures are
/// non-fatal — they log a warning and let the agent continue with a
/// fresh DB.
fn migrate_chainlink_if_needed(cwd: &std::path::Path, dest_db: &PathBuf) {
    if dest_db.exists() {
        return; // already migrated or freshly created
    }
    let legacy = cwd.join(LEGACY_CHAINLINK_DIR).join("issues.db");
    if !legacy.exists() {
        return; // nothing to migrate
    }
    if let Err(e) = std::fs::copy(&legacy, dest_db) {
        tracing::warn!(
            legacy = %legacy.display(),
            dest = %dest_db.display(),
            "Failed to migrate chainlink DB to crosslink: {e}; \
             starting with an empty crosslink store."
        );
        return; // best-effort — do not block the tool
    }
    tracing::info!(
        legacy = %legacy.display(),
        dest = %dest_db.display(),
        "Migrated legacy chainlink DB into crosslink store. \
         Crosslink will apply incremental schema migrations on next open."
    );
}

/// Open a fresh `Database` handle for one tool invocation.
///
/// `Database::open` is idempotent + schema-migrating, so it's safe
/// to open and drop per call. We do NOT cache the handle in a
/// static because (a) the cwd can change mid-session (worktree
/// switches) and (b) `rusqlite::Connection` is `!Sync`.
///
/// This is the write path: it creates `.crosslink/` and migrates a legacy
/// `.chainlink` store when needed. Query operations use
/// [`open_db_for_query`], which does neither.
fn open_db(run: &crate::tools::security::ToolRunContext) -> Result<Database, String> {
    let path = db_path_for_cwd(run)?;
    Database::open(&path).map_err(|e| format!("Failed to open crosslink DB: {e}"))
}

/// Open the store for a query operation, refusing to create it.
///
/// `Database::open` still runs `init_schema()` against an existing file, which
/// is why queries do not claim [`ToolEffect::ReadOnly`]. What this avoids is a
/// query being the reason the store, its directory, or a migrated copy of a
/// legacy database exists at all.
fn open_db_for_query(run: &crate::tools::security::ToolRunContext) -> Result<Database, String> {
    let path = db_path_for_query(run)?;
    Database::open(&path).map_err(|e| format!("Failed to open crosslink DB: {e}"))
}

/// Typed accessors over the tool arguments.
///
/// Each returns a typed value or a denial-shaped error. None of them parse a
/// command string.
struct Args<'a, S: BuildHasher>(&'a HashMap<String, Value, S>);

impl<S: BuildHasher> Args<'_, S> {
    fn required_str(&self, key: &'static str) -> Result<&str, String> {
        self.0.arg_str_strict(key).map_err(|e| e.to_string())
    }

    fn optional_str(&self, key: &'static str) -> Result<Option<&str>, String> {
        self.0.arg_str_opt_strict(key).map_err(|e| e.to_string())
    }

    /// Read a required integer issue id. Rejects floats and numeric strings —
    /// the schema declares an integer, so anything else is malformed input
    /// rather than something to coerce.
    fn required_id(&self, key: &'static str) -> Result<i64, String> {
        match self.0.get(key) {
            Some(Value::Number(n)) => n
                .as_i64()
                .ok_or_else(|| format!("'{key}' must be an integer issue id")),
            Some(_) => Err(format!("'{key}' must be an integer issue id")),
            None => Err(format!("missing required '{key}' field")),
        }
    }

    fn optional_id(&self, key: &'static str) -> Result<Option<i64>, String> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(n)) => n
                .as_i64()
                .map(Some)
                .ok_or_else(|| format!("'{key}' must be an integer issue id")),
            Some(_) => Err(format!("'{key}' must be an integer issue id")),
        }
    }

    fn string_list(&self, key: &'static str) -> Result<Vec<String>, String> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(ToString::to_string)
                        .ok_or_else(|| format!("'{key}' must be an array of strings"))
                })
                .collect(),
            Some(_) => Err(format!("'{key}' must be an array of strings")),
        }
    }
}

/// Entry point — dispatches the typed `operation` field.
///
/// The operation is classified by [`classify_operation`] before this runs, so
/// by the time execution begins the effect is already known and authorized.
#[must_use]
pub fn execute_crosslink<S: BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool) {
    let value = Value::Object(args.iter().map(|(k, v)| (k.clone(), v.clone())).collect());

    // Re-derive the operation through the same classifier the policy layer
    // used. If the two ever disagreed, the effect that was authorized would
    // not be the effect that runs, so they must not be separate tables.
    let classified = match classify_operation(&value) {
        Ok(classified) => classified,
        Err(reason) => return (format!("crosslink: {reason}"), true),
    };

    let typed = Args(args);

    let Some(declared) = operation(&classified.operation) else {
        return (
            "crosslink: classified operation disappeared from its declaration table".to_string(),
            true,
        );
    };

    // Static documentation never opens the database. Keeping this decision in
    // the same operation row as the classifier prevents a nominal help call
    // from recreating the former behavior of mutating `.crosslink/` merely to
    // print usage text.
    if !declared.requires_store {
        return match classified.operation.as_str() {
            "help" | "--help" | "-h" => (help_text(), false),
            other => (
                format!("crosslink: storeless operation '{other}' has no implementation"),
                true,
            ),
        };
    }

    // A query never creates the store; only a record mutation may. The flag
    // comes from the same OPERATIONS row the classifier read, so the store is
    // materialized by exactly the operations that declare they write records.
    let db = if declared.mutates_records {
        match open_db(run) {
            Ok(db) => db,
            Err(e) => return (e, true),
        }
    } else {
        match open_db_for_query(run) {
            Ok(db) => db,
            Err(e) => return (e, true),
        }
    };

    let outcome = match classified.operation.as_str() {
        "create" => op_create(&db, &typed),
        "close" => op_close(&db, &typed),
        "reopen" => op_reopen(&db, &typed),
        "comment" => op_comment(&db, &typed),
        "label" => op_label(&db, &typed, false),
        "unlabel" => op_label(&db, &typed, true),
        "list" => op_list(&db, &typed),
        "show" => op_show(&db, &typed),
        "search" => op_search(&db, &typed),
        "subissue" => op_subissue(&db, &typed),
        "relate" => op_relate(&db, &typed),
        "block" => op_block(&db, &typed, true),
        "unblock" => op_block(&db, &typed, false),
        "next" | "ready" => op_next(&db),
        "tree" => op_tree(&db, &typed),
        "update" => op_update(&db, &typed),
        "session_start" => op_session_start(&db),
        "session_end" => op_session_end(&db, &typed),
        "session_work" => op_session_work(&db, &typed),
        "session_action" => op_session_action(&db, &typed),
        "session_status" => op_session_status(&db),
        // Unreachable because `classify_operation` already rejected anything
        // outside OPERATIONS, and both read the same table. Kept as an
        // explicit denial rather than `unreachable!` so a future operation
        // added to the table without a dispatch arm fails closed instead of
        // panicking in the agent loop.
        other => Err(format!(
            "operation '{other}' is classified but has no dispatch implementation"
        )),
    };

    match outcome {
        Ok(msg) if msg.is_empty() => ("(crosslink command completed)".to_string(), false),
        Ok(msg) => (msg, false),
        Err(e) => (format!("crosslink {}: {e}", classified.operation), true),
    }
}

/// The model-facing schema for the typed operation contract.
#[must_use]
pub fn tool_parameters() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": OPERATIONS.iter().map(|op| op.name).collect::<Vec<_>>(),
                "description": "The operation to perform. Static documentation: help, --help, -h. Store queries: list, show, search, tree, next, ready, session_status. Mutations: create, close, reopen, comment, label, unlabel, subissue, relate, block, unblock, update, session_start, session_end, session_work, session_action."
            },
            "id": {
                "type": "integer",
                "description": "Issue id. Required by show, close, reopen, comment, label, unlabel, update, session_work; optional root for tree."
            },
            "parent_id": {
                "type": "integer",
                "description": "Parent issue id. Required by subissue."
            },
            "other_id": {
                "type": "integer",
                "description": "Second issue id. Required by relate, block and unblock (the blocked issue; `id` is the blocker)."
            },
            "title": {
                "type": "string",
                "description": "Issue title. Required by create and subissue; optional new title for update."
            },
            "description": {
                "type": "string",
                "description": "Issue description for create, subissue and update."
            },
            "priority": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"],
                "description": "Issue priority for create, subissue, update, and as a list filter."
            },
            "labels": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Labels to attach on create."
            },
            "label": {
                "type": "string",
                "description": "Single label for the label and unlabel operations, or as a list filter."
            },
            "text": {
                "type": "string",
                "description": "Comment body for comment; action text for session_action; handoff notes for session_end."
            },
            "query": {
                "type": "string",
                "description": "Search query for search."
            },
            "status": {
                "type": "string",
                "enum": ["open", "closed", "archived", "all"],
                "description": "Status filter for list. Defaults to open."
            }
        },
        "required": ["operation"]
    })
}

// ── Operation implementations ─────────────────────────────────────────────

fn op_create<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let title = args.required_str("title")?;
    let description = args.optional_str("description")?;
    let priority = args.optional_str("priority")?.unwrap_or("medium");
    let labels = args.string_list("labels")?;

    let id = db
        .create_issue(title, description, priority)
        .map_err(|e| e.to_string())?;
    for label in &labels {
        let _ = db.add_label(id, label);
    }
    Ok(format!("Created issue #{id}: {title}"))
}

fn op_close<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let id = args.required_id("id")?;
    let closed = db.close_issue(id).map_err(|e| e.to_string())?;
    Ok(if closed {
        format!("Closed issue #{id}")
    } else {
        format!("Issue #{id} not found or already closed")
    })
}

fn op_reopen<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let id = args.required_id("id")?;
    let reopened = db.reopen_issue(id).map_err(|e| e.to_string())?;
    Ok(if reopened {
        format!("Reopened issue #{id}")
    } else {
        format!("Issue #{id} not found or already open")
    })
}

fn op_comment<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let id = args.required_id("id")?;
    let content = args.required_str("text")?;
    let cid = db
        .add_comment(id, content, "note")
        .map_err(|e| e.to_string())?;
    Ok(format!("Added comment #{cid} on issue #{id}"))
}

fn op_label<S: BuildHasher>(
    db: &Database,
    args: &Args<'_, S>,
    remove: bool,
) -> Result<String, String> {
    let id = args.required_id("id")?;
    let label = args.required_str("label")?;
    if remove {
        db.remove_label(id, label).map_err(|e| e.to_string())?;
        Ok(format!("Removed label '{label}' from issue #{id}"))
    } else {
        db.add_label(id, label).map_err(|e| e.to_string())?;
        Ok(format!("Added label '{label}' to issue #{id}"))
    }
}

fn op_list<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let status = match args.optional_str("status")? {
        Some("all") => None,
        Some(status) => Some(status.to_string()),
        None => Some("open".to_string()),
    };
    let label = args.optional_str("label")?.map(ToString::to_string);
    let priority = args.optional_str("priority")?.map(ToString::to_string);

    let issues = db
        .list_issues(status.as_deref(), label.as_deref(), priority.as_deref())
        .map_err(|e| e.to_string())?;
    if issues.is_empty() {
        return Ok("(no matching issues)".to_string());
    }
    let mut out = String::new();
    for issue in issues.iter().take(50) {
        let _ = writeln!(
            out,
            "#{:<4} [{:<6}] [{:<8}] {}",
            issue.id, issue.status, issue.priority, issue.title
        );
    }
    if issues.len() > 50 {
        let _ = writeln!(
            out,
            "... ({} more — narrow with filters)",
            issues.len() - 50
        );
    }
    Ok(out.trim_end().to_string())
}

fn op_show<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let id = args.required_id("id")?;
    let issue = db.require_issue(id).map_err(|e| e.to_string())?;
    let comments = db.get_comments(id).map_err(|e| e.to_string())?;
    let labels = db.get_labels(id).map_err(|e| e.to_string())?;
    let mut out = format!(
        "#{} [{}] [{}] {}\nCreated: {}\nUpdated: {}\n",
        issue.id, issue.status, issue.priority, issue.title, issue.created_at, issue.updated_at
    );
    if let Some(desc) = &issue.description {
        let _ = writeln!(out, "\nDescription:\n{desc}");
    }
    if !labels.is_empty() {
        let _ = writeln!(out, "\nLabels: {}", labels.join(", "));
    }
    if !comments.is_empty() {
        let _ = writeln!(out, "\nComments:");
        for c in comments {
            let _ = writeln!(out, "  #{} {}: {}", c.id, c.created_at, c.content);
        }
    }
    Ok(out.trim_end().to_string())
}

fn op_search<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let query = args.required_str("query")?;
    let hits = db.search_issues(query).map_err(|e| e.to_string())?;
    if hits.is_empty() {
        return Ok("(no matches)".to_string());
    }
    let mut out = String::new();
    for issue in hits.iter().take(25) {
        let _ = writeln!(
            out,
            "#{:<4} [{:<6}] {}",
            issue.id, issue.status, issue.title
        );
    }
    if hits.len() > 25 {
        let _ = writeln!(out, "... ({} more matches)", hits.len() - 25);
    }
    Ok(out.trim_end().to_string())
}

fn op_subissue<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let parent = args.required_id("parent_id")?;
    let title = args.required_str("title")?;
    let description = args.optional_str("description")?;
    let priority = args.optional_str("priority")?.unwrap_or("medium");
    let id = db
        .create_subissue(parent, title, description, priority)
        .map_err(|e| e.to_string())?;
    Ok(format!("Created subissue #{id} under #{parent}: {title}"))
}

fn op_relate<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let a = args.required_id("id")?;
    let b = args.required_id("other_id")?;
    db.add_relation(a, b).map_err(|e| e.to_string())?;
    Ok(format!("Related issues #{a} ↔ #{b}"))
}

fn op_block<S: BuildHasher>(
    db: &Database,
    args: &Args<'_, S>,
    add: bool,
) -> Result<String, String> {
    let upstream = args.required_id("id")?;
    let downstream = args.required_id("other_id")?;
    if add {
        db.add_dependency(upstream, downstream)
            .map_err(|e| e.to_string())?;
        Ok(format!("#{upstream} now blocks #{downstream}"))
    } else {
        db.remove_dependency(upstream, downstream)
            .map_err(|e| e.to_string())?;
        Ok(format!("Removed block #{upstream} → #{downstream}"))
    }
}

fn op_session_start(db: &Database) -> Result<String, String> {
    let id = db
        .start_session_with_agent(None)
        .map_err(|e| e.to_string())?;
    Ok(format!("Started session #{id}"))
}

fn op_session_end<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let sess = db
        .get_current_session_for_agent(None)
        .map_err(|e| e.to_string())?
        .ok_or("no active session to end")?;
    let notes = args.optional_str("text")?;
    db.end_session(sess.id, notes).map_err(|e| e.to_string())?;
    Ok(format!("Ended session #{}", sess.id))
}

fn op_session_work<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let sess = db
        .get_current_session_for_agent(None)
        .map_err(|e| e.to_string())?
        .ok_or("no active session; run session_start first")?;
    let issue_id = args.required_id("id")?;
    db.set_session_issue(sess.id, issue_id)
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "Session #{} now tracking issue #{}",
        sess.id, issue_id
    ))
}

fn op_session_action<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let sess = db
        .get_current_session_for_agent(None)
        .map_err(|e| e.to_string())?
        .ok_or("no active session; run session_start first")?;
    let action = args.required_str("text")?;
    db.set_session_action(sess.id, action)
        .map_err(|e| e.to_string())?;
    Ok(format!("Recorded action on session #{}", sess.id))
}

fn op_session_status(db: &Database) -> Result<String, String> {
    match db
        .get_current_session_for_agent(None)
        .map_err(|e| e.to_string())?
    {
        Some(s) => Ok(format!(
            "Session #{}: started {}, active issue {:?}, last action {:?}",
            s.id, s.started_at, s.active_issue_id, s.last_action
        )),
        None => Ok("(no active session)".to_string()),
    }
}

fn op_next(db: &Database) -> Result<String, String> {
    // Preserve the legacy `next` / `ready` behavior: select the
    // highest-priority open issue. Blocker-aware graph selection is not
    // implemented here and is owned by S-052, so neither the schema nor the
    // help text claims otherwise.
    let open = db
        .list_issues(Some("open"), None, None)
        .map_err(|e| e.to_string())?;
    if open.is_empty() {
        return Ok("(no open issues)".to_string());
    }
    let priority_rank = |p: &str| match p {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    let mut sorted = open;
    sorted.sort_by_key(|i| (priority_rank(i.priority.as_str()), i.id));
    let pick = &sorted[0];
    Ok(format!(
        "Suggested next: #{} [{}] {}",
        pick.id, pick.priority, pick.title
    ))
}

fn help_text() -> String {
    "Crosslink typed operations:\n  \
     create | close | reopen | comment | label | unlabel\n  \
     list | show | search | subissue | relate | block | unblock\n  \
     session_start | session_end | session_work | session_action | session_status\n  \
     next | ready              # highest-priority open issue\n  \
     tree | update\n\n\
     Supply operation-specific values in the typed fields advertised by this tool's schema."
        .to_string()
}

fn op_tree<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let root_id = args.optional_id("id")?;
    let mut out = String::new();
    if let Some(id) = root_id {
        render_subtree(db, id, 0, &mut out)?;
    } else {
        let issues = db
            .list_issues(Some("open"), None, None)
            .map_err(|e| e.to_string())?;
        for issue in issues.iter().filter(|i| i.parent_id.is_none()) {
            // Top-level only: render anything without a parent.
            render_subtree(db, issue.id, 0, &mut out)?;
        }
    }
    Ok(if out.is_empty() {
        "(no issues to render)".to_string()
    } else {
        out.trim_end().to_string()
    })
}

fn render_subtree(db: &Database, id: i64, depth: usize, out: &mut String) -> Result<(), String> {
    let issue = db.require_issue(id).map_err(|e| e.to_string())?;
    let indent = "  ".repeat(depth);
    let _ = writeln!(
        out,
        "{indent}#{} [{}] [{}] {}",
        issue.id, issue.status, issue.priority, issue.title
    );
    let subs = db.get_subissues(id).map_err(|e| e.to_string())?;
    for s in subs {
        render_subtree(db, s.id, depth + 1, out)?;
    }
    Ok(())
}

fn op_update<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let id = args.required_id("id")?;
    let title = args.optional_str("title")?;
    let description = args.optional_str("description")?;
    let priority = args.optional_str("priority")?;
    db.update_issue(id, title, description, priority)
        .map_err(|e| e.to_string())?;
    Ok(format!("Updated issue #{id}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_operation_is_classified_before_dispatch() {
        for op in OPERATIONS {
            let classified = classify_operation(&json!({"operation": op.name}))
                .unwrap_or_else(|e| panic!("operation {} must classify: {e}", op.name));
            assert_eq!(classified.effect, op.effect);
            assert_eq!(classified.operation, op.name);
        }
    }

    #[test]
    fn unknown_operation_is_denied_not_defaulted() {
        let err = classify_operation(&json!({"operation": "rm_rf"})).unwrap_err();
        assert!(err.contains("unknown operation"), "{err}");
    }

    #[test]
    fn missing_operation_is_denied() {
        assert!(classify_operation(&json!({})).is_err());
    }

    #[test]
    fn non_string_operation_is_denied() {
        assert!(classify_operation(&json!({"operation": 3})).is_err());
    }

    /// The whole point of F-052: a mutation must not be able to present
    /// itself as a read. There is no argv string left to hide one inside.
    #[test]
    fn mutations_are_not_classified_read_only() {
        for name in [
            "create",
            "close",
            "reopen",
            "comment",
            "label",
            "unlabel",
            "subissue",
            "relate",
            "block",
            "unblock",
            "update",
            "session_start",
            "session_end",
            "session_work",
            "session_action",
        ] {
            let classified = classify_operation(&json!({"operation": name})).unwrap();
            assert_eq!(
                classified.effect,
                ToolEffect::WorkspaceMutation,
                "{name} must be classified as a workspace mutation"
            );
            assert!(classified.effect.requires_authorization());
        }
    }

    #[test]
    fn queries_are_classified_for_the_store_initialization_they_perform() {
        for name in [
            "list",
            "show",
            "search",
            "tree",
            "next",
            "ready",
            "session_status",
        ] {
            let classified = classify_operation(&json!({"operation": name})).unwrap();
            assert_eq!(
                classified.effect,
                ToolEffect::WorkspaceMutation,
                "{name}: Database::open initializes schema even for queries"
            );
        }
    }

    fn call(run: &crate::tools::ToolRunContext, entries: &[(&str, Value)]) -> (String, bool) {
        let args: HashMap<String, Value> = entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect();
        execute_crosslink(run, &args)
    }

    fn assert_ok(
        run: &crate::tools::ToolRunContext,
        operation: &str,
        entries: &[(&str, Value)],
    ) -> String {
        let mut args = vec![("operation", json!(operation))];
        args.extend_from_slice(entries);
        let (message, is_error) = call(run, &args);
        assert!(!is_error, "{operation} failed: {message}");
        message
    }

    /// Exercise the real parser, database calls, and dispatcher for every
    /// declared operation. Schema/classifier-only tests would still pass if a
    /// table row had no implementation or if typed field names drifted.
    #[test]
    fn every_declared_operation_dispatches_against_an_isolated_store() {
        let root = tempfile::tempdir().expect("crosslink test root");
        let run = crate::tools::security::test_run_context_for(root.path());

        for help in ["help", "--help", "-h"] {
            let message = assert_ok(&run, help, &[]);
            assert!(message.contains("Crosslink typed operations"));
            assert!(
                !root.path().join(CROSSLINK_DIR).exists(),
                "{help} must not create or open the Crosslink store"
            );
        }

        assert_ok(
            &run,
            "create",
            &[
                ("title", json!("root issue")),
                ("description", json!("root description")),
                ("priority", json!("high")),
                ("labels", json!(["audit"])),
            ],
        );
        assert_ok(&run, "list", &[]);
        assert_ok(&run, "show", &[("id", json!(1))]);
        assert_ok(&run, "search", &[("query", json!("root"))]);
        assert_ok(
            &run,
            "update",
            &[("id", json!(1)), ("title", json!("updated root"))],
        );
        assert_ok(
            &run,
            "comment",
            &[("id", json!(1)), ("text", json!("note"))],
        );
        assert_ok(
            &run,
            "label",
            &[("id", json!(1)), ("label", json!("review"))],
        );
        assert_ok(
            &run,
            "unlabel",
            &[("id", json!(1)), ("label", json!("review"))],
        );
        assert_ok(
            &run,
            "subissue",
            &[("parent_id", json!(1)), ("title", json!("child issue"))],
        );
        assert_ok(&run, "relate", &[("id", json!(1)), ("other_id", json!(2))]);
        assert_ok(&run, "block", &[("id", json!(1)), ("other_id", json!(2))]);
        assert_ok(&run, "unblock", &[("id", json!(1)), ("other_id", json!(2))]);
        assert_ok(&run, "tree", &[("id", json!(1))]);
        assert_ok(&run, "next", &[]);
        assert_ok(&run, "ready", &[]);
        assert_ok(&run, "close", &[("id", json!(1))]);
        assert_ok(&run, "reopen", &[("id", json!(1))]);
        assert_ok(&run, "session_start", &[]);
        assert_ok(&run, "session_work", &[("id", json!(1))]);
        assert_ok(
            &run,
            "session_action",
            &[("text", json!("audited dispatch"))],
        );
        assert_ok(&run, "session_status", &[]);
        assert_ok(&run, "session_end", &[("text", json!("done"))]);

        let exercised = [
            "create",
            "list",
            "show",
            "search",
            "update",
            "comment",
            "label",
            "unlabel",
            "subissue",
            "relate",
            "block",
            "unblock",
            "tree",
            "next",
            "ready",
            "close",
            "reopen",
            "session_start",
            "session_work",
            "session_action",
            "session_status",
            "session_end",
            "help",
            "--help",
            "-h",
        ];
        assert_eq!(exercised.len(), OPERATIONS.len());
        for operation in OPERATIONS {
            assert!(
                exercised.contains(&operation.name),
                "declared operation {} was not driven through dispatch",
                operation.name
            );
        }
    }

    /// A shell-shaped payload is no longer a parse target. It is simply not a
    /// recognized operation, so it denies before any database is opened.
    #[test]
    fn shell_shaped_payload_is_not_an_operation() {
        for payload in [
            "create \"x\" -p high",
            "close 1; rm -rf /",
            "list && create \"y\"",
        ] {
            assert!(
                classify_operation(&json!({"operation": payload})).is_err(),
                "{payload} must not classify"
            );
        }
    }

    #[test]
    fn schema_enum_matches_the_operation_table() {
        let params = tool_parameters();
        let enumerated: Vec<String> = params["properties"]["operation"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let declared: Vec<String> = OPERATIONS.iter().map(|op| op.name.to_string()).collect();
        assert_eq!(
            enumerated, declared,
            "advertised operations must equal the classified operations"
        );
    }
}

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
use crate::tools::{
    ToolFailure, ToolFailureCode, ToolHandlerResult, ToolObservation, ToolRetryability,
};
use crosslink::db::Database;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt::Write as _;
use std::hash::BuildHasher;
use std::path::PathBuf;

/// Project-local crosslink data directory. Matches crosslink's own
/// convention (`crosslink init` creates `.crosslink/issues.db`).
const CROSSLINK_DIR: &str = ".crosslink";
// Keep the adapter at or below both the external crate's 512-byte title cap
// and the canonical graph's subject cap so a locally accepted record can be
// projected without a predictable partial outcome.
pub const MAX_CROSSLINK_TITLE_BYTES: usize = 512;
pub const MAX_CROSSLINK_DESCRIPTION_BYTES: usize = crate::task_graph::MAX_TASK_DESCRIPTION_BYTES;
pub const MAX_CROSSLINK_TEXT_BYTES: usize = 8_192;
pub const MAX_CROSSLINK_QUERY_BYTES: usize = 512;
pub const MAX_CROSSLINK_LABEL_BYTES: usize = 128;
pub const MAX_CROSSLINK_LABELS: usize = 64;
const MAX_CROSSLINK_TREE_DEPTH: usize = 64;
const MAX_CROSSLINK_TREE_OUTPUT_BYTES: usize = 256 * 1024;

/// Retired Chainlink data directory. A store in this namespace blocks implicit
/// Crosslink creation so historical mutable state is never copied silently.
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

/// Resolve the Crosslink DB path under the current working directory.
/// Creates `.crosslink/` if missing so `Database::open` succeeds without a
/// separate `crosslink init` step. If only a retired `.chainlink/issues.db`
/// exists, this fails closed instead of copying unvalidated mutable state into
/// a second live store.
fn db_path_for_cwd(run: &crate::tools::security::ToolRunContext) -> Result<PathBuf, String> {
    run.require(crate::tools::security::ToolResource::WorkspaceWrite)
        .map_err(|error| error.to_string())?;
    let cwd = run.working_directory().to_path_buf();
    let dir = cwd.join(CROSSLINK_DIR);
    let db = dir.join("issues.db");
    if !path_entry_exists(&db)? {
        let legacy = cwd.join(LEGACY_CHAINLINK_DIR).join("issues.db");
        if path_entry_exists(&legacy)? {
            return Err(format!(
                "retired {LEGACY_CHAINLINK_DIR}/issues.db detected; automatic import is disabled \
                 because copying an unvalidated mutable database can create split-brain state. \
                 Back up and explicitly resolve the legacy store before creating \
                 {CROSSLINK_DIR}/issues.db"
            ));
        }
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create {CROSSLINK_DIR}/: {e}"))?;
    Ok(db)
}

fn path_entry_exists(path: &std::path::Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("Failed to inspect {}: {error}", path.display())),
    }
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

/// Open a fresh `Database` handle for one tool invocation.
///
/// `Database::open` is idempotent + schema-migrating, so it's safe
/// to open and drop per call. We do NOT cache the handle in a
/// static because (a) the cwd can change mid-session (worktree
/// switches) and (b) `rusqlite::Connection` is `!Sync`.
///
/// This is the write path: it may create `.crosslink/`, but it never imports a
/// retired `.chainlink` store. Query operations use [`open_db_for_query`],
/// which does not create either path.
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
        let value = self.0.arg_str_strict(key).map_err(|e| e.to_string())?;
        validate_crosslink_string(key, value)?;
        Ok(value)
    }

    fn optional_str(&self, key: &'static str) -> Result<Option<&str>, String> {
        let value = self.0.arg_str_opt_strict(key).map_err(|e| e.to_string())?;
        if let Some(value) = value {
            validate_crosslink_string(key, value)?;
        }
        Ok(value)
    }

    /// Read a required integer issue id. Rejects floats and numeric strings —
    /// the schema declares an integer, so anything else is malformed input
    /// rather than something to coerce.
    fn required_id(&self, key: &'static str) -> Result<i64, String> {
        match self.0.get(key) {
            Some(Value::Number(n)) => n
                .as_i64()
                .filter(|id| *id > 0)
                .ok_or_else(|| format!("'{key}' must be a positive integer issue id")),
            Some(_) => Err(format!("'{key}' must be an integer issue id")),
            None => Err(format!("missing required '{key}' field")),
        }
    }

    fn optional_id(&self, key: &'static str) -> Result<Option<i64>, String> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Number(n)) => n
                .as_i64()
                .filter(|id| *id > 0)
                .map(Some)
                .ok_or_else(|| format!("'{key}' must be a positive integer issue id")),
            Some(_) => Err(format!("'{key}' must be an integer issue id")),
        }
    }

    fn string_list(&self, key: &'static str) -> Result<Vec<String>, String> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) => {
                if items.len() > MAX_CROSSLINK_LABELS {
                    return Err(format!(
                        "'{key}' exceeds the limit of {MAX_CROSSLINK_LABELS} labels"
                    ));
                }
                items
                    .iter()
                    .map(|item| {
                        let item = item
                            .as_str()
                            .ok_or_else(|| format!("'{key}' must be an array of strings"))?;
                        validate_crosslink_string("label", item)?;
                        Ok(item.to_string())
                    })
                    .collect()
            }
            Some(_) => Err(format!("'{key}' must be an array of strings")),
        }
    }
}

fn validate_crosslink_string(key: &'static str, value: &str) -> Result<(), String> {
    let (max_bytes, allow_empty) = match key {
        "title" => (MAX_CROSSLINK_TITLE_BYTES, false),
        "description" => (MAX_CROSSLINK_DESCRIPTION_BYTES, true),
        "text" => (MAX_CROSSLINK_TEXT_BYTES, false),
        "query" => (MAX_CROSSLINK_QUERY_BYTES, false),
        "label" => (MAX_CROSSLINK_LABEL_BYTES, false),
        "priority" | "status" => (16, false),
        _ => return Err(format!("unknown Crosslink string field '{key}'")),
    };
    if !allow_empty && value.trim().is_empty() {
        return Err(format!("'{key}' must not be empty"));
    }
    if value.len() > max_bytes {
        return Err(format!("'{key}' exceeds the limit of {max_bytes} bytes"));
    }
    Ok(())
}

fn validate_typed_arguments<S: BuildHasher>(
    operation: &str,
    args: &HashMap<String, Value, S>,
) -> Result<(), String> {
    let allowed: &[&str] = match operation {
        "create" => &["operation", "title", "description", "priority", "labels"],
        "close" | "reopen" | "show" | "tree" | "session_work" => &["operation", "id"],
        "comment" => &["operation", "id", "text"],
        "label" | "unlabel" => &["operation", "id", "label"],
        "list" => &["operation", "status", "priority", "label"],
        "search" => &["operation", "query"],
        "subissue" => &["operation", "parent_id", "title", "description", "priority"],
        "relate" | "block" | "unblock" => &["operation", "id", "other_id"],
        "update" => &["operation", "id", "title", "description", "priority"],
        "session_end" | "session_action" => &["operation", "text"],
        "next" | "ready" | "session_start" | "session_status" | "help" | "--help" | "-h" => {
            &["operation"]
        }
        _ => return Err(format!("unknown operation '{operation}'")),
    };
    if let Some(key) = args.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!(
            "field '{key}' is not valid for Crosslink operation '{operation}'"
        ));
    }

    let typed = Args(args);
    for field in ["title", "description", "label", "text", "query"] {
        if args.contains_key(field) {
            typed.optional_str(field)?;
        }
    }
    if let Some(priority) = typed.optional_str("priority")? {
        if !matches!(priority, "critical" | "high" | "medium" | "low") {
            return Err(format!("invalid Crosslink priority '{priority}'"));
        }
    }
    if let Some(status) = typed.optional_str("status")? {
        if !matches!(status, "open" | "closed" | "archived" | "all") {
            return Err(format!("invalid Crosslink status '{status}'"));
        }
    }
    if args.contains_key("labels") {
        typed.string_list("labels")?;
    }
    for field in ["id", "parent_id", "other_id"] {
        if args.contains_key(field) {
            typed.optional_id(field)?;
        }
    }

    if matches!(operation, "create" | "subissue") {
        typed.required_str("title")?;
    }
    if matches!(
        operation,
        "close"
            | "reopen"
            | "show"
            | "comment"
            | "label"
            | "unlabel"
            | "relate"
            | "block"
            | "unblock"
            | "update"
            | "session_work"
    ) {
        typed.required_id("id")?;
    }
    if matches!(operation, "comment" | "session_action") {
        typed.required_str("text")?;
    }
    if matches!(operation, "label" | "unlabel") {
        typed.required_str("label")?;
    }
    if operation == "search" {
        typed.required_str("query")?;
    }
    if operation == "subissue" {
        typed.required_id("parent_id")?;
    }
    if matches!(operation, "relate" | "block" | "unblock") {
        typed.required_id("other_id")?;
    }
    if operation == "update"
        && !["title", "description", "priority"]
            .iter()
            .any(|field| args.contains_key(*field))
    {
        return Err("Crosslink update requires at least one changed field".to_string());
    }
    Ok(())
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
    if let Err(reason) = validate_typed_arguments(&classified.operation, args) {
        return (
            format!("crosslink {}: {reason}", classified.operation),
            true,
        );
    }

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

/// Execute a Crosslink operation and reconcile its bounded issue view.
///
/// The database operation always happens first;
/// therefore a later graph failure is reported as a typed partial effect and
/// never collapsed into an ordinary error that implies nothing changed.
#[must_use]
pub fn execute_crosslink_with_tasks<S: BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
    task_manager: Option<&mut crate::session::TaskManager>,
) -> ToolHandlerResult {
    let value = Value::Object(
        args.iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    let classified = match classify_operation(&value) {
        Ok(classified) => classified,
        Err(reason) => {
            return ToolHandlerResult::error(ToolFailure::new(
                ToolFailureCode::InvalidArguments,
                format!("crosslink: {reason}"),
                ToolRetryability::Never,
            ));
        }
    };
    let Some(declared) = operation(&classified.operation) else {
        return ToolHandlerResult::error(ToolFailure::new(
            ToolFailureCode::InvalidArguments,
            "crosslink: classified operation disappeared from its declaration table".to_string(),
            ToolRetryability::Never,
        ));
    };
    if let Err(reason) = validate_typed_arguments(&classified.operation, args) {
        return ToolHandlerResult::error(ToolFailure::new(
            ToolFailureCode::InvalidArguments,
            format!("crosslink {}: {reason}", classified.operation),
            ToolRetryability::Never,
        ));
    }
    let (content, is_error) = execute_crosslink(run, args);
    if is_error {
        return ToolHandlerResult::error(ToolFailure::new(
            ToolFailureCode::External,
            content,
            ToolRetryability::Unknown,
        ));
    }
    if !declared.requires_store {
        return ToolHandlerResult::success_text(content);
    }

    let Some(task_manager) = task_manager else {
        return crosslink_partial(
            &content,
            &classified.operation,
            "Crosslink operation completed, but no canonical task graph was bound to this frontend",
        );
    };
    if let Err(error) = reconcile_task_graph(run, args, task_manager) {
        return crosslink_partial(&content, &classified.operation, &error);
    }
    let generation = task_manager.generation().get();
    let mut result = ToolHandlerResult::success_structured(
        content,
        serde_json::json!({
            "operation": classified.operation,
            "external_effect": "completed",
            "task_graph": "reconciled",
            "task_graph_generation": generation,
        }),
    );
    result.observations.push(ToolObservation {
        kind: "canonical_task_graph_reconciled".to_string(),
        authoritative: true,
        data: serde_json::json!({
            "external_system": "crosslink",
            "generation": generation,
        }),
    });
    result
}

fn crosslink_partial(content: &str, operation: &str, reason: &str) -> ToolHandlerResult {
    let retryability = self::operation(operation).map_or(ToolRetryability::Never, |declared| {
        if declared.mutates_records {
            ToolRetryability::Never
        } else {
            ToolRetryability::Safe
        }
    });
    ToolHandlerResult::partial_structured(
        format!("{content}\nCanonical task graph reconciliation failed: {reason}"),
        serde_json::json!({
            "operation": operation,
            "external_effect": "completed",
            "task_graph": "not_reconciled",
        }),
        vec![ToolFailure::new(
            ToolFailureCode::Conflict,
            format!("Canonical task graph reconciliation failed: {reason}"),
            retryability,
        )],
        None,
    )
}

fn reconcile_task_graph<S: BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
    task_manager: &mut crate::session::TaskManager,
) -> Result<(), String> {
    task_manager.refresh()?;
    let expected_generation = task_manager.generation();
    let db = open_db_for_query(run)?;
    let mut issue_ids = db
        .list_issues(Some("open"), None, None)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|issue| issue.id)
        .collect::<BTreeSet<_>>();
    for external_id in task_manager.projected_external_ids("crosslink") {
        let id = external_id
            .parse::<i64>()
            .map_err(|_| "persisted Crosslink projection has a non-numeric issue id".to_string())?;
        issue_ids.insert(id);
    }
    for field in ["id", "parent_id", "other_id"] {
        if let Some(id) = args.get(field).and_then(Value::as_i64) {
            issue_ids.insert(id);
        }
    }
    if issue_ids.len() > crate::task_graph::MAX_TASKS {
        return Err(format!(
            "Crosslink active projection exceeds the canonical task bound ({})",
            crate::task_graph::MAX_TASKS
        ));
    }

    let mut queue = issue_ids.iter().copied().collect::<VecDeque<_>>();
    let mut drafts = Vec::new();
    let mut observed = BTreeSet::new();
    while let Some(issue_id) = queue.pop_front() {
        if !observed.insert(issue_id) {
            continue;
        }
        if observed.len() > crate::task_graph::MAX_TASKS {
            return Err(format!(
                "Crosslink dependency closure exceeds the canonical task bound ({})",
                crate::task_graph::MAX_TASKS
            ));
        }
        let issue = db
            .require_issue(issue_id)
            .map_err(|error| error.to_string())?;
        let blockers = db
            .get_blockers(issue_id)
            .map_err(|error| error.to_string())?;
        for blocker in &blockers {
            if !observed.contains(blocker) {
                queue.push_back(*blocker);
            }
        }
        let blocker_ids = blockers
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        drafts.push(crate::task_graph::ExternalTaskDraft {
            external_id: issue.id.to_string(),
            observed_version: issue_version(&issue, &blockers)?,
            subject: issue.title,
            description: issue.description.unwrap_or_default(),
            status: match issue.status {
                crosslink::models::IssueStatus::Open => {
                    crate::task_graph::CanonicalTaskStatus::Pending
                }
                crosslink::models::IssueStatus::Closed => {
                    crate::task_graph::CanonicalTaskStatus::Completed
                }
                crosslink::models::IssueStatus::Archived => {
                    crate::task_graph::CanonicalTaskStatus::Canceled
                }
            },
            priority: match issue.priority {
                crosslink::models::Priority::Critical => crate::task_graph::TaskPriority::Critical,
                crosslink::models::Priority::High => crate::task_graph::TaskPriority::High,
                crosslink::models::Priority::Medium => crate::task_graph::TaskPriority::Medium,
                crosslink::models::Priority::Low => crate::task_graph::TaskPriority::Low,
            },
            blocked_by_external_ids: blocker_ids,
        });
    }
    drafts.sort_unstable_by(|left, right| left.external_id.cmp(&right.external_id));
    task_manager.reconcile_external_checked(expected_generation, "crosslink".to_string(), drafts)
}

fn issue_version(issue: &crosslink::models::Issue, blockers: &[i64]) -> Result<String, String> {
    let mut blockers = blockers.to_vec();
    blockers.sort_unstable();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "id": issue.id,
        "title": issue.title,
        "description": issue.description,
        "status": issue.status,
        "priority": issue.priority,
        "parent_id": issue.parent_id,
        "created_at": issue.created_at,
        "updated_at": issue.updated_at,
        "closed_at": issue.closed_at,
        "scheduled_at": issue.scheduled_at,
        "due_at": issue.due_at,
        "blockers": blockers,
    }))
    .map_err(|error| format!("failed to encode Crosslink issue version: {error}"))?;
    let digest = Sha256::digest(bytes);
    let mut version = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut version, "{byte:02x}")
            .map_err(|_| "failed to format Crosslink issue version".to_string())?;
    }
    Ok(version)
}

/// The model-facing schema for the typed operation contract.
#[must_use]
pub fn tool_parameters() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "operation": {
                "type": "string",
                "enum": OPERATIONS.iter().map(|op| op.name).collect::<Vec<_>>(),
                "description": "The operation to perform. Static documentation: help, --help, -h. Store queries: list, show, search, tree, next, ready, session_status. Mutations: create, close, reopen, comment, label, unlabel, subissue, relate, block, unblock, update, session_start, session_end, session_work, session_action."
            },
            "id": {
                "type": "integer",
                "minimum": 1,
                "description": "Issue id. Required by show, close, reopen, comment, label, unlabel, update, session_work; optional root for tree."
            },
            "parent_id": {
                "type": "integer",
                "minimum": 1,
                "description": "Parent issue id. Required by subissue."
            },
            "other_id": {
                "type": "integer",
                "minimum": 1,
                "description": "Second issue id. Required by relate, block and unblock (the blocked issue; `id` is the blocker)."
            },
            "title": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CROSSLINK_TITLE_BYTES,
                "description": "Issue title. Required by create and subissue; optional new title for update."
            },
            "description": {
                "type": "string",
                "maxLength": MAX_CROSSLINK_DESCRIPTION_BYTES,
                "description": "Issue description for create, subissue and update."
            },
            "priority": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"],
                "description": "Issue priority for create, subissue, update, and as a list filter."
            },
            "labels": {
                "type": "array",
                "maxItems": MAX_CROSSLINK_LABELS,
                "items": {"type": "string", "minLength": 1, "maxLength": MAX_CROSSLINK_LABEL_BYTES},
                "description": "Labels to attach on create."
            },
            "label": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CROSSLINK_LABEL_BYTES,
                "description": "Single label for the label and unlabel operations, or as a list filter."
            },
            "text": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CROSSLINK_TEXT_BYTES,
                "description": "Comment body for comment; action text for session_action; handoff notes for session_end."
            },
            "query": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CROSSLINK_QUERY_BYTES,
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
        db.add_dependency(downstream, upstream)
            .map_err(|e| e.to_string())?;
        Ok(format!("#{upstream} now blocks #{downstream}"))
    } else {
        db.remove_dependency(downstream, upstream)
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
    let ready = db.list_ready_issues().map_err(|e| e.to_string())?;
    if ready.is_empty() {
        return Ok("(no blocker-ready open issues)".to_string());
    }
    let priority_rank = |p: &str| match p {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    };
    let mut sorted = ready;
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
     next | ready              # highest-priority blocker-ready open issue\n  \
     tree | update\n\n\
     Supply operation-specific values in the typed fields advertised by this tool's schema."
        .to_string()
}

fn op_tree<S: BuildHasher>(db: &Database, args: &Args<'_, S>) -> Result<String, String> {
    let root_id = args.optional_id("id")?;
    let mut out = String::new();
    let mut visited = BTreeSet::new();
    let mut nodes = 0;
    if let Some(id) = root_id {
        render_subtree(db, id, 0, &mut out, &mut visited, &mut nodes)?;
    } else {
        let issues = db
            .list_issues(Some("open"), None, None)
            .map_err(|e| e.to_string())?;
        if issues.len() > crate::task_graph::MAX_TASKS {
            return Err(format!(
                "Crosslink tree exceeds the bounded node view ({})",
                crate::task_graph::MAX_TASKS
            ));
        }
        for issue in issues.iter().filter(|i| i.parent_id.is_none()) {
            render_subtree(db, issue.id, 0, &mut out, &mut visited, &mut nodes)?;
        }
    }
    Ok(if out.is_empty() {
        "(no issues to render)".to_string()
    } else {
        out.trim_end().to_string()
    })
}

fn render_subtree(
    db: &Database,
    id: i64,
    depth: usize,
    out: &mut String,
    visited: &mut BTreeSet<i64>,
    nodes: &mut usize,
) -> Result<(), String> {
    if depth > MAX_CROSSLINK_TREE_DEPTH {
        return Err(format!(
            "Crosslink tree exceeds the maximum depth of {MAX_CROSSLINK_TREE_DEPTH}"
        ));
    }
    if !visited.insert(id) {
        return Err(format!(
            "Crosslink tree repeats issue #{id}; persisted hierarchy is cyclic or inconsistent"
        ));
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| "Crosslink tree node count overflowed".to_string())?;
    if *nodes > crate::task_graph::MAX_TASKS {
        return Err(format!(
            "Crosslink tree exceeds the bounded node view ({})",
            crate::task_graph::MAX_TASKS
        ));
    }
    let issue = db.require_issue(id).map_err(|e| e.to_string())?;
    let indent = "  ".repeat(depth);
    let line = format!(
        "{indent}#{} [{}] [{}] {}",
        issue.id, issue.status, issue.priority, issue.title
    );
    if out.len().saturating_add(line.len()).saturating_add(1) > MAX_CROSSLINK_TREE_OUTPUT_BYTES {
        return Err(format!(
            "Crosslink tree output exceeds {MAX_CROSSLINK_TREE_OUTPUT_BYTES} bytes"
        ));
    }
    let _ = writeln!(out, "{line}");
    let subs = db.get_subissues(id).map_err(|e| e.to_string())?;
    if subs.len() > crate::task_graph::MAX_TASKS {
        return Err(format!(
            "Crosslink issue #{id} exceeds the bounded child view ({})",
            crate::task_graph::MAX_TASKS
        ));
    }
    for s in subs {
        render_subtree(db, s.id, depth + 1, out, visited, nodes)?;
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

    #[test]
    fn invalid_typed_arguments_are_rejected_before_store_creation() {
        let root = tempfile::tempdir().expect("crosslink test root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let cases = [
            HashMap::from([("operation".to_string(), json!("create"))]),
            HashMap::from([
                ("operation".to_string(), json!("create")),
                (
                    "title".to_string(),
                    json!("x".repeat(MAX_CROSSLINK_TITLE_BYTES + 1)),
                ),
            ]),
            HashMap::from([
                ("operation".to_string(), json!("create")),
                ("title".to_string(), json!("bounded")),
                ("ignored".to_string(), json!("must reject")),
            ]),
            HashMap::from([
                ("operation".to_string(), json!("close")),
                ("id".to_string(), json!(0)),
            ]),
            HashMap::from([
                ("operation".to_string(), json!("update")),
                ("id".to_string(), json!(1)),
            ]),
        ];
        for args in cases {
            let (message, is_error) = execute_crosslink(&run, &args);
            assert!(is_error, "invalid arguments succeeded: {message}");
            assert!(
                !root.path().join(CROSSLINK_DIR).exists(),
                "invalid arguments created the Crosslink store: {message}"
            );
        }
    }

    #[test]
    fn tree_rendering_rejects_excessive_hierarchy_depth() {
        let root = tempfile::tempdir().expect("crosslink test root");
        let run = crate::tools::security::test_run_context_for(root.path());
        assert_ok(&run, "create", &[("title", json!("root"))]);
        let excessive_depth =
            i64::try_from(MAX_CROSSLINK_TREE_DEPTH).expect("tree depth fits in i64") + 1;
        for parent_id in 1..=excessive_depth {
            assert_ok(
                &run,
                "subissue",
                &[
                    ("parent_id", json!(parent_id)),
                    ("title", json!(format!("child-{parent_id}"))),
                ],
            );
        }
        let (message, is_error) = call(&run, &[("operation", json!("tree")), ("id", json!(1))]);
        assert!(is_error, "excessive tree unexpectedly rendered");
        assert!(message.contains("maximum depth"), "{message}");
    }

    fn call_with_tasks(
        run: &crate::tools::ToolRunContext,
        task_manager: Option<&mut crate::session::TaskManager>,
        operation: &str,
        entries: &[(&str, Value)],
    ) -> ToolHandlerResult {
        let mut args = HashMap::from([("operation".to_string(), json!(operation))]);
        args.extend(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_string(), value.clone())),
        );
        execute_crosslink_with_tasks(run, &args, task_manager)
    }

    #[test]
    fn dependency_direction_readiness_and_canonical_projection_agree() {
        let root = tempfile::tempdir().expect("crosslink test root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let mut manager = crate::session::TaskManager::for_run(&run).expect("task manager");

        for title in ["upstream", "downstream"] {
            let result = call_with_tasks(
                &run,
                Some(&mut manager),
                "create",
                &[("title", json!(title))],
            );
            assert!(
                matches!(result.outcome, crate::tools::ToolOutcome::Success { .. }),
                "{}",
                result.content()
            );
        }
        let blocked = call_with_tasks(
            &run,
            Some(&mut manager),
            "block",
            &[("id", json!(1)), ("other_id", json!(2))],
        );
        assert!(
            matches!(blocked.outcome, crate::tools::ToolOutcome::Success { .. }),
            "{}",
            blocked.content()
        );

        let db = open_db_for_query(&run).expect("database");
        assert_eq!(
            db.get_blockers(1).expect("upstream blockers"),
            Vec::<i64>::new()
        );
        assert_eq!(db.get_blockers(2).expect("downstream blockers"), vec![1]);
        drop(db);

        let by_external_id = manager
            .list_tasks()
            .iter()
            .filter_map(|task| match &task.source {
                crate::task_graph::TaskSource::ExternalIssue { external_id, .. } => {
                    Some((external_id.clone(), task))
                }
                _ => None,
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            by_external_id["2"].blocked_by,
            vec![by_external_id["1"].id.clone()]
        );

        let next = call_with_tasks(&run, Some(&mut manager), "next", &[]);
        assert!(next.content().contains("#1"), "{}", next.content());
        let closed = call_with_tasks(&run, Some(&mut manager), "close", &[("id", json!(1))]);
        assert!(
            matches!(closed.outcome, crate::tools::ToolOutcome::Success { .. }),
            "{}",
            closed.content()
        );
        let ready = manager.ready_tasks(10).expect("ready tasks");
        assert_eq!(ready.tasks.len(), 1);
        assert!(matches!(
            ready.tasks[0].source,
            crate::task_graph::TaskSource::ExternalIssue {
                ref external_id,
                ..
            } if external_id == "2"
        ));
    }

    #[test]
    fn missing_task_graph_reports_partial_after_external_mutation() {
        let root = tempfile::tempdir().expect("crosslink test root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let result = call_with_tasks(
            &run,
            None,
            "create",
            &[("title", json!("externally committed"))],
        );
        assert!(matches!(
            result.outcome,
            crate::tools::ToolOutcome::Partial { ref failures, .. }
                if failures.len() == 1
                    && failures[0].retryability == ToolRetryability::Never
        ));
        let db = open_db_for_query(&run).expect("database");
        assert_eq!(
            db.require_issue(1).expect("committed issue").title,
            "externally committed"
        );
    }

    #[test]
    fn query_reconciliation_partial_is_safe_to_retry() {
        let root = tempfile::tempdir().expect("crosslink test root");
        let run = crate::tools::security::test_run_context_for(root.path());
        assert!(matches!(
            call_with_tasks(&run, None, "create", &[("title", json!("existing issue"))]).outcome,
            crate::tools::ToolOutcome::Partial { .. }
        ));
        let result = call_with_tasks(&run, None, "list", &[]);
        assert!(matches!(
            result.outcome,
            crate::tools::ToolOutcome::Partial { ref failures, .. }
                if failures.len() == 1
                    && failures[0].retryability == ToolRetryability::Safe
        ));
    }

    #[test]
    fn legacy_chainlink_store_blocks_implicit_copy_and_new_store_creation() {
        let root = tempfile::tempdir().expect("crosslink test root");
        let legacy_dir = root.path().join(LEGACY_CHAINLINK_DIR);
        std::fs::create_dir(&legacy_dir).expect("legacy directory");
        let legacy = legacy_dir.join("issues.db");
        let sentinel = b"legacy database bytes must remain untouched";
        std::fs::write(&legacy, sentinel).expect("legacy fixture");
        let run = crate::tools::security::test_run_context_for(root.path());

        let (message, is_error) = call(
            &run,
            &[
                ("operation", json!("create")),
                ("title", json!("must not create a new store")),
            ],
        );

        assert!(is_error, "legacy state must block implicit store creation");
        assert!(
            message.contains("automatic import is disabled"),
            "{message}"
        );
        assert_eq!(std::fs::read(&legacy).unwrap(), sentinel);
        assert!(
            !root.path().join(CROSSLINK_DIR).exists(),
            "rejection must not materialize a second live store"
        );
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
        assert_eq!(params["additionalProperties"], json!(false));
        assert_eq!(
            params["properties"]["title"]["maxLength"],
            json!(MAX_CROSSLINK_TITLE_BYTES)
        );
        assert_eq!(
            params["properties"]["labels"]["maxItems"],
            json!(MAX_CROSSLINK_LABELS)
        );
        assert_eq!(
            params["properties"]["query"]["maxLength"],
            json!(MAX_CROSSLINK_QUERY_BYTES)
        );
    }
}

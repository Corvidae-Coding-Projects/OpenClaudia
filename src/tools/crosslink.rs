//! Crosslink tool — deep library integration.
//!
//! Replaces the legacy `chainlink` tool (which shelled out to a
//! separate binary). Calls the `crosslink` crate's library API
//! directly, so:
//!
//! * No subprocess fork+exec per command.
//! * No `chainlink` (or `crosslink`) binary required on `$PATH`.
//! * The agent and the `OpenClaudia` process share the same
//!   `sqlite`-backed `Database`, so we could later expose
//!   transactional batches if the use cases warrant it.
//!
//! The model-facing surface keeps the same argv-string contract as
//! the old chainlink tool — `args="create \"title\" -p high"` — so
//! existing prompts and skills continue to work. Each supported
//! subcommand maps to one or more `db::*` calls and renders the
//! result as a short text reply.
//!
//! Supported subcommands (parity with the old chainlink set):
//! `create`, `close`, `reopen`, `comment`, `label`, `unlabel`,
//! `list`, `show`, `search`, `subissue`, `relate`, `block`,
//! `unblock`, `session`, `next`, `tree`, `update`, `help`.
//!
//! Out-of-scope here:
//! * Read/write paths that need new schema (sentinel runs, agent
//!   handoffs with token-usage projection, etc.) live behind their
//!   own focused tools (`session_*`, `handoff_*`) added in a
//!   later phase. This tool exposes the GitHub-issue-style core
//!   workflow only.

use crate::tools::args::ToolArgs as _;
use crosslink::db::Database;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::BuildHasher;
use std::path::PathBuf;

/// Project-local crosslink data directory. Matches crosslink's own
/// convention (`crosslink init` creates `.crosslink/issues.db`).
const CROSSLINK_DIR: &str = ".crosslink";

/// Allowlist of subcommands the model is permitted to invoke. New
/// commands are added explicitly so a typo doesn't silently fall
/// through to "unknown subcommand" — and so we can document scope
/// drift in the changelog rather than discovering it via test
/// flakes.
const ALLOWED_SUBCOMMANDS: &[&str] = &[
    "create", "close", "reopen", "comment", "label", "unlabel", "list", "show", "search",
    "subissue", "relate", "block", "unblock", "session", "next", "ready", "tree", "update", "help",
    "--help", "-h",
];

/// Reject any argv token containing shell metacharacters. Defense
/// in depth — we never exec a shell, but newlines / nulls in argv
/// can still confuse downstream text rendering.
fn token_has_metachar(tok: &str) -> bool {
    tok.chars().any(|c| matches!(c, '\n' | '\r' | '\0'))
}

/// Legacy chainlink data directory. Migrated on first use — see
/// [`migrate_chainlink_if_needed`].
const LEGACY_CHAINLINK_DIR: &str = ".chainlink";

/// Resolve the crosslink DB path under the current working directory.
/// Creates `.crosslink/` if missing so `Database::open` succeeds
/// without a separate `crosslink init` step. When `.chainlink/issues.db`
/// exists and `.crosslink/issues.db` does not, copies the legacy DB
/// into the new location so existing project history survives the
/// chainlink→crosslink migration.
fn db_path_for_cwd() -> Result<PathBuf, String> {
    let cwd = crate::tools::security::current_context()?
        .working_directory()
        .to_path_buf();
    let dir = cwd.join(CROSSLINK_DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Failed to create {CROSSLINK_DIR}/: {e}"))?;
    let db = dir.join("issues.db");
    migrate_chainlink_if_needed(&cwd, &db);
    Ok(db)
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
fn open_db() -> Result<Database, String> {
    let path = db_path_for_cwd()?;
    Database::open(&path).map_err(|e| format!("Failed to open crosslink DB: {e}"))
}

/// Entry point — dispatches `args["args"]` against the subcommand allowlist.
#[must_use]
pub fn execute_crosslink<S: BuildHasher>(args: &HashMap<String, Value, S>) -> (String, bool) {
    // crosslink #675: typed accessor.
    let cmd_args = match args.arg_str_strict("args") {
        Ok(c) => c,
        Err(e) => return e.into_tool_error(),
    };

    let tokens: Vec<String> = match shlex::split(cmd_args) {
        Some(t) if !t.is_empty() => t,
        Some(_) => return ("Missing crosslink subcommand".to_string(), true),
        None => {
            return (
                "Could not parse crosslink args (unbalanced quotes or unsupported escape)"
                    .to_string(),
                true,
            );
        }
    };

    let subcmd = tokens[0].as_str();
    if !ALLOWED_SUBCOMMANDS.contains(&subcmd) {
        return (
            format!(
                "Subcommand '{subcmd}' is not in the crosslink allowlist. Allowed: {}",
                ALLOWED_SUBCOMMANDS.join(", ")
            ),
            true,
        );
    }

    if let Some(bad) = tokens.iter().find(|t| token_has_metachar(t)) {
        return (
            format!("Rejected argv token containing control character: {bad:?}"),
            true,
        );
    }

    let db = match open_db() {
        Ok(d) => d,
        Err(e) => return (e, true),
    };

    let rest = &tokens[1..];
    let outcome = match subcmd {
        "create" => cmd_create(&db, rest),
        "close" => cmd_close(&db, rest),
        "reopen" => cmd_reopen(&db, rest),
        "comment" => cmd_comment(&db, rest),
        "label" => cmd_label(&db, rest, false),
        "unlabel" => cmd_label(&db, rest, true),
        "list" => cmd_list(&db, rest),
        "show" => cmd_show(&db, rest),
        "search" => cmd_search(&db, rest),
        "subissue" => cmd_subissue(&db, rest),
        "relate" => cmd_relate(&db, rest),
        "block" => cmd_block(&db, rest, true),
        "unblock" => cmd_block(&db, rest, false),
        "session" => cmd_session(&db, rest),
        "next" | "ready" => cmd_next(&db),
        "tree" => cmd_tree(&db, rest),
        "update" => cmd_update(&db, rest),
        "help" | "--help" | "-h" => Ok(help_text()),
        _ => unreachable!("subcommand allowlist enforced above"),
    };

    match outcome {
        Ok(msg) if msg.is_empty() => ("(crosslink command completed)".to_string(), false),
        Ok(msg) => (msg, false),
        Err(e) => (format!("crosslink {subcmd}: {e}"), true),
    }
}

// ── Subcommand implementations ────────────────────────────────────────────

fn cmd_create(db: &Database, rest: &[String]) -> Result<String, String> {
    // Mini-CLI: `create "<title>" [-p <priority>] [-d "<description>"] [-l <label>]...`
    let mut title: Option<String> = None;
    let mut priority = "medium".to_string();
    let mut description: Option<String> = None;
    let mut labels: Vec<String> = Vec::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "-p" | "--priority" => {
                i += 1;
                priority = rest.get(i).cloned().ok_or("expected value after -p")?;
            }
            "-d" | "--description" => {
                i += 1;
                description = Some(rest.get(i).cloned().ok_or("expected value after -d")?);
            }
            "-l" | "--label" => {
                i += 1;
                labels.push(rest.get(i).cloned().ok_or("expected value after -l")?);
            }
            other if title.is_none() => title = Some(other.to_string()),
            other => return Err(format!("unexpected argument: {other}")),
        }
        i += 1;
    }
    let title = title.ok_or("create: missing required <title> argument")?;
    let id = db
        .create_issue(&title, description.as_deref(), &priority)
        .map_err(|e| e.to_string())?;
    for label in &labels {
        let _ = db.add_label(id, label);
    }
    Ok(format!("Created issue #{id}: {title}"))
}

fn parse_id(tok: &str, ctx: &str) -> Result<i64, String> {
    tok.parse::<i64>()
        .map_err(|_| format!("{ctx}: expected numeric issue id, got '{tok}'"))
}

fn cmd_close(db: &Database, rest: &[String]) -> Result<String, String> {
    let id = parse_id(rest.first().ok_or("close: missing <id>")?, "close")?;
    let closed = db.close_issue(id).map_err(|e| e.to_string())?;
    Ok(if closed {
        format!("Closed issue #{id}")
    } else {
        format!("Issue #{id} not found or already closed")
    })
}

fn cmd_reopen(db: &Database, rest: &[String]) -> Result<String, String> {
    let id = parse_id(rest.first().ok_or("reopen: missing <id>")?, "reopen")?;
    let reopened = db.reopen_issue(id).map_err(|e| e.to_string())?;
    Ok(if reopened {
        format!("Reopened issue #{id}")
    } else {
        format!("Issue #{id} not found or already open")
    })
}

fn cmd_comment(db: &Database, rest: &[String]) -> Result<String, String> {
    let id = parse_id(rest.first().ok_or("comment: missing <id>")?, "comment")?;
    let content = rest
        .get(1)
        .ok_or("comment: missing comment text (quote it: '#5 \"...\"')")?;
    let cid = db
        .add_comment(id, content, "note")
        .map_err(|e| e.to_string())?;
    Ok(format!("Added comment #{cid} on issue #{id}"))
}

fn cmd_label(db: &Database, rest: &[String], remove: bool) -> Result<String, String> {
    let id = parse_id(rest.first().ok_or("label: missing <id>")?, "label")?;
    let label = rest.get(1).ok_or("label: missing <label>")?;
    if remove {
        db.remove_label(id, label).map_err(|e| e.to_string())?;
        Ok(format!("Removed label '{label}' from issue #{id}"))
    } else {
        db.add_label(id, label).map_err(|e| e.to_string())?;
        Ok(format!("Added label '{label}' to issue #{id}"))
    }
}

fn cmd_list(db: &Database, rest: &[String]) -> Result<String, String> {
    // Optional filters: `-s open|closed|archived`, `-l <label>`, `-p <priority>`
    let mut status: Option<String> = Some("open".to_string());
    let mut label: Option<String> = None;
    let mut priority: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "-s" | "--status" => {
                i += 1;
                let v = rest.get(i).ok_or("expected value after -s")?;
                status = if v == "all" { None } else { Some(v.clone()) };
            }
            "-l" | "--label" => {
                i += 1;
                label = Some(rest.get(i).cloned().ok_or("expected value after -l")?);
            }
            "-p" | "--priority" => {
                i += 1;
                priority = Some(rest.get(i).cloned().ok_or("expected value after -p")?);
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
        i += 1;
    }
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

fn cmd_show(db: &Database, rest: &[String]) -> Result<String, String> {
    let id = parse_id(rest.first().ok_or("show: missing <id>")?, "show")?;
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

fn cmd_search(db: &Database, rest: &[String]) -> Result<String, String> {
    let query = rest
        .first()
        .ok_or("search: missing query string (quote it)")?;
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

fn cmd_subissue(db: &Database, rest: &[String]) -> Result<String, String> {
    let parent = parse_id(
        rest.first().ok_or("subissue: missing <parent_id>")?,
        "subissue",
    )?;
    let title = rest.get(1).ok_or("subissue: missing <title>")?;
    let priority = rest
        .iter()
        .position(|t| t == "-p" || t == "--priority")
        .and_then(|i| rest.get(i + 1))
        .map_or("medium", String::as_str);
    let id = db
        .create_subissue(parent, title, None, priority)
        .map_err(|e| e.to_string())?;
    Ok(format!("Created subissue #{id} under #{parent}: {title}"))
}

fn cmd_relate(db: &Database, rest: &[String]) -> Result<String, String> {
    let a = parse_id(rest.first().ok_or("relate: missing <id1>")?, "relate")?;
    let b = parse_id(rest.get(1).ok_or("relate: missing <id2>")?, "relate")?;
    db.add_relation(a, b).map_err(|e| e.to_string())?;
    Ok(format!("Related issues #{a} ↔ #{b}"))
}

fn cmd_block(db: &Database, rest: &[String], add: bool) -> Result<String, String> {
    let upstream = parse_id(rest.first().ok_or("block: missing <blocker_id>")?, "block")?;
    let downstream = parse_id(rest.get(1).ok_or("block: missing <blocked_id>")?, "block")?;
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

fn cmd_session(db: &Database, rest: &[String]) -> Result<String, String> {
    // Crosslink 0.5's public API exposes the `*_for_agent` variants only;
    // pass `None` to use the default (non-agent-scoped) session bucket.
    let sub = rest.first().map_or("status", String::as_str);
    match sub {
        "start" => {
            let id = db
                .start_session_with_agent(None)
                .map_err(|e| e.to_string())?;
            Ok(format!("Started session #{id}"))
        }
        "end" => {
            let sess = db
                .get_current_session_for_agent(None)
                .map_err(|e| e.to_string())?
                .ok_or("no active session to end")?;
            let notes = rest
                .iter()
                .position(|t| t == "--notes" || t == "-n")
                .and_then(|i| rest.get(i + 1).map(String::as_str));
            db.end_session(sess.id, notes).map_err(|e| e.to_string())?;
            Ok(format!("Ended session #{}", sess.id))
        }
        "work" => {
            let sess = db
                .get_current_session_for_agent(None)
                .map_err(|e| e.to_string())?
                .ok_or("no active session; run `session start` first")?;
            let issue_id = parse_id(
                rest.get(1).ok_or("session work: missing <issue_id>")?,
                "session work",
            )?;
            db.set_session_issue(sess.id, issue_id)
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "Session #{} now tracking issue #{}",
                sess.id, issue_id
            ))
        }
        "action" => {
            let sess = db
                .get_current_session_for_agent(None)
                .map_err(|e| e.to_string())?
                .ok_or("no active session; run `session start` first")?;
            let action = rest
                .get(1)
                .ok_or("session action: missing action text (quote it)")?;
            db.set_session_action(sess.id, action)
                .map_err(|e| e.to_string())?;
            Ok(format!("Recorded action on session #{}", sess.id))
        }
        "status" | "show" => match db
            .get_current_session_for_agent(None)
            .map_err(|e| e.to_string())?
        {
            Some(s) => Ok(format!(
                "Session #{}: started {}, active issue {:?}, last action {:?}",
                s.id, s.started_at, s.active_issue_id, s.last_action
            )),
            None => Ok("(no active session)".to_string()),
        },
        other => Err(format!("unknown session subcommand: {other}")),
    }
}

fn cmd_next(db: &Database) -> Result<String, String> {
    // crosslink's `next` recommends the highest-priority ready issue
    // (no open blockers). Fall back to "highest priority open issue"
    // when the dependency graph is too small for a meaningful
    // recommendation.
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

fn cmd_tree(db: &Database, rest: &[String]) -> Result<String, String> {
    let root_id = rest.first().map(|t| parse_id(t, "tree")).transpose()?;
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

fn cmd_update(db: &Database, rest: &[String]) -> Result<String, String> {
    let id = parse_id(rest.first().ok_or("update: missing <id>")?, "update")?;
    let mut title: Option<String> = None;
    let mut description: Option<String> = None;
    let mut priority: Option<String> = None;
    let mut i = 1;
    while i < rest.len() {
        match rest[i].as_str() {
            "-t" | "--title" => {
                i += 1;
                title = Some(rest.get(i).cloned().ok_or("expected value after -t")?);
            }
            "-d" | "--description" => {
                i += 1;
                description = Some(rest.get(i).cloned().ok_or("expected value after -d")?);
            }
            "-p" | "--priority" => {
                i += 1;
                priority = Some(rest.get(i).cloned().ok_or("expected value after -p")?);
            }
            other => return Err(format!("unexpected argument: {other}")),
        }
        i += 1;
    }
    db.update_issue(
        id,
        title.as_deref(),
        description.as_deref(),
        priority.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    Ok(format!("Updated issue #{id}"))
}

fn help_text() -> String {
    "crosslink subcommands:\n  \
     create \"<title>\" [-p priority] [-d desc] [-l label]\n  \
     close <id>\n  \
     reopen <id>\n  \
     comment <id> \"<text>\"\n  \
     label <id> <label>      / unlabel <id> <label>\n  \
     list [-s status] [-l label] [-p priority]\n  \
     show <id>\n  \
     search \"<query>\"\n  \
     subissue <parent_id> \"<title>\" [-p priority]\n  \
     relate <id1> <id2>\n  \
     block <blocker_id> <blocked_id>   / unblock <blocker_id> <blocked_id>\n  \
     session start | end [--notes \"...\"] | work <id> | action \"...\" | status\n  \
     next                    # suggest the highest-priority ready issue\n  \
     tree [<root_id>]\n  \
     update <id> [-t title] [-d desc] [-p priority]"
        .to_string()
}

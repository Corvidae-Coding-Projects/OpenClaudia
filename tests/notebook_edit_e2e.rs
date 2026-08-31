//! End-to-end tests for `execute_notebook_edit` and the
//! `source_to_line_array` helper.
//!
//! Sprint 23 of the verification effort. `src/tools/file/notebook.rs`
//! has 20 unit tests for the leaf functions but no integration
//! coverage that drives a full read → edit → read round-trip
//! through the public dispatch.
//!
//! Coverage shape:
//!
//!   - **`source_to_line_array` round-trip** — the conversion
//!     between a string source and the nbformat "source as
//!     array of strings, each but the last ending in '\\n'"
//!     representation MUST be byte-exact and lossless.
//!   - **Cell replace** — locating a cell by id and rewriting
//!     its source updates the persisted file; other cells are
//!     untouched.
//!   - **Cell insert** — inserts a new cell with the requested
//!     `cell_type`; the file's `cells.len()` grows by 1.
//!   - **Cell delete** — removes the cell; `cells.len()`
//!     shrinks by 1.
//!   - **Validation** — invalid `edit_mode` rejected; invalid
//!     `cell_type` rejected; unknown `cell_id` reported.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{execute_tool, source_to_line_array, FunctionCall, ToolCall};
use serde_json::{json, Value};
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

static SESSION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn session_lock() -> MutexGuard<'static, ()> {
    SESSION_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn call(name: &str, args: &Value) -> ToolCall {
    ToolCall {
        id: format!("sprint23_{name}"),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: args.to_string(),
        },
    }
}

/// Drive `read_file` through public dispatch and return its typed generation.
fn mark_read_snapshot(path: &str) -> String {
    let result = execute_tool(
        support::shared_run_context(),
        &call("read_file", &json!({"path": path})),
    );
    assert!(
        !result.is_error(),
        "read_file must succeed: {}",
        result.content()
    );
    result
        .structured()
        .and_then(|value| value.pointer("/artifact/generation"))
        .and_then(Value::as_str)
        .expect("successful notebook read must expose a typed snapshot generation")
        .to_string()
}

fn notebook_edit(args: &Value) -> (String, bool) {
    let r = execute_tool(support::shared_run_context(), &call("notebook_edit", args));
    (r.content().to_string(), r.is_error())
}

/// Build a minimal valid nbformat-v4 notebook with the given cells.
/// Each cell is `(id, cell_type, source)`.
fn make_notebook(cells: &[(&str, &str, &str)]) -> Value {
    let cell_array: Vec<Value> = cells
        .iter()
        .map(|(id, ct, src)| {
            let mut cell = json!({
                "id": id,
                "cell_type": ct,
                "metadata": {},
                "source": source_to_line_array(src),
            });
            if *ct == "code" {
                cell["outputs"] = json!([]);
                cell["execution_count"] = Value::Null;
            }
            cell
        })
        .collect();
    json!({
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {},
        "cells": cell_array,
    })
}

fn write_notebook(path: &std::path::Path, nb: &Value) {
    std::fs::write(path, serde_json::to_string_pretty(nb).unwrap()).expect("write notebook");
}

fn read_notebook(path: &std::path::Path) -> Value {
    let s = std::fs::read_to_string(path).expect("read notebook");
    serde_json::from_str(&s).expect("parse notebook")
}

fn cells_len(nb: &Value) -> usize {
    nb.get("cells")
        .and_then(|c| c.as_array())
        .map_or(0, std::vec::Vec::len)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — source_to_line_array conversion
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn source_to_line_array_empty_input_yields_empty_array() {
    let arr = source_to_line_array("");
    assert_eq!(arr, json!([]));
}

#[test]
fn source_to_line_array_single_line_no_trailing_newline() {
    // A single line without trailing \n is one element with no \n.
    let arr = source_to_line_array("only line");
    assert_eq!(arr, json!(["only line"]));
}

#[test]
fn source_to_line_array_multi_line_appends_newline_to_each_except_last() {
    // The nbformat convention: every element except the last
    // ends with '\n'. A trailing newline in the source means the
    // last element is empty (so its predecessor still ends in \n).
    let arr = source_to_line_array("alpha\nbravo\ncharlie");
    assert_eq!(arr, json!(["alpha\n", "bravo\n", "charlie"]));
}

#[test]
fn source_to_line_array_trailing_newline_drops_empty_final_element() {
    // Implementation contract (src/tools/file/notebook.rs:30-49):
    // the last line is included as-is, BUT the empty trailing
    // string produced by split('\n') on a string ending in '\n'
    // is dropped. So "alpha\nbravo\n" yields the same shape as
    // "alpha\nbravo" with each non-last line terminated.
    let arr = source_to_line_array("alpha\nbravo\n");
    assert_eq!(arr, json!(["alpha\n", "bravo\n"]));
}

#[test]
fn source_to_line_array_preserves_unicode() {
    let arr = source_to_line_array("héllo\n世界\n🚀");
    assert_eq!(arr, json!(["héllo\n", "世界\n", "🚀"]));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — execute_notebook_edit happy paths
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn replace_cell_by_id_rewrites_source() {
    let _sess = session_lock();

    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("nb.ipynb");
    let nb = make_notebook(&[
        ("c1", "code", "print('one')"),
        ("c2", "code", "print('two')"),
    ]);
    write_notebook(&path, &nb);
    let path_str = path.to_string_lossy().to_string();

    // Mark the file as read so the gate passes.
    let snapshot = mark_read_snapshot(&path_str);

    let (msg, is_err) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_id": "c2",
        "edit_mode": "replace",
        "new_source": "print('TWO REPLACED')",
        "expected_snapshot": snapshot,
    }));
    assert!(!is_err, "replace must succeed: {msg:?}");

    let after = read_notebook(&path);
    let cells = after.get("cells").and_then(|c| c.as_array()).unwrap();
    assert_eq!(cells.len(), 2, "cell count unchanged after replace");
    // c1 untouched.
    let c1_src = &cells[0].get("source");
    assert!(
        format!("{c1_src:?}").contains("print('one')"),
        "c1 must be unchanged; got {c1_src:?}"
    );
    // c2 replaced.
    let c2_src = &cells[1].get("source");
    assert!(
        format!("{c2_src:?}").contains("TWO REPLACED"),
        "c2 must be rewritten; got {c2_src:?}"
    );
}

#[test]
fn insert_cell_grows_notebook_by_one() {
    let _sess = session_lock();

    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("nb.ipynb");
    let nb = make_notebook(&[("c1", "code", "x = 1")]);
    write_notebook(&path, &nb);
    let path_str = path.to_string_lossy().to_string();
    let snapshot = mark_read_snapshot(&path_str);

    let before = read_notebook(&path);
    assert_eq!(cells_len(&before), 1);

    let (msg, is_err) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_id": "c1",
        "edit_mode": "insert",
        "cell_type": "markdown",
        "new_source": "# Inserted markdown",
        "expected_snapshot": snapshot,
    }));
    assert!(!is_err, "insert must succeed: {msg:?}");

    let after = read_notebook(&path);
    assert_eq!(
        cells_len(&after),
        2,
        "cell count must grow by 1 after insert"
    );
    let inserted_id = after["cells"][1]["id"]
        .as_str()
        .expect("inserted cell has a stable id");
    assert!((1..=64).contains(&inserted_id.len()));
    assert!(inserted_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
}

#[test]
fn delete_cell_shrinks_notebook_by_one() {
    let _sess = session_lock();

    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("nb.ipynb");
    let nb = make_notebook(&[
        ("c1", "code", "x = 1"),
        ("c2", "code", "y = 2"),
        ("c3", "code", "z = 3"),
    ]);
    write_notebook(&path, &nb);
    let path_str = path.to_string_lossy().to_string();
    let snapshot = mark_read_snapshot(&path_str);

    let (msg, is_err) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_id": "c2",
        "edit_mode": "delete",
        "expected_snapshot": snapshot,
    }));
    assert!(!is_err, "delete must succeed: {msg:?}");

    let after = read_notebook(&path);
    let cells = after.get("cells").and_then(|c| c.as_array()).unwrap();
    assert_eq!(cells.len(), 2);
    // c2 must be gone; c1 + c3 remain.
    let ids: Vec<&str> = cells
        .iter()
        .filter_map(|c| c.get("id").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(ids, vec!["c1", "c3"], "c2 must be removed");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — validation refusals
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn invalid_edit_mode_is_refused() {
    let _sess = session_lock();

    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("nb.ipynb");
    write_notebook(&path, &make_notebook(&[("c1", "code", "x = 1")]));
    let path_str = path.to_string_lossy().to_string();
    let snapshot = mark_read_snapshot(&path_str);

    let (msg, is_err) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_id": "c1",
        "edit_mode": "yeet",
        "new_source": "placeholder",
        "expected_snapshot": snapshot,
    }));
    assert!(is_err, "invalid edit_mode must error");
    assert!(
        msg.to_lowercase().contains("edit_mode") || msg.to_lowercase().contains("invalid"),
        "msg must mention the invalid edit_mode; got {msg:?}"
    );
}

#[test]
fn invalid_cell_type_on_insert_is_refused() {
    let _sess = session_lock();

    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("nb.ipynb");
    write_notebook(&path, &make_notebook(&[("c1", "code", "x = 1")]));
    let path_str = path.to_string_lossy().to_string();
    let snapshot = mark_read_snapshot(&path_str);

    let (msg, is_err) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_id": "c1",
        "edit_mode": "insert",
        "cell_type": "garbage",
        "new_source": "x",
        "expected_snapshot": snapshot,
    }));
    assert!(is_err, "invalid cell_type must error");
    assert!(
        msg.to_lowercase().contains("cell_type") || msg.to_lowercase().contains("invalid"),
        "msg must mention invalid cell_type; got {msg:?}"
    );
}

#[test]
fn unknown_cell_id_on_replace_is_refused() {
    let _sess = session_lock();

    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("nb.ipynb");
    write_notebook(&path, &make_notebook(&[("c1", "code", "x = 1")]));
    let path_str = path.to_string_lossy().to_string();
    let snapshot = mark_read_snapshot(&path_str);

    let (msg, is_err) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_id": "no-such-cell",
        "edit_mode": "replace",
        "new_source": "y",
        "expected_snapshot": snapshot,
    }));
    assert!(is_err, "unknown cell_id must error; got msg={msg:?}");
}

#[test]
fn parent_dir_traversal_in_notebook_path_is_refused_before_read_gate() {
    let _sess = session_lock();

    let (msg, is_err) = notebook_edit(&json!({
        "notebook_path": "/tmp/../etc/passwd",
        "cell_id": "c1",
        "edit_mode": "replace",
        "new_source": "x",
        "expected_snapshot": format!("sha256:{}", "0".repeat(64)),
    }));
    assert!(is_err, "../-traversal notebook_path MUST be rejected");
    assert!(
        msg.contains("traversal") || msg.contains("Path"),
        "MUST surface path-traversal message; got {msg:?}"
    );
    assert!(
        !msg.contains("must read"),
        "traversal must fail before must-read gate; got {msg:?}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_leaf_notebook_path_is_refused_through_public_dispatch() {
    let _sess = session_lock();

    let dir = TempDir::new_in(".").expect("tempdir");
    let target = dir.path().join("target.ipynb");
    let nb = make_notebook(&[("guarded", "code", "SAFE")]);
    write_notebook(&target, &nb);
    let link = dir.path().join("link.ipynb");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let link_str = link.to_string_lossy().to_string();

    let snapshot = mark_read_snapshot(&link_str);

    let (msg, is_err) = notebook_edit(&json!({
        "notebook_path": link_str,
        "cell_id": "guarded",
        "edit_mode": "replace",
        "new_source": "ATTACKER_INJECTED_SOURCE",
        "expected_snapshot": snapshot,
    }));
    assert!(
        is_err,
        "notebook_edit through a symlink leaf must fail via public dispatch: {msg}"
    );

    let after = std::fs::read_to_string(&target).expect("read target");
    assert!(
        after.contains("SAFE"),
        "symlink target must not be overwritten; got {after}"
    );
    assert!(
        !after.contains("ATTACKER_INJECTED_SOURCE"),
        "injected source must not appear in target"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — schema preservation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn nbformat_top_level_fields_survive_edit() {
    // nbformat / nbformat_minor / metadata must round-trip
    // unchanged after a cell edit — losing them would invalidate
    // the file as a notebook in Jupyter clients.
    let _sess = session_lock();

    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("nb.ipynb");
    let nb = make_notebook(&[("c1", "code", "x = 1")]);
    write_notebook(&path, &nb);
    let path_str = path.to_string_lossy().to_string();
    let snapshot = mark_read_snapshot(&path_str);

    let (_, is_err) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_id": "c1",
        "edit_mode": "replace",
        "new_source": "x = 2",
        "expected_snapshot": snapshot,
    }));
    assert!(!is_err);

    let after = read_notebook(&path);
    assert_eq!(
        after.get("nbformat").and_then(Value::as_i64),
        Some(4),
        "nbformat MUST survive edit"
    );
    assert_eq!(
        after.get("nbformat_minor").and_then(Value::as_i64),
        Some(5),
        "nbformat_minor MUST survive edit"
    );
    assert!(
        after.get("metadata").is_some(),
        "metadata MUST survive edit"
    );
}

#[test]
fn stale_snapshot_never_overwrites_a_concurrent_notebook_generation() {
    let _sess = session_lock();
    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("stale.ipynb");
    write_notebook(&path, &make_notebook(&[("c1", "code", "reviewed")]));
    let path_str = path.to_string_lossy().to_string();
    let snapshot = mark_read_snapshot(&path_str);

    let concurrent = make_notebook(&[("c1", "code", "external update")]);
    let concurrent_bytes = serde_json::to_vec_pretty(&concurrent).expect("serialize concurrent");
    std::fs::write(&path, &concurrent_bytes).expect("concurrent write");

    let (message, is_error) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_id": "c1",
        "edit_mode": "replace",
        "new_source": "agent update",
        "expected_snapshot": snapshot,
    }));
    assert!(is_error, "stale generation must be refused");
    assert!(
        message.contains("changed") || message.contains("conflict"),
        "failure must explain the generation conflict: {message}"
    );
    assert_eq!(
        std::fs::read(&path).expect("read concurrent notebook"),
        concurrent_bytes,
        "the concurrent generation must remain byte-for-byte intact"
    );
}

#[test]
fn malformed_notebook_is_rejected_without_rewriting_it() {
    let _sess = session_lock();
    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("duplicate-ids.ipynb");
    let malformed = json!({
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {"preserve": true},
        "cells": [
            {"id": "duplicate", "cell_type": "code", "metadata": {}, "source": ["a"], "outputs": [], "execution_count": null},
            {"id": "duplicate", "cell_type": "markdown", "metadata": {}, "source": ["b"]}
        ]
    });
    let original = serde_json::to_vec_pretty(&malformed).expect("serialize malformed");
    std::fs::write(&path, &original).expect("write malformed notebook");
    let path_str = path.to_string_lossy().to_string();
    let snapshot = mark_read_snapshot(&path_str);

    let (message, is_error) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_number": 0,
        "edit_mode": "replace",
        "new_source": "changed",
        "expected_snapshot": snapshot,
    }));
    assert!(is_error, "duplicate cell IDs must be rejected");
    assert!(
        message.contains("repeats cell id"),
        "unexpected error: {message}"
    );
    assert_eq!(std::fs::read(&path).expect("read malformed"), original);
}

#[test]
fn legacy_v4_notebook_round_trip_adds_ids_and_preserves_unrelated_content() {
    let _sess = session_lock();
    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("legacy.ipynb");
    let legacy = json!({
        "nbformat": 4,
        "nbformat_minor": 4,
        "metadata": {"kernelspec": {"name": "python3"}, "custom": [1, 2, 3]},
        "cells": [
            {
                "cell_type": "code",
                "metadata": {"trusted": true},
                "source": ["print('kept')"],
                "outputs": [{"output_type": "stream", "name": "stdout", "text": ["kept\n"]}],
                "execution_count": 7
            },
            {"cell_type": "markdown", "metadata": {"tag": "edit"}, "source": ["old"]}
        ]
    });
    write_notebook(&path, &legacy);
    let path_str = path.to_string_lossy().to_string();
    let snapshot = mark_read_snapshot(&path_str);

    let (message, is_error) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_number": 1,
        "edit_mode": "replace",
        "new_source": "new markdown",
        "expected_snapshot": snapshot,
    }));
    assert!(!is_error, "legacy notebook edit must succeed: {message}");

    let after = read_notebook(&path);
    assert_eq!(after["nbformat_minor"], 5);
    assert_eq!(after["metadata"], legacy["metadata"]);
    assert_eq!(after["cells"][0]["outputs"], legacy["cells"][0]["outputs"]);
    assert_eq!(
        after["cells"][0]["execution_count"],
        legacy["cells"][0]["execution_count"]
    );
    let ids: Vec<&str> = after["cells"]
        .as_array()
        .expect("cells")
        .iter()
        .map(|cell| cell["id"].as_str().expect("stable cell id"))
        .collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn expected_snapshot_is_mandatory_after_a_successful_read() {
    let _sess = session_lock();
    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("generation-required.ipynb");
    write_notebook(&path, &make_notebook(&[("c1", "code", "old")]));
    let path_str = path.to_string_lossy().to_string();
    let _snapshot = mark_read_snapshot(&path_str);
    let original = std::fs::read(&path).expect("original bytes");

    let (message, is_error) = notebook_edit(&json!({
        "notebook_path": path_str,
        "cell_id": "c1",
        "edit_mode": "replace",
        "new_source": "new",
    }));
    assert!(is_error, "missing generation must be rejected");
    assert!(
        message.contains("expected_snapshot"),
        "unexpected error: {message}"
    );
    assert_eq!(std::fs::read(&path).expect("unchanged bytes"), original);
}

#[test]
fn successful_edit_returns_the_committed_generation() {
    let _sess = session_lock();
    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("receipt.ipynb");
    write_notebook(&path, &make_notebook(&[("c1", "code", "old")]));
    let path_str = path.to_string_lossy().to_string();
    let before = mark_read_snapshot(&path_str);

    let result = execute_tool(
        support::shared_run_context(),
        &call(
            "notebook_edit",
            &json!({
                "notebook_path": path_str,
                "cell_id": "c1",
                "edit_mode": "replace",
                "new_source": "new",
                "expected_snapshot": before,
            }),
        ),
    );
    assert!(
        !result.is_error(),
        "edit must succeed: {}",
        result.content()
    );
    let receipt = result.structured().expect("typed notebook edit receipt");
    assert_eq!(receipt["before_snapshot"], before);
    let committed = receipt["after_snapshot"]
        .as_str()
        .expect("committed generation");
    assert_ne!(committed, before);
    assert_eq!(mark_read_snapshot(&path_str), committed);
}
mod support;

//! Integration tests for file tools — pins the behavioral contracts from Phase 1 spec (#525).
//!
//! Each test covers a cross-tool or cross-behavior flow that cannot be verified
//! in a single-function unit test. The write → read → edit → read flow (Behavior 1+4+6)
//! is the primary focus; public `glob` and `grep` dispatch through
//! `execute_tool` is also pinned here.
//!
//! Naming convention: `<behavior_slug>_<scenario>` so the audit mapping is clear.

use openclaudia::tools::{execute_tool, reset_read_tracker, FunctionCall, ToolCall};
use serde_json::json;
use std::fs;
use std::sync::Mutex;
use tempfile::TempDir;

/// Serialise-and-reset guard so every test that touches `READ_TRACKER` runs in
/// isolation even when `cargo test` uses multiple threads.
static READ_TRACKER_LOCK: Mutex<()> = Mutex::new(());

fn make_call(name: &str, args: &serde_json::Value) -> ToolCall {
    ToolCall {
        id: format!("inttest_{name}"),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: args.to_string(),
        },
    }
}

// =============================================================================
// Behavior 6 + 1 + 4: write → read → edit → read cross-tool flow
// =============================================================================

#[test]
fn write_read_edit_read_cross_tool_flow() {
    // Covers Behavior 6 (write with parent-dir create), Behavior 1 (read with
    // offset/limit), and Behavior 4 (edit with old_string present/absent).
    let _lock = READ_TRACKER_LOCK.lock().expect("lock");
    reset_read_tracker(support::shared_run_context());

    let dir = TempDir::new_in(".").expect("tempdir");
    let sub = dir.path().join("subdir").join("notes.txt");

    // ---- Step 1: write creates missing parent directory (Behavior 6) --------
    let write_call = make_call(
        "write_file",
        &json!({
            "path": sub.to_string_lossy(),
            "content": "line one\nline two\nline three\n"
        }),
    );
    let wr = execute_tool(support::shared_run_context(), &write_call);
    assert!(!wr.is_error(), "write_file must succeed: {}", wr.content());
    assert!(sub.exists(), "file created on disk");
    assert!(sub.parent().expect("parent").is_dir(), "parent dir created");

    // ---- Step 2: read without offset returns all lines (Behavior 1) ----------
    let read_all_call = make_call("read_file", &json!({ "path": sub.to_string_lossy() }));
    let ra = execute_tool(support::shared_run_context(), &read_all_call);
    assert!(!ra.is_error(), "read_file must succeed: {}", ra.content());
    assert!(ra.content().contains("line one"), "all lines present");
    assert!(ra.content().contains("line three"), "all lines present");

    // ---- Step 3: read with offset + limit (Behavior 1) ----------------------
    let read_slice_call = make_call(
        "read_file",
        &json!({
            "path": sub.to_string_lossy(),
            "offset": 2,
            "limit": 1
        }),
    );
    let rs = execute_tool(support::shared_run_context(), &read_slice_call);
    assert!(
        !rs.is_error(),
        "read with offset must succeed: {}",
        rs.content()
    );
    assert!(rs.content().contains("line two"), "offset=2 yields line 2");
    assert!(!rs.content().contains("line one"), "line 1 excluded");
    assert!(!rs.content().contains("line three"), "line 3 excluded");
    assert!(
        rs.content().contains("showing lines 2-2 of 3 total"),
        "suffix present: {}",
        rs.content()
    );

    // ---- Step 4: edit with matching old_string (Behavior 4 happy path) ------
    let edit_ok_call = make_call(
        "edit_file",
        &json!({
            "path": sub.to_string_lossy(),
            "old_string": "line two",
            "new_string": "LINE TWO (edited)"
        }),
    );
    let eo = execute_tool(support::shared_run_context(), &edit_ok_call);
    assert!(!eo.is_error(), "edit_file must succeed: {}", eo.content());

    // ---- Step 5: verify the edit landed on disk -----------------------------
    let disk = fs::read_to_string(&sub).expect("read after edit");
    assert!(disk.contains("LINE TWO (edited)"), "edit persisted");
    assert!(!disk.contains("line two\n"), "old string gone");

    // ---- Step 6: re-read and confirm the new content (Behavior 1 round-trip)
    let read_final = make_call("read_file", &json!({ "path": sub.to_string_lossy() }));
    let rf = execute_tool(support::shared_run_context(), &read_final);
    assert!(!rf.is_error(), "re-read must succeed: {}", rf.content());
    assert!(
        rf.content().contains("LINE TWO (edited)"),
        "edited content visible via read"
    );

    // ---- Step 7: edit with absent old_string returns error (Behavior 4) -----
    let edit_bad_call = make_call(
        "edit_file",
        &json!({
            "path": sub.to_string_lossy(),
            "old_string": "ABSENT TEXT",
            "new_string": "whatever"
        }),
    );
    let eb = execute_tool(support::shared_run_context(), &edit_bad_call);
    assert!(
        eb.is_error(),
        "edit with missing old_string must error: {}",
        eb.content()
    );
    assert!(
        eb.content().contains("Could not find the specified text"),
        "error message: {}",
        eb.content()
    );

    // File must be unmodified after failed edit
    let disk2 = fs::read_to_string(&sub).expect("read after failed edit");
    assert!(
        disk2.contains("LINE TWO (edited)"),
        "file unmodified after error"
    );
}

// =============================================================================
// Behavior 6: write parent-dir creation — deep nested path
// =============================================================================

#[test]
fn write_creates_deeply_nested_parent_directories() {
    // Behavior 6: create_dir_all handles any depth
    let dir = TempDir::new_in(".").expect("tempdir");
    let deep = dir
        .path()
        .join("a")
        .join("b")
        .join("c")
        .join("d")
        .join("file.txt");
    let call = make_call(
        "write_file",
        &json!({
            "path": deep.to_string_lossy(),
            "content": "deep"
        }),
    );
    let r = execute_tool(support::shared_run_context(), &call);
    assert!(!r.is_error(), "deep write must succeed: {}", r.content());
    assert_eq!(fs::read_to_string(&deep).expect("read"), "deep");
}

// =============================================================================
// Behavior 1: offset beyond EOF — non-error empty result
// =============================================================================

#[test]
fn read_offset_beyond_eof_is_non_error() {
    // Behavior 1 edge: OC does NOT error when offset > file line count.
    // CC would emit a warning; OC returns an empty body with a suffix.
    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("short.txt");
    fs::write(&path, "only one line\n").expect("write");

    let call = make_call(
        "read_file",
        &json!({
            "path": path.to_string_lossy(),
            "offset": 999
        }),
    );
    let r = execute_tool(support::shared_run_context(), &call);
    assert!(
        !r.is_error(),
        "offset > EOF must NOT be an error in OC: {}",
        r.content()
    );
    assert!(
        !r.content().contains("only one line"),
        "no content after skip"
    );
}

// =============================================================================
// Behavior 8: large file — truncation is non-error (not an error like CC)
// =============================================================================

#[test]
fn read_large_file_truncated_as_non_error() {
    // Behavior 8: OC silently truncates at 100 000 chars; CC throws an error.
    // Pinned as current OC behavior. CC parity gap: no error flag, no offset
    // guidance in the result.
    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("large.txt");
    // Each numbered line is ~208 chars; 600 lines ≈ 124 800 chars → triggers truncation
    let line = "y".repeat(200) + "\n";
    let content = line.repeat(600);
    fs::write(&path, &content).expect("write");

    let call = make_call("read_file", &json!({ "path": path.to_string_lossy() }));
    let r = execute_tool(support::shared_run_context(), &call);
    assert!(
        !r.is_error(),
        "OC large-file truncation is NOT an error (CC parity gap, Behavior 8): {}",
        r.content()
    );
    assert!(
        r.content().contains("file truncated"),
        "truncation note present: {}",
        r.content()
    );
}

// =============================================================================
// Behavior 2: detect_file_type dispatches image extensions correctly
// =============================================================================

#[test]
fn read_image_extensions_dispatched_as_image() {
    // Behavior 2: .png, .jpg, .jpeg, .gif, .webp must trigger the image path.
    // We write 1 byte (not valid image data, but enough to confirm dispatch).
    let dir = TempDir::new_in(".").expect("tempdir");
    for ext in &["png", "jpg", "jpeg", "gif", "webp"] {
        let path = dir.path().join(format!("img.{ext}"));
        fs::write(&path, b"\x00").expect("write");
        let call = make_call("read_file", &json!({ "path": path.to_string_lossy() }));
        let r = execute_tool(support::shared_run_context(), &call);
        // OC returns a plain-text block with base64 (Behavior 2 OC path)
        assert!(
            !r.is_error(),
            "image read ({ext}) must succeed: {}",
            r.content()
        );
        assert!(
            r.content().contains("[Image:"),
            "image header for .{ext}: {}",
            r.content()
        );
    }
}

// =============================================================================
// GlobTool — public execute_tool dispatch
// =============================================================================

#[test]
fn glob_tool_finds_matching_files_through_execute_tool() {
    let dir = TempDir::new_in(".").expect("tempdir");
    fs::write(dir.path().join("alpha.rs"), "fn alpha() {}\n").expect("write alpha");
    fs::write(dir.path().join("beta.rs"), "fn beta() {}\n").expect("write beta");
    fs::write(dir.path().join("notes.txt"), "not rust\n").expect("write notes");

    let call = make_call(
        "glob",
        &json!({
            "pattern": "*.rs",
            "path": dir.path().to_string_lossy()
        }),
    );
    let r = execute_tool(support::shared_run_context(), &call);
    assert!(
        !r.is_error(),
        "glob must be implemented and succeed through execute_tool: {}",
        r.content()
    );
    assert!(r.content().contains("alpha.rs"), "must include alpha.rs");
    assert!(r.content().contains("beta.rs"), "must include beta.rs");
    assert!(
        !r.content().contains("notes.txt"),
        "*.rs glob must not include notes.txt: {}",
        r.content()
    );
}

// =============================================================================
// GrepTool — public execute_tool dispatch
// =============================================================================

#[test]
fn grep_tool_finds_matching_lines_through_execute_tool() {
    let dir = TempDir::new_in(".").expect("tempdir");
    fs::write(
        dir.path().join("src.txt"),
        "first line\nneedle: important result\nlast line\n",
    )
    .expect("write source");
    fs::write(dir.path().join("other.txt"), "no match here\n").expect("write other");

    let call = make_call(
        "grep",
        &json!({
            "pattern": "needle",
            "path": dir.path().to_string_lossy()
        }),
    );
    let r = execute_tool(support::shared_run_context(), &call);
    assert!(
        !r.is_error(),
        "grep must be implemented and succeed through execute_tool: {}",
        r.content()
    );
    assert!(r.content().contains("needle: important result"));
    assert!(
        !r.content().contains("no match here"),
        "grep output must include only matching files/lines: {}",
        r.content()
    );
}

// =============================================================================
// Behavior 5: replace_all with multi-occurrence
// =============================================================================

#[test]
fn edit_replace_all_multi_occurrence_replaces_every_match() {
    let _lock = READ_TRACKER_LOCK.lock().expect("lock");
    reset_read_tracker(support::shared_run_context());

    let dir = TempDir::new_in(".").expect("tempdir");
    let path = dir.path().join("multi.txt");
    fs::write(&path, "foo bar foo baz foo\n").expect("write");

    // Read first (enforced by OC)
    let read_call = make_call("read_file", &json!({ "path": path.to_string_lossy() }));
    let _ = execute_tool(support::shared_run_context(), &read_call);

    let edit_call = make_call(
        "edit_file",
        &json!({
            "path": path.to_string_lossy(),
            "old_string": "foo",
            "new_string": "qux",
            "replace_all": true
        }),
    );
    let r = execute_tool(support::shared_run_context(), &edit_call);
    assert!(
        !r.is_error(),
        "replace_all multi-occurrence edit must succeed: {}",
        r.content()
    );
    assert!(
        r.content().contains("Replaced 3 occurrences"),
        "edit output should report every replacement: {}",
        r.content()
    );
    let disk = fs::read_to_string(&path).expect("read back");
    assert_eq!(disk, "qux bar qux baz qux\n");
}
mod support;

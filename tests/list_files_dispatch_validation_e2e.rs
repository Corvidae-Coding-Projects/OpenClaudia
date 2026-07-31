//! End-to-end tests for the `list_files` tool dispatched
//! through the registry — path resolution, traversal
//! rejection, dirs-before-files ordering (#953), and
//! happy-path enumeration.
//!
//! Sprint 153 of the verification effort. Sprint 16
//! covered direct `execute_list_files` calls; this file
//! pins the registry-dispatched path so the wire-facing
//! contract matches.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use serde_json::{json, Value};
use std::collections::HashMap;

fn dispatch_list(args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch("list_files", args, &mut ctx)
        .expect("list_files must be registered")
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Path default + arg shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_path_arg_defaults_to_cwd_dot() {
    // PINS DEFAULT: omitted path defaults to current dir and should not error.
    let (msg, is_err) = dispatch_list(&HashMap::new());
    assert!(!is_err, "default path . MUST succeed; got {msg:?}");
}

#[test]
fn path_arg_as_number_returns_validation_error() {
    let args = args_with(&[("path", json!(42))]);
    let (msg, is_err) = dispatch_list(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid 'path' argument: expected string"),
        "non-string path MUST be rejected; got {msg:?}"
    );
}

#[test]
fn path_arg_as_null_returns_validation_error() {
    let args = args_with(&[("path", Value::Null)]);
    let (msg, is_err) = dispatch_list(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid 'path' argument: expected string"),
        "null path MUST be rejected; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Path resolution rejection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn path_with_parent_dir_traversal_rejected() {
    let args = args_with(&[("path", json!("/tmp/../etc"))]);
    let (msg, is_err) = dispatch_list(&args);
    assert!(is_err, "traversal MUST be rejected");
    assert!(
        msg.contains("traversal") || msg.contains("Path"),
        "MUST surface traversal message; got {msg:?}"
    );
}

#[test]
fn nonexistent_path_errors_with_documented_message() {
    let args = args_with(&[("path", json!("definitely_nonexistent_xyz_marker_153"))]);
    let (msg, is_err) = dispatch_list(&args);
    assert!(is_err);
    assert!(
        msg.contains("Failed to list directory") || msg.contains("not found"),
        "MUST surface stat / not-found; got {msg:?}"
    );
    assert!(
        msg.contains("definitely_nonexistent_xyz_marker_153"),
        "MUST echo offending path; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Happy path enumeration
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lists_files_in_tempdir() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(dir.path().join("alpha.txt"), "").expect("write a");
    std::fs::write(dir.path().join("beta.rs"), "").expect("write b");
    std::fs::write(dir.path().join("gamma.md"), "").expect("write g");

    let args = args_with(&[("path", json!(dir.path().to_str().unwrap()))]);
    let (text, is_err) = dispatch_list(&args);
    assert!(!is_err);
    assert!(text.contains("alpha.txt"));
    assert!(text.contains("beta.rs"));
    assert!(text.contains("gamma.md"));
}

#[test]
fn lists_empty_dir_returns_empty_output_not_error() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let args = args_with(&[("path", json!(dir.path().to_str().unwrap()))]);
    let (text, is_err) = dispatch_list(&args);
    assert!(!is_err);
    assert!(
        text.is_empty() || text.trim().is_empty(),
        "empty dir MUST yield empty output; got {text:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Dir-vs-file marker + ordering (#953)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn directories_marked_with_trailing_slash() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::create_dir(dir.path().join("subdir")).expect("mkdir");
    std::fs::write(dir.path().join("file.txt"), "").expect("write");

    let args = args_with(&[("path", json!(dir.path().to_str().unwrap()))]);
    let (text, _is_err) = dispatch_list(&args);
    assert!(
        text.contains("subdir/"),
        "directory MUST be marked with trailing /; got {text:?}"
    );
    assert!(
        text.contains("file.txt") && !text.contains("file.txt/"),
        "file MUST NOT have trailing /; got {text:?}"
    );
}

#[test]
fn dirs_appear_before_files_in_output() {
    // PINS #953: dirs-before-files alphabetical layout.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    // Use names that would mix if simple alphabetical.
    std::fs::write(dir.path().join("a_file.txt"), "").expect("write");
    std::fs::create_dir(dir.path().join("z_dir")).expect("mkdir");
    std::fs::write(dir.path().join("m_file.txt"), "").expect("write");
    std::fs::create_dir(dir.path().join("b_dir")).expect("mkdir");

    let args = args_with(&[("path", json!(dir.path().to_str().unwrap()))]);
    let (text, _is_err) = dispatch_list(&args);

    // Both dirs MUST appear before any file in the output.
    let z_dir_pos = text.find("z_dir/").expect("z_dir/ present");
    let b_dir_pos = text.find("b_dir/").expect("b_dir/ present");
    let a_file_pos = text.find("a_file.txt").expect("a_file present");
    let m_file_pos = text.find("m_file.txt").expect("m_file present");

    assert!(
        z_dir_pos < a_file_pos,
        "z_dir/ MUST appear before a_file.txt (dirs first); got positions z_dir={z_dir_pos} a_file={a_file_pos}"
    );
    assert!(
        b_dir_pos < m_file_pos,
        "b_dir/ MUST appear before m_file.txt; got positions"
    );
    // Within dirs: alphabetical b_dir before z_dir.
    assert!(b_dir_pos < z_dir_pos, "dirs alphabetical");
    // Within files: alphabetical a_file before m_file.
    assert!(a_file_pos < m_file_pos, "files alphabetical");
}

#[test]
fn nested_dirs_listed_at_only_top_level() {
    // list_files is non-recursive.
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::create_dir(dir.path().join("outer")).expect("mkdir outer");
    std::fs::write(dir.path().join("outer/inner.txt"), "").expect("write inner");

    let args = args_with(&[("path", json!(dir.path().to_str().unwrap()))]);
    let (text, _is_err) = dispatch_list(&args);
    assert!(text.contains("outer/"));
    // Nested inner.txt MUST NOT appear at top level.
    assert!(
        !text.contains("inner.txt"),
        "list_files MUST be non-recursive; got {text:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Unicode filenames
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unicode_filename_listed_byte_exact() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    std::fs::write(dir.path().join("日本語.txt"), "").expect("write unicode");
    std::fs::create_dir(dir.path().join("フォルダ")).expect("mkdir unicode");

    let args = args_with(&[("path", json!(dir.path().to_str().unwrap()))]);
    let (text, _is_err) = dispatch_list(&args);
    assert!(text.contains("日本語.txt"));
    assert!(text.contains("フォルダ/"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Registration + forward-compat
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn list_files_registered_in_registry() {
    assert!(registry().get("list_files").is_some());
}

#[test]
fn list_files_never_panics_on_arbitrary_extra_args() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let args = args_with(&[
        ("path", json!(dir.path().to_str().unwrap())),
        ("extra", json!({"k": "v"})),
        ("nested", json!([1, 2, 3])),
        ("recursive", json!(true)),
    ]);
    let (_text, _is_err) = dispatch_list(&args);
}

#[test]
fn list_files_path_to_regular_file_errors_cleanly() {
    let dir = tempfile::TempDir::new_in(".").expect("tempdir");
    let f = dir.path().join("just_a_file.txt");
    std::fs::write(&f, "body").expect("write");

    let args = args_with(&[("path", json!(f.to_str().unwrap()))]);
    let (msg, is_err) = dispatch_list(&args);
    assert!(is_err, "list on a file (not dir) MUST error");
    assert!(
        msg.contains("Failed to list directory") || msg.contains("Not a directory"),
        "MUST surface not-a-directory error; got {msg:?}"
    );
}

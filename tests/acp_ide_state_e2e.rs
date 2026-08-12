//! End-to-end tests for `acp::IdeState`, `IdeSelection`, and
//! `IdeDiagnostic` serde round-trips + default shapes.
//!
//! Sprint 89 of the verification effort. The ACP module's
//! `AcpServer` body is private (handlers are not exported);
//! the data types `IdeState` / `IdeSelection` / `IdeDiagnostic`
//! ARE exported because they cross the JSON-RPC boundary and
//! must match the Claude Code editor-plugin schema byte-for-byte.
//! This file pins that wire-shape contract.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::acp::{IdeDiagnostic, IdeSelection, IdeState};
use serde_json::json;
use std::collections::HashMap;

// ───────────────────────────────────────────────────────────────────────────
// Section A — IdeState defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn ide_state_default_has_all_fields_empty_or_none() {
    let state = IdeState::default();
    assert!(state.active_file.is_none());
    assert!(state.recent_files.is_empty());
    assert!(state.selection.is_none());
    assert!(state.diagnostics.is_empty());
}

#[test]
fn ide_state_clone_preserves_all_fields() {
    let mut diagnostics = HashMap::new();
    diagnostics.insert(
        "/src/main.rs".to_string(),
        vec![IdeDiagnostic {
            line: 42,
            severity: "error".to_string(),
            message: "unused variable".to_string(),
            source: Some("rustc".to_string()),
        }],
    );
    let state = IdeState {
        active_file: Some("/src/main.rs".to_string()),
        recent_files: vec!["/a".to_string(), "/b".to_string()],
        selection: None,
        diagnostics,
    };
    let cloned = state.clone();
    assert_eq!(cloned.active_file, state.active_file);
    assert_eq!(cloned.recent_files, state.recent_files);
    assert_eq!(cloned.diagnostics.len(), state.diagnostics.len());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — IdeState serde round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn ide_state_empty_serializes_to_json_with_default_fields() {
    let state = IdeState::default();
    let json_str = serde_json::to_string(&state).expect("ser");
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("re-parse");
    assert!(parsed.is_object());
    // Required fields are all present even when empty.
    assert!(parsed.get("active_file").is_some());
    assert!(parsed.get("recent_files").is_some());
    assert!(parsed.get("selection").is_some());
    assert!(parsed.get("diagnostics").is_some());
}

#[test]
fn ide_state_full_shape_round_trips() {
    let mut state = IdeState {
        active_file: Some("/src/lib.rs".to_string()),
        recent_files: vec!["/src/lib.rs".to_string(), "/src/main.rs".to_string()],
        selection: Some(IdeSelection {
            file_path: "/src/lib.rs".to_string(),
            line_start: 100,
            line_count: 5,
            text: "selected text".to_string(),
        }),
        diagnostics: HashMap::new(),
    };
    state.diagnostics.insert(
        "/src/main.rs".to_string(),
        vec![IdeDiagnostic {
            line: 10,
            severity: "warning".to_string(),
            message: "unused import".to_string(),
            source: Some("rust-analyzer".to_string()),
        }],
    );

    let json_str = serde_json::to_string(&state).expect("ser");
    let back: IdeState = serde_json::from_str(&json_str).expect("de");
    assert_eq!(back.active_file.as_deref(), Some("/src/lib.rs"));
    assert_eq!(back.recent_files.len(), 2);
    let sel = back.selection.expect("selection MUST be present");
    assert_eq!(sel.file_path, "/src/lib.rs");
    assert_eq!(sel.line_start, 100);
    assert_eq!(sel.line_count, 5);
    assert_eq!(sel.text, "selected text");
    let diags = back.diagnostics.get("/src/main.rs").expect("present");
    assert_eq!(diags.len(), 1);
    assert_eq!(diags[0].message, "unused import");
}

#[test]
fn ide_state_deserialize_from_minimal_json_uses_defaults() {
    let state: IdeState = serde_json::from_str("{}").expect("missing fields use defaults");
    assert!(state.active_file.is_none());
    assert!(state.recent_files.is_empty());
    assert!(state.selection.is_none());
    assert!(state.diagnostics.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — IdeSelection serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn ide_selection_round_trips_with_byte_exact_fields() {
    let sel = IdeSelection {
        file_path: "/abs/path/to/file.rs".to_string(),
        line_start: 42,
        line_count: 3,
        text: "fn main() {\n    println!(\"hi\");\n}".to_string(),
    };
    let json_str = serde_json::to_string(&sel).expect("ser");
    let back: IdeSelection = serde_json::from_str(&json_str).expect("de");
    assert_eq!(back.file_path, sel.file_path);
    assert_eq!(back.line_start, sel.line_start);
    assert_eq!(back.line_count, sel.line_count);
    assert_eq!(back.text, sel.text);
}

#[test]
fn ide_selection_deserializes_from_documented_cc_schema() {
    // Documented CC schema matches these field names.
    let json_str = r#"{
        "file_path": "/proj/lib.rs",
        "line_start": 5,
        "line_count": 10,
        "text": "code"
    }"#;
    let sel: IdeSelection = serde_json::from_str(json_str).expect("de");
    assert_eq!(sel.file_path, "/proj/lib.rs");
    assert_eq!(sel.line_start, 5);
    assert_eq!(sel.line_count, 10);
}

#[test]
fn ide_selection_text_field_accepts_unicode_and_newlines() {
    let sel = IdeSelection {
        file_path: "/x".to_string(),
        line_start: 0,
        line_count: 1,
        text: "Hello\n日本語\nemoji 🎉\nCRLF\r\nend".to_string(),
    };
    let json_str = serde_json::to_string(&sel).expect("ser");
    let back: IdeSelection = serde_json::from_str(&json_str).expect("de");
    assert_eq!(back.text, sel.text);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — IdeDiagnostic serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn ide_diagnostic_round_trips_with_all_fields() {
    let diag = IdeDiagnostic {
        line: 100,
        severity: "error".to_string(),
        message: "type mismatch".to_string(),
        source: Some("rustc".to_string()),
    };
    let json_str = serde_json::to_string(&diag).expect("ser");
    let back: IdeDiagnostic = serde_json::from_str(&json_str).expect("de");
    assert_eq!(back.line, 100);
    assert_eq!(back.severity, "error");
    assert_eq!(back.message, "type mismatch");
    assert_eq!(back.source.as_deref(), Some("rustc"));
}

#[test]
fn ide_diagnostic_source_field_is_optional() {
    let diag = IdeDiagnostic {
        line: 5,
        severity: "warning".to_string(),
        message: "no source".to_string(),
        source: None,
    };
    let json_str = serde_json::to_string(&diag).expect("ser");
    // skip_serializing_if = "Option::is_none" should omit the
    // field on wire.
    assert!(
        !json_str.contains("\"source\""),
        "None source MUST be skipped; got {json_str:?}"
    );
}

#[test]
fn ide_diagnostic_deserializes_without_source_field() {
    let json_str = json!({
        "line": 1,
        "severity": "info",
        "message": "ok"
    })
    .to_string();
    let diag: IdeDiagnostic = serde_json::from_str(&json_str).expect("de");
    assert!(diag.source.is_none());
    assert_eq!(diag.line, 1);
    assert_eq!(diag.severity, "info");
}

#[test]
fn ide_diagnostic_severity_strings_documented_lsp_set() {
    // Documented severity values: error / warning / info / hint.
    for sev in &["error", "warning", "info", "hint"] {
        let diag = IdeDiagnostic {
            line: 0,
            severity: (*sev).to_string(),
            message: "x".to_string(),
            source: None,
        };
        let json_str = serde_json::to_string(&diag).expect("ser");
        let back: IdeDiagnostic = serde_json::from_str(&json_str).expect("de");
        assert_eq!(back.severity, *sev);
    }
}

#[test]
fn ide_diagnostic_line_is_0_indexed_per_lsp_convention() {
    // Line 0 represents the first line in LSP convention.
    // Test that the field accepts 0 (no validation).
    let diag = IdeDiagnostic {
        line: 0,
        severity: "error".to_string(),
        message: "first line".to_string(),
        source: None,
    };
    let json_str = serde_json::to_string(&diag).expect("ser");
    let back: IdeDiagnostic = serde_json::from_str(&json_str).expect("de");
    assert_eq!(back.line, 0);
}

#[test]
fn ide_diagnostic_clone_preserves_all_fields() {
    let original = IdeDiagnostic {
        line: 42,
        severity: "error".to_string(),
        message: "msg".to_string(),
        source: Some("clippy".to_string()),
    };
    let cloned = original.clone();
    assert_eq!(cloned.line, original.line);
    assert_eq!(cloned.severity, original.severity);
    assert_eq!(cloned.message, original.message);
    assert_eq!(cloned.source, original.source);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — IdeState diagnostics map keyed by file path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn diagnostics_map_separates_diagnostics_per_file() {
    let mut state = IdeState::default();
    state.diagnostics.insert(
        "/file/a.rs".to_string(),
        vec![IdeDiagnostic {
            line: 1,
            severity: "error".to_string(),
            message: "a-error".to_string(),
            source: None,
        }],
    );
    state.diagnostics.insert(
        "/file/b.rs".to_string(),
        vec![IdeDiagnostic {
            line: 5,
            severity: "warning".to_string(),
            message: "b-warning".to_string(),
            source: None,
        }],
    );
    let a_diags = state.diagnostics.get("/file/a.rs").unwrap();
    let b_diags = state.diagnostics.get("/file/b.rs").unwrap();
    assert_eq!(a_diags[0].message, "a-error");
    assert_eq!(b_diags[0].message, "b-warning");
    assert_eq!(state.diagnostics.len(), 2);
}

#[test]
fn diagnostics_map_supports_multi_diagnostic_per_file() {
    let mut state = IdeState::default();
    state.diagnostics.insert(
        "/file.rs".to_string(),
        vec![
            IdeDiagnostic {
                line: 1,
                severity: "error".to_string(),
                message: "first".to_string(),
                source: None,
            },
            IdeDiagnostic {
                line: 5,
                severity: "warning".to_string(),
                message: "second".to_string(),
                source: None,
            },
        ],
    );
    let diags = state.diagnostics.get("/file.rs").unwrap();
    assert_eq!(diags.len(), 2);
    assert_eq!(diags[0].line, 1);
    assert_eq!(diags[1].line, 5);
}

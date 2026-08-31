//! End-to-end tests for `tools::lsp` data types — `LspAction`
//! serde camelCase + `LspResult` / `LspLocation` / `LspSymbol`
//! shape + `LSP_MAX_FILE_SIZE` cap constant.
//!
//! Sprint 109 of the verification effort. Sprint 47 covered
//! the LSP `mark_opened`/`mark_closed` lifecycle plus
//! `is_lsp_connected`; this file pins the LSP data-type
//! wire-shape contract (camelCase serde for `LspAction`,
//! optional preview/hover semantics, hierarchical
//! `LspSymbol`).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::lsp::{LspAction, LspLocation, LspResult, LspSymbol, LSP_MAX_FILE_SIZE};

// ───────────────────────────────────────────────────────────────────────────
// Section A — LSP_MAX_FILE_SIZE
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_max_file_size_constant_is_10_mib() {
    assert_eq!(LSP_MAX_FILE_SIZE, 10 * 1024 * 1024);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — LspAction serde camelCase
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_action_go_to_definition_serializes_as_camel_case() {
    let json = serde_json::to_string(&LspAction::GoToDefinition).expect("ser");
    assert_eq!(json, "\"goToDefinition\"");
}

#[test]
fn lsp_action_find_references_serializes_as_camel_case() {
    let json = serde_json::to_string(&LspAction::FindReferences).expect("ser");
    assert_eq!(json, "\"findReferences\"");
}

#[test]
fn lsp_action_hover_serializes_as_lowercase() {
    let json = serde_json::to_string(&LspAction::Hover).expect("ser");
    assert_eq!(json, "\"hover\"");
}

#[test]
fn lsp_action_document_symbols_serializes_as_camel_case() {
    let json = serde_json::to_string(&LspAction::DocumentSymbols).expect("ser");
    assert_eq!(json, "\"documentSymbols\"");
}

#[test]
fn lsp_action_workspace_symbol_serializes_as_camel_case() {
    let json = serde_json::to_string(&LspAction::WorkspaceSymbol).expect("ser");
    assert_eq!(json, "\"workspaceSymbol\"");
}

#[test]
fn lsp_action_go_to_implementation_serializes_as_camel_case() {
    let json = serde_json::to_string(&LspAction::GoToImplementation).expect("ser");
    assert_eq!(json, "\"goToImplementation\"");
}

#[test]
fn lsp_action_call_hierarchy_variants_serialize_as_camel_case() {
    let prepare = serde_json::to_string(&LspAction::PrepareCallHierarchy).expect("ser");
    let incoming = serde_json::to_string(&LspAction::IncomingCalls).expect("ser");
    let outgoing = serde_json::to_string(&LspAction::OutgoingCalls).expect("ser");
    assert_eq!(prepare, "\"prepareCallHierarchy\"");
    assert_eq!(incoming, "\"incomingCalls\"");
    assert_eq!(outgoing, "\"outgoingCalls\"");
}

#[test]
fn lsp_action_deserializes_from_camel_case_strings() {
    let cases = [
        ("\"goToDefinition\"", LspAction::GoToDefinition),
        ("\"findReferences\"", LspAction::FindReferences),
        ("\"hover\"", LspAction::Hover),
        ("\"documentSymbols\"", LspAction::DocumentSymbols),
        ("\"workspaceSymbol\"", LspAction::WorkspaceSymbol),
        ("\"goToImplementation\"", LspAction::GoToImplementation),
        ("\"prepareCallHierarchy\"", LspAction::PrepareCallHierarchy),
        ("\"incomingCalls\"", LspAction::IncomingCalls),
        ("\"outgoingCalls\"", LspAction::OutgoingCalls),
    ];
    for (input, expected) in cases {
        let parsed: LspAction = serde_json::from_str(input).expect("de");
        assert_eq!(parsed, expected, "input {input:?} MUST deserialize");
    }
}

#[test]
fn lsp_action_rejects_snake_case_or_unknown_strings() {
    // snake_case is NOT the documented format.
    assert!(serde_json::from_str::<LspAction>("\"go_to_definition\"").is_err());
    assert!(serde_json::from_str::<LspAction>("\"unknown_action\"").is_err());
    assert!(serde_json::from_str::<LspAction>("\"\"").is_err());
}

#[test]
fn lsp_action_round_trips_through_serde() {
    let variants = [
        LspAction::GoToDefinition,
        LspAction::FindReferences,
        LspAction::Hover,
        LspAction::DocumentSymbols,
        LspAction::WorkspaceSymbol,
        LspAction::GoToImplementation,
        LspAction::PrepareCallHierarchy,
        LspAction::IncomingCalls,
        LspAction::OutgoingCalls,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).expect("ser");
        let back: LspAction = serde_json::from_str(&json).expect("de");
        assert_eq!(back, *v);
    }
}

#[test]
fn lsp_action_is_copy_and_eq() {
    let a = LspAction::Hover;
    let copy = a;
    let again = a;
    assert_eq!(copy, again);
    assert_eq!(a, LspAction::Hover);
    assert_ne!(a, LspAction::GoToDefinition);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — LspLocation shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_location_required_fields_round_trip() {
    let original = LspLocation {
        resource_id: "src/lib.rs".to_string(),
        uri: "file:///src/lib.rs".to_string(),
        line: 42,
        character: 12,
        end_line: None,
        end_character: None,
        preview: None,
    };
    let json = serde_json::to_string(&original).expect("ser");
    let back: LspLocation = serde_json::from_str(&json).expect("de");
    assert_eq!(back.uri, original.uri);
    assert_eq!(back.line, 42);
    assert_eq!(back.character, 12);
}

#[test]
fn lsp_location_with_range_end_fields_round_trip() {
    let original = LspLocation {
        resource_id: "src/main.rs".to_string(),
        uri: "file:///src/main.rs".to_string(),
        line: 10,
        character: 0,
        end_line: Some(20),
        end_character: Some(15),
        preview: Some("fn main() {}".to_string()),
    };
    let json = serde_json::to_string(&original).expect("ser");
    let back: LspLocation = serde_json::from_str(&json).expect("de");
    assert_eq!(back.end_line, Some(20));
    assert_eq!(back.end_character, Some(15));
    assert_eq!(back.preview.as_deref(), Some("fn main() {}"));
}

#[test]
fn lsp_location_clone_preserves_all_fields() {
    let original = LspLocation {
        resource_id: "x".to_string(),
        uri: "file:///x".to_string(),
        line: 1,
        character: 2,
        end_line: Some(3),
        end_character: Some(4),
        preview: Some("body".to_string()),
    };
    let cloned = original.clone();
    assert_eq!(cloned.uri, original.uri);
    assert_eq!(cloned.line, original.line);
    assert_eq!(cloned.end_line, original.end_line);
    assert_eq!(cloned.preview, original.preview);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — LspSymbol shape (recursive children)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_symbol_with_no_children_round_trips() {
    let original = LspSymbol {
        name: "Foo".to_string(),
        kind: "struct".to_string(),
        uri: None,
        resource_id: None,
        container_name: None,
        line: 10,
        character: None,
        end_line: Some(30),
        end_character: None,
        children: Vec::new(),
    };
    let json = serde_json::to_string(&original).expect("ser");
    let back: LspSymbol = serde_json::from_str(&json).expect("de");
    assert_eq!(back.name, "Foo");
    assert_eq!(back.kind, "struct");
    assert!(back.children.is_empty());
}

#[test]
fn lsp_symbol_with_nested_children_round_trips() {
    // PINS RECURSIVE: LspSymbol::children: Vec<Self>.
    let child_method = LspSymbol {
        name: "method_a".to_string(),
        kind: "method".to_string(),
        uri: None,
        resource_id: None,
        container_name: None,
        line: 12,
        character: None,
        end_line: Some(14),
        end_character: None,
        children: Vec::new(),
    };
    let parent_struct = LspSymbol {
        name: "Foo".to_string(),
        kind: "struct".to_string(),
        uri: None,
        resource_id: None,
        container_name: None,
        line: 10,
        character: None,
        end_line: Some(40),
        end_character: None,
        children: vec![child_method],
    };
    let json = serde_json::to_string(&parent_struct).expect("ser");
    let back: LspSymbol = serde_json::from_str(&json).expect("de");
    assert_eq!(back.name, "Foo");
    assert_eq!(back.children.len(), 1);
    assert_eq!(back.children[0].name, "method_a");
    assert_eq!(back.children[0].kind, "method");
}

#[test]
fn lsp_symbol_clone_preserves_recursive_tree() {
    let symbol = LspSymbol {
        name: "X".to_string(),
        kind: "class".to_string(),
        uri: None,
        resource_id: None,
        container_name: None,
        line: 1,
        character: None,
        end_line: Some(10),
        end_character: None,
        children: vec![LspSymbol {
            name: "y".to_string(),
            kind: "method".to_string(),
            uri: None,
            resource_id: None,
            container_name: None,
            line: 5,
            character: None,
            end_line: None,
            end_character: None,
            children: Vec::new(),
        }],
    };
    let cloned = symbol;
    assert_eq!(cloned.children.len(), 1);
    assert_eq!(cloned.children[0].name, "y");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — LspResult shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn lsp_result_full_shape_round_trips() {
    let original = LspResult {
        action: "goToDefinition".to_string(),
        file_path: "/src/lib.rs".to_string(),
        results: vec![LspLocation {
            resource_id: "src/lib.rs".to_string(),
            uri: "file:///src/lib.rs".to_string(),
            line: 100,
            character: 5,
            end_line: None,
            end_character: None,
            preview: None,
        }],
        hover_text: None,
        symbols: Vec::new(),
        provenance: None,
        call_hierarchy_items: Vec::new(),
        diagnostics: Vec::new(),
        partial_reasons: Vec::new(),
        content_authority: "untrusted_language_server_output".to_string(),
    };
    let json = serde_json::to_string(&original).expect("ser");
    let back: LspResult = serde_json::from_str(&json).expect("de");
    assert_eq!(back.action, "goToDefinition");
    assert_eq!(back.file_path, "/src/lib.rs");
    assert_eq!(back.results.len(), 1);
    assert_eq!(back.results[0].line, 100);
}

#[test]
fn lsp_result_hover_action_carries_hover_text_field() {
    let original = LspResult {
        action: "hover".to_string(),
        file_path: "/x".to_string(),
        results: Vec::new(),
        hover_text: Some("fn name() -> Result<()>".to_string()),
        symbols: Vec::new(),
        provenance: None,
        call_hierarchy_items: Vec::new(),
        diagnostics: Vec::new(),
        partial_reasons: Vec::new(),
        content_authority: "untrusted_language_server_output".to_string(),
    };
    let json = serde_json::to_string(&original).expect("ser");
    let back: LspResult = serde_json::from_str(&json).expect("de");
    assert_eq!(back.hover_text.as_deref(), Some("fn name() -> Result<()>"));
}

#[test]
fn lsp_result_document_symbols_action_carries_symbols_field() {
    let original = LspResult {
        action: "documentSymbols".to_string(),
        file_path: "/x".to_string(),
        results: Vec::new(),
        hover_text: None,
        symbols: vec![LspSymbol {
            name: "Top".to_string(),
            kind: "struct".to_string(),
            uri: None,
            resource_id: None,
            container_name: None,
            line: 0,
            character: None,
            end_line: Some(10),
            end_character: None,
            children: Vec::new(),
        }],
        provenance: None,
        call_hierarchy_items: Vec::new(),
        diagnostics: Vec::new(),
        partial_reasons: Vec::new(),
        content_authority: "untrusted_language_server_output".to_string(),
    };
    let json = serde_json::to_string(&original).expect("ser");
    let back: LspResult = serde_json::from_str(&json).expect("de");
    assert_eq!(back.symbols.len(), 1);
    assert_eq!(back.symbols[0].name, "Top");
}

#[test]
fn lsp_result_clone_preserves_all_fields() {
    let original = LspResult {
        action: "findReferences".to_string(),
        file_path: "/x".to_string(),
        results: Vec::new(),
        hover_text: Some("text".to_string()),
        symbols: Vec::new(),
        provenance: None,
        call_hierarchy_items: Vec::new(),
        diagnostics: Vec::new(),
        partial_reasons: Vec::new(),
        content_authority: "untrusted_language_server_output".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(cloned.action, original.action);
    assert_eq!(cloned.hover_text, original.hover_text);
}

#[test]
fn lsp_result_serialized_shape_marks_untrusted_server_content() {
    let result = LspResult {
        action: "x".to_string(),
        file_path: "x".to_string(),
        results: Vec::new(),
        hover_text: None,
        symbols: Vec::new(),
        provenance: None,
        call_hierarchy_items: Vec::new(),
        diagnostics: Vec::new(),
        partial_reasons: Vec::new(),
        content_authority: "untrusted_language_server_output".to_string(),
    };
    let json: serde_json::Value = serde_json::to_value(&result).expect("ser");
    let obj = json.as_object().expect("obj");
    // PINS SHAPE: stable result fields plus explicit server-content authority.
    assert_eq!(obj.len(), 6);
    for field in &[
        "action",
        "file_path",
        "results",
        "hover_text",
        "symbols",
        "content_authority",
    ] {
        assert!(obj.contains_key(*field), "MUST contain field {field:?}");
    }
}

#[test]
fn pre_s069_result_shape_deserializes_with_safe_metadata_defaults() {
    let result: LspResult = serde_json::from_value(serde_json::json!({
        "action": "goToDefinition",
        "file_path": "src/lib.rs",
        "results": [{
            "uri": "file:///src/lib.rs",
            "line": 1,
            "character": 1,
            "end_line": null,
            "end_character": null,
            "preview": null
        }],
        "hover_text": null,
        "symbols": []
    }))
    .expect("legacy serialized result remains readable");
    assert_eq!(result.content_authority, "untrusted_language_server_output");
    assert!(result.results[0].resource_id.is_empty());
    assert!(result.diagnostics.is_empty());
    assert!(result.partial_reasons.is_empty());
}

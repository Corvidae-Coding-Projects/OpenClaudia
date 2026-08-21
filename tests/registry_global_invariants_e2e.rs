//! End-to-end tests for `tools::registry::registry()` —
//! global invariants across the full HANDLERS table:
//! every registered handler has a matching name, every
//! definition is well-formed, every handler carries a mandatory effect
//! declaration, and the registry has the documented tool count.
//!
//! Sprint 160 of the verification effort. Sprint 23 / 132
//! covered the registry dispatch shape; this file pins
//! the cross-handler invariants — the kind of test that
//! would catch a new tool added without a `name()`
//! override or with a colliding registration.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{
    effect::{ToolEffect, ToolTarget},
    get_tool_definitions,
    registry::registry,
    ToolResource,
};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

/// Documented core tool catalog.
/// Lock-step: adding a tool here is paired with an entry in
/// HANDLERS in src/tools/registry.rs.
fn documented_tool_names() -> Vec<&'static str> {
    let mut names = vec![
        "bash",
        "bash_output",
        "kill_shell",
        "kill_shells_for_agent",
        "read_file",
        "grounding_context",
        "write_file",
        "edit_file",
        "list_files",
        "glob",
        "grep",
        "crosslink",
        "memory_save",
        "memory_search",
        "memory_list",
        "memory_update",
        "memory_delete",
        "memory_review",
        "memory_export",
        "memory_import",
        "memory_source_status",
        "memory_source_refresh",
        "web_fetch",
        "web_search",
        "web_browser",
        "todo_write",
        "todo_read",
        "notebook_edit",
        "task_create",
        "ask_user_question",
        "task_update",
        "task_get",
        "task_list",
        "enter_plan_mode",
        "exit_plan_mode",
        "list_mcp_resources",
        "read_mcp_resource",
        "lsp",
        "enter_worktree",
        "exit_worktree",
        "list_worktrees",
        "cron_create",
        "cron_delete",
        "cron_list",
        "skill",
        "tool_search",
    ];

    if !cfg!(feature = "browser") {
        names.retain(|name| *name != "web_search");
        names.retain(|name| *name != "web_browser");
    }

    names
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Registry size + completeness
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn registry_contains_all_documented_tool_names() {
    let reg = registry();
    for name in documented_tool_names() {
        assert!(
            reg.get(name).is_some(),
            "registry MUST contain documented tool {name:?}"
        );
    }
}

#[test]
fn documented_tool_names_match_emitted_tool_definitions() {
    let documented: BTreeSet<_> = documented_tool_names().into_iter().collect();
    let emitted: BTreeSet<String> = get_tool_definitions()
        .as_array()
        .expect("tool definitions array")
        .iter()
        .map(|def| {
            def.pointer("/function/name")
                .and_then(Value::as_str)
                .expect("tool definition name")
                .to_string()
        })
        .collect();
    let emitted_refs: BTreeSet<_> = emitted.iter().map(String::as_str).collect();

    assert_eq!(
        documented, emitted_refs,
        "documented tool names must exactly match get_tool_definitions()"
    );
}

#[test]
fn registry_documented_tool_count_is_current() {
    // PINS CATALOG SIZE: 46 with the browser feature, 44 without it.
    // Adding a tool: append a line to HANDLERS and bump this number.
    let expected = if cfg!(feature = "browser") { 46 } else { 44 };
    assert_eq!(
        documented_tool_names().len(),
        expected,
        "DOCUMENTED_TOOL_NAMES MUST match HANDLERS catalog"
    );
}

#[test]
fn every_documented_name_is_unique_in_list() {
    let mut sorted = documented_tool_names();
    let n = sorted.len();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        n,
        "DOCUMENTED_TOOL_NAMES MUST have no duplicates"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Per-handler invariants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_handler_name_matches_its_definition_function_name() {
    let reg = registry();
    for name in documented_tool_names() {
        let handler = reg.get(name).expect(name);
        // handler.name() and definition()["function"]["name"]
        // MUST agree (otherwise the model sees a different
        // name than the dispatch table accepts).
        let def = handler.definition();
        let def_name = def["function"]["name"].as_str().expect("string");
        assert_eq!(
            def_name,
            handler.name(),
            "handler.name() {:?} MUST match definition.function.name {def_name:?}",
            handler.name()
        );
    }
}

#[test]
fn every_handler_definition_is_a_function_envelope() {
    let reg = registry();
    for name in documented_tool_names() {
        let handler = reg.get(name).expect(name);
        let def = handler.definition();
        assert_eq!(def["type"], "function", "{name} MUST be type=function");
        assert!(
            def["function"].is_object(),
            "{name} MUST have function object"
        );
        assert!(
            def["function"]["description"].is_string(),
            "{name} MUST have description"
        );
        assert!(
            def["function"]["parameters"].is_object(),
            "{name} MUST have parameters"
        );
    }
}

#[test]
fn every_handler_parameters_type_is_object() {
    let reg = registry();
    for name in documented_tool_names() {
        let handler = reg.get(name).expect(name);
        let def = handler.definition();
        assert_eq!(
            def["function"]["parameters"]["type"], "object",
            "{name} parameters.type MUST be object"
        );
    }
}

#[test]
fn every_handler_required_fields_are_in_properties() {
    let reg = registry();
    for name in documented_tool_names() {
        let handler = reg.get(name).expect(name);
        let def = handler.definition();
        let Some(required) = def["function"]["parameters"]["required"].as_array() else {
            continue; // no required fields — skip.
        };
        let Some(properties) = def["function"]["parameters"]["properties"].as_object() else {
            continue;
        };
        for req in required {
            let req_str = req.as_str().expect("required is string");
            assert!(
                properties.contains_key(req_str),
                "{name} required field {req_str:?} MUST appear in properties"
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Permission-target invariants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_documented_tool_declares_an_effect() {
    // S-016 replaces the old "exactly 5 handlers declare permission_target"
    // pin. That number WAS the defect (F-001): the other twenty-eight
    // handlers inherited "read-only / safe" from a trait default. The
    // declaration is now mandatory at compile time, so what remains to pin is
    // that each declaration is usable by the rule engine.
    let reg = registry();
    for name in documented_tool_names() {
        let handler = reg
            .get(name)
            .unwrap_or_else(|| panic!("{name} must be registered"));
        handler
            .effect_spec()
            .validate(name)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn effectful_tools_outnumber_the_five_that_used_to_be_gated() {
    // Guards the specific regression shape: if a future change reintroduced a
    // permissive default, the set of tools requiring authorization would
    // collapse back toward the original five.
    let reg = registry();
    let gated: Vec<&str> = documented_tool_names()
        .into_iter()
        .filter(|name| {
            reg.get(name)
                .expect("registered")
                .effect_spec()
                .effect
                .requires_authorization()
        })
        .collect();
    assert!(
        gated.len() > 5,
        "only {} tools require authorization ({gated:?}); F-001 was filed because that set \
         was five while twenty-eight mutating tools sat outside it",
        gated.len()
    );
    for expected in [
        "bash",
        "edit_file",
        "write_file",
        "notebook_edit",
        "web_fetch",
    ] {
        assert!(gated.contains(&expected), "{expected} must still be gated");
    }
}

#[test]
fn bash_effect_is_destructive_on_the_command_argument() {
    let reg = registry();
    let spec = reg.get("bash").expect("bash").effect_spec();
    assert_eq!(spec.canonical, "Bash");
    assert_eq!(spec.effect, ToolEffect::Destructive);
    assert_eq!(spec.target, ToolTarget::Arg("command"));
}

#[test]
fn write_file_effect_is_workspace_mutation_on_path() {
    let reg = registry();
    let spec = reg.get("write_file").expect("write_file").effect_spec();
    assert_eq!(spec.canonical, "Write");
    assert_eq!(spec.effect, ToolEffect::WorkspaceMutation);
    assert_eq!(spec.target, ToolTarget::Arg("path"));
}

#[test]
fn edit_file_effect_is_workspace_mutation_on_path() {
    let reg = registry();
    let spec = reg.get("edit_file").expect("edit_file").effect_spec();
    assert_eq!(spec.canonical, "Edit");
    assert_eq!(spec.effect, ToolEffect::WorkspaceMutation);
    assert_eq!(spec.target, ToolTarget::Arg("path"));
}

#[test]
fn notebook_edit_effect_uses_notebook_path_arg_key() {
    // notebook_edit shares the Edit capability (notebook edits ARE file
    // edits) but keys on `notebook_path`, not `path`.
    let reg = registry();
    let spec = reg
        .get("notebook_edit")
        .expect("notebook_edit")
        .effect_spec();
    assert!(
        spec.canonical == "Edit" || spec.canonical == "Write",
        "MUST canonicalize to Edit or Write; got {:?}",
        spec.canonical
    );
    assert_eq!(spec.effect, ToolEffect::WorkspaceMutation);
    assert_eq!(
        spec.target,
        ToolTarget::Arg("notebook_path"),
        "PINS DOC: notebook_edit uses notebook_path key not path"
    );
}

#[test]
fn technical_memory_source_tools_declare_exact_effects_and_resources() {
    let reg = registry();
    let status = reg
        .get("memory_source_status")
        .expect("memory source status");
    let status_spec = status.effect_spec();
    assert_eq!(status_spec.canonical, "MemorySourceRead");
    assert_eq!(status_spec.effect, ToolEffect::ReadOnly);
    assert_eq!(status_spec.target, ToolTarget::ToolScope);
    assert_eq!(
        status.required_resources(&HashMap::new()),
        [ToolResource::WorkspaceRead, ToolResource::Memory]
    );

    let refresh = reg
        .get("memory_source_refresh")
        .expect("memory source refresh");
    let refresh_spec = refresh.effect_spec();
    assert_eq!(refresh_spec.canonical, "MemorySourceRefresh");
    assert_eq!(refresh_spec.effect, ToolEffect::ExternalMutation);
    assert_eq!(refresh_spec.target, ToolTarget::ToolScope);
    assert_eq!(
        refresh.required_resources(&HashMap::new()),
        [ToolResource::WorkspaceRead, ToolResource::Memory]
    );
}

#[test]
fn technical_memory_review_declares_exact_effect_and_resource() {
    let review = registry().get("memory_review").expect("memory review");
    let spec = review.effect_spec();
    assert_eq!(spec.canonical, "MemoryReview");
    assert_eq!(spec.effect, ToolEffect::ExternalMutation);
    assert_eq!(spec.target, ToolTarget::Arg("logical_id"));
    assert_eq!(
        review.required_resources(&HashMap::new()),
        [ToolResource::WorkspaceRead, ToolResource::Memory]
    );
}

#[test]
fn portable_memory_tools_declare_exact_effects_and_resources() {
    let export = registry().get("memory_export").expect("memory export");
    let export_spec = export.effect_spec();
    assert_eq!(export_spec.canonical, "MemoryExport");
    assert_eq!(export_spec.effect, ToolEffect::ExternalMutation);
    assert_eq!(export_spec.target, ToolTarget::Arg("destination_root"));
    assert_eq!(
        export.required_resources(&HashMap::new()),
        [
            ToolResource::WorkspaceRead,
            ToolResource::WorkspaceWrite,
            ToolResource::Memory,
        ]
    );

    let import = registry().get("memory_import").expect("memory import");
    let import_spec = import.effect_spec();
    assert_eq!(import_spec.canonical, "MemoryImport");
    assert_eq!(import_spec.effect, ToolEffect::ExternalMutation);
    assert_eq!(import_spec.target, ToolTarget::Arg("source_root"));
    assert_eq!(
        import.required_resources(&HashMap::new()),
        [ToolResource::WorkspaceRead, ToolResource::Memory]
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Registration invariants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_documented_tool_is_registered() {
    let reg = registry();
    for name in documented_tool_names() {
        assert!(reg.get(name).is_some(), "{name:?} MUST be registered");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Description sanity (no empty, reasonable bounds)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_handler_description_is_non_empty() {
    let reg = registry();
    for name in documented_tool_names() {
        let handler = reg.get(name).expect(name);
        let def = handler.definition();
        let desc = def["function"]["description"].as_str().expect("string");
        assert!(!desc.is_empty(), "{name} description MUST be non-empty");
    }
}

#[test]
fn no_handler_description_exceeds_2000_bytes() {
    // PINS COMPACTNESS: tool descriptions are inlined into the
    // model's prompt — over-long ones bloat context.
    let reg = registry();
    for name in documented_tool_names() {
        let handler = reg.get(name).expect(name);
        let def = handler.definition();
        let desc = def["function"]["description"].as_str().expect("string");
        assert!(
            desc.len() <= 2000,
            "{name} description MUST stay under 2000 bytes; got {}",
            desc.len()
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Schema name uniqueness across the catalog
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn no_two_handlers_share_the_same_definition_name() {
    let reg = registry();
    let mut seen: HashMap<String, &str> = HashMap::new();
    for name in documented_tool_names() {
        let handler = reg.get(name).expect(name);
        let def = handler.definition();
        let def_name = def["function"]["name"]
            .as_str()
            .expect("string")
            .to_string();
        if let Some(existing) = seen.insert(def_name.clone(), name) {
            panic!("duplicate function.name {def_name:?} shared by {existing:?} and {name:?}");
        }
    }
}

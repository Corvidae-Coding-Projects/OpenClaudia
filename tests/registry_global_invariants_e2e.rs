//! End-to-end tests for `tools::registry::registry()` —
//! global invariants across the full HANDLERS table:
//! every registered handler has a matching name, every
//! definition is well-formed, exactly 5 handlers declare
//! a `permission_target` (Bash/Edit/NotebookEdit/WebFetch/Write),
//! and the registry has the documented tool count.
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
    get_tool_definitions,
    registry::{registry, ToolContext},
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
    // PINS CATALOG SIZE: 36 with the browser feature, 34 without it.
    // Adding a tool: append a line to HANDLERS and bump this number.
    let expected = if cfg!(feature = "browser") { 36 } else { 34 };
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
fn exactly_5_handlers_declare_permission_target() {
    // AUTHORING DISCOVERY: 5 gated tools. notebook_edit also declares a
    // permission_target since it overwrites .ipynb on disk; web_fetch declares
    // a URL target so preapproved documentation hosts can bypass prompts while
    // arbitrary network reads still ask.
    // PINS the actual catalog: bash + edit_file + notebook_edit
    // + web_fetch + write_file. Adding a new gated tool: append here
    // AND in src/tools/registry.rs's permission_target impl.
    let reg = registry();
    let mut with_target: Vec<&str> = Vec::new();
    for name in documented_tool_names() {
        let handler = reg.get(name).expect(name);
        if handler.permission_target().is_some() {
            with_target.push(name);
        }
    }
    with_target.sort_unstable();
    assert_eq!(
        with_target,
        vec![
            "bash",
            "edit_file",
            "notebook_edit",
            "web_fetch",
            "write_file"
        ],
        "PINS PERMISSION TARGETS: exactly 5 gated tools"
    );
}

#[test]
fn bash_permission_target_canonical_is_bash() {
    let reg = registry();
    let handler = reg.get("bash").expect("bash");
    let target = handler.permission_target().expect("Some");
    assert_eq!(target.canonical, "Bash");
    assert_eq!(target.arg_key, "command");
}

#[test]
fn write_file_permission_target_canonical_is_write() {
    let reg = registry();
    let handler = reg.get("write_file").expect("write_file");
    let target = handler.permission_target().expect("Some");
    assert_eq!(target.canonical, "Write");
    assert_eq!(target.arg_key, "path");
}

#[test]
fn edit_file_permission_target_canonical_is_edit() {
    let reg = registry();
    let handler = reg.get("edit_file").expect("edit_file");
    let target = handler.permission_target().expect("Some");
    assert_eq!(target.canonical, "Edit");
    assert_eq!(target.arg_key, "path");
}

#[test]
fn notebook_edit_permission_target_uses_notebook_path_arg_key() {
    // AUTHORING DISCOVERY: notebook_edit also declares a
    // permission_target — its arg_key is "notebook_path",
    // not "path", because the notebook tool uses the
    // distinct notebook_path field name.
    let reg = registry();
    let handler = reg.get("notebook_edit").expect("notebook_edit");
    let target = handler.permission_target().expect("Some");
    // Canonical capability is documented to share with Edit
    // (notebook edits ARE file edits semantically).
    assert!(
        target.canonical == "Edit" || target.canonical == "Write",
        "MUST canonicalize to Edit or Write; got {:?}",
        target.canonical
    );
    assert_eq!(
        target.arg_key, "notebook_path",
        "PINS DOC: notebook_edit uses notebook_path key not path"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Dispatch invariants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_documented_tool_dispatches_to_some_result() {
    let reg = registry();
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    let empty_args: HashMap<String, Value> = HashMap::new();
    for name in documented_tool_names() {
        let outcome = reg.dispatch(name, &empty_args, &mut ctx);
        assert!(
            outcome.is_some(),
            "dispatch({name:?}) MUST return Some(...)"
        );
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

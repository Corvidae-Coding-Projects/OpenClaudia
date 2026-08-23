//! End-to-end tests for the tool-registry JSON schema emitted by
//! `get_tool_definitions()`. This is the exact JSON the model
//! sees on every chat-completion request, so schema invariants
//! are model-correctness contracts.
//!
//! Sprint 30 of the verification effort. The registry has
//! per-tool unit tests but no integration check that the
//! aggregate output is well-formed.
//!
//! Coverage shape:
//!
//!   - **Well-formed `OpenAI` tool shape** — every entry is an
//!     object with `type: "function"` and a `function` object
//!     containing `name`, `description`, `parameters`.
//!   - **No name collisions** — the set of tool names is
//!     pairwise distinct.
//!   - **`snake_case` naming** — every tool name matches
//!     `[a-z][a-z0-9_]*` (model-friendly identifier shape).
//!   - **Required fields are subsets of properties** — for
//!     every tool with `parameters.required`, every name in
//!     that list MUST exist in `parameters.properties`.
//!   - **Documented core tools present** — `bash`, `read_file`,
//!     `write_file`, `edit_file`, `glob`, `grep` all
//!     registered (regression guard against accidental
//!     removal).
//!   - **Deterministic dispatch** — `registry().get(name)`
//!     returns the same handler reference across calls
//!     (static singleton invariant).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::{
    session::PLAN_MODE_ALLOWED_TOOLS,
    tools::{get_tool_definitions, registry::registry, ToolHandler},
};
use serde_json::Value;

// ───────────────────────────────────────────────────────────────────────────
// Section A — aggregate shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_tool_definitions_returns_non_empty_array() {
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("definitions must be a JSON array");
    assert!(
        !arr.is_empty(),
        "tool registry MUST register at least one tool"
    );
}

#[test]
fn every_tool_entry_is_well_formed_function_object() {
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    let mut malformed = Vec::new();
    for (i, entry) in arr.iter().enumerate() {
        // Top-level: `type: "function"` + `function` object.
        if entry.get("type") != Some(&Value::String("function".to_string())) {
            malformed.push(format!("#{i}: missing or wrong `type` field"));
            continue;
        }
        let Some(func) = entry.get("function").and_then(Value::as_object) else {
            malformed.push(format!("#{i}: missing `function` object"));
            continue;
        };
        // function: name + description + parameters
        for field in &["name", "description", "parameters"] {
            if !func.contains_key(*field) {
                malformed.push(format!("#{i}: function missing field {field:?}"));
            }
        }
        if let Some(name) = func.get("name").and_then(Value::as_str) {
            if name.is_empty() {
                malformed.push(format!("#{i}: empty function name"));
            }
        }
    }
    assert!(
        malformed.is_empty(),
        "{} malformed tool entries:\n  {}",
        malformed.len(),
        malformed.join("\n  ")
    );
}

#[test]
fn tool_names_are_pairwise_distinct() {
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    let mut names: Vec<&str> = arr
        .iter()
        .filter_map(|e| e.pointer("/function/name").and_then(Value::as_str))
        .collect();
    let original_len = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        original_len,
        "tool names MUST be pairwise distinct; dedup removed {} entries",
        original_len - names.len()
    );
}

#[test]
fn every_tool_name_matches_snake_case_identifier_shape() {
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    let mut wrong = Vec::new();
    for entry in arr {
        let name = entry
            .pointer("/function/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        // Tool names must be `[a-z][a-z0-9_]*` — the shape every
        // provider (OpenAI, Anthropic, Google) accepts as a
        // function identifier.
        let valid = !name.is_empty()
            && name.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !valid {
            wrong.push(name.to_string());
        }
    }
    assert!(
        wrong.is_empty(),
        "{} tool names violate snake_case identifier shape:\n  {:?}",
        wrong.len(),
        wrong
    );
}

#[test]
fn required_fields_are_subsets_of_properties() {
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    let mut violations = Vec::new();
    for entry in arr {
        let name = entry
            .pointer("/function/name")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let Some(params) = entry.pointer("/function/parameters") else {
            continue;
        };
        let Some(required) = params.get("required").and_then(Value::as_array) else {
            continue; // no required list — vacuously fine
        };
        let Some(properties) = params.get("properties").and_then(Value::as_object) else {
            // required-without-properties is itself a bug class.
            violations.push(format!(
                "{name}: required list present but no properties object"
            ));
            continue;
        };
        for req in required {
            let Some(req_name) = req.as_str() else {
                violations.push(format!("{name}: required entry is not a string: {req:?}"));
                continue;
            };
            if !properties.contains_key(req_name) {
                violations.push(format!(
                    "{name}: required field {req_name:?} not in properties"
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "{} required-vs-properties violations:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

#[test]
fn no_tool_schema_uses_anthropic_rejected_top_level_combinators() {
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    let mut rejected = Vec::new();
    for entry in arr {
        let name = entry
            .pointer("/function/name")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let Some(params) = entry.pointer("/function/parameters") else {
            continue;
        };
        for keyword in ["oneOf", "allOf", "anyOf"] {
            if params.get(keyword).is_some() {
                rejected.push(format!("{name}: top-level {keyword}"));
            }
        }
    }
    assert!(
        rejected.is_empty(),
        "Anthropic rejects top-level oneOf/allOf/anyOf in tool input_schema; found:\n  {}",
        rejected.join("\n  ")
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — documented core tools present
// ───────────────────────────────────────────────────────────────────────────

/// Core tools that MUST always be registered. A regression that
/// un-registers any of these would silently strip a major model
/// capability — pinning the list by name surfaces which one.
const CORE_TOOLS: &[&str] = &[
    "bash",
    "bash_output",
    "kill_shell",
    "kill_shells_for_agent",
    "read_file",
    "grounding_context",
    "write_file",
    "edit_file",
    "notebook_edit",
    "list_files",
    "glob",
    "grep",
    "web_fetch",
    #[cfg(feature = "browser")]
    "web_search",
    "todo_write",
    "todo_read",
];

#[test]
fn documented_core_tools_all_registered() {
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    let names: Vec<&str> = arr
        .iter()
        .filter_map(|e| e.pointer("/function/name").and_then(Value::as_str))
        .collect();
    let mut missing = Vec::new();
    for tool in CORE_TOOLS {
        if !names.contains(tool) {
            missing.push(*tool);
        }
    }
    assert!(
        missing.is_empty(),
        "{} core tool(s) MISSING from registry: {:?}\n\
         Full registered set: {:?}",
        missing.len(),
        missing,
        names
    );
}

#[test]
fn bash_output_schema_allows_no_shell_id_list_mode() {
    let handler = registry().get("bash_output").expect("registered");
    let def = handler.definition();

    assert!(
        def.pointer("/function/parameters/required").is_none(),
        "bash_output must not require shell_id because omitted shell_id lists all background shells"
    );
    let shell_id_description = def
        .pointer("/function/parameters/properties/shell_id/description")
        .and_then(Value::as_str)
        .expect("shell_id description");
    assert!(
        shell_id_description.contains("Omit"),
        "bash_output shell_id description must document no-arg list mode; got {shell_id_description:?}"
    );
}

#[test]
fn bash_schema_advertises_the_enforced_foreground_timeout_contract() {
    let definition = registry()
        .get("bash")
        .expect("bash registered")
        .definition();
    let timeout = definition
        .pointer("/function/parameters/properties/timeout")
        .expect("bash timeout schema");

    assert_eq!(timeout["type"], "integer");
    assert_eq!(timeout["minimum"], 1);
    assert_eq!(timeout["maximum"], 600_000);
    let description = timeout["description"]
        .as_str()
        .expect("bash timeout description");
    assert!(description.contains("default 300000"), "{description}");
    assert!(
        description.contains("Not valid with run_in_background"),
        "{description}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — registry handler dispatch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn registry_get_returns_same_handler_reference_across_calls() {
    // The registry is a process-global static; repeated lookups
    // for the same name MUST return the same pointer.
    let a = registry().get("bash").expect("bash registered");
    let b = registry().get("bash").expect("bash still registered");
    let a_ptr = std::ptr::from_ref::<dyn ToolHandler>(a);
    let b_ptr = std::ptr::from_ref::<dyn ToolHandler>(b);
    assert_eq!(
        a_ptr, b_ptr,
        "registry().get('bash') MUST return the same handler reference twice"
    );
}

#[test]
fn registry_get_returns_none_for_unknown_tool() {
    let outcome = registry().get("absolutely-not-a-real-tool-xyz-9999");
    assert!(
        outcome.is_none(),
        "registry().get(unknown) MUST return None; got handler with name={:?}",
        outcome.map(ToolHandler::name)
    );
}

#[test]
fn every_registered_handler_reports_a_non_empty_name() {
    // Each handler's `name()` method must match the registry
    // key it's stored under. We can't iterate from outside the
    // crate (iter_handlers is pub(crate)), so we drive via the
    // definitions array and ensure every advertised name
    // resolves back through registry().get(name) to a handler
    // whose name() matches.
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    for entry in arr {
        let advertised = entry
            .pointer("/function/name")
            .and_then(Value::as_str)
            .expect("advertised name");
        let handler = registry().get(advertised).unwrap_or_else(|| {
            panic!("advertised tool {advertised:?} not resolvable via registry().get()")
        });
        assert_eq!(
            handler.name(),
            advertised,
            "handler.name() must equal the advertised name; got {} vs {advertised}",
            handler.name()
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — parameters.type is "object"
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_tool_parameters_has_type_object() {
    // OpenAI/Anthropic function-calling schemas require
    // `parameters.type == "object"`. A regression that drops
    // this would silently break every provider's parser.
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    let mut wrong = Vec::new();
    for entry in arr {
        let name = entry
            .pointer("/function/name")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let type_field = entry.pointer("/function/parameters/type");
        if type_field != Some(&Value::String("object".to_string())) {
            wrong.push(format!(
                "{name}: parameters.type={type_field:?} (expected \"object\")"
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} tools have wrong parameters.type:\n  {}",
        wrong.len(),
        wrong.join("\n  ")
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — description content discipline
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_tool_description_is_non_trivial() {
    // A tool with an empty / one-word description starves the
    // model of context. Pin a minimum length so a future PR
    // that strips descriptions fails loudly.
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    let mut thin = Vec::new();
    for entry in arr {
        let name = entry
            .pointer("/function/name")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let desc = entry
            .pointer("/function/description")
            .and_then(Value::as_str)
            .unwrap_or("");
        if desc.trim().len() < 20 {
            thin.push(format!("{name}: description {desc:?} is <20 chars"));
        }
    }
    assert!(
        thin.is_empty(),
        "{} tools have thin (<20 char) descriptions:\n  {}",
        thin.len(),
        thin.join("\n  ")
    );
}

#[test]
fn enter_plan_mode_description_names_allowed_tool_surface() {
    let def = registry()
        .get("enter_plan_mode")
        .expect("enter_plan_mode registered")
        .definition();
    let desc = def
        .pointer("/function/description")
        .and_then(Value::as_str)
        .expect("enter_plan_mode description");

    for tool in PLAN_MODE_ALLOWED_TOOLS {
        assert!(
            desc.contains(tool),
            "enter_plan_mode description must mention plan-mode allowed tool {tool:?}; got {desc:?}"
        );
    }
    assert!(
        desc.contains("write_file may write only to the plan file"),
        "enter_plan_mode description must explain the write_file plan-file exception; got {desc:?}"
    );
}

#[test]
fn web_search_description_pins_free_browser_backends() {
    if cfg!(not(feature = "browser")) {
        assert!(
            registry().get("web_search").is_none(),
            "no-browser builds must not register web_search because the only supported backend is browser scraping"
        );
        return;
    }

    let def = registry()
        .get("web_search")
        .expect("web_search registered")
        .definition();
    let desc = def
        .pointer("/function/description")
        .and_then(Value::as_str)
        .expect("web_search description");
    let limit_schema = def
        .pointer("/function/parameters/properties/limit")
        .expect("web_search limit schema");

    assert!(
        desc.contains("free DuckDuckGo/Bing browser scraping"),
        "web_search must advertise the actual free browser-backed backend; got {desc:?}"
    );
    assert!(
        desc.contains("No search API key is required"),
        "web_search must not imply users need a paid search provider key; got {desc:?}"
    );
    for forbidden in [
        "Serper",
        "SERPER_API_KEY",
        "Brave",
        "BRAVE_API_KEY",
        "Tavily",
        "Jina",
    ] {
        assert!(
            !desc.contains(forbidden),
            "web_search description must not mention retired paid backend {forbidden}; got {desc:?}"
        );
    }
    assert_eq!(
        limit_schema.get("minimum").and_then(Value::as_u64),
        Some(1),
        "web_search schema must advertise the enforced minimum limit"
    );
    assert_eq!(
        limit_schema.get("maximum").and_then(Value::as_u64),
        Some(10),
        "web_search schema must advertise the enforced maximum limit"
    );
}

#[test]
fn lsp_position_schema_advertises_indexing_bounds() {
    let def = registry().get("lsp").expect("lsp registered").definition();
    let line_schema = def
        .pointer("/function/parameters/properties/line")
        .expect("lsp line schema");
    let character_schema = def
        .pointer("/function/parameters/properties/character")
        .expect("lsp character schema");

    assert_eq!(
        line_schema.get("minimum").and_then(Value::as_u64),
        Some(1),
        "lsp line schema must advertise the enforced 1-indexed lower bound"
    );
    assert_eq!(
        character_schema.get("minimum").and_then(Value::as_u64),
        Some(0),
        "lsp character schema must advertise the enforced zero-indexed lower bound"
    );
}

#[test]
fn read_file_window_schema_advertises_positive_bounds() {
    let def = registry()
        .get("read_file")
        .expect("read_file registered")
        .definition();
    let offset_schema = def
        .pointer("/function/parameters/properties/offset")
        .expect("read_file offset schema");
    let limit_schema = def
        .pointer("/function/parameters/properties/limit")
        .expect("read_file limit schema");

    assert_eq!(
        offset_schema.get("minimum").and_then(Value::as_u64),
        Some(1),
        "read_file offset schema must advertise the enforced 1-indexed lower bound"
    );
    assert_eq!(
        limit_schema.get("minimum").and_then(Value::as_u64),
        Some(1),
        "read_file limit schema must advertise the enforced positive lower bound"
    );
}

#[test]
fn grep_context_schema_advertises_non_negative_bound() {
    let def = registry()
        .get("grep")
        .expect("grep registered")
        .definition();
    let context_schema = def
        .pointer("/function/parameters/properties/context_lines")
        .expect("grep context_lines schema");

    assert_eq!(
        context_schema.get("minimum").and_then(Value::as_u64),
        Some(0),
        "grep context_lines schema must advertise the enforced non-negative lower bound"
    );
}

#[test]
fn boolean_tool_flag_schemas_match_runtime_validation() {
    for (tool_name, flag_name) in [
        ("bash", "run_in_background"),
        ("edit_file", "replace_all"),
        ("grep", "case_insensitive"),
        ("exit_worktree", "apply_changes"),
        ("exit_worktree", "discard_changes"),
        ("cron_create", "recurring"),
        ("cron_create", "durable"),
    ] {
        let def = registry()
            .get(tool_name)
            .unwrap_or_else(|| panic!("{tool_name} registered"))
            .definition();
        let pointer = format!("/function/parameters/properties/{flag_name}/type");
        assert_eq!(
            def.pointer(&pointer).and_then(Value::as_str),
            Some("boolean"),
            "{tool_name}.{flag_name} must advertise boolean input"
        );
    }
}

#[test]
fn tool_search_max_results_schema_advertises_bounds() {
    let def = registry()
        .get("tool_search")
        .expect("tool_search registered")
        .definition();
    let max_results_schema = def
        .pointer("/function/parameters/properties/max_results")
        .expect("tool_search max_results schema");

    assert_eq!(
        max_results_schema.get("minimum").and_then(Value::as_u64),
        Some(1),
        "tool_search max_results schema must advertise the enforced lower bound"
    );
    assert_eq!(
        max_results_schema.get("maximum").and_then(Value::as_u64),
        Some(8),
        "tool_search max_results schema must advertise the enforced ceiling"
    );
    assert_eq!(
        def.pointer("/function/parameters/additionalProperties")
            .and_then(Value::as_bool),
        Some(false),
        "tool_search must reject unrecognized control fields"
    );
    assert_eq!(
        def.pointer("/function/parameters/properties/catalog_generation/type")
            .and_then(Value::as_str),
        Some("string"),
        "tool_search must advertise the generation binding field"
    );
}

#[test]
fn grounding_context_schema_advertises_id_and_stale_contract() {
    let def = registry()
        .get("grounding_context")
        .expect("grounding_context registered")
        .definition();
    let ids_schema = def
        .pointer("/function/parameters/properties/ids")
        .expect("grounding_context ids schema");
    let include_stale_schema = def
        .pointer("/function/parameters/properties/include_stale")
        .expect("grounding_context include_stale schema");

    assert_eq!(
        ids_schema.get("type").and_then(Value::as_str),
        Some("array"),
        "grounding_context ids schema must advertise an array"
    );
    assert_eq!(
        ids_schema.pointer("/items/type").and_then(Value::as_str),
        Some("string"),
        "grounding_context ids schema must advertise string observation IDs"
    );
    assert_eq!(
        ids_schema.get("minItems").and_then(Value::as_u64),
        Some(1),
        "grounding_context ids schema must advertise the enforced lower bound"
    );
    assert_eq!(
        ids_schema.get("maxItems").and_then(Value::as_u64),
        Some(16),
        "grounding_context ids schema must advertise the enforced ceiling"
    );
    assert_eq!(
        include_stale_schema.get("type").and_then(Value::as_str),
        Some("boolean"),
        "grounding_context include_stale schema must match runtime boolean validation"
    );
}

#[test]
fn canonical_task_and_todo_schemas_advertise_runtime_bounds() {
    let create = registry()
        .get("task_create")
        .expect("task_create registered")
        .definition();
    assert_eq!(
        create
            .pointer("/function/parameters/properties/subject/maxLength")
            .and_then(Value::as_u64),
        Some(openclaudia::task_graph::MAX_TASK_SUBJECT_BYTES as u64)
    );
    assert_eq!(
        create
            .pointer("/function/parameters/properties/description/maxLength")
            .and_then(Value::as_u64),
        Some(openclaudia::task_graph::MAX_TASK_DESCRIPTION_BYTES as u64)
    );
    assert_eq!(
        create
            .pointer("/function/parameters/properties/active_form/maxLength")
            .and_then(Value::as_u64),
        Some(openclaudia::task_graph::MAX_TASK_ACTIVE_FORM_BYTES as u64)
    );

    let update = registry()
        .get("task_update")
        .expect("task_update registered")
        .definition();
    for field in [
        "add_blocks",
        "add_blocked_by",
        "remove_blocks",
        "remove_blocked_by",
    ] {
        let pointer = format!("/function/parameters/properties/{field}");
        let schema = update.pointer(&pointer).expect("edge schema");
        assert_eq!(
            schema.get("maxItems").and_then(Value::as_u64),
            Some(openclaudia::task_graph::MAX_TASK_EDGES as u64),
            "{field}"
        );
        assert_eq!(
            schema.pointer("/items/maxLength").and_then(Value::as_u64),
            Some(openclaudia::task_graph::MAX_TASK_ID_BYTES as u64),
            "{field}"
        );
    }

    let list = registry()
        .get("task_list")
        .expect("task_list registered")
        .definition();
    assert_eq!(
        list.pointer("/function/parameters/properties/cursor/maxLength")
            .and_then(Value::as_u64),
        Some(openclaudia::task_graph::MAX_PAGE_CURSOR_BYTES as u64)
    );

    let todo = registry()
        .get("todo_write")
        .expect("todo_write registered")
        .definition();
    assert_eq!(
        todo.pointer("/function/parameters/properties/todos/maxItems")
            .and_then(Value::as_u64),
        Some(openclaudia::task_graph::MAX_TASKS as u64)
    );
    assert_eq!(
        todo.pointer("/function/parameters/properties/todos/items/properties/content/maxLength")
            .and_then(Value::as_u64),
        Some(openclaudia::task_graph::MAX_TASK_SUBJECT_BYTES as u64)
    );
    assert_eq!(
        todo.pointer("/function/parameters/properties/todos/items/properties/activeForm/maxLength")
            .and_then(Value::as_u64),
        Some(openclaudia::task_graph::MAX_TASK_ACTIVE_FORM_BYTES as u64)
    );
}

#[test]
fn notebook_edit_schema_advertises_all_runtime_cell_types() {
    let def = registry()
        .get("notebook_edit")
        .expect("notebook_edit registered")
        .definition();
    let cell_type_enum = def
        .pointer("/function/parameters/properties/cell_type/enum")
        .and_then(Value::as_array)
        .expect("notebook_edit cell_type enum");
    let variants: Vec<&str> = cell_type_enum.iter().filter_map(Value::as_str).collect();

    for expected in ["code", "markdown", "raw"] {
        assert!(
            variants.contains(&expected),
            "notebook_edit cell_type schema must advertise runtime-supported {expected:?}; got {variants:?}"
        );
    }
}

#[test]
fn file_tool_path_descriptions_match_relative_path_support() {
    for (tool_name, path_property) in [
        ("read_file", "path"),
        ("write_file", "path"),
        ("edit_file", "path"),
        ("notebook_edit", "notebook_path"),
        ("list_files", "path"),
    ] {
        let def = registry()
            .get(tool_name)
            .unwrap_or_else(|| panic!("{tool_name} registered"))
            .definition();
        let pointer = format!("/function/parameters/properties/{path_property}/description");
        let desc = def
            .pointer(&pointer)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{tool_name}.{path_property} description"));
        let desc_lower = desc.to_ascii_lowercase();

        assert!(
            desc.contains("relative paths are resolved against the current working directory"),
            "{tool_name}.{path_property} must document actual relative-path support; got {desc:?}"
        );
        assert!(
            !desc_lower.contains("must be absolute") && !desc_lower.contains("not relative"),
            "{tool_name}.{path_property} must not claim paths are absolute-only; got {desc:?}"
        );
    }
}

#[test]
fn cron_create_description_does_not_claim_openclaudia_runs_schedules() {
    let def = registry()
        .get("cron_create")
        .expect("cron_create registered")
        .definition();
    let desc = def
        .pointer("/function/description")
        .and_then(Value::as_str)
        .expect("cron_create description");
    assert!(
        desc.contains("external schedulers"),
        "cron_create must describe the actual execution boundary; got {desc:?}"
    );
    assert!(
        !desc.contains("executed by loop mode"),
        "cron_create must not advertise automatic loop-mode execution; got {desc:?}"
    );
    assert!(
        !desc.contains("OpenClaudia runs"),
        "cron_create must not imply OpenClaudia executes schedules automatically; got {desc:?}"
    );
}

#[test]
fn cron_delete_schema_matches_identifier_contract() {
    let def = registry()
        .get("cron_delete")
        .expect("cron_delete registered")
        .definition();
    let desc = def
        .pointer("/function/description")
        .and_then(Value::as_str)
        .expect("cron_delete description");
    assert!(
        desc.contains("stored cron schedule metadata"),
        "cron_delete must describe deletion as metadata removal; got {desc:?}"
    );
    assert!(
        !desc.contains("scheduled task"),
        "cron_delete must not imply OpenClaudia owns task execution; got {desc:?}"
    );

    let params = def
        .pointer("/function/parameters")
        .expect("cron_delete parameters");
    assert!(
        params.pointer("/properties/name").is_some(),
        "cron_delete schema must expose preferred name deletion: {params:?}"
    );
    assert!(
        params.pointer("/properties/index").is_some(),
        "cron_delete schema must expose list-index deletion: {params:?}"
    );
    assert!(
        params.pointer("/properties/id").is_some(),
        "cron_delete schema must expose legacy id deletion: {params:?}"
    );
    for keyword in ["oneOf", "allOf", "anyOf"] {
        assert!(
            params.get(keyword).is_none(),
            "cron_delete must not use top-level {keyword}; Anthropic rejects it: {params:?}"
        );
    }
    let params_desc = params
        .pointer("/description")
        .and_then(Value::as_str)
        .expect("cron_delete parameter description");
    assert!(
        params_desc.contains("exactly one identifier"),
        "cron_delete schema must explain the identifier contract without top-level anyOf; got {params_desc:?}"
    );
    let id_desc = params
        .pointer("/properties/id/description")
        .and_then(Value::as_str)
        .expect("cron_delete id description");
    assert!(
        id_desc.contains("16-character"),
        "cron_delete legacy id description must match persisted ids; got {id_desc:?}"
    );
}

#[test]
fn cron_list_schema_describes_stored_metadata_not_runner() {
    let def = registry()
        .get("cron_list")
        .expect("cron_list registered")
        .definition();
    let desc = def
        .pointer("/function/description")
        .and_then(Value::as_str)
        .expect("cron_list description");
    assert!(
        desc.contains("stored cron schedule metadata"),
        "cron_list must describe stored metadata; got {desc:?}"
    );
    assert!(
        !desc.contains("scheduled tasks"),
        "cron_list must not imply OpenClaudia owns task execution; got {desc:?}"
    );
}

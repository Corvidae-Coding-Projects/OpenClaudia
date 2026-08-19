//! End-to-end tests for `tools::registry` `ToolHandler` trait
//! introspection + mandatory `ToolEffectSpec` declarations + registry
//! integrity that sprint 30 left uncovered.
//!
//! Sprint 71 of the verification effort. Sprint 30 covered the
//! schema validation; this file pins the per-handler
//! effect metadata, `name`/`definition` self-consistency,
//! and the registry's dispatch identity (same handler reference
//! returned across calls).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;

use openclaudia::tools::effect::{ToolEffect, ToolEffectSpec, ToolTarget};
use openclaudia::tools::registry::registry;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

/// All tool names that the registry exposes. Mined from
/// `get_tool_definitions` so test stays in sync with the wire
/// list.
fn registered_tool_names() -> Vec<String> {
    let defs = openclaudia::tools::get_tool_definitions();
    defs.as_array()
        .expect("tool definitions is array")
        .iter()
        .filter_map(|def| {
            def.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .map(String::from)
        })
        .collect()
}

fn readme_available_tool_names() -> BTreeSet<String> {
    let readme = include_str!("../README.md");
    let available_tools = readme
        .split_once("## Available Tools")
        .expect("README must document available tools")
        .1
        .split_once("## Supported Models")
        .expect("README available-tools section must end before supported models")
        .0;

    available_tools
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with('|') {
                return None;
            }
            let first_col = trimmed.split('|').nth(1)?.trim();
            let after_tick = first_col.strip_prefix('`')?;
            let tool_name = after_tick.split_once('`')?.0;
            if tool_name.is_empty() {
                None
            } else {
                Some(tool_name.to_string())
            }
        })
        .collect()
}

fn readme_available_tool_row(tool_name: &str) -> String {
    let readme = include_str!("../README.md");
    let available_tools = readme
        .split_once("## Available Tools")
        .expect("README must document available tools")
        .1
        .split_once("## Supported Models")
        .expect("README available-tools section must end before supported models")
        .0;

    available_tools
        .lines()
        .find(|line| line.trim_start().starts_with(&format!("| `{tool_name}` |")))
        .unwrap_or_else(|| panic!("README Available Tools must document {tool_name:?}"))
        .to_string()
}

fn registered_tool_description(tool_name: &str) -> String {
    let defs = openclaudia::tools::get_tool_definitions();
    defs.as_array()
        .expect("tool definitions is array")
        .iter()
        .find_map(|def| {
            let function = def.get("function")?;
            let name = function.get("name")?.as_str()?;
            if name == tool_name {
                function.get("description")?.as_str().map(str::to_string)
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("registered tool {tool_name:?} must have a description"))
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — name() / definition() self-consistency
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn handler_name_matches_definition_function_name() {
    let r = registry();
    for tool_name in registered_tool_names() {
        let handler = r
            .get(&tool_name)
            .unwrap_or_else(|| panic!("handler for {tool_name:?} MUST be registered"));
        assert_eq!(
            handler.name(),
            tool_name,
            "handler.name() MUST equal registered tool name"
        );
        let def = handler.definition();
        let def_name = def["function"]["name"].as_str().unwrap_or("");
        assert_eq!(
            def_name, tool_name,
            "definition.function.name MUST equal registered tool name; got {def_name:?}"
        );
    }
}

#[test]
fn handler_definition_uses_function_type_envelope() {
    let r = registry();
    for tool_name in registered_tool_names() {
        let handler = r.get(&tool_name).unwrap();
        let def = handler.definition();
        assert_eq!(
            def["type"], "function",
            "tool {tool_name:?} definition MUST have type=function"
        );
        assert!(
            def.get("function").is_some(),
            "tool {tool_name:?} MUST have function envelope"
        );
    }
}

#[test]
fn handler_definition_function_has_parameters_schema() {
    let r = registry();
    for tool_name in registered_tool_names() {
        let handler = r.get(&tool_name).unwrap();
        let def = handler.definition();
        let params = &def["function"]["parameters"];
        assert!(
            params.is_object(),
            "tool {tool_name:?} parameters MUST be an object schema"
        );
        assert_eq!(
            params["type"], "object",
            "tool {tool_name:?} parameters.type MUST be 'object'"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Mandatory effect declarations (S-016)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn bash_handler_declares_bash_canonical_with_command_arg_key() {
    let r = registry();
    let spec = r.get("bash").expect("bash registered").effect_spec();
    assert_eq!(spec.canonical, "Bash");
    assert_eq!(spec.target, ToolTarget::Arg("command"));
    assert_eq!(spec.effect, ToolEffect::Destructive);
}

#[test]
fn write_file_handler_declares_write_canonical_with_path_arg_key() {
    let r = registry();
    let spec = r
        .get("write_file")
        .expect("write_file registered")
        .effect_spec();
    assert_eq!(spec.canonical, "Write");
    assert_eq!(spec.target, ToolTarget::Arg("path"));
    assert_eq!(spec.effect, ToolEffect::WorkspaceMutation);
}

#[test]
fn edit_file_handler_declares_edit_canonical() {
    let r = registry();
    let spec = r
        .get("edit_file")
        .expect("edit_file registered")
        .effect_spec();
    assert_eq!(spec.canonical, "Edit");
    assert_eq!(spec.target, ToolTarget::Arg("path"));
}

#[test]
fn mutation_tool_descriptions_document_successful_read_gate() {
    for tool_name in ["write_file", "edit_file", "notebook_edit"] {
        let desc = registered_tool_description(tool_name);
        assert!(
            desc.contains("read") && desc.contains("successfully"),
            "{tool_name} registry description must document the successful read_file gate; got {desc:?}"
        );

        let row = readme_available_tool_row(tool_name);
        assert!(
            row.contains("successful `read_file` first"),
            "README row for {tool_name} must document the successful read_file gate; got {row:?}"
        );
    }
}

#[test]
fn web_fetch_handler_declares_webfetch_canonical_with_url_arg_key() {
    let r = registry();
    let spec = r
        .get("web_fetch")
        .expect("web_fetch registered")
        .effect_spec();
    assert_eq!(spec.canonical, "WebFetch");
    assert_eq!(spec.target, ToolTarget::Arg("url"));
    assert_eq!(spec.effect, ToolEffect::NetworkRead);
}

#[test]
fn read_only_tools_declare_read_only_as_a_positive_claim() {
    // S-016: read-only is now an assertion the handler makes, not the
    // absence of an override. The old form of this test ("MUST return None
    // from permission_target") could not tell a genuine read-only tool from
    // one that simply forgot to classify itself — which is F-001.
    let r = registry();
    for tool_name in &[
        "read_file",
        "grounding_context",
        "list_files",
        "glob",
        "grep",
    ] {
        let spec = r.get(tool_name).expect("registered").effect_spec();
        assert_eq!(
            spec.effect,
            ToolEffect::ReadOnly,
            "read-only tool {tool_name:?} MUST declare ToolEffect::ReadOnly"
        );
        assert!(!spec.effect.requires_authorization());
    }
}

#[test]
fn every_handler_declares_a_structurally_valid_spec() {
    let r = registry();
    for tool_name in registered_tool_names() {
        let handler = r.get(&tool_name).unwrap();
        handler
            .effect_spec()
            .validate(&tool_name)
            .unwrap_or_else(|e| panic!("{tool_name}: {e}"));
    }
}

#[test]
fn effect_specs_are_referentially_stable_across_calls() {
    let r = registry();
    let handler = r.get("bash").unwrap();
    assert_eq!(
        handler.effect_spec(),
        handler.effect_spec(),
        "effect_spec MUST be deterministic per handler"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Registry identity + dispatch shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn registry_get_returns_same_ptr_across_repeat_lookups() {
    let r = registry();
    let h1 = r.get("bash").unwrap();
    let h2 = r.get("bash").unwrap();
    // Same reference target (no heap alloc per dispatch).
    // Compare data-pointer addresses of the trait objects; both
    // arms come from the same OnceLock-backed slot.
    assert!(
        std::ptr::addr_eq(std::ptr::from_ref(h1), std::ptr::from_ref(h2)),
        "registry MUST return identical pointers across calls"
    );
}

#[test]
fn registry_returns_none_for_unregistered_name() {
    let r = registry();
    assert!(r.get("totally-not-registered-2099").is_none());
    assert!(r.get("").is_none());
}

#[test]
fn registry_singleton_is_referentially_stable_across_calls() {
    let r1 = registry();
    let r2 = registry();
    assert!(
        std::ptr::eq(r1, r2),
        "registry() MUST be a singleton (OnceLock-backed)"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — ToolEffectSpec shape + Eq
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn effect_spec_with_same_fields_compares_equal() {
    let a = ToolEffectSpec::effectful(ToolEffect::Destructive, "Bash", "command");
    let b = ToolEffectSpec::effectful(ToolEffect::Destructive, "Bash", "command");
    assert_eq!(a, b);
}

#[test]
fn effect_spec_different_effect_compares_not_equal() {
    let a = ToolEffectSpec::effectful(ToolEffect::Destructive, "Bash", "command");
    let b = ToolEffectSpec::effectful(ToolEffect::ReadOnly, "Bash", "command");
    assert_ne!(
        a, b,
        "two declarations differing only in effect must not compare equal; \
         collapsing them would let a destructive tool pass as a read"
    );
}

#[test]
fn effect_spec_is_copy_clone_for_zero_alloc_dispatch() {
    let a = ToolEffectSpec::read_only("X");
    // Copy semantics — value passes without clone() call.
    let b = a;
    let c = a; // a still usable (Copy).
    assert_eq!(b, c);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — All registered tools end-to-end smoke
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_registered_tool_has_lookup_handler_and_definition() {
    let r = registry();
    for tool_name in registered_tool_names() {
        let handler = r
            .get(&tool_name)
            .unwrap_or_else(|| panic!("tool {tool_name:?} MUST resolve"));
        // The full pipeline — name + definition + maybe-target
        // — MUST not panic and MUST be self-consistent.
        let _ = handler.name();
        let _ = handler.definition();
        let _ = handler.effect_spec();
    }
}

#[test]
fn readme_available_tools_match_registered_tool_names() {
    let registered: BTreeSet<String> = registered_tool_names().into_iter().collect();
    let documented = readme_available_tool_names();

    let missing_from_readme: Vec<_> = registered.difference(&documented).cloned().collect();
    assert!(
        missing_from_readme.is_empty(),
        "README Available Tools must document every registered tool; missing {missing_from_readme:?}"
    );

    let extra_in_readme: Vec<_> = documented
        .difference(&registered)
        .filter(|name| {
            !(cfg!(not(feature = "browser"))
                && matches!(name.as_str(), "web_browser" | "web_search"))
        })
        .cloned()
        .collect();
    assert!(
        extra_in_readme.is_empty(),
        "README Available Tools must not advertise unregistered tools; extra {extra_in_readme:?}"
    );

    for must_document in ["crosslink", "glob", "grep", "skill", "tool_search"] {
        assert!(
            documented.contains(must_document),
            "README Available Tools must document registered tool {must_document:?}"
        );
    }
    assert!(
        !documented.contains("chainlink"),
        "README must not advertise the removed Chainlink CLI tool"
    );
    let readme = include_str!("../README.md");
    assert!(
        !readme.contains("Chainlink") && !readme.contains("chainlink"),
        "README must not advertise the removed Chainlink CLI dependency"
    );
}

#[test]
fn readme_lsp_row_uses_registered_action_names() {
    let row = readme_available_tool_row("lsp");
    let lsp_definition = registry()
        .get("lsp")
        .expect("lsp handler must be registered")
        .definition();
    let action_enum = lsp_definition["function"]["parameters"]["properties"]["action"]["enum"]
        .as_array()
        .expect("lsp action enum");
    let action_names: BTreeSet<&str> = action_enum
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();

    assert!(action_names.contains("documentSymbols"));
    assert!(
        row.contains("documentSymbols"),
        "README LSP row must use the registered documentSymbols action name; got {row:?}"
    );
    assert!(
        !row.contains("documentSymbol,"),
        "README LSP row must not use the singular non-schema action name; got {row:?}"
    );
}

#[test]
fn web_tool_descriptions_match_browser_feature_set() {
    let fetch_description = registered_tool_description("web_fetch");

    if cfg!(feature = "browser") {
        let search_description = registered_tool_description("web_search");
        assert!(
            fetch_description.contains("headless Chromium fallback")
                && fetch_description.contains("JavaScript-rendered"),
            "browser build web_fetch description must advertise browser fallback; got {fetch_description:?}"
        );
        assert!(
            search_description.contains("DuckDuckGo/Bing browser scraping"),
            "browser build web_search description must advertise browser-backed search; got {search_description:?}"
        );
    } else {
        assert!(
            fetch_description.contains("direct HTTP")
                && fetch_description.contains("does not include JavaScript rendering"),
            "no-browser web_fetch description must not imply browser fallback; got {fetch_description:?}"
        );
        assert!(
            registry().get("web_search").is_none(),
            "no-browser builds must not register web_search because browser-backed free search is unavailable"
        );
        assert!(
            !fetch_description.contains("headless Chromium fallback"),
            "no-browser web_fetch description must not advertise unavailable browser fallback"
        );
    }
}

#[test]
fn readme_web_search_docs_explain_browser_feature_boundary() {
    let readme = include_str!("../README.md");
    let comparison = include_str!("../COMPARISON.md");
    let prompt_tools = include_str!("../prompts/base/tools.md");
    let claude_code_features = include_str!("../CLAUDE_CODE_FEATURES.md");
    let architecture = include_str!("../ARCHITECTURE.md");
    let cargo_toml = include_str!("../Cargo.toml");
    let changelog = include_str!("../CHANGELOG.md");

    assert!(
        readme.contains("Free DuckDuckGo/Bing browser scraping"),
        "README must explain that web search is free and browser-backed"
    );
    assert!(
        comparison.contains("free DuckDuckGo/Bing browser scraping"),
        "COMPARISON.md must describe OpenClaudia web search as free and browser-backed"
    );
    assert!(
        readme.contains("web_search is unavailable"),
        "README no-default-features build note must explain web_search's browser-feature requirement"
    );
    assert!(
        prompt_tools.contains(
            "tool definitions attached to the current request are the authoritative list"
        ) && !prompt_tools.contains("web_search")
            && !prompt_tools.contains("search API key"),
        "model-facing base policy must stay capability-neutral instead of hard-coding web-search availability"
    );
    assert!(
        claude_code_features.contains("free DuckDuckGo/Bing browser scraping"),
        "Claude Code feature parity doc must describe the current free search backend"
    );
    assert!(
        architecture.contains("DuckDuckGo") && architecture.contains("/ Bing"),
        "architecture doc must describe the current free search backend"
    );
    for doc in [
        readme,
        comparison,
        prompt_tools,
        claude_code_features,
        architecture,
        changelog,
    ] {
        assert!(
            !doc.contains("API keys work in all builds")
                && !doc.contains("web_search requires")
                && !doc.contains("APIs work in all builds")
                && !doc.contains(concat!("TA", "VILY"))
                && !doc.contains(concat!("BR", "AVE"))
                && !doc.contains(concat!("Ta", "vily"))
                && !doc.contains(concat!("Bra", "ve")),
            "docs must not advertise paid web-search API backends"
        );
    }

    for doc in [
        readme,
        comparison,
        prompt_tools,
        claude_code_features,
        architecture,
        cargo_toml,
    ] {
        assert!(
            !doc.contains(concat!("Ji", "na"))
                && !doc.contains(concat!("j", "ina"))
                && !doc.contains("hosted converter"),
            "current web-search/fetch surface must not reference retired hosted-converter backends"
        );
    }
}

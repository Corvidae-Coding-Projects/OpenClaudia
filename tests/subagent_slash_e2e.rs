//! End-to-end tests for `subagent::AgentType` taxonomy +
//! `slash_commands::SLASH_SECTIONS` registry shape.
//!
//! Sprint 60 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::command_registry::{
    registry as command_registry, CommandFrontend, CommandId, CommandParseError,
};
use openclaudia::slash_commands::{all_commands, SLASH_SECTIONS};
use openclaudia::subagent::AgentType;

// ───────────────────────────────────────────────────────────────────────────
// Section A — AgentType::ALL completeness
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn agent_type_all_contains_5_documented_variants() {
    assert_eq!(
        AgentType::ALL.len(),
        5,
        "AgentType::ALL MUST have 5 documented variants; got {}",
        AgentType::ALL.len()
    );
}

#[test]
fn agent_type_all_includes_every_variant_pairwise_distinct() {
    let names: Vec<&str> = AgentType::ALL.iter().map(AgentType::name).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        names.len(),
        "names MUST be pairwise distinct; got {names:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — AgentType::name canonical strings
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn agent_type_name_matches_documented_kebab_case() {
    let cases = &[
        (AgentType::GeneralPurpose, "general-purpose"),
        (AgentType::Explore, "explore"),
        (AgentType::Plan, "plan"),
        (AgentType::Guide, "claude-code-guide"),
        (AgentType::Coordinator, "coordinator"),
    ];
    for (agent, expected) in cases {
        assert_eq!(
            agent.name(),
            *expected,
            "{agent:?} name MUST equal {expected:?}; got {:?}",
            agent.name()
        );
    }
}

#[test]
fn agent_type_name_is_lowercase_only() {
    for agent in AgentType::ALL {
        let n = agent.name();
        assert_eq!(n.to_lowercase(), n, "name {n:?} MUST be lowercase");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — AgentType::parse_type
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_type_round_trips_canonical_names() {
    for agent in AgentType::ALL {
        let parsed = AgentType::parse_type(agent.name())
            .unwrap_or_else(|| panic!("parse_type({:?}) MUST succeed", agent.name()));
        assert_eq!(parsed, *agent);
    }
}

#[test]
fn parse_type_accepts_documented_aliases() {
    let aliases = &[
        ("general_purpose", AgentType::GeneralPurpose),
        ("generalpurpose", AgentType::GeneralPurpose),
        ("explorer", AgentType::Explore),
        ("planner", AgentType::Plan),
        ("guide", AgentType::Guide),
    ];
    for (alias, expected) in aliases {
        let parsed =
            AgentType::parse_type(alias).unwrap_or_else(|| panic!("alias {alias:?} MUST parse"));
        assert_eq!(parsed, *expected);
    }
}

#[test]
fn parse_type_is_case_insensitive() {
    assert_eq!(AgentType::parse_type("EXPLORE"), Some(AgentType::Explore));
    assert_eq!(
        AgentType::parse_type("General-Purpose"),
        Some(AgentType::GeneralPurpose)
    );
}

#[test]
fn parse_type_rejects_unknown_strings() {
    for bad in &["", "unknown", "agent", "ggeneral-purpose"] {
        assert!(
            AgentType::parse_type(bad).is_none(),
            "{bad:?} MUST NOT parse"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — AgentType::description
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_agent_type_has_non_trivial_description() {
    for agent in AgentType::ALL {
        let desc = agent.description();
        assert!(
            desc.len() >= 10,
            "agent {agent:?} description must be substantive (>= 10 chars); \
             got {desc:?}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — AgentType::allowed_tools
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_agent_type_has_at_least_one_allowed_tool() {
    for agent in AgentType::ALL {
        let tools = agent.allowed_tools();
        assert!(
            !tools.is_empty(),
            "agent {agent:?} MUST have at least one allowed tool"
        );
    }
}

#[test]
fn explore_agent_does_not_have_write_or_edit_tools() {
    // Explore is read-only by design.
    let tools = AgentType::Explore.allowed_tools();
    assert!(
        !tools.contains(&"write_file"),
        "Explore MUST NOT have write_file; got {tools:?}"
    );
    assert!(
        !tools.contains(&"edit_file"),
        "Explore MUST NOT have edit_file; got {tools:?}"
    );
    assert_eq!(
        tools.contains(&"web_search"),
        cfg!(feature = "browser"),
        "Explore should only advertise web_search when browser-backed search is compiled"
    );
}

#[test]
fn plan_agent_does_not_have_write_or_edit_tools() {
    let tools = AgentType::Plan.allowed_tools();
    assert!(!tools.contains(&"write_file"));
    assert!(!tools.contains(&"edit_file"));
    assert!(
        !tools.contains(&"bash"),
        "Plan is read-only and MUST NOT have bash; got {tools:?}"
    );
}

#[test]
fn guide_agent_does_not_have_bash() {
    // Guide is docs-only.
    let tools = AgentType::Guide.allowed_tools();
    assert!(
        !tools.contains(&"bash"),
        "Guide MUST NOT have bash; got {tools:?}"
    );
    assert_eq!(
        tools.contains(&"web_search"),
        cfg!(feature = "browser"),
        "Guide should only advertise web_search when browser-backed search is compiled"
    );
}

#[test]
fn coordinator_has_task_agent_output_and_task_stop_for_delegation() {
    let tools = AgentType::Coordinator.allowed_tools();
    assert!(
        tools.contains(&"task"),
        "Coordinator MUST have task tool; got {tools:?}"
    );
    assert!(
        tools.contains(&"agent_output"),
        "Coordinator MUST have agent_output tool; got {tools:?}"
    );
    assert!(
        tools.contains(&"task_stop"),
        "Coordinator MUST have task_stop tool; got {tools:?}"
    );
}

#[test]
fn general_purpose_has_read_and_write_tools() {
    let tools = AgentType::GeneralPurpose.allowed_tools();
    assert!(tools.contains(&"read_file"));
    assert!(tools.contains(&"write_file"));
    assert!(tools.contains(&"edit_file"));
    assert!(tools.contains(&"bash"));
    assert!(tools.contains(&"kill_shells_for_agent"));
    assert_eq!(
        tools.contains(&"web_search"),
        cfg!(feature = "browser"),
        "GeneralPurpose should only advertise web_search when browser-backed search is compiled"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — system_prompt content sanity
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_agent_type_has_non_empty_system_prompt() {
    for agent in AgentType::ALL {
        let prompt = agent.system_prompt();
        assert!(
            prompt.len() > 50,
            "agent {agent:?} system prompt must be substantive (>50 chars); \
             got {} chars",
            prompt.len()
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — AgentType serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn agent_type_serde_uses_kebab_case_of_variant_name() {
    // Authoring discovery: serde derives kebab-case from the
    // VARIANT NAME (not from name()), so most variants match
    // name() exactly — but Guide diverges:
    //   * name() = "claude-code-guide" (parser alias)
    //   * serde encoding = "guide" (kebab-case of variant)
    // Pin the actual serde contract here.
    let serde_cases = &[
        (AgentType::GeneralPurpose, "general-purpose"),
        (AgentType::Explore, "explore"),
        (AgentType::Plan, "plan"),
        (AgentType::Guide, "guide"),
        (AgentType::Coordinator, "coordinator"),
    ];
    for (agent, expected_json) in serde_cases {
        let json = serde_json::to_string(agent).expect("serialize");
        assert_eq!(
            json.trim_matches('"'),
            *expected_json,
            "serde encoding for {agent:?} MUST equal {expected_json:?}"
        );
        let back: AgentType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, *agent);
    }
}

#[test]
fn agent_type_guide_has_distinct_serde_and_name_strings() {
    // Specifically pin the Guide divergence so a future
    // change that aligns them surfaces here as a notification.
    assert_eq!(AgentType::Guide.name(), "claude-code-guide");
    let json = serde_json::to_string(&AgentType::Guide).expect("serialize");
    assert_eq!(json.trim_matches('"'), "guide");
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — SLASH_SECTIONS shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn slash_sections_table_is_non_empty() {
    assert!(!SLASH_SECTIONS.is_empty());
}

#[test]
fn every_section_has_title_and_non_empty_commands() {
    for section in SLASH_SECTIONS.iter() {
        assert!(!section.title.is_empty(), "section title MUST be non-empty");
        assert!(
            !section.commands.is_empty(),
            "section {} has no commands",
            section.title
        );
    }
}

#[test]
fn every_command_invocation_starts_with_slash() {
    for command in all_commands() {
        assert!(
            command.invocation.starts_with('/'),
            "invocation {:?} MUST start with '/'",
            command.invocation
        );
    }
}

#[test]
fn every_command_description_is_non_empty() {
    for command in all_commands() {
        assert!(
            !command.description.is_empty(),
            "command {:?} MUST have non-empty description",
            command.invocation
        );
    }
}

#[test]
fn all_commands_iter_traverses_every_section() {
    let total_from_sections: usize = SLASH_SECTIONS.iter().map(|s| s.commands.len()).sum();
    let total_from_iter = all_commands().count();
    assert_eq!(
        total_from_iter, total_from_sections,
        "all_commands().count() MUST equal sum-of-section-lens"
    );
}

#[test]
fn slash_table_includes_canonical_core_commands() {
    let invocations: Vec<&str> = all_commands().map(|c| c.invocation).collect();
    for canonical in &[
        "/help, /?",
        "/new, /clear",
        "/exit, /quit, /q",
        "/sessions, /list",
    ] {
        assert!(
            invocations.contains(canonical),
            "canonical command {canonical:?} MUST appear in SLASH_SECTIONS; \
             got {invocations:?}"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — canonical typed registry behavior
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn aliases_resolve_to_the_same_typed_handler() {
    let registry = command_registry();
    for alias in ["/new", "/clear"] {
        let proposal = registry
            .parse(alias, CommandFrontend::LegacyCli)
            .expect("new-session spelling must parse");
        assert_eq!(proposal.id(), CommandId::New);
    }
    for alias in ["/continue", "/load", "/resume"] {
        let proposal = registry
            .parse(alias, CommandFrontend::Tui)
            .expect("session-resume spelling must parse");
        assert_eq!(proposal.id(), CommandId::Continue);
    }
}

#[test]
fn frontend_availability_is_enforced_during_pure_parsing() {
    assert!(matches!(
        command_registry().parse("/connect", CommandFrontend::Tui),
        Err(CommandParseError::FrontendUnavailable {
            name,
            frontend: CommandFrontend::Tui,
        }) if name == "connect"
    ));
    assert!(matches!(
        command_registry().parse("/provider", CommandFrontend::LegacyCli),
        Err(CommandParseError::FrontendUnavailable {
            name,
            frontend: CommandFrontend::LegacyCli,
        }) if name == "provider"
    ));
}

#[test]
fn plugin_commands_are_namespaced_typed_proposals() {
    let proposal = command_registry()
        .parse("/formatter:fix src/main.rs", CommandFrontend::LegacyCli)
        .expect("namespaced plugin command must parse");
    assert_eq!(proposal.id(), CommandId::DynamicPlugin);
    assert_eq!(proposal.namespace(), Some("formatter"));
    assert_eq!(proposal.component(), Some("fix"));
    assert_eq!(proposal.arguments_text(), "src/main.rs");
}

//! Compatibility view over the canonical typed command registry.
//!
//! The legacy REPL and full-screen TUI no longer maintain hand-authored
//! catalogues. These lazy section views are generated from the same validated
//! [`crate::command_registry::CommandSpec`] records used for parsing,
//! completion, admission, and dispatch.

use std::sync::LazyLock;

use crate::command_registry::{self, CommandFrontend};

pub use crate::command_registry::{
    CommandHelpEntry as SlashCommand, CommandHelpSection as SlashSection,
};

/// Generated legacy-REPL help sections.
pub static SLASH_SECTIONS: LazyLock<Vec<SlashSection>> =
    LazyLock::new(|| command_registry::registry().help_sections(CommandFrontend::LegacyCli));

/// Generated full-screen-TUI help sections.
pub static TUI_SLASH_SECTIONS: LazyLock<Vec<SlashSection>> =
    LazyLock::new(|| command_registry::registry().help_sections(CommandFrontend::Tui));

/// Flat iterator over every legacy-REPL help row.
pub fn all_commands() -> impl Iterator<Item = &'static SlashCommand> {
    SLASH_SECTIONS
        .iter()
        .flat_map(|section| section.commands.iter())
}

/// Flat iterator over every full-screen-TUI help row.
pub fn all_tui_commands() -> impl Iterator<Item = &'static SlashCommand> {
    TUI_SLASH_SECTIONS
        .iter()
        .flat_map(|section| section.commands.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_registry::{registry, CommandFrontend};

    #[test]
    fn generated_sections_are_non_empty_and_well_formed() {
        for sections in [&*SLASH_SECTIONS, &*TUI_SLASH_SECTIONS] {
            assert!(!sections.is_empty());
            for section in sections {
                assert!(!section.title.is_empty());
                assert!(!section.commands.is_empty());
                for command in &section.commands {
                    assert!(command.invocation.starts_with('/'));
                    assert!(!command.description.is_empty());
                }
            }
        }
    }

    #[test]
    fn generated_help_roots_resolve_on_the_same_frontend() {
        for (frontend, sections) in [
            (CommandFrontend::LegacyCli, &*SLASH_SECTIONS),
            (CommandFrontend::Tui, &*TUI_SLASH_SECTIONS),
        ] {
            for section in sections {
                for command in &section.commands {
                    for form in command.invocation.split(',').map(str::trim) {
                        let root = form.split_whitespace().next().unwrap_or(form);
                        if root.contains("<plugin>") || root.contains("<skill-name>") {
                            let concrete = root
                                .replace("<plugin>", "demo")
                                .replace("<command>", "run")
                                .replace("<skill-name>", "demo-skill");
                            assert!(
                                registry().parse(&concrete, frontend).is_ok(),
                                "dynamic help form {root:?} does not parse as {concrete:?} on {frontend:?}"
                            );
                            continue;
                        }
                        let name = root.trim_start_matches('/');
                        assert!(
                            registry()
                                .get(name)
                                .is_some_and(|spec| spec.frontends.contains(frontend)),
                            "help form {root:?} in {} does not resolve on {frontend:?}",
                            section.title
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn completion_names_are_exactly_recognized_names() {
        for frontend in [CommandFrontend::LegacyCli, CommandFrontend::Tui] {
            for name in registry().completion_names(frontend) {
                assert!(
                    registry()
                        .get(name)
                        .is_some_and(|spec| spec.frontends.contains(frontend)),
                    "completion name {name:?} is not recognized on {frontend:?}"
                );
            }
        }
    }

    #[test]
    fn frontend_catalogues_include_supported_commands_only() {
        let legacy = all_commands()
            .map(|command| command.invocation)
            .collect::<Vec<_>>();
        assert!(legacy
            .iter()
            .any(|invocation| invocation.contains("/commit-push-pr")));
        assert!(legacy
            .iter()
            .any(|invocation| invocation.contains("/<plugin>:<command>")));

        let tui = all_tui_commands()
            .map(|command| command.invocation)
            .collect::<Vec<_>>();
        assert!(tui
            .iter()
            .any(|invocation| invocation.contains("/provider")));
        assert!(tui.iter().any(|invocation| invocation.contains("/copy")));
        assert!(!tui.iter().any(|invocation| invocation.contains("/connect")));
    }
}

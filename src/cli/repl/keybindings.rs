use super::slash::SlashCommandResult;
use openclaudia::config;

/// Convert a crossterm `KeyEvent` to a keybinding string format
/// Examples: "escape", "f2", "ctrl-x", "ctrl-x n" (with leader key state)
pub fn key_event_to_string(
    event: &crossterm::event::KeyEvent,
    leader_active: bool,
) -> Option<String> {
    let key_str = config::ParsedKeystroke::from_key_event(event)?.display();

    if leader_active {
        Some(format!("ctrl-x {key_str}"))
    } else {
        Some(key_str)
    }
}

/// Execute a key action and return a result indicator
pub fn execute_key_action(action: &config::KeyAction) -> Option<SlashCommandResult> {
    use config::KeyAction;

    match action {
        KeyAction::Cancel | KeyAction::None => None,
        KeyAction::NewSession | KeyAction::Clear => Some(SlashCommandResult::Clear),
        KeyAction::Exit => Some(SlashCommandResult::Exit),
        KeyAction::Export => Some(SlashCommandResult::Export),
        KeyAction::Compact => Some(SlashCommandResult::Compact { instructions: None }),
        KeyAction::Undo => Some(SlashCommandResult::Undo),
        KeyAction::Redo => Some(SlashCommandResult::Redo),
        KeyAction::ToggleMode => Some(SlashCommandResult::ToggleMode),
        KeyAction::Status => Some(SlashCommandResult::Status),
        KeyAction::Models => {
            println!("\nUse /models to see available models.\n");
            Some(SlashCommandResult::Handled)
        }
        KeyAction::ListSessions => {
            println!("\nUse /sessions to see saved sessions.\n");
            Some(SlashCommandResult::Handled)
        }
        KeyAction::CopyResponse => {
            println!("\nUse /copy to copy the last response.\n");
            Some(SlashCommandResult::Handled)
        }
        KeyAction::Editor => {
            println!("\nUse /editor to open external editor.\n");
            Some(SlashCommandResult::Handled)
        }
        KeyAction::Help => {
            println!("\nUse /help for commands.\n");
            Some(SlashCommandResult::Handled)
        }
    }
}

/// Display current keybindings configuration
pub fn display_keybindings(keybindings: &config::KeybindingsConfig) {
    use config::KeyAction;

    println!("\nConfigured Keybindings:");
    println!("========================\n");

    let resolver = config::KeybindingResolver::from_config(keybindings);
    let actions = [
        (KeyAction::NewSession, "New session"),
        (KeyAction::ListSessions, "List sessions"),
        (KeyAction::Export, "Export conversation"),
        (KeyAction::CopyResponse, "Copy last response"),
        (KeyAction::Editor, "Open external editor"),
        (KeyAction::Models, "Show/switch models"),
        (KeyAction::ToggleMode, "Toggle Build/Plan mode"),
        (KeyAction::Cancel, "Cancel response"),
        (KeyAction::Status, "Show status"),
        (KeyAction::Help, "Show help"),
        (KeyAction::Clear, "Clear/new conversation"),
        (KeyAction::Undo, "Undo last exchange"),
        (KeyAction::Redo, "Redo last exchange"),
        (KeyAction::Compact, "Compact conversation"),
        (KeyAction::Exit, "Exit application"),
    ];

    for (action, description) in actions {
        let keys = resolver
            .effective_bindings(config::KeyContext::Global)
            .into_iter()
            .filter_map(|(chord, effective)| (effective == action).then_some(chord))
            .collect::<Vec<_>>();
        if !keys.is_empty() {
            println!("  {:20} {description}", keys.join(", "));
        }
    }
    if !resolver.diagnostics().is_empty() {
        println!("\nUnavailable bindings:");
        for diagnostic in resolver.diagnostics() {
            println!("  {diagnostic}");
        }
    }

    let disabled = keybindings.get_keys_for_action(&KeyAction::None);
    if !disabled.is_empty() {
        println!("\nDisabled bindings:");
        for key in disabled {
            println!("  {key} (disabled)");
        }
    }

    println!("\nTo customize, add a 'keybindings' section to your config.yaml.");
    println!("Set any key to 'none' to disable it.\n");
}

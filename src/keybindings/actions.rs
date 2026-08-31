//! Keybinding action enumeration.
//!
//! Defines every action a keybinding can dispatch. Lives outside `src/config/`
//! because it is consumed by the runtime resolver and the TUI dispatch sites,
//! not just the config schema. The matching YAML deserialization tag is the
//! `snake_case` form of the variant name.

use serde::Deserialize;

/// Keybinding action names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAction {
    /// Start a new session
    NewSession,
    /// List saved sessions
    ListSessions,
    /// Export conversation to markdown
    Export,
    /// Copy last response to clipboard
    CopyResponse,
    /// Open external editor
    Editor,
    /// Show/switch models
    Models,
    /// Toggle Build/Plan mode
    ToggleMode,
    /// Cancel in-progress response
    Cancel,
    /// Show session status
    Status,
    /// Show help
    Help,
    /// Clear/new conversation
    Clear,
    /// Exit the application
    Exit,
    /// Undo last exchange
    Undo,
    /// Redo last undone exchange
    Redo,
    /// Compact conversation
    Compact,
    /// No action (disabled keybinding)
    None,
}

impl KeyAction {
    /// Canonical slash command used by both interactive frontends for this
    /// action. Cancellation is contextual and `None` is deliberately unbound.
    #[must_use]
    pub const fn command_name(&self) -> Option<&'static str> {
        match self {
            Self::NewSession | Self::Clear => Some("new"),
            Self::ListSessions => Some("sessions"),
            Self::Export => Some("export"),
            Self::CopyResponse => Some("copy"),
            Self::Editor => Some("editor"),
            Self::Models => Some("models"),
            Self::ToggleMode => Some("plan"),
            Self::Status => Some("status"),
            Self::Help => Some("help"),
            Self::Exit => Some("exit"),
            Self::Undo => Some("undo"),
            Self::Redo => Some("redo"),
            Self::Compact => Some("compact"),
            Self::Cancel | Self::None => None,
        }
    }

    /// Stable user-facing label used by generated effective-key help.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::NewSession => "New session",
            Self::ListSessions => "List sessions",
            Self::Export => "Export conversation",
            Self::CopyResponse => "Copy last response",
            Self::Editor => "Open external editor",
            Self::Models => "Show or switch models",
            Self::ToggleMode => "Toggle Build/Plan mode",
            Self::Cancel => "Cancel current operation",
            Self::Status => "Show status",
            Self::Help => "Show help",
            Self::Clear => "Clear conversation",
            Self::Exit => "Exit application",
            Self::Undo => "Undo last exchange",
            Self::Redo => "Redo last exchange",
            Self::Compact => "Compact conversation",
            Self::None => "Disabled",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_action_serialization() {
        let action = KeyAction::NewSession;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"new_session\"");

        let action2: KeyAction = serde_json::from_str("\"toggle_mode\"").unwrap();
        assert_eq!(action2, KeyAction::ToggleMode);
    }

    #[test]
    fn test_key_action_all_variants() {
        // Ensure all variants can be serialized/deserialized
        let actions = vec![
            ("\"new_session\"", KeyAction::NewSession),
            ("\"list_sessions\"", KeyAction::ListSessions),
            ("\"export\"", KeyAction::Export),
            ("\"copy_response\"", KeyAction::CopyResponse),
            ("\"editor\"", KeyAction::Editor),
            ("\"models\"", KeyAction::Models),
            ("\"toggle_mode\"", KeyAction::ToggleMode),
            ("\"cancel\"", KeyAction::Cancel),
            ("\"status\"", KeyAction::Status),
            ("\"help\"", KeyAction::Help),
            ("\"clear\"", KeyAction::Clear),
            ("\"exit\"", KeyAction::Exit),
            ("\"undo\"", KeyAction::Undo),
            ("\"redo\"", KeyAction::Redo),
            ("\"compact\"", KeyAction::Compact),
            ("\"none\"", KeyAction::None),
        ];

        for (json, expected) in actions {
            let parsed: KeyAction = serde_json::from_str(json).unwrap();
            assert_eq!(parsed, expected);
        }
    }
}

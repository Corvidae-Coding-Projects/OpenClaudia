//! Runtime lookup helpers on [`crate::config::KeybindingsConfig`].
//!
//! These methods are convenience accessors used by the TUI/REPL dispatch
//! sites; they live here (alongside the resolver) rather than in
//! `src/config/keybindings.rs` because they are runtime concerns, not part
//! of the YAML schema. See crosslink #357.

use super::actions::KeyAction;
use super::parser::parse_chord;
use crate::config::KeybindingsConfig;

impl KeybindingsConfig {
    /// Get the action for a key combination.
    ///
    /// Lookup is case-insensitive: the `key` argument is lowercased before
    /// searching the bindings map. Default bindings are also stored in
    /// lowercase, so user-supplied keys like `"Ctrl-X N"` will match
    /// `"ctrl-x n"` correctly.
    #[must_use]
    pub fn get_action(&self, key: &str) -> Option<&KeyAction> {
        let canonical = canonical_chord(key)?;
        let mut matches = self.bindings.iter().filter(|(candidate, _)| {
            canonical_chord(candidate).as_deref() == Some(canonical.as_str())
        });
        let (_, action) = matches.next()?;
        matches.next().is_none().then_some(action)
    }

    /// Check if a key is bound (returns `false` for disabled or unbound keys).
    #[must_use]
    pub fn is_bound(&self, key: &str) -> bool {
        matches!(self.get_action(key), Some(action) if *action != KeyAction::None)
    }

    /// Get all bindings for a specific action.
    #[must_use]
    pub fn get_keys_for_action(&self, action: &KeyAction) -> Vec<&String> {
        let mut keys = self
            .bindings
            .iter()
            .filter(|(_, a)| *a == action)
            .map(|(k, _)| k)
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    /// Get the action for a key, with `KeyAction::None` as default fallback.
    #[must_use]
    pub fn get_action_or_default(&self, key: &str) -> KeyAction {
        self.get_action(key).cloned().unwrap_or(KeyAction::None)
    }
}

fn canonical_chord(raw: &str) -> Option<String> {
    parse_chord(raw).map(|chord| {
        chord
            .iter()
            .map(super::parser::ParsedKeystroke::display)
            .collect::<Vec<_>>()
            .join(" ")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keybindings_config_default() {
        let config = KeybindingsConfig::default();

        // Verify default bindings exist
        assert_eq!(
            config.bindings.get("ctrl-x n"),
            Some(&KeyAction::NewSession)
        );
        assert_eq!(
            config.bindings.get("ctrl-x l"),
            Some(&KeyAction::ListSessions)
        );
        assert_eq!(config.bindings.get("ctrl-x x"), Some(&KeyAction::Export));
        assert_eq!(config.bindings.get("f2"), Some(&KeyAction::Models));
        assert_eq!(config.bindings.get("tab"), Some(&KeyAction::ToggleMode));
        assert_eq!(config.bindings.get("escape"), Some(&KeyAction::Cancel));
    }

    #[test]
    fn test_keybindings_get_action() {
        let config = KeybindingsConfig::default();

        // Case-insensitive lookup
        assert_eq!(config.get_action("ctrl-x n"), Some(&KeyAction::NewSession));
        assert_eq!(config.get_action("CTRL-X N"), Some(&KeyAction::NewSession));

        // Unknown key returns None
        assert_eq!(config.get_action("unknown-key"), None);
    }

    #[test]
    fn test_keybindings_is_bound() {
        let mut config = KeybindingsConfig::default();

        // Regular binding is bound
        assert!(config.is_bound("ctrl-x n"));

        // Unknown key is not bound
        assert!(!config.is_bound("unknown-key"));

        // Explicitly disabled key (set to None) is not bound
        config
            .bindings
            .insert("disabled-key".to_string(), KeyAction::None);
        assert!(!config.is_bound("disabled-key"));
    }

    #[test]
    fn test_keybindings_get_keys_for_action() {
        let config = KeybindingsConfig::default();

        // Models has two bindings in default config
        let model_keys = config.get_keys_for_action(&KeyAction::Models);
        assert!(model_keys.contains(&&"ctrl-x m".to_string()));
        assert!(model_keys.contains(&&"f2".to_string()));
    }

    #[test]
    fn test_keybindings_get_action_or_default() {
        let config = KeybindingsConfig::default();

        // Known key returns its action
        assert_eq!(
            config.get_action_or_default("ctrl-x n"),
            KeyAction::NewSession
        );

        // Unknown key returns None action
        assert_eq!(config.get_action_or_default("unknown"), KeyAction::None);
    }
}

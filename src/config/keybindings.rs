//! Keybindings configuration schema.
//!
//! Pure YAML-deserializable map of key-combination strings to actions.
//! Runtime logic — chord parsing, resolver, key contexts, lookup helpers —
//! lives in [`crate::keybindings`]. See crosslink #357.

use crate::keybindings::KeyAction;
use serde::Deserialize;
use std::collections::HashMap;

/// Keybindings configuration.
///
/// Maps key-combination strings (case-insensitive, e.g. `"ctrl-x n"`) to
/// [`KeyAction`] variants. Use `KeyAction::None` to disable a binding without
/// removing it.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct KeybindingsConfig {
    /// Map of key combination strings to action names. The
    /// `#[serde(flatten)]` lets every YAML top-level key under `keybindings:`
    /// become a binding entry.
    #[serde(flatten)]
    pub bindings: HashMap<String, KeyAction>,
}

impl Default for KeybindingsConfig {
    fn default() -> Self {
        let mut bindings = HashMap::new();
        // Keys are stored lowercase for case-insensitive lookup.
        bindings.insert("ctrl-x n".to_string(), KeyAction::NewSession);
        bindings.insert("ctrl-x l".to_string(), KeyAction::ListSessions);
        bindings.insert("ctrl-x x".to_string(), KeyAction::Export);
        bindings.insert("ctrl-x y".to_string(), KeyAction::CopyResponse);
        bindings.insert("ctrl-x e".to_string(), KeyAction::Editor);
        bindings.insert("ctrl-x m".to_string(), KeyAction::Models);
        bindings.insert("ctrl-x s".to_string(), KeyAction::Status);
        bindings.insert("ctrl-x h".to_string(), KeyAction::Help);
        bindings.insert("f2".to_string(), KeyAction::Models);
        bindings.insert("tab".to_string(), KeyAction::ToggleMode);
        bindings.insert("escape".to_string(), KeyAction::Cancel);
        Self { bindings }
    }
}

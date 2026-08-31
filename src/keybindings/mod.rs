//! Keybinding runtime logic — action enum, chord parsing, and runtime resolver.
//!
//! `KeybindingsConfig` itself remains in [`crate::config::keybindings`] as a
//! pure YAML-deserializable schema; everything that does more than describe
//! the on-disk shape lives here. See crosslink #357.

pub mod actions;
mod lookup;
pub mod parser;
pub mod resolver;

pub use actions::KeyAction;
pub use parser::{parse_chord, ParsedKeystroke};
pub use resolver::{ChordResolveResult, KeyContext, KeybindingResolver, DEFAULT_CHORD_TIMEOUT};

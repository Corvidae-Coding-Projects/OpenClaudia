//! Chord / keystroke parsing.
//!
//! Translates human-readable keybinding strings such as `"ctrl-x n"` or
//! `"alt-shift-tab"` into structured [`ParsedKeystroke`] sequences for the
//! runtime resolver.

/// A single parsed keystroke such as `ctrl-x` or `alt-shift-n`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ParsedKeystroke {
    /// The base key name (e.g. "x", "n", "f2", "tab").
    pub key: String,
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
}

impl ParsedKeystroke {
    /// Parse a human-readable keystroke string.
    ///
    /// Modifiers (`ctrl`, `alt`, `shift`) are separated from the key name by
    /// `-`. Order of modifiers does not matter. The *last* non-modifier segment
    /// is the key name.
    ///
    /// Examples:
    /// - `"ctrl-x"` -> ctrl=true, key="x"
    /// - `"alt-shift-n"` -> alt=true, shift=true, key="n"
    /// - `"f2"` -> key="f2"
    /// - `"a"` -> key="a"
    /// - `"shift-tab"` -> shift=true, key="tab"
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_lowercase();
        if s.is_empty() {
            return None;
        }

        let parts: Vec<&str> = s.split('-').collect();
        if parts.iter().any(|part| part.is_empty()) {
            return None;
        }

        let mut ctrl = false;
        let mut alt = false;
        let mut shift = false;
        let mut key = None;

        for part in parts {
            match part {
                "ctrl" if key.is_none() && !ctrl => ctrl = true,
                "alt" if key.is_none() && !alt => alt = true,
                "shift" if key.is_none() && !shift => shift = true,
                "ctrl" | "alt" | "shift" => return None,
                _ => {
                    if key.is_some() {
                        return None;
                    }
                    key = canonical_key_name(part);
                }
            }
        }

        Some(Self {
            key: key?,
            ctrl,
            alt,
            shift,
        })
    }

    /// Convert one real crossterm key event into the same canonical shape used
    /// by configuration parsing. Unsupported terminal-only modifier families
    /// return `None` so the frontend can pass the event through unchanged.
    #[must_use]
    pub fn from_key_event(event: &crossterm::event::KeyEvent) -> Option<Self> {
        use crossterm::event::{KeyCode, KeyModifiers};

        if event
            .modifiers
            .intersects(KeyModifiers::SUPER | KeyModifiers::HYPER | KeyModifiers::META)
        {
            return None;
        }

        let (key, back_tab) = match event.code {
            KeyCode::Backspace => ("backspace".to_string(), false),
            KeyCode::Enter => ("enter".to_string(), false),
            KeyCode::Left => ("left".to_string(), false),
            KeyCode::Right => ("right".to_string(), false),
            KeyCode::Up => ("up".to_string(), false),
            KeyCode::Down => ("down".to_string(), false),
            KeyCode::Home => ("home".to_string(), false),
            KeyCode::End => ("end".to_string(), false),
            KeyCode::PageUp => ("pageup".to_string(), false),
            KeyCode::PageDown => ("pagedown".to_string(), false),
            KeyCode::Tab => ("tab".to_string(), false),
            KeyCode::BackTab => ("tab".to_string(), true),
            KeyCode::Delete => ("delete".to_string(), false),
            KeyCode::Insert => ("insert".to_string(), false),
            KeyCode::F(number @ 1..=24) => (format!("f{number}"), false),
            KeyCode::Char(character) => (character.to_lowercase().collect::<String>(), false),
            KeyCode::Esc => ("escape".to_string(), false),
            _ => return None,
        };

        Some(Self {
            key,
            ctrl: event.modifiers.contains(KeyModifiers::CONTROL),
            alt: event.modifiers.contains(KeyModifiers::ALT),
            shift: back_tab || event.modifiers.contains(KeyModifiers::SHIFT),
        })
    }

    /// Human-readable representation, e.g. `"ctrl-x"` or `"alt-shift-n"`.
    #[must_use]
    pub fn display(&self) -> String {
        let mut parts = Vec::new();
        if self.ctrl {
            parts.push("ctrl");
        }
        if self.alt {
            parts.push("alt");
        }
        if self.shift {
            parts.push("shift");
        }
        parts.push(&self.key);
        parts.join("-")
    }
}

fn canonical_key_name(raw: &str) -> Option<String> {
    let named = match raw {
        "esc" | "escape" => Some("escape"),
        "return" | "enter" => Some("enter"),
        "tab" | "backspace" | "delete" | "insert" | "home" | "end" | "pageup" | "pagedown"
        | "up" | "down" | "left" | "right" => Some(raw),
        _ => None,
    };
    if let Some(named) = named {
        return Some(named.to_string());
    }
    if let Some(number) = raw.strip_prefix('f').and_then(|n| n.parse::<u8>().ok()) {
        return (1..=24).contains(&number).then(|| format!("f{number}"));
    }
    let mut characters = raw.chars();
    let character = characters.next()?;
    characters.next().is_none().then(|| character.to_string())
}

/// Parse a chord string (space-separated keystrokes) into a sequence.
///
/// For example `"ctrl-x n"` produces two `ParsedKeystroke` values, while
/// `"f2"` produces one.
#[must_use]
pub fn parse_chord(s: &str) -> Option<Vec<ParsedKeystroke>> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let keystrokes: Option<Vec<ParsedKeystroke>> =
        parts.iter().map(|p| ParsedKeystroke::parse(p)).collect();
    keystrokes.filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // ParsedKeystroke tests
    // ====================================================================

    #[test]
    fn test_parsed_keystroke_ctrl_x() {
        let ks = ParsedKeystroke::parse("ctrl-x").unwrap();
        assert!(ks.ctrl);
        assert!(!ks.alt);
        assert!(!ks.shift);
        assert_eq!(ks.key, "x");
    }

    #[test]
    fn test_parsed_keystroke_alt_n() {
        let ks = ParsedKeystroke::parse("alt-n").unwrap();
        assert!(!ks.ctrl);
        assert!(ks.alt);
        assert!(!ks.shift);
        assert_eq!(ks.key, "n");
    }

    #[test]
    fn test_parsed_keystroke_shift_tab() {
        let ks = ParsedKeystroke::parse("shift-tab").unwrap();
        assert!(!ks.ctrl);
        assert!(!ks.alt);
        assert!(ks.shift);
        assert_eq!(ks.key, "tab");
    }

    #[test]
    fn test_parsed_keystroke_plain_a() {
        let ks = ParsedKeystroke::parse("a").unwrap();
        assert!(!ks.ctrl);
        assert!(!ks.alt);
        assert!(!ks.shift);
        assert_eq!(ks.key, "a");
    }

    #[test]
    fn test_parsed_keystroke_f2() {
        let ks = ParsedKeystroke::parse("f2").unwrap();
        assert!(!ks.ctrl);
        assert!(!ks.alt);
        assert!(!ks.shift);
        assert_eq!(ks.key, "f2");
    }

    #[test]
    fn test_parsed_keystroke_alt_shift_n() {
        let ks = ParsedKeystroke::parse("alt-shift-n").unwrap();
        assert!(!ks.ctrl);
        assert!(ks.alt);
        assert!(ks.shift);
        assert_eq!(ks.key, "n");
    }

    #[test]
    fn test_parsed_keystroke_display() {
        let ks = ParsedKeystroke::parse("ctrl-x").unwrap();
        assert_eq!(ks.display(), "ctrl-x");

        let ks2 = ParsedKeystroke::parse("alt-shift-n").unwrap();
        assert_eq!(ks2.display(), "alt-shift-n");

        let ks3 = ParsedKeystroke::parse("f2").unwrap();
        assert_eq!(ks3.display(), "f2");
    }

    #[test]
    fn test_parsed_keystroke_empty_returns_none() {
        assert!(ParsedKeystroke::parse("").is_none());
        assert!(ParsedKeystroke::parse("   ").is_none());
    }

    #[test]
    fn test_parsed_keystroke_only_modifiers_returns_none() {
        assert!(ParsedKeystroke::parse("ctrl").is_none());
        assert!(ParsedKeystroke::parse("ctrl-alt-shift").is_none());
    }

    // ====================================================================
    // parse_chord tests
    // ====================================================================

    #[test]
    fn test_parse_chord_two_keystrokes() {
        let chord = parse_chord("ctrl-x n").unwrap();
        assert_eq!(chord.len(), 2);

        assert!(chord[0].ctrl);
        assert_eq!(chord[0].key, "x");

        assert!(!chord[1].ctrl);
        assert_eq!(chord[1].key, "n");
    }

    #[test]
    fn test_parse_chord_single_keystroke() {
        let chord = parse_chord("f2").unwrap();
        assert_eq!(chord.len(), 1);
        assert_eq!(chord[0].key, "f2");
    }

    #[test]
    fn test_parse_chord_empty_returns_none() {
        assert!(parse_chord("").is_none());
        assert!(parse_chord("   ").is_none());
    }
}

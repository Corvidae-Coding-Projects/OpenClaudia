//! Runtime keystroke resolver.
//!
//! Buffers incoming keystrokes and matches them against parsed chord
//! bindings loaded from a [`KeybindingsConfig`]. Lives outside `src/config/`
//! because it is runtime logic, not a YAML schema.

use super::actions::KeyAction;
use super::parser::{parse_chord, ParsedKeystroke};
use crate::config::KeybindingsConfig;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Maximum time a frontend waits for another key in a chord.
pub const DEFAULT_CHORD_TIMEOUT: Duration = Duration::from_millis(650);

/// Contexts in which keybindings may apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyContext {
    Global,
    Chat,
    Help,
    Confirmation,
    Transcript,
    Autocomplete,
    ModelPicker,
    Settings,
    /// A provider response is in flight. Only cancellation bindings apply.
    Streaming,
}

/// Result of attempting to resolve a keystroke sequence against the bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChordResolveResult {
    /// The pending keystrokes exactly match a binding.
    Match { action: KeyAction },
    /// The pending keystrokes are a prefix of at least one binding (waiting
    /// for more keys).
    Prefix,
    /// The pending keystrokes do not match or prefix any binding.
    NoMatch,
}

/// A single parsed binding: the chord (sequence of keystrokes) mapped to an
/// action.
#[derive(Debug, Clone)]
struct ParsedBinding {
    chord: Vec<ParsedKeystroke>,
    canonical: String,
    action: KeyAction,
}

/// Runtime resolver that buffers incoming keystrokes and matches them against
/// parsed chord bindings.
#[derive(Debug)]
pub struct KeybindingResolver {
    bindings: Vec<ParsedBinding>,
    pending: Vec<ParsedKeystroke>,
    pending_context: Option<KeyContext>,
    pending_exact: Option<KeyAction>,
    deadline: Option<Instant>,
    replay: Vec<ParsedKeystroke>,
    timeout: Duration,
    diagnostics: Vec<String>,
}

impl KeybindingResolver {
    /// Build a resolver from a `KeybindingsConfig`.
    ///
    /// Invalid and normalized-colliding bindings are disabled deterministically
    /// and exposed through [`Self::diagnostics`].
    #[must_use]
    pub fn from_config(config: &KeybindingsConfig) -> Self {
        let mut sources = config.bindings.iter().collect::<Vec<_>>();
        sources.sort_by_key(|(source, _)| *source);

        let mut by_chord = BTreeMap::<String, ParsedBinding>::new();
        let mut collisions = BTreeMap::<String, Vec<String>>::new();
        let mut diagnostics = Vec::new();
        for (source, action) in sources {
            let Some(chord) = parse_chord(source) else {
                diagnostics.push(format!("invalid keybinding chord '{source}'"));
                continue;
            };
            let canonical = chord
                .iter()
                .map(ParsedKeystroke::display)
                .collect::<Vec<_>>()
                .join(" ");
            if let Some(existing) = collisions.get_mut(&canonical) {
                existing.push(source.clone());
                continue;
            }
            if let Some(previous) = by_chord.remove(&canonical) {
                collisions.insert(canonical, vec![previous.canonical, source.clone()]);
                continue;
            }
            by_chord.insert(
                canonical.clone(),
                ParsedBinding {
                    chord,
                    canonical: source.clone(),
                    action: action.clone(),
                },
            );
        }
        for (canonical, mut sources) in collisions {
            sources.sort();
            diagnostics.push(format!(
                "colliding keybinding chord '{canonical}' from: {}",
                sources.join(", ")
            ));
        }
        Self {
            bindings: by_chord
                .into_iter()
                .map(|(canonical, mut binding)| {
                    binding.canonical = canonical;
                    binding
                })
                .collect(),
            pending: Vec::new(),
            pending_context: None,
            pending_exact: None,
            deadline: None,
            replay: Vec::new(),
            timeout: DEFAULT_CHORD_TIMEOUT,
            diagnostics,
        }
    }

    /// Override the chord timeout for a frontend or deterministic clock test.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout.max(Duration::from_millis(1));
        self
    }

    /// Feed a keystroke into the resolver and get the result.
    ///
    /// - `Match` means the full chord is resolved; pending buffer is cleared.
    /// - `Prefix` means we matched the beginning of at least one chord; keep
    ///   waiting.
    /// - `NoMatch` means no binding starts with the current pending sequence;
    ///   pending buffer is cleared.
    pub fn resolve(&mut self, keystroke: ParsedKeystroke) -> ChordResolveResult {
        self.resolve_in_context_at(KeyContext::Global, keystroke, Instant::now())
    }

    /// Resolve a real input event under the frontend's current modal context.
    pub fn resolve_in_context(
        &mut self,
        context: KeyContext,
        keystroke: ParsedKeystroke,
    ) -> ChordResolveResult {
        self.resolve_in_context_at(context, keystroke, Instant::now())
    }

    /// Clock-injected contextual resolution used by event loops and tests.
    pub fn resolve_in_context_at(
        &mut self,
        context: KeyContext,
        keystroke: ParsedKeystroke,
        now: Instant,
    ) -> ChordResolveResult {
        self.replay.clear();

        if !self.pending.is_empty() && self.pending_context != Some(context) {
            self.replay.append(&mut self.pending);
            self.clear_pending();
        }

        if self.deadline.is_some_and(|deadline| now >= deadline) {
            let fallback = self.pending_exact.take();
            if let Some(action) = fallback {
                self.clear_pending();
                self.replay.push(keystroke);
                return ChordResolveResult::Match { action };
            }
            self.replay.append(&mut self.pending);
            self.clear_pending();
        }

        let fallback = self.pending_exact.clone();
        self.pending.push(keystroke);
        self.pending_context = Some(context);

        let mut exact_match: Option<KeyAction> = None;
        let mut has_prefix = false;

        for binding in self
            .bindings
            .iter()
            .filter(|binding| action_is_available(&binding.action, context))
        {
            let chord = &binding.chord;

            if chord.len() < self.pending.len() {
                continue;
            }

            // Check whether the pending buffer matches the beginning of this chord.
            let prefix_matches = self.pending.iter().zip(chord.iter()).all(|(a, b)| a == b);

            if !prefix_matches {
                continue;
            }

            if chord.len() == self.pending.len() {
                exact_match = Some(binding.action.clone());
            } else {
                // chord is longer than pending -- this is a prefix match.
                has_prefix = true;
            }
        }

        if !has_prefix {
            if let Some(action) = exact_match {
                self.clear_pending();
                return ChordResolveResult::Match { action };
            }
        }

        if has_prefix {
            self.pending_exact = exact_match;
            self.deadline = Some(now + self.timeout);
            ChordResolveResult::Prefix
        } else if let Some(action) = fallback {
            let mismatching = self.pending.pop();
            self.clear_pending();
            self.replay.extend(mismatching);
            ChordResolveResult::Match { action }
        } else {
            self.replay.append(&mut self.pending);
            self.clear_pending();
            ChordResolveResult::NoMatch
        }
    }

    /// Resolve an expired prefix. An exact shorter chord wins at the deadline;
    /// an incomplete prefix is returned through the replay buffer.
    pub fn resolve_timeout(&mut self) -> Option<ChordResolveResult> {
        self.resolve_timeout_at(Instant::now())
    }

    /// Clock-injected timeout resolution.
    pub fn resolve_timeout_at(&mut self, now: Instant) -> Option<ChordResolveResult> {
        if self.deadline.is_none_or(|deadline| now < deadline) || self.pending.is_empty() {
            return None;
        }
        self.replay.clear();
        let fallback = self.pending_exact.take();
        if let Some(action) = fallback {
            self.clear_pending();
            Some(ChordResolveResult::Match { action })
        } else {
            self.replay.append(&mut self.pending);
            self.clear_pending();
            Some(ChordResolveResult::NoMatch)
        }
    }

    /// Keystrokes that did not belong to a resolved command. Frontends must
    /// replay these through their ordinary input path in the original order.
    pub fn take_replay(&mut self) -> Vec<ParsedKeystroke> {
        std::mem::take(&mut self.replay)
    }

    /// Deterministic diagnostics produced while compiling the configured map.
    #[must_use]
    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }

    /// The normalized, collision-free map that is reachable in `context`.
    #[must_use]
    pub fn effective_bindings(&self, context: KeyContext) -> Vec<(String, KeyAction)> {
        self.bindings
            .iter()
            .filter(|binding| action_is_available(&binding.action, context))
            .map(|binding| (binding.canonical.clone(), binding.action.clone()))
            .collect()
    }

    /// Cancel any pending chord, clearing the buffer.
    pub fn cancel(&mut self) {
        self.clear_pending();
        self.replay.clear();
    }

    /// Whether the resolver is waiting for more keystrokes to complete a chord.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Human-readable representation of the pending keystrokes so far (e.g.
    /// for status-bar display).
    #[must_use]
    pub fn pending_display(&self) -> String {
        self.pending
            .iter()
            .map(ParsedKeystroke::display)
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn clear_pending(&mut self) {
        self.pending.clear();
        self.pending_context = None;
        self.pending_exact = None;
        self.deadline = None;
    }
}

const fn action_is_available(action: &KeyAction, context: KeyContext) -> bool {
    if matches!(action, KeyAction::None) {
        return true;
    }
    match context {
        KeyContext::Global | KeyContext::Chat => true,
        KeyContext::Streaming | KeyContext::Confirmation => {
            matches!(action, KeyAction::Cancel)
        }
        KeyContext::Help => matches!(action, KeyAction::Cancel | KeyAction::Help),
        KeyContext::Transcript
        | KeyContext::Autocomplete
        | KeyContext::ModelPicker
        | KeyContext::Settings => matches!(action, KeyAction::Cancel | KeyAction::Help),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Helper: build a config with specific bindings.
    fn test_config(bindings: Vec<(&str, KeyAction)>) -> KeybindingsConfig {
        let mut map = HashMap::new();
        for (k, a) in bindings {
            map.insert(k.to_string(), a);
        }
        KeybindingsConfig { bindings: map }
    }

    #[test]
    fn test_resolver_single_key_match() {
        let config = test_config(vec![("f2", KeyAction::Models)]);
        let mut resolver = KeybindingResolver::from_config(&config);

        let result = resolver.resolve(ParsedKeystroke::parse("f2").unwrap());
        assert_eq!(
            result,
            ChordResolveResult::Match {
                action: KeyAction::Models
            }
        );
        assert!(!resolver.is_pending());
    }

    #[test]
    fn test_resolver_chord_prefix() {
        let config = test_config(vec![("ctrl-x n", KeyAction::NewSession)]);
        let mut resolver = KeybindingResolver::from_config(&config);

        // First keystroke is a prefix
        let result = resolver.resolve(ParsedKeystroke::parse("ctrl-x").unwrap());
        assert_eq!(result, ChordResolveResult::Prefix);
        assert!(resolver.is_pending());
        assert_eq!(resolver.pending_display(), "ctrl-x");
    }

    #[test]
    fn test_resolver_chord_complete() {
        let config = test_config(vec![("ctrl-x n", KeyAction::NewSession)]);
        let mut resolver = KeybindingResolver::from_config(&config);

        // First keystroke: prefix
        let r1 = resolver.resolve(ParsedKeystroke::parse("ctrl-x").unwrap());
        assert_eq!(r1, ChordResolveResult::Prefix);

        // Second keystroke: match
        let r2 = resolver.resolve(ParsedKeystroke::parse("n").unwrap());
        assert_eq!(
            r2,
            ChordResolveResult::Match {
                action: KeyAction::NewSession
            }
        );
        assert!(!resolver.is_pending());
    }

    #[test]
    fn test_resolver_no_match() {
        let config = test_config(vec![("f2", KeyAction::Models)]);
        let mut resolver = KeybindingResolver::from_config(&config);

        let result = resolver.resolve(ParsedKeystroke::parse("f5").unwrap());
        assert_eq!(result, ChordResolveResult::NoMatch);
        assert!(!resolver.is_pending());
    }

    #[test]
    fn test_resolver_no_match_after_prefix() {
        let config = test_config(vec![("ctrl-x n", KeyAction::NewSession)]);
        let mut resolver = KeybindingResolver::from_config(&config);

        // First keystroke is a prefix
        let r1 = resolver.resolve(ParsedKeystroke::parse("ctrl-x").unwrap());
        assert_eq!(r1, ChordResolveResult::Prefix);

        // Second keystroke does not complete any chord
        let r2 = resolver.resolve(ParsedKeystroke::parse("z").unwrap());
        assert_eq!(r2, ChordResolveResult::NoMatch);
        assert!(!resolver.is_pending());
    }

    #[test]
    fn test_resolver_cancel() {
        let config = test_config(vec![("ctrl-x n", KeyAction::NewSession)]);
        let mut resolver = KeybindingResolver::from_config(&config);

        let _ = resolver.resolve(ParsedKeystroke::parse("ctrl-x").unwrap());
        assert!(resolver.is_pending());

        resolver.cancel();
        assert!(!resolver.is_pending());
        assert_eq!(resolver.pending_display(), "");
    }

    #[test]
    fn test_resolver_multiple_bindings() {
        let config = test_config(vec![
            ("ctrl-x n", KeyAction::NewSession),
            ("ctrl-x l", KeyAction::ListSessions),
            ("f2", KeyAction::Models),
        ]);
        let mut resolver = KeybindingResolver::from_config(&config);

        // f2 matches immediately
        let r = resolver.resolve(ParsedKeystroke::parse("f2").unwrap());
        assert_eq!(
            r,
            ChordResolveResult::Match {
                action: KeyAction::Models
            }
        );

        // ctrl-x is prefix for two chords
        let r = resolver.resolve(ParsedKeystroke::parse("ctrl-x").unwrap());
        assert_eq!(r, ChordResolveResult::Prefix);

        // l completes to ListSessions
        let r = resolver.resolve(ParsedKeystroke::parse("l").unwrap());
        assert_eq!(
            r,
            ChordResolveResult::Match {
                action: KeyAction::ListSessions
            }
        );
    }

    #[test]
    fn test_resolver_from_default_config() {
        let config = KeybindingsConfig::default();
        let mut resolver = KeybindingResolver::from_config(&config);

        // Default config has "ctrl-x n" -> NewSession
        let r1 = resolver.resolve(ParsedKeystroke::parse("ctrl-x").unwrap());
        assert_eq!(r1, ChordResolveResult::Prefix);

        let r2 = resolver.resolve(ParsedKeystroke::parse("n").unwrap());
        assert_eq!(
            r2,
            ChordResolveResult::Match {
                action: KeyAction::NewSession
            }
        );
    }

    #[test]
    fn shorter_exact_binding_wins_on_prefix_timeout() {
        let config = test_config(vec![("g", KeyAction::Help), ("g g", KeyAction::Status)]);
        let start = Instant::now();
        let mut resolver =
            KeybindingResolver::from_config(&config).with_timeout(Duration::from_millis(10));

        assert_eq!(
            resolver.resolve_in_context_at(
                KeyContext::Chat,
                ParsedKeystroke::parse("g").unwrap(),
                start,
            ),
            ChordResolveResult::Prefix
        );
        assert_eq!(
            resolver.resolve_timeout_at(start + Duration::from_millis(10)),
            Some(ChordResolveResult::Match {
                action: KeyAction::Help,
            })
        );
        assert!(resolver.take_replay().is_empty());
    }

    #[test]
    fn shorter_exact_binding_executes_and_replays_mismatch() {
        let config = test_config(vec![("g", KeyAction::Help), ("g g", KeyAction::Status)]);
        let mut resolver = KeybindingResolver::from_config(&config);

        assert_eq!(
            resolver.resolve_in_context(KeyContext::Chat, ParsedKeystroke::parse("g").unwrap(),),
            ChordResolveResult::Prefix
        );
        assert_eq!(
            resolver.resolve_in_context(KeyContext::Chat, ParsedKeystroke::parse("λ").unwrap(),),
            ChordResolveResult::Match {
                action: KeyAction::Help,
            }
        );
        assert_eq!(
            resolver.take_replay(),
            vec![ParsedKeystroke::parse("λ").unwrap()]
        );
    }

    #[test]
    fn incomplete_unicode_chord_replays_every_original_keystroke() {
        let config = test_config(vec![("λ x", KeyAction::Help)]);
        let mut resolver = KeybindingResolver::from_config(&config);

        assert_eq!(
            resolver.resolve_in_context(KeyContext::Chat, ParsedKeystroke::parse("λ").unwrap(),),
            ChordResolveResult::Prefix
        );
        assert_eq!(
            resolver.resolve_in_context(KeyContext::Chat, ParsedKeystroke::parse("β").unwrap(),),
            ChordResolveResult::NoMatch
        );
        assert_eq!(
            resolver.take_replay(),
            vec![
                ParsedKeystroke::parse("λ").unwrap(),
                ParsedKeystroke::parse("β").unwrap(),
            ]
        );
    }

    #[test]
    fn streaming_context_exposes_only_cancel_bindings() {
        let config = test_config(vec![
            ("f2", KeyAction::Models),
            ("escape", KeyAction::Cancel),
        ]);
        let mut resolver = KeybindingResolver::from_config(&config);

        assert_eq!(
            resolver
                .resolve_in_context(KeyContext::Streaming, ParsedKeystroke::parse("f2").unwrap(),),
            ChordResolveResult::NoMatch
        );
        assert_eq!(
            resolver.resolve_in_context(
                KeyContext::Streaming,
                ParsedKeystroke::parse("escape").unwrap(),
            ),
            ChordResolveResult::Match {
                action: KeyAction::Cancel,
            }
        );
    }

    #[test]
    fn normalized_collisions_are_disabled_with_diagnostics() {
        let config = test_config(vec![
            ("CTRL-X", KeyAction::Help),
            ("ctrl-x", KeyAction::Status),
        ]);
        let resolver = KeybindingResolver::from_config(&config);

        assert!(resolver.effective_bindings(KeyContext::Chat).is_empty());
        assert_eq!(resolver.diagnostics().len(), 1);
        assert!(resolver.diagnostics()[0].contains("colliding keybinding chord 'ctrl-x'"));
    }
}

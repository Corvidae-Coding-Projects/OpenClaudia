//! Legacy LSP diagnostic staging retained for compatibility.
//!
//! Language servers emit `textDocument/publishDiagnostics` notifications
//! asynchronously: a request like `goToDefinition` triggers a full
//! background re-analysis that may yield warnings/errors several
//! seconds after the original tool call has returned.
//! [`crate::services::LspServerManager`] now drains notifications during a
//! bounded protocol turn and publishes capability-validated, versioned typed
//! data in the LSP tool result.
//!
//! Production does not construct this registry or inject its rendered text.
//! This older shape lacks workspace/generation/document-version identity,
//! aggregate byte budgets, and an untrusted-evidence boundary; it is therefore
//! not the production notification path.
//!
//! ## What ships
//!
//! * [`Diagnostic`] — lossy staging projection of an LSP diagnostic.
//! * [`DiagnosticRegistry`] — legacy thread-safe accumulator keyed by file
//!   URI for compatibility tests and downstream callers.
//! * [`DiagnosticInjector`] — trait the conversation layer
//!   (`session.rs` / `pipeline.rs`) implements to splice the
//!   accumulated diagnostics into the next assistant turn as a
//!   `<lsp-diagnostics>` block.
//! * [`NoopDiagnosticInjector`] — explicit library/test discard behavior; it
//!   is not a production fallback.
//!
//! New code should consume [`crate::services::LspDiagnosticPublication`]
//! instead of injecting this registry's rendered XML into a later prompt.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use tracing::error;

/// LSP `DiagnosticSeverity` (LSP §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    /// `1` on the wire — compilation-blocking issue.
    Error,
    /// `2` on the wire — non-fatal.
    Warning,
    /// `3` on the wire — informational only.
    Information,
    /// `4` on the wire — code-style hint.
    Hint,
}

impl DiagnosticSeverity {
    /// Wire integer per LSP spec.
    #[must_use]
    pub const fn wire(&self) -> u8 {
        match self {
            Self::Error => 1,
            Self::Warning => 2,
            Self::Information => 3,
            Self::Hint => 4,
        }
    }

    /// Decode an LSP wire integer (defaults to `Information` for
    /// out-of-range values so a stray notification can never panic).
    #[must_use]
    pub const fn from_wire(n: u8) -> Self {
        match n {
            1 => Self::Error,
            2 => Self::Warning,
            4 => Self::Hint,
            _ => Self::Information,
        }
    }
}

/// One LSP diagnostic projected onto an OC-friendly shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Diagnostic {
    /// 1-based line number where the diagnostic starts (matches
    /// `parse_locations`' line-conversion convention).
    pub line: u32,
    /// 0-based character offset.
    pub character: u32,
    /// Severity discriminator.
    pub severity: DiagnosticSeverity,
    /// Server-supplied message body.
    pub message: String,
    /// Diagnostic source ("rust-analyzer", "tsserver", etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Thread-safe staging accumulator (crosslink #638).
///
/// A per-URI count cap truncates each supplied vector. URI count and aggregate
/// bytes remain unbounded, and the type carries no ordering/version proof;
/// callers must not treat it as a production bounded FIFO.
pub struct DiagnosticRegistry {
    inner: Mutex<HashMap<String, Vec<Diagnostic>>>,
    per_file_cap: usize,
}

/// Default per-file cap. Tuned for typical Rust diagnostic densities;
/// override via [`DiagnosticRegistry::with_cap`] when a noisy server
/// (clangd over a large project) needs more headroom.
pub const DEFAULT_PER_FILE_CAP: usize = 64;

impl Default for DiagnosticRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DiagnosticRegistry {
    /// Build a registry with the default per-file cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_cap(DEFAULT_PER_FILE_CAP)
    }

    /// Build a registry with a custom per-file cap.
    #[must_use]
    pub fn with_cap(per_file_cap: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            per_file_cap: per_file_cap.max(1),
        }
    }

    fn inner_guard(
        &self,
        operation: &'static str,
    ) -> Option<MutexGuard<'_, HashMap<String, Vec<Diagnostic>>>> {
        match self.inner.lock() {
            Ok(guard) => Some(guard),
            Err(err) => {
                error!(operation, error = %err, "LSP diagnostic registry lock poisoned");
                None
            }
        }
    }

    /// Replace the entire diagnostic list for `uri` (matches LSP's
    /// `publishDiagnostics` semantics — each publish is a full
    /// replacement for that file).
    pub fn set(&self, uri: &str, diagnostics: Vec<Diagnostic>) {
        let mut diags = diagnostics;
        if diags.len() > self.per_file_cap {
            // Keep the most recent N. LSP servers emit newest-first
            // sometimes, oldest-first others — we don't try to be
            // clever, we just bound the storage.
            diags.truncate(self.per_file_cap);
        }
        if let Some(mut g) = self.inner_guard("set") {
            if diags.is_empty() {
                g.remove(uri);
            } else {
                g.insert(uri.to_string(), diags);
            }
        }
    }

    /// Borrow-clone every diagnostic currently held for `uri`.
    #[must_use]
    pub fn get(&self, uri: &str) -> Vec<Diagnostic> {
        self.inner_guard("get")
            .and_then(|g| g.get(uri).cloned())
            .unwrap_or_default()
    }

    /// Drain every accumulated diagnostic and return them grouped by URI.
    /// The registry is empty after this call — used by injectors at
    /// turn boundaries.
    pub fn drain(&self) -> HashMap<String, Vec<Diagnostic>> {
        self.inner_guard("drain")
            .map_or_else(HashMap::new, |mut g| std::mem::take(&mut *g))
    }

    /// Total diagnostic count across every URI.
    #[must_use]
    pub fn total(&self) -> usize {
        self.inner_guard("total")
            .map_or(0, |g| g.values().map(Vec::len).sum())
    }
}

/// Trait the conversation layer implements to splice diagnostics into
/// the next assistant turn (crosslink #640).
///
/// Implementations decide *how* the block is rendered (a system
/// message, an extra tool-result, a sidebar). The trait only contracts
/// the consumption shape.
pub trait DiagnosticInjector: Send + Sync {
    /// Render `diagnostics` into a message body the next turn can
    /// consume. Returns `None` when there are no diagnostics worth
    /// injecting (empty input, or implementation chose to suppress).
    fn render(&self, diagnostics: &HashMap<String, Vec<Diagnostic>>) -> Option<String>;
}

/// Safe default: drop every accumulated diagnostic. Used in
/// non-interactive / batch modes where surfacing diagnostics to the
/// model would just add noise.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDiagnosticInjector;

impl DiagnosticInjector for NoopDiagnosticInjector {
    fn render(&self, _diagnostics: &HashMap<String, Vec<Diagnostic>>) -> Option<String> {
        None
    }
}

/// Reference renderer (crosslink #640).
///
/// Produces an `<lsp-diagnostics>` block with one line per diagnostic,
/// grouped by file. Intended as the default for interactive sessions;
/// tests can swap a custom impl that renders to another shape.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultDiagnosticInjector;

impl DiagnosticInjector for DefaultDiagnosticInjector {
    fn render(&self, diagnostics: &HashMap<String, Vec<Diagnostic>>) -> Option<String> {
        use std::fmt::Write;
        if diagnostics.is_empty() {
            return None;
        }
        // Deterministic ordering by URI so tests pin output stably.
        let mut entries: Vec<(&String, &Vec<Diagnostic>)> = diagnostics.iter().collect();
        entries.sort_by_key(|(uri, _)| *uri);

        let mut out = String::new();
        out.push_str("<lsp-diagnostics>\n");
        let mut rendered_any = false;
        for (uri, diags) in entries {
            if diags.is_empty() {
                continue;
            }
            rendered_any = true;
            out.push_str("  file: ");
            out.push_str(uri);
            out.push('\n');
            for d in diags {
                let src = d
                    .source
                    .as_ref()
                    .map_or_else(String::new, |s| format!(" ({s})"));
                let _ = writeln!(
                    out,
                    "    {sev} at {line}:{ch}: {msg}{src}",
                    sev = severity_label(d.severity),
                    line = d.line,
                    ch = d.character,
                    msg = d.message,
                );
            }
        }
        if !rendered_any {
            return None;
        }
        out.push_str("</lsp-diagnostics>");
        Some(out)
    }
}

const fn severity_label(s: DiagnosticSeverity) -> &'static str {
    match s {
        DiagnosticSeverity::Error => "error",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Information => "info",
        DiagnosticSeverity::Hint => "hint",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(line: u32, msg: &str, sev: DiagnosticSeverity) -> Diagnostic {
        Diagnostic {
            line,
            character: 0,
            severity: sev,
            message: msg.to_string(),
            source: Some("rust-analyzer".to_string()),
        }
    }

    #[test]
    fn severity_wire_roundtrip() {
        for sev in [
            DiagnosticSeverity::Error,
            DiagnosticSeverity::Warning,
            DiagnosticSeverity::Information,
            DiagnosticSeverity::Hint,
        ] {
            assert_eq!(DiagnosticSeverity::from_wire(sev.wire()), sev);
        }
    }

    #[test]
    fn severity_from_wire_invalid_defaults_information() {
        assert_eq!(
            DiagnosticSeverity::from_wire(99),
            DiagnosticSeverity::Information
        );
    }

    #[test]
    fn registry_set_and_get_round_trips() {
        let reg = DiagnosticRegistry::new();
        let diags = vec![d(10, "missing semicolon", DiagnosticSeverity::Error)];
        reg.set("file:///a.rs", diags.clone());
        assert_eq!(reg.get("file:///a.rs"), diags);
    }

    #[test]
    fn registry_set_empty_removes_entry() {
        let reg = DiagnosticRegistry::new();
        reg.set("file:///a.rs", vec![d(1, "x", DiagnosticSeverity::Error)]);
        assert_eq!(reg.total(), 1);
        reg.set("file:///a.rs", Vec::new());
        assert_eq!(reg.total(), 0);
    }

    #[test]
    fn registry_caps_per_file() {
        let reg = DiagnosticRegistry::with_cap(2);
        let diags = vec![
            d(1, "a", DiagnosticSeverity::Error),
            d(2, "b", DiagnosticSeverity::Warning),
            d(3, "c", DiagnosticSeverity::Hint),
        ];
        reg.set("file:///x.rs", diags);
        assert_eq!(reg.get("file:///x.rs").len(), 2);
    }

    #[test]
    fn registry_drain_empties_state() {
        let reg = DiagnosticRegistry::new();
        reg.set("file:///a.rs", vec![d(1, "x", DiagnosticSeverity::Error)]);
        reg.set("file:///b.rs", vec![d(2, "y", DiagnosticSeverity::Warning)]);
        let drained = reg.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(reg.total(), 0);
    }

    #[test]
    fn noop_injector_returns_none() {
        let mut map = HashMap::new();
        map.insert(
            "file:///a.rs".to_string(),
            vec![d(1, "x", DiagnosticSeverity::Error)],
        );
        assert!(NoopDiagnosticInjector.render(&map).is_none());
    }

    #[test]
    fn default_injector_renders_block() {
        let mut map = HashMap::new();
        map.insert(
            "file:///a.rs".to_string(),
            vec![d(10, "unused variable", DiagnosticSeverity::Warning)],
        );
        let body = DefaultDiagnosticInjector.render(&map).unwrap();
        assert!(body.starts_with("<lsp-diagnostics>"));
        assert!(body.ends_with("</lsp-diagnostics>"));
        assert!(body.contains("file:///a.rs"));
        assert!(body.contains("warning at 10:0: unused variable"));
        assert!(body.contains("(rust-analyzer)"));
    }

    #[test]
    fn default_injector_empty_input_returns_none() {
        let map = HashMap::new();
        assert!(DefaultDiagnosticInjector.render(&map).is_none());
    }

    #[test]
    fn default_injector_empty_diagnostic_entries_return_none() {
        let mut map = HashMap::new();
        map.insert("file:///empty.rs".to_string(), Vec::new());
        assert!(DefaultDiagnosticInjector.render(&map).is_none());
    }
}

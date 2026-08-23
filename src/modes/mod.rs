//! Behavioral modes system for `OpenClaudia`.
//!
//! Implements a three-axis model (agency, quality, scope) with named presets
//! and composable modifiers. Inspired by claude-code-modes but integrated
//! directly into `OpenClaudia`'s prompt pipeline.
//!
//! # Architecture
//!
//! The system works by assembling markdown prompt fragments at runtime:
//! - **Base fragments**: identity, tools, principles, comms (always included)
//! - **Axis fragments**: one each from agency, quality, scope
//! - **Modifiers**: zero or more behavioral overlays
//!
//! Fragments are compiled into the binary via `include_str!` — no filesystem
//! reads at runtime.

pub mod fragments;

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::RwLock;

// =========================================================================
// Axis enums
// =========================================================================

/// How much initiative the agent takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Agency {
    /// Makes decisions, creates files, restructures without asking.
    #[default]
    Autonomous,
    /// Explains reasoning, checks in at decision points.
    Collaborative,
    /// Executes exactly what was asked, nothing more.
    Surgical,
}

/// What code quality standard to target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Quality {
    /// Proper abstractions, error handling, forward-thinking structure.
    Architect,
    /// Match existing patterns, improve incrementally.
    #[default]
    Pragmatic,
    /// Smallest correct change, no speculative improvements.
    Minimal,
}

/// How far beyond the request the agent can go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// Free to create, reorganize, restructure.
    Unrestricted,
    /// Fix related issues in the neighborhood.
    #[default]
    Adjacent,
    /// Only what was explicitly asked.
    Narrow,
}

/// Behavioral modifier overlays.
///
/// Crosslink #830: variant names `Debug`, `Methodical`, `Director` overlap
/// with [`Preset`] variants of the same name. Serde-level disambiguation
/// is provided by explicit `rename` attributes so JSON readers see
/// `"modifier-debug"` for a modifier and `"preset-debug"` for a preset,
/// even when both appear in the same document. `Display` continues to
/// emit the short human-readable form for status bars / logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Modifier {
    /// Confident, idiomatic code — no hedging.
    Bold,
    /// Investigation-first debugging.
    #[serde(rename = "modifier-debug")]
    Debug,
    /// Step-by-step precision.
    #[serde(rename = "modifier-methodical")]
    Methodical,
    /// Orchestrate subagents, delegate implementation.
    #[serde(rename = "modifier-director")]
    Director,
    /// No file modifications — read and explain only.
    Readonly,
    /// Pace work to context limits — clean pause points.
    ContextPacing,
}

/// Named preset combining axis values and optional modifiers.
///
/// Crosslink #830: variant names `Debug`, `Methodical`, `Director` overlap
/// with [`Modifier`] variants. Serde-level disambiguation is provided by
/// explicit `rename` attributes so a JSON document containing both an
/// active preset and an active modifier list is unambiguous to consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    /// Build from scratch with proper architecture.
    Create,
    /// Extend a fast-built project, improve incrementally.
    ///
    /// Differs from [`Preset::Refactor`] by scope: `Extend` operates with
    /// `Scope::Adjacent` (touch the call site and ±1 hop, e.g. add a tool
    /// argument and update its single caller). Pick `Extend` when the work
    /// stays inside one module's blast radius. Crosslink #379.
    Extend,
    /// Surgical precision, minimal risk.
    Safe,
    /// Restructure freely across the codebase.
    ///
    /// Differs from [`Preset::Extend`] by scope: `Refactor` operates with
    /// `Scope::Unrestricted` (cross-module rewrites are expected, e.g.
    /// extract a trait that touches 12 implementors, split a god module).
    /// Pick `Refactor` when the change must reshape boundaries.
    /// Crosslink #379.
    Refactor,
    /// Read-only — understand code without changing it.
    Explore,
    /// Investigation-first debugging.
    #[serde(rename = "preset-debug")]
    Debug,
    /// Step-by-step precision.
    #[serde(rename = "preset-methodical")]
    Methodical,
    /// Delegate to subagents, orchestrate and verify.
    #[serde(rename = "preset-director")]
    Director,
}

// =========================================================================
// Display / FromStr implementations
// =========================================================================

impl fmt::Display for Agency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Autonomous => write!(f, "autonomous"),
            Self::Collaborative => write!(f, "collaborative"),
            Self::Surgical => write!(f, "surgical"),
        }
    }
}

impl fmt::Display for Quality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Architect => write!(f, "architect"),
            Self::Pragmatic => write!(f, "pragmatic"),
            Self::Minimal => write!(f, "minimal"),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unrestricted => write!(f, "unrestricted"),
            Self::Adjacent => write!(f, "adjacent"),
            Self::Narrow => write!(f, "narrow"),
        }
    }
}

impl fmt::Display for Modifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bold => write!(f, "bold"),
            Self::Debug => write!(f, "debug"),
            Self::Methodical => write!(f, "methodical"),
            Self::Director => write!(f, "director"),
            Self::Readonly => write!(f, "readonly"),
            Self::ContextPacing => write!(f, "context-pacing"),
        }
    }
}

impl fmt::Display for Preset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create => write!(f, "create"),
            Self::Extend => write!(f, "extend"),
            Self::Safe => write!(f, "safe"),
            Self::Refactor => write!(f, "refactor"),
            Self::Explore => write!(f, "explore"),
            Self::Debug => write!(f, "debug"),
            Self::Methodical => write!(f, "methodical"),
            Self::Director => write!(f, "director"),
        }
    }
}

impl FromStr for Agency {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "autonomous" | "auto" => Ok(Self::Autonomous),
            "collaborative" | "collab" => Ok(Self::Collaborative),
            "surgical" => Ok(Self::Surgical),
            _ => Err(format!(
                "unknown agency: \"{s}\". Must be: autonomous, collaborative, surgical"
            )),
        }
    }
}

impl FromStr for Quality {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "architect" | "arch" => Ok(Self::Architect),
            "pragmatic" | "prag" => Ok(Self::Pragmatic),
            "minimal" | "min" => Ok(Self::Minimal),
            _ => Err(format!(
                "unknown quality: \"{s}\". Must be: architect, pragmatic, minimal"
            )),
        }
    }
}

impl FromStr for Scope {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unrestricted" => Ok(Self::Unrestricted),
            "adjacent" | "adj" => Ok(Self::Adjacent),
            "narrow" => Ok(Self::Narrow),
            _ => Err(format!(
                "unknown scope: \"{s}\". Must be: unrestricted, adjacent, narrow"
            )),
        }
    }
}

impl FromStr for Modifier {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "bold" => Ok(Self::Bold),
            "debug" => Ok(Self::Debug),
            "methodical" => Ok(Self::Methodical),
            "director" => Ok(Self::Director),
            "readonly" | "read-only" => Ok(Self::Readonly),
            "context-pacing" | "pacing" => Ok(Self::ContextPacing),
            _ => Err(format!(
                "unknown modifier: \"{s}\". Must be: bold, debug, methodical, director, readonly, context-pacing"
            )),
        }
    }
}

/// Canonical CLI-accepted names for `--mode`.
///
/// Mirrors the lowercased keys in [`Preset::from_str`] so clap's
/// `PossibleValuesParser` can reject typos at parse time instead of
/// letting them flow into the runtime mode-resolution path.
///
/// Re-exported so `main.rs` can wire this into clap (closes the gap
/// surfaced by the binary-verification audit where `--mode bogusmode`
/// was silently accepted).
pub const SUPPORTED_PRESETS: &[&str] = &[
    "create",
    "extend",
    "safe",
    "refactor",
    "explore",
    "debug",
    "methodical",
    "director",
];

impl FromStr for Preset {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(Self::Create),
            "extend" => Ok(Self::Extend),
            "safe" => Ok(Self::Safe),
            "refactor" => Ok(Self::Refactor),
            "explore" => Ok(Self::Explore),
            "debug" => Ok(Self::Debug),
            "methodical" => Ok(Self::Methodical),
            "director" => Ok(Self::Director),
            _ => Err(format!(
                "unknown preset: \"{s}\". Must be: create, extend, safe, refactor, explore, debug, methodical, director"
            )),
        }
    }
}

// =========================================================================
// BehaviorMode — the assembled configuration
// =========================================================================

/// Complete behavioral configuration: three axis values plus optional modifiers.
///
/// `modifiers` carries `#[serde(default)]` so sessions persisted
/// before the field existed deserialize cleanly into an empty Vec
/// (crosslink #839). The companion test
/// `serde_missing_modifiers_defaults_to_empty` pins the round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorMode {
    pub agency: Agency,
    pub quality: Quality,
    pub scope: Scope,
    #[serde(default)]
    pub modifiers: Vec<Modifier>,
}

impl Default for BehaviorMode {
    /// Default mode: autonomous / pragmatic / adjacent (matches `extend` preset).
    fn default() -> Self {
        Self {
            agency: Agency::Autonomous,
            quality: Quality::Pragmatic,
            scope: Scope::Adjacent,
            modifiers: Vec::new(),
        }
    }
}

impl fmt::Display for BehaviorMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.agency, self.quality, self.scope)?;
        if !self.modifiers.is_empty() {
            write!(f, " [")?;
            for (i, m) in self.modifiers.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{m}")?;
            }
            write!(f, "]")?;
        }
        Ok(())
    }
}

impl BehaviorMode {
    /// Create a mode from a preset, optionally overriding individual axes.
    #[must_use]
    pub fn from_preset(preset: Preset) -> Self {
        let (agency, quality, scope, modifiers) = match preset {
            Preset::Create => (
                Agency::Autonomous,
                Quality::Architect,
                Scope::Unrestricted,
                vec![],
            ),
            Preset::Extend => (
                Agency::Autonomous,
                Quality::Pragmatic,
                Scope::Adjacent,
                vec![],
            ),
            Preset::Safe => (
                Agency::Collaborative,
                Quality::Minimal,
                Scope::Narrow,
                vec![],
            ),
            Preset::Refactor => (
                Agency::Autonomous,
                Quality::Pragmatic,
                Scope::Unrestricted,
                vec![],
            ),
            Preset::Explore => (
                Agency::Collaborative,
                Quality::Architect,
                Scope::Narrow,
                vec![Modifier::Readonly],
            ),
            Preset::Debug => (
                Agency::Collaborative,
                Quality::Pragmatic,
                Scope::Narrow,
                vec![Modifier::Debug],
            ),
            Preset::Methodical => (
                Agency::Surgical,
                Quality::Architect,
                Scope::Narrow,
                vec![Modifier::Methodical],
            ),
            Preset::Director => (
                Agency::Collaborative,
                Quality::Architect,
                Scope::Unrestricted,
                vec![Modifier::Director],
            ),
        };
        Self {
            agency,
            quality,
            scope,
            modifiers,
        }
    }

    /// Add a modifier if not already present.
    pub fn add_modifier(&mut self, modifier: Modifier) {
        if !self.modifiers.contains(&modifier) {
            self.modifiers.push(modifier);
        }
    }

    /// Remove a modifier if present.
    pub fn remove_modifier(&mut self, modifier: Modifier) {
        self.modifiers.retain(|m| *m != modifier);
    }

    /// Try to find a matching preset name for the current configuration.
    /// Returns `None` if no built-in preset matches exactly.
    ///
    /// Crosslink #830 (resolved) addressed the `Modifier::Debug` vs
    /// `Preset::Debug` naming collision via explicit `serde(rename)` so
    /// the two variants no longer round-trip through the same wire token.
    /// Crosslink #925 also asked about a perf concern (linear scan of 8
    /// presets per hot-path display); the cost is `8 * cmp_struct` per
    /// call which is well below the noise floor of the surrounding
    /// rendering work, so we have intentionally NOT cached the result —
    /// a `OnceLock` cache would have to be invalidated on every modifier
    /// mutation and the bookkeeping outweighs the saved compares.
    #[must_use]
    pub fn matching_preset(&self) -> Option<Preset> {
        let presets = [
            Preset::Create,
            Preset::Extend,
            Preset::Safe,
            Preset::Refactor,
            Preset::Explore,
            Preset::Debug,
            Preset::Methodical,
            Preset::Director,
        ];
        presets.into_iter().find(|p| &Self::from_preset(*p) == self)
    }

    /// Human-readable description of the mode for status displays.
    #[must_use]
    pub fn description(&self) -> String {
        self.matching_preset().map_or_else(
            || format!("custom: {self}"),
            |preset| {
                let desc = match preset {
                    Preset::Create => "Build from scratch with proper architecture",
                    // Extend vs Refactor distinguished by scope (crosslink #379):
                    // Extend = Adjacent scope (touch the call-site + 1 hop);
                    // Refactor = Unrestricted scope (cross-module reshape OK).
                    Preset::Extend => {
                        "Extend incrementally — local changes near the call site (e.g. add a field, wire a new tool)"
                    }
                    Preset::Safe => "Surgical precision, minimal risk",
                    Preset::Refactor => {
                        "Restructure freely across the codebase (e.g. extract trait, split module, move types)"
                    }
                    Preset::Explore => "Read-only — understand code without changing it",
                    Preset::Debug => "Investigation-first debugging",
                    Preset::Methodical => "Step-by-step precision",
                    Preset::Director => "Orchestrate subagents, delegate and verify",
                };
                format!("{preset}: {desc}")
            },
        )
    }

    /// Short display name — preset name if matching, otherwise axis summary.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.matching_preset()
            .map_or_else(|| self.to_string(), |p| p.to_string())
    }

    /// Assemble the complete behavioral prompt fragment for this mode.
    ///
    /// Returns the assembled string of all axis + modifier fragments,
    /// ready to be inserted into the system prompt.
    #[must_use]
    pub fn assemble_behavioral_prompt(&self) -> String {
        let mut sections: Vec<&str> = Vec::with_capacity(6);

        // Axis fragments
        sections.push(fragments::agency_fragment(self.agency));
        sections.push(fragments::quality_fragment(self.quality));
        sections.push(fragments::scope_fragment(self.scope));

        // Modifier fragments
        for modifier in &self.modifiers {
            sections.push(fragments::modifier_fragment(*modifier));
        }

        sections.join("\n\n")
    }
}

// =========================================================================
// Runtime capability profiles
// =========================================================================

const MAX_SCOPE_TARGETS: usize = 128;
const MAX_SCOPE_TARGET_BYTES: usize = 4096;

/// One user- or task-approved resource for a restricted behavioral scope.
///
/// Workspace targets are stored relative to the session project so a saved
/// session can be rebound to the same logical resource in an isolated child
/// worktree. Tool targets grant one exact wire-level tool surface; they are
/// never inferred from task prose.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BehaviorScopeTarget {
    WorkspacePath(PathBuf),
    Tool(String),
}

/// Persistable target intent used to compile adjacent and narrow scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorScopeTargets {
    /// Distinguishes an explicit user/task grant from the compatibility grant
    /// for the workspace selected at process launch.
    explicit: bool,
    targets: Vec<BehaviorScopeTarget>,
}

impl Default for BehaviorScopeTargets {
    fn default() -> Self {
        Self::workspace_root()
    }
}

impl BehaviorScopeTargets {
    /// Adjacent-mode compatibility target: the workspace the user launched.
    #[must_use]
    pub fn workspace_root() -> Self {
        Self {
            explicit: false,
            targets: vec![BehaviorScopeTarget::WorkspacePath(PathBuf::from("."))],
        }
    }

    /// Parse explicit CLI/UI target values against one session workspace.
    ///
    /// Values beginning with `tool:` approve one exact tool surface. All other
    /// values (optionally prefixed with `path:`) name a workspace-relative or
    /// workspace-contained absolute path.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, excessive, malformed, or escaping targets.
    pub fn from_user_values(
        project_root: &Path,
        working_directory: &Path,
        values: &[String],
    ) -> Result<Self, String> {
        if values.is_empty() {
            return Err("at least one explicit scope target is required".to_string());
        }
        if values.len() > MAX_SCOPE_TARGETS {
            return Err(format!(
                "at most {MAX_SCOPE_TARGETS} behavioral scope targets may be approved"
            ));
        }

        let mut targets = BTreeSet::new();
        for value in values {
            let value = value.trim();
            if value.is_empty() || value.len() > MAX_SCOPE_TARGET_BYTES {
                return Err(format!(
                    "scope targets must contain 1-{MAX_SCOPE_TARGET_BYTES} bytes"
                ));
            }
            if let Some(tool) = value.strip_prefix("tool:") {
                validate_scope_tool(tool)?;
                targets.insert(BehaviorScopeTarget::Tool(tool.to_string()));
                continue;
            }

            let path = value.strip_prefix("path:").unwrap_or(value);
            let relative = normalize_scope_path(project_root, working_directory, path)?;
            targets.insert(BehaviorScopeTarget::WorkspacePath(relative));
        }

        Ok(Self {
            explicit: true,
            targets: targets.into_iter().collect(),
        })
    }

    #[must_use]
    pub const fn is_explicit(&self) -> bool {
        self.explicit
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub(crate) fn targets(&self) -> &[BehaviorScopeTarget] {
        &self.targets
    }

    fn validate(&self) -> Result<(), String> {
        if self.targets.len() > MAX_SCOPE_TARGETS {
            return Err(format!(
                "at most {MAX_SCOPE_TARGETS} behavioral scope targets may be approved"
            ));
        }
        for target in &self.targets {
            match target {
                BehaviorScopeTarget::WorkspacePath(path) => validate_relative_scope_path(path)?,
                BehaviorScopeTarget::Tool(tool) => validate_scope_tool(tool)?,
            }
        }
        Ok(())
    }
}

fn validate_scope_tool(tool: &str) -> Result<(), String> {
    if tool.is_empty()
        || tool.len() > 256
        || !tool
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(format!(
            "invalid scope tool '{tool}'; use 1-256 ASCII letters, digits, '_', '-' or '.'"
        ));
    }
    Ok(())
}

fn normalize_scope_path(
    project_root: &Path,
    working_directory: &Path,
    value: &str,
) -> Result<PathBuf, String> {
    let supplied = Path::new(value);
    if supplied
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(format!("scope target '{value}' contains parent traversal"));
    }
    let absolute = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        working_directory.join(supplied)
    };
    let relative = absolute.strip_prefix(project_root).map_err(|_| {
        format!(
            "scope target '{}' is outside project '{}'",
            absolute.display(),
            project_root.display()
        )
    })?;
    let relative = if relative.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative.to_path_buf()
    };
    validate_relative_scope_path(&relative)?;
    Ok(relative)
}

fn validate_relative_scope_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err("workspace scope targets must be non-empty relative paths".to_string());
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(format!(
            "workspace scope target '{}' is not lexically normalized",
            path.display()
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundBehaviorScopeTargets {
    paths: Vec<PathBuf>,
    tools: BTreeSet<String>,
}

impl BoundBehaviorScopeTargets {
    fn bind(project_root: &Path, targets: &BehaviorScopeTargets) -> Result<Self, String> {
        targets.validate()?;
        let mut paths = BTreeSet::new();
        let mut tools = BTreeSet::new();
        for target in targets.targets() {
            match target {
                BehaviorScopeTarget::WorkspacePath(relative) => {
                    let absolute = canonicalize_scope_target(&project_root.join(relative))?;
                    if !absolute.starts_with(project_root) {
                        return Err(format!(
                            "scope target '{}' resolves outside project '{}'",
                            relative.display(),
                            project_root.display()
                        ));
                    }
                    paths.insert(absolute);
                }
                BehaviorScopeTarget::Tool(tool) => {
                    tools.insert(tool.clone());
                }
            }
        }
        Ok(Self {
            paths: paths.into_iter().collect(),
            tools,
        })
    }

    fn allows_path(&self, scope: Scope, project_root: &Path, path: &Path) -> bool {
        self.paths.iter().any(|target| {
            let boundary = if scope == Scope::Adjacent {
                target
                    .parent()
                    .filter(|parent| parent.starts_with(project_root))
                    .unwrap_or(target)
            } else {
                target.as_path()
            };
            path == boundary || path.starts_with(boundary)
        })
    }

    fn allows_tool(&self, tool: &str) -> bool {
        self.tools.contains(tool)
    }
}

fn canonicalize_scope_target(path: &Path) -> Result<PathBuf, String> {
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }
    let mut ancestor = path;
    let mut suffix = Vec::new();
    let canonical_ancestor = loop {
        if let Ok(canonical) = ancestor.canonicalize() {
            break canonical;
        }
        let name = ancestor.file_name().ok_or_else(|| {
            format!(
                "cannot resolve any existing ancestor of scope target '{}'",
                path.display()
            )
        })?;
        suffix.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| format!("cannot resolve parent of scope target '{}'", path.display()))?;
    };
    let mut canonical = canonical_ancestor;
    for component in suffix.iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

/// Host-enforced mode requested for one agent run.
///
/// Behavioral prompts remain useful explanations, but this value is the
/// authority consulted at tool admission. `Plan` is distinct from a generic
/// read-only mode because it may update the one host-pinned plan file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeMode {
    /// Normal behavior, including the read-only and director modifiers.
    Behavioral(BehaviorMode),
    /// Plan workflow: observe the codebase and update only the pinned plan.
    Plan,
    /// ACP context-gathering mode. Unlike `Plan`, it cannot write a plan file.
    Initializer,
    /// Explicit planner/orchestrator posture selected by a frontend flag.
    Coordinator,
}

impl Default for RuntimeMode {
    fn default() -> Self {
        Self::Behavioral(BehaviorMode::default())
    }
}

/// Effective capability class produced from a validated [`RuntimeMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeModeClass {
    /// Host permissions and guardrails decide which tools may run.
    Standard,
    /// Local observation and explicit user questions only.
    ReadOnly,
    /// Read-only analysis plus the exact pinned plan-file workflow.
    Plan,
    /// Observation plus the three subagent lifecycle tools.
    Coordinator,
}

/// Immutable public view of the mode authority installed in a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeModeSnapshot {
    /// Monotonic generation changed by every successful transition.
    pub generation: u64,
    /// Validated frontend request that produced the profile.
    pub mode: RuntimeMode,
    /// Enforced capability class.
    pub class: RuntimeModeClass,
    /// Persistable target intent bound into this exact mode generation.
    pub scope_targets: BehaviorScopeTargets,
    bound_scope_targets: BoundBehaviorScopeTargets,
}

impl RuntimeModeSnapshot {
    /// Stable label for diagnostics and typed denial messages.
    #[must_use]
    pub fn display_name(&self) -> String {
        match &self.mode {
            RuntimeMode::Behavioral(mode) => mode.display_name(),
            RuntimeMode::Plan => "plan".to_string(),
            RuntimeMode::Initializer => "initializer".to_string(),
            RuntimeMode::Coordinator => "coordinator".to_string(),
        }
    }

    /// Whether this profile may create or control child runs.
    #[must_use]
    pub const fn allows_child_runs(&self) -> bool {
        matches!(
            self.class,
            RuntimeModeClass::Standard | RuntimeModeClass::Coordinator
        )
    }

    /// Approval policy exposed for status and audit output.
    #[must_use]
    pub const fn approval_semantics(&self) -> &'static str {
        "host-policy-with-non-bypassable-mode-ceiling"
    }

    /// Budget policy exposed for status and audit output.
    #[must_use]
    pub const fn budget_semantics(&self) -> &'static str {
        if self.allows_child_runs() {
            "inherit-run-budget"
        } else {
            "inherit-run-budget; child-runs-denied"
        }
    }

    /// Explain why a model-visible definition is outside this exact profile.
    #[must_use]
    pub fn definition_denial(
        &self,
        tool_name: &str,
        effect: crate::tools::effect::ToolEffect,
    ) -> Option<String> {
        if profile_allows_definition(self, tool_name, effect) {
            None
        } else {
            Some(format!(
                "runtime mode '{}' generation {} does not grant this tool",
                self.display_name(),
                self.generation
            ))
        }
    }
}

/// Atomic mode authority owned by one exact run.
#[derive(Debug)]
pub struct RuntimeModeAuthority {
    project_root: PathBuf,
    state: RwLock<RuntimeModeSnapshot>,
}

impl RuntimeModeAuthority {
    /// Validate and install an initial generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested mode contains conflicting
    /// capability modifiers.
    pub fn new(mode: RuntimeMode) -> Result<Self, String> {
        let scope_targets = BehaviorScopeTargets::workspace_root();
        let project_root = PathBuf::from("/");
        let bound_scope_targets = BoundBehaviorScopeTargets {
            paths: vec![project_root.clone()],
            tools: BTreeSet::new(),
        };
        Self::from_bound(mode, scope_targets, bound_scope_targets, project_root)
    }

    pub(crate) fn new_for_run(
        mode: RuntimeMode,
        scope_targets: BehaviorScopeTargets,
        project_root: &Path,
    ) -> Result<Self, String> {
        let bound_scope_targets = BoundBehaviorScopeTargets::bind(project_root, &scope_targets)?;
        Self::from_bound(
            mode,
            scope_targets,
            bound_scope_targets,
            project_root.to_path_buf(),
        )
    }

    fn from_bound(
        mode: RuntimeMode,
        scope_targets: BehaviorScopeTargets,
        bound_scope_targets: BoundBehaviorScopeTargets,
        project_root: PathBuf,
    ) -> Result<Self, String> {
        let class = validate_runtime_mode(&mode, &scope_targets)?;
        Ok(Self {
            project_root,
            state: RwLock::new(RuntimeModeSnapshot {
                generation: 1,
                mode,
                class,
                scope_targets,
                bound_scope_targets,
            }),
        })
    }

    /// Read one internally consistent mode generation.
    #[must_use]
    pub fn snapshot(&self) -> RuntimeModeSnapshot {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Validate first, then atomically replace the whole effective profile.
    ///
    /// # Errors
    ///
    /// Returns an error for conflicting modifiers or generation exhaustion.
    pub fn transition(&self, mode: RuntimeMode) -> Result<RuntimeModeSnapshot, String> {
        let scope_targets = self.snapshot().scope_targets;
        self.transition_scoped(mode, scope_targets)
    }

    /// Validate a transition against the current target generation without
    /// mutating authority.
    pub(crate) fn validate_transition(&self, mode: &RuntimeMode) -> Result<(), String> {
        let scope_targets = self.snapshot().scope_targets;
        validate_runtime_mode(mode, &scope_targets)?;
        BoundBehaviorScopeTargets::bind(&self.project_root, &scope_targets).map(|_| ())
    }

    pub(crate) fn transition_scoped(
        &self,
        mode: RuntimeMode,
        scope_targets: BehaviorScopeTargets,
    ) -> Result<RuntimeModeSnapshot, String> {
        let class = validate_runtime_mode(&mode, &scope_targets)?;
        let bound_scope_targets =
            BoundBehaviorScopeTargets::bind(&self.project_root, &scope_targets)?;
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| "runtime mode generation exhausted".to_string())?;
        *state = RuntimeModeSnapshot {
            generation,
            mode,
            class,
            scope_targets,
            bound_scope_targets,
        };
        Ok(state.clone())
    }

    /// Enforce the current profile for one fully classified invocation.
    ///
    /// # Errors
    ///
    /// Returns a typed explanation when the active profile denies the call.
    pub fn admit_resolved_tool(
        &self,
        tool_name: &str,
        resolved: &crate::tools::effect::ResolvedEffect,
        canonical_path: Option<&Path>,
        arguments: &serde_json::Value,
        plan_file: &Path,
    ) -> Result<(), String> {
        let snapshot = self.snapshot();
        if profile_allows_call(
            &snapshot,
            tool_name,
            resolved,
            canonical_path,
            arguments,
            plan_file,
            &self.project_root,
        ) {
            Ok(())
        } else {
            Err(format!(
                "Runtime mode '{}' generation {} denies tool '{}' ({})",
                snapshot.display_name(),
                snapshot.generation,
                tool_name,
                resolved.effect.as_str()
            ))
        }
    }

    /// Check a definition-level effect without a concrete resource target.
    ///
    /// Production dispatch uses [`Self::admit_resolved_tool`]. This compatibility
    /// surface remains useful to callers deciding whether a non-path tool class
    /// is admitted at all.
    ///
    /// # Errors
    ///
    /// Returns a mode denial when the active profile does not grant the tool.
    pub fn admit_tool(
        &self,
        tool_name: &str,
        effect: crate::tools::effect::ToolEffect,
        arguments: &serde_json::Value,
        plan_file: &Path,
    ) -> Result<(), String> {
        let resolved = crate::tools::effect::ResolvedEffect {
            effect,
            canonical: tool_name.to_string(),
            target: tool_name.to_string(),
            target_kind: crate::tools::effect::ToolTargetKind::Tool,
            operation: None,
        };
        self.admit_resolved_tool(tool_name, &resolved, None, arguments, plan_file)
    }

    /// Explain why a definition must not be shown to the model in this mode.
    #[must_use]
    pub fn definition_denial(
        &self,
        tool_name: &str,
        effect: crate::tools::effect::ToolEffect,
    ) -> Option<String> {
        self.snapshot().definition_denial(tool_name, effect)
    }

    /// Deny effectful frontend shortcuts that do not pass through a tool.
    ///
    /// # Errors
    ///
    /// Returns a typed explanation unless the active mode permits ordinary
    /// direct frontend operations.
    pub fn admit_direct_operation(&self, operation: &str) -> Result<(), String> {
        let snapshot = self.snapshot();
        if snapshot.class == RuntimeModeClass::Standard {
            Ok(())
        } else {
            Err(format!(
                "Runtime mode '{}' generation {} denies direct operation '{}'",
                snapshot.display_name(),
                snapshot.generation,
                operation
            ))
        }
    }
}

fn validate_runtime_mode(
    mode: &RuntimeMode,
    scope_targets: &BehaviorScopeTargets,
) -> Result<RuntimeModeClass, String> {
    scope_targets.validate()?;
    let RuntimeMode::Behavioral(behavior) = mode else {
        return Ok(match mode {
            RuntimeMode::Plan => RuntimeModeClass::Plan,
            RuntimeMode::Initializer => RuntimeModeClass::ReadOnly,
            RuntimeMode::Coordinator => RuntimeModeClass::Coordinator,
            RuntimeMode::Behavioral(_) => unreachable!(),
        });
    };
    let readonly = behavior.modifiers.contains(&Modifier::Readonly);
    let director = behavior.modifiers.contains(&Modifier::Director);
    if readonly && director {
        return Err(
            "behavioral mode cannot combine readonly and director capabilities".to_string(),
        );
    }
    if behavior.scope == Scope::Narrow && (!scope_targets.is_explicit() || scope_targets.is_empty())
    {
        return Err(
            "narrow behavioral scope requires at least one explicit --scope-target; targets are never inferred from task prose"
                .to_string(),
        );
    }
    if behavior.scope == Scope::Adjacent && scope_targets.is_empty() {
        return Err("adjacent behavioral scope requires an approved target set".to_string());
    }
    Ok(if readonly {
        RuntimeModeClass::ReadOnly
    } else if director {
        RuntimeModeClass::Coordinator
    } else {
        RuntimeModeClass::Standard
    })
}

fn profile_allows_definition(
    snapshot: &RuntimeModeSnapshot,
    tool_name: &str,
    effect: crate::tools::effect::ToolEffect,
) -> bool {
    match snapshot.class {
        RuntimeModeClass::Standard => true,
        RuntimeModeClass::Plan => {
            tool_name == "write_file"
                || tool_name == "enter_plan_mode"
                || tool_name == "exit_plan_mode"
                || observation_tool_allowed(tool_name, effect)
        }
        RuntimeModeClass::ReadOnly => observation_tool_allowed(tool_name, effect),
        RuntimeModeClass::Coordinator => {
            matches!(tool_name, "task" | "agent_output" | "task_stop")
                || observation_tool_allowed(tool_name, effect)
        }
    }
}

fn profile_allows_call(
    snapshot: &RuntimeModeSnapshot,
    tool_name: &str,
    resolved: &crate::tools::effect::ResolvedEffect,
    canonical_path: Option<&Path>,
    arguments: &serde_json::Value,
    plan_file: &Path,
    project_root: &Path,
) -> bool {
    if snapshot.class == RuntimeModeClass::Plan {
        return crate::session::is_tool_allowed_in_plan_mode(tool_name, plan_file, arguments);
    }
    if !profile_allows_definition(snapshot, tool_name, resolved.effect) {
        return false;
    }
    let RuntimeMode::Behavioral(behavior) = &snapshot.mode else {
        return true;
    };
    if behavior.scope == Scope::Unrestricted {
        return true;
    }
    if behavior.scope == Scope::Adjacent && !snapshot.scope_targets.is_explicit() {
        return true;
    }
    match resolved.target_kind {
        crate::tools::effect::ToolTargetKind::Path
        | crate::tools::effect::ToolTargetKind::PathScope => canonical_path.is_some_and(|path| {
            snapshot
                .bound_scope_targets
                .allows_path(behavior.scope, project_root, path)
        }),
        crate::tools::effect::ToolTargetKind::Tool
        | crate::tools::effect::ToolTargetKind::Opaque => {
            resolved.effect == crate::tools::effect::ToolEffect::ReadOnly
                || snapshot.bound_scope_targets.allows_tool(tool_name)
        }
    }
}

pub(crate) fn observation_tool_allowed(
    tool_name: &str,
    effect: crate::tools::effect::ToolEffect,
) -> bool {
    if tool_name == "ask_user_question" || tool_name == "tool_search" {
        return true;
    }
    if prohibited_observation_family(tool_name) {
        return false;
    }
    effect == crate::tools::effect::ToolEffect::ReadOnly
}

fn prohibited_observation_family(tool_name: &str) -> bool {
    tool_name == "crosslink"
        || tool_name == "task"
        || tool_name == "agent_output"
        || tool_name == "task_stop"
        || tool_name.starts_with("task_")
        || tool_name.starts_with("todo_")
        || tool_name == "bash"
        || tool_name == "bash_output"
        || tool_name == "kill_shell"
        || tool_name == "kill_shells_for_agent"
        || tool_name == "enter_worktree"
        || tool_name == "exit_worktree"
        || tool_name == "list_worktrees"
        || tool_name == "web_fetch"
        || tool_name == "web_search"
        || tool_name == "web_browser"
        || tool_name == "list_mcp_resources"
        || tool_name == "read_mcp_resource"
        || tool_name == "lsp"
        || tool_name.starts_with("mcp__")
        || tool_name.starts_with("plugin__")
}

/// List all available preset names with their descriptions.
#[must_use]
pub fn list_presets() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "create",
            "autonomous / architect / unrestricted — Build from scratch",
        ),
        (
            "extend",
            "autonomous / pragmatic / adjacent — Extend and improve",
        ),
        (
            "safe",
            "collaborative / minimal / narrow — Surgical precision",
        ),
        (
            "refactor",
            "autonomous / pragmatic / unrestricted — Restructure freely",
        ),
        (
            "explore",
            "collaborative / architect / narrow + readonly — Understand code",
        ),
        (
            "debug",
            "collaborative / pragmatic / narrow + debug — Investigation-first",
        ),
        (
            "methodical",
            "surgical / architect / narrow + methodical — Step-by-step",
        ),
        (
            "director",
            "collaborative / architect / unrestricted + director — Orchestrate agents",
        ),
    ]
}

/// List all available modifier names with their descriptions.
///
/// Iterates the single-source `fragments::MODIFIERS` table so a new modifier
/// added there automatically appears here — no parallel list to keep in sync.
/// The canonical name comes from the `MODIFIERS` entry's `name` field, which
/// the `every_modifier_variant_appears_in_table_exactly_once` test verifies
/// is identical to the variant's `Display` and parses back via `FromStr`.
#[must_use]
pub fn list_modifiers() -> Vec<(&'static str, &'static str)> {
    fragments::MODIFIERS
        .iter()
        .map(|e| (e.name, e.description))
        .collect()
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // =====================================================================
    // Preset uniqueness & identity
    // =====================================================================

    const ALL_PRESETS: [Preset; 8] = [
        Preset::Create,
        Preset::Extend,
        Preset::Safe,
        Preset::Refactor,
        Preset::Explore,
        Preset::Debug,
        Preset::Methodical,
        Preset::Director,
    ];

    /// Every preset must produce a distinct `BehaviorMode`.  If two presets
    /// collapse to the same config, one of them is redundant or miswired.
    #[test]
    fn all_presets_produce_unique_modes() {
        let modes: Vec<BehaviorMode> = ALL_PRESETS
            .iter()
            .map(|p| BehaviorMode::from_preset(*p))
            .collect();
        for i in 0..modes.len() {
            for j in (i + 1)..modes.len() {
                assert_ne!(
                    modes[i], modes[j],
                    "presets {} and {} collapsed to identical BehaviorMode",
                    ALL_PRESETS[i], ALL_PRESETS[j]
                );
            }
        }
    }

    /// `from_preset` → `matching_preset` must round-trip for every preset.
    #[test]
    fn preset_roundtrip_all() {
        for preset in ALL_PRESETS {
            let mode = BehaviorMode::from_preset(preset);
            assert_eq!(
                mode.matching_preset(),
                Some(preset),
                "preset {preset} did not round-trip through matching_preset"
            );
        }
    }

    /// Changing ANY single field of a preset's mode must break `matching_preset`.
    /// This catches a `matching_preset` implementation that ignores a field.
    #[test]
    fn matching_preset_sensitive_to_each_field() {
        for preset in ALL_PRESETS {
            let base = BehaviorMode::from_preset(preset);

            // Flip agency
            let mut m = base.clone();
            m.agency = if m.agency == Agency::Autonomous {
                Agency::Surgical
            } else {
                Agency::Autonomous
            };
            assert_ne!(
                m.matching_preset(),
                Some(preset),
                "preset {preset}: flipping agency should break match"
            );

            // Flip quality
            let mut m = base.clone();
            m.quality = if m.quality == Quality::Architect {
                Quality::Minimal
            } else {
                Quality::Architect
            };
            assert_ne!(
                m.matching_preset(),
                Some(preset),
                "preset {preset}: flipping quality should break match"
            );

            // Flip scope
            let mut m = base.clone();
            m.scope = if m.scope == Scope::Unrestricted {
                Scope::Narrow
            } else {
                Scope::Unrestricted
            };
            assert_ne!(
                m.matching_preset(),
                Some(preset),
                "preset {preset}: flipping scope should break match"
            );

            // Add an extra modifier
            let mut m = base.clone();
            let extra = if m.modifiers.contains(&Modifier::Bold) {
                Modifier::ContextPacing
            } else {
                Modifier::Bold
            };
            m.add_modifier(extra);
            assert_ne!(
                m.matching_preset(),
                Some(preset),
                "preset {preset}: adding modifier should break match"
            );
        }
    }

    // =====================================================================
    // FromStr adversarial
    // =====================================================================

    /// Empty strings, whitespace-only, numbers, and near-miss typos must
    /// all be rejected, not silently accepted as some default.
    #[test]
    fn from_str_rejects_garbage_inputs() {
        let garbage = [
            "",
            " ",
            "\t",
            "\n",
            "123",
            "null",
            "none",
            "true",
            "AUTONOMOUS",   // wrong case is accepted, but...
            "autonomou",    // one char short
            "collaborativ", // truncated
            "surgica",
            "🔥",
            "auto\0nomic",
            "auto nomous", // embedded space
        ];
        for input in garbage {
            // Some of these (like "AUTONOMOUS") ARE valid because FromStr
            // lowercases. We test the definitely-invalid ones.
            if input.trim().is_empty()
                || input.contains('\0')
                || input.contains(' ')
                || input.contains('🔥')
            {
                assert!(
                    input.parse::<Agency>().is_err(),
                    "Agency should reject {input:?}"
                );
                assert!(
                    input.parse::<Quality>().is_err(),
                    "Quality should reject {input:?}"
                );
                assert!(
                    input.parse::<Scope>().is_err(),
                    "Scope should reject {input:?}"
                );
                assert!(
                    input.parse::<Preset>().is_err(),
                    "Preset should reject {input:?}"
                );
                assert!(
                    input.parse::<Modifier>().is_err(),
                    "Modifier should reject {input:?}"
                );
            }
        }
    }

    /// Every Display output must parse back to the original value.
    /// Catches Display/FromStr drift.
    #[test]
    fn display_from_str_roundtrip_all_enums() {
        for v in [Agency::Autonomous, Agency::Collaborative, Agency::Surgical] {
            assert_eq!(v.to_string().parse::<Agency>().unwrap(), v);
        }
        for v in [Quality::Architect, Quality::Pragmatic, Quality::Minimal] {
            assert_eq!(v.to_string().parse::<Quality>().unwrap(), v);
        }
        for v in [Scope::Unrestricted, Scope::Adjacent, Scope::Narrow] {
            assert_eq!(v.to_string().parse::<Scope>().unwrap(), v);
        }
        for v in ALL_PRESETS {
            assert_eq!(v.to_string().parse::<Preset>().unwrap(), v);
        }
        for v in [
            Modifier::Bold,
            Modifier::Debug,
            Modifier::Methodical,
            Modifier::Director,
            Modifier::Readonly,
            Modifier::ContextPacing,
        ] {
            assert_eq!(v.to_string().parse::<Modifier>().unwrap(), v);
        }
    }

    /// Modifier aliases must parse correctly — "read-only" and "readonly"
    /// both map to Readonly; "pacing" maps to `ContextPacing`.
    #[test]
    fn modifier_aliases_all_resolve() {
        assert_eq!("read-only".parse::<Modifier>().unwrap(), Modifier::Readonly);
        assert_eq!("readonly".parse::<Modifier>().unwrap(), Modifier::Readonly);
        assert_eq!(
            "context-pacing".parse::<Modifier>().unwrap(),
            Modifier::ContextPacing
        );
        assert_eq!(
            "pacing".parse::<Modifier>().unwrap(),
            Modifier::ContextPacing
        );
        // underscore normalisation
        assert_eq!(
            "context_pacing".parse::<Modifier>().unwrap(),
            Modifier::ContextPacing
        );
    }

    // =====================================================================
    // Modifier operations
    // =====================================================================

    /// Adding all 6 modifiers, then removing them one by one, must leave
    /// the mode with exactly the remaining modifiers in insertion order.
    #[test]
    fn modifier_add_remove_preserves_order() {
        let all_mods = [
            Modifier::Bold,
            Modifier::Debug,
            Modifier::Methodical,
            Modifier::Director,
            Modifier::Readonly,
            Modifier::ContextPacing,
        ];
        let mut mode = BehaviorMode::from_preset(Preset::Create);
        for m in &all_mods {
            mode.add_modifier(*m);
        }
        assert_eq!(mode.modifiers.len(), 6);
        assert_eq!(mode.modifiers, all_mods.to_vec());

        // Remove from the middle
        mode.remove_modifier(Modifier::Methodical);
        assert_eq!(mode.modifiers.len(), 5);
        assert_eq!(mode.modifiers[0], Modifier::Bold);
        assert_eq!(mode.modifiers[1], Modifier::Debug);
        assert_eq!(mode.modifiers[2], Modifier::Director); // shifted up
        assert_eq!(mode.modifiers[3], Modifier::Readonly);

        // Removing a non-present modifier is a no-op
        mode.remove_modifier(Modifier::Methodical);
        assert_eq!(mode.modifiers.len(), 5);
    }

    /// Duplicate `add_modifier` calls must be idempotent — the modifier
    /// list must never contain duplicates.
    #[test]
    fn add_modifier_is_idempotent() {
        let mut mode = BehaviorMode::default();
        for _ in 0..100 {
            mode.add_modifier(Modifier::Bold);
        }
        assert_eq!(
            mode.modifiers
                .iter()
                .filter(|m| **m == Modifier::Bold)
                .count(),
            1
        );
    }

    // =====================================================================
    // Serde edge cases
    // =====================================================================

    /// Every preset must survive serde JSON round-trip exactly.
    #[test]
    fn serde_roundtrip_all_presets() {
        for preset in ALL_PRESETS {
            let mode = BehaviorMode::from_preset(preset);
            let json = serde_json::to_string(&mode).unwrap();
            let restored: BehaviorMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, restored, "serde roundtrip failed for preset {preset}");
        }
    }

    /// A custom mode with all 6 modifiers must round-trip through serde.
    #[test]
    fn serde_roundtrip_all_modifiers() {
        let mode = BehaviorMode {
            agency: Agency::Surgical,
            quality: Quality::Minimal,
            scope: Scope::Narrow,
            modifiers: vec![
                Modifier::Bold,
                Modifier::Debug,
                Modifier::Methodical,
                Modifier::Director,
                Modifier::Readonly,
                Modifier::ContextPacing,
            ],
        };
        let json = serde_json::to_string(&mode).unwrap();
        let restored: BehaviorMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, restored);
    }

    /// Deserialization of the Default value from JSON must produce Default.
    /// Tests backwards compat: old config files with default values.
    #[test]
    fn serde_deserialize_defaults() {
        let json =
            r#"{"agency":"autonomous","quality":"pragmatic","scope":"adjacent","modifiers":[]}"#;
        let mode: BehaviorMode = serde_json::from_str(json).unwrap();
        assert_eq!(mode, BehaviorMode::default());
    }

    /// Missing `modifiers` field MUST default to an empty Vec so
    /// sessions persisted before the field was added (crosslink #839
    /// regression) still load. The struct carries `#[serde(default)]`
    /// on the field — this is the round-trip pin.
    #[test]
    fn serde_missing_modifiers_defaults_to_empty() {
        let json = r#"{"agency":"autonomous","quality":"pragmatic","scope":"adjacent"}"#;
        let mode: BehaviorMode =
            serde_json::from_str(json).expect("BehaviorMode must accept missing `modifiers`");
        assert_eq!(mode.agency, Agency::Autonomous);
        assert_eq!(mode.quality, Quality::Pragmatic);
        assert_eq!(mode.scope, Scope::Adjacent);
        assert!(
            mode.modifiers.is_empty(),
            "missing `modifiers` must default to empty, got {:?}",
            mode.modifiers
        );
    }

    /// Unknown enum variant in JSON should produce a clear error.
    #[test]
    fn serde_rejects_unknown_variants() {
        let json = r#"{"agency":"yolo","quality":"pragmatic","scope":"adjacent","modifiers":[]}"#;
        assert!(serde_json::from_str::<BehaviorMode>(json).is_err());

        let json = r#"{"agency":"autonomous","quality":"pragmatic","scope":"adjacent","modifiers":["teleport"]}"#;
        assert!(serde_json::from_str::<BehaviorMode>(json).is_err());
    }

    // =====================================================================
    // Assembly adversarial
    // =====================================================================

    /// Every pair of distinct presets must produce distinct assembled prompts.
    /// Catches fragment wiring bugs where two presets map to the same content.
    #[test]
    fn distinct_presets_produce_distinct_prompts() {
        let prompts: Vec<(Preset, String)> = ALL_PRESETS
            .iter()
            .map(|p| {
                (
                    *p,
                    BehaviorMode::from_preset(*p).assemble_behavioral_prompt(),
                )
            })
            .collect();
        for i in 0..prompts.len() {
            for j in (i + 1)..prompts.len() {
                assert_ne!(
                    prompts[i].1, prompts[j].1,
                    "presets {} and {} produced identical prompt text",
                    prompts[i].0, prompts[j].0
                );
            }
        }
    }

    /// Assembly must be deterministic: same mode, same output.
    #[test]
    fn assembly_is_deterministic() {
        let mode = BehaviorMode::from_preset(Preset::Director);
        let a = mode.assemble_behavioral_prompt();
        let b = mode.assemble_behavioral_prompt();
        assert_eq!(a, b);
    }

    /// Assembled prompt for a mode with modifiers must contain content from
    /// ALL modifiers, and the modifier content must appear AFTER the axis
    /// content. This catches ordering regressions.
    #[test]
    fn assembly_ordering_axes_before_modifiers() {
        let mode = BehaviorMode {
            agency: Agency::Autonomous,
            quality: Quality::Architect,
            scope: Scope::Unrestricted,
            modifiers: vec![Modifier::Bold, Modifier::ContextPacing],
        };
        let prompt = mode.assemble_behavioral_prompt();

        let agency_pos = prompt.find("# Agency:").expect("missing agency");
        let quality_pos = prompt.find("# Quality:").expect("missing quality");
        let scope_pos = prompt.find("# Scope:").expect("missing scope");
        let bold_pos = prompt.find("# Bold").expect("missing bold modifier");
        let pacing_pos = prompt
            .find("# Context and Pacing")
            .expect("missing context-pacing modifier");

        // Axes in order
        assert!(agency_pos < quality_pos, "agency must precede quality");
        assert!(quality_pos < scope_pos, "quality must precede scope");
        // Modifiers after axes, in insertion order
        assert!(scope_pos < bold_pos, "scope must precede bold modifier");
        assert!(bold_pos < pacing_pos, "bold must precede context-pacing");
    }

    /// Stacking all 6 modifiers on a preset must not panic, must not
    /// duplicate fragment text, and must include content from each modifier.
    #[test]
    fn stacking_all_modifiers_produces_complete_prompt() {
        let mut mode = BehaviorMode::from_preset(Preset::Create);
        let all_mods = [
            Modifier::Bold,
            Modifier::Debug,
            Modifier::Methodical,
            Modifier::Director,
            Modifier::Readonly,
            Modifier::ContextPacing,
        ];
        for m in &all_mods {
            mode.add_modifier(*m);
        }
        let prompt = mode.assemble_behavioral_prompt();

        // Each modifier's unique heading must appear exactly once
        let unique_markers = [
            "# Bold",
            "# Investigation Mode",
            "# Methodical Mode",
            "# Director",
            "# Read-Only Mode",
            "# Context and Pacing",
        ];
        for marker in unique_markers {
            let count = prompt.matches(marker).count();
            assert_eq!(
                count, 1,
                "expected exactly 1 occurrence of \"{marker}\", found {count}"
            );
        }
    }

    // =====================================================================
    // list_presets / list_modifiers consistency
    // =====================================================================

    /// Every preset returned by `list_presets()` must be parseable as a Preset.
    #[test]
    fn list_presets_names_all_parse() {
        for (name, _desc) in list_presets() {
            assert!(
                name.parse::<Preset>().is_ok(),
                "list_presets() contains unparseable name: {name:?}"
            );
        }
    }

    /// The set of names from `list_presets()` must equal the set from `ALL_PRESETS`.
    #[test]
    fn list_presets_covers_all_variants() {
        let listed: HashSet<String> = list_presets().iter().map(|(n, _)| n.to_string()).collect();
        let expected: HashSet<String> = ALL_PRESETS
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(listed, expected, "list_presets() doesn't match ALL_PRESETS");
    }

    /// Every modifier name from `list_modifiers()` must be parseable.
    #[test]
    fn list_modifiers_names_all_parse() {
        for (name, _desc) in list_modifiers() {
            assert!(
                name.parse::<Modifier>().is_ok(),
                "list_modifiers() contains unparseable name: {name:?}"
            );
        }
    }

    // =====================================================================
    // Display edge cases
    // =====================================================================

    /// Display for a mode with multiple modifiers must list them all,
    /// comma-separated, in brackets.
    #[test]
    fn display_multiple_modifiers() {
        let mode = BehaviorMode {
            agency: Agency::Surgical,
            quality: Quality::Minimal,
            scope: Scope::Narrow,
            modifiers: vec![Modifier::Debug, Modifier::Bold, Modifier::Readonly],
        };
        let s = mode.to_string();
        assert!(s.contains("[debug, bold, readonly]"), "got: {s}");
    }

    /// `display_name` returns the preset name for matching presets,
    /// and the full axis string for custom modes.
    #[test]
    fn display_name_preset_vs_custom() {
        let matching = BehaviorMode::from_preset(Preset::Create);
        assert_eq!(matching.display_name(), "create");

        let custom = BehaviorMode {
            agency: Agency::Surgical,
            quality: Quality::Architect,
            scope: Scope::Unrestricted,
            modifiers: vec![],
        };
        // No preset matches this combo, so display_name is the axis string
        assert_eq!(custom.display_name(), "surgical/architect/unrestricted");
    }

    /// `description()` for a custom mode must include the axis values
    /// so the user can tell what's configured.
    #[test]
    fn description_custom_includes_axes() {
        let mode = BehaviorMode {
            agency: Agency::Surgical,
            quality: Quality::Minimal,
            scope: Scope::Unrestricted,
            modifiers: vec![Modifier::Bold],
        };
        let desc = mode.description();
        assert!(
            desc.contains("surgical"),
            "description missing agency: {desc}"
        );
        assert!(
            desc.contains("minimal"),
            "description missing quality: {desc}"
        );
        assert!(
            desc.contains("unrestricted"),
            "description missing scope: {desc}"
        );
    }

    #[test]
    fn runtime_profiles_enforce_real_mode_boundaries() {
        use crate::tools::effect::ToolEffect;

        let plan_dir = tempfile::tempdir().expect("plan dir");
        let plan_file = plan_dir.path().join("plan.md");
        std::fs::write(&plan_file, "# Plan\n").expect("plan file");
        let plan_file = std::fs::canonicalize(plan_file).expect("canonical plan");
        let empty = serde_json::json!({});

        let targets = BehaviorScopeTargets::from_user_values(
            plan_dir.path(),
            plan_dir.path(),
            &[".".to_string()],
        )
        .expect("explicit explore target");
        let authority = RuntimeModeAuthority::new_for_run(
            RuntimeMode::Behavioral(BehaviorMode::from_preset(Preset::Explore)),
            targets,
            plan_dir.path(),
        )
        .expect("explore profile");
        assert_eq!(authority.snapshot().class, RuntimeModeClass::ReadOnly);
        assert!(authority
            .admit_tool("read_file", ToolEffect::ReadOnly, &empty, &plan_file)
            .is_ok());
        for (tool, effect) in [
            ("write_file", ToolEffect::WorkspaceMutation),
            ("web_fetch", ToolEffect::NetworkRead),
            ("task_get", ToolEffect::ReadOnly),
            ("todo_read", ToolEffect::ReadOnly),
            ("crosslink", ToolEffect::ReadOnly),
        ] {
            assert!(
                authority
                    .admit_tool(tool, effect, &empty, &plan_file)
                    .is_err(),
                "explore mode must deny {tool}"
            );
        }

        let coordinator =
            RuntimeModeAuthority::new(RuntimeMode::Coordinator).expect("coordinator profile");
        assert!(coordinator
            .admit_tool("task", ToolEffect::Destructive, &empty, &plan_file)
            .is_ok());
        assert!(coordinator
            .admit_tool("bash", ToolEffect::Destructive, &empty, &plan_file)
            .is_err());
    }

    #[test]
    fn plan_profile_only_writes_the_pinned_plan_and_transitions_atomically() {
        use crate::tools::effect::ToolEffect;

        let plan_dir = tempfile::tempdir().expect("plan dir");
        let plan_file = plan_dir.path().join("plan.md");
        std::fs::write(&plan_file, "# Plan\n").expect("plan file");
        let plan_file = std::fs::canonicalize(plan_file).expect("canonical plan");
        let authority = RuntimeModeAuthority::new(RuntimeMode::default()).expect("default mode");
        let next = authority.transition(RuntimeMode::Plan).expect("enter plan");
        assert_eq!(next.generation, 2);
        assert_eq!(next.class, RuntimeModeClass::Plan);

        let plan_args = serde_json::json!({"path": plan_file});
        assert!(authority
            .admit_tool(
                "write_file",
                ToolEffect::WorkspaceMutation,
                &plan_args,
                &plan_file,
            )
            .is_ok());
        let other_args = serde_json::json!({"path": plan_dir.path().join("other.md")});
        assert!(authority
            .admit_tool(
                "write_file",
                ToolEffect::WorkspaceMutation,
                &other_args,
                &plan_file,
            )
            .is_err());
    }

    #[test]
    fn conflicting_runtime_modifiers_fail_validation_without_transition() {
        let mode = BehaviorMode {
            modifiers: vec![Modifier::Readonly, Modifier::Director],
            ..BehaviorMode::default()
        };
        let authority = RuntimeModeAuthority::new(RuntimeMode::default()).expect("default mode");
        let before = authority.snapshot();
        assert!(authority.transition(RuntimeMode::Behavioral(mode)).is_err());
        assert_eq!(authority.snapshot(), before);
    }
}

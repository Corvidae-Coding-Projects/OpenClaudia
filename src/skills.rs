//! Provenance-aware skill packages and scoped activation.
//!
//! Skills are host-managed, user-owned, or repository-proposed Markdown
//! packages. Repository packages remain inert until a host-owned trust
//! receipt is captured by the exact run. Skill text is always projected as
//! labelled reference context; only an explicit user invocation may apply the
//! separately bounded one-turn tool/model/effort/hook capability request.

mod catalog;
mod trust;

pub use trust::{
    inspect_project_skill_trust, inspect_project_skill_trust_at, revoke_project_skills,
    revoke_project_skills_at, skill_trust_store_path, trust_project_skills,
    trust_project_skills_at, ProjectSkillAccess, SkillCapabilityPolicy, SkillRunAccess,
    SkillTrustError, SkillTrustStatus,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Env var that turns off the managed / policy skill layer at host startup.
pub const DISABLE_POLICY_SKILLS_ENV: &str = "OPENCLAUDIA_DISABLE_POLICY_SKILLS";
/// Host startup path whose `skills/` child contributes managed skills.
pub const MANAGED_PATH_ENV: &str = "OPENCLAUDIA_MANAGED_PATH";

const MAX_FRONTMATTER_BYTES: usize = 32 * 1024;
const MAX_SKILL_NAME_BYTES: usize = 96;
const MAX_DESCRIPTION_BYTES: usize = 2 * 1024;
const MAX_WHEN_TO_USE_BYTES: usize = 4 * 1024;
const MAX_ARGUMENT_HINT_BYTES: usize = 512;
const MAX_MODEL_BYTES: usize = 256;
const MAX_EFFORT_BYTES: usize = 64;
const MAX_ALLOWED_TOOLS: usize = 64;
const MAX_ALLOWED_TOOL_BYTES: usize = 512;
const MAX_PATH_PATTERNS: usize = 64;
const MAX_PATH_PATTERN_BYTES: usize = 512;
const MAX_SKILL_HOOK_BYTES: usize = 64 * 1024;

/// Structured skill-file failures.
#[derive(Debug, Error)]
pub enum SkillParseError {
    #[error("failed to read skill file: {0}")]
    ReadFailed(#[from] std::io::Error),
    #[error("skill file has no YAML frontmatter (`---` delimiters)")]
    FrontmatterMissing,
    #[error("failed to parse skill frontmatter as YAML: {0}")]
    YamlFailed(#[from] serde_yaml::Error),
    #[error("skill file exceeds the {max_bytes}-byte limit ({actual_bytes} bytes)")]
    TooLarge { actual_bytes: u64, max_bytes: u64 },
    #[error("invalid skill definition: {0}")]
    InvalidDefinition(String),
}

/// Backward-compatible skill frontmatter shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillDefinition {
    pub name: String,
    pub description: String,
    #[serde(
        default,
        rename = "allowed_tools",
        alias = "allowed-tools",
        deserialize_with = "deserialize_tools_list"
    )]
    pub allowed_tools: Option<Vec<String>>,
    #[serde(default, rename = "when_to_use", alias = "whenToUse")]
    pub when_to_use: Option<String>,
    #[serde(default, rename = "argument-hint", alias = "argument_hint")]
    pub argument_hint: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub effort: Option<String>,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
    #[serde(default)]
    pub hooks: Option<Value>,
    #[serde(
        default = "default_user_invocable",
        rename = "user-invocable",
        alias = "user_invocable"
    )]
    pub user_invocable: bool,
    #[serde(skip)]
    pub prompt: String,
    #[serde(skip)]
    pub path: PathBuf,
}

const fn default_user_invocable() -> bool {
    true
}

/// Source class used for deterministic precedence and model-visible provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillSource {
    Managed,
    Project,
    User,
}

/// Immutable package and catalog identity attached to a loaded skill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkillProvenance {
    pub source: SkillSource,
    pub root: PathBuf,
    pub relative_path: PathBuf,
    pub content_digest: String,
    pub catalog_generation: String,
    pub workspace_generation: u64,
}

/// A validated skill plus its source and host-selected capability ceiling.
#[derive(Debug, Clone)]
pub struct ResolvedSkill {
    definition: SkillDefinition,
    provenance: SkillProvenance,
    capability_policy: SkillCapabilityPolicy,
}

impl ResolvedSkill {
    pub(crate) const fn new(
        definition: SkillDefinition,
        provenance: SkillProvenance,
        capability_policy: SkillCapabilityPolicy,
    ) -> Self {
        Self {
            definition,
            provenance,
            capability_policy,
        }
    }

    #[must_use]
    pub const fn definition(&self) -> &SkillDefinition {
        &self.definition
    }

    #[must_use]
    pub const fn provenance(&self) -> &SkillProvenance {
        &self.provenance
    }
}

impl Deref for ResolvedSkill {
    type Target = SkillDefinition;

    fn deref(&self) -> &Self::Target {
        &self.definition
    }
}

/// Why a skill body entered the current turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillActivationTrigger {
    ExplicitUser,
    ModelSelection,
    PathMatch,
}

/// Model-visible typed skill selection. This is data, never a prompt marker.
#[derive(Debug, Clone, Serialize)]
pub struct SkillSelection {
    pub schema: &'static str,
    pub name: String,
    pub description: String,
    pub prompt: String,
    pub argument_hint: Option<String>,
    pub trigger: SkillActivationTrigger,
    pub provenance: SkillProvenance,
    pub requested_allowed_tools: Vec<String>,
    pub effective_allowed_tools: Vec<String>,
    pub effective_model: Option<String>,
    pub effective_effort: Option<String>,
    pub hooks_active: bool,
}

/// One scoped activation consumed by a frontend for a single turn.
#[derive(Debug, Clone)]
pub struct SkillActivation {
    selection: SkillSelection,
    effective_hooks: Option<crate::config::HooksConfig>,
}

impl SkillActivation {
    #[must_use]
    pub const fn selection(&self) -> &SkillSelection {
        &self.selection
    }

    #[must_use]
    pub fn allowed_tools(&self) -> Option<&[String]> {
        (!self.selection.effective_allowed_tools.is_empty())
            .then_some(self.selection.effective_allowed_tools.as_slice())
    }

    #[must_use]
    pub fn model(&self) -> Option<&str> {
        self.selection.effective_model.as_deref()
    }

    #[must_use]
    pub fn effort(&self) -> Option<&str> {
        self.selection.effective_effort.as_deref()
    }

    #[must_use]
    pub const fn hooks(&self) -> Option<&crate::config::HooksConfig> {
        self.effective_hooks.as_ref()
    }

    #[must_use]
    /// Serialize the typed selection for a tool result.
    ///
    /// # Panics
    ///
    /// Panics only if Serde cannot serialize the statically typed selection.
    pub fn structured(&self) -> Value {
        serde_json::to_value(&self.selection).expect("SkillSelection serialization cannot fail")
    }

    /// Source-labelled, budgetable context for one selected skill.
    #[must_use]
    pub fn context_item(&self, id: impl Into<String>) -> crate::context::ContextItem {
        let source = &self.selection.provenance;
        crate::context::ContextItem::reference(
            id,
            crate::context::ReferenceSource::Skill,
            format!(
                "{:?}:{}#{}",
                source.source,
                source.root.join(&source.relative_path).display(),
                source.content_digest
            ),
            format!(
                "Selected skill reference\nName: {}\nSource: {:?}\nContent digest: {}\n\n{}",
                self.selection.name, source.source, source.content_digest, self.selection.prompt
            ),
            crate::context::ContextFreshness::Turn,
            180,
        )
    }
}

#[derive(Debug, Error)]
pub enum SkillActivationError {
    #[error("unknown or unavailable skill `{0}`")]
    Unavailable(String),
    #[error("skill `{0}` is not user-invocable")]
    NotUserInvocable(String),
    #[error("skill `{name}` has invalid hooks: {reason}")]
    InvalidHooks { name: String, reason: String },
}

/// Parse a skill file with a hard pre-allocation size limit.
///
/// # Errors
///
/// Returns an error when the file cannot be read, exceeds its size limit, or
/// has invalid frontmatter, schema, hooks, or package fields.
pub fn parse_skill_file(path: &Path) -> Result<SkillDefinition, SkillParseError> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > catalog::MAX_SKILL_FILE_BYTES {
        return Err(SkillParseError::TooLarge {
            actual_bytes: metadata.len(),
            max_bytes: catalog::MAX_SKILL_FILE_BYTES,
        });
    }
    let bytes = std::fs::read(path)?;
    parse_skill_bytes(path, &bytes)
}

pub(crate) fn parse_skill_bytes(
    path: &Path,
    bytes: &[u8],
) -> Result<SkillDefinition, SkillParseError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > catalog::MAX_SKILL_FILE_BYTES {
        return Err(SkillParseError::TooLarge {
            actual_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            max_bytes: catalog::MAX_SKILL_FILE_BYTES,
        });
    }
    let raw = std::str::from_utf8(bytes).map_err(|error| {
        SkillParseError::InvalidDefinition(format!("skill file is not UTF-8: {error}"))
    })?;
    let stripped = raw.trim_start_matches('\u{FEFF}');
    let normalized = if stripped.contains('\r') {
        stripped.replace("\r\n", "\n").replace('\r', "\n")
    } else {
        stripped.to_string()
    };
    let mut lines = normalized.split_inclusive('\n');
    let first = lines.next().ok_or(SkillParseError::FrontmatterMissing)?;
    if first.trim_end_matches('\n') != "---" {
        return Err(SkillParseError::FrontmatterMissing);
    }
    let frontmatter_start = first.len();
    let mut frontmatter_end = None;
    let mut offset = frontmatter_start;
    for line in lines {
        let line_without_newline = line.trim_end_matches('\n');
        if line_without_newline == "---" {
            frontmatter_end = Some((offset, offset.saturating_add(line.len())));
            break;
        }
        offset = offset.saturating_add(line.len());
        if offset.saturating_sub(frontmatter_start) > MAX_FRONTMATTER_BYTES {
            return Err(SkillParseError::InvalidDefinition(format!(
                "frontmatter exceeds {MAX_FRONTMATTER_BYTES} bytes"
            )));
        }
    }
    let (frontmatter_end, body_start) =
        frontmatter_end.ok_or(SkillParseError::FrontmatterMissing)?;
    let frontmatter = normalized[frontmatter_start..frontmatter_end].trim();
    let body = normalized[body_start..].trim();
    let mut definition: SkillDefinition = serde_yaml::from_str(frontmatter)?;
    if definition.name.trim().is_empty() {
        definition.name = fallback_skill_name(path);
    }
    definition.prompt = body.to_string();
    definition.path = path.to_path_buf();
    validate_definition(&definition)?;
    Ok(definition)
}

fn fallback_skill_name(path: &Path) -> String {
    if path.file_name().and_then(|name| name.to_str()) == Some("SKILL.md") {
        return path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();
    }
    path.file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn validate_definition(definition: &SkillDefinition) -> Result<(), SkillParseError> {
    validate_identifier("name", &definition.name, MAX_SKILL_NAME_BYTES)?;
    validate_text(
        "description",
        &definition.description,
        1,
        MAX_DESCRIPTION_BYTES,
    )?;
    if let Some(value) = definition.when_to_use.as_deref() {
        validate_text("when_to_use", value, 1, MAX_WHEN_TO_USE_BYTES)?;
    }
    if let Some(value) = definition.argument_hint.as_deref() {
        validate_text("argument-hint", value, 1, MAX_ARGUMENT_HINT_BYTES)?;
    }
    if let Some(value) = definition.model.as_deref() {
        validate_identifier("model", value, MAX_MODEL_BYTES)?;
    }
    if let Some(value) = definition.effort.as_deref() {
        validate_identifier("effort", value, MAX_EFFORT_BYTES)?;
    }
    if let Some(tools) = definition.allowed_tools.as_deref() {
        if tools.len() > MAX_ALLOWED_TOOLS {
            return invalid(format!("allowed_tools exceeds {MAX_ALLOWED_TOOLS} entries"));
        }
        for tool in tools {
            validate_text("allowed_tools entry", tool, 1, MAX_ALLOWED_TOOL_BYTES)?;
        }
    }
    if let Some(patterns) = definition.paths.as_deref() {
        if patterns.len() > MAX_PATH_PATTERNS {
            return invalid(format!("paths exceeds {MAX_PATH_PATTERNS} entries"));
        }
        for pattern in patterns {
            validate_text("paths entry", pattern, 1, MAX_PATH_PATTERN_BYTES)?;
            if Path::new(pattern).is_absolute()
                || Path::new(pattern)
                    .components()
                    .any(|component| component == Component::ParentDir)
            {
                return invalid(format!("path glob '{pattern}' escapes the workspace"));
            }
            glob_to_regex(pattern).map_err(|error| {
                SkillParseError::InvalidDefinition(format!(
                    "path glob '{pattern}' is invalid: {error}"
                ))
            })?;
        }
    }
    if let Some(hooks) = definition.hooks.as_ref() {
        let encoded = serde_json::to_vec(hooks).map_err(|error| {
            SkillParseError::InvalidDefinition(format!("hooks cannot be encoded: {error}"))
        })?;
        if encoded.len() > MAX_SKILL_HOOK_BYTES {
            return invalid(format!("hooks exceeds {MAX_SKILL_HOOK_BYTES} bytes"));
        }
        parse_hooks(hooks).map_err(|reason| {
            SkillParseError::InvalidDefinition(format!("hooks schema is invalid: {reason}"))
        })?;
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str, max_bytes: usize) -> Result<(), SkillParseError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return invalid(format!(
            "{field} must contain 1..={max_bytes} ASCII identifier bytes"
        ));
    }
    Ok(())
}

fn validate_text(
    field: &str,
    value: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<(), SkillParseError> {
    if value.len() < min_bytes
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character == '\0' || (character.is_control() && character != '\n' && character != '\t')
        })
    {
        return invalid(format!(
            "{field} must contain {min_bytes}..={max_bytes} bounded text bytes"
        ));
    }
    Ok(())
}

const fn invalid<T>(reason: String) -> Result<T, SkillParseError> {
    Err(SkillParseError::InvalidDefinition(reason))
}

fn deserialize_tools_list<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: Option<serde_yaml::Value> = Option::deserialize(deserializer)?;
    match value {
        Some(serde_yaml::Value::Sequence(sequence)) => {
            let mut tools = Vec::with_capacity(sequence.len());
            for value in sequence {
                let serde_yaml::Value::String(tool) = value else {
                    return Err(serde::de::Error::custom(
                        "allowed_tools entries must be strings",
                    ));
                };
                tools.push(tool);
            }
            Ok((!tools.is_empty()).then_some(tools))
        }
        Some(serde_yaml::Value::String(value)) => {
            let tools = crate::permissions::split_allowed_tool_specs_scalar(&value);
            Ok((!tools.is_empty()).then_some(tools))
        }
        None => Ok(None),
        Some(_) => Err(serde::de::Error::custom(
            "allowed_tools must be a string or sequence of strings",
        )),
    }
}

/// True when a validated conditional path pattern matches a project-relative path.
#[must_use]
pub fn skill_matches_path(skill: &SkillDefinition, touched: &Path) -> bool {
    let Some(patterns) = skill.paths.as_ref() else {
        return false;
    };
    let touched = touched.to_string_lossy().replace('\\', "/");
    patterns
        .iter()
        .any(|pattern| glob_to_regex(pattern).is_ok_and(|expression| expression.is_match(&touched)))
}

fn glob_to_regex(glob: &str) -> Result<regex::Regex, regex::Error> {
    let mut output = String::with_capacity(glob.len().saturating_mul(2).saturating_add(4));
    output.push('^');
    let mut characters = glob.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '*' => {
                if characters.peek() == Some(&'*') {
                    characters.next();
                    if characters.peek() == Some(&'/') {
                        characters.next();
                        output.push_str("(?:.*/)?");
                    } else {
                        output.push_str(".*");
                    }
                } else {
                    output.push_str("[^/]*");
                }
            }
            '?' => output.push_str("[^/]"),
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' => {
                output.push('\\');
                output.push(character);
            }
            _ => output.push(character),
        }
    }
    output.push('$');
    regex::Regex::new(&output)
}

/// Deterministic candidate shape shared with plugin discovery.
#[derive(Debug, Clone)]
pub enum SkillEntry {
    DirWithSkillMd { dir: PathBuf, file: PathBuf },
    BareMdFile(PathBuf),
}

impl SkillEntry {
    #[must_use]
    pub fn root_path(&self) -> &Path {
        match self {
            Self::DirWithSkillMd { dir, .. } => dir,
            Self::BareMdFile(path) => path,
        }
    }
}

/// Enumerate direct skill packages deterministically without following links.
#[must_use]
pub fn walk_skill_entries(dir: &Path) -> Vec<SkillEntry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .take(catalog::MAX_SKILL_COUNT.saturating_add(1))
        .collect::<Vec<_>>();
    if paths.len() > catalog::MAX_SKILL_COUNT {
        tracing::warn!(
            target: "openclaudia::skills",
            skill_root = %dir.display(),
            "Skill entry walker reached its count ceiling"
        );
        return Vec::new();
    }
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| {
            let metadata = std::fs::symlink_metadata(&path).ok()?;
            if metadata.file_type().is_symlink() {
                return None;
            }
            if metadata.is_dir() {
                let file = path.join("SKILL.md");
                let file_metadata = std::fs::symlink_metadata(&file).ok()?;
                (!file_metadata.file_type().is_symlink() && file_metadata.is_file())
                    .then_some(SkillEntry::DirWithSkillMd { dir: path, file })
            } else if metadata.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("md")
            {
                Some(SkillEntry::BareMdFile(path))
            } else {
                None
            }
        })
        .collect()
}

/// Load only managed and user-owned skills. Ambient CWD never authorizes a project layer.
#[must_use]
pub fn load_skills() -> Vec<ResolvedSkill> {
    load_global_skills()
}

#[must_use]
pub fn load_global_skills() -> Vec<ResolvedSkill> {
    catalog::load_global()
}

/// Load the exact run's trusted skill catalog.
#[must_use]
pub fn load_skills_for_run(run: &crate::tools::ToolRunContext) -> Vec<ResolvedSkill> {
    catalog::load_for_run(run)
}

#[must_use]
pub fn get_skill(name: &str) -> Option<ResolvedSkill> {
    load_global_skills()
        .into_iter()
        .find(|skill| skill.name == name)
}

#[must_use]
pub fn get_skill_for_run(name: &str, run: &crate::tools::ToolRunContext) -> Option<ResolvedSkill> {
    load_skills_for_run(run)
        .into_iter()
        .find(|skill| skill.name == name)
}

#[must_use]
pub fn get_user_invocable_skill(name: &str) -> Option<ResolvedSkill> {
    get_skill(name).filter(|skill| skill.user_invocable)
}

#[must_use]
pub fn get_user_invocable_skill_for_run(
    name: &str,
    run: &crate::tools::ToolRunContext,
) -> Option<ResolvedSkill> {
    get_skill_for_run(name, run).filter(|skill| skill.user_invocable)
}

/// Resolve one skill and compile only the capabilities valid for this trigger.
///
/// # Errors
///
/// Returns an error when the named skill is unavailable or its activation
/// metadata cannot be compiled.
pub fn activate_skill_for_run(
    run: &crate::tools::ToolRunContext,
    name: &str,
    trigger: SkillActivationTrigger,
) -> Result<SkillActivation, SkillActivationError> {
    let skill = get_skill_for_run(name, run)
        .ok_or_else(|| SkillActivationError::Unavailable(name.to_string()))?;
    activate_resolved(&skill, trigger)
}

/// Resolve an explicitly user-invoked skill.
///
/// # Errors
///
/// Returns an error when the named skill is unavailable, is not user-invocable,
/// or its activation metadata cannot be compiled.
pub fn activate_user_invocable_skill_for_run(
    run: &crate::tools::ToolRunContext,
    name: &str,
) -> Result<SkillActivation, SkillActivationError> {
    let skill = get_skill_for_run(name, run)
        .ok_or_else(|| SkillActivationError::Unavailable(name.to_string()))?;
    if !skill.user_invocable {
        return Err(SkillActivationError::NotUserInvocable(name.to_string()));
    }
    activate_resolved(&skill, SkillActivationTrigger::ExplicitUser)
}

/// Resolve an explicitly user-invoked host-owned skill without consulting an
/// ambient repository.
///
/// # Errors
///
/// Returns an error when the named skill is unavailable, is not user-invocable,
/// or its activation metadata cannot be compiled.
pub fn activate_user_invocable_skill(name: &str) -> Result<SkillActivation, SkillActivationError> {
    let skill =
        get_skill(name).ok_or_else(|| SkillActivationError::Unavailable(name.to_string()))?;
    if !skill.user_invocable {
        return Err(SkillActivationError::NotUserInvocable(name.to_string()));
    }
    activate_resolved(&skill, SkillActivationTrigger::ExplicitUser)
}

fn activate_resolved(
    skill: &ResolvedSkill,
    trigger: SkillActivationTrigger,
) -> Result<SkillActivation, SkillActivationError> {
    let may_apply_capabilities = trigger == SkillActivationTrigger::ExplicitUser;
    let requested_tools = skill.allowed_tools.clone().unwrap_or_default();
    let effective_allowed_tools = if may_apply_capabilities {
        requested_tools
            .iter()
            .filter(|tool| skill.capability_policy.allows_tool(tool))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let effective_model = (may_apply_capabilities && skill.capability_policy.allows_model())
        .then(|| skill.model.clone())
        .flatten();
    let effective_effort = (may_apply_capabilities && skill.capability_policy.allows_effort())
        .then(|| skill.effort.clone())
        .flatten();
    let effective_hooks = if may_apply_capabilities && skill.capability_policy.allows_hooks() {
        skill
            .hooks
            .as_ref()
            .map(parse_hooks)
            .transpose()
            .map_err(|reason| SkillActivationError::InvalidHooks {
                name: skill.name.clone(),
                reason,
            })?
    } else {
        None
    };
    Ok(SkillActivation {
        selection: SkillSelection {
            schema: "openclaudia.skill_selection.v1",
            name: skill.name.clone(),
            description: skill.description.clone(),
            prompt: skill.prompt.clone(),
            argument_hint: skill.argument_hint.clone(),
            trigger,
            provenance: skill.provenance.clone(),
            requested_allowed_tools: requested_tools,
            effective_allowed_tools,
            effective_model,
            effective_effort,
            hooks_active: effective_hooks.is_some(),
        },
        effective_hooks,
    })
}

fn parse_hooks(value: &Value) -> Result<crate::config::HooksConfig, String> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

/// Build bounded automatic path-match context for the current run.
#[must_use]
pub fn conditional_skill_context_items_for_run(
    run: &crate::tools::ToolRunContext,
) -> Vec<crate::context::ContextItem> {
    let touched = run.skill_touched_paths();
    if touched.is_empty() {
        return Vec::new();
    }
    load_skills_for_run(run)
        .into_iter()
        .filter(|skill| touched.iter().any(|path| skill_matches_path(skill, path)))
        .filter_map(|skill| activate_resolved(&skill, SkillActivationTrigger::PathMatch).ok())
        .enumerate()
        .map(|(index, activation)| {
            activation.context_item(format!(
                "skill.path_activation.{index}.{}",
                activation.selection().name
            ))
        })
        .collect()
}

/// Clear the bounded catalog cache. Trust is still revalidated independently.
pub fn invalidate_cache() {
    catalog::invalidate();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_skill(root: &Path, relative: &str, frontmatter: &str, body: &str) -> PathBuf {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("skill parent");
        }
        std::fs::write(&path, format!("---\n{frontmatter}\n---\n{body}\n")).expect("skill fixture");
        path
    }

    #[test]
    fn delimiter_must_be_a_complete_line() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("bad.md");
        std::fs::write(
            &path,
            "---\nname: demo\ndescription: contains --- text\nbody without delimiter",
        )
        .expect("fixture");
        assert!(matches!(
            parse_skill_file(&path),
            Err(SkillParseError::FrontmatterMissing)
        ));
    }

    #[test]
    fn parser_rejects_invalid_capability_shapes() {
        let root = tempfile::tempdir().expect("root");
        let path = write_skill(
            root.path(),
            "bad.md",
            "name: demo\ndescription: demo\nallowed_tools: [bash, 42]",
            "body",
        );
        assert!(matches!(
            parse_skill_file(&path),
            Err(SkillParseError::YamlFailed(_))
        ));
    }

    #[test]
    fn parser_preserves_compatible_frontmatter() {
        let root = tempfile::tempdir().expect("root");
        let path = write_skill(
            root.path(),
            "demo/SKILL.md",
            "name: demo\ndescription: Demo skill\nwhenToUse: while testing\nargument_hint: <path>\npaths: [\"src/**/*.rs\"]\nuser-invocable: false",
            "Do the work.",
        );
        let skill = parse_skill_file(&path).expect("skill");
        assert_eq!(skill.when_to_use.as_deref(), Some("while testing"));
        assert_eq!(skill.argument_hint.as_deref(), Some("<path>"));
        assert!(!skill.user_invocable);
        assert!(skill_matches_path(&skill, Path::new("src/lib.rs")));
    }

    #[test]
    fn walker_is_sorted_and_rejects_links() {
        let root = tempfile::tempdir().expect("root");
        write_skill(root.path(), "z.md", "name: z\ndescription: z", "z");
        write_skill(root.path(), "a.md", "name: a\ndescription: a", "a");
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.path().join("a.md"), root.path().join("link.md"))
            .expect("link");
        let entries = walk_skill_entries(root.path());
        assert_eq!(entries.len(), 2);
        assert!(entries[0].root_path().ends_with("a.md"));
        assert!(entries[1].root_path().ends_with("z.md"));
    }

    #[test]
    fn model_and_path_activation_never_grant_effects() {
        let root = tempfile::tempdir().expect("root");
        let path = write_skill(
            root.path(),
            "demo.md",
            "name: demo\ndescription: demo\nallowed_tools: [\"Bash(git status *)\"]\nmodel: gpt-5.5\neffort: high",
            "body",
        );
        let definition = parse_skill_file(&path).expect("definition");
        let resolved = ResolvedSkill::new(
            definition,
            SkillProvenance {
                source: SkillSource::User,
                root: root.path().to_path_buf(),
                relative_path: PathBuf::from("demo.md"),
                content_digest: "sha256:test".to_string(),
                catalog_generation: "sha256:catalog".to_string(),
                workspace_generation: 1,
            },
            SkillCapabilityPolicy::host_owned(),
        );
        for trigger in [
            SkillActivationTrigger::ModelSelection,
            SkillActivationTrigger::PathMatch,
        ] {
            let activation = activate_resolved(&resolved, trigger).expect("activation");
            assert!(activation.allowed_tools().is_none());
            assert!(activation.model().is_none());
            assert!(activation.effort().is_none());
        }
        let explicit = activate_resolved(&resolved, SkillActivationTrigger::ExplicitUser)
            .expect("explicit activation");
        assert!(explicit.allowed_tools().is_some());
        assert_eq!(explicit.model(), Some("gpt-5.5"));
    }

    #[test]
    fn workspace_escaping_glob_is_rejected_during_parse() {
        let root = tempfile::tempdir().expect("root");
        let path = write_skill(
            root.path(),
            "bad.md",
            "name: bad\ndescription: bad\npaths: [\"../secret\"]",
            "body",
        );
        assert!(matches!(
            parse_skill_file(&path),
            Err(SkillParseError::InvalidDefinition(_))
        ));
    }

    #[test]
    fn selection_is_typed_data_without_control_markers() {
        let selection = SkillSelection {
            schema: "openclaudia.skill_selection.v1",
            name: "demo".to_string(),
            description: "demo".to_string(),
            prompt: "body".to_string(),
            argument_hint: None,
            trigger: SkillActivationTrigger::ModelSelection,
            provenance: SkillProvenance {
                source: SkillSource::User,
                root: PathBuf::from("/host/skills"),
                relative_path: PathBuf::from("demo.md"),
                content_digest: "sha256:test".to_string(),
                catalog_generation: "sha256:catalog".to_string(),
                workspace_generation: 1,
            },
            requested_allowed_tools: Vec::new(),
            effective_allowed_tools: Vec::new(),
            effective_model: None,
            effective_effort: None,
            hooks_active: false,
        };
        let value = serde_json::to_value(selection).expect("selection JSON");
        assert_eq!(value["schema"], json!("openclaudia.skill_selection.v1"));
        assert!(!value.to_string().contains("<skill"));
    }
}

//! Canonical, generation-bound plugin capability registrations.
//!
//! Plugin package discovery produces inert [`Plugin`] values. This module is
//! the activation boundary: it compiles every component of one reviewed
//! package into an owned, namespaced registration and only publishes the set
//! after the whole package has compiled. Runtime consumers therefore never
//! need to reread mutable plugin files or invent component identities.

use super::manifest::{LspServerConfig, McpServerConfig};
use super::transaction::{
    digest_package_tree, verify_installed_generation, ArtifactGenerationReceipt,
    ArtifactSourceProvenance, ArtifactVerificationLevel,
};
use super::{Plugin, PluginCommand, PluginError, PluginHook, PluginMcpServer};
use crate::tools::effect::ToolEffect;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Schema carried by capability snapshots and lifecycle revocation receipts.
pub const PLUGIN_CAPABILITY_SCHEMA: &str = "openclaudia.plugin_capabilities.v1";
const MAX_AGENT_FILE_BYTES: u64 = 256 * 1024;

/// The canonical subsystem that owns an activated component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginComponentKind {
    Command,
    Hook,
    Skill,
    Agent,
    Mcp,
    Lsp,
}

impl PluginComponentKind {
    /// Stable component token used in canonical registration names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Hook => "hook",
            Self::Skill => "skill",
            Self::Agent => "agent",
            Self::Mcp => "mcp",
            Self::Lsp => "lsp",
        }
    }
}

impl std::fmt::Display for PluginComponentKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Immutable artifact and source identity retained on every registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginPackageProvenance {
    pub plugin_id: String,
    pub package: String,
    pub publisher: String,
    pub version: Option<String>,
    pub artifact_digest: String,
    pub source: ArtifactSourceProvenance,
    pub verification: ArtifactVerificationLevel,
    pub verified_signers: Vec<String>,
    pub activated_at_unix: Option<u64>,
}

impl PluginPackageProvenance {
    fn from_plugin(plugin: &Plugin) -> Result<Self, PluginActivationError> {
        let observed_digest = digest_package_tree(plugin.root()).map_err(|error| {
            PluginActivationError::package(plugin, format!("cannot bind package bytes: {error}"))
        })?;
        let receipt = match plugin.generation_receipt() {
            Some(receipt) => Some(receipt.clone()),
            None => verify_installed_generation(plugin.root()).map_err(|error| {
                PluginActivationError::package(
                    plugin,
                    format!("cannot verify installed generation: {error}"),
                )
            })?,
        };

        if let Some(receipt) = receipt {
            if receipt.statement.artifact_digest != observed_digest {
                return Err(PluginActivationError::package(
                    plugin,
                    format!(
                        "activation bytes differ from receipt digest {}",
                        receipt.statement.artifact_digest
                    ),
                ));
            }
            return Ok(Self::from_receipt(receipt));
        }

        Ok(Self {
            plugin_id: plugin.id.clone(),
            package: plugin.name().to_string(),
            publisher: "host-observed-unsigned".to_string(),
            version: plugin.manifest.version.clone(),
            artifact_digest: observed_digest.clone(),
            source: ArtifactSourceProvenance {
                kind: plugin.source.clone(),
                locator: plugin.root().to_string_lossy().into_owned(),
                requested_revision: None,
                resolved_revision: observed_digest,
            },
            verification: ArtifactVerificationLevel::DigestBound,
            verified_signers: Vec::new(),
            activated_at_unix: None,
        })
    }

    fn from_receipt(receipt: ArtifactGenerationReceipt) -> Self {
        Self {
            plugin_id: receipt.plugin_id,
            package: receipt.statement.package,
            publisher: receipt.statement.publisher,
            version: receipt.statement.version,
            artifact_digest: receipt.statement.artifact_digest,
            source: receipt.source,
            verification: receipt.verification,
            verified_signers: receipt.verified_signers,
            activated_at_unix: Some(receipt.activated_at_unix),
        }
    }
}

/// Resource owner used to revoke all work belonging to one artifact generation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PluginLifecycleOwner {
    pub plugin_id: String,
    pub artifact_digest: String,
    pub source_revision: String,
}

impl From<&PluginPackageProvenance> for PluginLifecycleOwner {
    fn from(provenance: &PluginPackageProvenance) -> Self {
        Self {
            plugin_id: provenance.plugin_id.clone(),
            artifact_digest: provenance.artifact_digest.clone(),
            source_revision: provenance.source.resolved_revision.clone(),
        }
    }
}

/// Authority requested by a component. Requests remain subordinate to host
/// policy; registration never turns them into approval receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PluginCapabilityRequest {
    Tool {
        declared: String,
        canonical: String,
        effect: String,
    },
    Model {
        model: String,
    },
    HookEvent {
        event: String,
    },
    Process {
        executable: String,
    },
    NetworkEndpoint {
        endpoint: String,
    },
    Environment {
        name: String,
    },
    Workspace {
        access: String,
    },
    McpToolSurface {
        server: String,
    },
    LanguageServer {
        language: String,
    },
}

/// Direct activation effect plus the maximum effect of the authority a
/// component asks the host to make available at invocation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginEffectDeclaration {
    pub activation: ToolEffect,
    pub invocation_ceiling: ToolEffect,
}

/// Shared identity, schema, effect, capability, and lifecycle record.
#[derive(Debug, Clone)]
pub struct PluginRegistrationMetadata {
    pub schema: &'static str,
    pub canonical_name: String,
    pub logical_name: String,
    pub component_name: String,
    pub kind: PluginComponentKind,
    pub provenance: PluginPackageProvenance,
    pub lifecycle_owner: PluginLifecycleOwner,
    pub activation_generation: u64,
    pub component_digest: String,
    pub input_schema: Value,
    pub result_schema: Value,
    pub effect: PluginEffectDeclaration,
    pub requested_capabilities: Vec<PluginCapabilityRequest>,
}

/// Canonical command registration. `command` is an owned snapshot of the
/// reviewed Markdown; invocation does not reread the package directory.
#[derive(Debug, Clone)]
pub struct PluginCommandRegistration {
    pub metadata: PluginRegistrationMetadata,
    pub command: PluginCommand,
}

/// One canonical hook registration ready for the host hook engine.
#[derive(Debug, Clone)]
pub struct PluginHookRegistration {
    pub metadata: PluginRegistrationMetadata,
    pub hook: PluginHook,
}

/// One parsed plugin skill package.
#[derive(Debug, Clone)]
pub struct PluginSkillRegistration {
    pub metadata: PluginRegistrationMetadata,
    pub definition: crate::skills::SkillDefinition,
}

/// Parsed agent Markdown retained as attributed reference data.
#[derive(Debug, Clone)]
pub struct PluginAgentDefinition {
    pub name: String,
    pub description: Option<String>,
    pub prompt: String,
    pub allowed_tools: Vec<String>,
    pub model: Option<String>,
    pub frontmatter: Value,
    pub source_path: PathBuf,
}

/// One canonical agent registration.
#[derive(Debug, Clone)]
pub struct PluginAgentRegistration {
    pub metadata: PluginRegistrationMetadata,
    pub definition: PluginAgentDefinition,
}

/// One canonical MCP server registration. Environment substitution occurs
/// only against the exact run supplied by the consumer.
#[derive(Debug, Clone)]
pub struct PluginMcpRegistration {
    pub metadata: PluginRegistrationMetadata,
    pub server_name: String,
    pub config: McpServerConfig,
}

impl PluginMcpRegistration {
    /// Resolve protected values from one immutable run capability.
    ///
    /// # Errors
    /// Returns an activation error when a required environment grant is absent
    /// or a protected value is requested in an unsafe process argument.
    pub fn resolve_for_run(
        &self,
        run: &crate::tools::ToolRunContext,
    ) -> Result<PluginMcpServer, PluginActivationError> {
        super::resolved_mcp_server_from_config_with(&self.server_name, &self.config, &|name| {
            Ok(run.mcp_environment_grants().get(name).cloned())
        })
        .map_err(|reason| PluginActivationError::Component {
            plugin: self.metadata.provenance.plugin_id.clone(),
            kind: PluginComponentKind::Mcp,
            component: self.server_name.clone(),
            reason,
        })
    }
}

/// One canonical LSP server registration.
#[derive(Debug, Clone)]
pub struct PluginLspRegistration {
    pub metadata: PluginRegistrationMetadata,
    pub language: String,
    pub config: LspServerConfig,
}

/// Every supported plugin component uses this single registry value type.
#[derive(Debug, Clone)]
pub enum PluginCapabilityRegistration {
    Command(PluginCommandRegistration),
    Hook(PluginHookRegistration),
    Skill(PluginSkillRegistration),
    Agent(PluginAgentRegistration),
    Mcp(PluginMcpRegistration),
    Lsp(PluginLspRegistration),
}

impl PluginCapabilityRegistration {
    #[must_use]
    pub const fn metadata(&self) -> &PluginRegistrationMetadata {
        match self {
            Self::Command(registration) => &registration.metadata,
            Self::Hook(registration) => &registration.metadata,
            Self::Skill(registration) => &registration.metadata,
            Self::Agent(registration) => &registration.metadata,
            Self::Mcp(registration) => &registration.metadata,
            Self::Lsp(registration) => &registration.metadata,
        }
    }
}

/// A typed command invocation that retains the exact package generation.
#[derive(Debug, Clone)]
pub struct PluginCommandInvocation {
    pub registration: PluginCommandRegistration,
    pub prompt: String,
}

/// A typed skill invocation that retains provenance and requested authority.
#[derive(Debug, Clone)]
pub struct PluginSkillInvocation {
    pub registration: PluginSkillRegistration,
    pub prompt: String,
}

/// A typed agent invocation that retains provenance and requested authority.
#[derive(Debug, Clone)]
pub struct PluginAgentInvocation {
    pub registration: PluginAgentRegistration,
    pub task: String,
}

/// Typed activation failures. A component error rejects its entire package
/// generation; the prior registry snapshot remains published.
#[derive(Debug, thiserror::Error)]
pub enum PluginActivationError {
    #[error("plugin '{plugin}' capability activation failed: {reason}")]
    Package { plugin: String, reason: String },
    #[error("plugin '{plugin}' {kind} '{component}' is unavailable: {reason}")]
    Component {
        plugin: String,
        kind: PluginComponentKind,
        component: String,
        reason: String,
    },
    #[error("canonical plugin registration collision: {0}")]
    Collision(String),
}

impl PluginActivationError {
    fn package(plugin: &Plugin, reason: impl Into<String>) -> Self {
        Self::Package {
            plugin: plugin.id.clone(),
            reason: reason.into(),
        }
    }

    fn component(
        plugin: &Plugin,
        kind: PluginComponentKind,
        component: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::Component {
            plugin: plugin.id.clone(),
            kind,
            component: component.into(),
            reason: reason.into(),
        }
    }
}

/// Atomic lifecycle handoff produced when disable/update removes registrations.
#[derive(Debug, Clone, Serialize)]
pub struct PluginCapabilityRevocation {
    pub schema: &'static str,
    pub retired_registry_generation: u64,
    pub successor_registry_generation: u64,
    pub retired_owners: Vec<PluginLifecycleOwner>,
    pub removed_registrations: Vec<String>,
    pub removed_kinds: BTreeSet<PluginComponentKind>,
}

impl PluginCapabilityRevocation {
    /// MCP and LSP components own live transports/processes that the
    /// composition root must disconnect and join before acknowledging revoke.
    #[must_use]
    pub fn requires_runtime_shutdown(&self) -> bool {
        self.removed_kinds
            .iter()
            .any(|kind| matches!(kind, PluginComponentKind::Mcp | PluginComponentKind::Lsp))
    }

    /// Commands, hooks, skills, and agents contribute model-visible schema or
    /// reference context and must be removed on the same handoff.
    #[must_use]
    pub fn removes_context_or_schema(&self) -> bool {
        self.removed_kinds.iter().any(|kind| {
            matches!(
                kind,
                PluginComponentKind::Command
                    | PluginComponentKind::Hook
                    | PluginComponentKind::Skill
                    | PluginComponentKind::Agent
                    | PluginComponentKind::Mcp
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ComponentAlias {
    plugin_name: String,
    kind: PluginComponentKind,
    component_name: String,
}

/// Immutable in-process catalogue for all activated plugin components.
#[derive(Debug, Clone, Default)]
pub struct PluginCapabilityRegistry {
    generation: u64,
    by_canonical: BTreeMap<String, PluginCapabilityRegistration>,
    aliases: BTreeMap<ComponentAlias, String>,
    owners_by_plugin: BTreeMap<String, PluginLifecycleOwner>,
}

impl PluginCapabilityRegistry {
    /// Current atomic catalogue generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Snapshot every active registration in canonical-name order.
    pub fn all(&self) -> impl Iterator<Item = &PluginCapabilityRegistration> {
        self.by_canonical.values()
    }

    pub fn commands(&self) -> impl Iterator<Item = &PluginCommandRegistration> {
        self.by_canonical
            .values()
            .filter_map(|registration| match registration {
                PluginCapabilityRegistration::Command(registration) => Some(registration),
                _ => None,
            })
    }

    pub fn hooks(&self) -> impl Iterator<Item = &PluginHookRegistration> {
        self.by_canonical
            .values()
            .filter_map(|registration| match registration {
                PluginCapabilityRegistration::Hook(registration) => Some(registration),
                _ => None,
            })
    }

    pub fn skills(&self) -> impl Iterator<Item = &PluginSkillRegistration> {
        self.by_canonical
            .values()
            .filter_map(|registration| match registration {
                PluginCapabilityRegistration::Skill(registration) => Some(registration),
                _ => None,
            })
    }

    pub fn agents(&self) -> impl Iterator<Item = &PluginAgentRegistration> {
        self.by_canonical
            .values()
            .filter_map(|registration| match registration {
                PluginCapabilityRegistration::Agent(registration) => Some(registration),
                _ => None,
            })
    }

    pub fn mcp_servers(&self) -> impl Iterator<Item = &PluginMcpRegistration> {
        self.by_canonical
            .values()
            .filter_map(|registration| match registration {
                PluginCapabilityRegistration::Mcp(registration) => Some(registration),
                _ => None,
            })
    }

    pub fn lsp_servers(&self) -> impl Iterator<Item = &PluginLspRegistration> {
        self.by_canonical
            .values()
            .filter_map(|registration| match registration {
                PluginCapabilityRegistration::Lsp(registration) => Some(registration),
                _ => None,
            })
    }

    #[must_use]
    pub fn find_command(
        &self,
        plugin_name: &str,
        command_name: &str,
    ) -> Option<&PluginCommandRegistration> {
        self.find(plugin_name, PluginComponentKind::Command, command_name)
            .and_then(|registration| match registration {
                PluginCapabilityRegistration::Command(registration) => Some(registration),
                _ => None,
            })
    }

    #[must_use]
    pub fn find_skill(
        &self,
        plugin_name: &str,
        skill_name: &str,
    ) -> Option<&PluginSkillRegistration> {
        self.find(plugin_name, PluginComponentKind::Skill, skill_name)
            .and_then(|registration| match registration {
                PluginCapabilityRegistration::Skill(registration) => Some(registration),
                _ => None,
            })
    }

    #[must_use]
    pub fn find_agent(
        &self,
        plugin_name: &str,
        agent_name: &str,
    ) -> Option<&PluginAgentRegistration> {
        self.find(plugin_name, PluginComponentKind::Agent, agent_name)
            .and_then(|registration| match registration {
                PluginCapabilityRegistration::Agent(registration) => Some(registration),
                _ => None,
            })
    }

    fn find(
        &self,
        plugin_name: &str,
        kind: PluginComponentKind,
        component_name: &str,
    ) -> Option<&PluginCapabilityRegistration> {
        let alias = ComponentAlias {
            plugin_name: plugin_name.to_string(),
            kind,
            component_name: component_name.to_string(),
        };
        self.aliases
            .get(&alias)
            .and_then(|canonical| self.by_canonical.get(canonical))
    }

    pub(crate) fn compile_plugin(
        plugin: &Plugin,
        activation_generation: u64,
    ) -> Result<CompiledPluginGeneration, PluginActivationError> {
        CompiledPluginGeneration::compile(plugin, activation_generation)
    }

    pub(crate) fn replace_all(
        &mut self,
        compiled: Vec<CompiledPluginGeneration>,
    ) -> Result<Option<PluginCapabilityRevocation>, PluginActivationError> {
        let successor_generation = self.generation.saturating_add(1);
        let mut next = Self {
            generation: successor_generation,
            ..Self::default()
        };
        for generation in compiled {
            next.insert_generation(generation)?;
        }
        let revocation = self.revocation_for(&next);
        *self = next;
        Ok(revocation)
    }

    pub(crate) fn activate(
        &mut self,
        compiled: CompiledPluginGeneration,
    ) -> Result<Option<PluginCapabilityRevocation>, PluginActivationError> {
        let mut next = self.clone();
        next.generation = self.generation.saturating_add(1);
        next.remove_plugin(&compiled.plugin_name);
        next.insert_generation(compiled)?;
        let revocation = self.revocation_for(&next);
        *self = next;
        Ok(revocation)
    }

    pub(crate) fn revoke_plugin(
        &mut self,
        plugin_name: &str,
    ) -> Option<PluginCapabilityRevocation> {
        let mut next = self.clone();
        next.generation = self.generation.saturating_add(1);
        next.remove_plugin(plugin_name);
        let revocation = self.revocation_for(&next);
        *self = next;
        revocation
    }

    fn insert_generation(
        &mut self,
        generation: CompiledPluginGeneration,
    ) -> Result<(), PluginActivationError> {
        if self
            .owners_by_plugin
            .insert(generation.plugin_name.clone(), generation.owner)
            .is_some()
        {
            return Err(PluginActivationError::Collision(format!(
                "plugin '{}' has more than one active generation",
                generation.plugin_name
            )));
        }
        for registration in generation.registrations {
            let metadata = registration.metadata();
            let alias = ComponentAlias {
                plugin_name: generation.plugin_name.clone(),
                kind: metadata.kind,
                component_name: metadata.component_name.clone(),
            };
            if self.aliases.contains_key(&alias) {
                return Err(PluginActivationError::Collision(format!(
                    "{}:{}:{}",
                    alias.plugin_name, alias.kind, alias.component_name
                )));
            }
            if self.by_canonical.contains_key(&metadata.canonical_name) {
                return Err(PluginActivationError::Collision(
                    metadata.canonical_name.clone(),
                ));
            }
            self.aliases.insert(alias, metadata.canonical_name.clone());
            self.by_canonical
                .insert(metadata.canonical_name.clone(), registration);
        }
        Ok(())
    }

    fn remove_plugin(&mut self, plugin_name: &str) {
        self.owners_by_plugin.remove(plugin_name);
        let canonical_names = self
            .aliases
            .iter()
            .filter(|(alias, _)| alias.plugin_name == plugin_name)
            .map(|(_, canonical)| canonical.clone())
            .collect::<Vec<_>>();
        self.aliases
            .retain(|alias, _| alias.plugin_name != plugin_name);
        for canonical in canonical_names {
            self.by_canonical.remove(&canonical);
        }
    }

    fn revocation_for(&self, next: &Self) -> Option<PluginCapabilityRevocation> {
        let retired_owners = self
            .owners_by_plugin
            .iter()
            .filter(|(plugin, owner)| next.owners_by_plugin.get(*plugin) != Some(*owner))
            .map(|(_, owner)| owner.clone())
            .collect::<Vec<_>>();
        let removed = self
            .by_canonical
            .iter()
            .filter(|(canonical, _)| !next.by_canonical.contains_key(*canonical))
            .collect::<Vec<_>>();
        if retired_owners.is_empty() && removed.is_empty() {
            return None;
        }
        Some(PluginCapabilityRevocation {
            schema: PLUGIN_CAPABILITY_SCHEMA,
            retired_registry_generation: self.generation,
            successor_registry_generation: next.generation,
            retired_owners,
            removed_registrations: removed
                .iter()
                .map(|(canonical, _)| (*canonical).clone())
                .collect(),
            removed_kinds: removed
                .iter()
                .map(|(_, registration)| registration.metadata().kind)
                .collect(),
        })
    }
}

pub(crate) struct CompiledPluginGeneration {
    plugin_name: String,
    owner: PluginLifecycleOwner,
    registrations: Vec<PluginCapabilityRegistration>,
}

impl CompiledPluginGeneration {
    fn compile(plugin: &Plugin, activation_generation: u64) -> Result<Self, PluginActivationError> {
        let provenance = PluginPackageProvenance::from_plugin(plugin)?;
        let owner = PluginLifecycleOwner::from(&provenance);
        let mut registrations = Vec::new();

        compile_commands(
            plugin,
            &provenance,
            &owner,
            activation_generation,
            &mut registrations,
        )?;
        compile_hooks(
            plugin,
            &provenance,
            &owner,
            activation_generation,
            &mut registrations,
        )?;
        compile_skills(
            plugin,
            &provenance,
            &owner,
            activation_generation,
            &mut registrations,
        )?;
        compile_agents(
            plugin,
            &provenance,
            &owner,
            activation_generation,
            &mut registrations,
        )?;
        compile_mcp(
            plugin,
            &provenance,
            &owner,
            activation_generation,
            &mut registrations,
        )?;
        compile_lsp(
            plugin,
            &provenance,
            &owner,
            activation_generation,
            &mut registrations,
        )?;

        let final_digest = digest_package_tree(plugin.root()).map_err(|error| {
            PluginActivationError::package(plugin, format!("cannot seal package bytes: {error}"))
        })?;
        if final_digest != provenance.artifact_digest {
            return Err(PluginActivationError::package(
                plugin,
                "package changed while its capability generation was being compiled",
            ));
        }

        registrations.sort_by(|left, right| {
            left.metadata()
                .canonical_name
                .cmp(&right.metadata().canonical_name)
        });
        let mut names = BTreeSet::new();
        for registration in &registrations {
            if !names.insert(registration.metadata().logical_name.clone()) {
                return Err(PluginActivationError::Collision(
                    registration.metadata().logical_name.clone(),
                ));
            }
        }

        Ok(Self {
            plugin_name: plugin.name().to_string(),
            owner,
            registrations,
        })
    }
}

fn compile_commands(
    plugin: &Plugin,
    provenance: &PluginPackageProvenance,
    owner: &PluginLifecycleOwner,
    activation_generation: u64,
    registrations: &mut Vec<PluginCapabilityRegistration>,
) -> Result<(), PluginActivationError> {
    let mut commands = plugin.resolved_commands();
    commands.sort_by(|left, right| left.name.cmp(&right.name));
    for command in commands {
        validate_component_name(plugin, PluginComponentKind::Command, &command.name)?;
        if command.content.trim().is_empty() {
            return Err(PluginActivationError::component(
                plugin,
                PluginComponentKind::Command,
                &command.name,
                "command body is empty",
            ));
        }
        let (capabilities, ceiling) = tool_capabilities(command.allowed_tools.as_deref());
        let mut requested = capabilities;
        if let Some(model) = command.model.as_ref() {
            requested.push(PluginCapabilityRequest::Model {
                model: model.clone(),
            });
        }
        let metadata = registration_metadata(
            plugin,
            provenance,
            owner,
            activation_generation,
            PluginComponentKind::Command,
            &command.name,
            command.content.as_bytes(),
            json!({
                "type": "object",
                "properties": {"arguments": {"type": "string"}},
                "additionalProperties": false
            }),
            context_result_schema(),
            PluginEffectDeclaration {
                activation: ToolEffect::ReadOnly,
                invocation_ceiling: ceiling,
            },
            requested,
        );
        registrations.push(PluginCapabilityRegistration::Command(
            PluginCommandRegistration { metadata, command },
        ));
    }
    Ok(())
}

fn compile_hooks(
    plugin: &Plugin,
    provenance: &PluginPackageProvenance,
    owner: &PluginLifecycleOwner,
    activation_generation: u64,
    registrations: &mut Vec<PluginCapabilityRegistration>,
) -> Result<(), PluginActivationError> {
    let mut hooks = plugin.resolved_hooks();
    hooks.sort_by(|left, right| {
        (&left.event, &left.matcher, &left.command).cmp(&(
            &right.event,
            &right.matcher,
            &right.command,
        ))
    });
    for (index, mut hook) in hooks.into_iter().enumerate() {
        if let Some(command) = hook.command.as_mut() {
            let quoted_root = shlex::try_quote(&provenance.source.locator).map_err(|error| {
                PluginActivationError::component(
                    plugin,
                    PluginComponentKind::Hook,
                    &hook.event,
                    format!("plugin root cannot be represented in a command: {error}"),
                )
            })?;
            *command = command
                .replace("${CLAUDE_PLUGIN_ROOT}", quoted_root.as_ref())
                .replace("$CLAUDE_PLUGIN_ROOT", quoted_root.as_ref())
                .replace("${PLUGIN_ROOT}", quoted_root.as_ref())
                .replace("$PLUGIN_ROOT", quoted_root.as_ref());
        }
        validate_hook(plugin, &hook)?;
        let component = format!("{}-{index}", hook.event);
        let command = hook.command.as_deref().unwrap_or_default();
        let mut requested = vec![
            PluginCapabilityRequest::HookEvent {
                event: hook.event.clone(),
            },
            PluginCapabilityRequest::Workspace {
                access: "sandboxed_mutation".to_string(),
            },
        ];
        if let Some(executable) = first_command_token(command) {
            requested.push(PluginCapabilityRequest::Process { executable });
        }
        let metadata = registration_metadata(
            plugin,
            provenance,
            owner,
            activation_generation,
            PluginComponentKind::Hook,
            &component,
            format!(
                "{}\0{}\0{}\0{}",
                hook.event,
                hook.matcher.as_deref().unwrap_or_default(),
                command,
                hook.timeout
            )
            .as_bytes(),
            json!({"$ref": "openclaudia.hook_input.v1"}),
            json!({"$ref": "openclaudia.hook_receipt.v1"}),
            PluginEffectDeclaration {
                activation: ToolEffect::ReadOnly,
                invocation_ceiling: ToolEffect::WorkspaceMutation,
            },
            requested,
        );
        registrations.push(PluginCapabilityRegistration::Hook(PluginHookRegistration {
            metadata,
            hook,
        }));
    }
    Ok(())
}

fn compile_skills(
    plugin: &Plugin,
    provenance: &PluginPackageProvenance,
    owner: &PluginLifecycleOwner,
    activation_generation: u64,
    registrations: &mut Vec<PluginCapabilityRegistration>,
) -> Result<(), PluginActivationError> {
    let mut paths = plugin.skill_paths.clone();
    paths.sort();
    paths.dedup();
    for root in paths {
        let path = if root.is_dir() {
            root.join("SKILL.md")
        } else {
            root.clone()
        };
        let definition = crate::skills::parse_skill_file(&path).map_err(|error| {
            PluginActivationError::component(
                plugin,
                PluginComponentKind::Skill,
                path.display().to_string(),
                error.to_string(),
            )
        })?;
        validate_component_name(plugin, PluginComponentKind::Skill, &definition.name)?;
        if let Some(hooks) = definition.hooks.as_ref() {
            let config = serde_json::from_value::<crate::config::HooksConfig>(hooks.clone())
                .map_err(|error| {
                    PluginActivationError::component(
                        plugin,
                        PluginComponentKind::Skill,
                        &definition.name,
                        format!("invalid skill hook schema: {error}"),
                    )
                })?;
            config.validate_runtime().map_err(|reason| {
                PluginActivationError::component(
                    plugin,
                    PluginComponentKind::Skill,
                    &definition.name,
                    format!("unavailable skill hooks: {reason}"),
                )
            })?;
        }
        let (capabilities, ceiling) = tool_capabilities(definition.allowed_tools.as_deref());
        let mut requested = capabilities;
        if let Some(model) = definition.model.as_ref() {
            requested.push(PluginCapabilityRequest::Model {
                model: model.clone(),
            });
        }
        let metadata = registration_metadata(
            plugin,
            provenance,
            owner,
            activation_generation,
            PluginComponentKind::Skill,
            &definition.name,
            definition.prompt.as_bytes(),
            json!({
                "type": "object",
                "properties": {"arguments": {"type": "string"}},
                "additionalProperties": false
            }),
            context_result_schema(),
            PluginEffectDeclaration {
                activation: ToolEffect::ReadOnly,
                invocation_ceiling: ceiling,
            },
            requested,
        );
        registrations.push(PluginCapabilityRegistration::Skill(
            PluginSkillRegistration {
                metadata,
                definition,
            },
        ));
    }
    Ok(())
}

fn compile_agents(
    plugin: &Plugin,
    provenance: &PluginPackageProvenance,
    owner: &PluginLifecycleOwner,
    activation_generation: u64,
    registrations: &mut Vec<PluginCapabilityRegistration>,
) -> Result<(), PluginActivationError> {
    let mut paths = plugin.agent_paths.clone();
    paths.sort();
    paths.dedup();
    for path in paths {
        let definition = parse_agent_file(plugin, &path)?;
        validate_component_name(plugin, PluginComponentKind::Agent, &definition.name)?;
        let default_tools = definition.allowed_tools.is_empty().then(|| {
            crate::subagent::AgentType::GeneralPurpose
                .allowed_tools()
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        });
        let effective_tools = default_tools
            .as_deref()
            .unwrap_or(&definition.allowed_tools);
        let (mut requested, ceiling) = tool_capabilities(Some(effective_tools));
        if let Some(model) = definition.model.as_ref() {
            requested.push(PluginCapabilityRequest::Model {
                model: model.clone(),
            });
        }
        let metadata = registration_metadata(
            plugin,
            provenance,
            owner,
            activation_generation,
            PluginComponentKind::Agent,
            &definition.name,
            definition.prompt.as_bytes(),
            json!({
                "type": "object",
                "properties": {"task": {"type": "string", "minLength": 1}},
                "required": ["task"],
                "additionalProperties": false
            }),
            json!({"$ref": "openclaudia.subagent_result.v1"}),
            PluginEffectDeclaration {
                activation: ToolEffect::ReadOnly,
                invocation_ceiling: ceiling,
            },
            requested,
        );
        registrations.push(PluginCapabilityRegistration::Agent(
            PluginAgentRegistration {
                metadata,
                definition,
            },
        ));
    }
    Ok(())
}

fn compile_mcp(
    plugin: &Plugin,
    provenance: &PluginPackageProvenance,
    owner: &PluginLifecycleOwner,
    activation_generation: u64,
    registrations: &mut Vec<PluginCapabilityRegistration>,
) -> Result<(), PluginActivationError> {
    let mut configs = plugin.mcp_configs.iter().collect::<Vec<_>>();
    configs.sort_by_key(|(name, _)| *name);
    for (name, config) in configs {
        validate_component_name(plugin, PluginComponentKind::Mcp, name)?;
        validate_mcp_config(plugin, name, config)?;
        let mut requested = vec![PluginCapabilityRequest::McpToolSurface {
            server: name.clone(),
        }];
        requested.extend(environment_capabilities(&config.env));
        match config.transport.as_str() {
            "stdio" => requested.push(PluginCapabilityRequest::Process {
                executable: config.command.clone().unwrap_or_default(),
            }),
            "http" => requested.push(PluginCapabilityRequest::NetworkEndpoint {
                endpoint: config.url.clone().unwrap_or_default(),
            }),
            _ => unreachable!("validated transport"),
        }
        let component_bytes = serde_json::to_vec(config).map_err(|error| {
            PluginActivationError::component(
                plugin,
                PluginComponentKind::Mcp,
                name,
                format!("cannot bind server configuration: {error}"),
            )
        })?;
        let metadata = registration_metadata(
            plugin,
            provenance,
            owner,
            activation_generation,
            PluginComponentKind::Mcp,
            name,
            &component_bytes,
            json!({"$ref": "mcp.initialize.v1"}),
            json!({"$ref": "mcp.tool_catalog.v1"}),
            PluginEffectDeclaration {
                activation: ToolEffect::ExternalMutation,
                invocation_ceiling: ToolEffect::Destructive,
            },
            requested,
        );
        registrations.push(PluginCapabilityRegistration::Mcp(PluginMcpRegistration {
            metadata,
            server_name: name.clone(),
            config: config.clone(),
        }));
    }
    Ok(())
}

fn compile_lsp(
    plugin: &Plugin,
    provenance: &PluginPackageProvenance,
    owner: &PluginLifecycleOwner,
    activation_generation: u64,
    registrations: &mut Vec<PluginCapabilityRegistration>,
) -> Result<(), PluginActivationError> {
    let mut configs = plugin.lsp_configs.iter().collect::<Vec<_>>();
    configs.sort_by_key(|(language, _)| *language);
    for (language, config) in configs {
        validate_component_name(plugin, PluginComponentKind::Lsp, language)?;
        if config.command.trim().is_empty() {
            return Err(PluginActivationError::component(
                plugin,
                PluginComponentKind::Lsp,
                language,
                "language server command is empty",
            ));
        }
        let mut requested = vec![
            PluginCapabilityRequest::LanguageServer {
                language: language.clone(),
            },
            PluginCapabilityRequest::Process {
                executable: config.command.clone(),
            },
            PluginCapabilityRequest::Workspace {
                access: "read".to_string(),
            },
        ];
        requested.extend(environment_capabilities(&config.env));
        let component_bytes = serde_json::to_vec(config).map_err(|error| {
            PluginActivationError::component(
                plugin,
                PluginComponentKind::Lsp,
                language,
                format!("cannot bind language server configuration: {error}"),
            )
        })?;
        let metadata = registration_metadata(
            plugin,
            provenance,
            owner,
            activation_generation,
            PluginComponentKind::Lsp,
            language,
            &component_bytes,
            json!({"$ref": "openclaudia.lsp_request.v1"}),
            json!({"$ref": "openclaudia.lsp_response.v1"}),
            PluginEffectDeclaration {
                activation: ToolEffect::ExternalMutation,
                invocation_ceiling: ToolEffect::ExternalMutation,
            },
            requested,
        );
        registrations.push(PluginCapabilityRegistration::Lsp(PluginLspRegistration {
            metadata,
            language: language.clone(),
            config: config.clone(),
        }));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // One immutable record assembled at the package transaction boundary.
fn registration_metadata(
    plugin: &Plugin,
    provenance: &PluginPackageProvenance,
    owner: &PluginLifecycleOwner,
    activation_generation: u64,
    kind: PluginComponentKind,
    component_name: &str,
    component_bytes: &[u8],
    input_schema: Value,
    result_schema: Value,
    effect: PluginEffectDeclaration,
    requested_capabilities: Vec<PluginCapabilityRequest>,
) -> PluginRegistrationMetadata {
    let plugin_namespace = encode_name(plugin.name());
    let component_namespace = encode_name(component_name);
    let package_namespace = encode_name(&provenance.package);
    let publisher_namespace = encode_name(&provenance.publisher);
    let digest_namespace = encode_name(&provenance.artifact_digest);
    let logical_name = format!(
        "plugin__{plugin_namespace}__{}__{component_namespace}",
        kind.as_str()
    );
    let canonical_name = format!(
        "plugin__{publisher_namespace}__{package_namespace}__{}__{component_namespace}__g{digest_namespace}",
        kind.as_str()
    );
    PluginRegistrationMetadata {
        schema: PLUGIN_CAPABILITY_SCHEMA,
        canonical_name,
        logical_name,
        component_name: component_name.to_string(),
        kind,
        provenance: provenance.clone(),
        lifecycle_owner: owner.clone(),
        activation_generation,
        component_digest: crate::runtime::ContentDigest::sha256(component_bytes).to_string(),
        input_schema,
        result_schema,
        effect,
        requested_capabilities,
    }
}

fn validate_component_name(
    plugin: &Plugin,
    kind: PluginComponentKind,
    name: &str,
) -> Result<(), PluginActivationError> {
    if name.trim().is_empty() {
        return Err(PluginActivationError::component(
            plugin,
            kind,
            name,
            "component name is empty",
        ));
    }
    if name.len() > 256 || name.chars().any(char::is_control) {
        return Err(PluginActivationError::component(
            plugin,
            kind,
            name,
            "component name is oversized or contains control characters",
        ));
    }
    Ok(())
}

fn validate_hook(plugin: &Plugin, hook: &PluginHook) -> Result<(), PluginActivationError> {
    if !matches!(
        hook.event.as_str(),
        "PreToolUse"
            | "PostToolUse"
            | "SessionStart"
            | "Notification"
            | "Stop"
            | "UserPromptSubmit"
    ) {
        return Err(PluginActivationError::component(
            plugin,
            PluginComponentKind::Hook,
            &hook.event,
            "event is not supported by the canonical hook lifecycle",
        ));
    }
    if hook.hook_type != "command" {
        return Err(PluginActivationError::component(
            plugin,
            PluginComponentKind::Hook,
            &hook.event,
            format!("hook type '{}' is not operational", hook.hook_type),
        ));
    }
    if hook
        .command
        .as_deref()
        .is_none_or(|command| command.trim().is_empty())
    {
        return Err(PluginActivationError::component(
            plugin,
            PluginComponentKind::Hook,
            &hook.event,
            "command hook has no command",
        ));
    }
    if hook.timeout == 0 {
        return Err(PluginActivationError::component(
            plugin,
            PluginComponentKind::Hook,
            &hook.event,
            "hook timeout must be at least one second",
        ));
    }
    Ok(())
}

fn validate_mcp_config(
    plugin: &Plugin,
    name: &str,
    config: &McpServerConfig,
) -> Result<(), PluginActivationError> {
    match config.transport.as_str() {
        "stdio"
            if config
                .command
                .as_deref()
                .is_none_or(|value| value.trim().is_empty()) =>
        {
            Err(PluginActivationError::component(
                plugin,
                PluginComponentKind::Mcp,
                name,
                "stdio transport requires a non-empty command",
            ))
        }
        "http"
            if config
                .url
                .as_deref()
                .is_none_or(|value| value.trim().is_empty()) =>
        {
            Err(PluginActivationError::component(
                plugin,
                PluginComponentKind::Mcp,
                name,
                "http transport requires a non-empty URL",
            ))
        }
        "stdio" | "http" => Ok(()),
        other => Err(PluginActivationError::component(
            plugin,
            PluginComponentKind::Mcp,
            name,
            format!("unsupported transport '{other}'"),
        )),
    }
}

fn environment_capabilities(
    grants: &crate::secrets::EnvironmentGrants,
) -> Vec<PluginCapabilityRequest> {
    let mut names = grants.keys().cloned().collect::<Vec<_>>();
    names.sort();
    names
        .into_iter()
        .map(|name| PluginCapabilityRequest::Environment { name })
        .collect()
}

fn tool_capabilities(tools: Option<&[String]>) -> (Vec<PluginCapabilityRequest>, ToolEffect) {
    let mut ceiling = ToolEffect::ReadOnly;
    let mut capabilities = Vec::new();
    for declared in tools.into_iter().flatten() {
        let wire_name = normalize_declared_tool(declared);
        let (canonical, effect) = crate::tools::effect::lookup(&wire_name).map_or_else(
            || ("unclassified".to_string(), ToolEffect::Destructive),
            |(_, spec)| (spec.canonical.to_string(), spec.effect),
        );
        ceiling = ceiling.max(effect);
        capabilities.push(PluginCapabilityRequest::Tool {
            declared: declared.clone(),
            canonical,
            effect: effect.as_str().to_string(),
        });
    }
    (capabilities, ceiling)
}

fn normalize_declared_tool(declared: &str) -> String {
    let name = declared
        .split_once('(')
        .map_or(declared, |(name, _)| name)
        .trim();
    let normalized = name
        .chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect::<String>();
    match normalized.as_str() {
        "bash" | "shell" => "bash",
        "read" | "readfile" => "read_file",
        "write" | "writefile" => "write_file",
        "edit" | "editfile" | "multiedit" => "edit_file",
        "notebookedit" => "notebook_edit",
        "glob" => "glob",
        "grep" => "grep",
        "listfiles" => "list_files",
        "webfetch" => "web_fetch",
        "websearch" => "web_search",
        "task" => "task",
        _ => name,
    }
    .to_string()
}

fn first_command_token(command: &str) -> Option<String> {
    shlex::split(command)
        .and_then(|parts| parts.into_iter().next())
        .filter(|part| !part.trim().is_empty())
}

fn context_result_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "context": {"type": "string"},
            "provenance": {"$ref": "openclaudia.plugin_provenance.v1"}
        },
        "required": ["context", "provenance"],
        "additionalProperties": false
    })
}

fn encode_name(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() {
            encoded.push(char::from(byte.to_ascii_lowercase()));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "_{byte:02x}");
        }
    }
    encoded
}

fn parse_agent_file(
    plugin: &Plugin,
    path: &Path,
) -> Result<PluginAgentDefinition, PluginActivationError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        PluginActivationError::component(
            plugin,
            PluginComponentKind::Agent,
            path.display().to_string(),
            format!("cannot inspect agent file: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PluginActivationError::component(
            plugin,
            PluginComponentKind::Agent,
            path.display().to_string(),
            "agent definition must be a regular file",
        ));
    }
    if metadata.len() > MAX_AGENT_FILE_BYTES {
        return Err(PluginActivationError::component(
            plugin,
            PluginComponentKind::Agent,
            path.display().to_string(),
            format!("agent definition exceeds {MAX_AGENT_FILE_BYTES} bytes"),
        ));
    }
    let content = std::fs::read_to_string(path).map_err(|error| {
        PluginActivationError::component(
            plugin,
            PluginComponentKind::Agent,
            path.display().to_string(),
            format!("cannot read agent file: {error}"),
        )
    })?;
    let (frontmatter, prompt) = split_markdown_frontmatter(&content).map_err(|reason| {
        PluginActivationError::component(
            plugin,
            PluginComponentKind::Agent,
            path.display().to_string(),
            reason,
        )
    })?;
    if prompt.trim().is_empty() {
        return Err(PluginActivationError::component(
            plugin,
            PluginComponentKind::Agent,
            path.display().to_string(),
            "agent prompt is empty",
        ));
    }
    let fallback_name = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let name = frontmatter
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or(fallback_name)
        .to_string();
    let description = frontmatter
        .get("description")
        .and_then(Value::as_str)
        .map(str::to_string);
    let model = frontmatter
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_string);
    let allowed_tools = parse_agent_tools(&frontmatter).map_err(|reason| {
        PluginActivationError::component(
            plugin,
            PluginComponentKind::Agent,
            path.display().to_string(),
            reason,
        )
    })?;
    Ok(PluginAgentDefinition {
        name,
        description,
        prompt,
        allowed_tools,
        model,
        frontmatter,
        source_path: path.to_path_buf(),
    })
}

fn split_markdown_frontmatter(content: &str) -> Result<(Value, String), String> {
    let Some(after_open) = content.strip_prefix("---") else {
        return Ok((json!({}), content.to_string()));
    };
    let after_open = after_open.trim_start_matches(['\r', '\n']);
    let Some(end) = after_open.find("\n---") else {
        return Err("agent YAML frontmatter is not terminated".to_string());
    };
    let yaml = after_open
        .get(..end)
        .ok_or_else(|| "agent frontmatter boundary is invalid".to_string())?;
    let body = after_open
        .get(end.saturating_add(4)..)
        .ok_or_else(|| "agent body boundary is invalid".to_string())?
        .trim_start_matches(['\r', '\n'])
        .to_string();
    let frontmatter = serde_yaml::from_str::<Value>(yaml)
        .map_err(|error| format!("invalid agent YAML frontmatter: {error}"))?;
    if !frontmatter.is_object() {
        return Err("agent frontmatter must be a mapping".to_string());
    }
    Ok((frontmatter, body))
}

fn parse_agent_tools(frontmatter: &Value) -> Result<Vec<String>, String> {
    let Some(value) = frontmatter
        .get("allowed-tools")
        .or_else(|| frontmatter.get("allowed_tools"))
        .or_else(|| frontmatter.get("tools"))
    else {
        return Ok(Vec::new());
    };
    let tools = match value {
        Value::String(value) => crate::permissions::split_allowed_tool_specs_scalar(value),
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "agent tools array must contain only strings".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err("agent tools must be a string or string array".to_string());
        }
    };
    Ok(tools)
}

impl PluginHookRegistration {
    fn canonical_entry(&self) -> crate::config::HookEntry {
        crate::config::HookEntry {
            matcher: self.hook.matcher.clone(),
            hooks: vec![crate::config::Hook::Command {
                command: self.hook.command.clone().unwrap_or_default(),
                shell: false,
                timeout: self.hook.timeout,
            }],
        }
    }
}

impl PluginCapabilityRegistry {
    /// Compile every active plugin hook into the canonical host configuration.
    /// The caller may merge this lower-authority layer with host hooks through
    /// [`crate::hooks::HookEngine::with_scoped_hooks`].
    ///
    /// # Errors
    /// Returns an activation error if a registry invariant is violated.
    pub fn hooks_config(&self) -> Result<crate::config::HooksConfig, PluginActivationError> {
        let mut config = crate::config::HooksConfig::default();
        for registration in self.hooks() {
            let entry = registration.canonical_entry();
            match registration.hook.event.as_str() {
                "PreToolUse" => config.pre_tool_use.push(entry),
                "PostToolUse" => config.post_tool_use.push(entry),
                "SessionStart" => config.session_start.push(entry),
                "Notification" => config.notification.push(entry),
                "Stop" => config.stop.push(entry),
                "UserPromptSubmit" => config.user_prompt_submit.push(entry),
                event => {
                    return Err(PluginActivationError::Component {
                        plugin: registration.metadata.provenance.plugin_id.clone(),
                        kind: PluginComponentKind::Hook,
                        component: registration.metadata.component_name.clone(),
                        reason: format!("unsupported canonical event '{event}'"),
                    });
                }
            }
        }
        config
            .validate_runtime()
            .map_err(|reason| PluginActivationError::Package {
                plugin: "active-plugin-hook-set".to_string(),
                reason,
            })?;
        Ok(config)
    }

    /// Resolve and render an attributed command invocation.
    ///
    /// # Errors
    /// Returns `PluginError::NotFound` when the namespaced command is not in
    /// the current capability generation.
    pub fn invoke_command(
        &self,
        plugin_name: &str,
        command_name: &str,
        arguments: &str,
    ) -> Result<PluginCommandInvocation, PluginError> {
        let registration = self
            .find_command(plugin_name, command_name)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(format!("{plugin_name}:{command_name}")))?;
        let arguments = arguments.trim();
        let prompt = if arguments.is_empty() {
            registration.command.content.clone()
        } else if registration.command.content.contains("$ARGUMENTS") {
            registration
                .command
                .content
                .replace("$ARGUMENTS", arguments)
        } else {
            format!(
                "{}\n\nUser arguments:\n{arguments}",
                registration.command.content
            )
        };
        Ok(PluginCommandInvocation {
            registration,
            prompt,
        })
    }

    /// Resolve and render an attributed skill invocation.
    ///
    /// # Errors
    /// Returns `PluginError::NotFound` when the namespaced skill is not in the
    /// current capability generation.
    pub fn invoke_skill(
        &self,
        plugin_name: &str,
        skill_name: &str,
        arguments: &str,
    ) -> Result<PluginSkillInvocation, PluginError> {
        let registration = self
            .find_skill(plugin_name, skill_name)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(format!("{plugin_name}:{skill_name}")))?;
        let arguments = arguments.trim();
        let prompt = if arguments.is_empty() {
            registration.definition.prompt.clone()
        } else {
            format!(
                "{}\n\nUser arguments:\n{arguments}",
                registration.definition.prompt
            )
        };
        Ok(PluginSkillInvocation {
            registration,
            prompt,
        })
    }

    /// Resolve one namespaced agent with its exact requested task.
    ///
    /// # Errors
    /// Returns `PluginError::NotFound` when the namespaced agent is not in the
    /// current capability generation or when the task is empty.
    pub fn invoke_agent(
        &self,
        plugin_name: &str,
        agent_name: &str,
        task: &str,
    ) -> Result<PluginAgentInvocation, PluginError> {
        if task.trim().is_empty() {
            return Err(PluginError::InvalidManifest(
                "plugin agent task cannot be empty".to_string(),
            ));
        }
        let registration = self
            .find_agent(plugin_name, agent_name)
            .cloned()
            .ok_or_else(|| PluginError::NotFound(format!("{plugin_name}:{agent_name}")))?;
        Ok(PluginAgentInvocation {
            registration,
            task: task.trim().to_string(),
        })
    }
}

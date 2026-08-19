//! Mandatory tool effect classification (S-016; findings F-001, F-052).
//!
//! Before this module, `ToolHandler::permission_target` defaulted to `None`
//! and a `None` target meant "read-only / safe, skip the permission gate".
//! Only five handlers — `bash`, `write_file`, `edit_file`, `notebook_edit`
//! and `web_fetch` — ever overrode it; every other registered handler, and
//! the subagent and MCP surfaces besides, inherited a safe classification by
//! omission. Worktree removal, cron mutation, process killing and Crosslink
//! database writes were all in that set.
//! `PermissionManager::extract_target` returned `None` for unregistered names
//! too, so an unknown tool scored the same as a read-only one.
//!
//! The replacement is a required declaration with no default:
//!
//! * every handler returns a [`ToolEffectSpec`] from
//!   [`crate::tools::ToolHandler::effect_spec`] — a trait method with no
//!   default body, so a new handler cannot compile without classifying itself;
//! * the registry validates every spec while it is being built, so a
//!   structurally invalid declaration fails construction rather than becoming
//!   a silent allow at dispatch time;
//! * tool names that resolve to no spec are denied, not allowed.
//!
//! [`ToolEffect`] uses the `ToolRisk` vocabulary fixed by section 4.2 of
//! `docs/production-remediation-design.md`.

use std::collections::BTreeMap;

/// The typed effect a tool has on the world.
///
/// Effects describe authority exercised on model-visible user, workspace,
/// process, network, and service state. Mandatory host-owned bookkeeping such
/// as append-only audit traces, accounting counters, and reality-ledger
/// observations does not upgrade an otherwise observational tool: those writes
/// are part of the trusted harness boundary and must occur regardless of model
/// approval. A semantic state change visible to later tool calls does count
/// (`bash_output` drains buffers; `agent_output` consumes completed entries).
///
/// Ordering is by escalating authority; [`ToolEffect::ReadOnly`] is the only
/// variant that may skip an authorization decision, and it is a positive claim
/// a handler must make rather than the consequence of an omitted override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The assignment rule, applied consistently so the matrix reads as evidence
/// rather than as a set of individual judgement calls:
///
/// * touches nothing outside the process and performs no egress → `ReadOnly`;
/// * changes only state that dies with the run → `SessionMutation`;
/// * writes durable state inside the workspace → `WorkspaceMutation`;
/// * leaves the host but only reads → `NetworkRead`;
/// * changes state outside the workspace or delegates behavior to a service or
///   long-lived process the host does not control → `ExternalMutation` (which
///   is why `lsp` and `web_browser` sit here while `web_fetch` does not);
/// * can irreversibly destroy user data → `Destructive`.
pub enum ToolEffect {
    /// Observes user/model-visible state without changing it or leaving the
    /// host. Trusted audit/accounting bookkeeping is excluded as described on
    /// the enum.
    ReadOnly,
    /// Mutates state owned by the current session only — in-memory task and
    /// todo lists that die with the process.
    SessionMutation,
    /// Mutates files or durable project state inside the workspace.
    WorkspaceMutation,
    /// Reads from the network. No local mutation and no process spawn, but it
    /// leaves the host and returns untrusted bytes.
    NetworkRead,
    /// Mutates state outside the workspace or acts through an external service
    /// or long-lived process the host does not own.
    ExternalMutation,
    /// Can irreversibly destroy user data.
    Destructive,
}

impl ToolEffect {
    /// Stable lowercase identifier used in the generated matrix and traces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::SessionMutation => "session_mutation",
            Self::WorkspaceMutation => "workspace_mutation",
            Self::NetworkRead => "network_read",
            Self::ExternalMutation => "external_mutation",
            Self::Destructive => "destructive",
        }
    }

    /// Whether an invocation must reach the authorization policy.
    ///
    /// Only [`ToolEffect::ReadOnly`] may bypass the normal approval policy.
    /// Every other variant reaches the rule engine. Policy may still
    /// auto-approve a positively classified session-local mutation; unknown or
    /// malformed classification never receives that treatment.
    #[must_use]
    pub const fn requires_authorization(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }
}

/// How the concrete target of an invocation is recovered from its arguments.
///
/// The target is the string permission rules pattern-match against. It is part
/// of the declaration because the previous design inferred it from a
/// hard-coded table in `permissions.rs` that drifted from the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolTarget {
    /// The tool itself is the whole scope; there is no per-call resource.
    /// Rules match against the wire-level tool name, never an empty target.
    ToolScope,
    /// The target is the string value of this argument key. A missing or
    /// non-string value is malformed and denies.
    Arg(&'static str),
    /// The target is this string argument when present, or a declared default
    /// when omitted. A present non-string value is malformed and denies.
    ///
    /// This is used by read tools such as `list_files`, `glob`, and `grep`,
    /// whose execution defaults `path` to the working directory. Classifying
    /// them against the search expression (or against the whole tool) would
    /// prevent a `Deny Read /protected/**` rule from seeing the resource that
    /// is actually read.
    ArgOrDefault {
        key: &'static str,
        default: &'static str,
    },
    /// The target is derived by the handler's own typed argument parsing
    /// before any effect decision is made — used where one wire-level tool
    /// exposes several operations with different effects.
    ///
    /// A handler declaring this MUST implement
    /// [`crate::tools::ToolHandler::resolve_typed_effect`]; the registry
    /// verifies that at construction time.
    TypedOperation,
}

/// A handler's complete, mandatory effect declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolEffectSpec {
    /// The effect of invoking this tool.
    pub effect: ToolEffect,
    /// Canonical capability name used in `PermissionRule::tool`. Several
    /// wire-level tools may share one canonical capability so that a single
    /// user rule keeps covering them.
    pub canonical: &'static str,
    /// How to recover the per-call target string.
    pub target: ToolTarget,
}

impl ToolEffectSpec {
    /// Declare a read-only tool whose scope is the tool itself.
    #[must_use]
    pub const fn read_only(canonical: &'static str) -> Self {
        Self {
            effect: ToolEffect::ReadOnly,
            canonical,
            target: ToolTarget::ToolScope,
        }
    }

    /// Declare a read-only tool whose target comes from an argument.
    #[must_use]
    pub const fn read_only_arg(canonical: &'static str, arg_key: &'static str) -> Self {
        Self {
            effect: ToolEffect::ReadOnly,
            canonical,
            target: ToolTarget::Arg(arg_key),
        }
    }

    /// Declare a read-only tool whose target is an optional string argument.
    #[must_use]
    pub const fn read_only_arg_or_default(
        canonical: &'static str,
        arg_key: &'static str,
        default: &'static str,
    ) -> Self {
        Self {
            effect: ToolEffect::ReadOnly,
            canonical,
            target: ToolTarget::ArgOrDefault {
                key: arg_key,
                default,
            },
        }
    }

    /// Declare an effectful tool whose target is an optional string argument.
    #[must_use]
    pub const fn effectful_arg_or_default(
        effect: ToolEffect,
        canonical: &'static str,
        arg_key: &'static str,
        default: &'static str,
    ) -> Self {
        Self {
            effect,
            canonical,
            target: ToolTarget::ArgOrDefault {
                key: arg_key,
                default,
            },
        }
    }

    /// Declare an effectful tool whose target comes from an argument.
    #[must_use]
    pub const fn effectful(
        effect: ToolEffect,
        canonical: &'static str,
        arg_key: &'static str,
    ) -> Self {
        Self {
            effect,
            canonical,
            target: ToolTarget::Arg(arg_key),
        }
    }

    /// Declare an effectful tool whose scope is the tool itself.
    #[must_use]
    pub const fn effectful_tool_scope(effect: ToolEffect, canonical: &'static str) -> Self {
        Self {
            effect,
            canonical,
            target: ToolTarget::ToolScope,
        }
    }

    /// Declare a tool whose effect and target are resolved from typed
    /// arguments before authorization. `ceiling` is the maximum effect any
    /// enumerated operation may return. Unparseable calls are denied; the
    /// ceiling is matrix metadata and a registry invariant, never a fallback.
    #[must_use]
    pub const fn typed_operation(ceiling: ToolEffect, canonical: &'static str) -> Self {
        Self {
            effect: ceiling,
            canonical,
            target: ToolTarget::TypedOperation,
        }
    }

    /// Structural validation applied to every spec at registry construction.
    ///
    /// This cannot check that the declared effect is *truthful* — only a human
    /// or the S-088 verifier can — but it does reject declarations that would
    /// silently degrade into the old fail-open shape: an empty canonical name
    /// matches no rule, and an empty argument key reads no argument.
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when the declaration is unusable.
    pub fn validate(&self, tool_name: &str) -> Result<(), String> {
        if self.canonical.trim().is_empty() {
            return Err(format!(
                "tool '{tool_name}' declares an empty canonical capability name; \
                 permission rules could never match it"
            ));
        }
        if let ToolTarget::Arg(key) | ToolTarget::ArgOrDefault { key, .. } = self.target {
            if key.trim().is_empty() {
                return Err(format!(
                    "tool '{tool_name}' declares ToolTarget::Arg with an empty argument key"
                ));
            }
        }
        if let ToolTarget::ArgOrDefault { default, .. } = self.target {
            if default.trim().is_empty() {
                return Err(format!(
                    "tool '{tool_name}' declares ToolTarget::ArgOrDefault with an empty default; \
                     permission rules would receive an unusable target"
                ));
            }
        }
        Ok(())
    }
}

/// The effect and target of one concrete invocation, after typed argument
/// resolution. Produced by [`resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEffect {
    /// Effect of this specific call.
    pub effect: ToolEffect,
    /// Canonical capability name for rule matching.
    pub canonical: String,
    /// Concrete target string for rule matching.
    pub target: String,
    /// Operation label when the tool multiplexes several operations, used for
    /// the generated matrix and traces.
    pub operation: Option<String>,
}

/// Why a tool invocation could not be classified.
///
/// Every variant is a denial. There is deliberately no "unclassified but
/// allowed" outcome — that shape is the bug F-001 records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectResolutionError {
    /// No handler and no declared dynamic surface owns this tool name.
    UnknownTool { tool: String },
    /// Tool arguments must use the object envelope required by function-call
    /// schemas. A scalar/array cannot be scoped reliably.
    MalformedEnvelope { tool: String },
    /// The declared target argument is absent or explicitly null.
    MissingArgument { tool: String, arg_key: String },
    /// The declared target argument is empty or has the wrong type.
    MalformedArguments { tool: String, arg_key: String },
    /// A typed-operation handler could not classify these arguments.
    UnclassifiableOperation { tool: String, reason: String },
}

impl EffectResolutionError {
    /// User- and model-facing denial reason.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::UnknownTool { tool } => format!(
                "Denied: tool '{tool}' has no effect classification. Unclassified and unknown \
                 tools are unavailable."
            ),
            Self::MalformedEnvelope { tool } => format!(
                "Denied: {tool} tool call has malformed arguments (expected a JSON object)"
            ),
            Self::MissingArgument { tool, arg_key } => {
                format!("Denied: Missing '{arg_key}' argument required for {tool} tool call")
            }
            Self::MalformedArguments { tool, arg_key } => format!(
                "Denied: {tool} tool call has malformed arguments (expected non-empty string '{arg_key}')"
            ),
            Self::UnclassifiableOperation { tool, reason } => format!(
                "Denied: {tool} tool call could not be classified before authorization: {reason}"
            ),
        }
    }
}

/// Resolve the effect of one invocation against a declared spec.
///
/// `typed` supplies the handler's own resolution for
/// [`ToolTarget::TypedOperation`] specs and is ignored otherwise.
///
/// # Errors
///
/// Returns [`EffectResolutionError`] when the call cannot be classified. Every
/// such outcome is a denial at the call site.
pub fn resolve(
    tool_name: &str,
    spec: &ToolEffectSpec,
    args: &serde_json::Value,
    typed: Option<Result<TypedEffect, String>>,
) -> Result<ResolvedEffect, EffectResolutionError> {
    match spec.target {
        // The tool name is the target, not the empty string. An empty target
        // is matched by ordinary path globs — `**` compiles to `^.*$`, which
        // matches `""` — so a user's `default_allow: ["**"]`, written with
        // file paths in mind, would silently grant every whole-tool-scope
        // capability. Naming the tool keeps such a rule writable and keeps
        // the audit trail legible. (`**` still matches the name; that the
        // default_allow catalog is target-only and not paired with a tool
        // category is F-030, owned by S-017.)
        ToolTarget::ToolScope => Ok(ResolvedEffect {
            effect: spec.effect,
            canonical: spec.canonical.to_string(),
            target: tool_name.to_string(),
            operation: None,
        }),
        ToolTarget::Arg(arg_key) => match args.get(arg_key) {
            Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
                Ok(ResolvedEffect {
                    effect: spec.effect,
                    canonical: spec.canonical.to_string(),
                    target: value.clone(),
                    operation: None,
                })
            }
            None | Some(serde_json::Value::Null) => Err(EffectResolutionError::MissingArgument {
                tool: tool_name.to_string(),
                arg_key: arg_key.to_string(),
            }),
            _ => Err(EffectResolutionError::MalformedArguments {
                tool: tool_name.to_string(),
                arg_key: arg_key.to_string(),
            }),
        },
        ToolTarget::ArgOrDefault { key, default } => match args.get(key) {
            None | Some(serde_json::Value::Null) => Ok(ResolvedEffect {
                effect: spec.effect,
                canonical: spec.canonical.to_string(),
                target: default.to_string(),
                operation: None,
            }),
            Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
                Ok(ResolvedEffect {
                    effect: spec.effect,
                    canonical: spec.canonical.to_string(),
                    target: value.clone(),
                    operation: None,
                })
            }
            Some(_) => Err(EffectResolutionError::MalformedArguments {
                tool: tool_name.to_string(),
                arg_key: key.to_string(),
            }),
        },
        ToolTarget::TypedOperation => match typed {
            Some(Ok(resolved)) => Ok(ResolvedEffect {
                effect: resolved.effect,
                canonical: spec.canonical.to_string(),
                target: resolved.target,
                operation: Some(resolved.operation),
            }),
            Some(Err(reason)) => Err(EffectResolutionError::UnclassifiableOperation {
                tool: tool_name.to_string(),
                reason,
            }),
            None => Err(EffectResolutionError::UnclassifiableOperation {
                tool: tool_name.to_string(),
                reason: "handler declared ToolTarget::TypedOperation but supplied no resolver"
                    .to_string(),
            }),
        },
    }
}

/// A handler's typed resolution of one multiplexed operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedEffect {
    /// Effect of this operation specifically.
    pub effect: ToolEffect,
    /// Operation label, e.g. `create`.
    pub operation: String,
    /// Concrete target string for rule matching.
    pub target: String,
}

impl TypedEffect {
    /// Build a typed resolution.
    #[must_use]
    pub fn new(
        effect: ToolEffect,
        operation: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            effect,
            operation: operation.into(),
            target: target.into(),
        }
    }
}

/// One row of the generated effect matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectMatrixRow {
    /// Wire-level tool name the model calls.
    pub tool: String,
    /// Where the classification and dispatch live.
    pub surface: ToolSurface,
    /// Declared effect (the ceiling for typed-operation tools).
    pub effect: ToolEffect,
    /// Canonical capability name.
    pub canonical: String,
    /// Rendered target source.
    pub target: String,
    /// Per-operation effects for typed-operation tools, sorted by name.
    pub operations: BTreeMap<String, ToolEffect>,
}

/// Which dispatch surface owns a tool.
///
/// The matrix is generated from the same declarations the dispatchers consult,
/// so a surface that is advertised but unclassified is a matrix failure rather
/// than a silent allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolSurface {
    /// A static handler in the tool registry.
    Registry,
    /// A subagent tool dispatched by `tools::execute_tool_full_unchecked`.
    Subagent,
    /// A dynamically named tool served by a connected MCP server.
    Mcp,
    /// A plugin-registered tool. No surface classifies these yet, so they are
    /// unavailable; S-063 owns activating plugin capabilities through the
    /// canonical registries.
    Plugin,
}

impl ToolSurface {
    /// Stable identifier used in the rendered matrix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Subagent => "subagent",
            Self::Mcp => "mcp",
            Self::Plugin => "plugin",
        }
    }
}

// ─── Catalog: every tool surface the model can reach ─────────────────────────

/// Subagent tools dispatched by `tools::execute_tool_full_unchecked`'s match
/// arms rather than by the registry.
///
/// They are advertised to the model by
/// `subagent::get_subagent_tool_definitions` and were therefore reachable and
/// unclassified: `extract_target` looked them up in the registry, missed, and
/// returned "no target", which `check` read as allow.
///
/// `task` spawns a subagent whose own tool access is the union of every tool
/// in this table, so its declared effect is the ceiling of that union.
const SUBAGENT_SPECS: &[(&str, ToolEffectSpec)] = &[
    (
        "task",
        ToolEffectSpec::effectful(ToolEffect::Destructive, "Task", "subagent_type"),
    ),
    (
        "agent_output",
        // Reading a completed result removes its BackgroundAgent entry. A
        // running poll may only observe, but the invocation's ceiling is a
        // session-local mutation and the optional id preserves the supported
        // no-argument listing behavior.
        ToolEffectSpec::effectful_arg_or_default(
            ToolEffect::SessionMutation,
            "AgentOutput",
            "agent_id",
            "agent_output",
        ),
    ),
    (
        "task_stop",
        // task_stop aborts the worker and terminates its background process
        // groups; that crosses the process boundary rather than changing only
        // an in-memory task flag.
        ToolEffectSpec::effectful(ToolEffect::ExternalMutation, "Task", "agent_id"),
    ),
];

/// Prefix identifying a dynamically named tool served by an MCP server.
const MCP_TOOL_PREFIX: &str = "mcp__";

/// Effect ceiling applied to every MCP-served tool.
///
/// The host cannot know what a third-party server's tool does, and a server is
/// untrusted per the project safety rules, so the classification is the
/// conservative ceiling rather than an optimistic guess. The concrete target
/// is the fully qualified `mcp__server__tool` name, which is what a user rule
/// scopes against.
#[must_use]
const fn mcp_spec() -> ToolEffectSpec {
    // An untrusted server can expose deletion or irreversible external
    // actions. ExternalMutation is not a ceiling for that set; Destructive is.
    ToolEffectSpec::effectful_tool_scope(ToolEffect::Destructive, "Mcp")
}

/// Return true only for the concrete name shape emitted by `McpManager`.
/// Prefix resemblance is insufficient: both server and tool components must
/// be present and non-empty.
fn is_mcp_tool_name(tool_name: &str) -> bool {
    let mut parts = tool_name.splitn(3, "__");
    matches!(parts.next(), Some("mcp"))
        && parts.next().is_some_and(|server| !server.trim().is_empty())
        && parts.next().is_some_and(|tool| !tool.trim().is_empty())
}

/// Prefix reserved for plugin-registered tools.
///
/// No surface classifies these, so [`lookup`] returns `None` and every such
/// call denies. That is the correct posture until S-063 activates plugin
/// capabilities through the canonical registries: a plugin tool has no
/// declaration, and an undeclared tool is unavailable. The matrix carries an
/// explicit row for the surface so its absence is recorded rather than
/// silently unrepresented.
pub const PLUGIN_TOOL_PREFIX: &str = "plugin__";

/// Look up the surface and declaration owning `tool_name`.
///
/// Returns `None` for a name no surface claims. Callers must treat that as a
/// denial — it is the case F-001 recorded as scoring `1.0` safe.
#[must_use]
pub fn lookup(tool_name: &str) -> Option<(ToolSurface, ToolEffectSpec)> {
    if let Some(handler) = crate::tools::registry::registry().get(tool_name) {
        return Some((ToolSurface::Registry, handler.effect_spec()));
    }
    if let Some((_, spec)) = SUBAGENT_SPECS.iter().find(|(name, _)| *name == tool_name) {
        return Some((ToolSurface::Subagent, *spec));
    }
    if is_mcp_tool_name(tool_name) {
        return Some((ToolSurface::Mcp, mcp_spec()));
    }
    None
}

/// Resolve the effect of one concrete invocation across every surface.
///
/// This is the single classification entry point used by the authorization
/// path. It has no permissive fallback: a tool no surface claims, or an
/// invocation whose effect cannot be established, returns `Err`.
///
/// # Errors
///
/// Returns [`EffectResolutionError`] whenever the call cannot be classified.
pub fn resolve_for_call(
    tool_name: &str,
    args: &serde_json::Value,
) -> Result<ResolvedEffect, EffectResolutionError> {
    if !args.is_object() {
        return Err(EffectResolutionError::MalformedEnvelope {
            tool: tool_name.to_string(),
        });
    }
    let Some((surface, spec)) = lookup(tool_name) else {
        return Err(EffectResolutionError::UnknownTool {
            tool: tool_name.to_string(),
        });
    };

    // An MCP tool's target is its fully qualified name; the server and tool
    // are both part of what a rule needs to scope.
    if surface == ToolSurface::Mcp {
        return Ok(ResolvedEffect {
            effect: spec.effect,
            canonical: spec.canonical.to_string(),
            target: tool_name.to_string(),
            operation: None,
        });
    }

    let typed = if matches!(spec.target, ToolTarget::TypedOperation) {
        let Some(handler) = crate::tools::registry::registry().get(tool_name) else {
            return Err(EffectResolutionError::UnclassifiableOperation {
                tool: tool_name.to_string(),
                reason: "typed-operation declaration is not owned by a registry handler"
                    .to_string(),
            });
        };
        let typed = handler.resolve_typed_effect(args);
        if let Some(Ok(resolved)) = &typed {
            if resolved.operation.trim().is_empty() || resolved.target.trim().is_empty() {
                return Err(EffectResolutionError::UnclassifiableOperation {
                    tool: tool_name.to_string(),
                    reason: "typed resolver returned an empty operation or target".to_string(),
                });
            }
            let declared = handler
                .typed_operations()
                .into_iter()
                .find(|(operation, _)| *operation == resolved.operation);
            match declared {
                Some((_, effect)) if effect == resolved.effect => {}
                Some((_, effect)) => {
                    return Err(EffectResolutionError::UnclassifiableOperation {
                        tool: tool_name.to_string(),
                        reason: format!(
                            "typed resolver returned effect {} for operation '{}', but the registry declares {}",
                            resolved.effect.as_str(),
                            resolved.operation,
                            effect.as_str()
                        ),
                    });
                }
                None => {
                    return Err(EffectResolutionError::UnclassifiableOperation {
                        tool: tool_name.to_string(),
                        reason: format!(
                            "typed resolver returned undeclared operation '{}'",
                            resolved.operation
                        ),
                    });
                }
            }
        }
        typed
    } else {
        None
    };

    resolve(tool_name, &spec, args, typed)
}

/// Build the effect matrix from the same declarations dispatch consults.
///
/// Every advertised tool contributes exactly one row. Nothing here is
/// hand-maintained: registry rows come from the registry, subagent rows from
/// the subagent table both the dispatcher and this function read, and
/// per-operation rows from the handlers' own operation tables.
#[must_use]
pub fn effect_matrix() -> Vec<EffectMatrixRow> {
    let mut rows = Vec::new();

    for handler in crate::tools::registry::iter_handlers() {
        let name = handler.name();
        let spec = handler.effect_spec();

        // Ask the handler for its own operations. There is deliberately no
        // `match name { ... _ => {} }` here: a name-matching catch-all would
        // let a future multiplexing handler produce an empty row silently,
        // which is the hand-maintained shape acceptance criterion 3 rules out.
        let operations: BTreeMap<String, ToolEffect> = handler
            .typed_operations()
            .into_iter()
            .map(|(op, effect)| (op.to_string(), effect))
            .collect();

        rows.push(EffectMatrixRow {
            tool: name.to_string(),
            surface: ToolSurface::Registry,
            effect: spec.effect,
            canonical: spec.canonical.to_string(),
            target: render_target(spec.target),
            operations,
        });
    }

    for (name, spec) in SUBAGENT_SPECS {
        rows.push(EffectMatrixRow {
            tool: (*name).to_string(),
            surface: ToolSurface::Subagent,
            effect: spec.effect,
            canonical: spec.canonical.to_string(),
            target: render_target(spec.target),
            operations: BTreeMap::new(),
        });
    }

    let dynamic = mcp_spec();
    rows.push(EffectMatrixRow {
        tool: format!("{MCP_TOOL_PREFIX}<server>__<tool>"),
        surface: ToolSurface::Mcp,
        effect: dynamic.effect,
        canonical: dynamic.canonical.to_string(),
        target: "fully-qualified tool name".to_string(),
        operations: BTreeMap::new(),
    });

    rows.push(EffectMatrixRow {
        tool: format!("{PLUGIN_TOOL_PREFIX}<plugin>__<tool>"),
        surface: ToolSurface::Plugin,
        effect: ToolEffect::Destructive,
        canonical: "unavailable".to_string(),
        target: "unclassified — denied".to_string(),
        operations: BTreeMap::new(),
    });

    rows
}

fn render_target(target: ToolTarget) -> String {
    match target {
        ToolTarget::ToolScope => "tool scope".to_string(),
        ToolTarget::Arg(key) => format!("arg:{key}"),
        ToolTarget::ArgOrDefault { key, default } => {
            format!("arg:{key} (default `{default}`)")
        }
        ToolTarget::TypedOperation => "typed operation".to_string(),
    }
}

/// Render [`effect_matrix`] as a stable Markdown table.
#[must_use]
pub fn render_effect_matrix() -> String {
    use std::fmt::Write as _;

    let mut out = String::from("| Tool | Surface | Effect | Capability | Target |\n");
    out.push_str("|---|---|---|---|---|\n");
    for row in effect_matrix() {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} |",
            row.tool,
            row.surface.as_str(),
            row.effect.as_str(),
            row.canonical,
            row.target
        );
        for (operation, effect) in &row.operations {
            let _ = writeln!(
                out,
                "| `{}` → `{operation}` | {} | {} | {} | operation |",
                row.tool,
                row.surface.as_str(),
                effect.as_str(),
                row.canonical
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_read_only_skips_authorization() {
        assert!(!ToolEffect::ReadOnly.requires_authorization());
        for effect in [
            ToolEffect::SessionMutation,
            ToolEffect::WorkspaceMutation,
            ToolEffect::NetworkRead,
            ToolEffect::ExternalMutation,
            ToolEffect::Destructive,
        ] {
            assert!(
                effect.requires_authorization(),
                "{effect:?} must reach an authorization decision"
            );
        }
    }

    #[test]
    fn empty_canonical_name_fails_validation() {
        let spec = ToolEffectSpec::read_only("");
        assert!(spec.validate("x").is_err());
    }

    #[test]
    fn empty_arg_key_fails_validation() {
        let spec = ToolEffectSpec::effectful(ToolEffect::WorkspaceMutation, "Write", "  ");
        assert!(spec.validate("x").is_err());
    }

    #[test]
    fn missing_declared_argument_is_explicitly_reported_not_allowed() {
        let spec = ToolEffectSpec::effectful(ToolEffect::WorkspaceMutation, "Write", "path");
        let err = resolve("write_file", &spec, &json!({}), None).unwrap_err();
        assert!(matches!(err, EffectResolutionError::MissingArgument { .. }));
        assert_eq!(
            err.reason(),
            "Denied: Missing 'path' argument required for write_file tool call"
        );
    }

    #[test]
    fn non_string_declared_argument_is_malformed() {
        let spec = ToolEffectSpec::effectful(ToolEffect::WorkspaceMutation, "Write", "path");
        let err = resolve("write_file", &spec, &json!({"path": 7}), None).unwrap_err();
        assert!(matches!(
            err,
            EffectResolutionError::MalformedArguments { .. }
        ));
    }

    #[test]
    fn typed_operation_without_resolver_is_denied() {
        let spec = ToolEffectSpec::typed_operation(ToolEffect::WorkspaceMutation, "Crosslink");
        let err = resolve("crosslink", &spec, &json!({}), None).unwrap_err();
        assert!(matches!(
            err,
            EffectResolutionError::UnclassifiableOperation { .. }
        ));
    }

    #[test]
    fn typed_operation_uses_per_call_effect_not_the_ceiling() {
        let spec = ToolEffectSpec::typed_operation(ToolEffect::WorkspaceMutation, "Crosslink");
        let resolved = resolve(
            "crosslink",
            &spec,
            &json!({"operation": "list"}),
            Some(Ok(TypedEffect::new(ToolEffect::ReadOnly, "list", "list"))),
        )
        .unwrap();
        assert_eq!(resolved.effect, ToolEffect::ReadOnly);
        assert_eq!(resolved.operation.as_deref(), Some("list"));
    }

    #[test]
    fn tool_scope_target_is_the_tool_name() {
        let spec = ToolEffectSpec::effectful_tool_scope(ToolEffect::SessionMutation, "TodoWrite");
        let resolved = resolve("todo_write", &spec, &json!({"todos": []}), None).unwrap();
        assert_eq!(resolved.target, "todo_write");
        assert_eq!(resolved.canonical, "TodoWrite");
    }
}

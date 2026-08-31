//! Versioned wire profiles and typed values for the Model Context Protocol.
//!
//! MCP 2026-07-28 is a different protocol era from the initialization-based
//! revisions `OpenClaudia` originally implemented. Keeping the era decision in
//! this module prevents transport and feature code from accidentally mixing
//! session-era messages with stateless per-request metadata.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const CURRENT_PROTOCOL_VERSION: &str = "2026-07-28";
pub const PREFERRED_LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// Protocol revisions whose wire behavior `OpenClaudia` implements explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpProtocolVersion {
    #[serde(rename = "2024-11-05")]
    V2024_11_05,
    #[serde(rename = "2025-03-26")]
    V2025_03_26,
    #[serde(rename = "2025-06-18")]
    V2025_06_18,
    #[serde(rename = "2025-11-25")]
    V2025_11_25,
    #[serde(rename = "2026-07-28")]
    V2026_07_28,
}

impl McpProtocolVersion {
    pub(crate) const CURRENT: Self = Self::V2026_07_28;

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::V2024_11_05 => "2024-11-05",
            Self::V2025_03_26 => "2025-03-26",
            Self::V2025_06_18 => "2025-06-18",
            Self::V2025_11_25 => "2025-11-25",
            Self::V2026_07_28 => CURRENT_PROTOCOL_VERSION,
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "2024-11-05" => Some(Self::V2024_11_05),
            "2025-03-26" => Some(Self::V2025_03_26),
            "2025-06-18" => Some(Self::V2025_06_18),
            "2025-11-25" => Some(Self::V2025_11_25),
            CURRENT_PROTOCOL_VERSION => Some(Self::V2026_07_28),
            _ => None,
        }
    }

    pub(crate) const fn era(self) -> McpProtocolEra {
        match self {
            Self::V2026_07_28 => McpProtocolEra::Modern,
            Self::V2024_11_05 | Self::V2025_03_26 | Self::V2025_06_18 | Self::V2025_11_25 => {
                McpProtocolEra::Legacy
            }
        }
    }
}

impl std::fmt::Display for McpProtocolVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpProtocolEra {
    Legacy,
    Modern,
}

/// Transport information needed to produce a protocol-correct request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRequestContext {
    pub(crate) version: McpProtocolVersion,
    pub(crate) routing_name: Option<String>,
    pub(crate) parameter_headers: Vec<(String, String)>,
}

impl McpRequestContext {
    pub(crate) const fn legacy(version: McpProtocolVersion) -> Self {
        Self {
            version,
            routing_name: None,
            parameter_headers: Vec::new(),
        }
    }
}

/// Exact selected profile.  Revisions are never inferred from response shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpProtocolAdapter {
    version: McpProtocolVersion,
}

impl McpProtocolAdapter {
    pub(crate) const fn new(version: McpProtocolVersion) -> Self {
        Self { version }
    }

    pub(crate) const fn current() -> Self {
        Self::new(McpProtocolVersion::CURRENT)
    }

    pub(crate) const fn version(self) -> McpProtocolVersion {
        self.version
    }

    pub(crate) const fn era(self) -> McpProtocolEra {
        self.version.era()
    }

    pub(crate) fn client_capabilities(capabilities: Value) -> Result<Value, String> {
        let Value::Object(mut capabilities) = capabilities else {
            return Err("MCP client capabilities must be an object".to_string());
        };
        // Tasks are deliberately absent. Their typed result forms are
        // recognized below, but OpenClaudia must not advertise them until a
        // visible, resumable input/task owner is composed.
        if let Some(extensions) = capabilities.get_mut("extensions") {
            let Some(extensions) = extensions.as_object_mut() else {
                return Err("MCP client capability extensions must be an object".to_string());
            };
            extensions.remove(TASKS_EXTENSION);
        }
        Ok(Value::Object(capabilities))
    }

    pub(crate) fn request_params(
        self,
        params: Option<Value>,
        client_capabilities: Value,
    ) -> Result<Value, String> {
        let mut object = match params.unwrap_or_else(|| json!({})) {
            Value::Object(object) => object,
            other => {
                return Err(format!(
                    "MCP request params must be an object, got {}",
                    value_type_name(&other)
                ));
            }
        };
        if self.era() == McpProtocolEra::Modern {
            let meta = object
                .entry("_meta".to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            let Some(meta) = meta.as_object_mut() else {
                return Err("MCP request _meta must be an object".to_string());
            };
            meta.insert(
                "io.modelcontextprotocol/protocolVersion".to_string(),
                Value::String(self.version.as_str().to_string()),
            );
            meta.insert(
                "io.modelcontextprotocol/clientCapabilities".to_string(),
                Self::client_capabilities(client_capabilities)?,
            );
            meta.insert(
                "io.modelcontextprotocol/clientInfo".to_string(),
                json!({
                    "name": "openclaudia",
                    "version": env!("CARGO_PKG_VERSION"),
                }),
            );
            meta.insert(
                "io.modelcontextprotocol/logLevel".to_string(),
                Value::String("info".to_string()),
            );
        }
        Ok(Value::Object(object))
    }

    pub(crate) const fn request_context(self, routing_name: Option<String>) -> McpRequestContext {
        McpRequestContext {
            version: self.version,
            routing_name,
            parameter_headers: Vec::new(),
        }
    }

    pub(crate) fn require_complete_result(
        self,
        operation: &str,
        value: &Value,
    ) -> Result<(), String> {
        if self.era() == McpProtocolEra::Legacy {
            return Ok(());
        }
        match value.get("resultType").and_then(Value::as_str) {
            Some("complete") => Ok(()),
            Some("input_required") => Err(format!(
                "MCP {operation} requires multi-round-trip input, but this run has no attributed interactive MCP input owner"
            )),
            Some("task") => Err(format!(
                "MCP {operation} returned a task without negotiated '{TASKS_EXTENSION}' support"
            )),
            Some(other) => Err(format!(
                "MCP {operation} returned unsupported resultType '{other}'"
            )),
            None => Err(format!(
                "MCP {operation} response for {} is missing required resultType",
                self.version
            )),
        }
    }

    pub(crate) fn require_cache_metadata(
        self,
        operation: &str,
        value: &Value,
    ) -> Result<(), String> {
        if self.era() == McpProtocolEra::Legacy {
            return Ok(());
        }
        if !value.get("ttlMs").is_some_and(Value::is_u64) {
            return Err(format!(
                "MCP {operation} response for {} is missing a non-negative ttlMs",
                self.version
            ));
        }
        if !matches!(
            value.get("cacheScope").and_then(Value::as_str),
            Some("private" | "public")
        ) {
            return Err(format!(
                "MCP {operation} response for {} has no valid cacheScope",
                self.version
            ));
        }
        Ok(())
    }
}

const fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpCapabilities {
    #[serde(default)]
    pub tools: Option<McpToolsCapability>,
    #[serde(default)]
    pub resources: Option<McpResourcesCapability>,
    #[serde(default)]
    pub prompts: Option<McpListCapability>,
    #[serde(default)]
    pub logging: Option<Value>,
    #[serde(default)]
    pub completions: Option<Value>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Value>,
    #[serde(default)]
    pub experimental: BTreeMap<String, Value>,
    /// Capabilities are an open set in the MCP schema. Preserve vendor keys
    /// so callers can make an explicit decision instead of losing evidence.
    #[serde(default, flatten)]
    pub additional: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolsCapability {
    #[serde(default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResourcesCapability {
    #[serde(default)]
    pub list_changed: bool,
    #[serde(default)]
    pub subscribe: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpListCapability {
    #[serde(default)]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerInfo {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub website_url: Option<String>,
    #[serde(default)]
    pub icons: Vec<McpIcon>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpIcon {
    pub src: String,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub sizes: Vec<String>,
    #[serde(default)]
    pub theme: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAnnotations {
    #[serde(default)]
    pub audience: Vec<McpRole>,
    #[serde(default)]
    pub priority: Option<f64>,
    #[serde(default)]
    pub last_modified: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpRole {
    User,
    Assistant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTool {
    pub name: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub output_schema: Option<Value>,
    #[serde(default)]
    pub annotations: Option<Value>,
    #[serde(default)]
    pub icons: Vec<McpIcon>,
    #[serde(default, rename = "_meta")]
    pub meta: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub annotations: Option<McpAnnotations>,
    #[serde(default)]
    pub icons: Vec<McpIcon>,
    #[serde(default, rename = "_meta")]
    pub meta: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPromptArgument {
    pub name: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPrompt {
    pub name: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub arguments: Vec<McpPromptArgument>,
    #[serde(default)]
    pub icons: Vec<McpIcon>,
    #[serde(default, rename = "_meta")]
    pub meta: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpContentBlock {
    Text {
        text: String,
        #[serde(default)]
        annotations: Option<McpAnnotations>,
        #[serde(default, rename = "_meta")]
        meta: BTreeMap<String, Value>,
    },
    Image {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
        #[serde(default)]
        annotations: Option<McpAnnotations>,
        #[serde(default, rename = "_meta")]
        meta: BTreeMap<String, Value>,
    },
    Audio {
        data: String,
        #[serde(rename = "mimeType")]
        mime_type: String,
        #[serde(default)]
        annotations: Option<McpAnnotations>,
        #[serde(default, rename = "_meta")]
        meta: BTreeMap<String, Value>,
    },
    ResourceLink {
        uri: String,
        name: String,
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        description: Option<String>,
        #[serde(default, rename = "mimeType")]
        mime_type: Option<String>,
        #[serde(default)]
        size: Option<u64>,
        #[serde(default)]
        annotations: Option<McpAnnotations>,
        #[serde(default)]
        icons: Vec<McpIcon>,
        #[serde(default, rename = "_meta")]
        meta: BTreeMap<String, Value>,
    },
    Resource {
        resource: McpResourceContents,
        #[serde(default)]
        annotations: Option<McpAnnotations>,
        #[serde(default, rename = "_meta")]
        meta: BTreeMap<String, Value>,
    },
}

impl McpContentBlock {
    pub(crate) fn text(&self) -> Option<&str> {
        match self {
            Self::Text { text, .. } => Some(text),
            _ => None,
        }
    }

    pub(crate) fn encoded_media(&self) -> Option<(&str, &str)> {
        match self {
            Self::Image {
                data, mime_type, ..
            }
            | Self::Audio {
                data, mime_type, ..
            } => Some((data, mime_type)),
            Self::Resource {
                resource:
                    McpResourceContents::Blob {
                        blob,
                        mime_type: Some(mime_type),
                        ..
                    },
                ..
            } => Some((blob, mime_type)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum McpResourceContents {
    Text {
        uri: String,
        text: String,
        #[serde(default, rename = "mimeType")]
        mime_type: Option<String>,
        #[serde(default, rename = "_meta")]
        meta: BTreeMap<String, Value>,
    },
    Blob {
        uri: String,
        blob: String,
        #[serde(default, rename = "mimeType")]
        mime_type: Option<String>,
        #[serde(default, rename = "_meta")]
        meta: BTreeMap<String, Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPromptMessage {
    pub role: McpRole,
    pub content: McpContentBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpCallToolResult {
    #[serde(default)]
    pub content: Vec<McpContentBlock>,
    #[serde(default)]
    pub structured_content: Option<Value>,
    #[serde(default)]
    pub is_error: bool,
    #[serde(default)]
    pub result_type: Option<String>,
    #[serde(default, rename = "_meta")]
    pub meta: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpReadResourceResult {
    pub contents: Vec<McpResourceContents>,
    #[serde(default)]
    pub result_type: Option<String>,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(default)]
    pub cache_scope: Option<String>,
    #[serde(default, rename = "_meta")]
    pub meta: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpGetPromptResult {
    pub messages: Vec<McpPromptMessage>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub result_type: Option<String>,
    #[serde(default, rename = "_meta")]
    pub meta: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTask {
    pub task_id: String,
    pub status: McpTaskStatus,
    #[serde(default)]
    pub status_message: Option<String>,
    pub created_at: String,
    pub last_updated_at: String,
    pub ttl_ms: Option<i64>,
    #[serde(default)]
    pub poll_interval_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTaskStatus {
    Working,
    InputRequired,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone)]
pub enum McpNotification {
    Progress {
        token: Value,
        progress: f64,
        total: Option<f64>,
        message: Option<String>,
    },
    Log {
        level: String,
        logger: Option<String>,
        data: Value,
    },
    CatalogueChanged {
        method: String,
    },
    ResourceUpdated {
        uri: String,
    },
}

pub fn parse_notification(value: &Value) -> Result<Option<McpNotification>, String> {
    let Some(method) = value.get("method").and_then(Value::as_str) else {
        return Ok(None);
    };
    let params = value.get("params").unwrap_or(&Value::Null);
    match method {
        "notifications/progress" => Ok(Some(McpNotification::Progress {
            token: params
                .get("progressToken")
                .cloned()
                .ok_or_else(|| "progress notification is missing progressToken".to_string())?,
            progress: params
                .get("progress")
                .and_then(Value::as_f64)
                .ok_or_else(|| "progress notification is missing numeric progress".to_string())?,
            total: params.get("total").and_then(Value::as_f64),
            message: params
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string),
        })),
        "notifications/message" => Ok(Some(McpNotification::Log {
            level: params
                .get("level")
                .and_then(Value::as_str)
                .ok_or_else(|| "logging notification is missing level".to_string())?
                .to_string(),
            logger: params
                .get("logger")
                .and_then(Value::as_str)
                .map(str::to_string),
            data: params
                .get("data")
                .cloned()
                .ok_or_else(|| "logging notification is missing data".to_string())?,
        })),
        "notifications/tools/list_changed"
        | "notifications/resources/list_changed"
        | "notifications/prompts/list_changed" => Ok(Some(McpNotification::CatalogueChanged {
            method: method.to_string(),
        })),
        "notifications/resources/updated" => Ok(Some(McpNotification::ResourceUpdated {
            uri: params
                .get("uri")
                .and_then(Value::as_str)
                .ok_or_else(|| "resource update notification is missing uri".to_string())?
                .to_string(),
        })),
        _ => Ok(None),
    }
}

//! Neutral file-type metadata shared by non-authority features.
//!
//! This module recognizes file extensions. It does not discover, load, or
//! interpret repository instructions and has no prompt-construction behavior.

use regex::Regex;
use serde_json::Value;
use std::path::Path;
use std::sync::OnceLock;
use tracing::warn;

/// Single source of truth for source and configuration file extensions used by
/// automatic-learning applicability metadata.
const LANGUAGE_EXTENSIONS: &[(&str, &[&str])] = &[
    ("rust", &["rs"]),
    ("python", &["py", "pyw"]),
    ("javascript", &["js", "mjs", "cjs"]),
    ("typescript", &["ts", "mts", "cts"]),
    ("tsx", &["tsx"]),
    ("jsx", &["jsx"]),
    ("go", &["go"]),
    ("java", &["java"]),
    ("kotlin", &["kt", "kts"]),
    ("swift", &["swift"]),
    ("c", &["c", "h"]),
    ("cpp", &["cpp", "cc", "cxx", "hpp", "hxx"]),
    ("csharp", &["cs"]),
    ("ruby", &["rb"]),
    ("php", &["php"]),
    ("scala", &["scala"]),
    ("elixir", &["ex", "exs"]),
    ("erlang", &["erl", "hrl"]),
    ("haskell", &["hs"]),
    ("clojure", &["clj", "cljs", "cljc"]),
    ("lua", &["lua"]),
    ("r", &["r"]),
    ("julia", &["jl"]),
    ("dart", &["dart"]),
    ("zig", &["zig"]),
    ("nim", &["nim"]),
    ("vlang", &["v"]),
    ("sql", &["sql"]),
    ("shell", &["sh", "bash", "zsh"]),
    ("powershell", &["ps1", "psm1"]),
    ("yaml", &["yml", "yaml"]),
    ("json", &["json"]),
    ("toml", &["toml"]),
    ("xml", &["xml"]),
    ("html", &["html", "htm"]),
    ("css", &["css"]),
    ("scss", &["scss", "sass"]),
    ("less", &["less"]),
    ("markdown", &["md", "markdown"]),
    ("vue", &["vue"]),
    ("svelte", &["svelte"]),
];

/// Return whether `extension` belongs to a recognized source or configuration
/// file type. Matching is ASCII case-insensitive.
#[must_use]
pub fn is_known_extension(extension: &str) -> bool {
    LANGUAGE_EXTENSIONS.iter().any(|(_, extensions)| {
        extensions
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(extension))
    })
}

fn compile_glob_extension_regex(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(error) => {
            warn!(
                pattern,
                error = %error,
                "Invalid glob-extension regex; hook file-type metadata disabled",
            );
            None
        }
    }
}

fn glob_extension_regex() -> Option<&'static Regex> {
    static REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    REGEX
        .get_or_init(|| compile_glob_extension_regex(r"\.([A-Za-z0-9]{1,8})[\*\?\]\}\)]*$"))
        .as_ref()
}

/// Extract neutral file-extension metadata for lifecycle hooks.
///
/// The result is descriptive data only. It is never used to select or load
/// instructions.
#[must_use]
pub fn extensions_from_tool_input(tool_name: &str, input: &Value) -> Vec<String> {
    let mut extensions = Vec::new();

    match tool_name {
        "Write" | "Edit" | "Read" | "write_file" | "edit_file" | "read_file" => {
            if let Some(path) = ["path", "file_path"]
                .into_iter()
                .find_map(|key| input.get(key).and_then(Value::as_str))
            {
                if let Some(extension) = Path::new(path).extension().and_then(|ext| ext.to_str()) {
                    extensions.push(extension.to_string());
                }
            }
        }
        "notebook_edit" | "NotebookEdit" => {
            if let Some(path) = input.get("notebook_path").and_then(Value::as_str) {
                if let Some(extension) = Path::new(path).extension().and_then(|ext| ext.to_str()) {
                    extensions.push(extension.to_string());
                }
            }
        }
        "Glob" | "glob" => {
            if let Some(pattern) = input.get("pattern").and_then(Value::as_str) {
                if let Some(extension) = glob_extension_regex()
                    .and_then(|regex| regex.captures(pattern))
                    .and_then(|captures| captures.get(1))
                {
                    extensions.push(extension.as_str().to_string());
                }
            }
        }
        _ => {}
    }

    extensions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_recognizes_every_declared_extension_case_insensitively() {
        for (language, extensions) in LANGUAGE_EXTENSIONS {
            assert!(
                !extensions.is_empty(),
                "{language} must declare an extension"
            );
            for extension in *extensions {
                assert!(is_known_extension(extension));
                assert!(is_known_extension(&extension.to_ascii_uppercase()));
            }
        }
        assert!(!is_known_extension("definitely_unknown"));
    }

    #[test]
    fn tool_metadata_extracts_paths_and_explicit_glob_suffixes() {
        assert_eq!(
            extensions_from_tool_input("write_file", &serde_json::json!({"path": "/src/main.rs"})),
            ["rs"]
        );
        assert_eq!(
            extensions_from_tool_input("Edit", &serde_json::json!({"file_path": "/src/lib.py"})),
            ["py"]
        );
        assert_eq!(
            extensions_from_tool_input(
                "notebook_edit",
                &serde_json::json!({"notebook_path": "/analysis/model.ipynb"})
            ),
            ["ipynb"]
        );
        assert_eq!(
            extensions_from_tool_input("glob", &serde_json::json!({"pattern": "**/*.ts"})),
            ["ts"]
        );
        assert!(extensions_from_tool_input(
            "glob",
            &serde_json::json!({"pattern": "src/components"})
        )
        .is_empty());
        assert!(extensions_from_tool_input(
            "Unknown",
            &serde_json::json!({"file_path": "/src/main.rs"})
        )
        .is_empty());
    }

    #[test]
    fn invalid_glob_regex_is_non_operational() {
        assert!(compile_glob_extension_regex("[").is_none());
    }
}

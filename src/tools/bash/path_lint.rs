//! Non-authoritative lexical diagnostics for Bash path-shaped tokens.
//!
//! Shell text cannot establish filesystem authority: expansion, aliases,
//! quoting, scripts, symlinks, and redirection all make a lexical scan
//! incomplete. This module therefore reports only a coarse telemetry signal.
//! It never grants or denies an invocation. The immutable run capabilities
//! and the OS sandbox are the filesystem boundary.

use std::path::{Component, Path, PathBuf};

/// Count literal path-shaped tokens that appear outside this run's declared
/// roots. The result is diagnostic only and must not control execution.
pub(super) fn outside_run_root_count(run: &crate::tools::ToolRunContext, command: &str) -> usize {
    let mut roots = vec![run.working_directory().to_path_buf()];
    for root in run.read_write_roots().iter().chain(run.read_only_roots()) {
        if !roots.contains(root) {
            roots.push(root.clone());
        }
    }

    outside_root_tokens(command, &roots, Some(run.private_temp_root())).len()
}

fn outside_root_tokens(command: &str, roots: &[PathBuf], home: Option<&Path>) -> Vec<String> {
    path_tokens(command)
        .into_iter()
        .filter(|token| {
            let path = expand_home(token, home);
            !lexically_within_roots(&path, roots)
        })
        .collect()
}

fn lexically_within_roots(path: &Path, roots: &[PathBuf]) -> bool {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        roots
            .first()
            .map_or_else(|| path.to_path_buf(), |root| root.join(path))
    };
    let normalized = normalize_lexically(&absolute);

    roots
        .iter()
        .map(|root| normalize_lexically(root))
        .any(|root| normalized.starts_with(root))
}

fn expand_home(token: &str, home: Option<&Path>) -> PathBuf {
    if let Some(rest) = token.strip_prefix("~/") {
        return home.map_or_else(|| PathBuf::from(token), |root| root.join(rest));
    }
    if token == "~" {
        return home.map_or_else(|| PathBuf::from(token), Path::to_path_buf);
    }
    PathBuf::from(token)
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !output.pop() {
                    output.push("..");
                }
            }
            other => output.push(other.as_os_str()),
        }
    }
    output
}

fn path_tokens(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for character in command.chars() {
        match character {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            value if value.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    push_if_path(&mut tokens, &current);
                    current.clear();
                }
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        push_if_path(&mut tokens, &current);
    }
    tokens
}

fn push_if_path(output: &mut Vec<String>, token: &str) {
    let stripped = strip_outer_quotes(token);
    if is_path_shaped(stripped) {
        output.push(stripped.to_string());
    }
}

fn strip_outer_quotes(value: &str) -> &str {
    if value.len() < 2 {
        return value;
    }
    let bytes = value.as_bytes();
    let matching_quotes = (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        || (bytes[0] == b'"' && bytes[value.len() - 1] == b'"');
    if matching_quotes {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn is_path_shaped(token: &str) -> bool {
    token.starts_with('/')
        || token.starts_with("~/")
        || token == "~"
        || token.starts_with("./")
        || token.starts_with("../")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_outside_paths_are_reported_as_diagnostics() {
        let roots = vec![PathBuf::from("/workspace"), PathBuf::from("/scratch")];
        assert_eq!(
            outside_root_tokens("cat /etc/passwd", &roots, Some(Path::new("/scratch"))),
            vec!["/etc/passwd"]
        );
        assert!(outside_root_tokens(
            "cat /workspace/README.md ~/notes",
            &roots,
            Some(Path::new("/scratch"))
        )
        .is_empty());
    }

    #[test]
    fn traversal_is_normalized_for_diagnostic_quality() {
        let roots = vec![PathBuf::from("/workspace")];
        assert_eq!(
            outside_root_tokens("cat ../../etc/passwd", &roots, None),
            vec!["../../etc/passwd"]
        );
    }

    #[test]
    fn lexical_scan_is_explicitly_incomplete() {
        let roots = vec![PathBuf::from("/workspace")];
        for bypass in [
            "cat $ROOT/etc/passwd",
            "printf x >/tmp/output",
            "python3 mutate.py",
            "source $SCRIPT",
        ] {
            assert!(
                outside_root_tokens(bypass, &roots, None).is_empty(),
                "a lexical hit would falsely imply complete shell parsing for {bypass:?}"
            );
        }
    }
}

//! Target input planning for single and multi-target scans.
//!
//! This module deliberately contains no scan execution logic. It converts the
//! operator's target file or single URL into normalized target specifications
//! consumed by the orchestration layer.

use serde::Deserialize;

use crate::target_utils::normalize_url;

/// A normalized scan target supplied by the CLI or a newline-delimited target file.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Target {
    /// A remote URL target. `fuzz` overrides the CLI default when present.
    Url { url: String, fuzz: Option<bool> },
    /// An authenticated forge target, optionally restricted to repository names.
    Token {
        token: String,
        repos: Option<Vec<String>>,
    },
    /// A local directory target.
    Dir { dir: String },
}

/// Load targets from a newline-delimited file.
///
/// Each non-empty, non-comment line is parsed as a typed JSON target first.
/// If JSON parsing fails, the line remains backward-compatible as a plain URL.
pub fn load_targets(path: &str, default_fuzz: bool) -> anyhow::Result<Vec<Target>> {
    let content = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("Cannot read targets file '{}': {}", path, error))?;
    let mut targets = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Ok(target) = serde_json::from_str::<Target>(line) {
            targets.push(target);
        } else {
            targets.push(Target::Url {
                url: normalize_url(line)?,
                fuzz: Some(default_fuzz),
            });
        }
    }

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::{load_targets, Target};
    use std::io::Write;

    #[test]
    fn loads_mixed_json_and_plain_url_targets() {
        let mut file = tempfile::NamedTempFile::new().expect("create target fixture");
        writeln!(file, "# comment").unwrap();
        writeln!(file, "https://example.test").unwrap();
        writeln!(file, r#"{{"dir":"./project"}}"#).unwrap();
        writeln!(file, r#"{{"token":"synthetic","repos":["owner/repo"]}}"#).unwrap();

        let targets = load_targets(file.path().to_str().unwrap(), true).unwrap();
        assert_eq!(targets.len(), 3);
        assert!(matches!(
            targets[0],
            Target::Url {
                fuzz: Some(true),
                ..
            }
        ));
        assert!(matches!(targets[1], Target::Dir { .. }));
        assert!(matches!(targets[2], Target::Token { .. }));
    }

    #[test]
    fn preserves_explicit_url_fuzz_override() {
        let mut file = tempfile::NamedTempFile::new().expect("create target fixture");
        writeln!(file, r#"{{"url":"https://example.test","fuzz":false}}"#).unwrap();

        let targets = load_targets(file.path().to_str().unwrap(), true).unwrap();
        assert!(matches!(
            targets[0],
            Target::Url {
                fuzz: Some(false),
                ..
            }
        ));
    }
}

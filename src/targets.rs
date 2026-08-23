//!
//! This module deliberately contains no scan execution logic. It converts the
//! operator's target file or single URL into normalized target specifications
//! consumed by the orchestration layer.

use serde::Deserialize;

use crate::target_utils::normalize_url;

/// Provider requested by an authenticated token target.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TokenProvider {
    #[default]
    Github,
    Gitlab,
    Bitbucket,
    Gitea,
    Azure,
}

impl TokenProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Bitbucket => "bitbucket",
            Self::Gitea => "gitea",
            Self::Azure => "azure",
        }
    }
}

/// A normalized scan target supplied by the CLI or a newline-delimited target file.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Target {
    /// A remote URL target. `fuzz` overrides the CLI default when present.
    Url { url: String, fuzz: Option<bool> },
    /// An authenticated forge target. `repos` is the legacy GitHub allowlist;
    /// `selectors` is the provider-neutral exact/glob selector field.
    Token {
        token: String,
        provider: Option<TokenProvider>,
        repos: Option<Vec<String>>,
        selectors: Option<Vec<String>>,
    },
    /// A local directory target.
    Dir { dir: String },
}

impl Target {
    /// Return the explicit provider, defaulting legacy token targets to GitHub.
    pub fn token_provider(&self) -> Option<TokenProvider> {
        match self {
            Self::Token { provider, .. } => Some(provider.unwrap_or_default()),
            _ => None,
        }
    }

    /// Merge legacy `repos` and provider-neutral `selectors` deterministically.
    pub fn token_selectors(&self) -> anyhow::Result<Option<Vec<String>>> {
        let Self::Token {
            repos, selectors, ..
        } = self
        else {
            return Ok(None);
        };
        merge_selectors(repos.as_deref(), selectors.as_deref())
    }
}

/// Merge legacy repository names and provider-neutral selectors deterministically.
pub fn merge_selectors(
    legacy_repos: Option<&[String]>,
    selectors: Option<&[String]>,
) -> anyhow::Result<Option<Vec<String>>> {
    let mut merged = Vec::new();
    for selector in legacy_repos
        .into_iter()
        .flatten()
        .chain(selectors.into_iter().flatten())
    {
        let selector = selector.trim();
        if selector.is_empty() {
            anyhow::bail!("Token target selector cannot be empty");
        }
        if !merged.iter().any(|existing: &String| existing == selector) {
            merged.push(selector.to_string());
        }
    }
    Ok((!merged.is_empty()).then_some(merged))
}

/// Match a repository/project full name against an exact or simple glob selector.
/// Matching is case-insensitive; `*` matches zero or more characters and `?` one.
pub fn selector_matches(name: &str, selector: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let selector = selector.trim().to_ascii_lowercase();
    let name = name.as_bytes();
    let selector = selector.as_bytes();
    let mut name_index = 0;
    let mut selector_index = 0;
    let mut star = None;
    let mut star_name_index = 0;

    while name_index < name.len() {
        if selector_index < selector.len()
            && (selector[selector_index] == name[name_index] || selector[selector_index] == b'?')
        {
            name_index += 1;
            selector_index += 1;
        } else if selector_index < selector.len() && selector[selector_index] == b'*' {
            star = Some(selector_index);
            selector_index += 1;
            star_name_index = name_index;
        } else if let Some(star_index) = star {
            selector_index = star_index + 1;
            star_name_index += 1;
            name_index = star_name_index;
        } else {
            return false;
        }
    }
    while selector_index < selector.len() && selector[selector_index] == b'*' {
        selector_index += 1;
    }
    selector_index == selector.len()
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
    use super::{load_targets, selector_matches, Target, TokenProvider};
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
        assert_eq!(targets[2].token_provider(), Some(TokenProvider::Github));
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

    #[test]
    fn parses_provider_and_merges_legacy_and_new_selectors() {
        let mut file = tempfile::NamedTempFile::new().expect("create target fixture");
        writeln!(
            file,
            r#"{{"token":"synthetic","provider":"gitlab","repos":["corp/legacy"],"selectors":["corp/*","corp/legacy"]}}"#
        )
        .unwrap();

        let targets = load_targets(file.path().to_str().unwrap(), false).unwrap();
        assert_eq!(targets[0].token_provider(), Some(TokenProvider::Gitlab));
        assert_eq!(
            targets[0].token_selectors().unwrap(),
            Some(vec!["corp/legacy".to_string(), "corp/*".to_string()])
        );
    }

    #[test]
    fn selector_matching_supports_exact_star_and_question_mark() {
        assert!(selector_matches("Corp/Platform/Repo", "corp/platform/repo"));
        assert!(selector_matches("corp/platform/repo", "corp/*/repo"));
        assert!(selector_matches("corp/platform/repo", "corp/????????/repo"));
        assert!(!selector_matches("corp/platform/other", "corp/*/repo"));
        assert!(!selector_matches("corp/platform/repo", "corp/platform"));
    }

    #[test]
    fn empty_selector_is_rejected() {
        let target = Target::Token {
            token: "synthetic".to_string(),
            provider: Some(TokenProvider::Github),
            repos: None,
            selectors: Some(vec!["  ".to_string()]),
        };
        assert!(target.token_selectors().is_err());
    }
}

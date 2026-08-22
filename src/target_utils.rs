//! Shared target normalization and naming helpers.

use std::path::Path;

pub(crate) fn normalize_url(url: &str) -> anyhow::Result<String> {
    crate::validation::validate_and_normalize_url(url)
        .map_err(|error| anyhow::anyhow!("Invalid URL: {}", error))
}

pub(crate) fn target_name(url: &str) -> String {
    let name = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace('/', "_");
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .chars()
        .take(200)
        .collect()
}

pub(crate) fn dir_target_name(path: &Path) -> String {
    let raw = path
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("directory_scan");
    target_name(raw)
}

pub(crate) fn parse_extra_headers(raw: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    raw.iter()
        .map(|header| {
            crate::validation::validate_custom_header(header)
                .map_err(|error| anyhow::anyhow!("Invalid header '{}': {}", header, error))
        })
        .collect()
}

/// Select cloned items by stable indexes, ignoring indexes outside the source slice.
///
/// Forge providers use this after interactive or non-interactive repository
/// selection so the selection semantics are identical across providers.
pub(crate) fn select_by_indexes<T: Clone>(
    items: &[T],
    indexes: impl IntoIterator<Item = usize>,
) -> Vec<T> {
    indexes
        .into_iter()
        .filter_map(|index| items.get(index).cloned())
        .collect()
}

#[cfg(test)]
mod selection_tests {
    use super::{normalize_url, parse_extra_headers, select_by_indexes};

    #[test]
    fn selects_valid_indexes_and_ignores_out_of_range_values() {
        let values = ["github", "gitlab", "gitea"];
        assert_eq!(
            select_by_indexes(&values, [2, 99, 0]),
            vec!["gitea", "github"]
        );
    }

    #[test]
    fn normalize_url_returns_error_instead_of_exiting() {
        assert!(normalize_url("javascript:alert(1)").is_err());
        assert_eq!(
            normalize_url("example.test/path").unwrap(),
            "https://example.test/path"
        );
    }

    #[test]
    fn parse_extra_headers_returns_error_instead_of_exiting() {
        let error = parse_extra_headers(&["bad header".to_string()]).unwrap_err();
        assert!(error.to_string().contains("Invalid header"));
        assert_eq!(
            parse_extra_headers(&["X-Test: value".to_string()]).unwrap(),
            vec![("X-Test".to_string(), "value".to_string())]
        );
    }
}

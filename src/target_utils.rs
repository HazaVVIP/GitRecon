//! Shared target normalization and naming helpers.

use std::path::Path;

pub(crate) fn normalize_url(url: &str) -> String {
    match crate::validation::validate_and_normalize_url(url) {
        Ok(normalized) => normalized,
        Err(e) => {
            eprintln!("  ✘  Invalid URL: {}", e);
            std::process::exit(1);
        }
    }
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

pub(crate) fn parse_extra_headers(raw: &[String]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for h in raw {
        match crate::validation::validate_custom_header(h) {
            Ok((k, v)) => result.push((k, v)),
            Err(e) => {
                eprintln!("  ✘  Invalid header '{}': {}", h, e);
                std::process::exit(1);
            }
        }
    }
    result
}

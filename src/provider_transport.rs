//! Provider-neutral transport parsing primitives.
//!
//! Providers retain ownership of retry policy, rate-limit semantics, and
//! endpoint response schemas. This module only centralizes wire-format parsing
//! that must remain byte-for-byte compatible across adapters.

use std::collections::HashMap;

/// Extract the URL marked `rel="next"` from an RFC 5988-style Link header.
pub(crate) fn parse_next_link(header: &str) -> Option<String> {
    for part in header.split(',') {
        let part = part.trim();
        if part.contains(r#"rel="next""#) {
            if let Some(start) = part.find('<') {
                if let Some(end) = part.find('>') {
                    return Some(part[start + 1..end].to_string());
                }
            }
        }
    }
    None
}

/// Parse a numeric Retry-After value.
///
/// HTTP-date values deliberately return `None`; providers choose their own
/// fallback because reset headers and rate-limit semantics differ by forge.
pub(crate) fn parse_retry_after(headers: &HashMap<String, String>) -> Option<u64> {
    let raw = headers
        .get("retry-after")
        .or_else(|| headers.get("Retry-After"))?;
    raw.trim().parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::{parse_next_link, parse_retry_after};
    use std::collections::HashMap;

    #[test]
    fn parses_next_link_and_ignores_other_relations() {
        let header = r#"<https://forge.invalid/items?page=2>; rel="next", <https://forge.invalid/items?page=9>; rel="last""#;
        assert_eq!(
            parse_next_link(header).as_deref(),
            Some("https://forge.invalid/items?page=2")
        );
        assert_eq!(
            parse_next_link(r#"<https://forge.invalid/items?page=1>; rel="prev""#),
            None
        );
    }

    #[test]
    fn parses_numeric_retry_after_and_rejects_dates() {
        let mut headers = HashMap::new();
        headers.insert("retry-after".to_string(), "7".to_string());
        assert_eq!(parse_retry_after(&headers), Some(7));
        headers.insert(
            "Retry-After".to_string(),
            "Wed, 21 Oct 2015 07:28:00 GMT".to_string(),
        );
        assert_eq!(parse_retry_after(&headers), Some(7));
        headers.remove("retry-after");
        assert_eq!(parse_retry_after(&headers), None);
    }
}

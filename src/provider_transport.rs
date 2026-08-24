//! Provider-neutral transport parsing primitives.
//!
//! Providers retain ownership of retry policy, rate-limit semantics, and
//! endpoint response schemas. This module only centralizes wire-format parsing
//! that must remain byte-for-byte compatible across adapters.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};

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

/// Parse a Retry-After value into a delay using a caller-supplied clock.
///
/// The wire format permits either delay-seconds or HTTP-date. This helper only
/// parses the header; callers retain ownership of fallback and maximum-delay
/// policy because rate-limit semantics differ by provider.
pub(crate) fn parse_retry_after_duration(
    headers: &HashMap<String, String>,
    now: DateTime<Utc>,
) -> Option<Duration> {
    let raw = headers
        .get("retry-after")
        .or_else(|| headers.get("Retry-After"))?
        .trim();
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }

    let parsed = DateTime::parse_from_rfc2822(raw)
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(raw, "%A, %d-%b-%y %H:%M:%S GMT")
                .ok()
                .map(|value| DateTime::from_naive_utc_and_offset(value, Utc))
        })
        .or_else(|| {
            NaiveDateTime::parse_from_str(raw, "%a %b %e %H:%M:%S %Y")
                .ok()
                .map(|value| DateTime::from_naive_utc_and_offset(value, Utc))
        })?;

    Some(Duration::from_secs(
        parsed.signed_duration_since(now).num_seconds().max(0) as u64,
    ))
}

#[cfg(test)]
mod tests {
    use super::{parse_next_link, parse_retry_after_duration};
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;
    use std::time::Duration;

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
    fn parses_numeric_and_all_http_date_forms_against_fixed_clock() {
        let now = DateTime::parse_from_rfc3339("2026-08-24T00:00:00Z")
            .expect("fixed test clock")
            .with_timezone(&Utc);
        for value in [
            "12",
            "Mon, 24 Aug 2026 00:00:12 GMT",
            "Monday, 24-Aug-26 00:00:12 GMT",
            "Mon Aug 24 00:00:12 2026",
        ] {
            let mut headers = HashMap::new();
            headers.insert("retry-after".to_string(), value.to_string());
            assert_eq!(
                parse_retry_after_duration(&headers, now),
                Some(Duration::from_secs(12)),
                "value: {value}"
            );
        }
    }

    #[test]
    fn clamps_http_dates_before_now_to_zero_and_rejects_malformed_values() {
        let now = DateTime::parse_from_rfc3339("2026-08-24T00:00:00Z")
            .expect("fixed test clock")
            .with_timezone(&Utc);
        let mut headers = HashMap::new();
        headers.insert(
            "retry-after".to_string(),
            "Sun, 23 Aug 2026 23:59:59 GMT".to_string(),
        );
        assert_eq!(
            parse_retry_after_duration(&headers, now),
            Some(Duration::ZERO)
        );
        headers.insert("retry-after".to_string(), "not-a-date".to_string());
        assert_eq!(parse_retry_after_duration(&headers, now), None);
    }
}

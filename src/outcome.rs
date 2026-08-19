//! Stable per-target outcome types used by orchestration and aggregate reports.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetStatus {
    Success,
    Failed,
    Partial,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetErrorCode {
    NoGitExposure,
    ConfidenceBelowMinimum,
    ScanFailed,
    PartialExposure,
    AuthenticationFailed,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScanSummary {
    pub(crate) report_path: String,
    pub(crate) findings_count: usize,
    pub(crate) risk_score: u32,
}

pub(crate) fn classify_error(error: &str) -> TargetErrorCode {
    let lower = error.to_ascii_lowercase();
    if lower.contains("authentication")
        || lower.contains("invalid or expired")
        || lower.contains("access denied")
        || lower.contains("http 401")
        || lower.contains("http 403")
    {
        TargetErrorCode::AuthenticationFailed
    } else {
        TargetErrorCode::ScanFailed
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_error, TargetErrorCode};

    #[test]
    fn classifies_authentication_failures() {
        assert!(matches!(
            classify_error("Invalid or expired token (HTTP 401)"),
            TargetErrorCode::AuthenticationFailed
        ));
        assert!(matches!(
            classify_error("Access denied (HTTP 403)"),
            TargetErrorCode::AuthenticationFailed
        ));
    }

    #[test]
    fn forge_authentication_contract_maps_401_and_403_for_all_providers() {
        let auth_errors = [
            "Invalid or expired token (HTTP 401)",
            "Invalid or expired App Password (HTTP 401)",
            "Access denied. Check App Password permissions (HTTP 403)",
            "Authentication failed with HTTP 403",
        ];
        for error in auth_errors {
            assert!(
                matches!(classify_error(error), TargetErrorCode::AuthenticationFailed),
                "expected authentication classification for: {error}"
            );
        }
    }

    #[test]
    fn forge_non_authentication_http_errors_remain_scan_failures() {
        for error in [
            "GET tree returned HTTP 404",
            "GET blob returned HTTP 500",
            "API endpoint returned HTTP 429",
        ] {
            assert!(matches!(classify_error(error), TargetErrorCode::ScanFailed));
        }
    }

    #[test]
    fn keeps_transport_and_scan_errors_distinct() {
        assert!(matches!(
            classify_error("GET tree returned HTTP 500"),
            TargetErrorCode::ScanFailed
        ));
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TargetOutcome {
    pub(crate) target: String,
    pub(crate) target_type: String,
    pub(crate) status: TargetStatus,
    pub(crate) report_path: Option<String>,
    pub(crate) findings_count: usize,
    pub(crate) risk_score: u32,
    pub(crate) error_code: Option<TargetErrorCode>,
    pub(crate) error: Option<String>,
}

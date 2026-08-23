//! Stable per-target outcome types used by orchestration and aggregate reports.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetStatus {
    Success,
    Failed,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TargetErrorCode {
    NoGitExposure,
    ConfidenceBelowMinimum,
    ScanFailed,
    PartialExposure,
    AuthenticationFailed,
    UnsupportedCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ErrorStage {
    Capability,
    Authentication,
    Transport,
    Scan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct ErrorMetadata {
    pub(crate) code: TargetErrorCode,
    pub(crate) stage: ErrorStage,
    pub(crate) http_status: Option<u16>,
    pub(crate) retryable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScanSummary {
    pub(crate) report_path: String,
    pub(crate) findings_count: usize,
    pub(crate) risk_score: u32,
}

pub(crate) fn classify_error_details(error: &str) -> ErrorMetadata {
    let lower = error.to_ascii_lowercase();
    let http_status = lower
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|parts| {
            (parts[0] == "http")
                .then(|| parts[1].parse::<u16>().ok())
                .flatten()
        });
    let capability = lower.contains("unsupported capability")
        || lower.contains("not available for this provider");
    let authentication = lower.contains("authentication")
        || lower.contains("invalid or expired")
        || lower.contains("access denied")
        || matches!(http_status, Some(401 | 403));
    let retryable = matches!(http_status, Some(408 | 425 | 429 | 500..=599));
    let (code, stage) = if capability {
        (
            TargetErrorCode::UnsupportedCapability,
            ErrorStage::Capability,
        )
    } else if authentication {
        (
            TargetErrorCode::AuthenticationFailed,
            ErrorStage::Authentication,
        )
    } else if http_status.is_some() {
        (TargetErrorCode::ScanFailed, ErrorStage::Transport)
    } else {
        (TargetErrorCode::ScanFailed, ErrorStage::Scan)
    };
    ErrorMetadata {
        code,
        stage,
        http_status,
        retryable,
    }
}

pub(crate) fn classify_error(error: &str) -> TargetErrorCode {
    classify_error_details(error).code
}

#[cfg(test)]
mod tests {
    use super::{classify_error, classify_error_details, ErrorStage, TargetErrorCode};

    #[test]
    fn typed_metadata_carries_transport_retryability() {
        let metadata = classify_error_details("GET blob returned HTTP 503");
        assert_eq!(metadata.code, TargetErrorCode::ScanFailed);
        assert_eq!(metadata.stage, ErrorStage::Transport);
        assert_eq!(metadata.http_status, Some(503));
        assert!(metadata.retryable);

        let metadata = classify_error_details(
            "Unsupported capability: history is not available for this provider",
        );
        assert_eq!(metadata.code, TargetErrorCode::UnsupportedCapability);
        assert_eq!(metadata.stage, ErrorStage::Capability);
        assert_eq!(metadata.http_status, None);
        assert!(!metadata.retryable);
    }

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
    fn unsupported_forge_capability_has_dedicated_error_code() {
        assert!(matches!(
            classify_error("Unsupported capability: forge scan scope 'history' is not available for this provider"),
            TargetErrorCode::UnsupportedCapability
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error_metadata: Option<ErrorMetadata>,
}

impl TargetOutcome {
    pub(crate) fn success(
        target: impl Into<String>,
        target_type: impl Into<String>,
        summary: &ScanSummary,
    ) -> Self {
        Self {
            target: target.into(),
            target_type: target_type.into(),
            status: TargetStatus::Success,
            report_path: (!summary.report_path.is_empty()).then(|| summary.report_path.clone()),
            findings_count: summary.findings_count,
            risk_score: summary.risk_score,
            error_code: None,
            error: None,
            error_metadata: None,
        }
    }

    pub(crate) fn failure(
        target: impl Into<String>,
        target_type: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        let error = error.into();
        let error_metadata = classify_error_details(&error);
        Self {
            target: target.into(),
            target_type: target_type.into(),
            status: TargetStatus::Failed,
            report_path: None,
            findings_count: 0,
            risk_score: 0,
            error_code: Some(error_metadata.code.clone()),
            error: Some(error),
            error_metadata: Some(error_metadata),
        }
    }
}

#[cfg(test)]
mod outcome_factory_tests {
    use super::{ErrorStage, ScanSummary, TargetErrorCode, TargetOutcome, TargetStatus};

    #[test]
    fn builds_success_outcome_from_summary() {
        let summary = ScanSummary {
            report_path: "report.json".to_string(),
            findings_count: 3,
            risk_score: 70,
        };
        let outcome = TargetOutcome::success("target", "DIR", &summary);
        assert!(matches!(outcome.status, TargetStatus::Success));
        assert_eq!(outcome.report_path.as_deref(), Some("report.json"));
        assert_eq!(outcome.findings_count, 3);
    }

    #[test]
    fn builds_classified_failure_outcome() {
        let outcome = TargetOutcome::failure("target", "TOKEN", "HTTP 401 authentication failed");
        assert!(matches!(outcome.status, TargetStatus::Failed));
        assert!(matches!(
            outcome.error_code,
            Some(TargetErrorCode::AuthenticationFailed)
        ));
        let metadata = outcome.error_metadata.expect("failure metadata");
        assert_eq!(metadata.stage, ErrorStage::Authentication);
        assert_eq!(metadata.http_status, Some(401));
        assert!(!metadata.retryable);
    }

    #[test]
    fn success_outcome_omits_optional_error_metadata() {
        let summary = ScanSummary {
            report_path: String::new(),
            findings_count: 0,
            risk_score: 0,
        };
        let value =
            serde_json::to_value(TargetOutcome::success("target", "DIR", &summary)).unwrap();
        assert!(!value.as_object().unwrap().contains_key("error_metadata"));
    }
}

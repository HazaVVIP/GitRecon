//! Shared content scanning and result aggregation for local and forge workflows.
//!
//! URL streaming keeps its object-specific orchestration in `streamer.rs`, while
//! this module owns the reusable content policy used by filesystem-backed paths.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use crate::binary_adapter::binary_tuples_to_findings;
use crate::streamer::{self, DynPattern, Finding, StreamResult};

#[derive(Debug)]
pub(crate) struct ContentScanOutcome {
    pub(crate) findings: Vec<Finding>,
    pub(crate) bytes: usize,
    pub(crate) archive_truncated: usize,
    pub(crate) archive_invalid: usize,
    pub(crate) failed: bool,
    pub(crate) stopped: bool,
}

impl ContentScanOutcome {
    pub(crate) fn failed() -> Self {
        Self {
            findings: Vec::new(),
            bytes: 0,
            archive_truncated: 0,
            archive_invalid: 0,
            failed: true,
            stopped: false,
        }
    }

    pub(crate) fn stopped() -> Self {
        Self {
            findings: Vec::new(),
            bytes: 0,
            archive_truncated: 0,
            archive_invalid: 0,
            failed: false,
            stopped: true,
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            findings: Vec::new(),
            bytes: 0,
            archive_truncated: 0,
            archive_invalid: 0,
            failed: false,
            stopped: false,
        }
    }
}

/// Shared policy adapter for text and binary content.
#[derive(Clone)]
pub(crate) struct ContentScanner {
    extra_patterns: Arc<Vec<DynPattern>>,
    exhaustive: bool,
    entropy_threshold: f64,
    max_blob_bytes: usize,
    scan_binaries: bool,
}

impl ContentScanner {
    pub(crate) fn new(
        extra_patterns: Arc<Vec<DynPattern>>,
        exhaustive: bool,
        entropy_threshold: f64,
        max_blob_bytes: usize,
        scan_binaries: bool,
    ) -> Self {
        Self {
            extra_patterns,
            exhaustive,
            entropy_threshold,
            max_blob_bytes,
            scan_binaries,
        }
    }

    pub(crate) fn scan_text_object(
        &self,
        content: &str,
        filename: &str,
        sha1: &str,
        is_deleted: bool,
        false_positive_keywords: &[String],
    ) -> Vec<Finding> {
        streamer::scan_text_with_context(streamer::TextScanContext {
            content,
            filename,
            sha1,
            is_deleted,
            extra_patterns: &self.extra_patterns,
            entropy_threshold: self.entropy_threshold,
            false_positive_keywords,
            exhaustive: self.exhaustive,
        })
    }

    pub(crate) fn scan(
        &self,
        data: &[u8],
        logical_path: &str,
        is_binary: bool,
    ) -> ContentScanOutcome {
        if data.is_empty() {
            return ContentScanOutcome::empty();
        }
        if data.len() > self.max_blob_bytes {
            return ContentScanOutcome::empty();
        }
        if is_binary {
            if !self.scan_binaries {
                return ContentScanOutcome {
                    findings: Vec::new(),
                    bytes: data.len(),
                    archive_truncated: 0,
                    archive_invalid: 0,
                    failed: false,
                    stopped: false,
                };
            }
            let (raw_findings, telemetry) =
                crate::binary_scanner::scan_binary_blob_with_patterns_and_telemetry(
                    data,
                    logical_path,
                    self.max_blob_bytes,
                    &self.extra_patterns,
                );
            return ContentScanOutcome {
                findings: binary_tuples_to_findings(
                    raw_findings,
                    logical_path,
                    self.exhaustive,
                    &self.extra_patterns,
                ),
                bytes: data.len(),
                archive_truncated: telemetry.truncation_total(),
                archive_invalid: telemetry.archive_invalid,
                failed: false,
                stopped: false,
            };
        }

        let text = String::from_utf8_lossy(data);
        let findings = self.scan_text_object(&text, logical_path, "", false, &[]);
        ContentScanOutcome {
            findings,
            bytes: data.len(),
            archive_truncated: 0,
            archive_invalid: 0,
            failed: false,
            stopped: false,
        }
    }
}

const RECENT_FINDINGS_WINDOW: usize = 20;

pub(crate) fn should_stop_scan(
    findings: &[Finding],
    max_findings: usize,
    stop_on_critical: bool,
) -> bool {
    (max_findings > 0 && findings.len() >= max_findings)
        || (stop_on_critical
            && findings
                .iter()
                .rev()
                .take(RECENT_FINDINGS_WINDOW)
                .any(|finding| finding.severity == "CRITICAL"))
}

/// Common sequential reducer for unordered content workers.
#[derive(Debug, Default)]
pub(crate) struct ScanAccumulator {
    pub(crate) findings: Vec<Finding>,
    pub(crate) tech_stack: HashSet<String>,
    pub(crate) blobs_scanned: usize,
    pub(crate) blobs_failed: usize,
    pub(crate) bytes_scanned: usize,
    pub(crate) archive_truncated: usize,
    pub(crate) archive_invalid: usize,
}

impl ScanAccumulator {
    pub(crate) fn absorb(&mut self, outcome: ContentScanOutcome, technologies: Vec<String>) {
        if outcome.stopped {
            return;
        }
        if outcome.failed {
            self.blobs_failed += 1;
            return;
        }
        self.archive_truncated += outcome.archive_truncated;
        self.archive_invalid += outcome.archive_invalid;
        if outcome.bytes > 0 {
            self.blobs_scanned += 1;
            self.bytes_scanned += outcome.bytes;
        }
        self.tech_stack.extend(technologies);
        self.findings.extend(outcome.findings);
    }

    pub(crate) fn into_stream_result(self, started_at: Instant) -> StreamResult {
        let mut tech_stack: Vec<String> = self.tech_stack.into_iter().collect();
        tech_stack.sort_unstable();
        StreamResult {
            findings: self.findings,
            contributors: Vec::new(),
            tech_stack,
            commit_count: 0,
            blobs_scanned: self.blobs_scanned,
            blobs_failed: self.blobs_failed,
            bytes_scanned: self.bytes_scanned,
            elapsed_s: started_at.elapsed().as_secs_f64(),
            files_saved: 0,
            files_save_failed: 0,
            cache_hits: 0,
            cache_misses: 0,
            cache_stats: None,
            object_source_stats: crate::streamer::ObjectSourceStats::default(),
            outcome_stats: crate::streamer::ScanOutcomeStats {
                archive_truncated: self.archive_truncated,
                archive_invalid: self.archive_invalid,
                ..Default::default()
            },
            rate_limit_allowed: 0,
            rate_limit_dropped: 0,
            rate_limit_wait_ms: 0,
            retry_stats: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{should_stop_scan, ContentScanner, ScanAccumulator};
    use crate::streamer::DynPattern;
    use regex::Regex;
    use std::sync::Arc;

    #[test]
    fn text_scanner_respects_normal_and_exhaustive_policy() {
        let patterns = Arc::new(Vec::<DynPattern>::new());
        let normal = ContentScanner::new(patterns.clone(), false, 4.5, 1024, true);
        let exhaustive = ContentScanner::new(patterns, true, 4.5, 1024, true);
        let data = b"api_key=your_api_key_here_value_123";
        assert!(normal.scan(data, "config.env", false).findings.is_empty());
        assert!(!exhaustive
            .scan(data, "config.env", false)
            .findings
            .is_empty());
    }

    #[test]
    fn metadata_aware_text_scan_preserves_object_provenance() {
        let scanner = ContentScanner::new(Arc::new(Vec::new()), true, 4.5, 1024, false);
        let sha1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let findings = scanner.scan_text_object(
            "api_key=your_api_key_here_value_123",
            "config.env",
            sha1,
            true,
            &[],
        );
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|finding| finding.is_deleted));
        assert!(findings
            .iter()
            .all(|finding| finding.commit_sha1.as_deref() == Some(sha1)));
    }

    #[test]
    fn custom_binary_pattern_preserves_metadata_through_adapter() {
        let pattern = DynPattern {
            id: "custom_binary".to_string(),
            sev: "CRITICAL".to_string(),
            desc: "Custom binary marker".to_string(),
            regex: Regex::new("CUSTOM_[A-Z0-9]{4}").unwrap(),
        };
        let scanner = ContentScanner::new(Arc::new(vec![pattern]), false, 4.5, 1024, true);
        let outcome = scanner.scan(b"\0\0CUSTOM_AB12\0", "fixture.bin", true);
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].pattern_id, "custom_binary");
        assert_eq!(outcome.findings[0].severity, "CRITICAL");
        assert_eq!(outcome.findings[0].description, "Custom binary marker");
    }

    #[test]
    fn binary_scanner_can_be_disabled_without_losing_byte_accounting() {
        let scanner = ContentScanner::new(Arc::new(Vec::new()), false, 4.5, 1024, false);
        let outcome = scanner.scan(b"binary bytes", "fixture.bin", true);
        assert!(!outcome.failed);
        assert_eq!(outcome.bytes, 12);
        assert!(outcome.findings.is_empty());
    }

    #[test]
    fn stop_condition_honors_limit_and_critical_policy() {
        let finding = crate::streamer::Finding {
            filename: "fixture.txt".to_string(),
            line: 1,
            pattern_id: "fixture".to_string(),
            description: "fixture".to_string(),
            severity: "CRITICAL".to_string(),
            match_str: "fixture".to_string(),
            context: String::new(),
            is_deleted: false,
            commit_sha1: None,
            confidence_adjustment: None,
        };
        assert!(should_stop_scan(std::slice::from_ref(&finding), 0, true));
        assert!(should_stop_scan(std::slice::from_ref(&finding), 1, false));
        assert!(!should_stop_scan(&[], 1, true));
    }

    #[test]
    fn accumulator_reduces_findings_tech_and_bytes() {
        let scanner = ContentScanner::new(Arc::new(Vec::new()), false, 4.5, 1024, true);
        let outcome = scanner.scan(b"ordinary text", "fixture.txt", false);
        let mut accumulator = ScanAccumulator::default();
        accumulator.absorb(outcome, vec!["Rust".to_string()]);
        let result = accumulator.into_stream_result(std::time::Instant::now());
        assert_eq!(result.blobs_scanned, 1);
        assert_eq!(result.bytes_scanned, 13);
        assert_eq!(result.tech_stack, vec!["Rust"]);
    }
}

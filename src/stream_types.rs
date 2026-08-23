//! Shared stream-domain data models.
//!
//! Behavior-heavy orchestration remains in `streamer`; these data models live
//! separately so reporters and future core-library extraction do not depend on
//! the monolithic worker implementation.

use std::collections::BTreeMap;

use crate::forge::ForgeCapabilities;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub filename: String,
    pub line: usize,
    pub pattern_id: String,
    pub description: String,
    pub severity: String,
    #[serde(rename = "match")]
    pub match_str: String,
    pub context: String,
    pub is_deleted: bool,
    pub commit_sha1: Option<String>,
    pub confidence_adjustment: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Contributor {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Default)]
pub struct StreamResult {
    pub findings: Vec<Finding>,
    pub contributors: Vec<Contributor>,
    pub tech_stack: Vec<String>,
    pub commit_count: usize,
    pub blobs_scanned: usize,
    pub blobs_failed: usize,
    pub bytes_scanned: usize,
    pub elapsed_s: f64,
    pub files_saved: usize,
    pub files_save_failed: usize,
    /// PERF-005: Cache metrics
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub cache_stats: Option<CacheReportStats>,
    /// Object acquisition source metrics for processed blobs.
    pub object_source_stats: ObjectSourceStats,
    /// Object processing outcome metrics.
    pub outcome_stats: ScanOutcomeStats,
    /// PERF-004: Rate limit metrics
    pub rate_limit_allowed: usize,
    pub rate_limit_dropped: usize,
    pub rate_limit_wait_ms: u64,
}

/// Object acquisition source metrics for processed blobs.
#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct ObjectSourceStats {
    pub pack: usize,
    pub cache: usize,
    pub loose_http: usize,
    pub forge: usize,
}

/// Object processing outcome metrics.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ScanOutcomeStats {
    pub skipped_stop_requested: usize,
    pub skipped_invalid_object: usize,
    pub skipped_not_found: usize,
    pub skipped_oversized: usize,
    pub skipped_resource_budget: usize,
    pub skipped_files: usize,
    pub failed_files: usize,
    pub archive_truncated: usize,
    pub archive_invalid: usize,
    pub resource_peak_bytes: usize,
    pub resource_denied_reservations: usize,
    pub scan_scope: Option<String>,
    pub capabilities: Option<ForgeCapabilities>,
    pub unsupported_capability: Option<String>,
    pub history_commits_scanned: usize,
    pub history_entries_considered: usize,
    pub history_entries_scanned: usize,
    pub history_entries_deduplicated: usize,
    pub history_deleted_entries: usize,
    pub history_truncated: bool,
    pub failed_http_statuses: BTreeMap<String, usize>,
}

/// Cache statistics for reporting.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheReportStats {
    pub total_entries: i64,
    pub total_bytes: i64,
    pub expired_entries: i64,
    pub evicted_entries: i64,
    pub evicted_bytes: i64,
    pub size_human: String,
}

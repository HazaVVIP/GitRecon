//! Shared scan accumulator state and checkpoint conversion.
//!
//! The worker scheduler still owns orchestration, while this module owns the
//! mutable aggregate state that is serialized into resumable checkpoints.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::checkpoint;
use crate::object_source::ObjectSourceKind;
use crate::stream_types::Finding;
use crate::streamer::{FailureKind, SkipReason};

#[derive(Default)]
pub(crate) struct State {
    pub(crate) findings: Vec<Finding>,
    pub(crate) contributors: HashMap<String, String>,
    pub(crate) tech_stack: HashSet<String>,
    pub(crate) commit_count: usize,
    pub(crate) blobs_scanned: usize,
    pub(crate) blobs_failed: usize,
    pub(crate) bytes_scanned: usize,
    pub(crate) archive_truncated: usize,
    pub(crate) archive_invalid: usize,
    pub(crate) files_saved: usize,
    pub(crate) files_save_failed: usize,
    pub(crate) skipped_by_reason: HashMap<SkipReason, usize>,
    pub(crate) failed_by_kind: HashMap<FailureKind, usize>,
    pub(crate) objects_by_source: HashMap<ObjectSourceKind, usize>,
}

impl State {
    pub(crate) fn record_skip(&mut self, reason: SkipReason) {
        *self.skipped_by_reason.entry(reason).or_default() += 1;
    }

    pub(crate) fn record_failure(&mut self, kind: FailureKind) {
        *self.failed_by_kind.entry(kind).or_default() += 1;
    }

    pub(crate) fn record_source(&mut self, source: ObjectSourceKind) {
        *self.objects_by_source.entry(source).or_default() += 1;
    }

    pub(crate) fn to_checkpoint(
        &self,
        cache_hits: usize,
        cache_misses: usize,
        rate_limit_allowed: usize,
        rate_limit_dropped: usize,
        rate_limit_wait_ms: u64,
    ) -> checkpoint::StreamAccumulatorCheckpoint {
        let mut tech_stack: Vec<String> = self.tech_stack.iter().cloned().collect();
        tech_stack.sort_unstable();

        let mut failed_http_statuses = BTreeMap::new();
        for (kind, count) in &self.failed_by_kind {
            let FailureKind::HttpStatus(status) = kind;
            failed_http_statuses.insert(*status, *count);
        }

        checkpoint::StreamAccumulatorCheckpoint {
            contributors: self
                .contributors
                .iter()
                .map(|(email, name)| (email.clone(), name.clone()))
                .collect(),
            tech_stack,
            commit_count: self.commit_count,
            blobs_scanned: self.blobs_scanned,
            blobs_failed: self.blobs_failed,
            bytes_scanned: self.bytes_scanned,
            archive_truncated: self.archive_truncated,
            archive_invalid: self.archive_invalid,
            files_saved: self.files_saved,
            files_save_failed: self.files_save_failed,
            skipped_stop_requested: self
                .skipped_by_reason
                .get(&SkipReason::StopRequested)
                .copied()
                .unwrap_or_default(),
            skipped_invalid_object: self
                .skipped_by_reason
                .get(&SkipReason::InvalidObject)
                .copied()
                .unwrap_or_default(),
            skipped_not_found: self
                .skipped_by_reason
                .get(&SkipReason::NotFound)
                .copied()
                .unwrap_or_default(),
            skipped_oversized: self
                .skipped_by_reason
                .get(&SkipReason::Oversized)
                .copied()
                .unwrap_or_default(),
            skipped_resource_budget: self
                .skipped_by_reason
                .get(&SkipReason::ResourceBudget)
                .copied()
                .unwrap_or_default(),
            failed_http_statuses,
            objects_pack: self
                .objects_by_source
                .get(&ObjectSourceKind::Pack)
                .copied()
                .unwrap_or_default(),
            objects_cache: self
                .objects_by_source
                .get(&ObjectSourceKind::Cache)
                .copied()
                .unwrap_or_default(),
            objects_loose_http: self
                .objects_by_source
                .get(&ObjectSourceKind::LooseHttp)
                .copied()
                .unwrap_or_default(),
            cache_hits,
            cache_misses,
            rate_limit_allowed,
            rate_limit_dropped,
            rate_limit_wait_ms,
        }
    }

    pub(crate) fn restore_checkpoint(&mut self, snapshot: checkpoint::StreamAccumulatorCheckpoint) {
        self.contributors = snapshot.contributors.into_iter().collect();
        self.tech_stack = snapshot.tech_stack.into_iter().collect();
        self.commit_count = snapshot.commit_count;
        self.blobs_scanned = snapshot.blobs_scanned;
        self.blobs_failed = snapshot.blobs_failed;
        self.bytes_scanned = snapshot.bytes_scanned;
        self.archive_truncated = snapshot.archive_truncated;
        self.archive_invalid = snapshot.archive_invalid;
        self.files_saved = snapshot.files_saved;
        self.files_save_failed = snapshot.files_save_failed;

        self.skipped_by_reason = [
            (SkipReason::StopRequested, snapshot.skipped_stop_requested),
            (SkipReason::InvalidObject, snapshot.skipped_invalid_object),
            (SkipReason::NotFound, snapshot.skipped_not_found),
            (SkipReason::Oversized, snapshot.skipped_oversized),
            (SkipReason::ResourceBudget, snapshot.skipped_resource_budget),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .collect();
        self.failed_by_kind = snapshot
            .failed_http_statuses
            .into_iter()
            .map(|(status, count)| (FailureKind::HttpStatus(status), count))
            .collect();
        self.objects_by_source = [
            (ObjectSourceKind::Pack, snapshot.objects_pack),
            (ObjectSourceKind::Cache, snapshot.objects_cache),
            (ObjectSourceKind::LooseHttp, snapshot.objects_loose_http),
        ]
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .collect();
    }
}

//! Shared scan accumulator state and checkpoint conversion.
//!
//! The worker scheduler still owns orchestration, while this module owns the
//! mutable aggregate state that is serialized into resumable checkpoints.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::checkpoint;
use crate::object_source::ObjectSourceKind;
use crate::resource_budget::{ResourceBudgetStats, ResourceStageStats};
use crate::scan_scheduler::SchedulerTelemetry;
use crate::stream_types::Finding;
use crate::streamer::{FailureKind, SkipReason};

#[derive(Debug, Clone)]
pub(crate) struct CheckpointTelemetry {
    pub(crate) cache_hits: usize,
    pub(crate) cache_misses: usize,
    pub(crate) rate_limit_allowed: usize,
    pub(crate) rate_limit_dropped: usize,
    pub(crate) rate_limit_wait_ms: u64,
    pub(crate) resource_stats: ResourceBudgetStats,
    pub(crate) scheduler_stats: SchedulerTelemetry,
}

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
    pub(crate) archive_invalid_reasons: BTreeMap<String, usize>,
    pub(crate) files_saved: usize,
    pub(crate) files_save_failed: usize,
    pub(crate) skipped_by_reason: HashMap<SkipReason, usize>,
    pub(crate) failed_by_kind: HashMap<FailureKind, usize>,
    pub(crate) objects_by_source: HashMap<ObjectSourceKind, usize>,
    pub(crate) resource_peak_bytes: usize,
    pub(crate) resource_denied_reservations: usize,
    pub(crate) resource_by_stage: BTreeMap<String, ResourceStageStats>,
    pub(crate) scheduler: checkpoint::SchedulerCheckpointTelemetry,
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
        telemetry: CheckpointTelemetry,
    ) -> checkpoint::StreamAccumulatorCheckpoint {
        let mut tech_stack: Vec<String> = self.tech_stack.iter().cloned().collect();
        tech_stack.sort_unstable();

        let mut failed_http_statuses = BTreeMap::new();
        for (kind, count) in &self.failed_by_kind {
            let FailureKind::HttpStatus(status) = kind;
            failed_http_statuses.insert(*status, *count);
        }

        let mut resource_by_stage = self.resource_by_stage.clone();
        for (stage, live) in &telemetry.resource_stats.by_stage {
            let merged = resource_by_stage
                .entry(stage.clone())
                .or_insert(ResourceStageStats {
                    current_bytes: 0,
                    peak_bytes: 0,
                    denied_reservations: 0,
                });
            merged.current_bytes = 0;
            merged.peak_bytes = merged.peak_bytes.max(live.peak_bytes);
            merged.denied_reservations = merged
                .denied_reservations
                .saturating_add(live.denied_reservations);
        }
        for stats in resource_by_stage.values_mut() {
            stats.current_bytes = 0;
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
            archive_invalid_reasons: self.archive_invalid_reasons.clone(),
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
            cache_hits: telemetry.cache_hits,
            cache_misses: telemetry.cache_misses,
            rate_limit_allowed: telemetry.rate_limit_allowed,
            rate_limit_dropped: telemetry.rate_limit_dropped,
            rate_limit_wait_ms: telemetry.rate_limit_wait_ms,
            resource_peak_bytes: self
                .resource_peak_bytes
                .max(telemetry.resource_stats.peak_bytes),
            resource_denied_reservations: self
                .resource_denied_reservations
                .saturating_add(telemetry.resource_stats.denied_reservations),
            resource_by_stage,
            scheduler: checkpoint::SchedulerCheckpointTelemetry {
                acquire_requests: self
                    .scheduler
                    .acquire_requests
                    .saturating_add(telemetry.scheduler_stats.acquire_requests),
                queued_acquires: self
                    .scheduler
                    .queued_acquires
                    .saturating_add(telemetry.scheduler_stats.queued_acquires),
                queue_wait_ms: self
                    .scheduler
                    .queue_wait_ms
                    .saturating_add(telemetry.scheduler_stats.queue_wait_ms),
                permits_granted: self
                    .scheduler
                    .permits_granted
                    .saturating_add(telemetry.scheduler_stats.permits_granted),
                active_peak: self
                    .scheduler
                    .active_peak
                    .max(telemetry.scheduler_stats.active_peak),
                limit_adjustments: self
                    .scheduler
                    .limit_adjustments
                    .saturating_add(telemetry.scheduler_stats.limit_adjustments),
                adjustment_events: self
                    .scheduler
                    .adjustment_events
                    .saturating_add(telemetry.scheduler_stats.adjustment_events),
                throttle_events: self
                    .scheduler
                    .throttle_events
                    .saturating_add(telemetry.scheduler_stats.throttle_events),
                headroom_events: self
                    .scheduler
                    .headroom_events
                    .saturating_add(telemetry.scheduler_stats.headroom_events),
            },
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
        self.archive_invalid_reasons = snapshot.archive_invalid_reasons;
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
        self.resource_peak_bytes = snapshot.resource_peak_bytes;
        self.resource_denied_reservations = snapshot.resource_denied_reservations;
        self.resource_by_stage = snapshot.resource_by_stage;
        for stats in self.resource_by_stage.values_mut() {
            stats.current_bytes = 0;
        }
        self.scheduler = snapshot.scheduler;
    }
}

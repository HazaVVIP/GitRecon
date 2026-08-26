//! Shared, cancellation-safe resource accounting for scan stages.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// The stage that owns a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceStage {
    Acquisition,
    ObjectScan,
    Archive,
    WorkspaceReconstruction,
    FileScan,
    TargetFanout,
}

impl ResourceStage {
    const ALL: [Self; 6] = [
        Self::Acquisition,
        Self::ObjectScan,
        Self::Archive,
        Self::WorkspaceReconstruction,
        Self::FileScan,
        Self::TargetFanout,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Acquisition => 0,
            Self::ObjectScan => 1,
            Self::Archive => 2,
            Self::WorkspaceReconstruction => 3,
            Self::FileScan => 4,
            Self::TargetFanout => 5,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Acquisition => "acquisition",
            Self::ObjectScan => "object_scan",
            Self::Archive => "archive",
            Self::WorkspaceReconstruction => "workspace_reconstruction",
            Self::FileScan => "file_scan",
            Self::TargetFanout => "target_fanout",
        }
    }
}

/// Per-stage snapshot of global budget activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ResourceStageStats {
    pub(crate) current_bytes: usize,
    pub(crate) peak_bytes: usize,
    pub(crate) denied_reservations: usize,
}

/// Snapshot of global budget activity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResourceBudgetStats {
    pub(crate) current_bytes: usize,
    pub(crate) peak_bytes: usize,
    pub(crate) denied_reservations: usize,
    pub(crate) by_stage: BTreeMap<String, ResourceStageStats>,
}

/// Shared byte budget. A limit of zero means unlimited, matching existing CLI
/// semantics for an unbounded memory setting.
#[derive(Debug)]
pub(crate) struct ResourceBudget {
    limit: usize,
    in_flight: Arc<AtomicU64>,
    peak: AtomicUsize,
    denied_reservations: AtomicUsize,
    stage_in_flight: [Arc<AtomicU64>; 6],
    stage_peak: [AtomicUsize; 6],
    stage_denied: [AtomicUsize; 6],
}

impl ResourceBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            in_flight: Arc::new(AtomicU64::new(0)),
            peak: AtomicUsize::new(0),
            denied_reservations: AtomicUsize::new(0),
            stage_in_flight: std::array::from_fn(|_| Arc::new(AtomicU64::new(0))),
            stage_peak: std::array::from_fn(|_| AtomicUsize::new(0)),
            stage_denied: std::array::from_fn(|_| AtomicUsize::new(0)),
        }
    }

    pub(crate) fn try_reserve(
        self: &Arc<Self>,
        stage: ResourceStage,
        bytes: usize,
    ) -> Option<ResourceReservation> {
        let stage_index = stage.index();
        if self.limit == 0 {
            return Some(ResourceReservation {
                budget: Arc::clone(self),
                bytes: 0,
                stage_index,
            });
        }
        let result = self
            .in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                let next = current.saturating_add(bytes as u64);
                (next <= self.limit as u64).then_some(next)
            });
        if result.is_err() {
            self.denied_reservations.fetch_add(1, Ordering::Relaxed);
            self.stage_denied[stage_index].fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let current = result.unwrap().saturating_add(bytes as u64) as usize;
        self.peak.fetch_max(current, Ordering::Relaxed);
        let stage_current = self.stage_in_flight[stage_index]
            .fetch_add(bytes as u64, Ordering::AcqRel)
            .saturating_add(bytes as u64) as usize;
        self.stage_peak[stage_index].fetch_max(stage_current, Ordering::Relaxed);
        Some(ResourceReservation {
            budget: Arc::clone(self),
            bytes,
            stage_index,
        })
    }

    pub(crate) fn stats(&self) -> ResourceBudgetStats {
        let mut by_stage = BTreeMap::new();
        for stage in ResourceStage::ALL {
            let index = stage.index();
            by_stage.insert(
                stage.as_str().to_string(),
                ResourceStageStats {
                    current_bytes: self.stage_in_flight[index].load(Ordering::Acquire) as usize,
                    peak_bytes: self.stage_peak[index].load(Ordering::Relaxed),
                    denied_reservations: self.stage_denied[index].load(Ordering::Relaxed),
                },
            );
        }
        ResourceBudgetStats {
            current_bytes: self.in_flight.load(Ordering::Acquire) as usize,
            peak_bytes: self.peak.load(Ordering::Relaxed),
            denied_reservations: self.denied_reservations.load(Ordering::Relaxed),
            by_stage,
        }
    }
}

/// RAII reservation. Dropping it releases the exact amount, including when a
/// worker is cancelled or returns early.
pub(crate) struct ResourceReservation {
    budget: Arc<ResourceBudget>,
    bytes: usize,
    stage_index: usize,
}

impl Drop for ResourceReservation {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.budget
                .in_flight
                .fetch_sub(self.bytes as u64, Ordering::Release);
            self.budget.stage_in_flight[self.stage_index]
                .fetch_sub(self.bytes as u64, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ResourceBudget, ResourceStage};
    use std::sync::Arc;

    #[test]
    fn reservation_releases_on_drop_and_tracks_peak() {
        let budget = Arc::new(ResourceBudget::new(10));
        let reservation = budget
            .try_reserve(ResourceStage::ObjectScan, 6)
            .expect("first reservation should fit");
        assert_eq!(budget.stats().current_bytes, 6);
        assert_eq!(budget.stats().peak_bytes, 6);
        assert_eq!(budget.stats().by_stage["object_scan"].current_bytes, 6);
        assert_eq!(budget.stats().by_stage["object_scan"].peak_bytes, 6);
        assert!(budget.try_reserve(ResourceStage::ObjectScan, 5).is_none());
        assert_eq!(budget.stats().denied_reservations, 1);
        assert_eq!(
            budget.stats().by_stage["object_scan"].denied_reservations,
            1
        );
        drop(reservation);
        assert_eq!(budget.stats().current_bytes, 0);
        assert_eq!(budget.stats().by_stage["object_scan"].current_bytes, 0);
        assert!(budget.try_reserve(ResourceStage::Acquisition, 10).is_some());
    }

    #[test]
    fn stages_track_peak_independently() {
        let budget = Arc::new(ResourceBudget::new(20));
        let acquisition = budget
            .try_reserve(ResourceStage::Acquisition, 8)
            .expect("acquisition should fit");
        let archive = budget
            .try_reserve(ResourceStage::Archive, 4)
            .expect("archive extraction should fit");
        assert_eq!(budget.stats().current_bytes, 12);
        assert_eq!(budget.stats().by_stage["acquisition"].peak_bytes, 8);
        assert_eq!(budget.stats().by_stage["archive"].peak_bytes, 4);
        drop(archive);
        drop(acquisition);
        assert_eq!(budget.stats().current_bytes, 0);
    }

    #[test]
    fn zero_limit_is_unlimited_and_cancellation_safe() {
        let budget = Arc::new(ResourceBudget::new(0));
        let reservation = budget
            .try_reserve(ResourceStage::ObjectScan, usize::MAX)
            .expect("zero limit should be unlimited");
        assert_eq!(budget.stats().current_bytes, 0);
        assert_eq!(budget.stats().denied_reservations, 0);
        assert_eq!(budget.stats().by_stage["object_scan"].peak_bytes, 0);
        drop(reservation);
        assert_eq!(budget.stats().current_bytes, 0);
    }
}

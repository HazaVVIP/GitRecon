//! Shared, cancellation-safe resource accounting for scan stages.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// The stage that owns a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceStage {
    ObjectScan,
}

/// Snapshot of global budget activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResourceBudgetStats {
    pub(crate) current_bytes: usize,
    pub(crate) peak_bytes: usize,
    pub(crate) denied_reservations: usize,
}

/// Shared byte budget. A limit of zero means unlimited, matching existing CLI
/// semantics for an unbounded memory setting.
#[derive(Debug)]
pub(crate) struct ResourceBudget {
    limit: usize,
    in_flight: Arc<AtomicU64>,
    peak: AtomicUsize,
    denied_reservations: AtomicUsize,
}

impl ResourceBudget {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            in_flight: Arc::new(AtomicU64::new(0)),
            peak: AtomicUsize::new(0),
            denied_reservations: AtomicUsize::new(0),
        }
    }

    pub(crate) fn try_reserve(
        self: &Arc<Self>,
        stage: ResourceStage,
        bytes: usize,
    ) -> Option<ResourceReservation> {
        let _ = stage;
        if self.limit == 0 {
            return Some(ResourceReservation {
                budget: Arc::clone(self),
                bytes: 0,
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
            return None;
        }
        let current = result.unwrap().saturating_add(bytes as u64) as usize;
        self.peak.fetch_max(current, Ordering::Relaxed);
        Some(ResourceReservation {
            budget: Arc::clone(self),
            bytes,
        })
    }

    pub(crate) fn stats(&self) -> ResourceBudgetStats {
        ResourceBudgetStats {
            current_bytes: self.in_flight.load(Ordering::Acquire) as usize,
            peak_bytes: self.peak.load(Ordering::Relaxed),
            denied_reservations: self.denied_reservations.load(Ordering::Relaxed),
        }
    }
}

/// RAII reservation. Dropping it releases the exact amount, including when a
/// worker is cancelled or returns early.
pub(crate) struct ResourceReservation {
    budget: Arc<ResourceBudget>,
    bytes: usize,
}

impl Drop for ResourceReservation {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.budget
                .in_flight
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
        assert!(budget.try_reserve(ResourceStage::ObjectScan, 5).is_none());
        assert_eq!(budget.stats().denied_reservations, 1);
        drop(reservation);
        assert_eq!(budget.stats().current_bytes, 0);
        assert!(budget.try_reserve(ResourceStage::ObjectScan, 10).is_some());
    }

    #[test]
    fn zero_limit_is_unlimited_and_cancellation_safe() {
        let budget = Arc::new(ResourceBudget::new(0));
        let reservation = budget
            .try_reserve(ResourceStage::ObjectScan, usize::MAX)
            .expect("zero limit should be unlimited");
        assert_eq!(budget.stats().current_bytes, 0);
        assert_eq!(budget.stats().denied_reservations, 0);
        drop(reservation);
        assert_eq!(budget.stats().current_bytes, 0);
    }
}

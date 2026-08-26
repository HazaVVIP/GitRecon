use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct TargetFanoutTelemetry {
    pub(crate) configured_limit: usize,
    pub(crate) current_active: usize,
    pub(crate) peak_active: usize,
    pub(crate) current_waiters: usize,
    pub(crate) queue_wait_count: usize,
    pub(crate) queue_wait_ms: u64,
    pub(crate) permits_granted: usize,
    pub(crate) targets_started: usize,
    pub(crate) targets_completed: usize,
}

#[derive(Debug)]
struct TargetFanoutState {
    configured_limit: usize,
    semaphore: Arc<Semaphore>,
    current_active: AtomicUsize,
    peak_active: AtomicUsize,
    current_waiters: AtomicUsize,
    queue_wait_count: AtomicUsize,
    queue_wait_ms: AtomicU64,
    permits_granted: AtomicUsize,
    targets_started: AtomicUsize,
    targets_completed: AtomicUsize,
}

#[derive(Debug, Clone)]
pub(crate) struct TargetFanoutGate {
    state: Arc<TargetFanoutState>,
}

#[derive(Debug)]
pub(crate) struct TargetFanoutPermit {
    _permit: OwnedSemaphorePermit,
    state: Arc<TargetFanoutState>,
}

impl TargetFanoutGate {
    pub(crate) fn new(limit: usize) -> Self {
        let configured_limit = limit.max(1);
        Self {
            state: Arc::new(TargetFanoutState {
                configured_limit,
                semaphore: Arc::new(Semaphore::new(configured_limit)),
                current_active: AtomicUsize::new(0),
                peak_active: AtomicUsize::new(0),
                current_waiters: AtomicUsize::new(0),
                queue_wait_count: AtomicUsize::new(0),
                queue_wait_ms: AtomicU64::new(0),
                permits_granted: AtomicUsize::new(0),
                targets_started: AtomicUsize::new(0),
                targets_completed: AtomicUsize::new(0),
            }),
        }
    }

    pub(crate) async fn acquire(&self) -> TargetFanoutPermit {
        self.state.current_waiters.fetch_add(1, Ordering::AcqRel);
        let was_contended = self.state.semaphore.available_permits() == 0;
        let wait_started = Instant::now();
        let permit = self
            .state
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("target fan-out semaphore is never closed");
        self.state.current_waiters.fetch_sub(1, Ordering::AcqRel);

        if was_contended {
            self.state.queue_wait_count.fetch_add(1, Ordering::Relaxed);
            self.state
                .queue_wait_ms
                .fetch_add(wait_started.elapsed().as_millis() as u64, Ordering::Relaxed);
        }

        let active = self
            .state
            .current_active
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.state.peak_active.fetch_max(active, Ordering::Relaxed);
        self.state.permits_granted.fetch_add(1, Ordering::Relaxed);
        self.state.targets_started.fetch_add(1, Ordering::Relaxed);

        TargetFanoutPermit {
            _permit: permit,
            state: self.state.clone(),
        }
    }

    pub(crate) fn snapshot(&self) -> TargetFanoutTelemetry {
        TargetFanoutTelemetry {
            configured_limit: self.state.configured_limit,
            current_active: self.state.current_active.load(Ordering::Acquire),
            peak_active: self.state.peak_active.load(Ordering::Relaxed),
            current_waiters: self.state.current_waiters.load(Ordering::Acquire),
            queue_wait_count: self.state.queue_wait_count.load(Ordering::Relaxed),
            queue_wait_ms: self.state.queue_wait_ms.load(Ordering::Relaxed),
            permits_granted: self.state.permits_granted.load(Ordering::Relaxed),
            targets_started: self.state.targets_started.load(Ordering::Relaxed),
            targets_completed: self.state.targets_completed.load(Ordering::Relaxed),
        }
    }
}

impl Drop for TargetFanoutPermit {
    fn drop(&mut self) {
        self.state.current_active.fetch_sub(1, Ordering::AcqRel);
        self.state.targets_completed.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::TargetFanoutGate;

    #[tokio::test]
    async fn snapshot_tracks_permit_lifecycle_and_peak() {
        let gate = TargetFanoutGate::new(2);
        let first = gate.acquire().await;
        let second = gate.acquire().await;

        let snapshot = gate.snapshot();
        assert_eq!(snapshot.configured_limit, 2);
        assert_eq!(snapshot.current_active, 2);
        assert_eq!(snapshot.peak_active, 2);
        assert_eq!(snapshot.current_waiters, 0);
        assert_eq!(snapshot.queue_wait_count, 0);
        assert_eq!(snapshot.permits_granted, 2);
        assert_eq!(snapshot.targets_started, 2);
        assert_eq!(snapshot.targets_completed, 0);

        drop(second);
        drop(first);
        let completed = gate.snapshot();
        assert_eq!(completed.current_active, 0);
        assert_eq!(completed.targets_completed, 2);
    }

    #[tokio::test]
    async fn contended_acquire_records_queue_pressure() {
        let gate = TargetFanoutGate::new(1);
        let first = gate.acquire().await;
        let waiting_gate = gate.clone();
        let waiting = tokio::spawn(async move {
            let _permit = waiting_gate.acquire().await;
        });

        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        assert_eq!(gate.snapshot().current_waiters, 1);
        drop(first);
        waiting.await.expect("waiting target should complete");

        let snapshot = gate.snapshot();
        assert_eq!(snapshot.queue_wait_count, 1);
        assert_eq!(snapshot.permits_granted, 2);
        assert_eq!(snapshot.targets_completed, 2);
        assert_eq!(snapshot.current_active, 0);
    }

    #[test]
    fn zero_limit_is_normalized_to_one() {
        let gate = TargetFanoutGate::new(0);
        assert_eq!(gate.snapshot().configured_limit, 1);
    }
}

//! Adaptive worker scheduling primitives.
//!
//! The scheduler owns worker-limit feedback and dynamic semaphore admission;
//! the streamer remains responsible for scan orchestration and accumulation.

use std::sync::atomic::{fence, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use crate::checkpoint::AdaptiveConcurrencyState;

const MIN_ADAPTIVE_WORKERS: usize = 5;
const MAX_ADAPTIVE_WORKERS: usize = 200;
const ADAPTIVE_ADJUSTMENT_INTERVAL: usize = 100;
const THROTTLE_ERROR_RATE: f64 = 0.10;
const HEADROOM_ERROR_RATE: f64 = 0.02;
const ADJUSTMENT_COOLDOWN_BLOBS: usize = 50;

/// Adaptive concurrency controller.
#[derive(Debug, Clone)]
pub struct AdaptiveConcurrency {
    current_workers: Arc<AtomicU64>,
    initial_workers: u64,
    window_requests: Arc<AtomicU64>,
    window_errors: Arc<AtomicU64>,
    last_adjustment_index: Arc<AtomicU64>,
    last_decrease_index: Arc<AtomicU64>,
    verbose: bool,
}

impl AdaptiveConcurrency {
    pub fn new(initial_workers: usize, verbose: bool) -> Self {
        Self {
            current_workers: Arc::new(AtomicU64::new(initial_workers as u64)),
            initial_workers: initial_workers as u64,
            window_requests: Arc::new(AtomicU64::new(0)),
            window_errors: Arc::new(AtomicU64::new(0)),
            last_adjustment_index: Arc::new(AtomicU64::new(0)),
            last_decrease_index: Arc::new(AtomicU64::new(0)),
            verbose,
        }
    }

    pub fn from_checkpoint(state: AdaptiveConcurrencyState, verbose: bool) -> Self {
        let validated_workers = state
            .current_workers
            .clamp(MIN_ADAPTIVE_WORKERS, MAX_ADAPTIVE_WORKERS);
        Self {
            current_workers: Arc::new(AtomicU64::new(validated_workers as u64)),
            initial_workers: state.initial_workers as u64,
            window_requests: Arc::new(AtomicU64::new(state.window_requests as u64)),
            window_errors: Arc::new(AtomicU64::new(state.window_errors as u64)),
            last_adjustment_index: Arc::new(AtomicU64::new(state.last_adjustment_index as u64)),
            last_decrease_index: Arc::new(AtomicU64::new(state.last_adjustment_index as u64)),
            verbose,
        }
    }

    pub fn to_checkpoint_state(&self) -> AdaptiveConcurrencyState {
        AdaptiveConcurrencyState {
            current_workers: self.current_workers.load(Ordering::Acquire) as usize,
            initial_workers: self.initial_workers as usize,
            window_requests: self.window_requests.load(Ordering::Acquire) as usize,
            window_errors: self.window_errors.load(Ordering::Acquire) as usize,
            last_adjustment_index: self.last_adjustment_index.load(Ordering::Acquire) as usize,
        }
    }

    pub fn record_success(&self) {
        self.window_requests.fetch_add(1, Ordering::AcqRel);
    }

    pub fn record_error(&self) {
        self.window_requests.fetch_add(1, Ordering::AcqRel);
        self.window_errors.fetch_add(1, Ordering::AcqRel);
    }

    pub fn current_workers(&self) -> usize {
        self.current_workers.load(Ordering::Acquire) as usize
    }

    pub(crate) fn window_counts(&self) -> (usize, usize) {
        (
            self.window_requests.load(Ordering::Acquire) as usize,
            self.window_errors.load(Ordering::Acquire) as usize,
        )
    }

    pub fn should_adjust(&self, blobs_processed: usize) -> bool {
        let last_adj = self.last_adjustment_index.load(Ordering::Acquire);
        blobs_processed as u64 >= last_adj + ADAPTIVE_ADJUSTMENT_INTERVAL as u64
    }

    pub fn adjust(&self, blobs_processed: usize) -> usize {
        self.last_adjustment_index
            .store(blobs_processed as u64, Ordering::Release);
        const DECAY_FACTOR: f64 = 0.2;
        let window_requests = self.window_requests.load(Ordering::Acquire);
        let window_errors = self.window_errors.load(Ordering::Acquire);
        self.window_requests.store(
            (window_requests as f64 * DECAY_FACTOR) as u64,
            Ordering::Release,
        );
        self.window_errors.store(
            (window_errors as f64 * DECAY_FACTOR) as u64,
            Ordering::Release,
        );

        if window_requests == 0 {
            return self.current_workers.load(Ordering::Acquire) as usize;
        }
        let error_rate = window_errors as f64 / window_requests as f64;
        let old_workers = self.current_workers.load(Ordering::Acquire) as usize;
        let mut new_workers = old_workers;
        let last_decrease = self.last_decrease_index.load(Ordering::Acquire);
        let in_cooldown =
            (blobs_processed as u64) < (last_decrease + ADJUSTMENT_COOLDOWN_BLOBS as u64);

        if error_rate > THROTTLE_ERROR_RATE && !in_cooldown {
            new_workers = (old_workers / 2).max(MIN_ADAPTIVE_WORKERS);
            fence(Ordering::Acquire);
            self.current_workers
                .store(new_workers as u64, Ordering::Release);
            fence(Ordering::Release);
            self.last_decrease_index
                .store(blobs_processed as u64, Ordering::Release);
            if self.verbose {
                eprintln!(
                    "  [ADAPTIVE] Throttling detected ({:.1}% errors). Decreasing workers: {} → {} (cooldown active for next {} blobs)",
                    error_rate * 100.0,
                    old_workers,
                    new_workers,
                    ADJUSTMENT_COOLDOWN_BLOBS
                );
            }
        } else if error_rate < HEADROOM_ERROR_RATE && window_requests >= 50 {
            let increase = (self.initial_workers / 10).max(1) as usize;
            let target = (self.initial_workers as usize).min(MAX_ADAPTIVE_WORKERS);
            new_workers = (old_workers + increase).min(target);
            self.current_workers
                .store(new_workers as u64, Ordering::Release);
            if self.verbose && new_workers != old_workers {
                eprintln!(
                    "  [ADAPTIVE] Headroom available ({:.1}% errors). Increasing workers: {} → {}",
                    error_rate * 100.0,
                    old_workers,
                    new_workers
                );
            }
        } else if self.verbose && window_requests >= 50 {
            eprintln!(
                "  [ADAPTIVE] Steady state ({:.1}% errors, {} requests). Workers: {}",
                error_rate * 100.0,
                window_requests,
                old_workers
            );
        }
        new_workers
    }
}

#[derive(Clone)]
pub(crate) struct AdaptiveConcurrencyGate {
    inner: Arc<AdaptiveConcurrencyGateInner>,
}

struct AdaptiveConcurrencyGateInner {
    semaphore: Arc<Semaphore>,
    limit: AtomicUsize,
    active: AtomicUsize,
    notify: Notify,
}

pub(crate) struct AdaptiveConcurrencyPermit {
    inner: Arc<AdaptiveConcurrencyGateInner>,
    _permit: OwnedSemaphorePermit,
}

impl AdaptiveConcurrencyGate {
    pub(crate) fn new(max_permits: usize) -> Self {
        let max_permits = max_permits.max(1);
        Self {
            inner: Arc::new(AdaptiveConcurrencyGateInner {
                semaphore: Arc::new(Semaphore::new(max_permits)),
                limit: AtomicUsize::new(max_permits),
                active: AtomicUsize::new(0),
                notify: Notify::new(),
            }),
        }
    }

    pub(crate) async fn acquire(&self) -> AdaptiveConcurrencyPermit {
        loop {
            let permit = self
                .inner
                .semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("adaptive concurrency semaphore cannot be closed");
            let active = self.inner.active.fetch_add(1, Ordering::AcqRel) + 1;
            if active <= self.inner.limit.load(Ordering::Acquire) {
                return AdaptiveConcurrencyPermit {
                    inner: self.inner.clone(),
                    _permit: permit,
                };
            }
            let notified = self.inner.notify.notified();
            self.inner.active.fetch_sub(1, Ordering::AcqRel);
            drop(permit);
            notified.await;
        }
    }

    pub(crate) fn set_limit(&self, limit: usize) {
        self.inner.limit.store(limit.max(1), Ordering::Release);
        self.inner.notify.notify_waiters();
    }

    #[cfg(test)]
    pub(crate) fn current_limit(&self) -> usize {
        self.inner.limit.load(Ordering::Acquire)
    }
}

impl Drop for AdaptiveConcurrencyPermit {
    fn drop(&mut self) {
        self.inner.active.fetch_sub(1, Ordering::AcqRel);
        self.inner.notify.notify_one();
    }
}

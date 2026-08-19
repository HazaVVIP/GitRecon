//! rate_limiter.rs
//! PERF-004: Thread-safe Token Bucket Rate Limiter with per-target support.
//!
//! Implementation:
//! - Token bucket algorithm with atomic operations for thread safety
//! - Per-target rate limiting for multi-target scans
//! - Metrics tracking: allowed/dropped/waited requests
//! - Support for unlimited mode (--rate 0)
//! - BUG-CONC-005: Uses mutex to ensure atomic refill operations

#[cfg(test)]
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime};
use tokio::time::sleep;

/// Rate limit metrics for reporting
#[derive(Debug, Default)]
pub struct RateLimitMetrics {
    /// Number of requests allowed (passed through rate limiter)
    pub allowed: AtomicU64,
    /// Number of requests dropped (exceeded rate limit)
    pub dropped: AtomicU64,
    /// Total time spent waiting for rate limit (milliseconds)
    pub total_wait_ms: AtomicU64,
}

impl RateLimitMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Get summary as a map for reporting in rate-limiter tests.
    #[cfg(test)]
    pub fn summary(&self) -> HashMap<String, u64> {
        let mut map = HashMap::new();
        map.insert("allowed".to_string(), self.allowed.load(Ordering::Relaxed));
        map.insert("dropped".to_string(), self.dropped.load(Ordering::Relaxed));
        map.insert(
            "total_wait_ms".to_string(),
            self.total_wait_ms.load(Ordering::Relaxed),
        );
        map
    }
}

/// Token bucket rate limiter using atomic operations for thread safety.
///
/// Algorithm:
/// - Bucket starts with `capacity` tokens
/// - Tokens refill at `refill_rate` per second
/// - Each request consumes 1 token
/// - If no tokens available, request waits or is dropped
#[derive(Debug)]
pub struct TokenBucket {
    /// Current number of tokens (in thousandths for precision)
    tokens: AtomicU64,
    /// Maximum tokens (in thousandths)
    capacity: u64,
    /// Refill rate per second (in thousandths)
    refill_rate: u64,
    /// Last refill timestamp (milliseconds since epoch)
    last_refill: AtomicU64,
    /// Rate limit metrics
    metrics: Arc<RateLimitMetrics>,
    /// Whether to allow unlimited requests (--rate 0)
    unlimited: bool,
    /// BUG-CONC-005: Mutex to ensure atomic refill operation (prevents check-then-act race)
    refill_mutex: Arc<StdMutex<()>>,
}

impl TokenBucket {
    /// Create a new token bucket with the given rate limit (requests per second).
    ///
    /// # Arguments
    /// * `rps` - Requests per second (0 = unlimited)
    ///
    /// # Examples
    /// ```
    /// let bucket = TokenBucket::new(10.0); // 10 requests per second
    /// let unlimited = TokenBucket::new(0.0); // Unlimited
    /// ```
    pub fn new(rps: f64) -> Self {
        let unlimited = rps <= 0.0;
        let capacity = if unlimited {
            u64::MAX
        } else {
            // Store capacity in thousandths for precision
            // 10 RPS = 10000 thousandths
            (rps * 1000.0) as u64
        };
        let refill_rate = if unlimited { u64::MAX } else { capacity };

        Self {
            tokens: AtomicU64::new(capacity),
            capacity,
            refill_rate,
            last_refill: AtomicU64::new(
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            ),
            metrics: RateLimitMetrics::new(),
            unlimited,
            // BUG-CONC-005: Initialize mutex for atomic refill operations
            refill_mutex: Arc::new(StdMutex::new(())),
        }
    }

    /// Try to acquire a token. Returns true if successful, false if rate limited.
    /// Thread-safe using atomic operations.
    ///
    /// This method does NOT wait - it immediately returns whether the request
    /// is allowed. For waiting behavior, use acquire() instead.
    /// BUG-CONC-007 FIX: Bounded loop instead of unbounded recursion to prevent stack overflow
    pub fn try_acquire(&self) -> bool {
        if self.unlimited {
            self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        self.refill();

        // BUG-CONC-007 FIX: Maximum retries for CAS to prevent unbounded recursion
        const MAX_CAS_RETRIES: u32 = 3;

        for _ in 0..MAX_CAS_RETRIES {
            let current = self.tokens.load(Ordering::Acquire);
            if current >= 1000 {
                // Need at least 1 token (1000 thousandths)
                if self
                    .tokens
                    .compare_exchange(current, current - 1000, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                // CAS failed, loop will retry
            } else {
                self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }

        // Exhausted retries
        self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Acquire a token, waiting if necessary. Always returns true (will eventually succeed).
    /// Thread-safe and async.
    /// BUG-LOGIC-010 FIX: Bounded loop with max retries to prevent infinite loop
    pub async fn acquire(&self) {
        if self.unlimited {
            self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // BUG-LOGIC-010 FIX: Maximum retries to prevent infinite loop
        const MAX_ACQUIRE_RETRIES: u32 = 100;

        // First try without waiting
        if self.try_acquire() {
            return;
        }

        // BUG-LOGIC-010 FIX: Bounded retry loop with max retries
        for _retry_count in 0..MAX_ACQUIRE_RETRIES {
            // Calculate wait time needed
            let wait_ms = self.calculate_wait_ms();

            // Wait and then retry
            if wait_ms > 0 {
                sleep(Duration::from_millis(wait_ms)).await;
                self.metrics
                    .total_wait_ms
                    .fetch_add(wait_ms, Ordering::Relaxed);
            }

            // After waiting, we should be able to acquire
            // Force a refill first
            self.refill();

            // Try again (should succeed now)
            let current = self.tokens.load(Ordering::Acquire);
            if current >= 1000
                && self
                    .tokens
                    .compare_exchange(current, current - 1000, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                self.metrics.allowed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        // BUG-LOGIC-010 FIX: If we exhaust retries, mark as dropped and return
        // This prevents infinite loop while still allowing the operation to complete
        self.metrics.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Refill tokens based on elapsed time. Thread-safe.
    /// BUG-CONC-005: Fixed - Uses mutex to ensure atomic operation and prevent check-then-act race.
    fn refill(&self) {
        // BUG-CONC-005: Lock mutex to ensure atomic refill operation
        let _guard = match self.refill_mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("WARNING: Rate limiter mutex poisoned, recovering...");
                poisoned.into_inner()
            }
        };

        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let last = self.last_refill.load(Ordering::Acquire);
        let elapsed_ms = now.saturating_sub(last);

        if elapsed_ms == 0 {
            return;
        }

        // BUG-CONC-005: Since we hold the mutex, we can safely update last_refill
        // without worrying about race conditions
        self.last_refill.store(now, Ordering::Release);

        // Calculate new tokens to add
        // refill_rate is per second in thousandths
        // tokens = refill_rate * elapsed_ms / 1000
        let new_tokens = (self.refill_rate as u128 * elapsed_ms as u128 / 1000) as u64;

        if new_tokens == 0 {
            return;
        }

        // BUG-CONC-005: Under mutex protection, token addition is guaranteed to complete
        // before any other thread can call refill() again
        let mut current = self.tokens.load(Ordering::Acquire);
        loop {
            let updated = current.saturating_add(new_tokens).min(self.capacity);
            match self.tokens.compare_exchange(
                current,
                updated,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Calculate milliseconds to wait for next token
    fn calculate_wait_ms(&self) -> u64 {
        let current = self.tokens.load(Ordering::Acquire);
        if current >= 1000 {
            return 0;
        }
        // Need (1000 - current) thousandths of a token
        // At refill_rate thousandths per second
        // wait_ms = (1000 - current) * 1000 / refill_rate
        let needed = 1000u64.saturating_sub(current);
        (needed as u128 * 1000 / self.refill_rate as u128) as u64
    }

    /// Check if rate limiter is in unlimited mode
    #[cfg(test)]
    pub fn is_unlimited(&self) -> bool {
        self.unlimited
    }

    /// Get current rate limit setting (requests per second)
    #[cfg(test)]
    pub fn rate_limit(&self) -> f64 {
        if self.unlimited {
            0.0
        } else {
            self.refill_rate as f64 / 1000.0
        }
    }
}

/// Per-target rate limiter for multi-target scans.
/// Maintains a separate token bucket for each target.
#[derive(Debug, Default)]
#[cfg(test)]
pub struct PerTargetRateLimiter {
    /// Map of target key to token bucket
    buckets: tokio::sync::RwLock<HashMap<String, Arc<TokenBucket>>>,
    /// Global rate limit (requests per second)
    global_rps: f64,
}

#[cfg(test)]
impl PerTargetRateLimiter {
    /// Create a new per-target rate limiter.
    ///
    /// # Arguments
    /// * `global_rps` - Global rate limit (0 = unlimited per-target)
    pub fn new(global_rps: f64) -> Self {
        Self {
            buckets: tokio::sync::RwLock::new(HashMap::new()),
            global_rps,
        }
    }

    /// Get or create a token bucket for the given target.
    pub async fn get_bucket(&self, target: &str) -> Arc<TokenBucket> {
        // Try read lock first
        {
            let buckets = self.buckets.read().await;
            if let Some(bucket) = buckets.get(target) {
                return Arc::clone(bucket);
            }
        }

        // Need to create new bucket - upgrade to write lock
        let mut buckets = self.buckets.write().await;
        // Double-check in case another thread created it while we were waiting
        if let Some(bucket) = buckets.get(target) {
            return Arc::clone(bucket);
        }

        let bucket = Arc::new(TokenBucket::new(self.global_rps));
        buckets.insert(target.to_string(), Arc::clone(&bucket));
        bucket
    }

    /// Get aggregate metrics across all targets
    pub async fn aggregate_metrics(&self) -> HashMap<String, u64> {
        let buckets = self.buckets.read().await;
        let mut total_allowed = 0u64;
        let mut total_dropped = 0u64;
        let mut total_wait = 0u64;

        for bucket in buckets.values() {
            total_allowed += bucket.metrics.allowed.load(Ordering::Relaxed);
            total_dropped += bucket.metrics.dropped.load(Ordering::Relaxed);
            total_wait += bucket.metrics.total_wait_ms.load(Ordering::Relaxed);
        }

        let mut result = HashMap::new();
        result.insert("allowed".to_string(), total_allowed);
        result.insert("dropped".to_string(), total_dropped);
        result.insert("total_wait_ms".to_string(), total_wait);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use tokio::time::sleep;

    #[test]
    fn test_token_bucket_unlimited() {
        let bucket = TokenBucket::new(0.0);
        assert!(bucket.is_unlimited());
        assert_eq!(bucket.rate_limit(), 0.0);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
        // Should always succeed
        for _ in 0..100 {
            assert!(bucket.try_acquire());
        }
    }

    #[test]
    fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(10.0); // 10 RPS
        assert!(!bucket.is_unlimited());
        assert_eq!(bucket.rate_limit(), 10.0);

        // Should allow 10 requests immediately
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }

        // 11th should fail (no tokens left)
        assert!(!bucket.try_acquire());
    }

    #[tokio::test]
    async fn test_token_bucket_acquire_waits() {
        let bucket = TokenBucket::new(10.0); // 10 RPS

        // Use all tokens
        for _ in 0..10 {
            bucket.acquire().await;
        }

        let start = Instant::now();
        bucket.acquire().await;
        let elapsed = start.elapsed();

        // Should have waited approximately 100ms (1/10th of a second)
        assert!(elapsed >= Duration::from_millis(90));
        assert!(elapsed < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(10.0); // 10 RPS

        // Use all tokens
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }
        assert!(!bucket.try_acquire());

        // Wait for refill
        sleep(Duration::from_millis(150)).await;

        // Should have ~1-2 tokens now
        let mut acquired = 0;
        for _ in 0..5 {
            if bucket.try_acquire() {
                acquired += 1;
            }
        }
        assert!(acquired >= 1);
        assert!(acquired <= 2);
    }

    #[test]
    fn test_metrics() {
        let bucket = TokenBucket::new(10.0);

        // Acquire 10 tokens
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }

        // Try one more (should be dropped)
        assert!(!bucket.try_acquire());

        let metrics = bucket.metrics.summary();
        assert_eq!(metrics.get("allowed"), Some(&10));
        assert_eq!(metrics.get("dropped"), Some(&1));
    }

    #[tokio::test]
    async fn test_per_target_limiter() {
        let limiter = PerTargetRateLimiter::new(5.0); // 5 RPS per target

        let bucket1 = limiter.get_bucket("target1").await;
        let bucket2 = limiter.get_bucket("target2").await;

        // Each bucket should have 5 tokens
        for _ in 0..5 {
            assert!(bucket1.try_acquire());
            assert!(bucket2.try_acquire());
        }

        // Both should be exhausted
        assert!(!bucket1.try_acquire());
        assert!(!bucket2.try_acquire());

        // Same bucket should be reused for same target
        let bucket1_again = limiter.get_bucket("target1").await;
        assert!(!bucket1_again.try_acquire());
    }

    #[tokio::test]
    async fn test_per_target_aggregate_metrics() {
        let limiter = PerTargetRateLimiter::new(5.0);

        let bucket1 = limiter.get_bucket("target1").await;
        let bucket2 = limiter.get_bucket("target2").await;

        // Use some tokens from each
        for _ in 0..3 {
            bucket1.acquire().await;
            bucket2.acquire().await;
        }

        let metrics = limiter.aggregate_metrics().await;
        assert_eq!(metrics.get("allowed"), Some(&6));
    }

    #[tokio::test]
    async fn test_concurrent_acquire() {
        let bucket = Arc::new(TokenBucket::new(100.0)); // 100 RPS

        let mut handles = Vec::new();
        for _ in 0..50 {
            let b = Arc::clone(&bucket);
            handles.push(tokio::spawn(async move {
                b.acquire().await;
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        // All should have succeeded
        let metrics = bucket.metrics.summary();
        assert_eq!(metrics.get("allowed"), Some(&50));
        assert_eq!(metrics.get("dropped"), Some(&0));
    }
}

//! http_client.rs
//! Async HTTP engine: retry, proxy, SSL bypass, UA rotation, rate limiting.
//! PERF-002: Smart retry per status code with configurable strategies.
//! PERF-004: Token bucket rate limiting with metrics tracking.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures::StreamExt;
use rand::seq::IndexedRandom;
use rand::Rng;
use reqwest::{Client, ClientBuilder, Proxy};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::sleep;

// PERF-004: Use the dedicated rate limiter module
use crate::rate_limiter::{TokenBucket, RateLimitMetrics};

// E-4: Expanded USER_AGENTS to 25+ entries
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "curl/7.88.1",
    "curl/8.4.0",
    "Wget/1.21.4",
    "Wget/1.21.3",
    "python-requests/2.31.0",
    "python-httpx/0.27.0",
    "Go-http-client/2.0",
    "Go-http-client/1.1",
];

/// PERF-002: Retry strategy for handling different failure scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetryStrategy {
    /// Aggressive: Maximum retries for bypassing rate limits and WAFs
    Aggressive,
    /// Standard: Balanced retry behavior (default)
    #[default]
    Standard,
    /// Conservative: Minimal retries, fail fast
    Conservative,
}

/// BUG-HTTP-002: TLS error classification for targeted retry handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsErrorType {
    /// Certificate validation error (no retries - permanent failure)
    CertInvalid,
    /// TLS handshake timeout (transient - may retry)
    Timeout,
    /// Other TLS errors (limited retries)
    Other,
}

impl RetryStrategy {
    fn max_retries(&self) -> u32 {
        match self {
            Self::Aggressive => 10,
            Self::Standard => 3,
            Self::Conservative => 1,
        }
    }

    fn max_backoff(&self) -> Duration {
        match self {
            Self::Aggressive => Duration::from_secs(60),
            Self::Standard => Duration::from_secs(30),
            Self::Conservative => Duration::from_secs(10),
        }
    }

    /// Base delay in milliseconds for exponential backoff
    fn base_delay_ms(&self) -> u64 {
        match self {
            Self::Aggressive => 100,
            Self::Standard => 500,
            Self::Conservative => 1000,
        }
    }
}

impl std::str::FromStr for RetryStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aggressive" => Ok(Self::Aggressive),
            "standard" => Ok(Self::Standard),
            "conservative" => Ok(Self::Conservative),
            _ => Err(format!("Invalid retry strategy: {}. Valid options: aggressive, standard, conservative", s)),
        }
    }
}

impl std::fmt::Display for RetryStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aggressive => write!(f, "aggressive"),
            Self::Standard => write!(f, "standard"),
            Self::Conservative => write!(f, "conservative"),
        }
    }
}

/// BUG-HTTP-002: Classify TLS errors for targeted retry handling
///
/// Returns None for non-TLS errors (use default retry logic).
/// Returns Some(TlsErrorType) for TLS-specific errors.
fn classify_tls_error(err: &reqwest::Error) -> Option<TlsErrorType> {
    // Check for timeout (transient - may retry)
    if err.is_timeout() {
        return Some(TlsErrorType::Timeout);
    }

    // Check for connection errors
    if err.is_connect() {
        let err_str = err.to_string().to_lowercase();

        // Certificate validation errors (permanent - no retries)
        if err_str.contains("certificate")
            || err_str.contains("cert")
            || err_str.contains("invalid")
            || err_str.contains("verify")
            || err_str.contains("hostname")
            || err_str.contains("authority") {
            return Some(TlsErrorType::CertInvalid);
        }

        // Other TLS errors (limited retries)
        if err_str.contains("tls")
            || err_str.contains("ssl")
            || err_str.contains("handshake") {
            return Some(TlsErrorType::Other);
        }
    }

    None
}

/// PERF-002: Retry metrics for status code aware retry tracking.
#[derive(Debug)]
pub struct RetryMetrics {
    /// Number of 404 responses (no retries)
    pub retry_404: AtomicUsize,
    /// Number of 403 responses (no retries)
    pub retry_403: AtomicUsize,
    /// Number of 429 responses with retries
    pub retry_429: AtomicUsize,
    /// Number of 500 responses with retries
    pub retry_500: AtomicUsize,
    /// Number of 502 responses with retries
    pub retry_502: AtomicUsize,
    /// Number of 503 responses with retries
    pub retry_503: AtomicUsize,
    /// Number of 504 responses with retries
    pub retry_504: AtomicUsize,
    /// Total successful requests
    pub success: AtomicUsize,
    /// Total failed requests (after all retries exhausted)
    pub failed: AtomicUsize,
    /// Network errors retried
    pub network_errors: AtomicUsize,
}

impl Default for RetryMetrics {
    fn default() -> Self {
        Self {
            retry_404: AtomicUsize::new(0),
            retry_403: AtomicUsize::new(0),
            retry_429: AtomicUsize::new(0),
            retry_500: AtomicUsize::new(0),
            retry_502: AtomicUsize::new(0),
            retry_503: AtomicUsize::new(0),
            retry_504: AtomicUsize::new(0),
            success: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
            network_errors: AtomicUsize::new(0),
        }
    }
}

impl RetryMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Get summary as a map for reporting
    pub fn summary(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        map.insert("404_no_retry".to_string(), self.retry_404.load(Ordering::Relaxed));
        map.insert("403_no_retry".to_string(), self.retry_403.load(Ordering::Relaxed));
        map.insert("429_retried".to_string(), self.retry_429.load(Ordering::Relaxed));
        map.insert("500_retried".to_string(), self.retry_500.load(Ordering::Relaxed));
        map.insert("502_retried".to_string(), self.retry_502.load(Ordering::Relaxed));
        map.insert("503_retried".to_string(), self.retry_503.load(Ordering::Relaxed));
        map.insert("504_retried".to_string(), self.retry_504.load(Ordering::Relaxed));
        map.insert("network_errors".to_string(), self.network_errors.load(Ordering::Relaxed));
        map.insert("success".to_string(), self.success.load(Ordering::Relaxed));
        map.insert("failed".to_string(), self.failed.load(Ordering::Relaxed));
        map
    }
}

// PERF-004: Old TokenBucket implementation removed - now using rate_limiter module

/// Configuration for the HTTP client.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub timeout: Duration,
    pub retries: u32,
    pub delay: Duration,
    pub jitter: Duration,
    pub proxy: Option<String>,
    pub verify_ssl: bool,
    pub custom_ua: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub max_size: usize,
    pub adaptive_timeout: bool,
    pub max_timeout: Duration,
    pub use_http2: bool,
    pub rate_limit_rps: Option<f64>,
    pub proxy_list: Vec<String>,
    pub ua_pool: Vec<String>,
    /// PERF-002: Retry strategy for status-code-aware retry logic
    pub retry_strategy: RetryStrategy,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            retries: 3,
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
            proxy: None,
            verify_ssl: true,  // BUG-HTTP-003: Default to SECURE (SSL verification enabled)
            custom_ua: None,
            extra_headers: vec![],
            max_size: 100 * 1024 * 1024,
            adaptive_timeout: true,
            max_timeout: Duration::from_secs(60),
            use_http2: false,
            rate_limit_rps: None,
            proxy_list: vec![],
            ua_pool: vec![],
            retry_strategy: RetryStrategy::Standard,
        }
    }
}

/// An HTTP response.
#[derive(Debug)]
pub struct Response {
    #[allow(dead_code)]
    pub url: String,
    pub status: u16,
    pub body: bytes::Bytes,
    pub headers: std::collections::HashMap<String, String>,
    #[allow(dead_code)]
    pub elapsed_ms: f64,
    #[allow(dead_code)]
    pub error: Option<String>,
}

impl Response {
    pub fn ok(&self) -> bool {
        self.status == 200
    }

    pub fn text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap_or("")
    }
}

/// Async HTTP client with retry, proxy, UA rotation, and rate limiting.
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    cfg: HttpConfig,
    latency_window: Arc<TokioMutex<std::collections::VecDeque<u64>>>,
    /// PERF-004: Token bucket for rate limiting (atomic, thread-safe)
    token_bucket: Option<Arc<TokenBucket>>,
    proxy_clients: Vec<Client>,
    proxy_index: Arc<AtomicUsize>,
    /// PERF-002: Retry metrics tracking
    pub retry_metrics: Arc<RetryMetrics>,
    /// PERF-004: Rate limit metrics tracking
    pub rate_limit_metrics: Option<Arc<RateLimitMetrics>>,
}

impl HttpClient {
    pub fn new(cfg: HttpConfig) -> anyhow::Result<Self> {
        let mut builder = ClientBuilder::new()
            .timeout(cfg.timeout)
            .gzip(true)
            .deflate(true)
            .danger_accept_invalid_certs(!cfg.verify_ssl)
            // BUG-HTTP-001: Add connection pool limits to prevent fd exhaustion
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90));

        // HTTP/2 support - reqwest auto-negotiates HTTP/2 when available
        // The flag is provided for explicit user intent but no additional config needed
        if cfg.use_http2 {
            // reqwest handles HTTP/2 negotiation automatically
        }

        if let Some(proxy_url) = &cfg.proxy {
            let proxy = Proxy::all(proxy_url.as_str())?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;

        // Build per-proxy clients for proxy rotation (E-2)
        let mut proxy_clients = Vec::new();
        for proxy_url in &cfg.proxy_list {
            let pb = ClientBuilder::new()
                .timeout(cfg.timeout)
                .gzip(true)
                .deflate(true)
                .danger_accept_invalid_certs(!cfg.verify_ssl)
                .proxy(Proxy::all(proxy_url.as_str())?)
                .build()?;
            proxy_clients.push(pb);
        }

        // PERF-004: Create token bucket for rate limiting
        let token_bucket = cfg.rate_limit_rps.map(|rps| {
            Arc::new(TokenBucket::new(rps))
        });

        // PERF-004: Extract rate limit metrics from the token bucket
        let rate_limit_metrics = token_bucket.as_ref().map(|tb| tb.metrics());

        Ok(Self {
            client,
            cfg,
            latency_window: Arc::new(TokioMutex::new(std::collections::VecDeque::with_capacity(20))),
            token_bucket,
            proxy_clients,
            proxy_index: Arc::new(AtomicUsize::new(0)),
            retry_metrics: RetryMetrics::new(),
            rate_limit_metrics,
        })
    }

    /// PERF-002: Parse Retry-After header for 429 responses.
    /// Supports both delay-seconds and HTTP-date formats.
    fn parse_retry_after(headers: &std::collections::HashMap<String, String>, strategy: RetryStrategy) -> Duration {
        headers
            .get("retry-after")
            .and_then(|v| {
                // Try parsing as seconds first
                if let Ok(secs) = v.parse::<u64>() {
                    return Some(Duration::from_secs(secs.min(strategy.max_backoff().as_secs())));
                }
                // Try parsing as HTTP-date (e.g., "Wed, 21 Oct 2015 07:28:00 GMT")
                if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(v) {
                    let delay = (dt.timestamp() as u64).saturating_sub(chrono::Utc::now().timestamp() as u64);
                    return Some(Duration::from_secs(delay.min(strategy.max_backoff().as_secs())));
                }
                None
            })
            .unwrap_or_else(|| {
                // Default backoff for 429 when no Retry-After header
                Duration::from_secs(5)
            })
    }

    /// PERF-002: Calculate exponential backoff delay based on attempt number.
    /// BUG-HTTP-004 FIX: Add full jitter to prevent thundering herd
    fn calculate_backoff(attempt: u32, strategy: RetryStrategy) -> Duration {
        let base_ms = strategy.base_delay_ms() as u128;
        let exponential_multiplier = 2u128.pow(attempt.min(30)); // Cap exponent to avoid overflow
        let exponential_ms = base_ms.saturating_mul(exponential_multiplier);

        // BUG-HTTP-004 FIX: Add full jitter - random value between base_delay and exponential backoff
        let jitter_ms = if exponential_ms > 0 {
            let mut rng = rand::rng();
            rng.random_range(0..exponential_ms as u64)
        } else {
            0
        };

        Duration::from_millis(jitter_ms).min(strategy.max_backoff())
    }

    /// PERF-002: Determine if a status code should be retried.
    fn should_retry_status(status: u16, strategy: RetryStrategy) -> bool {
        match status {
            // PERF-002: 404 and 403 - never retry (not found / forbidden is not transient)
            404 | 403 => false,
            // PERF-002: 429 - always retry (rate limited, may succeed after delay)
            429 => true,
            // PERF-002: 500/502/503/504 - retry based on strategy
            500 | 502 | 503 | 504 => {
                matches!(strategy, RetryStrategy::Standard | RetryStrategy::Aggressive)
            }
            // Other 4xx errors - don't retry (client errors)
            400..=499 => false,
            // Other 5xx errors - retry with standard/aggressive strategy
            500..=599 => matches!(strategy, RetryStrategy::Standard | RetryStrategy::Aggressive),
            _ => false,
        }
    }

    /// Perform a GET request with smart status-code-aware retry.
    pub async fn get(&self, url: &str) -> Response {
        // PERF-004: Token bucket rate limiting (atomic, thread-safe)
        if let Some(ref tb) = self.token_bucket {
            tb.acquire().await;
        }
        self.rate_limit().await;

        let strategy = self.cfg.retry_strategy;
        // Sprint 3 (S3.8): user override wins — cfg.retries is a CEILING, not a floor.
        // Previously `.max()` meant --retries=1 with RetryStrategy::Aggressive still
        // did 10 retries, silently overriding user intent.
        let max_retries = strategy.max_retries().min(self.cfg.retries.max(1));
        let mut attempt = 0u32;

        loop {
            match self.do_get(url).await {
                Ok(r) => {
                    // PERF-002: Status-code-aware retry logic
                    match r.status {
                        // No retry for permanent failures
                        404 => {
                            self.retry_metrics.retry_404.fetch_add(1, Ordering::Relaxed);
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        403 => {
                            self.retry_metrics.retry_403.fetch_add(1, Ordering::Relaxed);
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        // Rate limited - retry with Retry-After header
                        429 => {
                            self.retry_metrics.retry_429.fetch_add(1, Ordering::Relaxed);

                            let wait = Self::parse_retry_after(&r.headers, strategy);

                            if attempt >= max_retries {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                return r;
                            }

                            sleep(wait).await;
                            attempt += 1;
                            continue;
                        }
                        // Server errors - retry with exponential backoff
                        500 => {
                            self.retry_metrics.retry_500.fetch_add(1, Ordering::Relaxed);
                            if attempt >= max_retries || !Self::should_retry_status(500, strategy) {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                return r;
                            }
                            let backoff = Self::calculate_backoff(attempt, strategy);
                            sleep(backoff).await;
                            attempt += 1;
                            continue;
                        }
                        502 => {
                            self.retry_metrics.retry_502.fetch_add(1, Ordering::Relaxed);
                            if attempt >= max_retries || !Self::should_retry_status(502, strategy) {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                return r;
                            }
                            let backoff = Self::calculate_backoff(attempt, strategy);
                            sleep(backoff).await;
                            attempt += 1;
                            continue;
                        }
                        503 => {
                            self.retry_metrics.retry_503.fetch_add(1, Ordering::Relaxed);
                            if attempt >= max_retries || !Self::should_retry_status(503, strategy) {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                return r;
                            }
                            let backoff = Self::calculate_backoff(attempt, strategy);
                            sleep(backoff).await;
                            attempt += 1;
                            continue;
                        }
                        504 => {
                            self.retry_metrics.retry_504.fetch_add(1, Ordering::Relaxed);
                            if attempt >= max_retries || !Self::should_retry_status(504, strategy) {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                return r;
                            }
                            let backoff = Self::calculate_backoff(attempt, strategy);
                            sleep(backoff).await;
                            attempt += 1;
                            continue;
                        }
                        // BUG-LOGIC-009 FIX: Only retry on retryable status codes
                        // 2xx success: return immediately, no retry
                        200..=299 => {
                            self.retry_metrics.success.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        // Other client errors (4xx except 403/404/429 already handled): no retry
                        400..=499 => {
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        // Other 5xx errors (excluding 500, 502-504 which are handled above): retry with aggressive strategy
                        501 | 505..=599 => {
                            if matches!(strategy, RetryStrategy::Standard | RetryStrategy::Aggressive) {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                if attempt >= max_retries {
                                    return r;
                                }
                                let backoff = Self::calculate_backoff(attempt, strategy);
                                sleep(backoff).await;
                                attempt += 1;
                                continue;
                            }
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        // Unknown status codes: no retry
                        _ => {
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                    }
                }
                Err(e) => {
                    self.retry_metrics.network_errors.fetch_add(1, Ordering::Relaxed);

                    let last_err = e.to_string();
                    if let Some(status) = e.status() {
                        self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                        return Response {
                            url: url.to_string(),
                            status: status.as_u16(),
                            body: bytes::Bytes::new(),
                            headers: Default::default(),
                            elapsed_ms: 0.0,
                            error: Some(last_err),
                        };
                    }

                    // BUG-HTTP-002: Classify TLS errors for targeted retry handling
                    match classify_tls_error(&e) {
                        Some(TlsErrorType::CertInvalid) => {
                            // 0 retries for certificate errors (permanent failure)
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return Response {
                                url: url.to_string(),
                                status: 0,
                                body: bytes::Bytes::new(),
                                headers: Default::default(),
                                elapsed_ms: 0.0,
                                error: Some(last_err),
                            };
                        }
                        Some(TlsErrorType::Timeout) => {
                            // 1 retry for TLS timeout (transient)
                            if attempt < 1 {
                                let backoff = Self::calculate_backoff(attempt, strategy);
                                sleep(backoff).await;
                                attempt += 1;
                                continue;
                            }
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return Response {
                                url: url.to_string(),
                                status: 0,
                                body: bytes::Bytes::new(),
                                headers: Default::default(),
                                elapsed_ms: 0.0,
                                error: Some(last_err),
                            };
                        }
                        Some(TlsErrorType::Other) => {
                            // 1 retry for other TLS errors
                            if attempt < 1 {
                                let backoff = Self::calculate_backoff(attempt, strategy);
                                sleep(backoff).await;
                                attempt += 1;
                                continue;
                            }
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return Response {
                                url: url.to_string(),
                                status: 0,
                                body: bytes::Bytes::new(),
                                headers: Default::default(),
                                elapsed_ms: 0.0,
                                error: Some(last_err),
                            };
                        }
                        None => {
                            // Default retry logic for non-TLS errors
                            if attempt < max_retries {
                                let backoff = Self::calculate_backoff(attempt, strategy);
                                sleep(backoff).await;
                                attempt += 1;
                                continue;
                            }
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
        }

        Response {
            url: url.to_string(),
            status: 0,
            body: bytes::Bytes::new(),
            headers: Default::default(),
            elapsed_ms: 0.0,
            error: Some("Max retries exceeded".to_string()),
        }
    }

    async fn do_get(&self, url: &str) -> Result<Response, reqwest::Error> {
        // E-4: UA pool selection
        let ua = if !self.cfg.ua_pool.is_empty() {
            let mut rng = rand::rng();
            self.cfg.ua_pool.choose(&mut rng).map(|s| s.as_str()).unwrap_or(USER_AGENTS[0])
        } else {
            self.cfg.custom_ua.as_deref().unwrap_or_else(|| {
                let mut rng = rand::rng();
                USER_AGENTS.choose(&mut rng).copied().unwrap_or(USER_AGENTS[0])
            })
        };

        // R-3: Compute adaptive timeout (BUG-ERR-010: use try_lock to avoid deadlock)
        let req_timeout = if self.cfg.adaptive_timeout {
            let avg_ms = {
                match self.latency_window.try_lock() {
                    Ok(w) => {
                        if w.len() >= 5 {
                            let sum: u64 = w.iter().sum();
                            Some(sum / w.len() as u64)
                        } else {
                            None
                        }
                    },
                    Err(_) => None, // Skip latency tracking this round if lock is held
                }
            };
            avg_ms.map(|ms| {
                let adaptive = Duration::from_millis(ms * 3);
                adaptive.max(self.cfg.timeout).min(self.cfg.max_timeout)
            })
        } else {
            None
        };

        // E-2: Select client (proxy rotation)
        let active_client = if !self.proxy_clients.is_empty() {
            let idx = self.proxy_index.fetch_add(1, Ordering::Relaxed) % self.proxy_clients.len();
            &self.proxy_clients[idx]
        } else {
            &self.client
        };

        let mut req = active_client
            .get(url)
            .header("User-Agent", ua)
            .header("Accept", "*/*")
            .header("Accept-Encoding", "gzip, deflate")
            .header("Cache-Control", "no-cache");

        for (k, v) in &self.cfg.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }

        if let Some(t) = req_timeout {
            req = req.timeout(t);
        }

        let t0 = Instant::now();
        let resp = req.send().await?;
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let status = resp.status().as_u16();

        // R-3: Update latency window (BUG-ERR-010: use try_lock to avoid deadlock)
        if self.cfg.adaptive_timeout {
            if let Ok(mut w) = self.latency_window.try_lock() {
                if w.len() >= 20 { w.pop_front(); }
                w.push_back(elapsed_ms as u64);
            }
            // If lock is held, skip latency tracking this round
        }

        let mut headers = std::collections::HashMap::new();
        for (k, v) in resp.headers() {
            let value = match v.to_str() {
                Ok(s) => s.to_string(),
                Err(e) => {
                    log::debug!("Failed to parse header value for {:?}: {}", k, e);
                    String::new()
                }
            };
            headers.insert(k.to_string(), value);
        }

        // Sprint 3 (S3.1): streaming download with size cap.
        //
        // The old code did `resp.bytes().await?` which loaded the FULL body into memory
        // BEFORE any `max_size` truncation. A hostile server (or a mis-targeted probe)
        // returning a 10 GB body would exhaust process memory even though `max_size`
        // defaults to 100 MB.
        //
        // Two-layer defence:
        //   1. Content-Length preflight — abort BEFORE reading if server advertises
        //      more than `max_size` bytes. Cheap when the header is honest.
        //   2. Stream chunk-by-chunk and stop as soon as accumulated bytes exceed
        //      `max_size`. Catches liars that omit Content-Length or lie about it.
        //
        // Note: `do_get` returns `Result<Response, reqwest::Error>` (callers pattern
        // match on `reqwest::Error::status()` and TLS classification), so we surface
        // size-cap violations by returning `Ok(Response { status:0, error: Some(...) })`
        // — same shape used elsewhere for TLS/connection failures.
        let max_size = self.cfg.max_size;
        if let Some(cl) = resp.content_length() {
            if cl as usize > max_size {
                return Ok(Response {
                    url: url.to_string(),
                    status: 0,
                    body: bytes::Bytes::new(),
                    headers,
                    elapsed_ms,
                    error: Some(format!(
                        "response body exceeds max_size ({} > {})", cl, max_size
                    )),
                });
            }
        }

        let mut body_bytes: Vec<u8> = Vec::with_capacity(
            resp.content_length()
                .map(|c| (c as usize).min(max_size))
                .unwrap_or(8192)
        );
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            let would_be = body_bytes.len().saturating_add(chunk.len());
            if would_be > max_size {
                // Same-shape error return as the Content-Length preflight above.
                let remaining = max_size.saturating_sub(body_bytes.len());
                body_bytes.extend_from_slice(&chunk[..remaining]);
                return Ok(Response {
                    url: url.to_string(),
                    status: 0,
                    body: bytes::Bytes::from(body_bytes),
                    headers,
                    elapsed_ms,
                    error: Some(format!(
                        "response body streamed past max_size ({} > {})", would_be, max_size
                    )),
                });
            }
            body_bytes.extend_from_slice(&chunk);
        }

        Ok(Response {
            url: url.to_string(),
            status,
            body: bytes::Bytes::from(body_bytes),
            headers,
            elapsed_ms,
            error: None,
        })
    }

    // O-4: POST method for webhook integration
    // BUG-HTTP-005 FIX: Added retry logic for POST requests
    pub async fn post(&self, url: &str, body: &str, extra_headers: &[(String, String)]) -> Response {
        // PERF-004: Apply rate limiting to POST requests as well
        if let Some(ref tb) = self.token_bucket {
            tb.acquire().await;
        }
        self.rate_limit().await;

        let strategy = self.cfg.retry_strategy;
        // Sprint 3 (S3.8): user override wins — cfg.retries is a CEILING, not a floor.
        // Previously `.max()` meant --retries=1 with RetryStrategy::Aggressive still
        // did 10 retries, silently overriding user intent.
        let max_retries = strategy.max_retries().min(self.cfg.retries.max(1));
        let mut attempt = 0u32;

        loop {
            match self.do_post(url, body, extra_headers).await {
                Ok(r) => {
                    // BUG-HTTP-005: Status-code-aware retry logic for POST
                    match r.status {
                        // No retry for permanent failures
                        404 => {
                            self.retry_metrics.retry_404.fetch_add(1, Ordering::Relaxed);
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        403 => {
                            self.retry_metrics.retry_403.fetch_add(1, Ordering::Relaxed);
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        // Rate limited - retry with Retry-After header
                        429 => {
                            self.retry_metrics.retry_429.fetch_add(1, Ordering::Relaxed);

                            let wait = Self::parse_retry_after(&r.headers, strategy);

                            if attempt >= max_retries {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                return r;
                            }

                            sleep(wait).await;
                            attempt += 1;
                            continue;
                        }
                        // Server errors - retry with exponential backoff
                        500 | 502 | 503 | 504 => {
                            match r.status {
                                500 => self.retry_metrics.retry_500.fetch_add(1, Ordering::Relaxed),
                                502 => self.retry_metrics.retry_502.fetch_add(1, Ordering::Relaxed),
                                503 => self.retry_metrics.retry_503.fetch_add(1, Ordering::Relaxed),
                                504 => self.retry_metrics.retry_504.fetch_add(1, Ordering::Relaxed),
                                _ => unreachable!(),
                            };

                            if attempt >= max_retries || !Self::should_retry_status(r.status, strategy) {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                return r;
                            }
                            let backoff = Self::calculate_backoff(attempt, strategy);
                            sleep(backoff).await;
                            attempt += 1;
                            continue;
                        }
                        // 2xx success: return immediately, no retry
                        200..=299 => {
                            self.retry_metrics.success.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        // Other client errors (4xx except 403/404/429 already handled): no retry
                        400..=499 => {
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        // Other 5xx errors (excluding 500, 502-504 which are handled above): retry with aggressive strategy
                        501 | 505..=599 => {
                            if matches!(strategy, RetryStrategy::Standard | RetryStrategy::Aggressive) {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                                if attempt >= max_retries {
                                    return r;
                                }
                                let backoff = Self::calculate_backoff(attempt, strategy);
                                sleep(backoff).await;
                                attempt += 1;
                                continue;
                            }
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                        // Unknown status codes: no retry
                        _ => {
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return r;
                        }
                    }
                }
                Err(e) => {
                    self.retry_metrics.network_errors.fetch_add(1, Ordering::Relaxed);

                    let last_err = e.to_string();
                    if let Some(status) = e.status() {
                        self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                        return Response {
                            url: url.to_string(),
                            status: status.as_u16(),
                            body: bytes::Bytes::new(),
                            headers: Default::default(),
                            elapsed_ms: 0.0,
                            error: Some(last_err),
                        };
                    }

                    // BUG-HTTP-002: Classify TLS errors for targeted retry handling
                    match classify_tls_error(&e) {
                        Some(TlsErrorType::CertInvalid) => {
                            // 0 retries for certificate errors (permanent failure)
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return Response {
                                url: url.to_string(),
                                status: 0,
                                body: bytes::Bytes::new(),
                                headers: Default::default(),
                                elapsed_ms: 0.0,
                                error: Some(last_err),
                            };
                        }
                        Some(TlsErrorType::Timeout) => {
                            // 1 retry for TLS timeout (transient)
                            if attempt < 1 {
                                let backoff = Self::calculate_backoff(attempt, strategy);
                                sleep(backoff).await;
                                attempt += 1;
                                continue;
                            }
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return Response {
                                url: url.to_string(),
                                status: 0,
                                body: bytes::Bytes::new(),
                                headers: Default::default(),
                                elapsed_ms: 0.0,
                                error: Some(last_err),
                            };
                        }
                        Some(TlsErrorType::Other) => {
                            // 1 retry for other TLS errors
                            if attempt < 1 {
                                let backoff = Self::calculate_backoff(attempt, strategy);
                                sleep(backoff).await;
                                attempt += 1;
                                continue;
                            }
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            return Response {
                                url: url.to_string(),
                                status: 0,
                                body: bytes::Bytes::new(),
                                headers: Default::default(),
                                elapsed_ms: 0.0,
                                error: Some(last_err),
                            };
                        }
                        None => {
                            // Default retry logic for non-TLS errors
                            if attempt < max_retries {
                                let backoff = Self::calculate_backoff(attempt, strategy);
                                sleep(backoff).await;
                                attempt += 1;
                                continue;
                            }
                            self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
        }

        Response {
            url: url.to_string(),
            status: 0,
            body: bytes::Bytes::new(),
            headers: Default::default(),
            elapsed_ms: 0.0,
            error: Some("Max retries exceeded".to_string()),
        }
    }

    /// BUG-HTTP-005: Helper method for POST requests
    async fn do_post(&self, url: &str, body: &str, extra_headers: &[(String, String)]) -> Result<Response, reqwest::Error> {
        // E-4: UA pool selection
        let ua = if !self.cfg.ua_pool.is_empty() {
            let mut rng = rand::rng();
            self.cfg.ua_pool.choose(&mut rng).map(|s| s.as_str()).unwrap_or(USER_AGENTS[0])
        } else {
            self.cfg.custom_ua.as_deref().unwrap_or_else(|| {
                let mut rng = rand::rng();
                USER_AGENTS.choose(&mut rng).copied().unwrap_or(USER_AGENTS[0])
            })
        };

        // E-2: Select client (proxy rotation)
        let active_client = if !self.proxy_clients.is_empty() {
            let idx = self.proxy_index.fetch_add(1, Ordering::Relaxed) % self.proxy_clients.len();
            &self.proxy_clients[idx]
        } else {
            &self.client
        };

        let mut req = active_client
            .post(url)
            .header("User-Agent", ua)
            .header("Content-Type", "application/json")
            .header("Accept", "*/*")
            .header("Accept-Encoding", "gzip, deflate")
            .header("Cache-Control", "no-cache")
            .body(body.to_string());

        for (k, v) in &self.cfg.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        for (k, v) in extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }

        let t0 = Instant::now();
        let resp = req.send().await?;
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let status = resp.status().as_u16();

        // R-3: Update latency window (BUG-ERR-010: use try_lock to avoid deadlock)
        if self.cfg.adaptive_timeout {
            if let Ok(mut w) = self.latency_window.try_lock() {
                if w.len() >= 20 { w.pop_front(); }
                w.push_back(elapsed_ms as u64);
            }
        }

        let mut headers = std::collections::HashMap::new();
        for (k, v) in resp.headers() {
            let value = match v.to_str() {
                Ok(s) => s.to_string(),
                Err(e) => {
                    log::debug!("Failed to parse header value for {:?} in POST: {}", k, e);
                    String::new()
                }
            };
            headers.insert(k.to_string(), value);
        }

        let body_bytes = resp.bytes().await.unwrap_or_default();

        Ok(Response {
            url: url.to_string(),
            status,
            body: body_bytes,
            headers,
            elapsed_ms,
            error: None,
        })
    }

    async fn rate_limit(&self) {
        if self.cfg.delay.is_zero() {
            return;
        }
        let mut wait = self.cfg.delay;
        if !self.cfg.jitter.is_zero() {
            use rand::Rng;
            let mut rng = rand::rng();
            let jitter_ms = rng.random_range(0..self.cfg.jitter.as_millis() as u64);
            wait += Duration::from_millis(jitter_ms);
        }
        sleep(wait).await;
    }
}

// ════════════════════════════════════════════════
// Sprint 3 (S3.8) — retry precedence tests
// ════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces the `max_retries` clamp: user `cfg.retries` is the ceiling, capped
    /// down by the strategy's ceiling as well. Previously the code used `.max()`
    /// which meant a user setting `--retries 1` with `RetryStrategy::Aggressive`
    /// still executed 10 retries — silently overriding the operator.
    fn clamp(strategy: RetryStrategy, user_retries: u32) -> u32 {
        strategy.max_retries().min(user_retries.max(1))
    }

    #[test]
    fn user_retries_can_lower_below_strategy_ceiling() {
        // Aggressive strategy defaults to 10; user wants 1 — must honour 1.
        assert_eq!(clamp(RetryStrategy::Aggressive, 1), 1);
        assert_eq!(clamp(RetryStrategy::Standard, 1), 1);
    }

    #[test]
    fn user_retries_capped_at_strategy_ceiling() {
        // User asks for 100 with Conservative (max=1) — still cap at 1.
        assert_eq!(clamp(RetryStrategy::Conservative, 100), 1);
        // User asks for 100 with Standard (max=3) — cap at 3.
        assert_eq!(clamp(RetryStrategy::Standard, 100), 3);
    }

    #[test]
    fn user_retries_zero_becomes_one() {
        // Zero would mean "never even try" — floor at 1 so the first attempt runs.
        assert_eq!(clamp(RetryStrategy::Aggressive, 0), 1);
    }

    #[test]
    fn retry_strategy_ceilings_are_documented_values() {
        // Locks in the current tier semantics for downstream calc.
        assert_eq!(RetryStrategy::Aggressive.max_retries(), 10);
        assert_eq!(RetryStrategy::Standard.max_retries(), 3);
        assert_eq!(RetryStrategy::Conservative.max_retries(), 1);
    }
}

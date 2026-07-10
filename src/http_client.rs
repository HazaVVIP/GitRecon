//! http_client.rs
//! Async HTTP engine: retry, proxy, SSL bypass, UA rotation, rate limiting.
//! PERF-002: Smart retry per status code with configurable strategies.
//! PERF-004: Token bucket rate limiting with metrics tracking.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use rand::seq::IndexedRandom;
use reqwest::{Client, ClientBuilder, Proxy};
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
            verify_ssl: false,
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
    latency_window: Arc<std::sync::Mutex<std::collections::VecDeque<u64>>>,
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
            .danger_accept_invalid_certs(!cfg.verify_ssl);

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
            latency_window: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::with_capacity(20))),
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
    fn calculate_backoff(attempt: u32, strategy: RetryStrategy) -> Duration {
        let base_ms = strategy.base_delay_ms() as u128;
        let exponential_multiplier = 2u128.pow(attempt.min(30)); // Cap exponent to avoid overflow
        let exponential_ms = base_ms.saturating_mul(exponential_multiplier);
        let exponential = Duration::from_millis(exponential_ms as u64);
        exponential.min(strategy.max_backoff())
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
        let max_retries = strategy.max_retries().max(self.cfg.retries);
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
                        // Success or other status codes
                        _ => {
                            if r.status >= 200 && r.status < 300 {
                                self.retry_metrics.success.fetch_add(1, Ordering::Relaxed);
                            } else {
                                self.retry_metrics.failed.fetch_add(1, Ordering::Relaxed);
                            }
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

                    // Network error - retry with exponential backoff
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

        // R-3: Compute adaptive timeout
        let req_timeout = if self.cfg.adaptive_timeout {
            let avg_ms = {
                let w = self.latency_window.lock().unwrap();
                if w.len() >= 5 {
                    let sum: u64 = w.iter().sum();
                    Some(sum / w.len() as u64)
                } else {
                    None
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

        // R-3: Update latency window
        if self.cfg.adaptive_timeout {
            let mut w = self.latency_window.lock().unwrap();
            if w.len() >= 20 { w.pop_front(); }
            w.push_back(elapsed_ms as u64);
        }

        let mut headers = std::collections::HashMap::new();
        for (k, v) in resp.headers() {
            headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
        }

        let mut body_bytes = Vec::new();
        let raw = resp.bytes().await?;
        let limit = self.cfg.max_size.min(raw.len());
        body_bytes.extend_from_slice(&raw[..limit]);

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
    pub async fn post(&self, url: &str, body: &str, extra_headers: &[(String, String)]) -> Response {
        // PERF-004: Apply rate limiting to POST requests as well
        if let Some(ref tb) = self.token_bucket {
            tb.acquire().await;
        }
        self.rate_limit().await;
        let mut req = self.client.post(url)
            .header("Content-Type", "application/json")
            .body(body.to_string());
        for (k, v) in extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let t0 = std::time::Instant::now();
        match req.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
                let mut headers = std::collections::HashMap::new();
                for (k, v) in resp.headers() {
                    headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
                }
                let body_bytes = resp.bytes().await.unwrap_or_default();
                Response { url: url.to_string(), status, body: body_bytes, headers, elapsed_ms, error: None }
            }
            Err(e) => Response {
                url: url.to_string(),
                status: 0,
                body: bytes::Bytes::new(),
                headers: Default::default(),
                elapsed_ms: 0.0,
                error: Some(e.to_string()),
            }
        }
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

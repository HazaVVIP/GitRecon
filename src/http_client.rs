//! http_client.rs
//! Async HTTP engine: retry, proxy, SSL bypass, UA rotation, rate limiting.

use std::time::{Duration, Instant};
use rand::seq::IndexedRandom;
use reqwest::{Client, ClientBuilder, Proxy};
use tokio::time::sleep;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

// E-1: Token bucket for rate limiting
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(rps: f64) -> Self {
        Self {
            tokens: rps,
            max_tokens: rps,
            refill_rate: rps / 1000.0,
            last_refill: std::time::Instant::now(),
        }
    }

    async fn consume(&mut self) {
        let now = std::time::Instant::now();
        let elapsed_ms = now.duration_since(self.last_refill).as_millis() as f64;
        self.tokens = (self.tokens + self.refill_rate * elapsed_ms).min(self.max_tokens);
        self.last_refill = now;
        
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
        } else {
            let wait_ms = ((1.0 - self.tokens) / self.refill_rate) as u64;
            sleep(Duration::from_millis(wait_ms)).await;
            self.tokens = 0.0;
        }
    }
}

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
    token_bucket: Option<Arc<tokio::sync::Mutex<TokenBucket>>>,
    proxy_clients: Vec<Client>,
    proxy_index: Arc<AtomicUsize>,
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

        let token_bucket = cfg.rate_limit_rps.map(|rps| {
            Arc::new(tokio::sync::Mutex::new(TokenBucket::new(rps)))
        });

        Ok(Self {
            client,
            cfg,
            latency_window: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::with_capacity(20))),
            token_bucket,
            proxy_clients,
            proxy_index: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Perform a GET request with retry and rate limiting.
    pub async fn get(&self, url: &str) -> Response {
        // Token bucket rate limiting (E-1)
        if let Some(ref tb) = self.token_bucket {
            tb.lock().await.consume().await;
        }
        self.rate_limit().await;

#[allow(unused_assignments)]
        let mut last_err = String::new();
        let max_retries = self.cfg.retries;
        let mut attempt = 0u32;

        loop {
            match self.do_get(url).await {
                Ok(r) => {
                    // R-2: Smart retry per HTTP status code
                    if r.status == 404 || r.status == 403 {
                        return r;
                    }
                    if r.status == 429 {
                        let wait_secs = r.headers.get("retry-after")
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(5)
                            .min(30);
                        sleep(Duration::from_secs(wait_secs)).await;
                        attempt += 1;
                        if attempt >= max_retries { return r; }
                        continue;
                    }
                    return r;
                }
                Err(e) => {
                    last_err = e.to_string();
                    if let Some(status) = e.status() {
                        return Response {
                            url: url.to_string(),
                            status: status.as_u16(),
                            body: bytes::Bytes::new(),
                            headers: Default::default(),
                            elapsed_ms: 0.0,
                            error: Some(last_err),
                        };
                    }
                    if attempt < max_retries - 1 {
                        let backoff = Duration::from_millis(500 * 2u64.pow(attempt)).min(Duration::from_secs(30));
                        sleep(backoff).await;
                    }
                    attempt += 1;
                    if attempt >= max_retries { break; }
                }
            }
        }

        Response {
            url: url.to_string(),
            status: 0,
            body: bytes::Bytes::new(),
            headers: Default::default(),
            elapsed_ms: 0.0,
            error: Some(last_err),
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

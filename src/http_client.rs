//! http_client.rs
//! Async HTTP engine: retry, proxy, SSL bypass, UA rotation, rate limiting.

use std::time::{Duration, Instant};
use rand::seq::IndexedRandom;
use reqwest::{Client, ClientBuilder, Proxy};
use tokio::time::sleep;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
     (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
];

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
            max_size: 100 * 1024 * 1024, // 100 MB
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
}

impl HttpClient {
    pub fn new(cfg: HttpConfig) -> anyhow::Result<Self> {
        let mut builder = ClientBuilder::new()
            .timeout(cfg.timeout)
            .gzip(true)
            .deflate(true)
            .danger_accept_invalid_certs(!cfg.verify_ssl);

        if let Some(proxy_url) = &cfg.proxy {
            let proxy = Proxy::all(proxy_url.as_str())?;
            builder = builder.proxy(proxy);
        }

        let client = builder.build()?;
        Ok(Self { client, cfg })
    }

    /// Perform a GET request with retry and rate limiting.
    pub async fn get(&self, url: &str) -> Response {
        self.rate_limit().await;

        let mut last_err = String::new();
        for attempt in 0..self.cfg.retries {
            match self.do_get(url).await {
                Ok(r) => return r,
                Err(e) => {
                    last_err = e.to_string();
                    // Check if it's an HTTP error with status code
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
                    if attempt < self.cfg.retries - 1 {
                        let backoff = Duration::from_millis(500 * 2u64.pow(attempt));
                        sleep(backoff).await;
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
            error: Some(last_err),
        }
    }

    async fn do_get(&self, url: &str) -> Result<Response, reqwest::Error> {
        let ua = self
            .cfg
            .custom_ua
            .as_deref()
            .unwrap_or_else(|| {
                let mut rng = rand::rng();
                USER_AGENTS.choose(&mut rng).copied().unwrap_or(USER_AGENTS[0])
            });

        let mut req = self
            .client
            .get(url)
            .header("User-Agent", ua)
            .header("Accept", "*/*")
            .header("Accept-Encoding", "gzip, deflate")
            .header("Cache-Control", "no-cache");

        for (k, v) in &self.cfg.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }

        let t0 = Instant::now();
        let resp = req.send().await?;
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        let status = resp.status().as_u16();

        let mut headers = std::collections::HashMap::new();
        for (k, v) in resp.headers() {
            headers.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
        }

        // Read body with max_size limit
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

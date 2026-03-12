//! detect.rs
//! Phase 1 — Detect whether .git/ is exposed.
//! Output: DetectResult with confidence 0–100 and early metadata.

use crate::http_client::HttpClient;
use crate::git_parser::{parse_head, GitConfigParser, PackedRefsParser};

// Probe: (path, weight)
// Verifier is applied to the response body.
type Verifier = fn(&[u8]) -> bool;

const PROBES: &[(&str, Verifier, u32)] = &[
    ("HEAD",           |b| b.windows(9).any(|w| w == b"ref: refs") || (b.len() >= 40 && b[..40].iter().all(|&c| c.is_ascii_hexdigit())), 40),
    ("config",         |b| b.windows(6).any(|w| w == b"[core]"),  30),
    ("packed-refs",    |b| b.iter().any(|&c| c.is_ascii_hexdigit()), 15),
    ("index",          |b| b.len() >= 4 && &b[..4] == b"DIRC",    20),
    ("logs/HEAD",      |b| b.iter().any(|&c| c.is_ascii_hexdigit()), 10),
    ("COMMIT_EDITMSG", |b| !b.trim_ascii().is_empty(),              5),
];

const TOTAL_WEIGHT: u32 = 40 + 30 + 15 + 20 + 10 + 5;

// Non-root .git locations
const PATH_VARIANTS: &[&str] = &[
    ".git",
    "api/.git", "v1/.git", "v2/.git", "v3/.git",
    "admin/.git", "backend/.git", "app/.git",
    "web/.git", "www/.git", "public/.git",
    "src/.git", "portal/.git", "wp-content/.git",
];

#[derive(Debug, Clone)]
pub struct ProbeDetail {
    pub path: String,
    pub status: u16,
    pub accessible: bool,
    pub valid: bool,
}

#[derive(Debug, Clone)]
pub struct DetectResult {
    pub url: String,
    pub git_url: String,
    pub confidence: u32,
    pub label: String,
    pub listing: bool,
    pub server: String,
    pub branch: Option<String>,
    pub remote_url: Option<String>,
    pub head_sha1: Option<String>,
    pub probes: Vec<ProbeDetail>,
}

impl DetectResult {
    pub fn actionable(&self) -> bool {
        self.confidence >= 45
    }
}

fn label(score: u32) -> &'static str {
    match score {
        90..=100 => "CONFIRMED",
        70..=89  => "HIGH",
        45..=69  => "MEDIUM",
        20..=44  => "LOW",
        _        => "NONE",
    }
}

async fn detect_server(client: &HttpClient, url: &str) -> String {
    let r = client.get(url).await;
    if !r.ok() {
        return "Unknown".to_string();
    }
    let sv = format!(
        "{} {}",
        r.headers.get("server").map(|s| s.as_str()).unwrap_or(""),
        r.headers.get("x-powered-by").map(|s| s.as_str()).unwrap_or(""),
    ).to_lowercase();

    if r.headers.keys().any(|k| k.to_lowercase() == "cf-ray") {
        return "Cloudflare".to_string();
    }
    let servers = [
        ("Nginx",      &["nginx"][..]),
        ("Apache",     &["apache"][..]),
        ("Caddy",      &["caddy"][..]),
        ("IIS",        &["microsoft-iis"][..]),
        ("LiteSpeed",  &["litespeed"][..]),
        ("Cloudflare", &["cloudflare"][..]),
        ("Vercel",     &["vercel"][..]),
        ("Netlify",    &["netlify"][..]),
    ];
    for (name, pats) in &servers {
        if pats.iter().any(|p| sv.contains(p)) {
            return name.to_string();
        }
    }
    "Unknown".to_string()
}

async fn check_listing(client: &HttpClient, git_url: &str) -> bool {
    let url = format!("{}/", git_url);
    let r = client.get(&url).await;
    let resp = if r.ok() { r } else { client.get(git_url).await };
    if !resp.ok() {
        return false;
    }
    let t = resp.text().to_lowercase();
    ["index of", "parent directory", "href=\"head\"", "href=\"config\"",
     "href=\"objects/\"", "directory listing"]
        .iter()
        .any(|kw| t.contains(kw))
}

async fn probe_one_path(
    client: &HttpClient,
    base_url: &str,
    git_path: &str,
) -> Option<DetectResult> {
    let git_url = format!("{}/{}", base_url, git_path);
    let mut earned = 0u32;
    let mut details = Vec::new();

    let cfg_parser  = GitConfigParser;
    let _refs_parser = PackedRefsParser;

    let mut branch: Option<String>     = None;
    let mut remote_url: Option<String> = None;
    let mut head_sha1: Option<String>  = None;

    for &(path, verify, weight) in PROBES {
        let url  = format!("{}/{}", git_url, path);
        let resp = client.get(&url).await;
        let ok   = resp.ok();
        let mut valid = false;

        if ok {
            valid = verify(&resp.body);
            if valid {
                earned += weight;
            }

            if path == "HEAD" && valid {
                let h = parse_head(resp.text());
                branch    = h.get("branch").cloned();
                head_sha1 = h.get("sha1").cloned();
            } else if path == "config" && valid {
                let cfg    = cfg_parser.parse(resp.text());
                let remotes = cfg_parser.remote_urls(&cfg);
                if let Some(first) = remotes.first() {
                    remote_url = first.get("url").cloned();
                }
            }
        }

        details.push(ProbeDetail {
            path: path.to_string(),
            status: resp.status,
            accessible: ok,
            valid,
        });

        // Fast-fail: if HEAD is not accessible this path is invalid
        if path == "HEAD" && !ok {
            return None;
        }
    }

    let score = ((earned as f64 / TOTAL_WEIGHT as f64) * 100.0) as u32;
    let score = score.min(100);

    let server  = detect_server(client, base_url).await;
    let listing = if score >= 20 { check_listing(client, &git_url).await } else { false };

    Some(DetectResult {
        url: base_url.to_string(),
        git_url,
        confidence: score,
        label: label(score).to_string(),
        listing,
        server,
        branch,
        remote_url,
        head_sha1,
        probes: details,
    })
}

/// Probe target and return the best DetectResult.
/// Returns None if no exposure detected.
pub async fn run(
    client: &HttpClient,
    base_url: &str,
    fuzz: bool,
) -> Option<DetectResult> {
    let base_url    = base_url.trim_end_matches('/');
    let candidates  = if fuzz { PATH_VARIANTS } else { &PATH_VARIANTS[..1] };
    let mut best: Option<DetectResult> = None;

    for &git_path in candidates {
        let result = probe_one_path(client, base_url, git_path).await;
        if let Some(r) = result {
            let better = best.as_ref().map_or(true, |b: &DetectResult| r.confidence > b.confidence);
            if better {
                let confirmed = r.label == "CONFIRMED";
                best = Some(r);
                if confirmed {
                    break;
                }
            }
        }
    }

    best.filter(|b| b.confidence >= 20)
}

//! detect.rs
//! Phase 1 — Detect whether .git/ is exposed.
//! Output: DetectResult with confidence 0–100 and early metadata.

use crate::http_client::HttpClient;
use crate::git_parser::{parse_head, GitConfigParser, PackedRefsParser};

// Probe: (path, weight)
// Verifier is applied to the response body.
type Verifier = fn(&[u8]) -> bool;

const PROBES: &[(&str, Verifier, u32)] = &[
    ("HEAD",              |b| b.windows(9).any(|w| w == b"ref: refs") || (b.len() >= 40 && b[..40].iter().all(|&c| c.is_ascii_hexdigit())), 40),
    ("config",            |b| b.windows(6).any(|w| w == b"[core]"),  30),
    // packed-refs: valid format has a line with 40 hex chars followed by ' refs/'
    ("packed-refs",       |b| b.windows(46).any(|w| {
        w[..40].iter().all(|&c| c.is_ascii_hexdigit()) && w[40] == b' ' && &w[41..46] == b"refs/"
    }), 15),
    ("index",             |b| b.len() >= 4 && &b[..4] == b"DIRC",    20),
    // logs/HEAD: valid format has two consecutive 40-char hex SHA1s separated by a space
    ("logs/HEAD",         |b| b.windows(82).any(|w| {
        w[..40].iter().all(|&c| c.is_ascii_hexdigit())
            && w[40] == b' '
            && w[41..81].iter().all(|&c| c.is_ascii_hexdigit())
    }), 10),
    ("COMMIT_EDITMSG",    |b| !b.trim_ascii().is_empty(),              5),
    // Objects tree confirms readable object storage — strongest corroboration after HEAD
    ("objects/info/packs",|b| b.windows(2).any(|w| w == b"P "),      10),
];

const TOTAL_WEIGHT: u32 = 40 + 30 + 15 + 20 + 10 + 5 + 10;

// Non-root .git locations
const PATH_VARIANTS: &[&str] = &[
    ".git",
    // API versioned paths
    "api/.git", "v1/.git", "v2/.git", "v3/.git",
    "api/v1/.git", "api/v2/.git",
    // Common subdirectory layouts
    "admin/.git", "backend/.git", "app/.git",
    "web/.git", "www/.git", "public/.git",
    "src/.git", "portal/.git", "wp-content/.git",
    "frontend/.git", "server/.git", "client/.git",
    "core/.git", "libs/.git", "service/.git",
    "mobile/.git", "static/.git", "uploads/.git",
    "storage/.git", "dashboard/.git",
    // Azure DevOps bare-repo style
    "_git",
    "git",
    // Build output paths
    "dist/.git", "build/.git", "assets/.git",
    "website/.git", "cms/.git",
    // Backup / typo exposures
    ".git.bak", ".git.old",
    // Numeric versioned roots
    "v4/.git", "v5/.git",
    // Framework-specific paths (gitdumper parity)
    "laravel/.git", "symfony/.git", "django/.git",
    "rails/.git", "express/.git", "flask/.git",
    "nextjs/.git", "nuxt/.git",
    // Environment / deployment paths
    "staging/.git", "test/.git", "dev/.git",
    "internal/.git", "demo/.git", "sandbox/.git",
    "preview/.git", "release/.git",
    // Documentation / auxiliary
    "docs/.git", "doc/.git", "wiki/.git",
    "blog/.git", "landing/.git",
    // Nested project structures
    "packages/.git", "modules/.git", "services/.git",
    "microservices/.git",
];

/// Minimum confidence score to report a DetectResult.
const MIN_CONFIDENCE: u32 = 20;

/// A 403 on HEAD means the path exists but the server is blocking directory traversal.
/// We report this as a low-confidence result so the operator knows the endpoint exists.
const PROTECTED_CONFIDENCE: u32 = 25;
const PROTECTED_LABEL: &str = "PROTECTED";

fn is_accessible_status(status: u16) -> bool {
    (200..300).contains(&status)
}

#[derive(Debug, Clone)]
pub struct ProbeDetail {
    #[allow(dead_code)]
    pub path: String,
    #[allow(dead_code)]
    pub status: u16,
    #[allow(dead_code)]
    pub accessible: bool,
    #[allow(dead_code)]
    pub valid: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DetectResult {
    pub url: String,
    pub git_url: String,
    pub confidence: u32,
    pub label: String,
    pub listing: bool,
    pub server: String,
    pub branch: Option<String>,
    pub remote_url: Option<String>,
    #[allow(dead_code)]
    pub head_sha1: Option<String>,
    #[allow(dead_code)]
    pub probes: Vec<ProbeDetail>,
}

impl DetectResult {
    #[allow(dead_code)]
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
        ("Gunicorn",   &["gunicorn"][..]),
        ("PHP",        &["php"][..]),
        ("OpenResty",  &["openresty"][..]),
        ("Traefik",    &["traefik"][..]),
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
    let resp = if is_accessible_status(r.status) { r } else { client.get(git_url).await };
    if !is_accessible_status(resp.status) {
        return false;
    }
    let t = resp.text().to_lowercase();
    ["index of", "parent directory", "href=\"head\"", "href=\"config\"",
     "href=\"objects/\"", "directory listing", "\"head\"", "\"config\"",
     ">objects/<", ">packed-refs<"]
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
        let ok   = is_accessible_status(resp.status);
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

        // Fast-fail: if HEAD returns 404/0, this path doesn't exist.
        // A 403 on HEAD means the directory exists but is access-controlled — report it.
        if path == "HEAD" && !ok {
            if resp.status == 403 {
                // .git exists but is protected — still worth reporting
                let server  = detect_server(client, base_url).await;
                let listing = false;
                return Some(DetectResult {
                    url: base_url.to_string(),
                    git_url,
                    confidence: PROTECTED_CONFIDENCE,
                    label: PROTECTED_LABEL.to_string(),
                    listing,
                    server,
                    branch: None,
                    remote_url: None,
                    head_sha1: None,
                    probes: details,
                });
            }
            return None;
        }
    }

    let score = ((earned as f64 / TOTAL_WEIGHT as f64) * 100.0) as u32;
    let score = score.min(100);

    let server  = detect_server(client, base_url).await;
    let listing = if score >= MIN_CONFIDENCE { check_listing(client, &git_url).await } else { false };

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
    let base_url = base_url.trim_end_matches('/');

    if !fuzz {
        // Fast path: only check the default `.git` location
        return probe_one_path(client, base_url, ".git").await
            .filter(|b| b.confidence >= MIN_CONFIDENCE);
    }

    // Fuzz mode: probe all path variants concurrently for speed.
    // We launch all tasks at once and collect results as they complete,
    // stopping early if a CONFIRMED result (≥ 90%) is found.
    let mut handles = Vec::new();
    for &git_path in PATH_VARIANTS {
        let client = client.clone();
        let base_url = base_url.to_string();
        let git_path = git_path.to_string();
        handles.push(tokio::spawn(async move {
            probe_one_path(&client, &base_url, &git_path).await
        }));
    }

    let mut best: Option<DetectResult> = None;
    for h in handles {
        if let Ok(Some(r)) = h.await {
            let better = best.as_ref().is_none_or(|b: &DetectResult| r.confidence > b.confidence);
            if better {
                let confirmed = r.confidence >= 90;
                best = Some(r);
                // Early exit: no need to wait for remaining tasks once we have a CONFIRMED result
                if confirmed {
                    break;
                }
            }
        }
    }

    best.filter(|b| b.confidence >= MIN_CONFIDENCE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_variants_contains_default() {
        assert!(PATH_VARIANTS.contains(&".git"), "Default .git path must be present");
    }

    #[test]
    fn test_path_variants_contains_backup_paths() {
        assert!(PATH_VARIANTS.contains(&".git.bak"), ".git.bak must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&".git.old"), ".git.old must be in PATH_VARIANTS");
    }

    #[test]
    fn test_path_variants_contains_azure_devops_path() {
        assert!(PATH_VARIANTS.contains(&"_git"), "_git (Azure DevOps) must be in PATH_VARIANTS");
    }

    #[test]
    fn test_path_variants_contains_dist_build() {
        assert!(PATH_VARIANTS.contains(&"dist/.git"), "dist/.git must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"build/.git"), "build/.git must be in PATH_VARIANTS");
    }

    #[test]
    fn test_path_variants_contains_api_versioned() {
        assert!(PATH_VARIANTS.contains(&"api/v1/.git"), "api/v1/.git must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"api/v2/.git"), "api/v2/.git must be in PATH_VARIANTS");
    }

    #[test]
    fn test_path_variants_contains_common_subdirs() {
        assert!(PATH_VARIANTS.contains(&"frontend/.git"), "frontend/.git must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"server/.git"),   "server/.git must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"client/.git"),   "client/.git must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"mobile/.git"),   "mobile/.git must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"static/.git"),   "static/.git must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"uploads/.git"),  "uploads/.git must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"storage/.git"),  "storage/.git must be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"dashboard/.git"),"dashboard/.git must be in PATH_VARIANTS");
    }

    #[test]
    fn test_probes_contains_objects_info_packs() {
        assert!(
            PROBES.iter().any(|(p, _, _)| *p == "objects/info/packs"),
            "PROBES must include objects/info/packs for pack file discovery"
        );
    }

    #[test]
    fn test_total_weight_matches_probe_sum() {
        let computed: u32 = PROBES.iter().map(|(_, _, w)| w).sum();
        assert_eq!(computed, TOTAL_WEIGHT, "TOTAL_WEIGHT must equal sum of probe weights");
    }

    #[test]
    fn test_label_thresholds() {
        assert_eq!(label(100), "CONFIRMED");
        assert_eq!(label(90),  "CONFIRMED");
        assert_eq!(label(89),  "HIGH");
        assert_eq!(label(45),  "MEDIUM");
        assert_eq!(label(20),  "LOW");
        assert_eq!(label(10),  "NONE");
    }

    #[test]
    fn test_packed_refs_verifier_accepts_valid_format() {
        // Valid packed-refs line: 40-char SHA1 followed by ' refs/heads/main'
        let valid = b"abc123def456abc123def456abc123def456abc1 refs/heads/main\n";
        let verifier = PROBES.iter().find(|(p, _, _)| *p == "packed-refs").map(|(_, v, _)| v).unwrap();
        assert!(verifier(valid), "packed-refs verifier must accept a properly formatted file");
    }

    #[test]
    fn test_packed_refs_verifier_rejects_plain_hex() {
        // A file that merely contains hex digits (no valid packed-refs line) must NOT match
        let not_packed = b"just some hex digits: abcdef1234567890\n";
        let verifier = PROBES.iter().find(|(p, _, _)| *p == "packed-refs").map(|(_, v, _)| v).unwrap();
        assert!(!verifier(not_packed), "packed-refs verifier must reject a file with only stray hex chars");
    }

    #[test]
    fn test_logs_head_verifier_accepts_valid_format() {
        // Valid git log line: old-SHA1 <space> new-SHA1
        let old_sha = "0000000000000000000000000000000000000000";
        let new_sha = "abc123def456abc123def456abc123def456abc1";
        let valid = format!("{} {} Author <a@b.com> 1234567890 +0000\tCommit\n", old_sha, new_sha);
        let verifier = PROBES.iter().find(|(p, _, _)| *p == "logs/HEAD").map(|(_, v, _)| v).unwrap();
        assert!(verifier(valid.as_bytes()), "logs/HEAD verifier must accept a properly formatted log line");
    }

    #[test]
    fn test_logs_head_verifier_rejects_plain_hex() {
        // A file with only stray hex digits must NOT match
        let not_log = b"just some hex: abcdef1234567890\n";
        let verifier = PROBES.iter().find(|(p, _, _)| *p == "logs/HEAD").map(|(_, v, _)| v).unwrap();
        assert!(!verifier(not_log), "logs/HEAD verifier must reject a file with only stray hex chars");
    }

    #[test]
    fn test_protected_confidence_is_above_min() {
        assert!(
            PROTECTED_CONFIDENCE >= MIN_CONFIDENCE,
            "PROTECTED_CONFIDENCE must be at least MIN_CONFIDENCE so protected results are reported"
        );
    }

    #[test]
    fn test_is_accessible_status_accepts_all_2xx() {
        assert!(is_accessible_status(200));
        assert!(is_accessible_status(204));
        assert!(is_accessible_status(206));
        assert!(is_accessible_status(299));
        assert!(!is_accessible_status(301));
        assert!(!is_accessible_status(403));
    }

    // ── V3.1 fuzz path tests ──────────────────────

    #[test]
    fn test_path_variants_contains_framework_paths() {
        assert!(PATH_VARIANTS.contains(&"laravel/.git"), "laravel/.git should be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"django/.git"), "django/.git should be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"rails/.git"), "rails/.git should be in PATH_VARIANTS");
    }

    #[test]
    fn test_path_variants_contains_env_paths() {
        assert!(PATH_VARIANTS.contains(&"staging/.git"), "staging/.git should be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"demo/.git"), "demo/.git should be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"sandbox/.git"), "sandbox/.git should be in PATH_VARIANTS");
    }

    #[test]
    fn test_path_variants_contains_nested_paths() {
        assert!(PATH_VARIANTS.contains(&"packages/.git"), "packages/.git should be in PATH_VARIANTS");
        assert!(PATH_VARIANTS.contains(&"services/.git"), "services/.git should be in PATH_VARIANTS");
    }
}

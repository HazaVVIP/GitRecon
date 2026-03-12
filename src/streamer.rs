//! streamer.rs
//! Phase 3 — Stream & Scan: fetch every object, scan for secrets in memory,
//! discard object after scan.  NO writes to disk.
//! Output: StreamResult with all findings + intel.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use regex::Regex;
use lazy_static::lazy_static;
use futures::StreamExt;

use crate::http_client::HttpClient;
use crate::git_parser::{ObjectParser, obj_path};
use crate::mapper::MapResult;

// ════════════════════════════════════════════════
// SECRET PATTERNS
// ════════════════════════════════════════════════

struct Pattern {
    id:    &'static str,
    sev:   &'static str,
    desc:  &'static str,
    regex: Regex,
}

macro_rules! pat {
    ($id:expr, $sev:expr, $desc:expr, $rx:expr) => {
        Pattern {
            id:   $id,
            sev:  $sev,
            desc: $desc,
            regex: Regex::new($rx).expect(concat!("bad regex: ", $rx)),
        }
    };
}

lazy_static! {
    static ref PATTERNS: Vec<Pattern> = vec![
        // Cloud
        pat!("aws_key_id",  "CRITICAL", "AWS Access Key ID",
             r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"),
        pat!("aws_secret",  "CRITICAL", "AWS Secret Access Key",
             r#"(?i)aws[_\-\s]?secret[_\-\s]?[a-z]*\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#),
        pat!("gcp_sa",      "CRITICAL", "GCP Service Account",
             r#""type"\s*:\s*"service_account""#),
        pat!("azure_conn",  "CRITICAL", "Azure Storage Connection String",
             r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
        // VCS tokens
        pat!("github_pat",   "CRITICAL", "GitHub Personal Access Token",
             r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
        pat!("github_oauth", "CRITICAL", "GitHub OAuth Token",
             r"gho_[A-Za-z0-9]{36}"),
        pat!("github_app",   "CRITICAL", "GitHub App Token",
             r"(ghu|ghs)_[A-Za-z0-9]{36}"),
        pat!("gitlab_pat",   "CRITICAL", "GitLab PAT",
             r"glpat-[A-Za-z0-9\-_]{20}"),
        // Payment
        pat!("stripe_sk", "CRITICAL", "Stripe Secret Key",
             r"sk_(live|test)_[A-Za-z0-9]{24,}"),
        pat!("stripe_pk", "HIGH",     "Stripe Publishable Key",
             r"pk_(live|test)_[A-Za-z0-9]{24,}"),
        // Messaging
        pat!("slack_token",   "HIGH", "Slack Token",
             r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"),
        pat!("slack_webhook", "HIGH", "Slack Webhook",
             r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        pat!("discord_token", "HIGH", "Discord Bot Token",
             r#"(?i)discord[_\-\s]?token\s*[=:]\s*['"]?([A-Za-z0-9._-]{59,})['"]?"#),
        pat!("telegram_bot",  "HIGH", "Telegram Bot Token",
             r"\d{8,10}:[A-Za-z0-9_-]{35}"),
        pat!("sendgrid",      "HIGH", "SendGrid API Key",
             r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        pat!("twilio",        "HIGH", "Twilio API Key",
             r"SK[0-9a-f]{32}"),
        pat!("mailgun",       "HIGH", "Mailgun Key",
             r"key-[0-9a-f]{32}"),
        // Database
        pat!("db_url",      "CRITICAL", "Database Connection URL",
             r"(?i)(mysql|postgres|postgresql|mongodb|redis|mssql|oracle)://[^:@\s]+:[^@\s]+@[^\s]+"),
        pat!("db_password", "CRITICAL", "Database Password",
             r#"(?i)db[_\-]?(pass(word)?|pwd)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?"#),
        // Keys
        pat!("private_key", "CRITICAL", "Private Key",
             r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----"),
        pat!("pgp_key",     "CRITICAL", "PGP Private Key",
             r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        // JWT
        pat!("jwt",        "HIGH",     "JWT Token",
             r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        pat!("jwt_secret", "CRITICAL", "JWT Secret",
             r#"(?i)jwt[_\-]?secret\s*[=:]\s*['"]?([^\s'"]{16,})['"]?"#),
        // Generic
        pat!("api_key",      "HIGH", "Generic API Key",
             r#"(?i)api[_\-\s]?key\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#),
        pat!("secret_key",   "HIGH", "Generic Secret Key",
             r#"(?i)secret[_\-\s]?key\s*[=:]\s*['"]?([A-Za-z0-9_\-!@#$]{16,})['"]?"#),
        pat!("access_token", "HIGH", "Access Token",
             r#"(?i)access[_\-\s]?token\s*[=:]\s*['"]?([A-Za-z0-9_\-\.]{20,})['"]?"#),
        // Password
        pat!("hardcoded_pass", "HIGH", "Hardcoded Password",
             r#"(?i)(password|passwd|pass|pwd)\s*[=:]\s*['"]([^'"\s]{8,})['"]"#),
        pat!("env_pass",       "HIGH", "Env Password Variable",
             r"(?m)^[A-Z_]*PASS(?:WORD)?[A-Z_]*\s*=\s*([^\s].+)$"),
        // Network
        pat!("private_ip", "MEDIUM", "Private IP Address",
             r"(?:^|[^0-9])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)"),
        // Cloud storage
        pat!("s3_url", "MEDIUM", "S3 Bucket URL",
             r"https?://[a-z0-9\-\.]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com"),
        // Misc
        pat!("firebase_fcm", "HIGH", "Firebase FCM Key",
             r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
        pat!("npm_token",    "HIGH", "NPM Token",
             r"(?:^|[^a-z])npm_[A-Za-z0-9]{36}"),
        pat!("docker_pat",   "HIGH", "Docker Hub PAT",
             r"dckr_pat_[A-Za-z0-9_-]{27}"),
        pat!("oauth_secret", "HIGH", "OAuth Client Secret",
             r#"(?i)client[_\-]?secret\s*[=:]\s*['"]?([A-Za-z0-9_\-]{16,})['"]?"#),
    ];

    static ref PLACEHOLDERS: Vec<&'static str> = vec![
        "your_", "YOUR_", "example", "EXAMPLE", "placeholder",
        "xxxx", "XXXX", "changeme", "CHANGE_ME", "insert_",
        "TODO", "FIXME", "test_", "TEST_", "dummy", "DUMMY",
        "replace", "REPLACE", "sample", "SAMPLE", "fake", "FAKE",
        "00000000", "11111111", "<", ">",
    ];

    static ref SENSITIVE_NAMES: Regex = Regex::new(
        r#"(?i)(\.env|\.env\.|config\.php|wp-config|database\.php|settings\.py|config\.ya?ml|credentials|secrets?\.json|service.account|\.npmrc|\.pypirc|\.netrc|id_rsa|id_ed25519|\.pem|\.key|\.pfx|\.p12|application\.(properties|ya?ml)|docker.compose|\.travis\.yml|\.circleci)"#
    ).unwrap();

    static ref ENTROPY_TOKEN_RE: Regex =
        Regex::new(r#"['"]([A-Za-z0-9+/=_\-]{24,})['"]"#).unwrap();
}

// ════════════════════════════════════════════════
// TECH STACK
// ════════════════════════════════════════════════

lazy_static! {
    static ref TECH_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("Python",     Regex::new(r"requirements\.txt|setup\.py|Pipfile|pyproject\.toml|manage\.py").unwrap()),
        ("Node.js",    Regex::new(r"package\.json|yarn\.lock|package-lock\.json").unwrap()),
        ("PHP",        Regex::new(r"composer\.json|composer\.lock|\.php$").unwrap()),
        ("Ruby",       Regex::new(r"Gemfile|\.ruby-version|\.rb$").unwrap()),
        ("Java",       Regex::new(r"pom\.xml|build\.gradle|\.java$").unwrap()),
        ("Go",         Regex::new(r"go\.mod|go\.sum|\.go$").unwrap()),
        ("Rust",       Regex::new(r"Cargo\.toml|Cargo\.lock|\.rs$").unwrap()),
        (".NET",       Regex::new(r"\.csproj|\.sln|web\.config").unwrap()),
        ("Docker",     Regex::new(r"Dockerfile|docker-compose").unwrap()),
        ("Kubernetes", Regex::new(r"kubectl|\.yaml$").unwrap()),
        ("Terraform",  Regex::new(r"\.tf$|terraform\.tfvars").unwrap()),
        ("WordPress",  Regex::new(r"wp-config|wp-content").unwrap()),
        ("Django",     Regex::new(r"manage\.py|settings\.py|wsgi\.py").unwrap()),
        ("Laravel",    Regex::new(r"artisan|\.blade\.php").unwrap()),
        ("React",      Regex::new(r"\.jsx$|\.tsx$").unwrap()),
        ("Vue",        Regex::new(r"\.vue$|vue\.config").unwrap()),
        ("Angular",    Regex::new(r"angular\.json|ng-package").unwrap()),
    ];
}

// ════════════════════════════════════════════════
// DATA STRUCTURES
// ════════════════════════════════════════════════

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub filename:    String,
    pub line:        usize,
    pub pattern_id:  String,
    pub description: String,
    pub severity:    String,
    #[serde(rename = "match")]
    pub match_str:   String,
    pub context:     String,
    pub is_deleted:  bool,
    pub commit_sha1: Option<String>,
}

impl Finding {
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "file":      self.filename,
            "line":      self.line,
            "type":      self.pattern_id,
            "desc":      self.description,
            "severity":  self.severity,
            "match":     &self.match_str[..self.match_str.len().min(120)],
            "context":   &self.context[..self.context.len().min(200)],
            "deleted":   self.is_deleted,
            "blob_sha1": self.commit_sha1,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Contributor {
    pub name:  String,
    pub email: String,
}

#[derive(Debug, Default)]
pub struct StreamResult {
    pub findings:       Vec<Finding>,
    pub contributors:   Vec<Contributor>,
    pub tech_stack:     Vec<String>,
    pub commit_count:   usize,
    pub blobs_scanned:  usize,
    pub blobs_failed:   usize,
    pub bytes_scanned:  usize,
    pub elapsed_s:      f64,
}

impl StreamResult {
    pub fn risk_score(&self) -> u32 {
        let mut critical = 0u32;
        let mut high = 0u32;
        let mut medium = 0u32;
        for f in &self.findings {
            match f.severity.as_str() {
                "CRITICAL" => critical += 1,
                "HIGH"     => high     += 1,
                "MEDIUM"   => medium   += 1,
                _          => {}
            }
        }
        let score = (critical * 20).min(60) + (high * 10).min(30) + (medium * 5).min(15);
        score.min(100)
    }

    pub fn severity_counts(&self) -> HashMap<&'static str, usize> {
        let mut c = HashMap::from([("CRITICAL", 0), ("HIGH", 0), ("MEDIUM", 0), ("LOW", 0)]);
        for f in &self.findings {
            match f.severity.as_str() {
                "CRITICAL" => *c.get_mut("CRITICAL").unwrap() += 1,
                "HIGH"     => *c.get_mut("HIGH").unwrap()     += 1,
                "MEDIUM"   => *c.get_mut("MEDIUM").unwrap()   += 1,
                "LOW"      => *c.get_mut("LOW").unwrap()      += 1,
                _          => {}
            }
        }
        c
    }
}

// ════════════════════════════════════════════════
// SHARED STATE
// ════════════════════════════════════════════════

#[derive(Default)]
struct State {
    findings:        Vec<Finding>,
    contributors:    HashMap<String, String>,   // email → name
    tech_stack:      HashSet<String>,
    commit_count:    usize,
    blobs_scanned:   usize,
    blobs_failed:    usize,
    bytes_scanned:   usize,
}

// Result sent back from each worker task via channel
enum WorkerResult {
    BlobScanned {
        findings: Vec<Finding>,
        tech:     Vec<String>,
        bytes:    usize,
    },
    BlobFailed,
    CommitProcessed {
        email: String,
        name:  String,
    },
    TreeProcessed {
        file_techs: Vec<(String, String)>,  // (sha1, filename)
    },
    Skipped,
}

// ════════════════════════════════════════════════
// MAIN STREAMER
// ════════════════════════════════════════════════

pub struct Streamer {
    client:      HttpClient,
    workers:     usize,
    mem_limit:   usize,
    verbose:     bool,
}

impl Streamer {
    pub fn new(client: HttpClient, workers: usize, mem_limit_mb: usize, verbose: bool) -> Self {
        Self {
            client,
            workers,
            mem_limit: mem_limit_mb * 1024 * 1024,
            verbose,
        }
    }

    pub async fn run(
        &self,
        git_url: &str,
        map_result: &MapResult,
        progress_cb: Option<Arc<dyn Fn(usize, usize) + Send + Sync>>,
    ) -> StreamResult {
        let t0 = Instant::now();
        let git_url = git_url.trim_end_matches('/').to_string();

        // Build sha1→filename lookup and current-blob set upfront
        let mut sha1_to_file: HashMap<String, String> = HashMap::with_capacity(map_result.index_entries.len());
        for entry in &map_result.index_entries {
            sha1_to_file.insert(entry.sha1.clone(), entry.filename.clone());
        }
        let current_blobs = map_result.blob_sha1s.clone();
        let sha1_to_file = Arc::new(sha1_to_file);
        let current_blobs = Arc::new(current_blobs);

        // Priority: blobs from index first (sensitive), then commit graph
        let mut priority_blobs: Vec<String> = map_result.blob_sha1s.iter().cloned().collect();
        let other_sha1s: Vec<String> = map_result.commit_sha1s.iter().cloned().collect();

        // Sort: sensitive files first (no lock needed — sha1_to_file is immutable here)
        priority_blobs.sort_by_key(|sha1| {
            if is_sensitive_file(sha1_to_file.get(sha1).map(|f| f.as_str()).unwrap_or("")) {
                0
            } else {
                1
            }
        });

        let all_sha1s: Vec<String> = priority_blobs.into_iter().chain(other_sha1s).collect();
        let total = all_sha1s.len();

        if self.verbose {
            println!(
                "  [*] Streaming {} objects ({} blobs + {} commit/tree graph)...",
                total,
                map_result.blob_sha1s.len(),
                map_result.commit_sha1s.len(),
            );
        }

        let done_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Use FuturesUnordered with buffer_unordered for bounded concurrency
        // Each future returns a WorkerResult; aggregation is single-threaded (no lock contention).
        let workers = self.workers;
        let stream = futures::stream::iter(all_sha1s)
            .map(|sha1| {
                let client = self.client.clone();
                let git_url = git_url.clone();
                let sha1_to_file = sha1_to_file.clone();
                let current_blobs = current_blobs.clone();
                async move {
                    fetch_and_process(&client, &git_url, &sha1, &sha1_to_file, &current_blobs).await
                }
            })
            .buffer_unordered(workers);

        let mut state = State::default();

        futures::pin_mut!(stream);
        while let Some(result) = stream.next().await {
            let done = done_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if let Some(ref cb) = progress_cb {
                cb(done, total);
            }
            match result {
                WorkerResult::BlobScanned { findings, tech, bytes } => {
                    state.blobs_scanned += 1;
                    state.bytes_scanned += bytes;
                    state.findings.extend(findings);
                    for t in tech {
                        state.tech_stack.insert(t);
                    }
                }
                WorkerResult::BlobFailed => {
                    state.blobs_failed += 1;
                }
                WorkerResult::CommitProcessed { email, name } => {
                    state.commit_count += 1;
                    if !email.is_empty() {
                        state.contributors.entry(email).or_insert(name);
                    }
                }
                WorkerResult::TreeProcessed { file_techs } => {
                    for (_sha1, filename) in file_techs {
                        detect_tech(&filename, &mut state.tech_stack);
                    }
                }
                WorkerResult::Skipped => {}
            }
        }

        let elapsed = t0.elapsed().as_secs_f64();
        let mut ts: Vec<_> = state.tech_stack.iter().cloned().collect();
        ts.sort();

        StreamResult {
            findings:      state.findings,
            contributors:  state.contributors.iter()
                             .map(|(email, name)| Contributor { name: name.clone(), email: email.clone() })
                             .collect(),
            tech_stack:    ts,
            commit_count:  state.commit_count,
            blobs_scanned: state.blobs_scanned,
            blobs_failed:  state.blobs_failed,
            bytes_scanned: state.bytes_scanned,
            elapsed_s:     elapsed,
        }
    }
}

// ════════════════════════════════════════════════
// PER-SHA1 PROCESSING (async, lock-free)
// ════════════════════════════════════════════════

/// Max blob content size to scan (4 MB). Larger blobs are skipped.
const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;

async fn fetch_and_process(
    client: &HttpClient,
    git_url: &str,
    sha1: &str,
    sha1_to_file: &HashMap<String, String>,
    current_blobs: &HashSet<String>,
) -> WorkerResult {
    let url  = format!("{}/{}", git_url, obj_path(sha1));
    let resp = client.get(&url).await;

    if !resp.ok() {
        return WorkerResult::BlobFailed;
    }

    let parser = ObjectParser;
    let obj = match parser.parse(&resp.body, sha1) {
        Some(o) => o,
        None    => return WorkerResult::Skipped,
    };

    let raw_bytes = resp.body.len();

    match obj.obj_type.as_str() {
        "blob" => {
            // Fast binary detection: check first 8 KB for null bytes
            let probe = &obj.data[..obj.data.len().min(8192)];
            let null_count = probe.iter().filter(|&&b| b == 0).count();
            if null_count > 10 {
                // Binary file — skip scanning, still count bytes
                return WorkerResult::BlobScanned {
                    findings: vec![],
                    tech: vec![],
                    bytes: raw_bytes,
                };
            }

            // Skip blobs that exceed the scan size limit
            if obj.data.len() > MAX_SCAN_BYTES {
                return WorkerResult::BlobScanned {
                    findings: vec![],
                    tech: vec![],
                    bytes: raw_bytes,
                };
            }

            let filename = sha1_to_file.get(sha1)
                .cloned()
                .unwrap_or_else(|| format!("[blob:{}]", &sha1[..8]));
            let is_deleted = !current_blobs.contains(sha1);

            let mut tech = Vec::new();
            collect_tech(&filename, &mut tech);

            let content = match std::str::from_utf8(&obj.data) {
                Ok(s)  => s.to_string(),
                Err(_) => String::from_utf8_lossy(&obj.data).into_owned(),
            };

            let findings = scan_content(&content, &filename, sha1, is_deleted);

            WorkerResult::BlobScanned { findings, tech, bytes: raw_bytes }
        }
        "commit" => {
            if let Some(commit) = parser.parse_commit(&obj) {
                WorkerResult::CommitProcessed {
                    email: commit.author_email,
                    name:  commit.author,
                }
            } else {
                WorkerResult::Skipped
            }
        }
        "tree" => {
            let entries = parser.parse_tree(&obj);
            let file_techs: Vec<(String, String)> = entries.into_iter()
                .filter(|e| e.is_blob())
                .map(|e| (e.sha1, e.name))
                .collect();
            WorkerResult::TreeProcessed { file_techs }
        }
        _ => WorkerResult::Skipped,
    }
}

fn scan_content(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        if line.len() > 2000 {
            continue;
        }

        for pat in PATTERNS.iter() {
            for m in pat.regex.find_iter(line) {
                let val = m.as_str().to_string();
                if is_placeholder(&val) {
                    continue;
                }
                findings.push(Finding {
                    filename:    filename.to_string(),
                    line:        lineno + 1,
                    pattern_id:  pat.id.to_string(),
                    description: pat.desc.to_string(),
                    severity:    pat.sev.to_string(),
                    match_str:   val,
                    context:     line.trim().to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                });
            }
        }

        // Entropy check for long tokens
        let trimmed = line.trim();
        if trimmed.len() >= 20
            && !trimmed.starts_with('#')
            && !trimmed.starts_with("//")
            && !trimmed.starts_with('*')
            && !trimmed.starts_with("<!--")
            && !trimmed.starts_with("--")
        {
            for cap in ENTROPY_TOKEN_RE.captures_iter(line) {
                let token = &cap[1];
                if high_entropy(token) && !is_placeholder(token) {
                    findings.push(Finding {
                        filename:    filename.to_string(),
                        line:        lineno + 1,
                        pattern_id:  "entropy_string".to_string(),
                        description: "High-entropy string (suspected secret)".to_string(),
                        severity:    "MEDIUM".to_string(),
                        match_str:   token.to_string(),
                        context:     line.trim().to_string(),
                        is_deleted,
                        commit_sha1: Some(sha1.to_string()),
                    });
                }
            }
        }
    }

    findings
}

// ════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════

/// Collect matching tech stack entries into a Vec (lock-free variant for worker tasks).
fn collect_tech(filename: &str, out: &mut Vec<String>) {
    for (tech, rx) in TECH_PATTERNS.iter() {
        if rx.is_match(filename) {
            out.push(tech.to_string());
        }
    }
}

/// Mutate a HashSet directly (used by the aggregator after receiving results).
fn detect_tech(filename: &str, stack: &mut HashSet<String>) {
    for (tech, rx) in TECH_PATTERNS.iter() {
        if rx.is_match(filename) {
            stack.insert(tech.to_string());
        }
    }
}

fn is_sensitive_file(filename: &str) -> bool {
    SENSITIVE_NAMES.is_match(filename)
}

fn is_placeholder(s: &str) -> bool {
    PLACEHOLDERS.iter().any(|p| s.contains(p))
}

fn entropy(s: &str, charset: &std::collections::HashSet<char>) -> f64 {
    let filtered: Vec<char> = s.chars().filter(|c| charset.contains(c)).collect();
    if filtered.len() < 12 {
        return 0.0;
    }
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in &filtered {
        *freq.entry(*c).or_insert(0) += 1;
    }
    let len = filtered.len() as f64;
    -freq.values().map(|&v| {
        let p = v as f64 / len;
        p * p.log2()
    }).sum::<f64>()
}

fn high_entropy(s: &str) -> bool {
    lazy_static! {
        static ref B64_CHARSET: std::collections::HashSet<char> =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
                .chars().collect();
        static ref HEX_CHARSET: std::collections::HashSet<char> =
            "0123456789abcdefABCDEF".chars().collect();
    }
    let threshold = 3.6;
    entropy(s, &B64_CHARSET) > threshold || entropy(s, &HEX_CHARSET) > threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_placeholder() {
        assert!(is_placeholder("your_api_key_here"));
        assert!(is_placeholder("AKIAIOSFODNN7EXAMPLE"));
        assert!(!is_placeholder("AKIAIOSFODNN7REAL_SECRET"));
    }

    #[test]
    fn test_high_entropy_base64() {
        // High-entropy Base64 string (random-looking)
        assert!(high_entropy("R2l0UmVjb25Jc0F3ZXNvbWVUb29sRm9yU2VjdXJpdHk="));
    }

    #[test]
    fn test_low_entropy() {
        assert!(!high_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn test_binary_detection_byte_level() {
        // A byte slice with >10 null bytes in the first 8 KB should be treated as binary
        let binary: Vec<u8> = (0u8..20).flat_map(|_| vec![b'A', 0u8]).collect();
        let probe = &binary[..binary.len().min(8192)];
        let null_count = probe.iter().filter(|&&b| b == 0).count();
        assert!(null_count > 10, "Should detect binary data");

        // Normal text should not exceed the threshold
        let text = b"hello world, this is a test file with no null bytes";
        let probe = &text[..text.len().min(8192)];
        let null_count = probe.iter().filter(|&&b| b == 0).count();
        assert!(null_count <= 10, "Plain text should not be detected as binary");
    }

    #[test]
    fn test_scan_content_finds_aws_key() {
        // AKIA + exactly 16 uppercase/digit chars, no placeholder substrings
        let content = "AWS_KEY=AKIAZ9XYZMNOP1234567";
        let findings = scan_content(content, "config.sh", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "aws_key_id"),
            "Should detect AWS key ID pattern"
        );
    }

    #[test]
    fn test_scan_content_skips_long_lines() {
        let long_line = "A".repeat(2001);
        let findings = scan_content(&long_line, "file.txt", "a".repeat(40).as_str(), false);
        // Long lines should be skipped — no findings
        assert!(findings.is_empty(), "Lines >2000 chars should be skipped");
    }

    #[test]
    fn test_collect_tech_python() {
        let mut tech = Vec::new();
        collect_tech("requirements.txt", &mut tech);
        assert!(tech.contains(&"Python".to_string()));
    }

    #[test]
    fn test_max_scan_bytes_constant() {
        assert_eq!(MAX_SCAN_BYTES, 4 * 1024 * 1024);
    }
}

//! main.rs
//! GitRecon v3.0.0 — Streaming Git Exposure Scanner (Rust)
//!
//! Usage:
//!   gitrecon <url> [options]
//!   gitrecon --token <PAT> [options]
//!
//! Examples:
//!   gitrecon https://target.com
//!   gitrecon https://target.com --save
//!   gitrecon https://target.com --proxy socks5://127.0.0.1:9050
//!   gitrecon https://target.com --delay 1.5 --timeout 15
//!   gitrecon https://target.com --save --output ./hasil
//!   gitrecon https://target.com --fuzz
//!   gitrecon https://target.com --no-color -q
//!   gitrecon --token ghp_xxxxxxxxxxxxxxxxxxxx
//!   gitrecon --token ghp_xxxx --format sarif --output ./results
//!   gitrecon --dir ./project

mod http_client;
mod git_parser;
mod detect;
mod mapper;
mod streamer;
mod reporter;
mod github_api;
mod gitlab_api;
mod bitbucket_api;
mod gitea_api; // GIT-003: Gitea/Forgejo support
mod azure_api; // GIT-004: Azure DevOps support
mod forge;
mod text_utils;
mod checkpoint;
mod binary_scanner;
mod validation;
mod temp_cleanup; // SEC-004: Temp file cleanup
mod rate_limiter; // PERF-004: Token bucket rate limiter
mod cache; // PERF-005: SQLite cache layer
#[allow(dead_code)]
mod reconstructor;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::io::{self, Write};

use forge::Forge;

use clap::Parser;
use futures::StreamExt;

use temp_cleanup::TempDirGuard; // SEC-004

use colored::Colorize;
use http_client::{HttpClient, HttpConfig};
use reporter::Reporter;
use streamer::StreamResult;
use serde::Deserialize;

// ════════════════════════════════════════════════
// A-1: Multi-Target Scanning - Target Definition
// ════════════════════════════════════════════════

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[allow(dead_code)]
enum Target {
    Url { url: String, fuzz: Option<bool> },
    Token { token: String, repos: Option<Vec<String>> },
    Dir { dir: String },
}

#[allow(dead_code)]
impl Target {
    fn kind(&self) -> &'static str {
        match self {
            Target::Url { .. } => "URL",
            Target::Token { .. } => "TOKEN",
            Target::Dir { .. } => "DIR",
        }
    }
}

// ════════════════════════════════════════════════
// CLI
// ════════════════════════════════════════════════

#[derive(Parser, Debug)]
#[command(
    name = "gitrecon",
    version = "3.2.0",
    about = "GitRecon — Streaming Git Exposure Scanner (Rust)",
    long_about = None,
    after_help = "Examples:\n  gitrecon https://target.com\n  gitrecon https://target.com --save\n  gitrecon https://target.com --proxy socks5://127.0.0.1:9050 --delay 1\n  gitrecon https://target.com --fuzz --timeout 15\n  gitrecon --targets urls.txt --parallel-targets 5\n  gitrecon https://target.com --format sarif --webhook https://alerts.example.com\n  gitrecon --token ghp_xxxxxxxxxxxxxxxxxxxx\n  gitrecon --token ghp_xxxx --format sarif --output ./results\n  gitrecon --token ghp_xxxx --workers 20 --max-blob-size 2\n  gitrecon --dir ./project --format json\n\nToken mode interactive flow:\n  1) Repositories are listed with numbers\n  2) Choose one number, comma-separated numbers, or 'all'\n  3) Confirm whether reconstruction should be saved [Y/N]"
)]
struct Cli {
    /// Target URL (optional when --targets or --token is used)
    #[arg(value_name = "URL", required = false)]
    url: Option<String>,

    /// GitHub Personal Access Token — interactive repo selection then scan selected repositories
    #[arg(long = "token", value_name = "PAT")]
    token: Option<String>,

    /// GitLab Personal Access Token — interactive repo selection then scan selected repositories
    #[arg(long = "gitlab-token", value_name = "PAT")]
    gitlab_token: Option<String>,

    /// GitLab instance URL (default: https://gitlab.com/api/v4)
    #[arg(long = "gitlab-url", value_name = "URL")]
    gitlab_url: Option<String>,

    /// Bitbucket App Password — interactive repo selection then scan selected repositories
    #[arg(long = "bitbucket-token", value_name = "APP_PASSWORD")]
    bitbucket_token: Option<String>,

    /// Bitbucket instance URL (default: https://api.bitbucket.org/2.0)
    #[arg(long = "bitbucket-url", value_name = "URL")]
    bitbucket_url: Option<String>,

    /// Gitea/Forgejo Access Token — interactive repo selection then scan selected repositories
    #[arg(long = "gitea-token", value_name = "TOKEN")]
    gitea_token: Option<String>,

    /// Gitea/Forgejo instance URL (default: https://gitea.com/api/v1)
    #[arg(long = "gitea-url", value_name = "URL")]
    gitea_url: Option<String>,

    /// Azure DevOps Personal Access Token — interactive repo selection then scan selected repositories
    #[arg(long = "azure-token", value_name = "PAT")]
    azure_token: Option<String>,

    /// Azure DevOps instance URL (default: https://dev.azure.com)
    /// For on-premise Azure DevOps Server, specify the full URL like https://tfs.company.com/tfs
    #[arg(long = "azure-url", value_name = "URL")]
    azure_url: Option<String>,

    /// Scan a local directory recursively for secrets
    #[arg(long = "dir", value_name = "PATH")]
    dir: Option<String>,

    /// Rekonstruksi source code ke disk setelah scan
    /// (in --token quiet/pipe mode, used as non-interactive default)
    #[arg(long)]
    save: bool,

    /// Direktori output (default: ./gitrecon_output)
    #[arg(short = 'o', long = "output", default_value = "./gitrecon_output", value_name = "DIR")]
    output: String,

    /// Proxy URL, contoh: socks5://127.0.0.1:9050
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Timeout request dalam detik (default: 10)
    #[arg(long, default_value = "10", value_name = "SEC")]
    timeout: u64,

    /// Jumlah retry (default: 3)
    #[arg(long, default_value = "3", value_name = "N")]
    retries: u32,

    /// Delay antar request dalam detik (default: 0)
    #[arg(long, default_value = "0.0", value_name = "SEC")]
    delay: f64,

    /// Jitter random maksimum (default: 0)
    #[arg(long, default_value = "0.0", value_name = "SEC")]
    jitter: f64,

    /// Custom User-Agent
    #[arg(long = "user-agent", value_name = "UA")]
    user_agent: Option<String>,

    /// Header tambahan (bisa diulang, format: Name:Value)
    #[arg(long = "header", action = clap::ArgAction::Append, value_name = "NAME:VALUE")]
    headers: Vec<String>,

    /// Coba non-standard .git paths (api/.git, admin/.git, dst)
    #[arg(long)]
    fuzz: bool,

    /// Worker tasks untuk streaming (default: 50)
    #[arg(short = 'w', long = "workers", default_value = "50", value_name = "N")]
    workers: usize,

    /// Batas memori untuk streaming (default: 256MB)
    #[arg(long = "mem-limit", default_value = "256", value_name = "MB")]
    mem_limit: usize,

    /// Berhenti setelah N temuan (0 = tidak terbatas)
    #[arg(long = "max-findings", default_value = "0", value_name = "N")]
    max_findings: usize,

    /// Hentikan scan segera setelah temuan CRITICAL pertama
    #[arg(long = "stop-on-critical")]
    stop_on_critical: bool,

    /// Path ke file JSON berisi pola deteksi tambahan
    #[arg(long = "patterns", value_name = "FILE")]
    patterns: Option<String>,

    // SCAN-001: Configurable false-positive keywords for context-aware confidence scoring
    /// Comma-separated list of additional false-positive keywords (extends defaults)
    #[arg(long = "false-positive-keywords", value_name = "KEYWORDS")]
    false_positive_keywords: Option<String>,

    /// Confidence minimum untuk lanjut scan (default: 45)
    #[arg(long = "min-confidence", default_value = "45", value_name = "PCT",
          value_parser = clap::value_parser!(u32).range(0..=100))]
    min_confidence: u32,

    /// Matikan warna terminal
    #[arg(long = "no-color")]
    no_color: bool,

    /// Kurangi output terminal
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    // DX-1: --patterns-help
    #[arg(long = "patterns-help")]
    patterns_help: bool,

    // DX-2: --max-blob-size
    #[arg(long = "max-blob-size", default_value = "4", value_name = "MB")]
    max_blob_size: usize,

    // DX-3: --entropy-threshold
    #[arg(long = "entropy-threshold", default_value = "4.5", value_name = "FLOAT")]
    entropy_threshold: f64,

    // DX-4: --dry-run
    #[arg(long = "dry-run")]
    dry_run: bool,

    // R-3, P-2: adaptive timeout and HTTP/2
    #[arg(long = "no-adaptive-timeout")]
    no_adaptive_timeout: bool,

    #[arg(long = "max-timeout", default_value = "60", value_name = "SEC")]
    max_timeout: u64,

    #[arg(long = "http2")]
    http2: bool,

    // P-1: adaptive concurrency
    #[arg(long = "no-adaptive")]
    no_adaptive: bool,

    // E-1: rate limiting
    #[arg(long = "rate", value_name = "N")]
    rate: Option<f64>,

    // E-2: proxy rotation
    #[arg(long = "proxy-list", value_name = "FILE")]
    proxy_list: Option<String>,

    // E-4: UA pool and git mode
    #[arg(long = "ua-file", value_name = "FILE")]
    ua_file: Option<String>,

    #[arg(long = "ua-git")]
    ua_git: bool,

    // O-1: live output
    #[arg(long = "live")]
    live: bool,

    // O-2, O-3: output formats
    #[arg(long = "format", default_value = "json", value_name = "FORMAT",
          value_parser = ["json", "sarif", "csv", "ndjson", "md", "html"])]
    format: String,

    // O-4: webhook
    #[arg(long = "webhook", value_name = "URL")]
    webhook: Option<String>,

    #[arg(long = "webhook-secret", value_name = "KEY")]
    webhook_secret: Option<String>,

    // A-1: multi-target scanning
    #[arg(long = "targets", value_name = "FILE")]
    targets: Option<String>,

    #[arg(long = "parallel-targets", default_value = "1", value_name = "N")]
    parallel_targets: usize,

    // A-6: pipe mode
    #[arg(long = "pipe")]
    pipe: bool,

    // R-1: checkpoint & resume
    #[arg(long = "resume")]
    resume: bool,

    #[arg(long = "checkpoint-dir", value_name = "DIR")]
    checkpoint_dir: Option<String>,

    #[arg(long = "checkpoint-interval", default_value = "1000", value_name = "N")]
    checkpoint_interval: usize,

    // S-3: binary file scanning
    #[arg(long = "scan-binaries")]
    scan_binaries: bool,

    // PERF-002: smart retry per status code
    #[arg(long = "retry-strategy", default_value = "standard", value_name = "STRATEGY",
          value_parser = clap::value_parser!(String))]
    retry_strategy: String,

    // PERF-005: SQLite cache layer
    /// Disable cache (bypass all cache operations)
    #[arg(long = "no-cache")]
    no_cache: bool,

    /// Cache TTL in seconds (default: 604800 = 7 days, 0 = no expiration)
    #[arg(long = "cache-ttl", default_value = "604800", value_name = "SECONDS")]
    cache_ttl: u64,

    /// Skip object accessibility verification (forces scan even if metadata-only exposure detected)
    #[arg(long = "skip-verification")]
    skip_verification: bool,
}

// ════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════

fn normalize_url(url: &str) -> String {
    match validation::validate_and_normalize_url(url) {
        Ok(normalized) => normalized,
        Err(e) => {
            eprintln!("  ✘  Invalid URL: {}", e);
            std::process::exit(1);
        }
    }
}

fn target_name(url: &str) -> String {
    let name = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace('/', "_");
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .chars()
        .take(200)
        .collect()
}

fn dir_target_name(path: &Path) -> String {
    let raw = path
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("directory_scan");
    target_name(raw)
}

fn parse_extra_headers(raw: &[String]) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for h in raw {
        match validation::validate_custom_header(h) {
            Ok((k, v)) => result.push((k, v)),
            Err(e) => {
                eprintln!("  ✘  Invalid header '{}': {}", h, e);
                std::process::exit(1);
            }
        }
    }
    result
}

const BINARY_DETECTION_PROBE_SIZE: usize = 8192;
const NULL_BYTE_THRESHOLD: usize = 10;
const RECENT_FINDINGS_WINDOW: usize = 20;

fn collect_local_files(root: &Path) -> Vec<(PathBuf, u64)> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };

        for entry in read_dir.flatten() {
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let path = entry.path();

            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if file_type.is_file() {
                let size = match entry.metadata() {
                    Ok(meta) => meta.len(),
                    Err(_) => continue,
                };
                files.push((path, size));
            }
        }
    }

    files
}

fn normalize_repo_relative_path(path: &str) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in Path::new(path).components() {
        match comp {
            Component::Normal(seg) => out.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn parse_repo_selection_input(input: &str, max_repo: usize) -> Result<Vec<usize>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Input tidak boleh kosong.".to_string());
    }
    if trimmed.eq_ignore_ascii_case("all") {
        return Ok((0..max_repo).collect());
    }
    let mut picked = std::collections::BTreeSet::new();
    for raw in trimmed.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            return Err("Format daftar nomor tidak valid.".to_string());
        }
        let num: usize = item
            .parse()
            .map_err(|_| format!("'{}' bukan nomor valid.", item))?;
        if num == 0 || num > max_repo {
            return Err(format!("Nomor {} di luar rentang 1..{}.", num, max_repo));
        }
        picked.insert(num - 1);
    }
    Ok(picked.into_iter().collect())
}

fn parse_yes_no_choice(input: &str) -> Option<bool> {
    let s = input.trim().to_ascii_lowercase();
    match s.as_str() {
        "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => None,
    }
}

fn prompt_line(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut line = String::new();
    let read = io::stdin().read_line(&mut line)?;
    if read == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stdin closed"));
    }
    Ok(line)
}

fn prompt_repo_selection(repos: &[github_api::GhRepo]) -> Vec<usize> {
    println!("  ◈  Pilih repository yang ingin di-scan:");
    for (idx, repo) in repos.iter().enumerate() {
        println!("      {:>4}. {}", idx + 1, repo.full_name);
    }
    println!("      Input: satu nomor (contoh: 3), banyak nomor (1,3,7), atau all");

    loop {
        match prompt_line("  > Pilihan repo: ") {
            Ok(input) => match parse_repo_selection_input(&input, repos.len()) {
                Ok(v) => return v,
                Err(msg) => eprintln!("  ✘  {} Coba lagi.", msg),
            },
            Err(_) => {
                eprintln!("  ⚠   Input tidak tersedia, default ke all.");
                return (0..repos.len()).collect();
            }
        }
    }
}

fn prompt_save_choice(default: bool) -> bool {
    println!("\n  ◈  Simpan hasil rekonstruksi/clone source repo terpilih? [Y/N]");
    loop {
        match prompt_line("  > Simpan source ke disk (Y/N): ") {
            Ok(input) => {
                if let Some(v) = parse_yes_no_choice(&input) {
                    return v;
                }
                eprintln!("  ✘  Input tidak valid. Gunakan Y atau N.");
            }
            Err(_) => {
                eprintln!(
                    "  ⚠   Input tidak tersedia, fallback ke default (--save={}): {}",
                    if default { "on" } else { "off" },
                    if default { "Y" } else { "N" }
                );
                return default;
            }
        }
    }
}

fn should_stop_scan(
    findings: &[streamer::Finding],
    max_findings: usize,
    stop_on_critical: bool,
) -> bool {
    (max_findings > 0 && findings.len() >= max_findings)
        || (stop_on_critical
            && findings
                .iter()
                .rev()
                .take(RECENT_FINDINGS_WINDOW)
                .any(|f| f.severity == "CRITICAL"))
}

/// Returns true for file extensions that indicate binary content unlikely to
/// contain plaintext secrets.  The list is intentionally conservative — when
/// in doubt a file is *not* skipped.
fn is_binary_extension(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    matches!(
        ext.as_str(),
        // Images
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "ico" | "webp" | "tiff" | "avif" |
        // Archives / packages
        "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" | "whl" | "jar" | "war" | "ear" |
        // Documents
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp" |
        // Binaries / shared libraries
        "exe" | "dll" | "so" | "dylib" | "bin" | "wasm" | "o" | "a" | "lib" | "obj" |
        // Media
        "mp3" | "mp4" | "wav" | "ogg" | "flac" | "avi" | "mov" | "mkv" | "webm" | "m4a" |
        // Fonts
        "ttf" | "otf" | "woff" | "woff2" | "eot" |
        // Compiled artefacts
        "pyc" | "pyo" | "class" |
        // SQLite databases are handled separately in the streamer; skip here
        "db" | "sqlite" | "sqlite3"
    )
}

// ════════════════════════════════════════════════
// TOKEN SCAN PIPELINE
// ════════════════════════════════════════════════

#[allow(clippy::too_many_lines)]
async fn run_token_scan(
    args:           &Cli,
    rep:            &Reporter,
    base_cfg:       HttpConfig,
    token:          &str,
    extra_patterns: Vec<streamer::DynPattern>,
) {
    let quiet   = args.quiet || args.pipe;
    let verbose = !quiet;

    // SEC-001: Validate GitHub token format
    if let Err(e) = validation::validate_github_token(token) {
        eprintln!("  ✘  Invalid GitHub token: {}", e);
        std::process::exit(1);
    }

    if !quiet {
        rep.banner();
        println!("  Mode  : GitHub Token Scan");
        println!("  Output: {}\n", args.output);
    }

    // ── 1. Build GitHub API client ───────────────
    let gh_client = match github_api::build_github_client(base_cfg, token) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("  ✘  Failed to build GitHub API client: {}", e);
            std::process::exit(1);
        }
    };

    // ── 2. Authenticate ──────────────────────────
    if verbose { println!("  ◈  Authenticating with GitHub API..."); }
    let (login, _name) = match github_api::whoami(&gh_client).await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Authentication failed: {}", e);
            std::process::exit(1);
        }
    };
    if verbose { println!("  ✔  Authenticated as: {}\n", login.cyan().bold()); }

    // ── 3. Enumerate repositories ────────────────
    if verbose { println!("  ◈  Enumerating repositories..."); }

    let mut all_repos = match github_api::list_repos(&gh_client).await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Failed to list repositories: {}", e);
            std::process::exit(1);
        }
    };

    // Include repos from organisations the user belongs to
    match github_api::list_user_orgs(&gh_client).await {
        Ok(orgs) => {
            for org in orgs {
                match github_api::list_org_repos(&gh_client, &org).await {
                    Ok(org_repos) => all_repos.extend(org_repos),
                    Err(e) => {
                        if verbose {
                            eprintln!("  ⚠   Skipping org '{}': {}", org, e);
                        }
                    }
                }
            }
        }
        Err(e) => {
            if verbose { eprintln!("  ⚠   Could not list orgs: {}", e); }
        }
    }

    // Deduplicate by full_name (user repos and org repos can overlap)
    let mut seen_names = std::collections::HashSet::new();
    all_repos.retain(|r| seen_names.insert(r.full_name.clone()));
    let total_repos = all_repos.len();
    if total_repos == 0 {
        if verbose {
            println!("  ⚠   Tidak ada repository yang bisa di-scan.\n");
        }
        return;
    }

    if verbose { println!("  ✔  Found {} repositories\n", total_repos); }

    let interactive = !args.quiet && !args.pipe;
    let selected_indexes = if interactive {
        prompt_repo_selection(&all_repos)
    } else {
        (0..all_repos.len()).collect()
    };
    let selected_repos: Vec<github_api::GhRepo> = selected_indexes
        .into_iter()
        .filter_map(|i| all_repos.get(i).cloned())
        .collect();
    let selected_repo_count = selected_repos.len();
    if selected_repo_count == 0 {
        eprintln!("  ✘  Tidak ada repository valid yang dipilih.");
        return;
    }

    if verbose {
        println!("  ✔  Selected {} repositories for scanning", selected_repo_count);
    }

    let persist_source = if interactive {
        prompt_save_choice(args.save)
    } else {
        args.save
    };
    if verbose {
        println!(
            "  ◈  Source persistence: {}\n",
            if persist_source { "enabled (--save behavior)" } else { "disabled (temporary workspace)" }
        );
    }

    // ── 4. Acquire source workspace and scan selected repositories ─────
    let t0              = Instant::now();
    let all_findings    = Arc::new(tokio::sync::Mutex::new(Vec::<streamer::Finding>::new()));
    let tech_stack_set  = Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::<String>::new()));
    let blobs_scanned   = Arc::new(AtomicUsize::new(0));
    let blobs_failed    = Arc::new(AtomicUsize::new(0));
    let bytes_scanned   = Arc::new(AtomicUsize::new(0));
    let stop_flag       = Arc::new(AtomicBool::new(false));

    let max_blob_bytes = args.max_blob_size * 1024 * 1024;
    let extra_pat_arc  = Arc::new(extra_patterns);
    let save_root      = if persist_source {
        Some(std::path::PathBuf::from(&args.output).join(format!("token_{}", login)))
    } else {
        None
    };

    // SEC-004: RAII guard for temp workspace
    // The guard will automatically clean up on Drop (including signal interruption)
    let temp_guard: Option<TempDirGuard> = if persist_source {
        None
    } else {
        let p = std::env::temp_dir().join(format!(
            "gitrecon_token_scan_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&p);
        Some(TempDirGuard::new(p))
    };
    let temp_root = temp_guard.as_ref().and_then(|g| g.path().map(|p| p.to_path_buf()));

    // Ensure temp_guard stays alive for the entire scan
    let _temp_guard = temp_guard;

    for (repo_idx, repo) in selected_repos.iter().enumerate() {
        if stop_flag.load(Ordering::Relaxed) { break; }

        if verbose {
            println!("  ▶  [{}/{}] {}", repo_idx + 1, selected_repo_count, repo.full_name);
        }

        // Get HEAD SHA for the default branch
        let head_sha = match github_api::get_head_sha(
            &gh_client, &repo.owner, &repo.name, &repo.default_branch,
        ).await {
            Ok(s)  => s,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot resolve HEAD for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        // Fetch the full recursive tree
        let tree = match github_api::get_tree(&gh_client, &repo.owner, &repo.name, &head_sha).await {
            Ok(t)  => t,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot get tree for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        let repo_workspace = if let Some(root) = save_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else if let Some(root) = temp_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else {
            continue;
        };
        let _ = std::fs::create_dir_all(&repo_workspace);

        // Reconstruct source workspace from tree blobs
        let blobs: Vec<_> = tree.into_iter()
            .filter(|e| e.obj_type == "blob")
            .filter(|e| e.size.is_none_or(|s| s <= max_blob_bytes as u64))
            .collect();

        if verbose && !blobs.is_empty() {
            println!("      Reconstructing {} files into workspace", blobs.len());
        }

        let reconstruct_stream = futures::stream::iter(blobs)
            .map(|entry| {
                let client          = gh_client.clone();
                let owner           = repo.owner.clone();
                let name            = repo.name.clone();
                let workspace       = repo_workspace.clone();
                async move {
                    let data = match github_api::get_blob_content(&client, &owner, &name, &entry.sha).await {
                        Ok(d)  => d,
                        Err(_) => return false,
                    };
                    if data.len() > max_blob_bytes {
                        return false;
                    }
                    let rel = match normalize_repo_relative_path(&entry.path) {
                        Some(r) => r,
                        None => return false,
                    };
                    let local_path = workspace.join(rel);
                    if !local_path.starts_with(&workspace) {
                        return false;
                    }
                    if let Some(parent) = local_path.parent() {
                        if std::fs::create_dir_all(parent).is_err() {
                            return false;
                        }
                    }
                    std::fs::write(local_path, &data).is_ok()
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(reconstruct_stream);
        while let Some(ok) = reconstruct_stream.next().await {
            if !ok {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
            }
        }

        let mut candidates: Vec<PathBuf> = collect_local_files(&repo_workspace)
            .into_iter()
            .filter(|(p, size)| !is_binary_extension(&p.to_string_lossy()) && *size <= max_blob_bytes as u64)
            .map(|(p, _)| p)
            .collect();
        candidates.sort_by_key(|p| if streamer::is_ai_sensitive_path(&p.to_string_lossy()) { 0 } else { 1 });

        if verbose {
            println!("      Scanning {} workspace files", candidates.len());
        }

        let file_stream = futures::stream::iter(candidates)
            .map(|path| {
                let stop = stop_flag.clone();
                let extra_patterns = extra_pat_arc.clone();
                let root = repo_workspace.clone();
                let full_name = repo.full_name.clone();
                let entropy_thresh = args.entropy_threshold;
                async move {
                    if stop.load(Ordering::Relaxed) {
                        return (vec![], vec![], 0usize, false, true);
                    }
                    let data = match tokio::fs::read(&path).await {
                        Ok(d) => d,
                        Err(_) => return (vec![], vec![], 0usize, true, false),
                    };
                    if data.is_empty() {
                        return (vec![], vec![], 0usize, false, false);
                    }
                    let probe = &data[..data.len().min(BINARY_DETECTION_PROBE_SIZE)];
                    let null_count = probe.iter().filter(|&&b| b == 0).count();
                    if null_count > NULL_BYTE_THRESHOLD {
                        return (vec![], vec![], 0usize, false, false);
                    }

                    let text = String::from_utf8_lossy(&data);
                    let rel = path
                        .strip_prefix(&root)
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                    let source = format!("{}/{}", full_name, rel);
                    let findings = streamer::scan_text(&text, &source, &extra_patterns, entropy_thresh);

                    let mut techs = Vec::new();
                    detect_tech_from_path(&rel, &mut techs);

                    (findings, techs, data.len(), false, false)
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(file_stream);
        while let Some((findings, techs, bytes, failed, skipped_by_stop)) = file_stream.next().await {
            if skipped_by_stop {
                continue;
            }
            if failed {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if bytes > 0 {
                blobs_scanned.fetch_add(1, Ordering::Relaxed);
                bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
            }

            if !techs.is_empty() {
                let mut ts = tech_stack_set.lock().await;
                for t in techs { ts.insert(t); }
            }
            if findings.is_empty() { continue; }

            if args.live || args.pipe {
                for f in &findings {
                    println!("{}", serde_json::to_string(&f.to_dict()).unwrap_or_default());
                }
            }

            let mut all = all_findings.lock().await;
            all.extend(findings);

            if should_stop_scan(&all, args.max_findings, args.stop_on_critical) {
                stop_flag.store(true, Ordering::Relaxed);
                if verbose {
                    if args.max_findings > 0 && all.len() >= args.max_findings {
                        println!("\n  [!] Reached --max-findings limit. Stopping scan.");
                    } else {
                        println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                    }
                }
                break;
            }
        }
    }

    // SEC-004: temp_guard automatically cleans up when dropped at end of scope
    // No manual cleanup needed here

    // ── 5. Assemble result ───────────────────────
    let elapsed_s   = t0.elapsed().as_secs_f64();
    let findings    = all_findings.lock().await.clone();
    let mut ts_vec: Vec<String> = tech_stack_set.lock().await.iter().cloned().collect();
    ts_vec.sort();

    let stream_r = StreamResult {
        findings,
        contributors:      vec![],
        tech_stack:        ts_vec,
        commit_count:      0,
        blobs_scanned:     blobs_scanned.load(Ordering::Relaxed),
        blobs_failed:      blobs_failed.load(Ordering::Relaxed),
        bytes_scanned:     bytes_scanned.load(Ordering::Relaxed),
        elapsed_s,
        files_saved:       0,
        files_save_failed: 0,
        // PERF-005: Cache metrics (not applicable for token mode scanning local files)
        cache_hits: 0,
        cache_misses: 0,
        cache_stats: None,
        // PERF-004: Rate limit metrics (not applicable for token mode)
        rate_limit_allowed: 0,
        rate_limit_dropped: 0,
        rate_limit_wait_ms: 0,
    };

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    // ── 7. Save report ───────────────────────────
    let report_name = format!("token_{}", login);
    let ext = match args.format.as_str() {
        "sarif"  => "sarif",
        "csv"    => "csv",
        "ndjson" => "ndjson",
        "md"     => "md",
        "html"   => "html",
        _        => "json",
    };
    let report_path = format!("{}/{}_report.{}", args.output, report_name, ext);

    let save_result = match args.format.as_str() {
        "sarif"  => rep.save_sarif(&report_path, &report_name, Some(&stream_r)),
        "csv"    => rep.save_csv(&report_path, Some(&stream_r)),
        "ndjson" => rep.save_ndjson(&report_path, Some(&stream_r)),
        "md"     => rep.save_markdown(&report_path, &report_name, Some(&stream_r)),
        "html"   => rep.save_html(&report_path, &report_name, Some(&stream_r)),
        _        => rep.save_token_report(&report_path, &login, selected_repo_count, &stream_r),
    };

    if let Err(e) = save_result {
        eprintln!("  ⚠   Could not save report: {}", e);
    }

    if verbose && !args.pipe {
        rep.print_token_report(&login, selected_repo_count, &stream_r, &report_path);
    }

    // ── 8. Webhook delivery ──────────────────────
    if let Some(ref webhook_url) = args.webhook {
        if let Ok(json_body) = std::fs::read_to_string(&report_path) {
            // We need a plain (no-auth) client for the webhook POST
            if let Ok(plain_cfg) = build_plain_http_config(args) {
                if let Ok(plain_client) = HttpClient::new(plain_cfg) {
                    let sent = rep.send_webhook(
                        webhook_url,
                        args.webhook_secret.as_deref(),
                        &json_body,
                        &plain_client,
                    ).await;
                    if verbose {
                        if sent { println!("  ✔   Webhook delivered to {}", webhook_url); }
                        else    { eprintln!("  ⚠   Webhook delivery failed"); }
                    }
                }
            }
        }
    }

    // ── 9. Pipe mode summary ─────────────────────
    if args.pipe {
        let summary = serde_json::json!({
            "type":     "summary",
            "mode":     "token",
            "user":     login,
            "repos":    selected_repo_count,
            "findings": stream_r.findings.len(),
            "risk_score": stream_r.risk_score(),
        });
        println!("{}", serde_json::to_string(&summary).unwrap_or_default());
    }

    if verbose && !args.pipe {
        println!("  ✔  Done\n");
    }
}

#[allow(clippy::too_many_lines)]
async fn run_gitlab_token_scan(
    args:           &Cli,
    rep:            &Reporter,
    base_cfg:       HttpConfig,
    token:          &str,
    gitlab_url:     Option<&str>,
    extra_patterns: Vec<streamer::DynPattern>,
) {
    let quiet   = args.quiet || args.pipe;
    let verbose = !quiet;

    // SEC-001: Validate GitLab token format (starts with glpat- or is a valid token)
    if let Err(e) = validation::validate_gitlab_token(token) {
        eprintln!("  ✘  Invalid GitLab token: {}", e);
        std::process::exit(1);
    }

    if !quiet {
        rep.banner();
        println!("  Mode  : GitLab Token Scan");
        if let Some(url) = gitlab_url {
            println!("  Instance: {}", url);
        }
        println!("  Output: {}\n", args.output);
    }

    // ── 1. Build GitLab API client ───────────────
    let (gl_client, api_base) = match gitlab_api::build_gitlab_client(base_cfg, token, gitlab_url) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("  ✘  Failed to build GitLab API client: {}", e);
            std::process::exit(1);
        }
    };

    // ── 2. Authenticate ──────────────────────────
    if verbose { println!("  ◈  Authenticating with GitLab API..."); }
    let mut gl_forge = gitlab_api::GitLabForgeClient::new(gl_client.clone(), api_base.clone());

    match gl_forge.authenticate(token).await {
        Ok(_) => {},
        Err(e) => {
            eprintln!("  ✘  Authentication failed: {}", e);
            std::process::exit(1);
        }
    }

    let (login, _name) = match gl_forge.whoami().await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Failed to get user info: {}", e);
            std::process::exit(1);
        }
    };

    if verbose { println!("  ✔  Authenticated as: {}\n", login.cyan().bold()); }

    // ── 3. Enumerate repositories ────────────────
    if verbose { println!("  ◈  Enumerating repositories..."); }

    let all_repos = match gl_forge.enumerate_repos(forge::EnumScope::All).await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Failed to list repositories: {}", e);
            std::process::exit(1);
        }
    };

    let total_repos = all_repos.len();
    if total_repos == 0 {
        if verbose {
            println!("  ⚠   Tidak ada repository yang bisa di-scan.\n");
        }
        return;
    }

    if verbose { println!("  ✔  Found {} repositories\n", total_repos); }

    let interactive = !args.quiet && !args.pipe;

    // Convert to a displayable format for selection
    let gl_projects: Vec<gitlab_api::GlProject> = all_repos.iter().map(|r| {
        gitlab_api::GlProject {
            full_name: r.full_name.clone(),
            owner: r.owner.clone(),
            name: r.name.clone(),
            private: r.private,
            default_branch: r.default_branch.clone(),
            clone_url: r.clone_url.clone(),
        }
    }).collect();

    let selected_indexes = if interactive {
        prompt_gitlab_repo_selection(&gl_projects)
    } else {
        (0..gl_projects.len()).collect()
    };

    let selected_repos: Vec<forge::Repository> = selected_indexes
        .into_iter()
        .filter_map(|i| all_repos.get(i).cloned())
        .collect();

    let selected_repo_count = selected_repos.len();
    if selected_repo_count == 0 {
        eprintln!("  ✘  Tidak ada repository valid yang dipilih.");
        return;
    }

    if verbose {
        println!("  ✔  Selected {} repositories for scanning", selected_repo_count);
    }

    let persist_source = if interactive {
        prompt_save_choice(args.save)
    } else {
        args.save
    };

    if verbose {
        println!(
            "  ◈  Source persistence: {}\n",
            if persist_source { "enabled (--save behavior)" } else { "disabled (temporary workspace)" }
        );
    }

    // ── 4. Acquire source workspace and scan selected repositories ─────
    let t0              = Instant::now();
    let all_findings    = Arc::new(tokio::sync::Mutex::new(Vec::<streamer::Finding>::new()));
    let tech_stack_set  = Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::<String>::new()));
    let blobs_scanned   = Arc::new(AtomicUsize::new(0));
    let blobs_failed    = Arc::new(AtomicUsize::new(0));
    let bytes_scanned   = Arc::new(AtomicUsize::new(0));
    let stop_flag       = Arc::new(AtomicBool::new(false));

    let max_blob_bytes = args.max_blob_size * 1024 * 1024;
    let extra_pat_arc  = Arc::new(extra_patterns);
    let save_root      = if persist_source {
        Some(std::path::PathBuf::from(&args.output).join(format!("gitlab_{}", login)))
    } else {
        None
    };

    // SEC-004: RAII guard for temp workspace
    let temp_guard: Option<TempDirGuard> = if persist_source {
        None
    } else {
        let p = std::env::temp_dir().join(format!(
            "gitrecon_gitlab_scan_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&p);
        Some(TempDirGuard::new(p))
    };
    let temp_root = temp_guard.as_ref().and_then(|g| g.path().map(|p| p.to_path_buf()));

    // Ensure temp_guard stays alive for the entire scan
    let _temp_guard = temp_guard;

    for (repo_idx, repo) in selected_repos.iter().enumerate() {
        if stop_flag.load(Ordering::Relaxed) { break; }

        if verbose {
            println!("  ▶  [{}/{}] {}", repo_idx + 1, selected_repo_count, repo.full_name);
        }

        // Get HEAD SHA for the default branch
        let _head_sha = match gl_forge.get_head_sha(repo, &repo.default_branch).await {
            Ok(s)  => s,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot resolve HEAD for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        // Fetch the full recursive tree
        let tree = match gl_forge.get_tree(repo, &repo.default_branch).await {
            Ok(t)  => t,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot get tree for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        let repo_workspace = if let Some(root) = save_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else if let Some(root) = temp_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else {
            continue;
        };
        let _ = std::fs::create_dir_all(&repo_workspace);

        // Reconstruct source workspace from tree blobs
        let blobs: Vec<_> = tree.into_iter()
            .filter(|e| e.obj_type == "blob")
            .filter(|e| e.size.is_none_or(|s| s <= max_blob_bytes as u64))
            .collect();

        if verbose && !blobs.is_empty() {
            println!("      Reconstructing {} files into workspace", blobs.len());
        }

        let reconstruct_stream = futures::stream::iter(blobs)
            .map(|entry| {
                let client          = gl_client.clone();
                let api_base        = api_base.clone();
                let owner           = repo.owner.clone();
                let name            = repo.name.clone();
                let workspace       = repo_workspace.clone();
                async move {
                    let data = match gitlab_api::get_blob_content(&client, &api_base, &owner, &name, &entry.sha).await {
                        Ok(d)  => d,
                        Err(_) => return false,
                    };
                    if data.len() > max_blob_bytes {
                        return false;
                    }
                    let rel = match normalize_repo_relative_path(&entry.path) {
                        Some(r) => r,
                        None => return false,
                    };
                    let local_path = workspace.join(rel);
                    if !local_path.starts_with(&workspace) {
                        return false;
                    }
                    if let Some(parent) = local_path.parent() {
                        if std::fs::create_dir_all(parent).is_err() {
                            return false;
                        }
                    }
                    std::fs::write(local_path, &data).is_ok()
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(reconstruct_stream);
        while let Some(ok) = reconstruct_stream.next().await {
            if !ok {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
            }
        }

        let mut candidates: Vec<PathBuf> = collect_local_files(&repo_workspace)
            .into_iter()
            .filter(|(p, size)| !is_binary_extension(&p.to_string_lossy()) && *size <= max_blob_bytes as u64)
            .map(|(p, _)| p)
            .collect();
        candidates.sort_by_key(|p| if streamer::is_ai_sensitive_path(&p.to_string_lossy()) { 0 } else { 1 });

        if verbose {
            println!("      Scanning {} workspace files", candidates.len());
        }

        let file_stream = futures::stream::iter(candidates)
            .map(|path| {
                let stop = stop_flag.clone();
                let extra_patterns = extra_pat_arc.clone();
                let root = repo_workspace.clone();
                let full_name = repo.full_name.clone();
                let entropy_thresh = args.entropy_threshold;
                async move {
                    if stop.load(Ordering::Relaxed) {
                        return (vec![], vec![], 0usize, false, true);
                    }
                    let data = match tokio::fs::read(&path).await {
                        Ok(d) => d,
                        Err(_) => return (vec![], vec![], 0usize, true, false),
                    };
                    if data.is_empty() {
                        return (vec![], vec![], 0usize, false, false);
                    }
                    let probe = &data[..data.len().min(BINARY_DETECTION_PROBE_SIZE)];
                    let null_count = probe.iter().filter(|&&b| b == 0).count();
                    if null_count > NULL_BYTE_THRESHOLD {
                        return (vec![], vec![], 0usize, false, false);
                    }

                    let text = String::from_utf8_lossy(&data);
                    let rel = path
                        .strip_prefix(&root)
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                    let source = format!("{}/{}", full_name, rel);
                    let findings = streamer::scan_text(&text, &source, &extra_patterns, entropy_thresh);

                    let mut techs = Vec::new();
                    detect_tech_from_path(&rel, &mut techs);

                    (findings, techs, data.len(), false, false)
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(file_stream);
        while let Some((findings, techs, bytes, failed, skipped_by_stop)) = file_stream.next().await {
            if skipped_by_stop {
                continue;
            }
            if failed {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if bytes > 0 {
                blobs_scanned.fetch_add(1, Ordering::Relaxed);
                bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
            }

            if !techs.is_empty() {
                let mut ts = tech_stack_set.lock().await;
                for t in techs { ts.insert(t); }
            }
            if findings.is_empty() { continue; }

            if args.live || args.pipe {
                for f in &findings {
                    println!("{}", serde_json::to_string(&f.to_dict()).unwrap_or_default());
                }
            }

            let mut all = all_findings.lock().await;
            all.extend(findings);

            if should_stop_scan(&all, args.max_findings, args.stop_on_critical) {
                stop_flag.store(true, Ordering::Relaxed);
                if verbose {
                    if args.max_findings > 0 && all.len() >= args.max_findings {
                        println!("\n  [!] Reached --max-findings limit. Stopping scan.");
                    } else {
                        println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                    }
                }
                break;
            }
        }
    }

    // SEC-004: temp_guard automatically cleans up when dropped at end of scope

    // ── 5. Assemble result ───────────────────────
    let elapsed_s   = t0.elapsed().as_secs_f64();
    let findings    = all_findings.lock().await.clone();
    let mut ts_vec: Vec<String> = tech_stack_set.lock().await.iter().cloned().collect();
    ts_vec.sort();

    let stream_r = StreamResult {
        findings,
        contributors:      vec![],
        tech_stack:        ts_vec,
        commit_count:      0,
        blobs_scanned:     blobs_scanned.load(Ordering::Relaxed),
        blobs_failed:      blobs_failed.load(Ordering::Relaxed),
        bytes_scanned:     bytes_scanned.load(Ordering::Relaxed),
        elapsed_s,
        files_saved:       0,
        files_save_failed: 0,
        cache_hits: 0,
        cache_misses: 0,
        cache_stats: None,
        rate_limit_allowed: 0,
        rate_limit_dropped: 0,
        rate_limit_wait_ms: 0,
    };

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    // ── 7. Save report ───────────────────────────
    let report_name = format!("gitlab_{}", login);
    let ext = match args.format.as_str() {
        "sarif"  => "sarif",
        "csv"    => "csv",
        "ndjson" => "ndjson",
        "md"     => "md",
        "html"   => "html",
        _        => "json",
    };
    let report_path = format!("{}/{}_report.{}", args.output, report_name, ext);

    let save_result = match args.format.as_str() {
        "sarif"  => rep.save_sarif(&report_path, &report_name, Some(&stream_r)),
        "csv"    => rep.save_csv(&report_path, Some(&stream_r)),
        "ndjson" => rep.save_ndjson(&report_path, Some(&stream_r)),
        "md"     => rep.save_markdown(&report_path, &report_name, Some(&stream_r)),
        "html"   => rep.save_html(&report_path, &report_name, Some(&stream_r)),
        _        => rep.save_token_report(&report_path, &login, selected_repo_count, &stream_r),
    };

    if let Err(e) = save_result {
        eprintln!("  ⚠   Could not save report: {}", e);
    }

    if verbose && !args.pipe {
        rep.print_token_report(&login, selected_repo_count, &stream_r, &report_path);
    }

    // ── 8. Webhook delivery ──────────────────────
    if let Some(ref webhook_url) = args.webhook {
        if let Ok(json_body) = std::fs::read_to_string(&report_path) {
            if let Ok(plain_cfg) = build_plain_http_config(args) {
                if let Ok(plain_client) = HttpClient::new(plain_cfg) {
                    let sent = rep.send_webhook(
                        webhook_url,
                        args.webhook_secret.as_deref(),
                        &json_body,
                        &plain_client,
                    ).await;
                    if verbose {
                        if sent { println!("  ✔   Webhook delivered to {}", webhook_url); }
                        else    { eprintln!("  ⚠   Webhook delivery failed"); }
                    }
                }
            }
        }
    }

    // ── 9. Pipe mode summary ─────────────────────
    if args.pipe {
        let summary = serde_json::json!({
            "type":     "summary",
            "mode":     "gitlab_token",
            "user":     login,
            "repos":    selected_repo_count,
            "findings": stream_r.findings.len(),
            "risk_score": stream_r.risk_score(),
        });
        println!("{}", serde_json::to_string(&summary).unwrap_or_default());
    }

    if verbose && !args.pipe {
        println!("  ✔  Done\n");
    }
}

/// Prompt for GitLab repository selection.
fn prompt_gitlab_repo_selection(repos: &[gitlab_api::GlProject]) -> Vec<usize> {
    println!("  ◈  Pilih repository yang ingin di-scan:");
    for (idx, repo) in repos.iter().enumerate() {
        println!("      {:>4}. {}", idx + 1, repo.full_name);
    }
    println!("      Input: satu nomor (contoh: 3), banyak nomor (1,3,7), atau all");

    loop {
        match prompt_line("  > Pilihan repo: ") {
            Ok(input) => match parse_repo_selection_input(&input, repos.len()) {
                Ok(v) => return v,
                Err(msg) => eprintln!("  ✘  {} Coba lagi.", msg),
            },
            Err(_) => {
                eprintln!("  ⚠   Input tidak tersedia, default ke all.");
                return (0..repos.len()).collect();
            }
        }
    }
}

/// Prompt for Bitbucket repository selection.
fn prompt_bitbucket_repo_selection(repos: &[bitbucket_api::BbRepo]) -> Vec<usize> {
    println!("  ◈  Pilih repository yang ingin di-scan:");
    for (idx, repo) in repos.iter().enumerate() {
        println!("      {:>4}. {}", idx + 1, repo.full_name);
    }
    println!("      Input: satu nomor (contoh: 3), banyak nomor (1,3,7), atau all");

    loop {
        match prompt_line("  > Pilihan repo: ") {
            Ok(input) => match parse_repo_selection_input(&input, repos.len()) {
                Ok(v) => return v,
                Err(msg) => eprintln!("  ✘  {} Coba lagi.", msg),
            },
            Err(_) => {
                eprintln!("  ⚠   Input tidak tersedia, default ke all.");
                return (0..repos.len()).collect();
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run_bitbucket_token_scan(
    args:           &Cli,
    rep:            &Reporter,
    base_cfg:       HttpConfig,
    token:          &str,
    bitbucket_url:  Option<&str>,
    extra_patterns: Vec<streamer::DynPattern>,
) {
    let quiet   = args.quiet || args.pipe;
    let verbose = !quiet;

    // SEC-001: Validate Bitbucket token format (App Password)
    // Bitbucket App Passwords are typically 16-24 characters alphanumeric
    if token.len() < 16 {
        eprintln!("  ⚠   Bitbucket App Password should be at least 16 characters");
    }

    if !quiet {
        rep.banner();
        println!("  Mode  : Bitbucket Token Scan");
        if let Some(url) = bitbucket_url {
            println!("  Instance: {}", url);
        }
        println!("  Output: {}\n", args.output);
    }

    // ── 1. Build Bitbucket API client ───────────────
    let (bb_client, api_base) = match bitbucket_api::build_bitbucket_client(base_cfg, token, bitbucket_url) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("  ✘  Failed to build Bitbucket API client: {}", e);
            std::process::exit(1);
        }
    };

    // ── 2. Authenticate ──────────────────────────
    if verbose { println!("  ◈  Authenticating with Bitbucket API..."); }
    let mut bb_forge = bitbucket_api::BitbucketForgeClient::new(bb_client.clone(), api_base.clone());

    match bb_forge.authenticate(token).await {
        Ok(_) => {},
        Err(e) => {
            eprintln!("  ✘  Authentication failed: {}", e);
            std::process::exit(1);
        }
    }

    let (login, _name) = match bb_forge.whoami().await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Failed to get user info: {}", e);
            std::process::exit(1);
        }
    };

    if verbose { println!("  ✔  Authenticated as: {}\n", login.cyan().bold()); }

    // ── 3. Enumerate repositories ────────────────
    if verbose { println!("  ◈  Enumerating repositories..."); }

    let all_repos = match bb_forge.enumerate_repos(forge::EnumScope::All).await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Failed to list repositories: {}", e);
            std::process::exit(1);
        }
    };

    let total_repos = all_repos.len();
    if total_repos == 0 {
        if verbose {
            println!("  ⚠   Tidak ada repository yang bisa di-scan.\n");
        }
        return;
    }

    if verbose { println!("  ✔  Found {} repositories\n", total_repos); }

    let interactive = !args.quiet && !args.pipe;

    // Convert to a displayable format for selection
    let bb_repos: Vec<bitbucket_api::BbRepo> = all_repos.iter().map(|r| {
        bitbucket_api::BbRepo {
            full_name: r.full_name.clone(),
            owner: r.owner.clone(),
            name: r.name.clone(),
            private: r.private,
            default_branch: r.default_branch.clone(),
            clone_url: r.clone_url.clone(),
        }
    }).collect();

    let selected_indexes = if interactive {
        prompt_bitbucket_repo_selection(&bb_repos)
    } else {
        (0..bb_repos.len()).collect()
    };

    let selected_repos: Vec<forge::Repository> = selected_indexes
        .into_iter()
        .filter_map(|i| all_repos.get(i).cloned())
        .collect();

    let selected_repo_count = selected_repos.len();
    if selected_repo_count == 0 {
        eprintln!("  ✘  Tidak ada repository valid yang dipilih.");
        return;
    }

    if verbose {
        println!("  ✔  Selected {} repositories for scanning", selected_repo_count);
    }

    let persist_source = if interactive {
        prompt_save_choice(args.save)
    } else {
        args.save
    };

    if verbose {
        println!(
            "  ◈  Source persistence: {}\n",
            if persist_source { "enabled (--save behavior)" } else { "disabled (temporary workspace)" }
        );
    }

    // ── 4. Acquire source workspace and scan selected repositories ─────
    let t0              = Instant::now();
    let all_findings    = Arc::new(tokio::sync::Mutex::new(Vec::<streamer::Finding>::new()));
    let tech_stack_set  = Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::<String>::new()));
    let blobs_scanned   = Arc::new(AtomicUsize::new(0));
    let blobs_failed    = Arc::new(AtomicUsize::new(0));
    let bytes_scanned   = Arc::new(AtomicUsize::new(0));
    let stop_flag       = Arc::new(AtomicBool::new(false));

    let max_blob_bytes = args.max_blob_size * 1024 * 1024;
    let extra_pat_arc  = Arc::new(extra_patterns);
    let save_root      = if persist_source {
        Some(std::path::PathBuf::from(&args.output).join(format!("bitbucket_{}", login)))
    } else {
        None
    };

    // SEC-004: RAII guard for temp workspace
    let temp_guard: Option<TempDirGuard> = if persist_source {
        None
    } else {
        let p = std::env::temp_dir().join(format!(
            "gitrecon_bitbucket_scan_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&p);
        Some(TempDirGuard::new(p))
    };
    let temp_root = temp_guard.as_ref().and_then(|g| g.path().map(|p| p.to_path_buf()));

    // Ensure temp_guard stays alive for the entire scan
    let _temp_guard = temp_guard;

    for (repo_idx, repo) in selected_repos.iter().enumerate() {
        if stop_flag.load(Ordering::Relaxed) { break; }

        if verbose {
            println!("  ▶  [{}/{}] {}", repo_idx + 1, selected_repo_count, repo.full_name);
        }

        // Get HEAD SHA for the default branch
        let head_sha = match bb_forge.get_head_sha(repo, &repo.default_branch).await {
            Ok(s)  => s,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot resolve HEAD for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        // Fetch the full recursive tree
        let tree = match bb_forge.get_tree(repo, &repo.default_branch).await {
            Ok(t)  => t,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot get tree for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        let repo_workspace = if let Some(root) = save_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else if let Some(root) = temp_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else {
            continue;
        };
        let _ = std::fs::create_dir_all(&repo_workspace);

        // Reconstruct source workspace from tree blobs
        let blobs: Vec<_> = tree.into_iter()
            .filter(|e| e.obj_type == "blob")
            .filter(|e| e.size.is_none_or(|s| s <= max_blob_bytes as u64))
            .collect();

        if verbose && !blobs.is_empty() {
            println!("      Reconstructing {} files into workspace", blobs.len());
        }

        let reconstruct_stream = futures::stream::iter(blobs)
            .map(|entry| {
                let client          = bb_client.clone();
                let api_base        = api_base.clone();
                let owner           = repo.owner.clone();
                let name            = repo.name.clone();
                let workspace       = repo_workspace.clone();
                let commit_sha      = head_sha.clone();
                async move {
                    // Bitbucket requires file path to fetch content
                    let data = match bitbucket_api::get_file_by_path(&client, &api_base, &owner, &name, &commit_sha, &entry.path).await {
                        Ok(d)  => d,
                        Err(_) => return false,
                    };
                    if data.len() > max_blob_bytes {
                        return false;
                    }
                    let rel = match normalize_repo_relative_path(&entry.path) {
                        Some(r) => r,
                        None => return false,
                    };
                    let local_path = workspace.join(rel);
                    if !local_path.starts_with(&workspace) {
                        return false;
                    }
                    if let Some(parent) = local_path.parent() {
                        if std::fs::create_dir_all(parent).is_err() {
                            return false;
                        }
                    }
                    std::fs::write(local_path, &data).is_ok()
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(reconstruct_stream);
        while let Some(ok) = reconstruct_stream.next().await {
            if !ok {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
            }
        }

        let mut candidates: Vec<PathBuf> = collect_local_files(&repo_workspace)
            .into_iter()
            .filter(|(p, size)| !is_binary_extension(&p.to_string_lossy()) && *size <= max_blob_bytes as u64)
            .map(|(p, _)| p)
            .collect();
        candidates.sort_by_key(|p| if streamer::is_ai_sensitive_path(&p.to_string_lossy()) { 0 } else { 1 });

        if verbose {
            println!("      Scanning {} workspace files", candidates.len());
        }

        let file_stream = futures::stream::iter(candidates)
            .map(|path| {
                let stop = stop_flag.clone();
                let extra_patterns = extra_pat_arc.clone();
                let root = repo_workspace.clone();
                let full_name = repo.full_name.clone();
                let entropy_thresh = args.entropy_threshold;
                async move {
                    if stop.load(Ordering::Relaxed) {
                        return (vec![], vec![], 0usize, false, true);
                    }
                    let data = match tokio::fs::read(&path).await {
                        Ok(d) => d,
                        Err(_) => return (vec![], vec![], 0usize, true, false),
                    };
                    if data.is_empty() {
                        return (vec![], vec![], 0usize, false, false);
                    }
                    let probe = &data[..data.len().min(BINARY_DETECTION_PROBE_SIZE)];
                    let null_count = probe.iter().filter(|&&b| b == 0).count();
                    if null_count > NULL_BYTE_THRESHOLD {
                        return (vec![], vec![], 0usize, false, false);
                    }

                    let text = String::from_utf8_lossy(&data);
                    let rel = path
                        .strip_prefix(&root)
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                    let source = format!("{}/{}", full_name, rel);
                    let findings = streamer::scan_text(&text, &source, &extra_patterns, entropy_thresh);

                    let mut techs = Vec::new();
                    detect_tech_from_path(&rel, &mut techs);

                    (findings, techs, data.len(), false, false)
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(file_stream);
        while let Some((findings, techs, bytes, failed, skipped_by_stop)) = file_stream.next().await {
            if skipped_by_stop {
                continue;
            }
            if failed {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if bytes > 0 {
                blobs_scanned.fetch_add(1, Ordering::Relaxed);
                bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
            }

            if !techs.is_empty() {
                let mut ts = tech_stack_set.lock().await;
                for t in techs { ts.insert(t); }
            }
            if findings.is_empty() { continue; }

            if args.live || args.pipe {
                for f in &findings {
                    println!("{}", serde_json::to_string(&f.to_dict()).unwrap_or_default());
                }
            }

            let mut all = all_findings.lock().await;
            all.extend(findings);

            if should_stop_scan(&all, args.max_findings, args.stop_on_critical) {
                stop_flag.store(true, Ordering::Relaxed);
                if verbose {
                    if args.max_findings > 0 && all.len() >= args.max_findings {
                        println!("\n  [!] Reached --max-findings limit. Stopping scan.");
                    } else {
                        println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                    }
                }
                break;
            }
        }
    }

    // SEC-004: temp_guard automatically cleans up when dropped at end of scope

    // ── 5. Assemble result ───────────────────────
    let elapsed_s   = t0.elapsed().as_secs_f64();
    let findings    = all_findings.lock().await.clone();
    let mut ts_vec: Vec<String> = tech_stack_set.lock().await.iter().cloned().collect();
    ts_vec.sort();

    let stream_r = StreamResult {
        findings,
        contributors:      vec![],
        tech_stack:        ts_vec,
        commit_count:      0,
        blobs_scanned:     blobs_scanned.load(Ordering::Relaxed),
        blobs_failed:      blobs_failed.load(Ordering::Relaxed),
        bytes_scanned:     bytes_scanned.load(Ordering::Relaxed),
        elapsed_s,
        files_saved:       0,
        files_save_failed: 0,
        cache_hits: 0,
        cache_misses: 0,
        cache_stats: None,
        rate_limit_allowed: 0,
        rate_limit_dropped: 0,
        rate_limit_wait_ms: 0,
    };

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    // ── 7. Save report ───────────────────────────
    let report_name = format!("bitbucket_{}", login);
    let ext = match args.format.as_str() {
        "sarif"  => "sarif",
        "csv"    => "csv",
        "ndjson" => "ndjson",
        "md"     => "md",
        "html"   => "html",
        _        => "json",
    };
    let report_path = format!("{}/{}_report.{}", args.output, report_name, ext);

    let save_result = match args.format.as_str() {
        "sarif"  => rep.save_sarif(&report_path, &report_name, Some(&stream_r)),
        "csv"    => rep.save_csv(&report_path, Some(&stream_r)),
        "ndjson" => rep.save_ndjson(&report_path, Some(&stream_r)),
        "md"     => rep.save_markdown(&report_path, &report_name, Some(&stream_r)),
        "html"   => rep.save_html(&report_path, &report_name, Some(&stream_r)),
        _        => rep.save_token_report(&report_path, &login, selected_repo_count, &stream_r),
    };

    if let Err(e) = save_result {
        eprintln!("  ⚠   Could not save report: {}", e);
    }

    if verbose && !args.pipe {
        rep.print_token_report(&login, selected_repo_count, &stream_r, &report_path);
    }

    // ── 8. Webhook delivery ──────────────────────
    if let Some(ref webhook_url) = args.webhook {
        if let Ok(json_body) = std::fs::read_to_string(&report_path) {
            if let Ok(plain_cfg) = build_plain_http_config(args) {
                if let Ok(plain_client) = HttpClient::new(plain_cfg) {
                    let sent = rep.send_webhook(
                        webhook_url,
                        args.webhook_secret.as_deref(),
                        &json_body,
                        &plain_client,
                    ).await;
                    if verbose {
                        if sent { println!("  ✔   Webhook delivered to {}", webhook_url); }
                        else    { eprintln!("  ⚠   Webhook delivery failed"); }
                    }
                }
            }
        }
    }

    // ── 9. Pipe mode summary ─────────────────────
    if args.pipe {
        let summary = serde_json::json!({
            "type":     "summary",
            "mode":     "bitbucket_token",
            "user":     login,
            "repos":    selected_repo_count,
            "findings": stream_r.findings.len(),
            "risk_score": stream_r.risk_score(),
        });
        println!("{}", serde_json::to_string(&summary).unwrap_or_default());
    }

    if verbose && !args.pipe {
        println!("  ✔  Done\n");
    }
}

/// Prompt for Gitea repository selection.
fn prompt_gitea_repo_selection(repos: &[gitea_api::GtRepo]) -> Vec<usize> {
    println!("  ◈  Pilih repository yang ingin di-scan:");
    for (idx, repo) in repos.iter().enumerate() {
        println!("      {:>4}. {}", idx + 1, repo.full_name);
    }
    println!("      Input: satu nomor (contoh: 3), banyak nomor (1,3,7), atau all");

    loop {
        match prompt_line("  > Pilihan repo: ") {
            Ok(input) => match parse_repo_selection_input(&input, repos.len()) {
                Ok(v) => return v,
                Err(msg) => eprintln!("  ✘  {} Coba lagi.", msg),
            },
            Err(_) => {
                eprintln!("  ⚠   Input tidak tersedia, default ke all.");
                return (0..repos.len()).collect();
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run_gitea_token_scan(
    args:           &Cli,
    rep:            &Reporter,
    base_cfg:       HttpConfig,
    token:          &str,
    gitea_url:      Option<&str>,
    extra_patterns: Vec<streamer::DynPattern>,
) {
    let quiet   = args.quiet || args.pipe;
    let verbose = !quiet;

    // SEC-001: Validate Gitea token format
    // Gitea tokens vary by instance type (user tokens, app tokens, OAuth tokens)
    if token.len() < 10 {
        eprintln!("  ⚠   Gitea token appears too short (minimum 10 characters expected)");
    }

    if !quiet {
        rep.banner();
        println!("  Mode  : Gitea/Forgejo Token Scan");
        if let Some(url) = gitea_url {
            println!("  Instance: {}", url);
        }
        println!("  Output: {}\n", args.output);
    }

    // ── 1. Build Gitea API client ───────────────
    let (gt_client, api_base) = match gitea_api::build_gitea_client(base_cfg, token, gitea_url) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("  ✘  Failed to build Gitea API client: {}", e);
            std::process::exit(1);
        }
    };

    // ── 2. Authenticate ──────────────────────────
    if verbose { println!("  ◈  Authenticating with Gitea API..."); }
    let mut gt_forge = gitea_api::GiteaForgeClient::new(gt_client.clone(), api_base.clone());

    match gt_forge.authenticate(token).await {
        Ok(_) => {},
        Err(e) => {
            eprintln!("  ✘  Authentication failed: {}", e);
            std::process::exit(1);
        }
    }

    let (login, _name) = match gt_forge.whoami().await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Failed to get user info: {}", e);
            std::process::exit(1);
        }
    };

    if verbose { println!("  ✔  Authenticated as: {}\n", login.cyan().bold()); }

    // ── 3. Enumerate repositories ────────────────
    if verbose { println!("  ◈  Enumerating repositories..."); }

    let all_repos = match gt_forge.enumerate_repos(forge::EnumScope::All).await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Failed to list repositories: {}", e);
            std::process::exit(1);
        }
    };

    let total_repos = all_repos.len();
    if total_repos == 0 {
        if verbose {
            println!("  ⚠   Tidak ada repository yang bisa di-scan.\n");
        }
        return;
    }

    if verbose { println!("  ✔  Found {} repositories\n", total_repos); }

    let interactive = !args.quiet && !args.pipe;

    // Convert to a displayable format for selection
    let gt_repos: Vec<gitea_api::GtRepo> = all_repos.iter().map(|r| {
        gitea_api::GtRepo {
            full_name: r.full_name.clone(),
            owner: r.owner.clone(),
            name: r.name.clone(),
            private: r.private,
            default_branch: r.default_branch.clone(),
            clone_url: r.clone_url.clone(),
        }
    }).collect();

    let selected_indexes = if interactive {
        prompt_gitea_repo_selection(&gt_repos)
    } else {
        (0..gt_repos.len()).collect()
    };

    let selected_repos: Vec<forge::Repository> = selected_indexes
        .into_iter()
        .filter_map(|i| all_repos.get(i).cloned())
        .collect();

    let selected_repo_count = selected_repos.len();
    if selected_repo_count == 0 {
        eprintln!("  ✘  Tidak ada repository valid yang dipilih.");
        return;
    }

    if verbose {
        println!("  ✔  Selected {} repositories for scanning", selected_repo_count);
    }

    let persist_source = if interactive {
        prompt_save_choice(args.save)
    } else {
        args.save
    };

    if verbose {
        println!(
            "  ◈  Source persistence: {}\n",
            if persist_source { "enabled (--save behavior)" } else { "disabled (temporary workspace)" }
        );
    }

    // ── 4. Acquire source workspace and scan selected repositories ─────
    let t0              = Instant::now();
    let all_findings    = Arc::new(tokio::sync::Mutex::new(Vec::<streamer::Finding>::new()));
    let tech_stack_set  = Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::<String>::new()));
    let blobs_scanned   = Arc::new(AtomicUsize::new(0));
    let blobs_failed    = Arc::new(AtomicUsize::new(0));
    let bytes_scanned   = Arc::new(AtomicUsize::new(0));
    let stop_flag       = Arc::new(AtomicBool::new(false));

    let max_blob_bytes = args.max_blob_size * 1024 * 1024;
    let extra_pat_arc  = Arc::new(extra_patterns);
    let save_root      = if persist_source {
        Some(std::path::PathBuf::from(&args.output).join(format!("gitea_{}", login)))
    } else {
        None
    };

    // SEC-004: RAII guard for temp workspace
    let temp_guard: Option<TempDirGuard> = if persist_source {
        None
    } else {
        let p = std::env::temp_dir().join(format!(
            "gitrecon_gitea_scan_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&p);
        Some(TempDirGuard::new(p))
    };
    let temp_root = temp_guard.as_ref().and_then(|g| g.path().map(|p| p.to_path_buf()));

    // Ensure temp_guard stays alive for the entire scan
    let _temp_guard = temp_guard;

    for (repo_idx, repo) in selected_repos.iter().enumerate() {
        if stop_flag.load(Ordering::Relaxed) { break; }

        if verbose {
            println!("  ▶  [{}/{}] {}", repo_idx + 1, selected_repo_count, repo.full_name);
        }

        // Get HEAD SHA for the default branch
        let _head_sha = match gt_forge.get_head_sha(repo, &repo.default_branch).await {
            Ok(s)  => s,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot resolve HEAD for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        // Fetch the full recursive tree
        let tree = match gt_forge.get_tree(repo, &repo.default_branch).await {
            Ok(t)  => t,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot get tree for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        let repo_workspace = if let Some(root) = save_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else if let Some(root) = temp_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else {
            continue;
        };
        let _ = std::fs::create_dir_all(&repo_workspace);

        // Reconstruct source workspace from tree blobs
        let blobs: Vec<_> = tree.into_iter()
            .filter(|e| e.obj_type == "blob")
            .filter(|e| e.size.is_none_or(|s| s <= max_blob_bytes as u64))
            .collect();

        if verbose && !blobs.is_empty() {
            println!("      Reconstructing {} files into workspace", blobs.len());
        }

        let reconstruct_stream = futures::stream::iter(blobs)
            .map(|entry| {
                let client          = gt_client.clone();
                let api_base        = api_base.clone();
                let owner           = repo.owner.clone();
                let name            = repo.name.clone();
                let workspace       = repo_workspace.clone();
                async move {
                    let data = match gitea_api::get_blob_content(&client, &api_base, &owner, &name, &entry.sha).await {
                        Ok(d)  => d,
                        Err(_) => return false,
                    };
                    if data.len() > max_blob_bytes {
                        return false;
                    }
                    let rel = match normalize_repo_relative_path(&entry.path) {
                        Some(r) => r,
                        None => return false,
                    };
                    let local_path = workspace.join(rel);
                    if !local_path.starts_with(&workspace) {
                        return false;
                    }
                    if let Some(parent) = local_path.parent() {
                        if std::fs::create_dir_all(parent).is_err() {
                            return false;
                        }
                    }
                    std::fs::write(local_path, &data).is_ok()
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(reconstruct_stream);
        while let Some(ok) = reconstruct_stream.next().await {
            if !ok {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
            }
        }

        let mut candidates: Vec<PathBuf> = collect_local_files(&repo_workspace)
            .into_iter()
            .filter(|(p, size)| !is_binary_extension(&p.to_string_lossy()) && *size <= max_blob_bytes as u64)
            .map(|(p, _)| p)
            .collect();
        candidates.sort_by_key(|p| if streamer::is_ai_sensitive_path(&p.to_string_lossy()) { 0 } else { 1 });

        if verbose {
            println!("      Scanning {} workspace files", candidates.len());
        }

        let file_stream = futures::stream::iter(candidates)
            .map(|path| {
                let stop = stop_flag.clone();
                let extra_patterns = extra_pat_arc.clone();
                let root = repo_workspace.clone();
                let full_name = repo.full_name.clone();
                let entropy_thresh = args.entropy_threshold;
                async move {
                    if stop.load(Ordering::Relaxed) {
                        return (vec![], vec![], 0usize, false, true);
                    }
                    let data = match tokio::fs::read(&path).await {
                        Ok(d) => d,
                        Err(_) => return (vec![], vec![], 0usize, true, false),
                    };
                    if data.is_empty() {
                        return (vec![], vec![], 0usize, false, false);
                    }
                    let probe = &data[..data.len().min(BINARY_DETECTION_PROBE_SIZE)];
                    let null_count = probe.iter().filter(|&&b| b == 0).count();
                    if null_count > NULL_BYTE_THRESHOLD {
                        return (vec![], vec![], 0usize, false, false);
                    }

                    let text = String::from_utf8_lossy(&data);
                    let rel = path
                        .strip_prefix(&root)
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                    let source = format!("{}/{}", full_name, rel);
                    let findings = streamer::scan_text(&text, &source, &extra_patterns, entropy_thresh);

                    let mut techs = Vec::new();
                    detect_tech_from_path(&rel, &mut techs);

                    (findings, techs, data.len(), false, false)
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(file_stream);
        while let Some((findings, techs, bytes, failed, skipped_by_stop)) = file_stream.next().await {
            if skipped_by_stop {
                continue;
            }
            if failed {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if bytes > 0 {
                blobs_scanned.fetch_add(1, Ordering::Relaxed);
                bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
            }

            if !techs.is_empty() {
                let mut ts = tech_stack_set.lock().await;
                for t in techs { ts.insert(t); }
            }
            if findings.is_empty() { continue; }

            if args.live || args.pipe {
                for f in &findings {
                    println!("{}", serde_json::to_string(&f.to_dict()).unwrap_or_default());
                }
            }

            let mut all = all_findings.lock().await;
            all.extend(findings);

            if should_stop_scan(&all, args.max_findings, args.stop_on_critical) {
                stop_flag.store(true, Ordering::Relaxed);
                if verbose {
                    if args.max_findings > 0 && all.len() >= args.max_findings {
                        println!("\n  [!] Reached --max-findings limit. Stopping scan.");
                    } else {
                        println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                    }
                }
                break;
            }
        }
    }

    // SEC-004: temp_guard automatically cleans up when dropped at end of scope

    // ── 5. Assemble result ───────────────────────
    let elapsed_s   = t0.elapsed().as_secs_f64();
    let findings    = all_findings.lock().await.clone();
    let mut ts_vec: Vec<String> = tech_stack_set.lock().await.iter().cloned().collect();
    ts_vec.sort();

    let stream_r = StreamResult {
        findings,
        contributors:      vec![],
        tech_stack:        ts_vec,
        commit_count:      0,
        blobs_scanned:     blobs_scanned.load(Ordering::Relaxed),
        blobs_failed:      blobs_failed.load(Ordering::Relaxed),
        bytes_scanned:     bytes_scanned.load(Ordering::Relaxed),
        elapsed_s,
        files_saved:       0,
        files_save_failed: 0,
        cache_hits: 0,
        cache_misses: 0,
        cache_stats: None,
        rate_limit_allowed: 0,
        rate_limit_dropped: 0,
        rate_limit_wait_ms: 0,
    };

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    // ── 7. Save report ───────────────────────────
    let report_name = format!("gitea_{}", login);
    let ext = match args.format.as_str() {
        "sarif"  => "sarif",
        "csv"    => "csv",
        "ndjson" => "ndjson",
        "md"     => "md",
        "html"   => "html",
        _        => "json",
    };
    let report_path = format!("{}/{}_report.{}", args.output, report_name, ext);

    let save_result = match args.format.as_str() {
        "sarif"  => rep.save_sarif(&report_path, &report_name, Some(&stream_r)),
        "csv"    => rep.save_csv(&report_path, Some(&stream_r)),
        "ndjson" => rep.save_ndjson(&report_path, Some(&stream_r)),
        "md"     => rep.save_markdown(&report_path, &report_name, Some(&stream_r)),
        "html"   => rep.save_html(&report_path, &report_name, Some(&stream_r)),
        _        => rep.save_token_report(&report_path, &login, selected_repo_count, &stream_r),
    };

    if let Err(e) = save_result {
        eprintln!("  ⚠   Could not save report: {}", e);
    }

    if verbose && !args.pipe {
        rep.print_token_report(&login, selected_repo_count, &stream_r, &report_path);
    }

    // ── 8. Webhook delivery ──────────────────────
    if let Some(ref webhook_url) = args.webhook {
        if let Ok(json_body) = std::fs::read_to_string(&report_path) {
            if let Ok(plain_cfg) = build_plain_http_config(args) {
                if let Ok(plain_client) = HttpClient::new(plain_cfg) {
                    let sent = rep.send_webhook(
                        webhook_url,
                        args.webhook_secret.as_deref(),
                        &json_body,
                        &plain_client,
                    ).await;
                    if verbose {
                        if sent { println!("  ✔   Webhook delivered to {}", webhook_url); }
                        else    { eprintln!("  ⚠   Webhook delivery failed"); }
                    }
                }
            }
        }
    }

    // ── 9. Pipe mode summary ─────────────────────
    if args.pipe {
        let summary = serde_json::json!({
            "type":     "summary",
            "mode":     "gitea_token",
            "user":     login,
            "repos":    selected_repo_count,
            "findings": stream_r.findings.len(),
            "risk_score": stream_r.risk_score(),
        });
        println!("{}", serde_json::to_string(&summary).unwrap_or_default());
    }

    if verbose && !args.pipe {
        println!("  ✔  Done\n");
    }
}

#[allow(clippy::too_many_lines)]
async fn run_azure_token_scan(
    args:           &Cli,
    rep:            &Reporter,
    base_cfg:       HttpConfig,
    token:          &str,
    azure_url:      Option<&str>,
    extra_patterns: Vec<streamer::DynPattern>,
) {
    let quiet   = args.quiet || args.pipe;
    let verbose = !quiet;

    // SEC-001: Validate Azure DevOps token format
    // Azure DevOps PATs are base64-like strings, typically 40-52+ characters
    if token.len() < 30 {
        eprintln!("  ⚠   Azure DevOps token appears too short (minimum 30 characters expected)");
    }

    if !quiet {
        rep.banner();
        println!("  Mode  : Azure DevOps Token Scan");
        if let Some(url) = azure_url {
            println!("  Instance: {}", url);
        }
        println!("  Output: {}\n", args.output);
    }

    // ── 1. Build Azure DevOps API client ───────────────
    let (az_client, api_base) = match azure_api::build_azure_client(base_cfg, token, azure_url) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("  ✘  Failed to build Azure DevOps API client: {}", e);
            std::process::exit(1);
        }
    };

    // ── 2. Authenticate ──────────────────────────
    if verbose { println!("  ◈  Authenticating with Azure DevOps API..."); }
    let mut az_forge = azure_api::AzureForgeClient::new(az_client.clone(), api_base.clone());

    match az_forge.authenticate(token).await {
        Ok(_) => {},
        Err(e) => {
            eprintln!("  ✘  Authentication failed: {}", e);
            std::process::exit(1);
        }
    }

    let (login, _name) = match az_forge.whoami().await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Failed to get user info: {}", e);
            std::process::exit(1);
        }
    };

    if verbose { println!("  ✔  Authenticated as: {}\n", login.cyan().bold()); }

    // ── 3. Enumerate repositories ────────────────
    if verbose { println!("  ◈  Enumerating repositories..."); }

    let all_repos = match az_forge.enumerate_repos(forge::EnumScope::All).await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("  ✘  Failed to list repositories: {}", e);
            eprintln!("  →  For Azure DevOps, you may need to specify the organization/project.");
            eprintln!("  →  Use --azure-url https://dev.azure.com/{{org}} for a specific organization.");
            std::process::exit(1);
        }
    };

    let total_repos = all_repos.len();
    if total_repos == 0 {
        if verbose {
            println!("  ⚠   No accessible repositories found.\n");
            println!("  →  Azure DevOps requires organization context. Try specifying:");
            println!("  →  --azure-url https://dev.azure.com/{{org}}");
            println!("  →  For on-premise: --azure-url https://{{server}}/{{collection}}");
        }
        return;
    }

    if verbose { println!("  ✔  Found {} repositories\n", total_repos); }

    let interactive = !args.quiet && !args.pipe;

    // Convert to a displayable format for selection
    let az_repos: Vec<azure_api::AzRepo> = all_repos.iter().map(|r| {
        azure_api::AzRepo {
            id: r.full_name.clone(),
            name: r.name.clone(),
            private: r.private,
            default_branch: r.default_branch.clone(),
            clone_url: r.clone_url.clone(),
            description: r.description.clone(),
            updated_at: r.updated_at.clone(),
        }
    }).collect();

    let selected_indexes = if interactive {
        prompt_azure_repo_selection(&az_repos)
    } else {
        (0..az_repos.len()).collect()
    };

    let selected_repos: Vec<forge::Repository> = selected_indexes
        .into_iter()
        .filter_map(|i| all_repos.get(i).cloned())
        .collect();

    let selected_repo_count = selected_repos.len();
    if selected_repo_count == 0 {
        eprintln!("  ✘  No valid repositories selected.");
        return;
    }

    if verbose {
        println!("  ✔  Selected {} repositories for scanning", selected_repo_count);
    }

    let persist_source = if interactive {
        prompt_save_choice(args.save)
    } else {
        args.save
    };

    if verbose {
        println!(
            "  ◈  Source persistence: {}\n",
            if persist_source { "enabled (--save behavior)" } else { "disabled (temporary workspace)" }
        );
    }

    // ── 4. Acquire source workspace and scan selected repositories ─────
    let t0              = Instant::now();
    let all_findings    = Arc::new(tokio::sync::Mutex::new(Vec::<streamer::Finding>::new()));
    let tech_stack_set  = Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::<String>::new()));
    let blobs_scanned   = Arc::new(AtomicUsize::new(0));
    let blobs_failed    = Arc::new(AtomicUsize::new(0));
    let bytes_scanned   = Arc::new(AtomicUsize::new(0));
    let stop_flag       = Arc::new(AtomicBool::new(false));

    let max_blob_bytes = args.max_blob_size * 1024 * 1024;
    let extra_pat_arc  = Arc::new(extra_patterns);
    let save_root      = if persist_source {
        Some(std::path::PathBuf::from(&args.output).join(format!("azure_{}", login)))
    } else {
        None
    };

    // SEC-004: RAII guard for temp workspace
    let temp_guard: Option<TempDirGuard> = if persist_source {
        None
    } else {
        let p = std::env::temp_dir().join(format!(
            "gitrecon_azure_scan_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&p);
        Some(TempDirGuard::new(p))
    };
    let temp_root = temp_guard.as_ref().and_then(|g| g.path().map(|p| p.to_path_buf()));

    // Ensure temp_guard stays alive for the entire scan
    let _temp_guard = temp_guard;

    for (repo_idx, repo) in selected_repos.iter().enumerate() {
        if stop_flag.load(Ordering::Relaxed) { break; }

        if verbose {
            println!("  ▶  [{}/{}] {}", repo_idx + 1, selected_repo_count, repo.full_name);
        }

        // Get HEAD SHA for the default branch
        let _head_sha = match az_forge.get_head_sha(repo, &repo.default_branch).await {
            Ok(s)  => s,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot resolve HEAD for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        // Fetch the full recursive tree
        let tree = match az_forge.get_tree(repo, &repo.default_branch).await {
            Ok(t)  => t,
            Err(e) => {
                if verbose {
                    eprintln!("    ⚠   Cannot get tree for {}: {}", repo.full_name, e);
                }
                continue;
            }
        };

        let repo_workspace = if let Some(root) = save_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else if let Some(root) = temp_root.as_ref() {
            root.join(repo.full_name.replace('/', "_"))
        } else {
            continue;
        };
        let _ = std::fs::create_dir_all(&repo_workspace);

        // Reconstruct source workspace from tree blobs
        let blobs: Vec<_> = tree.into_iter()
            .filter(|e| e.obj_type == "blob")
            .filter(|e| e.size.is_none_or(|s| s <= max_blob_bytes as u64))
            .collect();

        if verbose && !blobs.is_empty() {
            println!("      Reconstructing {} files into workspace", blobs.len());
        }

        let reconstruct_stream = futures::stream::iter(blobs)
            .map(|entry| {
                let client          = az_client.clone();
                let api_base        = api_base.clone();
                let repo_id         = repo.full_name.clone();
                let workspace       = repo_workspace.clone();
                let entry_path      = entry.path.clone();
                let entry_sha        = entry.sha.clone();
                async move {
                    let data = match azure_api::get_blob_content(&client, &api_base, &repo_id, &entry_sha).await {
                        Ok(d)  => d,
                        Err(_) => return false,
                    };
                    if data.len() > max_blob_bytes {
                        return false;
                    }
                    let rel = match normalize_repo_relative_path(&entry_path) {
                        Some(r) => r,
                        None => return false,
                    };
                    let local_path = workspace.join(rel);
                    if !local_path.starts_with(&workspace) {
                        return false;
                    }
                    if let Some(parent) = local_path.parent() {
                        if std::fs::create_dir_all(parent).is_err() {
                            return false;
                        }
                    }
                    std::fs::write(local_path, &data).is_ok()
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(reconstruct_stream);
        while let Some(ok) = reconstruct_stream.next().await {
            if !ok {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
            }
        }

        let mut candidates: Vec<PathBuf> = collect_local_files(&repo_workspace)
            .into_iter()
            .filter(|(p, size)| !is_binary_extension(&p.to_string_lossy()) && *size <= max_blob_bytes as u64)
            .map(|(p, _)| p)
            .collect();
        candidates.sort_by_key(|p| if streamer::is_ai_sensitive_path(&p.to_string_lossy()) { 0 } else { 1 });

        if verbose {
            println!("      Scanning {} workspace files", candidates.len());
        }

        let file_stream = futures::stream::iter(candidates)
            .map(|path| {
                let stop = stop_flag.clone();
                let extra_patterns = extra_pat_arc.clone();
                let root = repo_workspace.clone();
                let full_name = repo.full_name.clone();
                let entropy_thresh = args.entropy_threshold;
                async move {
                    if stop.load(Ordering::Relaxed) {
                        return (vec![], vec![], 0usize, false, true);
                    }
                    let data = match tokio::fs::read(&path).await {
                        Ok(d) => d,
                        Err(_) => return (vec![], vec![], 0usize, true, false),
                    };
                    if data.is_empty() {
                        return (vec![], vec![], 0usize, false, false);
                    }
                    let probe = &data[..data.len().min(BINARY_DETECTION_PROBE_SIZE)];
                    let null_count = probe.iter().filter(|&&b| b == 0).count();
                    if null_count > NULL_BYTE_THRESHOLD {
                        return (vec![], vec![], 0usize, false, false);
                    }

                    let text = String::from_utf8_lossy(&data);
                    let rel = path
                        .strip_prefix(&root)
                        .map(|p| p.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                    let source = format!("{}/{}", full_name, rel);
                    let findings = streamer::scan_text(&text, &source, &extra_patterns, entropy_thresh);

                    let mut techs = Vec::new();
                    detect_tech_from_path(&rel, &mut techs);

                    (findings, techs, data.len(), false, false)
                }
            })
            .buffer_unordered(args.workers);

        futures::pin_mut!(file_stream);
        while let Some((findings, techs, bytes, failed, skipped_by_stop)) = file_stream.next().await {
            if skipped_by_stop {
                continue;
            }
            if failed {
                blobs_failed.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if bytes > 0 {
                blobs_scanned.fetch_add(1, Ordering::Relaxed);
                bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
            }

            if !techs.is_empty() {
                let mut ts = tech_stack_set.lock().await;
                for t in techs { ts.insert(t); }
            }
            if findings.is_empty() { continue; }

            if args.live || args.pipe {
                for f in &findings {
                    println!("{}", serde_json::to_string(&f.to_dict()).unwrap_or_default());
                }
            }

            let mut all = all_findings.lock().await;
            all.extend(findings);

            if should_stop_scan(&all, args.max_findings, args.stop_on_critical) {
                stop_flag.store(true, Ordering::Relaxed);
                if verbose {
                    if args.max_findings > 0 && all.len() >= args.max_findings {
                        println!("\n  [!] Reached --max-findings limit. Stopping scan.");
                    } else {
                        println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                    }
                }
                break;
            }
        }
    }

    // SEC-004: temp_guard automatically cleans up when dropped at end of scope

    // ── 5. Assemble result ───────────────────────
    let elapsed_s   = t0.elapsed().as_secs_f64();
    let findings    = all_findings.lock().await.clone();
    let mut ts_vec: Vec<String> = tech_stack_set.lock().await.iter().cloned().collect();
    ts_vec.sort();

    let stream_r = StreamResult {
        findings,
        contributors:      vec![],
        tech_stack:        ts_vec,
        commit_count:      0,
        blobs_scanned:     blobs_scanned.load(Ordering::Relaxed),
        blobs_failed:      blobs_failed.load(Ordering::Relaxed),
        bytes_scanned:     bytes_scanned.load(Ordering::Relaxed),
        elapsed_s,
        files_saved:       0,
        files_save_failed: 0,
        cache_hits: 0,
        cache_misses: 0,
        cache_stats: None,
        rate_limit_allowed: 0,
        rate_limit_dropped: 0,
        rate_limit_wait_ms: 0,
    };

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    // ── 7. Save report ───────────────────────────
    let report_name = format!("azure_{}", login);
    let ext = match args.format.as_str() {
        "sarif"  => "sarif",
        "csv"    => "csv",
        "ndjson" => "ndjson",
        "md"     => "md",
        "html"   => "html",
        _        => "json",
    };
    let report_path = format!("{}/{}_report.{}", args.output, report_name, ext);

    let save_result = match args.format.as_str() {
        "sarif"  => rep.save_sarif(&report_path, &report_name, Some(&stream_r)),
        "csv"    => rep.save_csv(&report_path, Some(&stream_r)),
        "ndjson" => rep.save_ndjson(&report_path, Some(&stream_r)),
        "md"     => rep.save_markdown(&report_path, &report_name, Some(&stream_r)),
        "html"   => rep.save_html(&report_path, &report_name, Some(&stream_r)),
        _        => rep.save_json(&report_path, "azure_token", None, None, Some(&stream_r)),
    };

    if save_result.is_ok() && !args.quiet {
        println!("  📄  Saved: {}\n", report_path);
    }

    // ── 8. Webhook ───────────────────────────────
    if let Some(ref webhook_url) = args.webhook {
        let webhook_body = serde_json::json!({
            "target":      azure_url.unwrap_or("https://dev.azure.com"),
            "scan_type":   "azure_token",
            "findings":    &stream_r.findings,
            "tech_stack":  &stream_r.tech_stack,
            "risk_score":  stream_r.risk_score(),
        });
        let _ = az_client.post(webhook_url, &webhook_body.to_string(), &[]).await;
        if !args.quiet {
            println!("  📡  Webhook sent\n");
        }
    }

    // ── 9. Pipe mode: emit final JSON summary ─────
    if args.pipe {
        let summary = serde_json::json!({
            "target":      azure_url.unwrap_or("https://dev.azure.com"),
            "scan_type":   "azure_token",
            "repos":       selected_repos.iter().map(|r| &r.full_name).collect::<Vec<_>>(),
            "findings":    stream_r.findings.len(),
            "tech":        stream_r.tech_stack,
            "blobs":       stream_r.blobs_scanned,
            "bytes":       stream_r.bytes_scanned,
            "elapsed":     stream_r.elapsed_s,
            "risk_score":  stream_r.risk_score(),
        });
        println!("{}", serde_json::to_string(&summary).unwrap_or_default());
    }

    if verbose && !args.pipe {
        println!("  ✔  Done\n");
    }
}

/// Prompt for Azure DevOps repository selection.
fn prompt_azure_repo_selection(repos: &[azure_api::AzRepo]) -> Vec<usize> {
    println!("  📋  Available repositories:\n");
    for (i, r) in repos.iter().enumerate() {
        let visibility = if r.private { "🔒" } else { "🌍" };
        let desc = r.description.as_deref().unwrap_or("No description");
        println!("    [{}] {} {} - {}", (i + 1).to_string().cyan(), visibility, r.name.bold(), desc.dimmed());
    }
    println!();

    loop {
        print!("  🔖  Select repositories (numbers comma-separated, or 'all'): ");
        io::stdout().flush().unwrap_or(());

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {},
            Err(_) => {
                eprintln!("  ✘  Failed to read input");
                std::process::exit(1);
            }
        }

        let input = input.trim().to_lowercase();
        if input == "all" {
            return (0..repos.len()).collect();
        }

        let mut selected = Vec::new();
        let mut valid = true;
        for part in input.split(',') {
            let part = part.trim();
            if let Ok(n) = part.parse::<usize>() {
                if n == 0 || n > repos.len() {
                    valid = false;
                    break;
                }
                selected.push(n - 1);
            } else {
                valid = false;
                break;
            }
        }

        if valid && !selected.is_empty() {
            selected.sort();
            selected.dedup();
            return selected;
        }

        eprintln!("  ⚠   Invalid selection. Try again (or 'all').");
    }
}

#[allow(clippy::too_many_lines)]
async fn run_dir_scan(
    args: &Cli,
    rep: &Reporter,
    client: &HttpClient,
    dir: &str,
    extra_patterns: Vec<streamer::DynPattern>,
) {
    let quiet = args.quiet || args.pipe;
    let verbose = !quiet;

    // SEC-001: Validate directory path
    let canonical_root = match validation::validate_directory_path(dir) {
        Ok(p) => PathBuf::from(p),
        Err(e) => {
            eprintln!("  ✘  {}", e);
            std::process::exit(1);
        }
    };

    if !quiet {
        rep.banner();
        println!("  Mode  : Local Directory Scan");
        println!("  Target: {}", canonical_root.display());
        println!("  Output: {}\n", args.output);
    }

    let all_files = collect_local_files(&canonical_root);
    let max_blob_bytes = args.max_blob_size * 1024 * 1024;

    let mut candidates: Vec<PathBuf> = all_files
        .into_iter()
        .filter(|(p, _)| !is_binary_extension(&p.to_string_lossy()))
        .filter(|(_, size)| *size <= max_blob_bytes as u64)
        .map(|(p, _)| p)
        .collect();
    candidates.sort_by_key(|p| if streamer::is_ai_sensitive_path(&p.to_string_lossy()) { 0 } else { 1 });

    if verbose {
        println!("  ◈  Found {} candidate files\n", candidates.len());
    }

    let t0 = Instant::now();
    let all_findings = Arc::new(tokio::sync::Mutex::new(Vec::<streamer::Finding>::new()));
    let tech_stack_set = Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::<String>::new()));
    let blobs_scanned = Arc::new(AtomicUsize::new(0));
    let blobs_failed = Arc::new(AtomicUsize::new(0));
    let bytes_scanned = Arc::new(AtomicUsize::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let extra_pat_arc = Arc::new(extra_patterns);
    let display_root = canonical_root.to_string_lossy().to_string();

    let file_stream = futures::stream::iter(candidates)
        .map(|path| {
            let stop = stop_flag.clone();
            let extra_patterns = extra_pat_arc.clone();
            let root = canonical_root.clone();
            let display_root = display_root.clone();
            let entropy_thresh = args.entropy_threshold;
            async move {
                if stop.load(Ordering::Relaxed) {
                    return (vec![], vec![], 0usize, false, true);
                }

                let data = match tokio::fs::read(&path).await {
                    Ok(d) => d,
                    Err(_) => return (vec![], vec![], 0usize, true, false),
                };

                if data.is_empty() {
                    return (vec![], vec![], 0usize, false, false);
                }

                let probe = &data[..data.len().min(BINARY_DETECTION_PROBE_SIZE)];
                let null_count = probe.iter().filter(|&&b| b == 0).count();
                if null_count > NULL_BYTE_THRESHOLD {
                    return (vec![], vec![], 0usize, false, false);
                }

                let text = String::from_utf8_lossy(&data);
                let rel = path
                    .strip_prefix(&root)
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                let source = format!("{}/{}", display_root, rel);
                let findings = streamer::scan_text(&text, &source, &extra_patterns, entropy_thresh);

                let mut techs = Vec::new();
                detect_tech_from_path(&rel, &mut techs);

                (findings, techs, data.len(), false, false)
            }
        })
        .buffer_unordered(args.workers);

    futures::pin_mut!(file_stream);
    while let Some((findings, techs, bytes, failed, skipped_by_stop)) = file_stream.next().await {
        if skipped_by_stop {
            continue;
        }

        if failed {
            blobs_failed.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        if bytes > 0 {
            blobs_scanned.fetch_add(1, Ordering::Relaxed);
            bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
        }

        if !techs.is_empty() {
            let mut ts = tech_stack_set.lock().await;
            for t in techs {
                ts.insert(t);
            }
        }

        if findings.is_empty() {
            continue;
        }

        if args.live || args.pipe {
            for f in &findings {
                println!("{}", serde_json::to_string(&f.to_dict()).unwrap_or_default());
            }
        }

        let mut all = all_findings.lock().await;
        all.extend(findings);

        if should_stop_scan(&all, args.max_findings, args.stop_on_critical) {
            stop_flag.store(true, Ordering::Relaxed);
            if verbose {
                if args.max_findings > 0 && all.len() >= args.max_findings {
                    println!("\n  [!] Reached --max-findings limit. Stopping scan.");
                } else {
                    println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                }
            }
        }
    }

    let elapsed_s = t0.elapsed().as_secs_f64();
    let findings = all_findings.lock().await.clone();
    let mut ts_vec: Vec<String> = tech_stack_set.lock().await.iter().cloned().collect();
    ts_vec.sort();

    let stream_r = StreamResult {
        findings,
        contributors: vec![],
        tech_stack: ts_vec,
        commit_count: 0,
        blobs_scanned: blobs_scanned.load(Ordering::Relaxed),
        blobs_failed: blobs_failed.load(Ordering::Relaxed),
        bytes_scanned: bytes_scanned.load(Ordering::Relaxed),
        elapsed_s,
        files_saved: 0,
        files_save_failed: 0,
        // PERF-005: Cache metrics (not applicable for dir mode scanning local files)
        cache_hits: 0,
        cache_misses: 0,
        cache_stats: None,
        // PERF-004: Rate limit metrics (not applicable for dir mode)
        rate_limit_allowed: 0,
        rate_limit_dropped: 0,
        rate_limit_wait_ms: 0,
    };

    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    let dir_name = dir_target_name(&canonical_root);
    let report_name = format!("dir_{}", dir_name);
    let ext = match args.format.as_str() {
        "sarif" => "sarif",
        "csv" => "csv",
        "ndjson" => "ndjson",
        "md" => "md",
        "html" => "html",
        _ => "json",
    };
    let report_path = format!("{}/{}_report.{}", args.output, report_name, ext);

    let save_result = match args.format.as_str() {
        "sarif" => rep.save_sarif(&report_path, &display_root, Some(&stream_r)),
        "csv" => rep.save_csv(&report_path, Some(&stream_r)),
        "ndjson" => rep.save_ndjson(&report_path, Some(&stream_r)),
        "md" => rep.save_markdown(&report_path, &display_root, Some(&stream_r)),
        "html" => rep.save_html(&report_path, &display_root, Some(&stream_r)),
        _ => rep.save_json(&report_path, &display_root, None, None, Some(&stream_r)),
    };

    if let Err(e) = save_result {
        eprintln!("  ⚠   Could not save report: {}", e);
    }

    if verbose && !args.pipe {
        rep.print_summary(&display_root, &stream_r, &report_path);
    }

    if let Some(ref webhook_url) = args.webhook {
        if let Ok(json_body) = std::fs::read_to_string(&report_path) {
            let sent = rep.send_webhook(
                webhook_url,
                args.webhook_secret.as_deref(),
                &json_body,
                client,
            ).await;
            if verbose {
                if sent {
                    println!("  ✔   Webhook delivered to {}", webhook_url);
                } else {
                    eprintln!("  ⚠   Webhook delivery failed");
                }
            }
        }
    }

    if args.pipe {
        let summary = serde_json::json!({
            "type": "summary",
            "mode": "dir",
            "target": display_root,
            "files_scanned": stream_r.blobs_scanned,
            "findings": stream_r.findings.len(),
            "risk_score": stream_r.risk_score(),
        });
        println!("{}", serde_json::to_string(&summary).unwrap_or_default());
    }

    if verbose && !args.pipe {
        println!("  ✔  Done\n");
    }
}

/// Detect tech stack from a file path (filename/extension signals only).
fn detect_tech_from_path(path: &str, out: &mut Vec<String>) {
    use lazy_static::lazy_static;
    use regex::Regex;
    lazy_static! {
        static ref TECH_PATTERNS: Vec<(&'static str, Regex)> = vec![
            ("Python",    Regex::new(r"requirements\.txt|setup\.py|Pipfile|pyproject\.toml|manage\.py").unwrap()),
            ("Node.js",   Regex::new(r"package\.json|yarn\.lock|package-lock\.json|\.nvmrc").unwrap()),
            ("PHP",       Regex::new(r"composer\.json|composer\.lock|\.php$").unwrap()),
            ("Ruby",      Regex::new(r"Gemfile|\.ruby-version|\.rb$|Rakefile").unwrap()),
            ("Java",      Regex::new(r"pom\.xml|build\.gradle|\.java$").unwrap()),
            ("Go",        Regex::new(r"go\.mod|go\.sum|\.go$").unwrap()),
            ("Rust",      Regex::new(r"Cargo\.toml|Cargo\.lock|\.rs$").unwrap()),
            (".NET",      Regex::new(r"\.csproj|\.sln|web\.config").unwrap()),
            ("Docker",    Regex::new(r"Dockerfile|docker-compose").unwrap()),
            ("Terraform", Regex::new(r"\.tf$|terraform\.tfvars").unwrap()),
        ];
    }
    for (tech, rx) in TECH_PATTERNS.iter() {
        if rx.is_match(path) {
            out.push(tech.to_string());
        }
    }
}

/// Build a plain (unauthenticated) `HttpConfig` for webhook delivery.
fn build_plain_http_config(args: &Cli) -> anyhow::Result<HttpConfig> {
    // PERF-002: Parse retry strategy
    let retry_strategy = match args.retry_strategy.to_lowercase().as_str() {
        "aggressive" => http_client::RetryStrategy::Aggressive,
        "conservative" => http_client::RetryStrategy::Conservative,
        _ => http_client::RetryStrategy::Standard,
    };

    Ok(HttpConfig {
        timeout:          Duration::from_secs(args.timeout),
        retries:          args.retries,
        delay:            Duration::ZERO,
        jitter:           Duration::ZERO,
        proxy:            args.proxy.clone(),
        verify_ssl:       false,
        custom_ua:        None,
        extra_headers:    vec![],
        max_size:         100 * 1024 * 1024,
        adaptive_timeout: false,
        max_timeout:      Duration::from_secs(args.max_timeout),
        use_http2:        args.http2,
        rate_limit_rps:   None,
        proxy_list:       vec![],
        ua_pool:          vec![],
        retry_strategy,
    })
}

// ════════════════════════════════════════════════
// MAIN PIPELINE
// ════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    // SEC-004: Initialize signal handlers for cleanup on interruption
    let cleanup_flag = temp_cleanup::init_global_cleanup().await;

    // Register signal handlers for graceful shutdown
    let cleanup_flag_clone = cleanup_flag.clone();
    tokio::spawn(async move {
        use signal_hook_tokio::Signals;

        let mut signals = match Signals::new([signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]) {
            Ok(s) => s,
            Err(_) => return,
        };

        #[allow(clippy::never_loop)]
        loop {
            match signals.next().await {
                Some(_signal) => {
                    cleanup_flag_clone.store(true, Ordering::Relaxed);
                    eprintln!("\n  [!] Interrupted. Cleaning up temporary files...");
                    std::process::exit(130); // Exit code for SIGINT (128 + 2)
                }
                None => break,
            }
        }
    });

    let args = Cli::parse();

    // SCAN-001: Parse false-positive keywords from CLI flag
    let false_positive_keywords: Vec<String> = if let Some(ref keywords_str) = args.false_positive_keywords {
        keywords_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    // DX-1: --patterns-help
    if args.patterns_help {
        println!("Custom patterns JSON format:");
        println!("{{");
        println!("  \"patterns\": [");
        println!("    {{");
        println!("      \"id\": \"my_token\",");
        println!("      \"severity\": \"CRITICAL|HIGH|MEDIUM|LOW|INFO\",");
        println!("      \"description\": \"Human-readable description\",");
        println!("      \"regex\": \"your_regex_here\"");
        println!("    }}");
        println!("  ]");
        println!("}}");
        println!("Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO");
        println!("Regex syntax: Rust regex crate (https://docs.rs/regex)");
        println!("Note: Use raw strings. Backslash escaping follows Rust regex rules.");
        println!("Example:");
        println!("  {{\"patterns\":[{{\"id\":\"internal_token\",\"severity\":\"HIGH\",\"description\":\"Internal API token\",\"regex\":\"int_tok_[A-Za-z0-9]{{32}}\"}}]}}");
        std::process::exit(0);
    }

    // A-6: --pipe mode
    if args.pipe {
        colored::control::set_override(false);
    }

    // Setup reporter and flags — done early so token mode can use them
    let quiet   = args.quiet || args.pipe;
    let verbose = !quiet;
    let rep     = Reporter::new(args.no_color);

    // SEC-001: Validate output path
    let _validated_output = match validation::validate_output_path(&args.output) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  ✘  Invalid output path: {}", e);
            std::process::exit(1);
        }
    };

    // R-1: Checkpoint & Resume - cleanup old checkpoints on startup
    if verbose {
        if let Ok(cleaned) = checkpoint::cleanup_old_checkpoints() {
            if cleaned > 0 {
                println!("  ◈  Cleaned up {} old checkpoint(s)", cleaned);
            }
        }
    }

    // PERF-001: --resume flag logic
    // When --resume is used without a URL, find the latest checkpoint and resume
    let resume_target = if args.resume && args.url.is_none() && args.targets.is_none() && args.token.is_none() && args.dir.is_none() {
        if verbose {
            println!("  ◈  --resume flag: searching for latest checkpoint...");
        }

        match checkpoint::find_latest_checkpoints(1) {
            Ok(latest) if !latest.is_empty() => {
                let latest_cp = &latest[0];
                let ts = chrono::DateTime::<chrono::Utc>::from_timestamp(latest_cp.updated_at as i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string());

                if verbose {
                    println!("  ◈  Found checkpoint for: {}", latest_cp.target);
                    println!("  ◈  Last updated: {}", ts);
                    println!("  ◈  Phase: {:?}", latest_cp.phase);
                }

                // Extract the URL from the checkpoint
                // For token mode checkpoints, the target format is different
                if latest_cp.target.starts_with("token_") || latest_cp.target.starts_with("dir_") {
                    if verbose {
                        eprintln!("  ⚠   Resume from token/dir mode checkpoints requires manual specification");
                        eprintln!("  → Use: gitrecon --resume with original --token or --dir argument");
                    }
                    std::process::exit(0);
                }

                Some(latest_cp.target.clone())
            }
            Ok(_) => {
                if verbose {
                    println!("  ⚠   No checkpoints found to resume from");
                }
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("  ✘  Failed to find checkpoints: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // If we found a resume target, use it as the URL
    let effective_url = resume_target.or_else(|| args.url.clone());

    // Setup UA pool and extra headers
    let mut ua_pool = vec![];
    if let Some(ref ua_file) = args.ua_file {
        match std::fs::read_to_string(ua_file) {
            Ok(content) => {
                // SEC-005: Validate UA file format
                match validation::validate_ua_file(&content) {
                    Ok(valid_uas) => ua_pool = valid_uas,
                    Err(e) => {
                        eprintln!("  ✘  Invalid UA file '{}': {}", ua_file, e);
                        std::process::exit(1);
                    }
                }
            },
            Err(e) => {
                eprintln!("  ⚠   Cannot read UA file '{}': {}", ua_file, e);
                // Not fatal - continue with empty pool
            }
        }
    }

    let mut extra_headers = parse_extra_headers(&args.headers);
    if args.ua_git {
        extra_headers.push(("Git-Protocol".to_string(), "version=2".to_string()));
    }

    let mut proxy_list = vec![];
    if let Some(ref pl_file) = args.proxy_list {
        if let Ok(content) = std::fs::read_to_string(pl_file) {
            proxy_list = content.lines().filter(|l| !l.trim().is_empty()).map(|l| l.to_string()).collect();
        }
    }

    // SEC-001: Validate proxy URL if provided
    if let Some(ref proxy_url) = args.proxy {
        if let Err(e) = validation::validate_proxy_url(proxy_url) {
            eprintln!("  ✘  Invalid proxy URL: {}", e);
            std::process::exit(1);
        }
    }

    // SEC-001: Validate proxy list if provided
    for proxy_url in &proxy_list {
        if let Err(e) = validation::validate_proxy_url(proxy_url) {
            eprintln!("  ✘  Invalid proxy URL in list: {}", e);
            std::process::exit(1);
        }
    }

    // PERF-002: Parse retry strategy
    let retry_strategy = match args.retry_strategy.to_lowercase().as_str() {
        "aggressive" => http_client::RetryStrategy::Aggressive,
        "conservative" => http_client::RetryStrategy::Conservative,
        _ => http_client::RetryStrategy::Standard,
    };

    // Build HTTP config (cloned for token mode before consuming)
    let base_cfg = HttpConfig {
        timeout:          Duration::from_secs(args.timeout),
        retries:          args.retries,
        delay:            Duration::from_secs_f64(args.delay),
        jitter:           Duration::from_secs_f64(args.jitter),
        proxy:            args.proxy.clone(),
        verify_ssl:       false,
        custom_ua:        if args.ua_git { Some("git/2.46.0".to_string()) } else { args.user_agent.clone() },
        extra_headers,
        max_size:         100 * 1024 * 1024,
        adaptive_timeout: !args.no_adaptive_timeout,
        max_timeout:      Duration::from_secs(args.max_timeout),
        use_http2:        args.http2,
        rate_limit_rps:   args.rate,
        proxy_list,
        ua_pool,
        retry_strategy,
    };

    let client = match HttpClient::new(base_cfg.clone()) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("  ✘  Failed to create HTTP client: {}", e);
            std::process::exit(1);
        }
    };

    // Load extra patterns (shared by both URL and token modes)
    let extra_patterns = if let Some(ref patterns_file) = args.patterns {
        match load_extra_patterns(patterns_file) {
            Ok(patterns) => patterns,
            Err(e) => {
                eprintln!("  ⚠   Failed to load patterns from '{}': {}", patterns_file, e);
                std::process::exit(1);
            }
        }
    } else {
        vec![]
    };

    // Validate mutually exclusive modes
    if args.token.is_some() && (args.dir.is_some() || args.targets.is_some() || args.url.is_some() || args.gitlab_token.is_some() || args.bitbucket_token.is_some() || args.gitea_token.is_some() || args.azure_token.is_some()) {
        eprintln!("  ✘  --token mode cannot be combined with --dir, <URL>, --targets, --gitlab-token, --bitbucket-token, --gitea-token, or --azure-token.");
        std::process::exit(1);
    }
    if args.gitlab_token.is_some() && (args.dir.is_some() || args.targets.is_some() || args.url.is_some() || args.token.is_some() || args.bitbucket_token.is_some() || args.gitea_token.is_some() || args.azure_token.is_some()) {
        eprintln!("  ✘  --gitlab-token mode cannot be combined with --dir, <URL>, --targets, --token, --bitbucket-token, --gitea-token, or --azure-token.");
        std::process::exit(1);
    }
    if args.bitbucket_token.is_some() && (args.dir.is_some() || args.targets.is_some() || args.url.is_some() || args.token.is_some() || args.gitlab_token.is_some() || args.gitea_token.is_some() || args.azure_token.is_some()) {
        eprintln!("  ✘  --bitbucket-token mode cannot be combined with --dir, <URL>, --targets, --token, --gitlab-token, --gitea-token, or --azure-token.");
        std::process::exit(1);
    }
    if args.gitea_token.is_some() && (args.dir.is_some() || args.targets.is_some() || args.url.is_some() || args.token.is_some() || args.gitlab_token.is_some() || args.bitbucket_token.is_some() || args.azure_token.is_some()) {
        eprintln!("  ✘  --gitea-token mode cannot be combined with --dir, <URL>, --targets, --token, --gitlab-token, --bitbucket-token, or --azure-token.");
        std::process::exit(1);
    }
    if args.azure_token.is_some() && (args.dir.is_some() || args.targets.is_some() || args.url.is_some() || args.token.is_some() || args.gitlab_token.is_some() || args.bitbucket_token.is_some() || args.gitea_token.is_some()) {
        eprintln!("  ✘  --azure-token mode cannot be combined with --dir, <URL>, --targets, --token, --gitlab-token, --bitbucket-token, or --gitea-token.");
        std::process::exit(1);
    }
    if args.dir.is_some() && (args.targets.is_some() || args.url.is_some()) {
        eprintln!("  ✘  --dir mode cannot be combined with <URL> or --targets.");
        std::process::exit(1);
    }

    // ── Token mode: enumerate GitHub repos and scan ──
    if let Some(ref token) = args.token {
        run_token_scan(&args, &rep, base_cfg, token, extra_patterns).await;
        return;
    }

    // ── GitLab Token mode: enumerate GitLab projects and scan ──
    if let Some(ref gitlab_token) = args.gitlab_token {
        run_gitlab_token_scan(&args, &rep, base_cfg, gitlab_token, args.gitlab_url.as_deref(), extra_patterns).await;
        return;
    }

    // ── Bitbucket Token mode: enumerate Bitbucket repositories and scan ──
    if let Some(ref bitbucket_token) = args.bitbucket_token {
        run_bitbucket_token_scan(&args, &rep, base_cfg, bitbucket_token, args.bitbucket_url.as_deref(), extra_patterns).await;
        return;
    }

    // ── Gitea Token mode: enumerate Gitea/Forgejo repositories and scan ──
    if let Some(ref gitea_token) = args.gitea_token {
        run_gitea_token_scan(&args, &rep, base_cfg, gitea_token, args.gitea_url.as_deref(), extra_patterns).await;
        return;
    }

    // ── Azure DevOps Token mode: enumerate Azure DevOps repositories and scan ──
    if let Some(ref azure_token) = args.azure_token {
        run_azure_token_scan(&args, &rep, base_cfg, azure_token, args.azure_url.as_deref(), extra_patterns).await;
        return;
    }

    // ── Directory mode: local recursive text scan ──
    if let Some(ref dir) = args.dir {
        run_dir_scan(&args, &rep, &client, dir, extra_patterns).await;
        return;
    }

    // Validate URL/targets (only required when not using --token/--dir)
    let raw_url = match (&effective_url, &args.targets) {
        (None, None) => {
            eprintln!("  ✘  Either <URL>, --targets FILE, --dir PATH, or --token PAT is required.");
            eprintln!("  → Use --resume to continue from latest checkpoint");
            std::process::exit(1);
        }
        (Some(u), _) => u.clone(),
        (None, Some(_)) => String::new(), // will use targets
    };

    // A-1: Multi-Target Scanning - Parse targets from NDJSON file
    let targets: Vec<Target> = if let Some(ref targets_file) = args.targets {
        match std::fs::read_to_string(targets_file) {
            Ok(content) => {
                let mut parsed = Vec::new();
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }

                    // Try parse as NDJSON first
                    if let Ok(target) = serde_json::from_str::<Target>(line) {
                        parsed.push(target);
                    } else {
                        // Fallback: treat as plain URL for backward compatibility
                        parsed.push(Target::Url {
                            url: normalize_url(line),
                            fuzz: Some(args.fuzz),
                        });
                    }
                }

                if verbose {
                    println!("  ◈  Loaded {} targets from {}", parsed.len(), targets_file);
                }

                parsed
            }
            Err(e) => {
                eprintln!("  ⚠   Cannot read targets file '{}': {}", targets_file, e);
                std::process::exit(1);
            }
        }
    } else {
        // Single URL target (from command line argument or --resume)
        vec![Target::Url {
            url: normalize_url(&raw_url),
            fuzz: Some(args.fuzz),
        }]
    };

    // A-1: Process each target (sequential for simplicity, parallel for --parallel-targets > 1)
    let mut all_results: Vec<serde_json::Value> = Vec::new();

    for (idx, target) in targets.iter().enumerate() {
        let target_num = idx + 1;
        let total_targets = targets.len();

        // A-1: Handle different target types
        match target {
            Target::Url { url, fuzz } => {
                let url = url.clone();
                let fuzz = fuzz.unwrap_or(args.fuzz);

                if !args.pipe && !quiet {
                    rep.banner();
                    println!("  Target [{}/{}]: {}\n", target_num, total_targets, url);
                }

                // ── Detect ──────────────────────────────────────────────────
                if verbose {
                    println!("  ◈  Target identification...");
                }

                let dr = detect::run(&client, &url, fuzz).await;

                let dr = match dr {
                    Some(r) => r,
                    None => {
                        if verbose {
                            println!("  ✘  No .git exposure detected");
                        }
                        continue;
                    }
                };

                if dr.confidence < args.min_confidence {
                    if verbose {
                        println!("  ✘  Confidence {}% < minimum {}%", dr.confidence, args.min_confidence);
                    }
                    continue;
                }

                if verbose {
                    println!("  ✔  Git detected! ({}%, {})", dr.confidence, dr.label);
                }

                // ── Reconnaissance ───────────────────────────────────────────
                if verbose {
                    println!("  ◈  Repository reconnaissance...");
                }

                let mapper  = mapper::Mapper::new(client.clone());
                let map_r   = mapper.run(&dr.git_url, dr.branch.as_deref(), args.skip_verification).await;

                // DX-4: --dry-run
                if args.dry_run {
                    println!("\n  ◈  [DRY RUN] Detection + Reconnaissance complete. Analysis skipped.");
                    println!("  SHA1 objects   : {}", map_r.all_sha1s().len());
                    println!("  Blobs (index)  : {}", map_r.blob_sha1s.len());
                    println!("  Commits/trees  : {}", map_r.commit_sha1s.len());
                    println!("  Est. disk size : {} ({} files)", map_r.size_human(), map_r.estimated_files);
                    println!("  Branches       : {}", map_r.branches[..map_r.branches.len().min(8)].join(", "));
                    if !map_r.remote_urls.is_empty() {
                        if let Some(u) = map_r.remote_urls.first().and_then(|m| m.get("url")) {
                            println!("  Remote origin  : {}", u);
                        }
                    }
                    println!();
                    continue;
                }

                let total = map_r.all_sha1s().len();
                if verbose {
                    println!("  ✔  Repository mapped: {} objects", total);
                }

                // VERIFICATION: Check if git objects are actually accessible
                // This catches partial exposure cases where only metadata is exposed
                if !map_r.objects_accessible {
                    if verbose {
                        println!("  ⚠  PARTIAL EXPOSURE DETECTED: Git metadata accessible but objects return 404");
                        println!("  → Skipping analysis (no accessible objects to scan)");
                        println!("  → Detection downgraded from {} to PARTIAL", dr.label);
                    } else {
                        eprintln!("  ⚠  Partial exposure: metadata only, objects not accessible");
                    }

                    // Generate a report indicating partial exposure
                    let partial_report = format!("{}/{}_report_partial.json", args.output, target_name(&url));
                    if let Err(e) = std::fs::write(
                        &partial_report,
                        serde_json::json!({
                            "target": url,
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                            "tool": "GitRecon",
                            "version": env!("CARGO_PKG_VERSION"),
                            "detection": {
                                "confidence": dr.confidence,
                                "label": format!("{}_PARTIAL", dr.label),
                                "git_url": dr.git_url,
                                "exposure_type": "metadata_only"
                            },
                            "map": {
                                "metadata_accessible": true,
                                "objects_accessible": false,
                                "blob_sha1s_found": map_r.blob_sha1s.len(),
                                "branches": map_r.branches,
                                "remote_urls": map_r.remote_urls
                            },
                            "result": {
                                "blobs_scanned": 0,
                                "findings": [],
                                "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                                "note": "Git metadata files (HEAD, config, index) are accessible, but git objects (blobs/trees/commits) return 404. This indicates partial .git exposure where only repository metadata is exposed."
                            }
                        }).to_string()
                    ) {
                        if verbose {
                            eprintln!("  ✗ Failed to write partial exposure report: {}", e);
                        }
                    } else if verbose {
                        println!("  → Partial exposure report saved: {}", partial_report);
                    }

                    // Skip to next target
                    continue;
                }

                // ── Analysis ─────────────────────────────────────────────────
                if verbose {
                    println!("  ◈  Deep object analysis...");
                    rep.print_stream_start(total);
                }

                let save_dir = if args.save {
                    Some(std::path::PathBuf::from(&args.output).join(target_name(&url)))
                } else {
                    None
                };

                // PERF-005: Create cache
                let cache = if !args.no_cache {
                    match cache::ObjectCache::new(args.cache_ttl as i64, args.no_cache) {
                        Ok(c) => Some(Arc::new(c)),
                        Err(e) => {
                            eprintln!("  ⚠   Failed to initialize cache: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                // PERF-005: Log cache status
                if verbose {
                    if let Some(ref cache) = cache {
                        if cache.is_disabled() {
                            println!("  ◈  Cache: disabled (--no-cache)");
                        } else {
                            let stats = cache.stats();
                            println!("  ◈  Cache: enabled ({} entries, {})",
                                stats.total_entries, stats.size_human());
                        }
                    } else {
                        println!("  ◈  Cache: disabled (initialization failed)");
                    }
                }

                let streamer = streamer::Streamer::new(
                    client.clone(),
                    args.workers,
                    args.mem_limit,
                    verbose,
                    args.max_findings,
                    args.stop_on_critical,
                    extra_patterns.clone(),
                    args.max_blob_size,
                    args.entropy_threshold,
                    args.live || args.pipe,
                    !args.no_adaptive,
                    args.checkpoint_interval,
                    Some(url.clone()),
                    cache,
                    false_positive_keywords.clone(),
                );

                let rep_arc          = Arc::new(rep.clone());
                let rep_for_progress = rep_arc.clone();
                let stream_r = streamer.run(
                    &dr.git_url,
                    &map_r,
                    if quiet {
                        None
                    } else {
                        Some(Arc::new(move |done: usize, total: usize| {
                            rep_for_progress.progress_bar(done, total, 0);
                        }))
                    },
                    save_dir,
                ).await;

                if verbose {
                    println!();
                }

                // ── Intelligence Report ──────────────────────────────────────
                if verbose {
                    println!("  ◈  Generating intelligence report...");
                }

                if !args.pipe {
                    rep.print_stream_done(&stream_r);
                }

                if verbose && !args.pipe {
                    rep.print_findings_summary(&stream_r.findings);
                }

                // Save report in requested format
                let tname = target_name(&url);
                let ext = match args.format.as_str() {
                    "sarif"  => "sarif",
                    "csv"    => "csv",
                    "ndjson" => "ndjson",
                    "md"     => "md",
                    "html"   => "html",
                    _        => "json",
                };
                let report_path = format!("{}/{}_report.{}", args.output, tname, ext);

                match args.format.as_str() {
                    "sarif" => {
                        if let Err(e) = rep.save_sarif(&report_path, &url, Some(&stream_r)) {
                            eprintln!("  ⚠   Could not save SARIF report: {}", e);
                        }
                    }
                    "csv" => {
                        if let Err(e) = rep.save_csv(&report_path, Some(&stream_r)) {
                            eprintln!("  ⚠   Could not save CSV report: {}", e);
                        }
                    }
                    "ndjson" => {
                        if let Err(e) = rep.save_ndjson(&report_path, Some(&stream_r)) {
                            eprintln!("  ⚠   Could not save NDJSON report: {}", e);
                        }
                    }
                    "md" => {
                        if let Err(e) = rep.save_markdown(&report_path, &url, Some(&stream_r)) {
                            eprintln!("  ⚠   Could not save Markdown report: {}", e);
                        }
                    }
                    "html" => {
                        if let Err(e) = rep.save_html(&report_path, &url, Some(&stream_r)) {
                            eprintln!("  ⚠   Could not save HTML report: {}", e);
                        }
                    }
                    _ => {
                        if let Err(e) = rep.save_json(&report_path, &url, Some(&dr), Some(&map_r), Some(&stream_r)) {
                            eprintln!("  ⚠   Could not save report: {}", e);
                        }
                    }
                }

                if verbose && !args.pipe {
                    rep.print_report(&dr, &map_r, &stream_r, &report_path);
                }

                // Collect result for aggregate report
                all_results.push(serde_json::json!({
                    "target": url,
                    "target_type": "URL",
                    "report_path": report_path,
                    "findings_count": stream_r.findings.len(),
                    "risk_score": stream_r.risk_score(),
                    "severity_counts": stream_r.severity_counts(),
                }));

                // O-4: Webhook delivery
                if let Some(ref webhook_url) = args.webhook {
                    if let Ok(json_body) = std::fs::read_to_string(&report_path) {
                        let sent = rep.send_webhook(webhook_url, args.webhook_secret.as_deref(), &json_body, &client).await;
                        if verbose {
                            if sent { println!("  ✔   Webhook delivered to {}", webhook_url); }
                            else { eprintln!("  ⚠   Webhook delivery failed"); }
                        }
                    }
                }

                // A-6: --pipe mode summary
                if args.pipe {
                    let summary = serde_json::json!({
                        "type": "summary",
                        "target": url,
                        "findings": stream_r.findings.len(),
                        "risk_score": stream_r.risk_score(),
                    });
                    println!("{}", serde_json::to_string(&summary).unwrap_or_default());
                }

                if verbose && !args.pipe {
                    println!("  ✔  Done\n");
                }
            }
            Target::Token { token: _, repos: _ } => {
                if verbose {
                    println!("  [{}] Token target: not yet implemented (use --token mode directly)", target_num);
                }
                // TODO: Implement token target handling in future iteration
                continue;
            }
            Target::Dir { dir: _ } => {
                if verbose {
                    println!("  [{}] Dir target: not yet implemented (use --dir mode directly)", target_num);
                }
                // TODO: Implement dir target handling in future iteration
                continue;
            }
        }
    }

    // A-1: Generate aggregate report if multiple targets were processed
    if targets.len() > 1 && !all_results.is_empty() {
        let aggregate_path = format!("{}/aggregate_report.json", args.output);
        if let Err(e) = std::fs::write(
            &aggregate_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "tool": "GitRecon",
                "version": env!("CARGO_PKG_VERSION"),
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "total_targets": targets.len(),
                "scanned_targets": all_results.len(),
                "results": all_results,
            })).unwrap_or_default()
        ) {
            if verbose {
                eprintln!("  ⚠   Could not save aggregate report: {}", e);
            }
        } else if verbose {
            println!("  ✔  Aggregate report saved: {}", aggregate_path);
        }
    }
}

// ════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════

/// Detect platform from a URL and create appropriate forge client.
///
/// # Arguments
/// * `url` - Repository URL or platform URL
/// * `base_cfg` - HTTP configuration base
///
/// # Returns
/// * `Ok(Box<dyn Forge>)` - Configured forge client
/// * `Err` - If platform detection fails or client creation fails
pub async fn create_forge_client_from_url(
    url: &str,
    base_cfg: HttpConfig,
) -> anyhow::Result<Box<dyn Forge>> {
    let platform = forge::Platform::from_url(url)
        .ok_or_else(|| anyhow::anyhow!("Could not detect platform from URL: {}", url))?;

    create_forge_client(platform, base_cfg).await
}

/// Create a forge client for the specified platform.
///
/// # Arguments
/// * `platform` - Target platform
/// * `base_cfg` - HTTP configuration base
///
/// # Returns
/// * `Ok(Box<dyn Forge>)` - Configured forge client
/// * `Err` - If client creation fails
pub async fn create_forge_client(
    platform: forge::Platform,
    _base_cfg: HttpConfig,
) -> anyhow::Result<Box<dyn Forge>> {
    match platform {
        forge::Platform::GitHub => {
            // GitHubForgeClient will be created after authentication
            anyhow::bail!("GitHub client requires authentication token; use authenticate_github_client()");
        }
        forge::Platform::GitLab => {
            // TODO: Implement GitLab client
            anyhow::bail!("GitLab client not yet implemented");
        }
        forge::Platform::Bitbucket => {
            // TODO: Implement Bitbucket client
            anyhow::bail!("Bitbucket client not yet implemented");
        }
        forge::Platform::Gitea => {
            // GiteaForgeClient can be created but requires token for authentication
            anyhow::bail!("Gitea client requires authentication token; use authenticate_gitea_client()");
        }
        forge::Platform::AzureDevOps => {
            // TODO: Implement Azure DevOps client
            anyhow::bail!("Azure DevOps client not yet implemented");
        }
    }
}

/// Create and authenticate a GitHub forge client.
///
/// # Arguments
/// * `base_cfg` - HTTP configuration base
/// * `token` - GitHub personal access token
///
/// # Returns
/// * `Ok(GitHubForgeClient)` - Authenticated GitHub client
/// * `Err` - If authentication fails
pub async fn authenticate_github_client(
    base_cfg: HttpConfig,
    token: &str,
) -> anyhow::Result<github_api::GitHubForgeClient> {
    let client = github_api::build_github_client(base_cfg, token)?;
    let mut gh_client = github_api::GitHubForgeClient::new(client);
    gh_client.authenticate(token).await?;
    Ok(gh_client)
}

/// Detect platform from a repository URL.
///
/// # Examples
/// ```ignore
/// assert_eq!(detect_platform("https://github.com/user/repo"), Some(Platform::GitHub));
/// ```
pub fn detect_platform(url: &str) -> Option<forge::Platform> {
    forge::Platform::from_url(url)
}

fn load_extra_patterns(file_path: &str) -> Result<Vec<streamer::DynPattern>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file_path)?;

    // SEC-005: Validate patterns JSON structure and regex patterns
    if let Err(e) = validation::validate_patterns_json(&content) {
        return Err(format!("Patterns file validation failed: {}", e).into());
    }

    let json: serde_json::Value = serde_json::from_str(&content)?;

    let patterns = json["patterns"].as_array()
        .ok_or("Missing 'patterns' array in JSON")?;

    let mut result = Vec::new();
    for p in patterns {
        let id = p["id"].as_str().ok_or("Missing 'id' field")?.to_string();
        let sev = p["severity"].as_str().ok_or("Missing 'severity' field")?.to_string();
        let desc = p["description"].as_str().ok_or("Missing 'description' field")?.to_string();
        let regex_str = p["regex"].as_str().ok_or("Missing 'regex' field")?;

        // SEC-005: Additional regex validation (already done in validate_patterns_json, but compile anyway)
        let regex = regex::Regex::new(regex_str)?;

        result.push(streamer::DynPattern { id, sev, desc, regex });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_find(severity: &str) -> streamer::Finding {
        streamer::Finding {
            filename: "a.txt".to_string(),
            line: 1,
            pattern_id: "p".to_string(),
            description: "d".to_string(),
            severity: severity.to_string(),
            match_str: "m".to_string(),
            context: "c".to_string(),
            is_deleted: false,
            commit_sha1: None,
            confidence_adjustment: None,
        }
    }

    #[test]
    fn test_is_binary_extension_detects_known_types() {
        assert!(is_binary_extension("foo.png"));
        assert!(is_binary_extension("foo.sqlite"));
        assert!(!is_binary_extension("foo.rs"));
        assert!(!is_binary_extension("foo.env"));
    }

    #[test]
    fn test_dir_target_name_fallback_and_sanitize() {
        assert_eq!(dir_target_name(Path::new("/tmp/my repo")), "my_repo");
        assert_eq!(dir_target_name(Path::new("/")), "directory_scan");
    }

    #[test]
    fn test_should_stop_scan_by_limit() {
        let findings = vec![mk_find("LOW"), mk_find("MEDIUM")];
        assert!(should_stop_scan(&findings, 2, false));
        assert!(!should_stop_scan(&findings, 3, false));
    }

    #[test]
    fn test_should_stop_scan_by_critical() {
        let findings = vec![mk_find("LOW"), mk_find("CRITICAL")];
        assert!(should_stop_scan(&findings, 0, true));
        assert!(!should_stop_scan(&findings, 0, false));
    }

    #[test]
    fn test_parse_repo_selection_input_all() {
        assert_eq!(parse_repo_selection_input("all", 3).unwrap(), vec![0, 1, 2]);
        assert_eq!(parse_repo_selection_input("ALL", 2).unwrap(), vec![0, 1]);
    }

    #[test]
    fn test_parse_repo_selection_input_multi_and_dedup() {
        assert_eq!(parse_repo_selection_input(" 3,1,3, 2 ", 4).unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn test_parse_repo_selection_input_invalid() {
        assert!(parse_repo_selection_input("", 3).is_err());
        assert!(parse_repo_selection_input("0", 3).is_err());
        assert!(parse_repo_selection_input("4", 3).is_err());
        assert!(parse_repo_selection_input("1,,2", 3).is_err());
        assert!(parse_repo_selection_input("x", 3).is_err());
    }

    #[test]
    fn test_parse_yes_no_choice() {
        assert_eq!(parse_yes_no_choice("Y"), Some(true));
        assert_eq!(parse_yes_no_choice("yes"), Some(true));
        assert_eq!(parse_yes_no_choice("N"), Some(false));
        assert_eq!(parse_yes_no_choice("no"), Some(false));
        assert_eq!(parse_yes_no_choice("maybe"), None);
    }

    #[test]
    fn test_normalize_repo_relative_path() {
        assert_eq!(
            normalize_repo_relative_path("src/main.rs"),
            Some(PathBuf::from("src/main.rs"))
        );
        assert_eq!(normalize_repo_relative_path("../etc/passwd"), None);
        assert_eq!(normalize_repo_relative_path("/abs/path"), None);
        assert_eq!(normalize_repo_relative_path(""), None);
    }

    // SEC-004: Tests for temp cleanup
    #[test]
    fn test_temp_dir_guard_basic() {
        use temp_cleanup::TempDirGuard;
        use std::fs;

        let temp_dir = std::env::temp_dir().join("gitrecon_test_guard_basic");
        fs::create_dir_all(&temp_dir).unwrap();
        assert!(temp_dir.exists());

        {
            let _guard = TempDirGuard::new(temp_dir.clone());
            assert!(temp_dir.exists());
        }

        // Directory removed after guard is dropped
        assert!(!temp_dir.exists());
    }

    #[test]
    fn test_temp_dir_guard_nested_paths() {
        use temp_cleanup::TempDirGuard;
        use std::fs;

        let temp_dir = std::env::temp_dir().join("gitrecon_test_nested");
        let nested_file = temp_dir.join("subdir").join("file.txt");

        fs::create_dir_all(temp_dir.join("subdir")).unwrap();
        fs::write(&nested_file, b"test").unwrap();

        assert!(temp_dir.exists());
        assert!(nested_file.exists());

        {
            let _guard = TempDirGuard::new(temp_dir.clone());
            assert!(temp_dir.exists());
        }

        // Entire tree removed
        assert!(!temp_dir.exists());
        assert!(!nested_file.exists());
    }

    #[test]
    fn test_temp_dir_guard_release() {
        use temp_cleanup::TempDirGuard;
        use std::fs;

        let temp_dir = std::env::temp_dir().join("gitrecon_test_guard_release");
        fs::create_dir_all(&temp_dir).unwrap();

        let guard = TempDirGuard::new(temp_dir.clone());
        let released = guard.release();

        assert_eq!(released, temp_dir);
        assert!(temp_dir.exists()); // Still exists after release

        // Manual cleanup
        fs::remove_dir_all(&temp_dir).unwrap();
    }
}

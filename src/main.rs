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
#[allow(dead_code)]
mod reconstructor;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use std::io::{self, Write};

use clap::Parser;
use futures::StreamExt;

use colored::Colorize;
use http_client::{HttpClient, HttpConfig};
use reporter::Reporter;
use streamer::StreamResult;

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
}

// ════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════

fn normalize_url(url: &str) -> String {
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };
    url.trim_end_matches('/').to_string()
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
    raw.iter()
        .filter_map(|h| {
            let mut parts = h.splitn(2, ':');
            let k = parts.next()?.trim().to_string();
            let v = parts.next()?.trim().to_string();
            Some((k, v))
        })
        .collect()
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
    let temp_root = if persist_source {
        None
    } else {
        let p = std::env::temp_dir().join(format!(
            "gitrecon_token_scan_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&p);
        Some(p)
    };

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

        let candidates: Vec<PathBuf> = collect_local_files(&repo_workspace)
            .into_iter()
            .filter(|(p, size)| !is_binary_extension(&p.to_string_lossy()) && *size <= max_blob_bytes as u64)
            .map(|(p, _)| p)
            .collect();

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

    if !persist_source {
        if let Some(root) = temp_root {
            let _ = std::fs::remove_dir_all(root);
        }
    }

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
async fn run_dir_scan(
    args: &Cli,
    rep: &Reporter,
    client: &HttpClient,
    dir: &str,
    extra_patterns: Vec<streamer::DynPattern>,
) {
    let quiet = args.quiet || args.pipe;
    let verbose = !quiet;

    let root_path = Path::new(dir);
    let canonical_root = match std::fs::canonicalize(root_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  ✘  Cannot access directory '{}': {}", dir, e);
            std::process::exit(1);
        }
    };

    if !canonical_root.is_dir() {
        eprintln!("  ✘  --dir must point to a directory.");
        std::process::exit(1);
    }

    if !quiet {
        rep.banner();
        println!("  Mode  : Local Directory Scan");
        println!("  Target: {}", canonical_root.display());
        println!("  Output: {}\n", args.output);
    }

    let all_files = collect_local_files(&canonical_root);
    let max_blob_bytes = args.max_blob_size * 1024 * 1024;

    let candidates: Vec<PathBuf> = all_files
        .into_iter()
        .filter(|(p, _)| !is_binary_extension(&p.to_string_lossy()))
        .filter(|(_, size)| *size <= max_blob_bytes as u64)
        .map(|(p, _)| p)
        .collect();

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
    })
}

// ════════════════════════════════════════════════
// MAIN PIPELINE
// ════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    let args = Cli::parse();

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

    // Setup UA pool and extra headers
    let mut ua_pool = vec![];
    if let Some(ref ua_file) = args.ua_file {
        if let Ok(content) = std::fs::read_to_string(ua_file) {
            ua_pool = content.lines().filter(|l| !l.trim().is_empty()).map(|l| l.to_string()).collect();
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
    if args.token.is_some() && (args.dir.is_some() || args.targets.is_some() || args.url.is_some()) {
        eprintln!("  ✘  --token mode cannot be combined with --dir, <URL>, or --targets.");
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

    // ── Directory mode: local recursive text scan ──
    if let Some(ref dir) = args.dir {
        run_dir_scan(&args, &rep, &client, dir, extra_patterns).await;
        return;
    }

    // Validate URL/targets (only required when not using --token/--dir)
    let raw_url = match (&args.url, &args.targets) {
        (None, None) => {
            eprintln!("  ✘  Either <URL>, --targets FILE, --dir PATH, or --token PAT is required.");
            std::process::exit(1);
        }
        (Some(u), _) => u.clone(),
        (None, Some(_)) => String::new(), // will use targets
    };

    // Collect URLs to process
    let urls: Vec<String> = if let Some(ref targets_file) = args.targets {
        match std::fs::read_to_string(targets_file) {
            Ok(content) => content.lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .map(|l| normalize_url(l.trim()))
                .collect(),
            Err(e) => {
                eprintln!("  ⚠   Cannot read targets file '{}': {}", targets_file, e);
                std::process::exit(1);
            }
        }
    } else {
        vec![normalize_url(&raw_url)]
    };

    // Process each URL (for simplicity, sequential processing)
    for url in &urls {
        if !args.pipe && !quiet {
            rep.banner();
            println!("  Target: {}\n", url);
        }

        // ── Detect ──────────────────────────────────────────────────
        if verbose {
            println!("  ◈  Target identification...");
        }

        let dr = detect::run(&client, url, args.fuzz).await;

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
        let map_r   = mapper.run(&dr.git_url, dr.branch.as_deref()).await;

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

        // ── Analysis ─────────────────────────────────────────────────
        if verbose {
            println!("  ◈  Deep object analysis...");
            rep.print_stream_start(total);
        }

        let save_dir = if args.save {
            Some(std::path::PathBuf::from(&args.output).join(target_name(url)))
        } else {
            None
        };

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
        let tname = target_name(url);
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
                if let Err(e) = rep.save_sarif(&report_path, url, Some(&stream_r)) {
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
                if let Err(e) = rep.save_markdown(&report_path, url, Some(&stream_r)) {
                    eprintln!("  ⚠   Could not save Markdown report: {}", e);
                }
            }
            "html" => {
                if let Err(e) = rep.save_html(&report_path, url, Some(&stream_r)) {
                    eprintln!("  ⚠   Could not save HTML report: {}", e);
                }
            }
            _ => {
                if let Err(e) = rep.save_json(&report_path, url, Some(&dr), Some(&map_r), Some(&stream_r)) {
                    eprintln!("  ⚠   Could not save report: {}", e);
                }
            }
        }

        if verbose && !args.pipe {
            rep.print_report(&dr, &map_r, &stream_r, &report_path);
        }

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
}

// ════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════

fn load_extra_patterns(file_path: &str) -> Result<Vec<streamer::DynPattern>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file_path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;
    
    let patterns = json["patterns"].as_array()
        .ok_or("Missing 'patterns' array in JSON")?;
    
    let mut result = Vec::new();
    for p in patterns {
        let id = p["id"].as_str().ok_or("Missing 'id' field")?.to_string();
        let sev = p["severity"].as_str().ok_or("Missing 'severity' field")?.to_string();
        let desc = p["description"].as_str().ok_or("Missing 'description' field")?.to_string();
        let regex_str = p["regex"].as_str().ok_or("Missing 'regex' field")?;
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
}

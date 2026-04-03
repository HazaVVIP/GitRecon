//! main.rs
//! GitRecon v3.0.0 — Streaming Git Exposure Scanner (Rust)
//!
//! Usage:
//!   gitrecon <url> [options]
//!
//! Examples:
//!   gitrecon https://target.com
//!   gitrecon https://target.com --save
//!   gitrecon https://target.com --proxy socks5://127.0.0.1:9050
//!   gitrecon https://target.com --delay 1.5 --timeout 15
//!   gitrecon https://target.com --save --output ./hasil
//!   gitrecon https://target.com --fuzz
//!   gitrecon https://target.com --no-color -q

mod http_client;
mod git_parser;
mod detect;
mod mapper;
mod streamer;
mod reporter;
#[allow(dead_code)]
mod reconstructor;

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use http_client::{HttpClient, HttpConfig};
use reporter::Reporter;

// ════════════════════════════════════════════════
// CLI
// ════════════════════════════════════════════════

#[derive(Parser, Debug)]
#[command(
    name = "gitrecon",
    version = "3.2.0",
    about = "GitRecon — Streaming Git Exposure Scanner (Rust)",
    long_about = None,
    after_help = "Examples:\n  gitrecon https://target.com\n  gitrecon https://target.com --save\n  gitrecon https://target.com --proxy socks5://127.0.0.1:9050 --delay 1\n  gitrecon https://target.com --fuzz --timeout 15\n  gitrecon --targets urls.txt --parallel-targets 5\n  gitrecon https://target.com --format sarif --webhook https://alerts.example.com"
)]
struct Cli {
    /// Target URL (optional when --targets is used)
    #[arg(value_name = "URL", required = false)]
    url: Option<String>,

    /// Rekonstruksi source code ke disk setelah scan
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

    // Validate URL/targets
    let raw_url = match (&args.url, &args.targets) {
        (None, None) => {
            eprintln!("  [✗] Either <URL> or --targets FILE is required.");
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
                eprintln!("  [!] Cannot read targets file '{}': {}", targets_file, e);
                std::process::exit(1);
            }
        }
    } else {
        vec![normalize_url(&raw_url)]
    };

    // Setup reporter and flags
    let quiet = args.quiet || args.pipe;
    let verbose = !quiet;
    let rep = Reporter::new(args.no_color);

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

    // Build HTTP config
    let cfg = HttpConfig {
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

    let client = match HttpClient::new(cfg) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("  [✗] Failed to create HTTP client: {}", e);
            std::process::exit(1);
        }
    };

    // Load extra patterns
    let extra_patterns = if let Some(ref patterns_file) = args.patterns {
        match load_extra_patterns(patterns_file) {
            Ok(patterns) => patterns,
            Err(e) => {
                eprintln!("  [!] Failed to load patterns from '{}': {}", patterns_file, e);
                std::process::exit(1);
            }
        }
    } else {
        vec![]
    };

    // Process each URL (for simplicity, sequential processing)
    for url in &urls {
        if !args.pipe && !quiet {
            rep.banner();
            println!("  Target: {}\n", url);
        }

        // ── Phase 1: Detect ──────────────────────────────────────────
        if verbose {
            println!("  [→] Phase 1: Detecting .git exposure...");
        }

        let dr = detect::run(&client, url, args.fuzz).await;

        let dr = match dr {
            Some(r) => r,
            None => {
                if verbose {
                    println!("  [✗] No .git exposure detected");
                }
                continue;
            }
        };

        if dr.confidence < args.min_confidence {
            if verbose {
                println!("  [✗] Confidence {}% < minimum {}%", dr.confidence, args.min_confidence);
            }
            continue;
        }

        if verbose {
            println!("  [✓] Git detected! ({}%, {})", dr.confidence, dr.label);
        }

        // ── Phase 2: Map ─────────────────────────────────────────────
        if verbose {
            println!("  [→] Phase 2: Mapping repository structure...");
        }

        let mapper = mapper::Mapper::new(client.clone());
        let map_r = mapper.run(&dr.git_url, dr.branch.as_deref()).await;

        // DX-4: --dry-run
        if args.dry_run {
            println!("\n  [DRY RUN] Phase 1+2 complete. Scan skipped.");
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
            println!("  [✓] Repository mapped: {} objects", total);
        }

        // ── Phase 3: Stream & Scan ──────────────────────────────────
        if verbose {
            println!("  [→] Phase 3: Streaming & scanning objects...");
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

        let rep_arc = Arc::new(rep.clone());
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

        // ── Phase 4: Report ─────────────────────────────────────────
        if verbose {
            println!("  [→] Phase 4: Generating report...");
        }

        if !args.pipe {
            rep.print_stream_done(&stream_r);
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
                    eprintln!("  [!] Could not save SARIF report: {}", e);
                }
            }
            "csv" => {
                if let Err(e) = rep.save_csv(&report_path, Some(&stream_r)) {
                    eprintln!("  [!] Could not save CSV report: {}", e);
                }
            }
            "ndjson" => {
                if let Err(e) = rep.save_ndjson(&report_path, Some(&stream_r)) {
                    eprintln!("  [!] Could not save NDJSON report: {}", e);
                }
            }
            "md" => {
                if let Err(e) = rep.save_markdown(&report_path, url, Some(&stream_r)) {
                    eprintln!("  [!] Could not save Markdown report: {}", e);
                }
            }
            "html" => {
                if let Err(e) = rep.save_html(&report_path, url, Some(&stream_r)) {
                    eprintln!("  [!] Could not save HTML report: {}", e);
                }
            }
            _ => {
                if let Err(e) = rep.save_json(&report_path, url, Some(&dr), Some(&map_r), Some(&stream_r)) {
                    eprintln!("  [!] Could not save report: {}", e);
                }
            }
        }

        if verbose && !args.pipe {
            println!("  [✓] Report saved: {}", report_path);
        }

        // O-4: Webhook delivery
        if let Some(ref webhook_url) = args.webhook {
            if let Ok(json_body) = std::fs::read_to_string(&report_path) {
                let sent = rep.send_webhook(webhook_url, args.webhook_secret.as_deref(), &json_body, &client).await;
                if verbose {
                    if sent { println!("  [✓] Webhook delivered to {}", webhook_url); }
                    else { eprintln!("  [!] Webhook delivery failed"); }
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
            println!("  [✓] Complete\n");
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

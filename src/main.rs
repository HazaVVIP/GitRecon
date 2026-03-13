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

use std::path::PathBuf;
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
    version = "3.0.0",
    about = "GitRecon — Streaming Git Exposure Scanner (Rust)",
    long_about = None,
    after_help = "Cara pakai:\n  gitrecon https://target.com\n  gitrecon https://target.com --save\n  gitrecon https://target.com --proxy socks5://127.0.0.1:9050 --delay 1\n  gitrecon https://target.com --fuzz --timeout 15"
)]
struct Cli {
    /// Target URL (e.g., https://target.com)
    url: String,

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

fn ask_save_confirm(size_human: &str, estimated_files: usize) -> bool {
    println!("\n  ⚠️  --save aktif");
    println!("  Estimasi ukuran : {} ({} files)", size_human, estimated_files);
    println!("  Disk akan terpakai sebesar estimasi di atas.");
    print!("  Lanjutkan? [y/N] ");
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

// ════════════════════════════════════════════════
// MAIN PIPELINE
// ════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let url     = normalize_url(&args.url);
    let rep     = Reporter::new(args.no_color);
    let verbose = !args.quiet;

    let cfg = HttpConfig {
        timeout:       Duration::from_secs(args.timeout),
        retries:       args.retries,
        delay:         Duration::from_secs_f64(args.delay),
        jitter:        Duration::from_secs_f64(args.jitter),
        proxy:         args.proxy.clone(),
        verify_ssl:    false,
        custom_ua:     args.user_agent.clone(),
        extra_headers: parse_extra_headers(&args.headers),
        ..Default::default()
    };

    let client = match HttpClient::new(cfg) {
        Ok(c)  => c,
        Err(e) => {
            eprintln!("  [✗] Failed to create HTTP client: {}", e);
            std::process::exit(1);
        }
    };

    rep.banner();
    println!("  Target: {}\n", url);

    // ── Phase 1: Detect ──────────────────────────────────────────
    if verbose {
        println!("  [→] Phase 1: Detecting .git exposure...");
    }

    let dr = detect::run(&client, &url, args.fuzz).await;

    let dr = match dr {
        Some(r) => r,
        None    => {
            println!("\n  [✗] Tidak ada .git exposure terdeteksi di: {}\n", url);
            std::process::exit(1);
        }
    };

    rep.print_detect(&dr);

    if dr.confidence < args.min_confidence {
        println!("  [!] Confidence {}% di bawah threshold {}%.", dr.confidence, args.min_confidence);
        println!("      Gunakan --min-confidence 0 untuk memaksa lanjut.\n");
        std::process::exit(1);
    }

    // ── Phase 2: Map ─────────────────────────────────────────────
    if verbose {
        println!("  [→] Phase 2: Mapping objects...");
    }

    let mapper = mapper::Mapper::new(client.clone());
    let map_r  = mapper.run(&dr.git_url, dr.branch.as_deref()).await;
    rep.print_map(&map_r);

    if map_r.all_sha1s().is_empty() {
        println!("  [!] Tidak ada SHA1 ditemukan. Repository mungkin kosong atau terproteksi.\n");
        std::process::exit(1);
    }

    // ── --save confirmation ──────────────────────────────────────
    let mut do_save = args.save;
    let tname      = target_name(&url);
    let source_dir = format!("{}/{}", args.output, tname);

    if do_save {
        if !ask_save_confirm(&map_r.size_human(), map_r.estimated_files) {
            println!("  Dibatalkan. Melanjutkan tanpa --save (mode online).");
            do_save = false;
        }
        println!();
    }

    // ── Phase 3: Stream & Scan (+ optional save) ─────────────────
    let total = map_r.all_sha1s().len();
    let save_dir: Option<PathBuf> = if do_save {
        Some(PathBuf::from(&source_dir))
    } else {
        None
    };

    // Load optional custom patterns
    let extra_patterns: Vec<streamer::DynPattern> = if let Some(ref path) = args.patterns {
        match streamer::load_patterns_from_file(path) {
            Ok(p)  => {
                if verbose {
                    println!("  [+] Loaded {} custom patterns from '{}'", p.len(), path);
                }
                p
            }
            Err(e) => {
                eprintln!("  [!] Failed to load patterns from '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    } else {
        vec![]
    };

    let streamer = streamer::Streamer::new(
        client.clone(),
        args.workers,
        args.mem_limit,
        verbose,
        args.max_findings,
        args.stop_on_critical,
        extra_patterns,
    );

    rep.print_stream_start(total);

    let rep_arc = Arc::new(rep);
    let rep_for_progress = rep_arc.clone();
    let quiet = args.quiet;

    let progress_cb: Arc<dyn Fn(usize, usize) + Send + Sync> =
        Arc::new(move |done: usize, total: usize| {
            if !quiet {
                rep_for_progress.progress_bar(done, total, 0);
            }
        });

    let stream_r = streamer.run(&dr.git_url, &map_r, Some(progress_cb), save_dir).await;
    rep_arc.print_stream_done(&stream_r);

    if do_save && (stream_r.files_saved > 0 || stream_r.files_save_failed > 0) {
        println!("  Location: {}", source_dir);
        println!();
    }

    // ── Phase 4: Report ──────────────────────────────────────────
    rep_arc.print_report(&dr, &map_r, &stream_r);

    // Save JSON report
    let report_path = format!("{}/{}_report.json", args.output, tname);

    if let Err(e) = rep_arc.save_json(&report_path, &url, Some(&dr), Some(&map_r), Some(&stream_r)) {
        eprintln!("  [!] Could not save report: {}", e);
    }

    // ── Summary ──────────────────────────────────────────────────
    rep_arc.print_summary(&url, &stream_r, &report_path);
}

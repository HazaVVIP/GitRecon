//! main.rs
//! GitRecon v3.2.6 — Streaming Git Exposure Scanner (Rust)
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

mod azure_api; // GIT-004: Azure DevOps support
mod binary_adapter;
mod binary_scanner;
mod bitbucket_api;
mod cache; // PERF-005: SQLite cache layer
mod checkpoint;
mod config;
mod content_scanner;
mod detect;
mod dir_pipeline;
mod forge;
mod forge_factory;
mod forge_scan;
mod git_parser;
mod gitea_api; // GIT-003: Gitea/Forgejo support
mod github_api;
mod gitlab_api;
mod http_client;
mod layout;
mod mapper;
mod object_source;
mod object_worker;
mod outcome;
mod pack_reader; // Sprint 5 (S5.1): pack file parser + delta resolver
mod provider_transport;
mod rate_limiter; // PERF-004: Token bucket rate limiter
mod reporter;
mod resource_budget;
mod scan_accumulator;
mod scan_scheduler;
mod scanner_factory;
mod scanner_policy;
mod stream_types;
mod streamer;
mod streamer_config;
mod target_utils;
mod targets;
mod temp_cleanup; // SEC-004: Temp file cleanup
mod text_utils;
mod ui;
mod url_pipeline;
mod validation;

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use forge::{Forge, ForgeScanScope};
use forge_factory::create_forge_client;
use futures::StreamExt;
use outcome::{classify_error, ScanSummary, TargetErrorCode, TargetOutcome, TargetStatus};
use scanner_factory::build_streamer;
use url_pipeline::run_stream;

use binary_adapter::is_binary_extension;
use colored::Colorize;
use http_client::{HttpClient, HttpConfig};
use reporter::{ReportContext, Reporter};
use target_utils::{
    dir_target_name, normalize_url, parse_extra_headers, select_by_indexes, target_name,
};
use targets::{load_targets, Target};
use ui::theme::{BannerStyle as ThemeBannerStyle, Theme};

struct UrlRunContext<'a> {
    args: &'a Cli,
    rep: &'a Reporter,
    client: &'a HttpClient,
    target_num: usize,
    total_targets: usize,
    extra_patterns: Vec<streamer::DynPattern>,
    false_positive_keywords: &'a [String],
    quiet: bool,
    verbose: bool,
}

async fn run_url_target(context: UrlRunContext<'_>, url: String, fuzz: bool) -> TargetOutcome {
    let UrlRunContext {
        args,
        rep,
        client,
        target_num,
        total_targets,
        extra_patterns,
        false_positive_keywords,
        quiet,
        verbose,
    } = context;
    if !args.pipe && !quiet {
        rep.banner();
        println!("  Target [{}/{}]: {}\n", target_num, total_targets, url);
    }

    // ── Detect ──────────────────────────────────────────────────
    if verbose {
        println!("  ◈  Target identification...");
    }

    let dr = detect::run(client, &url, fuzz).await;

    let dr = match dr {
        Some(r) => r,
        None => {
            if verbose {
                println!("  ✘  No .git exposure detected");
            }
            return TargetOutcome {
                target: url.clone(),
                target_type: "URL".to_string(),
                status: TargetStatus::Failed,
                report_path: None,
                findings_count: 0,
                risk_score: 0,
                error_code: Some(TargetErrorCode::NoGitExposure),
                error: Some("No .git exposure detected".to_string()),
                error_metadata: None,
            };
        }
    };

    if dr.confidence < args.min_confidence {
        if verbose {
            println!(
                "  ✘  Confidence {}% < minimum {}%",
                dr.confidence, args.min_confidence
            );
        }
        return TargetOutcome {
            target: url.clone(),
            target_type: "URL".to_string(),
            status: TargetStatus::Failed,
            report_path: None,
            findings_count: 0,
            risk_score: 0,
            error_code: Some(TargetErrorCode::ConfidenceBelowMinimum),
            error: Some(format!("Confidence below minimum: {}", dr.confidence)),
            error_metadata: None,
        };
    }
    if verbose {
        println!("  ✔  Git detected! ({}%, {})", dr.confidence, dr.label);
    }

    // ── Reconnaissance ───────────────────────────────────────────
    if verbose {
        println!("  ◈  Repository reconnaissance...");
    }

    let mapper = mapper::Mapper::new(client.clone()).with_max_history(args.max_history);
    let map_r = mapper
        .run(&dr.git_url, dr.branch.as_deref(), !args.no_verify_objects)
        .await;

    let total = map_r.all_sha1s().len();
    if verbose {
        println!("  ✔  Repository mapped: {} objects", total);
    }

    // VERIFICATION: Check if git objects are actually accessible.
    // Metadata-only exposure reporting is intentionally opt-in because it can
    // create noisy partial statuses during broad default scans.
    if should_short_circuit_partial_exposure(map_r.objects_accessible, args.partial_exposure) {
        if verbose {
            println!("  ⚠  PARTIAL EXPOSURE DETECTED: Git metadata files (HEAD, index, config) are accessible, but git objects cannot be fetched (blocked, 404, or non-git response)");
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
                                "note": "Git metadata files (HEAD, config, index) are accessible, but git objects (blobs/trees/commits) cannot be fetched. This indicates partial .git exposure where the server blocks or restricts access to objects/, or returns non-git responses."
                            }
                        }).to_string()
                    ) {
                        if verbose {
                            eprintln!("  ✗ Failed to write partial exposure report: {}", e);
                        }
                                        } else if verbose {
                        println!("  → Partial exposure report saved: {}", partial_report);
                    }
        return TargetOutcome {
            target: url.clone(),
            target_type: "URL".to_string(),
            status: TargetStatus::Partial,
            report_path: Some(partial_report),
            findings_count: 0,
            risk_score: 0,
            error_code: Some(TargetErrorCode::PartialExposure),
            error: Some("Git metadata is accessible but git objects are unavailable".to_string()),
            error_metadata: None,
        };
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

    // PERF-005: Log cache status (BUG-ERR-009: now async)
    if verbose {
        if let Some(ref cache) = cache {
            if cache.is_disabled() {
                println!("  ◈  Cache: disabled (--no-cache)");
            } else {
                let stats = cache.stats().await;
                println!(
                    "  ◈  Cache: enabled ({} entries, {})",
                    stats.total_entries,
                    stats.size_human()
                );
            }
        } else {
            println!("  ◈  Cache: disabled (initialization failed)");
        }
    }

    let scan_config = config::ScanConfigInput {
        workers: args.workers,
        mem_limit: args.mem_limit,
        max_findings: args.max_findings,
        stop_on_critical: args.stop_on_critical,
        max_blob_size: args.max_blob_size,
        max_history: args.max_history,
        entropy_threshold: args.entropy_threshold,
        live: args.live || args.pipe,
        adaptive_workers: !args.no_adaptive,
        resume: args.resume,
        checkpoint_interval: args.checkpoint_interval,
        exhaustive: args.exhaustive,
        scan_binaries: !args.no_scan_binaries,
        verify_objects: !args.no_verify_objects,
        cache_enabled: !args.no_cache,
        cache_ttl: args.cache_ttl,
    }
    .build()
    .unwrap_or_else(|error| {
        eprintln!("  ✘  {}", error);
        std::process::exit(2);
    });
    let streamer = build_streamer(
        client.clone(),
        &scan_config,
        verbose,
        extra_patterns.clone(),
        Some(url.clone()),
        cache,
        false_positive_keywords.to_vec(),
    );

    let stream_r = run_stream(&streamer, &dr.git_url, &map_r, rep, verbose, save_dir).await;

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
    let report_path = reporter::build_report_path(&args.output, &tname, &args.format);

    if let Err(e) = rep.save_scan_report(
        &report_path,
        &args.format,
        &url,
        &stream_r,
        ReportContext::Exposure {
            target: &url,
            detect: &dr,
            map: &map_r,
        },
    ) {
        eprintln!("  ⚠   Could not save report: {}", e);
    }

    if verbose && !args.pipe {
        rep.print_report(&dr, &map_r, &stream_r, &report_path);
    }

    // Collect result for aggregate report
    let outcome = TargetOutcome {
        target: url.clone(),
        target_type: "URL".to_string(),
        status: TargetStatus::Success,
        report_path: Some(report_path.clone()),
        findings_count: stream_r.findings.len(),
        risk_score: stream_r.risk_score(),
        error_code: None,
        error: None,
        error_metadata: None,
    };
    // O-4: Webhook delivery
    deliver_report_webhook_if_configured(
        rep,
        args,
        &report_path,
        verbose,
        WebhookSuccessStyle::Standard,
    )
    .await;

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
    outcome
}

fn validate_dry_run_target(target: &Target) -> anyhow::Result<()> {
    match target {
        Target::Url { url, .. } => validation::validate_and_normalize_url(url)
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("Invalid URL target: {}", error)),
        Target::Dir { dir } => validation::validate_directory_path(dir)
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("Invalid directory target '{}': {}", dir, error)),
        Target::Token { token, .. } => validation::validate_github_token(token)
            .map_err(|error| anyhow::anyhow!("Invalid GitHub token target: {}", error)),
    }
}

fn validate_dry_run_inputs(
    args: &Cli,
    effective_url: Option<&str>,
    extra_patterns: &[streamer::DynPattern],
) -> anyhow::Result<()> {
    let mut targets = Vec::new();
    let mut provider_token_targets = 0usize;

    if let Some(ref targets_file) = args.targets {
        targets = load_targets(targets_file, args.fuzz)?;
    } else if let Some(ref dir) = args.dir {
        targets.push(Target::Dir { dir: dir.clone() });
    } else if let Some(ref token) = args.token {
        validation::validate_github_token(token)
            .map_err(|error| anyhow::anyhow!("Invalid GitHub token: {}", error))?;
        targets.push(Target::Token {
            token: token.clone(),
            repos: None,
        });
    } else if let Some(ref token) = args.gitlab_token {
        validation::validate_gitlab_token(token)
            .map_err(|error| anyhow::anyhow!("Invalid GitLab token: {}", error))?;
        provider_token_targets = 1;
    } else if let Some(token) = args
        .bitbucket_token
        .as_deref()
        .or(args.gitea_token.as_deref())
        .or(args.azure_token.as_deref())
    {
        if token.trim().is_empty() {
            return Err(anyhow::anyhow!("Provider token cannot be empty"));
        }
        provider_token_targets = 1;
    } else if let Some(url) = effective_url {
        let normalized = validation::validate_and_normalize_url(url)?;
        targets.push(Target::Url {
            url: normalized,
            fuzz: Some(args.fuzz),
        });
    } else if args.bitbucket_token.is_none()
        && args.gitea_token.is_none()
        && args.azure_token.is_none()
    {
        return Err(anyhow::anyhow!(
            "Either <URL>, --targets FILE, --dir PATH, or a token is required"
        ));
    }

    for target in &targets {
        validate_dry_run_target(target)?;
    }

    let quiet = args.quiet || args.pipe;
    if !quiet {
        println!("\n  ◈  [DRY RUN] Validation complete; no network or content scan performed.");
        println!(
            "  Targets        : {}",
            targets.len() + provider_token_targets
        );
        println!("  Custom patterns: {}", extra_patterns.len());
        println!("  Mode           : exhaustive={}", args.exhaustive);
        println!("  Binary scan    : {}", !args.no_scan_binaries);
        println!("  Object verify  : {}", !args.no_verify_objects);
        println!("  Reports        : skipped");
        println!("  Webhooks       : skipped\n");
    } else if args.pipe {
        println!(
            "{}",
            serde_json::json!({
                "type": "dry_run",
                "valid": true,
                "targets": targets.len() + provider_token_targets,
                "custom_patterns": extra_patterns.len(),
                "network": "skipped",
                "content_scan": "skipped",
                "reports": "skipped",
                "webhooks": "skipped"
            })
        );
    }
    Ok(())
}

async fn run_non_url_target(
    args: &Cli,
    rep: &Reporter,
    client: &HttpClient,
    base_cfg: &HttpConfig,
    target: Target,
    extra_patterns: Vec<streamer::DynPattern>,
) -> TargetOutcome {
    match target {
        Target::Token { token, repos } => {
            let target_name = format!("token:{}", &token[..token.len().min(8)]);
            match run_token_scan(
                args,
                rep,
                base_cfg.clone(),
                &token,
                repos.as_deref(),
                extra_patterns,
            )
            .await
            {
                Ok(summary) => TargetOutcome {
                    target: target_name,
                    target_type: "TOKEN".to_string(),
                    status: TargetStatus::Success,
                    report_path: (!summary.report_path.is_empty()).then_some(summary.report_path),
                    findings_count: summary.findings_count,
                    risk_score: summary.risk_score,
                    error_code: None,
                    error: None,
                    error_metadata: None,
                },
                Err(error) => TargetOutcome {
                    target: target_name,
                    target_type: "TOKEN".to_string(),
                    status: TargetStatus::Failed,
                    report_path: None,
                    findings_count: 0,
                    risk_score: 0,
                    error_code: Some(classify_error(&error.to_string())),
                    error: Some(error.to_string()),
                    error_metadata: None,
                },
            }
        }
        Target::Dir { dir } => {
            let target_name = dir.clone();
            match run_dir_scan(args, rep, client, &dir, extra_patterns).await {
                Ok(summary) => TargetOutcome {
                    target: target_name,
                    target_type: "DIR".to_string(),
                    status: TargetStatus::Success,
                    report_path: (!summary.report_path.is_empty()).then_some(summary.report_path),
                    findings_count: summary.findings_count,
                    risk_score: summary.risk_score,
                    error_code: None,
                    error: None,
                    error_metadata: None,
                },
                Err(error) => TargetOutcome {
                    target: target_name,
                    target_type: "DIR".to_string(),
                    status: TargetStatus::Failed,
                    report_path: None,
                    findings_count: 0,
                    risk_score: 0,
                    error_code: Some(classify_error(&error.to_string())),
                    error: Some(error.to_string()),
                    error_metadata: None,
                },
            }
        }
        Target::Url { .. } => TargetOutcome {
            target: "url".to_string(),
            target_type: "URL".to_string(),
            status: TargetStatus::Failed,
            report_path: None,
            findings_count: 0,
            risk_score: 0,
            error_code: Some(TargetErrorCode::ScanFailed),
            error: Some("URL targets require sequential orchestration".to_string()),
            error_metadata: None,
        },
    }
}

// ════════════════════════════════════════════════
// CLI
// ════════════════════════════════════════════════

#[derive(Parser, Debug)]
#[command(
    name = "gitrecon",
    version = env!("CARGO_PKG_VERSION"),
        about = "Streaming Git exposure and secret-candidate scanner",
    long_about = "GitRecon detects exposed Git metadata, maps repository objects, scans recovered or local content, and writes structured reports. It supports URL, local-directory, multi-target, and authenticated forge workflows. Normal scans suppress common template placeholders; use --exhaustive when every candidate matters. Object verification and local binary scanning are enabled by default.",
    after_help = r##"Examples:
  # Scan a remote target with the default detection and verification pipeline
  gitrecon https://target.example

  # Probe additional Git exposure paths and reconstruct recovered source
  gitrecon https://target.example --fuzz --save --output ./results

  # Scan a local project, including binary/archive strings by default
  gitrecon --dir ./project --output ./results

  # Retain placeholder-like candidates for exhaustive investigation
  gitrecon --dir ./project --exhaustive --format json

  # Scan many targets concurrently with bounded target orchestration
  gitrecon --targets ./targets.ndjson --parallel-targets 8 --workers 50

  # Use a proxy, rate limit, timeout, and custom request header
  gitrecon https://target.example --proxy socks5://127.0.0.1:9050 --rate 2 \
    --timeout 20 --header X-Bounty-Program:authorized

  # Enumerate repositories through a GitHub token and emit SARIF
  gitrecon --token "$GITHUB_TOKEN" --format sarif --output ./results --quiet

  # Scan selected repositories non-interactively in pipeline mode
  gitrecon --token "$GITHUB_TOKEN" --pipe --save --format ndjson

  # Resume a checkpointed scan and bypass the object cache
  gitrecon https://target.example --resume --checkpoint-dir ./checkpoints --no-cache

  # Send a completed report to a validated HTTPS webhook
  gitrecon https://target.example --format json --webhook https://alerts.example/webhook

Token mode:
  1. GitRecon lists repositories accessible to the selected forge token.
  2. Select one repository, comma-separated repositories, or 'all'.
  3. Confirm whether reconstructed source should be saved to disk.

Safety and scope:
  Only scan systems and repositories you own or are explicitly authorized to assess.
  Reports may contain plaintext secret material; protect the output directory."##
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
    #[arg(
        short = 'o',
        long = "output",
        default_value = "./gitrecon_output",
        value_name = "DIR"
    )]
    output: String,

    /// Proxy URL, contoh: socks5://127.0.0.1:9050
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// Timeout request dalam detik (default: 10)
    #[arg(long, default_value = "10", value_name = "SEC", value_parser = clap::value_parser!(u64).range(1..=3600))]
    timeout: u64,

    /// Jumlah retry (default: 3)
    #[arg(long, default_value = "3", value_name = "N", value_parser = clap::value_parser!(u32).range(0..=100))]
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
    // Sprint 4 (S4.1): `--workers 0` used to silent-hang because
    // futures::stream::buffer_unordered(0) never polls. Enforced post-parse in main().
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

    /// Reduce output verbosity to minimal format (compact findings display)
    #[arg(short = 'C', long = "compact")]
    compact: bool,

    /// Print the JSON schema and examples for custom detection patterns, then exit.
    #[arg(long = "patterns-help")]
    patterns_help: bool,

    /// Maximum individual blob or local file size to scan in megabytes (default: 4).
    // Sprint 4 (S4.1): reject 0 in main() (would make every blob "too big").
    #[arg(long = "max-blob-size", default_value = "4", value_name = "MB")]
    max_blob_size: usize,

    /// Maximum commit-history traversal depth; 0 means unlimited (default: 500).
    // Sprint 1: bound the commit-graph traversal depth (previously hardcoded to 100 in mapper.rs).
    // Deeper history means more historical blobs discovered — at the cost of extra HTTP fetches.
    // Sprint 4 (S4.1): 0 means unlimited (documented behaviour in Mapper::with_max_history).
    // Range checked in main().
    #[arg(long = "max-history", default_value = "500", value_name = "COMMITS")]
    max_history: usize,

    /// Forge content scope: snapshot is the default-branch state; history is rejected unless supported.
    #[arg(long = "scan-scope", value_enum, default_value = "snapshot")]
    scan_scope: ForgeScanScope,

    /// Shannon-entropy threshold for high-entropy candidate detection (default: 4.5).
    #[arg(
        long = "entropy-threshold",
        default_value = "4.5",
        value_name = "FLOAT"
    )]
    entropy_threshold: f64,

    /// Validate configuration and targets without performing network or file scanning.
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Disable adaptive per-request timeout adjustment.
    #[arg(long = "no-adaptive-timeout")]
    no_adaptive_timeout: bool,

    /// Upper bound for adaptive request timeouts in seconds (default: 60).
    #[arg(long = "max-timeout", default_value = "60", value_name = "SEC", value_parser = clap::value_parser!(u64).range(1..=3600))]
    max_timeout: u64,

    /// Enable HTTP/2 where supported by the target and proxy configuration.
    #[arg(long = "http2")]
    http2: bool,
    // BUG-HTTP-003: SSL verification control
    /// Disable SSL verification (SECURITY RISK: MITM vulnerable!)
    /// Only use this if you understand the risks and have a specific reason.
    #[arg(
        long = "insecure",
        alias = "skip-ssl-verification",
        help = "Disable SSL verification (SECURITY RISK: MITM vulnerable!)"
    )]
    insecure: bool,

    /// Disable adaptive concurrency tuning for object and file workers.
    #[arg(long = "no-adaptive")]
    no_adaptive: bool,

    /// Apply a global request rate limit in requests per second.
    #[arg(long = "rate", value_name = "N")]
    rate: Option<f64>,

    /// Read a newline-delimited proxy list and rotate proxies between requests.
    #[arg(long = "proxy-list", value_name = "FILE")]
    proxy_list: Option<String>,

    /// Read additional User-Agent strings from a file, one per line.
    #[arg(long = "ua-file", value_name = "FILE")]
    ua_file: Option<String>,

    /// Use a Git-compatible User-Agent profile for requests.
    #[arg(long = "ua-git")]
    ua_git: bool,

    /// Stream findings and progress to the terminal as they are produced.
    #[arg(long = "live")]
    live: bool,

    /// Report format: json, sarif, csv, ndjson, md, or html.
    #[arg(long = "format", default_value = "json", value_name = "FORMAT",
          value_parser = ["json", "sarif", "csv", "ndjson", "md", "html"])]
    format: String,

    /// Deliver the completed report to a validated webhook URL.
    #[arg(long = "webhook", value_name = "URL")]
    webhook: Option<String>,

    /// Secret used to sign webhook requests when configured.
    #[arg(long = "webhook-secret", value_name = "KEY")]
    webhook_secret: Option<String>,

    /// Sprint 2 (S2.4): allow plain HTTP webhooks. By default only https:// is accepted
    /// because webhook bodies contain the full report including matched secret plaintext.
    #[arg(long = "webhook-allow-http")]
    webhook_allow_http: bool,

    /// Sprint 2 (S2.4): allow webhook host to resolve to loopback / RFC1918 / link-local.
    /// Off by default — blocks the common cloud-metadata / internal-service SSRF payload.
    #[arg(long = "webhook-allow-internal")]
    webhook_allow_internal: bool,

    /// Read URL, token, and directory targets from a newline-delimited target file.
    #[arg(long = "targets", value_name = "FILE")]
    targets: Option<String>,

    /// Maximum number of targets scanned concurrently (default: 1).
    #[arg(long = "parallel-targets", default_value = "1", value_name = "N")]
    parallel_targets: usize,

    /// Emit machine-readable newline-delimited output suitable for pipelines.
    #[arg(long = "pipe")]
    pipe: bool,

    /// Resume a prior scan from a verified checkpoint.
    #[arg(long = "resume")]
    resume: bool,

    /// Directory containing checkpoint state files.
    #[arg(long = "checkpoint-dir", value_name = "DIR")]
    checkpoint_dir: Option<String>,

    /// Persist scan progress after this many processed objects (default: 1000).
    #[arg(long = "checkpoint-interval", default_value = "1000", value_name = "N")]
    checkpoint_interval: usize,

    // S-3: binary file scanning
    /// Skip binary/archive scanning in local directory targets.
    #[arg(long = "no-scan-binaries")]
    no_scan_binaries: bool,

    /// Preserve placeholder-like candidates in direct pattern scanning.
    #[arg(long = "exhaustive")]
    exhaustive: bool,

    /// Retry policy: standard, conservative, or aggressive.
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

    /// Skip object accessibility verification before scanning.
    /// Verification is enabled by default for offensive object discovery.
    #[arg(long = "no-verify-objects")]
    no_verify_objects: bool,

    /// Report metadata-only Git exposure as PARTIAL; disabled by default.
    #[arg(long = "partial-exposure")]
    partial_exposure: bool,

    // Theme system
    /// Theme configuration file path (default: ~/.config/gitrecon/theme.toml)
    #[arg(long = "theme", value_name = "PATH")]
    theme_file: Option<String>,

    /// Banner display style (minimal, standard, full, none)
    #[arg(long = "banner-style", value_name = "STYLE",
          value_parser = ["minimal", "standard", "full", "none"])]
    banner_style: Option<String>,

    /// Disable unicode characters in output (use ASCII symbols)
    #[arg(long = "no-unicode")]
    no_unicode: bool,
}

// ════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════

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

fn prompt_repository_indexes<F>(repository_count: usize, render_row: F, prompt: &str) -> Vec<usize>
where
    F: Fn(usize),
{
    for index in 0..repository_count {
        render_row(index);
    }
    println!("      Input: satu nomor (contoh: 3), banyak nomor (1,3,7), atau all");
    loop {
        match prompt_line(prompt) {
            Ok(input) => match parse_repo_selection_input(&input, repository_count) {
                Ok(selection) => return selection,
                Err(message) => eprintln!("  ✘  {} Coba lagi.", message),
            },
            Err(_) => {
                eprintln!("  ⚠   Input tidak tersedia, default ke all.");
                return (0..repository_count).collect();
            }
        }
    }
}

fn github_repo_to_repository(repo: &github_api::GhRepo) -> forge::Repository {
    forge::Repository {
        full_name: repo.full_name.clone(),
        owner: repo.owner.clone(),
        name: repo.name.clone(),
        private: repo.private,
        default_branch: repo.default_branch.clone(),
        clone_url: repo.clone_url.clone(),
        platform: forge::Platform::GitHub,
        stars: None,
        forks: None,
        description: None,
        updated_at: None,
    }
}

fn prompt_repo_selection(repos: &[forge::Repository]) -> Vec<usize> {
    println!("  ◈  Pilih repository yang ingin di-scan:");
    prompt_repository_indexes(
        repos.len(),
        |index| println!("      {:>4}. {}", index + 1, repos[index].full_name),
        "  > Pilihan repo: ",
    )
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

fn build_forge_file_scan_config(
    args: &Cli,
    verbose: bool,
    extra_patterns: Vec<streamer::DynPattern>,
) -> (Instant, forge_scan::FileScanConfig) {
    let started_at = Instant::now();
    let scan_config = forge_scan::FileScanConfig {
        workspace: PathBuf::new(),
        repository_name: String::new(),
        max_blob_bytes: args.max_blob_size * 1024 * 1024,
        workers: args.workers,
        scan_scope: args.scan_scope,
        max_history: args.max_history,
        scan_binaries: !args.no_scan_binaries,
        exhaustive: args.exhaustive,
        entropy_threshold: args.entropy_threshold,
        live: args.live,
        pipe: args.pipe,
        verbose,
        max_findings: args.max_findings,
        stop_on_critical: args.stop_on_critical,
        extra_patterns: Arc::new(extra_patterns),
        stop_flag: Arc::new(AtomicBool::new(false)),
        all_findings: Arc::new(tokio::sync::Mutex::new(Vec::<streamer::Finding>::new())),
        tech_stack_set: Arc::new(tokio::sync::Mutex::new(
            std::collections::HashSet::<String>::new(),
        )),
        blobs_scanned: Arc::new(AtomicUsize::new(0)),
        blobs_failed: Arc::new(AtomicUsize::new(0)),
        bytes_scanned: Arc::new(AtomicUsize::new(0)),
        outcome_stats: Arc::new(tokio::sync::Mutex::new(
            streamer::ScanOutcomeStats::default(),
        )),
    };
    (started_at, scan_config)
}

struct SelectedForgeScan<'a> {
    args: &'a Cli,
    verbose: bool,
    extra_patterns: Vec<streamer::DynPattern>,
    forge: Arc<dyn Forge>,
    selected_repos: &'a [forge::Repository],
    report_name: &'a str,
    persist_source: bool,
    temp_prefix: &'a str,
}

async fn scan_selected_forge_repositories(
    request: SelectedForgeScan<'_>,
) -> streamer::StreamResult {
    let SelectedForgeScan {
        args,
        verbose,
        extra_patterns,
        forge,
        selected_repos,
        report_name,
        persist_source,
        temp_prefix,
    } = request;
    let (started_at, scan_config) = build_forge_file_scan_config(args, verbose, extra_patterns);
    let workspace_lifecycle = forge_scan::WorkspaceLifecycle::new(
        Path::new(&args.output),
        report_name,
        persist_source,
        temp_prefix,
    );
    forge_scan::run_repository_scan_loop(
        forge,
        selected_repos,
        &workspace_lifecycle,
        scan_config,
        |forge, repo, entry, head_sha| async move {
            forge.get_blob_entry_at(&repo, &entry, &head_sha).await
        },
        started_at,
    )
    .await
}

struct PreparedForgeSelection {
    repositories: Vec<forge::Repository>,
    persist_source: bool,
}

fn prepare_forge_selection(
    args: &Cli,
    verbose: bool,
    interactive: bool,
    repositories: &[forge::Repository],
    selected_indexes: Vec<usize>,
) -> Option<PreparedForgeSelection> {
    let selected_repos = select_by_indexes(repositories, selected_indexes);
    if selected_repos.is_empty() {
        return None;
    }
    if verbose {
        println!(
            "  ✔  Selected {} repositories for scanning",
            selected_repos.len()
        );
    }
    let persist_source = if interactive {
        prompt_save_choice(args.save)
    } else {
        args.save
    };
    if verbose {
        println!(
            "  ◈  Source persistence: {}\\n",
            if persist_source {
                "enabled (--save behavior)"
            } else {
                "disabled (temporary workspace)"
            }
        );
    }
    Some(PreparedForgeSelection {
        repositories: selected_repos,
        persist_source,
    })
}

// ════════════════════════════════════════════════
// TOKEN SCAN PIPELINE
// ════════════════════════════════════════════════

async fn collect_github_repositories(
    client: &HttpClient,
    verbose: bool,
    repo_allowlist: Option<&[String]>,
) -> anyhow::Result<Vec<forge::Repository>> {
    if verbose {
        println!("  ◈  Enumerating repositories...");
    }
    let mut all_repos = github_api::list_repos(client)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list repositories: {}", error))?;
    match github_api::list_user_orgs(client).await {
        Ok(orgs) => {
            for org in orgs {
                match github_api::list_org_repos(client, &org).await {
                    Ok(org_repos) => all_repos.extend(org_repos),
                    Err(error) => {
                        if verbose {
                            eprintln!("  ⚠   Skipping org '{}': {}", org, error);
                        }
                    }
                }
            }
        }
        Err(error) => {
            if verbose {
                eprintln!("  ⚠   Could not list orgs: {}", error);
            }
        }
    }
    let mut seen_names = std::collections::HashSet::new();
    all_repos.retain(|repo| seen_names.insert(repo.full_name.clone()));
    if let Some(allowlist) = repo_allowlist {
        let requested: std::collections::HashSet<String> = allowlist
            .iter()
            .map(|name| name.trim().trim_matches('/').to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect();
        if requested.is_empty() {
            return Err(anyhow::anyhow!(
                "Token target repository allowlist is empty."
            ));
        }
        all_repos.retain(|repo| requested.contains(&repo.full_name.to_ascii_lowercase()));
        if all_repos.is_empty() {
            return Err(anyhow::anyhow!(
                "None of the requested repositories are accessible."
            ));
        }
    }
    Ok(all_repos.iter().map(github_repo_to_repository).collect())
}

fn reject_unsupported_forge_scope(result: &streamer::StreamResult) -> anyhow::Result<()> {
    if let Some(capability) = result.outcome_stats.unsupported_capability.as_deref() {
        anyhow::bail!(
            "Unsupported capability: forge scan scope '{}' is not available for this provider",
            capability
        );
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_token_scan(
    args: &Cli,
    rep: &Reporter,
    base_cfg: HttpConfig,
    token: &str,
    repo_allowlist: Option<&[String]>,
    extra_patterns: Vec<streamer::DynPattern>,
) -> anyhow::Result<ScanSummary> {
    let quiet = args.quiet || args.pipe;
    let verbose = !quiet;

    // SEC-001: Validate GitHub token format
    if let Err(e) = validation::validate_github_token(token) {
        return Err(anyhow::anyhow!("Invalid GitHub token: {}", e));
    }

    if !quiet {
        rep.banner();
        println!("  Mode  : GitHub Token Scan");
        println!("  Output: {}\n", args.output);
    }

    // ── 1. Build GitHub API client ───────────────
    let gh_client = match github_api::build_github_client(base_cfg, token) {
        Ok(c) => c,
        Err(e) => return Err(anyhow::anyhow!("Failed to build GitHub API client: {}", e)),
    };
    let gh_forge = github_api::GitHubForgeClient::new(gh_client.clone());

    // ── 2. Authenticate ──────────────────────────
    if verbose {
        println!("  ◈  Authenticating with GitHub API...");
    }
    let (login, _name) = match github_api::whoami(&gh_client).await {
        Ok(r) => r,
        Err(e) => return Err(anyhow::anyhow!("Authentication failed: {}", e)),
    };
    if verbose {
        println!("  ✔  Authenticated as: {}\n", login.cyan().bold());
    }

    // ── 3. Enumerate repositories ────────────────
    let unified_repos = collect_github_repositories(&gh_client, verbose, repo_allowlist).await?;
    let total_repos = unified_repos.len();
    if total_repos == 0 {
        if verbose {
            println!("  ⚠   Tidak ada repository yang bisa di-scan.\n");
        }
        return Ok(ScanSummary {
            report_path: String::new(),
            findings_count: 0,
            risk_score: 0,
        });
    }
    if verbose {
        println!("  ✔  Found {} repositories\n", total_repos);
    }
    let interactive = !args.quiet && !args.pipe;
    let selected_indexes = if interactive {
        prompt_repo_selection(&unified_repos)
    } else {
        (0..unified_repos.len()).collect()
    };
    let Some(selection) =
        prepare_forge_selection(args, verbose, interactive, &unified_repos, selected_indexes)
    else {
        return Err(anyhow::anyhow!("Tidak ada repository valid yang dipilih."));
    };
    let selected_repos = selection.repositories;
    let selected_repo_count = selected_repos.len();
    let persist_source = selection.persist_source;
    // ── 4. Acquire source workspace and scan selected repositories ─────
    let stream_r = scan_selected_forge_repositories(SelectedForgeScan {
        args,
        verbose,
        extra_patterns,
        forge: Arc::new(gh_forge),
        selected_repos: &selected_repos,
        report_name: &format!("token_{}", login),
        persist_source,
        temp_prefix: "gitrecon_token_scan",
    })
    .await;

    reject_unsupported_forge_scope(&stream_r)?;

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    let summary = finalize_standard_token_report(StandardTokenReport {
        args,
        rep,
        login: &login,
        repo_count: selected_repo_count,
        mode: "token",
        report_prefix: "token",
        stream_r: &stream_r,
        verbose,
    })
    .await;
    Ok(summary)
}

#[allow(clippy::too_many_lines)]
async fn run_gitlab_token_scan(
    args: &Cli,
    rep: &Reporter,
    base_cfg: HttpConfig,
    token: &str,
    gitlab_url: Option<&str>,
    extra_patterns: Vec<streamer::DynPattern>,
) -> anyhow::Result<()> {
    let quiet = args.quiet || args.pipe;
    let verbose = !quiet;

    // SEC-001: Validate GitLab token format (starts with glpat- or is a valid token)
    if let Err(e) = validation::validate_gitlab_token(token) {
        return Err(anyhow::anyhow!("Invalid GitLab token: {}", e));
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
        Ok(c) => c,
        Err(e) => return Err(anyhow::anyhow!("Failed to build GitLab API client: {}", e)),
    };

    // ── 2–3. Authenticate, identify, and enumerate ─────
    let session = forge_scan::establish_session(
        Box::new(gitlab_api::GitLabForgeClient::new(
            gl_client.clone(),
            api_base.clone(),
        )),
        token,
        verbose,
        "GitLab",
    )
    .await
    .map_err(|error| anyhow::anyhow!("forge scan setup failed: {}", error))?;
    let gl_forge = session.forge;
    let login = session.login;
    let all_repos = session.repositories;
    let total_repos = all_repos.len();
    if total_repos == 0 {
        return Ok(());
    }
    let interactive = !args.quiet && !args.pipe;

    // Convert to a displayable format for selection
    let gl_projects: Vec<gitlab_api::GlProject> = all_repos
        .iter()
        .map(|r| gitlab_api::GlProject {
            full_name: r.full_name.clone(),
            owner: r.owner.clone(),
            name: r.name.clone(),
            private: r.private,
            default_branch: r.default_branch.clone(),
            clone_url: r.clone_url.clone(),
        })
        .collect();

    let selected_indexes = if interactive {
        prompt_gitlab_repo_selection(&gl_projects)
    } else {
        (0..all_repos.len()).collect()
    };
    let Some(selection) =
        prepare_forge_selection(args, verbose, interactive, &all_repos, selected_indexes)
    else {
        eprintln!("  ✘  Tidak ada repository valid yang dipilih.");
        return Ok(());
    };
    let selected_repos = selection.repositories;
    let selected_repo_count = selected_repos.len();
    let persist_source = selection.persist_source;
    // ── 4. Acquire source workspace and scan selected repositories ─────
    let stream_r = scan_selected_forge_repositories(SelectedForgeScan {
        args,
        verbose,
        extra_patterns,
        forge: gl_forge,
        selected_repos: &selected_repos,
        report_name: &format!("gitlab_{}", login),
        persist_source,
        temp_prefix: "gitrecon_gitlab_scan",
    })
    .await;

    reject_unsupported_forge_scope(&stream_r)?;

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }
    let _ = finalize_standard_token_report(StandardTokenReport {
        args,
        rep,
        login: &login,
        repo_count: selected_repo_count,
        mode: "gitlab_token",
        report_prefix: "gitlab",
        stream_r: &stream_r,
        verbose,
    })
    .await;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_bitbucket_token_scan(
    args: &Cli,
    rep: &Reporter,
    base_cfg: HttpConfig,
    token: &str,
    bitbucket_url: Option<&str>,
    extra_patterns: Vec<streamer::DynPattern>,
) -> anyhow::Result<()> {
    let quiet = args.quiet || args.pipe;
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
    let (bb_client, api_base) =
        match bitbucket_api::build_bitbucket_client(base_cfg, token, bitbucket_url) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("  ✘  Failed to build Bitbucket API client: {}", e);
                return Err(anyhow::anyhow!("forge scan setup failed"));
            }
        };

    // ── 2–3. Authenticate, identify, and enumerate ─────
    let session = forge_scan::establish_session(
        Box::new(bitbucket_api::BitbucketForgeClient::new(
            bb_client.clone(),
            api_base.clone(),
        )),
        token,
        verbose,
        "Bitbucket",
    )
    .await
    .map_err(|error| anyhow::anyhow!("forge scan setup failed: {}", error))?;
    let bb_forge = session.forge;
    let login = session.login;
    let all_repos = session.repositories;
    let total_repos = all_repos.len();
    if total_repos == 0 {
        return Ok(());
    }
    let interactive = !args.quiet && !args.pipe;

    // Convert to a displayable format for selection
    let bb_repos: Vec<bitbucket_api::BbRepo> = all_repos
        .iter()
        .map(|r| bitbucket_api::BbRepo {
            full_name: r.full_name.clone(),
            owner: r.owner.clone(),
            name: r.name.clone(),
            private: r.private,
            default_branch: r.default_branch.clone(),
            clone_url: r.clone_url.clone(),
        })
        .collect();

    let selected_indexes = if interactive {
        prompt_bitbucket_repo_selection(&bb_repos)
    } else {
        (0..all_repos.len()).collect()
    };
    let Some(selection) =
        prepare_forge_selection(args, verbose, interactive, &all_repos, selected_indexes)
    else {
        eprintln!("  ✘  Tidak ada repository valid yang dipilih.");
        return Ok(());
    };
    let selected_repos = selection.repositories;
    let selected_repo_count = selected_repos.len();
    let persist_source = selection.persist_source;
    // ── 4. Acquire source workspace and scan selected repositories ─────
    let stream_r = scan_selected_forge_repositories(SelectedForgeScan {
        args,
        verbose,
        extra_patterns,
        forge: bb_forge,
        selected_repos: &selected_repos,
        report_name: &format!("bitbucket_{}", login),
        persist_source,
        temp_prefix: "gitrecon_bitbucket_scan",
    })
    .await;

    reject_unsupported_forge_scope(&stream_r)?;

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    let _ = finalize_standard_token_report(StandardTokenReport {
        args,
        rep,
        login: &login,
        repo_count: selected_repo_count,
        mode: "bitbucket_token",
        report_prefix: "bitbucket",
        stream_r: &stream_r,
        verbose,
    })
    .await;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_gitea_token_scan(
    args: &Cli,
    rep: &Reporter,
    base_cfg: HttpConfig,
    token: &str,
    gitea_url: Option<&str>,
    extra_patterns: Vec<streamer::DynPattern>,
) -> anyhow::Result<()> {
    let quiet = args.quiet || args.pipe;
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
        Ok(c) => c,
        Err(e) => {
            eprintln!("  ✘  Failed to build Gitea API client: {}", e);
            return Err(anyhow::anyhow!("forge scan setup failed"));
        }
    };

    // ── 2–3. Authenticate, identify, and enumerate ─────
    let session = forge_scan::establish_session(
        Box::new(gitea_api::GiteaForgeClient::new(
            gt_client.clone(),
            api_base.clone(),
        )),
        token,
        verbose,
        "Gitea",
    )
    .await
    .map_err(|error| anyhow::anyhow!("forge scan setup failed: {}", error))?;
    let gt_forge = session.forge;
    let login = session.login;
    let all_repos = session.repositories;
    let total_repos = all_repos.len();
    if total_repos == 0 {
        return Ok(());
    }
    let interactive = !args.quiet && !args.pipe;

    // Convert to a displayable format for selection
    let gt_repos: Vec<gitea_api::GtRepo> = all_repos
        .iter()
        .map(|r| gitea_api::GtRepo {
            full_name: r.full_name.clone(),
            owner: r.owner.clone(),
            name: r.name.clone(),
            private: r.private,
            default_branch: r.default_branch.clone(),
            clone_url: r.clone_url.clone(),
        })
        .collect();

    let selected_indexes = if interactive {
        prompt_gitea_repo_selection(&gt_repos)
    } else {
        (0..all_repos.len()).collect()
    };
    let Some(selection) =
        prepare_forge_selection(args, verbose, interactive, &all_repos, selected_indexes)
    else {
        eprintln!("  ✘  Tidak ada repository valid yang dipilih.");
        return Ok(());
    };
    let selected_repos = selection.repositories;
    let selected_repo_count = selected_repos.len();
    let persist_source = selection.persist_source;
    // ── 4. Acquire source workspace and scan selected repositories ─────
    let stream_r = scan_selected_forge_repositories(SelectedForgeScan {
        args,
        verbose,
        extra_patterns,
        forge: gt_forge,
        selected_repos: &selected_repos,
        report_name: &format!("gitea_{}", login),
        persist_source,
        temp_prefix: "gitrecon_gitea_scan",
    })
    .await;

    reject_unsupported_forge_scope(&stream_r)?;

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    let _ = finalize_standard_token_report(StandardTokenReport {
        args,
        rep,
        login: &login,
        repo_count: selected_repo_count,
        mode: "gitea_token",
        report_prefix: "gitea",
        stream_r: &stream_r,
        verbose,
    })
    .await;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_azure_token_scan(
    args: &Cli,
    rep: &Reporter,
    base_cfg: HttpConfig,
    token: &str,
    azure_url: Option<&str>,
    extra_patterns: Vec<streamer::DynPattern>,
) -> anyhow::Result<()> {
    let quiet = args.quiet || args.pipe;
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
        Ok(c) => c,
        Err(e) => {
            eprintln!("  ✘  Failed to build Azure DevOps API client: {}", e);
            return Err(anyhow::anyhow!("forge scan setup failed"));
        }
    };

    // ── 2–3. Authenticate, identify, and enumerate ─────
    let session = forge_scan::establish_session(
        Box::new(azure_api::AzureForgeClient::new(
            az_client.clone(),
            api_base.clone(),
        )),
        token,
        verbose,
        "Azure DevOps",
    )
    .await
    .map_err(|error| anyhow::anyhow!("forge scan setup failed: {}", error))?;
    let az_forge = session.forge;
    let login = session.login;
    let all_repos = session.repositories;
    let total_repos = all_repos.len();
    if total_repos == 0 {
        if verbose {
            println!("  →  Azure DevOps requires organization context. Try specifying:");
            println!("  →  --azure-url https://dev.azure.com/{{org}}");
            println!("  →  For on-premise: --azure-url https://{{server}}/{{collection}}");
        }
        return Ok(());
    }
    let interactive = !args.quiet && !args.pipe;

    // Convert to a displayable format for selection
    let az_repos: Vec<azure_api::AzRepo> = all_repos
        .iter()
        .map(|r| azure_api::AzRepo {
            id: r.full_name.clone(),
            name: r.name.clone(),
            private: r.private,
            default_branch: r.default_branch.clone(),
            clone_url: r.clone_url.clone(),
            description: r.description.clone(),
            updated_at: r.updated_at.clone(),
        })
        .collect();

    let selected_indexes = if interactive {
        prompt_azure_repo_selection(&az_repos)
    } else {
        (0..all_repos.len()).collect()
    };
    let Some(selection) =
        prepare_forge_selection(args, verbose, interactive, &all_repos, selected_indexes)
    else {
        eprintln!("  ✘  No valid repositories selected.");
        return Ok(());
    };
    let selected_repos = selection.repositories;
    let persist_source = selection.persist_source;
    // ── 4. Acquire source workspace and scan selected repositories ─────
    let stream_r = scan_selected_forge_repositories(SelectedForgeScan {
        args,
        verbose,
        extra_patterns,
        forge: az_forge,
        selected_repos: &selected_repos,
        report_name: &format!("azure_{}", login),
        persist_source,
        temp_prefix: "gitrecon_azure_scan",
    })
    .await;

    reject_unsupported_forge_scope(&stream_r)?;

    // ── 6. Terminal summary ──────────────────────
    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    let report_name = format!("azure_{}", login);
    let _ = finalize_provider_report(
        args,
        rep,
        ProviderReport {
            report_name: &report_name,
            stream_r: &stream_r,
            report_context: ReportContext::Stream {
                target: "azure_token",
            },
            verbose,
            webhook_style: WebhookSuccessStyle::Azure,
            pipe_summary: serde_json::json!({
                "target": azure_url.unwrap_or("https://dev.azure.com"),
                "scan_type": "azure_token",
                "repos": selected_repos.iter().map(|r| &r.full_name).collect::<Vec<_>>(),
                "findings": stream_r.findings.len(),
                "tech": stream_r.tech_stack.clone(),
                "blobs": stream_r.blobs_scanned,
                "bytes": stream_r.bytes_scanned,
                "elapsed": stream_r.elapsed_s,
                "risk_score": stream_r.risk_score(),
            }),
            token_report: None,
            print_saved_notice: true,
        },
    )
    .await;
    Ok(())
}

/// Prompt for GitLab repository selection.
fn prompt_gitlab_repo_selection(repos: &[gitlab_api::GlProject]) -> Vec<usize> {
    println!("  ◈  Pilih repository yang ingin di-scan:");
    prompt_repository_indexes(
        repos.len(),
        |index| println!("      {:>4}. {}", index + 1, repos[index].full_name),
        "  > Pilihan repo: ",
    )
}

/// Prompt for Bitbucket repository selection.
fn prompt_bitbucket_repo_selection(repos: &[bitbucket_api::BbRepo]) -> Vec<usize> {
    println!("  ◈  Pilih repository yang ingin di-scan:");
    prompt_repository_indexes(
        repos.len(),
        |index| println!("      {:>4}. {}", index + 1, repos[index].full_name),
        "  > Pilihan repo: ",
    )
}

/// Prompt for Gitea repository selection.
fn prompt_gitea_repo_selection(repos: &[gitea_api::GtRepo]) -> Vec<usize> {
    println!("  ◈  Pilih repository yang ingin di-scan:");
    prompt_repository_indexes(
        repos.len(),
        |index| println!("      {:>4}. {}", index + 1, repos[index].full_name),
        "  > Pilihan repo: ",
    )
}

struct ProviderReport<'a> {
    report_name: &'a str,
    stream_r: &'a streamer::StreamResult,
    report_context: ReportContext<'a>,
    verbose: bool,
    webhook_style: WebhookSuccessStyle,
    pipe_summary: serde_json::Value,
    token_report: Option<(&'a str, usize)>,
    print_saved_notice: bool,
}

async fn finalize_provider_report(
    args: &Cli,
    rep: &Reporter,
    report: ProviderReport<'_>,
) -> ScanSummary {
    let ProviderReport {
        report_name,
        stream_r,
        report_context,
        verbose,
        webhook_style,
        pipe_summary,
        token_report,
        print_saved_notice,
    } = report;
    let report_path = reporter::build_report_path(&args.output, report_name, &args.format);
    let save_result = rep.save_scan_report(
        &report_path,
        &args.format,
        report_name,
        stream_r,
        report_context,
    );
    if let Err(error) = save_result {
        eprintln!("  ⚠   Could not save report: {}", error);
    } else if print_saved_notice && !args.quiet {
        println!("  📄  Saved: {}\\n", report_path);
    }
    if let Some((login, repo_count)) = token_report {
        if verbose && !args.pipe {
            rep.print_token_report(login, repo_count, stream_r, &report_path);
        }
    }
    deliver_report_webhook_if_configured(rep, args, &report_path, verbose, webhook_style).await;
    if args.pipe {
        println!(
            "{}",
            serde_json::to_string(&pipe_summary).unwrap_or_default()
        );
    }
    if verbose && !args.pipe {
        println!("  ✔  Done\\n");
    }
    ScanSummary {
        report_path,
        findings_count: stream_r.findings.len(),
        risk_score: stream_r.risk_score(),
    }
}

struct StandardTokenReport<'a> {
    args: &'a Cli,
    rep: &'a Reporter,
    login: &'a str,
    repo_count: usize,
    mode: &'a str,
    report_prefix: &'a str,
    stream_r: &'a streamer::StreamResult,
    verbose: bool,
}

async fn finalize_standard_token_report(request: StandardTokenReport<'_>) -> ScanSummary {
    let StandardTokenReport {
        args,
        rep,
        login,
        repo_count,
        mode,
        report_prefix,
        stream_r,
        verbose,
    } = request;
    let report_name = format!("{}_{}", report_prefix, login);
    finalize_provider_report(
        args,
        rep,
        ProviderReport {
            report_name: &report_name,
            stream_r,
            report_context: ReportContext::Token { login, repo_count },
            verbose,
            webhook_style: WebhookSuccessStyle::Standard,
            pipe_summary: serde_json::json!({
                "type": "summary",
                "mode": mode,
                "user": login,
                "repos": repo_count,
                "findings": stream_r.findings.len(),
                "risk_score": stream_r.risk_score(),
            }),
            token_report: Some((login, repo_count)),
            print_saved_notice: false,
        },
    )
    .await
}

async fn finalize_dir_report(
    args: &Cli,
    rep: &Reporter,
    display_root: &str,
    report_name: &str,
    stream_r: &streamer::StreamResult,
    verbose: bool,
) -> ScanSummary {
    let report_path = reporter::build_report_path(&args.output, report_name, &args.format);
    let save_result = rep.save_scan_report(
        &report_path,
        &args.format,
        display_root,
        stream_r,
        ReportContext::Stream {
            target: display_root,
        },
    );
    if let Err(error) = save_result {
        eprintln!("  ⚠   Could not save report: {}", error);
    }
    if verbose && !args.pipe {
        rep.print_summary(display_root, stream_r, &report_path);
    }
    deliver_report_webhook_if_configured(
        rep,
        args,
        &report_path,
        verbose,
        WebhookSuccessStyle::Standard,
    )
    .await;
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
        println!("  ✔  Done\\n");
    }
    ScanSummary {
        report_path,
        findings_count: stream_r.findings.len(),
        risk_score: stream_r.risk_score(),
    }
}

/// Prompt for Azure DevOps repository selection.
fn prompt_azure_repo_selection(repos: &[azure_api::AzRepo]) -> Vec<usize> {
    println!("  📋  Available repositories:\n");
    for (i, r) in repos.iter().enumerate() {
        let visibility = if r.private { "🔒" } else { "🌍" };
        let desc = r.description.as_deref().unwrap_or("No description");
        println!(
            "    [{}] {} {} - {}",
            (i + 1).to_string().cyan(),
            visibility,
            r.name.bold(),
            desc.dimmed()
        );
    }
    println!();

    loop {
        print!("  🔖  Select repositories (numbers comma-separated, or 'all'): ");
        io::stdout().flush().unwrap_or(());

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {}
            Err(_) => {
                eprintln!("  ✘  Failed to read input");
                return (0..repos.len()).collect();
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

async fn run_dir_scan(
    args: &Cli,
    rep: &Reporter,
    _client: &HttpClient,
    dir: &str,
    extra_patterns: Vec<streamer::DynPattern>,
) -> anyhow::Result<ScanSummary> {
    let quiet = args.quiet || args.pipe;
    let verbose = !quiet;

    // SEC-001: Validate directory path
    let canonical_root = match validation::validate_directory_path(dir) {
        Ok(p) => PathBuf::from(p),
        Err(e) => return Err(e),
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
        .filter(|(path, _)| !args.no_scan_binaries || !is_binary_extension(&path.to_string_lossy()))
        .filter(|(_, size)| *size <= max_blob_bytes as u64)
        .map(|(path, _)| path)
        .collect();
    candidates.sort_by_key(|path| {
        if streamer::is_ai_sensitive_path(&path.to_string_lossy()) {
            0
        } else {
            1
        }
    });
    if verbose {
        println!("  ◈  Found {} candidate files\n", candidates.len());
    }
    let display_root = canonical_root.to_string_lossy().to_string();
    let stream_r = dir_pipeline::scan_local_files(dir_pipeline::LocalScanConfig {
        candidates,
        root: canonical_root.clone(),
        display_root: display_root.clone(),
        max_blob_bytes,
        workers: args.workers,
        no_scan_binaries: args.no_scan_binaries,
        exhaustive: args.exhaustive,
        max_findings: args.max_findings,
        stop_on_critical: args.stop_on_critical,
        entropy_threshold: args.entropy_threshold,
        extra_patterns,
        verbose,
        emit_findings: args.live || args.pipe,
    })
    .await;

    if verbose && !args.pipe {
        rep.print_findings_summary(&stream_r.findings);
    }

    let report_name = format!("dir_{}", dir_target_name(&canonical_root));
    Ok(finalize_dir_report(args, rep, &display_root, &report_name, &stream_r, verbose).await)
}
/// Detect tech stack from a file path (filename/extension signals only).
fn detect_tech_from_path(path: &str, out: &mut Vec<String>) {
    use lazy_static::lazy_static;
    use regex::Regex;
    lazy_static! {
        static ref TECH_PATTERNS: Vec<(&'static str, Regex)> = vec![
            (
                "Python",
                Regex::new(r"requirements\.txt|setup\.py|Pipfile|pyproject\.toml|manage\.py")
                    .unwrap()
            ),
            (
                "Node.js",
                Regex::new(r"package\.json|yarn\.lock|package-lock\.json|\.nvmrc").unwrap()
            ),
            (
                "PHP",
                Regex::new(r"composer\.json|composer\.lock|\.php$").unwrap()
            ),
            (
                "Ruby",
                Regex::new(r"Gemfile|\.ruby-version|\.rb$|Rakefile").unwrap()
            ),
            (
                "Java",
                Regex::new(r"pom\.xml|build\.gradle|\.java$").unwrap()
            ),
            ("Go", Regex::new(r"go\.mod|go\.sum|\.go$").unwrap()),
            (
                "Rust",
                Regex::new(r"Cargo\.toml|Cargo\.lock|\.rs$").unwrap()
            ),
            (".NET", Regex::new(r"\.csproj|\.sln|web\.config").unwrap()),
            ("Docker", Regex::new(r"Dockerfile|docker-compose").unwrap()),
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
        timeout: Duration::from_secs(args.timeout),
        retries: args.retries,
        delay: Duration::ZERO,
        jitter: Duration::ZERO,
        proxy: args.proxy.clone(),
        verify_ssl: !args.insecure, // BUG-HTTP-003: Use insecure flag to control SSL verification
        custom_ua: None,
        extra_headers: vec![],
        max_size: 100 * 1024 * 1024,
        adaptive_timeout: false,
        max_timeout: Duration::from_secs(args.max_timeout),
        use_http2: args.http2,
        rate_limit_rps: None,
        proxy_list: vec![],
        ua_pool: vec![],
        retry_strategy,
    })
}

/// Sprint 2 (S2.4): validate webhook URL against SSRF/exfil rules and deliver via a
/// plain unauthenticated HTTP client. Every webhook call-site (7 in main.rs) funnels
/// through here so the policy is applied uniformly — previously the Azure branch
/// bypassed validation AND leaked the operator's Azure PAT by reusing `az_client`.
///
/// Returns `Ok(true)` on 2xx delivery, `Ok(false)` on non-2xx, `Err` on validation
/// failure. Validation errors are surfaced to the caller so operators know the report
/// was NOT delivered (and why) rather than a silent skip.
async fn try_deliver_webhook(
    reporter: &reporter::Reporter,
    args: &Cli,
    webhook_url: &str,
    body: &str,
) -> anyhow::Result<bool> {
    let _validated = validation::validate_webhook_url(
        webhook_url,
        args.webhook_allow_http,
        args.webhook_allow_internal,
    )?;
    let cfg = build_plain_http_config(args)?;
    let plain_client = http_client::HttpClient::new(cfg)?;
    Ok(reporter
        .send_webhook(
            webhook_url,
            args.webhook_secret.as_deref(),
            body,
            &plain_client,
        )
        .await)
}

#[derive(Clone, Copy)]
enum WebhookSuccessStyle {
    Standard,
    Azure,
}

async fn deliver_report_webhook_if_configured(
    reporter: &Reporter,
    args: &Cli,
    report_path: &str,
    verbose: bool,
    style: WebhookSuccessStyle,
) {
    let Some(webhook_url) = args.webhook.as_deref() else {
        return;
    };
    let Ok(json_body) = std::fs::read_to_string(report_path) else {
        return;
    };
    match try_deliver_webhook(reporter, args, webhook_url, &json_body).await {
        Ok(true) => {
            if verbose {
                match style {
                    WebhookSuccessStyle::Standard => {
                        println!("  ✔   Webhook delivered to {}", webhook_url);
                    }
                    WebhookSuccessStyle::Azure => println!("  📡  Webhook sent\n"),
                }
            }
        }
        Ok(false) => {
            if verbose {
                eprintln!("  ⚠   Webhook delivery failed (non-2xx response)");
            }
        }
        Err(error) => eprintln!("  ✗   Webhook refused: {}", error),
    }
}

fn should_short_circuit_partial_exposure(objects_accessible: bool, report_partial: bool) -> bool {
    !objects_accessible && report_partial
}

fn validate_runtime_numeric_options(args: &Cli) -> Result<(), String> {
    const MAX_DELAY_SECONDS: f64 = 3_600.0;
    const MAX_RATE_RPS: f64 = 1_000_000.0;

    for (name, value) in [("--delay", args.delay), ("--jitter", args.jitter)] {
        if !value.is_finite() || !(0.0..=MAX_DELAY_SECONDS).contains(&value) {
            return Err(format!(
                "{} must be finite and in [0, {}] seconds, got {}",
                name, MAX_DELAY_SECONDS, value
            ));
        }
    }
    if !args.entropy_threshold.is_finite() || args.entropy_threshold < 0.0 {
        return Err(format!(
            "--entropy-threshold must be finite and non-negative, got {}",
            args.entropy_threshold
        ));
    }
    if let Some(rate) = args.rate {
        if !rate.is_finite() || !(0.0..=MAX_RATE_RPS).contains(&rate) {
            return Err(format!(
                "--rate must be finite and in [0, {}] requests/second, got {}",
                MAX_RATE_RPS, rate
            ));
        }
    }
    let forge_token_selected = args.token.is_some()
        || args.gitlab_token.is_some()
        || args.bitbucket_token.is_some()
        || args.gitea_token.is_some()
        || args.azure_token.is_some();
    if args.scan_scope == ForgeScanScope::History && !forge_token_selected {
        return Err(
            "--scan-scope history is only valid with a forge token target; URL and directory scans use snapshot scope"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_parallel_targets(value: usize) -> Result<(), String> {
    if value == 0 || value > 1000 {
        Err(format!(
            "--parallel-targets must be in [1, 1000], got {}",
            value
        ))
    } else {
        Ok(())
    }
}

// ════════════════════════════════════════════════
// MAIN PIPELINE
// ════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    // SEC-004: Initialize signal handlers for cleanup on interruption
    let cleanup_flag = temp_cleanup::init_global_cleanup().await;

    // Sprint 2 (S2.6): sweep orphan gitrecon_*_scan_* dirs left by a prior force-kill
    // BEFORE this run starts creating new ones. Anything > 1h old belongs to a dead
    // process — we cannot leak someone else's live workspace because their PID no
    // longer holds those files. Runs synchronously; typically a few ms.
    temp_cleanup::sweep_orphan_temp_dirs(std::time::Duration::from_secs(60 * 60));

    // Register signal handlers for graceful shutdown.
    // Sprint 5 (S5.8): signal-hook-tokio is Unix-only (uses UnixStream); on Windows
    // we let the default OS handler terminate the process — Drop will fire on
    // TempDirGuard for normal exits, and the startup sweep above catches force-kill
    // remnants on the next run.
    #[cfg(unix)]
    {
        let cleanup_flag_clone = cleanup_flag.clone();
        tokio::spawn(async move {
            use signal_hook_tokio::Signals;

            let mut signals =
                match Signals::new([signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM]) {
                    Ok(s) => s,
                    Err(_) => return,
                };

            #[allow(clippy::never_loop)]
            #[allow(clippy::while_let_loop)]
            loop {
                match signals.next().await {
                    Some(_signal) => {
                        cleanup_flag_clone.store(true, Ordering::Relaxed);
                        eprintln!("\n  [!] Interrupted. Cleaning up temporary files...");
                        // Sprint 2 (S2.6): Drop handlers don't run under process::exit,
                        // so we walk the registered TempDirGuard paths ourselves before
                        // exiting. Previously reconstructed source of every scanned repo
                        // survived in $TMPDIR after Ctrl+C — a nasty exposure on shared
                        // red-team boxes.
                        temp_cleanup::cleanup_registered_paths();
                        std::process::exit(130); // Exit code for SIGINT (128 + 2)
                    }
                    None => break,
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = cleanup_flag; // silence unused warning on Windows
    }

    let args = Cli::parse();
    if let Some(checkpoint_dir) = args.checkpoint_dir.as_deref() {
        std::env::set_var(checkpoint::CHECKPOINT_DIR_ENV, checkpoint_dir);
    }

    // Sprint 4 (S4.1): explicit numeric range checks. Clap's value_parser!.range()
    // only supports the fixed-width numeric types (u8..u64/i8..i64), not `usize`,
    // so the usize fields validate here at start-up instead.
    if let Err(error) = validate_parallel_targets(args.parallel_targets) {
        eprintln!("  ✘  {}", error);
        std::process::exit(2);
    }
    if let Err(error) = validate_runtime_numeric_options(&args) {
        eprintln!("  ✘  {}", error);
        std::process::exit(2);
    }

    // BUG-HTTP-003: Warn when SSL verification is disabled
    if args.insecure {
        eprintln!("  ⚠️  WARNING: SSL verification disabled - MITM vulnerability!");
        eprintln!("     Your connections are NOT secure. Traffic can be intercepted.");
    }

    // SCAN-001: Parse false-positive keywords from CLI flag
    let false_positive_keywords: Vec<String> =
        if let Some(ref keywords_str) = args.false_positive_keywords {
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

    // Theme system: Load theme at startup
    let theme = if let Some(ref theme_path) = args.theme_file {
        // Load from custom theme file
        if let Ok(content) = std::fs::read_to_string(theme_path) {
            if let Ok(custom_theme) = toml::from_str::<Theme>(&content) {
                custom_theme
            } else {
                eprintln!("  ⚠   Failed to parse theme file, using defaults");
                Theme::load()
            }
        } else {
            eprintln!("  ⚠   Could not read theme file, using defaults");
            Theme::load()
        }
    } else {
        // Load from default config path or use defaults
        Theme::load()
    };

    // Apply CLI overrides to theme
    let mut theme = theme;
    if args.no_unicode {
        theme.unicode = false;
    }
    if args.compact {
        theme.compact = true;
    }
    if let Some(ref banner_style) = args.banner_style {
        theme.banner_style = match banner_style.to_lowercase().as_str() {
            "minimal" => ThemeBannerStyle::Minimal,
            "standard" => ThemeBannerStyle::Standard,
            "full" => ThemeBannerStyle::Full,
            "none" => ThemeBannerStyle::None,
            _ => ThemeBannerStyle::Standard,
        };
    }

    // Setup reporter and flags — done early so token mode can use them
    let quiet = args.quiet || args.pipe;
    let verbose = !quiet;
    let rep = Reporter::new(args.no_color, &theme);

    // SEC-001: Validate output path — reject empty, non-directory, and system paths
    // (Sprint 4 S4.2: rejects /etc, /usr, /var, /root, /boot, /sys, /proc, /dev on
    // Linux; C:\Windows, C:\Program Files, C:\ProgramData on Windows).
    // We overwrite args.output with the canonical form so every downstream
    // `PathBuf::from(&args.output)` and `format!(".../{}...", args.output)` uses the
    // resolved absolute path — previously the ".../" concat could silently escape a
    // symlinked output_dir back into a system location.
    let mut args = args;
    match validation::validate_output_path(&args.output) {
        Ok(canonical) => {
            args.output = canonical;
        }
        Err(e) => {
            eprintln!("  ✘  Invalid output path: {}", e);
            std::process::exit(1);
        }
    }

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
    let resume_target = if args.resume
        && args.url.is_none()
        && args.targets.is_none()
        && args.token.is_none()
        && args.dir.is_none()
    {
        if verbose {
            println!("  ◈  --resume flag: searching for latest checkpoint...");
        }

        match checkpoint::find_latest_checkpoints(1) {
            Ok(latest) if !latest.is_empty() => {
                let latest_cp = &latest[0];
                let ts =
                    chrono::DateTime::<chrono::Utc>::from_timestamp(latest_cp.updated_at as i64, 0)
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
                        eprintln!(
                            "  → Use: gitrecon --resume with original --token or --dir argument"
                        );
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
            }
            Err(e) => {
                eprintln!("  ⚠   Cannot read UA file '{}': {}", ua_file, e);
                // Not fatal - continue with empty pool
            }
        }
    }

    let mut extra_headers = match parse_extra_headers(&args.headers) {
        Ok(headers) => headers,
        Err(error) => {
            eprintln!("  ✘  {}", error);
            std::process::exit(1);
        }
    };
    if args.ua_git {
        extra_headers.push(("Git-Protocol".to_string(), "version=2".to_string()));
    }

    let mut proxy_list = vec![];
    if let Some(ref pl_file) = args.proxy_list {
        if let Ok(content) = std::fs::read_to_string(pl_file) {
            proxy_list = content
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.to_string())
                .collect();
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
        timeout: Duration::from_secs(args.timeout),
        retries: args.retries,
        delay: Duration::from_secs_f64(args.delay),
        jitter: Duration::from_secs_f64(args.jitter),
        proxy: args.proxy.clone(),
        verify_ssl: !args.insecure, // BUG-HTTP-003: Use insecure flag to control SSL verification
        custom_ua: if args.ua_git {
            Some("git/2.46.0".to_string())
        } else {
            args.user_agent.clone()
        },
        extra_headers,
        max_size: 100 * 1024 * 1024,
        adaptive_timeout: !args.no_adaptive_timeout,
        max_timeout: Duration::from_secs(args.max_timeout),
        use_http2: args.http2,
        rate_limit_rps: args.rate,
        proxy_list,
        ua_pool,
        retry_strategy,
    };

    let client = match HttpClient::new(base_cfg.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  ✘  Failed to create HTTP client: {}", e);
            std::process::exit(1);
        }
    };

    // Load extra patterns (shared by both URL and token modes)
    let extra_patterns = if let Some(ref patterns_file) = args.patterns {
        match streamer::load_patterns_from_file(patterns_file) {
            Ok(patterns) => patterns,
            Err(e) => {
                eprintln!(
                    "  ⚠   Failed to load patterns from '{}': {}",
                    patterns_file, e
                );
                std::process::exit(1);
            }
        }
    } else {
        vec![]
    };

    // Validate mutually exclusive modes
    if args.token.is_some()
        && (args.dir.is_some()
            || args.targets.is_some()
            || args.url.is_some()
            || args.gitlab_token.is_some()
            || args.bitbucket_token.is_some()
            || args.gitea_token.is_some()
            || args.azure_token.is_some())
    {
        eprintln!("  ✘  --token mode cannot be combined with --dir, <URL>, --targets, --gitlab-token, --bitbucket-token, --gitea-token, or --azure-token.");
        std::process::exit(1);
    }
    if args.gitlab_token.is_some()
        && (args.dir.is_some()
            || args.targets.is_some()
            || args.url.is_some()
            || args.token.is_some()
            || args.bitbucket_token.is_some()
            || args.gitea_token.is_some()
            || args.azure_token.is_some())
    {
        eprintln!("  ✘  --gitlab-token mode cannot be combined with --dir, <URL>, --targets, --token, --bitbucket-token, --gitea-token, or --azure-token.");
        std::process::exit(1);
    }
    if args.bitbucket_token.is_some()
        && (args.dir.is_some()
            || args.targets.is_some()
            || args.url.is_some()
            || args.token.is_some()
            || args.gitlab_token.is_some()
            || args.gitea_token.is_some()
            || args.azure_token.is_some())
    {
        eprintln!("  ✘  --bitbucket-token mode cannot be combined with --dir, <URL>, --targets, --token, --gitlab-token, --gitea-token, or --azure-token.");
        std::process::exit(1);
    }
    if args.gitea_token.is_some()
        && (args.dir.is_some()
            || args.targets.is_some()
            || args.url.is_some()
            || args.token.is_some()
            || args.gitlab_token.is_some()
            || args.bitbucket_token.is_some()
            || args.azure_token.is_some())
    {
        eprintln!("  ✘  --gitea-token mode cannot be combined with --dir, <URL>, --targets, --token, --gitlab-token, --bitbucket-token, or --azure-token.");
        std::process::exit(1);
    }
    if args.azure_token.is_some()
        && (args.dir.is_some()
            || args.targets.is_some()
            || args.url.is_some()
            || args.token.is_some()
            || args.gitlab_token.is_some()
            || args.bitbucket_token.is_some()
            || args.gitea_token.is_some())
    {
        eprintln!("  ✘  --azure-token mode cannot be combined with --dir, <URL>, --targets, --token, --gitlab-token, --bitbucket-token, or --gitea-token.");
        std::process::exit(1);
    }
    if args.dir.is_some() && (args.targets.is_some() || args.url.is_some()) {
        eprintln!("  ✘  --dir mode cannot be combined with <URL> or --targets.");
        std::process::exit(1);
    }

    if args.dry_run {
        if let Err(error) =
            validate_dry_run_inputs(&args, effective_url.as_deref(), &extra_patterns)
        {
            eprintln!("  ✘  Dry-run validation failed: {}", error);
            std::process::exit(1);
        }
        return;
    }

    // ── Token mode: enumerate GitHub repos and scan ──
    if let Some(ref token) = args.token {
        if let Err(e) = run_token_scan(&args, &rep, base_cfg, token, None, extra_patterns).await {
            eprintln!("  ✘  Token scan failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // ── GitLab Token mode: enumerate GitLab projects and scan ──
    if let Some(ref gitlab_token) = args.gitlab_token {
        if let Err(e) = run_gitlab_token_scan(
            &args,
            &rep,
            base_cfg,
            gitlab_token,
            args.gitlab_url.as_deref(),
            extra_patterns,
        )
        .await
        {
            eprintln!("  ✘  GitLab token scan failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // ── Bitbucket Token mode: enumerate Bitbucket repositories and scan ──
    if let Some(ref bitbucket_token) = args.bitbucket_token {
        if let Err(e) = run_bitbucket_token_scan(
            &args,
            &rep,
            base_cfg,
            bitbucket_token,
            args.bitbucket_url.as_deref(),
            extra_patterns,
        )
        .await
        {
            eprintln!("  ✘  Bitbucket token scan failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // ── Gitea Token mode: enumerate Gitea/Forgejo repositories and scan ──
    if let Some(ref gitea_token) = args.gitea_token {
        if let Err(e) = run_gitea_token_scan(
            &args,
            &rep,
            base_cfg,
            gitea_token,
            args.gitea_url.as_deref(),
            extra_patterns,
        )
        .await
        {
            eprintln!("  ✘  Gitea token scan failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // ── Azure DevOps Token mode: enumerate Azure DevOps repositories and scan ──
    if let Some(ref azure_token) = args.azure_token {
        if let Err(e) = run_azure_token_scan(
            &args,
            &rep,
            base_cfg,
            azure_token,
            args.azure_url.as_deref(),
            extra_patterns,
        )
        .await
        {
            eprintln!("  ✘  Azure token scan failed: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // ── Directory mode: local recursive text scan ──
    if let Some(ref dir) = args.dir {
        if let Err(e) = run_dir_scan(&args, &rep, &client, dir, extra_patterns).await {
            eprintln!("  ✘  Directory scan failed: {}", e);
            std::process::exit(1);
        }
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
        match load_targets(targets_file, args.fuzz) {
            Ok(parsed) => {
                if verbose {
                    println!("  ◈  Loaded {} targets from {}", parsed.len(), targets_file);
                }
                parsed
            }
            Err(error) => {
                eprintln!("  ⚠   {}", error);
                std::process::exit(1);
            }
        }
    } else {
        // Single URL target (from command line argument or --resume)
        let normalized_url = match normalize_url(&raw_url) {
            Ok(url) => url,
            Err(error) => {
                eprintln!("  ✘  {}", error);
                std::process::exit(1);
            }
        };
        vec![Target::Url {
            url: normalized_url,
            fuzz: Some(args.fuzz),
        }]
    };

    let mut all_results: Vec<TargetOutcome> = Vec::new();
    if args.parallel_targets > 1 {
        let args_ref = &args;
        let rep_ref = &rep;
        let client_ref = &client;
        let base_cfg_ref = &base_cfg;
        let false_positive_ref = &false_positive_keywords;
        let total_targets = targets.len();
        let mut parallel_results = futures::stream::iter(targets.iter().cloned().enumerate())
            .map(|(index, target)| {
                let patterns = extra_patterns.clone();
                async move {
                    let outcome = match target {
                        Target::Url { url, fuzz } => {
                            run_url_target(
                                UrlRunContext {
                                    args: args_ref,
                                    rep: rep_ref,
                                    client: client_ref,
                                    target_num: index + 1,
                                    total_targets,
                                    extra_patterns: patterns,
                                    false_positive_keywords: false_positive_ref,
                                    quiet,
                                    verbose,
                                },
                                url,
                                fuzz.unwrap_or(args_ref.fuzz),
                            )
                            .await
                        }
                        non_url_target => {
                            run_non_url_target(
                                args_ref,
                                rep_ref,
                                client_ref,
                                base_cfg_ref,
                                non_url_target,
                                patterns,
                            )
                            .await
                        }
                    };
                    (index, outcome)
                }
            })
            .buffer_unordered(args.parallel_targets)
            .collect::<Vec<_>>()
            .await;
        parallel_results.sort_by_key(|(index, _)| *index);
        all_results.extend(parallel_results.into_iter().map(|(_, outcome)| outcome));
    } else {
        for (idx, target) in targets.iter().enumerate() {
            let target_num = idx + 1;
            let total_targets = targets.len();

            // A-1: Handle different target types
            match target {
                Target::Url { url, fuzz } => {
                    let outcome = run_url_target(
                        UrlRunContext {
                            args: &args,
                            rep: &rep,
                            client: &client,
                            target_num,
                            total_targets,
                            extra_patterns: extra_patterns.clone(),
                            false_positive_keywords: &false_positive_keywords,
                            quiet,
                            verbose,
                        },
                        url.clone(),
                        fuzz.unwrap_or(args.fuzz),
                    )
                    .await;
                    all_results.push(outcome);
                }
                Target::Token { token, repos } => {
                    let target = format!("token:{}", &token[..token.len().min(8)]);
                    if verbose {
                        println!("  [{}] Running token target {}", target_num, target);
                    }
                    let scan_result = run_token_scan(
                        &args,
                        &rep,
                        base_cfg.clone(),
                        token,
                        repos.as_deref(),
                        extra_patterns.clone(),
                    )
                    .await;
                    let outcome = match scan_result {
                        Ok(summary) => TargetOutcome::success(target, "TOKEN", &summary),
                        Err(error) => TargetOutcome::failure(target, "TOKEN", error.to_string()),
                    };
                    all_results.push(outcome);
                }
                Target::Dir { dir } => {
                    if verbose {
                        println!("  [{}] Running directory target {}", target_num, dir);
                    }
                    let target = dir.clone();
                    let scan_result =
                        run_dir_scan(&args, &rep, &client, dir, extra_patterns.clone()).await;
                    let outcome = match scan_result {
                        Ok(summary) => TargetOutcome::success(target, "DIR", &summary),
                        Err(error) => TargetOutcome::failure(target, "DIR", error.to_string()),
                    };
                    all_results.push(outcome);
                }
            }
        }
    }
    // A-1: Generate aggregate report if multiple targets were processed
    if targets.len() > 1 && !all_results.is_empty() {
        let aggregate_path = format!("{}/aggregate_report.json", args.output);
        if let Err(e) =
            reporter::save_aggregate_report(&aggregate_path, targets.len(), &all_results)
        {
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
    token: &str,
) -> anyhow::Result<Box<dyn Forge>> {
    let platform = forge::Platform::from_url(url)
        .ok_or_else(|| anyhow::anyhow!("Could not detect platform from URL: {}", url))?;
    create_forge_client(platform, base_cfg, token, Some(url)).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_exposure_short_circuit_is_opt_in() {
        assert!(!should_short_circuit_partial_exposure(false, false));
        assert!(should_short_circuit_partial_exposure(false, true));
        assert!(!should_short_circuit_partial_exposure(true, false));
        assert!(!should_short_circuit_partial_exposure(true, true));
    }

    #[test]
    fn parallel_target_bounds_reject_zero_and_excessive_values() {
        assert!(validate_parallel_targets(0).is_err());
        assert!(validate_parallel_targets(1001).is_err());
        assert!(validate_parallel_targets(1).is_ok());
        assert!(validate_parallel_targets(1000).is_ok());
    }

    #[test]
    fn runtime_numeric_validation_rejects_non_finite_values() {
        let mut args = Cli::try_parse_from(["gitrecon", "https://example.test"]).unwrap();
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            args.delay = value;
            assert!(validate_runtime_numeric_options(&args).is_err());
            args.jitter = value;
            assert!(validate_runtime_numeric_options(&args).is_err());
            args.entropy_threshold = value;
            assert!(validate_runtime_numeric_options(&args).is_err());
            args.rate = Some(value);
            assert!(validate_runtime_numeric_options(&args).is_err());
        }
    }

    #[test]
    fn runtime_numeric_validation_rejects_negative_values() {
        let mut args = Cli::try_parse_from(["gitrecon", "https://example.test"]).unwrap();
        args.delay = -0.001;
        assert!(validate_runtime_numeric_options(&args).is_err());
        args.delay = 0.0;
        args.jitter = -0.001;
        assert!(validate_runtime_numeric_options(&args).is_err());
        args.jitter = 0.0;
        args.entropy_threshold = -0.001;
        assert!(validate_runtime_numeric_options(&args).is_err());
        args.entropy_threshold = 4.5;
        args.rate = Some(-0.001);
        assert!(validate_runtime_numeric_options(&args).is_err());
    }

    #[test]
    fn runtime_numeric_validation_preserves_safe_boundaries() {
        let mut args = Cli::try_parse_from(["gitrecon", "https://example.test"]).unwrap();
        args.delay = 3_600.0;
        args.jitter = 3_600.0;
        args.entropy_threshold = 0.0;
        args.rate = Some(0.0);
        assert!(validate_runtime_numeric_options(&args).is_ok());
        args.rate = Some(1_000_000.0);
        assert!(validate_runtime_numeric_options(&args).is_ok());
        args.delay = 3_600.001;
        assert!(validate_runtime_numeric_options(&args).is_err());
    }

    #[test]
    fn cli_offensive_defaults_and_opt_outs() {
        let defaults = Cli::try_parse_from(["gitrecon", "--dir", "./target"]).unwrap();
        assert!(!defaults.exhaustive);
        assert!(!defaults.no_scan_binaries);
        assert!(!defaults.no_verify_objects);
        assert!(!defaults.partial_exposure);

        let opt_outs = Cli::try_parse_from([
            "gitrecon",
            "--dir",
            "./target",
            "--exhaustive",
            "--no-scan-binaries",
            "--no-verify-objects",
            "--partial-exposure",
        ])
        .unwrap();
        assert!(opt_outs.exhaustive);
        assert!(opt_outs.no_scan_binaries);
        assert!(opt_outs.no_verify_objects);
        assert!(opt_outs.partial_exposure);
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
    fn test_parse_repo_selection_input_all() {
        assert_eq!(parse_repo_selection_input("all", 3).unwrap(), vec![0, 1, 2]);
        assert_eq!(parse_repo_selection_input("ALL", 2).unwrap(), vec![0, 1]);
    }

    #[test]
    fn test_parse_repo_selection_input_multi_and_dedup() {
        assert_eq!(
            parse_repo_selection_input(" 3,1,3, 2 ", 4).unwrap(),
            vec![0, 1, 2]
        );
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
        use std::fs;
        use temp_cleanup::TempDirGuard;

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
        use std::fs;
        use temp_cleanup::TempDirGuard;

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
        use std::fs;
        use temp_cleanup::TempDirGuard;

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

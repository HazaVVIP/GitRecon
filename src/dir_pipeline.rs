//! Local-directory scanning pipeline.
//!
//! Keeps local file traversal and binary/text policy separate from target routing,
//! reporting, and aggregate outcome handling in the binary root.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use futures::StreamExt;

use crate::binary_adapter::binary_findings_to_findings;
use crate::streamer::{self, DynPattern, Finding, StreamResult};

const BINARY_DETECTION_PROBE_SIZE: usize = 8192;
const NULL_BYTE_THRESHOLD: usize = 10;
const RECENT_FINDINGS_WINDOW: usize = 20;

pub(crate) struct LocalScanConfig {
    pub(crate) candidates: Vec<PathBuf>,
    pub(crate) root: PathBuf,
    pub(crate) display_root: String,
    pub(crate) max_blob_bytes: usize,
    pub(crate) workers: usize,
    pub(crate) no_scan_binaries: bool,
    pub(crate) exhaustive: bool,
    pub(crate) max_findings: usize,
    pub(crate) stop_on_critical: bool,
    pub(crate) entropy_threshold: f64,
    pub(crate) extra_patterns: Vec<DynPattern>,
    pub(crate) verbose: bool,
    pub(crate) emit_findings: bool,
}

pub(crate) async fn scan_local_files(config: LocalScanConfig) -> StreamResult {
    let LocalScanConfig {
        candidates,
        root,
        display_root,
        max_blob_bytes,
        workers,
        no_scan_binaries,
        exhaustive,
        max_findings,
        stop_on_critical,
        entropy_threshold,
        extra_patterns,
        verbose,
        emit_findings,
    } = config;
    let started_at = Instant::now();
    let all_findings = Arc::new(tokio::sync::Mutex::new(Vec::<Finding>::new()));
    let tech_stack_set = Arc::new(tokio::sync::Mutex::new(HashSet::<String>::new()));
    let blobs_scanned = Arc::new(AtomicUsize::new(0));
    let blobs_failed = Arc::new(AtomicUsize::new(0));
    let bytes_scanned = Arc::new(AtomicUsize::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let extra_patterns = Arc::new(extra_patterns);
    let file_stream = futures::stream::iter(candidates)
        .map(|path| {
            let stop = stop_flag.clone();
            let extra_patterns = extra_patterns.clone();
            let root = root.clone();
            let display_root = display_root.clone();
            async move {
                if stop.load(Ordering::Relaxed) {
                    return (vec![], vec![], 0usize, false, true);
                }
                let data = match tokio::fs::read(&path).await {
                    Ok(data) => data,
                    Err(_) => return (vec![], vec![], 0usize, true, false),
                };
                if data.is_empty() {
                    return (vec![], vec![], 0usize, false, false);
                }
                let probe = &data[..data.len().min(BINARY_DETECTION_PROBE_SIZE)];
                let null_count = probe.iter().filter(|&&byte| byte == 0).count();
                if null_count > NULL_BYTE_THRESHOLD {
                    if no_scan_binaries {
                        return (vec![], vec![], data.len(), false, false);
                    }
                    let findings = binary_findings_to_findings(
                        &data,
                        &path.to_string_lossy(),
                        max_blob_bytes,
                        exhaustive,
                    );
                    return (findings, vec![], data.len(), false, false);
                }
                let text = String::from_utf8_lossy(&data);
                let relative_path = path
                    .strip_prefix(&root)
                    .map(|relative| relative.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                let source = format!("{}/{}", display_root, relative_path);
                let findings = if exhaustive {
                    streamer::scan_text_exhaustive(
                        &text,
                        &source,
                        &extra_patterns,
                        entropy_threshold,
                    )
                } else {
                    streamer::scan_text(&text, &source, &extra_patterns, entropy_threshold)
                };
                let mut technologies = Vec::new();
                detect_tech_from_path(&relative_path, &mut technologies);
                (findings, technologies, data.len(), false, false)
            }
        })
        .buffer_unordered(workers);
    futures::pin_mut!(file_stream);
    while let Some((findings, technologies, bytes, failed, skipped_by_stop)) =
        file_stream.next().await
    {
        if skipped_by_stop {
            continue;
        }
        if failed {
            blobs_failed.fetch_add(1, Ordering::Relaxed);
        } else {
            blobs_scanned.fetch_add(1, Ordering::Relaxed);
            bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
        }
        if !technologies.is_empty() {
            let mut stack = tech_stack_set.lock().await;
            stack.extend(technologies);
        }
        if findings.is_empty() {
            continue;
        }
        if emit_findings {
            for finding in &findings {
                println!(
                    "{}",
                    serde_json::to_string(&finding.to_dict()).unwrap_or_default()
                );
            }
        }
        let mut all = all_findings.lock().await;
        all.extend(findings);
        if should_stop_scan(&all, max_findings, stop_on_critical) {
            stop_flag.store(true, Ordering::Relaxed);
            if verbose {
                if max_findings > 0 && all.len() >= max_findings {
                    println!("\n  [!] Reached --max-findings limit. Stopping scan.");
                } else {
                    println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                }
            }
        }
    }
    let findings = all_findings.lock().await.clone();
    let mut technologies: Vec<String> = tech_stack_set.lock().await.iter().cloned().collect();
    technologies.sort();
    StreamResult {
        findings,
        contributors: vec![],
        tech_stack: technologies,
        commit_count: 0,
        blobs_scanned: blobs_scanned.load(Ordering::Relaxed),
        blobs_failed: blobs_failed.load(Ordering::Relaxed),
        bytes_scanned: bytes_scanned.load(Ordering::Relaxed),
        elapsed_s: started_at.elapsed().as_secs_f64(),
        files_saved: 0,
        files_save_failed: 0,
        cache_hits: 0,
        cache_misses: 0,
        cache_stats: None,
        object_source_stats: crate::streamer::ObjectSourceStats::default(),
        rate_limit_allowed: 0,
        rate_limit_dropped: 0,
        rate_limit_wait_ms: 0,
    }
}

fn should_stop_scan(findings: &[Finding], max_findings: usize, stop_on_critical: bool) -> bool {
    (max_findings > 0 && findings.len() >= max_findings)
        || (stop_on_critical
            && findings
                .iter()
                .rev()
                .take(RECENT_FINDINGS_WINDOW)
                .any(|finding| finding.severity == "CRITICAL"))
}

fn detect_tech_from_path(path: &str, output: &mut Vec<String>) {
    const SIGNALS: &[(&str, &[&str])] = &[
        (
            "Python",
            &[
                "requirements.txt",
                "setup.py",
                "Pipfile",
                "pyproject.toml",
                "manage.py",
            ],
        ),
        (
            "Node.js",
            &["package.json", "yarn.lock", "package-lock.json", ".nvmrc"],
        ),
        ("PHP", &["composer.json", "composer.lock", ".php"]),
        ("Ruby", &["Gemfile", ".ruby-version", ".rb", "Rakefile"]),
        ("Java", &["pom.xml", "build.gradle", ".java"]),
        ("Go", &["go.mod", "go.sum", ".go"]),
        ("Rust", &["Cargo.toml", "Cargo.lock", ".rs"]),
        (".NET", &[".csproj", ".sln", "web.config"]),
        ("Docker", &["Dockerfile", "docker-compose"]),
        ("Terraform", &[".tf", "terraform.tfvars"]),
    ];
    for (technology, signals) in SIGNALS {
        if signals.iter().any(|signal| path.contains(signal)) {
            output.push((*technology).to_string());
        }
    }
}

//! Local-directory scanning pipeline.
//!
//! Keeps local file traversal and binary/text policy separate from target routing,
//! reporting, and aggregate outcome handling in the binary root.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use futures::StreamExt;

use crate::binary_scanner;
use crate::content_scanner::{ContentScanOutcome, ContentScanner, ScanAccumulator};
use crate::streamer::{DynPattern, StreamResult};

const BINARY_DETECTION_PROBE_SIZE: usize = 8192;
const NULL_BYTE_THRESHOLD: usize = 10;

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
    pub(crate) false_positive_keywords: Vec<String>,
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
        false_positive_keywords,
        extra_patterns,
        verbose,
        emit_findings,
    } = config;
    let started_at = Instant::now();
    let accumulator = Arc::new(tokio::sync::Mutex::new(ScanAccumulator::default()));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let scanner = Arc::new(ContentScanner::new(
        Arc::new(extra_patterns),
        exhaustive,
        entropy_threshold,
        max_blob_bytes,
        !no_scan_binaries,
    ));
    let file_stream = futures::stream::iter(candidates)
        .map(|path| {
            let stop = stop_flag.clone();
            let scanner = scanner.clone();
            let false_positive_keywords = false_positive_keywords.clone();
            let root = root.clone();
            let display_root = display_root.clone();
            async move {
                if stop.load(Ordering::Relaxed) {
                    return (ContentScanOutcome::stopped(), Vec::new());
                }
                let data = match tokio::fs::read(&path).await {
                    Ok(data) => data,
                    Err(_) => return (ContentScanOutcome::failed(), Vec::new()),
                };
                let relative_path = path
                    .strip_prefix(&root)
                    .map(|relative| relative.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                let source = format!("{}/{}", display_root, relative_path);
                let dispatch = binary_scanner::classify_binary(
                    &data,
                    &source,
                    BINARY_DETECTION_PROBE_SIZE,
                    NULL_BYTE_THRESHOLD,
                );
                let is_binary = dispatch.is_binary();
                let scan_path = if is_binary {
                    path.to_string_lossy().into_owned()
                } else {
                    source
                };
                let outcome = scanner.scan(&data, &scan_path, is_binary, &false_positive_keywords);
                let mut technologies = Vec::new();
                if !is_binary {
                    detect_tech_from_path(&relative_path, &mut technologies);
                }
                (outcome, technologies)
            }
        })
        .buffer_unordered(workers);
    futures::pin_mut!(file_stream);
    while let Some((outcome, technologies)) = file_stream.next().await {
        let mut accumulator = accumulator.lock().await;
        if emit_findings {
            for finding in &outcome.findings {
                println!(
                    "{}",
                    serde_json::to_string(&finding.to_dict()).unwrap_or_default()
                );
            }
        }
        accumulator.absorb(outcome, technologies);
        if crate::content_scanner::should_stop_scan(
            &accumulator.findings,
            max_findings,
            stop_on_critical,
        ) {
            stop_flag.store(true, Ordering::Relaxed);
            if verbose {
                if max_findings > 0 && accumulator.findings.len() >= max_findings {
                    println!("\\n  [!] Reached --max-findings limit. Stopping scan.");
                } else {
                    println!("\\n  [!] --stop-on-critical triggered. Stopping scan.");
                }
            }
        }
    }
    let accumulator = Arc::try_unwrap(accumulator)
        .expect("local scan accumulator has no remaining workers")
        .into_inner();
    accumulator.into_stream_result(started_at)
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

#[cfg(test)]
mod tests {
    use super::{scan_local_files, LocalScanConfig};
    use std::fs;
    use std::path::PathBuf;

    #[tokio::test]
    async fn local_scan_forwards_custom_false_positive_keywords() {
        let root = std::env::temp_dir().join(format!(
            "gitrecon-local-keyword-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("test root should be creatable");
        let file = root.join("config.env");
        fs::write(
            &file,
            b"api_key = \"synthetic_value_123456\" # internal-fixture",
        )
        .expect("test fixture should be writable");

        let result = scan_local_files(LocalScanConfig {
            candidates: vec![PathBuf::from(&file)],
            root: root.clone(),
            display_root: root.to_string_lossy().into_owned(),
            max_blob_bytes: 1024,
            workers: 1,
            no_scan_binaries: false,
            exhaustive: false,
            max_findings: 0,
            stop_on_critical: false,
            entropy_threshold: 4.5,
            false_positive_keywords: vec!["internal-fixture".to_string()],
            extra_patterns: Vec::new(),
            verbose: false,
            emit_findings: false,
        })
        .await;

        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].pattern_id, "api_key");
        assert_eq!(result.findings[0].severity, "MEDIUM");
        assert!(result.findings[0].confidence_adjustment.is_some());
        fs::remove_dir_all(root).expect("test root should be removable");
    }
}

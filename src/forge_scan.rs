//! Provider-neutral repository scan boundaries.
//!
//! Forge adapters remain responsible for fetching provider-specific data. These
//! types describe the common execution contract consumed by the scanner loop.

use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::forge::Repository;
use crate::streamer::{DynPattern, Finding, StreamResult};
use tokio::sync::Mutex;

pub(crate) trait BlobEntry: Clone + Send + 'static {
    fn is_blob(&self) -> bool;
    fn path(&self) -> &str;
    fn sha(&self) -> &str;
    fn size(&self) -> Option<u64>;
}

macro_rules! impl_blob_entry {
    ($entry:ty) => {
        impl BlobEntry for $entry {
            fn is_blob(&self) -> bool {
                self.obj_type == "blob"
            }

            fn path(&self) -> &str {
                &self.path
            }

            fn sha(&self) -> &str {
                &self.sha
            }

            fn size(&self) -> Option<u64> {
                self.size
            }
        }
    };
}

impl_blob_entry!(crate::forge::TreeEntry);
impl_blob_entry!(crate::github_api::GhTreeEntry);
impl_blob_entry!(crate::gitlab_api::GlTreeEntry);
impl_blob_entry!(crate::bitbucket_api::BbTreeEntry);
impl_blob_entry!(crate::gitea_api::GtTreeEntry);
impl_blob_entry!(crate::azure_api::AzTreeEntry);
use futures::StreamExt;

/// Common context for scanning one repository from an authenticated forge.
#[derive(Debug, Clone)]
pub(crate) struct RepositoryScanRequest {
    pub(crate) repository: Repository,
    pub(crate) index: usize,
    pub(crate) total: usize,
}

impl RepositoryScanRequest {
    pub(crate) fn new(repository: Repository, index: usize, total: usize) -> Self {
        Self {
            repository,
            index,
            total,
        }
    }

    pub(crate) fn progress_label(&self) -> String {
        format!(
            "[{}/{}] {}",
            self.index + 1,
            self.total,
            self.repository.full_name
        )
    }

    pub(crate) fn workspace_name(&self) -> String {
        self.repository.full_name.replace('/', "_")
    }
}

/// Provider-neutral counters returned by a repository scan loop.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RepositoryScanOutcome {
    pub(crate) blobs_recovered: usize,
    pub(crate) blobs_failed: usize,
    pub(crate) bytes_scanned: usize,
}

impl RepositoryScanOutcome {
    pub(crate) fn from_counts(
        blobs_recovered: usize,
        blobs_failed: usize,
        bytes_scanned: usize,
    ) -> Self {
        Self {
            blobs_recovered,
            blobs_failed,
            bytes_scanned,
        }
    }
}

/// Reconstruct blob entries into a repository workspace.
///
/// The forge-specific fetch operation is supplied by the caller because each
/// provider uses a different endpoint and authentication shape. All shared
/// safety and resource rules stay here.
pub(crate) async fn reconstruct_blobs<E, F, Fut>(
    tree: Vec<E>,
    workspace: PathBuf,
    max_blob_bytes: usize,
    workers: usize,
    fetch_blob: F,
) -> usize
where
    E: BlobEntry,
    F: Fn(E) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<Vec<u8>>> + Send,
{
    let blobs: Vec<_> = tree
        .into_iter()
        .filter(BlobEntry::is_blob)
        .filter(|entry| {
            entry
                .size()
                .is_none_or(|size| size <= max_blob_bytes as u64)
        })
        .collect();

    let reconstruct_stream = futures::stream::iter(blobs).map(|entry| {
        let fetch_blob = fetch_blob.clone();
        let workspace = workspace.clone();
        async move {
            let data = match fetch_blob(entry.clone()).await {
                Ok(data) if data.len() <= max_blob_bytes => data,
                _ => return false,
            };
            let relative_path = match crate::normalize_repo_relative_path(entry.path()) {
                Some(path) => path,
                None => return false,
            };
            let local_path = workspace.join(relative_path);
            if !local_path.starts_with(&workspace) {
                return false;
            }
            if let Some(parent) = local_path.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    return false;
                }
            }
            std::fs::write(local_path, data).is_ok()
        }
    });
    let reconstruct_stream = reconstruct_stream.buffer_unordered(workers.max(1));

    futures::pin_mut!(reconstruct_stream);
    let mut failed = 0;
    while let Some(success) = reconstruct_stream.next().await {
        if !success {
            failed += 1;
        }
    }
    failed
}

/// Build the provider-neutral result for a forge repository scan.
pub(crate) async fn build_stream_result(
    started_at: Instant,
    all_findings: Arc<Mutex<Vec<Finding>>>,
    tech_stack_set: Arc<Mutex<HashSet<String>>>,
    blobs_scanned: Arc<AtomicUsize>,
    blobs_failed: Arc<AtomicUsize>,
    bytes_scanned: Arc<AtomicUsize>,
) -> StreamResult {
    let findings = all_findings.lock().await.clone();
    let mut tech_stack: Vec<String> = tech_stack_set.lock().await.iter().cloned().collect();
    tech_stack.sort();
    let outcome = RepositoryScanOutcome::from_counts(
        blobs_scanned.load(Ordering::Relaxed),
        blobs_failed.load(Ordering::Relaxed),
        bytes_scanned.load(Ordering::Relaxed),
    );
    StreamResult {
        findings,
        contributors: vec![],
        tech_stack,
        commit_count: 0,
        blobs_scanned: outcome.blobs_recovered,
        blobs_failed: outcome.blobs_failed,
        bytes_scanned: outcome.bytes_scanned,
        elapsed_s: started_at.elapsed().as_secs_f64(),
        files_saved: 0,
        files_save_failed: 0,
        cache_hits: 0,
        cache_misses: 0,
        cache_stats: None,
        rate_limit_allowed: 0,
        rate_limit_dropped: 0,
        rate_limit_wait_ms: 0,
    }
}

/// Configuration and shared state for scanning reconstructed repository files.
#[derive(Clone)]
pub(crate) struct FileScanConfig {
    pub(crate) workspace: PathBuf,
    pub(crate) repository_name: String,
    pub(crate) max_blob_bytes: usize,
    pub(crate) workers: usize,
    pub(crate) exhaustive: bool,
    pub(crate) entropy_threshold: f64,
    pub(crate) live: bool,
    pub(crate) pipe: bool,
    pub(crate) verbose: bool,
    pub(crate) max_findings: usize,
    pub(crate) stop_on_critical: bool,
    pub(crate) extra_patterns: Arc<Vec<DynPattern>>,
    pub(crate) stop_flag: Arc<AtomicBool>,
    pub(crate) all_findings: Arc<Mutex<Vec<Finding>>>,
    pub(crate) tech_stack_set: Arc<Mutex<HashSet<String>>>,
    pub(crate) blobs_scanned: Arc<AtomicUsize>,
    pub(crate) blobs_failed: Arc<AtomicUsize>,
    pub(crate) bytes_scanned: Arc<AtomicUsize>,
}

/// Scan all eligible files in a reconstructed repository workspace.
pub(crate) async fn scan_workspace_files(config: FileScanConfig) {
    let mut candidates: Vec<PathBuf> = crate::collect_local_files(&config.workspace)
        .into_iter()
        .filter(|(path, size)| {
            !crate::binary_adapter::is_binary_extension(&path.to_string_lossy())
                && *size <= config.max_blob_bytes as u64
        })
        .map(|(path, _)| path)
        .collect();
    candidates.sort_by_key(|path| {
        if crate::streamer::is_ai_sensitive_path(&path.to_string_lossy()) {
            0
        } else {
            1
        }
    });

    if config.verbose {
        println!("      Scanning {} workspace files", candidates.len());
    }

    let file_stream = futures::stream::iter(candidates)
        .map(|path| {
            let stop_flag = config.stop_flag.clone();
            let extra_patterns = config.extra_patterns.clone();
            let workspace = config.workspace.clone();
            let repository_name = config.repository_name.clone();
            let entropy_threshold = config.entropy_threshold;
            async move {
                if stop_flag.load(Ordering::Relaxed) {
                    return (Vec::new(), Vec::new(), 0usize, false, true);
                }
                let data = match tokio::fs::read(&path).await {
                    Ok(data) => data,
                    Err(_) => return (Vec::new(), Vec::new(), 0usize, true, false),
                };
                if data.is_empty() {
                    return (Vec::new(), Vec::new(), 0usize, false, false);
                }
                let probe = &data[..data.len().min(crate::BINARY_DETECTION_PROBE_SIZE)];
                let null_count = probe.iter().filter(|&&byte| byte == 0).count();
                if null_count > crate::NULL_BYTE_THRESHOLD {
                    return (Vec::new(), Vec::new(), 0usize, false, false);
                }
                let text = String::from_utf8_lossy(&data);
                let relative_path = path
                    .strip_prefix(&workspace)
                    .map(|relative| relative.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                let source = format!("{}/{}", repository_name, relative_path);
                let findings = if config.exhaustive {
                    crate::streamer::scan_text_exhaustive(
                        &text,
                        &source,
                        &extra_patterns,
                        entropy_threshold,
                    )
                } else {
                    crate::streamer::scan_text(&text, &source, &extra_patterns, entropy_threshold)
                };
                let mut technologies = Vec::new();
                crate::detect_tech_from_path(&relative_path, &mut technologies);
                (findings, technologies, data.len(), false, false)
            }
        })
        .buffer_unordered(config.workers.max(1));
    futures::pin_mut!(file_stream);
    while let Some((findings, technologies, bytes, failed, skipped_by_stop)) =
        file_stream.next().await
    {
        if skipped_by_stop {
            continue;
        }
        if failed {
            config.blobs_failed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if bytes > 0 {
            config.blobs_scanned.fetch_add(1, Ordering::Relaxed);
            config.bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
        }
        if !technologies.is_empty() {
            let mut tech_stack = config.tech_stack_set.lock().await;
            tech_stack.extend(technologies);
        }
        if findings.is_empty() {
            continue;
        }
        if config.live || config.pipe {
            for finding in &findings {
                println!(
                    "{}",
                    serde_json::to_string(&finding.to_dict()).unwrap_or_default()
                );
            }
        }
        let mut all_findings = config.all_findings.lock().await;
        all_findings.extend(findings);
        if crate::should_stop_scan(&all_findings, config.max_findings, config.stop_on_critical) {
            config.stop_flag.store(true, Ordering::Relaxed);
            if config.verbose {
                if config.max_findings > 0 && all_findings.len() >= config.max_findings {
                    println!("\n  [!] Reached --max-findings limit. Stopping scan.");
                } else {
                    println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                }
            }
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use super::{
        build_stream_result, reconstruct_blobs, scan_workspace_files, FileScanConfig,
        RepositoryScanOutcome, RepositoryScanRequest,
    };
    use crate::forge::{Platform, Repository, TreeEntry};
    use crate::streamer::DynPattern;
    use tokio::sync::Mutex;

    fn fixture_repository() -> Repository {
        Repository {
            full_name: "acme/example".to_string(),
            owner: "acme".to_string(),
            name: "example".to_string(),
            private: true,
            default_branch: "main".to_string(),
            clone_url: "https://forge.example/acme/example.git".to_string(),
            platform: Platform::Gitea,
            stars: None,
            forks: None,
            description: None,
            updated_at: None,
        }
    }

    #[test]
    fn request_provides_stable_progress_and_workspace_names() {
        let request = RepositoryScanRequest::new(fixture_repository(), 1, 4);
        assert_eq!(request.progress_label(), "[2/4] acme/example");
        assert_eq!(request.workspace_name(), "acme_example");
    }

    #[tokio::test]
    async fn reconstruct_blobs_writes_safe_entries_and_rejects_traversal() {
        let workspace =
            std::env::temp_dir().join(format!("gitrecon-forge-scan-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).expect("test workspace should be creatable");

        let tree = vec![
            TreeEntry {
                path: "config/settings.toml".to_string(),
                obj_type: "blob".to_string(),
                sha: "safe-sha".to_string(),
                size: Some(7),
                mode: None,
            },
            TreeEntry {
                path: "../escape.txt".to_string(),
                obj_type: "blob".to_string(),
                sha: "unsafe-sha".to_string(),
                size: Some(7),
                mode: None,
            },
            TreeEntry {
                path: "ignored-directory".to_string(),
                obj_type: "tree".to_string(),
                sha: "tree-sha".to_string(),
                size: None,
                mode: None,
            },
        ];
        let failed = reconstruct_blobs(tree, workspace.clone(), 1024, 2, |_entry| async {
            Ok(b"content".to_vec())
        })
        .await;

        assert_eq!(failed, 1);
        assert_eq!(
            fs::read(workspace.join("config/settings.toml")).unwrap(),
            b"content"
        );
        assert!(!workspace.parent().unwrap().join("escape.txt").exists());
        fs::remove_dir_all(workspace).expect("test workspace should be removable");
    }

    #[tokio::test]
    async fn scan_workspace_files_filters_binary_files_and_collects_findings() {
        let workspace =
            std::env::temp_dir().join(format!("gitrecon-file-scan-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).expect("test workspace should be creatable");
        fs::write(workspace.join("config.txt"), b"CUSTOM_ABCD1234").unwrap();
        fs::write(workspace.join("image.png"), [0_u8, 1, 2, 3]).unwrap();

        let all_findings = Arc::new(Mutex::new(Vec::new()));
        let tech_stack_set = Arc::new(Mutex::new(HashSet::new()));
        let blobs_scanned = Arc::new(AtomicUsize::new(0));
        let blobs_failed = Arc::new(AtomicUsize::new(0));
        let bytes_scanned = Arc::new(AtomicUsize::new(0));
        scan_workspace_files(FileScanConfig {
            workspace: workspace.clone(),
            repository_name: "acme/example".to_string(),
            max_blob_bytes: 1024,
            workers: 2,
            exhaustive: true,
            entropy_threshold: 4.5,
            live: false,
            pipe: false,
            verbose: false,
            max_findings: 0,
            stop_on_critical: false,
            extra_patterns: Arc::new(vec![DynPattern {
                id: "custom_token".to_string(),
                sev: "HIGH".to_string(),
                desc: "Custom test token".to_string(),
                regex: regex::Regex::new(r"CUSTOM_[A-Z0-9]{8}").unwrap(),
            }]),
            stop_flag: Arc::new(AtomicBool::new(false)),
            all_findings: all_findings.clone(),
            tech_stack_set,
            blobs_scanned: blobs_scanned.clone(),
            blobs_failed: blobs_failed.clone(),
            bytes_scanned: bytes_scanned.clone(),
        })
        .await;

        let findings = all_findings.lock().await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].filename, "acme/example/config.txt");
        assert_eq!(blobs_scanned.load(Ordering::Relaxed), 1);
        assert_eq!(blobs_failed.load(Ordering::Relaxed), 0);
        assert_eq!(bytes_scanned.load(Ordering::Relaxed), 15);
        drop(findings);
        fs::remove_dir_all(workspace).expect("test workspace should be removable");
    }

    #[tokio::test]
    async fn build_stream_result_aggregates_shared_state() {
        let all_findings = Arc::new(Mutex::new(Vec::new()));
        let tech_stack_set = Arc::new(Mutex::new(HashSet::from([
            "Rust".to_string(),
            "Git".to_string(),
        ])));
        let blobs_scanned = Arc::new(AtomicUsize::new(3));
        let blobs_failed = Arc::new(AtomicUsize::new(1));
        let bytes_scanned = Arc::new(AtomicUsize::new(42));

        let result = build_stream_result(
            Instant::now(),
            all_findings,
            tech_stack_set,
            blobs_scanned,
            blobs_failed,
            bytes_scanned,
        )
        .await;

        assert_eq!(result.findings.len(), 0);
        assert_eq!(result.tech_stack, vec!["Git", "Rust"]);
        assert_eq!(result.blobs_scanned, 3);
        assert_eq!(result.blobs_failed, 1);
        assert_eq!(result.bytes_scanned, 42);
        assert_eq!(result.commit_count, 0);
    }

    #[test]
    fn outcome_accumulates_success_and_failure_counters() {
        let outcome = RepositoryScanOutcome::from_counts(1, 1, 12);
        assert_eq!(
            outcome,
            RepositoryScanOutcome {
                blobs_recovered: 1,
                blobs_failed: 1,
                bytes_scanned: 12,
            }
        );
    }
}

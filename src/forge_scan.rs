//! Provider-neutral repository scan boundaries.
//!
//! Forge adapters remain responsible for fetching provider-specific data. These
//! types describe the common execution contract consumed by the scanner loop.

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::content_scanner::{ContentScanOutcome, ContentScanner, ScanAccumulator};
use crate::forge::{Forge, Repository};
use crate::streamer::{DynPattern, Finding, StreamResult};
use crate::temp_cleanup::TempDirGuard;
use colored::Colorize;
use tokio::sync::Mutex;

const RECENT_FINDINGS_WINDOW: usize = 20;

pub(crate) trait BlobEntry: Clone + Send {
    fn is_blob(&self) -> bool;
    fn path(&self) -> &str;
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

/// Authenticated forge state shared by provider-specific selection and reporting code.
pub(crate) struct ForgeSession {
    pub(crate) forge: Arc<dyn Forge>,
    pub(crate) login: String,
    pub(crate) repositories: Vec<Repository>,
}

/// Authenticate a forge, resolve identity, and enumerate accessible repositories.
pub(crate) async fn establish_session(
    forge: Box<dyn Forge>,
    token: &str,
    verbose: bool,
    platform_name: &str,
) -> anyhow::Result<ForgeSession> {
    if verbose {
        println!("  ◈  Authenticating with {} API...", platform_name);
    }
    let mut forge = forge;
    forge
        .authenticate(token)
        .await
        .map_err(|error| anyhow::anyhow!("Authentication failed: {}", error))?;
    let (login, _name) = forge
        .whoami()
        .await
        .map_err(|error| anyhow::anyhow!("Failed to get user info: {}", error))?;
    if verbose {
        println!("  ✔  Authenticated as: {}\n", login.cyan().bold());
        println!("  ◈  Enumerating repositories...");
    }
    let repositories = forge
        .enumerate_repos(crate::forge::EnumScope::All)
        .await
        .map_err(|error| anyhow::anyhow!("Failed to list repositories: {}", error))?;
    if repositories.is_empty() {
        if verbose {
            println!("  ⚠   Tidak ada repository yang bisa di-scan.\n");
        }
    } else if verbose {
        println!("  ✔  Found {} repositories\n", repositories.len());
    }
    Ok(ForgeSession {
        forge: Arc::from(forge),
        login,
        repositories,
    })
}

/// Owns persisted or temporary workspace roots for a forge scan.
pub(crate) struct WorkspaceLifecycle {
    save_root: Option<PathBuf>,
    temp_guard: Option<TempDirGuard>,
}

impl WorkspaceLifecycle {
    pub(crate) fn new(
        output: &Path,
        report_name: &str,
        persist_source: bool,
        temp_prefix: &str,
    ) -> Self {
        let save_root = persist_source.then(|| output.join(report_name));
        let temp_guard = if persist_source {
            None
        } else {
            let path = std::env::temp_dir().join(format!(
                "{}_{}_{}",
                temp_prefix,
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            ));
            let _ = std::fs::create_dir_all(&path);
            Some(TempDirGuard::new(path))
        };
        Self {
            save_root,
            temp_guard,
        }
    }

    pub(crate) fn repository_path(&self, workspace_name: &str) -> Option<PathBuf> {
        if let Some(root) = self.save_root.as_ref() {
            return Some(root.join(workspace_name));
        }
        self.temp_guard
            .as_ref()
            .and_then(|guard| guard.path().map(|root| root.join(workspace_name)))
    }
}

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
    F: Fn(E) -> Fut + Clone + Send + Sync,
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
        object_source_stats: crate::streamer::ObjectSourceStats::default(),
        outcome_stats: crate::streamer::ScanOutcomeStats::default(),
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
    let scanner = Arc::new(ContentScanner::new(
        config.extra_patterns.clone(),
        config.exhaustive,
        config.entropy_threshold,
        config.max_blob_bytes,
        false,
    ));
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

    let mut accumulator = ScanAccumulator::default();
    let file_stream = futures::stream::iter(candidates)
        .map(|path| {
            let stop_flag = config.stop_flag.clone();
            let scanner = scanner.clone();
            let workspace = config.workspace.clone();
            let repository_name = config.repository_name.clone();
            async move {
                if stop_flag.load(Ordering::Relaxed) {
                    return (ContentScanOutcome::stopped(), Vec::new());
                }
                let data = match tokio::fs::read(&path).await {
                    Ok(data) => data,
                    Err(_) => return (ContentScanOutcome::failed(), Vec::new()),
                };
                if data.is_empty() {
                    return (ContentScanOutcome::empty(), Vec::new());
                }
                let probe = &data[..data.len().min(crate::BINARY_DETECTION_PROBE_SIZE)];
                let null_count = probe.iter().filter(|&&byte| byte == 0).count();
                if null_count > crate::NULL_BYTE_THRESHOLD {
                    return (ContentScanOutcome::empty(), Vec::new());
                }
                let relative_path = path
                    .strip_prefix(&workspace)
                    .map(|relative| relative.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                let source = format!("{}/{}", repository_name, relative_path);
                let outcome = scanner.scan(&data, &source, false);
                let mut technologies = Vec::new();
                crate::detect_tech_from_path(&relative_path, &mut technologies);
                (outcome, technologies)
            }
        })
        .buffer_unordered(config.workers.max(1));
    futures::pin_mut!(file_stream);
    while let Some((outcome, technologies)) = file_stream.next().await {
        if outcome.stopped {
            continue;
        }
        if config.live || config.pipe {
            for finding in &outcome.findings {
                println!(
                    "{}",
                    serde_json::to_string(&finding.to_dict()).unwrap_or_default()
                );
            }
        }
        accumulator.absorb(outcome, technologies);
        let existing_findings = config.all_findings.lock().await.len();
        let local_limit_reached = config.max_findings > 0
            && existing_findings + accumulator.findings.len() >= config.max_findings;
        let local_critical_reached = config.stop_on_critical
            && accumulator
                .findings
                .iter()
                .rev()
                .take(RECENT_FINDINGS_WINDOW)
                .any(|finding| finding.severity == "CRITICAL");
        if local_limit_reached || local_critical_reached {
            config.stop_flag.store(true, Ordering::Relaxed);
            if config.verbose {
                if local_limit_reached {
                    println!("\\n  [!] Reached --max-findings limit. Stopping scan.");
                } else {
                    println!("\\n  [!] --stop-on-critical triggered. Stopping scan.");
                }
            }
            break;
        }
    }

    config
        .blobs_failed
        .fetch_add(accumulator.blobs_failed, Ordering::Relaxed);
    config
        .blobs_scanned
        .fetch_add(accumulator.blobs_scanned, Ordering::Relaxed);
    config
        .bytes_scanned
        .fetch_add(accumulator.bytes_scanned, Ordering::Relaxed);
    {
        let mut all_findings = config.all_findings.lock().await;
        all_findings.extend(accumulator.findings);
    }
    {
        let mut tech_stack = config.tech_stack_set.lock().await;
        tech_stack.extend(accumulator.tech_stack);
    }
}

/// Execute the common per-repository forge scan lifecycle through the Forge trait.
pub(crate) async fn run_repository_scan_loop<F, Fut>(
    forge: Arc<dyn Forge>,
    selected_repos: &[Repository],
    workspace_lifecycle: &WorkspaceLifecycle,
    scan_config: FileScanConfig,
    fetch_blob: F,
    started_at: Instant,
) -> StreamResult
where
    F: Fn(Arc<dyn Forge>, Repository, crate::forge::TreeEntry, String) -> Fut
        + Clone
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = anyhow::Result<Vec<u8>>> + Send,
{
    for (repo_idx, repo) in selected_repos.iter().enumerate() {
        if scan_config.stop_flag.load(Ordering::Relaxed) {
            break;
        }
        let scan_request = RepositoryScanRequest::new(repo.clone(), repo_idx, selected_repos.len());
        if scan_config.verbose {
            println!("  ▶  {}", scan_request.progress_label());
        }
        let head_sha = match forge.get_head_sha(repo, &repo.default_branch).await {
            Ok(head_sha) => head_sha,
            Err(error) => {
                if scan_config.verbose {
                    eprintln!(
                        "    ⚠   Cannot resolve HEAD for {}: {}",
                        repo.full_name, error
                    );
                }
                continue;
            }
        };
        let tree = match forge.get_tree(repo, &repo.default_branch).await {
            Ok(tree) => tree,
            Err(error) => {
                if scan_config.verbose {
                    eprintln!("    ⚠   Cannot get tree for {}: {}", repo.full_name, error);
                }
                continue;
            }
        };
        let Some(repo_workspace) =
            workspace_lifecycle.repository_path(&scan_request.workspace_name())
        else {
            continue;
        };
        let _ = std::fs::create_dir_all(&repo_workspace);
        let blob_count = tree
            .iter()
            .filter(|entry| entry.obj_type == "blob")
            .filter(|entry| {
                entry
                    .size
                    .is_none_or(|size| size <= scan_config.max_blob_bytes as u64)
            })
            .count();
        if scan_config.verbose && blob_count > 0 {
            println!("      Reconstructing {} files into workspace", blob_count);
        }
        let forge_ref = forge.clone();
        let repo_for_blob = repo.clone();
        let fetch_blob_for_repo = fetch_blob.clone();
        let failed = reconstruct_blobs(
            tree,
            repo_workspace.clone(),
            scan_config.max_blob_bytes,
            scan_config.workers,
            move |entry| {
                let forge = forge_ref.clone();
                let repo = repo_for_blob.clone();
                let fetch_blob = fetch_blob_for_repo.clone();
                let head_sha = head_sha.clone();
                async move { fetch_blob(forge, repo, entry, head_sha).await }
            },
        )
        .await;
        scan_config
            .blobs_failed
            .fetch_add(failed, Ordering::Relaxed);
        scan_workspace_files(FileScanConfig {
            workspace: repo_workspace,
            repository_name: repo.full_name.clone(),
            ..scan_config.clone()
        })
        .await;
    }
    build_stream_result(
        started_at,
        scan_config.all_findings.clone(),
        scan_config.tech_stack_set.clone(),
        scan_config.blobs_scanned.clone(),
        scan_config.blobs_failed.clone(),
        scan_config.bytes_scanned.clone(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use super::{
        build_stream_result, establish_session, reconstruct_blobs, run_repository_scan_loop,
        scan_workspace_files, FileScanConfig, RepositoryScanOutcome, RepositoryScanRequest,
        WorkspaceLifecycle,
    };
    use crate::forge::{EnumScope, Forge, Platform, RateLimitInfo, Repository, TreeEntry};
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

    #[test]
    fn workspace_lifecycle_selects_persistent_or_temporary_roots() {
        let output =
            std::env::temp_dir().join(format!("gitrecon-workspace-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&output);
        fs::create_dir_all(&output).expect("test output root should be creatable");

        let persisted =
            WorkspaceLifecycle::new(&output, "github_example", true, "gitrecon_workspace_test");
        assert_eq!(
            persisted.repository_path("acme_example"),
            Some(output.join("github_example/acme_example"))
        );
        drop(persisted);

        let temporary =
            WorkspaceLifecycle::new(&output, "github_example", false, "gitrecon_workspace_test");
        let temporary_repo = temporary
            .repository_path("acme_example")
            .expect("temporary repository path should exist");
        let temporary_root = temporary_repo
            .parent()
            .expect("temporary repository root should exist")
            .to_path_buf();
        assert!(temporary_root.exists());
        drop(temporary);
        assert!(!temporary_root.exists());
        fs::remove_dir_all(output).expect("test output root should be removable");
    }

    struct EmptyForge;

    #[async_trait::async_trait]
    impl Forge for EmptyForge {
        async fn authenticate(&mut self, _token: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn enumerate_repos(&self, _scope: EnumScope) -> anyhow::Result<Vec<Repository>> {
            Ok(Vec::new())
        }

        async fn get_tree(
            &self,
            _repo: &Repository,
            _branch: &str,
        ) -> anyhow::Result<Vec<TreeEntry>> {
            Ok(Vec::new())
        }

        async fn get_blob(&self, _repo: &Repository, _sha: &str) -> anyhow::Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn rate_limit_remaining(&self) -> Option<(u32, std::time::Duration)> {
            None
        }

        fn rate_limit_info(&self) -> Option<RateLimitInfo> {
            None
        }

        fn platform(&self) -> Platform {
            Platform::GitHub
        }

        async fn get_head_sha(&self, _repo: &Repository, _branch: &str) -> anyhow::Result<String> {
            Ok(String::new())
        }

        async fn whoami(&self) -> anyhow::Result<(String, String)> {
            Ok(("empty".to_string(), "Empty Forge".to_string()))
        }
    }

    #[tokio::test]
    async fn establish_session_preserves_identity_and_empty_repository_state() {
        let session =
            establish_session(Box::new(EmptyForge), "synthetic-token", false, "Test Forge")
                .await
                .expect("empty forge session should establish");
        assert_eq!(session.login, "empty");
        assert!(session.repositories.is_empty());
        assert_eq!(session.forge.platform(), Platform::GitHub);
    }

    #[tokio::test]
    async fn run_repository_scan_loop_handles_empty_selection() {
        let workspace = WorkspaceLifecycle::new(
            &std::env::temp_dir(),
            "gitrecon-empty-selection",
            true,
            "gitrecon_empty_selection_scan",
        );
        let result = run_repository_scan_loop(
            Arc::new(EmptyForge),
            &[],
            &workspace,
            FileScanConfig {
                workspace: PathBuf::new(),
                repository_name: String::new(),
                max_blob_bytes: 1024,
                workers: 1,
                exhaustive: true,
                entropy_threshold: 4.5,
                live: false,
                pipe: false,
                verbose: false,
                max_findings: 0,
                stop_on_critical: false,
                extra_patterns: Arc::new(Vec::new()),
                stop_flag: Arc::new(AtomicBool::new(false)),
                all_findings: Arc::new(Mutex::new(Vec::new())),
                tech_stack_set: Arc::new(Mutex::new(HashSet::new())),
                blobs_scanned: Arc::new(AtomicUsize::new(0)),
                blobs_failed: Arc::new(AtomicUsize::new(0)),
                bytes_scanned: Arc::new(AtomicUsize::new(0)),
            },
            |_forge, _repo, _entry, _head_sha| async { Ok(Vec::new()) },
            Instant::now(),
        )
        .await;
        assert!(result.findings.is_empty());
        assert_eq!(result.blobs_scanned, 0);
        assert_eq!(result.blobs_failed, 0);
        assert_eq!(result.bytes_scanned, 0);
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

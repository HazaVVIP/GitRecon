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

use crate::binary_scanner;
use crate::content_scanner::{ContentScanOutcome, ContentScanner, ScanAccumulator};
use crate::forge::{Forge, ForgeScanScope, HistoryChangeStatus, Repository, TreeEntry};
use crate::resource_budget::{ResourceBudget, ResourceStage};
use crate::streamer::{DynPattern, Finding, ScanOutcomeStats, StreamResult};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconstructionOutcome {
    Recovered,
    Failed,
    ResourceSkipped,
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
#[cfg(test)]
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
    reconstruct_blobs_with_stats(
        tree,
        workspace,
        max_blob_bytes,
        workers,
        fetch_blob,
        None,
        None,
    )
    .await
    .failed
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ReconstructionSummary {
    failed: usize,
    resource_skipped: usize,
}

async fn reconstruct_blobs_with_stats<E, F, Fut>(
    tree: Vec<E>,
    workspace: PathBuf,
    max_blob_bytes: usize,
    workers: usize,
    fetch_blob: F,
    outcome_stats: Option<Arc<Mutex<ScanOutcomeStats>>>,
    resource_budget: Option<Arc<ResourceBudget>>,
) -> ReconstructionSummary
where
    E: BlobEntry,
    F: Fn(E) -> Fut + Clone + Send + Sync,
    Fut: Future<Output = anyhow::Result<Vec<u8>>> + Send,
{
    let blobs: Vec<_> = tree.into_iter().filter(BlobEntry::is_blob).collect();

    let reconstruct_stream = futures::stream::iter(blobs).map(|entry| {
        let fetch_blob = fetch_blob.clone();
        let workspace = workspace.clone();
        let outcome_stats = outcome_stats.clone();
        let resource_budget = resource_budget.clone();
        async move {
            if entry
                .size()
                .is_some_and(|size| size > max_blob_bytes as u64)
            {
                if let Some(stats) = outcome_stats.as_ref() {
                    stats.lock().await.skipped_oversized += 1;
                }
                return ReconstructionOutcome::Failed;
            }

            // Hold the reservation for the fetched bytes until the workspace
            // write completes. The declared size is an admission upper bound;
            // unknown-size entries use the configured per-blob ceiling.
            let reservation_bytes = entry
                .size()
                .map(|size| size.min(max_blob_bytes as u64) as usize)
                .unwrap_or(max_blob_bytes);
            let _workspace_reservation = resource_budget.as_ref().and_then(|budget| {
                budget.try_reserve(ResourceStage::WorkspaceReconstruction, reservation_bytes)
            });
            if resource_budget.is_some() && _workspace_reservation.is_none() {
                if let Some(stats) = outcome_stats.as_ref() {
                    stats.lock().await.skipped_resource_budget += 1;
                }
                return ReconstructionOutcome::ResourceSkipped;
            }

            let data = match fetch_blob(entry.clone()).await {
                Ok(data) if data.len() <= max_blob_bytes => data,
                Ok(_) => {
                    if let Some(stats) = outcome_stats.as_ref() {
                        stats.lock().await.skipped_oversized += 1;
                    }
                    return ReconstructionOutcome::Failed;
                }
                Err(_) => {
                    if let Some(stats) = outcome_stats.as_ref() {
                        stats.lock().await.failed_files += 1;
                    }
                    return ReconstructionOutcome::Failed;
                }
            };
            let relative_path = match crate::normalize_repo_relative_path(entry.path()) {
                Some(path) => path,
                None => {
                    if let Some(stats) = outcome_stats.as_ref() {
                        stats.lock().await.skipped_files += 1;
                    }
                    return ReconstructionOutcome::Failed;
                }
            };
            let local_path = workspace.join(relative_path);
            if !local_path.starts_with(&workspace) {
                if let Some(stats) = outcome_stats.as_ref() {
                    stats.lock().await.skipped_files += 1;
                }
                return ReconstructionOutcome::Failed;
            }
            if let Some(parent) = local_path.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    if let Some(stats) = outcome_stats.as_ref() {
                        stats.lock().await.failed_files += 1;
                    }
                    return ReconstructionOutcome::Failed;
                }
            }
            if std::fs::write(local_path, data).is_err() {
                if let Some(stats) = outcome_stats.as_ref() {
                    stats.lock().await.failed_files += 1;
                }
                return ReconstructionOutcome::Failed;
            }
            ReconstructionOutcome::Recovered
        }
    });
    let reconstruct_stream = reconstruct_stream.buffer_unordered(workers.max(1));

    futures::pin_mut!(reconstruct_stream);
    let mut summary = ReconstructionSummary::default();
    while let Some(outcome) = reconstruct_stream.next().await {
        match outcome {
            ReconstructionOutcome::Recovered => {}
            ReconstructionOutcome::Failed => summary.failed += 1,
            ReconstructionOutcome::ResourceSkipped => summary.resource_skipped += 1,
        }
    }
    summary
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
        object_source_stats: crate::streamer::ObjectSourceStats {
            forge: outcome.blobs_recovered,
            ..Default::default()
        },
        outcome_stats: crate::streamer::ScanOutcomeStats::default(),
        rate_limit_allowed: 0,
        rate_limit_dropped: 0,
        rate_limit_wait_ms: 0,
        retry_stats: None,
    }
}

/// Configuration and shared state for scanning reconstructed repository files.
#[derive(Clone)]
pub(crate) struct FileScanConfig {
    pub(crate) workspace: PathBuf,
    pub(crate) repository_name: String,
    pub(crate) scan_scope: crate::forge::ForgeScanScope,
    pub(crate) max_history: usize,
    pub(crate) max_blob_bytes: usize,
    pub(crate) workers: usize,
    pub(crate) scan_binaries: bool,
    pub(crate) exhaustive: bool,
    pub(crate) entropy_threshold: f64,
    pub(crate) false_positive_keywords: Vec<String>,
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
    pub(crate) outcome_stats: Arc<Mutex<ScanOutcomeStats>>,
    pub(crate) resource_budget: Arc<ResourceBudget>,
}

/// Scan all eligible files in a reconstructed repository workspace.
pub(crate) async fn scan_workspace_files(config: FileScanConfig) {
    let scanner = Arc::new(ContentScanner::new(
        config.extra_patterns.clone(),
        config.exhaustive,
        config.entropy_threshold,
        config.max_blob_bytes,
        config.scan_binaries,
    ));
    let all_files = crate::collect_local_files(&config.workspace);
    let oversized_files = all_files
        .iter()
        .filter(|(_, size)| *size > config.max_blob_bytes as u64)
        .count();
    if oversized_files > 0 {
        config.outcome_stats.lock().await.skipped_oversized += oversized_files;
    }
    let mut candidates: Vec<PathBuf> = all_files
        .into_iter()
        .filter(|(_, size)| *size <= config.max_blob_bytes as u64)
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
    let false_positive_keywords = config.false_positive_keywords.clone();
    let file_stream = futures::stream::iter(candidates)
        .map(|path| {
            let stop_flag = config.stop_flag.clone();
            let false_positive_keywords = false_positive_keywords.clone();
            let outcome_stats = config.outcome_stats.clone();
            let scanner = scanner.clone();
            let workspace = config.workspace.clone();
            let repository_name = config.repository_name.clone();
            async move {
                if stop_flag.load(Ordering::Relaxed) {
                    outcome_stats.lock().await.skipped_stop_requested += 1;
                    return (ContentScanOutcome::stopped(), Vec::new());
                }
                let data = match tokio::fs::read(&path).await {
                    Ok(data) => data,
                    Err(_) => {
                        outcome_stats.lock().await.failed_files += 1;
                        return (ContentScanOutcome::failed(), Vec::new());
                    }
                };
                if data.is_empty() {
                    outcome_stats.lock().await.skipped_files += 1;
                    return (ContentScanOutcome::empty(), Vec::new());
                }
                let relative_path = path
                    .strip_prefix(&workspace)
                    .map(|relative| relative.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"));
                let source = format!("{}/{}", repository_name, relative_path);
                let dispatch = binary_scanner::classify_binary(&data, &source, 8192, 10);
                let is_binary = dispatch.is_binary();
                let outcome = scanner.scan(&data, &source, is_binary, &false_positive_keywords);
                let mut technologies = Vec::new();
                if !is_binary {
                    crate::detect_tech_from_path(&relative_path, &mut technologies);
                }
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
        if outcome.archive_truncated > 0
            || outcome.archive_invalid > 0
            || !outcome.archive_issues.is_empty()
        {
            let mut stats = config.outcome_stats.lock().await;
            stats.archive_truncated += outcome.archive_truncated;
            stats.archive_invalid += outcome.archive_invalid;
            for (issue, count) in &outcome.archive_issues {
                *stats
                    .archive_invalid_reasons
                    .entry(issue.clone())
                    .or_default() += count;
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

async fn scan_history_repositories<F, Fut>(
    forge: Arc<dyn Forge>,
    selected_repos: &[Repository],
    config: &FileScanConfig,
    fetch_blob: F,
) where
    F: Fn(Arc<dyn Forge>, Repository, TreeEntry, String) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<Vec<u8>>> + Send,
{
    let scanner = ContentScanner::new(
        config.extra_patterns.clone(),
        config.exhaustive,
        config.entropy_threshold,
        config.max_blob_bytes,
        config.scan_binaries,
    );
    let mut seen_views = HashSet::new();

    for repo in selected_repos {
        if config.stop_flag.load(Ordering::Relaxed) {
            break;
        }
        let history = match forge
            .get_history(repo, &repo.default_branch, config.max_history)
            .await
        {
            Ok(history) => history,
            Err(error) => {
                let mut stats = config.outcome_stats.lock().await;
                if error
                    .to_string()
                    .to_ascii_lowercase()
                    .contains("unsupported capability")
                {
                    stats.unsupported_capability = Some("history".to_string());
                } else {
                    stats.failed_files += 1;
                }
                continue;
            }
        };
        {
            let mut stats = config.outcome_stats.lock().await;
            stats.history_commits_scanned += history.commits_scanned;
            stats.history_truncated |= history.truncated;
            stats.history_entries_considered += history.entries.len();
        }

        for entry in history.entries {
            if config.stop_flag.load(Ordering::Relaxed) {
                config.outcome_stats.lock().await.skipped_stop_requested += 1;
                break;
            }
            let is_deleted = entry.status == HistoryChangeStatus::Removed;
            if is_deleted {
                config.outcome_stats.lock().await.history_deleted_entries += 1;
            }
            let view_key = match entry.blob_sha.as_ref() {
                Some(blob_sha) => format!("{}:{}", entry.path, blob_sha),
                None if is_deleted => continue,
                // GitLab's diff API provides changed paths but not blob IDs. A
                // commit/path key preserves every revision view for those entries.
                None => format!("{}:commit:{}", entry.path, entry.commit_sha),
            };
            if !seen_views.insert(view_key) {
                config
                    .outcome_stats
                    .lock()
                    .await
                    .history_entries_deduplicated += 1;
                continue;
            }
            let tree_entry = TreeEntry {
                path: entry.path.clone(),
                obj_type: "blob".to_string(),
                // Path-based providers ignore this synthetic value in their
                // get_blob_entry_at override; SHA-addressable providers always
                // supply blob_sha above.
                sha: entry
                    .blob_sha
                    .clone()
                    .unwrap_or_else(|| format!("history:{}", entry.commit_sha)),
                size: entry.size,
                mode: None,
            };
            let data = match fetch_blob(
                forge.clone(),
                repo.clone(),
                tree_entry,
                entry.commit_sha.clone(),
            )
            .await
            {
                Ok(data) => data,
                Err(_) => {
                    config.outcome_stats.lock().await.failed_files += 1;
                    config.blobs_failed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            if data.is_empty() {
                config.outcome_stats.lock().await.skipped_files += 1;
                continue;
            }
            let source = format!(
                "{}/history/{}/{}",
                repo.full_name, entry.commit_sha, entry.path
            );
            let dispatch = binary_scanner::classify_binary(&data, &source, 8192, 10);
            let mut outcome = scanner.scan(
                &data,
                &source,
                dispatch.is_binary(),
                &config.false_positive_keywords,
            );
            for finding in &mut outcome.findings {
                finding.commit_sha1 = Some(entry.commit_sha.clone());
                finding.is_deleted = is_deleted;
            }
            {
                let mut stats = config.outcome_stats.lock().await;
                stats.history_entries_scanned += 1;
                stats.archive_truncated += outcome.archive_truncated;
                stats.archive_invalid += outcome.archive_invalid;
                for (issue, count) in &outcome.archive_issues {
                    *stats
                        .archive_invalid_reasons
                        .entry(issue.clone())
                        .or_default() += count;
                }
            }
            if outcome.bytes > 0 {
                config.blobs_scanned.fetch_add(1, Ordering::Relaxed);
                config
                    .bytes_scanned
                    .fetch_add(outcome.bytes, Ordering::Relaxed);
            }
            if !outcome.findings.is_empty() {
                config.all_findings.lock().await.extend(outcome.findings);
            }
            if config.max_findings > 0
                && config.all_findings.lock().await.len() >= config.max_findings
            {
                config.stop_flag.store(true, Ordering::Relaxed);
                break;
            }
        }
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
    let capabilities = forge.capabilities();
    {
        let mut stats = scan_config.outcome_stats.lock().await;
        stats.scan_scope = Some(scan_config.scan_scope.as_str().to_string());
        stats.capabilities = Some(capabilities.clone());
    }
    if scan_config.scan_scope == crate::forge::ForgeScanScope::History && !capabilities.history {
        scan_config
            .outcome_stats
            .lock()
            .await
            .unsupported_capability = Some("history".to_string());
    } else if scan_config.scan_scope == ForgeScanScope::History {
        scan_history_repositories(
            forge.clone(),
            selected_repos,
            &scan_config,
            fetch_blob.clone(),
        )
        .await;
    } else {
        for (repo_idx, repo) in selected_repos.iter().enumerate() {
            if scan_config.stop_flag.load(Ordering::Relaxed) {
                break;
            }
            let scan_request =
                RepositoryScanRequest::new(repo.clone(), repo_idx, selected_repos.len());
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
            let failed = reconstruct_blobs_with_stats(
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
                Some(scan_config.outcome_stats.clone()),
                Some(scan_config.resource_budget.clone()),
            )
            .await;
            scan_config
                .blobs_failed
                .fetch_add(failed.failed, Ordering::Relaxed);
            scan_workspace_files(FileScanConfig {
                workspace: repo_workspace,
                repository_name: repo.full_name.clone(),
                ..scan_config.clone()
            })
            .await;
        }
    }
    let mut result = build_stream_result(
        started_at,
        scan_config.all_findings.clone(),
        scan_config.tech_stack_set.clone(),
        scan_config.blobs_scanned.clone(),
        scan_config.blobs_failed.clone(),
        scan_config.bytes_scanned.clone(),
    )
    .await;
    result.outcome_stats = scan_config.outcome_stats.lock().await.clone();
    let resource_stats = scan_config.resource_budget.stats();
    result.outcome_stats.resource_peak_bytes = resource_stats.peak_bytes;
    result.outcome_stats.resource_denied_reservations = resource_stats.denied_reservations;
    result.outcome_stats.resource_by_stage = resource_stats.by_stage;
    result.retry_stats = forge.retry_stats();
    result
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use super::{
        build_stream_result, establish_session, reconstruct_blobs, run_repository_scan_loop,
        scan_workspace_files, FileScanConfig, RepositoryScanOutcome, RepositoryScanRequest,
        WorkspaceLifecycle,
    };
    use crate::forge::{
        EnumScope, Forge, ForgeCapabilities, ForgeHistory, ForgeScanScope, HistoryChangeStatus,
        HistoryEntry, Platform, RateLimitInfo, Repository, TreeEntry,
    };
    use crate::streamer::{DynPattern, ScanOutcomeStats};
    use tokio::sync::Mutex;
    use zip::{write::SimpleFileOptions, ZipWriter};

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
    async fn reconstruct_blobs_reports_workspace_budget_denial() {
        let workspace =
            std::env::temp_dir().join(format!("gitrecon-forge-budget-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).expect("test workspace should be creatable");

        let tree = vec![TreeEntry {
            path: "config/settings.toml".to_string(),
            obj_type: "blob".to_string(),
            sha: "budget-sha".to_string(),
            size: Some(8),
            mode: None,
        }];
        let outcome_stats = Arc::new(Mutex::new(ScanOutcomeStats::default()));
        let budget = Arc::new(crate::resource_budget::ResourceBudget::new(4));
        let fetch_calls = Arc::new(AtomicUsize::new(0));
        let fetch_calls_for_worker = fetch_calls.clone();
        let summary = super::reconstruct_blobs_with_stats(
            tree,
            workspace.clone(),
            1024,
            1,
            move |_entry| {
                fetch_calls_for_worker.fetch_add(1, Ordering::Relaxed);
                async { Ok(b"should-not-fetch".to_vec()) }
            },
            Some(outcome_stats.clone()),
            Some(budget.clone()),
        )
        .await;

        assert_eq!(summary.failed, 0);
        assert_eq!(summary.resource_skipped, 1);
        assert_eq!(fetch_calls.load(Ordering::Relaxed), 0);
        assert_eq!(outcome_stats.lock().await.skipped_resource_budget, 1);
        assert_eq!(budget.stats().current_bytes, 0);
        assert_eq!(
            budget.stats().by_stage["workspace_reconstruction"].denied_reservations,
            1
        );
        assert!(!workspace.join("config/settings.toml").exists());
        fs::remove_dir_all(workspace).expect("test workspace should be removable");
    }

    #[tokio::test]
    async fn scan_workspace_files_scans_binary_files_and_collects_findings() {
        let workspace =
            std::env::temp_dir().join(format!("gitrecon-file-scan-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).expect("test workspace should be creatable");
        fs::write(workspace.join("config.txt"), b"CUSTOM_ABCD1234").unwrap();
        let mut archive_writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        archive_writer
            .start_file("nested/config.txt", SimpleFileOptions::default())
            .unwrap();
        archive_writer.write_all(b"CUSTOM_ABCD1234").unwrap();
        let archive = archive_writer.finish().unwrap().into_inner();
        let archive_bytes = archive.len();
        fs::write(workspace.join("fixture.zip"), archive).unwrap();
        fs::write(workspace.join("empty.txt"), b"").unwrap();
        fs::write(workspace.join("oversized.bin"), vec![b'x'; 1025]).unwrap();

        let all_findings = Arc::new(Mutex::new(Vec::new()));
        let tech_stack_set = Arc::new(Mutex::new(HashSet::new()));
        let blobs_scanned = Arc::new(AtomicUsize::new(0));
        let blobs_failed = Arc::new(AtomicUsize::new(0));
        let bytes_scanned = Arc::new(AtomicUsize::new(0));
        let outcome_stats = Arc::new(Mutex::new(ScanOutcomeStats::default()));
        scan_workspace_files(FileScanConfig {
            workspace: workspace.clone(),
            repository_name: "acme/example".to_string(),
            scan_scope: crate::forge::ForgeScanScope::Snapshot,
            max_history: 500,
            max_blob_bytes: 1024,
            workers: 2,
            scan_binaries: true,
            exhaustive: true,
            entropy_threshold: 4.5,
            false_positive_keywords: Vec::new(),
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
            outcome_stats: outcome_stats.clone(),
            resource_budget: Arc::new(crate::resource_budget::ResourceBudget::new(0)),
        })
        .await;

        let findings = all_findings.lock().await;
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|finding| finding.filename == "acme/example/config.txt"));
        let archive_finding = findings
            .iter()
            .find(|finding| finding.filename == "acme/example/fixture.zip")
            .expect("archive finding should be present");
        assert_eq!(archive_finding.pattern_id, "custom_token");
        assert_eq!(archive_finding.severity, "HIGH");
        assert_eq!(archive_finding.description, "Custom test token");
        assert!(archive_finding.context.contains("nested/config.txt"));
        assert_eq!(blobs_scanned.load(Ordering::Relaxed), 2);
        assert_eq!(blobs_failed.load(Ordering::Relaxed), 0);
        assert_eq!(bytes_scanned.load(Ordering::Relaxed), 15 + archive_bytes);
        let outcome_stats = outcome_stats.lock().await;
        assert_eq!(outcome_stats.skipped_files, 1);
        assert_eq!(outcome_stats.skipped_oversized, 1);
        assert_eq!(outcome_stats.failed_files, 0);
        drop(outcome_stats);
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
    struct ParityForge;
    struct HistoryForge;
    struct PathHistoryForge;

    #[async_trait::async_trait]
    impl Forge for PathHistoryForge {
        async fn authenticate(&mut self, _token: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn enumerate_repos(&self, _scope: EnumScope) -> anyhow::Result<Vec<Repository>> {
            Ok(vec![fixture_repository()])
        }

        async fn get_tree(
            &self,
            _repo: &Repository,
            _branch: &str,
        ) -> anyhow::Result<Vec<TreeEntry>> {
            Ok(Vec::new())
        }

        async fn get_blob(&self, _repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("path-based history mock must use revision fetch: {sha}")
        }

        async fn get_blob_entry_at(
            &self,
            _repo: &Repository,
            entry: &TreeEntry,
            revision: &str,
        ) -> anyhow::Result<Vec<u8>> {
            anyhow::ensure!(entry.path == "config.txt", "unexpected path");
            anyhow::ensure!(revision.starts_with("commit-"), "unexpected revision");
            Ok(b"CUSTOM_ABCD1234".to_vec())
        }

        async fn get_history(
            &self,
            _repo: &Repository,
            _branch: &str,
            max_commits: usize,
        ) -> anyhow::Result<ForgeHistory> {
            anyhow::ensure!(max_commits == 2, "unexpected history bound");
            Ok(ForgeHistory {
                commits_scanned: 2,
                entries: vec![
                    HistoryEntry {
                        commit_sha: "commit-one".to_string(),
                        path: "config.txt".to_string(),
                        status: HistoryChangeStatus::Modified,
                        blob_sha: None,
                        previous_path: None,
                        size: None,
                    },
                    HistoryEntry {
                        commit_sha: "commit-two".to_string(),
                        path: "config.txt".to_string(),
                        status: HistoryChangeStatus::Modified,
                        blob_sha: None,
                        previous_path: None,
                        size: None,
                    },
                ],
                truncated: false,
            })
        }

        fn capabilities(&self) -> ForgeCapabilities {
            ForgeCapabilities {
                snapshot: true,
                history: true,
                branches: false,
                tags: false,
                commits: true,
                deleted_blobs: false,
            }
        }

        fn rate_limit_remaining(&self) -> Option<(u32, std::time::Duration)> {
            Some((999, std::time::Duration::from_secs(30)))
        }

        fn platform(&self) -> Platform {
            Platform::GitLab
        }

        async fn get_head_sha(&self, _repo: &Repository, _branch: &str) -> anyhow::Result<String> {
            Ok("path-history-head".to_string())
        }

        async fn whoami(&self) -> anyhow::Result<(String, String)> {
            Ok((
                "path-history-user".to_string(),
                "Path History User".to_string(),
            ))
        }
    }

    #[async_trait::async_trait]
    impl Forge for HistoryForge {
        async fn authenticate(&mut self, _token: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn enumerate_repos(&self, _scope: EnumScope) -> anyhow::Result<Vec<Repository>> {
            Ok(vec![fixture_repository()])
        }

        async fn get_tree(
            &self,
            _repo: &Repository,
            _branch: &str,
        ) -> anyhow::Result<Vec<TreeEntry>> {
            Ok(Vec::new())
        }

        async fn get_blob(&self, _repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>> {
            match sha {
                "history-sha" | "deleted-sha" => Ok(b"CUSTOM_ABCD1234".to_vec()),
                _ => anyhow::bail!("unexpected history blob {sha}"),
            }
        }

        async fn get_history(
            &self,
            _repo: &Repository,
            _branch: &str,
            max_commits: usize,
        ) -> anyhow::Result<ForgeHistory> {
            assert_eq!(max_commits, 2);
            Ok(ForgeHistory {
                commits_scanned: 2,
                entries: vec![
                    HistoryEntry {
                        commit_sha: "commit-one".to_string(),
                        path: "config.txt".to_string(),
                        status: HistoryChangeStatus::Modified,
                        blob_sha: Some("history-sha".to_string()),
                        previous_path: None,
                        size: Some(15),
                    },
                    HistoryEntry {
                        commit_sha: "commit-two".to_string(),
                        path: "config.txt".to_string(),
                        status: HistoryChangeStatus::Modified,
                        blob_sha: Some("history-sha".to_string()),
                        previous_path: None,
                        size: Some(15),
                    },
                    HistoryEntry {
                        commit_sha: "commit-two".to_string(),
                        path: "old.txt".to_string(),
                        status: HistoryChangeStatus::Removed,
                        blob_sha: Some("deleted-sha".to_string()),
                        previous_path: None,
                        size: Some(15),
                    },
                ],
                truncated: true,
            })
        }

        fn capabilities(&self) -> ForgeCapabilities {
            ForgeCapabilities {
                snapshot: true,
                history: true,
                branches: false,
                tags: false,
                commits: true,
                deleted_blobs: true,
            }
        }

        fn rate_limit_remaining(&self) -> Option<(u32, std::time::Duration)> {
            Some((999, std::time::Duration::from_secs(30)))
        }

        fn platform(&self) -> Platform {
            Platform::GitHub
        }

        async fn get_head_sha(&self, _repo: &Repository, _branch: &str) -> anyhow::Result<String> {
            Ok("history-head".to_string())
        }

        async fn whoami(&self) -> anyhow::Result<(String, String)> {
            Ok(("history-user".to_string(), "History User".to_string()))
        }
    }

    #[async_trait::async_trait]
    impl Forge for ParityForge {
        async fn authenticate(&mut self, _token: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn enumerate_repos(&self, _scope: EnumScope) -> anyhow::Result<Vec<Repository>> {
            Ok(vec![fixture_repository()])
        }

        async fn get_tree(
            &self,
            _repo: &Repository,
            branch: &str,
        ) -> anyhow::Result<Vec<TreeEntry>> {
            anyhow::ensure!(branch == "main", "unexpected branch");
            Ok(vec![
                TreeEntry {
                    path: "config.txt".to_string(),
                    obj_type: "blob".to_string(),
                    sha: "text-sha".to_string(),
                    size: Some(15),
                    mode: Some("100644".to_string()),
                },
                TreeEntry {
                    path: "fixture.zip".to_string(),
                    obj_type: "blob".to_string(),
                    sha: "archive-sha".to_string(),
                    size: None,
                    mode: Some("100644".to_string()),
                },
            ])
        }

        async fn get_blob(&self, _repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("get_blob should not be called for path-aware mock entry {sha}")
        }

        async fn get_blob_entry(
            &self,
            _repo: &Repository,
            entry: &TreeEntry,
        ) -> anyhow::Result<Vec<u8>> {
            if entry.path == "config.txt" {
                return Ok(b"CUSTOM_ABCD1234".to_vec());
            }
            let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
            writer
                .start_file("nested/config.txt", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"CUSTOM_ABCD1234").unwrap();
            Ok(writer.finish().unwrap().into_inner())
        }

        fn rate_limit_remaining(&self) -> Option<(u32, std::time::Duration)> {
            Some((999, std::time::Duration::from_secs(30)))
        }

        fn platform(&self) -> Platform {
            Platform::Gitea
        }

        async fn get_head_sha(&self, _repo: &Repository, branch: &str) -> anyhow::Result<String> {
            anyhow::ensure!(branch == "main", "unexpected branch");
            Ok("abcdef0123456789abcdef0123456789abcdef01".to_string())
        }

        async fn whoami(&self) -> anyhow::Result<(String, String)> {
            Ok(("fixture-user".to_string(), "Fixture User".to_string()))
        }
    }

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
    async fn provider_mock_repository_loop_scans_text_and_archive_parity() {
        let output = tempfile::tempdir().expect("create output directory");
        let workspace = WorkspaceLifecycle::new(
            output.path(),
            "provider-mock",
            true,
            "gitrecon_provider_mock_scan",
        );
        let all_findings = Arc::new(Mutex::new(Vec::new()));
        let tech_stack_set = Arc::new(Mutex::new(HashSet::new()));
        let blobs_scanned = Arc::new(AtomicUsize::new(0));
        let blobs_failed = Arc::new(AtomicUsize::new(0));
        let bytes_scanned = Arc::new(AtomicUsize::new(0));
        let outcome_stats = Arc::new(Mutex::new(ScanOutcomeStats::default()));
        let result = run_repository_scan_loop(
            Arc::new(ParityForge),
            &[fixture_repository()],
            &workspace,
            FileScanConfig {
                workspace: PathBuf::new(),
                repository_name: String::new(),
                scan_scope: crate::forge::ForgeScanScope::Snapshot,
                max_history: 500,
                max_blob_bytes: 1024 * 1024,
                workers: 2,
                scan_binaries: true,
                exhaustive: true,
                entropy_threshold: 4.5,
                false_positive_keywords: Vec::new(),
                live: false,
                pipe: false,
                verbose: false,
                max_findings: 0,
                stop_on_critical: false,
                extra_patterns: Arc::new(vec![DynPattern {
                    id: "custom_token".to_string(),
                    sev: "CRITICAL".to_string(),
                    desc: "Custom provider token".to_string(),
                    regex: regex::Regex::new(r"CUSTOM_[A-Z0-9]{8}").unwrap(),
                }]),
                stop_flag: Arc::new(AtomicBool::new(false)),
                all_findings: all_findings.clone(),
                tech_stack_set,
                blobs_scanned,
                blobs_failed,
                bytes_scanned,
                outcome_stats,
                resource_budget: Arc::new(crate::resource_budget::ResourceBudget::new(1024 * 1024)),
            },
            |forge, repo, entry, _head_sha| async move {
                forge.get_blob_entry(&repo, &entry).await
            },
            Instant::now(),
        )
        .await;

        assert_eq!(result.findings.len(), 2);
        assert!(result
            .findings
            .iter()
            .all(|finding| finding.pattern_id == "custom_token"));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.context.contains("nested/config.txt")));
        assert_eq!(result.object_source_stats.forge, 2);
        assert_eq!(result.outcome_stats.failed_files, 0);
        assert_eq!(result.outcome_stats.skipped_files, 0);
        assert_eq!(result.outcome_stats.scan_scope.as_deref(), Some("snapshot"));
        let capabilities = result.outcome_stats.capabilities.as_ref().unwrap();
        assert!(capabilities.snapshot);
        assert!(!capabilities.history);
        assert_eq!(result.outcome_stats.unsupported_capability, None);
        assert!(result.outcome_stats.resource_by_stage["workspace_reconstruction"].peak_bytes > 0);
        assert_eq!(
            result.outcome_stats.resource_by_stage["workspace_reconstruction"].current_bytes,
            0
        );
    }

    #[tokio::test]
    async fn history_scope_scans_deduplicated_and_deleted_entries() {
        let output = tempfile::tempdir().expect("create output directory");
        let workspace = WorkspaceLifecycle::new(
            output.path(),
            "history-mock",
            false,
            "gitrecon_history_mock_scan",
        );
        let all_findings = Arc::new(Mutex::new(Vec::new()));
        let outcome_stats = Arc::new(Mutex::new(ScanOutcomeStats::default()));
        let result = run_repository_scan_loop(
            Arc::new(HistoryForge),
            &[fixture_repository()],
            &workspace,
            FileScanConfig {
                workspace: PathBuf::new(),
                repository_name: String::new(),
                scan_scope: ForgeScanScope::History,
                max_history: 2,
                max_blob_bytes: 1024,
                workers: 1,
                scan_binaries: true,
                exhaustive: true,
                entropy_threshold: 4.5,
                false_positive_keywords: Vec::new(),
                live: false,
                pipe: false,
                verbose: false,
                max_findings: 0,
                stop_on_critical: false,
                extra_patterns: Arc::new(vec![DynPattern {
                    id: "custom_token".to_string(),
                    sev: "CRITICAL".to_string(),
                    desc: "Custom history token".to_string(),
                    regex: regex::Regex::new(r"CUSTOM_[A-Z0-9]{8}").unwrap(),
                }]),
                stop_flag: Arc::new(AtomicBool::new(false)),
                all_findings: all_findings.clone(),
                tech_stack_set: Arc::new(Mutex::new(HashSet::new())),
                blobs_scanned: Arc::new(AtomicUsize::new(0)),
                blobs_failed: Arc::new(AtomicUsize::new(0)),
                bytes_scanned: Arc::new(AtomicUsize::new(0)),
                outcome_stats,
                resource_budget: Arc::new(crate::resource_budget::ResourceBudget::new(0)),
            },
            |forge, repo, entry, _head_sha| async move {
                forge.get_blob_entry(&repo, &entry).await
            },
            Instant::now(),
        )
        .await;

        assert_eq!(result.findings.len(), 2);
        assert!(result.findings.iter().any(|finding| finding.is_deleted));
        assert!(result
            .findings
            .iter()
            .all(|finding| finding.pattern_id == "custom_token"));
        assert!(result
            .findings
            .iter()
            .all(|finding| finding.commit_sha1.is_some()));
        assert_eq!(result.object_source_stats.forge, 2);
        assert_eq!(result.bytes_scanned, 30);
        assert_eq!(result.outcome_stats.scan_scope.as_deref(), Some("history"));
        assert_eq!(result.outcome_stats.history_commits_scanned, 2);
        assert_eq!(result.outcome_stats.history_entries_considered, 3);
        assert_eq!(result.outcome_stats.history_entries_scanned, 2);
        assert_eq!(result.outcome_stats.history_entries_deduplicated, 1);
        assert_eq!(result.outcome_stats.history_deleted_entries, 1);
        assert!(result.outcome_stats.history_truncated);
        assert_eq!(result.outcome_stats.unsupported_capability, None);
    }

    #[tokio::test]
    async fn history_scope_scans_path_only_provider_entries_at_each_revision() {
        let output = tempfile::tempdir().expect("create output directory");
        let workspace = WorkspaceLifecycle::new(
            output.path(),
            "path-history-mock",
            false,
            "gitrecon_path_history_mock_scan",
        );
        let all_findings = Arc::new(Mutex::new(Vec::new()));
        let outcome_stats = Arc::new(Mutex::new(ScanOutcomeStats::default()));
        let result = run_repository_scan_loop(
            Arc::new(PathHistoryForge),
            &[fixture_repository()],
            &workspace,
            FileScanConfig {
                workspace: PathBuf::new(),
                repository_name: String::new(),
                scan_scope: ForgeScanScope::History,
                max_history: 2,
                max_blob_bytes: 1024,
                workers: 1,
                scan_binaries: true,
                exhaustive: true,
                entropy_threshold: 4.5,
                false_positive_keywords: Vec::new(),
                live: false,
                pipe: false,
                verbose: false,
                max_findings: 0,
                stop_on_critical: false,
                extra_patterns: Arc::new(vec![DynPattern {
                    id: "custom_path_history".to_string(),
                    sev: "CRITICAL".to_string(),
                    desc: "Custom path history token".to_string(),
                    regex: regex::Regex::new(r"CUSTOM_[A-Z0-9]{8}").unwrap(),
                }]),
                stop_flag: Arc::new(AtomicBool::new(false)),
                all_findings: all_findings.clone(),
                tech_stack_set: Arc::new(Mutex::new(HashSet::new())),
                blobs_scanned: Arc::new(AtomicUsize::new(0)),
                blobs_failed: Arc::new(AtomicUsize::new(0)),
                bytes_scanned: Arc::new(AtomicUsize::new(0)),
                outcome_stats,
                resource_budget: Arc::new(crate::resource_budget::ResourceBudget::new(0)),
            },
            |forge, repo, entry, revision| async move {
                forge.get_blob_entry_at(&repo, &entry, &revision).await
            },
            Instant::now(),
        )
        .await;

        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.blobs_scanned, 2);
        assert_eq!(result.blobs_failed, 0);
        assert!(result
            .findings
            .iter()
            .all(|finding| finding.pattern_id == "custom_path_history"));
        assert!(result
            .findings
            .iter()
            .all(|finding| finding.commit_sha1.is_some()));
        assert_eq!(result.outcome_stats.history_entries_scanned, 2);
        assert_eq!(result.outcome_stats.history_entries_deduplicated, 0);
        assert_eq!(result.outcome_stats.unsupported_capability, None);
    }

    #[tokio::test]
    async fn run_repository_scan_loop_reports_unsupported_history_scope() {
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
                scan_scope: crate::forge::ForgeScanScope::History,
                max_history: 1,
                max_blob_bytes: 1024,
                workers: 1,
                scan_binaries: true,
                exhaustive: true,
                entropy_threshold: 4.5,
                false_positive_keywords: Vec::new(),
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
                outcome_stats: Arc::new(Mutex::new(ScanOutcomeStats::default())),
                resource_budget: Arc::new(crate::resource_budget::ResourceBudget::new(0)),
            },
            |_forge, _repo, _entry, _head_sha| async { Ok(Vec::new()) },
            Instant::now(),
        )
        .await;
        assert!(result.findings.is_empty());
        assert_eq!(result.blobs_scanned, 0);
        assert_eq!(result.blobs_failed, 0);
        assert_eq!(result.bytes_scanned, 0);
        assert_eq!(result.outcome_stats.scan_scope.as_deref(), Some("history"));
        assert_eq!(
            result.outcome_stats.unsupported_capability.as_deref(),
            Some("history")
        );
        assert!(!result.outcome_stats.capabilities.as_ref().unwrap().history);
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

#[cfg(test)]
mod keyword_policy_tests {
    use super::{scan_workspace_files, FileScanConfig};
    use crate::streamer::ScanOutcomeStats;
    use std::collections::HashSet;
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn forge_workspace_scan_forwards_custom_false_positive_keywords() {
        let workspace = std::env::temp_dir().join(format!(
            "gitrecon-forge-keyword-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&workspace);
        fs::create_dir_all(&workspace).expect("test workspace should be creatable");
        fs::write(
            workspace.join("config.env"),
            b"api_key = \"synthetic_value_123456\" # internal-fixture",
        )
        .expect("test fixture should be writable");

        let all_findings = Arc::new(Mutex::new(Vec::new()));
        scan_workspace_files(FileScanConfig {
            workspace: workspace.clone(),
            repository_name: "acme/example".to_string(),
            scan_scope: crate::forge::ForgeScanScope::Snapshot,
            max_history: 500,
            max_blob_bytes: 1024,
            workers: 1,
            scan_binaries: true,
            exhaustive: false,
            entropy_threshold: 4.5,
            false_positive_keywords: vec!["internal-fixture".to_string()],
            live: false,
            pipe: false,
            verbose: false,
            max_findings: 0,
            stop_on_critical: false,
            extra_patterns: Arc::new(Vec::new()),
            stop_flag: Arc::new(AtomicBool::new(false)),
            all_findings: all_findings.clone(),
            tech_stack_set: Arc::new(Mutex::new(HashSet::new())),
            blobs_scanned: Arc::new(AtomicUsize::new(0)),
            blobs_failed: Arc::new(AtomicUsize::new(0)),
            bytes_scanned: Arc::new(AtomicUsize::new(0)),
            outcome_stats: Arc::new(Mutex::new(ScanOutcomeStats::default())),
            resource_budget: Arc::new(crate::resource_budget::ResourceBudget::new(0)),
        })
        .await;

        let findings = all_findings.lock().await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id, "api_key");
        assert_eq!(findings[0].severity, "MEDIUM");
        assert!(findings[0].confidence_adjustment.is_some());
        drop(findings);
        fs::remove_dir_all(workspace).expect("test workspace should be removable");
    }
}

//! Provider-neutral repository scan boundaries.
//!
//! Forge adapters remain responsible for fetching provider-specific data. These
//! types describe the common execution contract consumed by the scanner loop.

use std::future::Future;
use std::path::PathBuf;

use crate::forge::Repository;

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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{reconstruct_blobs, RepositoryScanOutcome, RepositoryScanRequest};
    use crate::forge::{Platform, Repository, TreeEntry};

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

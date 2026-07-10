//! reconstructor.rs
//! Optional: reconstruct source code to disk when --save is active.
//! Only runs after streaming completes.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::http_client::HttpClient;
use crate::git_parser::{ObjectParser, obj_path};

pub struct Reconstructor {
    client:  HttpClient,
    workers: usize,
}

impl Reconstructor {
    pub fn new(client: HttpClient, workers: usize) -> Self {
        Self { client, workers }
    }

    /// Download and write blobs to disk.
    /// sha1_to_file: sha1 → filename (from index entries).
    pub async fn run(
        &self,
        git_url: &str,
        sha1_to_file: &std::collections::HashMap<String, String>,
        output_dir: &Path,
        progress_cb: Option<Arc<dyn Fn(usize, usize) + Send + Sync>>,
    ) -> std::collections::HashMap<&'static str, usize> {
        let git_url = git_url.trim_end_matches('/').to_string();
        if let Err(e) = std::fs::create_dir_all(output_dir) {
            log::error!("Failed to create output directory {:?}: {}", output_dir, e);
            return std::collections::HashMap::new();
        }

        let total = sha1_to_file.len();
        let semaphore = Arc::new(Semaphore::new(self.workers));
        let done_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let saved = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let failed = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();

        for (sha1, filename) in sha1_to_file {
            // BUG-ERR-014: Handle semaphore closure gracefully
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    log::debug!("Semaphore closed, skipping blob {}", sha1);
                    continue;
                }
            };
            let client = self.client.clone();
            let git_url = git_url.clone();
            let sha1 = sha1.clone();
            let filename = filename.clone();
            let output_dir = output_dir.to_path_buf();
            let done_counter = done_counter.clone();
            let saved = saved.clone();
            let failed = failed.clone();
            let progress_cb = progress_cb.clone();

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                let ok = save_blob(&client, &git_url, &sha1, &filename, &output_dir).await;
                if ok {
                    saved.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                } else {
                    failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let done = done_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if let Some(ref cb) = progress_cb {
                    cb(done, total);
                }
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let mut result = std::collections::HashMap::new();
        result.insert("saved",  saved.load(std::sync::atomic::Ordering::Relaxed));
        result.insert("failed", failed.load(std::sync::atomic::Ordering::Relaxed));
        result
    }
}

async fn save_blob(
    client: &HttpClient,
    git_url: &str,
    sha1: &str,
    filename: &str,
    output_dir: &Path,
) -> bool {
    let url  = format!("{}/{}", git_url, obj_path(sha1));
    let resp = client.get(&url).await;
    if !resp.ok() {
        return false;
    }

    let parser = ObjectParser;
    let obj = match parser.parse(&resp.body, sha1) {
        Some(o) if o.obj_type == "blob" => o,
        _ => return false,
    };

    // Sanitize path: no ".." or absolute paths
    let parts_owned: Vec<String> = filename
        .replace('\\', "/")
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".." && *p != ".")
        .map(|s| s.to_string())
        .collect();

    if parts_owned.is_empty() {
        return false;
    }

    let local_path: PathBuf = parts_owned.iter().fold(output_dir.to_path_buf(), |acc, p| acc.join(p));

    // Defense in depth: verify the joined path is still rooted inside output_dir
    if !local_path.starts_with(output_dir) {
        return false;
    }

    if let Some(parent) = local_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            log::error!("Failed to create parent directory {:?} for {}: {}", parent, sha1, e);
            return false;
        }
    }

    std::fs::write(&local_path, &obj.data).is_ok()
}

//! Object acquisition worker boundary.
//!
//! This module owns the asynchronous fetch, cancellation re-check, and
//! acquisition-outcome mapping. Content processing remains in `streamer` until
//! its detector dependencies are extracted in a later increment.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::http_client::HttpClient;
use crate::object_source::{AcquisitionOutcome, ObjectSource, ObjectSourceConfig};
use crate::resource_budget::ResourceBudget;
use crate::streamer::{
    attach_source, process_blob_content, DynPattern, FailureKind, SkipReason, WorkerResult,
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_process(
    client: &HttpClient,
    git_url: &str,
    sha1: &str,
    sha1_to_file: &HashMap<String, String>,
    sha1_extras: &HashMap<String, Vec<String>>,
    current_blobs: &HashSet<String>,
    pack_objects: &HashMap<String, Vec<u8>>,
    save_dir: Option<Arc<PathBuf>>,
    extra_patterns: Arc<Vec<DynPattern>>,
    stop_flag: Arc<AtomicBool>,
    mem_limit: usize,
    resource_budget: Arc<ResourceBudget>,
    max_scan_bytes: usize,
    entropy_threshold: f64,
    verbose: bool,
    cache: Option<Arc<crate::cache::ObjectCache>>,
    cache_hits: Arc<AtomicUsize>,
    cache_misses: Arc<AtomicUsize>,
    false_positive_keywords: Arc<Vec<String>>,
    exhaustive: bool,
) -> WorkerResult {
    if stop_flag.load(Ordering::Relaxed) {
        return WorkerResult::Skipped {
            reason: SkipReason::StopRequested,
        };
    }

    let source = ObjectSource::new(ObjectSourceConfig {
        client,
        git_url,
        pack_objects,
        cache: cache.as_deref(),
        max_blob_size: max_scan_bytes,
        save_enabled: save_dir.is_some(),
        cache_hits: &cache_hits,
        cache_misses: &cache_misses,
        resource_budget: Arc::clone(&resource_budget),
    });
    let envelope = match source.acquire(sha1).await {
        Ok(envelope) => envelope,
        Err(AcquisitionOutcome::NotFound) => {
            return WorkerResult::Skipped {
                reason: SkipReason::NotFound,
            };
        }
        Err(AcquisitionOutcome::Oversized) => {
            if verbose {
                eprintln!(
                    "  [!] Blob {} exceeds --max-blob-size limit, skipping",
                    &sha1[..sha1.len().min(8)]
                );
            }
            return WorkerResult::Skipped {
                reason: SkipReason::Oversized,
            };
        }
        Err(AcquisitionOutcome::HttpStatus(status)) => {
            return WorkerResult::BlobFailed {
                kind: FailureKind::HttpStatus(status),
            };
        }
        Err(AcquisitionOutcome::ResourceBudget) => {
            return WorkerResult::Skipped {
                reason: SkipReason::ResourceBudget,
            };
        }
    };

    // Re-check cancellation after acquisition: an in-flight request may have
    // completed after another worker triggered --max-findings or --stop-on-critical.
    if stop_flag.load(Ordering::Relaxed) {
        return WorkerResult::Skipped {
            reason: SkipReason::StopRequested,
        };
    }

    if save_dir.is_some() && verbose && envelope.bytes.len() > max_scan_bytes {
        eprintln!(
            "  [!] Blob {} ({} bytes) exceeds --max-blob-size but --save is on: saving without scan",
            &sha1[..sha1.len().min(8)],
            envelope.bytes.len()
        );
    }

    attach_source(
        process_blob_content(
            &envelope.bytes,
            sha1,
            sha1_to_file,
            sha1_extras,
            current_blobs,
            save_dir,
            extra_patterns,
            mem_limit,
            resource_budget,
            max_scan_bytes,
            entropy_threshold,
            verbose,
            false_positive_keywords,
            exhaustive,
        ),
        envelope.source,
    )
}

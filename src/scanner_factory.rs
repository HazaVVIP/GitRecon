//! Streamer construction boundary.
//!
//! Keeps runtime configuration mapping in one place so orchestration paths do not
//! duplicate the scanner constructor's resource, policy, cache, and checkpoint wiring.

use std::sync::Arc;

use crate::config::ScanConfig;
use crate::http_client::HttpClient;
use crate::streamer::{DynPattern, Streamer};

pub(crate) fn build_streamer(
    client: HttpClient,
    config: &ScanConfig,
    verbose: bool,
    extra_patterns: Vec<DynPattern>,
    target_url: Option<String>,
    cache: Option<Arc<crate::cache::ObjectCache>>,
    false_positive_keywords: Vec<String>,
) -> Streamer {
    Streamer::new(
        client,
        config.workers,
        config.mem_limit,
        verbose,
        config.max_findings,
        config.stop_on_critical,
        extra_patterns,
        config.max_blob_size,
        config.entropy_threshold,
        config.live,
        config.adaptive_workers,
        config.resume,
        config.checkpoint_interval,
        target_url,
        cache,
        false_positive_keywords,
        config.exhaustive,
    )
}

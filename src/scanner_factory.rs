//! Streamer construction boundary.
//!
//! Keeps runtime configuration mapping in one place so orchestration paths do not
//! duplicate the scanner constructor's resource, policy, cache, and checkpoint wiring.

use std::sync::Arc;

use crate::config::ScanConfig;
use crate::http_client::HttpClient;
use crate::streamer::{DynPattern, Streamer};
use crate::streamer_config::StreamerConfig;

pub(crate) fn build_streamer(
    client: HttpClient,
    config: &ScanConfig,
    verbose: bool,
    extra_patterns: Vec<DynPattern>,
    target_url: Option<String>,
    cache: Option<Arc<crate::cache::ObjectCache>>,
    false_positive_keywords: Vec<String>,
) -> Streamer {
    Streamer::new(StreamerConfig::from_scan_config(
        client,
        config,
        verbose,
        extra_patterns,
        target_url,
        cache,
        false_positive_keywords,
    ))
}

//! Typed construction boundary for the stream worker.

use std::sync::Arc;

use crate::checkpoint::ScanConfigSnapshot;
use crate::http_client::HttpClient;
use crate::streamer::DynPattern;

pub(crate) struct StreamerConfig {
    pub(crate) client: HttpClient,
    pub(crate) workers: usize,
    pub(crate) mem_limit_mb: usize,
    pub(crate) verbose: bool,
    pub(crate) max_findings: usize,
    pub(crate) stop_on_critical: bool,
    pub(crate) extra_patterns: Vec<DynPattern>,
    pub(crate) max_blob_size: usize,
    pub(crate) entropy_threshold: f64,
    pub(crate) live: bool,
    pub(crate) adaptive: bool,
    pub(crate) resume_from_checkpoint: bool,
    pub(crate) checkpoint_interval: usize,
    pub(crate) target_url: Option<String>,
    pub(crate) cache: Option<Arc<crate::cache::ObjectCache>>,
    pub(crate) false_positive_keywords: Vec<String>,
    pub(crate) exhaustive: bool,
    pub(crate) config_snapshot: ScanConfigSnapshot,
}

impl StreamerConfig {
    pub(crate) fn from_scan_config(
        client: HttpClient,
        config: &crate::config::ScanConfig,
        verbose: bool,
        extra_patterns: Vec<DynPattern>,
        target_url: Option<String>,
        cache: Option<Arc<crate::cache::ObjectCache>>,
        false_positive_keywords: Vec<String>,
    ) -> Self {
        Self {
            client,
            workers: config.workers,
            mem_limit_mb: config.mem_limit,
            verbose,
            max_findings: config.max_findings,
            stop_on_critical: config.stop_on_critical,
            extra_patterns,
            max_blob_size: config.max_blob_size,
            entropy_threshold: config.entropy_threshold,
            live: config.live,
            adaptive: config.adaptive_workers,
            resume_from_checkpoint: config.resume,
            checkpoint_interval: config.checkpoint_interval,
            target_url,
            cache,
            false_positive_keywords,
            exhaustive: config.exhaustive,
            config_snapshot: ScanConfigSnapshot::from_config(config),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StreamerConfig;
    use crate::config::ScanConfig;
    use crate::http_client::{HttpClient, HttpConfig};

    #[test]
    fn maps_scan_config_without_dropping_runtime_policy() {
        let scan_config = ScanConfig::from_values(
            8, 256, 100, true, 4, 500, 4.5, true, false, true, 1000, true, true, true, true, 604800,
        );
        let streamer_config = StreamerConfig::from_scan_config(
            HttpClient::new(HttpConfig::default()).unwrap(),
            &scan_config,
            true,
            vec![],
            Some("https://fixture.invalid/repository".to_string()),
            None,
            vec!["fixture".to_string()],
        );

        assert_eq!(streamer_config.workers, 8);
        assert_eq!(streamer_config.mem_limit_mb, 256);
        assert_eq!(streamer_config.max_blob_size, 4);
        assert!(streamer_config.stop_on_critical);
        assert!(streamer_config.exhaustive);
        assert!(!streamer_config.adaptive);
        assert!(streamer_config.resume_from_checkpoint);
        assert_eq!(streamer_config.checkpoint_interval, 1000);
        assert_eq!(
            streamer_config.target_url.as_deref(),
            Some("https://fixture.invalid/repository")
        );
        assert_eq!(streamer_config.false_positive_keywords, vec!["fixture"]);
    }
}

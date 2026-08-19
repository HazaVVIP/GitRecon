//! Runtime scan configuration shared across orchestration and scanner boundaries.

/// Validated, immutable settings that affect scanner behavior and resource usage.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScanConfig {
    pub(crate) workers: usize,
    pub(crate) mem_limit: usize,
    pub(crate) max_findings: usize,
    pub(crate) stop_on_critical: bool,
    pub(crate) max_blob_size: usize,
    pub(crate) max_history: usize,
    pub(crate) entropy_threshold: f64,
    pub(crate) live: bool,
    pub(crate) adaptive_workers: bool,
    pub(crate) resume: bool,
    pub(crate) checkpoint_interval: usize,
    pub(crate) exhaustive: bool,
    pub(crate) scan_binaries: bool,
    pub(crate) verify_objects: bool,
    pub(crate) cache_enabled: bool,
    pub(crate) cache_ttl: u64,
}

impl ScanConfig {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_values(
        workers: usize,
        mem_limit: usize,
        max_findings: usize,
        stop_on_critical: bool,
        max_blob_size: usize,
        max_history: usize,
        entropy_threshold: f64,
        live: bool,
        adaptive_workers: bool,
        resume: bool,
        checkpoint_interval: usize,
        exhaustive: bool,
        scan_binaries: bool,
        verify_objects: bool,
        cache_enabled: bool,
        cache_ttl: u64,
    ) -> Self {
        Self {
            workers,
            mem_limit,
            max_findings,
            stop_on_critical,
            max_blob_size,
            max_history,
            entropy_threshold,
            live,
            adaptive_workers,
            resume,
            checkpoint_interval,
            exhaustive,
            scan_binaries,
            verify_objects,
            cache_enabled,
            cache_ttl,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ScanConfig;

    #[test]
    fn preserves_runtime_values_without_normalizing_policy() {
        let config = ScanConfig::from_values(
            8, 256, 100, true, 4, 500, 4.5, true, false, true, 1000, true, true, true, true, 604800,
        );
        assert_eq!(config.workers, 8);
        assert!(config.exhaustive);
        assert!(config.verify_objects);
        assert_eq!(config.cache_ttl, 604800);
    }
}

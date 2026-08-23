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

/// Named input boundary for constructing validated ScanConfig values.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ScanConfigInput {
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

impl ScanConfigInput {
    pub(crate) fn build(self) -> Result<ScanConfig, String> {
        if self.workers == 0 || self.workers > 1000 {
            return Err(format!(
                "--workers must be in [1, 1000], got {}",
                self.workers
            ));
        }
        if self.max_blob_size == 0 || self.max_blob_size > 10_240 {
            return Err(format!(
                "--max-blob-size must be in [1, 10240] MB, got {}",
                self.max_blob_size
            ));
        }
        if self.max_history > 1_000_000 {
            return Err(format!(
                "--max-history must be in [0, 1_000_000], got {}",
                self.max_history
            ));
        }
        if self.checkpoint_interval == 0 || self.checkpoint_interval > 1_000_000 {
            return Err(format!(
                "--checkpoint-interval must be in [1, 1_000_000], got {}",
                self.checkpoint_interval
            ));
        }
        if !self.entropy_threshold.is_finite() || self.entropy_threshold < 0.0 {
            return Err(format!(
                "--entropy-threshold must be finite and non-negative, got {}",
                self.entropy_threshold
            ));
        }

        Ok(ScanConfig {
            workers: self.workers,
            mem_limit: self.mem_limit,
            max_findings: self.max_findings,
            stop_on_critical: self.stop_on_critical,
            max_blob_size: self.max_blob_size,
            max_history: self.max_history,
            entropy_threshold: self.entropy_threshold,
            live: self.live,
            adaptive_workers: self.adaptive_workers,
            resume: self.resume,
            checkpoint_interval: self.checkpoint_interval,
            exhaustive: self.exhaustive,
            scan_binaries: self.scan_binaries,
            verify_objects: self.verify_objects,
            cache_enabled: self.cache_enabled,
            cache_ttl: self.cache_ttl,
        })
    }
}

impl ScanConfig {
    /// Compatibility constructor for existing internal tests.
    #[cfg(test)]
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
        ScanConfigInput {
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
        .build()
        .expect("ScanConfig::from_values received invalid runtime configuration")
    }
}

#[cfg(test)]
mod tests {
    use super::{ScanConfig, ScanConfigInput};

    fn valid_input() -> ScanConfigInput {
        ScanConfigInput {
            workers: 8,
            mem_limit: 256,
            max_findings: 100,
            stop_on_critical: true,
            max_blob_size: 4,
            max_history: 500,
            entropy_threshold: 4.5,
            live: true,
            adaptive_workers: false,
            resume: true,
            checkpoint_interval: 1000,
            exhaustive: true,
            scan_binaries: true,
            verify_objects: true,
            cache_enabled: true,
            cache_ttl: 604800,
        }
    }

    #[test]
    fn preserves_runtime_values_without_normalizing_policy() {
        let config = valid_input().build().unwrap();
        assert_eq!(config.workers, 8);
        assert!(config.exhaustive);
        assert!(config.verify_objects);
        assert_eq!(config.cache_ttl, 604800);
    }

    #[test]
    fn rejects_invalid_resource_and_policy_invariants() {
        let mut input = valid_input();
        input.workers = 0;
        assert!(input.build().is_err());

        let mut input = valid_input();
        input.max_history = 1_000_001;
        assert!(input.build().is_err());

        let mut input = valid_input();
        input.entropy_threshold = f64::NAN;
        assert!(input.build().is_err());
    }

    #[test]
    fn compatibility_constructor_uses_validated_input() {
        let config = ScanConfig::from_values(
            8, 256, 100, true, 4, 500, 4.5, true, false, true, 1000, true, true, true, true, 604800,
        );
        assert_eq!(config, valid_input().build().unwrap());
    }
}

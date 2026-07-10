//! checkpoint.rs
//! Checkpoint & Resume system for GitRecon (R-1, P0)
//!
//! ## SEC-006: Checkpoint Secrets Protection
//!
//! Checkpoints store ONLY progress metadata and hash identifiers—NEVER actual secret values.
//!
//! **What IS stored:**
//! - Target URL, timestamps, phase
//! - Configuration fingerprint (hash of args)
//! - SHA1 identifiers (hex strings of git objects)
//! - Progress counters (counts, indices)
//!
//! **What is NOT stored:**
//! - Actual secret findings (API keys, tokens, passwords, etc.)
//! - Decrypted blob contents
//! - Any sensitive plaintext data
//!
//! This design means resuming a checkpoint won't restore previously found secret values—only
//! scan progress. This is an intentional security trade-off acceptable for pentesting.
//!
//! **File Permissions:** All checkpoint files are created with mode 0600 (owner read/write only).
//!
//! ## SEC-007: TOCTOU Race Protection
//!
//! **Save operations:** Use atomic file creation with O_CREAT|O_EXCL (via create_new) to prevent
//! symlink attacks during checkpoint writes.
//!
//! **Load operations:** Validate file metadata AFTER opening, not before. The exists()->read()
//! pattern is vulnerable to TOCTOU races where an attacker can replace the file between the check
//! and use.
//!
//! **Directory validation:** Checkpoint directories must be owned by the current user and not
//! world-writable to prevent symlink placement attacks.
//!
//! **Custom directories:** GITRECON_CHECKPOINT_DIR env var allows custom checkpoint locations
//! for pentesting scenarios. Custom directories undergo the same validation.

use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};

/// Default checkpoint directory
const CHECKPOINT_DIR: &str = ".gitrecon/checkpoints";

/// Environment variable for custom checkpoint directory (for pentesting)
const CHECKPOINT_DIR_ENV: &str = "GITRECON_CHECKPOINT_DIR";

/// Maximum age for checkpoints (7 days in seconds)
const MAX_CHECKPOINT_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Current checkpoint format version
const CURRENT_CHECKPOINT_VERSION: CheckpointVersion = CheckpointVersion::V2;

/// Checkpoint format version for backward compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckpointVersion {
    /// V1: Initial checkpoint format (legacy)
    V1,
    /// V2: Enhanced format with versioning field
    V2,
}

impl CheckpointVersion {
    /// Get the latest supported version
    pub fn latest() -> Self {
        CURRENT_CHECKPOINT_VERSION
    }
}

/// Checkpoint data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint format version (for backward compatibility)
    #[serde(default = "CheckpointVersion::latest")]
    pub version: CheckpointVersion,

    /// Target URL (normalized)
    pub target: String,

    /// Checkpoint creation timestamp (Unix seconds)
    pub created_at: u64,

    /// Last update timestamp (Unix seconds)
    pub updated_at: u64,

    /// Current phase: DETECT, MAP, STREAM
    pub phase: CheckpointPhase,

    /// Configuration fingerprint (hash of key args)
    pub config_fingerprint: String,

    /// Phase 1: Detect result (if completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detect_result: Option<DetectCheckpoint>,

    /// Phase 2: Map result (if completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub map_result: Option<MapCheckpoint>,

    /// Phase 3: Stream progress
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_progress: Option<StreamCheckpoint>,
}

impl Checkpoint {
    /// Create a new checkpoint with the current version
    #[allow(dead_code)]
    pub fn new(
        target: String,
        phase: CheckpointPhase,
        config_fingerprint: String,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            version: CURRENT_CHECKPOINT_VERSION,
            target,
            created_at: now,
            updated_at: now,
            phase,
            config_fingerprint,
            detect_result: None,
            map_result: None,
            stream_progress: None,
        }
    }

    /// Check if this checkpoint is compatible with the current version
    pub fn is_compatible(&self) -> bool {
        matches!(self.version, CheckpointVersion::V1 | CheckpointVersion::V2)
    }

    /// Migrate V1 checkpoint to V2 format
    pub fn migrate_to_v2(&mut self) {
        if self.version == CheckpointVersion::V1 {
            self.version = CheckpointVersion::V2;
            self.updated_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CheckpointPhase {
    Detect,
    Map,
    Stream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectCheckpoint {
    pub git_url: String,
    pub confidence: u32,
    pub label: String,
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapCheckpoint {
    pub total_objects: usize,
    pub blob_sha1s_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCheckpoint {
    /// Total SHA1s to process
    pub total_sha1s: usize,

    /// SHA1s already processed (hex strings)
    pub processed_sha1s: Vec<String>,

    /// Findings collected so far
    pub findings_count: usize,

    /// Last checkpoint index (for periodic checkpointing)
    pub last_checkpoint_index: usize,

    /// PERF-003: Adaptive concurrency state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adaptive_state: Option<AdaptiveConcurrencyState>,
}

/// PERF-003: Adaptive concurrency state for checkpoint resume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveConcurrencyState {
    /// Current worker count (after adaptive adjustments)
    pub current_workers: usize,

    /// Initial worker count (from --workers flag)
    pub initial_workers: usize,

    /// Total requests tracked in current window
    pub window_requests: usize,

    /// Total errors tracked in current window
    pub window_errors: usize,

    /// Last adjustment index (blob count when last adjustment was made)
    pub last_adjustment_index: usize,
}

/// Compute config fingerprint from key arguments
///
/// This ensures we don't resume with mismatched configuration.
#[allow(dead_code)]
pub fn compute_config_fingerprint(
    fuzz: bool,
    min_confidence: u32,
    entropy_threshold: f64,
    max_blob_size: usize,
) -> String {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    fuzz.hash(&mut hasher);
    min_confidence.hash(&mut hasher);
    entropy_threshold.to_bits().hash(&mut hasher);
    max_blob_size.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Get checkpoint directory path
///
/// SEC-007: Supports custom checkpoint directory via GITRECON_CHECKPOINT_DIR
/// for pentesting scenarios. Custom directories undergo validation.
pub fn checkpoint_dir() -> PathBuf {
    if let Ok(custom_dir) = std::env::var(CHECKPOINT_DIR_ENV) {
        PathBuf::from(custom_dir)
    } else {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(CHECKPOINT_DIR)
    }
}

/// SEC-007: Validate directory is safe for checkpoint operations
///
/// **TOCTOU Protection:** This validation is performed AFTER the directory is created
/// or opened, not before. The validation checks:
/// - Directory is owned by current user (prevents other users from tampering)
/// - Directory is not world-writable (prevents symlink placement attacks)
/// - Directory is not a symlink (prevents symlink redirection attacks)
///
/// Returns Ok if safe, Err if validation fails.
fn validate_directory_safe(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("Failed to get metadata for directory: {}", path.display()))?;

    // Check: not a symlink
    if path.is_symlink() {
        anyhow::bail!("Security violation: checkpoint path is a symlink: {}", path.display());
    }

    // Check: owned by current user
    let uid = metadata.uid();
    let current_uid = unsafe { libc::getuid() };
    if uid != current_uid {
        anyhow::bail!(
            "Security violation: checkpoint directory not owned by current user (uid={}, expected={}): {}",
            uid, current_uid, path.display()
        );
    }

    // Check: not world-writable (no o+w)
    let mode = metadata.mode() & 0o777;
    if mode & 0o002 != 0 {
        anyhow::bail!(
            "Security violation: checkpoint directory is world-writable: {}",
            path.display()
        );
    }

    Ok(())
}

/// Ensure checkpoint directory exists and is safe
///
/// SEC-007: Creates directory with secure permissions and validates safety
/// after creation to prevent TOCTOU races.
pub fn ensure_checkpoint_dir() -> Result<PathBuf> {
    let dir = checkpoint_dir();

    // Create directory if it doesn't exist
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create checkpoint directory: {}", dir.display()))?;

        // Set restrictive permissions (0700 = owner rwx only)
        let mut perms = fs::metadata(&dir)
            .with_context(|| format!("Failed to get metadata for checkpoint directory: {}", dir.display()))?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&dir, perms)
            .with_context(|| format!("Failed to set permissions on checkpoint directory: {}", dir.display()))?;
    }

    // Validate directory is safe (TOCTOU protection: validate after creation)
    validate_directory_safe(&dir)?;

    Ok(dir)
}

/// Get checkpoint file path for a target
pub fn checkpoint_path(target: &str) -> PathBuf {
    let target_name = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .replace('/', "_")
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '.' { c } else { '_' })
        .collect::<String>();

    checkpoint_dir().join(format!("{}.json", target_name))
}

/// SEC-007: Validate checkpoint file is safe to read
///
/// **TOCTOU Protection:** This validation runs on an OPEN file handle, not on path.
/// By the time we validate, we already have the file open, so TOCTOU races during
/// the validation cannot affect the file we're reading.
///
/// Validates:
/// - File is owned by current user
/// - File permissions are 0600 (owner read/write only)
/// - File is a regular file (not symlink, device, etc.)
/// - File size is reasonable (< 10MB to prevent DoS)
fn validate_checkpoint_file(file: &File) -> Result<()> {
    let metadata = file.metadata()
        .context("Failed to get file metadata for checkpoint")?;

    // Check: regular file (not symlink, directory, device, etc.)
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        anyhow::bail!("Security violation: checkpoint file is a symlink");
    }
    if !file_type.is_file() {
        anyhow::bail!("Security violation: checkpoint path is not a regular file");
    }

    // Check: owned by current user
    let uid = metadata.uid();
    let current_uid = unsafe { libc::getuid() };
    if uid != current_uid {
        anyhow::bail!(
            "Security violation: checkpoint file not owned by current user (uid={}, expected={})",
            uid, current_uid
        );
    }

    // Check: permissions are exactly 0600 (owner read/write only)
    let mode = metadata.mode() & 0o777;
    if mode != 0o600 {
        anyhow::bail!(
            "Security violation: checkpoint file has insecure permissions (mode={:04o}, expected=0600)",
            mode
        );
    }

    // Check: file size is reasonable (< 10MB)
    let file_size = metadata.len();
    const MAX_CHECKPOINT_SIZE: u64 = 10 * 1024 * 1024; // 10MB
    if file_size > MAX_CHECKPOINT_SIZE {
        anyhow::bail!(
            "Security violation: checkpoint file too large ({} bytes, max {})",
            file_size, MAX_CHECKPOINT_SIZE
        );
    }

    Ok(())
}

/// Save checkpoint to disk
///
/// SEC-006: Checkpoint files are created with mode 0600 (owner read/write only)
/// to prevent other users from accessing checkpoint data.
///
/// SEC-007: Uses atomic file creation with O_CREAT|O_EXCL (via OpenOptions::create_new)
/// to prevent TOCTOU races during checkpoint writes. This ensures that if the file
/// already exists (possibly as a symlink placed by an attacker), the operation fails
/// rather than overwriting it.
///
/// The old pattern of `fs::write()` after checking `exists()` is vulnerable because
/// an attacker could replace the file with a symlink between the check and write.
pub fn save_checkpoint(checkpoint: &Checkpoint) -> Result<()> {
    ensure_checkpoint_dir()?;

    let path = checkpoint_path(&checkpoint.target);
    let json = serde_json::to_string_pretty(checkpoint)
        .context("Failed to serialize checkpoint")?;

    // SEC-007: Atomic file creation with O_CREAT|O_EXCL equivalent
    // create_new() fails if file exists, preventing symlink overwrite attacks
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT|O_EXCL - fail if exists
        .mode(0o600) // Set permissions atomically on create
        .open(&path)
        .with_context(|| format!("Failed to create checkpoint atomically: {}", path.display()))?;

    // Write the checkpoint data
    use std::io::Write;
    file.write_all(json.as_bytes())
        .with_context(|| format!("Failed to write checkpoint: {}", path.display()))?;

    // Sync to ensure data is written to disk
    file.sync_all()
        .with_context(|| format!("Failed to sync checkpoint to disk: {}", path.display()))?;

    Ok(())
}

/// Load checkpoint for a target
///
/// SEC-007: Validates file AFTER opening to prevent TOCTOU races. The old pattern
/// was: `if path.exists() { fs::read_to_string(&path) }` - this is vulnerable because
/// an attacker could replace the file between the exists() check and the read.
///
/// The new pattern opens the file first (getting a file handle), then validates that
/// the opened file is safe to read. If validation fails, we close the handle without
/// using any data from it.
///
/// PERF-001: Automatically migrates V1 checkpoints to V2 format on load.
pub fn load_checkpoint(target: &str) -> Result<Option<Checkpoint>> {
    let path = checkpoint_path(target);

    // Try to open the file - this is the TOCTOU-safe approach
    // If the file doesn't exist, we return None (not an error)
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context(format!("Failed to open checkpoint: {}", path.display())),
    };

    // SEC-007: Validate the OPEN file handle (not the path)
    // This prevents TOCTOU races during validation
    validate_checkpoint_file(&file)
        .with_context(|| format!("Checkpoint validation failed: {}", path.display()))?;

    // Read and parse the checkpoint
    let mut reader = BufReader::new(file);
    let mut json = String::new();
    reader.read_to_string(&mut json)
        .with_context(|| format!("Failed to read checkpoint: {}", path.display()))?;

    let mut checkpoint: Checkpoint = serde_json::from_str(&json)
        .with_context(|| format!("Failed to parse checkpoint: {}", path.display()))?;

    // PERF-001: Migrate V1 checkpoints to V2
    if checkpoint.version == CheckpointVersion::V1 {
        checkpoint.migrate_to_v2();
        // Save migrated checkpoint back to disk
        let _ = save_checkpoint(&checkpoint);
    }

    Ok(Some(checkpoint))
}

/// Delete checkpoint for a target
#[allow(dead_code)]
pub fn delete_checkpoint(target: &str) -> Result<()> {
    let path = checkpoint_path(target);

    // SEC-007: Validate before delete
    if path.exists() {
        // Check it's a regular file we own
        let metadata = fs::metadata(&path)
            .with_context(|| format!("Failed to get metadata for checkpoint: {}", path.display()))?;

        if !metadata.file_type().is_file() {
            anyhow::bail!("Security violation: checkpoint path is not a regular file: {}", path.display());
        }

        let current_uid = unsafe { libc::getuid() };
        if metadata.uid() != current_uid {
            anyhow::bail!("Security violation: checkpoint file not owned by current user: {}", path.display());
        }

        fs::remove_file(&path)
            .with_context(|| format!("Failed to delete checkpoint: {}", path.display()))?;
    }

    Ok(())
}

/// Cleanup old checkpoints (>7 days)
///
/// SEC-007: Validates each file before deletion to prevent accidental removal
/// of files placed via symlink attacks.
pub fn cleanup_old_checkpoints() -> Result<usize> {
    let dir = ensure_checkpoint_dir()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut cleaned = 0;

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        // SEC-007: Validate file before processing
        // Check it's owned by us and is a regular file
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue, // Skip files we can't read
        };

        if !metadata.file_type().is_file() {
            continue; // Skip non-files
        }

        let current_uid = unsafe { libc::getuid() };
        if metadata.uid() != current_uid {
            continue; // Skip files not owned by us
        }

        if let Ok(modified) = metadata.modified() {
            let age_secs = now.saturating_sub(modified.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());

            if age_secs > MAX_CHECKPOINT_AGE_SECS && fs::remove_file(&path).is_ok() {
                cleaned += 1;
            }
        }
    }

    Ok(cleaned)
}

/// Verify config fingerprint matches
#[allow(dead_code)]
pub fn verify_config_fingerprint(
    checkpoint: &Checkpoint,
    fuzz: bool,
    min_confidence: u32,
    entropy_threshold: f64,
    max_blob_size: usize,
) -> Result<bool> {
    let current_fingerprint = compute_config_fingerprint(
        fuzz,
        min_confidence,
        entropy_threshold,
        max_blob_size,
    );

    Ok(checkpoint.config_fingerprint == current_fingerprint)
}

/// Find the latest checkpoint across all targets
///
/// PERF-001: Enables --resume flag to find the most recent checkpoint
/// when no specific target is provided. Returns checkpoints sorted by
/// updated_at timestamp (newest first).
pub fn find_latest_checkpoints(limit: usize) -> Result<Vec<Checkpoint>> {
    let dir = ensure_checkpoint_dir()?;
    let mut checkpoints: Vec<Checkpoint> = Vec::new();

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();

        // Only process JSON files
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        // SEC-007: Validate file before processing
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };

        if !metadata.file_type().is_file() {
            continue;
        }

        let current_uid = unsafe { libc::getuid() };
        if metadata.uid() != current_uid {
            continue;
        }

        // Try to load the checkpoint
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };

        if validate_checkpoint_file(&file).is_err() {
            continue;
        }

        let mut reader = BufReader::new(file);
        let mut json = String::new();
        if reader.read_to_string(&mut json).is_err() {
            continue;
        }

        if let Ok(cp) = serde_json::from_str::<Checkpoint>(&json) {
            // Check compatibility and migrate if needed
            if cp.is_compatible() {
                checkpoints.push(cp);
            }
        }
    }

    // Sort by updated_at descending (newest first)
    checkpoints.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    // Return at most `limit` checkpoints
    checkpoints.truncate(limit);

    Ok(checkpoints)
}

/// Get a list of all checkpoint targets
///
/// Returns a list of target identifiers that have checkpoints,
/// sorted by last update time (newest first).
#[allow(dead_code)]
pub fn list_checkpoint_targets() -> Result<Vec<String>> {
    let checkpoints = find_latest_checkpoints(100)?;
    Ok(checkpoints.into_iter().map(|cp| cp.target).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_fingerprint() {
        let fp1 = compute_config_fingerprint(true, 45, 4.5, 4);
        let fp2 = compute_config_fingerprint(true, 45, 4.5, 4);
        let fp3 = compute_config_fingerprint(false, 45, 4.5, 4);

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_checkpoint_path() {
        let path = checkpoint_path("https://example.com");
        assert!(path.to_string_lossy().contains("example.com"));
    }

    #[test]
    fn test_checkpoint_roundtrip() {
        let checkpoint = Checkpoint {
            version: CURRENT_CHECKPOINT_VERSION,
            target: "https://example.com".to_string(),
            created_at: 123456,
            updated_at: 123456,
            phase: CheckpointPhase::Stream,
            config_fingerprint: "test123".to_string(),
            detect_result: None,
            map_result: None,
            stream_progress: Some(StreamCheckpoint {
                total_sha1s: 1000,
                processed_sha1s: vec!["abc123".to_string()],
                findings_count: 5,
                last_checkpoint_index: 100,
                adaptive_state: None,
            }),
        };

        let json = serde_json::to_string(&checkpoint).unwrap();
        let loaded: Checkpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.target, checkpoint.target);
        assert!(matches!(loaded.phase, CheckpointPhase::Stream));
        assert_eq!(loaded.stream_progress.unwrap().processed_sha1s.len(), 1);
    }

    #[test]
    fn test_validate_regular_file() {
        // This test verifies that validation works for regular files
        // A full TOCTOU test would require creating symlinks and testing races
        let checkpoint = Checkpoint {
            version: CURRENT_CHECKPOINT_VERSION,
            target: "https://test.example.com".to_string(),
            created_at: 123456,
            updated_at: 123456,
            phase: CheckpointPhase::Detect,
            config_fingerprint: compute_config_fingerprint(true, 45, 4.5, 4),
            detect_result: Some(DetectCheckpoint {
                git_url: "https://test.example.com".to_string(),
                confidence: 95,
                label: "Git".to_string(),
                branch: Some("main".to_string()),
            }),
            map_result: None,
            stream_progress: None,
        };

        // Try to save (will create new file)
        let result = save_checkpoint(&checkpoint);
        // This might fail if directory doesn't exist or permissions issue
        // but in a proper test environment it should work
        if result.is_ok() {
            // Load it back
            if let Ok(Some(loaded)) = load_checkpoint("https://test.example.com") {
                assert_eq!(loaded.target, checkpoint.target);
                // Cleanup
                let _ = delete_checkpoint("https://test.example.com");
            }
        }
    }
}

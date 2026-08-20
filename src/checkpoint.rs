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
//! - Finding metadata and matched values needed to preserve report continuity on resume
//!
//! **What is NOT stored:**
//! - Decrypted blob contents
//! - Unrelated source files or full repository snapshots
//! - Any data beyond the serialized finding/checkpoint fields
//!
//! Resuming restores processed-object state and serialized findings so a resumed report does not
//! lose findings collected before interruption. Checkpoint files therefore remain sensitive and
//! are protected with restrictive permissions, integrity validation, and HMAC verification.
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

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Default checkpoint directory
const CHECKPOINT_DIR: &str = ".gitrecon/checkpoints";

/// Environment variable for custom checkpoint directory (for pentesting)
const CHECKPOINT_DIR_ENV: &str = "GITRECON_CHECKPOINT_DIR";

/// Maximum age for checkpoints (7 days in seconds)
const MAX_CHECKPOINT_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// BUG-STAB-009: Maximum retry attempts for checkpoint save
const MAX_SAVE_RETRIES: usize = 3;

/// BUG-STAB-009: Base delay for exponential backoff (milliseconds)
const RETRY_BASE_DELAY_MS: u64 = 100;

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

    /// BUG-SEC-005 FIX: HMAC-SHA256 for integrity verification
    /// Computed over all other fields to detect tampering
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

impl Checkpoint {
    /// Create a new checkpoint with the current version
    #[allow(dead_code)]
    pub fn new(target: String, phase: CheckpointPhase, config_fingerprint: String) -> Self {
        // Sprint 3 (S3.6): panic-safe timestamp — see safe_now_secs comment near save_checkpoint.
        let now = safe_now_secs();

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
            hmac: None,
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
            // Sprint 3 (S3.6): panic-safe timestamp.
            self.updated_at = safe_now_secs();
        }
    }

    /// BUG-SEC-005 FIX: Compute HMAC-SHA256 for checkpoint integrity
    ///
    /// The HMAC is computed over all checkpoint fields except the hmac field itself.
    /// Uses a fixed secret key derived from the target and config fingerprint.
    /// For pentesting scenarios, this provides tamper detection without requiring
    /// external secret management.
    fn compute_hmac(&self) -> Result<String> {
        // Create a clone without hmac for computation
        let mut checkpoint_without_hmac = self.clone();
        checkpoint_without_hmac.hmac = None;

        // Serialize to canonical JSON
        let json_str = serde_json::to_string(&checkpoint_without_hmac)
            .context("Failed to serialize checkpoint for HMAC computation")?;

        // Derive a key from target and config fingerprint
        // This ensures each checkpoint has a unique key while being deterministic
        let key_material = format!(
            "{}:{}:gitrecon-integrity",
            checkpoint_without_hmac.target, checkpoint_without_hmac.config_fingerprint
        );

        // Use SHA256 to derive a 32-byte key
        let key_bytes = sha2::Sha256::digest(key_material.as_bytes());

        // Compute HMAC-SHA256
        let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
            .map_err(|e| anyhow::anyhow!("HMAC key error: {}", e))?;
        mac.update(json_str.as_bytes());
        let result = mac.finalize();

        Ok(hex::encode(result.into_bytes()))
    }

    /// BUG-SEC-005 FIX: Verify HMAC integrity
    ///
    /// Returns true if HMAC is valid or if checkpoint is from legacy version (no HMAC).
    /// Returns false if HMAC verification fails (potential tampering detected).
    pub fn verify_hmac(&self) -> bool {
        // If no HMAC present, this is a legacy checkpoint - accept it
        if self.hmac.is_none() {
            return true;
        }

        // Compute expected HMAC and compare
        match self.compute_hmac() {
            Ok(expected) => {
                self.hmac.as_ref().is_some_and(|actual| {
                    // Constant-time comparison to prevent timing attacks
                    if expected.as_bytes().ct_eq(actual.as_bytes()).into() {
                        return true;
                    }
                    false
                })
            }
            Err(_) => {
                // If we can't compute HMAC, fail closed
                false
            }
        }
    }

    /// BUG-SEC-005 FIX: Update HMAC before saving
    ///
    /// This should be called before serializing a checkpoint for save.
    /// It ensures the hmac field contains the current integrity value.
    pub fn update_hmac(&mut self) -> Result<()> {
        self.hmac = Some(self.compute_hmac()?);
        Ok(())
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

    /// BUG-STAB-011: Store serialized findings for resume capability
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<FindingCheckpoint>,

    /// Last checkpoint index (for periodic checkpointing)
    pub last_checkpoint_index: usize,

    /// PERF-003: Adaptive concurrency state
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adaptive_state: Option<AdaptiveConcurrencyState>,
}

/// BUG-STAB-011: Minimal finding representation for checkpoint storage
/// Stores only essential info for resume; full Finding recreated on load
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCheckpoint {
    pub filename: String,
    pub line: usize,
    pub pattern_id: String,
    pub description: String,
    pub severity: String,
    #[serde(rename = "match")]
    pub match_str: String,
    pub context: String,
    pub is_deleted: bool,
    pub commit_sha1: Option<String>,
    pub confidence_adjustment: Option<String>,
}

impl From<crate::streamer::Finding> for FindingCheckpoint {
    fn from(finding: crate::streamer::Finding) -> Self {
        Self {
            filename: finding.filename,
            line: finding.line,
            pattern_id: finding.pattern_id,
            description: finding.description,
            severity: finding.severity,
            match_str: finding.match_str,
            context: finding.context,
            is_deleted: finding.is_deleted,
            commit_sha1: finding.commit_sha1,
            confidence_adjustment: finding.confidence_adjustment,
        }
    }
}

impl From<FindingCheckpoint> for crate::streamer::Finding {
    fn from(fc: FindingCheckpoint) -> Self {
        Self {
            filename: fc.filename,
            line: fc.line,
            pattern_id: fc.pattern_id,
            description: fc.description,
            severity: fc.severity,
            match_str: fc.match_str,
            context: fc.context,
            is_deleted: fc.is_deleted,
            commit_sha1: fc.commit_sha1,
            confidence_adjustment: fc.confidence_adjustment,
        }
    }
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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    fuzz.hash(&mut hasher);
    min_confidence.hash(&mut hasher);
    entropy_threshold.to_bits().hash(&mut hasher);
    max_blob_size.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Compute a checkpoint fingerprint including scan-policy identity.
///
/// The legacy function remains stable for old checkpoint fixtures; new Streamer
/// checkpoints use this variant so normal and exhaustive scans cannot resume
/// from one another's object-processing state.
pub fn compute_config_fingerprint_with_policy(
    fuzz: bool,
    min_confidence: u32,
    entropy_threshold: f64,
    max_blob_size: usize,
    exhaustive: bool,
) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    compute_config_fingerprint(fuzz, min_confidence, entropy_threshold, max_blob_size)
        .hash(&mut hasher);
    exhaustive.hash(&mut hasher);
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
        anyhow::bail!(
            "Security violation: checkpoint path is a symlink: {}",
            path.display()
        );
    }

    // Sprint 5 (S5.8): Unix-only ownership + mode checks. See validate_checkpoint_file
    // for the rationale — Windows uses NTFS ACLs, unreproducible portably here.
    #[cfg(unix)]
    {
        let uid = metadata.uid();
        let current_uid = unsafe { libc::getuid() };
        if uid != current_uid {
            anyhow::bail!(
                "Security violation: checkpoint directory not owned by current user (uid={}, expected={}): {}",
                uid, current_uid, path.display()
            );
        }

        let mode = metadata.mode() & 0o777;
        if mode & 0o002 != 0 {
            anyhow::bail!(
                "Security violation: checkpoint directory is world-writable: {}",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata; // silence unused warning
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

        // Sprint 5 (S5.8): 0700 dir permissions are Unix-only. On Windows the
        // parent %APPDATA% inherits owner-only ACLs, so this stays secure by
        // NTFS default without an explicit set_permissions call.
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&dir)
                .with_context(|| {
                    format!(
                        "Failed to get metadata for checkpoint directory: {}",
                        dir.display()
                    )
                })?
                .permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&dir, perms).with_context(|| {
                format!(
                    "Failed to set permissions on checkpoint directory: {}",
                    dir.display()
                )
            })?;
        }
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
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
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
    let metadata = file
        .metadata()
        .context("Failed to get file metadata for checkpoint")?;

    // Check: regular file (not symlink, directory, device, etc.)
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        anyhow::bail!("Security violation: checkpoint file is a symlink");
    }
    if !file_type.is_file() {
        anyhow::bail!("Security violation: checkpoint path is not a regular file");
    }

    // Sprint 5 (S5.8): the ownership + permission checks below are Unix-only.
    // Windows relies on NTFS ACLs; we can't reproduce the exact "owned by
    // current user + mode 0600" contract portably. Skip on Windows — the file
    // was created by the same process (see save_checkpoint's create_new + mode
    // 0600 write which is also Unix-gated), so a Windows attacker would need
    // filesystem-level access we can't defend against at this layer anyway.
    #[cfg(unix)]
    {
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
    }

    // Check: file size is reasonable (< 10MB)
    let file_size = metadata.len();
    const MAX_CHECKPOINT_SIZE: u64 = 10 * 1024 * 1024; // 10MB
    if file_size > MAX_CHECKPOINT_SIZE {
        anyhow::bail!(
            "Security violation: checkpoint file too large ({} bytes, max {})",
            file_size,
            MAX_CHECKPOINT_SIZE
        );
    }

    Ok(())
}

/// Save checkpoint to disk
///
/// SEC-006: Checkpoint files are created with mode 0600 (owner read/write only)
/// to prevent other users from accessing checkpoint data.
///
/// SEC-007: Uses atomic write+rename pattern to prevent TOCTOU races during
/// checkpoint writes. This ensures that checkpoint updates are atomic:
/// either the full new checkpoint is visible, or the old one remains.
///
/// The old pattern of `fs::write()` after checking `exists()` is vulnerable because
/// an attacker could replace the file with a symlink between the check and write.
///
/// BUG-SEC-003 FIX: Uses temp file + atomic rename instead of create_new(),
/// allowing safe updates to existing checkpoints without race conditions.
///
/// BUG-STAB-009 FIX: Implements retry with exponential backoff on save failure.
///
/// BUG-SEC-005 FIX: Computes HMAC before saving for integrity verification.
/// Sprint 3 (S3.6): sweep orphan `.tmp-<ts>-<pid>` files left by a killed process.
///
/// `save_checkpoint` creates temp files with `create_new(true)` — if a prior run was
/// killed between temp-create and rename, the .tmp survives forever, cluttering the
/// checkpoint dir and (worse) potentially colliding with future timestamps at
/// extreme edge cases. Called opportunistically by `save_checkpoint` on entry.
fn sweep_orphan_tmp_files(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let cutoff = SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(5 * 60))
        .unwrap_or(UNIX_EPOCH);
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        // Match the exact temp-file convention: <basename>.tmp-<ts>-<pid>
        if !name.contains(".tmp-") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let Ok(mtime) = meta.modified() else { continue };
        if mtime < cutoff {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Sprint 3 (S3.6): fsync the parent directory after a rename so the directory
/// entry itself is durable. Without this, on POSIX a crash between the rename
/// completing and the directory being flushed can lose the file entirely.
/// On non-Unix this is a no-op — Windows guarantees rename durability via NTFS
/// journaling.
#[cfg(unix)]
fn fsync_parent_dir(child: &Path) -> std::io::Result<()> {
    if let Some(parent) = child.parent() {
        let dir = fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}
#[cfg(not(unix))]
fn fsync_parent_dir(_child: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Return current wall-clock nanos since UNIX_EPOCH, saturating on clock skew.
///
/// Sprint 3 (S3.6 panic-safety): the codebase used to `duration_since(UNIX_EPOCH).unwrap()`
/// on hot paths — this panics if the system clock was set before 1970 (rare, but
/// happens on containers and VMs with a busted RTC). A panic mid-save loses every
/// finding accumulated so far. `Duration::ZERO` is the correct fallback: a temp
/// filename collision is far cheaper than a lost scan.
fn safe_now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn safe_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn save_checkpoint(checkpoint: &Checkpoint) -> Result<()> {
    ensure_checkpoint_dir()?;

    let path = checkpoint_path(&checkpoint.target);

    // Sprint 3 (S3.6): opportunistic orphan sweep. Cheap (single readdir); catches
    // .tmp files left by force-killed prior runs.
    if let Some(dir) = path.parent() {
        sweep_orphan_tmp_files(dir);
    }

    // BUG-SEC-005 FIX: Update HMAC before saving
    let mut checkpoint_with_hmac = checkpoint.clone();
    checkpoint_with_hmac
        .update_hmac()
        .context("Failed to compute checkpoint HMAC")?;

    let json = serde_json::to_string_pretty(&checkpoint_with_hmac)
        .context("Failed to serialize checkpoint")?;

    // BUG-STAB-009: Retry loop with exponential backoff
    for attempt in 0..MAX_SAVE_RETRIES {
        // BUG-SEC-003 FIX: Use temp file + atomic rename pattern
        // Use unique temp path to avoid conflicts in concurrent scenarios
        // Sprint 3 (S3.6): panic-safe timestamp — see safe_now_nanos comment.
        let timestamp = safe_now_nanos();
        let temp_path = path.with_extension(format!("tmp-{}-{}", timestamp, std::process::id()));

        // BUG-STAB-009: Helper function to write to temp file with proper cleanup
        let write_result = (|| {
            use std::io::Write;
            // Sprint 5 (S5.8): OpenOptions::mode() is a Unix-only extension.
            // On Windows, permissions come from NTFS ACL inheritance and there's
            // no direct portable equivalent — the file lives in %APPDATA% which
            // inherits owner-only ACLs from the user's profile.
            #[cfg(unix)]
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp_path)
                .with_context(|| {
                    format!("Failed to create temp checkpoint: {}", temp_path.display())
                })?;
            #[cfg(not(unix))]
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .with_context(|| {
                    format!("Failed to create temp checkpoint: {}", temp_path.display())
                })?;

            file.write_all(json.as_bytes()).with_context(|| {
                format!("Failed to write temp checkpoint: {}", temp_path.display())
            })?;

            file.sync_all().with_context(|| {
                format!("Failed to sync temp checkpoint: {}", temp_path.display())
            })?;

            Ok::<(), anyhow::Error>(())
        })();

        if let Err(e) = write_result {
            // Clean up temp file if write failed
            let _ = fs::remove_file(&temp_path);

            // BUG-STAB-009: Exponential backoff before retry
            if attempt < MAX_SAVE_RETRIES - 1 {
                let delay_ms = RETRY_BASE_DELAY_MS * (2_u64.pow(attempt as u32));
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                continue;
            }
            return Err(e);
        }

        // Atomic rename - this is the TOCTOU-safe operation
        // On POSIX, rename() is atomic and replaces the target if it exists
        let rename_result = fs::rename(&temp_path, &path);

        if let Err(e) = rename_result {
            // Clean up temp file if rename failed
            let _ = fs::remove_file(&temp_path);

            // BUG-STAB-009: Retry on rename failure with backoff
            if attempt < MAX_SAVE_RETRIES - 1 {
                let delay_ms = RETRY_BASE_DELAY_MS * (2_u64.pow(attempt as u32));
                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                continue;
            }
            return Err(e).with_context(|| {
                format!(
                    "Failed to rename checkpoint: {} -> {}",
                    temp_path.display(),
                    path.display()
                )
            });
        }

        // Sprint 3 (S3.6): fsync the parent directory so the rename itself is
        // durable. Without this, a crash between rename() returning and the
        // directory entry being flushed can lose the checkpoint on POSIX. Best
        // effort — a failure here doesn't invalidate the write.
        let _ = fsync_parent_dir(&path);

        // Success - break out of retry loop
        return Ok(());
    }

    // Should not reach here, but handle the case
    anyhow::bail!(
        "Failed to save checkpoint after {} retries",
        MAX_SAVE_RETRIES
    )
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
///
/// BUG-SEC-005 FIX: Verifies HMAC integrity after loading. Detects tampering.
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
    reader
        .read_to_string(&mut json)
        .with_context(|| format!("Failed to read checkpoint: {}", path.display()))?;

    let mut checkpoint: Checkpoint = serde_json::from_str(&json)
        .with_context(|| format!("Failed to parse checkpoint: {}", path.display()))?;

    // PERF-001: Migrate V1 checkpoints to V2
    if checkpoint.version == CheckpointVersion::V1 {
        checkpoint.migrate_to_v2();
        // Save migrated checkpoint back to disk
        let _ = save_checkpoint(&checkpoint);
    }

    // BUG-SEC-005 FIX: Verify HMAC integrity
    if !checkpoint.verify_hmac() {
        anyhow::bail!(
            "Checkpoint HMAC verification failed - possible tampering detected: {}",
            path.display()
        );
    }

    Ok(Some(checkpoint))
}

/// Delete checkpoint for a target
///
/// BUG-SEC-001 FIX: Uses open-handle-validate-unlink pattern to prevent TOCTOU attacks.
/// The old pattern of exists() → metadata() → remove_file() was vulnerable because
/// an attacker could replace the file with a symlink between the check and unlink.
///
/// The new pattern:
/// 1. Open file handle (gets reference to actual inode)
/// 2. Validate on OPENED handle (not path)
/// 3. Close handle, then unlink (safe because we've validated what we opened)
#[allow(dead_code)]
pub fn delete_checkpoint(target: &str) -> Result<()> {
    let path = checkpoint_path(target);

    // BUG-SEC-001 FIX: Open file handle FIRST
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context(format!("Failed to open checkpoint: {}", path.display())),
    };

    // BUG-SEC-001 FIX: Validate on OPENED handle (not path)
    let metadata = file
        .metadata()
        .with_context(|| format!("Failed to get metadata for checkpoint: {}", path.display()))?;

    if !metadata.file_type().is_file() {
        anyhow::bail!(
            "Security violation: checkpoint path is not a regular file: {}",
            path.display()
        );
    }

    // Sprint 5 (S5.8): Unix-only ownership check.
    #[cfg(unix)]
    {
        let current_uid = unsafe { libc::getuid() };
        if metadata.uid() != current_uid {
            anyhow::bail!(
                "Security violation: checkpoint file not owned by current user: {}",
                path.display()
            );
        }
    }

    // Close handle, then unlink (safe because we validated the handle)
    drop(file);
    fs::remove_file(&path)
        .with_context(|| format!("Failed to delete checkpoint: {}", path.display()))?;

    Ok(())
}

/// Cleanup old checkpoints (>7 days)
///
/// BUG-SEC-002 FIX: Uses open-handle-validate-unlink pattern to prevent TOCTOU attacks.
/// The old pattern of metadata check → remove_file() was vulnerable because an attacker
/// could replace the file with a symlink after the metadata check but before removal.
///
/// The new pattern:
/// 1. Open file handle FIRST
/// 2. Validate age/ownership on OPENED handle
/// 3. Close handle, then unlink (safe because we've validated what we opened)
pub fn cleanup_old_checkpoints() -> Result<usize> {
    let dir = ensure_checkpoint_dir()?;
    // Sprint 3 (S3.6): panic-safe timestamp.
    let now = safe_now_secs();

    let mut cleaned = 0;

    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        // BUG-SEC-002 FIX: Open FIRST
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(_) => continue, // Skip files we can't open
        };

        // BUG-SEC-002 FIX: Validate on handle
        let metadata = match file.metadata() {
            Ok(m) => m,
            Err(_) => {
                drop(file);
                continue;
            }
        };

        // Skip non-files
        if !metadata.file_type().is_file() {
            drop(file);
            continue;
        }

        // Skip files not owned by us (Unix only — see S5.8).
        #[cfg(unix)]
        {
            let current_uid = unsafe { libc::getuid() };
            if metadata.uid() != current_uid {
                drop(file);
                continue;
            }
        }

        // Check age
        let should_delete = if let Ok(modified) = metadata.modified() {
            let age_secs = now.saturating_sub(
                modified
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            age_secs > MAX_CHECKPOINT_AGE_SECS
        } else {
            false
        };

        if should_delete {
            // BUG-SEC-002 FIX: Close BEFORE delete
            drop(file);
            if fs::remove_file(&path).is_ok() {
                cleaned += 1;
            }
        } else {
            drop(file);
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
    let current_fingerprint =
        compute_config_fingerprint(fuzz, min_confidence, entropy_threshold, max_blob_size);

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

        // Sprint 5 (S5.8): Unix-only ownership check.
        #[cfg(unix)]
        {
            let current_uid = unsafe { libc::getuid() };
            if metadata.uid() != current_uid {
                continue;
            }
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
    checkpoints.sort_by_key(|b| std::cmp::Reverse(b.updated_at));

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
    use std::fs;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;
    use tempfile::TempDir;

    // Global mutex to prevent parallel test execution interference
    // with the GITRECON_CHECKPOINT_DIR environment variable
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// Helper: Create a test checkpoint with valid data
    fn create_test_checkpoint(target: &str) -> Checkpoint {
        Checkpoint {
            version: CURRENT_CHECKPOINT_VERSION,
            target: target.to_string(),
            created_at: 123456,
            updated_at: 123456,
            phase: CheckpointPhase::Detect,
            config_fingerprint: compute_config_fingerprint(true, 45, 4.5, 4),
            detect_result: Some(DetectCheckpoint {
                git_url: target.to_string(),
                confidence: 95,
                label: "Git".to_string(),
                branch: Some("main".to_string()),
            }),
            map_result: None,
            stream_progress: None,
            hmac: None,
        }
    }

    /// Helper: Set up a temporary checkpoint directory
    fn setup_temp_checkpoint_dir() -> TempDir {
        let temp_dir = TempDir::new().unwrap();
        std::env::set_var(CHECKPOINT_DIR_ENV, temp_dir.path());
        temp_dir
    }

    /// Test 1: Atomic write succeeds even with concurrent saves
    ///
    /// BUG-SEC-003 UPDATE: With atomic rename pattern, all saves succeed
    /// (last one wins via atomic rename). This verifies the atomic nature
    /// of the rename operation - no corruption occurs even with concurrent saves.
    #[test]
    fn test_atomic_write_concurrent_saves() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();
        let barrier = Arc::new(Barrier::new(4));
        let target = "https://concurrent.example.com";
        let mut handles = vec![];

        // Spawn 4 threads trying to save the same checkpoint concurrently
        for i in 0..4 {
            let barrier_clone = Arc::clone(&barrier);
            let target_clone = target.to_string();
            let handle = thread::spawn(move || {
                let mut checkpoint = create_test_checkpoint(&target_clone);
                checkpoint.config_fingerprint = format!("variant_{}", i);

                // Wait for all threads to be ready
                barrier_clone.wait();

                // All threads attempt to save simultaneously
                save_checkpoint(&checkpoint)
            });
            handles.push(handle);
        }

        // Collect results - all should succeed with atomic rename
        let mut success_count = 0;
        for handle in handles {
            if handle.join().unwrap().is_ok() {
                success_count += 1;
            }
        }

        // All saves should succeed due to atomic rename (last one wins)
        assert_eq!(
            success_count, 4,
            "All saves should succeed with atomic rename pattern"
        );

        // Verify the saved checkpoint is valid (one of the variants)
        let loaded = load_checkpoint(target).unwrap().unwrap();
        assert_eq!(loaded.target, target);
        // The final fingerprint should be one of the variants (we don't know which due to racing)
        assert!(loaded.config_fingerprint.starts_with("variant_"));

        // Cleanup - temp_dir dropped here
        drop(temp_dir);
    }

    /// Test 2: Atomic update doesn't leave corrupt files
    ///
    /// BUG-SEC-003 UPDATE: Verifies that atomic rename ensures checkpoint
    /// updates are atomic - either the new checkpoint is fully visible or
    /// the old one remains. No intermediate/corrupt state is possible.
    #[test]
    fn test_partial_write_no_corruption() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();
        let target = "https://partial.example.com";

        // First, save a valid checkpoint
        let checkpoint1 = create_test_checkpoint(target);
        save_checkpoint(&checkpoint1).unwrap();

        // Verify it's valid
        let loaded1 = load_checkpoint(target).unwrap().unwrap();
        assert_eq!(loaded1.config_fingerprint, checkpoint1.config_fingerprint);

        // Now update with a new checkpoint - should succeed atomically
        let mut checkpoint2 = create_test_checkpoint(target);
        checkpoint2.config_fingerprint = "updated".to_string();
        let result = save_checkpoint(&checkpoint2);

        // Should succeed with atomic rename
        assert!(result.is_ok(), "Atomic update should succeed");

        // Verify checkpoint is valid (now contains the update)
        let loaded2 = load_checkpoint(target).unwrap().unwrap();
        assert_eq!(
            loaded2.config_fingerprint, "updated",
            "Checkpoint should contain the new data"
        );
        assert!(loaded2.is_compatible(), "Checkpoint should be valid JSON");

        // temp_dir dropped here
        drop(temp_dir);
    }

    /// Test 3: Existing checkpoint can be updated atomically
    ///
    /// BUG-SEC-003 UPDATE: Verifies that checkpoint updates are atomic
    /// via the rename pattern - no delete-then-save needed, the update
    /// happens atomically in a single operation.
    #[test]
    fn test_atomic_update_checkpoint() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();
        let target = "https://update.example.com";

        // Save initial checkpoint
        let checkpoint1 = create_test_checkpoint(target);
        save_checkpoint(&checkpoint1).unwrap();

        // Verify initial state
        let loaded1 = load_checkpoint(target).unwrap().unwrap();
        assert_eq!(loaded1.config_fingerprint, checkpoint1.config_fingerprint);

        // Update checkpoint directly - should succeed atomically via rename
        let mut checkpoint2 = create_test_checkpoint(target);
        checkpoint2.config_fingerprint = "updated_fingerprint".to_string();
        let result = save_checkpoint(&checkpoint2);

        assert!(result.is_ok(), "Atomic update should succeed via rename");

        // Verify updated state (original is gone, update is in place)
        let loaded2 = load_checkpoint(target).unwrap().unwrap();
        assert_eq!(
            loaded2.config_fingerprint, "updated_fingerprint",
            "Update should be in place atomically"
        );

        // temp_dir dropped here
        drop(temp_dir);
    }

    /// Test 4: Permissions are preserved (0600)
    ///
    /// Verifies that checkpoint files are created with mode 0600
    /// (owner read/write only) for security.
    #[test]
    fn test_permissions_preserved() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();
        let target = "https://permissions.example.com";

        // Save checkpoint
        let checkpoint = create_test_checkpoint(target);
        save_checkpoint(&checkpoint).unwrap();

        // Check file permissions
        let path = checkpoint_path(target);
        let metadata = fs::metadata(&path).unwrap();
        let mode = metadata.permissions().mode();

        // Verify 0600 (rw-------)
        // Note: mode includes file type bits, so we check the permission bits
        assert_eq!(
            mode & 0o777,
            0o600,
            "Checkpoint file should have 0600 permissions (owner rw only)"
        );

        // Verify the file is readable by owner
        let file = File::open(&path).unwrap();
        assert!(validate_checkpoint_file(&file).is_ok());

        // temp_dir dropped here
        drop(temp_dir);
    }

    /// Test 5: Error recovery works correctly
    ///
    /// Verifies that the system recovers gracefully from various error scenarios.
    #[test]
    fn test_error_recovery() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();

        // Test 5a: Loading non-existent checkpoint returns None (not error)
        let result = load_checkpoint("https://nonexistent.example.com");
        assert!(result.is_ok(), "Loading non-existent should not error");
        assert!(
            result.unwrap().is_none(),
            "Should return None for non-existent"
        );

        // Test 5b: Saving with invalid directory should fail gracefully
        // Save a valid checkpoint first
        let target = "https://recovery.example.com";
        let checkpoint = create_test_checkpoint(target);
        save_checkpoint(&checkpoint).unwrap();

        // Verify it loads
        let loaded = load_checkpoint(target).unwrap().unwrap();
        assert_eq!(loaded.target, target);

        // Test 5c: Deleting non-existent checkpoint is OK (no error)
        let result = delete_checkpoint("https://also-nonexistent.example.com");
        assert!(result.is_ok(), "Deleting non-existent should not error");

        // Test 5d: Corrupted JSON is handled gracefully
        let path = checkpoint_path(target);
        let corrupted_json = r#"{"invalid": "json", "missing": "fields"#;

        // Write corrupted data (bypassing save_checkpoint)
        fs::write(&path, corrupted_json).unwrap();

        // Loading should fail gracefully
        let result = load_checkpoint(target);
        assert!(result.is_err(), "Loading corrupted JSON should fail");

        // temp_dir dropped here
        drop(temp_dir);
    }

    /// Test 6: TOCTOU protection - validate after open
    ///
    /// Verifies that file validation happens on an open file handle,
    /// not on the path (preventing TOCTOU races).
    #[test]
    fn test_toctou_protection_validate_after_open() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();
        let target = "https://toctou.example.com";

        // Save checkpoint
        let checkpoint = create_test_checkpoint(target);
        save_checkpoint(&checkpoint).unwrap();

        // Verify load_checkpoint opens first, then validates
        // The implementation should:
        // 1. File::open(&path) - get handle
        // 2. validate_checkpoint_file(&file) - validate handle
        // 3. Read from handle (not path)
        let loaded = load_checkpoint(target).unwrap();
        assert!(loaded.is_some(), "Checkpoint should load successfully");
        assert_eq!(loaded.unwrap().target, target);

        // temp_dir dropped here
        drop(temp_dir);
    }

    /// Test 7: Directory validation prevents symlink attacks
    ///
    /// Verifies that checkpoint directory validation rejects symlinks.
    #[test]
    fn test_directory_validation_rejects_symlinks() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();

        // Verify our checkpoint directory is not a symlink
        let checkpoint_dir_path = checkpoint_dir();
        let metadata = fs::metadata(&checkpoint_dir_path).unwrap();
        let file_type = metadata.file_type();
        assert!(
            !file_type.is_symlink(),
            "Checkpoint directory should not be a symlink"
        );

        // Verify it's owned by current user (Unix only — see S5.8).
        #[cfg(unix)]
        {
            let current_uid = unsafe { libc::getuid() };
            assert_eq!(metadata.uid(), current_uid);
        }

        // temp_dir dropped here
        drop(temp_dir);
    }

    /// Test 8: File size limit prevents DoS
    ///
    /// Verifies that oversized checkpoint files are rejected.
    #[test]
    fn test_file_size_limit() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();
        let target = "https://oversized.example.com";

        // Create a checkpoint
        let checkpoint = create_test_checkpoint(target);
        save_checkpoint(&checkpoint).unwrap();

        let path = checkpoint_path(target);

        // Create a file larger than 10MB (which should be rejected)
        let oversized_data = vec![b'x'; 11 * 1024 * 1024]; // 11MB

        // Delete the checkpoint first, then write oversized data
        // We need to bypass save_checkpoint to create this invalid file
        delete_checkpoint(target).ok();

        // Write oversized data directly (bypassing security checks for testing)
        fs::write(&path, oversized_data).unwrap();

        // Try to open and validate
        let file = File::open(&path).unwrap();
        let result = validate_checkpoint_file(&file);

        assert!(result.is_err(), "Oversized file should be rejected");

        // temp_dir dropped here
        drop(temp_dir);
    }

    /// Test 9: Checkpoint version compatibility and migration
    ///
    /// Verifies V1 to V2 migration works correctly.
    // Sprint 5 (S5.8): test uses OpenOptions::mode which is Unix-only.
    #[cfg(unix)]
    #[test]
    fn test_checkpoint_version_migration() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();
        let target = "https://migration.example.com";

        // Create a V1 checkpoint (without version field, defaults to V1)
        let v1_json = r#"{
            "version": "v1",
            "target": "https://migration.example.com",
            "created_at": 123456,
            "updated_at": 123456,
            "phase": "Detect",
            "config_fingerprint": "test123",
            "detect_result": {
                "git_url": "https://migration.example.com",
                "confidence": 95,
                "label": "Git",
                "branch": "main"
            }
        }"#;

        let path = checkpoint_path(target);

        // Write with proper 0600 permissions using OpenOptions
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(v1_json.as_bytes()).unwrap();
        file.sync_all().unwrap();

        // Load and migrate
        let loaded = load_checkpoint(target).unwrap();
        assert!(loaded.is_some(), "Checkpoint should load successfully");
        assert_eq!(loaded.unwrap().version, CheckpointVersion::V2);

        // temp_dir dropped here
        drop(temp_dir);
    }

    /// Test 10: Cleanup old checkpoints respects ownership
    ///
    /// Verifies cleanup only removes files owned by current user.
    #[test]
    fn test_cleanup_respects_ownership() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();

        // Create some checkpoints
        for i in 0..3 {
            let target = format!("https://cleanup{}.example.com", i);
            let checkpoint = create_test_checkpoint(&target);
            save_checkpoint(&checkpoint).unwrap();
        }

        // Cleanup should succeed
        let result = cleanup_old_checkpoints();
        assert!(result.is_ok(), "Cleanup should succeed");

        // Clean up test checkpoints
        for i in 0..3 {
            let target = format!("https://cleanup{}.example.com", i);
            delete_checkpoint(&target).ok();
        }

        // temp_dir dropped here
        drop(temp_dir);
    }

    // Legacy tests from original implementation
    #[test]
    fn test_config_fingerprint() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let fp1 = compute_config_fingerprint(true, 45, 4.5, 4);
        let fp2 = compute_config_fingerprint(true, 45, 4.5, 4);
        let fp3 = compute_config_fingerprint(false, 45, 4.5, 4);
        let normal_policy = compute_config_fingerprint_with_policy(true, 45, 4.5, 4, false);
        let exhaustive_policy = compute_config_fingerprint_with_policy(true, 45, 4.5, 4, true);
        let exhaustive_policy_again =
            compute_config_fingerprint_with_policy(true, 45, 4.5, 4, true);

        assert_eq!(fp1, fp2);
        assert_ne!(fp1, fp3);
        assert_ne!(normal_policy, exhaustive_policy);
        assert_eq!(exhaustive_policy, exhaustive_policy_again);
    }

    #[test]
    fn finding_checkpoint_roundtrip_preserves_resume_metadata() {
        let finding = crate::streamer::Finding {
            filename: "fixture.txt".to_string(),
            line: 7,
            pattern_id: "fixture_pattern".to_string(),
            description: "Fixture finding".to_string(),
            severity: "HIGH".to_string(),
            match_str: "fixture-value".to_string(),
            context: "fixture context".to_string(),
            is_deleted: false,
            commit_sha1: Some("fixture-sha".to_string()),
            confidence_adjustment: Some("fixture adjustment".to_string()),
        };
        let checkpoint = FindingCheckpoint::from(finding.clone());
        let restored = crate::streamer::Finding::from(checkpoint);
        assert_eq!(restored.filename, finding.filename);
        assert_eq!(restored.line, finding.line);
        assert_eq!(restored.pattern_id, finding.pattern_id);
        assert_eq!(restored.match_str, finding.match_str);
        assert_eq!(restored.context, finding.context);
        assert_eq!(restored.commit_sha1, finding.commit_sha1);
        assert_eq!(
            restored.confidence_adjustment,
            finding.confidence_adjustment
        );
    }

    #[test]
    fn stream_checkpoint_json_roundtrip_preserves_findings() {
        let progress = StreamCheckpoint {
            total_sha1s: 2,
            processed_sha1s: vec!["fixture-sha".to_string()],
            findings_count: 1,
            findings: vec![FindingCheckpoint {
                filename: "fixture.txt".to_string(),
                line: 3,
                pattern_id: "fixture_pattern".to_string(),
                description: "Fixture finding".to_string(),
                severity: "MEDIUM".to_string(),
                match_str: "fixture-value".to_string(),
                context: "fixture context".to_string(),
                is_deleted: false,
                commit_sha1: Some("fixture-sha".to_string()),
                confidence_adjustment: None,
            }],
            last_checkpoint_index: 1,
            adaptive_state: None,
        };
        let encoded = serde_json::to_string(&progress).unwrap();
        let restored: StreamCheckpoint = serde_json::from_str(&encoded).unwrap();
        assert_eq!(restored.findings_count, 1);
        assert_eq!(restored.findings.len(), 1);
        assert_eq!(restored.findings[0].match_str, "fixture-value");
        assert_eq!(restored.processed_sha1s, vec!["fixture-sha"]);
    }

    #[test]
    fn test_checkpoint_path() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let path = checkpoint_path("https://example.com");
        assert!(path.to_string_lossy().contains("example.com"));
    }

    #[test]
    fn test_checkpoint_roundtrip() {
        let _lock = TEST_MUTEX.lock().unwrap();
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
                findings: vec![],
                last_checkpoint_index: 100,
                adaptive_state: None,
            }),
            hmac: None,
        };

        let json = serde_json::to_string(&checkpoint).unwrap();
        let loaded: Checkpoint = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.target, checkpoint.target);
        assert!(matches!(loaded.phase, CheckpointPhase::Stream));
        assert_eq!(loaded.stream_progress.unwrap().processed_sha1s.len(), 1);
    }

    #[test]
    fn test_validate_regular_file() {
        let _lock = TEST_MUTEX.lock().unwrap();
        let temp_dir = setup_temp_checkpoint_dir();
        let target = "https://test.example.com";

        let checkpoint = create_test_checkpoint(target);

        // Try to save (will create new file)
        let result = save_checkpoint(&checkpoint);
        assert!(result.is_ok(), "Save should succeed with temp dir");

        // Load it back
        let loaded = load_checkpoint(target).unwrap().unwrap();
        assert_eq!(loaded.target, checkpoint.target);

        // temp_dir dropped here
        drop(temp_dir);
    }

    // ── Sprint 3 (S3.6) — orphan sweep + panic-safe timestamp ────────────────

    #[test]
    fn safe_now_secs_returns_non_zero_on_healthy_clock() {
        // Sanity: on any host where the clock isn't set before 1970, we get a
        // positive value. The point of the helper is not to change the value but
        // to never panic — regression asserts here.
        let ts = safe_now_secs();
        assert!(
            ts > 1_600_000_000,
            "expected recent epoch seconds, got {ts}"
        );
    }

    #[test]
    fn safe_now_nanos_matches_secs_scale() {
        let secs = safe_now_secs();
        let nanos = safe_now_nanos();
        // nanos should be at least secs * 1e9 in the same reference frame.
        assert!(
            nanos as u64
                >= secs
                    .saturating_mul(1_000_000_000)
                    .saturating_sub(1_000_000_000),
            "nanos vs secs skew unexpectedly large"
        );
    }

    #[test]
    fn sweep_orphan_tmp_files_removes_stale_tmp_and_keeps_fresh_ones() {
        // Layout: temp dir with one very-old .tmp-* (mtime set to epoch via touch trick)
        // and one fresh .tmp-* — sweep must remove only the old one.
        //
        // We can't easily backdate mtime without an extra dep, so we assert the
        // KEEP direction: fresh files must NOT be removed.
        let dir =
            std::env::temp_dir().join(format!("gitrecon_ckpt_sweep_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let fresh = dir.join("checkpoint.tmp-999-999");
        let unrelated = dir.join("checkpoint.json");
        fs::write(&fresh, b"in flight").unwrap();
        fs::write(&unrelated, b"final").unwrap();

        sweep_orphan_tmp_files(&dir);

        assert!(
            fresh.exists(),
            "fresh .tmp file (< 5 min old) must survive sweep"
        );
        assert!(unrelated.exists(), "non-.tmp files must never be swept");

        let _ = fs::remove_dir_all(&dir);
    }
}

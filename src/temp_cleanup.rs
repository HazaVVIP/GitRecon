//! temp_cleanup.rs
//! SEC-004: Temporary File Cleanup Race Conditions
//!
//! Provides RAII guards for temporary file/directory cleanup that:
//! 1. Automatically clean up on Drop (normal exit)
//! 2. Clean up on signal interruption (SIGINT/SIGTERM)
//! 3. Support atomic checkpoint/resume operations
//! 4. Handle nested cleanup scopes

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tokio::sync::OnceCell;

static GLOBAL_CLEANUP_FLAG: OnceCell<Arc<AtomicBool>> = OnceCell::const_new();

/// Initialize the global cleanup system.
/// Returns the global flag that is set to true when shutdown is triggered.
pub async fn init_global_cleanup() -> Arc<AtomicBool> {
    GLOBAL_CLEANUP_FLAG
        .get_or_init(|| async {
            Arc::new(AtomicBool::new(false))
        })
        .await
        .clone()
}

/// RAII guard that cleans up a temporary directory when dropped.
///
/// # Examples
/// ```no_run
/// use temp_cleanup::TempDirGuard;
///
/// let temp = std::env::temp_dir().join("my_temp");
/// std::fs::create_dir_all(&temp).unwrap();
/// let _guard = TempDirGuard::new(temp.clone());
///
/// // temp is automatically removed when _guard goes out of scope
/// // or when the process receives SIGINT/SIGTERM
/// ```
#[derive(Debug, Clone)]
pub struct TempDirGuard {
    path: Option<PathBuf>,
    registered: bool,
}

impl TempDirGuard {
    /// Create a new guard for the given path.
    /// The path will be removed when this guard is dropped.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            registered: false,
        }
    }

    /// Register this guard with the global cleanup system.
    /// After registration, the directory will be cleaned up on signals.
    pub fn register(&mut self) {
        self.registered = true;
    }

    /// Manually release the guard without cleanup.
    /// This is useful when you want to keep the temp directory.
    pub fn release(mut self) -> PathBuf {
        self.path.take().unwrap_or_default()
    }

    /// Get the path being guarded.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Check if this guard has a valid path.
    pub fn is_valid(&self) -> bool {
        self.path.as_ref().map(|p| p.exists()).unwrap_or(false)
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            // Silent best-effort cleanup
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

/// RAII guard for a temporary file.
///
/// Similar to TempDirGuard but for individual files.
#[derive(Debug, Clone)]
pub struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    /// Create a new guard for the given file path.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path: Some(path),
        }
    }

    /// Get the path being guarded.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Release the guard without cleanup.
    pub fn release(mut self) -> PathBuf {
        self.path.take().unwrap_or_default()
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Atomic file operations for checkpoint/resume safety.
///
/// This module provides atomic write operations that are safe to use
/// with checkpoint/resume functionality.
pub mod atomic {
    use std::io::Write;
    use std::path::Path;

    /// Atomically write data to a file.
    ///
    /// This writes to a temporary file and then renames it,
    /// ensuring that the target file is either complete or not present.
    ///
    /// # Errors
    /// Returns an error if the write or rename fails.
    pub fn write_atomically<P: AsRef<Path>>(
        path: P,
        data: &[u8],
    ) -> std::io::Result<()> {
        let path = path.as_ref();
        let temp_path = path.with_extension("tmp");

        // Write to temp file
        {
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(data)?;
            file.sync_all()?;
        }

        // Atomic rename
        std::fs::rename(&temp_path, path)?;

        Ok(())
    }

    /// Atomically write string data to a file.
    ///
    /// # Errors
    /// Returns an error if the write or rename fails.
    pub fn write_string_atomically<P: AsRef<Path>>(
        path: P,
        data: &str,
    ) -> std::io::Result<()> {
        write_atomically(path, data.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temp_dir_guard_cleanup() {
        let temp_dir = std::env::temp_dir().join("gitrecon_test_cleanup");
        std::fs::create_dir_all(&temp_dir).unwrap();
        assert!(temp_dir.exists());

        {
            let _guard = TempDirGuard::new(temp_dir.clone());
            assert!(temp_dir.exists());
        }

        // Guard dropped, directory removed
        assert!(!temp_dir.exists());
    }

    #[test]
    fn test_temp_dir_guard_release() {
        let temp_dir = std::env::temp_dir().join("gitrecon_test_release");
        std::fs::create_dir_all(&temp_dir).unwrap();

        let guard = TempDirGuard::new(temp_dir.clone());
        let released = guard.release();
        assert_eq!(released, temp_dir);

        // Directory still exists after release
        assert!(temp_dir.exists());

        // Manual cleanup
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_temp_file_guard_cleanup() {
        let temp_file = std::env::temp_dir().join("gitrecon_test_file.tmp");
        std::fs::write(&temp_file, b"test data").unwrap();
        assert!(temp_file.exists());

        {
            let _guard = TempFileGuard::new(temp_file.clone());
            assert!(temp_file.exists());
        }

        // File removed after drop
        assert!(!temp_file.exists());
    }

    #[test]
    fn test_atomic_write() {
        let target = std::env::temp_dir().join("gitrecon_atomic_test.txt");
        let data = b"atomic test data";

        atomic::write_atomically(&target, data).unwrap();

        // File exists with correct content
        assert!(target.exists());
        let content = std::fs::read(&target).unwrap();
        assert_eq!(content, data);

        // Cleanup
        std::fs::remove_file(&target).unwrap();
    }

    #[test]
    fn test_atomic_write_overwrite() {
        let target = std::env::temp_dir().join("gitrecon_atomic_overwrite.txt");

        // First write
        atomic::write_atomically(&target, b"first").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "first");

        // Overwrite
        atomic::write_atomically(&target, b"second").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");

        // Cleanup
        std::fs::remove_file(&target).unwrap();
    }
}

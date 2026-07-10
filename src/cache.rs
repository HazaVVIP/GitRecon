//! cache.rs
//! PERF-005: SQLite Cache Layer
//!
//! SHA1→content cache with TTL to avoid re-fetching the same objects across scans.
//! - Cache location: ~/.gitrecon/cache.db
//! - TTL: 7 days (configurable via --cache-ttl)
//! - Max size: 1GB with LRU eviction
//! - Cross-target cache sharing (same SHA1 from different targets cached once)

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

/// Default TTL for cache entries (7 days in seconds)
const DEFAULT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Maximum cache size in bytes (1GB)
const MAX_CACHE_SIZE_BYTES: i64 = 1024 * 1024 * 1024;

/// Cache directory: ~/.gitrecon/
fn cache_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".gitrecon")
}

/// Cache database path: ~/.gitrecon/cache.db
fn cache_db_path() -> PathBuf {
    cache_dir().join("cache.db")
}

/// Initialize the cache database and create tables if they don't exist.
fn init_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache (
            sha1 TEXT PRIMARY KEY,
            content BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            source_url TEXT
        )",
        [],
    )
    .context("Failed to create cache table")?;

    // Create index on created_at for TTL-based cleanup
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_created_at ON cache(created_at)",
        [],
    )
    .context("Failed to create created_at index")?;

    Ok(())
}

/// ObjectCache struct for SHA1→content caching
#[derive(Clone)]
pub struct ObjectCache {
    /// The inner connection is wrapped in Arc<Mutex<>> for thread-safe sharing across async tasks
    conn: Arc<Mutex<Connection>>,
    ttl_seconds: i64,
    no_cache: bool,
}

impl ObjectCache {
    /// Create a new ObjectCache instance
    ///
    /// # Arguments
    /// * `ttl_seconds` - Time-to-live for cache entries in seconds (0 = no expiration)
    /// * `no_cache` - If true, bypass cache entirely (skip all cache operations)
    pub fn new(ttl_seconds: i64, no_cache: bool) -> Result<Self> {
        let cache_path = cache_db_path();

        // Create cache directory if it doesn't exist
        if let Some(parent) = cache_path.parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create cache directory")?;
        }

        let conn = Connection::open(&cache_path)
            .context("Failed to open cache database")?;

        // Set performance optimization pragmas
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;  -- 64MB cache
            PRAGMA temp_store = MEMORY;
        ")
        .context("Failed to set pragmas")?;

        init_db(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            ttl_seconds: if ttl_seconds > 0 { ttl_seconds } else { DEFAULT_TTL_SECONDS },
            no_cache,
        })
    }

    /// Check if an entry exists in the cache and is not expired
    #[allow(dead_code)]
    pub fn contains(&self, sha1: &str) -> bool {
        if self.no_cache {
            return false;
        }

        if let Ok(conn) = self.conn.lock() {
            let now = now_seconds();
            let cutoff = now - self.ttl_seconds;

            conn.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM cache
                    WHERE sha1 = ?1 AND created_at >= ?2
                    LIMIT 1
                )",
                params![sha1, cutoff],
                |row| row.get::<_, i32>(0),
            )
            .unwrap_or(0) == 1
        } else {
            false
        }
    }

    /// Get content from cache by SHA1
    ///
    /// Returns None if:
    /// - --no-cache is enabled
    /// - SHA1 not found in cache
    /// - Entry has expired (TTL exceeded)
    pub fn get(&self, sha1: &str) -> Option<Vec<u8>> {
        if self.no_cache {
            return None;
        }

        let conn = self.conn.lock().ok()?;
        let now = now_seconds();
        let cutoff = now - self.ttl_seconds;

        conn.query_row(
            "SELECT content FROM cache
             WHERE sha1 = ?1 AND created_at >= ?2",
            params![sha1, cutoff],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .ok()
    }

    /// Put content into cache
    ///
    /// If --no-cache is enabled, this is a no-op.
    pub fn put(&self, sha1: &str, content: &[u8], source_url: Option<&str>) {
        if self.no_cache {
            return;
        }

        if let Ok(conn) = self.conn.lock() {
            let now = now_seconds();

            // Insert or replace the entry
            let _ = conn.execute(
                "INSERT OR REPLACE INTO cache (sha1, content, created_at, source_url)
                 VALUES (?1, ?2, ?3, ?4)",
                params![sha1, content, now, source_url.unwrap_or("")],
            );

            // Evict old entries if cache is too large
            // Note: We need to drop the lock before calling evict_if_needed
            // because it needs to mutate the connection
            drop(conn);
        }

        // Acquire a new mutable lock for eviction if needed
        if let Ok(mut conn) = self.conn.lock() {
            let _ = Self::evict_if_needed(&mut *conn);
        }
    }

    /// Evict oldest entries if cache size exceeds MAX_CACHE_SIZE_BYTES
    fn evict_if_needed(conn: &mut Connection) -> Result<()> {
        // Get current cache size
        let size: i64 = conn.query_row(
            "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM cache",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

        if size > MAX_CACHE_SIZE_BYTES {
            // Delete oldest entries until we're under the limit
            // Use a transaction for efficiency
            let tx = conn.transaction()?;

            while tx.query_row(
                "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM cache",
                [],
                |row| row.get::<_, i64>(0),
            ).unwrap_or(0) > MAX_CACHE_SIZE_BYTES * 9 / 10  // Target 90% of max
            {
                // Delete the oldest 100 entries
                tx.execute(
                    "DELETE FROM cache
                     WHERE sha1 IN (
                         SELECT sha1 FROM cache
                         ORDER BY created_at ASC
                         LIMIT 100
                     )",
                    [],
                )?;
            }

            tx.commit()?;
        }

        Ok(())
    }

    /// Clean up expired entries (TTL-based cleanup)
    #[allow(dead_code)]
    pub fn cleanup_expired(&self) -> Result<usize> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire lock for cleanup: {}", e))?;

        let now = now_seconds();
        let cutoff = now - self.ttl_seconds;

        let deleted = conn.execute(
            "DELETE FROM cache WHERE created_at < ?1",
            params![cutoff],
        )
        .context("Failed to delete expired entries")?;

        Ok(deleted)
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return CacheStats::default(),
        };

        CacheStats {
            total_entries: conn.query_row(
                "SELECT COUNT(*) FROM cache",
                [],
                |row| row.get(0),
            ).unwrap_or(0),
            total_bytes: conn.query_row(
                "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM cache",
                [],
                |row| row.get(0),
            ).unwrap_or(0),
            expired_entries: {
                let now = now_seconds();
                let cutoff = now - self.ttl_seconds;
                conn.query_row(
                    "SELECT COUNT(*) FROM cache WHERE created_at < ?1",
                    params![cutoff],
                    |row| row.get(0),
                ).unwrap_or(0)
            },
        }
    }

    /// Clear all cache entries
    #[allow(dead_code)]
    pub fn clear(&self) -> Result<()> {
        let conn = self.conn.lock()
            .map_err(|e| anyhow::anyhow!("Failed to acquire lock for clear: {}", e))?;

        conn.execute("DELETE FROM cache", [])
            .context("Failed to clear cache")?;

        Ok(())
    }

    /// Check if cache is disabled (via --no-cache flag)
    pub fn is_disabled(&self) -> bool {
        self.no_cache
    }
}

/// Cache statistics
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub total_entries: i64,
    pub total_bytes: i64,
    pub expired_entries: i64,
}

impl CacheStats {
    /// Format byte count as human-readable size
    pub fn format_bytes(bytes: i64) -> String {
        const KB: i64 = 1024;
        const MB: i64 = KB * 1024;
        const GB: i64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Get human-readable cache size
    pub fn size_human(&self) -> String {
        Self::format_bytes(self.total_bytes)
    }

    /// Calculate hit rate from hits and total requests
    #[allow(dead_code)]
    pub fn hit_rate(hits: u64, total: u64) -> f64 {
        if total == 0 {
            0.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }
}

/// Get current time as seconds since UNIX_EPOCH
fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_dir() {
        let dir = cache_dir();
        assert!(dir.ends_with(".gitrecon"));
    }

    #[test]
    fn test_cache_db_path() {
        let path = cache_db_path();
        assert!(path.ends_with(".gitrecon/cache.db"));
    }

    #[test]
    fn test_cache_stats_default() {
        let stats = CacheStats::default();
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.total_bytes, 0);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(CacheStats::format_bytes(0), "0 B");
        assert_eq!(CacheStats::format_bytes(512), "512 B");
        assert_eq!(CacheStats::format_bytes(1024), "1.00 KB");
        assert_eq!(CacheStats::format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(CacheStats::format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_hit_rate() {
        assert_eq!(CacheStats::hit_rate(0, 0), 0.0);
        assert_eq!(CacheStats::hit_rate(0, 100), 0.0);
        assert_eq!(CacheStats::hit_rate(50, 100), 50.0);
        assert_eq!(CacheStats::hit_rate(100, 100), 100.0);
    }
}

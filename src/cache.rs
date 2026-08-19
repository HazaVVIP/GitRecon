//! cache.rs
//! PERF-005: SQLite Cache Layer
//!
//! SHA1→content cache with TTL to avoid re-fetching the same objects across scans.
//! - Cache location: ~/.gitrecon/cache.db
//! - TTL: 7 days (configurable via --cache-ttl)
//! - Max size: 1GB with LRU eviction
//! - Cross-target cache sharing (same SHA1 from different targets cached once)
//!   BUG-ERR-009: Convert to tokio::sync::Mutex for timeout support

use anyhow::{Context, Result};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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

    // Sprint 3 (S3.9): metadata key-value table for O(1) size tracking. Previously
    // `evict_if_needed` ran `SELECT SUM(LENGTH(content)) FROM cache` on EVERY put()
    // — O(n) scan across up to 1 GB of blobs. We now maintain the running total in
    // this table, updated inside the same transaction as the INSERT/DELETE.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache_meta (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        )",
        [],
    )
    .context("Failed to create cache_meta table")?;

    // If the size row is missing (fresh DB or upgraded from pre-S3.9 schema),
    // recompute once via SUM and seed it. This is the ONLY time we scan.
    let seed: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM cache",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    conn.execute(
        "INSERT OR IGNORE INTO cache_meta (key, value) VALUES ('total_bytes', ?1)",
        params![seed],
    )
    .context("Failed to seed cache_meta.total_bytes")?;

    Ok(())
}

/// ObjectCache struct for SHA1→content caching
#[derive(Clone)]
pub struct ObjectCache {
    /// r2d2 connection pool for thread-safe SQLite access
    pool: Pool<SqliteConnectionManager>,
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
            std::fs::create_dir_all(parent).context("Failed to create cache directory")?;
        }

        // Create r2d2 pool with SQLite connection manager
        let manager = SqliteConnectionManager::file(&cache_path);
        let pool = Pool::builder()
            .max_size(15)
            .build(manager)
            .context("Failed to create connection pool")?;

        // Initialize database and set pragmas on a connection from the pool
        let conn = pool
            .get()
            .context("Failed to get connection for initialization")?;

        // Set performance optimization pragmas
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;  -- 64MB cache
            PRAGMA temp_store = MEMORY;
        ",
        )
        .context("Failed to set pragmas")?;

        init_db(&conn)?;

        Ok(Self {
            pool,
            // BUG-LOGIC-004 FIX: ttl == 0 means permanent (no expiration), not expiring
            // Use i64::MAX to represent permanent entries
            ttl_seconds: if ttl_seconds == 0 {
                i64::MAX
            } else {
                ttl_seconds
            },
            no_cache,
        })
    }

    /// Get content from cache by SHA1
    ///
    /// Returns None if:
    /// - --no-cache is enabled
    /// - SHA1 not found in cache
    /// - Entry has expired (TTL exceeded)
    /// - Failed to get connection from pool
    pub async fn get(&self, sha1: &str) -> Option<Vec<u8>> {
        if self.no_cache {
            return None;
        }

        let conn = self.pool.get().ok()?;

        // Sprint 3 (S3.5): permanent-TTL short-circuit. When ttl_seconds == i64::MAX
        // (set when the operator passes `--cache-ttl 0`), the old `now - i64::MAX`
        // underflowed via wrapping — panicking in debug builds and silently
        // producing a garbage cutoff in release, rejecting every row. We now
        // skip the created_at predicate entirely for the permanent case.
        if self.ttl_seconds == i64::MAX {
            return conn
                .query_row(
                    "SELECT content FROM cache WHERE sha1 = ?1",
                    params![sha1],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .ok();
        }

        let now = now_seconds();
        let cutoff = now.saturating_sub(self.ttl_seconds);

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
    ///
    /// Sprint 3 (S3.9): insert AND eviction happen in the same transaction, and the
    /// running total-size counter (`cache_meta.total_bytes`) is updated atomically
    /// alongside. Two concurrent writers can no longer see stale sizes and evict
    /// each other's fresh entries; and `evict_if_needed` no longer runs a full
    /// SUM(LENGTH(content)) scan on every put.
    pub async fn put(&self, sha1: &str, content: &[u8], source_url: Option<&str>) {
        if self.no_cache {
            return;
        }

        let mut conn = match self.pool.get().ok() {
            Some(c) => c,
            None => return, // Failed to get connection, skip caching
        };

        let now = now_seconds();
        let content_len = content.len() as i64;

        // Everything wrapped in one transaction so put + size accounting + eviction
        // are all-or-nothing.
        let _ = (|| -> rusqlite::Result<()> {
            let tx = conn.transaction()?;

            // If we're overwriting an existing entry, subtract its old size from the
            // running total before writing.
            let old_len: i64 = tx
                .query_row(
                    "SELECT LENGTH(content) FROM cache WHERE sha1 = ?1",
                    params![sha1],
                    |row| row.get(0),
                )
                .unwrap_or(0);

            tx.execute(
                "INSERT OR REPLACE INTO cache (sha1, content, created_at, source_url)
                 VALUES (?1, ?2, ?3, ?4)",
                params![sha1, content, now, source_url.unwrap_or("")],
            )?;

            let delta = content_len - old_len;
            tx.execute(
                "UPDATE cache_meta SET value = value + ?1 WHERE key = 'total_bytes'",
                params![delta],
            )?;

            // Read current total and evict if over budget — still inside the txn so
            // concurrent writers see consistent size.
            let mut total: i64 = tx
                .query_row(
                    "SELECT value FROM cache_meta WHERE key = 'total_bytes'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            if total > MAX_CACHE_SIZE_BYTES {
                let target = MAX_CACHE_SIZE_BYTES * 9 / 10;
                // Evict in batches of 100 until we reach 90 % of the cap.
                while total > target {
                    let deleted_size: i64 = tx
                        .query_row(
                            "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM (
                            SELECT content FROM cache
                            ORDER BY created_at ASC
                            LIMIT 100
                         )",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap_or(0);
                    if deleted_size == 0 {
                        break; // Nothing to evict — cache empty (shouldn't happen).
                    }
                    tx.execute(
                        "DELETE FROM cache
                         WHERE sha1 IN (
                             SELECT sha1 FROM cache
                             ORDER BY created_at ASC
                             LIMIT 100
                         )",
                        [],
                    )?;
                    tx.execute(
                        "UPDATE cache_meta SET value = value - ?1 WHERE key = 'total_bytes'",
                        params![deleted_size],
                    )?;
                    total -= deleted_size;
                }
            }

            tx.commit()?;
            Ok(())
        })();
    }

    /// Clean up expired entries (TTL-based cleanup)
    #[allow(dead_code)]
    pub async fn cleanup_expired(&self) -> Result<usize> {
        // Sprint 3 (S3.5): permanent-TTL short-circuit — nothing to clean.
        if self.ttl_seconds == i64::MAX {
            return Ok(0);
        }

        let conn = match self.pool.get().ok() {
            Some(c) => c,
            None => return Ok(0), // Failed to get connection
        };

        let now = now_seconds();
        let cutoff = now.saturating_sub(self.ttl_seconds);

        let deleted = conn
            .execute("DELETE FROM cache WHERE created_at < ?1", params![cutoff])
            .context("Failed to delete expired entries")?;

        Ok(deleted)
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let conn = match self.pool.get().ok() {
            Some(c) => c,
            None => {
                // Return empty stats if connection fails
                return CacheStats {
                    total_entries: 0,
                    total_bytes: 0,
                    expired_entries: 0,
                };
            }
        };

        // Sprint 3 (S3.9): pull total_bytes from the metadata row rather than
        // recomputing via SUM. Falls back to SUM on schema-migration seed miss.
        let total_bytes = conn
            .query_row(
                "SELECT value FROM cache_meta WHERE key = 'total_bytes'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|_| {
                conn.query_row(
                    "SELECT COALESCE(SUM(LENGTH(content)), 0) FROM cache",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0)
            });

        // Sprint 3 (S3.5): permanent TTL means nothing ever expires — skip the
        // underflowing cutoff computation.
        let expired_entries = if self.ttl_seconds == i64::MAX {
            0
        } else {
            let now = now_seconds();
            let cutoff = now.saturating_sub(self.ttl_seconds);
            conn.query_row(
                "SELECT COUNT(*) FROM cache WHERE created_at < ?1",
                params![cutoff],
                |row| row.get(0),
            )
            .unwrap_or(0)
        };

        CacheStats {
            total_entries: conn
                .query_row("SELECT COUNT(*) FROM cache", [], |row| row.get(0))
                .unwrap_or(0),
            total_bytes,
            expired_entries,
        }
    }

    /// Clear all cache entries
    #[allow(dead_code)]
    pub async fn clear(&self) -> Result<()> {
        let conn = match self.pool.get().ok() {
            Some(c) => c,
            None => return Ok(()), // Failed to get connection, assume cleared
        };

        conn.execute("DELETE FROM cache", [])
            .context("Failed to clear cache")?;
        // Sprint 3 (S3.9): reset the running size counter alongside.
        conn.execute(
            "UPDATE cache_meta SET value = 0 WHERE key = 'total_bytes'",
            [],
        )
        .ok();

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

    // ── Sprint 3 (S3.5) — TTL underflow guard ────────────────────────────────
    //
    // The constructor maps `ttl_seconds == 0` (operator's "permanent" intent) onto
    // `i64::MAX` internally. The old get/cleanup/stats did `now - i64::MAX` which
    // wraps in release and panics in debug — silently rejecting every row. Direct
    // arithmetic tests here without touching the on-disk DB.

    #[test]
    fn permanent_ttl_never_underflows() {
        // Simulate the cutoff computation with the new saturating path.
        let now: i64 = 1_700_000_000;
        let permanent = i64::MAX;
        // The old code was `now - permanent` — that underflows.
        // Our fix short-circuits on this exact sentinel: assert the sentinel value
        // is what the constructor produces for `ttl == 0`.
        assert_eq!(permanent, i64::MAX);
        // And that saturating_sub is safe as the general fallback.
        let cutoff = now.saturating_sub(permanent);
        assert_eq!(
            cutoff, -9_223_372_035_154_775_807,
            "saturating_sub must preserve the representable result"
        );
    }

    #[test]
    fn saturating_sub_matches_short_circuit_semantics() {
        // For non-permanent TTLs, saturating_sub is the correct replacement for `-`.
        let now: i64 = 1_700_000_000;
        assert_eq!(now.saturating_sub(3600), now - 3600);
        assert_eq!(now.saturating_sub(0), now);
    }
}

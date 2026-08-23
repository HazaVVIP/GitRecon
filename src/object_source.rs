//! Raw Git object acquisition for the streaming engine.
//!
//! This module selects pack, cache, or loose HTTP sources. Parsing and scanning
//! stay in the streamer so source behavior can be tested independently.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::cache::ObjectCache;
use crate::git_parser::{obj_path, ObjectParser};
use crate::http_client::HttpClient;

const CACHE_NAMESPACE: &str = "raw-object-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ObjectSourceKind {
    Pack,
    Cache,
    LooseHttp,
}

#[derive(Debug)]
pub(crate) struct ObjectEnvelope {
    pub(crate) bytes: Vec<u8>,
    pub(crate) source: ObjectSourceKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcquisitionOutcome {
    NotFound,
    Oversized,
    HttpStatus(u16),
}

pub(crate) struct ObjectSourceConfig<'a> {
    pub(crate) client: &'a HttpClient,
    pub(crate) git_url: &'a str,
    pub(crate) pack_objects: &'a HashMap<String, Vec<u8>>,
    pub(crate) cache: Option<&'a ObjectCache>,
    pub(crate) max_blob_size: usize,
    pub(crate) save_enabled: bool,
    pub(crate) cache_hits: &'a AtomicUsize,
    pub(crate) cache_misses: &'a AtomicUsize,
}

pub(crate) struct ObjectSource<'a> {
    config: ObjectSourceConfig<'a>,
}

impl<'a> ObjectSource<'a> {
    pub(crate) fn new(config: ObjectSourceConfig<'a>) -> Self {
        Self { config }
    }

    pub(crate) async fn acquire(&self, sha1: &str) -> Result<ObjectEnvelope, AcquisitionOutcome> {
        if let Some(bytes) = self.config.pack_objects.get(sha1) {
            return Ok(ObjectEnvelope {
                bytes: bytes.clone(),
                source: ObjectSourceKind::Pack,
            });
        }

        let cache_key = format!("{CACHE_NAMESPACE}:{sha1}");
        if let Some(cache) = self.config.cache {
            if let Some(bytes) = cache.get(&cache_key).await {
                if ObjectParser.parse(&bytes, sha1).is_some() {
                    self.config.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(ObjectEnvelope {
                        bytes,
                        source: ObjectSourceKind::Cache,
                    });
                }
                // Never let a stale or corrupted cache row hide a valid remote
                // object. Remove it transactionally, then fall through to HTTP.
                let _ = cache.remove(&cache_key).await;
            }
            self.config.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        let url = format!("{}/{}", self.config.git_url, obj_path(sha1));
        let response = self.config.client.get(&url).await;
        if !response.ok() {
            if response.status == 0
                && response
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("max_size"))
            {
                return Err(AcquisitionOutcome::Oversized);
            }
            return if response.status == 404 {
                Err(AcquisitionOutcome::NotFound)
            } else {
                Err(AcquisitionOutcome::HttpStatus(response.status))
            };
        }

        if !self.config.save_enabled {
            if let Some(length) = response
                .headers
                .get("content-length")
                .and_then(|value| value.parse::<u64>().ok())
            {
                if crate::validation::validate_content_length(
                    Some(length),
                    self.config.max_blob_size,
                )
                .is_err()
                {
                    return Err(AcquisitionOutcome::Oversized);
                }
            }
        }

        let bytes = response.body.to_vec();
        if ObjectParser.parse(&bytes, sha1).is_some() {
            if let Some(cache) = self.config.cache {
                cache.put(&cache_key, &bytes, Some(&url)).await;
            }
        }

        Ok(ObjectEnvelope {
            bytes,
            source: ObjectSourceKind::LooseHttp,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use flate2::{write::ZlibEncoder, Compression};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{AcquisitionOutcome, ObjectSource, ObjectSourceConfig, ObjectSourceKind};
    use crate::cache::ObjectCache;
    use crate::git_parser::ObjectParser;
    use crate::http_client::{HttpClient, HttpConfig, RetryStrategy};

    type HttpFixture = (u16, Vec<(String, String)>, Vec<u8>);

    async fn spawn_http_without_content_length(body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let read = socket.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            for chunk in body.chunks(8) {
                socket.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        format!("http://{address}")
    }

    async fn spawn_http_sequence(responses: Vec<HttpFixture>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            for (status, headers, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2048];
                let read = socket.read(&mut request).await.unwrap();
                assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /"));
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    429 => "Too Many Requests",
                    _ => "Fixture",
                };
                let mut response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (name, value) in headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str("\r\n");
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });
        format!("http://{address}")
    }

    fn encoded_blob(content: &[u8]) -> (String, Vec<u8>) {
        let sha1 = ObjectParser.sha1_of("blob", content);
        let mut raw = format!("blob {}\x00", content.len()).into_bytes();
        raw.extend_from_slice(content);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&raw).unwrap();
        (sha1, encoder.finish().unwrap())
    }

    fn source_config<'a>(
        client: &'a HttpClient,
        git_url: &'a str,
        pack_objects: &'a HashMap<String, Vec<u8>>,
        cache: Option<&'a ObjectCache>,
        max_blob_size: usize,
        cache_hits: &'a AtomicUsize,
        cache_misses: &'a AtomicUsize,
    ) -> ObjectSource<'a> {
        ObjectSource::new(ObjectSourceConfig {
            client,
            git_url,
            pack_objects,
            cache,
            max_blob_size,
            save_enabled: false,
            cache_hits,
            cache_misses,
        })
    }

    #[tokio::test]
    async fn pack_source_wins_without_http() {
        let mut pack_objects = HashMap::new();
        pack_objects.insert("abc123".to_string(), vec![1, 2, 3]);
        let client = HttpClient::new(HttpConfig::default()).unwrap();
        let cache_hits = AtomicUsize::new(0);
        let cache_misses = AtomicUsize::new(0);
        let source = ObjectSource::new(ObjectSourceConfig {
            client: &client,
            git_url: "http://127.0.0.1:1/.git/objects",
            pack_objects: &pack_objects,
            cache: None,
            max_blob_size: 1024,
            save_enabled: false,
            cache_hits: &cache_hits,
            cache_misses: &cache_misses,
        });

        let envelope = source.acquire("abc123").await.unwrap();
        assert_eq!(envelope.bytes, vec![1, 2, 3]);
        assert_eq!(envelope.source, ObjectSourceKind::Pack);
        assert_eq!(cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(cache_misses.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn cache_source_wins_and_loose_success_is_cached() {
        let temp = tempdir().unwrap();
        let cache = ObjectCache::new_at_path(temp.path().join("cache.db"), 0, false).unwrap();
        let (cache_sha, cache_bytes) = encoded_blob(b"cached-content");
        cache
            .put(&format!("raw-object-v1:{cache_sha}"), &cache_bytes, None)
            .await;

        let client = HttpClient::new(HttpConfig::default()).unwrap();
        let pack_objects = HashMap::new();
        let cache_hits = AtomicUsize::new(0);
        let cache_misses = AtomicUsize::new(0);
        let source = source_config(
            &client,
            "http://127.0.0.1:1/.git/objects",
            &pack_objects,
            Some(&cache),
            1024,
            &cache_hits,
            &cache_misses,
        );
        let cached = source.acquire(&cache_sha).await.unwrap();
        assert_eq!(cached.source, ObjectSourceKind::Cache);
        assert_eq!(cached.bytes, cache_bytes);
        assert_eq!(cache_hits.load(Ordering::Relaxed), 1);
        assert_eq!(cache_misses.load(Ordering::Relaxed), 0);

        let (sha1, encoded) = encoded_blob(b"loose-fixture");
        let encoded_len = encoded.len();
        let base_url = spawn_http_sequence(vec![(200, vec![], encoded)]).await;
        let client = HttpClient::new(HttpConfig::default()).unwrap();
        let cache_hits = AtomicUsize::new(0);
        let cache_misses = AtomicUsize::new(0);
        let pack_objects = HashMap::new();
        let git_url = format!("{base_url}/.git/objects");
        let source = source_config(
            &client,
            &git_url,
            &pack_objects,
            Some(&cache),
            1024,
            &cache_hits,
            &cache_misses,
        );
        let fetched = source.acquire(&sha1).await.unwrap();
        assert_eq!(fetched.source, ObjectSourceKind::LooseHttp);
        assert_eq!(fetched.bytes.len(), encoded_len);
        assert_eq!(cache_misses.load(Ordering::Relaxed), 1);
        let cached_again = source_config(
            &client,
            &git_url,
            &pack_objects,
            Some(&cache),
            1024,
            &cache_hits,
            &cache_misses,
        )
        .acquire(&sha1)
        .await
        .unwrap();
        assert_eq!(cached_again.source, ObjectSourceKind::Cache);
        assert_eq!(cache_hits.load(Ordering::Relaxed), 1);
        assert_eq!(cache.stats().await.total_entries, 2);
    }

    #[tokio::test]
    async fn corrupted_cache_entry_is_quarantined_before_http_fallback() {
        let temp = tempdir().unwrap();
        let cache = ObjectCache::new_at_path(temp.path().join("cache.db"), 0, false).unwrap();
        let (sha1, valid_object) = encoded_blob(b"recovered-content");
        let cache_key = format!("raw-object-v1:{sha1}");
        cache.put(&cache_key, b"corrupted-cache-row", None).await;
        let base_url = spawn_http_sequence(vec![(200, vec![], valid_object)]).await;
        let client = HttpClient::new(HttpConfig::default()).unwrap();
        let pack_objects = HashMap::new();
        let cache_hits = AtomicUsize::new(0);
        let cache_misses = AtomicUsize::new(0);
        let git_url = format!("{base_url}/.git/objects");
        let fetched = source_config(
            &client,
            &git_url,
            &pack_objects,
            Some(&cache),
            1024,
            &cache_hits,
            &cache_misses,
        )
        .acquire(&sha1)
        .await
        .unwrap();

        assert_eq!(fetched.source, ObjectSourceKind::LooseHttp);
        assert_eq!(cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(cache_misses.load(Ordering::Relaxed), 1);
        assert_eq!(cache.stats().await.total_entries, 1);
        let recovered = cache.get(&cache_key).await.expect("recovered cache row");
        assert!(ObjectParser.parse(&recovered, &sha1).is_some());
    }

    #[tokio::test]
    async fn invalid_loose_object_is_not_admitted_to_cache() {
        let temp = tempdir().unwrap();
        let cache = ObjectCache::new_at_path(temp.path().join("cache.db"), 0, false).unwrap();
        let (sha1, _) = encoded_blob(b"expected-content");
        let base_url = spawn_http_sequence(vec![(200, vec![], b"invalid-fixture".to_vec())]).await;
        let client = HttpClient::new(HttpConfig::default()).unwrap();
        let pack_objects = HashMap::new();
        let cache_hits = AtomicUsize::new(0);
        let cache_misses = AtomicUsize::new(0);
        let git_url = format!("{base_url}/.git/objects");
        let source = source_config(
            &client,
            &git_url,
            &pack_objects,
            Some(&cache),
            1024,
            &cache_hits,
            &cache_misses,
        );
        let fetched = source.acquire(&sha1).await.unwrap();
        assert_eq!(fetched.source, ObjectSourceKind::LooseHttp);
        assert_eq!(cache.stats().await.total_entries, 0);
    }

    #[tokio::test]
    async fn http_fixture_exposes_retry_not_found_and_oversized_outcomes() {
        let (sha1, valid_object) = encoded_blob(b"retry-fixture");
        let retry_url = spawn_http_sequence(vec![
            (
                429,
                vec![("Retry-After".to_string(), "0".to_string())],
                Vec::new(),
            ),
            (200, vec![], valid_object),
        ])
        .await;
        let retry_config = HttpConfig {
            retries: 1,
            retry_strategy: RetryStrategy::Standard,
            ..HttpConfig::default()
        };
        let client = HttpClient::new(retry_config).unwrap();
        let pack_objects = HashMap::new();
        let cache_hits = AtomicUsize::new(0);
        let cache_misses = AtomicUsize::new(0);
        let retry_git_url = format!("{retry_url}/.git/objects");
        let source = source_config(
            &client,
            &retry_git_url,
            &pack_objects,
            None,
            1024,
            &cache_hits,
            &cache_misses,
        );
        assert_eq!(
            source.acquire(&sha1).await.unwrap().source,
            ObjectSourceKind::LooseHttp
        );
        assert_eq!(client.retry_metrics.retry_429.load(Ordering::Relaxed), 1);
        assert_eq!(client.retry_metrics.success.load(Ordering::Relaxed), 1);

        let not_found_url = spawn_http_sequence(vec![(404, vec![], Vec::new())]).await;
        let not_found_client = HttpClient::new(HttpConfig::default()).unwrap();
        let not_found_git_url = format!("{not_found_url}/.git/objects");
        let not_found_source = source_config(
            &not_found_client,
            &not_found_git_url,
            &pack_objects,
            None,
            1024,
            &cache_hits,
            &cache_misses,
        );
        assert!(matches!(
            not_found_source.acquire("missing-sha").await,
            Err(AcquisitionOutcome::NotFound)
        ));

        let oversized_url = spawn_http_sequence(vec![(200, vec![], vec![b'x'; 128])]).await;
        let oversized_config = HttpConfig {
            max_response_size: 16,
            ..HttpConfig::default()
        };
        let oversized_client = HttpClient::new(oversized_config).unwrap();
        let oversized_git_url = format!("{oversized_url}/.git/objects");
        let oversized_source = source_config(
            &oversized_client,
            &oversized_git_url,
            &pack_objects,
            None,
            16,
            &cache_hits,
            &cache_misses,
        );
        assert!(matches!(
            oversized_source.acquire("oversized-sha").await,
            Err(AcquisitionOutcome::Oversized)
        ));

        let streamed_url = spawn_http_without_content_length(vec![b'y'; 128]).await;
        let streamed_config = HttpConfig {
            max_response_size: 16,
            ..HttpConfig::default()
        };
        let streamed_client = HttpClient::new(streamed_config).unwrap();
        let streamed_git_url = format!("{streamed_url}/.git/objects");
        let streamed_source = source_config(
            &streamed_client,
            &streamed_git_url,
            &pack_objects,
            None,
            16,
            &cache_hits,
            &cache_misses,
        );
        assert!(matches!(
            streamed_source.acquire("streamed-oversized-sha").await,
            Err(AcquisitionOutcome::Oversized)
        ));

        let (saved_sha, saved_object) = encoded_blob(b"save-without-scan");
        let saved_url = spawn_http_sequence(vec![(200, vec![], saved_object)]).await;
        let saved_client = HttpClient::new(HttpConfig::default()).unwrap();
        let saved_git_url = format!("{saved_url}/.git/objects");
        let saved_source = ObjectSource::new(ObjectSourceConfig {
            client: &saved_client,
            git_url: &saved_git_url,
            pack_objects: &pack_objects,
            cache: None,
            max_blob_size: 1,
            save_enabled: true,
            cache_hits: &cache_hits,
            cache_misses: &cache_misses,
        });
        let saved = saved_source.acquire(&saved_sha).await.unwrap();
        assert_eq!(saved.source, ObjectSourceKind::LooseHttp);
        assert!(saved.bytes.len() > 1);
    }

    #[test]
    fn source_kinds_are_distinct() {
        assert_ne!(ObjectSourceKind::Pack, ObjectSourceKind::Cache);
        assert_ne!(
            AcquisitionOutcome::NotFound,
            AcquisitionOutcome::HttpStatus(404)
        );
    }
}

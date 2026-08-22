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
                self.config.cache_hits.fetch_add(1, Ordering::Relaxed);
                return Ok(ObjectEnvelope {
                    bytes,
                    source: ObjectSourceKind::Cache,
                });
            }
            self.config.cache_misses.fetch_add(1, Ordering::Relaxed);
        }

        let url = format!("{}/{}", self.config.git_url, obj_path(sha1));
        let response = self.config.client.get(&url).await;
        if !response.ok() {
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{AcquisitionOutcome, ObjectSource, ObjectSourceConfig, ObjectSourceKind};
    use crate::http_client::{HttpClient, HttpConfig};

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

    #[test]
    fn source_kinds_are_distinct() {
        assert_ne!(ObjectSourceKind::Pack, ObjectSourceKind::Cache);
        assert_ne!(
            AcquisitionOutcome::NotFound,
            AcquisitionOutcome::HttpStatus(404)
        );
    }
}

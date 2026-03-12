//! mapper.rs
//! Phase 2 — Mapping: collect all SHA1s that need to be scanned.
//! Only downloads metadata (HEAD, config, index, packed-refs, logs).
//! Does NOT download blobs.  Does NOT write to disk.
//! Output: MapResult with SHA1 sets + size estimates.

use std::collections::{HashMap, HashSet};
use regex::Regex;
use lazy_static::lazy_static;
use crate::http_client::HttpClient;
use crate::git_parser::{
    IndexParser, PackedRefsParser, PackIndexParser,
    GitConfigParser, parse_head, parse_info_packs, extract_sha1s, IndexEntry,
};

const META_FILES: &[&str] = &[
    "HEAD",
    "config",
    "packed-refs",
    "index",
    "logs/HEAD",
    "COMMIT_EDITMSG",
    "ORIG_HEAD",
    "FETCH_HEAD",
    "refs/heads/master",
    "refs/heads/main",
    "refs/heads/develop",
    "refs/heads/dev",
    "refs/heads/staging",
    "refs/heads/production",
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/master",
    "refs/remotes/origin/main",
    "refs/stash",
    "logs/refs/heads/master",
    "logs/refs/heads/main",
    "logs/refs/heads/develop",
    "logs/refs/remotes/origin/HEAD",
    "objects/info/packs",
    "refs/wip/index/refs/heads/master",
    "refs/wip/wtree/refs/heads/master",
];

const SIZE_PER_BLOB: usize = 4 * 1024; // ~4 KB average

#[derive(Debug, Default)]
pub struct MapResult {
    pub commit_sha1s: HashSet<String>,
    pub tree_sha1s:   HashSet<String>,
    pub blob_sha1s:   HashSet<String>,
    pub pack_sha1s:   Vec<String>,
    pub meta:         HashMap<String, Vec<u8>>,
    pub branches:     Vec<String>,
    pub remote_urls:  Vec<HashMap<String, String>>,
    pub index_entries: Vec<IndexEntry>,
    pub estimated_files: usize,
    pub estimated_bytes: usize,
}

impl MapResult {
    pub fn all_sha1s(&self) -> HashSet<String> {
        self.commit_sha1s
            .iter()
            .chain(self.tree_sha1s.iter())
            .chain(self.blob_sha1s.iter())
            .cloned()
            .collect()
    }

    pub fn size_human(&self) -> String {
        let b = self.estimated_bytes;
        if b < 1024 {
            format!("{b} B")
        } else if b < 1024 * 1024 {
            format!("{:.1} KB", b as f64 / 1024.0)
        } else if b < 1024 * 1024 * 1024 {
            format!("{:.1} MB", b as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", b as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }
}

lazy_static! {
    static ref SHA40_RE: Regex = Regex::new(r"^[0-9a-f]{40}$").unwrap();
}

pub struct Mapper {
    client: HttpClient,
}

impl Mapper {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn run(&self, git_url: &str, branch: Option<&str>) -> MapResult {
        let git_url = git_url.trim_end_matches('/');
        let mut result = MapResult::default();
        let mut meta: HashMap<String, Vec<u8>> = HashMap::new();

        // 1. Fetch all metadata files concurrently
        let mut fetch_tasks = Vec::new();
        for &path in META_FILES {
            let url = format!("{}/{}", git_url, path);
            fetch_tasks.push((path.to_string(), url));
        }

        // Add branch-specific paths
        if let Some(br) = branch {
            for ref_path in &[
                format!("refs/heads/{}", br),
                format!("logs/refs/heads/{}", br),
            ] {
                if !META_FILES.contains(&ref_path.as_str()) {
                    fetch_tasks.push((ref_path.clone(), format!("{}/{}", git_url, ref_path)));
                }
            }
        }

        // Fetch all metadata concurrently using tokio tasks
        let fetch_results = {
            let mut handles = Vec::new();
            for (path, url) in fetch_tasks {
                let client = self.client.clone();
                handles.push(tokio::spawn(async move {
                    let r = client.get(&url).await;
                    if r.ok() && !r.body.is_empty() {
                        Some((path, r.body.to_vec()))
                    } else {
                        None
                    }
                }));
            }
            let mut results = Vec::new();
            for h in handles {
                if let Ok(Some(pair)) = h.await {
                    results.push(pair);
                }
            }
            results
        };

        for (path, body) in fetch_results {
            meta.insert(path, body);
        }

        result.meta = meta.clone();
        let mut sha1s: HashSet<String> = HashSet::new();

        // 2. Parse HEAD
        if let Some(raw) = meta.get("HEAD") {
            let text = String::from_utf8_lossy(raw);
            let head = parse_head(&text);
            match head.get("type").map(|s| s.as_str()) {
                Some("detached") => {
                    if let Some(s) = head.get("sha1") {
                        sha1s.insert(s.clone());
                    }
                }
                Some("ref") => {
                    if let Some(ref_path) = head.get("ref") {
                        let r = self.client.get(&format!("{}/{}", git_url, ref_path)).await;
                        if r.ok() {
                            meta.insert(ref_path.clone(), r.body.to_vec());
                        }
                        if let Some(body) = meta.get(ref_path) {
                            let s = String::from_utf8_lossy(body).trim().to_string();
                            if SHA40_RE.is_match(&s) {
                                sha1s.insert(s);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // 3. Parse config
        if let Some(raw) = meta.get("config") {
            let text = String::from_utf8_lossy(raw);
            let cfg_parser = GitConfigParser;
            let cfg = cfg_parser.parse(&text);
            result.remote_urls = cfg_parser.remote_urls(&cfg);
            result.branches = cfg_parser.branches(&cfg);

            // Fetch refs for each branch
            let branch_paths: Vec<(String, String)> = result.branches
                .iter()
                .take(15)
                .flat_map(|br| {
                    vec![
                        format!("refs/heads/{}", br),
                        format!("logs/refs/heads/{}", br),
                    ]
                })
                .filter(|p| !meta.contains_key(p))
                .map(|p| (p.clone(), format!("{}/{}", git_url, p)))
                .collect();

            for (p, url) in branch_paths {
                let r = self.client.get(&url).await;
                if r.ok() && !r.body.is_empty() {
                    meta.insert(p, r.body.to_vec());
                }
            }
        }

        // 4. Parse packed-refs
        if let Some(raw) = meta.get("packed-refs") {
            let text = String::from_utf8_lossy(raw);
            let parser = PackedRefsParser;
            let refs = parser.parse(&text);
            sha1s.extend(parser.sha1s(&refs));
            for r in &refs {
                if r.ref_name.contains("heads") {
                    let br = r.ref_name.rsplit('/').next().unwrap_or("").to_string();
                    if !result.branches.contains(&br) {
                        result.branches.push(br);
                    }
                }
            }
        }

        // 5. Parse index (DIRC)
        if let Some(raw) = meta.get("index") {
            let parser = IndexParser;
            if let Ok(entries) = parser.parse(raw) {
                for e in &entries {
                    sha1s.insert(e.sha1.clone());
                    result.blob_sha1s.insert(e.sha1.clone());
                }
                result.index_entries = entries;
            }
        }

        // 6. Extract SHA1s from log files
        for (path, body) in &meta {
            if path.starts_with("logs/") {
                let text = String::from_utf8_lossy(body);
                sha1s.extend(extract_sha1s(&text));
            }
        }

        // 7. Extract SHA1s from ref files
        for (path, body) in &meta {
            if path.starts_with("refs/") {
                let text = String::from_utf8_lossy(body).trim().to_string();
                if SHA40_RE.is_match(&text) {
                    sha1s.insert(text);
                }
            }
        }

        // 8. Pack discovery via objects/info/packs
        if let Some(raw) = meta.get("objects/info/packs") {
            let text = String::from_utf8_lossy(raw);
            let packs = parse_info_packs(&text);
            result.pack_sha1s = packs.clone();

            for pack_sha1 in &packs {
                let idx_path = format!("objects/pack/pack-{}.idx", pack_sha1);
                let r = self.client.get(&format!("{}/{}", git_url, idx_path)).await;
                if r.ok() && !r.body.is_empty() {
                    let parser = PackIndexParser;
                    let pack_sha1s = parser.parse(&r.body);
                    sha1s.extend(pack_sha1s);
                }
            }
        }

        // 9. Classify SHA1s
        result.commit_sha1s = sha1s.difference(&result.blob_sha1s).cloned().collect();

        // 10. Size estimation
        result.estimated_files = if !result.index_entries.is_empty() {
            result.index_entries.len()
        } else {
            result.blob_sha1s.len()
        };
        result.estimated_bytes = if !result.index_entries.is_empty() {
            result.index_entries.iter().map(|e| e.file_size as usize).sum()
        } else {
            result.estimated_files * SIZE_PER_BLOB
        };

        result
    }
}

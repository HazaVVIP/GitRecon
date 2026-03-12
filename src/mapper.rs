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
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "refs/heads/master",
    "refs/heads/main",
    "refs/heads/develop",
    "refs/heads/dev",
    "refs/heads/staging",
    "refs/heads/production",
    "refs/heads/release",
    "refs/heads/hotfix",
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/master",
    "refs/remotes/origin/main",
    "refs/remotes/origin/develop",
    "refs/stash",
    "logs/refs/heads/master",
    "logs/refs/heads/main",
    "logs/refs/heads/develop",
    "logs/refs/remotes/origin/HEAD",
    "objects/info/packs",
    "info/refs",
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

            // Fetch refs for each branch — all concurrently
            let branch_paths: Vec<(String, String)> = result.branches
                .iter()
                .take(20)
                .flat_map(|br| {
                    vec![
                        format!("refs/heads/{}", br),
                        format!("logs/refs/heads/{}", br),
                    ]
                })
                .filter(|p| !meta.contains_key(p))
                .map(|p| (p.clone(), format!("{}/{}", git_url, p)))
                .collect();

            let mut branch_handles = Vec::new();
            for (p, url) in branch_paths {
                let client = self.client.clone();
                branch_handles.push(tokio::spawn(async move {
                    let r = client.get(&url).await;
                    if r.ok() && !r.body.is_empty() {
                        Some((p, r.body.to_vec()))
                    } else {
                        None
                    }
                }));
            }
            for h in branch_handles {
                if let Ok(Some((p, body))) = h.await {
                    meta.insert(p, body);
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

        // 7. Extract SHA1s from ref files and info/refs
        for (path, body) in &meta {
            if path.starts_with("refs/") {
                let text = String::from_utf8_lossy(body).trim().to_string();
                if SHA40_RE.is_match(&text) {
                    sha1s.insert(text);
                }
            } else if path == "info/refs" {
                // info/refs lists all refs as "<sha1>\t<refname>"
                let text = String::from_utf8_lossy(body);
                sha1s.extend(extract_sha1s(&text));
            }
        }

        // 8. Pack discovery via objects/info/packs
        if let Some(raw) = meta.get("objects/info/packs") {
            let text = String::from_utf8_lossy(raw);
            let packs = parse_info_packs(&text);
            result.pack_sha1s = packs.clone();

            // Fetch all pack indexes concurrently
            let mut pack_handles = Vec::new();
            for pack_sha1 in &packs {
                let client = self.client.clone();
                let idx_url = format!("{}/objects/pack/pack-{}.idx", git_url, pack_sha1);
                pack_handles.push(tokio::spawn(async move {
                    let r = client.get(&idx_url).await;
                    if r.ok() && !r.body.is_empty() {
                        Some(r.body.to_vec())
                    } else {
                        None
                    }
                }));
            }
            for h in pack_handles {
                if let Ok(Some(body)) = h.await {
                    let parser = PackIndexParser;
                    sha1s.extend(parser.parse(&body));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_result_all_sha1s_union() {
        let mut r = MapResult::default();
        r.blob_sha1s.insert("blob1111blob1111blob1111blob1111blob1111b".to_string());
        r.commit_sha1s.insert("comm1111comm1111comm1111comm1111comm1111c".to_string());
        let all = r.all_sha1s();
        assert_eq!(all.len(), 2);
        assert!(all.contains("blob1111blob1111blob1111blob1111blob1111b"));
        assert!(all.contains("comm1111comm1111comm1111comm1111comm1111c"));
    }

    #[test]
    fn test_map_result_size_human() {
        let mut r = MapResult::default();
        r.estimated_bytes = 500;
        assert!(r.size_human().ends_with("B"));

        r.estimated_bytes = 2048;
        assert!(r.size_human().contains("KB"));

        r.estimated_bytes = 2 * 1024 * 1024;
        assert!(r.size_human().contains("MB"));
    }

    #[test]
    fn test_meta_files_contains_info_refs() {
        assert!(META_FILES.contains(&"info/refs"));
    }

    #[test]
    fn test_meta_files_contains_merge_head() {
        assert!(META_FILES.contains(&"MERGE_HEAD"));
    }
}

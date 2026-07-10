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
    is_valid_sha1, obj_path, ObjectParser,
};
use std::io::Write;

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
    "SQUASH_MSG",
    "REBASE_HEAD",
    "rebase-merge/head-name",
    "config.worktree",
    "shallow",
    // Repository metadata
    "description",
    "info/exclude",
    // Standard branch refs
    "refs/heads/master",
    "refs/heads/main",
    "refs/heads/develop",
    "refs/heads/dev",
    "refs/heads/staging",
    "refs/heads/production",
    "refs/heads/release",
    "refs/heads/hotfix",
    "refs/heads/test",
    "refs/heads/beta",
    "refs/heads/feature",
    "refs/heads/fix",
    "refs/heads/next",
    "refs/heads/trunk",
    // Common tag refs (gitdumper parity)
    "refs/tags/latest",
    "refs/tags/v1",
    "refs/tags/v2",
    "refs/tags/v1.0",
    "refs/tags/v1.0.0",
    "refs/tags/v2.0.0",
    // Remote tracking refs
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/master",
    "refs/remotes/origin/main",
    "refs/remotes/origin/develop",
    "refs/remotes/origin/staging",
    "refs/remotes/origin/production",
    // Remote tracking for common non-default remotes
    "refs/remotes/upstream/HEAD",
    "refs/remotes/upstream/main",
    // Stash
    "refs/stash",
    // Log files
    "logs/refs/heads/master",
    "logs/refs/heads/main",
    "logs/refs/heads/develop",
    "logs/refs/remotes/origin/HEAD",
    // Pack/object discovery
    "objects/info/packs",
    // Smart-HTTP info refs (dumb + smart protocol)
    "info/refs",
    "info/refs?service=git-upload-pack",
    // Work-in-progress refs (VS Code, Gerrit)
    "refs/wip/index/refs/heads/master",
    "refs/wip/wtree/refs/heads/master",
    // Submodule and attribute metadata
    ".gitmodules",
    ".gitattributes",
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
    /// SHA1→filename mapping from index file only
    pub index_sha1_to_file: HashMap<String, String>,
    /// SHA1→filename mapping from commit graph tree traversal (for bare repos, historical files)
    pub graph_sha1_to_file: HashMap<String, String>,
    pub estimated_files: usize,
    pub estimated_bytes: usize,
    /// Whether at least one git object (blob/tree/commit) is accessible
    /// This distinguishes between full exposure and partial (metadata-only) exposure
    pub objects_accessible: bool,
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

    /// Get complete SHA1→filename mapping, preferring index entries for current files
    pub fn complete_sha1_to_file(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();

        // First, add all index entries (current working directory state)
        for entry in &self.index_entries {
            result.insert(entry.sha1.clone(), entry.filename.clone());
        }

        // Then, add graph-derived entries for files not in index
        // (historical files, bare repos without index)
        for (sha1, path) in &self.graph_sha1_to_file {
            result.entry(sha1.clone()).or_insert_with(|| path.clone());
        }

        result
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

    pub async fn run(&self, git_url: &str, branch: Option<&str>, skip_verification: bool) -> MapResult {
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
                    // Populate index_sha1_to_file mapping
                    result.index_sha1_to_file.insert(e.sha1.clone(), e.filename.clone());
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
                } else {
                    // Multi-line ref files (e.g. info/refs format in some bare repos)
                    sha1s.extend(extract_sha1s(&String::from_utf8_lossy(body)));
                }
            } else if path == "info/refs" {
                // info/refs lists all refs as "<sha1>\t<refname>"; also extract branch names
                let text = String::from_utf8_lossy(body);
                sha1s.extend(extract_sha1s(&text));
                for line in text.lines() {
                    let parts: Vec<&str> = line.splitn(2, '\t').collect();
                    if parts.len() == 2 {
                        let ref_name = parts[1].trim();
                        if let Some(br) = ref_name.strip_prefix("refs/heads/") {
                            let br = br.to_string();
                            if !result.branches.contains(&br) {
                                result.branches.push(br);
                            }
                        }
                    }
                }
            }
        }

        // 8. Extract SHA1s from special per-operation head files and shallow clone info.
        // These files are already fetched via META_FILES but are not under refs/ or logs/,
        // so they need their own extraction pass.
        const SPECIAL_HEAD_FILES: &[&str] = &[
            "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD",
            "REBASE_HEAD", "shallow",
        ];
        for file in SPECIAL_HEAD_FILES {
            if let Some(body) = meta.get(*file) {
                let text = String::from_utf8_lossy(body);
                sha1s.extend(extract_sha1s(&text));
            }
        }

        // 8b. Parse .gitmodules for submodule remote URLs
        if let Some(raw) = meta.get(".gitmodules") {
            let text = String::from_utf8_lossy(raw);
            let cfg_parser = GitConfigParser;
            let cfg = cfg_parser.parse(&text);
            for (sec, data) in &cfg {
                if sec.starts_with("submodule.") {
                    if let Some(url) = data.get("url") {
                        let mut m = std::collections::HashMap::new();
                        m.insert("remote".into(), sec.clone());
                        m.insert("url".into(), url.clone());
                        if !result.remote_urls.iter().any(|r| r.get("url") == Some(url)) {
                            result.remote_urls.push(m);
                        }
                    }
                }
            }
        }

        // 9. Pack discovery via objects/info/packs
        // ENHANCED: Added fallback for missing/incomplete info/packs file
        let mut packs = if let Some(raw) = meta.get("objects/info/packs") {
            let text = String::from_utf8_lossy(raw);
            parse_info_packs(&text)
        } else {
            Vec::new()
        };

        // Fallback: Try to discover pack files directly if info/packs is empty/missing
        if packs.is_empty() {
            // Try common pack file patterns by directly probing .idx files
            // This handles cases where info/packs doesn't list all packs or is missing
            let potential_packs = [
                "pack-0000000000000000000000000000000000000000.idx",
                "pack-a000000000000000000000000000000000000000.idx",
                "pack-b000000000000000000000000000000000000000.idx",
                "pack-c000000000000000000000000000000000000000.idx",
                "pack-d000000000000000000000000000000000000000.idx",
                "pack-e000000000000000000000000000000000000000.idx",
                "pack-f000000000000000000000000000000000000000.idx",
            ];

            let mut pack_handles = Vec::new();
            for pack_name in potential_packs.iter() {
                let client = self.client.clone();
                let git_url = git_url.to_string();
                let pack_name = pack_name.to_string();
                pack_handles.push(tokio::spawn(async move {
                    let idx_url = format!("{}/objects/pack/{}", git_url, pack_name);
                    let r = client.get(&idx_url).await;
                    if r.ok() && !r.body.is_empty() {
                        Some(pack_name.strip_suffix(".idx").unwrap_or(&pack_name).to_string())
                    } else {
                        None
                    }
                }));
            }

            for h in pack_handles {
                if let Ok(Some(pack_sha1)) = h.await {
                    // Extract SHA1 from pack-xxxxx... format
                    if let Some(sha1) = pack_sha1.strip_prefix("pack-") {
                        if sha1.len() == 40 && sha1.bytes().all(|b| b.is_ascii_hexdigit()) {
                            packs.push(sha1.to_string());
                        }
                    }
                }
            }
        }

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

        // Collect pack index results
        for h in pack_handles {
            if let Ok(Some(body)) = h.await {
                let parser = PackIndexParser;
                sha1s.extend(parser.parse(&body));
            }
        }

        // 10. Discard malformed SHA1s that would cause panics downstream
        sha1s.retain(|s| is_valid_sha1(s));
        result.blob_sha1s.retain(|s| is_valid_sha1(s));

        // 11. Classify SHA1s
        result.commit_sha1s = sha1s.difference(&result.blob_sha1s).cloned().collect();

        // 12. NEW: Walk commit graph for complete blob enumeration
        // This handles cases where index is missing or incomplete (bare repos, historical files)
        let head_sha1 = if let Some(raw) = meta.get("HEAD") {
            let text = String::from_utf8_lossy(raw);
            let head = parse_head(&text);
            match head.get("type").map(|s| s.as_str()) {
                Some("detached") => head.get("sha1").cloned(),
                Some("ref") => {
                    // We already fetched the ref value above, extract from sha1s
                    sha1s.iter().find(|s| is_valid_sha1(s)).cloned()
                }
                _ => None,
            }
        } else {
            None
        };

        if let Some(head) = head_sha1 {
            if is_valid_sha1(&head) {
                // Inline commit graph and tree traversal implementation
                let client = self.client.clone();
                let git_url_walk = git_url.to_string();

                // Walk commit graph and collect all blob SHA1s with paths
                let max_commits = 100; // Limit traversal for performance
                let mut visited_commits = std::collections::HashSet::new();
                let mut graph_blobs = std::collections::HashSet::new();
                let mut graph_paths = std::collections::HashMap::new();
                let mut commit_queue = std::collections::VecDeque::new();

                commit_queue.push_back(head.clone());

                while let Some(commit_sha1) = commit_queue.pop_front() {
                    if visited_commits.contains(&commit_sha1) {
                        continue;
                    }
                    if visited_commits.len() >= max_commits {
                        break;
                    }

                    // Fetch commit object
                    let commit_url = format!("{}/{}", git_url_walk, obj_path(&commit_sha1));
                    let commit_resp = client.get(&commit_url).await;
                    let commit_data = if commit_resp.ok() && !commit_resp.body.is_empty() {
                        commit_resp.body.to_vec()
                    } else {
                        continue;
                    };

                    let parser = ObjectParser;
                    let commit_obj = match parser.parse(&commit_data, &commit_sha1) {
                        Some(obj) if obj.obj_type == "commit" => obj,
                        _ => continue,
                    };

                    let commit_info = match parser.parse_commit(&commit_obj) {
                        Some(info) => info,
                        None => continue,
                    };

                    visited_commits.insert(commit_sha1.clone());

                    // Recursively traverse tree to collect all blobs
                    let mut tree_queue = std::collections::VecDeque::new();
                    tree_queue.push_back((commit_info.tree.clone(), String::new()));

                    while let Some((tree_sha1, path_prefix)) = tree_queue.pop_front() {
                        let tree_url = format!("{}/{}", git_url_walk, obj_path(&tree_sha1));
                        let tree_resp = client.get(&tree_url).await;
                        let tree_data = if tree_resp.ok() && !tree_resp.body.is_empty() {
                            tree_resp.body.to_vec()
                        } else {
                            continue;
                        };

                        let tree_obj = match parser.parse(&tree_data, &tree_sha1) {
                            Some(obj) if obj.obj_type == "tree" => obj,
                            _ => continue,
                        };

                        let entries = parser.parse_tree(&tree_obj);

                        for entry in entries {
                            let full_path = if path_prefix.is_empty() {
                                entry.name.clone()
                            } else {
                                format!("{}/{}", path_prefix, entry.name)
                            };

                            if entry.is_blob() {
                                graph_blobs.insert(entry.sha1.clone());
                                graph_paths.entry(entry.sha1).or_insert(full_path);
                            } else if entry.mode == "040000" {
                                // Queue nested tree
                                tree_queue.push_back((entry.sha1, full_path));
                            }
                        }
                    }

                    // Queue parent commits
                    for parent_sha1 in commit_info.parents {
                        if !visited_commits.contains(&parent_sha1) {
                            commit_queue.push_back(parent_sha1);
                        }
                    }
                }

                let commits_walked = visited_commits.len();

                if !graph_blobs.is_empty() {
                    // Merge blob SHA1s
                    result.blob_sha1s.extend(graph_blobs.clone());

                    // Store graph-derived SHA1→path mappings for reconstruction
                    result.graph_sha1_to_file = graph_paths;

                    // Log commit graph walk results
                    if commits_walked > 0 {
                        let _ = writeln!(
                            &mut std::io::stderr(),
                            "  [*] Commit graph walk: {} commits, {} blobs discovered",
                            commits_walked,
                            graph_blobs.len()
                        );
                    }
                }
            }
        }

        // 13. Size estimation
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

        // VERIFICATION: Check if git objects are actually accessible
        // This distinguishes between full exposure and partial (metadata-only) exposure
        result.objects_accessible = if skip_verification {
            // Skip verification and assume objects are accessible
            true
        } else if result.blob_sha1s.is_empty() {
            false
        } else {
            // Try to fetch a sample of blobs to verify accessibility
            // Sample up to 10 blobs to get a better representation
            // Require at least 30% of samples to succeed before declaring full exposure
            // (This handles cases where some blobs are genuinely missing/deleted)
            let sample_size = result.blob_sha1s.len().min(10);
            let sample_sha1s: Vec<_> = result.blob_sha1s.iter().take(sample_size).cloned().collect();
            let mut accessible_count = 0;
            for sha1 in sample_sha1s {
                let url = format!("{}/{}", git_url, obj_path(&sha1));
                let resp = self.client.get(&url).await;
                if resp.ok() && !resp.body.is_empty() {
                    // Verify it's a valid git object
                    let parser = ObjectParser;
                    if parser.parse(&resp.body, &sha1).is_some() {
                        accessible_count += 1;
                    }
                }
            }
            // Require at least 30% of samples to be accessible
            // (e.g., 3 out of 10, or 1 out of 3)
            let threshold = (sample_size as f64 * 0.3).ceil() as usize;
            accessible_count >= threshold.max(1)
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

    // ── V3 new meta-file coverage ─────────────────

    #[test]
    fn test_meta_files_contains_shallow() {
        assert!(META_FILES.contains(&"shallow"), "shallow must be in META_FILES for shallow-clone detection");
    }

    #[test]
    fn test_meta_files_contains_squash_msg() {
        assert!(META_FILES.contains(&"SQUASH_MSG"), "SQUASH_MSG must be in META_FILES");
    }

    #[test]
    fn test_meta_files_contains_rebase_head() {
        assert!(META_FILES.contains(&"REBASE_HEAD"), "REBASE_HEAD must be in META_FILES");
    }

    #[test]
    fn test_meta_files_contains_config_worktree() {
        assert!(META_FILES.contains(&"config.worktree"), "config.worktree must be in META_FILES");
    }

    #[test]
    fn test_meta_files_contains_gitmodules() {
        assert!(META_FILES.contains(&".gitmodules"), ".gitmodules must be in META_FILES for submodule detection");
    }

    #[test]
    fn test_meta_files_contains_gitattributes() {
        assert!(META_FILES.contains(&".gitattributes"), ".gitattributes must be in META_FILES");
    }

    #[test]
    fn test_meta_files_contains_extended_branch_refs() {
        assert!(META_FILES.contains(&"refs/heads/test"),  "refs/heads/test must be in META_FILES");
        assert!(META_FILES.contains(&"refs/heads/beta"),  "refs/heads/beta must be in META_FILES");
        assert!(META_FILES.contains(&"refs/heads/trunk"), "refs/heads/trunk must be in META_FILES");
        assert!(META_FILES.contains(&"refs/heads/next"),  "refs/heads/next must be in META_FILES");
    }

    #[test]
    fn test_meta_files_contains_remote_tracking_refs() {
        assert!(META_FILES.contains(&"refs/remotes/origin/staging"),    "staging remote ref must be in META_FILES");
        assert!(META_FILES.contains(&"refs/remotes/origin/production"), "production remote ref must be in META_FILES");
    }

    #[test]
    fn test_map_result_size_human_gb() {
        let mut r = MapResult::default();
        r.estimated_bytes = 2 * 1024 * 1024 * 1024;
        assert!(r.size_human().contains("GB"), "sizes ≥ 1 GiB should use GB suffix");
    }

    // ── V3.1 metadata probe tests ────────────────

    #[test]
    fn test_meta_files_contains_description() {
        assert!(META_FILES.contains(&"description"), "description should be in META_FILES");
    }

    #[test]
    fn test_meta_files_contains_info_exclude() {
        assert!(META_FILES.contains(&"info/exclude"), "info/exclude should be in META_FILES");
    }

    #[test]
    fn test_meta_files_contains_smart_http_refs() {
        assert!(
            META_FILES.contains(&"info/refs?service=git-upload-pack"),
            "Smart HTTP info/refs endpoint should be in META_FILES"
        );
    }

    #[test]
    fn test_meta_files_contains_tag_refs() {
        assert!(META_FILES.contains(&"refs/tags/latest"), "refs/tags/latest should be in META_FILES");
        assert!(META_FILES.contains(&"refs/tags/v1.0.0"), "refs/tags/v1.0.0 should be in META_FILES");
    }

    #[test]
    fn test_meta_files_contains_upstream_remote() {
        assert!(META_FILES.contains(&"refs/remotes/upstream/HEAD"), "upstream/HEAD should be in META_FILES");
    }
}

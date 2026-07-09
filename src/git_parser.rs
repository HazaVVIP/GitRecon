//! git_parser.rs
//! Pure Rust parsers for all Git binary formats:
//! Index (DIRC), loose objects, pack index (.idx), packed-refs, logs, config, HEAD.

use std::collections::HashMap;
use flate2::read::ZlibDecoder;
use std::io::Read;
use regex::Regex;
use lazy_static::lazy_static;
use sha1::{Sha1, Digest};

// ════════════════════════════════════════════════
// DATA TYPES
// ════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub sha1: String,
    pub filename: String,
    #[allow(dead_code)]
    pub mode: u32,
    #[allow(dead_code)]
    pub file_size: u32,
}

#[derive(Debug, Clone)]
pub struct GitObject {
    pub sha1: String,
    pub obj_type: String,
    #[allow(dead_code)]
    pub size: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    #[allow(dead_code)]
    pub sha1: String,
    #[allow(dead_code)]
    pub tree: String,
    #[allow(dead_code)]
    pub parents: Vec<String>,
    pub author: String,
    pub author_email: String,
    #[allow(dead_code)]
    pub author_ts: i64,
    #[allow(dead_code)]
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub mode: String,
    pub name: String,
    pub sha1: String,
}

impl TreeEntry {
    pub fn is_blob(&self) -> bool {
        self.mode == "100644" || self.mode == "100755"
    }

    #[allow(dead_code)]
    pub fn is_tree(&self) -> bool {
        self.mode == "040000"
    }
}

#[derive(Debug, Clone)]
pub struct RefEntry {
    pub sha1: String,
    pub ref_name: String,
    pub peeled: Option<String>,
}

// ════════════════════════════════════════════════
// INDEX PARSER  (.git/index — DIRC binary)
// ════════════════════════════════════════════════

pub struct IndexParser;

impl IndexParser {
    const MAGIC: &'static [u8; 4] = b"DIRC";

    pub fn parse(&self, data: &[u8]) -> Result<Vec<IndexEntry>, String> {
        if data.len() < 12 || &data[..4] != Self::MAGIC {
            return Err("Not a valid git index file".into());
        }

        let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let n = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;

        if !matches!(version, 2..=4) {
            return Err(format!("Unsupported index version: {version}"));
        }

        let mut entries = Vec::new();
        let mut offset = 12usize;

        for _ in 0..n {
            if offset + 62 > data.len() {
                break;
            }
            match Self::parse_entry(data, offset, version) {
                Some((entry, next)) => {
                    entries.push(entry);
                    offset = next;
                }
                None => break,
            }
        }

        Ok(entries)
    }

    fn parse_entry(data: &[u8], offset: usize, version: u32) -> Option<(IndexEntry, usize)> {
        let base = offset;
        if offset + 62 > data.len() {
            return None;
        }

        let mode = u32::from_be_bytes(data[offset + 24..offset + 28].try_into().ok()?);
        let size = u32::from_be_bytes(data[offset + 36..offset + 40].try_into().ok()?);
        let sha1 = hex::encode(&data[offset + 40..offset + 60]);
        let flags = u16::from_be_bytes(data[offset + 60..offset + 62].try_into().ok()?);
        let extended = (flags >> 14) & 1 == 1;
        let name_len = (flags & 0x0FFF) as usize;
        let extra = if version >= 3 && extended { 2 } else { 0 };
        let name_start = offset + 62 + extra;

        let (raw_name, end) = if name_len < 0xFFF {
            if name_start + name_len > data.len() {
                return None;
            }
            (&data[name_start..name_start + name_len], name_start + name_len + 1)
        } else {
            let nul = data[name_start..].iter().position(|&b| b == 0)?;
            (&data[name_start..name_start + nul], name_start + nul + 1)
        };

        let padded = base + (((end - base) + 7) & !7);

        let filename = String::from_utf8_lossy(raw_name).into_owned();

        // Security: reject path traversal
        if filename.contains("..") || filename.starts_with('/') {
            return Some((
                IndexEntry { sha1: String::new(), filename: String::new(), mode: 0, file_size: 0 },
                padded,
            ));
        }

        Some((IndexEntry { sha1, filename, mode, file_size: size }, padded))
    }
}

// ════════════════════════════════════════════════
// OBJECT PARSER  (loose objects, zlib-compressed)
// ════════════════════════════════════════════════

lazy_static! {
    static ref ID_RE: Regex = Regex::new(r"<([^>]+)>").unwrap();
    static ref TS_RE: Regex = Regex::new(r">\s+(\d+)").unwrap();
}

pub struct ObjectParser;

const VALID_TYPES: &[&str] = &["blob", "tree", "commit", "tag"];

impl ObjectParser {
    pub fn parse(&self, data: &[u8], sha1: &str) -> Option<GitObject> {
        let mut decoder = ZlibDecoder::new(data);
        let mut raw = Vec::new();
        decoder.read_to_end(&mut raw).ok()?;

        let nul = raw.iter().position(|&b| b == 0)?;
        let header = std::str::from_utf8(&raw[..nul]).ok()?;
        let (obj_type, size_str) = header.split_once(' ')?;

        if !VALID_TYPES.contains(&obj_type) {
            return None;
        }

        let size: usize = size_str.parse().ok()?;
        let obj_data = raw[nul + 1..].to_vec();

        Some(GitObject {
            sha1: sha1.to_string(),
            obj_type: obj_type.to_string(),
            size,
            data: obj_data,
        })
    }

    pub fn parse_commit(&self, obj: &GitObject) -> Option<CommitInfo> {
        if obj.obj_type != "commit" {
            return None;
        }
        let text = String::from_utf8_lossy(&obj.data).into_owned();

        let mut tree = String::new();
        let mut parents = Vec::new();
        let mut author = String::new();
        let mut author_email = String::new();
        let mut author_ts = 0i64;
        let mut msg_lines = Vec::new();
        let mut in_msg = false;

        for line in text.lines() {
            if in_msg {
                msg_lines.push(line);
                continue;
            }
            if line.is_empty() {
                in_msg = true;
                continue;
            }
            if let Some(rest) = line.strip_prefix("tree ") {
                tree = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("parent ") {
                parents.push(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("author ") {
                if let Some(cap) = ID_RE.captures(rest) {
                    author_email = cap[1].to_string();
                }
                if let Some(cap) = TS_RE.captures(rest) {
                    author_ts = cap[1].parse().unwrap_or(0);
                }
                author = rest.split('<').next().unwrap_or("").trim().to_string();
            }
        }

        Some(CommitInfo {
            sha1: obj.sha1.clone(),
            tree,
            parents,
            author,
            author_email,
            author_ts,
            message: msg_lines.join("\n").trim().to_string(),
        })
    }

    pub fn parse_tree(&self, obj: &GitObject) -> Vec<TreeEntry> {
        if obj.obj_type != "tree" {
            return vec![];
        }
        let data = &obj.data;
        let mut entries = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            let sp = match data[pos..].iter().position(|&b| b == b' ') {
                Some(i) => pos + i,
                None => break,
            };
            let nul = match data[sp + 1..].iter().position(|&b| b == 0) {
                Some(i) => sp + 1 + i,
                None => break,
            };
            if nul + 21 > data.len() {
                break;
            }
            let mode = String::from_utf8_lossy(&data[pos..sp]).trim().to_string();
            let name = String::from_utf8_lossy(&data[sp + 1..nul]).into_owned();
            let sha1 = hex::encode(&data[nul + 1..nul + 21]);
            entries.push(TreeEntry { mode, name, sha1 });
            pos = nul + 21;
        }

        entries
    }

    #[allow(dead_code)]
    pub fn sha1_of(&self, obj_type: &str, content: &[u8]) -> String {
        let header = format!("{} {}\x00", obj_type, content.len());
        let mut hasher = Sha1::new();
        hasher.update(header.as_bytes());
        hasher.update(content);
        hex::encode(hasher.finalize())
    }
}

// ════════════════════════════════════════════════
// PACK INDEX PARSER  (.git/objects/pack/*.idx)
// ════════════════════════════════════════════════

pub struct PackIndexParser;

impl PackIndexParser {
    const MAGIC_V2: &'static [u8; 4] = &[0xff, 0x74, 0x4f, 0x63];

    pub fn parse(&self, data: &[u8]) -> Vec<String> {
        if data.len() < 8 {
            return vec![];
        }
        if &data[..4] == Self::MAGIC_V2 {
            self.parse_v2(data)
        } else {
            self.parse_v1(data)
        }
    }

    fn parse_v2(&self, data: &[u8]) -> Vec<String> {
        if data.len() < 1032 {
            return vec![];
        }
        let offset = 8 + 255 * 4;
        let n = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;
        if n == 0 || n > 5_000_000 {
            return vec![];
        }
        let start = 1032;
        (0..n)
            .filter(|&i| start + i * 20 + 20 <= data.len())
            .map(|i| hex::encode(&data[start + i * 20..start + i * 20 + 20]))
            .collect()
    }

    fn parse_v1(&self, data: &[u8]) -> Vec<String> {
        if data.len() < 1024 {
            return vec![];
        }
        let n = u32::from_be_bytes(data[255 * 4..256 * 4].try_into().unwrap_or([0; 4])) as usize;
        if n == 0 || n > 5_000_000 {
            return vec![];
        }
        (0..n)
            .filter(|&i| 1024 + i * 24 + 24 <= data.len())
            .map(|i| hex::encode(&data[1024 + i * 24 + 4..1024 + i * 24 + 24]))
            .collect()
    }
}

// ════════════════════════════════════════════════
// PACKED-REFS PARSER
// ════════════════════════════════════════════════

lazy_static! {
    static ref REF_RE: Regex = Regex::new(r"^([0-9a-f]{40})\s+(.+)$").unwrap();
    static ref PEEL_RE: Regex = Regex::new(r"^\^([0-9a-f]{40})$").unwrap();
}

pub struct PackedRefsParser;

impl PackedRefsParser {
    pub fn parse(&self, text: &str) -> Vec<RefEntry> {
        let mut refs: Vec<RefEntry> = Vec::new();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(cap) = PEEL_RE.captures(line) {
                if let Some(last) = refs.last_mut() {
                    last.peeled = Some(cap[1].to_string());
                }
                continue;
            }
            if let Some(cap) = REF_RE.captures(line) {
                refs.push(RefEntry {
                    sha1: cap[1].to_string(),
                    ref_name: cap[2].trim().to_string(),
                    peeled: None,
                });
            }
        }

        refs
    }

    pub fn sha1s(&self, refs: &[RefEntry]) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        for r in refs {
            set.insert(r.sha1.clone());
            if let Some(p) = &r.peeled {
                set.insert(p.clone());
            }
        }
        set
    }
}

// ════════════════════════════════════════════════
// CONFIG PARSER  (.git/config — INI-like)
// ════════════════════════════════════════════════

lazy_static! {
    static ref SEC_RE: Regex = Regex::new(r#"^\[([^\]"]+?)(?:\s+"([^"]+)")?\]$"#).unwrap();
    static ref KV_RE: Regex = Regex::new(r"^\s*(\w[\w-]*)\s*=\s*(.+)$").unwrap();
}

pub struct GitConfigParser;

impl GitConfigParser {
    pub fn parse(&self, text: &str) -> HashMap<String, HashMap<String, String>> {
        let mut result: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut current: Option<String> = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(cap) = SEC_RE.captures(line) {
                let sec = cap[1].trim().to_string();
                let key = if let Some(sub) = cap.get(2) {
                    format!("{}.{}", sec, sub.as_str())
                } else {
                    sec
                };
                result.entry(key.clone()).or_default();
                current = Some(key);
                continue;
            }
            if let Some(cap) = KV_RE.captures(line) {
                if let Some(ref cur) = current {
                    result
                        .entry(cur.clone())
                        .or_default()
                        .insert(cap[1].trim().to_string(), cap[2].trim().to_string());
                }
            }
        }

        result
    }

    pub fn remote_urls(&self, cfg: &HashMap<String, HashMap<String, String>>) -> Vec<HashMap<String, String>> {
        let mut out = Vec::new();
        for (sec, data) in cfg {
            if sec.starts_with("remote.") {
                if let Some(url) = data.get("url") {
                    let mut m = HashMap::new();
                    m.insert("remote".into(), sec.split_once('.').map(|x| x.1).unwrap_or("").to_string());
                    m.insert("url".into(), url.clone());
                    out.push(m);
                }
            }
        }
        out
    }

    pub fn branches(&self, cfg: &HashMap<String, HashMap<String, String>>) -> Vec<String> {
        cfg.keys()
            .filter(|k| k.starts_with("branch."))
            .map(|k| k.split_once('.').map(|x| x.1).unwrap_or("").to_string())
            .collect()
    }
}

// ════════════════════════════════════════════════
// SMALL UTILITIES
// ════════════════════════════════════════════════

lazy_static! {
    static ref SHA1_RE: Regex = Regex::new(r"\b([0-9a-f]{40})\b").unwrap();
    static ref NULL_SHA1: &'static str = "0000000000000000000000000000000000000000";
}

pub fn extract_sha1s(text: &str) -> std::collections::HashSet<String> {
    SHA1_RE
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .filter(|s| s.as_str() != *NULL_SHA1)
        .collect()
}

pub fn parse_head(text: &str) -> HashMap<String, String> {
    let text = text.trim();
    let mut m = HashMap::new();
    if let Some(rest) = text.strip_prefix("ref: ") {
        let r = rest.trim();
        let branch = r.rsplit('/').next().unwrap_or("").to_string();
        m.insert("type".into(), "ref".into());
        m.insert("ref".into(), r.to_string());
        m.insert("branch".into(), branch);
    } else if text.len() == 40 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        m.insert("type".into(), "detached".into());
        m.insert("sha1".into(), text.to_string());
    } else {
        m.insert("type".into(), "unknown".into());
    }
    m
}

pub fn parse_info_packs(text: &str) -> Vec<String> {
    lazy_static! {
        static ref PACK_RE: Regex = Regex::new(r"P\s+pack-([0-9a-f]{40})\.pack").unwrap();
    }
    PACK_RE
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .collect()
}

pub fn is_valid_sha1(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn obj_path(sha1: &str) -> String {
    if sha1.len() < 2 {
        return format!("objects/{}", sha1);
    }
    format!("objects/{}/{}", &sha1[..2], &sha1[2..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_head_ref() {
        let m = parse_head("ref: refs/heads/main");
        assert_eq!(m["type"], "ref");
        assert_eq!(m["branch"], "main");
    }

    #[test]
    fn test_parse_head_detached() {
        let sha = "a".repeat(40);
        let m = parse_head(&sha);
        assert_eq!(m["type"], "detached");
        assert_eq!(m["sha1"], sha);
    }

    #[test]
    fn test_extract_sha1s() {
        let text = "abc a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4 xyz";
        let set = extract_sha1s(text);
        assert!(set.contains("a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4"));
    }

    #[test]
    fn test_obj_path() {
        let sha = "a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4";
        assert_eq!(obj_path(sha), format!("objects/a3/{}", &sha[2..]));
    }

    #[test]
    fn test_obj_path_empty_sha1() {
        // Should not panic on empty string
        let result = obj_path("");
        assert_eq!(result, "objects/");
    }

    #[test]
    fn test_obj_path_short_sha1() {
        // Should not panic on single character
        let result = obj_path("a");
        assert_eq!(result, "objects/a");
    }

    // ── TreeWalker tests ─────────────────────────────────────────────────────
    // TODO: Re-enable when TreeWalker is implemented
    /*
    #[test]
    fn test_tree_walker_traverse_sync_with_blob() {
        // Create a mock tree object with a single blob entry
        let tree_data = b"100644 README.md\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let header = format!("tree {}\x00", tree_data.len());
        let mut full_data = header.into_bytes();
        full_data.extend_from_slice(tree_data);

        let tree_obj = GitObject {
            sha1: "test".repeat(10),
            obj_type: "tree".to_string(),
            size: tree_data.len(),
            data: tree_data.to_vec(),
        };

        // Note: This test is limited as we can't create valid SHA1s without proper hashing
        // The sync traversal mainly validates the structure
        let result = TreeWalker::traverse_sync(&tree_obj, "");
        // In real scenario with valid SHA1s, this would contain the blob mapping
    }

    #[test]
    fn test_tree_walker_traverse_sync_with_nested_tree() {
        // Test that sync traversal handles nested trees (though it won't recurse without fetches)
        let tree_data = b"040000 src\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02";
        let header = format!("tree {}\x00", tree_data.len());
        let mut full_data = header.into_bytes();
        full_data.extend_from_slice(tree_data);

        let tree_obj = GitObject {
            sha1: "test".repeat(10),
            obj_type: "tree".to_string(),
            size: tree_data.len(),
            data: tree_data.to_vec(),
        };

        let result = TreeWalker::traverse_sync(&tree_obj, "");
        // Nested tree should be in results but not traversed in sync mode
        assert!(result.is_empty(), "Sync traversal doesn't recurse into nested trees");
    }
    */

    #[test]
    fn test_is_valid_sha1() {
        assert!(is_valid_sha1("a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4"));
        assert!(is_valid_sha1("0000000000000000000000000000000000000000"));
        assert!(!is_valid_sha1(""));
        assert!(!is_valid_sha1("a"));
        assert!(!is_valid_sha1("xyz"));
        assert!(!is_valid_sha1("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"));
        assert!(!is_valid_sha1("a3b4c5")); // too short
    }

    #[test]
    fn test_packed_refs_parser() {
        let text = "a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4 refs/heads/main\n\
                    ^b3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4\n";
        let parser = PackedRefsParser;
        let refs = parser.parse(text);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].ref_name, "refs/heads/main");
        assert_eq!(refs[0].peeled.as_deref(), Some("b3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4"));
    }
}

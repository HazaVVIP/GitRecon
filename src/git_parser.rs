//! git_parser.rs
//! Pure Rust parsers for all Git binary formats:
//! Index (DIRC), loose objects, pack index (.idx), packed-refs, logs, config, HEAD.

use flate2::read::ZlibDecoder;
use lazy_static::lazy_static;
use regex::Regex;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::io::Read;

// ════════════════════════════════════════════════
// HELPER FUNCTIONS
// ════════════════════════════════════════════════

/// Safely read a big-endian u32 from a slice at a given offset.
/// Returns None if the slice is too short.
pub(crate) fn read_u32_be(data: &[u8], offset: usize) -> Option<u32> {
    if data.len() < offset + 4 {
        return None;
    }
    let arr: [u8; 4] = data[offset..offset + 4].try_into().ok()?;
    Some(u32::from_be_bytes(arr))
}

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

/// Sprint 5 (S5.2): metadata extracted from an annotated tag object. Callers use
/// `target` to recurse into whatever the tag points at (commit / tree / blob /
/// another tag — annotated tags CAN be nested).
#[derive(Debug, Clone)]
pub struct TagInfo {
    pub target: String,
    #[allow(dead_code)]
    pub target_type: String,
    #[allow(dead_code)]
    pub tag_name: String,
}

#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub mode: String,
    pub name: String,
    pub sha1: String,
}

impl TreeEntry {
    /// Regular files (100644) and executables (100755).
    ///
    /// Symlinks (120000) are treated as blobs because their "content" is the target path —
    /// often useful for secret discovery (e.g. .env → /etc/passwd style pointers).
    pub fn is_blob(&self) -> bool {
        let m = self.normalized_mode();
        m == "100644" || m == "100755" || m == "120000"
    }

    /// Subdirectory tree entry. Git stores tree mode as "40000" (5 chars, no leading zero) —
    /// comparing against "040000" (6 chars) never matches, which used to silently drop
    /// every subdirectory during commit-graph traversal.
    pub fn is_tree(&self) -> bool {
        self.normalized_mode() == "40000"
    }

    /// Submodule reference (gitlink). Points to a commit in a foreign repo — we cannot
    /// enumerate it without recursing into `.gitmodules`, so callers should log-skip.
    #[allow(dead_code)]
    pub fn is_gitlink(&self) -> bool {
        self.normalized_mode() == "160000"
    }

    /// Symlink blob — content is the target path string.
    #[allow(dead_code)]
    pub fn is_symlink(&self) -> bool {
        self.normalized_mode() == "120000"
    }

    /// Strip leading zeros so `"040000"` and `"40000"` compare equal. Git's canonical
    /// tree encoding omits the leading zero, but some third-party writers pad it.
    fn normalized_mode(&self) -> &str {
        let trimmed = self.mode.trim_start_matches('0');
        if trimmed.is_empty() {
            "0"
        } else {
            trimmed
        }
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

        let version = match read_u32_be(data, 4) {
            Some(v) => v,
            None => return Err("Invalid index file: truncated version field".into()),
        };
        let n = match read_u32_be(data, 8) {
            Some(count) => count as usize,
            None => return Err("Invalid index file: truncated entry count".into()),
        };

        if !matches!(version, 2..=4) {
            return Err(format!("Unsupported index version: {version}"));
        }

        let mut entries = Vec::new();
        let mut offset = 12usize;
        let mut previous_name = String::new();

        for _ in 0..n {
            if offset + 62 > data.len() {
                break;
            }
            let parsed = if version == 4 {
                Self::parse_entry_v4(data, offset, &previous_name)
            } else {
                Self::parse_entry(data, offset, version)
            };
            match parsed {
                Some((entry, next)) => {
                    previous_name = entry.filename.clone();
                    entries.push(entry);
                    offset = next;
                }
                None => break,
            }
        }

        Ok(entries)
    }

    /// Parse a Git index v4 entry. Unlike v2/v3, v4 stores no per-entry padding;
    /// the pathname is encoded as a varint prefix-strip count followed by a NUL-terminated
    /// suffix relative to the previous entry's pathname.
    fn parse_entry_v4(
        data: &[u8],
        offset: usize,
        previous_name: &str,
    ) -> Option<(IndexEntry, usize)> {
        if offset.checked_add(62)? > data.len() {
            return None;
        }
        let mode = u32::from_be_bytes(data.get(offset + 24..offset + 28)?.try_into().ok()?);
        let size = u32::from_be_bytes(data.get(offset + 36..offset + 40)?.try_into().ok()?);
        let sha1 = hex::encode(data.get(offset + 40..offset + 60)?);
        let flags = u16::from_be_bytes(data.get(offset + 60..offset + 62)?.try_into().ok()?);
        let extended = (flags >> 14) & 1 == 1;
        let extra = if extended { 2 } else { 0 };
        let mut cursor = offset.checked_add(62)?.checked_add(extra)?;

        let mut strip_len = 0usize;
        loop {
            let byte = *data.get(cursor)?;
            cursor = cursor.checked_add(1)?;
            strip_len = strip_len
                .checked_shl(7)?
                .checked_add((byte & 0x7f) as usize)?;
            if byte & 0x80 == 0 {
                break;
            }
            if strip_len > previous_name.len() {
                return None;
            }
        }
        if strip_len > previous_name.len() {
            return None;
        }
        let suffix_end = data.get(cursor..)?.iter().position(|&b| b == 0)?;
        let suffix = std::str::from_utf8(data.get(cursor..cursor + suffix_end)?).ok()?;
        let filename = format!(
            "{}{}",
            &previous_name[..previous_name.len() - strip_len],
            suffix
        );
        let next = cursor.checked_add(suffix_end)?.checked_add(1)?;
        if filename.contains("..") || filename.starts_with('/') {
            return Some((
                IndexEntry {
                    sha1: String::new(),
                    filename: String::new(),
                    mode: 0,
                    file_size: 0,
                },
                next,
            ));
        }
        Some((
            IndexEntry {
                sha1,
                filename,
                mode,
                file_size: size,
            },
            next,
        ))
    }

    fn parse_entry(data: &[u8], offset: usize, version: u32) -> Option<(IndexEntry, usize)> {
        let base = offset;
        // Bounds check: minimum entry size is 62 bytes
        if offset + 62 > data.len() {
            return None;
        }

        // Safe slice access with get()
        let mode_bytes = data.get(offset + 24..offset + 28)?;
        let mode = u32::from_be_bytes(mode_bytes.try_into().ok()?);

        let size_bytes = data.get(offset + 36..offset + 40)?;
        let size = u32::from_be_bytes(size_bytes.try_into().ok()?);

        let sha1_bytes = data.get(offset + 40..offset + 60)?;
        let sha1 = hex::encode(sha1_bytes);

        let flags_bytes = data.get(offset + 60..offset + 62)?;
        let flags = u16::from_be_bytes(flags_bytes.try_into().ok()?);

        let extended = (flags >> 14) & 1 == 1;
        let name_len = (flags & 0x0FFF) as usize;
        let extra = if version >= 3 && extended { 2 } else { 0 };

        // Safe addition with overflow check
        let name_start = offset.checked_add(62).and_then(|v| v.checked_add(extra))?;

        let (raw_name, end) = if name_len < 0xFFF {
            if name_start
                .checked_add(name_len)
                .is_none_or(|v| v > data.len())
            {
                return None;
            }
            let name_end = name_start
                .checked_add(name_len)
                .and_then(|v| v.checked_add(1))?;
            (data.get(name_start..name_start + name_len)?, name_end)
        } else {
            // Safe nul search with get()
            let nul_offset = data.get(name_start..)?.iter().position(|&b| b == 0)?;
            let nul_absolute = name_start
                .checked_add(nul_offset)
                .and_then(|v| v.checked_add(1))?;
            let raw_name = data.get(name_start..name_start + nul_offset)?;
            (raw_name, nul_absolute)
        };

        // BUG-LOGIC-007 FIX: Off-by-one in index padding calculation
        // Padding should align to 8-byte boundary: (diff + 7) & !7 rounds up to next multiple of 8
        // But we need to ensure minimum padding of 1 byte if not already aligned
        let diff = end.checked_sub(base)?;
        let padded = if diff % 8 == 0 {
            end // Already aligned, no padding needed
        } else {
            base.checked_add((diff + 7) & !7)?
        };

        let filename = String::from_utf8_lossy(raw_name).into_owned();

        // Security: reject path traversal
        if filename.contains("..") || filename.starts_with('/') {
            return Some((
                IndexEntry {
                    sha1: String::new(),
                    filename: String::new(),
                    mode: 0,
                    file_size: 0,
                },
                padded,
            ));
        }

        Some((
            IndexEntry {
                sha1,
                filename,
                mode,
                file_size: size,
            },
            padded,
        ))
    }
}

// ════════════════════════════════════════════════
// OBJECT PARSER  (loose objects, zlib-compressed)
// ════════════════════════════════════════════════

lazy_static! {
    static ref ID_RE: Regex = Regex::new(r"<([^>]+)>").expect("ID_RE regex pattern is valid");
    static ref TS_RE: Regex = Regex::new(r">\s+(\d+)").expect("TS_RE regex pattern is valid");
}

pub struct ObjectParser;

const VALID_TYPES: &[&str] = &["blob", "tree", "commit", "tag"];

/// Hard cap on inflated loose-object size when the caller does not specify a limit.
/// 128 MB matches the largest object git-core supports without special config, and
/// stops a `1 KB deflate -> 5 GB` decompression bomb from OOM-ing the scanner.
const DEFAULT_MAX_INFLATED: usize = 128 * 1024 * 1024;

impl ObjectParser {
    /// Legacy entry point — inflate with the default max output size (128 MB) and no
    /// hash verification. Kept for existing call-sites that don't have a `max_output`
    /// value handy. New code should prefer `parse_with_limit`.
    pub fn parse(&self, data: &[u8], sha1: &str) -> Option<GitObject> {
        self.parse_with_limit(data, sha1, DEFAULT_MAX_INFLATED, /*verify_sha1=*/ true)
    }

    /// Sprint 3 (S3.2 + S3.3 + S3.4): inflate a loose object with:
    ///
    /// - **Output size cap** (S3.2). `ZlibDecoder::read_to_end` used to be unbounded.
    ///   A hostile server serving a 1 KB deflate stream that inflates to gigabytes
    ///   would exhaust process memory. We wrap the decoder in `Read::take(max_output)`
    ///   and refuse to proceed if the inflated stream reaches that boundary.
    ///
    /// - **Header size validation** (S3.4). Git's object header is
    ///   `"<type> <size>\0<content>"`. If `content.len() != size` the object is
    ///   truncated or padded — a benign fetch bug, or a hostile probe. Either way
    ///   we refuse to hand malformed bytes downstream.
    ///
    /// - **SHA1 verification** (S3.3). Every git object has a self-identifying hash.
    ///   Verifying `sha1_of(type, content) == expected_sha1` defeats a middlebox or
    ///   hostile server that swaps blob content while preserving the URL. This is
    ///   opt-in via `verify_sha1` because pack-derived objects reach this path
    ///   without a canonical SHA1 (their identity is computed inside the pack).
    pub fn parse_with_limit(
        &self,
        data: &[u8],
        sha1: &str,
        max_output: usize,
        verify_sha1: bool,
    ) -> Option<GitObject> {
        // Wrap in `.take()` so the inflated stream is bounded. We ask for one byte
        // more than the limit so we can DETECT overflow (vs. silently truncating).
        let mut decoder = ZlibDecoder::new(data);
        let mut raw = Vec::new();
        std::io::Read::take(&mut decoder, max_output as u64 + 1)
            .read_to_end(&mut raw)
            .ok()?;
        if raw.len() > max_output {
            log::warn!(
                "ObjectParser::parse: refusing object {} — inflated size exceeds {} bytes (zlib bomb defence)",
                &sha1[..sha1.len().min(8)],
                max_output
            );
            return None;
        }

        let nul = raw.iter().position(|&b| b == 0)?;
        let header = std::str::from_utf8(&raw[..nul]).ok()?;
        let (obj_type, size_str) = header.split_once(' ')?;

        if !VALID_TYPES.contains(&obj_type) {
            return None;
        }

        let size: usize = size_str.parse().ok()?;
        let content = &raw[nul + 1..];

        // S3.4: header size MUST match the actual content length. Truncated or padded
        // objects are rejected here — the parser used to silently accept them.
        if content.len() != size {
            log::warn!(
                "ObjectParser::parse: refusing object {} — header size {} != content length {}",
                &sha1[..sha1.len().min(8)],
                size,
                content.len()
            );
            return None;
        }

        let obj_data = content.to_vec();

        // S3.3: SHA1 self-check. Skipped for pack-derived call-sites (verify_sha1=false)
        // whose SHA1 doesn't come from the loose-object hash. All loose-object fetches
        // (streamer.rs, mapper.rs commit-graph walk) go through `parse` which verifies.
        if verify_sha1 && is_valid_sha1(sha1) {
            let computed = Self.sha1_of(obj_type, &obj_data);
            if computed != sha1 {
                log::warn!(
                    "ObjectParser::parse: refusing object {} — SHA1 mismatch (got {}, expected {})",
                    &sha1[..sha1.len().min(8)],
                    &computed[..8],
                    &sha1[..sha1.len().min(8)]
                );
                return None;
            }
        }

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

    /// Sprint 5 (S5.2): parse an annotated tag object.
    ///
    /// Annotated tags (`git tag -a v1.0`) are first-class objects containing:
    /// ```text
    /// object <sha1>       ← target commit / tree / blob / another tag
    /// type <object-type>
    /// tag <tag-name>
    /// tagger <name> <email> <ts> <tz>
    ///
    /// <optional message>
    /// ```
    /// Historically the mapper stopped at `obj_type == "commit"` in the graph walk
    /// which meant a HEAD pointing at a tag terminated traversal immediately.
    /// This returns the `object` SHA1 so callers can recurse.
    pub fn parse_tag(&self, obj: &GitObject) -> Option<TagInfo> {
        if obj.obj_type != "tag" {
            return None;
        }
        let text = String::from_utf8_lossy(&obj.data);

        let mut target = String::new();
        let mut target_type = String::new();
        let mut tag_name = String::new();

        for line in text.lines() {
            if line.is_empty() {
                break; // header/body separator
            }
            if let Some(rest) = line.strip_prefix("object ") {
                target = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("type ") {
                target_type = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("tag ") {
                tag_name = rest.trim().to_string();
            }
        }

        if !is_valid_sha1(&target) {
            return None;
        }
        Some(TagInfo {
            target,
            target_type,
            tag_name,
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
            // Safe space search with get()
            let sp_offset = match data.get(pos..) {
                Some(slice) => slice.iter().position(|&b| b == b' '),
                None => break,
            };
            let sp = match sp_offset {
                Some(i) => match pos.checked_add(i) {
                    Some(v) => v,
                    None => break,
                },
                None => break,
            };

            // Safe nul search with bounds check
            let sp_plus_one = match sp.checked_add(1) {
                Some(v) => v,
                None => break,
            };
            let nul_offset = match data.get(sp_plus_one..) {
                Some(slice) => slice.iter().position(|&b| b == 0),
                None => break,
            };
            let nul = match nul_offset {
                Some(i) => match sp_plus_one.checked_add(i) {
                    Some(v) => v,
                    None => break,
                },
                None => break,
            };

            // Check if we have enough bytes for SHA1 (20 bytes after nul)
            let nul_plus_21 = match nul.checked_add(21) {
                Some(v) => v,
                None => break,
            };
            if nul_plus_21 > data.len() {
                break;
            }

            // Safe slice access with get() - use if let since return type is Vec
            let mode_bytes = match data.get(pos..sp) {
                Some(bytes) => bytes,
                None => break,
            };
            let name_bytes = match data.get(sp_plus_one..nul) {
                Some(bytes) => bytes,
                None => break,
            };
            let sha1_bytes = match data.get(nul + 1..nul_plus_21) {
                Some(bytes) => bytes,
                None => break,
            };

            let mode = String::from_utf8_lossy(mode_bytes).trim().to_string();
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            let sha1 = hex::encode(sha1_bytes);
            entries.push(TreeEntry { mode, name, sha1 });

            // Safe position update with saturating add
            pos = nul.saturating_add(21);
        }

        entries
    }

    /// Compute git-canonical SHA1 for `(type, content)`. Format matches on-disk loose
    /// object hashing: `"<type> <length>\0<content>"` fed to SHA1. Used by
    /// `parse_with_limit` to verify inflated object identity against expected SHA1.
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
        let n = match read_u32_be(data, offset) {
            Some(count) => count as usize,
            None => return vec![],
        };
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
        let n = match read_u32_be(data, 255 * 4) {
            Some(count) => count as usize,
            None => return vec![],
        };
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

    pub fn remote_urls(
        &self,
        cfg: &HashMap<String, HashMap<String, String>>,
    ) -> Vec<HashMap<String, String>> {
        let mut out = Vec::new();
        for (sec, data) in cfg {
            if sec.starts_with("remote.") {
                if let Some(url) = data.get("url") {
                    let mut m = HashMap::new();
                    m.insert(
                        "remote".into(),
                        sec.split_once('.').map(|x| x.1).unwrap_or("").to_string(),
                    );
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
    // Legacy TreeWalker sketches are retained below only as historical context;
    // active coverage targets the implemented ObjectParser::parse_tree API.
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
    fn parse_tree_extracts_blob_entry() {
        let mut data = b"100644 README.md\0".to_vec();
        data.extend_from_slice(&[0x11; 20]);
        let obj = GitObject {
            sha1: "a".repeat(40),
            obj_type: "tree".to_string(),
            size: data.len(),
            data,
        };
        let entries = ObjectParser.parse_tree(&obj);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mode, "100644");
        assert_eq!(entries[0].name, "README.md");
        assert_eq!(entries[0].sha1, "11".repeat(20));
    }

    #[test]
    fn parse_tree_preserves_nested_tree_entry() {
        let mut data = b"40000 src\0".to_vec();
        data.extend_from_slice(&[0x22; 20]);
        let obj = GitObject {
            sha1: "b".repeat(40),
            obj_type: "tree".to_string(),
            size: data.len(),
            data,
        };
        let entries = ObjectParser.parse_tree(&obj);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_tree());
        assert_eq!(entries[0].name, "src");
        assert_eq!(entries[0].sha1, "22".repeat(20));
    }

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
        assert_eq!(
            refs[0].peeled.as_deref(),
            Some("b3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4")
        );
    }

    // ── Sprint 1 — TreeEntry mode classification ─────────────────────────────
    fn te(mode: &str) -> TreeEntry {
        TreeEntry {
            mode: mode.to_string(),
            name: "x".into(),
            sha1: "a".repeat(40),
        }
    }

    #[test]
    fn tree_entry_regular_file_is_blob() {
        assert!(te("100644").is_blob());
        assert!(!te("100644").is_tree());
    }

    #[test]
    fn tree_entry_executable_is_blob() {
        assert!(te("100755").is_blob());
    }

    #[test]
    fn tree_entry_symlink_is_blob() {
        // Regression: symlink target strings often point to secret material (.env, /etc/passwd).
        // They must be enumerated, not silently dropped.
        assert!(te("120000").is_blob());
        assert!(te("120000").is_symlink());
    }

    #[test]
    fn tree_entry_subtree_canonical_form_is_tree() {
        // Regression: Git writes subtree mode as "40000" (no leading zero). Comparing
        // against "040000" — as the old walker did — never matched, silently dropping
        // every subdirectory.
        assert!(te("40000").is_tree());
        assert!(!te("40000").is_blob());
    }

    #[test]
    fn tree_entry_subtree_padded_form_is_tree() {
        // Some third-party tools pad the leading zero.
        assert!(te("040000").is_tree());
    }

    #[test]
    fn tree_entry_gitlink_neither_blob_nor_tree() {
        // Submodule (foreign commit reference) — must be recognisable so callers can skip.
        assert!(te("160000").is_gitlink());
        assert!(!te("160000").is_blob());
        assert!(!te("160000").is_tree());
    }

    // ── IndexParser version coverage ──────────────────────────────────────────
    #[test]
    fn index_parser_decodes_v4_path_prefix_compression() {
        fn entry(sha: u8, path: &[u8], strip: u8) -> Vec<u8> {
            let mut raw = vec![0u8; 62];
            raw[24..28].copy_from_slice(&0o100644u32.to_be_bytes());
            raw[36..40].copy_from_slice(&1u32.to_be_bytes());
            raw[40..60].fill(sha);
            raw.extend_from_slice(&[strip]);
            raw.extend_from_slice(path);
            raw.push(0);
            raw
        }

        let mut data = Vec::from(b"DIRC" as &[u8]);
        data.extend_from_slice(&4u32.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend(entry(0x11, b"src/a.txt", 0));
        data.extend(entry(0x22, b"b.txt", 5)); // strip "src/a"; retain "src/"
        data.extend_from_slice(&[0u8; 20]); // checksum is not validated by IndexParser

        let entries = IndexParser.parse(&data).expect("v4 fixture must parse");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].filename, "src/a.txt");
        assert_eq!(entries[0].sha1, "11".repeat(20));
        assert_eq!(entries[1].filename, "src/b.txt");
        assert_eq!(entries[1].sha1, "22".repeat(20));
    }

    #[test]
    fn index_parser_rejects_unsupported_version() {
        let mut data = Vec::from(b"DIRC" as &[u8]);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        assert!(IndexParser.parse(&data).is_err());
    }

    #[test]
    fn index_parser_accepts_v2_and_v3_header() {
        for version in [2u32, 3u32] {
            let mut data = Vec::from(b"DIRC" as &[u8]);
            data.extend_from_slice(&version.to_be_bytes());
            data.extend_from_slice(&0u32.to_be_bytes());
            let out = IndexParser.parse(&data).expect("v2/v3 header must parse");
            assert!(out.is_empty(), "empty index expected for zero entries");
        }
    }

    #[test]
    fn index_parser_rejects_v1() {
        let mut data = Vec::from(b"DIRC" as &[u8]);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        assert!(IndexParser.parse(&data).is_err());
    }

    // ── Sprint 3 (S3.2/S3.3/S3.4) — ObjectParser hardening ───────────────────

    fn deflate(bytes: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    /// Encode a valid loose-object payload: `<type> <size>\0<content>`.
    fn encode_object(obj_type: &str, content: &[u8]) -> (Vec<u8>, String) {
        let mut raw = format!("{} {}\x00", obj_type, content.len()).into_bytes();
        raw.extend_from_slice(content);
        let sha1 = ObjectParser.sha1_of(obj_type, content);
        (deflate(&raw), sha1)
    }

    #[test]
    fn object_parser_accepts_valid_blob() {
        let (compressed, sha1) = encode_object("blob", b"hello world");
        let obj = ObjectParser
            .parse(&compressed, &sha1)
            .expect("valid blob must parse");
        assert_eq!(obj.obj_type, "blob");
        assert_eq!(obj.data, b"hello world");
    }

    #[test]
    fn object_parser_rejects_sha1_mismatch() {
        // S3.3: content whose canonical SHA1 differs from `expected` must be refused.
        let (compressed, _real_sha1) = encode_object("blob", b"attacker payload");
        let fake_sha = "0".repeat(40);
        assert!(
            ObjectParser.parse(&compressed, &fake_sha).is_none(),
            "MITM-swapped content must fail hash verification"
        );
    }

    #[test]
    fn object_parser_rejects_size_mismatch() {
        // S3.4: header claims size N but content has M != N bytes → refuse.
        // Craft raw `blob 100\0AAAA...` where content is only 4 bytes.
        let mut raw = b"blob 100\x00AAAA".to_vec();
        // Ensure the SHA1 CHECK isn't the reason we fail — pass `verify_sha1=false`.
        let compressed = deflate(&raw);
        let sha = "a".repeat(40);
        assert!(
            ObjectParser
                .parse_with_limit(&compressed, &sha, 4096, false)
                .is_none(),
            "header size mismatch must be refused even with SHA1 check off"
        );

        // Also verify that WITH a correctly declared size (12), we accept.
        raw = b"blob 4\x00AAAA".to_vec();
        let compressed = deflate(&raw);
        let obj = ObjectParser
            .parse_with_limit(&compressed, &sha, 4096, false)
            .expect("size-correct payload must parse");
        assert_eq!(obj.data, b"AAAA");
    }

    #[test]
    fn object_parser_caps_zlib_bomb() {
        // S3.2: a 1 KB deflate stream that inflates to megabytes must be refused
        // when max_output is set below the inflated size.
        let big = vec![0u8; 4 * 1024 * 1024]; // 4 MB of zeros — compresses to ~4 KB
        let mut raw = format!("blob {}\x00", big.len()).into_bytes();
        raw.extend_from_slice(&big);
        let compressed = deflate(&raw);

        // With small cap: refuse.
        let sha = "a".repeat(40);
        assert!(
            ObjectParser
                .parse_with_limit(&compressed, &sha, 1024, false)
                .is_none(),
            "inflated size > max_output must be refused"
        );

        // With generous cap: accepts (size validation still passes since we
        // declared the correct size in the header).
        assert!(ObjectParser
            .parse_with_limit(&compressed, &sha, 8 * 1024 * 1024, false)
            .is_some());
    }

    #[test]
    fn object_parser_rejects_invalid_type() {
        let (compressed, sha1) = encode_object("random", b"content");
        assert!(ObjectParser.parse(&compressed, &sha1).is_none());
    }

    #[test]
    fn sha1_of_matches_git_canonical_form() {
        // git canonical: SHA1("<type> <length>\0<content>"). Verify sha1_of matches
        // what a real git command would produce for the empty tree.
        let empty_tree_sha1 = ObjectParser.sha1_of("tree", b"");
        assert_eq!(empty_tree_sha1, "4b825dc642cb6eb9a060e54bf8d69288fbee4904");
    }

    // ── Sprint 5 (S5.2) — tag object dereference ─────────────────────────────

    #[test]
    fn parse_tag_extracts_target_sha() {
        let target = "1".repeat(40);
        let body = format!("object {target}\ntype commit\ntag v1.0\ntagger Someone <s@e> 0 +0000\n\nrelease note\n");
        let obj = GitObject {
            sha1: "a".repeat(40),
            obj_type: "tag".to_string(),
            size: body.len(),
            data: body.into_bytes(),
        };
        let info = ObjectParser.parse_tag(&obj).expect("valid tag must parse");
        assert_eq!(info.target, target);
        assert_eq!(info.target_type, "commit");
        assert_eq!(info.tag_name, "v1.0");
    }

    #[test]
    fn parse_tag_rejects_non_tag() {
        let obj = GitObject {
            sha1: "a".repeat(40),
            obj_type: "commit".to_string(),
            size: 0,
            data: b"".to_vec(),
        };
        assert!(ObjectParser.parse_tag(&obj).is_none());
    }

    #[test]
    fn parse_tag_rejects_missing_object_line() {
        let body = "type commit\ntag v1.0\n\nnote";
        let obj = GitObject {
            sha1: "a".repeat(40),
            obj_type: "tag".to_string(),
            size: body.len(),
            data: body.as_bytes().to_vec(),
        };
        assert!(ObjectParser.parse_tag(&obj).is_none());
    }

    #[test]
    fn parse_tag_rejects_malformed_sha() {
        let body = "object not-a-sha\ntype commit\ntag v1.0\n\n";
        let obj = GitObject {
            sha1: "a".repeat(40),
            obj_type: "tag".to_string(),
            size: body.len(),
            data: body.as_bytes().to_vec(),
        };
        assert!(ObjectParser.parse_tag(&obj).is_none());
    }
}

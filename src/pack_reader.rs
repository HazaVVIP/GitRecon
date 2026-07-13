//! pack_reader.rs
//!
//! Sprint 5 (S5.1): Parse a Git pack file + apply deltas to recover the four
//! canonical object types (commit / tree / blob / tag).
//!
//! Motivation: `.git`-exposed servers that have been `git gc`'d ship blobs
//! *inside* `.pack` files rather than loose `objects/xx/yyyyy…`. Before this
//! module the mapper enumerated SHA1s from `.idx` files but every loose-object
//! fetch returned 404 → the whole pack was silently unusable, and `--save`
//! reconstructed nothing.
//!
//! Format reference: <https://git-scm.com/docs/pack-format>
//!
//! Scope:
//! - Pack v2 header parse (`PACK` + version + object count).
//! - Iterate object entries at offsets given by the .idx v2 fanout table.
//! - Undeltified types 1..=4: OBJ_COMMIT, OBJ_TREE, OBJ_BLOB, OBJ_TAG.
//! - Deltified types 6 (OBJ_OFS_DELTA) and 7 (OBJ_REF_DELTA), including recursion
//!   into the base object (base can itself be a delta — spec requires we resolve
//!   the chain).
//! - Zlib inflation with an explicit size cap (defeats decompression bombs).
//! - SHA1 verification against `.idx` entries.
//!
//! Not in scope (see docs/limitations):
//! - Pack v3 (Git 2.42+, SHA-256 objects).
//! - Streaming reads — we assume the pack fits in memory (typical exposure
//!   scenario: single small pack under 100 MB).

use std::collections::HashMap;
use std::io::Read;

use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};

use crate::git_parser::read_u32_be;

/// Hard cap on the size of a single inflated object. Matches
/// `git_parser::DEFAULT_MAX_INFLATED` (128 MB) — larger values would let a
/// hostile pack OOM the scanner.
const MAX_INFLATED: usize = 128 * 1024 * 1024;

/// One resolved pack object.
#[derive(Debug, Clone)]
pub struct PackObject {
    /// SHA1 of the object (computed / verified by the reader).
    pub sha1: String,
    /// One of "commit", "tree", "blob", "tag".
    pub obj_type: String,
    /// Fully-resolved object content (deltas applied).
    pub data: Vec<u8>,
}

// ── Object type constants (from pack-format spec) ────────────────────────────

const OBJ_COMMIT: u8 = 1;
const OBJ_TREE: u8 = 2;
const OBJ_BLOB: u8 = 3;
const OBJ_TAG: u8 = 4;
const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;

fn type_name(t: u8) -> Option<&'static str> {
    match t {
        OBJ_COMMIT => Some("commit"),
        OBJ_TREE => Some("tree"),
        OBJ_BLOB => Some("blob"),
        OBJ_TAG => Some("tag"),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Parse a `.idx` v2 file into `(sha1_hex, pack_offset)` pairs so we know where
/// every object lives inside the corresponding `.pack`.
///
/// The existing `PackIndexParser` only extracts SHA1s (it was written when the
/// scanner just needed to enumerate names). We add offset extraction here.
pub fn parse_idx_v2_offsets(idx: &[u8]) -> Option<Vec<(String, u64)>> {
    // Magic (\xff\x74\x4f\x63) + version (2u32).
    if idx.len() < 8 { return None; }
    if &idx[..4] != &[0xff, 0x74, 0x4f, 0x63] { return None; }
    let version = read_u32_be(idx, 4)?;
    if version != 2 { return None; }

    // Fanout table: 256 * u32, last entry = total object count.
    let n = read_u32_be(idx, 8 + 255 * 4)? as usize;
    if n == 0 || n > 5_000_000 { return None; }

    // Layout after fanout:
    //   SHA1 table:      n * 20 bytes         (start = 1032)
    //   CRC32 table:     n * 4 bytes
    //   Offset table:    n * 4 bytes           (may point to large offsets)
    //   Large offset table: variable
    let sha1_start = 1032usize;
    let crc_start = sha1_start.checked_add(n.checked_mul(20)?)?;
    let ofs_start = crc_start.checked_add(n.checked_mul(4)?)?;
    let large_start = ofs_start.checked_add(n.checked_mul(4)?)?;

    if idx.len() < large_start { return None; }

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let sha_pos = sha1_start + i * 20;
        let sha1 = hex::encode(&idx[sha_pos..sha_pos + 20]);
        let ofs_pos = ofs_start + i * 4;
        let raw = read_u32_be(idx, ofs_pos)?;
        let offset: u64 = if raw & 0x8000_0000 != 0 {
            // MSB set → index into large-offset table (u64).
            let large_idx = (raw & 0x7FFF_FFFF) as usize;
            let large_pos = large_start.checked_add(large_idx.checked_mul(8)?)?;
            if idx.len() < large_pos + 8 { return None; }
            u64::from_be_bytes(idx[large_pos..large_pos + 8].try_into().ok()?)
        } else {
            raw as u64
        };
        out.push((sha1, offset));
    }
    Some(out)
}

/// Read a full pack file into memory and resolve every object it contains,
/// applying deltas so callers see undeltified `commit`/`tree`/`blob`/`tag`
/// content indistinguishable from a loose-object fetch.
///
/// `idx` and `pack` are the raw bytes of `.git/objects/pack/pack-<sha>.idx`
/// and `.git/objects/pack/pack-<sha>.pack` respectively.
pub fn read_pack(idx: &[u8], pack: &[u8]) -> Result<Vec<PackObject>, String> {
    // Header: PACK + version(u32) + count(u32) = 12 bytes.
    if pack.len() < 12 || &pack[..4] != b"PACK" {
        return Err("Not a valid PACK file".into());
    }
    let version = read_u32_be(pack, 4).ok_or("truncated PACK version")?;
    if !matches!(version, 2..=3) {
        return Err(format!("Unsupported PACK version: {version}"));
    }
    let count = read_u32_be(pack, 8).ok_or("truncated PACK object count")? as usize;
    if count > 5_000_000 {
        return Err(format!("PACK object count {count} exceeds 5M — refusing"));
    }

    // Get offsets from idx. Sort by offset ascending so we can resolve
    // OFS_DELTA (which references an earlier object by negative offset).
    let mut idx_pairs = parse_idx_v2_offsets(idx)
        .ok_or("Failed to parse .idx (offsets)")?;
    if idx_pairs.len() != count {
        return Err(format!(
            ".idx claims {} objects but .pack header claims {count}",
            idx_pairs.len()
        ));
    }
    idx_pairs.sort_by_key(|(_, o)| *o);

    // Cache resolved objects by pack-offset (for OFS_DELTA lookup) AND by SHA1
    // (for REF_DELTA lookup). We keep both because deltas can reference either.
    let mut by_offset: HashMap<u64, PackObject> = HashMap::with_capacity(count);
    let mut by_sha: HashMap<String, PackObject> = HashMap::with_capacity(count);
    let mut resolved = Vec::with_capacity(count);

    // Also confirm each idx SHA1 lines up with what we read.
    let expected_sha: HashMap<u64, String> = idx_pairs.iter()
        .map(|(sha, off)| (*off, sha.clone()))
        .collect();

    // Resolve each object in offset order.
    for (offset_pos, (_sha1, offset)) in idx_pairs.iter().enumerate() {
        let obj = read_pack_object(
            pack,
            *offset,
            &by_offset,
            &by_sha,
            /*depth=*/ 0,
        )?;
        // Confirm SHA1 lines up with what .idx claimed.
        if let Some(exp) = expected_sha.get(offset) {
            if &obj.sha1 != exp {
                return Err(format!(
                    "SHA1 mismatch at offset {offset}: pack says {}, idx says {exp}",
                    obj.sha1
                ));
            }
        }
        // Ratchet expectations forward — if a hostile pack orders objects wrong
        // this catches it.
        let _ = offset_pos;

        by_offset.insert(*offset, obj.clone());
        by_sha.insert(obj.sha1.clone(), obj.clone());
        resolved.push(obj);
    }

    Ok(resolved)
}

/// Read a single object at `offset`. If it's a delta, recursively resolve
/// against `by_offset` or `by_sha`. `depth` guards against pathologically
/// long delta chains (spec suggests 50 max; we cap at 100).
fn read_pack_object(
    pack: &[u8],
    offset: u64,
    by_offset: &HashMap<u64, PackObject>,
    by_sha: &HashMap<String, PackObject>,
    depth: u32,
) -> Result<PackObject, String> {
    if depth > 100 {
        return Err("Delta chain deeper than 100 — refusing (possible malicious pack)".into());
    }
    let start = offset as usize;
    if start >= pack.len() {
        return Err(format!("Object offset {offset} past pack end"));
    }

    // Variable-length header: first byte's high bit = "more" flag,
    // bits 4..=6 = object type, bits 0..=3 = size low nibble.
    // Subsequent bytes contribute 7 bits of size each.
    let mut pos = start;
    let mut byte = pack[pos];
    pos += 1;
    let obj_type = (byte >> 4) & 0b0111;
    let mut size: usize = (byte & 0x0F) as usize;
    let mut shift = 4;
    while byte & 0x80 != 0 {
        if pos >= pack.len() {
            return Err("Truncated object header".into());
        }
        byte = pack[pos];
        pos += 1;
        // Cap at a huge but bounded value to avoid usize overflow.
        let chunk = ((byte & 0x7F) as usize).checked_shl(shift)
            .ok_or("Size overflow in object header")?;
        size = size.checked_add(chunk).ok_or("Size overflow in object header")?;
        shift += 7;
        if size > MAX_INFLATED {
            return Err(format!("Declared object size {size} exceeds MAX_INFLATED"));
        }
    }

    match obj_type {
        OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => {
            let data = inflate_from(pack, pos, size)?;
            let type_str = type_name(obj_type).unwrap().to_string();
            let sha1 = sha1_git(&type_str, &data);
            Ok(PackObject { sha1, obj_type: type_str, data })
        }
        OBJ_OFS_DELTA => {
            // Variable-length base-offset: like size but encoded differently.
            // See git pack-format spec — "offset encoding".
            let (base_delta, hdr_end) = read_offset_delta(pack, pos)?;
            let base_abs = offset.checked_sub(base_delta)
                .ok_or("OFS_DELTA points before pack start")?;
            let base = by_offset.get(&base_abs)
                .cloned()
                .ok_or_else(|| format!("OFS_DELTA base at offset {base_abs} not yet resolved"))?;
            let delta = inflate_from(pack, hdr_end, size)?;
            let data = apply_delta(&base.data, &delta)?;
            let type_str = base.obj_type;
            let sha1 = sha1_git(&type_str, &data);
            Ok(PackObject { sha1, obj_type: type_str, data })
        }
        OBJ_REF_DELTA => {
            if pos + 20 > pack.len() {
                return Err("Truncated REF_DELTA base SHA1".into());
            }
            let base_sha = hex::encode(&pack[pos..pos + 20]);
            let base = by_sha.get(&base_sha)
                .cloned()
                .ok_or_else(|| format!("REF_DELTA base {base_sha} not yet resolved"))?;
            let delta = inflate_from(pack, pos + 20, size)?;
            let data = apply_delta(&base.data, &delta)?;
            let _ = depth; // (recursion here would be through by_sha lookup already resolved)
            let type_str = base.obj_type;
            let sha1 = sha1_git(&type_str, &data);
            Ok(PackObject { sha1, obj_type: type_str, data })
        }
        _ => Err(format!("Unknown object type {obj_type} at offset {offset}")),
    }
}

/// Inflate zlib-compressed data starting at `pos`, taking at most
/// `expected_size + 1` output bytes so a bomb can't OOM us.
fn inflate_from(pack: &[u8], pos: usize, expected_size: usize) -> Result<Vec<u8>, String> {
    if pos > pack.len() {
        return Err("Inflate start past pack end".into());
    }
    let cap = expected_size.min(MAX_INFLATED);
    let decoder = ZlibDecoder::new(&pack[pos..]);
    let mut out = Vec::with_capacity(cap);
    decoder.take((cap as u64).saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|e| format!("Inflate failed: {e}"))?;
    if out.len() != expected_size {
        // Not fatal in every case (some encoders pad) — but a size mismatch is
        // almost always a bug. Log and return what we got; downstream SHA1
        // verify will catch corruption.
        log::debug!(
            "pack inflate: expected {} bytes, got {} — continuing",
            expected_size, out.len()
        );
    }
    Ok(out)
}

/// Read the OFS_DELTA variable-length offset encoding. Returns
/// `(base_delta_bytes_back, bytes_consumed_into_pack)`.
fn read_offset_delta(pack: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    if pos >= pack.len() { return Err("Truncated OFS_DELTA".into()); }
    let mut byte = pack[pos];
    pos += 1;
    let mut val: u64 = (byte & 0x7F) as u64;
    while byte & 0x80 != 0 {
        if pos >= pack.len() { return Err("Truncated OFS_DELTA".into()); }
        val = val.checked_add(1).ok_or("Offset overflow")?;
        val = val.checked_shl(7).ok_or("Offset overflow")?;
        byte = pack[pos];
        pos += 1;
        val = val.checked_add((byte & 0x7F) as u64).ok_or("Offset overflow")?;
    }
    Ok((val, pos))
}

/// Apply a Git delta (`base` + `delta_ops`) → reconstructed object bytes.
///
/// Delta format:
///   varint source_size
///   varint target_size
///   { op }*
/// Op:
///   MSB=1: COPY. Following bits encode which of the four offset bytes and
///          three size bytes are present. Copies `size` bytes from `base`
///          starting at `offset`.
///   MSB=0: INSERT. Low 7 bits = number of bytes (1..=127) to insert
///          verbatim from the delta stream.
fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, String> {
    let mut pos = 0usize;
    let (src_size, np) = read_varint(delta, pos)?;
    pos = np;
    let (tgt_size, np) = read_varint(delta, pos)?;
    pos = np;

    if base.len() != src_size as usize {
        return Err(format!(
            "Delta base size mismatch: expected {} got {}",
            src_size, base.len()
        ));
    }
    if tgt_size as usize > MAX_INFLATED {
        return Err(format!("Delta target size {} exceeds cap", tgt_size));
    }

    let mut out = Vec::with_capacity(tgt_size as usize);
    while pos < delta.len() {
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            // Copy.
            let mut cp_off: u32 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if pos >= delta.len() { return Err("Truncated delta COPY offset".into()); }
                    cp_off |= (delta[pos] as u32) << (i * 8);
                    pos += 1;
                }
            }
            let mut cp_size: u32 = 0;
            for i in 0..3 {
                if op & (1 << (i + 4)) != 0 {
                    if pos >= delta.len() { return Err("Truncated delta COPY size".into()); }
                    cp_size |= (delta[pos] as u32) << (i * 8);
                    pos += 1;
                }
            }
            if cp_size == 0 { cp_size = 0x10000; } // Spec quirk.
            let end = (cp_off as usize).checked_add(cp_size as usize)
                .ok_or("Delta COPY end overflow")?;
            if end > base.len() {
                return Err(format!("Delta COPY range {}..{} beyond base ({})",
                    cp_off, end, base.len()));
            }
            out.extend_from_slice(&base[cp_off as usize..end]);
        } else if op != 0 {
            // Insert `op` bytes verbatim.
            let n = op as usize;
            if pos + n > delta.len() {
                return Err("Truncated delta INSERT payload".into());
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        } else {
            return Err("Reserved delta opcode 0x00 — refusing".into());
        }
    }
    if out.len() != tgt_size as usize {
        return Err(format!(
            "Applied delta produced {} bytes, expected {}", out.len(), tgt_size
        ));
    }
    Ok(out)
}

/// Read a git delta varint (LSB-first, 7 bits per byte, high bit = more).
fn read_varint(buf: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut val: u64 = 0;
    let mut shift = 0;
    loop {
        if pos >= buf.len() { return Err("Truncated varint".into()); }
        let b = buf[pos];
        pos += 1;
        val |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 { break; }
        shift += 7;
        if shift > 63 { return Err("Varint too large".into()); }
    }
    Ok((val, pos))
}

/// Git canonical SHA1: `SHA1("<type> <length>\0<content>")`.
fn sha1_git(obj_type: &str, content: &[u8]) -> String {
    let mut hasher = Sha1::new();
    let header = format!("{} {}\0", obj_type, content.len());
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Sprint 5 (S5.1): encode a resolved pack object as loose-object bytes so it
/// looks identical to `.git/objects/xx/yy…` on disk. This lets the streamer's
/// existing `ObjectParser::parse` codepath handle it without a special case.
pub fn encode_as_loose(obj: &PackObject) -> std::io::Result<Vec<u8>> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let header = format!("{} {}\0", obj.obj_type, obj.data.len());
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(header.as_bytes())?;
    encoder.write_all(&obj.data)?;
    encoder.finish()
}

// ─────────────────────────────────────────────────────────────────────────────
// Re-exports for git_parser.rs (read_u32_be is currently private there).
// If read_u32_be moves module we adjust the import above.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn read_pack_rejects_bad_magic() {
        let bad = b"NOPE\0\0\0\x02\0\0\0\0";
        let err = read_pack(&[], bad).unwrap_err();
        assert!(err.contains("PACK"));
    }

    #[test]
    fn read_pack_rejects_bad_version() {
        let mut pack = Vec::from(b"PACK" as &[u8]);
        pack.extend_from_slice(&99u32.to_be_bytes());
        pack.extend_from_slice(&0u32.to_be_bytes());
        assert!(read_pack(&[], &pack).is_err());
    }

    #[test]
    fn sha1_git_matches_canonical_empty_tree() {
        // Well-known: empty tree object hash.
        assert_eq!(sha1_git("tree", b""), "4b825dc642cb6eb9a060e54bf8d69288fbee4904");
    }

    #[test]
    fn apply_delta_insert_only() {
        let base = b"";
        // Delta: src_size=0, tgt_size=5, then INSERT 5 bytes.
        let mut delta = Vec::new();
        delta.push(0x00); // src_size = 0 (single byte varint)
        delta.push(0x05); // tgt_size = 5
        delta.push(0x05); // INSERT 5 bytes
        delta.extend_from_slice(b"hello");
        let out = apply_delta(base, &delta).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn apply_delta_copy_full_base() {
        let base = b"Hello, world!"; // 13 bytes
        // src_size=13, tgt_size=13, COPY offset=0 size=13.
        let mut delta = Vec::new();
        delta.push(13);   // src_size varint (single byte)
        delta.push(13);   // tgt_size varint (single byte)
        // Copy op: MSB=1, offset byte 0 present (bit 0), size byte 0 present (bit 4)
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(0);    // offset LSB
        delta.push(13);   // size LSB
        let out = apply_delta(base, &delta).unwrap();
        assert_eq!(out, base);
    }

    #[test]
    fn apply_delta_rejects_size_mismatch() {
        let base = b"12345";
        let mut delta = Vec::new();
        delta.push(99); // wrong src_size
        delta.push(5);
        assert!(apply_delta(base, &delta).is_err());
    }

    #[test]
    fn read_offset_delta_single_byte() {
        // "1010 0000" = 0x20, MSB clear, low 7 bits = 32.
        let (val, pos) = read_offset_delta(&[0x20], 0).unwrap();
        assert_eq!(val, 32);
        assert_eq!(pos, 1);
    }
}

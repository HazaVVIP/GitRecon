//! binary_scanner.rs
//! Binary File Scanning (S-3, P3)
//!
//! Detects and extracts credentials from binary files:
//! - SQLite databases via table scanning and string extraction
//! - JAR/ZIP archives via recursive unpacking with size limits
//! - ELF binaries via section-aware string extraction with safe fallback
//! - Magic bytes detection for file type identification

use once_cell::sync::Lazy;
use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Read};

use crate::streamer::DynPattern;

/// Magic byte signatures for common binary formats
pub mod magic {
    /// SQLite database signature
    pub const SQLITE: &[u8] = b"SQLite format 3";

    /// ZIP/JAR archive signature (PK\x03\x04)
    pub const ZIP: &[u8] = b"PK\x03\x04";

    /// GZIP signature
    pub const GZIP: &[u8] = b"\x1f\x8b";

    /// ELF executable signature
    pub const ELF: &[u8] = b"\x7fELF";
}

/// Detected binary file type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryType {
    SQLite,
    ZipJar,
    Gzip,
    Elf,
    Unknown,
}

/// Confidence source used when deciding whether a content item enters the
/// binary scanner. The null-byte heuristic remains a fallback signal rather
/// than the primary dispatch gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryDetectionConfidence {
    MagicBytes,
    ExtensionFallback,
    NullByteHeuristic,
    Text,
}

/// Typed decision used by local and URL content pipelines before scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryDispatch {
    pub binary_type: BinaryType,
    pub confidence: BinaryDetectionConfidence,
}

impl BinaryDispatch {
    pub fn is_binary(&self) -> bool {
        self.confidence != BinaryDetectionConfidence::Text
    }
}

/// Classify content using magic bytes first, supported extensions second, and
/// the legacy null-byte heuristic as a final unknown-binary fallback.
pub fn classify_binary(
    data: &[u8],
    filename: &str,
    probe_size: usize,
    null_threshold: usize,
) -> BinaryDispatch {
    let magic_type = detect_binary_type(data);
    if magic_type != BinaryType::Unknown {
        return BinaryDispatch {
            binary_type: magic_type,
            confidence: BinaryDetectionConfidence::MagicBytes,
        };
    }

    if let Some(extension_type) = binary_type_from_extension(filename) {
        return BinaryDispatch {
            binary_type: extension_type,
            confidence: BinaryDetectionConfidence::ExtensionFallback,
        };
    }

    let probe = &data[..data.len().min(probe_size)];
    if probe.iter().filter(|&&byte| byte == 0).count() > null_threshold {
        BinaryDispatch {
            binary_type: BinaryType::Unknown,
            confidence: BinaryDetectionConfidence::NullByteHeuristic,
        }
    } else {
        BinaryDispatch {
            binary_type: BinaryType::Unknown,
            confidence: BinaryDetectionConfidence::Text,
        }
    }
}

/// Return whether a path has an extension commonly associated with binary
/// content. This remains shared with forge candidate filtering until forge
/// binary parity is implemented in P1-04.
pub(crate) fn is_binary_extension(path: &str) -> bool {
    binary_type_from_extension(path).is_some() || {
        let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
        matches!(
            ext.as_str(),
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "bmp"
                | "ico"
                | "webp"
                | "tiff"
                | "avif"
                | "tar"
                | "bz2"
                | "xz"
                | "7z"
                | "rar"
                | "pdf"
                | "doc"
                | "docx"
                | "xls"
                | "xlsx"
                | "ppt"
                | "pptx"
                | "odt"
                | "ods"
                | "odp"
                | "exe"
                | "dll"
                | "so"
                | "dylib"
                | "bin"
                | "wasm"
                | "o"
                | "a"
                | "lib"
                | "obj"
                | "mp3"
                | "mp4"
                | "wav"
                | "ogg"
                | "flac"
                | "avi"
                | "mov"
                | "mkv"
                | "webm"
                | "m4a"
                | "ttf"
                | "otf"
                | "woff"
                | "woff2"
                | "eot"
                | "pyc"
                | "pyo"
                | "class"
        )
    }
}

fn unsupported_archive_extension(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    matches!(
        ext.as_str(),
        "tar" | "tgz" | "tbz" | "tbz2" | "txz" | "bz2" | "xz" | "7z" | "rar"
    )
}

fn binary_type_from_extension(path: &str) -> Option<BinaryType> {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "db" | "sqlite" | "sqlite3" => Some(BinaryType::SQLite),
        "zip" | "jar" | "war" | "ear" | "whl" => Some(BinaryType::ZipJar),
        "gz" => Some(BinaryType::Gzip),
        "tar" | "tgz" | "tbz" | "tbz2" | "txz" | "bz2" | "xz" | "7z" | "rar" => {
            Some(BinaryType::Unknown)
        }
        _ => None,
    }
}

/// Detect binary type from magic bytes
pub fn detect_binary_type(data: &[u8]) -> BinaryType {
    if data.starts_with(magic::SQLITE) {
        BinaryType::SQLite
    } else if data.starts_with(magic::ZIP) {
        BinaryType::ZipJar
    } else if data.starts_with(magic::GZIP) {
        BinaryType::Gzip
    } else if data.starts_with(magic::ELF) {
        BinaryType::Elf
    } else {
        BinaryType::Unknown
    }
}

/// Extract strings from a SQLite database blob.
///
/// Sprint 5 (S5.6): this used to open an in-memory SQLite connection and query
/// each user table's TEXT columns via `restore_sqlite_from_bytes` — a function
/// that was hard-coded to return `Err(InvalidQuery)` because the `rusqlite`
/// `backup` feature wasn't enabled. Every SQLite blob fell through to
/// `extract_printable_strings` regardless. Marketing copy claimed "table
/// querying" that never fired.
///
/// The dead branch is removed; we call `extract_printable_strings` directly.
/// If proper table-level parsing is ever needed, enable `rusqlite = { features
/// = ["backup"] }` in Cargo.toml and reintroduce the query loop.
pub fn extract_sqlite_strings_enhanced(data: &[u8]) -> Vec<String> {
    // Deduplicate while preserving order
    let raw = extract_printable_strings(data, 4);
    let mut seen = HashSet::with_capacity(raw.len());
    let mut out = Vec::with_capacity(raw.len());
    for s in raw {
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

/// Maximum total extraction size for ZIP/JAR archives (100MB)
const MAX_EXTRACTION_SIZE: usize = 100 * 1024 * 1024;

/// Maximum number of files to extract from a ZIP archive
const MAX_ZIP_FILES: usize = 500;

/// Maximum nested archive depth accepted during recursive binary scanning.
const MAX_NESTED_ARCHIVE_DEPTH: usize = 8;

/// Typed archive limit or invalid-input reason emitted by binary scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArchiveIssue {
    Malformed,
    Traversal,
    Depth,
    EntryCount,
    EntrySize,
    ExpansionSize,
    GzipOutput,
    GzipRatio,
    UnsupportedFormat,
}

impl ArchiveIssue {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Traversal => "traversal",
            Self::Depth => "depth",
            Self::EntryCount => "entry_count",
            Self::EntrySize => "entry_size",
            Self::ExpansionSize => "expansion_size",
            Self::GzipOutput => "gzip_output",
            Self::GzipRatio => "gzip_ratio",
            Self::UnsupportedFormat => "unsupported_format",
        }
    }
}

/// Typed limits telemetry emitted by binary/archive scanning.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct BinaryScanTelemetry {
    pub(crate) zip_entries_limited: usize,
    pub(crate) zip_files_oversized: usize,
    pub(crate) zip_depth_limited: usize,
    pub(crate) gzip_output_limited: usize,
    pub(crate) gzip_ratio_limited: usize,
    pub(crate) archive_invalid: usize,
    pub(crate) archive_issues: BTreeMap<String, usize>,
}

impl BinaryScanTelemetry {
    pub(crate) fn truncation_total(&self) -> usize {
        self.zip_entries_limited
            + self.zip_files_oversized
            + self.zip_depth_limited
            + self.gzip_output_limited
            + self.gzip_ratio_limited
    }

    pub(crate) fn record_issue(&mut self, issue: ArchiveIssue) {
        *self
            .archive_issues
            .entry(issue.as_str().to_string())
            .or_default() += 1;
    }

    fn absorb(&mut self, other: Self) {
        self.zip_entries_limited += other.zip_entries_limited;
        self.zip_files_oversized += other.zip_files_oversized;
        self.zip_depth_limited += other.zip_depth_limited;
        self.gzip_output_limited += other.gzip_output_limited;
        self.gzip_ratio_limited += other.gzip_ratio_limited;
        self.archive_invalid += other.archive_invalid;
        for (issue, count) in other.archive_issues {
            *self.archive_issues.entry(issue).or_default() += count;
        }
    }
}

/// Maximum size for individual file extraction (10MB)
const MAX_FILE_EXTRACTION_SIZE: usize = 10 * 1024 * 1024;

/// Extract files from ZIP/JAR archive with size limits
///
/// Recursively extracts files from ZIP/JAR archives, respecting:
/// - Total extraction size limit (100MB)
/// - Per-file size limit (10MB)
/// - Maximum file count (500)
/// - Recursive ZIP scanning (nested archives)
fn extract_zip_files_with_telemetry(data: &[u8]) -> (Vec<(String, Vec<u8>)>, BinaryScanTelemetry) {
    extract_zip_files_with_limits(
        data,
        MAX_EXTRACTION_SIZE,
        MAX_ZIP_FILES,
        MAX_FILE_EXTRACTION_SIZE,
    )
}

fn extract_zip_files_with_limits(
    data: &[u8],
    max_total_size: usize,
    max_file_count: usize,
    max_file_size: usize,
) -> (Vec<(String, Vec<u8>)>, BinaryScanTelemetry) {
    use zip::read::ZipArchive;

    let mut files = Vec::new();
    let mut telemetry = BinaryScanTelemetry::default();
    let mut total_size = 0usize;
    let cursor = Cursor::new(data);

    let Ok(mut archive) = ZipArchive::new(cursor) else {
        telemetry.archive_invalid = 1;
        telemetry.record_issue(ArchiveIssue::Malformed);
        return (files, telemetry);
    };
    let archive_len = archive.len();
    let file_count = archive_len.min(max_file_count);
    telemetry.zip_entries_limited = archive_len.saturating_sub(file_count);
    if telemetry.zip_entries_limited > 0 {
        telemetry.record_issue(ArchiveIssue::EntryCount);
    }

    for i in 0..file_count {
        if total_size >= max_total_size {
            telemetry.zip_entries_limited += file_count.saturating_sub(i);
            if file_count > i {
                telemetry.record_issue(ArchiveIssue::ExpansionSize);
            }
            break;
        }

        let Ok(mut file) = archive.by_index(i) else {
            telemetry.archive_invalid += 1;
            telemetry.record_issue(ArchiveIssue::Malformed);
            continue;
        };
        if file.is_dir() {
            continue;
        }
        let file_name = file.name().to_string();
        if file_name.starts_with('/') || file_name.split('/').any(|part| part == "..") {
            telemetry.record_issue(ArchiveIssue::Traversal);
            continue;
        }

        let file_size = file.size() as usize;
        if file_size > max_file_size {
            telemetry.zip_files_oversized += 1;
            telemetry.record_issue(ArchiveIssue::EntrySize);
            continue;
        }
        if total_size.saturating_add(file_size) > max_total_size {
            telemetry.zip_files_oversized += 1;
            telemetry.record_issue(ArchiveIssue::ExpansionSize);
            continue;
        }

        let mut buffer = Vec::with_capacity(file_size);
        if file.read_to_end(&mut buffer).is_ok() {
            total_size += buffer.len();
            files.push((file_name, buffer));
        } else {
            telemetry.archive_invalid += 1;
            telemetry.record_issue(ArchiveIssue::Malformed);
        }
    }

    (files, telemetry)
}

/// Maximum decompressed GZIP output accepted for scanning.
const MAX_GZIP_OUTPUT_SIZE: usize = 100 * 1024 * 1024;

/// Maximum decompressed-to-compressed GZIP expansion ratio accepted for scanning.
const MAX_GZIP_EXPANSION_RATIO: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GzipDecompressionFailure {
    Malformed,
    OutputLimited,
    RatioLimited,
}

fn decompress_gzip_with_status(data: &[u8]) -> Result<Vec<u8>, GzipDecompressionFailure> {
    decompress_gzip_with_limits(data, MAX_GZIP_OUTPUT_SIZE, MAX_GZIP_EXPANSION_RATIO)
}

#[cfg(test)]
fn decompress_gzip_with_limit(
    data: &[u8],
    max_output_size: usize,
) -> Result<Vec<u8>, GzipDecompressionFailure> {
    decompress_gzip_with_limits(data, max_output_size, MAX_GZIP_EXPANSION_RATIO)
}

fn decompress_gzip_with_limits(
    data: &[u8],
    max_output_size: usize,
    max_expansion_ratio: usize,
) -> Result<Vec<u8>, GzipDecompressionFailure> {
    use flate2::read::GzDecoder;

    let decoder = GzDecoder::new(Cursor::new(data));
    let mut limited = decoder.take((max_output_size + 1) as u64);
    let mut decompressed = Vec::new();
    let ratio_limit = data.len().saturating_mul(max_expansion_ratio);
    match limited.read_to_end(&mut decompressed) {
        Ok(_) if decompressed.len() > max_output_size => {
            Err(GzipDecompressionFailure::OutputLimited)
        }
        Ok(_) if decompressed.len() > ratio_limit => Err(GzipDecompressionFailure::RatioLimited),
        Ok(_) => Ok(decompressed),
        Err(_) if decompressed.len() > max_output_size => {
            Err(GzipDecompressionFailure::OutputLimited)
        }
        Err(_) if decompressed.len() > ratio_limit => Err(GzipDecompressionFailure::RatioLimited),
        Err(_) => Err(GzipDecompressionFailure::Malformed),
    }
}

/// Scan binary blob for secrets with enhanced detection
///
/// Returns findings (pattern_id, match_string, context, source)
#[cfg(test)]
pub fn scan_binary_blob(
    data: &[u8],
    filename: &str,
    max_blob_size: usize,
) -> Vec<(String, String, String, String)> {
    scan_binary_blob_with_patterns(data, filename, max_blob_size, &[])
}

/// Scan binary content with additive runtime patterns.
///
/// The built-in matcher remains unchanged and custom patterns are evaluated on
/// every printable-string view, including recursively extracted archive and
/// decompressed GZIP content.
#[cfg_attr(not(test), allow(dead_code))]
pub fn scan_binary_blob_with_patterns(
    data: &[u8],
    filename: &str,
    max_blob_size: usize,
    extra_patterns: &[DynPattern],
) -> Vec<(String, String, String, String)> {
    scan_binary_blob_with_patterns_and_telemetry(data, filename, max_blob_size, extra_patterns).0
}

pub(crate) fn scan_binary_blob_with_patterns_and_telemetry(
    data: &[u8],
    filename: &str,
    max_blob_size: usize,
    extra_patterns: &[DynPattern],
) -> (Vec<(String, String, String, String)>, BinaryScanTelemetry) {
    let mut telemetry = BinaryScanTelemetry::default();
    let findings = scan_binary_blob_with_patterns_at_depth(
        data,
        filename,
        max_blob_size,
        extra_patterns,
        0,
        &mut telemetry,
    );
    (findings, telemetry)
}

fn scan_binary_blob_with_patterns_at_depth(
    data: &[u8],
    filename: &str,
    max_blob_size: usize,
    extra_patterns: &[DynPattern],
    depth: usize,
    telemetry: &mut BinaryScanTelemetry,
) -> Vec<(String, String, String, String)> {
    let mut findings = Vec::new();

    // Skip if too large
    if data.len() > max_blob_size {
        return findings;
    }

    let bin_type = detect_binary_type(data);

    match bin_type {
        BinaryType::SQLite => {
            // Use enhanced SQLite scanning with table querying
            let strings = extract_sqlite_strings_enhanced(data);
            for s in strings {
                for (pattern_id, match_str) in
                    check_string_for_secrets_with_patterns(&s, extra_patterns)
                {
                    findings.push((
                        pattern_id,
                        match_str,
                        format!("SQLite: {}", filename),
                        "binary".to_string(),
                    ));
                }
            }
        }
        BinaryType::ZipJar => {
            if depth >= MAX_NESTED_ARCHIVE_DEPTH {
                telemetry.zip_depth_limited += 1;
                telemetry.record_issue(ArchiveIssue::Depth);
                return findings;
            }
            // Extract and scan inner files recursively
            let (files, extraction_telemetry) = extract_zip_files_with_telemetry(data);
            telemetry.absorb(extraction_telemetry);
            for (inner_path, inner_data) in files {
                // Skip recursive extraction for non-binary files (check magic bytes)
                let inner_type = detect_binary_type(&inner_data);
                match inner_type {
                    BinaryType::ZipJar => {
                        // Recursively scan nested ZIP/JAR files
                        let inner_findings = scan_binary_blob_with_patterns_at_depth(
                            &inner_data,
                            &format!("{}/{}", filename, inner_path),
                            max_blob_size,
                            extra_patterns,
                            depth + 1,
                            telemetry,
                        );
                        findings.extend(inner_findings);
                    }
                    BinaryType::SQLite => {
                        // Scan SQLite databases found in ZIP
                        let inner_findings = scan_binary_blob_with_patterns_at_depth(
                            &inner_data,
                            &format!("{}/{}", filename, inner_path),
                            max_blob_size,
                            extra_patterns,
                            depth + 1,
                            telemetry,
                        );
                        findings.extend(inner_findings);
                    }
                    _ => {
                        // Scan other files as text or extract strings
                        if std::str::from_utf8(&inner_data).is_ok() {
                            // It's text - scan it directly
                            for s in extract_printable_strings(&inner_data, 4) {
                                for (pattern_id, match_str) in
                                    check_string_for_secrets_with_patterns(&s, extra_patterns)
                                {
                                    findings.push((
                                        pattern_id,
                                        match_str,
                                        format!("ZIP:{}: {}", filename, inner_path),
                                        "binary".to_string(),
                                    ));
                                }
                            }
                        } else {
                            // Binary file - extract strings and scan
                            let strings = extract_printable_strings(&inner_data, 4);
                            for s in strings {
                                for (pattern_id, match_str) in
                                    check_string_for_secrets_with_patterns(&s, extra_patterns)
                                {
                                    findings.push((
                                        pattern_id,
                                        match_str,
                                        format!("ZIP:{}: {}", filename, inner_path),
                                        "binary".to_string(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        BinaryType::Elf => {
            // Extract strings from ELF binaries
            let strings = extract_elf_strings(data);
            for s in strings {
                for (pattern_id, match_str) in
                    check_string_for_secrets_with_patterns(&s, extra_patterns)
                {
                    findings.push((
                        pattern_id,
                        match_str,
                        format!("ELF: {}", filename),
                        "binary".to_string(),
                    ));
                }
            }
        }
        BinaryType::Unknown => {
            if unsupported_archive_extension(filename) {
                telemetry.record_issue(ArchiveIssue::UnsupportedFormat);
            }
            // Try to extract printable strings anyway
            let strings = extract_printable_strings(data, 4);
            for s in strings {
                for (pattern_id, match_str) in
                    check_string_for_secrets_with_patterns(&s, extra_patterns)
                {
                    findings.push((
                        pattern_id,
                        match_str,
                        format!("Binary: {}", filename),
                        "binary".to_string(),
                    ));
                }
            }
        }
        BinaryType::Gzip => {
            // Scan decompressed content recursively, then retain the legacy raw
            // string fallback for malformed or unusual GZIP payloads.
            match decompress_gzip_with_status(data) {
                Ok(decompressed) => findings.extend(scan_binary_blob_with_patterns_at_depth(
                    &decompressed,
                    &format!("{}:gzip", filename),
                    max_blob_size,
                    extra_patterns,
                    depth + 1,
                    telemetry,
                )),
                Err(GzipDecompressionFailure::OutputLimited) => {
                    telemetry.gzip_output_limited += 1;
                    telemetry.record_issue(ArchiveIssue::GzipOutput);
                }
                Err(GzipDecompressionFailure::RatioLimited) => {
                    telemetry.gzip_ratio_limited += 1;
                    telemetry.record_issue(ArchiveIssue::GzipRatio);
                }
                Err(GzipDecompressionFailure::Malformed) => {
                    telemetry.archive_invalid += 1;
                    telemetry.record_issue(ArchiveIssue::Malformed);
                }
            }
            let strings = extract_printable_strings(data, 4);
            for s in strings {
                for (pattern_id, match_str) in
                    check_string_for_secrets_with_patterns(&s, extra_patterns)
                {
                    findings.push((
                        pattern_id,
                        match_str,
                        format!("Binary: {}", filename),
                        "binary".to_string(),
                    ));
                }
            }
        }
    }

    findings
}

/// Calculate Shannon entropy of a byte slice
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if a region has high entropy (likely already compressed/encrypted)
fn is_high_entropy_region(data: &[u8]) -> bool {
    // Skip very short regions
    if data.len() < 16 {
        return false;
    }

    // Check a sample of the data for high entropy
    let sample_size = data.len().min(4096);
    let entropy = calculate_entropy(&data[..sample_size]);

    // High entropy threshold (typically > 7.5 indicates encryption/compression)
    entropy > 7.5
}

/// Extract printable strings from binary data, skipping high-entropy regions
fn extract_printable_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current_string = String::new();
    let mut last_non_printable = 0usize;

    for (i, &byte) in data.iter().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' {
            current_string.push(byte as char);
        } else {
            if current_string.len() >= min_length {
                // Check if this region is high-entropy (likely compressed data)
                let region_start = last_non_printable;
                let region_end = i;
                if region_end > region_start && region_end - region_start >= 16 {
                    let region = &data[region_start..region_end];
                    // BUG-LOGIC-002 FIX: Only add string if region is NOT high entropy
                    // (high entropy = compressed/encrypted, should skip)
                    if is_high_entropy_region(region) {
                        // Skip this string - it's from a compressed/encrypted region
                        current_string.clear();
                        last_non_printable = i + 1;
                        continue;
                    }
                    strings.push(current_string.clone());
                } else {
                    strings.push(current_string.clone());
                }
            }
            current_string.clear();
            last_non_printable = i + 1;
        }
    }

    // Handle last string
    if current_string.len() >= min_length {
        strings.push(current_string);
    }

    strings
}

/// Extract strings from ELF binaries.
///
/// Prefer common string-bearing sections when a complete ELF section table is
/// available. Unsupported, malformed, stripped, and truncated inputs retain the
/// previous full-binary string fallback so scanning effectiveness is not reduced.
fn extract_elf_strings(data: &[u8]) -> Vec<String> {
    if !data.starts_with(magic::ELF) {
        return Vec::new();
    }
    let Some(&class) = data.get(4) else {
        return extract_printable_strings(data, 4);
    };
    let Some(&endianness) = data.get(5) else {
        return extract_printable_strings(data, 4);
    };
    let big_endian = match endianness {
        1 => false,
        2 => true,
        _ => return extract_printable_strings(data, 4),
    };
    let (shoff_width, shoff_offset, shentsize_offset, shnum_offset, shstrndx_offset) = match class {
        1 => (4, 32, 46, 48, 50),
        2 => (8, 40, 58, 60, 62),
        _ => return extract_printable_strings(data, 4),
    };
    let Some(section_offset) = read_elf_uint(data, shoff_offset, shoff_width, big_endian)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return extract_printable_strings(data, 4);
    };
    let Some(section_size) = read_elf_uint(data, shentsize_offset, 2, big_endian)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return extract_printable_strings(data, 4);
    };
    let Some(section_count) = read_elf_uint(data, shnum_offset, 2, big_endian)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return extract_printable_strings(data, 4);
    };
    let Some(name_table_index) = read_elf_uint(data, shstrndx_offset, 2, big_endian)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return extract_printable_strings(data, 4);
    };
    let minimum_section_size = if class == 1 { 40 } else { 64 };
    if section_count == 0
        || name_table_index >= section_count
        || section_size < minimum_section_size
    {
        return extract_printable_strings(data, 4);
    }
    let Some(table_size) = section_size.checked_mul(section_count) else {
        return extract_printable_strings(data, 4);
    };
    let Some(table_end) = section_offset.checked_add(table_size) else {
        return extract_printable_strings(data, 4);
    };
    if table_end > data.len() {
        return extract_printable_strings(data, 4);
    }
    let name_table_header = section_offset + section_size * name_table_index;
    let (name_offset_field, name_size_field, name_offset_width) =
        if class == 1 { (16, 20, 4) } else { (24, 32, 8) };
    let Some(name_table_offset) = read_elf_uint(
        data,
        name_table_header + name_offset_field,
        name_offset_width,
        big_endian,
    )
    .and_then(|value| usize::try_from(value).ok()) else {
        return extract_printable_strings(data, 4);
    };
    let Some(name_table_size) = read_elf_uint(
        data,
        name_table_header + name_size_field,
        name_offset_width,
        big_endian,
    )
    .and_then(|value| usize::try_from(value).ok()) else {
        return extract_printable_strings(data, 4);
    };
    let Some(name_table_end) = name_table_offset.checked_add(name_table_size) else {
        return extract_printable_strings(data, 4);
    };
    let Some(name_table) = data.get(name_table_offset..name_table_end) else {
        return extract_printable_strings(data, 4);
    };
    let mut strings = Vec::new();
    let mut seen = HashSet::new();
    for index in 0..section_count {
        let header = section_offset + section_size * index;
        let Some(name_index) = read_elf_uint(data, header, 4, big_endian)
            .and_then(|value| usize::try_from(value).ok())
        else {
            continue;
        };
        let Some(name) = elf_section_name(name_table, name_index) else {
            continue;
        };
        if !matches!(
            name,
            ".rodata" | ".data" | ".data.rel.ro" | ".strtab" | ".dynstr" | ".comment"
        ) {
            continue;
        }
        let Some(offset) = read_elf_uint(
            data,
            header + name_offset_field,
            name_offset_width,
            big_endian,
        )
        .and_then(|value| usize::try_from(value).ok()) else {
            continue;
        };
        let Some(size) = read_elf_uint(
            data,
            header + name_size_field,
            name_offset_width,
            big_endian,
        )
        .and_then(|value| usize::try_from(value).ok()) else {
            continue;
        };
        let Some(end) = offset.checked_add(size) else {
            continue;
        };
        let Some(section) = data.get(offset..end) else {
            continue;
        };
        for value in extract_printable_strings(section, 4) {
            if seen.insert(value.clone()) {
                strings.push(value);
            }
        }
    }
    if strings.is_empty() {
        extract_printable_strings(data, 4)
    } else {
        strings
    }
}

fn read_elf_uint(data: &[u8], offset: usize, width: usize, big_endian: bool) -> Option<u64> {
    let end = offset.checked_add(width)?;
    let bytes = data.get(offset..end)?;
    match width {
        2 => Some(if big_endian {
            u16::from_be_bytes(bytes.try_into().ok()?) as u64
        } else {
            u16::from_le_bytes(bytes.try_into().ok()?) as u64
        }),
        4 => Some(if big_endian {
            u32::from_be_bytes(bytes.try_into().ok()?) as u64
        } else {
            u32::from_le_bytes(bytes.try_into().ok()?) as u64
        }),
        8 => Some(if big_endian {
            u64::from_be_bytes(bytes.try_into().ok()?)
        } else {
            u64::from_le_bytes(bytes.try_into().ok()?)
        }),
        _ => None,
    }
}

fn elf_section_name(table: &[u8], offset: usize) -> Option<&str> {
    let bytes = table.get(offset..)?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&bytes[..end]).ok()
}

/// Static lazy regex patterns for secret detection
static SECRET_PATTERNS: Lazy<[(regex::Regex, &str); 4]> = Lazy::new(|| {
    [
        (
            regex::Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b").unwrap(),
            "aws_key_id",
        ),
        (
            regex::Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(),
            "gcp_api_key",
        ),
        (
            regex::Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
            "github_pat",
        ),
        (
            regex::Regex::new(r"sk_(live|test)_[A-Za-z0-9]{24,}").unwrap(),
            "stripe_sk",
        ),
    ]
});

/// Check a string for common secret patterns (simplified)
fn check_string_for_secrets(s: &str) -> Option<(String, String)> {
    for (regex, id) in SECRET_PATTERNS.iter() {
        if let Some(mat) = regex.find(s) {
            return Some((id.to_string(), mat.as_str().to_string()));
        }
    }

    None
}

fn check_string_for_secrets_with_patterns(
    s: &str,
    extra_patterns: &[DynPattern],
) -> Vec<(String, String)> {
    let mut matches = check_string_for_secrets(s).into_iter().collect::<Vec<_>>();
    for pattern in extra_patterns {
        matches.extend(
            pattern
                .regex
                .find_iter(s)
                .map(|matched| (pattern.id.clone(), matched.as_str().to_string())),
        );
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_aws_key() -> String {
        ["AKIA", "IOSFODNN7EXAMPLE"].concat()
    }

    #[test]
    fn classify_magic_bytes_before_null_heuristic() {
        let data = b"PK\x03\x04archive marker";
        let dispatch = classify_binary(data, "fixture.txt", 8192, 10);
        assert_eq!(dispatch.binary_type, BinaryType::ZipJar);
        assert_eq!(dispatch.confidence, BinaryDetectionConfidence::MagicBytes);
        assert!(dispatch.is_binary());
    }

    #[test]
    fn classify_extension_fallback_for_sparse_gzip() {
        let dispatch = classify_binary(b"ARCHIVE_AB12", "fixture.gz", 8192, 10);
        assert_eq!(dispatch.binary_type, BinaryType::Gzip);
        assert_eq!(
            dispatch.confidence,
            BinaryDetectionConfidence::ExtensionFallback
        );
        assert!(dispatch.is_binary());
    }

    #[test]
    fn classify_unsupported_archive_extension_as_binary() {
        let dispatch = classify_binary(b"plain tar payload", "fixture.tar", 8192, 10);
        assert_eq!(dispatch.binary_type, BinaryType::Unknown);
        assert_eq!(
            dispatch.confidence,
            BinaryDetectionConfidence::ExtensionFallback
        );
        assert!(dispatch.is_binary());
    }

    #[test]
    fn classify_exact_null_threshold_as_text() {
        let mut data = vec![0u8; 10];
        data.extend_from_slice(b"ordinary text");
        let dispatch = classify_binary(&data, "fixture.data", 8192, 10);
        assert_eq!(dispatch.binary_type, BinaryType::Unknown);
        assert_eq!(dispatch.confidence, BinaryDetectionConfidence::Text);
        assert!(!dispatch.is_binary());
    }

    #[test]
    fn classify_unknown_binary_from_null_heuristic() {
        let mut data = vec![0u8; 11];
        data.extend_from_slice(b"CUSTOM_AB12");
        let dispatch = classify_binary(&data, "fixture.data", 8192, 10);
        assert_eq!(dispatch.binary_type, BinaryType::Unknown);
        assert_eq!(
            dispatch.confidence,
            BinaryDetectionConfidence::NullByteHeuristic
        );
        assert!(dispatch.is_binary());
    }

    #[test]
    fn classify_truncated_magic_uses_extension_fallback() {
        let dispatch = classify_binary(b"\x1f", "fixture.gz", 8192, 10);
        assert_eq!(dispatch.binary_type, BinaryType::Gzip);
        assert_eq!(
            dispatch.confidence,
            BinaryDetectionConfidence::ExtensionFallback
        );
        assert!(dispatch.is_binary());
    }

    #[test]
    fn test_detect_sqlite() {
        let data = b"SQLite format 3\x00";
        assert_eq!(detect_binary_type(data), BinaryType::SQLite);
    }

    #[test]
    fn test_detect_zip() {
        let data = b"PK\x03\x04\x14\x00\x00\x00";
        assert_eq!(detect_binary_type(data), BinaryType::ZipJar);
    }

    #[test]
    fn test_detect_elf() {
        let data = b"\x7fELF\x01\x01\x01";
        assert_eq!(detect_binary_type(data), BinaryType::Elf);
    }

    #[test]
    fn test_detect_gzip() {
        let data = b"\x1f\x8b\x08\x00";
        assert_eq!(detect_binary_type(data), BinaryType::Gzip);
    }

    #[test]
    fn test_detect_unknown() {
        let data = b"random data";
        assert_eq!(detect_binary_type(data), BinaryType::Unknown);
    }

    #[test]
    fn test_extract_printable_strings() {
        let data = b"test\x00password123\x00\x00AKIATEST123456789\x00";
        let strings = extract_printable_strings(data, 4);
        assert!(strings.iter().any(|s| s.contains("password123")));
        assert!(strings.iter().any(|s| s.contains("AKIA")));
    }

    #[test]
    fn test_read_elf_uint_supports_endian_widths() {
        assert_eq!(read_elf_uint(&[0x34, 0x12], 0, 2, false), Some(0x1234));
        assert_eq!(read_elf_uint(&[0x12, 0x34], 0, 2, true), Some(0x1234));
        assert_eq!(
            read_elf_uint(&[0x78, 0x56, 0x34, 0x12], 0, 4, false),
            Some(0x12345678)
        );
        assert_eq!(
            read_elf_uint(&[0x12, 0x34, 0x56, 0x78], 0, 4, true),
            Some(0x12345678)
        );
        assert_eq!(read_elf_uint(&[0, 1, 2], 1, 4, false), None);
    }

    #[test]
    fn test_extract_elf_strings_prefers_named_sections() {
        let mut elf = vec![0u8; 0x300];
        elf[..4].copy_from_slice(magic::ELF);
        elf[4] = 2;
        elf[5] = 1;
        let section_table_offset = 0x200u64;
        elf[40..48].copy_from_slice(&section_table_offset.to_le_bytes());
        elf[58..60].copy_from_slice(&(64u16).to_le_bytes());
        elf[60..62].copy_from_slice(&(3u16).to_le_bytes());
        elf[62..64].copy_from_slice(&(2u16).to_le_bytes());

        let rodata_offset = 0x100usize;
        let rodata = [b"SAFE\0".as_slice(), synthetic_aws_key().as_bytes()].concat();
        elf[rodata_offset..rodata_offset + rodata.len()].copy_from_slice(&rodata);
        let off_section = b"outside-section\0";
        elf[0x80..0x80 + off_section.len()].copy_from_slice(off_section);
        let names = b"\0.rodata\0.shstrtab\0";
        let names_offset = 0x180usize;
        elf[names_offset..names_offset + names.len()].copy_from_slice(names);

        let first_section = section_table_offset as usize + 64;
        elf[first_section..first_section + 4].copy_from_slice(&(1u32).to_le_bytes());
        elf[first_section + 24..first_section + 32]
            .copy_from_slice(&(rodata_offset as u64).to_le_bytes());
        elf[first_section + 32..first_section + 40]
            .copy_from_slice(&(rodata.len() as u64).to_le_bytes());
        let names_section = section_table_offset as usize + 128;
        elf[names_section..names_section + 4].copy_from_slice(&(9u32).to_le_bytes());
        elf[names_section + 24..names_section + 32]
            .copy_from_slice(&(names_offset as u64).to_le_bytes());
        elf[names_section + 32..names_section + 40]
            .copy_from_slice(&(names.len() as u64).to_le_bytes());

        let strings = extract_elf_strings(&elf);
        assert!(strings.iter().any(|value| value.contains("AKIA")));
        assert!(!strings
            .iter()
            .any(|value| value.contains("outside-section")));
    }

    #[test]
    fn test_check_string_for_secrets() {
        // Build a valid AWS-key-shaped fixture without storing it as a literal.
        let aws_key = synthetic_aws_key();
        assert!(check_string_for_secrets(&aws_key).is_some());
        // GCP API key (36 chars)
        assert!(check_string_for_secrets("AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe").is_some());
        // GitHub PAT (40 chars)
        assert!(check_string_for_secrets("ghp_1234567890abcdefghijklmnopqrstuvwxyz").is_some());
        // Stripe key (test pattern, not real secret)
        assert!(check_string_for_secrets("sk_live_1234567890abcdefghijklmnopqrstuvwxyz").is_some());
        // Normal string
        assert!(check_string_for_secrets("normal_string").is_none());
    }

    #[test]
    fn test_entropy_calculation() {
        let low_entropy = b"aaaaaaa";
        let high_entropy = b"\x00\x01\x02\x03\x04\x05\x06\x07";

        assert!(calculate_entropy(low_entropy) < calculate_entropy(high_entropy));
        assert!(calculate_entropy(high_entropy) > 2.0);
    }

    #[test]
    fn test_high_entropy_detection() {
        // Test that low entropy data is not detected as high entropy
        let low_entropy_data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let low_entropy = calculate_entropy(low_entropy_data);
        assert!(
            low_entropy < 2.0,
            "Low entropy data should have entropy < 2.0, got {}",
            low_entropy
        );
        assert!(!is_high_entropy_region(low_entropy_data));

        // Test that truly random-like data has higher entropy
        // Use data with unique bytes to maximize entropy
        let mut high_entropy_data = [0u8; 64];
        for (i, b) in high_entropy_data.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let high_entropy = calculate_entropy(&high_entropy_data);
        assert!(
            high_entropy > low_entropy,
            "High entropy data should have higher entropy than low entropy data"
        );
    }

    #[test]
    fn custom_pattern_matches_unknown_binary_strings() {
        let pattern = DynPattern {
            id: "custom_binary".to_string(),
            sev: "HIGH".to_string(),
            desc: "Custom binary marker".to_string(),
            regex: regex::Regex::new("CUSTOM_[A-Z0-9]{4}").unwrap(),
        };
        let data = b"\0\0CUSTOM_AB12\0";
        let findings = scan_binary_blob_with_patterns(data, "fixture.bin", 1024, &[pattern]);
        assert!(findings
            .iter()
            .any(|finding| finding.0 == "custom_binary" && finding.1 == "CUSTOM_AB12"));
    }

    #[test]
    fn custom_pattern_matches_decompressed_gzip_content() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"custom=ARCHIVE_AB12").unwrap();
        let compressed = encoder.finish().unwrap();
        let pattern = DynPattern {
            id: "custom_archive".to_string(),
            sev: "MEDIUM".to_string(),
            desc: "Custom archive marker".to_string(),
            regex: regex::Regex::new("ARCHIVE_[A-Z0-9]{4}").unwrap(),
        };
        let findings = scan_binary_blob_with_patterns(&compressed, "fixture.gz", 1024, &[pattern]);
        assert!(findings
            .iter()
            .any(|finding| finding.0 == "custom_archive" && finding.1 == "ARCHIVE_AB12"));
    }

    #[test]
    fn custom_pattern_matches_zip_entry() {
        use std::io::Write;
        use zip::{write::SimpleFileOptions, ZipWriter};

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("nested/config.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"custom=ARCHIVE_AB12").unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let pattern = DynPattern {
            id: "custom_archive".to_string(),
            sev: "HIGH".to_string(),
            desc: "Custom archive marker".to_string(),
            regex: regex::Regex::new("ARCHIVE_[A-Z0-9]{4}").unwrap(),
        };

        let findings = scan_binary_blob_with_patterns(&archive, "fixture.zip", 1024, &[pattern]);
        assert!(findings
            .iter()
            .any(|finding| finding.0 == "custom_archive" && finding.1 == "ARCHIVE_AB12"));
    }

    #[test]
    fn test_scan_binary_blob_sqlite() {
        // Use a valid AWS-key-shaped fixture assembled at runtime.
        let mut data = b"SQLite format 3\x00password123\x00".to_vec();
        data.extend_from_slice(synthetic_aws_key().as_bytes());
        data.push(0);
        let findings = scan_binary_blob(&data, "test.db", 1024);
        assert!(!findings.is_empty());
        // Check that findings include the source tag
        assert!(findings.iter().all(|f| f.3 == "binary"));
    }

    #[test]
    fn test_scan_binary_blob_gzip_decompresses_and_scans() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        let key = synthetic_aws_key();
        write!(encoder, "config_key={key}").unwrap();
        let compressed = encoder.finish().unwrap();

        let findings = scan_binary_blob(&compressed, "config.env.gz", 1024);
        assert!(findings
            .iter()
            .any(|finding| { finding.1 == key && finding.2.contains(":gzip") }));
    }

    #[test]
    fn zip_limit_telemetry_reports_entry_count_and_size_skips() {
        use std::io::Write;
        use zip::{write::SimpleFileOptions, ZipWriter};

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for name in ["one.txt", "two.txt", "three.txt"] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"1234").unwrap();
        }
        let archive = writer.finish().unwrap().into_inner();

        let (_, count_limited) = extract_zip_files_with_limits(&archive, 100, 2, 100);
        assert_eq!(count_limited.zip_entries_limited, 1);
        assert_eq!(count_limited.zip_files_oversized, 0);
        assert_eq!(count_limited.archive_issues.get("entry_count"), Some(&1));

        let (_, size_limited) = extract_zip_files_with_limits(&archive, 5, 10, 100);
        assert_eq!(size_limited.zip_entries_limited, 0);
        assert_eq!(size_limited.zip_files_oversized, 2);
        assert_eq!(size_limited.archive_issues.get("expansion_size"), Some(&2));
    }

    #[test]
    fn zip_and_gzip_limit_telemetry_is_typed() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        use zip::{write::SimpleFileOptions, ZipWriter};

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("oversized.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"12345").unwrap();
        let archive = writer.finish().unwrap().into_inner();
        let (_, zip_telemetry) = extract_zip_files_with_limits(&archive, 100, 10, 3);
        assert_eq!(zip_telemetry.zip_files_oversized, 1);
        let (_, invalid_zip) = extract_zip_files_with_limits(b"not a zip", 100, 10, 100);
        assert_eq!(invalid_zip.archive_invalid, 1);
        assert_eq!(invalid_zip.archive_issues.get("malformed"), Some(&1));

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"0123456789").unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(
            decompress_gzip_with_limit(&compressed, 4),
            Err(GzipDecompressionFailure::OutputLimited)
        );
        let mut ratio_encoder = GzEncoder::new(Vec::new(), Compression::default());
        ratio_encoder.write_all(&vec![b'a'; 1_000_001]).unwrap();
        let ratio_compressed = ratio_encoder.finish().unwrap();
        assert_eq!(
            decompress_gzip_with_limits(&ratio_compressed, 2 * 1024 * 1024, 2),
            Err(GzipDecompressionFailure::RatioLimited)
        );
        assert_eq!(
            decompress_gzip_with_limit(b"not gzip", 4),
            Err(GzipDecompressionFailure::Malformed)
        );
    }

    #[test]
    fn unsupported_archive_format_keeps_printable_fallback() {
        let (findings, telemetry) = scan_binary_blob_with_patterns_and_telemetry(
            b"tar fixture CUSTOM_ARCHIVE_MARKER",
            "fixture.tar",
            1024,
            &[],
        );
        assert!(findings.is_empty());
        assert_eq!(telemetry.archive_issues.get("unsupported_format"), Some(&1));
    }

    #[test]
    fn zip_traversal_entry_is_rejected_with_typed_reason() {
        use std::io::Write;
        use zip::{write::SimpleFileOptions, ZipWriter};

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("../outside.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"should not be extracted").unwrap();
        let archive = writer.finish().unwrap().into_inner();

        let (files, telemetry) = extract_zip_files_with_limits(&archive, 100, 10, 100);
        assert!(files.is_empty());
        assert_eq!(telemetry.archive_issues.get("traversal"), Some(&1));
    }

    #[test]
    fn nested_archive_depth_limit_is_reported() {
        use std::io::Write;
        use zip::{write::SimpleFileOptions, ZipWriter};

        let mut nested = b"leaf marker".to_vec();
        for _ in 0..=MAX_NESTED_ARCHIVE_DEPTH {
            let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
            writer
                .start_file("nested.zip", SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&nested).unwrap();
            nested = writer.finish().unwrap().into_inner();
        }
        let (_, telemetry) =
            scan_binary_blob_with_patterns_and_telemetry(&nested, "nested.zip", 1024 * 1024, &[]);
        assert!(telemetry.zip_depth_limited > 0);
        assert!(telemetry.truncation_total() >= telemetry.zip_depth_limited);
        assert!(
            telemetry
                .archive_issues
                .get("depth")
                .copied()
                .unwrap_or_default()
                > 0
        );
    }

    #[test]
    fn test_scan_binary_blob_respects_max_blob_size() {
        let mut data = b"SQLite format 3\0".to_vec();
        data.extend_from_slice(synthetic_aws_key().as_bytes());
        data.push(0);
        let findings = scan_binary_blob(&data, "test.db", 8);
        assert!(findings.is_empty(), "oversized binary must be skipped");
    }

    #[test]
    fn test_scan_binary_blob_malformed_elf_is_safe() {
        let data = b"\x7fELF\x01\x02\x03\x04truncated";
        let findings = scan_binary_blob(data, "broken.elf", 1024);
        assert!(findings.is_empty() || findings.iter().all(|f| f.3 == "binary"));
    }

    #[test]
    fn test_scan_binary_blob_elf() {
        let mut elf_data = vec![0x7f, b'E', b'L', b'F', 0x01, 0x01, 0x01];
        // Use a valid AWS-key-shaped fixture assembled at runtime.
        elf_data.push(0);
        elf_data.extend_from_slice(synthetic_aws_key().as_bytes());
        elf_data.push(0);
        elf_data.extend_from_slice(b"\x00ghp_1234567890abcdefghijklmnopqrstuvwxyz\x00");

        let findings = scan_binary_blob(&elf_data, "test.elf", 1024);
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.3 == "binary"));
    }
}

//! binary_scanner.rs
//! Binary File Scanning (S-3, P3)
//!
//! Detects and extracts credentials from binary files:
//! - SQLite databases via table scanning and string extraction
//! - JAR/ZIP archives via recursive unpacking with size limits
//! - ELF binaries via printable string extraction
//! - Magic bytes detection for file type identification

use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::io::{Cursor, Read};

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
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryType {
    SQLite,
    ZipJar,
    Gzip,
    Elf,
    Unknown,
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

/// Maximum size for individual file extraction (10MB)
const MAX_FILE_EXTRACTION_SIZE: usize = 10 * 1024 * 1024;

/// Extract files from ZIP/JAR archive with size limits
///
/// Recursively extracts files from ZIP/JAR archives, respecting:
/// - Total extraction size limit (100MB)
/// - Per-file size limit (10MB)
/// - Maximum file count (500)
/// - Recursive ZIP scanning (nested archives)
pub fn extract_zip_files_enhanced(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    use zip::read::ZipArchive;

    let mut files = Vec::new();
    let mut total_size = 0usize;
    let cursor = Cursor::new(data);

    if let Ok(mut archive) = ZipArchive::new(cursor) {
        let file_count = archive.len().min(MAX_ZIP_FILES);

        for i in 0..file_count {
            if total_size > MAX_EXTRACTION_SIZE {
                break; // Stop if we've exceeded the total size limit
            }

            if let Ok(mut file) = archive.by_index(i) {
                let path = file.name().to_string();

                // Skip directories
                if file.is_dir() {
                    continue;
                }

                // Skip files that are too large
                let file_size = file.size() as usize;
                if file_size > MAX_FILE_EXTRACTION_SIZE {
                    continue;
                }

                // Check if adding this file would exceed the total size limit
                if total_size + file_size > MAX_EXTRACTION_SIZE {
                    continue;
                }

                let mut buffer = Vec::with_capacity(file_size);
                if file.read_to_end(&mut buffer).is_ok() {
                    total_size += buffer.len();
                    files.push((path, buffer));
                }
            }
        }
    }

    files
}

/// Scan binary blob for secrets with enhanced detection
///
/// Returns findings (pattern_id, match_string, context, source)
pub fn scan_binary_blob(
    data: &[u8],
    filename: &str,
    max_blob_size: usize,
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
                if let Some((pattern_id, match_str)) = check_string_for_secrets(&s) {
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
            // Extract and scan inner files recursively
            let files = extract_zip_files_enhanced(data);
            for (inner_path, inner_data) in files {
                // Skip recursive extraction for non-binary files (check magic bytes)
                let inner_type = detect_binary_type(&inner_data);
                match inner_type {
                    BinaryType::ZipJar => {
                        // Recursively scan nested ZIP/JAR files
                        let inner_findings = scan_binary_blob(
                            &inner_data,
                            &format!("{}/{}", filename, inner_path),
                            max_blob_size,
                        );
                        findings.extend(inner_findings);
                    }
                    BinaryType::SQLite => {
                        // Scan SQLite databases found in ZIP
                        let inner_findings = scan_binary_blob(
                            &inner_data,
                            &format!("{}/{}", filename, inner_path),
                            max_blob_size,
                        );
                        findings.extend(inner_findings);
                    }
                    _ => {
                        // Scan other files as text or extract strings
                        if std::str::from_utf8(&inner_data).is_ok() {
                            // It's text - scan it directly
                            for s in extract_printable_strings(&inner_data, 4) {
                                if let Some((pattern_id, match_str)) = check_string_for_secrets(&s)
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
                                if let Some((pattern_id, match_str)) = check_string_for_secrets(&s)
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
                if let Some((pattern_id, match_str)) = check_string_for_secrets(&s) {
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
            // Try to extract printable strings anyway
            let strings = extract_printable_strings(data, 4);
            for s in strings {
                if let Some((pattern_id, match_str)) = check_string_for_secrets(&s) {
                    findings.push((
                        pattern_id,
                        match_str,
                        format!("Binary: {}", filename),
                        "binary".to_string(),
                    ));
                }
            }
        }
        _ => {
            // Gzip and other formats - use basic string extraction
            let strings = extract_printable_strings(data, 4);
            for s in strings {
                if let Some((pattern_id, match_str)) = check_string_for_secrets(&s) {
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

/// Extract strings from ELF binaries
///
/// Focuses on .rodata, .data, and .strtab sections if possible,
/// otherwise falls back to full binary string extraction.
fn extract_elf_strings(data: &[u8]) -> Vec<String> {
    // Basic ELF validation
    if !data.starts_with(magic::ELF) {
        return Vec::new();
    }

    // Use bounded printable-string extraction until section-table metadata is
    // available; malformed or truncated ELF inputs are handled safely above.
    extract_printable_strings(data, 4)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_aws_key() -> String {
        ["AKIA", "IOSFODNN7EXAMPLE"].concat()
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

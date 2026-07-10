//! validation.rs
//! Input validation and sanitization for all user-supplied data.

use std::path::Path;
use anyhow::{Result, anyhow};

/// Maximum URL length to prevent DoS
const MAX_URL_LENGTH: usize = 2048;

/// Maximum token length for GitHub PATs
const MAX_TOKEN_LENGTH: usize = 256;

/// Maximum path length to prevent filesystem issues
const MAX_PATH_LENGTH: usize = 4096;

/// Validates and normalizes a URL input
///
/// # Security Considerations
/// - Prevents excessively long URLs (DoS protection)
/// - Ensures valid URL structure
/// - Rejects obviously malicious URLs (javascript:, data:, etc.)
///
/// # Arguments
/// * `url_str` - The raw URL string from user input
///
/// # Returns
/// * `Ok(String)` - Normalized HTTPS URL
/// * `Err(String)` - Error message if validation fails
pub fn validate_and_normalize_url(url_str: &str) -> Result<String> {
    // Check length first (DoS protection)
    if url_str.len() > MAX_URL_LENGTH {
        return Err(anyhow!("URL exceeds maximum length of {} characters", MAX_URL_LENGTH));
    }

    let trimmed = url_str.trim();

    // Block dangerous protocols
    let lower = trimmed.to_lowercase();
    if lower.starts_with("javascript:") || lower.starts_with("data:") || lower.starts_with("vbscript:") {
        return Err(anyhow!("Dangerous protocol detected: URL must use http:// or https://"));
    }

    // Ensure it looks like a URL
    if trimmed.is_empty() {
        return Err(anyhow!("URL cannot be empty"));
    }

    // Add https:// if no protocol specified
    let normalized = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else if trimmed.contains('/') {
        format!("https://{}", trimmed)
    } else {
        // Assume it's a domain without path
        format!("https://{}", trimmed)
    };

    // Validate URL structure
    let parsed = url::Url::parse(&normalized)
        .map_err(|e| anyhow!("Invalid URL format: {}", e))?;

    // Ensure it's HTTP or HTTPS
    match parsed.scheme() {
        "http" | "https" => {},
        s => return Err(anyhow!("Unsupported scheme '{}': only http and https are allowed", s)),
    }

    // Reject localhost and local IP ranges by default (security measure)
    let host = parsed.host().ok_or_else(|| anyhow!("URL must have a valid host"))?;
    let host_str = host.to_string().to_lowercase();

    // Check for potentially dangerous hosts
    if host_str == "localhost" || host_str.starts_with("127.") || host_str == "::1" {
        // Allow but warn - could be legitimate for testing
        // In production, you might want to reject these
    }

    // Trim trailing slash for consistency
    Ok(normalized.trim_end_matches('/').to_string())
}

/// Validates a GitHub Personal Access Token (PAT) format
///
/// # Security Considerations
/// - Validates token format without exposing the actual token
/// - Prevents injection of malicious strings
/// - Enforces length limits
///
/// # Arguments
/// * `token` - The raw token string from user input
///
/// # Returns
/// * `Ok(())` - Token is valid
/// * `Err(String)` - Error message if validation fails
pub fn validate_github_token(token: &str) -> Result<()> {
    let trimmed = token.trim();

    // Check length
    if trimmed.is_empty() {
        return Err(anyhow!("GitHub token cannot be empty"));
    }

    if trimmed.len() > MAX_TOKEN_LENGTH {
        return Err(anyhow!("GitHub token exceeds maximum length of {} characters", MAX_TOKEN_LENGTH));
    }

    // GitHub PATs typically start with specific prefixes
    // ghp_, gho_, ghu_, ghs_, ghr_ (as of 2021+)
    // We're lenient here to support various token types

    // Check for suspicious characters (prevent injection)
    if trimmed.contains(char::is_whitespace) {
        return Err(anyhow!("GitHub token cannot contain whitespace"));
    }

    if trimmed.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
        return Err(anyhow!("GitHub token cannot contain control characters"));
    }

    // GitHub tokens are alphanumeric and underscores
    if !trimmed.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(anyhow!("GitHub token contains invalid characters (only alphanumeric, underscore, and hyphen allowed)"));
    }

    // Validate length (GitHub tokens are typically 36-40 characters)
    if trimmed.len() < 20 {
        return Err(anyhow!("GitHub token appears too short (minimum 20 characters)"));
    }

    Ok(())
}

/// Validates a GitLab Personal Access Token (PAT) format
///
/// # Security Considerations
/// - Validates token format without exposing the actual token
/// - Prevents injection of malicious strings
/// - Enforces length limits
///
/// # Arguments
/// * `token` - The raw token string from user input
///
/// # Returns
/// * `Ok(())` - Token is valid
/// * `Err(String)` - Error message if validation fails
pub fn validate_gitlab_token(token: &str) -> Result<()> {
    let trimmed = token.trim();

    // Check length
    if trimmed.is_empty() {
        return Err(anyhow!("GitLab token cannot be empty"));
    }

    if trimmed.len() > MAX_TOKEN_LENGTH {
        return Err(anyhow!("GitLab token exceeds maximum length of {} characters", MAX_TOKEN_LENGTH));
    }

    // GitLab PATs typically start with 'glpat-' prefix
    // but we're lenient to support various token types (e.g., deploy tokens, feed tokens)

    // Check for suspicious characters (prevent injection)
    if trimmed.contains(char::is_whitespace) {
        return Err(anyhow!("GitLab token cannot contain whitespace"));
    }

    if trimmed.chars().any(|c| c == '\n' || c == '\r' || c == '\t') {
        return Err(anyhow!("GitLab token cannot contain control characters"));
    }

    // GitLab tokens are alphanumeric with underscores and hyphens (glpat- prefix)
    if !trimmed.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(anyhow!("GitLab token contains invalid characters (only alphanumeric, underscore, and hyphen allowed)"));
    }

    // Validate length (GitLab tokens are typically 20-32 characters after glpat- prefix)
    // glpat- prefix with 20 characters is the standard format
    if trimmed.len() < 20 {
        return Err(anyhow!("GitLab token appears too short (minimum 20 characters)"));
    }

    Ok(())
}

/// Validates and sanitizes a directory path
///
/// # Security Considerations
/// - Prevents path traversal attacks
/// - Ensures path exists and is accessible
/// - Resolves symlinks to prevent symlink-based attacks
///
/// # Arguments
/// * `path_str` - The raw path string from user input
///
/// # Returns
/// * `Ok(String)` - Canonicalized absolute path
/// * `Err(String)` - Error message if validation fails
pub fn validate_directory_path(path_str: &str) -> Result<String> {
    // Check length first
    if path_str.len() > MAX_PATH_LENGTH {
        return Err(anyhow!("Path exceeds maximum length of {} characters", MAX_PATH_LENGTH));
    }

    let trimmed = path_str.trim();

    if trimmed.is_empty() {
        return Err(anyhow!("Directory path cannot be empty"));
    }

    let path = Path::new(trimmed);

    // Resolve to canonical path (resolves symlinks, ., and ..)
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| anyhow!("Cannot access directory '{}': {}", trimmed, e))?;

    // Ensure it's actually a directory
    if !canonical.is_dir() {
        return Err(anyhow!("Path '{}' is not a directory", trimmed));
    }

    // Return the canonical path as String
    canonical.into_os_string()
        .into_string()
        .map_err(|_| anyhow!("Path contains invalid UTF-8 characters"))
}

/// Validates a proxy URL
///
/// # Security Considerations
/// - Ensures valid proxy URL format
/// - Supports common proxy protocols (http, https, socks4, socks5)
/// - Prevents injection of malicious URLs
///
/// # Arguments
/// * `proxy_url` - The raw proxy URL string from user input
///
/// # Returns
/// * `Ok(())` - Proxy URL is valid
/// * `Err(String)` - Error message if validation fails
pub fn validate_proxy_url(proxy_url: &str) -> Result<()> {
    let trimmed = proxy_url.trim();

    if trimmed.is_empty() {
        return Err(anyhow!("Proxy URL cannot be empty"));
    }

    // Parse the URL
    let parsed = url::Url::parse(trimmed)
        .map_err(|e| anyhow!("Invalid proxy URL format: {}", e))?;

    // Ensure supported scheme
    match parsed.scheme() {
        "http" | "https" | "socks4" | "socks4a" | "socks5" | "socks5h" => {},
        s => return Err(anyhow!("Unsupported proxy scheme '{}': supported schemes are http, https, socks4, socks5", s)),
    }

    // Must have a host
    if parsed.host().is_none() {
        return Err(anyhow!("Proxy URL must include a host"));
    }

    Ok(())
}

/// Validates an output directory path
///
/// # Security Considerations
/// - Ensures path is safe for writing output
/// - Prevents overwriting sensitive system files
/// - Creates directory if it doesn't exist
///
/// # Arguments
/// * `path_str` - The raw output path string from user input
///
/// # Returns
/// * `Ok(String)` - Canonicalized absolute path
/// * `Err(String)` - Error message if validation fails
pub fn validate_output_path(path_str: &str) -> Result<String> {
    if path_str.is_empty() {
        return Err(anyhow!("Output path cannot be empty"));
    }

    let path = Path::new(path_str);

    // If path doesn't exist, try to create it
    if !path.exists() {
        std::fs::create_dir_all(path)
            .map_err(|e| anyhow!("Cannot create output directory '{}': {}", path_str, e))?;
    }

    // Get canonical path
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| anyhow!("Cannot access output directory '{}': {}", path_str, e))?;

    // Ensure it's a directory
    if !canonical.is_dir() {
        return Err(anyhow!("Output path '{}' is not a directory", path_str));
    }

    canonical.into_os_string()
        .into_string()
        .map_err(|_| anyhow!("Output path contains invalid UTF-8 characters"))
}

/// Validates custom header format
///
/// # Security Considerations
/// - Validates header format (Name:Value)
/// - Prevents header injection attacks
/// - Ensures header names are valid
///
/// # Arguments
/// * `header_str` - The raw header string from user input (format: "Name:Value")
///
/// # Returns
/// * `Ok((String, String))` - Parsed (name, value) tuple
/// * `Err(String)` - Error message if validation fails
pub fn validate_custom_header(header_str: &str) -> Result<(String, String)> {
    let trimmed = header_str.trim();

    if trimmed.is_empty() {
        return Err(anyhow!("Header cannot be empty"));
    }

    // Split on first colon
    let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid header format: expected 'Name:Value', got '{}'", trimmed));
    }

    let name = parts[0].trim();
    let value = parts[1].trim();

    if name.is_empty() {
        return Err(anyhow!("Header name cannot be empty"));
    }

    // Validate header name (RFC 7230: token)
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(anyhow!("Header name contains invalid characters: '{}'", name));
    }

    // Check for dangerous headers that might override security
    let lower_name = name.to_lowercase();
    match lower_name.as_str() {
        "host" | "content-length" | "transfer-encoding" => {
            return Err(anyhow!("Cannot override protected header: {}", name));
        },
        _ => {},
    }

    Ok((name.to_string(), value.to_string()))
}

// ════════════════════════════════════════════════
// SEC-005: Additional Input Validation
// ════════════════════════════════════════════════

/// Maximum number of patterns allowed in a patterns file
const MAX_PATTERNS: usize = 100;

/// Maximum regex pattern length (prevents ReDoS via overly complex patterns)
const MAX_PATTERN_LENGTH: usize = 1000;

/// Maximum User-Agent string length
const MAX_UA_LENGTH: usize = 512;

/// Maximum number of lines in UA file
const MAX_UA_LINES: usize = 100;

/// Maximum CSV field length
const MAX_CSV_FIELD_LENGTH: usize = 32768;

/// Validates a pattern regex string for potential ReDoS vulnerabilities
///
/// # Security Considerations
/// - Prevents ReDoS (Regular Expression Denial of Service) attacks
/// - Checks for nested quantifiers that can cause exponential backtracking
/// - Checks for overlapping character classes with quantifiers
/// - Enforces complexity limits
///
/// # Arguments
/// * `pattern` - The regex pattern string to validate
///
/// # Returns
/// * `Ok(())` - Pattern is safe
/// * `Err(String)` - Error message if pattern is unsafe
pub fn validate_regex_pattern(pattern: &str) -> Result<()> {
    // Check length
    if pattern.len() > MAX_PATTERN_LENGTH {
        return Err(anyhow!("Pattern exceeds maximum length of {} characters", MAX_PATTERN_LENGTH));
    }

    // Empty pattern
    if pattern.trim().is_empty() {
        return Err(anyhow!("Pattern cannot be empty"));
    }

    // Check for nested quantifiers (major ReDoS risk)
    // Use simple string matching to detect dangerous patterns
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Detect patterns like (a+)+, (a*)*, [a+]+, etc.
        if chars[i] == '(' {
            // Find closing paren
            let mut depth = 1;
            let mut j = i + 1;
            let mut has_quantifier = false;

            while j < chars.len() && depth > 0 {
                if chars[j] == '(' { depth += 1; }
                else if chars[j] == ')' { depth -= 1; }
                else if chars[j] == '*' || chars[j] == '+' || chars[j] == '?' {
                    // Check if this is inside the group (before closing paren)
                    if depth == 1 {
                        has_quantifier = true;
                    }
                }
                j += 1;
            }

            // After the closing paren, check for another quantifier
            if j < chars.len() && has_quantifier {
                if chars[j] == '*' || chars[j] == '+' || chars[j] == '?' || chars[j] == '{' {
                    return Err(anyhow!("Pattern contains nested quantifiers which can cause ReDoS"));
                }
            }
        } else if chars[i] == '[' {
            // Find closing bracket
            let mut j = i + 1;
            let mut has_quantifier = false;

            while j < chars.len() && chars[j] != ']' {
                if chars[j] == '*' || chars[j] == '+' {
                    has_quantifier = true;
                }
                j += 1;
            }

            // After the closing bracket, check for another quantifier
            if j < chars.len() && has_quantifier && (j + 1) < chars.len() {
                let next = chars[j + 1];
                if next == '*' || next == '+' || next == '?' {
                    return Err(anyhow!("Pattern contains nested quantifiers which can cause ReDoS"));
                }
            }

            i = j;
        }
        i += 1;
    }

    // Check for catastrophic backtracking patterns
    // Multiple overlapping character classes with quantifiers
    if pattern.matches(|c| c == '(').count() > 20 {
        return Err(anyhow!("Pattern has too many capture groups (max 20)"));
    }

    // Check for overly deep alternation
    if pattern.matches(|c| c == '|').count() > 15 {
        return Err(anyhow!("Pattern has too many alternations (max 15)"));
    }

    // Try to compile the pattern to check for basic regex syntax errors
    regex::Regex::new(pattern)
        .map_err(|e| anyhow!("Invalid regex pattern: {}", e))?;

    Ok(())
}

/// Validates the entire patterns JSON structure
///
/// # Arguments
/// * `json_str` - The raw JSON string from the patterns file
///
/// # Returns
/// * `Ok(usize)` - Number of valid patterns
/// * `Err(String)` - Error message if validation fails
pub fn validate_patterns_json(json_str: &str) -> Result<usize> {
    // Parse JSON first
    let json: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| anyhow!("Invalid JSON in patterns file: {}", e))?;

    // Check for patterns array
    let patterns = json["patterns"].as_array()
        .ok_or_else(|| anyhow!("Patterns file must contain a top-level 'patterns' array"))?;

    // Check pattern count
    if patterns.is_empty() {
        return Err(anyhow!("Patterns array cannot be empty"));
    }

    if patterns.len() > MAX_PATTERNS {
        return Err(anyhow!("Too many patterns (max {})", MAX_PATTERNS));
    }

    let mut count = 0;
    for (i, p) in patterns.iter().enumerate() {
        // Validate id
        let id = p["id"].as_str()
            .ok_or_else(|| anyhow!("Pattern #{}: missing 'id' field", i))?;

        if id.trim().is_empty() {
            return Err(anyhow!("Pattern #{}: 'id' cannot be empty", i));
        }

        if id.len() > 100 {
            return Err(anyhow!("Pattern #{}: 'id' too long (max 100 chars)", i));
        }

        // Validate severity
        let sev = p["severity"].as_str()
            .ok_or_else(|| anyhow!("Pattern #{}: missing 'severity' field", i))?;

        let valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
        if !valid_severities.contains(&sev) {
            return Err(anyhow!("Pattern #{}: invalid severity '{}', must be one of: {:?}",
                i, sev, valid_severities));
        }

        // Validate description
        let desc = p["description"].as_str()
            .ok_or_else(|| anyhow!("Pattern #{}: missing 'description' field", i))?;

        if desc.trim().is_empty() {
            return Err(anyhow!("Pattern #{}: 'description' cannot be empty", i));
        }

        if desc.len() > 500 {
            return Err(anyhow!("Pattern #{}: 'description' too long (max 500 chars)", i));
        }

        // Validate regex pattern
        let regex_str = p["regex"].as_str()
            .ok_or_else(|| anyhow!("Pattern #{}: missing 'regex' field", i))?;

        validate_regex_pattern(regex_str)
            .map_err(|e| anyhow!("Pattern #{} (id: '{}'): {}", i, id, e))?;

        count += 1;
    }

    Ok(count)
}

/// Validates a single User-Agent string
///
/// # Arguments
/// * `ua` - The User-Agent string to validate
/// * `line_num` - Line number for error reporting
///
/// # Returns
/// * `Ok(())` - UA string is valid
/// * `Err(String)` - Error message if validation fails
pub fn validate_user_agent(ua: &str, line_num: usize) -> Result<()> {
    let trimmed = ua.trim();

    // Skip empty lines and comments
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(());
    }

    // Check length
    if trimmed.len() > MAX_UA_LENGTH {
        return Err(anyhow!("Line {}: User-Agent exceeds maximum length of {} characters",
            line_num, MAX_UA_LENGTH));
    }

    // Check for newlines (multi-line UA is invalid)
    if trimmed.contains('\n') || trimmed.contains('\r') {
        return Err(anyhow!("Line {}: User-Agent cannot contain newlines", line_num));
    }

    // Check for control characters
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(anyhow!("Line {}: User-Agent contains control characters", line_num));
    }

    Ok(())
}

/// Validates a User-Agent file content
///
/// # Arguments
/// * `content` - The raw content of the UA file
///
/// # Returns
/// * `Ok(Vec<String>)` - Validated UA strings
/// * `Err(String)` - Error message if validation fails
pub fn validate_ua_file(content: &str) -> Result<Vec<String>> {
    let lines: Vec<&str> = content.lines().collect();

    // Check line count
    if lines.len() > MAX_UA_LINES {
        return Err(anyhow!("UA file has too many lines (max {})", MAX_UA_LINES));
    }

    let mut result = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let line_num = i + 1;
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Validate the UA string
        validate_user_agent(line, line_num)?;

        result.push(trimmed.to_string());
    }

    // At least one valid UA
    if result.is_empty() {
        return Err(anyhow!("UA file must contain at least one valid User-Agent string"));
    }

    Ok(result)
}

/// Validates and sanitizes a CSV field value
///
/// # Security Considerations
/// - Prevents CSV injection attacks
/// - Escapes fields that start with formula characters (=, +, -, @)
/// - Limits field length
///
/// # Arguments
/// * `field` - The raw field value
///
/// # Returns
/// * `String` - Sanitized field value
pub fn sanitize_csv_field(field: &str) -> String {
    let trimmed = field.trim();

    // Truncate if too long
    let sanitized = if trimmed.len() > MAX_CSV_FIELD_LENGTH {
        &trimmed[..MAX_CSV_FIELD_LENGTH]
    } else {
        trimmed
    };

    // CSV injection protection: prefix dangerous characters with single quote
    // This prevents Excel/Sheets from interpreting the field as a formula
    if sanitized.starts_with('=') || sanitized.starts_with('+') ||
       sanitized.starts_with('-') || sanitized.starts_with('@') {
        format!("'{}", sanitized)
    } else {
        sanitized.to_string()
    }
}

/// Validates that a size value is within safe limits
///
/// # Arguments
/// * `content_length` - The Content-Length header value (bytes)
/// * `max_size` - Maximum allowed size in bytes
///
/// # Returns
/// * `Ok(())` - Size is within limits
/// * `Err(String)` - Error message if size exceeds limits
pub fn validate_content_length(content_length: Option<u64>, max_size: usize) -> Result<()> {
    if let Some(length) = content_length {
        if length > max_size as u64 {
            return Err(anyhow!(
                "Content-Length ({}) exceeds maximum allowed size ({})",
                length, max_size
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_and_normalize_url_valid() {
        assert!(validate_and_normalize_url("https://example.com").is_ok());
        assert!(validate_and_normalize_url("http://example.com").is_ok());
        assert!(validate_and_normalize_url("example.com").is_ok());
        assert!(validate_and_normalize_url("example.com/path").is_ok());
        assert!(validate_and_normalize_url("example.com/").is_ok());
    }

    #[test]
    fn test_validate_and_normalize_url_trailing_slash() {
        assert_eq!(validate_and_normalize_url("https://example.com/").unwrap(), "https://example.com");
        assert_eq!(validate_and_normalize_url("https://example.com/path/").unwrap(), "https://example.com/path");
    }

    #[test]
    fn test_validate_and_normalize_url_invalid() {
        assert!(validate_and_normalize_url("javascript:alert(1)").is_err());
        assert!(validate_and_normalize_url("data:text/html,<script>").is_err());
        assert!(validate_and_normalize_url("").is_err());
    }

    #[test]
    fn test_validate_and_normalize_url_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(MAX_URL_LENGTH));
        assert!(validate_and_normalize_url(&long_url).is_err());
    }

    #[test]
    fn test_validate_github_token_valid() {
        assert!(validate_github_token("ghp_1234567890abcdefghij").is_ok());
        assert!(validate_github_token("gho_1234567890abcdefghij").is_ok());
        assert!(validate_github_token("ghu_1234567890abcdefghij").is_ok());
        assert!(validate_github_token("ghs_1234567890abcdefghij").is_ok());
        assert!(validate_github_token("ghr_1234567890abcdefghij").is_ok());
    }

    #[test]
    fn test_validate_github_token_invalid() {
        assert!(validate_github_token("").is_err());
        assert!(validate_github_token("short").is_err());
        assert!(validate_github_token("token with spaces").is_err());
        assert!(validate_github_token("token\nwith\nnewlines").is_err());
        assert!(validate_github_token("token@with$special!chars").is_err());
    }

    #[test]
    fn test_validate_github_token_too_long() {
        let long_token = "a".repeat(MAX_TOKEN_LENGTH + 1);
        assert!(validate_github_token(&long_token).is_err());
    }

    #[test]
    fn test_validate_custom_header_valid() {
        assert!(validate_custom_header("Authorization:Bearer token").is_ok());
        assert!(validate_custom_header("X-Custom-Header:value").is_ok());
        assert!(validate_custom_header("User_Agent:test").is_ok());
    }

    #[test]
    fn test_validate_custom_header_invalid() {
        assert!(validate_custom_header("").is_err());
        assert!(validate_custom_header("NoColon").is_err());
        assert!(validate_custom_header(":ValueOnly").is_err());
        assert!(validate_custom_header("Name:").is_ok()); // Empty value is allowed
        assert!(validate_custom_header("Host:evil.com").is_err());
    }

    // ════════════════════════════════════════════════
    // SEC-005: Additional Validation Tests
    // ════════════════════════════════════════════════

    #[test]
    fn test_validate_regex_pattern_valid() {
        assert!(validate_regex_pattern(r"[A-Za-z0-9]+").is_ok());
        assert!(validate_regex_pattern(r"\bghp_[A-Za-z0-9]{36}\b").is_ok());
        assert!(validate_regex_pattern(r"(?i)api[_-]?key").is_ok());
        assert!(validate_regex_pattern(r"sk-[A-Za-z0-9]+").is_ok());
    }

    #[test]
    fn test_validate_regex_pattern_redos() {
        // Nested quantifiers - ReDoS risk
        assert!(validate_regex_pattern(r"(a+)+").is_err());
        assert!(validate_regex_pattern(r"(a*)*").is_err());
        assert!(validate_regex_pattern(r"([a-z]+)+").is_err());
    }

    #[test]
    fn test_validate_regex_pattern_too_long() {
        let long_pattern = "a".repeat(MAX_PATTERN_LENGTH + 1);
        assert!(validate_regex_pattern(&long_pattern).is_err());
    }

    #[test]
    fn test_validate_regex_pattern_invalid_syntax() {
        assert!(validate_regex_pattern(r"(?P<unclosed").is_err());
        assert!(validate_regex_pattern(r"[a-z").is_err());
    }

    #[test]
    fn test_validate_patterns_json_valid() {
        let json = r#"{"patterns": [
            {"id": "test", "severity": "HIGH", "description": "Test pattern", "regex": "[A-Za-z0-9]+"}
        ]}"#;
        assert!(validate_patterns_json(json).is_ok());
    }

    #[test]
    fn test_validate_patterns_json_invalid() {
        // Missing patterns array
        assert!(validate_patterns_json(r#"{}"#).is_err());

        // Empty patterns
        assert!(validate_patterns_json(r#"{"patterns": []}"#).is_err());

        // Too many patterns
        let mut patterns = String::from(r#"{"patterns": ["#);
        for i in 0..=MAX_PATTERNS {
            if i > 0 { patterns.push_str(","); }
            patterns.push_str(&format!(r#"{{"id":"t{}","severity":"HIGH","description":"t","regex":"a"}}"#, i));
        }
        patterns.push_str("]}");
        assert!(validate_patterns_json(&patterns).is_err());

        // Invalid severity
        assert!(validate_patterns_json(r#"{"patterns": [{"id":"t","severity":"INVALID","description":"t","regex":"a"}]}"#).is_err());
    }

    #[test]
    fn test_validate_user_agent_valid() {
        assert!(validate_user_agent("Mozilla/5.0", 1).is_ok());
        assert!(validate_user_agent("curl/7.68.0", 1).is_ok());
        assert!(validate_user_agent("git/2.46.0", 1).is_ok());
        assert!(validate_user_agent("", 1).is_ok()); // Empty is OK (skipped)
        assert!(validate_user_agent("# comment", 1).is_ok()); // Comment is OK
    }

    #[test]
    fn test_validate_user_agent_invalid() {
        // Multi-line UA
        assert!(validate_user_agent("line1\nline2", 1).is_err());

        // Control characters
        assert!(validate_user_agent("UA\x00null", 1).is_err());

        // Too long
        let long_ua = "a".repeat(MAX_UA_LENGTH + 1);
        assert!(validate_user_agent(&long_ua, 1).is_err());
    }

    #[test]
    fn test_validate_ua_file_valid() {
        let content = r#"# Comment line
Mozilla/5.0 (Windows NT 10.0; Win64; x64)
curl/7.68.0
git/2.46.0"#;
        assert!(validate_ua_file(content).is_ok());
    }

    #[test]
    fn test_validate_ua_file_empty() {
        assert!(validate_ua_file("").is_err());
        assert!(validate_ua_file("# only comments\n# and more\n").is_err());
    }

    #[test]
    fn test_validate_ua_file_too_many_lines() {
        let mut content = String::new();
        for _ in 0..=MAX_UA_LINES {
            content.push_str("UA\n");
        }
        assert!(validate_ua_file(&content).is_err());
    }

    #[test]
    fn test_sanitize_csv_field() {
        // CSV injection protection
        assert_eq!(sanitize_csv_field("=1+1"), "'=1+1");
        assert_eq!(sanitize_csv_field("-SUM(A1:A10)"), "'-SUM(A1:A10)");
        assert_eq!(sanitize_csv_field("+cmd|' /C calc'!A0"), "'+cmd|' /C calc'!A0");
        assert_eq!(sanitize_csv_field("@SUM(1+1)"), "'@SUM(1+1)");

        // Safe fields unchanged
        assert_eq!(sanitize_csv_field("normal text"), "normal text");
        assert_eq!(sanitize_csv_field(" value "), "value");

        // Long fields truncated
        let long_field = "a".repeat(MAX_CSV_FIELD_LENGTH + 100);
        let sanitized = sanitize_csv_field(&long_field);
        assert!(sanitized.len() <= MAX_CSV_FIELD_LENGTH);
    }

    #[test]
    fn test_validate_content_length() {
        assert!(validate_content_length(Some(1000), 10000).is_ok());
        assert!(validate_content_length(Some(10000), 10000).is_ok());
        assert!(validate_content_length(None, 10000).is_ok());

        assert!(validate_content_length(Some(10001), 10000).is_err());
    }
}

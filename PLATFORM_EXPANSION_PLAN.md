# Platform Expansion (v2.1) — Forge Abstraction Implementation Plan

**Version:** 3.3.0 Platform Expansion  
**Status:** Design Phase  
**Created:** 2025-01-09  
**Roadmap ID:** A-7 (Architecture & Scalability)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current State Analysis](#2-current-state-analysis)
3. [Design Goals](#3-design-goals)
4. [Forge Abstraction Trait](#4-forge-abstraction-trait)
5. [Platform-Specific Implementations](#5-platform-specific-implementations)
6. [Migration Strategy](#6-migration-strategy)
7. [Testing Strategy](#7-testing-strategy)
8. [Rollout Plan](#8-rollout-plan)

---

## 1. Executive Summary

### 1.1 Purpose

Extend GitRecon's `--token` mode from GitHub-only to support five major Git forges:
- **GitHub** (existing — refactoring required)
- **GitLab** (new)
- **Bitbucket** (new)
- **Gitea/Forgejo** (new)
- **Azure DevOps** (new)

### 1.2 Key Outcomes

1. **Unified Interface:** Single `Forge` trait abstracting platform differences
2. **Zero Code Duplication:** Platform-specific logic isolated per platform
3. **Graceful Degradation:** Platform-specific quirks handled internally
4. **Future-Proof:** Easy addition of new platforms (e.g., Sourcehut, Codeberg)

### 1.3 Success Metrics

- [ ] Token mode works across all 5 platforms
- [ ] <5% performance overhead vs. current GitHub implementation
- [ ] Zero breaking changes to existing GitHub workflow
- [ ] Unit test coverage >90% for new code

---

## 2. Current State Analysis

### 2.1 Existing GitHub Implementation

**File:** `src/github_api.rs` (~420 lines)

**Capabilities:**
- PAT authentication via `Authorization: token <PAT>` header
- User/org repository enumeration (paginated via `Link` header)
- HEAD SHA resolution via refs/commits endpoints
- Recursive tree traversal via Git Tree API
- Blob content fetching (base64-decoded)

**Dependencies:**
- `http_client::HttpClient` for all HTTP operations
- `serde_json` for response parsing
- `base64` for blob decoding

**Limitations:**
- Tightly coupled to GitHub API v3 structure
- No abstraction for pagination (manual `Link` parsing)
- Platform-specific error handling mixed with core logic
- No rate limit awareness (relies on `http_client` retry)

### 2.2 Architecture Gap

Current call graph:
```
main.rs ──► github_api.rs ──► http_client.rs
         └─ GhRepo
         └─ GhTreeEntry
```

Target call graph:
```
main.rs ──► forge/mod.rs ──► Forge trait
                      ├─► github.rs ──► Forge impl
                      ├─► gitlab.rs ──► Forge impl
                      ├─► bitbucket.rs ──► Forge impl
                      ├─► gitea.rs ──► Forge impl
                      └─► azure_devops.rs ──► Forge impl
                      └─► http_client.rs (shared)
```

---

## 3. Design Goals

### 3.1 Functional Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-1 | Single `--token` entry point for all platforms | P0 |
| FR-2 | Auto-detect platform from token format (optional) | P1 |
| FR-3 | Manual platform selection via `--platform` flag | P0 |
| FR-4 | Consistent repo enumeration across platforms | P0 |
| FR-5 | Platform-aware rate limiting | P1 |
| FR-6 | Graceful handling of platform-specific errors | P1 |

### 3.2 Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-1 | Zero breaking changes to existing GitHub mode | 100% |
| NFR-2 | Performance overhead | <5% |
| NFR-3 | Test coverage | >90% |
| NFR-4 | Clippy warnings | 0 |
| NFR-5 | Binary size increase | <500KB |

### 3.3 Design Principles

1. **Trait-Based Abstraction:** Use Rust traits for compile-time polymorphism
2. **Error Transparency:** Preserve platform-specific error context
3. **Pagination Opacity:** Hide pagination details behind the trait
4. **Async-First:** All operations must be async (`async fn`)
5. **Testability:** Each platform implementation independently testable

---

## 4. Forge Abstraction Trait

### 4.1 Core Trait Definition

```rust
// src/forge/mod.rs

//! Forge abstraction layer
//! 
//! Unifies repository enumeration and object fetching across Git forges.

use async_trait::async_trait;
use std::collections::HashMap;

/// Supported Git forge platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ForgePlatform {
    GitHub,
    GitLab,
    Bitbucket,
    Gitea,
    AzureDevOps,
}

impl ForgePlatform {
    /// Detect platform from token prefix (heuristic)
    pub fn detect_from_token(token: &str) -> Option<Self> {
        if token.starts_with("ghp_") || token.starts_with("github_pat_") {
            Some(Self::GitHub)
        } else if token.starts_with("glpat-") {
            Some(Self::GitLab)
        } else if token.len() >= 32 && token.chars().all(|c| c.is_alphanumeric()) {
            // Bitbucket uses app passwords (variable length)
            Some(Self::Bitbucket)
        } else {
            None // Cannot reliably detect
        }
    }
    
    /// Get API base URL for platform
    pub fn api_url(&self) -> &str {
        match self {
            Self::GitHub => "https://api.github.com",
            Self::GitLab => "https://gitlab.com/api/v4",
            Self::Bitbucket => "https://api.bitbucket.org/2.0",
            Self::Gitea => "https://gitea.com/api/v1", // default, configurable for self-hosted
            Self::AzureDevOps => "https://dev.azure.com", // organization-specific URL
        }
    }
}

/// Unified repository representation
#[derive(Debug, Clone)]
pub struct ForgeRepo {
    /// Unique identifier: "owner/name" or "project/repo"
    pub full_name: String,
    
    /// Repository owner/namespace
    pub owner: String,
    
    /// Repository name
    pub name: String,
    
    /// Whether repository is private
    pub private: bool,
    
    /// Default branch name
    pub default_branch: String,
    
    /// Clone URL (https:// or git@)
    pub clone_url: String,
    
    /// Platform-specific metadata (preserved for debugging)
    pub platform_meta: HashMap<String, String>,
}

/// Unified tree entry representation
#[derive(Debug, Clone)]
pub struct ForgeTreeEntry {
    /// File/directory path
    pub path: String,
    
    /// Object type: "blob" or "tree"
    pub obj_type: String,
    
    /// SHA-1 hash (or equivalent for platform)
    pub sha: String,
    
    /// File size in bytes (None for directories)
    pub size: Option<u64>,
}

/// Authentication error
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Invalid or expired token (HTTP {0})")]
    InvalidToken(u16),
    
    #[error("Insufficient permissions for {resource}")]
    InsufficientPermissions { resource: String },
    
    #[error("Authentication required")]
    AuthRequired,
    
    #[error("Platform-specific auth error: {0}")]
    PlatformSpecific(String),
}

/// Forge API error
#[derive(Debug, thiserror::Error)]
pub enum ForgeError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    
    #[error("Rate limit exceeded: retry after {0}s")]
    RateLimit(u64),
    
    #[error("Resource not found: {0}")]
    NotFound(String),
    
    #[error("Authentication failed: {0}")]
    Auth(#[from] AuthError),
    
    #[error("Platform-specific error: {platform} - {message}")]
    PlatformSpecific { platform: String, message: String },
    
    #[error("Response parsing failed: {0}")]
    ParseError(String),
    
    #[error("Unsupported operation on this platform: {0}")]
    UnsupportedOperation(String),
}

/// Result type for Forge operations
pub type ForgeResult<T> = Result<T, ForgeError>;

/// Main Forge trait — defines interface for all Git forges
#[async_trait]
pub trait Forge: Send + Sync {
    /// Get platform identifier
    fn platform(&self) -> ForgePlatform;
    
    /// Get authenticated user identity
    /// Returns (username, display_name)
    async fn whoami(&self) -> ForgeResult<(String, String)>;
    
    /// List all repositories accessible to the authenticated user
    /// Includes owned, collaborated, and organization repositories
    async fn list_repos(&self) -> ForgeResult<Vec<ForgeRepo>>;
    
    /// List repositories for a specific organization/project
    async fn list_org_repos(&self, org: &str) -> ForgeResult<Vec<ForgeRepo>>;
    
    /// List organizations/groups the user belongs to
    async fn list_orgs(&self) -> ForgeResult<Vec<String>>;
    
    /// Resolve HEAD commit SHA for a branch
    async fn get_head_sha(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> ForgeResult<String>;
    
    /// Get full file tree for a commit (recursive)
    async fn get_tree(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<ForgeTreeEntry>>;
    
    /// Get raw content of a blob/file
    async fn get_blob_content(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<u8>>;
    
    /// Get default timeout for this platform (for adaptive timeouts)
    fn default_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }
    
    /// Get recommended rate limit (requests per second)
    fn recommended_rate_limit(&self) -> f64 {
        10.0 // conservative default
    }
}
```

### 4.2 Factory Pattern

```rust
/// Forge factory — creates appropriate Forge implementation
pub struct ForgeFactory {
    http_config: http_client::HttpConfig,
}

impl ForgeFactory {
    pub fn new(http_config: http_client::HttpConfig) -> Self {
        Self { http_config }
    }
    
    /// Create Forge instance from platform enum and token
    pub fn create(
        &self,
        platform: ForgePlatform,
        token: &str,
    ) -> ForgeResult<Box<dyn Forge>> {
        match platform {
            ForgePlatform::GitHub => {
                github::GitHubForge::new(self.http_config.clone(), token)
                    .map(|f| Box::new(f) as Box<dyn Forge>)
            }
            ForgePlatform::GitLab => {
                gitlab::GitLabForge::new(self.http_config.clone(), token)
                    .map(|f| Box::new(f) as Box<dyn Forge>)
            }
            ForgePlatform::Bitbucket => {
                bitbucket::BitbucketForge::new(self.http_config.clone(), token)
                    .map(|f| Box::new(f) as Box<dyn Forge>)
            }
            ForgePlatform::Gitea => {
                gitea::GiteaForge::new(self.http_config.clone(), token, None)
                    .map(|f| Box::new(f) as Box<dyn Forge>)
            }
            ForgePlatform::AzureDevOps => {
                azure_devops::AzureDevOpsForge::new(self.http_config.clone(), token, None)
                    .map(|f| Box::new(f) as Box<dyn Forge>)
            }
        }
    }
    
    /// Auto-detect platform from token (with fallback)
    pub fn create_auto_detect(
        &self,
        token: &str,
    ) -> ForgeResult<Box<dyn Forge>> {
        let platform = ForgePlatform::detect_from_token(token)
            .unwrap_or(ForgePlatform::GitHub); // default to GitHub
        
        self.create(platform, token)
    }
}
```

---

## 5. Platform-Specific Implementations

### 5.1 GitHub (Refactor Existing)

#### API Endpoints

| Operation | Method | Endpoint | Notes |
|-----------|--------|----------|-------|
| Whoami | GET | `/user` | Returns login + name |
| List repos | GET | `/user/repos?type=all&per_page=100` | Pagination via `Link` header |
| List orgs | GET | `/user/orgs?per_page=100` | Pagination via `Link` header |
| List org repos | GET | `/orgs/{org}/repos?per_page=100` | Pagination via `Link` header |
| Get HEAD SHA | GET | `/repos/{owner}/{repo}/git/refs/heads/{branch}` | Fallback to `/commits/{branch}` |
| Get tree | GET | `/repos/{owner}/{repo}/git/trees/{sha}?recursive=1` | May be truncated for large repos |
| Get blob | GET | `/repos/{owner}/{repo}/git/blobs/{sha}` | Content base64-encoded |

#### Authentication

```rust
// Header-based authentication
Authorization: token <PAT>
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2022-11-28
```

**Token Prefixes:**
- `ghp_` — Classic PAT
- `github_pat_` — Fine-grained PAT

#### Rate Limits

| Tier | Limit | Reset |
|------|-------|-------|
| Authenticated (classic) | 5000 req/hour | Top of hour |
| Authenticated (fine-grained) | Variable (1000+) | Varies |
| No auth | 60 req/hour | Top of hour |

**Headers:**
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Unix timestamp
- `X-RateLimit-Used`: Requests used

#### Quirks & Workarounds

1. **Tree Truncation:** Large repos return `truncated: true`
   - Workaround: Fetch subtrees recursively (future enhancement)
   
2. **Empty Repo HEAD:** First commit may not be in refs
   - Workaround: Fallback to `/commits/{branch}` endpoint
   
3. **Link Header Pagination:** Non-standard format
   - Workaround: Parse `rel="next"` URL from header

#### Implementation Sketch

```rust
// src/forge/github.rs

use super::Forge;
use crate::http_client::HttpClient;
use async_trait::async_trait;

pub struct GitHubForge {
    client: HttpClient,
    api_base: String,
}

impl GitHubForge {
    pub fn new(
        mut cfg: http_client::HttpConfig,
        token: &str,
    ) ForgeResult<Self> {
        cfg.extra_headers.push(("Authorization".into(), format!("token {}", token)));
        cfg.extra_headers.push(("Accept".into(), "application/vnd.github+json".into()));
        cfg.extra_headers.push(("X-GitHub-Api-Version".into(), "2022-11-28".into()));
        
        let client = HttpClient::new(cfg)?;
        
        Ok(Self {
            client,
            api_base: "https://api.github.com".to_string(),
        })
    }
    
    // Parse GitHub Link header for pagination
    fn parse_next_link(link_header: &str) -> Option<String> {
        // ... existing implementation from github_api.rs
    }
    
    // Parse GitHub repo response to ForgeRepo
    fn parse_repo(json: &serde_json::Value) -> Option<ForgeRepo> {
        let full_name = json["full_name"].as_str()?.to_string();
        let owner = json["owner"]["login"].as_str()?.to_string();
        let name = json["name"].as_str()?.to_string();
        let private = json["private"].as_bool().unwrap_or(false);
        let default_branch = json["default_branch"].as_str().unwrap_or("main").to_string();
        let clone_url = json["clone_url"].as_str().unwrap_or("").to_string();
        
        let mut platform_meta = std::collections::HashMap::new();
        if let Some(id) = json["id"].as_u64() {
            platform_meta.insert("id".to_string(), id.to_string());
        }
        if let Some(visibility) = json["visibility"].as_str() {
            platform_meta.insert("visibility".to_string(), visibility.to_string());
        }
        
        Some(ForgeRepo {
            full_name, owner, name, private, default_branch, clone_url,
            platform_meta,
        })
    }
}

#[async_trait]
impl Forge for GitHubForge {
    fn platform(&self) -> ForgePlatform {
        ForgePlatform::GitHub
    }
    
    async fn whoami(&self) -> ForgeResult<(String, String)> {
        let url = format!("{}/user", self.api_base);
        let resp = self.client.get(&url).await;
        
        match resp.status {
            401 => Err(ForgeError::Auth(AuthError::InvalidToken(401))),
            200 => {
                let json: serde_json::Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| ForgeError::ParseError(e.to_string()))?;
                
                let login = json["login"].as_str().unwrap_or("").to_string();
                let name = json["name"].as_str().unwrap_or("").to_string();
                Ok((login, name))
            }
            s => Err(ForgeError::HttpError(format!("GET /user returned HTTP {}", s))),
        }
    }
    
    async fn list_repos(&self) -> ForgeResult<Vec<ForgeRepo>> {
        let mut repos = Vec::new();
        let mut url = format!("{}/user/repos?per_page=100&type=all&sort=updated", self.api_base);
        
        loop {
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                return Err(ForgeError::HttpError(format!("GET {} returned HTTP {}", url, resp.status)));
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .map_err(|e| ForgeError::ParseError(e.to_string()))?;
            
            let arr = json.as_array()
                .ok_or_else(|| ForgeError::ParseError("Expected JSON array".into()))?;
            
            for repo_json in arr {
                if let Some(repo) = Self::parse_repo(repo_json) {
                    repos.push(repo);
                }
            }
            
            match resp.headers.get("link").and_then(|h| Self::parse_next_link(h)) {
                Some(next_url) => url = next_url,
                None => break,
            }
        }
        
        Ok(repos)
    }
    
    async fn list_org_repos(&self, org: &str) -> ForgeResult<Vec<ForgeRepo>> {
        // Similar to list_repos but with /orgs/{org}/repos endpoint
        // ... implementation
    }
    
    async fn list_orgs(&self) -> ForgeResult<Vec<String>> {
        // ... implementation using /user/orgs endpoint
    }
    
    async fn get_head_sha(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> ForgeResult<String> {
        // Try refs endpoint first, fallback to commits endpoint
        let url = format!("{}/repos/{}/{}/git/refs/heads/{}", self.api_base, owner, repo, branch);
        let resp = self.client.get(&url).await;
        
        if resp.ok() {
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .map_err(|e| ForgeError::ParseError(e.to_string()))?;
            
            let sha = if let Some(arr) = json.as_array() {
                arr.first()
                    .and_then(|r| r["object"]["sha"].as_str())
                    .map(|s| s.to_string())
            } else {
                json["object"]["sha"].as_str().map(|s| s.to_string())
            };
            
            if let Some(sha) = sha {
                return Ok(sha);
            }
        }
        
        // Fallback to commits endpoint
        let fallback = format!("{}/repos/{}/{}/commits/{}?per_page=1", self.api_base, owner, repo, branch);
        let fallback_resp = self.client.get(&fallback).await;
        
        if fallback_resp.ok() {
            let json: serde_json::Value = serde_json::from_slice(&fallback_resp.body)
                .map_err(|e| ForgeError::ParseError(e.to_string()))?;
            
            let sha = if let Some(arr) = json.as_array() {
                arr.first().and_then(|c| c["sha"].as_str()).map(|s| s.to_string())
            } else {
                json["sha"].as_str().map(|s| s.to_string())
            };
            
            if let Some(sha) = sha {
                return Ok(sha);
            }
        }
        
        Err(ForgeError::NotFound(format!(
            "Cannot resolve HEAD SHA for {}/{} branch '{}'", owner, repo, branch
        )))
    }
    
    async fn get_tree(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<ForgeTreeEntry>> {
        let url = format!("{}/repos/{}/{}/git/trees/{}?recursive=1", self.api_base, owner, repo, sha);
        let resp = self.client.get(&url).await;
        
        if !resp.ok() {
            return Err(ForgeError::HttpError(format!("GET tree {} returned HTTP {}", url, resp.status)));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        let tree = json["tree"].as_array()
            .ok_or_else(|| ForgeError::ParseError("Missing tree array".into()))?;
        
        let mut entries = Vec::new();
        for item in tree {
            let path = item["path"].as_str().unwrap_or("").to_string();
            let obj_type = item["type"].as_str().unwrap_or("").to_string();
            let sha = item["sha"].as_str().unwrap_or("").to_string();
            let size = item["size"].as_u64();
            
            if path.is_empty() || sha.is_empty() {
                continue;
            }
            
            entries.push(ForgeTreeEntry { path, obj_type, sha, size });
        }
        
        Ok(entries)
    }
    
    async fn get_blob_content(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<u8>> {
        let url = format!("{}/repos/{}/{}/git/blobs/{}", self.api_base, owner, repo, sha);
        let resp = self.client.get(&url).await;
        
        if !resp.ok() {
            return Err(ForgeError::HttpError(format!("GET blob {} returned HTTP {}", url, resp.status)));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        let encoding = json["encoding"].as_str().unwrap_or("base64");
        let content_str = json["content"].as_str().unwrap_or("");
        
        if encoding == "base64" {
            let cleaned: String = content_str.chars()
                .filter(|&c| c != '\n' && c != '\r')
                .collect();
            
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .map_err(|e| ForgeError::ParseError(format!("Base64 decode failed: {}", e)))
        } else {
            Ok(content_str.as_bytes().to_vec())
        }
    }
    
    fn recommended_rate_limit(&self) -> f64 {
        // GitHub: 5000 req/hour = ~1.4 req/s (conservative)
        1.4
    }
}
```

### 5.2 GitLab

#### API Endpoints

| Operation | Method | Endpoint | Notes |
|-----------|--------|----------|-------|
| Whoami | GET | `/user` | Returns username + name |
| List repos | GET | `/projects?membership=true&per_page=100&simple=true` | Pagination via `X-Next-Page` header |
| List orgs | GET | `/groups?per_page=100` | GitLab uses "groups" |
| List org repos | GET | `/groups/{group}/projects?per_page=100&simple=true` | Include subgroups with `include_subgroups=true` |
| Get HEAD SHA | GET | `/projects/{id}/repository/commits/{branch}` | Uses numeric project ID |
| Get tree | GET | `/projects/{id}/repository/tree?sha={sha}&recursive=true` | Pagination for large trees |
| Get blob | GET | `/projects/{id}/repository/files/{file_path}/raw?ref={sha}` | Direct raw download |

#### Authentication

```rust
// Header-based authentication
PRIVATE-TOKEN: <PAT>
```

**Token Prefixes:**
- `glpat-` — Personal Access Token
- `glft-` — Feed token (not useful for API)

#### Rate Limits

| Tier | Limit | Reset |
|------|-------|-------|
| Authenticated (free tier) | 2000 req/min | Rolling window |
| Authenticated (premium) | 10000 req/min | Rolling window |
| No auth | Unknown (varies) | - |

**Headers:**
- `RateLimit-Remaining`: Requests remaining
- `RateLimit-Reset`: Unix timestamp
- `RateLimit-Limit`: Total limit

**Pagination Headers:**
- `X-Total`: Total items
- `X-Total-Pages`: Total pages
- `X-Per-Page`: Items per page
- `X-Next-Page`: Next page number
- `X-Page`: Current page

#### Quirks & Workarounds

1. **Project IDs vs. Names:** GitLab uses numeric project IDs internally
   - Workaround: Accept both `owner/repo` and numeric ID
   
2. **File Path Encoding:** Spaces in paths must be encoded
   - Workaround: URL-encode file paths in blob requests
   
3. **Group Projects:** Projects can belong to nested groups
   - Workaround: Use `include_subgroups=true` when listing
   
4. **Default Branch:** Not always returned in simple project view
   - Workaround: Fetch full project metadata if needed

#### Implementation Sketch

```rust
// src/forge/gitlab.rs

use super::Forge;
use crate::http_client::HttpClient;
use async_trait::async_trait;

pub struct GitLabForge {
    client: HttpClient,
    api_base: String,
}

impl GitLabForge {
    pub fn new(
        mut cfg: http_client::HttpConfig,
        token: &str,
    ) -> ForgeResult<Self> {
        cfg.extra_headers.push(("PRIVATE-TOKEN".into(), token.to_string()));
        
        let client = HttpClient::new(cfg)?;
        
        Ok(Self {
            client,
            api_base: "https://gitlab.com/api/v4".to_string(),
        })
    }
    
    /// Resolve owner/repo to numeric project ID
    async fn resolve_project_id(&self, owner: &str, repo: &str) -> ForgeResult<u64> {
        let encoded_path = format!("{}/{}", owner, repo);
        let url = format!("{}/projects/{}", self.api_base, percent_encode(&encoded_path));
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::NotFound(format!("Project {}/{} not found", owner, repo)));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        json["id"].as_u64()
            .ok_or_else(|| ForgeError::ParseError("Missing project ID".into()))
    }
    
    /// Parse GitLab project to ForgeRepo
    fn parse_project(json: &serde_json::Value) -> Option<ForgeRepo> {
        let full_name = json["path_with_namespace"].as_str()?.to_string();
        let name = json["path"].as_str()?.to_string();
        let owner = json["owner"]["username"].as_str()
            .or_else(|| json["namespace"]["full_path"].as_str())
            .unwrap_or("").to_string();
        let private = matches!(json["visibility"].as_str(), Some("private") | Some("internal"));
        let default_branch = json["default_branch"].as_str().unwrap_or("main").to_string();
        let clone_url = json["http_url_to_repo"].as_str().unwrap_or("").to_string();
        
        let mut platform_meta = std::collections::HashMap::new();
        if let Some(id) = json["id"].as_u64() {
            platform_meta.insert("id".to_string(), id.to_string());
        }
        if let Some(visibility) = json["visibility"].as_str() {
            platform_meta.insert("visibility".to_string(), visibility.to_string());
        }
        
        Some(ForgeRepo { full_name, owner, name, private, default_branch, clone_url, platform_meta })
    }
}

#[async_trait]
impl Forge for GitLabForge {
    fn platform(&self) -> ForgePlatform {
        ForgePlatform::GitLab
    }
    
    async fn whoami(&self) -> ForgeResult<(String, String)> {
        let url = format!("{}/user", self.api_base);
        let resp = self.client.get(&url).await;
        
        match resp.status {
            401 => Err(ForgeError::Auth(AuthError::InvalidToken(401))),
            200 => {
                let json: serde_json::Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| ForgeError::ParseError(e.to_string()))?;
                
                let username = json["username"].as_str().unwrap_or("").to_string();
                let name = json["name"].as_str().unwrap_or("").to_string();
                Ok((username, name))
            }
            s => Err(ForgeError::HttpError(format!("GET /user returned HTTP {}", s))),
        }
    }
    
    async fn list_repos(&self) -> ForgeResult<Vec<ForgeRepo>> {
        let mut repos = Vec::new();
        let mut page = 1;
        const PER_PAGE: u32 = 100;
        
        loop {
            let url = format!(
                "{}/projects?membership=true&per_page={}&simple=true&page={}",
                self.api_base, PER_PAGE, page
            );
            
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            let arr = json.as_array().unwrap_or(&vec![]);
            if arr.is_empty() {
                break;
            }
            
            for project in arr {
                if let Some(repo) = Self::parse_project(project) {
                    repos.push(repo);
                }
            }
            
            // Check if more pages exist via X-Next-Page header
            match resp.headers.get("x-next-page") {
                Some(next) if !next.is_empty() => {
                    page = next.parse().unwrap_or(page + 1);
                }
                _ => break,
            }
        }
        
        Ok(repos)
    }
    
    async fn list_org_repos(&self, org: &str) -> ForgeResult<Vec<ForgeRepo>> {
        let mut repos = Vec::new();
        let mut page = 1;
        const PER_PAGE: u32 = 100;
        
        loop {
            let encoded_org = percent_encode(org);
            let url = format!(
                "{}/groups/{}/projects?per_page={}&simple=true&include_subgroups=true&page={}",
                self.api_base, encoded_org, PER_PAGE, page
            );
            
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            let arr = json.as_array().unwrap_or(&vec![]);
            if arr.is_empty() {
                break;
            }
            
            for project in arr {
                if let Some(repo) = Self::parse_project(project) {
                    repos.push(repo);
                }
            }
            
            match resp.headers.get("x-next-page") {
                Some(next) if !next.is_empty() => {
                    page = next.parse().unwrap_or(page + 1);
                }
                _ => break,
            }
        }
        
        Ok(repos)
    }
    
    async fn list_orgs(&self) -> ForgeResult<Vec<String>> {
        let mut orgs = Vec::new();
        let mut page = 1;
        const PER_PAGE: u32 = 100;
        
        loop {
            let url = format!("{}/groups?per_page={}&page={}", self.api_base, PER_PAGE, page);
            let resp = self.client.get(&url).await;
            
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            let arr = json.as_array().unwrap_or(&vec![]);
            if arr.is_empty() {
                break;
            }
            
            for group in arr {
                if let Some(path) = group["full_path"].as_str() {
                    orgs.push(path.to_string());
                }
            }
            
            match resp.headers.get("x-next-page") {
                Some(next) if !next.is_empty() => {
                    page = next.parse().unwrap_or(page + 1);
                }
                _ => break,
            }
        }
        
        Ok(orgs)
    }
    
    async fn get_head_sha(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> ForgeResult<String> {
        let project_id = self.resolve_project_id(owner, repo).await?;
        let url = format!(
            "{}/projects/{}/repository/commits/{}",
            self.api_base, project_id, branch
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::NotFound(format!(
                "Branch '{}' not found in {}/{} (HTTP {})",
                branch, owner, repo, resp.status
            )));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        json["id"].as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ForgeError::ParseError("Missing commit ID".into()))
    }
    
    async fn get_tree(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<ForgeTreeEntry>> {
        let project_id = self.resolve_project_id(owner, repo).await?;
        
        // GitLab has a limit on recursive tree size; may need pagination
        let url = format!(
            "{}/projects/{}/repository/tree?sha={}&recursive=true&per_page=10000",
            self.api_base, project_id, sha
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::HttpError(format!("GET tree {} returned HTTP {}", url, resp.status)));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        let tree = json.as_array()
            .ok_or_else(|| ForgeError::ParseError("Expected JSON array".into()))?;
        
        let mut entries = Vec::new();
        for item in tree {
            let path = item["path"].as_str().unwrap_or("").to_string();
            let obj_type = item["type"].as_str().unwrap_or("").to_string();
            let sha = item["id"].as_str().unwrap_or("").to_string();
            let size = item["size"].as_u64();
            
            if path.is_empty() || sha.is_empty() {
                continue;
            }
            
            entries.push(ForgeTreeEntry { path, obj_type, sha, size });
        }
        
        Ok(entries)
    }
    
    async fn get_blob_content(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<u8>> {
        // GitLab doesn't have a direct blob-by-SHA endpoint for raw content
        // We need to find the file path from the tree first, then use files API
        // For now, we'll use the raw file API with ref (less efficient but works)
        
        // Alternative: Use repository archive API and extract specific file
        // For simplicity, we return unsupported for now (can be enhanced later)
        
        Err(ForgeError::UnsupportedOperation(
            "GitLab blob-by-SHA not directly supported; use file path instead".into()
        ))
        
        // Future enhancement: Cache tree entries, look up path by SHA, then:
        // let project_id = self.resolve_project_id(owner, repo).await?;
        // let url = format!("{}/projects/{}/repository/files/{}/raw?ref={}",
        //     self.api_base, project_id, percent_encode(path), sha
        // );
    }
    
    fn recommended_rate_limit(&self) -> f64 {
        // GitLab: 2000 req/min = ~33 req/s (conservative)
        33.0
    }
}

/// URL-encode path segment (for spaces and special chars)
fn percent_encode(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}
```

### 5.3 Bitbucket

#### API Endpoints

| Operation | Method | Endpoint | Notes |
|-----------|--------|----------|-------|
| Whoami | GET | `/user` | Returns username + display_name |
| List repos | GET | `/repositories?role=contributor` | Pagination via `next` URL in response |
| List orgs | GET | `/workspaces?q=slug="*"` | Bitbucket Cloud uses "workspaces" |
| List org repos | GET | `/repositories/{workspace}` | Pagination via `next` URL |
| Get HEAD SHA | GET | `/repositories/{workspace}/{repo}/commits/{branch}` | Returns latest commit |
| Get tree | GET | `/repositories/{workspace}/{repo}/src/{commit}/` | Recursively list directory |
| Get blob | GET | `/repositories/{workspace}/{repo}/src/{commit}/{path}` | Direct raw download |

#### Authentication

```rust
// Header-based authentication
Authorization: Bearer <APP_PASSWORD>
```

**Token Format:**
- No standard prefix (app passwords are arbitrary strings)
- Must be created in account settings with specific scopes

#### Rate Limits

| Tier | Limit | Reset |
|------|-------|-------|
| Authenticated | 1000 req/hour per workspace | Rolling window |
| IP-based | 1000 req/hour | Rolling window |

**Response Body:**
```json
{
  "type": "error",
  "error": {
    "message": "Rate limit exceeded"
  }
}
```

#### Quirks & Workarounds

1. **Workspace vs. Owner:** Bitbucket uses "workspace" as top-level container
   - Workaround: Accept both workspace and owner terminology
   
2. **Pagination in Response Body:** Next URL embedded in JSON response
   - Workaround: Parse `next` field from response
   
3. **No Direct Tree API:** Must use `/src/{commit}/` for directory listing
   - Workaround: Recursively fetch directory structure
   
4. **Main Branch Default:** May be `main` or `mainline`
   - Workaround: Check `mainbranch` field in repo metadata

#### Implementation Sketch

```rust
// src/forge/bitbucket.rs

use super::Forge;
use crate::http_client::HttpClient;
use async_trait::async_trait;

pub struct BitbucketForge {
    client: HttpClient,
    api_base: String,
}

impl BitbucketForge {
    pub fn new(
        mut cfg: http_client::HttpConfig,
        token: &str,
    ) -> ForgeResult<Self> {
        cfg.extra_headers.push(("Authorization".into(), format!("Bearer {}", token)));
        cfg.extra_headers.push(("Accept".into(), "application/json".into()));
        
        let client = HttpClient::new(cfg)?;
        
        Ok(Self {
            client,
            api_base: "https://api.bitbucket.org/2.0".to_string(),
        })
    }
    
    /// Parse Bitbucket repo response to ForgeRepo
    fn parse_repo(json: &serde_json::Value) -> Option<ForgeRepo> {
        let full_name = json["full_name"].as_str()?.to_string();
        let name = json["name"].as_str()?.to_string();
        let owner = json["owner"]["nickname"].as_str()
            .or_else(|| json["owner"]["username"].as_str())
            .unwrap_or("").to_string();
        let private = json["is_private"].as_bool().unwrap_or(false);
        
        // Main branch detection
        let default_branch = json["mainbranch"]["name"].as_str()
            .or_else(|| json["mainbranch"]["name"].as_str())
            .unwrap_or("main").to_string();
        
        let clone_url = json["links"]["clone"][0]["href"].as_str()
            .unwrap_or("").to_string();
        
        let mut platform_meta = std::collections::HashMap::new();
        if let Some(uuid) = json["uuid"].as_str() {
            platform_meta.insert("uuid".to_string(), uuid.to_string());
        }
        if let Some(slug) = json["slug"].as_str() {
            platform_meta.insert("slug".to_string(), slug.to_string());
        }
        if let Some(workspace) = json["workspace"]["slug"].as_str() {
            platform_meta.insert("workspace".to_string(), workspace.to_string());
        }
        
        Some(ForgeRepo { full_name, owner, name, private, default_branch, clone_url, platform_meta })
    }
}

#[async_trait]
impl Forge for BitbucketForge {
    fn platform(&self) -> ForgePlatform {
        ForgePlatform::Bitbucket
    }
    
    async fn whoami(&self) -> ForgeResult<(String, String)> {
        let url = format!("{}/user", self.api_base);
        let resp = self.client.get(&url).await;
        
        match resp.status {
            401 | 403 => Err(ForgeError::Auth(AuthError::InvalidToken(resp.status))),
            200 => {
                let json: serde_json::Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| ForgeError::ParseError(e.to_string()))?;
                
                let username = json["username"].as_str().unwrap_or("").to_string();
                let display_name = json["display_name"].as_str().unwrap_or("").to_string();
                Ok((username, display_name))
            }
            s => Err(ForgeError::HttpError(format!("GET /user returned HTTP {}", s))),
        }
    }
    
    async fn list_repos(&self) -> ForgeResult<Vec<ForgeRepo>> {
        let mut repos = Vec::new();
        let mut url = format!("{}/repositories?role=contributor", self.api_base);
        
        loop {
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            // Parse repositories from "values" array
            if let Some(values) = json["values"].as_array() {
                for repo_json in values {
                    if let Some(repo) = Self::parse_repo(repo_json) {
                        repos.push(repo);
                    }
                }
            }
            
            // Get next page URL from response
            url = json["next"].as_str().unwrap_or("").to_string();
            if url.is_empty() {
                break;
            }
        }
        
        Ok(repos)
    }
    
    async fn list_org_repos(&self, org: &str) -> ForgeResult<Vec<ForgeRepo>> {
        let mut repos = Vec::new();
        let mut url = format!("{}/repositories/{}", self.api_base, org);
        
        loop {
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            if let Some(values) = json["values"].as_array() {
                for repo_json in values {
                    if let Some(repo) = Self::parse_repo(repo_json) {
                        repos.push(repo);
                    }
                }
            }
            
            url = json["next"].as_str().unwrap_or("").to_string();
            if url.is_empty() {
                break;
            }
        }
        
        Ok(repos)
    }
    
    async fn list_orgs(&self) -> ForgeResult<Vec<String>> {
        let mut orgs = Vec::new();
        let mut url = format!("{}/workspaces", self.api_base);
        
        loop {
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            if let Some(values) = json["values"].as_array() {
                for workspace in values {
                    if let Some(slug) = workspace["slug"].as_str() {
                        orgs.push(slug.to_string());
                    }
                }
            }
            
            url = json["next"].as_str().unwrap_or("").to_string();
            if url.is_empty() {
                break;
            }
        }
        
        Ok(orgs)
    }
    
    async fn get_head_sha(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> ForgeResult<String> {
        let url = format!(
            "{}/repositories/{}/{}/commits/{}",
            self.api_base, owner, repo, branch
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::NotFound(format!(
                "Branch '{}' not found in {}/{} (HTTP {})",
                branch, owner, repo, resp.status
            )));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        json["values"].as_array()
            .and_then(|v| v.first())
            .and_then(|c| c["hash"].as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| ForgeError::ParseError("Missing commit hash".into()))
    }
    
    async fn get_tree(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<ForgeTreeEntry>> {
        // Bitbucket doesn't have a direct tree API
        // We need to fetch the root directory and recursively traverse
        let mut entries = Vec::new();
        let mut dirs_to_visit = vec!["".to_string()];
        
        while let Some(dir) = dirs_to_visit.pop() {
            let path = if dir.is_empty() { "".to_string() } else { format!("/{}", dir) };
            let url = format!(
                "{}/repositories/{}/{}/src/{}{}",
                self.api_base, owner, repo, sha, path
            );
            
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                continue; // Skip inaccessible directories
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            if let Some(values) = json["values"].as_array() {
                for item in values {
                    let item_path = item["path"].as_str().unwrap_or("").to_string();
                    let obj_type = item["type"].as_str().unwrap_or("").to_string();
                    let commit_hash = item["commit"].as_str().unwrap_or("").to_string();
                    
                    if item_path.is_empty() || commit_hash.is_empty() {
                        continue;
                    }
                    
                    entries.push(ForgeTreeEntry {
                        path: item_path.clone(),
                        obj_type: obj_type.clone(),
                        sha: commit_hash,
                        size: item["size"].as_u64(),
                    });
                    
                    if obj_type == "commit_directory" {
                        dirs_to_visit.push(item_path);
                    }
                }
            }
        }
        
        Ok(entries)
    }
    
    async fn get_blob_content(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<u8>> {
        // Bitbucket doesn't support blob-by-SHA directly
        // Need to maintain path->SHA mapping from tree traversal
        // For now, return unsupported
        Err(ForgeError::UnsupportedOperation(
            "Bitbucket blob-by-SHA requires path lookup from tree".into()
        ))
    }
    
    fn recommended_rate_limit(&self) -> f64 {
        // Bitbucket: 1000 req/hour = ~0.28 req/s (very conservative)
        0.3
    }
}
```

### 5.4 Gitea/Forgejo

#### API Endpoints

| Operation | Method | Endpoint | Notes |
|-----------|--------|----------|-------|
| Whoami | GET | `/user` | Returns login + full_name |
| List repos | GET | `/user/repos?limit=50` | Pagination via `page` parameter |
| List orgs | GET | `/user/orgs?limit=50` | Pagination via `page` parameter |
| List org repos | GET | `/orgs/{org}/repos?limit=50` | Pagination via `page` parameter |
| Get HEAD SHA | GET | `/repos/{owner}/{repo}/git/refs/heads/{branch}` | Standard Git refs API |
| Get tree | GET | `/repos/{owner}/{repo}/git/trees/{sha}?recursive=1` | GitHub-compatible API |
| Get blob | GET | `/repos/{owner}/{repo}/git/blobs/{sha}` | Content base64-encoded |

#### Authentication

```rust
// Header-based authentication
Authorization: token <PAT>
```

**Token Format:**
- No standard prefix (configurable in server settings)
- SHA256 hash of secret (40 hex characters)

#### Rate Limits

| Tier | Limit | Reset |
|------|-------|-------|
| Configurable | Server-defined | Varies by instance |
| Default (if enabled) | 1000 req/hour | Rolling window |

**Headers:**
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Limit`: Total limit
- `X-RateLimit-Reset`: Unix timestamp

**Quirk:** Rate limiting can be disabled entirely on self-hosted instances.

#### Quirks & Workarounds

1. **Self-Hosted Instances:** API base URL varies
   - Workaround: Accept custom base URL via config/env
   
2. **Default Pagination Size:** Default limit is 30 (lower than others)
   - Workaround: Explicitly set `limit=50` or higher
   
3. **Tree Truncation:** Similar to GitHub, large trees may be truncated
   - Workaround: Fetch subtrees recursively (future enhancement)

#### Implementation Sketch

```rust
// src/forge/gitea.rs

use super::Forge;
use crate::http_client::HttpClient;
use async_trait::async_trait;

pub struct GiteaForge {
    client: HttpClient,
    api_base: String,
}

impl GiteaForge {
    pub fn new(
        mut cfg: http_client::HttpConfig,
        token: &str,
        custom_base: Option<&str>,
    ) -> ForgeResult<Self> {
        cfg.extra_headers.push(("Authorization".into(), format!("token {}", token)));
        cfg.extra_headers.push(("Accept".into(), "application/json".into()));
        
        let client = HttpClient::new(cfg)?;
        
        let api_base = custom_base
            .map(|s| s.to_string())
            .unwrap_or_else(|| "https://gitea.com/api/v1".to_string());
        
        Ok(Self { client, api_base })
    }
    
    /// Parse Gitea repo response to ForgeRepo
    fn parse_repo(json: &serde_json::Value) -> Option<ForgeRepo> {
        let full_name = json["full_name"].as_str()?.to_string();
        let owner = json["owner"]["login"].as_str()?.to_string();
        let name = json["name"].as_str()?.to_string();
        let private = json["private"].as_bool().unwrap_or(false);
        let default_branch = json["default_branch"].as_str().unwrap_or("main").to_string();
        let clone_url = json["clone_url"].as_str().unwrap_or("").to_string();
        
        let mut platform_meta = std::collections::HashMap::new();
        if let Some(id) = json["id"].as_u64() {
            platform_meta.insert("id".to_string(), id.to_string());
        }
        if let Some(repo_type) = json["type"].as_str() {
            platform_meta.insert("type".to_string(), repo_type.to_string());
        }
        
        Some(ForgeRepo { full_name, owner, name, private, default_branch, clone_url, platform_meta })
    }
}

#[async_trait]
impl Forge for GiteaForge {
    fn platform(&self) -> ForgePlatform {
        ForgePlatform::Gitea
    }
    
    async fn whoami(&self) -> ForgeResult<(String, String)> {
        let url = format!("{}/user", self.api_base);
        let resp = self.client.get(&url).await;
        
        match resp.status {
            401 => Err(ForgeError::Auth(AuthError::InvalidToken(401))),
            200 => {
                let json: serde_json::Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| ForgeError::ParseError(e.to_string()))?;
                
                let login = json["login"].as_str().unwrap_or("").to_string();
                let full_name = json["full_name"].as_str().unwrap_or("").to_string();
                Ok((login, full_name))
            }
            s => Err(ForgeError::HttpError(format!("GET /user returned HTTP {}", s))),
        }
    }
    
    async fn list_repos(&self) -> ForgeResult<Vec<ForgeRepo>> {
        let mut repos = Vec::new();
        let mut page = 1;
        const PER_PAGE: u32 = 50;
        
        loop {
            let url = format!(
                "{}/user/repos?limit={}&page={}",
                self.api_base, PER_PAGE, page
            );
            
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            let arr = json.as_array().unwrap_or(&vec![]);
            if arr.is_empty() {
                break;
            }
            
            for repo_json in arr {
                if let Some(repo) = Self::parse_repo(repo_json) {
                    repos.push(repo);
                }
            }
            
            page += 1;
        }
        
        Ok(repos)
    }
    
    async fn list_org_repos(&self, org: &str) -> ForgeResult<Vec<ForgeRepo>> {
        let mut repos = Vec::new();
        let mut page = 1;
        const PER_PAGE: u32 = 50;
        
        loop {
            let url = format!(
                "{}/orgs/{}/repos?limit={}&page={}",
                self.api_base, org, PER_PAGE, page
            );
            
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            let arr = json.as_array().unwrap_or(&vec![]);
            if arr.is_empty() {
                break;
            }
            
            for repo_json in arr {
                if let Some(repo) = Self::parse_repo(repo_json) {
                    repos.push(repo);
                }
            }
            
            page += 1;
        }
        
        Ok(repos)
    }
    
    async fn list_orgs(&self) -> ForgeResult<Vec<String>> {
        let mut orgs = Vec::new();
        let mut page = 1;
        const PER_PAGE: u32 = 50;
        
        loop {
            let url = format!("{}/user/orgs?limit={}&page={}", self.api_base, PER_PAGE, page);
            let resp = self.client.get(&url).await;
            
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            let arr = json.as_array().unwrap_or(&vec![]);
            if arr.is_empty() {
                break;
            }
            
            for org_json in arr {
                if let Some(username) = org_json["username"].as_str() {
                    orgs.push(username.to_string());
                }
            }
            
            page += 1;
        }
        
        Ok(orgs)
    }
    
    async fn get_head_sha(
        &self,
        owner: &str,
        repo: &str,
        branch: &str,
    ) -> ForgeResult<String> {
        let url = format!(
            "{}/repos/{}/{}/git/refs/heads/{}",
            self.api_base, owner, repo, branch
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::NotFound(format!(
                "Branch '{}' not found in {}/{} (HTTP {})",
                branch, owner, repo, resp.status
            )));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        json["object"]["sha"].as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ForgeError::ParseError("Missing SHA in ref".into()))
    }
    
    async fn get_tree(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<ForgeTreeEntry>> {
        let url = format!(
            "{}/repos/{}/{}/git/trees/{}?recursive=1",
            self.api_base, owner, repo, sha
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::HttpError(format!("GET tree {} returned HTTP {}", url, resp.status)));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        let tree = json["tree"].as_array()
            .ok_or_else(|| ForgeError::ParseError("Missing tree array".into()))?;
        
        let mut entries = Vec::new();
        for item in tree {
            let path = item["path"].as_str().unwrap_or("").to_string();
            let obj_type = item["type"].as_str().unwrap_or("").to_string();
            let sha = item["sha"].as_str().unwrap_or("").to_string();
            let size = item["size"].as_u64();
            
            if path.is_empty() || sha.is_empty() {
                continue;
            }
            
            entries.push(ForgeTreeEntry { path, obj_type, sha, size });
        }
        
        Ok(entries)
    }
    
    async fn get_blob_content(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<u8>> {
        let url = format!(
            "{}/repos/{}/{}/git/blobs/{}",
            self.api_base, owner, repo, sha
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::HttpError(format!("GET blob {} returned HTTP {}", url, resp.status)));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        let encoding = json["encoding"].as_str().unwrap_or("base64");
        let content_str = json["content"].as_str().unwrap_or("");
        
        if encoding == "base64" {
            let cleaned: String = content_str.chars()
                .filter(|&c| c != '\n' && c != '\r')
                .collect();
            
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .map_err(|e| ForgeError::ParseError(format!("Base64 decode failed: {}", e)))
        } else {
            Ok(content_str.as_bytes().to_vec())
        }
    }
    
    fn recommended_rate_limit(&self) -> f64 {
        // Gitea: 1000 req/hour (typical) = ~0.28 req/s
        0.3
    }
}
```

### 5.5 Azure DevOps

#### API Endpoints

| Operation | Method | Endpoint | Notes |
|-----------|--------|----------|-------|
| Whoami | GET | `/_apis/Profile/Profile?api-version=7.0` | Returns profile data |
| List repos | GET | `/_apis/git/repositories?api-version=7.0` | Pagination via continuation token |
| List orgs | GET | `/_apis/Graph/Users?api-version=7.0-preview.1` | List organizations (complex) |
| List org repos | GET | `/{org}/_apis/git/repositories?api-version=7.0` | Org-specific repos |
| Get HEAD SHA | GET | `/{org}/_apis/git/repositories/{repo}/commits?branch={branch}&api-version=7.0` | Returns latest commit |
| Get tree | GET | `/{org}/_apis/git/repositories/{repo}/trees/{sha}&api-version=7.0` | May require recursive traversal |
| Get blob | GET | `/{org}/_apis/git/repositories/{repo}/blobs/{sha}?api-version=7.0` | Content base64-encoded |

#### Authentication

```rust
// Either Bearer token (PAT) or OAuth
Authorization: Bearer <PAT>
```

**Token Format:**
- PAT (Personal Access Token): Base64-encoded string
- No standard prefix; user-defined

#### Rate Limits

| Tier | Limit | Reset |
|------|-------|-------|
| Authenticated | 12000 req/hour (varies) | Rolling window |
| IP-based | Variable | - |

**Headers:**
- `X-RateLimit-Remaining`: Requests remaining (if enforced)
- `X-Request-Id`: Request ID (for debugging)

**Quirk:** Rate limiting is complex and depends on SKU (Free vs. paid).

#### Quirks & Workarounds

1. **Organization-Based URLs:** All URLs require organization name
   - Workaround: Parse org from token or require explicit `--org` flag
   
2. **Project vs. Repository:** Azure DevOps has projects containing repos
   - Workaround: List repos across all projects
   
3. **Continuation Token Pagination:** Uses opaque continuation token
   - Workaround: Extract `continuationToken` from response headers
   
4. **Branch Name Format:** Uses `refs/heads/branch` prefix internally
   - Workaround: Accept both `branch` and `refs/heads/branch`
   
5. **SHA Format:** Uses "commit ID" (SHA1) but may be represented differently
   - Workaround: Normalize to standard SHA1 format

#### Implementation Sketch

```rust
// src/forge/azure_devops.rs

use super::Forge;
use crate::http_client::HttpClient;
use async_trait::async_trait;

pub struct AzureDevOpsForge {
    client: HttpClient,
    org: String,
    api_base: String,
}

impl AzureDevOpsForge {
    pub fn new(
        mut cfg: http_client::HttpConfig,
        token: &str,
        custom_org: Option<&str>,
    ) -> ForgeResult<Self> {
        cfg.extra_headers.push(("Authorization".into(), format!("Bearer {}", token)));
        cfg.extra_headers.push(("Accept".into(), "application/json".into()));
        
        let client = HttpClient::new(cfg)?;
        
        // Organization is required for Azure DevOps
        // Try to detect from token or require explicit parameter
        let org = custom_org
            .map(|s| s.to_string())
            .ok_or_else(|| ForgeError::PlatformSpecific {
                platform: "Azure DevOps".to_string(),
                message: "Organization name required (use --org)".to_string(),
            })?;
        
        let api_base = format!("https://dev.azure.com/{}", org);
        
        Ok(Self { client, org, api_base })
    }
    
    /// Parse Azure DevOps repo response to ForgeRepo
    fn parse_repo(json: &serde_json::Value) -> Option<ForgeRepo> {
        let name = json["name"].as_str()?.to_string();
        let project = json["project"]["name"].as_str().unwrap_or("").to_string();
        let full_name = format!("{}/{}", project, name);
        let owner = json["owner"]["displayName"].as_str()
            .or_else(|| json["owner"]["uniqueName"].as_str())
            .unwrap_or("").to_string();
        let private = matches!(json["visibility"].as_str(), Some("private"));
        let default_branch = json["defaultBranch"].as_str()
            .map(|b| b.strip_prefix("refs/heads/").unwrap_or(b))
            .unwrap_or("main")
            .to_string();
        
        let clone_url = json["remoteUrl"].as_str().unwrap_or("").to_string();
        
        let mut platform_meta = std::collections::HashMap::new();
        if let Some(id) = json["id"].as_str() {
            platform_meta.insert("id".to_string(), id.to_string());
        }
        if let Some(project_id) = json["project"]["id"].as_str() {
            platform_meta.insert("projectId".to_string(), project_id.to_string());
        }
        if let Some(url) = json["url"].as_str() {
            platform_meta.insert("url".to_string(), url.to_string());
        }
        
        Some(ForgeRepo { full_name, owner, name, private, default_branch, clone_url, platform_meta })
    }
}

#[async_trait]
impl Forge for AzureDevOpsForge {
    fn platform(&self) -> ForgePlatform {
        ForgePlatform::AzureDevOps
    }
    
    async fn whoami(&self) -> ForgeResult<(String, String)> {
        let url = format!("{}/_apis/Profile/Profile?api-version=7.0", self.api_base);
        let resp = self.client.get(&url).await;
        
        match resp.status {
            401 | 403 => Err(ForgeError::Auth(AuthError::InvalidToken(resp.status))),
            200 => {
                let json: serde_json::Value = serde_json::from_slice(&resp.body)
                    .map_err(|e| ForgeError::ParseError(e.to_string()))?;
                
                let display_name = json["displayName"].as_str().unwrap_or("").to_string();
                let email = json["emailAddress"].as_str().unwrap_or("").to_string();
                Ok((email, display_name))
            }
            s => Err(ForgeError::HttpError(format!("GET profile returned HTTP {}", s))),
        }
    }
    
    async fn list_repos(&self) -> ForgeResult<Vec<ForgeRepo>> {
        let mut repos = Vec::new();
        let mut continuation_token = None;
        
        loop {
            let mut url = format!("{}/_apis/git/repositories?api-version=7.0", self.api_base);
            if let Some(token) = &continuation_token {
                url.push_str(&format!("&continuationToken={}", token));
            }
            
            let resp = self.client.get(&url).await;
            if !resp.ok() {
                break;
            }
            
            let json: serde_json::Value = serde_json::from_slice(&resp.body)
                .unwrap_or(serde_json::json!([]));
            
            if let Some(values) = json["value"].as_array() {
                for repo_json in values {
                    if let Some(repo) = Self::parse_repo(repo_json) {
                        repos.push(repo);
                    }
                }
            }
            
            // Check for continuation token
            continuation_token = resp.headers.get("x-ms-continuationtoken")
                .map(|s| s.to_string());
            
            if continuation_token.is_none() {
                break;
            }
        }
        
        Ok(repos)
    }
    
    async fn list_org_repos(&self, org: &str) -> ForgeResult<Vec<ForgeRepo>> {
        // Azure DevOps treats "org" as the organization in the URL
        // If the org doesn't match, we're essentially listing for a different org
        if org != self.org {
            return Err(ForgeError::NotFound(format!(
                "Organization '{}' does not match configured org '{}'",
                org, self.org
            )));
        }
        
        self.list_repos().await
    }
    
    async fn list_orgs(&self) -> ForgeResult<Vec<String>> {
        // Azure DevOps doesn't have a simple "list orgs" endpoint
        // The org is embedded in the URL
        Err(ForgeError::UnsupportedOperation(
            "Azure DevOps organization enumeration not supported".into()
        ))
    }
    
    async fn get_head_sha(
        &self,
        owner: &str,  // Actually project in Azure DevOps
        repo: &str,
        branch: &str,
    ) -> ForgeResult<String> {
        // Normalize branch name (remove refs/heads/ prefix if present)
        let branch_name = branch.strip_prefix("refs/heads/").unwrap_or(branch);
        
        let url = format!(
            "{}/_apis/git/repositories/{}/commits?searchCriteria.branchName=refs/heads/{}&api-version=7.0",
            self.api_base, repo, branch_name
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::NotFound(format!(
                "Branch '{}' not found in project/{}/{} (HTTP {})",
                branch, owner, repo, resp.status
            )));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        json["value"].as_array()
            .and_then(|v| v.first())
            .and_then(|c| c["commitId"].as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| ForgeError::ParseError("Missing commitId".into()))
    }
    
    async fn get_tree(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<ForgeTreeEntry>> {
        // Azure DevOps doesn't have a direct recursive tree endpoint
        // Need to fetch items endpoint recursively
        let mut entries = Vec::new();
        let mut path = String::new();
        
        // First, resolve repo ID from name
        let repo_id = self.resolve_repo_id(owner, repo).await?;
        
        // Fetch root items
        let url = format!(
            "{}/_apis/git/repositories/{}/items?version={}&api-version=7.0",
            self.api_base, repo_id, sha
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::HttpError(format!("GET items {} returned HTTP {}", url, resp.status)));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        if let Some(values) = json["value"].as_array() {
            for item in values {
                let item_path = item["path"].as_str().unwrap_or("").to_string();
                let obj_type = if item["isFolder"].as_bool().unwrap_or(false) {
                    "tree".to_string()
                } else {
                    "blob".to_string()
                };
                let item_sha = item["objectId"].as_str().unwrap_or("").to_string();
                
                if item_path.is_empty() || item_sha.is_empty() {
                    continue;
                }
                
                entries.push(ForgeTreeEntry {
                    path: item_path,
                    obj_type,
                    sha: item_sha,
                    size: item["size"].as_u64(),
                });
            }
        }
        
        Ok(entries)
    }
    
    async fn get_blob_content(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> ForgeResult<Vec<u8>> {
        let repo_id = self.resolve_repo_id(owner, repo).await?;
        
        let url = format!(
            "{}/_apis/git/repositories/{}/blobs/{}?api-version=7.0",
            self.api_base, repo_id, sha
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::HttpError(format!("GET blob {} returned HTTP {}", url, resp.status)));
        }
        
        // Azure DevOps returns raw content directly
        Ok(resp.body.to_vec())
    }
    
    fn recommended_rate_limit(&self) -> f64 {
        // Azure DevOps: 12000 req/hour = ~3.3 req/s
        3.3
    }
}

/// Helper: Resolve repo name to GUID
impl AzureDevOpsForge {
    async fn resolve_repo_id(&self, owner: &str, repo: &str) -> ForgeResult<String> {
        let url = format!(
            "{}/_apis/git/repositories/{}?api-version=7.0",
            self.api_base, repo
        );
        
        let resp = self.client.get(&url).await;
        if !resp.ok() {
            return Err(ForgeError::NotFound(format!(
                "Repository '{}' not found in project '{}'",
                repo, owner
            )));
        }
        
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ForgeError::ParseError(e.to_string()))?;
        
        json["id"].as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ForgeError::ParseError("Missing repository ID".into()))
    }
}
```

---

## 6. Migration Strategy

### 6.1 Backward Compatibility

**Existing `--token` mode must continue to work without any changes.**

```rust
// CLI changes in main.rs

#[arg(long, value_name = "TOKEN")]
/// Git forge Personal Access Token (auto-detects platform)
token: Option<String>,

#[arg(long, value_name = "PLATFORM")]
/// Force platform (github|gitlab|bitbucket|gitea|azure-devops)
platform: Option<String>,

#[arg(long, value_name = "URL")]
/// Custom API base URL (for self-hosted Gitea/GitLab)
api_url: Option<String>,

#[arg(long, value_name = "ORG")]
/// Organization/workspace (required for Azure DevOps)
org: Option<String>,
```

### 6.2 Refactor Steps

1. **Create `src/forge/` module**
   - `mod.rs` — trait definitions and factory
   - `github.rs` — refactor existing `github_api.rs`
   - `gitlab.rs` — new implementation
   - `bitbucket.rs` — new implementation
   - `gitea.rs` — new implementation
   - `azure_devops.rs` — new implementation

2. **Update `main.rs`**
   - Replace direct `github_api` calls with `Forge` trait
   - Add platform detection logic
   - Handle new CLI flags

3. **Deprecate `src/github_api.rs`**
   - Keep for compatibility during transition
   - Mark as deprecated in comments

### 6.3 Code Changes

**Before (GitHub-only):**
```rust
let gh_client = github_api::build_github_client(base_cfg, token)?;
let (login, name) = github_api::whoami(&gh_client).await?;
let repos = github_api::list_repos(&gh_client).await?;
```

**After (multi-platform):**
```rust
let platform = args.platform
    .and_then(|p| p.parse::<ForgePlatform>().ok())
    .or_else(|| ForgePlatform::detect_from_token(&token))
    .unwrap_or(ForgePlatform::GitHub);

let factory = ForgeFactory::new(base_cfg);
let forge = factory.create(platform, &token)?;

let (login, name) = forge.whoami().await?;
let repos = forge.list_repos().await?;
```

---

## 7. Testing Strategy

### 7.1 Unit Tests

Each platform implementation must have:
- Parser tests (`parse_repo`, `parse_tree`, etc.)
- Pagination logic tests
- Error handling tests

**Example:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_github_repo() {
        let json = serde_json::json!({
            "full_name": "octocat/hello-world",
            "owner": {"login": "octocat"},
            "name": "hello-world",
            "private": false,
            "default_branch": "main",
            "clone_url": "https://github.com/octocat/hello-world.git"
        });
        
        let repo = GitHubForge::parse_repo(&json).unwrap();
        assert_eq!(repo.full_name, "octocat/hello-world");
        assert_eq!(repo.default_branch, "main");
    }
}
```

### 7.2 Integration Tests

Create `tests/forge_integration.rs` with:
- Mock HTTP server tests (using `wiremock`)
- End-to-end token mode tests (with test tokens if available)
- Pagination behavior tests

### 7.3 Test Coverage Targets

| Component | Target Coverage |
|-----------|----------------|
| `forge/mod.rs` | 95% |
| `github.rs` | 90% |
| `gitlab.rs` | 90% |
| `bitbucket.rs` | 90% |
| `gitea.rs` | 90% |
| `azure_devops.rs` | 90% |

---

## 8. Rollout Plan

### Phase 1: Foundation (Week 1)

- [ ] Create `src/forge/` module structure
- [ ] Define `Forge` trait and supporting types
- [ ] Implement `ForgeFactory`
- [ ] Add unit tests for trait definitions

### Phase 2: GitHub Refactor (Week 1)

- [ ] Refactor `github_api.rs` into `forge/github.rs`
- [ ] Implement `Forge` trait for GitHub
- [ ] Port all existing tests
- [ ] Verify zero performance regression

### Phase 3: GitLab (Week 2)

- [ ] Implement `forge/gitlab.rs`
- [ ] Add unit tests
- [ ] Add integration tests with wiremock
- [ ] Document GitLab-specific behavior

### Phase 4: Bitbucket (Week 2)

- [ ] Implement `forge/bitbucket.rs`
- [ ] Add unit tests
- [ ] Add integration tests with wiremock
- [ ] Document Bitbucket-specific behavior

### Phase 5: Gitea/Forgejo (Week 3)

- [ ] Implement `forge/gitea.rs`
- [ ] Add unit tests
- [ ] Add integration tests with wiremock
- [ ] Document Gitea-specific behavior

### Phase 6: Azure DevOps (Week 3)

- [ ] Implement `forge/azure_devops.rs`
- [ ] Add unit tests
- [ ] Add integration tests with wiremock
- [ ] Document Azure DevOps-specific behavior

### Phase 7: CLI Integration (Week 4)

- [ ] Update `main.rs` with new CLI flags
- [ ] Implement platform auto-detection
- [ ] Add integration tests for full token mode
- [ ] Update README documentation

### Phase 8: Documentation (Week 4)

- [ ] Update README with platform support
- [ ] Add examples for each platform
- [ ] Document authentication methods
- [ ] Document rate limits
- [ ] Add troubleshooting section

### Phase 9: Release (Week 5)

- [ ] Full test suite run
- [ ] Security audit of new code
- [ ] Performance benchmarking
- [ ] Create release notes
- [ ] Tag v3.3.0 release

---

## Appendix A: Platform Comparison Matrix

| Feature | GitHub | GitLab | Bitbucket | Gitea | Azure DevOps |
|---------|--------|--------|-----------|-------|--------------|
| **Auth Method** | Header: `token <PAT>` | Header: `PRIVATE-TOKEN` | Header: `Bearer` | Header: `token` | Header: `Bearer` |
| **Pagination** | `Link` header | `X-Next-Page` header | Response body `next` | `page` param | Continuation token |
| **Rate Limit Header** | `X-RateLimit-*` | `RateLimit-*` | None (response body) | `X-RateLimit-*` | `X-RateLimit-*` |
| **Tree API** | Yes (recursive) | Yes (recursive) | No (use `/src`) | Yes (recursive) | Partial (use `/items`) |
| **Blob-by-SHA** | Yes | No (needs path) | No (needs path) | Yes | Yes |
| **Org Concept** | Yes | Groups | Workspaces | Orgs | Projects |
| **Max Reqs/Hour** | 5000 | 2000/min | 1000 | 1000 | 12000 |
| **Default Branch** | Configurable | Configurable | `main` or `mainline` | Configurable | Configurable |

---

## Appendix B: Token Prefix Reference

| Platform | Token Prefix | Example |
|----------|--------------|---------|
| GitHub | `ghp_` or `github_pat_` | `ghp_xxxxxxxxxxxx` |
| GitLab | `glpat-` | `glpat_xxxxxxxxxxxx` |
| Bitbucket | None (app password) | `R_0_xxxxxxxxxxxx` |
| Gitea | None (SHA256) | `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |
| Azure DevOps | None (Base64) | `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` |

---

## Appendix C: API Version Reference

| Platform | API Version | Stability |
|----------|-------------|-----------|
| GitHub | v3 (2022-11-28) | Stable |
| GitLab | v4 | Stable |
| Bitbucket | 2.0 | Stable |
| Gitea | v1 | Stable |
| Azure DevOps | 7.0 | Stable |

---

## Appendix D: Error Code Mapping

| HTTP Status | GitHub | GitLab | Bitbucket | Gitea | Azure DevOps |
|-------------|--------|--------|-----------|-------|--------------|
| 401 | Invalid PAT | Invalid token | Invalid token | Invalid token | Invalid token |
| 403 | Forbidden | Forbidden | Forbidden | Forbidden | Forbidden |
| 404 | Not found | Not found | Not found | Not found | Not found |
| 429 | Rate limit | Rate limit | Rate limit (body) | Rate limit | Rate limit |
| 500 | Server error | Server error | Server error | Server error | Server error |

---

**Document Version:** 1.0  
**Last Updated:** 2025-01-09  
**Author:** GitRecon Development Team  
**Status:** Ready for Implementation  

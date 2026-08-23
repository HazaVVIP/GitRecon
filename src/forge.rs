//! forge.rs
//!
//! Multi-platform Git forge abstraction trait.
//!
//! Defines a unified interface for interacting with different Git hosting platforms
//! (GitHub, GitLab, Bitbucket, Gitea, Azure DevOps).

use async_trait::async_trait;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ════════════════════════════════════════════════
// PLATFORM ENUMERATION
// ════════════════════════════════════════════════

/// Supported Git hosting platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    GitHub,
    GitLab,
    Bitbucket,
    Gitea,
    AzureDevOps,
}

impl Platform {
    /// Detect platform from a URL.
    ///
    /// # Examples
    /// ```
    /// assert_eq!(Platform::from_url("https://github.com/user/repo"), Some(Platform::GitHub));
    /// assert_eq!(Platform::from_url("https://gitlab.com/user/repo"), Some(Platform::GitLab));
    /// ```
    pub fn from_url(url: &str) -> Option<Self> {
        let url = url.to_lowercase();

        // Extract hostname from URL
        let host = url.split("://").nth(1).and_then(|s| s.split('/').next());

        match host {
            Some(h) if h.contains("github.com") => Some(Platform::GitHub),
            Some(h) if h.contains("gitlab.com") || h.contains("gitlab") => Some(Platform::GitLab),
            Some(h) if h.contains("bitbucket.org") || h.contains("bitbucket") => {
                Some(Platform::Bitbucket)
            }
            Some(h) if h.contains("gitea.io") || h.contains("gitea") => Some(Platform::Gitea),
            Some(h)
                if h.contains("dev.azure.com")
                    || h.contains("azure")
                    || h.contains("visualstudio.com") =>
            {
                Some(Platform::AzureDevOps)
            }
            _ => None,
        }
    }

    /// Get the API base URL for this platform.
    pub fn api_base_url(&self) -> &'static str {
        match self {
            Platform::GitHub => "https://api.github.com",
            Platform::GitLab => "https://gitlab.com/api/v4",
            Platform::Bitbucket => "https://api.bitbucket.org/2.0",
            Platform::Gitea => "https://gitea.com/api/v1", // Default, instance-specific
            Platform::AzureDevOps => "https://dev.azure.com",
        }
    }

    /// Get platform name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Platform::GitHub => "GitHub",
            Platform::GitLab => "GitLab",
            Platform::Bitbucket => "Bitbucket",
            Platform::Gitea => "Gitea",
            Platform::AzureDevOps => "Azure DevOps",
        }
    }

    /// Default rate limit (requests per hour) for authenticated requests.
    pub fn default_rate_limit(&self) -> u32 {
        match self {
            Platform::GitHub => 5000,
            Platform::GitLab => 2000, // Variable depending on tier
            Platform::Bitbucket => 1000,
            Platform::Gitea => 1000,
            Platform::AzureDevOps => 180, // Per minute, not hour
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ════════════════════════════════════════════════
// ENUMERATION SCOPE
// ════════════════════════════════════════════════

/// Scope for repository enumeration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnumScope {
    /// Enumerate repositories owned by the authenticated user.
    User,
    /// Enumerate repositories within an organization.
    Org(String),
    /// Enumerate all accessible repositories.
    All,
}

// ════════════════════════════════════════════════
// COMMON DATA STRUCTURES
// ════════════════════════════════════════════════

/// Unified repository metadata.
#[derive(Debug, Clone)]
pub struct Repository {
    /// Unique identifier (e.g., "owner/repo" for GitHub).
    pub full_name: String,
    /// Repository owner/organization.
    pub owner: String,
    /// Repository name.
    pub name: String,
    /// Whether the repository is private.
    pub private: bool,
    /// Default branch name.
    pub default_branch: String,
    /// Clone URL (HTTPS).
    pub clone_url: String,
    /// Platform-specific metadata.
    pub platform: Platform,
    /// Star count (if available).
    pub stars: Option<u32>,
    /// Fork count (if available).
    pub forks: Option<u32>,
    /// Repository description (if available).
    pub description: Option<String>,
    /// Last update timestamp (if available).
    pub updated_at: Option<String>,
}

/// Unified tree entry (blob or tree).
#[derive(Debug, Clone)]
pub struct TreeEntry {
    /// Path relative to repository root.
    pub path: String,
    /// Object type: "blob" or "tree".
    pub obj_type: String,
    /// SHA-1 hash of the object.
    pub sha: String,
    /// Size in bytes (only for blobs).
    pub size: Option<u64>,
    /// Last modification mode (unix permissions).
    pub mode: Option<String>,
}

/// Rate limit information.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Requests remaining in the current window.
    pub remaining: u32,
    /// Time until the rate limit resets.
    pub reset_in: Duration,
    /// Total requests allowed per window.
    pub limit: u32,
}

/// Repository content scope requested from a forge integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ForgeScanScope {
    /// Scan the provider's current default-branch snapshot.
    Snapshot,
    /// Traverse bounded repository history when the provider advertises support.
    History,
}

impl ForgeScanScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::History => "history",
        }
    }
}

/// Provider capabilities relevant to snapshot and history scans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeCapabilities {
    pub snapshot: bool,
    pub history: bool,
    pub branches: bool,
    pub tags: bool,
    pub commits: bool,
    pub deleted_blobs: bool,
}

impl ForgeCapabilities {
    pub fn snapshot_only() -> Self {
        Self {
            snapshot: true,
            history: false,
            branches: false,
            tags: false,
            commits: false,
            deleted_blobs: false,
        }
    }
}

impl Default for ForgeCapabilities {
    fn default() -> Self {
        Self::snapshot_only()
    }
}

/// Change classification for a path observed in provider history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryChangeStatus {
    Added,
    Modified,
    Removed,
    Renamed,
    Copied,
    Changed,
    Unknown,
}

impl HistoryChangeStatus {
    pub fn from_provider_status(status: &str) -> Self {
        match status {
            "added" => Self::Added,
            "modified" => Self::Modified,
            "removed" => Self::Removed,
            "renamed" => Self::Renamed,
            "copied" => Self::Copied,
            "changed" => Self::Changed,
            _ => Self::Unknown,
        }
    }
}

/// One provider history file change with optional current blob content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub commit_sha: String,
    pub path: String,
    pub status: HistoryChangeStatus,
    pub blob_sha: Option<String>,
    pub previous_path: Option<String>,
    pub size: Option<u64>,
}

/// Bounded history retrieval result and coverage signal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgeHistory {
    pub commits_scanned: usize,
    pub entries: Vec<HistoryEntry>,
    pub truncated: bool,
}

// ════════════════════════════════════════════════
// FORGE TRAIT
// ════════════════════════════════════════════════

/// Abstraction over Git hosting platform APIs.
#[async_trait]
pub trait Forge: Send + Sync {
    /// Authenticate with the platform.
    ///
    /// # Arguments
    /// * `token` - Authentication token
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err` if authentication fails
    async fn authenticate(&mut self, token: &str) -> anyhow::Result<()>;

    /// Enumerate repositories based on scope.
    ///
    /// # Arguments
    /// * `scope` - Enumeration scope (user, org, all)
    ///
    /// # Returns
    /// * `Ok(Vec<Repository>)` - List of repositories
    /// * `Err` on failure
    async fn enumerate_repos(&self, scope: EnumScope) -> anyhow::Result<Vec<Repository>>;

    /// Get the full recursive tree for a repository branch.
    ///
    /// # Arguments
    /// * `repo` - Repository metadata
    /// * `branch` - Branch name
    ///
    /// # Returns
    /// * `Ok(Vec<TreeEntry>)` - List of tree entries
    /// * `Err` on failure
    async fn get_tree(&self, repo: &Repository, branch: &str) -> anyhow::Result<Vec<TreeEntry>>;

    /// Fetch a blob's content by its SHA.
    ///
    /// # Arguments
    /// * `repo` - Repository metadata
    /// * `sha` - SHA-1 hash of the blob
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Raw blob content
    /// * `Err` on failure
    async fn get_blob(&self, repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>>;

    /// Fetch a tree entry's content using its path-aware metadata when required.
    ///
    /// Providers with SHA-addressable blob endpoints inherit the default behavior;
    /// providers whose source API requires a file path may override this method.
    async fn get_blob_entry(
        &self,
        repo: &Repository,
        entry: &TreeEntry,
    ) -> anyhow::Result<Vec<u8>> {
        self.get_blob(repo, &entry.sha).await
    }

    /// Fetch a path-aware entry at an explicit revision for history scans.
    ///
    /// SHA-addressable providers can use the default entry fetcher; providers
    /// whose raw-file API requires a path and ref may override this method.
    async fn get_blob_entry_at(
        &self,
        repo: &Repository,
        entry: &TreeEntry,
        _revision: &str,
    ) -> anyhow::Result<Vec<u8>> {
        self.get_blob_entry(repo, entry).await
    }

    /// Retrieve bounded commit history and changed paths.
    ///
    /// Providers without implemented history traversal must return a typed
    /// unsupported-capability error instead of silently returning an empty scan.
    async fn get_history(
        &self,
        _repo: &Repository,
        _branch: &str,
        _max_commits: usize,
    ) -> anyhow::Result<ForgeHistory> {
        anyhow::bail!("Unsupported capability: forge history retrieval is not implemented")
    }

    /// Get current rate limit status.
    ///
    /// # Returns
    /// * `Some((remaining, reset_in))` - Rate limit info
    /// * `None` - Rate limit information unavailable
    fn rate_limit_remaining(&self) -> Option<(u32, Duration)>;

    /// Get detailed rate limit information.
    ///
    /// # Returns
    /// * `Some(RateLimitInfo)` - Detailed rate limit info
    /// * `None` - Rate limit information unavailable
    fn rate_limit_info(&self) -> Option<RateLimitInfo> {
        self.rate_limit_remaining()
            .map(|(remaining, reset_in)| RateLimitInfo {
                remaining,
                reset_in,
                limit: 0, // Unknown total
            })
    }

    /// Advertise capabilities supported by this provider implementation.
    ///
    /// The default is deliberately snapshot-only. Providers must override this
    /// method only when their history traversal and deleted-blob semantics are
    /// implemented and covered by provider-mock tests.
    fn capabilities(&self) -> ForgeCapabilities {
        ForgeCapabilities::snapshot_only()
    }

    /// Get the platform identifier.
    fn platform(&self) -> Platform;

    /// Resolve HEAD commit SHA for a branch.
    ///
    /// # Arguments
    /// * `repo` - Repository metadata
    /// * `branch` - Branch name
    ///
    /// # Returns
    /// * `Ok(String)` - SHA-1 hash of the HEAD commit
    /// * `Err` on failure
    async fn get_head_sha(&self, repo: &Repository, branch: &str) -> anyhow::Result<String>;

    /// Identify the authenticated user.
    ///
    /// # Returns
    /// * `Ok((username, display_name))`
    /// * `Err` on failure
    async fn whoami(&self) -> anyhow::Result<(String, String)>;
}

// ════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    // Test-only utilities moved here to suppress dead_code warnings

    /// Authentication token type.
    #[derive(Debug, Clone)]
    enum AuthToken {
        /// Personal Access Token.
        Personal(String),
        /// OAuth token.
        OAuth(String),
        /// JWT (for service accounts).
        Jwt(String),
    }

    #[allow(dead_code)]
    impl AuthToken {
        /// Get the token value.
        fn value(&self) -> &str {
            match self {
                AuthToken::Personal(t) => t,
                AuthToken::OAuth(t) => t,
                AuthToken::Jwt(t) => t,
            }
        }

        /// Create from a string.
        fn from_str(s: String) -> Self {
            // Auto-detect token type based on prefix/length
            if s.starts_with("ghp_")
                || s.starts_with("gho_")
                || s.starts_with("ghu_")
                || s.starts_with("glpat-")
            {
                AuthToken::Personal(s)
            } else if s.contains('.') && s.split('.').count() == 3 {
                // Likely JWT
                AuthToken::Jwt(s)
            } else {
                AuthToken::OAuth(s)
            }
        }
    }

    /// Parse a repository URL into (owner, repo) components.
    fn parse_repo_url(url: &str) -> Option<(String, String)> {
        let url = url.trim_end_matches(".git");

        // Parse URL path
        let path = url
            .split("://")
            .nth(1)?
            .split('/')
            .skip(1)
            .collect::<Vec<_>>();

        if path.len() >= 2 {
            let owner = path[0].to_string();
            let repo = path[1].to_string();
            Some((owner, repo))
        } else {
            None
        }
    }

    /// Build API headers for a given platform and token.
    fn build_api_headers(platform: Platform, token: &str) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        match platform {
            Platform::GitHub => {
                headers.push(("Authorization".to_string(), format!("token {}", token)));
                headers.push((
                    "Accept".to_string(),
                    "application/vnd.github+json".to_string(),
                ));
                headers.push(("X-GitHub-Api-Version".to_string(), "2022-11-28".to_string()));
            }
            Platform::GitLab => {
                headers.push(("PRIVATE-TOKEN".to_string(), token.to_string()));
            }
            Platform::Bitbucket => {
                headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
            }
            Platform::Gitea => {
                headers.push(("Authorization".to_string(), format!("token {}", token)));
            }
            Platform::AzureDevOps => {
                // Azure DevOps uses basic auth with PAT as username (empty password)
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", token, ""));
                headers.push(("Authorization".to_string(), format!("Basic {}", encoded)));
            }
        }

        headers
    }

    #[test]
    fn forge_scope_and_capability_defaults_are_stable() {
        assert_eq!(ForgeScanScope::Snapshot.as_str(), "snapshot");
        assert_eq!(ForgeScanScope::History.as_str(), "history");
        let capabilities = ForgeCapabilities::default();
        assert!(capabilities.snapshot);
        assert!(!capabilities.history);
        assert!(!capabilities.deleted_blobs);
    }

    #[test]
    fn history_status_mapping_preserves_unknown_values() {
        assert_eq!(
            HistoryChangeStatus::from_provider_status("modified"),
            HistoryChangeStatus::Modified
        );
        assert_eq!(
            HistoryChangeStatus::from_provider_status("removed"),
            HistoryChangeStatus::Removed
        );
        assert_eq!(
            HistoryChangeStatus::from_provider_status("provider-specific"),
            HistoryChangeStatus::Unknown
        );
    }

    #[test]
    fn test_platform_from_url_github() {
        assert_eq!(
            Platform::from_url("https://github.com/user/repo"),
            Some(Platform::GitHub)
        );
        assert_eq!(
            Platform::from_url("http://github.com/org/project"),
            Some(Platform::GitHub)
        );
        assert_eq!(
            Platform::from_url("https://api.github.com/v3/user"),
            Some(Platform::GitHub)
        );
    }

    #[test]
    fn test_platform_from_url_gitlab() {
        assert_eq!(
            Platform::from_url("https://gitlab.com/user/repo"),
            Some(Platform::GitLab)
        );
        assert_eq!(
            Platform::from_url("https://gitlab.example.com/group/project"),
            Some(Platform::GitLab)
        );
    }

    #[test]
    fn test_platform_from_url_bitbucket() {
        assert_eq!(
            Platform::from_url("https://bitbucket.org/user/repo"),
            Some(Platform::Bitbucket)
        );
    }

    #[test]
    fn test_platform_from_url_gitea() {
        assert_eq!(
            Platform::from_url("https://gitea.com/user/repo"),
            Some(Platform::Gitea)
        );
        assert_eq!(
            Platform::from_url("https://gitea.example.com/user/repo"),
            Some(Platform::Gitea)
        );
    }

    #[test]
    fn test_platform_from_url_azure() {
        assert_eq!(
            Platform::from_url("https://dev.azure.com/org/project/_git/repo"),
            Some(Platform::AzureDevOps)
        );
        assert_eq!(
            Platform::from_url("https://org.visualstudio.com/project/_git/repo"),
            Some(Platform::AzureDevOps)
        );
    }

    #[test]
    fn test_platform_from_url_unknown() {
        assert_eq!(Platform::from_url("https://example.com/user/repo"), None);
        assert_eq!(Platform::from_url("not-a-url"), None);
    }

    #[test]
    fn test_platform_name() {
        assert_eq!(Platform::GitHub.name(), "GitHub");
        assert_eq!(Platform::GitLab.name(), "GitLab");
        assert_eq!(Platform::Bitbucket.name(), "Bitbucket");
        assert_eq!(Platform::Gitea.name(), "Gitea");
        assert_eq!(Platform::AzureDevOps.name(), "Azure DevOps");
    }

    #[test]
    fn test_platform_api_base_url() {
        assert_eq!(Platform::GitHub.api_base_url(), "https://api.github.com");
        assert_eq!(Platform::GitLab.api_base_url(), "https://gitlab.com/api/v4");
        assert_eq!(
            Platform::Bitbucket.api_base_url(),
            "https://api.bitbucket.org/2.0"
        );
    }

    #[test]
    fn test_platform_default_rate_limit() {
        assert_eq!(Platform::GitHub.default_rate_limit(), 5000);
        assert_eq!(Platform::GitLab.default_rate_limit(), 2000);
        assert_eq!(Platform::Bitbucket.default_rate_limit(), 1000);
    }

    #[test]
    fn test_parse_repo_url_github() {
        assert_eq!(
            parse_repo_url("https://github.com/user/repo"),
            Some(("user".to_string(), "repo".to_string()))
        );
        assert_eq!(
            parse_repo_url("https://github.com/user/repo.git"),
            Some(("user".to_string(), "repo".to_string()))
        );
    }

    #[test]
    fn test_parse_repo_url_gitlab() {
        assert_eq!(
            parse_repo_url("https://gitlab.com/group/project"),
            Some(("group".to_string(), "project".to_string()))
        );
    }

    #[test]
    fn test_parse_repo_url_invalid() {
        assert_eq!(parse_repo_url("not-a-url"), None);
        assert_eq!(parse_repo_url("https://example.com"), None);
    }

    #[test]
    fn test_auth_token_from_str_github() {
        assert!(matches!(
            AuthToken::from_str("ghp_1234567890".to_string()),
            AuthToken::Personal(_)
        ));
        assert!(matches!(
            AuthToken::from_str("gho_1234567890".to_string()),
            AuthToken::Personal(_)
        ));
    }

    #[test]
    fn test_auth_token_from_str_gitlab() {
        assert!(matches!(
            AuthToken::from_str("glpat-1234567890".to_string()),
            AuthToken::Personal(_)
        ));
    }

    #[test]
    fn test_auth_token_from_str_jwt() {
        // JWT format: header.payload.signature
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(matches!(
            AuthToken::from_str(jwt.to_string()),
            AuthToken::Jwt(_)
        ));
    }

    #[test]
    fn test_auth_token_value() {
        let token = "my_token";
        assert_eq!(AuthToken::Personal(token.to_string()).value(), token);
        assert_eq!(AuthToken::OAuth(token.to_string()).value(), token);
        assert_eq!(AuthToken::Jwt(token.to_string()).value(), token);
    }

    #[test]
    fn test_build_api_headers_github() {
        let headers = build_api_headers(Platform::GitHub, "ghp_test");
        assert!(headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "token ghp_test"));
        assert!(headers
            .iter()
            .any(|(k, v)| k == "Accept" && v == "application/vnd.github+json"));
        assert!(headers.iter().any(|(k, _v)| k == "X-GitHub-Api-Version"));
    }

    #[test]
    fn test_build_api_headers_gitlab() {
        let headers = build_api_headers(Platform::GitLab, "glpat-test");
        assert!(headers
            .iter()
            .any(|(k, v)| k == "PRIVATE-TOKEN" && v == "glpat-test"));
    }

    #[test]
    fn test_build_api_headers_bitbucket() {
        let headers = build_api_headers(Platform::Bitbucket, "test_token");
        assert!(headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer test_token"));
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{EnumScope, Forge, Platform, RateLimitInfo, Repository, TreeEntry};
    use async_trait::async_trait;
    use std::time::Duration;

    struct ContractForge {
        authenticated: bool,
    }

    fn fixture_repository() -> Repository {
        Repository {
            full_name: "acme/example".to_string(),
            owner: "acme".to_string(),
            name: "example".to_string(),
            private: true,
            default_branch: "main".to_string(),
            clone_url: "https://forge.example/acme/example.git".to_string(),
            platform: Platform::GitHub,
            stars: Some(7),
            forks: Some(2),
            description: Some("contract fixture".to_string()),
            updated_at: None,
        }
    }

    #[async_trait]
    impl Forge for ContractForge {
        async fn authenticate(&mut self, token: &str) -> anyhow::Result<()> {
            anyhow::ensure!(!token.is_empty(), "empty token");
            self.authenticated = true;
            Ok(())
        }

        async fn enumerate_repos(&self, _scope: EnumScope) -> anyhow::Result<Vec<Repository>> {
            anyhow::ensure!(self.authenticated, "not authenticated");
            Ok(vec![fixture_repository()])
        }

        async fn get_tree(
            &self,
            _repo: &Repository,
            branch: &str,
        ) -> anyhow::Result<Vec<TreeEntry>> {
            anyhow::ensure!(branch == "main", "unexpected branch");
            Ok(vec![TreeEntry {
                path: "config.txt".to_string(),
                obj_type: "blob".to_string(),
                sha: "0123456789012345678901234567890123456789".to_string(),
                size: Some(12),
                mode: Some("100644".to_string()),
            }])
        }

        async fn get_blob(&self, _repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>> {
            anyhow::ensure!(!sha.is_empty(), "empty blob sha");
            Ok(b"TOKEN=fixture".to_vec())
        }

        fn rate_limit_remaining(&self) -> Option<(u32, Duration)> {
            Some((4999, Duration::from_secs(30)))
        }

        fn rate_limit_info(&self) -> Option<RateLimitInfo> {
            Some(RateLimitInfo {
                remaining: 4999,
                reset_in: Duration::from_secs(30),
                limit: 5000,
            })
        }

        fn platform(&self) -> Platform {
            Platform::GitHub
        }

        async fn get_head_sha(&self, _repo: &Repository, branch: &str) -> anyhow::Result<String> {
            anyhow::ensure!(branch == "main", "unexpected branch");
            Ok("abcdef0123456789abcdef0123456789abcdef01".to_string())
        }

        async fn whoami(&self) -> anyhow::Result<(String, String)> {
            anyhow::ensure!(self.authenticated, "not authenticated");
            Ok(("fixture-user".to_string(), "Fixture User".to_string()))
        }
    }

    #[tokio::test]
    async fn forge_contract_covers_core_repository_lifecycle() {
        let mut forge = ContractForge {
            authenticated: false,
        };
        forge.authenticate("synthetic-token").await.unwrap();
        let repos = forge.enumerate_repos(EnumScope::User).await.unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].full_name, "acme/example");

        let tree = forge.get_tree(&repos[0], "main").await.unwrap();
        assert_eq!(tree[0].obj_type, "blob");
        let blob = forge.get_blob(&repos[0], &tree[0].sha).await.unwrap();
        assert_eq!(blob, b"TOKEN=fixture");
        assert_eq!(
            forge.get_head_sha(&repos[0], "main").await.unwrap().len(),
            40
        );
    }

    #[tokio::test]
    async fn forge_contract_exposes_identity_platform_and_rate_limit() {
        let mut forge = ContractForge {
            authenticated: false,
        };
        assert_eq!(forge.platform(), Platform::GitHub);
        assert_eq!(forge.rate_limit_remaining().unwrap().0, 4999);
        assert_eq!(forge.rate_limit_info().unwrap().limit, 5000);
        assert!(forge.whoami().await.is_err());
        forge.authenticate("synthetic-token").await.unwrap();
        assert_eq!(forge.whoami().await.unwrap().0, "fixture-user");
    }
}

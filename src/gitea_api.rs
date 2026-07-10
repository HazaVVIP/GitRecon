//! gitea_api.rs
//! Gitea/Forgejo REST API v1 integration for `--gitea-token` mode.
//!
//! Provides repository enumeration and file blob fetching via PAT authentication.
//! All requests are authenticated with `Authorization: token <PAT>` and target
//! `https://gitea.com/api/v1` or self-hosted instances via --gitea-url.
//!
//! Compatible with Gitea 1.19+ and Forgejo (API-compatible fork).

use crate::forge::{EnumScope, Forge, Platform, RateLimitInfo, Repository, TreeEntry};
use crate::http_client::{HttpClient, HttpConfig};
use async_trait::async_trait;
use std::time::{Duration, Instant};

const DEFAULT_GT_API: &str = "https://gitea.com/api/v1";

// ════════════════════════════════════════════════
// FORGE TRAIT IMPLEMENTATION
// ════════════════════════════════════════════════

/// Gitea API client implementing the Forge trait.
pub struct GiteaForgeClient {
    client: HttpClient,
    api_base: String,
    rate_limit_remaining: std::sync::Arc<std::sync::Mutex<Option<(u32, Instant)>>>,
}

impl GiteaForgeClient {
    /// Create a new Gitea forge client.
    pub fn new(client: HttpClient, api_base: String) -> Self {
        Self {
            client,
            api_base,
            rate_limit_remaining: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Update rate limit from response headers.
    fn update_rate_limit(&self, headers: &std::collections::HashMap<String, String>) {
        // Gitea/Forgejo rate limit headers (if configured)
        // X-RateLimit-Remaining, X-RateLimit-Reset
        if let Some(remaining) = headers.get("x-ratelimit-remaining") {
            if let Ok(r) = remaining.parse::<u32>() {
                let reset_time = headers
                    .get("x-ratelimit-reset")
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|ts| {
                        let reset = std::time::UNIX_EPOCH + Duration::from_secs(ts);
                        let now = std::time::SystemTime::now();
                        reset.duration_since(now).unwrap_or(Duration::from_secs(3600))
                    })
                    .unwrap_or(Duration::from_secs(3600));

                *self.rate_limit_remaining.lock().unwrap() = Some((r, Instant::now() + reset_time));
            }
        }
    }

    /// Make a GET request and update rate limit tracking.
    async fn get_with_rate_limit(&self, url: &str) -> anyhow::Result<crate::http_client::Response> {
        let resp = self.client.get(url).await;

        // Update rate limit from headers
        if resp.status == 200 || resp.status == 0 {
            let mut headers = std::collections::HashMap::new();
            for (k, v) in resp.headers.iter() {
                headers.insert(k.to_lowercase(), v.clone());
            }
            self.update_rate_limit(&headers);
        }

        Ok(resp)
    }
}

#[async_trait]
impl Forge for GiteaForgeClient {
    async fn authenticate(&mut self, _token: &str) -> anyhow::Result<()> {
        // Validate token by calling /user
        let url = format!("{}/user", self.api_base);
        let resp = self.get_with_rate_limit(&url).await?;

        if resp.status == 401 {
            anyhow::bail!("Invalid or expired token (HTTP 401)");
        }

        if !resp.ok() {
            anyhow::bail!("Authentication failed with HTTP {}", resp.status);
        }

        Ok(())
    }

    async fn enumerate_repos(&self, scope: EnumScope) -> anyhow::Result<Vec<Repository>> {
        let mut repos = Vec::new();

        match scope {
            EnumScope::User => {
                // Get user repos via /user/repos
                let url = format!("{}/user/repos?limit=50", self.api_base);
                repos.extend(self.fetch_all_repos(url).await?);
            }
            EnumScope::Org(org) => {
                // Get org repos
                let url = format!("{}/orgs/{}/repos?limit=50", self.api_base, org);
                repos.extend(self.fetch_all_repos(url).await?);
            }
            EnumScope::All => {
                // For "All", fetch user repos and then org repos
                let user_url = format!("{}/user/repos?limit=50", self.api_base);
                repos.extend(self.fetch_all_repos(user_url).await?);

                // Also fetch orgs the user belongs to and their repos
                if let Ok(orgs) = list_user_orgs(&self.client, &self.api_base).await {
                    for org in orgs {
                        let url = format!("{}/orgs/{}/repos?limit=50", self.api_base, org);
                        if let Ok(org_repos) = self.fetch_all_repos(url).await {
                            repos.extend(org_repos);
                        }
                    }
                }
            }
        }

        // Deduplicate by full name
        let mut seen = std::collections::HashSet::new();
        repos.retain(|r| seen.insert(r.full_name.clone()));

        Ok(repos)
    }

    async fn get_tree(&self, repo: &Repository, branch: &str) -> anyhow::Result<Vec<TreeEntry>> {
        let sha = self.get_head_sha(repo, branch).await?;
        let url = format!("{}/repos/{}/{}/git/trees/{}?recursive=true", self.api_base, repo.owner, repo.name, sha);
        let resp = self.get_with_rate_limit(&url).await?;

        if !resp.ok() {
            anyhow::bail!("GET tree {} returned HTTP {}", url, resp.status);
        }

        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        let gt_entries = parse_tree_entries(&json);

        // Convert to unified TreeEntry format
        Ok(gt_entries
            .into_iter()
            .map(|e| TreeEntry {
                path: e.path,
                obj_type: e.obj_type,
                sha: e.sha,
                size: e.size,
                mode: e.mode,
            })
            .collect())
    }

    async fn get_blob(&self, repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>> {
        get_blob_content(&self.client, &self.api_base, &repo.owner, &repo.name, sha).await
    }

    fn rate_limit_remaining(&self) -> Option<(u32, Duration)> {
        self.rate_limit_remaining
            .lock()
            .unwrap()
            .as_ref()
            .map(|(remaining, reset)| (*remaining, reset.saturating_duration_since(Instant::now())))
    }

    fn rate_limit_info(&self) -> Option<RateLimitInfo> {
        self.rate_limit_remaining().map(|(remaining, reset_in)| RateLimitInfo {
            remaining,
            reset_in,
            limit: Platform::Gitea.default_rate_limit(),
        })
    }

    fn platform(&self) -> Platform {
        Platform::Gitea
    }

    async fn get_head_sha(&self, repo: &Repository, branch: &str) -> anyhow::Result<String> {
        get_head_sha(&self.client, &self.api_base, &repo.owner, &repo.name, branch).await
    }

    async fn whoami(&self) -> anyhow::Result<(String, String)> {
        whoami(&self.client, &self.api_base).await
    }
}

impl GiteaForgeClient {
    /// Fetch all repositories from a paginated Gitea endpoint.
    async fn fetch_all_repos(&self, mut url: String) -> anyhow::Result<Vec<Repository>> {
        let mut repos = Vec::new();
        let mut page = 1;

        loop {
            // Add page parameter if not present
            if !url.contains("page=") {
                url = format!("{}&page={}", url, page);
            }

            let resp = self.get_with_rate_limit(&url).await?;
            if !resp.ok() {
                anyhow::bail!("GET {} returned HTTP {}", url, resp.status);
            }

            let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
            let arr = json.as_array().ok_or_else(|| {
                anyhow::anyhow!("Expected JSON array from repos endpoint")
            })?;

            if arr.is_empty() {
                break;
            }

            for r in arr {
                if let Some(gt_repo) = parse_repo(r) {
                    repos.push(Repository {
                        full_name: gt_repo.full_name.clone(),
                        owner: gt_repo.owner.clone(),
                        name: gt_repo.name.clone(),
                        private: gt_repo.private,
                        default_branch: gt_repo.default_branch.clone(),
                        clone_url: gt_repo.clone_url.clone(),
                        platform: Platform::Gitea,
                        stars: r["stars_count"].as_u64().map(|v| v as u32),
                        forks: r["forks_count"].as_u64().map(|v| v as u32),
                        description: r["description"].as_str().map(|s| s.to_string()),
                        updated_at: r["updated_at"].as_str().map(|s| s.to_string()),
                    });
                }
            }

            // Check if there are more pages
            // Gitea API v1 doesn't use Link header, uses pagination parameters
            // We'll continue until we get an empty response
            page += 1;

            // Remove page parameter for next iteration
            if let Some(pos) = url.find("&page=") {
                url = format!("{}&page={}", &url[..pos], page);
            }
        }

        Ok(repos)
    }
}

// ════════════════════════════════════════════════
// DATA STRUCTURES
// ════════════════════════════════════════════════

/// A Gitea repository accessible to the authenticated user.
#[derive(Debug, Clone)]
pub struct GtRepo {
    pub full_name:      String,
    pub owner:          String,
    pub name:           String,
    pub private:        bool,
    pub default_branch: String,
    pub clone_url:      String,
}

/// A single entry (blob or tree) from a Gitea tree API response.
#[derive(Debug, Clone)]
pub struct GtTreeEntry {
    pub path:     String,
    pub obj_type: String,   // "blob" or "tree"
    pub sha:      String,
    pub size:     Option<u64>,
    pub mode:     Option<String>,
}

// ════════════════════════════════════════════════
// CLIENT BUILDER
// ════════════════════════════════════════════════

/// Create a new [`HttpClient`] configured for Gitea API calls.
///
/// Clones `base_cfg` and injects the required Gitea header:
/// - `Authorization: token <PAT>`
pub fn build_gitea_client(mut base_cfg: HttpConfig, token: &str, gitea_url: Option<&str>) -> anyhow::Result<(HttpClient, String)> {
    let api_base = gitea_url.unwrap_or(DEFAULT_GT_API).to_string();

    // Ensure API base ends with /api/v1
    let api_base = if api_base.ends_with("/api/v1") {
        api_base
    } else if api_base.ends_with("/api/v1/") {
        api_base.trim_end_matches('/').to_string()
    } else if api_base.contains("/api/") {
        api_base
    } else {
        format!("{}/api/v1", api_base.trim_end_matches('/'))
    };

    base_cfg.extra_headers.push(("Authorization".to_string(), format!("token {}", token)));
    let client = HttpClient::new(base_cfg)?;

    Ok((client, api_base))
}

// ════════════════════════════════════════════════
// API HELPERS
// ════════════════════════════════════════════════

fn parse_repo(v: &serde_json::Value) -> Option<GtRepo> {
    let full_name      = v["full_name"].as_str()?.to_string();
    let owner          = v["owner"]["login"].as_str().unwrap_or("").to_string();
    let name           = v["name"].as_str().unwrap_or("").to_string();
    let private        = v["private"].as_bool().unwrap_or(false);
    let default_branch = v["default_branch"].as_str().unwrap_or("main").to_string();
    let clone_url      = v["clone_url"].as_str().unwrap_or("").to_string();
    Some(GtRepo { full_name, owner, name, private, default_branch, clone_url })
}

fn parse_tree_entries(json: &serde_json::Value) -> Vec<GtTreeEntry> {
    let tree = match json["tree"].as_array() {
        Some(a) => a,
        None    => return Vec::new(),
    };
    tree.iter()
        .filter_map(|item| {
            let path     = item["path"].as_str().unwrap_or("").to_string();
            let obj_type = item["type"].as_str().unwrap_or("").to_string();
            let sha      = item["sha"].as_str().unwrap_or("").to_string();
            let size     = item["size"].as_u64();
            let mode     = item["mode"].as_str().map(|s| s.to_string());
            if path.is_empty() || sha.is_empty() { return None; }
            Some(GtTreeEntry { path, obj_type, sha, size, mode })
        })
        .collect()
}

// ════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════

/// Identify the authenticated user.
///
/// Calls `GET /user` and returns `(login, full_name)`.
/// Returns an error on HTTP 401 (invalid/expired token) or any non-200 status.
pub async fn whoami(client: &HttpClient, api_base: &str) -> anyhow::Result<(String, String)> {
    let url  = format!("{}/user", api_base);
    let resp = client.get(&url).await;
    if resp.status == 401 {
        anyhow::bail!("Invalid or expired token (HTTP 401)");
    }
    if !resp.ok() {
        anyhow::bail!("GET /user returned HTTP {}", resp.status);
    }
    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
    let login = json["login"].as_str().unwrap_or("").to_string();
    let full_name = json["full_name"].as_str().unwrap_or("").to_string();
    Ok((login, full_name))
}

/// List all organisations the authenticated user belongs to.
pub async fn list_user_orgs(client: &HttpClient, api_base: &str) -> anyhow::Result<Vec<String>> {
    let mut orgs = Vec::new();
    let mut page = 1i32;

    loop {
        let url = format!("{}/user/orgs?limit=50&page={}", api_base, page);
        let resp = client.get(&url).await;
        if !resp.ok() { break; }
        let json: serde_json::Value = serde_json::from_slice(&resp.body).unwrap_or_default();
        let arr  = match json.as_array() {
            Some(a) => a,
            None    => break,
        };

        if arr.is_empty() {
            break;
        }

        for o in arr {
            if let Some(username) = o["username"].as_str() {
                orgs.push(username.to_string());
            }
        }
        page += 1;
    }
    Ok(orgs)
}

/// Resolve the HEAD commit SHA for a branch.
///
/// Uses `GET /repos/{owner}/{repo}/git/refs/heads/{branch}`.
pub async fn get_head_sha(
    client:  &HttpClient,
    api_base: &str,
    owner:   &str,
    repo:    &str,
    branch:  &str,
) -> anyhow::Result<String> {
    let url  = format!("{}/repos/{}/{}/git/refs/heads/{}", api_base, owner, repo, branch);
    let resp = client.get(&url).await;
    if resp.ok() {
        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        // Response can be a single object or an array of matching refs
        let sha = if let Some(arr) = json.as_array() {
            arr.first().and_then(|r| r["object"]["sha"].as_str()).map(|s| s.to_string())
        } else {
            json["object"]["sha"].as_str().map(|s| s.to_string())
        };
        if let Some(s) = sha {
            return Ok(s);
        }
    }

    anyhow::bail!(
        "Cannot resolve HEAD SHA for {}/{} branch '{}' (HTTP {})",
        owner, repo, branch, resp.status
    )
}

/// Fetch the raw content of a blob by its SHA.
///
/// Uses `GET /repos/{owner}/{repo}/git/blobs/{sha}`.
/// Gitea returns content as base64; this function decodes it automatically.
pub async fn get_blob_content(
    client:  &HttpClient,
    api_base: &str,
    owner:   &str,
    repo:    &str,
    sha:     &str,
) -> anyhow::Result<Vec<u8>> {
    let url  = format!("{}/repos/{}/{}/git/blobs/{}", api_base, owner, repo, sha);
    let resp = client.get(&url).await;
    if !resp.ok() {
        anyhow::bail!("GET blob {} returned HTTP {}", url, resp.status);
    }
    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
    let encoding    = json["encoding"].as_str().unwrap_or("base64");
    let content_str = json["content"].as_str().unwrap_or("");

    if encoding == "base64" {
        // Gitea embeds newlines in the base64 payload — strip them before decoding
        let cleaned: String = content_str.chars().filter(|&c| c != '\n' && c != '\r').collect();
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .map_err(|e| anyhow::anyhow!("Base64 decode of blob {} failed: {}", sha, e))
    } else {
        // UTF-8 / raw content
        Ok(content_str.as_bytes().to_vec())
    }
}

// ════════════════════════════════════════════════
// TESTS
// ════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_repo_full() {
        let v = serde_json::json!({
            "full_name":      "octocat/hello-world",
            "owner":          {"login": "octocat"},
            "name":           "hello-world",
            "private":        false,
            "default_branch": "main",
            "clone_url":      "https://gitea.com/octocat/hello-world.git"
        });
        let repo = parse_repo(&v).unwrap();
        assert_eq!(repo.full_name, "octocat/hello-world");
        assert_eq!(repo.owner, "octocat");
        assert_eq!(repo.name, "hello-world");
        assert!(!repo.private);
        assert_eq!(repo.default_branch, "main");
        assert_eq!(repo.clone_url, "https://gitea.com/octocat/hello-world.git");
    }

    #[test]
    fn test_parse_repo_private() {
        let v = serde_json::json!({
            "full_name":      "corp/secret-repo",
            "owner":          {"login": "corp"},
            "name":           "secret-repo",
            "private":        true,
            "default_branch": "master",
            "clone_url":      "https://gitea.com/corp/secret-repo.git"
        });
        let repo = parse_repo(&v).unwrap();
        assert!(repo.private);
        assert_eq!(repo.default_branch, "master");
    }

    #[test]
    fn test_parse_tree_entries_blob_and_tree() {
        let json = serde_json::json!({
            "tree": [
                {"path": "src/main.rs", "type": "blob", "sha": "abc123abc123abc123abc123abc123abc123abc1", "size": 1024, "mode": "100644"},
                {"path": "src",         "type": "tree", "sha": "def456def456def456def456def456def456def4", "mode": "040000"},
                {"path": "",            "type": "blob", "sha": "bad000"},
            ],
            "truncated": false
        });
        let entries = parse_tree_entries(&json);
        // Empty path entry must be dropped
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "src/main.rs");
        assert_eq!(entries[0].obj_type, "blob");
        assert_eq!(entries[0].size, Some(1024));
        assert_eq!(entries[0].mode, Some("100644".to_string()));
        assert_eq!(entries[1].obj_type, "tree");
    }

    #[test]
    fn test_build_gitea_client_api_base_normalization() {
        use crate::http_client::HttpConfig;
        let base_cfg = HttpConfig {
            timeout: Duration::from_secs(10),
            retries: 3,
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
            proxy: None,
            verify_ssl: false,
            custom_ua: None,
            extra_headers: vec![],
            max_size: 100 * 1024 * 1024,
            adaptive_timeout: false,
            max_timeout: Duration::from_secs(60),
            use_http2: false,
            rate_limit_rps: None,
            proxy_list: vec![],
            ua_pool: vec![],
            retry_strategy: crate::http_client::RetryStrategy::Standard,
        };

        // Test with full URL
        let (client1, api_base1) = build_gitea_client(base_cfg.clone(), "test_token", Some("https://gitea.example.com/api/v1")).unwrap();
        assert_eq!(api_base1, "https://gitea.example.com/api/v1");
        drop(client1);

        // Test with base URL (should append /api/v1)
        let (client2, api_base2) = build_gitea_client(base_cfg.clone(), "test_token", Some("https://gitea.example.com")).unwrap();
        assert_eq!(api_base2, "https://gitea.example.com/api/v1");
        drop(client2);

        // Test with default (no URL provided)
        let (client3, api_base3) = build_gitea_client(base_cfg, "test_token", None).unwrap();
        assert_eq!(api_base3, DEFAULT_GT_API);
        drop(client3);
    }
}

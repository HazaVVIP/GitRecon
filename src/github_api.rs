//! github_api.rs
//! GitHub REST API v3 integration for `--token` mode.
//!
//! Provides repository enumeration and file blob fetching via PAT authentication.
//! All requests are authenticated with `Authorization: token <PAT>` and target
//! `https://api.github.com`.

use crate::forge::{EnumScope, Forge, Platform, RateLimitInfo, Repository, TreeEntry};
use crate::http_client::{HttpClient, HttpConfig};
use async_trait::async_trait;
use std::time::{Duration, Instant};
use anyhow::Context;

const GH_API: &str = "https://api.github.com";

// ════════════════════════════════════════════════
// FORGE TRAIT IMPLEMENTATION
// ════════════════════════════════════════════════

/// GitHub API client implementing the Forge trait.
pub struct GitHubForgeClient {
    client: HttpClient,
    rate_limit_remaining: std::sync::Arc<std::sync::Mutex<Option<(u32, Instant)>>>,
}

impl GitHubForgeClient {
    /// Create a new GitHub forge client.
    pub fn new(client: HttpClient) -> Self {
        Self {
            client,
            rate_limit_remaining: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Update rate limit from response headers.
    fn update_rate_limit(&self, headers: &std::collections::HashMap<String, String>) {
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

                if let Ok(mut guard) = self.rate_limit_remaining.lock() {
                    *guard = Some((r, Instant::now() + reset_time));
                }
            }
        }
    }

    /// Make a GET request and update rate limit tracking.
    async fn get_with_rate_limit(&self, url: &str) -> anyhow::Result<crate::http_client::Response> {
        let resp = self.client.get(url).await;

        // Update rate limit from headers
        if resp.status == 200 || resp.status == 0 {
            // Try to parse rate limit headers
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
impl Forge for GitHubForgeClient {
    async fn authenticate(&mut self, _token: &str) -> anyhow::Result<()> {
        // Validate token by calling /user
        let url = format!("{}/user", GH_API);
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

        let url = match &scope {
            EnumScope::User => format!("{}/user/repos?per_page=100&type=all&sort=updated", GH_API),
            EnumScope::Org(org) => format!("{}/orgs/{}/repos?per_page=100&type=all", GH_API, org),
            EnumScope::All => {
                // For "All", we'll start with user repos
                format!("{}/user/repos?per_page=100&type=all&sort=updated", GH_API)
            }
        };

        let mut current_url = url;
        loop {
            let resp = self.get_with_rate_limit(&current_url).await?;
            if !resp.ok() {
                anyhow::bail!("GET {} returned HTTP {}", current_url, resp.status);
            }

            let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
            let arr = json.as_array().ok_or_else(|| {
                anyhow::anyhow!("Expected JSON array from repos endpoint")
            })?;

            for r in arr {
                if let Some(gh_repo) = parse_repo(r) {
                    repos.push(Repository {
                        full_name: gh_repo.full_name.clone(),
                        owner: gh_repo.owner.clone(),
                        name: gh_repo.name.clone(),
                        private: gh_repo.private,
                        default_branch: gh_repo.default_branch.clone(),
                        clone_url: gh_repo.clone_url.clone(),
                        platform: Platform::GitHub,
                        stars: r["stargazers_count"].as_u64().map(|v| v as u32),
                        forks: r["forks_count"].as_u64().map(|v| v as u32),
                        description: r["description"].as_str().map(|s| s.to_string()),
                        updated_at: r["updated_at"].as_str().map(|s| s.to_string()),
                    });
                }
            }

            match resp.headers.get("link").and_then(|h| parse_next_link(h)) {
                Some(next) => current_url = next,
                None => break,
            }
        }

        // For EnumScope::All, also fetch org repos
        if let EnumScope::All = scope {
            if let Ok(orgs) = list_user_orgs(&self.client).await {
                for org in orgs {
                    if let Ok(org_repos) = self.enumerate_repos(EnumScope::Org(org)).await {
                        repos.extend(org_repos);
                    }
                }
            }
        }

        // Deduplicate
        let mut seen = std::collections::HashSet::new();
        repos.retain(|r| seen.insert(r.full_name.clone()));

        Ok(repos)
    }

    async fn get_tree(&self, repo: &Repository, branch: &str) -> anyhow::Result<Vec<TreeEntry>> {
        let sha = self.get_head_sha(repo, branch).await?;
        let url = format!("{}/repos/{}/{}/git/trees/{}?recursive=1", GH_API, repo.owner, repo.name, sha);
        let resp = self.get_with_rate_limit(&url).await?;

        if !resp.ok() {
            anyhow::bail!("GET tree {} returned HTTP {}", url, resp.status);
        }

        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        let gh_entries = parse_tree_entries(&json);

        // Convert to unified TreeEntry format
        Ok(gh_entries
            .into_iter()
            .map(|e| TreeEntry {
                path: e.path,
                obj_type: e.obj_type,
                sha: e.sha,
                size: e.size,
                mode: None, // GitHub API tree doesn't include mode in recursive response
            })
            .collect())
    }

    async fn get_blob(&self, repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>> {
        get_blob_content(&self.client, &repo.owner, &repo.name, sha).await
    }

    fn rate_limit_remaining(&self) -> Option<(u32, Duration)> {
        self.rate_limit_remaining
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|(remaining, reset)| {
                (*remaining, reset.saturating_duration_since(Instant::now()))
            }))
    }

    fn rate_limit_info(&self) -> Option<RateLimitInfo> {
        self.rate_limit_remaining().map(|(remaining, reset_in)| RateLimitInfo {
            remaining,
            reset_in,
            limit: Platform::GitHub.default_rate_limit(),
        })
    }

    fn platform(&self) -> Platform {
        Platform::GitHub
    }

    async fn get_head_sha(&self, repo: &Repository, branch: &str) -> anyhow::Result<String> {
        get_head_sha(&self.client, &repo.owner, &repo.name, branch).await
    }

    async fn whoami(&self) -> anyhow::Result<(String, String)> {
        whoami(&self.client).await
    }
}

// ════════════════════════════════════════════════
// DATA STRUCTURES
// ════════════════════════════════════════════════

/// A GitHub repository accessible to the authenticated user.
#[derive(Debug, Clone)]
pub struct GhRepo {
    pub full_name:      String,
    pub owner:          String,
    pub name:           String,
    #[allow(dead_code)]
    pub private:        bool,
    pub default_branch: String,
    #[allow(dead_code)]
    pub clone_url:      String,
}

/// A single entry (blob or tree) from a Git tree API response.
#[derive(Debug, Clone)]
pub struct GhTreeEntry {
    pub path:     String,
    pub obj_type: String,   // "blob" or "tree"
    pub sha:      String,
    pub size:     Option<u64>,
}

// ════════════════════════════════════════════════
// CLIENT BUILDER
// ════════════════════════════════════════════════

/// Create a new [`HttpClient`] configured for GitHub API calls.
///
/// Clones `base_cfg` and injects the three required GitHub headers:
/// - `Authorization: token <PAT>`
/// - `Accept: application/vnd.github+json`
/// - `X-GitHub-Api-Version: 2022-11-28`
pub fn build_github_client(mut base_cfg: HttpConfig, token: &str) -> anyhow::Result<HttpClient> {
    base_cfg.extra_headers.push(("Authorization".to_string(), format!("token {}", token)));
    base_cfg.extra_headers.push(("Accept".to_string(), "application/vnd.github+json".to_string()));
    base_cfg.extra_headers.push(("X-GitHub-Api-Version".to_string(), "2022-11-28".to_string()));
    HttpClient::new(base_cfg)
}

// ════════════════════════════════════════════════
// API HELPERS
// ════════════════════════════════════════════════

/// Parse the `next` URL from a GitHub `Link` response header.
///
/// # Example header
/// ```text
/// <https://api.github.com/user/repos?page=2>; rel="next", ...
/// ```
fn parse_next_link(header: &str) -> Option<String> {
    for part in header.split(',') {
        let part = part.trim();
        if part.contains(r#"rel="next""#) {
            if let Some(start) = part.find('<') {
                if let Some(end) = part.find('>') {
                    return Some(part[start + 1..end].to_string());
                }
            }
        }
    }
    None
}

fn parse_repo(v: &serde_json::Value) -> Option<GhRepo> {
    let full_name      = v["full_name"].as_str()?.to_string();
    let owner          = v["owner"]["login"].as_str().unwrap_or("").to_string();
    let name           = v["name"].as_str().unwrap_or("").to_string();
    let private        = v["private"].as_bool().unwrap_or(false);
    let default_branch = v["default_branch"].as_str().unwrap_or("main").to_string();
    let clone_url      = v["clone_url"].as_str().unwrap_or("").to_string();
    Some(GhRepo { full_name, owner, name, private, default_branch, clone_url })
}

fn parse_tree_entries(json: &serde_json::Value) -> Vec<GhTreeEntry> {
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
            if path.is_empty() || sha.is_empty() { return None; }
            Some(GhTreeEntry { path, obj_type, sha, size })
        })
        .collect()
}

// ════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════

/// Identify the authenticated user.
///
/// Calls `GET /user` and returns `(login, name)`.
/// Returns an error on HTTP 401 (invalid/expired token) or any non-200 status.
pub async fn whoami(client: &HttpClient) -> anyhow::Result<(String, String)> {
    let url  = format!("{}/user", GH_API);
    let resp = client.get(&url).await;
    if resp.status == 401 {
        anyhow::bail!("Invalid or expired token (HTTP 401)");
    }
    if !resp.ok() {
        anyhow::bail!("GET /user returned HTTP {}", resp.status);
    }
    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
    let login = json["login"].as_str().unwrap_or("").to_string();
    let name  = json["name"].as_str().unwrap_or("").to_string();
    Ok((login, name))
}

/// List all repositories accessible to the authenticated user (paginated).
///
/// Uses `GET /user/repos?type=all` which returns repos the user owns, has
/// collaborator access to, or has organisation membership for.
pub async fn list_repos(client: &HttpClient) -> anyhow::Result<Vec<GhRepo>> {
    let mut repos = Vec::new();
    let mut url   = format!("{}/user/repos?per_page=100&type=all&sort=updated", GH_API);
    loop {
        let resp = client.get(&url).await;
        if !resp.ok() {
            anyhow::bail!("GET {} returned HTTP {}", url, resp.status);
        }
        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        let arr  = json.as_array()
            .ok_or_else(|| anyhow::anyhow!("Expected JSON array from /user/repos"))?;
        for r in arr {
            if let Some(repo) = parse_repo(r) {
                repos.push(repo);
            }
        }
        match resp.headers.get("link").and_then(|h| parse_next_link(h)) {
            Some(next) => url = next,
            None       => break,
        }
    }
    Ok(repos)
}

/// List all organisations the authenticated user belongs to.
pub async fn list_user_orgs(client: &HttpClient) -> anyhow::Result<Vec<String>> {
    let mut orgs = Vec::new();
    let mut url  = format!("{}/user/orgs?per_page=100", GH_API);
    loop {
        let resp = client.get(&url).await;
        if !resp.ok() { break; }
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .with_context(|| format!("Failed to parse JSON response from {}", url))?;
        let arr  = match json.as_array() {
            Some(a) => a,
            None    => break,
        };
        for o in arr {
            if let Some(login) = o["login"].as_str() {
                orgs.push(login.to_string());
            }
        }
        match resp.headers.get("link").and_then(|h| parse_next_link(h)) {
            Some(next) => url = next,
            None       => break,
        }
    }
    Ok(orgs)
}

/// List all repositories in an organisation (paginated).
pub async fn list_org_repos(client: &HttpClient, org: &str) -> anyhow::Result<Vec<GhRepo>> {
    let mut repos = Vec::new();
    let mut url   = format!("{}/orgs/{}/repos?per_page=100&type=all", GH_API, org);
    loop {
        let resp = client.get(&url).await;
        if !resp.ok() { break; }
        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .with_context(|| format!("Failed to parse JSON response from {}", url))?;
        let arr  = match json.as_array() {
            Some(a) => a,
            None    => break,
        };
        for r in arr {
            if let Some(repo) = parse_repo(r) {
                repos.push(repo);
            }
        }
        match resp.headers.get("link").and_then(|h| parse_next_link(h)) {
            Some(next) => url = next,
            None       => break,
        }
    }
    Ok(repos)
}

/// Resolve the HEAD commit SHA for a branch.
///
/// Uses `GET /repos/{owner}/{repo}/git/refs/heads/{branch}`.
/// Falls back to `GET /repos/{owner}/{repo}/commits/{branch}` if refs return
/// a 404 (e.g. for empty repos with a non-default first commit).
pub async fn get_head_sha(
    client:  &HttpClient,
    owner:   &str,
    repo:    &str,
    branch:  &str,
) -> anyhow::Result<String> {
    let url  = format!("{}/repos/{}/{}/git/refs/heads/{}", GH_API, owner, repo, branch);
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

    // Fallback: get latest commit via commits endpoint
    let fallback_url  = format!("{}/repos/{}/{}/commits/{}?per_page=1", GH_API, owner, repo, branch);
    let fallback_resp = client.get(&fallback_url).await;
    if fallback_resp.ok() {
        let json: serde_json::Value = serde_json::from_slice(&fallback_resp.body)?;
        // Response can be a single commit or array
        let sha = if let Some(arr) = json.as_array() {
            arr.first().and_then(|c| c["sha"].as_str()).map(|s| s.to_string())
        } else {
            json["sha"].as_str().map(|s| s.to_string())
        };
        if let Some(s) = sha {
            return Ok(s);
        }
    }

    anyhow::bail!(
        "Cannot resolve HEAD SHA for {}/{} branch '{}' (HTTP {} / {})",
        owner, repo, branch, resp.status, fallback_resp.status
    )
}

/// Retrieve all file-tree entries for a commit, recursively.
///
/// Uses `GET /repos/{owner}/{repo}/git/trees/{sha}?recursive=1`.
/// When the response is `truncated: true` the partial tree is returned as-is;
/// large monorepos will still be partially scanned.
pub async fn get_tree(
    client: &HttpClient,
    owner:  &str,
    repo:   &str,
    sha:    &str,
) -> anyhow::Result<Vec<GhTreeEntry>> {
    let url  = format!("{}/repos/{}/{}/git/trees/{}?recursive=1", GH_API, owner, repo, sha);
    let resp = client.get(&url).await;
    if !resp.ok() {
        anyhow::bail!("GET tree {} returned HTTP {}", url, resp.status);
    }
    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
    Ok(parse_tree_entries(&json))
}

/// Fetch the raw (decoded) content of a blob by its SHA.
///
/// Uses `GET /repos/{owner}/{repo}/git/blobs/{sha}`.
/// GitHub returns content as base64; this function decodes it automatically.
pub async fn get_blob_content(
    client: &HttpClient,
    owner:  &str,
    repo:   &str,
    sha:    &str,
) -> anyhow::Result<Vec<u8>> {
    let url  = format!("{}/repos/{}/{}/git/blobs/{}", GH_API, owner, repo, sha);
    let resp = client.get(&url).await;
    if !resp.ok() {
        anyhow::bail!("GET blob {} returned HTTP {}", url, resp.status);
    }
    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
    let encoding    = json["encoding"].as_str().unwrap_or("base64");
    let content_str = json["content"].as_str().unwrap_or("");

    if encoding == "base64" {
        // GitHub embeds newlines in the base64 payload — strip them before decoding
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
    fn test_parse_next_link_extracts_url() {
        let header = r#"<https://api.github.com/user/repos?page=2>; rel="next", <https://api.github.com/user/repos?page=5>; rel="last""#;
        assert_eq!(
            parse_next_link(header),
            Some("https://api.github.com/user/repos?page=2".to_string())
        );
    }

    #[test]
    fn test_parse_next_link_no_next_rel() {
        let header = r#"<https://api.github.com/user/repos?page=1>; rel="prev""#;
        assert!(parse_next_link(header).is_none());
    }

    #[test]
    fn test_parse_next_link_empty_header() {
        assert!(parse_next_link("").is_none());
    }

    #[test]
    fn test_parse_next_link_last_page_only() {
        let header = r#"<https://api.github.com/user/repos?page=5>; rel="last", <https://api.github.com/user/repos?page=4>; rel="prev""#;
        assert!(parse_next_link(header).is_none());
    }

    #[test]
    fn test_parse_tree_entries_blob_and_tree() {
        let json = serde_json::json!({
            "tree": [
                {"path": "src/main.rs", "type": "blob", "sha": "abc123abc123abc123abc123abc123abc123abc1", "size": 1024},
                {"path": "src",         "type": "tree", "sha": "def456def456def456def456def456def456def4"},
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
        assert_eq!(entries[1].obj_type, "tree");
    }

    #[test]
    fn test_parse_tree_entries_empty_tree() {
        let json = serde_json::json!({"tree": [], "truncated": false});
        assert!(parse_tree_entries(&json).is_empty());
    }

    #[test]
    fn test_parse_tree_entries_missing_tree_key() {
        let json = serde_json::json!({});
        assert!(parse_tree_entries(&json).is_empty());
    }

    #[test]
    fn test_parse_repo_full() {
        let v = serde_json::json!({
            "full_name":      "octocat/hello-world",
            "owner":          {"login": "octocat"},
            "name":           "hello-world",
            "private":        false,
            "default_branch": "main",
            "clone_url":      "https://github.com/octocat/hello-world.git"
        });
        let repo = parse_repo(&v).unwrap();
        assert_eq!(repo.full_name, "octocat/hello-world");
        assert_eq!(repo.owner, "octocat");
        assert_eq!(repo.name, "hello-world");
        assert!(!repo.private);
        assert_eq!(repo.default_branch, "main");
        assert_eq!(repo.clone_url, "https://github.com/octocat/hello-world.git");
    }

    #[test]
    fn test_parse_repo_private() {
        let v = serde_json::json!({
            "full_name":      "corp/secret-repo",
            "owner":          {"login": "corp"},
            "name":           "secret-repo",
            "private":        true,
            "default_branch": "master",
            "clone_url":      "https://github.com/corp/secret-repo.git"
        });
        let repo = parse_repo(&v).unwrap();
        assert!(repo.private);
        assert_eq!(repo.default_branch, "master");
    }

    #[test]
    fn test_parse_repo_missing_full_name_returns_none() {
        let v = serde_json::json!({"owner": {"login": "x"}, "name": "y"});
        assert!(parse_repo(&v).is_none(), "full_name is required");
    }

    #[test]
    fn test_parse_repo_defaults_default_branch() {
        let v = serde_json::json!({
            "full_name": "a/b",
            "owner": {"login": "a"},
            "name": "b"
        });
        let repo = parse_repo(&v).unwrap();
        assert_eq!(repo.default_branch, "main", "Should default to 'main'");
    }
}

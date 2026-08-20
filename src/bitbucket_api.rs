//! bitbucket_api.rs
//! Bitbucket REST API v2 integration for `--bitbucket-token` mode.
//!
//! Provides repository enumeration and file blob fetching via App Password authentication.
//! Supports both Bitbucket Cloud (bitbucket.org) and Bitbucket Server/Data Center.
//! All requests are authenticated with `Authorization: Bearer <APP_PASSWORD>` and target
//! `https://api.bitbucket.org/2.0` or self-hosted instances.

use crate::forge::{EnumScope, Forge, Platform, RateLimitInfo, Repository, TreeEntry};
use crate::http_client::{HttpClient, HttpConfig};
use anyhow::Context;
use async_trait::async_trait;
use std::time::{Duration, Instant};

const DEFAULT_BB_API: &str = "https://api.bitbucket.org/2.0";

// ════════════════════════════════════════════════
// FORGE TRAIT IMPLEMENTATION
// ════════════════════════════════════════════════

/// Bitbucket API client implementing the Forge trait.
pub struct BitbucketForgeClient {
    client: HttpClient,
    api_base: String,
    rate_limit_remaining: std::sync::Arc<std::sync::Mutex<Option<(u32, Instant)>>>,
    username: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    is_cloud: std::sync::Arc<std::sync::Mutex<Option<bool>>>,
}

impl BitbucketForgeClient {
    /// Create a new Bitbucket forge client.
    pub fn new(client: HttpClient, api_base: String) -> Self {
        Self {
            client,
            api_base,
            rate_limit_remaining: std::sync::Arc::new(std::sync::Mutex::new(None)),
            username: std::sync::Arc::new(std::sync::Mutex::new(None)),
            is_cloud: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Update rate limit from response headers.
    fn update_rate_limit(&self, headers: &std::collections::HashMap<String, String>) {
        // Bitbucket Cloud rate limit headers (not always present):
        // X-RateLimit-Remaining, X-RateLimit-Limit, X-RateLimit-Reset
        if let Some(remaining) = headers.get("x-ratelimit-remaining") {
            if let Ok(r) = remaining.parse::<u32>() {
                let reset_time = headers
                    .get("x-ratelimit-reset")
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|ts| {
                        let reset = std::time::UNIX_EPOCH + Duration::from_secs(ts);
                        let now = std::time::SystemTime::now();
                        reset
                            .duration_since(now)
                            .unwrap_or(Duration::from_secs(3600))
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
        // Sprint 5 (S5.5): retry on 429 with Retry-After; see github_api counterpart.
        for attempt in 0..3u32 {
            let resp = self.client.get(url).await;
            if resp.status == 429 {
                let wait_s = resp
                    .headers
                    .get("retry-after")
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .unwrap_or(60)
                    .min(300);
                log::warn!(
                    "Bitbucket rate-limited (HTTP 429); sleeping {}s before retry {}/3",
                    wait_s,
                    attempt + 1,
                );
                tokio::time::sleep(std::time::Duration::from_secs(wait_s)).await;
                continue;
            }
            let mut headers = std::collections::HashMap::new();
            for (k, v) in resp.headers.iter() {
                headers.insert(k.to_lowercase(), v.clone());
            }
            self.update_rate_limit(&headers);
            return Ok(resp);
        }
        anyhow::bail!(
            "Rate limit exhausted after 3 retries for {}",
            crate::validation::redact_url(url)
        )
    }

    /// Get the authenticated user's username.
    async fn get_username(&self) -> anyhow::Result<String> {
        if let Ok(guard) = self.username.lock() {
            if let Some(ref user) = *guard {
                return Ok(user.clone());
            }
        }

        let url = format!("{}/user", self.api_base);
        let resp = self.get_with_rate_limit(&url).await?;

        if !resp.ok() {
            anyhow::bail!("GET /user returned HTTP {}", resp.status);
        }

        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        let login = json["username"]
            .as_str()
            .or_else(|| json["display_name"].as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing username in response"))?
            .to_string();

        if let Ok(mut guard) = self.username.lock() {
            *guard = Some(login.clone());
        }
        Ok(login)
    }

    /// URL-encode a path component for Bitbucket API.
    fn encode_path(path: &str) -> String {
        // Manual percent encoding that preserves path separators
        let encode_byte = |byte: u8| -> String {
            match byte {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (byte as char).to_string()
                }
                b' ' => "%20".to_string(),
                _ => format!("%{:02X}", byte),
            }
        };
        path.split('/')
            .map(|segment| segment.bytes().map(encode_byte).collect::<String>())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Check if response indicates Bitbucket Server vs Cloud.
    fn detect_instance_type(&self, resp: &crate::http_client::Response) {
        // Cloud: api.bitbucket.org
        // Server: self-hosted, different response structure
        if let Some(content_type) = resp.headers.get("content-type") {
            if content_type.contains("application/vnd.atlassian.bitbucket+json") {
                if let Ok(mut guard) = self.is_cloud.lock() {
                    *guard = Some(true);
                }
            }
        }

        // Also check the API base URL
        let base = self.api_base.to_lowercase();
        if base.contains("bitbucket.org") {
            if let Ok(mut guard) = self.is_cloud.lock() {
                *guard = Some(true);
            }
        } else if base.contains("stash") || base.contains("bitbucket-server") {
            if let Ok(mut guard) = self.is_cloud.lock() {
                *guard = Some(false);
            }
        }
    }
}

#[async_trait]
impl Forge for BitbucketForgeClient {
    async fn authenticate(&mut self, _token: &str) -> anyhow::Result<()> {
        // Validate token by calling /user
        let url = format!("{}/user", self.api_base);
        let resp = self.get_with_rate_limit(&url).await?;

        self.detect_instance_type(&resp);

        if resp.status == 401 {
            anyhow::bail!("Invalid or expired App Password (HTTP 401)");
        }

        if resp.status == 403 {
            anyhow::bail!("Access denied. Check App Password permissions (HTTP 403)");
        }

        if !resp.ok() {
            anyhow::bail!("Authentication failed with HTTP {}", resp.status);
        }

        // Cache username for subsequent calls
        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        if let Some(login) = json["username"].as_str() {
            if let Ok(mut guard) = self.username.lock() {
                *guard = Some(login.to_string());
            }
        }

        Ok(())
    }

    async fn enumerate_repos(&self, scope: EnumScope) -> anyhow::Result<Vec<Repository>> {
        let mut repos = Vec::new();

        match scope {
            EnumScope::User => {
                // Get user's repositories
                let username = self.get_username().await?;
                let url = format!(
                    "{}/repositories/{}?pagelen=100",
                    self.api_base,
                    Self::encode_path(&username)
                );
                repos.extend(self.fetch_all_repos(url).await?);
            }
            EnumScope::Org(workspace) => {
                // Get workspace repositories
                let workspace_encoded = Self::encode_path(&workspace);
                let url = format!(
                    "{}/repositories/{}?pagelen=100",
                    self.api_base, workspace_encoded
                );
                repos.extend(self.fetch_all_repos(url).await?);
            }
            EnumScope::All => {
                // For "All", fetch user repos and then discover workspaces
                let username = self.get_username().await?;
                let user_url = format!(
                    "{}/repositories/{}?pagelen=100",
                    self.api_base,
                    Self::encode_path(&username)
                );
                repos.extend(self.fetch_all_repos(user_url).await?);

                // Discover workspaces the user has access to
                if let Ok(workspaces) = list_user_workspaces(&self.client, &self.api_base).await {
                    for workspace in workspaces {
                        let workspace_encoded = Self::encode_path(&workspace);
                        let url = format!(
                            "{}/repositories/{}?pagelen=100",
                            self.api_base, workspace_encoded
                        );
                        if let Ok(ws_repos) = self.fetch_all_repos(url).await {
                            repos.extend(ws_repos);
                        }
                    }
                }
            }
        }

        // Deduplicate by full_name
        let mut seen = std::collections::HashSet::new();
        repos.retain(|r| seen.insert(r.full_name.clone()));

        Ok(repos)
    }

    async fn get_tree(&self, repo: &Repository, branch: &str) -> anyhow::Result<Vec<TreeEntry>> {
        let workspace = Self::encode_path(&repo.owner);
        let repo_slug = Self::encode_path(&repo.name);
        let commit_sha = self.get_head_sha(repo, branch).await?;

        // Bitbucket API: GET /repositories/{workspace}/{repo_slug}/src/{commit_sha}
        // This returns the directory listing for the root
        let mut all_entries = Vec::new();
        let mut stack = vec!["".to_string()];

        while let Some(current_path) = stack.pop() {
            // Sprint 4 (S4.4): Bitbucket paginates the `src` listing at 100 entries
            // per page by default; a directory with >100 files previously silent-
            // truncated (the old code read `json["next"]` but never followed it,
            // just left a comment "for simplicity, we proceed"). We now follow
            // `next` until it disappears so the tree is complete.
            let mut next_url: Option<String> = Some(if current_path.is_empty() {
                format!(
                    "{}/repositories/{}/{}/src/{}?pagelen=100",
                    self.api_base, workspace, repo_slug, commit_sha
                )
            } else {
                format!(
                    "{}/repositories/{}/{}/src/{}/{}?pagelen=100",
                    self.api_base,
                    workspace,
                    repo_slug,
                    commit_sha,
                    Self::encode_path(&current_path)
                )
            });

            while let Some(url) = next_url.take() {
                let resp = self.get_with_rate_limit(&url).await?;

                if !resp.ok() {
                    // Path might not exist (empty directory or deleted). Break out of
                    // pagination for this directory — stack still contains any siblings.
                    break;
                }

                let json: serde_json::Value = serde_json::from_slice(&resp.body)?;

                // Bitbucket API v2 response structure for src endpoint
                // Returns "values" array with file/directory entries
                if let Some(values) = json["values"].as_array() {
                    for entry in values {
                        if let Some(bb_entry) = parse_tree_entry(entry, &current_path) {
                            if bb_entry.obj_type == "tree" {
                                // It's a directory, add to stack
                                stack.push(bb_entry.path.clone());
                            } else {
                                // It's a file/blob
                                all_entries.push(TreeEntry {
                                    path: bb_entry.path,
                                    obj_type: bb_entry.obj_type,
                                    sha: bb_entry.sha,
                                    size: bb_entry.size,
                                    mode: None,
                                });
                            }
                        }
                    }
                }

                // Follow `next` (absolute URL provided by Bitbucket) until null.
                next_url = json["next"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());
            }
        }

        Ok(all_entries)
    }

    async fn get_blob(&self, repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>> {
        get_blob_content(&self.client, &self.api_base, &repo.owner, &repo.name, sha).await
    }

    fn rate_limit_remaining(&self) -> Option<(u32, Duration)> {
        self.rate_limit_remaining.lock().ok().and_then(|guard| {
            guard.as_ref().map(|(remaining, reset)| {
                (*remaining, reset.saturating_duration_since(Instant::now()))
            })
        })
    }

    fn rate_limit_info(&self) -> Option<RateLimitInfo> {
        self.rate_limit_remaining()
            .map(|(remaining, reset_in)| RateLimitInfo {
                remaining,
                reset_in,
                limit: Platform::Bitbucket.default_rate_limit(),
            })
    }

    fn platform(&self) -> Platform {
        Platform::Bitbucket
    }

    async fn get_head_sha(&self, repo: &Repository, branch: &str) -> anyhow::Result<String> {
        get_head_sha(
            &self.client,
            &self.api_base,
            &repo.owner,
            &repo.name,
            branch,
        )
        .await
    }

    async fn whoami(&self) -> anyhow::Result<(String, String)> {
        whoami(&self.client, &self.api_base).await
    }
}

impl BitbucketForgeClient {
    /// Fetch all repositories from a paginated Bitbucket endpoint.
    async fn fetch_all_repos(&self, start_url: String) -> anyhow::Result<Vec<Repository>> {
        let mut repos = Vec::new();
        let mut next_url = Some(start_url);

        while let Some(url) = next_url {
            let resp = self.get_with_rate_limit(&url).await?;
            if !resp.ok() {
                anyhow::bail!(
                    "GET {} returned HTTP {}",
                    crate::validation::redact_url(&url),
                    resp.status
                );
            }

            let json: serde_json::Value = serde_json::from_slice(&resp.body)?;

            // Parse repositories from "values" array
            if let Some(values) = json["values"].as_array() {
                for repo in values {
                    if let Some(bb_repo) = parse_repo(repo) {
                        repos.push(Repository {
                            full_name: bb_repo.full_name.clone(),
                            owner: bb_repo.owner.clone(),
                            name: bb_repo.name.clone(),
                            private: bb_repo.private,
                            default_branch: bb_repo.default_branch.clone(),
                            clone_url: bb_repo.clone_url.clone(),
                            platform: Platform::Bitbucket,
                            stars: None, // Bitbucket doesn't have stars
                            forks: None, // Not directly available in list view
                            description: repo["description"].as_str().map(|s| s.to_string()),
                            updated_at: repo["updated_on"].as_str().map(|s| s.to_string()),
                        });
                    }
                }
            }

            // Get next page from "next" field
            next_url = json["next"].as_str().map(|s| s.to_string());
        }

        Ok(repos)
    }
}

// ════════════════════════════════════════════════
// DATA STRUCTURES
// ════════════════════════════════════════════════

/// A Bitbucket repository accessible to the authenticated user.
#[derive(Debug, Clone)]
pub struct BbRepo {
    pub full_name: String,
    pub owner: String,
    pub name: String,
    #[allow(dead_code)]
    pub private: bool,
    pub default_branch: String,
    #[allow(dead_code)]
    pub clone_url: String,
}

/// A single entry (blob or tree) from a Bitbucket src API response.
#[derive(Debug, Clone)]
pub struct BbTreeEntry {
    pub path: String,
    pub obj_type: String, // "blob" or "tree"
    pub sha: String,
    pub size: Option<u64>,
}

// ════════════════════════════════════════════════
// CLIENT BUILDER
// ════════════════════════════════════════════════

/// Create a new [`HttpClient`] configured for Bitbucket API calls.
///
/// Clones `base_cfg` and injects the required Bitbucket header:
/// - `Authorization: Bearer <APP_PASSWORD>`
pub fn build_bitbucket_client(
    mut base_cfg: HttpConfig,
    token: &str,
    bitbucket_url: Option<&str>,
) -> anyhow::Result<(HttpClient, String)> {
    let api_base = bitbucket_url.unwrap_or(DEFAULT_BB_API).to_string();

    // Bitbucket uses Bearer auth with App Password
    base_cfg
        .extra_headers
        .push(("Authorization".to_string(), format!("Bearer {}", token)));
    let client = HttpClient::new(base_cfg)?;

    Ok((client, api_base))
}

// ════════════════════════════════════════════════
// API HELPERS
// ════════════════════════════════════════════════

fn parse_repo(v: &serde_json::Value) -> Option<BbRepo> {
    // Bitbucket API v2 structure:
    // {
    //   "slug": "repo-name",
    //   "full_name": "workspace/repo-name",
    //   "owner": {"username": "workspace"},
    //   "is_private": true,
    //   "mainbranch": {"name": "main"},
    //   "links": {"clone": [{"href": "...", "name": "https"}]}
    // }

    let full_name = v["full_name"].as_str()?;
    let slug = v["slug"].as_str()?;

    // Extract owner (workspace) from full_name or owner object
    let owner = v["owner"]
        .as_object()
        .and_then(|o| o.get("username"))
        .and_then(|u| u.as_str())
        .or_else(|| full_name.split('/').next())
        .unwrap_or("")
        .to_string();

    let name = slug.to_string();
    let is_private = v["is_private"].as_bool().unwrap_or(false);

    // Default branch: check mainbranch, or default to "main"
    let default_branch = v["mainbranch"]
        .as_object()
        .and_then(|m| m.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("main")
        .to_string();

    // Clone URL: get HTTPS clone link
    let clone_url = v["links"]
        .as_object()
        .and_then(|l| l.get("clone"))
        .and_then(|c| c.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|link| link["name"].as_str() == Some("https"))
                .and_then(|link| link["href"].as_str())
        })
        .unwrap_or("")
        .to_string();

    Some(BbRepo {
        full_name: full_name.to_string(),
        owner,
        name,
        private: is_private,
        default_branch,
        clone_url,
    })
}

fn parse_tree_entry(v: &serde_json::Value, base_path: &str) -> Option<BbTreeEntry> {
    // Bitbucket src API response structure:
    // {
    //   "path": "src/main.rs",
    //   "type": "commit_file",  // for files
    //   "commit": {"hash": "..."},
    //   "size": 1234
    // }
    // Or for directories:
    // {
    //   "path": "src",
    //   "type": "commit_directory"
    // }

    let path = v["path"].as_str()?.to_string();
    let type_field = v["type"].as_str().unwrap_or("");

    // Map Bitbucket types to our types
    let obj_type = match type_field {
        "commit_file" => "blob",
        "commit_directory" => "tree",
        _ => type_field, // Passthrough unknown types
    };

    // SHA is in commit.hash for Bitbucket
    let sha = v["commit"]
        .as_object()
        .and_then(|c| c.get("hash"))
        .and_then(|h| h.as_str())
        .unwrap_or("")
        .to_string();

    let size = v["size"].as_u64();

    let full_path = if base_path.is_empty() {
        path.clone()
    } else {
        format!("{}/{}", base_path, path)
    };

    Some(BbTreeEntry {
        path: full_path,
        obj_type: obj_type.to_string(),
        sha,
        size,
    })
}

/// Identify the authenticated user.
///
/// Calls `GET /user` and returns `(username, display_name)`.
/// Returns an error on HTTP 401 (invalid/expired token) or any non-200 status.
pub async fn whoami(client: &HttpClient, api_base: &str) -> anyhow::Result<(String, String)> {
    let url = format!("{}/user", api_base);
    let resp = client.get(&url).await;

    if resp.status == 401 {
        anyhow::bail!("Invalid or expired App Password (HTTP 401)");
    }
    if !resp.ok() {
        anyhow::bail!("GET /user returned HTTP {}", resp.status);
    }

    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
    // BUG-LOGIC-003 FIX: Validate response structure before accessing fields
    let login = json["username"]
        .as_str()
        .or_else(|| json["display_name"].as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing username in /user response"))?
        .to_string();

    let name = json["display_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing display_name in /user response"))?
        .to_string();

    Ok((login, name))
}

/// List all workspaces the authenticated user has access to.
pub async fn list_user_workspaces(
    client: &HttpClient,
    api_base: &str,
) -> anyhow::Result<Vec<String>> {
    let mut workspaces = Vec::new();

    // Bitbucket API: GET /workspaces
    let mut next_url = format!("{}/workspaces?pagelen=100", api_base);

    while let Some(url) = Some(next_url.clone()) {
        let resp = client.get(&url).await;
        if !resp.ok() {
            break;
        }

        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .with_context(|| format!("Failed to parse JSON response from {}", url))?;

        if let Some(values) = json["values"].as_array() {
            for ws in values {
                if let Some(slug) = ws["slug"].as_str() {
                    workspaces.push(slug.to_string());
                }
            }
        }

        // Get next page
        next_url = json["next"].as_str().unwrap_or("").to_string();
        if next_url.is_empty() {
            break;
        }
    }

    Ok(workspaces)
}

/// Resolve the HEAD commit SHA for a branch.
///
/// Uses `GET /repositories/{workspace}/{repo_slug}/refs/branches/{branch_name}`.
pub async fn get_head_sha(
    client: &HttpClient,
    api_base: &str,
    owner: &str,
    repo: &str,
    branch: &str,
) -> anyhow::Result<String> {
    let workspace = BitbucketForgeClient::encode_path(owner);
    let repo_slug = BitbucketForgeClient::encode_path(repo);
    let branch_encoded = BitbucketForgeClient::encode_path(branch);

    let url = format!(
        "{}/repositories/{}/{}/refs/branches/{}",
        api_base, workspace, repo_slug, branch_encoded
    );
    let resp = client.get(&url).await;

    if !resp.ok() {
        anyhow::bail!(
            "Cannot resolve HEAD SHA for {}/{} branch '{}' (HTTP {})",
            owner,
            repo,
            branch,
            resp.status
        );
    }

    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;

    // Bitbucket returns branch info with target.commit.hash
    let sha = json["target"]
        .as_object()
        .and_then(|t| t.get("commit"))
        .and_then(|c| c.get("hash"))
        .and_then(|h| h.as_str())
        .map(|s| s.to_string());

    sha.ok_or_else(|| anyhow::anyhow!("Missing commit hash in branch response"))
}

/// Fetch the raw (decoded) content of a blob by its SHA.
///
/// Note: Bitbucket doesn't have a direct blob-by-SHA endpoint like GitHub.
/// Use `get_file_by_path` instead which takes a file path and commit SHA.
pub async fn get_blob_content(
    _client: &HttpClient,
    _api_base: &str,
    _owner: &str,
    _repo: &str,
    _sha: &str,
) -> anyhow::Result<Vec<u8>> {
    // Bitbucket doesn't support blob-by-SHA lookup
    // Use get_file_by_path instead
    anyhow::bail!("Bitbucket blob fetch requires file path. Use get_file_by_path instead.");
}

/// Fetch a file's content by path and commit SHA.
///
/// Uses `GET /repositories/{workspace}/{repo_slug}/src/{commit_sha}/{file_path}`.
pub async fn get_file_by_path(
    client: &HttpClient,
    api_base: &str,
    owner: &str,
    repo: &str,
    commit_sha: &str,
    file_path: &str,
) -> anyhow::Result<Vec<u8>> {
    let workspace = BitbucketForgeClient::encode_path(owner);
    let repo_slug = BitbucketForgeClient::encode_path(repo);
    let path_encoded = BitbucketForgeClient::encode_path(file_path);

    let url = format!(
        "{}/repositories/{}/{}/src/{}/{}",
        api_base, workspace, repo_slug, commit_sha, path_encoded
    );
    let resp = client.get(&url).await;

    if !resp.ok() {
        anyhow::bail!(
            "GET file {} returned HTTP {}",
            crate::validation::redact_url(&url),
            resp.status
        );
    }

    Ok(resp.body.to_vec())
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
            "slug": "hello-world",
            "full_name": "octocat/hello-world",
            "owner": {"username": "octocat"},
            "is_private": false,
            "mainbranch": {"name": "main"},
            "links": {
                "clone": [
                    {"href": "https://bitbucket.org/octocat/hello-world.git", "name": "https"}
                ]
            }
        });
        let repo = parse_repo(&v).unwrap();
        assert_eq!(repo.full_name, "octocat/hello-world");
        assert_eq!(repo.owner, "octocat");
        assert_eq!(repo.name, "hello-world");
        assert!(!repo.private);
        assert_eq!(repo.default_branch, "main");
    }

    #[test]
    fn test_parse_repo_private() {
        let v = serde_json::json!({
            "slug": "secret-repo",
            "full_name": "corp/secret-repo",
            "owner": {"username": "corp"},
            "is_private": true,
            "mainbranch": {"name": "master"},
            "links": {
                "clone": [
                    {"href": "https://bitbucket.org/corp/secret-repo.git", "name": "https"}
                ]
            }
        });
        let repo = parse_repo(&v).unwrap();
        assert!(repo.private);
        assert_eq!(repo.default_branch, "master");
    }

    #[test]
    fn test_parse_repo_no_mainbranch() {
        let v = serde_json::json!({
            "slug": "test-repo",
            "full_name": "user/test-repo",
            "owner": {"username": "user"},
            "is_private": false,
            "links": {
                "clone": [
                    {"href": "https://bitbucket.org/user/test-repo.git", "name": "https"}
                ]
            }
        });
        let repo = parse_repo(&v).unwrap();
        assert_eq!(repo.default_branch, "main"); // Should default to "main"
    }

    #[test]
    fn test_parse_tree_entry_file() {
        let v = serde_json::json!({
            "path": "README.md",
            "type": "commit_file",
            "commit": {"hash": "abc123"},
            "size": 1024
        });
        let entry = parse_tree_entry(&v, "").unwrap();
        assert_eq!(entry.path, "README.md");
        assert_eq!(entry.obj_type, "blob");
        assert_eq!(entry.size, Some(1024));
    }

    #[test]
    fn test_parse_tree_entry_directory() {
        let v = serde_json::json!({
            "path": "src",
            "type": "commit_directory",
            "commit": {"hash": "def456"}
        });
        let entry = parse_tree_entry(&v, "").unwrap();
        assert_eq!(entry.path, "src");
        assert_eq!(entry.obj_type, "tree");
    }

    #[test]
    fn test_encode_path() {
        assert_eq!(
            BitbucketForgeClient::encode_path("src/main.rs"),
            "src/main.rs"
        );
        assert_eq!(
            BitbucketForgeClient::encode_path("path with spaces"),
            "path%20with%20spaces"
        );
        assert_eq!(
            BitbucketForgeClient::encode_path("special/chars/测试"),
            "special/chars/%E6%B5%8B%E8%AF%95"
        );
    }
    async fn spawn_contract_server(status: u16, body: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn mock_server_contract_covers_bitbucket_identity_success() {
        let base_url = spawn_contract_server(
            200,
            r#"{"username":"fixture","display_name":"Fixture User"}"#,
        )
        .await;
        let (client, api_base) =
            build_bitbucket_client(HttpConfig::default(), "synthetic-token", Some(&base_url))
                .unwrap();
        let identity = whoami(&client, &api_base).await.unwrap();
        assert_eq!(
            identity,
            ("fixture".to_string(), "Fixture User".to_string())
        );
    }

    #[tokio::test]
    async fn mock_server_contract_maps_bitbucket_401_to_authentication_error() {
        let base_url = spawn_contract_server(401, "{}").await;
        let (client, api_base) =
            build_bitbucket_client(HttpConfig::default(), "synthetic-token", Some(&base_url))
                .unwrap();
        let error = whoami(&client, &api_base).await.unwrap_err().to_string();
        assert!(error.contains("HTTP 401"));
    }
    #[tokio::test]
    async fn mock_server_contract_fetches_bitbucket_file_content() {
        let base_url = spawn_contract_server(200, "fixture-value").await;
        let (client, api_base) =
            build_bitbucket_client(HttpConfig::default(), "synthetic-token", Some(&base_url))
                .unwrap();
        let content = get_file_by_path(&client, &api_base, "fixture", "repo", "sha", "config.txt")
            .await
            .unwrap();
        assert_eq!(content, b"fixture-value");
    }
}

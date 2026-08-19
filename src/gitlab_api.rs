//! gitlab_api.rs
//! GitLab REST API v4 integration for `--gitlab-token` mode.
//!
//! Provides repository enumeration and file blob fetching via PAT authentication.
//! All requests are authenticated with `PRIVATE-TOKEN: <PAT>` and target
//! `https://gitlab.com/api/v4` or self-hosted instances via --gitlab-url.

use crate::forge::{EnumScope, Forge, Platform, RateLimitInfo, Repository, TreeEntry};
use crate::http_client::{HttpClient, HttpConfig};
use anyhow::Context;
use async_trait::async_trait;
use std::time::{Duration, Instant};

const DEFAULT_GL_API: &str = "https://gitlab.com/api/v4";

// ════════════════════════════════════════════════
// FORGE TRAIT IMPLEMENTATION
// ════════════════════════════════════════════════

/// GitLab API client implementing the Forge trait.
pub struct GitLabForgeClient {
    client: HttpClient,
    api_base: String,
    rate_limit_remaining: std::sync::Arc<std::sync::Mutex<Option<(u32, Instant)>>>,
    user_id: std::sync::Arc<std::sync::Mutex<Option<u64>>>,
}

impl GitLabForgeClient {
    /// Create a new GitLab forge client.
    pub fn new(client: HttpClient, api_base: String) -> Self {
        Self {
            client,
            api_base,
            rate_limit_remaining: std::sync::Arc::new(std::sync::Mutex::new(None)),
            user_id: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Update rate limit from response headers.
    fn update_rate_limit(&self, headers: &std::collections::HashMap<String, String>) {
        // GitLab rate limit headers (GitLab Premium/Ultimate)
        // RateLimit-Remaining, RateLimit-Limit, RateLimit-Reset
        if let Some(remaining) = headers.get("ratelimit-remaining") {
            if let Ok(r) = remaining.parse::<u32>() {
                let reset_time = headers
                    .get("ratelimit-reset")
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
                    "GitLab rate-limited (HTTP 429); sleeping {}s before retry {}/3",
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

    /// URL-encode a file path for GitLab API.
    fn encode_path(path: &str) -> String {
        url::form_urlencoded::byte_serialize(path.as_bytes()).collect::<String>()
    }
}

#[async_trait]
impl Forge for GitLabForgeClient {
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

        // Cache user ID for subsequent calls
        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        if let Some(id) = json["id"].as_u64() {
            if let Ok(mut guard) = self.user_id.lock() {
                *guard = Some(id);
            }
        }

        Ok(())
    }

    async fn enumerate_repos(&self, scope: EnumScope) -> anyhow::Result<Vec<Repository>> {
        let mut repos = Vec::new();

        match scope {
            EnumScope::User => {
                // Get user projects via /projects?membership=true
                let url = format!(
                    "{}/projects?membership=true&per_page=100&order_by=updated&sort=desc",
                    self.api_base
                );
                repos.extend(self.fetch_all_projects(url).await?);
            }
            EnumScope::Org(group) => {
                // Get group projects
                let group_encoded = Self::encode_path(&group);
                let url = format!(
                    "{}/groups/{}/projects?per_page=100&order_by=updated&sort=desc",
                    self.api_base, group_encoded
                );
                repos.extend(self.fetch_all_projects(url).await?);
            }
            EnumScope::All => {
                // For "All", fetch user projects and then group projects
                let user_url = format!(
                    "{}/projects?membership=true&per_page=100&order_by=updated&sort=desc",
                    self.api_base
                );
                repos.extend(self.fetch_all_projects(user_url).await?);

                // Also fetch groups the user belongs to and their projects
                if let Ok(groups) = list_user_groups(&self.client, &self.api_base).await {
                    for group in groups {
                        let group_encoded = Self::encode_path(&group);
                        let url = format!(
                            "{}/groups/{}/projects?per_page=100&order_by=updated&sort=desc",
                            self.api_base, group_encoded
                        );
                        if let Ok(group_repos) = self.fetch_all_projects(url).await {
                            repos.extend(group_repos);
                        }
                    }
                }
            }
        }

        // Deduplicate by project ID
        let mut seen = std::collections::HashSet::new();
        repos.retain(|r| seen.insert((r.owner.clone(), r.name.clone())));

        Ok(repos)
    }

    async fn get_tree(&self, repo: &Repository, branch: &str) -> anyhow::Result<Vec<TreeEntry>> {
        let project_encoded = Self::encode_path(&format!("{}/{}", repo.owner, repo.name));

        // GitLab API doesn't have recursive=true for tree endpoint
        // We need to traverse manually
        let mut all_entries = Vec::new();
        let mut stack = vec!["".to_string()];

        while let Some(current_path) = stack.pop() {
            let path_encoded = Self::encode_path(&current_path);
            let url = if current_path.is_empty() {
                format!(
                    "{}/projects/{}/repository/tree?ref={}",
                    self.api_base, project_encoded, branch
                )
            } else {
                format!(
                    "{}/projects/{}/repository/tree?ref={}&path={}",
                    self.api_base, project_encoded, branch, path_encoded
                )
            };

            let resp = self.get_with_rate_limit(&url).await?;

            if !resp.ok() {
                // If we get a 404, the path might not exist (empty directory or deleted)
                continue;
            }

            let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
            let arr = json
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Expected JSON array from tree endpoint"))?;

            for entry in arr {
                if let Some(gl_entry) = parse_tree_entry(entry, &current_path) {
                    if gl_entry.obj_type == "tree" {
                        stack.push(gl_entry.path.clone());
                    } else {
                        all_entries.push(TreeEntry {
                            path: gl_entry.path,
                            obj_type: gl_entry.obj_type,
                            sha: gl_entry.sha,
                            size: gl_entry.size,
                            mode: None,
                        });
                    }
                }
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
                limit: Platform::GitLab.default_rate_limit(),
            })
    }

    fn platform(&self) -> Platform {
        Platform::GitLab
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

impl GitLabForgeClient {
    /// Fetch all projects from a paginated GitLab endpoint.
    async fn fetch_all_projects(&self, mut url: String) -> anyhow::Result<Vec<Repository>> {
        let mut repos = Vec::new();

        loop {
            let resp = self.get_with_rate_limit(&url).await?;
            if !resp.ok() {
                anyhow::bail!(
                    "GET {} returned HTTP {}",
                    crate::validation::redact_url(&url),
                    resp.status
                );
            }

            let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
            let arr = json
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Expected JSON array from projects endpoint"))?;

            for p in arr {
                if let Some(gl_repo) = parse_repo(p) {
                    repos.push(Repository {
                        full_name: gl_repo.full_name.clone(),
                        owner: gl_repo.owner.clone(),
                        name: gl_repo.name.clone(),
                        private: gl_repo.private,
                        default_branch: gl_repo.default_branch.clone(),
                        clone_url: gl_repo.clone_url.clone(),
                        platform: Platform::GitLab,
                        stars: p["star_count"].as_u64().map(|v| v as u32),
                        forks: p["forks_count"].as_u64().map(|v| v as u32),
                        description: p["description"].as_str().map(|s| s.to_string()),
                        updated_at: p["last_activity_at"].as_str().map(|s| s.to_string()),
                    });
                }
            }

            // GitLab uses Link header for pagination
            match resp.headers.get("link").and_then(|h| parse_next_link(h)) {
                Some(next) => url = next,
                None => break,
            }
        }

        Ok(repos)
    }
}

// ════════════════════════════════════════════════
// DATA STRUCTURES
// ════════════════════════════════════════════════

/// A GitLab project accessible to the authenticated user.
#[derive(Debug, Clone)]
pub struct GlProject {
    pub full_name: String,
    pub owner: String,
    pub name: String,
    #[allow(dead_code)]
    pub private: bool,
    pub default_branch: String,
    #[allow(dead_code)]
    pub clone_url: String,
}

/// A single entry (blob or tree) from a GitLab tree API response.
#[derive(Debug, Clone)]
pub struct GlTreeEntry {
    pub path: String,
    pub obj_type: String, // "blob" or "tree"
    pub sha: String,
    pub size: Option<u64>,
}

// ════════════════════════════════════════════════
// CLIENT BUILDER
// ════════════════════════════════════════════════

/// Create a new [`HttpClient`] configured for GitLab API calls.
///
/// Clones `base_cfg` and injects the required GitLab header:
/// - `PRIVATE-TOKEN: <PAT>`
pub fn build_gitlab_client(
    mut base_cfg: HttpConfig,
    token: &str,
    gitlab_url: Option<&str>,
) -> anyhow::Result<(HttpClient, String)> {
    let api_base = gitlab_url.unwrap_or(DEFAULT_GL_API).to_string();

    base_cfg
        .extra_headers
        .push(("PRIVATE-TOKEN".to_string(), token.to_string()));
    let client = HttpClient::new(base_cfg)?;

    Ok((client, api_base))
}

// ════════════════════════════════════════════════
// API HELPERS
// ════════════════════════════════════════════════

/// Parse the `next` URL from a GitLab `Link` response header.
///
/// # Example header
/// ```text
/// <https://gitlab.com/api/v4/projects?page=2>; rel="next", ...
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

fn parse_repo(v: &serde_json::Value) -> Option<GlProject> {
    let path_with_namespace = v["path_with_namespace"].as_str()?;
    let parts: Vec<&str> = path_with_namespace.split('/').collect();
    if parts.len() < 2 {
        return None;
    }

    let owner = parts[0].to_string();
    let name = parts[1].to_string();
    let full_name = path_with_namespace.to_string();
    let private =
        v["visibility"].as_str() == Some("private") || v["visibility"].as_str() == Some("internal");
    let default_branch = v["default_branch"].as_str().unwrap_or("main").to_string();
    let clone_url = v["http_url_to_repo"].as_str().unwrap_or("").to_string();

    Some(GlProject {
        full_name,
        owner,
        name,
        private,
        default_branch,
        clone_url,
    })
}

fn parse_tree_entry(v: &serde_json::Value, base_path: &str) -> Option<GlTreeEntry> {
    let name = v["name"].as_str()?.to_string();
    let obj_type = v["type"].as_str()?.to_string();
    let sha = v["id"].as_str()?.to_string();

    let path = if base_path.is_empty() {
        name.clone()
    } else {
        format!("{}/{}", base_path, name)
    };

    let size = v["size"].as_u64();

    Some(GlTreeEntry {
        path,
        obj_type,
        sha,
        size,
    })
}

/// Identify the authenticated user.
///
/// Calls `GET /user` and returns `(username, name)`.
/// Returns an error on HTTP 401 (invalid/expired token) or any non-200 status.
pub async fn whoami(client: &HttpClient, api_base: &str) -> anyhow::Result<(String, String)> {
    let url = format!("{}/user", api_base);
    let resp = client.get(&url).await;

    if resp.status == 401 {
        anyhow::bail!("Invalid or expired token (HTTP 401)");
    }
    if !resp.ok() {
        anyhow::bail!("GET /user returned HTTP {}", resp.status);
    }

    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
    let login = json["username"].as_str().unwrap_or("").to_string();
    let name = json["name"].as_str().unwrap_or("").to_string();
    Ok((login, name))
}

/// List all groups the authenticated user belongs to.
pub async fn list_user_groups(client: &HttpClient, api_base: &str) -> anyhow::Result<Vec<String>> {
    let mut groups = Vec::new();
    let mut url = format!("{}/groups?per_page=100", api_base);

    loop {
        let resp = client.get(&url).await;
        if !resp.ok() {
            break;
        }

        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .with_context(|| format!("Failed to parse JSON response from {}", url))?;
        let arr = match json.as_array() {
            Some(a) => a,
            None => break,
        };

        for g in arr {
            if let Some(path) = g["full_path"].as_str() {
                groups.push(path.to_string());
            }
        }

        match resp.headers.get("link").and_then(|h| parse_next_link(h)) {
            Some(next) => url = next,
            None => break,
        }
    }

    Ok(groups)
}

/// Resolve the HEAD commit SHA for a branch.
///
/// Uses `GET /projects/:id/repository/commits/:ref_name`.
pub async fn get_head_sha(
    client: &HttpClient,
    api_base: &str,
    owner: &str,
    repo: &str,
    branch: &str,
) -> anyhow::Result<String> {
    let project_encoded = GitLabForgeClient::encode_path(&format!("{}/{}", owner, repo));
    let url = format!(
        "{}/projects/{}/repository/commits/{}",
        api_base, project_encoded, branch
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
    let sha = json["id"].as_str().map(|s| s.to_string());

    sha.ok_or_else(|| anyhow::anyhow!("Missing commit id in response"))
}

/// Fetch the raw (decoded) content of a blob by its SHA.
///
/// Uses `GET /projects/:id/repository/files/:file_path/raw?ref=sha`.
/// For GitLab, we fetch by file path and reference (branch/SHA).
pub async fn get_blob_content(
    client: &HttpClient,
    api_base: &str,
    owner: &str,
    repo: &str,
    sha: &str,
) -> anyhow::Result<Vec<u8>> {
    // GitLab doesn't have a direct blob-by-SHA endpoint like GitHub
    // We need to use the files API with the SHA as ref
    // However, for our use case we already have the file path from the tree

    // Alternative: Use the raw blob content if we can get it
    // GitLab's API: GET /projects/:id/repository/blobs/:sha
    // This returns raw content directly
    let project_encoded = GitLabForgeClient::encode_path(&format!("{}/{}", owner, repo));
    let url = format!(
        "{}/projects/{}/repository/blobs/{}",
        api_base, project_encoded, sha
    );
    let resp = client.get(&url).await;

    if !resp.ok() {
        anyhow::bail!(
            "GET blob {} returned HTTP {}",
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
    fn test_parse_next_link_extracts_url() {
        let header = r#"<https://gitlab.com/api/v4/projects?page=2>; rel="next", <https://gitlab.com/api/v4/projects?page=5>; rel="last""#;
        assert_eq!(
            parse_next_link(header),
            Some("https://gitlab.com/api/v4/projects?page=2".to_string())
        );
    }

    #[test]
    fn test_parse_next_link_no_next_rel() {
        let header = r#"<https://gitlab.com/api/v4/projects?page=1>; rel="prev""#;
        assert!(parse_next_link(header).is_none());
    }

    #[test]
    fn test_parse_repo_full() {
        let v = serde_json::json!({
            "path_with_namespace": "octocat/hello-world",
            "visibility": "public",
            "default_branch": "main",
            "http_url_to_repo": "https://gitlab.com/octocat/hello-world.git"
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
            "path_with_namespace": "corp/secret-repo",
            "visibility": "private",
            "default_branch": "master",
            "http_url_to_repo": "https://gitlab.com/corp/secret-repo.git"
        });
        let repo = parse_repo(&v).unwrap();
        assert!(repo.private);
        assert_eq!(repo.default_branch, "master");
    }

    #[test]
    fn test_parse_tree_entry_blob() {
        let v = serde_json::json!({
            "name": "README.md",
            "type": "blob",
            "id": "abc123",
            "size": 1024
        });
        let entry = parse_tree_entry(&v, "").unwrap();
        assert_eq!(entry.path, "README.md");
        assert_eq!(entry.obj_type, "blob");
        assert_eq!(entry.size, Some(1024));
    }

    #[test]
    fn test_parse_tree_entry_nested() {
        let v = serde_json::json!({
            "name": "main.rs",
            "type": "blob",
            "id": "def456",
            "size": 2048
        });
        let entry = parse_tree_entry(&v, "src").unwrap();
        assert_eq!(entry.path, "src/main.rs");
    }
}

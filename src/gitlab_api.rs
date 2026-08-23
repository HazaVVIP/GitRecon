//! gitlab_api.rs
//! GitLab REST API v4 integration for `--gitlab-token` mode.
//!
//! Provides repository enumeration and file blob fetching via PAT authentication.
//! All requests are authenticated with `PRIVATE-TOKEN: <PAT>` and target
//! `https://gitlab.com/api/v4` or self-hosted instances via --gitlab-url.

use crate::forge::{
    EnumScope, Forge, ForgeCapabilities, ForgeHistory, HistoryChangeStatus, HistoryEntry, Platform,
    RateLimitInfo, Repository, TreeEntry,
};
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
                let wait_s = parse_retry_after(&resp.headers).unwrap_or(60).min(300);
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
        let branch_encoded = Self::encode_path(branch);

        // GitLab API does not have recursive=true for tree endpoint. Traverse
        // directories manually and follow the provider's per-directory pages.
        let mut all_entries = Vec::new();
        let mut stack = vec!["".to_string()];

        while let Some(current_path) = stack.pop() {
            let path_encoded = Self::encode_path(&current_path);
            let mut page = 1usize;

            loop {
                let url = if current_path.is_empty() {
                    format!(
                        "{}/projects/{}/repository/tree?ref={}&per_page=100&page={}",
                        self.api_base, project_encoded, branch_encoded, page
                    )
                } else {
                    format!(
                        "{}/projects/{}/repository/tree?ref={}&path={}&per_page=100&page={}",
                        self.api_base, project_encoded, branch_encoded, path_encoded, page
                    )
                };

                let resp = self.get_with_rate_limit(&url).await?;

                if !resp.ok() {
                    // If we get a 404, the path might not exist (empty directory or deleted)
                    break;
                }

                let next_page = next_page_from_response(&resp.headers, page);
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

                match next_page {
                    Some(next) => page = next,
                    None => break,
                }
            }
        }

        Ok(all_entries)
    }

    async fn get_blob(&self, repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>> {
        get_blob_content(&self.client, &self.api_base, &repo.owner, &repo.name, sha).await
    }

    async fn get_blob_entry_at(
        &self,
        repo: &Repository,
        entry: &TreeEntry,
        revision: &str,
    ) -> anyhow::Result<Vec<u8>> {
        get_file_content_at_ref(
            &self.client,
            &self.api_base,
            &repo.owner,
            &repo.name,
            &entry.path,
            revision,
        )
        .await
    }

    async fn get_history(
        &self,
        repo: &Repository,
        branch: &str,
        max_commits: usize,
    ) -> anyhow::Result<ForgeHistory> {
        get_history_at(self, &repo.owner, &repo.name, branch, max_commits).await
    }

    fn capabilities(&self) -> ForgeCapabilities {
        ForgeCapabilities {
            snapshot: true,
            history: true,
            branches: false,
            tags: false,
            commits: true,
            deleted_blobs: false,
        }
    }

    fn retry_stats(&self) -> Option<crate::stream_types::RetryReportStats> {
        Some(self.client.retry_metrics.snapshot())
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
    crate::provider_transport::parse_next_link(header)
}

fn next_page_from_response(
    headers: &std::collections::HashMap<String, String>,
    current_page: usize,
) -> Option<usize> {
    let header_page = headers
        .get("x-next-page")
        .and_then(|value| value.trim().parse::<usize>().ok());
    let link_page = headers.get("link").and_then(|header| {
        let next = parse_next_link(header)?;
        url::Url::parse(&next)
            .ok()?
            .query_pairs()
            .find(|(key, _)| key == "page")
            .and_then(|(_, value)| value.parse::<usize>().ok())
    });
    header_page
        .filter(|page| *page > current_page)
        .or_else(|| link_page.filter(|page| *page > current_page))
}

fn parse_retry_after(headers: &std::collections::HashMap<String, String>) -> Option<u64> {
    crate::provider_transport::parse_retry_after(headers)
}

fn parse_repo(v: &serde_json::Value) -> Option<GlProject> {
    let path_with_namespace = v["path_with_namespace"].as_str()?;
    let (owner, name) = path_with_namespace.rsplit_once('/')?;
    let owner = owner.to_string();
    let name = name.to_string();
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

const MAX_GITLAB_HISTORY_COMMITS: usize = 5_000;

/// Fetch bounded commit history and changed paths from GitLab.
async fn get_history_at(
    client: &GitLabForgeClient,
    owner: &str,
    repo: &str,
    branch: &str,
    max_commits: usize,
) -> anyhow::Result<ForgeHistory> {
    let requested_limit = if max_commits == 0 {
        MAX_GITLAB_HISTORY_COMMITS
    } else {
        max_commits.min(MAX_GITLAB_HISTORY_COMMITS)
    };
    let project_encoded = GitLabForgeClient::encode_path(&format!("{}/{}", owner, repo));
    let branch_encoded = GitLabForgeClient::encode_path(branch);
    let mut page = 1usize;
    let mut history = ForgeHistory::default();

    while history.commits_scanned < requested_limit {
        let url = format!(
            "{}/projects/{}/repository/commits?ref_name={}&per_page=100&page={}",
            client.api_base, project_encoded, branch_encoded, page
        );
        let response = client.get_with_rate_limit(&url).await?;
        if !response.ok() {
            anyhow::bail!(
                "GET history {} returned HTTP {}",
                crate::validation::redact_url(&url),
                response.status
            );
        }
        let commits = serde_json::from_slice::<serde_json::Value>(&response.body)?;
        let Some(commits) = commits.as_array() else {
            anyhow::bail!("Expected JSON array from GitLab history endpoint");
        };
        if commits.is_empty() {
            break;
        }

        for commit in commits {
            if history.commits_scanned >= requested_limit {
                history.truncated = true;
                break;
            }
            let Some(commit_sha) = commit["id"].as_str() else {
                continue;
            };
            let commit_sha_encoded = GitLabForgeClient::encode_path(commit_sha);
            let detail_url = format!(
                "{}/projects/{}/repository/commits/{}/diff",
                client.api_base, project_encoded, commit_sha_encoded
            );
            let detail_response = client.get_with_rate_limit(&detail_url).await?;
            if !detail_response.ok() {
                anyhow::bail!(
                    "GET commit diff {} returned HTTP {}",
                    crate::validation::redact_url(&detail_url),
                    detail_response.status
                );
            }
            let diffs = serde_json::from_slice::<serde_json::Value>(&detail_response.body)?;
            if let Some(files) = diffs.as_array() {
                for file in files {
                    let old_path = file["old_path"].as_str();
                    let new_path = file["new_path"].as_str();
                    let path = if file["deleted_file"].as_bool().unwrap_or(false) {
                        old_path.or(new_path)
                    } else {
                        new_path.or(old_path)
                    };
                    let Some(path) = path else { continue };
                    let status = if file["deleted_file"].as_bool().unwrap_or(false) {
                        HistoryChangeStatus::Removed
                    } else if file["renamed_file"].as_bool().unwrap_or(false) {
                        HistoryChangeStatus::Renamed
                    } else if file["new_file"].as_bool().unwrap_or(false) {
                        HistoryChangeStatus::Added
                    } else {
                        HistoryChangeStatus::Modified
                    };
                    history.entries.push(HistoryEntry {
                        commit_sha: commit_sha.to_string(),
                        path: path.to_string(),
                        status,
                        blob_sha: None,
                        previous_path: if file["renamed_file"].as_bool().unwrap_or(false) {
                            old_path.map(str::to_string)
                        } else {
                            None
                        },
                        size: None,
                    });
                }
            }
            history.commits_scanned += 1;
        }
        if history.truncated {
            break;
        }
        let next_page = response
            .headers
            .get("x-next-page")
            .and_then(|value| value.parse::<usize>().ok());
        match next_page {
            Some(next) if next > page => page = next,
            _ => break,
        }
    }
    if max_commits > MAX_GITLAB_HISTORY_COMMITS {
        history.truncated = true;
    }
    Ok(history)
}

/// Fetch a file’s raw content at an explicit GitLab branch or commit ref.
async fn get_file_content_at_ref(
    client: &HttpClient,
    api_base: &str,
    owner: &str,
    repo: &str,
    path: &str,
    revision: &str,
) -> anyhow::Result<Vec<u8>> {
    let project_encoded = GitLabForgeClient::encode_path(&format!("{}/{}", owner, repo));
    let path_encoded = GitLabForgeClient::encode_path(path);
    let ref_encoded = GitLabForgeClient::encode_path(revision);
    let url = format!(
        "{}/projects/{}/repository/files/{}/raw?ref={}",
        api_base, project_encoded, path_encoded, ref_encoded
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
    fn test_parse_repo_preserves_nested_group_namespace() {
        let v = serde_json::json!({
            "path_with_namespace": "corp/platform/secret-repo",
            "visibility": "private",
            "default_branch": "main",
            "http_url_to_repo": "https://gitlab.com/corp/platform/secret-repo.git"
        });
        let repo = parse_repo(&v).unwrap();
        assert_eq!(repo.owner, "corp/platform");
        assert_eq!(repo.name, "secret-repo");
        assert_eq!(repo.full_name, "corp/platform/secret-repo");
    }

    #[test]
    fn test_next_page_from_response_accepts_progressing_header_or_link() {
        let mut headers = std::collections::HashMap::new();
        headers.insert("x-next-page".to_string(), "3".to_string());
        assert_eq!(next_page_from_response(&headers, 2), Some(3));

        headers.clear();
        headers.insert(
            "link".to_string(),
            r#"<https://gitlab.example/tree?page=4>; rel="next""#.to_string(),
        );
        assert_eq!(next_page_from_response(&headers, 3), Some(4));

        headers.insert("x-next-page".to_string(), "2".to_string());
        assert_eq!(next_page_from_response(&headers, 3), Some(4));

        headers.insert("x-next-page".to_string(), "not-a-page".to_string());
        headers.insert(
            "link".to_string(),
            r#"<https://gitlab.example/tree?page=2>; rel="next""#.to_string(),
        );
        assert_eq!(next_page_from_response(&headers, 3), None);
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

    async fn spawn_tree_pagination_server() -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let pages = [
                (
                    1,
                    r#"[{"name":"first.txt","type":"blob","id":"blob-one","size":5}]"#,
                    Some("2"),
                ),
                (
                    2,
                    r#"[{"name":"second.txt","type":"blob","id":"blob-two","size":6}]"#,
                    None,
                ),
            ];
            for (page, body, next_page) in pages {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let read = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..read]);
                assert!(request.contains("projects/corp%2Fplatform%2Frepo/repository/tree"));
                assert!(request.contains("ref=main"));
                assert!(request.contains("per_page=100"));
                assert!(request.contains(&format!("page={page}")));
                let continuation = next_page
                    .map(|value| format!("X-Next-Page: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{continuation}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn mock_server_contract_covers_gitlab_identity_success() {
        let base_url =
            spawn_contract_server(200, r#"{"username":"fixture","name":"Fixture User"}"#).await;
        let (client, api_base) =
            build_gitlab_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let identity = whoami(&client, &api_base).await.unwrap();
        assert_eq!(
            identity,
            ("fixture".to_string(), "Fixture User".to_string())
        );
    }

    #[tokio::test]
    async fn mock_server_contract_maps_gitlab_401_to_authentication_error() {
        let base_url = spawn_contract_server(401, "{}").await;
        let (client, api_base) =
            build_gitlab_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let error = whoami(&client, &api_base).await.unwrap_err().to_string();
        assert!(error.contains("HTTP 401"));
    }
    #[tokio::test]
    async fn mock_server_contract_maps_403_to_identity_error() {
        let base_url = spawn_contract_server(403, "{}").await;
        let (client, api_base) =
            build_gitlab_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let error = whoami(&client, &api_base).await.unwrap_err().to_string();
        assert!(error.contains("HTTP 403") || error.contains("Access denied"));
    }
    #[tokio::test]
    async fn mock_server_contract_follows_tree_pagination_for_nested_project() {
        use crate::forge::Forge;

        let base_url = spawn_tree_pagination_server().await;
        let (client, api_base) =
            build_gitlab_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let forge = GitLabForgeClient::new(client, api_base);
        let repo = Repository {
            full_name: "corp/platform/repo".to_string(),
            owner: "corp/platform".to_string(),
            name: "repo".to_string(),
            private: true,
            default_branch: "main".to_string(),
            clone_url: "https://gitlab.example/corp/platform/repo.git".to_string(),
            platform: Platform::GitLab,
            stars: None,
            forks: None,
            description: None,
            updated_at: None,
        };

        let tree = forge.get_tree(&repo, "main").await.unwrap();
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].path, "first.txt");
        assert_eq!(tree[1].path, "second.txt");
    }

    #[tokio::test]
    async fn mock_server_contract_fetches_gitlab_blob_content() {
        let base_url = spawn_contract_server(200, "fixture-value").await;
        let (client, api_base) =
            build_gitlab_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let content = get_blob_content(&client, &api_base, "fixture", "repo", "sha")
            .await
            .unwrap();
        assert_eq!(content, b"fixture-value");
    }
    #[tokio::test]
    async fn mock_server_contract_scans_bounded_history_and_fetches_revision_content() {
        use crate::forge::Forge;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        tokio::spawn(async move {
            for _ in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 2048];
                let read = socket.read(&mut request).await.unwrap();
                let request_line = String::from_utf8_lossy(&request[..read]);
                assert!(request_line.starts_with("GET /projects/"));
                let (content_type, body) = if request_line.contains("/repository/commits?") {
                    (
                        "application/json",
                        r#"[{"id":"commit-one"},{"id":"commit-two"}]"#,
                    )
                } else if request_line.contains("commit-one/diff") {
                    (
                        "application/json",
                        r#"[{"old_path":"config.env","new_path":"config.env","new_file":true,"renamed_file":false,"deleted_file":false}]"#,
                    )
                } else if request_line.contains("commit-two/diff") {
                    (
                        "application/json",
                        r#"[{"old_path":"old.txt","new_path":"new.txt","new_file":false,"renamed_file":true,"deleted_file":false}]"#,
                    )
                } else if request_line.contains("/repository/files/") {
                    ("text/plain", "fixture-history-content")
                } else {
                    panic!("unexpected GitLab history route: {request_line}");
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let (http_client, api_base) =
            build_gitlab_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let forge = GitLabForgeClient::new(http_client, api_base);
        assert!(forge.capabilities().history);
        assert!(!forge.capabilities().deleted_blobs);

        let history = get_history_at(&forge, "fixture", "repo", "main", 1)
            .await
            .unwrap();
        assert_eq!(history.commits_scanned, 1);
        assert!(history.truncated);
        assert_eq!(history.entries.len(), 1);
        assert_eq!(history.entries[0].commit_sha, "commit-one");
        assert_eq!(history.entries[0].status, HistoryChangeStatus::Added);

        let entry = TreeEntry {
            path: "config.env".to_string(),
            obj_type: "blob".to_string(),
            sha: "unused-sha".to_string(),
            size: None,
            mode: None,
        };
        let content = forge
            .get_blob_entry_at(
                &Repository {
                    full_name: "fixture/repo".to_string(),
                    owner: "fixture".to_string(),
                    name: "repo".to_string(),
                    private: true,
                    default_branch: "main".to_string(),
                    clone_url: "https://gitlab.example/fixture/repo.git".to_string(),
                    platform: Platform::GitLab,
                    stars: None,
                    forks: None,
                    description: None,
                    updated_at: None,
                },
                &entry,
                "commit-one",
            )
            .await
            .unwrap();
        assert_eq!(content, b"fixture-history-content");
    }

    #[tokio::test]
    async fn mock_server_contract_follows_gitlab_group_pagination() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let base_url = format!("http://{address}");
        let first_body = r#"[{"full_path":"fixture/first-group"}]"#;
        let second_body = r#"[{"full_path":"fixture/second-group"}]"#;
        let next_header = format!("<{base_url}/page-2>; rel=\"next\"");
        tokio::spawn(async move {
            for (body, link) in [(first_body, Some(next_header)), (second_body, None)] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = socket.read(&mut request).await;
                let link_header = link
                    .map(|value| format!("Link: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{link_header}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let (client, api_base) =
            build_gitlab_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let groups = list_user_groups(&client, &api_base).await.unwrap();
        assert_eq!(groups, vec!["fixture/first-group", "fixture/second-group"]);
    }
}

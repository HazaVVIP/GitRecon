//! azure_api.rs
//! Azure DevOps REST API integration for `--azure-token` mode.
//!
//! Provides repository enumeration and file blob fetching via PAT authentication.
//! Supports both Azure DevOps Cloud (dev.azure.com) and Azure DevOps Server
//! (on-premise TFS/VSTS). All requests are authenticated with Basic auth using
//! the PAT as the username.

use crate::forge::{EnumScope, Forge, Platform, RateLimitInfo, Repository, TreeEntry};
use crate::http_client::{HttpClient, HttpConfig};
use async_trait::async_trait;
use std::time::{Duration, Instant};

const DEFAULT_AZURE_API: &str = "https://dev.azure.com";

// ════════════════════════════════════════════════
// FORGE TRAIT IMPLEMENTATION
// ════════════════════════════════════════════════

/// Azure DevOps API client implementing the Forge trait.
pub struct AzureForgeClient {
    client: HttpClient,
    api_base: String,
    rate_limit_remaining: std::sync::Arc<std::sync::Mutex<Option<(u32, Instant)>>>,
    org_url: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

impl AzureForgeClient {
    /// Create a new Azure DevOps forge client.
    pub fn new(client: HttpClient, api_base: String) -> Self {
        Self {
            client,
            api_base,
            rate_limit_remaining: std::sync::Arc::new(std::sync::Mutex::new(None)),
            org_url: std::sync::Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Update rate limit from response headers.
    fn update_rate_limit(&self, headers: &std::collections::HashMap<String, String>) {
        // Azure DevOps rate limit headers:
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
                    .unwrap_or(Duration::from_secs(60));

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
                    "Azure DevOps rate-limited (HTTP 429); sleeping {}s before retry {}/3",
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

    /// URL-encode a path for Azure DevOps API.
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

    /// Detect if the API base URL is for Azure DevOps Server (on-premise).
    fn is_on_premise(&self) -> bool {
        !self.api_base.contains("dev.azure.com") && !self.api_base.contains("visualstudio.com")
    }
}

#[async_trait]
impl Forge for AzureForgeClient {
    async fn authenticate(&mut self, _token: &str) -> anyhow::Result<()> {
        // Validate token by calling the profile API
        let url = format!("{}/_apis/profile/profiles/me", self.api_base);
        let resp = self.get_with_rate_limit(&url).await?;

        if resp.status == 401 || resp.status == 403 {
            anyhow::bail!("Invalid or expired token (HTTP {})", resp.status);
        }

        if resp.status != 200 && resp.status != 404 {
            // 404 might mean we're using an on-premise server without the profile API
            anyhow::bail!("Authentication failed with HTTP {}", resp.status);
        }

        // For on-premise, we need a different validation approach
        if resp.status == 404 && self.is_on_premise() {
            // Try to list projects to validate the token
            // For on-premise: https://{server}/{collection}/_apis/projects
            let projects_url = format!("{}/_apis/projects?api-version=7.0", self.api_base);
            let proj_resp = self.get_with_rate_limit(&projects_url).await?;

            if proj_resp.status == 401 || proj_resp.status == 403 {
                anyhow::bail!("Invalid or expired token (HTTP {})", proj_resp.status);
            }
        }

        Ok(())
    }

    async fn enumerate_repos(&self, scope: EnumScope) -> anyhow::Result<Vec<Repository>> {
        let mut repos = Vec::new();

        match scope {
            EnumScope::User => {
                // For user scope, we need to list all accessible projects first
                // Azure DevOps organizes repos as: Organization -> Project -> Repository
                let projects = self.list_projects().await?;

                for project in projects {
                    if let Ok(project_repos) = self.list_project_repos(&project).await {
                        repos.extend(project_repos);
                    }
                }
            }
            EnumScope::Org(org) => {
                // Azure DevOps uses "organizations" which map to the org parameter
                // URL format: https://dev.azure.com/{org}
                // For on-premise, org might be the collection name

                if self.is_on_premise() {
                    // For on-premise, we need to use the collection/projects structure
                    let projects = self.list_projects().await?;
                    for project in projects {
                        if let Ok(project_repos) = self.list_project_repos(&project).await {
                            repos.extend(project_repos);
                        }
                    }
                } else {
                    // For cloud, construct the org-specific URL
                    let org_api_base = if self.api_base.ends_with('/') {
                        format!("{}{}", self.api_base, org)
                    } else {
                        format!("{}/{}", self.api_base, org)
                    };

                    // Store the org URL for future calls
                    if let Ok(mut guard) = self.org_url.lock() {
                        *guard = Some(org_api_base.clone());
                    }

                    // List projects in the organization
                    let projects_url = format!("{}/_apis/projects?api-version=7.0", org_api_base);
                    let resp = self.get_with_rate_limit(&projects_url).await?;

                    if !resp.ok() {
                        anyhow::bail!(
                            "GET {} returned HTTP {}",
                            crate::validation::redact_url(&projects_url),
                            resp.status
                        );
                    }

                    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
                    if let Some(arr) = json["value"].as_array() {
                        for project in arr {
                            if let Some(project_name) = project["name"].as_str() {
                                if let Ok(project_repos) = self
                                    .list_org_project_repos(&org_api_base, project_name)
                                    .await
                                {
                                    repos.extend(project_repos);
                                }
                            }
                        }
                    }
                }
            }
            EnumScope::All => {
                // For "All", we need to discover all accessible organizations
                // This is limited in Azure DevOps Cloud - we'll use the user's known orgs
                if self.is_on_premise() {
                    let projects = self.list_projects().await?;
                    for project in projects {
                        if let Ok(project_repos) = self.list_project_repos(&project).await {
                            repos.extend(project_repos);
                        }
                    }
                } else {
                    // For cloud, try to enumerate from the user's profile
                    // Store current API base
                    let current_api = self.api_base.clone();
                    if let Ok(mut guard) = self.org_url.lock() {
                        *guard = Some(current_api);
                    }

                    // We can't easily enumerate all orgs without additional API calls
                    // So we'll return repos from projects accessible via the base URL
                    let projects = self.list_projects().await?;
                    for project in projects {
                        if let Ok(project_repos) = self.list_project_repos(&project).await {
                            repos.extend(project_repos);
                        }
                    }
                }
            }
        }

        // Deduplicate by full name
        let mut seen = std::collections::HashSet::new();
        repos.retain(|r| seen.insert((r.owner.clone(), r.name.clone())));

        Ok(repos)
    }

    async fn get_tree(&self, repo: &Repository, _branch: &str) -> anyhow::Result<Vec<TreeEntry>> {
        // Azure DevOps Git Items API: GET /repositories/{repoId}/items
        // This returns the root directory items, we need to traverse recursively
        let repo_id = &repo.full_name; // In our implementation, full_name holds the repo ID

        let mut all_entries = Vec::new();
        let mut stack = vec!["".to_string()];

        while let Some(current_path) = stack.pop() {
            let url = if current_path.is_empty() {
                format!(
                    "{}/_apis/git/repositories/{}/items?api-version=7.0&recursionLevel=OneLevel&includeContentMetadata=false",
                    self.api_base, repo_id
                )
            } else {
                let encoded_path = Self::encode_path(&current_path);
                format!(
                    "{}/_apis/git/repositories/{}/items?api-version=7.0&path={}&recursionLevel=OneLevel&includeContentMetadata=false",
                    self.api_base, repo_id, encoded_path
                )
            };

            let resp = self.get_with_rate_limit(&url).await;

            match resp {
                Ok(r) if r.status == 200 => {
                    let json: serde_json::Value = serde_json::from_slice(&r.body)?;
                    if let Some(arr) = json["value"].as_array() {
                        for entry in arr {
                            if let Some(az_entry) = parse_tree_entry(entry, &current_path) {
                                if az_entry.obj_type == "tree" {
                                    stack.push(az_entry.path.clone());
                                } else {
                                    all_entries.push(TreeEntry {
                                        path: az_entry.path,
                                        obj_type: az_entry.obj_type,
                                        sha: az_entry.sha,
                                        size: az_entry.size,
                                        mode: None,
                                    });
                                }
                            }
                        }
                    }
                }
                _ => {
                    // If we get a 404 or other error, the path might not exist
                    continue;
                }
            }
        }

        Ok(all_entries)
    }

    async fn get_blob(&self, repo: &Repository, sha: &str) -> anyhow::Result<Vec<u8>> {
        get_blob_content(&self.client, &self.api_base, &repo.full_name, sha).await
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
                limit: Platform::AzureDevOps.default_rate_limit(),
            })
    }

    fn platform(&self) -> Platform {
        Platform::AzureDevOps
    }

    async fn get_head_sha(&self, repo: &Repository, branch: &str) -> anyhow::Result<String> {
        get_head_sha(&self.client, &self.api_base, &repo.full_name, branch).await
    }

    async fn whoami(&self) -> anyhow::Result<(String, String)> {
        whoami(&self.client, &self.api_base).await
    }
}

impl AzureForgeClient {
    /// List all projects accessible to the authenticated user.
    async fn list_projects(&self) -> anyhow::Result<Vec<String>> {
        let mut projects = Vec::new();
        let url = format!("{}/_apis/projects?api-version=7.0", self.api_base);

        let resp = self.get_with_rate_limit(&url).await;

        match resp {
            Ok(r) if r.status == 200 => {
                let json: serde_json::Value = serde_json::from_slice(&r.body)?;
                if let Some(arr) = json["value"].as_array() {
                    for project in arr {
                        if let Some(name) = project["name"].as_str() {
                            projects.push(name.to_string());
                        }
                    }
                }
            }
            _ => {
                // For on-premise, the URL structure might be different
                // Return empty list
            }
        }

        Ok(projects)
    }

    /// List all repositories in a specific project (for on-premise/default API base).
    async fn list_project_repos(&self, project: &str) -> anyhow::Result<Vec<Repository>> {
        let mut repos = Vec::new();
        let _encoded_project = Self::encode_path(project);
        let url = format!("{}/_apis/git/repositories?api-version=7.0", self.api_base);

        let resp = self.get_with_rate_limit(&url).await?;

        if resp.status != 200 {
            anyhow::bail!(
                "GET {} returned HTTP {}",
                crate::validation::redact_url(&url),
                resp.status
            );
        }

        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        if let Some(arr) = json["value"].as_array() {
            for repo in arr {
                if let Some(az_repo) = parse_repo(repo, project) {
                    repos.push(Repository {
                        full_name: az_repo.id.clone(),
                        owner: project.to_string(),
                        name: az_repo.name.clone(),
                        private: az_repo.private,
                        default_branch: az_repo.default_branch.clone(),
                        clone_url: az_repo.clone_url.clone(),
                        platform: Platform::AzureDevOps,
                        stars: None, // Azure DevOps doesn't have stars
                        forks: None,
                        description: az_repo.description,
                        updated_at: az_repo.updated_at,
                    });
                }
            }
        }

        Ok(repos)
    }

    /// List all repositories in a specific organization's project (for cloud).
    async fn list_org_project_repos(
        &self,
        org_api_base: &str,
        project: &str,
    ) -> anyhow::Result<Vec<Repository>> {
        let mut repos = Vec::new();
        let url = format!("{}/_apis/git/repositories?api-version=7.0", org_api_base);

        let resp = self.get_with_rate_limit(&url).await?;

        if resp.status != 200 {
            anyhow::bail!(
                "GET {} returned HTTP {}",
                crate::validation::redact_url(&url),
                resp.status
            );
        }

        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        if let Some(arr) = json["value"].as_array() {
            for repo in arr {
                if let Some(az_repo) = parse_repo(repo, project) {
                    repos.push(Repository {
                        full_name: az_repo.id.clone(),
                        owner: project.to_string(),
                        name: az_repo.name.clone(),
                        private: az_repo.private,
                        default_branch: az_repo.default_branch.clone(),
                        clone_url: az_repo.clone_url.clone(),
                        platform: Platform::AzureDevOps,
                        stars: None,
                        forks: None,
                        description: az_repo.description,
                        updated_at: az_repo.updated_at,
                    });
                }
            }
        }

        Ok(repos)
    }
}

// ════════════════════════════════════════════════
// DATA STRUCTURES
// ════════════════════════════════════════════════

/// An Azure DevOps repository accessible to the authenticated user.
#[derive(Debug, Clone)]
pub struct AzRepo {
    pub id: String,
    pub name: String,
    #[allow(dead_code)]
    pub private: bool,
    pub default_branch: String,
    pub clone_url: String,
    pub description: Option<String>,
    pub updated_at: Option<String>,
}

/// A single entry (blob or tree) from an Azure DevOps Git Items API response.
#[derive(Debug, Clone)]
pub struct AzTreeEntry {
    pub path: String,
    pub obj_type: String, // "blob" or "tree"
    pub sha: String,
    pub size: Option<u64>,
}

// ════════════════════════════════════════════════
// CLIENT BUILDER
// ════════════════════════════════════════════════

/// Create a new [`HttpClient`] configured for Azure DevOps API calls.
///
/// Azure DevOps uses Basic authentication with the PAT as the username.
pub fn build_azure_client(
    mut base_cfg: HttpConfig,
    token: &str,
    azure_url: Option<&str>,
) -> anyhow::Result<(HttpClient, String)> {
    let api_base = azure_url.unwrap_or(DEFAULT_AZURE_API).to_string();

    // Azure DevOps uses Basic auth with PAT as username (empty password)
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{}:", token));
    base_cfg
        .extra_headers
        .push(("Authorization".to_string(), format!("Basic {}", encoded)));
    base_cfg
        .extra_headers
        .push(("Accept".to_string(), "application/json".to_string()));

    let client = HttpClient::new(base_cfg)?;

    Ok((client, api_base))
}

// ════════════════════════════════════════════════
// API HELPERS
// ════════════════════════════════════════════════

fn parse_repo(v: &serde_json::Value, _project: &str) -> Option<AzRepo> {
    let id = v["id"].as_str()?.to_string();
    let name = v["name"].as_str()?.to_string();
    let private = match v.get("project") {
        Some(p) => {
            p["visibility"].as_str() == Some("private")
                || p["visibility"].as_str() == Some("organization")
        }
        None => true, // Default to private if visibility not specified
    };
    let default_branch = v["defaultBranch"].as_str().unwrap_or("main").to_string();
    let clone_url = if let Some(url) = v["remoteUrl"].as_str() {
        url.to_string()
    } else if let Some(url) = v["webUrl"].as_str() {
        url.to_string()
    } else {
        String::new()
    };
    let description = v["description"].as_str().map(|s| s.to_string());
    let updated_at = v["lastUpdatedDate"].as_str().map(|s| s.to_string());

    Some(AzRepo {
        id,
        name,
        private,
        default_branch,
        clone_url,
        description,
        updated_at,
    })
}

fn parse_tree_entry(v: &serde_json::Value, _base_path: &str) -> Option<AzTreeEntry> {
    let path = v["path"].as_str()?.to_string();
    let obj_type = match v.get("gitObjectType") {
        Some(t) => t.as_str().unwrap_or("blob").to_string(),
        None => {
            // Fallback: check if it's a tree based on isFolder field
            if v["isFolder"].as_bool().unwrap_or(false) {
                "tree".to_string()
            } else {
                "blob".to_string()
            }
        }
    };
    let sha = v["objectId"].as_str().unwrap_or("").to_string();
    let size = v["size"].as_u64();

    if sha.is_empty() {
        return None;
    }

    Some(AzTreeEntry {
        path,
        obj_type,
        sha,
        size,
    })
}

/// Identify the authenticated user.
///
/// For Azure DevOps, we use the profile API or return a default user identifier.
pub async fn whoami(client: &HttpClient, api_base: &str) -> anyhow::Result<(String, String)> {
    let url = format!("{}/_apis/profile/profiles/me?api-version=7.0", api_base);
    let resp = client.get(&url).await;

    if resp.ok() {
        let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
        let id = json["id"].as_str().unwrap_or("azure-user").to_string();
        let display_name = json["displayName"]
            .as_str()
            .unwrap_or("Azure DevOps User")
            .to_string();
        return Ok((id, display_name));
    }

    // Fallback for on-premise or if profile API is not accessible
    Ok(("azure-user".to_string(), "Azure DevOps User".to_string()))
}

/// Resolve the HEAD commit SHA for a branch.
///
/// Uses `GET /git/repositories/{repoId}/refs?filter=heads/{branch}`.
pub async fn get_head_sha(
    client: &HttpClient,
    api_base: &str,
    repo_id: &str,
    branch: &str,
) -> anyhow::Result<String> {
    let url = format!(
        "{}/_apis/git/repositories/{}/refs?filter=heads/{}&api-version=7.0",
        api_base, repo_id, branch
    );
    let resp = client.get(&url).await;

    if !resp.ok() {
        anyhow::bail!(
            "Cannot resolve HEAD SHA for repo '{}' branch '{}' (HTTP {})",
            repo_id,
            branch,
            resp.status
        );
    }

    let json: serde_json::Value = serde_json::from_slice(&resp.body)?;
    if let Some(arr) = json["value"].as_array() {
        if let Some(ref_obj) = arr.first() {
            if let Some(sha) = ref_obj["objectId"].as_str() {
                return Ok(sha.to_string());
            }
        }
    }

    anyhow::bail!(
        "Missing commit SHA in response for repo '{}' branch '{}'",
        repo_id,
        branch
    );
}

/// Fetch the raw content of a blob by its SHA.
///
/// Uses `GET /git/repositories/{repoId}/blobs/{sha}`.
pub async fn get_blob_content(
    client: &HttpClient,
    api_base: &str,
    repo_id: &str,
    sha: &str,
) -> anyhow::Result<Vec<u8>> {
    let url = format!(
        "{}/_apis/git/repositories/{}/blobs/{}?api-version=7.0",
        api_base, repo_id, sha
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
    fn test_parse_repo_full() {
        let v = serde_json::json!({
            "id": "12345678-1234-1234-1234-123456789012",
            "name": "test-repo",
            "defaultBranch": "main",
            "remoteUrl": "https://dev.azure.com/org/project/_git/test-repo",
            "description": "Test repository",
            "project": {
                "visibility": "public"
            }
        });
        let repo = parse_repo(&v, "project").unwrap();
        assert_eq!(repo.id, "12345678-1234-1234-1234-123456789012");
        assert_eq!(repo.name, "test-repo");
        assert!(!repo.private);
        assert_eq!(repo.default_branch, "main");
        assert_eq!(repo.description, Some("Test repository".to_string()));
    }

    #[test]
    fn test_parse_repo_private() {
        let v = serde_json::json!({
            "id": "87654321-4321-4321-4321-210987654321",
            "name": "private-repo",
            "defaultBranch": "master",
            "remoteUrl": "https://dev.azure.com/org/project/_git/private-repo",
            "project": {
                "visibility": "private"
            }
        });
        let repo = parse_repo(&v, "project").unwrap();
        assert!(repo.private);
        assert_eq!(repo.default_branch, "master");
    }

    #[test]
    fn test_parse_tree_entry_blob() {
        let v = serde_json::json!({
            "path": "README.md",
            "gitObjectType": "blob",
            "objectId": "abc123",
            "size": 1024
        });
        let entry = parse_tree_entry(&v, "").unwrap();
        assert_eq!(entry.path, "README.md");
        assert_eq!(entry.obj_type, "blob");
        assert_eq!(entry.sha, "abc123");
        assert_eq!(entry.size, Some(1024));
    }

    #[test]
    fn test_parse_tree_entry_tree() {
        let v = serde_json::json!({
            "path": "src",
            "gitObjectType": "tree",
            "objectId": "def456"
        });
        let entry = parse_tree_entry(&v, "").unwrap();
        assert_eq!(entry.path, "src");
        assert_eq!(entry.obj_type, "tree");
    }

    #[test]
    fn test_parse_tree_entry_is_folder() {
        let v = serde_json::json!({
            "path": "docs",
            "isFolder": true,
            "objectId": "ghi789"
        });
        let entry = parse_tree_entry(&v, "").unwrap();
        assert_eq!(entry.path, "docs");
        assert_eq!(entry.obj_type, "tree");
    }

    #[test]
    fn test_encode_path() {
        assert_eq!(AzureForgeClient::encode_path("src/main.rs"), "src/main.rs");
        assert_eq!(
            AzureForgeClient::encode_path("path with spaces"),
            "path%20with%20spaces"
        );
        assert_eq!(
            AzureForgeClient::encode_path("特殊字符"),
            "%E7%89%B9%E6%AE%8A%E5%AD%97%E7%AC%A6"
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
    async fn mock_server_contract_covers_azure_identity_success() {
        let base_url =
            spawn_contract_server(200, r#"{"id":"fixture-id","displayName":"Fixture User"}"#).await;
        let (client, api_base) =
            build_azure_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let identity = whoami(&client, &api_base).await.unwrap();
        assert_eq!(
            identity,
            ("fixture-id".to_string(), "Fixture User".to_string())
        );
    }

    #[tokio::test]
    async fn mock_server_contract_documents_azure_identity_fallback_on_401() {
        let base_url = spawn_contract_server(401, "{}").await;
        let (client, api_base) =
            build_azure_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let identity = whoami(&client, &api_base).await.unwrap();
        assert_eq!(
            identity,
            ("azure-user".to_string(), "Azure DevOps User".to_string())
        );
    }
    #[tokio::test]
    async fn mock_server_contract_fetches_azure_blob_content() {
        let base_url = spawn_contract_server(200, "fixture-value").await;
        let (client, api_base) =
            build_azure_client(HttpConfig::default(), "synthetic-token", Some(&base_url)).unwrap();
        let content = get_blob_content(&client, &api_base, "fixture-repo", "sha")
            .await
            .unwrap();
        assert_eq!(content, b"fixture-value");
    }
}

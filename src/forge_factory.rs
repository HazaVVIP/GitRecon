//! Authenticated forge-client construction shared by token scanning and orchestration.

use crate::forge::Forge;
use crate::http_client::HttpConfig;

/// Create and authenticate a forge client for the selected provider.
pub async fn create_forge_client(
    platform: crate::forge::Platform,
    base_cfg: HttpConfig,
    token: &str,
    api_url: Option<&str>,
) -> anyhow::Result<Box<dyn Forge>> {
    match platform {
        crate::forge::Platform::GitHub => {
            Ok(Box::new(authenticate_github_client(base_cfg, token).await?))
        }
        crate::forge::Platform::GitLab => {
            let (client, api_base) =
                crate::gitlab_api::build_gitlab_client(base_cfg, token, api_url)?;
            let mut forge = crate::gitlab_api::GitLabForgeClient::new(client, api_base);
            forge.authenticate(token).await?;
            Ok(Box::new(forge))
        }
        crate::forge::Platform::Bitbucket => {
            let (client, api_base) =
                crate::bitbucket_api::build_bitbucket_client(base_cfg, token, api_url)?;
            let mut forge = crate::bitbucket_api::BitbucketForgeClient::new(client, api_base);
            forge.authenticate(token).await?;
            Ok(Box::new(forge))
        }
        crate::forge::Platform::Gitea => {
            let (client, api_base) =
                crate::gitea_api::build_gitea_client(base_cfg, token, api_url)?;
            let mut forge = crate::gitea_api::GiteaForgeClient::new(client, api_base);
            forge.authenticate(token).await?;
            Ok(Box::new(forge))
        }
        crate::forge::Platform::AzureDevOps => {
            let (client, api_base) =
                crate::azure_api::build_azure_client(base_cfg, token, api_url)?;
            let mut forge = crate::azure_api::AzureForgeClient::new(client, api_base);
            forge.authenticate(token).await?;
            Ok(Box::new(forge))
        }
    }
}

/// Create and authenticate a GitHub forge client.
pub async fn authenticate_github_client(
    base_cfg: HttpConfig,
    token: &str,
) -> anyhow::Result<crate::github_api::GitHubForgeClient> {
    let client = crate::github_api::build_github_client(base_cfg, token)?;
    let mut github = crate::github_api::GitHubForgeClient::new(client);
    github.authenticate(token).await?;
    Ok(github)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_module_is_linked_to_forge_trait() {
        fn assert_forge<T: Forge + ?Sized>() {}
        assert_forge::<dyn Forge>();
    }
}

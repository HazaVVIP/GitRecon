//! streamer.rs
//! Phase 3 — Stream & Scan: fetch every object, scan for secrets in memory,
//! optionally writing blobs to disk when --save is active.
//! Output: StreamResult with all findings + intel.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use regex::Regex;
use lazy_static::lazy_static;
use futures::StreamExt;

use crate::http_client::HttpClient;
use crate::git_parser::{ObjectParser, obj_path};
use crate::mapper::MapResult;
use crate::text_utils::truncate_utf8;

// ════════════════════════════════════════════════
// SECRET PATTERNS
// ════════════════════════════════════════════════

/// A secret-detection pattern loaded at runtime (e.g. from `--patterns FILE`).
#[derive(Clone)]
pub struct DynPattern {
    pub id:    String,
    pub sev:   String,
    pub desc:  String,
    pub regex: Regex,
}

/// Load custom detection patterns from a JSON file.
///
/// Expected format:
/// ```json
/// {"patterns": [{"id": "my_token", "severity": "CRITICAL", "description": "...", "regex": "..."}]}
/// ```
#[allow(dead_code)]
pub fn load_patterns_from_file(path: &str) -> anyhow::Result<Vec<DynPattern>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read patterns file '{}': {}", path, e))?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("Invalid JSON in patterns file '{}': {}", path, e))?;
    let arr = json["patterns"].as_array()
        .ok_or_else(|| anyhow::anyhow!("Patterns file must contain a top-level 'patterns' array"))?;

    let mut result = Vec::with_capacity(arr.len());
    for (i, p) in arr.iter().enumerate() {
        let id      = p["id"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Pattern #{}: missing 'id' field", i))?;
        let sev     = p["severity"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Pattern #{}: missing 'severity' field", i))?;
        let desc    = p["description"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Pattern #{}: missing 'description' field", i))?;
        let rx_str  = p["regex"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Pattern #{}: missing 'regex' field", i))?;
        let regex = Regex::new(rx_str)
            .map_err(|e| anyhow::anyhow!("Pattern #{} '{}': invalid regex '{}': {}", i, id, rx_str, e))?;
        result.push(DynPattern { id: id.into(), sev: sev.into(), desc: desc.into(), regex });
    }
    Ok(result)
}

struct Pattern {
    id:    &'static str,
    sev:   &'static str,
    desc:  &'static str,
    regex: Regex,
}

macro_rules! pat {
    ($id:expr, $sev:expr, $desc:expr, $rx:expr) => {
        Pattern {
            id:   $id,
            sev:  $sev,
            desc: $desc,
            regex: Regex::new($rx).expect(concat!("bad regex: ", $rx)),
        }
    };
}

lazy_static! {
    static ref PATTERNS: Vec<Pattern> = vec![
        // Cloud — AWS
        pat!("aws_key_id",  "CRITICAL", "AWS Access Key ID",
             r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"),
        pat!("aws_secret",  "CRITICAL", "AWS Secret Access Key",
             r#"(?i)aws[_\-\s]?secret[_\-\s]?[a-z]*\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#),
        pat!("aws_mfa",     "HIGH",     "AWS MFA Serial",
             r"\barn:aws:iam::\d{12}:mfa/[A-Za-z0-9+=,.@_/-]+"),
        // Cloud — GCP
        pat!("gcp_sa",      "CRITICAL", "GCP Service Account",
             r#""type"\s*:\s*"service_account""#),
        pat!("gcp_api_key", "CRITICAL", "GCP API Key",
             r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        // Cloud — Azure
        pat!("azure_conn",  "CRITICAL", "Azure Storage Connection String",
             r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
        pat!("azure_sas",   "HIGH",     "Azure SAS Token",
             r"sig=[A-Za-z0-9%+/]+=?&se=\d{4}-\d{2}-\d{2}"),
        pat!("azure_tenant","HIGH",     "Azure AD Client Secret",
             r#"(?i)client[_\-]?secret\s*[=:]\s*['"]?([A-Za-z0-9~._@\-]{32,})['"]?"#),
        // VCS tokens
        pat!("github_pat",   "CRITICAL", "GitHub Personal Access Token",
             r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
        pat!("github_oauth", "CRITICAL", "GitHub OAuth Token",
             r"gho_[A-Za-z0-9]{36}"),
        pat!("github_app",   "CRITICAL", "GitHub App Token",
             r"(ghu|ghs)_[A-Za-z0-9]{36}"),
        pat!("gitlab_pat",   "CRITICAL", "GitLab PAT",
             r"glpat-[A-Za-z0-9\-_]{20}"),
        pat!("bitbucket_key","CRITICAL", "Bitbucket App Password",
             r"\bATBB[A-Za-z0-9]{32}\b"),
        // Payment
        pat!("stripe_sk", "CRITICAL", "Stripe Secret Key",
             r"sk_(live|test)_[A-Za-z0-9]{24,}"),
        pat!("stripe_pk", "HIGH",     "Stripe Publishable Key",
             r"pk_(live|test)_[A-Za-z0-9]{24,}"),
        pat!("stripe_webhook", "HIGH", "Stripe Webhook Secret",
             r"\bwhsec_[A-Za-z0-9]{32,}\b"),
        pat!("paypal_client", "HIGH",  "PayPal Client ID / Secret",
             r#"(?i)paypal[_\-\s]?(client[_\-]?id|secret)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#),
        // Messaging / Comms
        pat!("slack_token",   "HIGH", "Slack Token",
             r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"),
        pat!("slack_webhook", "HIGH", "Slack Webhook",
             r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        pat!("slack_signing",  "HIGH", "Slack Signing Secret",
             r"\bv0=[0-9a-f]{64}\b"),
        pat!("discord_token", "HIGH", "Discord Bot Token",
             r#"(?i)discord[_\-\s]?token\s*[=:]\s*['"]?([A-Za-z0-9._-]{59,})['"]?"#),
        pat!("discord_webhook","HIGH", "Discord Webhook URL",
             r"https://discord(?:app)?\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_\-]{68}"),
        pat!("telegram_bot",  "HIGH", "Telegram Bot Token",
             r#"(?i)(?:telegram|bot)[_\-\s]?(?:token|api[_\-]?key|auth[_\-]?token|chat[_\-]?id)\s*[=:]\s*['"]?\d{8,10}:[A-Za-z0-9_-]{35}['"]?"#),
        pat!("sendgrid",      "HIGH", "SendGrid API Key",
             r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        pat!("twilio",        "HIGH", "Twilio API Key",
             r"SK[0-9a-f]{32}"),
        pat!("twilio_account","HIGH", "Twilio Account SID",
             r"\bAC[0-9a-f]{32}\b"),
        pat!("mailgun",       "HIGH", "Mailgun Key",
             r"key-[0-9a-f]{32}"),
        pat!("pusher_key",    "HIGH", "Pusher App Key/Secret",
             r#"(?i)pusher[_\-]?(app[_\-]?key|app[_\-]?secret|key|secret)\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?"#),
        // E-commerce / PaaS
        pat!("shopify_token",  "CRITICAL", "Shopify Admin API Token",
             r"shpat_[A-Za-z0-9]{32}"),
        pat!("shopify_secret", "HIGH",     "Shopify Shared Secret",
             r"shpss_[A-Za-z0-9]{32}"),
        pat!("heroku_api_key", "CRITICAL", "Heroku API Key",
             r#"(?i)heroku[_\-]?(api[_\-]?key|token|auth)\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?"#),
        pat!("vercel_token",   "CRITICAL", "Vercel API Token",
             r"\bvercel[_\-]?token\s*[=:]\s*[A-Za-z0-9]{24,}\b"),
        // Database
        pat!("db_url",      "CRITICAL", "Database Connection URL",
             r"(?i)(mysql|postgres|postgresql|mongodb|redis|mssql|oracle|cockroachdb|clickhouse)://[^:@\s]+:[^@\s]+@[^\s]+"),
        pat!("db_password", "CRITICAL", "Database Password",
             r#"(?i)db[_\-]?(pass(word)?|pwd)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?"#),
        pat!("mongodb_atlas","CRITICAL", "MongoDB Atlas Connection String",
             r"mongodb\+srv://[^:@\s]+:[^@\s]+@[^\s]+\.mongodb\.net"),
        // Keys & Certificates
        pat!("private_key", "CRITICAL", "Private Key",
             r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----"),
        pat!("pgp_key",     "CRITICAL", "PGP Private Key",
             r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        pat!("pkcs12",      "HIGH",     "PKCS12/PFX Certificate Bundle Reference",
             r#"(?i)(keystore|truststore|\.p12|\.pfx)\s*[=:]\s*['"]?([^\s'"]{4,})['"]?"#),
        // JWT
        pat!("jwt",        "HIGH",     "JWT Token",
             r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        pat!("jwt_secret", "CRITICAL", "JWT Secret",
             r#"(?i)jwt[_\-]?secret\s*[=:]\s*['"]?([^\s'"]{16,})['"]?"#),
        // Generic
        pat!("api_key",      "HIGH", "Generic API Key",
             r#"(?i)api[_\-\s]?key\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#),
        pat!("secret_key",   "HIGH", "Generic Secret Key",
             r#"(?i)secret[_\-\s]?key\s*[=:]\s*['"]?([A-Za-z0-9_\-!@#$]{16,})['"]?"#),
        pat!("access_token", "HIGH", "Access Token",
             r#"(?i)access[_\-\s]?token\s*[=:]\s*['"]?([A-Za-z0-9_\-\.]{20,})['"]?"#),
        pat!("bearer_token", "HIGH", "Bearer Token in Authorization Header",
             r"(?i)Authorization\s*[:=]\s*[Bb]earer\s+([A-Za-z0-9_\-\.]{20,})"),
        // Password
        pat!("hardcoded_pass", "HIGH", "Hardcoded Password",
             r#"(?i)(password|passwd|pass|pwd)\s*[=:]\s*['"]([^'"\s]{8,})['"]"#),
        pat!("env_pass",       "HIGH", "Env Password Variable",
             r"(?m)^[A-Z_]*PASS(?:WORD)?[A-Z_]*\s*=\s*([^\s].+)$"),
        // WordPress / PHP — define('KEY', 'value') with comma separator
        pat!("wp_define", "CRITICAL", "WordPress Config Credential",
             r#"(?i)define\s*\(\s*['"](?:DB_PASSWORD|DB_USER|DB_HOST|DB_NAME|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT|SECRET_KEY|SECRET_SALT)['"]\s*,\s*['"]([^'"]{4,})['"]"#),
        // Generic PHP define() — catches define('..._KEY', ...), define('..._SECRET', ...), etc.
        pat!("php_define_secret", "HIGH", "PHP define() Secret/Key/Token",
             r#"(?i)define\s*\(\s*['"][A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Z0-9_]*['"]\s*,\s*['"]([^'"]{8,})['"]"#),
        // Django / Flask
        pat!("django_secret", "CRITICAL", "Django/Flask SECRET_KEY",
             r#"(?i)SECRET_KEY\s*=\s*['"]([^'"]{20,})['"]"#),
        // Rails
        pat!("rails_secret", "CRITICAL", "Rails secret_key_base",
             r#"(?i)secret_key_base\s*[=:]\s*['"]?([A-Za-z0-9]{64,})['"]?"#),
        // Mailchimp
        pat!("mailchimp_key", "HIGH", "Mailchimp API Key",
             r"[0-9a-f]{32}-us[1-9][0-9]?\b"),
        // Laravel
        pat!("laravel_app_key", "CRITICAL", "Laravel APP_KEY",
             r"APP_KEY=base64:[A-Za-z0-9+/=]{40,}"),
        // Misc SaaS
        pat!("firebase_fcm", "HIGH", "Firebase FCM Key",
             r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
        pat!("firebase_rtdb", "HIGH", "Firebase RTDB URL with Auth",
             r"https://[a-z0-9\-]+\.firebaseio\.com.*[?&]auth=[A-Za-z0-9_\-]{20,}"),
        pat!("npm_token",    "HIGH", "NPM Token",
             r"(?:^|[^a-z])npm_[A-Za-z0-9]{36}"),
        pat!("docker_pat",   "HIGH", "Docker Hub PAT",
             r"dckr_pat_[A-Za-z0-9_-]{27}"),
        pat!("oauth_secret", "HIGH", "OAuth Client Secret",
             r#"(?i)client[_\-]?secret\s*[=:]\s*['"]?([A-Za-z0-9_\-]{16,})['"]?"#),
        pat!("twitch_token",  "CRITICAL", "Twitch OAuth Token",
             r"\boauth:[A-Za-z0-9]{30}\b"),
        pat!("algolia_key",   "HIGH", "Algolia API Key",
             r#"(?i)algolia[_\-\s]?(api[_\-]?key|app[_\-]?id)\s*[=:]\s*['"]?([A-Za-z0-9]{32,})['"]?"#),
        pat!("sentry_dsn",    "HIGH", "Sentry DSN",
             r"https://[0-9a-f]{32}@(?:o\d+\.)?ingest\.sentry\.io/\d+"),
        pat!("cloudinary_url","HIGH", "Cloudinary Credentials",
             r"cloudinary://[A-Za-z0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9]+"),
        pat!("okta_api_token","CRITICAL", "Okta API Token",
             r#"(?i)okta[_\-]?api[_\-]?token\s*[=:]\s*['"]?([A-Za-z0-9_\-]{32,})['"]?"#),
        pat!("pagerduty_key", "HIGH", "PagerDuty API Key",
             r#"(?i)pagerduty[_\-]?(api[_\-]?key|token)\s*[=:]\s*['"]?([A-Za-z0-9\+]{20,})['"]?"#),
        pat!("terraform_cloud","CRITICAL","Terraform Cloud Token",
             r"\btfp[a-z0-9]{30,}\b"),
        // AI Providers
        pat!("openai_key", "CRITICAL", "OpenAI API Key",
             r"sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9_\-]{86}|sk-svcacct-[A-Za-z0-9_\-]{86}"),
        pat!("anthropic_key", "CRITICAL", "Anthropic API Key",
             r"sk-ant-[A-Za-z0-9_\-]{93,}"),
        pat!("huggingface_token", "HIGH", "HuggingFace Token",
             r"\bhf_[A-Za-z0-9]{34,}\b"),
        pat!("cohere_key",    "HIGH", "Cohere API Key",
             r#"(?i)cohere[_\-]?api[_\-]?key\s*[=:]\s*['"]?([A-Za-z0-9]{40})['"]?"#),
        pat!("openrouter_key", "CRITICAL", "OpenRouter API Key",
             r#"(?i)\bopenrouter[_\-]?api[_\-]?key\s*[=:]\s*['"]?(sk-or-v1-[A-Za-z0-9_\-]{20,})['"]?"#),
        pat!("ai_provider_env_key", "HIGH", "AI Provider API Key Variable",
             r#"(?i)\b(gemini_api_key|google_ai_api_key|xai_api_key|deepseek_api_key|mistral_api_key|perplexity_api_key)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#),
        // Infrastructure / PaaS
        pat!("digitalocean_pat", "CRITICAL", "DigitalOcean Personal Access Token",
             r"\bdop_v1_[a-f0-9]{64}\b"),
        pat!("vault_token", "CRITICAL", "HashiCorp Vault Token",
             r"\bhvs\.[A-Za-z0-9_\-]{28,}\b"),
        pat!("databricks_token", "CRITICAL", "Databricks API Token",
             r"\bdapi[0-9a-f]{32}\b"),
        pat!("cloudflare_key",   "CRITICAL", "Cloudflare Global API Key",
             r#"(?i)cloudflare[_\-]?(api[_\-]?key|token)\s*[=:]\s*['"]?([A-Za-z0-9]{37,})['"]?"#),
        pat!("cloudflare_token", "CRITICAL", "Cloudflare API Token",
             r"\bcloudflare_token\s*=\s*[A-Za-z0-9_\-]{40}\b"),
        pat!("netlify_pat",      "CRITICAL", "Netlify Personal Access Token",
             r#"(?i)netlify[_\-]?token\s*[=:]\s*['"]?([A-Za-z0-9_\-]{40,})['"]?"#),
        // Database-as-a-service
        pat!("planetscale_token", "CRITICAL", "PlanetScale Token",
             r"\bpscale_tkn_[A-Za-z0-9_]{43}\b"),
        pat!("supabase_key", "CRITICAL", "Supabase Service Role Key",
             r"\bsbp_[A-Za-z0-9]{40}\b"),
        pat!("neon_token",   "HIGH",     "Neon Database Token",
             r"\bneon_[A-Za-z0-9_\-]{40,}\b"),
        // Secrets management
        pat!("doppler_token", "CRITICAL", "Doppler Service Token",
             r"\bdp\.pt\.[A-Za-z0-9]{43}\b"),
        // Project management / Collaboration
        pat!("linear_key",   "HIGH", "Linear API Key",
             r"\blin_api_[A-Za-z0-9]{40}\b"),
        pat!("jira_token",   "HIGH", "Atlassian / Jira API Token",
             r"ATATT[A-Za-z0-9+/=]{28,}"),
        pat!("confluence_api","HIGH", "Confluence API Token",
             r"ATCTT[A-Za-z0-9+/=]{28,}"),
        pat!("asana_token",  "HIGH", "Asana Personal Access Token",
             r#"(?i)asana[_\-]?(token|pat|access[_\-]?token)\s*[=:]\s*['"]?(0/[A-Za-z0-9]{32})['"]?"#),
        pat!("notion_token", "HIGH", "Notion Integration Token",
             r"\bsecret_[A-Za-z0-9]{43}\b"),
        // Observability / Monitoring
        pat!("datadog_api",  "HIGH", "Datadog API Key",
             r#"(?i)datadog[_\-]?api[_\-]?key\s*[=:]\s*['"]?([0-9a-f]{32})['"]?"#),
        pat!("newrelic_key", "HIGH", "New Relic License Key",
             r"\bNRAL-[A-Za-z0-9]{32,}\b"),
        pat!("grafana_token","HIGH", "Grafana Service Account Token",
             r"\bglsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8}\b"),
        // Cloud — Oracle
        pat!("oracle_oci_fingerprint", "CRITICAL", "Oracle Cloud API Key Fingerprint",
             r"fingerprint\s*=\s*([0-9a-f]{2}:){15}[0-9a-f]{2}"),
        // Cloud — Alibaba
        pat!("alibaba_key_id",  "CRITICAL", "Alibaba Cloud Access Key ID",
             r"\bLTAI[A-Za-z0-9]{12,20}\b"),
        pat!("alibaba_secret",  "CRITICAL", "Alibaba Cloud Access Key Secret",
             r#"(?i)alibaba[_\-]?(cloud[_\-]?)?access[_\-]?key[_\-]?secret\s*[=:]\s*['"]?([A-Za-z0-9]{30})"#),
        // Cloud — IBM
        pat!("ibm_cloud_key",   "CRITICAL", "IBM Cloud API Key",
             r#"(?i)ibm[_\-]?cloud[_\-]?api[_\-]?key\s*[=:]\s*['"]?([A-Za-z0-9_\-]{44})"#),
        // Cloud — Linode
        pat!("linode_token",    "CRITICAL", "Linode / Akamai Cloud PAT",
             r#"(?i)linode[_\-]?(token|api[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9]{64})"#),
        // Cloud — Vultr
        pat!("vultr_api_key",   "CRITICAL", "Vultr API Key",
             r#"(?i)vultr[_\-]?(api[_\-]?key|token)\s*[=:]\s*['"]?([A-Za-z0-9\-]{36,})"#),
        // Cloud — Hetzner
        pat!("hetzner_token",   "CRITICAL", "Hetzner Cloud API Token",
             r#"(?i)hcloud[_\-]?token\s*[=:]\s*['"]?([A-Za-z0-9_\-]{64})"#),
        // Cloud — Scaleway
        pat!("scaleway_secret_key", "CRITICAL", "Scaleway Secret Key",
             r"SCW_SECRET_KEY=[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        // Cloud — Fly.io
        pat!("flyio_token",     "CRITICAL", "Fly.io API Token",
             r"\bfo1_[A-Za-z0-9_\-]{40,}\b"),
        // Cloud — Render
        pat!("render_api_key",  "HIGH",     "Render API Key",
             r"\brnd_[A-Za-z0-9]{32}\b"),
        // CI/CD — CircleCI
        pat!("circleci_token",  "CRITICAL", "CircleCI API Token",
             r#"(?i)circle[_\-]?(?:ci[_\-]?)?token\s*[=:]\s*['"]?([0-9a-f]{40})"#),
        // CI/CD — Travis CI
        pat!("travis_token",    "HIGH",     "Travis CI Token",
             r#"(?i)travis[_\-]?token\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,50})"#),
        // CI/CD — Jenkins
        pat!("jenkins_api_token","HIGH",    "Jenkins API Token",
             r#"(?i)jenkins[_\-]?api[_\-]?token\s*[=:]\s*['"]?([0-9a-f]{32})"#),
        // Database — Upstash Redis
        pat!("upstash_redis",   "CRITICAL", "Upstash Redis Connection URL",
             r"rediss?://[^@:]+:[A-Za-z0-9+/=_\-]{32,}@[a-z0-9\-]+\.upstash\.io"),
        // Database — Fauna
        pat!("fauna_secret",    "CRITICAL", "Fauna Database Secret",
             r"\bfn[A-Za-z0-9]{40,}\b"),
        // Database — Xata
        pat!("xata_api_key",    "CRITICAL", "Xata API Key",
             r"\bxau_[A-Za-z0-9_]{48}\b"),
        // Database — Turso
        pat!("turso_token",     "CRITICAL", "Turso Database Auth Token",
             r#"(?i)TURSO_AUTH_TOKEN\s*=\s*['"]?([A-Za-z0-9_\-=.]{40,})"#),
        // Payment — Square
        pat!("square_api_key",  "CRITICAL", "Square API Key / Access Token",
             r"sq0csp-[A-Za-z0-9\-_]{43}|EAAAAA[A-Za-z0-9_\-]{55,}"),
        // Payment — Adyen
        pat!("adyen_api_key",   "CRITICAL", "Adyen API Key",
             r#"(?i)adyen[_\-]?(api[_\-]?key|ws[_\-]?key)\s*[=:]\s*['"]?(AQE[A-Za-z0-9/+=]{56,})"#),
        // Payment — Razorpay
        pat!("razorpay_key",    "CRITICAL", "Razorpay API Key",
             r"\brzp_(live|test)_[A-Za-z0-9]{14,}\b"),
        // Payment — Braintree
        pat!("braintree_token", "CRITICAL", "Braintree Access Token",
             r"access_token\$(?:production|sandbox)\$[a-z0-9]+_[a-z0-9_]+\$[a-f0-9]+"),
        // Payment — Coinbase
        pat!("coinbase_secret", "HIGH",     "Coinbase API Key / Secret",
             r#"(?i)coinbase[_\-]?(api[_\-]?key|secret|api[_\-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{32,})"#),
        // Maps — Mapbox
        pat!("mapbox_token",    "HIGH",     "Mapbox Access Token",
             r"\bpk\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        // Blockchain / Web3
        pat!("infura_key",      "HIGH",     "Infura Project Key",
             r#"(?i)infura[_\-]?(project[_\-]?id|api[_\-]?key|secret)\s*[=:]\s*['"]?([A-Za-z0-9]{32})"#),
        // Platform
        pat!("railway_token",   "HIGH",     "Railway API Token",
             r#"(?i)railway[_\-]?token\s*[=:]\s*['"]?([A-Za-z0-9_\-]{40,})"#),
        // GitHub fine-grained PAT (new format)
        pat!("github_fine_pat", "CRITICAL", "GitHub Fine-Grained Personal Access Token",
             r"github_pat_[A-Za-z0-9_]{82}"),
        // AI providers — extended
        pat!("groq_key",       "CRITICAL", "Groq API Key",
             r"\bgsk_[A-Za-z0-9]{52}\b"),
        pat!("mistral_key",    "CRITICAL", "Mistral API Key",
             r#"(?i)mistral[_\-]?api[_\-]?key\s*[=:]\s*['"]?([A-Za-z0-9]{32})"#),
        pat!("replicate_token","CRITICAL", "Replicate API Token",
             r"\br8_[A-Za-z0-9]{40}\b"),
        // Auth / Identity
        pat!("auth0_secret",   "CRITICAL", "Auth0 Client Secret",
             r#"(?i)auth0[_\-]?client[_\-]?secret\s*[=:]\s*['"]?([A-Za-z0-9_\-]{32,})"#),
        pat!("clerk_secret",   "CRITICAL", "Clerk Secret Key",
             r"\bsk_live_[A-Za-z0-9]{27,}\b"),
        // CMS / Headless
        pat!("contentful_token","HIGH",    "Contentful Delivery/Management Token",
             r"\bCFPAT-[A-Za-z0-9_\-]{43}\b"),
        pat!("sanity_token",    "HIGH",    "Sanity API Token",
             r"\bskC[A-Za-z0-9]{60,}\b"),
        // Productivity / SaaS
        pat!("airtable_key",   "HIGH",     "Airtable API Key / PAT",
             r"\bpat[A-Za-z0-9]{14}\.[0-9a-f]{64}\b"),
        pat!("postman_key",    "HIGH",     "Postman API Key",
             r"\bPMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}\b"),
        pat!("snyk_token",     "HIGH",     "Snyk API Token",
             r#"(?i)snyk[_\-]?token\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"#),
        // Cloud — Tencent
        pat!("tencent_secret_id", "CRITICAL", "Tencent Cloud SecretId",
             r"\bAKID[A-Za-z0-9]{32}\b"),
        // Encryption
        pat!("age_secret_key", "CRITICAL", "Age Encryption Secret Key",
             r"AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"),
        // AWS extended
        pat!("aws_session",    "HIGH",     "AWS Session Token",
             r#"(?i)aws[_\-\s]?session[_\-\s]?token\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?"#),
        // Docker
        pat!("docker_config_auth", "CRITICAL", "Docker Registry Auth (Base64)",
             r#""auth"\s*:\s*"([A-Za-z0-9+/=]{20,})""#),
        // Email — SMTP / IMAP / POP3
        pat!("smtp_credentials", "CRITICAL", "SMTP Credentials",
             r#"(?i)\bsmtp[_\-]?(?:pass(?:word)?|pwd)\b['"]*\s*(?:=>|[=:])\s*['"]?([^\s'">,]{8,})['"]?"#),
        pat!("smtp_url",         "CRITICAL", "SMTP Connection URL",
             r"(?i)smtps?://[^:@\s]+:[^@\s]{8,}@[^\s]+"),
        pat!("imap_credentials", "HIGH",     "IMAP/POP3 Credentials",
             r#"(?i)\b(?:imap|pop3)[_\-]?(?:pass(?:word)?|pwd)\b['"]*\s*(?:=>|[=:])\s*['"]?([^\s'">,]{8,})['"]?"#),
        // File transfer — FTP / SFTP
        pat!("ftp_credentials",  "HIGH",     "FTP/SFTP Credentials",
             r#"(?i)\bs?ftp[_\-]?(?:pass(?:word)?|pwd)\b['"]*\s*(?:=>|[=:])\s*['"]?([^\s'">,]{8,})['"]?"#),
        pat!("ftp_url",          "HIGH",     "FTP Connection URL with Credentials",
             r"(?i)s?ftp://[^:@\s]+:[^@\s]{8,}@[^\s]+"),
        // Message queues — AMQP / RabbitMQ
        pat!("amqp_url",         "HIGH",     "AMQP/RabbitMQ Connection URL",
             r"(?i)amqps?://[^:@\s]+:[^@\s]{8,}@[^\s]+"),
        // Directory services — LDAP
        pat!("ldap_credentials", "HIGH",     "LDAP/LDAPS Credentials",
             r"(?i)ldaps?://[^:@\s]+:[^@\s]{8,}@[^\s]+"),
    ];

    static ref PLACEHOLDERS: Vec<&'static str> = vec![
        "your_", "YOUR_", "your-", "YOUR-",
        "example", "EXAMPLE", "placeholder",
        "xxxx", "XXXX", "changeme", "CHANGE_ME", "changeit", "ChangeMe",
        "insert_", "INSERT_",
        "TODO", "FIXME", "test_", "TEST_", "dummy", "DUMMY",
        "replace", "REPLACE", "sample", "SAMPLE", "fake", "FAKE",
        "00000000", "11111111", "<",
        // Additional common dev/template placeholders
        "n/a", "N/A", "none", "NONE", "null", "NULL", "undefined",
        "my_", "MY_", "enter_", "ENTER_", "set_", "SET_",
        "fill_", "FILL_",
        // "put_" / "PUT_" (underscore) and "put " (space) cover both `put_your_key_here`
        // style and WordPress wp-config-sample.php `put your unique phrase here` values.
        "put_", "PUT_", "put ",
        "add_", "ADD_",
        // Common template / documentation phrases
        "change this", "change-this",
    ];

    static ref SENSITIVE_NAMES: Regex = Regex::new(
        r#"(?i)(\.env|\.env\.|config\.php|wp-config|database\.php|settings\.py|config\.ya?ml|credentials|secrets?\.json|service.account|\.npmrc|\.pypirc|\.netrc|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem|\.key|\.pfx|\.p12|application\.(properties|ya?ml)|docker.compose|\.travis\.yml|\.circleci|\.github/workflows|\.env\.local|\.env\.prod(uction)?|\.env\.staging|\.env\.development|vault\.ya?ml|terraform\.tfvars|\.kubeconfig|kubeconfig|\.htpasswd|\.aws/credentials|\.aws/config|gcloud/credentials|\.config/gcloud|sentry\.properties|\.npmrc|\.yarnrc|Dockerfile|\.kube/config|\.ssh/config|authorized_keys|known_hosts|\.docker/config\.json|\.terraform/|\.gradle/gradle\.properties|\.m2/settings\.xml|\.cargo/credentials|bower\.json|\.babelrc|\.eslintrc|shadow|passwd|\.gnupg/|\.pgpass|\.my\.cnf|\.s3cfg|\.gitconfig|\.bash_history|\.zsh_history|\.profile|\.bashrc|\.zshrc)"#
    ).unwrap();
}


// ════════════════════════════════════════════════
// TECH STACK
// ════════════════════════════════════════════════

lazy_static! {
    static ref TECH_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("Python",      Regex::new(r"requirements\.txt|setup\.py|Pipfile|pyproject\.toml|manage\.py|tox\.ini").unwrap()),
        ("Node.js",     Regex::new(r"package\.json|yarn\.lock|package-lock\.json|\.nvmrc").unwrap()),
        ("PHP",         Regex::new(r"composer\.json|composer\.lock|\.php$").unwrap()),
        ("Ruby",        Regex::new(r"Gemfile|\.ruby-version|\.rb$|Rakefile").unwrap()),
        ("Java",        Regex::new(r"pom\.xml|build\.gradle|\.java$|\.jar$").unwrap()),
        ("Go",          Regex::new(r"go\.mod|go\.sum|\.go$").unwrap()),
        ("Rust",        Regex::new(r"Cargo\.toml|Cargo\.lock|\.rs$").unwrap()),
        (".NET",        Regex::new(r"\.csproj|\.sln|web\.config|\.fsproj|\.vbproj").unwrap()),
        ("Docker",      Regex::new(r"Dockerfile|docker-compose|\.dockerignore").unwrap()),
        ("Kubernetes",  Regex::new(r"kubectl|\.yaml$|kustomization\.ya?ml").unwrap()),
        ("Terraform",   Regex::new(r"\.tf$|terraform\.tfvars|\.tfstate").unwrap()),
        ("WordPress",   Regex::new(r"wp-config|wp-content|wp-includes").unwrap()),
        ("Django",      Regex::new(r"manage\.py|settings\.py|wsgi\.py|asgi\.py").unwrap()),
        ("Laravel",     Regex::new(r"artisan|\.blade\.php|bootstrap/app\.php").unwrap()),
        ("React",       Regex::new(r"\.jsx$|\.tsx$|react-scripts").unwrap()),
        ("Vue",         Regex::new(r"\.vue$|vue\.config|vuex").unwrap()),
        ("Angular",     Regex::new(r"angular\.json|ng-package|\.component\.ts$").unwrap()),
        ("Svelte",      Regex::new(r"svelte\.config|\.svelte$").unwrap()),
        ("Next.js",     Regex::new(r"next\.config\.(js|ts)|_next/|\.next/").unwrap()),
        ("NestJS",      Regex::new(r"nest-cli\.json|\.module\.ts$|\.controller\.ts$").unwrap()),
        ("FastAPI",     Regex::new(r"\bfastapi\b|\buvicorn\b").unwrap()),
        ("Spring",      Regex::new(r"pom\.xml|spring-boot|ApplicationContext\.xml|application\.properties").unwrap()),
        ("Flutter",     Regex::new(r"pubspec\.yaml|\.dart$").unwrap()),
        ("Ansible",     Regex::new(r"ansible\.cfg|playbook\.ya?ml|inventory\.ya?ml").unwrap()),
        ("Helm",        Regex::new(r"Chart\.ya?ml|values\.ya?ml|templates/").unwrap()),
        ("Elixir",      Regex::new(r"mix\.exs|mix\.lock|\.ex$|\.exs$").unwrap()),
        ("Kotlin",      Regex::new(r"\.kt$|\.kts$|build\.gradle\.kts").unwrap()),
        ("Swift",       Regex::new(r"\.swift$|Package\.swift|Podfile").unwrap()),
        ("Scala",       Regex::new(r"\.scala$|build\.sbt|\.sc$").unwrap()),
        ("Haskell",     Regex::new(r"\.hs$|\.cabal$|stack\.yaml").unwrap()),
        ("Pulumi",      Regex::new(r"Pulumi\.ya?ml|Pulumi\..*\.ya?ml").unwrap()),
        ("CDK",         Regex::new(r"cdk\.json|aws-cdk").unwrap()),
        ("Remix",       Regex::new(r"remix\.config\.(js|ts)|entry\.server\.(ts|tsx)").unwrap()),
        ("Astro",       Regex::new(r"astro\.config\.(mjs|ts)|\.astro$").unwrap()),
        ("Deno",        Regex::new(r"deno\.json[c]?|mod\.ts$|deps\.ts$").unwrap()),
        ("Bun",         Regex::new(r"bun\.lockb|bunfig\.toml").unwrap()),
        ("Nuxt",        Regex::new(r"nuxt\.config\.(js|ts)|\.nuxt/").unwrap()),
        ("SvelteKit",   Regex::new(r"svelte\.config\.(js|ts)|\.svelte-kit/").unwrap()),
        ("Vite",        Regex::new(r"vite\.config\.(js|ts|mjs)").unwrap()),
        ("Tauri",       Regex::new(r"tauri\.conf\.json|src-tauri/").unwrap()),
        ("Electron",    Regex::new(r"electron\.js|electron-builder\.(ya?ml|json)").unwrap()),
    ];
}

// ════════════════════════════════════════════════
// CONTENT-BASED TECH DETECTION (supplements filenames)
// ════════════════════════════════════════════════

lazy_static! {
    static ref TECH_CONTENT_PATTERNS: Vec<(&'static str, Regex)> = vec![
        ("Flask",      Regex::new(r"(?-u)from flask import|import flask\b").unwrap()),
        ("Django",     Regex::new(r"(?-u)from django\b|DJANGO_SETTINGS_MODULE|django\.conf").unwrap()),
        ("FastAPI",    Regex::new(r"(?-u)from fastapi import|import fastapi\b").unwrap()),
        ("Celery",     Regex::new(r"(?-u)from celery import|Celery\(").unwrap()),
        ("SQLAlchemy", Regex::new(r"(?-u)from sqlalchemy|import sqlalchemy").unwrap()),
        ("Express",    Regex::new(r#"require\(['"]express['"]\)|from ['"]express['"]\b"#).unwrap()),
        ("React",      Regex::new(r#"from ['"]react['"]|import React\b"#).unwrap()),
        ("Vue",        Regex::new(r#"from ['"]vue['"]|createApp\(|new Vue\("#).unwrap()),
        ("Angular",    Regex::new(r#"@NgModule\(|@Component\(|from ['"]@angular"#).unwrap()),
        ("NestJS",     Regex::new(r"@Module\(|@Controller\(|@Injectable\(").unwrap()),
        ("Redux",      Regex::new(r"createStore\(|configureStore\(|createSlice\(").unwrap()),
        ("Prisma",     Regex::new(r#"from ['"]@prisma/client['"]|new PrismaClient"#).unwrap()),
        ("GraphQL",    Regex::new(r"gql`|ApolloServer|graphene\.ObjectType|strawberry\.type").unwrap()),
        ("Spring",     Regex::new(r"@SpringBootApplication|import org\.springframework").unwrap()),
        ("Laravel",    Regex::new(r"use Illuminate\\|namespace App\\Http").unwrap()),
        ("Rails",      Regex::new(r#"require ['"]rails['"]|include Rails\b"#).unwrap()),
        ("Remix",      Regex::new(r#"from ['"]@remix-run|createCookieSessionStorage"#).unwrap()),
        ("Astro",      Regex::new(r#"import.*from ['"]astro['"]|---\s*\n.*import"#).unwrap()),
        ("Deno",       Regex::new(r#"Deno\.(serve|readTextFile|env)|from ['"]https://deno\.land"#).unwrap()),
        ("tRPC",       Regex::new(r"initTRPC|createTRPCRouter|t\.procedure").unwrap()),
        ("Supabase",   Regex::new(r"createClient\(.*supabase|@supabase/supabase-js").unwrap()),
        ("Tailwind",   Regex::new(r"tailwindcss|@tailwind\s+(base|components|utilities)").unwrap()),
    ];

    // Regex for entropy-based secret detection (keyword context check).
    // Uses word-boundary anchors to avoid false positives (e.g. "monkey" ≠ "key").
    static ref ENTROPY_CONTEXT_RE: Regex = Regex::new(
        r#"(?i)\b(key|secret|token|password|passwd|pass|auth|credential|api|private)\b"#
    ).unwrap();

    // Captures a quoted value that is at least 20 characters long and uses the
    // base64 / alphanumeric / punctuation character set common to real secrets.
    static ref ENTROPY_VALUE_RE: Regex = Regex::new(
        r#"['"]([A-Za-z0-9+/=_\-\.!@#$%^&*]{20,})['"]"#
    ).unwrap();
}

// ════════════════════════════════════════════════
// DATA STRUCTURES
// ════════════════════════════════════════════════

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub filename:    String,
    pub line:        usize,
    pub pattern_id:  String,
    pub description: String,
    pub severity:    String,
    #[serde(rename = "match")]
    pub match_str:   String,
    pub context:     String,
    pub is_deleted:  bool,
    pub commit_sha1: Option<String>,
    pub confidence_adjustment: Option<String>,
}

impl Finding {
    pub fn to_dict(&self) -> serde_json::Value {
        let (ai_related, ai_category, ai_tags) = ai_metadata_for_finding(self);
        serde_json::json!({
            "file":      self.filename,
            "line":      self.line,
            "type":      self.pattern_id,
            "desc":      self.description,
            "severity":  self.severity,
            "match":     truncate_utf8(&self.match_str, 120),
            "context":   truncate_utf8(&self.context, 200),
            "deleted":   self.is_deleted,
            "blob_sha1": self.commit_sha1,
            "confidence_adjustment": self.confidence_adjustment,
            "ai_related": ai_related,
            "ai_category": ai_category,
            "ai_tags": ai_tags,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Contributor {
    pub name:  String,
    pub email: String,
}

#[derive(Debug, Default)]
pub struct StreamResult {
    pub findings:          Vec<Finding>,
    pub contributors:      Vec<Contributor>,
    pub tech_stack:        Vec<String>,
    pub commit_count:      usize,
    pub blobs_scanned:     usize,
    #[allow(dead_code)]
    pub blobs_failed:      usize,
    pub bytes_scanned:     usize,
    pub elapsed_s:         f64,
    pub files_saved:       usize,
    #[allow(dead_code)]
    pub files_save_failed: usize,
}

impl StreamResult {
    pub fn risk_score(&self) -> u32 {
        let mut critical = 0u32;
        let mut high = 0u32;
        let mut medium = 0u32;
        for f in &self.findings {
            match f.severity.as_str() {
                "CRITICAL" => critical += 1,
                "HIGH"     => high     += 1,
                "MEDIUM"   => medium   += 1,
                _          => {}
            }
        }
        let score = (critical * 20).min(60) + (high * 10).min(30) + (medium * 5).min(15);
        score.min(100)
    }

    pub fn severity_counts(&self) -> HashMap<&'static str, usize> {
        let mut c = HashMap::from([("CRITICAL", 0), ("HIGH", 0), ("MEDIUM", 0), ("LOW", 0)]);
        for f in &self.findings {
            match f.severity.as_str() {
                "CRITICAL" => *c.get_mut("CRITICAL").unwrap() += 1,
                "HIGH"     => *c.get_mut("HIGH").unwrap()     += 1,
                "MEDIUM"   => *c.get_mut("MEDIUM").unwrap()   += 1,
                "LOW"      => *c.get_mut("LOW").unwrap()      += 1,
                _          => {}
            }
        }
        c
    }

    /// Returns one finding per unique `(pattern_id, match_str)` pair.
    /// Useful for deduplicating the same secret found across multiple blobs.
    #[allow(dead_code)]
    pub fn unique_findings(&self) -> Vec<&Finding> {
        let mut seen = HashSet::new();
        self.findings.iter()
            .filter(|f| {
                let key = (f.pattern_id.as_str(), truncate_utf8(&f.match_str, 80));
                seen.insert(key)
            })
            .collect()
    }

    /// Count of unique secrets (may be less than `findings.len()` when the same
    /// secret appears in multiple blobs).
    #[allow(dead_code)]
    pub fn unique_count(&self) -> usize {
        let mut seen = HashSet::new();
        for f in &self.findings {
            seen.insert((f.pattern_id.as_str(), truncate_utf8(&f.match_str, 80)));
        }
        seen.len()
    }
}

// ════════════════════════════════════════════════
// SHARED STATE
// ════════════════════════════════════════════════

#[derive(Default)]
struct State {
    findings:          Vec<Finding>,
    contributors:      HashMap<String, String>,   // email → name
    tech_stack:        HashSet<String>,
    commit_count:      usize,
    blobs_scanned:     usize,
    blobs_failed:      usize,
    bytes_scanned:     usize,
    files_saved:       usize,
    files_save_failed: usize,
}

// Result sent back from each worker task via channel
enum WorkerResult {
    BlobScanned {
        findings:    Vec<Finding>,
        tech:        Vec<String>,
        bytes:       usize,
        save_result: Option<bool>,  // None = not attempted, Some(true) = saved, Some(false) = failed
    },
    BlobFailed,
    CommitProcessed {
        email:    String,
        name:     String,
        findings: Vec<Finding>,
    },
    TreeProcessed {
        file_techs: Vec<(String, String)>,  // (sha1, filename)
    },
    Skipped,
}

// ════════════════════════════════════════════════
// MAIN STREAMER
// ════════════════════════════════════════════════

pub struct Streamer {
    client:           HttpClient,
    workers:          usize,
    mem_limit:        usize,
    verbose:          bool,
    /// Stop after collecting this many findings (0 = unlimited).
    max_findings:     usize,
    /// Stop as soon as the first CRITICAL finding is encountered.
    stop_on_critical: bool,
    /// Runtime-loaded extra patterns (from `--patterns FILE`).
    extra_patterns:   Arc<Vec<DynPattern>>,
    max_blob_size:    usize,   // DX-2: in bytes
    entropy_threshold: f64,   // DX-3
    live:             bool,   // O-1
    adaptive:         bool,   // P-1
    initial_workers:  usize,  // P-1
}

impl Streamer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client:           HttpClient,
        workers:          usize,
        mem_limit_mb:     usize,
        verbose:          bool,
        max_findings:     usize,
        stop_on_critical: bool,
        extra_patterns:   Vec<DynPattern>,
        max_blob_size:    usize,
        entropy_threshold: f64,
        live:             bool,
        adaptive:         bool,
    ) -> Self {
        Self {
            client,
            workers,
            mem_limit: mem_limit_mb * 1024 * 1024,
            verbose,
            max_findings,
            stop_on_critical,
            extra_patterns: Arc::new(extra_patterns),
            max_blob_size: max_blob_size * 1024 * 1024,
            entropy_threshold,
            live,
            adaptive,
            initial_workers: workers,
        }
    }

    pub async fn run(
        &self,
        git_url: &str,
        map_result: &MapResult,
        progress_cb: Option<Arc<dyn Fn(usize, usize) + Send + Sync>>,
        save_dir: Option<PathBuf>,
    ) -> StreamResult {
        let t0 = Instant::now();
        let git_url = git_url.trim_end_matches('/').to_string();

        // Create save directory upfront if --save is active
        if let Some(ref dir) = save_dir {
            let _ = std::fs::create_dir_all(dir);
        }
        let save_dir_arc: Option<Arc<PathBuf>> = save_dir.map(Arc::new);

        // Build sha1→filename lookup and current-blob set upfront
        let mut sha1_to_file: HashMap<String, String> = HashMap::with_capacity(map_result.index_entries.len());
        for entry in &map_result.index_entries {
            sha1_to_file.insert(entry.sha1.clone(), entry.filename.clone());
        }
        let current_blobs = map_result.blob_sha1s.clone();
        let sha1_to_file  = Arc::new(sha1_to_file);
        let current_blobs = Arc::new(current_blobs);

        // Priority: blobs from index first (sensitive), then commit graph
        let mut priority_blobs: Vec<String> = map_result.blob_sha1s.iter().cloned().collect();
        let other_sha1s: Vec<String>        = map_result.commit_sha1s.iter().cloned().collect();

        // Sort: sensitive files first
        priority_blobs.sort_by_key(|sha1| {
            if is_sensitive_file(sha1_to_file.get(sha1).map(|f| f.as_str()).unwrap_or("")) { 0 } else { 1 }
        });

        // Deduplicate — the union of blob + commit sets can overlap after MapResult processing
        let all_sha1s: Vec<String> = {
            let mut seen = HashSet::with_capacity(priority_blobs.len() + other_sha1s.len());
            priority_blobs.into_iter().chain(other_sha1s)
                .filter(|s| seen.insert(s.clone()))
                .collect()
        };
        let total = all_sha1s.len();

        if self.verbose {
            println!(
                "  [*] Streaming {} objects ({} blobs + {} commit/tree graph)...",
                total,
                map_result.blob_sha1s.len(),
                map_result.commit_sha1s.len(),
            );
        }

        let done_counter    = Arc::new(AtomicUsize::new(0));
        let stop_flag       = Arc::new(AtomicBool::new(false));
        let bytes_in_flight = Arc::new(AtomicUsize::new(0));

        let workers      = self.workers;
        let mem_limit    = self.mem_limit;
        let extra_pat    = self.extra_patterns.clone();
        let max_scan_bytes  = self.max_blob_size;
        let entropy_thresh  = self.entropy_threshold;
        let verbose_flag    = self.verbose;

        let stream = futures::stream::iter(all_sha1s)
            .map(|sha1| {
                let client          = self.client.clone();
                let git_url         = git_url.clone();
                let sha1_to_file    = sha1_to_file.clone();
                let current_blobs   = current_blobs.clone();
                let save_dir        = save_dir_arc.clone();
                let extra_patterns  = extra_pat.clone();
                let stop_flag       = stop_flag.clone();
                let bytes_in_flight = bytes_in_flight.clone();
                async move {
                    fetch_and_process(
                        &client, &git_url, &sha1,
                        &sha1_to_file, &current_blobs,
                        save_dir, extra_patterns,
                        stop_flag, mem_limit, bytes_in_flight,
                        max_scan_bytes, entropy_thresh, verbose_flag,
                    ).await
                }
            })
            .buffer_unordered(workers);

        let mut state = State::default();

        // P-1: Adaptive concurrency monitoring
        let current_workers = Arc::new(AtomicUsize::new(self.workers));
        let err_window_count = Arc::new(AtomicUsize::new(0));
        let req_window_count = Arc::new(AtomicUsize::new(0));
        let initial_workers = self.initial_workers;
        let adaptive = self.adaptive;

        if adaptive {
            let cw = current_workers.clone();
            let err_c = err_window_count.clone();
            let req_c = req_window_count.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    let reqs = req_c.swap(0, Ordering::Relaxed);
                    let errs = err_c.swap(0, Ordering::Relaxed);
                    if reqs == 0 { continue; }
                    let err_rate = errs as f64 / reqs as f64;
                    let w = cw.load(Ordering::Relaxed);
                    if err_rate > 0.20 {
                        cw.store(w.saturating_sub(w / 2).max(2), Ordering::Relaxed);
                    } else if err_rate < 0.05 && reqs >= 100 {
                        cw.store((w + 5).min(initial_workers), Ordering::Relaxed);
                    }
                }
            });
        }

        futures::pin_mut!(stream);
        while let Some(result) = stream.next().await {
            let done = done_counter.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(ref cb) = progress_cb {
                cb(done, total);
            }
            // P-1: Track requests/errors for adaptive concurrency
            req_window_count.fetch_add(1, Ordering::Relaxed);
            match result {
                WorkerResult::BlobScanned { findings, tech, bytes, save_result } => {
                    state.blobs_scanned += 1;
                    state.bytes_scanned += bytes;
                    // O-1: Live output
                    if self.live {
                        for f in &findings {
                            println!("{}", serde_json::to_string(&f.to_dict()).unwrap_or_default());
                        }
                    }
                    state.findings.extend(findings);
                    for t in tech {
                        state.tech_stack.insert(t);
                    }
                    match save_result {
                        Some(true)  => state.files_saved       += 1,
                        Some(false) => state.files_save_failed += 1,
                        None        => {}
                    }
                }
                WorkerResult::BlobFailed => {
                    err_window_count.fetch_add(1, Ordering::Relaxed);
                    state.blobs_failed += 1;
                }
                WorkerResult::CommitProcessed { email, name, findings } => {
                    state.commit_count += 1;
                    // O-1: Live output for commit findings too
                    if self.live {
                        for f in &findings {
                            println!("{}", serde_json::to_string(&f.to_dict()).unwrap_or_default());
                        }
                    }
                    state.findings.extend(findings);
                    if !email.is_empty() {
                        state.contributors.entry(email).or_insert(name);
                    }
                }
                WorkerResult::TreeProcessed { file_techs } => {
                    for (_sha1, filename) in file_techs {
                        detect_tech(&filename, &mut state.tech_stack);
                    }
                }
                WorkerResult::Skipped => {}
            }

            // Check early-stop conditions
            let hit_limit    = self.max_findings > 0 && state.findings.len() >= self.max_findings;
            let hit_critical = self.stop_on_critical
                && state.findings.iter().rev().take(20).any(|f| f.severity == "CRITICAL");
            if hit_limit || hit_critical {
                stop_flag.store(true, Ordering::Relaxed);
                if self.verbose {
                    if hit_limit {
                        println!("\n  [!] Reached --max-findings limit ({}). Stopping scan.", self.max_findings);
                    } else {
                        println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                    }
                }
                break;
            }
        }

        let elapsed = t0.elapsed().as_secs_f64();
        let mut ts: Vec<_> = state.tech_stack.iter().cloned().collect();
        ts.sort();

        StreamResult {
            findings:          state.findings,
            contributors:      state.contributors.iter()
                                 .map(|(email, name)| Contributor { name: name.clone(), email: email.clone() })
                                 .collect(),
            tech_stack:        ts,
            commit_count:      state.commit_count,
            blobs_scanned:     state.blobs_scanned,
            blobs_failed:      state.blobs_failed,
            bytes_scanned:     state.bytes_scanned,
            elapsed_s:         elapsed,
            files_saved:       state.files_saved,
            files_save_failed: state.files_save_failed,
        }
    }
}

// ════════════════════════════════════════════════
// PER-SHA1 PROCESSING (async, lock-free)
// ════════════════════════════════════════════════

/// Max blob content size to scan (4 MB). Larger blobs are skipped.
#[allow(dead_code)]
const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;

#[allow(clippy::too_many_arguments)]
async fn fetch_and_process(
    client:          &HttpClient,
    git_url:         &str,
    sha1:            &str,
    sha1_to_file:    &HashMap<String, String>,
    current_blobs:   &HashSet<String>,
    save_dir:        Option<Arc<PathBuf>>,
    extra_patterns:  Arc<Vec<DynPattern>>,
    stop_flag:       Arc<AtomicBool>,
    mem_limit:       usize,
    bytes_in_flight: Arc<AtomicUsize>,
    max_scan_bytes:  usize,
    entropy_threshold: f64,
    verbose:         bool,
) -> WorkerResult {
    // Bail immediately if a stop condition was already triggered
    if stop_flag.load(Ordering::Relaxed) {
        return WorkerResult::Skipped;
    }

    let url  = format!("{}/{}", git_url, obj_path(sha1));
    let resp = client.get(&url).await;

    if !resp.ok() {
        // 404 → loose object simply not present (expected for pack-only repos); not a failure
        if resp.status == 404 {
            return WorkerResult::Skipped;
        }
        return WorkerResult::BlobFailed;
    }

    let parser = ObjectParser;
    let obj = match parser.parse(&resp.body, sha1) {
        Some(o) => o,
        None    => return WorkerResult::Skipped,
    };

    let raw_bytes = resp.body.len();

    match obj.obj_type.as_str() {
        "blob" => {
            // Persist blob to disk first, before any scan-skip guards, so that
            // --save writes all blobs regardless of whether they are scannable
            // (binary files, oversized blobs, memory-budget overflow, etc.).
            let save_result = if let Some(ref dir) = save_dir {
                if let Some(actual_name) = sha1_to_file.get(sha1) {
                    Some(write_blob_to_disk(actual_name, &obj.data, dir))
                } else {
                    None
                }
            } else {
                None
            };

            let filename   = sha1_to_file.get(sha1)
                .cloned()
                .unwrap_or_else(|| format!("[blob:{}]", &sha1[..sha1.len().min(8)]));
            let is_deleted = !current_blobs.contains(sha1);

            // Fast binary detection: check first 8 KB for null bytes
            let probe      = &obj.data[..obj.data.len().min(8192)];
            let null_count = probe.iter().filter(|&&b| b == 0).count();
            if null_count > 10 {
                // S-3: Check for SQLite or ZIP before skipping
                if obj.data.starts_with(b"SQLite format 3\0") {
                    let strings = extract_printable_strings(&obj.data, 6);
                    let text = strings.join("\n");
                    let findings = scan_content(&text, &filename, sha1, is_deleted, &extra_patterns, entropy_threshold);
                    return WorkerResult::BlobScanned { findings, tech: vec![], bytes: raw_bytes, save_result };
                }
                if obj.data.starts_with(b"PK\x03\x04") {
                    // TODO: Add zip crate dependency for full ZIP scanning
                    return WorkerResult::BlobScanned { findings: vec![], tech: vec![], bytes: raw_bytes, save_result };
                }
                return WorkerResult::BlobScanned {
                    findings: vec![], tech: vec![], bytes: raw_bytes, save_result,
                };
            }

            // Skip blobs that exceed the per-blob scan size limit
            let blob_size      = obj.data.len();
            let per_blob_limit = if mem_limit > 0 {
                // At most a quarter of the total memory budget per individual blob
                (mem_limit / 4).min(max_scan_bytes)
            } else {
                max_scan_bytes
            };
            if blob_size > per_blob_limit {
                if verbose {
                    let blob_size_mb = blob_size as f64 / 1024.0 / 1024.0;
                    let max_size_mb = max_scan_bytes as f64 / 1024.0 / 1024.0;
                    eprintln!("  [!] Blob {} ({:.2} MB) exceeds --max-blob-size {:.0}MB, skipping scan", &sha1[..8], blob_size_mb, max_size_mb);
                }
                return WorkerResult::BlobScanned {
                    findings: vec![], tech: vec![], bytes: raw_bytes, save_result,
                };
            }

            // Track in-flight bytes for overall memory budget enforcement
            if mem_limit > 0 {
                let prev = bytes_in_flight.fetch_add(blob_size, Ordering::Relaxed);
                if prev + blob_size > mem_limit {
                    bytes_in_flight.fetch_sub(blob_size, Ordering::Relaxed);
                    return WorkerResult::BlobScanned {
                        findings: vec![], tech: vec![], bytes: raw_bytes, save_result,
                    };
                }
            }

            // Collect tech tags from filename
            let mut tech_set: HashSet<String> = HashSet::new();
            {
                let mut v = Vec::new();
                collect_tech(&filename, &mut v);
                tech_set.extend(v);
            }

            let content = match std::str::from_utf8(&obj.data) {
                Ok(s)  => s.to_string(),
                Err(_) => String::from_utf8_lossy(&obj.data).into_owned(),
            };

            // Supplement with content-based tech detection
            detect_tech_from_content(&content, &mut tech_set);
            let tech: Vec<String> = tech_set.into_iter().collect();

            // Primary line-by-line scan (patterns + entropy)
            let mut findings = scan_content(&content, &filename, sha1, is_deleted, &extra_patterns, entropy_threshold);

            // Multi-line YAML next-line secret detection
            findings.extend(scan_yaml_nextline_secrets(&content, &filename, sha1, is_deleted));

            // S-4: DB credential detection
            findings.extend(scan_db_config_blocks(&content, &filename, sha1, is_deleted));

            // Release in-flight budget
            if mem_limit > 0 {
                bytes_in_flight.fetch_sub(blob_size, Ordering::Relaxed);
            }

            WorkerResult::BlobScanned { findings, tech, bytes: raw_bytes, save_result }
        }
        "commit" => {
            if let Some(commit) = parser.parse_commit(&obj) {
                // Scan commit message for secrets (trufflehog/gitleaks parity)
                let msg_findings = if !commit.message.is_empty() {
                    scan_content(
                        &commit.message,
                        &format!("[commit:{}:message]", &sha1[..sha1.len().min(8)]),
                        sha1,
                        false,
                        &extra_patterns,
                        entropy_threshold,
                    )
                } else {
                    vec![]
                };
                WorkerResult::CommitProcessed {
                    email:    commit.author_email,
                    name:     commit.author,
                    findings: msg_findings,
                }
            } else {
                WorkerResult::Skipped
            }
        }
        "tree" => {
            let entries = parser.parse_tree(&obj);
            let file_techs: Vec<(String, String)> = entries.into_iter()
                .filter(|e| e.is_blob())
                .map(|e| (e.sha1, e.name))
                .collect();
            WorkerResult::TreeProcessed { file_techs }
        }
        _ => WorkerResult::Skipped,
    }
}

fn scan_content(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    extra_patterns: &[DynPattern],
    entropy_threshold: f64,
) -> Vec<Finding> {
    let lines: Vec<&str> = content.lines().collect();
    let mut findings     = Vec::new();
    let is_js            = is_js_file(filename);
    if let Some(path_finding) = ai_path_finding(filename, sha1, is_deleted) {
        findings.push(path_finding);
    }

    for (lineno, &line) in lines.iter().enumerate() {
        if line.len() > 2000 {
            // For minified JS/TS try scanning segments split at statement boundaries
            if is_js && line.len() <= 50_000 {
                scan_minified_segments(line, lineno, filename, sha1, is_deleted, &mut findings);
            }
            continue;
        }

        let mut line_has_finding = false;

        // Static patterns
        for pat in PATTERNS.iter() {
            for m in pat.regex.find_iter(line) {
                let val = m.as_str().to_string();
                if is_placeholder(&val) { continue; }
                findings.push(Finding {
                    filename:    filename.to_string(),
                    line:        lineno + 1,
                    pattern_id:  pat.id.to_string(),
                    description: pat.desc.to_string(),
                    severity:    pat.sev.to_string(),
                    match_str:   val,
                    context:     build_context_window(&lines, lineno, 2),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                });
                line_has_finding = true;
            }
        }

        // Runtime / custom patterns
        for pat in extra_patterns.iter() {
            for m in pat.regex.find_iter(line) {
                let val = m.as_str().to_string();
                if is_placeholder(&val) { continue; }
                findings.push(Finding {
                    filename:    filename.to_string(),
                    line:        lineno + 1,
                    pattern_id:  pat.id.clone(),
                    description: pat.desc.clone(),
                    severity:    pat.sev.clone(),
                    match_str:   val,
                    context:     build_context_window(&lines, lineno, 2),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                });
                line_has_finding = true;
            }
        }

        // Shannon-entropy scan — only fires when no specific pattern matched the line
        // (avoids redundant/noisy entries for already-identified secrets)
        if !line_has_finding {
            scan_entropy_line(line, lineno, filename, sha1, is_deleted, &lines, &mut findings, entropy_threshold);
        }
    }

    // S-1: Context-aware confidence adjustment
    for f in findings.iter_mut() {
        let lines_ref: Vec<&str> = content.lines().collect();
        if let Some(reason) = context_suggests_example(&lines_ref, f.line.saturating_sub(1)) {
            f.severity = downgrade_severity(&f.severity).to_string();
            f.confidence_adjustment = Some(reason);
        }
    }

    // S-2: Multi-line scan
    findings.extend(scan_multiline(content, filename, sha1, is_deleted));

    findings
}

// ════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════

/// Write blob data to disk under `output_dir`, reconstructing directory structure.
/// Sanitises the path to prevent path-traversal (rejects `..` and absolute components).
/// Returns true if the file was written successfully.
fn write_blob_to_disk(filename: &str, data: &[u8], output_dir: &Path) -> bool {
    let normalized = filename.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".." && *p != ".")
        .collect();
    if parts.is_empty() {
        return false;
    }
    let local_path: PathBuf = parts.iter().fold(output_dir.to_path_buf(), |acc, p| acc.join(p));
    // Defense in depth: verify the joined path is still rooted inside output_dir
    if !local_path.starts_with(output_dir) {
        return false;
    }
    if let Some(parent) = local_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&local_path, data).is_ok()
}

/// Collect matching tech stack entries into a Vec (lock-free variant for worker tasks).
fn collect_tech(filename: &str, out: &mut Vec<String>) {
    for (tech, rx) in TECH_PATTERNS.iter() {
        if rx.is_match(filename) {
            out.push(tech.to_string());
        }
    }
}

/// Mutate a HashSet directly (used by the aggregator after receiving results).
fn detect_tech(filename: &str, stack: &mut HashSet<String>) {
    for (tech, rx) in TECH_PATTERNS.iter() {
        if rx.is_match(filename) {
            stack.insert(tech.to_string());
        }
    }
}

fn is_sensitive_file(filename: &str) -> bool {
    SENSITIVE_NAMES.is_match(filename) || classify_ai_path(filename).is_some()
}

fn is_placeholder(s: &str) -> bool {
    PLACEHOLDERS.iter().any(|p| s.contains(p))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AiPathCategory {
    Config,
    PromptHistory,
    State,
    Credential,
}

impl AiPathCategory {
    fn pattern_id(self) -> &'static str {
        match self {
            Self::Config => "ai_path_config",
            Self::PromptHistory => "ai_path_prompt_history",
            Self::State => "ai_path_state",
            Self::Credential => "ai_path_credential",
        }
    }
    fn description(self) -> &'static str {
        match self {
            Self::Config => "AI configuration path exposed",
            Self::PromptHistory => "AI prompt/history path exposed",
            Self::State => "AI runtime state/session path exposed",
            Self::Credential => "AI credential/token path exposed",
        }
    }
    fn severity(self) -> &'static str {
        match self {
            Self::Credential => "HIGH",
            Self::Config | Self::PromptHistory => "MEDIUM",
            Self::State => "LOW",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Config => "config_path",
            Self::PromptHistory => "prompt_history_path",
            Self::State => "state_path",
            Self::Credential => "credential_path",
        }
    }
}

fn ai_ecosystem_tags(path_lc: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    if path_lc.contains(".claude/") || path_lc.starts_with(".claude/") { out.push("claude"); }
    if path_lc.contains(".cursor/") || path_lc.starts_with(".cursor/") { out.push("cursor"); }
    if path_lc.contains(".continue/") || path_lc.starts_with(".continue/") { out.push("continue"); }
    if path_lc.contains(".aider") || path_lc.contains("/aider") { out.push("aider"); }
    if path_lc.contains(".windsurf/") || path_lc.starts_with(".windsurf/") { out.push("windsurf"); }
    if path_lc.contains("copilot") || path_lc.contains(".github/prompts") { out.push("copilot"); }
    out
}

fn classify_ai_path(path: &str) -> Option<AiPathCategory> {
    let p = path.replace('\\', "/").to_lowercase();
    let ai_scope = p.contains("/.claude/") || p.starts_with(".claude/")
        || p.contains("/.cursor/") || p.starts_with(".cursor/")
        || p.contains("/.continue/") || p.starts_with(".continue/")
        || p.contains(".aider")
        || p.contains("/.windsurf/") || p.starts_with(".windsurf/")
        || p.contains(".github/copilot")
        || p.contains(".github/prompts")
        || p.contains("/copilot-instructions.md")
        || p.ends_with("/copilot-instructions.md");
    if !ai_scope {
        return None;
    }

    if p.contains("credential") || p.contains("secret") || p.contains("token")
        || p.contains("api_key") || p.contains("apikey")
        || p.ends_with(".env") || p.contains(".env.")
    {
        return Some(AiPathCategory::Credential);
    }
    if p.contains("prompt") || p.contains("history") || p.contains("chat")
        || p.contains("conversation")
    {
        return Some(AiPathCategory::PromptHistory);
    }
    if p.contains("cache") || p.contains("state") || p.contains("session")
        || p.contains("workspace")
    {
        return Some(AiPathCategory::State);
    }
    Some(AiPathCategory::Config)
}

fn ai_path_finding(path: &str, sha1: &str, is_deleted: bool) -> Option<Finding> {
    let category = classify_ai_path(path)?;
    Some(Finding {
        filename: path.to_string(),
        line: 1,
        pattern_id: category.pattern_id().to_string(),
        description: category.description().to_string(),
        severity: category.severity().to_string(),
        match_str: path.to_string(),
        context: format!("ai_path_category={}", category.label()),
        is_deleted,
        commit_sha1: if sha1.is_empty() { None } else { Some(sha1.to_string()) },
        confidence_adjustment: None,
    })
}

fn ai_provider_tag_from_pattern(pattern_id: &str) -> Option<&'static str> {
    if pattern_id.starts_with("openai") { return Some("openai"); }
    if pattern_id.starts_with("anthropic") { return Some("anthropic"); }
    if pattern_id.starts_with("huggingface") { return Some("huggingface"); }
    if pattern_id.starts_with("cohere") { return Some("cohere"); }
    if pattern_id.starts_with("openrouter") { return Some("openrouter"); }
    if pattern_id == "ai_provider_env_key" { return Some("multi_provider"); }
    if pattern_id.starts_with("groq") { return Some("groq"); }
    None
}

pub fn ai_metadata_for_finding(f: &Finding) -> (bool, Option<String>, Vec<String>) {
    if let Some(provider) = ai_provider_tag_from_pattern(&f.pattern_id) {
        return (
            true,
            Some("provider_key".to_string()),
            vec!["ai".to_string(), "key_material".to_string(), provider.to_string()],
        );
    }

    let path_cat = if let Some(rest) = f.pattern_id.strip_prefix("ai_path_") {
        Some(rest.to_string())
    } else {
        classify_ai_path(&f.filename).map(|c| c.label().to_string())
    };

    if let Some(category) = path_cat {
        let mut tags = vec!["ai".to_string(), "path".to_string()];
        tags.push(category.clone());
        let path_lc = f.filename.to_lowercase();
        for tag in ai_ecosystem_tags(&path_lc) {
            tags.push(tag.to_string());
        }
        return (true, Some(category), tags);
    }

    (false, None, Vec::new())
}

// ── New helpers ────────────────────────────────────────────────

/// Returns true for JavaScript / TypeScript file extensions where minified lines are common.
fn is_js_file(filename: &str) -> bool {
    matches!(
        filename.rsplit('.').next().unwrap_or(""),
        "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs"
    )
}

/// Compute the Shannon entropy (bits per character) of `s`.
/// Returns 0.0 for strings shorter than 4 characters.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.len() < 4 { return 0.0; }
    let len = s.len() as f64;
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| { let p = c as f64 / len; -p * p.log2() })
        .sum()
}

/// Attempt to detect secrets in a minified JS/TS line by splitting at common
/// statement-level separators and scanning each resulting segment.
/// Limits processing to the first 200 segments to bound worst-case latency.
fn scan_minified_segments(
    line:       &str,
    lineno:     usize,
    filename:   &str,
    sha1:       &str,
    is_deleted: bool,
    out:        &mut Vec<Finding>,
) {
    for segment in line.split([';', '{', '}', ',']).take(200) {
        let seg = segment.trim();
        if seg.is_empty() || seg.len() > 2000 || seg.len() < 10 { continue; }
        for pat in PATTERNS.iter() {
            for m in pat.regex.find_iter(seg) {
                let val = m.as_str().to_string();
                if is_placeholder(&val) { continue; }
                out.push(Finding {
                    filename:    filename.to_string(),
                    line:        lineno + 1,
                    pattern_id:  pat.id.to_string(),
                    description: pat.desc.to_string(),
                    severity:    pat.sev.to_string(),
                    match_str:   val,
                    context:     format!("[minified] {}", truncate_utf8(seg, 200)),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                });
            }
        }
    }
}

/// Build a context string from lines surrounding `center` (within `radius` lines).
/// Lines are joined with ` | ` after trimming whitespace.
fn build_context_window(lines: &[&str], center: usize, radius: usize) -> String {
    let start = center.saturating_sub(radius);
    let end   = (center + radius + 1).min(lines.len());
    lines[start..end]
        .iter()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Shannon-entropy based secret scan for a single line.
/// Only fires when ENTROPY_CONTEXT_RE matches the line (keyword context),
/// to keep the false-positive rate low.
#[allow(clippy::too_many_arguments)]
fn scan_entropy_line(
    line:       &str,
    lineno:     usize,
    filename:   &str,
    sha1:       &str,
    is_deleted: bool,
    all_lines:  &[&str],
    out:        &mut Vec<Finding>,
    threshold:  f64,
) {
    if !ENTROPY_CONTEXT_RE.is_match(line) { return; }

    for m in ENTROPY_VALUE_RE.find_iter(line) {
        let quoted = m.as_str();
        // Strip the enclosing quotes
        let inner = &quoted[1..quoted.len() - 1];
        if is_placeholder(inner) { continue; }
        let ent = shannon_entropy(inner);
        if ent < threshold { continue; }
        out.push(Finding {
            filename:    filename.to_string(),
            line:        lineno + 1,
            pattern_id:  "high_entropy_secret".to_string(),
            description: format!("High-entropy secret ({:.2} bits/char)", ent),
            severity:    "HIGH".to_string(),
            match_str:   inner.to_string(),
            context:     build_context_window(all_lines, lineno, 2),
            is_deleted,
            commit_sha1: Some(sha1.to_string()),
            confidence_adjustment: None,
        });
    }
}

/// Detect secrets where the value appears on the line *following* a bare YAML key
/// (no inline value), e.g.:
/// ```yaml
/// db_password:
///   actual_secret_value
/// ```
fn scan_yaml_nextline_secrets(
    content:    &str,
    filename:   &str,
    sha1:       &str,
    is_deleted: bool,
) -> Vec<Finding> {
    lazy_static! {
        static ref YAML_KEY_ONLY: Regex = Regex::new(
            r#"(?i)^\s*(password|db_pass|secret|api_key|api_secret|access_token|auth_token|private_key|signing_key|encryption_key|jwt_secret|client_secret)\s*:\s*$"#
        ).unwrap();
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();

    for (i, &line) in lines.iter().enumerate() {
        if !YAML_KEY_ONLY.is_match(line) { continue; }
        let Some(&next_line) = lines.get(i + 1) else { continue };
        let value = next_line.trim();
        if value.is_empty() || value.starts_with('#') { continue; }
        if value.len() < 8 { continue; }
        if is_placeholder(value) { continue; }
        if shannon_entropy(value) < 2.5 { continue; }
        findings.push(Finding {
            filename:    filename.to_string(),
            line:        i + 2,  // value is on line i+1 (1-indexed = i+2)
            pattern_id:  "yaml_nextline_secret".to_string(),
            description: "Secret value on line following YAML key".to_string(),
            severity:    "HIGH".to_string(),
            match_str:   value.to_string(),
            context:     format!("{} | {}", line.trim(), value),
            is_deleted,
            commit_sha1: Some(sha1.to_string()),
            confidence_adjustment: None,
        });
    }
    findings
}

/// Supplement the filename-based tech stack with content-based signals.
fn detect_tech_from_content(content: &str, stack: &mut HashSet<String>) {
    for (tech, rx) in TECH_CONTENT_PATTERNS.iter() {
        if rx.is_match(content) {
            stack.insert(tech.to_string());
        }
    }
}

// S-1: Context-aware confidence adjustment helper functions
fn context_suggests_example(lines: &[&str], center: usize) -> Option<String> {
    let start = center.saturating_sub(3);
    let end = (center + 4).min(lines.len());
    let window = lines[start..end].join(" ");
    let has_comment = window.contains("# ") || window.contains("// ")
        || window.contains("/* ") || window.contains("-- ");
    lazy_static! {
        static ref EXAMPLE_KEYWORDS: Regex = Regex::new(
            r"(?i)\b(example|sample|demo|test|placeholder|fake|mock|dummy|your_|changeme|foobar)\b"
        ).unwrap();
    }
    let has_example = EXAMPLE_KEYWORDS.is_match(&window);
    if has_comment && has_example {
        Some("context: comment+example".to_string())
    } else if has_example {
        Some("context: example keyword".to_string())
    } else {
        None
    }
}

fn downgrade_severity(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => "HIGH",
        "HIGH"     => "MEDIUM",
        "MEDIUM"   => "LOW",
        _          => "LOW",
    }
}

// S-2: Multi-line pattern scanning
fn scan_multiline(content: &str, filename: &str, sha1: &str, is_deleted: bool) -> Vec<Finding> {
    lazy_static! {
        static ref PEM_MULTILINE: Regex = Regex::new(
            r"(?s)-----BEGIN [A-Z ]+PRIVATE KEY-----[^-]*-----END [A-Z ]+PRIVATE KEY-----"
        ).unwrap();
        static ref JSON_MULTILINE_SECRET: Regex = Regex::new(
            r#"(?si)"(password|passwd|secret|api_key|access_token|private_key|client_secret)"\s*:\s*"([^"]{8,})""#
        ).unwrap();
    }
    let mut findings = Vec::new();
    for m in PEM_MULTILINE.find_iter(content) {
        let val = m.as_str().to_string();
        if !is_placeholder(&val) {
            let line_no = content[..m.start()].lines().count() + 1;
            findings.push(Finding {
                filename: filename.to_string(),
                line: line_no,
                pattern_id: "pem_key_multiline".to_string(),
                description: "PEM Private Key (multi-line)".to_string(),
                severity: "CRITICAL".to_string(),
                match_str: truncate_utf8(&val, 100).to_string(),
                context: "multi-line PEM block".to_string(),
                is_deleted,
                commit_sha1: Some(sha1.to_string()),
                confidence_adjustment: None,
            });
        }
    }
    for cap in JSON_MULTILINE_SECRET.captures_iter(content) {
        if let Some(val) = cap.get(2) {
            let v = val.as_str();
            if !is_placeholder(v) {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                findings.push(Finding {
                    filename: filename.to_string(),
                    line: line_no,
                    pattern_id: "json_nested_secret".to_string(),
                    description: format!("JSON secret: {}", cap.get(1).unwrap().as_str()),
                    severity: "HIGH".to_string(),
                    match_str: truncate_utf8(v, 100).to_string(),
                    context: "multi-line JSON".to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                });
            }
        }
    }
    findings
}

// ════════════════════════════════════════════════
// PUBLIC SCAN API (used by --token mode)
// ════════════════════════════════════════════════

/// Scan arbitrary text content for secrets using all built-in patterns plus
/// any caller-supplied extra patterns.
///
/// * `text`              — UTF-8 content to scan
/// * `source`            — file path / label used in the returned [`Finding`]s
/// * `dyn_patterns`      — additional runtime-loaded patterns (from `--patterns`)
/// * `entropy_threshold` — minimum Shannon entropy for the high-entropy scanner
///   (pass `4.5` for the default)
///
/// All findings returned have `is_deleted = false` and `commit_sha1 = None`
/// because there is no Git object SHA in this context.
pub fn scan_text(
    text:              &str,
    source:            &str,
    dyn_patterns:      &[DynPattern],
    entropy_threshold: f64,
) -> Vec<Finding> {
    let mut findings = scan_content(text, source, "", false, dyn_patterns, entropy_threshold);
    findings.extend(scan_yaml_nextline_secrets(text, source, "", false));
    findings.extend(scan_db_config_blocks(text, source, "", false));
    findings
}

// S-3: Binary file string extraction
fn extract_printable_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();
    for &b in data {
        if (0x20..0x7f).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = std::str::from_utf8(&current) {
                    result.push(s.to_string());
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        if let Ok(s) = std::str::from_utf8(&current) {
            result.push(s.to_string());
        }
    }
    result
}

// S-4: Database credential detection
fn scan_db_config_blocks(content: &str, filename: &str, sha1: &str, is_deleted: bool) -> Vec<Finding> {
    lazy_static! {
        static ref DJANGO_DB: Regex = Regex::new(
            r#"(?si)'PASSWORD'\s*:\s*'([^']{6,})'"#
        ).unwrap();
        static ref DB_URL_PASS: Regex = Regex::new(
            r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:([^@]+)@"
        ).unwrap();
    }
    let mut findings = Vec::new();
    for cap in DJANGO_DB.captures_iter(content) {
        if let Some(val) = cap.get(1) {
            let v = val.as_str();
            if !is_placeholder(v) {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                findings.push(Finding {
                    filename: filename.to_string(),
                    line: line_no,
                    pattern_id: "django_db_password".to_string(),
                    description: "Django/Python database password".to_string(),
                    severity: "HIGH".to_string(),
                    match_str: truncate_utf8(v, 100).to_string(),
                    context: "DB config block".to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                });
            }
        }
    }
    for cap in DB_URL_PASS.captures_iter(content) {
        if let Some(val) = cap.get(2) {
            let v = val.as_str();
            if !is_placeholder(v) {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                findings.push(Finding {
                    filename: filename.to_string(),
                    line: line_no,
                    pattern_id: "db_url_password".to_string(),
                    description: "Database connection string with password".to_string(),
                    severity: "HIGH".to_string(),
                    match_str: truncate_utf8(v, 100).to_string(),
                    context: "DB connection URL".to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_placeholder() {
        assert!(is_placeholder("your_api_key_here"));
        assert!(is_placeholder("AKIAIOSFODNN7EXAMPLE"));
        assert!(!is_placeholder("AKIAIOSFODNN7REAL_SECRET"));
    }

    #[test]
    fn test_binary_detection_byte_level() {
        // A byte slice with >10 null bytes in the first 8 KB should be treated as binary
        let binary: Vec<u8> = (0u8..20).flat_map(|_| vec![b'A', 0u8]).collect();
        let probe = &binary[..binary.len().min(8192)];
        let null_count = probe.iter().filter(|&&b| b == 0).count();
        assert!(null_count > 10, "Should detect binary data");

        // Normal text should not exceed the threshold
        let text = b"hello world, this is a test file with no null bytes";
        let probe = &text[..text.len().min(8192)];
        let null_count = probe.iter().filter(|&&b| b == 0).count();
        assert!(null_count <= 10, "Plain text should not be detected as binary");
    }

    #[test]
    fn test_scan_content_finds_aws_key() {
        // AKIA + exactly 16 uppercase/digit chars, no placeholder substrings
        let content = "AWS_KEY=AKIAZ9XYZMNOP1234567";
        let findings = scan_content(content, "config.sh", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "aws_key_id"),
            "Should detect AWS key ID pattern"
        );
    }

    #[test]
    fn test_scan_content_skips_long_lines() {
        let long_line = "A".repeat(2001);
        let findings = scan_content(&long_line, "file.txt", "a".repeat(40).as_str(), false, &[], 4.5);
        // Long lines should be skipped — no findings
        assert!(findings.is_empty(), "Lines >2000 chars should be skipped");
    }

    #[test]
    fn test_scan_content_finds_wp_define_credential() {
        let content = r#"define('DB_PASSWORD', 'supersecret123');"#;
        let findings = scan_content(content, "wp-config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "wp_define"),
            "Should detect WordPress define() credential"
        );
    }

    #[test]
    fn test_scan_content_wp_define_placeholder_is_filtered() {
        // "put your unique phrase here" is a WordPress wp-config-sample.php placeholder.
        // After adding "put " to PLACEHOLDERS, this should NOT produce a finding.
        let content = r#"define( 'AUTH_KEY', 'put your unique phrase here' );"#;
        let findings = scan_content(content, "wp-config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "wp_define"),
            "WordPress AUTH_KEY with placeholder value 'put your unique phrase here' must be filtered"
        );
    }

    #[test]
    fn test_scan_content_finds_php_define_aws_key() {
        let content = r#"define('AWS_KEY', 'CQITEE7X4TT318J00PWC');"#;
        let findings = scan_content(content, "config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should detect define() with AWS_KEY"
        );
    }

    #[test]
    fn test_scan_content_finds_php_define_aws_secret_key() {
        let content = r#"define('AWS_SECRET_KEY', 'GmZvCzpcTTczGfApjlhoycln0SzNGCoQEbJtbUPa');"#;
        let findings = scan_content(content, "config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should detect define() with AWS_SECRET_KEY"
        );
    }

    #[test]
    fn test_scan_content_finds_php_define_auth_token_secret() {
        let content = r#"define('AUTH_TOKEN_SECRET', 'jq6uik0LxAPCUBIHlHk3usBEZ8pJf9t9');"#;
        let findings = scan_content(content, "config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should detect define() with AUTH_TOKEN_SECRET"
        );
    }

    #[test]
    fn test_scan_content_php_define_ignores_non_secret_keys() {
        // BUCKET_NAME and ENDPOINT don't contain secret-related keywords
        let content = r#"define('BUCKET_NAME', 'developer-request');"#;
        let findings = scan_content(content, "config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should NOT detect define() with non-secret key name BUCKET_NAME"
        );
    }

    #[test]
    fn test_scan_content_php_define_ignores_short_values() {
        let content = r#"define('API_KEY', 'short');"#;
        let findings = scan_content(content, "config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should NOT detect define() with value shorter than 8 chars"
        );
    }

    #[test]
    fn test_scan_content_php_define_placeholder_is_filtered() {
        let content = r#"define('API_KEY', 'your_api_key_here_placeholder');"#;
        let findings = scan_content(content, "config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Placeholder value in define() should be filtered"
        );
    }

    #[test]
    fn test_scan_content_finds_django_secret_key() {
        let content = r#"SECRET_KEY = 'django-insecure-abcdefghijklmnopqrstuvwxyz1234567890!@#'"#;
        let findings = scan_content(content, "settings.py", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "django_secret"),
            "Should detect Django SECRET_KEY"
        );
    }

    #[test]
    fn test_scan_content_finds_google_api_key() {
        // AIza + exactly 35 alphanumeric/dash/underscore chars
        let content = "GOOGLE_KEY=AIzaSyC1234567890abcdefghijklmnop123456";
        let findings = scan_content(content, "config.js", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "gcp_api_key"),
            "Should detect Google/GCP API Key"
        );
    }

    #[test]
    fn test_scan_content_finds_laravel_app_key() {
        let content = "APP_KEY=base64:SomeBase64EncodedKeyHereThatIsLongEnoughToMatch==";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "laravel_app_key"),
            "Should detect Laravel APP_KEY"
        );
    }

    #[test]
    fn test_no_private_ip_false_positive() {
        // Private IPs no longer trigger any finding
        let content = "db_host = 192.168.1.100";
        let findings = scan_content(content, "config.ini", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "private_ip"),
            "Private IP should not be flagged"
        );
    }

    #[test]
    fn test_no_s3_url_false_positive() {
        // S3 URLs no longer trigger a MEDIUM finding
        let content = "endpoint = https://mybucket.s3.amazonaws.com";
        let findings = scan_content(content, "config.ini", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "s3_url"),
            "S3 URL should not be flagged"
        );
    }

    #[test]
    fn test_no_entropy_medium_finding() {
        // Entropy check is removed; quoted high-entropy strings should not produce MEDIUM findings
        let content = r#"some_field = "R2l0UmVjb25Jc0F3ZXNvbWVUb29sRm9yU2VjdXJpdHk=""#;
        let findings = scan_content(content, "file.txt", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.severity == "MEDIUM"),
            "Entropy check should not produce MEDIUM findings"
        );
    }

    #[test]
    fn test_write_blob_to_disk_sanitises_path_traversal() {
        let dir = std::env::temp_dir().join("gitrecon_test_write");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Path-traversal attempt: `..` components are stripped so the path is
        // sanitised to stay inside `dir` (e.g. dir/etc/passwd).
        let result = write_blob_to_disk("../../etc/passwd", b"test_gitrecon", &dir);
        if result {
            // The sanitised path must land inside `dir`
            let sanitised = dir.join("etc").join("passwd");
            assert!(sanitised.exists(), "Sanitised file must be inside the output directory");
            // The real /etc/passwd must not have been modified
            if std::path::Path::new("/etc/passwd").exists() {
                let content = std::fs::read("/etc/passwd").unwrap_or_default();
                assert_ne!(content, b"test_gitrecon", "Must not overwrite /etc/passwd");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_blob_to_disk_creates_subdirs() {
        let dir = std::env::temp_dir().join("gitrecon_test_subdirs");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ok = write_blob_to_disk("sub/dir/file.txt", b"hello", &dir);
        assert!(ok, "Should write successfully");
        assert!(dir.join("sub/dir/file.txt").exists(), "Should create sub-directories");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_blob_to_disk_saves_binary_blob() {
        // Regression test: binary blobs (with many null bytes) must be saved to
        // disk when --save is active, even though they are skipped for scanning.
        let dir = std::env::temp_dir().join("gitrecon_test_binary_save");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Construct data that would trigger the null-byte binary check (>10 nulls)
        let mut binary_data = vec![0u8; 20];
        binary_data.extend_from_slice(b"some extra bytes");
        let ok = write_blob_to_disk("image.png", &binary_data, &dir);
        assert!(ok, "Binary blob should be saved to disk even when skipped for scanning");
        assert!(dir.join("image.png").exists(), "Binary blob file must exist on disk");
        let saved = std::fs::read(dir.join("image.png")).unwrap();
        assert_eq!(saved, binary_data, "Saved binary content must match original");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_blob_to_disk_saves_oversized_blob() {
        // Regression test: blobs larger than MAX_SCAN_BYTES must be saved to disk
        // when --save is active, even though they are skipped for scanning.
        let dir = std::env::temp_dir().join("gitrecon_test_oversized_save");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Simulate an oversized blob (just over MAX_SCAN_BYTES)
        let oversized_data: Vec<u8> = b"x".repeat(MAX_SCAN_BYTES + 1).to_vec();
        let ok = write_blob_to_disk("large_file.bin", &oversized_data, &dir);
        assert!(ok, "Oversized blob should be saved to disk even when skipped for scanning");
        assert!(dir.join("large_file.bin").exists(), "Oversized blob file must exist on disk");
        let saved = std::fs::read(dir.join("large_file.bin")).unwrap();
        assert_eq!(saved.len(), MAX_SCAN_BYTES + 1, "Saved oversized content must be complete");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_collect_tech_python() {
        let mut tech = Vec::new();
        collect_tech("requirements.txt", &mut tech);
        assert!(tech.contains(&"Python".to_string()));
    }

    #[test]
    fn test_max_scan_bytes_constant() {
        assert_eq!(MAX_SCAN_BYTES, 4 * 1024 * 1024);
    }

    // ── V3 new secret patterns ───────────────────

    #[test]
    fn test_scan_content_finds_openai_key_legacy() {
        // 48 alphanumeric chars after sk-
        let key = format!("sk-{}", "A".repeat(48));
        let content = format!("OPENAI_API_KEY={}", key);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "openai_key"),
            "Should detect legacy OpenAI API key (sk-<48 chars>)"
        );
    }

    #[test]
    fn test_scan_content_finds_openai_project_key() {
        // Project key: sk-proj-<86 chars of A-Za-z0-9_->
        let key = format!("sk-proj-{}", "A".repeat(86));
        let content = format!("key={}", key);
        let findings = scan_content(&content, "config.py", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "openai_key"),
            "Should detect OpenAI project key (sk-proj-<86 chars>)"
        );
    }

    #[test]
    fn test_scan_content_finds_anthropic_key() {
        let key = format!("sk-ant-{}", "A".repeat(95));
        let content = format!("ANTHROPIC_API_KEY={}", key);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "anthropic_key"),
            "Should detect Anthropic API key"
        );
    }

    #[test]
    fn test_scan_content_finds_openrouter_key() {
        let key = format!("sk-or-v1-{}", "A".repeat(30));
        let content = format!("OPENROUTER_API_KEY={}", key);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "openrouter_key"),
            "Should detect OpenRouter API key"
        );
    }

    #[test]
    fn test_scan_content_finds_ai_provider_env_key() {
        let key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let content = format!("DEEPSEEK_API_KEY={}", key);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "ai_provider_env_key"),
            "Should detect AI provider env-style API key"
        );
    }

    #[test]
    fn test_scan_content_ai_provider_env_placeholder_filtered() {
        let content = "GEMINI_API_KEY=your_api_key_here";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "ai_provider_env_key"),
            "Placeholder AI env key should be filtered"
        );
    }

    #[test]
    fn test_scan_content_finds_huggingface_token() {
        let token = format!("hf_{}", "a".repeat(36));
        let content = format!("HF_TOKEN={}", token);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "huggingface_token"),
            "Should detect HuggingFace token"
        );
    }

    #[test]
    fn test_scan_content_finds_digitalocean_pat() {
        let token = format!("dop_v1_{}", "a".repeat(64));
        let content = format!("DO_TOKEN={}", token);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "digitalocean_pat"),
            "Should detect DigitalOcean PAT"
        );
    }

    #[test]
    fn test_scan_content_finds_databricks_token() {
        // dapi + exactly 32 hex chars; constructed at runtime to avoid secret-scanner false positives
        let token = ["dapi", &"a".repeat(32)].concat();
        let content = format!("DATABRICKS_TOKEN={}", token);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "databricks_token"),
            "Should detect Databricks API token"
        );
    }

    #[test]
    fn test_scan_content_finds_vault_hvs_token() {
        let token = format!("hvs.{}", "A".repeat(30));
        let content = format!("VAULT_TOKEN={}", token);
        let findings = scan_content(&content, "config.sh", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "vault_token"),
            "Should detect HashiCorp Vault hvs token"
        );
    }    #[test]
    fn test_scan_content_finds_planetscale_token() {
        let token = format!("pscale_tkn_{}", "A".repeat(43));
        let content = format!("DATABASE_TOKEN={}", token);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "planetscale_token"),
            "Should detect PlanetScale token"
        );
    }

    #[test]
    fn test_scan_content_finds_supabase_key() {
        let key = format!("sbp_{}", "A".repeat(40));
        let content = format!("SUPABASE_KEY={}", key);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "supabase_key"),
            "Should detect Supabase service role key"
        );
    }

    #[test]
    fn test_scan_content_finds_linear_key() {
        let key = format!("lin_api_{}", "A".repeat(40));
        let content = format!("LINEAR_KEY={}", key);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "linear_key"),
            "Should detect Linear API key"
        );
    }

    #[test]
    fn test_sensitive_names_htpasswd() {
        assert!(is_sensitive_file(".htpasswd"), ".htpasswd should be sensitive");
    }

    #[test]
    fn test_sensitive_names_env_prod() {
        assert!(is_sensitive_file(".env.prod"), ".env.prod should be sensitive");
        assert!(is_sensitive_file(".env.production"), ".env.production should be sensitive");
    }

    #[test]
    fn test_collect_tech_svelte() {
        let mut tech = Vec::new();
        collect_tech("svelte.config.js", &mut tech);
        assert!(tech.contains(&"Svelte".to_string()), "Should detect Svelte");
    }

    #[test]
    fn test_collect_tech_flutter() {
        let mut tech = Vec::new();
        collect_tech("pubspec.yaml", &mut tech);
        assert!(tech.contains(&"Flutter".to_string()), "Should detect Flutter");
    }

    #[test]
    fn test_collect_tech_helm() {
        let mut tech = Vec::new();
        collect_tech("Chart.yaml", &mut tech);
        assert!(tech.contains(&"Helm".to_string()), "Should detect Helm");
    }

    #[test]
    fn test_collect_tech_elixir() {
        let mut tech = Vec::new();
        collect_tech("mix.exs", &mut tech);
        assert!(tech.contains(&"Elixir".to_string()), "Should detect Elixir");
    }

    #[test]
    fn test_collect_tech_kotlin() {
        let mut tech = Vec::new();
        collect_tech("build.gradle.kts", &mut tech);
        assert!(tech.contains(&"Kotlin".to_string()), "Should detect Kotlin");
    }

    #[test]
    fn test_collect_tech_swift() {
        let mut tech = Vec::new();
        collect_tech("Package.swift", &mut tech);
        assert!(tech.contains(&"Swift".to_string()), "Should detect Swift");
    }

    // ── New secret pattern tests ─────────────────

    #[test]
    fn test_scan_content_finds_shopify_token() {
        let content = format!("SHOPIFY_TOKEN=shpat_{}", "A".repeat(32));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "shopify_token"),
            "Should detect Shopify Admin API token"
        );
    }

    #[test]
    fn test_scan_content_finds_jira_token() {
        let content = format!("JIRA_TOKEN=ATATT{}", "A".repeat(30));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "jira_token"),
            "Should detect Atlassian/Jira API token"
        );
    }

    #[test]
    fn test_scan_content_finds_sentry_dsn() {
        let dsn = format!("https://{}@o1234.ingest.sentry.io/5678", "a".repeat(32));
        let content = format!("SENTRY_DSN={}", dsn);
        let findings = scan_content(&content, "sentry.properties", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "sentry_dsn"),
            "Should detect Sentry DSN"
        );
    }

    #[test]
    fn test_scan_content_finds_cloudinary_url() {
        let content = "CLOUDINARY_URL=cloudinary://apikey:apisecret@cloudname";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "cloudinary_url"),
            "Should detect Cloudinary credentials URL"
        );
    }

    #[test]
    fn test_scan_content_finds_notion_token() {
        let content = format!("NOTION_TOKEN=secret_{}", "A".repeat(43));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "notion_token"),
            "Should detect Notion integration token"
        );
    }

    #[test]
    fn test_scan_content_finds_grafana_token() {
        let content = format!("GRAFANA_TOKEN=glsa_{}_ABCD1234", "A".repeat(32));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "grafana_token"),
            "Should detect Grafana service account token"
        );
    }

    #[test]
    fn test_scan_content_finds_mongodb_atlas_uri() {
        let content = "MONGO_URI=mongodb+srv://user:password@cluster.mongodb.net/db";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "mongodb_atlas"),
            "Should detect MongoDB Atlas connection string"
        );
    }

    #[test]
    fn test_scan_content_finds_discord_webhook() {
        let content = format!("DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789012345678/{}", "A".repeat(68));
        let findings = scan_content(&content, "config.js", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "discord_webhook"),
            "Should detect Discord webhook URL"
        );
    }

    #[test]
    fn test_placeholder_extended() {
        assert!(is_placeholder("null_token"), "null_ prefix should be a placeholder");
        assert!(is_placeholder("my_secret_key"), "my_ prefix should be a placeholder");
        assert!(is_placeholder("ENTER_VALUE_HERE"), "ENTER_ prefix should be a placeholder");
        assert!(!is_placeholder("ghp_REALTOKEN123456789012345678901234567"));
    }

    #[test]
    fn test_sensitive_names_ssh_config() {
        assert!(is_sensitive_file(".ssh/config"), ".ssh/config should be sensitive");
        assert!(is_sensitive_file("authorized_keys"), "authorized_keys should be sensitive");
    }

    #[test]
    fn test_classify_ai_path_config() {
        assert_eq!(
            classify_ai_path(".claude/settings.json"),
            Some(AiPathCategory::Config)
        );
    }

    #[test]
    fn test_classify_ai_path_prompt_history() {
        assert_eq!(
            classify_ai_path(".cursor/prompts/system.md"),
            Some(AiPathCategory::PromptHistory)
        );
    }

    #[test]
    fn test_scan_content_emits_ai_path_finding() {
        let findings = scan_content(
            "model = \"claude-3\"",
            ".claude/settings.json",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "ai_path_config"),
            "AI path finding should be emitted even without key regex matches"
        );
    }

    #[test]
    fn test_ai_metadata_for_finding_provider_key() {
        let key = format!("sk-proj-{}", "A".repeat(86));
        let findings = scan_content(
            &format!("OPENAI_API_KEY={}", key),
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
        );
        let openai = findings.iter().find(|f| f.pattern_id == "openai_key").expect("openai finding");
        let (is_ai, category, tags) = ai_metadata_for_finding(openai);
        assert!(is_ai, "OpenAI key should be AI-related");
        assert_eq!(category.as_deref(), Some("provider_key"));
        assert!(tags.iter().any(|t| t == "openai"));
    }

    #[test]
    fn test_ai_metadata_for_finding_path() {
        let findings = scan_content(
            "last_model: claude-3-opus",
            ".claude/history/session.log",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
        );
        let path_finding = findings.iter().find(|f| f.pattern_id == "ai_path_prompt_history").expect("ai path finding");
        let (is_ai, category, tags) = ai_metadata_for_finding(path_finding);
        assert!(is_ai);
        assert_eq!(category.as_deref(), Some("prompt_history_path"));
        assert!(tags.iter().any(|t| t == "claude"));
    }

    #[test]
    fn test_sensitive_names_aws_credentials() {
        assert!(is_sensitive_file(".aws/credentials"), ".aws/credentials should be sensitive");
        assert!(is_sensitive_file(".aws/config"), ".aws/config should be sensitive");
    }

    #[test]
    fn test_sensitive_names_id_ecdsa() {
        assert!(is_sensitive_file("id_ecdsa"), "id_ecdsa private key file should be sensitive");
    }

    // ── New feature tests ─────────────────────────────────────────

    // Shannon entropy
    #[test]
    fn test_shannon_entropy_low_for_repeated_chars() {
        // "aaaa" has 0 entropy (only one distinct char)
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn test_shannon_entropy_high_for_random_string() {
        // A random-looking 40-char string should score well above 3.5 bits/char
        let s = "aB3xZ9qR2mK7wL5nP8tC1vD6yJ4uE0fG";
        assert!(shannon_entropy(s) > 3.5, "Random string should have high entropy");
    }

    #[test]
    fn test_shannon_entropy_returns_zero_for_short_string() {
        assert_eq!(shannon_entropy("ab"), 0.0, "Strings shorter than 4 chars yield 0.0");
    }

    // Content-based tech detection
    #[test]
    fn test_detect_tech_from_content_flask() {
        let mut stack = std::collections::HashSet::new();
        detect_tech_from_content("from flask import Flask, render_template", &mut stack);
        assert!(stack.contains("Flask"), "Should detect Flask from content");
    }

    #[test]
    fn test_detect_tech_from_content_express() {
        let mut stack = std::collections::HashSet::new();
        detect_tech_from_content(r#"const express = require('express')"#, &mut stack);
        assert!(stack.contains("Express"), "Should detect Express.js from content");
    }

    #[test]
    fn test_detect_tech_from_content_react() {
        let mut stack = std::collections::HashSet::new();
        detect_tech_from_content("import React from 'react'", &mut stack);
        assert!(stack.contains("React"), "Should detect React from content");
    }

    #[test]
    fn test_detect_tech_from_content_prisma() {
        let mut stack = std::collections::HashSet::new();
        detect_tech_from_content("const client = new PrismaClient()", &mut stack);
        assert!(stack.contains("Prisma"), "Should detect Prisma from content");
    }

    // Context window
    #[test]
    fn test_build_context_window_center() {
        let lines = vec!["a", "b", "c", "d", "e"];
        let ctx = build_context_window(&lines, 2, 2);
        assert!(ctx.contains('a'), "Window radius=2 from center=2 should include line 0");
        assert!(ctx.contains('e'), "Window radius=2 from center=2 should include line 4");
    }

    #[test]
    fn test_build_context_window_edges() {
        let lines = vec!["only"];
        let ctx = build_context_window(&lines, 0, 2);
        assert_eq!(ctx, "only");
    }

    // Minified JS segment scanning
    #[test]
    fn test_scan_minified_segments_finds_aws_key() {
        let sha = "a".repeat(40);
        let minified = format!(
            "var x=1;const k=\"{}\";function f(){{}}",
            "AKIAZ9XYZMNOP1234567"
        );
        let mut findings = Vec::new();
        scan_minified_segments(&minified, 0, "bundle.min.js", &sha, false, &mut findings);
        assert!(
            findings.iter().any(|f| f.pattern_id == "aws_key_id"),
            "Should detect AWS key in minified JS segment"
        );
    }

    // YAML next-line secrets
    #[test]
    fn test_scan_yaml_nextline_finds_secret() {
        let sha   = "a".repeat(40);
        let content = "password:\n  SuperSecretP@ssw0rd!!abc123xyz";
        let findings = scan_yaml_nextline_secrets(content, "config.yaml", &sha, false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "yaml_nextline_secret"),
            "Should detect YAML next-line secret"
        );
    }

    #[test]
    fn test_scan_yaml_nextline_skips_empty_value() {
        let sha     = "a".repeat(40);
        let content = "password:\n  ";
        let findings = scan_yaml_nextline_secrets(content, "config.yaml", &sha, false);
        assert!(findings.is_empty(), "Should not flag empty YAML value");
    }

    // Entropy line scan
    #[test]
    fn test_scan_entropy_line_fires_for_high_entropy_secret() {
        let sha   = "a".repeat(40);
        // Use a standalone keyword ("secret") so \bsecret\b matches
        let line  = r#"secret = "xK9mQz3rN7wT2vB5sL0pJ4hY8uE6fA1d""#;
        let lines = vec![line];
        let mut out = Vec::new();
        scan_entropy_line(line, 0, "config.py", &sha, false, &lines, &mut out, 4.5);
        assert!(
            out.iter().any(|f| f.pattern_id == "high_entropy_secret"),
            "Should fire for high-entropy quoted value in keyword context"
        );
    }

    #[test]
    fn test_scan_entropy_line_silent_without_keyword_context() {
        let sha   = "a".repeat(40);
        // 'description' is not in our keyword list, so no entropy finding expected
        let line  = r#"description = "xK9mQz3rN7wT2vB5sL0pJ4hY8uE6fA1d""#;
        let lines = vec![line];
        let mut out = Vec::new();
        scan_entropy_line(line, 0, "config.py", &sha, false, &lines, &mut out, 4.5);
        assert!(out.is_empty(), "Should not fire when no keyword context present");
    }

    // New provider patterns

    #[test]
    fn test_scan_content_finds_razorpay_key() {
        let content = format!("RAZORPAY_KEY=rzp_live_{}", "A".repeat(14));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "razorpay_key"),
            "Should detect Razorpay key"
        );
    }

    #[test]
    fn test_scan_content_finds_flyio_token() {
        let content = format!("FLY_TOKEN=fo1_{}", "A".repeat(40));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "flyio_token"),
            "Should detect Fly.io token"
        );
    }

    #[test]
    fn test_scan_content_finds_render_api_key() {
        let content = format!("RENDER_KEY=rnd_{}", "A".repeat(32));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "render_api_key"),
            "Should detect Render API key"
        );
    }

    #[test]
    fn test_scan_content_finds_scaleway_secret() {
        let content = "SCW_SECRET_KEY=12345678-1234-1234-1234-123456789abc";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "scaleway_secret_key"),
            "Should detect Scaleway secret key"
        );
    }

    #[test]
    fn test_scan_content_finds_square_key() {
        let content = format!("SQUARE_TOKEN=sq0csp-{}", "A".repeat(43));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "square_api_key"),
            "Should detect Square API key"
        );
    }

    #[test]
    fn test_scan_content_finds_mapbox_token() {
        let content = "MAPBOX_TOKEN=pk.eyJhIjoiYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoifQ.ABCDEFGHIJKLMNOPQRS";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "mapbox_token"),
            "Should detect Mapbox access token"
        );
    }

    // unique_findings / unique_count
    #[test]
    fn test_unique_findings_deduplicates() {
        let sha = "a".repeat(40);
        let content = "AKIAZ9XYZMNOP1234567\nAKIAZ9XYZMNOP1234567";
        let raw = scan_content(content, "file.sh", &sha, false, &[], 4.5);
        // Build a StreamResult manually
        let sr = super::StreamResult {
            findings: raw,
            contributors: vec![],
            tech_stack: vec![],
            commit_count: 0,
            blobs_scanned: 1,
            blobs_failed: 0,
            bytes_scanned: 0,
            elapsed_s: 0.0,
            files_saved: 0,
            files_save_failed: 0,
        };
        // Both lines have the same match, so unique should be 1
        assert_eq!(sr.unique_count(), 1, "Same secret on two lines should deduplicate to 1");
        assert!(sr.unique_findings().len() <= sr.findings.len());
    }

    // DynPattern / load_patterns_from_file
    #[test]
    fn test_scan_content_uses_dyn_pattern() {
        let dyn_pat = super::DynPattern {
            id:    "custom_token".to_string(),
            sev:   "HIGH".to_string(),
            desc:  "Custom test token".to_string(),
            regex: regex::Regex::new(r"CUSTOM_[A-Z0-9]{8}").unwrap(),
        };
        let content = "TOKEN=CUSTOM_ABCD1234";
        let findings = scan_content(content, "config.sh", "a".repeat(40).as_str(), false, &[dyn_pat], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "custom_token"),
            "Should detect custom dynamic pattern"
        );
    }

    #[test]
    fn test_load_patterns_from_file_valid() {
        let path = std::env::temp_dir().join("gitrecon_patterns_valid.json");
        std::fs::write(&path, br#"{"patterns":[{"id":"t","severity":"HIGH","description":"Test","regex":"TEST_[0-9]+"}]}"#).unwrap();
        let loaded = super::load_patterns_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "t");
        assert_eq!(loaded[0].sev, "HIGH");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_patterns_from_file_missing() {
        let result = super::load_patterns_from_file("/tmp/gitrecon_nonexistent_file.json");
        assert!(result.is_err(), "Missing file should return an error");
    }

    #[test]
    fn test_load_patterns_from_file_invalid_json() {
        let dir = std::env::temp_dir();
        let path = dir.join("gitrecon_invalid.json");
        std::fs::write(&path, b"not valid json").unwrap();
        let result = super::load_patterns_from_file(path.to_str().unwrap());
        assert!(result.is_err(), "Invalid JSON should return an error");
        let _ = std::fs::remove_file(&path);
    }

    // ── False-positive reduction tests ───────────────────────────

    /// Entropy scanner must never produce MEDIUM-severity findings.
    /// (Historically, values in the 3.5–4.5 bits/char range were labelled MEDIUM
    ///  and caused the bulk of false positives. The threshold is now 4.5.)
    #[test]
    fn test_entropy_scanner_never_produces_medium() {
        let sha = "a".repeat(40);
        // A keyword context line with a borderline-entropy value (3.5–4.4 range)
        let line = r#"api_key = "AbCdEfGhIjKlMnOpQrStUvWxYz12345678""#;
        let lines = vec![line];
        let mut out = Vec::new();
        scan_entropy_line(line, 0, "config.py", &sha, false, &lines, &mut out, 4.5);
        assert!(
            !out.iter().any(|f| f.severity == "MEDIUM"),
            "Entropy scanner must never produce MEDIUM-severity findings (threshold is 4.5)"
        );
    }

    /// Values with entropy below 4.5 bits/char should not produce any entropy finding.
    #[test]
    fn test_entropy_scanner_skips_below_threshold() {
        let sha = "a".repeat(40);
        // "aababababababababab" has entropy ~1.0 — well below 4.5
        let line = r#"password = "aababababababababab""#;
        let lines = vec![line];
        let mut out = Vec::new();
        scan_entropy_line(line, 0, "config.py", &sha, false, &lines, &mut out, 4.5);
        assert!(out.is_empty(), "Low-entropy value (< 4.5 bits/char) must not produce findings");
    }

    /// Verify that "put " (with space) is now treated as a placeholder.
    /// This covers WordPress wp-config-sample.php style "put your unique phrase here" values.
    #[test]
    fn test_placeholder_put_space_is_recognized() {
        assert!(is_placeholder("put your unique phrase here"), "'put ' should be recognized as a placeholder");
        // A real-looking secret that does not contain any placeholder substring
        assert!(!is_placeholder("xK9mQz3rN7wT2vB5sL0pJ4hY8uE6fA1d"), "A high-entropy secret must not be flagged as placeholder");
    }

    /// "your-api-key" style (hyphen) placeholder should be recognized.
    #[test]
    fn test_placeholder_your_hyphen_is_recognized() {
        assert!(is_placeholder("your-api-key-here"), "'your-' (with hyphen) should be recognized as a placeholder");
        assert!(is_placeholder("YOUR-SECRET-HERE"), "'YOUR-' (with hyphen) should be recognized as a placeholder");
    }

    /// "changeit" and "ChangeMe" should be recognized as placeholders.
    #[test]
    fn test_placeholder_changeit_changeme_variants() {
        assert!(is_placeholder("changeit"), "'changeit' should be a placeholder");
        assert!(is_placeholder("ChangeMe_value"), "'ChangeMe' variant should be a placeholder");
        assert!(is_placeholder("change this value"), "'change this' should be a placeholder");
        assert!(is_placeholder("change-this-value"), "'change-this' should be a placeholder");
    }

    /// Telegram bot pattern must require "telegram" or "bot" context keyword.
    /// A bare numeric-ID:token string without context must NOT match.
    #[test]
    fn test_telegram_bot_requires_context_keyword() {
        let sha = "a".repeat(40);
        // Bare token without any label (common FP source: order IDs, tracking numbers)
        let content = "order_id=1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
        let findings = scan_content(content, "config.php", &sha, false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "telegram_bot"),
            "Bare numeric:token without 'telegram'/'bot' context must not be flagged as Telegram Bot Token"
        );
    }

    /// Telegram bot pattern MUST fire when proper context keyword is present.
    #[test]
    fn test_telegram_bot_fires_with_context_keyword() {
        let sha = "a".repeat(40);
        let content = "TELEGRAM_BOT_TOKEN=1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
        let findings = scan_content(content, ".env", &sha, false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "telegram_bot"),
            "Telegram bot token with 'TELEGRAM_BOT_TOKEN=' label must be detected"
        );
    }

    // ── V3.1 new secret pattern tests ─────────────

    #[test]
    fn test_scan_content_finds_github_fine_pat() {
        let content = format!("TOKEN=github_pat_{}", "A".repeat(82));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "github_fine_pat"),
            "Should detect GitHub fine-grained PAT"
        );
    }

    #[test]
    fn test_scan_content_finds_groq_key() {
        let content = format!("GROQ_KEY=gsk_{}", "A".repeat(52));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "groq_key"),
            "Should detect Groq API key"
        );
    }

    #[test]
    fn test_scan_content_finds_replicate_token() {
        let content = format!("REPLICATE_TOKEN=r8_{}", "A".repeat(40));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "replicate_token"),
            "Should detect Replicate API token"
        );
    }

    #[test]
    fn test_scan_content_finds_contentful_token() {
        let content = format!("CONTENTFUL_TOKEN=CFPAT-{}", "A".repeat(43));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "contentful_token"),
            "Should detect Contentful token"
        );
    }

    #[test]
    fn test_scan_content_finds_postman_key() {
        let content = format!("POSTMAN_KEY=PMAK-{}-{}", "A".repeat(24), "B".repeat(34));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "postman_key"),
            "Should detect Postman API key"
        );
    }

    #[test]
    fn test_scan_content_finds_tencent_secret_id() {
        let content = format!("TENCENT_ID=AKID{}", "A".repeat(32));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "tencent_secret_id"),
            "Should detect Tencent Cloud SecretId"
        );
    }

    #[test]
    fn test_scan_content_finds_age_secret_key() {
        let content = "AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6M";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "age_secret_key"),
            "Should detect Age encryption secret key"
        );
    }

    #[test]
    fn test_scan_content_finds_clerk_secret() {
        let content = format!("CLERK_SECRET=sk_live_{}", "A".repeat(30));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "clerk_secret"),
            "Should detect Clerk secret key"
        );
    }

    // ── V3.1 sensitive file tests ─────────────────

    #[test]
    fn test_sensitive_names_docker_config() {
        assert!(is_sensitive_file(".docker/config.json"), ".docker/config.json should be sensitive");
    }

    #[test]
    fn test_sensitive_names_gradle_properties() {
        assert!(is_sensitive_file(".gradle/gradle.properties"), ".gradle/gradle.properties should be sensitive");
    }

    #[test]
    fn test_sensitive_names_cargo_credentials() {
        assert!(is_sensitive_file(".cargo/credentials"), ".cargo/credentials should be sensitive");
    }

    #[test]
    fn test_sensitive_names_bash_history() {
        assert!(is_sensitive_file(".bash_history"), ".bash_history should be sensitive");
    }

    #[test]
    fn test_sensitive_names_pgpass() {
        assert!(is_sensitive_file(".pgpass"), ".pgpass should be sensitive");
    }

    // ── V3.1 tech stack tests ────────────────────

    #[test]
    fn test_collect_tech_remix() {
        let mut tech = Vec::new();
        collect_tech("remix.config.ts", &mut tech);
        assert!(tech.contains(&"Remix".to_string()), "Should detect Remix");
    }

    #[test]
    fn test_collect_tech_astro() {
        let mut tech = Vec::new();
        collect_tech("astro.config.mjs", &mut tech);
        assert!(tech.contains(&"Astro".to_string()), "Should detect Astro");
    }

    #[test]
    fn test_collect_tech_deno() {
        let mut tech = Vec::new();
        collect_tech("deno.json", &mut tech);
        assert!(tech.contains(&"Deno".to_string()), "Should detect Deno");
    }

    #[test]
    fn test_collect_tech_bun() {
        let mut tech = Vec::new();
        collect_tech("bun.lockb", &mut tech);
        assert!(tech.contains(&"Bun".to_string()), "Should detect Bun");
    }

    #[test]
    fn test_collect_tech_vite() {
        let mut tech = Vec::new();
        collect_tech("vite.config.ts", &mut tech);
        assert!(tech.contains(&"Vite".to_string()), "Should detect Vite");
    }

    #[test]
    fn test_collect_tech_tauri() {
        let mut tech = Vec::new();
        collect_tech("tauri.conf.json", &mut tech);
        assert!(tech.contains(&"Tauri".to_string()), "Should detect Tauri");
    }

    #[test]
    fn test_collect_tech_electron() {
        let mut tech = Vec::new();
        collect_tech("electron.js", &mut tech);
        assert!(tech.contains(&"Electron".to_string()), "Should detect Electron");
    }

    // ── V3.1 content-based tech detection ─────────

    #[test]
    fn test_detect_tech_from_content_deno() {
        let mut stack = std::collections::HashSet::new();
        detect_tech_from_content("Deno.serve(handler)", &mut stack);
        assert!(stack.contains("Deno"), "Should detect Deno from content");
    }

    #[test]
    fn test_detect_tech_from_content_trpc() {
        let mut stack = std::collections::HashSet::new();
        detect_tech_from_content("const t = initTRPC.create()", &mut stack);
        assert!(stack.contains("tRPC"), "Should detect tRPC from content");
    }

    #[test]
    fn test_detect_tech_from_content_tailwind() {
        let mut stack = std::collections::HashSet::new();
        detect_tech_from_content("@tailwind base;\n@tailwind components;", &mut stack);
        assert!(stack.contains("Tailwind"), "Should detect Tailwind CSS from content");
    }

    // ── V3.1 commit message scanning ──────────────

    #[test]
    fn test_scan_content_on_commit_message_finds_secret() {
        // Simulate scanning a commit message that contains a secret
        let content = "fix: update config\n\nAWS_KEY=AKIAZ9XYZMNOP1234567";
        let findings = scan_content(content, "[commit:abcd1234:message]", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "aws_key_id"),
            "Should detect secrets in commit messages"
        );
    }

    // ── SMTP / email credential pattern tests ─────

    #[test]
    fn test_scan_content_finds_smtp_credentials_php_array() {
        // PHP array format: 'smtp_pass' => 'p4ncasona@23'
        let content = r#"'smtp_pass' => 'p4ncasona@23',"#;
        let findings = scan_content(content, "email.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "smtp_credentials"),
            "Should detect smtp_pass in PHP array format"
        );
    }

    #[test]
    fn test_scan_content_finds_smtp_credentials_env() {
        let content = "SMTP_PASS=secretpassword123";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "smtp_credentials"),
            "Should detect SMTP_PASS in .env format"
        );
    }

    #[test]
    fn test_scan_content_finds_smtp_password_yaml() {
        let content = "smtp_password: mysecretpassword";
        let findings = scan_content(content, "config.yaml", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "smtp_credentials"),
            "Should detect smtp_password in YAML format"
        );
    }

    #[test]
    fn test_scan_content_finds_smtp_url_with_credentials() {
        let content = "MAIL_URL=smtps://mailuser:secretpass@smtp.acme.net:465";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "smtp_url"),
            "Should detect SMTP URL with embedded credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_imap_credentials() {
        let content = r#"'imap_pass' => 'mailboxSecret99',"#;
        let findings = scan_content(content, "config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "imap_credentials"),
            "Should detect IMAP credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_pop3_credentials() {
        let content = "pop3_password = 'inbox_secret_pass'";
        let findings = scan_content(content, "mail.conf", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "imap_credentials"),
            "Should detect POP3 credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_ftp_credentials() {
        let content = r#"'ftp_pass' => 'ftpS3cret!',"#;
        let findings = scan_content(content, "deploy.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "ftp_credentials"),
            "Should detect FTP credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_sftp_credentials() {
        let content = "SFTP_PASSWORD=deploy_secret_key";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "ftp_credentials"),
            "Should detect SFTP credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_ftp_url_with_credentials() {
        let content = "FTP_URL=ftp://ftpuser:ftppassword@ftp.acme.net";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "ftp_url"),
            "Should detect FTP URL with embedded credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_amqp_url_with_credentials() {
        let content = "AMQP_URL=amqp://rabbitmq:r4bbitPass@localhost:5672/vhost";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "amqp_url"),
            "Should detect AMQP connection URL with credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_amqps_url_with_credentials() {
        let content = "RABBITMQ_URL=amqps://admin:amqpSecret@mq.acme.net:5671";
        let findings = scan_content(content, "config.sh", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "amqp_url"),
            "Should detect AMQPS (TLS) connection URL with credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_ldap_credentials() {
        let content = "LDAP_URL=ldap://cn=admin:ldapSecret@ldap.acme.net";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            findings.iter().any(|f| f.pattern_id == "ldap_credentials"),
            "Should detect LDAP URL with embedded credentials"
        );
    }

    #[test]
    fn test_smtp_credentials_placeholder_filtered() {
        let content = "smtp_pass = 'changeme'";
        let findings = scan_content(content, "config.php", "a".repeat(40).as_str(), false, &[], 4.5);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "smtp_credentials"),
            "Placeholder SMTP password 'changeme' should be filtered"
        );
    }

    #[test]
    fn test_finding_to_dict_truncates_unicode_safely() {
        let finding = Finding {
            filename: "file.txt".to_string(),
            line: 1,
            pattern_id: "jwt_secret".to_string(),
            description: "JWT Secret".to_string(),
            severity: "CRITICAL".to_string(),
            match_str: "密钥🔐─".repeat(80),
            context: "context─你好🌍".repeat(80),
            is_deleted: false,
            commit_sha1: Some("a".repeat(40)),
            confidence_adjustment: None,
        };
        let dict = finding.to_dict();
        let m = dict["match"].as_str().expect("match as str");
        let c = dict["context"].as_str().expect("context as str");
        assert!(m.chars().count() <= 120, "match must be truncated by char count");
        assert!(c.chars().count() <= 200, "context must be truncated by char count");
    }

    #[test]
    fn test_unique_findings_handles_unicode_without_panic() {
        let finding_a = Finding {
            filename: "a.txt".to_string(),
            line: 1,
            pattern_id: "jwt_secret".to_string(),
            description: "JWT Secret".to_string(),
            severity: "CRITICAL".to_string(),
            match_str: "token─🔐你好".repeat(20),
            context: "ctx".to_string(),
            is_deleted: false,
            commit_sha1: Some("a".repeat(40)),
            confidence_adjustment: None,
        };
        let finding_b = finding_a.clone();
        let stream = StreamResult {
            findings: vec![finding_a, finding_b],
            contributors: vec![],
            tech_stack: vec![],
            commit_count: 0,
            blobs_scanned: 0,
            blobs_failed: 0,
            bytes_scanned: 0,
            elapsed_s: 0.0,
            files_saved: 0,
            files_save_failed: 0,
        };
        assert_eq!(stream.unique_count(), 1);
        assert_eq!(stream.unique_findings().len(), 1);
    }

    #[test]
    fn test_scan_minified_segments_unicode_context_is_safe() {
        let mut out = Vec::new();
        let line = format!(
            "const key='{} AKIAZ9XYZMNOP1234567';",
            "─你好🔐".repeat(70)
        );
        scan_minified_segments(&line, 0, "bundle.min.js", &"a".repeat(40), false, &mut out);
        assert!(!out.is_empty(), "Expected at least one finding from AWS key pattern");
        assert!(
            out.iter().any(|f| f.pattern_id == "aws_key_id"),
            "Expected aws_key_id finding from minified segment"
        );
        let ctx = out[0].context.strip_prefix("[minified] ").unwrap_or(&out[0].context);
        assert!(ctx.chars().count() <= 200, "Minified context must be truncated by char count");
    }
}

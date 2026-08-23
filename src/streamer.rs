//! streamer.rs
//! Phase 3 — Stream & Scan: fetch every object, scan for secrets in memory,
//! optionally writing blobs to disk when --save is active.
//! Output: StreamResult with all findings + intel.

use futures::StreamExt;
use lazy_static::lazy_static;
use regex::{Regex, RegexSet};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as TokioMutex;

use crate::binary_scanner;
#[cfg(test)]
use crate::checkpoint::AdaptiveConcurrencyState;
use crate::checkpoint::{self, Checkpoint, CheckpointPhase, StreamCheckpoint};
use crate::content_scanner::ContentScanner;
use crate::git_parser::ObjectParser;
use crate::http_client::HttpClient;
use crate::mapper::MapResult;
use crate::object_source::ObjectSourceKind;
use crate::resource_budget::{ResourceBudget, ResourceStage};
use crate::scanner_policy::ScanPolicy;
use crate::text_utils::truncate_utf8;

// ════════════════════════════════════════════════
// SECRET PATTERNS
// ════════════════════════════════════════════════

/// A secret-detection pattern loaded at runtime (e.g. from `--patterns FILE`).
#[derive(Clone)]
pub struct DynPattern {
    pub id: String,
    pub sev: String,
    pub desc: String,
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
    // SEC-006: Validate path to prevent path traversal attacks
    use crate::validation;
    let validated_path = validation::validate_patterns_path(path)?;
    let raw = std::fs::read_to_string(&validated_path)
        .map_err(|e| anyhow::anyhow!("Cannot read patterns file '{}': {}", path, e))?;
    crate::validation::validate_patterns_json(&raw)
        .map_err(|error| anyhow::anyhow!("Pattern validation failed for '{}': {}", path, error))?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("Invalid JSON in patterns file '{}': {}", path, e))?;
    let arr = json["patterns"].as_array().ok_or_else(|| {
        anyhow::anyhow!("Patterns file must contain a top-level 'patterns' array")
    })?;

    let mut result = Vec::with_capacity(arr.len());
    for (i, p) in arr.iter().enumerate() {
        let id = p["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Pattern #{}: missing 'id' field", i))?;
        let sev = p["severity"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Pattern #{}: missing 'severity' field", i))?;
        let desc = p["description"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Pattern #{}: missing 'description' field", i))?;
        let rx_str = p["regex"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Pattern #{}: missing 'regex' field", i))?;
        let regex = Regex::new(rx_str).map_err(|e| {
            anyhow::anyhow!("Pattern #{} '{}': invalid regex '{}': {}", i, id, rx_str, e)
        })?;
        result.push(DynPattern {
            id: id.into(),
            sev: sev.into(),
            desc: desc.into(),
            regex,
        });
    }
    Ok(result)
}

struct Pattern {
    id: &'static str,
    sev: &'static str,
    desc: &'static str,
    source: &'static str,
    regex: Regex,
}

macro_rules! pat {
    ($id:expr, $sev:expr, $desc:expr, $rx:expr) => {
        Pattern {
            id: $id,
            sev: $sev,
            desc: $desc,
            source: $rx,
            regex: Regex::new($rx).expect(concat!("bad regex: ", $rx)),
        }
    };
}

lazy_static! {
    // SCAN-001: Default false-positive keywords for context-aware confidence scoring
    static ref DEFAULT_FALSE_POSITIVE_KEYWORDS: Vec<&'static str> = vec![
        "example", "sample", "test", "dummy", "placeholder",
        "fake", "mock", "xxxxx", "localhost", "127.0.0.1",
        "your_", "YOUR_", "your-", "YOUR-",
        "changeme", "CHANGE_ME", "changeit", "ChangeMe",
        "insert_", "INSERT_", "TODO", "FIXME",
        "replace", "REPLACE", "xxxx", "XXXX",
        "n/a", "N/A", "none", "NONE", "null", "NULL",
        "undefined", "my_", "MY_", "enter_", "ENTER_",
        "set_", "SET_", "fill_", "FILL_",
        "put_", "PUT_", "put ", "add_", "ADD_",
        "change this", "change-this",
        "00000000", "11111111", "<",
    ];

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
             // Sprint 5 (S5.7): anchor with \b so we don't match `SK` embedded in
             // a longer identifier. Real Twilio keys are exactly 32 lowercase hex.
             r"\bSK[0-9a-f]{32}\b"),
        pat!("twilio_account","HIGH", "Twilio Account SID",
             r"\bAC[0-9a-f]{32}\b"),
        pat!("mailgun",       "HIGH", "Mailgun Key",
             // Sprint 5 (S5.7): anchor + case-insensitive; real Mailgun keys are
             // `key-<32 hex>` isolated tokens, not substrings.
             r"(?i)\bkey-[0-9a-f]{32}\b"),
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
             // Sprint 5 (S5.7): bump minimum segment length from 10 → 20 to reject
             // the `eyJXXX.YYY.ZZZ` shape from sample docs / test fixtures. Real
             // JWTs almost always have header + payload ≥ 20 chars each.
             r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
        pat!("jwt_secret", "CRITICAL", "JWT Secret",
             r#"(?i)jwt[_\-]?secret\s*[=:]\s*['"]?([^\s'"]{16,})['"]?"#),
        // Generic
        pat!("api_key",      "HIGH", "Generic API Key",
             r#"(?i)api[_\-\s]?key\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?"#),
        pat!("secret_key",   "HIGH", "Generic Secret Key",
             r#"(?i)secret[_\-\s]?key\s*[=:]\s*['"]?([A-Za-z0-9_\-!@#$]{16,})['"]?"#),
        pat!("access_token", "HIGH", "Access Token",
             // Sprint 5 (S5.7): cap trailing capture at 256 chars — a URL after
             // `access_token=` used to be greedy-eaten because `.` was allowed
             // and there was no upper bound.
             r#"(?i)access[_\-\s]?token\s*[=:]\s*['"]?([A-Za-z0-9_\-\.]{20,256})['"]?"#),
        pat!("bearer_token", "HIGH", "Bearer Token in Authorization Header",
             // Sprint 5 (S5.7): same 256-char cap as access_token.
             r"(?i)Authorization\s*[:=]\s*[Bb]earer\s+([A-Za-z0-9_\-\.]{20,256})"),
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
             // Sprint 5 (S5.7): anchor with `\b` on the LEFT — without it any 32
             // hex chars followed by `-us1` (a git SHA fragment in context, say)
             // triggered. Real keys are isolated tokens.
             r"\b[0-9a-f]{32}-us[1-9][0-9]?\b"),
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

    // One automaton quickly identifies candidate patterns before the exact regex
    // captures run. The full Pattern registry remains authoritative and ordered.
    static ref PATTERN_SET: RegexSet = RegexSet::new(PATTERNS.iter().map(|pattern| pattern.source))
        .expect("static detector pattern set must compile");

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
        (
            "Python",
            Regex::new(r"requirements\.txt|setup\.py|Pipfile|pyproject\.toml|manage\.py|tox\.ini")
                .unwrap()
        ),
        (
            "Node.js",
            Regex::new(r"package\.json|yarn\.lock|package-lock\.json|\.nvmrc").unwrap()
        ),
        (
            "PHP",
            Regex::new(r"composer\.json|composer\.lock|\.php$").unwrap()
        ),
        (
            "Ruby",
            Regex::new(r"Gemfile|\.ruby-version|\.rb$|Rakefile").unwrap()
        ),
        (
            "Java",
            Regex::new(r"pom\.xml|build\.gradle|\.java$|\.jar$").unwrap()
        ),
        ("Go", Regex::new(r"go\.mod|go\.sum|\.go$").unwrap()),
        (
            "Rust",
            Regex::new(r"Cargo\.toml|Cargo\.lock|\.rs$").unwrap()
        ),
        (
            ".NET",
            Regex::new(r"\.csproj|\.sln|web\.config|\.fsproj|\.vbproj").unwrap()
        ),
        (
            "Docker",
            Regex::new(r"Dockerfile|docker-compose|\.dockerignore").unwrap()
        ),
        (
            "Kubernetes",
            Regex::new(r"kubectl|\.yaml$|kustomization\.ya?ml").unwrap()
        ),
        (
            "Terraform",
            Regex::new(r"\.tf$|terraform\.tfvars|\.tfstate").unwrap()
        ),
        (
            "WordPress",
            Regex::new(r"wp-config|wp-content|wp-includes").unwrap()
        ),
        (
            "Django",
            Regex::new(r"manage\.py|settings\.py|wsgi\.py|asgi\.py").unwrap()
        ),
        (
            "Laravel",
            Regex::new(r"artisan|\.blade\.php|bootstrap/app\.php").unwrap()
        ),
        ("React", Regex::new(r"\.jsx$|\.tsx$|react-scripts").unwrap()),
        ("Vue", Regex::new(r"\.vue$|vue\.config|vuex").unwrap()),
        (
            "Angular",
            Regex::new(r"angular\.json|ng-package|\.component\.ts$").unwrap()
        ),
        ("Svelte", Regex::new(r"svelte\.config|\.svelte$").unwrap()),
        (
            "Next.js",
            Regex::new(r"next\.config\.(js|ts)|_next/|\.next/").unwrap()
        ),
        (
            "NestJS",
            Regex::new(r"nest-cli\.json|\.module\.ts$|\.controller\.ts$").unwrap()
        ),
        ("FastAPI", Regex::new(r"\bfastapi\b|\buvicorn\b").unwrap()),
        (
            "Spring",
            Regex::new(r"pom\.xml|spring-boot|ApplicationContext\.xml|application\.properties")
                .unwrap()
        ),
        ("Flutter", Regex::new(r"pubspec\.yaml|\.dart$").unwrap()),
        (
            "Ansible",
            Regex::new(r"ansible\.cfg|playbook\.ya?ml|inventory\.ya?ml").unwrap()
        ),
        (
            "Helm",
            Regex::new(r"Chart\.ya?ml|values\.ya?ml|templates/").unwrap()
        ),
        (
            "Elixir",
            Regex::new(r"mix\.exs|mix\.lock|\.ex$|\.exs$").unwrap()
        ),
        (
            "Kotlin",
            Regex::new(r"\.kt$|\.kts$|build\.gradle\.kts").unwrap()
        ),
        (
            "Swift",
            Regex::new(r"\.swift$|Package\.swift|Podfile").unwrap()
        ),
        ("Scala", Regex::new(r"\.scala$|build\.sbt|\.sc$").unwrap()),
        (
            "Haskell",
            Regex::new(r"\.hs$|\.cabal$|stack\.yaml").unwrap()
        ),
        (
            "Pulumi",
            Regex::new(r"Pulumi\.ya?ml|Pulumi\..*\.ya?ml").unwrap()
        ),
        ("CDK", Regex::new(r"cdk\.json|aws-cdk").unwrap()),
        (
            "Remix",
            Regex::new(r"remix\.config\.(js|ts)|entry\.server\.(ts|tsx)").unwrap()
        ),
        (
            "Astro",
            Regex::new(r"astro\.config\.(mjs|ts)|\.astro$").unwrap()
        ),
        (
            "Deno",
            Regex::new(r"deno\.json[c]?|mod\.ts$|deps\.ts$").unwrap()
        ),
        ("Bun", Regex::new(r"bun\.lockb|bunfig\.toml").unwrap()),
        (
            "Nuxt",
            Regex::new(r"nuxt\.config\.(js|ts)|\.nuxt/").unwrap()
        ),
        (
            "SvelteKit",
            Regex::new(r"svelte\.config\.(js|ts)|\.svelte-kit/").unwrap()
        ),
        ("Vite", Regex::new(r"vite\.config\.(js|ts|mjs)").unwrap()),
        (
            "Tauri",
            Regex::new(r"tauri\.conf\.json|src-tauri/").unwrap()
        ),
        (
            "Electron",
            Regex::new(r"electron\.js|electron-builder\.(ya?ml|json)").unwrap()
        ),
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

pub use crate::stream_types::{
    CacheReportStats, Contributor, Finding, ObjectSourceStats, ScanOutcomeStats, StreamResult,
};

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

impl ScanOutcomeStats {
    fn from_state(state: &State) -> Self {
        let count_skip = |reason| state.skipped_by_reason.get(&reason).copied().unwrap_or(0);
        let mut failed_http_statuses = BTreeMap::new();
        for (kind, count) in &state.failed_by_kind {
            let FailureKind::HttpStatus(status) = kind;
            failed_http_statuses.insert(status.to_string(), *count);
        }
        Self {
            skipped_stop_requested: count_skip(SkipReason::StopRequested),
            skipped_invalid_object: count_skip(SkipReason::InvalidObject),
            skipped_not_found: count_skip(SkipReason::NotFound),
            skipped_oversized: count_skip(SkipReason::Oversized),
            skipped_resource_budget: count_skip(SkipReason::ResourceBudget),
            skipped_files: 0,
            failed_files: 0,
            archive_truncated: state.archive_truncated,
            archive_invalid: state.archive_invalid,
            archive_invalid_reasons: state.archive_invalid_reasons.clone(),
            resource_peak_bytes: 0,
            resource_denied_reservations: 0,
            scan_scope: None,
            capabilities: None,
            unsupported_capability: None,
            history_commits_scanned: 0,
            history_entries_considered: 0,
            history_entries_scanned: 0,
            history_entries_deduplicated: 0,
            history_deleted_entries: 0,
            history_truncated: false,
            failed_http_statuses,
        }
    }

    pub fn skipped_total(&self) -> usize {
        self.skipped_stop_requested
            + self.skipped_invalid_object
            + self.skipped_not_found
            + self.skipped_oversized
            + self.skipped_files
    }

    pub fn failed_total(&self) -> usize {
        self.failed_files + self.failed_http_statuses.values().sum::<usize>()
    }

    pub fn truncated_total(&self) -> usize {
        self.archive_truncated
    }
}

impl StreamResult {
    pub fn risk_score(&self) -> u32 {
        let mut critical = 0u32;
        let mut high = 0u32;
        let mut medium = 0u32;
        for f in &self.findings {
            match f.severity.as_str() {
                "CRITICAL" => critical += 1,
                "HIGH" => high += 1,
                "MEDIUM" => medium += 1,
                _ => {}
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
                "HIGH" => *c.get_mut("HIGH").unwrap() += 1,
                "MEDIUM" => *c.get_mut("MEDIUM").unwrap() += 1,
                "LOW" => *c.get_mut("LOW").unwrap() += 1,
                _ => {}
            }
        }
        c
    }

    /// Returns one finding per unique `(pattern_id, match_str)` pair.
    /// Useful for deduplicating the same secret found across multiple blobs.
    #[allow(dead_code)]
    pub fn unique_findings(&self) -> Vec<&Finding> {
        let mut seen = HashSet::new();
        self.findings
            .iter()
            .filter(|finding| seen.insert(finding_dedup_key(finding)))
            .collect()
    }

    /// Count of unique secrets (may be less than `findings.len()` when the same
    /// secret appears in multiple blobs).
    #[allow(dead_code)]
    pub fn unique_count(&self) -> usize {
        self.findings
            .iter()
            .map(finding_dedup_key)
            .collect::<HashSet<_>>()
            .len()
    }
}

fn finding_dedup_key(finding: &Finding) -> (&str, &str) {
    (finding.pattern_id.as_str(), finding.match_str.as_str())
}

fn ordered_processed_sha1s(processed: &HashSet<String>) -> Vec<String> {
    let mut ordered: Vec<String> = processed.iter().cloned().collect();
    ordered.sort_unstable();
    ordered
}

// ════════════════════════════════════════════════
// SHARED STATE
// ════════════════════════════════════════════════

pub(crate) use crate::scan_accumulator::State;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SkipReason {
    StopRequested,
    InvalidObject,
    ResourceBudget,
    NotFound,
    Oversized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FailureKind {
    HttpStatus(u16),
}

// Result sent back from each worker task via channel
pub(crate) enum WorkerResult {
    BlobScanned {
        findings: Vec<Finding>,
        tech: Vec<String>,
        bytes: usize,
        save_result: Option<bool>, // None = not attempted, Some(true) = saved, Some(false) = failed
        archive_issues: BTreeMap<String, usize>,
        source: ObjectSourceKind,
    },
    BlobFailed {
        kind: FailureKind,
    },
    CommitProcessed {
        email: String,
        name: String,
        findings: Vec<Finding>,
    },
    TreeProcessed {
        file_techs: Vec<(String, String)>, // (sha1, filename)
    },
    Skipped {
        reason: SkipReason,
    },
}

pub(crate) use crate::scan_scheduler::{AdaptiveConcurrency, AdaptiveConcurrencyGate};

// ════════════════════════════════════════════════
// MAIN STREAMER
// ════════════════════════════════════════════════

pub struct Streamer {
    client: HttpClient,
    workers: usize,
    mem_limit: usize,
    verbose: bool,
    /// Stop after collecting this many findings (0 = unlimited).
    max_findings: usize,
    /// Stop as soon as the first CRITICAL finding is encountered.
    stop_on_critical: bool,
    /// Runtime-loaded extra patterns (from `--patterns FILE`).
    extra_patterns: Arc<Vec<DynPattern>>,
    max_blob_size: usize,   // DX-2: in bytes
    entropy_threshold: f64, // DX-3
    live: bool,             // O-1
    adaptive: bool,         // P-1
    // R-1: Checkpoint support
    resume_from_checkpoint: bool, // Apply checkpoint resume only when --resume is enabled
    checkpoint_interval: usize,   // Save checkpoint every N blobs processed
    target_url: Option<String>,   // Target URL for checkpoint filename
    // PERF-005: Cache layer
    cache: Option<Arc<crate::cache::ObjectCache>>,
    cache_hits: Arc<AtomicUsize>,
    cache_misses: Arc<AtomicUsize>,
    // PERF-004: Rate limit metrics
    rate_limit_allowed: Arc<AtomicUsize>,
    rate_limit_dropped: Arc<AtomicUsize>,
    rate_limit_wait_ms: Arc<AtomicU64>,
    // SCAN-001: Custom false-positive keywords for context-aware confidence scoring
    false_positive_keywords: Arc<Vec<String>>,
    exhaustive: bool,
    /// Complete runtime settings used for checkpoint compatibility.
    config_snapshot: checkpoint::ScanConfigSnapshot,
}

impl Streamer {
    pub(crate) fn new(config: crate::streamer_config::StreamerConfig) -> Self {
        Self {
            client: config.client,
            workers: config.workers,
            mem_limit: config.mem_limit_mb * 1024 * 1024,
            verbose: config.verbose,
            max_findings: config.max_findings,
            stop_on_critical: config.stop_on_critical,
            extra_patterns: Arc::new(config.extra_patterns),
            max_blob_size: config.max_blob_size * 1024 * 1024,
            entropy_threshold: config.entropy_threshold,
            live: config.live,
            adaptive: config.adaptive,
            resume_from_checkpoint: config.resume_from_checkpoint,
            checkpoint_interval: config.checkpoint_interval,
            target_url: config.target_url,
            cache: config.cache,
            cache_hits: Arc::new(AtomicUsize::new(0)),
            cache_misses: Arc::new(AtomicUsize::new(0)),
            rate_limit_allowed: Arc::new(AtomicUsize::new(0)),
            rate_limit_dropped: Arc::new(AtomicUsize::new(0)),
            rate_limit_wait_ms: Arc::new(AtomicU64::new(0)),
            false_positive_keywords: Arc::new(config.false_positive_keywords),
            exhaustive: config.exhaustive,
            config_snapshot: config.config_snapshot,
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
        let config_fingerprint = self
            .config_snapshot
            .fingerprint()
            .unwrap_or_else(|_| "snapshot-unavailable".to_string());

        // Create save directory upfront if --save is active
        if let Some(ref dir) = save_dir {
            let _ = std::fs::create_dir_all(dir);
        }
        let save_dir_arc: Option<Arc<PathBuf>> = save_dir.map(Arc::new);

        // Build sha1→filename lookup and current-blob set upfront
        // FIXED: Use complete_sha1_to_file() which includes both index and graph-derived mappings
        let sha1_to_file: HashMap<String, String> = map_result.complete_sha1_to_file();

        // Sprint 5 (S5.3): full multi-path mapping — SHA1 → every known path.
        // A blob at multiple paths (LICENSE copies, generated stubs, shared fixtures)
        // used to be written to only one location. We derive the full multi-path
        // map here and thread just the extra paths (beyond the primary) through
        // to the writer so `--save` reconstructs every location.
        let full_paths_map: HashMap<String, Vec<String>> = map_result.complete_sha1_to_files();
        // "Extras" = paths beyond the first, keyed by SHA1. Empty vec for SHA1s that
        // only have one path (the vast majority).
        let sha1_extras: HashMap<String, Vec<String>> = full_paths_map
            .iter()
            .filter_map(|(sha1, paths)| {
                if paths.len() > 1 {
                    Some((sha1.clone(), paths[1..].to_vec()))
                } else {
                    None
                }
            })
            .collect();
        let current_blobs = map_result.blob_sha1s.clone();
        let sha1_to_file = Arc::new(sha1_to_file);
        let sha1_extras = Arc::new(sha1_extras);
        let current_blobs = Arc::new(current_blobs);

        // Sprint 5 (S5.1): pack-resolved objects as loose-encoded bytes. When
        // the target repo is pack-only (post-`git gc`, `.git/objects/xx/yy`
        // returns 404 for everything), fetch_and_process now serves out of this
        // map instead of hammering the server with 404s.
        let pack_objects: Arc<HashMap<String, Vec<u8>>> = Arc::new(map_result.pack_objects.clone());

        // Priority: deleted & sensitive files first (high value historical secrets)
        //           then deleted files, then sensitive files, then regular files
        let mut priority_blobs: Vec<String> = map_result.blob_sha1s.iter().cloned().collect();
        let other_sha1s: Vec<String> = map_result.commit_sha1s.iter().cloned().collect();

        // ENHANCED: Prioritize deleted files (historical secrets) and sensitive files
        priority_blobs.sort_by(|a, b| {
            let a_path = sha1_to_file.get(a).map(|s| s.as_str()).unwrap_or("");
            let b_path = sha1_to_file.get(b).map(|s| s.as_str()).unwrap_or("");

            let a_deleted = !current_blobs.contains(a);
            let b_deleted = !current_blobs.contains(b);

            let a_sensitive = is_sensitive_file(a_path);
            let b_sensitive = is_sensitive_file(b_path);

            // Priority order: deleted & sensitive > deleted > sensitive > regular
            match (a_deleted && a_sensitive, b_deleted && b_sensitive) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => match (a_deleted, b_deleted) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => match (a_sensitive, b_sensitive) {
                        (true, false) => std::cmp::Ordering::Less,
                        (false, true) => std::cmp::Ordering::Greater,
                        _ => std::cmp::Ordering::Equal,
                    },
                },
            }
        });

        // Deduplicate — the union of blob + commit sets can overlap after MapResult processing
        let all_sha1s: Vec<String> = {
            let mut seen = HashSet::with_capacity(priority_blobs.len() + other_sha1s.len());
            priority_blobs
                .into_iter()
                .chain(other_sha1s)
                .filter(|s| seen.insert(s.clone()))
                .collect()
        };
        let total = all_sha1s.len();

        // R-1: Checkpoint & Resume logic
        let mut checkpoint: Option<Checkpoint> = None;
        let mut restored_accumulator: Option<checkpoint::StreamAccumulatorCheckpoint> = None;
        let mut processed_sha1s_set: HashSet<String> = HashSet::new();
        let target_for_checkpoint = self.target_url.as_ref().unwrap_or(&git_url);

        // Load checkpoint only when resume mode is explicitly enabled
        if self.resume_from_checkpoint {
            if let Ok(Some(loaded)) = checkpoint::load_checkpoint(target_for_checkpoint) {
                if self.verbose {
                    let ts = chrono::DateTime::<chrono::Utc>::from_timestamp(
                        loaded.updated_at as i64,
                        0,
                    )
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| "unknown".to_string());
                    println!("  [R] Found checkpoint from {}", ts);
                }

                // Verify we're in STREAM phase and, for modern checkpoints,
                // that the complete scan configuration is unchanged.
                if matches!(loaded.phase, CheckpointPhase::Stream) {
                    let snapshot_compatible = loaded
                        .config_snapshot
                        .as_ref()
                        .map(|snapshot| {
                            snapshot == &self.config_snapshot
                                && loaded.config_fingerprint == config_fingerprint
                        })
                        // V1/V2 checkpoints created before the snapshot field
                        // remain readable and retain the legacy resume behavior.
                        .unwrap_or(true);
                    if snapshot_compatible {
                        if let Some(ref stream_prog) = loaded.stream_progress {
                            processed_sha1s_set =
                                stream_prog.processed_sha1s.clone().into_iter().collect();
                            restored_accumulator = stream_prog.accumulator.clone();
                            checkpoint = Some(loaded.clone());

                            if self.verbose {
                                if loaded.config_snapshot.is_none() {
                                    println!(
                                        "  [R] Resuming legacy checkpoint without config snapshot"
                                    );
                                }
                                println!(
                                    "  [R] Resuming from checkpoint: {} SHA1s already processed",
                                    processed_sha1s_set.len()
                                );
                            }
                        }
                    } else if self.verbose {
                        println!(
                            "  [R] Checkpoint configuration differs from the current scan; starting a fresh stream"
                        );
                    }
                }
            }
        }

        // Filter out already-processed SHA1s
        let filtered_sha1s: Vec<String> = all_sha1s
            .into_iter()
            .filter(|s| !processed_sha1s_set.contains(s))
            .collect();

        let actual_total = filtered_sha1s.len();
        let skipped_count = total - actual_total;

        if self.verbose {
            if skipped_count > 0 {
                println!(
                    "  [*] Skipping {} already-processed objects (from checkpoint)",
                    skipped_count
                );
            }
            println!(
                "  [*] Streaming {} objects ({} blobs + {} commit/tree graph)...",
                actual_total,
                map_result.blob_sha1s.len(),
                map_result.commit_sha1s.len(),
            );
        }

        let done_counter = Arc::new(AtomicUsize::new(processed_sha1s_set.len()));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let resource_budget = Arc::new(ResourceBudget::new(self.mem_limit));

        // R-1: Track processed SHA1s for checkpoint resume (BUG-CONC-002: use tokio::sync::Mutex for async context)
        // BUG-STAB-010: Fixed - Initialize tracker with already-processed SHA1s from checkpoint
        let processed_sha1s_tracker = Arc::new(TokioMutex::new(processed_sha1s_set.clone()));

        // PERF-003: Create adaptive concurrency controller BEFORE stream to use correct worker count
        // BUG-STAB-004: Fixed - adaptive_concurrency created before buffer_unordered
        let mut adaptive_concurrency = if self.adaptive {
            // Try to restore from checkpoint
            if let Some(ref cp) = checkpoint {
                if let Some(ref stream_prog) = cp.stream_progress {
                    if let Some(ref adaptive_state) = stream_prog.adaptive_state {
                        Some(AdaptiveConcurrency::from_checkpoint(
                            adaptive_state.clone(),
                            self.verbose,
                        ))
                    } else {
                        Some(AdaptiveConcurrency::new(self.workers, self.verbose))
                    }
                } else {
                    Some(AdaptiveConcurrency::new(self.workers, self.verbose))
                }
            } else {
                Some(AdaptiveConcurrency::new(self.workers, self.verbose))
            }
        } else {
            None
        };

        // BUG-STAB-004: Use adaptive current_workers() if enabled, otherwise default workers
        let initial_workers = adaptive_concurrency
            .as_ref()
            .map(|ac| ac.current_workers())
            .unwrap_or(self.workers);

        if let Some(ref ac) = adaptive_concurrency {
            if self.verbose {
                eprintln!(
                    "  [ADAPTIVE] Concurrency control enabled. Starting with {} workers",
                    ac.current_workers()
                );
            }
        }

        let mem_limit = self.mem_limit;
        let extra_pat = self.extra_patterns.clone();
        let max_scan_bytes = self.max_blob_size;
        let entropy_thresh = self.entropy_threshold;
        let verbose_flag = self.verbose;
        let cache = self.cache.clone();
        let cache_hits = self.cache_hits.clone();
        let cache_misses = self.cache_misses.clone();
        let adaptive_enabled = self.adaptive;
        let concurrency_gate = AdaptiveConcurrencyGate::new(initial_workers);

        let stream = futures::stream::iter(filtered_sha1s)
            .map(|sha1| {
                let client = self.client.clone();
                let git_url = git_url.clone();
                let sha1_to_file = sha1_to_file.clone();
                let sha1_extras = sha1_extras.clone();
                let current_blobs = current_blobs.clone();
                let pack_objects = pack_objects.clone();
                let save_dir = save_dir_arc.clone();
                let extra_patterns = extra_pat.clone();
                let stop_flag = stop_flag.clone();
                let resource_budget = resource_budget.clone();
                let cache = cache.clone();
                let cache_hits = cache_hits.clone();
                let cache_misses = cache_misses.clone();
                let fp_keywords = self.false_positive_keywords.clone();
                let processed_tracker = processed_sha1s_tracker.clone();
                let concurrency_gate = concurrency_gate.clone();
                async move {
                    let _permit = concurrency_gate.acquire().await;
                    let result = crate::object_worker::fetch_and_process(
                        &client,
                        &git_url,
                        &sha1,
                        &sha1_to_file,
                        &sha1_extras,
                        &current_blobs,
                        &pack_objects,
                        save_dir,
                        extra_patterns,
                        stop_flag,
                        mem_limit,
                        resource_budget,
                        max_scan_bytes,
                        entropy_thresh,
                        verbose_flag,
                        cache,
                        cache_hits,
                        cache_misses,
                        fp_keywords,
                        self.exhaustive,
                    )
                    .await;
                    // R-1: Register processed SHA1 on success (BUG-CON-002: use .lock().await for tokio::sync::Mutex)
                    if !matches!(
                        result,
                        WorkerResult::Skipped { .. } | WorkerResult::BlobFailed { .. }
                    ) {
                        let mut tracker = processed_tracker.lock().await;
                        tracker.insert(sha1.to_string());
                    }
                    result
                }
            })
            // BUG-STAB-004: Use initial_workers (includes adaptive restored value if applicable)
            .buffer_unordered(initial_workers);

        let mut state = State::default();
        if let Some(snapshot) = restored_accumulator {
            self.cache_hits
                .store(snapshot.cache_hits, Ordering::Relaxed);
            self.cache_misses
                .store(snapshot.cache_misses, Ordering::Relaxed);
            self.rate_limit_allowed
                .store(snapshot.rate_limit_allowed, Ordering::Relaxed);
            self.rate_limit_dropped
                .store(snapshot.rate_limit_dropped, Ordering::Relaxed);
            self.rate_limit_wait_ms
                .store(snapshot.rate_limit_wait_ms, Ordering::Relaxed);
            state.restore_checkpoint(snapshot);
        }

        // BUG-STAB-011: Restore findings from checkpoint for resume capability
        if let Some(ref cp) = checkpoint {
            if let Some(ref stream_prog) = cp.stream_progress {
                if !stream_prog.findings.is_empty() {
                    state.findings = stream_prog
                        .findings
                        .iter()
                        .map(|fc| Finding::from(fc.clone()))
                        .collect();
                    if self.verbose {
                        println!(
                            "  [R] Restored {} findings from checkpoint",
                            state.findings.len()
                        );
                    }
                }
            }
        }

        // Track current workers for buffer_unordered recreation
        let current_workers = Arc::new(AtomicUsize::new(initial_workers));

        futures::pin_mut!(stream);
        while let Some(result) = stream.next().await {
            let done = done_counter.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(ref cb) = progress_cb {
                cb(done, total);
            }

            // PERF-003: Track requests for adaptive concurrency
            let mut worker_result_failed = false;
            match result {
                WorkerResult::BlobScanned {
                    findings,
                    tech,
                    bytes,
                    save_result,
                    archive_issues,
                    source,
                } => {
                    state.blobs_scanned += 1;
                    for (issue, count) in archive_issues {
                        *state.archive_invalid_reasons.entry(issue).or_default() += count;
                    }
                    state.record_source(source);
                    state.bytes_scanned += bytes;
                    // O-1: Live output
                    if self.live {
                        for f in &findings {
                            println!(
                                "{}",
                                serde_json::to_string(&f.to_dict()).unwrap_or_default()
                            );
                        }
                    }
                    state.findings.extend(findings);
                    for t in tech {
                        state.tech_stack.insert(t);
                    }
                    match save_result {
                        Some(true) => state.files_saved += 1,
                        Some(false) => state.files_save_failed += 1,
                        None => {}
                    }
                }
                WorkerResult::BlobFailed { kind } => {
                    worker_result_failed = true;
                    state.blobs_failed += 1;
                    state.record_failure(kind);
                }
                WorkerResult::CommitProcessed {
                    email,
                    name,
                    findings,
                } => {
                    state.commit_count += 1;
                    // O-1: Live output for commit findings too
                    if self.live {
                        for f in &findings {
                            println!(
                                "{}",
                                serde_json::to_string(&f.to_dict()).unwrap_or_default()
                            );
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
                WorkerResult::Skipped { reason } => {
                    state.record_skip(reason);
                }
            }

            // PERF-003: Update adaptive concurrency tracking
            if adaptive_enabled {
                if let Some(ref mut ac) = adaptive_concurrency {
                    if worker_result_failed {
                        ac.record_error();
                    } else {
                        ac.record_success();
                    }
                }
            }

            // PERF-003: Check and adjust adaptive concurrency periodically
            if adaptive_enabled {
                if let Some(ref mut ac) = adaptive_concurrency {
                    if ac.should_adjust(done) {
                        let old_workers = current_workers.load(Ordering::Relaxed);
                        let new_workers = ac.adjust(done);
                        current_workers.store(new_workers, Ordering::Relaxed);
                        concurrency_gate.set_limit(new_workers);
                        // The gate applies the adjusted limit to subsequent work in
                        // this stream while existing operations drain naturally.
                        if self.verbose && new_workers != old_workers {
                            eprintln!(
                                "  [ADAPTIVE] Worker count adjusted: {} → {}",
                                old_workers, new_workers
                            );
                        }
                    }
                }
            }

            // Check early-stop conditions
            let hit_limit = self.max_findings > 0 && state.findings.len() >= self.max_findings;
            let hit_critical = self.stop_on_critical
                && state
                    .findings
                    .iter()
                    .rev()
                    .take(20)
                    .any(|f| f.severity == "CRITICAL");
            if hit_limit || hit_critical {
                stop_flag.store(true, Ordering::Relaxed);
                if self.verbose {
                    if hit_limit {
                        println!(
                            "\n  [!] Reached --max-findings limit ({}). Stopping scan.",
                            self.max_findings
                        );
                    } else {
                        println!("\n  [!] --stop-on-critical triggered. Stopping scan.");
                    }
                }
                break;
            }

            // R-1: Save checkpoint periodically (every checkpoint_interval blobs)
            if self.checkpoint_interval > 0
                && done.is_multiple_of(self.checkpoint_interval)
                && self.target_url.is_some()
            {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // PERF-003: Include adaptive state in checkpoint
                let adaptive_state = if adaptive_enabled {
                    adaptive_concurrency
                        .as_ref()
                        .map(|ac| ac.to_checkpoint_state())
                } else {
                    None
                };

                // R-1: Collect processed SHA1s for checkpoint resume (BUG-CON-002: await tokio::sync::Mutex lock)
                let processed_list = {
                    let tracker = processed_sha1s_tracker.lock().await;
                    ordered_processed_sha1s(&tracker)
                };

                let accumulator = state.to_checkpoint(
                    self.cache_hits.load(Ordering::Relaxed),
                    self.cache_misses.load(Ordering::Relaxed),
                    self.rate_limit_allowed.load(Ordering::Relaxed),
                    self.rate_limit_dropped.load(Ordering::Relaxed),
                    self.rate_limit_wait_ms.load(Ordering::Relaxed),
                );
                let new_checkpoint = Checkpoint {
                    version: checkpoint::CheckpointVersion::latest(),
                    target: target_for_checkpoint.clone(),
                    created_at: checkpoint.as_ref().map(|c| c.created_at).unwrap_or(now),
                    updated_at: now,
                    phase: CheckpointPhase::Stream,
                    // Stable fingerprint over the complete runtime configuration.
                    config_fingerprint: config_fingerprint.clone(),
                    config_snapshot: Some(self.config_snapshot.clone()),
                    detect_result: None,
                    map_result: None,
                    stream_progress: Some(StreamCheckpoint {
                        total_sha1s: actual_total,
                        processed_sha1s: processed_list, // Save actual processed SHA1s for resume
                        findings_count: state.findings.len(),
                        // BUG-STAB-011: Save findings to checkpoint for resume capability
                        findings: state
                            .findings
                            .iter()
                            .map(|f| checkpoint::FindingCheckpoint::from(f.clone()))
                            .collect(),
                        last_checkpoint_index: done,
                        accumulator: Some(accumulator),
                        adaptive_state,
                    }),
                    hmac: None, // BUG-SEC-005: Will be computed in save_checkpoint()
                };

                if let Err(e) = checkpoint::save_checkpoint(&new_checkpoint) {
                    if self.verbose {
                        eprintln!("  [R] Failed to save checkpoint: {}", e);
                    }
                } else if self.verbose {
                    println!("  [R] Checkpoint saved at blob {}/{}", done, actual_total);
                    if let Some(ref ac) = adaptive_concurrency {
                        eprintln!(
                            "  [R] Adaptive state: {} workers, {} req, {} err in window",
                            ac.current_workers(),
                            ac.window_counts().0,
                            ac.window_counts().1
                        );
                    }
                }

                checkpoint = Some(new_checkpoint);
            }
        }

        // BUG-STAB-012: Save final checkpoint before completion to prevent findings loss
        // This ensures all findings generated during the stream are captured before exiting
        if self.checkpoint_interval > 0 && self.target_url.is_some() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // PERF-003: Include adaptive state in final checkpoint
            let adaptive_state = if adaptive_enabled {
                adaptive_concurrency
                    .as_ref()
                    .map(|ac| ac.to_checkpoint_state())
            } else {
                None
            };

            // R-1: Collect processed SHA1s for final checkpoint
            let processed_list: Vec<String> = {
                let tracker = processed_sha1s_tracker.lock().await;
                ordered_processed_sha1s(&tracker)
            };
            let accumulator = state.to_checkpoint(
                self.cache_hits.load(Ordering::Relaxed),
                self.cache_misses.load(Ordering::Relaxed),
                self.rate_limit_allowed.load(Ordering::Relaxed),
                self.rate_limit_dropped.load(Ordering::Relaxed),
                self.rate_limit_wait_ms.load(Ordering::Relaxed),
            );

            let final_checkpoint = Checkpoint {
                version: checkpoint::CheckpointVersion::latest(),
                target: target_for_checkpoint.clone(),
                created_at: checkpoint.as_ref().map(|c| c.created_at).unwrap_or(now),
                updated_at: now,
                phase: CheckpointPhase::Stream,
                config_fingerprint: config_fingerprint.clone(),
                config_snapshot: Some(self.config_snapshot.clone()),
                detect_result: None,
                map_result: None,
                stream_progress: Some(StreamCheckpoint {
                    total_sha1s: actual_total,
                    processed_sha1s: processed_list,
                    findings_count: state.findings.len(),
                    // BUG-STAB-012: Include all findings in final checkpoint
                    findings: state
                        .findings
                        .iter()
                        .map(|f| checkpoint::FindingCheckpoint::from(f.clone()))
                        .collect(),
                    last_checkpoint_index: done_counter.load(Ordering::Relaxed),
                    accumulator: Some(accumulator),
                    adaptive_state,
                }),
                hmac: None, // BUG-SEC-005: Will be computed in save_checkpoint()
            };

            // BUG-STAB-012: Ensure final checkpoint is saved before returning
            if let Err(e) = checkpoint::save_checkpoint(&final_checkpoint) {
                if self.verbose {
                    eprintln!("  [R] Failed to save final checkpoint: {}", e);
                }
            } else if self.verbose {
                println!(
                    "  [R] Final checkpoint saved with {} findings",
                    state.findings.len()
                );
            }
        }

        let mut outcome_stats = ScanOutcomeStats::from_state(&state);
        let resource_stats = resource_budget.stats();
        outcome_stats.resource_peak_bytes = resource_stats.peak_bytes;
        outcome_stats.resource_denied_reservations = resource_stats.denied_reservations;
        let elapsed = t0.elapsed().as_secs_f64();
        let mut ts: Vec<_> = state.tech_stack.iter().cloned().collect();
        ts.sort();

        // PERF-005: Extract cache stats (BUG-ERR-009: now async)
        let cache_hits_final = self.cache_hits.load(Ordering::Relaxed);
        let cache_misses_final = self.cache_misses.load(Ordering::Relaxed);
        let cache_stats_final = if let Some(ref cache) = self.cache {
            let stats = cache.stats().await;
            Some(CacheReportStats {
                total_entries: stats.total_entries,
                total_bytes: stats.total_bytes,
                expired_entries: stats.expired_entries,
                evicted_entries: stats.evicted_entries,
                evicted_bytes: stats.evicted_bytes,
                size_human: stats.size_human(),
            })
        } else {
            None
        };

        // PERF-004: Extract rate limit metrics
        let rate_limit_allowed_final = self.rate_limit_allowed.load(Ordering::Relaxed);
        let rate_limit_dropped_final = self.rate_limit_dropped.load(Ordering::Relaxed);
        let rate_limit_wait_ms_final = self.rate_limit_wait_ms.load(Ordering::Relaxed);

        StreamResult {
            findings: state.findings,
            contributors: state
                .contributors
                .iter()
                .map(|(email, name)| Contributor {
                    name: name.clone(),
                    email: email.clone(),
                })
                .collect(),
            tech_stack: ts,
            commit_count: state.commit_count,
            blobs_scanned: state.blobs_scanned,
            blobs_failed: state.blobs_failed,
            bytes_scanned: state.bytes_scanned,
            elapsed_s: elapsed,
            files_saved: state.files_saved,
            files_save_failed: state.files_save_failed,
            // PERF-005: Cache metrics
            cache_hits: cache_hits_final,
            cache_misses: cache_misses_final,
            cache_stats: cache_stats_final,
            object_source_stats: ObjectSourceStats {
                pack: *state
                    .objects_by_source
                    .get(&ObjectSourceKind::Pack)
                    .unwrap_or(&0),
                cache: *state
                    .objects_by_source
                    .get(&ObjectSourceKind::Cache)
                    .unwrap_or(&0),
                loose_http: *state
                    .objects_by_source
                    .get(&ObjectSourceKind::LooseHttp)
                    .unwrap_or(&0),
                forge: 0,
            },
            outcome_stats,
            // PERF-004: Rate limit metrics
            rate_limit_allowed: rate_limit_allowed_final,
            rate_limit_dropped: rate_limit_dropped_final,
            rate_limit_wait_ms: rate_limit_wait_ms_final,
            retry_stats: Some(self.client.retry_metrics.snapshot()),
        }
    }
}

// ════════════════════════════════════════════════
// PER-SHA1 PROCESSING (async, lock-free)
// ════════════════════════════════════════════════

/// Max blob content size to scan (4 MB). Larger blobs are skipped.
#[allow(dead_code)]
const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;

/// PERF-005: Process blob content (shared between cache and fetch paths)
///
/// This helper function processes raw blob content and returns a WorkerResult.
/// It's called from both the cache hit path (when content is already cached)
/// and the fetch path (when content was just downloaded).
/// BUG-STAB-001/STAB-002: Uses BudgetGuard for RAII-style budget management.
#[allow(clippy::too_many_arguments)]
pub(crate) fn process_blob_content(
    content: &[u8],
    sha1: &str,
    sha1_to_file: &HashMap<String, String>,
    sha1_extras: &HashMap<String, Vec<String>>,
    current_blobs: &HashSet<String>,
    save_dir: Option<Arc<PathBuf>>,
    extra_patterns: Arc<Vec<DynPattern>>,
    mem_limit: usize,
    resource_budget: Arc<ResourceBudget>,
    max_scan_bytes: usize,
    entropy_threshold: f64,
    verbose: bool,
    false_positive_keywords: Arc<Vec<String>>,
    exhaustive: bool,
) -> WorkerResult {
    let parser = ObjectParser;
    let obj = match parser.parse(content, sha1) {
        Some(o) => o,
        None => {
            return WorkerResult::Skipped {
                reason: SkipReason::InvalidObject,
            };
        }
    };

    let raw_bytes = content.len();

    match obj.obj_type.as_str() {
        "blob" => {
            // Persist blob to disk first, before any scan-skip guards.
            //
            // For blobs WITHOUT a filename mapping (deep-history blobs discovered via pack
            // enumeration or commit-graph walks beyond `max_commits`, dangling refs, etc.)
            // we still write the content under an `_unreferenced/<xx>/<rest>` fallback path
            // so the reconstruction is lossless. Previously these were silently dropped —
            // `save_result = None` — leaving the local tree incomplete with no diagnostic.
            //
            // Sprint 5 (S5.3): when a blob is referenced at multiple paths (LICENSE
            // copies, duplicate config, etc.) `sha1_extras` carries the secondary
            // paths. We hard_link (or copy on failure) each extra so every location
            // materialises. The primary write's success dictates `save_result`; extras
            // are best-effort — if hard_link fails on cross-fs mounts, we fall back
            // to a full write.
            let save_result = if let Some(ref dir) = save_dir {
                if let Some(actual_name) = sha1_to_file.get(sha1) {
                    let primary_ok = write_blob_to_disk(actual_name, &obj.data, dir);
                    if primary_ok {
                        // Materialise every secondary path.
                        if let Some(extras) = sha1_extras.get(sha1) {
                            for extra_path in extras {
                                let _ = write_or_link(actual_name, extra_path, &obj.data, dir);
                            }
                        }
                    }
                    Some(primary_ok)
                } else if sha1.len() >= 3 {
                    let fallback = format!("_unreferenced/{}/{}", &sha1[..2], &sha1[2..]);
                    Some(write_blob_to_disk(&fallback, &obj.data, dir))
                } else {
                    None
                }
            } else {
                None
            };

            let filename = sha1_to_file
                .get(sha1)
                .cloned()
                .unwrap_or_else(|| format!("[blob:{}]", &sha1[..sha1.len().min(8)]));
            let is_deleted = !current_blobs.contains(sha1);

            // Binary dispatch prioritizes magic bytes, then filename extension,
            // and finally retains the legacy null-byte signal for unknown data.
            let dispatch = binary_scanner::classify_binary(&obj.data, &filename, 8192, 10);
            let mut archive_issues = BTreeMap::new();
            if dispatch.is_binary() {
                // S-3: Enhanced binary file scanning
                let bin_type = dispatch.binary_type;
                let (binary_findings, binary_telemetry) =
                    binary_scanner::scan_binary_blob_with_patterns_and_telemetry(
                        &obj.data,
                        &filename,
                        max_scan_bytes,
                        &extra_patterns,
                    );
                archive_issues = binary_telemetry.archive_issues;

                // Handle different binary types
                if matches!(bin_type, binary_scanner::BinaryType::SQLite) {
                    // Enhanced SQLite scanning with table querying
                    let binary_findings = binary_findings.clone();

                    if !binary_findings.is_empty() {
                        let fp_keywords: Vec<&str> =
                            false_positive_keywords.iter().map(|s| s.as_str()).collect();
                        let findings = normalize_binary_findings(
                            binary_findings,
                            BinaryFindingContext {
                                filename: &filename,
                                sha1,
                                is_deleted,
                                fallback_description: "Binary Secret",
                                context_keywords: Some(&fp_keywords),
                                include_placeholders: exhaustive,
                                extra_patterns: &extra_patterns,
                            },
                        );

                        return WorkerResult::BlobScanned {
                            findings,
                            tech: vec![],
                            bytes: raw_bytes,
                            save_result,
                            archive_issues: archive_issues.clone(),
                            source: ObjectSourceKind::LooseHttp,
                        };
                    }
                }

                // Handle ZIP/JAR archives
                if matches!(bin_type, binary_scanner::BinaryType::ZipJar) {
                    let binary_findings = binary_findings.clone();

                    if !binary_findings.is_empty() {
                        let findings = normalize_binary_findings(
                            binary_findings,
                            BinaryFindingContext {
                                filename: &filename,
                                sha1,
                                is_deleted,
                                fallback_description: "ZIP Secret",
                                context_keywords: None,
                                include_placeholders: exhaustive,
                                extra_patterns: &extra_patterns,
                            },
                        );
                        return WorkerResult::BlobScanned {
                            findings,
                            tech: vec![],
                            bytes: raw_bytes,
                            save_result,
                            archive_issues: archive_issues.clone(),
                            source: ObjectSourceKind::LooseHttp,
                        };
                    }
                }

                // Handle ELF binaries
                if matches!(bin_type, binary_scanner::BinaryType::Elf) {
                    let binary_findings = binary_findings.clone();

                    if !binary_findings.is_empty() {
                        let findings = normalize_binary_findings(
                            binary_findings,
                            BinaryFindingContext {
                                filename: &filename,
                                sha1,
                                is_deleted,
                                fallback_description: "ELF Secret",
                                context_keywords: None,
                                include_placeholders: exhaustive,
                                extra_patterns: &extra_patterns,
                            },
                        );
                        return WorkerResult::BlobScanned {
                            findings,
                            tech: vec![],
                            bytes: raw_bytes,
                            save_result,
                            archive_issues: archive_issues.clone(),
                            source: ObjectSourceKind::LooseHttp,
                        };
                    }
                }

                // GZIP may contain text even when its compressed bytes do not have
                // enough nulls to trigger the legacy binary branch above.
                if matches!(bin_type, binary_scanner::BinaryType::Gzip) {
                    let binary_findings = binary_findings.clone();
                    let fp_keywords: Vec<&str> =
                        false_positive_keywords.iter().map(|s| s.as_str()).collect();
                    let findings = normalize_binary_findings(
                        binary_findings,
                        BinaryFindingContext {
                            filename: &filename,
                            sha1,
                            is_deleted,
                            fallback_description: "GZIP Secret",
                            context_keywords: Some(&fp_keywords),
                            include_placeholders: exhaustive,
                            extra_patterns: &extra_patterns,
                        },
                    );
                    return WorkerResult::BlobScanned {
                        findings,
                        tech: vec![],
                        bytes: raw_bytes,
                        save_result,
                        archive_issues: archive_issues.clone(),
                        source: ObjectSourceKind::LooseHttp,
                    };
                }

                // Unknown binary content still receives the printable-string
                // scanner. This preserves discovery coverage for unsupported
                // formats and extension-only binary fixtures.
                if matches!(bin_type, binary_scanner::BinaryType::Unknown) {
                    let binary_findings = binary_findings.clone();
                    let fp_keywords: Vec<&str> =
                        false_positive_keywords.iter().map(|s| s.as_str()).collect();
                    let findings = normalize_binary_findings(
                        binary_findings,
                        BinaryFindingContext {
                            filename: &filename,
                            sha1,
                            is_deleted,
                            fallback_description: "Binary Secret",
                            context_keywords: Some(&fp_keywords),
                            include_placeholders: exhaustive,
                            extra_patterns: &extra_patterns,
                        },
                    );
                    return WorkerResult::BlobScanned {
                        findings,
                        tech: vec![],
                        bytes: raw_bytes,
                        save_result,
                        archive_issues: archive_issues.clone(),
                        source: ObjectSourceKind::LooseHttp,
                    };
                }

                return WorkerResult::BlobScanned {
                    findings: vec![],
                    tech: vec![],
                    bytes: raw_bytes,
                    save_result,
                    archive_issues: archive_issues.clone(),
                    source: ObjectSourceKind::LooseHttp,
                };
            }

            // Skip blobs that exceed the per-blob scan size limit
            let blob_size = obj.data.len();
            let per_blob_limit = if mem_limit > 0 {
                (mem_limit / 4).min(max_scan_bytes)
            } else {
                max_scan_bytes
            };
            if blob_size > per_blob_limit {
                if verbose {
                    let blob_size_mb = blob_size as f64 / 1024.0 / 1024.0;
                    let max_size_mb = max_scan_bytes as f64 / 1024.0 / 1024.0;
                    eprintln!(
                        "  [!] Blob {} ({:.2} MB) exceeds --max-blob-size {:.0}MB, skipping scan",
                        &sha1[..8],
                        blob_size_mb,
                        max_size_mb
                    );
                }
                return WorkerResult::BlobScanned {
                    findings: vec![],
                    tech: vec![],
                    bytes: raw_bytes,
                    save_result,
                    archive_issues: archive_issues.clone(),
                    source: ObjectSourceKind::LooseHttp,
                };
            }

            // BUG-STAB-001/STAB-002: Use RAII BudgetGuard for atomic budget reservation
            // This ensures budget is always released, even on early returns or panics.
            let _budget_guard =
                match resource_budget.try_reserve(ResourceStage::ObjectScan, blob_size) {
                    Some(guard) => guard,
                    None => {
                        // Memory budget exhausted: surface a typed skip instead
                        // of presenting the object as successfully scanned.
                        return WorkerResult::Skipped {
                            reason: SkipReason::ResourceBudget,
                        };
                    }
                };

            // Collect tech tags from filename
            let mut tech_set: HashSet<String> = HashSet::new();
            {
                let mut v = Vec::new();
                collect_tech(&filename, &mut v);
                tech_set.extend(v);
            }

            let content_str = match std::str::from_utf8(&obj.data) {
                Ok(s) => s.to_string(),
                Err(_) => String::from_utf8_lossy(&obj.data).into_owned(),
            };

            // Supplement with content-based tech detection
            detect_tech_from_content(&content_str, &mut tech_set);
            let tech: Vec<String> = tech_set.into_iter().collect();

            let shared_scanner = ContentScanner::new(
                extra_patterns.clone(),
                exhaustive,
                entropy_threshold,
                max_scan_bytes,
                false,
            );
            let findings = shared_scanner.scan_text_object(
                &content_str,
                &filename,
                sha1,
                is_deleted,
                &false_positive_keywords,
            );

            // BUG-STAB-002: Budget is automatically released when _budget_guard drops here
            WorkerResult::BlobScanned {
                findings,
                tech,
                bytes: raw_bytes,
                save_result,
                archive_issues: archive_issues.clone(),
                source: ObjectSourceKind::LooseHttp,
            }
        }
        "commit" => {
            let parser = ObjectParser;
            if let Some(commit) = parser.parse_commit(&obj) {
                let msg_findings = if !commit.message.is_empty() {
                    let fp_keywords: Vec<&str> =
                        false_positive_keywords.iter().map(|s| s.as_str()).collect();
                    let policy = if exhaustive {
                        ScanPolicy::exhaustive(entropy_threshold, &fp_keywords)
                    } else {
                        ScanPolicy::normal(entropy_threshold, &fp_keywords)
                    };
                    let message_filename =
                        format!("[commit:{}:message]", &sha1[..sha1.len().min(8)]);
                    scan_content_with_policy(
                        &commit.message,
                        &message_filename,
                        sha1,
                        false,
                        &extra_patterns,
                        policy,
                    )
                } else {
                    vec![]
                };
                WorkerResult::CommitProcessed {
                    email: commit.author_email,
                    name: commit.author,
                    findings: msg_findings,
                }
            } else {
                WorkerResult::Skipped {
                    reason: SkipReason::InvalidObject,
                }
            }
        }
        "tree" => {
            let parser = ObjectParser;
            let entries = parser.parse_tree(&obj);
            let file_techs: Vec<(String, String)> = entries
                .into_iter()
                .filter(|e| e.is_blob())
                .map(|e| (e.sha1, e.name))
                .collect();
            WorkerResult::TreeProcessed { file_techs }
        }
        _ => WorkerResult::Skipped {
            reason: SkipReason::InvalidObject,
        },
    }
}

pub(crate) fn attach_source(result: WorkerResult, source: ObjectSourceKind) -> WorkerResult {
    match result {
        WorkerResult::BlobScanned {
            findings,
            tech,
            bytes,
            save_result,
            archive_issues,
            ..
        } => WorkerResult::BlobScanned {
            findings,
            tech,
            bytes,
            save_result,
            archive_issues,
            source,
        },
        other => other,
    }
}

struct BinaryFindingContext<'a> {
    filename: &'a str,
    sha1: &'a str,
    is_deleted: bool,
    fallback_description: &'a str,
    context_keywords: Option<&'a [&'a str]>,
    include_placeholders: bool,
    extra_patterns: &'a [DynPattern],
}

fn normalize_binary_findings(
    binary_findings: Vec<(String, String, String, String)>,
    context: BinaryFindingContext<'_>,
) -> Vec<Finding> {
    let mut findings = binary_findings
        .into_iter()
        .filter(|(_, match_str, _, _)| context.include_placeholders || !is_placeholder(match_str))
        .map(|(pattern_id, match_str, context_text, _source)| {
            let (description, severity) = context
                .extra_patterns
                .iter()
                .find(|pattern| pattern.id == pattern_id)
                .map(|pattern| (pattern.desc.clone(), pattern.sev.clone()))
                .or_else(|| {
                    PATTERNS
                        .iter()
                        .find(|pattern| pattern.id == pattern_id)
                        .map(|pattern| (pattern.desc.to_string(), pattern.sev.to_string()))
                })
                .unwrap_or_else(|| (context.fallback_description.to_string(), "HIGH".to_string()));
            Finding {
                filename: context.filename.to_string(),
                line: 1,
                pattern_id,
                description,
                severity,
                match_str,
                context: context_text,
                is_deleted: context.is_deleted,
                commit_sha1: Some(context.sha1.to_string()),
                confidence_adjustment: None,
            }
        })
        .collect::<Vec<_>>();

    if let Some(keywords) = context.context_keywords {
        let contexts: Vec<String> = findings
            .iter()
            .map(|finding| finding.context.clone())
            .collect();
        let lines_ref: Vec<&str> = contexts.iter().map(String::as_str).collect();
        for finding in &mut findings {
            if let Some(reason) = analyze_context_for_binary(&lines_ref, 0, keywords) {
                finding.severity = downgrade_severity(&finding.severity).to_string();
                finding.confidence_adjustment = Some(reason);
            }
        }
    }
    findings
}

struct DetectorContext<'a> {
    filename: &'a str,
    sha1: &'a str,
    is_deleted: bool,
    extra_patterns: &'a [DynPattern],
    policy: ScanPolicy<'a>,
}

pub(crate) struct TextScanContext<'a> {
    pub(crate) content: &'a str,
    pub(crate) filename: &'a str,
    pub(crate) sha1: &'a str,
    pub(crate) is_deleted: bool,
    pub(crate) extra_patterns: &'a [DynPattern],
    pub(crate) entropy_threshold: f64,
    pub(crate) false_positive_keywords: &'a [String],
    pub(crate) exhaustive: bool,
}

pub(crate) fn scan_text_with_context(context: TextScanContext<'_>) -> Vec<Finding> {
    let keywords: Vec<&str> = context
        .false_positive_keywords
        .iter()
        .map(String::as_str)
        .collect();
    let policy = if context.exhaustive {
        ScanPolicy::exhaustive(context.entropy_threshold, &keywords)
    } else {
        ScanPolicy::normal(context.entropy_threshold, &keywords)
    };
    scan_text_detectors(
        context.content,
        DetectorContext {
            filename: context.filename,
            sha1: context.sha1,
            is_deleted: context.is_deleted,
            extra_patterns: context.extra_patterns,
            policy,
        },
    )
}

fn scan_text_detectors(content: &str, context: DetectorContext<'_>) -> Vec<Finding> {
    let mut findings = scan_content_with_policy(
        content,
        context.filename,
        context.sha1,
        context.is_deleted,
        context.extra_patterns,
        context.policy,
    );
    findings.extend(scan_yaml_nextline_secrets_with_policy(
        content,
        context.filename,
        context.sha1,
        context.is_deleted,
        context.policy.false_positive_keywords,
        context.policy.include_placeholders,
    ));
    findings.extend(scan_db_config_blocks_with_policy(
        content,
        context.filename,
        context.sha1,
        context.is_deleted,
        context.policy.false_positive_keywords,
        context.policy.include_placeholders,
    ));
    findings
}

#[cfg(test)]
fn scan_content(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    extra_patterns: &[DynPattern],
    entropy_threshold: f64,
    false_positive_keywords: &[&str],
) -> Vec<Finding> {
    scan_content_with_policy(
        content,
        filename,
        sha1,
        is_deleted,
        extra_patterns,
        ScanPolicy::normal(entropy_threshold, false_positive_keywords),
    )
}

fn scan_content_with_policy(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    extra_patterns: &[DynPattern],
    policy: ScanPolicy<'_>,
) -> Vec<Finding> {
    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();
    let is_js = is_js_file(filename);
    if let Some(path_finding) = ai_path_finding(filename, sha1, is_deleted) {
        findings.push(path_finding);
    }

    for (lineno, &line) in lines.iter().enumerate() {
        if line.len() > 2000 {
            // For minified JS/TS try scanning segments split at statement boundaries
            if is_js && line.len() <= 50_000 {
                scan_minified_segments(
                    line,
                    lineno,
                    filename,
                    sha1,
                    is_deleted,
                    false,
                    policy.false_positive_keywords,
                    &mut findings,
                );
            }
            continue;
        }

        let mut line_has_finding = false;

        // Static patterns
        for pattern_index in PATTERN_SET.matches(line).iter() {
            let pat = &PATTERNS[pattern_index];
            for m in pat.regex.find_iter(line) {
                let val = m.as_str().to_string();
                if !policy.include_placeholders && is_placeholder(&val) {
                    continue;
                }
                findings.push(Finding {
                    filename: filename.to_string(),
                    line: lineno + 1,
                    pattern_id: pat.id.to_string(),
                    description: pat.desc.to_string(),
                    severity: pat.sev.to_string(),
                    match_str: val,
                    context: build_context_window(&lines, lineno, 2),
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
                if !policy.include_placeholders && is_placeholder(&val) {
                    continue;
                }
                findings.push(Finding {
                    filename: filename.to_string(),
                    line: lineno + 1,
                    pattern_id: pat.id.clone(),
                    description: pat.desc.clone(),
                    severity: pat.sev.clone(),
                    match_str: val,
                    context: build_context_window(&lines, lineno, 2),
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
            scan_entropy_line_with_policy(
                line,
                lineno,
                filename,
                sha1,
                is_deleted,
                &lines,
                &mut findings,
                policy.entropy_threshold,
                policy.include_placeholders,
            );
        }
    }
    // S-1: SCAN-001 Enhanced context-aware confidence adjustment with custom keywords
    for f in findings.iter_mut() {
        if let Some(reason) = analyze_context(
            &lines,
            f.line.saturating_sub(1),
            policy.false_positive_keywords,
        ) {
            f.severity = downgrade_severity(&f.severity).to_string();
            f.confidence_adjustment = Some(reason);
        }
    }

    // S-2: Multi-line scan
    findings.extend(scan_multiline_with_policy(
        content,
        filename,
        sha1,
        is_deleted,
        policy.false_positive_keywords,
        policy.include_placeholders,
    ));
    findings
}
// ════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════

/// Write blob data to disk under `output_dir`, reconstructing directory structure.
///
/// Path sanitisation (Sprint 2, S2.8 — Linux primary, Windows guarded):
/// - Split on both `/` and `\` (Windows-style paths in tree entries).
/// - Reject empty, `.`, `..` components (path traversal).
/// - Reject NUL byte in any component (Linux allows it in bytes but the fs conventions
///   fail — better to refuse than corrupt).
/// - `#[cfg(windows)]`: reject reserved device names (CON, PRN, AUX, NUL, COM1-9,
///   LPT1-9) case-insensitive, drive letters (`C:foo`), trailing dot/space
///   (Windows silently strips those, letting attacker collide filenames).
/// - After joining, canonicalise both `output_dir` and the resolved path — this
///   defeats a symlink-under-output-dir escape (workspace contains `link` →
///   `../../etc`; naive `starts_with` on the un-canonicalised join would allow it).
///
/// Returns true if the file was written successfully.
/// Sprint 5 (S5.3) helper: write a secondary path for a blob that already exists
/// at `primary_filename`. Prefers `hard_link` for space efficiency (a repo with
/// 500 identical LICENSE files ends up as 1 inode + 500 dirents on ext4), falls
/// back to a full write if the underlying filesystem doesn't support hard links
/// (e.g. cross-filesystem or FAT32 exports).
///
/// All the sanitisation guards (NUL byte reject, Windows reserved names, symlink
/// escape canonicalisation) live in `write_blob_to_disk` — this helper delegates
/// to that for the fallback write path. For the hard-link path we still validate
/// the target path ourselves so we don't `link()` outside `output_dir`.
fn write_or_link(
    primary_filename: &str,
    extra_filename: &str,
    data: &[u8],
    output_dir: &Path,
) -> bool {
    // Resolve the two paths using the same sanitisation as write_blob_to_disk.
    // We do it via public API — compute the destination path and let the helper
    // decide whether it's safe.
    let src = resolve_safe_path(primary_filename, output_dir);
    let dst = resolve_safe_path(extra_filename, output_dir);
    if let (Some(src), Some(dst)) = (src, dst) {
        if src == dst {
            return true; // Nothing to do — same path.
        }
        if let Some(parent) = dst.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // hard_link fails if `dst` already exists → try to unlink first so the
        // caller's re-run behaviour matches write_blob_to_disk's truncate semantic.
        let _ = std::fs::remove_file(&dst);
        if std::fs::hard_link(&src, &dst).is_ok() {
            return true;
        }
        log::debug!(
            "write_or_link: hard_link {:?} -> {:?} failed, falling back to full write",
            src,
            dst
        );
    }
    // Fallback: write the extra path with fresh bytes.
    write_blob_to_disk(extra_filename, data, output_dir)
}

/// Sprint 5 (S5.3) helper: resolve `filename` inside `output_dir` using the same
/// sanitisation as `write_blob_to_disk` — but return the resolved path instead of
/// writing. Returns None if any component is rejected.
fn resolve_safe_path(filename: &str, output_dir: &Path) -> Option<PathBuf> {
    let normalized = filename.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".." && *p != ".")
        .collect();
    if parts.is_empty() {
        return None;
    }
    for p in &parts {
        if p.contains('\0') {
            return None;
        }
        #[cfg(windows)]
        {
            if is_windows_reserved_name(p) {
                return None;
            }
            if p.len() >= 2 && p.as_bytes()[1] == b':' {
                return None;
            }
            if p.ends_with('.') || p.ends_with(' ') {
                return None;
            }
        }
    }
    let local_path: PathBuf = parts
        .iter()
        .fold(output_dir.to_path_buf(), |acc, p| acc.join(p));
    if !local_path.starts_with(output_dir) {
        return None;
    }
    Some(local_path)
}

fn write_blob_to_disk(filename: &str, data: &[u8], output_dir: &Path) -> bool {
    let normalized = filename.replace('\\', "/");
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".." && *p != ".")
        .collect();
    if parts.is_empty() {
        return false;
    }

    // Sprint 2 (S2.8): additional per-component rejects.
    for p in &parts {
        if p.contains('\0') {
            return false;
        }
        #[cfg(windows)]
        {
            if is_windows_reserved_name(p) {
                return false;
            }
            // Drive-letter component (`C:foo`) or trailing dot/space that Windows
            // silently strips when opening.
            if p.len() >= 2 && p.as_bytes()[1] == b':' {
                return false;
            }
            if p.ends_with('.') || p.ends_with(' ') {
                return false;
            }
        }
    }

    let local_path: PathBuf = parts
        .iter()
        .fold(output_dir.to_path_buf(), |acc, p| acc.join(p));

    // Defense in depth #1: string-level prefix check (fast, catches obvious cases).
    if !local_path.starts_with(output_dir) {
        return false;
    }

    // Defense in depth #2 (Sprint 2, S2.8): canonicalise parent + verify prefix.
    // This closes the symlink-escape hole where `output_dir/link` points outside.
    // We canonicalise the PARENT because `local_path` itself doesn't exist yet;
    // canonicalising a non-existent path errors on Linux.
    let parent = match local_path.parent() {
        Some(p) => p,
        None => return false,
    };
    if let Err(e) = std::fs::create_dir_all(parent) {
        log::debug!(
            "write_blob_to_disk: create_dir_all({:?}) failed: {}",
            parent,
            e
        );
        return false;
    }
    if let (Ok(canonical_parent), Ok(canonical_root)) = (
        std::fs::canonicalize(parent),
        std::fs::canonicalize(output_dir),
    ) {
        if !canonical_parent.starts_with(&canonical_root) {
            // A symlink under output_dir points outside — refuse the write.
            log::warn!(
                "write_blob_to_disk: refusing to write outside output_dir (parent {:?} escapes {:?})",
                canonical_parent, canonical_root
            );
            return false;
        }
    }

    std::fs::write(&local_path, data).is_ok()
}

/// Sprint 2 (S2.8) helper: is `name` a Windows-reserved device name?
/// Matches base name case-insensitively, ignoring extension: `CON`, `con.txt`,
/// `COM1.log` all reserved. See MS docs on "Naming Files, Paths, and Namespaces".
#[cfg(windows)]
fn is_windows_reserved_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or(name);
    let upper = base.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
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
    SENSITIVE_NAMES.is_match(filename) || is_ai_sensitive_path(filename)
}

pub(crate) fn is_placeholder(s: &str) -> bool {
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
    if path_lc.contains(".claude/") || path_lc.starts_with(".claude/") {
        out.push("claude");
    }
    if path_lc.contains(".cursor/") || path_lc.starts_with(".cursor/") {
        out.push("cursor");
    }
    if path_lc.contains(".continue/") || path_lc.starts_with(".continue/") {
        out.push("continue");
    }
    if path_lc.contains(".aider") || path_lc.contains("/aider") {
        out.push("aider");
    }
    if path_lc.contains(".windsurf/") || path_lc.starts_with(".windsurf/") {
        out.push("windsurf");
    }
    if path_lc.contains("copilot") || path_lc.contains(".github/prompts") {
        out.push("copilot");
    }
    out
}

fn normalize_path_lc(path: &str) -> String {
    path.replace('\\', "/").to_lowercase()
}

fn is_ai_scope_path_lc(p: &str) -> bool {
    p.contains("/.claude/")
        || p.starts_with(".claude/")
        || p.contains("/.cursor/")
        || p.starts_with(".cursor/")
        || p.contains("/.continue/")
        || p.starts_with(".continue/")
        || p.contains(".aider")
        || p.contains("/.windsurf/")
        || p.starts_with(".windsurf/")
        || p.contains(".github/copilot")
        || p.contains(".github/prompts")
        || p.contains("/copilot-instructions.md")
        || p.ends_with("/copilot-instructions.md")
}

fn classify_ai_path(path: &str) -> Option<AiPathCategory> {
    let p = normalize_path_lc(path);
    if !is_ai_scope_path_lc(&p) {
        return None;
    }

    let credential_markers = [
        "/credentials",
        "/credential",
        "/secrets",
        "/secret",
        "/tokens",
        "/token",
        "/api_key",
        "/apikey",
        ".env",
        "/auth.json",
    ];
    if credential_markers.iter().any(|m| p.contains(m)) {
        return Some(AiPathCategory::Credential);
    }
    if p.contains("prompt")
        || p.contains("history")
        || p.contains("chat")
        || p.contains("conversation")
    {
        return Some(AiPathCategory::PromptHistory);
    }
    if p.contains("cache")
        || p.contains("state")
        || p.contains("session")
        || p.contains("workspace")
    {
        return Some(AiPathCategory::State);
    }
    Some(AiPathCategory::Config)
}

pub fn is_ai_sensitive_path(path: &str) -> bool {
    classify_ai_path(path).is_some()
}

fn ai_path_finding(path: &str, sha1: &str, is_deleted: bool) -> Option<Finding> {
    const AI_PATH_FINDING_LINE: usize = 1;
    let category = classify_ai_path(path)?;
    Some(Finding {
        filename: path.to_string(),
        line: AI_PATH_FINDING_LINE,
        pattern_id: category.pattern_id().to_string(),
        description: category.description().to_string(),
        severity: category.severity().to_string(),
        match_str: path.to_string(),
        context: format!("ai_path_category={}", category.label()),
        is_deleted,
        commit_sha1: if sha1.is_empty() {
            None
        } else {
            Some(sha1.to_string())
        },
        confidence_adjustment: None,
    })
}

fn ai_provider_tag_from_pattern(pattern_id: &str) -> Option<&'static str> {
    if pattern_id.starts_with("openai") {
        return Some("openai");
    }
    if pattern_id.starts_with("anthropic") {
        return Some("anthropic");
    }
    if pattern_id.starts_with("huggingface") {
        return Some("huggingface");
    }
    if pattern_id.starts_with("cohere") {
        return Some("cohere");
    }
    if pattern_id.starts_with("openrouter") {
        return Some("openrouter");
    }
    if pattern_id == "ai_provider_env_key" {
        return Some("multi_provider");
    }
    if pattern_id.starts_with("groq") {
        return Some("groq");
    }
    None
}

pub fn ai_metadata_for_finding(f: &Finding) -> (bool, Option<String>, Vec<String>) {
    if let Some(provider) = ai_provider_tag_from_pattern(&f.pattern_id) {
        return (
            true,
            Some("provider_key".to_string()),
            vec![
                "ai".to_string(),
                "key_material".to_string(),
                provider.to_string(),
            ],
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
        let path_lc = normalize_path_lc(&f.filename);
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
    if s.len() < 4 {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Attempt to detect secrets in a minified JS/TS line by splitting at common
/// statement-level separators and scanning each resulting segment.
/// Limits processing to the first 200 segments to bound worst-case latency.
#[allow(clippy::too_many_arguments)]
fn scan_minified_segments(
    line: &str,
    lineno: usize,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    apply_context: bool,
    false_positive_keywords: &[&str],
    out: &mut Vec<Finding>,
) {
    for segment in line.split([';', '{', '}', ',']).take(200) {
        let seg = segment.trim();
        if seg.is_empty() || seg.len() > 2000 || seg.len() < 10 {
            continue;
        }
        for pattern_index in PATTERN_SET.matches(seg).iter() {
            let pat = &PATTERNS[pattern_index];
            for m in pat.regex.find_iter(seg) {
                let val = m.as_str().to_string();
                if is_placeholder(&val) {
                    continue;
                }

                // Build a simple context window for minified segments
                let lines: Vec<&str> = seg.lines().collect();

                out.push(Finding {
                    filename: filename.to_string(),
                    line: lineno + 1,
                    pattern_id: pat.id.to_string(),
                    description: pat.desc.to_string(),
                    severity: pat.sev.to_string(),
                    match_str: val,
                    context: format!("[minified] {}", truncate_utf8(seg, 200)),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                });

                // Apply context analysis to the last finding if requested
                if apply_context {
                    if let Some(last) = out.last_mut() {
                        if let Some(reason) = analyze_context(&lines, 0, false_positive_keywords) {
                            last.severity = downgrade_severity(&last.severity).to_string();
                            last.confidence_adjustment = Some(format!("[minified] {}", reason));
                        }
                    }
                }
            }
        }
    }
}

/// Build a context string from lines surrounding `center` (within `radius` lines).
/// Lines are joined with ` | ` after trimming whitespace.
fn build_context_window(lines: &[&str], center: usize, radius: usize) -> String {
    let start = center.saturating_sub(radius);
    let end = (center + radius + 1).min(lines.len());
    lines[start..end]
        .iter()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Shannon-entropy based secret scan for a single line.
/// Only fires when ENTROPY_CONTEXT_RE matches the line (keyword context),
/// to keep the false-positive rate low.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn scan_entropy_line(
    line: &str,
    lineno: usize,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    all_lines: &[&str],
    out: &mut Vec<Finding>,
    threshold: f64,
) {
    scan_entropy_line_with_policy(
        line, lineno, filename, sha1, is_deleted, all_lines, out, threshold, false,
    );
}

#[allow(clippy::too_many_arguments)]
fn scan_entropy_line_with_policy(
    line: &str,
    lineno: usize,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    all_lines: &[&str],
    out: &mut Vec<Finding>,
    threshold: f64,
    include_placeholders: bool,
) {
    if !ENTROPY_CONTEXT_RE.is_match(line) {
        return;
    }

    for m in ENTROPY_VALUE_RE.find_iter(line) {
        let quoted = m.as_str();
        // Strip the enclosing quotes
        let inner = &quoted[1..quoted.len() - 1];
        if !include_placeholders && is_placeholder(inner) {
            continue;
        }
        let ent = shannon_entropy(inner);
        if ent < threshold {
            continue;
        }
        out.push(Finding {
            filename: filename.to_string(),
            line: lineno + 1,
            pattern_id: "high_entropy_secret".to_string(),
            description: format!("High-entropy secret ({:.2} bits/char)", ent),
            severity: "HIGH".to_string(),
            match_str: inner.to_string(),
            context: build_context_window(all_lines, lineno, 2),
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
/// SCAN-005: YAML Next-Line Secret Detection
///
/// Detects secret values on the line following YAML keys, including:
/// - Block scalars (key: | and key: >)
/// - Folded/literal syntax
/// - Generic secret key patterns
///
/// Line number preservation: Reports the KEY line number for finding location.
/// Context includes key name for accurate attribution.
#[allow(clippy::needless_range_loop)]
#[cfg(test)]
fn scan_yaml_nextline_secrets(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    false_positive_keywords: &[&str],
) -> Vec<Finding> {
    scan_yaml_nextline_secrets_with_policy(
        content,
        filename,
        sha1,
        is_deleted,
        false_positive_keywords,
        false,
    )
}

fn scan_yaml_nextline_secrets_with_policy(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    false_positive_keywords: &[&str],
    include_placeholders: bool,
) -> Vec<Finding> {
    lazy_static! {
        // SCAN-005: Generic YAML key pattern for secret-like keys
        // Matches: key_name: or password: or api_key: or key_name: | or key_name: >
        // Captures the key name for context
        static ref YAML_KEY_PATTERN: Regex = Regex::new(
            r#"^\s*([a-z][a-z0-9_]{2,})\s*:\s*(?:\||>|\s*)?$"#
        ).unwrap();

        // SCAN-005: YAML block scalar indicators
        // Matches: key: | or key: > (literal/folded blocks)
        static ref YAML_BLOCK_SCALAR: Regex = Regex::new(
            r#"^\s*([a-z][a-z0-9_]{2,})\s*:\s*(\||>)\s*$"#
        ).unwrap();

        // SCAN-005: Inline YAML value pattern (key: value)
        // For secrets that appear on same line but with block-style syntax
        static ref YAML_INLINE_VALUE: Regex = Regex::new(
            r#"^\s*([a-z][a-z0-9_]{2,})\s*:\s*[|>]?\s*([A-Za-z0-9+/=]{20,})\s*(?:#.*)?$"#
        ).unwrap();

        // SCAN-005: YAML anchor/alias pattern for secrets
        static ref YAML_ANCHOR: Regex = Regex::new(
            r#"^\s*([a-z][a-z0-9_]{2,})\s*:\s*&\s*([a-z_]+)\s*$"#
        ).unwrap();
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();

    for (i, &line) in lines.iter().enumerate() {
        // Mode 1: Block scalar detection (key: | or key: >)
        // Value is on next line(s), report key line number
        if let Some(caps) = YAML_BLOCK_SCALAR.captures(line) {
            let key_name = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
            let scalar_type = caps.get(2).map(|m| m.as_str()).unwrap_or("|");

            // Look ahead for value lines (skip empty lines and comments)
            let mut value_lines = Vec::new();

            for next_line in lines.iter().skip(i + 1).map(|line| line.trim()) {
                if next_line.is_empty() || next_line.starts_with('#') {
                    continue;
                }
                // Stop at next YAML key (indented less or same level with key)
                if next_line.ends_with(':') && !next_line.starts_with('-') {
                    break;
                }
                value_lines.push(next_line);
                // For folded style (>), we might have multiple lines
                if scalar_type == "|" && !value_lines.is_empty() {
                    break; // literal style - take first non-empty line
                }
            }

            if !value_lines.is_empty() {
                let combined_value = value_lines.join(" ");
                let value = if combined_value.len() > 120 {
                    truncate_utf8(&combined_value, 120).to_string()
                } else {
                    combined_value
                };

                if value.len() >= 8
                    && (include_placeholders || !is_placeholder(&value))
                    && shannon_entropy(&value) >= 2.5
                {
                    let finding = Finding {
                        filename: filename.to_string(),
                        line: i + 1, // SCAN-005: Report KEY line number (1-indexed)
                        pattern_id: "yaml_block_scalar_secret".to_string(),
                        description: format!("YAML block scalar secret (key: {})", key_name),
                        severity: "HIGH".to_string(),
                        match_str: value.clone(),
                        context: format!("{}: {} | {}", key_name, scalar_type, value),
                        is_deleted,
                        commit_sha1: Some(sha1.to_string()),
                        confidence_adjustment: None,
                    };
                    findings.push(apply_context_analysis(
                        finding,
                        &lines,
                        i,
                        false_positive_keywords,
                    ));
                }
            }
            continue;
        }

        // Mode 2: Inline YAML value detection (key: secret_value)
        // Both key and value on same line, report current line
        if let Some(caps) = YAML_INLINE_VALUE.captures(line) {
            let key_name = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
            let value = caps.get(2).map(|m| m.as_str()).unwrap_or("");

            if (include_placeholders || !is_placeholder(value)) && shannon_entropy(value) >= 2.5 {
                let finding = Finding {
                    filename: filename.to_string(),
                    line: i + 1, // SCAN-005: Current line (key line)
                    pattern_id: "yaml_inline_secret".to_string(),
                    description: format!("YAML inline secret (key: {})", key_name),
                    severity: "HIGH".to_string(),
                    match_str: value.to_string(),
                    context: format!("{}: {}", key_name, truncate_utf8(value, 80)),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                };
                findings.push(apply_context_analysis(
                    finding,
                    &lines,
                    i,
                    false_positive_keywords,
                ));
            }
            continue;
        }

        // Mode 3: YAML anchor/alias detection (key: &anchor_name)
        // Report key line, value defined elsewhere via alias
        if let Some(caps) = YAML_ANCHOR.captures(line) {
            let key_name = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
            let anchor_name = caps.get(2).map(|m| m.as_str()).unwrap_or("unknown");

            // Look ahead for anchor value
            if let Some(&next_line) = lines.get(i + 1) {
                let value = next_line.trim();
                if !value.is_empty()
                    && !value.starts_with('#')
                    && value.len() >= 8
                    && (include_placeholders || !is_placeholder(value))
                    && shannon_entropy(value) >= 2.5
                {
                    let finding = Finding {
                        filename: filename.to_string(),
                        line: i + 1, // SCAN-005: Report KEY line number
                        pattern_id: "yaml_anchor_secret".to_string(),
                        description: format!(
                            "YAML anchor secret (key: {}, anchor: &{})",
                            key_name, anchor_name
                        ),
                        severity: "HIGH".to_string(),
                        match_str: value.to_string(),
                        context: format!("{}: &{} -> {}", key_name, anchor_name, value),
                        is_deleted,
                        commit_sha1: Some(sha1.to_string()),
                        confidence_adjustment: None,
                    };
                    findings.push(apply_context_analysis(
                        finding,
                        &lines,
                        i,
                        false_positive_keywords,
                    ));
                }
            }
            continue;
        }

        // Mode 4: Generic YAML key-only pattern (existing behavior)
        // Matches: secret_key: (with value on next line)
        if let Some(caps) = YAML_KEY_PATTERN.captures(line) {
            let key_name = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");

            // Check if this looks like a secret key
            let is_secret_like = key_name.contains("pass")
                || key_name.contains("secret")
                || key_name.contains("key")
                || key_name.contains("token")
                || key_name.contains("auth")
                || key_name.contains("credential");

            if !is_secret_like {
                continue; // Skip non-secret-like keys
            }

            // Look ahead for value on next line
            if let Some(&next_line) = lines.get(i + 1) {
                let value = next_line.trim();
                if value.is_empty() || value.starts_with('#') {
                    continue;
                }
                if value.len() < 8 {
                    continue;
                }
                if !include_placeholders && is_placeholder(value) {
                    continue;
                }
                if shannon_entropy(value) < 2.5 {
                    continue;
                }

                let finding = Finding {
                    filename: filename.to_string(),
                    line: i + 1, // SCAN-005: Report KEY line number
                    pattern_id: "yaml_nextline_secret".to_string(),
                    description: format!("YAML next-line secret (key: {})", key_name),
                    severity: "HIGH".to_string(),
                    match_str: value.to_string(),
                    context: format!("{}: | {}", key_name, truncate_utf8(value, 80)),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                };
                findings.push(apply_context_analysis(
                    finding,
                    &lines,
                    i,
                    false_positive_keywords,
                ));
            }
        }
    }

    findings
}

/// Helper: Apply context analysis to a YAML finding
fn apply_context_analysis(
    mut finding: Finding,
    lines: &[&str],
    line_index: usize,
    false_positive_keywords: &[&str],
) -> Finding {
    // Apply context analysis for YAML findings
    if let Some(reason) = analyze_context(lines, line_index, false_positive_keywords) {
        finding.severity = downgrade_severity(&finding.severity).to_string();
        finding.confidence_adjustment = Some(reason);
    }
    finding
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

/// SCAN-001: Analyze context window around a match (±3 lines) for false-positive indicators.
///
/// # Arguments
/// * `lines` - Full content lines
/// * `center` - Line number of the match (0-indexed)
/// * `custom_keywords` - Optional custom false-positive keywords (extends defaults)
///
/// # Returns
/// * `None` - 100% confidence (no indicators found)
/// * `Some("1 keyword found")` - 50% confidence (possible placeholder)
/// * `Some("2+ keywords found")` - 10% confidence (likely placeholder)
fn analyze_context(lines: &[&str], center: usize, custom_keywords: &[&str]) -> Option<String> {
    let start = center.saturating_sub(3);
    let end = (center + 4).min(lines.len());
    let window: String = lines[start..end].join(" ");

    // Check for comment markers (additional indicator)
    let has_comment = window.contains("# ")
        || window.contains("// ")
        || window.contains("/* ")
        || window.contains("-- ")
        || window.contains("; ")
        || window.contains("REM ");

    // Build combined keyword list (defaults + custom)
    let keywords: Vec<&str> = DEFAULT_FALSE_POSITIVE_KEYWORDS
        .iter()
        .cloned()
        .chain(custom_keywords.iter().cloned())
        .collect();

    // Count how many keywords appear in the window
    let mut keyword_count = 0usize;
    let mut found_keywords = Vec::new();

    for &keyword in &keywords {
        let kw_lower = keyword.to_lowercase();
        if window.to_lowercase().contains(&kw_lower) {
            keyword_count += 1;
            found_keywords.push(keyword);
            // Early exit if we already have 2+
            if keyword_count >= 2 {
                break;
            }
        }
    }

    // Return confidence adjustment based on keyword count and comment presence
    match (keyword_count, has_comment) {
        (0, false) => None, // 100% confidence - no indicators
        (1, false) => Some(format!(
            "possible placeholder: '{}' found nearby",
            found_keywords.join("', '")
        )), // 50% confidence
        (1, true) => Some(format!(
            "possible placeholder: '{}' + comment",
            found_keywords[0]
        )), // 50% confidence
        (2.., false) => Some(format!(
            "likely placeholder: {}+ keywords found",
            keyword_count
        )), // 10% confidence
        (2.., true) => Some(format!(
            "likely placeholder: {}+ keywords + comment",
            keyword_count
        )), // 10% confidence
        (0, true) => Some("context: comment only (reduced confidence)".to_string()), // Comment marker reduces confidence
    }
}

/// Analyze context for binary findings (simplified version)
///
/// Binary findings typically have single-line context from the binary scanner.
/// This checks if the extracted string contains false-positive indicators.
fn analyze_context_for_binary(
    lines: &[&str],
    center: usize,
    custom_keywords: &[&str],
) -> Option<String> {
    if lines.is_empty() {
        return None;
    }

    let context = lines.get(center).unwrap_or(&lines[0]);

    // Build combined keyword list (defaults + custom)
    let keywords: Vec<&str> = DEFAULT_FALSE_POSITIVE_KEYWORDS
        .iter()
        .cloned()
        .chain(custom_keywords.iter().cloned())
        .collect();

    // Check if context contains false-positive indicators
    let mut keyword_count = 0usize;
    let mut found_keywords = Vec::new();

    for &keyword in &keywords {
        let kw_lower = keyword.to_lowercase();
        if context.to_lowercase().contains(&kw_lower) {
            keyword_count += 1;
            found_keywords.push(keyword);
            if keyword_count >= 2 {
                break;
            }
        }
    }

    match keyword_count {
        0 => None,
        1 => Some(format!(
            "possible placeholder: '{}' in binary string",
            found_keywords[0]
        )),
        _ => Some(format!(
            "likely placeholder: {}+ keywords in binary string",
            keyword_count
        )),
    }
}

fn downgrade_severity(sev: &str) -> &'static str {
    match sev {
        "CRITICAL" => "HIGH",
        "HIGH" => "MEDIUM",
        "MEDIUM" => "LOW",
        _ => "LOW",
    }
}

// S-2: Multi-line pattern scanning (SCAN-002: Enhanced multi-line support)
//
// Implements full multi-line pattern matching with:
// 1. PEM blocks with (?s) dot-all for complete key capture
// 2. Nested JSON detection (3 levels deep)
// 3. YAML block scalar scanning (key: |\n  secret_value)
// 4. Multi-line Python/Ruby/PHP config patterns
// 5. Performance-optimized with <10% overhead
#[cfg(test)]
fn scan_multiline(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    false_positive_keywords: &[&str],
) -> Vec<Finding> {
    scan_multiline_with_policy(
        content,
        filename,
        sha1,
        is_deleted,
        false_positive_keywords,
        false,
    )
}

fn scan_multiline_with_policy(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    false_positive_keywords: &[&str],
    include_placeholders: bool,
) -> Vec<Finding> {
    lazy_static! {
        // PEM blocks: Enhanced to capture full key content with key type detection
        // (?s) enables dot-all mode to match across newlines
        // Matches RSA PRIVATE KEY, EC PRIVATE KEY, DSA PRIVATE KEY, etc.
        static ref PEM_MULTILINE: Regex = Regex::new(
            r"(?s)-----BEGIN (RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----[a-zA-Z0-9+/=\n]+-----END (RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----"
        ).unwrap();

        // Nested JSON (3 levels): Detects parent.child: "secret" patterns
        // Matches structures like: "database": { "config": { "password": "secret" } }
        static ref JSON_NESTED_SECRET: Regex = Regex::new(
            r#"(?si)"([a-z_]+)":\s*\{[^}]*"(password|passwd|secret|api_key|access_token|private_key|client_secret)"\s*:\s*"([^"]{8,})"[^}]*\}"#
        ).unwrap();

        // YAML block scalar: Detects key: |\n  secret_value patterns
        // Matches YAML literal block scalars where secret appears on next line
        static ref YAML_BLOCK_SCALAR: Regex = Regex::new(
            r"(?i)([a-z_][a-z0-9_]*)\s*:\s*\|[\n\r]+([^\n\r]*?(?:akia|aws_|secret|password|token|key|credential)[^\n\r]*)"
        ).unwrap();

        // Python triple-quoted multi-line strings
        static ref PYTHON_TRIPLE_QUOTE: Regex = Regex::new(
            r#"(?im)^[A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z_]*\s*=\s*['"]{3}[^'"\n]{8,}['"]{3}"#
        ).unwrap();

        // Ruby heredoc-style multi-line secrets
        static ref RUBY_HEREDOC_SECRET: Regex = Regex::new(
            r#"(?im)^([A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z_]*)\s*=\s*<<(?:[-~])['"]?([A-Z]+)['"]?\n\s+([^\n]{8,})"#
        ).unwrap();

        // PHP multi-line array config with secret values.
        // v3.2.7: tightened from [A-Z_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z_]*
        // to require the keyword to be preceded by underscore or be at start,
        // and followed by underscore or end.  This stops matching camelCase
        // API method names (getPageToken, setPageToken, NextToken) from
        // AWS SDK paginator files and Google API descriptor configs that
        // were generating 9 000+ false positives per run.
        static ref PHP_MULTILINE_SECRET: Regex = Regex::new(
            r#"(?im)['"]([A-Z_]*_(?:PASSWORD|SECRET|KEY|TOKEN)(?:_[A-Z_]+)?)['"]\s*=>\s*['"]([^'\n]{8,})['"]"#
        ).unwrap();
    }
    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();

    // 1. PEM blocks with enhanced key type detection
    for cap in PEM_MULTILINE.captures_iter(content) {
        let key_type = cap.get(1).map(|m| m.as_str()).unwrap_or("RSA");
        let full_match = cap.get(0).unwrap();
        let val = full_match.as_str().to_string();
        if include_placeholders || !is_placeholder(&val) {
            let line_no = content[..full_match.start()].lines().count() + 1;
            let finding = Finding {
                filename: filename.to_string(),
                line: line_no,
                pattern_id: "pem_key_multiline".to_string(),
                description: format!("PEM Private Key ({})", key_type),
                severity: "CRITICAL".to_string(),
                match_str: truncate_utf8(&val, 100).to_string(),
                context: format!("multi-line PEM block ({} lines)", val.lines().count()),
                is_deleted,
                commit_sha1: Some(sha1.to_string()),
                confidence_adjustment: None,
            };

            // PEM keys are always CRITICAL - no context analysis needed
            findings.push(finding);
        }
    }

    // 2. Nested JSON secrets (3 levels deep)
    for cap in JSON_NESTED_SECRET.captures_iter(content) {
        let parent_key = cap.get(1).unwrap().as_str();
        let secret_type = cap.get(2).unwrap().as_str();
        let secret_value = cap.get(3).unwrap().as_str();

        if include_placeholders || !is_placeholder(secret_value) {
            let match_start = cap.get(0).unwrap().start();
            let line_no = content[..match_start].lines().count() + 1;
            let mut finding = Finding {
                filename: filename.to_string(),
                line: line_no,
                pattern_id: "json_nested_secret".to_string(),
                description: format!("JSON nested secret: {}.{}", parent_key, secret_type),
                severity: "HIGH".to_string(),
                match_str: truncate_utf8(secret_value, 100).to_string(),
                context: format!("nested JSON (parent: {})", parent_key),
                is_deleted,
                commit_sha1: Some(sha1.to_string()),
                confidence_adjustment: None,
            };

            if let Some(reason) = analyze_context(
                &lines,
                finding.line.saturating_sub(1),
                false_positive_keywords,
            ) {
                finding.severity = downgrade_severity(&finding.severity).to_string();
                finding.confidence_adjustment = Some(reason);
            }

            findings.push(finding);
        }
    }

    // 3. YAML block scalar secrets (key: |\n  secret_value)
    for cap in YAML_BLOCK_SCALAR.captures_iter(content) {
        let key_name = cap.get(1).unwrap().as_str();
        let secret_value = cap.get(2).unwrap().as_str();

        // Check if the secret value contains keywords indicating sensitive data
        let value_lower = secret_value.to_lowercase();
        let has_keyword = value_lower.contains("akia")
            || value_lower.contains("aws_")
            || value_lower.contains("secret")
            || value_lower.contains("password")
            || value_lower.contains("token")
            || value_lower.contains("credential")
            || value_lower.contains("access_key")
            || value_lower.contains("api_key");

        // Extract just the value part (after colon) for entropy check
        let value_part = if let Some(colon_pos) = secret_value.find(':') {
            &secret_value[colon_pos + 1..]
        } else {
            secret_value
        };

        let entropy_ok = shannon_entropy(value_part.trim()) >= 2.5;

        // Apply the same placeholder policy as the other multiline detectors.
        // Check the value, not the YAML key name, to avoid filtering legitimate keys
        // that contain words such as "key" or "secret".
        if has_keyword && entropy_ok && (include_placeholders || !is_placeholder(secret_value)) {
            let match_start = cap.get(0).unwrap().start();
            let line_no = content[..match_start].lines().count() + 1;
            let mut finding = Finding {
                filename: filename.to_string(),
                line: line_no,
                pattern_id: "yaml_block_scalar_secret".to_string(),
                description: format!("YAML block scalar: {}", key_name),
                severity: "HIGH".to_string(),
                match_str: truncate_utf8(secret_value, 100).to_string(),
                context: format!("YAML block scalar (|) {}", key_name),
                is_deleted,
                commit_sha1: Some(sha1.to_string()),
                confidence_adjustment: None,
            };

            if let Some(reason) = analyze_context(
                &lines,
                finding.line.saturating_sub(1),
                false_positive_keywords,
            ) {
                finding.severity = downgrade_severity(&finding.severity).to_string();
                finding.confidence_adjustment = Some(reason);
            }

            findings.push(finding);
        }
    }

    // 4. Python triple-quoted multi-line config
    for cap in PYTHON_TRIPLE_QUOTE.find_iter(content) {
        if include_placeholders || !is_placeholder(cap.as_str()) {
            let match_start = cap.start();
            let line_no = content[..match_start].lines().count() + 1;
            let mut finding = Finding {
                filename: filename.to_string(),
                line: line_no,
                pattern_id: "python_multiline_secret".to_string(),
                description: "Python multi-line config secret".to_string(),
                severity: "HIGH".to_string(),
                match_str: truncate_utf8(cap.as_str(), 100).to_string(),
                context: "Python triple-quoted multi-line value".to_string(),
                is_deleted,
                commit_sha1: Some(sha1.to_string()),
                confidence_adjustment: None,
            };

            if let Some(reason) = analyze_context(
                &lines,
                finding.line.saturating_sub(1),
                false_positive_keywords,
            ) {
                finding.severity = downgrade_severity(&finding.severity).to_string();
                finding.confidence_adjustment = Some(reason);
            }

            findings.push(finding);
        }
    }

    // 5. Ruby heredoc-style multi-line secrets
    for cap in RUBY_HEREDOC_SECRET.captures_iter(content) {
        let key_name = cap.get(1).unwrap().as_str();
        let secret_value = cap.get(3).unwrap().as_str();

        if include_placeholders || !is_placeholder(secret_value) {
            let match_start = cap.get(0).unwrap().start();
            let line_no = content[..match_start].lines().count() + 1;
            let mut finding = Finding {
                filename: filename.to_string(),
                line: line_no,
                pattern_id: "ruby_heredoc_secret".to_string(),
                description: format!("Ruby heredoc: {}", key_name),
                severity: "HIGH".to_string(),
                match_str: truncate_utf8(secret_value, 100).to_string(),
                context: format!("Ruby heredoc multi-line ({})", key_name),
                is_deleted,
                commit_sha1: Some(sha1.to_string()),
                confidence_adjustment: None,
            };

            if let Some(reason) = analyze_context(
                &lines,
                finding.line.saturating_sub(1),
                false_positive_keywords,
            ) {
                finding.severity = downgrade_severity(&finding.severity).to_string();
                finding.confidence_adjustment = Some(reason);
            }

            findings.push(finding);
        }
    }

    // 6. PHP multi-line array config
    // Skip known false-positive paths: AWS SDK paginator configs and
    // Google API descriptor configs that contain camelCase key names
    // like getPageToken, setPageToken, NextToken — these are API method
    // names, not secrets.
    {
        let lower = filename.to_lowercase();
        if lower.contains("/data/") && lower.ends_with("paginators-1.json.php")
            || lower.contains("descriptor_config.php")
        {
            return findings; // skip this file entirely (pure false positives)
        }
    }

    for cap in PHP_MULTILINE_SECRET.captures_iter(content) {
        let key_name = cap.get(1).unwrap().as_str();
        let secret_value = cap.get(2).unwrap().as_str();

        if include_placeholders || !is_placeholder(secret_value) {
            let match_start = cap.get(0).unwrap().start();
            let line_no = content[..match_start].lines().count() + 1;
            let mut finding = Finding {
                filename: filename.to_string(),
                line: line_no,
                pattern_id: "php_multiline_secret".to_string(),
                description: format!("PHP config: {}", key_name),
                severity: "HIGH".to_string(),
                match_str: truncate_utf8(secret_value, 100).to_string(),
                context: format!("PHP array config ({})", key_name),
                is_deleted,
                commit_sha1: Some(sha1.to_string()),
                confidence_adjustment: None,
            };

            if let Some(reason) = analyze_context(
                &lines,
                finding.line.saturating_sub(1),
                false_positive_keywords,
            ) {
                finding.severity = downgrade_severity(&finding.severity).to_string();
                finding.confidence_adjustment = Some(reason);
            }

            findings.push(finding);
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
#[cfg(test)]
pub fn scan_text(
    text: &str,
    source: &str,
    dyn_patterns: &[DynPattern],
    entropy_threshold: f64,
) -> Vec<Finding> {
    scan_text_with_policy(text, source, dyn_patterns, entropy_threshold, false)
}

/// Exhaustive text scan for offensive workflows. It preserves direct pattern
/// candidates that normal mode classifies as placeholders while retaining all
/// existing resource limits and report structures.
#[cfg(test)]
pub fn scan_text_exhaustive(
    text: &str,
    source: &str,
    dyn_patterns: &[DynPattern],
    entropy_threshold: f64,
) -> Vec<Finding> {
    scan_text_with_policy(text, source, dyn_patterns, entropy_threshold, true)
}

#[cfg(test)]
fn scan_text_with_policy(
    text: &str,
    source: &str,
    dyn_patterns: &[DynPattern],
    entropy_threshold: f64,
    include_placeholders: bool,
) -> Vec<Finding> {
    // Empty custom keywords - uses defaults only
    let custom_keywords: Vec<&str> = vec![];
    let mut findings = scan_content_with_policy(
        text,
        source,
        "",
        false,
        dyn_patterns,
        if include_placeholders {
            ScanPolicy::exhaustive(entropy_threshold, &custom_keywords)
        } else {
            ScanPolicy::normal(entropy_threshold, &custom_keywords)
        },
    );
    findings.extend(scan_yaml_nextline_secrets_with_policy(
        text,
        source,
        "",
        false,
        &custom_keywords,
        include_placeholders,
    ));
    findings.extend(scan_db_config_blocks_with_policy(
        text,
        source,
        "",
        false,
        &custom_keywords,
        include_placeholders,
    ));
    findings
}

// SCAN-004: Multi-Line DB Credential Detection
//
// Detects framework-specific database credentials across multiple lines:
// 1. Django/Flask SECRET_KEY patterns
// 2. Ruby/Rails DATABASE_URL and config hash patterns
// 3. PHP Laravel APP_KEY and DB_* patterns
// 4. Go config struct patterns with Password field
#[cfg(test)]
fn scan_db_config_blocks(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    false_positive_keywords: &[&str],
) -> Vec<Finding> {
    scan_db_config_blocks_with_policy(
        content,
        filename,
        sha1,
        is_deleted,
        false_positive_keywords,
        false,
    )
}

fn scan_db_config_blocks_with_policy(
    content: &str,
    filename: &str,
    sha1: &str,
    is_deleted: bool,
    false_positive_keywords: &[&str],
    include_placeholders: bool,
) -> Vec<Finding> {
    lazy_static! {
        // Django DB: 'PASSWORD': 'secret_value' in DATABASES config
        static ref DJANGO_DB: Regex = Regex::new(
            r#"(?si)'PASSWORD'\s*:\s*'([^']{6,})'"#
        ).unwrap();

        // Django SECRET_KEY: SECRET_KEY = 'long_secret_value_here' (at least 20 chars)
        static ref DJANGO_SECRET_KEY: Regex = Regex::new(
            r#"(?i)SECRET_KEY\s*=\s*['\"]([^'"]{20,})['\"]"#
        ).unwrap();

        // Django os.environ: SECRET_KEY = os.environ.get('KEY_NAME') or os.environ['KEY_NAME']
        static ref DJANGO_ENV_SECRET: Regex = Regex::new(
            r#"(?i)SECRET_KEY\s*=\s*os\.environ(?:\.get)?\s*\(\s*['\"]([^'\"\s]+)['\"]\s*\)"#
        ).unwrap();

        // Ruby DATABASE_URL: DATABASE_URL = "protocol://user:pass@host/db" or DATABASE_URL: "..."
        static ref RUBY_DATABASE_URL: Regex = Regex::new(
            r#"(?i)DATABASE_URL\s*[=:]\s*['\"]?([a-z]+://[^'\"\s]{10,})['\"]?"#
        ).unwrap();

        // Ruby config hash: database: { password: 'secret' } or db_config: { password: "value" }
        static ref RUBY_CONFIG_HASH: Regex = Regex::new(
            r#"(?i)[a-z_]+\s*:\s*\{[^}]*password:\s*['"]([^'"\s]{4,})['"]"#
        ).unwrap();

        // PHP Laravel APP_KEY: APP_KEY=base64:long_base64_string_here (at least 32 chars after base64:)
        static ref PHP_LARAVEL_KEY: Regex = Regex::new(
            r"(?i)APP_KEY\s*=\s*base64:\s*([A-Za-z0-9+/=]{32,})"
        ).unwrap();

        // PHP DB_* config: DB_PASSWORD='value' or DB_DATABASE="dbname"
        static ref PHP_DB_CONFIG: Regex = Regex::new(
            r#"(?i)DB_[A-Z_]+\s*=\s*['"]([^'"\s]{6,})['"]"#
        ).unwrap();

        // Go config struct: type Config struct { ... Password string ... }
        static ref GO_CONFIG_STRUCT: Regex = Regex::new(
            r"(?s)type\s+([A-Z]\w+)\s+struct\s*\{[^}]*Password\s+string[^}]*\}"
        ).unwrap();

        // DB URL password: postgres://user:password@host/db or mysql://user:pass@host
        static ref DB_URL_PASS: Regex = Regex::new(
            r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:([^@]+)@"
        ).unwrap();
    }
    // Every detector below requires one of these literal markers. Avoid building a
    // line-index vector for unrelated content, which is the common path for this
    // supplemental detector. This is only an allocation prefilter; regex matching
    // remains authoritative and all supported marker families are represented.
    let has_db_marker = content.contains("PASSWORD")
        || content.contains("SECRET_KEY")
        || content.contains("DATABASE_URL")
        || content.contains("password")
        || content.contains("APP_KEY")
        || content.contains("DB_")
        || content.contains("Password")
        || content.contains("://");
    if !has_db_marker {
        return Vec::new();
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut findings = Vec::new();

    // Django DB password in DATABASES dict
    for cap in DJANGO_DB.captures_iter(content) {
        if let Some(val) = cap.get(1) {
            let v = val.as_str();
            if include_placeholders || !is_placeholder(v) {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                let mut finding = Finding {
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
                };

                if let Some(reason) = analyze_context(
                    &lines,
                    finding.line.saturating_sub(1),
                    false_positive_keywords,
                ) {
                    finding.severity = downgrade_severity(&finding.severity).to_string();
                    finding.confidence_adjustment = Some(reason);
                }

                findings.push(finding);
            }
        }
    }

    // Django SECRET_KEY detection
    for cap in DJANGO_SECRET_KEY.captures_iter(content) {
        if let Some(val) = cap.get(1) {
            let v = val.as_str();
            if (include_placeholders || !is_placeholder(v)) && shannon_entropy(v) >= 2.5 {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                let mut finding = Finding {
                    filename: filename.to_string(),
                    line: line_no,
                    pattern_id: "django_secret_key".to_string(),
                    description: "Django/Flask SECRET_KEY detected".to_string(),
                    severity: "CRITICAL".to_string(),
                    match_str: truncate_utf8(v, 100).to_string(),
                    context: "Django settings".to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                };

                if let Some(reason) = analyze_context(
                    &lines,
                    finding.line.saturating_sub(1),
                    false_positive_keywords,
                ) {
                    finding.severity = downgrade_severity(&finding.severity).to_string();
                    finding.confidence_adjustment = Some(reason);
                }

                findings.push(finding);
            }
        }
    }

    // Django os.environ.get() pattern
    for cap in DJANGO_ENV_SECRET.captures_iter(content) {
        if let Some(val) = cap.get(1) {
            let env_var = val.as_str();
            let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
            findings.push(Finding {
                filename: filename.to_string(),
                line: line_no,
                pattern_id: "django_env_secret_key".to_string(),
                description: format!("Django SECRET_KEY from environment variable: {}", env_var),
                severity: "HIGH".to_string(),
                match_str: env_var.to_string(),
                context: "os.environ reference".to_string(),
                is_deleted,
                commit_sha1: Some(sha1.to_string()),
                confidence_adjustment: None,
            });
        }
    }

    // Ruby DATABASE_URL detection
    for cap in RUBY_DATABASE_URL.captures_iter(content) {
        if let Some(val) = cap.get(1) {
            let url = val.as_str();
            if (include_placeholders || !is_placeholder(url)) && url.contains("://") {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                let mut finding = Finding {
                    filename: filename.to_string(),
                    line: line_no,
                    pattern_id: "ruby_database_url".to_string(),
                    description: "Ruby/Rails DATABASE_URL connection string".to_string(),
                    severity: "HIGH".to_string(),
                    match_str: truncate_utf8(url, 100).to_string(),
                    context: "Ruby database config".to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                };

                if let Some(reason) = analyze_context(
                    &lines,
                    finding.line.saturating_sub(1),
                    false_positive_keywords,
                ) {
                    finding.severity = downgrade_severity(&finding.severity).to_string();
                    finding.confidence_adjustment = Some(reason);
                }

                findings.push(finding);
            }
        }
    }

    // Ruby config hash with password field
    for cap in RUBY_CONFIG_HASH.captures_iter(content) {
        if let Some(val) = cap.get(1) {
            let password = val.as_str();
            if include_placeholders || !is_placeholder(password) {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                let mut finding = Finding {
                    filename: filename.to_string(),
                    line: line_no,
                    pattern_id: "ruby_config_password".to_string(),
                    description: "Ruby config hash password field".to_string(),
                    severity: "HIGH".to_string(),
                    match_str: truncate_utf8(password, 100).to_string(),
                    context: "Ruby hash config".to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                };

                if let Some(reason) = analyze_context(
                    &lines,
                    finding.line.saturating_sub(1),
                    false_positive_keywords,
                ) {
                    finding.severity = downgrade_severity(&finding.severity).to_string();
                    finding.confidence_adjustment = Some(reason);
                }

                findings.push(finding);
            }
        }
    }

    // PHP Laravel APP_KEY detection
    for cap in PHP_LARAVEL_KEY.captures_iter(content) {
        if let Some(val) = cap.get(1) {
            let key = val.as_str();
            if (include_placeholders || !is_placeholder(key)) && shannon_entropy(key) >= 2.5 {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                let mut finding = Finding {
                    filename: filename.to_string(),
                    line: line_no,
                    pattern_id: "php_laravel_app_key".to_string(),
                    description: "PHP Laravel APP_KEY".to_string(),
                    severity: "CRITICAL".to_string(),
                    match_str: truncate_utf8(key, 100).to_string(),
                    context: "Laravel .env/config".to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                };

                if let Some(reason) = analyze_context(
                    &lines,
                    finding.line.saturating_sub(1),
                    false_positive_keywords,
                ) {
                    finding.severity = downgrade_severity(&finding.severity).to_string();
                    finding.confidence_adjustment = Some(reason);
                }

                findings.push(finding);
            }
        }
    }

    // PHP DB_* config detection
    for cap in PHP_DB_CONFIG.captures_iter(content) {
        if let Some(val) = cap.get(1) {
            let value = val.as_str();
            if (include_placeholders || !is_placeholder(value)) && shannon_entropy(value) >= 2.0 {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                let mut finding = Finding {
                    filename: filename.to_string(),
                    line: line_no,
                    pattern_id: "php_db_config".to_string(),
                    description: "PHP DB_* configuration value".to_string(),
                    severity: "HIGH".to_string(),
                    match_str: truncate_utf8(value, 100).to_string(),
                    context: "PHP database config".to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                    confidence_adjustment: None,
                };

                if let Some(reason) = analyze_context(
                    &lines,
                    finding.line.saturating_sub(1),
                    false_positive_keywords,
                ) {
                    finding.severity = downgrade_severity(&finding.severity).to_string();
                    finding.confidence_adjustment = Some(reason);
                }

                findings.push(finding);
            }
        }
    }

    // Go config struct with Password field
    for cap in GO_CONFIG_STRUCT.captures_iter(content) {
        if let Some(struct_name) = cap.get(1) {
            let name = struct_name.as_str();
            let match_obj = cap.get(0).unwrap();
            let line_no = content[..match_obj.start()].lines().count() + 1;
            findings.push(Finding {
                filename: filename.to_string(),
                line: line_no,
                pattern_id: "go_config_password_struct".to_string(),
                description: format!("Go config struct '{}' with Password field", name),
                severity: "MEDIUM".to_string(),
                match_str: format!("{} struct contains Password field", name),
                context: "Go struct definition".to_string(),
                is_deleted,
                commit_sha1: Some(sha1.to_string()),
                confidence_adjustment: None,
            });
        }
    }

    // DB URL password extraction
    for cap in DB_URL_PASS.captures_iter(content) {
        if let Some(val) = cap.get(2) {
            let v = val.as_str();
            if include_placeholders || !is_placeholder(v) {
                let line_no = content[..cap.get(0).unwrap().start()].lines().count() + 1;
                let mut finding = Finding {
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
                };

                if let Some(reason) = analyze_context(
                    &lines,
                    finding.line.saturating_sub(1),
                    false_positive_keywords,
                ) {
                    finding.severity = downgrade_severity(&finding.severity).to_string();
                    finding.confidence_adjustment = Some(reason);
                }

                findings.push(finding);
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_finding_normalizer_uses_custom_metadata() {
        let custom = DynPattern {
            id: "custom_binary".to_string(),
            sev: "CRITICAL".to_string(),
            desc: "Custom binary credential".to_string(),
            regex: Regex::new("CUSTOM_[A-Z0-9]{4}").unwrap(),
        };
        let findings = normalize_binary_findings(
            vec![(
                "custom_binary".to_string(),
                "CUSTOM_AB12".to_string(),
                "Binary: fixture.bin".to_string(),
                "binary".to_string(),
            )],
            BinaryFindingContext {
                filename: "fixture.bin",
                sha1: "0123456789012345678901234567890123456789",
                is_deleted: false,
                fallback_description: "Binary Secret",
                context_keywords: None,
                include_placeholders: false,
                extra_patterns: &[custom],
            },
        );
        assert_eq!(findings[0].severity, "CRITICAL");
        assert_eq!(findings[0].description, "Custom binary credential");
    }

    #[test]
    fn binary_finding_normalizer_preserves_provenance() {
        let findings = normalize_binary_findings(
            vec![(
                "api_key".to_string(),
                "candidate_value".to_string(),
                "SQLite: config.db".to_string(),
                "binary".to_string(),
            )],
            BinaryFindingContext {
                filename: "config.db",
                sha1: "0123456789012345678901234567890123456789",
                is_deleted: true,
                fallback_description: "Binary Secret",
                context_keywords: None,
                include_placeholders: false,
                extra_patterns: &[],
            },
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern_id, "api_key");
        assert_eq!(findings[0].description, "Generic API Key");
        assert_eq!(findings[0].filename, "config.db");
        assert_eq!(findings[0].context, "SQLite: config.db");
        assert!(findings[0].is_deleted);
        assert_eq!(
            findings[0].commit_sha1.as_deref(),
            Some("0123456789012345678901234567890123456789")
        );
    }

    #[test]
    fn db_config_prefilter_preserves_supported_markers() {
        let irrelevant = scan_db_config_blocks_with_policy(
            "ordinary source text without configuration markers",
            "fixture.txt",
            "a".repeat(40).as_str(),
            false,
            &[],
            true,
        );
        assert!(irrelevant.is_empty());

        let database_url = scan_db_config_blocks_with_policy(
            r#"DATABASE_URL = "postgres://fixture:synthetic_fixture_value@host/db""#,
            "settings.rb",
            "a".repeat(40).as_str(),
            false,
            &[],
            true,
        );
        assert!(database_url
            .iter()
            .any(|finding| finding.pattern_id == "ruby_database_url"));
    }

    #[test]
    fn typed_worker_outcomes_are_accounted_by_reason() {
        let mut state = State::default();
        state.record_skip(SkipReason::NotFound);
        state.record_skip(SkipReason::NotFound);
        state.record_skip(SkipReason::Oversized);
        state.record_failure(FailureKind::HttpStatus(429));

        assert_eq!(state.skipped_by_reason.get(&SkipReason::NotFound), Some(&2));
        assert_eq!(
            state.skipped_by_reason.get(&SkipReason::Oversized),
            Some(&1)
        );
        assert_eq!(
            state.failed_by_kind.get(&FailureKind::HttpStatus(429)),
            Some(&1)
        );
    }

    #[test]
    fn test_is_placeholder() {
        assert!(is_placeholder("your_api_key_here"));
        let aws_placeholder = ["AKIA", "IOSFODNN7EXAMPLE"].concat();
        assert!(is_placeholder(&aws_placeholder));
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
        assert!(
            null_count <= 10,
            "Plain text should not be detected as binary"
        );
    }

    #[test]
    fn test_scan_content_finds_aws_key() {
        // AKIA + exactly 16 uppercase/digit chars, no placeholder substrings
        let content = "AWS_KEY=AKIAZ9XYZMNOP1234567";
        let findings = scan_content(
            content,
            "config.sh",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "aws_key_id"),
            "Should detect AWS key ID pattern"
        );
    }

    #[test]
    fn test_scan_content_skips_long_lines() {
        let long_line = "A".repeat(2001);
        let findings = scan_content(
            &long_line,
            "file.txt",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        // Long lines should be skipped — no findings
        assert!(findings.is_empty(), "Lines >2000 chars should be skipped");
    }

    #[test]
    fn test_scan_content_finds_wp_define_credential() {
        let content = r#"define('DB_PASSWORD', 'supersecret123');"#;
        let findings = scan_content(
            content,
            "wp-config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
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
        let findings = scan_content(
            content,
            "wp-config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            !findings.iter().any(|f| f.pattern_id == "wp_define"),
            "WordPress AUTH_KEY with placeholder value 'put your unique phrase here' must be filtered"
        );
    }

    #[test]
    fn test_scan_content_finds_php_define_aws_key() {
        let content = r#"define('AWS_KEY', 'CQITEE7X4TT318J00PWC');"#;
        let findings = scan_content(
            content,
            "config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should detect define() with APP_SECRET_KEY"
        );
    }

    #[test]
    fn test_scan_content_finds_php_define_aws_secret_key() {
        let content = r#"define('APP_SECRET_KEY', 'synthetic_php_fixture_value_1234567890');"#;
        let findings = scan_content(
            content,
            "config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should detect define() with AWS_SECRET_KEY"
        );
    }

    #[test]
    fn test_scan_content_finds_php_define_auth_token_secret() {
        let content = r#"define('AUTH_TOKEN_SECRET', 'jq6uik0LxAPCUBIHlHk3usBEZ8pJf9t9');"#;
        let findings = scan_content(
            content,
            "config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should detect define() with AUTH_TOKEN_SECRET"
        );
    }

    #[test]
    fn test_scan_content_php_define_ignores_non_secret_keys() {
        // BUCKET_NAME and ENDPOINT don't contain secret-related keywords
        let content = r#"define('BUCKET_NAME', 'developer-request');"#;
        let findings = scan_content(
            content,
            "config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            !findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should NOT detect define() with non-secret key name BUCKET_NAME"
        );
    }

    #[test]
    fn test_scan_content_php_define_ignores_short_values() {
        let content = r#"define('API_KEY', 'short');"#;
        let findings = scan_content(
            content,
            "config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            !findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Should NOT detect define() with value shorter than 8 chars"
        );
    }

    #[test]
    fn test_scan_content_php_define_placeholder_is_filtered() {
        let content = r#"define('API_KEY', 'your_api_key_here_placeholder');"#;
        let findings = scan_content(
            content,
            "config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            !findings.iter().any(|f| f.pattern_id == "php_define_secret"),
            "Placeholder value in define() should be filtered"
        );
    }

    #[test]
    fn test_scan_content_finds_django_secret_key() {
        let content = r#"SECRET_KEY = 'django-insecure-abcdefghijklmnopqrstuvwxyz1234567890!@#'"#;
        let findings = scan_content(
            content,
            "settings.py",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "django_secret"),
            "Should detect Django SECRET_KEY"
        );
    }

    #[test]
    fn test_scan_content_finds_google_api_key() {
        // AIza + exactly 35 alphanumeric/dash/underscore chars
        let content = "GOOGLE_KEY=AIzaSyC1234567890abcdefghijklmnop123456";
        let findings = scan_content(
            content,
            "config.js",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "gcp_api_key"),
            "Should detect Google/GCP API Key"
        );
    }

    #[test]
    fn test_scan_content_finds_laravel_app_key() {
        let content = "APP_KEY=base64:SomeBase64EncodedKeyHereThatIsLongEnoughToMatch==";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "laravel_app_key"),
            "Should detect Laravel APP_KEY"
        );
    }

    #[test]
    fn test_no_private_ip_false_positive() {
        // Private IPs no longer trigger any finding
        let content = "db_host = 192.168.1.100";
        let findings = scan_content(
            content,
            "config.ini",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            !findings.iter().any(|f| f.pattern_id == "private_ip"),
            "Private IP should not be flagged"
        );
    }

    #[test]
    fn test_no_s3_url_false_positive() {
        // S3 URLs no longer trigger a MEDIUM finding
        let content = "endpoint = https://mybucket.s3.amazonaws.com";
        let findings = scan_content(
            content,
            "config.ini",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            !findings.iter().any(|f| f.pattern_id == "s3_url"),
            "S3 URL should not be flagged"
        );
    }

    #[test]
    fn test_no_entropy_medium_finding() {
        // Entropy check is removed; quoted high-entropy strings should not produce MEDIUM findings
        let content = r#"some_field = "R2l0UmVjb25Jc0F3ZXNvbWVUb29sRm9yU2VjdXJpdHk=""#;
        let findings = scan_content(
            content,
            "file.txt",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
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
            assert!(
                sanitised.exists(),
                "Sanitised file must be inside the output directory"
            );
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
        assert!(
            dir.join("sub/dir/file.txt").exists(),
            "Should create sub-directories"
        );
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
        assert!(
            ok,
            "Binary blob should be saved to disk even when skipped for scanning"
        );
        assert!(
            dir.join("image.png").exists(),
            "Binary blob file must exist on disk"
        );
        let saved = std::fs::read(dir.join("image.png")).unwrap();
        assert_eq!(
            saved, binary_data,
            "Saved binary content must match original"
        );
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
        assert!(
            ok,
            "Oversized blob should be saved to disk even when skipped for scanning"
        );
        assert!(
            dir.join("large_file.bin").exists(),
            "Oversized blob file must exist on disk"
        );
        let saved = std::fs::read(dir.join("large_file.bin")).unwrap();
        assert_eq!(
            saved.len(),
            MAX_SCAN_BYTES + 1,
            "Saved oversized content must be complete"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_write_blob_to_disk_unreferenced_fallback_layout() {
        // Sprint 1 regression: blobs without a filename mapping (deep-history, dangling
        // refs, pack-only enumeration) must still land on disk under the
        // `_unreferenced/<xx>/<rest>` fallback so --save is lossless.
        let dir = std::env::temp_dir().join("gitrecon_test_unreferenced");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sha1 = "abcdef1234567890abcdef1234567890abcdef12";
        let fallback = format!("_unreferenced/{}/{}", &sha1[..2], &sha1[2..]);
        let ok = write_blob_to_disk(&fallback, b"unmapped blob content", &dir);
        assert!(ok, "fallback path must be writable");
        let expected = dir
            .join("_unreferenced")
            .join("ab")
            .join("cdef1234567890abcdef1234567890abcdef12");
        assert!(
            expected.exists(),
            "fallback path shape must be _unreferenced/<xx>/<rest>"
        );
        assert_eq!(std::fs::read(&expected).unwrap(), b"unmapped blob content");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Sprint 2 (S2.8) — path validation hardening ──────────────────────────

    #[test]
    fn write_blob_rejects_nul_byte_in_component() {
        let dir = std::env::temp_dir().join(format!("gitrecon_nul_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // \0 in filename — Linux allows it in raw bytes but every filesystem-facing tool
        // and grep-style consumer breaks on it. We refuse rather than corrupt output.
        let ok = write_blob_to_disk("evil\0file.txt", b"x", &dir);
        assert!(!ok, "NUL byte in path component must be rejected");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_blob_rejects_symlink_escape() {
        // Sprint 2 (S2.8) core regression: attacker plants `link` inside output_dir
        // that points OUTSIDE output_dir. The raw prefix check (starts_with) misses
        // this — we need canonical-path comparison.
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let root =
                std::env::temp_dir().join(format!("gitrecon_symlink_test_{}", std::process::id()));
            let outside =
                std::env::temp_dir().join(format!("gitrecon_outside_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
            std::fs::create_dir_all(&root).unwrap();
            std::fs::create_dir_all(&outside).unwrap();
            // Plant symlink: <root>/escape -> <outside>
            symlink(&outside, root.join("escape")).unwrap();

            // Try to write escape/pwned — must be refused because escape resolves outside root.
            let ok = write_blob_to_disk("escape/pwned", b"payload", &root);
            assert!(!ok, "symlink-under-output_dir escape must be refused");
            // And the file must NOT exist in the outside dir.
            assert!(
                !outside.join("pwned").exists(),
                "canonical-path check failed — file leaked to {:?}",
                outside
            );

            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
        }
    }

    #[cfg(windows)]
    #[test]
    fn write_blob_rejects_windows_reserved_names() {
        let dir = std::env::temp_dir().join("gitrecon_win_reserved");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // CON, PRN etc. — Windows opens the device, not a file.
        assert!(!write_blob_to_disk("CON", b"x", &dir));
        assert!(!write_blob_to_disk("con.txt", b"x", &dir));
        assert!(!write_blob_to_disk("COM1.log", b"x", &dir));
        assert!(!write_blob_to_disk("lpt9", b"x", &dir));
        // Trailing dot/space are silently stripped by Windows.
        assert!(!write_blob_to_disk("evil.", b"x", &dir));
        assert!(!write_blob_to_disk("evil ", b"x", &dir));
        // Drive-letter component sneaked in.
        assert!(!write_blob_to_disk("C:evil.txt", b"x", &dir));
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

    // ── Sprint 5 (S5.7) — regex anchor correctness ───────────────────────────

    fn pattern(id: &str) -> Option<&'static Pattern> {
        PATTERNS.iter().find(|p| p.id == id)
    }

    #[test]
    fn twilio_regex_requires_word_boundary() {
        let re = &pattern("twilio").expect("twilio pattern must exist").regex;
        // Split the fixture across format! so GitHub push-protection secret
        // scanners don't flag the test string as a real credential — it's a
        // regex shape check, not a live key.
        let fake_key = format!("SK{}{}", "1234567890abcdef", "1234567890abcdef");
        assert!(re.is_match(&fake_key));
        // Same 32 hex chars but glued to a longer identifier — no boundary → reject.
        let embedded = format!("prefix{}suffix", fake_key);
        assert!(!re.is_match(&embedded));
    }

    #[test]
    fn mailchimp_regex_left_anchored() {
        let re = &pattern("mailchimp_key").expect("mailchimp pattern").regex;
        // 32 hex + `-us1` shape, split to defeat literal-string secret scanners.
        let fake_key = format!("{}{}-us1", "abcdef1234567890", "abcdef1234567890");
        assert!(re.is_match(&fake_key));
        // Embedded in longer hex — no left boundary → reject.
        let embedded = format!("prefix{}", fake_key);
        assert!(!re.is_match(&embedded));
    }

    #[test]
    fn jwt_regex_requires_20_chars_per_segment() {
        let re = &pattern("jwt").expect("jwt pattern").regex;
        // 20+ char segments — real JWT shape → match.
        let real = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                    eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.\
                    dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(re.is_match(real));
        // 10-char shape (previously accepted) — now rejected.
        assert!(!re.is_match("eyJabc.defghijklm.nopqrstuv"));
    }

    #[test]
    fn bearer_token_capped_at_256_chars() {
        let re = &pattern("bearer_token").expect("bearer_token pattern").regex;
        // 30-char token — legit shape → match.
        assert!(re.is_match("Authorization: Bearer abcdef1234567890abcdef1234567890"));
        // 300-char token — beyond cap, should still match up to 256 chars.
        // Regex engine won't greedy-eat past 256 now, so a super-long alphanumeric
        // string preceded by `Bearer ` still hits.
        let big = format!("Authorization: Bearer {}", "a".repeat(300));
        assert!(re.is_match(&big));
    }

    // ── V3 new secret patterns ───────────────────

    #[test]
    fn test_scan_content_finds_openai_key_legacy() {
        // 48 alphanumeric chars after sk-
        let key = format!("sk-{}", "A".repeat(48));
        let content = format!("OPENAI_API_KEY={}", key);
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
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
        let findings = scan_content(
            &content,
            "config.py",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "openai_key"),
            "Should detect OpenAI project key (sk-proj-<86 chars>)"
        );
    }

    #[test]
    fn test_scan_content_finds_anthropic_key() {
        let key = format!("sk-ant-{}", "A".repeat(95));
        let content = format!("ANTHROPIC_API_KEY={}", key);
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "anthropic_key"),
            "Should detect Anthropic API key"
        );
    }

    #[test]
    fn test_scan_content_finds_openrouter_key() {
        let key = format!("sk-or-v1-{}", "A".repeat(30));
        let content = format!("OPENROUTER_API_KEY={}", key);
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "openrouter_key"),
            "Should detect OpenRouter API key"
        );
    }

    #[test]
    fn test_scan_content_openrouter_key_min_boundary() {
        let key = format!("sk-or-v1-{}", "A".repeat(20));
        let findings = scan_content(
            &format!("OPENROUTER_API_KEY={}", key),
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(findings.iter().any(|f| f.pattern_id == "openrouter_key"));
    }

    #[test]
    fn test_scan_content_openrouter_key_below_boundary_not_detected() {
        let key = format!("sk-or-v1-{}", "A".repeat(19));
        let findings = scan_content(
            &format!("OPENROUTER_API_KEY={}", key),
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(!findings.iter().any(|f| f.pattern_id == "openrouter_key"));
    }

    #[test]
    fn test_scan_content_finds_ai_provider_env_key() {
        let key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let content = format!("DEEPSEEK_API_KEY={}", key);
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "ai_provider_env_key"),
            "Should detect AI provider env-style API key"
        );
    }

    #[test]
    fn test_scan_content_ai_provider_env_placeholder_filtered() {
        let content = "GEMINI_API_KEY=your_api_key_here";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.pattern_id == "ai_provider_env_key"),
            "Placeholder AI env key should be filtered"
        );
    }

    #[test]
    fn test_scan_content_finds_huggingface_token() {
        let token = format!("hf_{}", "a".repeat(36));
        let content = format!("HF_TOKEN={}", token);
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "huggingface_token"),
            "Should detect HuggingFace token"
        );
    }

    #[test]
    fn test_scan_content_finds_digitalocean_pat() {
        let token = format!("dop_v1_{}", "a".repeat(64));
        let content = format!("DO_TOKEN={}", token);
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
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
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "databricks_token"),
            "Should detect Databricks API token"
        );
    }

    #[test]
    fn test_scan_content_finds_vault_hvs_token() {
        let token = format!("hvs.{}", "A".repeat(30));
        let content = format!("VAULT_TOKEN={}", token);
        let findings = scan_content(
            &content,
            "config.sh",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "vault_token"),
            "Should detect HashiCorp Vault hvs token"
        );
    }
    #[test]
    fn test_scan_content_finds_planetscale_token() {
        let token = format!("pscale_tkn_{}", "A".repeat(43));
        let content = format!("DATABASE_TOKEN={}", token);
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "planetscale_token"),
            "Should detect PlanetScale token"
        );
    }

    #[test]
    fn test_scan_content_finds_supabase_key() {
        let key = format!("sbp_{}", "A".repeat(40));
        let content = format!("SUPABASE_KEY={}", key);
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "supabase_key"),
            "Should detect Supabase service role key"
        );
    }

    #[test]
    fn test_scan_content_finds_linear_key() {
        let key = format!("lin_api_{}", "A".repeat(40));
        let content = format!("LINEAR_KEY={}", key);
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "linear_key"),
            "Should detect Linear API key"
        );
    }

    #[test]
    fn test_sensitive_names_htpasswd() {
        assert!(
            is_sensitive_file(".htpasswd"),
            ".htpasswd should be sensitive"
        );
    }

    #[test]
    fn test_sensitive_names_env_prod() {
        assert!(
            is_sensitive_file(".env.prod"),
            ".env.prod should be sensitive"
        );
        assert!(
            is_sensitive_file(".env.production"),
            ".env.production should be sensitive"
        );
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
        assert!(
            tech.contains(&"Flutter".to_string()),
            "Should detect Flutter"
        );
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
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "shopify_token"),
            "Should detect Shopify Admin API token"
        );
    }

    #[test]
    fn test_scan_content_finds_jira_token() {
        let content = format!("JIRA_TOKEN=ATATT{}", "A".repeat(30));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "jira_token"),
            "Should detect Atlassian/Jira API token"
        );
    }

    #[test]
    fn test_scan_content_finds_sentry_dsn() {
        let dsn = format!("https://{}@o1234.ingest.sentry.io/5678", "a".repeat(32));
        let content = format!("SENTRY_DSN={}", dsn);
        let findings = scan_content(
            &content,
            "sentry.properties",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "sentry_dsn"),
            "Should detect Sentry DSN"
        );
    }

    #[test]
    fn test_scan_content_finds_cloudinary_url() {
        let content = "CLOUDINARY_URL=cloudinary://apikey:apisecret@cloudname";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "cloudinary_url"),
            "Should detect Cloudinary credentials URL"
        );
    }

    #[test]
    fn test_scan_content_finds_notion_token() {
        let content = format!("NOTION_TOKEN=secret_{}", "A".repeat(43));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "notion_token"),
            "Should detect Notion integration token"
        );
    }

    #[test]
    fn test_scan_content_finds_grafana_token() {
        let content = format!("GRAFANA_TOKEN=glsa_{}_ABCD1234", "A".repeat(32));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "grafana_token"),
            "Should detect Grafana service account token"
        );
    }

    #[test]
    fn test_scan_content_finds_mongodb_atlas_uri() {
        let content = "MONGO_URI=mongodb+srv://user:password@cluster.mongodb.net/db";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "mongodb_atlas"),
            "Should detect MongoDB Atlas connection string"
        );
    }

    #[test]
    fn test_scan_content_finds_discord_webhook() {
        let content = format!(
            "DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789012345678/{}",
            "A".repeat(68)
        );
        let findings = scan_content(
            &content,
            "config.js",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "discord_webhook"),
            "Should detect Discord webhook URL"
        );
    }

    #[test]
    fn test_placeholder_extended() {
        assert!(
            is_placeholder("null_token"),
            "null_ prefix should be a placeholder"
        );
        assert!(
            is_placeholder("my_secret_key"),
            "my_ prefix should be a placeholder"
        );
        assert!(
            is_placeholder("ENTER_VALUE_HERE"),
            "ENTER_ prefix should be a placeholder"
        );
        assert!(!is_placeholder("ghp_REALTOKEN123456789012345678901234567"));
    }

    #[test]
    fn test_sensitive_names_ssh_config() {
        assert!(
            is_sensitive_file(".ssh/config"),
            ".ssh/config should be sensitive"
        );
        assert!(
            is_sensitive_file("authorized_keys"),
            "authorized_keys should be sensitive"
        );
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
            &[],
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
            &[],
        );
        let openai = findings
            .iter()
            .find(|f| f.pattern_id == "openai_key")
            .expect("openai finding");
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
            &[],
        );
        let path_finding = findings
            .iter()
            .find(|f| f.pattern_id == "ai_path_prompt_history")
            .expect("ai path finding");
        let (is_ai, category, tags) = ai_metadata_for_finding(path_finding);
        assert!(is_ai);
        assert_eq!(category.as_deref(), Some("prompt_history"));
        assert!(tags.iter().any(|t| t == "claude"));
    }

    #[test]
    fn test_sensitive_names_aws_credentials() {
        assert!(
            is_sensitive_file(".aws/credentials"),
            ".aws/credentials should be sensitive"
        );
        assert!(
            is_sensitive_file(".aws/config"),
            ".aws/config should be sensitive"
        );
    }

    #[test]
    fn test_sensitive_names_id_ecdsa() {
        assert!(
            is_sensitive_file("id_ecdsa"),
            "id_ecdsa private key file should be sensitive"
        );
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
        assert!(
            shannon_entropy(s) > 3.5,
            "Random string should have high entropy"
        );
    }

    #[test]
    fn test_shannon_entropy_returns_zero_for_short_string() {
        assert_eq!(
            shannon_entropy("ab"),
            0.0,
            "Strings shorter than 4 chars yield 0.0"
        );
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
        assert!(
            stack.contains("Express"),
            "Should detect Express.js from content"
        );
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
        assert!(
            stack.contains("Prisma"),
            "Should detect Prisma from content"
        );
    }

    // Context window
    #[test]
    fn test_build_context_window_center() {
        let lines = vec!["a", "b", "c", "d", "e"];
        let ctx = build_context_window(&lines, 2, 2);
        assert!(
            ctx.contains('a'),
            "Window radius=2 from center=2 should include line 0"
        );
        assert!(
            ctx.contains('e'),
            "Window radius=2 from center=2 should include line 4"
        );
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
        scan_minified_segments(
            &minified,
            0,
            "bundle.min.js",
            &sha,
            false,
            false,
            &[],
            &mut findings,
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "aws_key_id"),
            "Should detect AWS key in minified JS segment"
        );
    }

    // YAML next-line secrets
    #[test]
    fn test_scan_yaml_nextline_finds_secret() {
        let sha = "a".repeat(40);
        let content = "password:\n  SuperSecretP@ssw0rd!!abc123xyz";
        let findings = scan_yaml_nextline_secrets(content, "config.yaml", &sha, false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "yaml_nextline_secret"),
            "Should detect YAML next-line secret"
        );
    }

    #[test]
    fn test_scan_yaml_nextline_skips_empty_value() {
        let sha = "a".repeat(40);
        let content = "password:\n  ";
        let findings = scan_yaml_nextline_secrets(content, "config.yaml", &sha, false, &[]);
        assert!(findings.is_empty(), "Should not flag empty YAML value");
    }

    // Entropy line scan
    #[test]
    fn test_scan_entropy_line_fires_for_high_entropy_secret() {
        let sha = "a".repeat(40);
        // Use a standalone keyword ("secret") so \bsecret\b matches
        let line = r#"secret = "xK9mQz3rN7wT2vB5sL0pJ4hY8uE6fA1d""#;
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
        let sha = "a".repeat(40);
        // 'description' is not in our keyword list, so no entropy finding expected
        let line = r#"description = "xK9mQz3rN7wT2vB5sL0pJ4hY8uE6fA1d""#;
        let lines = vec![line];
        let mut out = Vec::new();
        scan_entropy_line(line, 0, "config.py", &sha, false, &lines, &mut out, 4.5);
        assert!(
            out.is_empty(),
            "Should not fire when no keyword context present"
        );
    }

    // New provider patterns

    #[test]
    fn test_scan_content_finds_razorpay_key() {
        let content = format!("RAZORPAY_KEY=rzp_live_{}", "A".repeat(14));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "razorpay_key"),
            "Should detect Razorpay key"
        );
    }

    #[test]
    fn test_scan_content_finds_flyio_token() {
        let content = format!("FLY_TOKEN=fo1_{}", "A".repeat(40));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "flyio_token"),
            "Should detect Fly.io token"
        );
    }

    #[test]
    fn test_scan_content_finds_render_api_key() {
        let content = format!("RENDER_KEY=rnd_{}", "A".repeat(32));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "render_api_key"),
            "Should detect Render API key"
        );
    }

    #[test]
    fn test_scan_content_finds_scaleway_secret() {
        let content = "SCW_SECRET_KEY=12345678-1234-1234-1234-123456789abc";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "scaleway_secret_key"),
            "Should detect Scaleway secret key"
        );
    }

    #[test]
    fn test_scan_content_finds_square_key() {
        let content = format!("SQUARE_TOKEN=sq0csp-{}", "A".repeat(43));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "square_api_key"),
            "Should detect Square API key"
        );
    }

    #[test]
    fn test_scan_content_finds_mapbox_token() {
        let content =
            "MAPBOX_TOKEN=pk.eyJhIjoiYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoifQ.ABCDEFGHIJKLMNOPQRS";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "mapbox_token"),
            "Should detect Mapbox access token"
        );
    }

    #[test]
    fn scan_outcome_stats_preserve_typed_reasons() {
        let mut state = State::default();
        state.record_skip(SkipReason::StopRequested);
        state.record_skip(SkipReason::NotFound);
        state.record_skip(SkipReason::NotFound);
        state.record_failure(FailureKind::HttpStatus(429));
        state.record_failure(FailureKind::HttpStatus(429));
        state.record_failure(FailureKind::HttpStatus(503));

        let stats = ScanOutcomeStats::from_state(&state);
        assert_eq!(stats.skipped_stop_requested, 1);
        assert_eq!(stats.skipped_not_found, 2);
        assert_eq!(stats.skipped_total(), 3);
        assert_eq!(stats.failed_total(), 3);
        assert_eq!(stats.failed_http_statuses.get("429"), Some(&2));
        assert_eq!(stats.failed_http_statuses.get("503"), Some(&1));
    }

    #[test]
    fn processed_checkpoint_objects_are_sorted_deterministically() {
        let processed = HashSet::from([
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "cccccccccccccccccccccccccccccccccccccccc".to_string(),
        ]);

        assert_eq!(
            ordered_processed_sha1s(&processed),
            vec![
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                "cccccccccccccccccccccccccccccccccccccccc".to_string(),
            ]
        );
    }

    #[test]
    fn aggregate_state_roundtrip_restores_report_metrics() {
        let mut original = State::default();
        original
            .contributors
            .insert("analyst@example.test".to_string(), "Analyst".to_string());
        original
            .tech_stack
            .extend(["Rust".to_string(), "SQLite".to_string()]);
        original.commit_count = 4;
        original.blobs_scanned = 8;
        original.blobs_failed = 1;
        original.bytes_scanned = 4096;
        original.files_saved = 6;
        original.files_save_failed = 1;
        original.record_skip(SkipReason::NotFound);
        original.record_skip(SkipReason::Oversized);
        original.record_skip(SkipReason::ResourceBudget);
        original.record_failure(FailureKind::HttpStatus(503));
        original.record_source(ObjectSourceKind::Pack);
        original.record_source(ObjectSourceKind::Cache);
        original.record_source(ObjectSourceKind::LooseHttp);

        let snapshot = original.to_checkpoint(11, 13, 17, 2, 125);
        assert_eq!(snapshot.tech_stack, vec!["Rust", "SQLite"]);
        let encoded = serde_json::to_string(&snapshot).unwrap();
        let restored_snapshot: checkpoint::StreamAccumulatorCheckpoint =
            serde_json::from_str(&encoded).unwrap();

        let mut resumed = State::default();
        resumed.restore_checkpoint(restored_snapshot);

        assert_eq!(resumed.contributors, original.contributors);
        assert_eq!(resumed.tech_stack, original.tech_stack);
        assert_eq!(resumed.commit_count, original.commit_count);
        assert_eq!(resumed.blobs_scanned, original.blobs_scanned);
        assert_eq!(resumed.blobs_failed, original.blobs_failed);
        assert_eq!(resumed.bytes_scanned, original.bytes_scanned);
        assert_eq!(resumed.files_saved, original.files_saved);
        assert_eq!(resumed.files_save_failed, original.files_save_failed);
        assert_eq!(resumed.skipped_by_reason, original.skipped_by_reason);
        assert_eq!(snapshot.skipped_resource_budget, 1);
        assert_eq!(resumed.failed_by_kind, original.failed_by_kind);
        assert_eq!(resumed.objects_by_source, original.objects_by_source);
    }

    // unique_findings / unique_count
    #[test]
    fn unique_findings_do_not_truncate_distinct_matches() {
        let prefix = "A".repeat(80);
        let mut first = StreamResult::default();
        first.findings.push(Finding {
            filename: "one.txt".to_string(),
            line: 1,
            pattern_id: "custom".to_string(),
            description: "Custom finding".to_string(),
            severity: "HIGH".to_string(),
            match_str: format!("{prefix}x"),
            context: String::new(),
            is_deleted: false,
            commit_sha1: None,
            confidence_adjustment: None,
        });
        first.findings.push(Finding {
            filename: "two.txt".to_string(),
            line: 1,
            pattern_id: "custom".to_string(),
            description: "Custom finding".to_string(),
            severity: "HIGH".to_string(),
            match_str: format!("{prefix}y"),
            context: String::new(),
            is_deleted: false,
            commit_sha1: None,
            confidence_adjustment: None,
        });

        assert_eq!(first.unique_count(), 2);
        assert_eq!(first.unique_findings().len(), 2);
    }

    #[test]
    fn test_unique_findings_deduplicates() {
        let sha = "a".repeat(40);
        let content = "AKIAZ9XYZMNOP1234567\nAKIAZ9XYZMNOP1234567";
        let raw = scan_content(content, "file.sh", &sha, false, &[], 4.5, &[]);
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
            rate_limit_allowed: 0,
            rate_limit_dropped: 0,
            rate_limit_wait_ms: 0,
            retry_stats: None,
            cache_hits: 0,
            cache_misses: 0,
            cache_stats: None,
            object_source_stats: ObjectSourceStats::default(),
            outcome_stats: ScanOutcomeStats::default(),
        };
        // Both lines have the same match, so unique should be 1
        assert_eq!(
            sr.unique_count(),
            1,
            "Same secret on two lines should deduplicate to 1"
        );
        assert!(sr.unique_findings().len() <= sr.findings.len());
    }

    // DynPattern / load_patterns_from_file
    #[test]
    fn test_scan_content_uses_dyn_pattern() {
        let dyn_pat = super::DynPattern {
            id: "custom_token".to_string(),
            sev: "HIGH".to_string(),
            desc: "Custom test token".to_string(),
            regex: regex::Regex::new(r"CUSTOM_[A-Z0-9]{8}").unwrap(),
        };
        let content = "TOKEN=CUSTOM_ABCD1234";
        let findings = scan_content(
            content,
            "config.sh",
            "a".repeat(40).as_str(),
            false,
            &[dyn_pat],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "custom_token"),
            "Should detect custom dynamic pattern"
        );
    }

    #[test]
    fn test_load_patterns_from_file_valid() {
        // SEC-006: Patterns file must be within working directory (path traversal protection)
        // Create test file in current working directory instead of temp_dir
        let path = std::path::Path::new("gitrecon_test_patterns_valid.json");
        std::fs::write(path, br#"{"patterns":[{"id":"t","severity":"HIGH","description":"Test","regex":"TEST_[0-9]+"}]}"#).unwrap();
        let loaded = super::load_patterns_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "t");
        assert_eq!(loaded[0].sev, "HIGH");
        // Clean up test file
        let _ = std::fs::remove_file(path);
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
        assert!(
            out.is_empty(),
            "Low-entropy value (< 4.5 bits/char) must not produce findings"
        );
    }

    /// Verify that "put " (with space) is now treated as a placeholder.
    /// This covers WordPress wp-config-sample.php style "put your unique phrase here" values.
    #[test]
    fn test_placeholder_put_space_is_recognized() {
        assert!(
            is_placeholder("put your unique phrase here"),
            "'put ' should be recognized as a placeholder"
        );
        // A real-looking secret that does not contain any placeholder substring
        assert!(
            !is_placeholder("xK9mQz3rN7wT2vB5sL0pJ4hY8uE6fA1d"),
            "A high-entropy secret must not be flagged as placeholder"
        );
    }

    /// "your-api-key" style (hyphen) placeholder should be recognized.
    #[test]
    fn test_placeholder_your_hyphen_is_recognized() {
        assert!(
            is_placeholder("your-api-key-here"),
            "'your-' (with hyphen) should be recognized as a placeholder"
        );
        assert!(
            is_placeholder("YOUR-SECRET-HERE"),
            "'YOUR-' (with hyphen) should be recognized as a placeholder"
        );
    }

    /// "changeit" and "ChangeMe" should be recognized as placeholders.
    #[test]
    fn test_placeholder_changeit_changeme_variants() {
        assert!(
            is_placeholder("changeit"),
            "'changeit' should be a placeholder"
        );
        assert!(
            is_placeholder("ChangeMe_value"),
            "'ChangeMe' variant should be a placeholder"
        );
        assert!(
            is_placeholder("change this value"),
            "'change this' should be a placeholder"
        );
        assert!(
            is_placeholder("change-this-value"),
            "'change-this' should be a placeholder"
        );
    }

    /// Telegram bot pattern must require "telegram" or "bot" context keyword.
    /// A bare numeric-ID:token string without context must NOT match.
    #[test]
    fn test_telegram_bot_requires_context_keyword() {
        let sha = "a".repeat(40);
        // Bare token without any label (common FP source: order IDs, tracking numbers)
        let content = "order_id=1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi";
        let findings = scan_content(content, "config.php", &sha, false, &[], 4.5, &[]);
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
        let findings = scan_content(content, ".env", &sha, false, &[], 4.5, &[]);
        assert!(
            findings.iter().any(|f| f.pattern_id == "telegram_bot"),
            "Telegram bot token with 'TELEGRAM_BOT_TOKEN=' label must be detected"
        );
    }

    // ── V3.1 new secret pattern tests ─────────────

    #[test]
    fn test_scan_content_finds_github_fine_pat() {
        let content = format!("TOKEN=github_pat_{}", "A".repeat(82));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "github_fine_pat"),
            "Should detect GitHub fine-grained PAT"
        );
    }

    #[test]
    fn test_scan_content_finds_groq_key() {
        let content = format!("GROQ_KEY=gsk_{}", "A".repeat(52));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "groq_key"),
            "Should detect Groq API key"
        );
    }

    #[test]
    fn test_scan_content_finds_replicate_token() {
        let content = format!("REPLICATE_TOKEN=r8_{}", "A".repeat(40));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "replicate_token"),
            "Should detect Replicate API token"
        );
    }

    #[test]
    fn test_scan_content_finds_contentful_token() {
        let content = format!("CONTENTFUL_TOKEN=CFPAT-{}", "A".repeat(43));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "contentful_token"),
            "Should detect Contentful token"
        );
    }

    #[test]
    fn test_scan_content_finds_postman_key() {
        let content = format!("POSTMAN_KEY=PMAK-{}-{}", "A".repeat(24), "B".repeat(34));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "postman_key"),
            "Should detect Postman API key"
        );
    }

    #[test]
    fn test_scan_content_finds_tencent_secret_id() {
        let content = format!("TENCENT_ID=AKID{}", "A".repeat(32));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "tencent_secret_id"),
            "Should detect Tencent Cloud SecretId"
        );
    }

    #[test]
    fn test_scan_content_finds_age_secret_key() {
        let content =
            "AGE-SECRET-KEY-1QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE6M";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "age_secret_key"),
            "Should detect Age encryption secret key"
        );
    }

    #[test]
    fn test_scan_content_finds_clerk_secret() {
        let content = format!("CLERK_SECRET=sk_live_{}", "A".repeat(30));
        let findings = scan_content(
            &content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "clerk_secret"),
            "Should detect Clerk secret key"
        );
    }

    // ── V3.1 sensitive file tests ─────────────────

    #[test]
    fn test_sensitive_names_docker_config() {
        assert!(
            is_sensitive_file(".docker/config.json"),
            ".docker/config.json should be sensitive"
        );
    }

    #[test]
    fn test_sensitive_names_gradle_properties() {
        assert!(
            is_sensitive_file(".gradle/gradle.properties"),
            ".gradle/gradle.properties should be sensitive"
        );
    }

    #[test]
    fn test_sensitive_names_cargo_credentials() {
        assert!(
            is_sensitive_file(".cargo/credentials"),
            ".cargo/credentials should be sensitive"
        );
    }

    #[test]
    fn test_sensitive_names_bash_history() {
        assert!(
            is_sensitive_file(".bash_history"),
            ".bash_history should be sensitive"
        );
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
        assert!(
            tech.contains(&"Electron".to_string()),
            "Should detect Electron"
        );
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
        assert!(
            stack.contains("Tailwind"),
            "Should detect Tailwind CSS from content"
        );
    }

    // ── V3.1 commit message scanning ──────────────

    #[test]
    fn test_scan_content_on_commit_message_finds_secret() {
        // Simulate scanning a commit message that contains a secret
        let content = "fix: update config\n\nAWS_KEY=AKIAZ9XYZMNOP1234567";
        let findings = scan_content(
            content,
            "[commit:abcd1234:message]",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
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
        let findings = scan_content(
            content,
            "email.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "smtp_credentials"),
            "Should detect smtp_pass in PHP array format"
        );
    }

    #[test]
    fn test_scan_content_finds_smtp_credentials_env() {
        let content = "SMTP_PASS=secretpassword123";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "smtp_credentials"),
            "Should detect SMTP_PASS in .env format"
        );
    }

    #[test]
    fn test_scan_content_finds_smtp_password_yaml() {
        let content = "smtp_password: mysecretpassword";
        let findings = scan_content(
            content,
            "config.yaml",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "smtp_credentials"),
            "Should detect smtp_password in YAML format"
        );
    }

    #[test]
    fn test_scan_content_finds_smtp_url_with_credentials() {
        let content = "MAIL_URL=smtps://mailuser:secretpass@smtp.acme.net:465";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "smtp_url"),
            "Should detect SMTP URL with embedded credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_imap_credentials() {
        let content = r#"'imap_pass' => 'mailboxSecret99',"#;
        let findings = scan_content(
            content,
            "config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "imap_credentials"),
            "Should detect IMAP credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_pop3_credentials() {
        let content = "pop3_password = 'inbox_secret_pass'";
        let findings = scan_content(
            content,
            "mail.conf",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "imap_credentials"),
            "Should detect POP3 credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_ftp_credentials() {
        let content = r#"'ftp_pass' => 'ftpS3cret!',"#;
        let findings = scan_content(
            content,
            "deploy.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "ftp_credentials"),
            "Should detect FTP credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_sftp_credentials() {
        let content = "SFTP_PASSWORD=deploy_secret_key";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "ftp_credentials"),
            "Should detect SFTP credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_ftp_url_with_credentials() {
        let content = "FTP_URL=ftp://ftpuser:ftppassword@ftp.acme.net";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "ftp_url"),
            "Should detect FTP URL with embedded credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_amqp_url_with_credentials() {
        let content = "AMQP_URL=amqp://rabbitmq:r4bbitPass@localhost:5672/vhost";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "amqp_url"),
            "Should detect AMQP connection URL with credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_amqps_url_with_credentials() {
        let content = "RABBITMQ_URL=amqps://admin:amqpSecret@mq.acme.net:5671";
        let findings = scan_content(
            content,
            "config.sh",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "amqp_url"),
            "Should detect AMQPS (TLS) connection URL with credentials"
        );
    }

    #[test]
    fn test_scan_content_finds_ldap_credentials() {
        let content = "LDAP_URL=ldap://cn=admin:ldapSecret@ldap.acme.net";
        let findings = scan_content(
            content,
            ".env",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
        assert!(
            findings.iter().any(|f| f.pattern_id == "ldap_credentials"),
            "Should detect LDAP URL with embedded credentials"
        );
    }

    #[test]
    fn test_smtp_credentials_placeholder_filtered() {
        let content = "smtp_pass = 'changeme'";
        let findings = scan_content(
            content,
            "config.php",
            "a".repeat(40).as_str(),
            false,
            &[],
            4.5,
            &[],
        );
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
        assert!(
            m.chars().count() <= 120,
            "match must be truncated by char count"
        );
        assert!(
            c.chars().count() <= 200,
            "context must be truncated by char count"
        );
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
            rate_limit_allowed: 0,
            rate_limit_dropped: 0,
            rate_limit_wait_ms: 0,
            retry_stats: None,
            cache_hits: 0,
            cache_misses: 0,
            cache_stats: None,
            object_source_stats: ObjectSourceStats::default(),
            outcome_stats: ScanOutcomeStats::default(),
        };
        assert_eq!(stream.unique_count(), 1);
        assert_eq!(stream.unique_findings().len(), 1);
    }

    #[test]
    fn test_scan_minified_segments_unicode_context_is_safe() {
        let mut out = Vec::new();
        let line = format!("const key='{} AKIAZ9XYZMNOP1234567';", "─你好🔐".repeat(70));
        scan_minified_segments(
            &line,
            0,
            "bundle.min.js",
            &"a".repeat(40),
            false,
            false,
            &[],
            &mut out,
        );
        assert!(
            !out.is_empty(),
            "Expected at least one finding from AWS key pattern"
        );
        assert!(
            out.iter().any(|f| f.pattern_id == "aws_key_id"),
            "Expected aws_key_id finding from minified segment"
        );
        let ctx = out[0]
            .context
            .strip_prefix("[minified] ")
            .unwrap_or(&out[0].context);
        assert!(
            ctx.chars().count() <= 200,
            "Minified context must be truncated by char count"
        );
    }

    // ── SCAN-002: Multi-line pattern tests ─────────────

    #[test]
    fn test_multiline_pem_rsa_key_detection() {
        let pem = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2Z1ZvJN8uRK0XC9I3rL6xP4kW2lX5y8uB9nC3mD4fG5hK6lM7
nO8pQ9rS0tU1vW2xY3zA4bC5dE6fG7hI8jK9lM0nO1pQ2rS3tU4vW5xY6z
-----END RSA PRIVATE KEY-----"#;

        let findings = scan_multiline(pem, "private.key", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings.iter().any(|f| f.pattern_id == "pem_key_multiline"),
            "Should detect RSA PEM private key"
        );
        let finding = findings
            .iter()
            .find(|f| f.pattern_id == "pem_key_multiline")
            .unwrap();
        assert!(
            finding.description.contains("RSA"),
            "Should identify RSA key type"
        );
        assert_eq!(finding.severity, "CRITICAL", "PEM keys should be CRITICAL");
    }

    #[test]
    fn test_multiline_pem_ec_key_detection() {
        let pem = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILv+3xCm7W2Qd+zYK5q6j4cBxB+pP9l/gW8a/kV5xGoAoGCCqGSM49
-----END EC PRIVATE KEY-----"#;

        let findings = scan_multiline(pem, "ec_key.pem", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings.iter().any(|f| f.pattern_id == "pem_key_multiline"),
            "Should detect EC PEM private key"
        );
        let finding = findings
            .iter()
            .find(|f| f.pattern_id == "pem_key_multiline")
            .unwrap();
        assert!(
            finding.description.contains("EC"),
            "Should identify EC key type"
        );
    }

    #[test]
    fn test_multiline_nested_json_secret() {
        let json = r#"{
    "database": {
        "config": {
            "password": "SuperSecret123!@#"
        }
    }
}"#;

        let findings = scan_multiline(json, "config.json", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "json_nested_secret"),
            "Should detect nested JSON secret (3 levels)"
        );
        let finding = findings
            .iter()
            .find(|f| f.pattern_id == "json_nested_secret")
            .unwrap();
        assert!(
            finding.context.contains("database"),
            "Should include parent key in context"
        );
        assert!(
            finding.match_str.contains("SuperSecret123"),
            "Should capture secret value"
        );
    }

    #[test]
    fn test_multiline_yaml_block_scalar() {
        let yaml = r#"database_config: |
  api_key: synthetic_yaml_fixture_value_12345
  region: us-west-2"#;

        let findings = scan_multiline(yaml, "config.yaml", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "yaml_block_scalar_secret"),
            "Should detect YAML block scalar secret"
        );
        let finding = findings
            .iter()
            .find(|f| f.pattern_id == "yaml_block_scalar_secret")
            .unwrap();
        assert!(
            finding.context.contains("database_config"),
            "Should include key name in context"
        );
    }

    #[test]
    fn test_multiline_yaml_block_scalar_with_aws_secret() {
        let yaml = r#"secrets: |
  aws_secret_access_key: AbCdEf1234567890XyZ
  bucket_name: my-bucket"#;

        let findings = scan_multiline(yaml, "aws_config.yaml", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "yaml_block_scalar_secret"),
            "Should detect AWS secret in YAML block scalar"
        );
    }

    #[test]
    fn test_multiline_python_triple_quote() {
        let python = r#"
DATABASE_PASSWORD = """SuperSecretPassword123!"""
"#;

        let findings = scan_multiline(python, "settings.py", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "python_multiline_secret"),
            "Should detect Python triple-quoted secret"
        );
        let finding = findings
            .iter()
            .find(|f| f.pattern_id == "python_multiline_secret")
            .unwrap();
        assert!(
            finding.context.contains("triple"),
            "Should indicate triple-quoted context"
        );
    }

    #[test]
    fn test_multiline_python_triple_single_quote() {
        let python = r#"
SECRET_KEY = '''MyVerySecretKey!@#$%^&*()'''
"#;

        let findings = scan_multiline(python, "config.py", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "python_multiline_secret"),
            "Should detect Python triple single-quoted secret"
        );
    }

    #[test]
    fn test_multiline_ruby_heredoc() {
        let ruby = r#"
DB_PASSWORD = <<~HEREDOC
  MyRubySecret123!
HEREDOC
"#;

        let findings = scan_multiline(ruby, "database.rb", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "ruby_heredoc_secret"),
            "Should detect Ruby heredoc secret"
        );
        let finding = findings
            .iter()
            .find(|f| f.pattern_id == "ruby_heredoc_secret")
            .unwrap();
        assert!(
            finding.context.contains("DB_PASSWORD"),
            "Should include key name"
        );
    }

    #[test]
    fn test_multiline_php_array_config() {
        let php = r#"
return [
    'DB_PASSWORD' => 'MyPhpSecret456!',
    'DB_HOST' => 'localhost',
];
"#;

        let findings = scan_multiline(php, "config.php", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "php_multiline_secret"),
            "Should detect PHP array config secret"
        );
        let finding = findings
            .iter()
            .find(|f| f.pattern_id == "php_multiline_secret")
            .unwrap();
        assert!(
            finding.match_str.contains("MyPhpSecret"),
            "Should capture secret value"
        );
    }

    #[test]
    fn test_multiline_placeholder_filtering() {
        let pem = r#"-----BEGIN RSA PRIVATE KEY-----
placeholder_key_here
-----END RSA PRIVATE KEY-----"#;

        let findings = scan_multiline(pem, "sample.key", "a".repeat(40).as_str(), false, &[]);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "pem_key_multiline"),
            "Should filter placeholder PEM keys"
        );
    }

    #[test]
    fn test_multiline_entropy_threshold_yaml_scalar() {
        let yaml = r#"config: |
  password: low
"#;

        let findings = scan_multiline(yaml, "config.yaml", "a".repeat(40).as_str(), false, &[]);
        assert!(
            !findings
                .iter()
                .any(|f| f.pattern_id == "yaml_block_scalar_secret"),
            "Should not flag low-entropy YAML scalar values"
        );
    }

    #[test]
    fn test_multiline_no_false_positives_normal_json() {
        let json = r#"{
    "username": "admin",
    "role": "user",
    "status": "active"
}"#;

        let findings = scan_multiline(json, "user.json", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings.is_empty(),
            "Should not produce false positives on normal JSON without secrets"
        );
    }

    #[test]
    fn test_multiline_context_analysis_applies() {
        let pem = r#"-----BEGIN RSA PRIVATE KEY-----
REPLACE_WITH_YOUR_KEY
-----END RSA PRIVATE KEY-----"#;

        let findings = scan_multiline(pem, "config.key", "a".repeat(40).as_str(), false, &[]);
        assert!(
            !findings.iter().any(|f| f.severity == "CRITICAL"),
            "Should downgrade severity for placeholder PEM keys"
        );
    }

    // ── SCAN-004: Multi-Line DB Credential Detection tests ─────

    #[test]
    fn test_scan_db_config_finds_django_secret_key() {
        let content = r#"SECRET_KEY = 'django-insecure-abcdefghijklmnopqrstuvwxyz1234567890!@#'"#;
        let findings =
            scan_db_config_blocks(content, "settings.py", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings.iter().any(|f| f.pattern_id == "django_secret_key"),
            "Should detect Django SECRET_KEY"
        );
    }

    #[test]
    fn test_scan_db_config_finds_django_env_secret() {
        let content = r#"SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')"#;
        let findings =
            scan_db_config_blocks(content, "settings.py", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "django_env_secret_key"),
            "Should detect Django SECRET_KEY from os.environ"
        );
        let finding = findings
            .iter()
            .find(|f| f.pattern_id == "django_env_secret_key")
            .unwrap();
        assert!(
            finding.match_str.contains("DJANGO_SECRET_KEY"),
            "Should capture env var name"
        );
    }

    #[test]
    fn test_scan_db_config_finds_ruby_database_url() {
        let content = r#"DATABASE_URL = "postgresql://user:secret_password@localhost/dbname""#;
        let findings =
            scan_db_config_blocks(content, "database.yml", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings.iter().any(|f| f.pattern_id == "ruby_database_url"),
            "Should detect Ruby DATABASE_URL"
        );
    }

    #[test]
    fn test_scan_db_config_finds_ruby_config_hash_password() {
        let content = r#"production: { adapter: 'postgresql', password: 'rubypass123' }"#;
        let findings =
            scan_db_config_blocks(content, "config.rb", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "ruby_config_password"),
            "Should detect Ruby config hash password"
        );
    }

    #[test]
    fn test_scan_db_config_finds_laravel_app_key() {
        let content = r#"APP_KEY=base64:2yXRi5GVjcL3PYQhjnGQ2Vt7W8KX4v0PHq1MQ=="#;
        let findings = scan_db_config_blocks(content, ".env", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "php_laravel_app_key"),
            "Should detect Laravel APP_KEY"
        );
    }

    #[test]
    fn test_scan_db_config_finds_php_db_config() {
        let content = r#"DB_PASSWORD='MyStrongP@ssw0rd'"#;
        let findings = scan_db_config_blocks(content, ".env", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings.iter().any(|f| f.pattern_id == "php_db_config"),
            "Should detect PHP DB_* config"
        );
    }

    #[test]
    fn test_scan_db_config_finds_go_config_password_struct() {
        let content = r#"type Config struct {
    Host     string
    Password string
    Port     int
}"#;
        let findings =
            scan_db_config_blocks(content, "config.go", "a".repeat(40).as_str(), false, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.pattern_id == "go_config_password_struct"),
            "Should detect Go config struct with Password field"
        );
    }

    #[test]
    fn test_scan_db_config_filters_django_secret_placeholder() {
        let content = r#"SECRET_KEY = 'change-this-to-your-secret-key'"#;
        let findings =
            scan_db_config_blocks(content, "settings.py", "a".repeat(40).as_str(), false, &[]);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "django_secret_key"),
            "Should filter placeholder Django SECRET_KEY"
        );
    }

    #[test]
    fn test_scan_db_config_filters_low_entropy_secret() {
        let content = r#"SECRET_KEY = 'abcdefgh'"#;
        let findings =
            scan_db_config_blocks(content, "settings.py", "a".repeat(40).as_str(), false, &[]);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "django_secret_key"),
            "Should filter low-entropy SECRET_KEY"
        );
    }

    // ════════════════════════════════════════════════
    // PERF-003: Adaptive Concurrency Tests
    // ════════════════════════════════════════════════

    #[tokio::test]
    async fn adaptive_gate_enforces_runtime_limit() {
        use tokio::time::{timeout, Duration};

        let gate = AdaptiveConcurrencyGate::new(2);
        let first = gate.acquire().await;
        let second = gate.acquire().await;
        gate.set_limit(1);
        assert_eq!(gate.current_limit(), 1);

        let waiter_gate = gate.clone();
        let mut waiter = tokio::spawn(async move {
            let _permit = waiter_gate.acquire().await;
        });
        assert!(timeout(Duration::from_millis(25), &mut waiter)
            .await
            .is_err());

        drop(second);
        drop(first);
        timeout(Duration::from_secs(1), &mut waiter)
            .await
            .expect("waiter should proceed after active permits drain")
            .expect("waiter task should succeed");
    }

    #[test]
    fn test_adaptive_new_initializes_correctly() {
        let ac = AdaptiveConcurrency::new(50, false);
        assert_eq!(ac.current_workers(), 50);
    }

    #[test]
    fn test_adaptive_from_checkpoint_restores_state() {
        let state = AdaptiveConcurrencyState {
            current_workers: 75,
            initial_workers: 100,
            window_requests: 42,
            window_errors: 3,
            last_adjustment_index: 500,
        };
        let ac = AdaptiveConcurrency::from_checkpoint(state, false);
        assert_eq!(ac.current_workers(), 75);
    }

    #[test]
    fn test_adaptive_to_checkpoint_state() {
        let ac = AdaptiveConcurrency::new(60, true);
        ac.record_success();
        ac.record_success();
        ac.record_error();

        let state = ac.to_checkpoint_state();
        assert_eq!(state.current_workers, 60);
        assert_eq!(state.initial_workers, 60);
        assert_eq!(state.window_requests, 3);
        assert_eq!(state.window_errors, 1);
        assert_eq!(state.last_adjustment_index, 0);
    }

    #[test]
    fn test_record_success_increments_requests() {
        let ac = AdaptiveConcurrency::new(20, false);
        ac.record_success();
        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, 1);
        assert_eq!(state.window_errors, 0);
    }

    #[test]
    fn test_record_error_increments_both_counters() {
        let ac = AdaptiveConcurrency::new(20, false);
        ac.record_error();
        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, 1);
        assert_eq!(state.window_errors, 1);
    }

    #[test]
    fn test_multiple_record_success_updates() {
        let ac = AdaptiveConcurrency::new(20, false);
        for _ in 0..100 {
            ac.record_success();
        }
        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, 100);
        assert_eq!(state.window_errors, 0);
    }

    #[test]
    fn test_mixed_success_and_error_counts() {
        let ac = AdaptiveConcurrency::new(20, false);
        ac.record_success();
        ac.record_success();
        ac.record_error();
        ac.record_success();
        ac.record_error();
        ac.record_error();

        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, 6);
        assert_eq!(state.window_errors, 3);
    }

    #[test]
    fn test_concurrent_record_success_no_lost_updates() {
        use std::sync::Arc;
        use std::thread;

        let ac = Arc::new(AdaptiveConcurrency::new(50, false));
        let iterations = 1000;

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let ac = Arc::clone(&ac);
                thread::spawn(move || {
                    for _ in 0..100 {
                        ac.record_success();
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let state = ac.to_checkpoint_state();
        assert_eq!(
            state.window_requests, iterations,
            "All concurrent updates should be recorded"
        );
        assert_eq!(state.window_errors, 0);
    }

    #[test]
    fn test_concurrent_record_error_no_lost_updates() {
        use std::sync::Arc;
        use std::thread;

        let ac = Arc::new(AdaptiveConcurrency::new(50, false));
        let iterations = 1000;

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let ac = Arc::clone(&ac);
                thread::spawn(move || {
                    for _ in 0..100 {
                        ac.record_error();
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, iterations);
        assert_eq!(state.window_errors, iterations);
    }

    #[test]
    fn test_concurrent_mixed_success_and_error() {
        use std::sync::Arc;
        use std::thread;

        let ac = Arc::new(AdaptiveConcurrency::new(50, false));
        let success_count = 750;
        let error_count = 250;

        let success_handles: Vec<_> = (0..5)
            .map(|_| {
                let ac = Arc::clone(&ac);
                thread::spawn(move || {
                    for _ in 0..150 {
                        ac.record_success();
                    }
                })
            })
            .collect();

        let error_handles: Vec<_> = (0..5)
            .map(|_| {
                let ac = Arc::clone(&ac);
                thread::spawn(move || {
                    for _ in 0..50 {
                        ac.record_error();
                    }
                })
            })
            .collect();

        for handle in success_handles {
            handle.join().unwrap();
        }
        for handle in error_handles {
            handle.join().unwrap();
        }

        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, success_count + error_count);
        assert_eq!(state.window_errors, error_count);
    }

    #[test]
    fn test_rayon_parallel_record_success() {
        use rayon::prelude::*;
        use std::sync::Arc;

        let ac = Arc::new(AdaptiveConcurrency::new(50, false));
        let iterations = 10_000;

        (0..iterations).into_par_iter().for_each(|_| {
            ac.record_success();
        });

        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, iterations);
    }

    #[test]
    fn test_rayon_parallel_record_error() {
        use rayon::prelude::*;
        use std::sync::Arc;

        let ac = Arc::new(AdaptiveConcurrency::new(50, false));
        let iterations = 10_000;

        (0..iterations).into_par_iter().for_each(|_| {
            ac.record_error();
        });

        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, iterations);
        assert_eq!(state.window_errors, iterations);
    }

    #[test]
    fn test_rayon_parallel_mixed_updates() {
        use rayon::prelude::*;
        use std::sync::Arc;

        let ac = Arc::new(AdaptiveConcurrency::new(50, false));
        let iterations = 10_000;

        (0..iterations).into_par_iter().for_each(|i| {
            if i % 4 == 0 {
                ac.record_error();
            } else {
                ac.record_success();
            }
        });

        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, iterations);
        assert_eq!(state.window_errors, iterations / 4);
    }

    #[test]
    fn test_error_rate_zero_percent() {
        let ac = AdaptiveConcurrency::new(50, false);
        for _ in 0..100 {
            ac.record_success();
        }

        let state = ac.to_checkpoint_state();
        let error_rate = state.window_errors as f64 / state.window_requests as f64;
        assert_eq!(error_rate, 0.0);
    }

    #[test]
    fn test_error_rate_fifty_percent() {
        let ac = AdaptiveConcurrency::new(50, false);
        for _ in 0..50 {
            ac.record_success();
            ac.record_error();
        }

        let state = ac.to_checkpoint_state();
        let error_rate = state.window_errors as f64 / state.window_requests as f64;
        assert_eq!(error_rate, 0.5);
    }

    #[test]
    fn test_error_rate_just_below_throttle_threshold() {
        let ac = AdaptiveConcurrency::new(50, false);
        for _ in 0..91 {
            ac.record_success();
        }
        for _ in 0..10 {
            ac.record_error();
        }

        let state = ac.to_checkpoint_state();
        let error_rate = state.window_errors as f64 / state.window_requests as f64;
        assert!((error_rate - 0.099).abs() < 0.001);
    }

    #[test]
    fn test_error_rate_at_throttle_threshold() {
        let ac = AdaptiveConcurrency::new(50, false);
        for _ in 0..90 {
            ac.record_success();
        }
        for _ in 0..10 {
            ac.record_error();
        }

        let state = ac.to_checkpoint_state();
        let error_rate = state.window_errors as f64 / state.window_requests as f64;
        assert_eq!(error_rate, 0.1);
    }

    #[test]
    fn test_error_rate_above_throttle_threshold() {
        let ac = AdaptiveConcurrency::new(50, false);
        for _ in 0..85 {
            ac.record_success();
        }
        for _ in 0..15 {
            ac.record_error();
        }

        let state = ac.to_checkpoint_state();
        let error_rate = state.window_errors as f64 / state.window_requests as f64;
        assert_eq!(error_rate, 0.15);
    }

    #[test]
    fn test_error_rate_under_load_concurrent() {
        use std::sync::Arc;
        use std::thread;

        let ac = Arc::new(AdaptiveConcurrency::new(50, false));
        let total = 10_000;

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let ac = Arc::clone(&ac);
                thread::spawn(move || {
                    for i in 0..(total / 10) {
                        if i % 10 < 2 {
                            // 20% error rate for more deterministic testing
                            ac.record_error();
                        } else {
                            ac.record_success();
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        let state = ac.to_checkpoint_state();
        let error_rate = state.window_errors as f64 / state.window_requests as f64;
        // Should be ~20% (2000/10000)
        assert!(
            error_rate > 0.19 && error_rate < 0.21,
            "Expected ~20% error rate, got {:.4}",
            error_rate
        );
    }

    #[test]
    fn test_should_adjust_at_interval() {
        let ac = AdaptiveConcurrency::new(50, false);
        assert!(ac.should_adjust(100));
        assert!(ac.should_adjust(200));
    }

    #[test]
    fn test_should_adjust_false_before_interval() {
        let ac = AdaptiveConcurrency::new(50, false);
        assert!(!ac.should_adjust(50));
        assert!(!ac.should_adjust(99));
    }

    #[test]
    fn test_adjust_decreases_on_throttle_detection() {
        let ac = AdaptiveConcurrency::new(50, false);
        for _ in 0..85 {
            ac.record_success();
        }
        for _ in 0..15 {
            ac.record_error();
        }

        let new_workers = ac.adjust(100);
        assert!(new_workers < 50);
        assert_eq!(new_workers, 25);
    }

    #[test]
    fn test_adjust_minimum_bound() {
        let ac = AdaptiveConcurrency::new(5, false);
        for _ in 0..85 {
            ac.record_success();
        }
        for _ in 0..15 {
            ac.record_error();
        }

        let new_workers = ac.adjust(100);
        assert_eq!(new_workers, 5);
    }

    #[test]
    fn test_adjust_no_change_moderate_error_rate() {
        let ac = AdaptiveConcurrency::new(50, false);
        for _ in 0..95 {
            ac.record_success();
        }
        for _ in 0..5 {
            ac.record_error();
        }

        let new_workers = ac.adjust(100);
        assert_eq!(new_workers, 50);
    }

    #[test]
    fn test_adjust_increases_on_headroom() {
        // Start below initial to allow headroom to increase
        let ac = AdaptiveConcurrency::new(30, false);
        // Reduce workers first by creating high error rate
        for _ in 0..85 {
            ac.record_success();
        }
        for _ in 0..15 {
            ac.record_error();
        }
        let workers_after_decrease = ac.adjust(100); // Decreases to 15

        // BUG-STAB-006: Counters decayed to 20%: 20 requests, 3 errors
        // Need to dilute decayed errors below 2% threshold to trigger increase
        // Formula: 3 / (20 + X) < 0.02  =>  X > 130
        for _ in 0..131 {
            ac.record_success();
        }

        let new_workers = ac.adjust(200);
        // Should increase from 15: increase = 30/10 = 3, new = 15 + 3 = 18
        assert!(
            new_workers > workers_after_decrease,
            "Workers should increase on low error rate"
        );
        assert_eq!(new_workers, 18, "Should increase by initial_workers/10");
    }

    #[test]
    fn test_adjust_does_not_exceed_initial() {
        let ac = AdaptiveConcurrency::new(30, false);
        for _ in 0..85 {
            ac.record_success();
        }
        for _ in 0..15 {
            ac.record_error();
        }
        let _ = ac.adjust(100); // Reduces to 15

        // Now record low error rate with big sample
        for _ in 0..199 {
            ac.record_success();
        }
        ac.record_error();

        let new_workers = ac.adjust(200);
        // Should not exceed initial (30)
        assert!(new_workers <= 30);
    }

    #[test]
    fn test_adjust_requires_minimum_sample_size() {
        let ac = AdaptiveConcurrency::new(50, false);
        for _ in 0..10 {
            ac.record_success();
        }

        let new_workers = ac.adjust(100);
        assert_eq!(new_workers, 50);
    }

    #[test]
    fn test_adjust_with_no_requests_returns_current() {
        let ac = AdaptiveConcurrency::new(50, false);
        let new_workers = ac.adjust(100);
        assert_eq!(new_workers, 50);
    }

    #[test]
    fn test_adjust_updates_last_adjustment_index() {
        let ac = AdaptiveConcurrency::new(50, false);
        ac.adjust(100);

        let state = ac.to_checkpoint_state();
        assert_eq!(state.last_adjustment_index, 100);
    }

    #[test]
    fn test_adjust_resets_window_counters() {
        let ac = AdaptiveConcurrency::new(50, false);
        for _ in 0..100 {
            ac.record_success();
        }

        ac.adjust(100);

        let state = ac.to_checkpoint_state();
        // BUG-STAB-006: Implementation uses exponential decay (20% retention) instead of hard reset
        assert_eq!(state.window_requests, 20); // 100 * 0.2 = 20 (decay factor)
        assert_eq!(state.window_errors, 0);
    }

    #[test]
    fn test_checkpoint_round_trip_preserves_state() {
        let ac1 = AdaptiveConcurrency::new(75, true);
        ac1.record_success();
        ac1.record_success();
        ac1.record_error();
        ac1.adjust(100);

        let state = ac1.to_checkpoint_state();
        let ac2 = AdaptiveConcurrency::from_checkpoint(state, false);

        assert_eq!(ac2.current_workers(), ac1.current_workers());
    }

    #[test]
    fn test_checkpoint_round_trip_with_adjusted_workers() {
        let ac1 = AdaptiveConcurrency::new(100, true);
        for _ in 0..80 {
            ac1.record_success();
        }
        for _ in 0..20 {
            ac1.record_error();
        }
        ac1.adjust(100);

        let state = ac1.to_checkpoint_state();
        let ac2 = AdaptiveConcurrency::from_checkpoint(state, false);

        assert_eq!(ac2.current_workers(), 50);
    }

    #[test]
    fn test_concurrent_adjust_during_updates() {
        use std::sync::Arc;
        use std::thread;

        let ac = Arc::new(AdaptiveConcurrency::new(100, false));

        let update_handle = thread::spawn({
            let ac = Arc::clone(&ac);
            move || {
                for _ in 0..1000 {
                    ac.record_success();
                    if ac.should_adjust(500) {
                        ac.adjust(500);
                    }
                }
            }
        });

        let read_handle = thread::spawn({
            let ac = Arc::clone(&ac);
            move || {
                for _ in 0..100 {
                    let _ = ac.current_workers();
                }
            }
        });

        update_handle.join().unwrap();
        read_handle.join().unwrap();
    }

    #[test]
    fn unified_detector_pipeline_preserves_exhaustive_superset() {
        let text = "api_key: |\n  your_api_key_here_value_123";
        let keywords: [&str; 0] = [];
        let normal = scan_text_detectors(
            text,
            DetectorContext {
                filename: "config.yaml",
                sha1: "a",
                is_deleted: true,
                extra_patterns: &[],
                policy: ScanPolicy::normal(2.5, &keywords),
            },
        );
        let exhaustive = scan_text_detectors(
            text,
            DetectorContext {
                filename: "config.yaml",
                sha1: "a",
                is_deleted: true,
                extra_patterns: &[],
                policy: ScanPolicy::exhaustive(2.5, &keywords),
            },
        );

        assert!(normal
            .iter()
            .all(|finding| exhaustive.iter().any(|candidate| {
                candidate.pattern_id == finding.pattern_id
                    && candidate.match_str == finding.match_str
            })));
        assert!(exhaustive
            .iter()
            .any(|finding| finding.pattern_id == "yaml_block_scalar_secret"));
    }

    #[test]
    fn exhaustive_scan_retains_placeholder_candidates() {
        let text = "api_key=your_api_key_here_value_123";
        let normal = scan_text(text, "config.env", &[], 4.5);
        let exhaustive = scan_text_exhaustive(text, "config.env", &[], 4.5);
        assert!(normal
            .iter()
            .all(|finding| !finding.match_str.contains("your_api_key_here_value_123")));
        assert!(exhaustive.iter().any(|finding| {
            finding.pattern_id == "api_key"
                && finding.match_str.contains("your_api_key_here_value_123")
        }));
    }

    #[test]
    fn exhaustive_entropy_scan_retains_placeholder_candidates() {
        let text = r#"secret = "your_xK9mQz3rN7wT2vB5sL0pJ4hY8uE6fA1d""#;
        let normal = scan_text(text, "config.env", &[], 4.5);
        let exhaustive = scan_text_exhaustive(text, "config.env", &[], 4.5);
        assert!(normal
            .iter()
            .all(|finding| finding.pattern_id != "high_entropy_secret"));
        assert!(exhaustive.iter().any(|finding| {
            finding.pattern_id == "high_entropy_secret"
                && finding
                    .match_str
                    .contains("your_xK9mQz3rN7wT2vB5sL0pJ4hY8uE6fA1d")
        }));
    }

    #[test]
    fn exhaustive_yaml_scan_retains_placeholder_candidates() {
        let text = "api_key: |\n  your_api_key_here_value_123";
        let normal = scan_text(text, "config.yaml", &[], 2.5);
        let exhaustive = scan_text_exhaustive(text, "config.yaml", &[], 2.5);
        assert!(normal
            .iter()
            .all(|finding| finding.pattern_id != "yaml_block_scalar_secret"));
        assert!(exhaustive.iter().any(|finding| {
            finding.pattern_id == "yaml_block_scalar_secret"
                && finding.match_str.contains("your_api_key_here_value_123")
        }));
    }

    #[test]
    fn test_stress_concurrent_updates_and_adjustments() {
        use rayon::prelude::*;
        use std::sync::Arc;

        let ac = Arc::new(AdaptiveConcurrency::new(100, false));
        let iterations = 50_000;

        (0..iterations).into_par_iter().for_each(|i| {
            if i % 100 == 0 {
                ac.record_error();
            } else {
                ac.record_success();
            }
        });

        let state = ac.to_checkpoint_state();
        assert_eq!(state.window_requests, iterations);
        assert!(state.window_errors > 0);
    }
}

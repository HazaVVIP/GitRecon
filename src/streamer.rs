//! streamer.rs
//! Phase 3 — Stream & Scan: fetch every object, scan for secrets in memory,
//! optionally writing blobs to disk when --save is active.
//! Output: StreamResult with all findings + intel.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use regex::Regex;
use lazy_static::lazy_static;
use futures::StreamExt;

use crate::http_client::HttpClient;
use crate::git_parser::{ObjectParser, obj_path};
use crate::mapper::MapResult;

// ════════════════════════════════════════════════
// SECRET PATTERNS
// ════════════════════════════════════════════════

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
             r"\d{8,10}:[A-Za-z0-9_-]{35}"),
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
    ];

    static ref PLACEHOLDERS: Vec<&'static str> = vec![
        "your_", "YOUR_", "example", "EXAMPLE", "placeholder",
        "xxxx", "XXXX", "changeme", "CHANGE_ME", "insert_",
        "TODO", "FIXME", "test_", "TEST_", "dummy", "DUMMY",
        "replace", "REPLACE", "sample", "SAMPLE", "fake", "FAKE",
        "00000000", "11111111", "<", ">",
        // Additional common dev/template placeholders
        "n/a", "N/A", "none", "NONE", "null", "NULL", "undefined",
        "my_", "MY_", "enter_", "ENTER_", "set_", "SET_",
        "fill_", "FILL_", "put_", "PUT_", "add_", "ADD_",
    ];

    static ref SENSITIVE_NAMES: Regex = Regex::new(
        r#"(?i)(\.env|\.env\.|config\.php|wp-config|database\.php|settings\.py|config\.ya?ml|credentials|secrets?\.json|service.account|\.npmrc|\.pypirc|\.netrc|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem|\.key|\.pfx|\.p12|application\.(properties|ya?ml)|docker.compose|\.travis\.yml|\.circleci|\.github/workflows|\.env\.local|\.env\.prod(uction)?|\.env\.staging|\.env\.development|vault\.ya?ml|terraform\.tfvars|\.kubeconfig|kubeconfig|\.htpasswd|\.aws/credentials|\.aws/config|gcloud/credentials|\.config/gcloud|sentry\.properties|\.npmrc|\.yarnrc|Dockerfile|\.kube/config|\.ssh/config|authorized_keys|known_hosts)"#
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
    ];
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
}

impl Finding {
    pub fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "file":      self.filename,
            "line":      self.line,
            "type":      self.pattern_id,
            "desc":      self.description,
            "severity":  self.severity,
            "match":     &self.match_str[..self.match_str.len().min(120)],
            "context":   &self.context[..self.context.len().min(200)],
            "deleted":   self.is_deleted,
            "blob_sha1": self.commit_sha1,
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
        email: String,
        name:  String,
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
    client:      HttpClient,
    workers:     usize,
    #[allow(dead_code)]
    mem_limit:   usize,
    verbose:     bool,
}

impl Streamer {
    pub fn new(client: HttpClient, workers: usize, mem_limit_mb: usize, verbose: bool) -> Self {
        Self {
            client,
            workers,
            mem_limit: mem_limit_mb * 1024 * 1024,
            verbose,
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
        let sha1_to_file = Arc::new(sha1_to_file);
        let current_blobs = Arc::new(current_blobs);

        // Priority: blobs from index first (sensitive), then commit graph
        let mut priority_blobs: Vec<String> = map_result.blob_sha1s.iter().cloned().collect();
        let other_sha1s: Vec<String> = map_result.commit_sha1s.iter().cloned().collect();

        // Sort: sensitive files first (no lock needed — sha1_to_file is immutable here)
        priority_blobs.sort_by_key(|sha1| {
            if is_sensitive_file(sha1_to_file.get(sha1).map(|f| f.as_str()).unwrap_or("")) {
                0
            } else {
                1
            }
        });

        let all_sha1s: Vec<String> = priority_blobs.into_iter().chain(other_sha1s).collect();
        let total = all_sha1s.len();

        if self.verbose {
            println!(
                "  [*] Streaming {} objects ({} blobs + {} commit/tree graph)...",
                total,
                map_result.blob_sha1s.len(),
                map_result.commit_sha1s.len(),
            );
        }

        let done_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Use FuturesUnordered with buffer_unordered for bounded concurrency
        // Each future returns a WorkerResult; aggregation is single-threaded (no lock contention).
        let workers = self.workers;
        let stream = futures::stream::iter(all_sha1s)
            .map(|sha1| {
                let client = self.client.clone();
                let git_url = git_url.clone();
                let sha1_to_file = sha1_to_file.clone();
                let current_blobs = current_blobs.clone();
                let save_dir = save_dir_arc.clone();
                async move {
                    fetch_and_process(&client, &git_url, &sha1, &sha1_to_file, &current_blobs, save_dir).await
                }
            })
            .buffer_unordered(workers);

        let mut state = State::default();

        futures::pin_mut!(stream);
        while let Some(result) = stream.next().await {
            let done = done_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if let Some(ref cb) = progress_cb {
                cb(done, total);
            }
            match result {
                WorkerResult::BlobScanned { findings, tech, bytes, save_result } => {
                    state.blobs_scanned += 1;
                    state.bytes_scanned += bytes;
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
                    state.blobs_failed += 1;
                }
                WorkerResult::CommitProcessed { email, name } => {
                    state.commit_count += 1;
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
const MAX_SCAN_BYTES: usize = 4 * 1024 * 1024;

async fn fetch_and_process(
    client: &HttpClient,
    git_url: &str,
    sha1: &str,
    sha1_to_file: &HashMap<String, String>,
    current_blobs: &HashSet<String>,
    save_dir: Option<Arc<PathBuf>>,
) -> WorkerResult {
    let url  = format!("{}/{}", git_url, obj_path(sha1));
    let resp = client.get(&url).await;

    if !resp.ok() {
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
            // Fast binary detection: check first 8 KB for null bytes
            let probe = &obj.data[..obj.data.len().min(8192)];
            let null_count = probe.iter().filter(|&&b| b == 0).count();
            if null_count > 10 {
                // Binary file — skip scanning, still count bytes
                return WorkerResult::BlobScanned {
                    findings:    vec![],
                    tech:        vec![],
                    bytes:       raw_bytes,
                    save_result: None,
                };
            }

            // Skip blobs that exceed the scan size limit
            if obj.data.len() > MAX_SCAN_BYTES {
                return WorkerResult::BlobScanned {
                    findings:    vec![],
                    tech:        vec![],
                    bytes:       raw_bytes,
                    save_result: None,
                };
            }

            let filename = sha1_to_file.get(sha1)
                .cloned()
                .unwrap_or_else(|| format!("[blob:{}]", &sha1[..8]));
            let is_deleted = !current_blobs.contains(sha1);

            let mut tech = Vec::new();
            collect_tech(&filename, &mut tech);

            let content = match std::str::from_utf8(&obj.data) {
                Ok(s)  => s.to_string(),
                Err(_) => String::from_utf8_lossy(&obj.data).into_owned(),
            };

            let findings = scan_content(&content, &filename, sha1, is_deleted);

            // Optionally write blob to disk (--save integration: avoids a second download pass)
            let save_result = if let Some(ref dir) = save_dir {
                if let Some(actual_name) = sha1_to_file.get(sha1) {
                    Some(write_blob_to_disk(actual_name, &obj.data, dir))
                } else {
                    None
                }
            } else {
                None
            };

            WorkerResult::BlobScanned { findings, tech, bytes: raw_bytes, save_result }
        }
        "commit" => {
            if let Some(commit) = parser.parse_commit(&obj) {
                WorkerResult::CommitProcessed {
                    email: commit.author_email,
                    name:  commit.author,
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
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        if line.len() > 2000 {
            continue;
        }

        for pat in PATTERNS.iter() {
            for m in pat.regex.find_iter(line) {
                let val = m.as_str().to_string();
                if is_placeholder(&val) {
                    continue;
                }
                findings.push(Finding {
                    filename:    filename.to_string(),
                    line:        lineno + 1,
                    pattern_id:  pat.id.to_string(),
                    description: pat.desc.to_string(),
                    severity:    pat.sev.to_string(),
                    match_str:   val,
                    context:     line.trim().to_string(),
                    is_deleted,
                    commit_sha1: Some(sha1.to_string()),
                });
            }
        }
    }

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
    SENSITIVE_NAMES.is_match(filename)
}

fn is_placeholder(s: &str) -> bool {
    PLACEHOLDERS.iter().any(|p| s.contains(p))
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
        let findings = scan_content(content, "config.sh", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "aws_key_id"),
            "Should detect AWS key ID pattern"
        );
    }

    #[test]
    fn test_scan_content_skips_long_lines() {
        let long_line = "A".repeat(2001);
        let findings = scan_content(&long_line, "file.txt", "a".repeat(40).as_str(), false);
        // Long lines should be skipped — no findings
        assert!(findings.is_empty(), "Lines >2000 chars should be skipped");
    }

    #[test]
    fn test_scan_content_finds_wp_define_credential() {
        let content = r#"define('DB_PASSWORD', 'supersecret123');"#;
        let findings = scan_content(content, "wp-config.php", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "wp_define"),
            "Should detect WordPress define() credential"
        );
    }

    #[test]
    fn test_scan_content_finds_wp_define_auth_key() {
        let content = r#"define( 'AUTH_KEY', 'put your unique phrase here' );"#;
        let findings = scan_content(content, "wp-config.php", "a".repeat(40).as_str(), false);
        // "put your" is not in PLACEHOLDERS, but we verify the pattern matches at all
        assert!(
            findings.iter().any(|f| f.pattern_id == "wp_define"),
            "Should detect WordPress AUTH_KEY define()"
        );
    }

    #[test]
    fn test_scan_content_finds_django_secret_key() {
        let content = r#"SECRET_KEY = 'django-insecure-abcdefghijklmnopqrstuvwxyz1234567890!@#'"#;
        let findings = scan_content(content, "settings.py", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "django_secret"),
            "Should detect Django SECRET_KEY"
        );
    }

    #[test]
    fn test_scan_content_finds_google_api_key() {
        // AIza + exactly 35 alphanumeric/dash/underscore chars
        let content = "GOOGLE_KEY=AIzaSyC1234567890abcdefghijklmnop123456";
        let findings = scan_content(content, "config.js", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "gcp_api_key"),
            "Should detect Google/GCP API Key"
        );
    }

    #[test]
    fn test_scan_content_finds_laravel_app_key() {
        let content = "APP_KEY=base64:SomeBase64EncodedKeyHereThatIsLongEnoughToMatch==";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "laravel_app_key"),
            "Should detect Laravel APP_KEY"
        );
    }

    #[test]
    fn test_no_private_ip_false_positive() {
        // Private IPs no longer trigger any finding
        let content = "db_host = 192.168.1.100";
        let findings = scan_content(content, "config.ini", "a".repeat(40).as_str(), false);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "private_ip"),
            "Private IP should not be flagged"
        );
    }

    #[test]
    fn test_no_s3_url_false_positive() {
        // S3 URLs no longer trigger a MEDIUM finding
        let content = "endpoint = https://mybucket.s3.amazonaws.com";
        let findings = scan_content(content, "config.ini", "a".repeat(40).as_str(), false);
        assert!(
            !findings.iter().any(|f| f.pattern_id == "s3_url"),
            "S3 URL should not be flagged"
        );
    }

    #[test]
    fn test_no_entropy_medium_finding() {
        // Entropy check is removed; quoted high-entropy strings should not produce MEDIUM findings
        let content = r#"some_field = "R2l0UmVjb25Jc0F3ZXNvbWVUb29sRm9yU2VjdXJpdHk=""#;
        let findings = scan_content(content, "file.txt", "a".repeat(40).as_str(), false);
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
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
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
        let findings = scan_content(&content, "config.py", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "openai_key"),
            "Should detect OpenAI project key (sk-proj-<86 chars>)"
        );
    }

    #[test]
    fn test_scan_content_finds_anthropic_key() {
        let key = format!("sk-ant-{}", "A".repeat(95));
        let content = format!("ANTHROPIC_API_KEY={}", key);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "anthropic_key"),
            "Should detect Anthropic API key"
        );
    }

    #[test]
    fn test_scan_content_finds_huggingface_token() {
        let token = format!("hf_{}", "a".repeat(36));
        let content = format!("HF_TOKEN={}", token);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "huggingface_token"),
            "Should detect HuggingFace token"
        );
    }

    #[test]
    fn test_scan_content_finds_digitalocean_pat() {
        let token = format!("dop_v1_{}", "a".repeat(64));
        let content = format!("DO_TOKEN={}", token);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
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
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "databricks_token"),
            "Should detect Databricks API token"
        );
    }

    #[test]
    fn test_scan_content_finds_vault_hvs_token() {
        let token = format!("hvs.{}", "A".repeat(30));
        let content = format!("VAULT_TOKEN={}", token);
        let findings = scan_content(&content, "config.sh", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "vault_token"),
            "Should detect HashiCorp Vault hvs token"
        );
    }    #[test]
    fn test_scan_content_finds_planetscale_token() {
        let token = format!("pscale_tkn_{}", "A".repeat(43));
        let content = format!("DATABASE_TOKEN={}", token);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "planetscale_token"),
            "Should detect PlanetScale token"
        );
    }

    #[test]
    fn test_scan_content_finds_supabase_key() {
        let key = format!("sbp_{}", "A".repeat(40));
        let content = format!("SUPABASE_KEY={}", key);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "supabase_key"),
            "Should detect Supabase service role key"
        );
    }

    #[test]
    fn test_scan_content_finds_linear_key() {
        let key = format!("lin_api_{}", "A".repeat(40));
        let content = format!("LINEAR_KEY={}", key);
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
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
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "shopify_token"),
            "Should detect Shopify Admin API token"
        );
    }

    #[test]
    fn test_scan_content_finds_jira_token() {
        let content = format!("JIRA_TOKEN=ATATT{}", "A".repeat(30));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "jira_token"),
            "Should detect Atlassian/Jira API token"
        );
    }

    #[test]
    fn test_scan_content_finds_sentry_dsn() {
        let dsn = format!("https://{}@o1234.ingest.sentry.io/5678", "a".repeat(32));
        let content = format!("SENTRY_DSN={}", dsn);
        let findings = scan_content(&content, "sentry.properties", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "sentry_dsn"),
            "Should detect Sentry DSN"
        );
    }

    #[test]
    fn test_scan_content_finds_cloudinary_url() {
        let content = "CLOUDINARY_URL=cloudinary://apikey:apisecret@cloudname";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "cloudinary_url"),
            "Should detect Cloudinary credentials URL"
        );
    }

    #[test]
    fn test_scan_content_finds_notion_token() {
        let content = format!("NOTION_TOKEN=secret_{}", "A".repeat(43));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "notion_token"),
            "Should detect Notion integration token"
        );
    }

    #[test]
    fn test_scan_content_finds_grafana_token() {
        let content = format!("GRAFANA_TOKEN=glsa_{}_ABCD1234", "A".repeat(32));
        let findings = scan_content(&content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "grafana_token"),
            "Should detect Grafana service account token"
        );
    }

    #[test]
    fn test_scan_content_finds_mongodb_atlas_uri() {
        let content = "MONGO_URI=mongodb+srv://user:password@cluster.mongodb.net/db";
        let findings = scan_content(content, ".env", "a".repeat(40).as_str(), false);
        assert!(
            findings.iter().any(|f| f.pattern_id == "mongodb_atlas"),
            "Should detect MongoDB Atlas connection string"
        );
    }

    #[test]
    fn test_scan_content_finds_discord_webhook() {
        let content = format!("DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789012345678/{}", "A".repeat(68));
        let findings = scan_content(&content, "config.js", "a".repeat(40).as_str(), false);
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
    fn test_sensitive_names_aws_credentials() {
        assert!(is_sensitive_file(".aws/credentials"), ".aws/credentials should be sensitive");
        assert!(is_sensitive_file(".aws/config"), ".aws/config should be sensitive");
    }

    #[test]
    fn test_sensitive_names_id_ecdsa() {
        assert!(is_sensitive_file("id_ecdsa"), "id_ecdsa private key file should be sensitive");
    }
}

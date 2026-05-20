# GitRecon

**GitRecon** is a high-performance, streaming Git exposure scanner written in Rust.  
It detects exposed `.git` directories on web servers and recovers secrets, credentials, and source code hidden inside — all in memory, without writing to disk.

**v3.1.0** · 127 secret patterns · 61 metadata probes · 59 tech stack fingerprints · ~4800 lines of Rust

---

## Features

- 🔍 **Phase 1 – Detect** — Discovers exposed `.git` directories with confidence scoring and optional path fuzzing  
- 🗺️ **Phase 2 – Map** — Reconstructs the full object graph (commits, trees, blobs) from the exposed repo  
- 🌊 **Phase 3 – Stream & Scan** — Fetches every object concurrently, scans in-memory for 110 secret patterns (API keys, passwords, tokens, private keys, …) plus Shannon entropy analysis  
- 📄 **Phase 4 – Report** — Outputs a structured JSON report and optional on-disk source reconstruction  

---

## Installation

### One-liner (recommended)

```bash
curl -sSf https://raw.githubusercontent.com/HazaVVIP/GitRecon/main/install.sh | bash
```

The installer will:
1. Try to download a pre-built binary from the [Releases](https://github.com/HazaVVIP/GitRecon/releases) page.  
2. If no pre-built binary is available for your platform, it will build from source using Cargo.

### Build from source

Requires [Rust](https://rustup.rs/) ≥ 1.75.

```bash
git clone https://github.com/HazaVVIP/GitRecon.git
cd GitRecon
cargo build --release
# Binary is at: ./target/release/gitrecon
```

---

## Usage

```
gitrecon <URL> [OPTIONS]
gitrecon --token <PAT> [OPTIONS]
gitrecon --dir <PATH> [OPTIONS]
```

### Basic examples

```bash
# Detect and scan a target
gitrecon https://target.com

# Scan a local directory recursively (text files)
gitrecon --dir ./my-project

# Save reconstructed source to disk
gitrecon https://target.com --save

# Use a SOCKS5 proxy (e.g., Tor)
gitrecon https://target.com --proxy socks5://127.0.0.1:9050

# Add request delay and custom timeout
gitrecon https://target.com --delay 1.5 --timeout 15

# Fuzz non-standard .git paths (api/.git, admin/.git, .git.bak, _git, …)
gitrecon https://target.com --fuzz

# Stop on first critical finding
gitrecon https://target.com --stop-on-critical

# Load custom patterns from a JSON file
gitrecon https://target.com --patterns my_patterns.json

# Quiet mode, save output to a custom directory
gitrecon https://target.com --no-color -q --output ./results
```

### All options

| Flag | Default | Description |
|---|---|---|
| `--dir PATH` | — | Scan local directory recursively (cannot be combined with URL/`--targets`/`--token`) |
| `--save` | off | Reconstruct source code to disk after scan |
| `-o`, `--output DIR` | `./gitrecon_output` | Output directory |
| `--proxy URL` | — | Proxy URL (`socks5://`, `socks4://`, `http://`) |
| `--timeout SEC` | 10 | HTTP request timeout |
| `--retries N` | 3 | Retry count per request |
| `--delay SEC` | 0 | Delay between requests |
| `--jitter SEC` | 0 | Random jitter added to delay |
| `--user-agent UA` | — | Custom User-Agent string |
| `--header NAME:VALUE` | — | Extra HTTP header (repeatable) |
| `--fuzz` | off | Try non-standard `.git` paths (including backups, build dirs) |
| `-w`, `--workers N` | 50 | Concurrent worker tasks |
| `--mem-limit MB` | 256 | Memory limit for streaming |
| `--max-findings N` | 0 | Stop after N findings (0 = unlimited) |
| `--stop-on-critical` | off | Stop scan immediately on first CRITICAL finding |
| `--patterns FILE` | — | Load additional detection patterns from a JSON file |
| `--min-confidence PCT` | 45 | Minimum confidence to continue (0–100) |
| `--no-color` | off | Disable terminal colours |
| `-q`, `--quiet` | off | Reduce terminal output |

Mode selection:
- `--token` mode: scan repositories accessible by GitHub PAT.
- `--dir` mode: scan local directory files directly (no HTTP/.git detection pipeline).
- URL/`--targets` mode: scan exposed `.git` endpoints remotely.

`--dir` notes: symbolic links are skipped to avoid traversal loops, binary-like extensions are skipped, and files larger than `--max-blob-size` are ignored.

---

## Output

Results are written as JSON to `<output>/<target>_report.json`.  
When `--save` is used, reconstructed source files are placed under `<output>/<target>/`.

---

## Detected Secret Types (110 patterns)

**Cloud providers:**  
AWS Access Key ID · AWS Secret Access Key · AWS MFA Serial · GCP Service Account · GCP API Key · Azure Storage Connection String · Azure SAS Token · Azure AD Client Secret · Oracle OCI API Key Fingerprint · Alibaba Cloud Access Key · IBM Cloud API Key

**Version control & CI/CD:**  
GitHub PAT · GitHub OAuth · GitHub App Token · GitLab PAT · Bitbucket App Password · CircleCI Token · Travis CI Token · Jenkins API Token

**AI providers:**  
OpenAI API keys (legacy, project-scoped, service account) · Anthropic API keys · HuggingFace tokens · Cohere API Key

**Payments & e-commerce:**  
Stripe secret/publishable/webhook keys · PayPal Client ID/Secret · Shopify Admin API Token · Shopify Shared Secret · Square API Key · Adyen API Key · Razorpay API Key · Braintree Access Token · Coinbase API Key

**Messaging & communications:**  
Slack tokens/webhooks/signing secrets · Discord bot tokens/webhooks · Telegram bot tokens · SendGrid · Twilio API Key/Account SID · Mailgun · Pusher · Mailchimp

**Infrastructure & PaaS:**  
HashiCorp Vault tokens · DigitalOcean PATs · Databricks tokens · Cloudflare Global API Key/Token · Heroku API Key · Vercel Token · Netlify PAT · Linode/Akamai PAT · Vultr API Key · Hetzner Cloud Token · Scaleway Secret Key · Fly.io Token · Render API Key · Terraform Cloud Token

**Database & DBaaS:**  
Database connection URLs (MySQL, PostgreSQL, MongoDB, Redis, MSSQL, CockroachDB, ClickHouse) · Database passwords · MongoDB Atlas Connection String · PlanetScale Token · Supabase Service Role Key · Neon Database Token · Upstash Redis · Fauna Secret · Xata API Key · Turso Auth Token

**Secrets management:**  
Doppler Service Token · Linear API Key

**Project management & collaboration:**  
Jira/Atlassian API Token · Confluence API Token · Asana PAT · Notion Integration Token

**Observability & monitoring:**  
Datadog API Key · New Relic License Key · Grafana Service Account Token · Sentry DSN · PagerDuty API Key

**Keys & certificates:**  
Private keys (RSA/EC/DSA/OpenSSH/PGP) · PKCS12/PFX references · JWT tokens · JWT secrets

**Application frameworks:**  
Generic API/secret keys · Access tokens · Bearer tokens · Hardcoded passwords · Env passwords · WordPress config credentials · Django/Flask SECRET_KEY · Rails secret_key_base · Laravel APP_KEY · OAuth Client Secret

**Other services:**  
Firebase FCM Key · Firebase RTDB Auth · NPM Token · Docker Hub PAT · Twitch OAuth · Algolia API Key · Cloudinary URL · Okta API Token · Mapbox Token · Infura Project Key · Railway Token

**Advanced detection:**  
Shannon entropy analysis (context-aware, threshold 4.5 bits/char) · YAML next-line secret detection · Minified JS segment scanning · Placeholder filtering (54 patterns) · Sensitive filename priority scoring

---

## Git Exposure Vectors Detected (--fuzz)

In fuzz mode GitRecon probes all common `.git` locations, including:

| Path | Use case |
|---|---|
| `/.git/` | Standard location |
| `/api/.git/`, `/v1/.git/`, … | Versioned API backends |
| `/admin/.git/`, `/backend/.git/` | Admin panels |
| `/_git/` | Azure DevOps / VSTS local clones |
| `/dist/.git/`, `/build/.git/` | Accidentally committed build artefacts |
| `/assets/.git/` | Static-asset directories |
| `/.git.bak/`, `/.git.old/` | Backup copies of `.git` |
| `/wp-content/.git/` | WordPress installs |

---

## Architecture

GitRecon operates in a **4-phase streaming pipeline**, each phase feeding into the next:

```
Phase 1 — DETECT        Phase 2 — MAP           Phase 3 — STREAM & SCAN       Phase 4 — REPORT
┌──────────────────┐    ┌──────────────────┐    ┌───────────────────────────┐   ┌──────────────────┐
│ Probe .git paths │    │ Fetch metadata   │    │ Concurrent object fetch   │   │ Risk scoring     │
│ Confidence score │ ──▶│ Collect SHA1s    │ ──▶│ Zlib decompress           │──▶│ JSON report      │
│ Fuzz variants    │    │ Parse pack index │    │ 110 regex secret patterns │   │ Terminal display  │
│ Branch & remote  │    │ Estimate size    │    │ Entropy analysis          │   │ Source reconstruct│
└──────────────────┘    └──────────────────┘    │ Tech stack fingerprint    │   └──────────────────┘
                                                │ Memory-limited streaming  │
                                                └───────────────────────────┘
```

### Modules

| Module | Lines | Responsibility |
|---|---|---|
| `main.rs` | ~330 | CLI parsing (clap), phase orchestration, configuration |
| `detect.rs` | ~410 | Phase 1 — probe 8 metadata files, confidence scoring (0–100 %), fuzz 18+ paths |
| `mapper.rs` | ~485 | Phase 2 — fetch 46 metadata files, collect SHA1s, parse pack indexes (v1 & v2) |
| `streamer.rs` | ~2020 | Phase 3 — concurrent fetch, 110 secret patterns, Shannon entropy, YAML multi-line, minified JS |
| `reporter.rs` | ~290 | Phase 4 — risk score, coloured terminal output, JSON report |
| `git_parser.rs` | ~545 | Git object parser (loose objects, DIRC index v2–v4, pack index v1/v2, packed-refs, config) |
| `http_client.rs` | ~200 | HTTP wrapper — exponential backoff, proxy (SOCKS5/HTTP), rate limiting, UA rotation |
| `reconstructor.rs` | ~120 | Optional source reconstruction to disk (`--save`), path-traversal defence |

### Tech Stack

- **Language:** Rust (edition 2021)
- **Async runtime:** Tokio (full features)
- **HTTP:** reqwest (rustls-tls, SOCKS, gzip/deflate)
- **CLI:** clap 4 (derive)
- **Concurrency:** futures `buffer_unordered`, rayon, lock-free atomics
- **Compression:** flate2 (zlib)
- **Hashing:** sha1, hex
- **Output:** serde_json, colored, indicatif

### Testing

GitRecon includes **110 unit tests** across all modules:

```bash
cargo test           # Run all tests
cargo clippy         # Lint check (zero warnings)
cargo fmt --check    # Format check
```

| Module | Tests | Coverage |
|---|---|---|
| `detect.rs` | 14 | Confidence scoring, path variants, verifiers |
| `mapper.rs` | 12 | MapResult methods, META_FILES coverage |
| `git_parser.rs` | 5 | HEAD/ref parsing, SHA1 extraction, packed-refs |
| `streamer.rs` | 79 | All 110 secret patterns, entropy, tech detection, placeholder filtering, YAML/minified scanning |

---

## Roadmap

Peningkatan diurutkan berdasarkan **dampak × kompleksitas**. Setiap tahap bersifat independen dan dapat di-release secara terpisah.

### Tahap 1 — Resilience & Reliability

| ID | Peningkatan | Prioritas |
|---|---|---|
| R-1 | **Checkpoint & Resume** — Simpan progress ke checkpoint file, flag `--resume` | **P0** |
| R-2 | **Smart Retry per Status Code** — `404` skip, `429` respect Retry-After, `503` backoff | **P1** |
| R-3 | **Adaptive Per-Object Timeout** — Moving average latency × 3 | **P2** |

### Tahap 2 — Performance & Throughput

| ID | Peningkatan | Prioritas |
|---|---|---|
| P-1 | **Adaptive Concurrency** — Auto-tune workers berdasarkan error rate | **P1** |
| P-2 | **HTTP/2 Multiplexing** — Flag `--http2` | **P2** |
| P-3 | **Prefetching Berbasis Graf** — Queue child blob SHA1s dari tree objects | **P3** |
| P-4 | **Streaming Decompression** — `async_compression` untuk lower peak memory | **P3** |

### Tahap 3 — Scanning Quality

| ID | Peningkatan | Prioritas |
|---|---|---|
| S-1 | **Context-Aware Confidence** — Turunkan confidence jika ada `# example` di sekitar match | **P2** |
| S-2 | **Full Multi-Line Pattern** — Regex dot-all untuk PEM, JSON nested, YAML block | **P2** |
| S-3 | **Binary File Scanning** — SQLite string extraction, JAR/ZIP scanning | **P3** |
| S-4 | **Multi-Line DB Credentials** — Python/Ruby/PHP database config detection | **P3** |

### Tahap 4 — Stealth & Evasion

| ID | Peningkatan | Prioritas |
|---|---|---|
| E-1 | **Token Bucket Rate Limiter** — Flag `--rate N` req/s | **P2** |
| E-2 | **Multi-Proxy Rotation** — Flag `--proxy-list FILE` | **P3** |
| E-3 | **Request Fingerprint Diversification** — Header variation, decoy requests | **P4** |
| E-4 | **Extended UA Pool** — 20+ UAs, `--ua-file FILE`, `--ua git/2.x.x` | **P4** |

### Tahap 5 — Output & Integration

| ID | Peningkatan | Prioritas |
|---|---|---|
| O-1 | **Real-Time Streaming Output** — Flag `--live` | **P2** |
| O-2 | **SARIF Format** — Flag `--format sarif` untuk GitHub Security tab | **P3** |
| O-3 | **Additional Formats** — CSV, NDJSON, Markdown, HTML | **P4** |
| O-4 | **Webhook Integration** — Flag `--webhook URL` | **P4** |

### Tahap 6 — Architecture & Scalability

| ID | Peningkatan | Prioritas |
|---|---|---|
| A-1 | **Multi-Target Scanning** — Flag `--targets FILE` | **P3** |
| A-2 | **SQLite Cache** — Cache di `~/.gitrecon/cache.db`, `--no-cache` | **P3** |
| A-3 | **Smart HTTP Protocol** — `git-upload-pack` negotiation | **P4** |
| A-4 | **Delta Object Resolution** — `OBJ_REF_DELTA` / `OBJ_OFS_DELTA` decompression | **P4** |
| A-5 | **Plugin Architecture** — Trait `Scanner` + shared library loader | **P5** |
| A-6 | **Pipeline Mode** — Flag `--pipe` untuk NDJSON stdout | **P3** |

---

## Contributing

1. Fork repositori
2. Buat branch fitur (`git checkout -b feature/R-1-checkpoint`)
3. Gunakan ID dari roadmap sebagai prefix branch dan commit
4. Pastikan `cargo test`, `cargo clippy`, dan `cargo fmt --check` bersih
5. Buat pull request dengan deskripsi perubahan

---

## Legal

This tool is intended for **authorised security testing and research only**.  
Do not use it against systems you do not own or have explicit permission to test.

---

## License

[MIT](LICENSE)

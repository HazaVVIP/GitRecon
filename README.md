# GitRecon

**GitRecon** is a high-performance, streaming Git exposure scanner written in Rust.  
It detects exposed `.git` directories on web servers and recovers secrets, credentials, and source code hidden inside.

---

## Features

- 🔍 **Phase 1 – Detect** — Discovers exposed `.git` directories with confidence scoring and optional path fuzzing  
- 🗺️ **Phase 2 – Map** — Reconstructs the full object graph (commits, trees, blobs) from the exposed repo  
- 🌊 **Phase 3 – Stream & Scan** — Fetches every object concurrently, scans in-memory for 50+ secret patterns (API keys, passwords, tokens, private keys, …)  
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
```

### Basic examples

```bash
# Detect and scan a target
gitrecon https://target.com

# Save reconstructed source to disk
gitrecon https://target.com --save

# Use a SOCKS5 proxy (e.g., Tor)
gitrecon https://target.com --proxy socks5://127.0.0.1:9050

# Add request delay and custom timeout
gitrecon https://target.com --delay 1.5 --timeout 15

# Fuzz non-standard .git paths (api/.git, admin/.git, .git.bak, _git, …)
gitrecon https://target.com --fuzz

# Quiet mode, save output to a custom directory
gitrecon https://target.com --no-color -q --output ./results
```

### All options

| Flag | Default | Description |
|---|---|---|
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
| `--min-confidence PCT` | 45 | Minimum confidence to continue (0–100) |
| `--no-color` | off | Disable terminal colours |
| `-q`, `--quiet` | off | Reduce terminal output |

---

## Output

Results are written as JSON to `<output>/<target>_report.json`.  
When `--save` is used, reconstructed source files are placed under `<output>/<target>/`.

---

## Detected Secret Types

**Cloud providers:**  
AWS keys · GCP service accounts · Azure connection strings

**Version control & CI:**  
GitHub/GitLab PATs · GitHub App/OAuth tokens

**AI providers (v3):**  
OpenAI API keys (legacy & project-scoped) · Anthropic API keys · HuggingFace tokens

**Payments:**  
Stripe secret/publishable keys

**Messaging:**  
Slack tokens/webhooks · Discord bot tokens · Telegram bot tokens · SendGrid · Twilio · Mailgun

**Infrastructure (v3):**  
HashiCorp Vault tokens · DigitalOcean PATs · Databricks tokens

**Database-as-a-service (v3):**  
Database connection URLs & passwords · PlanetScale tokens · Supabase service keys

**Secrets management (v3):**  
Doppler service tokens · Linear API keys

**Keys & certs:**  
Private keys (RSA/EC/DSA/OpenSSH/PGP)

**Application frameworks:**  
JWT tokens & secrets · Generic API/secret keys · Access tokens · Hardcoded passwords ·  
WordPress config credentials · Django/Flask SECRET_KEY · Rails secret_key_base · Laravel APP_KEY

**Other:**  
Firebase FCM keys · NPM tokens · Docker Hub PATs · OAuth client secrets

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

## Legal

This tool is intended for **authorised security testing and research only**.  
Do not use it against systems you do not own or have explicit permission to test.

---

## License

[MIT](LICENSE)

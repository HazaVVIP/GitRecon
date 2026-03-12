# GitRecon

**GitRecon** is a high-performance, streaming Git exposure scanner written in Rust.  
It detects exposed `.git` directories on web servers and recovers secrets, credentials, and source code hidden inside.

---

## Features

- 🔍 **Phase 1 – Detect** — Discovers exposed `.git` directories with confidence scoring and optional path fuzzing  
- 🗺️ **Phase 2 – Map** — Reconstructs the full object graph (commits, trees, blobs) from the exposed repo  
- 🌊 **Phase 3 – Stream & Scan** — Fetches every object concurrently, scans in-memory for 40+ secret patterns (API keys, passwords, tokens, private keys, …)  
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

# Fuzz non-standard .git paths (api/.git, admin/.git, …)
gitrecon https://target.com --fuzz

# Quiet mode, save output to a custom directory
gitrecon https://target.com --no-color -q --output ./results
```

### All options

| Flag | Default | Description |
|---|---|---|
| `--save` | off | Reconstruct source code to disk after scan |
| `-o`, `--output DIR` | `./gitrecon_output` | Output directory |
| `--proxy URL` | — | Proxy URL (`socks5://`, `http://`) |
| `--timeout SEC` | 10 | HTTP request timeout |
| `--retries N` | 3 | Retry count per request |
| `--delay SEC` | 0 | Delay between requests |
| `--jitter SEC` | 0 | Random jitter added to delay |
| `--user-agent UA` | — | Custom User-Agent string |
| `--header NAME:VALUE` | — | Extra HTTP header (repeatable) |
| `--fuzz` | off | Try non-standard `.git` paths |
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

AWS keys · GCP service accounts · Azure connection strings · GitHub/GitLab PATs ·  
Stripe keys · Slack tokens/webhooks · Discord bot tokens · Telegram bot tokens ·  
SendGrid · Twilio · Mailgun · Database connection URLs & passwords · Private keys (RSA/EC/DSA/OpenSSH/PGP) ·  
JWT tokens & secrets · Generic API/secret keys · Access tokens · Hardcoded passwords ·  
Firebase FCM keys · NPM tokens · Docker Hub PATs · OAuth client secrets ·  
High-entropy strings · S3 bucket URLs · Private IP addresses

---

## Legal

This tool is intended for **authorised security testing and research only**.  
Do not use it against systems you do not own or have explicit permission to test.

---

## License

[MIT](LICENSE)

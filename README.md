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

## Architecture

GitRecon operates in a **4-phase streaming pipeline**, each phase feeding into the next:

```
Phase 1 — DETECT        Phase 2 — MAP           Phase 3 — STREAM & SCAN       Phase 4 — REPORT
┌──────────────────┐    ┌──────────────────┐    ┌───────────────────────────┐   ┌──────────────────┐
│ Probe .git paths │    │ Fetch metadata   │    │ Concurrent object fetch   │   │ Risk scoring     │
│ Confidence score │ ──▶│ Collect SHA1s    │ ──▶│ Zlib decompress           │──▶│ JSON report      │
│ Fuzz variants    │    │ Parse pack index │    │ 75+ regex secret patterns │   │ Terminal display  │
│ Branch & remote  │    │ Estimate size    │    │ Entropy analysis          │   │ Source reconstruct│
└──────────────────┘    └──────────────────┘    │ Tech stack fingerprint    │   └──────────────────┘
                                                │ Memory-limited streaming  │
                                                └───────────────────────────┘
```

### Modules

| Module | Lines | Responsibility |
|---|---|---|
| `main.rs` | ~330 | CLI parsing (clap), phase orchestration, configuration |
| `detect.rs` | ~410 | Phase 1 — probe 8 metadata files, confidence scoring (0–100 %), fuzz 24+ paths |
| `mapper.rs` | ~480 | Phase 2 — fetch 71 metadata files, collect SHA1s, parse pack indexes (v1 & v2) |
| `streamer.rs` | ~2000 | Phase 3 — concurrent fetch, 75+ secret patterns, Shannon entropy, YAML multi-line, minified JS |
| `reporter.rs` | ~290 | Phase 4 — risk score, coloured terminal output, JSON report |
| `git_parser.rs` | ~550 | Git object parser (loose objects, DIRC index v2–v4, pack index v1/v2, packed-refs, config) |
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

---

## Development Framework

> **Panduan pengembangan GitRecon** — hasil audit arsitektur v3.0.0.  
> Dokumen ini menggantikan riset lama (STREAMING_SCANNING_RESEARCH.md) yang sebagian besar sudah diimplementasikan.  
> Item yang belum diimplementasikan dari dokumen lama telah dimasukkan ke dalam roadmap di bawah ini.

### Status Implementasi Saat Ini

Fitur-fitur berikut **sudah** diimplementasikan di v3.0.0:

| Fitur | Modul | Catatan |
|---|---|---|
| 75+ pola deteksi secret (AWS, GCP, Azure, GitHub, Stripe, OpenAI, …) | `streamer.rs` | Regex + Shannon entropy + YAML multi-line |
| Pack file index parsing (v1 & v2) | `mapper.rs`, `git_parser.rs` | SHA1 diekstrak dari `.idx` |
| Enforcement `--mem-limit` | `streamer.rs` | Budget global + ceiling per-blob + in-flight tracking |
| Deduplikasi SHA1 | `streamer.rs` | Union set sebelum streaming |
| Deduplikasi finding | `reporter.rs` | De-dup berdasarkan `(pattern_id, match[0:40])` |
| Multi-line pattern matching | `streamer.rs` | YAML next-line secrets + segmentasi JS minified |
| Error categorization pada retry | `http_client.rs` | HTTP status → langsung return; network error → exponential backoff |
| Shannon entropy detection | `streamer.rs` | Context-aware, threshold 4.5 bits/char |
| Custom patterns dari file JSON | `streamer.rs` | Flag `--patterns FILE` |
| Early termination | `streamer.rs` | `--max-findings`, `--stop-on-critical` |
| Deteksi file terhapus (deleted blobs) | `streamer.rs` | `is_deleted` flag pada finding |
| Tech stack detection (40+ framework) | `streamer.rs` | Dual-mode: filename + content-based |
| Sensitive file priority | `streamer.rs` | `.env`, `config.*`, SSH keys, dsb. diprioritaskan |
| Placeholder filtering (50+ pattern) | `streamer.rs` | `your_`, `example`, `changeme`, dsb. dibuang |
| Source reconstruction | `reconstructor.rs` | `--save` + path-traversal defence |
| Proxy support | `http_client.rs` | SOCKS5, SOCKS4, HTTP |
| Rate limiting (delay + jitter) | `http_client.rs` | Per-request |
| User-Agent rotation | `http_client.rs` | 4 preset UA + custom override |
| Confidence scoring & fuzz | `detect.rs` | 8 verifier × 24+ path variant |

### Kerangka Pengembangan (Roadmap)

Peningkatan di bawah ini diurutkan berdasarkan **dampak × kompleksitas**. Setiap tahap bersifat independen dan dapat di-release secara terpisah.

#### Tahap 1 — Resilience & Reliability

> Tujuan: menjadikan GitRecon andal untuk target besar (>10000 objek) dan koneksi tidak stabil.

| ID | Peningkatan | Deskripsi | Prioritas |
|---|---|---|---|
| R-1 | **Checkpoint & Resume** | Simpan progress ke `{target}_checkpoint.json` setiap 500 objek. Flag `--resume` untuk melanjutkan dari titik terakhir. Hapus checkpoint setelah scan selesai. | **P0** |
| R-2 | **Smart Retry per Status Code** | `404` → jangan retry (objek tidak ada). `429` → pause sesuai `Retry-After`. `503` → exponential backoff. `403` → tandai sebagai protected. | **P1** |
| R-3 | **Adaptive Per-Object Timeout** | Hitung moving average latency 100 request terakhir. Timeout individual = `max(global_timeout, avg_latency × 3)`. Objek besar mendapat timeout proporsional ukuran. | **P2** |

#### Tahap 2 — Performance & Throughput

> Tujuan: meningkatkan kecepatan scanning tanpa mengorbankan stealth.

| ID | Peningkatan | Deskripsi | Prioritas |
|---|---|---|---|
| P-1 | **Adaptive Concurrency** | Pantau sliding window 100 request (success rate, latency). Error rate >20% → kurangi worker. Error rate <5% → tambah worker. Flag `--max-workers` / `--min-workers`. | **P1** |
| P-2 | **HTTP/2 Multiplexing** | Aktifkan HTTP/2 via `--http2` flag. Satu koneksi TCP membawa ratusan request paralel, mengurangi TLS handshake overhead. | **P2** |
| P-3 | **Prefetching Berbasis Graf** | Saat memproses `tree` object, langsung queue child blob SHA1 dengan prioritas tinggi. Waktu-to-first-finding lebih cepat. | **P3** |
| P-4 | **Streaming Decompression** | Gunakan `async_compression` untuk decompress sambil menerima stream HTTP. Peak memory per-objek turun dari `2×size` ke `~1×size`. | **P3** |

#### Tahap 3 — Scanning Quality

> Tujuan: meningkatkan akurasi dan cakupan deteksi secret.

| ID | Peningkatan | Deskripsi | Prioritas |
|---|---|---|---|
| S-1 | **Context-Aware Scanning** | Simpan ±3 baris konteks. Jika ada `# example`, `if test:` di sekitar match → turunkan confidence. Sliding window 7 baris. | **P2** |
| S-2 | **Full Multi-Line Pattern** | Scan seluruh konten file dengan regex dot-all (`(?s)`) untuk secret PEM, JSON nested, YAML block scalar. Batasi ke file <500 KB. | **P2** |
| S-3 | **Scanning File Biner Terpilih** | Whitelist format: SQLite (ekstrak string dari tabel), JAR/ZIP (scan `.properties`, `.xml`, `.json`), `.plist` (parse XML). | **P3** |
| S-4 | **Deteksi Kredensial Database Multi-Baris** | Deteksi konfigurasi database Python/Ruby/PHP yang memecah kredensial ke beberapa baris (`DATABASES = { ... 'PASSWORD': '...' }`). | **P3** |

#### Tahap 4 — Stealth & Evasion

> Tujuan: mengurangi kemungkinan deteksi oleh WAF dan IDS.

| ID | Peningkatan | Deskripsi | Prioritas |
|---|---|---|---|
| E-1 | **Token Bucket Rate Limiter** | Ganti delay per-request dengan token bucket global. Flag `--rate N` (maks N req/s). Distribusi merata tanpa burst. | **P2** |
| E-2 | **Multi-Proxy Rotation** | Flag `--proxy-list FILE`. Strategi: round-robin atau weighted. Proxy gagal 3× → tandai down, skip ke berikutnya. | **P3** |
| E-3 | **Request Fingerprint Diversifikasi** | Variasi header `Accept`, sisipkan decoy request ke path publik, distribusi delay Gaussian. | **P4** |
| E-4 | **Extended UA Pool** | Perluas ke 20+ UA modern + mobile. Flag `--ua-file FILE`. Opsi `--ua git/2.x.x` untuk menyamar sebagai git client. | **P4** |

#### Tahap 5 — Output & Integration

> Tujuan: memperluas format output dan integrasi CI/CD.

| ID | Peningkatan | Deskripsi | Prioritas |
|---|---|---|---|
| O-1 | **Real-Time Streaming Output** | Flag `--live`: tampilkan finding segera saat ditemukan. Channel `mpsc` antara worker dan output writer. Kompatibel dengan pipe. | **P2** |
| O-2 | **Format SARIF** | Flag `--format sarif`: output SARIF 2.1.0 yang dapat diupload ke GitHub Security tab. Integrasi GitHub Actions. | **P3** |
| O-3 | **Format Output Tambahan** | `--format csv` (spreadsheet), `--format ndjson` (streaming), `--format md` (Markdown), `--format html` (interaktif). | **P4** |
| O-4 | **Webhook Integration** | Flag `--webhook URL`: POST setiap finding sebagai JSON. Autentikasi HMAC-SHA256 via `--webhook-secret`. | **P4** |

#### Tahap 6 — Architecture & Scalability

> Tujuan: fondasi arsitektur untuk fitur jangka panjang.

| ID | Peningkatan | Deskripsi | Prioritas |
|---|---|---|---|
| A-1 | **Multi-Target Scanning** | Flag `--targets FILE`: scan daftar URL. Phase 1 paralel, lalu Phase 2–3 untuk target positif. Shared worker pool + aggregate report. | **P3** |
| A-2 | **SQLite Cache** | Simpan hasil scan di `~/.gitrecon/cache.db`. Re-scan target yang sama hanya perlu scan SHA1 baru. Flag `--no-cache`. | **P3** |
| A-3 | **Smart HTTP Protocol** | Negosiasi via `git-upload-pack` untuk download repository lengkap dalam satu pack file. Fallback ke dumb mode. | **P4** |
| A-4 | **Delta Object Resolution** | Implementasi `apply_delta(base, delta)` untuk dekompresi objek `OBJ_REF_DELTA` / `OBJ_OFS_DELTA` dari pack file. | **P4** |
| A-5 | **Plugin Architecture** | Trait `Scanner` yang dapat di-implement oleh modul eksternal. Loader via shared library (`.so`/`.dll`). | **P5** |
| A-6 | **Pipeline Mode** | Flag `--pipe`: output NDJSON ke stdout. Kompatibel dengan `jq`, `grep`, `tee` untuk automation workflow. | **P3** |

### Engineering Practices (Planned)

| Area | Status | Target |
|---|---|---|
| **Unit Tests** | Belum ada | Tambahkan test untuk setiap modul (`#[cfg(test)]`) |
| **Integration Tests** | Belum ada | Test end-to-end dengan mock HTTP server |
| **CI/CD** | Belum ada | GitHub Actions: `cargo test`, `cargo clippy`, `cargo fmt --check`, release binary |
| **Code Formatting** | Default rustfmt | Tambahkan `.rustfmt.toml` dengan konfigurasi konsisten |
| **Linting** | Belum ada | Tambahkan `clippy.toml`, jalankan `cargo clippy -- -D warnings` di CI |
| **Documentation** | README saja | Tambahkan `//!` module-level docs dan `///` function-level docs |
| **Benchmarks** | Belum ada | Gunakan `criterion` untuk benchmark streaming & regex performance |
| **Security Audit** | Manual | Integrasikan `cargo audit` di CI untuk dependency vulnerability scanning |

### Kontribusi

1. Fork repositori
2. Buat branch fitur (`git checkout -b feature/R-1-checkpoint`)
3. Gunakan ID dari roadmap di atas sebagai prefix branch dan commit
4. Pastikan `cargo build --release` dan `cargo clippy` bersih
5. Buat pull request dengan deskripsi perubahan

---

## Legal

This tool is intended for **authorised security testing and research only**.  
Do not use it against systems you do not own or have explicit permission to test.

---

## License

[MIT](LICENSE)

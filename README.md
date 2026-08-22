# GitRecon

GitRecon is a high-performance Rust scanner for exposed Git repositories, local source trees, and forge-accessible repositories. It detects exposed `.git` metadata, maps Git objects, scans recovered content for secret candidates, and emits structured reports.

> Use GitRecon only against systems and repositories that you own or are explicitly authorized to assess.

## Capabilities

GitRecon provides a four-stage remote pipeline: exposure detection, Git metadata and object mapping, concurrent streaming analysis, and report generation. It also supports local-directory scanning, binary and archive string extraction, multiple forge APIs, bounded multi-target concurrency, checkpoint/resume, cache isolation, proxy and rate-control options, object-source metrics, typed scan outcomes, and JSON, SARIF, CSV, NDJSON, Markdown, and HTML output. Forge workspace snapshots now use the same binary/archive scanner as local content, including custom patterns and the `--no-scan-binaries` opt-out; forge-specific acquisition telemetry remains under active roadmap work.

The scanner is intentionally discovery-oriented. Normal mode filters common template placeholders to reduce noise. `--exhaustive` retains placeholder-like candidates for investigative workflows. Object verification and local binary scanning are enabled by default and can be disabled explicitly. Local, URL, and forge snapshot dispatch classify binary content by magic bytes first, then supported filename extension, and finally the null-byte heuristic for unknown binary data; therefore sparse GZIP and low-null archive content are not forced through the text path. Forge-specific acquisition telemetry remains a separate roadmap item.

## Installation

### Quick install (recommended)

Install the latest published release binary with one command:

```bash
curl -sSf https://raw.githubusercontent.com/HazaVVIP/GitRecon/main/install.sh | bash
```

The installer detects the operating system and CPU architecture, downloads the matching archive from [GitHub Releases](https://github.com/HazaVVIP/GitRecon/releases), verifies its SHA-256 checksum when a checksum utility is available, and installs `gitrecon` to `/usr/local/bin`. The published binary is currently available for Linux `x86_64`; when a compatible release asset is unavailable, the installer falls back to a source build and may install Rust and system build dependencies.

After installation, verify the command and view the available options:

```bash
gitrecon --version
gitrecon --help
```

For a pinned release or a manual checksum-verified download, use the assets listed on the [v3.2.6 release page](https://github.com/HazaVVIP/GitRecon/releases/tag/v3.2.6).

### Build from source

Install [Rust](https://rustup.rs/) and run:

```bash
git clone https://github.com/HazaVVIP/GitRecon.git
cd GitRecon
cargo build --release
./target/release/gitrecon --help
```

## Usage

```bash
gitrecon <URL> [OPTIONS]
gitrecon --targets targets.ndjson [OPTIONS]
gitrecon --dir ./project [OPTIONS]
gitrecon --token <PAT> [OPTIONS]
gitrecon --gitlab-token <PAT> [OPTIONS]
gitrecon --bitbucket-token <APP_PASSWORD> [OPTIONS]
gitrecon --gitea-token <TOKEN> [OPTIONS]
gitrecon --azure-token <PAT> [OPTIONS]
```

Examples:

```bash
# Scan an exposed Git endpoint
gitrecon https://target.example

# Probe non-standard Git paths
gitrecon https://target.example --fuzz

# Scan a local project, including binaries by default
gitrecon --dir ./project --output ./results

# Retain template-like candidates
gitrecon --dir ./project --exhaustive

# Disable binary scanning explicitly
gitrecon --dir ./project --no-scan-binaries

# Verify an authenticated forge token and scan selected repositories
gitrecon --token "$GITHUB_TOKEN" --quiet --format sarif --output ./results

# Scan targets concurrently while preserving deterministic aggregate ordering
gitrecon --targets targets.ndjson --parallel-targets 8 --workers 50

# Use adaptive timeout and entropy tuning for a large remote scan
gitrecon https://target.example --max-history 0 --max-blob-size 8 \
  --entropy-threshold 4.2 --max-timeout 120

# Add custom patterns and false-positive context keywords
gitrecon --dir ./project --patterns ./patterns.json \
  --false-positive-keywords example,test,fixture

# Validate configuration and target input without network or content scanning
gitrecon --targets targets.ndjson --dry-run

# Emit a machine-readable dry-run result (no report or webhook is created)
gitrecon --dir ./project --dry-run --pipe
```

## Target Files and Custom Patterns

The `--targets` file accepts one target per line. Blank lines and lines beginning with `#` are ignored. Each line may be a plain URL, or a JSON object matching one of the typed target forms:

```text
https://target-one.example
{"url":"https://target-two.example","fuzz":true}
{"dir":"./local-project"}
{"token":"YOUR_TOKEN","repos":["owner/repository"]}
```

For custom detectors, `--patterns-help` prints the current schema. The file must contain a top-level `patterns` array, and each entry requires `id`, `severity`, `description`, and `regex`:

```json
{
  "patterns": [
    {
      "id": "internal_service_token",
      "severity": "HIGH",
      "description": "Internal service bearer token",
      "regex": "internal_[A-Za-z0-9_]{20,}"
    }
  ]
}
```

Replace the example quantifier with a valid regular-expression bound appropriate for the token format you are detecting. Custom patterns are validated before scanning and apply to text, printable binary strings, archive entries, decompressed GZIP content, SQLite strings, and ELF strings.

## Important Options

| Option | Default | Purpose |
|---|---:|---|
| `--dir PATH` | — | Recursively scan a local directory |
| `--targets FILE` | — | Read plain URLs or typed JSON targets, one per line |
| `--parallel-targets N` | `1` (maximum `1000`) | Bound concurrent target orchestration |
| `--workers N` | `50` | Bound concurrent object or file scanning work |
| `--timeout SEC` | `10` | Per-request timeout |
| `--retries N` | `3` | Retry count after the initial request; `0` means no retry |
| `--mem-limit MB` | `256` | Streaming memory limit |
| `--max-findings N` | `0` | Stop after a limit; zero means unlimited |
| `--fuzz` | disabled | Probe additional Git exposure paths |
| `--exhaustive` | disabled | Retain placeholder-like candidates |
| `--no-scan-binaries` | disabled | Opt out of local binary/archive scanning |
| `--no-verify-objects` | disabled | Skip object accessibility verification |
| `--partial-exposure` | disabled | Report metadata-only Git exposure as `PARTIAL` |
| `--save` | disabled | Reconstruct recovered source to disk |
| `--resume` | disabled | Resume from a verified checkpoint |
| `--no-cache` | disabled | Bypass the SQLite object cache |
| `--format FORMAT` | `json` | Select `json`, `sarif`, `csv`, `ndjson`, `md`, or `html` |
| `--live` | disabled | Emit findings as they arrive |
| `--pipe` | disabled | Emit machine-readable pipeline output |
| `--webhook URL` | — | Deliver a completed report to a validated webhook |
| `--dry-run` | disabled | Validate all target/configuration input without network, content scanning, reports, or webhooks |
| `--patterns FILE` | — | Load validated custom JSON detection patterns |
| `--false-positive-keywords LIST` | built-in list | Extend context keywords used for false-positive scoring |
| `--max-blob-size MB` | `4` | Maximum individual blob or local file size |
| `--max-history COMMITS` | `500` | Commit traversal depth; `0` means unlimited |
| `--entropy-threshold FLOAT` | `4.5` | High-entropy candidate threshold |
| `--max-timeout SEC` | `60` | Maximum adaptive request timeout |
| `--rate N` | — | Global request rate limit; `0` means unlimited and values must be finite |
| `--proxy-list FILE` | — | Rotate proxies from a newline-delimited file |
| `--ua-file FILE` | — | Load User-Agent values from a file |
| `--retry-strategy STRATEGY` | `standard` | Select retry behavior |
| `--checkpoint-dir DIR` | — | Checkpoint storage directory |
| `--checkpoint-interval N` | `1000` | Checkpoint cadence in processed objects |
| `--theme PATH` | — | Load a TOML terminal theme |
| `--banner-style STYLE` | `standard` | Select `minimal`, `standard`, `full`, or `none` |
| `--no-unicode` | disabled | Use ASCII-compatible terminal symbols |
| `--insecure` | disabled | Disable TLS verification; use only in controlled environments |

Run `gitrecon --help` for the complete option list, including forge-specific URLs, proxy rotation, user-agent pools, rate limiting, checkpoint intervals, partial-exposure reporting, themes, and webhook controls.

## Outputs

Reports are written below the selected output directory. The default JSON report contains detection metadata, mapping information, findings, severity counts, risk score, scan statistics, technology fingerprints, object-source distribution, and typed skip/failure outcomes. `--save` writes reconstructed source under a target-specific directory. Treat reports and reconstructed source as sensitive because findings may contain plaintext credential material.

## Architecture

| Domain | Modules | Responsibility |
|---|---|---|
| Orchestration | `main.rs`, `config.rs`, `targets.rs`, `target_utils.rs`, `outcome.rs` | CLI routing, runtime scan policy, target planning, bounded concurrency, deterministic outcomes, and error classification |
| URL and local pipelines | `url_pipeline.rs`, `dir_pipeline.rs`, `detect.rs`, `mapper.rs`, `git_parser.rs`, `pack_reader.rs` | URL exposure-to-stream execution, local recursive file scanning, binary/text policy, Git object mapping, pack parsing, and delta resolution |
| Forge clients | `forge.rs`, `forge_factory.rs`, `forge_scan.rs`, `*_api.rs` | Provider authentication, repository enumeration, provider-neutral workspace lifecycle, path-aware Bitbucket retrieval, bounded blob reconstruction, and object retrieval |
| Scanner | `streamer.rs`, `scanner_factory.rs`, `scanner_policy.rs`, `binary_scanner.rs`, `binary_adapter.rs` | Policy-driven pattern, entropy, multiline, database, AI-path, text, binary, and archive analysis |
| Reliability | `http_client.rs`, `cache.rs`, `checkpoint.rs`, `rate_limiter.rs`, `temp_cleanup.rs` | HTTP resilience, caching, checkpoint integrity, rate control, and cleanup |
| Reporting | `reporter.rs`, `validation.rs`, `layout.rs`, `ui/theme.rs` | Report formats, aggregate and per-target persistence, input validation, terminal presentation, and optional themes; `tools/benchmark_local_scan.py` provides reproducible release benchmarking |

## Quality Gates

Run the following before committing or publishing a release:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
```

The repository includes unit tests, forge identity, retrieval, forbidden/error, and path-aware Bitbucket contracts using local TCP response servers, pagination regression tests for GitHub, GitLab, and Bitbucket, checkpoint-directory resume coverage, CLI help coverage, and binary-level integration tests using temporary fixtures. Tests do not require live credentials or external network access.

See [DEVELOPMENT.md](DEVELOPMENT.md) for production defaults, maintenance rules, architecture details, and the release checklist.

## License

[MIT](LICENSE)

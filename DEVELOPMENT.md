# GitRecon Development and Release Guide

**Version:** 3.2.6
**Status:** Production-readiness maintenance
**Language:** Rust 2021

## Purpose

GitRecon is a streaming Git exposure and secret-candidate scanner. It supports remote `.git` exposure detection, repository mapping and object reconstruction, local-directory scanning, multi-target orchestration, forge token workflows, binary/archive string scanning, and structured reports.

The project intentionally favors **offensive discovery effectiveness**. Normal scans suppress common template placeholders to reduce noise; `--exhaustive` retains placeholder-like candidates for investigative workflows. Object verification and local binary scanning are enabled by default, with explicit opt-out flags.

## Architecture

| Domain | Primary modules | Responsibility |
|---|---|---|
| Orchestration | `src/main.rs`, `src/config.rs`, `src/targets.rs`, `src/target_utils.rs`, `src/outcome.rs` | CLI parsing, runtime scan configuration, target planning, shared repository selection, target dispatch, bounded concurrency, deterministic aggregate outcomes, and error classification |
| URL and local pipelines | `src/url_pipeline.rs`, `src/dir_pipeline.rs`, `src/detect.rs`, `src/mapper.rs`, `src/git_parser.rs`, `src/pack_reader.rs` | URL exposure-to-stream execution, local recursive file scanning, binary/text policy, Git object mapping, loose and packed object parsing, and delta resolution |
| Forge integrations | `src/forge.rs`, `src/forge_factory.rs`, `src/forge_scan.rs`, `src/*_api.rs` | Common forge contract, provider construction, authentication, enumeration, provider-neutral workspace lifecycle, path-aware blob retrieval, bounded blob reconstruction, and object access; local TCP contracts cover identity, retrieval, pagination, and forbidden/error paths |
| Scanning | `src/streamer.rs`, `src/scanner_factory.rs`, `src/scanner_policy.rs`, `src/binary_scanner.rs`, `src/binary_adapter.rs`, `src/object_source.rs` | Policy-driven pattern, entropy, multiline, database, AI-path, text, binary, archive, pack/cache/HTTP acquisition, and typed scan-outcome metrics |
| Reliability | `src/http_client.rs`, `src/cache.rs`, `src/checkpoint.rs`, `src/rate_limiter.rs`, `src/temp_cleanup.rs` | Timeouts, retries, rate limits, cache isolation, HMAC checkpoints, and temporary-resource cleanup |
| Reporting and validation | `src/reporter.rs`, `src/validation.rs`, `src/layout.rs` | JSON, SARIF, CSV, NDJSON, Markdown, HTML, aggregate and per-target persistence, terminal output, input validation, and layout helpers |
| Theme | `src/ui/theme.rs` | Optional TOML-backed terminal theme configuration |

## Development Workflow

Use a clean working tree for release work. Build and test with the commands below:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
```

Integration tests execute the compiled binary against temporary local fixtures. They cover local-directory reports, binary placeholder policy, mixed target aggregation, deterministic result ordering, custom checkpoint-directory resume discovery, CLI help coverage, and clean handling of invalid targets. Adapter unit suites also use local TCP response servers to contract-test identity success, blob/file retrieval, path-aware Bitbucket retrieval, provider-specific HTTP-401/403 behavior, Azure identity fallback, and pagination for GitHub, GitLab, and Bitbucket without live credentials. Avoid tests that require external forge credentials or network availability.

When changing scanner policy, add both a normal-mode assertion and an exhaustive-mode assertion. For custom detector changes, cover at least one text path and one printable binary/archive path, and verify configured severity, description, and provenance are preserved. When changing orchestration or forge errors, add a contract test that verifies the resulting `TargetOutcome` status and `TargetErrorCode`.

### CLI Documentation Contract

The `--help` output is a supported operator interface, not an implementation detail. Every public option must have a concise description, defaults must match the parser and runtime behavior, and the examples must be executable against the documented input formats. Keep `README.md`, this guide, and the Clap metadata in `src/main.rs` synchronized. When adding a target mode, output format, or safety-sensitive opt-out, update all three locations and add a CLI-level regression when practical.

The numeric runtime options `--delay` and `--jitter` accept finite values from 0 through 3,600 seconds. `--entropy-threshold` must be finite and non-negative. `--rate` accepts finite values from 0 through 1,000,000 requests per second, where 0 means unlimited. `--retries 0` performs the initial request but no retry.

The `--targets` input accepts one target per line: plain URLs remain supported, while JSON lines may describe URL, directory, or token targets. `--parallel-targets` is validated to the range 1–1000 so a malformed or accidental value cannot create unbounded task fan-out. Metadata-only Git exposure is not reported as `PARTIAL` by default; operators can opt in with `--partial-exposure`. The `--patterns-help` output is the source of truth for the custom pattern JSON schema. Custom patterns are evaluated consistently on text, printable binary strings, archive entries, decompressed GZIP content, SQLite strings, and ELF strings; binary adapter metadata must preserve the configured severity and description.

`--dry-run` is a strict validation-only path for URL, directory, token, and `--targets` modes. It validates CLI configuration, target shape, directory existence, target-file parsing, and custom patterns, but does not perform URL detection, repository reconnaissance, provider authentication, repository enumeration, local content reads, detector execution, report writing, aggregate report writing, or webhook delivery. With `--pipe`, it emits one machine-readable `dry_run` object and still performs no scan side effects.

## Production Defaults

The following defaults are deliberate and should not be changed casually:

| Behavior | Production default | Opt-out |
|---|---:|---|
| Object accessibility verification | Enabled | `--no-verify-objects` |
| Local binary/archive scanning | Enabled | `--no-scan-binaries` |
| Placeholder filtering | Enabled in normal mode | `--exhaustive` to retain candidates |
| Partial exposure reporting | Disabled | `--partial-exposure` to report metadata-only exposure as `PARTIAL` |
| Request timeout | 10 seconds | `--timeout` |
| Retries after initial request | 3 | `--retries`; `0` means no retry |
| Stream workers | 50 | `--workers` |
| Memory limit | 256 MB | `--mem-limit` |
| Cache TTL | 7 days | `--cache-ttl`, `--no-cache` |
| TLS verification | Enabled | `--insecure` only for controlled investigations |
| Parallel target concurrency | Maximum 1000 | `--parallel-targets N` within the validated range |

## Scanner Benchmarking

The repository includes a black-box local-directory benchmark at `tools/benchmark_local_scan.py`. Run it against the optimized release binary with:

```bash
cargo build --release
python3 tools/benchmark_local_scan.py --repetitions 5
```

The benchmark creates temporary, non-sensitive fixtures and reports normal versus exhaustive scan timings. Use it to compare commits on the same machine and build profile; do not treat the output as a cross-machine performance claim. A baseline run on the development sandbox with 40 files and 250 lines per file, using five repetitions, produced median times of approximately `0.3200s` in normal mode and `0.3193s` in exhaustive mode. Dry-run regressions should additionally assert that valid directory and target-list inputs create no report files and that `--pipe` emits a valid `dry_run` JSON object.

## Release Checklist

Before publishing a release, confirm that the version in `Cargo.toml`, the crate-level CLI description, and README metadata agree. Run formatting, Clippy, all tests, and a release build. Review `git status --short` for generated files, temporary scripts, credentials, and unexpected binaries. Confirm that reports handle operational metadata according to the selected output mode, webhook validation remains enabled by default, and no test depends on an external account or service.

Release artifacts should contain source, `Cargo.toml`, `Cargo.lock`, `README.md`, `DEVELOPMENT.md`, `LICENSE`, `src/`, `tests/`, and the reproducible benchmark under `tools/`. Build output under `target/` is local and must not be committed.

## Maintenance Principles

Keep detector behavior policy-driven rather than duplicating normal and exhaustive implementations. Prefer small domain modules over adding new orchestration branches to `main.rs`. Keep URL execution in `url_pipeline.rs`, local file policy in `dir_pipeline.rs`, provider-neutral forge lifecycle code in `forge_scan.rs`, scanner construction in `scanner_factory.rs`, and common report finalization in the orchestration boundary. Do not silence Clippy globally. A narrowly scoped allowance is acceptable only when a public data model, compatibility API, or intentionally broad test helper requires it; otherwise remove the unused symbol or refactor the call site.

Document architectural decisions in code comments close to the implementation. Avoid maintaining numerical line-count claims in documentation; use the source tree and automated quality gates as the source of truth.

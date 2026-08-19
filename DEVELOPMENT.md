# GitRecon Development and Release Guide

**Version:** 3.2.5
**Status:** Production-readiness maintenance
**Language:** Rust 2021

## Purpose

GitRecon is a streaming Git exposure and secret-candidate scanner. It supports remote `.git` exposure detection, repository mapping and object reconstruction, local-directory scanning, multi-target orchestration, forge token workflows, binary/archive string scanning, and structured reports.

The project intentionally favors **offensive discovery effectiveness**. Normal scans suppress common template placeholders to reduce noise; `--exhaustive` retains placeholder-like candidates for investigative workflows. Object verification and local binary scanning are enabled by default, with explicit opt-out flags.

## Architecture

| Domain | Primary modules | Responsibility |
|---|---|---|
| Orchestration | `src/main.rs`, `src/config.rs`, `src/target_utils.rs`, `src/targets.rs`, `src/outcome.rs` | CLI parsing, runtime scan configuration, target planning, target dispatch, bounded concurrency, deterministic aggregate outcomes, and error classification |
| Forge integrations | `src/forge.rs`, `src/forge_factory.rs`, `src/*_api.rs` | Common forge contract, provider construction, authentication, pagination, repository and object access; unified provider runtime extraction remains a planned follow-up because current public compatibility helpers keep the forge graph reachable from the binary root |
| Exposure pipeline | `src/detect.rs`, `src/mapper.rs`, `src/git_parser.rs`, `src/pack_reader.rs` | Detect exposed Git metadata, map object graphs, parse loose and packed objects, and resolve deltas |
| Scanning | `src/streamer.rs`, `src/scanner_policy.rs`, `src/binary_scanner.rs`, `src/binary_adapter.rs` | Policy-driven pattern, entropy, multiline, database, AI-path, text, binary, and archive detection; custom pattern loading is centralized in `streamer::load_patterns_from_file` |
| Reliability | `src/http_client.rs`, `src/cache.rs`, `src/checkpoint.rs`, `src/rate_limiter.rs`, `src/temp_cleanup.rs` | Timeouts, retries, rate limits, cache isolation, HMAC checkpoints, and temporary-resource cleanup |
| Reporting and validation | `src/reporter.rs`, `src/validation.rs`, `src/layout.rs` | JSON, SARIF, CSV, NDJSON, Markdown, HTML, terminal output, input validation, and layout helpers |
| Theme | `src/ui/theme.rs` | Optional TOML-backed terminal theme configuration |

## Development Workflow

Use a clean working tree for release work. Build and test with the commands below:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
```

Integration tests execute the compiled binary against temporary local fixtures. They cover local-directory reports, binary placeholder policy, mixed target aggregation, deterministic result ordering, and clean handling of invalid targets. Avoid tests that require live external forge credentials or network availability.

When changing scanner policy, add both a normal-mode assertion and an exhaustive-mode assertion. When changing orchestration or forge errors, add a contract test that verifies the resulting `TargetOutcome` status and `TargetErrorCode`.

### CLI Documentation Contract

The `--help` output is a supported operator interface, not an implementation detail. Every public option must have a concise description, defaults must match the parser and runtime behavior, and the examples must be executable against the documented input formats. Keep `README.md`, this guide, and the Clap metadata in `src/main.rs` synchronized. When adding a target mode, output format, or safety-sensitive opt-out, update all three locations and add a CLI-level regression when practical.

The `--targets` input accepts one target per line: plain URLs remain supported, while JSON lines may describe URL, directory, or token targets. The `--patterns-help` output is the source of truth for the custom pattern JSON schema.

## Production Defaults

The following defaults are deliberate and should not be changed casually:

| Behavior | Production default | Opt-out |
|---|---:|---|
| Object accessibility verification | Enabled | `--no-verify-objects` |
| Local binary/archive scanning | Enabled | `--no-scan-binaries` |
| Placeholder filtering | Enabled in normal mode | `--exhaustive` to retain candidates |
| Request timeout | 10 seconds | `--timeout` |
| Retries | 3 | `--retries` |
| Stream workers | 50 | `--workers` |
| Memory limit | 256 MB | `--mem-limit` |
| Cache TTL | 7 days | `--cache-ttl`, `--no-cache` |
| TLS verification | Enabled | `--insecure` only for controlled investigations |

## Release Checklist

Before publishing a release, confirm that the version in `Cargo.toml`, the crate-level CLI description, and README metadata agree. Run formatting, Clippy, all tests, and a release build. Review `git status --short` for generated files, temporary scripts, credentials, and unexpected binaries. Confirm that reports handle operational metadata according to the selected output mode, webhook validation remains enabled by default, and no test depends on an external account or service.

Release artifacts should contain source, `Cargo.toml`, `Cargo.lock`, `README.md`, `DEVELOPMENT.md`, `LICENSE`, `src/`, and `tests/`. Build output under `target/` is local and must not be committed.

## Maintenance Principles

Keep detector behavior policy-driven rather than duplicating normal and exhaustive implementations. Prefer small domain modules over adding new orchestration branches to `main.rs`. Do not silence Clippy globally. A narrowly scoped allowance is acceptable only when a public data model, compatibility API, or intentionally broad test helper requires it; otherwise remove the unused symbol or refactor the call site.

Document architectural decisions in code comments close to the implementation. Avoid maintaining numerical line-count claims in documentation; use the source tree and automated quality gates as the source of truth.

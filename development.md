# GitRecon v2.0+ Development Guide

**Version:** 3.2.0  
**Status:** Active Development  
**Last Updated:** 2025-01-09

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Overview](#2-architecture-overview)
3. [Development Guidelines](#3-development-guidelines)
4. [Component Structure](#4-component-structure)
5. [Development Workflow](#5-development-workflow)
6. [Coordination Protocol](#6-coordination-protocol)
7. [Quality Gates](#7-quality-gates)

---

## 1. Project Overview

### 1.1 Current State Summary

GitRecon is a **high-performance, streaming Git exposure scanner** written in Rust. It operates as a monolithic CLI tool that detects exposed `.git` directories and recovers secrets, credentials, and source code entirely in-memory.

**Current Capabilities:**
- **Phase 1 — Detect:** Probes 8 metadata files with confidence scoring (0-100%), supports 18+ path fuzzing variants
- **Phase 2 — Map:** Fetches 46 metadata files, collects SHA1s, parses pack indexes (v1 & v2)
- **Phase 3 — Stream & Scan:** Concurrent object fetch with 110+ secret patterns, Shannon entropy analysis, YAML multi-line detection
- **Phase 4 — Report:** Risk scoring, colored terminal output, multiple format support (JSON, SARIF, CSV, NDJSON, Markdown, HTML)

**Metrics (v3.2.0):**
- ~9,200 lines of Rust
- 110 secret patterns
- 61 metadata probes
- 59 tech stack fingerprints
- 110 unit tests across all modules

**Technical Foundation:**
- Language: Rust 2021 edition
- Async Runtime: Tokio (full features)
- HTTP: reqwest with rustls-tls, SOCKS, gzip/deflate
- Concurrency: futures `buffer_unordered`, rayon, lock-free atomics

### 1.2 Vision and Mission

**Vision:** Establish GitRecon as the gold standard for automated Git repository security reconnaissance — balancing speed, accuracy, and operational security.

**Mission:**
1. **Reliability First:** Ensure zero data loss with checkpoint/resume capabilities and smart error recovery
2. **Performance Leadership:** Maintain sub-minute scan times for repositories up to 10K objects
3. **Comprehensive Coverage:** Detect 95%+ of common secret types with <5% false positive rate
4. **Integration Ready:** Support multiple output formats and webhook delivery for DevSecOps pipelines
5. **Stealth & Evasion:** Provide advanced options for operational security (rate limiting, proxy rotation, UA diversification)

### 1.3 Target Users

**Primary Users:**
- Red Team Operators: Rapid intelligence gathering during authorized engagements
- Bug Bounty Hunters: Efficient discovery of exposed Git repositories and secrets
- Security Researchers: Large-scale analysis of Git exposure patterns

**Secondary Users:**
- DevSecOps Teams: Integration into CI/CD pipelines for pre-deployment Git exposure checks
- Incident Responders: Quick assessment of credential exposure scope
- Compliance Auditors: Evidence collection for regulatory requirements

---

## 2. Architecture Overview

### 2.1 Current Architecture (Monolithic Rust CLI)

```
┌─────────────────────────────────────────────────────────────────┐
│                         gitrecon binary                           │
├─────────────────────────────────────────────────────────────────┤
│  main.rs (~330 lines)                                            │
│  ├─ CLI parsing (clap)                                          │
│  ├─ Mode routing (URL/Token/Dir/Targets)                        │
│  └─ Phase orchestration                                          │
├─────────────────────────────────────────────────────────────────┤
│                        Core Modules                              │
├────────────────┬────────────────┬────────────────┬────────────────┤
│  detect.rs     │  mapper.rs    │  streamer.rs   │  reporter.rs   │
│  (~410 lines)  │  (~485 lines)  │  (~2020 lines) │  (~290 lines)  │
│  Phase 1       │  Phase 2       │  Phase 3       │  Phase 4       │
│  Probe .git    │  Fetch meta   │  Concurrent    │  Risk score    │
│  Confidence    │  Collect SHA1 │  fetch & scan   │  Terminal/UI   │
│  Fuzz variants │  Parse index   │  110 patterns  │  JSON/SARIF    │
├────────────────┴────────────────┴────────────────┴────────────────┤
│                      Supporting Modules                           │
├────────────────┬────────────────┬────────────────┬────────────────┤
│  http_client   │  git_parser    │  github_api    │  checkpoint    │
│  (~200 lines)  │  (~545 lines)  │  (~XXX lines)  │  (~XXX lines)  │
│  HTTP wrapper  │  Object parser │  Token mode    │  Resume state  │
│  Backoff       │  Loose/pack    │  Enumerate     │  Progress save │
│  Proxy         │  DIRC v2-v4    │  Download      │  Recovery      │
├────────────────┴────────────────┴────────────────┴────────────────┤
│                      Utility Modules                               │
├────────────────┬────────────────┬────────────────┬────────────────┤
│  text_utils     │  binary_scanner│ reconstructor  │                │
│  (~XXX lines)   │  (~XXX lines)  │  (~120 lines)  │                │
│  UTF8 handling  │  SQLite/ZIP    │  Disk write    │                │
│  Truncation     │  String ext.   │  Path sanit.   │                │
└────────────────┴────────────────┴────────────────┴────────────────┘
```

**Data Flow (Single Target):**
```
CLI Args → HttpClient → Detect() → Mapper() → Streamer() → Reporter() → Files
    │         │           │           │           │            │          │
    │         │           │           │           │            │          └── JSON/SARIF/CSV/NDJSON/MD/HTML
    │         │           │           │           │            └──────────── Colored Terminal
    │         │           │           │           └────────────────────────── Findings
    │         │           │           └───────────────────────────────────── SHA1s
    │         │           └────────────────────────────────────────────────── Git URL
    │         └────────────────────────────────────────────────────────────── HTTP Requests
    └───────────────────────────────────────────────────────────────────────── Configuration
```

### 2.2 Target Architecture (Modular Plugin System)

**v4.0 Vision:** Plugin-based architecture with trait-defined interfaces

```
┌─────────────────────────────────────────────────────────────────┐
│                    gitrecon-core (library)                       │
├─────────────────────────────────────────────────────────────────┤
│  Trait Definitions                                              │
│  ├─ Scanner (detection patterns)                                │
│  ├─ Fetcher (HTTP/file/git protocols)                          │
│  ├─ Analyzer (entropy, context, tech stack)                    │
│  ├─ Reporter (output formats)                                  │
│  └─ Persistence (checkpoint, cache)                           │
└─────────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
┌───────────▼────┐  ┌─────────▼──────┐  ┌───────▼────────┐
│ gitrecon-cli   │  │  gitrecon-scan  │  │ gitrecon-repo  │
│ (binary)       │  │   (plugins)    │  │   (scanner)    │
│  Main entry    │  │  ├─ aws-plugin │  │  ├─ git-exposed │
│  Route modes   │  │  ├─ gcp-plugin │  │  ├─ github-token│
│  Load plugins  │  │  ├─ azure-plugin│  │  └─ local-dir  │
└────────────────┘  │  └─ custom-...  │  └────────────────┘
                    └─────────────────┘
```

**Key Interfaces (Traits):**

```rust
// Core trait for detection patterns
pub trait Scanner: Send + Sync {
    fn id(&self) -> &str;
    fn severity(&self) -> &str;
    fn scan(&self, content: &str, context: &ScanContext) -> Vec<Finding>;
}

// Core trait for fetching objects
pub trait Fetcher: Send + Sync {
    async fn fetch(&self, sha1: &str) -> Result<Vec<u8>, FetchError>;
    fn supports(&self, protocol: &str) -> bool;
}

// Core trait for analysis
pub trait Analyzer: Send + Sync {
    fn analyze(&self, content: &str, metadata: &Metadata) -> AnalysisResult;
}
```

### 2.3 Migration Strategy

**Phase 1: Foundation (v3.3 - v3.5)**
- Extract core functionality into `gitrecon-core` library crate
- Define trait interfaces for Scanner, Fetcher, Analyzer
- Refactor existing modules to implement traits
- Maintain backward compatibility with CLI

**Phase 2: Plugin System (v4.0 - v4.2)**
- Implement dynamic plugin loading via `libloading`
- Create plugin examples (AWS-specific, GCP-specific)
- Add plugin discovery from `~/.gitrecon/plugins/`
- Document plugin development guide

**Phase 3: Ecosystem (v4.3+)**
- Support community plugin registry
- Add plugin versioning and dependency resolution
- Implement plugin sandboxing
- Create plugin testing framework

---

## 3. Development Guidelines

### 3.1 Code Style and Conventions

**Rust Standards:**
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting (enforced in CI)
- Use `cargo clippy` with zero warnings policy
- Document all public APIs with rustdoc comments (`///` or `//!`)

**Naming Conventions:**
- **Modules:** `snake_case` (e.g., `http_client`, `git_parser`)
- **Types/Structs:** `PascalCase` (e.g., `DetectResult`, `HttpClient`)
- **Functions:** `snake_case` (e.g., `run_detect`, `parse_head`)
- **Constants:** `SCREAMING_SNAKE_CASE` (e.g., `TOTAL_WEIGHT`, `META_FILES`)
- **Acronyms:** Treat as words (e.g., `HttpConfig` not `HTTPConfig`)

**Code Organization:**
```rust
// File header: module purpose and brief description
//! module_name.rs
//! One-line summary of what this module does.
//!
//! More detailed explanation if needed.

// Standard imports (grouped alphabetically by crate)
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::module_a::TypeA;
use crate::module_b::function_b;

// Constants first
const MAX_RETRIES: u32 = 3;
const DEFAULT_TIMEOUT: u64 = 10;

// Type definitions
pub struct MyStruct {
    pub field: Type,
}

// Trait implementations
impl MyStruct {
    pub fn new() -> Self {
        Self { field: Type::default() }
    }
}

// Private helpers
fn helper_function() -> ResultType {
    // Implementation
}

// Tests at bottom
#[cfg(test)]
mod tests {
    use super::*;
}
```

**Error Handling:**
- Use `anyhow::Error` for application-level errors
- Use `thiserror` for library-level error types
- Always provide context with `.context()` or `.with_context()`
- Avoid panicking in production code — use `Result` return types

```rust
// Good: proper error handling
async fn fetch_object(&self, sha1: &str) -> Result<Vec<u8>, anyhow::Error> {
    let response = self.client
        .get(&format!("{}/objects/{}", self.base_url, sha1))
        .send()
        .await
        .context("HTTP request failed during object fetch")?;
    
    if !response.status().is_success() {
        anyhow::bail!("Object fetch returned {}", response.status());
    }
    
    // ... rest of implementation
    Ok(data)
}

// Bad: panic in production code
async fn fetch_object(&self, sha1: &str) -> Vec<u8> {
    let response = self.client.get(&format!("...")).send().await.unwrap();
    response.bytes().await.unwrap().to_vec()
}
```

### 3.2 Testing Requirements

**Unit Tests:**
- Every module must have unit tests
- Test coverage minimum: 80% (target: 90%)
- Tests should be fast (< 1 second total)
- Use `#[cfg(test)]` for test-only code

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_url() {
        assert_eq!(normalize_url("example.com"), "https://example.com");
        assert_eq!(normalize_url("http://example.com"), "http://example.com");
    }

    #[test]
    fn test_confidence_scoring() {
        let result = DetectResult {
            confidence: 75,
            // ... other fields
        };
        assert!(result.is_high_confidence());
    }
}
```

**Integration Tests:**
- Place in `tests/` directory
- Test multi-module interactions
- Can use fixtures in `tests/fixtures/`
- Should be idempotent and cleanup after themselves

**Performance Tests:**
- Use criterion for benchmarks
- Test against known workloads (100, 1K, 10K objects)
- Monitor memory usage with `--profile` feature

```rust
// benches/scanner_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_scan(c: &mut Criterion) {
    let content = include_str!("../fixtures/sample_code.rs");
    c.bench_function("scan_rust_code", |b| {
        b.iter(|| scan_text(black_box(content), "test.rs", &[], 4.5))
    });
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
```

### 3.3 Security Review Checklist

**Code Review:**
- [ ] No hardcoded credentials or API keys
- [ ] Input validation on all user-provided data
- [ ] Path traversal protection in file operations
- [ ] Proper error handling without leaking sensitive information
- [ ] No use of `unsafe` without documented justification
- [ ] Dependencies are audited (use `cargo-audit`)

**Secret Pattern Reviews:**
- [ ] New patterns tested against known false positives
- [ ] Regex efficiency validated (avoid catastrophic backtracking)
- [ ] Pattern documented with example matches
- [ ] Severity level appropriately assigned

**Network Security:**
- [ ] SSL/TLS verification enabled by default
- [ ] Request timeouts configured
- [ ] Rate limiting respected
- [ ] No sensitive data in URL parameters
- [ ] Proxy support for operational security

**File Operations:**
- [ ] No writes outside designated output directory
- [ ] Symbolic link protection
- [ ] Permission checks on file access
- [ ] Temporary file cleanup

### 3.4 Performance Benchmarks

**Baseline Performance (v3.2.0):**

| Repository Size | Objects | Detection | Mapping | Streaming | Total |
|----------------|---------|-----------|---------|-----------|-------|
| Small (< 100)  | ~50     | ~2s       | ~1s     | ~3s       | ~6s   |
| Medium (1K)     | ~1,000  | ~3s       | ~5s     | ~15s      | ~23s  |
| Large (10K)     | ~10,000 | ~5s       | ~15s    | ~90s      | ~110s |

**Performance Targets (v4.0):**

| Metric                      | v3.2.0 | v4.0 Target | Improvement |
|----------------------------|--------|-------------|-------------|
| Small repository scan      | ~6s    | ~4s         | 33% faster  |
| Medium repository scan     | ~23s   | ~15s        | 35% faster  |
| Large repository scan      | ~110s  | ~60s        | 45% faster  |
| Memory usage (10K objects) | ~256MB | ~128MB      | 50% reduction|
| Binary size                 | ~2MB   | ~2.5MB      | +25%        |

**Benchmarking Commands:**
```bash
# Run benchmarks
cargo bench

# Profile with flamegraph
cargo flamegraph --bin gitrecon -- https://example.com

# Memory profiling
valgrind --tool=massif ./target/release/gitrecon https://example.com

# Time profiling
hyperfine './target/release/gitrecon https://example.com'
```

---

## 4. Component Structure

### 4.1 Module Responsibilities

| Module       | Lines  | Phase | Responsibility                                                    | Dependencies                  |
|--------------|--------|-------|------------------------------------------------------------------|-------------------------------|
| `main.rs`    | ~1,700 | All   | CLI parsing, mode routing, phase orchestration                     | All modules                   |
| `detect.rs`  | ~410   | 1     | Probe .git paths, confidence scoring, fuzz variants              | http_client, git_parser       |
| `mapper.rs`  | ~485   | 2     | Fetch metadata, collect SHA1s, parse pack indexes                | http_client, git_parser       |
| `streamer.rs`| ~2,020 | 3     | Concurrent fetch, secret scanning, entropy analysis               | http_client, git_parser       |
| `reporter.rs`| ~290   | 4     | Risk scoring, terminal output, report generation                  | All phases                    |
| `http_client`| ~200   | All   | HTTP wrapper, backoff, proxy, rate limiting                       | reqwest, tokio                |
| `git_parser` | ~545   | 2-3   | Parse Git objects (loose, pack, index)                          | flate2, sha1                  |
| `github_api` | ~XXX   | Token | GitHub API client, repo enumeration, blob fetch                   | http_client                   |
| `checkpoint` | ~XXX   | All   | Progress saving, resume state                                     | serde, dirs                   |
| `binary_scan`| ~XXX   | 3     | SQLite string extraction, JAR/ZIP scanning                        | rusqlite, zip                 |
| `text_utils` | ~XXX   | All   | UTF-8 handling, truncation                                        | -                             |
| `reconstruct`| ~120   | 3     | Optional source reconstruction to disk                           | -                             |

### 4.2 Dependency Graph

```
main.rs
 ├─> http_client
 │    └─> reqwest, tokio, bytes
 ├─> detect
 │    ├─> http_client
 │    └─> git_parser
 ├─> mapper
 │    ├─> http_client
 │    └─> git_parser
 ├─> streamer
 │    ├─> http_client
 │    ├─> git_parser
 │    └─> checkpoint
 ├─> reporter
 │    ├─> detect
 │    ├─> mapper
 │    ├─> streamer
 │    └─> text_utils
 ├─> github_api
 │    └─> http_client
 └─> checkpoint
      └─> serde, dirs
```

### 4.3 Interface Contracts

**Phase 1 → Phase 2 Contract (DetectResult):**
```rust
pub struct DetectResult {
    pub git_url: String,           // Base URL for .git objects
    pub confidence: u32,           // 0-100, minimum 45 to proceed
    pub label: String,             // Human-readable exposure type
    pub branch: Option<String>,     // Default branch if detected
}
```

**Phase 2 → Phase 3 Contract (MapResult):**
```rust
pub struct MapResult {
    // SHA1 collections
    pub commit_sha1s: HashSet<String>,
    pub tree_sha1s: HashSet<String>,
    pub blob_sha1s: HashSet<String>,
    
    // Metadata
    pub branches: Vec<String>,
    pub remote_urls: Vec<HashMap<String, String>>,
    pub contributors: Vec<String>,
    
    // Estimates
    pub estimated_files: usize,
    pub estimated_size_bytes: u64,
    
    // Verification
    pub objects_accessible: bool,
}
```

**Phase 3 → Phase 4 Contract (StreamResult):**
```rust
pub struct StreamResult {
    pub findings: Vec<Finding>,
    pub contributors: Vec<String>,
    pub tech_stack: Vec<String>,
    pub commit_count: usize,
    pub blobs_scanned: usize,
    pub blobs_failed: usize,
    pub bytes_scanned: usize,
    pub elapsed_s: f64,
    pub files_saved: usize,
    pub files_save_failed: usize,
}
```

**Finding Structure:**
```rust
pub struct Finding {
    pub filename: String,              // Relative path in repo
    pub line: usize,                    // Line number (1-indexed)
    pub pattern_id: String,             // Pattern that matched
    pub description: String,            // Human-readable description
    pub severity: String,              // CRITICAL/HIGH/MEDIUM/LOW/INFO
    pub match_str: String,             // Matched content (redacted if needed)
    pub context: String,               // Surrounding lines for context
    pub is_deleted: bool,              // If found in deleted file
    pub commit_sha1: Option<String>,   // Commit if deleted
    pub confidence_adjustment: Option<f32>, // Context-aware adjustment
}
```

---

## 5. Development Workflow

### 5.1 Branch Strategy

**Repository Structure:**
```
main                    ── Stable releases only ( vX.Y.Z )
├── develop            ── Integration branch for features
│   ├── feature/R-1-checkpoint
│   ├── feature/P-1-adaptive-concurrency
│   ├── feature/S-1-context-aware-confidence
│   └── feature/O-1-live-output
├── release/v3.3       ── Release preparation
└── hotfix/v3.2.1      ── Emergency fixes only
```

**Branch Naming:**
- `feature/ROADMAP-ID-description` — New features from roadmap
- `bugfix/ISSUE-ID-description` — Bug fixes
- `hotfix/vX.Y.Z-description` — Emergency production fixes
- `docs/description` — Documentation updates
- `refactor/module-name` — Code refactoring

**Workflow:**
1. Create branch from `develop`: `git checkout -b feature/R-1-checkpoint`
2. Develop and test locally
3. Push to remote: `git push origin feature/R-1-checkpoint`
4. Create PR to `develop` with roadmap ID in title
5. Code review and automated tests must pass
6. Merge to `develop`
7. Periodically merge `develop` to `main` for releases

### 5.2 PR Requirements

**Pull Request Template:**
```markdown
## Roadmap Entry
- ID: [R-1 / P-1 / etc.]
- Title: [Brief title from roadmap]
- Priority: [P0/P1/P2/P3/P4]

## Changes
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Description
[Detailed description of changes]

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Performance benchmarks run

## Checklist
- [ ] Code follows style guidelines
- [ ] `cargo fmt` applied
- [ ] `cargo clippy` produces no warnings
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
```

**Required Reviews:**
- At least one maintainer approval
- All automated checks must pass
- No merge conflicts
- Security-sensitive changes require 2 reviewer approvals

**Automated Checks:**
- `cargo test` — All tests pass
- `cargo clippy` — Zero warnings
- `cargo fmt --check` — Formatting check
- `cargo audit` — Security audit of dependencies
- Integration tests — End-to-end validation

### 5.3 CI/CD Pipeline

**GitHub Actions Workflow:**
```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [develop, main]
  pull_request:
    branches: [develop, main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        rust: [stable, beta, nightly]
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: ${{ matrix.rust }}
      - run: cargo test --all-features
      - run: cargo clippy -- -D warnings
      - run: cargo fmt --check
  
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo install cargo-audit
      - run: cargo audit
  
  bench:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/develop'
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo bench
  
  release:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    needs: [test, security]
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - run: cargo build --release
      - uses: softprops/action-gh-release@v1
        with:
          files: target/release/gitrecon
```

### 5.4 Release Process

**Version Numbering:**
- Format: `vMAJOR.MINOR.PATCH`
- MAJOR: Breaking changes or new architecture
- MINOR: New features, backward compatible
- PATCH: Bug fixes, small improvements

**Release Checklist:**
1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md` with release notes
3. Create release branch from `main`: `git checkout -b release/vX.Y.Z`
4. Update documentation with new features
5. Run full test suite on all platforms
6. Tag release: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
7. Push tag: `git push origin vX.Y.Z`
8. Create GitHub release with:
   - Compiled binaries for Linux, macOS, Windows
   - Release notes from CHANGELOG
   - Installation instructions
9. Update `install.sh` to point to new version
10. Announce on communication channels

**Release Announcement Template:**
```markdown
# GitRecon vX.Y.Z Released

## Highlights
- Feature 1 description
- Feature 2 description
- Performance improvements

## Upgrade Instructions
```bash
curl -sSf https://raw.githubusercontent.com/HazaVVIP/GitRecon/main/install.sh | bash
```

## Breaking Changes
[List any breaking changes and migration paths]

## Full Changelog
[Link to GitHub release]
```

---

## 6. Coordination Protocol

### 6.1 Progress Tracking

**Roadmap Tracking:**
- Each roadmap item has unique ID (e.g., `R-1`, `P-1`, `S-1`)
- Use GitHub Projects for Kanban board
- Columns: `Backlog`, `In Progress`, `In Review`, `Done`

**Issue Tracking:**
- All work tracked via GitHub Issues
- Use roadmap ID in issue title: `[R-1] Checkpoint & Resume Implementation`
- Link issues to roadmap items
- Assign milestone for release planning

**Progress Metrics:**
- Track % completion per roadmap phase
- Update weekly in development meetings
- Maintain burndown chart for current release

### 6.2 Conflict Resolution

**Technical Disagreements:**
1. Document both approaches in issue comments
2. Create RFC (Request for Comments) for significant decisions
3. Vote after 3-day discussion period
4. Maintainer has tie-breaking vote

**Merge Conflicts:**
1. Notify both parties immediately
2. Schedule sync meeting within 24 hours
3. Resolve together with screen sharing
4. Update tests to cover conflict scenario

**Priority Conflicts:**
1. P0 (Critical) — Always takes precedence
2. P1 — Security vulnerabilities, customer-reported bugs
3. P2 — Planned features, performance improvements
4. P3-P4 — Backlog items

### 6.3 Team Coordination

**Communication Channels:**
- **Discord/Slack:** Daily communication, quick questions
- **GitHub Issues:** Bug reports, feature requests
- **GitHub PRs:** Code review discussions
- **Weekly Sync:** Progress review, planning

**Meeting Schedule:**
- **Daily Standup (Async):** Update in #daily-standup channel
- **Weekly Planning:** Monday, 30 minutes, prioritize upcoming work
- **Sprint Review:** Friday, 30 minutes, demo completed features
- **Monthly Retro:** Last Friday, 1 hour, process improvements

**Documentation Standards:**
- All design discussions in GitHub Issues or RFCs
- Implementation details in code comments
- User-facing documentation in README.md
- Developer documentation in development.md

### 6.4 Decision-Making Process

**Decision Types:**

| Type | Process | Approval Required |
|------|---------|-------------------|
| Code style | Team discussion | Consensus |
| Architecture | RFC + 2-week discussion | Maintainer + 2 others |
| Breaking changes | RFC + 2-week discussion | Maintainer |
| Bug fixes | Issue discussion | Any contributor |
| Features | Issue + PR discussion | 1 reviewer |
| Roadmap | Team planning | Maintainer |

**RFC Template:**
```markdown
# RFC: Title

## Status
- [ ] Proposed
- [ ] Discussion
- [ ] Accepted
- [ ] Implemented
- [ ] Rejected

## Context
[Background and motivation]

## Proposed Solution
[Detailed description of the proposal]

## Alternatives Considered
[Other approaches and why they were rejected]

## Impact
- Breaking changes: [Yes/No]
- Performance impact: [None/Positive/Negative]
- Migration path: [Description if breaking]

## Unresolved Questions
[Open questions to be resolved]
```

---

## 7. Quality Gates

### 7.1 Definition of Done

**Feature Level:**
- [ ] Code reviewed and approved
- [ ] Unit tests with >80% coverage
- [ ] Integration tests passing
- [ ] Documentation updated
- [ ] Performance benchmarks acceptable
- [ ] No clippy warnings
- [ ] No security vulnerabilities
- [ ] CHANGELOG.md updated

**Phase Level (e.g., Resilience Phase):**
- [ ] All features in phase complete
- [ ] End-to-end testing across all features
- [ ] Performance regression testing
- [ ] Security audit of changes
- [ ] User documentation complete
- [ ] Migration guide if breaking changes

**Release Level:**
- [ ] All phases complete
- [ ] Full test suite passing
- [ ] Security audit passed
- [ ] Performance targets met
- [ ] Documentation complete and reviewed
- [ ] Release notes prepared
- [ ] Backport plan for critical fixes

### 7.2 Acceptance Criteria

**Per Roadmap Item:**

**R-1: Checkpoint & Resume**
- [ ] Progress saved to `~/.gitrecon/checkpoints/` every N objects
- [ ] `--resume` flag successfully continues interrupted scan
- [ ] Checkpoint file format versioned and backward compatible
- [ ] Cleanup of old checkpoints (>7 days old)
- [ ] Works across all scan modes (URL, token, dir)
- [ ] Performance overhead <5%

**R-2: Smart Retry per Status Code**
- [ ] 404 responses skip retries immediately
- [ ] 429 responses respect `Retry-After` header
- [ ] 503 responses use exponential backoff
- [ ] Retry count respected per status code type
- [ ] Retry behavior configurable

**P-1: Adaptive Concurrency**
- [ ] Worker count adjusts based on error rate
- [ ] Decrease workers on >10% errors
- [ ] Increase workers on <2% errors
- [ ] Minimum 5 workers, maximum 200 workers
- [ ] Adaptive behavior opt-outable with `--no-adaptive`

**S-1: Context-Aware Confidence**
- [ ] Context keywords reduce match confidence
- [ ] Keywords: `example`, `sample`, `test`, `dummy`
- [ ] Confidence adjustment documented in finding
- [ ] Configurable keyword list

### 7.3 Rollback Procedures

**Automated Rollback Triggers:**
- >5% increase in false positive rate
- >20% performance degradation
- Security vulnerability in release
- Data loss or corruption

**Rollback Process:**
1. Issue hotfix branch from previous stable release
2. Cherry-pick critical fixes only
3. Test hotfix thoroughly
4. Release as `vX.Y.Z+1`
5. Update installation script
6. Announce rollback with detailed explanation

**Post-Mortem Process:**
1. Document root cause
2. Identify process gaps
3. Implement prevention measures
4. Update development guidelines
5. Share learnings with team

### 7.4 Quality Metrics

**Code Quality:**
- Test coverage: >80% (target 90%)
- Clippy warnings: 0
- Code duplication: <5%
- Function complexity: McCabe <10

**Performance:**
- Small repo scan: <5s
- Medium repo scan: <20s
- Large repo scan: <60s
- Memory efficiency: <150MB for 10K objects

**Security:**
- Zero high/critical vulnerabilities
- Regular dependency audits (monthly)
- Secret pattern false positive rate: <5%
- Zero hardcoded secrets

**Documentation:**
- All public APIs documented
- README.md always current
- CHANGELOG.md updated for each release
- Development.md reviewed quarterly

---

## Appendix A: Roadmap Quick Reference

**Phase 1 — Resilience & Reliability**
- R-1: Checkpoint & Resume (P0)
- R-2: Smart Retry per Status Code (P1)
- R-3: Adaptive Per-Object Timeout (P2)

**Phase 2 — Performance & Throughput**
- P-1: Adaptive Concurrency (P1)
- P-2: HTTP/2 Multiplexing (P2)
- P-3: Prefetching Berbasis Graf (P3)
- P-4: Streaming Decompression (P3)

**Phase 3 — Scanning Quality**
- S-1: Context-Aware Confidence (P2)
- S-2: Full Multi-Line Pattern (P2)
- S-3: Binary File Scanning (P3)
- S-4: Multi-Line DB Credentials (P3)

**Phase 4 — Stealth & Evasion**
- E-1: Token Bucket Rate Limiter (P2)
- E-2: Multi-Proxy Rotation (P3)
- E-3: Request Fingerprint Diversification (P4)
- E-4: Extended UA Pool (P4)

**Phase 5 — Output & Integration**
- O-1: Real-Time Streaming Output (P2)
- O-2: SARIF Format (P3)
- O-3: Additional Formats (P4)
- O-4: Webhook Integration (P4)

**Phase 6 — Architecture & Scalability**
- A-1: Multi-Target Scanning (P3)
- A-2: SQLite Cache (P3)
- A-3: Smart HTTP Protocol (P4)
- A-4: Delta Object Resolution (P4)
- A-5: Plugin Architecture (P5)
- A-6: Pipeline Mode (P3)

---

## Appendix B: Development Resources

**Rust Resources:**
- [The Rust Programming Language](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [cargo-clippy](https://github.com/rust-lang/rust-clippy)

**Git Internals:**
- [Git Internals](https://git-scm.com/book/en/v2/Git-Internals)
- [Pack Format](https://github.com/git/git/blob/master/Documentation/technical/pack-format.txt)
- [Loose Object Format](https://github.com/git/git/blob/master/Documentation/technical/loose-object-format.txt)

**Testing Resources:**
- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Criterion Benchmarking](https://bheisler.github.io/criterion.rs/book/)

**Security:**
- [Rust Security Guidelines](https://doc.rust-lang.org/nomicon/security-measures.html)
- [OWASP Regex Dos](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)

---

**Document Version:** 1.0  
**Last Updated:** 2025-01-09  
**Maintained By:** GitRecon Development Team  

For questions or contributions, please refer to the main repository at [GitHub](https://github.com/HazaVVIP/GitRecon).

# GitRecon v2.0+ Development Guide

**Version:** 3.2.0  
**Status:** Active Development  
**Last Updated:** 2026-07-09

---

## Executive Summary

GitRecon is a high-performance, streaming Git exposure scanner written in Rust. This guide coordinates implementation of v2.0+ features across 55 tasks organized by priority.

### Quick Reference
- **Total Tasks:** 55
- **Estimated Effort:** 330 hours
- **P0 (Critical Security):** 6 tasks
- **P1 (Infrastructure):** 8 tasks
- **P2 (Platform):** 11 tasks
- **P3 (Scanning):** 6 tasks
- **P4 (Fable5):** 5 tasks
- **P5 (Architecture):** 7 tasks
- **P6 (Library):** 5 tasks
- **P7 (Enterprise):** 7 tasks

### Current State (v3.2.0)
- **Lines of Code:** ~9,200
- **Secret Patterns:** 110
- **Metadata Probes:** 61
- **Tech Stack Fingerprints:** 59
- **Unit Tests:** 110

---

## Project Overview

### Vision
Establish GitRecon as the gold standard for automated Git repository security reconnaissance — balancing speed, accuracy, and operational security.

### Mission
1. **Reliability First:** Zero data loss with checkpoint/resume and smart error recovery
2. **Performance Leadership:** Sub-minute scan times for repositories up to 10K objects
3. **Comprehensive Coverage:** 95%+ secret detection with <5% false positive rate
4. **Integration Ready:** Multiple output formats and webhook delivery
5. **Stealth & Evasion:** Rate limiting, proxy rotation, UA diversification

### Target Users
- **Primary:** Red Team Operators, Bug Bounty Hunters, Security Researchers
- **Secondary:** DevSecOps Teams, Incident Responders, Compliance Auditors

---

## Architecture Overview

### Current Architecture (Monolithic)

```
┌─────────────────────────────────────────────────────────────────┐
│                         gitrecon binary                           │
├─────────────────────────────────────────────────────────────────┤
│  main.rs (~680 lines)                                            │
│  ├─ CLI parsing (clap)                                          │
│  ├─ Mode routing (URL/Token/Dir/Targets)                        │
│  └─ Phase orchestration                                          │
├─────────────────────────────────────────────────────────────────┤
│                        Core Modules                              │
├────────────────┬────────────────┬────────────────┬────────────────┤
│  detect.rs     │  mapper.rs    │  streamer.rs   │  reporter.rs   │
│  (~410 lines)  │  (~485 lines)  │  (~1430 lines) │  (~290 lines)  │
│  Phase 1       │  Phase 2       │  Phase 3       │  Phase 4       │
│  Probe .git    │  Fetch meta   │  Concurrent    │  Risk score    │
│  Confidence    │  Collect SHA1 │  fetch & scan   │  Terminal/UI   │
│  Fuzz variants │  Parse index   │  110 patterns  │  JSON/SARIF    │
├────────────────┴────────────────┴────────────────┴────────────────┤
│                      Supporting Modules                           │
├────────────────┬────────────────┬────────────────┬────────────────┤
│  http_client   │  git_parser    │  github_api    │  checkpoint    │
│  (~200 lines)  │  (~545 lines)  │  (~163 lines)  │  (~79 lines)   │
│  HTTP wrapper  │  Object parser │  Token mode    │  Resume state  │
│  Backoff       │  Loose/pack    │  Enumerate     │  Progress save │
│  Proxy         │  DIRC v2-v4    │  Download      │  Recovery      │
├────────────────┴────────────────┴────────────────┴────────────────┤
│  binary_scanner.rs (~79 lines)                                   │
│  reconstructor.rs (~40 lines)                                    │
│  text_utils.rs (~30 lines)                                       │
└─────────────────────────────────────────────────────────────────┘
```

### Target Architecture (v4.0 Plugin-Based)

```
┌─────────────────────────────────────────────────────────────────┐
│                         gitrecon CLI                              │
│                    (thin orchestration)                          │
├─────────────────────────────────────────────────────────────────┤
│                    Plugin Loading System                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐│
│  │  Scanner   │  │  Fetcher   │  │  Analyzer  │  │  Reporter  ││
│  │  Plugins   │  │  Plugins   │  │  Plugins   │  │  Plugins   ││
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘│
├─────────────────────────────────────────────────────────────────┤
│                    Core Library (gitrecon-core)                  │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐│
│  │ Trait API  │  │  HTTP      │  │  Git       │  │  Pattern   ││
│  │ Definitions│  │  Engine    │  │  Parser    │  │  Engine    ││
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## Development Guidelines

### Rust Coding Standards

1. **Format:** `cargo fmt` before commit
2. **Lint:** `cargo clippy -- -D warnings` must pass
3. **Documentation:** Public items need `///` doc comments
4. **Error Handling:** Use `anyhow::Result` for application errors
5. **Async:** Use `tokio` runtime, prefer `async fn` over blocking

### Testing Requirements

- **Coverage Minimum:** 80% per module
- **Unit Tests:** Located in module `#[cfg(test)]` blocks
- **Integration Tests:** `tests/` directory
- **Test Naming:** `test_<function>_<condition>`

### Security Review Checklist

- [ ] No hardcoded credentials
- [ ] All user inputs validated
- [ ] Path traversal protection
- [ ] TLS verification enforced
- [ ] No unsafe code without justification
- [ ] Dependencies audited

### Performance Benchmarks

- **URL Scan:** <60s for 10K object repository
- **Token Scan:** <5s per 100 files
- **Memory:** <500MB for 10K objects
- **Concurrent Workers:** 50 default, 5-200 adaptive

---

## Component Structure

| Module | LOC | Responsibility |
|--------|-----|----------------|
| `main.rs` | 680 | CLI parsing, mode routing, orchestration |
| `detect.rs` | 410 | Phase 1: .git detection, confidence scoring |
| `mapper.rs` | 485 | Phase 2: Metadata fetch, SHA1 collection |
| `streamer.rs` | 1430 | Phase 3: Concurrent object fetch and scan |
| `reporter.rs` | 290 | Phase 4: Output formatting, risk scoring |
| `http_client.rs` | 200 | HTTP engine with retry, proxy, rate limit |
| `git_parser.rs` | 545 | Git object parsing (loose, pack, DIRC) |
| `github_api.rs` | 163 | GitHub API client for token mode |
| `checkpoint.rs` | 79 | Checkpoint/resume state management |
| `binary_scanner.rs` | 79 | Binary file scanning (SQLite, JAR, ZIP) |
| `reconstructor.rs` | 40 | Git repository reconstruction |
| `text_utils.rs` | 30 | Text processing utilities |

---

## Development Workflow

### Branch Strategy
- `main`: Stable releases only
- `develop`: Integration branch for features
- `feature/*`: Feature branches
- `fix/*`: Bugfix branches

### Pull Request Requirements
1. All tests pass (`cargo test --all-features`)
2. Clippy warnings resolved
3. Documentation updated
4. Changelog entry added
5. Sign-off added to commits

### CI/CD Pipeline
- **On PR:** Test + Clippy + Format check
- **On Merge:** Full test suite + benchmarks
- **On Tag:** Release build + publish

### Release Process
1. Update `Cargo.toml` version
2. Update CHANGELOG.md
3. Create git tag `vX.Y.Z`
4. GitHub Actions builds binaries
5. Publish to crates.io

---

## Coordination Protocol

### Progress Tracking
- Use roadmap IDs (e.g., SEC-001, PERF-001)
- Update TODO.md checkboxes
- Reference plan documents

### Conflict Resolution
1. Check existing PRs before starting
2. Coordinate in `develop` branch for cross-cutting changes
3. Resolve merge conflicts with maintainers

### Decision Making
- RFC process for breaking changes
- Voting: maintainers + 2 contributors
- Implementation period: 2 weeks

---

## Quality Gates

### Definition of Done
- **Feature:** Tests documented, PR merged, changelog updated
- **Phase:** All tasks complete, integration tests pass
- **Release:** All phases complete, docs updated, tagged

### Acceptance Criteria
Each roadmap item includes acceptance criteria. Verify with:
```bash
cargo test --all-features
cargo clippy -- -D warnings
```

### Rollback Procedures
- Revert merge commit if critical bug found
- Hotfix branch for urgent fixes
- Point release for non-breaking fixes

### Quality Metrics
- **Code:** 80% test coverage, zero clippy warnings
- **Performance:** Benchmarks within 10% of baseline
- **Security:** No high-severity CVEs in dependencies
- **Documentation:** All public APIs documented

---

## Task Priorities

### P0 (Critical Security) - 6 tasks
- SEC-001: Input Validation for All User-Supplied Data
- SEC-002: Path Traversal Protection in File Operations
- SEC-003: Secure Temporary File Handling
- SEC-004: TLS Certificate Verification Enforcement
- SEC-005: Audit and Fix Regex Patterns for ReDoS
- SEC-006: Rate Limiting per Target

### P1 (Infrastructure) - 8 tasks
- PERF-001: Checkpoint & Resume System
- PERF-002: Smart Retry per Status Code
- PERF-003: Adaptive Concurrency Control
- PERF-004: HTTP/2 Multiplexing Support
- PERF-005: Prefetching Based on Graph
- PERF-006: SQLite Cache Layer
- PERF-007: Streaming Decompression
- PERF-008: Configuration File Support

### P2 (Platform) - 11 tasks
- FORGE-001 through FORGE-011: Multi-platform support

### P3 (Scanning) - 6 tasks
- SCAN-001 through SCAN-006: Enhanced scanning capabilities

### P4 (Fable5) - 5 tasks
- FABLE-001 through FABLE-005: Fable5 integration

### P5 (Architecture) - 7 tasks
- ARCH-001 through ARCH-007: Plugin architecture

### P6 (Library) - 5 tasks
- LIB-001 through LIB-005: Python bindings

### P7 (Enterprise) - 7 tasks
- ENT-001 through ENT-007: Enterprise features

---

## Resources

### Documentation
- Rust Book: https://doc.rust-lang.org/book/
- Tokio Guide: https://tokio.rs/tokio/tutorial
- Regex Tutorial: https://docs.rs/regex/

### Git Internals
- Git SCM Book: https://git-scm.com/book/en/v2
- Pack Format: https://git-scm.com/docs/pack-protocol
- Object Database: https://git-scm.com/docs/gitformat-pack

### Project-Specific
- PLATFORM_EXPANSION_PLAN.md
- SECURITY_PLAN.md
- CHANGELOG.md

---

## Appendix

### Roadmap Quick Reference
- **R-1:** Checkpoint & Resume (PERF-001)
- **R-2:** Smart Retry (PERF-002)
- **R-3:** Adaptive Timeout (implemented)
- **P-1:** Adaptive Concurrency (PERF-003)
- **P-2:** HTTP/2 (PERF-004)
- **P-3:** Prefetching (PERF-005)
- **P-4:** Streaming Decompression (PERF-007)
- **A-1:** Multi-Target (implemented)
- **A-2:** Cache (PERF-006)
- **A-6:** Pipeline Mode (implemented)
- **A-7:** Forge Abstraction (FORGE-001)
- **S-1:** Context Scoring (SCAN-001)
- **S-2:** Multi-Line (SCAN-002)
- **S-3:** Binary Scanning (SCAN-003, partial)
- **S-4:** DB Credentials (SCAN-004)
- **E-1:** Rate Limit (SEC-006, partial)
- **E-2:** Proxy Rotation (implemented)
- **E-3:** Fingerprint Diversification (ENT-004)
- **E-4:** UA Pool (ENT-005)
- **O-1:** Live Output (ENT-001)
- **O-2:** SARIF (ENT-002)
- **O-3:** Output Formats (implemented)
- **O-4:** Webhook (ENT-003)

---

**Document Status:** Active  
**Maintainer:** GitRecon Development Team  
**Contact:** via GitHub Issues

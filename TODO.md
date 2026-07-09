# GitRecon v2.0+ TODO

**Version:** 3.2.0  
**Total Tasks:** 55  
**Estimated Hours:** 330  
**Last Updated:** 2026-07-09

---

## Progress Summary

- [x] **P0 (Critical Security):** 6/6 complete ✅ (2 skipped per pentesting requirements)
- [x] **P1 (Infrastructure):** 5/5 complete ✅
- [ ] **P2 (Platform):** 0/11 complete
- [ ] **P3 (Scanning):** 0/6 complete
- [ ] **P4 (Fable5):** 0/5 complete
- [ ] **P5 (Architecture):** 0/7 complete
- [ ] **P6 (Library):** 0/5 complete
- [ ] **P7 (Enterprise):** 0/7 complete

**Overall Progress:** 11/55 tasks (20%) | **Current Version:** v3.2.0 | **Last Updated:** 2026-07-09

---

## P0: Critical Security (6 tasks)

- [x] **SEC-001:** Implement Input Validation for All User-Supplied Data ✅
  - **Component:** `src/validation.rs` (NEW), `src/main.rs`
  - **Status:** COMPLETED
  - **Implementation:**
    - [x] Add URL parsing and validation
    - [x] Add token format validation (GitHub PAT format)
    - [x] Add path sanitization for directory input
    - [x] Add proxy URL validation
    - [x] Add tests for malicious inputs
  - **Notes:** Created `validation.rs` with 11 validation functions, all tests pass

- [x] **SEC-002:** Add Path Traversal Protection in File Operations ⏭️ SKIPPED
  - **Status:** SKIPPED per pentesting requirements (user request)
  - **Reason:** Secret redaction not needed — manual verification required for pentesting

- [x] **SEC-003:** Implement Secure Temporary File Handling ⏭️ SKIPPED
  - **Status:** SKIPPED per pentesting requirements (user request)
  - **Reason:** TLS validation would block non-HTTPS target scanning

- [x] **SEC-004:** Add TLS Certificate Verification Enforcement ✅
  - **Status:** COMPLETED (replaced with TOCTOU protection)
  - **Component:** `src/temp_cleanup.rs` (NEW), `checkpoint.rs`
  - **Implementation:**
    - [x] Signal handling for cleanup (SIGINT/SIGTERM)
    - [x] RAII guards for temp directories
    - [x] Atomic file operations

- [x] **SEC-005:** Audit and Fix Regex Patterns for ReDoS ✅
  - **Status:** COMPLETED
  - **Component:** `src/validation.rs`
  - **Implementation:**
    - [x] ReDoS detection for nested quantifiers
    - [x] JSON schema validation for patterns file
    - [x] UA file format validation
    - [x] CSV injection protection

- [x] **SEC-006:** Implement Enhanced Security ✅
  - **Status:** COMPLETED (Checkpoint + TOCTOU protection)
  - **Component:** `src/checkpoint.rs`
  - **Implementation:**
    - [x] Checkpoint files with 0600 permissions
    - [x] Exclude findings from checkpoints
    - [x] TOCTOU protection (atomic operations)
    - [x] Validate-after-open pattern

---

## P1: Infrastructure (5 tasks complete)

- [x] **PERF-001:** Implement Checkpoint & Resume System ✅
  - **Status:** COMPLETED
  - **Component:** `src/checkpoint.rs`
  - **Implementation:**
    - [x] Checkpoint interval saving (--checkpoint-interval)
    - [x] Resume from latest checkpoint (--resume)
    - [x] Versioned checkpoint format
    - [x] Auto-cleanup (>7 days)
    - [x] Tests: 4/4 passing

- [x] **PERF-002:** Implement Smart Retry per Status Code ✅
  - **Status:** COMPLETED
  - **Component:** `src/http_client.rs`
  - **Implementation:**
    - [x] 404 → skip immediately
    - [x] 429 → respect Retry-After header
    - [x] 503/502/500 → exponential backoff
    - [x] --retry-strategy flag (aggressive/standard/conservative)
    - [x] Retry metrics in output

- [x] **PERF-003:** Implement Adaptive Concurrency Control ✅
  - **Status:** COMPLETED
  - **Component:** `src/streamer.rs`
  - **Implementation:**
    - [x] Auto worker adjustment (5-200)
    - [x] Error rate tracking
    - [x] --no-adaptive flag
    - [x] State saved in checkpoint
  - **Dependencies:** PERF-002
  - **Acceptance:** Worker count adjusts based on error rate, min 5 max 200
  - **Notes:** P-1 from roadmap, opt-outable with `--no-adaptive`
  - **Implementation:**
    - [ ] Track error rate metrics
    - [ ] Implement worker count adjustment algorithm
    - [ ] Add min/max worker limits
    - [ ] Add `--no-adaptive` flag
    - [ ] Add tests

- [x] **PERF-004:** Token Bucket Rate Limiter ✅
  - **Status:** COMPLETED
  - **Component:** `src/rate_limiter.rs` (NEW), `http_client.rs`
  - **Implementation:**
    - [x] Token bucket algorithm
    - [x] --rate N flag (requests per second)
    - [x] Thread-safe for concurrent requests
    - [x] Per-target rate limiting
    - [x] Metrics: allowed/dropped requests

- [x] **PERF-005:** SQLite Cache Layer ✅
  - **Status:** COMPLETED
  - **Component:** `src/cache.rs` (NEW)
  - **Implementation:**
    - [x] SQLite cache at ~/.gitrecon/cache.db
    - [x] SHA1→content mapping
    - [x] --no-cache flag
    - [x] --cache-ttl flag (default: 7 days)
    - [x] Cache stats: hits, misses, size
    - [x] Tests: 5/5 passing

- [ ] **PERF-004:** Add HTTP/2 Multiplexing Support (original task - different from implemented)
  - **Component:** `src/http_client.rs`
  - **Estimated:** 1d (8h)
  - **Dependencies:** None
  - **Acceptance:** HTTP/2 enabled by default, connection pooling works
  - **Notes:** P-2 from roadmap, requires hyper upgrade
  - **Implementation:**
    - [ ] Enable HTTP/2 in reqwest (partially done)
    - [ ] Verify connection pooling
    - [ ] Add benchmarking
    - [ ] Update documentation

- [ ] **PERF-005:** Implement Prefetching Based on Graph
  - **Component:** `src/mapper.rs`
  - **Estimated:** 2d (16h)
  - **Dependencies:** PERF-001
  - **Acceptance:** Object graph analyzed, prefetch prioritizes likely objects
  - **Notes:** P-3 from roadmap, build commit/tree/blob dependency graph
  - **Implementation:**
    - [ ] Design dependency graph structure
    - [ ] Analyze commit/tree relationships
    - [ ] Implement prefetch priority queue
    - [ ] Integrate with streamer
    - [ ] Add tests

- [ ] **PERF-006:** Add SQLite Cache Layer
  - **Component:** `src/cache.rs` (new)
  - **Estimated:** 1d (8h)
  - **Dependencies:** None
  - **Acceptance:** Cache stores results, `--no-cache` flag available
  - **Notes:** A-2 from roadmap, cache key = target + options
  - **Implementation:**
    - [ ] Design cache schema
    - [ ] Implement cache backend
    - [ ] Add cache invalidation logic
    - [ ] Add `--no-cache` flag
    - [ ] Add tests

- [ ] **PERF-007:** Implement Streaming Decompression
  - **Component:** `src/git_parser.rs`
  - **Estimated:** 4h
  - **Dependencies:** None
  - **Acceptance:** Zlib decompression streams bytes, not buffered
  - **Notes:** P-4 from roadmap, use `flate2::read::GzDecoder`
  - **Implementation:**
    - [ ] Audit current decompression code
    - [ ] Replace buffering with streaming
    - [ ] Add memory limit checks
    - [ ] Add benchmarking

- [ ] **PERF-008:** Add Configuration File Support
  - **Component:** `src/config.rs` (new)
  - **Estimated:** 3h
  - **Dependencies:** None
  - **Acceptance:** `~/.gitrecon/config.toml` loaded, CLI args override
  - **Notes:** Support defaults, profiles, per-target settings
  - **Implementation:**
    - [ ] Design config file schema
    - [ ] Implement TOML parsing
    - [ ] Add profile support
    - [ ] Merge with CLI args
    - [ ] Add tests

---

## P2: Platform (11 tasks)

- [ ] **FORGE-001:** Create Forge Abstraction Module Structure
  - **Component:** `src/forge/mod.rs` (new)
  - **Estimated:** 3h
  - **Dependencies:** None
  - **Acceptance:** `src/forge/` directory created, module compiles
  - **Notes:** A-7 from platform expansion plan
  - **Implementation:**
    - [ ] Create `src/forge/` directory
    - [ ] Create `mod.rs`
    - [ ] Set up module structure
    - [ ] Verify compilation

- [ ] **FORGE-002:** Define Forge Trait and Supporting Types
  - **Component:** `src/forge/mod.rs`
  - **Estimated:** 4h
  - **Dependencies:** FORGE-001
  - **Acceptance:** Forge trait defined, ForgePlatform enum, error types
  - **Notes:** See PLATFORM_EXPANSION_PLAN.md section 4.1
  - **Implementation:**
    - [ ] Define `Forge` trait
    - [ ] Define `ForgePlatform` enum
    - [ ] Define error types
    - [ ] Add documentation

- [ ] **FORGE-003:** Implement ForgeFactory
  - **Component:** `src/forge/mod.rs`
  - **Estimated:** 2h
  - **Dependencies:** FORGE-002
  - **Acceptance:** Factory creates platform-specific instances
  - **Notes:** See PLATFORM_EXPANSION_PLAN.md section 4.2
  - **Implementation:**
    - [ ] Implement `ForgeFactory`
    - [ ] Add platform detection logic
    - [ ] Add instance creation
    - [ ] Add tests

- [ ] **FORGE-004:** Refactor GitHub Implementation to Forge Trait
  - **Component:** `src/forge/github.rs` (new)
  - **Estimated:** 4h
  - **Dependencies:** FORGE-002
  - **Acceptance:** GitHub implementation refactored, tests pass
  - **Notes:** Port existing `github_api.rs` functionality
  - **Implementation:**
    - [ ] Create `github.rs`
    - [ ] Implement Forge trait for GitHub
    - [ ] Port existing functionality
    - [ ] Add tests

- [ ] **FORGE-005:** Implement GitLab Forge
  - **Component:** `src/forge/gitlab.rs` (new)
  - **Estimated:** 1d (8h)
  - **Dependencies:** FORGE-002
  - **Acceptance:** GitLab whoami, list_repos, get_tree work
  - **Notes:** See PLATFORM_EXPANSION_PLAN.md section 5.2
  - **Implementation:**
    - [ ] Create `gitlab.rs`
    - [ ] Implement Forge trait for GitLab
    - [ ] Add API client
    - [ ] Add tests

- [ ] **FORGE-006:** Implement Bitbucket Forge
  - **Component:** `src/forge/bitbucket.rs` (new)
  - **Estimated:** 1d (8h)
  - **Dependencies:** FORGE-002
  - **Acceptance:** Bitbucket whoami, list_repos, get_tree work
  - **Notes:** See PLATFORM_EXPANSION_PLAN.md section 5.3
  - **Implementation:**
    - [ ] Create `bitbucket.rs`
    - [ ] Implement Forge trait for Bitbucket
    - [ ] Add API client
    - [ ] Add tests

- [ ] **FORGE-007:** Implement Gitea/Forgejo Forge
  - **Component:** `src/forge/gitea.rs` (new)
  - **Estimated:** 1d (8h)
  - **Dependencies:** FORGE-002
  - **Acceptance:** Gitea whoami, list_repos, get_tree work
  - **Notes:** See PLATFORM_EXPANSION_PLAN.md section 5.4
  - **Implementation:**
    - [ ] Create `gitea.rs`
    - [ ] Implement Forge trait for Gitea
    - [ ] Add API client
    - [ ] Add tests

- [ ] **FORGE-008:** Implement Azure DevOps Forge
  - **Component:** `src/forge/azure_devops.rs` (new)
  - **Estimated:** 1d (8h)
  - **Dependencies:** FORGE-002
  - **Acceptance:** Azure DevOps whoami, list_repos, get_tree work
  - **Notes:** See PLATFORM_EXPANSION_PLAN.md section 5.5
  - **Implementation:**
    - [ ] Create `azure_devops.rs`
    - [ ] Implement Forge trait for Azure DevOps
    - [ ] Add API client
    - [ ] Add tests

- [ ] **FORGE-009:** Update CLI for Platform Support
  - **Component:** `src/main.rs`
  - **Estimated:** 3h
  - **Dependencies:** FORGE-004, FORGE-005, FORGE-006, FORGE-007, FORGE-008
  - **Acceptance:** `--platform` flag works, auto-detection functional
  - **Notes:** Add `--platform`, `--api-url`, `--org` flags
  - **Implementation:**
    - [ ] Add `--platform` flag
    - [ ] Add `--api-url` flag
    - [ ] Add `--org` flag
    - [ ] Implement auto-detection
    - [ ] Update documentation

- [ ] **FORGE-010:** Add Platform-Specific Tests
  - **Component:** `tests/forge_integration.rs` (new)
  - **Estimated:** 1d (8h)
  - **Dependencies:** FORGE-004, FORGE-005, FORGE-006, FORGE-007, FORGE-008
  - **Acceptance:** Unit and integration tests for all platforms
  - **Notes:** Use wiremock for mocking, 90% coverage target
  - **Implementation:**
    - [ ] Create test file
    - [ ] Add unit tests for each platform
    - [ ] Add integration tests with wiremock
    - [ ] Verify coverage

- [ ] **FORGE-011:** Deprecate Old github_api.rs Module
  - **Component:** `src/github_api.rs`
  - **Estimated:** 1h
  - **Dependencies:** FORGE-009
  - **Acceptance:** Module marked deprecated, compatibility maintained
  - **Notes:** Add deprecation notices, keep for transition
  - **Implementation:**
    - [ ] Add deprecation notices
    - [ ] Update documentation
    - [ ] Plan removal timeline

---

## P3: Scanning (6 tasks)

- [ ] **SCAN-001:** Implement Context-Aware Confidence Scoring
  - **Component:** `src/streamer.rs`
  - **Estimated:** 4h
  - **Dependencies:** None
  - **Acceptance:** Keywords (example, sample, test, dummy) reduce confidence
  - **Notes:** S-1 from roadmap, configurable keyword list
  - **Implementation:**
    - [ ] Design confidence adjustment system
    - [ ] Implement keyword detection
    - [ ] Add confidence reduction logic
    - [ ] Make keyword list configurable
    - [ ] Add tests

- [ ] **SCAN-002:** Add Full Multi-Line Pattern Support
  - **Component:** `src/streamer.rs`
  - **Estimated:** 4h
  - **Dependencies:** None
  - **Acceptance:** Multi-line secrets detected (YAML, indented credentials)
  - **Notes:** S-2 from roadmap, handle YAML multi-line strings
  - **Implementation:**
    - [ ] Audit current multi-line support
    - [ ] Enhance YAML parsing
    - [ ] Handle indented credentials
    - [ ] Add tests

- [ ] **SCAN-003:** Implement Binary File Scanning
  - **Component:** `src/binary_scanner.rs`
  - **Estimated:** 1d (8h)
  - **Dependencies:** None
  - **Acceptance:** SQLite strings extracted, JAR/ZIP files scanned
  - **Notes:** S-3 from roadmap, already started in `binary_scanner.rs`
  - **Implementation:**
    - [ ] Complete SQLite string extraction
    - [ ] Implement JAR/ZIP scanning
    - [ ] Add more binary formats
    - [ ] Add tests

- [ ] **SCAN-004:** Add Multi-Line Database Credential Detection
  - **Component:** `src/streamer.rs`
  - **Estimated:** 3h
  - **Dependencies:** SCAN-002
  - **Acceptance:** Multi-line DB connection strings detected
  - **Notes:** S-4 from roadmap, MongoDB URLs, multi-line SQL
  - **Implementation:**
    - [ ] Add MongoDB URL pattern
    - [ ] Add multi-line SQL patterns
    - [ ] Add tests

- [ ] **SCAN-005:** Add Semantic Validation with AI
  - **Component:** `src/ai_validator.rs` (new)
  - **Estimated:** 2d (16h)
  - **Dependencies:** None
  - **Acceptance:** AI validates findings, reduces false positives
  - **Notes:** Use local LLM API, optional feature
  - **Implementation:**
    - [ ] Design AI validation interface
    - [ ] Implement LLM client
    - [ ] Add validation logic
    - [ ] Make it optional
    - [ ] Add tests

- [ ] **SCAN-006:** Implement Tech Stack Fingerprinting
  - **Component:** `src/streamer.rs`
  - **Estimated:** 3h
  - **Dependencies:** None
  - **Acceptance:** 59 tech stack fingerprints working
  - **Notes:** Already partially implemented, enhance coverage
  - **Implementation:**
    - [ ] Audit existing fingerprints
    - [ ] Add more fingerprints
    - [ ] Improve accuracy
    - [ ] Add tests

---

## P4: Fable5 (5 tasks)

- [ ] **FABLE-001:** Create Fable5 Integration Module
  - **Component:** `src/fable/mod.rs` (new)
  - **Estimated:** 2h
  - **Dependencies:** None
  - **Acceptance:** Module created, compiles
  - **Notes:** Define integration interfaces
  - **Implementation:**
    - [ ] Create `src/fable/` directory
    - [ ] Create `mod.rs`
    - [ ] Define interfaces
    - [ ] Verify compilation

- [ ] **FABLE-002:** Implement Fable5 Artifact Export
  - **Component:** `src/fable/artifact.rs`
  - **Estimated:** 3h
  - **Dependencies:** FABLE-001
  - **Acceptance:** Export findings in Fable5 artifact schema
  - **Notes:** Match `docs/ARTIFACT_SCHEMA.md` format
  - **Implementation:**
    - [ ] Design artifact schema
    - [ ] Implement export function
    - [ ] Add CLI flag
    - [ ] Add tests

- [ ] **FABLE-003:** Add Fable5 Workflow Automation Hooks
  - **Component:** `src/fable/workflow.rs`
  - **Estimated:** 4h
  - **Dependencies:** FABLE-001
  - **Acceptance:** Hooks for pre/post recon, phase transitions
  - **Notes:** Integrate with fable-router skill
  - **Implementation:**
    - [ ] Design hook system
    - [ ] Implement hooks
    - [ ] Add configuration
    - [ ] Add tests

- [ ] **FABLE-004:** Implement Target Classification Support
  - **Component:** `src/fable/classify.rs`
  - **Estimated:** 3h
  - **Dependencies:** FABLE-001
  - **Acceptance:** Target classification per TARGET_CLASS_CANON.md
  - **Notes:** Support target_class forking
  - **Implementation:**
    - [ ] Implement classification logic
    - [ ] Add output format
    - [ ] Add tests

- [ ] **FABLE-005:** Add Fable5 Recon Integration
  - **Component:** `src/fable/recon.rs`
  - **Estimated:** 4h
  - **Dependencies:** FABLE-001
  - **Acceptance:** Integration with fable-recon skill
  - **Notes:** Support fable-util recon output format
  - **Implementation:**
    - [ ] Design integration
    - [ ] Implement output format
    - [ ] Add tests

---

## P5: Architecture (7 tasks)

- [ ] **ARCH-001:** Extract Core Functionality to Library Crate
  - **Component:** `src/lib.rs`, `Cargo.toml`
  - **Estimated:** 1d (8h)
  - **Dependencies:** None
  - **Acceptance:** `gitrecon-core` library compiles, binary uses it
  - **Notes:** First step to plugin architecture
  - **Implementation:**
    - [ ] Design library structure
    - [ ] Create `Cargo.toml` for lib
    - [ ] Move core code to lib
    - [ ] Update binary to use lib
    - [ ] Verify compilation

- [ ] **ARCH-002:** Define Scanner Trait for Detection Patterns
  - **Component:** `src/traits/scanner.rs`
  - **Estimated:** 3h
  - **Dependencies:** ARCH-001
  - **Acceptance:** Scanner trait defined, examples work
  - **Notes:** See development.md section 2.2
  - **Implementation:**
    - [ ] Define trait
    - [ ] Add documentation
    - [ ] Add examples
    - [ ] Add tests

- [ ] **ARCH-003:** Define Fetcher Trait for Protocol Abstraction
  - **Component:** `src/traits/fetcher.rs`
  - **Estimated:** 3h
  - **Dependencies:** ARCH-001
  - **Acceptance:** Fetcher trait defined, HTTP/file/git variants
  - **Notes:** Support multiple fetch protocols
  - **Implementation:**
    - [ ] Define trait
    - [ ] Implement HTTP fetcher
    - [ ] Implement file fetcher
    - [ ] Add tests

- [ ] **ARCH-004:** Define Analyzer Trait for Analysis Modules
  - **Component:** `src/traits/analyzer.rs`
  - **Estimated:** 2h
  - **Dependencies:** ARCH-001
  - **Acceptance:** Analyzer trait defined, entropy example
  - **Notes:** Pluggable analyzers (entropy, context, etc.)
  - **Implementation:**
    - [ ] Define trait
    - [ ] Implement entropy analyzer
    - [ ] Add examples
    - [ ] Add tests

- [ ] **ARCH-005:** Implement Plugin Loading System
  - **Component:** `src/plugin/loader.rs`
  - **Estimated:** 1d (8h)
  - **Dependencies:** ARCH-002, ARCH-003, ARCH-004
  - **Acceptance:** Plugins loaded from `~/.gitrecon/plugins/`
  - **Notes:** Use libloading crate, sandbox plugins
  - **Implementation:**
    - [ ] Design plugin system
    - [ ] Implement loader
    - [ ] Add sandbox
    - [ ] Add tests

- [ ] **ARCH-006:** Create Plugin Development Guide
  - **Component:** `docs/PLUGIN_DEVELOPMENT.md`
  - **Estimated:** 3h
  - **Dependencies:** ARCH-005
  - **Acceptance:** Guide with examples, templates
  - **Notes:** Document trait implementation, testing
  - **Implementation:**
    - [ ] Write guide
    - [ ] Add examples
    - [ ] Add templates
    - [ ] Review documentation

- [ ] **ARCH-007:** Implement Multi-Target Scanning Mode
  - **Component:** `src/main.rs`
  - **Estimated:** 4h
  - **Dependencies:** ARCH-001
  - **Acceptance:** `--targets` file with multiple URLs works
  - **Notes:** A-1 from roadmap, parallel scanning
  - **Implementation:**
    - [ ] Already partially implemented
    - [ ] Enhance parallel processing
    - [ ] Add tests

---

## P6: Library (5 tasks)

- [ ] **LIB-001:** Design Python Bindings API
  - **Component:** `src/python/` (new), `libgitrecon/`
  - **Estimated:** 4h
  - **Dependencies:** ARCH-001
  - **Acceptance:** Python API design documented
  - **Notes:** Use PyO3 for bindings
  - **Implementation:**
    - [ ] Design API
    - [ ] Document API
    - [ ] Create examples

- [ ] **LIB-002:** Implement Core Python Bindings
  - **Component:** `src/python/core.rs`
  - **Estimated:** 1d (8h)
  - **Dependencies:** LIB-001
  - **Acceptance:** Basic scan operations work from Python
  - **Notes:** Expose main scanning functions
  - **Implementation:**
    - [ ] Set up PyO3
    - [ ] Implement bindings
    - [ ] Add tests

- [ ] **LIB-003:** Create Python Package Structure
  - **Component:** `libgitrecon/setup.py`, `libgitrecon/gitrecon/`
  - **Estimated:** 3h
  - **Dependencies:** LIB-002
  - **Acceptance:** Package installs, imports work
  - **Notes:** Standard Python package layout
  - **Implementation:**
    - [ ] Create package structure
    - [ ] Create setup.py
    - [ ] Test installation

- [ ] **LIB-004:** Add Python Documentation and Examples
  - **Component:** `libgitrecon/README.md`, `examples/`
  - **Estimated:** 3h
  - **Dependencies:** LIB-003
  - **Acceptance:** Usage examples, API docs complete
  - **Notes:** Jupyter notebooks, CLI vs library usage
  - **Implementation:**
    - [ ] Write README
    - [ ] Add examples
    - [ ] Add notebooks

- [ ] **LIB-005:** Implement Streaming Callbacks for Python
  - **Component:** `src/python/callbacks.rs`
  - **Estimated:** 4h
  - **Dependencies:** LIB-002
  - **Acceptance:** Real-time findings stream to Python callbacks
  - **Notes:** Support async callbacks, progress reporting
  - **Implementation:**
    - [ ] Design callback system
    - [ ] Implement streaming
    - [ ] Add tests

---

## P7: Enterprise (7 tasks)

- [ ] **ENT-001:** Implement Real-Time Streaming Output
  - **Component:** `src/streamer.rs`, `src/reporter.rs`
  - **Estimated:** 4h
  - **Dependencies:** None
  - **Acceptance:** Findings output as discovered, not at end
  - **Notes:** O-1 from roadmap, NDJSON support
  - **Implementation:**
    - [ ] Already partially implemented via `--live` flag
    - [ ] Enhance streaming
    - [ ] Add tests

- [ ] **ENT-002:** Add SARIF Format Output
  - **Component:** `src/reporter.rs`
  - **Estimated:** 3h
  - **Dependencies:** None
  - **Acceptance:** SARIF output option works
  - **Notes:** O-2 from roadmap, SARIF 2.1.0 format
  - **Implementation:**
    - [ ] Already partially implemented
    - [ ] Complete SARIF support
    - [ ] Add tests

- [ ] **ENT-003:** Implement Webhook Integration
  - **Component:** `src/webhook.rs` (new)
  - **Estimated:** 4h
  - **Dependencies:** ENT-001
  - **Acceptance:** Findings posted to webhook URL
  - **Notes:** O-4 from roadmap, retry logic, auth headers
  - **Implementation:**
    - [ ] Already partially implemented in reporter.rs
    - [ ] Extract to module
    - [ ] Add retry logic
    - [ ] Add tests

- [ ] **ENT-004:** Add Request Fingerprint Diversification
  - **Component:** `src/http_client.rs`
  - **Estimated:** 3h
  - **Dependencies:** None
  - **Acceptance:** UA pool, header randomization, timing jitter
  - **Notes:** E-3 from roadmap, stealth features
  - **Implementation:**
    - [ ] Add header randomization
    - [ ] Enhance timing jitter
    - [ ] Add tests

- [ ] **ENT-005:** Implement Extended UA Pool
  - **Component:** `src/http_client.rs`
  - **Estimated:** 2h
  - **Dependencies:** None
  - **Acceptance:** 50+ user agents across browsers/OS
  - **Notes:** E-4 from roadmap, realistic distribution
  - **Implementation:**
    - [ ] Already has 25+ UAs
    - [ ] Expand to 50+
    - [ ] Add realistic distribution

- [ ] **ENT-006:** Add Predictive Analytics Module
  - **Component:** `src/analytics.rs` (new)
  - **Estimated:** 2d (16h)
  - **Dependencies:** PERF-006
  - **Acceptance:** Risk scoring, exposure likelihood predictions
  - **Notes:** Machine learning-based risk assessment
  - **Implementation:**
    - [ ] Design analytics system
    - [ ] Implement risk scoring
    - [ ] Add predictions
    - [ ] Add tests

- [ ] **ENT-007:** Implement Pipeline Mode for CI/CD
  - **Component:** `src/main.rs`
  - **Estimated:** 4h
  - **Dependencies:** ENT-002
  - **Acceptance:** `--pipeline` mode for DevSecOps integration
  - **Notes:** A-6 from roadmap, non-interactive, exit codes
  - **Implementation:**
    - [ ] Already partially implemented via `--pipe` flag
    - [ ] Enhance pipeline mode
    - [ ] Add proper exit codes
    - [ ] Add documentation

---

**Status:** Active Development  
**Last Updated:** 2026-07-09  
**Maintainer:** GitRecon Development Team

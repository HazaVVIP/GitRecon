# GitRecon Capability Matrix and Limitations

**Version reference:** `v3.2.6` source baseline. This document describes the current implementation and deliberately distinguishes capabilities that are available in production from roadmap work that has not yet been released.

## Capability matrix

| Capability | URL exposure mode | Local directory mode | Forge snapshot mode | Forge history mode | Current status and limits |
|---|---|---|---|---|---|
| `.git` exposure detection | Supported | Not applicable | Not applicable | Not applicable | Probes the configured URL and reports exposure according to the selected detection policy. `--fuzz` adds probe paths; it does not imply historical scanning. |
| Repository mapping and object reconstruction | Supported | Not applicable | Not applicable | Not applicable | Supports loose objects and packed objects through the mapped repository pipeline. Object accessibility verification is enabled by default and can be disabled with `--no-verify-objects`. |
| Local filesystem scanning | Not applicable | Supported | Workspace-backed provider paths use the shared scanner | Not applicable | Recursive directory scanning is bounded by configured file/blob and resource limits. |
| Forge repository enumeration | Not applicable | Not applicable | GitHub, GitLab, Bitbucket, Gitea, and Azure client paths are implemented | Provider-specific | Authentication and repository selection depend on the provider token and API response. Tests use local response fixtures rather than live credentials. |
| Forge snapshot content scanning | Not applicable | Not applicable | Supported | Not applicable | Provider workspaces use the shared text, binary, archive, custom-pattern, and object outcome pipeline. Binary/archive scanning is enabled by default; `--no-scan-binaries` is an explicit opt-out. |
| Forge history traversal | Not applicable | Not applicable | Not applicable | GitHub and GitLab only | History is bounded by `--max-history`, deduplicates commit/blob work, and reports coverage. Other providers return typed `unsupported_capability` rather than an empty success. |
| Deleted-content coverage | Not applicable | Not applicable | Provider-dependent | GitHub can scan deleted blobs when a historical blob SHA is provided; GitLab maps deleted paths but cannot scan deleted content when its API supplies no historical blob address | Deleted paths and coverage limitations are reported separately from snapshot findings. |
| Binary scanning | Not applicable | Supported | Supported in forge snapshots | Supported where history content is acquired | Magic bytes are preferred, followed by supported extension and null-byte fallback. Printable strings, ELF strings, SQLite content, and binary custom patterns remain eligible under the shared policy. |
| Archive scanning | Not applicable | Supported | Supported in forge snapshots | Supported where history content is acquired | ZIP/JAR and GZIP extraction is bounded by entry count, per-file size, total expanded size, and nested depth. Limits remain active in `--exhaustive`. |
| Custom patterns | Not applicable | Supported | Supported | Supported where acquired content is scanned | Patterns are validated before scanning and preserve configured severity, description, and provenance across text, binary, archive, GZIP, SQLite, and ELF paths. |
| Normal versus exhaustive policy | Supported for acquired content | Supported | Supported | Supported | Normal mode filters common placeholders. `--exhaustive` retains placeholder-like candidates and is a superset of normal finding retention; it does not disable resource limits or silently filter additional content. |
| Checkpoint and resume | Supported for applicable scan orchestration | Supported | Supported for applicable orchestration | Supported for applicable orchestration | Checkpoints are integrity-protected and scoped to the configured checkpoint directory. Resume validation rejects incompatible or invalid state. |
| SQLite object cache | Supported | Applicable to shared object acquisition | Applicable where object acquisition uses the cache | Applicable where object acquisition uses the cache | Valid cached loose objects are verified before use. Corrupt entries are quarantined and acquisition falls back to loose HTTP. `--cache-stats` and `--cache-clear` operate without a target; `--no-cache` avoids SQLite initialization and I/O. |
| Structured output | Supported | Supported | Supported | Supported | JSON, SARIF, CSV, NDJSON, Markdown, and HTML are available. `--pipe` emits machine-readable pipeline objects; telemetry is additive and findings remain the primary report content. |
| Multi-target orchestration | Supported through target files | Supported through target files | Supported through typed target entries | Supported where the provider mode supports it | `--parallel-targets` is bounded to 1–1000 and aggregate outcomes preserve input order. |
| Platform installer | Pre-built release asset or source fallback | Pre-built release asset or source fallback | Not applicable | Not applicable | The installer currently recognizes Linux and macOS with x86_64 and aarch64/arm64 tags. Published assets must be checked against an exact `SHA256SUMS` entry; unsupported or unavailable assets fall back to a source build with an actionable message. |

## Important limitations

### Historical coverage is not equivalent to snapshot coverage

Forge snapshot mode scans the selected current workspace. History mode is a separate bounded capability currently implemented for GitHub and GitLab. A successful forge snapshot must not be interpreted as proof that historical commits or deleted content were scanned. The report's scope and coverage metadata identify the mode used.

### Provider APIs constrain deleted-content recovery

Deleted-path metadata can be available even when the provider does not expose a historical blob address. GitHub history can scan deleted blobs when the API returns a usable blob SHA. GitLab can preserve deleted-path and coverage metadata, but its current diff path does not scan deleted content when no historical blob address is supplied. Other providers remain snapshot-only for history requests.

### Resource limits apply in every finding-retention mode

`--exhaustive` expands candidate retention; it does not mean unlimited archive expansion, unlimited blob size, unlimited history traversal, or unlimited task fan-out. Maximum blob size, archive limits, memory budget, worker count, target parallelism, timeout, and history depth remain active to keep scans bounded.

### Object verification and cache integrity are separate boundaries

Object verification is enabled by default for mapped Git objects. The SQLite cache also validates canonical loose-object bytes on cache hits. Pack-object resolution deliberately follows its existing pack-reader path; cache-hit verification is not applied to pack-resolved objects because packs are not cached as canonical loose-object rows.

### Release and platform support are intentionally conservative

The repository currently publishes a Linux x86_64 release asset. The installer recognizes additional Linux ARM64 and macOS architecture tags so future compatible assets can be selected, but a recognized tag is not a claim that a corresponding published binary exists. Windows support and reproducible multi-platform release artifacts remain roadmap work. Source fallback may require Rust and platform build dependencies.

### Reports and reconstructed files may contain sensitive content

Findings, object bodies, reconstructed source, and report files can contain plaintext credential material. Store output directories with appropriate permissions and treat generated reports as sensitive. The scanner's validation and output controls do not make discovered content safe to publish.

## Operator interpretation

A clean result means no retained finding was emitted under the selected policy and limits; it does not prove that every historical object, deleted file, unsupported provider mode, or resource-limited archive was inspected. Operators should review scope, coverage, skip/failure, truncation, and acquisition-source metrics alongside findings before drawing conclusions.

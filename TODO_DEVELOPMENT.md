# GitRecon Development TODO

**Versi backlog:** setelah audit penuh v3.2.6
**Status baseline:** `origin/main` dan local `main` sinkron pada `0c3f04c1`; worktree bersih dan post-merge CI green
**Prioritas utama:** provider correctness dan coverage integrity, feature parity lintas mode, offensive coverage, performance/resource control, lalu maintainability dan release governance

Dokumen ini adalah backlog development resmi GitRecon. Item dikerjakan secara inkremental, satu paket perubahan pada satu waktu, dan setiap paket wajib mempertahankan kualitas build, test, serta perilaku offensive scanning yang sudah ada. `--exhaustive`, binary scanning default, object verification default, dan partial-exposure opt-in tidak boleh berubah secara tidak sengaja. Tidak boleh ada pagination loss, branch mis-selection, provider misattribution, atau silent filtering baru.

## Cara menggunakan backlog

Setiap item memiliki ID stabil, prioritas, status, dependensi, ruang lingkup, dan acceptance criteria. Status yang digunakan adalah `TODO`, `IN PROGRESS`, `BLOCKED`, dan `DONE`. Satu commit sebaiknya menyelesaikan satu item atau satu sub-bagian yang koheren. Perubahan yang memengaruhi output JSON, checkpoint, CLI, atau report harus disertai regression test dan catatan kompatibilitas.

| Prioritas | Makna | Urutan kerja |
|---|---|---|
| **P0** | Correctness dan kontrak operator; harus selesai sebelum fitur besar baru | Dikerjakan terlebih dahulu |
| **P1** | Feature parity, offensive coverage, acquisition depth, dan resource control | Setelah P0 stabil |
| **P2** | Modularisasi, typed error, provider abstraction, dan technical debt | Setelah boundary behavior stabil |
| **P3** | CI, governance, reproducible release, telemetry, dan distribusi multi-platform | Setelah P0–P2 siap |

## Definition of Done umum

Sebuah item dianggap selesai apabila implementasi, unit/integration test, dokumentasi yang relevan, dan quality gates sudah lulus. Quality gates minimum adalah:

```bash
cargo fmt --all -- --check
git diff --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
bash -n install.sh
```

Untuk perubahan behavior, acceptance test harus membuktikan bahwa mode normal tetap memfilter placeholder sesuai kontrak, mode `--exhaustive` tetap merupakan superset normal, binary scanning tetap aktif secara default, object verification tetap aktif secara default, dan `--partial-exposure` tetap opt-in. Test tidak boleh memakai credential-shaped literal yang terlihat seperti kredensial nyata; gunakan fixture sintetis yang dibangun saat runtime.

---

# Roadmap refresh setelah full functionality audit

Audit penuh terhadap `origin/main` mengubah urutan kerja berikutnya. Implementasi baru harus dimulai dari correctness boundary provider, karena kesalahan scope atau branch dapat membuat hasil scan terlihat valid tetapi merepresentasikan content yang salah. Setelah boundary tersebut stabil, pekerjaan berlanjut ke policy parity, acquisition/archive depth, history/report parity, stage-aware performance, dan release engineering.

| Gelombang baru | Fokus | Item utama | Status |
|---|---|---|---|
| A | Provider correctness dan coverage integrity | Azure project scoping, branch/ref, auth; GitLab nested namespace dan tree pagination | DONE |
| B | Cross-mode operator control | False-positive keyword parity; provider-aware token target; repository/project selectors | IN PROGRESS |
| C | Acquisition dan content depth | Streaming size enforcement; typed invalid archive reasons; tar/compressed-tar; archive corpus | TODO |
| D | History dan report parity | Provider history capability; deleted-content coverage; SARIF/NDJSON/CSV/Markdown/HTML metadata | TODO |
| E | Performance dan resource control | Stage-aware budget; queue/concurrency telemetry; cold/warm cache benchmark; retry/transport consistency | TODO |
| F | Release dan maintainability | Provider contract matrix; cross-platform CI; provenance/SBOM; incremental core extraction | TODO |

## Acceptance contract untuk roadmap baru

Setiap item baru wajib menyatakan scope provider/mode yang benar-benar diuji, termasuk perilaku unsupported. Pagination harus exhaust sampai provider menyatakan tidak ada halaman berikutnya atau limit typed tercapai. Branch/ref harus diteruskan secara eksplisit ke endpoint. Error authentication, invalid archive, resource denial, dan incomplete history harus terlihat pada outcome atau telemetry. Perubahan pada policy harus memiliki parity test URL, local, dan forge bila capability tersedia.

### Item baru P0-06 — Azure DevOps provider correctness

**Status:** `DONE` — merged via PR #33 (`b96fc0fd`); post-merge CI run `32665876034` passed
**Dependensi:** P0-04, P1-06
**Area:** `src/azure_api.rs`, `src/forge_scan.rs`, provider mock tests

Perbaiki enumerasi repository agar benar-benar project-scoped, teruskan branch/ref ke Items API, dan hilangkan synthetic identity fallback pada `whoami` untuk authentication failure; `authenticate` sudah menolak 401/403, tetapi fallback non-OK dan on-premise validation masih perlu dipersempit. Pertahankan pagination, redaction, retry telemetry, serta snapshot capability contract.

### Implementasi P0-06 (sub-bagian Azure boundary correctness)

Azure repository listing sekarang menggunakan project-scoped API base dan mengikuti `x-ms-continuationtoken` tanpa menggabungkan repository dari project lain. Azure Items traversal meneruskan branch melalui `versionDescriptor.version` dan `versionDescriptor.versionType=branch` pada setiap directory request serta meng-encode path/query secara eksplisit. `whoami` hanya mengizinkan synthetic identity untuk 404 pada endpoint profile di Azure DevOps Server/on-premise; 401/403 dan status lain menjadi error, sedangkan on-premise validation juga menolak status non-2xx. Regression fixtures mencakup project path, continuation page, branch name dengan slash, identity success, dan 401/403 failure. P0-06 selesai pada boundary correctness yang ditetapkan; provider contract matrix lintas provider tetap menjadi pekerjaan P3-08.

**Acceptance criteria:** Dua project dengan repository berbeda tidak saling tertukar; dua branch menghasilkan tree berbeda sesuai ref; 401/403 pada authenticate maupun whoami menjadi authentication failure typed; fallback 404 hanya berlaku pada on-premise contract yang terdokumentasi; fixture pagination dan empty-project cases tercakup; tidak ada repository yang hilang tanpa outcome.

### Item baru P0-07 — GitLab namespace dan tree completeness

**Status:** `DONE` — merged via PR #34 (`f012e0df`); post-merge CI run `32667495205` passed
**Dependensi:** P0-04, P1-06
**Area:** `src/gitlab_api.rs`, provider mock tests

Pertahankan full nested namespace GitLab saat membentuk project identity dan ikuti pagination pada setiap directory tree request. History path-based behavior dan keterbatasan deleted blob harus tetap dilaporkan secara eksplisit.

### Implementasi P0-07 (sub-bagian namespace dan tree completeness)

GitLab project parsing sekarang memisahkan namespace dari nama repository pada slash terakhir, sehingga `group/subgroup/repository` tetap dapat digunakan sebagai project path penuh. Directory tree requests meneruskan branch yang di-encode, meminta `per_page=100`, dan mengikuti `x-next-page`; Link header `rel="next"` menjadi fallback bila tersedia. Stale, malformed, atau non-advancing continuation tidak menyebabkan loop. Regression fixtures mencakup nested namespace, dua halaman tree, encoded project path, branch query, provider header, Link fallback, serta stale/malformed page values. History path-based retrieval dan batas deleted-content tetap tidak diubah. P0-07 selesai melalui PR #34 (`f012e0df`) dengan post-merge CI run `32667495205` yang sukses.

**Acceptance criteria:** `group/subgroup/repository` dapat di-address dengan benar; directory yang melampaui satu halaman seluruhnya dipindai; empty page dan malformed pagination header tidak menyebabkan loop; history deleted-path coverage tetap dibedakan dari deleted-content scanning.

### Item baru P1-09 — Cross-mode false-positive policy parity

**Status:** `DONE` — merged via PR #35 (`0c3f04c1`); post-merge CI run `32669132214` passed
**Dependensi:** P1-01, P2-03
**Area:** `src/content_scanner.rs`, `src/dir_pipeline.rs`, `src/forge_scan.rs`, `src/main.rs`

Teruskan `--false-positive-keywords` melalui local directory dan forge workspace scanner, bukan hanya URL object path. Gunakan immutable typed configuration dan pastikan normal/exhaustive semantics identik pada setiap mode.

**Acceptance criteria:** Fixture yang sama menghasilkan suppression yang sama di URL, local, dan forge snapshot; tanpa keywords default behavior tidak berubah; exhaustive tetap superset normal; binary/archive/custom pattern paths tidak ikut terfilter secara tidak sengaja.

### Implementasi P1-09

`--false-positive-keywords` sekarang diparsing melalui satu helper canonical dan diteruskan ke local directory serta forge snapshot/history melalui immutable scan configuration. URL, local, dan forge memakai fixture sintetis yang sama pada policy normal dan exhaustive; binary/archive paths tetap menerima scanner tanpa filtering keyword text. PR #35 (`0c3f04c1`) dan post-merge CI run `32669132214` selesai sukses dengan 613 unit test Rust lulus.
### Item baru P1-10 — Provider-aware token target schema dan selectors

**Status:** `TODO`
**Dependensi:** P0-05, P1-06
**Area:** `src/targets.rs`, `src/main.rs`, provider adapters, report outcome

Perluas target-file token entry dengan provider discriminator yang backward-compatible terhadap GitHub shorthand. Tambahkan selector repository/project/group yang dapat dipakai dalam mode non-interactive dan menghasilkan scope report yang deterministic serta redacted.

**Acceptance criteria:** Target file dapat mengekspresikan GitHub, GitLab, Bitbucket, Gitea, dan Azure secara eksplisit; token tidak muncul pada target label/error; selector exact dan glob tervalidasi; unsupported provider/selector menghasilkan error typed; selected scope tersimpan di report.

### Item baru P1-11 — Bounded acquisition size

**Status:** `TODO`
**Dependensi:** P1-07, P1-08
**Area:** `src/http_client.rs`, `src/object_source.rs`, `src/object_worker.rs`

Pisahkan batas ukuran response acquisition dari batas ukuran scan dan gunakan streaming body limit agar response oversized tidak selalu dialokasikan penuh terlebih dahulu. Pertahankan pack/cache/loose precedence dan typed `Oversized` telemetry.

**Acceptance criteria:** Content-Length yang besar ditolak sebelum body penuh; response tanpa Content-Length tetap dibatasi saat streaming; save/non-save memiliki contract yang terdokumentasi; cache tidak menyimpan oversized atau invalid object; regression fixture mencakup truncation dan retry interaction.

### Item baru P1-12 — Archive format and invalid-reason depth

**Status:** `TODO`
**Dependensi:** P1-05, P1-08
**Area:** `src/binary_scanner.rs`, `src/content_scanner.rs`, archive corpus tests

Tambahkan typed invalid-archive reason dan perluas parity ke tar/compressed-tar bila dependency dan resource model mendukung. Raw printable-string fallback harus tetap tersedia ketika format parsing gagal; `--exhaustive` tidak menghapus archive limits.

**Acceptance criteria:** Malformed, traversal, depth, entry-count, expansion-size, ratio, dan unsupported-format states dapat dibedakan; ZIP/JAR/GZIP behavior tidak regress; custom patterns tetap aktif pada archive views; corpus regression berjalan deterministic.

### Item baru P2-08 — Report-format telemetry parity

**Status:** `TODO`
**Dependensi:** P3-04, P1-05
**Area:** `src/reporter.rs`, schema tests, documentation

Tambahkan additive scan-level metadata ke SARIF run properties dan format lain melalui contract yang tidak merusak consumer finding-only. NDJSON membutuhkan reserved metadata record; CSV membutuhkan envelope/sidecar yang terdokumentasi; Markdown/HTML mendapat summary operasional.

**Acceptance criteria:** Existing finding fields dan row consumers tetap valid; telemetry memuat scope, capability, source, skip/failure/truncation, cache/retry/resource summary; schema tests mencakup setiap format; tidak ada secret plaintext tambahan.

### Item baru P2-09 — Stage-aware resource and scheduler telemetry

**Status:** `TODO`
**Dependensi:** P1-08, P3-04, P3-05
**Area:** `src/resource_budget.rs`, `src/scan_scheduler.rs`, `src/stream_types.rs`, benchmark tools

Perluas resource stages dari ObjectScan ke acquisition, decompression/archive, file scan, workspace reconstruction, dan target fan-out. Expose configured/current/peak concurrency, queue wait, active permits, adjustment/throttle events, dan denied reservations.

**Acceptance criteria:** Cancellation me-release reservation pada setiap stage; exhaustive tetap bounded; report membedakan resource denial dari clean result; benchmark dapat membandingkan throughput, peak RSS, queue wait, dan cache/retry behavior tanpa wall-clock threshold naif.

### Item baru P2-10 — Shared date-aware transport parsing

**Status:** `TODO`
**Dependensi:** P0-04, P2-04
**Area:** `src/provider_transport.rs`, `src/http_client.rs`, provider adapters

Satukan parsing numeric dan HTTP-date `Retry-After` dengan clock-safe tests, sementara reset semantics tetap provider-specific. Retry telemetry harus membedakan status retryable, terminal failure, network error, dan exhausted retry.

**Acceptance criteria:** Numeric/date header menghasilkan delay yang bounded dan deterministic; malformed date memakai fallback documented; semua built-in provider memakai helper yang sama kecuali override yang beralasan; existing retry policy tidak berubah tanpa test evidence.

### Item baru P3-07 — Cross-platform quality matrix

**Status:** `TODO`
**Dependensi:** P3-01, P3-03
**Area:** `.github/workflows/`, `Cargo.toml`, installer

Tambahkan compile/test matrix untuk Linux x86_64, Linux ARM64, macOS, dan Windows-compatible paths sesuai dukungan aktual. Validasi SARIF, archive corpus, provider mocks, source fallback installer, dan lockfile di CI.

### Item baru P3-08 — Provider contract test matrix

**Status:** `TODO`
**Dependensi:** P0-06, P0-07, P1-06
**Area:** `tests/`, provider modules, mock server harness

Bangun fixture contract reusable untuk auth, pagination, branch/ref, tree/blob, rate-limit, retry, unsupported capability, and deleted-content states pada seluruh provider. Tujuannya adalah parity yang dapat diukur, bukan menyamakan capability yang memang berbeda.

### Item baru P3-09 — Reproducible release provenance

**Status:** `TODO`
**Dependensi:** P3-01, P3-02, P3-07
**Area:** release workflow, `install.sh`, documentation

Lengkapi multi-platform release dengan reproducible build metadata, SBOM/provenance, checksum verification, dan source-fallback contract. Release asset tidak boleh diterbitkan sebelum binary, source commit, platform tag, dan checksum dapat diaudit.

---

# P0 — Correctness sebelum fitur baru

## P0-01 — Lengkapi state checkpoint dan resume equivalence

**Status:** `DONE` — commit `16ad6ade`
**Dependensi:** tidak ada
**Area:** `src/checkpoint.rs`, `src/streamer.rs`, `tests/checkpoint_resume.rs`

Checkpoint saat ini memulihkan processed SHA dan findings, tetapi belum memulihkan seluruh aggregate state. Tambahkan snapshot accumulator yang mencakup contributors, technology stack, commit count, blobs scanned, bytes scanned, files saved, source distribution, skip/failure outcomes, cache/rate metrics yang relevan, cancellation state, dan coverage metadata. Naikkan schema version secara backward-compatible; checkpoint legacy tetap dapat dibaca dengan fallback yang terdokumentasi.

### Acceptance criteria

- Scan one-shot dan scan interrupted-plus-resumed menghasilkan findings serta seluruh summary aggregate yang ekuivalen.
- Processed SHA selalu disimpan dalam urutan deterministik, termasuk final checkpoint.
- Resume dengan konfigurasi berbeda tetap ditolak atau memulai fresh stream sesuai kontrak snapshot.
- Checkpoint lama tanpa accumulator masih dapat dibaca tanpa panic dan menghasilkan warning yang jelas.
- Checkpoint tidak menyimpan blob plaintext selain matched values yang memang sudah menjadi kontrak finding continuity.
- Ditambahkan integration test yang membandingkan JSON report one-shot dengan report resumed setelah interruption sintetis.

## P0-02 — Perbaiki object verification untuk bare/no-index repository

**Status:** `DONE` — commit `f9b7d1c1`
**Dependensi:** tidak ada
**Area:** `src/mapper.rs`, `src/object_source.rs`, `tests/`

Verification tidak boleh hanya bergantung pada `index_entries`. Candidate verification harus mencakup union object yang ditemukan dari index, commit graph, pack enumeration, refs, dan metadata. Bedakan `no_candidates`, `verified`, `partially_verified`, dan `verification_failed` secara typed agar bare repository tidak salah dianggap inaccessible.

### Acceptance criteria

- Bare/no-index repository dengan object yang dapat diambil diklasifikasikan benar.
- Pack-only repository tetap diverifikasi melalui pack source.
- Repository benar-benar tidak accessible tetap menghasilkan failure yang dapat dijelaskan.
- Sampling tetap bounded dan tidak mengorbankan exhaustive discovery.
- Report mencantumkan candidate count, sampled count, accessible count, dan verification reason.
- Ditambahkan regression test untuk index-only, graph-only, pack-only, invalid-object, dan empty-candidate cases.

## P0-03 — Benahi kontrak `--dry-run` di seluruh mode

**Status:** `DONE` — implementation validated locally; commit pending in current package
**Dependensi:** tidak ada
**Area:** `src/main.rs`, `src/url_pipeline.rs`, `src/dir_pipeline.rs`, `src/targets.rs`

`--dry-run` saat ini efektif pada URL flow, tetapi directory mode tetap mengumpulkan dan memindai file. Tetapkan kontrak tunggal: dry-run hanya memvalidasi CLI, target, paths, patterns, dan konfigurasi; tidak melakukan network acquisition, file content read, detector execution, report scan result, atau webhook delivery.

### Acceptance criteria

- URL, directory, token, dan `--targets` dry-run tidak memindai content.
- Dry-run tetap dapat memeriksa keberadaan dan bentuk input yang diperlukan tanpa membaca isi file target secara tidak perlu.
- Output dry-run menyebutkan mode, target count, configuration summary, dan tindakan yang dilewati.
- Exit code konsisten untuk input valid dan invalid.
- Ditambahkan CLI integration test untuk seluruh target mode.
- README dan DEVELOPMENT.md diperbarui sesuai perilaku final.

### Implementasi P0-03

Dry-run sekarang berhenti sebelum URL detection, repository reconnaissance, provider authentication, repository enumeration, local file collection, content read, detector execution, report writing, aggregate report writing, dan webhook delivery. Target directory serta target-file entries tetap divalidasi; `--pipe` menghasilkan satu objek JSON `dry_run`. Regression test directory dry-run dan mixed target-file dry-run sudah ditambahkan.

## P0-04 — Validasi input numerik dan perbaiki semantics retry/HTTP

**Status:** `DONE` — implementation validated locally; commit pending in current package
**Dependensi:** tidak ada
**Area:** `src/main.rs`, `src/http_client.rs`, `src/rate_limiter.rs`

Tambahkan validator finite dan non-negative untuk `delay`, `jitter`, `entropy-threshold`, serta `rate` sesuai semantics masing-masing. Saat ini `--delay NaN` dan `--delay inf` dapat menyebabkan panic pada `Duration::from_secs_f64`. Selaraskan pula `--retries 0`, `Response::ok()`, dan retry metrics.

### Acceptance criteria

- NaN, positive infinity, negative infinity, dan nilai negatif ditolak dengan error CLI yang terkontrol.
- `--retries 0` benar-benar berarti tanpa retry, atau parser menolak nilai 0 dengan pesan yang konsisten.
- `Response::ok()` dan retry loop memakai definisi 2xx yang sama.
- Metrics membedakan request attempts, retries, terminal failures, dan status counts.
- POST dan GET memiliki policy retry yang eksplisit; webhook non-idempotent tidak diam-diam diduplikasi tanpa policy.
- Ditambahkan tests untuk 0, boundary values, NaN/inf, 2xx, 4xx, 429, dan 5xx.

### Implementasi P0-04

`--delay` dan `--jitter` kini wajib finite dalam rentang 0–3.600 detik; `--entropy-threshold` wajib finite dan non-negative; `--rate` wajib finite dalam rentang 0–1.000.000 requests/second dengan 0 berarti unlimited. `Response::ok()` kini menerima seluruh status 2xx. `--retries 0` melakukan request awal tanpa retry pada GET maupun POST. Regression tests mencakup NaN, infinity, nilai negatif, boundary values, zero retry, dan seluruh rentang 2xx.

## P0-05 — Ganti process exit pada helper reusable dengan typed errors

**Status:** `DONE` — implementation validated locally; commit pending in current package
**Dependensi:** P2-02 bila dilakukan bersamaan dengan core extraction
**Area:** `src/target_utils.rs`, `src/validation.rs`, `src/outcome.rs`

`normalize_url` dan `parse_extra_headers` tidak boleh memanggil `std::process::exit` dari helper reusable. Kembalikan `Result` dengan error typed; hanya boundary CLI yang menentukan exit code. Pertahankan redaction pada URL, token, header, dan error message.

### Acceptance criteria

- Tidak ada process exit di helper domain yang dipanggil oleh core logic.
- Invalid URL/header dapat diuji langsung sebagai `Result`.
- Aggregate target mode dapat melaporkan error per target tanpa mematikan seluruh process secara prematur.
- Exit code CLI tetap kompatibel pada jalur command-line utama.

### Implementasi P0-05

`normalize_url` dan `parse_extra_headers` kini mengembalikan `anyhow::Result` dan tidak lagi menghentikan process dari helper reusable. `targets::load_targets` meneruskan error typed ke caller, sedangkan exit tetap dilakukan hanya pada CLI boundary. Unit tests memastikan URL/header invalid dapat diuji sebagai error dan behavior CLI utama tetap kompatibel.

---

# P1 — Universal scanner dan offensive coverage

## P1-01 — Ekstrak `ContentScanner` dan `ScanAccumulator`

**Status:** `DONE` — implementation validated locally; commit pending in current package
**Dependensi:** P0-01, P0-03
**Area:** `src/streamer.rs`, `src/dir_pipeline.rs`, `src/forge_scan.rs`, `src/scanner_factory.rs`

Buat scanner engine bersama yang menerima `ContentView` dan policy. `ContentView` minimal mencakup text, printable binary strings, SQLite content, archive entries, GZIP payload, ELF sections, commit message, dan tree metadata. `ScanAccumulator` harus menjadi satu-satunya pemilik aggregation logic untuk findings, contributors, tech stack, source, outcomes, bytes, limits, dan timing.

### Acceptance criteria

- URL, local, dan forge mode memakai engine dan accumulator yang sama.
- Stop conditions, cancellation, maximum findings, exhaustive policy, and metrics tidak diduplikasi di tiga pipeline.
- Report schema tetap backward-compatible kecuali field baru ditambahkan secara additive.
- Unit test dapat memanggil core scanner tanpa menjalankan CLI process.
- Local, URL, dan forge fixture yang setara menghasilkan policy dan result shape yang konsisten.

### Implementasi P1-01

Modul `src/content_scanner.rs` sekarang menyediakan shared `ContentScanner`, `ContentScanOutcome`, `ScanAccumulator`, dan stop policy. Local directory serta forge workspace scanning memakai text/binary policy dan accumulator yang sama; URL streamer memakai adapter text yang sama dengan object SHA, deleted-state, false-positive context, dan exhaustive policy tetap terjaga. Regression tests mencakup normal-versus-exhaustive policy, binary opt-out accounting, accumulator metrics, stop limits, object provenance, dan existing local scan behavior.

## P1-02 — Satukan detector registry untuk text, binary, dan archive

**Status:** `DONE`
**Dependensi:** P1-01
**Area:** `src/binary_scanner.rs`, `src/binary_adapter.rs`, `src/streamer.rs`, `src/scanner_policy.rs`

Custom patterns saat ini hanya mengalir ke text detector. Pindahkan detector menjadi registry/pipeline bersama sehingga `DynPattern`, severity, description, false-positive context, placeholder policy, dan exhaustive behavior berlaku juga pada printable strings, archive entries, GZIP, SQLite, dan ELF sections.

### Acceptance criteria

- Custom pattern yang sama terdeteksi pada text, binary printable strings, archive entry, dan decompressed GZIP content.
- Severity serta description tidak lagi hardcode menjadi `HIGH` pada adapter.
- Normal mode memfilter placeholder sesuai policy; exhaustive mode mempertahankan candidate tersebut.
- Finding menyimpan source view, logical path, object SHA bila tersedia, dan context yang jelas.
- Ditambahkan parity tests untuk setiap content view.

### Implementasi P1-02

`scan_binary_blob_with_patterns` sekarang mempertahankan built-in detectors sambil mengevaluasi `DynPattern` pada printable strings dan seluruh view binary yang telah didukung: archive ZIP/JAR, GZIP payload, SQLite strings, ELF strings, dan unknown binary. Adapter binary serta URL normalizer mempertahankan severity, description, source context, object SHA, dan deleted-state; filtering placeholder tetap normal-mode dan `--exhaustive` tetap superset. Regression coverage mencakup metadata adapter, provenance, local CLI binary scan, dan normal-versus-exhaustive policy. P1-03 tetap diperlukan untuk mengganti null-byte gate dengan magic-byte plus extension fallback; sparse GZIP yang belum masuk binary dispatch bukan bagian dari P1-02.

## P1-03 — Ganti null-byte gate dengan magic-byte plus extension fallback

**Status:** `DONE`
**Dependensi:** P1-01
**Area:** `src/dir_pipeline.rs`, `src/streamer.rs`, `src/binary_adapter.rs`

Null-byte heuristic tetap dapat dipakai sebagai signal, tetapi tidak boleh menjadi satu-satunya pintu masuk. Gunakan magic-byte detection untuk SQLite, ZIP/JAR, GZIP, ELF, dan format yang didukung; gunakan extension sebagai fallback dan catat confidence. Unknown binary tetap diproses melalui printable-string scanner jika policy mengizinkan.

### Acceptance criteria

- GZIP dengan sparse null bytes tetap dipindai.
- ZIP/JAR tanpa lebih dari 10 null bytes tetap dikenali dari magic bytes.
- Unknown binary tidak otomatis dibuang tanpa typed reason.
- `--no-scan-binaries` tetap menjadi opt-out yang jelas.
- Ditambahkan boundary tests untuk files exactly-at-threshold, truncated headers, and unknown binary.

### Implementasi P1-03

`BinaryDispatch` sekarang dipakai oleh local dan URL pipeline dengan urutan magic bytes, extension fallback, lalu null-byte heuristic. SQLite, ZIP/JAR, GZIP, dan ELF tidak lagi bergantung pada lebih dari 10 null bytes untuk masuk ke binary scanner; unknown binary tetap diproses melalui printable-string fallback dengan confidence yang typed. Regression tests mencakup sparse GZIP end-to-end, ZIP magic priority, extension fallback, truncated header, exact threshold, dan unknown binary. Forge mode tetap belum diubah karena parity binary forge adalah scope P1-04.

## P1-04 — Pulihkan binary/archive parity pada forge mode

**Status:** `IN PROGRESS`
**Dependensi:** P1-01, P1-02, P1-03
**Area:** `src/forge_scan.rs`, `src/forge.rs`, provider modules

Forge mode tidak boleh memfilter binary sebelum scanner menerima data. Pertahankan workspace reconstruction untuk `--save`, tetapi gunakan scanner engine yang sama untuk content bytes dan file path. Source metrics, typed outcomes, cache semantics, dan report fields harus konsisten dengan URL/local mode.

### Acceptance criteria

- Forge snapshot scan mendeteksi binary/archive findings dengan rules yang sama seperti local scan.
- Custom pattern binary berlaku pada forge mode.
- `object_source_stats`, `outcome_stats`, cache, and rate metrics tidak lagi selalu zero tanpa penjelasan.
- Malformed, oversized, skipped, dan failed file memiliki outcome terstruktur.
- Ditambahkan forge-vs-local parity integration test menggunakan provider mock.

### Implementasi P1-04 (sub-bagian binary/archive parity)

Forge workspace snapshots sekarang tidak lagi memfilter file binary berdasarkan ekstensi atau null-byte count sebelum scanner menerima bytes. `FileScanConfig` meneruskan `--no-scan-binaries`, dan shared `ContentScanner` memakai `BinaryDispatch` serta detector registry yang sama dengan local mode. `ObjectSourceStats.forge` menandai blob hasil rekonstruksi forge, sedangkan `ScanOutcomeStats` mencatat file kosong, oversized, invalid, stop-requested, dan failed. Regression test membuktikan custom finding pada text dan ZIP archive, termasuk severity, description, archive provenance, byte count, typed outcomes, dan opt-out wiring. Pekerjaan P1-04 yang tersisa adalah cache/rate-limit telemetry acquisition yang berasal dari provider, error/status classification yang lebih rinci, dan provider-mock integration parity penuh.

## P1-05 — Tambahkan archive limits dan typed truncation outcomes

**Status:** `IN PROGRESS`
**Dependensi:** P1-02, P1-03
**Area:** `src/binary_scanner.rs`, `src/content_scanner.rs`, `src/streamer.rs`, `src/checkpoint.rs`, `src/reporter.rs`

Pertahankan bounded extraction, tetapi ubah silent truncation menjadi telemetry. Tambahkan maximum nested archive depth, maximum extracted entries, per-entry bytes, total expanded bytes, and decompression ratio guard. Limit yang menghentikan coverage harus tampil pada report.

### Acceptance criteria

- Nested archive recursion selalu bounded oleh depth dan total resource budget.
- ZIP/GZIP/SQLite malformed input tidak panic.
- Report membedakan complete scan, truncated scan, oversized entry, invalid archive, dan decompression limit.
- Exhaustive mode tidak menghapus limits resource; exhaustive berarti coverage policy, bukan unlimited memory.

### Implementasi P1-05 (sub-bagian typed archive limits)

ZIP/JAR extraction sekarang memiliki telemetry typed untuk batas jumlah entry, oversized per-file/total budget, dan nested archive depth. GZIP decompression membedakan payload malformed dari output yang melewati batas. `ContentScanner`, forge snapshot outcomes, terminal output, JSON reports, dan stream checkpoints mempertahankan `archive_truncated` secara additive. Regression tests menggunakan fixture kecil untuk entry-count, total/per-file size, malformed/oversized GZIP, expansion-ratio, nested-depth, checkpoint round-trip, dan provider/local scan paths. Pekerjaan yang tersisa adalah klasifikasi invalid archive yang lebih rinci dan meneruskan telemetry ke URL binary normalization agar semua pipeline memiliki outcome detail yang identik.

## P1-06 — Definisikan capability dan history mode untuk forge

**Status:** `IN PROGRESS`
**Dependensi:** P1-01, P1-04
**Area:** `src/forge.rs`, `src/forge_factory.rs`, `src/*_api.rs`, `src/forge_scan.rs`, `src/main.rs`, `src/outcome.rs`

Dokumentasikan dan modelkan perbedaan `snapshot` versus `history` scan. Tambahkan capability discovery untuk branches, tags, commits, deleted blobs, and provider-specific history support. Implementasikan history mode bertahap, dimulai dari GitHub dan GitLab, tanpa mengklaim parity sebelum coverage benar-benar tersedia.

### Acceptance criteria

- Report selalu menyatakan `scan_scope=snapshot|history` dan capability yang tidak tersedia.
- Snapshot mode tetap cepat dan backward-compatible.
- History mode memiliki bounded traversal, deduplication, deleted-path mapping, and coverage metrics.
- Provider yang belum mendukung history mengembalikan typed `unsupported_capability`, bukan silent success.
- README usage examples membedakan snapshot dan history.

### Implementasi P1-06 (scope dan capability foundation)

`ForgeScanScope` sekarang memodelkan `snapshot` dan `history`, dengan `--scan-scope snapshot` sebagai default yang backward-compatible. Trait `Forge` memiliki capability contract, revision-aware blob retrieval, dan typed `ForgeHistory`. GitHub mengimplementasikan bounded commit pagination, changed-path status mapping, blob SHA retrieval, rename provenance, deduplication, deleted-path scanning, dan coverage counters. GitLab mengimplementasikan bounded commit pagination, commit-diff status mapping, rename provenance, path-at-commit retrieval, serta coverage counters; deleted paths tetap dipetakan tetapi tidak dapat dipindai bila API tidak menyediakan historical blob address. Forge reports menyimpan `scan_scope`, capability map, history coverage, dan `unsupported_capability`; provider snapshot-only tidak lagi menjadi silent success. Branch/tag capability discovery, provider lain, dan parity deleted-blob lintas provider masih menjadi pekerjaan roadmap.

## P1-07 — Bangun deterministic remote acquisition test harness

**Status:** `IN PROGRESS`
**Dependensi:** P1-01
**Area:** `tests/`, `src/object_source.rs`, `src/http_client.rs`, `tools/`

Buat local HTTP fixture server untuk menguji pack, cache, loose object, invalid object, 404, oversized response, 429, 5xx, retry-after, and cancellation. Harness harus menghasilkan source/outcome metrics yang dapat dibandingkan secara deterministic.

### Acceptance criteria

- Precedence pack → cache → loose HTTP teruji.
- Object verification menolak response invalid dan menerima valid canonical object.
- Cache hit/miss serta source provenance muncul benar di JSON report.
- Retry attempts, terminal failures, cancellation, and response caps dapat diverifikasi tanpa internet.
- Benchmark dapat menghasilkan JSON output dan menjalankan fixture yang sama di CI.

### Implementasi P1-07 (sub-bagian acquisition fixture dan metrics)

`ObjectSource` sekarang memiliki contract coverage deterministic untuk precedence pack → cache → loose HTTP, cache write-back hanya untuk canonical Git object yang lolos verifikasi, invalid loose object yang tidak masuk cache, 429 retry, 404, dan response-size cap. `ObjectCache::new_at_path` memungkinkan SQLite fixture terisolasi tanpa mengubah lokasi cache produksi. `tools/benchmark_remote_acquisition.py` membuat repository Git sementara, menyajikannya melalui localhost, menjalankan release binary, memvalidasi object acquisition, dan menghasilkan JSON source/outcome/timing metrics. Harness tidak memakai network eksternal atau credential-shaped fixture. Pekerjaan tersisa adalah memperluas fixture black-box menjadi skenario pack/cache/cancellation/resume yang dapat dijalankan konsisten di CI.

## P1-08 — Bangun global resource budget

**Status:** `IN PROGRESS`
**Dependensi:** P1-01, P1-05, P1-07
**Area:** `src/streamer.rs`, `src/pack_reader.rs`, `src/binary_scanner.rs`, `src/http_client.rs`

`--mem-limit` harus mencakup acquisition buffer, pack bytes, inflated object, archive expansion, GZIP decompression, detector buffers, dan report accumulator. Buat `ResourceBudget` shared dengan reserve/release yang aman terhadap cancellation.

### Acceptance criteria

- Peak memory-sensitive allocations tercatat per stage.
- Pack besar tidak dapat melewati budget hanya karena budget scanner belum aktif.
- Archive/decompression limits memakai budget yang sama.
- Cancellation selalu me-release reservation.
- Report menjelaskan objek yang dilewati karena memory budget, bukan menyamarkannya sebagai clean scan.

### Implementasi P1-08 (sub-bagian shared object-scan budget)

`ResourceBudget` sekarang menyediakan reservasi atomik lintas worker dengan RAII release yang aman terhadap early return dan cancellation. URL streamer mengganti raw blob budget guard dengan shared budget, mencatat peak bytes dan denied reservations, serta mengembalikan `skipped_resource_budget` typed ketika reservation gagal; checkpoint accumulator mempertahankan counter tersebut secara backward-compatible. Semantics existing tetap dipertahankan: `--mem-limit 0` berarti unlimited, batas `--max-blob-size` dan archive tetap aktif, dan `--exhaustive` tidak menonaktifkan resource limits. Integrasi acquisition buffer, pack storage, archive expansion, decompression, dan report accumulator masih menjadi pekerjaan lanjutan P1-08.

---

# P2 — Modularisasi dan maintainability

## P2-01 — Ekstrak core library dari binary-only crate

**Status:** `IN PROGRESS`
**Dependensi:** P0 selesai, P1-01 minimal tersedia
**Area:** `src/lib.rs`, `src/main.rs`, module tree

### Implementasi P2-01 (sub-bagian stream domain models)

Model `Finding`, `Contributor`, `StreamResult`, object-source metrics, outcome metrics, dan cache metrics dipindahkan ke `src/stream_types.rs`. `streamer` tetap me-re-export model tersebut, sehingga reporter, forge scan, dan callers existing tidak mengalami perubahan API atau output. Implementasi behavior-heavy dan orchestration masih berada pada boundary lama untuk menjaga kompatibilitas; pemecahan `main.rs`, worker pipeline, dan resource ownership dilanjutkan bertahap.

Pindahkan domain logic ke `src/lib.rs` atau core crate internal. `main.rs` harus menjadi CLI adapter tipis yang menangani parse args, display, exit code, dan orchestration boundary.

### Acceptance criteria

- Parser, detector, object source, mapper, checkpoint, and reporter core dapat diuji tanpa process invocation.
- `std::process::exit` hanya berada pada CLI boundary.
- Public API internal memiliki ownership dan error contract yang jelas.
- Integration tests dapat memilih library API atau binary sesuai kebutuhan.

## P2-02 — Pecah `streamer.rs` dan `main.rs` berdasarkan domain

**Status:** `IN PROGRESS`
**Dependensi:** P1-01, P2-01
**Area:** `src/streamer.rs`, `src/main.rs`, `src/object_worker.rs`

### Implementasi P2-02 (sub-bagian object worker)

Acquisition, cancellation re-check, typed object-source mapping, dan dispatch ke content processor dipindahkan ke `src/object_worker.rs`. Adaptive concurrency controller dan dynamic semaphore gate dipindahkan ke `src/scan_scheduler.rs`; aggregate `State` serta checkpoint/restore bookkeeping dipindahkan ke `src/scan_accumulator.rs`. `streamer` mempertahankan compatibility re-export dan scheduler call contract. Compatibility seam untuk `WorkerResult`, `SkipReason`, `FailureKind`, `process_blob_content`, dan `attach_source` menjaga checkpoint, reporting, serta semantics `--exhaustive` tetap tidak berubah. Pemisahan checkpoint adapter dan content detector masih menjadi pekerjaan berikutnya setelah boundary ownership memiliki coverage tersendiri.

### Implementasi P2-02 (sub-bagian static pattern dispatch performance)

Static detector registry kini memiliki `RegexSet` selector terkompilasi yang menentukan kandidat pattern sebelum exact regex capture berjalan pada setiap baris teks dan segmen minified. Seluruh `Pattern` tetap berada dalam registry yang sama dan exact regex tetap authoritative; selector ini hanya mengurangi evaluasi regex yang pasti tidak relevan, bukan memfilter hasil atau mengubah urutan pattern. Regression suite streamer tetap lulus lengkap, termasuk exhaustive-superset dan detector-specific coverage. Pada fixture lokal deterministic yang sama (80 files × 300 lines, 3 repetitions), median normal scan berubah dari `0.7347s` pada pre-RegexSet baseline menjadi `0.1590s` pada optimized build (sekitar 78.4% lebih rendah), sedangkan median exhaustive berubah dari `0.7226s` menjadi `0.1590s` (sekitar 78.0% lebih rendah). Angka tersebut hanya perbandingan same-host dan bukan klaim lintas mesin.

Ekstrak domain berikut secara bertahap: `stream_types`, `scan_scheduler`, `content_scanner`, `scan_accumulator`, `stream_checkpoint`, `object_worker`, dan `scanner_factory`. Di `main.rs`, pisahkan command/flow untuk URL, local, targets, dan provider token.

### Acceptance criteria

- Tidak ada perubahan output yang tidak disengaja.
- Setiap extracted module memiliki focused tests.
- `#[allow(clippy::too_many_arguments)]` berkurang melalui typed config/builder.
- Dependency direction tidak berputar: CLI → orchestration → core domains → transport/storage abstractions.

## P2-03 — Ganti positional configuration constructor dengan typed config

**Status:** `IN PROGRESS`
**Dependensi:** P1-01
**Area:** `src/config.rs`, `src/scanner_factory.rs`, `src/streamer_config.rs`

### Implementasi P2-03 (sub-bagian StreamerConfig)

Constructor `Streamer::new` tidak lagi menerima daftar positional arguments yang panjang. `src/streamer_config.rs` menyediakan typed boundary yang dibangun canonical dari `ScanConfig`, sedangkan `scanner_factory` menjadi satu-satunya adapter mapping. Unit conversion, checkpoint snapshot, runtime policy, cache, custom patterns, dan false-positive keywords tetap dipetakan secara eksplisit. Pekerjaan lanjutan adalah mengelompokkan input CLI mentah ke builder tervalidasi di `config.rs` sehingga invalid invariants ditolak sebelum orchestration.

Ganti constructor dengan 16 positional arguments menjadi `ScanConfigBuilder` atau typed `ScanConfigInput`. Kelompokkan policy, resource, transport, output, and checkpoint settings. Validasi invariants saat construction sehingga core menerima konfigurasi yang sudah valid.

### Acceptance criteria

- Compiler membantu mencegah field tertukar.
- Snapshot checkpoint dibangun dari satu canonical config object.
- Config serialization/fingerprint tetap deterministic.
- Existing CLI defaults tetap sama dan memiliki regression test.

## P2-04 — Ekstrak common provider transport

**Status:** `IN PROGRESS`
**Dependensi:** P0-04, P2-01
**Area:** `src/http_client.rs`, `src/forge.rs`, `src/*_api.rs`, `src/provider_transport.rs`

### Implementasi P2-04 (sub-bagian wire-format parsers)

Parser `rel="next"` pada Link header dan numeric `Retry-After` dipindahkan ke `src/provider_transport.rs`. GitHub dan GitLab tetap memiliki thin compatibility wrappers sehingga retry policy, fallback delay, rate-limit reset semantics, endpoint schema, dan provider-specific pagination header tetap berada di adapter masing-masing. Pekerjaan berikutnya adalah common response/error mapping, URL normalization, dan pagination abstraction lintas provider setelah contract coverage diperluas.

Satukan retry, Retry-After, rate-limit header parsing, pagination primitives, URL normalization, response-size policy, dan redacted error handling. Provider modules hanya menangani endpoint serta response schema yang spesifik.

### Acceptance criteria

- Tidak ada lima implementasi rate-limit wrapper yang drift tanpa alasan provider-specific.
- Per-provider behavior tetap dapat mengoverride format header dan pagination.
- Contract tests tetap lulus untuk GitHub, GitLab, Bitbucket, Gitea, dan Azure.
- GitHub API base URL dapat dikonfigurasi untuk GitHub Enterprise atau compatibility endpoint bila provider contract mendukungnya.

## P2-05 — Perkenalkan typed error taxonomy

**Status:** `IN PROGRESS`
**Dependensi:** P0-04, P2-04
**Area:** `src/outcome.rs`, `src/forge.rs`, `src/http_client.rs`, `src/mapper.rs`

### Implementasi P2-05 (sub-bagian classification metadata)

`outcome.rs` kini memiliki `ErrorMetadata` dan `ErrorStage` internal yang mengklasifikasikan capability, authentication, transport, dan scan errors, serta mengekstrak HTTP status dan retryability secara deterministic. `TargetErrorCode` tetap menjadi report contract yang sama dan `classify_error` mempertahankan behavior existing. Migrasi typed metadata ke provider/mapper error boundary, redacted target/source context, dan report serialization dilakukan bertahap setelah contract surface stabil.

Buat error type yang membawa stage, provider, HTTP status, retryability, redacted target, and source context. `TargetErrorCode` menjadi mapping report boundary, bukan hasil parsing substring dari error message.

### Acceptance criteria

- Error classification tidak bergantung pada substring bahasa manusia.
- Retry decision dapat diuji dari typed properties.
- Per-target aggregate report tetap deterministic.
- Secret/token/authorization material tidak masuk ke error output.

## P2-06 — Perbaiki cache semantics dan lifecycle

**Status:** `IN PROGRESS`
**Dependensi:** P1-07, P1-08
**Area:** `src/cache.rs`, `src/object_source.rs`, README, DEVELOPMENT.md

Pilih dan implementasikan semantics yang benar-benar diinginkan: update access timestamp untuk LRU, atau ubah dokumentasi menjadi oldest-inserted eviction. Tambahkan cleanup policy, inspect/stats command, eviction telemetry, dan handling expired entry yang eksplisit.

### Implementasi P2-06 (sub-bagian lifecycle dan integrity quarantine)

Cache-enabled scan sekarang membersihkan entry TTL-expired pada awal scan, dengan TTL `0` tetap berarti permanent dan tidak ikut dibersihkan. Cache hit untuk namespace `raw-object-v1:<sha1>` wajib lolos parsing canonical loose Git object serta verifikasi SHA-1 sebelum digunakan; entry invalid/corrupt dihapus secara transactional dengan pembaruan `cache_meta.total_bytes`, lalu acquisition tetap jatuh ke loose HTTP. Object HTTP yang valid kembali di-cache, sehingga corruption tidak memblokir coverage dan source precedence tetap pack → valid cache → loose HTTP. Eviction saat batas byte terlampaui kini secara eksplisit memakai oldest-inserted order (`created_at`, lalu `rowid` sebagai tie-break), bukan LRU karena cache hit tidak memperbarui access timestamp. Setiap pooled SQLite connection memiliki busy timeout, sedangkan cache put dan per-key removal memakai immediate transaction agar concurrent writer/invalidation tidak kehilangan entry atau mengurangi metadata lebih dari sekali. Regression tests mencakup metadata removal/idempotence, cache hit canonical, quarantine, fallback, cache miss/hit accounting, re-admission object hasil recovery, 32 concurrent puts, 8 concurrent removals atas key yang sama, serta eviction threshold dengan counter entry/byte. Cache report dan terminal summary kini menampilkan cumulative `evicted_entries` serta `evicted_bytes` secara additive. `--cache-stats` menyediakan inspect surface standalone tanpa target, dengan JSON melalui `--pipe` dan no-I/O disabled path melalui `--no-cache`. Seluruh lifecycle API (`get`, `put`, `remove`, `cleanup_expired`, dan `stats`) short-circuit saat cache disabled; constructor disabled memakai in-memory pool dan tidak membuat file SQLite. Cleanup TTL juga memakai immediate transaction, dan regression campuran memvalidasi 8 cleanup concurrent bersama 8 per-key invalidation tanpa double-subtraction metadata. Pekerjaan tersisa: observability stress test yang lebih luas bila dibutuhkan oleh telemetry production.

### Acceptance criteria

- Dokumentasi tidak lagi menyebut LRU bila implementasi tidak memperbarui access time.
- Cache tetap bounded pada entry count/bytes dan cleanup tidak merusak size accounting.
- Cache hit/miss/eviction/expiration dapat diuji.
- `--no-cache` benar-benar melewati seluruh cache I/O.

## P2-07 — Kurangi dead-code allowances dan hapus jalur obsolete

**Status:** `IN PROGRESS`
**Dependensi:** P2-01, P2-02
**Area:** seluruh `src/`

### Implementasi P2-07 (sub-bagian shared helper)

`CacheStats::hit_rate` sekarang dipakai langsung oleh reporter sehingga perhitungan hit-rate tidak diduplikasi dan suppression `dead_code` pada helper tersebut telah dihapus. `ObjectCache::clear` kini memiliki no-cache short-circuit dan dipakai oleh command standalone `--cache-clear`, dengan regression path pipe yang tidak memerlukan target. `StreamResult::blobs_failed` kini ditampilkan pada terminal summary ketika non-zero sehingga field suppression-nya dapat dihapus tanpa mengurangi telemetry. Rate-limit counters (`allowed`, `dropped`, `wait_ms`) juga ditampilkan secara kondisional pada terminal summary sehingga tiga suppression field terkait dapat dihapus tanpa mengubah metrik. `TempDirGuard` tidak lagi membawa flag registration yang tidak pernah dibaca atau menyediakan no-op `register`; constructor tetap mendaftarkan path ke signal registry, sementara RAII drop/release dan signal cleanup tetap dipertahankan. `TempFileGuard` dan wrapper `write_string_atomically`/test-only atomic module dihapus setelah audit call-site membuktikan tidak ada consumer produksi; atomic checkpoint logic yang aktif di modul lain tidak disentuh. Helper `_compile_dyn_pattern_type` yang hanya menjadi type-check test helper juga dihapus setelah seluruh custom pattern production path dan regression tests terbukti membangun `DynPattern` secara langsung. Jalur scanner, binary dispatch, object verification, dan exhaustive policy tidak disentuh. Kandidat allowance lain tetap menunggu klasifikasi per-symbol serta regression coverage sebelum dihapus atau dimigrasikan.

Audit setiap `#[allow(dead_code)]`, `#[allow(clippy::too_many_lines)]`, dan helper yang hanya tersisa dari pipeline lama. Migrasikan API yang masih relevan atau hapus code path yang tidak digunakan.

### Acceptance criteria

- Setiap remaining allowance memiliki alasan lokal yang jelas.
- Obsolete scanner loop tidak tersisa setelah shared engine aktif.
- Tidak ada pengurangan coverage untuk menghilangkan warning.
- Strict Clippy tetap lulus tanpa global suppression.

---

# P3 — Production operations dan release governance

## P3-01 — Tambahkan GitHub Actions quality pipeline
**Status:** `DONE` — baseline quality workflow merged; cross-platform and extended contract gates moved to P3-07/P3-08
**Dependensi:** P0-04
**Area:** `.github/workflows/`

### Implementasi P3-01 (sub-bagian core quality workflow)

`.github/workflows/quality.yml` sekarang menjalankan fmt check, whitespace check, strict Clippy, all-target tests, release build, installer syntax, benchmark Python syntax, `cargo-audit`, dan deterministic remote-acquisition benchmark pada push/pull request ke `main`. Workflow memakai `permissions: contents: read`, concurrency cancellation, timeout, dan tidak membutuhkan live credentials atau target eksternal. Lockfile diperbarui secara targeted ke patched releases untuk `crossbeam-epoch`, `quinn-proto`, `rustls-webpki`, `anyhow`, dan `rand`; `cargo audit` kini hanya melaporkan warning unmaintained `number_prefix` dan exit sukses. Remaining work: shellcheck/toolchain policy, artifact checksum/provenance, dan branch protection.

Buat workflow untuk fmt, Clippy, all-target tests, release build, `cargo-audit` atau `cargo-deny`, lockfile consistency, installer shellcheck/syntax, dan artifact checksum. Jalankan pada push/pull request ke `main`.

### Acceptance criteria

- Setiap pull request wajib melewati quality checks.
- Dependency audit dijalankan otomatis.
- Failure pada format, test, build, atau audit memblokir merge.
- Workflow tidak memerlukan live credentials atau target eksternal.

## P3-02 — Aktifkan branch protection dan release approval

**Status:** `DONE`
**Dependensi:** P3-01
**Area:** GitHub repository settings

Proteksi `main`, wajibkan required status checks, dan tetapkan release checklist yang membandingkan version metadata, source commit, tag, archive checksum, dan release asset. Release manual tetap boleh, tetapi harus mengacu pada artifact yang terverifikasi.

### Implementasi P3-02

Branch `main` kini mewajibkan pull request dengan minimal satu approval, required check `Rust and black-box quality gates` dalam mode strict/up-to-date, conversation resolution, dan admin enforcement. Force-push serta branch deletion dinonaktifkan. `install.sh` juga kini menolak release binary bila asset `SHA256SUMS`, entry checksum archive yang tepat, atau utilitas SHA-256 lokal tidak tersedia; verifikasi hanya membandingkan archive yang dipilih sehingga checksum entries untuk asset lain tidak menyebabkan false failure.

### Acceptance criteria

- Direct push yang melewati checks tidak menjadi jalur normal.
- Release target commit dan binary build commit selalu tercatat.
- `SHA256SUMS` diverifikasi sebelum publikasi.
- Tidak ada build artifact yang dikomit ke source repository.

## P3-03 — Reproducible multi-platform release

**Status:** `TODO`
**Dependensi:** P3-01, P3-02, P2-01
**Area:** release workflow, `install.sh`, documentation

Perluas release setelah cross-platform support diuji: Linux x86_64 tetap dipertahankan, lalu evaluasi Linux ARM64, macOS, dan Windows. Tambahkan artifact provenance/SBOM dan installer behavior per platform.

### Acceptance criteria

- Setiap asset memiliki checksum dan build metadata.
- Installer memilih asset yang benar atau gagal dengan pesan yang actionable.
- Unsupported platform tidak diam-diam melakukan source build tanpa persetujuan/penjelasan.
- README support matrix sama dengan asset release aktual.

## P3-04 — Structured telemetry dan coverage report

**Status:** `IN PROGRESS`
**Dependensi:** P1-01, P1-05, P1-07, P1-08
**Area:** `src/reporter.rs`, `src/streamer.rs`, benchmark tools

### Implementasi P3-04 (sub-bagian operational report telemetry)

URL dan token JSON reports kini secara additive menyertakan `files_saved`, `files_save_failed`, object cache `hits`/`misses`/`stats`, rate-limit `allowed`/`dropped`/`wait_ms`, serta optional `retry` telemetry (`attempts`, `retries`, success/failure, network errors, dan status counts). Retry snapshot dipopulasi pada URL scan dan seluruh built-in HTTP-backed forge clients melalui hook provider-neutral; local scan serta custom Forge implementations dapat tetap `null`. Object-source dan typed outcome metrics yang sudah ada tetap dipertahankan. Regression tests memverifikasi kedua report paths, field zero-value, resource-budget, history-coverage, dan retry snapshot tanpa mengubah findings. Remaining work: stage timing dan queue/concurrency metrics yang lebih granular.

Tambahkan stage timing, request attempts, retry counts, acquisition source, skip/failure reason, truncation, memory-budget events, coverage limits, dan queue/concurrency metrics ke JSON report secara additive. Pastikan findings tetap menjadi fokus utama dan telemetry tidak membocorkan secret.

### Acceptance criteria

- Operator dapat membedakan clean result dari incomplete result.
- Metrics dapat dipakai untuk benchmark regression tanpa parsing terminal output.
- JSON schema regression test diperbarui.
- NDJSON/live mode tetap valid dan tidak rusak oleh metadata baru.

## P3-05 — Upgrade benchmark suite
**Status:** `IN PROGRESS`
**Dependensi:** P1-07, P1-08, P3-04
**Area:** `tools/benchmark_local_scan.py`, `tools/benchmark_remote_acquisition.py`

### Implementasi P3-05 (sub-bagian remote benchmark metadata)

`tools/benchmark_remote_acquisition.py` kini mempertahankan output JSON lama sekaligus menambahkan metadata fixture (file, commit, byte), build profile eksplisit, host metadata non-sensitif, mean/median/min/max elapsed, population variance, relative spread, per-sample dan summary `peak_rss_bytes` dari child process, throughput bytes/blobs per second, serta report-derived cache dan retry telemetry. `--build-profile` membantu membedakan release, debug, dan custom binary dalam hasil benchmark; fixture tetap lokal, deterministic, dan tidak memerlukan credentials atau internet. Remaining work: retry/cache-hit scenarios yang terisolasi dan regression threshold multi-sample yang lebih kaya.

Pertahankan local normal-versus-exhaustive benchmark, lalu tambah remote acquisition benchmark dengan deterministic fixture. Ukur throughput, cache hit rate, source distribution, retry behavior, typed outcomes, peak RSS, dan variance antar repetition. Output utama harus JSON.

### Acceptance criteria

- Benchmark tidak membutuhkan credentials atau internet.
- Baseline menyertakan fixture size, build profile, repetition count, host metadata, dan variance.
- Regression threshold tidak menggunakan satu sample wall-clock secara naif.
- Benchmark release binary dan local optimized binary dapat dibandingkan dengan fixture yang sama.

## P3-06 — Dokumentasi capability matrix dan limitations

**Status:** `IN PROGRESS`
**Dependensi:** P1-04, P1-06, P1-05, P3-03
**Area:** `README.md`, `DEVELOPMENT.md`, `docs/limitations.md`

### Implementasi P3-06 (sub-bagian capability matrix)

`docs/limitations.md` sekarang memuat matrix yang memisahkan URL exposure, local snapshot, forge snapshot, forge history, binary/archive, custom patterns, checkpoint, cache, structured output, multi-target, dan platform installer. Dokumen tersebut juga menjelaskan batas deleted-content provider, resource limits, object/cache verification, platform asset versus source fallback, serta interpretasi clean result. README dan DEVELOPMENT menautkan dokumen ini. Status tetap `IN PROGRESS` karena capability matrix masih perlu disinkronkan dengan release multi-platform aktual setelah P3-03 selesai.

### Acceptance criteria

- Tidak ada klaim umum yang menyamakan forge snapshot dengan URL historical scan.
- README, DEVELOPMENT.md, `--help`, dan release notes memakai istilah yang konsisten.
- Limit, truncation, unsupported capability, dan default behavior terdokumentasi.
- Semua contoh penggunaan dapat dijalankan terhadap fixture yang tidak sensitif.

---

# Matrix dependensi eksekusi

| Gelombang | Item wajib | Output utama |
|---:|---|---|
| 1 | P0-01, P0-02, P0-03, P0-04 | Resume benar, verification benar, dry-run benar, input/retry contract benar |
| 2 | P0-05, P1-01 | Typed boundary dan shared scanner/accumulator mulai tersedia |
| 3 | P1-02, P1-03, P1-04, P1-05 | Binary/archive/custom-pattern parity lintas mode |
| 4 | P1-06, P1-07, P1-08 | Forge history capability, acquisition harness, global resource budget |
| 5 | P2-01, P2-02, P2-03, P2-04, P2-05 | Core library, modular streamer, typed config/error, provider transport |
| 6 | P2-06, P2-07 | Cache semantics dan technical-debt cleanup |
| 7 | P3-01, P3-02 | CI dan branch governance |
| 8 | P3-03, P3-04, P3-05, P3-06 | Release multi-platform, telemetry, benchmark, capability docs |

## Paket release yang disarankan

| Release target | Isi |
|---|---|
| **v3.2.7** | P0 correctness: checkpoint equivalence, bare verification, dry-run, float/retry/HTTP contracts, process-exit cleanup yang aman |
| **v3.3.0** | Shared scanner/accumulator, binary custom patterns, magic-byte dispatch, forge binary parity, typed truncation |
| **v3.4.0** | Remote acquisition harness, global resource budget, forge capability/history foundation, provider transport consolidation |
| **v3.5.0** | Core library extraction, streamer/main modularization, typed errors, cache lifecycle, dead-code cleanup |
| **v4.0.0** | CI-enforced governance, reproducible multi-platform release, structured telemetry, benchmark publication, dan capability matrix final |

Nomor versi di atas adalah usulan perencanaan, bukan perubahan metadata saat ini. Setiap release harus tetap mempertahankan compatibility contract atau mencatat breaking change secara eksplisit.

## Checklist sebelum memulai item berikutnya

| Pemeriksaan | Status |
|---|---|
| Item sebelumnya sudah memiliki acceptance test | `TODO` |
| Working tree bersih sebelum perubahan | `TODO` |
| Tidak ada credential-shaped literal baru | `TODO` |
| Normal/exhaustive semantics tetap diuji | `TODO` |
| Binary scanning default dan object verification default tetap aktif | `TODO` |
| Partial exposure tetap opt-in | `TODO` |
| Quality gates lengkap lulus | `TODO` |
| Commit message menjelaskan satu paket perubahan | `TODO` |
| Push ke `origin/main` hanya setelah review lokal selesai | `TODO` |

## References

[1]: https://github.com/HazaVVIP/GitRecon/blob/bdcad7c0cf6fdb6586d131df75c993c8f92eea50/src/streamer.rs "Streamer engine, scheduling, detector dispatch, and checkpoint integration"
[2]: https://github.com/HazaVVIP/GitRecon/blob/bdcad7c0cf6fdb6586d131df75c993c8f92eea50/src/checkpoint.rs "Checkpoint schema and compatibility handling"
[3]: https://github.com/HazaVVIP/GitRecon/blob/bdcad7c0cf6fdb6586d131df75c993c8f92eea50/src/mapper.rs "Git object mapping and verification"
[4]: https://github.com/HazaVVIP/GitRecon/blob/bdcad7c0cf6fdb6586d131df75c993c8f92eea50/src/forge_scan.rs "Forge reconstruction and workspace scan path"
[5]: https://github.com/HazaVVIP/GitRecon/blob/bdcad7c0cf6fdb6586d131df75c993c8f92eea50/src/binary_scanner.rs "Binary and archive scanner"
[6]: https://github.com/HazaVVIP/GitRecon/blob/bdcad7c0cf6fdb6586d131df75c993c8f92eea50/src/http_client.rs "HTTP transport, retry, and body handling"
[7]: https://github.com/HazaVVIP/GitRecon/blob/bdcad7c0cf6fdb6586d131df75c993c8f92eea50/README.md "GitRecon operator documentation"
[8]: https://github.com/HazaVVIP/GitRecon/blob/bdcad7c0cf6fdb6586d131df75c993c8f92eea50/DEVELOPMENT.md "GitRecon development and release guide"
[9]: https://github.com/HazaVVIP/GitRecon/releases/tag/v3.2.6 "GitRecon v3.2.6 release"

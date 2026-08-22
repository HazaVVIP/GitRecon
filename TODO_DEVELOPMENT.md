# GitRecon Development TODO

**Versi backlog:** setelah audit penuh v3.2.6  
**Status baseline:** `main` bersih pada `bdcad7c0cf6fdb6586d131df75c993c8f92eea50`  
**Prioritas utama:** correctness, feature parity, offensive coverage, lalu maintainability dan release governance

Dokumen ini adalah backlog development resmi GitRecon. Item dikerjakan secara inkremental, satu paket perubahan pada satu waktu, dan setiap paket wajib mempertahankan kualitas build, test, serta perilaku offensive scanning yang sudah ada. `--exhaustive`, binary scanning default, object verification default, dan partial-exposure opt-in tidak boleh berubah secara tidak sengaja.

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

**Status:** `TODO`  
**Dependensi:** P1-01  
**Area:** `src/dir_pipeline.rs`, `src/streamer.rs`, `src/binary_adapter.rs`

Null-byte heuristic tetap dapat dipakai sebagai signal, tetapi tidak boleh menjadi satu-satunya pintu masuk. Gunakan magic-byte detection untuk SQLite, ZIP/JAR, GZIP, ELF, dan format yang didukung; gunakan extension sebagai fallback dan catat confidence. Unknown binary tetap diproses melalui printable-string scanner jika policy mengizinkan.

### Acceptance criteria

- GZIP dengan sparse null bytes tetap dipindai.
- ZIP/JAR tanpa lebih dari 10 null bytes tetap dikenali dari magic bytes.
- Unknown binary tidak otomatis dibuang tanpa typed reason.
- `--no-scan-binaries` tetap menjadi opt-out yang jelas.
- Ditambahkan boundary tests untuk files exactly-at-threshold, truncated headers, and unknown binary.

## P1-04 — Pulihkan binary/archive parity pada forge mode

**Status:** `TODO`  
**Dependensi:** P1-01, P1-02, P1-03  
**Area:** `src/forge_scan.rs`, `src/forge.rs`, provider modules

Forge mode tidak boleh memfilter binary sebelum scanner menerima data. Pertahankan workspace reconstruction untuk `--save`, tetapi gunakan scanner engine yang sama untuk content bytes dan file path. Source metrics, typed outcomes, cache semantics, dan report fields harus konsisten dengan URL/local mode.

### Acceptance criteria

- Forge snapshot scan mendeteksi binary/archive findings dengan rules yang sama seperti local scan.
- Custom pattern binary berlaku pada forge mode.
- `object_source_stats`, `outcome_stats`, cache, and rate metrics tidak lagi selalu zero tanpa penjelasan.
- Malformed, oversized, skipped, dan failed file memiliki outcome terstruktur.
- Ditambahkan forge-vs-local parity integration test menggunakan provider mock.

## P1-05 — Tambahkan archive limits dan typed truncation outcomes

**Status:** `TODO`  
**Dependensi:** P1-02, P1-03  
**Area:** `src/binary_scanner.rs`, `src/streamer.rs`, `src/reporter.rs`

Pertahankan bounded extraction, tetapi ubah silent truncation menjadi telemetry. Tambahkan maximum nested archive depth, maximum extracted entries, per-entry bytes, total expanded bytes, and decompression ratio guard. Limit yang menghentikan coverage harus tampil pada report.

### Acceptance criteria

- Nested archive recursion selalu bounded oleh depth dan total resource budget.
- ZIP/GZIP/SQLite malformed input tidak panic.
- Report membedakan complete scan, truncated scan, oversized entry, invalid archive, dan decompression limit.
- Exhaustive mode tidak menghapus limits resource; exhaustive berarti coverage policy, bukan unlimited memory.

## P1-06 — Definisikan capability dan history mode untuk forge

**Status:** `TODO`  
**Dependensi:** P1-01, P1-04  
**Area:** `src/forge.rs`, `src/forge_factory.rs`, `src/*_api.rs`, `src/forge_scan.rs`

Dokumentasikan dan modelkan perbedaan `snapshot` versus `history` scan. Tambahkan capability discovery untuk branches, tags, commits, deleted blobs, and provider-specific history support. Implementasikan history mode bertahap, dimulai dari GitHub dan GitLab, tanpa mengklaim parity sebelum coverage benar-benar tersedia.

### Acceptance criteria

- Report selalu menyatakan `scan_scope=snapshot|history` dan capability yang tidak tersedia.
- Snapshot mode tetap cepat dan backward-compatible.
- History mode memiliki bounded traversal, deduplication, deleted-path mapping, and coverage metrics.
- Provider yang belum mendukung history mengembalikan typed `unsupported_capability`, bukan silent success.
- README usage examples membedakan snapshot dan history.

## P1-07 — Bangun deterministic remote acquisition test harness

**Status:** `TODO`  
**Dependensi:** P1-01  
**Area:** `tests/`, `src/object_source.rs`, `src/http_client.rs`, `tools/`

Buat local HTTP fixture server untuk menguji pack, cache, loose object, invalid object, 404, oversized response, 429, 5xx, retry-after, and cancellation. Harness harus menghasilkan source/outcome metrics yang dapat dibandingkan secara deterministic.

### Acceptance criteria

- Precedence pack → cache → loose HTTP teruji.
- Object verification menolak response invalid dan menerima valid canonical object.
- Cache hit/miss serta source provenance muncul benar di JSON report.
- Retry attempts, terminal failures, cancellation, and response caps dapat diverifikasi tanpa internet.
- Benchmark dapat menghasilkan JSON output dan menjalankan fixture yang sama di CI.

## P1-08 — Bangun global resource budget

**Status:** `TODO`  
**Dependensi:** P1-01, P1-05, P1-07  
**Area:** `src/streamer.rs`, `src/pack_reader.rs`, `src/binary_scanner.rs`, `src/http_client.rs`

`--mem-limit` harus mencakup acquisition buffer, pack bytes, inflated object, archive expansion, GZIP decompression, detector buffers, dan report accumulator. Buat `ResourceBudget` shared dengan reserve/release yang aman terhadap cancellation.

### Acceptance criteria

- Peak memory-sensitive allocations tercatat per stage.
- Pack besar tidak dapat melewati budget hanya karena budget scanner belum aktif.
- Archive/decompression limits memakai budget yang sama.
- Cancellation selalu me-release reservation.
- Report menjelaskan objek yang dilewati karena memory budget, bukan menyamarkannya sebagai clean scan.

---

# P2 — Modularisasi dan maintainability

## P2-01 — Ekstrak core library dari binary-only crate

**Status:** `TODO`  
**Dependensi:** P0 selesai, P1-01 minimal tersedia  
**Area:** `src/lib.rs`, `src/main.rs`, module tree

Pindahkan domain logic ke `src/lib.rs` atau core crate internal. `main.rs` harus menjadi CLI adapter tipis yang menangani parse args, display, exit code, dan orchestration boundary.

### Acceptance criteria

- Parser, detector, object source, mapper, checkpoint, and reporter core dapat diuji tanpa process invocation.
- `std::process::exit` hanya berada pada CLI boundary.
- Public API internal memiliki ownership dan error contract yang jelas.
- Integration tests dapat memilih library API atau binary sesuai kebutuhan.

## P2-02 — Pecah `streamer.rs` dan `main.rs` berdasarkan domain

**Status:** `TODO`  
**Dependensi:** P1-01, P2-01  
**Area:** `src/streamer.rs`, `src/main.rs`

Ekstrak domain berikut secara bertahap: `stream_types`, `scan_scheduler`, `content_scanner`, `scan_accumulator`, `stream_checkpoint`, `object_worker`, dan `scanner_factory`. Di `main.rs`, pisahkan command/flow untuk URL, local, targets, dan provider token.

### Acceptance criteria

- Tidak ada perubahan output yang tidak disengaja.
- Setiap extracted module memiliki focused tests.
- `#[allow(clippy::too_many_arguments)]` berkurang melalui typed config/builder.
- Dependency direction tidak berputar: CLI → orchestration → core domains → transport/storage abstractions.

## P2-03 — Ganti positional configuration constructor dengan typed config

**Status:** `TODO`  
**Dependensi:** P1-01  
**Area:** `src/config.rs`, `src/scanner_factory.rs`

Ganti constructor dengan 16 positional arguments menjadi `ScanConfigBuilder` atau typed `ScanConfigInput`. Kelompokkan policy, resource, transport, output, and checkpoint settings. Validasi invariants saat construction sehingga core menerima konfigurasi yang sudah valid.

### Acceptance criteria

- Compiler membantu mencegah field tertukar.
- Snapshot checkpoint dibangun dari satu canonical config object.
- Config serialization/fingerprint tetap deterministic.
- Existing CLI defaults tetap sama dan memiliki regression test.

## P2-04 — Ekstrak common provider transport

**Status:** `TODO`  
**Dependensi:** P0-04, P2-01  
**Area:** `src/http_client.rs`, `src/forge.rs`, `src/*_api.rs`

Satukan retry, Retry-After, rate-limit header parsing, pagination primitives, URL normalization, response-size policy, dan redacted error handling. Provider modules hanya menangani endpoint serta response schema yang spesifik.

### Acceptance criteria

- Tidak ada lima implementasi rate-limit wrapper yang drift tanpa alasan provider-specific.
- Per-provider behavior tetap dapat mengoverride format header dan pagination.
- Contract tests tetap lulus untuk GitHub, GitLab, Bitbucket, Gitea, dan Azure.
- GitHub API base URL dapat dikonfigurasi untuk GitHub Enterprise atau compatibility endpoint bila provider contract mendukungnya.

## P2-05 — Perkenalkan typed error taxonomy

**Status:** `TODO`  
**Dependensi:** P0-04, P2-04  
**Area:** `src/outcome.rs`, `src/forge.rs`, `src/http_client.rs`, `src/mapper.rs`

Buat error type yang membawa stage, provider, HTTP status, retryability, redacted target, and source context. `TargetErrorCode` menjadi mapping report boundary, bukan hasil parsing substring dari error message.

### Acceptance criteria

- Error classification tidak bergantung pada substring bahasa manusia.
- Retry decision dapat diuji dari typed properties.
- Per-target aggregate report tetap deterministic.
- Secret/token/authorization material tidak masuk ke error output.

## P2-06 — Perbaiki cache semantics dan lifecycle

**Status:** `TODO`  
**Dependensi:** P1-07, P1-08  
**Area:** `src/cache.rs`, README, DEVELOPMENT.md

Pilih dan implementasikan semantics yang benar-benar diinginkan: update access timestamp untuk LRU, atau ubah dokumentasi menjadi oldest-inserted eviction. Tambahkan cleanup policy, inspect/stats command, eviction telemetry, dan handling expired entry yang eksplisit.

### Acceptance criteria

- Dokumentasi tidak lagi menyebut LRU bila implementasi tidak memperbarui access time.
- Cache tetap bounded pada entry count/bytes dan cleanup tidak merusak size accounting.
- Cache hit/miss/eviction/expiration dapat diuji.
- `--no-cache` benar-benar melewati seluruh cache I/O.

## P2-07 — Kurangi dead-code allowances dan hapus jalur obsolete

**Status:** `TODO`  
**Dependensi:** P2-01, P2-02  
**Area:** seluruh `src/`

Audit setiap `#[allow(dead_code)]`, `#[allow(clippy::too_many_lines)]`, dan helper yang hanya tersisa dari pipeline lama. Migrasikan API yang masih relevan atau hapus code path yang tidak digunakan.

### Acceptance criteria

- Setiap remaining allowance memiliki alasan lokal yang jelas.
- Obsolete scanner loop tidak tersisa setelah shared engine aktif.
- Tidak ada pengurangan coverage untuk menghilangkan warning.
- Strict Clippy tetap lulus tanpa global suppression.

---

# P3 — Production operations dan release governance

## P3-01 — Tambahkan GitHub Actions quality pipeline

**Status:** `TODO`  
**Dependensi:** P0-04  
**Area:** `.github/workflows/`

Buat workflow untuk fmt, Clippy, all-target tests, release build, `cargo-audit` atau `cargo-deny`, lockfile consistency, installer shellcheck/syntax, dan artifact checksum. Jalankan pada push/pull request ke `main`.

### Acceptance criteria

- Setiap pull request wajib melewati quality checks.
- Dependency audit dijalankan otomatis.
- Failure pada format, test, build, atau audit memblokir merge.
- Workflow tidak memerlukan live credentials atau target eksternal.

## P3-02 — Aktifkan branch protection dan release approval

**Status:** `TODO`  
**Dependensi:** P3-01  
**Area:** GitHub repository settings

Proteksi `main`, wajibkan required status checks, dan tetapkan release checklist yang membandingkan version metadata, source commit, tag, archive checksum, dan release asset. Release manual tetap boleh, tetapi harus mengacu pada artifact yang terverifikasi.

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

**Status:** `TODO`  
**Dependensi:** P1-01, P1-05, P1-07, P1-08  
**Area:** `src/reporter.rs`, `src/streamer.rs`, benchmark tools

Tambahkan stage timing, request attempts, retry counts, acquisition source, skip/failure reason, truncation, memory-budget events, coverage limits, dan queue/concurrency metrics ke JSON report secara additive. Pastikan findings tetap menjadi fokus utama dan telemetry tidak membocorkan secret.

### Acceptance criteria

- Operator dapat membedakan clean result dari incomplete result.
- Metrics dapat dipakai untuk benchmark regression tanpa parsing terminal output.
- JSON schema regression test diperbarui.
- NDJSON/live mode tetap valid dan tidak rusak oleh metadata baru.

## P3-05 — Upgrade benchmark suite

**Status:** `TODO`  
**Dependensi:** P1-07, P1-08, P3-04  
**Area:** `tools/benchmark_local_scan.py`, `tools/benchmark_remote_acquisition.py`

Pertahankan local normal-versus-exhaustive benchmark, lalu tambah remote acquisition benchmark dengan deterministic fixture. Ukur throughput, cache hit rate, source distribution, retry behavior, typed outcomes, peak RSS, dan variance antar repetition. Output utama harus JSON.

### Acceptance criteria

- Benchmark tidak membutuhkan credentials atau internet.
- Baseline menyertakan fixture size, build profile, repetition count, host metadata, dan variance.
- Regression threshold tidak menggunakan satu sample wall-clock secara naif.
- Benchmark release binary dan local optimized binary dapat dibandingkan dengan fixture yang sama.

## P3-06 — Dokumentasi capability matrix dan limitations

**Status:** `TODO`  
**Dependensi:** P1-04, P1-06, P1-05, P3-03  
**Area:** `README.md`, `DEVELOPMENT.md`, `docs/limitations.md`

Buat satu capability matrix yang membedakan URL exposure, local snapshot, forge snapshot, forge history, binary/archive, custom patterns, checkpoint, cache, dan platform support. Tambahkan `docs/limitations.md` untuk referensi pack reader dan batas coverage.

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

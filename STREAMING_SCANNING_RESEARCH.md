# Riset & Rancangan Peningkatan Phase "STREAMING & SCANNING"

> **Dokumen ini adalah hasil brainstorming dan riset desain murni — tidak ada perubahan kode.**  
> Tujuan: mengidentifikasi seluruh area yang dapat ditingkatkan pada Phase 3 GitRecon (streamer.rs)
> dan merumuskan proposal rancangan untuk setiap peningkatan.

---

## Daftar Isi

1. [Gambaran Singkat Phase 3 Saat Ini](#1-gambaran-singkat-phase-3-saat-ini)
2. [Peningkatan Performa & Throughput](#2-peningkatan-performa--throughput)
3. [Manajemen Memori](#3-manajemen-memori)
4. [Kualitas & Cakupan Scanning](#4-kualitas--cakupan-scanning)
5. [Dukungan Pack File & Objek Delta](#5-dukungan-pack-file--objek-delta)
6. [Ketahanan & Pemulihan (Resilience)](#6-ketahanan--pemulihan-resilience)
7. [Stealth & Penghindaran Deteksi](#7-stealth--penghindaran-deteksi)
8. [Format Output & Integrasi](#8-format-output--integrasi)
9. [Perluasan Pola Deteksi Secret](#9-perluasan-pola-deteksi-secret)
10. [Rekayasa Arsitektur Jangka Panjang](#10-rekayasa-arsitektur-jangka-panjang)
11. [Tabel Prioritas](#11-tabel-prioritas)

---

## 1. Gambaran Singkat Phase 3 Saat Ini

### Cara Kerja

Phase 3 (*streamer.rs*) menerima daftar SHA1 dari Phase 2 (mapper), lalu untuk setiap SHA1:

1. **Fetch** — `GET /.git/objects/{sha1[0:2]}/{sha1[2:40]}` via HTTP
2. **Decompress** — zlib inflate objek Git
3. **Classify** — tentukan tipe objek: `blob`, `commit`, atau `tree`
4. **Scan** (khusus blob):
   - Deteksi biner: periksa 8 KB pertama untuk null byte (>10 null → skip)
   - Filter ukuran: skip jika >4 MB
   - Regex scan: terapkan 60+ pola pada setiap baris
   - Filter panjang baris: skip baris >2.000 karakter
   - Filter placeholder: buang match yang mengandung kata dummy
5. **Kontribusi & Tech Stack** — ekstrak email/nama dari commit, fingerprint framework dari nama file
6. **Opsional Save** — tulis blob ke disk jika `--save` aktif

### Model Concurrency

- `futures::stream::iter().buffer_unordered(workers)` — batas default 50 worker
- Aggregasi hasil: *single-threaded* (tidak ada mutex, tidak ada channel asinkron per-worker)
- Progress callback dipanggil setiap objek selesai

### Keterbatasan yang Diidentifikasi

| Keterbatasan | Dampak |
|---|---|
| Hanya fetch *loose objects*, tidak mendukung *pack file* | Miss semua objek yang sudah di-GC atau repository besar |
| `mem_limit` diparse tapi tidak diimplementasikan | Scan repository besar bisa OOM |
| Tidak ada resume/checkpoint | Scan >100k objek harus restart dari awal jika gagal |
| Regex dijalankan untuk semua pola pada setiap baris | CPU-bound pada file besar |
| Pola hanya single-line | Miss secret yang terbagi antar baris |
| Tidak ada deduplication finding | Laporan bisa berisi ratusan finding identik dari file berbeda |
| Worker count statis | Tidak adaptif terhadap kondisi jaringan server |
| Binary detection hanya heuristic null byte | Bisa false-negative untuk beberapa format biner |

---

## 2. Peningkatan Performa & Throughput

### 2.1 Adaptive Concurrency (Kontrol Worker Dinamis)

**Masalah saat ini:** Worker count ditetapkan secara statis via `--workers` (default 50). Jika server lambat atau menolak request, antrian tetap penuh dan menghasilkan banyak error/timeout yang membuang waktu.

**Rancangan:**
- Pantau *sliding window* dari 100 request terakhir: hitung persentase sukses, rata-rata latency, dan jumlah timeout.
- Jika error rate >20% atau rata-rata latency >5 detik: kurangi worker (`workers = max(5, workers - 10)`)
- Jika error rate <5% dan latency <1 detik: tambah worker (`workers = min(max_workers, workers + 5)`)
- Tambah flag `--max-workers` (batas atas) dan `--min-workers` (batas bawah)
- Implementasi via `tokio::sync::watch` channel untuk broadcast perubahan concurrency ke stream loop

**Manfaat:** Optimal throughput otomatis; tidak perlu tuning manual per target.

---

### 2.2 HTTP/2 Multiplexing

**Masalah saat ini:** reqwest secara default menggunakan HTTP/1.1 (meski mendukung HTTP/2). Setiap request Git object membuka koneksi baru atau menunggu slot keep-alive.

**Rancangan:**
- Aktifkan HTTP/2 di `ClientBuilder` dengan `.http2_prior_knowledge()` untuk target HTTP atau `.https_only()` dengan ALPN H2
- Manfaat: satu koneksi TCP dapat membawa ratusan request paralel (stream HTTP/2), mengurangi overhead TLS handshake dan connection setup
- Tambah flag `--http2` (opt-in) karena tidak semua server mendukung HTTP/2 untuk static file

**Trade-off:** Server Apache/Nginx yang melayani `.git` mungkin tidak mendukung HTTP/2 untuk direktori statis.

---

### 2.3 Request Batching via Range Headers

**Masalah saat ini:** Setiap objek Git di-fetch dalam satu request terpisah. Untuk repository dengan 10.000+ objek, ini menghasilkan 10.000+ round-trip.

**Rancangan:**
- Untuk server yang mendukung `Range` header: gabungkan beberapa objek kecil (<2 KB) menjadi satu multipart request
- Deteksi dukungan Range dari header `Accept-Ranges: bytes` pada respons awal
- Implementasi: kumpulkan objek kecil dalam batch 20-50, fetch sebagai satu request multipart, parse respons terpecah
- Estimasi penghematan: untuk repository dengan 5.000 objek kecil, dari 5.000 request menjadi ~250 request

**Kompleksitas:** Tinggi — membutuhkan implementasi multipart HTTP response parsing.

---

### 2.4 Prefetching Berbasis Graf Objek

**Masalah saat ini:** SHA1 di-fetch dalam urutan daftar datar (flat list). Tidak ada prediksi objek mana yang akan dibutuhkan selanjutnya berdasarkan struktur graf Git.

**Rancangan:**
- Saat memproses objek `tree`, langsung ekstrak SHA1 semua child blob dan masukkan ke antrian prioritas
- Saat memproses objek `commit`, ekstrak SHA1 tree dan parent commit, dan prefetch keduanya
- Implementasi: gunakan `tokio::sync::mpsc` channel sebagai priority queue; objek dari tree aktif mendapat prioritas lebih tinggi dari objek historis
- Hasil: blobs dari HEAD/working tree ditemukan dan di-scan lebih awal, sehingga finding kritis muncul lebih cepat

**Manfaat:** Waktu-to-first-finding lebih pendek; jika scan diinterupsi lebih awal tetap mendapat coverage tertinggi.

---

### 2.5 Streaming Decompression (Zero-Copy)

**Masalah saat ini:** Body HTTP di-buffer sepenuhnya dalam memori sebelum di-decompress. Untuk objek besar, ini berarti dua kopi dalam memori sekaligus (raw + decompressed).

**Rancangan:**
- Gunakan `async_compression::tokio::bufread::ZlibDecoder` untuk decompress sambil membaca stream HTTP
- Integrasi dengan `reqwest` response sebagai `AsyncRead` stream
- Batas streaming: scan baris per baris sambil menerima data, tidak perlu buffer seluruh konten
- Manfaat: penggunaan memori puncak untuk satu objek turun dari `2×size` menjadi `~1×size`

---

### 2.6 Cache SHA1 yang Sudah Diproses (Skip Duplikat)

**Masalah saat ini:** Jika dua branch memiliki blob SHA1 yang sama (tidak ada perubahan pada file), blob tersebut tetap di-fetch dan di-scan ulang karena daftar SHA1 dari mapper bisa mengandung duplikat.

**Rancangan:**
- Sebelum streaming, deduplikasi daftar `all_sha1s` dengan `HashSet`
- Optionally: simpan hasil scan (findings per SHA1) dalam `HashMap<String, Vec<Finding>>` sehingga jika SHA1 yang sama muncul di konteks berbeda, hasil scan dapat di-reuse
- Estimasi penghematan: repository dengan banyak branch bersama → 30-60% pengurangan request

---

## 3. Manajemen Memori

### 3.1 Implementasi Nyata `mem_limit`

**Masalah saat ini:** Flag `--mem-limit` diparse tetapi variabel `mem_limit` di `Streamer` diberi anotasi `#[allow(dead_code)]` — tidak pernah digunakan.

**Rancangan:**
- Gunakan `Arc<AtomicUsize>` sebagai counter total bytes yang sedang di-proses (in-flight objects)
- Sebelum memulai fetch objek baru, periksa apakah `bytes_in_flight + estimated_size > mem_limit`
- Jika mendekati limit: pause stream (turunkan concurrency atau tunggu worker selesai)
- Estimasi `estimated_size` dari header `Content-Length` saat tersedia
- Log peringatan saat mendekati 80% dan 95% mem_limit
- Tambah metric `peak_memory_mb` pada `StreamResult` untuk pelaporan

**Manfaat:** Tool dapat dijalankan pada mesin 512 MB tanpa risiko OOM; penting untuk lingkungan container/VPS kecil.

---

### 3.2 Finding Deduplication In-Memory

**Masalah saat ini:** Jika pola yang sama ditemukan di banyak file (misalnya API key yang sama dicopy-paste ke 50 file konfigurasi), `findings` Vec akan berisi 50 entri nyaris identik, membuang memori dan menghasilkan laporan yang sulit dibaca.

**Rancangan:**
- Definisikan kunci dedup sebagai `(pattern_id, match_str_trimmed)` — abaikan filename dan baris
- Gunakan `HashMap<(String, String), Vec<FindingLocation>>` alih-alih `Vec<Finding>` flat
- Setiap *unique secret* memiliki satu entri dengan daftar semua lokasi temuan (file + baris)
- Dalam laporan: tampilkan "Found in 12 files" daripada 12 baris terpisah

**Manfaat:** Laporan lebih mudah dibaca; penggunaan memori turun signifikan untuk repository dengan banyak duplikat konfigurasi.

---

### 3.3 Batasan Ukuran Findings Vec

**Masalah saat ini:** `state.findings` tumbuh tidak terbatas. Pada target besar dengan banyak false positive, ini bisa mengonsumsi GB memori.

**Rancangan:**
- Tambah parameter `max_findings` (default: 10.000)
- Jika limit tercapai, log peringatan dan hentikan menyimpan finding baru (kecuali severity CRITICAL)
- Alternatif lebih canggih: tulis findings ke file sementara (streaming JSON output) dan hanya simpan index dalam memori

---

## 4. Kualitas & Cakupan Scanning

### 4.1 Multi-Line Pattern Matching

**Masalah saat ini:** `scan_content()` bekerja baris per baris. Secret yang terbagi antar baris (misalnya private key PEM, JSON dengan newline, YAML multiline) tidak terdeteksi kecuali berada dalam satu baris.

**Rancangan:**
- Pisahkan pola menjadi dua kategori: *single-line* (saat ini) dan *multi-line*
- Untuk pola multi-line: scan seluruh konten file dengan regex `(?s)` (dot-all mode)
- Contoh kasus yang terlewat:
  ```
  SECRET_KEY = (
      "abcdefghijklmnopqrstuvwxyz1234567890"
  )
  ```
- Contoh pola multi-line yang berguna: private key PEM (BEGIN → END), YAML block scalar, JSON nested object
- Batasi scan multi-line ke file <500 KB untuk menghindari catastrophic backtracking

---

### 4.2 Deteksi Berbasis Entropi Shannon

**Masalah saat ini:** Pola regex saja bisa miss secret yang tidak memiliki prefix yang dikenal (misalnya custom API key tanpa format standar).

**Rancangan:**
- Untuk setiap token yang cocok dengan format *quoted string* atau *value after `=`/:*, hitung entropi Shannon
- Rumus: `H = -Σ p(c) × log2(p(c))` di mana `p(c)` adalah frekuensi karakter `c`
- Threshold: string dengan panjang ≥20 dan entropi ≥4.0 bits/char → tandai sebagai "potential secret" dengan severity MEDIUM
- Kombinasikan dengan konteks nama variabel: jika nama variabel mengandung kata sensitif (`key`, `secret`, `token`, `pass`, `auth`), naikkan severity ke HIGH
- Referensi: pendekatan ini digunakan oleh TruffleHog v3 dan GitLeaks dengan akurasi tinggi

**Trade-off:** Meningkatkan false positive. Perlu threshold yang baik dan daftar false-positive yang diperluas.

---

### 4.3 Context-Aware Scanning (Analisis Konteks)

**Masalah saat ini:** Setiap baris di-scan secara independen. Tidak ada informasi tentang konteks sekitar (baris sebelum/sesudah).

**Rancangan:**
- Saat menemukan match, simpan 3 baris sebelum dan 3 baris sesudah sebagai konteks yang lebih kaya
- Gunakan konteks untuk meningkatkan akurasi: jika ada `if test:` atau `# example` dalam 3 baris sebelum match → tingkatkan kemungkinan false positive → filter atau tandai dengan confidence rendah
- Implementasi: scan dengan sliding window 7 baris, pass window ke fungsi scoring

---

### 4.4 Deteksi Secret di File Minified

**Masalah saat ini:** File JavaScript minified sering berisi API key yang di-bundle ke dalam satu baris panjang. Saat ini baris >2.000 karakter di-skip seluruhnya.

**Rancangan:**
- Alih-alih skip seluruh baris panjang, pisahkan berdasarkan karakter pemisah umum dalam minified code: `;`, `{`, `}`, `&&`, `||`
- Scan setiap "token" hasil pemisahan sebagai baris virtual
- Batasi pemisahan ke baris ≤50.000 karakter (hindari baris infinitely long dari concatenated files)
- Alternatif: gunakan batas karakter yang lebih panjang, misalnya 10.000 karakter, untuk file berekstensi `.js`, `.min.js`, `.bundle.js`

---

### 4.5 Scanning File Biner Terpilih

**Masalah saat ini:** Semua file biner di-skip. Namun beberapa format biner mengandung plaintext yang berisi secret: SQLite databases, Java `.properties` dalam JAR, compiled Kotlin, PropertyList (`.plist`).

**Rancangan:**
- Whitelist format biner yang kemungkinan mengandung plaintext secret:
  - SQLite: buka sebagai database, ekstrak semua string dari tabel
  - JAR/ZIP: ekstrak entry `.properties`, `.xml`, `.json`, `.env` dan scan isinya
  - `.plist`: parse XML plist untuk value yang mencurigakan
- Untuk format lain: scan dengan regex hanya pada segmen printable ASCII (panjang ≥20 karakter berturut-turut)
- Implementasi menggunakan pustaka: `zip` untuk JAR/ZIP, `rusqlite` untuk SQLite

---

### 4.6 Deteksi Secret Historis (Deleted Files)

**Masalah saat ini:** Field `is_deleted` sudah ada di `Finding`, tetapi tidak ada mekanisme untuk secara proaktif mencari file yang sudah dihapus dari commit terbaru namun masih ada dalam sejarah.

**Rancangan:**
- Saat memproses object `commit`, parse daftar file yang dimodifikasi/dihapus antara commit tersebut dan parent-nya
- Untuk blob yang `is_deleted = true`, naikkan priority scanning (karena developer mungkin menghapus file justru karena berisi secret)
- Dalam laporan: buat seksi terpisah "Secrets in Deleted/Historical Files" yang di-highlight merah

---

### 4.7 Fingerprinting Framework dari Konten File (Content-Based)

**Masalah saat ini:** Tech stack dideteksi hanya dari nama file. File `app.py` yang berisi `from flask import Flask` akan terdeteksi sebagai "Python" tapi tidak sebagai "Flask".

**Rancangan:**
- Tambah regex konten per framework yang hanya dijalankan pada blob yang sudah di-fetch (tidak membutuhkan request tambahan):
  - `from flask import` → Flask
  - `from django` → Django
  - `require('express')` → Express.js
  - `import React` → React
  - `@SpringBootApplication` → Spring Boot
- Scan konten ini bersamaan dengan scanning secret (satu pass, tidak ada overhead tambahan)
- Hasil: tech stack detection jauh lebih akurat

---

### 4.8 Pendeteksian Kredensial Database dari Konten

**Masalah saat ini:** Database URL dideteksi hanya jika menggunakan format URL standar (`mysql://user:pass@host`). Banyak aplikasi menyimpan kredensial terpisah dalam variabel atau dictionary.

**Rancangan:**
- Tambah pola untuk mendeteksi konfigurasi database multi-baris yang umum:
  ```python
  DATABASES = {
      'default': {
          'ENGINE': '...',
          'NAME': '...',
          'USER': '...',
          'PASSWORD': 'secret_pass',  # ← target
      }
  }
  ```
- Gunakan konteks multi-baris (lihat 4.3): jika dalam 10 baris sebelumnya ada `DATABASES`, `db_config`, atau `database:`, maka baris dengan `'PASSWORD'` atau `'password'` dianggap high-confidence finding

---

## 5. Dukungan Pack File & Objek Delta

### 5.1 Fetch dan Parse Pack File

**Masalah saat ini:** GitRecon hanya menangani *loose objects* (`/.git/objects/{2-hex}/{38-hex}`). Repository yang telah dijalankan `git gc` menyimpan semua objek dalam *pack files* (`.git/objects/pack/*.pack`). Ini berarti **mayoritas objek di repository production tidak dapat di-fetch sama sekali**.

**Konteks teknis:**
- Pack file index (`.idx`) berisi mapping SHA1 → offset di dalam `.pack`
- Pack file (`.pack`) berisi semua objek yang dikompresi, termasuk objek delta (diff dari objek lain)
- Format: terdiri dari header 4-byte magic, versi, jumlah objek, lalu sequence of packed objects

**Rancangan:**
- **Step 1**: Fetch `/.git/objects/info/packs` untuk mendapatkan daftar pack files
- **Step 2**: Fetch setiap `.idx` file → parse untuk mendapatkan mapping SHA1 → offset
- **Step 3**: Fetch `.pack` file dengan `Range` header untuk objek spesifik (hindari download seluruh pack yang bisa berukuran GB)
- **Step 4**: Implementasi delta decompression (OBJ_REF_DELTA, OBJ_OFS_DELTA) untuk merekonstruksi objek delta
- Referensi: Git pack format didokumentasikan di `Documentation/technical/pack-format.txt`

**Dampak:** Ini adalah peningkatan **terpenting secara keseluruhan** — tanpa pack file support, repository production nyaris tidak dapat di-scan sama sekali.

---

### 5.2 Smart HTTP Protocol (Git Upload-Pack)

**Masalah saat ini:** GitRecon mengakses objek Git secara "dumb" — hanya menggunakan HTTP GET ke path yang diketahui. Git *smart HTTP protocol* (menggunakan `/info/refs?service=git-upload-pack` dan `/git-upload-pack`) memungkinkan discovery objek yang jauh lebih lengkap.

**Rancangan:**
- Request `GET /.git/info/refs?service=git-upload-pack`
- Parse respons untuk mendapatkan daftar ref dan kemampuan server
- Kirim `POST /.git/git-upload-pack` dengan `want {sha1}` untuk setiap SHA1 yang diinginkan
- Server merespons dengan pack file yang mengandung seluruh objek yang diminta
- Ini memungkinkan download repository lengkap dalam satu request daripada ribuan request individual

**Trade-off:** Lebih kompleks, dan beberapa server mematikan git-upload-pack untuk `dumb HTTP`. Perlu fallback ke dumb mode.

---

### 5.3 Objek Delta: Dekompresi dan Rekonstruksi

**Masalah saat ini:** Objek delta (`OBJ_REF_DELTA`, `OBJ_OFS_DELTA`) mengandung instruksi diff relatif terhadap objek base. Tanpa kemampuan dekompresi delta, objek-objek ini tidak dapat dibaca.

**Rancangan:**
- Implementasi fungsi `apply_delta(base: &[u8], delta: &[u8]) -> Vec<u8>` yang mengimplementasikan format delta Git:
  - Header varint: ukuran base dan ukuran hasil
  - Instruksi COPY: `0x80 | offset_encoding | size_encoding`, diikuti offset dan size
  - Instruksi ADD: `0x7F & len`, diikuti `len` bytes baru
- Resolusi dependency: jika objek delta membutuhkan base yang belum di-fetch, tambahkan base ke antrian fetch terlebih dahulu
- Strategi: DFS traversal dari dependency chain delta

---

## 6. Ketahanan & Pemulihan (Resilience)

### 6.1 Resume / Checkpoint

**Masalah saat ini:** Tidak ada mekanisme checkpoint. Jika scan terhadap repository dengan 50.000 objek gagal di objek ke-40.000 (koneksi jaringan putus, OOM, Ctrl+C), seluruh proses harus diulang dari awal.

**Rancangan:**
- Saat streaming dimulai, buat file checkpoint di direktori output: `{target}_checkpoint.json`
- Format checkpoint:
  ```json
  {
    "git_url": "https://...",
    "all_sha1s": [...],
    "processed_sha1s": [...],
    "findings_so_far": [...],
    "timestamp": "..."
  }
  ```
- Setiap 500 objek selesai: update checkpoint secara atomik (tulis ke file temp, lalu rename)
- Flag `--resume`: jika checkpoint ada untuk target yang sama, lanjutkan dari titik terakhir
- Pada akhir scan sukses: hapus file checkpoint

**Manfaat:** Sangat penting untuk target besar (>10.000 objek) dan scan via proxy yang unstable.

---

### 6.2 Error Categorization & Smart Retry

**Masalah saat ini:** Semua kegagalan request diperlakukan sama. HTTP 404 (objek tidak ada) diretry 3 kali percuma. HTTP 429 (rate limited) tidak mendapat penanganan khusus.

**Rancangan:**
- Kategorikan error:
  - `404 Not Found` → **jangan retry**, objek memang tidak ada (loose object yang sudah di-pack)
  - `429 Too Many Requests` → **pause semua worker** selama durasi `Retry-After` header, lalu lanjutkan
  - `503 Service Unavailable` → **exponential backoff** dengan jitter, maksimal 5 retry
  - `0 (network error)` → **standard retry** dengan backoff
  - `403 Forbidden` → **jangan retry**, catat sebagai "protected object"
- Implementasi: enum `FetchError` dengan variant per kategori, handler berbeda di `fetch_and_process`

---

### 6.3 Timeout Per-Objek yang Adaptif

**Masalah saat ini:** Timeout diterapkan secara global untuk semua request. Objek kecil yang membutuhkan >10 detik menunjukkan masalah server, bukan masalah ukuran.

**Rancangan:**
- Hitung moving average dari latency 100 request terakhir
- Set timeout individual ke `max(global_timeout, avg_latency × 3)`
- Untuk objek yang diketahui ukurannya besar (dari Content-Length): timeout = `size_mb × 2 + base_timeout`

---

### 6.4 Partial Scan Mode (Early Exit)

**Masalah saat ini:** Tidak ada cara untuk menghentikan scan setelah menemukan N findings kritis — scan selalu berlanjut sampai semua objek habis.

**Rancangan:**
- Flag `--max-findings N` (default: tidak terbatas): hentikan streaming setelah N findings terkumpul
- Flag `--stop-on-critical`: hentikan segera setelah menemukan finding CRITICAL pertama
- Implementasi: atomic counter untuk jumlah findings; setiap worker cek counter sebelum mulai scan

**Manfaat:** Untuk bug bounty hunter yang hanya perlu bukti kerentanan, bukan laporan lengkap.

---

## 7. Stealth & Penghindaran Deteksi

### 7.1 Rate Limiting Per-Worker (Bukan Global)

**Masalah saat ini:** Rate limiting (`--delay`, `--jitter`) diterapkan di level `HttpClient` dan dipanggil di setiap request. Dengan 50 worker concurrent, semua 50 worker memanggil `rate_limit()` secara bersamaan, efektif mengirim burst 50 request sekaligus lalu pause.

**Rancangan:**
- Implementasi *token bucket* atau *leaky bucket* algorithm sebagai `Arc<tokio::sync::Mutex<RateLimiter>>`
- Token bucket: isi token setiap interval; setiap request konsumsi 1 token; jika habis, worker menunggu
- `--rate N` flag: maksimum N request per detik (misalnya `--rate 10` = maks 10 req/s)
- Distribusi yang merata di seluruh waktu scan, bukan burst-then-pause

---

### 7.2 Rotasi Proxy Multi-Endpoint

**Masalah saat ini:** Hanya satu proxy yang dapat dikonfigurasi. Untuk target yang memblokir berdasarkan IP, satu proxy berarti seluruh scan diblokir.

**Rancangan:**
- Flag `--proxy-list FILE`: file teks berisi daftar proxy (satu per baris)
- Strategi rotasi: round-robin, random, atau weighted (berdasarkan latency)
- Setiap worker pool mendapat proxy berbeda dari list
- Fallback: jika proxy X gagal 3× berturut-turut, tandai sebagai down dan skip ke proxy berikutnya
- Dukungan format: `socks5://`, `socks4://`, `http://`, dengan opsional autentikasi

---

### 7.3 Request Fingerprint Diversifikasi

**Masalah saat ini:** Meski ada rotasi User-Agent, pola request sangat mudah diidentifikasi: semua request ke path `/.git/objects/{hex}/{hex}` dengan interval reguler.

**Rancangan:**
- Variasikan header Accept secara acak: `text/html`, `application/json`, `*/*`
- Tambahkan header opsional dengan nilai acak: `X-Request-ID`, `X-Correlation-ID`
- Variasikan urutan header (reqwest tidak menjamin urutan)
- Sisipkan "decoy request" sesekali ke path publik yang valid (gambar, halaman utama) untuk menyamarkan pola akses
- Variasi delay: distribusi Gaussian alih-alih uniform untuk pola yang lebih manusiawi

---

### 7.4 User-Agent Pool yang Dapat Dikustomisasi

**Masalah saat ini:** Hanya 4 User-Agent yang hardcoded. WAF modern dapat fingerprint tool berdasarkan pola UA yang terbatas.

**Rancangan:**
- Flag `--ua-file FILE`: load daftar User-Agent dari file teks
- Default pool diperluas ke 20+ UA modern (berbagai browser versi terbaru)
- Tambah UA mobile: Android Chrome, iOS Safari
- Opsi `--ua git/2.x.x` untuk menyamar sebagai git client asli

---

## 8. Format Output & Integrasi

### 8.1 Real-Time Streaming Output (Live Findings)

**Masalah saat ini:** Semua finding dikumpulkan dulu dalam memori, baru ditampilkan dan disimpan di akhir Phase 4. Untuk scan besar, pengguna menunggu lama sebelum melihat hasil.

**Rancangan:**
- Tambah flag `--live` atau `--stream-output`: tampilkan setiap finding langsung saat ditemukan
- Implementasi: gunakan `tokio::sync::mpsc` channel antara worker dan output writer
- Format live output: satu baris per finding, warna berdasarkan severity
- Kompatibel dengan pipe: `gitrecon target | grep CRITICAL | head -20`

---

### 8.2 Format Output SARIF

**Masalah saat ini:** Hanya output JSON custom. Tidak kompatibel langsung dengan tool CI/CD dan platform security seperti GitHub Advanced Security, SonarQube, Semgrep.

**Rancangan:**
- Implementasi SARIF 2.1.0 (Static Analysis Results Interchange Format) sebagai format output opsional
- Flag `--format sarif`: output file `.sarif` yang dapat langsung diupload ke GitHub Security tab
- SARIF mendukung: rules, results, locations, code flows, suppressions
- Manfaat: integrasi langsung ke GitHub Actions workflow sebagai security scan

---

### 8.3 Webhook Integration (Real-Time Push)

**Masalah saat ini:** Untuk pipeline otomasi, tidak ada cara mendapatkan hasil secara real-time tanpa polling file output.

**Rancangan:**
- Flag `--webhook URL`: POST setiap finding ke URL sebagai JSON payload segera setelah ditemukan
- Payload per-finding: `{target, finding, severity, file, line, match, timestamp}`
- Autentikasi webhook: `--webhook-secret KEY` untuk HMAC-SHA256 signature di header `X-Signature`
- Rate limiting webhook: maximum 10 POST/detik untuk menghindari spam ke endpoint eksternal

---

### 8.4 Output Format yang Diperluas

**Rancangan untuk format output tambahan:**

| Format | Deskripsi | Flag |
|---|---|---|
| CSV | Satu baris per finding, cocok untuk spreadsheet | `--format csv` |
| NDJSON | Newline-delimited JSON, streaming-friendly | `--format ndjson` |
| Markdown | Laporan dalam format GitHub Markdown | `--format md` |
| HTML | Laporan interaktif dengan filter/sort | `--format html` |
| JUnit XML | Kompatibel dengan CI/CD test reports | `--format junit` |

---

### 8.5 Deduplication dan Grouping di Laporan

**Masalah saat ini:** Laporan JSON berisi flat array findings. Satu token yang sama ditemukan di 20 file = 20 entri terpisah yang identik.

**Rancangan:**
- Di laporan akhir, group findings berdasarkan `(pattern_id, match_fingerprint)`:
  ```json
  {
    "unique_secrets": [
      {
        "type": "aws_key_id",
        "severity": "CRITICAL",
        "value_preview": "AKIA***...",
        "found_in": [
          {"file": ".env", "line": 3},
          {"file": "config/prod.yml", "line": 15}
        ],
        "first_seen_commit": "abc123"
      }
    ]
  }
  ```
- Tambah statistik: `total_findings`, `unique_secrets`, `duplicate_count`

---

## 9. Perluasan Pola Deteksi Secret

### 9.1 Provider Cloud Tambahan

| Provider | Pattern yang Perlu Ditambahkan |
|---|---|
| **Oracle Cloud** | OCI config file: `[DEFAULT]` block dengan `user=ocid1.user...`, `key_file`, `fingerprint` |
| **Alibaba Cloud** | `LTAI` prefix Access Key ID (20 chars), `aliyun` prefix di konfigurasi |
| **IBM Cloud** | `apikey: [A-Za-z0-9_-]{44}` dalam konteks IBM Cloud |
| **Linode / Akamai** | `linode_token` atau token format `[A-Za-z0-9]{64}` |
| **Vultr** | `VULTR_API_KEY=` dengan 36-char alphanumeric |
| **Hetzner Cloud** | `HCLOUD_TOKEN=` dengan 64-char token |
| **Scaleway** | `SCW_SECRET_KEY=` format UUID |
| **Fly.io** | `FLY_API_TOKEN=` dengan `fo1_` prefix |

---

### 9.2 CI/CD & DevOps Tools

| Tool | Pattern |
|---|---|
| **CircleCI** | `CIRCLE_TOKEN=` dengan 40-char hex |
| **Travis CI** | `token:` dalam `.travis.yml` dengan 22-char alphanumeric |
| **Jenkins** | `jenkins_api_token` dalam groovy/XML dengan 32-char hex |
| **ArgoCD** | `argocd-server` bearer token |
| **Kubernetes** | ServiceAccount JWT dalam `kubectl config` base64 encoded |
| **Vault** | Tambah AppRole `secret_id` format: `[0-9a-f-]{36}` |

---

### 9.3 Layanan Database & Cache

| Layanan | Pattern |
|---|---|
| **Upstash Redis** | `rediss://default:[A-Za-z0-9]{128}@` |
| **Railway.app** | `DATABASE_URL=postgresql://...` specific Railway format |
| **CockroachDB** | `postgresql://...cockroachlabs.cloud` |
| **Fauna** | `fn[A-Za-z0-9]{40}` |
| **Turso** | `libsql://...turso.io` dengan auth token |
| **Xata** | `xau_[A-Za-z0-9_]{48}` |

---

### 9.4 Payment & Fintech

| Provider | Pattern |
|---|---|
| **Square** | `sq0csp-` atau `EAAAAA[A-Za-z0-9_-]{60}` |
| **Braintree** | Access token dengan `access_token$production$` prefix |
| **Adyen** | API key `AQE` prefix dengan 56+ chars |
| **Razorpay** | `rzp_live_` atau `rzp_test_` dengan 14-char alphanumeric |
| **Coinbase** | `coinbase_api_key` pattern |

---

### 9.5 Pola Kustom dari File Eksternal

**Rancangan:**
- Flag `--patterns FILE`: load pola tambahan dari file YAML/JSON
- Format file pola:
  ```yaml
  patterns:
    - id: my_internal_token
      severity: CRITICAL
      description: "Internal API Token"
      regex: "INT_[A-Z0-9]{32}"
  ```
- Pola kustom digabungkan dengan pola built-in sebelum scan dimulai
- Mendukung disable pola built-in tertentu: `--disable-pattern stripe_pk`

---

### 9.6 Scoring Kontekstual untuk Mengurangi False Positive

**Masalah saat ini:** Pola generik (`api_key`, `secret_key`) memiliki false positive rate tinggi karena regex tidak mempertimbangkan konteks.

**Rancangan:**
- Setiap finding diberi *confidence score* 0-100 berdasarkan:
  - Nama variabel/key yang mengandung kata sensitif: +30 poin
  - File sensitif (`.env`, `wp-config.php`): +20 poin
  - Tidak ada kata placeholder dalam 2 baris sekitar: +15 poin
  - Nilai memiliki entropi Shannon >3.5: +15 poin
  - Pattern ID adalah pola high-precision (aws_key_id, github_pat): +20 poin
- Finding dengan confidence <40 ditampilkan sebagai "Possible" bukan confirmed
- Flag `--min-confidence-finding N`: filter finding di bawah threshold tertentu

---

## 10. Rekayasa Arsitektur Jangka Panjang

### 10.1 Multi-Target Scanning

**Rancangan:**
- Flag `--targets FILE`: scan daftar URL dari file teks, satu URL per baris
- Jalankan Phase 1 (detect) untuk semua target secara paralel
- Setelah detect selesai, jalankan Phase 2 dan 3 untuk target yang positif
- Shared worker pool antar target: efisiensi lebih tinggi dibanding fork proses terpisah
- Output terpisah per target + satu aggregate report
- Progress bar multi-level: per-target dan keseluruhan

---

### 10.2 Plugin Architecture untuk Scanner

**Rancangan:**
- Definisikan trait `Scanner` yang dapat di-implement oleh modul eksternal:
  ```rust
  trait Scanner: Send + Sync {
      fn name(&self) -> &str;
      fn scan_blob(&self, content: &str, filename: &str) -> Vec<Finding>;
  }
  ```
- Loader dinamis via shared library (`.so`/`.dll`) menggunakan crate `libloading`
- Pengguna dapat menulis scanner custom tanpa fork seluruh repository
- Contoh scanner yang dapat di-plugin: SAST rules, compliance checks, custom enterprise patterns

---

### 10.3 Caching Database (SQLite)

**Rancangan:**
- Simpan hasil scan dalam SQLite database lokal: `~/.gitrecon/cache.db`
- Skema: `(target_url, sha1, scan_timestamp, findings_json)`
- Sebelum fetch objek, cek cache: jika SHA1 sudah pernah di-scan dan hasilnya ada, gunakan hasil cache
- Manfaat besar: re-scan target yang sama setelah update kecil hanya perlu scan SHA1 baru
- Flag `--no-cache`: bypass cache, selalu scan ulang
- Flag `--cache-dir DIR`: lokasi kustom database cache

---

### 10.4 Streaming Output ke STDIN/STDOUT Pipeline

**Rancangan:**
- Mode pipeline: `gitrecon target --pipe` → output NDJSON ke stdout, satu objek per baris
- Format: `{"type": "finding", "data": {...}}` atau `{"type": "progress", "done": 100, "total": 1000}`
- Contoh penggunaan:
  ```bash
  gitrecon https://target.com --pipe | jq 'select(.type=="finding") | .data' | \
    grep -i CRITICAL | notify-send "GitRecon Alert"
  ```
- Kompatibel dengan `xargs`, `jq`, `grep`, `tee` untuk automation workflow

---

### 10.5 Integrasi dengan Git Smart HTTP (Clone Virtual)

**Rancangan jangka panjang:**
- Implementasikan subset dari Git transfer protocol untuk melakukan "virtual clone" tanpa menyentuh disk
- Negosiasikan dengan server menggunakan `git-upload-pack` untuk mendapatkan seluruh pack file secara efisien
- Parse pack file in-memory, decompress semua objek, scan semua blob
- Ini setara dengan `git clone --mirror` tapi sepenuhnya in-memory dan tanpa membuat direktori `.git`
- Estimasi: 10-100× lebih cepat dari pendekatan per-object-request untuk repository besar

---

## 11. Tabel Prioritas

Berikut adalah tabel semua peningkatan yang diusulkan, diurutkan berdasarkan dampak vs. kompleksitas implementasi:

| # | Peningkatan | Dampak | Kompleksitas | Prioritas |
|---|---|---|---|---|
| 5.1 | Pack file support | 🔴 KRITIS | Tinggi | **P0** |
| 3.1 | Implementasi nyata `mem_limit` | 🔴 Tinggi | Rendah | **P0** |
| 6.1 | Resume / Checkpoint | 🔴 Tinggi | Sedang | **P1** |
| 2.6 | Deduplikasi SHA1 | 🟠 Sedang | Rendah | **P1** |
| 3.2 | Finding deduplication | 🟠 Sedang | Rendah | **P1** |
| 4.1 | Multi-line pattern matching | 🟠 Sedang | Sedang | **P1** |
| 2.1 | Adaptive concurrency | 🟠 Sedang | Sedang | **P2** |
| 6.2 | Error categorization & smart retry | 🟠 Sedang | Rendah | **P2** |
| 4.2 | Deteksi entropi Shannon | 🟠 Sedang | Sedang | **P2** |
| 9.5 | Custom patterns dari file eksternal | 🟠 Sedang | Rendah | **P2** |
| 8.1 | Real-time streaming output | 🟡 Sedang | Sedang | **P2** |
| 4.4 | Scan file minified JS | 🟡 Sedang | Rendah | **P2** |
| 10.3 | Caching database (SQLite) | 🟡 Sedang | Sedang | **P3** |
| 5.2 | Smart HTTP protocol | 🔴 Tinggi | Sangat Tinggi | **P3** |
| 2.2 | HTTP/2 multiplexing | 🟡 Sedang | Rendah | **P3** |
| 7.1 | Rate limiting per-worker (token bucket) | 🟡 Sedang | Sedang | **P3** |
| 8.2 | Format output SARIF | 🟡 Rendah | Sedang | **P3** |
| 9.1–9.4 | Perluasan pola secret | 🟠 Sedang | Rendah | **P3** |
| 4.3 | Context-aware scanning | 🟡 Sedang | Sedang | **P4** |
| 4.5 | Scanning file biner terpilih | 🟡 Sedang | Tinggi | **P4** |
| 7.2 | Rotasi proxy multi-endpoint | 🟡 Rendah | Sedang | **P4** |
| 10.1 | Multi-target scanning | 🟡 Sedang | Tinggi | **P4** |
| 2.3 | Request batching (Range headers) | 🟡 Rendah | Tinggi | **P5** |
| 10.2 | Plugin architecture | 🟡 Rendah | Sangat Tinggi | **P5** |
| 10.5 | Git virtual clone (Smart HTTP full) | 🔴 Tinggi | Sangat Tinggi | **P5** |

### Rekomendasi Urutan Implementasi

**Tahap 1 (Quick Wins)** — berdampak besar, kompleksitas rendah:
1. Deduplikasi SHA1 (`all_sha1s` dedup sebelum stream)
2. Finding deduplication in-memory
3. Error categorization (jangan retry 404)
4. Custom patterns dari file YAML
5. Implementasi `mem_limit` enforcement

**Tahap 2 (Fondasi)** — berdampak besar, kompleksitas sedang:
6. Resume/Checkpoint system
7. Multi-line pattern matching
8. Adaptive concurrency (token bucket + autoscaling workers)
9. Pack file parsing (Phase 3 → Phase 2 integration)

**Tahap 3 (Peningkatan Lanjut)** — meningkatkan kualitas deteksi:
10. Shannon entropy scoring
11. Context-aware scanning (sliding window 7 baris)
12. Minified JS handling
13. Perluasan pola (cloud providers baru, CI/CD tools)
14. Real-time streaming output (`--live` flag)

**Tahap 4 (Arsitektur Skala Besar)**:
15. Smart HTTP protocol (git-upload-pack)
16. SQLite cache untuk re-scan efisien
17. Multi-target batch scanning
18. SARIF output format

---

*Dokumen ini dibuat berdasarkan analisis source code GitRecon v3.0.0 (streamer.rs, mapper.rs, http_client.rs, git_parser.rs) dan riset best practice dari tools serupa: TruffleHog v3, GitLeaks, gitleaks, git-dumper, GitHacker.*

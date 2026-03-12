"""
phases/streamer.py
Phase 3 — Stream & Scan: fetch setiap object, scan secrets di memory,
buang object setelah scan. TIDAK ada tulis ke disk.
Output: StreamResult berisi semua findings + intel.
"""

import re
import math
import time
import threading
from dataclasses import dataclass, field
from typing      import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.http_client import HttpClient
from core.git_parser   import ObjectParser, obj_path
from phases.mapper     import MapResult


# ════════════════════════════════════════════════
# SECRET PATTERNS
# ════════════════════════════════════════════════

_PATTERNS = [
    # Cloud
    ("aws_key_id",      "CRITICAL", "AWS Access Key ID",
     r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ("aws_secret",      "CRITICAL", "AWS Secret Access Key",
     r"(?i)aws[_\-\s]?secret[_\-\s]?[a-z]*\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
    ("gcp_sa",          "CRITICAL", "GCP Service Account",
     r'"type"\s*:\s*"service_account"'),
    ("azure_conn",      "CRITICAL", "Azure Storage Connection String",
     r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),
    # VCS tokens
    ("github_pat",      "CRITICAL", "GitHub Personal Access Token",
     r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),
    ("github_oauth",    "CRITICAL", "GitHub OAuth Token",
     r"gho_[A-Za-z0-9]{36}"),
    ("github_app",      "CRITICAL", "GitHub App Token",
     r"(ghu|ghs)_[A-Za-z0-9]{36}"),
    ("gitlab_pat",      "CRITICAL", "GitLab PAT",
     r"glpat-[A-Za-z0-9\-_]{20}"),
    # Payment
    ("stripe_sk",       "CRITICAL", "Stripe Secret Key",
     r"sk_(live|test)_[A-Za-z0-9]{24,}"),
    ("stripe_pk",       "HIGH",     "Stripe Publishable Key",
     r"pk_(live|test)_[A-Za-z0-9]{24,}"),
    # Messaging
    ("slack_token",     "HIGH",     "Slack Token",
     r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}"),
    ("slack_webhook",   "HIGH",     "Slack Webhook",
     r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("discord_token",   "HIGH",     "Discord Bot Token",
     r"(?i)discord[_\-\s]?token\s*[=:]\s*['\"]?([A-Za-z0-9._-]{59,})['\"]?"),
    ("telegram_bot",    "HIGH",     "Telegram Bot Token",
     r"\d{8,10}:[A-Za-z0-9_-]{35}"),
    ("sendgrid",        "HIGH",     "SendGrid API Key",
     r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    ("twilio",          "HIGH",     "Twilio API Key",
     r"SK[0-9a-f]{32}"),
    ("mailgun",         "HIGH",     "Mailgun Key",
     r"key-[0-9a-f]{32}"),
    # Database
    ("db_url",          "CRITICAL", "Database Connection URL",
     r"(?i)(mysql|postgres|postgresql|mongodb|redis|mssql|oracle)://[^:@\s]+:[^@\s]+@[^\s]+"),
    ("db_password",     "CRITICAL", "Database Password",
     r"(?i)db[_\-]?(pass(word)?|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?"),
    # Keys
    ("private_key",     "CRITICAL", "Private Key",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----"),
    ("pgp_key",         "CRITICAL", "PGP Private Key",
     r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    # JWT
    ("jwt",             "HIGH",     "JWT Token",
     r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("jwt_secret",      "CRITICAL", "JWT Secret",
     r"(?i)jwt[_\-]?secret\s*[=:]\s*['\"]?([^\s'\"]{16,})['\"]?"),
    # Generic
    ("api_key",         "HIGH",     "Generic API Key",
     r"(?i)api[_\-\s]?key\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"),
    ("secret_key",      "HIGH",     "Generic Secret Key",
     r"(?i)secret[_\-\s]?key\s*[=:]\s*['\"]?([A-Za-z0-9_\-\!\@\#\$]{16,})['\"]?"),
    ("access_token",    "HIGH",     "Access Token",
     r"(?i)access[_\-\s]?token\s*[=:]\s*['\"]?([A-Za-z0-9_\-\.]{20,})['\"]?"),
    # Password
    ("hardcoded_pass",  "HIGH",     "Hardcoded Password",
     r"(?i)(password|passwd|pass|pwd)\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]"),
    ("env_pass",        "HIGH",     "Env Password Variable",
     r"(?im)^[A-Z_]*PASS(?:WORD)?[A-Z_]*\s*=\s*([^\s].+)$"),
    # Network
    ("private_ip",      "MEDIUM",   "Private IP Address",
     r"(?:^|[^0-9])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:[^0-9]|$)"),
    # Cloud storage
    ("s3_url",          "MEDIUM",   "S3 Bucket URL",
     r"https?://[a-z0-9\-\.]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com"),
    # Misc
    ("firebase_fcm",    "HIGH",     "Firebase FCM Key",
     r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"),
    ("npm_token",       "HIGH",     "NPM Token",
     r"(?:^|[^a-z])npm_[A-Za-z0-9]{36}"),
    ("docker_pat",      "HIGH",     "Docker Hub PAT",
     r"dckr_pat_[A-Za-z0-9_-]{27}"),
    ("oauth_secret",    "HIGH",     "OAuth Client Secret",
     r"(?i)client[_\-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"),
]

_COMPILED = []
for _id, _sev, _desc, _rx in _PATTERNS:
    try:
        _COMPILED.append((_id, _sev, _desc, re.compile(_rx, re.MULTILINE)))
    except re.error:
        pass

_PLACEHOLDERS = [
    "your_", "YOUR_", "example", "EXAMPLE", "placeholder",
    "xxxx", "XXXX", "changeme", "CHANGE_ME", "insert_",
    "TODO", "FIXME", "test_", "TEST_", "dummy", "DUMMY",
    "replace", "REPLACE", "sample", "SAMPLE", "fake", "FAKE",
    "00000000", "11111111", "<", ">",
]

_ENTROPY_CHARSET_B64 = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_ENTROPY_CHARSET_HEX = set("0123456789abcdefABCDEF")

# File-file yang biasanya berisi secrets (prioritas tinggi)
_SENSITIVE_NAMES = re.compile(
    r"(\.env|\.env\.|config\.php|wp-config|database\.php|"
    r"settings\.py|config\.ya?ml|credentials|secrets?\.json|"
    r"service.account|\.npmrc|\.pypirc|\.netrc|id_rsa|id_ed25519|"
    r"\.pem|\.key|\.pfx|\.p12|application\.(properties|ya?ml)|"
    r"docker.compose|\.travis\.yml|\.circleci)",
    re.IGNORECASE
)


# ════════════════════════════════════════════════
# DATA STRUCTURES
# ════════════════════════════════════════════════

@dataclass
class Finding:
    filename:    str
    line:        int
    pattern_id:  str
    description: str
    severity:    str
    match:       str
    context:     str
    is_deleted:  bool           # True = file sudah dihapus dari HEAD
    commit_sha1: Optional[str]  = None

    def to_dict(self) -> dict:
        return {
            "file":       self.filename,
            "line":       self.line,
            "type":       self.pattern_id,
            "desc":       self.description,
            "severity":   self.severity,
            "match":      self.match[:120],
            "context":    self.context[:200],
            "deleted":    self.is_deleted,
            "blob_sha1":  self.commit_sha1,
        }


@dataclass
class Contributor:
    name:  str
    email: str


@dataclass
class StreamResult:
    findings:      list  = field(default_factory=list)   # list[Finding]
    contributors:  list  = field(default_factory=list)   # list[Contributor]
    tech_stack:    list  = field(default_factory=list)
    commit_count:  int   = 0
    blobs_scanned: int   = 0
    blobs_failed:  int   = 0
    bytes_scanned: int   = 0
    elapsed_s:     float = 0.0

    @property
    def risk_score(self) -> int:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        score = (min(counts["CRITICAL"] * 20, 60) +
                 min(counts["HIGH"]     * 10, 30) +
                 min(counts["MEDIUM"]   *  5, 15))
        return min(score, 100)

    @property
    def severity_counts(self) -> dict:
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c


# ════════════════════════════════════════════════
# TECH STACK FINGERPRINTING
# ════════════════════════════════════════════════

_TECH = {
    "Python":     r"requirements\.txt|setup\.py|Pipfile|pyproject\.toml|manage\.py",
    "Node.js":    r"package\.json|yarn\.lock|package-lock\.json",
    "PHP":        r"composer\.json|composer\.lock|\.php$",
    "Ruby":       r"Gemfile|\.ruby-version|\.rb$",
    "Java":       r"pom\.xml|build\.gradle|\.java$",
    "Go":         r"go\.mod|go\.sum|\.go$",
    "Rust":       r"Cargo\.toml|Cargo\.lock|\.rs$",
    ".NET":       r"\.csproj|\.sln|web\.config",
    "Docker":     r"Dockerfile|docker-compose",
    "Kubernetes": r"kubectl|\.yaml$",
    "Terraform":  r"\.tf$|terraform\.tfvars",
    "WordPress":  r"wp-config|wp-content",
    "Django":     r"manage\.py|settings\.py|wsgi\.py",
    "Laravel":    r"artisan|\.blade\.php",
    "React":      r"\.jsx$|\.tsx$",
    "Vue":        r"\.vue$|vue\.config",
    "Angular":    r"angular\.json|ng-package",
}
_TECH_RE = {k: re.compile(v, re.IGNORECASE) for k, v in _TECH.items()}


# ════════════════════════════════════════════════
# MAIN STREAMER CLASS
# ════════════════════════════════════════════════

class Streamer:
    def __init__(self, client: HttpClient, workers: int = 12,
                 mem_limit_mb: int = 256, verbose: bool = True):
        self._client      = client
        self._workers     = workers
        self._mem_limit   = mem_limit_mb * 1024 * 1024
        self._verbose     = verbose
        self._obj_parser  = ObjectParser()
        self._lock        = threading.Lock()

        # State shared antar threads
        self._findings:    list         = []
        self._contributors: dict        = {}   # email → name
        self._tech_stack:  set          = set()
        self._commit_count: int         = 0
        self._blobs_scanned: int        = 0
        self._blobs_failed:  int        = 0
        self._bytes_scanned: int        = 0

        # SHA1s yang sudah diproses (deduplikasi)
        self._seen:   set = set()

        # SHA1 → filename mapping dari index (untuk label finding)
        self._sha1_to_file: dict = {}

        # SHA1 yang ada di HEAD (untuk deteksi "deleted")
        self._current_blobs: set = set()

    def run(self, git_url: str, map_result: MapResult,
            progress_cb=None) -> StreamResult:
        """
        Stream dan scan semua SHA1 dari MapResult.
        progress_cb(done, total) dipanggil setiap ada kemajuan.
        """
        t0      = time.time()
        git_url = git_url.rstrip("/")

        # Build lookup: sha1 → filename (dari index)
        for entry in map_result.index_entries:
            self._sha1_to_file[entry.sha1] = entry.filename
        self._current_blobs = map_result.blob_sha1s.copy()

        # Semua SHA1 yang perlu diproses
        # Prioritas: blob dari index dulu (sensitif), baru commit graph
        priority_blobs  = list(map_result.blob_sha1s)
        other_sha1s     = list(map_result.commit_sha1s)

        # Urutkan: file sensitif duluan
        priority_blobs.sort(
            key=lambda s: 0 if self._is_sensitive_file(
                self._sha1_to_file.get(s, "")) else 1
        )

        all_sha1s = priority_blobs + other_sha1s
        total     = len(all_sha1s)
        done      = 0

        self._log(f"[*] Streaming {total} objects ({len(priority_blobs)} blobs + "
                  f"{len(other_sha1s)} commit/tree graph)...")

        # Proses dalam batch untuk kontrol memori
        batch_size = min(200, max(50, self._mem_limit // (50 * 1024)))

        for i in range(0, len(all_sha1s), batch_size):
            batch = all_sha1s[i:i + batch_size]

            with ThreadPoolExecutor(max_workers=self._workers) as pool:
                futures = {
                    pool.submit(self._process_sha1, git_url, sha1): sha1
                    for sha1 in batch
                    if sha1 not in self._seen
                }
                for future in as_completed(futures):
                    done += 1
                    if progress_cb:
                        progress_cb(done, total)

        elapsed = time.time() - t0

        return StreamResult(
            findings      = self._findings,
            contributors  = [Contributor(name=n, email=e)
                              for e, n in self._contributors.items()],
            tech_stack    = sorted(self._tech_stack),
            commit_count  = self._commit_count,
            blobs_scanned = self._blobs_scanned,
            blobs_failed  = self._blobs_failed,
            bytes_scanned = self._bytes_scanned,
            elapsed_s     = elapsed,
        )

    # ── Per-SHA1 processing ───────────────────────────────────────

    def _process_sha1(self, git_url: str, sha1: str):
        with self._lock:
            if sha1 in self._seen:
                return
            self._seen.add(sha1)

        url  = f"{git_url}/{obj_path(sha1)}"
        resp = self._client.get(url)

        if not resp.ok:
            with self._lock:
                self._blobs_failed += 1
            return

        obj = self._obj_parser.parse(resp.body, sha1)
        if not obj:
            return

        with self._lock:
            self._bytes_scanned += len(resp.body)

        if obj.obj_type == "blob":
            self._scan_blob(obj)

        elif obj.obj_type == "commit":
            commit = self._obj_parser.parse_commit(obj)
            if commit:
                with self._lock:
                    self._commit_count += 1
                    if commit.author_email:
                        self._contributors[commit.author_email] = commit.author

        elif obj.obj_type == "tree":
            # Dari tree, kita temukan filename → sha1 mapping baru
            entries = self._obj_parser.parse_tree(obj)
            for entry in entries:
                if entry.is_blob:
                    with self._lock:
                        if entry.sha1 not in self._sha1_to_file:
                            self._sha1_to_file[entry.sha1] = entry.name
                        # Deteksi tech dari nama file
                        self._detect_tech(entry.name)
        # object: resp di-GC setelah method ini return → tidak ada di memory

    # ── Blob scanning ─────────────────────────────────────────────

    def _scan_blob(self, obj):
        # Coba decode sebagai text
        try:
            content = obj.data.decode("utf-8", errors="replace")
        except Exception:
            return

        # Skip binary files (NUL byte banyak)
        if content.count("\x00") > 20:
            return

        with self._lock:
            self._blobs_scanned += 1
            filename = self._sha1_to_file.get(obj.sha1, f"[blob:{obj.sha1[:8]}]")
            is_deleted = obj.sha1 not in self._current_blobs
            # Deteksi tech dari konten
            self._detect_tech(filename)

        findings = self._scan_content(content, filename, obj.sha1, is_deleted)

        if findings:
            with self._lock:
                self._findings.extend(findings)

    def _scan_content(self, content: str, filename: str,
                      sha1: str, is_deleted: bool) -> list:
        findings = []
        lines    = content.splitlines()

        for lineno, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue

            for pat_id, sev, desc, rx in _COMPILED:
                for m in rx.finditer(line):
                    val = m.group(0)
                    if self._is_placeholder(val):
                        continue
                    findings.append(Finding(
                        filename=filename, line=lineno,
                        pattern_id=pat_id, description=desc,
                        severity=sev, match=val,
                        context=line.strip(),
                        is_deleted=is_deleted,
                        commit_sha1=sha1,
                    ))

            # Entropy check untuk token panjang
            if len(line.strip()) >= 20 and not line.strip().startswith(("#","//","*","<!--","--")):
                for token in re.findall(r"['\"]([A-Za-z0-9+/=_\-]{24,})['\"]", line):
                    if self._high_entropy(token) and not self._is_placeholder(token):
                        findings.append(Finding(
                            filename=filename, line=lineno,
                            pattern_id="entropy_string",
                            description="High-entropy string (suspected secret)",
                            severity="MEDIUM", match=token,
                            context=line.strip(),
                            is_deleted=is_deleted,
                            commit_sha1=sha1,
                        ))

        return findings

    # ── Helpers ───────────────────────────────────────────────────

    def _detect_tech(self, filename: str):
        for tech, rx in _TECH_RE.items():
            if rx.search(filename):
                self._tech_stack.add(tech)

    def _is_sensitive_file(self, filename: str) -> bool:
        return bool(_SENSITIVE_NAMES.search(filename))

    def _is_placeholder(self, s: str) -> bool:
        return any(p in s for p in _PLACEHOLDERS)

    def _high_entropy(self, s: str, threshold: float = 3.6) -> bool:
        def entropy(string, charset):
            filtered = [c for c in string if c in charset]
            if len(filtered) < 12:
                return 0.0
            freq = {}
            for c in filtered:
                freq[c] = freq.get(c, 0) + 1
            return -sum((v/len(filtered)) * math.log2(v/len(filtered))
                        for v in freq.values())
        return (entropy(s, _ENTROPY_CHARSET_B64) > threshold or
                entropy(s, _ENTROPY_CHARSET_HEX) > threshold)

    def _log(self, msg):
        if self._verbose:
            print(msg)

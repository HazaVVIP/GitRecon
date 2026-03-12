"""
phases/detect.py
Phase 1 — Deteksi apakah .git/ terekspos.
Output: DetectResult dengan confidence 0-100 dan metadata awal.
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from core.http_client import HttpClient
from core.git_parser   import parse_head, ConfigParser, PackedRefsParser


# Probe: (path, verifier_fn, weight)
# verifier menerima body bytes, return bool
_PROBES = [
    ("HEAD",        lambda b: b"ref: refs/" in b or bool(re.match(rb"^[0-9a-f]{40}", b)), 40),
    ("config",      lambda b: b"[core]" in b,                                              30),
    ("packed-refs", lambda b: bool(re.search(rb"[0-9a-f]{40}", b)),                        15),
    ("index",       lambda b: b[:4] == b"DIRC",                                            20),
    ("logs/HEAD",   lambda b: bool(re.search(rb"[0-9a-f]{40}", b)),                        10),
    ("COMMIT_EDITMSG", lambda b: len(b.strip()) > 0,                                        5),
]

_TOTAL_WEIGHT = sum(w for _, _, w in _PROBES)

# Non-root .git locations yang sering ditemui
_PATH_VARIANTS = [
    ".git",
    "api/.git", "v1/.git", "v2/.git", "v3/.git",
    "admin/.git", "backend/.git", "app/.git",
    "web/.git", "www/.git", "public/.git",
    "src/.git", "portal/.git", "wp-content/.git",
]


@dataclass
class ProbeDetail:
    path:       str
    status:     int
    accessible: bool
    valid:      bool


@dataclass
class DetectResult:
    url:          str              # base URL target
    git_url:      str              # URL .git/ yang ditemukan
    confidence:   int              # 0–100
    label:        str              # NONE / LOW / MEDIUM / HIGH / CONFIRMED
    listing:      bool             # directory listing aktif?
    server:       str              # web server type
    branch:       Optional[str]    = None
    remote_url:   Optional[str]    = None
    head_sha1:    Optional[str]    = None
    probes:       list             = field(default_factory=list)

    @property
    def actionable(self) -> bool:
        return self.confidence >= 45

    @property
    def short(self) -> str:
        parts = [f"[{self.label}] {self.git_url}"]
        if self.branch:
            parts.append(f"branch={self.branch}")
        if self.listing:
            parts.append("listing=ON")
        return " | ".join(parts)


def _label(score: int) -> str:
    if score >= 90: return "CONFIRMED"
    if score >= 70: return "HIGH"
    if score >= 45: return "MEDIUM"
    if score >= 20: return "LOW"
    return "NONE"


def _detect_server(client: HttpClient, url: str) -> str:
    try:
        r = client.get(url)
        sv = r.headers.get("Server", "") + " " + r.headers.get("X-Powered-By", "")
        if "cf-ray" in {k.lower() for k in r.headers}:
            return "Cloudflare"
        for name, pats in [
            ("Nginx",     ["nginx"]),
            ("Apache",    ["apache"]),
            ("Caddy",     ["caddy"]),
            ("IIS",       ["microsoft-iis"]),
            ("LiteSpeed", ["litespeed"]),
            ("Cloudflare",["cloudflare"]),
            ("Vercel",    ["vercel"]),
            ("Netlify",   ["netlify"]),
        ]:
            if any(p in sv.lower() for p in pats):
                return name
    except Exception:
        pass
    return "Unknown"


def _check_listing(client: HttpClient, git_url: str) -> bool:
    r = client.get(git_url + "/")
    if not r.ok:
        r = client.get(git_url)
    if not r.ok:
        return False
    t = r.text.lower()
    return any(kw in t for kw in [
        "index of", "parent directory",
        'href="head"', 'href="config"', 'href="objects/"',
        "directory listing",
    ])


def _probe_one_path(client: HttpClient, base_url: str, git_path: str
                    ) -> Optional[DetectResult]:
    git_url = f"{base_url}/{git_path}"
    earned  = 0
    details = []
    config_parser  = ConfigParser()
    packed_parser  = PackedRefsParser()

    branch     = None
    remote_url = None
    head_sha1  = None

    for path, verify, weight in _PROBES:
        url  = f"{git_url}/{path}"
        resp = client.get(url)
        ok   = resp.ok
        valid = False

        if ok:
            try:
                valid = verify(resp.body)
            except Exception:
                valid = False
            if valid:
                earned += weight

            # Extract early intel
            if path == "HEAD" and valid:
                h = parse_head(resp.text)
                branch    = h.get("branch")
                head_sha1 = h.get("sha1")

            elif path == "config" and valid:
                try:
                    cfg    = config_parser.parse(resp.text)
                    remotes = config_parser.remote_urls(cfg)
                    if remotes:
                        remote_url = remotes[0]["url"]
                except Exception:
                    pass

        details.append(ProbeDetail(path=path, status=resp.status,
                                   accessible=ok, valid=valid))

        # Fast-fail: jika HEAD tidak accessible, path ini tidak valid
        if path == "HEAD" and not ok:
            return None

    score  = int((earned / _TOTAL_WEIGHT) * 100)
    score  = min(score, 100)

    server  = _detect_server(client, base_url)
    listing = _check_listing(client, git_url) if score >= 20 else False

    return DetectResult(
        url=base_url, git_url=git_url,
        confidence=score, label=_label(score),
        listing=listing, server=server,
        branch=branch, remote_url=remote_url,
        head_sha1=head_sha1, probes=details,
    )


def run(client: HttpClient, base_url: str, fuzz: bool = False) -> Optional[DetectResult]:
    """
    Probe target dan return DetectResult terbaik.
    Jika tidak ada exposure terdeteksi, return None.
    """
    base_url    = base_url.rstrip("/")
    candidates  = _PATH_VARIANTS if fuzz else [".git"]
    best        = None

    for git_path in candidates:
        result = _probe_one_path(client, base_url, git_path)
        if result is None:
            continue
        if best is None or result.confidence > best.confidence:
            best = result
        if best.label == "CONFIRMED":
            break

    if best and best.confidence >= 20:
        return best
    return None

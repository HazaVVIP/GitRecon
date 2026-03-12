"""
phases/mapper.py
Phase 2 — Mapping: kumpulkan semua SHA1 yang perlu di-scan.
Hanya download metadata (HEAD, config, index, packed-refs, logs).
TIDAK mendownload blob. TIDAK menulis ke disk.
Output: MapResult berisi set SHA1 + estimasi ukuran.
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from core.http_client import HttpClient
from core.git_parser   import (
    IndexParser, PackedRefsParser, PackIndexParser,
    ConfigParser,
    parse_head, parse_info_packs, extract_sha1s, obj_path,
)


# File metadata yang ingin di-fetch (urutan prioritas)
_META_FILES = [
    "HEAD",
    "config",
    "packed-refs",
    "index",                        # DIRC binary → semua SHA1 current state
    "logs/HEAD",
    "COMMIT_EDITMSG",
    "ORIG_HEAD",
    "FETCH_HEAD",
    "refs/heads/master",
    "refs/heads/main",
    "refs/heads/develop",
    "refs/heads/dev",
    "refs/heads/staging",
    "refs/heads/production",
    "refs/remotes/origin/HEAD",
    "refs/remotes/origin/master",
    "refs/remotes/origin/main",
    "refs/stash",
    "logs/refs/heads/master",
    "logs/refs/heads/main",
    "logs/refs/heads/develop",
    "logs/refs/remotes/origin/HEAD",
    "objects/info/packs",           # untuk discover pack files
    # JGit
    "refs/wip/index/refs/heads/master",
    "refs/wip/wtree/refs/heads/master",
]

_SIZE_PER_BLOB = 4 * 1024   # estimasi rata-rata blob ~4KB jika unknown


@dataclass
class MapResult:
    # SHA1 yang perlu di-fetch dan di-scan
    commit_sha1s:   set   = field(default_factory=set)
    tree_sha1s:     set   = field(default_factory=set)
    blob_sha1s:     set   = field(default_factory=set)   # dari index
    pack_sha1s:     list  = field(default_factory=list)  # nama pack

    # Metadata (sudah di-fetch, disimpan sebagai teks/bytes)
    meta:           dict  = field(default_factory=dict)  # path → body

    # Intel awal
    branches:       list  = field(default_factory=list)
    remote_urls:    list  = field(default_factory=list)
    index_entries:  list  = field(default_factory=list)   # list[IndexEntry]

    # Estimasi
    estimated_files:  int   = 0
    estimated_bytes:  int   = 0    # bytes total jika di-save ke disk

    @property
    def all_sha1s(self) -> set:
        return self.commit_sha1s | self.tree_sha1s | self.blob_sha1s

    @property
    def size_human(self) -> str:
        b = self.estimated_bytes
        if b < 1024:
            return f"{b} B"
        if b < 1024**2:
            return f"{b/1024:.1f} KB"
        if b < 1024**3:
            return f"{b/1024**2:.1f} MB"
        return f"{b/1024**3:.2f} GB"


class Mapper:
    def __init__(self, client: HttpClient):
        self._client  = client
        self._idx_p   = IndexParser()
        self._refs_p  = PackedRefsParser()
        self._pack_p  = PackIndexParser()
        self._cfg_p   = ConfigParser()
        self._log_p   = LogParser()

    def run(self, git_url: str, branch: str = None) -> MapResult:
        """
        Fetch semua metadata, parse, kumpulkan SHA1.
        git_url = URL lengkap ke .git/ (tanpa trailing slash)
        """
        git_url = git_url.rstrip("/")
        result  = MapResult()
        meta    = {}

        # ── 1. Fetch semua metadata files ──────────────────
        for path in _META_FILES:
            r = self._client.get(f"{git_url}/{path}")
            if r.ok and r.body:
                meta[path] = r.body

        # Juga fetch ref dari branch yang terdeteksi di Phase 1
        if branch:
            for ref_path in [
                f"refs/heads/{branch}",
                f"logs/refs/heads/{branch}",
            ]:
                if ref_path not in meta:
                    r = self._client.get(f"{git_url}/{ref_path}")
                    if r.ok and r.body:
                        meta[ref_path] = r.body

        result.meta = meta
        sha1s: set = set()

        # ── 2. Parse HEAD ───────────────────────────────────
        if b"HEAD" in {k.encode() for k in meta} or "HEAD" in meta:
            raw  = meta.get("HEAD", b"").decode("utf-8", errors="replace")
            head = parse_head(raw)
            if head["type"] == "detached" and head.get("sha1"):
                sha1s.add(head["sha1"])
            elif head["type"] == "ref":
                # Fetch ref file secara eksplisit
                ref_path = head["ref"]
                if ref_path not in meta:
                    r = self._client.get(f"{git_url}/{ref_path}")
                    if r.ok:
                        meta[ref_path] = r.body
                sha1_raw = meta.get(ref_path, b"").decode("utf-8", errors="replace").strip()
                if re.match(r"^[0-9a-f]{40}$", sha1_raw):
                    sha1s.add(sha1_raw)

        # ── 3. Parse config ─────────────────────────────────
        if "config" in meta:
            cfg = self._cfg_p.parse(meta["config"].decode("utf-8", errors="replace"))
            result.remote_urls = self._cfg_p.remote_urls(cfg)
            result.branches    = self._cfg_p.branches(cfg)

            # Fetch ref + log untuk setiap branch di config
            for br in result.branches[:15]:
                for p in [f"refs/heads/{br}", f"logs/refs/heads/{br}"]:
                    if p not in meta:
                        r = self._client.get(f"{git_url}/{p}")
                        if r.ok and r.body:
                            meta[p] = r.body

        # ── 4. Parse packed-refs ────────────────────────────
        if "packed-refs" in meta:
            refs = self._refs_p.parse(meta["packed-refs"].decode("utf-8", errors="replace"))
            sha1s.update(self._refs_p.sha1s(refs))
            for ref in refs:
                if "heads" in ref.ref:
                    br = ref.ref.rsplit("/", 1)[-1]
                    if br not in result.branches:
                        result.branches.append(br)

        # ── 5. Parse index (DIRC) ───────────────────────────
        if "index" in meta:
            try:
                entries = self._idx_p.parse(meta["index"])
                result.index_entries = entries
                for e in entries:
                    sha1s.add(e.sha1)
                    result.blob_sha1s.add(e.sha1)
            except Exception:
                pass

        # ── 6. Extract SHA1 dari semua log files ────────────
        for path, body in meta.items():
            if path.startswith("logs/"):
                try:
                    text = body.decode("utf-8", errors="replace")
                    sha1s.update(extract_sha1s(text))
                except Exception:
                    pass

        # ── 7. Extract SHA1 dari ref files ──────────────────
        for path, body in meta.items():
            if path.startswith("refs/"):
                text = body.decode("utf-8", errors="replace").strip()
                if re.match(r"^[0-9a-f]{40}$", text):
                    sha1s.add(text)

        # ── 8. Pack discovery via objects/info/packs ────────
        if "objects/info/packs" in meta:
            packs = parse_info_packs(meta["objects/info/packs"].decode("utf-8", errors="replace"))
            result.pack_sha1s = packs

            for pack_sha1 in packs:
                # Fetch .idx untuk mendapatkan semua SHA1 dalam pack
                idx_path = f"objects/pack/pack-{pack_sha1}.idx"
                r = self._client.get(f"{git_url}/{idx_path}")
                if r.ok and r.body:
                    meta[idx_path] = r.body
                    try:
                        pack_sha1s = self._pack_p.parse(r.body)
                        sha1s.update(pack_sha1s)
                    except Exception:
                        pass

        # ── 9. Klasifikasi SHA1 ──────────────────────────────
        # Semua yang ada di index = blob (current state)
        # Sisanya = kemungkinan commit atau tree (diklarifikasi saat stream)
        result.commit_sha1s = sha1s - result.blob_sha1s
        result.tree_sha1s   = set()  # diisi saat traversal di streamer

        # ── 10. Estimasi ukuran ──────────────────────────────
        result.estimated_files = len(result.index_entries) or len(result.blob_sha1s)
        if result.index_entries:
            # Gunakan file_size dari index (sangat akurat untuk current state)
            result.estimated_bytes = sum(e.file_size for e in result.index_entries)
        else:
            result.estimated_bytes = result.estimated_files * _SIZE_PER_BLOB

        return result


# ── Re-export LogParser supaya bisa dipakai dari sini ──
class LogParser:
    _LINE_RE = re.compile(
        r"^([0-9a-f]{40})\s+([0-9a-f]{40})\s+(.+?)\s+(\d+)\s+[+-]\d+\s+(.+)$"
    )

    def parse(self, text: str) -> list:
        entries = []
        for line in text.splitlines():
            m = self._LINE_RE.match(line.strip())
            if m:
                entries.append({
                    "old": m.group(1), "new": m.group(2),
                    "identity": m.group(3), "ts": int(m.group(4)),
                    "action": m.group(5),
                })
        return entries

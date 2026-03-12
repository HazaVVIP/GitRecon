"""
core/git_parser.py
Pure Python parsers untuk semua format binary Git.
Index (DIRC), loose objects, pack index (.idx),
packed-refs, logs, config, HEAD.
"""

import re
import struct
import zlib
import hashlib
from dataclasses import dataclass, field
from typing import Optional


# ════════════════════════════════════════════════
# DATA TYPES
# ════════════════════════════════════════════════

@dataclass
class IndexEntry:
    sha1:      str
    filename:  str
    mode:      int
    file_size: int    # bytes, dari stat data di index


@dataclass
class GitObject:
    sha1:     str
    obj_type: str     # blob | tree | commit | tag
    size:     int
    data:     bytes


@dataclass
class CommitInfo:
    sha1:         str
    tree:         str
    parents:      list
    author:       str
    author_email: str
    author_ts:    int
    message:      str


@dataclass
class TreeEntry:
    mode: str
    name: str
    sha1: str

    @property
    def is_blob(self) -> bool:
        return self.mode in ("100644", "100755")

    @property
    def is_tree(self) -> bool:
        return self.mode == "040000"


@dataclass
class RefEntry:
    sha1:   str
    ref:    str
    peeled: Optional[str] = None


# ════════════════════════════════════════════════
# INDEX PARSER  (.git/index — DIRC binary)
# ════════════════════════════════════════════════

class IndexParser:
    MAGIC = b"DIRC"

    def parse(self, data: bytes) -> list:
        """Returns list[IndexEntry]. Raises ValueError jika invalid."""
        if len(data) < 12 or data[:4] != self.MAGIC:
            raise ValueError("Not a valid git index file")

        version = struct.unpack(">I", data[4:8])[0]
        n       = struct.unpack(">I", data[8:12])[0]

        if version not in (2, 3, 4):
            raise ValueError(f"Unsupported index version: {version}")

        entries, offset = [], 12
        for _ in range(n):
            if offset + 62 > len(data):
                break
            entry, offset = self._parse_entry(data, offset, version)
            if entry:
                entries.append(entry)
        return entries

    def _parse_entry(self, data, offset, version):
        base     = offset
        mode     = struct.unpack(">I", data[offset+24:offset+28])[0]
        size     = struct.unpack(">I", data[offset+36:offset+40])[0]
        sha1     = data[offset+40:offset+60].hex()
        flags    = struct.unpack(">H", data[offset+60:offset+62])[0]
        extended = (flags >> 14) & 1
        name_len = flags & 0x0FFF
        name_start = offset + 62 + (2 if version >= 3 and extended else 0)

        if name_len < 0xFFF:
            raw_name = data[name_start:name_start + name_len]
            end      = name_start + name_len + 1
        else:
            nul = data.find(b"\x00", name_start)
            if nul == -1:
                return None, offset + 62
            raw_name = data[name_start:nul]
            end      = nul + 1

        padded = base + (((end - base) + 7) & ~7)

        try:
            filename = raw_name.decode("utf-8", errors="replace")
        except Exception:
            filename = raw_name.decode("latin-1", errors="replace")

        # Security: tolak path traversal
        if ".." in filename or filename.startswith("/"):
            return None, padded

        return IndexEntry(sha1=sha1, filename=filename,
                          mode=mode, file_size=size), padded


# ════════════════════════════════════════════════
# OBJECT PARSER  (loose objects, zlib-compressed)
# ════════════════════════════════════════════════

class ObjectParser:
    VALID_TYPES = {"blob", "tree", "commit", "tag"}
    _ID_RE      = re.compile(r"<([^>]+)>")
    _TS_RE      = re.compile(r">\s+(\d+)")

    def parse(self, data: bytes, sha1: str = "") -> Optional[GitObject]:
        """Dekompresi + parse satu loose object."""
        try:
            raw = zlib.decompress(data)
        except zlib.error:
            return None

        nul = raw.find(b"\x00")
        if nul == -1:
            return None

        try:
            header = raw[:nul].decode("ascii")
        except UnicodeDecodeError:
            return None

        parts = header.split(" ", 1)
        if len(parts) != 2 or parts[0] not in self.VALID_TYPES:
            return None

        try:
            size = int(parts[1])
        except ValueError:
            return None

        return GitObject(sha1=sha1, obj_type=parts[0],
                         size=size, data=raw[nul+1:])

    def parse_commit(self, obj: GitObject) -> Optional[CommitInfo]:
        if obj.obj_type != "commit":
            return None
        try:
            text = obj.data.decode("utf-8", errors="replace")
        except Exception:
            return None

        tree = ""
        parents = []
        author = author_email = ""
        author_ts = 0
        msg_lines = []
        in_msg = False

        for line in text.split("\n"):
            if in_msg:
                msg_lines.append(line)
                continue
            if line == "":
                in_msg = True
                continue
            if line.startswith("tree "):
                tree = line[5:].strip()
            elif line.startswith("parent "):
                parents.append(line[7:].strip())
            elif line.startswith("author "):
                body = line[7:]
                m_email = self._ID_RE.search(body)
                m_ts    = self._TS_RE.search(body)
                author_email = m_email.group(1) if m_email else ""
                author       = body.split("<")[0].strip()
                author_ts    = int(m_ts.group(1)) if m_ts else 0

        return CommitInfo(sha1=obj.sha1, tree=tree, parents=parents,
                          author=author, author_email=author_email,
                          author_ts=author_ts,
                          message="\n".join(msg_lines).strip())

    def parse_tree(self, obj: GitObject) -> list:
        if obj.obj_type != "tree":
            return []
        entries, data, pos = [], obj.data, 0
        while pos < len(data):
            sp  = data.find(b" ", pos)
            nul = data.find(b"\x00", sp + 1) if sp != -1 else -1
            if sp == -1 or nul == -1 or nul + 21 > len(data):
                break
            try:
                mode = data[pos:sp].decode("ascii").strip()
                name = data[sp+1:nul].decode("utf-8", errors="replace")
                sha1 = data[nul+1:nul+21].hex()
            except Exception:
                pos = nul + 21
                continue
            entries.append(TreeEntry(mode=mode, name=name, sha1=sha1))
            pos = nul + 21
        return entries

    def sha1_of(self, obj_type: str, content: bytes) -> str:
        header = f"{obj_type} {len(content)}\x00".encode()
        return hashlib.sha1(header + content).hexdigest()


# ════════════════════════════════════════════════
# PACK INDEX PARSER  (.git/objects/pack/*.idx)
# ════════════════════════════════════════════════

class PackIndexParser:
    MAGIC_V2 = b"\xff\x74\x4f\x63"

    def parse(self, data: bytes) -> list:
        """Returns list[str] SHA1 hex dari semua objects dalam pack."""
        if len(data) < 8:
            return []
        return self._v2(data) if data[:4] == self.MAGIC_V2 else self._v1(data)

    def _v2(self, data):
        if len(data) < 1032:
            return []
        N = struct.unpack(">I", data[8 + 255*4 : 8 + 256*4])[0]
        if N == 0 or N > 5_000_000:
            return []
        start = 1032
        return [data[start + i*20 : start + i*20 + 20].hex()
                for i in range(N) if start + i*20 + 20 <= len(data)]

    def _v1(self, data):
        if len(data) < 1024:
            return []
        N = struct.unpack(">I", data[255*4 : 256*4])[0]
        if N == 0 or N > 5_000_000:
            return []
        return [data[1024 + i*24 + 4 : 1024 + i*24 + 24].hex()
                for i in range(N) if 1024 + i*24 + 24 <= len(data)]


# ════════════════════════════════════════════════
# PACKED-REFS PARSER
# ════════════════════════════════════════════════

class PackedRefsParser:
    _REF_RE    = re.compile(r"^([0-9a-f]{40})\s+(.+)$")
    _PEEL_RE   = re.compile(r"^\^([0-9a-f]{40})$")

    def parse(self, text: str) -> list:
        """Returns list[RefEntry]."""
        refs, last = [], None
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = self._PEEL_RE.match(line)
            if m and last:
                last.peeled = m.group(1)
                continue
            m = self._REF_RE.match(line)
            if m:
                last = RefEntry(sha1=m.group(1), ref=m.group(2).strip())
                refs.append(last)
        return refs

    def sha1s(self, refs: list) -> set:
        s = set()
        for r in refs:
            s.add(r.sha1)
            if r.peeled:
                s.add(r.peeled)
        return s


# ════════════════════════════════════════════════
# CONFIG PARSER  (.git/config — INI-like)
# ════════════════════════════════════════════════

class ConfigParser:
    _SEC_RE = re.compile(r'^\[([^\]"]+?)(?:\s+"([^"]+)")?\]$')
    _KV_RE  = re.compile(r"^\s*(\w[\w-]*)\s*=\s*(.+)$")

    def parse(self, text: str) -> dict:
        result, current = {}, None
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            m = self._SEC_RE.match(line)
            if m:
                sec = m.group(1).strip()
                sub = m.group(2)
                current = f"{sec}.{sub}" if sub else sec
                result.setdefault(current, {})
                continue
            m = self._KV_RE.match(line)
            if m and current:
                result[current][m.group(1).strip()] = m.group(2).strip()
        return result

    def remote_urls(self, cfg: dict) -> list:
        out = []
        for sec, data in cfg.items():
            if sec.startswith("remote.") and "url" in data:
                out.append({"remote": sec.split(".", 1)[1], "url": data["url"]})
        return out

    def branches(self, cfg: dict) -> list:
        return [s.split(".", 1)[1] for s in cfg if s.startswith("branch.")]


# ════════════════════════════════════════════════
# SMALL UTILITIES
# ════════════════════════════════════════════════

_SHA1_RE   = re.compile(r"\b([0-9a-f]{40})\b")
_NULL_SHA1 = "0" * 40

def extract_sha1s(text: str) -> set:
    """Semua SHA1 40-char dari teks apapun, minus null SHA1."""
    return set(_SHA1_RE.findall(text)) - {_NULL_SHA1}

def parse_head(text: str) -> dict:
    text = text.strip()
    if text.startswith("ref: "):
        ref    = text[5:].strip()
        branch = ref.rsplit("/", 1)[-1]
        return {"type": "ref", "ref": ref, "branch": branch}
    if re.match(r"^[0-9a-f]{40}$", text):
        return {"type": "detached", "sha1": text, "branch": None}
    return {"type": "unknown"}

def parse_info_packs(text: str) -> list:
    """Returns list of pack SHA1 dari objects/info/packs."""
    return re.findall(r"P\s+pack-([0-9a-f]{40})\.pack", text)

def obj_path(sha1: str) -> str:
    """SHA1 → relative path dalam .git/objects/"""
    return f"objects/{sha1[:2]}/{sha1[2:]}"

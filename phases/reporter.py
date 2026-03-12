"""
phases/reporter.py
Phase 4 — Report: terminal summary berwarna + JSON ke disk.
Satu-satunya hal yang ditulis ke disk adalah file JSON report.
"""

import json
import os
from datetime  import datetime, timezone
from typing    import Optional


# ════════════════════════════════════════════════
# COLORS
# ════════════════════════════════════════════════

class C:
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    RED   = "\033[91m"
    ORA   = "\033[93m"
    YEL   = "\033[33m"
    GRN   = "\033[92m"
    CYN   = "\033[96m"
    BLU   = "\033[94m"
    MAG   = "\033[95m"
    WHT   = "\033[97m"
    GRY   = "\033[90m"

SEV_COLOR = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.ORA,
    "MEDIUM":   C.YEL,
    "LOW":      C.CYN,
}
CONF_COLOR = {
    "CONFIRMED": C.RED + C.BOLD,
    "HIGH":      C.ORA,
    "MEDIUM":    C.YEL,
    "LOW":       C.CYN,
    "NONE":      C.GRY,
}

def _risk_color(score: int) -> str:
    if score >= 70: return C.RED + C.BOLD
    if score >= 40: return C.ORA
    if score >= 15: return C.YEL
    return C.GRN

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


# ════════════════════════════════════════════════
# REPORTER
# ════════════════════════════════════════════════

class Reporter:
    def __init__(self, no_color: bool = False):
        self._nc = no_color

    # ── Banner ───────────────────────────────────

    def banner(self):
        art = r"""
  ██████╗ ██╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔════╝ ██║╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║  ███╗██║   ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║   ██║██║   ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚██████╔╝██║   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═════╝ ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""
        print(self._c(C.CYN + C.BOLD) + art + self._c(C.RST))
        print(self._c(C.GRY) + "  Git Exposure · Streaming Scanner · No disk required" + self._c(C.RST))
        print(self._c(C.GRY) + "  " + "─"*53 + self._c(C.RST) + "\n")

    # ── Phase 1: Detect ──────────────────────────

    def print_detect(self, r):
        b, rst = self._c(C.BOLD), self._c(C.RST)
        conf_c = self._c(CONF_COLOR.get(r.label, ""))
        icon   = "✅" if r.actionable else "⚠️ "

        print(f"\n{b}{'─'*58}{rst}")
        print(f"{b}  [1/4] DETECTION{rst}")
        print(f"{'─'*58}")
        print(f"  {b}Target    {rst}: {r.url}")
        print(f"  {b}Git URL   {rst}: {self._c(C.CYN)}{r.git_url}{rst}")
        print(f"  {b}Confidence{rst}: {conf_c}{r.label} ({r.confidence}%){rst}  {icon}")
        print(f"  {b}Dir List  {rst}: {'⚠️  ON' if r.listing else 'OFF'}")
        print(f"  {b}Server    {rst}: {r.server}")
        if r.branch:
            print(f"  {b}Branch    {rst}: {r.branch}")
        if r.remote_url:
            print(f"  {b}Remote    {rst}: {self._c(C.YEL)}{r.remote_url}{rst}")
        print()

    # ── Phase 2: Map ─────────────────────────────

    def print_map(self, m):
        b, rst = self._c(C.BOLD), self._c(C.RST)
        print(f"  {b}[2/4] MAP{rst}")
        print(f"  {'─'*50}")
        print(f"  SHA1s found   : {self._c(C.CYN)}{len(m.all_sha1s)}{rst}")
        print(f"  Blobs (index) : {len(m.blob_sha1s)}")
        print(f"  Commits/trees : {len(m.commit_sha1s)}")
        print(f"  Branches      : {', '.join(m.branches[:8]) or '—'}")
        if m.remote_urls:
            print(f"  Remote        : {self._c(C.YEL)}{m.remote_urls[0]['url']}{rst}")
        if m.pack_sha1s:
            print(f"  Pack files    : {len(m.pack_sha1s)}")
        print(f"  Est. disk size: {self._c(C.GRN)}{m.size_human}{rst} (if --save)")
        print()

    # ── Phase 3: Stream ──────────────────────────

    def print_stream_start(self, total: int):
        b, rst = self._c(C.BOLD), self._c(C.RST)
        print(f"  {b}[3/4] STREAMING & SCANNING{rst}")
        print(f"  {'─'*50}")
        print(f"  Scanning {self._c(C.CYN)}{total}{rst} objects in memory (no disk write)...")

    def progress_bar(self, done: int, total: int, findings: int):
        if total == 0:
            return
        pct  = done / total
        bar  = int(pct * 30)
        bar_s = "█" * bar + "░" * (30 - bar)
        sev_c = self._c(C.RED + C.BOLD) if findings > 0 else self._c(C.GRN)
        print(f"\r  [{bar_s}] {pct*100:5.1f}%  "
              f"{done}/{total} objs  "
              f"findings={sev_c}{findings}{self._c(C.RST)}   ",
              end="", flush=True)

    def print_stream_done(self, r):
        print()  # newline setelah progress bar
        b, rst = self._c(C.BOLD), self._c(C.RST)
        print(f"  Blobs scanned : {r.blobs_scanned}")
        print(f"  Data processed: {r.bytes_scanned // 1024:,} KB")
        print(f"  Elapsed       : {r.elapsed_s:.1f}s")
        print()

    # ── Phase 4: Report ──────────────────────────

    def print_report(self, detect, map_r, stream_r):
        b, rst  = self._c(C.BOLD), self._c(C.RST)
        risk_c  = self._c(_risk_color(stream_r.risk_score))
        counts  = stream_r.severity_counts

        print(f"  {b}[4/4] FINDINGS REPORT{rst}")
        print(f"  {'─'*50}")
        print(f"  Risk Score : {risk_c}{stream_r.risk_score}/100{rst}")
        print(f"  Secrets    : {b}{len(stream_r.findings)}{rst}  "
              f"[ {self._c(C.RED+C.BOLD)}CRIT:{counts.get('CRITICAL',0)}{rst} "
              f"{self._c(C.ORA)}HIGH:{counts.get('HIGH',0)}{rst} "
              f"{self._c(C.YEL)}MED:{counts.get('MEDIUM',0)}{rst} ]")

        if stream_r.tech_stack:
            print(f"  Tech Stack : {', '.join(stream_r.tech_stack)}")
        if stream_r.contributors:
            print(f"  Developers : {len(stream_r.contributors)} found")
            for c in stream_r.contributors[:4]:
                print(f"    · {c.name} <{self._c(C.CYN)}{c.email}{rst}>")
        print(f"  Commits    : ~{stream_r.commit_count}")

        # Deduplicate + sort by severity
        seen_keys = set()
        deduped   = []
        for f in sorted(stream_r.findings,
                        key=lambda x: _SEV_ORDER.get(x.severity, 99)):
            key = (f.pattern_id, f.match[:40])
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(f)

        if deduped:
            print(f"\n  {b}Secret Findings ({len(deduped)} unique):{rst}")
            for i, f in enumerate(deduped[:25], 1):
                sev_c  = self._c(SEV_COLOR.get(f.severity, ""))
                del_tag = self._c(C.GRY) + " [DELETED]" + rst if f.is_deleted else ""
                print(f"\n  {b}#{i}{rst} [{sev_c}{f.severity}{rst}] {f.description}{del_tag}")
                print(f"     File   : {self._c(C.CYN)}{f.filename}{rst}  line {f.line}")
                print(f"     Match  : {f.match[:100]}")
                print(f"     Context: {self._c(C.GRY)}{f.context[:120]}{rst}")
            if len(deduped) > 25:
                print(f"\n  ... +{len(deduped)-25} more findings in JSON report")

    # ── Final summary ────────────────────────────

    def print_summary(self, target: str, stream_r, report_path: str):
        b, rst  = self._c(C.BOLD), self._c(C.RST)
        risk_c  = self._c(_risk_color(stream_r.risk_score))
        print(f"\n{'═'*58}")
        print(f"{b}  DONE{rst}  |  {target}")
        print(f"{'═'*58}")
        print(f"  Risk Score : {risk_c}{stream_r.risk_score}/100{rst}")
        print(f"  Secrets    : {len(stream_r.findings)} findings "
              f"(0 bytes written to disk)")
        print(f"  Report     : {self._c(C.GRN)}{report_path}{rst}")
        print(f"{'═'*58}\n")

    # ── Save JSON ────────────────────────────────

    def save_json(self, path: str, target: str,
                  detect=None, map_r=None, stream_r=None) -> str:
        report = {
            "tool":      "GitRecon",
            "version":   "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target":    target,
        }

        if detect:
            report["detection"] = {
                "git_url":    detect.git_url,
                "git_path":   detect.git_url.split(target)[-1].lstrip("/"),
                "confidence": detect.confidence,
                "label":      detect.label,
                "listing":    detect.listing,
                "server":     detect.server,
                "branch":     detect.branch,
                "remote_url": detect.remote_url,
            }

        if map_r:
            report["map"] = {
                "total_sha1s":      len(map_r.all_sha1s),
                "blob_sha1s":       len(map_r.blob_sha1s),
                "commit_sha1s":     len(map_r.commit_sha1s),
                "branches":         map_r.branches,
                "remote_urls":      map_r.remote_urls,
                "pack_count":       len(map_r.pack_sha1s),
                "estimated_files":  map_r.estimated_files,
                "estimated_bytes":  map_r.estimated_bytes,
                "size_human":       map_r.size_human,
            }

        if stream_r:
            counts = stream_r.severity_counts
            report["result"] = {
                "risk_score":      stream_r.risk_score,
                "secrets_total":   len(stream_r.findings),
                "severity_counts": counts,
                "tech_stack":      stream_r.tech_stack,
                "commit_count":    stream_r.commit_count,
                "contributors":    [
                    {"name": c.name, "email": c.email}
                    for c in stream_r.contributors[:50]
                ],
                "blobs_scanned":   stream_r.blobs_scanned,
                "bytes_scanned":   stream_r.bytes_scanned,
                "elapsed_s":       round(stream_r.elapsed_s, 2),
                "findings":        [f.to_dict() for f in stream_r.findings],
            }

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        return path

    # ── Helper ───────────────────────────────────

    def _c(self, code: str) -> str:
        return "" if self._nc else code

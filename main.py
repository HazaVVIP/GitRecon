#!/usr/bin/env python3
"""
GitRecon v1.0.0
Streaming Git Exposure Scanner

Usage:
  python main.py <url> [options]

Examples:
  python main.py https://target.com
  python main.py https://target.com --save
  python main.py https://target.com --proxy socks5://127.0.0.1:9050
  python main.py https://target.com --delay 1.5 --timeout 15
  python main.py https://target.com --save --output ./hasil
  python main.py https://target.com --fuzz
  python main.py https://target.com --no-color -q
"""

import sys
import os
import re
import argparse
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.http_client  import HttpClient, HttpConfig
from phases            import detect, mapper, reporter
from phases.streamer   import Streamer


# ════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gitrecon",
        description="GitRecon — Streaming Git Exposure Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Cara pakai:
  python main.py https://target.com
  python main.py https://target.com --save
  python main.py https://target.com --proxy socks5://127.0.0.1:9050 --delay 1
  python main.py https://target.com --fuzz --timeout 15
        """
    )

    p.add_argument("url", help="Target URL (e.g., https://target.com)")

    # Save mode
    p.add_argument("--save", action="store_true",
                   help="Rekonstruksi source code ke disk setelah scan "
                        "(default: hanya report JSON yang disimpan)")
    p.add_argument("-o", "--output", default="./gitrecon_output",
                   metavar="DIR",
                   help="Direktori output (default: ./gitrecon_output)")

    # HTTP
    p.add_argument("--proxy",   metavar="URL",
                   help="Proxy URL, contoh: socks5://127.0.0.1:9050")
    p.add_argument("--timeout", type=int, default=10, metavar="SEC",
                   help="Timeout request (default: 10s)")
    p.add_argument("--retries", type=int, default=3, metavar="N",
                   help="Jumlah retry (default: 3)")
    p.add_argument("--delay",   type=float, default=0.0, metavar="SEC",
                   help="Delay antar request dalam detik (default: 0)")
    p.add_argument("--jitter",  type=float, default=0.0, metavar="SEC",
                   help="Jitter random maksimum (default: 0)")
    p.add_argument("--user-agent", metavar="UA",
                   help="Custom User-Agent")
    p.add_argument("--header",  action="append", dest="headers",
                   metavar="NAME:VALUE",
                   help="Header tambahan (bisa diulang)")

    # Scan options
    p.add_argument("--fuzz", action="store_true",
                   help="Coba non-standard .git paths (api/.git, admin/.git, dst)")
    p.add_argument("-w", "--workers", type=int, default=12, metavar="N",
                   help="Worker threads untuk streaming (default: 12)")
    p.add_argument("--mem-limit", type=int, default=256, metavar="MB",
                   help="Batas memori untuk streaming (default: 256MB)")
    p.add_argument("--min-confidence", type=int, default=45,
                   choices=[0, 20, 45, 70, 90],
                   help="Confidence minimum untuk lanjut scan (default: 45)")

    # Output
    p.add_argument("--no-color", action="store_true",
                   help="Matikan warna terminal")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Kurangi output terminal")

    return p


# ════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════

def build_client(args) -> HttpClient:
    headers = {}
    if args.headers:
        for h in args.headers:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    cfg = HttpConfig(
        timeout       = args.timeout,
        retries       = args.retries,
        delay         = args.delay,
        jitter        = args.jitter,
        proxy         = args.proxy,
        verify_ssl    = False,
        custom_ua     = getattr(args, "user_agent", None),
        extra_headers = headers,
    )
    return HttpClient(cfg)


def normalize_url(url: str) -> str:
    """Pastikan URL punya scheme dan tidak trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def target_name(url: str) -> str:
    """Buat nama file dari URL."""
    parsed = urllib.parse.urlparse(url)
    name   = parsed.netloc + parsed.path.replace("/", "_")
    # Bersihkan karakter tidak valid untuk filename
    name   = re.sub(r"[^\w\-\.]", "_", name)
    return name.strip("_") or "target"


def ask_save_confirm(size_human: str, estimated_files: int) -> bool:
    """Tanya user konfirmasi sebelum save ke disk."""
    print(f"\n  ⚠️  --save aktif")
    print(f"  Estimasi ukuran : {size_human} ({estimated_files} files)")
    print(f"  Disk akan terpakai sebesar estimasi di atas.")
    ans = input("  Lanjutkan? [y/N] ").strip().lower()
    return ans in ("y", "yes")


# ════════════════════════════════════════════════
# MAIN PIPELINE
# ════════════════════════════════════════════════

def main():
    parser = build_parser()
    args   = parser.parse_args()

    url      = normalize_url(args.url)
    rep      = reporter.Reporter(no_color=args.no_color)
    client   = build_client(args)
    verbose  = not args.quiet

    rep.banner()
    print(f"  Target: {url}\n")

    # ── Phase 1: Detect ──────────────────────────────────────────
    if verbose:
        print("  [→] Phase 1: Detecting .git exposure...")

    dr = detect.run(client, url, fuzz=args.fuzz)

    if not dr:
        print(f"\n  [✗] Tidak ada .git exposure terdeteksi di: {url}\n")
        sys.exit(1)

    rep.print_detect(dr)

    if dr.confidence < args.min_confidence:
        print(f"  [!] Confidence {dr.confidence}% di bawah threshold {args.min_confidence}%.")
        print(f"      Gunakan --min-confidence 0 untuk memaksa lanjut.\n")
        sys.exit(1)

    # ── Phase 2: Map ─────────────────────────────────────────────
    if verbose:
        print("  [→] Phase 2: Mapping objects...")

    m = mapper.Mapper(client)
    map_r = m.run(dr.git_url, branch=dr.branch)
    rep.print_map(map_r)

    if not map_r.all_sha1s:
        print("  [!] Tidak ada SHA1 ditemukan. Repository mungkin kosong atau terproteksi.\n")
        sys.exit(1)

    # ── --save confirmation ──────────────────────────────────────
    if args.save:
        if not ask_save_confirm(map_r.size_human, map_r.estimated_files):
            print("  Dibatalkan. Melanjutkan tanpa --save (mode online).")
            args.save = False
        print()

    # ── Phase 3: Stream & Scan ───────────────────────────────────
    total   = len(map_r.all_sha1s)
    streamer = Streamer(
        client       = client,
        workers      = args.workers,
        mem_limit_mb = args.mem_limit,
        verbose      = verbose,
    )

    rep.print_stream_start(total)
    findings_count = [0]

    def progress(done, total_):
        findings_count[0] = len(streamer._findings)
        if not args.quiet:
            rep.progress_bar(done, total_, findings_count[0])

    stream_r = streamer.run(dr.git_url, map_r, progress_cb=progress)
    rep.print_stream_done(stream_r)

    # ── Phase 4: Report ──────────────────────────────────────────
    rep.print_report(dr, map_r, stream_r)

    # Simpan JSON report
    tname       = target_name(url)
    report_path = os.path.join(args.output, f"{tname}_report.json")
    rep.save_json(report_path, url, detect=dr, map_r=map_r, stream_r=stream_r)

    # ── Optional: Reconstruct ────────────────────────────────────
    if args.save and map_r.index_entries:
        from phases.reconstructor import Reconstructor

        source_dir = os.path.join(args.output, tname)
        sha1_map   = {e.sha1: e.filename for e in map_r.index_entries}
        recon      = Reconstructor(client, workers=args.workers)

        print(f"\n  [→] Reconstructing {len(sha1_map)} files to disk...")
        done_save = [0]

        def save_progress(d, t):
            done_save[0] = d
            if not args.quiet:
                pct = d / t if t else 0
                bar = int(pct * 30)
                print(f"\r  [{'█'*bar}{'░'*(30-bar)}] {pct*100:5.1f}%  {d}/{t}",
                      end="", flush=True)

        stats = recon.run(dr.git_url, sha1_map, source_dir, progress_cb=save_progress)
        print(f"\n  Saved: {stats['saved']} files  Failed: {stats['failed']}")
        print(f"  Location: {source_dir}")

    # ── Summary ──────────────────────────────────────────────────
    rep.print_summary(url, stream_r, report_path)


if __name__ == "__main__":
    main()

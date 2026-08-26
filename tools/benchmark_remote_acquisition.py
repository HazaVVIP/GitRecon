"""Deterministic black-box benchmark for remote Git acquisition.

The benchmark creates a temporary single-commit repository, serves it through a
local HTTP server, runs the release binary against that fixture, and emits JSON
samples. It intentionally uses generic fixture text and never contacts a live
forge or target. Results are comparable only on the same machine and build
profile.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import tempfile
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


class QuietHandler(SimpleHTTPRequestHandler):
    """HTTP fixture handler without access-log noise."""

    def log_message(self, format: str, *args: object) -> None:
        return


def build_fixture(root: Path) -> tuple[Path, dict[str, int]]:
    repository = root / "fixture-repository"
    repository.mkdir()
    subprocess.run(
        ["git", "init", "--quiet", "--initial-branch=main", str(repository)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.name", "GitRecon Fixture"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "fixture@example.invalid"],
        check=True,
    )
    content = (
        "service.fixture.enabled=true\n"
        "service.fixture.region=local\n"
        "service.fixture.note=deterministic acquisition fixture\n"
    )
    config = repository / "config" / "fixture.txt"
    config.parent.mkdir()
    config.write_text(content, encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "commit",
            "--quiet",
            "-m",
            "fixture commit",
        ],
        check=True,
    )
    return repository, {"files": 1, "commits": 1, "bytes": len(content.encode("utf-8"))}


def report_file(output: Path) -> Path:
    reports = sorted(output.glob("*.json"))
    if not reports:
        raise RuntimeError(f"no JSON report generated in {output}")
    return reports[0]


def process_peak_rss_bytes(pid: int) -> int | None:
    """Read Linux VmHWM for a running child; return null on unsupported hosts."""

    status_path = Path(f"/proc/{pid}/status")
    try:
        for line in status_path.read_text(encoding="utf-8").splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    except (FileNotFoundError, OSError, ValueError):
        return None
    return None


def run_once(binary: Path, target: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="gitrecon-remote-bench-output-") as output_dir:
        output = Path(output_dir)
        command = [
            str(binary),
            target,
            "--output",
            str(output),
            "--format",
            "json",
            "--quiet",
            "--no-color",
            "--no-cache",
            "--workers",
            "4",
        ]
        started = time.perf_counter()
        completed_process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        peak_rss_bytes: int | None = None
        while completed_process.poll() is None:
            current_rss = process_peak_rss_bytes(completed_process.pid)
            if current_rss is not None:
                peak_rss_bytes = max(peak_rss_bytes or 0, current_rss)
            time.sleep(0.01)
        stdout, stderr = completed_process.communicate()
        elapsed = time.perf_counter() - started
        if completed_process.returncode != 0:
            raise RuntimeError(
                f"gitrecon failed with {completed_process.returncode}: {stderr.strip()}"
            )
        report = json.loads(report_file(output).read_text(encoding="utf-8"))
        result = report.get("result", {})
        source_stats = result.get("object_sources", {})
        outcome_stats = result.get("outcomes", {})
        cache_stats = result.get("cache")
        retry_stats = result.get("retry")
        scheduler_stats = outcome_stats.get("scheduler") or {}
        resource_by_stage = outcome_stats.get("resource_by_stage") or {}
        blobs_scanned = result.get("blobs_scanned", 0)
        bytes_scanned = result.get("bytes_scanned", 0)
        if not any(
            source_stats.get(key, 0) > 0 for key in ("pack", "cache", "loose_http")
        ):
            raise RuntimeError(
                "remote fixture did not exercise object acquisition; "
                f"stdout={stdout[-500:]!r} stderr={stderr[-500:]!r}"
            )
        return {
            "elapsed_s": elapsed,
            "peak_rss_bytes": peak_rss_bytes,
            "throughput": {
                "bytes_per_s": bytes_scanned / elapsed if elapsed else 0.0,
                "blobs_per_s": blobs_scanned / elapsed if elapsed else 0.0,
            },
            "cache": cache_stats,
            "retry": retry_stats,
            "findings": len(result.get("findings", [])),
            "objects": {
                "pack": source_stats.get("pack", 0),
                "cache": source_stats.get("cache", 0),
                "loose_http": source_stats.get("loose_http", 0),
            },
            "outcomes": {
                "blobs_scanned": blobs_scanned,
                "bytes_scanned": bytes_scanned,
                "blobs_failed": outcome_stats.get("blobs_failed", 0),
                "skipped_files": outcome_stats.get("skipped_files", 0),
            },
            "observability": {
                "scheduler": scheduler_stats,
                "resource_peak_bytes": outcome_stats.get("resource_peak_bytes", 0),
                "resource_denied_reservations": outcome_stats.get(
                    "resource_denied_reservations", 0
                ),
                "resource_by_stage": resource_by_stage,
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/gitrecon"))
    parser.add_argument(
        "--build-profile",
        choices=("release", "debug", "custom"),
        default="release",
        help="Profile used to build the benchmark binary (default: release)",
    )
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")

    with tempfile.TemporaryDirectory(prefix="gitrecon-remote-bench-fixture-") as fixture_dir:
        root = Path(fixture_dir)
        _, fixture_metadata = build_fixture(root)
        handler = lambda *handler_args, **handler_kwargs: QuietHandler(
            *handler_args, directory=str(root), **handler_kwargs
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}/fixture-repository"
            samples = [run_once(args.binary, target) for _ in range(args.repetitions)]
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

    elapsed_values = [sample["elapsed_s"] for sample in samples]
    peak_rss_values = [
        sample["peak_rss_bytes"]
        for sample in samples
        if sample["peak_rss_bytes"] is not None
    ]
    throughput_bytes_values = [sample["throughput"]["bytes_per_s"] for sample in samples]
    throughput_blobs_values = [sample["throughput"]["blobs_per_s"] for sample in samples]
    scheduler_queue_wait_values = [
        sample["observability"]["scheduler"].get("queue_wait_ms", 0)
        for sample in samples
    ]
    scheduler_queued_values = [
        sample["observability"]["scheduler"].get("queued_acquires", 0)
        for sample in samples
    ]
    resource_peak_values = [
        sample["observability"].get("resource_peak_bytes", 0) for sample in samples
    ]
    resource_denied_values = [
        sample["observability"].get("resource_denied_reservations", 0)
        for sample in samples
    ]
    median_elapsed = statistics.median(elapsed_values)
    print(
        json.dumps(
            {
                "fixture": {
                    "description": "temporary single-commit Git repository over localhost HTTP",
                    **fixture_metadata,
                },
                "build_profile": args.build_profile,
                "host": {
                    "os": platform.system(),
                    "architecture": platform.machine(),
                    "python": platform.python_version(),
                    "cpu_count": os.cpu_count(),
                },
                "repetitions": args.repetitions,
                "samples": samples,
                "summary": {
                    "median_elapsed_s": median_elapsed,
                    "mean_elapsed_s": statistics.mean(elapsed_values),
                    "min_elapsed_s": min(elapsed_values),
                    "max_elapsed_s": max(elapsed_values),
                    "elapsed_variance_s2": statistics.pvariance(elapsed_values),
                    "peak_rss_bytes": max(peak_rss_values) if peak_rss_values else None,
                    "mean_throughput_bytes_per_s": statistics.mean(throughput_bytes_values),
                    "median_throughput_bytes_per_s": statistics.median(throughput_bytes_values),
                    "mean_throughput_blobs_per_s": statistics.mean(throughput_blobs_values),
                    "median_throughput_blobs_per_s": statistics.median(throughput_blobs_values),
                    "mean_scheduler_queue_wait_ms": statistics.mean(scheduler_queue_wait_values),
                    "median_scheduler_queue_wait_ms": statistics.median(
                        scheduler_queue_wait_values
                    ),
                    "mean_scheduler_queued_acquires": statistics.mean(scheduler_queued_values),
                    "median_scheduler_queued_acquires": statistics.median(scheduler_queued_values),
                    "resource_peak_bytes": max(resource_peak_values),
                    "mean_resource_peak_bytes": statistics.mean(resource_peak_values),
                    "resource_denied_reservations": sum(resource_denied_values),
                    "relative_spread": (
                        (max(elapsed_values) - min(elapsed_values)) / median_elapsed
                        if median_elapsed
                        else 0.0
                    ),
                },
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()


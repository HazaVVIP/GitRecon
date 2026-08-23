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


def build_fixture(root: Path) -> Path:
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
    return repository


def report_file(output: Path) -> Path:
    reports = sorted(output.glob("*.json"))
    if not reports:
        raise RuntimeError(f"no JSON report generated in {output}")
    return reports[0]


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
        completed = subprocess.run(command, capture_output=True, text=True)
        elapsed = time.perf_counter() - started
        if completed.returncode != 0:
            raise RuntimeError(
                f"gitrecon failed with {completed.returncode}: {completed.stderr.strip()}"
            )
        report = json.loads(report_file(output).read_text(encoding="utf-8"))
        result = report.get("result", {})
        source_stats = result.get("object_sources", {})
        outcome_stats = result.get("outcomes", {})
        if not any(
            source_stats.get(key, 0) > 0 for key in ("pack", "cache", "loose_http")
        ):
            raise RuntimeError(
                "remote fixture did not exercise object acquisition; "
                f"stdout={completed.stdout[-500:]!r} stderr={completed.stderr[-500:]!r}"
            )
        return {
            "elapsed_s": elapsed,
            "findings": len(result.get("findings", [])),
            "objects": {
                "pack": source_stats.get("pack", 0),
                "cache": source_stats.get("cache", 0),
                "loose_http": source_stats.get("loose_http", 0),
            },
            "outcomes": {
                "blobs_scanned": result.get("blobs_scanned", 0),
                "bytes_scanned": result.get("bytes_scanned", 0),
                "blobs_failed": outcome_stats.get("blobs_failed", 0),
                "skipped_files": outcome_stats.get("skipped_files", 0),
            },
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/gitrecon"))
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")

    with tempfile.TemporaryDirectory(prefix="gitrecon-remote-bench-fixture-") as fixture_dir:
        root = Path(fixture_dir)
        build_fixture(root)
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

    print(
        json.dumps(
            {
                "fixture": "temporary single-commit Git repository over localhost HTTP",
                "repetitions": args.repetitions,
                "samples": samples,
                "summary": {
                    "median_elapsed_s": statistics.median(
                        sample["elapsed_s"] for sample in samples
                    ),
                    "min_elapsed_s": min(sample["elapsed_s"] for sample in samples),
                    "max_elapsed_s": max(sample["elapsed_s"] for sample in samples),
                },
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()


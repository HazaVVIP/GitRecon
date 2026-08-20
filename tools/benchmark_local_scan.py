#!/usr/bin/env python3
"""Black-box local scanner benchmark for release regression checks.

The fixture intentionally contains generic configuration-like text rather than
credential-shaped literals. Results are comparable within the same machine and
build profile; they are not cross-machine performance claims.
"""

from __future__ import annotations

import argparse
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


def build_fixture(root: Path, files: int, lines: int) -> None:
    template = (
        "service.fixture.enabled=true\n"
        "service.fixture.region=local\n"
        "service.fixture.endpoint=https://fixture.invalid/api\n"
        "service.fixture.note=benchmark text without sensitive material\n"
    )
    payload = template * lines
    for index in range(files):
        path = root / ("src" if index % 2 else "config") / f"fixture_{index:04}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")


def run_once(binary: Path, fixture: Path, exhaustive: bool) -> float:
    with tempfile.TemporaryDirectory(prefix="gitrecon-bench-output-") as output:
        command = [
            str(binary),
            "--dir",
            str(fixture),
            "--output",
            output,
            "--format",
            "json",
            "--quiet",
            "--no-color",
            "--workers",
            "50",
        ]
        if exhaustive:
            command.append("--exhaustive")
        started = time.perf_counter()
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return time.perf_counter() - started


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/gitrecon"))
    parser.add_argument("--files", type=int, default=40)
    parser.add_argument("--lines", type=int, default=250)
    parser.add_argument("--repetitions", type=int, default=3)
    args = parser.parse_args()
    if args.files < 1 or args.lines < 1 or args.repetitions < 1:
        parser.error("files, lines, and repetitions must be positive")
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")

    with tempfile.TemporaryDirectory(prefix="gitrecon-bench-fixture-") as fixture_dir:
        fixture = Path(fixture_dir)
        build_fixture(fixture, args.files, args.lines)
        print(f"fixture_files={args.files} fixture_lines_per_file={args.lines}")
        for label, exhaustive in (("normal", False), ("exhaustive", True)):
            samples = [run_once(args.binary, fixture, exhaustive) for _ in range(args.repetitions)]
            print(
                f"mode={label} samples_s={','.join(f'{sample:.4f}' for sample in samples)} "
                f"median_s={statistics.median(samples):.4f} min_s={min(samples):.4f}"
            )


if __name__ == "__main__":
    main()

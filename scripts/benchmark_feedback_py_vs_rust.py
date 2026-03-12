#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUST_CRATE = ROOT / "rust_feedback_bench"
RUST_BIN = RUST_CRATE / "target" / "release" / "rust_feedback_bench"
PY_BENCH = ROOT / "scripts" / "benchmark_feedback_python.py"


def run_command(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)


def parse_time_v(stderr: str) -> dict[str, float]:
    def find(pattern: str) -> float:
        match = re.search(pattern, stderr)
        return float(match.group(1)) if match else 0.0

    max_rss_kb = find(r"Maximum resident set size \(kbytes\):\s*(\d+)")
    return {
        "max_rss_kb": max_rss_kb,
        "max_rss_mb": round(max_rss_kb / 1024.0, 3),
        "user_sec": find(r"User time \(seconds\):\s*([0-9.]+)"),
        "sys_sec": find(r"System time \(seconds\):\s*([0-9.]+)"),
        "cpu_percent": find(r"Percent of CPU this job got:\s*(\d+)"),
    }


def parse_json_stdout(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        text = line.strip()
        if text.startswith("{") and text.endswith("}"):
            return json.loads(text)
    raise RuntimeError("json payload not found in stdout")


def generate_input_lines(
    *,
    row_count: int,
    existing_ratio: float,
    loops: int,
    min_hits: int,
) -> list[str]:
    rng = random.Random(20260311)
    feedback_types = ["false_positive", "false_negative", "true_positive"]
    rows: list[tuple[str, str, str, int]] = []
    for idx in range(row_count):
        rows.append(
            (
                f"ipros-{idx % 8}",
                f"rule-{idx:06d}",
                feedback_types[idx % len(feedback_types)],
                1 + ((idx * 7) % 9),
            )
        )

    existing_count = int(row_count * existing_ratio)
    sampled_indices = rng.sample(range(row_count), k=min(existing_count, row_count))
    existing: list[tuple[str, str, str]] = []
    for idx in sampled_indices:
        row = rows[idx]
        existing.append((row[0], row[1], f"feedback_{row[2]}"))

    lines: list[str] = [f"CONFIG|{loops}|{min_hits}"]
    for source_product, source_ref, feedback_type, count in rows:
        lines.append(f"ROW|{source_product}|{source_ref}|{feedback_type}|{count}")
    for source_product, target_ref, candidate_type in existing:
        lines.append(f"EXISTING|{source_product}|{target_ref}|{candidate_type}")
    return lines


def run_python(input_path: Path) -> dict[str, Any]:
    proc = run_command(
        ["/usr/bin/time", "-v", "python3", str(PY_BENCH), str(input_path)],
        cwd=ROOT,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"python bench failed\nstdout={proc.stdout}\nstderr={proc.stderr}")
    payload = parse_json_stdout(proc.stdout)
    payload["resource"] = parse_time_v(proc.stderr)
    return payload


def run_rust(input_path: Path) -> dict[str, Any]:
    build = run_command(["cargo", "build", "--release", "--quiet"], cwd=RUST_CRATE)
    if build.returncode != 0:
        raise RuntimeError(f"rust build failed\nstdout={build.stdout}\nstderr={build.stderr}")

    proc = run_command(
        ["/usr/bin/time", "-v", str(RUST_BIN), "bench", str(input_path)],
        cwd=RUST_CRATE,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"rust bench failed\nstdout={proc.stdout}\nstderr={proc.stderr}")
    payload = parse_json_stdout(proc.stdout)
    payload["resource"] = parse_time_v(proc.stderr)
    return payload


def calc_ratio(numerator: float, denominator: float) -> float | None:
    if denominator <= 0:
        return None
    return numerator / denominator


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=120000)
    parser.add_argument("--existing-ratio", type=float, default=0.35)
    parser.add_argument("--loops", type=int, default=10)
    parser.add_argument("--min-hits", type=int, default=3)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "docs" / "perf_soc_feedback_py_vs_rust.json",
    )
    args = parser.parse_args()

    input_lines = generate_input_lines(
        row_count=max(1, args.rows),
        existing_ratio=max(0.0, min(args.existing_ratio, 0.95)),
        loops=max(1, args.loops),
        min_hits=max(1, args.min_hits),
    )

    with NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as fp:
        temp_input = Path(fp.name)
        fp.write("\n".join(input_lines))

    try:
        python_result = run_python(temp_input)
        rust_result = run_rust(temp_input)
    finally:
        temp_input.unlink(missing_ok=True)

    py_elapsed = float(python_result.get("elapsed_sec", 0.0))
    rust_elapsed = float(rust_result.get("elapsed_sec", 0.0))
    py_rss = float(python_result.get("resource", {}).get("max_rss_mb", 0.0))
    rust_rss = float(rust_result.get("resource", {}).get("max_rss_mb", 0.0))

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "workload": {
            "rows": args.rows,
            "existing_ratio": args.existing_ratio,
            "loops": args.loops,
            "min_hits": args.min_hits,
        },
        "python": python_result,
        "rust": rust_result,
        "comparison": {
            "speedup_rust_vs_python": calc_ratio(py_elapsed, rust_elapsed),
            "rss_ratio_rust_vs_python": calc_ratio(rust_rss, py_rss),
            "rss_reduction_percent": (1.0 - calc_ratio(rust_rss, py_rss)) * 100.0 if py_rss > 0 else None,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    json_text = json.dumps(summary, indent=2)
    args.out.write_text(json_text, encoding="utf-8")
    print(json_text)


if __name__ == "__main__":
    main()

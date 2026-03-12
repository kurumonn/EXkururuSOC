#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any


def parse_input(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]], int, int]:
    rows: list[dict[str, Any]] = []
    existing: list[dict[str, str]] = []
    loops = 0
    min_hits = 0

    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        parts = line.split("|")
        if parts[0] == "CONFIG":
            if len(parts) != 3:
                raise ValueError(f"invalid CONFIG line: {line_no}")
            loops = int(parts[1])
            min_hits = int(parts[2])
        elif parts[0] == "ROW":
            if len(parts) != 5:
                raise ValueError(f"invalid ROW line: {line_no}")
            rows.append(
                {
                    "source_product": parts[1],
                    "source_ref": parts[2],
                    "feedback_type": parts[3],
                    "c": int(parts[4]),
                }
            )
        elif parts[0] == "EXISTING":
            if len(parts) != 4:
                raise ValueError(f"invalid EXISTING line: {line_no}")
            existing.append(
                {
                    "source_product": parts[1],
                    "target_ref": parts[2],
                    "candidate_type": parts[3],
                }
            )
        else:
            raise ValueError(f"unknown record type at line: {line_no}")

    if loops < 1:
        raise ValueError("invalid loops")
    if min_hits < 1:
        raise ValueError("invalid min_hits")
    return rows, existing, loops, min_hits


def run_once(
    rows: list[dict[str, Any]],
    min_hits: int,
    base_existing_keys: set[tuple[str, str, str]],
) -> int:
    existing_keys = set(base_existing_keys)
    created = 0
    for row in rows:
        hit_count = int(row["c"])
        if hit_count < min_hits:
            continue
        source_product = str(row["source_product"])
        source_ref = str(row["source_ref"])
        feedback_type = str(row["feedback_type"])
        dedupe_key = (source_product, source_ref, f"feedback_{feedback_type}")
        if dedupe_key in existing_keys:
            continue

        recommended_action = "reduce_score" if feedback_type == "false_positive" else "raise_score"
        proposal = {
            "strategy": "feedback_driven_tuning",
            "feedback_type": feedback_type,
            "source_ref": source_ref,
            "recommended_action": recommended_action,
        }
        evidence = {"feedback_hits": hit_count, "source_ref": source_ref, "feedback_type": feedback_type}
        expected = {"false_positive_delta": -0.1 if feedback_type == "false_positive" else 0.0}
        _serialized_len = len(json.dumps(proposal)) + len(json.dumps(evidence)) + len(json.dumps(expected))
        if _serialized_len < 0:
            raise RuntimeError("unreachable")

        existing_keys.add(dedupe_key)
        created += 1
    return created


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_json", type=Path)
    args = parser.parse_args()

    rows, existing, loops, min_hits = parse_input(args.input_json)

    base_existing_keys = {
        (str(item["source_product"]), str(item["target_ref"]), str(item["candidate_type"])) for item in existing
    }

    started = time.perf_counter()
    total_created = 0
    for _ in range(loops):
        total_created += run_once(rows, min_hits, base_existing_keys)
    elapsed_sec = time.perf_counter() - started
    loops_per_sec = (float(loops) / elapsed_sec) if elapsed_sec > 0 else 0.0

    print(
        json.dumps(
            {
                "loops": loops,
                "min_hits": min_hits,
                "row_count": len(rows),
                "existing_count": len(existing),
                "total_created": total_created,
                "elapsed_sec": elapsed_sec,
                "loops_per_sec": loops_per_sec,
            }
        )
    )


if __name__ == "__main__":
    main()

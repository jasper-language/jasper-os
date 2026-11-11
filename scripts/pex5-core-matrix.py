#!/usr/bin/env python3
"""Validate PEX-5 host heap size-class and growth-tail evidence."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path


SIZES = {16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048, 4096, 8192}
GROWTH = {64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024}


def fail(message: str) -> None:
    print(f"PEX-5 core: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    rows = []
    for line in Path(args.input).read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    sizes = {row["bytes"]: row for row in rows if row.get("case") == "size-class"}
    growth = {
        row["request_bytes"]: row for row in rows if row.get("case") == "growth-tail"
    }
    if set(sizes) != SIZES:
        fail(f"size-class mismatch: {sorted(set(sizes) ^ SIZES)}")
    if set(growth) != GROWTH:
        fail(f"growth-tail mismatch: {sorted(set(growth) ^ GROWTH)}")
    for size, row in sizes.items():
        if row.get("count", 0) <= 0:
            fail(f"empty size class {size}")
        if row.get("free_bytes") != row.get("total_bytes"):
            fail(f"size class {size} did not return all bytes")
        if row.get("final_free_blocks") != 1:
            fail(f"size class {size} did not coalesce")
    for request, row in growth.items():
        if not row.get("allocated") or row.get("extends", 0) <= 0:
            fail(f"growth case {request} is incomplete")
        if row.get("mapped_bytes", 0) < request:
            fail(f"growth case {request} mapped too little")

    ordered = [sizes[size] for size in sorted(sizes)]
    result = {
        "schema": 1,
        "stage": "PEX-5-core",
        "coverage": {
            "size_classes": len(sizes),
            "growth_cases": len(growth),
            "complete": True,
        },
        "size_classes": ordered,
        "growth_tail": [growth[value] for value in sorted(growth)],
        "alloc_p999_ns_median": statistics.median(
            row["alloc_p999_ns"] for row in ordered
        ),
        "free_p999_ns_median": statistics.median(
            row["free_p999_ns"] for row in ordered
        ),
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "pex5-core-matrix.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"PEX-5 core: PASS evidence={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

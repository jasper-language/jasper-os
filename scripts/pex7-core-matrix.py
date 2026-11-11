#!/usr/bin/env python3
"""Validate PEX-7 host frame allocator and cache-model evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    print(f"PEX-7 core: FAIL: {message}", file=sys.stderr)
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
    baseline = [row for row in rows if row.get("case") == "baseline"]
    models = {row["cpus"]: row for row in rows if row.get("case") == "cache-model"}
    if len(baseline) != 1 or not baseline[0].get("reclaimed"):
        fail("central bitmap baseline missing or unreclaimed")
    if set(models) != {1, 2, 4, 8}:
        fail(f"CPU model mismatch: {sorted(set(models) ^ {1, 2, 4, 8})}")
    if any(not row.get("reclaimed") for row in models.values()):
        fail("cache model did not reclaim every frame")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    result = {
        "schema": 1,
        "stage": "PEX-7-core",
        "coverage": {"cpus": sorted(models), "complete": True},
        "baseline": baseline[0],
        "cache_models": [models[cpu] for cpu in sorted(models)],
    }
    (out / "pex7-core-matrix.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"PEX-7 core: PASS evidence={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

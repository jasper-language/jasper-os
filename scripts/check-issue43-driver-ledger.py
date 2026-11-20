#!/usr/bin/env python3
"""Validate the Issue #43 compatibility-driver-domain requirement ledger."""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "verification" / "issue43-driver-domain-ledger.tsv"
EXPECTED_IDS = [f"D{index:02d}" for index in range(1, 13)]
HEADER = [
    "id",
    "requirement",
    "compatible_surface",
    "native_authority",
    "evidence_paths",
    "status",
    "layers",
    "remaining_gate",
]
STATUSES = {"missing", "software-contract", "partial", "blocked-hardware"}
LAYERS = {"core", "service", "runtime", "compat", "verification"}


def validate(rows: list[dict[str, str]], root: Path = ROOT) -> None:
    if not rows or list(rows[0]) != HEADER:
        raise ValueError("ledger header drift")
    if [row["id"] for row in rows] != EXPECTED_IDS:
        raise ValueError("ledger IDs must be exactly D01..D12 in order")
    for row in rows:
        row_id = row["id"]
        for field in HEADER:
            if not row[field].strip():
                raise ValueError(f"{row_id}: empty {field}")
        if row["status"] not in STATUSES:
            raise ValueError(f"{row_id}: invalid status {row['status']}")
        if any(layer not in LAYERS for layer in row["layers"].split(";")):
            raise ValueError(f"{row_id}: invalid layers {row['layers']}")
        for evidence in row["evidence_paths"].split(";"):
            if not (root / evidence.strip()).exists():
                raise ValueError(f"{row_id}: missing evidence path {evidence}")


def self_test() -> None:
    rows = []
    for row_id in EXPECTED_IDS:
        row = {field: "value" for field in HEADER}
        row.update(
            {
                "id": row_id,
                "status": "partial",
                "layers": "core;compat",
                "evidence_paths": "Cargo.toml",
            }
        )
        rows.append(row)
    validate(rows)
    invalid = [dict(row) for row in rows]
    invalid[0]["status"] = "done"
    try:
        validate(invalid)
    except ValueError as error:
        assert "invalid status" in str(error)
    else:
        raise AssertionError("self-test accepted invalid status")
    print("issue43-driver-ledger: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        with LEDGER.open(newline="", encoding="utf-8") as source:
            rows = list(csv.DictReader(source, delimiter="\t"))
        validate(rows)
    except (OSError, ValueError, csv.Error) as error:
        print(f"issue43-driver-ledger: FAIL {error}", file=sys.stderr)
        return 1
    counts = Counter(row["status"] for row in rows)
    print(
        "issue43-driver-ledger: PASS "
        + " ".join(f"{name}={counts[name]}" for name in sorted(STATUSES))
        + f" total={len(rows)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

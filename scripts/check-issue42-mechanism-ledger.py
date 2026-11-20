#!/usr/bin/env python3
"""Validate the machine-readable Issue #42 mechanism audit ledger."""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "verification" / "issue42-mechanism-ledger.tsv"
EXPECTED_IDS = [f"M{index:02d}" for index in range(1, 26)]
HEADER = [
    "id",
    "external_source",
    "compatible_surfaces",
    "native_authority",
    "coverage",
    "status",
    "layers",
    "evidence_paths",
    "remaining_gate",
]
STATUSES = {"implemented-tested", "partial", "research", "compat-retained"}
LAYERS = {"core", "service", "runtime", "compat", "verification"}


def validate(rows: list[dict[str, str]], root: Path = ROOT) -> None:
    if not rows:
        raise ValueError("ledger is empty")
    if list(rows[0]) != HEADER:
        raise ValueError("ledger header drift")
    ids = [row["id"] for row in rows]
    if ids != EXPECTED_IDS:
        raise ValueError(
            f"ledger IDs must be exactly {EXPECTED_IDS[0]}..{EXPECTED_IDS[-1]} in order"
        )
    for row in rows:
        row_id = row["id"]
        for field in HEADER:
            if not row[field].strip():
                raise ValueError(f"{row_id}: empty {field}")
        if row["status"] not in STATUSES:
            raise ValueError(f"{row_id}: invalid status {row['status']}")
        layers = row["layers"].split(";")
        if not layers or any(not layer or layer not in LAYERS for layer in layers):
            raise ValueError(f"{row_id}: invalid layers {row['layers']}")
        if "core;compat" in row["coverage"]:
            raise ValueError(f"{row_id}: coverage contains an implementation field")
        for evidence in row["evidence_paths"].split(";"):
            path = root / evidence.strip()
            if not path.exists():
                raise ValueError(f"{row_id}: missing evidence path {evidence}")


def load(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source, delimiter="\t"))


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
    invalid_status = [dict(row) for row in rows]
    invalid_status[0]["status"] = "done"
    try:
        validate(invalid_status)
    except ValueError as error:
        assert "invalid status" in str(error)
    else:
        raise AssertionError("self-test did not reject an invalid status")
    missing_evidence = [dict(row) for row in rows]
    missing_evidence[-1]["evidence_paths"] = "missing-issue42-evidence"
    try:
        validate(missing_evidence)
    except ValueError as error:
        assert "missing evidence path" in str(error)
    else:
        raise AssertionError("self-test did not reject missing evidence")
    print("issue42-mechanism-ledger: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        rows = load(LEDGER)
        validate(rows)
    except (OSError, ValueError, csv.Error) as error:
        print(f"issue42-mechanism-ledger: FAIL {error}", file=sys.stderr)
        return 1
    counts = Counter(row["status"] for row in rows)
    print(
        "issue42-mechanism-ledger: PASS "
        + " ".join(f"{name}={counts[name]}" for name in sorted(STATUSES))
        + f" total={len(rows)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

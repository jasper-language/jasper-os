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
RESOLVED_STATUSES = {"implemented-tested", "compat-retained"}
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


def validate_final(rows: list[dict[str, str]]) -> None:
    """Require every Issue #42 mechanism to have a final disposition."""
    unresolved = [
        f"{row['id']}={row['status']}"
        for row in rows
        if row["status"] not in RESOLVED_STATUSES
    ]
    if unresolved:
        raise ValueError(
            "Issue #42 has unresolved mechanism families: " + ", ".join(unresolved)
        )
    for row in rows:
        gate = row["remaining_gate"]
        if row["status"] == "implemented-tested":
            prefix = f"No {row['id']} "
            if not gate.startswith(prefix) or "gate remains;" not in gate:
                raise ValueError(
                    f"{row['id']}: implemented-tested remaining_gate must start with "
                    f"{prefix!r} and state that the gate remains closed"
                )
        elif not gate.startswith("Permanent compatibility boundary:"):
            raise ValueError(
                f"{row['id']}: compat-retained row must state the permanent "
                "compatibility boundary"
            )


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
    unresolved = [dict(row) for row in rows]
    unresolved[0]["status"] = "partial"
    try:
        validate_final(unresolved)
    except ValueError as error:
        assert "unresolved mechanism families" in str(error)
    else:
        raise AssertionError("final self-test did not reject a partial mechanism")
    resolved = [dict(row) for row in rows]
    for row in resolved:
        row["status"] = "implemented-tested"
        row["remaining_gate"] = f"No {row['id']} gate remains; covered"
    validate_final(resolved)
    stale_language = [dict(row) for row in resolved]
    stale_language[0]["remaining_gate"] = "pending implementation"
    try:
        validate_final(stale_language)
    except ValueError as error:
        assert "remaining_gate" in str(error)
    else:
        raise AssertionError("final self-test did not reject stale gate text")
    print("issue42-mechanism-ledger: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--final",
        action="store_true",
        help="require every mechanism family to be implemented-tested or compat-retained",
    )
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        rows = load(LEDGER)
        validate(rows)
        if args.final:
            validate_final(rows)
    except (OSError, ValueError, csv.Error) as error:
        print(f"issue42-mechanism-ledger: FAIL {error}", file=sys.stderr)
        return 1
    counts = Counter(row["status"] for row in rows)
    print(
        f"issue42-mechanism-ledger: {'FINAL PASS' if args.final else 'PASS'} "
        + " ".join(f"{name}={counts[name]}" for name in sorted(STATUSES))
        + f" total={len(rows)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

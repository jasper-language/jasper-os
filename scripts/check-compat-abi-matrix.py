#!/usr/bin/env python3
"""Validate the reusable Linux/POSIX compatibility ABI evidence matrix."""

from __future__ import annotations

import argparse
import copy
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "verification/linux-posix-abi-matrix.toml"
REQUIRED_ITEM_FIELDS = {
    "id",
    "abi",
    "positive_coverage",
    "negative_coverage",
    "evidence",
    "commit",
    "environment",
    "status",
}
STATUSES = {"mapped", "partial", "missing", "stale", "verified"}


def fail(message: str) -> None:
    raise ValueError(message)


def validate(matrix: dict, root: Path = ROOT) -> dict[str, int]:
    if matrix.get("schema") != 1:
        fail("schema must be 1")
    if matrix.get("scope") != "compat-linux-posix":
        fail("scope must be compat-linux-posix")
    if matrix.get("baseline") != "Ubuntu Linux x86_64":
        fail("baseline must be Ubuntu Linux x86_64")
    if not str(matrix.get("updated", "")).strip():
        fail("updated must be set")

    items = matrix.get("item")
    if not isinstance(items, list) or not items:
        fail("at least one ABI item is required")
    seen: set[str] = set()
    counts = {status: 0 for status in sorted(STATUSES)}
    for item in items:
        if not isinstance(item, dict):
            fail("each ABI item must be a table")
        missing = REQUIRED_ITEM_FIELDS - set(item)
        extra = set(item) - REQUIRED_ITEM_FIELDS
        if missing:
            fail(f"ABI item missing fields: {sorted(missing)}")
        if extra:
            fail(f"ABI item has unknown fields: {sorted(extra)}")
        item_id = item["id"]
        if not isinstance(item_id, str) or not item_id or item_id in seen:
            fail(f"invalid or duplicate ABI item id: {item_id!r}")
        seen.add(item_id)
        for field in REQUIRED_ITEM_FIELDS - {"id", "status"}:
            if not isinstance(item[field], str) or not item[field].strip():
                fail(f"{item_id}: {field} must be a non-empty string")
        status = item["status"]
        if status not in STATUSES:
            fail(f"{item_id}: unsupported status {status!r}")
        counts[status] += 1
        if status == "verified":
            coverage = (item["positive_coverage"] + item["negative_coverage"]).lower()
            if "pending" in coverage or "not " in coverage or "missing" in coverage:
                fail(f"{item_id}: verified item advertises incomplete coverage")
        for evidence in item["evidence"].split(";"):
            evidence = evidence.strip()
            if not evidence:
                fail(f"{item_id}: empty evidence path")
            if not (root / evidence).exists():
                fail(f"{item_id}: evidence does not exist: {evidence}")
        if item["environment"] == "qemu-jasper-linux-abi" and status == "mapped":
            fail(f"{item_id}: QEMU evidence cannot promote an item only to mapped")

    remaining = matrix.get("remaining", [])
    if not isinstance(remaining, list):
        fail("remaining must be an array of tables")
    remaining_ids: set[str] = set()
    for gate in remaining:
        if set(gate) != {"id", "reason"}:
            fail("remaining gates require exactly id and reason")
        if not str(gate["id"]).strip() or not str(gate["reason"]).strip():
            fail("remaining gate id and reason must be non-empty")
        if gate["id"] in remaining_ids:
            fail(f"duplicate remaining gate: {gate['id']}")
        remaining_ids.add(gate["id"])
    return counts


def self_test() -> None:
    matrix = tomllib.loads(DEFAULT_MATRIX.read_text(encoding="utf-8"))
    validate(matrix)

    broken = copy.deepcopy(matrix)
    broken["scope"] = "native"
    try:
        validate(broken)
    except ValueError:
        pass
    else:
        fail("self-test accepted the wrong scope")

    broken = copy.deepcopy(matrix)
    broken["item"][0]["status"] = "done"
    try:
        validate(broken)
    except ValueError:
        pass
    else:
        fail("self-test accepted an unsupported status")

    broken = copy.deepcopy(matrix)
    broken["item"][0]["evidence"] = "evidence/does-not-exist"
    try:
        validate(broken)
    except ValueError:
        pass
    else:
        fail("self-test accepted missing evidence")

    broken = copy.deepcopy(matrix)
    broken["item"][1]["environment"] = "qemu-jasper-linux-abi"
    broken["item"][1]["status"] = "mapped"
    try:
        validate(broken)
    except ValueError:
        pass
    else:
        fail("self-test accepted QEMU coverage as only mapped")

    print("compat-abi-matrix: SELF-TEST PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    matrix = tomllib.loads(args.check.read_text(encoding="utf-8"))
    counts = validate(matrix, args.check.resolve().parents[1])
    summary = " ".join(f"{status}={count}" for status, count in counts.items() if count)
    print(f"compat-abi-matrix: PASS items={len(matrix['item'])} {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

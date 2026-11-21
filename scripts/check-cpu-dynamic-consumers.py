#!/usr/bin/env python3
"""Freeze the Issue #47 CPU-width consumer inventory.

This is an audit inventory, not proof that every fixed bootstrap table is fully
dynamic. Production rows marked ``in-progress`` must remain visible until their
heap-tail migration and failure tests are complete.
"""

from __future__ import annotations

import csv
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "verification/cpu-dynamic-consumers.tsv"
HEADER = [
    "path",
    "production_occurrences",
    "test_occurrences",
    "status",
    "classification",
    "lifetime",
    "migration",
    "evidence",
]
STATUSES = {"verified", "in-progress", "fixture"}
CLASSIFICATIONS = {
    "bootstrap",
    "dynamic",
    "fixed-unmigrated",
    "test-only",
    "excluded",
}
TERM = re.compile(
    r"\b(?:MAX_CPUS|BOOTSTRAP_CPUS|CPU_SET_WORDS)\b|"
    r"\[\s*[^\]]*MAX_CPUS[^\]]*\]"
)
ROOTS = (Path("kernel/src"), Path("kernel-core/src"))
TEST_PATH_MARKERS = ("_demo.rs", "pex4_probe.rs", "smp/demo.rs")


def count_source(path: Path) -> tuple[int, int]:
    lines = path.read_text(encoding="utf-8").splitlines()
    test_start = len(lines)
    for index, line in enumerate(lines):
        if "#[cfg(test)]" in line and index + 1 < len(lines):
            if "mod tests" in lines[index + 1]:
                test_start = index
                break
    production = sum(bool(TERM.search(line)) for line in lines[:test_start])
    tests = sum(bool(TERM.search(line)) for line in lines[test_start:])
    return production, tests


def scan(root: Path = ROOT) -> dict[str, tuple[int, int]]:
    found: dict[str, tuple[int, int]] = {}
    for directory in ROOTS:
        for path in sorted((root / directory).rglob("*.rs")):
            production, tests = count_source(path)
            if production or tests:
                found[path.relative_to(root).as_posix()] = (production, tests)
    return found


def load(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def validate(rows: list[dict[str, str]], root: Path = ROOT) -> None:
    if not rows:
        raise ValueError("CPU consumer inventory is empty")
    if list(rows[0]) != HEADER:
        raise ValueError("CPU consumer inventory header drift")
    actual = scan(root)
    listed: dict[str, tuple[int, int]] = {}
    for index, row in enumerate(rows, 2):
        for field in HEADER:
            if not row[field].strip():
                raise ValueError(f"row {index}: empty {field}")
        path = row["path"]
        if path in listed:
            raise ValueError(f"row {index}: duplicate path {path}")
        try:
            production = int(row["production_occurrences"])
            tests = int(row["test_occurrences"])
        except ValueError as error:
            raise ValueError(f"row {index}: non-numeric count") from error
        if row["status"] not in STATUSES:
            raise ValueError(f"row {index}: invalid status {row['status']}")
        if row["classification"] not in CLASSIFICATIONS:
            raise ValueError(
                f"row {index}: invalid classification {row['classification']}"
            )
        if row["status"] == "verified" and row["classification"] not in {
            "bootstrap",
            "dynamic",
        }:
            raise ValueError(
                f"row {index}: verified consumer must be bootstrap or dynamic"
            )
        if row["status"] == "in-progress" and row["classification"] == "test-only":
            raise ValueError(f"row {index}: production consumer cannot be test-only")
        if row["status"] == "fixture" and row["classification"] not in {
            "test-only",
            "excluded",
        }:
            raise ValueError(
                f"row {index}: fixture consumer must be test-only or excluded"
            )
        if row["classification"] == "test-only" and production:
            raise ValueError(
                f"row {index}: test-only consumer still appears in production code"
            )
        if row["classification"] == "excluded" and tests:
            raise ValueError(
                f"row {index}: excluded consumer unexpectedly contains test occurrences"
            )
        listed[path] = (production, tests)

    missing = sorted(set(actual) - set(listed))
    stale = sorted(set(listed) - set(actual))
    if missing:
        raise ValueError(f"unregistered CPU consumer paths: {missing}")
    if stale:
        raise ValueError(f"stale CPU consumer paths: {stale}")
    for path, expected in actual.items():
        if listed[path] != expected:
            raise ValueError(
                f"{path}: inventory drift expected {listed[path]}, actual {expected}"
            )


def self_test() -> None:
    rows = load(LEDGER)
    validate(rows)
    broken = [dict(row) for row in rows]
    broken[0]["production_occurrences"] = "999999"
    try:
        validate(broken)
    except ValueError as error:
        assert "inventory drift" in str(error)
    else:
        raise AssertionError("self-test accepted a CPU inventory count drift")
    broken = rows[:-1]
    try:
        validate(broken)
    except ValueError as error:
        assert "unregistered CPU consumer paths" in str(error)
    else:
        raise AssertionError("self-test accepted a missing consumer path")
    broken = [dict(row) for row in rows]
    broken[0]["classification"] = "unknown"
    try:
        validate(broken)
    except ValueError as error:
        assert "invalid classification" in str(error)
    else:
        raise AssertionError("self-test accepted an unknown CPU consumer class")
    broken = [dict(row) for row in rows]
    in_progress = broken[0]
    in_progress["status"] = "in-progress"
    in_progress["classification"] = "bootstrap"
    validate(broken)
    broken = [dict(row) for row in rows]
    broken[0]["classification"] = "fixed-unmigrated"
    try:
        validate(broken)
    except ValueError as error:
        assert "verified consumer must be bootstrap or dynamic" in str(error)
    else:
        raise AssertionError("self-test marked a fixed consumer verified")
    print("cpu-dynamic-consumers: self-test PASS")


def main() -> int:
    try:
        if "--self-test" in sys.argv[1:]:
            self_test()
            return 0
        rows = load(LEDGER)
        validate(rows)
        status = {name: 0 for name in sorted(STATUSES)}
        classification = {name: 0 for name in sorted(CLASSIFICATIONS)}
        for row in rows:
            status[row["status"]] += 1
            classification[row["classification"]] += 1
        print(
            "cpu-dynamic-consumers: PASS "
            + " ".join(f"{name}={count}" for name, count in status.items())
            + " "
            + " ".join(
                f"{name}={count}" for name, count in classification.items()
            )
            + f" paths={len(rows)}"
        )
    except (OSError, ValueError, csv.Error, AssertionError) as error:
        print(f"cpu-dynamic-consumers: FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

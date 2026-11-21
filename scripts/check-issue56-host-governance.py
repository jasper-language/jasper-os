#!/usr/bin/env python3
"""Validate the Issue #56 phase-A host-governance inventory."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "verification/issue56-host-governance.tsv"
DOC = ROOT / "docs/ISSUE-56-HOST-GOVERNANCE-MATRIX.md"
HEADER = [
    "domain",
    "backend",
    "native_authority",
    "management_granularity",
    "status",
    "evidence",
    "gap",
]
DOMAINS = {
    "identity_workload",
    "cpu_memory_quota",
    "security_authz",
    "handle_memory",
    "files_namespace",
    "network_egress",
    "device_ownership",
    "ui_surface_input",
    "install_lifecycle",
    "observability_audit",
}
BACKENDS = {"native", "linux", "android", "wine", "vm"}
STATUSES = {"verified", "partial", "missing", "unsupported"}


def fail(message: str) -> None:
    raise SystemExit(f"issue56-host-governance: FAIL: {message}")


def load() -> list[dict[str, str]]:
    with LEDGER.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def validate(rows: list[dict[str, str]], root: Path = ROOT) -> None:
    if not rows or list(rows[0]) != HEADER:
        raise ValueError("ledger header drift")
    seen: set[tuple[str, str]] = set()
    for line_number, row in enumerate(rows, 2):
        for field in HEADER:
            if not row[field].strip():
                raise ValueError(f"row {line_number}: empty {field}")
        key = (row["domain"], row["backend"])
        if key in seen:
            raise ValueError(f"row {line_number}: duplicate {key}")
        seen.add(key)
        if row["domain"] not in DOMAINS:
            raise ValueError(f"row {line_number}: unknown domain {row['domain']}")
        if row["backend"] not in BACKENDS:
            raise ValueError(f"row {line_number}: unknown backend {row['backend']}")
        if row["status"] not in STATUSES:
            raise ValueError(f"row {line_number}: invalid status {row['status']}")
        if row["status"] == "verified":
            raise ValueError(
                f"row {line_number}: phase-A inventory cannot claim verified governance"
            )
        for evidence in row["evidence"].split(";"):
            if not (root / evidence).is_file():
                raise ValueError(f"row {line_number}: missing evidence {evidence}")

    expected = {(domain, backend) for domain in DOMAINS for backend in BACKENDS}
    if seen != expected:
        raise ValueError(f"matrix cells differ: {sorted(expected ^ seen)}")

    vm_rows = [row for row in rows if row["backend"] == "vm"]
    if any(row["status"] != "missing" for row in vm_rows):
        raise ValueError("VM application governance must remain missing until guest verticals pass")


def self_test() -> None:
    rows = load()
    validate(rows)
    broken = [dict(row) for row in rows]
    broken[0]["status"] = "verified"
    try:
        validate(broken)
    except ValueError as error:
        assert "cannot claim verified" in str(error)
    else:
        raise AssertionError("self-test accepted an unproved verified cell")
    broken = rows[:-1]
    try:
        validate(broken)
    except ValueError as error:
        assert "matrix cells differ" in str(error)
    else:
        raise AssertionError("self-test accepted a missing matrix cell")
    print("issue56-host-governance: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        rows = load()
        validate(rows)
    except (OSError, ValueError, csv.Error) as error:
        fail(str(error))
    text = DOC.read_text(encoding="utf-8")
    for anchor in ("阶段 A", "只有一套宿主", "VM 管理的默认粒度", "不得"):
        if anchor not in text:
            fail(f"documentation missing anchor: {anchor}")
    print(
        "issue56-host-governance: PASS "
        f"phase=A cells={len(rows)} domains={len(DOMAINS)} backends={len(BACKENDS)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

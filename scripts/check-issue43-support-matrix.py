#!/usr/bin/env python3
"""Validate the fail-closed Pixel 6a driver support and redistribution matrix."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "verification" / "issue43-pixel6a-support-matrix.tsv"
HEADER = [
    "component",
    "kind",
    "observed_name",
    "source_revision",
    "license_status",
    "firmware_provenance",
    "redistribution",
    "security_response",
    "end_of_support",
    "verification_status",
    "evidence",
]
KINDS = {"linux-module", "android-hal", "firmware", "userspace-service"}
LICENSE_STATUSES = {"verified", "unverified", "proprietary", "not-applicable"}
REDISTRIBUTION = {"approved", "metadata-only", "denied"}
VERIFICATION = {
    "approved",
    "verification-required",
    "blocked-hardware",
    "not-redistributable",
}
UNKNOWN = {"", "unknown", "unverified", "not-verified"}


def validate(rows: list[dict[str, str]], root: Path = ROOT) -> None:
    if not rows or list(rows[0]) != HEADER:
        raise ValueError("support matrix header drift")
    seen: set[tuple[str, str]] = set()
    for row in rows:
        name = row.get("observed_name", "")
        for field in HEADER:
            if not row.get(field, "").strip():
                raise ValueError(f"{name or '<unknown>'}: empty {field}")
        if row["kind"] not in KINDS:
            raise ValueError(f"{name}: invalid kind {row['kind']}")
        if row["license_status"] not in LICENSE_STATUSES:
            raise ValueError(f"{name}: invalid license status")
        if row["redistribution"] not in REDISTRIBUTION:
            raise ValueError(f"{name}: invalid redistribution status")
        if row["verification_status"] not in VERIFICATION:
            raise ValueError(f"{name}: invalid verification status")
        key = (row["kind"], name)
        if key in seen:
            raise ValueError(f"{name}: duplicate component")
        seen.add(key)
        if row["verification_status"] == "approved":
            required = (
                row["source_revision"],
                row["license_status"],
                row["firmware_provenance"],
                row["security_response"],
                row["end_of_support"],
            )
            if any(value.strip().lower() in UNKNOWN for value in required):
                raise ValueError(f"{name}: approved entry has unknown required facts")
            if row["license_status"] != "verified":
                raise ValueError(f"{name}: approved entry needs verified license")
        if row["redistribution"] == "approved":
            for evidence in row["evidence"].split(";"):
                if not (root / evidence.strip()).exists():
                    raise ValueError(f"{name}: missing evidence {evidence}")


def self_test() -> None:
    base = dict.fromkeys(HEADER, "value")
    base.update(
        {
            "component": "component",
            "kind": "linux-module",
            "observed_name": "module.ko",
            "source_revision": "unknown",
            "license_status": "unverified",
            "firmware_provenance": "unknown",
            "redistribution": "denied",
            "security_response": "unknown",
            "end_of_support": "unknown",
            "verification_status": "verification-required",
            "evidence": "Cargo.toml",
        }
    )
    validate([base])
    approved = dict(base)
    approved["verification_status"] = "approved"
    try:
        validate([approved])
    except ValueError as error:
        assert "approved entry" in str(error)
    else:
        raise AssertionError("self-test accepted unverified approved entry")
    print("issue43-support-matrix: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        with MATRIX.open(newline="", encoding="utf-8") as source:
            validate(list(csv.DictReader(source, delimiter="\t")))
    except (OSError, ValueError, csv.Error) as error:
        print(f"issue43-support-matrix: FAIL {error}")
        return 1
    print("issue43-support-matrix: PASS fail-closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

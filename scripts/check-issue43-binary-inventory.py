#!/usr/bin/env python3
"""Validate the metadata-only Pixel 6a vendor binary inventory."""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "verification" / "issue43-pixel6a-binary-inventory.tsv"
HEADER = [
    "kind",
    "observed_name",
    "device_path",
    "size_bytes",
    "sha256",
    "access",
    "loaded",
    "build_fingerprint",
    "kernel_release",
]
EXPECTED_COUNTS = {
    "android-hal": 26,
    "linux-module": 318,
    "linux-module-metadata": 5,
}
FINGERPRINT = "google/bluejay/bluejay:16/BP4A.251205.006/14401865:user/release-keys"
KERNEL_RELEASE = "6.1.145-android14-11-gc1de4747ac59-ab14219743"
ACCESS = {"readable", "unreadable-by-adb-shell"}
HEX256 = re.compile(r"^[0-9a-f]{64}$")


def validate(
    rows: list[dict[str, str]],
    expected_counts: dict[str, int] = EXPECTED_COUNTS,
    root: Path = ROOT,
) -> None:
    if not rows or list(rows[0]) != HEADER:
        raise ValueError("binary inventory header drift")
    counts = Counter(row["kind"] for row in rows)
    if counts != Counter(expected_counts):
        raise ValueError(f"binary inventory counts drift: {dict(counts)}")
    seen: set[tuple[str, str]] = set()
    for row in rows:
        name = row["observed_name"]
        if any(not row[field].strip() for field in HEADER):
            raise ValueError(f"{name}: empty inventory field")
        key = (row["kind"], name)
        if key in seen:
            raise ValueError(f"{name}: duplicate inventory row")
        seen.add(key)
        if row["build_fingerprint"] != FINGERPRINT:
            raise ValueError(f"{name}: build fingerprint drift")
        if row["kernel_release"] != KERNEL_RELEASE:
            raise ValueError(f"{name}: kernel release drift")
        if row["access"] not in ACCESS:
            raise ValueError(f"{name}: invalid access state")
        if row["loaded"] not in {"yes", "no"}:
            raise ValueError(f"{name}: invalid loaded state")
        suffix = ".so" if row["kind"] == "android-hal" else ".ko"
        if row["kind"] in {"android-hal", "linux-module"} and not name.endswith(suffix):
            raise ValueError(f"{name}: invalid component suffix")
        evidence = root / row["device_path"].lstrip("/")
        if evidence.exists() and evidence.is_file():
            raise ValueError(f"{name}: device path must be an Android path, not repository data")
        if row["access"] == "readable":
            if not row["size_bytes"].isdigit() or int(row["size_bytes"]) <= 0:
                raise ValueError(f"{name}: readable file lacks size")
            if not HEX256.fullmatch(row["sha256"]):
                raise ValueError(f"{name}: readable file lacks SHA-256")
        elif row["size_bytes"] != "-" or row["sha256"] != "-":
            raise ValueError(f"{name}: unreadable file must not claim metadata")


def self_test() -> None:
    rows = []
    for kind, count in EXPECTED_COUNTS.items():
        for index in range(count):
            suffix = ".so" if kind == "android-hal" else (
                "" if kind == "linux-module-metadata" else ".ko"
            )
            rows.append(
                {
                    "kind": kind,
                    "observed_name": f"{kind}-{index}{suffix}",
                    "device_path": f"/device/{kind}-{index}{suffix}",
                    "size_bytes": "1",
                    "sha256": "0" * 64,
                    "access": "readable",
                    "loaded": "no",
                    "build_fingerprint": FINGERPRINT,
                    "kernel_release": KERNEL_RELEASE,
                }
            )
    validate(rows)
    invalid = [dict(row) for row in rows]
    invalid[0]["sha256"] = "-"
    try:
        validate(invalid)
    except ValueError as error:
        assert "lacks SHA-256" in str(error)
    else:
        raise AssertionError("self-test accepted readable file without SHA-256")

    invalid = [dict(row) for row in rows]
    invalid[-1]["kind"] = "linux-module"
    try:
        validate(invalid)
    except ValueError as error:
        assert "counts drift" in str(error)
    else:
        raise AssertionError("self-test accepted inventory count drift")
    print("issue43-binary-inventory: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        with INVENTORY.open(newline="", encoding="utf-8") as source:
            validate(list(csv.DictReader(source, delimiter="\t")))
    except (OSError, ValueError, csv.Error) as error:
        print(f"issue43-binary-inventory: FAIL {error}")
        return 1
    print(
        "issue43-binary-inventory: PASS "
        "modules=318 metadata=5 hal=26 total=349"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

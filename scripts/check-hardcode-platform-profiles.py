#!/usr/bin/env python3
"""Validate explicit Pixel/QEMU platform-adapter boundaries."""

from __future__ import annotations

import csv
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "verification/hardcode-platform-profiles.tsv"
CARGO = ROOT / "kernel/Cargo.toml"
HEADER = ["profile", "source", "path", "fragment", "evidence"]
SOURCES = {
    "pixel-verification-platform",
    "loongarch-qemu-verification-platform",
}
ALLOWED_PREFIXES = (
    "kernel/build.rs",
    "kernel/src/arch/aarch64/",
    "kernel/src/arch/loongarch64/",
    "kernel/src/kmain.rs",
)


def validate(rows: list[dict[str, str]], root: Path = ROOT) -> None:
    if not rows:
        raise ValueError("platform matrix is empty")
    if list(rows[0]) != HEADER:
        raise ValueError("platform matrix header drift")
    seen = set()
    for index, row in enumerate(rows, 2):
        for field in HEADER:
            if not row[field].strip():
                raise ValueError(f"row {index}: empty {field}")
        if row["source"] not in SOURCES:
            raise ValueError(f"row {index}: unregistered source {row['source']}")
        if not row["path"].startswith(ALLOWED_PREFIXES):
            raise ValueError(f"row {index}: generic/non-platform path {row['path']}")
        key = (row["path"], row["fragment"])
        if key in seen:
            raise ValueError(f"row {index}: duplicate {row['path']} fragment")
        seen.add(key)
        source = (root / row["path"]).read_text(encoding="utf-8")
        matches = [line for line in source.splitlines() if row["fragment"] in line]
        if not matches:
            raise ValueError(f"row {index}: missing source fragment {row['fragment']}")
        marker = f"source={row['source']}"
        # The inventory gate separately requires every scanned occurrence to be
        # registered. This matrix validates that each declared profile has at
        # least one concrete annotated production path.
        if not any(marker in line for line in matches):
            raise ValueError(f"row {index}: fragment lacks {marker}")

    cargo = (root / "kernel/Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r"(?ms)^default\s*=\s*\[(?P<body>.*?)\]", cargo)
    if match is None or "pixel6a" in match.group("body") or "qemu" in match.group("body"):
        raise ValueError("default production features include a platform verification profile")


def load(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def self_test() -> None:
    root = ROOT
    rows = load(MATRIX)
    validate(rows, root)
    broken = [dict(row) for row in rows]
    broken[0]["source"] = "unregistered"
    try:
        validate(broken, root)
    except ValueError as error:
        assert "unregistered source" in str(error)
    else:
        raise AssertionError("self-test accepted an unregistered platform source")
    broken = [dict(row) for row in rows]
    broken[0]["path"] = "kernel/src/fs.rs"
    try:
        validate(broken, root)
    except ValueError as error:
        assert "non-platform path" in str(error)
    else:
        raise AssertionError("self-test accepted a generic path as a platform adapter")
    print("hardcode-platform-profiles: self-test PASS")


def main() -> int:
    try:
        if "--self-test" in sys.argv[1:]:
            self_test()
        else:
            validate(load(MATRIX))
            print("hardcode-platform-profiles: PASS")
    except (OSError, ValueError, csv.Error, AssertionError) as error:
        print(f"hardcode-platform-profiles: FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

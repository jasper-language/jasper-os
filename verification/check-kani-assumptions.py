#!/usr/bin/env python3
"""Reject Kani assumptions/stubs that were not reviewed by FV-1."""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
import tomllib
from collections import Counter
from pathlib import Path


OCCURRENCE = re.compile(r"\bkani::(?:assume|stub)\b|#\s*\[\s*kani::stub")


def scan(root: Path) -> Counter[str]:
    actual: Counter[str] = Counter()
    for path in (root / "kernel-core/src").rglob("*.rs"):
        count = len(OCCURRENCE.findall(path.read_text(encoding="utf-8")))
        if count:
            actual[path.relative_to(root).as_posix()] = count
    return actual


def reviewed(data: dict) -> dict[str, tuple[int, str]]:
    entries: dict[str, tuple[int, str]] = {}
    for entry in data.get("reviewed_kani_assumption", []):
        path = entry.get("path")
        count = entry.get("count")
        review = entry.get("review")
        if not isinstance(path, str) or not path.startswith("kernel-core/src/"):
            raise ValueError(f"invalid reviewed assumption path: {path!r}")
        if path in entries:
            raise ValueError(f"duplicate reviewed assumption path: {path}")
        if not isinstance(count, int) or count <= 0:
            raise ValueError(f"{path}: count must be a positive integer")
        if not isinstance(review, str) or not review.strip():
            raise ValueError(f"{path}: an explicit review reason is required")
        entries[path] = (count, review)
    return entries


def validate(actual: Counter[str], entries: dict[str, tuple[int, str]]) -> None:
    for path in sorted(set(actual) | set(entries)):
        found = actual.get(path, 0)
        expected = entries.get(path, (0, ""))[0]
        if found != expected:
            raise ValueError(
                f"{path}: reviewed Kani constraints={expected}, source occurrences={found}"
            )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "kernel-core/src/example.rs"
        source.parent.mkdir(parents=True)
        source.write_text("kani::assume(x != 0);\n", encoding="utf-8")
        actual = scan(root)
        entries = {
            "kernel-core/src/example.rs": (1, "symbolic input domain is explicit"),
        }
        validate(actual, entries)
        source.write_text("kani::assume(x != 0);\nkani::assume(y != 0);\n", encoding="utf-8")
        try:
            validate(scan(root), entries)
        except ValueError:
            pass
        else:
            raise SystemExit("negative self-test: an unreviewed assumption was accepted")
    print("Kani assumption gate self-test: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, default=Path("verification/FV1.toml"))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    try:
        data = tomllib.loads(args.manifest.read_text(encoding="utf-8"))
        entries = reviewed(data)
        actual = scan(args.root)
        validate(actual, entries)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        print(f"Kani assumption gate: FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "Kani assumption gate: PASS "
        f"files={len(actual)} occurrences={sum(actual.values())}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

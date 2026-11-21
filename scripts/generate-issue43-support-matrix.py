#!/usr/bin/env python3
"""Generate the complete fail-closed Pixel 6a component support matrix."""

from __future__ import annotations

import argparse
import csv
import io
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "verification/issue43-pixel6a-binary-inventory.tsv"
MATRIX = ROOT / "verification/issue43-pixel6a-support-matrix.tsv"
EVIDENCE = "docs/ISSUE-43-PIXEL6A-DRIVER-INVENTORY.md"
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


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source, delimiter="\t"))


def default_row(item: dict[str, str]) -> dict[str, str]:
    return {
        "component": item["observed_name"],
        "kind": item["kind"],
        "observed_name": item["observed_name"],
        "source_revision": "unknown",
        "license_status": "unverified",
        "firmware_provenance": "unknown",
        "redistribution": "denied",
        "security_response": "Android Security Bulletin / vendor response",
        "end_of_support": "Pixel 6a support lifecycle",
        "verification_status": "verification-required",
        "evidence": EVIDENCE,
    }


def generate() -> list[dict[str, str]]:
    current = read_tsv(MATRIX) if MATRIX.is_file() else []
    curated = {
        (row["kind"], row["observed_name"]): row
        for row in current
        if row.get("kind") in {"linux-module", "android-hal"}
    }
    rows: list[dict[str, str]] = []
    inventory_keys: set[tuple[str, str]] = set()
    for item in read_tsv(INVENTORY):
        if item["kind"] not in {"linux-module", "android-hal"}:
            continue
        key = (item["kind"], item["observed_name"])
        inventory_keys.add(key)
        rows.append(curated.get(key, default_row(item)))
    for key, row in curated.items():
        if key not in inventory_keys:
            rows.append(row)
    rows.sort(key=lambda row: (row["kind"], row["observed_name"]))
    return rows


def render(rows: list[dict[str, str]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=HEADER,
        delimiter="\t",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = render(generate())
    if args.check:
        current = MATRIX.read_text(encoding="utf-8") if MATRIX.is_file() else ""
        if current != rendered:
            print("issue43-support-matrix-generate: FAIL stale matrix; run without --check")
            return 1
        print("issue43-support-matrix-generate: PASS")
        return 0
    MATRIX.write_text(rendered, encoding="utf-8")
    print(f"issue43-support-matrix-generate: wrote {len(generate())} components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate the NET-0 core claim matrix."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "verification" / "net0-contract.toml"
MODULE = ROOT / "kernel-core" / "src" / "net.rs"
LIB = ROOT / "kernel-core" / "src" / "lib.rs"
STATES = {"tested", "implemented-not-integrated", "pending"}


def fail(message: str) -> None:
    print(f"net0-contract: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    try:
        matrix = tomllib.loads(MATRIX.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read matrix: {exc}")
    if matrix.get("schema") != 1 or matrix.get("stage") != "NET-0":
        fail("schema/stage mismatch")
    if matrix.get("status") not in {"in-progress", "done"}:
        fail("invalid status")
    if not MODULE.is_file() or "pub mod net;" not in LIB.read_text(encoding="utf-8"):
        fail("kernel-core does not export NET-0")

    items = matrix.get("acceptance", [])
    seen: set[str] = set()
    unresolved: list[str] = []
    for item in items:
        for key in ("id", "state", "statement", "evidence"):
            if not isinstance(item.get(key), str) or not item[key]:
                fail(f"item missing {key}: {item}")
        if item["id"] in seen:
            fail(f"duplicate item {item['id']}")
        seen.add(item["id"])
        if item["state"] not in STATES:
            fail(f"invalid state {item['state']}")
        if item["state"] != "tested":
            unresolved.append(f"{item['id']}:{item['state']}")
    if len(items) < 10:
        fail("NET-0 needs at least 10 acceptance items")
    if matrix["status"] == "done" and unresolved:
        fail("NET-0 cannot be done with unresolved items")
    print(
        f"net0-contract: PASS [{matrix['status']}] "
        f"({len(items) - len(unresolved)}/{len(items)} tested/complete, "
        f"unresolved={len(unresolved)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

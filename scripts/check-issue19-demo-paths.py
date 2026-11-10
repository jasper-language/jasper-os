#!/usr/bin/env python3
"""Check that every demo module is classified and excluded from production calls."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "kernel/src"
LIB = SRC / "lib.rs"
PRODUCTION = ROOT / "kernel/src/production.rs"
CLASSIFICATION = ROOT / "kernel/demo-path-classification.txt"
VALID = {"verification-only", "temporary-in-use", "superseded"}
TEMPORARY_PRODUCTION_CALLERS: set[str] = set()


def fail(message: str) -> None:
    print(f"issue19-demo-paths: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def classified() -> dict[str, str]:
    result: dict[str, str] = {}
    for line_number, line in enumerate(
        CLASSIFICATION.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, category = line.partition("=")
        name = name.strip()
        category = category.strip()
        if not separator or not name or category not in VALID:
            fail(f"invalid classification line {line_number}: {line}")
        if name in result:
            fail(f"duplicate classification for {name}")
        result[name] = category
    return result


def main() -> int:
    source = LIB.read_text(encoding="utf-8")
    modules = set()
    declaration = re.compile(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z0-9_]*demo)\s*;",
        re.MULTILINE,
    )
    for path in SRC.rglob("*.rs"):
        relative = path.relative_to(SRC)
        if relative.name in {"lib.rs", "main.rs", "mod.rs"}:
            parts = list(relative.parent.parts)
        else:
            parts = [*relative.parent.parts, relative.stem]
        parent = "::".join(part for part in parts if part != ".")
        for name in declaration.findall(path.read_text(encoding="utf-8")):
            modules.add(f"{parent}::{name}" if parent else name)
    modules.update(
        re.findall(r"pub\s+use\s+(?:[A-Za-z0-9_]+::)*([A-Za-z0-9_]*_demo)\s*;", source)
    )
    classes = classified()
    if set(classes) != modules:
        fail(f"classification drift: {sorted(set(classes) ^ modules)}")
    production = PRODUCTION.read_text(encoding="utf-8")
    tokens = set(
        re.findall(
            r"(?:^|::)([A-Za-z0-9_]*(?:_demo|demo))::",
            production,
            re.MULTILINE,
        )
    )
    referenced = set()
    undeclared = set()
    for token in tokens:
        if token in classes:
            referenced.add(token)
            continue
        matches = {name for name in classes if name.endswith(f"::{token}")}
        if not matches:
            undeclared.add(token)
        elif len(matches) > 1:
            fail(f"production token {token} is ambiguous: {sorted(matches)}")
        else:
            referenced.update(matches)
    if undeclared:
        fail(f"production references unclassified demo modules: {sorted(undeclared)}")
    forbidden = {
        name
        for name in referenced
        if classes.get(name) != "temporary-in-use" or name not in TEMPORARY_PRODUCTION_CALLERS
    }
    if forbidden:
        fail(f"production references verification-only demo modules: {sorted(forbidden)}")
    for name, category in classes.items():
        if category == "temporary-in-use" and name not in referenced:
            fail(f"temporary production dependency {name} is no longer referenced; reclassify it")
    temporary = sum(category == "temporary-in-use" for category in classes.values())
    print(
        "issue19-demo-paths: PASS "
        f"modules={len(modules)} verification_only={len(modules) - temporary} "
        f"temporary_in_use={temporary} production_refs={sorted(referenced)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

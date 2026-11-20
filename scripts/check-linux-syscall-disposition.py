#!/usr/bin/env python3
"""Check Linux syscall dispatch inventory and generate its review matrix."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENUM_SOURCE = ROOT / "compat-core/src/syscall.rs"
DISPATCH_SOURCE = ROOT / "kernel/src/linux_abi.rs"
MATRIX = ROOT / "docs/linux-syscall-disposition.tsv"
NATIVE_EXTENSIONS = {"RseqSliceYield", "Uprobe"}


def enum_variants(source: str) -> list[str]:
    marker = "pub enum LinuxSyscall {"
    body_start = source.index(marker) + len(marker)
    body_end = source.index("\n}", body_start)
    variants = re.findall(r"^    ([A-Z][A-Za-z0-9_]*),?$", source[body_start:body_end], re.MULTILINE)
    if len(variants) != len(set(variants)):
        raise ValueError("duplicate LinuxSyscall enum variant")
    return variants


def unsupported_group(body: str) -> set[str]:
    marker = "LinuxSyscall::GetThreadArea"
    start = body.index(marker)
    end = body.index("=>", start)
    return set(re.findall(r"LinuxSyscall::([A-Za-z0-9_]+)", body[start:end]))


def matrix_rows() -> list[tuple[str, str, str, str]]:
    enum_source = ENUM_SOURCE.read_text(encoding="utf-8")
    dispatch_source = DISPATCH_SOURCE.read_text(encoding="utf-8")
    variants = enum_variants(enum_source)
    body = dispatch_source
    unsupported = unsupported_group(body)
    rows = []
    for variant in variants:
        needle = f"LinuxSyscall::{variant}"
        at = body.find(needle)
        if at < 0:
            raise ValueError(f"missing dispatch for {variant}")
        line = body.count("\n", 0, at) + 1
        scope = "jasper-native-extension" if variant in NATIVE_EXTENSIONS else "linux-x86_64"
        disposition = (
            "native-extension"
            if variant in NATIVE_EXTENSIONS
            else "unsupported-abi"
            if variant in unsupported
            else "dispatched"
        )
        rows.append((variant, scope, disposition, f"kernel/src/linux_abi.rs:{line}"))
    seen = {row[0] for row in rows}
    for variant in set(re.findall(r"LinuxSyscall::([A-Za-z0-9_]+)", body)) - set(variants):
        if variant not in seen:
            raise ValueError(f"dispatch references unknown LinuxSyscall::{variant}")
    return rows


def render(rows: list[tuple[str, str, str, str]]) -> str:
    lines = ["variant\tscope\tdisposition\tdispatch_evidence"]
    lines.extend("\t".join(row) for row in rows)
    return "\n".join(lines) + "\n"


def self_test() -> None:
    sample = "pub enum LinuxSyscall {\n    Read,\n    RseqSliceYield,\n}\n"
    assert enum_variants(sample) == ["Read", "RseqSliceYield"]
    assert render([("Read", "linux-x86_64", "dispatched", "x:1")]).startswith("variant\t")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("linux-syscall-disposition: self-test PASS")
        return 0
    try:
        rows = matrix_rows()
    except (ValueError, OSError) as error:
        raise SystemExit(f"linux-syscall-disposition: FAIL {error}") from error
    total = len(rows)
    linux = sum(row[1] == "linux-x86_64" for row in rows)
    native = total - linux
    if total != 385 or native != len(NATIVE_EXTENSIONS):
        raise SystemExit(
            f"linux-syscall-disposition: FAIL expected 385 total with "
            f"{len(NATIVE_EXTENSIONS)} explicit native extensions, "
            f"got {linux} Linux + {native} native ({total} total)"
        )
    rendered = render(rows)
    if args.write:
        MATRIX.write_text(rendered, encoding="utf-8")
        print(f"linux-syscall-disposition: wrote {total} rows to {MATRIX.relative_to(ROOT)}")
        return 0
    if not MATRIX.exists() or MATRIX.read_text(encoding="utf-8") != rendered:
        raise SystemExit("linux-syscall-disposition: FAIL matrix drift; run --write")
    print(
        "linux-syscall-disposition: PASS "
        f"linux={linux} native_extensions={native} total={total} "
        f"unsupported={sum(row[2] == 'unsupported-abi' for row in rows)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

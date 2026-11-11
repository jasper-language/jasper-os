#!/usr/bin/env python3
"""Attribute production-kernel sections and symbols and enforce size ceilings."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

DEMO_SYMBOL = re.compile(r"(?:^|::)(?:[A-Za-z0-9_]+_demo|demo)::")


def fail(message: str) -> None:
    print(f"production-footprint: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(command: list[str]) -> str:
    try:
        return subprocess.run(
            command,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"command failed: {error}")


def module_name(symbol: str) -> str:
    symbol = symbol.lstrip("<&").split("::<", 1)[0]
    parts = symbol.split("::")
    if not parts:
        return "unknown"
    if parts[0] == "jasper_kernel" and len(parts) > 1:
        return f"jasper_kernel::{parts[1]}"
    return parts[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--size", default="size")
    parser.add_argument("--max-text", type=int, default=1024 * 1024)
    parser.add_argument("--max-rodata", type=int, default=512 * 1024)
    parser.add_argument("--max-symbol", type=int, default=64 * 1024)
    args = parser.parse_args()
    if not args.elf.is_file():
        fail(f"ELF does not exist: {args.elf}")

    section_output = run([args.size, "--format=sysv", str(args.elf)])
    sections: dict[str, int] = {}
    for line in section_output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0].startswith("."):
            try:
                sections[fields[0]] = int(fields[1])
            except ValueError:
                continue
    for required in (".text", ".rodata", ".data", ".bss"):
        if required not in sections:
            fail(f"required section is missing: {required}")

    symbol_output = run(
        [args.nm, "-S", "-C", "--defined-only", "--size-sort", str(args.elf)]
    )
    symbols: list[tuple[int, str]] = []
    code_symbols: list[tuple[int, str]] = []
    for line in symbol_output.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) != 4:
            continue
        _, size_text, kind, name = fields
        if kind.lower() == "a":
            continue
        try:
            size = int(size_text, 16)
        except ValueError:
            continue
        symbols.append((size, name))
        if kind.lower() in {"t", "w"}:
            code_symbols.append((size, name))
    if not symbols:
        fail("ELF has no sized defined symbols; attribution is impossible")

    demos = [name for _, name in symbols if DEMO_SYMBOL.search(name)]
    if demos:
        for name in demos[:20]:
            print(name, file=sys.stderr)
        fail(f"production footprint contains {len(demos)} demo symbols")

    if not code_symbols:
        fail("ELF has no sized code symbols")
    largest_code = max(code_symbols)
    if largest_code[0] > args.max_symbol:
        fail(
            f"code symbol exceeds ceiling: size={largest_code[0]} "
            f"name={largest_code[1]}"
        )
    if sections[".text"] > args.max_text:
        fail(f".text exceeds ceiling: {sections['.text']} > {args.max_text}")
    if sections[".rodata"] > args.max_rodata:
        fail(f".rodata exceeds ceiling: {sections['.rodata']} > {args.max_rodata}")

    attribution: Counter[str] = Counter()
    for size, name in symbols:
        attribution[module_name(name)] += size
    attributed = sum(attribution.values())
    print(
        "production-footprint: sections "
        f"text={sections['.text']} rodata={sections['.rodata']} "
        f"data={sections['.data']} bss={sections['.bss']}"
    )
    print(
        "production-footprint: symbols "
        f"count={len(symbols)} attributed_bytes={attributed} "
        f"code_count={len(code_symbols)} largest_code={largest_code[0]} "
        f"largest_code_symbol={largest_code[1]}"
    )
    for module, size in attribution.most_common(20):
        print(f"production-footprint: module bytes={size} name={module}")
    print(
        "production-footprint: PASS "
        f"demo_symbols=0 max_text={args.max_text} max_rodata={args.max_rodata}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

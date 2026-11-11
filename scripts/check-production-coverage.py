#!/usr/bin/env python3
"""Match QEMU in_asm blocks to production ELF functions and require runtime paths."""

from __future__ import annotations

import argparse
import bisect
import re
import subprocess
import sys
from pathlib import Path

DEMO_SYMBOL = re.compile(r"(?:^|::)(?:[A-Za-z0-9_]+_demo|demo)::")
BLOCK_LINE = re.compile(r"^\s*0x([0-9a-fA-F]+):\s*$")


def fail(message: str) -> None:
    print(f"production-coverage: FAIL: {message}", file=sys.stderr)
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


def function_symbols(elf: Path, nm: str) -> list[tuple[int, int, str]]:
    output = run([nm, "-n", "-S", "-C", "--defined-only", str(elf)])
    entries = []
    for line in output.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) == 4:
            address, size, kind, name = fields
        elif len(fields) == 3:
            address, kind, name = fields
            size = "0"
        else:
            continue
        if kind.lower() not in {"t", "w"}:
            continue
        try:
            start = int(address, 16)
            length = int(size, 16)
        except ValueError:
            continue
        entries.append((start, length, name))
    entries.sort()
    functions = []
    for index, (start, length, name) in enumerate(entries):
        if length == 0 and index + 1 < len(entries):
            next_start = entries[index + 1][0]
            length = next_start - start
        if length > 0:
            functions.append((start, length, name))
    return functions


def executed_blocks(log: Path, load_bias: int) -> set[int]:
    blocks = set()
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        match = BLOCK_LINE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        if address >= load_bias:
            address -= load_bias
        blocks.add(address)
    return blocks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("in_asm", type=Path)
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--load-bias", type=lambda value: int(value, 0), default=0x10000000000)
    parser.add_argument("--require-executed", action="append", default=[])
    args = parser.parse_args()
    if not args.elf.is_file():
        fail(f"ELF does not exist: {args.elf}")
    if not args.in_asm.is_file():
        fail(f"QEMU in_asm log does not exist: {args.in_asm}")
    functions = function_symbols(args.elf, args.nm)
    if not functions:
        fail("ELF has no sized code symbols")
    demo = [name for _, _, name in functions if DEMO_SYMBOL.search(name)]
    if demo:
        fail(f"production coverage input contains {len(demo)} demo symbols")
    blocks = executed_blocks(args.in_asm, args.load_bias)
    if not blocks:
        fail("QEMU in_asm log contains no executed blocks after load-bias adjustment")

    starts = [start for start, _, _ in functions]
    executed_functions: set[int] = set()
    largest_block = max(blocks)
    smallest_block = min(blocks)
    for block in blocks:
        index = bisect.bisect_right(starts, block) - 1
        if index < 0:
            continue
        start, size, _ = functions[index]
        if start <= block < start + size:
            executed_functions.add(start)

    names = {(start, size): name for start, size, name in functions}
    missing = []
    not_executed = []
    for required in args.require_executed:
        matches = [
            (start, size)
            for start, size, name in functions
            if name == required
        ]
        if not matches:
            missing.append(required)
            continue
        if not any(
            start <= block < start + size
            for start, size in matches
            for block in blocks
        ):
            not_executed.append(required)
    if missing:
        fail(f"required symbols are absent: {missing}")
    if not_executed:
        fail(f"required functions did not execute: {not_executed}")

    executed_names = sorted(
        names[(start, size)]
        for start, size in names
        if start in executed_functions
    )
    print(
        "production-coverage: PASS "
        f"blocks={len(blocks)} functions={len(functions)} "
        f"executed_functions={len(executed_functions)} "
        f"block_range={smallest_block:#x}..{largest_block:#x} demo_symbols=0"
    )
    for name in args.require_executed:
        print(f"production-coverage: required name={name} executed=true")
    for name in executed_names[:30]:
        print(f"production-coverage: executed name={name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

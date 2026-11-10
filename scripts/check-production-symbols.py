#!/usr/bin/env python3
"""Reject linked demo code from a production kernel ELF."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

DEMO_SYMBOL = re.compile(r"(?:^|::)(?:[A-Za-z0-9_]+_demo|demo)::")


def fail(message: str) -> None:
    print(f"production-symbols: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--nm", default="nm")
    args = parser.parse_args()
    if not args.elf.is_file():
        fail(f"ELF does not exist: {args.elf}")
    try:
        result = subprocess.run(
            [args.nm, "-C", "--defined-only", str(args.elf)],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot inspect symbols: {exc}")
    symbols = [line for line in result.stdout.splitlines() if line.strip()]
    if not symbols:
        fail("ELF has no defined symbols; linked-code audit is not possible")
    demo_symbols = [line for line in symbols if DEMO_SYMBOL.search(line)]
    if demo_symbols:
        for symbol in demo_symbols[:40]:
            print(symbol, file=sys.stderr)
        fail(f"production ELF contains {len(demo_symbols)} demo symbols")
    print(f"production-symbols: PASS symbols={len(symbols)} demo_symbols=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

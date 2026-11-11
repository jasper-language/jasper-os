#!/usr/bin/env python3
"""Build the direct-call graph of a production ELF from named code symbols."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import deque
from pathlib import Path

DEMO_SYMBOL = re.compile(r"(?:^|::)(?:[A-Za-z0-9_]+_demo|demo)::")
FUNCTION_LINE = re.compile(r"^([0-9a-fA-F]+) <(.+)>:$")
CALL_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:call|jmp)\s+(.+?)\s*$"
)


def fail(message: str) -> None:
    print(f"production-callgraph: FAIL: {message}", file=sys.stderr)
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


def symbols(elf: Path, nm: str) -> dict[int, tuple[int, str]]:
    output = run([nm, "-n", "-S", "-C", "--defined-only", str(elf)])
    result: dict[int, tuple[int, str]] = {}
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
            result[int(address, 16)] = (int(size, 16), name)
        except ValueError:
            continue
    return result


def relative_relocations(elf: Path) -> dict[int, int]:
    output = run(["readelf", "-rW", str(elf)])
    result: dict[int, int] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[2] != "R_X86_64_RELATIVE":
            continue
        try:
            result[int(fields[0], 16)] = int(fields[-1].split("+", 1)[0], 16)
        except ValueError:
            continue
    return result


def build_graph(
    elf: Path,
    nm: str,
    objdump: str,
) -> tuple[
    dict[int, tuple[int, str]],
    dict[int, set[int]],
    dict[int, int],
]:
    code = symbols(elf, nm)
    relocations = relative_relocations(elf)
    output = run([objdump, "-d", "--demangle", "--no-show-raw-insn", str(elf)])
    graph: dict[int, set[int]] = {address: set() for address in code}
    unresolved: dict[int, int] = {}
    current = None
    for line in output.splitlines():
        function = FUNCTION_LINE.match(line)
        if function:
            current = int(function.group(1), 16)
            continue
        if current is None:
            continue
        call = CALL_LINE.match(line)
        if not call:
            continue
        operand = call.group(2)
        target = None
        direct = re.match(r"^([0-9a-fA-F]+)\s+<", operand)
        if direct:
            target = int(direct.group(1), 16)
        else:
            pointer = re.search(r"#\s*([0-9a-fA-F]+)", operand)
            if pointer:
                target = relocations.get(int(pointer.group(1), 16))
        if target in code:
            graph.setdefault(current, set()).add(target)
        elif "*" in operand:
            unresolved[current] = unresolved.get(current, 0) + 1
    return code, graph, unresolved


def roots(code: dict[int, tuple[int, str]]) -> set[int]:
    result = set()
    for address, (_, name) in code.items():
        if name in {
            "_start",
            "jsr_syscall_entry",
            "jasper_kernel::smp::secondary_main",
            "jasper_kernel::arch::x86_64::smp::ap_entry",
            "jasper_kernel::production::first_program",
            "jasper_kernel::production::wait_for_services",
            "jasper_kernel::production::minimum_health",
        } or (
            "jasper_kernel::arch::x86_64::idt::" in name
            and name.endswith("handler")
        ):
            result.add(address)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--objdump", default="objdump")
    parser.add_argument("--require-reachable", action="append", default=[])
    args = parser.parse_args()
    if not args.elf.is_file():
        fail(f"ELF does not exist: {args.elf}")
    code, graph, unresolved = build_graph(args.elf, args.nm, args.objdump)
    if not code:
        fail("ELF has no named text symbols")
    demo = [name for _, name in code.values() if DEMO_SYMBOL.search(name)]
    if demo:
        for name in demo[:20]:
            print(name, file=sys.stderr)
        fail(f"production call graph contains {len(demo)} demo symbols")
    starts = roots(code)
    if not starts:
        fail("no production entry or interrupt roots were found")

    names = {name: address for address, (_, name) in code.items()}
    missing_roots = [name for name in args.require_reachable if name not in names]
    if missing_roots:
        fail(f"required symbols are absent: {missing_roots}")
    reachable = set(starts)
    queue = deque(starts)
    while queue:
        current = queue.popleft()
        for target in graph.get(current, ()):
            if target not in reachable:
                reachable.add(target)
                queue.append(target)

    unreachable_required = [
        name for name in args.require_reachable if names[name] not in reachable
    ]
    if unreachable_required:
        fail(f"required symbols are not directly reachable: {unreachable_required}")
    unresolved_calls = sum(unresolved.values())
    unreachable = sorted(
        (size, name)
        for address, (size, name) in code.items()
        if address not in reachable and size > 0
    )
    print(
        "production-callgraph: PASS "
        f"functions={len(code)} roots={len(starts)} reachable={len(reachable)} "
        f"direct_edges={sum(len(edges) for edges in graph.values())} "
        f"unresolved_indirect={unresolved_calls} "
        f"unreachable_named={len(unreachable)} demo_symbols=0"
    )
    for size, name in sorted(unreachable, reverse=True)[:20]:
        print(f"production-callgraph: unreachable bytes={size} name={name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

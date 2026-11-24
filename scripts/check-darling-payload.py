#!/usr/bin/env python3
"""Validate the pinned Darling research payload without executing it."""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "verification/darling-payload.toml"

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_X86_64 = 0x01000007
MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_DYLINKER = 0x7
LC_LOAD_DYLIB = 0xC
LC_LOAD_DYLINKER = 0xE
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_MAIN = 0x80000028


class ValidationError(ValueError):
    """The Darling research payload is malformed or changed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def bounded_struct(data: bytes, offset: int, size: int) -> bytes:
    require(offset >= 0 and size >= 0 and offset + size <= len(data), "truncated object")
    return data[offset : offset + size]


def select_x86_64_slice(data: bytes) -> bytes:
    require(len(data) >= 8, "object is too small")
    magic = struct.unpack(">I", data[:4])[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        return data
    count = struct.unpack(">I", data[4:8])[0]
    require(0 < count <= 32, "invalid fat architecture count")
    entry_size = 32 if magic == FAT_MAGIC_64 else 20
    table_end = 8 + count * entry_size
    require(table_end <= len(data), "truncated fat architecture table")
    for index in range(count):
        offset = 8 + index * entry_size
        if entry_size == 20:
            cpu, _, slice_offset, slice_size, _ = struct.unpack(
                ">IIIII", bounded_struct(data, offset, entry_size)
            )
        else:
            cpu, _, slice_offset, slice_size, _, _ = struct.unpack(
                ">IIQQII", bounded_struct(data, offset, entry_size)
            )
        if cpu != CPU_TYPE_X86_64:
            continue
        require(slice_size >= 32, "empty x86_64 slice")
        return bounded_struct(data, slice_offset, slice_size)
    raise ValidationError("fat object has no x86_64 slice")


def parse_macho(data: bytes) -> dict[str, Any]:
    image = select_x86_64_slice(data)
    require(
        struct.unpack("<I", bounded_struct(image, 0, 4))[0] == MH_MAGIC_64,
        "Mach-O object is not 64-bit little-endian",
    )
    (
        _magic,
        cpu_type,
        _cpu_subtype,
        file_type,
        command_count,
        command_bytes,
        _flags,
        _reserved,
    ) = struct.unpack("<IIIIIIII", bounded_struct(image, 0, 32))
    require(cpu_type == CPU_TYPE_X86_64, "Mach-O CPU is not x86_64")
    require(command_count <= 4096, "Mach-O command count is excessive")
    require(32 + command_bytes <= len(image), "truncated Mach-O command area")
    cursor = 32
    dependencies: list[str] = []
    has_dylinker = False
    has_main = False
    for _ in range(command_count):
        command, size = struct.unpack("<II", bounded_struct(image, cursor, 8))
        require(size >= 8 and cursor + size <= 32 + command_bytes, "invalid load command")
        if command in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
            name_offset = struct.unpack("<I", bounded_struct(image, cursor + 8, 4))[0]
            require(12 <= name_offset < size, "invalid dylib name offset")
            name = bounded_struct(image, cursor + name_offset, size - name_offset)
            dependencies.append(name.split(b"\0", 1)[0].decode("utf-8", "replace"))
        elif command == LC_LOAD_DYLINKER:
            name_offset = struct.unpack("<I", bounded_struct(image, cursor + 8, 4))[0]
            require(12 <= name_offset < size, "invalid dylinker name offset")
            has_dylinker = True
        elif command == LC_MAIN:
            require(size >= 24, "truncated LC_MAIN")
            has_main = True
        cursor += size
    return {
        "file_type": file_type,
        "dependencies": dependencies,
        "has_dylinker": has_dylinker,
        "has_main": has_main,
    }


def synthetic_macho() -> bytes:
    dylinker = b"/usr/lib/dyld\0"
    dylinker_command_size = (12 + len(dylinker) + 7) & ~7
    dylib = b"/usr/lib/libSystem.B.dylib\0"
    dylib_command_size = (24 + len(dylib) + 7) & ~7
    commands = bytearray()
    commands += struct.pack("<III", LC_LOAD_DYLINKER, dylinker_command_size, 12)
    commands += dylinker.ljust(dylinker_command_size - 12, b"\0")
    commands += struct.pack(
        "<IIIIII", LC_LOAD_DYLIB, dylib_command_size, 24, 0, 0, 0
    )
    commands += dylib.ljust(dylib_command_size - 24, b"\0")
    header = struct.pack(
        "<IIIIIIII",
        MH_MAGIC_64,
        CPU_TYPE_X86_64,
        3,
        MH_EXECUTE,
        2,
        len(commands),
        0,
        0,
    )
    return header + commands


def self_test() -> None:
    parsed = parse_macho(synthetic_macho())
    require(parsed["file_type"] == MH_EXECUTE, "synthetic file type mismatch")
    require(parsed["has_dylinker"], "synthetic dylinker command missing")
    require(
        parsed["dependencies"] == ["/usr/lib/libSystem.B.dylib"],
        "synthetic dependency mismatch",
    )
    malformed = bytearray(synthetic_macho())
    malformed[32:40] = struct.pack("<II", LC_LOAD_DYLIB, 0xFFFF_FFFF)
    try:
        parse_macho(bytes(malformed))
    except ValidationError:
        pass
    else:
        raise AssertionError("oversized load command was accepted")
    print("darling-payload: self-test PASS")


def validate_tree(tree: Path) -> int:
    spec = tomllib.loads(SPEC.read_text(encoding="utf-8"))
    require(spec.get("schema") == 1, "payload schema must be 1")
    require(spec.get("architecture") == "x86_64", "payload architecture changed")
    require(
        spec.get("claim") == "research inventory only; no Jasper guest execution",
        "payload claim boundary changed",
    )
    payloads = spec.get("payload", [])
    require(len(payloads) == 8, "payload inventory size mismatch")
    seen: set[str] = set()
    for item in payloads:
        relative = item["path"]
        require(relative not in seen, f"duplicate payload path {relative}")
        seen.add(relative)
        path = tree / relative
        require(path.is_file(), f"missing payload {relative}")
        data = path.read_bytes()
        require(len(data) == item["size"], f"payload size mismatch {relative}")
        require(
            hashlib.sha256(data).hexdigest() == item["sha256"],
            f"payload digest mismatch {relative}",
        )
        expected_format = item["format"]
        if expected_format == "elf64":
            require(data[:4] == b"\x7fELF", f"payload is not ELF {relative}")
            require(len(data) >= 5 and data[4] == 2, f"payload is not ELF64 {relative}")
        elif expected_format.startswith("macho"):
            parsed = parse_macho(data)
            role = item["role"]
            if role in {"mach-o-loader", "mach-o-echo", "launchd"}:
                require(parsed["file_type"] == MH_EXECUTE, f"not MH_EXECUTE {relative}")
                require(parsed["has_dylinker"], f"missing LC_LOAD_DYLINKER {relative}")
                require(parsed["has_main"], f"missing LC_MAIN {relative}")
            elif role == "darwin-dyld":
                require(parsed["file_type"] == MH_DYLINKER, f"not MH_DYLINKER {relative}")
            elif role in {"libsystem", "corefoundation"}:
                require(parsed["file_type"] == MH_DYLIB, f"not MH_DYLIB {relative}")
                require(
                    bool(parsed["dependencies"]),
                    f"no Mach-O dependencies {relative}",
                )
            else:
                raise ValidationError(f"unknown Mach-O role {role}")
        else:
            raise ValidationError(f"unknown payload format {expected_format}")
    print(f"darling-payload: PASS payloads={len(payloads)} architecture=x86_64")
    return len(payloads)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--tree", type=Path)
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            if args.tree is None:
                with tempfile.TemporaryDirectory() as directory:
                    del directory
                return 0
        if args.tree is None:
            parser.error("--tree is required unless only running --self-test")
        validate_tree(args.tree.resolve())
        return 0
    except (OSError, KeyError, tomllib.TOMLDecodeError, ValidationError) as error:
        print(f"darling-payload: FAIL {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

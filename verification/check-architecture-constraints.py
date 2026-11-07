#!/usr/bin/env python3
"""Validate the machine-readable issue #11 architecture constraints."""

from __future__ import annotations

import pathlib
import tomllib


ROOT = pathlib.Path(__file__).resolve().parent.parent
MATRIX = ROOT / "verification/architecture_constraints.toml"
DOC = ROOT / "docs/issue-11-架构约束.md"
PROFILE_ERRORS = ROOT / "kernel-core/src/profile.rs"
ASSEMBLY_ERRORS = ROOT / "kernel-core/src/assembly.rs"
SYSCALL = ROOT / "kernel/src/syscall/mod.rs"
REGISTRY = ROOT / "abi/system-ids.txt"

REQUIRED_DIMENSIONS = {
    "dependency_closure",
    "execution_domain",
    "resource_rights",
    "call_or_ipc",
    "object_references",
    "lifecycle",
    "boot_graph",
    "time_guarantee",
    "platform_premise",
}


def fail(message: str) -> None:
    raise SystemExit(f"architecture constraints: FAIL: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def main() -> None:
    with MATRIX.open("rb") as source:
        matrix = tomllib.load(source)

    require(matrix.get("schema") == 1, "unsupported schema")
    require(matrix.get("baseline") == "dc3f7ba", "unexpected baseline")
    dimensions = set(matrix.get("dimensions", {}).get("required", []))
    require(dimensions == REQUIRED_DIMENSIONS, "dimension set differs from the release matrix")

    k_items = matrix.get("k_items", [])
    require({item.get("id") for item in k_items} == {f"K-0{i}" for i in range(1, 9)},
            "K-01 through K-08 must each appear exactly once")
    require(all(item.get("disposition") for item in k_items), "K item lacks disposition")

    legal = matrix.get("legal_profiles", [])
    require({item.get("id") for item in legal} == {"headless", "headless-min"},
            "legal profile cases must cover both built-in profiles")

    illegal = matrix.get("illegal_configs", [])
    illegal_ids = [item.get("id") for item in illegal]
    require(len(illegal_ids) == len(set(illegal_ids)), "illegal case ids must be unique")
    require(all(item.get("expected_code") for item in illegal), "illegal case lacks rejection code")

    profile_source = PROFILE_ERRORS.read_text(encoding="utf-8")
    assembly_source = ASSEMBLY_ERRORS.read_text(encoding="utf-8")
    syscall_source = SYSCALL.read_text(encoding="utf-8")
    for code in ("missing_capability", "dependency_cycle", "service_conflict", "ambiguous_service"):
        require(code in profile_source or code in assembly_source, f"rejection code not found: {code}")
    require("operation_route" in assembly_source, "operation_route implementation missing")
    require("operation_audit" in syscall_source or "operation_route" in syscall_source,
            "syscall self-check does not enforce operation ownership")
    require("Ungated" not in assembly_source and "Ungated" not in syscall_source,
            "ungated system-call path must not remain")

    registered = {
        fields[2]
        for line in REGISTRY.read_text(encoding="utf-8").splitlines()
        if not line.startswith("#") and len(fields := line.split("\t")) >= 3 and fields[1] == "op"
    }
    reserved = set(matrix.get("reserved_unsupported", {}).get("operations", []))
    require(reserved <= registered, f"reserved operation is not registered: {sorted(reserved - registered)}")

    documentation = DOC.read_text(encoding="utf-8")
    for k in (f"K-0{i}" for i in range(1, 9)):
        require(k in documentation, f"architecture document lacks {k}")
    for topic in ("跨域", "取消", "服务死亡", "启动回滚", "性能"):
        require(topic in documentation, f"architecture document lacks {topic} contract")

    k06 = matrix.get("k06", {})
    require(k06.get("standard_active_unavailable") == 0, "standard profile must assemble all services")
    require(k06.get("minimum_active_unavailable", 0) > 0, "minimal profile must omit a service module")
    require(k06.get("standard_ring") == "available", "standard async ring must be available")
    require(k06.get("minimum_ring") == "unavailable", "minimal async ring must be unavailable")

    print(
        "architecture constraints: PASS "
        f"k_items={len(k_items)} legal={len(legal)} illegal={len(illegal)} "
        f"dimensions={len(dimensions)}"
    )


if __name__ == "__main__":
    main()

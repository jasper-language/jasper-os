#!/usr/bin/env python3
"""Validate the COMPAT-D3D-1 D3D12 fixture and asset boundary."""

from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "verification/compat-d3d12.toml"
PROBE = ROOT / "verification/fixtures/windows/d3d12_probe.c"
BUILD = ROOT / "scripts/build-d3d12-probe.sh"
STAGE = ROOT / "scripts/prepare-vkd3d-proton-tree.sh"


class ValidationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def validate(matrix: dict[str, Any]) -> tuple[int, int]:
    require(matrix.get("schema") == 1, "schema must be 1")
    require(matrix.get("node") == "COMPAT-D3D-1", "wrong DAG node")
    require(matrix.get("status") == "core-passed", "fixture cannot promote D3D node")
    require(
        matrix.get("acceptance_claim") == "bounded-fixture-not-runtime-pass",
        "fixture must not claim a D3D12 runtime pass",
    )

    baseline = matrix.get("baseline", {})
    require(baseline.get("name") == "VKD3D-Proton", "wrong baseline")
    require(baseline.get("version") == "3.1", "wrong VKD3D version")
    require(
        baseline.get("archive_sha256")
        == "b85ea8219b71093a3924913dd7aae6172333dc0c069983ed510816d67f02120b",
        "VKD3D archive digest drift",
    )
    require(baseline.get("license") == "LGPL-2.1", "license must be pinned")
    require(baseline.get("backend") == "Vulkan", "D3D12 baseline must target Vulkan")

    artifacts = {item.get("path"): item for item in matrix.get("artifact", [])}
    require(
        set(artifacts)
        == {
            "vkd3d-proton-3.1/x64/d3d12.dll",
            "vkd3d-proton-3.1/x64/d3d12core.dll",
        },
        "x64 VKD3D artifact set mismatch",
    )
    require(
        artifacts["vkd3d-proton-3.1/x64/d3d12.dll"].get("sha256")
        == "502694a5fd5e06381ef2cdb33359c5948b6a012938902ddc9e9b381841bc0ce7",
        "d3d12.dll digest drift",
    )
    require(
        artifacts["vkd3d-proton-3.1/x64/d3d12core.dll"].get("sha256")
        == "0dfd690a39ef8361ca3b64e9fd8e945b27d2c568dac5dc0dce1a45abf65914cc",
        "d3d12core.dll digest drift",
    )

    cases = {item.get("id"): item for item in matrix.get("case", [])}
    require(
        set(cases)
        == {
            "d3d11-offscreen-core",
            "d3d12-offscreen-fixture",
            "d3d12-offscreen-runtime",
            "wsi-present",
            "physical-gpu",
        },
        "case set mismatch",
    )
    require(cases["d3d11-offscreen-core"].get("status") == "passed", "D3D11 core evidence missing")
    require(
        cases["d3d11-offscreen-core"].get("hardware_gpu") is False,
        "software D3D11 result cannot claim hardware GPU",
    )
    require(
        cases["d3d12-offscreen-fixture"].get("status") == "fixture-available",
        "D3D12 fixture must remain fixture-available",
    )
    fixture_evidence = ROOT / cases["d3d12-offscreen-fixture"].get("evidence", "")
    require(fixture_evidence.is_file(), "D3D12 fixture build evidence is missing")
    require(
        "No `D3D12_PROBE_OK` marker has been captured in Jasper"
        in fixture_evidence.read_text(encoding="utf-8"),
        "fixture build evidence must not claim a Jasper runtime pass",
    )
    for case_id in ("d3d12-offscreen-runtime", "wsi-present", "physical-gpu"):
        require(cases[case_id].get("status") == "not-run", f"{case_id} cannot be passed")
    require(cases["physical-gpu"].get("hardware_gpu") is True, "physical gate required")

    gates = {item.get("id") for item in matrix.get("remaining_gate", [])}
    require(
        gates
        == {
            "d3d12-runtime-through-wine",
            "swapchain-wsi-present",
            "input-and-desktop",
            "resource-reclamation",
            "physical-gpu-and-pixel6a",
        },
        "remaining D3D12 gates mismatch",
    )

    source = PROBE.read_text(encoding="utf-8")
    required_calls = (
        "D3D12CreateDevice",
        "CreateCommandQueue",
        "CreateCommandAllocator",
        "CreateCommandList",
        "CreateCommittedResource",
        "CreateRenderTargetView",
        "ClearRenderTargetView",
        "CopyTextureRegion",
        "ID3D12Resource_Map",
    )
    for call in required_calls:
        require(call in source, f"probe missing required operation: {call}")
    require(
        "D3D12_PROBE_OK pixel=32,64,128,255 observed=" in source,
        "probe success marker must carry the accepted pixel tuple",
    )
    require("d3d11.h" not in source, "D3D12 probe must not depend on d3d11.h")
    require("D3D11_PROBE_OK" not in source, "D3D11 marker cannot substitute for D3D12")
    require("--disable-dynamicbase" in source, "bounded image-base limitation must be explicit")

    build = BUILD.read_text(encoding="utf-8")
    require("x86_64-w64-mingw32-gcc" in build, "probe toolchain must be explicit")
    require(
        "-Werror" in build
        and "-ld3d12" in build
        and "-ldxguid" in build
        and "-luuid" in build,
        "strict probe build flags missing",
    )

    stage = STAGE.read_text(encoding="utf-8")
    require(baseline["archive_sha256"] in stage, "staging script digest is not pinned")
    require("tar --zstd -xf" in stage, "staging script must extract the pinned archive")
    require("d3d12core.dll" in stage, "staging script must verify D3D12 core")
    return len(cases), len(gates)


def self_test(matrix: dict[str, Any]) -> None:
    broken = copy.deepcopy(matrix)
    broken["status"] = "done"
    try:
        validate(broken)
    except ValidationError:
        pass
    else:
        raise AssertionError("checker accepted a fabricated done status")

    broken = copy.deepcopy(matrix)
    next(item for item in broken["case"] if item["id"] == "d3d12-offscreen-runtime")[
        "status"
    ] = "passed"
    try:
        validate(broken)
    except ValidationError:
        pass
    else:
        raise AssertionError("checker accepted an unexecuted D3D12 runtime pass")

    broken = copy.deepcopy(matrix)
    broken["baseline"]["archive_sha256"] = "0" * 64
    try:
        validate(broken)
    except ValidationError:
        pass
    else:
        raise AssertionError("checker accepted a digest drift")


def main() -> int:
    matrix = tomllib.loads(MATRIX.read_text(encoding="utf-8"))
    self_test(matrix)
    cases, gates = validate(matrix)
    print(
        "compat-d3d12: PASS "
        f"status={matrix['status']} cases={cases} remaining={gates} runtime=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

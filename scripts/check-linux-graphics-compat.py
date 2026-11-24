#!/usr/bin/env python3
"""Validate the public COMPAT-GRAPHICS-1 evidence matrix."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "verification/linux-graphics-compat.toml"
DOC = ROOT / "docs/LINUX-GRAPHICS-COMPAT-status.md"
SCRIPT = ROOT / "scripts/compat-graphics-software-check.sh"


def fail(message: str) -> None:
    raise SystemExit(f"linux-graphics-compat: FAIL: {message}")


def main() -> int:
    matrix = tomllib.loads(MATRIX.read_text(encoding="utf-8"))
    if matrix.get("schema") != 1:
        fail("schema must be 1")
    if matrix.get("node") != "COMPAT-GRAPHICS-1":
        fail("wrong DAG node")
    if matrix.get("status") != "core-passed":
        fail("software evidence cannot promote the node past core-passed")

    cases = {case["id"]: case for case in matrix.get("case", [])}
    required = {
        "vulkan-capability-profiling",
        "wsi-input-lifecycle",
        "gpu-import-submit-sync-reset",
        "vulkan-loader-swiftshader-compute",
        "metal2vulkan-render-lavapipe",
    }
    if set(cases) != required:
        fail(f"case set mismatch: expected {sorted(required)}, got {sorted(cases)}")
    for case in cases.values():
        if not case.get("command") or not case.get("evidence"):
            fail(f"case {case['id']} lacks command or evidence")
        if case["id"] not in {
            "vulkan-loader-swiftshader-compute",
            "metal2vulkan-render-lavapipe",
        }:
            if case.get("hardware_gpu") is not False:
                fail(f"case {case['id']} must not claim hardware GPU")
    software = cases["vulkan-loader-swiftshader-compute"]
    if software.get("kind") != "qemu-software" or software.get("hardware_gpu") is not False:
        fail("software loader/ICD case must remain qemu-software and hardware_gpu=false")
    render = cases["metal2vulkan-render-lavapipe"]
    if (
        render.get("kind") != "qemu-software"
        or render.get("hardware_gpu") is not False
        or render.get("status") != "passed"
    ):
        fail("Metal2Vulkan render must remain bounded software evidence")
    render_evidence = ROOT / render["evidence"]
    if not render_evidence.is_file():
        fail("Metal2Vulkan render evidence is missing")
    render_text = render_evidence.read_text(encoding="utf-8")
    for marker in (
        "device: llvmpipe",
        "every texel as expected",
        "program=metal2vulkan-render",
        "resources=true",
        "qemu_rc=33",
    ):
        if marker not in render_text:
            fail(f"Metal2Vulkan evidence lacks marker: {marker}")

    gates = {gate["id"] for gate in matrix.get("remaining_gate", [])}
    if gates != {
        "physical-gpu-vulkan-wsi",
        "metal2vulkan-wsi-present",
    }:
        fail("hardware and D3D remaining gates must remain explicit")

    if not SCRIPT.is_file():
        fail("software acceptance script is missing")
    text = DOC.read_text(encoding="utf-8")
    for phrase in ("软件 Vulkan loader/ICD 执行", "CPU 设备", "物理 GPU"):
        if phrase not in text:
            fail(f"status document lacks boundary: {phrase}")

    print(
        "linux-graphics-compat: PASS "
        f"cases={len(cases)} remaining={len(gates)} status=core-passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

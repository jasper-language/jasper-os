#!/usr/bin/env python3
"""Enforce backend-neutral system.gpu/service.ui boundaries and UI isolation."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYSTEM_IDS = ROOT / "abi" / "system-ids.txt"
GPU_SOURCE_ROOTS = (ROOT / "kernel" / "src", ROOT / "kernel-core" / "src")
KERNEL_MANIFESTS = (
    ROOT / "kernel" / "Cargo.toml",
    ROOT / "kernel-core" / "Cargo.toml",
)
FORBIDDEN_API_TOKENS = (
    "VkInstance",
    "VkPhysicalDevice",
    "VkDevice",
    "VkDeviceMemory",
    "VkQueue",
    "VkSwapchain",
    "VkCommandBuffer",
    "VkSemaphore",
    "VkFence",
)
FORBIDDEN_CRATES = (
    "ash",
    "vulkano",
    "wgpu",
    "blitz",
    "vello",
    "parley",
    "jasper-ui-engine",
    "jasper-ui-framework",
)
API_NAME = re.compile(r"(?:vulkan|(?<![A-Za-z])vk[A-Z0-9_]*)", re.IGNORECASE)


def scan_registry(text: str) -> list[str]:
    findings: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if len(fields) < 3 or fields[1] != "op":
            continue
        name = fields[2]
        if (name.startswith("system.gpu.") or name.startswith("service.ui.")) and API_NAME.search(
            name
        ):
            findings.append(
                f"abi/system-ids.txt:{line_number}: backend API leaked into {name}"
            )
    return findings


def scan_source(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    relevant = "gpu" in path.name.lower() or "system.gpu" in text
    if not relevant:
        return findings
    for line_number, line in enumerate(text.splitlines(), 1):
        for token in FORBIDDEN_API_TOKENS:
            if token in line:
                display = (
                    path.relative_to(ROOT).as_posix()
                    if path.is_relative_to(ROOT)
                    else path.as_posix()
                )
                findings.append(
                    f"{display}:{line_number}: "
                    f"Vulkan object type {token} in generic GPU mechanism"
                )
    return findings


def scan_manifest(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        package = line.split("=", 1)[0].strip().strip('"')
        if package in FORBIDDEN_CRATES:
            display = (
                path.relative_to(ROOT).as_posix()
                if path.is_relative_to(ROOT)
                else path.as_posix()
            )
            findings.append(
                f"{display}:{line_number}: "
                f"UI/GPU API crate {package} linked into kernel layer"
            )
    return findings


def scan() -> list[str]:
    findings = scan_registry(SYSTEM_IDS.read_text(encoding="utf-8"))
    for root in GPU_SOURCE_ROOTS:
        for path in sorted(root.rglob("*.rs")):
            findings.extend(
                scan_source(path, path.read_text(encoding="utf-8", errors="replace"))
            )
    for path in KERNEL_MANIFESTS:
        findings.extend(scan_manifest(path, path.read_text(encoding="utf-8")))
    return findings


def self_test() -> None:
    registry = (
        "1 op system.gpu.vulkan.queue.create 1 write x\n"
        "2 op service.ui.session.create 1 write x\n"
        "3 op system.gpu.queue.create 1 write x\n"
    )
    assert scan_registry(registry) == [
        "abi/system-ids.txt:1: backend API leaked into system.gpu.vulkan.queue.create"
    ]
    assert scan_source(Path("kernel/src/gpu.rs"), "pub struct Queue(VkQueue);")
    assert not scan_source(Path("kernel/src/display.rs"), "framebuffer only")
    assert scan_manifest(Path("kernel/Cargo.toml"), 'wgpu = "1"')
    print("gpu-abi-boundary: self-test PASS")


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        self_test()
        return 0
    findings = scan()
    if findings:
        print("gpu-abi-boundary: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(
        "gpu-abi-boundary: PASS registry=backend-neutral kernel/no-ui-engine "
        "gpu/no-vulkan-objects"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail closed unless the D3D11 WSI fixture preserves every required layer."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import sys
import tempfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "verification/fixtures/windows/d3d11_wsi_probe.c"
MANIFEST = ROOT / "verification/d3d11-wsi-probe.toml"
CARGO = ROOT / "kernel/Cargo.toml"
VFS = ROOT / "kernel/src/linux_vfs.rs"
LIFECYCLE = ROOT / "kernel/src/lifecycle_health.rs"
BOOT = ROOT / "scripts/issue21-uefi-boot-check.sh"
STAGING_MANIFEST = ROOT / "verification/wine-d3d-staging.json"
PASS_MARKER = "D3D11_WSI_PROBE_OK"
FAIL_MARKER = "D3D11_WSI_PROBE_FAIL"


class ValidationError(RuntimeError):
    """The WSI fixture or evidence claim is incomplete."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def validate_source(source: str) -> None:
    required = (
        "CreateWindowExW(",
        "D3D11CreateDevice(",
        "IDXGIFactory2_CreateSwapChainForHwnd(",
        "IDXGISwapChain1_GetBuffer(",
        "ClearRenderTargetView(",
        "IDXGISwapChain1_Present(",
        "result != S_OK",
        "__wineservice_winstation",
    )
    for token in required:
        require(token in source, f"required WSI operation is missing: {token}")
    require(source.count(PASS_MARKER) == 1, "the pass marker must occur exactly once")
    require(source.count(FAIL_MARKER) >= 2, "failure paths must remain explicit")
    require(source.count("IDXGISwapChain1_Present(") == 1, "duplicate Present calls are ambiguous")

    order = [
        "CreateWindowExW(",
        "IDXGIFactory2_CreateSwapChainForHwnd(",
        "IDXGISwapChain1_GetBuffer(",
        "IDXGISwapChain1_Present(",
        PASS_MARKER,
    ]
    positions = [source.index(token) for token in order]
    require(positions == sorted(positions), "pass marker is emitted before the WSI chain")


def validate_manifest(manifest: dict[str, object]) -> None:
    require(manifest.get("schema") == 1, "manifest schema must be 1")
    require(manifest.get("id") == "COMPAT-D3D11-WSI-1", "WSI fixture identity mismatch")
    require(manifest.get("status") == "verification-pending", "WSI fixture cannot claim a pass")
    require(manifest.get("jasper_guest_passed") is False, "Jasper guest pass is not established")
    require(manifest.get("physical_gpu_passed") is False, "physical GPU pass is not established")
    require(manifest.get("source") == SOURCE.relative_to(ROOT).as_posix(), "source path mismatch")
    require(manifest.get("binary_bytes") == 659156, "reference binary size mismatch")
    require(
        manifest.get("binary_sha256")
        == "cbd9bb9aa7298fdd90d32abdc25df21ea98452a198fbe20e49bc088dc153da11",
        "reference binary digest mismatch",
    )
    evidence = ROOT / str(manifest.get("build_evidence", ""))
    require(evidence.is_file(), "reference build evidence is missing")
    require(
        str(manifest["binary_sha256"]) in evidence.read_text(encoding="utf-8"),
        "reference binary digest is absent from build evidence",
    )
    require(manifest.get("pass_marker") == PASS_MARKER, "pass marker mismatch")
    require(manifest.get("fail_marker") == FAIL_MARKER, "fail marker mismatch")
    layers = manifest.get("required_layer")
    require(isinstance(layers, list), "required layers must be a list")
    expected = {
        "wine-service-desktop",
        "win32u-window",
        "dxgi-swapchain",
        "dxvk-vulkan-wsi",
        "jasper-vulkan-surface",
        "present",
    }
    require(set(layers) == expected, "required WSI layer set mismatch")
    require(bool(manifest.get("blockers")), "at least one explicit blocker is required")

    cargo = CARGO.read_text(encoding="utf-8")
    require(
        'compat-wine-wsi-verify = ["compat-wine-d3d-verify"]' in cargo,
        "D3D11 WSI verification feature is not wired",
    )
    vfs = VFS.read_text(encoding="utf-8")
    require(
        "/opt/wine-devel/lib/wine/x86_64-windows/d3d11-wsi-probe.exe" in vfs,
        "D3D11 WSI VFS path is missing",
    )
    lifecycle = LIFECYCLE.read_text(encoding="utf-8")
    require(
        'feature = "compat-wine-wsi-verify"' in lifecycle,
        "D3D11 WSI probe is not behind its verification feature",
    )
    require(
        'run_root_dynamic_program_with_deadline(\n                    "compat-wine-wsi"'
        in lifecycle,
        "D3D11 WSI program identity is missing",
    )
    boot = BOOT.read_text(encoding="utf-8")
    require("compat-wine-wsi)" in boot, "D3D11 WSI UEFI mode is missing")
    require("^D3D11_WSI_PROBE_OK .*present=1" in boot,
            "D3D11 WSI marker gate is missing")
    require("program=compat-wine-wsi " in boot,
            "D3D11 WSI lifecycle gate is missing")
    staged = json.loads(STAGING_MANIFEST.read_text(encoding="utf-8"))
    require(
        staged.get("final_files", {}).get(
            "opt/wine-devel/lib/wine/x86_64-windows/d3d11-wsi-probe.exe"
        )
        == manifest["binary_sha256"],
        "D3D11 WSI staging digest mismatch",
    )


def validate_binary(path: Path, *, enforce_reference: bool = True) -> None:
    data = path.read_bytes()
    if enforce_reference:
        require(len(data) == 659156, f"reference PE size mismatch: {len(data)}")
        require(
            hashlib.sha256(data).hexdigest()
            == "cbd9bb9aa7298fdd90d32abdc25df21ea98452a198fbe20e49bc088dc153da11",
            "reference PE digest mismatch",
        )
    require(data[:2] == b"MZ", "artifact is not a PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    require(data[pe_offset:pe_offset + 4] == b"PE\0\0", "missing PE signature")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    require(machine == 0x8664, f"PE machine must be x86_64, got 0x{machine:04x}")
    require(PASS_MARKER.encode() in data, "artifact does not contain the pass marker")
    require(FAIL_MARKER.encode() in data, "artifact does not contain the fail marker")


def load_manifest() -> dict[str, object]:
    with MANIFEST.open("rb") as source:
        manifest = tomllib.load(source)
    validate_manifest(manifest)
    return manifest


def self_test() -> None:
    manifest = load_manifest()
    source = SOURCE.read_text(encoding="utf-8")
    validate_source(source)

    missing_window = source.replace("CreateWindowExW(", "CreateWindowExA(", 1)
    try:
        validate_source(missing_window)
    except ValidationError:
        pass
    else:
        raise ValidationError("source without CreateWindowExW was accepted")

    premature_marker = source.replace(
        "result = IDXGISwapChain1_Present(swapchain, 1, 0);",
        f'printf("{PASS_MARKER}\\n");\n'
        "    result = IDXGISwapChain1_Present(swapchain, 1, 0);",
        1,
    )
    try:
        validate_source(premature_marker)
    except ValidationError:
        pass
    else:
        raise ValidationError("pass marker before Present was accepted")

    bad = copy.deepcopy(manifest)
    bad["jasper_guest_passed"] = True
    try:
        validate_manifest(bad)
    except ValidationError:
        pass
    else:
        raise ValidationError("unproven Jasper guest pass was accepted")

    image = bytearray(0x100)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", image, 0x44, 0x8664)
    image.extend(PASS_MARKER.encode() + b"\0" + FAIL_MARKER.encode() + b"\0")
    with tempfile.NamedTemporaryFile(prefix="jasper-wsi-pe-") as binary:
        binary.write(image)
        binary.flush()
        validate_binary(Path(binary.name), enforce_reference=False)

    print(
        "d3d11-wsi-probe: self-test PASS "
        f"layers={len(manifest['required_layer'])} fail_closed=true"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    try:
        manifest = load_manifest()
        validate_source(SOURCE.read_text(encoding="utf-8"))
        if args.self_test:
            self_test()
        if args.binary is not None:
            validate_binary(args.binary)
    except (OSError, ValidationError) as error:
        print(f"d3d11-wsi-probe: FAIL {error}", file=sys.stderr)
        return 1
    print(
        f"d3d11-wsi-probe: PASS status={manifest['status']} "
        f"layers={len(manifest['required_layer'])} guest_passed=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

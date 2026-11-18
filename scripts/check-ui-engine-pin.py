#!/usr/bin/env python3
"""Validate the pinned Jasper UI Engine provenance and kernel isolation boundary."""

from __future__ import annotations

import hashlib
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "ui-engine.lock.toml"
KERNEL_MANIFESTS = (ROOT / "kernel" / "Cargo.toml", ROOT / "kernel-core" / "Cargo.toml")
UI_SERVICE_MANIFEST = ROOT / "user" / "ui-service" / "Cargo.toml"
UI_SERVICE_SOURCE = ROOT / "user" / "ui-service" / "src" / "lib.rs"
FORBIDDEN = (
    "jasper-ui-engine",
    "jasper-ui-framework",
    "blitz",
    "vello",
    "parley",
    "wgpu",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(lock_path: Path, manifests: tuple[Path, ...]) -> list[str]:
    findings: list[str] = []
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [f"ui-engine-pin: invalid lock: {exc}"]
    engine = lock.get("engine", {})
    target = lock.get("jasper_os", {})
    boundary = lock.get("host_boundary", {})
    if lock.get("schema") != 1:
        findings.append("ui-engine-pin: schema must be 1")
    if engine.get("repository") != "https://github.com/jasper-language/jasper-ui-engine":
        findings.append("ui-engine-pin: repository mismatch")
    commit = engine.get("commit")
    if not isinstance(commit, str) or len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit
    ):
        findings.append("ui-engine-pin: commit must be a lowercase hexadecimal revision")
    if engine.get("version") != "0.1.0" or engine.get("license") != "Apache-2.0":
        findings.append("ui-engine-pin: version/license mismatch")
    for field in ("cargo_lock_sha256", "cargo_manifest_sha256", "license_sha256"):
        value = engine.get(field)
        if not isinstance(value, str) or len(value) != 64:
            findings.append(f"ui-engine-pin: invalid {field}")
    if engine.get("features") != ["native-engine-cpu"]:
        findings.append("ui-engine-pin: native-engine-cpu must remain the exact selected feature")
    if target.get("target") != "x86_64-unknown-none":
        findings.append("ui-engine-pin: Jasper-OS target mismatch")
    if target.get("status") not in {
        "blocked-no-std",
        "port-ready",
        "integrated-cpu",
    }:
        findings.append("ui-engine-pin: invalid target status")
    if target.get("kernel_linked") is not False:
        findings.append("ui-engine-pin: engine must never link into the kernel")
    if target.get("fallback") != "rescue-console":
        findings.append("ui-engine-pin: rescue console fallback must remain independent")
    if boundary.get("loopback_is_acceptance") is not False:
        findings.append("ui-engine-pin: host loopback must not be acceptance evidence")
    evidence = target.get("evidence")
    if not isinstance(evidence, str) or not (ROOT / evidence).is_file():
        findings.append("ui-engine-pin: evidence document is missing")
    if UI_SERVICE_SOURCE.is_file() and isinstance(commit, str):
        source = UI_SERVICE_SOURCE.read_text(encoding="utf-8", errors="replace")
        expected_pin = f'PINNED_ENGINE_COMMIT: &str = "{commit}"'
        if expected_pin not in source:
            findings.append("ui-engine-pin: UI service source pin does not match lock")
    for manifest in manifests:
        text = manifest.read_text(encoding="utf-8", errors="replace")
        for crate in FORBIDDEN:
            if crate in text:
                display = (
                    manifest.relative_to(ROOT)
                    if manifest.is_relative_to(ROOT)
                    else manifest
                )
                findings.append(
                    f"ui-engine-pin: forbidden UI/GPU crate {crate} in {display}"
                )
    return findings


def self_test() -> None:
    good_lock = """
schema = 1
[engine]
repository = "https://github.com/jasper-language/jasper-ui-engine"
commit = "4194117011f13fdc063977683162fd5a145c85d7"
version = "0.1.0"
license = "Apache-2.0"
cargo_lock_sha256 = "dd733d3930c9e18224463ba3979997a86e589f272da79b46dbd26c166536f78e"
cargo_manifest_sha256 = "428c56cf48ae7551055f07ea7befa9bc4deb157a270518600fd2c5624f1ce0b5"
license_sha256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"
features = ["native-engine-cpu"]
[jasper_os]
target = "x86_64-unknown-none"
status = "blocked-no-std"
evidence = "evidence/ui-engine-pin-4194117/README.md"
kernel_linked = false
fallback = "rescue-console"
[host_boundary]
loopback_is_acceptance = false
"""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "lock.toml"
        manifest = Path(directory) / "Cargo.toml"
        manifest.write_text("[package]\nname='safe'\n", encoding="utf-8")
        path.write_text(
            good_lock.replace(
                "evidence/ui-engine-pin-4194117/README.md",
                "evidence/ui-engine-pin-4194117/not-present.md",
            ),
            encoding="utf-8",
        )
        findings = validate(path, (manifest,))
        assert any("evidence document is missing" in item for item in findings)
        path.write_text(good_lock, encoding="utf-8")
        manifest.write_text("[dependencies]\nwgpu='1'\n", encoding="utf-8")
        findings = validate(path, (manifest,))
        assert any("forbidden UI/GPU crate wgpu" in item for item in findings)
    print("ui-engine-pin: self-test PASS")


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        self_test()
        return 0
    findings = validate(LOCK, (*KERNEL_MANIFESTS, UI_SERVICE_MANIFEST))
    if findings:
        print("ui-engine-pin: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    lock = tomllib.loads(LOCK.read_text(encoding="utf-8"))
    print(
        "ui-engine-pin: PASS "
        f"commit={lock['engine']['commit']} "
        f"target={lock['jasper_os']['target']} "
        f"status={lock['jasper_os']['status']} kernel_linked=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

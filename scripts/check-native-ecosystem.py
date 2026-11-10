#!/usr/bin/env python3
"""Check that compatibility components stay outside the native Jasper profile."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "verification/native-ecosystem.toml"
KERNEL_MANIFEST = ROOT / "kernel/Cargo.toml"
DAG = ROOT / "milestones/unified-dag.toml"

REQUIRED_ACCEPTANCE = {
    "optional-compat-dependencies",
    "native-profile-isolation",
    "explicit-syscall-activation",
    "explicit-elf-activation",
    "runtime-install-stop-uninstall",
    "default-distribution-exclusion",
}


def fail(message: str) -> None:
    print(f"native-ecosystem: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot read {path.relative_to(ROOT)}: {exc}")


def require_anchors(relative: str, anchors: tuple[str, ...]) -> None:
    text = (ROOT / relative).read_text(encoding="utf-8")
    missing = [anchor for anchor in anchors if anchor not in text]
    if missing:
        fail(f"{relative} is missing anchors: {missing}")


def check_dependency_trees() -> int:
    if shutil.which("cargo") is None:
        fail("cargo is required for --dependency-tree")

    def tree(arguments: list[str]) -> str:
        command = [
            "cargo",
            "tree",
            "-p",
            "jasper-kernel",
            "--target",
            "x86_64-unknown-none",
            "-e",
            "normal",
            *arguments,
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            fail(f"dependency tree command failed: {' '.join(command)}: {result.stderr}")
        return result.stdout

    native = tree(["--no-default-features"])
    for component in ("jasper-compat-core", "jasper-compat-loader"):
        if component in native:
            fail(f"native dependency tree contains {component}")

    syscall = tree(["--features", "compat-syscall-verify"])
    if "jasper-compat-core" not in syscall:
        fail("syscall feature tree is missing jasper-compat-core")
    if "jasper-compat-loader" in syscall:
        fail("syscall feature tree unexpectedly contains jasper-compat-loader")

    elf = tree(["--features", "compat-elf-backend-verify"])
    if "jasper-compat-loader" not in elf:
        fail("ELF feature tree is missing jasper-compat-loader")
    if "jasper-compat-core" in elf:
        fail("ELF feature tree unexpectedly contains jasper-compat-core")

    dynamic = tree(["--features", "compat-dynamic-libc-verify"])
    if "jasper-compat-core" not in dynamic or "jasper-compat-loader" not in dynamic:
        fail("dynamic libc feature tree is missing one or both compatibility services")
    return 4


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dependency-tree",
        action="store_true",
        help="run Cargo dependency-tree isolation checks",
    )
    args = parser.parse_args()

    planning_present = MATRIX.is_file()
    passed = pending = None
    if planning_present:
        matrix = read_toml(MATRIX)
        if matrix.get("schema") != 1 or matrix.get("stage") != "NATIVE-ECOSYSTEM-1":
            fail("bad matrix schema or stage")
        acceptance = {
            item.get("id"): item
            for item in matrix.get("acceptance", [])
            if isinstance(item, dict)
        }
        if set(acceptance) != REQUIRED_ACCEPTANCE:
            fail(f"acceptance set mismatch: {sorted(set(acceptance) ^ REQUIRED_ACCEPTANCE)}")

        passed = {key for key, item in acceptance.items() if item.get("state") == "passed"}
        pending = {key for key, item in acceptance.items() if item.get("state") == "pending"}
        required_passed = REQUIRED_ACCEPTANCE - {
            "runtime-install-stop-uninstall",
            "default-distribution-exclusion",
        }
        if passed != required_passed:
            fail(f"core-passed evidence mismatch: {sorted(required_passed ^ passed)}")
        if pending != REQUIRED_ACCEPTANCE - required_passed:
            fail(f"pending boundary mismatch: {sorted(pending)}")
        if matrix.get("status") != "core-passed":
            fail("component removal and default-distribution exclusion are not complete")

    manifest = read_toml(KERNEL_MANIFEST)
    deps = manifest.get("dependencies", {})
    for name in ("jasper-compat-loader", "compat-core"):
        dependency = deps.get(name)
        if not isinstance(dependency, dict) or dependency.get("optional") is not True:
            fail(f"{name} must be an optional kernel dependency")

    features = manifest.get("features", {})
    if "dep:jasper-compat-loader" not in features.get("compat-elf", []):
        fail("compat-elf must own the optional ELF loader dependency")
    if "dep:compat-core" not in features.get("linux-abi", []):
        fail("linux-abi must own the optional compatibility-core dependency")
    if "compat-elf" not in features.get("compat-elf-backend-verify", []):
        fail("ELF acceptance must explicitly activate compat-elf")
    if "linux-abi" not in features.get("compat-syscall-verify", []):
        fail("syscall acceptance must explicitly activate linux-abi")
    dynamic = features.get("compat-dynamic-libc-verify", [])
    if not {"linux-abi", "compat-elf"}.issubset(dynamic):
        fail("dynamic libc acceptance must explicitly activate both compatibility services")
    default = features.get("default", [])
    if any("compat" in item or "linux" in item for item in default):
        fail("default kernel features contain a compatibility component")
    build_dependencies = manifest.get("build-dependencies", {})
    for forbidden in ("goblin", "jasper-compat-core", "jasper-compat-loader"):
        if forbidden in build_dependencies:
            fail(f"native build dependency chain contains {forbidden}")

    require_anchors(
        "kernel/src/lib.rs",
        (
            '#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]\npub mod linux_abi;',
            '#[cfg(all(feature = "compat-elf", target_arch = "x86_64"))]\npub mod compat_elf;',
            '#[cfg(all(feature = "compat-dynamic-libc-verify", target_arch = "x86_64"))]\npub mod linux_vfs;',
        ),
    )
    require_anchors(
        "kernel/src/proc/mod.rs",
        (
            '#[cfg(feature = "linux-abi")]\nstruct LinuxProcessState',
            '#[cfg(feature = "linux-abi")]\n    linux: Option<LinuxProcessState>',
            '#[cfg(feature = "linux-abi")]\npub fn create_linux',
            '#[cfg(feature = "linux-abi")]\npub fn load_linux_elf',
        ),
    )
    require_anchors(
        "kernel/src/syscall/mod.rs",
        (
            '#[cfg(all(feature = "linux-abi", target_arch = "x86_64"))]',
            ".is_some_and(proc::is_linux_process)",
        ),
    )
    syscall_source = (ROOT / "kernel/src/syscall/mod.rs").read_text(encoding="utf-8")
    if "SyscallFlavor" in syscall_source:
        fail("native syscall dispatch still embeds a compatibility flavor type")

    if planning_present:
        dag = read_toml(DAG)
        nodes = {node["id"]: node for node in dag.get("node", []) if "id" in node}
        node = nodes.get("NATIVE-ECOSYSTEM-1")
        if node is None:
            fail("NATIVE-ECOSYSTEM-1 is missing from the unified DAG")
        if node.get("status") != "core-passed" or node.get("blocking") is not True:
            fail("native ecosystem node must stay core-passed and blocking")
        if not {"OS-CORE", "NATIVE-ABI-AUDIT-1"}.issubset(node.get("deps", [])):
            fail("native ecosystem node is missing its foundation dependencies")
        if "NATIVE-ECOSYSTEM-1" not in nodes["ISSUE-20-UNIXLIKE"].get("deps", []):
            fail("Linux compatibility acceptance must depend on ecosystem independence")

        require_anchors(
            "docs/product-architecture-layers.md",
            ("独立生态原则", "永久性的基础依赖", "原生 Profile 不链接"),
        )
        require_anchors(
            "docs/native-ecosystem-independence.md",
            ("默认 Jasper Profile", "发行组件卸载", "默认发行退出"),
        )

    trees = check_dependency_trees() if args.dependency_tree else 0
    mode = "planning" if planning_present else "code-only"
    print(
        "native-ecosystem: PASS [core-passed] "
        f"mode={mode} acceptance={len(passed or ()) + len(pending or ())} "
        f"passed={len(passed or ())} pending={len(pending or ())} trees={trees}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

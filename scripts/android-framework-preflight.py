#!/usr/bin/env python3
"""Inspect a real Android ext4 root for Activity/Framework launch prerequisites."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


EXECUTABLES = {
    "app_process64": "/system/bin/app_process64",
    "zygote64": "/system/bin/zygote64",
    "system_server": "/system/bin/system_server",
    "servicemanager": "/system/bin/servicemanager",
    "installd": "/system/bin/installd",
}
FRAMEWORK = {
    "framework_jar": "/system/framework/framework.jar",
    "services_jar": "/system/framework/services.jar",
    "am_jar": "/system/framework/am.jar",
    "framework_resources": "/system/framework/framework-res.apk",
}
DIRECTORIES = {
    "permissions": "/system/etc/permissions",
    "runtime_apex": "/apex/com.android.runtime",
}
REQUIRED_APK_ENTRIES = {"AndroidManifest.xml", "resources.arsc"}


class PreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class Inode:
    file_type: str
    mode: int
    size: int
    link_target: str | None


def run(command: list[str], *, timeout: int = 120) -> bytes:
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PreflightError(f"command failed: {' '.join(command)}: {error}") from error
    return result.stdout


def parse_inode(text: str) -> Inode | None:
    if "Inode:" not in text or "File not found" in text:
        return None
    header = re.search(
        r"Inode:\s+\d+\s+Type:\s+(\S+).*?Mode:\s+([0-7]+).*?Size:\s+(\d+)",
        text,
        re.DOTALL,
    )
    if header is None:
        raise PreflightError("debugfs stat output has no inode header")
    link = re.search(r'Fast link dest:\s+"([^"]+)"', text)
    return Inode(
        file_type=header.group(1),
        mode=int(header.group(2), 8),
        size=int(header.group(3)),
        link_target=link.group(1) if link else None,
    )


def debugfs(debugfs_bin: Path, image: Path, request: str) -> bytes:
    return run([str(debugfs_bin), "-R", request, str(image)])


def stat_path(debugfs_bin: Path, image: Path, path: str) -> Inode | None:
    try:
        output = debugfs(debugfs_bin, image, f"stat {path}")
    except PreflightError:
        return None
    return parse_inode(output.decode("utf-8", errors="replace"))


def dump_file(debugfs_bin: Path, image: Path, path: str, destination: Path) -> None:
    output = debugfs(debugfs_bin, image, f"dump {path} {destination}")
    if output and b"File not found" in output:
        raise PreflightError(f"cannot dump missing file: {path}")
    if not destination.is_file():
        raise PreflightError(f"debugfs did not create {destination}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_resource_apk(path: Path) -> dict[str, object]:
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise PreflightError("framework resource APK has duplicate ZIP members")
            missing = sorted(REQUIRED_APK_ENTRIES - set(names))
            if missing:
                raise PreflightError(f"framework resource APK lacks {missing}")
            if archive.testzip() is not None:
                raise PreflightError("framework resource APK failed ZIP CRC validation")
            resource_bytes = archive.read("resources.arsc")
    except (OSError, zipfile.BadZipFile) as error:
        raise PreflightError(f"invalid framework resource APK: {error}") from error
    if len(resource_bytes) < 12:
        raise PreflightError("resources.arsc is shorter than its header")
    chunk_type, header_size, total_size = struct.unpack_from("<HHI", resource_bytes)
    if chunk_type != 0x0002 or header_size < 12 or total_size > len(resource_bytes):
        raise PreflightError("resources.arsc has an invalid table header")
    return {
        "entries": len(names),
        "resource_entries": sum(name.startswith("res/") for name in names),
        "resources_arsc_bytes": len(resource_bytes),
        "resources_arsc_header_bytes": header_size,
        "resources_arsc_total_bytes": total_size,
    }


def inspect_image(debugfs_bin: Path, image: Path) -> dict[str, object]:
    if not image.is_file() or image.stat().st_size == 0:
        raise PreflightError(f"invalid Android image: {image}")
    if not debugfs_bin.is_file():
        raise PreflightError(f"debugfs is missing: {debugfs_bin}")

    executables: dict[str, dict[str, object]] = {}
    framework: dict[str, dict[str, object]] = {}
    directories: dict[str, dict[str, object]] = {}
    missing: list[str] = []

    for name, path in EXECUTABLES.items():
        inode = stat_path(debugfs_bin, image, path)
        if inode is None:
            missing.append(name)
            executables[name] = {"path": path, "present": False}
            continue
        executable = inode.file_type == "regular" and inode.mode & 0o111 != 0
        if not executable:
            missing.append(name)
        executables[name] = {
            "path": path,
            "present": True,
            "type": inode.file_type,
            "mode": oct(inode.mode),
            "size": inode.size,
            "executable": executable,
            "link_target": inode.link_target,
        }

    with tempfile.TemporaryDirectory(prefix="jasper-android-framework-") as temporary:
        root = Path(temporary)
        for name, path in FRAMEWORK.items():
            inode = stat_path(debugfs_bin, image, path)
            if inode is None or inode.file_type != "regular" or inode.size == 0:
                missing.append(name)
                framework[name] = {"path": path, "present": False}
                continue
            dumped = root / f"{name}.bin"
            dump_file(debugfs_bin, image, path, dumped)
            details: dict[str, object] = {
                "path": path,
                "present": True,
                "size": inode.size,
                "sha256": sha256_file(dumped),
            }
            if name == "framework_resources":
                details.update(inspect_resource_apk(dumped))
            framework[name] = details

    for name, path in DIRECTORIES.items():
        inode = stat_path(debugfs_bin, image, path)
        present = inode is not None and inode.file_type == "directory"
        if not present:
            missing.append(name)
        directories[name] = {"path": path, "present": present}

    container_ready = not missing
    return {
        "schema": "jasper.android.framework-preflight/1",
        "image": str(image),
        "image_bytes": image.stat().st_size,
        "container_ready": container_ready,
        "activity_runtime_ready": False,
        "activity_runtime_limitations": [
            "This preflight does not start zygote, system_server, ActivityManager or an Activity.",
            "A complete root also needs matching APEX mounts, SELinux policy, Binder services and framework configuration.",
            "Activity onCreate/onStart/onResume, resources/configuration, graphics, input and audio remain separate runtime gates.",
        ],
        "missing": missing,
        "executables": executables,
        "framework": framework,
        "directories": directories,
    }


def self_test() -> None:
    sample = (
        "Inode: 309   Type: regular    Mode:  0755   Flags: 0x80000\n"
        "User: 1000 Group: 1000 Project: 0 Size: 14416\n"
    )
    inode = parse_inode(sample)
    assert inode == Inode("regular", 0o755, 14416, None)
    link = parse_inode(
        "Inode: 481 Type: symlink Mode: 0777 Flags: 0\n"
        "User: 1000 Group: 1000 Project: 0 Size: 38\n"
        'Fast link dest: "/apex/com.android.runtime/bin/linker64"\n'
    )
    assert link is not None and link.link_target == "/apex/com.android.runtime/bin/linker64"
    assert parse_inode("/missing: File not found by ext2_lookup") is None

    with tempfile.TemporaryDirectory(prefix="jasper-android-preflight-selftest-") as temporary:
        apk = Path(temporary) / "resources.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
            archive.writestr(
                "resources.arsc",
                struct.pack("<HHI", 0x0002, 12, 12) + b"\0" * 4,
            )
            archive.writestr("res/raw/value", b"x")
        result = inspect_resource_apk(apk)
        assert result["resource_entries"] == 1
        assert result["resources_arsc_header_bytes"] == 12
    print("android-framework-preflight: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path)
    parser.add_argument("--debugfs", type=Path, default=Path("/usr/sbin/debugfs"))
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.image is None:
        parser.error("--image is required unless --self-test is used")
    try:
        report = inspect_image(args.debugfs, args.image)
    except PreflightError as error:
        print(f"android-framework-preflight: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    print(
        "android-framework-preflight: "
        f"container_ready={str(report['container_ready']).lower()} "
        f"activity_runtime_ready=false missing={','.join(report['missing']) or 'none'}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

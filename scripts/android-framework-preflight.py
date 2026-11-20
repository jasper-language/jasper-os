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
    "servicemanager": "/system/bin/servicemanager",
    "installd": "/system/bin/installd",
}
ZYGOTE64_RC = "/system/etc/init/hw/init.zygote64.rc"
INIT_RC_CANDIDATES = (
    "/system/etc/init/hw/init.rc",
    "/system/etc/init/init.rc",
    "/init.rc",
)
FRAMEWORK = {
    "framework_jar": "/system/framework/framework.jar",
    "services_jar": "/system/framework/services.jar",
    "am_jar": "/system/framework/am.jar",
    "framework_resources": "/system/framework/framework-res.apk",
}
DIRECTORIES = {
    "permissions": "/system/etc/permissions",
    "runtime_apex": "/apex/com.android.runtime",
    "linker_config_root": "/linkerconfig",
    "system_apex_root": "/system/apex",
    "selinux_policy": "/system/etc/selinux",
    "init_hw": "/system/etc/init/hw",
}
STATIC_FILES = {
    "vintf_manifest": "/system/etc/vintf/manifest.xml",
    "passwd": "/system/etc/passwd",
}
LINKER_CONFIG = "/linkerconfig/ld.config.txt"
REQUIRED_APK_ENTRIES = {"AndroidManifest.xml", "resources.arsc"}


class PreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class Inode:
    file_type: str
    mode: int
    size: int
    link_target: str | None
    uid: int
    gid: int


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
    owner = re.search(
        r"User:\s+(\d+).*?Group:\s+(\d+)",
        text,
        re.DOTALL,
    )
    if owner is None:
        raise PreflightError("debugfs stat output has no owner identity")
    return Inode(
        file_type=header.group(1),
        mode=int(header.group(2), 8),
        size=int(header.group(3)),
        link_target=link.group(1) if link else None,
        uid=int(owner.group(1)),
        gid=int(owner.group(2)),
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


def linker_bootstrap_state(text: str) -> dict[str, object]:
    apex = text.find("exec_start apexd-bootstrap")
    update = text.find("update_linker_config")
    bootstrap_dir = re.search(r"mkdir\s+/linkerconfig/bootstrap\b", text)
    bootstrap_write = re.search(
        r"write\s+/linkerconfig/bootstrap/ld\.config\.txt\b",
        text,
    )
    bootstrap_mount = re.search(
        r"mount\s+none\s+/linkerconfig/bootstrap\s+/linkerconfig\s+bind\b",
        text,
    )
    ordered = apex >= 0 and update > apex
    ready = bool(
        bootstrap_dir
        and bootstrap_write
        and bootstrap_mount
        and ordered
    )
    return {
        "apexd_bootstrap_before_update": ordered,
        "bootstrap_directory": bool(bootstrap_dir),
        "bootstrap_mount": bool(bootstrap_mount),
        "bootstrap_write": bool(bootstrap_write),
        "generated_at_boot": ready,
        "update_linker_config": update >= 0,
    }


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
            "uid": inode.uid,
            "gid": inode.gid,
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

    static_files: dict[str, dict[str, object]] = {}
    for name, path in STATIC_FILES.items():
        inode = stat_path(debugfs_bin, image, path)
        present = inode is not None and inode.file_type == "regular"
        details: dict[str, object] = {"path": path, "present": present}
        if present:
            details["uid"] = inode.uid
            details["gid"] = inode.gid
            if name == "passwd":
                # AOSP's stock system image ships an empty system account
                # database. Presence and ownership are the static facts;
                # Android's user/group services provide the runtime identity
                # model rather than a non-empty passwd file being boot-critical.
                details["stock_empty_database"] = inode.size == 0
                present = inode.uid == 1000 and inode.gid == 1000
            with tempfile.TemporaryDirectory(prefix="jasper-android-static-") as temporary:
                dumped = Path(temporary) / name
                dump_file(debugfs_bin, image, path, dumped)
                content = dumped.read_bytes()
                details["size"] = len(content)
                details["sha256"] = hashlib.sha256(content).hexdigest()
        if not present:
            missing.append(name)
        static_files[name] = details

    linker_text = ""
    linker_init_path = None
    with tempfile.TemporaryDirectory(prefix="jasper-android-init-") as temporary:
        for index, path in enumerate(INIT_RC_CANDIDATES):
            inode = stat_path(debugfs_bin, image, path)
            if inode is None or inode.file_type != "regular" or inode.size == 0:
                continue
            dumped = Path(temporary) / f"init-{index}.rc"
            dump_file(debugfs_bin, image, path, dumped)
            linker_text = dumped.read_text(encoding="utf-8", errors="replace")
            linker_init_path = path
            break
    linker_bootstrap = linker_bootstrap_state(linker_text)
    linker_bootstrap["init_rc"] = linker_init_path
    static_config = stat_path(debugfs_bin, image, LINKER_CONFIG)
    static_config_present = (
        static_config is not None
        and static_config.file_type == "regular"
        and static_config.size != 0
    )
    linker_bootstrap["static_config_path"] = LINKER_CONFIG
    linker_bootstrap["static_config_present"] = static_config_present
    if not linker_bootstrap["generated_at_boot"]:
        missing.append("linker_config_generation")

    zygote_rc = stat_path(debugfs_bin, image, ZYGOTE64_RC)
    zygote_text = ""
    if zygote_rc is not None and zygote_rc.file_type == "regular" and zygote_rc.size != 0:
        with tempfile.TemporaryDirectory(prefix="jasper-android-zygote-") as temporary:
            dumped = Path(temporary) / "init.zygote64.rc"
            dump_file(debugfs_bin, image, ZYGOTE64_RC, dumped)
            zygote_text = dumped.read_text(encoding="utf-8", errors="replace")
    starts_zygote = re.search(
        r"service\s+zygote\s+/system/bin/app_process64\b.*--zygote\b",
        zygote_text,
    ) is not None
    starts_system_server = "--start-system-server" in zygote_text
    if not starts_zygote:
        missing.append("zygote64")
    if not starts_system_server:
        missing.append("system_server")
    launch = {
        "zygote64": {
            "path": ZYGOTE64_RC,
            "present": zygote_rc is not None,
            "starts_app_process64_zygote": starts_zygote,
            "starts_system_server": starts_system_server,
        }
    }

    container_ready = not missing
    return {
        "schema": "jasper.android.framework-preflight/2",
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
        "static_files": static_files,
        "linker_bootstrap": linker_bootstrap,
        "launch": launch,
    }


def self_test() -> None:
    sample = (
        "Inode: 309   Type: regular    Mode:  0755   Flags: 0x80000\n"
        "User: 1000 Group: 1000 Project: 0 Size: 14416\n"
    )
    inode = parse_inode(sample)
    assert inode == Inode("regular", 0o755, 14416, None, 1000, 1000)
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
    assert re.search(
        r"service\s+zygote\s+/system/bin/app_process64\b.*--zygote\b",
        "service zygote /system/bin/app_process64 -Xzygote /system/bin --zygote",
    )
    assert linker_bootstrap_state(
        "mkdir /linkerconfig/bootstrap 0755\n"
        "write /linkerconfig/bootstrap/ld.config.txt #\n"
        "mount none /linkerconfig/bootstrap /linkerconfig bind rec\n"
        "exec_start apexd-bootstrap\n"
        "update_linker_config\n"
    )["generated_at_boot"]
    assert not linker_bootstrap_state(
        "mkdir /linkerconfig/bootstrap 0755\nupdate_linker_config\n"
    )["generated_at_boot"]
    print("android-framework-preflight: self-test PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path)
    parser.add_argument("--debugfs", type=Path, default=Path("/usr/sbin/debugfs"))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--write", type=Path, help="write the deterministic JSON report")
    parser.add_argument("--check", type=Path, help="compare against a saved deterministic report")
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
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.write is not None:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(rendered, encoding="utf-8")
    elif args.check is not None:
        if not args.check.is_file() or args.check.read_text(encoding="utf-8") != rendered:
            print("android-framework-preflight: FAIL report drift", file=sys.stderr)
            return 1
    else:
        print(rendered, end="")
    print(
        "android-framework-preflight: "
        f"container_ready={str(report['container_ready']).lower()} "
        f"activity_runtime_ready=false missing={','.join(report['missing']) or 'none'}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

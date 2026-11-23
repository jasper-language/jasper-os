#!/usr/bin/env python3
"""Prepare a fail-closed Wine 11.22 + DXVK + lavapipe staging root.

This creates a staging tree for Jasper's Linux compatibility verification. It
does not claim a Jasper guest pass, WSI/present support or physical GPU
acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "verification/wine-d3d-staging.json"
ARCHIVE_CACHE = REPO / "target/wine-d3d-staging-cache"
PROBE_SOURCE = REPO / "verification/fixtures/windows/d3d11_probe.c"
D3D12_PROBE_SOURCE = REPO / "verification/fixtures/windows/d3d12_probe.c"
D3D11_WSI_PROBE_SOURCE = REPO / "verification/fixtures/windows/d3d11_wsi_probe.c"
DEFAULT_OUTPUT = REPO / "target/wine-d3d-staging"
MESA_FILES = (
    (
        Path("/usr/lib/x86_64-linux-gnu/libvulkan.so.1"),
        Path("usr/lib/x86_64-linux-gnu/libvulkan.so.1"),
    ),
    (
        Path("/usr/lib/x86_64-linux-gnu/libvulkan_lvp.so"),
        Path("usr/lib/x86_64-linux-gnu/libvulkan_lvp.so"),
    ),
    (
        Path("/usr/share/vulkan/icd.d/lvp_icd.json"),
        Path("usr/lib/x86_64-linux-gnu/lvp_icd.json"),
    ),
)
WINE_WINDOWS_DIR = Path("opt/wine-devel/lib/wine/x86_64-windows")
WINE_UNIX_DIR = Path("opt/wine-devel/lib/wine/x86_64-unix")


class StagingError(RuntimeError):
    """The staging transaction cannot continue safely."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StagingError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_digest(path: Path, expected_sha256: str, label: str) -> None:
    actual = sha256_file(path)
    require(
        actual == expected_sha256,
        f"{label} digest mismatch: actual={actual} expected={expected_sha256}",
    )


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        manifest = json.load(source)
    validate_manifest(manifest)
    return manifest


def _validate_relative_path(value: str, label: str) -> None:
    path = Path(value)
    require(not path.is_absolute(), f"{label} must be relative: {value}")
    require(".." not in path.parts, f"{label} escapes the staging root: {value}")
    require(bool(path.parts), f"{label} is empty")


def validate_manifest(manifest: dict[str, Any]) -> None:
    require(manifest.get("schema") == 1, "manifest schema must be 1")
    require(manifest.get("architecture") == "x86_64", "architecture must be x86_64")
    require(
        manifest.get("release")
        == "wine-11.22-dxvk-3.1.1-vkd3d-3.1-lavapipe-26.0.8",
        "release identity mismatch",
    )
    components = manifest.get("components", {})
    expected_components = {
        "wine-source",
        "wine-devel",
        "wine-devel-amd64",
        "dxvk",
        "d3d11-probe-source",
        "d3d11-probe",
        "d3d12-probe-source",
        "d3d12-probe",
        "d3d11-wsi-probe-source",
        "d3d11-wsi-probe",
        "vkd3d-proton",
    }
    require(set(components) == expected_components, "component set mismatch")

    expected_versions = {
        "wine-source": "11.22",
        "wine-devel": "11.22~noble-1",
        "wine-devel-amd64": "11.22~noble-1",
        "dxvk": "3.1.1",
        "vkd3d-proton": "3.1",
    }
    for name, version in expected_versions.items():
        item = components[name]
        require(item.get("version") == version, f"{name} version mismatch")
        digest = item.get("sha256")
        require(isinstance(digest, str) and len(digest) == 64, f"{name} digest missing")
        require(item.get("license"), f"{name} license missing")

    probe_sources = (
        ("d3d11-probe-source", PROBE_SOURCE),
        ("d3d12-probe-source", D3D12_PROBE_SOURCE),
        ("d3d11-wsi-probe-source", D3D11_WSI_PROBE_SOURCE),
    )
    for name, source_path in probe_sources:
        probe_source = components[name]
        require(
            probe_source.get("path") == source_path.relative_to(REPO).as_posix(),
            f"{name} path mismatch",
        )
        require(
            probe_source.get("sha256") == sha256_file(source_path),
            f"{name} digest mismatch",
        )
    for name in ("d3d11-probe", "d3d12-probe", "d3d11-wsi-probe"):
        item = components[name]
        require(
            isinstance(item.get("bytes"), int) and item["bytes"] > 0,
            f"{name} byte length missing",
        )
        require(
            isinstance(item.get("sha256"), str) and len(item["sha256"]) == 64,
            f"{name} digest missing",
        )

    final_files = manifest.get("final_files", {})
    require(len(final_files) == 16, "final file set is incomplete")
    for path, digest in final_files.items():
        _validate_relative_path(path, "final file")
        require(isinstance(digest, str) and len(digest) == 64, f"{path} digest missing")

    packages = manifest.get("host", {}).get("packages", {})
    require(packages.get("mesa-vulkan-drivers") == "26.0.8-1ubuntu0.3",
            "Mesa lavapipe version mismatch")
    require(packages.get("libllvm21") == "1:21.1.8-6ubuntu1",
            "LLVM version mismatch")
    require(packages.get("libvulkan1") == "1.4.341.0-1",
            "Vulkan loader version mismatch")


def package_version(name: str) -> str | None:
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Version}", name],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout if result.returncode == 0 else None


def verify_host_packages(manifest: dict[str, Any]) -> None:
    for name, expected in manifest["host"]["packages"].items():
        actual = package_version(name)
        require(actual == expected, f"host package drift: {name}={actual!r}, expected {expected!r}")


def command_path(name: str) -> str | None:
    return shutil.which(name)


def verify_tools() -> None:
    for tool in ("dpkg-deb", "ldd", "tar"):
        require(command_path(tool) is not None, f"required tool is missing: {tool}")


def download_verified(url: str, destination: Path, expected_sha256: str) -> None:
    if destination.is_file():
        verify_digest(destination, expected_sha256, f"cached artifact {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "Jasper-OS-staging/1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=destination.name + ".", delete=False
        ) as temporary:
            shutil.copyfileobj(response, temporary, length=1024 * 1024)
            temporary_path = Path(temporary.name)
    try:
        verify_digest(temporary_path, expected_sha256, f"downloaded artifact {url}")
        temporary_path.replace(destination)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def explicit_artifact(environment: str, cache: Path, filename: str,
                      spec: dict[str, Any]) -> Path:
    override = os.environ.get(environment)
    path = Path(override) if override else cache / filename
    if override:
        require(path.is_file(), f"{environment} does not name a file: {path}")
        verify_digest(path, spec["sha256"], environment)
        return path
    download_verified(spec["url"], path, spec["sha256"])
    return path


def extract_deb(archive: Path, destination: Path) -> None:
    subprocess.run(
        ["dpkg-deb", "-x", str(archive), str(destination)],
        check=True,
    )


def safe_extract_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:*") as source:
        source.extractall(destination, filter="data")


def safe_extract_zstd_tar(archive: Path, destination: Path) -> None:
    listing = subprocess.run(
        ["tar", "--zstd", "-tf", str(archive)],
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    for name in listing.splitlines():
        member = Path(name)
        require(
            not member.is_absolute() and ".." not in member.parts,
            f"zstd archive path escapes extraction root: {name}",
        )
    destination.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["tar", "--zstd", "-xf", str(archive), "-C", str(destination)],
        check=True,
    )


def ldd_paths(inputs: list[Path]) -> set[Path]:
    dependencies: set[Path] = set()
    environment = os.environ.copy()
    wine_directory = WINE_UNIX_DIR.as_posix()
    environment["LD_LIBRARY_PATH"] = wine_directory
    for input_path in inputs:
        result = subprocess.run(
            ["ldd", str(input_path)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=False,
        )
        for line in result.stdout.splitlines():
            fields = line.split()
            candidate: str | None = None
            if "=>" in fields:
                index = fields.index("=>")
                if index + 1 < len(fields) and fields[index + 1].startswith("/"):
                    candidate = fields[index + 1]
            elif fields and fields[0].startswith("/"):
                candidate = fields[0]
            if candidate:
                dependencies.add(Path(candidate))
    return dependencies


def copy_host_path(source: Path, root: Path) -> None:
    relative = source.relative_to("/")
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination, follow_symlinks=True)


def write_identity_files(root: Path) -> None:
    (root / "etc").mkdir(parents=True, exist_ok=True)
    (root / "data/wineprefix").mkdir(parents=True, exist_ok=True)
    (root / "tmp").mkdir(parents=True, exist_ok=True)
    (root / "etc/passwd").write_text(
        "root:x:0:0:root:/data:/bin/dash\n"
        "user:x:1000:1000:user:/data:/bin/dash\n",
        encoding="utf-8",
    )
    (root / "etc/group").write_text("root:x:0:\nuser:x:1000:\n", encoding="utf-8")
    (root / "etc/jasper-compat-wine").write_text(
        "compat-wine version=11.22 dxvk=3.1.1 vulkan=lavapipe-26.0.8\n",
        encoding="utf-8",
    )
    (root / "tmp").chmod(stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO | stat.S_ISVTX)


def supplied_artifact(
    explicit: Path | None,
    environment: str,
    label: str,
    expected_sha256: str,
) -> Path:
    override = os.environ.get(environment)
    path = explicit if explicit is not None else Path(override) if override else None
    require(path is not None, f"pass {label} or set {environment}")
    require(path.is_file(), f"{label} is missing: {path}")
    verify_digest(path, expected_sha256, label)
    return path


def prepare(
    manifest: dict[str, Any],
    output: Path,
    cache: Path,
    probe: Path | None,
    d3d12_probe: Path | None,
    wsi_probe: Path | None,
) -> None:
    require(not output.exists(), f"output already exists; choose a new directory: {output}")
    verify_tools()
    verify_host_packages(manifest)
    components = manifest["components"]
    probe_path = supplied_artifact(
        probe,
        "JASPER_D3D11_PROBE",
        "D3D11 probe",
        components["d3d11-probe"]["sha256"],
    )
    d3d12_probe_path = supplied_artifact(
        d3d12_probe,
        "JASPER_D3D12_PROBE",
        "D3D12 probe",
        components["d3d12-probe"]["sha256"],
    )
    wsi_probe_path = supplied_artifact(
        wsi_probe,
        "JASPER_D3D11_WSI_PROBE",
        "D3D11 WSI probe",
        components["d3d11-wsi-probe"]["sha256"],
    )

    cache.mkdir(parents=True, exist_ok=True)
    wine_deb = explicit_artifact(
        "JASPER_WINE_DEVEL_DEB",
        cache,
        "wine-devel_11.22~noble-1_amd64.deb",
        components["wine-devel"],
    )
    wine_amd64_deb = explicit_artifact(
        "JASPER_WINE_DEVEL_AMD64_DEB",
        cache,
        "wine-devel-amd64_11.22~noble-1_amd64.deb",
        components["wine-devel-amd64"],
    )
    dxvk_archive = explicit_artifact(
        "JASPER_DXVK_ARCHIVE",
        cache,
        "dxvk-3.1.1.tar.gz",
        components["dxvk"],
    )
    vkd3d_archive = explicit_artifact(
        "JASPER_VKD3D_PROTON_ARCHIVE",
        cache,
        "vkd3d-proton-3.1.tar.zst",
        components["vkd3d-proton"],
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_root = Path(tempfile.mkdtemp(prefix=output.name + ".tmp-", dir=output.parent))
    try:
        extract_deb(wine_deb, temporary_root)
        extract_deb(wine_amd64_deb, temporary_root)
        with tempfile.TemporaryDirectory(prefix="jasper-dxvk-") as dxvk_work:
            dxvk_root = Path(dxvk_work)
            safe_extract_tar(dxvk_archive, dxvk_root)
            source = dxvk_root / "dxvk-3.1.1/x64"
            require(source.is_dir(), "DXVK x64 directory is missing")
            destination = temporary_root / WINE_WINDOWS_DIR
            destination.mkdir(parents=True, exist_ok=True)
            for item in source.iterdir():
                if item.is_file():
                    shutil.copy2(item, destination / item.name)
            configuration = dxvk_root / "dxvk-3.1.1/dxvk.conf"
            if configuration.is_file():
                shutil.copy2(configuration, destination / configuration.name)
        with tempfile.TemporaryDirectory(prefix="jasper-vkd3d-") as vkd3d_work:
            vkd3d_root = Path(vkd3d_work)
            safe_extract_zstd_tar(vkd3d_archive, vkd3d_root)
            source = vkd3d_root / "vkd3d-proton-3.1/x64"
            require(source.is_dir(), "VKD3D-Proton x64 directory is missing")
            destination = temporary_root / WINE_WINDOWS_DIR
            for name in ("d3d12.dll", "d3d12core.dll"):
                shutil.copy2(source / name, destination / name)
        shutil.copy2(probe_path, temporary_root / WINE_WINDOWS_DIR / "d3d11-probe.exe")
        shutil.copy2(
            d3d12_probe_path,
            temporary_root / WINE_WINDOWS_DIR / "d3d12-probe.exe",
        )
        shutil.copy2(
            wsi_probe_path,
            temporary_root / WINE_WINDOWS_DIR / "d3d11-wsi-probe.exe",
        )

        for source, relative in MESA_FILES:
            require(source.is_file(), f"Mesa host file is missing: {source}")
            destination = temporary_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

        wine_inputs = [
            temporary_root / WINE_UNIX_DIR / "wine",
            temporary_root / "opt/wine-devel/bin/wineserver",
            Path("/usr/lib/x86_64-linux-gnu/libvulkan_lvp.so"),
            Path("/usr/lib/x86_64-linux-gnu/libvulkan.so.1"),
        ]
        for dependency in sorted(ldd_paths(wine_inputs)):
            if dependency.is_file():
                copy_host_path(dependency, temporary_root)
        copy_host_path(Path("/lib64/ld-linux-x86-64.so.2"), temporary_root)
        write_identity_files(temporary_root)
        verify_final_files(manifest, temporary_root, run_wine=True)
        (temporary_root / ".complete").write_text("", encoding="utf-8")
        temporary_root.rename(output)
    except Exception:
        shutil.rmtree(temporary_root, ignore_errors=True)
        raise

    print(f"wine-d3d-staging: PASS release={manifest['release']} root={output} host=Ubuntu-Resolute")


def verify_final_files(
    manifest: dict[str, Any], root: Path, *, run_wine: bool
) -> None:
    require(root.is_dir(), f"staging root is missing: {root}")
    for relative, expected in manifest["final_files"].items():
        path = root / relative
        require(path.is_file(), f"staged file is missing: {relative}")
        verify_digest(path, expected, f"staged file {relative}")
    wine = root / "opt/wine-devel/bin/wine"
    require(wine.is_file(), "staged Wine launcher is missing")
    require(os.access(wine, os.X_OK), "staged Wine launcher is not executable")
    if run_wine:
        result = subprocess.run(
            [str(wine), "--version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(result.returncode == 0, f"staged Wine version probe failed: {result.stderr}")
        require(result.stdout.strip() == "wine-11.22", "staged Wine version mismatch")


def verify_existing(manifest: dict[str, Any], root: Path) -> None:
    verify_host_packages(manifest)
    verify_final_files(manifest, root, run_wine=True)
    print(f"wine-d3d-staging: VERIFY PASS root={root}")


def self_test() -> None:
    manifest = load_manifest()
    with tempfile.TemporaryDirectory(prefix="jasper-wine-staging-self-test-") as work:
        root = Path(work) / "root"
        for relative in manifest["final_files"]:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(relative.encode("utf-8"))
        artifact = root / "artifact"
        artifact.write_bytes(b"tampered")
        try:
            verify_digest(artifact, "0" * 64, "tampered artifact")
        except StagingError:
            pass
        else:
            raise StagingError("tampered artifact digest was accepted")
        bad = json.loads(json.dumps(manifest))
        bad["final_files"]["../escape"] = "0" * 64
        try:
            validate_manifest(bad)
        except StagingError:
            pass
        else:
            raise StagingError("escaping final path was accepted")
    print(
        "wine-d3d-staging: self-test PASS "
        f"components={len(manifest['components'])} "
        f"final_files={len(manifest['final_files'])} fail_closed=true"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--verify-only", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cache", type=Path, default=ARCHIVE_CACHE)
    parser.add_argument("--probe", type=Path)
    parser.add_argument("--d3d12-probe", type=Path)
    parser.add_argument("--d3d11-wsi-probe", type=Path)
    args = parser.parse_args(argv)

    try:
        manifest = load_manifest()
        if args.self_test:
            self_test()
        elif args.verify_only is not None:
            verify_existing(manifest, args.verify_only)
        elif args.prepare:
            prepare(
                manifest,
                args.output,
                args.cache,
                args.probe,
                args.d3d12_probe,
                args.d3d11_wsi_probe,
            )
        else:
            parser.error("choose --self-test, --prepare or --verify-only")
    except (OSError, subprocess.CalledProcessError, StagingError) as error:
        print(f"wine-d3d-staging: FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

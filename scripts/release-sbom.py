#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM for the Jasper-OS workspace."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def cargo_metadata() -> dict:
    output = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    return json.loads(output)


def lock_checksums() -> dict[str, str]:
    with (ROOT / "Cargo.lock").open("rb") as stream:
        lock = tomllib.load(stream)
    checksums = {}
    for package in lock.get("package", []):
        checksum = package.get("checksum")
        source = package.get("source")
        if checksum and source:
            checksums[f"{package['name']}@{package['version']}|{source}"] = checksum
    return checksums


def workspace_source_digest(directory: Path) -> str:
    relative = directory.relative_to(ROOT).as_posix()
    pattern = f"{relative}/**" if relative != "." else "**"
    files = subprocess.run(
        ["git", "ls-files", "-z", "--", pattern],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout.split(b"\0")
    digest = hashlib.sha256()
    for raw in sorted(path for path in files if path):
        path = raw.decode("utf-8")
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update((ROOT / path).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def component_ref(package: dict) -> str:
    source = package.get("source")
    qualifier = ""
    if source and source.startswith("registry+"):
        qualifier = "?repository_url=" + source.removeprefix("registry+")
    elif source:
        qualifier = "?source=" + hashlib.sha256(source.encode()).hexdigest()[:16]
    return f"pkg:cargo/{package['name']}@{package['version']}{qualifier}"


def generate() -> bytes:
    metadata = cargo_metadata()
    checksums = lock_checksums()
    workspace_members = set(metadata["workspace_members"])
    packages = sorted(
        metadata["packages"],
        key=lambda package: (package["name"], package["version"], package["id"]),
    )
    refs = {package["id"]: component_ref(package) for package in packages}
    components = []
    for package in packages:
        source = package.get("source")
        component = {
            "type": "library",
            "bom-ref": refs[package["id"]],
            "name": package["name"],
            "version": package["version"],
            "properties": [
                {
                    "name": "jasper:workspace_member",
                    "value": str(package["id"] in workspace_members).lower(),
                },
                {
                    "name": "jasper:source",
                    "value": source or "workspace",
                },
            ],
        }
        if package.get("license"):
            component["licenses"] = [{"expression": package["license"]}]
        checksum = None
        if source:
            checksum = checksums.get(
                f"{package['name']}@{package['version']}|{source}"
            )
        else:
            checksum = workspace_source_digest(Path(package["manifest_path"]).parent)
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        components.append(component)

    dependencies = []
    for node in sorted(
        metadata.get("resolve", {}).get("nodes", []),
        key=lambda node: refs.get(node["id"], node["id"]),
    ):
        dependencies.append(
            {
                "ref": refs.get(node["id"], node["id"]),
                "dependsOn": sorted(
                    refs.get(dependency, dependency)
                    for dependency in node.get("dependencies", [])
                    if dependency in refs
                ),
            }
        )

    root_package = next(
        (
            package
            for package in packages
            if package["name"] == "jasper-os"
        ),
        None,
    )
    root_version = root_package["version"] if root_package else "workspace"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "jasper-release-sbom",
                        "version": "1",
                    }
                ]
            },
            "component": {
                "type": "operating-system",
                "bom-ref": f"pkg:generic/jasper-os@{root_version}",
                "name": "jasper-os",
                "version": root_version,
            },
            "properties": [
                {
                    "name": "jasper:workspace_members",
                    "value": str(len(workspace_members)),
                }
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }
    return (json.dumps(bom, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def validate(payload: bytes) -> None:
    bom = json.loads(payload)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["components"]
    refs = [component["bom-ref"] for component in bom["components"]]
    assert len(refs) == len(set(refs)), "duplicate component reference"
    for component in bom["components"]:
        assert component["name"] and component["version"]
        if component["properties"][0]["value"] == "true":
            assert component.get("licenses"), (
                f"workspace component without license: {component['name']}"
            )
        assert component.get("hashes"), (
            f"component without source checksum: {component['name']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    first = generate()
    validate(first)
    if args.check:
        second = generate()
        assert first == second, "SBOM generation is not deterministic"
    if args.output:
        Path(args.output).write_bytes(first)
    print(
        f"release-sbom: PASS components={json.loads(first)['components'].__len__()} "
        f"deterministic={str(args.check).lower()}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, subprocess.CalledProcessError) as error:
        print(f"release-sbom: FAIL {error}", file=sys.stderr)
        raise SystemExit(1) from error

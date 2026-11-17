#!/usr/bin/env python3
"""Validate LC-5 release-channel and supply-chain policy."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "release" / "release-policy.toml"


def workspace_licenses() -> list[str]:
    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
    )
    members = set(metadata["workspace_members"])
    return sorted(
        package["name"]
        for package in metadata["packages"]
        if package["id"] in members and not package.get("license")
    )


def validate(policy: dict) -> None:
    assert policy["schema"] == 1
    assert policy["min_update_sources"] >= 2
    assert policy["require_sbom"] is True
    assert policy["require_reproducible_build"] is True
    assert policy["require_signed_manifest"] is True
    assert policy["require_offline_source"] is True
    channels = policy["channel"]
    names = [channel["name"] for channel in channels]
    assert len(names) == len(set(names))
    assert {"stable", "lts"} <= set(names)
    for channel in channels:
        assert channel["support_days"] > 0
        assert channel["security_response_hours"] > 0
        assert 0 < channel["critical_fix_days"] <= channel["high_fix_days"]
    stable = next(channel for channel in channels if channel["name"] == "stable")
    lts = next(channel for channel in channels if channel["name"] == "lts")
    assert lts["support_days"] > stable["support_days"]
    assert (ROOT / "scripts" / "release-sbom.py").is_file()
    assert (ROOT / "scripts" / "release-repro-check.sh").is_file()
    assert (ROOT / "scripts" / "release-artifact.py").is_file()
    assert (ROOT / "scripts" / "release-source-drill.py").is_file()
    assert (ROOT / "scripts" / "release-supply-check.sh").is_file()
    assert (ROOT / "scripts" / "check-vulnerabilities.py").is_file()
    assert (ROOT / "release" / "vulnerabilities.toml").is_file()
    assert not workspace_licenses(), workspace_licenses()


def main() -> int:
    with POLICY.open("rb") as stream:
        policy = tomllib.load(stream)
    validate(policy)
    print(
        "release-policy: PASS channels="
        + ",".join(channel["name"] for channel in policy["channel"])
        + " sources>="
        + str(policy["min_update_sources"])
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, KeyError, subprocess.CalledProcessError) as error:
        print(f"release-policy: FAIL {error}", file=sys.stderr)
        raise SystemExit(1) from error

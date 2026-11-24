#!/usr/bin/env python3
"""Validate Issue 43 compatibility profile identities and fail-closed scopes."""

from __future__ import annotations

import argparse
import copy
import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROFILES = ROOT / "verification/issue43-compatibility-profiles.toml"
ABI = ROOT / "abi/abi-version.txt"
INVENTORY = ROOT / "verification/issue43-pixel6a-binary-inventory.tsv"

KINDS = {
    "linux-device-uapi",
    "isolated-linux-driver-domain",
    "android-hal-user-service",
}
RUNTIME_STATES = {"software-contract", "inventory-only", "executable-unverified"}
REQUIRED = {
    "id",
    "kind",
    "execution_domain",
    "runtime_status",
    "architecture",
    "host_authority",
    "promotion_gate",
    "evidence",
}


def abi_version() -> str:
    values: dict[str, int] = {}
    for line in ABI.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        values[key] = int(value)
    return f"{values['major']}.{values['minor']}.{values['patch']}"


def inventory_fingerprints() -> tuple[set[str], set[str]]:
    lines = INVENTORY.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    fingerprint_at = header.index("build_fingerprint")
    kernel_at = header.index("kernel_release")
    fingerprints: set[str] = set()
    kernels: set[str] = set()
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != len(header):
            raise ValueError("binary inventory row has the wrong column count")
        fingerprints.add(fields[fingerprint_at])
        kernels.add(fields[kernel_at])
    return fingerprints, kernels


def validate(document: dict[str, object]) -> int:
    if document.get("schema") != 1:
        raise ValueError("schema must be 1")
    expected_native = abi_version()
    if document.get("native_abi") != expected_native:
        raise ValueError("native_abi does not match the authoritative ABI generation")
    if document.get("authority") != "kernel-device-broker":
        raise ValueError("compatibility profiles must retain the Device Broker authority")

    profiles = document.get("profile")
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("at least one profile is required")
    identifiers: set[str] = set()
    fingerprints, kernels = inventory_fingerprints()
    for profile in profiles:
        if not isinstance(profile, dict):
            raise ValueError("profile must be a table")
        missing = REQUIRED - profile.keys()
        if missing:
            raise ValueError(f"{profile.get('id', '<unnamed>')}: missing {sorted(missing)}")
        identifier = profile["id"]
        if not isinstance(identifier, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9.-]*@[1-9][0-9]*", identifier
        ):
            raise ValueError(f"invalid versioned profile id: {identifier!r}")
        if identifier in identifiers:
            raise ValueError(f"duplicate profile id: {identifier}")
        identifiers.add(identifier)
        if profile["kind"] not in KINDS:
            raise ValueError(f"{identifier}: unknown kind")
        if profile["execution_domain"] != "compatibility":
            raise ValueError(f"{identifier}: a compatibility profile cannot become native authority")
        if profile["runtime_status"] not in RUNTIME_STATES:
            raise ValueError(f"{identifier}: invalid runtime status")
        if profile["host_authority"] != "kernel-device-broker":
            raise ValueError(f"{identifier}: host authority changed")
        if not isinstance(profile["evidence"], list) or not profile["evidence"]:
            raise ValueError(f"{identifier}: evidence is required")
        for path in profile["evidence"]:
            if not isinstance(path, str) or not (ROOT / path).exists():
                raise ValueError(f"{identifier}: missing evidence {path!r}")
        fingerprint = profile.get("build_fingerprint")
        if fingerprint is not None and fingerprint not in fingerprints:
            raise ValueError(f"{identifier}: build fingerprint is not in the live inventory")
        kernel = profile.get("linux_kernel")
        if (
            profile["kind"] == "isolated-linux-driver-domain"
            and kernel not in kernels
        ):
            raise ValueError(f"{identifier}: kernel release is not in the live inventory")
    return len(profiles)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        document = tomllib.loads(PROFILES.read_text(encoding="utf-8"))
        if args.self_test:
            invalid = copy.deepcopy(document)
            invalid["profile"][0]["host_authority"] = "compatibility-root"
            try:
                validate(invalid)
            except ValueError as error:
                if "host authority changed" not in str(error):
                    raise
            else:
                raise ValueError("self-test mutation was accepted")
            print("issue43-compatibility-profiles: SELF-TEST PASS rejected authority escalation")
            return 0
        count = validate(document)
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as error:
        print(f"issue43-compatibility-profiles: FAIL {error}")
        return 1
    print(f"issue43-compatibility-profiles: PASS profiles={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

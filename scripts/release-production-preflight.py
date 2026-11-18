#!/usr/bin/env python3
"""Fail-closed audit of the LC-5 production signing environment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SCANNED_FILE = 1024 * 1024


class Audit:
    def __init__(self) -> None:
        self.checks: list[dict[str, object]] = []

    def pass_(self, name: str, **facts: object) -> None:
        self.checks.append({"name": name, "ok": True, **facts})

    def fail(self, name: str, reason: str, **facts: object) -> None:
        self.checks.append({"name": name, "ok": False, "reason": reason, **facts})

    def require(self, condition: bool, name: str, reason: str, **facts: object) -> None:
        if condition:
            self.pass_(name, **facts)
        else:
            self.fail(name, reason, **facts)


def command_exists(command: str) -> bool:
    return bool(shutil.which(command))


def executable(path: str | None) -> tuple[Path | None, str]:
    if not path:
        return None, "missing"
    candidate = Path(path)
    if not candidate.is_file():
        return None, "not a regular file"
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None, "unresolvable path"
    if not resolved.is_file():
        return None, "resolved target is not a regular file"
    if not os.access(resolved, os.X_OK):
        return None, "not executable"
    # tpm2-tools dispatches on argv[0]. Keeping the requested path preserves
    # calls such as tpm2_nvreadpublic when that path is a symlink to tpm2.
    return candidate, "ok"


def public_fingerprint(path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return hashlib.sha256(result.stdout).hexdigest()


def inspect_trust_directory(path: Path, label: str, audit: Audit) -> list[str]:
    if not path.is_dir() or path.is_symlink():
        audit.fail(label, "trust directory is missing or is a symlink", path=str(path))
        return []
    entries = sorted(path.iterdir())
    invalid = [
        entry.name
        for entry in entries
        if not entry.is_file() or entry.is_symlink() or entry.suffix not in {".pem", ".pub"}
    ]
    audit.require(
        not invalid,
        f"{label}-files",
        "trust directory contains non-public-key entries",
        invalid=invalid,
    )
    fingerprints: list[str] = []
    for entry in entries:
        if entry in {path / item for item in invalid}:
            continue
        fingerprint = public_fingerprint(entry)
        if fingerprint is None:
            audit.fail(f"{label}-parse", "public key cannot be parsed", file=entry.name)
        else:
            fingerprints.append(fingerprint)
    if len(fingerprints) != len(set(fingerprints)):
        audit.fail(f"{label}-unique", "trust directory contains duplicate keys")
    else:
        audit.pass_(f"{label}-unique", count=len(fingerprints))
    return sorted(set(fingerprints))


def tracked_private_keys(repo: Path, audit: Audit) -> None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        audit.fail("tracked-key-scan", f"git ls-files failed: {error}")
        return
    suspicious: list[str] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = raw.decode("utf-8", "surrogateescape")
        path = repo / relative
        lower = relative.lower()
        if any(token in lower for token in ("private", "secret", "signing-key")):
            suspicious.append(relative)
            continue
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SCANNED_FILE:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if any(marker in data for marker in PRIVATE_KEY_MARKERS):
            suspicious.append(relative)
    audit.require(
        not suspicious,
        "tracked-private-keys",
        "private key material or private-key-named files are tracked",
        paths=sorted(set(suspicious)),
    )


def tpm_inventory(args: argparse.Namespace, audit: Audit) -> None:
    device = Path(args.tpm_device)
    try:
        is_character_device = stat.S_ISCHR(device.stat().st_mode)
    except OSError:
        is_character_device = False
    audit.require(
        is_character_device,
        "tpm-device",
        "TPM character device is missing",
        path=str(device),
    )
    audit.require(
        os.access(device, os.R_OK | os.W_OK),
        "tpm-access",
        "current account cannot read/write the TPM resource-manager device",
        path=str(device),
        uid=os.getuid(),
        gid=os.getgid(),
    )
    tpm_sysfs = Path("/sys/class/tpm/tpm0")
    version_path = tpm_sysfs / "tpm_version_major"
    version = version_path.read_text(encoding="ascii").strip() if version_path.is_file() else ""
    audit.require(version == "2", "tpm-version", "TPM 2.0 was not discovered", version=version)
    for label, path, default in (
        ("tpm-getcap", args.tpm_getcap_command, "tpm2_getcap"),
        ("tpm-nvread", args.tpm_nvread_command, "tpm2_nvread"),
        ("tpm-nvreadpublic", args.tpm_nvreadpublic_command, "tpm2_nvreadpublic"),
        ("tpm-nvincrement", args.tpm_nvincrement_command, "tpm2_nvincrement"),
    ):
        selected, reason = executable(path or shutil.which(default))
        audit.require(selected is not None, label, f"tool is unavailable: {reason}", command=path or default)


def inspect_tpm_counter(args: argparse.Namespace, audit: Audit) -> None:
    if not args.tpm_nv_index:
        audit.fail("tpm-nv-index", "production monotonic-counter NV index is not configured")
        return
    try:
        index = int(args.tpm_nv_index, 0)
    except ValueError:
        audit.fail(
            "tpm-nv-index",
            "NV index is not a valid integer",
            index=args.tpm_nv_index,
        )
        return
    audit.require(
        0 <= index <= 0xFFFFFFFFFFFFFFFF,
        "tpm-nv-index",
        "NV index is outside the 64-bit TPM range",
        index=args.tpm_nv_index,
    )
    if not 0 <= index <= 0xFFFFFFFFFFFFFFFF:
        return

    selected, reason = executable(
        args.tpm_nvreadpublic_command or shutil.which("tpm2_nvreadpublic")
    )
    if selected is None:
        audit.fail(
            "tpm-nv-index-shape",
            f"cannot inspect the NV index without tpm2_nvreadpublic: {reason}",
            index=f"0x{index:08x}",
        )
        return
    try:
        result = subprocess.run(
            [str(selected), f"0x{index:08x}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        audit.fail("tpm-nv-index-shape", f"tpm2_nvreadpublic failed: {error}")
        return
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        audit.fail(
            "tpm-nv-index-shape",
            f"configured NV index is absent or unreadable: {detail}",
            index=f"0x{index:08x}",
        )
        return
    output = result.stdout.decode("utf-8", "replace")
    counter_type = bool(re.search(r"friendly:\s+[^\n]*\bnt=0x1\b", output))
    size_eight = bool(re.search(r"^\s*size:\s*8\s*$", output, re.MULTILINE))
    audit.require(
        counter_type and size_eight,
        "tpm-nv-index-shape",
        "production NV index must be an 8-byte TPM counter",
        index=f"0x{index:08x}",
        counter=counter_type,
        size_eight=size_eight,
    )


def audit_endpoint(value: str, audit: Audit) -> None:
    parsed = urlsplit(value)
    valid = (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
        and parsed.fragment == ""
    )
    audit.require(
        valid,
        "remote-audit-endpoint",
        "endpoint must be HTTPS without embedded credentials or fragment",
        endpoint=value,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--tpm-device", default="/dev/tpmrm0")
    parser.add_argument("--tpm-nv-index")
    parser.add_argument("--tpm-getcap-command")
    parser.add_argument("--tpm-nvread-command")
    parser.add_argument("--tpm-nvreadpublic-command")
    parser.add_argument("--tpm-nvincrement-command")
    parser.add_argument("--release-trusted-dir", type=Path)
    parser.add_argument("--governance-trusted-dir", type=Path)
    parser.add_argument("--remote-audit-endpoint")
    parser.add_argument("--inventory", action="store_true")
    args = parser.parse_args()

    audit = Audit()
    policy_path = args.repo / "release" / "release-policy.toml"
    try:
        policy = tomllib.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        audit.fail("release-policy", f"cannot read policy: {error}")
        policy = {}
    audit.require(
        policy.get("release_signer_threshold") == 2
        and policy.get("release_signer_count") == 3
        and policy.get("require_hardware_monotonic_anchor") is True,
        "release-policy",
        "2-of-3 signer and hardware-anchor policy is not enforced",
    )
    tracked_private_keys(args.repo, audit)
    tpm_inventory(args, audit)
    inspect_tpm_counter(args, audit)
    release_fingerprints: list[str] = []

    if args.release_trusted_dir:
        release_fingerprints = inspect_trust_directory(
            args.release_trusted_dir, "release-trust", audit
        )
        audit.require(
            len(release_fingerprints) == 3,
            "release-trust-count",
            "exactly three distinct release public keys are required",
            count=len(release_fingerprints),
        )
    else:
        audit.fail("release-trust", "production release trust directory is not configured")

    if args.governance_trusted_dir:
        governance = inspect_trust_directory(
            args.governance_trusted_dir, "governance-trust", audit
        )
        audit.require(
            len(governance) == 1,
            "governance-trust-count",
            "exactly one independent governance public key is required",
            count=len(governance),
        )
        audit.require(
            not set(governance).intersection(release_fingerprints),
            "governance-independent",
            "governance key must differ from every release signer",
        )
    else:
        audit.fail(
            "governance-trust",
            "independent production governance trust directory is not configured",
        )

    if args.remote_audit_endpoint:
        audit_endpoint(args.remote_audit_endpoint, audit)
    else:
        audit.fail("remote-audit-endpoint", "immutable remote audit endpoint is not configured")

    result = {
        "schema": "jasper.release-production-preflight/1",
        "inventory_only": args.inventory,
        "ok": all(check["ok"] for check in audit.checks),
        "checks": audit.checks,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    failures = [check for check in audit.checks if not check["ok"]]
    if failures:
        print(
            "release-production-preflight: NOT READY "
            + " ".join(str(check["name"]) for check in failures),
            file=sys.stderr,
        )
        return 1
    print("release-production-preflight: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

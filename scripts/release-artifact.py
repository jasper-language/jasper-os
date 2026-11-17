#!/usr/bin/env python3
"""Create and verify deterministic, Ed25519-signed LC-5 release manifests.

The private key is used only by the ``create`` command. Verification accepts a
directory of trusted public keys and an optional revoked-fingerprint list. A
release manifest binds release metadata, the exact kernel payload, and the exact
SBOM without embedding host paths or timestamps.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = "jasper.release-artifact/v1"
DOMAIN = b"JASPER-RELEASE-V1\0"
CHANNELS = {"stable", "lts"}
MAX_MANIFEST_BYTES = 64 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ABI_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def fail(message: str) -> None:
    print(f"release-artifact: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def digest(path: Path) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size


def openssl(*args: str, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["openssl", *args],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"openssl {' '.join(args[:2])} failed: {detail}")
    return result.stdout


def public_fingerprint(public_key: Path) -> str:
    der = openssl("pkey", "-pubin", "-in", str(public_key), "-outform", "DER")
    return hashlib.sha256(der).hexdigest()


def signing_message(manifest: bytes) -> bytes:
    return DOMAIN + manifest


def data_file(value: str, option: str) -> Path:
    path = Path(value)
    if not path.is_file() or path.is_symlink():
        fail(f"{option} must be a regular non-symlink file: {path}")
    return path


def create(args: argparse.Namespace) -> None:
    payload = data_file(args.payload, "--payload")
    sbom = data_file(args.sbom, "--sbom")
    key = data_file(args.private_key, "--private-key")
    if args.channel not in CHANNELS:
        fail(f"unsupported channel: {args.channel}")
    if not COMMIT_RE.fullmatch(args.source_commit):
        fail("--source-commit must be a full lowercase SHA-1")
    if not ABI_RE.fullmatch(args.abi):
        fail("--abi must be major.minor.patch")
    if not args.target or any(char.isspace() for char in args.target):
        fail("--target must be one non-empty token")

    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    # The public key is derived from the private key; callers cannot supply a
    # misleading signer identity.
    with tempfile.TemporaryDirectory(prefix="jasper-release-key-") as temporary:
        public_key = Path(temporary) / "signer.pem"
        openssl("pkey", "-in", str(key), "-pubout", "-out", str(public_key))
        signer = public_fingerprint(public_key)

    payload_sha256, payload_size = digest(payload)
    sbom_sha256, sbom_size = digest(sbom)
    manifest_value = {
        "schema": SCHEMA,
        "release": {
            "abi": args.abi,
            "channel": args.channel,
            "source_commit": args.source_commit,
            "target": args.target,
        },
        "payload": {
            "name": payload.name,
            "sha256": payload_sha256,
            "size": payload_size,
        },
        "sbom": {
            "name": sbom.name,
            "sha256": sbom_sha256,
            "size": sbom_size,
        },
        "signer": signer,
    }
    manifest = canonical_json(manifest_value)
    if len(manifest) > MAX_MANIFEST_BYTES:
        fail("release manifest exceeds bounded size")

    manifest_path = output / f"{args.name}.manifest.json"
    signature_path = output / f"{args.name}.manifest.sig"
    if manifest_path.exists() or signature_path.exists():
        fail("refusing to overwrite an existing release manifest or signature")
    manifest_path.write_bytes(manifest)
    with tempfile.NamedTemporaryFile(prefix="jasper-release-message-") as message:
        message.write(signing_message(manifest))
        message.flush()
        signature = openssl(
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(key),
            "-in",
            message.name,
        )
    if len(signature) != 64:
        fail(f"unexpected Ed25519 signature length: {len(signature)}")
    signature_path.write_bytes(signature)
    print(
        f"release-artifact: CREATED signer={signer} channel={args.channel} "
        f"payload={payload_sha256} sbom={sbom_sha256}"
    )


def load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.stat().st_size == 0 or path.stat().st_size > MAX_MANIFEST_BYTES:
        fail("manifest size is outside its bound")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"manifest is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict) or canonical_json(value) != raw:
        fail("manifest is not canonical JSON")
    if set(value) != {"schema", "release", "payload", "sbom", "signer"}:
        fail("manifest field set is not recognized")
    if value["schema"] != SCHEMA:
        fail("manifest schema mismatch")
    release = value["release"]
    if not isinstance(release, dict) or set(release) != {
        "abi",
        "channel",
        "source_commit",
        "target",
    }:
        fail("release metadata field set is not recognized")
    if release["channel"] not in CHANNELS:
        fail("release channel is not stable or lts")
    if not isinstance(release["source_commit"], str) or not COMMIT_RE.fullmatch(
        release["source_commit"]
    ):
        fail("release source commit is invalid")
    if not isinstance(release["abi"], str) or not ABI_RE.fullmatch(release["abi"]):
        fail("release ABI is invalid")
    if not isinstance(release["target"], str) or not release["target"]:
        fail("release target is invalid")
    for field in ("payload", "sbom"):
        item = value[field]
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "size"}:
            fail(f"{field} descriptor is not recognized")
        if (
            not isinstance(item["name"], str)
            or not item["name"]
            or Path(item["name"]).name != item["name"]
        ):
            fail(f"{field} name must be a basename")
        if not isinstance(item["sha256"], str) or not SHA256_RE.fullmatch(
            item["sha256"]
        ):
            fail(f"{field} SHA-256 is invalid")
        if not isinstance(item["size"], int) or item["size"] < 0:
            fail(f"{field} size is invalid")
    signer = value["signer"]
    if not isinstance(signer, str) or not SHA256_RE.fullmatch(signer):
        fail("signer fingerprint is invalid")
    return value, raw


def find_trusted_key(trusted_dir: Path, signer: str) -> Path:
    if not trusted_dir.is_dir():
        fail(f"trusted-key directory does not exist: {trusted_dir}")
    matches = [
        path
        for path in sorted(trusted_dir.glob("*.pem"))
        if path.is_file()
        and not path.is_symlink()
        and public_fingerprint(path) == signer
    ]
    if len(matches) != 1:
        fail(f"signer {signer} must have exactly one trusted public key")
    return matches[0]


def revoked(revocation_list: Path | None, signer: str) -> bool:
    if revocation_list is None:
        return False
    if not revocation_list.is_file():
        fail(f"revocation list does not exist: {revocation_list}")
    entries = {
        line.strip().lower()
        for line in revocation_list.read_text(encoding="ascii").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    bad = [entry for entry in entries if not SHA256_RE.fullmatch(entry)]
    if bad:
        fail(f"revocation list contains an invalid fingerprint: {bad[0]}")
    return signer in entries


def verify(args: argparse.Namespace) -> None:
    manifest_path = data_file(args.manifest, "--manifest")
    signature_path = data_file(args.signature, "--signature")
    payload = data_file(args.payload, "--payload")
    sbom = data_file(args.sbom, "--sbom")
    value, manifest = load_manifest(manifest_path)
    signer = value["signer"]
    if revoked(Path(args.revoked) if args.revoked else None, signer):
        fail(f"signer is revoked: {signer}")
    public_key = find_trusted_key(Path(args.trusted_dir), signer)
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        fail("signature is not exactly one Ed25519 signature")
    with tempfile.NamedTemporaryFile(prefix="jasper-release-message-") as message:
        message.write(signing_message(manifest))
        message.flush()
        openssl(
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key),
            "-rawin",
            "-in",
            message.name,
            "-sigfile",
            str(signature_path),
        )
    for label, actual, descriptor in (
        ("payload", payload, value["payload"]),
        ("sbom", sbom, value["sbom"]),
    ):
        actual_sha256, actual_size = digest(actual)
        if (
            actual.name != descriptor["name"]
            or actual_sha256 != descriptor["sha256"]
            or actual_size != descriptor["size"]
        ):
            fail(f"{label} identity does not match the signed manifest")
    print(
        f"release-artifact: PASS signer={signer} "
        f"channel={value['release']['channel']} payload={value['payload']['sha256']} "
        f"sbom={value['sbom']['sha256']}"
    )


def fingerprint(args: argparse.Namespace) -> None:
    key = data_file(args.public_key, "--public-key")
    print(f"fingerprint={public_fingerprint(key)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    create_parser = commands.add_parser("create")
    create_parser.add_argument("--payload", required=True)
    create_parser.add_argument("--sbom", required=True)
    create_parser.add_argument("--private-key", required=True)
    create_parser.add_argument("--output-dir", required=True)
    create_parser.add_argument("--name", required=True)
    create_parser.add_argument("--channel", required=True)
    create_parser.add_argument("--source-commit", required=True)
    create_parser.add_argument("--target", required=True)
    create_parser.add_argument("--abi", required=True)
    create_parser.set_defaults(run=create)

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--manifest", required=True)
    verify_parser.add_argument("--signature", required=True)
    verify_parser.add_argument("--payload", required=True)
    verify_parser.add_argument("--sbom", required=True)
    verify_parser.add_argument("--trusted-dir", required=True)
    verify_parser.add_argument("--revoked")
    verify_parser.set_defaults(run=verify)

    fingerprint_parser = commands.add_parser("fingerprint")
    fingerprint_parser.add_argument("--public-key", required=True)
    fingerprint_parser.set_defaults(run=fingerprint)

    args = parser.parse_args()
    args.run(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as error:
        fail(str(error))

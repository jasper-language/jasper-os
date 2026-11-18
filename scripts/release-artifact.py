#!/usr/bin/env python3
"""Create and verify deterministic, threshold-signed LC-5 release manifests.

创建并验证确定性的 LC-5 门限签名发布清单。

Private keys are used only by the ``create`` command. Verification accepts a
directory of trusted public keys and an optional revoked-fingerprint list. A
release manifest binds release metadata, the exact kernel payload, the exact
SBOM, the declared signer set, and its threshold without embedding host paths or
timestamps.
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
import tomllib
from pathlib import Path
from typing import Any

SCHEMA = "jasper.release-artifact/v2"
DOMAIN = b"JASPER-RELEASE-V1\0"
CHANNELS = {"stable", "lts"}
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIGNERS = 8
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


def signing_policy() -> tuple[int, int]:
    """Read the repository's authoritative threshold policy.

    从仓库发布策略读取门限和签名者数量，验证器不能自行接受更宽松的门限。
    """
    policy_path = Path(__file__).resolve().parents[1] / "release" / "release-policy.toml"
    try:
        with policy_path.open("rb") as stream:
            policy = tomllib.load(stream)
        threshold = policy["release_signer_threshold"]
        signers = policy["release_signer_count"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot load release signing policy: {error}")
    if (
        not isinstance(threshold, int)
        or not isinstance(signers, int)
        or threshold < 2
        or threshold >= signers
        or signers > MAX_SIGNERS
    ):
        fail("release signing policy is invalid")
    return threshold, signers


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


def signature_name(release_name: str, signer: str) -> str:
    return f"{release_name}.{signer}.manifest.sig"


def build_manifest(
    payload: Path,
    sbom: Path,
    fingerprints: list[str],
    args: argparse.Namespace,
) -> tuple[dict[str, Any], bytes]:
    threshold, required_signers = signing_policy()
    if len(fingerprints) != required_signers:
        fail(
            f"release policy requires {required_signers} signer keys, "
            f"got {len(fingerprints)}"
        )
    if len(fingerprints) != len(set(fingerprints)):
        fail("release signer keys must be distinct")
    fingerprints = sorted(fingerprints)
    if args.channel not in CHANNELS:
        fail(f"unsupported channel: {args.channel}")
    if not COMMIT_RE.fullmatch(args.source_commit):
        fail("--source-commit must be a full lowercase SHA-1")
    if not ABI_RE.fullmatch(args.abi):
        fail("--abi must be major.minor.patch")
    if not args.target or any(char.isspace() for char in args.target):
        fail("--target must be one non-empty token")
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
        "signing": {
            "threshold": threshold,
            "signers": [
                {
                    "fingerprint": fingerprint,
                    "signature": signature_name(args.name, fingerprint),
                }
                for fingerprint in fingerprints
            ],
        },
    }
    manifest = canonical_json(manifest_value)
    if len(manifest) > MAX_MANIFEST_BYTES:
        fail("release manifest exceeds bounded size")
    return manifest_value, manifest


def write_new(path: Path, contents: bytes) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
    except FileExistsError:
        fail(f"refusing to overwrite an existing file: {path}")
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())


def public_fingerprints(keys: list[Path]) -> list[str]:
    fingerprints = []
    with tempfile.TemporaryDirectory(prefix="jasper-release-key-") as temporary:
        for index, key in enumerate(keys):
            public_key = Path(temporary) / f"signer-{index}.pem"
            openssl("pkey", "-in", str(key), "-pubout", "-out", str(public_key))
            fingerprints.append(public_fingerprint(public_key))
    return fingerprints


def prepare(args: argparse.Namespace) -> None:
    payload = data_file(args.payload, "--payload")
    sbom = data_file(args.sbom, "--sbom")
    keys = [data_file(value, "--public-key") for value in args.public_key]
    _, manifest = build_manifest(
        payload,
        sbom,
        [public_fingerprint(key) for key in keys],
        args,
    )
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / f"{args.name}.manifest.json"
    write_new(manifest_path, manifest)
    print(
        f"release-artifact: PREPARED threshold={signing_policy()[0]} "
        f"signers={len(keys)} manifest_sha256={hashlib.sha256(manifest).hexdigest()}"
    )


def sign(args: argparse.Namespace) -> None:
    manifest_path = data_file(args.manifest, "--manifest")
    key = data_file(args.private_key, "--private-key")
    _, manifest = load_manifest(manifest_path)
    value = json.loads(manifest)
    fingerprint = public_fingerprints([key])[0]
    if fingerprint not in {
        signer["fingerprint"] for signer in value["signing"]["signers"]
    }:
        fail(f"private key is not a declared release signer: {fingerprint}")
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
    write_new(Path(args.output), signature)
    print(
        f"release-artifact: SIGNED signer={fingerprint} "
        f"manifest_sha256={hashlib.sha256(manifest).hexdigest()}"
    )


def data_file(value: str, option: str) -> Path:
    path = Path(value)
    if not path.is_file() or path.is_symlink():
        fail(f"{option} must be a regular non-symlink file: {path}")
    return path


def create(args: argparse.Namespace) -> None:
    payload = data_file(args.payload, "--payload")
    sbom = data_file(args.sbom, "--sbom")
    keys = [data_file(value, "--private-key") for value in args.private_key]
    threshold, required_signers = signing_policy()
    threshold = threshold if args.threshold is None else args.threshold
    if threshold != required_signers - 1 or len(keys) != required_signers:
        fail(
            f"release policy requires {required_signers - 1}-of-{required_signers}, "
            f"got threshold={threshold} signers={len(keys)}"
        )
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
    # Public identities are derived from private keys; callers cannot supply a
    # misleading signer set. Fingerprints are sorted so manifest bytes do not
    # depend on command-line key order.
    # 公钥身份由私钥派生，签名者按指纹排序，避免伪造身份或依赖参数顺序。
    signers: list[tuple[str, Path]] = []
    with tempfile.TemporaryDirectory(prefix="jasper-release-key-") as temporary:
        for index, key in enumerate(keys):
            public_key = Path(temporary) / f"signer-{index}.pem"
            openssl("pkey", "-in", str(key), "-pubout", "-out", str(public_key))
            signers.append((public_fingerprint(public_key), key))
    signers.sort()
    fingerprints = [fingerprint for fingerprint, _ in signers]
    if len(fingerprints) != len(set(fingerprints)):
        fail("release signer keys must be distinct")

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
        "signing": {
            "threshold": threshold,
            "signers": [
                {
                    "fingerprint": fingerprint,
                    "signature": signature_name(args.name, fingerprint),
                }
                for fingerprint in fingerprints
            ],
        },
    }
    manifest = canonical_json(manifest_value)
    if len(manifest) > MAX_MANIFEST_BYTES:
        fail("release manifest exceeds bounded size")

    manifest_path = output / f"{args.name}.manifest.json"
    signature_paths = {
        fingerprint: output / signature_name(args.name, fingerprint)
        for fingerprint in fingerprints
    }
    if manifest_path.exists() or any(path.exists() for path in signature_paths.values()):
        fail("refusing to overwrite an existing release manifest or signature")

    signed = []
    with tempfile.NamedTemporaryFile(prefix="jasper-release-message-") as message:
        message.write(signing_message(manifest))
        message.flush()
        for fingerprint, key in signers:
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
            signed.append((fingerprint, signature))

    manifest_path.write_bytes(manifest)
    for fingerprint, signature in signed:
        signature_paths[fingerprint].write_bytes(signature)
    print(
        f"release-artifact: CREATED threshold={threshold} signers={len(signers)} "
        f"channel={args.channel} payload={payload_sha256} sbom={sbom_sha256}"
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
    if set(value) != {"schema", "release", "payload", "sbom", "signing"}:
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
    signing = value["signing"]
    if not isinstance(signing, dict) or set(signing) != {"threshold", "signers"}:
        fail("signing descriptor is not recognized")
    threshold = signing["threshold"]
    signers = signing["signers"]
    required_threshold, required_signers = signing_policy()
    actual_signers = len(signers) if isinstance(signers, list) else -1
    if (
        not isinstance(threshold, int)
        or not isinstance(signers, list)
        or threshold != required_threshold
        or actual_signers != required_signers
    ):
        fail(
            f"release policy requires {required_threshold}-of-{required_signers}, "
            f"got threshold={threshold} signers={actual_signers}"
        )
    fingerprints = []
    signature_names = []
    for signer in signers:
        if not isinstance(signer, dict) or set(signer) != {
            "fingerprint",
            "signature",
        }:
            fail("release signer descriptor is not recognized")
        fingerprint = signer["fingerprint"]
        name = signer["signature"]
        if not isinstance(fingerprint, str) or not SHA256_RE.fullmatch(fingerprint):
            fail("signer fingerprint is invalid")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not name.endswith(".manifest.sig")
        ):
            fail("signature name must be a bounded basename")
        fingerprints.append(fingerprint)
        signature_names.append(name)
    if fingerprints != sorted(fingerprints) or len(set(fingerprints)) != len(
        fingerprints
    ):
        fail("release signers must be unique and canonically ordered")
    if len(set(signature_names)) != len(signature_names):
        fail("release signature names must be unique")
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
    payload = data_file(args.payload, "--payload")
    sbom = data_file(args.sbom, "--sbom")
    value, manifest = load_manifest(manifest_path)
    signing = value["signing"]
    expected = {
        signer["signature"]: signer["fingerprint"] for signer in signing["signers"]
    }
    signatures = [data_file(value, "--signature") for value in args.signature]
    provided: dict[str, Path] = {}
    for path in signatures:
        if path.name not in expected:
            fail(f"unexpected signature file: {path.name}")
        if path.name in provided:
            fail(f"duplicate signature file: {path.name}")
        provided[path.name] = path
    if len(provided) < signing["threshold"]:
        fail(
            f"release threshold not met: provided={len(provided)} "
            f"threshold={signing['threshold']}"
        )
    revocation_path = Path(args.revoked) if args.revoked else None
    for signer in signing["signers"]:
        if revoked(revocation_path, signer["fingerprint"]):
            fail(f"signer is revoked: {signer['fingerprint']}")

    valid_signers = []
    with tempfile.NamedTemporaryFile(prefix="jasper-release-message-") as message:
        message.write(signing_message(manifest))
        message.flush()
        for name, path in provided.items():
            fingerprint = expected[name]
            signature = path.read_bytes()
            if len(signature) != 64:
                fail("signature is not exactly one Ed25519 signature")
            public_key = find_trusted_key(Path(args.trusted_dir), fingerprint)
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
                str(path),
            )
            valid_signers.append(fingerprint)
    # A repeated file cannot satisfy another signer slot.
    # 同一签名文件不能重复占用不同签名槽。
    if len(valid_signers) < signing["threshold"]:
        fail(
            f"release threshold not met: valid={len(valid_signers)} "
            f"threshold={signing['threshold']}"
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
        f"release-artifact: PASS valid_signers={len(valid_signers)} "
        f"threshold={signing['threshold']} "
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
    create_parser.add_argument("--private-key", action="append", required=True)
    create_parser.add_argument("--threshold", type=int)
    create_parser.add_argument("--output-dir", required=True)
    create_parser.add_argument("--name", required=True)
    create_parser.add_argument("--channel", required=True)
    create_parser.add_argument("--source-commit", required=True)
    create_parser.add_argument("--target", required=True)
    create_parser.add_argument("--abi", required=True)
    create_parser.set_defaults(run=create)

    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--payload", required=True)
    prepare_parser.add_argument("--sbom", required=True)
    prepare_parser.add_argument("--public-key", action="append", required=True)
    prepare_parser.add_argument("--output-dir", required=True)
    prepare_parser.add_argument("--name", required=True)
    prepare_parser.add_argument("--channel", required=True)
    prepare_parser.add_argument("--source-commit", required=True)
    prepare_parser.add_argument("--target", required=True)
    prepare_parser.add_argument("--abi", required=True)
    prepare_parser.set_defaults(run=prepare)

    sign_parser = commands.add_parser("sign")
    sign_parser.add_argument("--manifest", required=True)
    sign_parser.add_argument("--private-key", required=True)
    sign_parser.add_argument("--output", required=True)
    sign_parser.set_defaults(run=sign)

    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--manifest", required=True)
    verify_parser.add_argument("--signature", action="append", required=True)
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

#!/usr/bin/env python3
"""Create and persist signed, monotonic LC-5 release-signer revocations.

The snapshot is signed by a governance key that is independent from release
signing keys. Acceptance is serialized, requires an exact epoch successor and
a matching previous-snapshot digest, and rejects attempts to remove an already
revoked fingerprint. Two identical local state copies fail closed if they
diverge. The audit journal records the intent before the state transition so an
interrupted transition can be completed by replaying the exact snapshot.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SNAPSHOT_SCHEMA = "jasper.release-revocations/v1"
STATE_SCHEMA = "jasper.release-revocation-state/v1"
ANCHOR_SCHEMA = "jasper.release-monotonic-anchor/v1"
ANCHOR_INTENT_SCHEMA = "jasper.release-monotonic-anchor-intent/v1"
DOMAIN = b"JASPER-REVOCATION-SNAPSHOT-V1\0"
MAX_SNAPSHOT_BYTES = 64 * 1024
MAX_ANCHOR_BYTES = 4 * 1024
ZERO_DIGEST = "0" * 64
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
U64_MAX = (1 << 64) - 1


def fail(message: str) -> None:
    print(f"release-revocations: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def digest(bytes_value: bytes) -> str:
    return hashlib.sha256(bytes_value).hexdigest()


def regular_file(path: Path, label: str) -> Path:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file: {path}")
    return path


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


def public_fingerprint(path: Path) -> str:
    der = openssl("pkey", "-pubin", "-in", str(path), "-outform", "DER")
    return digest(der)


def parse_revoked(path: Path) -> list[str]:
    lines = [
        line.strip().lower()
        for line in regular_file(path, "--revoked").read_text(encoding="ascii").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if any(not SHA256_RE.fullmatch(item) for item in lines):
        fail("revocation input contains an invalid fingerprint")
    if len(lines) != len(set(lines)):
        fail("revocation input contains duplicate fingerprints")
    return sorted(lines)


def snapshot_value(epoch: int, previous_sha256: str, revoked: list[str]) -> dict[str, Any]:
    if epoch <= 0:
        fail("snapshot epoch must be positive")
    if not SHA256_RE.fullmatch(previous_sha256):
        fail("previous snapshot digest is invalid")
    return {
        "epoch": epoch,
        "previous_sha256": previous_sha256,
        "revoked": revoked,
        "schema": SNAPSHOT_SCHEMA,
    }


def create(args: argparse.Namespace) -> None:
    key = regular_file(Path(args.private_key), "--private-key")
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    snapshot_path = output / f"{args.name}.revocations.json"
    signature_path = output / f"{args.name}.revocations.sig"
    if snapshot_path.exists() or signature_path.exists():
        fail("refusing to overwrite a revocation snapshot or signature")
    raw = canonical(
        snapshot_value(
            args.epoch,
            args.previous_sha256.lower(),
            parse_revoked(Path(args.revoked)),
        )
    )
    if len(raw) > MAX_SNAPSHOT_BYTES:
        fail("revocation snapshot exceeds its bound")
    with tempfile.NamedTemporaryFile(prefix="jasper-revocation-message-") as message:
        message.write(DOMAIN + raw)
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
    snapshot_path.write_bytes(raw)
    signature_path.write_bytes(signature)
    print(
        f"release-revocations: CREATED epoch={args.epoch} "
        f"snapshot={digest(raw)} revoked={len(parse_revoked(Path(args.revoked)))}"
    )


def validate_snapshot_value(value: Any) -> None:
    if set(value) != {"epoch", "previous_sha256", "revoked", "schema"}:
        fail("snapshot field set is not recognized")
    if value["schema"] != SNAPSHOT_SCHEMA:
        fail("snapshot schema mismatch")
    if not isinstance(value["epoch"], int) or value["epoch"] <= 0:
        fail("snapshot epoch is invalid")
    if not isinstance(value["previous_sha256"], str) or not SHA256_RE.fullmatch(
        value["previous_sha256"]
    ):
        fail("snapshot previous digest is invalid")
    revoked = value["revoked"]
    if (
        not isinstance(revoked, list)
        or any(
            not isinstance(item, str) or not SHA256_RE.fullmatch(item)
            for item in revoked
        )
        or revoked != sorted(set(revoked))
    ):
        fail("snapshot revoked fingerprints are invalid or non-canonical")


def load_snapshot(path: Path) -> tuple[dict[str, Any], bytes]:
    path = regular_file(path, "--snapshot")
    if path.stat().st_size == 0 or path.stat().st_size > MAX_SNAPSHOT_BYTES:
        fail("snapshot size is outside its bound")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"snapshot is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict) or canonical(value) != raw:
        fail("snapshot is not canonical JSON")
    validate_snapshot_value(value)
    return value, raw


def initial_state() -> dict[str, Any]:
    return {
        "epoch": 0,
        "governance": ZERO_DIGEST,
        "revoked": [],
        "schema": STATE_SCHEMA,
        "signature": None,
        "snapshot": None,
        "snapshot_sha256": ZERO_DIGEST,
    }


def load_state(root: Path) -> dict[str, Any]:
    paths = [root / "state.0.json", root / "state.1.json"]
    if not any(path.exists() for path in paths):
        return initial_state()
    if not all(path.is_file() and not path.is_symlink() for path in paths):
        fail("both revocation state copies must exist")
    first = paths[0].read_bytes()
    second = paths[1].read_bytes()
    if first != second:
        fail("revocation state copies diverge")
    try:
        value = json.loads(first)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"revocation state is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict) or canonical(value) != first:
        fail("revocation state is not canonical JSON")
    if set(value) != {
        "epoch",
        "governance",
        "revoked",
        "schema",
        "signature",
        "snapshot",
        "snapshot_sha256",
    }:
        fail("revocation state field set is not recognized")
    if (
        value["schema"] != STATE_SCHEMA
        or not isinstance(value["epoch"], int)
        or value["epoch"] < 0
        or not isinstance(value["governance"], str)
        or not SHA256_RE.fullmatch(value["governance"])
        or not isinstance(value["snapshot_sha256"], str)
        or not SHA256_RE.fullmatch(value["snapshot_sha256"])
    ):
        fail("revocation state contents are invalid")
    revoked_state = value["revoked"]
    if (
        not isinstance(revoked_state, list)
        or any(
            not isinstance(item, str) or not SHA256_RE.fullmatch(item)
            for item in revoked_state
        )
        or revoked_state != sorted(set(revoked_state))
    ):
        fail("revocation state fingerprints are invalid or non-canonical")
    if value["epoch"] == 0:
        if value["signature"] is not None or value["snapshot"] is not None:
            fail("initial revocation state carries an unexpected snapshot")
    else:
        signature = value["signature"]
        snapshot = value["snapshot"]
        if (
            not isinstance(signature, str)
            or not re.fullmatch(r"[0-9a-f]{128}", signature)
            or not isinstance(snapshot, dict)
        ):
            fail("revocation state snapshot or signature is invalid")
        validate_snapshot_value(snapshot)
        raw_snapshot = canonical(snapshot)
        if (
            digest(raw_snapshot) != value["snapshot_sha256"]
            or snapshot["epoch"] != value["epoch"]
            or snapshot["revoked"] != value["revoked"]
        ):
            fail("revocation state does not match its signed snapshot")
    return value


def audit_records(root: Path) -> list[dict[str, Any]]:
    path = root / "audit.jsonl"
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    previous_epoch = 0
    previous_sha256 = ZERO_DIGEST
    for line in regular_file(path, "audit journal").read_text(encoding="ascii").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            fail(f"audit journal contains invalid JSON: {error}")
        if canonical(value).rstrip(b"\n") != line.encode("ascii"):
            fail("audit journal record is not canonical JSON")
        if set(value) != {"epoch", "previous_sha256", "snapshot_sha256"}:
            fail("audit journal field set is not recognized")
        if (
            value["epoch"] != previous_epoch + 1
            or value["previous_sha256"] != previous_sha256
            or not isinstance(value["snapshot_sha256"], str)
            or not SHA256_RE.fullmatch(value["snapshot_sha256"])
        ):
            fail("audit journal is not a contiguous snapshot chain")
        previous_epoch = value["epoch"]
        previous_sha256 = value["snapshot_sha256"]
        records.append(value)
    return records


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path: Path, value: bytes) -> None:
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def append_audit(root: Path, event: dict[str, Any]) -> None:
    path = root / "audit.jsonl"
    with path.open("ab") as stream:
        stream.write(canonical(event))
        stream.flush()
        os.fsync(stream.fileno())


def write_state(root: Path, state: dict[str, Any]) -> None:
    raw = canonical(state)
    atomic_write(root / "state.0.json", raw)
    atomic_write(root / "state.1.json", raw)
    fsync_directory(root)


def tpm_enabled(args: argparse.Namespace) -> bool:
    return getattr(args, "tpm_nv_index", None) is not None


def require_anchor_mode(args: argparse.Namespace) -> None:
    hardware = tpm_enabled(args)
    software = bool(getattr(args, "development_software_anchor", False))
    if hardware and software:
        fail("TPM and development software anchor modes are mutually exclusive")
    if hardware:
        return
    if software:
        return
    fail(
        "a TPM2 monotonic anchor is required; "
        "--development-software-anchor is test-only"
    )


def tpm_auth_arguments(args: argparse.Namespace) -> list[str]:
    return [
        "-C",
        args.tpm_auth_handle,
        "-P",
        args.tpm_auth_password,
    ]


def run_tpm_command(command: list[str], action: str, timeout: int) -> bytes:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        fail(f"TPM {action} exceeded its {timeout}s command deadline")
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"TPM {action} failed with status {result.returncode}: {detail}")
    return result.stdout


def tpm_increment(args: argparse.Namespace) -> None:
    run_tpm_command(
        [
            args.tpm_increment_command,
            *tpm_auth_arguments(args),
            args.tpm_nv_index,
        ],
        "increment",
        args.tpm_command_timeout,
    )


def tpm_read_counter(args: argparse.Namespace) -> int:
    raw = run_tpm_command(
        [
            args.tpm_read_command,
            *tpm_auth_arguments(args),
            "--offset",
            "0",
            "-s",
            "8",
            args.tpm_nv_index,
        ],
        "read",
        args.tpm_command_timeout,
    )
    if len(raw) != 8:
        fail(f"TPM counter read returned {len(raw)} bytes instead of exactly 8")
    counter = int.from_bytes(raw, "big")
    if counter > U64_MAX:
        fail("TPM counter read returned an out-of-range value")
    return counter


def load_anchor_document(
    path: Path, schema: str, fields: set[str], label: str
) -> dict[str, Any] | None:
    if not path.exists():
        return None
    path = regular_file(path, label)
    if path.stat().st_size == 0 or path.stat().st_size > MAX_ANCHOR_BYTES:
        fail(f"{label} size is outside its bound")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict) or canonical(value) != raw or set(value) != fields:
        fail(f"{label} is not canonical or has an unknown field set")
    if value["schema"] != schema:
        fail(f"{label} schema mismatch")
    return value


def load_anchor(root: Path) -> dict[str, Any] | None:
    value = load_anchor_document(
        root / "monotonic-anchor.json",
        ANCHOR_SCHEMA,
        {"counter", "schema", "snapshot_sha256"},
        "monotonic anchor",
    )
    if value is None:
        return None
    if (
        not isinstance(value["counter"], int)
        or value["counter"] <= 0
        or value["counter"] > U64_MAX
        or not isinstance(value["snapshot_sha256"], str)
        or not SHA256_RE.fullmatch(value["snapshot_sha256"])
    ):
        fail("monotonic anchor contents are invalid")
    return value


def load_anchor_intent(root: Path) -> dict[str, Any] | None:
    value = load_anchor_document(
        root / "monotonic-anchor.intent.json",
        ANCHOR_INTENT_SCHEMA,
        {
            "expected_counter",
            "previous_counter",
            "previous_snapshot_sha256",
            "schema",
            "snapshot_sha256",
        },
        "monotonic anchor intent",
    )
    if value is None:
        return None
    if (
        not isinstance(value["expected_counter"], int)
        or not isinstance(value["previous_counter"], int)
        or value["previous_counter"] < 0
        or value["expected_counter"] != value["previous_counter"] + 1
        or value["expected_counter"] > U64_MAX
        or not isinstance(value["previous_snapshot_sha256"], str)
        or not SHA256_RE.fullmatch(value["previous_snapshot_sha256"])
        or not isinstance(value["snapshot_sha256"], str)
        or not SHA256_RE.fullmatch(value["snapshot_sha256"])
    ):
        fail("monotonic anchor intent contents are invalid")
    return value


def write_anchor(root: Path, counter: int, snapshot_sha256: str) -> None:
    value = {
        "counter": counter,
        "schema": ANCHOR_SCHEMA,
        "snapshot_sha256": snapshot_sha256,
    }
    atomic_write(root / "monotonic-anchor.json", canonical(value))
    fsync_directory(root)


def write_anchor_intent(root: Path, value: dict[str, Any]) -> None:
    atomic_write(root / "monotonic-anchor.intent.json", canonical(value))
    fsync_directory(root)


def clear_anchor_intent(root: Path) -> None:
    path = root / "monotonic-anchor.intent.json"
    if path.exists():
        path.unlink()
        fsync_directory(root)


def require_tpm_anchor_for_state(
    root: Path, args: argparse.Namespace, state: dict[str, Any]
) -> None:
    if not tpm_enabled(args):
        return
    if load_anchor_intent(root) is not None:
        fail("monotonic anchor has an unfinished increment intent")
    anchor = load_anchor(root)
    counter = tpm_read_counter(args)
    if state["epoch"] == 0:
        if anchor is not None or counter != 0:
            fail("initial revocation state conflicts with the TPM monotonic anchor")
        return
    if anchor is None:
        fail("non-empty revocation state has no TPM monotonic anchor")
    if anchor["snapshot_sha256"] != state["snapshot_sha256"]:
        fail("TPM monotonic anchor does not match the revocation state")
    if counter < anchor["counter"]:
        fail("TPM monotonic counter rolled back below the persisted anchor")
    if counter > anchor["counter"]:
        fail("TPM monotonic counter contains an unregistered increment")


def advance_tpm_anchor(
    root: Path,
    args: argparse.Namespace,
    state: dict[str, Any],
    snapshot_sha256: str,
) -> None:
    if not tpm_enabled(args):
        return
    anchor = load_anchor(root)
    intent = load_anchor_intent(root)
    counter = tpm_read_counter(args)

    if intent is not None:
        previous_counter = 0 if anchor is None else anchor["counter"]
        previous_snapshot = ZERO_DIGEST if anchor is None else anchor["snapshot_sha256"]
        if (
            intent["previous_counter"] != previous_counter
            or intent["previous_snapshot_sha256"] != previous_snapshot
            or intent["snapshot_sha256"] != snapshot_sha256
        ):
            fail("monotonic anchor intent does not bind the current transition")
        if counter < intent["expected_counter"]:
            tpm_increment(args)
            counter = tpm_read_counter(args)
        if counter != intent["expected_counter"]:
            fail(
                "TPM counter does not equal the pending increment intent "
                f"({counter} != {intent['expected_counter']})"
            )
        write_anchor(root, counter, snapshot_sha256)
        clear_anchor_intent(root)
        return

    if anchor is None:
        if counter != 0:
            fail("TPM counter is non-zero before the first recorded anchor")
        previous_counter = 0
        previous_snapshot = ZERO_DIGEST
    else:
        if counter < anchor["counter"]:
            fail("TPM monotonic counter rolled back below the persisted anchor")
        if counter > anchor["counter"]:
            fail("TPM monotonic counter contains an unregistered increment")
        if anchor["snapshot_sha256"] == snapshot_sha256:
            return
        if anchor["snapshot_sha256"] != state["snapshot_sha256"]:
            fail("TPM anchor and revocation state disagree before a new transition")
        previous_counter = anchor["counter"]
        previous_snapshot = anchor["snapshot_sha256"]

    expected = previous_counter + 1
    write_anchor_intent(
        root,
        {
            "expected_counter": expected,
            "previous_counter": previous_counter,
            "previous_snapshot_sha256": previous_snapshot,
            "schema": ANCHOR_INTENT_SCHEMA,
            "snapshot_sha256": snapshot_sha256,
        },
    )
    tpm_increment(args)
    counter = tpm_read_counter(args)
    if counter != expected:
        fail(f"TPM counter did not advance exactly once ({counter} != {expected})")
    write_anchor(root, counter, snapshot_sha256)
    clear_anchor_intent(root)


def verify_snapshot_signature(
    snapshot: bytes, signature: bytes, public_key: Path
) -> None:
    if len(signature) != 64:
        fail("signature is not exactly one Ed25519 signature")
    with tempfile.NamedTemporaryFile(prefix="jasper-revocation-message-") as message:
        message.write(DOMAIN + snapshot)
        message.flush()
        with tempfile.NamedTemporaryFile(prefix="jasper-revocation-signature-") as signature_file:
            signature_file.write(signature)
            signature_file.flush()
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
                signature_file.name,
            )


def read_and_verify_signature(
    snapshot: bytes, signature_path: Path, public_key: Path
) -> bytes:
    signature = regular_file(signature_path, "--signature").read_bytes()
    verify_snapshot_signature(snapshot, signature, public_key)
    return signature


def verify_persisted_state(state: dict[str, Any], public_key: Path) -> None:
    if state["epoch"] == 0:
        return
    signature = bytes.fromhex(state["signature"])
    raw_snapshot = canonical(state["snapshot"])
    verify_snapshot_signature(raw_snapshot, signature, public_key)
    if public_fingerprint(public_key) != state["governance"]:
        fail("persisted revocation state uses another governance key")


def verify_state_matches_signature(state: dict[str, Any], public_key: Path) -> None:
    verify_persisted_state(state, public_key)
    if state["epoch"] == 0:
        return
    if (
        digest(canonical(state["snapshot"])) != state["snapshot_sha256"]
        or state["snapshot"]["epoch"] != state["epoch"]
        or state["snapshot"]["revoked"] != state["revoked"]
    ):
        fail("persisted revocation state does not match its signed snapshot")


def accept(args: argparse.Namespace) -> None:
    require_anchor_mode(args)
    root = Path(args.state_dir)
    root.mkdir(parents=True, exist_ok=True)
    public_key = regular_file(Path(args.governance_public_key), "--governance-public-key")
    value, raw = load_snapshot(Path(args.snapshot))
    signature_bytes = read_and_verify_signature(raw, Path(args.signature), public_key)
    governance = public_fingerprint(public_key)
    snapshot_sha256 = digest(raw)

    with (root / "accept.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        state = load_state(root)
        verify_state_matches_signature(state, public_key)
        audit = audit_records(root)
        if state["epoch"] != len(audit):
            if (
                state["epoch"] + 1 != len(audit)
                or not audit
                or audit[-1]["epoch"] != value["epoch"]
                or audit[-1]["snapshot_sha256"] != snapshot_sha256
                or audit[-1]["previous_sha256"] != state["snapshot_sha256"]
                or value["previous_sha256"] != state["snapshot_sha256"]
            ):
                fail("state and audit journal are inconsistent")
            pending_recovery = True
        else:
            pending_recovery = False

        if state["governance"] not in (ZERO_DIGEST, governance):
            fail("snapshot governance key differs from the persisted key")
        if snapshot_sha256 == state["snapshot_sha256"] and value["epoch"] == state["epoch"]:
            require_tpm_anchor_for_state(root, args, state)
            print(f"release-revocations: IDEMPOTENT epoch={state['epoch']} snapshot={snapshot_sha256}")
            return
        if value["epoch"] < state["epoch"]:
            fail("stale revocation snapshot")
        if value["epoch"] != state["epoch"] + 1:
            fail("revocation snapshot epoch is not the exact successor")
        if value["previous_sha256"] != state["snapshot_sha256"]:
            fail("revocation snapshot previous digest mismatch")
        if not set(state["revoked"]).issubset(value["revoked"]):
            fail("revocation snapshot attempts to remove a revoked fingerprint")
        next_state = {
            "epoch": value["epoch"],
            "governance": governance,
            "revoked": value["revoked"],
            "schema": STATE_SCHEMA,
            "signature": signature_bytes.hex(),
            "snapshot": value,
            "snapshot_sha256": snapshot_sha256,
        }
        advance_tpm_anchor(root, args, state, snapshot_sha256)
        if not pending_recovery:
            append_audit(
                root,
                {
                    "epoch": value["epoch"],
                    "previous_sha256": state["snapshot_sha256"],
                    "snapshot_sha256": snapshot_sha256,
                },
            )
        write_state(root, next_state)
        event = "RECOVERED" if pending_recovery else "ACCEPTED"
        print(
            f"release-revocations: {event} epoch={value['epoch']} "
            f"snapshot={snapshot_sha256} revoked={len(value['revoked'])}"
        )


def export(args: argparse.Namespace) -> None:
    require_anchor_mode(args)
    root = Path(args.state_dir)
    public_key = regular_file(Path(args.governance_public_key), "--governance-public-key")
    with (root / "accept.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
        state = load_state(root)
        verify_state_matches_signature(state, public_key)
        audit = audit_records(root)
        if state["epoch"] != len(audit):
            fail("cannot export an inconsistent revocation state")
        require_tpm_anchor_for_state(root, args, state)
    output = Path(args.output)
    lines = "".join(f"{fingerprint}\n" for fingerprint in state["revoked"])
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(output, lines.encode("ascii"))
    print(f"release-revocations: EXPORTED epoch={state['epoch']} revoked={len(state['revoked'])}")


def status(args: argparse.Namespace) -> None:
    require_anchor_mode(args)
    root = Path(args.state_dir)
    public_key = regular_file(Path(args.governance_public_key), "--governance-public-key")
    with (root / "accept.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
        state = load_state(root)
        verify_state_matches_signature(state, public_key)
        audit = audit_records(root)
        require_tpm_anchor_for_state(root, args, state)
    if state["epoch"] != len(audit):
        fail("revocation state and audit journal are inconsistent")
    print(
        f"release-revocations: STATUS epoch={state['epoch']} "
        f"snapshot={state['snapshot_sha256']} governance={state['governance']} "
        f"revoked={len(state['revoked'])} audit={len(audit)}"
    )


def add_tpm_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--development-software-anchor",
        action="store_true",
        help="test-only fallback; never valid for a production release state",
    )
    parser.add_argument(
        "--tpm-nv-index",
        help="TPM2 NV counter index; enabling this activates the hardware anchor",
    )
    parser.add_argument(
        "--tpm-increment-command",
        default="tpm2_nvincrement",
        help="tpm2-tools nvincrement executable",
    )
    parser.add_argument(
        "--tpm-read-command",
        default="tpm2_nvread",
        help="tpm2-tools nvread executable",
    )
    parser.add_argument(
        "--tpm-auth-handle",
        default="o",
        help="TPM auth handle passed as tpm2-tools -C",
    )
    parser.add_argument(
        "--tpm-auth-password",
        default="",
        help="TPM auth password passed as tpm2-tools -P",
    )
    parser.add_argument(
        "--tpm-command-timeout",
        type=int,
        default=30,
        help="maximum seconds for one tpm2-tools command",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    create_parser = commands.add_parser("create")
    create_parser.add_argument("--private-key", required=True)
    create_parser.add_argument("--output-dir", required=True)
    create_parser.add_argument("--name", required=True)
    create_parser.add_argument("--epoch", type=int, required=True)
    create_parser.add_argument("--previous-sha256", required=True)
    create_parser.add_argument("--revoked", required=True)
    create_parser.set_defaults(run=create)

    accept_parser = commands.add_parser("accept")
    accept_parser.add_argument("--snapshot", required=True)
    accept_parser.add_argument("--signature", required=True)
    accept_parser.add_argument("--governance-public-key", required=True)
    accept_parser.add_argument("--state-dir", required=True)
    add_tpm_arguments(accept_parser)
    accept_parser.set_defaults(run=accept)

    export_parser = commands.add_parser("export")
    export_parser.add_argument("--state-dir", required=True)
    export_parser.add_argument("--governance-public-key", required=True)
    export_parser.add_argument("--output", required=True)
    add_tpm_arguments(export_parser)
    export_parser.set_defaults(run=export)

    status_parser = commands.add_parser("status")
    status_parser.add_argument("--state-dir", required=True)
    status_parser.add_argument("--governance-public-key", required=True)
    add_tpm_arguments(status_parser)
    status_parser.set_defaults(run=status)

    args = parser.parse_args()
    if hasattr(args, "tpm_command_timeout") and not 1 <= args.tpm_command_timeout <= 600:
        fail("--tpm-command-timeout must be between 1 and 600 seconds")
    args.run(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as error:
        fail(str(error))

#!/usr/bin/env python3
"""Append one LC-5 audit event to a content-addressed HTTPS sink."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA = "jasper.remote-audit-upload/v1"
MAX_AUDIT_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 4096
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ZERO_DIGEST = "0" * 64


def fail(message: str) -> None:
    print(f"release-remote-audit: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def regular_file(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"{label} is unavailable: {error}")
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file")
    if metadata.st_size > MAX_AUDIT_BYTES:
        fail(f"{label} exceeds its byte bound")
    return path


def validate_endpoint(value: str, allow_http_local: bool) -> str:
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    scheme_ok = parsed.scheme == "https" or (
        allow_http_local and parsed.scheme == "http" and loopback
    )
    if (
        not scheme_ok
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        fail("endpoint must be HTTPS without credentials, query, or fragment")
    return value.rstrip("/")


def audit_event(path: Path, event_index: int) -> tuple[bytes, dict[str, Any]]:
    path = regular_file(path, "audit journal")
    lines = path.read_bytes().splitlines(keepends=True)
    if not lines or event_index < 1 or event_index > len(lines):
        fail("event index is outside the audit journal")
    previous_epoch = 0
    previous_sha256 = ZERO_DIGEST
    selected: bytes | None = None
    selected_value: dict[str, Any] | None = None
    for index, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"audit journal contains invalid JSON: {error}")
        if canonical(value) != line:
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
        if index == event_index:
            selected = line
            selected_value = value
        previous_epoch = value["epoch"]
        previous_sha256 = value["snapshot_sha256"]
    if selected is None or selected_value is None:
        fail("selected audit event is missing")
    return selected, selected_value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def request(
    method: str,
    url: str,
    body: bytes | None,
    headers: dict[str, str],
    context: ssl.SSLContext,
) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    opener = urllib.request.build_opener(
        NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    try:
        with opener.open(req, timeout=30) as response:
            return response.status, response.read(MAX_AUDIT_BYTES + 1), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(MAX_AUDIT_BYTES + 1), dict(error.headers)
    except (OSError, urllib.error.URLError) as error:
        fail(f"remote audit request failed: {error}")


def atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=path.parent, prefix=f".{path.name}.", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def upload(args: argparse.Namespace) -> None:
    endpoint = validate_endpoint(args.endpoint, args.development_allow_http_local)
    event, value = audit_event(Path(args.audit_journal), args.event_index)
    event_sha256 = digest(event)
    object_url = f"{endpoint}/objects/{event_sha256}"
    context = ssl.create_default_context(cafile=args.ca_file)
    headers = {
        "Content-Type": "application/json",
        "If-None-Match": "*",
        "User-Agent": "jasper-release-audit/1",
    }
    if args.bearer_token_file:
        token_path = regular_file(Path(args.bearer_token_file), "bearer token file")
        token = token_path.read_bytes().rstrip(b"\r\n")
        if not token or len(token) > MAX_TOKEN_BYTES or any(byte < 0x20 for byte in token):
            fail("bearer token is empty, oversized, or contains control bytes")
        headers["Authorization"] = "Bearer " + token.decode("ascii")

    status, _, _ = request("PUT", object_url, event, headers, context)
    if status != 201 and status not in {409, 412}:
        fail(f"remote append returned status {status}; expected 201 or an existing-object conflict")
    get_headers = {"User-Agent": "jasper-release-audit/1"}
    if "Authorization" in headers:
        get_headers["Authorization"] = headers["Authorization"]
    get_status, remote, _ = request("GET", object_url, None, get_headers, context)
    if get_status != 200:
        fail(f"remote audit readback returned status {get_status}")
    if len(remote) > MAX_AUDIT_BYTES or remote != event:
        fail("remote audit object does not exactly match the selected journal event")

    receipt_dir = Path(args.receipt_dir)
    receipt_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = receipt_dir / f"{value['epoch']:020d}.{event_sha256}.json"
    receipt = canonical(
        {
            "endpoint": endpoint,
            "epoch": value["epoch"],
            "event_index": args.event_index,
            "event_sha256": event_sha256,
            "schema": SCHEMA,
            "state": "stored",
        }
    )
    with (receipt_dir / ".lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if receipt_path.exists():
            if receipt_path.is_symlink() or receipt_path.read_bytes() != receipt:
                fail("existing remote-audit receipt conflicts with this event")
            print(
                f"release-remote-audit: IDEMPOTENT epoch={value['epoch']} "
                f"sha256={event_sha256}"
            )
            return
        atomic_write(receipt_path, receipt)
    print(
        f"release-remote-audit: STORED epoch={value['epoch']} "
        f"sha256={event_sha256}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--audit-journal", required=True)
    parser.add_argument("--event-index", type=int, required=True)
    parser.add_argument("--receipt-dir", required=True)
    parser.add_argument("--bearer-token-file")
    parser.add_argument("--ca-file")
    parser.add_argument("--development-allow-http-local", action="store_true")
    args = parser.parse_args()
    if args.development_allow_http_local:
        print("release-remote-audit: development HTTP loopback only", file=sys.stderr)
    upload(args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OSError as error:
        fail(str(error))

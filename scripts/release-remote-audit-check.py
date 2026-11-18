#!/usr/bin/env python3
"""Exercise the content-addressed remote-audit protocol against a loopback sink."""

from __future__ import annotations

import http.server
import subprocess
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release-remote-audit.py"
TOKEN = "test-release-audit-token"


class Sink(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    objects: dict[str, bytes] = {}

    def log_message(self, format: str, *args: object) -> None:
        pass

    def authorized(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    def empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self) -> None:
        if not self.authorized():
            self.empty(401)
            return
        if not self.path.startswith("/objects/"):
            self.empty(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path in self.objects:
            self.empty(412)
            return
        self.objects[self.path] = body
        self.empty(201)

    def do_GET(self) -> None:
        if not self.authorized():
            self.empty(401)
            return
        body = self.objects.get(self.path)
        if body is None:
            self.empty(404)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(SCRIPT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def main() -> int:
    Sink.objects = {}
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    endpoint = f"http://127.0.0.1:{port}"
    try:
        with tempfile.TemporaryDirectory(prefix="jasper-remote-audit-") as temporary:
            root = Path(temporary)
            journal = root / "audit.jsonl"
            journal.write_text(
                '{"epoch":1,"previous_sha256":"'
                + "0" * 64
                + '","snapshot_sha256":"'
                + "1" * 64
                + '"}\n'
                '{"epoch":2,"previous_sha256":"'
                + "1" * 64
                + '","snapshot_sha256":"'
                + "2" * 64
                + '"}\n',
                encoding="ascii",
            )
            token = root / "token"
            token.write_text(TOKEN + "\n", encoding="ascii")
            receipts = root / "receipts"
            common = [
                "--endpoint",
                endpoint,
                "--audit-journal",
                str(journal),
                "--event-index",
                "2",
                "--receipt-dir",
                str(receipts),
                "--bearer-token-file",
                str(token),
                "--development-allow-http-local",
            ]
            first = run(common)
            if first.returncode != 0 or "STORED epoch=2" not in first.stdout:
                raise SystemExit(
                    f"remote-audit-check: first append failed\n{first.stdout}{first.stderr}"
                )
            second = run(common)
            if second.returncode != 0 or "IDEMPOTENT epoch=2" not in second.stdout:
                raise SystemExit(
                    f"remote-audit-check: replay failed\n{second.stdout}{second.stderr}"
                )

            object_path = next(iter(Sink.objects))
            original = Sink.objects[object_path]
            Sink.objects[object_path] = original + b"tampered\n"
            tampered = run(common)
            if tampered.returncode == 0 or "does not exactly match" not in tampered.stderr:
                raise SystemExit("remote-audit-check: remote tamper was accepted")
            Sink.objects[object_path] = original

            no_auth = run(
                [
                    item
                    for item in common
                    if item not in {str(token), "--bearer-token-file"}
                ]
            )
            if no_auth.returncode == 0 or "status 401" not in no_auth.stderr:
                raise SystemExit("remote-audit-check: unauthenticated append was accepted")

            bad_index = run(
                [
                    "9" if item == "2" else item
                    for item in common
                ]
            )
            if bad_index.returncode == 0 or "outside the audit journal" not in bad_index.stderr:
                raise SystemExit("remote-audit-check: out-of-range event was accepted")

            insecure = run(
                [
                    "--endpoint",
                    "http://example.invalid",
                    "--audit-journal",
                    str(journal),
                    "--event-index",
                    "2",
                    "--receipt-dir",
                    str(receipts),
                    "--bearer-token-file",
                    str(token),
                ]
            )
            if insecure.returncode == 0 or "endpoint must be HTTPS" not in insecure.stderr:
                raise SystemExit("remote-audit-check: insecure endpoint was accepted")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    print(
        "release-remote-audit-check: PASS append=true idempotent=true "
        "tamper_rejected=true auth_rejected=true index_rejected=true https_required=true"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

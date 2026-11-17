#!/usr/bin/env python3
"""Exercise two authenticated HTTPS release sources plus one offline copy.

The servers use an ephemeral test CA and bind only to loopback. The client
requires certificate and hostname verification and records a per-source SHA-256
comparison. No production trust key or external network is used.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import shutil
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

BASE_FILES = ("release.manifest.json", "jasper-kernel", "sbom.json")
SIGNATURE_SUFFIX = ".manifest.sig"


def run(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def serve(root: Path, context: ssl.SSLContext):
    handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(  # noqa: E731
        *args, directory=str(root), **kwargs
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def fetch_first(
    client: ssl.SSLContext, urls: list[str]
) -> tuple[bytes, str]:
    errors = []
    for url in urls:
        try:
            with urllib.request.urlopen(url, context=client, timeout=5) as response:
                return response.read(), url
        except (urllib.error.URLError, TimeoutError) as error:
            errors.append(f"{url}: {error}")
    raise RuntimeError("all release sources failed: " + "; ".join(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    source = Path(args.bundle)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    signatures = sorted(source.glob(f"*{SIGNATURE_SUFFIX}"))
    if len(signatures) < 2 or len(signatures) > 8:
        raise SystemExit(
            "release-source-drill: bundle must contain between 2 and 8 threshold signatures"
        )
    files = tuple(BASE_FILES) + tuple(path.name for path in signatures)
    for name in files:
        path = source / name
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"release-source-drill: missing regular bundle file: {path}")

    with tempfile.TemporaryDirectory(prefix="jasper-release-tls-") as temporary:
        temp = Path(temporary)
        ca_key = temp / "ca.key"
        ca_cert = temp / "ca.pem"
        server_key = temp / "server.key"
        server_csr = temp / "server.csr"
        server_cert = temp / "server.pem"
        extensions = temp / "server.ext"
        extensions.write_text(
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n",
            encoding="ascii",
        )
        run(
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(ca_key),
        )
        run(
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-days",
            "1",
            "-subj",
            "/CN=Jasper LC-5 test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        run(
            "openssl",
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(server_key),
        )
        run(
            "openssl",
            "req",
            "-new",
            "-key",
            str(server_key),
            "-out",
            str(server_csr),
            "-subj",
            "/CN=localhost",
        )
        run(
            "openssl",
            "x509",
            "-req",
            "-in",
            str(server_csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(server_cert),
            "-days",
            "1",
            "-extfile",
            str(extensions),
        )

        primary_root = temp / "primary"
        mirror_root = temp / "mirror"
        shutil.copytree(source, primary_root, dirs_exist_ok=True)
        shutil.copytree(source, mirror_root, dirs_exist_ok=True)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(server_cert, server_key)
        primary, primary_thread = serve(primary_root, server_context)
        mirror, mirror_thread = serve(mirror_root, server_context)
        client_context = ssl.create_default_context(cafile=ca_cert)
        client_context.check_hostname = True
        client_context.verify_mode = ssl.CERT_REQUIRED
        primary_base = f"https://127.0.0.1:{primary.server_port}/"
        mirror_base = f"https://127.0.0.1:{mirror.server_port}/"

        for name in files:
            direct = []
            for base in (primary_base, mirror_base):
                with urllib.request.urlopen(
                    base + name, context=client_context, timeout=5
                ) as response:
                    direct.append(response.read())
            if direct[0] != direct[1]:
                raise SystemExit(f"release-source-drill: HTTPS parity failed: {name}")

            # Primary is intentionally unavailable for this object; the mirror
            # must deliver the exact same bytes.
            data, selected = fetch_first(
                client_context,
                [primary_base + "missing/" + name, mirror_base + name],
            )
            offline = (source / name).read_bytes()
            if data != offline:
                raise SystemExit(f"release-source-drill: offline parity failed: {name}")
            (output / name).write_bytes(data)
            print(
                f"release-source-drill: PASS file={name} sha256={sha256(data)} "
                f"source={selected} offline=true"
            )

        primary.shutdown()
        mirror.shutdown()
        primary_thread.join(timeout=5)
        mirror_thread.join(timeout=5)
        primary.server_close()
        mirror.server_close()
    print("release-source-drill: PASS https_sources=2 offline_sources=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

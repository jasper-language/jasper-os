#!/usr/bin/env python3
"""Validate an APK container and manifest with the upstream AOSP aapt2 tool."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path


MAX_APK_BYTES = 512 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED = 1024 * 1024 * 1024


def fail(message: str) -> None:
    print(f"android-apk-preflight: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def run_aapt2(aapt2: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            [str(aapt2), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        fail(f"aapt2 failed: {error}")
    return result.stdout


def one(pattern: str, text: str, what: str) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if match is None:
        fail(f"aapt2 did not report {what}")
    return match.group(1)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--aapt2", required=True, type=Path)
    parser.add_argument("--expected-package", required=True)
    parser.add_argument("--expected-activity", required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()

    apk = args.apk
    aapt2 = args.aapt2
    if not apk.is_file() or not 0 < apk.stat().st_size <= MAX_APK_BYTES:
        fail(f"invalid APK size: {apk}")
    if not aapt2.is_file() or not os.access(aapt2, os.X_OK):
        fail(f"aapt2 is missing or not executable: {aapt2}")

    digest = sha256_file(apk)
    if digest != args.expected_sha256.lower():
        fail(f"APK digest mismatch: expected={args.expected_sha256.lower()} actual={digest}")
    try:
        with zipfile.ZipFile(apk) as archive:
            infos = archive.infolist()
            names = [entry.filename for entry in infos]
            if len(names) != len(set(names)):
                fail("APK contains duplicate ZIP member names")
            if any(entry.flag_bits & 1 for entry in infos):
                fail("encrypted APK entries are unsupported")
            total = sum(entry.file_size for entry in infos)
            if total > MAX_TOTAL_UNCOMPRESSED:
                fail(f"APK expands beyond the bounded limit: {total}")
            required = {"AndroidManifest.xml", "resources.arsc"}
            missing = sorted(required - set(names))
            if missing:
                fail(f"APK is missing required entries: {missing}")
            dex_numbers = []
            for name in names:
                match = re.fullmatch(r"classes(?:(\d+))?[.]dex", name)
                if match is not None:
                    dex_numbers.append(1 if match.group(1) is None else int(match.group(1)))
            dex_numbers.sort()
            if not dex_numbers:
                fail("APK contains no classes*.dex entries")
            if dex_numbers != list(range(1, len(dex_numbers) + 1)):
                fail(f"APK DEX sequence is not contiguous: {dex_numbers}")
            dex = ["classes.dex"] + [
                f"classes{number}.dex" for number in dex_numbers[1:]
            ]
            if archive.testzip() is not None:
                fail("APK ZIP CRC validation failed")
    except (OSError, zipfile.BadZipFile) as error:
        fail(f"invalid APK ZIP container: {error}")

    badging = run_aapt2(aapt2, "dump", "badging", str(apk))
    package = one(r"^package: name='([^']+)'", badging, "package name")
    version_code = one(r"^package: .* versionCode='([^']+)'", badging, "versionCode")
    version_name = one(r"^package: .* versionName='([^']*)'", badging, "versionName")
    min_sdk = one(r"^sdkVersion:'([0-9]+)'", badging, "minSdkVersion")
    target_sdk = one(r"^targetSdkVersion:'([0-9]+)'", badging, "targetSdkVersion")
    activity = one(r"^launchable-activity: name='([^']+)'", badging, "launcher activity")
    if package != args.expected_package:
        fail(f"package mismatch: expected={args.expected_package} actual={package}")
    if activity != args.expected_activity:
        fail(f"launcher mismatch: expected={args.expected_activity} actual={activity}")

    manifest = run_aapt2(aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk))
    if not re.search(r"^\s*E: manifest\b", manifest, re.MULTILINE):
        fail("binary AndroidManifest.xml has no manifest root")
    if not re.search(
        rf'android:name\([^)]*\)="({re.escape(activity)})"', manifest, re.MULTILINE
    ):
        fail("launcher activity is not present in AndroidManifest.xml")

    result = {
        "schema": "android.apk.preflight/1",
        "sha256": digest,
        "bytes": apk.stat().st_size,
        "package": package,
        "version_code": version_code,
        "version_name": version_name,
        "min_sdk": int(min_sdk),
        "target_sdk": int(target_sdk),
        "launcher": activity,
        "dex_entries": dex,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    print(
        "android-apk-preflight: PASS "
        f"package={package} launcher={activity} sdk={min_sdk}/{target_sdk} "
        f"dex={len(dex)} sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

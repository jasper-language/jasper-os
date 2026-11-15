#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${1:-/home/auth/.cache/jasper-abi-runtime-test/android-system-image/art-test-v1/data/local/tmp/app.apk}"
URL="https://github.com/BaseMax/AndroidAutoBuildAPK/releases/download/18/AndroidAutoBuildAPK.apk"
SHA256="22c31a97b1e551d2814df0e9d2f59c5da93f37c9b43e2e03ac0f84c4359c0d05"

mkdir -p "$(dirname "$DEST")"
tmp="$(mktemp "$DEST.download.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
curl -fL --retry 3 -o "$tmp" "$URL"
actual="$(sha256sum "$tmp" | awk '{print $1}')"
if [ "$actual" != "$SHA256" ]; then
  echo "upstream APK checksum mismatch: expected=$SHA256 actual=$actual" >&2
  exit 1
fi
mv "$tmp" "$DEST"
trap - EXIT
printf 'upstream-apk: PASS url=%s sha256=%s bytes=%s dest=%s\n' \
  "$URL" "$actual" "$(stat -c %s "$DEST")" "$DEST"

#!/usr/bin/env bash
# Fetch and verify the unmodified VKD3D-Proton release used by COMPAT-D3D-1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION=3.1
ARCHIVE_NAME="vkd3d-proton-${VERSION}.tar.zst"
ARCHIVE_SHA256="b85ea8219b71093a3924913dd7aae6172333dc0c069983ed510816d67f02120b"
URL="https://github.com/HansKristian-Work/vkd3d-proton/releases/download/v${VERSION}/${ARCHIVE_NAME}"
OUT="${VKD3D_PROTON_TREE:-$ROOT/target/vkd3d-proton-${VERSION}}"
ARCHIVE="${VKD3D_PROTON_ARCHIVE:-$OUT/$ARCHIVE_NAME}"
UNPACK="$OUT/unpack"

mkdir -p "$OUT"
if [ ! -f "$ARCHIVE" ]; then
    curl --fail --location --retry 3 --output "$ARCHIVE" "$URL"
fi
actual_sha256=$(sha256sum "$ARCHIVE" | awk '{ print $1 }')
if [ "$actual_sha256" != "$ARCHIVE_SHA256" ]; then
    echo "prepare-vkd3d-proton-tree: archive digest mismatch: $actual_sha256" >&2
    exit 1
fi

if [ -e "$UNPACK" ]; then
    echo "prepare-vkd3d-proton-tree: refusing to overwrite $UNPACK" >&2
    exit 1
fi
mkdir -p "$UNPACK"
tar --zstd -xf "$ARCHIVE" -C "$UNPACK"

for dll in d3d12.dll d3d12core.dll; do
    path="$UNPACK/vkd3d-proton-${VERSION}/x64/$dll"
    test -f "$path"
    test "$(head -c 2 "$path" | od -An -tx1 | tr -d ' \n')" = "4d5a"
done
test "$(sha256sum "$UNPACK/vkd3d-proton-${VERSION}/x64/d3d12.dll" | awk '{ print $1 }')" = \
    "502694a5fd5e06381ef2cdb33359c5948b6a012938902ddc9e9b381841bc0ce7"
test "$(sha256sum "$UNPACK/vkd3d-proton-${VERSION}/x64/d3d12core.dll" | awk '{ print $1 }')" = \
    "0dfd690a39ef8361ca3b64e9fd8e945b27d2c568dac5dc0dce1a45abf65914cc"

printf 'vkd3d_proton=%s\narchive_sha256=%s\ntree=%s\nverified=true\n' \
    "$VERSION" "$ARCHIVE_SHA256" "$UNPACK/vkd3d-proton-${VERSION}" \
    >"$OUT/summary.txt"
cat "$OUT/summary.txt"

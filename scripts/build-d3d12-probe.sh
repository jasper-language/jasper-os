#!/usr/bin/env bash
# Build the bounded D3D12 offscreen probe used by COMPAT-D3D-1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CC="${X86_64_W64_MINGW32_GCC:-x86_64-w64-mingw32-gcc}"
SOURCE="$ROOT/verification/fixtures/windows/d3d12_probe.c"
OUT="${D3D12_PROBE_OUT:-$ROOT/target/compat-d3d12/d3d12-probe.exe}"

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "build-d3d12-probe: missing $CC (install a bounded x86_64 MinGW toolchain)" >&2
    exit 69
fi
mkdir -p "$(dirname "$OUT")"
"$CC" -O2 -Wall -Wextra -Werror \
    -Wl,--disable-dynamicbase \
    -o "$OUT" "$SOURCE" -ld3d12 -ldxguid -luuid
file "$OUT"
sha256sum "$OUT"

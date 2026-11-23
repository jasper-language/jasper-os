#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_file="$root/verification/fixtures/windows/d3d11_wsi_probe.c"
output="${JASPER_D3D11_WSI_PROBE:-$root/target/windows/d3d11-wsi-probe.exe}"
compiler="${MINGW_CC:-x86_64-w64-mingw32-gcc}"

if [[ "${1:-}" == "--check-source" ]]; then
  python3 "$root/scripts/check-d3d11-wsi-probe.py" --self-test
  exit 0
fi

if ! command -v "$compiler" >/dev/null 2>&1; then
  echo "build-d3d11-wsi-probe: FAIL missing $compiler" >&2
  echo "Install the pinned MinGW x86_64 toolchain or set MINGW_CC." >&2
  exit 69
fi

mkdir -p "$(dirname "$output")"
temporary="$(mktemp "$output.tmp.XXXXXX")"
trap 'rm -f "$temporary"' EXIT

"$compiler" \
  -O2 \
  -Wall \
  -Wextra \
  -Werror \
  -Wl,--disable-dynamicbase,--no-insert-timestamp \
  -o "$temporary" \
  "$source_file" \
  -ld3d11 \
  -ldxgi \
  -lole32 \
  -luuid

python3 "$root/scripts/check-d3d11-wsi-probe.py" --binary "$temporary"
chmod 0755 "$temporary"
mv "$temporary" "$output"
trap - EXIT
echo "build-d3d11-wsi-probe: PASS output=$output"

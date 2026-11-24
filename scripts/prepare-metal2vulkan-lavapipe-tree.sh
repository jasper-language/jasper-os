#!/usr/bin/env bash
# Assemble the unmodified Metal2Vulkan examples over the pinned Mesa lavapipe
# user-space closure already produced by the Wine D3D staging pipeline.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TREE="${1:?usage: $0 OUTPUT_TREE}"
WINE_ROOT="${JASPER_WINE_D3D_ROOT:-${JASPER_ANDROID_TREE:-}}"
METAL="${METAL2VULKAN_DIR:-/home/auth/.cache/jasper-abi-runtime-test/upstream/metal2vulkan-v0.2.0/target/release/examples}"
LLVM_AS="${LLVM_AS:-/home/auth/.cache/jasper-sw64-llvm21/ubuntu-dev/usr/lib/llvm-21/bin/llvm-as}"
RUNTIME_AIR_SOURCE="${RUNTIME_AIR_SOURCE:-/home/auth/.cache/jasper-abi-runtime-test/upstream/metal2vulkan-v0.2.0/crates/metal2vulkan-validation/fixtures/public/examples/runtime_examples.ll}"
LIBDIR="$TREE/usr/lib/x86_64-linux-gnu"
BINDIR="$TREE/usr/bin"

[ -n "$WINE_ROOT" ] || {
  echo "prepare-metal2vulkan-lavapipe: JASPER_WINE_D3D_ROOT is required" >&2
  exit 2
}
[ ! -e "$TREE" ] || {
  echo "prepare-metal2vulkan-lavapipe: output already exists: $TREE" >&2
  exit 2
}

mkdir -p "$LIBDIR" "$BINDIR" "$TREE/sys/devices/system/cpu" "$TREE/proc"

libraries=(
  libvulkan.so.1
  libvulkan_lvp.so
  libLLVM.so.21.1
  libdrm.so.2
  libexpat.so.1
  libdisplay-info.so.3
  libxml2.so.16
  libedit.so.2
  libtinfo.so.6
  libbsd.so.0
  libmd.so.0
  libzstd.so.1
  libz.so.1
  libstdc++.so.6
  libgcc_s.so.1
  libffi.so.8
  libX11-xcb.so.1
  libxcb.so.1
  libxcb-dri3.so.0
  libxcb-present.so.0
  libxcb-randr.so.0
  libxcb-sync.so.1
  libxcb-shm.so.0
  libxcb-xfixes.so.0
  libxshmfence.so.1
  libwayland-client.so.0
  libXau.so.6
  libXdmcp.so.6
)

for library in "${libraries[@]}"; do
  source="$WINE_ROOT/usr/lib/x86_64-linux-gnu/$library"
  [ -f "$source" ] || {
    echo "prepare-metal2vulkan-lavapipe: missing staged library: $source" >&2
    exit 2
  }
  install -m 0755 "$source" "$LIBDIR/$library"
done
install -m 0644 "$WINE_ROOT/usr/lib/x86_64-linux-gnu/lvp_icd.json" "$LIBDIR/lvp_icd.json"

"$LLVM_AS" -o "$LIBDIR/runtime_examples.air" "$RUNTIME_AIR_SOURCE"
cc -nostdlib -fPIE -pie -Wl,-e,_start,--no-dynamic-linker \
  -fno-stack-protector -O2 -Wall -Wextra \
  "$ROOT/verification/fixtures/vulkan/llvm-as-shim.c" -o "$BINDIR/llvm-as"
install -m 0755 "$METAL/compute_dispatch" "$BINDIR/metal2vulkan-compute"
install -m 0755 "$METAL/render_to_texture" "$BINDIR/metal2vulkan-render"
strip --strip-debug --strip-unneeded \
  "$BINDIR/metal2vulkan-compute" \
  "$BINDIR/metal2vulkan-render"

printf '0\n' >"$TREE/sys/devices/system/cpu/online"
printf 'cpu  1 0 1 10000 0 0 0 0 0 0\nintr 0\nctxt 0\nbtime 0\nprocesses 0\nprocs_running 1\nprocs_blocked 0\n' \
  >"$TREE/proc/stat"

(
  cd "$TREE"
  sums=(
    usr/lib/x86_64-linux-gnu/lvp_icd.json
    usr/lib/x86_64-linux-gnu/runtime_examples.air
    usr/bin/llvm-as
    sys/devices/system/cpu/online
    proc/stat
    usr/bin/metal2vulkan-compute
    usr/bin/metal2vulkan-render
  )
  for library in "${libraries[@]}"; do
    sums+=("usr/lib/x86_64-linux-gnu/$library")
  done
  sha256sum "${sums[@]}"
) >"$TREE/SHA256SUMS"
cat "$TREE/SHA256SUMS"

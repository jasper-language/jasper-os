#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHROME="${CHROME_DIR:-/home/auth/.cache/puppeteer/chrome/linux-155.0.8059.79/chrome-linux64}"
METAL="${METAL2VULKAN_DIR:-/home/auth/.cache/jasper-abi-runtime-test/metal2vulkan-release-target/release/examples}"
TREE="${1:-/home/auth/.cache/jasper-abi-runtime-test/vulkan-metal2vulkan-tree}"
LIBDIR="$TREE/usr/lib/x86_64-linux-gnu"
BINDIR="$TREE/usr/bin"
GLIBC_LIBDIR="${VULKAN_GLIBC_LIBDIR:-/usr/lib/x86_64-linux-gnu}"
LLVM_AS="${LLVM_AS:-/home/auth/.cache/jasper-abi-runtime-test/llvm-root/usr/lib/llvm-21/bin/llvm-as}"
RUNTIME_AIR_SOURCE="${RUNTIME_AIR_SOURCE:-/home/auth/.cache/jasper-abi-runtime-test/upstream/metal2vulkan/crates/metal2vulkan-validation/fixtures/public/examples/runtime_examples.ll}"
ONLINE_CPU="${VULKAN_ONLINE_CPU:-0}"

mkdir -p "$LIBDIR" "$BINDIR"
install -m 0755 "$CHROME/libvulkan.so.1" "$LIBDIR/libvulkan.so.1"
install -m 0755 "$CHROME/libvk_swiftshader.so" "$LIBDIR/libvk_swiftshader.so"
install -m 0644 "$ROOT/verification/fixtures/vulkan/vk_swiftshader_icd.json" \
  "$LIBDIR/vk_swiftshader_icd.json"
# Chrome's Vulkan loader and SwiftShader retain DT_NEEDED entries for the
# glibc compatibility DSOs even though current glibc also exports these symbols
# from libc. Supply the unmodified upstream compatibility bytes.
install -m 0755 "$GLIBC_LIBDIR/libdl.so.2" "$LIBDIR/libdl.so.2"
install -m 0755 "$GLIBC_LIBDIR/libpthread.so.0" "$LIBDIR/libpthread.so.0"
"$LLVM_AS" -o "$LIBDIR/runtime_examples.air" "$RUNTIME_AIR_SOURCE"
cc -nostdlib -fPIE -pie -Wl,-e,_start,--no-dynamic-linker \
  -fno-stack-protector -O2 \
  -Wall -Wextra \
  "$ROOT/verification/fixtures/vulkan/llvm-as-shim.c" -o "$BINDIR/llvm-as"
mkdir -p "$TREE/sys/devices/system/cpu" "$TREE/proc"
printf '%s\n' "$ONLINE_CPU" >"$TREE/sys/devices/system/cpu/online"
printf 'cpu  1 0 1 10000 0 0 0 0 0 0\ncpu%s 1 0 1 10000 0 0 0 0 0 0\nintr 0\nctxt 0\nbtime 0\nprocesses 0\nprocs_running 1\nprocs_blocked 0\n' \
  "$ONLINE_CPU" >"$TREE/proc/stat"
printf '[Processor]\nThreadCount=1\n' >"$TREE/SwiftShader.ini"
install -m 0755 "$METAL/compute_dispatch" "$BINDIR/metal2vulkan-compute"
install -m 0755 "$METAL/render_to_texture" "$BINDIR/metal2vulkan-render"
strip --strip-debug --strip-unneeded \
  "$BINDIR/metal2vulkan-compute" \
  "$BINDIR/metal2vulkan-render"

(
  cd "$TREE"
  sha256sum \
    usr/lib/x86_64-linux-gnu/libvulkan.so.1 \
    usr/lib/x86_64-linux-gnu/libvk_swiftshader.so \
    usr/lib/x86_64-linux-gnu/vk_swiftshader_icd.json \
    usr/lib/x86_64-linux-gnu/libdl.so.2 \
    usr/lib/x86_64-linux-gnu/libpthread.so.0 \
    usr/lib/x86_64-linux-gnu/runtime_examples.air \
    usr/bin/llvm-as \
    sys/devices/system/cpu/online \
    proc/stat \
    SwiftShader.ini \
    usr/bin/metal2vulkan-compute \
    usr/bin/metal2vulkan-render
) >"$TREE/SHA256SUMS"
cat "$TREE/SHA256SUMS"

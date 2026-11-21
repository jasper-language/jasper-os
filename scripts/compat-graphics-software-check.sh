#!/usr/bin/env bash
# Exercise the Linux Vulkan loader + software ICD path inside Jasper-OS.
#
# This verifies the software Vulkan loader/ICD and compute dispatch path. It is
# not evidence for render-to-texture/WSI success, a physical GPU, a hardware
# display backend, DXVK/VKD3D execution, reset, DMA silence or IOMMU isolation.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TREE="${JASPER_GRAPHICS_TREE:-${JASPER_ANDROID_TREE:-/home/auth/.cache/jasper-abi-runtime-test/vulkan-metal2vulkan-tree}}"
OUT="${COMPAT_GRAPHICS_OUT:-$ROOT/evidence/compat-graphics-software-$(date '+%Y%m%d-%H%M%S')}"
CHECK_ONLY="${COMPAT_GRAPHICS_CHECK_ONLY:-0}"

required=(
  "$TREE/SHA256SUMS"
  "$TREE/SwiftShader.ini"
  "$TREE/proc/stat"
  "$TREE/sys/devices/system/cpu/online"
  "$TREE/usr/bin/llvm-as"
  "$TREE/usr/bin/metal2vulkan-compute"
  "$TREE/usr/bin/metal2vulkan-render"
  "$TREE/usr/lib/x86_64-linux-gnu/libvulkan.so.1"
  "$TREE/usr/lib/x86_64-linux-gnu/libvk_swiftshader.so"
  "$TREE/usr/lib/x86_64-linux-gnu/vk_swiftshader_icd.json"
  "$TREE/usr/lib/x86_64-linux-gnu/runtime_examples.air"
)
for path in "${required[@]}"; do
  [ -f "$path" ] || {
    echo "compat-graphics-software: missing input $path" >&2
    exit 2
  }
done
for tool in sha256sum grep timeout qemu-system-x86_64; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "compat-graphics-software: missing tool $tool" >&2
    exit 69
  }
done

(
  cd "$TREE"
  sha256sum -c SHA256SUMS
) >"${TMPDIR:-/tmp}/compat-graphics-sha256-$$.log"
sha_log="${TMPDIR:-/tmp}/compat-graphics-sha256-$$.log"
trap 'rm -f "$sha_log"' EXIT
grep -q 'libvulkan.so.1: OK' "$sha_log"
grep -q 'libvk_swiftshader.so: OK' "$sha_log"
grep -q 'vk_swiftshader_icd.json: OK' "$sha_log"
grep -q 'metal2vulkan-compute: OK' "$sha_log"
grep -q 'metal2vulkan-render: OK' "$sha_log"

if [ "$CHECK_ONLY" = 1 ]; then
  echo "compat-graphics-software: ASSETS PASS tree=$TREE sha256=true"
  exit 0
fi

mkdir -p "$OUT"
cp "$TREE/SHA256SUMS" "$OUT/upstream-SHA256SUMS"
export ISSUE21_UEFI_OUT="$OUT"
export ISSUE21_UEFI_MODE=vulkan-swiftshader
export JASPER_ANDROID_TREE="$TREE"
export ISSUE21_QEMU_CPUS="${ISSUE21_QEMU_CPUS:-$("$ROOT/scripts/qemu-cpu-set.sh")}"
export ISSUE21_QEMU_SMP="${ISSUE21_QEMU_SMP:-2}"
export ISSUE21_QEMU_MEMORY="${ISSUE21_QEMU_MEMORY:-2G}"
export ISSUE21_UEFI_TIMEOUT="${ISSUE21_UEFI_TIMEOUT:-240}"
export JASPER_BUILD_CPUS="${JASPER_BUILD_CPUS:-0-1}"

bash "$ROOT/scripts/issue21-uefi-boot-check.sh" | tee "$OUT/wrapper.log"

grep -aq '^output\[0\.\.4\] = \[0\.0, 3\.0, 6\.0, 9\.0\].*as expected' "$OUT/serial.log"
grep -aq 'program=metal2vulkan-compute .*exit_zero=true .*resources=true failed=0' "$OUT/serial.log"
! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"

cat >"$OUT/README.md" <<EOF
# COMPAT-GRAPHICS-1 software Vulkan acceptance

Command:

\`\`\`text
COMPAT_GRAPHICS_OUT=$OUT bash scripts/compat-graphics-software-check.sh
\`\`\`

The Jasper root userland loaded the unmodified Vulkan loader and SwiftShader
ICD, then ran the upstream metal2vulkan compute example. All 1000 output values
matched the upstream expectation and the process returned to the resource
baseline.

This proves the declared software Vulkan path only. It does not prove a physical
GPU backend, metal2vulkan render-to-texture/WSI, hardware display, DXVK/VKD3D
execution, GPU reset, DMA silence, IOMMU isolation or performance. The current
render example reaches the fragment pipeline but faults at
\`ip=0x100086f1909d\` while reading \`0x10006e4ba4f0\`; it remains a diagnosed
pending compatibility bug.
EOF

sha256sum "$OUT/qemu.rc" "$OUT/serial.log" "$OUT/upstream-SHA256SUMS" \
  >"$OUT/artifacts.sha256"
echo "compat-graphics-software: PASS loader=true icd=swiftshader compute=true render=false resources=true hardware_gpu=false evidence=$OUT"

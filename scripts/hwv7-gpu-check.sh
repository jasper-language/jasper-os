#!/usr/bin/env bash
# Focused HWV-7 virtio-gpu acceptance through a real Linux guest.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${HWV7_GPU_OUT:-$ROOT/evidence/hwv7-gpu-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${HWV7_GPU_TARGET:-$ROOT/target/hwv7-gpu}"
LIMIT="${HWV7_GPU_TIMEOUT:-600}"
HEADER="${JSR_LINUX_GUEST_HEADER:?set JSR_LINUX_GUEST_HEADER}"
KERNEL="${JSR_LINUX_GUEST_KERNEL:?set JSR_LINUX_GUEST_KERNEL}"
INITRAMFS="${JSR_LINUX_GUEST_INITRAMFS:?set JSR_LINUX_GUEST_INITRAMFS}"
CPUS="${HWV7_GPU_CPUS:-0-3}"
SMP="${HWV7_GPU_SMP:-4}"
ACCEL="${HWV7_GPU_ACCEL:-kvm}"
CPU_MODEL="${HWV7_GPU_CPU:-host}"
mkdir -p "$OUT" "$TARGET"

cargo build --locked --release --target-dir "$TARGET" -p xtask \
  >"$OUT/xtask-build.log" 2>&1
JSR_LINUX_GUEST_HEADER="$HEADER" \
JSR_LINUX_GUEST_KERNEL="$KERNEL" \
JSR_LINUX_GUEST_INITRAMFS="$INITRAMFS" \
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel \
  --no-default-features --features hwv7-gpu-verify \
  >"$OUT/kernel-build.log" 2>&1
"$TARGET/release/xtask" \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" \
  >"$OUT/image.log" 2>&1

set +e
nice -n 10 taskset -c "$CPUS" timeout "$LIMIT" qemu-system-x86_64 \
  -accel "$ACCEL" \
  -cpu "$CPU_MODEL" \
  -machine q35 \
  -m 512M \
  -smp "$SMP" \
  -drive format=raw,file="$OUT/kernel.img",snapshot=on \
  -device virtio-rng-pci \
  -serial "file:$OUT/serial.log" \
  -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  >"$OUT/qemu.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/qemu.rc"
[ "$rc" -eq 33 ]
grep -aFq '[JSR-HWV5-GPU] device=gpu discovered=true display=true create=true attach=true scanout=true transfer=true flush=true unref=true reset=true ok=true' \
  "$OUT/serial.log"
grep -aEq '\[JSR-HWV4-LINUX\] .*virtio_gpu_resources=[01] virtio_gpu_reset_generation=2 virtio_gpu_commands=[1-9][0-9]* virtio_gpu_created=[2-9][0-9]* virtio_gpu_destroyed=[1-9][0-9]* virtio_gpu_scanouts=[1-9][0-9]* virtio_gpu_transfers=[1-9][0-9]* virtio_gpu_flushes=[1-9][0-9]* .*reclaim=true' \
  "$OUT/serial.log"
grep -aq '^\[JSR-HWV7-GPU\] .*commands=[1-9][0-9]* created=[2-9][0-9]* destroyed=[1-9][0-9]* scanouts=[1-9][0-9]* transfers=[1-9][0-9]* flushes=[1-9][0-9]* rejected=0 resources=[01] reset_generation=2 ok=true' \
  "$OUT/serial.log"
! grep -aqE '^\[JSR-HWV5-GPU\].*ok=false|^\[JSR-HWV5-FAIL\]|^\[JSR-HWV5-VMM-FAIL\]|^\[JSR-PANIC\]|panicked at|KERNEL PANIC' \
  "$OUT/serial.log"

echo "hwv7-gpu: PASS evidence=$OUT"

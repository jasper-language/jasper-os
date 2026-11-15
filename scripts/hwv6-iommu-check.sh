#!/usr/bin/env bash
# Focused HWV-6 acceptance on QEMU's Intel VT-d model.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${HWV6_IOMMU_OUT:-$ROOT/evidence/hwv6-iommu-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${HWV6_IOMMU_TARGET:-$ROOT/target/hwv6-iommu}"
LIMIT="${HWV6_IOMMU_TIMEOUT:-300}"
CPUS="${HWV6_IOMMU_CPUS:-0}"
mkdir -p "$OUT" "$TARGET"

cargo build --locked --release --target-dir "$TARGET" -p xtask \
  >"$OUT/xtask-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel \
  --no-default-features --features hwv6-verify >"$OUT/kernel-build.log" 2>&1
"$TARGET/release/xtask" \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" \
  >"$OUT/image.log" 2>&1

set +e
nice -n 10 taskset -c "$CPUS" timeout "$LIMIT" qemu-system-x86_64 \
  -accel kvm \
  -machine q35,kernel-irqchip=split \
  -cpu host \
  -m 512M \
  -smp 4 \
  -device intel-iommu,intremap=on,eim=off,caching-mode=on,device-iotlb=on \
  -device rtl8139 \
  -device rtl8139 \
  -device virtio-rng-pci \
  -drive format=raw,file="$OUT/kernel.img",snapshot=on \
  -serial "file:$OUT/serial.log" \
  -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  >"$OUT/qemu.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/qemu.rc"
[ "$rc" -eq 33 ]
sync -f "$OUT/serial.log"
grep -aq '^\[JSR-HWV6\] backend=qemu-intel-iommu dmar=true .* translation=true faults=2 ir=true reset=true resources=true failed=0' \
  "$OUT/serial.log"
grep -aq '^\[JSR-HWV6-DMA-FAULT\].*phase=unbind ok=true' "$OUT/serial.log"
grep -aq '^\[JSR-HWV6-DMA-FAULT\].*phase=unbound ok=true' "$OUT/serial.log"
grep -aq '^\[JSR-HWV6-IR\].*remapped=true compatibility_blocked=true ok=true' \
  "$OUT/serial.log"
grep -aq '^\[JSR-HWV6-LIFECYCLE\] exclusive=true authorized=true denied=true revoked=true old_dma=false irq_clean=true resources=true' \
  "$OUT/serial.log"
! grep -aqE '^\[JSR-HWV6-FAIL\]|^\[JSR-PANIC\]|panicked at|KERNEL PANIC' \
  "$OUT/serial.log"

echo "hwv6-iommu: PASS evidence=$OUT"

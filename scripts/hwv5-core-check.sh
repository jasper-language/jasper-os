#!/usr/bin/env bash
# Focused HWV-5-CORE acceptance on host KVM with a real nested Linux guest.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${HWV5_CORE_OUT:-$ROOT/evidence/hwv5-core-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${HWV5_CORE_TARGET:-$ROOT/target/hwv5-core}"
LIMIT="${HWV5_CORE_TIMEOUT:-300}"
HEADER="${JSR_LINUX_GUEST_HEADER:?set JSR_LINUX_GUEST_HEADER}"
KERNEL="${JSR_LINUX_GUEST_KERNEL:?set JSR_LINUX_GUEST_KERNEL}"
CPUS="${HWV5_CORE_CPUS:-4-11}"
SMP="${HWV5_CORE_SMP:-4}"
ACCEL="${HWV5_CORE_ACCEL:-kvm}"
CPU_MODEL="${HWV5_CORE_CPU:-host}"
mkdir -p "$OUT" "$TARGET"

cargo build --locked --release --target-dir "$TARGET" -p xtask \
  >"$OUT/xtask-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel \
  --no-default-features --features hwv5-verify >"$OUT/kernel-build.log" 2>&1
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
grep -aq '\[JSR-HWV5\] backend=Vmx bus=mmio devices=rng,console,block linux=true vmm=true policy=true policy_allowed=[1-9][0-9]* policy_denied=[1-9][0-9]* policy_overflow=0 failed=0' \
  "$OUT/serial.log"
grep -aFq '[JSR-HWV4-LINUX] linux=true' "$OUT/serial.log"
grep -aEq 'virtio_rng_requests=[1-9][0-9]*' "$OUT/serial.log"
grep -aEq 'virtio_console_bytes=[1-9][0-9]*' "$OUT/serial.log"
grep -aEq 'virtio_block_requests=[1-9][0-9]*' "$OUT/serial.log"
grep -aFq 'reclaim=true' "$OUT/serial.log"
grep -aq '\[JSR-HWV5-PIO\] device=jpio discovered=true ping=true reset=true pending=true cancel=true generation=2 writes=0 ok=true' \
  "$OUT/serial.log"
grep -aq '\[JSR-HWV5-PIO\] backend=Vmx transport=pio decoded=true routed=true probe=true reset=true pending=true cancel=true failure_atomic=true resource=true failed=0' \
  "$OUT/serial.log"
grep -aq '\[JSR-HWV5-NET\] device=net discovered=true link=true tx=true rx=true arp=true ok=true' \
  "$OUT/serial.log"
grep -aq '\[JSR-HWV5-FS\] device=fs discovered=true mount=true lookup=true read=true write=true ok=true' \
  "$OUT/serial.log"
grep -aqE '\[JSR-HWV4-LINUX\] .*virtio_net_tx_frames=[1-9][0-9]* virtio_net_rx_frames=[1-9][0-9]* .*virtio_fs_requests=[1-9][0-9]* .*pio_marker=true marker=true .*reclaim=true' \
  "$OUT/serial.log"
! grep -aqE '^\[JSR-HWV5-FAIL\]|^\[JSR-HWV5-VMM-FAIL\]|^\[JSR-PANIC\]|panicked at|KERNEL PANIC' \
  "$OUT/serial.log"

echo "hwv5-core: PASS evidence=$OUT"

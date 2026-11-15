#!/usr/bin/env bash
# Run the focused Intel VMX Host/Guest XState acceptance without unrelated host suites.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${HWV2_XSTATE_OUT:-$ROOT/evidence/hwv2-xstate-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${HWV2_XSTATE_TARGET:-$ROOT/target/hwv2-xstate}"
LIMIT="${HWV2_XSTATE_TIMEOUT:-300}"
ACCEL="${HWV2_XSTATE_ACCEL:-tcg}"
CPU_MODEL="${HWV2_XSTATE_CPU:-max,+vmx}"
mkdir -p "$OUT" "$TARGET"

cargo build --locked --release --target-dir "$TARGET" -p xtask \
  >"$OUT/xtask-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel \
  --no-default-features --features hwv2-verify >"$OUT/kernel-build.log" 2>&1
"$TARGET/release/xtask" \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" \
  >"$OUT/image.log" 2>&1

set +e
nice -n 10 taskset -c 0 timeout "$LIMIT" qemu-system-x86_64 \
  -accel "$ACCEL" \
  -machine q35 \
  -cpu "$CPU_MODEL" \
  -m 512M \
  -smp 1 \
  -drive format=raw,file="$OUT/kernel.img",snapshot=on \
  -serial "file:$OUT/serial.log" \
  -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/qemu.rc"
[ "$rc" -eq 33 ]
for _ in $(seq 1 50); do
  grep -aq '^\[JSR-HWV2\] backend=Vmx entered=true ' "$OUT/serial.log" && break
  sleep 0.1
done
sync -f "$OUT/serial.log"
grep -aFq '[JSR-HWV2] backend=Vmx entered=true vmxoff=true vmcs=true ept=true cpuid=1 rdtsc=1 msr=1 io=1 ept_exit=1 exception=1 exits=6 tsc=true xsave=true state_saved=true failed=0' \
  "$OUT/serial.log"
grep -aFq '[JSR-HWV2-XSTATE] host_xcr0=0x7 guest_xcr0=0x3 invalid_rejected=4 host_restored=true failed=0' \
  "$OUT/serial.log"
! grep -aqE '^\[JSR-HWV2-FAIL\]|^\[JSR-PANIC\]|panicked at|KERNEL PANIC' \
  "$OUT/serial.log"

echo "hwv2-xstate: PASS evidence=$OUT"

#!/usr/bin/env bash
# Focused ACPI/MADT -> IOAPIC discovery and device-route acceptance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${IOAPIC_ROUTE_OUT:-$ROOT/evidence/ioapic-route-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${IOAPIC_ROUTE_TARGET:-$ROOT/target/ioapic-route}"
LIMIT="${IOAPIC_ROUTE_TIMEOUT:-360}"
CPUS="${IOAPIC_ROUTE_CPUS:-4-7}"
SMP="${IOAPIC_ROUTE_SMP:-4}"
mkdir -p "$OUT" "$TARGET"

cargo build --locked --release --target-dir "$TARGET" -p xtask \
  >"$OUT/xtask-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel --no-default-features \
  >"$OUT/kernel-build.log" 2>&1
"$TARGET/release/xtask" \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" \
  >"$OUT/image.log" 2>&1

exec 9>/tmp/jasper-os-qemu.lock
flock 9
nice -n 10 taskset -c "$CPUS" qemu-system-x86_64 \
  -accel tcg -icount shift=5,sleep=off \
  -cpu max -machine q35 -m 512M -smp "$SMP" \
  -drive format=raw,file="$OUT/kernel.img",snapshot=on \
  -serial "file:$OUT/serial.log" \
  -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  >"$OUT/qemu.log" 2>&1 &
QPID=$!

cleanup() {
    kill -TERM "$QPID" 2>/dev/null || true
    wait "$QPID" 2>/dev/null || true
}
trap cleanup EXIT

deadline=$((SECONDS + LIMIT))
while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -aq '^\[JSR-SMP3\] case=route ' "$OUT/serial.log" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$QPID" 2>/dev/null; then
        break
    fi
    sleep 0.5
done
cleanup
trap - EXIT
flock -u 9
exec 9>&-

grep -aEq '^\[JSR-IOAPIC\] controllers=[1-9][0-9]* pins=[1-9][0-9]* exposed=2 unsupported=[0-9]+ invalid=0 dropped=0' \
  "$OUT/serial.log"
grep -aFq '[JSR-IOAPIC] line=0 name=serial ' "$OUT/serial.log"
grep -aFq '[JSR-IOAPIC] line=1 name=rtc ' "$OUT/serial.log"
grep -aFq "[JSR-SMP3] case=route cpus=$SMP lines=2 delivered_exact=$SMP/$SMP handler_calls_match=true disabled_after=true" \
  "$OUT/serial.log"

echo "ioapic-route: PASS evidence=$OUT"

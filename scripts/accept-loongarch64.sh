#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
: "${JASPER_CORES:=4-11}"
: "${JASPER_SMP:=4}"
: "${JASPER_QEMU_TIMEOUT:=180}"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target-loongarch}"
OUT="$ROOT/evidence/accept-loongarch64-$(date '+%Y%m%d-%H%M%S')"
KERNEL="$TARGET_DIR/loongarch64-unknown-none-softfloat/release/jasper-kernel"
QEMU="${JASPER_QEMU:-qemu-system-loongarch64}"

mkdir -p "$OUT"
cd "$ROOT"

{
    echo "time=$(date --iso-8601=seconds)"
    echo "target=loongarch64-unknown-none-softfloat"
    echo "smp=$JASPER_SMP"
    echo "cpu_affinity=$JASPER_CORES"
    "$QEMU" --version | head -1
    rustc -Vv
} > "$OUT/environment.txt"

CARGO_TARGET_DIR="$TARGET_DIR" \
    cargo build -p jasper-kernel \
        --target loongarch64-unknown-none-softfloat \
        --no-default-features --release 2>&1 | tee "$OUT/build.log"

readelf -h "$KERNEL" | grep -E 'Class:|Machine:|Entry point' | tee "$OUT/elf.txt"

set +e
flock /tmp/jasper-os-qemu.lock \
    taskset -c "$JASPER_CORES" \
    timeout -s KILL "$JASPER_QEMU_TIMEOUT" \
    "$QEMU" -M virt -cpu la464 -smp "$JASPER_SMP" -m 128M \
        -kernel "$KERNEL" -serial file:"$OUT/serial.log" \
        -display none -monitor none -no-reboot \
        >"$OUT/qemu.stdout" 2>"$OUT/qemu.stderr"
RC=$?
set -e

grep -a -q '^\[JSR-BOOT\].*loongarch64' "$OUT/serial.log"
grep -a -q '^\[JSR-VEC\] ok' "$OUT/serial.log"
grep -a -q '^\[JSR-TICK\] n=25' "$OUT/serial.log"
grep -a -q '^\[JSR-EXIT\] success' "$OUT/serial.log"
if [ "$JASPER_SMP" -gt 1 ]; then
    grep -a -q "present=$JASPER_SMP online=$JASPER_SMP failed=0" "$OUT/serial.log"
fi
grep -a -q '^\[JSR-EXIT-CODE\] code=33' "$OUT/serial.log"

echo "accept-loongarch64: PASS"
echo "evidence: $OUT"
echo "qemu_timeout_rc=$RC"

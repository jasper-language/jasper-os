#!/usr/bin/env bash
# Dedicated 4/8-vCPU guest for Ubuntu dynamic-libc execution on APs.
# 专用 4/8 vCPU 客机：验证动态 libc、FXSAVE/FS_BASE 在应用处理器上可用。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"
exec 9>/tmp/jasper-os-qemu.lock
flock 9

OUT="${COMPAT_DYNAMIC_SMP_OUT:-$ROOT/evidence/compat-dynamic-smp-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${COMPAT_DYNAMIC_SMP_TARGET:-$ROOT/target/compat-dynamic-smp}"
CORES="${JASPER_CORES:-0-7}"
TIMEOUT="${COMPAT_DYNAMIC_SMP_TIMEOUT:-300}"
mkdir -p "$OUT"

CARGO_TARGET_DIR="$TARGET" taskset -c "$CORES" cargo build --locked --release --target x86_64-unknown-none \
  -p jasper-kernel --features compat-dynamic-libc-verify >"$OUT/build-kernel.log" 2>&1
taskset -c "$CORES" cargo build --locked --release -p xtask >"$OUT/build-xtask.log" 2>&1
target/release/xtask "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" \
  >"$OUT/image.log" 2>&1
truncate -s 1M "$OUT/blank.img"

for cpus in 4 8; do
  serial="$OUT/serial-$cpus.log"
  set +e
  taskset -c "$CORES" timeout "$TIMEOUT" qemu-system-x86_64 \
    -accel tcg \
    -drive format=raw,file="$OUT/kernel.img" \
    -device virtio-rng-pci \
    -device virtio-blk-pci,drive=d1 \
    -drive if=none,id=d1,file="$OUT/blank.img",format=raw \
    -serial "file:$serial" -display none -monitor none -no-reboot -m 256M \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 -smp "$cpus"
  rc=$?
  set -e
  printf '%s\n' "$rc" >"$OUT/rc-$cpus"
  [ "$rc" -eq 33 ] || {
    echo "compat-dynamic-smp: cpus=$cpus QEMU rc=$rc, expected 33" >&2
    tail -n 40 "$serial" >&2
    exit 1
  }
  grep -qE "^\\[JSR-SMP\\] start present=$cpus online=$cpus failed=0" "$serial" || {
    echo "compat-dynamic-smp: cpus=$cpus did not bring every AP online" >&2
    exit 1
  }
  grep -qE '^\[JSR-COMPAT-DYNAMIC\] .*exit_zero=true .*resources=true failed=0' "$serial" || {
    echo "compat-dynamic-smp: cpus=$cpus lacks dynamic-libc success evidence" >&2
    exit 1
  }
  grep -qE '^\[JSR-COMPAT-DYNAMIC-GETCONF\] .*exit_zero=true .*resources=true failed=0' "$serial" || {
    echo "compat-dynamic-smp: cpus=$cpus lacks getconf success evidence" >&2
    exit 1
  }
  grep -q '^\[JSR-COMPAT-DYNAMIC-SUMMARY\] true=true getconf=true resources=true failed=0' "$serial" || {
    echo "compat-dynamic-smp: cpus=$cpus lacks combined dynamic summary" >&2
    exit 1
  }
  ! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$serial" || {
    echo "compat-dynamic-smp: cpus=$cpus contains a panic/failure marker" >&2
    exit 1
  }
done

# The AP SSE enablement plus FXSAVE/FS_BASE switching is exercised by every
# secondary CPU entering scheduling before the dynamic guest completes.
echo "compat-dynamic-smp: PASS cpus=4,8 evidence=$OUT"

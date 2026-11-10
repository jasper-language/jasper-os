#!/usr/bin/env bash
# Run the unmodified Ubuntu glibc pthread create/join/mutex/condvar fixture.
# 运行未修改的 Ubuntu glibc pthread create/join/mutex/condvar fixture。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${COMPAT_PTHREAD_OUT:-$ROOT/evidence/compat-pthread-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${COMPAT_PTHREAD_TARGET:-$ROOT/target/compat-pthread}"
CPUS="${COMPAT_PTHREAD_CPUS:-1}"
TIMEOUT="${COMPAT_PTHREAD_TIMEOUT:-180}"
mkdir -p "$OUT" "$TARGET"

gcc -O2 -pthread verification/fixtures/linux/pthread_basic.c \
  -o "$TARGET/pthread-basic" >"$OUT/fixture-build.log" 2>&1
export JSR_UBUNTU_PTHREAD="$TARGET/pthread-basic"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none \
  -p jasper-kernel --features compat-pthread-verify >"$OUT/kernel-build.log" 2>&1
cargo build --locked --release -p xtask >"$OUT/xtask-build.log" 2>&1
target/release/xtask "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" \
  >"$OUT/image.log" 2>&1

set +e
timeout "$TIMEOUT" qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -m 512M \
  -smp "$CPUS" \
  -drive format=raw,file="$OUT/kernel.img" \
  -serial "file:$OUT/serial.log" \
  -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/qemu.rc"
[ "$rc" -eq 33 ]
grep -aq '^jasper-pthread-ok' "$OUT/serial.log"
grep -aqE '^\[JSR-COMPAT-PTHREAD\] .*exit_zero=true .*resources=true failed=0' \
  "$OUT/serial.log"
! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL|LINUX-ABI-FAIL)\]|panicked at|KERNEL PANIC' \
  "$OUT/serial.log"

echo "compat-pthread: PASS cpus=$CPUS evidence=$OUT"

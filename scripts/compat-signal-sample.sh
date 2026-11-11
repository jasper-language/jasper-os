#!/usr/bin/env bash
# Run an unmodified Ubuntu glibc signal handler and rt_sigreturn fixture.
# 运行未修改的 Ubuntu glibc 信号处理器与 rt_sigreturn fixture。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${COMPAT_SIGNAL_OUT:-$ROOT/evidence/compat-signal-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${COMPAT_SIGNAL_TARGET:-$ROOT/target/compat-signal}"
TIMEOUT="${COMPAT_SIGNAL_TIMEOUT:-180}"
CPUS="${COMPAT_SIGNAL_CPUS:-1}"
mkdir -p "$OUT" "$TARGET"

gcc -O2 -pthread -fno-stack-protector \
  verification/fixtures/linux/signal_basic.c \
  -o "$TARGET/signal-basic" >"$OUT/fixture-build.log" 2>&1
export JSR_UBUNTU_SIGNAL="$TARGET/signal-basic"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none \
  -p jasper-kernel --features compat-signal-verify >"$OUT/kernel-build.log" 2>&1
cargo build --locked --release -p xtask >"$OUT/xtask-build.log" 2>&1
target/release/xtask "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" \
  >"$OUT/image.log" 2>&1

set +e
timeout "$TIMEOUT" qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -cpu max \
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
grep -aq '^jasper-signal-ok' "$OUT/serial.log"
grep -aq '^jasper-fpu-ok' "$OUT/serial.log"
grep -aq '^\[JSR-COMPAT-SIGNAL\] .*exit_zero=true .*resources=true failed=0' \
  "$OUT/serial.log"
! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL|LINUX-ABI-FAIL)\]|panicked at|KERNEL PANIC' \
  "$OUT/serial.log"

echo "compat-signal: PASS cpus=$CPUS evidence=$OUT"

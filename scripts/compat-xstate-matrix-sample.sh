#!/usr/bin/env bash
# Verify YMM0-YMM15 across scheduling and migration on 1/2/4/8 vCPUs.
# 在 1/2/4/8 vCPU 上验证 YMM0-YMM15 的调度与迁移保持。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${COMPAT_XSTATE_OUT:-$ROOT/evidence/compat-xstate-matrix-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${COMPAT_XSTATE_TARGET:-$ROOT/target/compat-xstate-matrix}"
LIMIT="${COMPAT_XSTATE_TIMEOUT:-300}"
CPU_LIST="${COMPAT_XSTATE_CPUS:-1 2 4 8}"
mkdir -p "$OUT" "$TARGET"

exec 9>/tmp/jasper-os-xstate-matrix.lock
if ! flock -w 900 9; then
  echo "FAIL XState matrix QEMU lock busy for 900s" >&2
  exit 75
fi

gcc -O2 -mavx -pthread -fcf-protection=none -fno-stack-protector \
  verification/fixtures/linux/xstate_threads.c \
  -o "$TARGET/xstate-matrix" >"$OUT/fixture-build.log" 2>&1
export JSR_UBUNTU_XSTATE_MATRIX="$TARGET/xstate-matrix"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel \
  --features compat-xstate-matrix-verify >"$OUT/kernel-build.log" 2>&1
cargo build --locked --release -p xtask >"$OUT/xtask-build.log" 2>&1
target/release/xtask \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" \
  >"$OUT/image.log" 2>&1

for cpus in $CPU_LIST; do
  serial="$OUT/serial-$cpus.log"
  rc_file="$OUT/qemu-$cpus.rc"
  set +e
  nice -n 10 taskset -c "0-$((cpus - 1))" timeout "$LIMIT" qemu-system-x86_64 \
    -accel tcg \
    -machine q35 \
    -cpu max \
    -m 512M \
    -smp "$cpus" \
    -drive format=raw,file="$OUT/kernel.img",snapshot=on \
    -serial "file:$serial" \
    -display none -monitor none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
  rc=$?
  set -e
  printf '%s\n' "$rc" >"$rc_file"
  [ "$rc" -eq 33 ]
  grep -aq "^jasper-xstate-matrix-ok workers=4 cpus=$cpus " "$serial"
  grep -aq '^\[JSR-COMPAT-XSTATE-MATRIX\] .*exit_zero=true .*resources=true failed=0' \
    "$serial"
  ! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL|LINUX-ABI-FAIL)\]|panicked at|KERNEL PANIC' \
    "$serial"
done

echo "compat-xstate-matrix: PASS cpus=[$CPU_LIST] evidence=$OUT"

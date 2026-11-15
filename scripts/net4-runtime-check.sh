#!/usr/bin/env bash
# Focused NET-4 runtime acceptance: real virtio-net frame -> UDP socket/WireGuard path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${NET4_RUNTIME_OUT:-$ROOT/evidence/net4-runtime-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${NET4_RUNTIME_TARGET:-$ROOT/target/net4-runtime}"
LIMIT="${NET4_RUNTIME_TIMEOUT:-300}"
mkdir -p "$OUT" "$TARGET"

cargo build --locked --release --target-dir "$TARGET" -p xtask \
  >"$OUT/xtask-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel \
  --no-default-features --features net4-runtime-verify >"$OUT/kernel-build.log" 2>&1
"$TARGET/release/xtask" \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$OUT/kernel.img" \
  >"$OUT/image.log" 2>&1

set +e
nice -n 10 taskset -c 0 timeout "$LIMIT" qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -cpu max \
  -m 256M \
  -smp 1 \
  -drive format=raw,file="$OUT/kernel.img",snapshot=on \
  -device virtio-rng-pci \
  -device virtio-net-pci,netdev=n0 \
  -netdev user,id=n0 \
  -serial "file:$OUT/serial.log" \
  -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/qemu.rc"
[ "$rc" -eq 33 ]
grep -aq '^\[JSR-NET4-RUNTIME\] wire=true udp=true socket=true quota=true generation=true echo=true service=true wireguard=true reset=true resources=true failed=0' \
  "$OUT/serial.log"
! grep -aqE '^\[JSR-NET4-RUNTIME-FAIL\]|^\[JSR-PANIC\]|panicked at|KERNEL PANIC' \
  "$OUT/serial.log"

echo "net4-runtime: PASS evidence=$OUT"

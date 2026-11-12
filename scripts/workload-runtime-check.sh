#!/usr/bin/env bash
# Reproduce the native Workload runtime quota and cleanup acceptance twice.
# 连续两次验收原生 Workload 的运行时配额与清理路径。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${WORKLOAD_OUT:-$ROOT/evidence/workload-runtime-$(date '+%Y%m%d-%H%M%S')}"
CARGO_TARGET="${WORKLOAD_CARGO_TARGET:-$ROOT/target}"
IMAGE="${WORKLOAD_IMAGE:-$ROOT/target/workload-runtime.img}"
LIMIT="${WORKLOAD_QEMU_TIMEOUT:-90}"
QEMU_CPUS="${WORKLOAD_QEMU_CPUS:-0-1}"
mkdir -p "$OUT"

# Serialize the complete build-and-run sequence with all other Jasper VM users.
exec 9>/tmp/jasper-os-qemu.lock
if ! flock -w 900 9; then
  echo "FAIL Jasper QEMU lock busy for 900s" >&2
  exit 75
fi

cleanup() {
  rm -f -- "$IMAGE"
}
trap cleanup EXIT

free_kib=$(df -Pk "$OUT" | awk 'NR == 2 { print $4 }')
[ "${free_kib:-0}" -ge 12582912 ] || {
    echo "FAIL less than 12 GiB free for Workload image" >&2
  exit 75
}
available_kib=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
[ "${available_kib:-0}" -ge 2097152 ] || {
  echo "FAIL less than 2 GiB host memory available" >&2
  exit 75
}
load1=$(awk '{ print $1 }' /proc/loadavg)
awk -v load="$load1" 'BEGIN { exit !(load <= 8.0) }' || {
  echo "FAIL host one-minute load $load1 is too high" >&2
  exit 75
}
runtime_active() {
  local comm
  for comm in /proc/[0-9]*/comm; do
    [ -r "$comm" ] || continue
    IFS= read -r name <"$comm" 2>/dev/null || continue
    case "$name" in
      qemu-system*|VBoxHeadless) return 0 ;;
    esac
  done
  return 1
}
if runtime_active; then
    echo "FAIL another QEMU/VBox workload is already running" >&2
  exit 75
fi

env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" \
    build --locked --release --target-dir "$CARGO_TARGET" -p xtask \
  >"$OUT/build.log" 2>&1
env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" \
    build --locked --release --target-dir "$CARGO_TARGET" \
    --target x86_64-unknown-none -p jasper-kernel --features workload-verify \
    >>"$OUT/build.log" 2>&1
"$CARGO_TARGET/release/xtask" \
  "$CARGO_TARGET/x86_64-unknown-none/release/jasper-kernel" "$IMAGE" \
  >"$OUT/image.log" 2>&1
test -s "$IMAGE"

for round in 1 2; do
  serial="$OUT/round-$round.serial"
  rc_file="$OUT/round-$round.rc"
  set +e
  nice -n 15 taskset -c "$QEMU_CPUS" \
    timeout "$LIMIT" qemu-system-x86_64 \
      -accel tcg -icount shift=5 \
      -drive format=raw,file="$IMAGE" \
      -smp 1 -m 512M -serial stdio -display none -monitor none -no-reboot \
      -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
      >"$serial" 2>&1
  rc=$?
  set -e
  printf '%s\n' "$rc" >"$rc_file"
  [ "$rc" -eq 33 ]
  grep -aq '^\[JSR-WORKLOAD\] runtime=true checks_failed=0 ' "$serial"
  ! grep -aqE '^\[JSR-(PANIC|LINUX-ABI-FAIL)\]|KERNEL PANIC|panicked at' "$serial"
done

echo "workload-runtime: PASS rounds=2 evidence=$OUT"

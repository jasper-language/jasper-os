#!/usr/bin/env bash
# Verify LC-1 diagnostics and installation state across two real boots.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="${LIFECYCLE_DIAG_OUT:-$ROOT/evidence/lifecycle-diagnostic-block-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${LIFECYCLE_DIAG_TARGET:-$ROOT/target/lifecycle-diagnostic-block}"
BOOT_IMAGE="$TARGET/boot.img"
DATA_IMAGE="$TARGET/data.img"
LIMIT="${LIFECYCLE_DIAG_TIMEOUT:-90}"
QEMU_CPUS="${LIFECYCLE_DIAG_QEMU_CPUS:-0-1}"
mkdir -p "$OUT" "$TARGET"

exec 9>/tmp/jasper-os-qemu.lock
if ! flock -w 900 9; then
  echo "FAIL Jasper QEMU lock busy for 900s" >&2
  exit 75
fi

cleanup() {
  rm -f -- "$BOOT_IMAGE" "$DATA_IMAGE"
}
trap cleanup EXIT

free_kib=$(df -Pk "$TARGET" | awk 'NR == 2 { print $4 }')
[ "${free_kib:-0}" -ge 12582912 ] || {
  echo "FAIL less than 12 GiB free for lifecycle diagnostic images" >&2
  exit 75
}
available_kib=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
[ "${available_kib:-0}" -ge 2097152 ] || {
  echo "FAIL less than 2 GiB host memory available" >&2
  exit 75
}
runtime_active() {
  local comm name
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

rm -f -- "$BOOT_IMAGE" "$DATA_IMAGE"
truncate -s 16M "$DATA_IMAGE"

"$ROOT/scripts/guarded-cargo.sh" build --locked --release \
  --target-dir "$TARGET" -p xtask >"$OUT/build.log" 2>&1
env -u CARGO_TARGET_DIR "$ROOT/scripts/guarded-cargo.sh" build --locked --release \
  --target-dir "$TARGET" --target x86_64-unknown-none -p jasper-kernel \
  --no-default-features --features lifecycle-diagnostic-block-verify \
  >>"$OUT/build.log" 2>&1
"$TARGET/release/xtask" \
  "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$BOOT_IMAGE" \
  >"$OUT/image.log" 2>&1
test -s "$BOOT_IMAGE"

for round in 1 2; do
  serial="$OUT/round-$round.serial"
  rc_file="$OUT/round-$round.rc"
  set +e
  nice -n 15 taskset -c "$QEMU_CPUS" timeout "$LIMIT" qemu-system-x86_64 \
    -accel tcg -icount shift=5 \
    -drive format=raw,file="$BOOT_IMAGE" \
    -drive format=raw,file="$DATA_IMAGE",if=virtio \
    -smp 1 -m 512M -serial stdio -display none -monitor none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    >"$serial" 2>&1
  rc=$?
  set -e
  printf '%s\n' "$rc" >"$rc_file"
  [ "$rc" -eq 33 ]
  grep -aq '^\[JSR-LIFE-DIAG\] summary failed=0 resources=true' "$serial"
  ! grep -aqE '^\[JSR-(PANIC|LIFE-DIAG-FAIL)\]|KERNEL PANIC|panicked at' "$serial"
done

grep -aq '^\[JSR-LIFE-DIAG\] stage=format events=3 sequence=4 query=2 privacy=true append=true failed=0' \
  "$OUT/round-1.serial"
grep -aq '^\[JSR-LIFE-DIAG\] stage=reopen events=4 sequence=5 query=2 privacy=true append=true failed=0' \
  "$OUT/round-2.serial"

echo "lifecycle-diagnostic-block: PASS rounds=2 evidence=$OUT"

#!/usr/bin/env bash
# FS-0: commit a journal checkpoint, kill QEMU, then recover the same disk.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"
exec 9>/tmp/jasper-os-qemu.lock
flock 9

CORES="${FS0_CORES:-4-11}"
OUT="${FS0_OUT:-$ROOT/evidence/fs0-powercut-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${FS0_TARGET:-$ROOT/target/fs0-powercut}"
XTASK="${FS0_XTASK:-$ROOT/target/release/xtask}"
DISK="$OUT/disk.img"
IMAGE="$OUT/kernel.img"
REBOOT_IMAGE="$OUT/kernel-reboot.img"
BOOT_IMAGE="$IMAGE"
mkdir -p "$OUT"

if ! [[ "$CORES" =~ ^[4-9](-[0-9]+)?(,[4-9](-[0-9]+)?)*$ ]] && [ "$CORES" != "4-11" ]; then
  echo "FS-0 power-cut: CPU set must stay within 4-11" >&2
  exit 2
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "FS-0 power-cut: /dev/kvm is required" >&2
  exit 2
fi

CARGO_TARGET_DIR="$TARGET" taskset -c "$CORES" cargo build --locked --release \
  --target x86_64-unknown-none -p jasper-kernel --features fs0-journal-verify \
  >"$OUT/build.log" 2>&1
if [ ! -x "$XTASK" ]; then
  taskset -c "$CORES" cargo build --locked --release -p xtask >>"$OUT/build.log" 2>&1
  XTASK="$ROOT/target/release/xtask"
fi
"$XTASK" "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$IMAGE" \
  >"$OUT/image.log" 2>&1
truncate -s 8M "$DISK"

qemu() {
  taskset -c "$CORES" qemu-system-x86_64 -accel kvm -cpu host \
    -drive format=raw,file="$BOOT_IMAGE" \
    -device virtio-blk-pci,drive=d1 \
    -drive if=none,id=d1,file="$DISK",format=raw,discard=unmap \
    -serial stdio -display none -monitor none -no-reboot -m 256M \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
}

qemu >"$OUT/serial-before-cut.log" 2>&1 &
qpid=$!
checkpoint=0
for _ in $(seq 1 600); do
  if ! kill -0 "$qpid" 2>/dev/null; then
    break
  fi
  if grep -qa '^\[JSR-FS0\] checkpoint=true sequence=1' \
    "$OUT/serial-before-cut.log"; then
    checkpoint=1
    pkill -9 -P "$qpid" 2>/dev/null || true
    kill -9 "$qpid" 2>/dev/null || true
    break
  fi
  sleep 0.1
done
wait "$qpid" 2>/dev/null || true
sleep 1
if [ "$checkpoint" -ne 1 ]; then
  echo "FS-0 power-cut: committed checkpoint not observed" >&2
  exit 1
fi

cp "$IMAGE" "$REBOOT_IMAGE"
BOOT_IMAGE="$REBOOT_IMAGE"
set +e
qemu >"$OUT/serial-after-reboot.log" 2>&1
rc=$?
set -e
grep -qa '^\[JSR-FS0\] recovered=true sequence=1 seed=true' \
  "$OUT/serial-after-reboot.log"
grep -qa '^\[JSR-FS0\] summary failed=0 recovered=true seed=true final_sequence=2 after_reboot=true resources=true' \
  "$OUT/serial-after-reboot.log"
if [ "$rc" -ne 33 ]; then
  echo "FS-0 power-cut: reboot QEMU exit=$rc" >&2
  exit 1
fi
echo "FS-0 power-cut: PASS evidence=$OUT"

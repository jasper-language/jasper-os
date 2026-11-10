#!/usr/bin/env bash
# Build a P0 GPT/ESP image and boot the production kernel through OVMF.
# 通过 OVMF 从 P0 GPT/ESP 启动生产内核。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${ISSUE21_UEFI_OUT:-$ROOT/evidence/issue21-uefi-boot-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${ISSUE21_UEFI_TARGET:-$ROOT/target/issue21-uefi-check}"
LIMIT="${ISSUE21_UEFI_TIMEOUT:-45}"
mkdir "$OUT"
IMAGE="$TARGET/p0.img"
ESP_IMAGE="$TARGET/esp.img"
UEFI_ESP="$TARGET/uefi-esp.img"
OVMF_VARS="$TARGET/OVMF_VARS.fd"
KERNEL="$TARGET/x86_64-unknown-none/release/jasper-kernel"
# 仅清理本脚本固定命名的派生产物；证据目录必须独占，防止陈旧日志混入。
# Remove only this script's fixed derived files; evidence output must be fresh.
rm -f -- "$IMAGE" "$ESP_IMAGE" "$UEFI_ESP" "$OVMF_VARS"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none \
  -p jasper-kernel --features production >"$OUT/kernel-build.log" 2>&1
cargo build --locked --release -p xtask >"$OUT/xtask-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-uefi \
  -p jasper-boot-manager >"$OUT/boot-manager-build.log" 2>&1

cargo run --locked -p jasper-lifecycle-staging --bin jasper-gpt-image -- \
  "$IMAGE" 38654705664 >"$OUT/gpt.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-esp-format -- \
  "$IMAGE" 38654705664 >"$OUT/esp-format.log" 2>&1
target/release/xtask uefi-managed-esp \
  "$KERNEL" "$KERNEL" \
  "$TARGET/x86_64-unknown-uefi/release/jasper-boot-manager.efi" \
  "$UEFI_ESP" >"$OUT/uefi-esp.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-esp-install -- \
  "$IMAGE" 38654705664 "$UEFI_ESP" >"$OUT/esp-install.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-ext4-provision -- \
  "$IMAGE" 38654705664 >"$OUT/ext4-provision.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-init -- \
  "$IMAGE" 38654705664 "$KERNEL" 1 1 1 1 1 >"$OUT/control-init.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" 38654705664 >"$OUT/control-inspect.log" 2>&1

dd if="$IMAGE" of="$ESP_IMAGE" bs=512 skip=2048 count=1048576 \
  conv=sparse status=none
fsck.fat -n -v -l "$ESP_IMAGE" >"$OUT/fsck-fat.log" 2>&1
! grep -qE 'Expected a valid|Bad short file name|Renamed to|share clusters|Start does point|Deleting ' \
  "$OUT/fsck-fat.log"
sgdisk -v "$IMAGE" >"$OUT/sgdisk.log" 2>&1
grep -q 'No problems found' "$OUT/sgdisk.log"

cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS"
set +e
timeout "$LIMIT" qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -m 512M \
  -smp 1 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$OVMF_VARS" \
  -drive file="$IMAGE",format=raw,if=ide \
  -serial "file:$OUT/serial.log" \
  -display none -monitor none -no-reboot
rc=$?
set -e
printf '%s\n' "$rc" >"$OUT/qemu.rc"
[ "$rc" -eq 124 ]
grep -aq 'Jasper-OS boot manager starting' "$OUT/serial.log"
grep -aq 'selecting slot=A reason=ConfirmedRelease attempt=1 release=1' "$OUT/serial.log"
grep -aq '^\[JSR-BOOT-STAGE\] done stage=user_runtime' "$OUT/serial.log"
grep -aq '^\[JSR-PROD\] first_program state=Some(Exited { code: 0 }) reclaimed=true' "$OUT/serial.log"
grep -aq '^\[JSR-PLAN\] finish plan=production stages=0xffff cases=1' "$OUT/serial.log"
grep -aqE '^\[JSR-PROD\] alive ticks=[1-9][0-9]*' "$OUT/serial.log"
! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' "$OUT/serial.log"
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" 38654705664 >"$OUT/control-postboot.log" 2>&1
grep -q 'generation=2 ' "$OUT/control-postboot.log"
grep -q 'slot=A state=Confirmed generation=2 release=1 attempts=1' \
  "$OUT/control-postboot.log"

echo "issue21-uefi-boot: PASS qemu_rc=$rc evidence=$OUT"

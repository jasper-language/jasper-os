#!/usr/bin/env bash
# Corrupt the newest copy after health confirmation, then verify OVMF recovery.
# 健康确认写盘后破坏最新控制副本，再用同一 P0 磁盘验证 OVMF 恢复并重新确认。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${ISSUE21_CONFIRM_CUT_OUT:-$ROOT/evidence/issue21-confirm-cut-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${ISSUE21_CONFIRM_CUT_TARGET:-$ROOT/target/issue21-confirm-cut}"
BOOT_LIMIT="${ISSUE21_CONFIRM_CUT_TIMEOUT:-20}"
TOTAL=38654705664
CONTROL_A_LBA=34605056
mkdir "$OUT"
mkdir -p "$TARGET"
IMAGE="$TARGET/p0.img"
UEFI_ESP="$TARGET/uefi-esp.img"
OVMF_VARS="$TARGET/OVMF_VARS.fd"
KERNEL="$TARGET/x86_64-unknown-none/release/jasper-kernel"
MANAGER="$TARGET/x86_64-unknown-uefi/release/jasper-boot-manager.efi"
rm -f -- "$IMAGE" "$UEFI_ESP" "$OVMF_VARS"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none \
  -p jasper-kernel --features production,lifecycle-ab-health >"$OUT/kernel-build.log" 2>&1
cargo build --locked --release -p xtask >"$OUT/xtask-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-uefi \
  -p jasper-boot-manager >"$OUT/boot-manager-build.log" 2>&1

cargo run --locked -p jasper-lifecycle-staging --bin jasper-gpt-image -- \
  "$IMAGE" "$TOTAL" >"$OUT/gpt.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-esp-format -- \
  "$IMAGE" "$TOTAL" >"$OUT/esp-format.log" 2>&1
target/release/xtask uefi-managed-esp \
  "$KERNEL" "$KERNEL" "$MANAGER" "$UEFI_ESP" >"$OUT/uefi-esp.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-esp-install -- \
  "$IMAGE" "$TOTAL" "$UEFI_ESP" >"$OUT/esp-install.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-ext4-provision -- \
  "$IMAGE" "$TOTAL" >"$OUT/ext4-provision.log" 2>&1
bash scripts/issue21-data-fixture.sh \
  install "$IMAGE" "$TARGET" "$TOTAL" >"$OUT/data-install.log" 2>&1
bash scripts/issue21-system-root-fixture.sh \
  "$IMAGE" "$TARGET" 1050624 A 1 >"$OUT/system-root-a.log" 2>&1
bash scripts/issue21-system-root-fixture.sh \
  "$IMAGE" "$TARGET" 17827840 B 2 >"$OUT/system-root-b.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-init -- \
  "$IMAGE" "$TOTAL" "$KERNEL" 1 1 1 1 1 >"$OUT/control-init.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-stage -- \
  "$IMAGE" "$TOTAL" "$KERNEL" 2 2 2 1 1 >"$OUT/control-stage.log" 2>&1

rm -f -- "$OVMF_VARS"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS"
set +e
timeout "$BOOT_LIMIT" qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -m 512M \
  -smp 1 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$OVMF_VARS" \
  -drive file="$IMAGE",format=raw,if=virtio \
  -serial "file:$OUT/serial-confirmed.log" \
  -display none -monitor none -no-reboot >"$OUT/qemu-confirmed.log" 2>&1
confirmed_rc=$?
set -e
printf '%s\n' "$confirmed_rc" >"$OUT/qemu-confirmed.rc"
[ "$confirmed_rc" -eq 124 ]
grep -aq 'selecting slot=B reason=CandidateTrial attempt=1 release=2' \
  "$OUT/serial-confirmed.log"
grep -aq '^\[JSR-LIFE-HEALTH\] result=confirmed slot=B generation=4 release=2 attempts=0 storage=virtio-blk' \
  "$OUT/serial-confirmed.log"
grep -aqE '^\[JSR-PROD\] alive ticks=[1-9][0-9]*' \
  "$OUT/serial-confirmed.log"
bash scripts/issue21-data-fixture.sh \
  verify "$IMAGE" "$TARGET" "$TOTAL" >"$OUT/data-after-confirmation.log" 2>&1

cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-before-corruption.log" 2>&1
grep -q 'generation=4 ' "$OUT/control-before-corruption.log"
grep -q 'active=B ' "$OUT/control-before-corruption.log"
grep -q 'slot=B state=Confirmed generation=3 release=2 attempts=0' \
  "$OUT/control-before-corruption.log"

# Generation 4 occupies Control A. Corrupt only that copy and preserve generation 3 in Control B.
printf 'torn-confirm-a' | \
  dd of="$IMAGE" bs=1 seek="$((CONTROL_A_LBA * 512))" \
    conv=notrunc status=none
sync
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-after-corruption.log" 2>&1
grep -q 'generation=3 ' "$OUT/control-after-corruption.log"
grep -q 'active=A ' "$OUT/control-after-corruption.log"
grep -q 'slot=B state=Candidate generation=2 release=2 attempts=1' \
  "$OUT/control-after-corruption.log"

rm -f -- "$OVMF_VARS"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS"
set +e
timeout "$BOOT_LIMIT" qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -m 512M \
  -smp 1 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$OVMF_VARS" \
  -drive file="$IMAGE",format=raw,if=virtio \
  -serial "file:$OUT/serial-recovery.log" \
  -display none -monitor none -no-reboot >"$OUT/qemu-recovery.log" 2>&1
recovery_rc=$?
set -e
printf '%s\n' "$recovery_rc" >"$OUT/qemu-recovery.rc"
[ "$recovery_rc" -eq 124 ]
grep -aq 'selecting slot=B reason=CandidateTrial attempt=2 release=2' \
  "$OUT/serial-recovery.log"
grep -aq '^\[JSR-LIFE-HEALTH\] result=confirmed slot=B generation=5 release=2 attempts=0 storage=virtio-blk' \
  "$OUT/serial-recovery.log"
grep -aqE '^\[JSR-PROD\] alive ticks=[1-9][0-9]*' \
  "$OUT/serial-recovery.log"
! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
  "$OUT/serial-recovery.log"

cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-recovered.log" 2>&1
grep -q 'generation=5 ' "$OUT/control-recovered.log"
grep -q 'active=B ' "$OUT/control-recovered.log"
grep -q 'slot=A state=Confirmed generation=1 release=1 attempts=0' \
  "$OUT/control-recovered.log"
grep -q 'slot=B state=Confirmed generation=4 release=2 attempts=0' \
  "$OUT/control-recovered.log"
bash scripts/issue21-data-fixture.sh \
  verify "$IMAGE" "$TARGET" "$TOTAL" >"$OUT/data-after-recovery.log" 2>&1

echo "issue21-confirm-cut: PASS prior_generation=3 reconfirmed_generation=5 evidence=$OUT"

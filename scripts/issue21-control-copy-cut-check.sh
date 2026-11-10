#!/usr/bin/env bash
# Corrupt the newest valid control copy after a cut, then verify OVMF recovery.
# 在断电后破坏最新有效控制副本，再用同一 P0 磁盘验证 OVMF 回退上一世代并完成试启动。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${ISSUE21_COPY_CUT_OUT:-$ROOT/evidence/issue21-control-copy-cut-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${ISSUE21_COPY_CUT_TARGET:-$ROOT/target/issue21-control-copy-cut}"
RECOVERY_LIMIT="${ISSUE21_COPY_CUT_TIMEOUT:-20}"
TOTAL=38654705664
CONTROL_B_LBA=34736128
mkdir "$OUT"
mkdir -p "$TARGET"
IMAGE="$TARGET/p0.img"
UEFI_ESP="$TARGET/uefi-esp.img"
OVMF_VARS="$TARGET/OVMF_VARS.fd"
KERNEL="$TARGET/x86_64-unknown-none/release/jasper-kernel"
MANAGER="$TARGET/x86_64-unknown-uefi/release/jasper-boot-manager.efi"
qpid=""
rm -f -- "$IMAGE" "$UEFI_ESP" "$OVMF_VARS"

cleanup() {
  if [ -n "$qpid" ] && kill -0 "$qpid" 2>/dev/null; then
    kill -9 "$qpid" 2>/dev/null || true
    wait "$qpid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

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
qemu-system-x86_64 \
  -accel tcg \
  -machine q35 \
  -m 512M \
  -smp 1 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$OVMF_VARS" \
  -drive file="$IMAGE",format=raw,if=virtio \
  -serial "file:$OUT/serial-before-cut.log" \
  -display none -monitor none -no-reboot >"$OUT/qemu-before-cut.log" 2>&1 &
qpid=$!
seen=0
for _ in $(seq 1 1000); do
  if ! kill -0 "$qpid" 2>/dev/null; then
    break
  fi
  if grep -aFq \
    'selecting slot=B reason=CandidateTrial attempt=1 release=2' \
    "$OUT/serial-before-cut.log" 2>/dev/null; then
    seen=1
    kill -9 "$qpid" 2>/dev/null || true
    break
  fi
  sleep 0.02
done
set +e
wait "$qpid" 2>/dev/null
cut_rc=$?
set -e
qpid=""
printf '%s\n' "$cut_rc" >"$OUT/qemu-before-cut.rc"
[ "$seen" -eq 1 ]
grep -aq 'selecting slot=B reason=CandidateTrial attempt=1 release=2' \
  "$OUT/serial-before-cut.log"
! grep -aq '^\[JSR-LIFE-HEALTH\]' "$OUT/serial-before-cut.log"

cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-before-corruption.log" 2>&1
grep -q 'generation=3 ' "$OUT/control-before-corruption.log"
grep -q 'slot=B state=Candidate generation=2 release=2 attempts=1' \
  "$OUT/control-before-corruption.log"

# The newer decision occupies Control B. Corrupt only that copy and preserve Control A.
printf 'torn-control-b' | \
  dd of="$IMAGE" bs=1 seek="$((CONTROL_B_LBA * 512))" \
    conv=notrunc status=none
sync
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-after-corruption.log" 2>&1
grep -q 'generation=2 ' "$OUT/control-after-corruption.log"
grep -q 'slot=B state=Candidate generation=1 release=2 attempts=0' \
  "$OUT/control-after-corruption.log"

rm -f -- "$OVMF_VARS"
cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS"
set +e
timeout "$RECOVERY_LIMIT" qemu-system-x86_64 \
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
grep -aq 'selecting slot=B reason=CandidateTrial attempt=1 release=2' \
  "$OUT/serial-recovery.log"
grep -aq '^\[JSR-LIFE-HEALTH\] result=confirmed slot=B generation=4 release=2 attempts=0 storage=virtio-blk' \
  "$OUT/serial-recovery.log"
grep -aqE '^\[JSR-PROD\] alive ticks=[1-9][0-9]*' \
  "$OUT/serial-recovery.log"
! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
  "$OUT/serial-recovery.log"

cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-recovered.log" 2>&1
grep -q 'generation=4 ' "$OUT/control-recovered.log"
grep -q 'active=B ' "$OUT/control-recovered.log"
grep -q 'slot=A state=Confirmed generation=1 release=1 attempts=0' \
  "$OUT/control-recovered.log"
grep -q 'slot=B state=Confirmed generation=3 release=2 attempts=0' \
  "$OUT/control-recovered.log"

echo "issue21-control-copy-cut: PASS recovered_generation=2 confirmed=B evidence=$OUT"

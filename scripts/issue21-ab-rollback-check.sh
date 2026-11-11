#!/usr/bin/env bash
# Verify B-candidate trial exhaustion and automatic return to confirmed slot A.
# 验收 B 候选试启动预算耗尽后自动回到已确认 A 槽。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${ISSUE21_AB_OUT:-$ROOT/evidence/issue21-ab-rollback-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${ISSUE21_AB_TARGET:-$ROOT/target/issue21-ab-rollback}"
LIMIT="${ISSUE21_AB_TIMEOUT:-30}"
ROOT_CORRUPT="${ISSUE21_AB_ROOT_CORRUPT:-0}"
FAIL_REASON="${ISSUE21_AB_FAIL_REASON:-injected_failure}"
TOTAL=38654705664
mkdir "$OUT"
mkdir -p "$TARGET"
IMAGE="$TARGET/p0.img"
UEFI_ESP="$TARGET/uefi-esp.img"
OVMF_VARS="$TARGET/OVMF_VARS.fd"
KERNEL_A="$TARGET/kernel-a"
KERNEL_B="$TARGET/kernel-b"
MANAGER="$TARGET/x86_64-unknown-uefi/release/jasper-boot-manager.efi"
rm -f -- "$IMAGE" "$UEFI_ESP" "$OVMF_VARS"

CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none \
  -p jasper-kernel --features production,lifecycle-ab-health >"$OUT/kernel-a-build.log" 2>&1
cp "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$KERNEL_A"
if [ "$ROOT_CORRUPT" = 1 ]; then
  CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none \
    -p jasper-kernel --features production,lifecycle-ab-health \
    >"$OUT/kernel-b-build.log" 2>&1
else
  CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-none \
    -p jasper-kernel \
    --features lifecycle-health-fail-verify \
    >"$OUT/kernel-b-build.log" 2>&1
fi
cp "$TARGET/x86_64-unknown-none/release/jasper-kernel" "$KERNEL_B"
cargo build --locked --release -p xtask >"$OUT/xtask-build.log" 2>&1
CARGO_TARGET_DIR="$TARGET" cargo build --locked --release --target x86_64-unknown-uefi \
  -p jasper-boot-manager >"$OUT/boot-manager-build.log" 2>&1

cargo run --locked -p jasper-lifecycle-staging --bin jasper-gpt-image -- \
  "$IMAGE" "$TOTAL" >"$OUT/gpt.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-esp-format -- \
  "$IMAGE" "$TOTAL" >"$OUT/esp-format.log" 2>&1
target/release/xtask uefi-managed-esp \
  "$KERNEL_A" "$KERNEL_B" "$MANAGER" "$UEFI_ESP" >"$OUT/uefi-esp.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-esp-install -- \
  "$IMAGE" "$TOTAL" "$UEFI_ESP" >"$OUT/esp-install.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-ext4-provision -- \
  "$IMAGE" "$TOTAL" >"$OUT/ext4-provision.log" 2>&1
bash scripts/issue21-system-root-fixture.sh \
  "$IMAGE" "$TARGET" 1050624 A 1 >"$OUT/system-root-a.log" 2>&1
bash scripts/issue21-system-root-fixture.sh \
  "$IMAGE" "$TARGET" 17827840 B 2 >"$OUT/system-root-b.log" 2>&1
if [ "$ROOT_CORRUPT" = 1 ]; then
  B_PARTITION="$TARGET/system-B.img"
  BAD_BINARY="$TARGET/system-B-bad-true"
  dd if="$IMAGE" of="$B_PARTITION" bs=512 skip=17827840 count=16777216 \
    conv=sparse status=none
  printf 'not-an-x86-64-linux-elf\n' >"$BAD_BINARY"
  debugfs -w -R 'rm /bin/true' "$B_PARTITION" >"$OUT/root-corrupt.log" 2>&1
  debugfs -w -R "write $BAD_BINARY /bin/true" "$B_PARTITION" >>"$OUT/root-corrupt.log" 2>&1
  debugfs -w -R 'sif /bin/true mode 0100755' "$B_PARTITION" >>"$OUT/root-corrupt.log" 2>&1
  e2fsck -fy "$B_PARTITION" >>"$OUT/root-corrupt.log" 2>&1
  e2fsck -fn "$B_PARTITION" >>"$OUT/root-corrupt.log" 2>&1
  dd if="$B_PARTITION" of="$IMAGE" bs=512 seek=17827840 \
    conv=notrunc,sparse status=none
  sync
fi
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-init -- \
  "$IMAGE" "$TOTAL" "$KERNEL_A" 1 1 1 1 1 >"$OUT/control-init.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-stage -- \
  "$IMAGE" "$TOTAL" "$KERNEL_B" 2 2 2 1 1 >"$OUT/control-stage.log" 2>&1
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-candidate.log" 2>&1

run_boot() {
  local label="$1"
  local expected="$2"
  local health="$3"
  local run="$OUT/$label"
  mkdir "$run"
  rm -f -- "$OVMF_VARS"
  cp /usr/share/OVMF/OVMF_VARS_4M.fd "$OVMF_VARS"
  set +e
  timeout "$LIMIT" qemu-system-x86_64 \
    -accel tcg \
    -machine q35 \
    -m 512M \
    -smp 1 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file="$OVMF_VARS" \
    -drive file="$IMAGE",format=raw,if=virtio \
    -serial "file:$run/serial.log" \
    -display none -monitor none -no-reboot >"$run/qemu.log" 2>&1
  local rc=$?
  set -e
  printf '%s\n' "$rc" >"$run/qemu.rc"
  [ "$rc" -eq 124 ]
  grep -aFq "$expected" "$run/serial.log"
  grep -aq '^\[JSR-PROD\] first_program state=Some(Exited { code: 0 }) reclaimed=true' \
    "$run/serial.log"
  if [ "$health" = "confirm" ]; then
    grep -aq '^\[JSR-LIFE-HEALTH\] result=confirmed slot=A generation=7 release=1 attempts=0 storage=virtio-blk' \
      "$run/serial.log"
    grep -aqE '^\[JSR-PROD\] alive ticks=[1-9][0-9]*' "$run/serial.log"
  else
    grep -aq "^\\[JSR-LIFE-HEALTH\\] result=failed reason=$FAIL_REASON" \
      "$run/serial.log"
  fi
  ! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
    "$run/serial.log"
}

run_boot candidate-1 'selecting slot=B reason=CandidateTrial attempt=1 release=2' fail
run_boot candidate-2 'selecting slot=B reason=CandidateTrial attempt=2 release=2' fail
run_boot candidate-3 'selecting slot=B reason=CandidateTrial attempt=3 release=2' fail
run_boot fallback-a 'selecting slot=A reason=ConfirmedRelease attempt=1 release=1' confirm

cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-rollback.log" 2>&1
grep -q 'generation=7 ' "$OUT/control-rollback.log"
grep -q 'active=A ' "$OUT/control-rollback.log"
grep -q 'slot=A state=Confirmed generation=3 release=1 attempts=0' \
  "$OUT/control-rollback.log"
grep -q 'slot=B state=Failed generation=5 release=2 attempts=0' \
  "$OUT/control-rollback.log"

echo "issue21-ab-rollback: PASS candidate_attempts=3 fallback=A evidence=$OUT"

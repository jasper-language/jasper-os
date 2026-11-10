#!/usr/bin/env bash
# Kill QEMU after each persisted candidate-trial decision, then verify recovery.
# 在每次候选试启动决策持久化后强杀 QEMU，再用同一磁盘验证预算与回退恢复。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export PATH="${HOME}/.cargo/bin:${PATH}"

OUT="${ISSUE21_CUT_OUT:-$ROOT/evidence/issue21-trial-powercut-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${ISSUE21_CUT_TARGET:-$ROOT/target/issue21-trial-powercut}"
FINAL_LIMIT="${ISSUE21_CUT_FINAL_TIMEOUT:-20}"
TOTAL=38654705664
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
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-staged.log" 2>&1
grep -q 'generation=2 ' "$OUT/control-staged.log"
grep -q 'slot=B state=Candidate generation=1 release=2 attempts=0' \
  "$OUT/control-staged.log"

start_qemu() {
  local label="$1"
  local run="$OUT/$label"
  mkdir "$run"
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
    -serial "file:$run/serial.log" \
    -display none -monitor none -no-reboot >"$run/qemu.log" 2>&1 &
  qpid=$!
}

cut_after_selection() {
  local label="$1"
  local expected="$2"
  local run="$OUT/$label"
  start_qemu "$label"
  local seen=0
  for _ in $(seq 1 1000); do
    if ! kill -0 "$qpid" 2>/dev/null; then
      break
    fi
    if grep -aFq "$expected" "$run/serial.log" 2>/dev/null; then
      seen=1
      kill -9 "$qpid" 2>/dev/null || true
      break
    fi
    sleep 0.02
  done
  set +e
  wait "$qpid" 2>/dev/null
  local rc=$?
  set -e
  qpid=""
  printf '%s\n' "$rc" >"$run/qemu.rc"
  [ "$seen" -eq 1 ]
  grep -aFq "$expected" "$run/serial.log"
  ! grep -aq '^\[JSR-LIFE-HEALTH\]' "$run/serial.log"
}

cut_after_selection cut-1 \
  'selecting slot=B reason=CandidateTrial attempt=1 release=2'
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-after-cut-1.log" 2>&1
grep -q 'generation=3 ' "$OUT/control-after-cut-1.log"
grep -q 'slot=B state=Candidate generation=2 release=2 attempts=1' \
  "$OUT/control-after-cut-1.log"

cut_after_selection cut-2 \
  'selecting slot=B reason=CandidateTrial attempt=2 release=2'
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-after-cut-2.log" 2>&1
grep -q 'generation=4 ' "$OUT/control-after-cut-2.log"
grep -q 'slot=B state=Candidate generation=3 release=2 attempts=2' \
  "$OUT/control-after-cut-2.log"

cut_after_selection cut-3 \
  'selecting slot=B reason=CandidateTrial attempt=3 release=2'
cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-after-cut-3.log" 2>&1
grep -q 'generation=5 ' "$OUT/control-after-cut-3.log"
grep -q 'slot=B state=Candidate generation=4 release=2 attempts=3' \
  "$OUT/control-after-cut-3.log"

start_qemu final-recovery
set +e
timeout "$FINAL_LIMIT" tail --pid="$qpid" -f /dev/null
tail_rc=$?
if [ "$tail_rc" -eq 124 ]; then
  kill -9 "$qpid" 2>/dev/null || true
fi
wait "$qpid" 2>/dev/null
qemu_rc=$?
set -e
qpid=""
printf '%s\n' "$qemu_rc" >"$OUT/final-recovery/qemu.rc"
grep -aq 'selecting slot=A reason=ConfirmedRelease attempt=1 release=1' \
  "$OUT/final-recovery/serial.log"
grep -aq '^\[JSR-LIFE-HEALTH\] result=confirmed slot=A generation=7 release=1 attempts=0 storage=virtio-blk' \
  "$OUT/final-recovery/serial.log"
grep -aqE '^\[JSR-PROD\] alive ticks=[1-9][0-9]*' \
  "$OUT/final-recovery/serial.log"
! grep -aqE '^\[JSR-(PANIC|COMPAT-DYNAMIC-FAIL)\]|panicked at|KERNEL PANIC' \
  "$OUT/final-recovery/serial.log"

cargo run --locked -p jasper-lifecycle-staging --bin jasper-control-inspect -- \
  "$IMAGE" "$TOTAL" >"$OUT/control-recovered.log" 2>&1
grep -q 'generation=7 ' "$OUT/control-recovered.log"
grep -q 'active=A ' "$OUT/control-recovered.log"
grep -q 'slot=A state=Confirmed generation=3 release=1 attempts=0' \
  "$OUT/control-recovered.log"
grep -q 'slot=B state=Failed generation=5 release=2 attempts=0' \
  "$OUT/control-recovered.log"

echo "issue21-trial-powercut: PASS cuts=3 recovered=A evidence=$OUT"

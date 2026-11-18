#!/usr/bin/env bash
# Two-boot LC-4 lifecycle receipt drill on one immutable P0/OVMF state.
# 同一个 P0/OVMF 状态连续两次启动的 LC-4 生命周期持久回执演练。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT_BASE="${LC4_LIFECYCLE_OUT:-$ROOT/evidence/driver-host-lifecycle-$(date '+%Y%m%d-%H%M%S')}"
TARGET="${LC4_LIFECYCLE_TARGET:-$ROOT/target/issue21-driver-lifecycle}"
qemu_budget="${ISSUE21_UEFI_TIMEOUT:-180}"
[ ! -e "$OUT_BASE" ] || {
  echo "driver-host-lifecycle: output already exists: $OUT_BASE" >&2
  exit 73
}

common=(
  env
  JASPER_BUILD_ALLOW_VBOX=1
  JASPER_BUILD_CPUS="${JASPER_BUILD_CPUS:-4-5}"
  JASPER_BUILD_MIN_DISK_GIB="${JASPER_BUILD_MIN_DISK_GIB:-8388608}"
  ISSUE21_QEMU_CPUS="${ISSUE21_QEMU_CPUS:-6-7}"
  ISSUE21_UEFI_MODE=driver-host-journal
  ISSUE21_UEFI_TIMEOUT="$qemu_budget"
  ISSUE21_UEFI_CARGO_TARGET="$ROOT/target"
  ISSUE21_UEFI_TARGET="$TARGET"
  ISSUE21_KEEP_DERIVED=1
)

"${common[@]}" \
  ISSUE21_DRIVER_HOST_EXPECT=initialized \
  ISSUE21_UEFI_OUT="$OUT_BASE/boot1" \
  bash scripts/issue21-uefi-boot-check.sh

"${common[@]}" \
  ISSUE21_DRIVER_HOST_EXPECT=reopened \
  ISSUE21_REUSE_P0=1 \
  ISSUE21_UEFI_PREBUILT=1 \
  ISSUE21_UEFI_OUT="$OUT_BASE/boot2" \
  bash scripts/issue21-uefi-boot-check.sh

grep -aFq 'sequence=5 last=reset' "$OUT_BASE/boot1/serial.log"
grep -aFq 'sequence=5 last=reset' "$OUT_BASE/boot2/serial.log"
grep -aFq 'live_restored=false' "$OUT_BASE/boot2/serial.log"
grep -aFq 'event=admitted' "$OUT_BASE/boot1/serial.log"
grep -aFq 'event=crashed' "$OUT_BASE/boot1/serial.log"
grep -aFq 'event=recovered' "$OUT_BASE/boot1/serial.log"
grep -aFq 'event=reset' "$OUT_BASE/boot1/serial.log"

echo "driver-host-lifecycle: PASS boots=2 sequence=5 crash=true recovery=true reset=true qemu_budget=$qemu_budget evidence=$OUT_BASE"

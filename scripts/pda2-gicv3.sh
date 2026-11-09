#!/bin/bash
# PDA-2 GICv3 acceptance: boot, timer PPIs, redistributors, SGIs and SPIs on
# one and four QEMU virt CPUs. The guest still exits 35 because the existing
# x86-only PCI/MSI/KRN0 drills are represented as expected baseline failures.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
target=aarch64-unknown-none-softfloat
out="evidence/pda2-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"

cargo build --release --target "$target" -p jasper-kernel --no-default-features \
  >"$out/build.log" 2>&1

run_case() {
  local cpus=$1 timeout_s=$2
  local log="$out/serial-gicv3-smp$cpus.log"
  set +e
  timeout "$timeout_s" qemu-system-aarch64 \
    -M virt,gic-version=3 -cpu cortex-a72 -m 256M -smp "$cpus" \
    -kernel "target/$target/release/jasper-kernel" \
    -semihosting -serial stdio -display none -monitor none -no-reboot \
    >"$log" 2>&1
  local rc=$?
  set -e
  [ "$rc" -eq 35 ] || {
    echo "GICv3 smp=$cpus: unexpected QEMU exit $rc" >&2
    return 1
  }

  grep -q '\[JSR-DTB\] gic=compatible=arm,gic-v3 kind=v3' "$log"
  grep -q '\[JSR-BOOT-STAGE\] done stage=timer done_mask=0x7' "$log"
  grep -q "\[JSR-SMP\] summary cpus=$cpus online=$cpus checks=" "$log"
  if [ "$cpus" -eq 4 ]; then
    grep -q '\[JSR-SMP\] start present=4 online=4 failed=0' "$log"
    grep -q '\[JSR-SMP\] ipi reschedule delivered=3/3' "$log"
    grep -q '\[JSR-SMP\] call ran_on_target=3/3' "$log"
    grep -q '\[JSR-SMP\] tlb .*after_shootdown=B:3/3' "$log"
    grep -q '\[JSR-SMP3\] case=route cpus=4 lines=2 delivered_exact=4/4' "$log"
    grep -q '\[JSR-SMP3\] summary cpus=4 .* failed=0' "$log"
  fi
  grep -q 'smp_failed=0' "$log"
  grep -q 'irq_failed=0' "$log"
}

run_case 1 90
run_case 4 180

echo "PDA-2 GICv3 PASS evidence=$out"

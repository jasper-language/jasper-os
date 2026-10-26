#!/usr/bin/env bash
# Author: chatgpt. Mechanism-only TCG test, no p99 or hardware throughput claim.
set -euo pipefail
cd "$(dirname "$0")/.."
label=${1:?unique evidence label};[[ "$label" =~ ^[a-zA-Z0-9._-]+$ ]]
out="evidence/evt1/$label";mkdir "$out"
inputs() { find kernel kernel-core abi user xtask .cargo scripts -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum;sha256sum Cargo.toml Cargo.lock rust-toolchain.toml; }
inputs > "$out/source-before.sha256"
cargo build --locked --release -p xtask > "$out/build.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features "${RT1_FEATURES:-rt1-verify}" >> "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum "$out/kernel.img" target/x86_64-unknown-none/release/jasper-kernel > "$out/artifacts.sha256"
set +e
timeout 180 qemu-system-x86_64 -accel tcg -icount shift=5 -drive format=raw,file="$out/kernel.img" -smp 4 -m 512M -serial stdio -display none -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial.log" 2>&1
rc=$?;set -e;printf '%s\n' "$rc" > "$out/exit.txt"
inputs > "$out/source-after.sha256";cmp "$out/source-before.sha256" "$out/source-after.sha256"
test "$rc" = 33
if [[ "${RT1_FEATURES:-rt1-verify}" == rt2-verify ]]; then
 grep -aFq '[JSR-RT2-INTEGRATION] ns_sleep=true bsp_ap=true cpl3=true ns_budget=true exit_cancel=true resources=true failed=0' "$out/serial.log"
 grep -aFq '[JSR-RT2-IRQ] delivered=true no_legacy_credit=true periodic_restored=true failed=0' "$out/serial.log"
 grep -aFq '[JSR-RT2-LAPIC] cpu=1 ns_programmed=true overflow_unchanged=true periodic_restored=true resources=true failed=0' "$out/serial.log"
elif [[ "${RT1_FEATURES:-rt1-verify}" == rt1-no-realtime ]]; then
 grep -aFq '[JSR-RT1-PROFILE] realtime=false syscall_allowed=true rejected=true resources=true failed=0' "$out/serial.log"
else
grep -aFq '[JSR-RT1-ADMISSION] cpus=4 canonical=true rejected_unchanged=true partition_guard=true exit_release=true resources=true failed=0' "$out/serial.log"
grep -aFq '[JSR-RT1-EDF] first_dispatch=early both_completed=true absolute_deadline=true failed=0' "$out/serial.log"
grep -aFq '[JSR-RT1-CPL3] capability=true syscall_gate=true affinity=true descriptor=true exit=true resources=true failed=0' "$out/serial.log"
fi
! grep -aEq 'panicked|JSR-PANIC' "$out/serial.log"
touch "$out/PASS"

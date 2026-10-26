#!/usr/bin/env bash
# Controlled KRN-3 AP fast-leaf tick contract; TCG proves mechanism only.
set -euo pipefail
cd "$(dirname "$0")/.."
label=${1:?unique evidence label}; [[ "$label" =~ ^[a-zA-Z0-9._-]+$ ]]
out="evidence/krn3/$label"; mkdir -p "$out"
inputs() { find kernel kernel-core abi user xtask .cargo scripts -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum; sha256sum Cargo.toml Cargo.lock rust-toolchain.toml; }
inputs > "$out/source-before.sha256"
cargo build --locked --release -p xtask > "$out/build.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --no-default-features --features krn3-fast-tick-verify >> "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
set +e
timeout "${KRN3_QEMU_TIMEOUT:-180}" qemu-system-x86_64 -accel tcg -icount shift=5 -drive format=raw,file="$out/kernel.img" -smp 2 -m 256M \
  -serial stdio -display none -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial.log" 2>&1
rc=$?; set -e; printf '%s\n' "$rc" > "$out/exit.txt"
inputs > "$out/source-after.sha256"; cmp "$out/source-before.sha256" "$out/source-after.sha256"
[[ "$rc" == 33 ]]
line=$(tr -d '\r' < "$out/serial.log" | grep -E '^\[JSR-KRN3-FAST-TICK\] spawned=true hits=[0-9]+ batch_peak=1 local_switches=[0-9]+ entity_ticks=[0-9]+ busy_ticks=[0-9]+ exact=true leaf_finishes=[0-9]+ worker_finishes=[0-9]+ lists_ok=true reclaimed=true failed=0$')
hits=$(sed -E 's/.* hits=([0-9]+).*/\1/' <<<"$line")
batch_peak=$(sed -E 's/.* batch_peak=([0-9]+).*/\1/' <<<"$line")
local_switches=$(sed -E 's/.* local_switches=([0-9]+).*/\1/' <<<"$line")
entity=$(sed -E 's/.* entity_ticks=([0-9]+).*/\1/' <<<"$line")
busy=$(sed -E 's/.* busy_ticks=([0-9]+).*/\1/' <<<"$line")
finishes=$(sed -E 's/.* leaf_finishes=([0-9]+).*/\1/' <<<"$line")
worker_finishes=$(sed -E 's/.* worker_finishes=([0-9]+).*/\1/' <<<"$line")
(( hits >= 3 )); [[ "$batch_peak" == 1 ]]; (( local_switches >= 3 )); [[ "$entity" == "$busy" ]]; (( finishes >= 1 )); (( worker_finishes >= 1 ))
grep -aEq '^\[JSR-SMP2\] case=affinity .* ok=true' "$out/serial.log"
! grep -aEq 'JSR-LOCK-ORDER|JSR-PANIC' "$out/serial.log"
printf 'target=competing-leaf-switch\nexit=%s\nmechanism=true\nphysical-performance=false\n' "$rc" > "$out/result.txt"
touch "$out/PASS"

#!/usr/bin/env bash
# Author: chatgpt. Mechanism-only TCG test, no p99 or hardware throughput claim.
set -euo pipefail
cd "$(dirname "$0")/.."
label=${1:?unique evidence label};[[ "$label" =~ ^[a-zA-Z0-9._-]+$ ]]
out="evidence/evt1/$label";mkdir "$out"
inputs() { find kernel kernel-core abi user xtask .cargo scripts -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum;sha256sum Cargo.toml Cargo.lock rust-toolchain.toml; }
inputs > "$out/source-before.sha256"
cargo build --locked --release -p xtask > "$out/build.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features budget-window-verify >> "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum "$out/kernel.img" target/x86_64-unknown-none/release/jasper-kernel > "$out/artifacts.sha256"
set +e
timeout 180 qemu-system-x86_64 -accel tcg -icount shift=5 -drive format=raw,file="$out/kernel.img" -smp 8 -m 512M -serial stdio -display none -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial.log" 2>&1
rc=$?;set -e;printf '%s\n' "$rc" > "$out/exit.txt"
inputs > "$out/source-after.sha256";cmp "$out/source-before.sha256" "$out/source-after.sha256"
test "$rc" = 33
grep -aFq '[JSR-BUDGET-DIAG] cpus=8 failed=0' "$out/serial.log"
grep -aFq '[JSR-BUDGET-LIFETIME]' "$out/serial.log"
! grep -aEq 'panicked|JSR-PANIC' "$out/serial.log"
touch "$out/PASS"

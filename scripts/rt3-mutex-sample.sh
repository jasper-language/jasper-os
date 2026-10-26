#!/usr/bin/env bash
# Controlled functional RT-3 guest. TCG timing is not a physical bound.
set -euo pipefail
cd "$(dirname "$0")/.."
label=${1:?unique evidence label}; [[ "$label" =~ ^[a-zA-Z0-9._-]+$ ]]
out="evidence/rt3/$label"; mkdir "$out"
cpus=${RT3_CPUS:-4}; [[ "$cpus" =~ ^[1-8]$ ]]
inputs() { find kernel kernel-core abi user xtask .cargo scripts -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum; sha256sum Cargo.toml Cargo.lock rust-toolchain.toml; }
inputs > "$out/source-before.sha256"
cargo build --locked --release -p xtask > "$out/build.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features rt3-verify >> "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum "$out/kernel.img" target/x86_64-unknown-none/release/jasper-kernel > "$out/artifacts.sha256"
set +e
printf 'cpus=%s\n' "$cpus" > "$out/config.txt"
timeout 180 qemu-system-x86_64 -accel tcg -icount shift=5 -drive format=raw,file="$out/kernel.img" -smp "$cpus" -m 512M -serial stdio -display none -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial.log" 2>&1
rc=$?; set -e; printf '%s\n' "$rc" > "$out/exit.txt"
inputs > "$out/source-after.sha256"; cmp "$out/source-before.sha256" "$out/source-after.sha256"
test "$rc" = 33
grep -aFq 'ring: rt3 create=true recursive_refused=true unlock=true close=true' "$out/serial.log"
grep -aFq '[JSR-RT3-IPC] cpl3=true channel=true ring=true resources=true' "$out/serial.log"
grep -aFq '[JSR-RT3] cpl3=true classic_inversion=true donated=1 ipc_donated=1 reclaimed=true failed=0' "$out/serial.log"
! grep -aEq 'panicked|JSR-PANIC|JSR-RT3-FAIL' "$out/serial.log"
touch "$out/PASS"

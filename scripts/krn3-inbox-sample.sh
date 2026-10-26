#!/usr/bin/env bash
# Controlled KRN-3 target-inbox production check; TCG proves mechanism only.
set -euo pipefail
cd "$(dirname "$0")/.."
label=${1:?unique evidence label}; [[ "$label" =~ ^[a-zA-Z0-9._-]+$ ]]
out="evidence/krn3/$label"; mkdir -p "$out"
inputs() { find kernel kernel-core abi user xtask .cargo scripts -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum; sha256sum Cargo.toml Cargo.lock rust-toolchain.toml; }
inputs > "$out/source-before.sha256"
cargo build --locked --release -p xtask > "$out/build.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features fault-inject >> "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
dd if=/dev/zero of="$out/blank.img" bs=1M count=1 status=none
set +e
timeout 300 qemu-system-x86_64 -accel tcg -icount shift=5 -drive format=raw,file="$out/kernel.img" -smp 4 -m 256M \
  -device virtio-rng-pci -device virtio-net-pci,netdev=n0 -netdev user,id=n0 \
  -device virtio-blk-pci,drive=d1 -drive if=none,id=d1,file="$out/blank.img",format=raw \
  -serial stdio -display none -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial.log" 2>&1
rc=$?; set -e; printf '%s\n' "$rc" > "$out/exit.txt"
inputs > "$out/source-after.sha256"; cmp "$out/source-before.sha256" "$out/source-after.sha256"
[[ "$rc" == 33 || "$rc" == 35 || "$rc" == 37 ]]
grep -aEq '^\[JSR-WAKE-MSG\] routed=[1-9][0-9]* timely=true returned=true reclaimed=true' "$out/serial.log"
grep -aFq '[JSR-WAKE-FULL] queued=16 fallback=1 returned=17/17 timely=true reclaimed=true' "$out/serial.log"
grep -aEq '^\[JSR-SCALE\] case=scale .*lists_ok=true' "$out/serial.log"
grep -aEq '^\[JSR-SCALE\] summary .*reclaimed=true' "$out/serial.log"
! grep -aEq 'JSR-LOCK-ORDER|JSR-PANIC' "$out/serial.log"
printf 'target=inbox-only\nexit=%s\ndefault-suite-pass=false\n' "$rc" > "$out/result.txt"
touch "$out/PASS"

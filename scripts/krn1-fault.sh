#!/usr/bin/env bash
# Author: chatgpt. Run inside build VM via vm-run.sh. Correctness only.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
out="evidence/krn1"
mkdir -p "$out"
cargo test -p kernel-core --test krn1_fault --test krn1_exit_interleavings --test krn1_interleavings > "$out/host-tests.log" 2>&1
bash verification/run-fault-tlc.sh > "$out/fault-tlc.log" 2>&1
cargo build --locked --release -p xtask > "$out/xtask-build.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features fault-inject > "$out/fault-build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/fault.img" > "$out/image.log" 2>&1
truncate -s 16M "$out/blank.img"
set +e
timeout 900 qemu-system-x86_64 -accel tcg,thread=single -icount shift=5,sleep=off \
  -drive "format=raw,file=$out/fault.img" -device virtio-rng-pci \
  -device virtio-net-pci,netdev=n0 -netdev user,id=n0 \
  -device virtio-blk-pci,drive=d1 -drive "if=none,id=d1,file=$out/blank.img,format=raw" \
  -smp 4 -m 256M -serial stdio -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/fault-serial.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" > "$out/qemu-exit.txt"
[[ "$rc" == 33 || "$rc" == 37 ]]
grep -aq '^\[JSR-FAULT\] sites=4 .*frame_conserved=true heap_conserved=true failed=0' "$out/fault-serial.log"
grep -aEq '^\[JSR-EXIT\] (success|timing-only)' "$out/fault-serial.log"
! grep -aq '^\[JSR-EXIT\] failure' "$out/fault-serial.log"
echo 'KRN-1 fault sites and full kernel functional run PASS (QEMU correctness only)'

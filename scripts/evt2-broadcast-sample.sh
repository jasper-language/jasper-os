#!/usr/bin/env bash
# Author: chatgpt. Mechanism-only TCG test, no p99 or hardware throughput claim.
set -euo pipefail
cd "$(dirname "$0")/.."
label=${1:?unique evidence label};[[ "$label" =~ ^[a-zA-Z0-9._-]+$ ]]
out="${EVT2_OUT:-evidence/evt1/$label}";mkdir -p "$out"
qemu_cpus="${EVT2_QEMU_CPUS:-4-11}"
qemu_memory="${EVT2_QEMU_MEMORY:-768M}"
inputs() { find kernel kernel-core abi user xtask .cargo scripts -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum;sha256sum Cargo.toml Cargo.lock rust-toolchain.toml; }
inputs > "$out/source-before.sha256"
JASPER_BUILD_ALLOW_VBOX="${JASPER_BUILD_ALLOW_VBOX:-1}" \
  scripts/guarded-cargo.sh build --locked --release -p xtask > "$out/build.log" 2>&1
JASPER_BUILD_ALLOW_VBOX="${JASPER_BUILD_ALLOW_VBOX:-1}" \
  scripts/guarded-cargo.sh build --locked --release --target x86_64-unknown-none \
  -p jasper-kernel --features evt2-broadcast-verify >> "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum "$out/kernel.img" target/x86_64-unknown-none/release/jasper-kernel > "$out/artifacts.sha256"
set +e
flock -w 900 /tmp/jasper-os-qemu.lock \
  nice -n 10 taskset -c "$qemu_cpus" timeout 1200 \
  qemu-system-x86_64 -accel tcg -icount shift=0 \
  -drive format=raw,file="$out/kernel.img" -smp 8 -m "$qemu_memory" \
  -serial stdio -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial.log" 2>&1
rc=$?;set -e;printf '%s\n' "$rc" > "$out/exit.txt"
inputs > "$out/source-after.sha256";cmp "$out/source-before.sha256" "$out/source-after.sha256"
test "$rc" = 33
grep -aFq '[JSR-EVT2-BROADCAST] cpus=8 events=1000000 subscribers=7 all_final=true sequence=true bounded=true resources=true failed=0' "$out/serial.log"
for cpu in 1 2 3 4 5 6 7; do grep -aEq "^\[JSR-EVT2-BROADCAST-SUB\] cpu=$cpu final=1000000 resyncs=[0-9]+ continuous_or_resync=true" "$out/serial.log";done
! grep -aEq 'panicked|JSR-PANIC' "$out/serial.log"
touch "$out/PASS"

#!/usr/bin/env bash
# Author: chatgpt. Strict original nohz assertions; collect all presets even on failure.
set -euo pipefail
cd "$(dirname "$0")/.."
out="evidence/shm1/${1:?unique label}";mkdir "$out"
find kernel kernel-core .cargo -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum > "$out/source-before.sha256"
cargo build --locked --release -p xtask > "$out/build.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features s3-nohz-verify >> "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum "$out/kernel.img" > "$out/image.sha256"
failed=0
for preset in smp4 smp8 q35; do
 n=4;extra=();[[ "$preset" == smp8 ]] && n=8;[[ "$preset" == q35 ]] && extra=(-machine q35)
 set +e
 timeout 120 qemu-system-x86_64 -accel tcg -icount shift=5 -drive format=raw,file="$out/kernel.img" -smp "$n" -m 512M -serial stdio -display none -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 "${extra[@]}" > "$out/serial-$preset.log" 2>&1
 rc=$?;set -e;printf '%s\n' "$rc" > "$out/exit-$preset.txt"
 [[ "$rc" == 33 ]] || failed=1
 grep -aFq '[JSR-NOHZ-DIAGNOSTIC]' "$out/serial-$preset.log" || failed=1
 if grep -aEq 'reconciled=false|panicked' "$out/serial-$preset.log"; then failed=1;fi
done
find kernel kernel-core .cargo -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum > "$out/source-after.sha256"
cmp "$out/source-before.sha256" "$out/source-after.sha256"
printf 'diagnostic collection complete; original failures=%s\n' "$failed"
exit "$failed"

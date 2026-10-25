#!/usr/bin/env bash
# Author: chatgpt. Strict original nohz assertions; collect all presets even on failure.
set -euo pipefail
cd "$(dirname "$0")/.."
out="evidence/evt1/${1:?unique label}";mkdir "$out"
find kernel kernel-core .cargo -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum > "$out/source-before.sha256"
cargo build --locked --release -p xtask > "$out/build.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features evt2-verify >> "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum "$out/kernel.img" > "$out/image.sha256"
failed=0
for preset in single smp4 smp8; do
 n=4;extra=();[[ "$preset" == single ]] && n=1;[[ "$preset" == smp8 ]] && n=8
 set +e
 timeout 120 qemu-system-x86_64 -accel tcg -icount shift=5 -drive format=raw,file="$out/kernel.img" -smp "$n" -m 512M -device virtio-rng-pci -serial stdio -display none -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 "${extra[@]}" > "$out/serial-$preset.log" 2>&1
 rc=$?;set -e;printf '%s\n' "$rc" > "$out/exit-$preset.txt"
 [[ "$rc" == 33 ]] || failed=1
 grep -aFq '[JSR-EVT2-OBJECTS] snapshot=true broadcast=true overflow=true rights=true source_close=true exit=true quota_return=true resources=true failed=0' "$out/serial-$preset.log" || failed=1
 grep -aFq '[JSR-EVT2-RING] immediate=true parked=true batch=3 cancel=true busy_atomic=true sub_close=true source_close=true pins=true resources=true failed=0' "$out/serial-$preset.log" || failed=1
 grep -aFq '[JSR-EVT2-QUOTA] subscriptions=32 slots=512 refused=true atomic=true retry=true exit=true resources=true failed=0' "$out/serial-$preset.log" || failed=1
 grep -aFq '[JSR-EVT2-CPL3] source=true snapshot=true parked=true record=true late_snapshot=true rights=true exit=true resources=true failed=0' "$out/serial-$preset.log" || failed=1
 grep -aEq '\[JSR-EVT2-IRQ\] cpu=[0-9]+ delivered=true delta=1 snapshot_total=0 resources_cleanup=true' "$out/serial-$preset.log" || failed=1
 grep -aFq '[JSR-EVT2-PRESSURE] state=true normal_critical_normal=true ring=true unchanged_no_event=true resources=true failed=0' "$out/serial-$preset.log" || failed=1
 grep -aFq 'evt2 public_task_spawn=true public_process_spawn=true source_rights=true exit_event=true' "$out/serial-$preset.log" || failed=1
 if grep -aEq 'reconciled=false|panicked' "$out/serial-$preset.log"; then failed=1;fi
done
find kernel kernel-core .cargo -type d -name target -prune -o -type f -print0 | sort -z | xargs -0 sha256sum > "$out/source-after.sha256"
cmp "$out/source-before.sha256" "$out/source-after.sha256"
if [[ "$failed" == 0 ]]; then touch "$out/PASS"; fi
printf 'fixture failures=%s\n' "$failed"
exit "$failed"

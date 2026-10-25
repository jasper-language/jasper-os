#!/usr/bin/env bash
# Author: chatgpt。仅经绝对vm-run运行的独立事件等待机制guest，默认生产配置不变。
set -euo pipefail
cd "$(dirname "$0")/.."
label=${1:?unique evidence label}
[[ "$label" =~ ^[a-zA-Z0-9._-]+$ ]]
out="evidence/evt1/$label"
mkdir -p evidence/evt1
mkdir "$out"
inputs() { find kernel kernel-core user jaso modules xtask .cargo scripts -type d \( -name target -o -name __pycache__ \) -prune -o -type f -print0 | sort -z | xargs -0 sha256sum; sha256sum Cargo.toml Cargo.lock rust-toolchain.toml; }
inputs > "$out/source-before.sha256"
cargo build --locked --release -p xtask > "$out/xtask.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features evt1-verify > "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum "$out/kernel.img" target/x86_64-unknown-none/release/jasper-kernel > "$out/artifacts.sha256"
for n in 1 4 8; do
    start=$(date +%s%N)
    set +e
    clock_args=(-icount shift=0)
    if [ "$n" = 1 ]; then clock_args=(-icount shift=5,sleep=on,align=on); fi
    timeout 300 qemu-system-x86_64 -accel tcg "${clock_args[@]}" -drive format=raw,file="$out/kernel.img" -smp "$n" -m 512M -serial stdio -display none -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial-$n.log" 2>&1
    rc=$?
    set -e
    printf '%s\n' "$rc" > "$out/exit-$n.txt"
    printf '%s %s\n' "$start" "$(date +%s%N)" > "$out/host-window-$n.txt"
    test "$rc" = 33
    grep -aEq '^\[JSR-EVT1-IDLE\] waiters=1000 registered=1000 ticks=[0-9]+ hz=100 invalid_resumes=0 clock=guest_ticks' "$out/serial-$n.log"
    for c in 0 1 2 3; do grep -aEq "^\[JSR-EVT1-CASE\] case=$c .*resources=true failed=0" "$out/serial-$n.log"; done
    grep -aFq '[JSR-EVT1-EXIT] failed=0' "$out/serial-$n.log"
    ! grep -aEq 'panicked|JSR-EVT1-FAIL' "$out/serial-$n.log"
done
inputs > "$out/source-after.sha256"
cmp "$out/source-before.sha256" "$out/source-after.sha256"
printf 'PASS\n' > "$out/PASS"

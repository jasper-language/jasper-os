#!/usr/bin/env bash
# Author: chatgpt。仅经绝对vm-run运行的独立共享页保活guest，默认生产配置不变。
set -euo pipefail
cd "$(dirname "$0")/.."
label=${1:?unique evidence label}
[[ "$label" =~ ^[a-zA-Z0-9._-]+$ ]]
out="evidence/shm1/$label"
mkdir -p evidence/shm1
mkdir "$out"
inputs() { find kernel kernel-core abi user jaso modules xtask .cargo scripts -type d \( -name target -o -name __pycache__ \) -prune -o -type f -print0 | sort -z | xargs -0 sha256sum; sha256sum Cargo.toml Cargo.lock rust-toolchain.toml; }
inputs > "$out/source-before.sha256"
cargo build --locked --release -p xtask > "$out/xtask.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel --features shm1-verify > "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum "$out/kernel.img" target/x86_64-unknown-none/release/jasper-kernel > "$out/artifacts.sha256"
for n in 1 4 8; do
    start=$(date +%s%N)
    set +e
    clock_args=(-icount shift=5)
    if [ "$n" = 1 ]; then clock_args=(-icount shift=5,sleep=on,align=on); fi
    timeout 300 qemu-system-x86_64 -accel tcg "${clock_args[@]}" -drive format=raw,file="$out/kernel.img" -smp "$n" -m 512M -serial stdio -display none -monitor none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial-$n.log" 2>&1
    rc=$?
    set -e
    printf '%s\n' "$rc" > "$out/exit-$n.txt"
    printf '%s %s\n' "$start" "$(date +%s%N)" > "$out/host-window-$n.txt"
    test "$rc" = 33
    grep -aEq "^\[JSR-S3-CHANNEL\] rounds=32 ping_cpu=0 pong_cpu=[01] cpl3=true rights=true transfer=true unmap=true exits=true resources=true failed=0" "$out/serial-$n.log"
    grep -aFq '[JSR-S3-SEQUENCE] rounds=64 steps=16 seed=53485f5345435552 warmup=1 measured=1 rights=true transfer=true pins=true exits=true resources=true failed=0' "$out/serial-$n.log"
    grep -aFq '[JSR-SHM1-BACKING] shared=true rights=true transfer=true revoke=true pin_survives=true resources=true quota=true creator_exit=true failed=0' "$out/serial-$n.log"
    grep -aEq '^\[JSR-SHM1-PIN-QUOTA\] live=8192 refused=true atomic=true returned=true resources=true warmup=1 measured=1 failed=0' "$out/serial-$n.log"
    grep -aFq '[JSR-SHM1-PRIVATE] anonymous=true loader=true pin_after_exit=true resources=true failed=0' "$out/serial-$n.log"
    grep -aFq '[JSR-SHM1-PIN-METADATA] refused=true atomic=true retry=true resources=true failed=0' "$out/serial-$n.log"
    if [ "$n" != 1 ]; then
        grep -aFq "[JSR-S3-CONCURRENT] mapper_cpu=0 revoker_cpu=1 map_attempts=64 pin_attempts=128 warmup=1 measured=1 exits=true retained=true resources=true failed=0" "$out/serial-$n.log"
        grep -aFq '[JSR-SHM1-REVOKE] writer_cpu=0 reader_cpu=1 target_included=true post_ack_fault=true resources=true failed=0' "$out/serial-$n.log"
    fi
    for c in 0 1 2; do
        expected=1; [ "$c" = 1 ] && expected=0
        grep -aFq "[JSR-SHM1-FAILURE] case=$c isolated=$expected expected=$expected resources=true failed=0" "$out/serial-$n.log"
    done
    ! grep -aEq 'panicked|SHM backing fixture:' "$out/serial-$n.log"
done
inputs > "$out/source-after.sha256"
cmp "$out/source-before.sha256" "$out/source-after.sha256"
printf 'PASS\n' > "$out/PASS"

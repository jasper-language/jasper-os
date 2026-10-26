#!/usr/bin/env bash
# Author: chatgpt. Focused KRN-3 correctness/ledger guest; TCG timings are relative only.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS=1

sample=${1:?sample label}; shift
(( $# > 0 ))
[[ "$sample" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]
out="evidence/krn3/$sample"
mkdir -p evidence/krn3
mkdir "$out"

manifest_inputs() {
    find kernel kernel-core user jaso modules xtask tools/jasopack abi .cargo scripts \
      -type d \( -name target -o -name __pycache__ \) -prune -o -type f -print0 \
      | LC_ALL=C sort -z | xargs -0 sha256sum
    sha256sum Cargo.toml Cargo.lock rust-toolchain.toml
}

manifest_inputs > "$out/source-before.sha256"
{ rustc -Vv; cargo -V; qemu-system-x86_64 --version; } > "$out/tool-versions.txt" 2>&1
printf 'fixture=krn3-postsplit\nclock=TCG-single-icount-shift5\n' > "$out/config.txt"
cargo build --locked --release -p xtask > "$out/xtask.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel \
  --no-default-features --features krn3-postsplit-verify,krn2-observe > "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum kernel/src/scale_demo.rs kernel/src/sched/scheduler.rs \
  target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/hashes.txt"
manifest_inputs > "$out/source-after-build.sha256"
cmp "$out/source-before.sha256" "$out/source-after-build.sha256"

for n in "$@"; do
    case "$n" in 4|8) ;; *) exit 2;; esac
    truncate -s 16M "$out/blank-$n.img"
    set +e
    timeout 300 qemu-system-x86_64 -accel tcg,thread=single -icount shift=5,sleep=off \
      -drive "format=raw,file=$out/kernel.img" -device virtio-rng-pci \
      -device virtio-net-pci,netdev=n0 -netdev user,id=n0 \
      -device virtio-blk-pci,drive=d1 -drive "if=none,id=d1,file=$out/blank-$n.img,format=raw" \
      -smp "$n" -m 256M -serial stdio -display none -monitor none -no-reboot \
      -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial-$n.log" 2>&1
    result=$?
    set -e
    echo "$result" > "$out/exit-$n.txt"
    [[ "$result" == 33 || "$result" == 37 ]]
    grep -aEq '^\[JSR-KRN3-POSTSPLIT\] done failed=0 timing_failed=[0-9]+' "$out/serial-$n.log"
    grep -aEq '^\[JSR-SCALE\] summary .*reclaimed=true .*failed=0' "$out/serial-$n.log"
    grep -aEq '^\[JSR-SYNC-WORK\].*bounded=true' "$out/serial-$n.log"
    grep -aEq '^\[JSR-RAW-WAKE\] samples=[1-9][0-9]* .*valid=true .*endpoint=resume-hook' "$out/serial-$n.log"
    ! grep -aq '^\[JSR-EXIT\] failure' "$out/serial-$n.log"
    grep -aE '^\[JSR-(KRN3-POSTSPLIT|SYNC-WORK|RAW-WAKE|SCALE).*' "$out/serial-$n.log" | tail -12
done

manifest_inputs > "$out/source-after-run.sha256"
cmp "$out/source-before.sha256" "$out/source-after-run.sha256"
touch "$out/PASS"

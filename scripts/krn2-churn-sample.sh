#!/usr/bin/env bash
# Author: chatgpt. VM-only deterministic functional samples, NOT parallel scaling evidence.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS=1
sample=${1:?sample label}; shift
(( $# > 0 ))
[[ "$sample" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]
out="evidence/krn2/$sample"
mkdir -p evidence/krn2
mkdir "$out"
# Author: chatgpt. Freeze the named build-input scope before any compilation.
# Excludes outputs/caches; Cargo registry/toolchain contents are not vendored here.
manifest_inputs() {
    find kernel kernel-core user jaso modules xtask tools/jasopack abi .cargo scripts \
      -type d \( -name target -o -name __pycache__ \) -prune -o -type f -print0 \
      | LC_ALL=C sort -z | xargs -0 sha256sum
    sha256sum Cargo.toml Cargo.lock rust-toolchain.toml
}
manifest_inputs > "$out/source-before.sha256"
{ rustc -Vv; cargo -V; qemu-system-x86_64 --version; } > "$out/tool-versions.txt" 2>&1
cargo build --locked --release -p xtask > "$out/xtask.log" 2>&1
extra=()
case "${KRN2_OBSERVE:-0}" in 0) ;; 1) extra=(--features krn2-observe);; *) exit 2;; esac
printf 'krn2_observe=%s\nclock=TCG-single-icount-shift5\n' "${KRN2_OBSERVE:-0}" > "$out/config.txt"
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel "${extra[@]}" > "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/image.log" 2>&1
sha256sum kernel/src/scale_demo.rs target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.img" > "$out/hashes.txt"
manifest_inputs > "$out/source-after-build.sha256"
cmp "$out/source-before.sha256" "$out/source-after-build.sha256"
sha256sum "$out/source-before.sha256" "$out/tool-versions.txt" "$out/config.txt" > "$out/identity.sha256"
for n in "$@"; do
    case "$n" in 1|4|8) ;; *) exit 2;; esac
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
    case "$n" in 1) mask=1;; 4) mask=f;; 8) mask=ff;; esac
    grep -aEq "^\[JSR-CHURN-BARRIER\] ready=$n/$n done=$n/$n mask=0x$mask rounds=2000" "$out/serial-$n.log"
    ! grep -aq '^\[JSR-EXIT\] failure' "$out/serial-$n.log"
    if [[ "${KRN2_OBSERVE:-0}" == 1 ]]; then
        grep -aEq '^\[JSR-PI-WORK\] scope=boot calls=[1-9][0-9]* .*overflow=false' "$out/serial-$n.log"
        grep -aEq '^\[JSR-PI-WORK\] scope=churn calls=[0-9]+ .*overflow=false' "$out/serial-$n.log"
        grep -a '^\[JSR-PI-WORK\]' "$out/serial-$n.log"
        grep -aEq '^\[JSR-SYNC-WORK\].*covered=true' "$out/serial-$n.log"
        grep -aEq '^\[JSR-RAW-CALLBACK\] samples=[1-9][0-9]* .*valid=true' "$out/serial-$n.log"
        grep -aEq '^\[JSR-RAW-WAKE\] samples=[1-9][0-9]* .*valid=true .*endpoint=resume-hook' "$out/serial-$n.log"
    fi
    grep -aE 'JSR-CHURN-BARRIER|JSR-SYNC-WORK|JSR-SCALE.*lock name=|JSR-EXIT' "$out/serial-$n.log" | tail -5
done

# A successful batch must still have exactly the frozen named source inputs.
manifest_inputs > "$out/source-after-run.sha256"
cmp "$out/source-before.sha256" "$out/source-after-run.sha256"

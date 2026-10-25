#!/usr/bin/env bash
# Execute inside the build VM via vm-run.sh; never writes a physical disk.
set -euo pipefail
cd "$(dirname "$0")/.."
# Instruction-count virtual time avoids keeping all build-VM vCPUs spinning.
# This is a correctness run, not a performance measurement.
export BM1_ICOUNT="${BM1_ICOUNT:-5}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export PATH="$HOME/.cargo/bin:$PATH"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="evidence/bm1-$stamp"
mkdir -p "$out" images
python3 -m unittest discover -s tools/bm1 -p 'test_*.py' -v > "$out/protocol-tests.log" 2>&1
bash verification/run-bm1-tlc.sh > "$out/tlc.log" 2>&1
cargo test -p kernel-core > "$out/kernel-core-tests.log" 2>&1
cargo build --release -p xtask > "$out/build.log" 2>&1
cargo build --release --target x86_64-unknown-none -p jasper-kernel --features bm1-hang >> "$out/build.log" 2>&1
cp target/x86_64-unknown-none/release/jasper-kernel "$out/hang.elf"
target/release/xtask uefi "$out/hang.elf" "$out/hang.img" >> "$out/build.log" 2>&1
python3 tools/bm1/run.py --image "$out/hang.img" --out "$out/watchdog" --boots 1 --hang --timeout 120 | tee "$out/watchdog.log"
cargo build --release --target x86_64-unknown-none -p jasper-kernel --features bm1-vm >> "$out/build.log" 2>&1
cp target/x86_64-unknown-none/release/jasper-kernel "$out/kernel.elf"
target/release/xtask uefi "$out/kernel.elf" "$out/uefi.img" >> "$out/build.log" 2>&1
python3 tools/bm1/run.py --image "$out/uefi.img" --out "$out/boots" --boots "${BM1_BOOTS:-10}" --timeout "${BM1_TIMEOUT:-900}" | tee "$out/boots.log"
# Multicore coverage is additional to the ten persistent single-core boots.
python3 tools/bm1/run.py --image "$out/uefi.img" --out "$out/smp4" --boots 1 --cpus 4 --timeout "${BM1_TIMEOUT:-900}" | tee "$out/smp4.log"
# Negative control: actual functional assertion failure must be rejected.
cargo build --release --target x86_64-unknown-none -p jasper-kernel --features bm1-vm,selftest-inject-failure >> "$out/build.log" 2>&1
target/release/xtask uefi target/x86_64-unknown-none/release/jasper-kernel "$out/functional-failure.img" >> "$out/build.log" 2>&1
set +e
python3 tools/bm1/run.py --image "$out/functional-failure.img" --out "$out/reject-failure" --boots 1 --timeout "${BM1_TIMEOUT:-900}" > "$out/reject-failure.log" 2>&1
reject_rc=$?
set -e
[ "$reject_rc" -ne 0 ]
grep -aEq '^\[JSR-EXIT\] failure .*scale_failed=1' "$out/reject-failure/serial.log"
grep -aq '^\[BM1\] selftest=FAIL' "$out/reject-failure/serial.log"
grep -aq 'kernel selftest or framebuffer failure' "$out/reject-failure.log"
[ -s "$out/reject-failure/boot-01.udp.log" ]
# Default BIOS/full correctness coverage uses the same deterministic clock.
# Keep the kernel feature set at its default; no BM-1 driver is enabled here.
JASPER_ACCEL=tcg,thread=single JASPER_QEMU_EXTRA="-icount shift=${BM1_ICOUNT},sleep=off" \
    JASPER_KEEP_AWAKE=0 bash scripts/accept.sh > "$out/default-full-icount.log" 2>&1
printf 'BM-1 VM acceptance complete: %s\n' "$out"

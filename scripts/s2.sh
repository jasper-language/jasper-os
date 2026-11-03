#!/usr/bin/env bash
# S-2: fixed-seed concurrent syscall campaign and fault-path audit.
# VM only. Produces raw serial/QEMU evidence; no log is synthesized.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH" CARGO_BUILD_JOBS=1
out="${S2_OUT:-evidence/s2}"
mkdir -p "$out"
# Author: chatgpt. Keep the generalized main-side campaign, default to the
# stricter eight-CPU integration scope while allowing an explicit four-CPU run.
cpus=${S2_CPUS:-8}
case "$cpus" in
  4) workers=4; probes=250000; mask=f ;;
  8) workers=8; probes=125000; mask=ff ;;
  *) echo 'S2_CPUS must be 4 or 8' >&2; exit 2 ;;
esac

# Shared seed/replay contract (host, no QEMU).
cargo test -p kernel-core --test s2_streams > "$out/streams.log" 2>&1
cargo test -p kernel-core --test krn1_fault > "$out/fault.log" 2>&1

# Protocol models: positive configuration must pass; the old MMIO behavior must
# still produce the named stale-reuse counterexample.
bash verification/run-mmio-tlc.sh > "$out/mmio-tlc.log" 2>&1
set +e
bash verification/run-mmio-tlc.sh mmio_rollback_negative.cfg > "$out/mmio-negative.log" 2>&1
negative_rc=$?
set -e
[[ "$negative_rc" != 0 ]]
grep -q 'Invariant NoStaleReuse is violated' "$out/mmio-negative.log"
bash verification/run-tlb-start-tlc.sh > "$out/tlb-start-tlc.log" 2>&1
bash verification/run-fault-tlc.sh > "$out/fault-tlc.log" 2>&1
bash verification/run-tlb-quarantine-tlc.sh > "$out/tlb-quarantine-tlc.log" 2>&1
set +e
bash verification/run-tlb-quarantine-tlc.sh tlb_timeout_quarantine_negative.cfg > "$out/tlb-quarantine-negative.log" 2>&1
quarantine_negative_rc=$?
set -e
[[ "$quarantine_negative_rc" != 0 ]]
grep -q 'Invariant NoReleaseWhileStale is violated' "$out/tlb-quarantine-negative.log"

# Dedicated image with the explicit campaign and fault hooks.
cargo build --locked --release -p xtask > "$out/xtask.log" 2>&1
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel \
  --features s2-only > "$out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$out/s2.img" > "$out/image.log" 2>&1
truncate -s 16M "$out/blank.img"

# Four/eight pinned workers; per-worker shares always total 1,000,000 probes.
set +e
# True parallel vCPUs are required: a single-threaded TCG scheduler can strand
# spinlock waiters across eight vCPUs even when every worker is runnable.
# The eight-CPU campaign takes about 29 minutes under TCG in the build VM.
timeout "${S2_QEMU_TIMEOUT:-2400}" qemu-system-x86_64 -accel tcg \
  -drive "format=raw,file=$out/s2.img" -device virtio-rng-pci \
  -device virtio-net-pci,netdev=n0 -netdev user,id=n0 \
  -device virtio-blk-pci,drive=d1 -drive "if=none,id=d1,file=$out/blank.img,format=raw" \
  -smp "$cpus" -m 256M -serial stdio -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$out/serial.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" > "$out/qemu-exit.txt"
[[ "$rc" == 33 || "$rc" == 37 ]]

# Every panic remains fatal in the dedicated S-2 guest.
if grep -aE 'panicked at|KERNEL PANIC|^\[JSR-PANIC\]' "$out/serial.log" | grep -avE '^\[JSR-USERTEXT\] task=rt-panic bytes=[0-9]+ text=panic: panicked at user/rtdemo/src/main.rs:[0-9]+:[0-9]+:'; then
  echo 'unexpected panic in S-2' >&2
  exit 1
fi
if grep -aq '^\[JSR-EXIT\] failure' "$out/serial.log"; then exit 1; fi

# Four fixed streams, three of the four fault sites exercised before the campaign.
grep -aq '^\[JSR-FAULT\] sites=4 .*frame_conserved=true heap_conserved=true failed=0' "$out/serial.log"
[[ "$(grep -ac '^\[JSR-S2\] worker=' "$out/serial.log")" == "$workers" ]]
[[ "$(grep -a '^\[JSR-S2\] worker=' "$out/serial.log" | sed -E 's/.*seed=(0x[0-9a-f]+).*/\1/' | sort -u | wc -l)" == "$workers" ]]
grep -aEq "^\[JSR-S2\] summary workers=$workers/$workers probes=1000000 calls=[0-9]+ cpu_mask=0x$mask .*reclaimed=true passed=true" "$out/serial.log"
[[ "$(grep -ac "robust: done calls=$probes .*failed=0" "$out/serial.log")" == "$workers" ]]

# Fault-path audit: MMIO rollback timeout, four process error cases, DMA unknown readback.
grep -aq '^\[JSR-S2-MMIO\] zero=true rollback=true timeout=true quarantined=true recovery=true frames_conserved=true intentional_slot_quarantine=1 passed=true' "$out/serial.log"
[[ "$(grep -ac '^\[JSR-S2-ERROR\] case=.*passed=true' "$out/serial.log")" == 4 ]]
[[ "$(grep -ac '^\[JSR-S2-ERROR\] case=[23] .*quarantine=2 reclaimed=true passed=true' "$out/serial.log")" == 2 ]]
grep -aq '^\[JSR-S2-QUARANTINE\] total=4 intentional=true' "$out/serial.log"
grep -aq '^\[JSR-S2-DMA\] readback=unavailable bus_master_off=true missing=4 quarantine=4 intentional=true passed=true' "$out/serial.log"

# Scheduler contracts removed from the dedicated guest above still need a checker:
# run scale_demo alone with fault hooks, which also reaches the full-mailbox and
# delayed-deadline paths that exist only under fault-inject.
scale_out="$out/fault-scale"
mkdir -p "$scale_out"
cargo build --locked --release --target x86_64-unknown-none -p jasper-kernel \
  --features krn3-postsplit-verify,fault-inject > "$scale_out/build.log" 2>&1
target/release/xtask target/x86_64-unknown-none/release/jasper-kernel "$scale_out/s2.img" > "$scale_out/image.log" 2>&1
set +e
timeout "${S2_QEMU_TIMEOUT:-600}" qemu-system-x86_64 -accel tcg \
  -drive "format=raw,file=$scale_out/s2.img" -smp "$cpus" -m 256M \
  -serial stdio -display none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 > "$scale_out/serial.log" 2>&1
rc=$?
set -e
printf '%s\n' "$rc" > "$scale_out/qemu-exit.txt"
[[ "$rc" == 33 || "$rc" == 37 ]]
if grep -aE 'panicked at|KERNEL PANIC|^\[JSR-PANIC\]' "$scale_out/serial.log"; then
  echo 'unexpected panic in S-2 scheduler contracts' >&2
  exit 1
fi
grep -aEq '^\[JSR-KRN3-POSTSPLIT\] done failed=0 timing_failed=[0-9]+' "$scale_out/serial.log"
grep -aq '^\[JSR-TASK-INDEX\] duplicate=true unchanged=true reused=true reclaimed=true' "$scale_out/serial.log"
grep -aEq '^\[JSR-WAKE-MSG\] routed=[1-9][0-9]* timely=true returned=true reclaimed=true' "$scale_out/serial.log"
grep -aq '^\[JSR-DEADLINE-OWNER\] registered=true moved=true target=2 consumed=true ran=true reclaimed=true' "$scale_out/serial.log"
grep -aq '^\[JSR-RT-LOCAL\] exhausted=true refilled=true disabled=true reclaimed=true' "$scale_out/serial.log"
grep -aEq '^\[JSR-BUDGET-TICK\] tick_path_rt=[0-9]+ tick_path_shared=[0-9]+ rt_exhausted=true used=[1-9][0-9]* group_throttle_events=[0-9]+ scheduler_throttles=[1-9][0-9]* configured=true reclaimed=true' "$scale_out/serial.log"
grep -aq '^\[JSR-WAKE-FULL\] queued=16 fallback=1 returned=17/17 timely=true reclaimed=true' "$scale_out/serial.log"
grep -aEq '^\[JSR-DEADLINE-IPI\] .*stopped=true ipis=[1-9][0-9]* cpu=2 linked=true' "$scale_out/serial.log"

echo 'S-2 million-probe campaign PASS; quarantine and fault-path evidence recorded'

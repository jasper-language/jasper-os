# Timer forward-progress multicore repair

Date: 2026-11-18.

## Failure

The previous gate used an arbitrary 1200-line endpoint. After newer SMP and
device tests were added, the hidden 8-vCPU failure moved from the original
timer livelock into unrelated virtio-blk work. A sub-tick high-resolution
retry could also re-enter before the interrupted instruction retired under
`-icount`.

## Fix

- Deferred local-timer retries wait at least one normal timer period.
- Userspace and POSIX deadlines are settled only after a complete timer
  transaction is admitted.
- `boot-trace.py` supports a semantic marker endpoint with the line limit kept
  as a fallback.
- `TIMER-PROGRESS` now requires every case to complete the SMP concurrency
  checks and enter real DRV-3 DMA. Later block-I/O and full acceptance remain
  separate gates.

## Result

```text
cpus=1 shift=5  PASS lines=633 stop=marker
cpus=1 shift=6  PASS lines=612 stop=marker
cpus=1 shift=7  PASS lines=626 stop=marker
cpus=1 shift=8  PASS lines=623 stop=marker
cpus=1 shift=9  PASS lines=609 stop=marker
cpus=1 shift=10 PASS lines=635 stop=marker
cpus=4 shift=9  PASS lines=677 stop=marker
cpus=8 shift=9  PASS lines=757 stop=marker
```

The 4-vCPU run completed in 20 seconds and the 8-vCPU run in 56 seconds.

```text
cargo test --locked -p kernel-core timer_progress
4 passed; 0 failed

python3 -m py_compile scripts/boot-trace.py
bash -n scripts/timer-progress-check.sh
PASS
```

This is QEMU regression evidence, not physical-hardware qualification.

# AMD Ryzen 7 5700X concurrent physical baseline

Date: 2026-11-24

This directory preserves the final screen and boot artifacts from the
development-stage 8-core and 16-thread physical test. The result is a
measurement baseline, not a final-product performance claim or a completed
performance-acceptance gate.

## Artifacts

```text
kernel-x86_64
4d5e0533eb80a9605dad5d720aa1fcc31cd88e7184e79a89af93c33dc7a8c538

bootloader.efi
ca9efd24a143dc6e04a505f2d9c535869a8161c7cdd1811b69a303672827193d

final-screen.jpeg
c709e5a7dd9b0eafd5d3aab42db67a404e69aaf3ff0b1e824ed15c4d6c3ad27e
```

## Observed result

- Physical topology: 1 package, 8 physical cores, 16 logical CPUs.
- Firmware discovery/admission/online state: 16/16/16.
- Both 8P and 16T modes executed 14 scalar benchmark projects and attempted
  `SCHED.CONTEXT_SWITCH`.
- The 8P mode retained 120,000,000 raw samples; the 16T mode retained
  240,000,000 raw samples.
- `SCHED.CONTEXT_SWITCH` was blocked in both modes with
  `SPAWNED=TRUE`, all expected tasks reaching the barrier, `DONE=TRUE`, and
  `MISSED=TRUE`.
- The final status was `FAILED=3`, `TIMING_FAILED=0`, `CHECKS=31`,
  `RECLAIMED=false`.

The final screen also contains a legacy diagnostic footer,
`SMP PERFORMANCE MATRIX ONLINE=16 RECORDS=0 FAILED_RUNS=0`. It came from the
older matrix reporter and is not a result row; the actual `SMP8P` and `SMP16T`
measurements appear above it.

The full measured tables, exclusions and known limitations are maintained in
the repository root [`README.md`](../../README.md).

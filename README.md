# Jasper-OS

Jasper-OS is a native operating system written in Rust, with a language-neutral
system execution environment and separate native ABI layers for supported
architectures.

## AMD Ryzen 7 5700X physical development baseline

This is a development-stage baseline collected from Jasper-OS running directly
on physical hardware over UEFI PXE. It is not a final-product performance
claim. The round is now closed; performance optimization is deferred until the
planned functional DAG is complete.

### Hardware and test environment

| Item | Value |
| --- | --- |
| Date | 2026-11-24 |
| CPU | AMD Ryzen 7 5700X, Zen 3 |
| Topology | 1 package, 8 physical cores, 16 logical processors |
| Firmware CPU discovery | 16 enabled CPUs discovered, 16 online |
| Concurrent participants | 8 physical cores and 16 logical CPUs |
| Execution | AMD x86_64 physical hardware, UEFI PXE |
| Timer | 100 Hz system timer; calibrated TSC |
| Usable RAM | 16302 MiB |
| Initial single-CPU physical-memory use | 13684 KiB (about 13.36 MiB) |
| Concurrent sample allocation | 64 MiB for 8P, 128 MiB for 16T |
| Kernel image SHA-256 | `4d5e0533eb80a9605dad5d720aa1fcc31cd88e7184e79a89af93c33dc7a8c538` |
| Bootloader SHA-256 | `ca9efd24a143dc6e04a505f2d9c535869a8161c7cdd1811b69a303672827193d` |

The concurrent figures describe temporary memory used while retaining raw
samples. They are not the idle/native memory footprint of Jasper-OS.

### Measurement method

- Formal projects retain 1,000,000 one-operation samples per participating CPU.
- In an SMP run, all selected CPUs execute the same project concurrently.
- Percentiles are calculated from the combined raw samples of every
  participating CPU; per-CPU percentile values are not averaged.
- `CURRENT` and `U64-REFERENCE` SyscallSet/Spawn variants remain separate rows.
- Human-readable output is rendered directly to the physical framebuffer.
- QEMU/OVMF is a control environment only and is never substituted for a
  physical result.

### Single-CPU baseline

| Benchmark | P50 | P99 | P99.9 | MAX |
| --- | ---: | ---: | ---: | ---: |
| Timer read overhead | 20 ns | 20 ns | 20 ns | 109.071 μs |
| Physical frame allocation | 722 ns | 732 ns | 732 ns | 87.278 μs |
| Physical frame release | 742 ns | 742 ns | 752 ns | 86.877 μs |
| 64-byte heap allocate/free | 1.434 μs | 1.444 μs | 1.444 μs | 87.399 μs |
| 4096-byte heap allocate/free | 1.434 μs | 1.444 μs | 1.444 μs | 87.991 μs |
| SyscallSet contains | 20 ns | 20 ns | 20 ns | 68.727 μs |
| SyscallSet subset test | 20 ns | 20 ns | 20 ns | 3.481 μs |
| SyscallSet copy | 20 ns | 20 ns | 20 ns | 64.744 μs |
| Spawn descriptor decode | 30 ns | 30 ns | 30 ns | 79.031 μs |
| Scheduler context switch | 6.085 μs | 6.165 μs | 6.220 μs | 65.948 μs |

### 8 physical cores

Each row combines 8,000,000 raw samples from the eight physical cores.

| Benchmark | P50 | P99 | P99.9 | P99.99 |
| --- | ---: | ---: | ---: | ---: |
| Timer read overhead | 40 ns | 40 ns | 40 ns | 40 ns |
| Physical frame allocation | 6.361 μs | 7.042 μs | 7.342 μs | 126.389 μs |
| Physical frame release | 6.361 μs | 7.042 μs | 7.342 μs | 126.389 μs |
| 64-byte heap allocate/free | 6.901 μs | 7.362 μs | 7.583 μs | not readable in captured screen |
| 4096-byte heap allocate/free | 6.901 μs | 7.362 μs | 7.583 μs | not readable in captured screen |
| SyscallSet contains, CURRENT | 20 ns | 20 ns | 20 ns | 20 ns |
| SyscallSet contains, U64-REFERENCE | 20 ns | 20 ns | 20 ns | 30 ns |
| SyscallSet subset, CURRENT | 20 ns | 20 ns | 20 ns | 30 ns |
| SyscallSet subset, U64-REFERENCE | 20 ns | 20 ns | 20 ns | 30 ns |
| SyscallSet copy, CURRENT | 20 ns | 20 ns | 20 ns | 20 ns |
| SyscallSet copy, U64-REFERENCE | 20 ns | 20 ns | 20 ns | 30 ns |
| Spawn descriptor decode, CURRENT | 30 ns | 30 ns | 30 ns | 40 ns |
| Spawn calls decode, CURRENT | 20 ns | 20 ns | 30 ns | 30 ns |
| Spawn calls decode, U64-REFERENCE | 20 ns | 20 ns | 20 ns | 20 ns |
| Scheduler context switch | BLOCKED | BLOCKED | BLOCKED | BLOCKED |

### 16 logical CPUs

Each row combines 16,000,000 raw samples from the sixteen logical CPUs.

| Benchmark | P50 | P99 | P99.9 | P99.99 |
| --- | ---: | ---: | ---: | ---: |
| Timer read overhead | 40 ns | 40 ns | 40 ns | 40 ns |
| Physical frame allocation | 15.617 μs | 16.789 μs | 17.640 μs | not readable in captured screen |
| Physical frame release | 15.617 μs | 16.789 μs | 17.640 μs | not readable in captured screen |
| 64-byte heap allocate/free | 14.244 μs | 15.176 μs | 15.717 μs | not readable in captured screen |
| 4096-byte heap allocate/free | 14.244 μs | 15.176 μs | 15.717 μs | not readable in captured screen |
| SyscallSet contains, CURRENT | 20 ns | 20 ns | 20 ns | 20 ns |
| SyscallSet contains, U64-REFERENCE | 20 ns | 30 ns | 30 ns | 30 ns |
| SyscallSet subset, CURRENT | 20 ns | 20 ns | 20 ns | 20 ns |
| SyscallSet subset, U64-REFERENCE | 20 ns | 30 ns | 30 ns | 30 ns |
| SyscallSet copy, CURRENT | 20 ns | 20 ns | 20 ns | 20 ns |
| SyscallSet copy, U64-REFERENCE | 30 ns | 30 ns | 30 ns | 30 ns |
| Spawn descriptor decode, CURRENT | 40 ns | 40 ns | 40 ns | 50 ns |
| Spawn calls decode, CURRENT | 20 ns | 20 ns | 30 ns | 30 ns |
| Spawn calls decode, U64-REFERENCE | 20 ns | 20 ns | 20 ns | 20 ns |
| Scheduler context switch | BLOCKED | BLOCKED | BLOCKED | BLOCKED |

P99.999, MAX and threshold counts were present in the runtime report path, but
the supplied physical-screen capture clipped them for most concurrent rows.
They are intentionally not reconstructed or inferred in this README.

### Passed, blocked and known issues

Passed in this physical round:

- Physical CPU discovery and admission of 8 cores and 16 logical CPUs.
- Concurrent execution and raw-sample collection for 14 scalar projects in
  both 8P and 16T modes.
- Separation of `CURRENT` and `U64-REFERENCE` comparison variants.
- Nanosecond/microsecond unit handling on the physical framebuffer.

Blocked or not passed:

- `SCHED.CONTEXT_SWITCH` in both modes reported
  `BLOCKED ... DONE=TRUE MISSED=TRUE`; no context-switch timing table is claimed.
- Both mode results reported `COMPLETE=FALSE`.
- The run reported `FAILED=3`, `RECLAIMED=false` and `CHECKS=31` with
  `TIMING_FAILED=0`.
- The result set is therefore a development measurement baseline, not a
  completed performance-acceptance gate.

Known performance issues:

- Frame and heap operations rise substantially from the single-CPU baseline
  under 8P and 16T concurrency.
- Some 8P scalar paths show long-tail P99.99 spikes separated sharply from P99.
- Context-switch synchronization did not produce a valid concurrent result.
- Raw-sample retention costs 64 MiB for 8P and 128 MiB for 16T during this
  benchmark.

These issues are deferred to the later performance and capacity governance
phase. This round does not change architecture, acceptance criteria, native
framework boundaries, Wine compatibility, or Metal2Vulkan requirements.

### Evidence and next phase

The physical artifact set and checksums are archived in
[`evidence/amd-smp-concurrent-physical-20261124`](evidence/amd-smp-concurrent-physical-20261124).
Detailed AMD topology and SMP bring-up findings remain in
[`evidence/amd-cpu-topology-20261124/README.md`](evidence/amd-cpu-topology-20261124/README.md).

Physical testing for this phase is closed. Development returns to QEMU/KVM and
continues the existing DAG, including the remaining Wine and Metal2Vulkan
compatibility work. No performance optimization is part of that continuation.

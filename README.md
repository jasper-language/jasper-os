# Jasper-OS

Jasper-OS is a native operating system written in Rust, with a language-neutral
system execution environment and separate native ABI layers for supported
architectures.

## AMD Ryzen 7 5700X physical performance baseline

This baseline was collected from Jasper-OS running directly on an AMD Ryzen 7
5700X physical machine over UEFI PXE. The benchmark profile admitted only the
bootstrap processor for this run. These values are a valid uniprocessor
baseline and must not be presented as 16-thread SMP performance.

### Environment

| Item | Value |
| --- | --- |
| Date | 2026-11-24 |
| CPU | AMD Ryzen 7 5700X, Zen 3 |
| Topology | 1 package, 8 physical cores, 16 logical processors |
| Benchmark CPUs | BSP only: 1 online, 1 participating |
| Execution | AMD x86_64 physical hardware, UEFI PXE |
| Timer | 100 Hz system timer; calibrated TSC |
| Usable RAM reported by the benchmark image | 16302 MiB |
| Sample target | 1,000,000 samples for each formal microbenchmark |
| Kernel image SHA-256 | `45af4bad8932c007aa8289a437902b0c442d51ce9042dc270d9d0a842026db5e` |

### Results

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

### Interpretation

- Values are calibrated physical-hardware measurements, not QEMU/TCG values.
- Sub-microsecond values are retained in nanoseconds or microseconds; zero
  counter intervals are reported as below timer resolution rather than as a
  false zero-latency result.
- The approximately 65-109 μs maxima show that tail spikes remain material
  even when P99 is close to P50. This table does not claim a spike cause.
- The P99.99 and P99.999 values and threshold counts were not included in the
  supplied physical result table and are therefore not inferred here.
- Full SMP, all-physical-core, all-logical-thread, NUMA, IPI, cache/TLB and
  contention matrices remain separate acceptance requirements. Passing this
  BSP-only baseline does not close them.

### Reproducibility

The benchmark is selected with the dedicated physical benchmark Profile and
runs the original complete test set. Machine-readable `jasper.perf.v1` records
are emitted alongside the human-readable screen output. QEMU/OVMF is retained
only as a control environment and is never substituted for physical evidence.

Detailed AMD topology and SMP bring-up findings are recorded in
[`evidence/amd-cpu-topology-20261124/README.md`](evidence/amd-cpu-topology-20261124/README.md).
The four-CPU INIT/SIPI control result is recorded in
[`evidence/amd-smp-init10ms-qemu-20261124/README.md`](evidence/amd-smp-init10ms-qemu-20261124/README.md).

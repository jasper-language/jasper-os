# Issue 95 unified matrix QEMU control

QEMU/OVMF TCG control group, 2026-11-24.

The same kernel image executed:

1. `SMP_SINGLE` on one logical CPU;
2. `SMP_PHYSICAL` on the dynamically discovered physical-core set;
3. `SMP_LOGICAL` on all online logical CPUs.

This smoke build used 100,000 scalar samples and 10,000 context-switch samples
per participating CPU. Formal physical builds retain 1,000,000 samples.

Verified:

- all three mode result lines reported `COMPLETE=true`;
- `SMP CONCURRENT FINAL` reported all three modes true;
- every metric separated planned, observed, valid, failed and incomplete
  sample counts;
- yield-gate retries were recorded separately and no empty yield attempt was
  retained as a context-switch latency sample;
- before, raw-retained and after memory records exist for every mode;
- resources returned to baseline;
- `qemu_rc=33`.

```text
SMP CONCURRENT FINAL SINGLE=true PHYSICAL=true LOGICAL=true SINGLE_CPUS=1 PHYSICAL_CPUS=2 LOGICAL_CPUS=2 SMT=false RECLAIMED=true FAILED=0 TIMING_FAILED=0
{"schema":"jasper.perf.v1","kind":"summary","metrics":62,"failed":0,"timing_failed":0,"checks":55,"resources_reclaimed":true,"discovered_cpus":2,"online_cpus":2,"parallel_matrix_run":true,"single_mode_run":true,"physical_mode_run":true,"logical_mode_run":true}
```

`serial.txt` is the machine-readable and textual control evidence. QEMU
numbers are not physical performance results.

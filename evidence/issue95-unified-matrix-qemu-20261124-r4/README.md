# Issue 95 unified matrix QEMU control after barrier fix

QEMU/OVMF TCG control group, 2026-11-24.

Both switch participants now enter the complete existing scheduler transaction
while waiting for the readiness barrier. This prevents the first worker from
being trapped by a gate-suppressed `yield_now` before the second worker can
start.

Verified:

- `SMP_SINGLE`, `SMP_PHYSICAL` and `SMP_LOGICAL` all reported
  `COMPLETE=true`;
- no switch barrier timeout, failed operation or incomplete sample appeared;
- `SMP CONCURRENT FINAL` reported all three modes true;
- resources returned to baseline;
- `qemu_rc=33`.

```text
SMP CONCURRENT FINAL SINGLE=true PHYSICAL=true LOGICAL=true SINGLE_CPUS=1 PHYSICAL_CPUS=2 LOGICAL_CPUS=2 SMT=false RECLAIMED=true FAILED=0 TIMING_FAILED=0
{"schema":"jasper.perf.v1","kind":"summary","metrics":62,"failed":0,"timing_failed":0,"checks":55,"resources_reclaimed":true,"discovered_cpus":2,"online_cpus":2,"parallel_matrix_run":true,"single_mode_run":true,"physical_mode_run":true,"logical_mode_run":true}
```

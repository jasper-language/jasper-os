# Issue 95 unified matrix QEMU control after switch fix

QEMU/OVMF TCG control group, 2026-11-24.

The context-switch measurement now enters the complete existing scheduler
transaction directly instead of using the general `yield_now` path, which may
return without switching through its yield gate.

Verified:

- `SMP_SINGLE`, `SMP_PHYSICAL` and `SMP_LOGICAL` all reported
  `COMPLETE=true`;
- no context-switch retries, failed operations or incomplete samples appeared;
- `SMP CONCURRENT FINAL` reported all three modes true;
- resources returned to baseline;
- `qemu_rc=33`.

```text
SMP CONCURRENT FINAL SINGLE=true PHYSICAL=true LOGICAL=true SINGLE_CPUS=1 PHYSICAL_CPUS=2 LOGICAL_CPUS=2 SMT=false RECLAIMED=true FAILED=0 TIMING_FAILED=0
{"schema":"jasper.perf.v1","kind":"summary","metrics":62,"failed":0,"timing_failed":0,"checks":55,"resources_reclaimed":true,"discovered_cpus":2,"online_cpus":2,"parallel_matrix_run":true,"single_mode_run":true,"physical_mode_run":true,"logical_mode_run":true}
```

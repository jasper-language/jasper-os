# Issue 95 KPR-0 QEMU control

Status: **PASS** (`qemu_rc=33`), QEMU smoke only, not physical performance.

Environment: 4-vCPU TCG multi-thread control, 4 physical/4 logical topology
without SMT, 100,000 samples per metric per CPU.

```text
SMP_PHYSICAL RESULT COMPLETE=true TOTAL_METRICS=16 RAW_SAMPLES=6400000
SMP_LOGICAL RESULT COMPLETE=true TOTAL_METRICS=16 RAW_SAMPLES=6400000
SMP CONCURRENT FINAL PHYSICAL=true LOGICAL=true PHYSICAL_CPUS=4 LOGICAL_CPUS=4 SMT=false RECLAIMED=true FAILED=0 TIMING_FAILED=0
SMP BENCH RESULT FAILED=0 TIMING_FAILED=0
resources_reclaimed=true
```

Each mode returned frame, object, pending and pin counts to baseline.

The separate `fast-leaf-yield` candidate was rejected: continuous voluntary
yields exposed a hot/cold task-state divergence. The candidate was removed and
is not present in the formal physical image.
